//! Server-direct local TCP port forwarding.
//!
//! Each configured loopback listener opens a data bi-stream on the client's
//! authenticated iroh connection and sends the target directly to the server.
//! No local SOCKS5 listener or handshake is involved. The server remains the
//! authority: it enforces its routed set before resolving or dialing the target.

use super::client::ServerForwarder;
use super::signaling::Target;
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Handle;
use tokio::task::{JoinHandle, JoinSet};

const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(250);

/// One server-direct local forward.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardSpec {
    pub id: String,
    pub local_port: u16,
    pub target: Target,
}

/// Live state of one forward listener.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForwardState {
    Starting,
    Listening,
    Failed(String),
}

/// Snapshot of one forward's listener and relay state.
#[derive(Clone, Debug)]
pub struct ForwardStatus {
    pub id: String,
    pub state: ForwardState,
    pub active: usize,
    pub last_conn_error: Option<String>,
}

struct ForwardShared {
    state: Mutex<ForwardState>,
    active: AtomicUsize,
    last_conn_error: Mutex<Option<String>>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct ForwardTask {
    spec: ForwardSpec,
    handle: JoinHandle<()>,
    shared: Arc<ForwardShared>,
}

/// Owns and reconciles server-direct listener tasks.
///
/// The runtime handle makes [`apply`](Self::apply) safe to call from a foreign
/// thread (the iOS FFI does this from Swift's main actor).
pub struct ForwardManager {
    runtime: Handle,
    forwarder: ServerForwarder,
    tasks: HashMap<String, ForwardTask>,
}

impl ForwardManager {
    pub fn new(runtime: Handle, forwarder: ServerForwarder, forwards: &[ForwardSpec]) -> Self {
        let mut manager = Self {
            runtime,
            forwarder,
            tasks: HashMap::new(),
        };
        manager.apply(forwards);
        manager
    }

    /// Reconcile listeners with the complete desired set.
    pub fn apply(&mut self, forwards: &[ForwardSpec]) {
        let desired: HashMap<&str, &ForwardSpec> =
            forwards.iter().map(|f| (f.id.as_str(), f)).collect();
        self.tasks.retain(|id, task| match desired.get(id.as_str()) {
            Some(spec) if **spec == task.spec => true,
            _ => {
                task.handle.abort();
                false
            }
        });
        for spec in forwards {
            if self.tasks.contains_key(&spec.id) {
                continue;
            }
            let shared = Arc::new(ForwardShared {
                state: Mutex::new(ForwardState::Starting),
                active: AtomicUsize::new(0),
                last_conn_error: Mutex::new(None),
            });
            let handle = self.runtime.spawn(run_forward(
                spec.clone(),
                self.forwarder.clone(),
                shared.clone(),
            ));
            self.tasks.insert(
                spec.id.clone(),
                ForwardTask {
                    spec: spec.clone(),
                    handle,
                    shared,
                },
            );
        }
    }

    pub fn statuses(&self) -> Vec<ForwardStatus> {
        self.tasks
            .iter()
            .map(|(id, task)| ForwardStatus {
                id: id.clone(),
                state: lock(&task.shared.state).clone(),
                active: task.shared.active.load(Ordering::Relaxed),
                last_conn_error: lock(&task.shared.last_conn_error).clone(),
            })
            .collect()
    }
}

impl Drop for ForwardManager {
    fn drop(&mut self) {
        for task in self.tasks.values() {
            task.handle.abort();
        }
    }
}

struct ActiveGuard(Arc<ForwardShared>);

impl ActiveGuard {
    fn new(shared: Arc<ForwardShared>) -> Self {
        shared.active.fetch_add(1, Ordering::Relaxed);
        Self(shared)
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn accept_on(listener: Option<&TcpListener>) -> io::Result<(TcpStream, SocketAddr)> {
    match listener {
        Some(listener) => listener.accept().await,
        None => std::future::pending().await,
    }
}

async fn run_forward(
    spec: ForwardSpec,
    forwarder: ServerForwarder,
    shared: Arc<ForwardShared>,
) {
    let port = spec.local_port;
    let v4 = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await;
    let v6 = TcpListener::bind((Ipv6Addr::LOCALHOST, port)).await;
    let (v4, v6) = match (v4, v6) {
        (Err(e4), Err(e6)) => {
            let reason = if e4.kind() == io::ErrorKind::AddrInUse
                || e6.kind() == io::ErrorKind::AddrInUse
            {
                format!("port {port} is in use")
            } else {
                e4.to_string()
            };
            log::error!("Forward localhost:{port} failed to bind: {reason}");
            *lock(&shared.state) = ForwardState::Failed(reason);
            return;
        }
        (v4, v6) => (v4.ok(), v6.ok()),
    };
    *lock(&shared.state) = ForwardState::Listening;
    log::info!(
        "Forwarding localhost:{port} → {:?} directly through the server ({}{})",
        spec.target,
        if v4.is_some() { "IPv4" } else { "" },
        match (&v4, &v6) {
            (Some(_), Some(_)) => "+IPv6",
            (None, Some(_)) => "IPv6",
            _ => "",
        }
    );

    let mut relays = JoinSet::new();
    loop {
        let accepted = tokio::select! {
            accepted = accept_on(v4.as_ref()) => accepted,
            accepted = accept_on(v6.as_ref()) => accepted,
            Some(_) = relays.join_next(), if !relays.is_empty() => continue,
        };
        let inbound = match accepted {
            Ok((inbound, _)) => inbound,
            Err(e) => {
                log::warn!("Forward localhost:{port} accept failed ({e}); retrying");
                tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
                continue;
            }
        };
        let shared = shared.clone();
        let forwarder = forwarder.clone();
        let target = spec.target.clone();
        relays.spawn(async move {
            let _guard = ActiveGuard::new(shared.clone());
            match forwarder.relay(inbound, &target).await {
                Ok(()) => *lock(&shared.last_conn_error) = None,
                Err(e) => {
                    log::warn!("Forward localhost:{port}: {e}");
                    *lock(&shared.last_conn_error) = Some(e.to_string());
                }
            }
        });
    }
}
