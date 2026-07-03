//! Local port forwarding: per-forward dual-stack loopback listeners
//! (`127.0.0.1` + `::1`, never wildcard) that relay every accepted connection
//! through the app's own SOCKS5 listener, mirroring the iOS forwarder. Going
//! through the SOCKS front-end means the core's split-tunnel routing,
//! server-side DNS, and reconnect-gap replies all apply unchanged.
//!
//! Each relayed connection authenticates with the SOCKS5 username/password
//! method carrying this session's random instance token, so a forward that
//! accidentally reaches some *other* SOCKS5 server on the port (another
//! flextunnel, an `ssh -D`) fails loudly instead of sending traffic to the
//! wrong place. Misconfiguration guard, not security — everything is loopback.

use flextunnel_core::proxy::signaling::{self, Target};
use flextunnel_core::proxy::socks5;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};

/// Deadline for the whole SOCKS5 setup (handshake + CONNECT reply). Must
/// exceed the core's own tunnel-open timeout (~30s) so a legitimately slow
/// target isn't cut off by us first.
const SOCKS_SETUP_TIMEOUT: Duration = Duration::from_secs(35);
/// Pause before retrying `accept()` after a failure (mirrors the core's
/// accept-retry pacing).
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(250);

/// One configured forward: `localhost:local_port` → `remote_host:remote_port`
/// through the tunnel's SOCKS5 listener. The remote host stays a string
/// end-to-end (sent as ATYP DOMAIN) so DNS happens server-side, like iOS.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortForward {
    pub id: String,
    #[serde(default)]
    pub label: String,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
    pub enabled: bool,
}

impl PortForward {
    pub fn new_id() -> String {
        format!("{:016x}", rand::random::<u64>())
    }

    pub fn display_name(&self) -> String {
        let label = self.label.trim();
        if label.is_empty() {
            format!("{}:{}", self.remote_host, self.remote_port)
        } else {
            label.to_string()
        }
    }

    pub fn route_description(&self) -> String {
        format!(
            "localhost:{} → {}:{}",
            self.local_port, self.remote_host, self.remote_port
        )
    }
}

/// Forwards live in a plain JSON file, not the keychain config blob — they are
/// not secret, and Windows credential blobs cap out around 2.5 KB. Same
/// treatment as the iOS app's `forwards.json`.
fn forwards_path() -> Option<PathBuf> {
    dirs::data_local_dir().map(|d| d.join("flextunnel").join("forwards.json"))
}

pub fn load() -> Vec<PortForward> {
    let Some(path) = forwards_path() else {
        return Vec::new();
    };
    load_from(&path)
}

pub fn save(forwards: &[PortForward]) -> anyhow::Result<()> {
    let path = forwards_path()
        .ok_or_else(|| anyhow::anyhow!("no local data directory to store forwards in"))?;
    save_to(&path, forwards)
}

fn load_from(path: &Path) -> Vec<PortForward> {
    let raw = match std::fs::read(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            log::error!("Failed to read {}: {e}", path.display());
            return Vec::new();
        }
    };
    match serde_json::from_slice(&raw) {
        Ok(forwards) => forwards,
        Err(e) => {
            log::error!("Failed to parse {}: {e}", path.display());
            Vec::new()
        }
    }
}

/// Write via a temp file + rename so a crash mid-write can't truncate the list.
fn save_to(path: &Path, forwards: &[PortForward]) -> anyhow::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("forwards path has no parent directory"))?;
    std::fs::create_dir_all(dir)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(forwards)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Live state of one forward's listener. "Stopped" is represented by absence:
/// a forward with no status has no running session (or is disabled).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForwardState {
    Listening,
    Failed(String),
}

#[derive(Clone, Debug)]
pub struct ForwardStatus {
    pub id: String,
    pub state: ForwardState,
    /// Live relayed connections.
    pub active: usize,
    /// Most recent per-connection setup failure; cleared by the next success.
    pub last_conn_error: Option<String>,
}

/// Cells shared between a forward's task (writer) and `statuses()` (reader).
struct ForwardShared {
    state: Mutex<ForwardState>,
    active: AtomicUsize,
    last_conn_error: Mutex<Option<String>>,
}

/// Never panic on a poisoned mutex — recover the guard.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct ForwardTask {
    forward: PortForward,
    handle: JoinHandle<()>,
    shared: Arc<ForwardShared>,
}

/// Owns the listener tasks for one tunnel session. Created when a session
/// starts, reconciled on every forward-list change, dropped (aborting
/// everything, relays included) when the session ends.
pub struct ForwardManager {
    socks_port: u16,
    auth_password: Arc<str>,
    tasks: HashMap<String, ForwardTask>,
}

impl ForwardManager {
    pub fn new(socks_port: u16, auth_password: Arc<str>, forwards: &[PortForward]) -> Self {
        let mut manager = Self {
            socks_port,
            auth_password,
            tasks: HashMap::new(),
        };
        manager.apply(forwards);
        manager
    }

    /// Reconcile the running tasks with the desired list: removed, disabled, or
    /// edited forwards are aborted (dropping their live relays); new or edited
    /// enabled forwards are spawned. Untouched forwards keep their listeners
    /// and open connections.
    pub fn apply(&mut self, forwards: &[PortForward]) {
        let desired: HashMap<&str, &PortForward> =
            forwards.iter().map(|f| (f.id.as_str(), f)).collect();
        self.tasks.retain(|id, task| {
            let keep = desired.get(id.as_str()) == Some(&&task.forward);
            if !keep {
                task.handle.abort();
            }
            keep
        });
        for forward in forwards {
            if forward.enabled && !self.tasks.contains_key(&forward.id) {
                let shared = Arc::new(ForwardShared {
                    state: Mutex::new(ForwardState::Listening),
                    active: AtomicUsize::new(0),
                    last_conn_error: Mutex::new(None),
                });
                let handle = tokio::spawn(run_forward(
                    forward.clone(),
                    self.socks_port,
                    self.auth_password.clone(),
                    shared.clone(),
                ));
                self.tasks.insert(
                    forward.id.clone(),
                    ForwardTask {
                        forward: forward.clone(),
                        handle,
                        shared,
                    },
                );
            }
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
        // Aborting a forward task drops its JoinSet, which aborts its relays.
        for task in self.tasks.values() {
            task.handle.abort();
        }
    }
}

/// Increments the forward's active-connection count for the relay's lifetime;
/// the `Drop` decrement runs even when the relay is aborted.
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

/// `accept()` on an optionally-bound listener; pends forever when the stack
/// didn't bind so it stays inert in the `select!`.
async fn accept_on(listener: Option<&TcpListener>) -> io::Result<(TcpStream, SocketAddr)> {
    match listener {
        Some(listener) => listener.accept().await,
        None => std::future::pending().await,
    }
}

async fn run_forward(
    forward: PortForward,
    socks_port: u16,
    auth_password: Arc<str>,
    shared: Arc<ForwardShared>,
) {
    let port = forward.local_port;
    let v4 = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await;
    let v6 = TcpListener::bind((Ipv6Addr::LOCALHOST, port)).await;
    let (v4, v6) = match (v4, v6) {
        // Listening as long as at least one loopback stack bound (a client app
        // dialing `localhost` may try either family first, but retries the
        // other on connection-refused).
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
    log::info!(
        "Forwarding localhost:{port} → {}:{} via SOCKS5 ({}{})",
        forward.remote_host,
        forward.remote_port,
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
            // Reap finished relays so the JoinSet doesn't grow unboundedly.
            Some(_) = relays.join_next(), if !relays.is_empty() => continue,
        };
        let inbound = match accepted {
            Ok((inbound, _peer)) => inbound,
            Err(e) => {
                log::warn!("Forward localhost:{port} accept failed ({e}); retrying");
                tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
                continue;
            }
        };
        let shared = shared.clone();
        let auth_password = auth_password.clone();
        let target = Target::Domain(forward.remote_host.clone(), forward.remote_port);
        relays.spawn(async move {
            let _guard = ActiveGuard::new(shared.clone());
            match relay_conn(inbound, socks_port, &auth_password, &target).await {
                Ok(()) => *lock(&shared.last_conn_error) = None,
                Err(e) => {
                    log::warn!("Forward localhost:{port}: {e}");
                    *lock(&shared.last_conn_error) = Some(e.to_string());
                }
            }
        });
    }
}

/// Relay one accepted connection: dial the local SOCKS5 listener, verify it is
/// this instance's (username/password instance handshake), CONNECT to the
/// forward's target, then splice bytes until either side closes.
async fn relay_conn(
    mut inbound: TcpStream,
    socks_port: u16,
    auth_password: &str,
    target: &Target,
) -> anyhow::Result<()> {
    // The core binds its SOCKS5 listener on 127.0.0.1 (tunnel.rs).
    let mut socks = TcpStream::connect((Ipv4Addr::LOCALHOST, socks_port))
        .await
        .map_err(|e| anyhow::anyhow!("SOCKS5 proxy unreachable: {e}"))?;
    let setup = async {
        socks5::client_handshake_userpass(&mut socks, socks5::AUTH_USERNAME, auth_password)
            .await?;
        socks5::client_write_connect(&mut socks, target).await?;
        let rep = socks5::client_read_reply(&mut socks).await?;
        if rep == signaling::REP_SUCCESS {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "connect failed: {}",
                socks5::describe_reply(rep)
            )))
        }
    };
    tokio::time::timeout(SOCKS_SETUP_TIMEOUT, setup)
        .await
        .map_err(|_| anyhow::anyhow!("SOCKS5 setup timed out"))??;
    // The pipe outcome is not a forward error — apps close however they like.
    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut socks).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    const PASSWORD: &str = "feedfacefeedfacefeedfacefeedface";

    fn forward(local_port: u16) -> PortForward {
        PortForward {
            id: PortForward::new_id(),
            label: String::new(),
            local_port,
            remote_host: "echo.internal".into(),
            remote_port: 7,
            enabled: true,
        }
    }

    #[test]
    fn persistence_roundtrip_and_corrupt_tolerance() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("forwards.json");

        assert_eq!(load_from(&path), Vec::new());

        let forwards = vec![forward(18081), forward(18082)];
        save_to(&path, &forwards).expect("save");
        assert_eq!(load_from(&path), forwards);

        std::fs::write(&path, b"not json").expect("write");
        assert_eq!(load_from(&path), Vec::new());
    }

    #[test]
    fn names_and_descriptions() {
        let mut f = forward(8080);
        assert_eq!(f.display_name(), "echo.internal:7");
        assert_eq!(f.route_description(), "localhost:8080 → echo.internal:7");
        f.label = "  echo  ".into();
        assert_eq!(f.display_name(), "echo");
    }

    /// A minimal flextunnel-style SOCKS5 server on an ephemeral port, built
    /// from the same core server functions the real listener uses: auth with
    /// PASSWORD, accept any CONNECT, then echo.
    async fn spawn_mini_socks(password: &'static str) -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind mini socks");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    if socks5::negotiate_method(&mut stream, password).await.is_err() {
                        return;
                    }
                    if socks5::read_connect_request(&mut stream).await.is_err() {
                        return;
                    }
                    if socks5::write_reply(&mut stream, signaling::REP_SUCCESS)
                        .await
                        .is_err()
                    {
                        return;
                    }
                    let (mut read, mut write) = stream.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        });
        port
    }

    async fn free_port() -> u16 {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("probe bind")
            .local_addr()
            .expect("addr")
            .port()
    }

    async fn status_of(manager: &ForwardManager, id: &str) -> ForwardStatus {
        manager
            .statuses()
            .into_iter()
            .find(|s| s.id == id)
            .expect("status present")
    }

    #[tokio::test]
    async fn forwards_bytes_through_matching_instance() {
        let socks_port = spawn_mini_socks(PASSWORD).await;
        let local_port = free_port().await;
        let forward = forward(local_port);
        let id = forward.id.clone();
        let manager = ForwardManager::new(socks_port, PASSWORD.into(), &[forward]);

        // The listener task binds asynchronously; retry the dial briefly.
        let mut conn = None;
        for _ in 0..50 {
            match TcpStream::connect((Ipv4Addr::LOCALHOST, local_port)).await {
                Ok(stream) => {
                    conn = Some(stream);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
        let mut conn = conn.expect("forward listener reachable");

        conn.write_all(b"ping").await.expect("write");
        let mut buf = [0u8; 4];
        conn.read_exact(&mut buf).await.expect("echo");
        assert_eq!(&buf, b"ping");

        let status = status_of(&manager, &id).await;
        assert_eq!(status.state, ForwardState::Listening);
        assert_eq!(status.active, 1);
        assert_eq!(status.last_conn_error, None);
    }

    #[tokio::test]
    async fn wrong_instance_drops_connection_and_reports() {
        // A server with a *different* instance token, as if another flextunnel
        // instance were squatting the port.
        let socks_port = spawn_mini_socks("00000000000000000000000000000000").await;
        let local_port = free_port().await;
        let forward = forward(local_port);
        let id = forward.id.clone();
        let manager = ForwardManager::new(socks_port, PASSWORD.into(), &[forward]);

        let mut conn = None;
        for _ in 0..50 {
            match TcpStream::connect((Ipv4Addr::LOCALHOST, local_port)).await {
                Ok(stream) => {
                    conn = Some(stream);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
        let mut conn = conn.expect("forward listener reachable");

        // The relay must drop the connection (EOF), not pass bytes through.
        let mut buf = [0u8; 1];
        assert_eq!(conn.read(&mut buf).await.expect("read"), 0);

        let status = status_of(&manager, &id).await;
        let error = status.last_conn_error.expect("error recorded");
        assert!(error.contains("rejected"), "got: {error}");
    }

    #[tokio::test]
    async fn apply_reconciles_tasks() {
        let socks_port = spawn_mini_socks(PASSWORD).await;
        let a = forward(free_port().await);
        let mut b = forward(free_port().await);
        let mut manager = ForwardManager::new(socks_port, PASSWORD.into(), &[a.clone(), b.clone()]);
        assert_eq!(manager.statuses().len(), 2);

        // Disable one: its task disappears.
        b.enabled = false;
        manager.apply(&[a.clone(), b.clone()]);
        let statuses = manager.statuses();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].id, a.id);

        // Remove the rest.
        manager.apply(&[]);
        assert!(manager.statuses().is_empty());
    }
}
