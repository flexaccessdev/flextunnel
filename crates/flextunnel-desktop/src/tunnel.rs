//! Background tunnel controller: a dedicated thread running a Tokio runtime,
//! driven by UI commands, publishing a status snapshot the UI polls each
//! frame. The `ProxyClient` future is owned by the session loop, so dropping
//! it (disconnect/shutdown) tears down the accept loops and the connection
//! manager together, followed by a graceful endpoint close.

use crate::config::AppConfig;
use crate::forward::{ForwardManager, ForwardStatus, PortForward};
use flextunnel_core::proxy::{ClientConfig, ProxyClient, TunnelRoutes};
use flextunnel_core::transport::endpoint::create_client_endpoint;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase {
    Idle,
    Connecting,
    Connected,
    Reconnecting,
    Failed,
}

#[derive(Clone)]
pub struct Snapshot {
    pub phase: Phase,
    pub connected_since: Option<Instant>,
    pub socks_addr: Option<SocketAddr>,
    pub http_addr: Option<SocketAddr>,
    pub routes: TunnelRoutes,
    pub last_error: Option<String>,
    /// Live status per running forward; empty while no session runs, which the
    /// UI renders as "stopped".
    pub forwards: Vec<ForwardStatus>,
}

impl Default for Snapshot {
    fn default() -> Self {
        Self {
            phase: Phase::Idle,
            connected_since: None,
            socks_addr: None,
            http_addr: None,
            routes: TunnelRoutes::default(),
            last_error: None,
            forwards: Vec::new(),
        }
    }
}

enum Command {
    Connect(AppConfig),
    Disconnect,
    /// Replace the desired forward list (the UI sends the full list at startup
    /// and after every add/edit/delete/toggle); applied live mid-session.
    SetForwards(Vec<PortForward>),
    Shutdown,
}

pub struct Controller {
    tx: mpsc::Sender<Command>,
    shared: Arc<Mutex<Snapshot>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Controller {
    pub fn start() -> Self {
        let (tx, rx) = mpsc::channel(16);
        let shared = Arc::new(Mutex::new(Snapshot::default()));
        let worker_shared = shared.clone();
        let thread = std::thread::Builder::new()
            .name("tunnel".into())
            .spawn(move || match flextunnel_core::app::build_runtime() {
                Ok(rt) => rt.block_on(run_loop(rx, worker_shared)),
                Err(e) => {
                    log::error!("Failed to build the Tokio runtime: {e:#}");
                    update(&worker_shared, |s| {
                        s.phase = Phase::Failed;
                        s.last_error = Some(format!("Failed to start: {e:#}"));
                    });
                }
            })
            .expect("spawn tunnel thread");
        Self {
            tx,
            shared,
            thread: Some(thread),
        }
    }

    pub fn snapshot(&self) -> Snapshot {
        self.shared
            .lock()
            .map(|s| s.clone())
            .unwrap_or_else(|poisoned| poisoned.into_inner().clone())
    }

    pub fn connect(&self, config: AppConfig) {
        let _ = self.tx.blocking_send(Command::Connect(config));
    }

    pub fn disconnect(&self) {
        let _ = self.tx.blocking_send(Command::Disconnect);
    }

    pub fn set_forwards(&self, forwards: Vec<PortForward>) {
        let _ = self.tx.blocking_send(Command::SetForwards(forwards));
    }

    /// Stop any session and join the worker thread (blocks briefly for the
    /// graceful endpoint close).
    pub fn shutdown(&mut self) {
        let _ = self.tx.blocking_send(Command::Shutdown);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn update<F: FnOnce(&mut Snapshot)>(shared: &Arc<Mutex<Snapshot>>, f: F) {
    let mut s = match shared.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    f(&mut s);
}

async fn run_loop(mut rx: mpsc::Receiver<Command>, shared: Arc<Mutex<Snapshot>>) {
    let mut forwards: Vec<PortForward> = Vec::new();
    while let Some(cmd) = rx.recv().await {
        match cmd {
            Command::Connect(config) => {
                if run_session(config, &mut forwards, &mut rx, &shared).await
                    == SessionExit::Shutdown
                {
                    return;
                }
            }
            Command::Disconnect => {}
            Command::SetForwards(f) => forwards = f,
            Command::Shutdown => return,
        }
    }
}

#[derive(PartialEq, Eq)]
enum SessionExit {
    Ended,
    Shutdown,
}

async fn run_session(
    config: AppConfig,
    forwards: &mut Vec<PortForward>,
    rx: &mut mpsc::Receiver<Command>,
    shared: &Arc<Mutex<Snapshot>>,
) -> SessionExit {
    let socks_addr = SocketAddr::from(([127, 0, 0, 1], config.socks_port));
    let http_addr = config.http_port.map(|p| SocketAddr::from(([127, 0, 0, 1], p)));
    update(shared, |s| {
        *s = Snapshot {
            phase: Phase::Connecting,
            socks_addr: Some(socks_addr),
            http_addr,
            ..Snapshot::default()
        };
    });

    // Endpoint creation can block for up to ~10s (the relay online-wait), so
    // it races the command channel — otherwise a Disconnect or app quit issued
    // during it would stall until it finished. It runs as a spawned task
    // rather than a raced future because cancelling it by drop could drop a
    // bound endpoint without `close()`, which is fatal under panic=abort (see
    // the CLI's run_client); on a stop the task finishes on its own and the
    // endpoint is closed gracefully.
    let mut create = tokio::spawn({
        let relay_urls = config.relay_urls.clone();
        async move { create_client_endpoint(&relay_urls, None).await }
    });
    let endpoint = loop {
        tokio::select! {
            created = &mut create => match created.map_err(anyhow::Error::from) {
                Ok(Ok(endpoint)) => break endpoint,
                Ok(Err(e)) | Err(e) => {
                    log::error!("Failed to create the iroh endpoint: {e:#}");
                    update(shared, |s| {
                        s.phase = Phase::Failed;
                        s.last_error = Some(format!("{e:#}"));
                    });
                    return SessionExit::Ended;
                }
            },
            cmd = rx.recv() => match cmd {
                Some(Command::Connect(_)) => {
                    log::warn!("Already running a session; disconnect first");
                }
                Some(Command::Disconnect) => {
                    log::info!("Disconnecting");
                    update(shared, |s| s.phase = Phase::Idle);
                    // Close the endpoint gracefully once creation finishes,
                    // without holding up the disconnect.
                    tokio::spawn(async move {
                        if let Ok(Ok(endpoint)) = create.await {
                            endpoint.close().await;
                        }
                    });
                    return SessionExit::Ended;
                }
                Some(Command::SetForwards(f)) => *forwards = f,
                Some(Command::Shutdown) | None => {
                    // Bounded grace so quitting stays responsive: close
                    // cleanly when creation finishes quickly, otherwise just
                    // exit — the process is going away anyway.
                    let _ = tokio::time::timeout(Duration::from_secs(2), async {
                        if let Ok(Ok(endpoint)) = create.await {
                            endpoint.close().await;
                        }
                    })
                    .await;
                    return SessionExit::Shutdown;
                }
            }
        }
    };
    log::info!("flextunnel client node id: {}", endpoint.id());

    let client = ProxyClient::new(ClientConfig {
        server_node_id: config.server_node_id.clone(),
        auth_token: config.auth_token.clone(),
        socks_listen: socks_addr,
        http_listen: http_addr,
        relay_urls: config.relay_urls.clone(),
        auto_reconnect: true,
        max_reconnect_attempts: None,
    });
    let routes = client.routes();

    // Forwards run for the whole session (including reconnect gaps — the SOCKS
    // listener stays bound); they die with the manager when the session ends.
    // The SOCKS listener binds when `run` is first polled below, so an early
    // relay sees at most one connection-refused, surfaced per-forward.
    let mut fwd_mgr =
        ForwardManager::new(config.socks_port, client.socks_auth_password().into(), forwards);

    let run = client.run(&endpoint);
    tokio::pin!(run);
    let mut ticker = tokio::time::interval(Duration::from_millis(500));
    let mut ever_connected = false;

    let exit = loop {
        tokio::select! {
            res = &mut run => {
                match res {
                    Ok(()) => update(shared, |s| s.phase = Phase::Idle),
                    Err(e) => {
                        log::error!("Client error: {e}");
                        update(shared, |s| {
                            s.phase = Phase::Failed;
                            s.last_error = Some(e.to_string());
                        });
                    }
                }
                break SessionExit::Ended;
            }
            _ = ticker.tick() => {
                let routes = routes
                    .lock()
                    .map(|r| r.clone())
                    .unwrap_or_default();
                ever_connected |= routes.connected;
                let forward_statuses = fwd_mgr.statuses();
                update(shared, |s| {
                    if routes.connected {
                        if s.phase != Phase::Connected {
                            s.connected_since = Some(Instant::now());
                        }
                        s.phase = Phase::Connected;
                    } else {
                        s.connected_since = None;
                        s.phase = if ever_connected {
                            Phase::Reconnecting
                        } else {
                            Phase::Connecting
                        };
                    }
                    s.routes = routes;
                    s.forwards = forward_statuses;
                });
            }
            cmd = rx.recv() => match cmd {
                Some(Command::Disconnect) => {
                    log::info!("Disconnecting");
                    update(shared, |s| s.phase = Phase::Idle);
                    break SessionExit::Ended;
                }
                Some(Command::Connect(_)) => {
                    log::warn!("Already running a session; disconnect first");
                }
                Some(Command::SetForwards(f)) => {
                    *forwards = f;
                    fwd_mgr.apply(forwards);
                    let forward_statuses = fwd_mgr.statuses();
                    update(shared, |s| s.forwards = forward_statuses);
                }
                Some(Command::Shutdown) | None => break SessionExit::Shutdown,
            }
        }
    };

    // The select loop is done with `run`; dropping it cancels the client.
    // Tear the forward listeners down with the session so their rows read
    // "stopped" immediately, then close the endpoint gracefully before it is
    // dropped (see the CLI's run_client for why an ungraceful drop is fatal
    // under panic=abort).
    drop(fwd_mgr);
    endpoint.close().await;
    update(shared, |s| {
        s.routes.connected = false;
        s.connected_since = None;
        s.forwards.clear();
    });
    exit
}
