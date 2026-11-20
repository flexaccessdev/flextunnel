//! Background tunnel controller: a supervisor thread routing UI commands to
//! the app's two sessions — the client and the server — each on its own OS
//! thread running its own Tokio runtime, whose threads carry the session's
//! name (`client` / `server`) so every log line a session emits (core
//! internals included) is attributed to it by thread name (see `logging`).
//! Status is published as snapshots the UI polls each frame.
//!
//! The client session is one [`ProxyClient`] over every destination: it binds
//! the local proxy ports and the port forwards, and connects to a destination
//! only when something is sent to it — closing the connection again once it
//! has gone unused (see [`flextunnel_core::proxy::ProxyClient::run`]). The
//! session owns its client future, so dropping it (stop/shutdown) tears down
//! the accept loops and every destination's manager together, followed by a
//! graceful close of the endpoints in use. The app's server
//! ([`crate::server_session`]) is routed through the same supervisor, so one
//! controller owns both sessions and one shutdown stops them.

use crate::config::{self, AuthKey, ClientSettings, Destination, ServerConfig};
use crate::server_session::{self, ServerCmd, ServerHandle, ServerSnapshot, SharedServerSnapshot};
use flextunnel_core::config::DEFAULT_IDLE_TIMEOUT;
use flextunnel_core::forwards::{ForwardManager, ForwardStatus, PortForward};
use flextunnel_core::proxy::{
    ClientAuth, ClientConfig, DestinationConfig, DestinationStatus, LocalListeners, ProxyClient,
};
use flextunnel_core::transport::endpoint::RelayConfig;
use flextunnel_core::transport::paths::ConnectionSnapshot;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

pub type DestinationId = String;

/// The client session's thread name, and so its log tag (`[client]`).
pub const CLIENT_THREAD_NAME: &str = "client";

/// Bound on the GUI thread's wait for a connection-path reply (see
/// [`Controller::query_conn_path`]). Must exceed the custom-relay `/healthz`
/// probe budget (relays checked in parallel, ~3s worst case) the session now
/// awaits before replying; it exists to fail open (empty result) rather than
/// hang if a session stalls.
const CONN_PATH_TIMEOUT: Duration = Duration::from_secs(5);

/// Bound on the client's graceful endpoint close at teardown. The close waits
/// out an endpoint still being built (see `ProxyClient::close`), which a stop
/// or a restart during a slow dial must not hang behind; an ordinary close
/// finishes well inside it.
const SESSION_CLOSE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ClientPhase {
    /// No session: nothing is listening.
    #[default]
    Stopped,
    /// Validating the settings and binding the local ports.
    Starting,
    /// The proxy ports and forwards are listening; each destination connects
    /// when something is sent to it.
    Running,
    /// Closing the endpoints in use; a restart waits for this to finish.
    Stopping,
    /// The session could not start (a local port is taken, say) or lost its
    /// listeners.
    Failed,
}

#[derive(Clone, Default)]
pub struct ClientSnapshot {
    pub phase: ClientPhase,
    /// What the session whose state this is was started with — the ports,
    /// destinations and key secrets actually in use. Published by the session
    /// itself, with the rest of its state, so it is never a start that was
    /// only asked for, queued behind a stop, or turned down. `None` while no
    /// session is starting or running.
    pub spec: Option<Arc<ClientSpec>>,
    pub running_since: Option<Instant>,
    pub last_error: Option<String>,
    /// Live state per destination of the running session, in its order; empty
    /// while none runs.
    pub destinations: Vec<DestinationStatus>,
    /// Live status per running forward; empty while no session runs, which the
    /// UI renders as "stopped".
    pub forwards: Vec<ForwardStatus>,
}

/// One destination as a session runs it: its settings plus the secret of the
/// auth key it references.
#[derive(Clone, PartialEq, Eq)]
pub struct DestinationSpec {
    pub destination: Destination,
    pub auth_secret: String,
}

/// Everything a client session is started with and keeps for its lifetime:
/// the proxy ports and the destinations. Comparing two tells whether saved
/// settings differ from the running ones (forwards are not part of it — they
/// apply live).
#[derive(Clone, PartialEq, Eq)]
pub struct ClientSpec {
    pub socks_port: Option<u16>,
    pub http_port: Option<u16>,
    pub destinations: Vec<DestinationSpec>,
}

impl ClientSpec {
    /// Resolve the settings against the key list. `None` when a destination's
    /// key is missing or has lost its secret — see
    /// [`ClientSettings::start_blocker`], which says so in words.
    pub fn resolve(client: &ClientSettings, keys: &[AuthKey]) -> Option<Self> {
        let destinations = client
            .destinations
            .iter()
            .map(|destination| {
                let key = config::find_key(keys, &destination.auth_key_id)?;
                (!key.secret.is_empty()).then(|| DestinationSpec {
                    destination: destination.clone(),
                    auth_secret: key.secret.clone(),
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self {
            socks_port: client.socks_port,
            http_port: client.http_port,
            destinations,
        })
    }
}

/// A client session to start: what it runs with, and its forwards.
type ClientStart = Box<(ClientSpec, Vec<PortForward>)>;

enum Command {
    /// Start the client session (the auth secrets travel inside the spec).
    StartClient(ClientStart),
    /// Stop the running client and start this one once it has stopped — how
    /// changed settings are applied. A restart already waiting for its stop
    /// takes this newer start instead; a client that is not running, or is
    /// stopping for good, is left alone.
    RestartClient(ClientStart),
    StopClient,
    /// Replace the desired forward list (the UI sends the full list after
    /// every add/edit/delete/toggle); applied live mid-session.
    SetForwards(Vec<PortForward>),
    /// Ask the destination named by this host for one connection attempt now,
    /// instead of waiting for its first use.
    ConnectNow(String),
    /// One-shot request for a destination's current iroh connection path(s),
    /// by host, answered on the reply channel (the UI's connection-path CTA).
    /// Empty when no session is running or the destination is not connected.
    /// A `std` channel (not tokio `oneshot`) so the GUI caller can wait with a
    /// bounded [`std::sync::mpsc::Receiver::recv_timeout`].
    QueryConnPath(String, std::sync::mpsc::Sender<ConnectionSnapshot>),
    /// Start the server session (its identity secret travels inside).
    StartServer(Box<ServerConfig>),
    /// Stop the running server and start this config once it has stopped —
    /// how changed settings are applied. A restart already waiting for its
    /// stop takes this newer config instead; a server that is not running, or
    /// is stopping for good, is left alone.
    RestartServer(Box<ServerConfig>),
    StopServer,
    /// Stop the server and reset its snapshot once it has stopped (the
    /// server was deleted).
    RemoveServer,
    Shutdown,
}

enum SessionCmd {
    Stop,
    SetForwards(Vec<PortForward>),
    ConnectNow(String),
    /// Answer the reply channel with the destination's path snapshot, once.
    QueryConnPath(String, std::sync::mpsc::Sender<ConnectionSnapshot>),
}

type SharedClientSnapshot = Arc<Mutex<ClientSnapshot>>;

/// The shared client snapshot, written by the session task.
#[derive(Clone)]
struct ClientSlot {
    shared: SharedClientSnapshot,
}

impl ClientSlot {
    fn update<F: FnOnce(&mut ClientSnapshot)>(&self, f: F) {
        let mut snapshot = match self.shared.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        f(&mut snapshot);
    }

    /// End a session that could not start: nothing is listening.
    fn fail(&self, reason: String) {
        log::error!("{reason}");
        self.update(|s| {
            *s = ClientSnapshot {
                phase: ClientPhase::Failed,
                last_error: Some(reason),
                ..ClientSnapshot::default()
            };
        });
    }
}

pub struct Controller {
    tx: mpsc::Sender<Command>,
    client_shared: SharedClientSnapshot,
    server_shared: SharedServerSnapshot,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Controller {
    pub fn start() -> Self {
        let (tx, rx) = mpsc::channel(16);
        let client_shared: SharedClientSnapshot = Arc::default();
        let worker_client_shared = client_shared.clone();
        let server_shared: SharedServerSnapshot = Arc::default();
        let worker_server_shared = server_shared.clone();
        // The supervisor only routes commands; sessions get their own
        // runtimes, so a single-threaded one suffices here.
        let thread = std::thread::Builder::new()
            .name("tunnel".into())
            .spawn(move || {
                match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                    Ok(rt) => rt.block_on(run_loop(rx, worker_client_shared, worker_server_shared)),
                    Err(e) => log::error!("Failed to build the Tokio runtime: {e:#}"),
                }
            })
            .expect("spawn tunnel thread");
        Self {
            tx,
            client_shared,
            server_shared,
            thread: Some(thread),
        }
    }

    pub fn client_snapshot(&self) -> ClientSnapshot {
        self.client_shared
            .lock()
            .map(|s| s.clone())
            .unwrap_or_else(|poisoned| poisoned.into_inner().clone())
    }

    pub fn server_snapshot(&self) -> ServerSnapshot {
        self.server_shared
            .lock()
            .map(|s| s.clone())
            .unwrap_or_else(|poisoned| poisoned.into_inner().clone())
    }

    pub fn start_server(&self, server: ServerConfig) {
        let _ = self.tx.blocking_send(Command::StartServer(Box::new(server)));
    }

    pub fn restart_server(&self, server: ServerConfig) {
        let _ = self.tx.blocking_send(Command::RestartServer(Box::new(server)));
    }

    pub fn stop_server(&self) {
        let _ = self.tx.blocking_send(Command::StopServer);
    }

    pub fn remove_server(&self) {
        let _ = self.tx.blocking_send(Command::RemoveServer);
    }

    pub fn start_client(&self, spec: ClientSpec, forwards: Vec<PortForward>) {
        let _ = self
            .tx
            .blocking_send(Command::StartClient(Box::new((spec, forwards))));
    }

    pub fn restart_client(&self, spec: ClientSpec, forwards: Vec<PortForward>) {
        let _ = self
            .tx
            .blocking_send(Command::RestartClient(Box::new((spec, forwards))));
    }

    pub fn stop_client(&self) {
        let _ = self.tx.blocking_send(Command::StopClient);
    }

    pub fn set_forwards(&self, forwards: Vec<PortForward>) {
        let _ = self.tx.blocking_send(Command::SetForwards(forwards));
    }

    pub fn connect_now(&self, host: &str) {
        let _ = self.tx.blocking_send(Command::ConnectNow(host.into()));
    }

    /// Fetch a destination's current iroh connection path(s), once. Returns
    /// empty when no session is running, the destination is not connected, the
    /// request can't be sent, or the session doesn't answer within
    /// [`CONN_PATH_TIMEOUT`]. The round-trip is a channel hop (normally
    /// sub-millisecond), but the deadline is what guarantees a wedged session
    /// can never freeze the GUI thread calling this from `App::update`.
    pub fn query_conn_path(&self, host: &str) -> ConnectionSnapshot {
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        if self
            .tx
            .blocking_send(Command::QueryConnPath(host.into(), reply_tx))
            .is_err()
        {
            return ConnectionSnapshot::default();
        }
        reply_rx.recv_timeout(CONN_PATH_TIMEOUT).unwrap_or_default()
    }

    /// Stop both sessions and join the worker thread (blocks briefly for the
    /// bounded graceful endpoint closes).
    pub fn shutdown(&mut self) {
        let _ = self.tx.blocking_send(Command::Shutdown);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Bind a local listener, mapping the common taken-port case to a clear
/// session error.
async fn bind_local(addr: SocketAddr, label: &str) -> Result<tokio::net::TcpListener, String> {
    tokio::net::TcpListener::bind(addr).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::AddrInUse {
            format!("{label} port {} is already in use — another flextunnel?", addr.port())
        } else {
            format!("Failed to bind the {label} listener on {addr}: {e}")
        }
    })
}

struct SessionHandle {
    tx: mpsc::Sender<SessionCmd>,
    /// Resolves when the session's thread finishes. The session keeps its
    /// command receiver until then, so `tx.is_closed()` also means "done".
    done: tokio::sync::oneshot::Receiver<()>,
}

/// Spawn the client session on its own OS thread with its own runtime, all
/// threads named [`CLIENT_THREAD_NAME`] so the logger can attribute every line
/// the session emits. `None` when the thread could not be spawned (the
/// snapshot is set to Failed instead).
fn spawn_client(
    spec: ClientSpec,
    forwards: Vec<PortForward>,
    shared: &SharedClientSnapshot,
) -> Option<SessionHandle> {
    let (tx, session_rx) = mpsc::channel(8);
    let (done_tx, done) = tokio::sync::oneshot::channel();
    let slot = ClientSlot {
        shared: shared.clone(),
    };
    let error_slot = slot.clone();
    let spawned = std::thread::Builder::new()
        .name(CLIENT_THREAD_NAME.into())
        .spawn(move || {
            // One worker is plenty for the client; multi_thread (rather than
            // current_thread) keeps the runtime semantics identical to the
            // other flextunnel binaries.
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .thread_name(CLIENT_THREAD_NAME)
                .enable_all()
                .build();
            match runtime {
                Ok(rt) => rt.block_on(run_client(spec, forwards, session_rx, slot)),
                Err(e) => slot.fail(format!("Failed to build the client runtime: {e:#}")),
            }
            let _ = done_tx.send(());
        });
    match spawned {
        Ok(_) => Some(SessionHandle { tx, done }),
        Err(e) => {
            error_slot.fail(format!("Failed to spawn the client thread: {e:#}"));
            None
        }
    }
}

/// Resolves when `handle`'s session has ended, if a start is waiting for that
/// (`waiting`); otherwise never.
async fn ended<T>(done: Option<&mut tokio::sync::oneshot::Receiver<T>>, waiting: bool) {
    match done {
        Some(done) if waiting => {
            let _ = done.await;
        }
        _ => std::future::pending().await,
    }
}

/// Supervisor: routes client commands to the client session and server
/// commands to the server session.
async fn run_loop(
    mut rx: mpsc::Receiver<Command>,
    client_shared: SharedClientSnapshot,
    server_shared: SharedServerSnapshot,
) {
    let mut client: Option<SessionHandle> = None;
    // A restart's start, run once the old session has ended: until then it
    // still holds the local ports and its connections to the servers.
    let mut pending_client: Option<ClientStart> = None;
    // Whether the current client session was told to stop: it reads no
    // further commands, and a start meanwhile waits in `pending_client`.
    let mut client_stopping = false;
    let mut server: Option<ServerHandle> = None;
    // A restart's config, started once the old session has ended: until its
    // endpoint is closed it holds the identity and its server lock.
    let mut pending_start: Option<ServerConfig> = None;
    // Whether the current server session was told to stop (or remove): a
    // start meanwhile waits for it in `pending_start` instead of being dropped.
    let mut stopping = false;
    loop {
        // An ended session drops its receiver, closing the sender.
        if client.as_ref().is_some_and(|handle| handle.tx.is_closed()) {
            client = None;
        }
        if client.is_none() {
            client_stopping = false;
            if let Some(start) = pending_client.take() {
                let (spec, forwards) = *start;
                client = spawn_client(spec, forwards, &client_shared);
            }
        }
        if server.as_ref().is_some_and(|handle| handle.tx.is_closed()) {
            server = None;
        }
        if server.is_none() {
            stopping = false;
        }
        if server.is_none()
            && let Some(config) = pending_start.take()
        {
            server = server_session::spawn_server(config, &server_shared);
        }
        // Waiting out a restart's stop: wake when the old session ends, so
        // the new one starts without waiting for the next command.
        let cmd = tokio::select! {
            cmd = rx.recv() => cmd,
            _ = ended(client.as_mut().map(|h| &mut h.done), pending_client.is_some()) => continue,
            _ = ended(server.as_mut().map(|h| &mut h.done), pending_start.is_some()) => continue,
        };
        if client.as_ref().is_some_and(|handle| handle.tx.is_closed()) {
            client = None;
            client_stopping = false;
        }
        if server.as_ref().is_some_and(|handle| handle.tx.is_closed()) {
            server = None;
            stopping = false;
        }
        // The session reading commands, if there is one: a stopping session
        // reads no more, so nothing is queued behind its close.
        let live_client = client.as_ref().filter(|_| !client_stopping);
        match cmd {
            Some(Command::StartClient(start)) => match &client {
                // Still closing (disabled and enabled again in quick
                // succession): start once it has.
                Some(_) if client_stopping => pending_client = Some(start),
                Some(_) => log::warn!("The client is still running"),
                None => {
                    // This start is the newest word: a restart whose old
                    // session ended just now must not start after it.
                    pending_client = None;
                    let (spec, forwards) = *start;
                    client = spawn_client(spec, forwards, &client_shared);
                }
            },
            Some(Command::RestartClient(start)) => match &client {
                // Decided here rather than from the UI's snapshot, which lags
                // the session by a poll.
                Some(_) if client_stopping => {
                    if pending_client.is_some() {
                        pending_client = Some(start);
                    }
                }
                Some(handle) => {
                    let _ = handle.tx.send(SessionCmd::Stop).await;
                    client_stopping = true;
                    pending_client = Some(start);
                }
                None => {}
            },
            Some(Command::StopClient) => {
                // Also calls off a restart that is waiting for the old stop.
                pending_client = None;
                if let Some(handle) = live_client {
                    let _ = handle.tx.send(SessionCmd::Stop).await;
                    client_stopping = true;
                }
            }
            Some(Command::SetForwards(forwards)) => match (live_client, &mut pending_client) {
                // A restart in flight starts with the newer list.
                (_, Some(start)) => start.1 = forwards,
                (Some(handle), None) => {
                    let _ = handle.tx.send(SessionCmd::SetForwards(forwards)).await;
                }
                // No session: nothing to do — the next start carries them.
                (None, None) => {}
            },
            Some(Command::ConnectNow(host)) => {
                if let Some(handle) = live_client {
                    let _ = handle.tx.send(SessionCmd::ConnectNow(host)).await;
                }
            }
            Some(Command::QueryConnPath(host, reply)) => {
                if let Some(handle) = live_client {
                    let _ = handle.tx.send(SessionCmd::QueryConnPath(host, reply)).await;
                }
                // No session: `reply` drops, and the caller gets an empty one.
            }
            Some(Command::StartServer(config)) => {
                match &server {
                    // A server still stopping holds the identity and the
                    // per-user lock until its endpoint is closed: start once
                    // it has (e.g. disabled and enabled again in quick
                    // succession).
                    Some(_) if stopping => pending_start = Some(*config),
                    Some(_) => log::warn!("The server is still running"),
                    None => {
                        // As for the client: no stale restart behind this.
                        pending_start = None;
                        server = server_session::spawn_server(*config, &server_shared);
                    }
                }
            }
            Some(Command::RestartServer(config)) => match &server {
                // Decided here rather than from the UI's snapshot, which reads
                // Stopped between a restart's two sessions: a change made
                // meanwhile (a client revoked) must still reach the new one.
                Some(_) if stopping => {
                    if pending_start.is_some() {
                        pending_start = Some(*config);
                    }
                }
                Some(handle) => {
                    let _ = handle.tx.send(ServerCmd::Stop).await;
                    stopping = true;
                    pending_start = Some(*config);
                }
                None => {}
            },
            Some(Command::StopServer) => {
                // Also calls off a restart that is waiting for the old stop.
                pending_start = None;
                if let Some(handle) = &server {
                    let _ = handle.tx.send(ServerCmd::Stop).await;
                    stopping = true;
                }
            }
            Some(Command::RemoveServer) => {
                pending_start = None;
                stopping = server.is_some();
                match &server {
                    // The handle stays until the session ends, so a server set up
                    // again meanwhile can't start while this one still holds the
                    // lock; the session resets the snapshot as its final write.
                    Some(handle) => {
                        // A closed channel means the session already made its
                        // final write (it holds the receiver until then).
                        if handle.tx.send(ServerCmd::Remove).await.is_err() {
                            reset_server_snapshot(&server_shared);
                        }
                    }
                    None => reset_server_snapshot(&server_shared),
                }
            }
            Some(Command::Shutdown) | None => break,
        }
    }
    // Bounded grace so quitting stays responsive: ask both sessions to stop,
    // give the graceful endpoint closes a shared deadline, then return — the
    // process is going away anyway.
    if let Some(handle) = client.as_ref().filter(|_| !client_stopping) {
        let _ = handle.tx.send(SessionCmd::Stop).await;
    }
    if let Some(handle) = &server {
        let _ = handle.tx.send(ServerCmd::Shutdown).await;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    if let Some(handle) = client {
        let _ = tokio::time::timeout_at(deadline, handle.done).await;
    }
    if let Some(handle) = server {
        let _ = tokio::time::timeout_at(deadline, handle.done).await;
    }
}

fn reset_server_snapshot(shared: &SharedServerSnapshot) {
    let mut snapshot = match shared.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    *snapshot = ServerSnapshot::default();
}

/// The core's configuration of one destination, or why its settings cannot be
/// used. The forms check all of it on save, but a hand-edited file or a
/// corrupted keychain entry can still surface here.
fn destination_config(spec: &DestinationSpec) -> Result<DestinationConfig, String> {
    let destination = &spec.destination;
    let host = &destination.host;
    let relay = RelayConfig::from_urls_with_token(
        &destination.relay_urls,
        destination.relay_auth_token.clone(),
    )
    .map_err(|e| format!("Destination \"{host}\": invalid relay configuration: {e:#}"))?;
    let client_key = flextunnel_core::auth::ClientKey::from_secret_str(spec.auth_secret.trim())
        .map_err(|e| format!("Destination \"{host}\": invalid client auth key: {e:#}"))?;
    let server_id = destination
        .server_node_id
        .trim()
        .parse()
        .map_err(|e| format!("Destination \"{host}\": invalid server node id: {e}"))?;
    Ok(DestinationConfig {
        host: host.clone(),
        server_id,
        auth: ClientAuth::Key(Box::new(client_key)),
        relay,
        routed_domains: destination.routed_domains.clone(),
        routed_cidrs: destination.routed_cidrs.clone(),
        keep_connected: false,
    })
}

async fn run_client(
    spec: ClientSpec,
    mut forwards: Vec<PortForward>,
    mut rx: mpsc::Receiver<SessionCmd>,
    slot: ClientSlot,
) {
    let loopback = |port: u16| SocketAddr::from(([127, 0, 0, 1], port));
    let socks_addr = spec.socks_port.map(loopback);
    let http_addr = spec.http_port.map(loopback);
    let spec = Arc::new(spec);
    slot.update(|s| {
        *s = ClientSnapshot {
            phase: ClientPhase::Starting,
            spec: Some(spec.clone()),
            ..ClientSnapshot::default()
        };
    });

    // Everything the session needs is validated before anything is bound, so
    // a bad setting fails the session cleanly rather than panicking.
    let destinations = match spec.destinations.iter().map(destination_config).collect() {
        Ok(destinations) => destinations,
        Err(reason) => return slot.fail(reason),
    };
    // Building the client validates the hosts and routes together and dials
    // nothing.
    let client = match ProxyClient::new(ClientConfig {
        destinations,
        idle_timeout: Some(DEFAULT_IDLE_TIMEOUT),
    }) {
        Ok(client) => client,
        Err(e) => return slot.fail(e.to_string()),
    };

    // Bind enabled proxy front-ends before any forward listener exists. A
    // taken proxy port fails the session before forwards come up.
    let listeners = async {
        let socks = match socks_addr {
            Some(addr) => Some(bind_local(addr, "SOCKS").await?),
            None => None,
        };
        let http = match http_addr {
            Some(addr) => Some(bind_local(addr, "HTTP").await?),
            None => None,
        };
        Ok::<_, String>((socks, http))
    };
    let (socks_listener, http_listener) = match listeners.await {
        Ok(listeners) => listeners,
        // No endpoint exists yet, so there is nothing to close.
        Err(reason) => return slot.fail(reason),
    };

    // Forwards listen for the whole session, whatever the connections are
    // doing (a forwarded connection connects its destination on demand); they
    // die with the manager when the session ends.
    let mut fwd_mgr = ForwardManager::new(
        tokio::runtime::Handle::current(),
        client.dialer(),
        &forwards,
    );

    // Boxed so it can be dropped before the endpoints are closed below.
    let mut run = Box::pin(client.run(LocalListeners::tcp(socks_listener, http_listener)));
    let mut ticker = tokio::time::interval(Duration::from_millis(500));
    log::info!("The client is running with {} destination(s)", spec.destinations.len());
    slot.update(|s| {
        s.phase = ClientPhase::Running;
        s.running_since = Some(Instant::now());
    });

    // How the session ended, for its final snapshot.
    let failure = loop {
        tokio::select! {
            res = &mut run => break match res {
                Ok(()) => None,
                Err(e) => {
                    log::error!("Client error: {e}");
                    Some(e.to_string())
                }
            },
            _ = ticker.tick() => {
                let destinations = client.status().destinations;
                let statuses = fwd_mgr.statuses();
                slot.update(|s| {
                    s.destinations = destinations;
                    s.forwards = statuses;
                });
            }
            cmd = rx.recv() => match cmd {
                Some(SessionCmd::SetForwards(f)) => {
                    forwards = f;
                    fwd_mgr.apply(&forwards);
                    let statuses = fwd_mgr.statuses();
                    slot.update(|s| s.forwards = statuses);
                }
                Some(SessionCmd::ConnectNow(host)) => {
                    if !client.dialer().warm(&host) {
                        log::warn!("No destination \"{host}\" in the running client");
                    }
                }
                Some(SessionCmd::QueryConnPath(host, reply)) => {
                    let _ = reply.send(client.connection_snapshot(&host).await);
                }
                Some(SessionCmd::Stop) | None => {
                    log::info!("Stopping the client");
                    break None;
                }
            }
        }
    };

    // The select loop is done with `run`; dropping it cancels the client.
    // Tear the forward listeners down with the session so their rows read
    // "stopped" immediately, then close the endpoints in use gracefully before
    // they are dropped (see the CLI's close_or_exit for why an ungraceful drop
    // is fatal under panic=abort). The command receiver lives until this
    // returns, so the supervisor starts nothing new before the close is done.
    slot.update(|s| {
        s.phase = ClientPhase::Stopping;
        s.spec = None;
        s.running_since = None;
        s.destinations.clear();
        s.forwards.clear();
    });
    drop(fwd_mgr);
    drop(run);
    if tokio::time::timeout(SESSION_CLOSE_TIMEOUT, client.close())
        .await
        .is_err()
    {
        log::warn!("Closing the client's endpoints is taking too long; giving up");
    }
    slot.update(|s| {
        *s = match failure {
            Some(reason) => ClientSnapshot {
                phase: ClientPhase::Failed,
                last_error: Some(reason),
                ..ClientSnapshot::default()
            },
            None => ClientSnapshot::default(),
        };
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: &str, secret: &str) -> AuthKey {
        AuthKey {
            id: id.into(),
            name: format!("key {id}"),
            public_key: format!("ed25519-pub:{id}"),
            secret: secret.into(),
        }
    }

    fn destination(host: &str, auth_key_id: &str) -> Destination {
        Destination {
            id: host.into(),
            host: host.into(),
            server_node_id: format!("node-{host}"),
            routed_domains: Vec::new(),
            routed_cidrs: Vec::new(),
            auth_key_id: auth_key_id.into(),
            relay_urls: Vec::new(),
            relay_auth_token: None,
        }
    }

    #[test]
    fn a_spec_carries_each_destinations_key_secret() {
        let keys = [key("k1", "secret-1"), key("k2", "secret-2")];
        let client = ClientSettings {
            socks_port: Some(1085),
            http_port: None,
            destinations: vec![destination("a.internal", "k2"), destination("b.internal", "k1")],
            ..ClientSettings::default()
        };
        let spec = ClientSpec::resolve(&client, &keys).expect("every key resolves");
        assert_eq!((spec.socks_port, spec.http_port), (Some(1085), None));
        let secrets: Vec<&str> = spec.destinations.iter().map(|d| d.auth_secret.as_str()).collect();
        assert_eq!(secrets, ["secret-2", "secret-1"]);

        // A missing key, or one whose secret was lost, resolves to nothing.
        assert!(ClientSpec::resolve(&client, &keys[..1]).is_none());
        assert!(ClientSpec::resolve(&client, &[key("k1", ""), key("k2", "s")]).is_none());
    }

    /// What tells the UI a restart is due: the ports, the destinations and the
    /// secrets they authenticate with — not the forwards, which apply live.
    #[test]
    fn a_spec_changes_with_what_a_session_keeps() {
        let keys = [key("k1", "secret-1")];
        let client = ClientSettings {
            destinations: vec![destination("a.internal", "k1")],
            ..ClientSettings::default()
        };
        let spec = ClientSpec::resolve(&client, &keys).unwrap();

        let mut with_forward = client.clone();
        with_forward.forwards.push(PortForward {
            id: "f".into(),
            label: String::new(),
            local_port: 8080,
            remote_host: "a.internal".into(),
            remote_port: 80,
            enabled: true,
        });
        with_forward.enabled = false;
        assert!(ClientSpec::resolve(&with_forward, &keys).unwrap() == spec);

        let mut other_port = client.clone();
        other_port.http_port = Some(18080);
        assert!(ClientSpec::resolve(&other_port, &keys).unwrap() != spec);
        let mut routed = client.clone();
        routed.destinations[0].routed_domains.push("*.corp.example".into());
        assert!(ClientSpec::resolve(&routed, &keys).unwrap() != spec);
        assert!(ClientSpec::resolve(&client, &[key("k1", "rotated")]).unwrap() != spec);
    }

    #[test]
    fn unusable_destination_settings_name_the_destination() {
        let spec = |destination: Destination, secret: &str| DestinationSpec {
            destination,
            auth_secret: secret.into(),
        };
        let secret = flextunnel_core::auth::ClientKey::generate().unwrap().secret_str();
        let server_id = flextunnel_core::iroh::SecretKey::generate().public().to_string();
        let mut good = destination("a.internal", "k1");
        good.server_node_id = server_id.clone();
        assert!(destination_config(&spec(good.clone(), &secret)).is_ok());

        let err = |spec: DestinationSpec| destination_config(&spec).err().expect("rejected");
        assert!(err(spec(good.clone(), "not-a-key")).contains("\"a.internal\": invalid client auth key"));
        let mut bad_server = good.clone();
        bad_server.server_node_id = "nope".into();
        assert!(err(spec(bad_server, &secret)).contains("invalid server node id"));
        let mut one_relay = good;
        one_relay.relay_urls = vec!["https://relay.example".into()];
        assert!(err(spec(one_relay, &secret)).contains("invalid relay configuration"));
    }
}
