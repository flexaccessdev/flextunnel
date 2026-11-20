//! Background tunnel controller: a supervisor thread routing UI commands to
//! one session per connected profile, each on its own OS thread running its
//! own Tokio runtime whose threads are named `tunnel-<profile>` — so every
//! log line a session emits (core internals included) is attributed to its
//! profile by thread name (see `logging`). Status is published as per-profile
//! snapshots the UI polls each frame. Each session is one client with one
//! destination — the profile's server — which it connects to on demand: once
//! when the session starts, so pressing Connect shows whether the server is
//! reachable, and from then on whenever something is sent to it after the
//! connection idled out. Each session owns its `ProxyClient` future, so
//! dropping it (disconnect/shutdown) tears down the accept loops and the
//! destination's manager together, followed by a graceful endpoint close. The app's server ([`crate::server_session`]) is routed through the
//! same supervisor, so one controller owns every session and one shutdown
//! stops them all.

use crate::config::{Profile, ServerConfig};
use crate::server_session::{self, ServerCmd, ServerHandle, ServerSnapshot, SharedServerSnapshot};
use flextunnel_core::forwards::{ForwardManager, ForwardStatus, PortForward};
use flextunnel_core::config::DEFAULT_IDLE_TIMEOUT;
use flextunnel_core::proxy::{
    ClientAuth, ClientConfig, DestinationConfig, DestinationState, LocalListeners, ProxyClient,
};
use flextunnel_core::transport::endpoint::RelayConfig;
use flextunnel_core::transport::paths::ConnectionSnapshot;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

pub type ProfileId = String;

/// Bound on the GUI thread's wait for a connection-path reply (see
/// [`Controller::query_conn_path`]). Must exceed the custom-relay `/healthz`
/// probe budget (relays checked in parallel, ~3s worst case) the session now
/// awaits before replying; it exists to fail open (empty result) rather than
/// hang if a session stalls.
const CONN_PATH_TIMEOUT: Duration = Duration::from_secs(5);

/// Bound on a session's graceful endpoint close at teardown. The close waits
/// out an endpoint still being built (see `ProxyClient::close`), which a
/// Disconnect or a quit during a slow dial must not hang behind; an ordinary
/// close finishes well inside it.
const SESSION_CLOSE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase {
    /// No session: the profile is not connected and nothing is listening.
    Idle,
    Connecting,
    Connected,
    /// The session is up — proxy and forwards are listening — and the
    /// server connection is closed for now: it idled out, or dropped with
    /// nothing using it. The next use connects it again.
    Standby,
    /// A connection attempt failed and is being retried for requests that
    /// are still waiting.
    Reconnecting,
    Failed,
}

#[derive(Clone)]
pub struct Snapshot {
    pub phase: Phase,
    pub connected_since: Option<Instant>,
    pub socks_addr: Option<SocketAddr>,
    pub http_addr: Option<SocketAddr>,
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
            last_error: None,
            forwards: Vec::new(),
        }
    }
}

impl Snapshot {
    /// Shared idle snapshot for profiles that never ran a session, so views
    /// can borrow a `&Snapshot` uniformly.
    pub fn empty() -> &'static Snapshot {
        static EMPTY: std::sync::OnceLock<Snapshot> = std::sync::OnceLock::new();
        EMPTY.get_or_init(Snapshot::default)
    }
}

enum Command {
    /// Start a session for the profile, authenticating with the given secret
    /// key (resolved by the UI from the profile's shared auth-key reference).
    Connect(Box<Profile>, String),
    Disconnect(ProfileId),
    /// Replace one profile's desired forward list (the UI sends the full list
    /// after every add/edit/delete/toggle); applied live mid-session.
    SetForwards(ProfileId, Vec<PortForward>),
    /// Disconnect and drop the profile's snapshot slot (profile deleted).
    RemoveProfile(ProfileId),
    /// One-shot request for the profile's current iroh connection path(s),
    /// answered on the reply channel (the UI's connection-path CTA). Empty when
    /// no session is running. A `std` channel (not tokio `oneshot`) so the GUI
    /// caller can wait with a bounded [`std::sync::mpsc::Receiver::recv_timeout`].
    QueryConnPath(ProfileId, std::sync::mpsc::Sender<ConnectionSnapshot>),
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
    Disconnect,
    SetForwards(Vec<PortForward>),
    /// Answer the reply channel with the live connection's path snapshot, once.
    QueryConnPath(std::sync::mpsc::Sender<ConnectionSnapshot>),
    Shutdown,
}

type SharedSnapshots = Arc<Mutex<HashMap<ProfileId, Snapshot>>>;

/// One profile's slot in the shared snapshot map, written by its session task.
#[derive(Clone)]
struct SnapshotSlot {
    shared: SharedSnapshots,
    id: ProfileId,
}

impl SnapshotSlot {
    fn update<F: FnOnce(&mut Snapshot)>(&self, f: F) {
        let mut map = match self.shared.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        f(map.entry(self.id.clone()).or_default());
    }
}

pub struct Controller {
    tx: mpsc::Sender<Command>,
    shared: SharedSnapshots,
    server_shared: SharedServerSnapshot,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Controller {
    pub fn start() -> Self {
        let (tx, rx) = mpsc::channel(16);
        let shared: SharedSnapshots = Arc::new(Mutex::new(HashMap::new()));
        let worker_shared = shared.clone();
        let server_shared: SharedServerSnapshot = Arc::default();
        let worker_server_shared = server_shared.clone();
        // The supervisor only routes commands; sessions get their own
        // runtimes, so a single-threaded one suffices here.
        let thread = std::thread::Builder::new()
            .name("tunnel".into())
            .spawn(move || {
                match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                    Ok(rt) => rt.block_on(run_loop(rx, worker_shared, worker_server_shared)),
                    Err(e) => log::error!("Failed to build the Tokio runtime: {e:#}"),
                }
            })
            .expect("spawn tunnel thread");
        Self {
            tx,
            shared,
            server_shared,
            thread: Some(thread),
        }
    }

    pub fn snapshots(&self) -> HashMap<ProfileId, Snapshot> {
        self.shared
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

    pub fn connect(&self, profile: Profile, auth_key: String) {
        let _ = self
            .tx
            .blocking_send(Command::Connect(Box::new(profile), auth_key));
    }

    pub fn disconnect(&self, id: &str) {
        let _ = self.tx.blocking_send(Command::Disconnect(id.into()));
    }

    pub fn set_forwards(&self, id: &str, forwards: Vec<PortForward>) {
        let _ = self
            .tx
            .blocking_send(Command::SetForwards(id.into(), forwards));
    }

    pub fn remove_profile(&self, id: &str) {
        let _ = self.tx.blocking_send(Command::RemoveProfile(id.into()));
    }

    /// Fetch the profile's current iroh connection path(s), once. Returns empty
    /// when no session is running, the request can't be sent, or the session
    /// doesn't answer within [`CONN_PATH_TIMEOUT`]. The round-trip is a channel
    /// hop (normally sub-millisecond), but the deadline is what guarantees a
    /// wedged session can never freeze the GUI thread calling this from
    /// `App::update`.
    pub fn query_conn_path(&self, id: &str) -> ConnectionSnapshot {
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        if self
            .tx
            .blocking_send(Command::QueryConnPath(id.into(), reply_tx))
            .is_err()
        {
            return ConnectionSnapshot::default();
        }
        reply_rx.recv_timeout(CONN_PATH_TIMEOUT).unwrap_or_default()
    }

    /// Stop all sessions and join the worker thread (blocks briefly for the
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
    /// Resolves when the session's thread finishes (its receiver dropping
    /// also marks `tx` closed).
    done: tokio::sync::oneshot::Receiver<()>,
    /// For the supervisor's duplicate-server guard and its error message.
    server_node_id: String,
    profile_name: String,
}

/// Spawn one profile's session on its own OS thread with its own runtime, all
/// threads named `tunnel-<profile>` so the logger can attribute every line
/// the session emits. `None` when the thread could not be spawned (the
/// snapshot is set to Failed instead).
fn spawn_session(
    profile: Profile,
    auth_key: String,
    shared: &SharedSnapshots,
) -> Option<SessionHandle> {
    let (tx, session_rx) = mpsc::channel(8);
    let (done_tx, done) = tokio::sync::oneshot::channel();
    let slot = SnapshotSlot {
        shared: shared.clone(),
        id: profile.id.clone(),
    };
    let error_slot = slot.clone();
    let server_node_id = profile.server_node_id.clone();
    let profile_name = profile.name.clone();
    let thread_name = format!("tunnel-{}", profile.name);
    let runtime_name = thread_name.clone();
    let spawned = std::thread::Builder::new().name(thread_name).spawn(move || {
        // One worker is plenty for a tunnel session; multi_thread (rather
        // than current_thread) keeps the runtime semantics identical to the
        // other flextunnel binaries.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name(runtime_name)
            .enable_all()
            .build();
        match runtime {
            Ok(rt) => rt.block_on(run_session(profile, auth_key, session_rx, slot)),
            Err(e) => {
                log::error!("Failed to build the session runtime: {e:#}");
                slot.update(|s| {
                    s.phase = Phase::Failed;
                    s.last_error = Some(format!("Failed to start: {e:#}"));
                });
            }
        }
        let _ = done_tx.send(());
    });
    match spawned {
        Ok(_) => Some(SessionHandle {
            tx,
            done,
            server_node_id,
            profile_name,
        }),
        Err(e) => {
            log::error!("Failed to spawn the session thread: {e:#}");
            error_slot.update(|s| {
                s.phase = Phase::Failed;
                s.last_error = Some(format!("Failed to start: {e:#}"));
            });
            None
        }
    }
}

/// Supervisor: routes profile-scoped commands to per-profile sessions and
/// server commands to the server session.
async fn run_loop(
    mut rx: mpsc::Receiver<Command>,
    shared: SharedSnapshots,
    server_shared: SharedServerSnapshot,
) {
    let mut sessions: HashMap<ProfileId, SessionHandle> = HashMap::new();
    let mut server: Option<ServerHandle> = None;
    // A restart's config, started once the old session has ended: until its
    // endpoint is closed it holds the identity and its server lock.
    let mut pending_start: Option<ServerConfig> = None;
    // Whether the current server session was told to stop (or remove): a
    // start meanwhile waits for it in `pending_start` instead of being dropped.
    let mut stopping = false;
    loop {
        // An ended session drops its receiver, closing the sender.
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
        let cmd = match server.as_mut() {
            // Waiting out a restart's stop: wake when the old session ends,
            // so the new one starts without waiting for the next command.
            Some(handle) if pending_start.is_some() => tokio::select! {
                cmd = rx.recv() => cmd,
                _ = &mut handle.done => continue,
            },
            _ => rx.recv().await,
        };
        sessions.retain(|_, handle| !handle.tx.is_closed());
        if server.as_ref().is_some_and(|handle| handle.tx.is_closed()) {
            server = None;
            stopping = false;
        }
        match cmd {
            Some(Command::StartServer(config)) => {
                match &server {
                    // A server still stopping holds the identity and the
                    // per-user lock until its endpoint is closed: start once
                    // it has (e.g. disabled and enabled again in quick
                    // succession).
                    Some(_) if stopping => pending_start = Some(*config),
                    Some(_) => log::warn!("The server is still running"),
                    None => server = server_session::spawn_server(*config, &server_shared),
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
            Some(Command::Connect(profile, auth_key)) => {
                if sessions.contains_key(&profile.id) {
                    log::warn!("Profile \"{}\" is already running a session", profile.name);
                    continue;
                }
                // Backend duplicate-server guard: whatever path asked for the
                // connection, never run two sessions against one server.
                if let Some(other) = sessions
                    .values()
                    .find(|h| h.server_node_id == profile.server_node_id)
                {
                    let reason = format!(
                        "Profile \"{}\" is already connected to this server",
                        other.profile_name
                    );
                    log::error!("Not connecting \"{}\": {reason}", profile.name);
                    SnapshotSlot {
                        shared: shared.clone(),
                        id: profile.id.clone(),
                    }
                    .update(|s| {
                        *s = Snapshot {
                            phase: Phase::Failed,
                            last_error: Some(reason),
                            ..Snapshot::default()
                        };
                    });
                    continue;
                }
                let id = profile.id.clone();
                if let Some(handle) = spawn_session(*profile, auth_key, &shared) {
                    sessions.insert(id, handle);
                }
            }
            Some(Command::Disconnect(id)) => {
                if let Some(handle) = sessions.get(&id) {
                    let _ = handle.tx.send(SessionCmd::Disconnect).await;
                }
            }
            Some(Command::SetForwards(id, forwards)) => {
                if let Some(handle) = sessions.get(&id) {
                    let _ = handle.tx.send(SessionCmd::SetForwards(forwards)).await;
                }
                // No session: nothing to do — forwards travel inside the
                // profile on the next Connect.
            }
            Some(Command::QueryConnPath(id, reply)) => {
                if let Some(handle) = sessions.get(&id) {
                    let _ = handle.tx.send(SessionCmd::QueryConnPath(reply)).await;
                }
                // No session: `reply` drops, and the caller gets an empty Vec.
            }
            Some(Command::RemoveProfile(id)) => {
                if let Some(handle) = sessions.remove(&id) {
                    let _ = handle.tx.send(SessionCmd::Disconnect).await;
                    // Drop the slot only after the session's final writes, or
                    // they would recreate it.
                    let shared = shared.clone();
                    tokio::spawn(async move {
                        let _ = handle.done.await;
                        remove_slot(&shared, &id);
                    });
                } else {
                    remove_slot(&shared, &id);
                }
            }
            Some(Command::Shutdown) | None => break,
        }
    }
    // Bounded grace so quitting stays responsive: ask every session to stop,
    // give the graceful endpoint closes a shared deadline, then return — the
    // process is going away anyway.
    for handle in sessions.values() {
        let _ = handle.tx.send(SessionCmd::Shutdown).await;
    }
    if let Some(handle) = &server {
        let _ = handle.tx.send(ServerCmd::Shutdown).await;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    for (_, handle) in sessions {
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

fn remove_slot(shared: &SharedSnapshots, id: &str) {
    let mut map = match shared.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    map.remove(id);
}

/// Publish the manager's current per-forward statuses to the snapshot.
fn refresh_forward_statuses(slot: &SnapshotSlot, fwd_mgr: &ForwardManager) {
    let statuses = fwd_mgr.statuses();
    slot.update(|s| s.forwards = statuses);
}

async fn run_session(
    profile: Profile,
    auth_key: String,
    mut rx: mpsc::Receiver<SessionCmd>,
    slot: SnapshotSlot,
) {
    let mut forwards = profile.forwards.clone();
    let socks_addr = profile
        .socks_port
        .map(|port| SocketAddr::from(([127, 0, 0, 1], port)));
    let http_addr = profile.http_port.map(|p| SocketAddr::from(([127, 0, 0, 1], p)));
    slot.update(|s| {
        *s = Snapshot {
            phase: Phase::Connecting,
            socks_addr,
            http_addr,
            ..Snapshot::default()
        };
    });

    // Everything the session needs is validated before anything is bound.
    // The profile form checks all of it on save, but a hand-edited file or a
    // corrupted keychain entry can still surface here — fail the session
    // cleanly rather than panic.
    let fail = |message: String| {
        log::error!("{message}");
        slot.update(|s| {
            s.phase = Phase::Failed;
            s.last_error = Some(message);
        });
    };
    let relay = match RelayConfig::from_urls_with_token(
        &profile.relay_urls,
        profile.relay_auth_token.clone(),
    ) {
        Ok(relay) => relay,
        Err(e) => return fail(format!("Invalid relay configuration: {e:#}")),
    };
    let client_key = match flextunnel_core::auth::ClientKey::from_secret_str(auth_key.trim()) {
        Ok(key) => key,
        Err(e) => return fail(format!("Invalid client auth key: {e:#}")),
    };
    let server_id = match profile.server_node_id.trim().parse() {
        Ok(id) => id,
        Err(e) => return fail(format!("Invalid server node id: {e}")),
    };
    // One destination: the profile's server, under the profile's host.
    // Building the client validates the host and routes and dials nothing.
    let client = match ProxyClient::new(ClientConfig {
        destinations: vec![DestinationConfig {
            host: profile.host.clone(),
            server_id,
            auth: ClientAuth::Key(Box::new(client_key)),
            relay,
            routed_domains: profile.routed_domains.clone(),
            routed_cidrs: profile.routed_cidrs.clone(),
            keep_connected: false,
        }],
        idle_timeout: Some(DEFAULT_IDLE_TIMEOUT),
    }) {
        Ok(client) => client,
        Err(e) => return fail(e.to_string()),
    };
    // The core stores the host normalized; status lookups use that form.
    let host = client.status().destinations[0].host.clone();

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
        Err(reason) => return fail(reason),
    };

    // Forwards listen for the whole session, whatever the connection is doing
    // (a forwarded connection connects the server on demand); they die with
    // the manager when the session ends.
    let mut fwd_mgr = ForwardManager::new(
        tokio::runtime::Handle::current(),
        client.dialer(),
        &forwards,
    );

    // Pressing Connect should say whether the server is reachable, so ask for
    // one connection attempt up front instead of waiting for the first use.
    // After that the connection lives, idles out and returns on demand.
    client.dialer().warm(&host);

    // Boxed so it can be dropped before the endpoint is closed below.
    let mut run = Box::pin(client.run(LocalListeners::tcp(socks_listener, http_listener)));
    let mut ticker = tokio::time::interval(Duration::from_millis(500));

    loop {
        tokio::select! {
            res = &mut run => {
                match res {
                    Ok(()) => slot.update(|s| s.phase = Phase::Idle),
                    Err(e) => {
                        log::error!("Client error: {e}");
                        slot.update(|s| {
                            s.phase = Phase::Failed;
                            s.last_error = Some(e.to_string());
                        });
                    }
                }
                break;
            }
            _ = ticker.tick() => {
                let status = client.status().destinations.swap_remove(0);
                // A server that refuses this client ends the session, as a
                // rejected key always has here: the fix is on the server or
                // in the profile, and Connect tries again.
                if status.state == DestinationState::Failed {
                    let reason = status
                        .last_error
                        .unwrap_or_else(|| "the server refused this client".into());
                    log::error!("Client error: {reason}");
                    slot.update(|s| {
                        s.phase = Phase::Failed;
                        s.connected_since = None;
                        s.last_error = Some(reason);
                    });
                    break;
                }
                slot.update(|s| {
                    s.phase = match status.state {
                        DestinationState::Connected => Phase::Connected,
                        DestinationState::Connecting => Phase::Connecting,
                        DestinationState::Backoff => Phase::Reconnecting,
                        DestinationState::Idle | DestinationState::Failed => Phase::Standby,
                    };
                    s.connected_since = status.connected_since;
                    // What the last attempt failed with, until one succeeds —
                    // also while in standby after a drop.
                    s.last_error = status.last_error;
                });
                refresh_forward_statuses(&slot, &fwd_mgr);
            }
            cmd = rx.recv() => match cmd {
                Some(SessionCmd::Disconnect) => {
                    log::info!("Disconnecting \"{}\"", profile.name);
                    slot.update(|s| s.phase = Phase::Idle);
                    break;
                }
                Some(SessionCmd::SetForwards(f)) => {
                    forwards = f;
                    fwd_mgr.apply(&forwards);
                    refresh_forward_statuses(&slot, &fwd_mgr);
                }
                Some(SessionCmd::QueryConnPath(reply)) => {
                    let _ = reply.send(client.connection_snapshot(&host).await);
                }
                Some(SessionCmd::Shutdown) | None => {
                    slot.update(|s| s.phase = Phase::Idle);
                    break;
                }
            }
        }
    }

    // The select loop is done with `run`; dropping it cancels the client.
    // Tear the forward listeners down with the session so their rows read
    // "stopped" immediately, then close the endpoint (if the server was in
    // use) gracefully before it is dropped (see the CLI's close_or_exit for
    // why an ungraceful drop is fatal under panic=abort). The UI already shows
    // the final phase and this session makes no further command reads, so
    // release the command channel first: an immediate reconnect may start a
    // fresh session while this thread finishes closing.
    drop(fwd_mgr);
    drop(run);
    drop(rx);
    if tokio::time::timeout(SESSION_CLOSE_TIMEOUT, client.close())
        .await
        .is_err()
    {
        log::warn!("Closing the endpoint of \"{}\" is taking too long; giving up", profile.name);
    }
    slot.update(|s| {
        s.connected_since = None;
        s.forwards.clear();
    });
}
