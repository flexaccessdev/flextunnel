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
//! has gone unused (see [`flextunnel_core::proxy::ProxyClient::run`]). Saved
//! changes apply to the running session in place: the destinations are
//! reconfigured — the unchanged ones keep their connections — and changed
//! proxy ports are rebound, so nothing is restarted for them. A change that
//! cannot be applied (a port that is taken, say) is reported and leaves the
//! session running as it was in that respect. The session
//! owns its client futures, so dropping them (stop/shutdown) tears down the
//! accept loops and every destination's manager together, followed by a
//! graceful close of the endpoints in use. The app's server
//! ([`crate::server_session`]) is routed through the same supervisor, so one
//! controller owns both sessions and one shutdown stops them.

use crate::config::{self, AuthKey, ClientSettings, Destination, ServerConfig};
use crate::server_session::{self, ServerCmd, ServerHandle, ServerSnapshot, SharedServerSnapshot};
use flextunnel_core::config::DEFAULT_IDLE_TIMEOUT;
use flextunnel_core::error::ProxyError;
use flextunnel_core::forwards::{ForwardManager, ForwardStatus, PortForward};
use flextunnel_core::proxy::{
    ClientAuth, ClientConfig, DestinationConfig, DestinationStatus, HeldDestination,
    LocalListeners, ProxyClient, ServerRoutes,
};
use flextunnel_core::transport::endpoint::{RelayConfig, relay_config};
use flextunnel_core::transport::paths::ConnectionSnapshot;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
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
/// during a slow dial must not hang behind; an ordinary close finishes well
/// inside it.
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
    /// Closing the endpoints in use; a start waits for this to finish.
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
    /// The destinations the latest apply asked for, when the session refused
    /// to run them, and why. A saved destination among them is not applied
    /// for that reason; one that is neither among them nor running is still
    /// on its way.
    pub destinations_refused: Option<(Vec<DestinationSpec>, String)>,
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

/// What a client session runs with: the proxy ports and the destinations.
/// Comparing two tells whether saved settings differ from the running ones,
/// which the session then applies in place (forwards are not part of it —
/// they apply on their own).
#[derive(Clone, PartialEq, Eq)]
pub struct ClientSpec {
    pub socks_port: Option<u16>,
    pub http_port: Option<u16>,
    pub destinations: Vec<DestinationSpec>,
    /// The destinations that cannot be used yet (see
    /// [`config::destination_blocker`]): routed but refused, never connected
    /// directly (see [`flextunnel_core::proxy::HeldDestination`]). A spec
    /// with any is only ever applied to a running session
    /// ([`Command::NarrowClient`]), never started with.
    pub held: Vec<Destination>,
}

impl ClientSpec {
    /// Resolve the settings against the key list: each destination with its
    /// key's secret, or held when it cannot be used — no server, or a key
    /// missing or without its secret ([`ClientSettings::start_blocker`] says
    /// so in words).
    pub fn resolve(client: &ClientSettings, keys: &[AuthKey]) -> Self {
        let mut destinations = Vec::new();
        let mut held = Vec::new();
        for destination in &client.destinations {
            let key = config::find_key(keys, &destination.auth_key_id)
                .filter(|_| config::destination_blocker(destination, keys).is_none());
            match key {
                Some(key) => destinations.push(DestinationSpec {
                    destination: destination.clone(),
                    auth_secret: key.secret.clone(),
                }),
                None => held.push(destination.clone()),
            }
        }
        Self {
            socks_port: client.socks_port,
            http_port: client.http_port,
            destinations,
            held,
        }
    }
}

/// A client session to start: what it runs with, and its forwards.
type ClientStart = Box<(ClientSpec, Vec<PortForward>)>;

enum Command {
    /// Run the client with these settings (the auth secrets travel inside the
    /// spec) — how it is started and how saved changes apply: started when
    /// no session runs; a running session takes them in place
    /// ([`SessionCmd::Reconfigure`]), applying what differs from what it runs.
    /// A start waiting for a stop takes this newer one instead. The forwards
    /// are only started with: a running session gets them from
    /// [`Command::SetForwards`].
    ApplyClient(ClientStart),
    /// Take these settings, which hold destinations that cannot be used yet
    /// ([`ClientSpec::held`]), if a session runs: never a start of its own,
    /// and a start waiting for a stop is called off, so a client that is
    /// down (failed, say, or restarting) waits for every destination.
    NarrowClient(Box<ClientSpec>),
    StopClient,
    /// Replace the desired forward list (the UI sends the full list after
    /// every add/edit/delete/toggle); applied live mid-session.
    SetForwards(Vec<PortForward>),
    /// One-shot request for a destination's current iroh connection path(s),
    /// by name, answered on the reply channel (the UI's connection-path CTA).
    /// Empty when no session is running or the destination is not connected.
    /// A `std` channel (not tokio `oneshot`) so the GUI caller can wait with a
    /// bounded [`std::sync::mpsc::Receiver::recv_timeout`].
    QueryConnPath(String, std::sync::mpsc::Sender<ConnectionSnapshot>),
    /// Run the server with this config (its identity secret travels inside):
    /// started when no session runs; a session running another config is
    /// stopped and this one started once it has — the server takes its
    /// settings only at start — and one already running it is left alone.
    ApplyServer(Box<ServerConfig>),
    StopServer,
    /// Stop the server and reset its snapshot once it has stopped (the
    /// server was deleted).
    RemoveServer,
    Shutdown,
}

enum SessionCmd {
    Stop,
    /// Run with this spec from now on: the destinations reconfigured (the
    /// unchanged ones keep their connections), changed proxy ports rebound.
    /// What cannot be applied is reported in the snapshot's `last_error` and
    /// left as it ran. Counted in [`SessionHandle::handled`] once handled.
    Reconfigure(ClientSpec),
    SetForwards(Vec<PortForward>),
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
                match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
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

    pub fn apply_server(&self, server: ServerConfig) {
        let _ = self
            .tx
            .blocking_send(Command::ApplyServer(Box::new(server)));
    }

    pub fn stop_server(&self) {
        let _ = self.tx.blocking_send(Command::StopServer);
    }

    pub fn remove_server(&self) {
        let _ = self.tx.blocking_send(Command::RemoveServer);
    }

    pub fn apply_client(&self, spec: ClientSpec, forwards: Vec<PortForward>) {
        let _ = self
            .tx
            .blocking_send(Command::ApplyClient(Box::new((spec, forwards))));
    }

    pub fn narrow_client(&self, spec: ClientSpec) {
        let _ = self.tx.blocking_send(Command::NarrowClient(Box::new(spec)));
    }

    pub fn stop_client(&self) {
        let _ = self.tx.blocking_send(Command::StopClient);
    }

    pub fn set_forwards(&self, forwards: Vec<PortForward>) {
        let _ = self.tx.blocking_send(Command::SetForwards(forwards));
    }

    /// Fetch a destination's current iroh connection path(s), once. Returns
    /// empty when no session is running, the destination is not connected, the
    /// request can't be sent, or the session doesn't answer within
    /// [`CONN_PATH_TIMEOUT`]. The round-trip is a channel hop (normally
    /// sub-millisecond), but the deadline is what guarantees a wedged session
    /// can never freeze the GUI thread calling this from `App::update`.
    pub fn query_conn_path(&self, name: &str) -> ConnectionSnapshot {
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        if self
            .tx
            .blocking_send(Command::QueryConnPath(name.into(), reply_tx))
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

/// A server to ask for its routes: its id, and the key and relays a
/// destination for it would use.
pub struct RoutesQuery {
    pub server_id: flextunnel_core::iroh::EndpointId,
    pub key: flextunnel_core::auth::ClientKey,
    pub relay: RelayConfig,
}

/// Ask a server what it routes (see
/// [`flextunnel_core::proxy::fetch_server_routes`]): one connection made for
/// the question, whatever the client session is doing — it need not be
/// running, nor know the server.
///
/// The request runs on a thread and runtime of its own, named like the client
/// session's so its log lines are filed with the client's. It always runs to
/// its end — the endpoint it binds is closed there, after the answer — even
/// when nobody waits for the answer any more.
pub async fn fetch_server_routes(query: RoutesQuery) -> Result<ServerRoutes, String> {
    let answer = flextunnel_core::proxy::fetch_server_routes(
        CLIENT_THREAD_NAME,
        query.server_id,
        query.key,
        query.relay,
    );
    match answer.await {
        Ok(Ok(routes)) => Ok(routes),
        Ok(Err(ProxyError::AuthenticationFailed(reason))) => Err(format!(
            "The server refused this client ({reason}): it must authorize the auth key's \
             public half before it answers."
        )),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("The request to the server could not be made".into()),
    }
}

/// Bind a local listener, mapping the common taken-port case to a clear
/// session error.
async fn bind_local(addr: SocketAddr, label: &str) -> Result<tokio::net::TcpListener, String> {
    tokio::net::TcpListener::bind(addr).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::AddrInUse {
            format!(
                "{label} port {} is already in use — another flextunnel?",
                addr.port()
            )
        } else {
            format!("Failed to bind the {label} listener on {addr}: {e}")
        }
    })
}

struct SessionHandle {
    tx: mpsc::Sender<SessionCmd>,
    /// What the session was last told to run with, and the forwards: what a
    /// replacement starts with when it ends before reading that ([`reap`]).
    spec: ClientSpec,
    forwards: Vec<PortForward>,
    /// Whether `spec` came from a [`Command::NarrowClient`], which no
    /// replacement starts on.
    narrowed: bool,
    /// [`SessionCmd::Reconfigure`]s sent, and those the session handled.
    sent: u64,
    handled: Arc<AtomicU64>,
    /// Resolves when the session's thread finishes. The session keeps its
    /// command receiver until then, so `tx.is_closed()` also means "done".
    done: tokio::sync::oneshot::Receiver<()>,
}

impl SessionHandle {
    /// Whether an apply sent to the session is still unread.
    fn unhandled(&self) -> bool {
        self.sent > self.handled.load(Ordering::SeqCst)
    }
}

/// Clear `client` once its session has ended. A session that ended with an
/// apply unread — sent while it was closing after a failure, which reads no
/// more commands — is started again with what that apply asked for, unless a
/// stop was asked for meanwhile or another start already waits.
fn reap(
    client: &mut Option<SessionHandle>,
    stopping: &mut bool,
    pending: &mut Option<ClientStart>,
) {
    let Some(handle) = client.take_if(|handle| handle.tx.is_closed()) else {
        return;
    };
    if !*stopping && pending.is_none() && !handle.narrowed && handle.unhandled() {
        *pending = Some(Box::new((handle.spec, handle.forwards)));
    }
    *stopping = false;
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
    let started = (spec.clone(), forwards.clone());
    let handled = Arc::new(AtomicU64::new(0));
    let session_handled = handled.clone();
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
                Ok(rt) => rt.block_on(run_client(
                    spec,
                    forwards,
                    session_rx,
                    slot,
                    session_handled,
                )),
                Err(e) => slot.fail(format!("Failed to build the client runtime: {e:#}")),
            }
            let _ = done_tx.send(());
        });
    match spawned {
        Ok(_) => Some(SessionHandle {
            tx,
            spec: started.0,
            forwards: started.1,
            narrowed: false,
            sent: 0,
            handled,
            done,
        }),
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
    // A start waiting for the old session to end: until then it still holds
    // the local ports and its connections to the servers.
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
        reap(&mut client, &mut client_stopping, &mut pending_client);
        if client.is_none() {
            client_stopping = false;
        }
        // Commands already queued are read first: one may replace or call off
        // the waiting start (a narrow, a stop), which must not run before it.
        if client.is_none()
            && rx.is_empty()
            && let Some(start) = pending_client.take()
        {
            let (spec, forwards) = *start;
            client = spawn_client(spec, forwards, &client_shared);
        }
        if server.as_ref().is_some_and(|handle| handle.tx.is_closed()) {
            server = None;
        }
        if server.is_none() {
            stopping = false;
        }
        // As for the client: a newer config, or a stop, already queued is
        // read before the waiting start runs.
        if server.is_none()
            && rx.is_empty()
            && let Some(config) = pending_start.take()
        {
            server = server_session::spawn_server(config, &server_shared);
        }
        // Waiting out a stop that a start is queued behind, or a session that
        // has an apply to read: wake when the old session ends, so the new
        // one starts without waiting for the next command.
        let restart_client =
            pending_client.is_some() || client.as_ref().is_some_and(SessionHandle::unhandled);
        let cmd = tokio::select! {
            cmd = rx.recv() => cmd,
            _ = ended(client.as_mut().map(|h| &mut h.done), restart_client) => continue,
            _ = ended(server.as_mut().map(|h| &mut h.done), pending_start.is_some()) => continue,
        };
        reap(&mut client, &mut client_stopping, &mut pending_client);
        if server.as_ref().is_some_and(|handle| handle.tx.is_closed()) {
            server = None;
            stopping = false;
        }
        // The session reading commands, if there is one: a stopping session
        // reads no more, so nothing is queued behind its close.
        let live_client = client.as_ref().filter(|_| !client_stopping);
        match cmd {
            // Decided here rather than from the UI's snapshot, which lags the
            // session by a poll.
            Some(Command::ApplyClient(start)) => match &mut client {
                // Still closing — disabled and enabled again in quick
                // succession: start this once it has.
                Some(_) if client_stopping => pending_client = Some(start),
                // The session compares it with what it runs. Counted, so that
                // one it never reads is not lost (see `reap`).
                Some(handle) => {
                    let (spec, forwards) = *start;
                    handle.spec = spec.clone();
                    handle.forwards = forwards.clone();
                    handle.narrowed = false;
                    if handle.tx.send(SessionCmd::Reconfigure(spec)).await.is_ok() {
                        handle.sent += 1;
                    } else {
                        // It has just ended: start one with these instead.
                        pending_client = Some(Box::new((handle.spec.clone(), forwards)));
                    }
                }
                // This start is the newest word: it replaces one waiting for a
                // session that ended just now, and starts once the commands
                // queued behind it are read (one may call it off).
                None => pending_client = Some(start),
            },
            Some(Command::NarrowClient(spec)) => {
                // A start waiting for the old session — still stopping, or
                // ended just now — would start on settings this replaces: it
                // waits for every destination instead.
                pending_client = None;
                match &mut client {
                    Some(_) if client_stopping => {}
                    Some(handle) => {
                        handle.spec = (*spec).clone();
                        handle.narrowed = true;
                        if handle.tx.send(SessionCmd::Reconfigure(*spec)).await.is_ok() {
                            handle.sent += 1;
                        }
                    }
                    // No session: nothing to narrow.
                    None => {}
                }
            }
            Some(Command::StopClient) => {
                // Also calls off a start that is waiting for the old stop.
                pending_client = None;
                if let Some(handle) = live_client {
                    let _ = handle.tx.send(SessionCmd::Stop).await;
                    client_stopping = true;
                }
            }
            Some(Command::SetForwards(forwards)) => match (
                client.as_mut().filter(|_| !client_stopping),
                &mut pending_client,
            ) {
                // A start waiting for the old session starts with the newer
                // list.
                (_, Some(start)) => start.1 = forwards,
                (Some(handle), None) => {
                    handle.forwards = forwards.clone();
                    let _ = handle.tx.send(SessionCmd::SetForwards(forwards)).await;
                }
                // No session: nothing to do — the next start carries them.
                (None, None) => {}
            },
            Some(Command::QueryConnPath(name, reply)) => {
                if let Some(handle) = live_client {
                    let _ = handle.tx.send(SessionCmd::QueryConnPath(name, reply)).await;
                }
                // No session: `reply` drops, and the caller gets an empty one.
            }
            // As for the client, decided here: the UI's snapshot reads
            // Stopped between a restart's two sessions, and a change made
            // meanwhile (a client revoked) must still reach the new one.
            Some(Command::ApplyServer(config)) => match &server {
                // A server still stopping holds the identity and the per-user
                // lock until its endpoint is closed: start once it has.
                Some(_) if stopping => pending_start = Some(*config),
                Some(handle) if handle.config == *config => {}
                Some(handle) => {
                    let _ = handle.tx.send(ServerCmd::Stop).await;
                    stopping = true;
                    pending_start = Some(*config);
                }
                // The newest config, started once the commands queued behind
                // it are read.
                None => pending_start = Some(*config),
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

/// One proxy front-end being served; replaced when its port changes.
type Serve<'a> = std::pin::Pin<Box<dyn Future<Output = Result<(), ProxyError>> + 'a>>;

/// The proxy front-ends, each served on its own so that moving one to another
/// port leaves the other's listener, and the connections waiting in it, as
/// they are: SOCKS, then HTTP.
const FRONTS: [&str; 2] = ["SOCKS", "HTTP"];

/// The front-ends' ports in `spec`, in [`FRONTS`] order.
fn ports(spec: &ClientSpec) -> [Option<u16>; 2] {
    [spec.socks_port, spec.http_port]
}

/// Serve front-end `front` on `listener`; with none, it serves nothing.
fn serve_front<'a>(
    client: &'a ProxyClient,
    front: usize,
    listener: Option<tokio::net::TcpListener>,
) -> Serve<'a> {
    let Some(listener) = listener else {
        return Box::pin(std::future::pending());
    };
    let listeners = match front {
        0 => LocalListeners::tcp(Some(listener), None),
        _ => LocalListeners::tcp(None, Some(listener)),
    };
    Box::pin(client.serve(listeners))
}

/// Bind the proxy front-ends `spec` enables, on loopback — all of them before
/// any is served — and serve them.
async fn serve_proxies<'a>(
    client: &'a ProxyClient,
    spec: &ClientSpec,
) -> Result<[Serve<'a>; 2], String> {
    let [socks, http] = ports(spec);
    let socks = bind_port(socks, FRONTS[0]).await?;
    let http = bind_port(http, FRONTS[1]).await?;
    Ok([serve_front(client, 0, socks), serve_front(client, 1, http)])
}

/// Why the proxy front-ends could not be moved to new ports.
enum Rebind {
    /// They serve on the ports they had.
    Refused(String),
    /// A front-end whose port changed serves nothing now: its old port could
    /// not be bound again either.
    Lost(String),
}

/// Move the proxy front-ends being served (`serves`) from `from`'s ports to
/// `to`'s; one whose port is unchanged is left alone. The new ports nothing
/// listens on yet are bound first, with every front-end still serving, so a
/// taken one refuses the move with nothing changed. The others are held by
/// front-ends that move too (the two swapped, say): those are released, then
/// bound again; should that fail, the moved front-ends are bound on their old
/// ports instead. The connections the old listeners accepted carry on.
async fn rebind_proxies<'a>(
    client: &'a ProxyClient,
    serves: &mut [Serve<'a>; 2],
    from: &ClientSpec,
    to: &ClientSpec,
) -> Result<(), Rebind> {
    let (old, new) = (ports(from), ports(to));
    let moved: Vec<usize> = (0..FRONTS.len()).filter(|&f| old[f] != new[f]).collect();
    let mut bound: [Option<tokio::net::TcpListener>; 2] = [None, None];
    for &f in &moved {
        if let Some(port) = new[f].filter(|port| !old.contains(&Some(*port))) {
            bound[f] = bind_port(Some(port), FRONTS[f])
                .await
                .map_err(Rebind::Refused)?;
        }
    }
    for &f in &moved {
        serves[f] = Box::pin(std::future::pending());
    }
    let mut failure = None;
    for &f in &moved {
        if bound[f].is_none() && new[f].is_some() {
            match bind_port(new[f], FRONTS[f]).await {
                Ok(listener) => bound[f] = listener,
                Err(reason) => {
                    failure = Some(reason);
                    break;
                }
            }
        }
    }
    let Some(reason) = failure else {
        for &f in &moved {
            serves[f] = serve_front(client, f, bound[f].take());
        }
        return Ok(());
    };
    // What was bound may hold the old ports of the other moved front-end.
    drop(bound);
    for &f in &moved {
        match bind_port(old[f], FRONTS[f]).await {
            Ok(listener) => serves[f] = serve_front(client, f, listener),
            Err(lost) => {
                return Err(Rebind::Lost(format!(
                    "{reason}, and the {} proxy's previous port could not be bound again: {lost}",
                    FRONTS[f]
                )));
            }
        }
    }
    Err(Rebind::Refused(reason))
}

/// How a session whose front-end stopped serving ends: failed, with why.
fn serve_ended(res: Result<(), ProxyError>) -> Option<String> {
    let e = res.err()?;
    log::error!("Client error: {e}");
    Some(e.to_string())
}

/// Bind a proxy front-end on `port` of loopback, if it has one.
async fn bind_port(
    port: Option<u16>,
    label: &str,
) -> Result<Option<tokio::net::TcpListener>, String> {
    match port {
        Some(port) => bind_local(SocketAddr::from(([127, 0, 0, 1], port)), label)
            .await
            .map(Some),
        None => Ok(None),
    }
}

/// The core's view of a destination that cannot be used yet: its routes, to
/// refuse.
fn held_destination(destination: &Destination) -> HeldDestination {
    HeldDestination {
        name: destination.name.clone(),
        routed_domains: destination.routed_domains.clone(),
        routed_cidrs: destination.routed_cidrs.clone(),
    }
}

/// The core's configuration of one destination, or why its settings cannot be
/// used. The forms check all of it on save, but a hand-edited file or a
/// corrupted keychain entry can still surface here.
fn destination_config(spec: &DestinationSpec) -> Result<DestinationConfig, String> {
    let destination = &spec.destination;
    let name = &destination.name;
    let relay = relay_config(
        &destination.relay_urls,
        destination.relay_auth_token.clone(),
        crate::config::relay_quic_addr_discovery_setting(destination.relay_quic_addr_discovery),
    )
    .map_err(|e| format!("Destination \"{name}\": invalid relay configuration: {e:#}"))?;
    let client_key = flextunnel_core::auth::ClientKey::from_secret_str(spec.auth_secret.trim())
        .map_err(|e| format!("Destination \"{name}\": invalid client auth key: {e:#}"))?;
    let server_id = destination
        .server_node_id
        .trim()
        .parse()
        .map_err(|e| format!("Destination \"{name}\": invalid server node id: {e}"))?;
    Ok(DestinationConfig {
        name: name.clone(),
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
    handled: Arc<AtomicU64>,
) {
    let mut spec = Arc::new(spec);
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
    // Building the client validates the names and routes together and dials
    // nothing.
    // Shared, so a connection-path probe can run on a task of its own.
    let client = match ProxyClient::new(ClientConfig {
        destinations,
        idle_timeout: Some(DEFAULT_IDLE_TIMEOUT),
    }) {
        Ok(client) => Arc::new(client),
        Err(e) => return slot.fail(e.to_string()),
    };

    // Bind enabled proxy front-ends before any forward listener exists. A
    // taken proxy port fails the session before forwards come up. Boxed so
    // they can be dropped before the endpoints are closed below; served apart
    // from the managers, so changed ports are rebound without touching the
    // destinations.
    let mut serves = match serve_proxies(&client, &spec).await {
        Ok(serves) => serves,
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

    // The managers run for the whole session.
    let mut manage = Box::pin(client.manage());
    let mut ticker = tokio::time::interval(Duration::from_millis(500));
    log::info!(
        "The client is running with {} destination(s)",
        spec.destinations.len()
    );
    slot.update(|s| {
        s.phase = ClientPhase::Running;
        s.running_since = Some(Instant::now());
    });

    // How the session ended, for its final snapshot.
    let failure = loop {
        let [socks_serve, http_serve] = &mut serves;
        tokio::select! {
            () = &mut manage => break None,
            res = socks_serve => break serve_ended(res),
            res = http_serve => break serve_ended(res),
            _ = ticker.tick() => {
                let destinations = client.status().destinations;
                let statuses = fwd_mgr.statuses();
                slot.update(|s| {
                    s.destinations = destinations;
                    s.forwards = statuses;
                });
            }
            cmd = rx.recv() => match cmd {
                Some(SessionCmd::Reconfigure(next)) => {
                    // Read, so not to be started again should the session end
                    // now (see `reap`).
                    handled.fetch_add(1, Ordering::SeqCst);
                    // Each part applies on its own; the spec published is what
                    // runs, so a part refused reads as not applied.
                    let mut applied = (*spec).clone();
                    let mut refused = Vec::new();
                    let mut destinations_refused = None;
                    if (&next.destinations, &next.held) != (&spec.destinations, &spec.held) {
                        let held = next.held.iter().map(held_destination).collect();
                        let reconfigured = next
                            .destinations
                            .iter()
                            .map(destination_config)
                            .collect::<Result<Vec<_>, _>>()
                            .and_then(|configs| {
                                client.reconfigure(configs, held).map_err(|e| e.to_string())
                            });
                        match reconfigured {
                            Ok(()) => {
                                applied.destinations = next.destinations.clone();
                                applied.held = next.held.clone();
                            }
                            Err(reason) => {
                                destinations_refused =
                                    Some((next.destinations.clone(), reason.clone()));
                                refused.push(reason);
                            }
                        }
                    }
                    if (next.socks_port, next.http_port) != (spec.socks_port, spec.http_port) {
                        match rebind_proxies(&client, &mut serves, &spec, &next).await {
                            Ok(()) => {
                                applied.socks_port = next.socks_port;
                                applied.http_port = next.http_port;
                            }
                            Err(Rebind::Refused(reason)) => refused.push(reason),
                            Err(Rebind::Lost(reason)) => {
                                log::error!("{reason}");
                                break Some(reason);
                            }
                        }
                    }
                    let error = (!refused.is_empty()).then(|| {
                        format!(
                            "Not applied: {}. The client runs on as it was in that respect.",
                            refused.join("; ")
                        )
                    });
                    if let Some(error) = &error {
                        log::error!("{error}");
                    }
                    spec = Arc::new(applied);
                    // With the destinations it now runs, so none reads as missing
                    // until the next tick.
                    let applied = spec.clone();
                    let destinations = client.status().destinations;
                    slot.update(|s| {
                        s.spec = Some(applied);
                        s.destinations = destinations;
                        s.last_error = error;
                        s.destinations_refused = destinations_refused;
                    });
                }
                Some(SessionCmd::SetForwards(f)) => {
                    forwards = f;
                    fwd_mgr.apply(&forwards);
                    let statuses = fwd_mgr.statuses();
                    slot.update(|s| s.forwards = statuses);
                }
                // On its own task, never awaited here: the snapshot probes the
                // destination's custom relays over HTTP (~3s worst case), and
                // this loop is what drives the client — its accept loops and
                // every destination's manager would stand still meanwhile.
                Some(SessionCmd::QueryConnPath(name, reply)) => {
                    let client = Arc::clone(&client);
                    tokio::spawn(async move {
                        let _ = reply.send(client.connection_snapshot(&name).await);
                    });
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
    drop(serves);
    drop(manage);
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
            name: host.into(),
            server_node_id: format!("node-{host}"),
            routed_domains: Vec::new(),
            routed_cidrs: Vec::new(),
            auth_key_id: auth_key_id.into(),
            relay_urls: Vec::new(),
            relay_auth_token: None,
            relay_quic_addr_discovery: true,
        }
    }

    #[test]
    fn a_spec_carries_each_destinations_key_secret() {
        let keys = [key("k1", "secret-1"), key("k2", "secret-2")];
        let client = ClientSettings {
            socks_port: Some(1085),
            http_port: None,
            destinations: vec![destination("a", "k2"), destination("b", "k1")],
            ..ClientSettings::default()
        };
        let spec = ClientSpec::resolve(&client, &keys);
        assert!(spec.held.is_empty(), "every key resolves");
        assert_eq!((spec.socks_port, spec.http_port), (Some(1085), None));
        let secrets: Vec<&str> = spec
            .destinations
            .iter()
            .map(|d| d.auth_secret.as_str())
            .collect();
        assert_eq!(secrets, ["secret-2", "secret-1"]);

        // A missing key, or one whose secret was lost, holds its destination.
        let held = |keys: &[AuthKey]| {
            let spec = ClientSpec::resolve(&client, keys);
            let names: Vec<String> = spec.held.into_iter().map(|d| d.name).collect();
            (spec.destinations.len(), names)
        };
        assert_eq!(held(&keys[..1]), (1, vec!["a".to_string()]));
        assert_eq!(
            held(&[key("k1", ""), key("k2", "s")]),
            (1, vec!["b".to_string()])
        );
    }

    /// What an apply reconfigures the client for: the ports, the destinations
    /// and the secrets they authenticate with — not the forwards, which apply
    /// on their own.
    #[test]
    fn a_spec_changes_with_what_a_session_keeps() {
        let keys = [key("k1", "secret-1")];
        let client = ClientSettings {
            destinations: vec![destination("a", "k1")],
            ..ClientSettings::default()
        };
        let spec = ClientSpec::resolve(&client, &keys);

        let mut with_forward = client.clone();
        with_forward.forwards.push(PortForward {
            id: "f".into(),
            label: String::new(),
            local_port: 8080,
            remote_host: "a.localhost.flextunnel.internal".into(),
            remote_port: 80,
            enabled: true,
        });
        with_forward.enabled = false;
        assert!(ClientSpec::resolve(&with_forward, &keys) == spec);

        let mut other_port = client.clone();
        other_port.http_port = Some(18080);
        assert!(ClientSpec::resolve(&other_port, &keys) != spec);
        let mut routed = client.clone();
        routed.destinations[0]
            .routed_domains
            .push("*.corp.example".into());
        assert!(ClientSpec::resolve(&routed, &keys) != spec);
        assert!(ClientSpec::resolve(&client, &[key("k1", "rotated")]) != spec);
        assert!(
            ClientSpec::resolve(&client, &[]) != spec,
            "held without its key"
        );
    }

    #[test]
    fn unusable_destination_settings_name_the_destination() {
        let spec = |destination: Destination, secret: &str| DestinationSpec {
            destination,
            auth_secret: secret.into(),
        };
        let secret = flextunnel_core::auth::ClientKey::generate()
            .unwrap()
            .secret_str();
        let server_id = flextunnel_core::iroh::SecretKey::generate()
            .public()
            .to_string();
        let mut good = destination("a", "k1");
        good.server_node_id = server_id.clone();
        assert!(destination_config(&spec(good.clone(), &secret)).is_ok());

        let err = |spec: DestinationSpec| destination_config(&spec).err().expect("rejected");
        assert!(err(spec(good.clone(), "not-a-key")).contains("\"a\": invalid client auth key"));
        let mut bad_server = good.clone();
        bad_server.server_node_id = "nope".into();
        assert!(err(spec(bad_server, &secret)).contains("invalid server node id"));
        let mut one_relay = good.clone();
        one_relay.relay_urls = vec!["https://only.example".into()];
        let config = destination_config(&spec(one_relay.clone(), &secret)).expect("one relay");
        assert_eq!(config.relay.custom_urls().len(), 1);
        assert_eq!(config.relay.quic_addr_discovery(), Some(true));
        // QUIC address discovery is as stored for custom relays; turned off
        // with the default ones (a hand-edited file), it cannot be used.
        let mut discovery_off = one_relay;
        discovery_off.relay_quic_addr_discovery = false;
        let config = destination_config(&spec(discovery_off.clone(), &secret)).expect("off");
        assert_eq!(config.relay.quic_addr_discovery(), Some(false));
        discovery_off.relay_urls.clear();
        assert!(err(spec(discovery_off, &secret)).contains("invalid relay configuration"));
        let mut bad_relay = good;
        bad_relay.relay_urls = vec!["not a url".into()];
        assert!(err(spec(bad_relay, &secret)).contains("invalid relay configuration"));
    }
}
