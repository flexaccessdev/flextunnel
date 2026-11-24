//! One client destination: a server reached on demand.
//!
//! A [`Destination`] owns everything about one configured server — its
//! endpoint, its connection, and the reconnect bookkeeping — and connects
//! **lazily**. Nothing touches the network until a request arrives for it:
//!
//! ```text
//!            a request arrives                  authenticated
//!   Idle ───────────────────────▶ Dialing ───────────────────────▶ Connected
//!    ▲                              │  ▲                              │
//!    │ nobody is waiting            │  │ retry time reached,          │ dropped
//!    │                              ▼  │ someone still waiting        │
//!    ├────────────────────────── Backoff ◀────────────────────────────┤
//!    │                                                                │
//!    └──────── no stream open for the idle timeout ───────────────────┘
//! ```
//!
//! * A request [acquires](Destination::acquire) the connection, waiting (up to
//!   [`TUNNEL_RECOVERY_HOLD`]) while it is dialed, and holds a [`Lease`] for as
//!   long as its stream is open.
//! * A connection with no stream open for the client's idle timeout is closed,
//!   and its endpoint with it: an idle endpoint still holds a relay link and
//!   answers pings, which is exactly the background chatter a client with many
//!   destinations should not pay for.
//! * A failed attempt or a dropped connection is retried with the usual
//!   backoff only **while requests are waiting**. With nobody waiting the
//!   destination goes idle and the next request redials — after the remainder
//!   of the backoff, so a down server is still probed at most once per step.
//! * A permanent failure (a rejected key) answers every request at once until
//!   its retry time, instead of making each one wait out a doomed dial.
//!
//! * Each time it connects, it reads what its server routes (the server's own
//!   lists, off its status page) and keeps the answer past the connection, so
//!   a status display can say which of this destination's rules the server
//!   will refuse — without connecting a destination that has not been used.
//!
//! Each destination has its own endpoint, built on first use and closed when
//! the destination goes idle: relay settings are endpoint-wide, and the
//! reconnect escalation that rebuilds a wedged endpoint must not sever the
//! connections to the other destinations' servers.

use crate::error::{ProxyError, ProxyResult};
use crate::proxy::client::{
    HANDSHAKE_TIMEOUT, TUNNEL_RECOVERY_HOLD, calculate_backoff, client_heartbeat_loop,
    connect_with_timeout, rebuild_due,
};
use crate::proxy::routed_set::{Coverage, RoutedSet, Rule};
use crate::proxy::server_routes::{self, ServerRoutes};
use crate::proxy::signaling::{self, Hello, HelloResponse};
use crate::transport::endpoint::{
    ClientEndpoint, PendingCloses, RelayConfig, create_client_endpoint,
    create_quick_client_endpoint,
};
use crate::transport::paths::ConnectionSnapshot;
use futures::future::BoxFuture;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Semaphore, watch};
use tokio::time::Instant;

/// Bound wait on an endpoint's graceful close when a destination goes idle.
/// The close runs as its own task and is never cancelled (dropping a bound
/// endpoint without `close()` is fatal under panic=abort); the bound only
/// keeps the destination from being stuck behind a slow close when the next
/// request arrives.
const IDLE_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// How a destination's client authenticates to its server.
#[derive(Clone)]
pub enum ClientAuth {
    /// Regular client: dial the client [`ALPN`](crate::transport::ALPN) and
    /// present this keypair's public key plus a signature over the client's
    /// own (ephemeral) endpoint id in the `Hello` (see [`crate::auth`]).
    Key(Box<crate::auth::ClientKey>),
    /// Quick-mode client: dial [`QUICK_ALPN`](crate::transport::QUICK_ALPN)
    /// with no keypair. The sole credential is the endpoint's
    /// TLS-authenticated id, which the quick server has allowlisted, so the
    /// endpoint is bound to this session secret (see
    /// [`create_quick_client_endpoint`]).
    ///
    /// Both variants are boxed: the keys are a couple of hundred bytes each,
    /// and a destination's config is cloned around.
    Quick(Box<SecretKey>),
}

/// One destination of a client: a name and the server behind it.
#[derive(Clone)]
pub struct DestinationConfig {
    /// The destination's name. As a target it means the server's own
    /// loopback; validated by [`validate_destination_name`].
    ///
    /// [`validate_destination_name`]: crate::proxy::route_table::validate_destination_name
    pub name: String,
    /// The server's iroh endpoint id.
    pub server_id: EndpointId,
    pub auth: ClientAuth,
    /// The relays this destination's endpoint uses. Custom relays double as
    /// the hints attached when dialing the server.
    pub relay: RelayConfig,
    /// Further domains (exact, `*.suffix` or `*`) sent through this server.
    pub routed_domains: Vec<String>,
    /// Further networks or bare IPs sent through this server.
    pub routed_cidrs: Vec<String>,
    /// Dial at start and stay connected for as long as the client runs,
    /// reconnecting with backoff — the opposite of lazy. For a session whose
    /// server waits for its one client (quick mode).
    pub keep_connected: bool,
}

/// Builds a destination's endpoint. The default creates a real client endpoint
/// from the destination's relay config; tests substitute loopback endpoints.
pub type EndpointProvider = Arc<
    dyn Fn(&DestinationConfig) -> BoxFuture<'static, anyhow::Result<ClientEndpoint>> + Send + Sync,
>;

/// The production [`EndpointProvider`]: an ephemeral-identity client endpoint,
/// or one bound to the session secret for a quick-mode destination.
pub(crate) fn default_endpoint_provider() -> EndpointProvider {
    Arc::new(|cfg: &DestinationConfig| {
        let relay = cfg.relay.clone();
        let secret = match &cfg.auth {
            ClientAuth::Key(_) => None,
            ClientAuth::Quick(secret) => Some(secret.clone()),
        };
        Box::pin(async move {
            // A client session's runtime outlives its endpoints: a close the
            // creation stops waiting for finishes on it by itself.
            let closes = PendingCloses::new();
            match secret {
                Some(secret) => create_quick_client_endpoint(&relay, *secret, &closes).await,
                None => create_client_endpoint(&relay, &closes).await,
            }
        })
    })
}

/// Dial the server `server_id` from `endpoint`, on the ALPN `auth` calls for.
pub(crate) async fn dial_server(
    endpoint: &Endpoint,
    server_id: EndpointId,
    relay: &RelayConfig,
    auth: &ClientAuth,
) -> ProxyResult<Connection> {
    // Custom relays are also where the server is found: with them
    // configured, internet discovery is off and these hints are the route.
    let mut addr = EndpointAddr::new(server_id);
    for relay_url in relay.custom_urls() {
        addr = addr.with_relay_url(relay_url.clone());
    }
    let alpn = match auth {
        ClientAuth::Key(_) => crate::transport::ALPN,
        ClientAuth::Quick(_) => crate::transport::QUICK_ALPN,
    };
    connect_with_timeout(endpoint, addr, alpn).await
}

/// Send this client's `Hello` on the connection's first bi-stream and read the
/// server's answer, returning it — accepted or not — with the stream halves.
/// The stream is the connection's control channel: the server ends the
/// connection when it closes, so the halves are kept for as long as the
/// connection is used.
///
/// `own_id` is the client's endpoint id, which a keypair client signs into its
/// credential so the server can bind the signature to this very connection.
///
/// The whole exchange has [`HANDSHAKE_TIMEOUT`], the stream's opening
/// included: `open_bi` waits for the peer to grant a stream, with no bound of
/// its own, so a peer that grants none would otherwise hold the caller for as
/// long as it keeps the connection up.
pub(crate) async fn exchange_hello(
    connection: &Connection,
    auth: &ClientAuth,
    own_id: EndpointId,
    instance_nonce: u128,
    duplicate_server_observed: bool,
) -> ProxyResult<(SendStream, RecvStream, HelloResponse)> {
    let auth = match auth {
        ClientAuth::Key(key) => Some(signaling::ClientAuthPayload {
            public_key: key.public_str(),
            endpoint_id: own_id.to_string(),
            signature: crate::auth::sign_endpoint_id(key, &own_id),
        }),
        // Quick mode: the endpoint id is the credential; the server's
        // allowlist hook already authenticated it at the TLS handshake.
        ClientAuth::Quick(_) => None,
    };
    let mut hello = Hello::new(auth, instance_nonce);
    hello.duplicate_server_observed = duplicate_server_observed;
    let hello = signaling::encode_hello(&hello)?;

    let exchange = async {
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|e| ProxyError::Signaling(format!("Failed to open handshake stream: {e}")))?;
        signaling::write_message(&mut send, &hello).await?;
        send.flush().await?;
        let data = signaling::read_message(&mut recv, signaling::MAX_HANDSHAKE_SIZE).await?;
        ProxyResult::Ok((send, recv, data))
    };
    let (send, recv, data) = tokio::time::timeout(HANDSHAKE_TIMEOUT, exchange)
        .await
        .map_err(|_| {
            ProxyError::Signaling("timed out waiting for server handshake response".into())
        })??;
    let response = signaling::decode_hello_response(&data)?;
    Ok((send, recv, response))
}

/// What a destination is doing, for status displays.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DestinationState {
    /// Not connected, and nothing is asking for it. The resting state.
    Idle,
    /// Building its endpoint, connecting or authenticating.
    Connecting,
    /// Connected and authenticated.
    Connected,
    /// The last attempt failed; waiting to retry for the requests still held.
    Backoff,
    /// The server refused this client (e.g. an unauthorized key). Requests
    /// fail at once until the retry time.
    Failed,
}

impl DestinationState {
    /// A lowercase word for status output (`idle`, `connecting`, …).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Connecting => "connecting",
            Self::Connected => "connected",
            Self::Backoff => "backoff",
            Self::Failed => "failed",
        }
    }
}

/// A point-in-time view of one destination, for status displays.
#[derive(Clone, Debug)]
pub struct DestinationStatus {
    pub name: String,
    pub server_node_id: String,
    pub state: DestinationState,
    /// When the current connection was authenticated; `None` unless connected.
    pub connected_since: Option<std::time::Instant>,
    /// Streams open on the connection right now.
    pub open_streams: usize,
    /// Requests waiting for a connection right now.
    pub waiting: usize,
    /// This client's endpoint id toward this server; `None` while idle (the
    /// endpoint only exists while the destination is in use).
    pub client_node_id: Option<String>,
    /// Consecutive failed attempts in the current outage; 0 once connected.
    pub failed_attempts: u32,
    /// When the next attempt may run. Reached only if a request still wants
    /// the destination by then.
    pub next_attempt_at: Option<std::time::Instant>,
    /// What the most recent attempt (or the last connection) failed with.
    pub last_error: Option<String>,
    pub routed_domains: Vec<String>,
    pub routed_cidrs: Vec<String>,
    /// The custom relays configured for this destination; empty for the
    /// default iroh relays.
    pub relay_urls: Vec<String>,
    /// What the server said it routes, read on the latest connection that
    /// could read it; kept while idle. `None` until a connection has.
    pub server_routes: Option<ServerRoutes>,
    /// Why reading the server's routes on the latest connection failed;
    /// cleared by a read that succeeds. Alongside `server_routes`, those are
    /// the last known lists, from an earlier connection.
    pub server_routes_error: Option<String>,
    /// Each of this destination's rules with how much of it `server_routes`
    /// covers, graded once when they were read; empty until then.
    pub server_coverage: Arc<HashMap<Rule, Coverage>>,
    /// A connection is reading the server's routes again: until it has,
    /// `server_routes` (if any) is the last known answer.
    pub server_routes_pending: bool,
}

/// State every destination of one client shares.
pub(crate) struct Shared {
    /// Random per-process identity of this client, sent in every `Hello` so a
    /// server can tell a benign reconnect (same nonce) from two distinct client
    /// processes sharing a node id (different nonces → a duplicate-client bug).
    pub(crate) instance_nonce: u128,
    /// Close a connection with no open stream after this long; `None` never
    /// closes one for idleness.
    pub(crate) idle_timeout: Option<Duration>,
    pub(crate) provider: EndpointProvider,
    /// Whether the embedding app is backgrounded: slows the heartbeat (see
    /// [`client_heartbeat_loop`]) and, on the flip back, cuts a backoff short.
    pub(crate) background: watch::Sender<bool>,
    /// Whether the device reports a usable network path. While it does not,
    /// nothing is dialed — retrying into a dead path is pure battery burn.
    pub(crate) network_available: watch::Sender<bool>,
    /// Latched by `ProxyClient::close`: an endpoint whose build finishes after
    /// it is closed by its own build task instead of being installed.
    pub(crate) closed: AtomicBool,
}

/// The link to the server, as requests see it.
#[derive(Clone)]
enum Link {
    Idle,
    Dialing,
    Connected(Connection),
    Backoff,
    /// A permanent failure: requests fail with `reason` at once. The manager
    /// leaves this state at `retry_at`.
    Failed {
        reason: String,
        retry_at: Instant,
    },
    /// The client was closed ([`Destination::close`]). Terminal: requests are
    /// turned away, and no later transition replaces it.
    Closed,
}

/// Everything the request path and the manager coordinate on, in **one** watch
/// value so the counters and the link change together: a request leasing the
/// connection and the idle check closing it can never interleave.
#[derive(Clone)]
struct DestState {
    link: Link,
    /// Requests waiting in [`Destination::acquire`].
    waiters: usize,
    /// Leases outstanding — streams open on the connection.
    streams: usize,
    /// A one-shot request for a dial attempt with nobody waiting on it (see
    /// [`Destination::kick`]).
    kick: bool,
    /// When the current connection was authenticated. Kept with the link, so
    /// a status reads the two as of one moment: `Some` exactly while connected.
    connected_since: Option<Instant>,
    /// When the connection was last released — connected, a stream closed, a
    /// waiter gone. The idle timeout counts from here rather than from when
    /// the idle check happened to look: a use too short for it to observe
    /// still pushes the close back.
    unused_since: Instant,
}

/// Client-side history of server instance nonces observed for one server id,
/// used to detect a *duplicate server*.
///
/// A single server that merely restarts emits a strictly-growing sequence of
/// fresh random nonces (a previous one never reappears, 2⁻¹²⁸). A client
/// bouncing between two servers that share one identity sees a previously-seen
/// nonce **reappear** after a different one — that flip-flop is the signal.
#[derive(Default)]
struct ServerNonceTracker {
    /// Distinct nonces seen, in first-seen order.
    history: Vec<u128>,
    /// The most recently observed nonce.
    last: Option<u128>,
}

/// The parts of a destination's status that are not in [`DestState`].
#[derive(Default)]
struct StatusFields {
    client_node_id: Option<String>,
    failed_attempts: u32,
    next_attempt_at: Option<Instant>,
    last_error: Option<String>,
    server_routes: Option<ServerRoutes>,
    server_routes_error: Option<String>,
    server_coverage: Arc<HashMap<Rule, Coverage>>,
    server_routes_pending: bool,
    /// Counts the connections whose server routes were asked for: a read
    /// answers only while its connection is still the latest asked, so a
    /// slow read on an older connection never overwrites a newer answer.
    server_routes_generation: u64,
}

/// What one connection's read of its server's routes brought: the lists,
/// with this destination's rules graded against them, or why they could not
/// be read or compared.
type RoutesRead = Result<(ServerRoutes, Arc<HashMap<Rule, Coverage>>), String>;

impl StatusFields {
    /// Start a connection's read of its server's routes, returning its
    /// generation. Whatever is kept from an earlier connection is the last
    /// known answer until this read replaces it.
    fn begin_routes_read(&mut self) -> u64 {
        self.server_routes_generation += 1;
        self.server_routes_pending = true;
        self.server_routes_generation
    }

    /// Take the answer of the read started as `generation`. `None` when a
    /// later connection's read has started since: this one is stale and
    /// changes nothing. Otherwise `Some` of whether the server's lists differ
    /// from the ones kept. A failed read keeps the last good lists and grades,
    /// now the last known, alongside its error.
    fn finish_routes_read(&mut self, generation: u64, read: &RoutesRead) -> Option<bool> {
        if self.server_routes_generation != generation {
            return None;
        }
        self.server_routes_pending = false;
        Some(match read {
            Ok((routes, coverage)) => {
                let changed = self.server_routes.as_ref() != Some(routes);
                self.server_routes = Some(routes.clone());
                self.server_coverage = coverage.clone();
                self.server_routes_error = None;
                changed
            }
            Err(e) => {
                self.server_routes_error = Some(e.clone());
                false
            }
        })
    }
}

/// The manager's memory of the current outage. Survives idle periods, so a
/// server that stays down is probed at most once per backoff step however the
/// requests for it arrive, and the endpoint-rebuild budget stays per outage.
#[derive(Default)]
struct Outage {
    /// Consecutive failed attempts; 0 once connected.
    attempt: u32,
    /// When this outage last rebuilt the endpoint (`None`: not yet).
    last_rebuild: Option<std::time::Instant>,
    /// Earliest time the next attempt may run.
    next_attempt_at: Option<Instant>,
    /// The last wait was cut short by a restored network path or a
    /// foregrounded app: the endpoint needs the rebind nudge even though the
    /// attempt counter was reset.
    nudge: bool,
}

/// A destination's claim on its listener's budget of held requests: the holds
/// set aside for this destination, then the pool every destination shares. A
/// server that is down can fill its own share and the pool, but never the
/// share another destination needs to hold its first request while it
/// connects.
#[derive(Clone, Copy)]
pub(crate) struct Holds<'a> {
    pub(crate) reserved: &'a Semaphore,
    pub(crate) shared: &'a Semaphore,
}

impl<'a> Holds<'a> {
    fn try_acquire(self) -> Option<tokio::sync::SemaphorePermit<'a>> {
        self.reserved
            .try_acquire()
            .or_else(|_| self.shared.try_acquire())
            .ok()
    }
}

impl Outage {
    /// Start a fresh backoff series with an attempt due right now.
    fn reset_backoff(&mut self) {
        self.attempt = 0;
        self.next_attempt_at = None;
        self.nudge = true;
    }
}

/// Why [`Destination::acquire`] returned no connection.
#[derive(Debug)]
pub(crate) enum AcquireError {
    /// No connection within [`TUNNEL_RECOVERY_HOLD`].
    TimedOut,
    /// The caller's hold budget was exhausted, so the request was not held. A
    /// dial was still requested, so the destination does not depend on some
    /// later request finding a free hold.
    HoldCap,
    /// The server refused this client; retrying now would fail the same way.
    Failed(String),
    /// The client is shutting down.
    Closed,
}

impl std::fmt::Display for AcquireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TimedOut => write!(
                f,
                "no connection to the server after {}s",
                TUNNEL_RECOVERY_HOLD.as_secs()
            ),
            Self::HoldCap => f.write_str("too many requests are already waiting for a connection"),
            Self::Failed(reason) => f.write_str(reason),
            Self::Closed => f.write_str("the client is shutting down"),
        }
    }
}

/// A live connection plus the claim that keeps it from being closed as idle.
/// Hold it for as long as a stream opened on [`Self::conn`] is in use.
pub(crate) struct Lease {
    pub(crate) conn: Connection,
    _stream: StreamGuard,
}

impl Lease {
    /// Split into the connection and the bare claim, for a caller that keeps
    /// the claim alongside the stream it opens.
    pub(crate) fn into_parts(self) -> (Connection, StreamGuard) {
        (self.conn, self._stream)
    }
}

/// Counts one open stream against its destination until dropped.
pub(crate) struct StreamGuard(Arc<Destination>);

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.0.state.send_modify(|s| {
            s.streams -= 1;
            s.unused_since = Instant::now();
        });
    }
}

/// Counts one waiting request against its destination until dropped.
struct WaiterGuard<'a>(&'a Destination);

impl Drop for WaiterGuard<'_> {
    fn drop(&mut self) {
        self.0.state.send_modify(|s| {
            s.waiters -= 1;
            s.unused_since = Instant::now();
        });
    }
}

/// How a connection ended.
enum ConnEnd {
    /// Unused for the idle timeout; the link is already `Idle`.
    Idle,
    Lost(ProxyError),
}

/// One destination and its connection manager. See the module docs.
pub(crate) struct Destination {
    cfg: DestinationConfig,
    shared: Arc<Shared>,
    state: watch::Sender<DestState>,
    /// The endpoint, present from the first dial until the destination goes
    /// idle. Std lock: never held across an await.
    endpoint: Mutex<Option<ClientEndpoint>>,
    /// Held by an endpoint build for its whole duration, so [`Self::close`]
    /// can wait a build in flight out instead of leaving it to be cut off.
    building: tokio::sync::Mutex<()>,
    nonce_tracker: Mutex<ServerNonceTracker>,
    /// Latches once a duplicate server has been observed; thereafter every
    /// `Hello` to this server carries the advisory so it can self-block.
    duplicate_server: AtomicBool,
    status: Mutex<StatusFields>,
}

impl Destination {
    pub(crate) fn new(cfg: DestinationConfig, shared: Arc<Shared>) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            shared,
            state: watch::Sender::new(DestState {
                link: Link::Idle,
                waiters: 0,
                streams: 0,
                kick: false,
                connected_since: None,
                unused_since: Instant::now(),
            }),
            endpoint: Mutex::new(None),
            building: tokio::sync::Mutex::new(()),
            nonce_tracker: Mutex::new(ServerNonceTracker::default()),
            duplicate_server: AtomicBool::new(false),
            status: Mutex::new(StatusFields::default()),
        })
    }

    pub(crate) fn name(&self) -> &str {
        &self.cfg.name
    }

    /// Whether anything wants this destination connected right now.
    fn wanted(&self, s: &DestState) -> bool {
        s.waiters > 0 || s.kick || self.cfg.keep_connected
    }

    /// Whether the connection is in use (and so must not be closed as idle).
    fn in_use(&self, s: &DestState) -> bool {
        s.waiters > 0 || s.streams > 0 || self.cfg.keep_connected
    }

    /// Move the link, and with it what belongs to it: a connection starts its
    /// uptime and its idle clock here, and leaving `Connected` ends the
    /// uptime. `Closed` is terminal and stays.
    fn set_link(&self, link: Link) {
        self.state.send_if_modified(|s| {
            if matches!(s.link, Link::Closed) {
                return false;
            }
            s.connected_since = None;
            if matches!(link, Link::Connected(_)) {
                let now = Instant::now();
                s.connected_since = Some(now);
                s.unused_since = now;
            }
            s.link = link;
            true
        });
    }

    fn status_fields(&self) -> std::sync::MutexGuard<'_, StatusFields> {
        self.status.lock().expect("destination status lock")
    }

    /// Ask for one dial attempt without waiting for it: the destination
    /// connects (or fails) in the background, and the connection then lives or
    /// idles out like any other. A no-op while connected or already wanted.
    pub(crate) fn kick(&self) {
        self.state.send_if_modified(|s| {
            if s.kick || matches!(s.link, Link::Connected(_)) {
                return false;
            }
            s.kick = true;
            true
        });
    }

    /// Lease the live connection if there is one, atomically with the counter
    /// update so the idle check cannot close it in between.
    fn try_lease(self: &Arc<Self>) -> Result<Option<Lease>, AcquireError> {
        let mut outcome = Ok(None);
        self.state.send_if_modified(|s| match &s.link {
            Link::Connected(conn) => {
                s.streams += 1;
                outcome = Ok(Some(conn.clone()));
                true
            }
            Link::Failed { reason, .. } => {
                outcome = Err(AcquireError::Failed(reason.clone()));
                false
            }
            Link::Closed => {
                outcome = Err(AcquireError::Closed);
                false
            }
            _ => false,
        });
        outcome.map(|conn| {
            conn.map(|conn| Lease {
                conn,
                _stream: StreamGuard(self.clone()),
            })
        })
    }

    /// The live connection, immediately when one is up, otherwise a bounded
    /// wait while it is dialed — which this very call triggers. Gives up after
    /// [`TUNNEL_RECOVERY_HOLD`], at once on a permanent failure, or — when
    /// `holds` is given and exhausted — without waiting at all, so held
    /// requests can never pin a caller's whole connection budget.
    pub(crate) async fn acquire(
        self: &Arc<Self>,
        holds: Option<Holds<'_>>,
    ) -> Result<Lease, AcquireError> {
        if let Some(lease) = self.try_lease()? {
            return Ok(lease);
        }
        let _hold = match holds {
            Some(holds) => match holds.try_acquire() {
                Some(permit) => Some(permit),
                None => {
                    log::debug!(
                        "Hold capacity exhausted; not holding request for {}",
                        self.name()
                    );
                    self.kick();
                    return Err(AcquireError::HoldCap);
                }
            },
            None => None,
        };
        log::debug!(
            "{} is not connected; holding request up to {}s while it connects",
            self.name(),
            TUNNEL_RECOVERY_HOLD.as_secs()
        );
        let mut live = self.state.subscribe();
        self.state.send_modify(|s| s.waiters += 1);
        let _waiter = WaiterGuard(self);
        let leased = async {
            loop {
                // `wait_for` inspects the current value first, so a publish
                // racing the registration above is never missed.
                let settled = |s: &DestState| {
                    matches!(
                        s.link,
                        Link::Connected(_) | Link::Failed { .. } | Link::Closed
                    )
                };
                if live.wait_for(settled).await.is_err() {
                    return Err(AcquireError::Closed);
                }
                if let Some(lease) = self.try_lease()? {
                    return Ok(lease);
                }
            }
        };
        tokio::time::timeout(TUNNEL_RECOVERY_HOLD, leased)
            .await
            .unwrap_or(Err(AcquireError::TimedOut))
    }

    /// The live connection, if any, without affecting the idle timer.
    fn connection(&self) -> Option<Connection> {
        match &self.state.borrow().link {
            Link::Connected(conn) => Some(conn.clone()),
            _ => None,
        }
    }

    /// The connection's iroh paths plus an on-demand health probe of the
    /// destination's custom relays; empty while not connected.
    pub(crate) async fn connection_snapshot(&self) -> ConnectionSnapshot {
        match self.connection() {
            Some(conn) => {
                crate::transport::paths::connection_snapshot(&conn, &self.cfg.relay).await
            }
            None => ConnectionSnapshot::default(),
        }
    }

    pub(crate) fn status(&self) -> DestinationStatus {
        // The state and the uptime that goes with it, as of one moment.
        let (state, connected_since, open_streams, waiting) = {
            let s = self.state.borrow();
            let state = match s.link {
                Link::Idle | Link::Closed => DestinationState::Idle,
                Link::Dialing => DestinationState::Connecting,
                Link::Connected(_) => DestinationState::Connected,
                Link::Backoff => DestinationState::Backoff,
                Link::Failed { .. } => DestinationState::Failed,
            };
            (state, s.connected_since, s.streams, s.waiters)
        };
        let fields = self.status_fields();
        DestinationStatus {
            name: self.cfg.name.clone(),
            server_node_id: self.cfg.server_id.to_string(),
            state,
            connected_since: connected_since.map(Instant::into_std),
            open_streams,
            waiting,
            client_node_id: fields.client_node_id.clone(),
            failed_attempts: fields.failed_attempts,
            next_attempt_at: fields.next_attempt_at.map(Instant::into_std),
            last_error: fields.last_error.clone(),
            routed_domains: self.cfg.routed_domains.clone(),
            routed_cidrs: self.cfg.routed_cidrs.clone(),
            relay_urls: self
                .cfg
                .relay
                .custom_urls()
                .iter()
                .map(ToString::to_string)
                .collect(),
            server_routes: fields.server_routes.clone(),
            server_routes_error: fields.server_routes_error.clone(),
            server_coverage: fields.server_coverage.clone(),
            server_routes_pending: fields.server_routes_pending,
        }
    }

    /// Close the endpoint at client shutdown, first waiting out an endpoint
    /// build in flight. `Shared::closed` is already latched, so that build
    /// closes the endpoint it produced, and no later one starts.
    ///
    /// The link goes to its terminal state first: requests held for this
    /// destination end at once, and a dialer that outlives the client is
    /// turned away instead of leasing a connection about to be closed.
    pub(crate) async fn close(&self) {
        self.state.send_modify(|s| {
            s.link = Link::Closed;
            s.connected_since = None;
        });
        drop(self.building.lock().await);
        let endpoint = self.endpoint.lock().expect("endpoint slot lock").take();
        if let Some(endpoint) = endpoint {
            endpoint.close().await;
        }
    }

    /// The connection manager: runs for the life of the client, never returns.
    pub(crate) async fn run(self: Arc<Self>) {
        let mut outage = Outage::default();
        loop {
            self.wait_until_due(&mut outage).await;
            self.set_link(Link::Dialing);
            match self.connect_once(&mut outage).await {
                Ok((connection, ctrl_send, ctrl_recv)) => {
                    // Connected: the outage, if there was one, is over.
                    outage = Outage::default();
                    {
                        let mut fields = self.status_fields();
                        fields.failed_attempts = 0;
                        fields.next_attempt_at = None;
                        fields.last_error = None;
                    }
                    // Publishing the connection wakes every request held in
                    // [`Self::acquire`].
                    self.set_link(Link::Connected(connection.clone()));
                    self.check_server_routes(&connection);
                    let end = self.serve(&connection, ctrl_send, ctrl_recv).await;
                    match end {
                        ConnEnd::Idle => {
                            log::info!(
                                "{}: no open stream for {}s; closing the idle connection",
                                self.name(),
                                self.shared.idle_timeout.unwrap_or_default().as_secs()
                            );
                            connection.close(0u32.into(), b"idle");
                        }
                        ConnEnd::Lost(e) => self.record_failure(e, &mut outage),
                    }
                }
                Err(e) => self.record_failure(e, &mut outage),
            }
        }
    }

    /// Read what the server on the fresh `connection` routes, on a task of its
    /// own so no request waits for it, and keep the answer for the status,
    /// with each of this destination's rules graded against it. A rule the
    /// server does not route in full is logged: the server refuses what is
    /// sent under it. The read opens a stream of its own on the connection
    /// without leasing it, so it neither keeps the connection from idling out
    /// nor survives its close. The answer is kept after the connection
    /// closes, until a later connection reads another.
    fn check_server_routes(self: &Arc<Self>, connection: &Connection) {
        let this = self.clone();
        let connection = connection.clone();
        let generation = self.status_fields().begin_routes_read();
        tokio::spawn(async move {
            // Graded before the status lock is taken, and off the async
            // workers: it is the work of both whole lists, and the status is
            // read on every poll.
            let read = match server_routes::read_routes(&connection).await {
                Ok(routes) => {
                    let grader = this.clone();
                    tokio::task::spawn_blocking(move || {
                        let coverage = grader.grade(&routes)?;
                        Ok((routes, coverage))
                    })
                    .await
                    .unwrap_or_else(|e| Err(format!("grading the server's routes failed: {e}")))
                }
                Err(e) => Err(e),
            };
            let Some(changed) = this.status_fields().finish_routes_read(generation, &read) else {
                return;
            };
            match read {
                Ok((_, coverage)) if changed => this.log_refused_rules(&coverage),
                Ok(_) => {}
                Err(e) => log::warn!(
                    "{}: could not read what the server routes: {e}",
                    this.name()
                ),
            }
        });
    }

    /// Each of this destination's rules with how much of it `routes` (the
    /// server's) covers, or why the two cannot be compared — a read that
    /// failed, so an earlier answer stays as the last known.
    fn grade(&self, routes: &ServerRoutes) -> Result<Arc<HashMap<Rule, Coverage>>, String> {
        RoutedSet::new(&self.cfg.routed_domains, &self.cfg.routed_cidrs)
            .and_then(|own| routes.coverage_of(&own))
            .map(Arc::new)
            .map_err(|e| format!("cannot compare routes with the server's: {e:#}"))
    }

    /// Log each of this destination's rules the server does not route in
    /// full, by `coverage` (see [`Self::grade`]).
    fn log_refused_rules(&self, coverage: &HashMap<Rule, Coverage>) {
        let mut refused: Vec<(&Rule, Coverage)> = coverage
            .iter()
            .filter(|(_, c)| **c != Coverage::Full)
            .map(|(rule, c)| (rule, *c))
            .collect();
        refused.sort_by_cached_key(|(rule, _)| rule.to_string());
        for (rule, coverage) in refused {
            match coverage {
                Coverage::Full => {}
                Coverage::Partial => log::warn!(
                    "{}: the server routes only part of {rule}; the rest is refused when sent",
                    self.name()
                ),
                Coverage::None => log::warn!(
                    "{}: the server does not route {rule}; what is sent under it is refused",
                    self.name()
                ),
            }
        }
    }

    /// Record a failed attempt or a lost connection and move the link out of
    /// `Dialing`/`Connected`: to `Backoff` for a recoverable error (requests
    /// keep waiting for the retry), to `Failed` for a permanent one (requests
    /// fail at once). Either way the next attempt is one backoff step away.
    fn record_failure(&self, e: ProxyError, outage: &mut Outage) {
        outage.attempt += 1;
        let backoff = calculate_backoff(outage.attempt);
        let due = Instant::now() + backoff;
        outage.next_attempt_at = Some(due);
        {
            let mut fields = self.status_fields();
            fields.failed_attempts = outage.attempt;
            fields.last_error = Some(e.to_string());
            fields.next_attempt_at = Some(due);
        }
        if e.is_recoverable() {
            log::warn!(
                "{}: {e}; next attempt in {:.1}s if still needed (attempt {})",
                self.name(),
                backoff.as_secs_f64(),
                outage.attempt
            );
            self.set_link(Link::Backoff);
        } else {
            log::error!(
                "{}: {e}; refusing requests for {:.1}s",
                self.name(),
                backoff.as_secs_f64()
            );
            self.set_link(Link::Failed {
                reason: e.to_string(),
                retry_at: due,
            });
        }
    }

    /// Wait until an attempt should run: something wants the destination, the
    /// device has a network path, and the outage's backoff has elapsed. With
    /// nothing wanting it the destination rests in `Idle` with its endpoint
    /// released — for as long as that lasts.
    async fn wait_until_due(&self, outage: &mut Outage) {
        let mut state = self.state.subscribe();
        // A permanent failure answers every request at once until its retry
        // time, wanted or not.
        let failed_until = match &state.borrow().link {
            Link::Failed { retry_at, .. } => Some(*retry_at),
            _ => None,
        };
        if let Some(retry_at) = failed_until {
            tokio::time::sleep_until(retry_at).await;
        }

        let mut available = self.shared.network_available.subscribe();
        loop {
            if !self.wanted(&state.borrow_and_update()) {
                self.set_link(Link::Idle);
                self.release_endpoint().await;
                // Rest until something wants the destination — but keep an
                // eye on the network meanwhile: a path that comes back makes
                // a retry time set before it went away stale, and the request
                // that ends this rest must not be made to wait that out.
                let mut online = *available.borrow_and_update();
                loop {
                    tokio::select! {
                        wanted = async { state.wait_for(|s| self.wanted(s)).await.is_ok() } => {
                            if !wanted {
                                std::future::pending::<()>().await;
                            }
                            break;
                        }
                        changed = available.changed() => {
                            if changed.is_err() {
                                std::future::pending::<()>().await;
                            }
                            let now_online = *available.borrow_and_update();
                            if now_online && !online {
                                log::debug!("{}: network available again while idle", self.name());
                                self.reset_backoff(outage);
                            }
                            online = now_online;
                        }
                    }
                }
                continue;
            }
            if !*available.borrow_and_update() {
                // No usable path: park with no timers at all, and give the
                // restored network an immediate, fresh attempt.
                log::info!(
                    "{}: network unavailable; not dialing until a path returns",
                    self.name()
                );
                self.set_link(Link::Backoff);
                tokio::select! {
                    r = available.wait_for(|a| *a) => {
                        if r.is_ok() {
                            log::info!("{}: network available again", self.name());
                            self.reset_backoff(outage);
                        }
                    }
                    _ = state.wait_for(|s| !self.wanted(s)) => {}
                }
                continue;
            }
            let Some(due) = outage.next_attempt_at.filter(|due| *due > Instant::now()) else {
                break;
            };
            self.set_link(Link::Backoff);
            tokio::select! {
                _ = tokio::time::sleep_until(due) => {}
                // Nobody is waiting any more: rest (the loop goes idle).
                _ = state.wait_for(|s| !self.wanted(s)) => {}
                // The path went away mid-wait: park (the loop does).
                _ = available.wait_for(|a| !*a) => {}
                // A backoff step sized for an unattended outage must not keep
                // a user who is now looking waiting.
                _ = foregrounded(&self.shared.background) => {
                    log::info!("{}: app foregrounded; connecting now", self.name());
                    self.reset_backoff(outage);
                }
            }
        }
        // The attempt about to run is the one a kick asked for.
        self.state.send_if_modified(|s| {
            s.kick = false;
            false
        });
    }

    fn reset_backoff(&self, outage: &mut Outage) {
        outage.reset_backoff();
        self.status_fields().next_attempt_at = Some(Instant::now());
    }

    /// One attempt: make sure there is an endpoint (nudged or rebuilt when the
    /// outage calls for it), then connect and authenticate.
    async fn connect_once(
        self: &Arc<Self>,
        outage: &mut Outage,
    ) -> ProxyResult<(Connection, SendStream, RecvStream)> {
        let existing = self.endpoint.lock().expect("endpoint slot lock").clone();
        let endpoint = match existing {
            Some(endpoint) => {
                if rebuild_due(outage.attempt, outage.last_rebuild) {
                    // Escalation: the nudge wasn't enough — rebuild the
                    // endpoint from scratch. On a rebuild failure (e.g. no
                    // route to bind on a dead network) the current endpoint
                    // stays in place and this attempt proceeds with it; the
                    // failed rebuild still counts against the interval.
                    log::warn!(
                        "{}: still failing after {} attempts; rebuilding the endpoint from scratch",
                        self.name(),
                        outage.attempt
                    );
                    outage.last_rebuild = Some(std::time::Instant::now());
                    if let Err(e) = endpoint.rebuild().await {
                        log::warn!(
                            "{}: endpoint rebuild failed ({e:#}); retrying with the current endpoint",
                            self.name()
                        );
                    }
                } else if outage.attempt > 0 || outage.nudge {
                    // Retrying after a failure: the endpoint's UDP sockets may
                    // be dead underneath it (iOS defuncts them while the
                    // process is suspended; a sleeping laptop can do the same)
                    // and iroh cannot always detect that by itself. Nudging it
                    // re-checks and rebinds the transports — harmless when
                    // nothing actually changed.
                    endpoint.endpoint().network_change().await;
                }
                endpoint
            }
            None => self.build_endpoint().await?,
        };
        outage.nudge = false;
        // The endpoint handle is taken fresh per attempt — a rebuild swapped it.
        let endpoint = endpoint.endpoint();
        self.status_fields().client_node_id = Some(endpoint.id().to_string());
        self.establish(&endpoint).await
    }

    /// Build this destination's endpoint and install it.
    ///
    /// The build runs as its own task so it is never cancelled half-way (a
    /// bound endpoint must be closed, not dropped): if the client is torn down
    /// while it is in flight, the task still finishes, finds
    /// [`Shared::closed`] latched, and closes the endpoint it built —
    /// [`Self::close`] waits for exactly that.
    async fn build_endpoint(self: &Arc<Self>) -> ProxyResult<ClientEndpoint> {
        let this = self.clone();
        let build = tokio::spawn(async move {
            let _building = this.building.lock().await;
            // `close` latches the flag before it takes the build lock: having
            // the lock with the flag set means the client is gone already.
            if this.shared.closed.load(Ordering::SeqCst) {
                anyhow::bail!("the client is shutting down");
            }
            let endpoint = (this.shared.provider)(&this.cfg).await?;
            let installed = {
                let mut slot = this.endpoint.lock().expect("endpoint slot lock");
                // Checked under the slot lock: `ProxyClient::close` latches the
                // flag before it empties the slots, so either it finds this
                // endpoint there or we see the flag here.
                if this.shared.closed.load(Ordering::SeqCst) {
                    false
                } else {
                    *slot = Some(endpoint.clone());
                    true
                }
            };
            if !installed {
                endpoint.close().await;
                anyhow::bail!("the client is shutting down");
            }
            Ok(endpoint)
        });
        match build.await {
            Ok(Ok(endpoint)) => {
                log::info!("{}: client node id {}", self.name(), endpoint.id());
                Ok(endpoint)
            }
            // Recoverable: the usual cause is the network (no relay reachable,
            // nothing to bind on), which a later attempt may find repaired.
            Ok(Err(e)) => Err(ProxyError::Signaling(format!(
                "Failed to create the iroh endpoint: {e:#}"
            ))),
            Err(e) => Err(ProxyError::Signaling(format!(
                "Endpoint creation task failed: {e}"
            ))),
        }
    }

    /// Close and forget the endpoint, if there is one (the destination is
    /// going idle).
    async fn release_endpoint(&self) {
        let endpoint = self.endpoint.lock().expect("endpoint slot lock").take();
        let Some(endpoint) = endpoint else {
            return;
        };
        self.status_fields().client_node_id = None;
        // Graceful close on its own task: bounded wait here, but the task is
        // never cancelled (see [`IDLE_CLOSE_TIMEOUT`]).
        let mut close = tokio::spawn(async move { endpoint.close().await });
        if tokio::time::timeout(IDLE_CLOSE_TIMEOUT, &mut close)
            .await
            .is_err()
        {
            log::warn!(
                "{}: idle endpoint's close is slow; leaving it to finish in the background",
                self.name()
            );
        }
    }

    /// Connect to the server and complete the auth handshake, returning the
    /// connection and the control-stream halves (kept open for heartbeats).
    async fn establish(
        &self,
        endpoint: &Endpoint,
    ) -> ProxyResult<(Connection, SendStream, RecvStream)> {
        log::info!(
            "{}: connecting to server {}",
            self.name(),
            self.cfg.server_id
        );
        let connection = dial_server(
            endpoint,
            self.cfg.server_id,
            &self.cfg.relay,
            &self.cfg.auth,
        )
        .await?;
        log::info!("{}: connected, authenticating...", self.name());
        let (send, recv) = self.handshake(&connection, endpoint.id()).await?;
        log::info!("{}: authenticated", self.name());
        Ok((connection, send, recv))
    }

    /// Perform the connection-level auth handshake on the first bi-stream,
    /// returning the control-stream halves — the stream is **not** closed; it
    /// stays open as the heartbeat channel.
    ///
    /// `own_id` is this client's (ephemeral) endpoint id, which a keypair
    /// client signs into its credential so the server can bind the signature
    /// to this very connection.
    async fn handshake(
        &self,
        connection: &Connection,
        own_id: EndpointId,
    ) -> ProxyResult<(SendStream, RecvStream)> {
        let (send, recv, response) = exchange_hello(
            connection,
            &self.cfg.auth,
            own_id,
            self.shared.instance_nonce,
            self.duplicate_server.load(Ordering::Relaxed),
        )
        .await?;

        // Record the server's instance nonce (drives duplicate-server detection)
        // before the accept/reject branch so a rejection still updates history.
        let newly_flagged_duplicate = self.observe_server_nonce(response.server_instance_nonce);

        if !response.accepted {
            let reason = response
                .reject_reason
                .unwrap_or_else(|| "unknown".to_string());
            return Err(ProxyError::AuthenticationFailed(reason));
        }

        // The `Hello` already sent on this handshake could not carry the advisory
        // (the duplicate was only detected from this very response). Drop the
        // connection with a recoverable error so the retry's `Hello` advises the
        // server to self-block — the request that asked for this connection is
        // still waiting, so the retry follows within one backoff step.
        if newly_flagged_duplicate {
            return Err(ProxyError::ConnectionLost(
                "duplicate server id detected; reconnecting to advise the server to self-block"
                    .into(),
            ));
        }
        Ok((send, recv))
    }

    /// Record a server instance nonce observed in a `HelloResponse` and apply the
    /// reappearance rule. Latches [`Self::duplicate_server`] on a confirmed
    /// duplicate; a plain change (restart or first sight of a second instance) is
    /// only logged. Returns `true` only when this call *newly* latched the flag,
    /// so the caller can force a reconnect to get the advisory out.
    fn observe_server_nonce(&self, nonce: u128) -> bool {
        let mut t = self.nonce_tracker.lock().expect("nonce tracker lock");
        let mut newly_flagged = false;
        match t.last {
            Some(last) if last == nonce => return false, // same server as last time
            Some(_) => {
                if t.history.contains(&nonce) {
                    // A previously-seen nonce reappeared after a different one:
                    // two concurrent servers share this identity.
                    newly_flagged = !self.duplicate_server.swap(true, Ordering::Relaxed);
                    if newly_flagged {
                        log::error!(
                            "{}: duplicate server id detected: server instance nonce {nonce} \
                             reappeared after a different one — two servers appear to share \
                             this identity. Advising the server to self-block.",
                            self.name()
                        );
                    }
                } else {
                    log::warn!(
                        "{}: server identity nonce changed ({nonce}) — a restart, or possibly \
                         a second server sharing this id; watching for a reappearance.",
                        self.name()
                    );
                    t.history.push(nonce);
                }
            }
            None => t.history.push(nonce), // first observation this process
        }
        t.last = Some(nonce);
        newly_flagged
    }

    /// Keep an established connection until it ends: the heartbeat fails, the
    /// QUIC connection closes, or it sits unused for the idle timeout.
    async fn serve(
        &self,
        connection: &Connection,
        ctrl_send: SendStream,
        ctrl_recv: RecvStream,
    ) -> ConnEnd {
        // Log the selected path (relay/direct) and any later switch, for the
        // lifetime of this connection. Guard is dropped when `serve` returns.
        let _path_watcher = crate::transport::paths::watch_connection_paths(connection);
        tokio::select! {
            r = client_heartbeat_loop(ctrl_send, ctrl_recv, self.shared.background.subscribe()) => {
                ConnEnd::Lost(r.err().unwrap_or_else(|| {
                    ProxyError::ConnectionLost("heartbeat channel ended".into())
                }))
            }
            reason = connection.closed() => {
                ConnEnd::Lost(ProxyError::ConnectionLost(reason.to_string()))
            }
            _ = self.idle_elapsed() => ConnEnd::Idle,
        }
    }

    /// Whether the connection may be closed as idle at `now`: connected, not
    /// in use, and released at least `idle_timeout` ago.
    fn idle_due(&self, s: &DestState, idle_timeout: Duration, now: Instant) -> bool {
        !self.in_use(s)
            && matches!(s.link, Link::Connected(_))
            && now.saturating_duration_since(s.unused_since) >= idle_timeout
    }

    /// Resolve once the connection has been unused — no stream open, nobody
    /// waiting — for the whole idle timeout, having moved the link to `Idle`
    /// in the same step that confirmed it (so no request can lease the
    /// connection after the decision). Never resolves with no idle timeout.
    async fn idle_elapsed(&self) {
        let Some(idle_timeout) = self.shared.idle_timeout else {
            return std::future::pending().await;
        };
        let mut state = self.state.subscribe();
        loop {
            // The deadline counts from the last release as recorded in the
            // state, not from when this task saw the connection unused: a
            // stream opened and closed between two looks leaves the count as
            // it was, and only its release time says the connection was used.
            let unused = state.wait_for(|s| !self.in_use(s)).await;
            let Some(unused_since) = unused.map(|s| s.unused_since).ok() else {
                return std::future::pending().await;
            };
            tokio::select! {
                _ = tokio::time::sleep_until(unused_since + idle_timeout) => {
                    let went_idle = self.state.send_if_modified(|s| {
                        if !self.idle_due(s, idle_timeout, Instant::now()) {
                            return false;
                        }
                        s.link = Link::Idle;
                        s.connected_since = None;
                        true
                    });
                    if went_idle {
                        return;
                    }
                }
                // Used again: start the timer over when it next falls unused.
                _ = state.wait_for(|s| self.in_use(s)) => {}
            }
        }
    }
}

/// Resolve when the embedding app *comes* to the foreground: the next time it
/// goes from backgrounded to foregrounded, whether it is backgrounded already
/// or only becomes so later in the wait. An app that stays in the foreground
/// never resolves this — its backoff runs its full course.
async fn foregrounded(background: &watch::Sender<bool>) {
    let mut background = background.subscribe();
    if background.wait_for(|b| *b).await.is_ok() && background.wait_for(|b| !*b).await.is_ok() {
        return;
    }
    std::future::pending::<()>().await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routes(domains: &[&str]) -> ServerRoutes {
        ServerRoutes {
            routed_domains: domains.iter().map(|d| d.to_string()).collect(),
            routed_cidrs: Vec::new(),
        }
    }

    fn answer(domains: &[&str], coverage: Coverage) -> RoutesRead {
        let graded = HashMap::from([(Rule::Suffix("corp.example".into()), coverage)]);
        Ok((routes(domains), Arc::new(graded)))
    }

    /// A read a later connection's read has overtaken changes nothing, and
    /// is not reported as a change; the newer one's answer stands.
    #[test]
    fn a_stale_routes_read_is_ignored() {
        let mut fields = StatusFields::default();
        let older = fields.begin_routes_read();
        let newer = fields.begin_routes_read();
        assert_eq!(
            fields.finish_routes_read(newer, &answer(&["*.corp.example"], Coverage::Full)),
            Some(true)
        );
        assert_eq!(
            fields.finish_routes_read(older, &answer(&["*.other.example"], Coverage::None)),
            None
        );
        assert_eq!(fields.server_routes, Some(routes(&["*.corp.example"])));
        assert!(!fields.server_routes_pending);
        // A late failure of the older read does not mark the newer answer
        // stale either.
        assert_eq!(
            fields.finish_routes_read(older, &Err("timed out".into())),
            None
        );
        assert_eq!(fields.server_routes_error, None);
    }

    /// A failed read after a good one keeps the good lists and grades — the
    /// last known — with the error; a later good read clears it.
    #[test]
    fn a_failed_routes_read_keeps_the_last_good_answer() {
        let mut fields = StatusFields::default();
        let first = fields.begin_routes_read();
        fields.finish_routes_read(first, &answer(&["*.corp.example"], Coverage::Full));
        let second = fields.begin_routes_read();
        assert!(
            fields.server_routes_pending,
            "kept lists are the last known while read again"
        );
        assert_eq!(
            fields.finish_routes_read(second, &Err("refused".into())),
            Some(false)
        );
        assert_eq!(fields.server_routes, Some(routes(&["*.corp.example"])));
        assert_eq!(
            fields
                .server_coverage
                .get(&Rule::Suffix("corp.example".into())),
            Some(&Coverage::Full)
        );
        assert_eq!(fields.server_routes_error.as_deref(), Some("refused"));
        assert!(!fields.server_routes_pending);
        let third = fields.begin_routes_read();
        assert_eq!(
            fields.finish_routes_read(third, &answer(&["*.corp.example"], Coverage::Full)),
            Some(false)
        );
        assert_eq!(fields.server_routes_error, None);
    }

    /// The same lists again are no change (nothing to log again); other
    /// lists are, and replace the grades.
    #[test]
    fn identical_routes_are_no_change() {
        let mut fields = StatusFields::default();
        let first = fields.begin_routes_read();
        assert_eq!(
            fields.finish_routes_read(first, &answer(&["*.corp.example"], Coverage::Full)),
            Some(true)
        );
        let second = fields.begin_routes_read();
        assert_eq!(
            fields.finish_routes_read(second, &answer(&["*.corp.example"], Coverage::Full)),
            Some(false)
        );
        let third = fields.begin_routes_read();
        assert_eq!(
            fields.finish_routes_read(third, &answer(&["*.example"], Coverage::Partial)),
            Some(true)
        );
        assert_eq!(
            fields
                .server_coverage
                .get(&Rule::Suffix("corp.example".into())),
            Some(&Coverage::Partial)
        );
    }

    fn shared(idle_timeout: Option<Duration>) -> Arc<Shared> {
        Arc::new(Shared {
            instance_nonce: 1,
            idle_timeout,
            // Never called: these tests drive the request path only.
            provider: Arc::new(|_| Box::pin(async { anyhow::bail!("no endpoint in this test") })),
            background: watch::Sender::new(false),
            network_available: watch::Sender::new(true),
            closed: AtomicBool::new(false),
        })
    }

    fn destination(keep_connected: bool) -> Arc<Destination> {
        let secret = SecretKey::from_bytes(&[7u8; 32]);
        Destination::new(
            DestinationConfig {
                name: "m1".to_string(),
                server_id: secret.public(),
                auth: ClientAuth::Quick(Box::new(secret)),
                relay: RelayConfig::default(),
                routed_domains: Vec::new(),
                routed_cidrs: Vec::new(),
                keep_connected,
            },
            shared(None),
        )
    }

    #[test]
    fn a_fresh_destination_is_idle_and_unwanted() {
        let d = destination(false);
        let status = d.status();
        assert_eq!(status.state, DestinationState::Idle);
        assert_eq!((status.open_streams, status.waiting), (0, 0));
        assert!(status.client_node_id.is_none());
        assert!(!d.wanted(&d.state.borrow()));
        // A kept-connected destination is wanted from the start.
        let kept = destination(true);
        assert!(kept.wanted(&kept.state.borrow()));
    }

    #[test]
    fn nonce_reappearance_latches_a_duplicate_server() {
        let d = destination(false);
        assert!(!d.observe_server_nonce(1), "first sight");
        assert!(!d.observe_server_nonce(1), "same server");
        assert!(!d.observe_server_nonce(2), "a change alone is a restart");
        assert!(
            d.observe_server_nonce(1),
            "an old nonce back again is a duplicate"
        );
        assert!(d.duplicate_server.load(Ordering::Relaxed));
        assert!(
            !d.observe_server_nonce(2),
            "already latched: not newly flagged"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_waits_then_times_out_and_stops_counting() {
        let d = destination(false);
        let waiting = {
            let d = d.clone();
            tokio::spawn(async move { d.acquire(None).await.map(|_| ()) })
        };
        // The waiter registered: the destination is now wanted.
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(d.status().waiting, 1);
        assert!(d.wanted(&d.state.borrow()));

        // No manager runs here, so nothing ever connects: the hold elapses.
        let result = waiting.await.unwrap();
        assert!(matches!(result, Err(AcquireError::TimedOut)), "{result:?}");
        assert_eq!(d.status().waiting, 0);
        assert!(!d.wanted(&d.state.borrow()));
    }

    #[tokio::test]
    async fn at_the_hold_cap_a_request_is_refused_but_still_asks_for_a_dial() {
        let d = destination(false);
        let (reserved, shared) = (Semaphore::new(0), Semaphore::new(0));
        let holds = Holds {
            reserved: &reserved,
            shared: &shared,
        };
        let result = d.acquire(Some(holds)).await.map(|_| ());
        assert!(matches!(result, Err(AcquireError::HoldCap)), "{result:?}");
        assert_eq!(d.status().waiting, 0);
        assert!(d.state.borrow().kick, "the destination was asked to dial");
        assert!(d.wanted(&d.state.borrow()));
    }

    /// A destination's own share of the hold budget is used before the pool
    /// every destination shares, and is what it still has when another
    /// destination has drained that pool.
    #[test]
    fn holds_come_from_the_reserved_share_then_the_pool() {
        let (reserved, shared) = (Semaphore::new(1), Semaphore::new(1));
        let holds = Holds {
            reserved: &reserved,
            shared: &shared,
        };
        let first = holds.try_acquire().expect("the reserved hold");
        assert_eq!(
            (reserved.available_permits(), shared.available_permits()),
            (0, 1)
        );
        let second = holds.try_acquire().expect("then one from the pool");
        assert!(holds.try_acquire().is_none(), "both exhausted");
        drop((first, second));

        // Another destination took the whole pool: the reserved hold is left.
        let drained = Semaphore::new(0);
        let holds = Holds {
            reserved: &reserved,
            shared: &drained,
        };
        assert!(holds.try_acquire().is_some());
    }

    /// Closing a destination ends the requests held for it at once and turns
    /// later ones away — a dialer kept past the client gets an answer, not a
    /// 45-second wait or a connection that is already gone.
    #[tokio::test(start_paused = true)]
    async fn close_turns_requests_away() {
        let d = destination(false);
        let held = {
            let d = d.clone();
            tokio::spawn(async move { d.acquire(None).await.map(|_| ()) })
        };
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(d.status().waiting, 1);

        let started = Instant::now();
        d.close().await;
        let result = held.await.unwrap();
        assert!(matches!(result, Err(AcquireError::Closed)), "{result:?}");
        assert_eq!(
            started.elapsed(),
            Duration::ZERO,
            "woken by the close, not the hold"
        );

        let result = d.acquire(None).await.map(|_| ());
        assert!(matches!(result, Err(AcquireError::Closed)), "{result:?}");
        assert_eq!(d.status().waiting, 0);
        // Terminal: a manager still winding down cannot reopen it.
        d.set_link(Link::Idle);
        d.set_link(Link::Backoff);
        assert!(matches!(d.state.borrow().link, Link::Closed));
    }

    /// Every release is stamped, so the idle timeout counts from the last use
    /// — one the idle check never saw included.
    #[tokio::test(start_paused = true)]
    async fn releases_restart_the_idle_clock() {
        let d = destination(false);
        let connected_at = d.state.borrow().unused_since;
        let idle_timeout = Duration::from_secs(300);

        // A stream opened and closed 299s in: the count is back to zero, and
        // only the release time shows the connection was used.
        tokio::time::sleep(Duration::from_secs(299)).await;
        d.state.send_modify(|s| s.streams += 1);
        drop(StreamGuard(d.clone()));
        let released_at = d.state.borrow().unused_since;
        assert_eq!(released_at - connected_at, Duration::from_secs(299));
        assert_eq!(d.state.borrow().streams, 0);

        // Not connected, so never due; the time test is the same one a
        // connected destination gets (see `idle_due`).
        let due_at = |now: Instant| {
            now.saturating_duration_since(d.state.borrow().unused_since) >= idle_timeout
        };
        assert!(
            !due_at(connected_at + idle_timeout),
            "300s after connecting is 1s after the use"
        );
        assert!(due_at(released_at + idle_timeout));
        assert!(!d.idle_due(&d.state.borrow(), idle_timeout, released_at + idle_timeout));

        // A waiter leaving is a release too.
        tokio::time::sleep(Duration::from_secs(5)).await;
        d.state.send_modify(|s| s.waiters += 1);
        drop(WaiterGuard(&d));
        assert_eq!(
            d.state.borrow().unused_since - released_at,
            Duration::from_secs(5)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_permanent_failure_fails_requests_at_once() {
        let d = destination(false);
        d.set_link(Link::Failed {
            reason: "Authentication failed: nope".to_string(),
            retry_at: Instant::now() + Duration::from_secs(30),
        });
        assert_eq!(d.status().state, DestinationState::Failed);
        let started = Instant::now();
        let result = d.acquire(None).await.map(|_| ());
        assert!(
            matches!(&result, Err(AcquireError::Failed(reason)) if reason.contains("nope")),
            "{result:?}"
        );
        assert_eq!(started.elapsed(), Duration::ZERO, "not held");
        assert_eq!(d.status().waiting, 0);
    }

    /// With nothing wanting the destination, the manager rests — however long,
    /// whatever the outage's retry time says. A kick then waits out only what
    /// is left of the backoff.
    #[tokio::test(start_paused = true)]
    async fn the_backoff_is_waited_out_only_while_wanted() {
        let d = destination(false);
        let mut outage = Outage {
            attempt: 2,
            next_attempt_at: Some(Instant::now() + Duration::from_secs(10)),
            ..Outage::default()
        };
        let rested =
            tokio::time::timeout(Duration::from_secs(3600), d.wait_until_due(&mut outage)).await;
        assert!(rested.is_err(), "an unwanted destination never becomes due");
        assert_eq!(d.status().state, DestinationState::Idle);

        outage.next_attempt_at = Some(Instant::now() + Duration::from_secs(10));
        d.kick();
        let started = Instant::now();
        d.wait_until_due(&mut outage).await;
        assert_eq!(
            started.elapsed(),
            Duration::from_secs(10),
            "the rest of the backoff"
        );
        assert!(!d.state.borrow().kick, "the kick is spent on this attempt");
        assert_eq!(outage.attempt, 2, "waiting does not reset the series");
    }

    /// A network path that returns while nothing wants the destination still
    /// ends the outage's backoff: the next request dials at once instead of
    /// waiting out a retry time set before the path went away. A repeated
    /// "available" report with no outage in between changes nothing.
    #[tokio::test(start_paused = true)]
    async fn a_path_restored_while_idle_clears_the_stale_backoff() {
        let d = destination(false);
        let mut outage = Outage {
            attempt: 5,
            next_attempt_at: Some(Instant::now() + Duration::from_secs(60)),
            ..Outage::default()
        };
        {
            let due = d.wait_until_due(&mut outage);
            tokio::pin!(due);
            // Idle, and told "available" again without having been offline.
            assert!(
                tokio::time::timeout(Duration::from_secs(1), &mut due)
                    .await
                    .is_err()
            );
            d.shared.network_available.send_replace(true);
            assert!(
                tokio::time::timeout(Duration::from_secs(1), &mut due)
                    .await
                    .is_err()
            );
        }
        assert_eq!(outage.attempt, 5, "no restoration, no reset");

        {
            let due = d.wait_until_due(&mut outage);
            tokio::pin!(due);
            d.shared.network_available.send_replace(false);
            assert!(
                tokio::time::timeout(Duration::from_secs(1), &mut due)
                    .await
                    .is_err()
            );
            d.shared.network_available.send_replace(true);
            // Still idle: restoring the path dials nothing by itself.
            assert!(
                tokio::time::timeout(Duration::from_secs(1), &mut due)
                    .await
                    .is_err()
            );
            assert_eq!(d.status().state, DestinationState::Idle);

            // The request that needs it is due at once.
            d.kick();
            tokio::time::timeout(Duration::from_millis(1), &mut due)
                .await
                .expect("due without waiting out the old backoff");
        }
        assert_eq!(outage.attempt, 0, "a restored path starts a fresh series");
        assert!(outage.nudge, "the endpoint is nudged on the next attempt");
    }

    /// With the network reported unavailable a wanted destination parks — no
    /// timers, not even the backoff's — and becomes due the moment the path
    /// returns, with a fresh backoff series.
    #[tokio::test(start_paused = true)]
    async fn offline_parks_and_resumes_when_the_path_returns() {
        let d = destination(true);
        d.shared.network_available.send_replace(false);
        let mut outage = Outage {
            attempt: 4,
            next_attempt_at: Some(Instant::now() + Duration::from_secs(8)),
            ..Outage::default()
        };
        {
            let due = d.wait_until_due(&mut outage);
            tokio::pin!(due);
            let parked = tokio::time::timeout(Duration::from_secs(3600), &mut due).await;
            assert!(parked.is_err(), "parked for as long as the path is gone");
            assert_eq!(d.status().state, DestinationState::Backoff);

            d.shared.network_available.send_replace(true);
            tokio::time::timeout(Duration::from_millis(1), &mut due)
                .await
                .expect("due as soon as the path is back");
        }
        assert_eq!(outage.attempt, 0, "a restored path starts a fresh series");
        assert!(outage.nudge, "the endpoint is nudged on the next attempt");
    }

    /// A path lost in the middle of a backoff switches to parking: the backoff
    /// elapsing does not make the destination due while offline.
    #[tokio::test(start_paused = true)]
    async fn a_path_lost_mid_backoff_parks() {
        let d = destination(true);
        let mut outage = Outage {
            attempt: 1,
            next_attempt_at: Some(Instant::now() + Duration::from_secs(5)),
            ..Outage::default()
        };
        let due = d.wait_until_due(&mut outage);
        tokio::pin!(due);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), &mut due)
                .await
                .is_err()
        );
        d.shared.network_available.send_replace(false);
        let parked = tokio::time::timeout(Duration::from_secs(3600), &mut due).await;
        assert!(
            parked.is_err(),
            "the elapsed backoff does not end a parked wait"
        );
    }

    /// The embedding app coming to the foreground ends a backoff at once; a
    /// client that was never backgrounded just waits it out.
    #[tokio::test(start_paused = true)]
    async fn foregrounding_cuts_a_backoff_short() {
        let d = destination(true);
        d.shared.background.send_replace(true);
        let mut outage = Outage {
            attempt: 6,
            next_attempt_at: Some(Instant::now() + Duration::from_secs(60)),
            ..Outage::default()
        };
        {
            let due = d.wait_until_due(&mut outage);
            tokio::pin!(due);
            assert!(
                tokio::time::timeout(Duration::from_secs(5), &mut due)
                    .await
                    .is_err()
            );
            d.shared.background.send_replace(false);
            tokio::time::timeout(Duration::from_millis(1), &mut due)
                .await
                .expect("due as soon as the app is foregrounded");
        }
        assert_eq!(outage.attempt, 0);
        assert!(outage.nudge);

        // Foreground all along: the full step.
        let mut outage = Outage {
            attempt: 6,
            next_attempt_at: Some(Instant::now() + Duration::from_secs(60)),
            ..Outage::default()
        };
        let started = Instant::now();
        d.wait_until_due(&mut outage).await;
        assert_eq!(started.elapsed(), Duration::from_secs(60));
        assert_eq!(outage.attempt, 6);

        // In the foreground when the backoff starts, backgrounded part-way
        // and brought back: that return ends the wait too.
        let mut outage = Outage {
            attempt: 6,
            next_attempt_at: Some(Instant::now() + Duration::from_secs(60)),
            ..Outage::default()
        };
        let started = Instant::now();
        {
            let due = d.wait_until_due(&mut outage);
            tokio::pin!(due);
            assert!(
                tokio::time::timeout(Duration::from_secs(5), &mut due)
                    .await
                    .is_err()
            );
            d.shared.background.send_replace(true);
            assert!(
                tokio::time::timeout(Duration::from_secs(5), &mut due)
                    .await
                    .is_err()
            );
            d.shared.background.send_replace(false);
            tokio::time::timeout(Duration::from_millis(1), &mut due)
                .await
                .expect("due as soon as the app returns to the foreground");
        }
        assert_eq!(started.elapsed(), Duration::from_secs(10));
        assert_eq!(outage.attempt, 0);
    }

    /// A recoverable failure keeps requests waiting for the retry; a permanent
    /// one fails them, and the destination leaves that state at its retry time.
    #[tokio::test(start_paused = true)]
    async fn failures_set_the_link_and_the_status() {
        let d = destination(false);
        let mut outage = Outage::default();
        d.record_failure(ProxyError::Signaling("timed out".into()), &mut outage);
        let status = d.status();
        assert_eq!(status.state, DestinationState::Backoff);
        assert_eq!(status.failed_attempts, 1);
        assert!(status.last_error.as_deref().unwrap().contains("timed out"));
        assert!(status.next_attempt_at.is_some());

        d.record_failure(ProxyError::AuthenticationFailed("nope".into()), &mut outage);
        let status = d.status();
        assert_eq!(status.state, DestinationState::Failed);
        assert_eq!(status.failed_attempts, 2);

        // Unwanted: once the retry time passes it is simply idle again, the
        // failure still on record.
        let rested =
            tokio::time::timeout(Duration::from_secs(600), d.wait_until_due(&mut outage)).await;
        assert!(rested.is_err());
        let status = d.status();
        assert_eq!(status.state, DestinationState::Idle);
        assert_eq!(status.failed_attempts, 2);
        assert!(status.last_error.is_some());
    }
}
