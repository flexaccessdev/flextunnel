//! flextunnel client: local SOCKS5 and optional HTTP proxy listeners, port
//! forwards and `nc`, whose requests are routed by a static table
//! ([`RouteTable`]) to one of several *destinations* — each a server reached
//! over its own iroh QUIC connection, opened on first use and closed when idle
//! (see [`super::destination`]). One bi-stream per proxied connection.

use crate::error::{ProxyError, ProxyResult};
use crate::proxy::destination::{
    AcquireError, Destination, DestinationConfig, DestinationStatus, EndpointProvider, Holds,
    Shared, StreamGuard, default_endpoint_provider,
};
use crate::proxy::route_table::{Route, RouteSpec, RouteTable};
use crate::proxy::signaling::{self, ControlMsg, StreamRequest, Target};
use crate::proxy::{client_status, dial, http, socks5};
use crate::transport::paths::ConnectionSnapshot;
use crate::transport::{HEARTBEAT_INTERVAL, HEARTBEAT_INTERVAL_IDLE, liveness_window};
use anyhow::Result;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr};
use rand::RngExt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::sync::{Semaphore, watch};

/// Reconnect backoff: base 1s, doubling per consecutive failed attempt, capped
/// here. The early steps (1s, 2s, 4s, …) catch a server restart within a
/// minute or two; past them the doubling settles at the cap, so a server that
/// stays down is probed at most once a minute — and only while a request is
/// actually waiting for it (see [`super::destination`]). Each probe is one
/// bounded connect ([`CONNECT_TIMEOUT`]), so an outage of any length is cheap
/// to sit through while still noticing the server's return within a minute.
/// Events that make an earlier attempt worthwhile — a restored network path,
/// a foregrounded app — cut the wait short.
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(60);
/// Escalate to a full endpoint rebuild once this many consecutive attempts of
/// an outage have failed. The attempts before it get the cheap
/// `network_change()` nudge, which repairs dead UDP sockets; a wedge that
/// survives the nudge plus two full connect timeouts is endpoint state a
/// rebind cannot fix — a relay link lost to a ping timeout and never
/// re-established, stale cached paths for the server — which only a fresh
/// endpoint repairs (observed as "restart the client process and it connects
/// instantly"; the rebuild is that restart, in-process).
const REBUILD_ENDPOINT_ATTEMPTS: u32 = 3;
/// After an outage's first rebuild, rebuild again no more often than this for
/// as long as the outage lasts. The rebuild is the expensive step — fresh
/// sockets and relay connections, a new ephemeral identity the relay has to
/// learn, the old endpoint's close — and it repairs a wedged *endpoint*; a
/// freshly built endpoint that still cannot connect has ruled that out, and
/// no amount of rebuilding brings back a server (or a network) that is down.
/// The nudge still runs before every attempt, so a network that changes
/// mid-outage is picked up without a rebuild; this is only the backstop for a
/// wedge that develops during a long outage. The budget is per outage: a
/// successful connection resets it.
const REBUILD_ENDPOINT_MIN_INTERVAL: Duration = Duration::from_secs(30 * 60);
/// Max jitter (ms) added to each backoff to avoid thundering reconnects.
const RECONNECT_JITTER_MAX_MS: u64 = 500;
/// Deadline for the auth handshake: opening the control stream, sending the
/// `Hello` and reading the server's response. Heartbeats only start after
/// the handshake, so without this a server that accepts the connection but
/// never grants the stream, or never replies on it, would stall the client
/// until the QUIC idle timeout, or indefinitely if the server keeps the
/// connection alive.
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Deadline for `Endpoint::connect` (address discovery + QUIC handshake). The
/// discovery phase awaits DNS/pkarr/mDNS lookups with no deadline of its own,
/// and on a wedged endpoint (seen on iOS after the OS suspends the process and
/// invalidates the socket state underneath it) that future can pend forever —
/// which would stall the reconnect loop permanently instead of retrying. The
/// retry then nudges `Endpoint::network_change()` to rebind the dead
/// transports (see `Destination::connect_once`), so the wedge is repaired
/// rather than merely timed out again.
/// Generous: a healthy connect through discovery + relay completes well within.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Connect to `addr` with `alpn` bounded by [`CONNECT_TIMEOUT`], mapping both
/// the timeout and the underlying connect error to a signaling error.
pub(crate) async fn connect_with_timeout(
    endpoint: &Endpoint,
    addr: EndpointAddr,
    alpn: &[u8],
) -> ProxyResult<Connection> {
    tokio::time::timeout(CONNECT_TIMEOUT, endpoint.connect(addr, alpn))
        .await
        .map_err(|_| {
            ProxyError::Signaling(format!(
                "timed out connecting to server after {}s",
                CONNECT_TIMEOUT.as_secs()
            ))
        })?
        .map_err(|e| ProxyError::Signaling(format!("Failed to connect to server: {e}")))
}
/// Deadline for opening a tunnel stream and receiving the server's CONNECT
/// reply. Must exceed the server's own connect timeout (it replies only after
/// dialing the target, up to ~10s), so a legitimately slow target isn't cut
/// off; without it a server that stalls after accepting the stream would hang
/// the local SOCKS5 connection forever.
pub const TUNNEL_OPEN_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a request for a destination that is not connected is held while
/// the destination connects — the first use of an idle destination, or a
/// reconnect after a drop — before being refused with a network-unreachable
/// reply. The request that finds the destination idle is what makes it dial,
/// so holding is what lets a lazy connection be invisible: the page load (or
/// the ssh, or the forwarded connection) waits out the dial and then proceeds
/// as if the tunnel had been up all along. Sized to cover a silent drop
/// end-to-end in the foreground: detection takes up to [`liveness_window`] of
/// [`HEARTBEAT_INTERVAL`] (33s), then the early backoff steps plus the
/// connect+handshake; a connection that hasn't landed by then is genuinely
/// stuck, and the bound keeps the failure inside a browser's own patience.
pub const TUNNEL_RECOVERY_HOLD: Duration = Duration::from_secs(45);
/// Deadline for the local app to complete its SOCKS5 handshake (method
/// negotiation + CONNECT request). A peer that connects to the loopback
/// listener but sends nothing would otherwise pin the spawned task and socket
/// forever; generous since this is loopback.
const LOCAL_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Pause before retrying `accept()` after a transient failure. Matters most
/// for fd exhaustion (EMFILE/ENFILE — easy to hit under macOS's default
/// 256-fd soft limit): the listener is still healthy, and apps retrying their
/// failed connections make it worse, so back off long enough for in-flight
/// connections to close and free descriptors instead of exiting the client.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(250);
/// Warn on the 1st transient accept failure of a burst and then every Nth —
/// one warn per ~10s at [`ACCEPT_RETRY_DELAY`] pacing — so sustained fd
/// exhaustion doesn't flood the log; the in-between retries log at debug.
const ACCEPT_RETRY_WARN_EVERY: u64 = 40;
/// Consecutive aborted accepts after which the listener itself is presumed
/// dead and rebound. A peer aborting a queued connection between the kernel
/// accepting it and us reading it yields the same error *occasionally*; a
/// listener socket the OS invalidated underneath us — iOS marks every socket
/// of a suspended process defunct, and `accept()` on one fails with
/// ECONNABORTED forever — yields it on *every* call. A short uniform burst
/// (~1s at [`ACCEPT_RETRY_DELAY`] pacing) separates the two.
const REBIND_AFTER_CONSECUTIVE_ABORTS: u64 = 4;
/// Cap on concurrent proxied connections per local front-end listener. At the
/// cap the loop pauses accepting — further connections wait in the kernel
/// backlog — until one closes, so a runaway local app degrades into queueing
/// instead of exhausting the process's file descriptors (each proxied
/// connection holds a socket plus a QUIC stream). Generous for the real
/// client: a browser's worst case is a few dozen parallel fetches.
const MAX_ACTIVE_LOCAL_CONNS: usize = 256;
/// Cap on requests concurrently *held* for a connecting destination per local
/// front-end listener (see `Destination::acquire`). A held request parks with
/// its [`MAX_ACTIVE_LOCAL_CONNS`] permit for up to [`TUNNEL_RECOVERY_HOLD`], so
/// without a separate bound a burst of retries toward a server that is down
/// could pin every permit and starve the direct traffic and the other
/// destinations. At this cap further tunneled requests are not held: they get
/// an immediate network-unreachable reply (the destination is still asked to
/// connect).
const MAX_HELD_CONNS: usize = 64;
/// Longest idle timeout a client accepts. The timeout is added to the time a
/// connection was last used, and a value near the limits of the clock would
/// overflow that sum — a panic, long after start, the first time a connection
/// falls unused. Nothing sensible is lost: a connection that should never be
/// closed for idleness has no timeout at all.
pub const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(365 * 24 * 60 * 60);
/// How many of a listener's [`MAX_HELD_CONNS`] holds are set aside for each
/// destination (fewer when there are too many destinations to give each this
/// many). Every first use of an idle destination needs a hold while it
/// connects, so without a share of its own a destination whose server is up
/// would be refused for as long as a burst of retries toward one that is
/// down fills the budget.
const HOLDS_RESERVED_PER_DESTINATION: usize = 8;

/// One listener's budget of held requests: [`MAX_HELD_CONNS`] in all, split
/// into a small share reserved for each destination and a pool they all draw
/// on once their own share is used.
pub(crate) struct HoldBudget {
    /// Indexed like the client's destinations.
    reserved: Vec<Semaphore>,
    shared: Semaphore,
}

impl HoldBudget {
    pub(crate) fn new(destinations: usize) -> Self {
        let each = (MAX_HELD_CONNS / destinations.max(1)).min(HOLDS_RESERVED_PER_DESTINATION);
        Self {
            reserved: (0..destinations).map(|_| Semaphore::new(each)).collect(),
            shared: Semaphore::new(MAX_HELD_CONNS - each * destinations),
        }
    }

    /// The claim of the destination at index `dest` on this budget.
    pub(crate) fn for_destination(&self, dest: usize) -> Holds<'_> {
        Holds {
            reserved: &self.reserved[dest],
            shared: &self.shared,
        }
    }
}

/// Configuration for the proxy client.
pub struct ClientConfig {
    /// The servers this client can reach, each under its own host name. At
    /// least one; hosts and server ids must be unique and the routing rules
    /// unambiguous (see [`RouteTable`]).
    pub destinations: Vec<DestinationConfig>,
    /// Close a destination's connection after this long with no stream open
    /// on it. `None` never closes one for idleness: once a destination has
    /// connected it stays up until the link drops.
    pub idle_timeout: Option<Duration>,
}

/// The local proxy front-ends a client serves. All optional: a client with
/// none still serves port forwards and `nc` through its [`TunnelDialer`].
#[derive(Default)]
pub struct LocalListeners {
    /// SOCKS5 (TCP CONNECT only).
    pub socks: Option<TcpListener>,
    /// HTTP proxy: `CONNECT` tunneling + absolute-URI plain-HTTP forwarding.
    pub http: Option<TcpListener>,
    /// SOCKS5 on a Unix-domain socket — for an embedder that wants the proxy
    /// reachable only through a socket file in its own sandbox instead of a
    /// loopback TCP port any process on the device can connect to. Unix only;
    /// there is no Windows equivalent.
    #[cfg(unix)]
    pub unix_socks: Option<UnixListener>,
}

impl LocalListeners {
    /// The TCP front-ends alone — the only ones there are off Unix, which is
    /// why callers use this rather than `..Default::default()`.
    pub fn tcp(socks: Option<TcpListener>, http: Option<TcpListener>) -> Self {
        Self {
            socks,
            http,
            #[cfg(unix)]
            unix_socks: None,
        }
    }
}

/// A point-in-time view of the client, for status displays.
#[derive(Clone, Debug)]
pub struct ClientStatus {
    /// Where the SOCKS5 front-end listens; `None` when it is off.
    pub socks_listen: Option<SocketAddr>,
    /// Where the HTTP front-end listens; `None` when it is off.
    pub http_listen: Option<SocketAddr>,
    pub idle_timeout: Option<Duration>,
    /// One entry per destination, in configuration order.
    pub destinations: Vec<DestinationStatus>,
}

/// The TCP front-end addresses a running client serves.
#[derive(Clone, Copy, Default)]
struct ListenAddrs {
    socks: Option<SocketAddr>,
    http: Option<SocketAddr>,
}

/// The client's routing state, shared by every request path: the static
/// table, and the destinations it indexes.
pub(crate) struct Router {
    pub(crate) table: RouteTable,
    /// Indexed by [`Route::Tunnel::dest`].
    pub(crate) destinations: Vec<Arc<Destination>>,
    shared: Arc<Shared>,
    listen: Mutex<ListenAddrs>,
}

impl Router {
    pub(crate) fn status(&self) -> ClientStatus {
        let listen = *self.listen.lock().expect("listen addrs lock");
        ClientStatus {
            socks_listen: listen.socks,
            http_listen: listen.http,
            idle_timeout: self.shared.idle_timeout,
            destinations: self.destinations.iter().map(|d| d.status()).collect(),
        }
    }

    fn destination(&self, host: &str) -> Option<&Arc<Destination>> {
        self.table.index_of(host).map(|dest| &self.destinations[dest])
    }

    /// Stop reporting the front-end addresses: nothing listens on them now.
    fn withdraw_listen_addrs(&self) {
        *self.listen.lock().expect("listen addrs lock") = ListenAddrs::default();
    }
}

/// Withdraws the advertised front-end addresses when a [`ProxyClient::run`]
/// ends, however it ends — returned, or dropped mid-flight — since its
/// listeners end with it.
struct AdvertisedAddrs<'a>(&'a Router);

impl Drop for AdvertisedAddrs<'_> {
    fn drop(&mut self) {
        self.0.withdraw_listen_addrs();
    }
}

/// One stream to a server, opened by a [`TunnelDialer`]. Reads and writes go
/// straight to the QUIC stream; holding it keeps its destination's connection
/// from being closed as idle.
pub struct TunnelStream {
    inner: tokio::io::Join<RecvStream, SendStream>,
    _stream: StreamGuard,
}

impl AsyncRead for TunnelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TunnelStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Cloneable handle for opening targets through the client's destinations,
/// bypassing the local proxy front-ends — what port forwards and `nc` use.
///
/// It routes exactly like a proxy request, with one difference: a target that
/// no destination routes is an **error**, never a direct connection. A forward
/// or an `nc` exists to reach something through a server; quietly dialing it
/// from this machine instead would be the wrong answer. Like a proxy request,
/// a call connects its destination on demand and is held while it does.
#[derive(Clone)]
pub struct TunnelDialer {
    router: Arc<Router>,
}

impl TunnelDialer {
    /// The host of the destination that would carry `target`, or `None` when
    /// no destination routes it (including the reserved `flextunnel.internal`
    /// names, which the client answers itself).
    pub fn destination_for(&self, target: &Target) -> Option<&str> {
        match self.router.table.route(target) {
            Route::Tunnel { dest, .. } => Some(self.router.destinations[dest].host()),
            Route::ClientStatus | Route::Reserved | Route::Direct => None,
        }
    }

    /// Open `target` through the destination that routes it and return its raw
    /// bidirectional byte stream.
    pub async fn connect(&self, target: &Target) -> Result<TunnelStream> {
        let (destination, request) = match self.router.table.route(target) {
            Route::Tunnel { dest, request } => (&self.router.destinations[dest], request),
            Route::ClientStatus | Route::Reserved => anyhow::bail!(
                "{} is the client's own status endpoint; reach it through a proxy listener",
                target_host(target)
            ),
            Route::Direct => anyhow::bail!("no destination routes {}", target_host(target)),
        };
        let lease = destination
            .acquire(None)
            .await
            .map_err(|e| anyhow::anyhow!("{}: {e}", destination.host()))?;
        let (conn, stream) = lease.into_parts();
        let (send, recv, rep) = tokio::time::timeout(TUNNEL_OPEN_TIMEOUT, open_tunnel(&conn, &request))
            .await
            .map_err(|_| anyhow::anyhow!("timed out opening a stream to {}", destination.host()))??;
        if rep != signaling::REP_SUCCESS {
            anyhow::bail!(
                "{} rejected target: {}",
                destination.host(),
                socks5::describe_reply(rep)
            );
        }
        Ok(TunnelStream {
            inner: tokio::io::join(recv, send),
            _stream: stream,
        })
    }

    /// Open `target` and splice it with one accepted local connection.
    pub async fn relay<S>(&self, mut local: S, target: &Target) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut tunnel = self.connect(target).await?;
        tokio::io::copy_bidirectional(&mut local, &mut tunnel).await?;
        Ok(())
    }

    /// Ask the destination named `host` to connect now, without waiting for
    /// it: one attempt in the background, after which the connection lives or
    /// idles out like any other. Returns whether there is such a destination.
    pub fn warm(&self, host: &str) -> bool {
        match self.router.destination(host) {
            Some(destination) => {
                destination.kick();
                true
            }
            None => false,
        }
    }
}

/// A target's host, for messages.
fn target_host(target: &Target) -> String {
    match target {
        Target::Domain(host, _) => host.clone(),
        Target::Ip(addr) => addr.ip().to_string(),
    }
}

/// Exponential backoff with jitter for the Nth (1-based) reconnect attempt,
/// shared by every client destination.
pub(crate) fn calculate_backoff(attempt: u32) -> Duration {
    // 2^(attempt-1) seconds; the shift is bounded well past where the cap
    // takes over, so it can never overflow.
    let shift = attempt.saturating_sub(1).min(16);
    let secs = (1u64 << shift).min(RECONNECT_BACKOFF_MAX.as_secs());
    let jitter = rand::rng().random_range(0..=RECONNECT_JITTER_MAX_MS);
    Duration::from_secs(secs) + Duration::from_millis(jitter)
}

/// Whether a destination should rebuild its endpoint before its next
/// attempt: the outage has reached [`REBUILD_ENDPOINT_ATTEMPTS`] consecutive
/// failures, and it either has not rebuilt yet or last did so at least
/// [`REBUILD_ENDPOINT_MIN_INTERVAL`] ago.
pub(crate) fn rebuild_due(attempt: u32, last_rebuild: Option<Instant>) -> bool {
    attempt >= REBUILD_ENDPOINT_ATTEMPTS
        && last_rebuild.is_none_or(|at| at.elapsed() >= REBUILD_ENDPOINT_MIN_INTERVAL)
}

/// The client: a routing table over lazily connected destinations, served to
/// local apps through proxy listeners ([`Self::run`]) and a [`TunnelDialer`].
pub struct ProxyClient {
    router: Arc<Router>,
    /// One-way close signal for the local front-end listeners, latched by
    /// [`Self::close_local_listeners`]. The accept loops watch the receiving
    /// side and drop their listener when it flips.
    local_close: watch::Sender<bool>,
}

impl ProxyClient {
    /// Build a client, validating the destinations: at least one, each host a
    /// valid and unique destination name, each server configured once, and no
    /// routing rule shared between two destinations (see [`RouteTable::new`]).
    /// Nothing is bound or dialed here — or at all, until a request arrives.
    pub fn new(config: ClientConfig) -> ProxyResult<Self> {
        Self::with_endpoint_provider(config, default_endpoint_provider())
    }

    /// [`Self::new`] with a custom recipe for building a destination's
    /// endpoint. The seam for tests, which run on loopback-only endpoints.
    pub fn with_endpoint_provider(
        config: ClientConfig,
        provider: EndpointProvider,
    ) -> ProxyResult<Self> {
        let ClientConfig {
            mut destinations,
            idle_timeout,
        } = config;
        if destinations.is_empty() {
            return Err(ProxyError::config("the client has no destinations configured"));
        }
        if let Some(idle_timeout) = idle_timeout
            && idle_timeout > MAX_IDLE_TIMEOUT
        {
            return Err(ProxyError::config(format!(
                "the idle timeout of {}s is longer than the {}s (one year) allowed; to never \
                 close an idle connection, set it to 0",
                idle_timeout.as_secs(),
                MAX_IDLE_TIMEOUT.as_secs()
            )));
        }
        let specs: Vec<RouteSpec<'_>> = destinations
            .iter()
            .map(|d| RouteSpec {
                host: &d.host,
                routed_domains: &d.routed_domains,
                routed_cidrs: &d.routed_cidrs,
            })
            .collect();
        let table = RouteTable::new(&specs).map_err(|e| ProxyError::config(format!("{e:#}")))?;
        // Nesting is allowed, but say where: a broad rule gives up whatever a
        // narrower one on another destination takes.
        let host = |dest: usize| table.hosts().nth(dest).unwrap_or_default().to_string();
        for overlap in table.overlaps() {
            log::info!(
                "Routing: {} ({}) is within {} ({}); the narrower rule wins there",
                overlap.inner.rule,
                host(overlap.inner.dest),
                overlap.outer.rule,
                host(overlap.outer.dest)
            );
        }
        // Store each host the way the table spells it (trimmed, lowercased).
        let hosts: Vec<String> = table.hosts().map(str::to_owned).collect();
        for (destination, host) in destinations.iter_mut().zip(hosts) {
            destination.host = host;
        }
        // Two names for one server would be two connections to it from one
        // process, each with its own endpoint and no reason to exist.
        for (i, destination) in destinations.iter().enumerate() {
            if let Some(earlier) = destinations[..i]
                .iter()
                .find(|d| d.server_id == destination.server_id)
            {
                return Err(ProxyError::config(format!(
                    "destinations {:?} and {:?} name the same server ({})",
                    earlier.host, destination.host, destination.server_id
                )));
            }
        }

        let shared = Arc::new(Shared {
            instance_nonce: rand::rng().random(),
            idle_timeout,
            provider,
            background: watch::Sender::new(false),
            network_available: watch::Sender::new(true),
            closed: AtomicBool::new(false),
        });
        let destinations = destinations
            .into_iter()
            .map(|cfg| Destination::new(cfg, shared.clone()))
            .collect();
        Ok(Self {
            router: Arc::new(Router {
                table,
                destinations,
                shared,
                listen: Mutex::new(ListenAddrs::default()),
            }),
            local_close: watch::Sender::new(false),
        })
    }

    /// Report the embedding app's scene state. Backgrounded, the heartbeat
    /// slows to [`HEARTBEAT_INTERVAL_IDLE`] (one radio wake a minute instead of
    /// six); foregrounded, it snaps back to [`HEARTBEAT_INTERVAL`] — a beat
    /// already overdue at the faster cadence is sent immediately — and a
    /// retry backoff in progress ends early: the next attempt runs at once,
    /// with a fresh backoff series (the user is looking, and a long backoff
    /// step sized for an unattended outage should not keep them waiting). Safe
    /// to call repeatedly with the same value.
    pub fn set_background(&self, background: bool) {
        self.router.shared.background.send_replace(background);
    }

    /// Report whether the device has a usable network path (e.g. from
    /// `NWPathMonitor`). While unavailable no destination dials — retrying
    /// into a dead path is pure battery burn; the flip back to available gives
    /// every waiting destination an immediate attempt with a fresh backoff
    /// series.
    pub fn set_network_available(&self, available: bool) {
        self.router.shared.network_available.send_replace(available);
    }

    /// Close the local proxy front-end listeners (SOCKS5/HTTP/Unix) while
    /// leaving the session — the destinations and established relays —
    /// running. One-way: there is no reopen for this client; the embedder
    /// relaunches the session when it wants listeners back.
    ///
    /// For embedders whose process is about to be suspended (iOS): the kernel
    /// keeps accepting into a frozen process's listen backlog, so a suspended
    /// listener is a black hole — local clients connect and then hang. Closing
    /// the listeners first turns that into an immediate connection-refused.
    pub fn close_local_listeners(&self) {
        self.local_close.send_replace(true);
    }

    /// A point-in-time view of the client and every destination. Cheap and
    /// synchronous; never causes a connection.
    pub fn status(&self) -> ClientStatus {
        self.router.status()
    }

    /// The iroh paths (relay/direct) of the connection to the destination
    /// named `host`, plus an on-demand `/healthz` probe of its custom relays —
    /// for a status UI. Empty when `host` is not a destination or is not
    /// connected right now; asking never connects it.
    pub async fn connection_snapshot(&self, host: &str) -> ConnectionSnapshot {
        match self.router.destination(host) {
            Some(destination) => destination.connection_snapshot().await,
            None => ConnectionSnapshot::default(),
        }
    }

    /// A cloneable handle for opening targets through this client's
    /// destinations without a proxy listener (port forwards, `nc`).
    pub fn dialer(&self) -> TunnelDialer {
        TunnelDialer {
            router: self.router.clone(),
        }
    }

    /// Serve the given local front-ends and manage the destinations until the
    /// future is dropped (or a front-end listener is lost for good).
    ///
    /// Nothing is dialed up front. A destination connects when a request for
    /// it arrives — from a listener here or through [`Self::dialer`] — and
    /// that request is held while it does; its connection is closed again
    /// after [`ClientConfig::idle_timeout`] without an open stream. A failed
    /// attempt or a dropped connection is retried with exponential backoff
    /// (1s doubling to [`RECONNECT_BACKOFF_MAX`]) for as long as requests keep
    /// waiting, escalating to an endpoint rebuild after
    /// [`REBUILD_ENDPOINT_ATTEMPTS`] failures; a server that refuses this
    /// client fails that destination's requests at once. No destination's
    /// trouble ends the session or touches another destination, and targets on
    /// no destination's list keep connecting directly throughout.
    ///
    /// The listeners stay bound for the whole session. Dropping the returned
    /// future stops everything but leaves the endpoints of the destinations in
    /// use open: call [`Self::close`] afterwards.
    pub async fn run(&self, listeners: LocalListeners) -> ProxyResult<()> {
        let LocalListeners {
            socks,
            http,
            #[cfg(unix)]
            unix_socks,
        } = listeners;
        let mut listen = ListenAddrs::default();
        if let Some(l) = &socks {
            let addr = l.local_addr()?;
            log::info!("SOCKS5 proxy listening on {addr} (TCP CONNECT only)");
            listen.socks = Some(addr);
        }
        if let Some(l) = &http {
            let addr = l.local_addr()?;
            log::info!(
                "HTTP proxy listening on {addr} (CONNECT tunneling + plain-HTTP forwarding)"
            );
            listen.http = Some(addr);
        }
        #[cfg(unix)]
        if let Some(l) = &unix_socks {
            log::info!("SOCKS5 proxy also listening on unix socket {:?}", l.local_addr()?);
        }
        *self.router.listen.lock().expect("listen addrs lock") = listen;
        // The addresses are advertised for as long as they are served: until
        // this future ends or is dropped, or the listeners are closed.
        let _advertised = AdvertisedAddrs(&self.router);
        log::info!(
            "{} destination(s), connected on demand: {}",
            self.router.destinations.len(),
            self.router.table.hosts().collect::<Vec<_>>().join(", ")
        );

        let router = &self.router;
        // An absent front-end is an inert branch (never resolves), so the
        // `select!` shape is the same whichever listeners are bound.
        let socks_accept = async {
            match socks {
                Some(l) => accept_loop(l, router, Socks5Proto, self.local_close.subscribe()).await,
                None => std::future::pending::<ProxyResult<()>>().await,
            }
        };
        let http_accept = async {
            match http {
                Some(l) => accept_loop(l, router, HttpProto, self.local_close.subscribe()).await,
                None => std::future::pending::<ProxyResult<()>>().await,
            }
        };
        let unix_accept = async {
            #[cfg(unix)]
            if let Some(l) = unix_socks {
                return accept_loop_unix(l, router, self.local_close.subscribe()).await;
            }
            std::future::pending::<ProxyResult<()>>().await
        };
        // The destination managers never finish; they are here so they run —
        // and stop — with this future. One task, N concurrent futures: an
        // embedder's `task.abort()` tears everything down, no orphaned task.
        let managers = futures::future::join_all(
            router.destinations.iter().map(|d| d.clone().run()),
        );

        // On the close signal every accept loop drops its listener and parks,
        // so the session lives on with nothing listening: say so.
        let listeners_closed = async {
            listener_closed(&mut self.local_close.subscribe()).await;
            router.withdraw_listen_addrs();
            std::future::pending::<ProxyResult<()>>().await
        };

        tokio::select! {
            _ = managers => Ok(()),
            r = socks_accept => r,
            r = http_accept => r,
            r = unix_accept => r,
            r = listeners_closed => r,
        }
    }

    /// Close every destination's endpoint gracefully. Call once the
    /// [`Self::run`] future has been dropped (session teardown): a bound
    /// endpoint must be closed, never just dropped. An endpoint still being
    /// built at that moment is waited for and then closed, so this can take as
    /// long as a build does — bound the wait if the caller cannot afford it.
    pub async fn close(&self) {
        self.router.shared.closed.store(true, Ordering::SeqCst);
        futures::future::join_all(self.router.destinations.iter().map(|d| d.close())).await;
    }
}

/// Client-side heartbeat loop over the retained control stream: send a
/// `Heartbeat` at the current cadence — [`HEARTBEAT_INTERVAL`] while
/// foregrounded, [`HEARTBEAT_INTERVAL_IDLE`] while `background` reads true —
/// and await its `HeartbeatAck` within [`liveness_window`] of that cadence. A
/// missing ack (or stream error) returns [`ProxyError::ConnectionLost`]
/// (recoverable), which ends the connection for its manager to redial.
///
/// A cadence flip takes effect on the *current* wait: the deadline is
/// recomputed from the last heartbeat, so a foreground flip 50s into an idle
/// minute sends the overdue beat immediately, and a background flip stretches
/// the pending wait instead of firing one more fast beat.
pub(crate) async fn client_heartbeat_loop(
    mut send: SendStream,
    mut recv: RecvStream,
    mut background: watch::Receiver<bool>,
) -> ProxyResult<()> {
    let mut seq: u64 = 0;
    loop {
        let last_beat = tokio::time::Instant::now();
        let interval = loop {
            let interval = if *background.borrow() {
                HEARTBEAT_INTERVAL_IDLE
            } else {
                HEARTBEAT_INTERVAL
            };
            tokio::select! {
                _ = tokio::time::sleep_until(last_beat + interval) => break interval,
                changed = background.changed() => {
                    // A dropped sender can't change the cadence any more; sleep
                    // out the current interval plainly instead of spinning.
                    if changed.is_err() {
                        tokio::time::sleep_until(last_beat + interval).await;
                        break interval;
                    }
                }
            }
        };
        seq = seq.wrapping_add(1);
        signaling::write_message(
            &mut send,
            &signaling::encode_control(&ControlMsg::Heartbeat { seq })?,
        )
        .await?;
        send.flush().await?;

        let data = tokio::time::timeout(
            liveness_window(interval),
            signaling::read_message(&mut recv, signaling::MAX_CONTROL_MSG_SIZE),
        )
        .await
        .map_err(|_| ProxyError::ConnectionLost("heartbeat ack timed out".into()))?
        .map_err(|e| ProxyError::ConnectionLost(format!("control stream closed: {e}")))?;
        // The liveness probe is only satisfied by the ack for *this* heartbeat.
        // A wrong-seq ack or any other control frame means the channel is out of
        // sync — treat it as a lost connection so we reconnect rather than count a
        // stale/unexpected message as liveness.
        match signaling::decode_control(&data)? {
            ControlMsg::HeartbeatAck { seq: ack } if ack == seq => {}
            other => {
                return Err(ProxyError::ConnectionLost(format!(
                    "expected HeartbeatAck({seq}), got {other:?}"
                )));
            }
        }
    }
}

/// A local front-end request resolved to a wire [`Target`], plus how to begin
/// the upstream exchange once connected.
pub(crate) struct LocalRequest {
    target: Target,
    /// Bytes to write upstream before splicing: the rewritten request head of
    /// an HTTP plain-forward, whose reply is the origin's own response. `None`
    /// for pure tunnels (SOCKS5, HTTP CONNECT), which instead answer the local
    /// app with a success reply.
    upstream_preamble: Option<Vec<u8>>,
}

/// A local front-end protocol (SOCKS5 or HTTP). The protocols differ only in
/// how they parse a local request into a [`LocalRequest`] and how they answer
/// with a server reply code; everything after that — routing, the direct
/// dial, tunnel open, and byte pipe — is shared (see [`handle_local_conn`]).
///
/// Methods return `impl Future + Send` (not bare `async fn`) so the futures are
/// `Send`, which [`accept_loop`] needs to `tokio::spawn` a generic handler.
/// The local front-end stream can be a TCP loopback socket or a Unix domain
/// socket (see [`accept_loop`] / [`accept_loop_unix`]), so the request parsing
/// and byte-splicing are generic over any async stream.
pub(crate) trait LocalStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<S: AsyncRead + AsyncWrite + Unpin + Send> LocalStream for S {}

pub(crate) trait LocalProto: Clone + Send + Sync + 'static {
    /// Parse the local handshake into a [`LocalRequest`]. Any error the caller
    /// can't yet answer with a reply code (a bad request, an unsupported
    /// method) must be written to `stream` here before returning `Err`, mirroring
    /// how [`socks5::read_connect_request`] writes its own error replies.
    fn read_request<S: LocalStream>(
        &self,
        stream: &mut S,
    ) -> impl Future<Output = Result<LocalRequest>> + Send;

    /// Answer the local app with the response corresponding to server reply
    /// code `rep` ([`signaling::REP_SUCCESS`] et al.).
    fn reply<S: LocalStream>(
        &self,
        stream: &mut S,
        rep: u8,
    ) -> impl Future<Output = io::Result<()>> + Send;
}

/// SOCKS5 front-end (RFC 1928): method negotiation + CONNECT parsing, 10-byte
/// reply frames.
#[derive(Clone)]
struct Socks5Proto;

impl LocalProto for Socks5Proto {
    async fn read_request<S: LocalStream>(&self, stream: &mut S) -> Result<LocalRequest> {
        socks5::negotiate_method(stream).await?;
        Ok(LocalRequest {
            target: socks5::read_connect_request(stream).await?,
            upstream_preamble: None,
        })
    }

    async fn reply<S: LocalStream>(&self, stream: &mut S, rep: u8) -> io::Result<()> {
        socks5::write_reply(stream, rep).await
    }
}

/// HTTP proxy front-end: `CONNECT host:port` tunneling and absolute-URI
/// plain-HTTP forwarding, HTTP status-line replies.
#[derive(Clone)]
struct HttpProto;

impl LocalProto for HttpProto {
    async fn read_request<S: LocalStream>(&self, stream: &mut S) -> Result<LocalRequest> {
        Ok(match http::read_request(stream).await? {
            http::HttpRequest::Connect(target) => LocalRequest {
                target,
                upstream_preamble: None,
            },
            http::HttpRequest::Forward { target, head } => LocalRequest {
                target,
                upstream_preamble: Some(head),
            },
        })
    }

    async fn reply<S: LocalStream>(&self, stream: &mut S, rep: u8) -> io::Result<()> {
        http::write_reply(stream, rep).await
    }
}

/// How a failed `accept()` should be handled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AcceptFailure {
    /// fd exhaustion (EMFILE per-process / ENFILE system-wide; no stable
    /// `io::ErrorKind` exists for these, so the raw OS codes are matched). The
    /// listener itself is healthy — retry, and never rebind: replacing the
    /// socket wouldn't free descriptors, and dropping it would throw away the
    /// queued backlog for nothing.
    ResourcePressure,
    /// An aborted/reset accept: either a benign per-connection race (the peer
    /// gave up between the kernel queuing the connection and us accepting it)
    /// or a defunct listener failing every call — indistinguishable from one
    /// error alone, so retry and rebind only after a
    /// [`REBIND_AFTER_CONSECUTIVE_ABORTS`] burst.
    Aborted,
    /// The listener socket itself is broken (e.g. EBADF/EINVAL after the OS
    /// invalidated it) — rebind immediately.
    Broken,
}

fn classify_accept_error(e: &io::Error) -> AcceptFailure {
    #[cfg(unix)]
    if matches!(e.raw_os_error(), Some(libc::EMFILE) | Some(libc::ENFILE)) {
        return AcceptFailure::ResourcePressure;
    }
    #[cfg(windows)]
    {
        const WSAEMFILE: i32 = 10024;
        if e.raw_os_error() == Some(WSAEMFILE) {
            return AcceptFailure::ResourcePressure;
        }
    }
    match e.kind() {
        io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::Interrupted => AcceptFailure::Aborted,
        _ => AcceptFailure::Broken,
    }
}

/// Bind a replacement for a dead local listener. One retry after
/// [`ACCEPT_RETRY_DELAY`] absorbs a lingering-socket race; a second failure is
/// fatal — the port is genuinely gone (taken by another process), so ending
/// the client (and with it the embedder's health probe) beats serving nothing
/// while looking alive.
pub(crate) async fn rebind_listener(addr: SocketAddr) -> ProxyResult<TcpListener> {
    if let Ok(listener) = TcpListener::bind(addr).await {
        return Ok(listener);
    }
    tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
    Ok(TcpListener::bind(addr).await?)
}

/// What an accept error means for the loop after the failure state machine has
/// digested it.
pub(crate) enum AcceptOutcome {
    /// The listener is dead (broken, or an abort burst): rebind it in place.
    Rebind,
    /// A transient failure: back off and retry the same listener.
    Retry,
}

/// Shared accept-failure state machine for the local listeners. Tracks the
/// consecutive-failure and consecutive-abort counters and turns each accept
/// result into the rebind-or-retry decision, so [`accept_loop`] and
/// [`accept_loop_unix`] carry only their transport-specific accept, rebind, and
/// log-label differences. `label` prefixes the recovery/retry log lines
/// (e.g. "Local proxy" / "Unix SOCKS5").
pub(crate) struct AcceptRetry {
    label: &'static str,
    consecutive_failures: u64,
    consecutive_aborts: u64,
}

impl AcceptRetry {
    pub(crate) fn new(label: &'static str) -> Self {
        Self {
            label,
            consecutive_failures: 0,
            consecutive_aborts: 0,
        }
    }

    /// Record a successful accept, logging recovery if we had been failing.
    pub(crate) fn record_success(&mut self) {
        if self.consecutive_failures > 0 {
            log::info!(
                "{} accepting again after {} failed attempt(s)",
                self.label,
                self.consecutive_failures
            );
            self.consecutive_failures = 0;
        }
        self.consecutive_aborts = 0;
    }

    /// Record an accept error and decide whether to rebind or retry.
    pub(crate) fn record_error(&mut self, e: &io::Error) -> AcceptOutcome {
        let failure = classify_accept_error(e);
        self.consecutive_aborts = match failure {
            AcceptFailure::Aborted => self.consecutive_aborts + 1,
            _ => 0,
        };
        if failure == AcceptFailure::Broken
            || self.consecutive_aborts >= REBIND_AFTER_CONSECUTIVE_ABORTS
        {
            AcceptOutcome::Rebind
        } else {
            AcceptOutcome::Retry
        }
    }

    /// Reset the counters after a successful rebind.
    pub(crate) fn record_rebind(&mut self) {
        self.consecutive_failures = 0;
        self.consecutive_aborts = 0;
    }

    /// Log the retry (warn periodically, debug otherwise) and back off.
    pub(crate) async fn wait_retry(&mut self, e: &io::Error) {
        if self.consecutive_failures.is_multiple_of(ACCEPT_RETRY_WARN_EVERY) {
            log::warn!(
                "{} accept failed ({e}); retrying every {}ms",
                self.label,
                ACCEPT_RETRY_DELAY.as_millis()
            );
        } else {
            log::debug!("{} accept failed ({e}); retrying", self.label);
        }
        self.consecutive_failures += 1;
        tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
    }
}

/// Acquire a permit against the per-listener connection cap, warning once per
/// saturation episode. At the cap this pauses the accept loop — further
/// connections queue in the kernel backlog — until a connection closes.
async fn acquire_conn_permit(
    limiter: &Arc<Semaphore>,
    warned_saturated: &mut bool,
    label: &str,
) -> tokio::sync::OwnedSemaphorePermit {
    if limiter.available_permits() == 0 {
        if !*warned_saturated {
            *warned_saturated = true;
            log::warn!(
                "{label} reached {MAX_ACTIVE_LOCAL_CONNS} concurrent connections; \
                 pausing accepts until one closes"
            );
        }
    } else {
        *warned_saturated = false;
    }
    limiter
        .clone()
        .acquire_owned()
        .await
        .expect("connection limiter is never closed")
}

/// Resolve once the local-listener close signal latches. Pends forever if the
/// signal's sender is gone — no close can arrive anymore — so a `select!` arm
/// built on this never fires spuriously. Cancel-safe (`watch::Receiver::wait_for`
/// is).
async fn listener_closed(close: &mut watch::Receiver<bool>) {
    if close.wait_for(|closed| *closed).await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// Accept loop for a local front-end listener. Each accepted connection is
/// handled by [`handle_local_conn`] parameterized on `proto`. Shared verbatim by
/// the SOCKS5 and HTTP listeners.
///
/// Failure policy (see [`AcceptFailure`]): resource pressure and one-off
/// aborts are retried after [`ACCEPT_RETRY_DELAY`]; a broken listener — or an
/// abort burst, the signature of a socket the OS invalidated underneath us
/// (iOS defuncts every socket of a suspended process, and the health probe
/// would otherwise keep reading "alive" while nothing can connect) — is
/// **rebound** in place on the same address. Concurrency is bounded by
/// [`MAX_ACTIVE_LOCAL_CONNS`]. Returns only when a rebind fails; on the
/// [`ProxyClient::close_local_listeners`] signal the listener is dropped and
/// the loop parks forever so the enclosing `select!` keeps the session alive.
async fn accept_loop<P: LocalProto>(
    mut listener: TcpListener,
    router: &Arc<Router>,
    proto: P,
    mut close: watch::Receiver<bool>,
) -> ProxyResult<()> {
    let addr = listener.local_addr()?;
    let mut retry = AcceptRetry::new("Local proxy");
    let limiter = Arc::new(Semaphore::new(MAX_ACTIVE_LOCAL_CONNS));
    let hold_limiter = Arc::new(HoldBudget::new(router.destinations.len()));
    let mut warned_saturated = false;
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            _ = listener_closed(&mut close) => {
                log::info!("Local proxy listener on {addr} closed on request");
                break;
            }
        };
        let (tcp, peer) = match accepted {
            Ok(accepted) => {
                retry.record_success();
                accepted
            }
            Err(e) => {
                match retry.record_error(&e) {
                    AcceptOutcome::Rebind => {
                        log::warn!("Local proxy listener on {addr} is dead ({e}); rebinding");
                        // The dead socket still owns the port; release it first.
                        drop(listener);
                        listener = rebind_listener(addr).await?;
                        log::info!("Local proxy listener rebound on {addr}");
                        retry.record_rebind();
                    }
                    AcceptOutcome::Retry => retry.wait_retry(&e).await,
                }
                continue;
            }
        };
        log::debug!("proxy connection from {peer}");
        // A saturated listener parks here, not in accept, so the close signal
        // must preempt this wait too (dropping the just-accepted socket).
        let permit = tokio::select! {
            permit = acquire_conn_permit(&limiter, &mut warned_saturated, "Local proxy") => permit,
            _ = listener_closed(&mut close) => {
                log::info!("Local proxy listener on {addr} closed on request");
                break;
            }
        };
        let router = router.clone();
        let proto = proto.clone();
        let hold_limiter = hold_limiter.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_local_conn(proto, tcp, router, hold_limiter).await {
                log::debug!("proxy connection from {peer} ended: {e}");
            }
        });
    }
    // Closed on request. Release the socket so new local connections get an
    // immediate refusal, then park: returning would resolve the session's
    // `select!` and tear down the destinations, which must outlive its
    // front-ends.
    drop(listener);
    std::future::pending().await
}

/// Accept loop for the optional Unix-domain SOCKS5 front-end. Mirrors
/// [`accept_loop`] but for a [`UnixListener`]; the per-connection handling is
/// shared (generic over the stream type). Kept separate from the TCP loop
/// because rebinding a socket file means unlinking + re-binding a path rather
/// than a `SocketAddr`. iOS defuncts every socket of a suspended process, so the
/// same "rebind a listener the OS invalidated underneath us" policy applies.
#[cfg(unix)]
async fn accept_loop_unix(
    mut listener: UnixListener,
    router: &Arc<Router>,
    mut close: watch::Receiver<bool>,
) -> ProxyResult<()> {
    let path = listener
        .local_addr()
        .ok()
        .and_then(|a| a.as_pathname().map(|p| p.to_path_buf()));
    let mut retry = AcceptRetry::new("Unix SOCKS5");
    let limiter = Arc::new(Semaphore::new(MAX_ACTIVE_LOCAL_CONNS));
    let hold_limiter = Arc::new(HoldBudget::new(router.destinations.len()));
    let mut warned_saturated = false;
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            _ = listener_closed(&mut close) => {
                log::info!("Unix SOCKS5 listener at {path:?} closed on request");
                break;
            }
        };
        let stream = match accepted {
            Ok((stream, _addr)) => {
                retry.record_success();
                stream
            }
            Err(e) => {
                match retry.record_error(&e) {
                    AcceptOutcome::Rebind => {
                        let Some(path) = &path else { return Err(e.into()) };
                        log::warn!("Unix SOCKS5 listener at {path:?} is dead ({e}); rebinding");
                        drop(listener);
                        listener = rebind_unix_listener(path).await?;
                        log::info!("Unix SOCKS5 listener rebound at {path:?}");
                        retry.record_rebind();
                    }
                    AcceptOutcome::Retry => retry.wait_retry(&e).await,
                }
                continue;
            }
        };
        log::debug!("unix proxy connection accepted");
        // As in `accept_loop`: the close signal must preempt a saturated wait.
        let permit = tokio::select! {
            permit = acquire_conn_permit(&limiter, &mut warned_saturated, "Unix SOCKS5") => permit,
            _ = listener_closed(&mut close) => {
                log::info!("Unix SOCKS5 listener at {path:?} closed on request");
                break;
            }
        };
        let router = router.clone();
        let hold_limiter = hold_limiter.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_local_conn(Socks5Proto, stream, router, hold_limiter).await {
                log::debug!("unix proxy connection ended: {e}");
            }
        });
    }
    // Closed on request: as in `accept_loop`, release the socket and park so
    // the session outlives its front-ends. The socket file is left behind;
    // connecting to it now fails with ECONNREFUSED.
    drop(listener);
    std::future::pending().await
}

/// Rebind a Unix-domain listener: remove the stale socket file (a defunct socket
/// still owns the path) then bind it again, with one retry after
/// [`ACCEPT_RETRY_DELAY`] to absorb a lingering-file race.
#[cfg(unix)]
async fn rebind_unix_listener(path: &std::path::Path) -> ProxyResult<UnixListener> {
    let _ = std::fs::remove_file(path);
    if let Ok(l) = UnixListener::bind(path) {
        return Ok(l);
    }
    tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
    let _ = std::fs::remove_file(path);
    Ok(UnixListener::bind(path)?)
}

/// Handle one local proxy connection: parse the front-end request, then route
/// it by the client's table. A target on a destination's list is tunneled to
/// that destination's server — connecting it first if need be, with the
/// request held up to [`TUNNEL_RECOVERY_HOLD`] (concurrent holds capped by
/// `hold_limiter`, per destination and in all) and answered
/// network-unreachable if no connection lands. A
/// target on no list is dialed directly from this device. The reserved
/// `flextunnel.internal` names are answered here, by the client itself.
async fn handle_local_conn<P: LocalProto, S: LocalStream>(
    proto: P,
    mut tcp: S,
    router: Arc<Router>,
    hold_limiter: Arc<HoldBudget>,
) -> Result<()> {
    // Bound the local handshake so a peer that connects and sends nothing can't
    // pin this task and its socket indefinitely.
    let LocalRequest {
        target,
        upstream_preamble,
    } = tokio::time::timeout(LOCAL_HANDSHAKE_TIMEOUT, proto.read_request(&mut tcp))
        .await
        .map_err(|_| anyhow::anyhow!("timed out during local proxy handshake"))??;

    let (dest, request) = match router.table.route(&target) {
        Route::Tunnel { dest, request } => (dest, request),
        // Split-tunnel: a target on no destination's list is dialed directly
        // from this device's own network (its DNS, its IP) — whatever state
        // the destinations are in.
        Route::Direct => {
            log::debug!("Direct (no destination routes it): {target:?}");
            return direct_connect(proto, tcp, &target, upstream_preamble).await;
        }
        route @ (Route::ClientStatus | Route::Reserved) => {
            log::debug!("Client status endpoint: {target:?}");
            return client_status::serve(
                &proto,
                &mut tcp,
                upstream_preamble,
                &router,
                route == Route::Reserved,
                &hold_limiter,
            )
            .await;
        }
    };

    // Tunneled: needs the destination's connection. If it is not up — an idle
    // destination's first use, or a drop being retried — this request is what
    // makes it connect, and is held while it does. Only a connection that
    // never lands answers with an error reply, so the app shows a connection
    // error for this target instead of hanging forever. A destination that is
    // connected takes no hold at all.
    let destination = &router.destinations[dest];
    let lease = match destination.acquire(Some(hold_limiter.for_destination(dest))).await {
        Ok(lease) => lease,
        Err(e) => {
            log::debug!("{}: {e}; refusing {target:?}", destination.host());
            let rep = match e {
                // The server turned this client away: no point in the app
                // retrying as it would an unreachable network.
                AcquireError::Failed(_) => signaling::REP_NOT_ALLOWED,
                AcquireError::TimedOut | AcquireError::HoldCap | AcquireError::Closed => {
                    signaling::REP_NET_UNREACHABLE
                }
            };
            let _ = proto.reply(&mut tcp, rep).await;
            return Ok(());
        }
    };
    log::debug!("Tunneling via {}: {target:?}", destination.host());

    // Open the tunnel stream and read the server's reply. If any step fails the
    // local app hasn't been answered yet, so send a general-failure reply
    // (best effort) instead of dropping the connection with no response.
    let opened = tokio::time::timeout(TUNNEL_OPEN_TIMEOUT, open_tunnel(&lease.conn, &request))
        .await
        .map_err(|_| anyhow::anyhow!("timed out opening tunnel / awaiting server reply"))
        .and_then(|r| r);
    let (mut send, recv, rep) = match opened {
        Ok(v) => v,
        Err(e) => {
            let _ = proto.reply(&mut tcp, signaling::REP_GENERAL_FAILURE).await;
            return Err(e);
        }
    };

    if rep != signaling::REP_SUCCESS {
        proto.reply(&mut tcp, rep).await?;
        return Ok(());
    }

    // Begin the exchange: a tunnel answers the local app with a success reply
    // and splices; a forward instead writes the rewritten request head upstream
    // — the origin's response, relayed by the splice, is the app's reply.
    match &upstream_preamble {
        None => proto.reply(&mut tcp, rep).await?,
        Some(head) => {
            // A forward hasn't answered the local app yet (its reply is the
            // origin's response, relayed by the splice). If writing the head
            // upstream fails, send a best-effort HTTP failure instead of
            // dropping the connection silently.
            if let Err(e) = send.write_all(head).await {
                let _ = proto.reply(&mut tcp, signaling::REP_GENERAL_FAILURE).await;
                return Err(e.into());
            }
        }
    }

    // The lease is held through the splice: an open stream keeps the
    // destination's connection from being closed as idle.
    let mut iroh = tokio::io::join(recv, send);
    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut iroh).await;
    drop(lease);
    Ok(())
}

/// Connect to `target` directly from this device (bypassing the tunnel) and pipe
/// bytes, answering the local app's request with the matching reply code via
/// `proto` (or, for an HTTP forward, writing its rewritten head upstream instead
/// of a success reply). Used for targets no destination routes.
/// The dial is bounded by the same deadline as opening a tunnel so a slow target
/// can't pin the task.
async fn direct_connect<P: LocalProto, S: LocalStream>(
    proto: P,
    mut tcp: S,
    target: &signaling::Target,
    upstream_preamble: Option<Vec<u8>>,
) -> Result<()> {
    // Direct connections resolve on the device via its own DNS; a server's
    // conditional forwarding does not apply here.
    let dialed = tokio::time::timeout(TUNNEL_OPEN_TIMEOUT, dial::dial_target(target, None)).await;
    let mut upstream = match dialed {
        Ok(Ok(mut s)) => {
            match &upstream_preamble {
                None => proto.reply(&mut tcp, signaling::REP_SUCCESS).await?,
                Some(head) => s.write_all(head).await?,
            }
            s
        }
        Ok(Err(e)) => {
            let _ = proto.reply(&mut tcp, signaling::map_io_err(&e)).await;
            return Ok(());
        }
        Err(_) => {
            let _ = proto.reply(&mut tcp, signaling::REP_HOST_UNREACHABLE).await;
            return Ok(());
        }
    };
    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut upstream).await;
    Ok(())
}

/// Open a bi-stream to the server, send the stream request, and read back the
/// reply code. Returns the stream halves and the reply so the caller can relay
/// the reply to the local app and then pipe bytes.
pub(crate) async fn open_tunnel(
    conn: &Connection,
    request: &StreamRequest,
) -> Result<(SendStream, RecvStream, u8)> {
    let (mut send, mut recv) = conn.open_bi().await?;
    signaling::write_request(&mut send, request).await?;
    send.flush().await?;
    let rep = signaling::read_reply(&mut recv).await?;
    Ok((send, recv, rep))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::destination::ClientAuth;
    use crate::transport::endpoint::RelayConfig;
    use iroh::SecretKey;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpStream;
    #[cfg(unix)]
    use tokio::net::UnixStream;

    /// A destination named `host` whose server id derives from `seed`, routing
    /// the given rules. Its key is throwaway: these tests never connect.
    fn test_destination(host: &str, seed: u8, domains: &[&str], cidrs: &[&str]) -> DestinationConfig {
        DestinationConfig {
            host: host.to_string(),
            server_id: SecretKey::from_bytes(&[seed; 32]).public(),
            auth: ClientAuth::Key(Box::new(crate::auth::ClientKey::generate().unwrap())),
            relay: RelayConfig::default(),
            routed_domains: domains.iter().map(|s| s.to_string()).collect(),
            routed_cidrs: cidrs.iter().map(|s| s.to_string()).collect(),
            keep_connected: false,
        }
    }

    /// A client whose one destination routes nothing a test dials, so loopback
    /// targets take the direct path.
    fn test_client() -> ProxyClient {
        ProxyClient::new(ClientConfig {
            destinations: vec![test_destination(
                "m1.internal",
                1,
                &["nothing.internal"],
                &["10.0.0.0/8"],
            )],
            idle_timeout: None,
        })
        .unwrap()
    }

    fn config_error(destinations: Vec<DestinationConfig>) -> String {
        match ProxyClient::new(ClientConfig {
            destinations,
            idle_timeout: None,
        }) {
            Ok(_) => panic!("expected a configuration error"),
            Err(e) => {
                assert!(matches!(e, ProxyError::Config(_)), "{e:?}");
                assert!(!e.is_recoverable());
                e.to_string()
            }
        }
    }

    /// The destinations are validated before anything is bound or dialed.
    #[test]
    fn invalid_destinations_are_rejected_at_construction() {
        assert!(config_error(Vec::new()).contains("no destinations"));
        // One server under two names.
        let message = config_error(vec![
            test_destination("m1.internal", 1, &[], &[]),
            test_destination("m2.internal", 1, &[], &[]),
        ]);
        assert!(message.contains("same server"), "{message}");
        assert!(message.contains("m1.internal") && message.contains("m2.internal"), "{message}");
        // Routing-table errors surface as configuration errors too.
        assert!(config_error(vec![test_destination("10.0.0.1", 1, &[], &[])]).contains("IP address"));
        assert!(
            config_error(vec![
                test_destination("m1.internal", 1, &["*.corp.example"], &[]),
                test_destination("m2.internal", 2, &["*.corp.example"], &[]),
            ])
            .contains("both route")
        );
    }

    /// A built client is entirely idle, and its hosts are stored normalized.
    #[test]
    fn a_new_client_is_idle() {
        let client = ProxyClient::new(ClientConfig {
            destinations: vec![
                test_destination(" Machine1.Internal ", 1, &["*.corp.example"], &[]),
                test_destination("m2.internal", 2, &[], &["10.0.0.0/8"]),
            ],
            idle_timeout: Some(Duration::from_secs(300)),
        })
        .unwrap();
        let status = client.status();
        assert_eq!(status.idle_timeout, Some(Duration::from_secs(300)));
        assert!(status.socks_listen.is_none() && status.http_listen.is_none());
        let hosts: Vec<&str> = status.destinations.iter().map(|d| d.host.as_str()).collect();
        assert_eq!(hosts, ["machine1.internal", "m2.internal"]);
        for destination in &status.destinations {
            assert_eq!(destination.state, crate::proxy::DestinationState::Idle);
            assert!(destination.client_node_id.is_none());
        }
    }

    /// The dialer routes like a proxy request but never connects directly: a
    /// target no destination routes is an error.
    #[tokio::test]
    async fn dialer_refuses_what_no_destination_routes() {
        let client = ProxyClient::new(ClientConfig {
            destinations: vec![
                test_destination("m1.internal", 1, &["*.corp.example"], &[]),
                test_destination("m2.internal", 2, &[], &["10.0.0.0/8"]),
            ],
            idle_timeout: None,
        })
        .unwrap();
        let dialer = client.dialer();
        let domain = |host: &str| Target::Domain(host.to_string(), 80);
        assert_eq!(dialer.destination_for(&domain("M1.internal")), Some("m1.internal"));
        assert_eq!(dialer.destination_for(&domain("api.corp.example")), Some("m1.internal"));
        assert_eq!(dialer.destination_for(&domain("10.2.3.4")), Some("m2.internal"));
        assert_eq!(dialer.destination_for(&domain("example.org")), None);
        assert_eq!(dialer.destination_for(&domain("flextunnel.internal")), None);

        let err = dialer.connect(&domain("example.org")).await.err().expect("refused");
        assert!(err.to_string().contains("no destination routes example.org"), "{err}");
        let err = dialer.connect(&domain("flextunnel.internal")).await.err().expect("refused");
        assert!(err.to_string().contains("status endpoint"), "{err}");
        // Refusing never asked a destination to connect.
        assert!(client.status().destinations.iter().all(|d| d.waiting == 0));

        assert!(dialer.warm("m2.internal"));
        assert!(!dialer.warm("nope.internal"));
    }

    /// fd exhaustion must be retried without ever rebinding; aborted/reset
    /// races retry and rebind only as a burst; a broken listener (bad fd)
    /// must rebind immediately instead of killing the client.
    #[cfg(unix)]
    #[test]
    fn accept_error_classification() {
        for code in [libc::EMFILE, libc::ENFILE] {
            assert_eq!(
                classify_accept_error(&io::Error::from_raw_os_error(code)),
                AcceptFailure::ResourcePressure,
                "os error {code} should be resource pressure"
            );
        }
        for code in [libc::ECONNABORTED, libc::EINTR] {
            assert_eq!(
                classify_accept_error(&io::Error::from_raw_os_error(code)),
                AcceptFailure::Aborted,
                "os error {code} should be an abort"
            );
        }
        // A kind-only error (no raw OS code) must be classified by the
        // `ErrorKind` branch alone.
        assert_eq!(
            classify_accept_error(&io::Error::new(
                io::ErrorKind::ConnectionReset,
                "peer reset before accept"
            )),
            AcceptFailure::Aborted
        );
        for code in [libc::EBADF, libc::EINVAL] {
            assert_eq!(
                classify_accept_error(&io::Error::from_raw_os_error(code)),
                AcceptFailure::Broken,
                "os error {code} should be broken"
            );
        }
    }

    /// An idle timeout the clock could not add to a moment is refused when the
    /// client is built, not found out by a panic once a connection falls
    /// unused. No timeout at all stays the way to never close one.
    #[test]
    fn an_oversized_idle_timeout_is_refused_at_construction() {
        let build = |idle_timeout| {
            ProxyClient::new(ClientConfig {
                destinations: vec![test_destination("m1.internal", 1, &[], &[])],
                idle_timeout,
            })
        };
        for too_long in [Duration::MAX, Duration::from_secs(u64::MAX), MAX_IDLE_TIMEOUT + Duration::from_secs(1)] {
            let err = build(Some(too_long)).err().expect("refused").to_string();
            assert!(err.contains("idle timeout") && err.contains("set it to 0"), "{err}");
        }
        for fine in [None, Some(Duration::ZERO), Some(Duration::from_secs(300)), Some(MAX_IDLE_TIMEOUT)] {
            assert!(build(fine).is_ok(), "{fine:?}");
        }
        // What an accepted timeout is added to cannot overflow.
        assert!(tokio::time::Instant::now().checked_add(MAX_IDLE_TIMEOUT).is_some());
    }

    /// The hold budget keeps its total, gives every destination a share no
    /// other can take, and leaves the rest to whoever needs it.
    #[test]
    fn the_hold_budget_reserves_a_share_per_destination() {
        for destinations in [1, 2, 5, 8, 9, 64, 200] {
            let budget = HoldBudget::new(destinations);
            let total: usize = budget.reserved.iter().map(Semaphore::available_permits).sum::<usize>()
                + budget.shared.available_permits();
            assert_eq!(total, MAX_HELD_CONNS, "{destinations} destinations");
        }
        assert_eq!(HoldBudget::new(1).reserved[0].available_permits(), HOLDS_RESERVED_PER_DESTINATION);
        assert_eq!(HoldBudget::new(200).reserved[0].available_permits(), 0, "too many to reserve for");

        // One destination's server is down and its retries pile up: it holds
        // everything it can reach...
        let budget = HoldBudget::new(3);
        let down = budget.for_destination(0);
        let mut held = Vec::new();
        while let Ok(permit) = down.reserved.try_acquire().or_else(|_| down.shared.try_acquire()) {
            held.push(permit);
        }
        assert_eq!(held.len(), MAX_HELD_CONNS - 2 * HOLDS_RESERVED_PER_DESTINATION);
        // ...and the other destinations can still hold their first requests.
        for other in [1, 2] {
            let holds = budget.for_destination(other);
            assert_eq!(holds.reserved.available_permits(), HOLDS_RESERVED_PER_DESTINATION);
            assert_eq!(holds.shared.available_permits(), 0);
        }
    }

    /// `close_local_listeners` must drop the front-end listener — local
    /// connects turn into refusals — while the accept future stays pending, so
    /// the session `select!` it lives in keeps the destinations running.
    #[tokio::test]
    async fn close_signal_drops_listener_without_ending_loop() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = test_client();
        let close = client.local_close.subscribe();
        let task = {
            let router = client.router.clone();
            tokio::spawn(async move { accept_loop(listener, &router, Socks5Proto, close).await })
        };
        // Live: a local connect lands.
        TcpStream::connect(addr).await.unwrap();

        client.close_local_listeners();
        // Closed: once the loop observes the signal and drops the listener,
        // connects are refused. Poll — the drop happens on the spawned task.
        let refused = async {
            loop {
                if TcpStream::connect(addr).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(5), refused)
            .await
            .expect("listener still accepting after close signal");
        // ...but the loop itself parks instead of resolving the session.
        assert!(!task.is_finished());
    }

    /// At the connection cap the loop parks awaiting a permit, not in accept;
    /// the close signal must preempt that wait too and still drop the listener.
    #[tokio::test]
    async fn close_signal_preempts_saturated_listener() {
        // ~2×(cap+1) sockets live at once; don't let the soft fd limit flake it.
        crate::app::raise_fd_limit();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = test_client();
        let close = client.local_close.subscribe();
        let task = {
            let router = client.router.clone();
            tokio::spawn(async move { accept_loop(listener, &router, Socks5Proto, close).await })
        };
        // Saturate every permit with idle connections (each accepted handler
        // sits in the SOCKS handshake read for LOCAL_HANDSHAKE_TIMEOUT, holding
        // its permit), plus one more so the loop parks in permit acquisition.
        let mut held = Vec::new();
        for _ in 0..=MAX_ACTIVE_LOCAL_CONNS {
            held.push(TcpStream::connect(addr).await.unwrap());
        }

        client.close_local_listeners();
        let refused = async {
            loop {
                if TcpStream::connect(addr).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(5), refused)
            .await
            .expect("saturated listener still accepting after close signal");
        assert!(!task.is_finished());
        drop(held);
    }

    /// Unix-domain twin of `close_signal_preempts_saturated_listener`: the
    /// close-vs-permit race is duplicated in `accept_loop_unix`, so cover it
    /// there as well (a closed Unix listener refuses instead of accepting).
    #[cfg(unix)]
    #[tokio::test]
    async fn close_signal_preempts_saturated_unix_listener() {
        crate::app::raise_fd_limit();
        let path = std::env::temp_dir().join(format!("ftsat{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let client = test_client();
        let close = client.local_close.subscribe();
        let task = {
            let router = client.router.clone();
            tokio::spawn(async move { accept_loop_unix(listener, &router, close).await })
        };
        let mut held = Vec::new();
        for _ in 0..=MAX_ACTIVE_LOCAL_CONNS {
            held.push(UnixStream::connect(&path).await.unwrap());
        }

        client.close_local_listeners();
        let refused = async {
            loop {
                if UnixStream::connect(&path).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(5), refused)
            .await
            .expect("saturated unix listener still accepting after close signal");
        assert!(!task.is_finished());
        drop(held);
        let _ = std::fs::remove_file(&path);
    }

    /// The accept loop must survive its listener dying: a defunct listener
    /// (simulated with an abort burst via `classify_accept_error` is not
    /// injectable on a real socket, so exercise the rebind path directly) is
    /// replaced by a fresh listener on the same address once the old socket is
    /// dropped.
    #[tokio::test]
    async fn rebind_listener_reclaims_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener); // as accept_loop does: the dead socket owns the port
        let rebound = rebind_listener(addr).await.unwrap();
        assert_eq!(rebound.local_addr().unwrap(), addr);
        // And it actually accepts.
        let client = TcpStream::connect(addr);
        let (accepted, _) = tokio::join!(rebound.accept(), client);
        accepted.unwrap();
    }

    /// End-to-end over a real Unix-domain socket: `accept_loop_unix` accepts a
    /// connection, the (generic) `handle_local_conn` speaks SOCKS5, and a
    /// target no destination routes takes the direct path — proving the UDS
    /// front-end serves SOCKS5 exactly like the TCP one.
    #[cfg(unix)]
    #[tokio::test]
    async fn unix_socks_direct_path_serves_socks5() {
        // A local origin the proxy will dial directly (no destination routes it).
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_port = origin.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = origin.accept().await.unwrap();
            let mut buf = [0u8; 16];
            let n = sock.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"ping");
            sock.write_all(b"pong").await.unwrap();
        });

        // The Unix-domain SOCKS5 front-end.
        let path = std::env::temp_dir().join(format!("ftuds{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        // 127.0.0.1 is on no destination's list, so the CONNECT goes direct.
        let router = test_client().router.clone();
        let (_close_tx, close_rx) = watch::channel(false);
        tokio::spawn(async move {
            accept_loop_unix(listener, &router, close_rx).await.ok();
        });

        // SOCKS5 client over the unix socket: greet, CONNECT 127.0.0.1:origin.
        let mut app = UnixStream::connect(&path).await.unwrap();
        app.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0u8; 2];
        app.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00], "no-auth method selected");
        let p = origin_port.to_be_bytes();
        app.write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, p[0], p[1]])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        app.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], signaling::REP_SUCCESS, "SOCKS5 CONNECT succeeded");

        // The tunnel/direct byte-splice is live: round-trip through it.
        app.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        app.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"pong");

        let _ = std::fs::remove_file(&path);
    }

    /// The backoff doubles from 1s and settles at the cap, jitter aside.
    #[test]
    fn backoff_doubles_to_the_cap() {
        let jitter = Duration::from_millis(RECONNECT_JITTER_MAX_MS);
        for (attempt, secs) in [(0, 1), (1, 1), (2, 2), (3, 4), (6, 32)] {
            let b = calculate_backoff(attempt);
            let base = Duration::from_secs(secs);
            assert!(b >= base && b <= base + jitter, "attempt {attempt}: {b:?}");
        }
        for attempt in [7, 9, 10, 20, u32::MAX] {
            let b = calculate_backoff(attempt);
            assert!(
                b >= RECONNECT_BACKOFF_MAX && b <= RECONNECT_BACKOFF_MAX + jitter,
                "attempt {attempt}: {b:?}"
            );
        }
    }

    /// An outage's first rebuild comes after the third consecutive failure;
    /// later ones are spaced by the minimum interval, however many attempts
    /// fail in between.
    #[test]
    fn rebuild_after_third_failure_then_at_most_every_interval() {
        assert!(!rebuild_due(0, None));
        assert!(!rebuild_due(REBUILD_ENDPOINT_ATTEMPTS - 1, None));
        assert!(rebuild_due(REBUILD_ENDPOINT_ATTEMPTS, None));
        assert!(rebuild_due(REBUILD_ENDPOINT_ATTEMPTS + 7, None));

        let just_now = Some(Instant::now());
        assert!(!rebuild_due(REBUILD_ENDPOINT_ATTEMPTS, just_now));
        assert!(!rebuild_due(REBUILD_ENDPOINT_ATTEMPTS * 4, just_now));

        let long_ago = Instant::now().checked_sub(REBUILD_ENDPOINT_MIN_INTERVAL);
        assert!(long_ago.is_some(), "test host has been up for over an hour");
        assert!(rebuild_due(REBUILD_ENDPOINT_ATTEMPTS, long_ago));
        assert!(!rebuild_due(REBUILD_ENDPOINT_ATTEMPTS - 1, long_ago));
    }


    /// End-to-end plain-HTTP forwarding through the *direct* path: the HTTP
    /// front-end rewrites the absolute-URI request to origin-form, the target
    /// no destination routes is dialed directly, the rewritten head is written
    /// upstream (no local success reply), and the origin's response streams
    /// back verbatim.
    #[tokio::test]
    async fn http_forward_direct_path_relays_origin_response() {
        // The origin: assert the head arrived rewritten, answer, and close —
        // the close is what ends the exchange (Connection: close semantics).
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_port = origin.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = origin.accept().await.unwrap();
            let mut head = Vec::new();
            let mut buf = [0u8; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = sock.read(&mut buf).await.unwrap();
                assert!(n > 0, "EOF before a complete request head");
                head.extend_from_slice(&buf[..n]);
            }
            let head = String::from_utf8(head).unwrap();
            assert!(
                head.starts_with("GET /hello HTTP/1.1\r\n"),
                "origin-form request line expected, got: {head:?}"
            );
            assert!(head.contains(&format!("Host: 127.0.0.1:{origin_port}\r\n")));
            assert!(head.contains("Connection: close\r\n"));
            assert!(!head.contains("Proxy-Connection"));
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi")
                .await
                .unwrap();
        });

        // The proxy: one accepted socket handled by a client none of whose
        // destinations routes 127.0.0.1, so the request takes the direct path.
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let router = test_client().router.clone();
        tokio::spawn(async move {
            let holds = Arc::new(HoldBudget::new(router.destinations.len()));
            let (tcp, _) = proxy.accept().await.unwrap();
            handle_local_conn(HttpProto, tcp, router, holds).await.unwrap();
        });

        let mut app = TcpStream::connect(proxy_addr).await.unwrap();
        app.write_all(
            format!(
                "GET http://127.0.0.1:{origin_port}/hello HTTP/1.1\r\n\
                 Host: 127.0.0.1:{origin_port}\r\n\
                 Proxy-Connection: keep-alive\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut resp = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), app.read_to_end(&mut resp))
            .await
            .expect("proxied response timed out")
            .unwrap();
        let resp = String::from_utf8(resp).unwrap();
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "got: {resp:?}");
        assert!(resp.ends_with("hi"), "got: {resp:?}");
    }

    /// Drive one already-parsed front-end exchange against `router`: write
    /// `request` to a duplex "app" socket handled by `handle_local_conn`, and
    /// return everything the app reads back.
    async fn exchange<P: LocalProto>(proto: P, router: Arc<Router>, request: Vec<u8>) -> String {
        let (mut app, server) = tokio::io::duplex(64 * 1024);
        let handler = tokio::spawn(async move {
            let holds = Arc::new(HoldBudget::new(router.destinations.len()));
            handle_local_conn(proto, server, router, holds).await
        });
        app.write_all(&request).await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), app.read_to_end(&mut response))
            .await
            .expect("response timed out")
            .unwrap();
        handler.await.unwrap().unwrap();
        String::from_utf8_lossy(&response).into_owned()
    }

    /// A SOCKS5 CONNECT to `host:80` followed by `http_request`, as raw bytes.
    fn socks_request(host: &str, http_request: &str) -> Vec<u8> {
        let mut bytes = vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, host.len() as u8];
        bytes.extend_from_slice(host.as_bytes());
        bytes.extend_from_slice(&80u16.to_be_bytes());
        bytes.extend_from_slice(http_request.as_bytes());
        bytes
    }

    /// `flextunnel.internal` is answered by the client itself from every
    /// front-end — SOCKS5, HTTP CONNECT and a plain absolute-URI GET — and
    /// answering never makes a destination connect.
    #[tokio::test]
    async fn client_status_endpoint_is_served_locally_from_every_front_end() {
        let client = test_client();
        let router = client.router.clone();

        // SOCKS5: method reply (2 bytes) + CONNECT reply (10 bytes), then HTTP.
        let get = "GET /status.json HTTP/1.1\r\nHost: flextunnel.internal\r\n\r\n";
        let response = exchange(Socks5Proto, router.clone(), socks_request("flextunnel.internal", get)).await;
        let body = response.split_once("\r\n\r\n").expect("an HTTP response").1;
        let json: serde_json::Value = serde_json::from_str(body).expect("JSON status");
        assert_eq!(json["destinations"][0]["host"], "m1.internal");
        assert_eq!(json["destinations"][0]["state"], "idle");
        assert_eq!(json["destinations"][0]["routed_cidrs"][0], "10.0.0.0/8");

        // HTTP CONNECT, then the request through the "tunnel"; `Accept` picks text.
        let connect = "CONNECT flextunnel.internal:80 HTTP/1.1\r\nHost: flextunnel.internal:80\r\n\r\n\
                       GET / HTTP/1.1\r\nHost: flextunnel.internal\r\nAccept: text/plain\r\n\r\n";
        let response = exchange(HttpProto, router.clone(), connect.as_bytes().to_vec()).await;
        assert!(response.starts_with("HTTP/1.1 200 Connection Established\r\n\r\n"), "{response:.80}");
        assert!(response.contains("Content-Type: text/plain"), "{response}");
        assert!(response.contains("flextunnel client status"));
        assert!(response.contains("m1.internal"));

        // A plain absolute-URI GET: the response is the page itself.
        let forward = "GET http://flextunnel.internal/ HTTP/1.1\r\nHost: flextunnel.internal\r\n\r\n";
        let response = exchange(HttpProto, router.clone(), forward.as_bytes().to_vec()).await;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response:.80}");
        assert!(response.contains("Content-Type: text/html"));
        assert!(response.contains("href=\"/servers/m1.internal/\""));

        // Unknown pages and destinations, other methods, other reserved names.
        for (request, status) in [
            ("GET http://flextunnel.internal/nope HTTP/1.1\r\n\r\n", "404 Not Found"),
            ("GET http://flextunnel.internal/servers/nope.internal/ HTTP/1.1\r\n\r\n", "404 Not Found"),
            ("GET http://flextunnel.internal/servers/m1.internal/x HTTP/1.1\r\n\r\n", "404 Not Found"),
            ("POST http://flextunnel.internal/ HTTP/1.1\r\nContent-Length: 0\r\n\r\n", "405 Method Not Allowed"),
            ("GET http://localhost.flextunnel.internal/ HTTP/1.1\r\n\r\n", "404 Not Found"),
        ] {
            let response = exchange(HttpProto, router.clone(), request.as_bytes().to_vec()).await;
            assert!(response.starts_with(&format!("HTTP/1.1 {status}\r\n")), "{request}: {response:.80}");
        }

        // None of it touched the destination.
        let status = client.status();
        assert_eq!(status.destinations[0].state, crate::proxy::DestinationState::Idle);
        assert_eq!(status.destinations[0].waiting, 0);
        assert!(status.destinations[0].client_node_id.is_none());
    }
}
