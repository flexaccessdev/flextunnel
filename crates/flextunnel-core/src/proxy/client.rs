//! flextunnel client: a local SOCKS5 listener whose CONNECTs are tunneled over
//! a single iroh QUIC connection to the server, one bi-stream per CONNECT.

use crate::error::{ProxyError, ProxyResult};
use crate::proxy::signaling::{self, ControlMsg, Hello, Target};
use crate::proxy::{dial, http, socks5, RoutedSet};
use crate::transport::{HEARTBEAT_INTERVAL, LIVENESS_WINDOW};
use anyhow::Result;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl};
use rand::Rng;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

/// Reconnect backoff: base 1s, doubling per attempt, capped at 60s.
const RECONNECT_BACKOFF_MAX: u64 = 60;
/// Max jitter (ms) added to each backoff to avoid thundering reconnects.
const RECONNECT_JITTER_MAX_MS: u64 = 500;
/// Deadline for the server's handshake response. The QUIC keep-alive keeps the
/// connection from idling out, so without this a server that accepts the
/// connection but never replies on the stream would hang the client forever.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Deadline for opening a tunnel stream and receiving the server's CONNECT
/// reply. Must exceed the server's own connect timeout (it replies only after
/// dialing the target, up to ~10s), so a legitimately slow target isn't cut
/// off; without it a server that stalls after accepting the stream would hang
/// the local SOCKS5 connection forever.
const TUNNEL_OPEN_TIMEOUT: Duration = Duration::from_secs(30);
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

/// The live QUIC connection shared with the always-on accept loop; `None` while
/// disconnected (during a drop/backoff), so off-list targets still connect
/// directly and on-list targets get a clean unreachable reply.
type SharedConn = Arc<Mutex<Option<Connection>>>;
/// The route policy (tunnel set) shared with the accept loop. `None` until the
/// first handshake learns it, then `Some` for the rest of the process — retained
/// across drops so split-tunnel routing keeps working while the connection is
/// down. While it is `None` the client **fails closed**: no connection is routed
/// (directly or tunneled) before the policy is known, so nothing leaks out.
type SharedRoutedSet = Arc<Mutex<Option<Arc<RoutedSet>>>>;

/// Configuration for the proxy client.
pub struct ClientConfig {
    /// Server's iroh EndpointId (as a string).
    pub server_node_id: String,
    /// Authentication token sent in the connection handshake.
    pub auth_token: String,
    /// Local address the SOCKS5 listener binds to.
    pub socks_listen: SocketAddr,
    /// Local address for the optional HTTP proxy listener (CONNECT tunneling +
    /// absolute-URI plain-HTTP forwarding). `None` leaves the HTTP front-end
    /// disabled; the SOCKS5 listener is always on.
    pub http_listen: Option<SocketAddr>,
    /// Relay URL hints (optional).
    pub relay_urls: Vec<String>,
    /// Reconnect with backoff on a transient failure instead of exiting.
    pub auto_reconnect: bool,
    /// Cap on reconnect attempts between successful connections (unlimited if None).
    pub max_reconnect_attempts: Option<NonZeroU32>,
}

/// Exponential backoff with jitter for the Nth (1-based) reconnect attempt.
///
/// Shared with [`crate::proxy::agent`], whose reconnect policy mirrors the
/// client's.
pub(crate) fn calculate_backoff(attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(6); // cap the doubling at 2^6 = 64
    let secs = (1u64 << shift).min(RECONNECT_BACKOFF_MAX);
    let jitter = rand::rng().random_range(0..=RECONNECT_JITTER_MAX_MS);
    Duration::from_secs(secs) + Duration::from_millis(jitter)
}

/// Snapshot of what the tunnel currently forwards: the split-tunnel set the
/// server pushed on the last successful handshake, plus whether a connection is
/// live right now. Shared with the FFI so the app can display the routed
/// domains/CIDRs. An empty set while `connected` is true means the server runs
/// no routed set and everything is tunneled.
#[derive(Clone, Default)]
pub struct TunnelRoutes {
    pub connected: bool,
    pub domains: Vec<String>,
    pub cidrs: Vec<String>,
}

/// Client-side history of server instance nonces observed for the configured
/// server id, used to detect a *duplicate server*.
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

pub struct ProxyClient {
    config: ClientConfig,
    routes: Arc<Mutex<TunnelRoutes>>,
    /// Random per-process identity of this client, sent in every `Hello` so the
    /// server can tell a benign reconnect (same nonce) from two distinct client
    /// processes sharing a node id (different nonces → a duplicate-client bug).
    instance_nonce: u128,
    /// Observed server-nonce history for duplicate-server detection.
    nonce_tracker: Mutex<ServerNonceTracker>,
    /// Latches once a duplicate server has been observed; thereafter every
    /// `Hello` carries the advisory so the server can self-block.
    duplicate_server: AtomicBool,
}

impl ProxyClient {
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config,
            routes: Arc::new(Mutex::new(TunnelRoutes::default())),
            instance_nonce: rand::rng().random(),
            nonce_tracker: Mutex::new(ServerNonceTracker::default()),
            duplicate_server: AtomicBool::new(false),
        }
    }

    /// Record a server instance nonce observed in a `HelloResponse` and apply the
    /// reappearance rule. Latches [`Self::duplicate_server`] on a confirmed
    /// duplicate; a plain change (restart or first sight of a second instance) is
    /// only logged. Returns `true` only when this call *newly* latched the flag,
    /// so the caller can force an immediate reconnect to get the advisory out.
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
                            "Duplicate server id detected: server instance nonce {nonce} \
                             reappeared after a different one — two servers appear to share \
                             this identity. Advising the server to self-block."
                        );
                    }
                } else {
                    log::warn!(
                        "Server identity nonce changed ({nonce}) — a restart, or possibly \
                         a second server sharing this id; watching for a reappearance."
                    );
                    t.history.push(nonce);
                }
            }
            None => t.history.push(nonce), // first observation this process
        }
        t.last = Some(nonce);
        newly_flagged
    }

    /// Shared handle to the live tunnel set, for callers (the FFI) that want to
    /// display what is routed. Refreshed on every (re)connect.
    pub fn routes(&self) -> Arc<Mutex<TunnelRoutes>> {
        self.routes.clone()
    }

    /// Flip the connected flag without disturbing the last-known route set.
    fn set_connected(&self, connected: bool) {
        if let Ok(mut routes) = self.routes.lock() {
            routes.connected = connected;
        }
    }

    /// Bind the local SOCKS5 listener (and the optional HTTP listener) once, then
    /// connect to the server and serve them. Reconnect policy (matching ezvpn):
    /// the **first** connection must succeed — if it fails, exit immediately (a
    /// bad node id, wrong relay, or down server is not worth retrying blindly).
    /// Once connected at least once, transient drops are retried with exponential
    /// backoff, indefinitely (unless `--max-reconnect-attempts` caps it or
    /// `--no-auto-reconnect` is set). The listeners stay bound across reconnects
    /// so local apps queue rather than see connection-refused during the gap.
    pub async fn run(&self, endpoint: &Endpoint) -> ProxyResult<()> {
        let socks = TcpListener::bind(self.config.socks_listen).await?;
        let http = match self.config.http_listen {
            Some(addr) => Some(TcpListener::bind(addr).await?),
            None => None,
        };
        self.run_with_listeners(endpoint, socks, http).await
    }

    /// Serve on an already-bound SOCKS5 listener (see [`run`](Self::run) for the
    /// reconnect policy). Callers that need the actual bound address — e.g. the
    /// FFI binding to an ephemeral `127.0.0.1:0` and reporting the chosen port —
    /// bind the [`TcpListener`] themselves, read `local_addr()`, then hand it
    /// here. `run` is the thin convenience wrapper that binds `socks_listen`.
    /// This path never enables the HTTP front-end.
    pub async fn run_with_listener(
        &self,
        endpoint: &Endpoint,
        listener: TcpListener,
    ) -> ProxyResult<()> {
        self.run_with_listeners(endpoint, listener, None).await
    }

    /// Serve the SOCKS5 listener and, when present, the HTTP CONNECT listener,
    /// both multiplexed over the same reconnecting server connection.
    async fn run_with_listeners(
        &self,
        endpoint: &Endpoint,
        socks_listener: TcpListener,
        http_listener: Option<TcpListener>,
    ) -> ProxyResult<()> {
        log::info!(
            "SOCKS5 proxy listening on {} (TCP CONNECT only)",
            socks_listener.local_addr()?
        );
        if let Some(l) = &http_listener {
            log::info!(
                "HTTP proxy listening on {} (CONNECT tunneling + plain-HTTP forwarding)",
                l.local_addr()?
            );
        }

        // Shared state between the always-on accept loops and the connection
        // manager: the current live connection (None during a drop/backoff) and
        // the route policy (None until the first handshake learns it). Keeping the
        // accept loops independent of the connection is what lets off-list targets
        // keep connecting directly while the tunnel is down — only on-list targets
        // fail until it recovers. The policy starts None so the client fails closed
        // until it is known.
        let current: SharedConn = Arc::new(Mutex::new(None));
        let routed_set: SharedRoutedSet = Arc::new(Mutex::new(None));

        // The HTTP branch is inert (never resolves) when no HTTP listener is
        // bound, so the `select!` shape is the same either way.
        let http_accept = async {
            match &http_listener {
                Some(l) => accept_loop(l, &current, &routed_set, HttpProto).await,
                None => std::future::pending::<ProxyResult<()>>().await,
            }
        };

        // One task, N concurrent futures. When the manager returns (a fatal
        // first-connect failure or a clean stop) the accept loops are dropped with
        // it, so `flextunnel_stop`'s `task.abort()` tears everything down — no
        // orphaned accept task.
        tokio::select! {
            r = self.manage_connection(endpoint, &current, &routed_set) => r,
            r = accept_loop(&socks_listener, &current, &routed_set, Socks5Proto) => r,
            r = http_accept => r,
        }
    }

    /// Maintain the server connection: (re)establish + authenticate, publish the
    /// live connection and tunnel set for the accept loop, and reconnect with
    /// backoff on drops. Reconnect policy is unchanged: the **first** connection
    /// must succeed (fail fast); once connected, transient drops are retried.
    async fn manage_connection(
        &self,
        endpoint: &Endpoint,
        current: &SharedConn,
        routed_set_shared: &SharedRoutedSet,
    ) -> ProxyResult<()> {
        let mut ever_connected = false;
        let mut attempt: u32 = 0;
        loop {
            // Until (re)authenticated, nothing is being forwarded.
            self.set_connected(false);
            *current.lock().expect("connection lock") = None;

            // Establish (connect + auth). The handshake also learns the server's
            // tunnel set (drives split-tunneling) and returns the control-stream
            // halves kept open for heartbeats.
            let (connection, routed_set, ctrl_send, ctrl_recv) = match self.establish(endpoint).await
            {
                Ok(established) => {
                    ever_connected = true;
                    attempt = 0; // reset backoff on a successful connection
                    established
                }
                Err(e) => match self.handle_failure(e, ever_connected, &mut attempt) {
                    Ok(backoff) => {
                        tokio::time::sleep(backoff).await;
                        continue;
                    }
                    Err(fatal) => return Err(fatal),
                },
            };

            // Publish the live connection + route policy so the accept loop routes
            // against them; the policy is retained on the next drop (never reset to
            // None once known, so we only fail closed before the *first* connect).
            *routed_set_shared.lock().expect("routed-set lock") = Some(routed_set);
            *current.lock().expect("connection lock") = Some(connection.clone());

            // Keep the connection alive until it drops, then reconnect (or exit).
            let maintained = self.maintain(&connection, ctrl_send, ctrl_recv).await;
            // The connection is no longer live; clear the FFI-visible flag and the
            // shared handle so on-list targets fail cleanly during the gap.
            self.set_connected(false);
            *current.lock().expect("connection lock") = None;
            if let Err(e) = maintained {
                match self.handle_failure(e, ever_connected, &mut attempt) {
                    Ok(backoff) => {
                        tokio::time::sleep(backoff).await;
                        continue;
                    }
                    Err(fatal) => return Err(fatal),
                }
            } else {
                return Ok(());
            }
        }
    }

    /// Decide what to do with a connection error: `Ok(backoff)` to retry after
    /// the given delay, or `Err(e)` to give up.
    ///
    /// Gives up when: the first connection never succeeded (`!ever_connected` —
    /// fail fast), auto-reconnect is disabled, the error is permanent
    /// (auth/config), or an explicit attempt cap was reached. Otherwise retries.
    fn handle_failure(
        &self,
        e: ProxyError,
        ever_connected: bool,
        attempt: &mut u32,
    ) -> Result<Duration, ProxyError> {
        if !ever_connected || !self.config.auto_reconnect || !e.is_recoverable() {
            return Err(e);
        }
        *attempt += 1;
        if let Some(max) = self.config.max_reconnect_attempts
            && *attempt > max.get()
        {
            log::error!("Giving up after {} reconnect attempt(s): {e}", max.get());
            return Err(e);
        }
        let backoff = calculate_backoff(*attempt);
        log::warn!(
            "Connection lost ({e}); reconnecting in {:.1}s (attempt {})",
            backoff.as_secs_f64(),
            *attempt
        );
        Ok(backoff)
    }

    /// Connect to the server and complete the auth handshake, returning the
    /// connection, the routed set the server pushed, and the control-stream halves
    /// (kept open for heartbeats).
    async fn establish(
        &self,
        endpoint: &Endpoint,
    ) -> ProxyResult<(Connection, Arc<RoutedSet>, SendStream, RecvStream)> {
        let endpoint_addr = self.resolve_server_addr()?;
        let connection = endpoint
            .connect(endpoint_addr, crate::transport::ALPN)
            .await
            .map_err(|e| ProxyError::Signaling(format!("Failed to connect to server: {e}")))?;
        log::info!("Connected to server, authenticating...");
        let (routed_set, send, recv) = self.handshake(&connection).await?;
        log::info!("Authenticated.");
        Ok((connection, Arc::new(routed_set), send, recv))
    }

    /// Keep the connection alive: run the heartbeat and watch for the QUIC
    /// connection closing, whichever ends first. (Accepting local connections is
    /// handled independently by [`accept_loop`] so it survives a drop.)
    async fn maintain(
        &self,
        connection: &Connection,
        ctrl_send: SendStream,
        ctrl_recv: RecvStream,
    ) -> ProxyResult<()> {
        tokio::select! {
            r = client_heartbeat_loop(ctrl_send, ctrl_recv) => r,
            reason = connection.closed() => Err(ProxyError::ConnectionLost(reason.to_string())),
        }
    }

    /// Resolve the server's `EndpointAddr`, attaching relay hints if given.
    fn resolve_server_addr(&self) -> ProxyResult<EndpointAddr> {
        let server_id: EndpointId = self.config.server_node_id.parse().map_err(|e| {
            ProxyError::config_with_source(
                format!("Invalid server node ID: {}", self.config.server_node_id),
                e,
            )
        })?;
        log::info!("Connecting to flextunnel server: {server_id}");

        if self.config.relay_urls.is_empty() {
            return Ok(EndpointAddr::new(server_id));
        }
        let mut addr = EndpointAddr::new(server_id);
        for relay_url_str in &self.config.relay_urls {
            let relay_url: RelayUrl = relay_url_str.parse().map_err(|e| {
                ProxyError::config_with_source(format!("Invalid relay URL: {relay_url_str}"), e)
            })?;
            addr = addr.with_relay_url(relay_url);
        }
        log::info!("Using {} relay hint(s)", self.config.relay_urls.len());
        Ok(addr)
    }

    /// Perform the connection-level auth handshake on the first bi-stream,
    /// returning the routed set (the tunnel set) the server pushed plus the
    /// control-stream halves — the stream is **not** closed; it stays open as the
    /// heartbeat channel. The client uses the routed set to split-tunnel; it
    /// configures no list of its own (the server is the single source of truth).
    async fn handshake(
        &self,
        connection: &Connection,
    ) -> ProxyResult<(RoutedSet, SendStream, RecvStream)> {
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|e| ProxyError::Signaling(format!("Failed to open handshake stream: {e}")))?;

        let mut hello = Hello::new(self.config.auth_token.clone(), self.instance_nonce);
        hello.duplicate_server_observed = self.duplicate_server.load(Ordering::Relaxed);
        signaling::write_message(&mut send, &signaling::encode_hello(&hello)?).await?;
        send.flush().await?;

        let data = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            signaling::read_message(&mut recv, signaling::MAX_HANDSHAKE_SIZE),
        )
        .await
        .map_err(|_| {
            ProxyError::Signaling("timed out waiting for server handshake response".into())
        })??;
        let response = signaling::decode_hello_response(&data)?;

        // Record the server's instance nonce (drives duplicate-server detection)
        // before the accept/reject branch so a rejection still updates history.
        let newly_flagged_duplicate = self.observe_server_nonce(response.server_instance_nonce);

        if !response.accepted {
            let reason = response.reject_reason.unwrap_or_else(|| "unknown".to_string());
            return Err(ProxyError::AuthenticationFailed(reason));
        }

        // The `Hello` already sent on this handshake could not carry the advisory
        // (the duplicate was only detected from this very response). Drop the
        // connection with a recoverable error so we reconnect immediately and the
        // next `Hello` advises the server to self-block — rather than waiting for a
        // natural disconnect that may never come while this connection is healthy.
        if newly_flagged_duplicate {
            return Err(ProxyError::ConnectionLost(
                "duplicate server id detected; reconnecting to advise the server to self-block"
                    .into(),
            ));
        }

        // Build the tunnel set from the server's pushed list. The server
        // validated these rules at startup, so a parse failure here is not
        // expected; surface it as a signaling error rather than panicking.
        let routed_set = RoutedSet::new(&response.routed_domains, &response.routed_cidrs)
            .map_err(|e| ProxyError::Signaling(format!("server pushed an invalid routed set: {e}")))?;
        // The tunnel set is required. The server validates this at startup, but
        // guard here too so a misconfigured/old server surfaces clearly instead of
        // the client silently direct-connecting everything.
        if routed_set.is_empty() {
            return Err(ProxyError::Signaling(
                "server pushed an empty tunnel set (configure a routed set, or \"*\" + 0.0.0.0/0 for full tunnel)".into(),
            ));
        }
        log::info!(
            "Server tunnel set: {} domain rule(s), {} CIDR(s) — off-list targets connect directly",
            response.routed_domains.len(),
            response.routed_cidrs.len()
        );

        // Publish the live tunnel set so the FFI/app can show what's forwarded.
        if let Ok(mut routes) = self.routes.lock() {
            routes.connected = true;
            routes.domains = response.routed_domains.clone();
            routes.cidrs = response.routed_cidrs.clone();
        }
        Ok((routed_set, send, recv))
    }
}

/// Client-side heartbeat loop over the retained control stream: send a
/// `Heartbeat` every [`HEARTBEAT_INTERVAL`] and await its `HeartbeatAck` within
/// [`LIVENESS_WINDOW`]. A missing ack (or stream error) returns
/// [`ProxyError::ConnectionLost`] (recoverable), which drives the reconnect loop.
///
/// Shared with [`crate::proxy::agent`]: an agent also sends heartbeats over its
/// retained control stream, so it reuses this loop verbatim.
pub(crate) async fn client_heartbeat_loop(
    mut send: SendStream,
    mut recv: RecvStream,
) -> ProxyResult<()> {
    let mut seq: u64 = 0;
    loop {
        tokio::time::sleep(HEARTBEAT_INTERVAL).await;
        seq = seq.wrapping_add(1);
        signaling::write_message(
            &mut send,
            &signaling::encode_control(&ControlMsg::Heartbeat { seq })?,
        )
        .await?;
        send.flush().await?;

        let data = tokio::time::timeout(
            LIVENESS_WINDOW,
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
struct LocalRequest {
    target: Target,
    /// Bytes to write upstream before splicing: the rewritten request head of
    /// an HTTP plain-forward, whose reply is the origin's own response. `None`
    /// for pure tunnels (SOCKS5, HTTP CONNECT), which instead answer the local
    /// app with a success reply.
    upstream_preamble: Option<Vec<u8>>,
}

/// A local front-end protocol (SOCKS5 or HTTP). The protocols differ only in
/// how they parse a local request into a [`LocalRequest`] and how they answer
/// with a server reply code; everything after that — the route policy,
/// split-tunnel dial, tunnel open, and byte pipe — is shared (see
/// [`handle_local_conn`]).
///
/// Methods return `impl Future + Send` (not bare `async fn`) so the futures are
/// `Send`, which [`accept_loop`] needs to `tokio::spawn` a generic handler.
trait LocalProto: Copy + Send + Sync + 'static {
    /// Parse the local handshake into a [`LocalRequest`]. Any error the caller
    /// can't yet answer with a reply code (a bad request, an unsupported
    /// method) must be written to `tcp` here before returning `Err`, mirroring
    /// how [`socks5::read_connect_request`] writes its own error replies.
    fn read_request(&self, tcp: &mut TcpStream)
    -> impl Future<Output = Result<LocalRequest>> + Send;

    /// Answer the local app with the response corresponding to server reply
    /// code `rep` ([`signaling::REP_SUCCESS`] et al.).
    fn reply(&self, tcp: &mut TcpStream, rep: u8) -> impl Future<Output = io::Result<()>> + Send;
}

/// SOCKS5 front-end (RFC 1928): method negotiation + CONNECT parsing, 10-byte
/// reply frames.
#[derive(Clone, Copy)]
struct Socks5Proto;

impl LocalProto for Socks5Proto {
    async fn read_request(&self, tcp: &mut TcpStream) -> Result<LocalRequest> {
        socks5::negotiate_method(tcp).await?;
        Ok(LocalRequest {
            target: socks5::read_connect_request(tcp).await?,
            upstream_preamble: None,
        })
    }

    async fn reply(&self, tcp: &mut TcpStream, rep: u8) -> io::Result<()> {
        socks5::write_reply(tcp, rep).await
    }
}

/// HTTP proxy front-end: `CONNECT host:port` tunneling and absolute-URI
/// plain-HTTP forwarding, HTTP status-line replies.
#[derive(Clone, Copy)]
struct HttpProto;

impl LocalProto for HttpProto {
    async fn read_request(&self, tcp: &mut TcpStream) -> Result<LocalRequest> {
        Ok(match http::read_request(tcp).await? {
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

    async fn reply(&self, tcp: &mut TcpStream, rep: u8) -> io::Result<()> {
        http::write_reply(tcp, rep).await
    }
}

/// Whether an `accept()` error is transient — the listener itself is fine and
/// accepting will work again once conditions change — as opposed to a broken
/// listener that should end the loop (and with it the client).
///
/// Transient: fd exhaustion (EMFILE per-process / ENFILE system-wide; no
/// stable `io::ErrorKind` exists for these, so match the raw OS codes) and
/// per-connection races where the peer aborted between the kernel queuing the
/// connection and us accepting it.
fn is_transient_accept_error(e: &io::Error) -> bool {
    if matches!(
        e.kind(),
        io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::Interrupted
    ) {
        return true;
    }
    #[cfg(unix)]
    {
        matches!(e.raw_os_error(), Some(libc::EMFILE) | Some(libc::ENFILE))
    }
    #[cfg(windows)]
    {
        const WSAEMFILE: i32 = 10024;
        e.raw_os_error() == Some(WSAEMFILE)
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// Accept loop for a local front-end listener. Each accepted connection is
/// handled by [`handle_local_conn`] parameterized on `proto`. Shared verbatim by
/// the SOCKS5 and HTTP listeners. Transient accept errors (fd exhaustion,
/// peer-aborted races) are retried after [`ACCEPT_RETRY_DELAY`]; returns only on
/// a fatal listener error.
async fn accept_loop<P: LocalProto>(
    listener: &TcpListener,
    current: &SharedConn,
    routed_set_shared: &SharedRoutedSet,
    proto: P,
) -> ProxyResult<()> {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) if is_transient_accept_error(&e) => {
                log::warn!(
                    "Local proxy accept failed ({e}); retrying in {}ms",
                    ACCEPT_RETRY_DELAY.as_millis()
                );
                tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        log::debug!("proxy connection from {peer}");
        let current = current.clone();
        let routed_set_shared = routed_set_shared.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_local_conn(proto, tcp, current, routed_set_shared).await {
                log::debug!("proxy connection from {peer} ended: {e}");
            }
        });
    }
}

/// Handle one local proxy connection: parse the front-end request, then route by
/// the current route policy — refused with a general-failure reply until the
/// policy is known (fail closed), otherwise an on-list target is tunneled to the
/// server (or answered with a network-unreachable reply if the tunnel is down)
/// and an off-list target is dialed directly from this device.
async fn handle_local_conn<P: LocalProto>(
    proto: P,
    mut tcp: TcpStream,
    current: SharedConn,
    routed_set_shared: SharedRoutedSet,
) -> Result<()> {
    // Bound the local handshake so a peer that connects and sends nothing can't
    // pin this task and its socket indefinitely.
    let LocalRequest {
        target,
        upstream_preamble,
    } = tokio::time::timeout(LOCAL_HANDSHAKE_TIMEOUT, proto.read_request(&mut tcp))
        .await
        .map_err(|_| anyhow::anyhow!("timed out during local proxy handshake"))??;

    // Fail closed until the route policy is known: before the first handshake
    // learns the tunnel set we don't route anything, so no traffic leaks out
    // (directly or tunneled) before we know how it should be routed. Answer with a
    // general-failure reply rather than leaving the app hanging.
    let policy = { routed_set_shared.lock().expect("routed-set lock").clone() };
    let Some(routed_set) = policy else {
        log::debug!("Route policy not yet known; refusing: {target:?}");
        let _ = proto.reply(&mut tcp, signaling::REP_GENERAL_FAILURE).await;
        return Ok(());
    };

    // Split-tunnel: a target not in the tunnel set is dialed directly from this
    // device's own network (its DNS, its IP) — works even when the tunnel is down.
    if !routed_set.allows(&target) {
        log::debug!("Direct (off tunnel set): {target:?}");
        return direct_connect(proto, tcp, &target, upstream_preamble).await;
    }

    // On-list: needs a live tunnel. If the connection is down (a drop/backoff),
    // answer with a network-unreachable reply so the app shows a connection error
    // for this routed target instead of hanging on a dead stream.
    let conn = { current.lock().expect("connection lock").clone() };
    let Some(conn) = conn else {
        log::debug!("Tunnel down; on-list target unreachable: {target:?}");
        let _ = proto.reply(&mut tcp, signaling::REP_NET_UNREACHABLE).await;
        return Ok(());
    };
    log::debug!("Tunneling: {target:?}");

    // Open the tunnel stream and read the server's reply. If any step fails the
    // local app hasn't been answered yet, so send a general-failure reply
    // (best effort) instead of dropping the connection with no response.
    let opened = tokio::time::timeout(TUNNEL_OPEN_TIMEOUT, open_tunnel(&conn, &target))
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

    let mut iroh = tokio::io::join(recv, send);
    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut iroh).await;
    Ok(())
}

/// Connect to `target` directly from this device (bypassing the tunnel) and pipe
/// bytes, answering the local app's request with the matching reply code via
/// `proto` (or, for an HTTP forward, writing its rewritten head upstream instead
/// of a success reply). Used for off-routed-set targets in split-tunnel mode.
/// The dial is bounded by the same deadline as opening a tunnel so a slow target
/// can't pin the task.
async fn direct_connect<P: LocalProto>(
    proto: P,
    mut tcp: TcpStream,
    target: &signaling::Target,
    upstream_preamble: Option<Vec<u8>>,
) -> Result<()> {
    let dialed = tokio::time::timeout(TUNNEL_OPEN_TIMEOUT, dial::dial_target(target)).await;
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

/// Open a bi-stream to the server, send the CONNECT request, and read back the
/// reply code. Returns the stream halves and the reply so the caller can relay
/// the reply to the local app and then pipe bytes.
async fn open_tunnel(
    conn: &Connection,
    target: &signaling::Target,
) -> Result<(SendStream, RecvStream, u8)> {
    let (mut send, mut recv) = conn.open_bi().await?;
    signaling::write_request(&mut send, target).await?;
    send.flush().await?;
    let rep = signaling::read_reply(&mut recv).await?;
    Ok((send, recv, rep))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    fn test_client() -> ProxyClient {
        ProxyClient::new(ClientConfig {
            server_node_id: "server".to_string(),
            auth_token: "token".to_string(),
            socks_listen: "127.0.0.1:0".parse().unwrap(),
            http_listen: None,
            relay_urls: Vec::new(),
            auto_reconnect: true,
            max_reconnect_attempts: None,
        })
    }

    /// fd exhaustion and peer-aborted races must be retried, not kill the
    /// client; a genuinely broken listener (e.g. bad fd) must still be fatal.
    #[cfg(unix)]
    #[test]
    fn accept_error_transience_classification() {
        for code in [libc::EMFILE, libc::ENFILE, libc::ECONNABORTED, libc::EINTR] {
            assert!(
                is_transient_accept_error(&io::Error::from_raw_os_error(code)),
                "os error {code} should be transient"
            );
        }
        assert!(!is_transient_accept_error(&io::Error::from_raw_os_error(
            libc::EBADF
        )));
        assert!(!is_transient_accept_error(&io::Error::from_raw_os_error(
            libc::EINVAL
        )));
    }

    #[test]
    fn restart_sequence_not_flagged_as_duplicate() {
        let c = test_client();
        // A steady server, then a restart to fresh nonces (never reappearing).
        // No observation should ever newly-flag a duplicate.
        for n in [10u128, 10, 20, 30, 40] {
            assert!(!c.observe_server_nonce(n));
        }
        assert!(!c.duplicate_server.load(Ordering::Relaxed));
    }

    #[test]
    fn reappearing_nonce_flags_duplicate() {
        let c = test_client();
        // A, B, then A again (flip-flop) → two concurrent servers share the id.
        assert!(!c.observe_server_nonce(1));
        assert!(!c.observe_server_nonce(2));
        assert!(!c.duplicate_server.load(Ordering::Relaxed));
        // The reappearance newly latches the flag → caller must reconnect.
        assert!(c.observe_server_nonce(1));
        assert!(c.duplicate_server.load(Ordering::Relaxed));
        // Already latched: a further reappearance is not a *new* flag, so it must
        // not force another reconnect abort.
        assert!(!c.observe_server_nonce(2));
    }

    /// End-to-end plain-HTTP forwarding through the split-tunnel *direct* path:
    /// the HTTP front-end rewrites the absolute-URI request to origin-form, the
    /// off-list target is dialed directly, the rewritten head is written
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

        // The proxy: one accepted socket handled with a policy that leaves
        // 127.0.0.1 off-list, so the request takes the direct path.
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let routed = RoutedSet::new(
            &["nothing.internal".to_string()],
            &["10.0.0.0/8".to_string()],
        )
        .unwrap();
        let current: SharedConn = Arc::new(Mutex::new(None));
        let policy: SharedRoutedSet = Arc::new(Mutex::new(Some(Arc::new(routed))));
        tokio::spawn(async move {
            let (tcp, _) = proxy.accept().await.unwrap();
            handle_local_conn(HttpProto, tcp, current, policy).await.unwrap();
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
}
