//! flextunnel server: accepts authenticated iroh connections and, per SOCKS5
//! bi-stream, resolves DNS and connects to the target from its own network,
//! then pipes bytes. Runs entirely in userspace — no root, no TUN device.

use crate::blocklist::{self, BlockList};
use crate::error::{ProxyError, ProxyResult};
use crate::proxy::signaling::{self, ControlMsg, HelloResponse, StreamRequest, Target};
use crate::proxy::status_page::{self, ServerStatusTemplate};
use crate::proxy::{dial, reserved, DnsForwarder, RoutedSet};
use crate::transport::LIVENESS_WINDOW;
use iroh::endpoint::{Connection, Incoming, RecvStream, SendStream};
use iroh::{Endpoint, EndpointId};
use rand::RngExt;
use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::sync::{Notify, Semaphore};

/// Deadline for receiving the client's auth handshake once a connection opens.
/// Heartbeats only start after the handshake, so without this a peer that never
/// opens the handshake stream would hold the task until the QUIC idle timeout,
/// or indefinitely if it keeps the connection alive itself.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Cap on concurrent connection handlers. A flood of inbound connections would
/// otherwise spawn unbounded handler tasks; once this many are live the accept
/// loop waits for a slot (backpressure) instead of spawning more. Per-connection
/// SOCKS5 streams are separately bounded by the QUIC transport's bidi-stream
/// limit, so this single cap is enough to bound overall task growth.
const MAX_CONCURRENT_CONNECTIONS: usize = 1024;

/// QUIC close code used when the server tears a connection down for a
/// duplicate-id conflict (distinct from the auth-failure code `1`).
const CLOSE_DUPLICATE: u32 = 2;

/// Monotonic per-connection sequence, assigned to each accepted connection so
/// the registry can key entries by connection instance (not just by node id or
/// nonce). This lets a benign same-process reconnect overlap keep two distinct
/// registry entries whose RAII guards clean up independently.
static NEXT_CONN_SEQ: AtomicU64 = AtomicU64::new(0);

/// One live connection tracked in the [`ProxyServer`] registry.
struct ConnEntry {
    /// The client process's instance nonce (from its `Hello`).
    nonce: u128,
    /// Last time a heartbeat refreshed this entry — its liveness.
    last_seen: Instant,
    /// Handle to the connection, so a confirmed duplicate can be torn down.
    connection: Connection,
    /// The authorized key (`ed25519-pub:...`) the client authenticated with;
    /// `None` for a quick-mode client (no keypair). Lets an embedding app show
    /// which of its authorized clients are connected.
    client_key: Option<String>,
}

/// `EndpointId → (conn_seq → entry)`. Two live entries under one node id with
/// *different* nonces are a confirmed duplicate client.
type Registry = HashMap<EndpointId, HashMap<u64, ConnEntry>>;

/// RAII cleanup for a registered connection: removes its registry entry on
/// *every* handler exit path (normal, error, panic-abort), so a dropped
/// connection never leaves a stale entry that would falsely look like a live
/// duplicate.
struct ConnGuard {
    registry: Arc<Mutex<Registry>>,
    remote_id: EndpointId,
    conn_seq: u64,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        if let Ok(mut reg) = self.registry.lock()
            && let Some(per) = reg.get_mut(&self.remote_id)
        {
            per.remove(&self.conn_seq);
            if per.is_empty() {
                reg.remove(&self.remote_id);
            }
        }
    }
}

pub struct ProxyServer {
    /// This server's own iroh `EndpointId` (persistent identity), used for the
    /// duplicate-server self-block record.
    own_id: EndpointId,
    /// Random per-process nonce, sent in every `HelloResponse`. Stable for this
    /// process; a client sees it change (and reappear) only across distinct
    /// server instances that share this identity — how a duplicate server is
    /// detected client-side.
    server_instance_nonce: u128,
    /// Authorized **client** public keys (`ed25519-pub:`), loaded from the
    /// server's authorized-keys file at startup.
    authorized_keys: crate::auth::AuthorizedKeys,
    /// Host aliases rewritten before connecting. Keys are lowercased and may be an
    /// exact host or a `*.suffix` wildcard; see [`resolve_alias`]/[`apply_alias`].
    host_aliases: HashMap<String, String>,
    /// Destinations routed through the tunnel, enforced here as a whitelist: a
    /// request for a target not on the set is rejected (the client routes by
    /// its own lists; this is the server's say — see [`RoutedSet`]).
    routed_set: RoutedSet,
    /// Raw routed-set rules, shown verbatim on the status page.
    routed_domains: Vec<String>,
    routed_cidrs: Vec<String>,
    /// Conditional DNS forwarding (split-DNS): names under a configured suffix
    /// are resolved via that suffix's upstream server instead of the system
    /// resolver. `None` when no `[dns_forwards]` are configured. See
    /// [`DnsForwarder`].
    dns_forwarder: Option<DnsForwarder>,
    /// Live-connection registry for duplicate-client detection.
    registry: Arc<Mutex<Registry>>,
    /// Persistent duplicate-id blocklist (shared, synced to disk on mutation).
    blocklist: Arc<Mutex<BlockList>>,
    /// Tripped when the server must stop itself (duplicate-server self-block);
    /// wakes the accept loop in [`run`](Self::run).
    shutdown: Arc<Notify>,
    /// Notified once on the first successful client connection (quick-mode idle
    /// timer cancellation); `None` for a normal server.
    first_client: Option<Arc<Notify>>,
}

/// Inputs for [`ProxyServer::new`], grouped into a struct so the many
/// same-typed collections can't be swapped positionally.
pub struct ProxyServerParams {
    pub own_id: EndpointId,
    pub authorized_keys: crate::auth::AuthorizedKeys,
    pub host_aliases: HashMap<String, String>,
    pub routed_set: RoutedSet,
    pub routed_domains: Vec<String>,
    pub routed_cidrs: Vec<String>,
    pub dns_forwarder: Option<DnsForwarder>,
    pub blocklist: BlockList,
    /// Fired once when the first client successfully connects. `server start
    /// --quick` uses it to cancel its "exit if idle" grace timer; `None` for a
    /// normal server.
    pub first_client: Option<Arc<Notify>>,
}

impl ProxyServer {
    pub fn new(params: ProxyServerParams) -> Arc<Self> {
        Arc::new(Self {
            own_id: params.own_id,
            server_instance_nonce: rand::rng().random(),
            authorized_keys: params.authorized_keys,
            host_aliases: params.host_aliases,
            routed_set: params.routed_set,
            routed_domains: params.routed_domains,
            routed_cidrs: params.routed_cidrs,
            dns_forwarder: params.dns_forwarder,
            registry: Arc::new(Mutex::new(Registry::new())),
            blocklist: Arc::new(Mutex::new(params.blocklist)),
            shutdown: Arc::new(Notify::new()),
            first_client: params.first_client,
        })
    }

    /// The configured host aliases as `(alias, target)` pairs, sorted for
    /// stable output. Shown on the status page.
    fn sorted_host_aliases(&self) -> Vec<(String, String)> {
        let mut host_aliases: Vec<(String, String)> = self
            .host_aliases
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        host_aliases.sort();
        host_aliases
    }

    /// The configured conditional DNS forwards as `(suffix, servers)` pairs,
    /// sorted by suffix. Empty when no `[dns_forwards]` are configured. Shown on
    /// the status page.
    fn dns_forwards(&self) -> Vec<(String, Vec<String>)> {
        self.dns_forwarder
            .as_ref()
            .map(DnsForwarder::forwards)
            .unwrap_or_default()
    }

    /// The distinct authorized keys (`ed25519-pub:...`) of the clients
    /// connected right now, sorted. A passive read of the duplicate-detection
    /// registry, which holds exactly the authenticated live connections.
    pub fn connected_client_keys(&self) -> Vec<String> {
        let reg = self.registry.lock().expect("registry lock");
        let keys: std::collections::BTreeSet<&str> = reg
            .values()
            .flat_map(HashMap::values)
            .filter_map(|e| e.client_key.as_deref())
            .collect();
        keys.into_iter().map(str::to_owned).collect()
    }

    /// Snapshot the live routing config into the status-page template. Secrets
    /// are never included; the blocklist is exposed as counts only.
    fn build_status_template(&self) -> ServerStatusTemplate {
        let bl = self.blocklist.lock().expect("blocklist lock");
        ServerStatusTemplate {
            version: env!("CARGO_PKG_VERSION"),
            node_id: self.own_id.to_string(),
            routed_domains: self.routed_domains.clone(),
            routed_cidrs: self.routed_cidrs.clone(),
            host_aliases: self.sorted_host_aliases(),
            dns_forwards: self.dns_forwards(),
            blocklist_path: bl.path().display().to_string(),
            blocked_client_count: bl.blocked_client_count(),
            conflicted_server_count: bl.conflicted_server_count(),
        }
    }

    /// Accept connections until the endpoint closes or the server self-blocks.
    pub async fn run(self: Arc<Self>, endpoint: &Endpoint) -> ProxyResult<()> {
        let conn_limit = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
        loop {
            // Acquire a slot before accepting so a flood of connections applies
            // backpressure here rather than spawning unbounded handlers.
            // `acquire_owned` only errors if the semaphore is closed, which never
            // happens (it lives for this loop).
            let permit = conn_limit
                .clone()
                .acquire_owned()
                .await
                .expect("connection semaphore is never closed");
            tokio::select! {
                incoming = endpoint.accept() => match incoming {
                    Some(incoming) => {
                        let server = self.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(e) = server.handle_connection(incoming).await {
                                log::debug!("Connection ended: {e}");
                            }
                        });
                    }
                    None => {
                        log::info!("Endpoint closed, shutting down");
                        return Ok(());
                    }
                },
                _ = self.shutdown.notified() => {
                    log::error!(
                        "Stopping: this server id was detected as a duplicate. \
                         Its id has been recorded in the blocklist and future starts \
                         with it will be refused until the conflict is resolved."
                    );
                    // Report a failure exit, not a clean shutdown, so a
                    // supervisor/monitor can see this was a fault (duplicate id),
                    // not a graceful stop.
                    return Err(ProxyError::DuplicateServerId(
                        "server id detected as a duplicate; recorded in the blocklist and stopping"
                            .into(),
                    ));
                }
            }
        }
    }

    /// Record this server's own id as conflicted (duplicate server detected),
    /// persist the blocklist, and trip the shutdown so [`run`](Self::run) exits.
    fn self_block(&self, reason: &str) {
        {
            let mut bl = self.blocklist.lock().expect("blocklist lock");
            if bl.add_conflicted_server(&self.own_id.to_string(), reason)
                && let Err(e) = persist_blocklist(&bl)
            {
                // The durable record is what makes the startup guard refuse a
                // restart; without it a restart of this id will NOT be
                // auto-refused, so spell out the manual action.
                log::error!(
                    "Detected a duplicate server id but could NOT persist the self-block record \
                     to {}: {e}. A restart of this server id will not be auto-refused — stop the \
                     duplicate server manually.",
                    bl.path().display()
                );
            }
        }
        log::error!("Duplicate server id detected: {reason}");
        self.shutdown.notify_one();
    }

    /// Record a confirmed duplicate client id and persist the blocklist.
    fn block_client(&self, id: &EndpointId, reason: &str) {
        let mut bl = self.blocklist.lock().expect("blocklist lock");
        if bl.add_blocked_client(&id.to_string(), reason)
            && let Err(e) = persist_blocklist(&bl)
        {
            // Runtime rejection already works from the in-memory block; the disk
            // write is an audit record (ephemeral client ids never recur), so a
            // failure here is non-fatal — just surface it.
            log::error!(
                "Blocked duplicate client {id} in memory but could not persist the audit record \
                 to {}: {e}",
                bl.path().display()
            );
        }
    }

    /// Whether a client node id is currently blocked (in-memory check).
    fn is_client_blocked(&self, id: &EndpointId) -> bool {
        self.blocklist
            .lock()
            .expect("blocklist lock")
            .is_client_blocked(&id.to_string())
    }

    /// Atomically register a live connection, or report a confirmed duplicate.
    ///
    /// Returns `Ok(())` after inserting the entry, or `Err(conns)` with the
    /// other live connections for this node id whose nonce differs — a confirmed
    /// duplicate client. The whole check-and-insert runs under one lock so two
    /// simultaneous first-connections can't both slip through.
    fn try_register(
        &self,
        remote_id: EndpointId,
        conn_seq: u64,
        nonce: u128,
        connection: Connection,
        client_key: Option<String>,
    ) -> Result<(), Vec<Connection>> {
        let mut reg = self.registry.lock().expect("registry lock");
        let now = Instant::now();
        let per = reg.entry(remote_id).or_default();
        let dups: Vec<Connection> = per
            .values()
            .filter(|e| e.nonce != nonce && now.duration_since(e.last_seen) < LIVENESS_WINDOW)
            .map(|e| e.connection.clone())
            .collect();
        if !dups.is_empty() {
            return Err(dups);
        }
        per.insert(
            conn_seq,
            ConnEntry {
                nonce,
                last_seen: now,
                connection,
                client_key,
            },
        );
        Ok(())
    }

    /// Verify a regular client's public-key credential: the claimed endpoint
    /// id must equal the connection's TLS-authenticated `remote_id`, the
    /// signature must verify under the presented public key, and the key must
    /// be on the authorized-keys set. Failures are logged (with the reason)
    /// but the wire rejection stays generic.
    fn verify_client_auth(
        &self,
        auth: &signaling::ClientAuthPayload,
        remote_id: &EndpointId,
    ) -> bool {
        let claimed = match auth.endpoint_id.parse::<EndpointId>() {
            Ok(claimed) => claimed,
            Err(e) => {
                log::warn!("Client {remote_id} sent an unparseable claimed endpoint id: {e}");
                return false;
            }
        };
        if claimed != *remote_id {
            log::warn!(
                "Client {remote_id} claimed a different endpoint id ({claimed}) in its \
                 auth payload"
            );
            return false;
        }
        let public = match auth.public_key.parse::<flexaccess_keys::PublicKey>() {
            Ok(public) => public,
            Err(e) => {
                log::warn!("Client {remote_id} sent an invalid public key: {e}");
                return false;
            }
        };
        if !self.authorized_keys.contains(&public) {
            log::warn!(
                "Client {remote_id} presented a key that is not on the authorized-keys \
                 file: {}",
                auth.public_key
            );
            return false;
        }
        if !crate::auth::verify_endpoint_id_signature(&public, remote_id, &auth.signature) {
            log::warn!("Client {remote_id} sent an invalid auth signature");
            return false;
        }
        true
    }

    /// Authenticate a connection, then serve its multiplexed SOCKS5 streams and
    /// its heartbeat control stream.
    async fn handle_connection(self: Arc<Self>, incoming: Incoming) -> ProxyResult<()> {
        let connection = incoming
            .await
            .map_err(|e| ProxyError::Signaling(format!("Failed to accept connection: {e}")))?;
        let remote_id = connection.remote_id();
        let conn_seq = NEXT_CONN_SEQ.fetch_add(1, Ordering::Relaxed);
        log::info!("New connection from {remote_id}");

        // Log the selected path (relay/direct) and any later switch, for the
        // lifetime of this connection. Guard is dropped when `handle_connection`
        // returns.
        let _path_watcher = crate::transport::paths::watch_connection_paths(&connection);

        // Control stream: read the handshake. Kept open afterwards for
        // heartbeats, so the send/recv halves flow through to the heartbeat
        // loop. Bounded so a peer that opens the connection but never sends the
        // handshake can't hang us.
        let (mut send, recv, data) = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            let (send, mut recv) = connection.accept_bi().await.map_err(|e| {
                ProxyError::Signaling(format!("Failed to accept handshake stream: {e}"))
            })?;
            let data = signaling::read_message(&mut recv, signaling::MAX_HANDSHAKE_SIZE).await?;
            Ok::<(SendStream, RecvStream, Vec<u8>), ProxyError>((send, recv, data))
        })
        .await
        .map_err(|_| ProxyError::Signaling("timed out waiting for client handshake".into()))??;

        let hello = signaling::decode_hello(&data)?;

        // Authenticate first: only a validated, non-blocklisted peer may influence
        // server behavior — including the duplicate-server self-block below. A
        // quick-mode client (QUICK_ALPN) is already authenticated: the endpoint's
        // `AllowlistHook` checked its TLS-authenticated id against the quick
        // allowlist at the handshake, so a non-allowlisted one never gets here.
        // For a keypair client the ALPN is not a credential, so without the
        // signature gate an unauthenticated peer could trip self-block + shutdown.
        let auth_ok = connection.alpn() == crate::transport::QUICK_ALPN
            || hello
                .auth
                .as_ref()
                .is_some_and(|auth| self.verify_client_auth(auth, &remote_id));
        let blocked = self.is_client_blocked(&remote_id);
        if !auth_ok || blocked {
            let reason = if blocked {
                log::warn!("Rejecting {remote_id}: node id is blocklisted (duplicate id)");
                "node id is blocklisted (duplicate id previously detected)"
            } else {
                log::warn!("Rejecting {remote_id}: public-key authentication failed");
                "public-key authentication failed"
            };
            let resp = HelloResponse::rejected(self.server_instance_nonce, reason);
            signaling::write_message(&mut send, &signaling::encode_hello_response(&resp)?).await?;
            let _ = send.finish();
            // Give the client a brief moment to read the rejection response, then
            // close gracefully with the reason (an abrupt drop would surface on
            // the client as a generic "connection lost"). Bounded so a non-reading
            // client can never stall this path.
            tokio::time::sleep(Duration::from_millis(200)).await;
            connection.close(1u32.into(), b"authentication rejected");
            return Err(ProxyError::AuthenticationFailed(format!(
                "client {remote_id} rejected: {reason}"
            )));
        }

        // Duplicate-server advisory (only reachable once authenticated): a trusted
        // client observed a pattern indicating another server shares this
        // identity. It is an observation, not a command — the server decides, and
        // self-blocks. Honors "at least one active client with the updated protocol".
        if hello.duplicate_server_observed {
            let reason = format!("client {remote_id} reported a duplicate-server pattern");
            self.self_block(&reason);
            let resp = HelloResponse::rejected(
                self.server_instance_nonce,
                "server is stopping: duplicate server id detected",
            );
            let _ = signaling::write_message(&mut send, &signaling::encode_hello_response(&resp)?)
                .await;
            let _ = send.finish();
            tokio::time::sleep(Duration::from_millis(200)).await;
            connection.close(CLOSE_DUPLICATE.into(), b"duplicate server id");
            return Ok(());
        }

        // Duplicate-client detection: register this connection, or find a
        // concurrently-live connection for the same node id with a *different*
        // instance nonce — a confirmed duplicate (a benign same-process reconnect
        // reuses the same nonce and is not flagged).
        // Only a keypair client's key was verified above; a quick-mode client
        // got in on its ALPN, so whatever key it sent is unchecked.
        let client_key = hello
            .auth
            .as_ref()
            .filter(|_| connection.alpn() != crate::transport::QUICK_ALPN)
            .and_then(|auth| auth.public_key.parse::<flexaccess_keys::PublicKey>().ok())
            .map(|public| public.to_token());
        let _guard = match self.try_register(
            remote_id,
            conn_seq,
            hello.client_instance_nonce,
            connection.clone(),
            client_key,
        ) {
            Ok(()) => ConnGuard {
                registry: self.registry.clone(),
                remote_id,
                conn_seq,
            },
            Err(dups) => {
                log::warn!(
                    "Duplicate client id {remote_id} ({} other live connection(s)); blocklisting",
                    dups.len()
                );
                self.block_client(&remote_id, "duplicate client id (concurrent live connections)");
                // Tear down the other live connections sharing this id, then
                // reject and close this one.
                for c in dups {
                    c.close(CLOSE_DUPLICATE.into(), b"duplicate client id");
                }
                let resp = HelloResponse::rejected(
                    self.server_instance_nonce,
                    "duplicate client id detected",
                );
                let _ = signaling::write_message(
                    &mut send,
                    &signaling::encode_hello_response(&resp)?,
                )
                .await;
                let _ = send.finish();
                tokio::time::sleep(Duration::from_millis(200)).await;
                connection.close(CLOSE_DUPLICATE.into(), b"duplicate client id");
                return Err(ProxyError::AuthenticationFailed(format!(
                    "duplicate client id {remote_id}"
                )));
            }
        };

        // Accept, with our server nonce. The control stream is NOT finished —
        // it stays open for heartbeats.
        let resp = HelloResponse::accepted(self.server_instance_nonce);
        signaling::write_message(&mut send, &signaling::encode_hello_response(&resp)?).await?;
        send.flush().await?;
        log::info!("Client {remote_id} authenticated");

        // Cancel the quick-mode idle-exit timer on the first client to connect
        // (harmless no-op for a normal server; `notify_one` is idempotent).
        if let Some(notify) = &self.first_client {
            notify.notify_one();
        }

        // Serve SOCKS5 streams and the heartbeat concurrently until either ends
        // (connection closed, or heartbeat liveness lost). `_guard` cleans the
        // registry on return via Drop.
        let socks = self.serve_socks(&connection, remote_id);
        let heartbeat =
            server_heartbeat_loop(send, recv, self.registry.clone(), remote_id, conn_seq);
        tokio::select! {
            r = socks => r,
            r = heartbeat => r,
        }
    }

    /// Accept and dispatch SOCKS5 bi-streams until the connection closes.
    async fn serve_socks(
        self: &Arc<Self>,
        connection: &Connection,
        remote_id: EndpointId,
    ) -> ProxyResult<()> {
        loop {
            match connection.accept_bi().await {
                Ok((send, recv)) => {
                    let server = Arc::clone(self);
                    tokio::spawn(async move {
                        if let Err(e) = handle_socks_stream(send, recv, &server).await {
                            log::debug!("SOCKS5 stream ended: {e}");
                        }
                    });
                }
                Err(e) => {
                    log::info!("Connection from {remote_id} closed: {e}");
                    return Ok(());
                }
            }
        }
    }
}

/// Server-side heartbeat loop over the retained control stream: reply
/// `HeartbeatAck` to each `Heartbeat` and refresh the liveness of the
/// connection's entry (`remote_id`, `conn_seq`) in the duplicate-detection
/// registry. A heartbeat gap beyond [`LIVENESS_WINDOW`] (or a stream error)
/// ends the loop, which tears the connection handler down.
async fn server_heartbeat_loop(
    mut send: SendStream,
    mut recv: RecvStream,
    registry: Arc<Mutex<Registry>>,
    remote_id: EndpointId,
    conn_seq: u64,
) -> ProxyResult<()> {
    loop {
        let data = match tokio::time::timeout(
            LIVENESS_WINDOW,
            signaling::read_message(&mut recv, signaling::MAX_CONTROL_MSG_SIZE),
        )
        .await
        {
            Ok(Ok(data)) => data,
            Ok(Err(e)) => {
                return Err(ProxyError::ConnectionLost(format!(
                    "control stream closed: {e}"
                )));
            }
            Err(_) => {
                return Err(ProxyError::ConnectionLost(
                    "heartbeat liveness window elapsed".into(),
                ));
            }
        };
        match signaling::decode_control(&data)? {
            ControlMsg::Heartbeat { seq } => {
                if let Ok(mut reg) = registry.lock()
                    && let Some(entry) = reg.get_mut(&remote_id).and_then(|p| p.get_mut(&conn_seq))
                {
                    entry.last_seen = Instant::now();
                }
                let ack = ControlMsg::HeartbeatAck { seq };
                signaling::write_message(&mut send, &signaling::encode_control(&ack)?).await?;
                send.flush().await?;
            }
            // A client only ever sends heartbeats; the server is the sole sender
            // of acks. Receiving one means a broken/mismatched peer — reject it as
            // a protocol error so it can't hold the connection open (resetting the
            // read timeout) without refreshing registry liveness.
            other @ ControlMsg::HeartbeatAck { .. } => {
                return Err(ProxyError::ConnectionLost(format!(
                    "unexpected control message from client: {other:?}"
                )));
            }
        }
    }
}

/// Serialize + atomically persist the blocklist, returning any failure so the
/// caller can react with the right consequence (in-memory state is already
/// updated regardless). Call this **while holding the blocklist lock** so writes
/// are serialized within the process (no reordering or lost updates between
/// concurrent detections); `write_atomic` additionally uses a unique temp file
/// so it is safe against a second process writing the same path.
fn persist_blocklist(bl: &BlockList) -> io::Result<()> {
    let json = bl.to_json()?;
    blocklist::write_atomic(bl.path(), &json)
}

/// Rewrite a requested target through the server's host-alias map.
///
/// Only domain targets are aliased (literal IPs are already concrete). A domain
/// whose lowercased name matches an alias key is replaced by the alias value
/// (an IP or another hostname on the server's network), keeping the requested
/// port; the value is then resolved + connected like any other domain.
fn apply_alias(target: Target, aliases: &HashMap<String, String>) -> Target {
    if let Target::Domain(host, port) = &target
        && let Some(mapped) = resolve_alias(aliases, host)
    {
        log::debug!("Aliasing host {host} -> {mapped}");
        return Target::Domain(mapped.to_string(), *port);
    }
    target
}

/// Resolve a requested `host` against the `[host_aliases]` map, whose keys are
/// exact lowercased hostnames or `*.suffix` wildcards (subdomains only — the
/// bare apex is excluded, matching the routed-set `*.` semantics). An exact key
/// always wins over any wildcard; among competing wildcards the most specific
/// (longest suffix) wins. Returns the matched value (a rewrite target). Keys
/// are validated at config resolution, so a bare `*` and malformed patterns
/// never reach here.
fn resolve_alias<'a>(map: &'a HashMap<String, String>, host: &str) -> Option<&'a str> {
    // The same name the routed set just matched: without the DNS root dot.
    let host = crate::proxy::routed_set::routing_key(host).to_ascii_lowercase();
    if let Some(value) = map.get(&host) {
        return Some(value.as_str());
    }
    // No exact hit: fall back to the most specific `*.suffix` wildcard. A key
    // `*.web.internal` matches `foo.web.internal` (and deeper) but not the apex
    // `web.internal`, and not a sibling like `evil-web.internal`.
    map.iter()
        .filter_map(|(key, value)| {
            let suffix = key.strip_prefix("*.")?;
            host.ends_with(&format!(".{suffix}"))
                .then_some((suffix.len(), value.as_str()))
        })
        .max_by_key(|(len, _)| *len)
        .map(|(_, value)| value)
}

/// Handle one stream from a client: read the request, then serve it — the
/// server's own loopback or status page, or, for everything else, resolve +
/// connect from the server's own network and pipe bytes.
async fn handle_socks_stream(
    send: SendStream,
    mut recv: RecvStream,
    server: &Arc<ProxyServer>,
) -> io::Result<()> {
    let requested = match signaling::read_request(&mut recv).await? {
        // An address in domain form is that address, as the routed set reads
        // it: from here on it is an IP, past the aliases and the resolver.
        StreamRequest::Connect(target) => target.into_numeric(),
        // A destination's own name on the client side. Dialed exactly like
        // `localhost` (dual-stack), outside the routed-set whitelist and host
        // aliases: no operator config is needed to reach the machine the
        // server runs on.
        StreamRequest::Loopback(port) => {
            let target = Target::Domain("localhost".to_string(), port);
            log::debug!("Loopback request -> {target:?}");
            return dial::connect_and_pipe(send, recv, &target, server.dns_forwarder.as_ref())
                .await;
        }
        StreamRequest::Status => return serve_status(send, recv, server).await,
    };

    // The reserved `flextunnel.internal` namespace belongs to the client, which
    // answers it locally and never sends it. Refuse it here before the routed
    // set, so no `routed_domains = ["*"]` can capture it and hand a name
    // flextunnel owns to the server's resolver.
    if let Target::Domain(host, _) = &requested
        && reserved::is_reserved_host(host)
    {
        log::warn!("Tunnel request for reserved name {host} rejected");
        return reject_not_allowed(send).await;
    }

    // Enforce the routed set as a whitelist on the requested target (before
    // aliasing). The client routes by its own configured lists, which
    // this server never sees, so a request for anything off-list means the two
    // sides disagree (or an untrusted client). Reject with the SOCKS5 "not
    // allowed by ruleset" code.
    if !server.routed_set.allows(&requested) {
        log::warn!("Tunnel request rejected by routed-set whitelist");
        log::debug!("Rejected {requested:?}: not in routed-set whitelist");
        return reject_not_allowed(send).await;
    }

    let target = apply_alias(requested, &server.host_aliases);
    log::debug!("Stream target: {target:?}");
    dial::connect_and_pipe(send, recv, &target, server.dns_forwarder.as_ref()).await
}

/// Answer a stream with "connection not allowed by ruleset".
async fn reject_not_allowed(mut send: SendStream) -> io::Result<()> {
    signaling::write_reply(&mut send, signaling::REP_NOT_ALLOWED).await?;
    send.flush().await
}

/// Serve the status page: the success reply byte, then an HTTP response to the
/// HTTP request the client wrote after its [`StreamRequest::Status`] header
/// (its path and `Accept` pick HTML, text or JSON).
async fn serve_status(
    mut send: SendStream,
    mut recv: RecvStream,
    server: &Arc<ProxyServer>,
) -> io::Result<()> {
    log::debug!("Serving the server status page");
    status_page::write_tunnel_success(&mut send).await?;
    let head = status_page::read_request_head(&mut recv).await;
    let (status_line, content_type, body) = match status_page::parse_status_request(&head) {
        Some(request) => {
            let format = status_page::status_format_for(&request.path, request.accept);
            status_page::render_status(&server.build_status_template(), format)
        }
        None => (
            "400 Bad Request",
            status_page::CONTENT_TYPE_TEXT,
            "not an HTTP request\n".to_string(),
        ),
    };
    status_page::write_http_payload(&mut send, status_line, content_type, &body).await?;
    let _ = send.finish();

    // Drain the peer's request instead of dropping `recv` immediately: an
    // abrupt drop sends STOP_SENDING, which can truncate the response as the
    // client relays it. We sent `Connection: close`, so the peer closes after
    // reading the response, giving us EOF. Bounded by both a byte cap and one
    // deadline for the whole drain, so a peer that never closes — sending
    // nothing, or a byte now and then — can't pin the task.
    let deadline = tokio::time::Instant::now() + status_page::REQUEST_READ_TIMEOUT;
    let mut buf = [0u8; 4096];
    let mut drained = 0usize;
    while drained < status_page::REQUEST_HEAD_LIMIT {
        match tokio::time::timeout_at(deadline, recv.read(&mut buf)).await {
            Ok(Ok(Some(n))) => drained += n,
            // EOF, read error, or the deadline: stop draining.
            Ok(Ok(None)) | Ok(Err(_)) | Err(_) => break,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aliases() -> HashMap<String, String> {
        // Keys are lowercased at config-resolution time (see `resolve_server`).
        HashMap::from([
            ("server.internal".to_string(), "127.0.0.1".to_string()),
            ("node2.internal".to_string(), "192.168.1.50".to_string()),
        ])
    }

    #[test]
    fn alias_rewrites_host_keeps_port() {
        let got = apply_alias(Target::Domain("server.internal".into(), 8000), &aliases());
        assert_eq!(got, Target::Domain("127.0.0.1".into(), 8000));
    }

    #[test]
    fn alias_to_internal_host() {
        let got = apply_alias(Target::Domain("node2.internal".into(), 22), &aliases());
        assert_eq!(got, Target::Domain("192.168.1.50".into(), 22));
    }

    #[test]
    fn alias_match_is_case_insensitive() {
        let got = apply_alias(Target::Domain("Server.Internal".into(), 80), &aliases());
        assert_eq!(got, Target::Domain("127.0.0.1".into(), 80));
    }

    #[test]
    fn alias_match_ignores_the_root_dot() {
        let got = apply_alias(Target::Domain("server.internal.".into(), 80), &aliases());
        assert_eq!(got, Target::Domain("127.0.0.1".into(), 80));
    }

    #[test]
    fn non_alias_domain_passes_through() {
        let got = apply_alias(Target::Domain("example.com".into(), 443), &aliases());
        assert_eq!(got, Target::Domain("example.com".into(), 443));
    }

    #[test]
    fn ip_target_is_never_aliased() {
        let t = Target::Ip("127.0.0.1:8000".parse().unwrap());
        assert_eq!(apply_alias(t.clone(), &aliases()), t);
    }

    fn wildcard_aliases() -> HashMap<String, String> {
        HashMap::from([
            ("*.web.internal".to_string(), "10.0.0.1".to_string()),
            // A more specific wildcard nested under the broader one.
            ("*.api.web.internal".to_string(), "10.0.0.2".to_string()),
            // An exact host that shadows the `*.web.internal` wildcard for one name.
            ("special.web.internal".to_string(), "10.0.0.9".to_string()),
        ])
    }

    #[test]
    fn wildcard_matches_subdomain() {
        assert_eq!(resolve_alias(&wildcard_aliases(), "foo.web.internal"), Some("10.0.0.1"));
        // Deeper subdomains match the broad wildcard too (when no closer one wins).
        assert_eq!(resolve_alias(&wildcard_aliases(), "a.b.web.internal"), Some("10.0.0.1"));
    }

    #[test]
    fn wildcard_does_not_match_apex_or_sibling() {
        // `*.web.internal` excludes the bare apex...
        assert_eq!(resolve_alias(&wildcard_aliases(), "web.internal"), None);
        // ...and a sibling that only shares a label suffix, not a dot boundary.
        assert_eq!(resolve_alias(&wildcard_aliases(), "evil-web.internal"), None);
    }

    #[test]
    fn exact_key_beats_wildcard() {
        // `special.web.internal` has an exact entry; it must win over `*.web.internal`.
        assert_eq!(resolve_alias(&wildcard_aliases(), "special.web.internal"), Some("10.0.0.9"));
    }

    #[test]
    fn most_specific_wildcard_wins() {
        // `x.api.web.internal` matches both `*.web.internal` and `*.api.web.internal`;
        // the longer (more specific) suffix wins regardless of map iteration order.
        assert_eq!(resolve_alias(&wildcard_aliases(), "x.api.web.internal"), Some("10.0.0.2"));
    }

    #[test]
    fn wildcard_match_is_case_insensitive() {
        assert_eq!(resolve_alias(&wildcard_aliases(), "Foo.Web.Internal"), Some("10.0.0.1"));
    }

    #[test]
    fn wildcard_alias_rewrites_through_apply_alias() {
        let got = apply_alias(Target::Domain("db.web.internal".into(), 5432), &wildcard_aliases());
        assert_eq!(got, Target::Domain("10.0.0.1".into(), 5432));
    }
}
