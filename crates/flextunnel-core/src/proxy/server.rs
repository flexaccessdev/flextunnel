//! flextunnel server: accepts authenticated iroh connections and, per SOCKS5
//! bi-stream, resolves DNS and connects to the target from its own network,
//! then pipes bytes. Runs entirely in userspace — no root, no TUN device.

use crate::blocklist::{self, BlockList};
use crate::error::{ProxyError, ProxyResult};
use crate::proxy::signaling::{self, ControlMsg, HelloResponse, Target};
use crate::proxy::{dial, Whitelist};
use crate::transport::LIVENESS_WINDOW;
use iroh::endpoint::{Connection, Incoming, RecvStream, SendStream};
use iroh::{Endpoint, EndpointId};
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::sync::{Notify, Semaphore};

/// Deadline for receiving the client's auth handshake once a connection opens.
/// The QUIC keep-alive keeps the connection from idling out, so without this a
/// peer that never opens the handshake stream would hang the task forever.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Deadline for dialing an outbound target (DNS resolution + TCP connect), so a
/// slow or black-holed target can't tie up a task and its sockets indefinitely.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
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
    valid_tokens: HashSet<String>,
    /// Host aliases (lowercased keys) rewritten before connecting; see
    /// [`apply_alias`].
    host_aliases: HashMap<String, String>,
    /// Destinations allowed to tunnel. When active, a request for a target not
    /// on the list is rejected (defense in depth — the client should already
    /// have split it off; see [`Whitelist`]).
    whitelist: Whitelist,
    /// Raw whitelist rules, pushed verbatim to clients in the handshake so they
    /// learn the tunnel set from the server (the single source of truth).
    whitelist_domains: Vec<String>,
    whitelist_cidrs: Vec<String>,
    /// Live-connection registry for duplicate-client detection.
    registry: Arc<Mutex<Registry>>,
    /// Persistent duplicate-id blocklist (shared, synced to disk on mutation).
    blocklist: Arc<Mutex<BlockList>>,
    /// Tripped when the server must stop itself (duplicate-server self-block);
    /// wakes the accept loop in [`run`](Self::run).
    shutdown: Arc<Notify>,
}

impl ProxyServer {
    pub fn new(
        own_id: EndpointId,
        valid_tokens: HashSet<String>,
        host_aliases: HashMap<String, String>,
        whitelist: Whitelist,
        whitelist_domains: Vec<String>,
        whitelist_cidrs: Vec<String>,
        blocklist: BlockList,
    ) -> Arc<Self> {
        Arc::new(Self {
            own_id,
            server_instance_nonce: rand::rng().random(),
            valid_tokens,
            host_aliases,
            whitelist,
            whitelist_domains,
            whitelist_cidrs,
            registry: Arc::new(Mutex::new(Registry::new())),
            blocklist: Arc::new(Mutex::new(blocklist)),
            shutdown: Arc::new(Notify::new()),
        })
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
            },
        );
        Ok(())
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

        // Control stream: read Hello. Kept open afterwards for heartbeats, so the
        // send/recv halves flow through to the heartbeat loop. Bounded so a peer
        // that opens the connection but never sends the handshake can't hang us.
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
        // server behavior — including the duplicate-server self-block below. The
        // ALPN is not a credential, so without this gate an unauthenticated peer
        // could trip self-block + shutdown.
        let token_ok = self.valid_tokens.contains(&hello.auth_token);
        let blocked = self.is_client_blocked(&remote_id);
        if !token_ok || blocked {
            let reason = if blocked {
                log::warn!("Rejecting {remote_id}: node id is blocklisted (duplicate id)");
                "node id is blocklisted (duplicate id previously detected)"
            } else {
                log::warn!("Rejecting {remote_id}: invalid auth token");
                "Invalid authentication token"
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
        let _guard = match self.try_register(remote_id, conn_seq, hello.client_instance_nonce, connection.clone()) {
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

        // Accept: push the whitelist and our server nonce. The control stream is
        // NOT finished — it stays open for heartbeats.
        let resp = HelloResponse::accepted(
            self.server_instance_nonce,
            self.whitelist_domains.clone(),
            self.whitelist_cidrs.clone(),
        );
        signaling::write_message(&mut send, &signaling::encode_hello_response(&resp)?).await?;
        send.flush().await?;
        log::info!("Client {remote_id} authenticated");

        // Serve SOCKS5 streams and the heartbeat concurrently until either ends
        // (connection closed, or heartbeat liveness lost). `_guard` cleans the
        // registry on return via Drop.
        let socks = self.serve_socks(&connection, remote_id);
        let heartbeat = server_heartbeat_loop(
            send,
            recv,
            self.registry.clone(),
            remote_id,
            conn_seq,
        );
        tokio::select! {
            r = socks => r,
            r = heartbeat => r,
        }
    }

    /// Accept and dispatch SOCKS5 bi-streams until the connection closes.
    async fn serve_socks(self: &Arc<Self>, connection: &Connection, remote_id: EndpointId) -> ProxyResult<()> {
        loop {
            match connection.accept_bi().await {
                Ok((send, recv)) => {
                    let server = Arc::clone(self);
                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_socks_stream(send, recv, &server.host_aliases, &server.whitelist)
                                .await
                        {
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

/// Server-side heartbeat loop over the retained control stream: refresh the
/// registry entry's liveness on each `Heartbeat` and reply `HeartbeatAck`. A
/// heartbeat gap beyond [`LIVENESS_WINDOW`] (or a stream error) ends the loop,
/// which tears the connection handler down.
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
        && let Some(mapped) = aliases.get(&host.to_ascii_lowercase())
    {
        log::debug!("Aliasing host {host} -> {mapped}");
        return Target::Domain(mapped.clone(), *port);
    }
    target
}

/// Handle one SOCKS5 stream: read the target, resolve + connect from the
/// server's network, reply, then pipe bytes bidirectionally.
async fn handle_socks_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    host_aliases: &HashMap<String, String>,
    whitelist: &Whitelist,
) -> io::Result<()> {
    let requested = signaling::read_request(&mut recv).await?;

    // Enforce the tunnel set on the requested target (before aliasing), as a
    // defense-in-depth boundary: a well-behaved client only tunnels on-list
    // targets, so a request for anything off-list means a misconfigured or
    // untrusted client. Reject with the SOCKS5 "not allowed by ruleset" code.
    if !whitelist.allows(&requested) {
        log::warn!("Tunnel request rejected by whitelist");
        log::debug!("Rejected {requested:?} by whitelist");
        signaling::write_reply(&mut send, signaling::REP_NOT_ALLOWED).await?;
        send.flush().await?;
        return Ok(());
    }

    let target = apply_alias(requested, host_aliases);
    log::debug!("Stream target: {target:?}");

    // Bound the dial (DNS + TCP connect) so a slow/black-holed target can't tie
    // up this task and its sockets indefinitely.
    let connected = match tokio::time::timeout(CONNECT_TIMEOUT, dial::dial_target(&target)).await {
        Ok(res) => res,
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out")),
    };

    let mut tcp = match connected {
        Ok(s) => {
            signaling::write_reply(&mut send, signaling::REP_SUCCESS).await?;
            s
        }
        Err(e) => {
            // Keep the failure visible at warn, but don't expose the requested
            // target there; log the target-specific detail at debug instead.
            log::warn!("Connect to target failed: {e}");
            log::debug!("Connect to {target:?} failed: {e}");
            signaling::write_reply(&mut send, signaling::map_io_err(&e)).await?;
            send.flush().await?;
            return Ok(());
        }
    };
    send.flush().await?;

    let mut iroh = tokio::io::join(recv, send);
    let _ = tokio::io::copy_bidirectional(&mut iroh, &mut tcp).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aliases() -> HashMap<String, String> {
        // Keys are lowercased at config-resolution time (see `resolve_server`).
        HashMap::from([
            ("server.ezvpn".to_string(), "127.0.0.1".to_string()),
            ("node2.ezvpn".to_string(), "192.168.1.50".to_string()),
        ])
    }

    #[test]
    fn alias_rewrites_host_keeps_port() {
        let got = apply_alias(Target::Domain("server.ezvpn".into(), 8000), &aliases());
        assert_eq!(got, Target::Domain("127.0.0.1".into(), 8000));
    }

    #[test]
    fn alias_to_internal_host() {
        let got = apply_alias(Target::Domain("node2.ezvpn".into(), 22), &aliases());
        assert_eq!(got, Target::Domain("192.168.1.50".into(), 22));
    }

    #[test]
    fn alias_match_is_case_insensitive() {
        let got = apply_alias(Target::Domain("Server.EzVPN".into(), 80), &aliases());
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
}
