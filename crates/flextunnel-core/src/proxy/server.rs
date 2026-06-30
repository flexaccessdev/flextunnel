//! flextunnel server: accepts authenticated iroh connections and, per SOCKS5
//! bi-stream, resolves DNS and connects to the target from its own network,
//! then pipes bytes. Runs entirely in userspace — no root, no TUN device.

use crate::error::{ProxyError, ProxyResult};
use crate::proxy::signaling::{self, HelloResponse, Target};
use crate::proxy::{dial, Whitelist};
use iroh::Endpoint;
use iroh::endpoint::{Incoming, RecvStream, SendStream};
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;

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

pub struct ProxyServer {
    valid_tokens: HashSet<String>,
    /// Host aliases (lowercased keys) rewritten before connecting; see
    /// [`apply_alias`].
    host_aliases: HashMap<String, String>,
    /// Destinations allowed to tunnel. When active, a request for a target not
    /// on the list is rejected (defense in depth — the client should already
    /// have split it off; see [`Whitelist`]).
    whitelist: Whitelist,
}

impl ProxyServer {
    pub fn new(
        valid_tokens: HashSet<String>,
        host_aliases: HashMap<String, String>,
        whitelist: Whitelist,
    ) -> Arc<Self> {
        Arc::new(Self {
            valid_tokens,
            host_aliases,
            whitelist,
        })
    }

    /// Accept connections until the endpoint closes.
    pub async fn run(self: Arc<Self>, endpoint: &Endpoint) -> ProxyResult<()> {
        let conn_limit = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
        loop {
            match endpoint.accept().await {
                Some(incoming) => {
                    // Acquire a slot before spawning so a flood of connections
                    // applies backpressure here rather than spawning unbounded
                    // handlers. The permit is released when the handler ends.
                    // `acquire_owned` only errors if the semaphore is closed,
                    // which never happens (it lives for this loop).
                    let permit = conn_limit
                        .clone()
                        .acquire_owned()
                        .await
                        .expect("connection semaphore is never closed");
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
            }
        }
    }

    /// Authenticate a connection, then serve its multiplexed SOCKS5 streams.
    async fn handle_connection(self: Arc<Self>, incoming: Incoming) -> ProxyResult<()> {
        let connection = incoming
            .await
            .map_err(|e| ProxyError::Signaling(format!("Failed to accept connection: {e}")))?;
        let remote_id = connection.remote_id();
        log::info!("New connection from {remote_id}");

        // Control stream: read Hello, validate token, reply. Bounded so a peer
        // that opens the connection but never sends the handshake can't hang us.
        let (mut send, data) = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            let (send, mut recv) = connection.accept_bi().await.map_err(|e| {
                ProxyError::Signaling(format!("Failed to accept handshake stream: {e}"))
            })?;
            let data = signaling::read_message(&mut recv, signaling::MAX_HANDSHAKE_SIZE).await?;
            Ok::<(SendStream, Vec<u8>), ProxyError>((send, data))
        })
        .await
        .map_err(|_| ProxyError::Signaling("timed out waiting for client handshake".into()))??;
        let hello = signaling::decode_hello(&data)?;

        let accepted = self.valid_tokens.contains(&hello.auth_token);
        let response = if accepted {
            HelloResponse::accepted()
        } else {
            log::warn!("Rejecting {remote_id}: invalid auth token");
            HelloResponse::rejected("Invalid authentication token")
        };
        signaling::write_message(&mut send, &signaling::encode_hello_response(&response)?).await?;
        let _ = send.finish();

        if !accepted {
            // Give the client a brief moment to read the rejection response, then
            // close the connection gracefully with the reason (an abrupt drop
            // would surface on the client as a generic "connection lost"). The
            // wait is bounded so a non-reading client can never stall this path.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            connection.close(1u32.into(), b"invalid authentication token");
            return Err(ProxyError::AuthenticationFailed(format!(
                "client {remote_id} provided an invalid token"
            )));
        }
        log::info!("Client {remote_id} authenticated");

        // Serve SOCKS5 streams until the connection closes.
        loop {
            match connection.accept_bi().await {
                Ok((send, recv)) => {
                    let server = self.clone();
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

    // Enforce the whitelist on the requested target (before aliasing), as a
    // defense-in-depth boundary: a well-behaved client only tunnels whitelisted
    // targets, so a request for anything off-list means a misconfigured or
    // untrusted client. Reject with the SOCKS5 "not allowed by ruleset" code.
    if whitelist.is_active() && !whitelist.allows(&requested) {
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
