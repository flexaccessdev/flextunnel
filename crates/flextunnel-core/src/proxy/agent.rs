//! flextunnel agent: a reverse-routing exit point. Unlike the client it runs no
//! local SOCKS5 listener; it dials the server with an **ephemeral** iroh identity
//! and identifies itself by its stable **machine id** (`/etc/machine-id`, sent in
//! the `Hello`). The operator reserves that machine id in the server's
//! `[agent_routes]`. The agent then *accepts* the bi-streams the server opens back
//! to it, connecting each to `127.0.0.1` on the agent's own machine and piping
//! bytes (reverse routing is loopback-only in v1).
//!
//! The connect/auth/reconnect/heartbeat machinery mirrors [`super::client`]; the
//! only difference on the wire is the `Hello` role (`Agent`) + `machine_id`, and
//! that data streams flow the other way (server-opened, agent-accepted).

use crate::error::{ProxyError, ProxyResult};
use crate::proxy::client::{calculate_backoff, client_heartbeat_loop};
use crate::proxy::signaling::{self, Hello, Target};
use crate::proxy::dial;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl};
use rand::Rng;
use std::num::NonZeroU32;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

/// Deadline for the server's handshake response (mirrors the client).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Configuration for the reverse-routing agent.
pub struct AgentConfig {
    /// Server's iroh EndpointId (as a string) — the agent still dials the server.
    pub server_node_id: String,
    /// This agent's stable machine id (`/etc/machine-id`), sent in the handshake
    /// and used by the server to identify and route to this agent.
    pub machine_id: String,
    /// Authentication token sent in the connection handshake (an `fta` token).
    pub auth_token: String,
    /// Relay URL hints (optional).
    pub relay_urls: Vec<String>,
    /// Reconnect with backoff on a transient failure instead of exiting.
    pub auto_reconnect: bool,
    /// Cap on reconnect attempts between successful connections (unlimited if None).
    pub max_reconnect_attempts: Option<NonZeroU32>,
}

pub struct ProxyAgent {
    config: AgentConfig,
    /// Random per-process identity, sent in every `Hello` (see the client).
    instance_nonce: u128,
}

impl ProxyAgent {
    pub fn new(config: AgentConfig) -> Self {
        Self {
            config,
            instance_nonce: rand::rng().random(),
        }
    }

    /// Connect to the server and serve routed streams, reconnecting on transient
    /// drops with the same policy as the client (the first connection must
    /// succeed; recoverable drops retry with exponential backoff).
    pub async fn run(&self, endpoint: &Endpoint) -> ProxyResult<()> {
        let mut ever_connected = false;
        let mut attempt: u32 = 0;
        loop {
            let (connection, ctrl_send, ctrl_recv) = match self.establish(endpoint).await {
                Ok(established) => {
                    ever_connected = true;
                    attempt = 0;
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

            let served = self.serve(&connection, ctrl_send, ctrl_recv).await;
            if let Err(e) = served {
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

    /// Decide whether to retry after a failure (mirrors `ProxyClient::handle_failure`).
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

    /// Connect + authenticate as an agent, returning the connection and the
    /// control-stream halves (kept open for heartbeats).
    async fn establish(
        &self,
        endpoint: &Endpoint,
    ) -> ProxyResult<(Connection, SendStream, RecvStream)> {
        let addr = self.resolve_server_addr()?;
        let connection = endpoint
            .connect(addr, crate::transport::ALPN)
            .await
            .map_err(|e| ProxyError::Signaling(format!("Failed to connect to server: {e}")))?;
        log::info!("Connected to server, authenticating as agent...");
        let (send, recv) = self.handshake(&connection).await?;
        log::info!("Authenticated.");
        Ok((connection, send, recv))
    }

    /// Perform the agent auth handshake on the first bi-stream, returning the
    /// control-stream halves. The stream stays open as the heartbeat channel.
    async fn handshake(
        &self,
        connection: &Connection,
    ) -> ProxyResult<(SendStream, RecvStream)> {
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|e| ProxyError::Signaling(format!("Failed to open handshake stream: {e}")))?;

        let hello = Hello::new_agent(
            self.config.auth_token.clone(),
            self.instance_nonce,
            self.config.machine_id.clone(),
        );
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

        if !response.accepted {
            let reason = response.reject_reason.unwrap_or_else(|| "unknown".to_string());
            return Err(ProxyError::AuthenticationFailed(reason));
        }
        // The server pushes no routed set to an agent; ignore any list fields.
        Ok((send, recv))
    }

    /// Serve routed streams and run the heartbeat concurrently until the
    /// connection drops or heartbeat liveness is lost.
    async fn serve(
        &self,
        connection: &Connection,
        ctrl_send: SendStream,
        ctrl_recv: RecvStream,
    ) -> ProxyResult<()> {
        let accept = accept_server_streams(connection);
        let heartbeat = client_heartbeat_loop(ctrl_send, ctrl_recv);
        tokio::select! {
            r = accept => r,
            r = heartbeat => r,
        }
    }

    /// Resolve the server's `EndpointAddr`, attaching relay hints if given
    /// (mirrors `ProxyClient::resolve_server_addr`).
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
}

/// Accept the bi-streams the server opens to this agent and serve each one, until
/// the QUIC connection drops.
async fn accept_server_streams(connection: &Connection) -> ProxyResult<()> {
    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                tokio::spawn(async move {
                    if let Err(e) = handle_routed_stream(send, recv).await {
                        log::debug!("Routed stream ended: {e}");
                    }
                });
            }
            Err(e) => {
                return Err(ProxyError::ConnectionLost(format!(
                    "connection to server closed: {e}"
                )));
            }
        }
    }
}

/// Handle one server-routed stream: read the target the server forwarded (a
/// loopback address in v1) and connect + pipe on this agent's own machine (the
/// shared exit-point body).
///
/// Reverse routing is loopback-only in v1, so the forwarded target is validated
/// against that contract *before* dialing: a compromised or misbehaving server
/// must not be able to pivot the agent into its local network. The check is kept
/// right next to `Target` parsing so no non-loopback target ever reaches
/// [`dial::connect_and_pipe`].
async fn handle_routed_stream(send: SendStream, mut recv: RecvStream) -> std::io::Result<()> {
    let target: Target = signaling::read_request(&mut recv).await?;
    if !is_loopback_target(&target) {
        log::warn!("Rejecting non-loopback routed target from server: {target:?}");
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("routed target is not loopback (reverse routing is loopback-only): {target:?}"),
        ));
    }
    log::debug!("Agent dialing routed target: {target:?}");
    dial::connect_and_pipe(send, recv, &target).await
}

/// Whether a server-forwarded target is loopback, enforcing the v1 loopback-only
/// reverse-routing contract. Accepts a loopback IP or the literal `localhost`
/// host; a domain that is not a loopback literal is rejected (it could resolve
/// anywhere, defeating the check).
fn is_loopback_target(target: &Target) -> bool {
    match target {
        Target::Ip(addr) => addr.ip().is_loopback(),
        Target::Domain(host, _) => {
            if host.eq_ignore_ascii_case("localhost") {
                return true;
            }
            host.parse::<std::net::IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_targets_are_allowed() {
        // The server rewrites routed targets to this in v1.
        assert!(is_loopback_target(&Target::Domain("127.0.0.1".into(), 8000)));
        assert!(is_loopback_target(&Target::Domain("::1".into(), 8000)));
        assert!(is_loopback_target(&Target::Domain("LocalHost".into(), 22)));
        assert!(is_loopback_target(&Target::Ip("127.0.0.1:80".parse().unwrap())));
        assert!(is_loopback_target(&Target::Ip("[::1]:80".parse().unwrap())));
    }

    #[test]
    fn non_loopback_targets_are_rejected() {
        assert!(!is_loopback_target(&Target::Ip("93.184.216.34:443".parse().unwrap())));
        assert!(!is_loopback_target(&Target::Ip("192.168.1.50:22".parse().unwrap())));
        assert!(!is_loopback_target(&Target::Domain("example.com".into(), 443)));
        // A domain that merely *looks* loopback-ish but isn't a loopback literal.
        assert!(!is_loopback_target(&Target::Domain("127.0.0.1.evil.com".into(), 80)));
    }
}
