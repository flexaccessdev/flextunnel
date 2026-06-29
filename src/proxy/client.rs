//! flextunnel client: a local SOCKS5 listener whose CONNECTs are tunneled over
//! a single iroh QUIC connection to the server, one bi-stream per CONNECT.

use crate::error::{ProxyError, ProxyResult};
use crate::proxy::signaling::{self, Hello};
use crate::proxy::socks5;
use anyhow::Result;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl};
use rand::Rng;
use std::net::SocketAddr;
use std::num::NonZeroU32;
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

/// Configuration for the proxy client.
pub struct ClientConfig {
    /// Server's iroh EndpointId (as a string).
    pub server_node_id: String,
    /// Authentication token sent in the connection handshake.
    pub auth_token: String,
    /// Local address the SOCKS5 listener binds to.
    pub socks_listen: SocketAddr,
    /// Relay URL hints (optional).
    pub relay_urls: Vec<String>,
    /// Reconnect with backoff on a transient failure instead of exiting.
    pub auto_reconnect: bool,
    /// Cap on reconnect attempts between successful connections (unlimited if None).
    pub max_reconnect_attempts: Option<NonZeroU32>,
}

/// Exponential backoff with jitter for the Nth (1-based) reconnect attempt.
fn calculate_backoff(attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(6); // cap the doubling at 2^6 = 64
    let secs = (1u64 << shift).min(RECONNECT_BACKOFF_MAX);
    let jitter = rand::rng().random_range(0..=RECONNECT_JITTER_MAX_MS);
    Duration::from_secs(secs) + Duration::from_millis(jitter)
}

pub struct ProxyClient {
    config: ClientConfig,
}

impl ProxyClient {
    pub fn new(config: ClientConfig) -> Self {
        Self { config }
    }

    /// Bind the local SOCKS5 listener once, then connect to the server and serve
    /// it. Reconnect policy (matching ezvpn): the **first** connection must
    /// succeed — if it fails, exit immediately (a bad node id, wrong relay, or
    /// down server is not worth retrying blindly). Once connected at least once,
    /// transient drops are retried with exponential backoff, indefinitely
    /// (unless `--max-reconnect-attempts` caps it or `--no-auto-reconnect` is
    /// set). The listener stays bound across reconnects so local apps queue
    /// rather than see connection-refused during the gap.
    pub async fn run(&self, endpoint: &Endpoint) -> ProxyResult<()> {
        let listener = TcpListener::bind(self.config.socks_listen).await?;
        log::info!(
            "SOCKS5 proxy listening on {} (TCP CONNECT only)",
            self.config.socks_listen
        );

        let mut ever_connected = false;
        let mut attempt: u32 = 0;
        loop {
            // Establish (connect + auth).
            let connection = match self.establish(endpoint).await {
                Ok(conn) => {
                    ever_connected = true;
                    attempt = 0; // reset backoff on a successful connection
                    conn
                }
                Err(e) => match self.handle_failure(e, ever_connected, &mut attempt) {
                    Ok(backoff) => {
                        tokio::time::sleep(backoff).await;
                        continue;
                    }
                    Err(fatal) => return Err(fatal),
                },
            };

            // Serve until the connection drops, then reconnect (or exit).
            if let Err(e) = self.serve(&connection, &listener).await {
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

    /// Connect to the server and complete the auth handshake.
    async fn establish(&self, endpoint: &Endpoint) -> ProxyResult<Connection> {
        let endpoint_addr = self.resolve_server_addr()?;
        let connection = endpoint
            .connect(endpoint_addr, signaling::ALPN)
            .await
            .map_err(|e| ProxyError::Signaling(format!("Failed to connect to server: {e}")))?;
        log::info!("Connected to server, authenticating...");
        self.handshake(&connection).await?;
        log::info!("Authenticated.");
        Ok(connection)
    }

    /// Accept local SOCKS5 connections and tunnel each over its own bi-stream,
    /// until the QUIC connection drops.
    async fn serve(&self, connection: &Connection, listener: &TcpListener) -> ProxyResult<()> {
        loop {
            let accept = tokio::select! {
                r = listener.accept() => r,
                reason = connection.closed() => {
                    return Err(ProxyError::ConnectionLost(reason.to_string()));
                }
            };
            let (tcp, peer) = accept?;
            log::debug!("SOCKS5 connection from {peer}");
            let conn = connection.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_local_conn(tcp, conn).await {
                    log::debug!("SOCKS5 connection from {peer} ended: {e}");
                }
            });
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

    /// Perform the connection-level auth handshake on the first bi-stream.
    async fn handshake(&self, connection: &Connection) -> ProxyResult<()> {
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|e| ProxyError::Signaling(format!("Failed to open handshake stream: {e}")))?;

        let hello = Hello::new(self.config.auth_token.clone());
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
        let _ = send.finish();

        if !response.accepted {
            let reason = response.reject_reason.unwrap_or_else(|| "unknown".to_string());
            return Err(ProxyError::AuthenticationFailed(reason));
        }
        Ok(())
    }
}

/// Handle one local SOCKS5 connection: negotiate, parse CONNECT, open a stream
/// to the server, relay the reply, then pipe bytes.
async fn handle_local_conn(mut tcp: TcpStream, conn: Connection) -> Result<()> {
    socks5::negotiate_method(&mut tcp).await?;
    let target = socks5::read_connect_request(&mut tcp).await?;

    // Open the tunnel stream and read the server's reply. If any step fails the
    // local app hasn't been answered yet, so send a SOCKS5 general-failure reply
    // (best effort) instead of dropping the connection with no response.
    let (send, recv, rep) = match open_tunnel(&conn, &target).await {
        Ok(v) => v,
        Err(e) => {
            let _ = socks5::write_reply(&mut tcp, signaling::REP_GENERAL_FAILURE).await;
            return Err(e);
        }
    };

    socks5::write_reply(&mut tcp, rep).await?;
    if rep != signaling::REP_SUCCESS {
        return Ok(());
    }

    let mut iroh = tokio::io::join(recv, send);
    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut iroh).await;
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
