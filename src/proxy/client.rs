//! flextunnel client: a local SOCKS5 listener whose CONNECTs are tunneled over
//! a single iroh QUIC connection to the server, one bi-stream per CONNECT.

use crate::error::{ProxyError, ProxyResult};
use crate::proxy::signaling::{self, Hello};
use crate::proxy::socks5;
use anyhow::Result;
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl};
use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

/// Configuration for the proxy client.
pub struct ClientConfig {
    /// Server's iroh EndpointId (as a string).
    pub server_node_id: String,
    /// Authentication token sent in the connection handshake.
    pub auth_token: String,
    /// ALPN value (embeds the shared "knock" token).
    pub alpn: Vec<u8>,
    /// Local address the SOCKS5 listener binds to.
    pub socks_listen: SocketAddr,
    /// Relay URL hints (optional).
    pub relay_urls: Vec<String>,
}

pub struct ProxyClient {
    config: ClientConfig,
}

impl ProxyClient {
    pub fn new(config: ClientConfig) -> Self {
        Self { config }
    }

    /// Connect to the server, authenticate, then serve the local SOCKS5
    /// listener until the QUIC connection drops or the listener fails.
    pub async fn run(&self, endpoint: &Endpoint) -> ProxyResult<()> {
        let endpoint_addr = self.resolve_server_addr()?;

        let connection = endpoint
            .connect(endpoint_addr, self.config.alpn.as_slice())
            .await
            .map_err(|e| ProxyError::Signaling(format!("Failed to connect to server: {e}")))?;
        log::info!("Connected to server, authenticating...");

        self.handshake(&connection).await?;
        log::info!("Authenticated.");

        let listener = TcpListener::bind(self.config.socks_listen).await?;
        log::info!(
            "SOCKS5 proxy listening on {} (TCP CONNECT only)",
            self.config.socks_listen
        );

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

        let data = signaling::read_message(&mut recv, signaling::MAX_HANDSHAKE_SIZE).await?;
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

    let (mut send, mut recv) = conn.open_bi().await?;
    signaling::write_request(&mut send, &target).await?;
    send.flush().await?;

    let rep = signaling::read_reply(&mut recv).await?;
    socks5::write_reply(&mut tcp, rep).await?;
    if rep != signaling::REP_SUCCESS {
        return Ok(());
    }

    let mut iroh = tokio::io::join(recv, send);
    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut iroh).await;
    Ok(())
}
