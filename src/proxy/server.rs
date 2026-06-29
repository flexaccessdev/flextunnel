//! flextunnel server: accepts authenticated iroh connections and, per SOCKS5
//! bi-stream, resolves DNS and connects to the target from its own network,
//! then pipes bytes. Runs entirely in userspace — no root, no TUN device.

use crate::error::{ProxyError, ProxyResult};
use crate::proxy::signaling::{self, HelloResponse, Target};
use iroh::Endpoint;
use iroh::endpoint::{Incoming, RecvStream, SendStream};
use std::collections::HashSet;
use std::io;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub struct ProxyServer {
    valid_tokens: HashSet<String>,
}

impl ProxyServer {
    pub fn new(valid_tokens: HashSet<String>) -> Arc<Self> {
        Arc::new(Self { valid_tokens })
    }

    /// Accept connections until the endpoint closes.
    pub async fn run(self: Arc<Self>, endpoint: &Endpoint) -> ProxyResult<()> {
        loop {
            match endpoint.accept().await {
                Some(incoming) => {
                    let server = self.clone();
                    tokio::spawn(async move {
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

        // Control stream: read Hello, validate token, reply.
        let (mut send, mut recv) = connection
            .accept_bi()
            .await
            .map_err(|e| ProxyError::Signaling(format!("Failed to accept handshake stream: {e}")))?;
        let data = signaling::read_message(&mut recv, signaling::MAX_HANDSHAKE_SIZE).await?;
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
                    tokio::spawn(async move {
                        if let Err(e) = handle_socks_stream(send, recv).await {
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

/// Handle one SOCKS5 stream: read the target, resolve + connect from the
/// server's network, reply, then pipe bytes bidirectionally.
async fn handle_socks_stream(mut send: SendStream, mut recv: RecvStream) -> io::Result<()> {
    let target = signaling::read_request(&mut recv).await?;
    log::debug!("Stream target: {target:?}");

    let connected = match &target {
        Target::Ip(sa) => TcpStream::connect(*sa).await,
        Target::Domain(host, port) => connect_resolved(host, *port).await,
    };

    let mut tcp = match connected {
        Ok(s) => {
            signaling::write_reply(&mut send, signaling::REP_SUCCESS).await?;
            s
        }
        Err(e) => {
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

/// Resolve a host:port via the server's DNS and connect to the first address
/// that accepts. Returns the last connect error, or a host-unreachable error if
/// resolution yielded no addresses.
async fn connect_resolved(host: &str, port: u16) -> io::Result<TcpStream> {
    let addrs = tokio::net::lookup_host((host, port)).await?;
    let mut last_err: Option<io::Error> = None;
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::HostUnreachable,
            format!("no addresses resolved for {host}:{port}"),
        )
    }))
}
