//! Dialing a [`Target`] to an outbound TCP connection.
//!
//! Shared by the server (which dials every tunneled target from its own
//! network) and the client's split-tunnel path (which dials non-routed
//! targets directly from the device). Callers wrap these in their own timeouts.

use crate::proxy::signaling::{self, Target};
use iroh::endpoint::{RecvStream, SendStream};
use std::io;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// Deadline for dialing a target (DNS resolution + TCP connect), so a slow or
/// black-holed target can't tie up a task and its sockets indefinitely. Used by
/// the server's exit path and by an agent dialing on its own network.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Connect to `target`: a literal IP connects directly, a domain is resolved
/// (via the caller's DNS) and tried address-by-address (see [`connect_resolved`]).
pub async fn dial_target(target: &Target) -> io::Result<TcpStream> {
    match target {
        Target::Ip(sa) => TcpStream::connect(*sa).await,
        Target::Domain(host, port) => connect_resolved(host, *port).await,
    }
}

/// Resolve a host:port via the local DNS and connect to the first address that
/// accepts. Returns the last connect error, or a host-unreachable error if
/// resolution yielded no addresses.
pub async fn connect_resolved(host: &str, port: u16) -> io::Result<TcpStream> {
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

/// Terminate a tunnel stream against a `target`: dial it (bounded by
/// [`CONNECT_TIMEOUT`]), write the SOCKS5-shaped reply byte, and — on success —
/// pipe bytes bidirectionally until either side closes.
///
/// This is the shared exit-point body: the **server** runs it for a normal
/// tunneled target (dialing from its own network), and an **agent** runs it for
/// a stream the server routed to it (dialing on the agent's network). Per-stream
/// errors stay per-stream; the shared QUIC connection is never torn down here.
pub async fn connect_and_pipe(
    mut send: SendStream,
    recv: RecvStream,
    target: &Target,
) -> io::Result<()> {
    let connected = match tokio::time::timeout(CONNECT_TIMEOUT, dial_target(target)).await {
        Ok(res) => res,
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out")),
    };

    let mut tcp = match connected {
        Ok(s) => {
            signaling::write_reply(&mut send, signaling::REP_SUCCESS).await?;
            s
        }
        Err(e) => {
            // Keep the failure visible at warn without exposing the target there;
            // log the target-specific detail at debug instead.
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
