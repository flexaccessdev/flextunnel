//! Dialing a [`Target`] to an outbound TCP connection.
//!
//! Shared by the server (which dials every tunneled target from its own
//! network) and the client's split-tunnel path (which dials non-routed
//! targets directly from the device). Callers wrap these in their own timeouts.

use crate::proxy::signaling::Target;
use std::io;
use tokio::net::TcpStream;

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
