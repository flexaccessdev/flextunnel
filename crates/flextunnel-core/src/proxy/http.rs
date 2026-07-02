//! Client-side HTTP proxy front-end (Phase 1): HTTP/1.x `CONNECT` tunneling.
//!
//! Handles `CONNECT host:port HTTP/1.1`, mapping the authority to a wire
//! [`Target`] — a hostname becomes [`Target::Domain`] so DNS happens on the
//! **server** (flextunnel's whole point), a literal IP becomes [`Target::Ip`]
//! (the client already resolved it). This mirrors the ATYP DOMAIN vs IP split in
//! [`crate::proxy::socks5::read_connect_request`].
//!
//! Absolute-URI plain-HTTP forwarding (`GET http://host/… HTTP/1.1`) is out of
//! scope for Phase 1 and is rejected with `501 Not Implemented`.

use crate::proxy::signaling::{self, Target};
use std::io;
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Cap on the request line + headers buffered before the tunnel begins. Sized
/// like the auth-handshake cap in `signaling` (`MAX_HANDSHAKE_SIZE`).
const MAX_HTTP_HEADER: usize = 64 * 1024;

/// Read an HTTP proxy request head (request line + headers, up to `\r\n\r\n`) and
/// parse a `CONNECT` target into a wire [`Target`].
///
/// Reads one byte at a time so it never consumes past `\r\n\r\n` — any following
/// bytes belong to the tunnel and must be left in the socket. On anything that
/// can't be tunneled (a non-CONNECT method, a malformed request line, or
/// oversized headers) it writes the matching HTTP error response to the client
/// before returning an error, mirroring how
/// [`crate::proxy::socks5::read_connect_request`] writes its own error replies.
pub async fn read_connect_request<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
) -> io::Result<Target> {
    // Accumulate the head byte-by-byte until the blank-line terminator. An I/O
    // error or EOF here propagates untouched — there's no complete request to
    // answer with a status line.
    let mut head = Vec::with_capacity(256);
    loop {
        head.push(stream.read_u8().await?);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() >= MAX_HTTP_HEADER {
            write_error(stream, 400, "Bad Request").await?;
            return Err(io::Error::other("HTTP request head exceeded size cap"));
        }
    }

    // Request line is everything up to the first CRLF (guaranteed present).
    let line_end = head
        .windows(2)
        .position(|w| w == b"\r\n")
        .expect("head ends with CRLFCRLF so a CRLF exists");
    let request_line = match std::str::from_utf8(&head[..line_end]) {
        Ok(s) => s,
        Err(_) => {
            write_error(stream, 400, "Bad Request").await?;
            return Err(io::Error::other("HTTP request line is not valid UTF-8"));
        }
    };

    // request-line = method SP request-target SP HTTP-version
    let mut parts = request_line.split(' ');
    let (method, request_target, version) = (
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
    );
    if method.is_empty() || request_target.is_empty() || version.is_empty() || parts.next().is_some()
    {
        write_error(stream, 400, "Bad Request").await?;
        return Err(io::Error::other(format!(
            "malformed HTTP request line: {request_line:?}"
        )));
    }

    // Phase 1 handles CONNECT only; plain-HTTP absolute-URI forwarding is Phase 2.
    if !method.eq_ignore_ascii_case("CONNECT") {
        write_error(stream, 501, "Not Implemented").await?;
        return Err(io::Error::other(format!(
            "HTTP method {method} not supported (CONNECT tunneling only)"
        )));
    }

    // CONNECT request-target is authority-form: host:port (RFC 9110 §9.3.6).
    let Some((host, port)) = split_authority(request_target) else {
        write_error(stream, 400, "Bad Request").await?;
        return Err(io::Error::other(format!(
            "invalid CONNECT authority: {request_target:?}"
        )));
    };

    let target = match host.parse::<IpAddr>() {
        Ok(ip) => Target::Ip(SocketAddr::new(ip, port)),
        Err(_) => Target::Domain(host.to_string(), port),
    };

    // Log the DNS mode at info (server-side vs client-side resolution) and the
    // specific destination only at debug, matching the SOCKS5 handler so default
    // logs don't leak user destinations.
    match &target {
        Target::Domain(host, port) => {
            log::info!("HTTP CONNECT — hostname (remote DNS, resolved on server)");
            log::debug!("HTTP CONNECT target {host}:{port}");
        }
        Target::Ip(addr) => {
            log::info!("HTTP CONNECT — literal IP (local DNS, client pre-resolved)");
            log::debug!("HTTP CONNECT target {addr}");
        }
    }
    Ok(target)
}

/// Split an authority-form `host:port` into its parts, handling bracketed IPv6
/// literals (`[::1]:443`). Returns `None` on a missing/empty host, a missing or
/// non-numeric port, or port 0.
fn split_authority(authority: &str) -> Option<(&str, u16)> {
    let (host, port_str) = if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal: [addr]:port — host is the address without the brackets.
        let (addr, after) = rest.split_once(']')?;
        (addr, after.strip_prefix(':')?)
    } else {
        authority.rsplit_once(':')?
    };
    if host.is_empty() {
        return None;
    }
    match port_str.parse::<u16>() {
        Ok(0) | Err(_) => None,
        Ok(port) => Some((host, port)),
    }
}

/// Answer the local app with the HTTP response for server reply code `rep`.
///
/// [`signaling::REP_SUCCESS`] becomes `200 Connection Established` (after which
/// the socket is an opaque tunnel); other codes map to an HTTP error status.
pub async fn write_reply<S: AsyncWriteExt + Unpin>(stream: &mut S, rep: u8) -> io::Result<()> {
    if rep == signaling::REP_SUCCESS {
        return stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await;
    }
    let (code, reason) = match rep {
        signaling::REP_NOT_ALLOWED => (403, "Forbidden"),
        // Timeouts, refusals, unreachable, and general failures all surface as a
        // bad-gateway to the local app in Phase 1.
        _ => (502, "Bad Gateway"),
    };
    write_error(stream, code, reason).await
}

/// Write a bodyless HTTP error response and ask the client to close.
async fn write_error<S: AsyncWriteExt + Unpin>(
    stream: &mut S,
    code: u16,
    reason: &str,
) -> io::Result<()> {
    let response =
        format!("HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    stream.write_all(response.as_bytes()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive `read_connect_request` with `request`, returning its result and any
    /// bytes it wrote back to the client (the error response, if any).
    async fn run(request: &[u8]) -> (io::Result<Target>, String) {
        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(request).await.unwrap();
        let result = read_connect_request(&mut server).await;
        drop(server);
        let mut resp = Vec::new();
        let _ = client.read_to_end(&mut resp).await;
        (result, String::from_utf8_lossy(&resp).into_owned())
    }

    #[tokio::test]
    async fn connect_domain_is_server_resolved() {
        let (target, _) =
            run(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n").await;
        assert_eq!(target.unwrap(), Target::Domain("example.com".to_string(), 443));
    }

    #[tokio::test]
    async fn connect_ipv4_literal_is_ip() {
        let (target, _) = run(b"CONNECT 93.184.216.34:443 HTTP/1.1\r\n\r\n").await;
        assert_eq!(
            target.unwrap(),
            Target::Ip("93.184.216.34:443".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn connect_ipv6_literal_is_ip() {
        let (target, _) = run(b"CONNECT [::1]:80 HTTP/1.1\r\n\r\n").await;
        assert_eq!(target.unwrap(), Target::Ip("[::1]:80".parse().unwrap()));
    }

    #[tokio::test]
    async fn non_connect_method_is_501() {
        let (target, resp) = run(b"GET http://example.com/ HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(target.is_err());
        assert!(resp.starts_with("HTTP/1.1 501"), "got: {resp:?}");
    }

    #[tokio::test]
    async fn missing_port_is_400() {
        let (target, resp) = run(b"CONNECT example.com HTTP/1.1\r\n\r\n").await;
        assert!(target.is_err());
        assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp:?}");
    }

    #[tokio::test]
    async fn malformed_request_line_is_400() {
        let (target, resp) = run(b"CONNECT\r\n\r\n").await;
        assert!(target.is_err());
        assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp:?}");
    }

    #[tokio::test]
    async fn zero_port_is_400() {
        let (target, resp) = run(b"CONNECT example.com:0 HTTP/1.1\r\n\r\n").await;
        assert!(target.is_err());
        assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp:?}");
    }

    #[tokio::test]
    async fn oversized_head_is_400() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        // A never-terminated head that overruns the cap. Held open so the reader
        // sees the overrun rather than an EOF.
        tokio::spawn(async move {
            let _ = client.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nX: ").await;
            let _ = client.write_all(&vec![b'a'; MAX_HTTP_HEADER + 16]).await;
            std::future::pending::<()>().await;
        });
        let err = read_connect_request(&mut server).await.unwrap_err();
        assert!(err.to_string().contains("size cap"), "got: {err}");
    }

    #[tokio::test]
    async fn reply_success_is_200_connection_established() {
        let mut buf = Vec::new();
        write_reply(&mut buf, signaling::REP_SUCCESS).await.unwrap();
        assert_eq!(&buf, b"HTTP/1.1 200 Connection Established\r\n\r\n");
    }

    #[tokio::test]
    async fn reply_not_allowed_is_403() {
        let mut buf = Vec::new();
        write_reply(&mut buf, signaling::REP_NOT_ALLOWED)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&buf).starts_with("HTTP/1.1 403"));
    }

    #[tokio::test]
    async fn reply_host_unreachable_is_502() {
        let mut buf = Vec::new();
        write_reply(&mut buf, signaling::REP_HOST_UNREACHABLE)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&buf).starts_with("HTTP/1.1 502"));
    }
}
