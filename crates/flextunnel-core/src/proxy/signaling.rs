//! Wire protocol for flextunnel.
//!
//! Two layers ride one iroh QUIC connection:
//!
//! * **Connection auth** — a [`Hello`]/[`HelloResponse`] exchange on the first
//!   bi-stream, framed with the length-prefixed [`write_message`]/[`read_message`]
//!   helpers (adapted from ezvpn's signaling).
//! * **Per-SOCKS5-connection** — each subsequent bi-stream carries a compact
//!   binary request header (reusing SOCKS5 ATYP encoding), a one-byte reply, then
//!   raw bytes in both directions.

use serde::{Deserialize, Serialize};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// flextunnel protocol version.
pub const PROTOCOL_VERSION: u16 = 1;

/// Maximum auth-handshake message size (16 KiB).
pub const MAX_HANDSHAKE_SIZE: usize = 16 * 1024;

/// Per-stream request/reply header version byte.
const STREAM_VERSION: u8 = 1;

// SOCKS5 address types (RFC 1928 ATYP), reused on the flextunnel wire.
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

// Reply codes — deliberately equal to RFC 1928 SOCKS5 reply codes so the client
// forwards the server's reply byte straight into its SOCKS5 reply to the app.
pub const REP_SUCCESS: u8 = 0x00;
pub const REP_GENERAL_FAILURE: u8 = 0x01;
/// Connection not allowed by ruleset — used when a whitelist rejects a target.
pub const REP_NOT_ALLOWED: u8 = 0x02;
pub const REP_NET_UNREACHABLE: u8 = 0x03;
pub const REP_HOST_UNREACHABLE: u8 = 0x04;
pub const REP_CONN_REFUSED: u8 = 0x05;
pub const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
pub const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

/// Client → server auth handshake (first bi-stream of the connection).
///
/// `Debug` is implemented manually to redact `auth_token` (a bearer credential)
/// so it can never leak into logs or error context.
#[derive(Clone, Serialize, Deserialize)]
pub struct Hello {
    pub version: u16,
    pub auth_token: String,
}

impl std::fmt::Debug for Hello {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hello")
            .field("version", &self.version)
            .field("auth_token", &"<redacted>")
            .finish()
    }
}

/// Server → client auth handshake response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloResponse {
    pub version: u16,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reject_reason: Option<String>,
}

impl Hello {
    pub fn new(auth_token: impl Into<String>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            auth_token: auth_token.into(),
        }
    }
}

impl HelloResponse {
    pub fn accepted() -> Self {
        Self {
            version: PROTOCOL_VERSION,
            accepted: true,
            reject_reason: None,
        }
    }

    pub fn rejected(reason: impl Into<String>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            accepted: false,
            reject_reason: Some(reason.into()),
        }
    }
}

/// A connection target requested over a per-SOCKS5 stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A resolved socket address (SOCKS5 ATYP IPv4/IPv6).
    Ip(SocketAddr),
    /// A domain name + port; resolved on the server side (SOCKS5 ATYP DOMAIN).
    Domain(String, u16),
}

/// Write a length-prefixed message (4-byte big-endian length + payload).
pub async fn write_message<W: AsyncWriteExt + Unpin>(writer: &mut W, data: &[u8]) -> io::Result<()> {
    let len = u32::try_from(data.len())
        .map_err(|_| io::Error::other(format!("Message too large: {} bytes", data.len())))?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(data).await?;
    Ok(())
}

/// Read a length-prefixed message, rejecting anything larger than `max_size`.
pub async fn read_message<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    max_size: usize,
) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max_size {
        return Err(io::Error::other(format!(
            "Message too large: {len} > {max_size}"
        )));
    }
    let mut data = vec![0u8; len];
    reader.read_exact(&mut data).await?;
    Ok(data)
}

/// Encode a `Hello` to JSON bytes.
pub fn encode_hello(hello: &Hello) -> io::Result<Vec<u8>> {
    serde_json::to_vec(hello).map_err(io::Error::other)
}

/// Decode a `Hello` from JSON bytes, validating the protocol version.
pub fn decode_hello(data: &[u8]) -> io::Result<Hello> {
    let hello: Hello = serde_json::from_slice(data).map_err(io::Error::other)?;
    if hello.version != PROTOCOL_VERSION {
        return Err(io::Error::other(format!(
            "Unsupported protocol version: {} (expected {})",
            hello.version, PROTOCOL_VERSION
        )));
    }
    Ok(hello)
}

/// Encode a `HelloResponse` to JSON bytes.
pub fn encode_hello_response(resp: &HelloResponse) -> io::Result<Vec<u8>> {
    serde_json::to_vec(resp).map_err(io::Error::other)
}

/// Decode a `HelloResponse` from JSON bytes, validating the protocol version.
pub fn decode_hello_response(data: &[u8]) -> io::Result<HelloResponse> {
    let resp: HelloResponse = serde_json::from_slice(data).map_err(io::Error::other)?;
    if resp.version != PROTOCOL_VERSION {
        return Err(io::Error::other(format!(
            "Unsupported protocol version: {} (expected {})",
            resp.version, PROTOCOL_VERSION
        )));
    }
    Ok(resp)
}

/// Write the per-stream request header: `[ver][atyp][addr][port:u16 BE]`.
pub async fn write_request<W: AsyncWriteExt + Unpin>(w: &mut W, t: &Target) -> io::Result<()> {
    let mut buf = vec![STREAM_VERSION];
    match t {
        Target::Ip(SocketAddr::V4(sa)) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&sa.ip().octets());
            buf.extend_from_slice(&sa.port().to_be_bytes());
        }
        Target::Ip(SocketAddr::V6(sa)) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&sa.ip().octets());
            buf.extend_from_slice(&sa.port().to_be_bytes());
        }
        Target::Domain(host, port) => {
            let bytes = host.as_bytes();
            let len = u8::try_from(bytes.len())
                .map_err(|_| io::Error::other("domain name longer than 255 bytes"))?;
            buf.push(ATYP_DOMAIN);
            buf.push(len);
            buf.extend_from_slice(bytes);
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }
    w.write_all(&buf).await
}

/// Read the per-stream request header written by [`write_request`].
pub async fn read_request<R: AsyncReadExt + Unpin>(r: &mut R) -> io::Result<Target> {
    let ver = r.read_u8().await?;
    if ver != STREAM_VERSION {
        return Err(io::Error::other(format!(
            "Unsupported stream version: {ver} (expected {STREAM_VERSION})"
        )));
    }
    let atyp = r.read_u8().await?;
    match atyp {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            r.read_exact(&mut octets).await?;
            let port = r.read_u16().await?;
            Ok(Target::Ip(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(octets),
                port,
            ))))
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            r.read_exact(&mut octets).await?;
            let port = r.read_u16().await?;
            Ok(Target::Ip(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(octets),
                port,
                0,
                0,
            ))))
        }
        ATYP_DOMAIN => {
            let len = r.read_u8().await? as usize;
            let mut host = vec![0u8; len];
            r.read_exact(&mut host).await?;
            let port = r.read_u16().await?;
            let host = String::from_utf8(host)
                .map_err(|_| io::Error::other("domain name is not valid UTF-8"))?;
            Ok(Target::Domain(host, port))
        }
        other => Err(io::Error::other(format!("invalid address type: 0x{other:02x}"))),
    }
}

/// Write the per-stream reply header: `[ver][rep]`.
pub async fn write_reply<W: AsyncWriteExt + Unpin>(w: &mut W, rep: u8) -> io::Result<()> {
    w.write_all(&[STREAM_VERSION, rep]).await
}

/// Read the per-stream reply header, returning the reply code.
pub async fn read_reply<R: AsyncReadExt + Unpin>(r: &mut R) -> io::Result<u8> {
    let ver = r.read_u8().await?;
    if ver != STREAM_VERSION {
        return Err(io::Error::other(format!(
            "Unsupported stream version: {ver} (expected {STREAM_VERSION})"
        )));
    }
    r.read_u8().await
}

/// Map an outbound-connect I/O error to a SOCKS5 reply code.
pub fn map_io_err(e: &io::Error) -> u8 {
    use io::ErrorKind::*;
    match e.kind() {
        ConnectionRefused => REP_CONN_REFUSED,
        NetworkUnreachable => REP_NET_UNREACHABLE,
        HostUnreachable => REP_HOST_UNREACHABLE,
        _ => REP_GENERAL_FAILURE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn request_roundtrip_ipv4() {
        let t = Target::Ip("93.184.216.34:443".parse().unwrap());
        let mut buf = Vec::new();
        write_request(&mut buf, &t).await.unwrap();
        let got = read_request(&mut buf.as_slice()).await.unwrap();
        assert_eq!(got, t);
    }

    #[tokio::test]
    async fn request_roundtrip_ipv6() {
        let t = Target::Ip("[2606:2800:220:1:248:1893:25c8:1946]:80".parse().unwrap());
        let mut buf = Vec::new();
        write_request(&mut buf, &t).await.unwrap();
        let got = read_request(&mut buf.as_slice()).await.unwrap();
        assert_eq!(got, t);
    }

    #[tokio::test]
    async fn request_roundtrip_domain() {
        let t = Target::Domain("example.com".to_string(), 443);
        let mut buf = Vec::new();
        write_request(&mut buf, &t).await.unwrap();
        let got = read_request(&mut buf.as_slice()).await.unwrap();
        assert_eq!(got, t);
    }

    #[tokio::test]
    async fn reply_roundtrip() {
        let mut buf = Vec::new();
        write_reply(&mut buf, REP_HOST_UNREACHABLE).await.unwrap();
        let rep = read_reply(&mut buf.as_slice()).await.unwrap();
        assert_eq!(rep, REP_HOST_UNREACHABLE);
    }

    #[test]
    fn hello_roundtrip() {
        let hello = Hello::new("token");
        let encoded = encode_hello(&hello).unwrap();
        let decoded = decode_hello(&encoded).unwrap();
        assert_eq!(decoded.auth_token, "token");
        assert_eq!(decoded.version, PROTOCOL_VERSION);
    }
}
