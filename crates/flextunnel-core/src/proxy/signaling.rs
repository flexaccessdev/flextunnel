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

/// flextunnel protocol version. v14: routing moved to the client — the
/// `HelloResponse` no longer carries the server's routed set, and a stream
/// request can ask for the server's own loopback or status page explicitly
/// ([`StreamRequest`]) instead of through a reserved hostname. A peer on
/// another version is turned away at the version check, before authentication.
pub const PROTOCOL_VERSION: u16 = 14;

/// Maximum auth-handshake message size (64 KiB) — far above what a `Hello` or
/// `HelloResponse` needs, while still bounding a misbehaving peer.
pub const MAX_HANDSHAKE_SIZE: usize = 64 * 1024;

/// Maximum size of a control-stream frame ([`ControlMsg`]). Generous for the
/// small heartbeat frames while still bounding a misbehaving peer.
pub const MAX_CONTROL_MSG_SIZE: usize = 16 * 1024;

/// Per-stream request/reply header version byte.
const STREAM_VERSION: u8 = 1;

// SOCKS5 address types (RFC 1928 ATYP), reused on the flextunnel wire.
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
// flextunnel's own request kinds, outside the SOCKS5 ATYP range.
/// `[port:u16 BE]` follows: dial that port on the server's own loopback.
const REQ_LOOPBACK: u8 = 0x10;
/// Nothing follows: serve the server's status page.
const REQ_STATUS: u8 = 0x11;

// Reply codes — deliberately equal to RFC 1928 SOCKS5 reply codes so the client
// forwards the server's reply byte straight into its SOCKS5 reply to the app.
pub const REP_SUCCESS: u8 = 0x00;
pub const REP_GENERAL_FAILURE: u8 = 0x01;
/// Connection not allowed by ruleset — used when the server's routed-set
/// whitelist rejects a target.
pub const REP_NOT_ALLOWED: u8 = 0x02;
pub const REP_NET_UNREACHABLE: u8 = 0x03;
pub const REP_HOST_UNREACHABLE: u8 = 0x04;
pub const REP_CONN_REFUSED: u8 = 0x05;
pub const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
pub const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

/// Public-key credential of a regular client's `Hello` (see [`crate::auth`]).
///
/// Nothing in it is secret: the public key is meant to be displayed, the
/// endpoint id is already TLS-visible, and the signature reveals nothing
/// about the secret key — so `Debug` derives plainly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientAuthPayload {
    /// The client's authentication public key (`ed25519-pub:...`), which
    /// must be on the server's authorized-keys file.
    pub public_key: String,
    /// The iroh endpoint id this client claims to be connecting from (its
    /// ephemeral endpoint identity). The server checks it against the
    /// connection's TLS-authenticated `remote_id()`.
    pub endpoint_id: String,
    /// base64url ed25519 signature over the domain-separated `endpoint_id`
    /// (see `auth::verify_endpoint_id_signature`), binding the credential to
    /// this connection so a captured `Hello` cannot be replayed elsewhere.
    pub signature: String,
}

/// Client → server auth handshake (first bi-stream of the connection).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub version: u16,
    /// Public-key credential for a regular [`ALPN`] client. `None` for a
    /// quick-mode [`QUICK_ALPN`] client, whose sole credential is its
    /// TLS-authenticated endpoint id — already checked against the server's
    /// allowlist natively before the connection reaches the accept loop.
    ///
    /// [`ALPN`]: crate::transport::ALPN
    /// [`QUICK_ALPN`]: crate::transport::QUICK_ALPN
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<ClientAuthPayload>,
    /// Random per-process identity of the *client process*, distinct from its
    /// (ephemeral) iroh node id. Lets the server tell a benign reconnect of one
    /// client (same nonce) apart from two distinct processes presenting the same
    /// node id (different nonces → a duplicate-client bug). See `proxy::server`.
    pub client_instance_nonce: u128,
    /// Non-privileged advisory: the client has observed a pattern that indicates
    /// a *duplicate server id* (two servers sharing this identity — see the
    /// server-nonce reappearance rule in `proxy::client`). It is an observation,
    /// not a command; the server decides whether to self-block on it.
    #[serde(default)]
    pub duplicate_server_observed: bool,
}

/// Server → client auth handshake response.
///
/// Carries no routing: each side configures its own routed set (see
/// [`crate::proxy::routed_set`]), so there is nothing for the server to push.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloResponse {
    pub version: u16,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reject_reason: Option<String>,
    /// Random per-process identity of the *server process*, stable for its
    /// lifetime. A restarting server emits a fresh random nonce each start (never
    /// reappearing); a client bouncing between two servers that share this
    /// identity sees nonces flip-flop. That reappearance is how a client detects
    /// a duplicate server id (see `proxy::destination`). Sent on acceptance and
    /// rejection alike so the client can always record it.
    pub server_instance_nonce: u128,
}

impl Hello {
    /// A client `Hello`. `auth` is `Some` for a keypair client, `None` for
    /// a quick-mode client (see the field docs).
    pub fn new(auth: Option<ClientAuthPayload>, client_instance_nonce: u128) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            auth,
            client_instance_nonce,
            duplicate_server_observed: false,
        }
    }
}

impl HelloResponse {
    pub fn accepted(server_instance_nonce: u128) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            accepted: true,
            reject_reason: None,
            server_instance_nonce,
        }
    }

    pub fn rejected(server_instance_nonce: u128, reason: impl Into<String>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            accepted: false,
            reject_reason: Some(reason.into()),
            server_instance_nonce,
        }
    }
}

/// Control-stream frames exchanged after the auth handshake.
///
/// The first bi-stream is not closed after `Hello`/`HelloResponse`; it stays
/// open as a control channel. The client sends [`ControlMsg::Heartbeat`] every
/// [`HEARTBEAT_INTERVAL`](crate::transport::HEARTBEAT_INTERVAL) and the server
/// replies [`ControlMsg::HeartbeatAck`]. This is an app-level liveness signal
/// (on top of QUIC keep-alive) that also drives the server's duplicate-client
/// registry. Framed with [`write_message`]/[`read_message`], capped at
/// [`MAX_CONTROL_MSG_SIZE`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlMsg {
    /// Client → server liveness ping, carrying a monotonically increasing seq.
    Heartbeat { seq: u64 },
    /// Server → client reply echoing the heartbeat's seq.
    HeartbeatAck { seq: u64 },
}

/// Encode a [`ControlMsg`] to JSON bytes.
pub fn encode_control(msg: &ControlMsg) -> io::Result<Vec<u8>> {
    serde_json::to_vec(msg).map_err(io::Error::other)
}

/// Decode a [`ControlMsg`] from JSON bytes.
pub fn decode_control(data: &[u8]) -> io::Result<ControlMsg> {
    serde_json::from_slice(data).map_err(io::Error::other)
}

/// A connection target requested over a per-SOCKS5 stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A resolved socket address (SOCKS5 ATYP IPv4/IPv6).
    Ip(SocketAddr),
    /// A domain name + port; resolved on the server side (SOCKS5 ATYP DOMAIN).
    Domain(String, u16),
}

impl Target {
    /// This target as the address it names when its host is an IP literal in
    /// domain form — `10.0.0.1`, `[fd00::1]`, `10.0.0.1.` — read the way the
    /// routed set reads one; any other target unchanged. What the CIDRs let
    /// through is then dialed as that address, never handed to a host alias
    /// or a resolver.
    pub fn into_numeric(self) -> Self {
        match self {
            Self::Domain(host, port) => match super::routed_set::parse_ip_literal(&host) {
                Some(ip) => Self::Ip(SocketAddr::new(ip, port)),
                None => Self::Domain(host, port),
            },
            ip => ip,
        }
    }
}

/// What a client asks the server for on one per-connection stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamRequest {
    /// Connect to `Target` from the server's network. The server enforces its
    /// routed set, then applies host aliases.
    Connect(Target),
    /// Connect to this port on the server's own loopback — what a client
    /// destination's loopback name means. Outside the routed set and aliases:
    /// every admitted client can reach the server's loopback.
    Loopback(u16),
    /// Serve the server's status page: an HTTP response to the HTTP request
    /// the client writes next.
    Status,
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

/// Write the per-stream request header. A [`StreamRequest::Connect`] is
/// `[ver][atyp][addr][port:u16 BE]` with the SOCKS5 address types; a
/// [`StreamRequest::Loopback`] is `[ver][0x10][port:u16 BE]`; a
/// [`StreamRequest::Status`] is `[ver][0x11]`.
pub async fn write_request<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    request: &StreamRequest,
) -> io::Result<()> {
    let mut buf = vec![STREAM_VERSION];
    match request {
        StreamRequest::Connect(Target::Ip(SocketAddr::V4(sa))) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&sa.ip().octets());
            buf.extend_from_slice(&sa.port().to_be_bytes());
        }
        StreamRequest::Connect(Target::Ip(SocketAddr::V6(sa))) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&sa.ip().octets());
            buf.extend_from_slice(&sa.port().to_be_bytes());
        }
        StreamRequest::Connect(Target::Domain(host, port)) => {
            let bytes = host.as_bytes();
            let len = u8::try_from(bytes.len())
                .map_err(|_| io::Error::other("domain name longer than 255 bytes"))?;
            buf.push(ATYP_DOMAIN);
            buf.push(len);
            buf.extend_from_slice(bytes);
            buf.extend_from_slice(&port.to_be_bytes());
        }
        StreamRequest::Loopback(port) => {
            buf.push(REQ_LOOPBACK);
            buf.extend_from_slice(&port.to_be_bytes());
        }
        StreamRequest::Status => buf.push(REQ_STATUS),
    }
    w.write_all(&buf).await
}

/// Read the per-stream request header written by [`write_request`].
pub async fn read_request<R: AsyncReadExt + Unpin>(r: &mut R) -> io::Result<StreamRequest> {
    let ver = r.read_u8().await?;
    if ver != STREAM_VERSION {
        return Err(io::Error::other(format!(
            "Unsupported stream version: {ver} (expected {STREAM_VERSION})"
        )));
    }
    let kind = r.read_u8().await?;
    match kind {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            r.read_exact(&mut octets).await?;
            let port = r.read_u16().await?;
            Ok(StreamRequest::Connect(Target::Ip(SocketAddr::V4(
                SocketAddrV4::new(Ipv4Addr::from(octets), port),
            ))))
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            r.read_exact(&mut octets).await?;
            let port = r.read_u16().await?;
            Ok(StreamRequest::Connect(Target::Ip(SocketAddr::V6(
                SocketAddrV6::new(Ipv6Addr::from(octets), port, 0, 0),
            ))))
        }
        ATYP_DOMAIN => {
            let len = r.read_u8().await? as usize;
            let mut host = vec![0u8; len];
            r.read_exact(&mut host).await?;
            let port = r.read_u16().await?;
            let host = String::from_utf8(host)
                .map_err(|_| io::Error::other("domain name is not valid UTF-8"))?;
            Ok(StreamRequest::Connect(Target::Domain(host, port)))
        }
        REQ_LOOPBACK => Ok(StreamRequest::Loopback(r.read_u16().await?)),
        REQ_STATUS => Ok(StreamRequest::Status),
        other => Err(io::Error::other(format!("invalid request kind: 0x{other:02x}"))),
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

    /// An IP literal in domain form is the address it names, however it is
    /// spelled; a hostname, or something only a hostname can be, stays one.
    #[test]
    fn a_numeric_domain_target_is_an_address() {
        let domain = |host: &str| Target::Domain(host.to_string(), 80);
        for (host, ip) in [
            ("127.0.0.1", "127.0.0.1:80"),
            ("127.0.0.1.", "127.0.0.1:80"),
            ("fd00::1", "[fd00::1]:80"),
            ("[fd00::1]", "[fd00::1]:80"),
            ("[fd00::1].", "[fd00::1]:80"),
        ] {
            assert_eq!(domain(host).into_numeric(), Target::Ip(ip.parse().unwrap()), "{host}");
        }
        for host in ["example.com", "example.com.", "127.0.0.1..", "10.1"] {
            assert_eq!(domain(host).into_numeric(), domain(host), "{host}");
        }
        let ip = Target::Ip("10.0.0.1:22".parse().unwrap());
        assert_eq!(ip.clone().into_numeric(), ip);
    }

    #[tokio::test]
    async fn request_roundtrips_every_kind() {
        for request in [
            StreamRequest::Connect(Target::Ip("93.184.216.34:443".parse().unwrap())),
            StreamRequest::Connect(Target::Ip(
                "[2606:2800:220:1:248:1893:25c8:1946]:80".parse().unwrap(),
            )),
            StreamRequest::Connect(Target::Domain("example.com".to_string(), 443)),
            StreamRequest::Loopback(22),
            StreamRequest::Status,
        ] {
            let mut buf = Vec::new();
            write_request(&mut buf, &request).await.unwrap();
            let got = read_request(&mut buf.as_slice()).await.unwrap();
            assert_eq!(got, request);
        }
    }

    #[tokio::test]
    async fn unknown_request_kind_is_rejected() {
        let buf = [STREAM_VERSION, 0x7f];
        assert!(read_request(&mut buf.as_slice()).await.is_err());
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
        let hello = Hello::new(
            Some(ClientAuthPayload {
                public_key: "ed25519-pub:abc".to_string(),
                endpoint_id: "endpointid".to_string(),
                signature: "sig".to_string(),
            }),
            0x1234_5678_9abc_def0_1122_3344_5566_7788,
        );
        let encoded = encode_hello(&hello).unwrap();
        let decoded = decode_hello(&encoded).unwrap();
        let auth = decoded.auth.expect("auth payload present");
        assert_eq!(auth.public_key, "ed25519-pub:abc");
        assert_eq!(auth.endpoint_id, "endpointid");
        assert_eq!(auth.signature, "sig");
        assert_eq!(decoded.version, PROTOCOL_VERSION);
        assert_eq!(
            decoded.client_instance_nonce,
            0x1234_5678_9abc_def0_1122_3344_5566_7788
        );
        assert!(!decoded.duplicate_server_observed);

        // A quick-mode hello carries no credential (the endpoint-id allowlist
        // is the credential); the field is omitted on the wire entirely.
        let quick = Hello::new(None, 7);
        let encoded = encode_hello(&quick).unwrap();
        assert!(!String::from_utf8_lossy(&encoded).contains("auth"));
        assert!(decode_hello(&encoded).unwrap().auth.is_none());
    }

    #[test]
    fn hello_response_roundtrip() {
        let resp = HelloResponse::accepted(42);
        let decoded = decode_hello_response(&encode_hello_response(&resp).unwrap()).unwrap();
        assert!(decoded.accepted);
        assert_eq!(decoded.version, PROTOCOL_VERSION);
        assert_eq!(decoded.server_instance_nonce, 42);
        assert!(decoded.reject_reason.is_none());

        // A rejection still carries the server nonce.
        let rej = HelloResponse::rejected(7, "nope");
        let decoded = decode_hello_response(&encode_hello_response(&rej).unwrap()).unwrap();
        assert!(!decoded.accepted);
        assert_eq!(decoded.reject_reason.as_deref(), Some("nope"));
        assert_eq!(decoded.server_instance_nonce, 7);
    }

    #[test]
    fn version_mismatch_is_rejected_before_auth() {
        // A peer on another protocol version must be rejected at the version
        // check — decode fails before any credential is even looked at, on
        // both directions of the handshake.
        let mut old = Hello::new(
            Some(ClientAuthPayload {
                public_key: "ed25519-pub:abc".to_string(),
                endpoint_id: "endpointid".to_string(),
                signature: "sig".to_string(),
            }),
            7,
        );
        old.version = PROTOCOL_VERSION - 1;
        let err = decode_hello(&serde_json::to_vec(&old).unwrap()).unwrap_err();
        assert!(err.to_string().contains("Unsupported protocol version"));

        let mut resp = HelloResponse::rejected(7, "nope");
        resp.version = PROTOCOL_VERSION - 1;
        assert!(decode_hello_response(&serde_json::to_vec(&resp).unwrap()).is_err());
    }

    #[test]
    fn control_msg_roundtrip() {
        for msg in [
            ControlMsg::Heartbeat { seq: 1 },
            ControlMsg::HeartbeatAck { seq: u64::MAX },
        ] {
            let decoded = decode_control(&encode_control(&msg).unwrap()).unwrap();
            assert_eq!(decoded, msg);
        }
    }
}
