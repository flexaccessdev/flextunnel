//! SOCKS5 (RFC 1928) for the local front-end: method negotiation, CONNECT
//! request parsing, and reply writing on the server side, plus a client-side
//! dialer (`client_*`) used by the desktop port forwarder to relay through the
//! local listener. No-auth and username/password (RFC 1929) methods; CONNECT
//! command only (TCP — no BIND, no UDP ASSOCIATE).
//!
//! Username/password here is not security (everything is loopback and trusted)
//! — it is the port forwarder's instance handshake: the password is a random
//! per-[`ProxyClient`](crate::proxy::ProxyClient) token, so a forwarder that
//! accidentally reaches some *other* SOCKS5 server on the port (another
//! flextunnel instance, an `ssh -D`) fails the negotiation instead of silently
//! sending traffic to the wrong place.

use crate::proxy::signaling::{self, Target};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SOCKS_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USERPASS: u8 = 0x02;
const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;

// RFC 1929 username/password subnegotiation.
const USERPASS_VER: u8 = 0x01;
const USERPASS_SUCCESS: u8 = 0x00;
const USERPASS_FAILURE: u8 = 0x01;
/// Fixed username for the instance handshake; the identity lives in the
/// password (the per-instance token).
pub const AUTH_USERNAME: &str = "flextunnel";

// SOCKS5 ATYP values (RFC 1928).
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// Perform the SOCKS5 greeting/method negotiation.
///
/// Reads `[VER, NMETHODS, METHODS..]`. A client offering username/password
/// (0x02) gets it — that is the port forwarder's instance handshake, verified
/// against `auth_password` ([`AUTH_USERNAME`] / the per-instance token).
/// Otherwise a client offering no-auth (0x00) proceeds unauthenticated as
/// before (browsers, curl, the iOS forwarder). Anything else gets
/// `[0x05, 0xFF]` and an error.
pub async fn negotiate_method<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    auth_password: &str,
) -> io::Result<()> {
    let ver = stream.read_u8().await?;
    if ver != SOCKS_VERSION {
        return Err(io::Error::other(format!(
            "unsupported SOCKS version: 0x{ver:02x}"
        )));
    }
    let nmethods = stream.read_u8().await? as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    if methods.contains(&METHOD_USERPASS) {
        stream.write_all(&[SOCKS_VERSION, METHOD_USERPASS]).await?;
        let ver = stream.read_u8().await?;
        if ver != USERPASS_VER {
            return Err(io::Error::other(format!(
                "unsupported SOCKS5 username/password subnegotiation version: 0x{ver:02x}"
            )));
        }
        let ulen = stream.read_u8().await? as usize;
        let mut username = vec![0u8; ulen];
        stream.read_exact(&mut username).await?;
        let plen = stream.read_u8().await? as usize;
        let mut password = vec![0u8; plen];
        stream.read_exact(&mut password).await?;

        if username == AUTH_USERNAME.as_bytes() && password == auth_password.as_bytes() {
            stream.write_all(&[USERPASS_VER, USERPASS_SUCCESS]).await?;
            Ok(())
        } else {
            stream.write_all(&[USERPASS_VER, USERPASS_FAILURE]).await?;
            Err(io::Error::other(
                "SOCKS5 username/password auth failed — a forwarder from a \
                 different flextunnel instance?",
            ))
        }
    } else if methods.contains(&METHOD_NO_AUTH) {
        stream.write_all(&[SOCKS_VERSION, METHOD_NO_AUTH]).await?;
        Ok(())
    } else {
        stream
            .write_all(&[SOCKS_VERSION, METHOD_NONE_ACCEPTABLE])
            .await?;
        Err(io::Error::other("client offered no acceptable SOCKS5 method"))
    }
}

/// Client side of the instance handshake: greet offering **only** the
/// username/password method and run the RFC 1929 subnegotiation.
///
/// Every failure mode maps to "this is not our SOCKS5 listener": a server
/// picking no-auth (never offered — protocol violation) or replying `0xFF` is
/// some other SOCKS5 server on the port, and a credential rejection is another
/// flextunnel instance.
pub async fn client_handshake_userpass<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    username: &str,
    password: &str,
) -> io::Result<()> {
    let (Ok(ulen), Ok(plen)) = (
        u8::try_from(username.len()),
        u8::try_from(password.len()),
    ) else {
        return Err(io::Error::other(
            "SOCKS5 username/password must be at most 255 bytes",
        ));
    };

    stream
        .write_all(&[SOCKS_VERSION, 1, METHOD_USERPASS])
        .await?;
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).await?;
    let [ver, method] = choice;
    if ver != SOCKS_VERSION {
        return Err(io::Error::other(format!(
            "not a SOCKS5 server (greeting version 0x{ver:02x})"
        )));
    }
    match method {
        METHOD_USERPASS => {}
        METHOD_NONE_ACCEPTABLE => {
            return Err(io::Error::other(
                "SOCKS5 server refused username/password auth — another SOCKS5 \
                 server (not this app) is on this port",
            ));
        }
        other => {
            return Err(io::Error::other(format!(
                "SOCKS5 server selected method 0x{other:02x} that was not offered — \
                 another SOCKS5 server (not this app) is on this port"
            )));
        }
    }

    let mut req = Vec::with_capacity(3 + username.len() + password.len());
    req.push(USERPASS_VER);
    req.push(ulen);
    req.extend_from_slice(username.as_bytes());
    req.push(plen);
    req.extend_from_slice(password.as_bytes());
    stream.write_all(&req).await?;

    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    let [ver, status] = reply;
    if ver != USERPASS_VER {
        return Err(io::Error::other(format!(
            "unexpected SOCKS5 auth reply version: 0x{ver:02x}"
        )));
    }
    if status != USERPASS_SUCCESS {
        return Err(io::Error::other(
            "SOCKS5 credentials rejected — the port is served by a different \
             flextunnel instance",
        ));
    }
    Ok(())
}

/// Client side: write a SOCKS5 CONNECT request for `target`. A
/// [`Target::Domain`] is sent as ATYP DOMAIN so the hostname stays unresolved
/// (server-side DNS, flextunnel's whole point).
pub async fn client_write_connect<S: AsyncWriteExt + Unpin>(
    stream: &mut S,
    target: &Target,
) -> io::Result<()> {
    let mut req = vec![SOCKS_VERSION, CMD_CONNECT, 0x00];
    match target {
        Target::Domain(host, port) => {
            let Ok(len) = u8::try_from(host.len()) else {
                return Err(io::Error::other(format!(
                    "SOCKS5 domain longer than 255 bytes: {host}"
                )));
            };
            req.push(ATYP_DOMAIN);
            req.push(len);
            req.extend_from_slice(host.as_bytes());
            req.extend_from_slice(&port.to_be_bytes());
        }
        Target::Ip(SocketAddr::V4(addr)) => {
            req.push(ATYP_IPV4);
            req.extend_from_slice(&addr.ip().octets());
            req.extend_from_slice(&addr.port().to_be_bytes());
        }
        Target::Ip(SocketAddr::V6(addr)) => {
            req.push(ATYP_IPV6);
            req.extend_from_slice(&addr.ip().octets());
            req.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    stream.write_all(&req).await
}

/// Client side: read a SOCKS5 CONNECT reply, consuming the BND address, and
/// return the REP code (see [`describe_reply`]).
pub async fn client_read_reply<S: AsyncReadExt + Unpin>(stream: &mut S) -> io::Result<u8> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    let [ver, rep, _rsv, atyp] = head;
    if ver != SOCKS_VERSION {
        return Err(io::Error::other(format!(
            "unexpected SOCKS5 reply version: 0x{ver:02x}"
        )));
    }
    let bnd_len = match atyp {
        ATYP_IPV4 => 4,
        ATYP_IPV6 => 16,
        ATYP_DOMAIN => stream.read_u8().await? as usize,
        other => {
            return Err(io::Error::other(format!(
                "unsupported SOCKS5 reply address type: 0x{other:02x}"
            )));
        }
    };
    let mut bnd = vec![0u8; bnd_len + 2]; // BND.ADDR + BND.PORT
    stream.read_exact(&mut bnd).await?;
    Ok(rep)
}

/// Human text for a SOCKS5 REP code, for forwarder error messages.
pub fn describe_reply(rep: u8) -> &'static str {
    match rep {
        signaling::REP_SUCCESS => "succeeded",
        signaling::REP_GENERAL_FAILURE => "general failure",
        signaling::REP_NOT_ALLOWED => "connection not allowed",
        signaling::REP_NET_UNREACHABLE => "network unreachable",
        signaling::REP_HOST_UNREACHABLE => "host unreachable",
        signaling::REP_CONN_REFUSED => "connection refused",
        signaling::REP_CMD_NOT_SUPPORTED => "command not supported",
        signaling::REP_ATYP_NOT_SUPPORTED => "address type not supported",
        _ => "unknown failure",
    }
}

/// Read and parse a SOCKS5 CONNECT request, returning the wire [`Target`].
///
/// On a non-CONNECT command or an unsupported address type, writes the matching
/// SOCKS5 reply to the client before returning an error.
pub async fn read_connect_request<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
) -> io::Result<Target> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    let [ver, cmd, rsv, atyp] = head;

    if ver != SOCKS_VERSION {
        return Err(io::Error::other(format!(
            "unsupported SOCKS version in request: 0x{ver:02x}"
        )));
    }
    if cmd != CMD_CONNECT {
        write_reply(stream, signaling::REP_CMD_NOT_SUPPORTED).await?;
        return Err(io::Error::other(format!(
            "unsupported SOCKS5 command: 0x{cmd:02x} (only CONNECT)"
        )));
    }
    // RSV is reserved and MUST be 0x00 (RFC 1928); reject a malformed request
    // before parsing the address.
    if rsv != 0x00 {
        write_reply(stream, signaling::REP_GENERAL_FAILURE).await?;
        return Err(io::Error::other(format!(
            "invalid SOCKS5 reserved byte: 0x{rsv:02x} (must be 0x00)"
        )));
    }

    let target = match atyp {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            let port = stream.read_u16().await?;
            Target::Ip(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(octets), port)))
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            let port = stream.read_u16().await?;
            Target::Ip(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(octets),
                port,
                0,
                0,
            )))
        }
        ATYP_DOMAIN => {
            let len = stream.read_u8().await? as usize;
            let mut host = vec![0u8; len];
            stream.read_exact(&mut host).await?;
            let port = stream.read_u16().await?;
            match String::from_utf8(host) {
                Ok(host) => Target::Domain(host, port),
                Err(_) => {
                    write_reply(stream, signaling::REP_GENERAL_FAILURE).await?;
                    return Err(io::Error::other("SOCKS5 domain is not valid UTF-8"));
                }
            }
        }
        other => {
            write_reply(stream, signaling::REP_ATYP_NOT_SUPPORTED).await?;
            return Err(io::Error::other(format!(
                "unsupported SOCKS5 address type: 0x{other:02x}"
            )));
        }
    };

    // Whether the SOCKS5 client sent a hostname (ATYP DOMAIN) or a pre-resolved
    // address (ATYP IPv4/IPv6) decides *where* DNS happens: a domain is resolved
    // on the server (flextunnel's whole point), an IP means the client already
    // resolved it locally. Log the DNS-mode diagnostic at debug and the specific
    // destination only at debug so default logs don't leak user destinations.
    match &target {
        Target::Domain(host, port) => {
            log::debug!("SOCKS5 CONNECT — ATYP_DOMAIN (remote DNS, resolved on server)");
            log::debug!("SOCKS5 CONNECT target {host}:{port}");
        }
        Target::Ip(addr) => {
            log::info!("SOCKS5 CONNECT — ATYP_IP (local DNS, client pre-resolved)");
            log::debug!("SOCKS5 CONNECT target {addr}");
        }
    }
    Ok(target)
}

/// Write a SOCKS5 reply to the local app: `[VER, REP, RSV, ATYP, BND.ADDR, BND.PORT]`.
///
/// We always report `BND = 0.0.0.0:0` (ATYP IPv4) — apps ignore the bound
/// address for CONNECT. `rep` is the code received from the flextunnel server.
pub async fn write_reply<S: AsyncWriteExt + Unpin>(stream: &mut S, rep: u8) -> io::Result<()> {
    // VER, REP, RSV, ATYP=IPv4, 0.0.0.0, port 0
    let reply = [SOCKS_VERSION, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
    stream.write_all(&reply).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "0123456789abcdef0123456789abcdef";

    /// Run the client and server halves of a negotiation over an in-memory
    /// duplex pipe and return both results.
    async fn negotiate(
        client: impl AsyncFnOnce(&mut tokio::io::DuplexStream) -> io::Result<()>,
        server_password: &str,
    ) -> (io::Result<()>, io::Result<()>) {
        let (mut c, mut s) = tokio::io::duplex(1024);
        tokio::join!(client(&mut c), negotiate_method(&mut s, server_password))
    }

    #[tokio::test]
    async fn userpass_roundtrip() {
        let (client, server) = negotiate(
            async |c| client_handshake_userpass(c, AUTH_USERNAME, PASSWORD).await,
            PASSWORD,
        )
        .await;
        client.expect("client ok");
        server.expect("server ok");
    }

    #[tokio::test]
    async fn no_auth_client_unchanged() {
        let (client, server) = negotiate(
            async |c| {
                c.write_all(&[SOCKS_VERSION, 1, METHOD_NO_AUTH]).await?;
                let mut choice = [0u8; 2];
                c.read_exact(&mut choice).await?;
                assert_eq!(choice, [SOCKS_VERSION, METHOD_NO_AUTH]);
                Ok(())
            },
            PASSWORD,
        )
        .await;
        client.expect("client ok");
        server.expect("server ok");
    }

    #[tokio::test]
    async fn wrong_password_rejected() {
        let (client, server) = negotiate(
            async |c| client_handshake_userpass(c, AUTH_USERNAME, "wrong").await,
            PASSWORD,
        )
        .await;
        assert!(client.unwrap_err().to_string().contains("rejected"));
        assert!(server.is_err());
    }

    #[tokio::test]
    async fn wrong_username_rejected() {
        let (client, server) = negotiate(
            async |c| client_handshake_userpass(c, "someone-else", PASSWORD).await,
            PASSWORD,
        )
        .await;
        assert!(client.is_err());
        assert!(server.is_err());
    }

    #[tokio::test]
    async fn foreign_server_picking_no_auth_aborts() {
        let (mut c, mut s) = tokio::io::duplex(1024);
        let fake_server = async {
            let mut greeting = [0u8; 3];
            s.read_exact(&mut greeting).await.unwrap();
            // A no-auth-only server that sloppily accepts anything.
            s.write_all(&[SOCKS_VERSION, METHOD_NO_AUTH]).await.unwrap();
        };
        let (client, ()) = tokio::join!(
            client_handshake_userpass(&mut c, AUTH_USERNAME, PASSWORD),
            fake_server
        );
        let message = client.unwrap_err().to_string();
        assert!(message.contains("not offered"), "got: {message}");
    }

    #[tokio::test]
    async fn foreign_server_refusing_userpass_aborts() {
        let (mut c, mut s) = tokio::io::duplex(1024);
        let fake_server = async {
            let mut greeting = [0u8; 3];
            s.read_exact(&mut greeting).await.unwrap();
            s.write_all(&[SOCKS_VERSION, METHOD_NONE_ACCEPTABLE])
                .await
                .unwrap();
        };
        let (client, ()) = tokio::join!(
            client_handshake_userpass(&mut c, AUTH_USERNAME, PASSWORD),
            fake_server
        );
        let message = client.unwrap_err().to_string();
        assert!(message.contains("refused"), "got: {message}");
    }

    #[tokio::test]
    async fn connect_roundtrip_domain_and_ips() {
        for target in [
            Target::Domain("db.internal".into(), 5432),
            Target::Ip("10.0.0.7:80".parse().unwrap()),
            Target::Ip("[2001:db8::1]:443".parse().unwrap()),
        ] {
            let (mut c, mut s) = tokio::io::duplex(1024);
            let (sent, parsed) = tokio::join!(
                client_write_connect(&mut c, &target),
                read_connect_request(&mut s)
            );
            sent.expect("write ok");
            assert_eq!(parsed.expect("parse ok"), target);
        }
    }

    #[tokio::test]
    async fn reply_roundtrip() {
        let (mut c, mut s) = tokio::io::duplex(1024);
        let (written, rep) = tokio::join!(
            write_reply(&mut s, signaling::REP_HOST_UNREACHABLE),
            client_read_reply(&mut c)
        );
        written.expect("write ok");
        assert_eq!(rep.expect("read ok"), signaling::REP_HOST_UNREACHABLE);
    }

    #[tokio::test]
    async fn reply_consumes_ipv6_and_domain_bnd() {
        // IPv6 BND
        let (mut c, mut s) = tokio::io::duplex(1024);
        let mut raw = vec![SOCKS_VERSION, signaling::REP_SUCCESS, 0x00, ATYP_IPV6];
        raw.extend_from_slice(&[0u8; 18]); // 16-byte addr + 2-byte port
        s.write_all(&raw).await.unwrap();
        assert_eq!(client_read_reply(&mut c).await.unwrap(), signaling::REP_SUCCESS);

        // Domain BND
        let (mut c, mut s) = tokio::io::duplex(1024);
        let mut raw = vec![SOCKS_VERSION, signaling::REP_SUCCESS, 0x00, ATYP_DOMAIN, 4];
        raw.extend_from_slice(b"host");
        raw.extend_from_slice(&[0u8; 2]);
        s.write_all(&raw).await.unwrap();
        assert_eq!(client_read_reply(&mut c).await.unwrap(), signaling::REP_SUCCESS);
    }
}
