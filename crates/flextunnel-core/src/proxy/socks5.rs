//! SOCKS5 (RFC 1928) for the local front-end: method negotiation, CONNECT
//! request parsing, and reply writing on the server side, plus a client-side
//! dialer (`client_*`) used by the desktop port forwarder to relay through the
//! local listener. No-auth only; CONNECT command only (TCP — no BIND, no UDP
//! ASSOCIATE).
//!
//! There is no authentication (everything is loopback and trusted). The port
//! forwarder guards against accidentally reaching some *other* SOCKS5 server
//! on the port (another flextunnel instance, an `ssh -D`) by fetching
//! `http://flextunnel.internal/status.json` through the proxy and checking the
//! reported server node id — see the desktop forwarder module.

use crate::proxy::signaling::{self, Target};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SOCKS_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;

// SOCKS5 ATYP values (RFC 1928).
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// Perform the SOCKS5 greeting/method negotiation.
///
/// Reads `[VER, NMETHODS, METHODS..]`. A client offering no-auth (0x00)
/// proceeds (browsers, curl, the port forwarders). Anything else gets
/// `[0x05, 0xFF]` and an error.
pub async fn negotiate_method<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
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

    if methods.contains(&METHOD_NO_AUTH) {
        stream.write_all(&[SOCKS_VERSION, METHOD_NO_AUTH]).await?;
        Ok(())
    } else {
        stream
            .write_all(&[SOCKS_VERSION, METHOD_NONE_ACCEPTABLE])
            .await?;
        Err(io::Error::other("client offered no acceptable SOCKS5 method"))
    }
}

/// Client side: greet offering only the no-auth method and require the server
/// to select it. A wrong greeting version, a `0xFF` refusal, or a method that
/// was never offered all map to "this is not a plain SOCKS5 listener".
pub async fn client_handshake_noauth<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
) -> io::Result<()> {
    stream.write_all(&[SOCKS_VERSION, 1, METHOD_NO_AUTH]).await?;
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).await?;
    let [ver, method] = choice;
    if ver != SOCKS_VERSION {
        return Err(io::Error::other(format!(
            "not a SOCKS5 server (greeting version 0x{ver:02x})"
        )));
    }
    match method {
        METHOD_NO_AUTH => Ok(()),
        METHOD_NONE_ACCEPTABLE => Err(io::Error::other(
            "SOCKS5 server refused the no-auth method — an authenticating SOCKS5 \
             server (not this app) is on this port",
        )),
        other => Err(io::Error::other(format!(
            "SOCKS5 server selected method 0x{other:02x} that was not offered — \
             another SOCKS5 server (not this app) is on this port"
        ))),
    }
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

    #[tokio::test]
    async fn noauth_roundtrip() {
        let (mut c, mut s) = tokio::io::duplex(1024);
        let (client, server) =
            tokio::join!(client_handshake_noauth(&mut c), negotiate_method(&mut s));
        client.expect("client ok");
        server.expect("server ok");
    }

    #[tokio::test]
    async fn server_rejects_authenticating_client() {
        // A client offering only username/password (0x02) gets 0xFF.
        let (mut c, mut s) = tokio::io::duplex(1024);
        let client = async {
            c.write_all(&[SOCKS_VERSION, 1, 0x02]).await?;
            let mut choice = [0u8; 2];
            c.read_exact(&mut choice).await?;
            assert_eq!(choice, [SOCKS_VERSION, METHOD_NONE_ACCEPTABLE]);
            io::Result::Ok(())
        };
        let (client, server) = tokio::join!(client, negotiate_method(&mut s));
        client.expect("client ok");
        assert!(server.unwrap_err().to_string().contains("no acceptable"));
    }

    #[tokio::test]
    async fn foreign_server_refusing_noauth_aborts() {
        let (mut c, mut s) = tokio::io::duplex(1024);
        let fake_server = async {
            let mut greeting = [0u8; 3];
            s.read_exact(&mut greeting).await.unwrap();
            s.write_all(&[SOCKS_VERSION, METHOD_NONE_ACCEPTABLE])
                .await
                .unwrap();
        };
        let (client, ()) = tokio::join!(client_handshake_noauth(&mut c), fake_server);
        let message = client.unwrap_err().to_string();
        assert!(message.contains("refused"), "got: {message}");
    }

    #[tokio::test]
    async fn foreign_server_picking_unoffered_method_aborts() {
        let (mut c, mut s) = tokio::io::duplex(1024);
        let fake_server = async {
            let mut greeting = [0u8; 3];
            s.read_exact(&mut greeting).await.unwrap();
            s.write_all(&[SOCKS_VERSION, 0x02]).await.unwrap();
        };
        let (client, ()) = tokio::join!(client_handshake_noauth(&mut c), fake_server);
        let message = client.unwrap_err().to_string();
        assert!(message.contains("not offered"), "got: {message}");
    }

    #[tokio::test]
    async fn non_socks_server_aborts() {
        let (mut c, mut s) = tokio::io::duplex(1024);
        let fake_server = async {
            let mut greeting = [0u8; 3];
            s.read_exact(&mut greeting).await.unwrap();
            // An HTTP server would start its response with 'H' (0x48).
            s.write_all(b"HT").await.unwrap();
        };
        let (client, ()) = tokio::join!(client_handshake_noauth(&mut c), fake_server);
        let message = client.unwrap_err().to_string();
        assert!(message.contains("not a SOCKS5 server"), "got: {message}");
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
