//! Client-side SOCKS5 (RFC 1928): method negotiation, CONNECT request parsing,
//! and reply writing. Only the no-auth method and the CONNECT command are
//! supported (TCP only — no BIND, no UDP ASSOCIATE).

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

/// Perform the SOCKS5 greeting/method negotiation, selecting no-auth.
///
/// Reads `[VER, NMETHODS, METHODS..]`; if the client offers the no-auth method
/// replies `[0x05, 0x00]`, otherwise replies `[0x05, 0xFF]` and errors.
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

/// Read and parse a SOCKS5 CONNECT request, returning the wire [`Target`].
///
/// On a non-CONNECT command or an unsupported address type, writes the matching
/// SOCKS5 reply to the client before returning an error.
pub async fn read_connect_request<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
) -> io::Result<Target> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    let [ver, cmd, _rsv, atyp] = head;

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
            let host = String::from_utf8(host)
                .map_err(|_| io::Error::other("SOCKS5 domain is not valid UTF-8"))?;
            Target::Domain(host, port)
        }
        other => {
            write_reply(stream, signaling::REP_ATYP_NOT_SUPPORTED).await?;
            return Err(io::Error::other(format!(
                "unsupported SOCKS5 address type: 0x{other:02x}"
            )));
        }
    };
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
