//! Client-side HTTP proxy front-end: HTTP/1.x `CONNECT` tunneling and
//! absolute-URI plain-HTTP forwarding.
//!
//! Both modes map the destination to a wire [`Target`] — a hostname becomes
//! [`Target::Domain`] (name resolution deferred), a literal IP becomes
//! [`Target::Ip`] (already an address). Where a domain is ultimately resolved is
//! decided later by the route policy, not here: a tunneled (on-list) target is
//! resolved on the **server** (flextunnel's whole point), while an off-list
//! target is dialed — and so resolved — locally (see
//! [`crate::proxy::client`]'s `direct_connect`). This mirrors the ATYP DOMAIN vs
//! IP split in [`crate::proxy::socks5::read_connect_request`].
//!
//! `CONNECT host:port` opens an opaque tunnel: answer `200`, then splice.
//!
//! Plain-HTTP requests arrive in absolute-form (`GET http://host/path
//! HTTP/1.1`, RFC 9112 §3.2.2). The head is rewritten to origin-form
//! (`GET /path`) with `Host` regenerated from the URI, hop-by-hop headers
//! stripped (RFC 9110 §7.6.1), and `Connection: close` appended — one upstream
//! connection per request; the origin closing it is what ends the exchange.
//! The request body and the whole response are relayed **verbatim** (their
//! `Content-Length`/chunked framing untouched), so no body parsing is needed
//! and the origin's response is the reply the local app sees.

use crate::proxy::signaling::{self, Target};
use std::io;
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Cap on the request line + headers buffered before the tunnel begins. Sized
/// like the auth-handshake cap in `signaling` (`MAX_HANDSHAKE_SIZE`).
const MAX_HTTP_HEADER: usize = 64 * 1024;

/// Headers never forwarded: the hop-by-hop set (RFC 9110 §7.6.1), the
/// pre-standard `Proxy-Connection`, and `Host` (regenerated from the request
/// URI, RFC 9112 §3.2.2). Headers named by a `Connection` header are stripped
/// dynamically on top of this list. `Transfer-Encoding`/`Content-Length` stay:
/// the body is relayed verbatim, so its framing must travel with it.
const STRIPPED_HEADERS: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "te",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
    "host",
];

/// A parsed request from the local HTTP proxy listener.
#[derive(Debug, PartialEq, Eq)]
pub enum HttpRequest {
    /// `CONNECT host:port` — open the tunnel, answer `200 Connection
    /// Established`, then splice raw bytes.
    Connect(Target),
    /// Absolute-URI plain-HTTP request — open the tunnel, write the rewritten
    /// origin-form `head` upstream, then splice raw bytes. The origin's
    /// response is the local app's reply, so no success response is generated
    /// locally. Any body bytes were left unread in the local socket and relay
    /// through the splice.
    Forward { target: Target, head: Vec<u8> },
}

/// Why a request can't be served: the HTTP status to answer the local app with
/// and the detail for the error returned to the caller.
struct Reject {
    code: u16,
    reason: &'static str,
    detail: String,
}

impl Reject {
    fn bad_request(detail: impl Into<String>) -> Self {
        Self {
            code: 400,
            reason: "Bad Request",
            detail: detail.into(),
        }
    }
}

/// Read an HTTP proxy request head (request line + headers, up to `\r\n\r\n`)
/// and parse it into an [`HttpRequest`] — a `CONNECT` tunnel or a rewritten
/// plain-HTTP forward.
///
/// Reads one byte at a time so it never consumes past `\r\n\r\n` — any
/// following bytes (the tunnel, or a forward's body) belong to the splice and
/// must be left in the socket. On anything that can't be served (a malformed
/// request line, a non-absolute plain-HTTP target, or oversized headers) it
/// writes the matching HTTP error response to the client before returning an
/// error, mirroring how [`crate::proxy::socks5::read_connect_request`] writes
/// its own error replies.
pub async fn read_request<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
) -> io::Result<HttpRequest> {
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

    // Reject any control byte (a bare CR/LF, NUL, tab, …) in the request line.
    // The line is split at only the first CRLF, so a smuggled control could
    // otherwise ride along in the request-target and be reintroduced into the
    // rewritten upstream head (path / Host header injection).
    if request_line.bytes().any(|b| b.is_ascii_control()) {
        write_error(stream, 400, "Bad Request").await?;
        return Err(io::Error::other("control byte in HTTP request line"));
    }

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

    // The listener speaks HTTP/1.x only: a forward is relayed in 1.x framing
    // end to end, and a CONNECT in this text form is a 1.x request too (a real
    // h2 CONNECT arrives as binary frames, which never parse this far).
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        write_error(stream, 505, "HTTP Version Not Supported").await?;
        return Err(io::Error::other(format!(
            "unsupported HTTP version: {version}"
        )));
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        // CONNECT request-target is authority-form: host:port (RFC 9110 §9.3.6);
        // the port is mandatory (no default to fall back on).
        let Some((host, port)) = split_authority(request_target, None) else {
            write_error(stream, 400, "Bad Request").await?;
            return Err(io::Error::other(format!(
                "invalid CONNECT authority: {request_target:?}"
            )));
        };
        let target = host_to_target(host, port);
        log_target("CONNECT", &target);
        return Ok(HttpRequest::Connect(target));
    }

    // Any other method is a plain-HTTP forward: rewrite the absolute-form head
    // to the origin-form head sent upstream.
    let header_block = &head[line_end + 2..head.len() - 2];
    match rewrite_forward(method, request_target, version, header_block) {
        Ok((target, head)) => {
            log_target(method, &target);
            Ok(HttpRequest::Forward { target, head })
        }
        Err(reject) => {
            write_error(stream, reject.code, reject.reason).await?;
            Err(io::Error::other(reject.detail))
        }
    }
}

/// Rewrite an absolute-form plain-HTTP request head into the origin-form head
/// to send upstream, returning it with the derived wire [`Target`].
fn rewrite_forward(
    method: &str,
    request_target: &str,
    version: &str,
    header_block: &[u8],
) -> Result<(Target, Vec<u8>), Reject> {
    // A proxied plain-HTTP request must be absolute-form (RFC 9112 §3.2.2).
    // `https://` can't appear here — TLS traffic reaches a proxy via CONNECT.
    let Some(rest) = strip_scheme(request_target, "http://") else {
        return Err(if strip_scheme(request_target, "https://").is_some() {
            Reject::bad_request(format!(
                "https absolute-URI must use CONNECT: {request_target:?}"
            ))
        } else {
            Reject::bad_request(format!(
                "request target is not an absolute http:// URI: {request_target:?}"
            ))
        });
    };
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) if rest.as_bytes()[i] == b'/' => (&rest[..i], rest[i..].to_string()),
        Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
        None => (rest, "/".to_string()),
    };
    if authority.contains('@') {
        // A client MUST NOT generate userinfo in the target (RFC 9112 §3.2.4);
        // reject rather than guess at credentials handling.
        return Err(Reject::bad_request(format!(
            "userinfo in request target: {request_target:?}"
        )));
    }
    let Some((host, port)) = split_authority(authority, Some(80)) else {
        return Err(Reject::bad_request(format!(
            "invalid authority in request target: {request_target:?}"
        )));
    };
    let target = host_to_target(host, port);

    // First pass over the headers: collect the connection options — headers the
    // client marked hop-by-hop — so the rewrite pass strips them too.
    let headers = split_header_lines(header_block)?;
    let mut connection_options: Vec<String> = Vec::new();
    for h in &headers {
        if h.name.eq_ignore_ascii_case("connection")
            || h.name.eq_ignore_ascii_case("proxy-connection")
        {
            connection_options.extend(
                String::from_utf8_lossy(h.value)
                    .split(',')
                    .map(|t| t.trim().to_ascii_lowercase()),
            );
        }
    }

    // Origin-form request line + regenerated Host, then the surviving headers —
    // rebuilt from the parsed name so tolerated-but-invalid whitespace before
    // the colon is removed (RFC 9112 §5.1) rather than replayed — then the
    // forced close so the origin ends the exchange by closing (one upstream
    // connection per request — no keep-alive reuse).
    let mut out = Vec::with_capacity(header_block.len() + 128);
    out.extend_from_slice(format!("{method} {path} {version}\r\nHost: {authority}\r\n").as_bytes());
    for h in &headers {
        let lower = h.name.to_ascii_lowercase();
        if STRIPPED_HEADERS.contains(&lower.as_str()) || connection_options.contains(&lower) {
            continue;
        }
        out.extend_from_slice(h.name.as_bytes());
        out.push(b':');
        out.extend_from_slice(h.value);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    Ok((target, out))
}

/// One parsed header line: the name (any invalid-but-tolerated whitespace
/// before the colon removed, as RFC 9112 §5.1 directs a proxy to do) and the
/// raw value bytes (leading OWS and all, so re-emitting `name:value` restores
/// the line in canonical form).
struct HeaderLine<'a> {
    name: &'a str,
    value: &'a [u8],
}

/// Split a CRLF-terminated header block into [`HeaderLine`]s. Rejects obs-fold
/// continuation lines (a proxy may answer those with `400`, RFC 9112 §5.2) and
/// lines without a colon.
fn split_header_lines(block: &[u8]) -> Result<Vec<HeaderLine<'_>>, Reject> {
    let mut out = Vec::new();
    let mut rest = block;
    while !rest.is_empty() {
        // The block is CRLF-terminated by construction (it ends right before the
        // head's final CRLF), so a missing CRLF can't happen; be defensive anyway.
        let end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .unwrap_or(rest.len());
        let line = &rest[..end];
        rest = &rest[(end + 2).min(rest.len())..];
        if line.first().is_some_and(|b| *b == b' ' || *b == b'\t') {
            return Err(Reject::bad_request(
                "obsolete header line folding is not supported".to_string(),
            ));
        }
        let malformed =
            || Reject::bad_request(format!("malformed header line: {:?}", line.escape_ascii()));
        let colon = line.iter().position(|&b| b == b':').ok_or_else(malformed)?;
        let name = std::str::from_utf8(&line[..colon])
            .map_err(|_| malformed())?
            .trim_ascii_end();
        let value = &line[colon + 1..];
        // Reject smuggled control bytes: a header name (a token) may contain
        // none, and a value must not carry CR/LF/NUL — a bare CR/LF would inject
        // an extra header line into the rewritten upstream head. HTAB and space
        // stay legal in a value (leading OWS is trimmed on re-emit by the reader).
        if name.bytes().any(|b| b.is_ascii_control())
            || value.iter().any(|&b| matches!(b, b'\r' | b'\n' | 0))
        {
            return Err(malformed());
        }
        out.push(HeaderLine { name, value });
    }
    Ok(out)
}

/// Case-insensitively strip a `scheme` prefix (e.g. `"http://"`).
fn strip_scheme<'a>(target: &'a str, scheme: &str) -> Option<&'a str> {
    let (prefix, rest) = target.split_at_checked(scheme.len())?;
    prefix.eq_ignore_ascii_case(scheme).then_some(rest)
}

/// A hostname becomes [`Target::Domain`] (name resolution deferred), a literal
/// IP [`Target::Ip`] (already an address). Whether a domain is later resolved on
/// the server (tunneled route) or locally (`direct_connect`) is up to the route
/// policy, decided after parsing.
fn host_to_target(host: &str, port: u16) -> Target {
    match host.parse::<IpAddr>() {
        Ok(ip) => Target::Ip(SocketAddr::new(ip, port)),
        Err(_) => Target::Domain(host.to_string(), port),
    }
}

/// Log the parsed target type (hostname vs literal IP) and the specific
/// destination only at debug, matching the SOCKS5 handler so default logs don't
/// leak user destinations. Where a hostname is ultimately resolved (server for a
/// tunneled route, locally for a direct one) is decided later by the route
/// policy, so it's not reported here.
fn log_target(what: &str, target: &Target) {
    match target {
        Target::Domain(host, port) => {
            log::debug!("HTTP {what} — hostname (name resolution deferred to route)");
            log::debug!("HTTP {what} target {host}:{port}");
        }
        Target::Ip(addr) => {
            log::debug!("HTTP {what} — literal IP");
            log::debug!("HTTP {what} target {addr}");
        }
    }
}

/// Split an authority `host[:port]` into its parts, handling bracketed IPv6
/// literals (`[::1]:443`). A missing port falls back to `default_port`; `None`
/// (CONNECT, where the port is mandatory) makes it an error. Returns `None` on
/// a missing/empty host, a malformed or non-numeric port, or port 0.
fn split_authority(authority: &str, default_port: Option<u16>) -> Option<(&str, u16)> {
    let (host, port_str) = if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal: [addr][:port] — host is the address without the brackets.
        let (addr, after) = rest.split_once(']')?;
        match after {
            "" => (addr, None),
            _ => (addr, Some(after.strip_prefix(':')?)),
        }
    } else {
        match authority.rsplit_once(':') {
            // A colon still in the host means a raw IPv6 literal (or garbage):
            // the host/port split is ambiguous, so require brackets.
            Some((host, _)) if host.contains(':') => return None,
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return None;
    }
    match port_str {
        Some(p) => match p.parse::<u16>() {
            Ok(0) | Err(_) => None,
            Ok(port) => Some((host, port)),
        },
        None => Some((host, default_port?)),
    }
}

/// Answer the local app with the HTTP response for server reply code `rep`.
///
/// [`signaling::REP_SUCCESS`] becomes `200 Connection Established` (after which
/// the socket is an opaque tunnel); other codes map to an HTTP error status.
/// Only the tunnel (CONNECT) path sends the success response — a forward's
/// success reply is the origin's own response.
pub async fn write_reply<S: AsyncWriteExt + Unpin>(stream: &mut S, rep: u8) -> io::Result<()> {
    if rep == signaling::REP_SUCCESS {
        return stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await;
    }
    let (code, reason) = match rep {
        signaling::REP_NOT_ALLOWED => (403, "Forbidden"),
        // Timeouts, refusals, unreachable, and general failures all surface as a
        // bad-gateway to the local app.
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

    /// Drive `read_request` with `request`, returning its result and any bytes
    /// it wrote back to the client (the error response, if any).
    async fn run(request: &[u8]) -> (io::Result<HttpRequest>, String) {
        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(request).await.unwrap();
        let result = read_request(&mut server).await;
        drop(server);
        let mut resp = Vec::new();
        let _ = client.read_to_end(&mut resp).await;
        (result, String::from_utf8_lossy(&resp).into_owned())
    }

    /// `run` for requests expected to parse into a forward; returns the target
    /// and the rewritten head as a string.
    async fn run_forward(request: &[u8]) -> (Target, String) {
        let (result, resp) = run(request).await;
        match result.unwrap() {
            HttpRequest::Forward { target, head } => {
                assert!(resp.is_empty(), "no local response expected, got: {resp:?}");
                (target, String::from_utf8(head).unwrap())
            }
            other => panic!("expected a forward, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn connect_domain_is_server_resolved() {
        let (target, _) =
            run(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n").await;
        assert_eq!(
            target.unwrap(),
            HttpRequest::Connect(Target::Domain("example.com".to_string(), 443))
        );
    }

    #[tokio::test]
    async fn connect_ipv4_literal_is_ip() {
        let (target, _) = run(b"CONNECT 93.184.216.34:443 HTTP/1.1\r\n\r\n").await;
        assert_eq!(
            target.unwrap(),
            HttpRequest::Connect(Target::Ip("93.184.216.34:443".parse().unwrap()))
        );
    }

    #[tokio::test]
    async fn connect_ipv6_literal_is_ip() {
        let (target, _) = run(b"CONNECT [::1]:80 HTTP/1.1\r\n\r\n").await;
        assert_eq!(
            target.unwrap(),
            HttpRequest::Connect(Target::Ip("[::1]:80".parse().unwrap()))
        );
    }

    #[tokio::test]
    async fn unbracketed_ipv6_authority_is_400() {
        // "::1:443" is itself a valid IPv6 address — the host/port split is
        // ambiguous without brackets, so it must be rejected, not guessed.
        let (target, resp) = run(b"CONNECT ::1:443 HTTP/1.1\r\n\r\n").await;
        assert!(target.is_err());
        assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp:?}");

        let (target, resp) = run(b"GET http://foo:bar:80/ HTTP/1.1\r\n\r\n").await;
        assert!(target.is_err(), "colon-bearing host must not become a Domain");
        assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp:?}");
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
        let err = read_request(&mut server).await.unwrap_err();
        assert!(err.to_string().contains("size cap"), "got: {err}");
    }

    #[tokio::test]
    async fn absolute_uri_get_is_rewritten_to_origin_form() {
        let (target, head) = run_forward(
            b"GET http://example.com/path?q=1 HTTP/1.1\r\n\
              Host: stale.example\r\n\
              Accept: */*\r\n\
              Proxy-Connection: keep-alive\r\n\r\n",
        )
        .await;
        assert_eq!(target, Target::Domain("example.com".to_string(), 80));
        assert_eq!(
            head,
            "GET /path?q=1 HTTP/1.1\r\n\
             Host: example.com\r\n\
             Accept: */*\r\n\
             Connection: close\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn forward_explicit_port_and_bare_authority() {
        // No path → "/", and the URI's explicit port survives in Host + target.
        let (target, head) = run_forward(b"GET http://example.com:8080 HTTP/1.1\r\n\r\n").await;
        assert_eq!(target, Target::Domain("example.com".to_string(), 8080));
        assert!(
            head.starts_with("GET / HTTP/1.1\r\nHost: example.com:8080\r\n"),
            "got: {head:?}"
        );
    }

    #[tokio::test]
    async fn forward_query_without_path_gets_slash() {
        let (_, head) = run_forward(b"GET http://example.com?q=1 HTTP/1.1\r\n\r\n").await;
        assert!(head.starts_with("GET /?q=1 HTTP/1.1\r\n"), "got: {head:?}");
    }

    #[tokio::test]
    async fn forward_ip_literals() {
        let (target, _) = run_forward(b"GET http://127.0.0.1:8080/x HTTP/1.1\r\n\r\n").await;
        assert_eq!(target, Target::Ip("127.0.0.1:8080".parse().unwrap()));

        let (target, head) = run_forward(b"GET http://[::1]/x HTTP/1.1\r\n\r\n").await;
        assert_eq!(target, Target::Ip("[::1]:80".parse().unwrap()));
        assert!(head.contains("Host: [::1]\r\n"), "got: {head:?}");
    }

    #[tokio::test]
    async fn forward_strips_connection_named_headers() {
        // "Connection: keep-alive, x-hop" marks X-Hop hop-by-hop; body framing
        // headers survive because the body is relayed verbatim.
        let (_, head) = run_forward(
            b"POST http://example.com/upload HTTP/1.1\r\n\
              Connection: keep-alive, x-hop\r\n\
              X-Hop: secret\r\n\
              Keep-Alive: timeout=5\r\n\
              Proxy-Authorization: Basic Zm9v\r\n\
              Transfer-Encoding: chunked\r\n\
              User-Agent: test\r\n\r\n",
        )
        .await;
        assert_eq!(
            head,
            "POST /upload HTTP/1.1\r\n\
             Host: example.com\r\n\
             Transfer-Encoding: chunked\r\n\
             User-Agent: test\r\n\
             Connection: close\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn forward_leaves_body_bytes_in_the_stream() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        client
            .write_all(
                b"POST http://example.com/ HTTP/1.1\r\nContent-Length: 4\r\n\r\nBODY",
            )
            .await
            .unwrap();
        let req = read_request(&mut server).await.unwrap();
        assert!(matches!(req, HttpRequest::Forward { .. }));
        let mut body = [0u8; 4];
        server.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"BODY");
    }

    #[tokio::test]
    async fn forward_http10_version_is_echoed() {
        let (_, head) = run_forward(b"GET http://example.com/ HTTP/1.0\r\n\r\n").await;
        assert!(head.starts_with("GET / HTTP/1.0\r\n"), "got: {head:?}");
    }

    #[tokio::test]
    async fn https_absolute_uri_is_400() {
        let (target, resp) = run(b"GET https://example.com/ HTTP/1.1\r\n\r\n").await;
        assert!(target.is_err());
        assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp:?}");
    }

    #[tokio::test]
    async fn origin_form_target_is_400() {
        let (target, resp) = run(b"GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
        assert!(target.is_err());
        assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp:?}");
    }

    #[tokio::test]
    async fn userinfo_in_target_is_400() {
        let (target, resp) = run(b"GET http://user:pw@example.com/ HTTP/1.1\r\n\r\n").await;
        assert!(target.is_err());
        assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp:?}");
    }

    #[tokio::test]
    async fn non_http1x_version_is_505() {
        let (target, resp) = run(b"GET http://example.com/ HTTP/2.0\r\n\r\n").await;
        assert!(target.is_err());
        assert!(resp.starts_with("HTTP/1.1 505"), "got: {resp:?}");

        // CONNECT is gated by the same version check as forwards.
        let (target, resp) = run(b"CONNECT example.com:443 HTTP/2.0\r\n\r\n").await;
        assert!(target.is_err());
        assert!(resp.starts_with("HTTP/1.1 505"), "got: {resp:?}");
    }

    #[tokio::test]
    async fn forward_normalizes_whitespace_before_header_colon() {
        // Whitespace between name and colon is invalid; a proxy removes it
        // (RFC 9112 §5.1) instead of replaying the raw line.
        let (_, head) =
            run_forward(b"GET http://example.com/ HTTP/1.1\r\nX-Test : value\r\n\r\n").await;
        assert!(head.contains("X-Test: value\r\n"), "got: {head:?}");
        assert!(!head.contains("X-Test :"), "got: {head:?}");
    }

    #[tokio::test]
    async fn control_byte_in_request_target_is_400() {
        // A bare LF in the request target must not survive into the rewritten
        // upstream head (request-line / Host injection).
        let (target, resp) = run(b"GET http://example.com/a\nfoo HTTP/1.1\r\n\r\n").await;
        assert!(target.is_err());
        assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp:?}");
    }

    #[tokio::test]
    async fn control_byte_in_header_value_is_400() {
        // A bare LF in a header value would inject a new header line upstream.
        let (target, resp) =
            run(b"GET http://example.com/ HTTP/1.1\r\nX-Foo: bar\nEvil: baz\r\n\r\n").await;
        assert!(target.is_err());
        assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp:?}");
    }

    #[tokio::test]
    async fn obs_fold_header_is_400() {
        let (target, resp) = run(
            b"GET http://example.com/ HTTP/1.1\r\nX-Long: a\r\n b\r\n\r\n",
        )
        .await;
        assert!(target.is_err());
        assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp:?}");
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
