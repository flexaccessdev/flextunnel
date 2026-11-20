//! The server status page, plus the small HTTP/1.1 plumbing it shares with the
//! client's own status endpoint ([`super::client_status`]).
//!
//! The status page reflects the **server's** live routing config, so it is
//! rendered server-side (with askama) and written back as opaque HTTP bytes
//! over a QUIC stream opened with [`signaling::StreamRequest::Status`]. A
//! client reaches it at `http://flextunnel.internal/servers/<destination>/` —
//! the client's own endpoint, which opens that stream on demand and splices
//! the response to the local app. HTTPS is not terminated — this is HTTP-only.

use askama::Template;
use serde::Serialize;
use std::io;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::proxy::signaling;

/// Plain-text variant of a status page.
pub const STATUS_TEXT_PATH: &str = "/status.txt";
/// JSON variant of a status page.
pub const STATUS_JSON_PATH: &str = "/status.json";

pub(crate) const CONTENT_TYPE_HTML: &str = "text/html; charset=utf-8";
pub(crate) const CONTENT_TYPE_TEXT: &str = "text/plain; charset=utf-8";
pub(crate) const CONTENT_TYPE_JSON: &str = "application/json; charset=utf-8";

/// Cap on the HTTP request head read from a status request.
pub(crate) const REQUEST_HEAD_LIMIT: usize = 64 * 1024;
/// Deadline for reading a status request's whole head (and, on the server,
/// for draining what follows it): a peer that neither sends nor closes — or
/// that trickles a byte at a time — must not pin the task.
pub(crate) const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// The blank line that ends an HTTP request head.
const HEAD_END: &[u8] = b"\r\n\r\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatusFormat {
    Html,
    Text,
    Json,
}

/// One configured outbound bridge plus whether its upstream connection to the
/// target server is live right now.
#[derive(Serialize)]
pub struct BridgeUpstreamStatus {
    pub name: String,
    pub endpoint_id: String,
    pub domains: Vec<String>,
    pub cidrs: Vec<String>,
    pub connected: bool,
}

/// One allowlisted inbound bridge server plus whether it is connected right now.
#[derive(Serialize)]
pub struct BridgeInboundStatus {
    pub endpoint_id: String,
    pub connected: bool,
}

/// The server status page. Fields are populated from the live `ProxyServer`
/// state; secrets are never included and the blocklist is shown as counts only.
#[derive(Template)]
#[template(path = "server_status.html")]
pub struct ServerStatusTemplate {
    pub version: &'static str,
    pub node_id: String,
    pub routed_domains: Vec<String>,
    pub routed_cidrs: Vec<String>,
    /// `(alias, target)` pairs, sorted for stable output.
    pub host_aliases: Vec<(String, String)>,
    /// Conditional DNS forwards as `(suffix, upstream servers)` pairs, sorted by
    /// suffix for stable output.
    pub dns_forwards: Vec<(String, Vec<String>)>,
    /// Outbound bridge routes with live connected state, sorted by name.
    pub bridges: Vec<BridgeUpstreamStatus>,
    /// Allowlisted inbound bridge servers with live connected state, sorted by
    /// endpoint id.
    pub inbound_bridges: Vec<BridgeInboundStatus>,
    pub blocklist_path: String,
    pub blocked_client_count: usize,
    pub conflicted_server_count: usize,
}

/// The `*.flextunnel.internal` "reserved for future use" page, served by the
/// client (see [`super::client_status`]).
#[derive(Template)]
#[template(path = "reserved_404.html")]
pub struct ReservedNotFoundTemplate;

#[derive(Template)]
#[template(path = "server_status.txt")]
struct ServerStatusTextTemplate<'a> {
    tpl: &'a ServerStatusTemplate,
}

#[derive(Serialize)]
struct ServerStatusJson<'a> {
    version: &'static str,
    server_node_id: &'a str,
    routed_domains: &'a [String],
    routed_cidrs: &'a [String],
    host_aliases: Vec<HostAliasJson<'a>>,
    dns_forwards: Vec<DnsForwardJson<'a>>,
    bridges: &'a [BridgeUpstreamStatus],
    inbound_bridges: &'a [BridgeInboundStatus],
    duplicate_id_blocklist: DuplicateIdBlocklistJson<'a>,
}

#[derive(Serialize)]
struct HostAliasJson<'a> {
    name: &'a str,
    target: &'a str,
}

#[derive(Serialize)]
struct DnsForwardJson<'a> {
    suffix: &'a str,
    servers: &'a [String],
}

#[derive(Serialize)]
struct DuplicateIdBlocklistJson<'a> {
    file: &'a str,
    blocked_clients: usize,
    conflicted_servers: usize,
}

/// Fallback body used if a template fails to render (should not happen with
/// compiled templates, but we never drop the stream uncleanly over it).
const FALLBACK_BODY: &str =
    "<!DOCTYPE html><title>flextunnel</title><p>status page unavailable</p>";
const FALLBACK_TEXT_BODY: &str = "flextunnel server status unavailable\n";
const FALLBACK_JSON_BODY: &str = "{\"error\":\"flextunnel server status unavailable\"}\n";

/// Render the status page, falling back to a 500 on the (unexpected) render
/// error. Returns `(http_status_line, content_type, body)`.
pub fn render_status(
    tpl: &ServerStatusTemplate,
    format: StatusFormat,
) -> (&'static str, &'static str, String) {
    match format {
        StatusFormat::Html => match tpl.render() {
            Ok(body) => ("200 OK", CONTENT_TYPE_HTML, body),
            Err(e) => {
                log::warn!("Failed to render status page: {e}");
                (
                    "500 Internal Server Error",
                    CONTENT_TYPE_HTML,
                    FALLBACK_BODY.to_string(),
                )
            }
        },
        StatusFormat::Text => match render_status_text(tpl) {
            Ok(body) => ("200 OK", CONTENT_TYPE_TEXT, body),
            Err(e) => {
                log::warn!("Failed to render status text page: {e}");
                (
                    "500 Internal Server Error",
                    CONTENT_TYPE_TEXT,
                    FALLBACK_TEXT_BODY.to_string(),
                )
            }
        },
        StatusFormat::Json => match render_status_json(tpl) {
            Ok(body) => ("200 OK", CONTENT_TYPE_JSON, body),
            Err(e) => {
                log::warn!("Failed to render status JSON page: {e}");
                (
                    "500 Internal Server Error",
                    CONTENT_TYPE_JSON,
                    FALLBACK_JSON_BODY.to_string(),
                )
            }
        },
    }
}

fn render_status_text(tpl: &ServerStatusTemplate) -> Result<String, askama::Error> {
    ServerStatusTextTemplate { tpl }.render()
}

fn render_status_json(tpl: &ServerStatusTemplate) -> Result<String, serde_json::Error> {
    let host_aliases = tpl
        .host_aliases
        .iter()
        .map(|(name, target)| HostAliasJson { name, target })
        .collect();
    let dns_forwards = tpl
        .dns_forwards
        .iter()
        .map(|(suffix, servers)| DnsForwardJson { suffix, servers })
        .collect();
    let payload = ServerStatusJson {
        version: tpl.version,
        server_node_id: &tpl.node_id,
        routed_domains: &tpl.routed_domains,
        routed_cidrs: &tpl.routed_cidrs,
        host_aliases,
        dns_forwards,
        bridges: &tpl.bridges,
        inbound_bridges: &tpl.inbound_bridges,
        duplicate_id_blocklist: DuplicateIdBlocklistJson {
            file: &tpl.blocklist_path,
            blocked_clients: tpl.blocked_client_count,
            conflicted_servers: tpl.conflicted_server_count,
        },
    };
    serde_json::to_string_pretty(&payload).map(|mut body| {
        body.push('\n');
        body
    })
}

/// Render the reserved-subdomain 404 page.
pub fn render_reserved_404() -> (&'static str, &'static str, String) {
    let body = ReservedNotFoundTemplate
        .render()
        .unwrap_or_else(|_| FALLBACK_BODY.to_string());
    ("404 Not Found", CONTENT_TYPE_HTML, body)
}

/// Write the per-stream success byte that lets the client start relaying.
pub async fn write_tunnel_success<W: AsyncWrite + Unpin>(send: &mut W) -> io::Result<()> {
    signaling::write_reply(send, signaling::REP_SUCCESS).await?;
    send.flush().await
}

/// Write a complete HTTP/1.1 response. `Connection: close` and a
/// `Content-Length` let the browser complete the response; the caller then
/// ends the stream (finishing a QUIC send half, or closing the socket) to
/// signal EOF.
pub async fn write_http_payload<W: AsyncWrite + Unpin>(
    send: &mut W,
    status_line: &str,
    content_type: &str,
    body: &str,
) -> io::Result<()> {
    write_http_response(send, status_line, content_type, "", body).await
}

/// [`write_http_payload`] with further header lines, each ending in CRLF.
pub(crate) async fn write_http_response<W: AsyncWrite + Unpin>(
    send: &mut W,
    status_line: &str,
    content_type: &str,
    extra_headers: &str,
    body: &str,
) -> io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status_line}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         {extra_headers}\
         Connection: close\r\n\
         \r\n{body}",
        body.len(),
    );
    send.write_all(response.as_bytes()).await?;
    send.flush().await
}

/// Read an HTTP request head from `recv`, through its blank line and no
/// further: bytes of a body that arrived in the same read are left out, so a
/// request parses the same however the peer's writes were split. Bounded by
/// [`REQUEST_HEAD_LIMIT`] and by [`REQUEST_READ_TIMEOUT`] for the whole head.
/// When the peer stalls, closes early or overruns the cap, what arrived is
/// returned without its blank line — which [`parse_status_request`] refuses.
pub(crate) async fn read_request_head<R: AsyncRead + Unpin>(recv: &mut R) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + REQUEST_READ_TIMEOUT;
    let mut head = Vec::with_capacity(512);
    let mut buf = [0u8; 1024];
    while head.len() < REQUEST_HEAD_LIMIT {
        let read_len = buf.len().min(REQUEST_HEAD_LIMIT - head.len());
        match tokio::time::timeout_at(deadline, recv.read(&mut buf[..read_len])).await {
            Ok(Ok(n)) if n > 0 => {
                // Only the new bytes, plus the few before them a blank line
                // could straddle, have not been looked at yet.
                let from = head.len().saturating_sub(HEAD_END.len() - 1);
                head.extend_from_slice(&buf[..n]);
                if let Some(end) = find_head_end(&head[from..]) {
                    head.truncate(from + end);
                    break;
                }
            }
            // EOF, read error, or the deadline.
            _ => break,
        }
    }
    head
}

/// The length of `bytes` through its first blank line, if it has one.
fn find_head_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(HEAD_END.len())
        .position(|window| window == HEAD_END)
        .map(|at| at + HEAD_END.len())
}

/// The parts of an HTTP request head a status endpoint acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StatusRequest {
    /// The request method as sent — methods are case-sensitive, so only an
    /// exact `GET` is one.
    pub method: String,
    /// The request path without its query — `/` for an absolute-URI target
    /// with no path (`http://flextunnel.internal`).
    pub path: String,
    /// The format the `Accept` header prefers, if it names one we serve.
    pub accept: Option<StatusFormat>,
}

/// Parse a request head into a [`StatusRequest`]. `None` for anything that is
/// not a whole HTTP request head: no blank line (the peer stalled or closed
/// part-way), not UTF-8, or a first line that is not `METHOD target
/// HTTP/x.y`. Bytes after the blank line are not looked at.
pub(crate) fn parse_status_request(head: &[u8]) -> Option<StatusRequest> {
    let head = &head[..find_head_end(head)?];
    let head = std::str::from_utf8(head).ok()?;
    let mut lines = head.split("\r\n");
    let mut parts = lines.next()?.split(' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    if method.is_empty() || target.is_empty() || !version.starts_with("HTTP/") || parts.next().is_some()
    {
        return None;
    }
    // The most preferred format any `Accept` line names, the first on a tie.
    let mut accept: Option<(f32, StatusFormat)> = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.eq_ignore_ascii_case("accept") {
            continue;
        }
        if let Some(preferred) = preferred_format(value)
            && accept.is_none_or(|(q, _)| preferred.0 > q)
        {
            accept = Some(preferred);
        }
    }
    Some(StatusRequest {
        method: method.to_string(),
        path: request_target_path(target).to_string(),
        accept: accept.map(|(_, format)| format),
    })
}

/// The format a status request asks for: the path's (`/status.txt`,
/// `/status.json`) when it names one, else the `Accept` header's, else HTML.
pub(crate) fn status_format_for(path_tail: &str, accept: Option<StatusFormat>) -> StatusFormat {
    match path_tail {
        STATUS_TEXT_PATH => StatusFormat::Text,
        STATUS_JSON_PATH => StatusFormat::Json,
        _ => accept.unwrap_or(StatusFormat::Html),
    }
}

/// The path of a request target, without its query. Handles both the
/// origin-form (`/status.json?x=1`) and the absolute-form
/// (`http://flextunnel.internal/status.json`) a plain-HTTP proxy request uses.
fn request_target_path(target: &str) -> &str {
    let path = if let Some(rest) = strip_http_scheme(target) {
        match rest.find(['/', '?']) {
            Some(i) if rest[i..].starts_with('/') => &rest[i..],
            _ => "/",
        }
    } else {
        target
    };
    path.split_once('?').map_or(path, |(path, _)| path)
}

/// The format an `Accept` header value prefers among the three served, with
/// its quality: the highest `q` wins (1 when absent), the first listed on a
/// tie, and `q=0` — "not acceptable" — never. Media ranges (`*/*`, `text/*`)
/// name no format, so a client sending only those gets the default.
fn preferred_format(value: &str) -> Option<(f32, StatusFormat)> {
    let mut best: Option<(f32, StatusFormat)> = None;
    for part in value.split(',') {
        let mut params = part.split(';');
        let media_type = params.next().unwrap_or_default().trim();
        let format = if media_type.eq_ignore_ascii_case("application/json") {
            StatusFormat::Json
        } else if media_type.eq_ignore_ascii_case("text/plain") {
            StatusFormat::Text
        } else if media_type.eq_ignore_ascii_case("text/html") {
            StatusFormat::Html
        } else {
            continue;
        };
        // An unreadable weight is no preference for the type at all.
        let quality = params
            .find_map(|param| {
                let (name, value) = param.split_once('=')?;
                name.trim()
                    .eq_ignore_ascii_case("q")
                    .then(|| value.trim().parse::<f32>().unwrap_or(0.0))
            })
            .unwrap_or(1.0)
            .min(1.0);
        if quality > 0.0 && best.is_none_or(|(q, _)| quality > q) {
            best = Some((quality, format));
        }
    }
    best
}

fn strip_http_scheme(target: &str) -> Option<&str> {
    let (prefix, rest) = target.split_at_checked("http://".len())?;
    prefix.eq_ignore_ascii_case("http://").then_some(rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(head: &str) -> StatusRequest {
        parse_status_request(head.as_bytes()).unwrap_or_else(|| panic!("{head:?} should parse"))
    }

    #[test]
    fn request_line_forms_yield_the_path() {
        assert_eq!(parse("GET / HTTP/1.1\r\n\r\n").path, "/");
        assert_eq!(parse("GET /status.json?x=1 HTTP/1.1\r\n\r\n").path, "/status.json");
        assert_eq!(parse("GET http://flextunnel.internal HTTP/1.1\r\n\r\n").path, "/");
        assert_eq!(
            parse("GET HTTP://flextunnel.internal/servers/m1/status.txt?q HTTP/1.1\r\n\r\n"),
            StatusRequest {
                method: "GET".to_string(),
                path: "/servers/m1/status.txt".to_string(),
                accept: None,
            }
        );
        // The method is kept as sent, for the caller's exact `GET` check.
        assert_eq!(parse("get / HTTP/1.1\r\n\r\n").method, "get");
        assert_eq!(parse("POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n").method, "POST");
    }

    /// Anything short of a whole request head is an error, not a `GET /`.
    #[test]
    fn incomplete_and_malformed_heads_do_not_parse() {
        for head in [
            "",
            "GET / HTTP/1.1\r\n",
            "GET / HTTP/1.1\r\nHost: flextunnel.internal\r\n",
            "GET /\r\n\r\n",
            "GET\r\n\r\n",
            "GET / FTP/1.1\r\n\r\n",
            "GET  / HTTP/1.1\r\n\r\n",
            "GET / HTTP/1.1 extra\r\n\r\n",
            "\r\n\r\n",
        ] {
            assert_eq!(parse_status_request(head.as_bytes()), None, "{head:?}");
        }
        assert_eq!(parse_status_request(&[0xff, 0xfe, b'\r', b'\n', b'\r', b'\n']), None);
    }

    /// What follows the blank line is a body, never headers.
    #[test]
    fn a_body_is_not_read_as_headers() {
        let request = "POST / HTTP/1.1\r\nContent-Length: 26\r\n\r\nAccept: application/json\r\n";
        let parsed = parse(request);
        assert_eq!((parsed.method.as_str(), parsed.accept), ("POST", None));
    }

    #[test]
    fn format_prefers_the_path_then_accept_then_html() {
        let json = parse("GET / HTTP/1.1\r\nAccept: application/json, text/html;q=0.9\r\n\r\n");
        assert_eq!(json.accept, Some(StatusFormat::Json));
        assert_eq!(status_format_for("/", json.accept), StatusFormat::Json);
        // The path names a format outright, whatever `Accept` says.
        assert_eq!(status_format_for(STATUS_TEXT_PATH, json.accept), StatusFormat::Text);
        assert_eq!(status_format_for(STATUS_JSON_PATH, Some(StatusFormat::Html)), StatusFormat::Json);
        assert_eq!(status_format_for(STATUS_JSON_PATH, None), StatusFormat::Json);
        assert_eq!(status_format_for("/", None), StatusFormat::Html);
        let text = parse("GET / HTTP/1.1\r\naccept: TEXT/PLAIN\r\n\r\n");
        assert_eq!(text.accept, Some(StatusFormat::Text));
    }

    #[test]
    fn accept_weights_are_honored() {
        let accept = |value: &str| parse(&format!("GET / HTTP/1.1\r\nAccept: {value}\r\n\r\n")).accept;
        // The heaviest served type wins, wherever it is listed.
        assert_eq!(accept("text/html, application/json;q=0.9"), Some(StatusFormat::Html));
        assert_eq!(accept("text/plain;q=0.5, application/json;q=0.8"), Some(StatusFormat::Json));
        assert_eq!(accept("application/json; Q=0.2 , text/plain; q=0.3"), Some(StatusFormat::Text));
        // A tie goes to the first listed.
        assert_eq!(accept("text/plain, application/json"), Some(StatusFormat::Text));
        // `q=0` is "not acceptable", and an unreadable weight is no preference.
        assert_eq!(accept("application/json;q=0, text/plain"), Some(StatusFormat::Text));
        assert_eq!(accept("application/json;q=0"), None);
        assert_eq!(accept("application/json;q=high, text/plain;q=0.1"), Some(StatusFormat::Text));
        // What a browser sends, and ranges alone: the default (HTML).
        assert_eq!(
            accept("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
            Some(StatusFormat::Html)
        );
        assert_eq!(accept("*/*"), None);
        // Several `Accept` lines are one list.
        let two = parse("GET / HTTP/1.1\r\nAccept: text/plain;q=0.4\r\nAccept: application/json;q=0.6\r\n\r\n");
        assert_eq!(two.accept, Some(StatusFormat::Json));
    }

    /// The head reader stops at the blank line — body bytes that came in the
    /// same read stay out — and gives the whole head one deadline.
    #[tokio::test(start_paused = true)]
    async fn the_head_reader_stops_at_the_blank_line_and_the_deadline() {
        let mut one_read: &[u8] = b"POST / HTTP/1.1\r\nA: b\r\n\r\nbody";
        assert_eq!(read_request_head(&mut one_read).await, b"POST / HTTP/1.1\r\nA: b\r\n\r\n");

        // The blank line split across two reads is still found.
        let (mut peer, mut ours) = tokio::io::duplex(64);
        let writer = tokio::spawn(async move {
            peer.write_all(b"GET / HTTP/1.1\r\n\r").await.unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
            peer.write_all(b"\nrest").await.unwrap();
            peer
        });
        assert_eq!(read_request_head(&mut ours).await, b"GET / HTTP/1.1\r\n\r\n");
        drop(writer.await.unwrap());

        // A peer trickling bytes is cut off at the one deadline, not kept
        // for as long as it keeps sending.
        let (mut peer, mut ours) = tokio::io::duplex(64);
        tokio::spawn(async move {
            loop {
                if peer.write_all(b"x").await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
        let started = tokio::time::Instant::now();
        let head = read_request_head(&mut ours).await;
        assert_eq!(started.elapsed(), REQUEST_READ_TIMEOUT);
        assert!(parse_status_request(&head).is_none(), "an unfinished head");
    }
}
