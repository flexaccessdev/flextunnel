//! The client's own status endpoint, `http://flextunnel.internal/`.
//!
//! The reserved `flextunnel.internal` name is answered by the running client
//! itself, from any of its proxy front-ends — SOCKS5, HTTP `CONNECT`, or a
//! plain `GET http://flextunnel.internal/…` — as HTTP/1.1 (never TLS):
//!
//! | Path | Serves |
//! | --- | --- |
//! | `/`, `/status.txt`, `/status.json` | This client: its routing across all destinations, and each destination's connection state. Answered locally — **no connection is opened**, so looking never wakes an idle destination. |
//! | `/servers/<destination>/`, `…/status.txt`, `…/status.json` | That destination server's own status page, fetched from the server on demand (which connects to it, like any other use). |
//!
//! The routing is the whole table in the order a target is tried against it
//! (see [`super::route_table`]), after the reserved names: every rule, the
//! destination it goes to, the other destinations' rules it lies inside or
//! that lie inside it, and whether its server routes it too — as the server
//! said on the destination's latest connection that read it ("last known"
//! when a later read failed), or "unchecked" for one not yet used.
//!
//! On `/` (and `/servers/<destination>/`) an `Accept: application/json` or
//! `text/plain` header picks the format, as the path suffix does. Any other
//! `*.flextunnel.internal` name is reserved and answers 404.
//!
//! A server's page is content from another machine shown under this
//! endpoint's own name, so it is never passed through as the server sent it:
//! the client reads the whole response, keeps its body, and answers with
//! headers of its own — a content type from the three served here, and a
//! `Content-Security-Policy: sandbox` that gives the page an origin of its
//! own (and no scripts), apart from the client's pages and the other servers'.

use super::client::{
    ClientStatus, HoldBudget, LocalProto, LocalStream, Router, TUNNEL_OPEN_TIMEOUT, open_tunnel,
};
use super::destination::{DestinationState, DestinationStatus};
use super::route_table::{RouteTable, TableRow, TableRule};
use super::routed_set::{Coverage, Rule};
use super::signaling::{self, StreamRequest};
use super::status_page::{
    self, CONTENT_TYPE_HTML, CONTENT_TYPE_JSON, CONTENT_TYPE_TEXT, STATUS_JSON_PATH,
    STATUS_TEXT_PATH, StatusFormat,
};
use anyhow::Result;
use askama::Template;
use iroh::endpoint::Connection;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Path prefix of a destination server's status page.
pub const SERVERS_PATH_PREFIX: &str = "/servers/";

/// Cap on a server status response read into memory to be relayed. The page
/// is a few kilobytes; this only bounds a server that sends without end.
const SERVER_STATUS_LIMIT: usize = 1024 * 1024;

/// Headers on a relayed server status page: the page gets an origin of its
/// own with scripts off, and its type is the one stated, not a guess.
const ISOLATION_HEADERS: &str =
    "Content-Security-Policy: sandbox\r\nX-Content-Type-Options: nosniff\r\n";

/// The path of `host`'s server status page in `format`, relative to
/// `http://flextunnel.internal`.
pub fn server_status_path(host: &str, format: StatusFormat) -> String {
    let tail = match format {
        StatusFormat::Html => "/",
        StatusFormat::Text => STATUS_TEXT_PATH,
        StatusFormat::Json => STATUS_JSON_PATH,
    };
    format!("{SERVERS_PATH_PREFIX}{host}{tail}")
}

/// One destination as the JSON status reports it.
#[derive(Serialize)]
struct DestinationJson<'a> {
    host: &'a str,
    server_node_id: &'a str,
    /// `idle`, `connecting`, `connected`, `backoff` or `failed`.
    state: &'static str,
    /// Seconds since the current connection was authenticated; `null` unless
    /// connected.
    connected_secs: Option<u64>,
    open_streams: usize,
    waiting: usize,
    /// This client's endpoint id toward this server; `null` while idle.
    client_node_id: Option<&'a str>,
    failed_attempts: u32,
    /// Seconds until the next attempt may run (0: due now); `null` when there
    /// is no failed attempt to retry.
    next_attempt_secs: Option<u64>,
    last_error: Option<&'a str>,
    routed_domains: &'a [String],
    routed_cidrs: &'a [String],
    relay_urls: &'a [String],
    /// What the server said it routes on the latest connection that read
    /// it; `null` until one has (see `server_routes_error`).
    server_routes: Option<&'a super::server_routes::ServerRoutes>,
    server_routes_error: Option<&'a str>,
    /// A connection is reading the server's routes again: until it has,
    /// `server_routes` is the last known answer.
    server_routes_pending: bool,
    /// Path of this server's own status page (fetching it connects).
    server_status: String,
}

#[derive(Serialize)]
struct ClientStatusJson<'a> {
    version: &'static str,
    socks_listen: Option<String>,
    http_listen: Option<String>,
    /// Seconds an unused connection is kept; `null` when one is never closed
    /// for idleness.
    idle_timeout_secs: Option<u64>,
    /// The table, most specific first; a target no rule matches connects
    /// directly.
    routes: &'a [RouteView],
    destinations: Vec<DestinationJson<'a>>,
}

/// One rule of another destination, next to a [`RouteView`].
#[derive(Serialize)]
struct RuleRef {
    rule: String,
    destination: String,
}

/// What a row's server makes of it ([`RouteView::server`] says it in words).
#[derive(Clone, Copy)]
enum ServerCheck {
    /// A destination's own host: its server's loopback, always served.
    Loopback,
    /// Graded against the server's lists as last read.
    Graded(Coverage),
    /// Not read from the server yet.
    Unchecked,
}

impl ServerCheck {
    fn as_str(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Graded(coverage) => coverage.as_str(),
            Self::Unchecked => "unchecked",
        }
    }
}

/// One row of the routing table as the pages show it.
#[derive(Serialize)]
struct RouteView {
    rule: String,
    /// `host` (the server's loopback), `exact`, `wildcard`, `catch-all` or
    /// `network`.
    kind: &'static str,
    destination: String,
    /// `loopback` (always served), `allowed`, `partly allowed`, `not allowed`
    /// (by the server's own lists), or `unchecked` (not read from the server
    /// yet).
    server: &'static str,
    /// `server` as the pages act on it.
    #[serde(skip)]
    check: ServerCheck,
    /// The server's lists behind `server` are the last known ones: the
    /// latest connection is still reading them again, or failed to (the
    /// destination's `server_routes_error` says why).
    server_last_known: bool,
    /// Other destinations' broader rules this one sits within: it wins over
    /// them for what it matches.
    within: Vec<RuleRef>,
    /// Other destinations' narrower rules inside this one: they take what
    /// they match.
    narrower: Vec<RuleRef>,
}

impl RouteView {
    /// A CSS class for the server check.
    fn server_class(&self) -> &'static str {
        match self.check {
            ServerCheck::Loopback | ServerCheck::Graded(Coverage::Full) => "connected",
            ServerCheck::Graded(Coverage::Partial) => "backoff",
            ServerCheck::Graded(Coverage::None) => "failed",
            ServerCheck::Unchecked => "idle",
        }
    }
}

/// The routing table over `status`'s destinations (the same, in the same
/// order, as `table`'s), with each server's answer about its own lists, as
/// the destination graded it when it read them.
fn routes(status: &ClientStatus, table: &RouteTable) -> Vec<RouteView> {
    let host = |dest: usize| table.hosts().nth(dest).unwrap_or_default().to_string();
    let refer = |row: &TableRow| RuleRef { rule: row.rule.to_string(), destination: host(row.dest) };
    // Each row's overlaps, in the table's overlap order: the broader rules it
    // sits within, and the narrower rules inside it.
    let mut within: HashMap<&TableRow, Vec<RuleRef>> = HashMap::new();
    let mut narrower: HashMap<&TableRow, Vec<RuleRef>> = HashMap::new();
    for overlap in table.overlaps() {
        within.entry(&overlap.inner).or_default().push(refer(&overlap.outer));
        narrower.entry(&overlap.outer).or_default().push(refer(&overlap.inner));
    }
    table
        .rows()
        .into_iter()
        .map(|row| {
            let within = within.remove(&row).unwrap_or_default();
            let narrower = narrower.remove(&row).unwrap_or_default();
            let destination = status.destinations.get(row.dest);
            let (kind, check) = match &row.rule {
                TableRule::Host(_) => ("host", ServerCheck::Loopback),
                TableRule::Routed(rule) => {
                    let kind = match rule {
                        Rule::CatchAll => "catch-all",
                        Rule::Suffix(_) => "wildcard",
                        Rule::Exact(_) => "exact",
                        Rule::Cidr(_) => "network",
                    };
                    let check = match destination.and_then(|d| d.server_coverage.get(rule)) {
                        Some(coverage) => ServerCheck::Graded(*coverage),
                        None => ServerCheck::Unchecked,
                    };
                    (kind, check)
                }
            };
            // Only a grade comes from the server's lists, so only a grade can
            // be out of date.
            let graded = match check {
                ServerCheck::Graded(_) => true,
                ServerCheck::Loopback | ServerCheck::Unchecked => false,
            };
            let server_last_known = graded
                && destination.is_some_and(|d| d.server_routes_pending || d.server_routes_error.is_some());
            RouteView {
                rule: row.rule.to_string(),
                kind,
                destination: host(row.dest),
                server: check.as_str(),
                check,
                server_last_known,
                within,
                narrower,
            }
        })
        .collect()
}

/// A destination's server routes as one line for the pages: the lists the
/// server sent (the last known ones while they are read again, or with why
/// reading them again failed), that they are being read, `unchecked`, or why
/// they could not be read.
fn server_routes_line(d: &DestinationStatus) -> String {
    match (&d.server_routes, &d.server_routes_error) {
        (Some(routes), error) => {
            let all: Vec<&str> = routes
                .routed_domains
                .iter()
                .chain(&routes.routed_cidrs)
                .map(String::as_str)
                .collect();
            let lists = if all.is_empty() { "none (loopback only)".to_string() } else { all.join(", ") };
            match error {
                _ if d.server_routes_pending => format!("{lists} (last known; reading them again)"),
                Some(error) => format!("{lists} (last known; reading them again failed: {error})"),
                None => lists,
            }
        }
        (None, None) if d.server_routes_pending => "being read".to_string(),
        (None, Some(error)) if d.server_routes_pending => {
            format!("being read again (the last read failed: {error})")
        }
        (None, Some(error)) => format!("unreadable: {error}"),
        (None, None) => "unchecked (read on the first connection)".to_string(),
    }
}

/// One destination as the HTML and text pages show it.
struct Row<'a> {
    status: &'a DestinationStatus,
    state: &'static str,
    /// What goes next to the state: an uptime, or the retry outlook.
    detail: String,
    /// What the server routes, as [`server_routes_line`] says it.
    server_routes: String,
    server_status_path: String,
}

#[derive(Template)]
#[template(path = "client_status.html")]
struct ClientStatusHtml<'a> {
    version: &'static str,
    socks_listen: String,
    http_listen: String,
    idle_timeout: String,
    routes: Vec<RouteView>,
    rows: Vec<Row<'a>>,
}

#[derive(Template)]
#[template(path = "client_status.txt")]
struct ClientStatusText<'a> {
    version: &'static str,
    socks_listen: String,
    http_listen: String,
    idle_timeout: String,
    routes: Vec<RouteView>,
    rows: Vec<Row<'a>>,
}

fn secs_since(at: Option<Instant>, now: Instant) -> Option<u64> {
    at.map(|at| now.saturating_duration_since(at).as_secs())
}

fn secs_until(at: Option<Instant>, now: Instant) -> Option<u64> {
    at.map(|at| at.saturating_duration_since(now).as_secs())
}

/// `1h 02m`, `3m 07s`, `12s`.
fn human_duration(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}h {m:02}m")
    } else if m > 0 {
        format!("{m}m {s:02}s")
    } else {
        format!("{s}s")
    }
}

fn rows(status: &ClientStatus, now: Instant) -> Vec<Row<'_>> {
    status
        .destinations
        .iter()
        .map(|d| {
            let detail = match d.state {
                DestinationState::Connected => match secs_since(d.connected_since, now) {
                    Some(secs) => format!("for {}", human_duration(secs)),
                    None => String::new(),
                },
                DestinationState::Idle if d.failed_attempts == 0 => {
                    "connects on first use".to_string()
                }
                DestinationState::Connecting if d.failed_attempts == 0 => String::new(),
                _ => {
                    let attempts = match d.failed_attempts {
                        1 => "1 failed attempt".to_string(),
                        n => format!("{n} failed attempts"),
                    };
                    match secs_until(d.next_attempt_at, now) {
                        Some(0) | None => attempts,
                        Some(secs) => format!("{attempts}, next in {}", human_duration(secs)),
                    }
                }
            };
            Row {
                status: d,
                state: d.state.as_str(),
                detail,
                server_routes: server_routes_line(d),
                server_status_path: server_status_path(&d.host, StatusFormat::Html),
            }
        })
        .collect()
}

/// Render the client status in `format`, its routing from `table` (the
/// client's, whose destinations `status` lists). Returns
/// `(http_status_line, content_type, body)`.
pub(crate) fn render(
    status: &ClientStatus,
    table: &RouteTable,
    format: StatusFormat,
) -> (&'static str, &'static str, String) {
    render_at(status, table, format, Instant::now())
}

/// [`render`] as of `now`: every uptime and retry delay is measured to it.
fn render_at(
    status: &ClientStatus,
    table: &RouteTable,
    format: StatusFormat,
    now: Instant,
) -> (&'static str, &'static str, String) {
    let routes = routes(status, table);
    let version = env!("CARGO_PKG_VERSION");
    let addr = |a: Option<std::net::SocketAddr>| a.map_or_else(|| "off".to_string(), |a| a.to_string());
    let idle_timeout = match status.idle_timeout {
        Some(idle) => human_duration(idle.as_secs()),
        None => "never".to_string(),
    };
    let rendered = match format {
        StatusFormat::Html => ClientStatusHtml {
            version,
            socks_listen: addr(status.socks_listen),
            http_listen: addr(status.http_listen),
            idle_timeout,
            routes,
            rows: rows(status, now),
        }
        .render()
        .map_err(|e| e.to_string()),
        StatusFormat::Text => ClientStatusText {
            version,
            socks_listen: addr(status.socks_listen),
            http_listen: addr(status.http_listen),
            idle_timeout,
            routes,
            rows: rows(status, now),
        }
        .render()
        .map_err(|e| e.to_string()),
        StatusFormat::Json => {
            let payload = ClientStatusJson {
                version,
                socks_listen: status.socks_listen.map(|a| a.to_string()),
                http_listen: status.http_listen.map(|a| a.to_string()),
                idle_timeout_secs: status.idle_timeout.map(|idle| idle.as_secs()),
                routes: &routes,
                destinations: status
                    .destinations
                    .iter()
                    .map(|d| DestinationJson {
                        host: &d.host,
                        server_node_id: &d.server_node_id,
                        state: d.state.as_str(),
                        connected_secs: secs_since(d.connected_since, now),
                        open_streams: d.open_streams,
                        waiting: d.waiting,
                        client_node_id: d.client_node_id.as_deref(),
                        failed_attempts: d.failed_attempts,
                        next_attempt_secs: secs_until(d.next_attempt_at, now),
                        last_error: d.last_error.as_deref(),
                        routed_domains: &d.routed_domains,
                        routed_cidrs: &d.routed_cidrs,
                        relay_urls: &d.relay_urls,
                        server_routes: d.server_routes.as_ref(),
                        server_routes_error: d.server_routes_error.as_deref(),
                        server_routes_pending: d.server_routes_pending,
                        server_status: server_status_path(&d.host, StatusFormat::Json),
                    })
                    .collect(),
            };
            serde_json::to_string_pretty(&payload)
                .map(|mut body| {
                    body.push('\n');
                    body
                })
                .map_err(|e| e.to_string())
        }
    };
    let content_type = match format {
        StatusFormat::Html => CONTENT_TYPE_HTML,
        StatusFormat::Text => CONTENT_TYPE_TEXT,
        StatusFormat::Json => CONTENT_TYPE_JSON,
    };
    match rendered {
        Ok(body) => ("200 OK", content_type, body),
        Err(e) => {
            log::warn!("Failed to render the client status page: {e}");
            (
                "500 Internal Server Error",
                CONTENT_TYPE_TEXT,
                "flextunnel client status unavailable\n".to_string(),
            )
        }
    }
}

/// Answer one local proxy request for the reserved namespace: the client
/// status endpoint for `flextunnel.internal` itself, a 404 for any other
/// `*.flextunnel.internal` name (`reserved_other`).
///
/// `preamble` is the request head of a plain-HTTP forward, already read by the
/// front-end. A tunnel (SOCKS5, HTTP `CONNECT`) has none: it is answered with
/// a success reply first, and the app then sends its HTTP request through it.
pub(super) async fn serve<P: LocalProto, S: LocalStream>(
    proto: &P,
    tcp: &mut S,
    preamble: Option<Vec<u8>>,
    router: &Arc<Router>,
    reserved_other: bool,
    holds: &HoldBudget,
) -> Result<()> {
    let head = match preamble {
        Some(head) => head,
        None => {
            proto.reply(tcp, signaling::REP_SUCCESS).await?;
            status_page::read_request_head(tcp).await
        }
    };
    if reserved_other {
        let (status_line, content_type, body) = status_page::render_reserved_404();
        return respond(tcp, status_line, content_type, &body).await;
    }
    let Some(request) = status_page::parse_status_request(&head) else {
        return respond(tcp, "400 Bad Request", CONTENT_TYPE_TEXT, "not an HTTP request\n").await;
    };
    if request.method != "GET" {
        return respond(
            tcp,
            "405 Method Not Allowed",
            CONTENT_TYPE_TEXT,
            "flextunnel.internal serves GET only\n",
        )
        .await;
    }
    if let Some(rest) = request.path.strip_prefix(SERVERS_PATH_PREFIX) {
        return serve_server_status(tcp, router, rest, request.accept, holds).await;
    }
    match request.path.as_str() {
        "/" | STATUS_TEXT_PATH | STATUS_JSON_PATH => {
            let format = status_page::status_format_for(&request.path, request.accept);
            let (status_line, content_type, body) = render(&router.status(), &router.table, format);
            respond(tcp, status_line, content_type, &body).await
        }
        other => not_found(tcp, &format!("no such page: {other}")).await,
    }
}

/// Serve `/servers/<host>[/status.txt|/status.json]`: fetch that destination
/// server's own status page over a [`StreamRequest::Status`] stream — which
/// connects to the server if it is not connected — and answer with its body
/// under headers of our own (see the module docs).
///
/// The server's response is read whole before anything is written, so every
/// failure — a refusal, a stalled server, a response that is not a status
/// page — is a clean 502, and the destination's connection is released
/// before the local app is written to.
async fn serve_server_status<S: LocalStream>(
    tcp: &mut S,
    router: &Arc<Router>,
    rest: &str,
    accept: Option<StatusFormat>,
    holds: &HoldBudget,
) -> Result<()> {
    let (host, tail) = match rest.split_once('/') {
        Some((host, tail)) => (host, format!("/{tail}")),
        None => (rest, "/".to_string()),
    };
    if !matches!(tail.as_str(), "/" | STATUS_TEXT_PATH | STATUS_JSON_PATH) {
        return not_found(tcp, &format!("no such page: {SERVERS_PATH_PREFIX}{rest}")).await;
    }
    let Some(dest) = router.table.index_of(host) else {
        return not_found(tcp, &format!("no destination named {host:?}")).await;
    };
    let destination = &router.destinations[dest];

    let fetched = async {
        let lease = destination
            .acquire(Some(holds.for_destination(dest)))
            .await
            .map_err(|e| e.to_string())?;
        fetch_server_status(&lease.conn, &tail, accept).await
        // `lease` ends here, on every path.
    };
    let fetched = fetched.await;
    let page = match &fetched {
        Ok(response) => parse_server_status(response),
        Err(detail) => Err(detail.clone()),
    };
    match page {
        Ok((content_type, body)) => {
            status_page::write_http_response(tcp, "200 OK", content_type, ISOLATION_HEADERS, body)
                .await?;
            tcp.shutdown().await?;
            Ok(())
        }
        Err(detail) => {
            let body = format!("{}: {detail}\n", destination.host());
            respond(tcp, "502 Bad Gateway", CONTENT_TYPE_TEXT, &body).await
        }
    }
}

/// Ask the server on `conn` for its status page at `tail` (`/`, `/status.txt`
/// or `/status.json`) over a [`StreamRequest::Status`] stream, and return its
/// whole HTTP response for [`parse_server_status`] to take apart.
pub(crate) async fn fetch_server_status(
    conn: &Connection,
    tail: &str,
    accept: Option<StatusFormat>,
) -> Result<Vec<u8>, String> {
    let (mut send, mut recv) =
        match tokio::time::timeout(TUNNEL_OPEN_TIMEOUT, open_tunnel(conn, &StreamRequest::Status))
            .await
        {
            Ok(Ok((send, recv, signaling::REP_SUCCESS))) => (send, recv),
            Ok(Ok((_, _, rep))) => {
                return Err(format!("server refused: {}", super::socks5::describe_reply(rep)));
            }
            Ok(Err(e)) => return Err(e.to_string()),
            Err(_) => return Err("timed out asking the server for its status page".to_string()),
        };

    // The server picks its format from this request's path and `Accept`.
    let accept = match accept {
        Some(StatusFormat::Json) => "application/json",
        Some(StatusFormat::Text) => "text/plain",
        Some(StatusFormat::Html) | None => "*/*",
    };
    let request = format!(
        "GET {tail} HTTP/1.1\r\nHost: {}\r\nAccept: {accept}\r\nConnection: close\r\n\r\n",
        super::reserved::STATUS_HOST
    );
    exchange(&mut send, &mut recv, request.as_bytes(), TUNNEL_OPEN_TIMEOUT).await
}

/// Send `request` on a status stream and read the server's whole response —
/// at most one byte past [`SERVER_STATUS_LIMIT`] — within `deadline` for the
/// exchange in all: a server that takes the stream and then says nothing, or
/// sends without end, must not hold the request, or the lease on its
/// connection, open.
async fn exchange<W, R>(
    send: &mut W,
    recv: &mut R,
    request: &[u8],
    deadline: std::time::Duration,
) -> Result<Vec<u8>, String>
where
    W: tokio::io::AsyncWrite + Unpin,
    R: tokio::io::AsyncRead + Unpin,
{
    let exchange = async {
        send.write_all(request).await?;
        // Nothing more to send: ending our half lets the server stop
        // draining at once.
        let _ = send.shutdown().await;
        let mut response = Vec::new();
        recv.take(SERVER_STATUS_LIMIT as u64 + 1)
            .read_to_end(&mut response)
            .await?;
        std::io::Result::Ok(response)
    };
    match tokio::time::timeout(deadline, exchange).await {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(e)) => Err(format!("reading the server's status page failed: {e}")),
        Err(_) => Err("timed out reading the server's status page".to_string()),
    }
}

/// Take a server's status response apart into what is relayed: one of the
/// three content types served here, and the body. Anything else — another
/// status, another type, a response cut short or too long — is refused with
/// the reason. A response that states its `Content-Length` must carry exactly
/// that many body bytes: a stream that ended early would otherwise be relayed
/// as a whole page. One without the header is delimited by the stream's end.
pub(crate) fn parse_server_status(response: &[u8]) -> Result<(&'static str, &str), String> {
    if response.len() > SERVER_STATUS_LIMIT {
        return Err("the server's status page is too large".to_string());
    }
    let malformed = || "the server did not answer with an HTTP response".to_string();
    let response = std::str::from_utf8(response).map_err(|_| malformed())?;
    let (head, body) = response.split_once("\r\n\r\n").ok_or_else(malformed)?;
    let mut lines = head.split("\r\n");
    let mut status_line = lines.next().unwrap_or_default().splitn(3, ' ');
    let (version, code) = (status_line.next().unwrap_or_default(), status_line.next());
    let header = |wanted: &str| {
        lines
            .clone()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case(wanted))
            .map(|(_, value)| value.trim())
    };
    if !version.starts_with("HTTP/") {
        return Err(malformed());
    }
    if code != Some("200") {
        return Err(format!("the server answered {}", code.unwrap_or("without a status")));
    }
    if let Some(stated) = header("content-length")
        && stated.parse::<usize>().ok() != Some(body.len())
    {
        return Err(format!(
            "the server's status page is incomplete: {} body bytes for a Content-Length of {stated}",
            body.len()
        ));
    }
    let content_type = header("content-type").unwrap_or_default().to_ascii_lowercase();
    let content_type = match content_type.split(';').next().unwrap_or_default().trim() {
        "text/html" => CONTENT_TYPE_HTML,
        "text/plain" => CONTENT_TYPE_TEXT,
        "application/json" => CONTENT_TYPE_JSON,
        other => return Err(format!("the server answered with content type {other:?}")),
    };
    Ok((content_type, body))
}

async fn not_found<S: LocalStream>(tcp: &mut S, detail: &str) -> Result<()> {
    respond(tcp, "404 Not Found", CONTENT_TYPE_TEXT, &format!("{detail}\n")).await
}

/// Write one complete HTTP response and end the exchange.
async fn respond<S: LocalStream>(
    tcp: &mut S,
    status_line: &str,
    content_type: &str,
    body: &str,
) -> Result<()> {
    status_page::write_http_payload(tcp, status_line, content_type, body).await?;
    tcp.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::route_table::RouteSpec;
    use crate::proxy::routed_set::RoutedSet;
    use crate::proxy::server_routes::ServerRoutes;
    use std::time::Duration;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    /// The table `status`'s destinations make with their own routes.
    fn table_of(status: &ClientStatus) -> RouteTable {
        let specs: Vec<RouteSpec<'_>> = status
            .destinations
            .iter()
            .map(|d| RouteSpec {
                host: &d.host,
                routed_domains: &d.routed_domains,
                routed_cidrs: &d.routed_cidrs,
            })
            .collect();
        RouteTable::new(&specs).unwrap()
    }

    fn destination(host: &str, state: DestinationState) -> DestinationStatus {
        DestinationStatus {
            host: host.to_string(),
            server_node_id: "serverid".to_string(),
            state,
            connected_since: None,
            open_streams: 0,
            waiting: 0,
            client_node_id: None,
            failed_attempts: 0,
            next_attempt_at: None,
            last_error: None,
            routed_domains: vec!["*.corp.example".to_string()],
            routed_cidrs: vec!["10.0.0.0/8".to_string()],
            relay_urls: Vec::new(),
            server_routes: None,
            server_routes_error: None,
            server_coverage: Arc::default(),
            server_routes_pending: false,
        }
    }

    /// `d` as after a connection read `routes` from its server: graded as
    /// the destination grades them.
    fn answered(d: &mut DestinationStatus, routes: ServerRoutes) {
        let own = RoutedSet::new(&d.routed_domains, &d.routed_cidrs).unwrap();
        d.server_coverage = Arc::new(routes.coverage_of(&own).unwrap());
        d.server_routes = Some(routes);
    }

    /// A status as of [`now`]: `m1` connected 125s earlier, `m2` retrying in
    /// 30s, `m3` idle. `m2`'s routes nest inside `m1`'s; `m1`'s server routes
    /// all of its wildcard and half its network, `m2`'s server nothing it
    /// lists, and `m3` has never connected.
    fn status() -> (ClientStatus, Instant) {
        // The connection is the fixed point and "now" is counted on from it,
        // so nothing depends on the clock while the test runs (or on how long
        // the machine has been up).
        let connected_at = Instant::now();
        let now = connected_at + Duration::from_secs(125);
        let mut connected = destination("m1.internal", DestinationState::Connected);
        connected.connected_since = Some(connected_at);
        connected.open_streams = 2;
        connected.client_node_id = Some("clientid".to_string());
        answered(
            &mut connected,
            ServerRoutes {
                routed_domains: strings(&["*.corp.example"]),
                routed_cidrs: strings(&["10.0.0.0/9"]),
            },
        );
        let mut backoff = destination("m2.internal", DestinationState::Backoff);
        backoff.routed_domains = strings(&["*.dev.corp.example"]);
        backoff.routed_cidrs = strings(&["10.1.0.0/16"]);
        answered(&mut backoff, ServerRoutes::default());
        backoff.failed_attempts = 3;
        backoff.last_error = Some("Signaling error: timed out".to_string());
        backoff.next_attempt_at = Some(now + Duration::from_secs(30));
        backoff.waiting = 1;
        let mut idle = destination("m3.internal", DestinationState::Idle);
        idle.routed_domains = strings(&["wiki.example"]);
        idle.routed_cidrs.clear();
        let status = ClientStatus {
            socks_listen: Some("127.0.0.1:1080".parse().unwrap()),
            http_listen: None,
            idle_timeout: Some(Duration::from_secs(300)),
            destinations: vec![connected, backoff, idle],
        };
        (status, now)
    }

    fn render_fixed(format: StatusFormat) -> (&'static str, &'static str, String) {
        let (status, now) = status();
        render_at(&status, &table_of(&status), format, now)
    }

    #[test]
    fn json_reports_every_destination() {
        let (line, content_type, body) = render_fixed(StatusFormat::Json);
        assert_eq!(line, "200 OK");
        assert_eq!(content_type, CONTENT_TYPE_JSON);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["socks_listen"], "127.0.0.1:1080");
        assert!(json["http_listen"].is_null());
        assert_eq!(json["idle_timeout_secs"], 300);
        let d = json["destinations"].as_array().unwrap();
        assert_eq!(d.len(), 3);
        assert_eq!(d[0]["host"], "m1.internal");
        assert_eq!(d[0]["state"], "connected");
        assert_eq!(d[0]["connected_secs"], 125);
        assert_eq!(d[0]["open_streams"], 2);
        assert_eq!(d[0]["client_node_id"], "clientid");
        assert_eq!(d[0]["server_status"], "/servers/m1.internal/status.json");
        assert_eq!(d[1]["state"], "backoff");
        assert_eq!(d[1]["failed_attempts"], 3);
        assert_eq!(d[1]["waiting"], 1);
        assert_eq!(d[1]["next_attempt_secs"], 30);
        assert_eq!(d[1]["last_error"], "Signaling error: timed out");
        assert_eq!(d[2]["state"], "idle");
        assert!(d[2]["connected_secs"].is_null());
        assert!(d[2]["client_node_id"].is_null());
        assert!(d[2]["next_attempt_secs"].is_null());
        assert_eq!(d[2]["routed_domains"][0], "wiki.example");
        assert!(d[2]["server_routes"].is_null());
        assert_eq!(d[0]["server_routes"]["routed_cidrs"][0], "10.0.0.0/9");
    }

    #[test]
    fn html_and_text_render_states_and_links() {
        let (line, content_type, html) = render_fixed(StatusFormat::Html);
        assert_eq!((line, content_type), ("200 OK", CONTENT_TYPE_HTML));
        assert!(html.contains("m1.internal"));
        assert!(html.contains("for 2m 05s"));
        assert!(html.contains("href=\"/servers/m1.internal/\""));
        assert!(html.contains("3 failed attempts, next in 30s"));
        assert!(html.contains("connects on first use"));

        let (line, content_type, text) = render_fixed(StatusFormat::Text);
        assert_eq!((line, content_type), ("200 OK", CONTENT_TYPE_TEXT));
        assert!(text.contains("socks5: 127.0.0.1:1080"));
        assert!(text.contains("http: off"));
        assert!(text.contains("m2.internal"));
        assert!(text.contains("state: backoff"));
        assert!(text.contains("last error: Signaling error: timed out"));
    }

    /// The routing is the whole table, most specific first, each rule with
    /// the destination it goes to, the other destinations' rules it nests
    /// with, and what its server said of it — without connecting anything.
    #[test]
    fn routing_is_shown_across_all_destinations() {
        let (_, _, body) = render_fixed(StatusFormat::Json);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        let routes = json["routes"].as_array().unwrap();
        let summary: Vec<(&str, &str, &str, &str)> = routes
            .iter()
            .map(|r| {
                (
                    r["rule"].as_str().unwrap(),
                    r["kind"].as_str().unwrap(),
                    r["destination"].as_str().unwrap(),
                    r["server"].as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                ("m1.internal", "host", "m1.internal", "loopback"),
                ("m2.internal", "host", "m2.internal", "loopback"),
                ("m3.internal", "host", "m3.internal", "loopback"),
                ("wiki.example", "exact", "m3.internal", "unchecked"),
                ("*.dev.corp.example", "wildcard", "m2.internal", "not allowed"),
                ("*.corp.example", "wildcard", "m1.internal", "allowed"),
                ("10.1.0.0/16", "network", "m2.internal", "not allowed"),
                ("10.0.0.0/8", "network", "m1.internal", "partly allowed"),
            ]
        );
        let dev = &routes[4];
        assert_eq!(dev["within"][0]["rule"], "*.corp.example");
        assert_eq!(dev["within"][0]["destination"], "m1.internal");
        let corp = &routes[5];
        assert_eq!(corp["narrower"][0]["rule"], "*.dev.corp.example");
        assert_eq!(corp["narrower"][0]["destination"], "m2.internal");
        assert!(corp["within"].as_array().unwrap().is_empty());

        let (_, _, text) = render_fixed(StatusFormat::Text);
        assert!(text.contains("*.dev.corp.example (wildcard) -> m2.internal, server: not allowed"), "{text}");
        assert!(text.contains("inside m1.internal's broader *.corp.example"), "{text}");
        assert!(text.contains("contains m2.internal's narrower 10.1.0.0/16"), "{text}");
        assert!(text.contains("*.flextunnel.internal -> this client (reserved, answers 404)"), "{text}");
        assert!(text.contains("anything else -> direct"), "{text}");
        assert!(text.contains("server routes: *.corp.example, 10.0.0.0/9"), "{text}");
        assert!(text.contains("server routes: unchecked"), "{text}");

        let (_, _, html) = render_fixed(StatusFormat::Html);
        assert!(html.contains("Routing"));
        assert!(html.contains("partly allowed"));
        assert!(html.contains("contains <span class=\"mono\">m2.internal</span>'s narrower"), "{html}");
        assert!(html.contains("*.flextunnel.internal"), "{html}");
    }

    /// A failed read after a good one keeps the earlier answer, shown as the
    /// last known, with why the latest read failed.
    #[test]
    fn a_failed_refresh_keeps_the_last_known_answer() {
        let (mut status, now) = status();
        status.destinations[0].server_routes_error = Some("timed out".to_string());
        let table = table_of(&status);
        let (_, _, body) = render_at(&status, &table, StatusFormat::Json, now);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        let corp = json["routes"].as_array().unwrap().iter().find(|r| r["rule"] == "*.corp.example").unwrap();
        assert_eq!(corp["server"], "allowed");
        assert_eq!(corp["server_last_known"], true);
        let dev = json["routes"].as_array().unwrap().iter().find(|r| r["rule"] == "*.dev.corp.example").unwrap();
        assert_eq!(dev["server_last_known"], false);

        let (_, _, text) = render_at(&status, &table, StatusFormat::Text, now);
        assert!(text.contains("-> m1.internal, server: allowed (last known)"), "{text}");
        assert!(
            text.contains("server routes: *.corp.example, 10.0.0.0/9 (last known; reading them again failed: timed out)"),
            "{text}"
        );
        let (_, _, html) = render_at(&status, &table, StatusFormat::Html, now);
        assert!(html.contains("last known"), "{html}");
        assert!(html.contains("reading them again failed: timed out"), "{html}");

        // While a new connection reads them again, the kept answer is the
        // last known too.
        status.destinations[0].server_routes_error = None;
        status.destinations[0].server_routes_pending = true;
        let (_, _, text) = render_at(&status, &table, StatusFormat::Text, now);
        assert!(text.contains("-> m1.internal, server: allowed (last known)"), "{text}");
        assert!(text.contains("10.0.0.0/9 (last known; reading them again)"), "{text}");

        // With nothing read yet, a read in progress says so — a first one, or
        // one retrying after a failure — instead of the failure or
        // "unchecked".
        let idle = &mut status.destinations[2];
        idle.server_routes_pending = true;
        let (_, _, text) = render_at(&status, &table, StatusFormat::Text, now);
        assert!(text.lines().any(|l| l.trim() == "server routes: being read"), "{text}");
        status.destinations[2].server_routes_error = Some("refused".to_string());
        let (_, _, text) = render_at(&status, &table, StatusFormat::Text, now);
        assert!(text.contains("server routes: being read again (the last read failed: refused)"), "{text}");
        status.destinations[2].server_routes_pending = false;
        let (_, _, text) = render_at(&status, &table, StatusFormat::Text, now);
        assert!(text.contains("server routes: unreadable: refused"), "{text}");
    }

    #[test]
    fn never_idle_is_reported() {
        let (mut status, _) = status();
        status.idle_timeout = None;
        let table = table_of(&status);
        let (_, _, body) = render(&status, &table, StatusFormat::Json);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(json["idle_timeout_secs"].is_null());
        let (_, _, text) = render(&status, &table, StatusFormat::Text);
        assert!(text.contains("idle timeout: never"));
    }

    #[test]
    fn durations_read_naturally() {
        assert_eq!(human_duration(7), "7s");
        assert_eq!(human_duration(125), "2m 05s");
        assert_eq!(human_duration(3725), "1h 02m");
    }

    /// Only a server's `200` with one of the three served types is relayed,
    /// and only its body: the content type sent on is ours, not the server's.
    #[test]
    fn a_server_status_response_is_taken_apart() {
        let response = |head: &str, body: &str| format!("{head}\r\n\r\n{body}").into_bytes();
        let ok = response("HTTP/1.1 200 OK\r\nContent-Type: Application/JSON; charset=utf-8\r\nSet-Cookie: x=1", "{}\n");
        assert_eq!(parse_server_status(&ok), Ok((CONTENT_TYPE_JSON, "{}\n")));
        let html = response("HTTP/1.1 200 OK\r\ncontent-type:text/html", "<p>hi</p>\r\n\r\nmore");
        assert_eq!(parse_server_status(&html), Ok((CONTENT_TYPE_HTML, "<p>hi</p>\r\n\r\nmore")));

        for (bad, why) in [
            (response("HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain", "x"), "answered 500"),
            (response("HTTP/1.1 200 OK\r\nContent-Type: image/svg+xml", "<svg/>"), "content type"),
            (response("HTTP/1.1 200 OK", "no type"), "content type"),
            (response("SSH-2.0-nope", ""), "HTTP response"),
            (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n".to_vec(), "HTTP response"),
            (vec![0xff; 16], "HTTP response"),
            (vec![b'a'; SERVER_STATUS_LIMIT + 1], "too large"),
        ] {
            let err = parse_server_status(&bad).unwrap_err();
            assert!(err.contains(why), "{why}: {err}");
        }
    }

    /// A stated `Content-Length` is held to: a body the stream cut short (or
    /// ran past, or a length that is no number) is not a page to relay. With
    /// no length stated, the end of the stream is the end of the body.
    #[test]
    fn a_server_status_body_must_match_its_stated_length() {
        let response = |length: &str, body: &str| {
            format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n{length}\r\n\r\n{body}").into_bytes()
        };
        // Bytes, not characters: "é" is two.
        assert_eq!(
            parse_server_status(&response("Content-Length: 6", "héllo")),
            Ok((CONTENT_TYPE_TEXT, "héllo"))
        );
        assert_eq!(
            parse_server_status(&response("content-length:  0 ", "")),
            Ok((CONTENT_TYPE_TEXT, ""))
        );
        for (length, body) in [
            ("Content-Length: 500", "cut short"),
            ("Content-Length: 3", "longer than stated"),
            ("Content-Length: 5", ""),
            ("Content-Length: lots", "lots"),
            ("Content-Length: -4", "four"),
            ("Content-Length:", "x"),
        ] {
            let err = parse_server_status(&response(length, body)).unwrap_err();
            assert!(err.contains("incomplete"), "{length:?}: {err}");
        }
        // Close-delimited: no length to hold it to.
        assert_eq!(
            parse_server_status(&response("Connection: close", "to the end")),
            Ok((CONTENT_TYPE_TEXT, "to the end"))
        );
    }

    /// The exchange with the server has one deadline: a server that takes
    /// the request and goes quiet, or never stops sending, is given up on —
    /// before anything was written to the app, so the answer is a clean 502.
    #[tokio::test(start_paused = true)]
    async fn the_server_status_exchange_is_bounded() {
        let deadline = Duration::from_secs(30);

        // A server that answers and closes: the whole response, request sent.
        let (mut ours, mut server) = tokio::io::duplex(1024);
        let serving = tokio::spawn(async move {
            let mut request = Vec::new();
            server.read_to_end(&mut request).await.unwrap();
            server.write_all(b"HTTP/1.1 200 OK\r\n\r\nbody").await.unwrap();
            request
        });
        let (mut recv, mut send) = tokio::io::split(&mut ours);
        let response = exchange(&mut send, &mut recv, b"GET / HTTP/1.1\r\n\r\n", deadline).await;
        assert_eq!(response.as_deref(), Ok(&b"HTTP/1.1 200 OK\r\n\r\nbody"[..]));
        assert_eq!(serving.await.unwrap(), b"GET / HTTP/1.1\r\n\r\n");

        // A server that reads the request and then says nothing.
        let (mut ours, _silent) = tokio::io::duplex(1024);
        let (mut recv, mut send) = tokio::io::split(&mut ours);
        let started = tokio::time::Instant::now();
        let err = exchange(&mut send, &mut recv, b"GET / HTTP/1.1\r\n\r\n", deadline).await.unwrap_err();
        assert!(err.contains("timed out"), "{err}");
        assert_eq!(started.elapsed(), deadline);

        // A server that sends a byte a second, forever: the same deadline.
        let (mut ours, mut server) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            while server.write_all(b"x").await.is_ok() {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
        let (mut recv, mut send) = tokio::io::split(&mut ours);
        let started = tokio::time::Instant::now();
        assert!(exchange(&mut send, &mut recv, b"GET /", deadline).await.is_err());
        assert_eq!(started.elapsed(), deadline);
    }

    #[test]
    fn server_status_paths() {
        assert_eq!(server_status_path("m1.internal", StatusFormat::Html), "/servers/m1.internal/");
        assert_eq!(
            server_status_path("m1.internal", StatusFormat::Text),
            "/servers/m1.internal/status.txt"
        );
    }
}
