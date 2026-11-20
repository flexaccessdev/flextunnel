//! The client's own status endpoint, `http://flextunnel.internal/`.
//!
//! The reserved `flextunnel.internal` name is answered by the running client
//! itself, from any of its proxy front-ends — SOCKS5, HTTP `CONNECT`, or a
//! plain `GET http://flextunnel.internal/…` — as HTTP/1.1 (never TLS):
//!
//! | Path | Serves |
//! | --- | --- |
//! | `/`, `/status.txt`, `/status.json` | This client: its destinations and each one's connection state. Answered locally — **no connection is opened**, so looking never wakes an idle destination. |
//! | `/servers/<destination>/`, `…/status.txt`, `…/status.json` | That destination server's own status page, fetched from the server on demand (which connects to it, like any other use). |
//!
//! On `/` (and `/servers/<destination>/`) an `Accept: application/json` or
//! `text/plain` header picks the format, as the path suffix does. Any other
//! `*.flextunnel.internal` name is reserved and answers 404.

use super::client::{ClientStatus, LocalProto, LocalStream, Router, TUNNEL_OPEN_TIMEOUT, open_tunnel};
use super::destination::{DestinationState, DestinationStatus};
use super::signaling::{self, StreamRequest};
use super::status_page::{
    self, CONTENT_TYPE_HTML, CONTENT_TYPE_JSON, CONTENT_TYPE_TEXT, STATUS_JSON_PATH,
    STATUS_TEXT_PATH, StatusFormat,
};
use anyhow::Result;
use askama::Template;
use serde::Serialize;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;

/// Path prefix of a destination server's status page.
pub const SERVERS_PATH_PREFIX: &str = "/servers/";

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
    destinations: Vec<DestinationJson<'a>>,
}

/// One destination as the HTML and text pages show it.
struct Row<'a> {
    status: &'a DestinationStatus,
    state: &'static str,
    /// What goes next to the state: an uptime, or the retry outlook.
    detail: String,
    server_status_path: String,
}

#[derive(Template)]
#[template(path = "client_status.html")]
struct ClientStatusHtml<'a> {
    version: &'static str,
    socks_listen: String,
    http_listen: String,
    idle_timeout: String,
    rows: Vec<Row<'a>>,
}

#[derive(Template)]
#[template(path = "client_status.txt")]
struct ClientStatusText<'a> {
    version: &'static str,
    socks_listen: String,
    http_listen: String,
    idle_timeout: String,
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
                server_status_path: server_status_path(&d.host, StatusFormat::Html),
            }
        })
        .collect()
}

/// Render the client status in `format`. Returns
/// `(http_status_line, content_type, body)`.
pub(crate) fn render(
    status: &ClientStatus,
    format: StatusFormat,
) -> (&'static str, &'static str, String) {
    let version = env!("CARGO_PKG_VERSION");
    let now = Instant::now();
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
            rows: rows(status, now),
        }
        .render()
        .map_err(|e| e.to_string()),
        StatusFormat::Text => ClientStatusText {
            version,
            socks_listen: addr(status.socks_listen),
            http_listen: addr(status.http_listen),
            idle_timeout,
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
    holds: &Semaphore,
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
    let request = status_page::parse_status_request(&head);
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
            let (status_line, content_type, body) = render(&router.status(), format);
            respond(tcp, status_line, content_type, &body).await
        }
        other => not_found(tcp, &format!("no such page: {other}")).await,
    }
}

/// Serve `/servers/<host>[/status.txt|/status.json]`: fetch that destination
/// server's own status page over a [`StreamRequest::Status`] stream — which
/// connects to the server if it is not connected — and relay the server's
/// HTTP response verbatim.
async fn serve_server_status<S: LocalStream>(
    tcp: &mut S,
    router: &Arc<Router>,
    rest: &str,
    accept: Option<StatusFormat>,
    holds: &Semaphore,
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
    let bad_gateway = |detail: String| format!("{}: {detail}\n", destination.host());

    let lease = match destination.acquire(Some(holds)).await {
        Ok(lease) => lease,
        Err(e) => {
            return respond(tcp, "502 Bad Gateway", CONTENT_TYPE_TEXT, &bad_gateway(e.to_string()))
                .await;
        }
    };
    let opened =
        tokio::time::timeout(TUNNEL_OPEN_TIMEOUT, open_tunnel(&lease.conn, &StreamRequest::Status))
            .await
            .map_err(|_| anyhow::anyhow!("timed out asking the server for its status page"))
            .and_then(|r| r);
    let (mut send, mut recv) = match opened {
        Ok((send, recv, signaling::REP_SUCCESS)) => (send, recv),
        Ok((_, _, rep)) => {
            let detail = format!("server refused: {}", super::socks5::describe_reply(rep));
            return respond(tcp, "502 Bad Gateway", CONTENT_TYPE_TEXT, &bad_gateway(detail)).await;
        }
        Err(e) => {
            return respond(tcp, "502 Bad Gateway", CONTENT_TYPE_TEXT, &bad_gateway(e.to_string()))
                .await;
        }
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
    send.write_all(request.as_bytes()).await?;
    // Nothing more to send: finishing lets the server stop draining at once.
    let _ = send.finish();
    tokio::io::copy(&mut recv, tcp).await?;
    tcp.shutdown().await?;
    Ok(())
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
    use std::time::Duration;

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
        }
    }

    fn status() -> ClientStatus {
        let now = Instant::now();
        let mut connected = destination("m1.internal", DestinationState::Connected);
        connected.connected_since = now.checked_sub(Duration::from_secs(125));
        connected.open_streams = 2;
        connected.client_node_id = Some("clientid".to_string());
        let mut backoff = destination("m2.internal", DestinationState::Backoff);
        backoff.failed_attempts = 3;
        backoff.last_error = Some("Signaling error: timed out".to_string());
        backoff.next_attempt_at = Some(now + Duration::from_secs(30));
        backoff.waiting = 1;
        ClientStatus {
            socks_listen: Some("127.0.0.1:1080".parse().unwrap()),
            http_listen: None,
            idle_timeout: Some(Duration::from_secs(300)),
            destinations: vec![connected, backoff, destination("m3.internal", DestinationState::Idle)],
        }
    }

    #[test]
    fn json_reports_every_destination() {
        let (line, content_type, body) = render(&status(), StatusFormat::Json);
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
        assert!(d[0]["connected_secs"].as_u64().unwrap() >= 125);
        assert_eq!(d[0]["open_streams"], 2);
        assert_eq!(d[0]["client_node_id"], "clientid");
        assert_eq!(d[0]["server_status"], "/servers/m1.internal/status.json");
        assert_eq!(d[1]["state"], "backoff");
        assert_eq!(d[1]["failed_attempts"], 3);
        assert_eq!(d[1]["waiting"], 1);
        assert!(d[1]["next_attempt_secs"].as_u64().unwrap() <= 30);
        assert_eq!(d[1]["last_error"], "Signaling error: timed out");
        assert_eq!(d[2]["state"], "idle");
        assert!(d[2]["connected_secs"].is_null());
        assert!(d[2]["client_node_id"].is_null());
        assert!(d[2]["next_attempt_secs"].is_null());
        assert_eq!(d[2]["routed_domains"][0], "*.corp.example");
    }

    #[test]
    fn html_and_text_render_states_and_links() {
        let (line, content_type, html) = render(&status(), StatusFormat::Html);
        assert_eq!((line, content_type), ("200 OK", CONTENT_TYPE_HTML));
        assert!(html.contains("m1.internal"));
        assert!(html.contains("for 2m 05s"));
        assert!(html.contains("href=\"/servers/m1.internal/\""));
        assert!(html.contains("3 failed attempts, next in"));
        assert!(html.contains("connects on first use"));

        let (line, content_type, text) = render(&status(), StatusFormat::Text);
        assert_eq!((line, content_type), ("200 OK", CONTENT_TYPE_TEXT));
        assert!(text.contains("socks5: 127.0.0.1:1080"));
        assert!(text.contains("http: off"));
        assert!(text.contains("m2.internal"));
        assert!(text.contains("state: backoff"));
        assert!(text.contains("last error: Signaling error: timed out"));
    }

    #[test]
    fn never_idle_is_reported() {
        let mut status = status();
        status.idle_timeout = None;
        let (_, _, body) = render(&status, StatusFormat::Json);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(json["idle_timeout_secs"].is_null());
        let (_, _, text) = render(&status, StatusFormat::Text);
        assert!(text.contains("idle timeout: never"));
    }

    #[test]
    fn durations_read_naturally() {
        assert_eq!(human_duration(7), "7s");
        assert_eq!(human_duration(125), "2m 05s");
        assert_eq!(human_duration(3725), "1h 02m");
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
