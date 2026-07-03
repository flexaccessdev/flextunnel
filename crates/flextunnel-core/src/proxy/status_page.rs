//! The `flextunnel.internal` server status page and the reserved-subdomain 404,
//! served as HTTP responses over the tunnel stream.
//!
//! The status page reflects the **server's** live routing config, so it is
//! rendered server-side (with askama) and written back to the client as opaque
//! HTTP bytes over the same QUIC stream a normal tunnel would use. The client
//! splices those bytes verbatim to the local app, so `http://flextunnel.internal`
//! renders in the browser. HTTPS is not terminated — this is HTTP-only.

use askama::Template;
use iroh::endpoint::SendStream;
use std::fmt::Write as _;
use std::io;
use tokio::io::AsyncWriteExt;

use crate::proxy::signaling;

/// Plain-text status endpoint under `flextunnel.internal`.
pub const STATUS_TEXT_PATH: &str = "/status.txt";

const CONTENT_TYPE_HTML: &str = "text/html; charset=utf-8";
const CONTENT_TYPE_TEXT: &str = "text/plain; charset=utf-8";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatusFormat {
    Html,
    Text,
}

/// One configured reverse route plus whether its agent is currently registered.
pub struct AgentRouteStatus {
    pub name: String,
    pub machine_id: String,
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
    /// Configured agent routes, sorted by alias for stable output.
    pub agent_routes: Vec<AgentRouteStatus>,
    pub blocklist_path: String,
    pub blocked_client_count: usize,
    pub blocked_agent_count: usize,
    pub conflicted_server_count: usize,
}

/// The `*.flextunnel.internal` "reserved for future use" page.
#[derive(Template)]
#[template(path = "reserved_404.html")]
pub struct ReservedNotFoundTemplate;

/// Fallback body used if a template fails to render (should not happen with
/// compiled templates, but we never drop the stream uncleanly over it).
const FALLBACK_BODY: &str =
    "<!DOCTYPE html><title>flextunnel</title><p>status page unavailable</p>";

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
        StatusFormat::Text => ("200 OK", CONTENT_TYPE_TEXT, render_status_text(tpl)),
    }
}

fn render_status_text(tpl: &ServerStatusTemplate) -> String {
    let mut out = String::new();
    writeln!(&mut out, "flextunnel server status").expect("write to String");
    writeln!(&mut out, "version: {}", tpl.version).expect("write to String");
    writeln!(&mut out, "server_node_id: {}", tpl.node_id).expect("write to String");
    writeln!(&mut out).expect("write to String");

    write_string_list(&mut out, "routed_domains", &tpl.routed_domains);
    write_string_list(&mut out, "routed_cidrs", &tpl.routed_cidrs);
    write_pair_list(&mut out, "host_aliases", &tpl.host_aliases);

    writeln!(&mut out, "agent_routes:").expect("write to String");
    if tpl.agent_routes.is_empty() {
        writeln!(&mut out, "  none configured").expect("write to String");
    } else {
        for route in &tpl.agent_routes {
            let status = if route.connected {
                "connected"
            } else {
                "disconnected"
            };
            writeln!(
                &mut out,
                "  - {} -> {} ({status})",
                route.name, route.machine_id
            )
            .expect("write to String");
        }
    }
    writeln!(&mut out).expect("write to String");

    writeln!(&mut out, "duplicate_id_blocklist:").expect("write to String");
    writeln!(&mut out, "  file: {}", tpl.blocklist_path).expect("write to String");
    writeln!(
        &mut out,
        "  blocked_clients: {}",
        tpl.blocked_client_count
    )
    .expect("write to String");
    writeln!(&mut out, "  blocked_agents: {}", tpl.blocked_agent_count)
        .expect("write to String");
    writeln!(
        &mut out,
        "  conflicted_servers: {}",
        tpl.conflicted_server_count
    )
    .expect("write to String");

    out
}

fn write_string_list(out: &mut String, title: &str, values: &[String]) {
    writeln!(out, "{title}:").expect("write to String");
    if values.is_empty() {
        writeln!(out, "  none").expect("write to String");
    } else {
        for value in values {
            writeln!(out, "  - {value}").expect("write to String");
        }
    }
    writeln!(out).expect("write to String");
}

fn write_pair_list(out: &mut String, title: &str, values: &[(String, String)]) {
    writeln!(out, "{title}:").expect("write to String");
    if values.is_empty() {
        writeln!(out, "  none configured").expect("write to String");
    } else {
        for (name, target) in values {
            writeln!(out, "  - {name} -> {target}").expect("write to String");
        }
    }
    writeln!(out).expect("write to String");
}

/// Render the reserved-subdomain 404 page.
pub fn render_reserved_404() -> (&'static str, &'static str, String) {
    let body = ReservedNotFoundTemplate
        .render()
        .unwrap_or_else(|_| FALLBACK_BODY.to_string());
    ("404 Not Found", CONTENT_TYPE_HTML, body)
}

/// Write the per-stream success byte that lets the local client start relaying.
pub async fn write_tunnel_success(send: &mut SendStream) -> io::Result<()> {
    signaling::write_reply(send, signaling::REP_SUCCESS).await?;
    send.flush().await
}

/// Write an HTTP/1.1 response after the per-stream success byte has been sent.
pub async fn write_http_payload(
    send: &mut SendStream,
    status_line: &str,
    content_type: &str,
    body: &str,
) -> io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status_line}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n{body}",
        body.len(),
    );
    send.write_all(response.as_bytes()).await?;
    send.flush().await?;
    let _ = send.finish();
    Ok(())
}

/// Write an HTTP/1.1 response as the tunnel-stream payload.
///
/// The client expects the per-stream success reply byte first (as with any
/// established tunnel), then treats the rest of the stream as opaque bytes to
/// splice to the local app — here, our HTTP response. `Connection: close` and a
/// `Content-Length` let the browser complete the response, and finishing the
/// stream signals EOF.
pub async fn write_http_response(
    send: &mut SendStream,
    status_line: &str,
    content_type: &str,
    body: &str,
) -> io::Result<()> {
    write_tunnel_success(send).await?;
    write_http_payload(send, status_line, content_type, body).await
}
