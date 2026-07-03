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
use std::io;
use tokio::io::AsyncWriteExt;

use crate::proxy::signaling;

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
/// error. Returns `(http_status_line, body)`.
pub fn render_status(tpl: &ServerStatusTemplate) -> (&'static str, String) {
    match tpl.render() {
        Ok(body) => ("200 OK", body),
        Err(e) => {
            log::warn!("Failed to render status page: {e}");
            ("500 Internal Server Error", FALLBACK_BODY.to_string())
        }
    }
}

/// Render the reserved-subdomain 404 page.
pub fn render_reserved_404() -> (&'static str, String) {
    let body = ReservedNotFoundTemplate
        .render()
        .unwrap_or_else(|_| FALLBACK_BODY.to_string());
    ("404 Not Found", body)
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
    body: &str,
) -> io::Result<()> {
    signaling::write_reply(send, signaling::REP_SUCCESS).await?;
    let response = format!(
        "HTTP/1.1 {status_line}\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
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
