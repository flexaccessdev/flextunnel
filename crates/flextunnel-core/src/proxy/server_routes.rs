//! A server's routed set, asked of the server itself.
//!
//! A client routes by its own per-destination lists and a server enforces its
//! own (see [`super::routed_set`]); the two are configured separately, and a
//! target a client sends that its server does not route is refused. This is
//! what reads the server's lists so a destination can be set up to match
//! them: one connection — dial, authenticate, read the server's JSON status
//! page, disconnect — made for the question alone, apart from any running
//! client. The server needs to authorize the key, as it does for any use.
//!
//! The answer is the server's routing as of the request. It is offered to
//! whoever is filling in a destination; nothing applies it, and nothing
//! follows the server's config afterwards.

use super::client_status;
use super::destination::{ClientAuth, dial_server, exchange_hello};
use super::status_page::{CONTENT_TYPE_JSON, STATUS_JSON_PATH, StatusFormat};
use crate::auth::ClientKey;
use crate::error::{ProxyError, ProxyResult};
use crate::transport::endpoint::{RelayConfig, create_client_endpoint};
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointId};
use rand::RngExt;
use serde::{Deserialize, Serialize};

/// What a server routes: its `routed_domains` and `routed_cidrs` as
/// configured, in the syntax a destination's own lists use.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerRoutes {
    pub routed_domains: Vec<String>,
    pub routed_cidrs: Vec<String>,
}

impl ServerRoutes {
    /// Read the routes out of a server's JSON status page
    /// ([`super::status_page`]), which lists them among the rest.
    fn from_status_json(body: &str) -> Result<Self, String> {
        serde_json::from_str(body)
            .map_err(|e| format!("the server's status page does not list its routes: {e}"))
    }
}

/// Ask the server `server_id` what it routes, authenticating with `key` and
/// reaching it through `relay` — what a destination for it would use.
///
/// One attempt, on an endpoint of its own that is closed before this returns:
/// a server that is unreachable, or that does not authorize `key`
/// ([`ProxyError::AuthenticationFailed`]), is an error and nothing is
/// retried. Each step is bounded (the endpoint's relay probe, the connect,
/// the handshake, the status exchange), so the whole can take about a minute
/// against a server that never answers.
pub async fn fetch_server_routes(
    server_id: EndpointId,
    key: &ClientKey,
    relay: &RelayConfig,
) -> ProxyResult<ServerRoutes> {
    let auth = ClientAuth::Key(Box::new(key.clone()));
    let relay = relay.clone();
    // On a task of its own, so that a caller giving up on the answer never
    // drops a bound endpoint half-way: it must be closed, not dropped.
    let fetch = tokio::spawn(async move {
        let endpoint = create_client_endpoint(&relay).await.map_err(|e| {
            ProxyError::Signaling(format!("Failed to create the iroh endpoint: {e:#}"))
        })?;
        let routes = fetch_over(&endpoint.endpoint(), server_id, &relay, &auth).await;
        endpoint.close().await;
        routes
    });
    fetch
        .await
        .map_err(|e| ProxyError::Signaling(format!("the routes request did not finish: {e}")))?
}

/// [`fetch_server_routes`] from a bound `endpoint`, which stays the caller's
/// to close.
pub(crate) async fn fetch_over(
    endpoint: &Endpoint,
    server_id: EndpointId,
    relay: &RelayConfig,
    auth: &ClientAuth,
) -> ProxyResult<ServerRoutes> {
    log::info!("Asking server {server_id} what it routes");
    let connection = dial_server(endpoint, server_id, relay, auth).await?;
    let routes = ask(&connection, auth, endpoint.id()).await;
    connection.close(0u32.into(), b"done");
    routes
}

/// Authenticate on `connection` and read the routes off the server's status
/// page.
async fn ask(
    connection: &Connection,
    auth: &ClientAuth,
    own_id: EndpointId,
) -> ProxyResult<ServerRoutes> {
    // A process of one connection: its own instance nonce, and no history of
    // the server's to report a duplicate from. The control stream is held to
    // the end — the server drops the connection when it closes — and needs no
    // heartbeat for an exchange this short.
    let instance_nonce: u128 = rand::rng().random();
    let (_ctrl_send, _ctrl_recv, response) =
        exchange_hello(connection, auth, own_id, instance_nonce, false).await?;
    if !response.accepted {
        let reason = response.reject_reason.unwrap_or_else(|| "unknown".to_string());
        return Err(ProxyError::AuthenticationFailed(reason));
    }

    let response =
        client_status::fetch_server_status(connection, STATUS_JSON_PATH, Some(StatusFormat::Json))
            .await
            .map_err(ProxyError::Signaling)?;
    let (content_type, body) =
        client_status::parse_server_status(&response).map_err(ProxyError::Signaling)?;
    if content_type != CONTENT_TYPE_JSON {
        return Err(ProxyError::Signaling(format!(
            "the server answered its JSON status with {content_type}"
        )));
    }
    ServerRoutes::from_status_json(body).map_err(ProxyError::Signaling)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::status_page::{ServerStatusTemplate, render_status};

    /// The routes are read from the very JSON a server renders, so the two
    /// cannot drift apart: a renamed field fails here.
    #[test]
    fn routes_are_read_from_the_page_a_server_renders() {
        let page = |routed_domains: &[&str], routed_cidrs: &[&str]| {
            let strings = |items: &[&str]| items.iter().map(|s| s.to_string()).collect();
            let template = ServerStatusTemplate {
                version: "0.0.0",
                node_id: "serverid".to_string(),
                routed_domains: strings(routed_domains),
                routed_cidrs: strings(routed_cidrs),
                host_aliases: vec![("nas.internal".to_string(), "10.0.0.7".to_string())],
                dns_forwards: Vec::new(),
                blocklist_path: "/nonexistent/blocklist.json".to_string(),
                blocked_client_count: 0,
                conflicted_server_count: 0,
            };
            let (status_line, _, body) = render_status(&template, StatusFormat::Json);
            assert_eq!(status_line, "200 OK");
            body
        };

        let routes = ServerRoutes::from_status_json(&page(
            &["*.corp.example", "httpbin.org"],
            &["10.0.0.0/8", "::/0"],
        ))
        .unwrap();
        assert_eq!(routes.routed_domains, ["*.corp.example", "httpbin.org"]);
        assert_eq!(routes.routed_cidrs, ["10.0.0.0/8", "::/0"]);

        // A server that routes nothing but itself says so with empty lists.
        assert_eq!(
            ServerRoutes::from_status_json(&page(&[], &[])).unwrap(),
            ServerRoutes::default()
        );
    }

    /// JSON that is no status page — a list missing, or of the wrong shape —
    /// is an error, never an empty answer to fill a form with.
    #[test]
    fn a_page_without_the_lists_is_refused() {
        for body in [
            "{}",
            r#"{"routed_domains": ["a.example"]}"#,
            r#"{"routed_domains": "a.example", "routed_cidrs": []}"#,
            r#"{"routed_domains": [1], "routed_cidrs": []}"#,
            "[]",
            "not json",
        ] {
            let err = ServerRoutes::from_status_json(body).unwrap_err();
            assert!(err.contains("does not list its routes"), "{body}: {err}");
        }
    }
}
