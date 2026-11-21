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
use super::routed_set::{Coverage, RoutedSet, Rule};
use super::destination::{ClientAuth, dial_server, exchange_hello};
use super::status_page::{CONTENT_TYPE_JSON, STATUS_JSON_PATH, StatusFormat};
use crate::auth::ClientKey;
use crate::error::{ProxyError, ProxyResult};
use crate::transport::endpoint::{PendingCloses, RelayConfig, create_client_endpoint};
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointId};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use tokio::sync::oneshot;

/// What a server routes: its `routed_domains` and `routed_cidrs` as
/// configured, in the syntax a destination's own lists use.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerRoutes {
    pub routed_domains: Vec<String>,
    pub routed_cidrs: Vec<String>,
}

impl ServerRoutes {
    /// Each of `own`'s rules with how much of it these routes cover: whether
    /// the server accepts what is sent under it. Fails when the server's lists
    /// are not a routed set this client can read.
    pub fn coverage_of(&self, own: &RoutedSet) -> anyhow::Result<HashMap<Rule, Coverage>> {
        let server = RoutedSet::new(&self.routed_domains, &self.routed_cidrs)?;
        Ok(own.rules().into_iter().map(|rule| { let coverage = server.coverage(&rule); (rule, coverage) }).collect())
    }

    /// Read the routes out of a server's JSON status page
    /// ([`super::status_page`]), which lists them among the rest.
    fn from_status_json(body: &str) -> Result<Self, String> {
        serde_json::from_str(body)
            .map_err(|e| format!("the server's status page does not list its routes: {e}"))
    }
}

/// Ask the server `server_id` what it routes, authenticating with `key` and
/// reaching it through `relay` — what a destination for it would use. The
/// answer arrives on the returned channel; a request that could not be started
/// at all drops it.
///
/// One attempt, on an endpoint of its own: a server that is unreachable, or
/// that does not authorize `key` ([`ProxyError::AuthenticationFailed`]), is an
/// error and nothing is retried. Each step is bounded (the endpoint's relay
/// probe, the connect, the handshake, the status exchange), so the answer can
/// take about a minute against a server that never answers.
///
/// The request has a thread named `thread_name` and a runtime to itself, and
/// both last until its endpoint has closed, which comes after the answer: the
/// close waits for the peer to acknowledge it and for the endpoint's own
/// tasks, with no deadline of its own, and must neither hold the answer back
/// nor be cut short by a caller that has what it asked for. The same goes
/// for the closes the endpoint's creation stopped waiting for
/// ([`PendingCloses`]): a relay probe's, or the endpoint's own when it never
/// came online.
pub fn fetch_server_routes(
    thread_name: &str,
    server_id: EndpointId,
    key: ClientKey,
    relay: RelayConfig,
) -> oneshot::Receiver<ProxyResult<ServerRoutes>> {
    on_own_thread(thread_name, move |answer| async move {
        let auth = ClientAuth::Key(Box::new(key));
        let closes = PendingCloses::new();
        let endpoint = create_client_endpoint(&relay, &closes).await;
        let routes = match &endpoint {
            Ok(endpoint) => fetch_over(&endpoint.endpoint(), server_id, &relay, &auth).await,
            Err(e) => Err(ProxyError::Signaling(format!(
                "Failed to create the iroh endpoint: {e:#}"
            ))),
        };
        if let Err(e) = &routes {
            log::warn!("Asking server {server_id} for its routes failed: {e}");
        }
        // The answer first, then the closes, on every outcome.
        let _ = answer.send(routes);
        if let Ok(endpoint) = endpoint {
            endpoint.close().await;
        }
        closes.finished().await;
    })
}

/// Run `request` on a thread named `thread_name` with a runtime of its own,
/// handing it the sender of the returned channel. Thread and runtime last
/// until the request's future ends — not merely until it has answered — so
/// what it does after answering runs to its end. A thread that cannot be
/// spawned drops the channel.
fn on_own_thread<T, F>(
    thread_name: &str,
    request: impl FnOnce(oneshot::Sender<ProxyResult<T>>) -> F + Send + 'static,
) -> oneshot::Receiver<ProxyResult<T>>
where
    T: Send + 'static,
    F: Future<Output = ()>,
{
    let (answer_tx, answer) = oneshot::channel();
    let spawned = std::thread::Builder::new().name(thread_name.into()).spawn(move || {
        match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(runtime) => runtime.block_on(request(answer_tx)),
            Err(e) => {
                let _ = answer_tx.send(Err(ProxyError::Signaling(format!(
                    "Failed to build a runtime for the request: {e:#}"
                ))));
            }
        }
    });
    if let Err(e) = spawned {
        // The sender went down with the closure, so the receiver reports a
        // dropped request; say why here.
        log::error!("Failed to spawn the {thread_name} thread for a request: {e:#}");
    }
    answer
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

    read_routes(connection).await.map_err(ProxyError::Signaling)
}

/// Read the routes off the JSON status page of the server on `connection`,
/// which is already authenticated. Bounded like any status fetch.
pub(crate) async fn read_routes(connection: &Connection) -> Result<ServerRoutes, String> {
    let response =
        client_status::fetch_server_status(connection, STATUS_JSON_PATH, Some(StatusFormat::Json))
            .await?;
    let (content_type, body) = client_status::parse_server_status(&response)?;
    if content_type != CONTENT_TYPE_JSON {
        return Err(format!("the server answered its JSON status with {content_type}"));
    }
    ServerRoutes::from_status_json(body)
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

    /// A request's answer is there as soon as it is sent, and what the request
    /// does afterwards — closing its endpoint — still runs to its end: the
    /// thread and runtime are not gone with the answer.
    #[test]
    fn a_request_goes_on_after_its_answer() {
        let (release, released) = oneshot::channel::<()>();
        let (done, finished) = std::sync::mpsc::channel::<()>();
        let answer = on_own_thread("test-request", move |answer| async move {
            let _ = answer.send(Ok(7));
            // The close: it needs the runtime, well after the answer.
            let _ = released.await;
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            let _ = done.send(());
        });

        assert_eq!(answer.blocking_recv().expect("answered").unwrap(), 7);
        assert!(finished.try_recv().is_err(), "still closing");
        release.send(()).unwrap();
        finished
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the request ran to its end");
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
