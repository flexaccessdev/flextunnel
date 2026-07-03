//! End-to-end duplicate-id detection tests over real (loopback) iroh endpoints.
//!
//! These exercise the *actual* [`ProxyServer`] accept/handshake path — not just
//! the codecs — by binding endpoints to `127.0.0.1:0` with relay + discovery
//! disabled and connecting via a direct address, so they are fully hermetic (no
//! network, no relay, deterministic).
//!
//! They cover both misconfiguration guard rails:
//!
//! * **Duplicate server** — a client advisory makes the server self-block (record
//!   its own id + shut down), and a server refuses to start once its id is
//!   recorded (startup guard, tested via [`crate::blocklist`]).
//! * **Duplicate client** — two client processes sharing one key (same node id)
//!   are detected and the id is blocklisted. Client identity is ephemeral in
//!   production, so a fixed key is injected here — the only way to reproduce a
//!   duplicate client id, exactly as the design intends.

use crate::blocklist::BlockList;
use crate::proxy::signaling::{self, Hello, HelloResponse, Target};
use crate::proxy::{dial, ProxyServer, RoutedSet};
use crate::transport::{ALPN, build_quic_transport_config};
use iroh::endpoint::{presets, Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const TOKEN: &str = "test-token";
/// A distinct agent-token string (the server checks pool membership, not the
/// prefix, so any string works as long as the pools differ).
const AGENT_TOKEN: &str = "test-agent-token";

/// Bind a hermetic loopback endpoint: relay off, no discovery, `127.0.0.1:0`.
/// Servers get the ALPN so they can accept; clients only dial.
async fn loopback_endpoint(secret: SecretKey, is_server: bool) -> Endpoint {
    let builder = Endpoint::builder(presets::Empty)
        .relay_mode(RelayMode::Disabled)
        .transport_config(build_quic_transport_config().unwrap())
        .crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .secret_key(secret)
        .bind_addr("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .unwrap();
    let builder = if is_server {
        builder.alpns(vec![ALPN.to_vec()])
    } else {
        builder
    };
    builder.bind().await.unwrap()
}

async fn with_timeout<F: std::future::Future>(f: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(10), f)
        .await
        .expect("operation timed out")
}

/// Spawn a `ProxyServer` on `endpoint` with a single client token, an empty
/// routed set, no agents, and the given blocklist path. Returns the server's own
/// id.
fn spawn_server(endpoint: Endpoint, blocklist_path: std::path::PathBuf) -> iroh::EndpointId {
    spawn_server_full(
        endpoint,
        blocklist_path,
        HashSet::new(),
        HashMap::new(),
        Vec::new(),
    )
}

/// Spawn a `ProxyServer` with configurable agent tokens + reverse routes. Client
/// token is always [`TOKEN`]; `routed_domains` seeds the routed set (empty = deny
/// all). Returns the server's own id.
fn spawn_server_full(
    endpoint: Endpoint,
    blocklist_path: std::path::PathBuf,
    agent_valid_tokens: HashSet<String>,
    agent_routes: HashMap<String, String>,
    routed_domains: Vec<String>,
) -> iroh::EndpointId {
    let own_id = endpoint.id();
    let mut tokens = HashSet::new();
    tokens.insert(TOKEN.to_string());
    let no_cidrs: Vec<String> = Vec::new();
    let server = ProxyServer::new(
        own_id,
        tokens,
        agent_valid_tokens,
        agent_routes,
        HashMap::new(),
        RoutedSet::new(&routed_domains, &no_cidrs).unwrap(),
        routed_domains,
        no_cidrs,
        BlockList::load(blocklist_path).unwrap(),
    );
    tokio::spawn(async move {
        // Surface why the server task ended — captured by the test harness and
        // shown on failure, aiding diagnosis. This must NOT panic: a
        // duplicate-server self-block legitimately returns `Err` here (it's the
        // expected outcome of one test), so it's informational, not an assertion.
        if let Err(e) = server.run(&endpoint).await {
            eprintln!("e2e test server task ended: {e}");
        }
    });
    own_id
}

/// Perform the client side of the auth handshake and return the open control
/// stream + the server's response.
async fn client_handshake(
    ep: &Endpoint,
    server_addr: EndpointAddr,
    nonce: u128,
    duplicate_server_observed: bool,
) -> (Connection, SendStream, RecvStream, HelloResponse) {
    let conn = with_timeout(ep.connect(server_addr, ALPN)).await.unwrap();
    let (mut send, mut recv) = with_timeout(conn.open_bi()).await.unwrap();
    let mut hello = Hello::new(TOKEN, nonce);
    hello.duplicate_server_observed = duplicate_server_observed;
    signaling::write_message(&mut send, &signaling::encode_hello(&hello).unwrap())
        .await
        .unwrap();
    send.flush().await.unwrap();
    let data = with_timeout(signaling::read_message(
        &mut recv,
        signaling::MAX_HANDSHAKE_SIZE,
    ))
    .await
    .unwrap();
    let resp = signaling::decode_hello_response(&data).unwrap();
    (conn, send, recv, resp)
}

/// Perform the agent side of the auth handshake (`role = Agent` + machine id)
/// and return the open control stream + the server's response.
async fn agent_handshake(
    ep: &Endpoint,
    server_addr: EndpointAddr,
    machine_id: &str,
    nonce: u128,
) -> (Connection, SendStream, RecvStream, HelloResponse) {
    let conn = with_timeout(ep.connect(server_addr, ALPN)).await.unwrap();
    let (mut send, mut recv) = with_timeout(conn.open_bi()).await.unwrap();
    let hello = Hello::new_agent(AGENT_TOKEN, nonce, machine_id);
    signaling::write_message(&mut send, &signaling::encode_hello(&hello).unwrap())
        .await
        .unwrap();
    send.flush().await.unwrap();
    let data = with_timeout(signaling::read_message(
        &mut recv,
        signaling::MAX_HANDSHAKE_SIZE,
    ))
    .await
    .unwrap();
    let resp = signaling::decode_hello_response(&data).unwrap();
    (conn, send, recv, resp)
}

fn temp_blocklist(tag: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "flextunnel-e2e-{tag}-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    path
}

/// Poll the persisted blocklist until `pred` holds, or panic after a timeout.
/// Replaces a fixed sleep so the persistence check waits for the server's write
/// instead of assuming a fixed delay is enough (which flakes under load).
async fn wait_for_blocklist(path: &std::path::Path, pred: impl Fn(&BlockList) -> bool) {
    let start = Instant::now();
    let deadline = Duration::from_secs(5);
    loop {
        if let Ok(bl) = BlockList::load(path.to_path_buf())
            && pred(&bl)
        {
            return;
        }
        assert!(
            start.elapsed() < deadline,
            "blocklist at {} did not reach the expected state within {deadline:?}",
            path.display()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Two clients sharing one key (same node id) with different instance nonces are
/// a confirmed duplicate: the id is blocklisted and the second is rejected.
#[tokio::test]
async fn duplicate_client_is_detected_and_blocklisted() {
    let bl_path = temp_blocklist("dupclient");

    let server_ep = loopback_endpoint(SecretKey::generate(), true).await;
    let server_addr = EndpointAddr::new(server_ep.id()).with_ip_addr(server_ep.bound_sockets()[0]);
    spawn_server(server_ep, bl_path.clone());

    // Two client processes sharing one secret → identical node id.
    let client_secret = SecretKey::generate();
    let ep1 = loopback_endpoint(client_secret.clone(), false).await;
    let ep2 = loopback_endpoint(client_secret, false).await;
    let client_id = ep1.id();

    // First client authenticates and stays live (held in scope).
    let (_conn1, _s1, _r1, resp1) = client_handshake(&ep1, server_addr.clone(), 1, false).await;
    assert!(resp1.accepted, "first client should be accepted");

    // Second client, same node id but a different instance nonce → duplicate.
    let (_conn2, _s2, _r2, resp2) = client_handshake(&ep2, server_addr.clone(), 2, false).await;
    assert!(!resp2.accepted, "duplicate client must be rejected");
    assert!(
        resp2
            .reject_reason
            .as_deref()
            .unwrap_or_default()
            .contains("duplicate"),
        "reject reason should mention duplicate: {:?}",
        resp2.reject_reason
    );

    // The server persisted the offending node id to the blocklist. Poll rather
    // than assume a fixed delay is enough (avoids flaking under load).
    wait_for_blocklist(&bl_path, |bl| bl.is_client_blocked(&client_id.to_string())).await;

    let _ = std::fs::remove_file(&bl_path);
}

/// A client advisory (`duplicate_server_observed`) makes the server self-block:
/// it records its own id in the blocklist and stops.
#[tokio::test]
async fn server_self_blocks_on_duplicate_advisory() {
    let bl_path = temp_blocklist("selfblock");

    let server_ep = loopback_endpoint(SecretKey::generate(), true).await;
    let server_addr = EndpointAddr::new(server_ep.id()).with_ip_addr(server_ep.bound_sockets()[0]);
    let own_id = spawn_server(server_ep, bl_path.clone());

    let client_ep = loopback_endpoint(SecretKey::generate(), false).await;
    let (_conn, _s, _r, resp) = client_handshake(&client_ep, server_addr, 9, true).await;
    assert!(!resp.accepted, "self-blocking server should reject the connection");

    // The server recorded its own id as conflicted. Poll rather than assume a
    // fixed delay is enough (avoids flaking under load).
    wait_for_blocklist(&bl_path, |bl| bl.is_server_conflicted(&own_id.to_string())).await;

    let _ = std::fs::remove_file(&bl_path);
}

/// End-to-end reverse routing: a client requests a hostname reserved in
/// `[agent_routes]`; the server forwards the stream over the connected agent's
/// live connection, the agent dials its own loopback, and bytes round-trip.
#[tokio::test]
async fn agent_reverse_route_pipes_to_agent_loopback() {
    // A tiny echo server on the agent's loopback: greets "HELLO", then echoes.
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = echo.accept().await {
            tokio::spawn(async move {
                let _ = sock.write_all(b"HELLO").await;
                let mut buf = [0u8; 256];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });

    let machine_id = "reverse-route-machine-id";
    let alias = "web.internal";
    let routes = HashMap::from([(alias.to_string(), machine_id.to_string())]);
    let agent_tokens = HashSet::from([AGENT_TOKEN.to_string()]);

    let server_ep = loopback_endpoint(SecretKey::generate(), true).await;
    let server_addr = EndpointAddr::new(server_ep.id()).with_ip_addr(server_ep.bound_sockets()[0]);
    // "*" routed set so the reserved alias passes the whitelist gate.
    spawn_server_full(
        server_ep,
        temp_blocklist("agentroute"),
        agent_tokens,
        routes,
        vec!["*".to_string()],
    );

    // Agent connects and serves each server-opened stream by dialing its loopback
    // (the shared exit-point body, exactly as `proxy::agent` does).
    let agent_ep = loopback_endpoint(SecretKey::generate(), false).await;
    let (agent_conn, _asend, _arecv, aresp) =
        agent_handshake(&agent_ep, server_addr.clone(), machine_id, 1).await;
    assert!(aresp.accepted, "agent should be accepted");
    let serve_conn = agent_conn.clone();
    tokio::spawn(async move {
        while let Ok((send, mut recv)) = serve_conn.accept_bi().await {
            tokio::spawn(async move {
                if let Ok(target) = signaling::read_request(&mut recv).await {
                    let _ = dial::connect_and_pipe(send, recv, &target).await;
                }
            });
        }
    });

    // Client requests the reserved alias at the echo port → routed to the agent.
    let client_ep = loopback_endpoint(SecretKey::generate(), false).await;
    let (client_conn, _cs, _cr, cresp) =
        client_handshake(&client_ep, server_addr, 2, false).await;
    assert!(cresp.accepted, "client should be accepted");

    let (mut send, mut recv) = with_timeout(client_conn.open_bi()).await.unwrap();
    signaling::write_request(&mut send, &Target::Domain(alias.to_string(), echo_port))
        .await
        .unwrap();
    send.flush().await.unwrap();
    let rep = with_timeout(signaling::read_reply(&mut recv)).await.unwrap();
    assert_eq!(rep, signaling::REP_SUCCESS, "reverse route should connect");

    // Round-trip through the agent: read the greeting, then our echoed bytes.
    send.write_all(b"ping").await.unwrap();
    send.flush().await.unwrap();
    let mut buf = [0u8; 9]; // "HELLO" + "ping"
    with_timeout(recv.read_exact(&mut buf)).await.unwrap();
    assert_eq!(&buf, b"HELLOping");

    // Keep the agent connection alive until the assertions complete.
    drop(agent_conn);
}

/// End-to-end reserved namespace: a request for `flextunnel.internal` is served
/// by the server itself as an HTTP status page (bypassing the routed-set
/// whitelist — note the routed set here does NOT contain it), and a
/// `*.flextunnel.internal` subdomain returns an HTTP 404.
#[tokio::test]
async fn reserved_internal_serves_status_page_and_subdomain_404() {
    let server_ep = loopback_endpoint(SecretKey::generate(), true).await;
    let server_addr = EndpointAddr::new(server_ep.id()).with_ip_addr(server_ep.bound_sockets()[0]);
    // A distinctive routed domain we expect to see rendered on the status page.
    // `flextunnel.internal` is deliberately NOT on the routed set.
    spawn_server_full(
        server_ep,
        temp_blocklist("reserved"),
        HashSet::new(),
        HashMap::new(),
        vec!["marker.example.com".to_string()],
    );

    let client_ep = loopback_endpoint(SecretKey::generate(), false).await;
    let (client_conn, _cs, _cr, cresp) =
        client_handshake(&client_ep, server_addr, 1, false).await;
    assert!(cresp.accepted, "client should be accepted");

    // The status host: expect an HTTP 200 whose body contains the routed domain.
    let body = fetch_reserved(&client_conn, "flextunnel.internal").await;
    assert!(body.starts_with("HTTP/1.1 200"), "status page should be 200: {body:.40}");
    assert!(
        body.contains("marker.example.com"),
        "status page should list the configured routed domain"
    );

    // A reserved subdomain: expect an HTTP 404 "reserved" page.
    let body = fetch_reserved(&client_conn, "sub.flextunnel.internal").await;
    assert!(body.starts_with("HTTP/1.1 404"), "reserved subdomain should be 404: {body:.40}");

    drop(client_conn);
}

/// Open a tunnel stream for `host:80`, send a minimal HTTP request, and return
/// the full response (after consuming the per-stream success reply byte). The
/// server responds without requiring the request, then drains it — so we write
/// the request best-effort (the drain may race the close) and read the response.
async fn fetch_reserved(conn: &Connection, host: &str) -> String {
    let (mut send, mut recv) = with_timeout(conn.open_bi()).await.unwrap();
    signaling::write_request(&mut send, &Target::Domain(host.to_string(), 80))
        .await
        .unwrap();
    send.flush().await.unwrap();
    let rep = with_timeout(signaling::read_reply(&mut recv)).await.unwrap();
    assert_eq!(rep, signaling::REP_SUCCESS, "reserved host should reply success");
    let _ = send
        .write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
        .await;
    let _ = send.finish();
    let bytes = with_timeout(recv.read_to_end(64 * 1024)).await.unwrap();
    String::from_utf8(bytes).unwrap()
}

/// Two agents presenting the *same* machine id concurrently (distinct ephemeral
/// node ids) are a duplicate: the second is rejected and the machine id is
/// blocklisted.
#[tokio::test]
async fn duplicate_agent_machine_id_is_detected_and_blocklisted() {
    let bl_path = temp_blocklist("dupagent");
    let agent_tokens = HashSet::from([AGENT_TOKEN.to_string()]);

    let server_ep = loopback_endpoint(SecretKey::generate(), true).await;
    let server_addr = EndpointAddr::new(server_ep.id()).with_ip_addr(server_ep.bound_sockets()[0]);
    spawn_server_full(server_ep, bl_path.clone(), agent_tokens, HashMap::new(), Vec::new());

    let machine_id = "dup-machine-id";

    // First agent authenticates and stays live (held in scope).
    let ep1 = loopback_endpoint(SecretKey::generate(), false).await;
    let (_c1, _s1, _r1, resp1) = agent_handshake(&ep1, server_addr.clone(), machine_id, 1).await;
    assert!(resp1.accepted, "first agent should be accepted");

    // Second agent: a different (ephemeral) node id but the same machine id.
    let ep2 = loopback_endpoint(SecretKey::generate(), false).await;
    let (_c2, _s2, _r2, resp2) = agent_handshake(&ep2, server_addr, machine_id, 2).await;
    assert!(!resp2.accepted, "duplicate agent must be rejected");
    assert!(
        resp2
            .reject_reason
            .as_deref()
            .unwrap_or_default()
            .contains("duplicate"),
        "reject reason should mention duplicate: {:?}",
        resp2.reject_reason
    );

    // The server persisted the offending machine id to the blocklist.
    wait_for_blocklist(&bl_path, |bl| bl.is_agent_blocked(machine_id)).await;

    let _ = std::fs::remove_file(&bl_path);
}

/// A same-instance agent reconnect (same instance nonce) must NOT be treated as a
/// duplicate: the stale connection is superseded and the machine id is never
/// blocklisted, so a legitimate reconnect after a network blip keeps working.
#[tokio::test]
async fn agent_reconnect_same_nonce_is_not_blocklisted() {
    let bl_path = temp_blocklist("agentreconnect");
    let agent_tokens = HashSet::from([AGENT_TOKEN.to_string()]);

    let server_ep = loopback_endpoint(SecretKey::generate(), true).await;
    let server_addr = EndpointAddr::new(server_ep.id()).with_ip_addr(server_ep.bound_sockets()[0]);
    spawn_server_full(server_ep, bl_path.clone(), agent_tokens, HashMap::new(), Vec::new());

    let machine_id = "reconnect-machine-id";
    let nonce = 42u128;

    // First connection authenticates and stays live (held in scope, mimicking a
    // stale connection not yet reaped when the agent reconnects).
    let ep1 = loopback_endpoint(SecretKey::generate(), false).await;
    let (_c1, _s1, _r1, resp1) = agent_handshake(&ep1, server_addr.clone(), machine_id, nonce).await;
    assert!(resp1.accepted, "first agent should be accepted");

    // Reconnect: a fresh (ephemeral) node id but the SAME machine id and nonce.
    let ep2 = loopback_endpoint(SecretKey::generate(), false).await;
    let (_c2, _s2, _r2, resp2) = agent_handshake(&ep2, server_addr, machine_id, nonce).await;
    assert!(resp2.accepted, "same-instance reconnect must be accepted: {:?}", resp2.reject_reason);

    // The machine id must NOT have been blocklisted.
    assert!(
        !BlockList::load(bl_path.clone()).unwrap().is_agent_blocked(machine_id),
        "a same-instance reconnect must never blocklist the machine id"
    );

    let _ = std::fs::remove_file(&bl_path);
}

/// The startup guard: a server whose own id is already recorded as conflicted
/// must be refused. (The CLI performs the same check in `run_server`; here we
/// assert the underlying predicate the guard relies on.)
#[tokio::test]
async fn startup_guard_recognizes_conflicted_own_id() {
    let bl_path = temp_blocklist("startupguard");

    let secret = SecretKey::generate();
    let own_id = secret.public();

    let mut bl = BlockList::load(bl_path.clone()).unwrap();
    assert!(!bl.is_server_conflicted(&own_id.to_string()));
    bl.add_conflicted_server(&own_id.to_string(), "test");
    crate::blocklist::write_atomic(bl.path(), &bl.to_json().unwrap()).unwrap();

    // A fresh load (as the CLI does at startup) sees the conflict and would bail.
    let reloaded = BlockList::load(bl_path.clone()).unwrap();
    assert!(reloaded.is_server_conflicted(&own_id.to_string()));

    let _ = std::fs::remove_file(&bl_path);
}
