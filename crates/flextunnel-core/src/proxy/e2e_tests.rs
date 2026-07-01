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
use crate::proxy::signaling::{self, Hello, HelloResponse};
use crate::proxy::{ProxyServer, Whitelist};
use crate::transport::{ALPN, build_quic_transport_config};
use iroh::endpoint::{presets, Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

const TOKEN: &str = "test-token";

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

/// Spawn a `ProxyServer` on `endpoint` with a single valid token, no whitelist,
/// and the given blocklist path. Returns the server's own id.
fn spawn_server(endpoint: Endpoint, blocklist_path: std::path::PathBuf) -> iroh::EndpointId {
    let own_id = endpoint.id();
    let mut tokens = HashSet::new();
    tokens.insert(TOKEN.to_string());
    let empty: Vec<String> = Vec::new();
    let server = ProxyServer::new(
        own_id,
        tokens,
        HashMap::new(),
        Whitelist::new(&empty, &empty).unwrap(),
        empty.clone(),
        empty,
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

fn temp_blocklist(tag: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "flextunnel-e2e-{tag}-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    path
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

    // The server persisted the offending node id to the blocklist.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let reloaded = BlockList::load(bl_path.clone()).unwrap();
    assert!(
        reloaded.is_client_blocked(&client_id.to_string()),
        "client id should be in the persisted blocklist"
    );

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

    // The server recorded its own id as conflicted.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let reloaded = BlockList::load(bl_path.clone()).unwrap();
    assert!(
        reloaded.is_server_conflicted(&own_id.to_string()),
        "server's own id should be recorded as conflicted"
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
