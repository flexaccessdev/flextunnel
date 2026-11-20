//! End-to-end tests over real (loopback) iroh endpoints.
//!
//! These exercise the *actual* [`ProxyServer`] accept/handshake path and the
//! full [`ProxyClient`] session — not just the codecs — by binding endpoints to
//! `127.0.0.1:0` with relay + discovery disabled and connecting via a direct
//! address, so they are fully hermetic (no network, no relay, deterministic).
//!
//! The client tests cover the lazy model: nothing connects before first use,
//! each destination reaches its own server, routes pick the destination,
//! requests are held while a destination connects, an idle connection is
//! closed and redialed, and one destination's failure leaves the others alone.
//!
//! The server tests cover both misconfiguration guard rails:
//!
//! * **Duplicate server** — a client advisory makes the server self-block (record
//!   its own id + shut down), and a server refuses to start once its id is
//!   recorded (startup guard, tested via [`crate::blocklist`]).
//! * **Duplicate client** — two client processes sharing one key (same node id)
//!   are detected and the id is blocklisted. Client identity is ephemeral in
//!   production, so a fixed key is injected here — the only way to reproduce a
//!   duplicate client id, exactly as the design intends.

use crate::blocklist::BlockList;
use crate::proxy::signaling::{self, BridgeHello, Hello, HelloResponse, StreamRequest, Target};
use crate::proxy::dns_forward::DnsForwarder;
use crate::proxy::{
    BridgeUpstream, BridgeUpstreamConfig, ClientAuth, ClientConfig, DestinationConfig,
    DestinationState, DestinationStatus, EndpointProvider, ForwardManager, ForwardSpec,
    LocalListeners, ProxyClient, ProxyServer, ProxyServerParams, RoutedSet,
};
use crate::transport::endpoint::{
    AllowlistHook, ClientEndpoint, EndpointAllowlists, RelayConfig,
};
use crate::transport::{ALPN, BRIDGE_ALPN, QUICK_ALPN, build_quic_transport_config};
use iroh::address_lookup::MemoryLookup;
use iroh::endpoint::{presets, Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The one authorized client keypair shared by the tests: servers authorize
/// its public half, clients sign their handshakes with it.
fn test_client_key() -> &'static crate::auth::ClientKey {
    static KEY: std::sync::OnceLock<crate::auth::ClientKey> = std::sync::OnceLock::new();
    KEY.get_or_init(|| crate::auth::ClientKey::generate().unwrap())
}

/// An authorized-keys set holding only [`test_client_key`]'s public half.
fn test_authorized_keys() -> crate::auth::AuthorizedKeys {
    flexaccess_keys::parse_authorized_key_entries(
        &[test_client_key().public_str()],
        "e2e_tests",
    )
    .unwrap()
}

/// A valid signed auth payload for `ep` (binding its own endpoint id), signed
/// with [`test_client_key`].
fn test_auth_payload(ep: &Endpoint) -> signaling::ClientAuthPayload {
    signaling::ClientAuthPayload {
        public_key: test_client_key().public_str(),
        endpoint_id: ep.id().to_string(),
        signature: crate::auth::sign_endpoint_id(test_client_key(), &ep.id()),
    }
}

/// Bind a hermetic loopback endpoint: relay off, no discovery, `127.0.0.1:0`.
/// Servers get the ALPNs so they can accept (with the allowlisted paths —
/// inbound bridging and quick clients — disabled: the hook gets empty sets);
/// clients only dial.
async fn loopback_endpoint(secret: SecretKey, is_server: bool) -> Endpoint {
    loopback_endpoint_seeded(secret, is_server, Vec::new()).await
}

/// Like [`loopback_endpoint`] but pre-seeded with out-of-band addresses for
/// `peers`, so an id-only dial — as a bridge upstream performs — resolves
/// hermetically (no relay, no discovery).
async fn loopback_endpoint_seeded(
    secret: SecretKey,
    is_server: bool,
    peers: Vec<EndpointAddr>,
) -> Endpoint {
    loopback_endpoint_full(
        secret,
        is_server,
        MemoryLookup::from_endpoint_info(peers),
        EndpointAllowlists::default(),
    )
    .await
}

/// The full-knob loopback endpoint: servers accept all three ALPNs and install
/// the native allowlist hook over `allowlists` (mirroring
/// `create_server_endpoint`); clients only dial. The externally-held
/// [`MemoryLookup`] (Arc-backed) lets a test add peer addresses *after*
/// binding — needed when two endpoints must learn each other's ephemeral
/// addresses.
async fn loopback_endpoint_full(
    secret: SecretKey,
    is_server: bool,
    lookup: MemoryLookup,
    allowlists: EndpointAllowlists,
) -> Endpoint {
    let builder = Endpoint::builder(presets::Empty)
        .relay_mode(RelayMode::Disabled)
        .transport_config(build_quic_transport_config().unwrap())
        .crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .secret_key(secret)
        .bind_addr("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .unwrap()
        .address_lookup(lookup);
    let builder = if is_server {
        builder
            .alpns(vec![ALPN.to_vec(), BRIDGE_ALPN.to_vec(), QUICK_ALPN.to_vec()])
            .hooks(AllowlistHook::new(allowlists))
    } else {
        builder
    };
    builder.bind().await.unwrap()
}

/// [`EndpointAllowlists`] with only the bridge set populated.
fn bridge_allowlist(ids: impl IntoIterator<Item = EndpointId>) -> EndpointAllowlists {
    EndpointAllowlists {
        bridge_servers: ids.into_iter().collect(),
        quick_clients: HashSet::new(),
    }
}

async fn with_timeout<F: std::future::Future>(f: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(10), f)
        .await
        .expect("operation timed out")
}

/// Spawn a `ProxyServer` on `endpoint` with a single authorized client key, an empty
/// routed set, and the given blocklist path. Returns the server's own id.
fn spawn_server(endpoint: Endpoint, blocklist_path: std::path::PathBuf) -> iroh::EndpointId {
    spawn_server_full(endpoint, blocklist_path, HashMap::new(), Vec::new())
}

/// Spawn a `ProxyServer` with configurable host aliases. The authorized client
/// key is always [`test_client_key`]; `routed_domains` seeds the routed set
/// (empty = deny all). Returns
/// the server's own id.
fn spawn_server_full(
    endpoint: Endpoint,
    blocklist_path: std::path::PathBuf,
    host_aliases: HashMap<String, String>,
    routed_domains: Vec<String>,
) -> iroh::EndpointId {
    spawn_server_dns(endpoint, blocklist_path, host_aliases, routed_domains, HashMap::new())
}

/// Like [`spawn_server_full`] but also seeds the conditional DNS-forwarding
/// table (`[dns_forwards]`), exercised by the status-page test.
fn spawn_server_dns(
    endpoint: Endpoint,
    blocklist_path: std::path::PathBuf,
    host_aliases: HashMap<String, String>,
    routed_domains: Vec<String>,
    dns_forwards: HashMap<String, Vec<String>>,
) -> iroh::EndpointId {
    let own_id = endpoint.id();
    let no_cidrs: Vec<String> = Vec::new();
    let dns_forwarder = DnsForwarder::new(&dns_forwards).unwrap();
    let server = ProxyServer::new(ProxyServerParams {
        own_id,
        authorized_keys: test_authorized_keys(),
        allowed_bridge_servers: HashSet::new(),
        host_aliases,
        routed_set: RoutedSet::new(&routed_domains, &no_cidrs).unwrap(),
        routed_domains,
        routed_cidrs: no_cidrs,
        dns_forwarder,
        bridges: Vec::new(),
        blocklist: BlockList::load(blocklist_path).unwrap(),
        first_client: None,
    });
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

/// Baseline [`ProxyServerParams`]: the [`test_client_key`] authorized and
/// everything else empty/off. Bridge tests override the fields they exercise.
fn base_params(own_id: iroh::EndpointId, blocklist_path: std::path::PathBuf) -> ProxyServerParams {
    ProxyServerParams {
        own_id,
        authorized_keys: test_authorized_keys(),
        allowed_bridge_servers: HashSet::new(),
        host_aliases: HashMap::new(),
        routed_set: RoutedSet::default(),
        routed_domains: Vec::new(),
        routed_cidrs: Vec::new(),
        dns_forwarder: None,
        bridges: Vec::new(),
        blocklist: BlockList::load(blocklist_path).unwrap(),
        first_client: None,
    }
}

/// Spawn a `ProxyServer` built from explicit [`ProxyServerParams`] (the bridge
/// tests need knobs the older helpers don't expose).
fn spawn_server_params(endpoint: Endpoint, params: ProxyServerParams) {
    let server = ProxyServer::new(params);
    tokio::spawn(async move {
        if let Err(e) = server.run(&endpoint).await {
            eprintln!("e2e test server task ended: {e}");
        }
    });
}

/// [`spawn_server_params`], keeping a handle to the server so a test can ask
/// which clients are connected to it.
fn spawn_server_handle(endpoint: Endpoint, params: ProxyServerParams) -> Arc<ProxyServer> {
    let server = ProxyServer::new(params);
    tokio::spawn({
        let server = server.clone();
        async move {
            if let Err(e) = server.run(&endpoint).await {
                eprintln!("e2e test server task ended: {e}");
            }
        }
    });
    server
}

/// A routed set (and its raw rules) for all of loopback — what the bridge tests
/// tunnel and bridge.
fn loopback_cidr_set() -> (RoutedSet, Vec<String>) {
    let cidrs = vec!["127.0.0.0/8".to_string()];
    (RoutedSet::new(&[], &cidrs).unwrap(), cidrs)
}

/// An outbound bridge upstream forwarding all of loopback to `target`.
fn loopback_bridge(name: &str, target: EndpointId) -> Arc<BridgeUpstream> {
    let (routed_set, cidrs) = loopback_cidr_set();
    BridgeUpstream::new(BridgeUpstreamConfig {
        name: name.to_string(),
        endpoint_id: target,
        relay_urls: Vec::new(),
        routed_set,
        domains: Vec::new(),
        cidrs,
    })
}

/// Poll `pred` until it holds, or panic after 10s.
async fn wait_until(what: &str, pred: impl Fn() -> bool) {
    let start = Instant::now();
    while !pred() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// A tiny loopback echo server: greets "HELLO", then echoes. Returns its port.
async fn spawn_echo() -> u16 {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = echo.local_addr().unwrap().port();
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
    port
}

/// Perform the client side of the auth handshake and return the open control
/// stream + the server's response.
async fn client_handshake(
    ep: &Endpoint,
    server_addr: EndpointAddr,
    nonce: u128,
    duplicate_server_observed: bool,
) -> (Connection, SendStream, RecvStream, HelloResponse) {
    handshake_on_alpn(ep, server_addr, ALPN, nonce, duplicate_server_observed).await
}

/// [`client_handshake`] on an explicit ALPN. The `Hello` carries a
/// [`test_client_key`]-signed credential on the client ALPN and no credential
/// on the quick ALPN, matching production.
async fn handshake_on_alpn(
    ep: &Endpoint,
    server_addr: EndpointAddr,
    alpn: &[u8],
    nonce: u128,
    duplicate_server_observed: bool,
) -> (Connection, SendStream, RecvStream, HelloResponse) {
    let auth = (alpn == ALPN).then(|| test_auth_payload(ep));
    let conn = with_timeout(ep.connect(server_addr, alpn)).await.unwrap();
    let (mut send, mut recv) = with_timeout(conn.open_bi()).await.unwrap();
    let mut hello = Hello::new(auth, nonce);
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

/// Dial `server_addr` on the bridge ALPN and assert the native allowlist hook
/// rejects it (see [`assert_rejected_by_allowlist`]).
async fn assert_bridge_rejected(ep: &Endpoint, server_addr: EndpointAddr, reason: &str) {
    let hello = signaling::encode_bridge_hello(&BridgeHello::new()).unwrap();
    assert_rejected_by_allowlist(ep, server_addr, BRIDGE_ALPN, hello, reason).await;
}

/// Dial `server_addr` on the quick ALPN and assert the native allowlist hook
/// rejects it (see [`assert_rejected_by_allowlist`]).
async fn assert_quick_client_rejected(ep: &Endpoint, server_addr: EndpointAddr, reason: &str) {
    let hello = signaling::encode_hello(&Hello::new(None, 1)).unwrap();
    assert_rejected_by_allowlist(ep, server_addr, QUICK_ALPN, hello, reason).await;
}

/// Dial `server_addr` on `alpn` and assert the native allowlist hook rejects
/// it: the server closes the connection at the TLS handshake with `reason`,
/// before any application handshake (`hello`) can be exchanged.
async fn assert_rejected_by_allowlist(
    ep: &Endpoint,
    server_addr: EndpointAddr,
    alpn: &[u8],
    hello: Vec<u8>,
    reason: &str,
) {
    // The QUIC handshake itself completes on the dialer side (the rejection is
    // an application close right after it), so `connect` may return Ok; the
    // rejection then surfaces as the connection closing with the hook's
    // reason. A `connect` error (rejection raced the handshake) is fine too.
    match with_timeout(ep.connect(server_addr, alpn)).await {
        Ok(conn) => {
            // Attempting the application handshake must fail...
            let handshake = async {
                let (mut send, mut recv) = conn.open_bi().await.map_err(std::io::Error::other)?;
                signaling::write_message(&mut send, &hello).await?;
                send.flush().await?;
                signaling::read_message(&mut recv, signaling::MAX_HANDSHAKE_SIZE).await
            };
            assert!(
                with_timeout(handshake).await.is_err(),
                "a rejected peer must not complete a handshake"
            );
            // ...because the server closed the connection with the hook's reason.
            let closed = with_timeout(conn.closed()).await.to_string();
            assert!(
                closed.contains(reason),
                "close reason should say {reason:?}: {closed}"
            );
        }
        Err(e) => {
            // Rejected before `connect` resolved (the close raced the
            // handshake) — equally a refusal, but only if the error carries
            // the hook's reason. Anything else (refused socket, wrong
            // address) is a test failure, not a rejection. Walk the source
            // chain: the close reason may sit below the top-level error.
            let mut chain = e.to_string();
            let mut source = std::error::Error::source(&e);
            while let Some(s) = source {
                chain.push_str(": ");
                chain.push_str(&s.to_string());
                source = s.source();
            }
            assert!(
                chain.contains(reason),
                "connect failed without the hook's reason {reason:?}: {chain}"
            );
        }
    }
}

/// Open a tunnel stream to `127.0.0.1:port` through `conn` and assert the echo
/// round-trip ("HELLO" greeting + our echoed bytes) completes.
async fn assert_echo_roundtrip(conn: &Connection, port: u16) {
    let (mut send, mut recv) = with_timeout(conn.open_bi()).await.unwrap();
    let target = Target::Ip(format!("127.0.0.1:{port}").parse().unwrap());
    signaling::write_request(&mut send, &StreamRequest::Connect(target)).await.unwrap();
    send.flush().await.unwrap();
    let rep = with_timeout(signaling::read_reply(&mut recv)).await.unwrap();
    assert_eq!(rep, signaling::REP_SUCCESS, "tunnel stream should connect");
    send.write_all(b"ping").await.unwrap();
    send.flush().await.unwrap();
    let mut buf = [0u8; 9]; // "HELLO" + "ping"
    with_timeout(recv.read_exact(&mut buf)).await.unwrap();
    assert_eq!(&buf, b"HELLOping");
}

/// Every endpoint a client under test has built, in build order.
type Built = Arc<std::sync::Mutex<Vec<Endpoint>>>;

/// A hermetic [`EndpointProvider`]: each destination endpoint — and each
/// rebuild of one — is a fresh loopback endpoint resolving servers through
/// `lookup`, recorded in the returned [`Built`] list so a test can count the
/// builds and inspect the endpoints.
fn loopback_provider(lookup: MemoryLookup) -> (EndpointProvider, Built) {
    let built: Built = Default::default();
    let provider: EndpointProvider = {
        let built = built.clone();
        Arc::new(move |cfg: &DestinationConfig| {
            // A quick destination's endpoint must present its session identity.
            let secret = match &cfg.auth {
                ClientAuth::Quick(secret) => Some((**secret).clone()),
                ClientAuth::Key(_) => None,
            };
            let (lookup, built) = (lookup.clone(), built.clone());
            let build = move || {
                let (lookup, built, secret) = (lookup.clone(), built.clone(), secret.clone());
                async move {
                    let endpoint = loopback_endpoint_full(
                        secret.unwrap_or_else(SecretKey::generate),
                        false,
                        lookup,
                        EndpointAllowlists::default(),
                    )
                    .await;
                    built.lock().unwrap().push(endpoint.clone());
                    endpoint
                }
            };
            Box::pin(async move {
                let first = build().await;
                Ok(ClientEndpoint::from_parts(
                    first,
                    Arc::new(move || {
                        let next = build();
                        Box::pin(async move { Ok(next.await) })
                    }),
                ))
            })
        })
    };
    (provider, built)
}

/// A destination named `host` for the server `server_id`, authenticating with
/// [`test_client_key`] and routing nothing beyond its own name.
fn destination(host: &str, server_id: EndpointId) -> DestinationConfig {
    DestinationConfig {
        host: host.to_string(),
        server_id,
        auth: ClientAuth::Key(Box::new(test_client_key().clone())),
        relay: RelayConfig::default(),
        routed_domains: Vec::new(),
        routed_cidrs: Vec::new(),
        keep_connected: false,
    }
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

/// A full [`ProxyClient`] session with real SOCKS5 and HTTP front-ends.
struct TestClient {
    client: Arc<ProxyClient>,
    socks: SocketAddr,
    http: SocketAddr,
    built: Built,
    session: tokio::task::JoinHandle<()>,
}

impl TestClient {
    fn status(&self, host: &str) -> DestinationStatus {
        self.client
            .status()
            .destinations
            .into_iter()
            .find(|d| d.host == host)
            .unwrap_or_else(|| panic!("no destination {host}"))
    }

    fn state(&self, host: &str) -> DestinationState {
        self.status(host).state
    }

    /// How many endpoints the client has built so far.
    fn built(&self) -> usize {
        self.built.lock().unwrap().len()
    }

    fn endpoint(&self, index: usize) -> Endpoint {
        self.built.lock().unwrap()[index].clone()
    }
}

impl Drop for TestClient {
    fn drop(&mut self) {
        self.session.abort();
    }
}

/// Start a client session over `destinations`, whose endpoints resolve servers
/// through `lookup`.
async fn start_client(
    destinations: Vec<DestinationConfig>,
    idle_timeout: Option<Duration>,
    lookup: MemoryLookup,
) -> TestClient {
    let (provider, built) = loopback_provider(lookup);
    let client = Arc::new(
        ProxyClient::with_endpoint_provider(
            ClientConfig {
                destinations,
                idle_timeout,
            },
            provider,
        )
        .unwrap(),
    );
    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (socks, http) = (
        socks_listener.local_addr().unwrap(),
        http_listener.local_addr().unwrap(),
    );
    let session = tokio::spawn({
        let client = client.clone();
        async move {
            let listeners = LocalListeners::tcp(Some(socks_listener), Some(http_listener));
            if let Err(e) = client.run(listeners).await {
                eprintln!("e2e test client session ended: {e}");
            }
        }
    });
    TestClient {
        client,
        socks,
        http,
        built,
        session,
    }
}

/// Greet the SOCKS5 proxy at `socks` and send a CONNECT for `host:port`
/// (domain form), without waiting for the reply.
async fn socks_request(socks: SocketAddr, host: &str, port: u16) -> TcpStream {
    let mut app = TcpStream::connect(socks).await.unwrap();
    app.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    with_timeout(app.read_exact(&mut method)).await.unwrap();
    assert_eq!(method, [0x05, 0x00], "no-auth method selected");
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    app.write_all(&request).await.unwrap();
    app
}

/// Read the SOCKS5 CONNECT reply and return its reply code.
async fn socks_reply(app: &mut TcpStream) -> u8 {
    let mut reply = [0u8; 10];
    with_timeout(app.read_exact(&mut reply)).await.unwrap();
    reply[1]
}

/// SOCKS5 CONNECT to `host:port` through the proxy at `socks`.
async fn socks_connect(socks: SocketAddr, host: &str, port: u16) -> (TcpStream, u8) {
    let mut app = socks_request(socks, host, port).await;
    let rep = socks_reply(&mut app).await;
    (app, rep)
}

/// Complete the [`spawn_echo`] exchange on a connected stream: the "HELLO"
/// greeting, then our bytes echoed back.
async fn expect_echo<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(app: &mut S) {
    let mut greeting = [0u8; 5];
    with_timeout(app.read_exact(&mut greeting)).await.unwrap();
    assert_eq!(&greeting, b"HELLO");
    app.write_all(b"ping").await.unwrap();
    let mut echoed = [0u8; 4];
    with_timeout(app.read_exact(&mut echoed)).await.unwrap();
    assert_eq!(&echoed, b"ping");
}

/// SOCKS5 CONNECT to `host:port` and run the echo exchange, returning the
/// still-open stream.
async fn socks_echo(socks: SocketAddr, host: &str, port: u16) -> TcpStream {
    let (mut app, rep) = socks_connect(socks, host, port).await;
    assert_eq!(rep, signaling::REP_SUCCESS, "CONNECT {host}:{port} should succeed");
    expect_echo(&mut app).await;
    app
}

/// `GET path` on `http://flextunnel.internal` through the SOCKS5 proxy,
/// returning the whole HTTP response.
async fn status_get(socks: SocketAddr, path: &str) -> String {
    let (mut app, rep) = socks_connect(socks, "flextunnel.internal", 80).await;
    assert_eq!(rep, signaling::REP_SUCCESS, "the status host always answers");
    app.write_all(format!("GET {path} HTTP/1.1\r\nHost: flextunnel.internal\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut response = Vec::new();
    with_timeout(app.read_to_end(&mut response)).await.unwrap();
    String::from_utf8(response).unwrap()
}

/// A loopback server endpoint plus the address a client reaches it at.
async fn server_endpoint(secret: SecretKey) -> (Endpoint, EndpointAddr) {
    let endpoint = loopback_endpoint(secret, true).await;
    let addr = EndpointAddr::new(endpoint.id()).with_ip_addr(endpoint.bound_sockets()[0]);
    (endpoint, addr)
}

/// Nothing happens until a destination is used: no endpoint is built, the
/// server sees no client. The first request for the destination's own name
/// connects it and reaches the server's loopback; the connection then stays
/// for the next request.
#[tokio::test]
async fn nothing_connects_before_first_use() {
    let echo_port = spawn_echo().await;
    let (server_ep, server_addr) = server_endpoint(SecretKey::generate()).await;
    let server_id = server_ep.id();
    let bl_path = temp_blocklist("lazy-first-use");
    // An empty routed set: the destination's own name needs no server config.
    let server = spawn_server_handle(server_ep, base_params(server_id, bl_path.clone()));

    let client = start_client(
        vec![destination("m1.internal", server_id)],
        Some(Duration::from_secs(300)),
        MemoryLookup::from_endpoint_info(vec![server_addr]),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(client.built(), 0, "no endpoint before first use");
    assert_eq!(client.state("m1.internal"), DestinationState::Idle);
    assert!(server.connected_client_keys().is_empty(), "the server saw nobody");
    // Looking at the client's status is not a use.
    let page = status_get(client.socks, "/status.json").await;
    assert!(page.contains("\"state\": \"idle\""), "{page}");
    assert_eq!(client.built(), 0, "the status page connects nothing");

    let app = socks_echo(client.socks, "m1.internal", echo_port).await;
    assert_eq!(client.built(), 1);
    let status = client.status("m1.internal");
    assert_eq!(status.state, DestinationState::Connected);
    assert_eq!(status.open_streams, 1);
    assert!(status.connected_since.is_some() && status.client_node_id.is_some());
    assert_eq!(server.connected_client_keys(), [test_client_key().public_str()]);

    // The stream ends; the connection stays for the next request.
    drop(app);
    wait_until("the stream to be released", || {
        client.status("m1.internal").open_streams == 0
    })
    .await;
    assert_eq!(client.state("m1.internal"), DestinationState::Connected);
    let _app = socks_echo(client.socks, "m1.internal", echo_port).await;
    assert_eq!(client.built(), 1, "the second request reused the connection");

    let _ = std::fs::remove_file(bl_path);
}

/// Each destination name reaches its own server, and using one leaves the
/// other untouched.
#[tokio::test]
async fn each_destination_reaches_its_own_server() {
    let echo_port = spawn_echo().await;
    let (ep1, addr1) = server_endpoint(SecretKey::generate()).await;
    let (ep2, addr2) = server_endpoint(SecretKey::generate()).await;
    let (id1, id2) = (ep1.id(), ep2.id());
    let server1 = spawn_server_handle(ep1, base_params(id1, temp_blocklist("two-dest-1")));
    let server2 = spawn_server_handle(ep2, base_params(id2, temp_blocklist("two-dest-2")));

    let client = start_client(
        vec![destination("m1.internal", id1), destination("m2.internal", id2)],
        None,
        MemoryLookup::from_endpoint_info(vec![addr1, addr2]),
    )
    .await;

    let _app2 = socks_echo(client.socks, "m2.internal", echo_port).await;
    assert_eq!(client.state("m2.internal"), DestinationState::Connected);
    assert_eq!(client.state("m1.internal"), DestinationState::Idle);
    assert_eq!(client.built(), 1);
    assert_eq!(server2.connected_client_keys().len(), 1);
    assert!(server1.connected_client_keys().is_empty(), "server 1 was never dialed");

    let _app1 = socks_echo(client.socks, "M1.Internal", echo_port).await;
    assert_eq!(client.state("m1.internal"), DestinationState::Connected);
    assert_eq!(client.built(), 2, "each destination has its own endpoint");
    assert_eq!(server1.connected_client_keys().len(), 1);
    assert_ne!(
        client.status("m1.internal").client_node_id,
        client.status("m2.internal").client_node_id
    );
}

/// The client's routes pick the destination — the most specific rule across
/// destinations wins — and a target on nobody's list is dialed directly,
/// connecting nothing.
#[tokio::test]
async fn routes_pick_the_destination_and_the_rest_goes_direct() {
    let echo_port = spawn_echo().await;
    let (ep1, addr1) = server_endpoint(SecretKey::generate()).await;
    let (ep2, addr2) = server_endpoint(SecretKey::generate()).await;
    let (id1, id2) = (ep1.id(), ep2.id());
    // Each server routes what its destination sends it, aliased to loopback
    // so the echo server answers.
    let server_params = |id, tag: &str, domains: &[&str], cidrs: &[&str]| {
        let (domains, cidrs) = (strings(domains), strings(cidrs));
        ProxyServerParams {
            host_aliases: domains
                .iter()
                .map(|d| (d.clone(), "127.0.0.1".to_string()))
                .collect(),
            routed_set: RoutedSet::new(&domains, &cidrs).unwrap(),
            routed_domains: domains,
            routed_cidrs: cidrs,
            ..base_params(id, temp_blocklist(tag))
        }
    };
    spawn_server_params(ep1, server_params(id1, "routes-1", &["*.corp.test"], &[]));
    spawn_server_params(
        ep2,
        server_params(id2, "routes-2", &["db.corp.test"], &["127.0.0.0/8"]),
    );

    let mut m1 = destination("m1.internal", id1);
    m1.routed_domains = strings(&["*.corp.test"]);
    let mut m2 = destination("m2.internal", id2);
    m2.routed_domains = strings(&["db.corp.test"]);
    m2.routed_cidrs = strings(&["127.0.0.1"]);
    let client = start_client(
        vec![m1, m2],
        None,
        MemoryLookup::from_endpoint_info(vec![addr1, addr2]),
    )
    .await;
    let streams = |host: &str| client.status(host).open_streams;

    // `localhost` is on no list: dialed from here, nothing connects.
    let direct = socks_echo(client.socks, "localhost", echo_port).await;
    assert_eq!(client.built(), 0, "a direct target builds no endpoint");
    assert_eq!((streams("m1.internal"), streams("m2.internal")), (0, 0));
    drop(direct);

    // A wildcard route → its destination.
    let api = socks_echo(client.socks, "api.corp.test", echo_port).await;
    assert_eq!((streams("m1.internal"), streams("m2.internal")), (1, 0));
    assert_eq!(client.state("m2.internal"), DestinationState::Idle);

    // An exact route on the other destination beats that wildcard.
    let db = socks_echo(client.socks, "db.corp.test", echo_port).await;
    assert_eq!((streams("m1.internal"), streams("m2.internal")), (1, 1));

    // An IP (here in domain form) is routed by network.
    let ip = socks_echo(client.socks, "127.0.0.1", echo_port).await;
    assert_eq!((streams("m1.internal"), streams("m2.internal")), (1, 2));

    drop((api, db, ip));
}

/// A client route its server does not also list is refused by that server:
/// the server's routed set stays the authority.
#[tokio::test]
async fn a_route_the_server_does_not_list_is_refused() {
    let (server_ep, server_addr) = server_endpoint(SecretKey::generate()).await;
    let server_id = server_ep.id();
    spawn_server_params(server_ep, base_params(server_id, temp_blocklist("route-refused")));

    let mut m1 = destination("m1.internal", server_id);
    m1.routed_domains = strings(&["*.corp.test"]);
    let client = start_client(
        vec![m1],
        None,
        MemoryLookup::from_endpoint_info(vec![server_addr]),
    )
    .await;
    let (_app, rep) = socks_connect(client.socks, "api.corp.test", 443).await;
    assert_eq!(rep, signaling::REP_NOT_ALLOWED);
    // The destination did connect — the refusal is the server's answer.
    assert_eq!(client.state("m1.internal"), DestinationState::Connected);
}

/// Port forwards and `nc` go through the dialer, which holds a request while
/// its destination connects — here across a server that is not up yet, then
/// comes up: a failed first attempt is retried for the request still waiting.
///
/// The stand-in for "not up yet" is the server's own endpoint with nothing
/// serving on it: every accepted connection is closed on the spot, so an
/// attempt fails fast (the alternative, a dead address, would sit out the
/// full connect timeout per attempt). The server then comes up on that same
/// endpoint — same identity, same address — exactly as a late-starting
/// service would.
#[tokio::test]
async fn dialer_holds_while_the_server_comes_up() {
    let echo_port = spawn_echo().await;
    let (server_ep, server_addr) = server_endpoint(SecretKey::generate()).await;
    let server_id = server_ep.id();
    let bl_path = temp_blocklist("dialer-hold");
    let params = base_params(server_id, bl_path.clone());

    let (up_tx, mut up_rx) = tokio::sync::watch::channel(false);
    tokio::spawn({
        let server_ep = server_ep.clone();
        async move {
            loop {
                // Only the accept wait is cancellable: an accepted connection
                // is always answered (closed), never dropped on the floor.
                let incoming = tokio::select! {
                    incoming = server_ep.accept() => incoming,
                    _ = up_rx.wait_for(|up| *up) => break,
                };
                let Some(incoming) = incoming else { return };
                if let Ok(conn) = incoming.await {
                    conn.close(0u32.into(), b"not up yet");
                }
            }
            let server = ProxyServer::new(params);
            if let Err(e) = server.run(&server_ep).await {
                eprintln!("e2e dialer-hold test server task ended: {e}");
            }
        }
    });

    let client = start_client(
        vec![destination("m1.internal", server_id)],
        None,
        MemoryLookup::from_endpoint_info(vec![server_addr]),
    )
    .await;
    let dialer = client.client.dialer();

    // A forward to a host no destination routes is refused outright.
    let unrouted = dialer
        .connect(&Target::Domain("off-list.invalid".into(), 443))
        .await
        .err()
        .expect("unrouted target refused");
    assert!(unrouted.to_string().contains("no destination routes"), "{unrouted:#}");
    assert_eq!(client.built(), 0);

    // The request makes the destination dial; the attempt fails; the request
    // stays held and the destination reports the failure.
    let pending = tokio::spawn({
        let dialer = dialer.clone();
        async move {
            dialer
                .connect(&Target::Domain("m1.internal".into(), echo_port))
                .await
        }
    });
    wait_until("the first attempt to fail", || {
        client.status("m1.internal").failed_attempts >= 1
    })
    .await;
    assert!(!pending.is_finished(), "the request is held, not failed");
    let status = client.status("m1.internal");
    assert_eq!(status.waiting, 1);
    assert!(status.last_error.is_some() && status.next_attempt_at.is_some());

    // The server comes up; the retry (1s backoff) lands and the held request
    // proceeds as if nothing had happened.
    up_tx.send_replace(true);
    let mut stream = with_timeout(pending).await.unwrap().expect("held request connects");
    expect_echo(&mut stream).await;
    let status = client.status("m1.internal");
    assert_eq!(status.state, DestinationState::Connected);
    assert_eq!(status.failed_attempts, 0, "a connection clears the outage");
    assert!(status.last_error.is_none());
    assert_eq!((status.open_streams, status.waiting), (1, 0));

    let _ = std::fs::remove_file(bl_path);
}

/// A connection with no stream open for the idle timeout is closed, endpoint
/// and all, and the server sees the client leave; an open stream keeps it up
/// however long it lasts. The next request redials on a fresh endpoint.
#[tokio::test]
async fn idle_connection_is_closed_and_redialed_on_demand() {
    let echo_port = spawn_echo().await;
    let (server_ep, server_addr) = server_endpoint(SecretKey::generate()).await;
    let server_id = server_ep.id();
    let bl_path = temp_blocklist("idle-timeout");
    let server = spawn_server_handle(server_ep, base_params(server_id, bl_path.clone()));

    let idle_timeout = Duration::from_millis(300);
    let client = start_client(
        vec![destination("m1.internal", server_id)],
        Some(idle_timeout),
        MemoryLookup::from_endpoint_info(vec![server_addr]),
    )
    .await;

    // In use: well past the idle timeout, the connection is still there.
    let mut app = socks_echo(client.socks, "m1.internal", echo_port).await;
    tokio::time::sleep(idle_timeout * 3).await;
    assert_eq!(client.state("m1.internal"), DestinationState::Connected);
    app.write_all(b"more").await.unwrap();
    let mut echoed = [0u8; 4];
    with_timeout(app.read_exact(&mut echoed)).await.unwrap();
    assert_eq!(&echoed, b"more");

    // Unused: it closes, and so does its endpoint.
    drop(app);
    wait_until("the idle connection to close", || {
        client.state("m1.internal") == DestinationState::Idle
    })
    .await;
    let first = client.endpoint(0);
    wait_until("the idle endpoint to close", || first.is_closed()).await;
    wait_until("the server to see the client leave", || {
        server.connected_client_keys().is_empty()
    })
    .await;
    wait_until("the endpoint to be forgotten", || {
        client.status("m1.internal").client_node_id.is_none()
    })
    .await;
    assert_eq!(client.status("m1.internal").failed_attempts, 0, "idling is not a failure");

    // The next request redials, on a new endpoint.
    let _app = socks_echo(client.socks, "m1.internal", echo_port).await;
    assert_eq!(client.built(), 2);
    assert_eq!(client.state("m1.internal"), DestinationState::Connected);

    let _ = std::fs::remove_file(bl_path);
}

/// A connection that drops with nobody using it is not redialed: the
/// destination goes idle and stays idle — no background reconnect loop —
/// until a request wants it, which is then held for the redial.
#[tokio::test]
async fn a_dropped_connection_is_redialed_only_on_demand() {
    let echo_port = spawn_echo().await;

    // First server incarnation, on a secret the test keeps to resurrect it.
    let server_secret = SecretKey::generate();
    let (server_ep, server_addr) = server_endpoint(server_secret.clone()).await;
    let server_id = server_ep.id();
    let bl_path = temp_blocklist("drop-no-redial");
    spawn_server_params(server_ep.clone(), base_params(server_id, bl_path.clone()));

    // The lookup is held externally so the resurrected server's fresh address
    // can be published mid-test.
    let lookup = MemoryLookup::from_endpoint_info(vec![server_addr]);
    let client = start_client(vec![destination("m1.internal", server_id)], None, lookup.clone()).await;
    drop(socks_echo(client.socks, "m1.internal", echo_port).await);
    wait_until("the stream to be released", || {
        client.status("m1.internal").open_streams == 0
    })
    .await;

    // Drop the connection out from under the session.
    server_ep.close().await;
    wait_until("the destination to go idle after the drop", || {
        let status = client.status("m1.internal");
        status.state == DestinationState::Idle && status.client_node_id.is_none()
    })
    .await;
    let status = client.status("m1.internal");
    assert_eq!(status.failed_attempts, 1, "the drop is recorded");
    assert!(status.last_error.is_some());
    let built = client.built();

    // Well past the first backoff step, still nothing has been tried.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let status = client.status("m1.internal");
    assert_eq!(status.state, DestinationState::Idle);
    assert_eq!(status.failed_attempts, 1, "no attempt without a request");
    assert_eq!(client.built(), built, "no endpoint without a request");

    // Resurrect the server on the same identity (a fresh nonce — a restart,
    // not a duplicate) and publish its new address.
    let (server_ep2, server_addr2) = server_endpoint(server_secret).await;
    lookup.set_endpoint_info(server_addr2);
    spawn_server_params(server_ep2, base_params(server_id, bl_path.clone()));

    // A request brings the destination back.
    let _app = socks_echo(client.socks, "m1.internal", echo_port).await;
    let status = client.status("m1.internal");
    assert_eq!(status.state, DestinationState::Connected);
    assert_eq!(status.failed_attempts, 0);
    assert_eq!(client.built(), built + 1);

    let _ = std::fs::remove_file(bl_path);
}

/// Connection holding: a SOCKS request arriving while its destination's
/// server is unreachable is *held* while the destination redials, and then
/// proceeds transparently on the fresh connection instead of being refused
/// with network-unreachable. The request is issued during the outage, the
/// server is resurrected on the same identity, and the held request completes
/// end-to-end.
#[tokio::test]
async fn a_request_is_held_until_the_server_is_back() {
    let echo_port = spawn_echo().await;

    let server_secret = SecretKey::generate();
    let (server_ep, server_addr) = server_endpoint(server_secret.clone()).await;
    let server_id = server_ep.id();
    let bl_path = temp_blocklist("hold-reconnect");
    spawn_server_params(server_ep.clone(), base_params(server_id, bl_path.clone()));

    let lookup = MemoryLookup::from_endpoint_info(vec![server_addr]);
    let client = start_client(vec![destination("m1.internal", server_id)], None, lookup.clone()).await;
    drop(socks_echo(client.socks, "m1.internal", echo_port).await);

    // Drop the connection out from under the session and wait for it to notice.
    server_ep.close().await;
    wait_until("the client to notice the drop", || {
        client.state("m1.internal") != DestinationState::Connected
    })
    .await;

    // Issue the request during the outage: the SOCKS handshake completes (the
    // listener is up), but the CONNECT reply is held while the destination
    // waits out its backoff and redials.
    let mut app = socks_request(client.socks, "m1.internal", echo_port).await;
    let mut reply = [0u8; 10];
    // Peeked, not read: nothing of a reply that did arrive would be consumed,
    // and only the timeout — no byte and no close — means it is being held.
    let mut probe = [0u8; 1];
    let early = tokio::time::timeout(Duration::from_millis(500), app.peek(&mut probe)).await;
    assert!(
        early.is_err(),
        "the request was answered (or the connection closed) instead of held: {early:?}"
    );
    assert_eq!(client.status("m1.internal").waiting, 1);

    // Resurrect the server on the same identity and publish its new address.
    let (server_ep2, server_addr2) = server_endpoint(server_secret).await;
    lookup.set_endpoint_info(server_addr2);
    spawn_server_params(server_ep2, base_params(server_id, bl_path.clone()));

    // The redial (backoff ~1s) wakes the held request, which then proceeds:
    // the echo greeting arriving through the SOCKS stream proves it.
    with_timeout(app.read_exact(&mut reply)).await.unwrap();
    assert_eq!(
        reply[1],
        signaling::REP_SUCCESS,
        "held request should succeed once the server is back"
    );
    expect_echo(&mut app).await;

    let _ = std::fs::remove_file(bl_path);
}

/// Endpoint-rebuild escalation: when attempts keep failing on an endpoint that
/// is broken beyond repair (here: closed out from under the session — the
/// loopback stand-in for a wedged endpoint whose relay link or path state
/// never recovers), the destination must escalate to rebuilding the endpoint
/// via its factory and reconnect on the fresh one. The old endpoint can never
/// connect again, so recovery itself proves the rebuild ran; the changed node
/// id confirms it.
///
/// A kept-connected destination supplies the standing demand that drives the
/// retries, and shows it connecting unasked at start.
#[tokio::test]
async fn a_kept_destination_reconnects_by_rebuilding_a_dead_endpoint() {
    let (server_ep, server_addr) = server_endpoint(SecretKey::generate()).await;
    let server_id = server_ep.id();
    let bl_path = temp_blocklist("rebuild-endpoint");
    spawn_server_params(server_ep, base_params(server_id, bl_path.clone()));

    let mut kept = destination("m1.internal", server_id);
    kept.keep_connected = true;
    let client = start_client(
        vec![kept],
        // Never closed for idleness either way: it is kept connected.
        Some(Duration::from_millis(200)),
        MemoryLookup::from_endpoint_info(vec![server_addr]),
    )
    .await;
    let connected = || client.state("m1.internal") == DestinationState::Connected;
    wait_until("the kept destination to connect unasked", connected).await;
    let first_id = client.status("m1.internal").client_node_id;
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(connected(), "a kept destination is not closed as idle");

    // Kill the client's own endpoint. Every attempt on it fails immediately,
    // so the backoff series reaches the rebuild escalation well inside the
    // wait window.
    client.endpoint(0).close().await;
    wait_until("the client to notice the drop", || !connected()).await;
    // Own, longer bound: reaching the rebuild takes the full early backoff
    // series (1s + 2s + 4s plus jitter), which crowds `wait_until`'s 10s.
    let start = Instant::now();
    while !connected() {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "timed out waiting for the destination to reconnect on a rebuilt endpoint"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_ne!(
        client.status("m1.internal").client_node_id,
        first_id,
        "recovery must have swapped in a freshly built endpoint"
    );
    assert!(client.built() >= 2);

    let _ = std::fs::remove_file(bl_path);
}

/// A server that refuses this client's key fails that destination's requests
/// at once — the first as soon as the rejection arrives, later ones without
/// dialing at all — and the other destination is unaffected.
#[tokio::test]
async fn a_rejected_key_fails_fast_and_spares_the_other_destination() {
    let echo_port = spawn_echo().await;
    let (ep1, addr1) = server_endpoint(SecretKey::generate()).await;
    let (ep2, addr2) = server_endpoint(SecretKey::generate()).await;
    let (id1, id2) = (ep1.id(), ep2.id());
    // Server 1 authorizes somebody else's key.
    let stranger = crate::auth::ClientKey::generate().unwrap();
    spawn_server_params(
        ep1,
        ProxyServerParams {
            authorized_keys: flexaccess_keys::parse_authorized_key_entries(
                &[stranger.public_str()],
                "e2e_tests",
            )
            .unwrap(),
            ..base_params(id1, temp_blocklist("rejected-1"))
        },
    );
    spawn_server_params(ep2, base_params(id2, temp_blocklist("rejected-2")));

    let client = start_client(
        vec![destination("m1.internal", id1), destination("m2.internal", id2)],
        None,
        MemoryLookup::from_endpoint_info(vec![addr1, addr2]),
    )
    .await;

    let started = Instant::now();
    let (_app, rep) = socks_connect(client.socks, "m1.internal", echo_port).await;
    assert_eq!(rep, signaling::REP_NOT_ALLOWED);
    assert!(started.elapsed() < Duration::from_secs(5), "not held for the full window");
    let status = client.status("m1.internal");
    assert_eq!(status.state, DestinationState::Failed);
    assert!(
        status.last_error.as_deref().unwrap_or_default().contains("Authentication failed"),
        "{:?}",
        status.last_error
    );

    // Asked again right away: refused without another dial.
    let started = Instant::now();
    let (_app, rep) = socks_connect(client.socks, "m1.internal", echo_port).await;
    assert_eq!(rep, signaling::REP_NOT_ALLOWED);
    assert!(started.elapsed() < Duration::from_millis(500), "failed fast");
    assert_eq!(client.status("m1.internal").failed_attempts, 1, "no second dial");

    // The other destination works as if nothing happened.
    let _app = socks_echo(client.socks, "m2.internal", echo_port).await;
    assert_eq!(client.state("m2.internal"), DestinationState::Connected);
}

/// `http://flextunnel.internal/servers/<destination>/…` is that server's own
/// status page, fetched on demand — which connects the destination like any
/// other use — and relayed verbatim, from the SOCKS and HTTP front-ends alike.
#[tokio::test]
async fn a_servers_status_page_is_fetched_through_the_client() {
    let (server_ep, server_addr) = server_endpoint(SecretKey::generate()).await;
    let server_id = server_ep.id();
    let params = ProxyServerParams {
        routed_set: RoutedSet::new(&strings(&["marker.example.com"]), &[]).unwrap(),
        routed_domains: strings(&["marker.example.com"]),
        ..base_params(server_id, temp_blocklist("status-proxy"))
    };
    spawn_server_params(server_ep, params);

    let client = start_client(
        vec![destination("m1.internal", server_id)],
        None,
        MemoryLookup::from_endpoint_info(vec![server_addr]),
    )
    .await;

    // An unknown destination is a local 404 and connects nothing.
    let missing = status_get(client.socks, "/servers/nope.internal/status.json").await;
    assert!(missing.starts_with("HTTP/1.1 404"), "{missing:.60}");
    assert_eq!(client.built(), 0);

    // JSON through SOCKS: the server's own view, node id and routed set.
    let response = status_get(client.socks, "/servers/m1.internal/status.json").await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response:.60}");
    let body = response.split_once("\r\n\r\n").expect("headers").1;
    let status: serde_json::Value = serde_json::from_str(body).expect("server JSON status");
    assert_eq!(status["server_node_id"], server_id.to_string());
    assert_eq!(status["routed_domains"], serde_json::json!(["marker.example.com"]));
    assert_eq!(client.built(), 1, "fetching it connected the destination");
    assert_eq!(client.state("m1.internal"), DestinationState::Connected);

    // HTML at the bare path. It is the server's content under the client's
    // own host name, so the client sends it with an origin of its own.
    let response = status_get(client.socks, "/servers/m1.internal/").await;
    assert!(response.contains("Content-Type: text/html"), "{response:.200}");
    assert!(response.contains("flextunnel server status"));
    assert!(response.contains("marker.example.com"));
    let head = response.split_once("\r\n\r\n").expect("headers").0;
    assert!(head.contains("Content-Security-Policy: sandbox\r\n"), "{head}");
    assert!(head.contains("X-Content-Type-Options: nosniff"), "{head}");
    // The client's own page is its own origin and carries no sandbox.
    let own = status_get(client.socks, "/").await;
    assert!(!own.contains("Content-Security-Policy"), "{own:.300}");

    // Through the HTTP proxy as a plain GET, with `Accept` picking text.
    let mut app = TcpStream::connect(client.http).await.unwrap();
    app.write_all(
        b"GET http://flextunnel.internal/servers/m1.internal HTTP/1.1\r\n\
          Host: flextunnel.internal\r\nAccept: text/plain\r\n\r\n",
    )
    .await
    .unwrap();
    let mut response = Vec::new();
    with_timeout(app.read_to_end(&mut response)).await.unwrap();
    let response = String::from_utf8(response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response:.60}");
    assert!(response.contains("Content-Type: text/plain"), "{response:.200}");
    assert!(response.contains("flextunnel server status"));

    // The client's own page now shows the destination connected.
    let page = status_get(client.socks, "/status.json").await;
    assert!(page.contains("\"state\": \"connected\""), "{page}");
}

/// The front-end addresses are part of the status only while something
/// listens on them: closing the listeners withdraws them — with the
/// destinations still served, to the dialer — and so does the end of the
/// session, after which a dialer that outlived it is turned away at once.
#[tokio::test]
async fn listener_addresses_are_reported_only_while_served() {
    let echo_port = spawn_echo().await;
    let (server_ep, server_addr) = server_endpoint(SecretKey::generate()).await;
    let server_id = spawn_server(server_ep, temp_blocklist("listen-addrs"));
    let lookup = MemoryLookup::from_endpoint_info(vec![server_addr]);

    let client = start_client(vec![destination("m1.internal", server_id)], None, lookup.clone()).await;
    // Reported once the session is serving them (it starts on its own task).
    wait_until("the listeners to be reported", || {
        let status = client.client.status();
        (status.socks_listen, status.http_listen) == (Some(client.socks), Some(client.http))
    })
    .await;

    client.client.close_local_listeners();
    wait_until("the listeners to be withdrawn", || {
        let status = client.client.status();
        status.socks_listen.is_none() && status.http_listen.is_none()
    })
    .await;
    // Listener-only: the destination managers are still running.
    let dialer = client.client.dialer();
    let target = Target::Domain("m1.internal".into(), echo_port);
    let mut stream = with_timeout(dialer.connect(&target)).await.expect("still tunnels");
    expect_echo(&mut stream).await;
    drop(stream);

    // The session ending withdraws them too, without any close signal.
    let other = start_client(vec![destination("m1.internal", server_id)], None, lookup).await;
    wait_until("the second session's listeners to be reported", || {
        other.client.status().socks_listen.is_some()
    })
    .await;
    other.session.abort();
    wait_until("the ended session's addresses to be withdrawn", || {
        let status = other.client.status();
        status.socks_listen.is_none() && status.http_listen.is_none()
    })
    .await;

    // And once the client is closed, a dialer kept past it gets an answer.
    client.session.abort();
    client.client.close().await;
    let refused = with_timeout(dialer.connect(&target)).await.err().expect("closed");
    assert!(refused.to_string().contains("shutting down"), "{refused:#}");
}

/// Port forwards bypass the local proxy front-ends: the listener hands an
/// accepted TCP stream straight to a QUIC data stream on the destination that
/// routes the forward's target — here an idle one, which the first forwarded
/// connection brings up. The server still rejects a target outside its
/// routed-set whitelist.
#[tokio::test]
async fn a_forward_connects_its_destination_and_relays() {
    let bl_path = temp_blocklist("forward");
    let (server_ep, server_addr) = server_endpoint(SecretKey::generate()).await;
    let server_id = server_ep.id();
    let (routed_set, routed_cidrs) = loopback_cidr_set();
    let params = ProxyServerParams {
        routed_set,
        routed_cidrs,
        ..base_params(server_id, bl_path.clone())
    };
    spawn_server_params(server_ep, params);

    // The client routes more than the server allows: loopback (allowed) and a
    // domain the server does not list.
    let mut m1 = destination("m1.internal", server_id);
    m1.routed_cidrs = strings(&["127.0.0.0/8"]);
    m1.routed_domains = strings(&["off-list.invalid"]);
    let client = start_client(
        vec![m1],
        None,
        MemoryLookup::from_endpoint_info(vec![server_addr]),
    )
    .await;
    let dialer = client.client.dialer();

    let echo_port = spawn_echo().await;
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_port = probe.local_addr().unwrap().port();
    drop(probe);
    let manager = ForwardManager::new(
        tokio::runtime::Handle::current(),
        dialer.clone(),
        &[ForwardSpec {
            id: "echo".into(),
            local_port,
            target: Target::Ip(format!("127.0.0.1:{echo_port}").parse().unwrap()),
        }],
    );

    // A forward that is merely listening connects nothing.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(client.built(), 0);
    assert_eq!(client.state("m1.internal"), DestinationState::Idle);

    let mut local = None;
    for _ in 0..50 {
        match TcpStream::connect(("127.0.0.1", local_port)).await {
            Ok(stream) => {
                local = Some(stream);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    let mut local = local.expect("forward listener reachable");
    // The first forwarded connection brings the destination up.
    expect_echo(&mut local).await;
    assert_eq!(manager.statuses()[0].active, 1);
    assert_eq!(client.state("m1.internal"), DestinationState::Connected);
    assert_eq!(client.status("m1.internal").open_streams, 1);

    // Routed by the client but not by the server: the server says no.
    let rejected = dialer
        .connect(&Target::Domain("off-list.invalid".into(), 443))
        .await
        .err()
        .expect("server rejects the target");
    assert!(
        rejected.to_string().contains("not allowed"),
        "unexpected rejection: {rejected:#}"
    );

    drop(manager);
    let _ = std::fs::remove_file(bl_path);
}

/// The shared startup path ([`crate::server::prepare`], used by the CLI and
/// the desktop app) yields a server that accepts an authorized client and
/// tunnels an on-list target; dropping `serve` stops it.
#[tokio::test]
async fn prepared_server_serves_an_authorized_client() {
    let bl_path = temp_blocklist("prepared-server");
    let secret = SecretKey::generate();
    let (_, routed_cidrs) = loopback_cidr_set();
    let prepared = crate::server::prepare(crate::server::ServerOptions {
        secret_key: secret.clone(),
        authorized_keys: test_authorized_keys(),
        quick_client: None,
        first_client: None,
        relay_urls: Vec::new(),
        relay_auth_token: None,
        host_aliases: HashMap::new(),
        routed_domains: Vec::new(),
        routed_cidrs,
        dns_forwards: HashMap::new(),
        bridges: HashMap::new(),
        allowed_bridge_servers: Vec::new(),
        blocklist_file: bl_path.clone(),
    })
    .unwrap();
    assert_eq!(prepared.own_id(), secret.public());

    let server_ep = loopback_endpoint(secret, true).await;
    let server_addr = EndpointAddr::new(server_ep.id()).with_ip_addr(server_ep.bound_sockets()[0]);
    let running = Arc::new(prepared.bind_on(server_ep));
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let served = tokio::spawn({
        let running = running.clone();
        async move {
            tokio::select! {
                res = running.serve() => res.map(|()| false),
                _ = stop_rx => Ok(true),
            }
        }
    });
    assert!(running.connected_client_keys().is_empty(), "no client yet");

    let client_ep = loopback_endpoint(SecretKey::generate(), false).await;
    let (conn, ctrl_send, ctrl_recv, response) =
        client_handshake(&client_ep, server_addr, 77, false).await;
    assert!(response.accepted, "authorized client accepted");
    assert_echo_roundtrip(&conn, spawn_echo().await).await;
    // The live client shows by the key it authenticated with, until it leaves.
    assert_eq!(running.connected_client_keys(), [test_client_key().public_str()]);
    drop((ctrl_send, ctrl_recv));
    conn.close(0u32.into(), b"done");
    wait_until("the client to leave", || running.connected_client_keys().is_empty()).await;

    stop_tx.send(()).unwrap();
    let stopped = with_timeout(served).await.unwrap().unwrap();
    assert!(stopped, "serve ran until stopped");
    running.endpoint().close().await;
    let _ = std::fs::remove_file(bl_path);
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

/// The routed-set whitelist is enforced on the *requested* hostname before any
/// alias resolution, so a `*.web.internal` host alias whose subdomain was
/// never added to the routed set does NOT smuggle an off-list host past the
/// gate. The same request, once the wildcard is on the routed set, resolves
/// through the alias to the server's loopback and pipes bytes.
#[tokio::test]
async fn wildcard_host_alias_still_requires_routed_set_coverage() {
    // The alias rewrites to loopback; this echo server is the on-list dial target.
    let echo_port = spawn_echo().await;
    let host_aliases = HashMap::from([("*.web.internal".to_string(), "127.0.0.1".to_string())]);

    // --- Off-list: the alias exists, but the routed set does not cover it. ---
    let server_ep = loopback_endpoint(SecretKey::generate(), true).await;
    let server_addr = EndpointAddr::new(server_ep.id()).with_ip_addr(server_ep.bound_sockets()[0]);
    spawn_server_full(
        server_ep,
        temp_blocklist("wildcard-alias-offlist"),
        host_aliases.clone(),
        // Covers a different name — `*.web.internal` is deliberately absent.
        vec!["allowed.example.com".to_string()],
    );

    let client_ep = loopback_endpoint(SecretKey::generate(), false).await;
    let (conn, _cs, _cr, resp) = client_handshake(&client_ep, server_addr, 61, false).await;
    assert!(resp.accepted, "client should be accepted");

    let (mut send, mut recv) = with_timeout(conn.open_bi()).await.unwrap();
    signaling::write_request(
        &mut send,
        &StreamRequest::Connect(Target::Domain("db.web.internal".to_string(), echo_port)),
    )
    .await
    .unwrap();
    send.flush().await.unwrap();
    let rep = with_timeout(signaling::read_reply(&mut recv)).await.unwrap();
    assert_eq!(
        rep,
        signaling::REP_NOT_ALLOWED,
        "off-list wildcard-aliased host must be rejected by the whitelist before aliasing"
    );

    // --- On-list: add the wildcard to the routed set; the alias now resolves. ---
    let server_ep2 = loopback_endpoint(SecretKey::generate(), true).await;
    let server_addr2 =
        EndpointAddr::new(server_ep2.id()).with_ip_addr(server_ep2.bound_sockets()[0]);
    spawn_server_full(
        server_ep2,
        temp_blocklist("wildcard-alias-onlist"),
        host_aliases,
        vec!["*.web.internal".to_string()],
    );

    let client_ep2 = loopback_endpoint(SecretKey::generate(), false).await;
    let (conn2, _cs2, _cr2, resp2) = client_handshake(&client_ep2, server_addr2, 62, false).await;
    assert!(resp2.accepted, "client should be accepted");

    let (mut send2, mut recv2) = with_timeout(conn2.open_bi()).await.unwrap();
    signaling::write_request(
        &mut send2,
        &StreamRequest::Connect(Target::Domain("db.web.internal".to_string(), echo_port)),
    )
    .await
    .unwrap();
    send2.flush().await.unwrap();
    let rep2 = with_timeout(signaling::read_reply(&mut recv2)).await.unwrap();
    assert_eq!(
        rep2,
        signaling::REP_SUCCESS,
        "on-list wildcard alias should resolve to the server's loopback"
    );
    // Round-trip through the aliased loopback echo server: greeting + echo.
    send2.write_all(b"ping").await.unwrap();
    send2.flush().await.unwrap();
    let mut buf = [0u8; 9]; // "HELLO" + "ping"
    with_timeout(recv2.read_exact(&mut buf)).await.unwrap();
    assert_eq!(&buf, b"HELLOping");
}

/// End-to-end status request: a [`StreamRequest::Status`] stream is served by
/// the server itself as an HTTP status page, in the format the request's path
/// or `Accept` header asks for.
#[tokio::test]
async fn status_request_serves_the_server_status_page() {
    let server_ep = loopback_endpoint(SecretKey::generate(), true).await;
    let server_addr = EndpointAddr::new(server_ep.id()).with_ip_addr(server_ep.bound_sockets()[0]);
    // A distinctive routed domain we expect to see rendered on the status page.
    let host_aliases =
        HashMap::from([("nas.internal".to_string(), "192.168.1.9".to_string())]);
    // Two conditional DNS forwards we expect rendered on the status page (each
    // suffix must be reachable through the routed set). `corp.example.com`
    // carries two servers in a deliberate, non-sorted order; the server must
    // emit the suffixes sorted (`corp` before `marker`) while preserving each
    // suffix's server order verbatim — exercised through every serialization
    // path below.
    let dns_forwards = HashMap::from([
        (
            "marker.example.com".to_string(),
            vec!["10.9.9.9:5353".to_string()],
        ),
        (
            "corp.example.com".to_string(),
            vec!["10.1.0.11".to_string(), "10.1.0.10:5353".to_string()],
        ),
    ]);
    spawn_server_dns(
        server_ep,
        temp_blocklist("status-page"),
        host_aliases,
        vec!["marker.example.com".to_string(), "corp.example.com".to_string()],
        dns_forwards,
    );

    let client_ep = loopback_endpoint(SecretKey::generate(), false).await;
    let (client_conn, _cs, _cr, cresp) =
        client_handshake(&client_ep, server_addr, 1, false).await;
    assert!(cresp.accepted, "client should be accepted");
    // The bare path: expect an HTTP 200 whose body contains the routed domain.
    let body = fetch_status(&client_conn, "/", None).await;
    assert!(body.starts_with("HTTP/1.1 200"), "status page should be 200: {body:.40}");
    assert!(
        body.contains("marker.example.com"),
        "status page should list the configured routed domain"
    );
    assert!(
        body.contains("10.9.9.9:5353"),
        "status page should list the configured DNS forward server"
    );
    assert!(
        body.contains("10.1.0.11, 10.1.0.10:5353"),
        "status page should list the multi-server forward with servers in verbatim order"
    );
    assert!(
        body.find("10.1.0.11").unwrap() < body.find("10.9.9.9:5353").unwrap(),
        "status page should render DNS forwards sorted by suffix (corp before marker)"
    );

    let body = fetch_status(&client_conn, "/status.txt", None).await;
    assert!(body.starts_with("HTTP/1.1 200"), "text status should be 200: {body:.40}");
    assert!(
        body.contains("Content-Type: text/plain; charset=utf-8"),
        "text status should use text/plain"
    );
    assert!(
        body.contains("flextunnel server status"),
        "text status should include a plain heading"
    );
    assert!(
        body.contains("  - nas.internal -> 192.168.1.9"),
        "text status should show the configured host alias"
    );
    assert!(
        body.contains("  - marker.example.com (+ subdomains) -> 10.9.9.9:5353"),
        "text status should show the configured DNS forward"
    );
    assert!(
        body.contains("  - corp.example.com (+ subdomains) -> 10.1.0.11, 10.1.0.10:5353"),
        "text status should show the multi-server forward with servers in verbatim order"
    );
    assert!(
        body.find("  - corp.example.com (+ subdomains) -> 10.1.0.11").unwrap()
            < body.find("  - marker.example.com (+ subdomains) -> 10.9.9.9:5353").unwrap(),
        "text status should render DNS forwards sorted by suffix (corp before marker)"
    );

    let body = fetch_status(&client_conn, "/status.json", None).await;
    assert!(body.starts_with("HTTP/1.1 200"), "json status should be 200: {body:.40}");
    assert!(
        body.contains("Content-Type: application/json; charset=utf-8"),
        "json status should use application/json"
    );
    let json_body = body
        .split_once("\r\n\r\n")
        .expect("json status response should include headers")
        .1;
    let status: serde_json::Value =
        serde_json::from_str(json_body).expect("json status body should parse");
    assert_eq!(
        status["routed_domains"],
        serde_json::json!(["marker.example.com", "corp.example.com"]),
        "json status should list the configured routed domains"
    );
    assert_eq!(
        status["host_aliases"],
        serde_json::json!([{"name": "nas.internal", "target": "192.168.1.9"}]),
        "json status should list the configured host alias"
    );
    assert_eq!(
        status["dns_forwards"],
        serde_json::json!([
            {"suffix": "corp.example.com", "servers": ["10.1.0.11", "10.1.0.10:5353"]},
            {"suffix": "marker.example.com", "servers": ["10.9.9.9:5353"]},
        ]),
        "json status should list the DNS forwards sorted by suffix, servers verbatim"
    );

    // Accept-header negotiation: a `/` request with `Accept: text/plain` should
    // also return the plain-text status response (not the HTML page).
    let body = fetch_status(&client_conn, "/", Some("text/plain")).await;
    assert!(body.starts_with("HTTP/1.1 200"), "accept-text status should be 200: {body:.40}");
    assert!(
        body.contains("Content-Type: text/plain; charset=utf-8"),
        "accept-text status should use text/plain"
    );
    assert!(
        body.contains("flextunnel server status"),
        "accept-text status should include a plain heading"
    );

    drop(client_conn);
}

/// Open a stream with `request` on `conn` and return the server's reply code
/// along with the stream halves.
async fn open_stream(conn: &Connection, request: StreamRequest) -> (SendStream, RecvStream, u8) {
    let (mut send, mut recv) = with_timeout(conn.open_bi()).await.unwrap();
    signaling::write_request(&mut send, &request).await.unwrap();
    send.flush().await.unwrap();
    let rep = with_timeout(signaling::read_reply(&mut recv)).await.unwrap();
    (send, recv, rep)
}

/// End-to-end loopback request: [`StreamRequest::Loopback`] reaches
/// `localhost:<port>` on the server with an empty routed set (deny-all) and no
/// host alias — what a client destination's own name asks for.
#[tokio::test]
async fn loopback_request_dials_the_servers_own_loopback() {
    let echo_port = spawn_echo().await;
    let server_ep = loopback_endpoint(SecretKey::generate(), true).await;
    let server_addr = EndpointAddr::new(server_ep.id()).with_ip_addr(server_ep.bound_sockets()[0]);
    spawn_server(server_ep, temp_blocklist("loopback-request"));

    let client_ep = loopback_endpoint(SecretKey::generate(), false).await;
    let (conn, _cs, _cr, resp) = client_handshake(&client_ep, server_addr, 63, false).await;
    assert!(resp.accepted, "client should be accepted");

    // Plain `localhost` is off the (empty) routed set and must be refused...
    let localhost = StreamRequest::Connect(Target::Domain("localhost".to_string(), echo_port));
    let (_send, _recv, rep) = open_stream(&conn, localhost).await;
    assert_eq!(rep, signaling::REP_NOT_ALLOWED, "bare localhost is subject to the routed set");

    // ...while the loopback request bypasses it.
    let (mut send, mut recv, rep) = open_stream(&conn, StreamRequest::Loopback(echo_port)).await;
    assert_eq!(rep, signaling::REP_SUCCESS, "a loopback request bypasses the routed set");
    send.write_all(b"ping").await.unwrap();
    send.flush().await.unwrap();
    let mut buf = [0u8; 9]; // "HELLO" + "ping"
    with_timeout(recv.read_exact(&mut buf)).await.unwrap();
    assert_eq!(&buf, b"HELLOping");

    // A connect failure surfaces as a failure reply. Port 0 is unconnectable
    // on every platform (nothing can listen on it), so this never depends on
    // which loopback ports happen to be in use.
    let (_send, _recv, rep) = open_stream(&conn, StreamRequest::Loopback(0)).await;
    assert_ne!(rep, signaling::REP_SUCCESS, "closed loopback port must not reply success");
}

/// The reserved `flextunnel.internal` namespace belongs to the client, which
/// answers it locally. A server refuses it as a target outright — even one
/// that routes every hostname.
#[tokio::test]
async fn reserved_names_are_refused_as_targets() {
    let server_ep = loopback_endpoint(SecretKey::generate(), true).await;
    let server_addr = EndpointAddr::new(server_ep.id()).with_ip_addr(server_ep.bound_sockets()[0]);
    spawn_server_full(
        server_ep,
        temp_blocklist("reserved-target"),
        HashMap::new(),
        vec!["*".to_string()],
    );

    let client_ep = loopback_endpoint(SecretKey::generate(), false).await;
    let (conn, _cs, _cr, resp) = client_handshake(&client_ep, server_addr, 64, false).await;
    assert!(resp.accepted, "client should be accepted");
    for host in [
        "flextunnel.internal",
        "FlexTunnel.Internal",
        "sub.flextunnel.internal",
        "localhost.flextunnel.internal",
    ] {
        let request = StreamRequest::Connect(Target::Domain(host.to_string(), 80));
        let (_send, _recv, rep) = open_stream(&conn, request).await;
        assert_eq!(rep, signaling::REP_NOT_ALLOWED, "{host} must be refused");
    }
}

/// A server bridging in forwards its clients' routed targets and nothing
/// else: it may not ask for this server's own loopback or status page.
#[tokio::test]
async fn a_bridge_may_only_ask_for_routed_targets() {
    let echo_port = spawn_echo().await;
    let (routed_set, cidrs) = loopback_cidr_set();

    // The "bridging server" is a bare endpoint speaking the bridge handshake.
    let bridge_secret = SecretKey::generate();
    let bridge_id = bridge_secret.public();
    let server_ep = loopback_endpoint_full(
        SecretKey::generate(),
        true,
        MemoryLookup::new(),
        bridge_allowlist([bridge_id]),
    )
    .await;
    let server_addr = EndpointAddr::new(server_ep.id()).with_ip_addr(server_ep.bound_sockets()[0]);
    let mut params = base_params(server_ep.id(), temp_blocklist("bridge-requests"));
    params.routed_set = routed_set;
    params.routed_cidrs = cidrs;
    params.allowed_bridge_servers = HashSet::from([bridge_id]);
    spawn_server_params(server_ep, params);

    let bridge_ep = loopback_endpoint(bridge_secret, false).await;
    let conn = with_timeout(bridge_ep.connect(server_addr, BRIDGE_ALPN)).await.unwrap();
    let (mut ctrl_send, mut ctrl_recv) = with_timeout(conn.open_bi()).await.unwrap();
    let hello = signaling::encode_bridge_hello(&BridgeHello::new()).unwrap();
    signaling::write_message(&mut ctrl_send, &hello).await.unwrap();
    ctrl_send.flush().await.unwrap();
    let data = with_timeout(signaling::read_message(
        &mut ctrl_recv,
        signaling::MAX_HANDSHAKE_SIZE,
    ))
    .await
    .unwrap();
    assert!(signaling::decode_hello_response(&data).unwrap().accepted, "bridge accepted");

    let (_send, _recv, rep) = open_stream(&conn, StreamRequest::Loopback(echo_port)).await;
    assert_eq!(rep, signaling::REP_NOT_ALLOWED, "no loopback for a bridge");
    let (_send, _recv, rep) = open_stream(&conn, StreamRequest::Status).await;
    assert_eq!(rep, signaling::REP_NOT_ALLOWED, "no status page for a bridge");
    // A routed target is what a bridge is for.
    assert_echo_roundtrip(&conn, echo_port).await;
}

/// Ask the server for its status page over a [`StreamRequest::Status`] stream
/// — `path` and the optional `Accept` header pick the format — and return the
/// full HTTP response after consuming the per-stream success reply byte.
async fn fetch_status(conn: &Connection, path: &str, accept: Option<&str>) -> String {
    let (mut send, mut recv, rep) = open_stream(conn, StreamRequest::Status).await;
    assert_eq!(rep, signaling::REP_SUCCESS, "a status request should reply success");
    let accept_header = accept.map(|a| format!("Accept: {a}\r\n")).unwrap_or_default();
    let _ = send
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: flextunnel.internal\r\n{accept_header}\r\n")
                .as_bytes(),
        )
        .await;
    let _ = send.finish();
    let bytes = with_timeout(recv.read_to_end(64 * 1024)).await.unwrap();
    String::from_utf8(bytes).unwrap()
}

/// End-to-end bridge routing: a client stream whose target matches server A's
/// bridge rules is spliced over A's persistent upstream connection to server B,
/// which dials the target from its own network; bytes round-trip. Also asserts
/// the informational surfaces: A's outbound bridge status (connected) and B's
/// inbound allowlist status (connected).
#[tokio::test]
async fn bridge_routes_pipe_through_target_server() {
    let echo_port = spawn_echo().await;
    let (routed_set, cidrs) = loopback_cidr_set();

    // A's identity is fixed up front so B's endpoint can allowlist it at bind.
    let a_secret = SecretKey::generate();
    let a_id = a_secret.public();

    // Server B (target): natively allows bridging from A, dials loopback locally.
    let b_ep = loopback_endpoint_full(
        SecretKey::generate(),
        true,
        MemoryLookup::new(),
        bridge_allowlist([a_id]),
    )
    .await;
    let b_id = b_ep.id();
    let b_addr = EndpointAddr::new(b_id).with_ip_addr(b_ep.bound_sockets()[0]);

    // Server A (bridging): seeded with B's direct address so its id-only
    // upstream dial resolves hermetically.
    let a_ep = loopback_endpoint_seeded(a_secret, true, vec![b_addr.clone()]).await;
    let a_addr = EndpointAddr::new(a_id).with_ip_addr(a_ep.bound_sockets()[0]);

    let mut b_params = base_params(b_id, temp_blocklist("bridgetarget"));
    b_params.routed_set = routed_set.clone();
    b_params.routed_cidrs = cidrs.clone();
    b_params.allowed_bridge_servers = HashSet::from([a_id]);
    spawn_server_params(b_ep, b_params);

    let bridge = loopback_bridge("lab", b_id);
    let mut a_params = base_params(a_id, temp_blocklist("bridgesource"));
    a_params.routed_set = routed_set;
    a_params.routed_cidrs = cidrs;
    a_params.bridges = vec![bridge.clone()];
    spawn_server_params(a_ep, a_params);

    // The upstream is established in the background; wait for it.
    wait_until("bridge upstream to connect", || bridge.is_connected()).await;

    // Client → A: the loopback target matches A's bridge rules → routed via B.
    let client_ep = loopback_endpoint(SecretKey::generate(), false).await;
    let (client_conn, _cs, _cr, cresp) = client_handshake(&client_ep, a_addr, 1, false).await;
    assert!(cresp.accepted, "client should be accepted");

    assert_echo_roundtrip(&client_conn, echo_port).await;

    // A's status page shows the outbound bridge as connected.
    let body = fetch_status(&client_conn, "/status.json", None).await;
    let json_body = body.split_once("\r\n\r\n").expect("headers").1;
    let status: serde_json::Value = serde_json::from_str(json_body).expect("json status parses");
    assert_eq!(
        status["bridges"],
        serde_json::json!([{
            "name": "lab",
            "endpoint_id": b_id.to_string(),
            "domains": [],
            "cidrs": ["127.0.0.0/8"],
            "connected": true,
        }]),
        "A's json status should show the connected outbound bridge"
    );
    let html = fetch_status(&client_conn, "/", None).await;
    assert!(html.contains("lab"), "A's status page should name the bridge");
    assert!(
        html.contains(&b_id.to_string()),
        "A's status page should show the bridge target's endpoint id"
    );

    // B's status page shows the allowlisted inbound bridge as connected.
    let b_client_ep = loopback_endpoint(SecretKey::generate(), false).await;
    let (b_client_conn, _bs, _br, bresp) = client_handshake(&b_client_ep, b_addr, 2, false).await;
    assert!(bresp.accepted, "client should be accepted by B");
    let body = fetch_status(&b_client_conn, "/status.json", None).await;
    let json_body = body.split_once("\r\n\r\n").expect("headers").1;
    let status: serde_json::Value = serde_json::from_str(json_body).expect("json status parses");
    assert_eq!(
        status["inbound_bridges"],
        serde_json::json!([{ "endpoint_id": a_id.to_string(), "connected": true }]),
        "B's json status should show the allowlisted inbound bridge as connected"
    );

    drop(client_conn);
    drop(b_client_conn);
}

/// Inbound bridge gating, enforced natively by the endpoint's allowlist hook:
/// a non-allowlisted id is rejected at the TLS handshake (the connection is
/// closed with the reason — no bridge ever reaches the server's accept path),
/// and an empty allowlist means bridging is off entirely.
#[tokio::test]
async fn bridge_rejected_by_native_allowlist() {
    // Case 1: id not allowlisted (allowlist names someone else).
    let ep1 = loopback_endpoint_full(
        SecretKey::generate(),
        true,
        MemoryLookup::new(),
        bridge_allowlist([SecretKey::generate().public()]),
    )
    .await;
    let addr1 = EndpointAddr::new(ep1.id()).with_ip_addr(ep1.bound_sockets()[0]);
    let mut p1 = base_params(ep1.id(), temp_blocklist("bridgerej1"));
    p1.allowed_bridge_servers = HashSet::from([SecretKey::generate().public()]);
    spawn_server_params(ep1, p1);
    let dialer = loopback_endpoint(SecretKey::generate(), false).await;
    assert_bridge_rejected(&dialer, addr1, "allowlist").await;

    // Case 2: bridging not enabled (empty allowlist) — every bridge dial is
    // rejected up front.
    let dialer2 = loopback_endpoint(SecretKey::generate(), false).await;
    let ep2 = loopback_endpoint(SecretKey::generate(), true).await;
    let addr2 = EndpointAddr::new(ep2.id()).with_ip_addr(ep2.bound_sockets()[0]);
    let p2 = base_params(ep2.id(), temp_blocklist("bridgerej2"));
    spawn_server_params(ep2, p2);
    assert_bridge_rejected(&dialer2, addr2, "not enabled").await;
}

/// Quick mode end to end: a client whose endpoint id is on the server's quick
/// allowlist connects over the quick ALPN with **no keypair** (the server runs
/// with an empty authorized-keys set, like a quick server), is served exactly
/// like a keypair client (tunnel streams pipe), and its heartbeat refreshes
/// liveness through the same accepted path.
#[tokio::test]
async fn quick_client_authenticates_by_endpoint_id() {
    let echo_port = spawn_echo().await;
    let (routed_set, cidrs) = loopback_cidr_set();

    // The client's identity is fixed up front — its id is what the quick
    // server allowlists (the user enters it at the server prompt).
    let client_secret = SecretKey::generate();
    let client_id = client_secret.public();

    let server_ep = loopback_endpoint_full(
        SecretKey::generate(),
        true,
        MemoryLookup::new(),
        EndpointAllowlists {
            bridge_servers: HashSet::new(),
            quick_clients: HashSet::from([client_id]),
        },
    )
    .await;
    let server_addr = EndpointAddr::new(server_ep.id()).with_ip_addr(server_ep.bound_sockets()[0]);
    let mut params = base_params(server_ep.id(), temp_blocklist("quickok"));
    params.authorized_keys = Default::default(); // a quick server has no client keys at all
    params.routed_set = routed_set;
    params.routed_cidrs = cidrs;
    spawn_server_params(server_ep, params);

    let client_ep = loopback_endpoint(client_secret, false).await;
    let (conn, _cs, _cr, resp) =
        handshake_on_alpn(&client_ep, server_addr, QUICK_ALPN, 1, false).await;
    assert!(resp.accepted, "allowlisted quick client must be accepted: {:?}", resp.reject_reason);
    assert_echo_roundtrip(&conn, echo_port).await;
}

/// Quick-mode gating, enforced natively by the endpoint's allowlist hook: a
/// non-allowlisted client id is rejected at the TLS handshake, and an empty
/// quick allowlist (every normal server) rejects the quick ALPN entirely. A
/// keypair credential is no substitute: case 1's dialer presents a validly
/// signed credential the server's authorized-keys set does accept (on the
/// client ALPN), yet is still rejected — the hook closes the connection
/// before the `Hello` is ever read.
#[tokio::test]
async fn quick_client_rejected_by_native_allowlist() {
    // Case 1: quick allowlist names someone else. The server's ProxyServer
    // authorizes [`test_client_key`] (base_params), and the dialer's Hello
    // carries a valid signed credential — proving an authorized keypair cannot
    // bypass the allowlist on the quick ALPN.
    let ep1 = loopback_endpoint_full(
        SecretKey::generate(),
        true,
        MemoryLookup::new(),
        EndpointAllowlists {
            bridge_servers: HashSet::new(),
            quick_clients: HashSet::from([SecretKey::generate().public()]),
        },
    )
    .await;
    let addr1 = EndpointAddr::new(ep1.id()).with_ip_addr(ep1.bound_sockets()[0]);
    let p1 = base_params(ep1.id(), temp_blocklist("quickrej1"));
    spawn_server_params(ep1, p1);
    let dialer = loopback_endpoint(SecretKey::generate(), false).await;
    let hello_with_valid_credential =
        signaling::encode_hello(&Hello::new(Some(test_auth_payload(&dialer)), 1)).unwrap();
    assert_rejected_by_allowlist(&dialer, addr1, QUICK_ALPN, hello_with_valid_credential, "allowlist")
        .await;

    // Case 2: quick mode not enabled (empty allowlist — every normal server).
    let ep2 = loopback_endpoint(SecretKey::generate(), true).await;
    let addr2 = EndpointAddr::new(ep2.id()).with_ip_addr(ep2.bound_sockets()[0]);
    let p2 = base_params(ep2.id(), temp_blocklist("quickrej2"));
    spawn_server_params(ep2, p2);
    let dialer2 = loopback_endpoint(SecretKey::generate(), false).await;
    assert_quick_client_rejected(&dialer2, addr2, "not enabled").await;
}

/// Send `hello` on the client ALPN and return the server's response.
async fn send_hello_expect_response(
    client_ep: &Endpoint,
    server_addr: EndpointAddr,
    hello: Hello,
) -> HelloResponse {
    let conn = with_timeout(client_ep.connect(server_addr, ALPN)).await.unwrap();
    let (mut send, mut recv) = with_timeout(conn.open_bi()).await.unwrap();
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
    signaling::decode_hello_response(&data).unwrap()
}

/// Every broken credential on the regular client ALPN is an auth failure: a
/// missing payload, an unauthorized (though validly signing) key, a claimed
/// endpoint id that differs from the connection's TLS-authenticated one
/// (replaying a captured credential from another endpoint), and a corrupted
/// signature. Only the intact [`test_client_key`] credential is accepted
/// (covered by the other tests via [`client_handshake`]).
#[tokio::test]
async fn broken_credentials_on_client_alpn_are_rejected() {
    let server_ep = loopback_endpoint(SecretKey::generate(), true).await;
    let server_addr = EndpointAddr::new(server_ep.id()).with_ip_addr(server_ep.bound_sockets()[0]);
    spawn_server(server_ep, temp_blocklist("badcreds"));

    let client_ep = loopback_endpoint(SecretKey::generate(), false).await;

    // No credential at all.
    let cases: Vec<(&str, Option<signaling::ClientAuthPayload>)> = vec![
        ("missing credential", None),
        ("unauthorized key", {
            let stranger = crate::auth::ClientKey::generate().unwrap();
            Some(signaling::ClientAuthPayload {
                public_key: stranger.public_str(),
                endpoint_id: client_ep.id().to_string(),
                signature: crate::auth::sign_endpoint_id(&stranger, &client_ep.id()),
            })
        }),
        ("mismatched claimed endpoint id", {
            // Validly signed by the authorized key, but binding a *different*
            // endpoint id — a replay from another endpoint.
            let other_id = SecretKey::generate().public();
            Some(signaling::ClientAuthPayload {
                public_key: test_client_key().public_str(),
                endpoint_id: other_id.to_string(),
                signature: crate::auth::sign_endpoint_id(test_client_key(), &other_id),
            })
        }),
        ("bad signature", {
            let mut auth = test_auth_payload(&client_ep);
            auth.signature = crate::auth::sign_endpoint_id(
                &crate::auth::ClientKey::generate().unwrap(),
                &client_ep.id(),
            );
            Some(auth)
        }),
    ];
    for (what, auth) in cases {
        let resp =
            send_hello_expect_response(&client_ep, server_addr.clone(), Hello::new(auth, 5)).await;
        assert!(!resp.accepted, "{what} must be rejected");
        assert!(
            resp.reject_reason
                .as_deref()
                .unwrap_or_default()
                .contains("authentication"),
            "{what}: reject reason should mention authentication: {:?}",
            resp.reject_reason
        );
    }
}

/// Single hop: two servers bridging the same range at each other must not
/// forward in a loop. A stream bridged A→B is flagged `from_bridge` on B, so B
/// dials it locally instead of re-bridging it back to A — without the guard
/// this request would ping-pong forever and time out.
#[tokio::test]
async fn bridged_stream_is_never_rebridged() {
    let echo_port = spawn_echo().await;
    let (routed_set, cidrs) = loopback_cidr_set();

    // Both identities are fixed up front so each endpoint can natively
    // allowlist the other at bind. Each server must also learn the other's
    // ephemeral address, so bind both with shared-handle lookups and seed them
    // after binding.
    let a_secret = SecretKey::generate();
    let b_secret = SecretKey::generate();
    let a_id = a_secret.public();
    let b_id = b_secret.public();
    let a_lookup = MemoryLookup::new();
    let b_lookup = MemoryLookup::new();
    let a_ep =
        loopback_endpoint_full(a_secret, true, a_lookup.clone(), bridge_allowlist([b_id])).await;
    let b_ep =
        loopback_endpoint_full(b_secret, true, b_lookup.clone(), bridge_allowlist([a_id])).await;
    let a_addr = EndpointAddr::new(a_id).with_ip_addr(a_ep.bound_sockets()[0]);
    let b_addr = EndpointAddr::new(b_id).with_ip_addr(b_ep.bound_sockets()[0]);
    a_lookup.add_endpoint_info(b_addr);
    b_lookup.add_endpoint_info(a_addr.clone());

    let bridge_a_to_b = loopback_bridge("to-b", b_id);
    let mut a_params = base_params(a_id, temp_blocklist("rebridge-a"));
    a_params.routed_set = routed_set.clone();
    a_params.routed_cidrs = cidrs.clone();
    a_params.bridges = vec![bridge_a_to_b.clone()];
    a_params.allowed_bridge_servers = HashSet::from([b_id]);
    spawn_server_params(a_ep, a_params);

    let bridge_b_to_a = loopback_bridge("to-a", a_id);
    let mut b_params = base_params(b_id, temp_blocklist("rebridge-b"));
    b_params.routed_set = routed_set;
    b_params.routed_cidrs = cidrs;
    b_params.bridges = vec![bridge_b_to_a.clone()];
    b_params.allowed_bridge_servers = HashSet::from([a_id]);
    spawn_server_params(b_ep, b_params);

    // Both upstreams live: the loop is armed if re-bridging were possible.
    wait_until("A→B bridge to connect", || bridge_a_to_b.is_connected()).await;
    wait_until("B→A bridge to connect", || bridge_b_to_a.is_connected()).await;

    // Client → A → (bridge) → B → local dial. Success proves B did not
    // re-bridge the stream back to A.
    let client_ep = loopback_endpoint(SecretKey::generate(), false).await;
    let (client_conn, _cs, _cr, cresp) = client_handshake(&client_ep, a_addr, 1, false).await;
    assert!(cresp.accepted, "client should be accepted");
    assert_echo_roundtrip(&client_conn, echo_port).await;
}

/// A matching request while the bridge upstream is down (target server never
/// existed/bound) fails fast with host-unreachable instead of hanging.
#[tokio::test]
async fn bridge_down_returns_host_unreachable() {
    let (routed_set, cidrs) = loopback_cidr_set();

    let a_ep = loopback_endpoint(SecretKey::generate(), true).await;
    let a_id = a_ep.id();
    let a_addr = EndpointAddr::new(a_id).with_ip_addr(a_ep.bound_sockets()[0]);

    // The bridge target is a generated identity that is never bound anywhere.
    let bridge = loopback_bridge("ghost", SecretKey::generate().public());
    let mut a_params = base_params(a_id, temp_blocklist("bridgedown"));
    a_params.routed_set = routed_set;
    a_params.routed_cidrs = cidrs;
    a_params.bridges = vec![bridge];
    spawn_server_params(a_ep, a_params);

    let client_ep = loopback_endpoint(SecretKey::generate(), false).await;
    let (client_conn, _cs, _cr, cresp) = client_handshake(&client_ep, a_addr, 1, false).await;
    assert!(cresp.accepted, "client should be accepted");

    let request = StreamRequest::Connect(Target::Ip("127.0.0.1:9999".parse().unwrap()));
    let (_send, _recv, rep) = open_stream(&client_conn, request).await;
    assert_eq!(
        rep,
        signaling::REP_HOST_UNREACHABLE,
        "a down bridge should fail fast with host-unreachable"
    );
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
