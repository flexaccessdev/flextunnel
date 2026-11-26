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
use crate::error::ProxyError;
use crate::proxy::signaling::{self, Hello, HelloResponse, StreamRequest, Target};
use crate::proxy::{
    ClientAuth, ClientConfig, DestinationConfig, DestinationState, DestinationStatus,
    EndpointProvider, ForwardManager, ForwardSpec, HeldDestination, LocalListeners, ProxyClient,
    ProxyServer, ProxyServerParams, RoutedSet, ServerRoutes, server_routes,
};
use crate::transport::endpoint::{ClientEndpoint, RelayConfig, server_setup};
use crate::transport::{ALPN, QUICK_ALPN, build_quic_transport_config};
use iroh::address_lookup::MemoryLookup;
use iroh::endpoint::{
    Builder as EndpointBuilder, Connection, RecvStream, SendStream, Side, presets,
};
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
    flexaccess_keys::parse_authorized_key_entries(&[test_client_key().public_str()], "e2e_tests")
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
/// Servers get the ALPNs so they can accept (with quick mode disabled: the
/// hook gets an empty allowlist); clients only dial.
async fn loopback_endpoint(secret: SecretKey, is_server: bool) -> Endpoint {
    loopback_endpoint_full(secret, is_server, MemoryLookup::new(), HashSet::new()).await
}

/// The hermetic base every test endpoint is built on, in place of the relay
/// setup: relay off, no discovery, `127.0.0.1:0`. `lookup` holds out-of-band
/// addresses for the peers the endpoint dials by id alone.
fn loopback_base(side: Side, lookup: MemoryLookup) -> EndpointBuilder {
    Endpoint::builder(presets::Empty)
        .relay_mode(RelayMode::Disabled)
        .transport_config(build_quic_transport_config(side).unwrap())
        .crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .bind_addr("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .unwrap()
        .address_lookup(lookup)
}

/// The full-knob loopback endpoint: a server is made one as a real server is
/// (both ALPNs, the native allowlist hook over `quick_clients`); clients only
/// dial.
async fn loopback_endpoint_full(
    secret: SecretKey,
    is_server: bool,
    lookup: MemoryLookup,
    quick_clients: HashSet<EndpointId>,
) -> Endpoint {
    let side = if is_server {
        Side::Server
    } else {
        Side::Client
    };
    let base = loopback_base(side, lookup);
    let builder = if is_server {
        server_setup(base, secret, quick_clients)
    } else {
        base.secret_key(secret)
    };
    builder.bind().await.unwrap()
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
    let own_id = endpoint.id();
    let no_cidrs: Vec<String> = Vec::new();
    let server = ProxyServer::new(ProxyServerParams {
        own_id,
        authorized_keys: test_authorized_keys(),
        host_aliases,
        routed_set: RoutedSet::new(&routed_domains, &no_cidrs).unwrap(),
        routed_domains,
        routed_cidrs: no_cidrs,
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
/// everything else empty/off. Tests override the fields they exercise.
fn base_params(own_id: iroh::EndpointId, blocklist_path: std::path::PathBuf) -> ProxyServerParams {
    ProxyServerParams {
        own_id,
        authorized_keys: test_authorized_keys(),
        host_aliases: HashMap::new(),
        routed_set: RoutedSet::default(),
        routed_domains: Vec::new(),
        routed_cidrs: Vec::new(),
        blocklist: BlockList::load(blocklist_path).unwrap(),
        first_client: None,
    }
}

/// Spawn a `ProxyServer` built from explicit [`ProxyServerParams`].
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

/// A routed set (and its raw rules) for all of loopback.
fn loopback_cidr_set() -> (RoutedSet, Vec<String>) {
    let cidrs = vec!["127.0.0.0/8".to_string()];
    (RoutedSet::new(&[], &cidrs).unwrap(), cidrs)
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

/// Dial `server_addr` on the quick ALPN and assert the native allowlist hook
/// rejects it (see [`assert_rejected_by_allowlist`]).
async fn assert_quick_client_rejected(ep: &Endpoint, server_addr: EndpointAddr, reason: &str) {
    let hello = signaling::encode_hello(&Hello::new(None, 1)).unwrap();
    assert_rejected_by_allowlist(ep, server_addr, hello, reason).await;
}

/// Dial `server_addr` on the quick ALPN and assert the native allowlist hook
/// rejects it: the server closes the connection at the TLS handshake with `reason`,
/// before any application handshake (`hello`) can be exchanged.
async fn assert_rejected_by_allowlist(
    ep: &Endpoint,
    server_addr: EndpointAddr,
    hello: Vec<u8>,
    reason: &str,
) {
    // The QUIC handshake itself completes on the dialer side (the rejection is
    // an application close right after it), so `connect` may return Ok; the
    // rejection then surfaces as the connection closing with the hook's
    // reason. A `connect` error (rejection raced the handshake) is fine too.
    match with_timeout(ep.connect(server_addr, QUICK_ALPN)).await {
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
    signaling::write_request(&mut send, &StreamRequest::Connect(target))
        .await
        .unwrap();
    send.flush().await.unwrap();
    let rep = with_timeout(signaling::read_reply(&mut recv))
        .await
        .unwrap();
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
                        HashSet::new(),
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

/// A destination called `name` for the server `server_id`, authenticating
/// with [`test_client_key`] and routing nothing beyond its loopback name.
fn destination(name: &str, server_id: EndpointId) -> DestinationConfig {
    DestinationConfig {
        name: name.to_string(),
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
    fn status(&self, name: &str) -> DestinationStatus {
        self.client
            .status()
            .destinations
            .into_iter()
            .find(|d| d.name == name)
            .unwrap_or_else(|| panic!("no destination {name}"))
    }

    fn state(&self, name: &str) -> DestinationState {
        self.status(name).state
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
    assert_eq!(
        rep,
        signaling::REP_SUCCESS,
        "CONNECT {host}:{port} should succeed"
    );
    expect_echo(&mut app).await;
    app
}

/// `GET path` on `http://flextunnel.internal` through the SOCKS5 proxy,
/// returning the whole HTTP response.
async fn status_get(socks: SocketAddr, path: &str) -> String {
    let (mut app, rep) = socks_connect(socks, "flextunnel.internal", 80).await;
    assert_eq!(
        rep,
        signaling::REP_SUCCESS,
        "the status host always answers"
    );
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
/// server sees no client. The first request for the destination's loopback name
/// connects it and reaches the server's loopback; the connection then stays
/// for the next request.
#[tokio::test]
async fn nothing_connects_before_first_use() {
    let echo_port = spawn_echo().await;
    let (server_ep, server_addr) = server_endpoint(SecretKey::generate()).await;
    let server_id = server_ep.id();
    let bl_path = temp_blocklist("lazy-first-use");
    // An empty routed set: the destination's loopback name needs no server config.
    let server = spawn_server_handle(server_ep, base_params(server_id, bl_path.clone()));

    let client = start_client(
        vec![destination("m1", server_id)],
        Some(Duration::from_secs(300)),
        MemoryLookup::from_endpoint_info(vec![server_addr]),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(client.built(), 0, "no endpoint before first use");
    assert_eq!(client.state("m1"), DestinationState::Idle);
    assert!(
        server.connected_client_keys().is_empty(),
        "the server saw nobody"
    );
    // Looking at the client's status is not a use.
    let page = status_get(client.socks, "/status.json").await;
    assert!(page.contains("\"state\": \"idle\""), "{page}");
    assert_eq!(client.built(), 0, "the status page connects nothing");

    let app = socks_echo(client.socks, "m1.localhost.flextunnel.internal", echo_port).await;
    assert_eq!(client.built(), 1);
    let status = client.status("m1");
    assert_eq!(status.state, DestinationState::Connected);
    assert_eq!(status.open_streams, 1);
    assert!(status.connected_since.is_some() && status.client_node_id.is_some());
    assert_eq!(
        server.connected_client_keys(),
        [test_client_key().public_str()]
    );

    // The stream ends; the connection stays for the next request.
    drop(app);
    wait_until("the stream to be released", || {
        client.status("m1").open_streams == 0
    })
    .await;
    assert_eq!(client.state("m1"), DestinationState::Connected);
    let _app = socks_echo(client.socks, "m1.localhost.flextunnel.internal", echo_port).await;
    assert_eq!(
        client.built(),
        1,
        "the second request reused the connection"
    );

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
        vec![destination("m1", id1), destination("m2", id2)],
        None,
        MemoryLookup::from_endpoint_info(vec![addr1, addr2]),
    )
    .await;

    let _app2 = socks_echo(client.socks, "m2.localhost.flextunnel.internal", echo_port).await;
    assert_eq!(client.state("m2"), DestinationState::Connected);
    assert_eq!(client.state("m1"), DestinationState::Idle);
    assert_eq!(client.built(), 1);
    assert_eq!(server2.connected_client_keys().len(), 1);
    assert!(
        server1.connected_client_keys().is_empty(),
        "server 1 was never dialed"
    );

    let _app1 = socks_echo(client.socks, "M1.LocalHost.FlexTunnel.Internal", echo_port).await;
    assert_eq!(client.state("m1"), DestinationState::Connected);
    assert_eq!(client.built(), 2, "each destination has its own endpoint");
    assert_eq!(server1.connected_client_keys().len(), 1);
    assert_ne!(
        client.status("m1").client_node_id,
        client.status("m2").client_node_id
    );
}

/// A reconfigure keeps each destination it leaves unchanged as it is — its
/// connection and the streams open on it carry on — and replaces the others:
/// a changed one is closed, its streams ending, and connects afresh on its
/// next use; a removed one is gone.
#[tokio::test]
async fn a_reconfigure_keeps_the_unchanged_destinations_connected() {
    let echo_port = spawn_echo().await;
    let (ep1, addr1) = server_endpoint(SecretKey::generate()).await;
    let (ep2, addr2) = server_endpoint(SecretKey::generate()).await;
    let (id1, id2) = (ep1.id(), ep2.id());
    spawn_server_handle(ep1, base_params(id1, temp_blocklist("reconfigure-1")));
    spawn_server_handle(ep2, base_params(id2, temp_blocklist("reconfigure-2")));

    let client = start_client(
        vec![destination("m1", id1), destination("m2", id2)],
        None,
        MemoryLookup::from_endpoint_info(vec![addr1, addr2]),
    )
    .await;
    let mut app1 = socks_echo(client.socks, "m1.localhost.flextunnel.internal", echo_port).await;
    let mut app2 = socks_echo(client.socks, "m2.localhost.flextunnel.internal", echo_port).await;
    assert_eq!(client.built(), 2);
    let m1_since = client.status("m1").connected_since;

    // m1 as it was; m2 with a route more.
    let mut m2 = destination("m2", id2);
    m2.routed_domains = strings(&["m2.example"]);
    client
        .client
        .reconfigure(vec![destination("m1", id1), m2], Vec::new())
        .unwrap();

    // m2's connection is closed with it, and its stream ends.
    let mut buf = [0u8; 4];
    let ended = with_timeout(async {
        let _ = app2.write_all(b"ping").await;
        app2.read(&mut buf).await
    })
    .await;
    assert!(matches!(ended, Ok(0) | Err(_)), "m2's stream ended");
    assert_eq!(client.state("m2"), DestinationState::Idle, "m2 is new");
    // m1 is untouched: the same connection, its stream still open.
    app1.write_all(b"pong").await.unwrap();
    with_timeout(app1.read_exact(&mut buf)).await.unwrap();
    assert_eq!(&buf, b"pong");
    let m1 = client.status("m1");
    assert_eq!(m1.state, DestinationState::Connected);
    assert_eq!(m1.connected_since, m1_since);
    assert_eq!(m1.open_streams, 1);

    // The new m2 connects on its next use, with an endpoint of its own.
    let _app2 = socks_echo(client.socks, "m2.localhost.flextunnel.internal", echo_port).await;
    assert_eq!(client.state("m2"), DestinationState::Connected);
    assert_eq!(client.built(), 3);

    // Removed, m1 is gone, and its stream with it.
    let mut m2_config = destination("m2", id2);
    m2_config.routed_domains = strings(&["m2.example"]);
    client
        .client
        .reconfigure(vec![m2_config], Vec::new())
        .unwrap();
    let ended = with_timeout(async {
        let _ = app1.write_all(b"ping").await;
        app1.read(&mut buf).await
    })
    .await;
    assert!(matches!(ended, Ok(0) | Err(_)), "m1's stream ended");
    let names: Vec<String> = client
        .client
        .status()
        .destinations
        .into_iter()
        .map(|d| d.name)
        .collect();
    assert_eq!(names, ["m2"]);
    assert_eq!(client.state("m2"), DestinationState::Connected, "m2 kept");

    // A configuration the client cannot run is refused, changing nothing.
    assert!(client.client.reconfigure(Vec::new(), Vec::new()).is_err());
    assert_eq!(client.state("m2"), DestinationState::Connected);
}

/// The client's close waits for the close of a destination a reconfigure
/// took out, so its endpoint is closed once the client's close returns.
#[tokio::test]
async fn a_close_waits_for_a_destination_taken_out() {
    let echo_port = spawn_echo().await;
    let (ep1, addr1) = server_endpoint(SecretKey::generate()).await;
    let (ep2, addr2) = server_endpoint(SecretKey::generate()).await;
    let (id1, id2) = (ep1.id(), ep2.id());
    spawn_server_handle(ep1, base_params(id1, temp_blocklist("retired-close-1")));
    spawn_server_handle(ep2, base_params(id2, temp_blocklist("retired-close-2")));
    let client = start_client(
        vec![destination("m1", id1), destination("m2", id2)],
        None,
        MemoryLookup::from_endpoint_info(vec![addr1, addr2]),
    )
    .await;
    let _app1 = socks_echo(client.socks, "m1.localhost.flextunnel.internal", echo_port).await;
    let m1_endpoint = client.endpoint(0);

    client
        .client
        .reconfigure(vec![destination("m2", id2)], Vec::new())
        .unwrap();
    with_timeout(client.client.close()).await;
    assert!(m1_endpoint.is_closed(), "the close waited for m1's");
}

/// A held destination's routes are refused — never dialed directly — while the
/// live destinations serve as ever; a reconfigure without it lets its targets
/// go direct again.
#[tokio::test]
async fn a_held_destination_refuses_what_it_routes() {
    let echo_port = spawn_echo().await;
    let (ep, addr) = server_endpoint(SecretKey::generate()).await;
    let id = ep.id();
    spawn_server_handle(ep, base_params(id, temp_blocklist("held")));
    let client = start_client(
        vec![destination("m1", id)],
        None,
        MemoryLookup::from_endpoint_info(vec![addr]),
    )
    .await;

    let held = HeldDestination {
        name: "pending".into(),
        routed_domains: Vec::new(),
        routed_cidrs: strings(&["127.0.0.1/32"]),
    };
    client
        .client
        .reconfigure(vec![destination("m1", id)], vec![held])
        .unwrap();
    // 127.0.0.1 would connect directly, to the echo server: held, it is refused.
    let (_app, rep) = socks_connect(client.socks, "127.0.0.1", echo_port).await;
    assert_eq!(rep, signaling::REP_NET_UNREACHABLE);
    let (_app, rep) = socks_connect(
        client.socks,
        "pending.localhost.flextunnel.internal",
        echo_port,
    )
    .await;
    assert_eq!(rep, signaling::REP_NET_UNREACHABLE);
    let dialer = client.client.dialer();
    let target = Target::Domain("127.0.0.1".into(), echo_port);
    assert_eq!(dialer.destination_for(&target).as_deref(), Some("pending"));
    let refused = with_timeout(dialer.connect(&target))
        .await
        .err()
        .expect("held");
    assert!(refused.to_string().contains("not set up"), "{refused:#}");
    // The live destination serves on.
    let _app = socks_echo(client.socks, "m1.localhost.flextunnel.internal", echo_port).await;
    assert_eq!(
        client.client.status().destinations.len(),
        1,
        "held is not a destination"
    );

    client
        .client
        .reconfigure(vec![destination("m1", id)], Vec::new())
        .unwrap();
    let (_app, rep) = socks_connect(client.socks, "127.0.0.1", echo_port).await;
    assert_eq!(rep, signaling::REP_SUCCESS, "direct again");
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

    let mut m1 = destination("m1", id1);
    m1.routed_domains = strings(&["*.corp.test"]);
    let mut m2 = destination("m2", id2);
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
    assert_eq!((streams("m1"), streams("m2")), (0, 0));
    drop(direct);

    // A wildcard route → its destination.
    let api = socks_echo(client.socks, "api.corp.test", echo_port).await;
    assert_eq!((streams("m1"), streams("m2")), (1, 0));
    assert_eq!(client.state("m2"), DestinationState::Idle);

    // An exact route on the other destination beats that wildcard.
    let db = socks_echo(client.socks, "db.corp.test", echo_port).await;
    assert_eq!((streams("m1"), streams("m2")), (1, 1));

    // An IP (here in domain form) is routed by network.
    let ip = socks_echo(client.socks, "127.0.0.1", echo_port).await;
    assert_eq!((streams("m1"), streams("m2")), (1, 2));
    // With the root dot it is the same address, dialed as one by the server.
    let dotted = socks_echo(client.socks, "127.0.0.1.", echo_port).await;
    assert_eq!((streams("m1"), streams("m2")), (1, 3));

    drop((api, db, ip, dotted));
}

/// A client route its server does not also list is refused by that server:
/// the server's routed set stays the authority.
#[tokio::test]
async fn a_route_the_server_does_not_list_is_refused() {
    let (server_ep, server_addr) = server_endpoint(SecretKey::generate()).await;
    let server_id = server_ep.id();
    spawn_server_params(
        server_ep,
        base_params(server_id, temp_blocklist("route-refused")),
    );

    let mut m1 = destination("m1", server_id);
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
    assert_eq!(client.state("m1"), DestinationState::Connected);
}

/// A destination reads what its server routes when it first connects, and
/// keeps it: the client's status page then says which of the destination's
/// rules the server refuses — `unchecked` until then, since looking connects
/// nothing.
#[tokio::test]
async fn a_destination_checks_its_routes_with_the_server_on_first_use() {
    let (server_ep, server_addr) = server_endpoint(SecretKey::generate()).await;
    let server_id = spawn_server_full(
        server_ep,
        temp_blocklist("route-check"),
        HashMap::new(),
        strings(&["*.corp.test"]),
    );
    let mut m1 = destination("m1", server_id);
    m1.routed_domains = strings(&["*.corp.test", "*.other.test"]);
    let client = start_client(
        vec![m1],
        None,
        MemoryLookup::from_endpoint_info(vec![server_addr]),
    )
    .await;

    let routes = |page: &str| -> Vec<(String, String)> {
        let body = page.split_once("\r\n\r\n").unwrap().1;
        let json: serde_json::Value = serde_json::from_str(body).unwrap();
        json["routes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r["rule"].as_str().unwrap().to_string(),
                    r["server"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    };
    let pair = |rule: &str, server: &str| (rule.to_string(), server.to_string());
    assert_eq!(
        routes(&status_get(client.socks, "/status.json").await),
        [
            pair("m1.localhost.flextunnel.internal", "loopback"),
            pair("*.other.test", "unchecked"),
            pair("*.corp.test", "unchecked")
        ]
    );
    assert_eq!(client.built(), 0, "the status page connects nothing");

    // Any use connects; this one the server refuses.
    let (_app, rep) = socks_connect(client.socks, "x.other.test", 443).await;
    assert_eq!(rep, signaling::REP_NOT_ALLOWED);
    wait_until("the server's routes are read", || {
        client.status("m1").server_routes.is_some()
    })
    .await;
    assert_eq!(
        client.status("m1").server_routes,
        Some(ServerRoutes {
            routed_domains: strings(&["*.corp.test"]),
            routed_cidrs: Vec::new()
        })
    );
    assert_eq!(
        routes(&status_get(client.socks, "/status.json").await),
        [
            pair("m1.localhost.flextunnel.internal", "loopback"),
            pair("*.other.test", "not allowed"),
            pair("*.corp.test", "allowed")
        ]
    );
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
        vec![destination("m1", server_id)],
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
    assert!(
        unrouted.to_string().contains("no destination routes"),
        "{unrouted:#}"
    );
    assert_eq!(client.built(), 0);

    // The request makes the destination dial; the attempt fails; the request
    // stays held and the destination reports the failure.
    let pending = tokio::spawn({
        let dialer = dialer.clone();
        async move {
            dialer
                .connect(&Target::Domain(
                    "m1.localhost.flextunnel.internal".into(),
                    echo_port,
                ))
                .await
        }
    });
    wait_until("the first attempt to fail", || {
        client.status("m1").failed_attempts >= 1
    })
    .await;
    assert!(!pending.is_finished(), "the request is held, not failed");
    let status = client.status("m1");
    assert_eq!(status.waiting, 1);
    assert!(status.last_error.is_some() && status.next_attempt_at.is_some());

    // The server comes up; the retry (1s backoff) lands and the held request
    // proceeds as if nothing had happened.
    up_tx.send_replace(true);
    let mut stream = with_timeout(pending)
        .await
        .unwrap()
        .expect("held request connects");
    expect_echo(&mut stream).await;
    let status = client.status("m1");
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
        vec![destination("m1", server_id)],
        Some(idle_timeout),
        MemoryLookup::from_endpoint_info(vec![server_addr]),
    )
    .await;

    // In use: well past the idle timeout, the connection is still there.
    let mut app = socks_echo(client.socks, "m1.localhost.flextunnel.internal", echo_port).await;
    tokio::time::sleep(idle_timeout * 3).await;
    assert_eq!(client.state("m1"), DestinationState::Connected);
    app.write_all(b"more").await.unwrap();
    let mut echoed = [0u8; 4];
    with_timeout(app.read_exact(&mut echoed)).await.unwrap();
    assert_eq!(&echoed, b"more");

    // Unused: it closes, and so does its endpoint.
    drop(app);
    wait_until("the idle connection to close", || {
        client.state("m1") == DestinationState::Idle
    })
    .await;
    let first = client.endpoint(0);
    wait_until("the idle endpoint to close", || first.is_closed()).await;
    wait_until("the server to see the client leave", || {
        server.connected_client_keys().is_empty()
    })
    .await;
    wait_until("the endpoint to be forgotten", || {
        client.status("m1").client_node_id.is_none()
    })
    .await;
    assert_eq!(
        client.status("m1").failed_attempts,
        0,
        "idling is not a failure"
    );

    // The next request redials, on a new endpoint.
    let _app = socks_echo(client.socks, "m1.localhost.flextunnel.internal", echo_port).await;
    assert_eq!(client.built(), 2);
    assert_eq!(client.state("m1"), DestinationState::Connected);

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
    let client = start_client(vec![destination("m1", server_id)], None, lookup.clone()).await;
    drop(socks_echo(client.socks, "m1.localhost.flextunnel.internal", echo_port).await);
    wait_until("the stream to be released", || {
        client.status("m1").open_streams == 0
    })
    .await;

    // Drop the connection out from under the session.
    server_ep.close().await;
    wait_until("the destination to go idle after the drop", || {
        let status = client.status("m1");
        status.state == DestinationState::Idle && status.client_node_id.is_none()
    })
    .await;
    let status = client.status("m1");
    assert_eq!(status.failed_attempts, 1, "the drop is recorded");
    assert!(status.last_error.is_some());
    let built = client.built();

    // Well past the first backoff step, still nothing has been tried.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let status = client.status("m1");
    assert_eq!(status.state, DestinationState::Idle);
    assert_eq!(status.failed_attempts, 1, "no attempt without a request");
    assert_eq!(client.built(), built, "no endpoint without a request");

    // Resurrect the server on the same identity (a fresh nonce — a restart,
    // not a duplicate) and publish its new address.
    let (server_ep2, server_addr2) = server_endpoint(server_secret).await;
    lookup.set_endpoint_info(server_addr2);
    spawn_server_params(server_ep2, base_params(server_id, bl_path.clone()));

    // A request brings the destination back.
    let _app = socks_echo(client.socks, "m1.localhost.flextunnel.internal", echo_port).await;
    let status = client.status("m1");
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
    let client = start_client(vec![destination("m1", server_id)], None, lookup.clone()).await;
    drop(socks_echo(client.socks, "m1.localhost.flextunnel.internal", echo_port).await);

    // Drop the connection out from under the session and wait for it to notice.
    server_ep.close().await;
    wait_until("the client to notice the drop", || {
        client.state("m1") != DestinationState::Connected
    })
    .await;

    // Issue the request during the outage: the SOCKS handshake completes (the
    // listener is up), but the CONNECT reply is held while the destination
    // waits out its backoff and redials.
    let mut app = socks_request(client.socks, "m1.localhost.flextunnel.internal", echo_port).await;
    let mut reply = [0u8; 10];
    // Peeked, not read: nothing of a reply that did arrive would be consumed,
    // and only the timeout — no byte and no close — means it is being held.
    let mut probe = [0u8; 1];
    let early = tokio::time::timeout(Duration::from_millis(500), app.peek(&mut probe)).await;
    assert!(
        early.is_err(),
        "the request was answered (or the connection closed) instead of held: {early:?}"
    );
    assert_eq!(client.status("m1").waiting, 1);

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

    let mut kept = destination("m1", server_id);
    kept.keep_connected = true;
    let client = start_client(
        vec![kept],
        // Never closed for idleness either way: it is kept connected.
        Some(Duration::from_millis(200)),
        MemoryLookup::from_endpoint_info(vec![server_addr]),
    )
    .await;
    let connected = || client.state("m1") == DestinationState::Connected;
    wait_until("the kept destination to connect unasked", connected).await;
    let first_id = client.status("m1").client_node_id;
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
        client.status("m1").client_node_id,
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
        vec![destination("m1", id1), destination("m2", id2)],
        None,
        MemoryLookup::from_endpoint_info(vec![addr1, addr2]),
    )
    .await;

    let started = Instant::now();
    let (_app, rep) =
        socks_connect(client.socks, "m1.localhost.flextunnel.internal", echo_port).await;
    assert_eq!(rep, signaling::REP_NOT_ALLOWED);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "not held for the full window"
    );
    let status = client.status("m1");
    assert_eq!(status.state, DestinationState::Failed);
    assert!(
        status
            .last_error
            .as_deref()
            .unwrap_or_default()
            .contains("Authentication failed"),
        "{:?}",
        status.last_error
    );

    // Asked again right away: refused without another dial.
    let started = Instant::now();
    let (_app, rep) =
        socks_connect(client.socks, "m1.localhost.flextunnel.internal", echo_port).await;
    assert_eq!(rep, signaling::REP_NOT_ALLOWED);
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "failed fast"
    );
    assert_eq!(client.status("m1").failed_attempts, 1, "no second dial");

    // The other destination works as if nothing happened.
    let _app = socks_echo(client.socks, "m2.localhost.flextunnel.internal", echo_port).await;
    assert_eq!(client.state("m2"), DestinationState::Connected);
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
        vec![destination("m1", server_id)],
        None,
        MemoryLookup::from_endpoint_info(vec![server_addr]),
    )
    .await;

    // An unknown destination is a local 404 and connects nothing.
    let missing = status_get(client.socks, "/servers/nope.internal/status.json").await;
    assert!(missing.starts_with("HTTP/1.1 404"), "{missing:.60}");
    assert_eq!(client.built(), 0);

    // JSON through SOCKS: the server's own view, node id and routed set.
    let response = status_get(client.socks, "/servers/m1/status.json").await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response:.60}");
    let body = response.split_once("\r\n\r\n").expect("headers").1;
    let status: serde_json::Value = serde_json::from_str(body).expect("server JSON status");
    assert_eq!(status["server_node_id"], server_id.to_string());
    assert_eq!(
        status["routed_domains"],
        serde_json::json!(["marker.example.com"])
    );
    assert_eq!(client.built(), 1, "fetching it connected the destination");
    assert_eq!(client.state("m1"), DestinationState::Connected);

    // HTML at the bare path. It is the server's content under the client's
    // own host name, so the client sends it with an origin of its own.
    let response = status_get(client.socks, "/servers/m1/").await;
    assert!(
        response.contains("Content-Type: text/html"),
        "{response:.200}"
    );
    assert!(response.contains("flextunnel server status"));
    assert!(response.contains("marker.example.com"));
    let head = response.split_once("\r\n\r\n").expect("headers").0;
    assert!(
        head.contains("Content-Security-Policy: sandbox\r\n"),
        "{head}"
    );
    assert!(head.contains("X-Content-Type-Options: nosniff"), "{head}");
    // The client's own page is its own origin and carries no sandbox.
    let own = status_get(client.socks, "/").await;
    assert!(!own.contains("Content-Security-Policy"), "{own:.300}");

    // Through the HTTP proxy as a plain GET, with `Accept` picking text.
    let mut app = TcpStream::connect(client.http).await.unwrap();
    app.write_all(
        b"GET http://flextunnel.internal/servers/m1 HTTP/1.1\r\n\
          Host: flextunnel.internal\r\nAccept: text/plain\r\n\r\n",
    )
    .await
    .unwrap();
    let mut response = Vec::new();
    with_timeout(app.read_to_end(&mut response)).await.unwrap();
    let response = String::from_utf8(response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response:.60}");
    assert!(
        response.contains("Content-Type: text/plain"),
        "{response:.200}"
    );
    assert!(response.contains("flextunnel server status"));

    // The client's own page now shows the destination connected.
    let page = status_get(client.socks, "/status.json").await;
    assert!(page.contains("\"state\": \"connected\""), "{page}");
}

/// A server's routed lists are read from it by a connection made for the
/// question alone — no client session, no destination — and gone once it is
/// answered. A key the server does not authorize is turned away as such.
#[tokio::test]
async fn a_servers_routes_are_fetched_in_one_connection() {
    let (server_ep, server_addr) = server_endpoint(SecretKey::generate()).await;
    let server_id = server_ep.id();
    let domains = strings(&["*.corp.example", "marker.example.com"]);
    let cidrs = strings(&["10.0.0.0/8", "192.168.1.7"]);
    let server = spawn_server_handle(
        server_ep,
        ProxyServerParams {
            routed_set: RoutedSet::new(&domains, &cidrs).unwrap(),
            routed_domains: domains.clone(),
            routed_cidrs: cidrs.clone(),
            ..base_params(server_id, temp_blocklist("routes-fetch"))
        },
    );
    let endpoint = loopback_endpoint_full(
        SecretKey::generate(),
        false,
        MemoryLookup::from_endpoint_info(vec![server_addr]),
        HashSet::new(),
    )
    .await;
    let relay = RelayConfig::default();

    let auth = ClientAuth::Key(Box::new(test_client_key().clone()));
    let routes = with_timeout(server_routes::fetch_over(
        &endpoint, server_id, &relay, &auth,
    ))
    .await
    .expect("an authorized key is answered");
    assert_eq!(
        routes,
        ServerRoutes {
            routed_domains: domains,
            routed_cidrs: cidrs,
        }
    );
    wait_until("the server to see the connection gone", || {
        server.connected_client_keys().is_empty()
    })
    .await;

    let stranger = ClientAuth::Key(Box::new(crate::auth::ClientKey::generate().unwrap()));
    let err = with_timeout(server_routes::fetch_over(
        &endpoint, server_id, &relay, &stranger,
    ))
    .await
    .expect_err("an unauthorized key is refused");
    assert!(matches!(err, ProxyError::AuthenticationFailed(_)), "{err}");
    endpoint.close().await;
}

/// A peer that takes the connection but grants no stream to say `Hello` on
/// holds the handshake for its timeout and no longer: opening the stream waits
/// on the peer, and has no bound of its own.
#[tokio::test]
async fn a_peer_granting_no_stream_times_the_handshake_out() {
    let no_streams = iroh::endpoint::QuicTransportConfig::builder()
        .max_concurrent_bidi_streams(0u32.into())
        .build();
    let server = server_setup(
        loopback_base(Side::Server, MemoryLookup::new()).transport_config(no_streams),
        SecretKey::generate(),
        HashSet::new(),
    )
    .bind()
    .await
    .unwrap();
    let server_addr = EndpointAddr::new(server.id()).with_ip_addr(server.bound_sockets()[0]);
    // Accepts, then only holds the connection open.
    let accepted = tokio::spawn({
        let server = server.clone();
        async move { server.accept().await.expect("an incoming connection").await }
    });

    let client = loopback_endpoint(SecretKey::generate(), false).await;
    let connection = with_timeout(client.connect(server_addr, ALPN))
        .await
        .unwrap();
    let _held = with_timeout(accepted)
        .await
        .unwrap()
        .expect("the server accepts");

    // Waited out for real (the timeout is 10s): an endpoint's own tasks keep
    // a paused clock from running ahead.
    let handshake_timeout = crate::proxy::client::HANDSHAKE_TIMEOUT;
    let started = Instant::now();
    let auth = ClientAuth::Key(Box::new(test_client_key().clone()));
    let result = tokio::time::timeout(
        handshake_timeout + Duration::from_secs(10),
        crate::proxy::destination::exchange_hello(&connection, &auth, client.id(), 1, false),
    )
    .await
    .expect("the handshake gives up by itself");
    match result {
        Err(ProxyError::Signaling(reason)) => assert!(reason.contains("timed out"), "{reason}"),
        Err(other) => panic!("expected the handshake to time out: {other}"),
        Ok(_) => panic!("a handshake with no stream to run on succeeded"),
    }
    assert!(
        started.elapsed() >= handshake_timeout,
        "{:?}",
        started.elapsed()
    );

    connection.close(0u32.into(), b"done");
    client.close().await;
    server.close().await;
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

    let client = start_client(vec![destination("m1", server_id)], None, lookup.clone()).await;
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
    let target = Target::Domain("m1.localhost.flextunnel.internal".into(), echo_port);
    let mut stream = with_timeout(dialer.connect(&target))
        .await
        .expect("still tunnels");
    expect_echo(&mut stream).await;
    drop(stream);

    // The session ending withdraws them too, without any close signal.
    let other = start_client(vec![destination("m1", server_id)], None, lookup).await;
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
    let refused = with_timeout(dialer.connect(&target))
        .await
        .err()
        .expect("closed");
    assert!(refused.to_string().contains("was closed"), "{refused:#}");
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
    let mut m1 = destination("m1", server_id);
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
    assert_eq!(client.state("m1"), DestinationState::Idle);

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
    assert_eq!(client.state("m1"), DestinationState::Connected);
    assert_eq!(client.status("m1").open_streams, 1);

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

/// `len` bytes that depend on their position and on `seed`, so a lost,
/// repeated or reordered run of them shows.
fn patterned(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u32).wrapping_mul(2_654_435_761).to_be_bytes()[0] ^ seed)
        .collect()
}

/// A forward carries a bulk transfer intact in both directions at once, and a
/// half-close crosses it either way: the local app's EOF reaches the target
/// while the target is still sending, what the target sends afterwards still
/// arrives, and the target's close ends the local stream.
#[tokio::test]
async fn a_forward_relays_bulk_data_and_half_closes() {
    const LEN: usize = 3 * 1024 * 1024 + 4321;

    let bl_path = temp_blocklist("forward-bulk");
    let (server_ep, server_addr) = server_endpoint(SecretKey::generate()).await;
    let server_id = server_ep.id();
    let (routed_set, routed_cidrs) = loopback_cidr_set();
    let params = ProxyServerParams {
        routed_set,
        routed_cidrs,
        ..base_params(server_id, bl_path.clone())
    };
    spawn_server_params(server_ep, params);

    let mut m1 = destination("m1", server_id);
    m1.routed_cidrs = strings(&["127.0.0.0/8"]);
    let client = start_client(
        vec![m1],
        None,
        MemoryLookup::from_endpoint_info(vec![server_addr]),
    )
    .await;

    // The target sends its own bulk while it reads the app's to EOF, then
    // reports what it read and closes.
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = target.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (sock, _) = target.accept().await.unwrap();
        let (mut from_app, mut to_app) = sock.into_split();
        let sending = tokio::spawn(async move {
            to_app.write_all(&patterned(0xB7, LEN)).await.unwrap();
            to_app
        });
        let mut received = Vec::new();
        from_app.read_to_end(&mut received).await.unwrap();
        let mut to_app = sending.await.unwrap();
        let verdict: &[u8] = if received == patterned(0x5A, LEN) {
            b"INTACT"
        } else {
            b"BROKEN"
        };
        to_app.write_all(verdict).await.unwrap();
    });

    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_port = probe.local_addr().unwrap().port();
    drop(probe);
    let manager = ForwardManager::new(
        tokio::runtime::Handle::current(),
        client.client.dialer(),
        &[ForwardSpec {
            id: "bulk".into(),
            local_port,
            target: Target::Ip(format!("127.0.0.1:{target_port}").parse().unwrap()),
        }],
    );
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
    let (mut from_target, mut to_target) = local.expect("forward listener reachable").into_split();

    let sending = tokio::spawn(async move {
        to_target.write_all(&patterned(0x5A, LEN)).await.unwrap();
        // EOF for the target, with its own bulk and verdict still to come.
        to_target.shutdown().await.unwrap();
        to_target
    });
    let mut received = Vec::new();
    with_timeout(from_target.read_to_end(&mut received))
        .await
        .unwrap();
    let _to_target = with_timeout(sending).await.unwrap();

    let (bulk, verdict) = received.split_at(received.len().saturating_sub(6));
    assert_eq!(verdict, b"INTACT", "the target read the app's bytes intact");
    assert!(
        bulk == patterned(0xB7, LEN),
        "the app read the target's bytes intact"
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
        blocklist_file: bl_path.clone(),
    })
    .unwrap();
    assert_eq!(prepared.own_id(), secret.public());

    let running = Arc::new(
        prepared
            .bind_with(loopback_base(Side::Server, MemoryLookup::new()))
            .await,
    );
    let server_ep = running.endpoint();
    assert_eq!(
        server_ep.id(),
        secret.public(),
        "bound under the configured identity"
    );
    let server_addr = EndpointAddr::new(server_ep.id()).with_ip_addr(server_ep.bound_sockets()[0]);
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
    assert_eq!(
        running.connected_client_keys(),
        [test_client_key().public_str()]
    );
    drop((ctrl_send, ctrl_recv));
    conn.close(0u32.into(), b"done");
    wait_until("the client to leave", || {
        running.connected_client_keys().is_empty()
    })
    .await;

    stop_tx.send(()).unwrap();
    let stopped = with_timeout(served).await.unwrap().unwrap();
    assert!(stopped, "serve ran until stopped");
    running.close().await;
    let _ = std::fs::remove_file(bl_path);
}

fn temp_blocklist(tag: &str) -> std::path::PathBuf {
    let path =
        std::env::temp_dir().join(format!("flextunnel-e2e-{tag}-{}.json", std::process::id()));
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
    assert!(
        !resp.accepted,
        "self-blocking server should reject the connection"
    );

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
    let rep = with_timeout(signaling::read_reply(&mut recv))
        .await
        .unwrap();
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
    let rep2 = with_timeout(signaling::read_reply(&mut recv2))
        .await
        .unwrap();
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
    let host_aliases = HashMap::from([("nas.internal".to_string(), "192.168.1.9".to_string())]);
    spawn_server_full(
        server_ep,
        temp_blocklist("status-page"),
        host_aliases,
        vec![
            "marker.example.com".to_string(),
            "corp.example.com".to_string(),
        ],
    );

    let client_ep = loopback_endpoint(SecretKey::generate(), false).await;
    let (client_conn, _cs, _cr, cresp) = client_handshake(&client_ep, server_addr, 1, false).await;
    assert!(cresp.accepted, "client should be accepted");
    // The bare path: expect an HTTP 200 whose body contains the routed domain.
    let body = fetch_status(&client_conn, "/", None).await;
    assert!(
        body.starts_with("HTTP/1.1 200"),
        "status page should be 200: {body:.40}"
    );
    assert!(
        body.contains("marker.example.com"),
        "status page should list the configured routed domain"
    );

    let body = fetch_status(&client_conn, "/status.txt", None).await;
    assert!(
        body.starts_with("HTTP/1.1 200"),
        "text status should be 200: {body:.40}"
    );
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

    let body = fetch_status(&client_conn, "/status.json", None).await;
    assert!(
        body.starts_with("HTTP/1.1 200"),
        "json status should be 200: {body:.40}"
    );
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

    // Accept-header negotiation: a `/` request with `Accept: text/plain` should
    // also return the plain-text status response (not the HTML page).
    let body = fetch_status(&client_conn, "/", Some("text/plain")).await;
    assert!(
        body.starts_with("HTTP/1.1 200"),
        "accept-text status should be 200: {body:.40}"
    );
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
    let rep = with_timeout(signaling::read_reply(&mut recv))
        .await
        .unwrap();
    (send, recv, rep)
}

/// End-to-end loopback request: [`StreamRequest::Loopback`] reaches
/// `localhost:<port>` on the server with an empty routed set (deny-all) and no
/// host alias — what a client destination's loopback name asks for.
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
    assert_eq!(
        rep,
        signaling::REP_NOT_ALLOWED,
        "bare localhost is subject to the routed set"
    );

    // ...while the loopback request bypasses it.
    let (mut send, mut recv, rep) = open_stream(&conn, StreamRequest::Loopback(echo_port)).await;
    assert_eq!(
        rep,
        signaling::REP_SUCCESS,
        "a loopback request bypasses the routed set"
    );
    send.write_all(b"ping").await.unwrap();
    send.flush().await.unwrap();
    let mut buf = [0u8; 9]; // "HELLO" + "ping"
    with_timeout(recv.read_exact(&mut buf)).await.unwrap();
    assert_eq!(&buf, b"HELLOping");

    // A connect failure surfaces as a failure reply. Port 0 is unconnectable
    // on every platform (nothing can listen on it), so this never depends on
    // which loopback ports happen to be in use.
    let (_send, _recv, rep) = open_stream(&conn, StreamRequest::Loopback(0)).await;
    assert_ne!(
        rep,
        signaling::REP_SUCCESS,
        "closed loopback port must not reply success"
    );
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
        "m1.localhost.flextunnel.internal",
    ] {
        let request = StreamRequest::Connect(Target::Domain(host.to_string(), 80));
        let (_send, _recv, rep) = open_stream(&conn, request).await;
        assert_eq!(rep, signaling::REP_NOT_ALLOWED, "{host} must be refused");
    }
}

/// Ask the server for its status page over a [`StreamRequest::Status`] stream
/// — `path` and the optional `Accept` header pick the format — and return the
/// full HTTP response after consuming the per-stream success reply byte.
async fn fetch_status(conn: &Connection, path: &str, accept: Option<&str>) -> String {
    let (mut send, mut recv, rep) = open_stream(conn, StreamRequest::Status).await;
    assert_eq!(
        rep,
        signaling::REP_SUCCESS,
        "a status request should reply success"
    );
    let accept_header = accept
        .map(|a| format!("Accept: {a}\r\n"))
        .unwrap_or_default();
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
        HashSet::from([client_id]),
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
    assert!(
        resp.accepted,
        "allowlisted quick client must be accepted: {:?}",
        resp.reject_reason
    );
    assert_echo_roundtrip(&conn, echo_port).await;
}

/// [`crate::server::ServerOptions::quick_client`] reaches the endpoint's
/// allowlist through the shared startup path: on a server prepared with it,
/// and with no client keys at all, the entered client id is served over the
/// quick ALPN and any other id is rejected at the handshake.
#[tokio::test]
async fn prepared_quick_server_admits_only_the_entered_client() {
    let bl_path = temp_blocklist("prepared-quick");
    let echo_port = spawn_echo().await;
    let client_secret = SecretKey::generate();
    let (_, routed_cidrs) = loopback_cidr_set();
    let prepared = crate::server::prepare(crate::server::ServerOptions {
        secret_key: SecretKey::generate(),
        authorized_keys: Default::default(),
        quick_client: Some(client_secret.public()),
        first_client: None,
        relay_urls: Vec::new(),
        relay_auth_token: None,
        host_aliases: HashMap::new(),
        routed_domains: Vec::new(),
        routed_cidrs,
        blocklist_file: bl_path.clone(),
    })
    .unwrap();
    let running = Arc::new(
        prepared
            .bind_with(loopback_base(Side::Server, MemoryLookup::new()))
            .await,
    );
    let server_ep = running.endpoint();
    let server_addr = EndpointAddr::new(server_ep.id()).with_ip_addr(server_ep.bound_sockets()[0]);
    let served = tokio::spawn({
        let running = running.clone();
        async move { running.serve().await }
    });

    let client_ep = loopback_endpoint(client_secret, false).await;
    let (conn, _cs, _cr, resp) =
        handshake_on_alpn(&client_ep, server_addr.clone(), QUICK_ALPN, 1, false).await;
    assert!(
        resp.accepted,
        "the entered client must be accepted: {:?}",
        resp.reject_reason
    );
    assert_echo_roundtrip(&conn, echo_port).await;

    let stranger = loopback_endpoint(SecretKey::generate(), false).await;
    assert_quick_client_rejected(&stranger, server_addr, "allowlist").await;

    served.abort();
    let _ = served.await;
    running.close().await;
    let _ = std::fs::remove_file(bl_path);
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
        HashSet::from([SecretKey::generate().public()]),
    )
    .await;
    let addr1 = EndpointAddr::new(ep1.id()).with_ip_addr(ep1.bound_sockets()[0]);
    let p1 = base_params(ep1.id(), temp_blocklist("quickrej1"));
    spawn_server_params(ep1, p1);
    let dialer = loopback_endpoint(SecretKey::generate(), false).await;
    let hello_with_valid_credential =
        signaling::encode_hello(&Hello::new(Some(test_auth_payload(&dialer)), 1)).unwrap();
    assert_rejected_by_allowlist(&dialer, addr1, hello_with_valid_credential, "allowlist").await;

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
    let conn = with_timeout(client_ep.connect(server_addr, ALPN))
        .await
        .unwrap();
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

/// A peer is granted the streams tunnels use and no others, so it cannot have
/// this side hold a window for any other: a client opens a bidirectional
/// stream to its server at once, where a unidirectional stream from either
/// end, or any stream from the server, waits.
#[tokio::test]
async fn a_peer_is_granted_only_the_streams_tunnels_use() {
    const TEST_ALPN: &[u8] = b"flextunnel-test/streams-granted";
    const WAIT: Duration = Duration::from_millis(500);

    let server = loopback_base(Side::Server, MemoryLookup::new())
        .secret_key(SecretKey::from_bytes(&[73; 32]))
        .alpns(vec![TEST_ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let server_addr = EndpointAddr::new(server.id()).with_ip_addr(server.bound_sockets()[0]);
    let client = loopback_base(Side::Client, MemoryLookup::new())
        .secret_key(SecretKey::from_bytes(&[74; 32]))
        .bind()
        .await
        .unwrap();

    let from_server = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        let bi = matches!(tokio::time::timeout(WAIT, conn.open_bi()).await, Ok(Ok(_)));
        let uni = matches!(tokio::time::timeout(WAIT, conn.open_uni()).await, Ok(Ok(_)));
        conn.closed().await;
        (bi, uni)
    });

    let conn = with_timeout(client.connect(server_addr, TEST_ALPN))
        .await
        .unwrap();
    with_timeout(conn.open_bi()).await.unwrap();
    let uni = tokio::time::timeout(WAIT, conn.open_uni()).await;
    assert!(uni.is_err(), "the client opened a unidirectional stream");

    // Past both of the server's waits before the connection goes.
    tokio::time::sleep(2 * WAIT).await;
    conn.close(0u32.into(), b"done");
    let (bi, uni) = with_timeout(from_server).await.unwrap();
    assert!(!bi, "the server opened a bidirectional stream");
    assert!(!uni, "the server opened a unidirectional stream");
}

/// A stream's flow-control window follows its reader. Unread, a stream holds
/// what every stream starts with and no more: the peer gets
/// [`STREAM_RECEIVE_WINDOW`](crate::transport::STREAM_RECEIVE_WINDOW) ahead of
/// the reader and is held there. Read as fast as loopback delivers, it is
/// given more, and keeps it when the reader stops: the peer then gets further
/// ahead than a starting window, though never past
/// [`STREAM_RECEIVE_WINDOW_MAX`](crate::transport::STREAM_RECEIVE_WINDOW_MAX).
#[tokio::test]
async fn a_streams_window_follows_its_reader() {
    use crate::transport::{STREAM_RECEIVE_WINDOW, STREAM_RECEIVE_WINDOW_MAX};
    use std::sync::atomic::{AtomicU64, Ordering};

    const TEST_ALPN: &[u8] = b"flextunnel-test/stream-window";
    const START: u64 = STREAM_RECEIVE_WINDOW as u64;
    const MAX: u64 = STREAM_RECEIVE_WINDOW_MAX as u64;
    // What the reader takes at a stretch before it stops to see how far ahead
    // the sender gets: several times what a window needs to reach its maximum.
    const STRETCH: u64 = 4 * MAX;
    // Long enough for a sender with credit to use all of it.
    const SETTLE: Duration = Duration::from_millis(500);

    let server = loopback_base(Side::Server, MemoryLookup::new())
        .secret_key(SecretKey::from_bytes(&[71; 32]))
        .alpns(vec![TEST_ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let server_addr = EndpointAddr::new(server.id()).with_ip_addr(server.bound_sockets()[0]);
    let client = loopback_base(Side::Client, MemoryLookup::new())
        .secret_key(SecretKey::from_bytes(&[72; 32]))
        .bind()
        .await
        .unwrap();

    // The far side writes to the stream opened to it for as long as the
    // stream takes it, counting what it has taken.
    let sent = Arc::new(AtomicU64::new(0));
    let sender = tokio::spawn({
        let sent = Arc::clone(&sent);
        async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let (mut send, _recv) = conn.accept_bi().await.unwrap();
            let chunk = vec![5u8; 64 * 1024];
            while let Ok(n) = send.write(&chunk).await {
                sent.fetch_add(n as u64, Ordering::Relaxed);
            }
        }
    });

    let all = async {
        let conn = client.connect(server_addr, TEST_ALPN).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"go").await.unwrap();

        // Unread, the stream takes its starting window and stops there.
        while sent.load(Ordering::Relaxed) < START {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(SETTLE).await;
        assert_eq!(sent.load(Ordering::Relaxed), START);

        // Read at full speed and then stopped, it has more than that. How fast
        // a stretch has to be read for the window to grow is the transport's
        // business; a slow machine gets several stretches to manage it.
        let mut read = 0u64;
        let mut chunks: [bytes::Bytes; 32] = std::array::from_fn(|_| bytes::Bytes::new());
        let mut ahead = 0;
        for _ in 0..8 {
            let until = read + STRETCH;
            while read < until {
                let n = recv.read_many_chunks(&mut chunks).await.unwrap().unwrap();
                read += chunks[..n].iter().map(|c| c.len() as u64).sum::<u64>();
            }
            tokio::time::sleep(SETTLE).await;
            ahead = sent.load(Ordering::Relaxed) - read;
            assert!(ahead <= MAX, "{ahead} bytes ahead of the reader");
            if ahead > START {
                break;
            }
        }
        // Only the iOS build's windows stay as they start. Any other build
        // has to show growth, whatever its maximum has been set to.
        if cfg!(target_os = "ios") {
            assert_eq!(MAX, START);
        } else {
            assert!(ahead > START, "the window never grew: {ahead} bytes ahead");
        }
        recv.stop(0u32.into()).unwrap();
    };
    tokio::time::timeout(Duration::from_secs(120), all)
        .await
        .expect("timed out");
    sender.await.unwrap();
}
