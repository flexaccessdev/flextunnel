//! Local port forwarding: per-forward dual-stack loopback listeners
//! (`127.0.0.1` + `::1`, never wildcard) that relay every accepted connection
//! through the app's own SOCKS5 listener, mirroring the iOS forwarder. Going
//! through the SOCKS front-end means the core's split-tunnel routing,
//! server-side DNS, and reconnect-gap replies all apply unchanged.
//!
//! Before the first connection of a session is relayed, the forwarder probes
//! the SOCKS port by fetching `http://flextunnel.internal/status.json` through
//! it and comparing the reported `server_node_id` against this session's
//! configured server, so a forward that accidentally reaches some *other*
//! SOCKS5 server on the port (another flextunnel, an `ssh -D`) fails loudly
//! instead of sending traffic to the wrong place. Success is cached for the
//! session; failures retry on the next connection. Misconfiguration guard, not
//! security — everything is loopback.

use flextunnel_core::proxy::signaling::{self, Target};
use flextunnel_core::proxy::{reserved, socks5, status_page};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};

/// Deadline for the whole SOCKS5 setup (instance probe + handshake + CONNECT
/// reply). Must exceed the core's own tunnel-open timeout (~30s) so a
/// legitimately slow target isn't cut off by us first.
const SOCKS_SETUP_TIMEOUT: Duration = Duration::from_secs(35);
/// Pause before retrying `accept()` after a failure (mirrors the core's
/// accept-retry pacing).
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(250);

/// One configured forward: `localhost:local_port` → `remote_host:remote_port`
/// through the tunnel's SOCKS5 listener. The remote host stays a string
/// end-to-end (sent as ATYP DOMAIN) so DNS happens server-side, like iOS.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortForward {
    pub id: String,
    #[serde(default)]
    pub label: String,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
    /// Runtime-only session state (the enable/disable switch): never written
    /// to disk, so every launch starts with all forwards disabled.
    #[serde(skip)]
    pub enabled: bool,
}

impl PortForward {
    pub fn new_id() -> String {
        format!("{:016x}", rand::random::<u64>())
    }

    pub fn display_name(&self) -> String {
        let label = self.label.trim();
        if label.is_empty() {
            format!("{}:{}", self.remote_host, self.remote_port)
        } else {
            label.to_string()
        }
    }

    pub fn local_endpoint(&self) -> String {
        format!("localhost:{}", self.local_port)
    }

    pub fn remote_endpoint(&self) -> String {
        format!("{}:{}", self.remote_host, self.remote_port)
    }

    /// Whether two configs relay identically. Display-only fields (the label)
    /// don't count, so editing them must not drop live connections.
    fn same_relay(&self, other: &Self) -> bool {
        self.local_port == other.local_port
            && self.remote_host == other.remote_host
            && self.remote_port == other.remote_port
            && self.enabled == other.enabled
    }
}

/// Live state of one forward's listener. "Stopped" is represented by absence:
/// a forward with no status has no running session (or is disabled).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForwardState {
    Listening,
    Failed(String),
}

#[derive(Clone, Debug)]
pub struct ForwardStatus {
    pub id: String,
    pub state: ForwardState,
    /// Live relayed connections.
    pub active: usize,
    /// Most recent per-connection setup failure; cleared by the next success.
    pub last_conn_error: Option<String>,
}

/// Cells shared between a forward's task (writer) and `statuses()` (reader).
struct ForwardShared {
    state: Mutex<ForwardState>,
    active: AtomicUsize,
    last_conn_error: Mutex<Option<String>>,
}

/// Never panic on a poisoned mutex — recover the guard.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct ForwardTask {
    forward: PortForward,
    handle: JoinHandle<()>,
    shared: Arc<ForwardShared>,
}

/// Session-wide wrong-instance guard: verifies, lazily and at most once per
/// session, that the SOCKS port is served by a flextunnel client connected to
/// the expected server (see the module docs). All forwards of a
/// [`ForwardManager`] share one check.
struct InstanceCheck {
    expected_node_id: Arc<str>,
    /// Latches on the first successful probe. An async mutex so concurrent
    /// first connections serialize on a single in-flight probe.
    verified: tokio::sync::Mutex<bool>,
}

impl InstanceCheck {
    fn new(expected_node_id: Arc<str>) -> Self {
        Self {
            expected_node_id,
            verified: tokio::sync::Mutex::new(false),
        }
    }

    /// Probe the SOCKS port unless a previous probe already succeeded this
    /// session. Failures are not cached — a transient outage (tunnel
    /// reconnecting) retries on the next connection.
    async fn ensure_verified(&self, socks_port: u16) -> anyhow::Result<()> {
        let mut verified = self.verified.lock().await;
        if *verified {
            return Ok(());
        }
        probe_instance(socks_port, &self.expected_node_id).await?;
        *verified = true;
        Ok(())
    }
}

/// Fetch `http://flextunnel.internal/status.json` through the SOCKS port and
/// require the reported `server_node_id` to match. Every failure mode maps to
/// "this is not the right SOCKS5 listener": a non-SOCKS or authenticating
/// server fails the handshake, a non-flextunnel proxy serves no status page,
/// and another flextunnel reports a different server node id.
async fn probe_instance(socks_port: u16, expected_node_id: &str) -> anyhow::Result<()> {
    let mut socks = TcpStream::connect((Ipv4Addr::LOCALHOST, socks_port))
        .await
        .map_err(|e| anyhow::anyhow!("SOCKS5 proxy unreachable: {e}"))?;
    socks5::client_handshake_noauth(&mut socks).await?;
    let status_target = Target::Domain(reserved::STATUS_HOST.into(), 80);
    socks5::client_write_connect(&mut socks, &status_target).await?;
    let rep = socks5::client_read_reply(&mut socks).await?;
    if rep != signaling::REP_SUCCESS {
        anyhow::bail!(
            "instance probe CONNECT to {} failed: {}",
            reserved::STATUS_HOST,
            socks5::describe_reply(rep)
        );
    }
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        status_page::STATUS_JSON_PATH,
        reserved::STATUS_HOST
    );
    socks.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    socks.read_to_end(&mut response).await?;
    let node_id = parse_status_node_id(&response).map_err(|e| {
        anyhow::anyhow!(
            "the SOCKS port did not serve the flextunnel status page ({e}) — \
             another SOCKS5 server (not this app) is on this port?"
        )
    })?;
    if !node_id.eq_ignore_ascii_case(expected_node_id) {
        anyhow::bail!(
            "the SOCKS port is served by a flextunnel connected to a different \
             server (node id {node_id}, expected {expected_node_id})"
        );
    }
    Ok(())
}

/// Parse the probe's HTTP response: require a 200 status line and extract
/// `server_node_id` from the JSON body.
fn parse_status_node_id(response: &[u8]) -> anyhow::Result<String> {
    let head_end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("no HTTP response head"))?;
    let head = std::str::from_utf8(&response[..head_end])
        .map_err(|_| anyhow::anyhow!("HTTP response head is not UTF-8"))?;
    let status_line = head.lines().next().unwrap_or_default();
    let mut parts = status_line.split(' ');
    if !parts.next().unwrap_or_default().starts_with("HTTP/1.") || parts.next() != Some("200") {
        anyhow::bail!("unexpected HTTP response: {status_line}");
    }
    let body: serde_json::Value = serde_json::from_slice(&response[head_end + 4..])?;
    body.get("server_node_id")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("status JSON has no server_node_id"))
}

/// Owns the listener tasks for one tunnel session. Created when a session
/// starts, reconciled on every forward-list change, dropped (aborting
/// everything, relays included) when the session ends.
pub struct ForwardManager {
    socks_port: u16,
    check: Arc<InstanceCheck>,
    tasks: HashMap<String, ForwardTask>,
}

impl ForwardManager {
    pub fn new(
        socks_port: u16,
        expected_server_node_id: Arc<str>,
        forwards: &[PortForward],
    ) -> Self {
        let mut manager = Self {
            socks_port,
            check: Arc::new(InstanceCheck::new(expected_server_node_id)),
            tasks: HashMap::new(),
        };
        manager.apply(forwards);
        manager
    }

    /// Reconcile the running tasks with the desired list: removed, disabled, or
    /// relay-edited forwards are aborted (dropping their live relays); new or
    /// edited enabled forwards are spawned. Forwards whose relay config is
    /// unchanged — including label-only edits — keep their listeners and open
    /// connections.
    pub fn apply(&mut self, forwards: &[PortForward]) {
        let desired: HashMap<&str, &PortForward> =
            forwards.iter().map(|f| (f.id.as_str(), f)).collect();
        self.tasks.retain(|id, task| match desired.get(id.as_str()) {
            Some(f) if f.same_relay(&task.forward) => {
                // Refresh display-only fields so the stored copy stays current.
                task.forward = (*f).clone();
                true
            }
            _ => {
                task.handle.abort();
                false
            }
        });
        for forward in forwards {
            if forward.enabled && !self.tasks.contains_key(&forward.id) {
                let shared = Arc::new(ForwardShared {
                    state: Mutex::new(ForwardState::Listening),
                    active: AtomicUsize::new(0),
                    last_conn_error: Mutex::new(None),
                });
                let handle = tokio::spawn(run_forward(
                    forward.clone(),
                    self.socks_port,
                    self.check.clone(),
                    shared.clone(),
                ));
                self.tasks.insert(
                    forward.id.clone(),
                    ForwardTask {
                        forward: forward.clone(),
                        handle,
                        shared,
                    },
                );
            }
        }
    }

    pub fn statuses(&self) -> Vec<ForwardStatus> {
        self.tasks
            .iter()
            .map(|(id, task)| ForwardStatus {
                id: id.clone(),
                state: lock(&task.shared.state).clone(),
                active: task.shared.active.load(Ordering::Relaxed),
                last_conn_error: lock(&task.shared.last_conn_error).clone(),
            })
            .collect()
    }
}

impl Drop for ForwardManager {
    fn drop(&mut self) {
        // Aborting a forward task drops its JoinSet, which aborts its relays.
        for task in self.tasks.values() {
            task.handle.abort();
        }
    }
}

/// Increments the forward's active-connection count for the relay's lifetime;
/// the `Drop` decrement runs even when the relay is aborted.
struct ActiveGuard(Arc<ForwardShared>);

impl ActiveGuard {
    fn new(shared: Arc<ForwardShared>) -> Self {
        shared.active.fetch_add(1, Ordering::Relaxed);
        Self(shared)
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// `accept()` on an optionally-bound listener; pends forever when the stack
/// didn't bind so it stays inert in the `select!`.
async fn accept_on(listener: Option<&TcpListener>) -> io::Result<(TcpStream, SocketAddr)> {
    match listener {
        Some(listener) => listener.accept().await,
        None => std::future::pending().await,
    }
}

async fn run_forward(
    forward: PortForward,
    socks_port: u16,
    check: Arc<InstanceCheck>,
    shared: Arc<ForwardShared>,
) {
    let port = forward.local_port;
    let v4 = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await;
    let v6 = TcpListener::bind((Ipv6Addr::LOCALHOST, port)).await;
    let (v4, v6) = match (v4, v6) {
        // Listening as long as at least one loopback stack bound (a client app
        // dialing `localhost` may try either family first, but retries the
        // other on connection-refused).
        (Err(e4), Err(e6)) => {
            let reason = if e4.kind() == io::ErrorKind::AddrInUse
                || e6.kind() == io::ErrorKind::AddrInUse
            {
                format!("port {port} is in use")
            } else {
                e4.to_string()
            };
            log::error!("Forward localhost:{port} failed to bind: {reason}");
            *lock(&shared.state) = ForwardState::Failed(reason);
            return;
        }
        (v4, v6) => (v4.ok(), v6.ok()),
    };
    log::info!(
        "Forwarding localhost:{port} → {}:{} via SOCKS5 ({}{})",
        forward.remote_host,
        forward.remote_port,
        if v4.is_some() { "IPv4" } else { "" },
        match (&v4, &v6) {
            (Some(_), Some(_)) => "+IPv6",
            (None, Some(_)) => "IPv6",
            _ => "",
        }
    );

    let mut relays = JoinSet::new();
    loop {
        let accepted = tokio::select! {
            accepted = accept_on(v4.as_ref()) => accepted,
            accepted = accept_on(v6.as_ref()) => accepted,
            // Reap finished relays so the JoinSet doesn't grow unboundedly.
            Some(_) = relays.join_next(), if !relays.is_empty() => continue,
        };
        let inbound = match accepted {
            Ok((inbound, _peer)) => inbound,
            Err(e) => {
                log::warn!("Forward localhost:{port} accept failed ({e}); retrying");
                tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
                continue;
            }
        };
        let shared = shared.clone();
        let check = check.clone();
        let target = Target::Domain(forward.remote_host.clone(), forward.remote_port);
        relays.spawn(async move {
            let _guard = ActiveGuard::new(shared.clone());
            match relay_conn(inbound, socks_port, &check, &target).await {
                Ok(()) => *lock(&shared.last_conn_error) = None,
                Err(e) => {
                    log::warn!("Forward localhost:{port}: {e}");
                    *lock(&shared.last_conn_error) = Some(e.to_string());
                }
            }
        });
    }
}

/// Relay one accepted connection: verify the SOCKS port is the right instance
/// (cached after the session's first success), dial the local SOCKS5 listener,
/// CONNECT to the forward's target, then splice bytes until either side closes.
async fn relay_conn(
    mut inbound: TcpStream,
    socks_port: u16,
    check: &InstanceCheck,
    target: &Target,
) -> anyhow::Result<()> {
    let setup = async {
        check.ensure_verified(socks_port).await?;
        // The core binds its SOCKS5 listener on 127.0.0.1 (tunnel.rs).
        let mut socks = TcpStream::connect((Ipv4Addr::LOCALHOST, socks_port))
            .await
            .map_err(|e| anyhow::anyhow!("SOCKS5 proxy unreachable: {e}"))?;
        socks5::client_handshake_noauth(&mut socks).await?;
        socks5::client_write_connect(&mut socks, target).await?;
        let rep = socks5::client_read_reply(&mut socks).await?;
        if rep == signaling::REP_SUCCESS {
            Ok(socks)
        } else {
            Err(anyhow::anyhow!(
                "connect failed: {}",
                socks5::describe_reply(rep)
            ))
        }
    };
    let mut socks = tokio::time::timeout(SOCKS_SETUP_TIMEOUT, setup)
        .await
        .map_err(|_| anyhow::anyhow!("SOCKS5 setup timed out"))??;
    // The pipe outcome is not a forward error — apps close however they like.
    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut socks).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE_ID: &str = "feedfacefeedfacefeedfacefeedface";

    fn forward(local_port: u16) -> PortForward {
        PortForward {
            id: PortForward::new_id(),
            label: String::new(),
            local_port,
            remote_host: "echo.internal".into(),
            remote_port: 7,
            enabled: true,
        }
    }

    #[test]
    fn names_and_descriptions() {
        let mut f = forward(8080);
        assert_eq!(f.display_name(), "echo.internal:7");
        assert_eq!(f.local_endpoint(), "localhost:8080");
        assert_eq!(f.remote_endpoint(), "echo.internal:7");
        f.label = "  echo  ".into();
        assert_eq!(f.display_name(), "echo");
    }

    /// The probe must understand the real status page, not just this module's
    /// canned test response — render one through the core's own template and
    /// HTTP shape (mirroring `status_page::write_http_payload`).
    #[test]
    fn probe_parses_real_status_page() {
        use flextunnel_core::proxy::status_page::{render_status, ServerStatusTemplate, StatusFormat};

        let tpl = ServerStatusTemplate {
            version: "test",
            node_id: NODE_ID.to_string(),
            routed_domains: Vec::new(),
            routed_cidrs: Vec::new(),
            host_aliases: Vec::new(),
            agent_routes: Vec::new(),
            dns_forwards: Vec::new(),
            bridges: Vec::new(),
            inbound_bridges: Vec::new(),
            blocklist_path: String::new(),
            blocked_client_count: 0,
            blocked_agent_count: 0,
            conflicted_server_count: 0,
        };
        let (status_line, content_type, body) = render_status(&tpl, StatusFormat::Json);
        let response = format!(
            "HTTP/1.1 {status_line}\r\nContent-Type: {content_type}\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len(),
        );
        assert_eq!(
            parse_status_node_id(response.as_bytes()).expect("parse"),
            NODE_ID
        );
    }

    /// A minimal flextunnel-style SOCKS5 server on an ephemeral port, built
    /// from the same core server functions the real listener uses: no-auth
    /// negotiation, a status-page reply (with `node_id` as the server node id)
    /// for a CONNECT to `flextunnel.internal:80`, echo for any other CONNECT.
    async fn spawn_mini_socks(node_id: &'static str) -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind mini socks");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    if socks5::negotiate_method(&mut stream).await.is_err() {
                        return;
                    }
                    let Ok(target) = socks5::read_connect_request(&mut stream).await else {
                        return;
                    };
                    if socks5::write_reply(&mut stream, signaling::REP_SUCCESS)
                        .await
                        .is_err()
                    {
                        return;
                    }
                    if target == Target::Domain(reserved::STATUS_HOST.into(), 80) {
                        let _ = serve_mini_status(&mut stream, node_id).await;
                    } else {
                        let (mut read, mut write) = stream.split();
                        let _ = tokio::io::copy(&mut read, &mut write).await;
                    }
                });
            }
        });
        port
    }

    /// Consume the probe's request head, then answer with a canned status JSON
    /// and close (the probe reads to EOF).
    async fn serve_mini_status(stream: &mut TcpStream, node_id: &str) -> io::Result<()> {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await?);
        }
        let body = format!("{{\"server_node_id\":\"{node_id}\"}}");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len(),
        );
        stream.write_all(response.as_bytes()).await
    }

    async fn free_port() -> u16 {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("probe bind")
            .local_addr()
            .expect("addr")
            .port()
    }

    async fn status_of(manager: &ForwardManager, id: &str) -> ForwardStatus {
        manager
            .statuses()
            .into_iter()
            .find(|s| s.id == id)
            .expect("status present")
    }

    #[tokio::test]
    async fn forwards_bytes_through_matching_instance() {
        let socks_port = spawn_mini_socks(NODE_ID).await;
        let local_port = free_port().await;
        let forward = forward(local_port);
        let id = forward.id.clone();
        let manager = ForwardManager::new(socks_port, NODE_ID.into(), &[forward]);

        // The listener task binds asynchronously; retry the dial briefly.
        let mut conn = None;
        for _ in 0..50 {
            match TcpStream::connect((Ipv4Addr::LOCALHOST, local_port)).await {
                Ok(stream) => {
                    conn = Some(stream);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
        let mut conn = conn.expect("forward listener reachable");

        conn.write_all(b"ping").await.expect("write");
        let mut buf = [0u8; 4];
        conn.read_exact(&mut buf).await.expect("echo");
        assert_eq!(&buf, b"ping");

        let status = status_of(&manager, &id).await;
        assert_eq!(status.state, ForwardState::Listening);
        assert_eq!(status.active, 1);
        assert_eq!(status.last_conn_error, None);
    }

    #[tokio::test]
    async fn wrong_instance_drops_connection_and_reports() {
        // A flextunnel-style server reporting a *different* server node id, as
        // if a flextunnel pointed at another server were squatting the port.
        let socks_port = spawn_mini_socks("00000000000000000000000000000000").await;
        let local_port = free_port().await;
        let forward = forward(local_port);
        let id = forward.id.clone();
        let manager = ForwardManager::new(socks_port, NODE_ID.into(), &[forward]);

        let mut conn = None;
        for _ in 0..50 {
            match TcpStream::connect((Ipv4Addr::LOCALHOST, local_port)).await {
                Ok(stream) => {
                    conn = Some(stream);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
        let mut conn = conn.expect("forward listener reachable");

        // The relay must drop the connection (EOF), not pass bytes through.
        let mut buf = [0u8; 1];
        assert_eq!(conn.read(&mut buf).await.expect("read"), 0);

        let status = status_of(&manager, &id).await;
        let error = status.last_conn_error.expect("error recorded");
        assert!(error.contains("different"), "got: {error}");
    }

    #[tokio::test]
    async fn non_flextunnel_port_drops_connection_and_reports() {
        // A plain echo server on the port: not a SOCKS5 server at all, like a
        // random service squatting the configured SOCKS port. Its "greeting
        // reply" echoes our own bytes back, which must fail the handshake.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind echo");
        let socks_port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let (mut read, mut write) = stream.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        });

        let local_port = free_port().await;
        let forward = forward(local_port);
        let id = forward.id.clone();
        let manager = ForwardManager::new(socks_port, NODE_ID.into(), &[forward]);

        let mut conn = None;
        for _ in 0..50 {
            match TcpStream::connect((Ipv4Addr::LOCALHOST, local_port)).await {
                Ok(stream) => {
                    conn = Some(stream);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
        let mut conn = conn.expect("forward listener reachable");

        let mut buf = [0u8; 1];
        assert_eq!(conn.read(&mut buf).await.expect("read"), 0);

        let status = status_of(&manager, &id).await;
        let error = status.last_conn_error.expect("error recorded");
        assert!(error.contains("not offered"), "got: {error}");
    }

    #[tokio::test]
    async fn apply_keeps_task_on_label_only_edit() {
        let socks_port = spawn_mini_socks(NODE_ID).await;
        let mut f = forward(free_port().await);
        let mut manager =
            ForwardManager::new(socks_port, NODE_ID.into(), std::slice::from_ref(&f));
        let shared_before = Arc::as_ptr(&manager.tasks[&f.id].shared);

        // Label-only edit: same task (same shared cells), refreshed metadata.
        f.label = "renamed".into();
        manager.apply(std::slice::from_ref(&f));
        assert_eq!(Arc::as_ptr(&manager.tasks[&f.id].shared), shared_before);
        assert_eq!(manager.tasks[&f.id].forward.label, "renamed");

        // Relay edit: task restarted (fresh shared cells).
        f.remote_port += 1;
        manager.apply(std::slice::from_ref(&f));
        assert_ne!(Arc::as_ptr(&manager.tasks[&f.id].shared), shared_before);
    }

    #[tokio::test]
    async fn apply_reconciles_tasks() {
        let socks_port = spawn_mini_socks(NODE_ID).await;
        let a = forward(free_port().await);
        let mut b = forward(free_port().await);
        let mut manager = ForwardManager::new(socks_port, NODE_ID.into(), &[a.clone(), b.clone()]);
        assert_eq!(manager.statuses().len(), 2);

        // Disable one: its task disappears.
        b.enabled = false;
        manager.apply(&[a.clone(), b.clone()]);
        let statuses = manager.statuses();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].id, a.id);

        // Remove the rest.
        manager.apply(&[]);
        assert!(manager.statuses().is_empty());
    }
}
