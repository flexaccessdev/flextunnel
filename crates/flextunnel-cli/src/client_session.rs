//! The headless `flextunnel client start` session: proxy front-ends (both
//! optional), port forwards, and the control channel that `flextunnel client
//! control` and `flextunnel client nc` attach to.
//!
//! Mirrors the desktop client's per-profile session (`flextunnel-desktop`'s
//! `tunnel.rs`): bind the enabled listeners, run the client, poll forward
//! state on a ticker, and serve status snapshots — here over the IPC socket
//! instead of a GUI channel. Starting the session connects nothing: each
//! destination connects when something is first sent to it. Unlike the
//! desktop, nothing is mutable from the panel: the forward set is the
//! config's.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

use flextunnel_core::config::ForwardConfig;
use flextunnel_core::forwards::{
    ForwardManager, ForwardState, ForwardStatus, PortForward, disable_failed_forwards,
    validate_label, validate_remote_host,
};
use flextunnel_core::iroh::{EndpointId, SecretKey};
use flextunnel_core::proxy::signaling::Target;
use flextunnel_core::proxy::{
    ClientAuth, ClientConfig, ClientStatus, DestinationConfig, DestinationStatus, LocalListeners,
    ProxyClient, TunnelDialer, reserved,
};
use flextunnel_core::transport::endpoint::RelayConfig;
use flextunnel_core::transport::paths::{ConnPath, ConnPathKind};
use flextunnel_core::{app, config};

use crate::ipc::{
    self, DestinationRow, ForwardRow, ForwardRowState, IpcCmd, StatusSnapshot, WireConnPath,
    WireConnSnapshot, WireCustomRelay, WireForward,
};
use crate::{instance, lock};

pub async fn run(r: config::ResolvedClient) -> Result<()> {
    // The instance name is the client's on-disk identity: lock and control
    // socket.
    let name = instance::instance_name(r.name.as_deref())?;
    let proxy_config = r.proxy_config()?;
    // The public halves are what the server operators need on their
    // authorized-keys files — never a secret, so log them plainly.
    let mut logged = Vec::new();
    for destination in &proxy_config.destinations {
        if let ClientAuth::Key(key) = &destination.auth {
            let public = key.public_str();
            if !logged.contains(&public) {
                log::info!("Client auth public key: {public}");
                logged.push(public);
            }
        }
    }

    // Held for the process lifetime; also what makes removing a stale control
    // socket safe (see ipc.rs).
    let _lock = lock::acquire_client(&name)?;

    // Validates the destinations (names, routes, one entry per server).
    // Nothing is bound or dialed by this.
    let client = Arc::new(
        ProxyClient::new(proxy_config)
            .map_err(|e| anyhow::anyhow!("Invalid client config: {e}"))?,
    );

    // The forward set is the config's `[[forwards]]` tables, fixed for the
    // session (the panel only observes it). Validated here like the rest of
    // the config, before anything is bound. All start enabled; one whose
    // listener fails to bind is switched off by the ticker below.
    let dialer = client.dialer();
    let forwards = forwards_from_config(&r.forwards, &dialer)
        .map_err(|e| anyhow::anyhow!("Invalid [[forwards]] in the client config: {e}"))?;
    if !forwards.is_empty() {
        log::info!("Loaded {} port forward(s) from the config", forwards.len());
    }

    let runtime = build_session(client, r.socks_port, r.http_port, name.clone(), forwards).await?;
    if runtime.state.socks_addr.is_none() && runtime.state.http_addr.is_none() {
        log::info!("No local proxy listeners configured; running in port-forward-only mode");
    }

    // Serve the control socket others attach to; a detaching panel never stops
    // the client, and the loop keeps running when the channel closes. `client
    // nc` tunnels go through the session's dialer, like the port forwards.
    drive_session(runtime, move |tx, _initial| {
        ipc::spawn_ipc_server(&name, tx, dialer).map(IpcSink::Socket)
    })
    .await
}

/// The one destination of a quick session. Its name is fixed — there is no
/// config to choose one in — and reaches the quick server's own loopback like
/// any destination's.
pub const QUICK_NAME: &str = "quick";

/// What a `client start --quick` session connects to and serves.
pub struct QuickSession {
    /// The quick server's EndpointId.
    pub server_id: EndpointId,
    pub socks_port: Option<u16>,
    pub http_port: Option<u16>,
    pub relay_urls: Vec<String>,
    pub relay_auth_token: Option<String>,
    pub relay_quic_addr_discovery: Option<bool>,
}

/// The self-contained `flextunnel client start --quick` session: an ephemeral
/// client that runs the live control panel in *this* terminal instead of
/// detaching. Unlike [`run`] it takes **no single-instance lock** and exposes
/// **no control socket** — nothing is persisted and nothing else can attach.
/// It reads no config, so it has no port forwards. The panel and the session
/// talk over an in-process channel; quitting the panel drops its sender, closing
/// the channel, which shuts the session down — so the tunnel disconnects rather
/// than detaching.
///
/// A quick session is the one that is **not** lazy: its single destination
/// ([`QUICK_NAME`]) routes everything — the quick server is a full tunnel —
/// and is dialed at once and kept connected, because the quick server exits
/// unless its client shows up soon after it starts.
///
/// `client_secret` is the session's pre-generated identity, whose endpoint id
/// the caller already printed for the user to allowlist on the quick server —
/// that id (not a keypair) is the quick client's credential, so the endpoint must
/// bind with exactly this secret.
pub async fn run_quick(quick: QuickSession, client_secret: SecretKey) -> Result<()> {
    let relay = RelayConfig::from_settings(
        &quick.relay_urls,
        quick.relay_auth_token,
        quick.relay_quic_addr_discovery,
    )
    .context("Invalid relay configuration")?;
    let client = Arc::new(
        ProxyClient::new(ClientConfig {
            destinations: vec![DestinationConfig {
                name: QUICK_NAME.to_string(),
                server_id: quick.server_id,
                auth: ClientAuth::Quick(Box::new(client_secret)),
                relay,
                routed_domains: vec!["*".to_string()],
                routed_cidrs: vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
                keep_connected: true,
            }],
            idle_timeout: None,
        })
        .map_err(|e| anyhow::anyhow!("{e}"))?,
    );

    // No config, so no forwards (the panel cannot declare any). The name is
    // display-only: no lock or socket is derived from it.
    let runtime = build_session(
        client,
        quick.socks_port,
        quick.http_port,
        "quick".to_string(),
        Vec::new(),
    )
    .await?;

    // Drive the self-contained panel over an in-process channel — no socket is
    // exposed, so `flextunnel client control` cannot attach. The panel runs a
    // blocking ratatui loop on a dedicated thread and owns the only command
    // sender: when the user quits, that sender drops, closing the channel, and
    // the loop treats that as the disconnect signal.
    drive_session(runtime, |tx, initial| {
        Ok(IpcSink::Panel(tokio::task::spawn_blocking(move || {
            crate::tui::run_quick_panel(tx, initial)
        })))
    })
    .await
}

/// The assembled per-session runtime that [`drive_session`] consumes: the
/// proxy client, the bound proxy listeners, the forward manager + set, and the
/// status state.
struct SessionRuntime {
    client: Arc<ProxyClient>,
    socks_listener: Option<tokio::net::TcpListener>,
    http_listener: Option<tokio::net::TcpListener>,
    fwd_mgr: ForwardManager,
    forwards: Vec<PortForward>,
    state: SessionState,
}

/// Bind the enabled proxy front-ends (127.0.0.1 only, like the desktop client
/// — unauthenticated, never exposed off-machine) and assemble the
/// [`SessionRuntime`]. Shared by [`run`] and [`run_quick`]; the caller supplies
/// the built client, the instance `name` (status display), and the session's
/// fixed `forwards`. No endpoint exists yet, so a failure here leaves nothing
/// to close.
async fn build_session(
    client: Arc<ProxyClient>,
    socks_port: Option<u16>,
    http_port: Option<u16>,
    name: String,
    forwards: Vec<PortForward>,
) -> Result<SessionRuntime> {
    // Bind the enabled proxy front-ends before anything else can take the
    // ports; a taken port fails startup with a clear message.
    let socks_listener = match socks_port {
        Some(port) => Some(bind_local(SocketAddr::from(([127, 0, 0, 1], port)), "SOCKS").await?),
        None => None,
    };
    let http_listener = match http_port {
        Some(port) => Some(bind_local(SocketAddr::from(([127, 0, 0, 1], port)), "HTTP").await?),
        None => None,
    };
    let socks_addr = local_addr(&socks_listener);
    let http_addr = local_addr(&http_listener);

    // Forwards listen for the whole session; a forwarded connection connects
    // its destination on demand. They die with the manager when the session
    // ends.
    let fwd_mgr = ForwardManager::new(
        tokio::runtime::Handle::current(),
        client.dialer(),
        &forwards,
    );

    let state = SessionState {
        name,
        socks_addr,
        http_addr,
        disabled_reasons: HashMap::new(),
    };

    Ok(SessionRuntime {
        client,
        socks_listener,
        http_listener,
        fwd_mgr,
        forwards,
        state,
    })
}

/// Where the session's control channel is served — the only structural
/// difference between a normal and a quick session's loop.
enum IpcSink {
    /// A control socket others attach to; a detaching panel never stops the
    /// tunnel, and the guard removes the socket on teardown.
    Socket(ipc::IpcServerGuard),
    /// The self-contained quick panel; when it quits (its sender drops, closing
    /// the channel) the tunnel disconnects, and the task is joined on teardown
    /// so the terminal is always restored.
    Panel(tokio::task::JoinHandle<Result<()>>),
}

/// Run the session's `tokio::select!` loop until the client future ends, a
/// shutdown signal arrives, or (panel only) the control channel closes; then
/// tear everything down and close the client's endpoints gracefully.
/// `make_sink` wires the freshly-created command channel to its consumer — the
/// control socket server, or the quick panel seeded with `initial` — keeping
/// the differing IPC/panel setup in the wrappers.
async fn drive_session(
    runtime: SessionRuntime,
    make_sink: impl FnOnce(mpsc::Sender<IpcCmd>, StatusSnapshot) -> Result<IpcSink>,
) -> Result<()> {
    let SessionRuntime {
        client,
        socks_listener,
        http_listener,
        mut fwd_mgr,
        mut forwards,
        mut state,
    } = runtime;
    let dialer = client.dialer();

    let (ipc_tx, mut ipc_rx) = mpsc::channel(8);
    let initial = state.snapshot(&client.status(), &forwards, &fwd_mgr, &dialer);
    // Nothing has been dialed yet, so a failure here has no endpoint to close.
    let sink = make_sink(ipc_tx, initial)?;
    // A closed control channel means the quick panel quit → disconnect. A normal
    // session's IPC accept task holds its sender while the guard lives, so the
    // channel never closes there and the `None` arm stays a no-op.
    let quit_on_ipc_close = matches!(sink, IpcSink::Panel(_));

    // Boxed so it can be dropped before the endpoints are closed below.
    let mut run = Box::pin(client.run(LocalListeners::tcp(socks_listener, http_listener)));
    let mut ticker = tokio::time::interval(Duration::from_millis(500));
    // One shutdown future for the whole loop rather than one per pass. Its
    // listeners see only the signals that arrive while they exist, so a signal
    // that lands as another arm completes would be lost with the future that
    // pass drops, and the handler stays installed, so the process would not
    // be killed either.
    let mut shutdown = std::pin::pin!(app::shutdown_signal());

    let res = loop {
        tokio::select! {
            res = &mut run => {
                break res.map_err(|e| anyhow::anyhow!("Client error: {e}"));
            }
            _ = ticker.tick() => {
                // A forward whose listener failed to bind flips back off, with
                // the reason retained for its status row (desktop parity).
                let failed = disable_failed_forwards(&mut forwards, &fwd_mgr.statuses());
                if !failed.is_empty() {
                    for (id, reason) in failed {
                        log::warn!("Port forward disabled: {reason}");
                        state.disabled_reasons.insert(id, reason);
                    }
                    fwd_mgr.apply(&forwards);
                }
            }
            cmd = ipc_rx.recv() => match cmd {
                Some(IpcCmd::Status(reply)) => {
                    let _ = reply.send(state.snapshot(&client.status(), &forwards, &fwd_mgr, &dialer));
                }
                // On-demand connection snapshot: paths + custom-relay /healthz.
                // Off-loaded to a task (never on the polled Status path, and
                // never awaited in-loop) because the health probe does on-demand
                // HTTP; ~3s worst case would otherwise stall the client run,
                // ticker, and shutdown futures this select is also driving.
                Some(IpcCmd::ConnPath(name, reply)) => {
                    let client = Arc::clone(&client);
                    tokio::spawn(async move {
                        let snap = client.connection_snapshot(&name).await;
                        let _ = reply.send(WireConnSnapshot {
                            paths: snap.paths.iter().map(wire_conn_path).collect(),
                            custom_relays: snap
                                .custom_relays
                                .into_iter()
                                .map(|r| WireCustomRelay {
                                    url: r.url,
                                    working: r.working,
                                    error: r.error,
                                })
                                .collect(),
                        });
                    });
                }
                None => {
                    if quit_on_ipc_close {
                        break Ok(());
                    }
                }
            },
            sig = &mut shutdown => {
                // Break (not return) even on a signal-handler error so the
                // graceful endpoint close below still runs.
                if sig.is_ok() {
                    log::info!("Received shutdown signal, stopping client");
                }
                break sig;
            }
        }
    };

    // Close the channel so a quick panel still waiting on a reply (or issuing
    // its next request) unblocks and exits, tear down forwards and the control
    // socket, stop the client, then close the endpoints of the destinations
    // that were in use gracefully — bounded so a slow teardown can't leave the
    // client hung (a second signal or timeout forces exit, just like the
    // server). Finally join the panel (if any) so the terminal is restored; a
    // graceful close completes well before that, so the normal path reaches
    // it.
    drop(ipc_rx);
    drop(fwd_mgr);
    let panel = match sink {
        IpcSink::Socket(guard) => {
            drop(guard);
            None
        }
        IpcSink::Panel(panel) => Some(panel),
    };
    drop(run);
    crate::close_or_exit(client.close()).await;
    if let Some(panel) = panel {
        let _ = panel.await;
    }
    res
}

/// Bind a local listener, mapping the common taken-port case to a clear error.
async fn bind_local(addr: SocketAddr, label: &str) -> Result<tokio::net::TcpListener> {
    tokio::net::TcpListener::bind(addr).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::AddrInUse {
            anyhow::anyhow!(
                "{label} port {} is already in use — another flextunnel?",
                addr.port()
            )
        } else {
            anyhow::anyhow!("Failed to bind the {label} listener on {addr}: {e}")
        }
    })
}

fn local_addr(listener: &Option<tokio::net::TcpListener>) -> Option<SocketAddr> {
    listener.as_ref().and_then(|l| l.local_addr().ok())
}

/// Session-scoped status state shared by the ticker and the IPC arms.
struct SessionState {
    /// The client's instance name (see `instance.rs`).
    name: String,
    socks_addr: Option<SocketAddr>,
    http_addr: Option<SocketAddr>,
    /// Bind-failure reasons of forwards switched off by the ticker, keyed by
    /// forward id, shown next to their rows for the rest of the session.
    disabled_reasons: HashMap<String, String>,
}

impl SessionState {
    fn snapshot(
        &self,
        status: &ClientStatus,
        forwards: &[PortForward],
        fwd_mgr: &ForwardManager,
        dialer: &TunnelDialer,
    ) -> StatusSnapshot {
        let statuses = fwd_mgr.statuses();
        let now = Instant::now();
        StatusSnapshot {
            name: self.name.clone(),
            socks_addr: self.socks_addr,
            http_addr: self.http_addr,
            status_page_host: reserved::STATUS_HOST.to_string(),
            idle_timeout_secs: status.idle_timeout.map(|idle| idle.as_secs()),
            destinations: status
                .destinations
                .iter()
                .map(|d| destination_row(d, now))
                .collect(),
            forwards: forwards
                .iter()
                .map(|f| self.forward_row(f, &statuses, dialer))
                .collect(),
        }
    }

    fn forward_row(
        &self,
        forward: &PortForward,
        statuses: &[ForwardStatus],
        dialer: &TunnelDialer,
    ) -> ForwardRow {
        let status = statuses.iter().find(|s| s.id == forward.id);
        let (state, error, active, last_conn_error) = if !forward.enabled {
            (
                ForwardRowState::Stopped,
                self.disabled_reasons.get(&forward.id).cloned(),
                0,
                None,
            )
        } else {
            match status {
                // Enabled but not yet reconciled into the manager: starting.
                None => (ForwardRowState::Starting, None, 0, None),
                Some(s) => match &s.state {
                    ForwardState::Starting => (
                        ForwardRowState::Starting,
                        None,
                        s.active,
                        s.last_conn_error.clone(),
                    ),
                    ForwardState::Listening => (
                        ForwardRowState::Listening,
                        None,
                        s.active,
                        s.last_conn_error.clone(),
                    ),
                    ForwardState::Failed(reason) => (
                        ForwardRowState::Failed,
                        Some(reason.clone()),
                        s.active,
                        s.last_conn_error.clone(),
                    ),
                },
            }
        };
        ForwardRow {
            forward: wire_forward(forward),
            // Every forward was checked to have one at startup.
            destination: dialer
                .destination_for(&forward_target(forward))
                .unwrap_or_default(),
            state,
            error,
            active,
            last_conn_error,
        }
    }
}

fn destination_row(d: &DestinationStatus, now: Instant) -> DestinationRow {
    DestinationRow {
        name: d.name.clone(),
        server_node_id: d.server_node_id.clone(),
        state: d.state.into(),
        connected_secs: d
            .connected_since
            .map(|at| now.saturating_duration_since(at).as_secs()),
        open_streams: d.open_streams,
        waiting: d.waiting,
        client_node_id: d.client_node_id.clone(),
        failed_attempts: d.failed_attempts,
        next_attempt_secs: d
            .next_attempt_at
            .map(|at| at.saturating_duration_since(now).as_secs()),
        last_error: d.last_error.clone(),
        routed_domains: d.routed_domains.clone(),
        routed_cidrs: d.routed_cidrs.clone(),
        relay_urls: d.relay_urls.clone(),
    }
}

/// The wire target of a forward — a domain-form target, like the forward
/// listener itself sends.
fn forward_target(forward: &PortForward) -> Target {
    Target::Domain(forward.remote_host.clone(), forward.remote_port)
}

/// Build the session's forward set from the config's `[[forwards]]` tables,
/// enforcing the invariants the running client and the panel rely on: valid
/// labels and remote hosts, nonzero ports, unique local ports (the local
/// port identifies a forward on the control channel), and a destination that
/// routes each remote host — a forward never connects directly, so one
/// pointing at a host nobody routes could only ever fail. Hosts and labels are
/// stored normalized (trimmed, IPv6 brackets stripped). Every forward starts
/// enabled. Errors name the offending entry by its 1-based position.
fn forwards_from_config(
    entries: &[ForwardConfig],
    dialer: &TunnelDialer,
) -> Result<Vec<PortForward>, String> {
    let mut forwards: Vec<PortForward> = Vec::with_capacity(entries.len());
    for (i, entry) in entries.iter().enumerate() {
        let n = i + 1;
        let label = validate_label(&entry.label).map_err(|e| format!("forward #{n}: {e}"))?;
        let remote_host =
            validate_remote_host(&entry.remote_host).map_err(|e| format!("forward #{n}: {e}"))?;
        if entry.local_port == 0 {
            return Err(format!("forward #{n}: local_port must be 1-65535"));
        }
        if entry.remote_port == 0 {
            return Err(format!("forward #{n}: remote_port must be 1-65535"));
        }
        if let Some(owner) = forwards.iter().find(|f| f.local_port == entry.local_port) {
            return Err(format!(
                "forward #{n}: local_port {} is already used by {}",
                entry.local_port,
                owner.display_name()
            ));
        }
        let forward = PortForward {
            // The core manager keys listeners by id; the local port is the
            // natural unique key here (there is no persisted identity).
            id: entry.local_port.to_string(),
            label,
            local_port: entry.local_port,
            remote_host,
            remote_port: entry.remote_port,
            enabled: true,
        };
        if dialer.destination_for(&forward_target(&forward)).is_none() {
            return Err(format!(
                "forward #{n}: no destination routes {} — use a destination's \
                 <name>.localhost.flextunnel.internal, or add the host to a destination's \
                 routed_domains / routed_cidrs",
                forward.remote_host
            ));
        }
        forwards.push(forward);
    }
    Ok(forwards)
}

fn wire_forward(f: &PortForward) -> WireForward {
    WireForward {
        label: f.label.clone(),
        local_port: f.local_port,
        remote_host: f.remote_host.clone(),
        remote_port: f.remote_port,
    }
}

fn wire_conn_path(p: &ConnPath) -> WireConnPath {
    WireConnPath {
        kind: match p.kind {
            ConnPathKind::Direct => "direct",
            ConnPathKind::Relay => "relay",
            ConnPathKind::Other => "other",
        }
        .to_string(),
        display: p.display.clone(),
        selected: p.selected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A dialer over two destinations: `m1` routing `*.internal` and
    /// `2001:db8::/32`, `m2` routing `10.0.0.0/8`. Building it
    /// connects nothing.
    fn dialer() -> TunnelDialer {
        let destination =
            |name: &str, seed: u8, domains: &[&str], cidrs: &[&str]| DestinationConfig {
                name: name.to_string(),
                server_id: SecretKey::from_bytes(&[seed; 32]).public(),
                auth: ClientAuth::Quick(Box::new(SecretKey::from_bytes(&[seed + 100; 32]))),
                relay: RelayConfig::default(),
                routed_domains: domains.iter().map(|s| s.to_string()).collect(),
                routed_cidrs: cidrs.iter().map(|s| s.to_string()).collect(),
                keep_connected: false,
            };
        ProxyClient::new(ClientConfig {
            destinations: vec![
                destination("m1", 1, &["*.internal"], &["2001:db8::/32"]),
                destination("m2", 2, &[], &["10.0.0.0/8"]),
            ],
            idle_timeout: None,
        })
        .unwrap()
        .dialer()
    }

    fn entry(local_port: u16, remote_host: &str) -> ForwardConfig {
        ForwardConfig {
            label: String::new(),
            local_port,
            remote_host: remote_host.into(),
            remote_port: 5432,
        }
    }

    #[tokio::test]
    async fn config_forwards_are_validated_and_start_enabled() {
        let dialer = dialer();
        let forwards = forwards_from_config(
            &[entry(5000, "db.internal"), entry(5001, "other.internal")],
            &dialer,
        )
        .expect("valid");
        assert_eq!(forwards.len(), 2);
        assert!(forwards.iter().all(|f| f.enabled));
        assert_eq!(forwards[0].id, "5000");
        assert_eq!(forwards[1].local_port, 5001);

        let err = forwards_from_config(
            &[entry(5000, "a.internal"), entry(5000, "b.internal")],
            &dialer,
        )
        .unwrap_err();
        assert!(err.contains("forward #2") && err.contains("5000"), "{err}");
        assert!(
            forwards_from_config(&[entry(0, "db.internal")], &dialer).is_err(),
            "zero local port"
        );
        assert!(
            forwards_from_config(&[entry(5000, "bad..host")], &dialer).is_err(),
            "bad host"
        );

        let mut zero_remote = entry(5000, "db.internal");
        zero_remote.remote_port = 0;
        assert!(
            forwards_from_config(&[zero_remote], &dialer).is_err(),
            "zero remote port"
        );

        let mut long_label = entry(5000, "db.internal");
        long_label.label = "x".repeat(65);
        assert!(
            forwards_from_config(&[long_label], &dialer).is_err(),
            "oversized label"
        );
    }

    #[tokio::test]
    async fn host_and_label_are_normalized() {
        let mut e = entry(5001, " [2001:db8::1] ");
        e.label = "  db  ".into();
        let f = forwards_from_config(&[e], &dialer()).unwrap().remove(0);
        assert_eq!(f.label, "db");
        assert_eq!(f.remote_host, "2001:db8::1");
    }

    /// A forward is carried by the destination that routes its host: a
    /// destination's loopback name (the server's loopback), a routed domain,
    /// or a routed network. A host nobody routes is refused at startup.
    #[tokio::test]
    async fn a_forward_needs_a_destination_that_routes_it() {
        let dialer = dialer();
        let state = SessionState {
            name: "test".into(),
            socks_addr: None,
            http_addr: None,
            disabled_reasons: HashMap::new(),
        };
        for (host, destination) in [
            ("m2.localhost.flextunnel.internal", "m2"),
            ("db.internal", "m1"),
            ("10.1.2.3", "m2"),
            ("2001:db8::7", "m1"),
        ] {
            let forward = forwards_from_config(&[entry(5000, host)], &dialer)
                .unwrap_or_else(|e| panic!("{host}: {e}"))
                .remove(0);
            assert_eq!(
                state.forward_row(&forward, &[], &dialer).destination,
                destination,
                "{host}"
            );
        }
        for unrouted in [
            "example.org",
            "192.168.1.1",
            "localhost",
            "m2",
            "flextunnel.internal",
            "nope.localhost.flextunnel.internal",
        ] {
            let err = forwards_from_config(&[entry(5000, unrouted)], &dialer).unwrap_err();
            assert!(
                err.contains("forward #1") && err.contains("no destination routes"),
                "{err}"
            );
        }
    }

    /// The status snapshot reports every destination, idle before any use.
    #[tokio::test]
    async fn snapshot_lists_the_destinations() {
        let client = ProxyClient::new(ClientConfig {
            destinations: vec![DestinationConfig {
                name: "m1".to_string(),
                server_id: SecretKey::from_bytes(&[1; 32]).public(),
                auth: ClientAuth::Quick(Box::new(SecretKey::from_bytes(&[9; 32]))),
                relay: RelayConfig::default(),
                routed_domains: vec!["*.corp.example".to_string()],
                routed_cidrs: Vec::new(),
                keep_connected: false,
            }],
            idle_timeout: Some(Duration::from_secs(300)),
        })
        .unwrap();
        let runtime = build_session(Arc::new(client), None, None, "work".to_string(), Vec::new())
            .await
            .unwrap();
        let snapshot = runtime.state.snapshot(
            &runtime.client.status(),
            &runtime.forwards,
            &runtime.fwd_mgr,
            &runtime.client.dialer(),
        );
        assert_eq!(snapshot.name, "work");
        assert_eq!(snapshot.status_page_host, "flextunnel.internal");
        assert_eq!(snapshot.idle_timeout_secs, Some(300));
        assert!(snapshot.socks_addr.is_none() && snapshot.forwards.is_empty());
        let row = &snapshot.destinations[0];
        assert_eq!(row.name, "m1");
        assert_eq!(row.state, crate::ipc::DestState::Idle);
        assert_eq!(row.routed_domains, ["*.corp.example"]);
        assert!(row.client_node_id.is_none() && row.connected_secs.is_none());
    }
}
