//! The headless `flextunnel client start` session: proxy front-ends (both
//! optional), server-direct port forwards, and the control channel that
//! `flextunnel client control` attaches to.
//!
//! Mirrors the desktop client's per-profile session (`flextunnel-desktop`'s
//! `tunnel.rs`): bind the enabled listeners, run the reconnecting client, poll
//! routes/forward state on a ticker, and serve status snapshots — here over the
//! IPC socket instead of a GUI channel. Unlike the desktop, nothing is mutable
//! from the panel: the forward set is the config's.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

use flextunnel_core::forwards::{
    ForwardManager, ForwardState, ForwardStatus, PortForward, disable_failed_forwards,
    validate_label, validate_remote_host,
};
use flextunnel_core::config::ForwardConfig;
use flextunnel_core::iroh::SecretKey;
use flextunnel_core::proxy::{ClientAuth, ClientConfig, ProxyClient, reserved};
use flextunnel_core::transport::endpoint::{
    ClientEndpoint, RelayConfig, create_client_endpoint, create_quick_client_endpoint,
};
use flextunnel_core::transport::paths::{ConnPath, ConnPathKind};
use flextunnel_core::{app, auth, config};

use crate::ipc::{
    self, ForwardRow, ForwardRowState, IpcCmd, Phase, StatusSnapshot, WireBridge, WireConnPath,
    WireConnSnapshot, WireCustomRelay, WireForward, WireRoutes,
};
use crate::{instance, lock};

pub async fn run(r: config::ResolvedClient) -> Result<()> {
    let server_node_id = r.server_node_id.clone().context(
        "The client requires a server node id (--server-node-id or server_node_id in the config).",
    )?;
    // A profile's server id never changes, so its prefix is the client's
    // on-disk identity: lock and control socket.
    let key = instance::instance_key(&server_node_id)?;
    let client_key = resolve_client_key(&r)?;
    // The public half is what the server operator needs on their
    // authorized-keys file — never a secret, so log it plainly.
    log::info!("Client auth public key: {}", client_key.public_str());

    // Held for the process lifetime; also what makes removing a stale control
    // socket safe (see ipc.rs).
    let _lock = lock::acquire_client(&key)?;

    // The forward set is the config's `[[forwards]]` tables, fixed for the
    // session (the panel only observes it). Validated here like the rest of
    // the config, before the endpoint exists. All start enabled; one whose
    // listener fails to bind is switched off by the ticker below.
    let forwards = forwards_from_config(&r.forwards)
        .map_err(|e| anyhow::anyhow!("Invalid [[forwards]] in the client config: {e}"))?;
    if !forwards.is_empty() {
        log::info!("Loaded {} port forward(s) from the config", forwards.len());
    }

    // The routed set (tunnel set) is configured on the server and pushed
    // during the handshake (see ProxyClient::handshake).
    let runtime = build_session(
        r,
        server_node_id,
        SessionAuth::Key(client_key),
        key.clone(),
        forwards,
    )
    .await?;
    if runtime.state.socks_addr.is_none() && runtime.state.http_addr.is_none() {
        log::info!("No local proxy listeners configured; running in port-forward-only mode");
    }

    // Serve the control socket others attach to; a detaching panel never stops
    // the tunnel, and the loop keeps running when the channel closes.
    drive_session(runtime, move |tx, _initial| {
        ipc::spawn_ipc_server(&key, tx).map(IpcSink::Socket)
    })
    .await
}

/// Resolve the client auth keypair: exactly one of the inline secret or the
/// key file. Normal sessions only — quick mode has no keypair (its credential
/// is the client's endpoint id, allowlisted on the quick server).
fn resolve_client_key(r: &config::ResolvedClient) -> Result<auth::ClientKey> {
    if r.auth_key.is_some() && r.auth_key_file.is_some() {
        anyhow::bail!("Provide only one of auth_key or auth_key_file, not both");
    }
    if let Some(secret) = &r.auth_key {
        auth::ClientKey::from_secret_str(secret.trim()).context("Invalid client secret key")
    } else if let Some(path) = &r.auth_key_file {
        auth::load_client_key_from_file(path).context("Failed to load the client key file")
    } else {
        anyhow::bail!(
            "The client requires an authentication keypair.\n\
             Generate one with: flexaccess-keys generate-auth-key -o <FILE>\n\
             Then pass --auth-key-file <FILE> (or --auth-key <SECRET>), or set \
             auth_key_file/auth_key in the config, and put the key's public half \
             (`flexaccess-keys show-auth-key --private-key-file <FILE>`) on the \
             server's authorized_keys_file."
        )
    }
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
/// `client_secret` is the session's pre-generated identity, whose endpoint id
/// the caller already printed for the user to allowlist on the quick server —
/// that id (not a keypair) is the quick client's credential, so the endpoint must
/// bind with exactly this secret.
pub async fn run_quick(r: config::ResolvedClient, client_secret: SecretKey) -> Result<()> {
    let server_node_id = r.server_node_id.clone().context(
        "The client requires a server node id (--server-node-id or server_node_id in the config).",
    )?;
    // Display-only in quick mode (no lock/socket paths are derived from it);
    // computing it also validates the id shape up front.
    let key = instance::instance_key(&server_node_id)?;

    // No config, so no forwards (the panel cannot declare any).
    let runtime = build_session(
        r,
        server_node_id,
        SessionAuth::Quick(client_secret),
        key,
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

/// The assembled per-session runtime that [`drive_session`] consumes: the iroh
/// endpoint, the proxy client and its live routes, the bound proxy listeners,
/// the forward manager + set, and the status state.
struct SessionRuntime {
    endpoint: ClientEndpoint,
    client: std::sync::Arc<ProxyClient>,
    routes: std::sync::Arc<std::sync::Mutex<flextunnel_core::proxy::TunnelRoutes>>,
    socks_listener: Option<tokio::net::TcpListener>,
    http_listener: Option<tokio::net::TcpListener>,
    fwd_mgr: ForwardManager,
    forwards: Vec<PortForward>,
    state: SessionState,
}

/// How a session authenticates, coupling the credential to the endpoint
/// identity it requires so the two cannot be mixed and matched: a keypair
/// session dials from an anonymous ephemeral endpoint, while a quick session
/// must bind its endpoint to the fixed secret whose id the quick server
/// allowlisted — the id *is* the credential.
enum SessionAuth {
    /// Normal session: signed keypair credential over the client ALPN.
    Key(auth::ClientKey),
    /// Quick session: no keypair; the endpoint binds to this secret and its
    /// endpoint id is checked against the quick server's allowlist.
    Quick(SecretKey),
}

/// Create the iroh endpoint, bind the enabled proxy front-ends (127.0.0.1 only,
/// like the desktop client — unauthenticated, never exposed off-machine), and
/// assemble the [`SessionRuntime`]. Shared by [`run`] and [`run_quick`]; the
/// caller supplies the [`SessionAuth`] (which also determines the endpoint's
/// identity), the instance `key` (status display), and the session's fixed
/// `forwards`. On any failure past endpoint creation the endpoint is closed
/// gracefully before returning.
async fn build_session(
    r: config::ResolvedClient,
    server_node_id: String,
    auth: SessionAuth,
    key: String,
    forwards: Vec<PortForward>,
) -> Result<SessionRuntime> {
    let relay_config = RelayConfig::from_urls_with_token(&r.relay_urls, r.relay_auth_token.clone())
        .context("Invalid relay configuration")?;
    let (endpoint, auth) = match auth {
        SessionAuth::Key(client_key) => (
            create_client_endpoint(&relay_config).await,
            ClientAuth::Key(Box::new(client_key)),
        ),
        SessionAuth::Quick(secret) => (
            create_quick_client_endpoint(&relay_config, secret).await,
            ClientAuth::QuickAllowlisted,
        ),
    };
    let endpoint = endpoint.context("Failed to create iroh endpoint")?;
    log::info!("flextunnel client Node ID: {}", endpoint.id());

    let socks_bind = r.socks_port.map(|p| SocketAddr::from(([127, 0, 0, 1], p)));
    let http_bind = r.http_port.map(|p| SocketAddr::from(([127, 0, 0, 1], p)));

    let client = std::sync::Arc::new(ProxyClient::new(ClientConfig {
        server_node_id: server_node_id.clone(),
        auth,
        socks_listen: socks_bind,
        http_listen: http_bind,
        relay_urls: r.relay_urls,
        relay_auth_token: r.relay_auth_token,
        auto_reconnect: r.auto_reconnect,
        max_reconnect_attempts: r.max_reconnect_attempts,
    }));
    let routes = client.routes();

    // Bind the enabled proxy front-ends before anything else can take the
    // ports; a taken port fails startup with a clear message.
    let listeners = async {
        let socks = match socks_bind {
            Some(addr) => Some(bind_local(addr, "SOCKS").await?),
            None => None,
        };
        let http = match http_bind {
            Some(addr) => Some(bind_local(addr, "HTTP").await?),
            None => None,
        };
        anyhow::Ok((socks, http))
    };
    let (socks_listener, http_listener) = match listeners.await {
        Ok(listeners) => listeners,
        Err(e) => {
            endpoint.close().await;
            return Err(e);
        }
    };
    let socks_addr = local_addr(&socks_listener);
    let http_addr = local_addr(&http_listener);

    // Forwards run for the whole session (including reconnect gaps); they die
    // with the manager when the session ends.
    let fwd_mgr = ForwardManager::new(
        tokio::runtime::Handle::current(),
        client.server_forwarder(),
        &forwards,
    );

    let state = SessionState {
        instance: key,
        name: r.name,
        server_node_id,
        client_node_id: endpoint.id().to_string(),
        socks_addr,
        http_addr,
        ever_connected: false,
        connected_since: None,
        last_error: None,
        disabled_reasons: HashMap::new(),
    };

    Ok(SessionRuntime {
        endpoint,
        client,
        routes,
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
/// tear everything down and close the endpoint gracefully. `make_sink` wires the
/// freshly-created command channel to its consumer — the control socket server,
/// or the quick panel seeded with `initial` — keeping the differing IPC/panel
/// setup in the wrappers.
async fn drive_session(
    runtime: SessionRuntime,
    make_sink: impl FnOnce(mpsc::Sender<IpcCmd>, StatusSnapshot) -> Result<IpcSink>,
) -> Result<()> {
    let SessionRuntime {
        endpoint,
        client,
        routes,
        socks_listener,
        http_listener,
        mut fwd_mgr,
        mut forwards,
        mut state,
    } = runtime;

    let (ipc_tx, mut ipc_rx) = mpsc::channel(8);
    let initial = state.snapshot(&routes, &forwards, &fwd_mgr);
    // Any failure past endpoint creation must still close the endpoint
    // gracefully (fatal under panic=abort otherwise).
    let sink = match make_sink(ipc_tx, initial) {
        Ok(sink) => sink,
        Err(e) => {
            drop(fwd_mgr);
            endpoint.close().await;
            return Err(e);
        }
    };
    // A closed control channel means the quick panel quit → disconnect. A normal
    // session's IPC accept task holds its sender while the guard lives, so the
    // channel never closes there and the `None` arm stays a no-op.
    let quit_on_ipc_close = matches!(sink, IpcSink::Panel(_));

    let run = client.run_with_optional_listeners(&endpoint, socks_listener, http_listener);
    tokio::pin!(run);
    let mut ticker = tokio::time::interval(Duration::from_millis(500));

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
                state.observe_connection(routes.lock().map(|r| r.connected).unwrap_or(false));
                // The reconnect loop rebuilds the endpoint after repeated
                // failures, which changes the (ephemeral) node id — keep the
                // status display current.
                state.client_node_id = endpoint.id().to_string();
            }
            cmd = ipc_rx.recv() => match cmd {
                Some(IpcCmd::Status(reply)) => {
                    let _ = reply.send(state.snapshot(&routes, &forwards, &fwd_mgr));
                }
                // On-demand connection snapshot: paths + custom-relay /healthz.
                // Off-loaded to a task (never on the polled Status path, and
                // never awaited in-loop) because the health probe does on-demand
                // HTTP; ~3s worst case would otherwise stall the client run,
                // ticker, and shutdown futures this select is also driving.
                Some(IpcCmd::ConnPath(reply)) => {
                    let client = std::sync::Arc::clone(&client);
                    tokio::spawn(async move {
                        let snap = client.connection_snapshot().await;
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
            sig = app::shutdown_signal() => {
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
    // socket, then close the endpoint gracefully — bounded so a slow teardown
    // can't leave the client hung (a second signal or timeout forces exit, just
    // like the server). Finally join the panel (if any) so the terminal is
    // restored; a graceful close completes well before that, so the normal path
    // reaches it.
    drop(ipc_rx);
    drop(fwd_mgr);
    let panel = match sink {
        IpcSink::Socket(guard) => {
            drop(guard);
            None
        }
        IpcSink::Panel(panel) => Some(panel),
    };
    crate::close_endpoint_or_exit(&endpoint.endpoint()).await;
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
    /// The server-id-prefix instance key (see `instance.rs`).
    instance: String,
    /// Friendly profile name from the config, display-only.
    name: Option<String>,
    server_node_id: String,
    client_node_id: String,
    socks_addr: Option<SocketAddr>,
    http_addr: Option<SocketAddr>,
    ever_connected: bool,
    connected_since: Option<Instant>,
    last_error: Option<String>,
    /// Bind-failure reasons of forwards switched off by the ticker, keyed by
    /// forward id, shown next to their rows for the rest of the session.
    disabled_reasons: HashMap<String, String>,
}

impl SessionState {
    fn observe_connection(&mut self, connected: bool) {
        if connected {
            self.ever_connected = true;
            if self.connected_since.is_none() {
                self.connected_since = Some(Instant::now());
            }
        } else {
            self.connected_since = None;
        }
    }

    fn phase(&self, connected: bool) -> Phase {
        if connected {
            Phase::Connected
        } else if self.ever_connected {
            Phase::Reconnecting
        } else {
            Phase::Connecting
        }
    }

    fn snapshot(
        &self,
        routes: &std::sync::Arc<std::sync::Mutex<flextunnel_core::proxy::TunnelRoutes>>,
        forwards: &[PortForward],
        fwd_mgr: &ForwardManager,
    ) -> StatusSnapshot {
        let routes = routes.lock().map(|r| r.clone()).unwrap_or_default();
        let statuses = fwd_mgr.statuses();
        StatusSnapshot {
            instance: self.instance.clone(),
            name: self.name.clone(),
            phase: self.phase(routes.connected),
            connected_secs: self.connected_since.map(|t| t.elapsed().as_secs()),
            server_node_id: self.server_node_id.clone(),
            client_node_id: self.client_node_id.clone(),
            socks_addr: self.socks_addr,
            http_addr: self.http_addr,
            status_page_host: reserved::STATUS_HOST.to_string(),
            last_error: self.last_error.clone(),
            routes: wire_routes(routes),
            forwards: forwards
                .iter()
                .map(|f| self.forward_row(f, &statuses))
                .collect(),
        }
    }

    fn forward_row(&self, forward: &PortForward, statuses: &[ForwardStatus]) -> ForwardRow {
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
                    ForwardState::Starting => {
                        (ForwardRowState::Starting, None, s.active, s.last_conn_error.clone())
                    }
                    ForwardState::Listening => {
                        (ForwardRowState::Listening, None, s.active, s.last_conn_error.clone())
                    }
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
            state,
            error,
            active,
            last_conn_error,
        }
    }
}

/// Build the session's forward set from the config's `[[forwards]]` tables,
/// enforcing the invariants the running client and the panel rely on: valid
/// labels and remote hosts, nonzero ports, and unique local ports (the local
/// port identifies a forward on the control channel). Hosts and labels are
/// stored normalized (trimmed, IPv6 brackets stripped). Every forward starts
/// enabled. Errors name the offending entry by its 1-based position.
fn forwards_from_config(entries: &[ForwardConfig]) -> Result<Vec<PortForward>, String> {
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
        forwards.push(PortForward {
            // The core manager keys listeners by id; the local port is the
            // natural unique key here (there is no persisted identity).
            id: entry.local_port.to_string(),
            label,
            local_port: entry.local_port,
            remote_host,
            remote_port: entry.remote_port,
            enabled: true,
        });
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

fn wire_routes(routes: flextunnel_core::proxy::TunnelRoutes) -> WireRoutes {
    WireRoutes {
        domains: routes.domains,
        cidrs: routes.cidrs,
        host_aliases: routes.host_aliases,
        dns_forwards: routes.dns_forwards,
        bridges: routes
            .bridges
            .into_iter()
            .map(|b| WireBridge {
                name: b.name,
                endpoint_id: b.endpoint_id,
                domains: b.domains,
                cidrs: b.cidrs,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(local_port: u16, remote_host: &str) -> ForwardConfig {
        ForwardConfig {
            label: String::new(),
            local_port,
            remote_host: remote_host.into(),
            remote_port: 5432,
        }
    }

    #[test]
    fn config_forwards_are_validated_and_start_enabled() {
        let forwards =
            forwards_from_config(&[entry(5000, "db.internal"), entry(5001, "other.internal")])
                .expect("valid");
        assert_eq!(forwards.len(), 2);
        assert!(forwards.iter().all(|f| f.enabled));
        assert_eq!(forwards[0].id, "5000");
        assert_eq!(forwards[1].local_port, 5001);

        let err = forwards_from_config(&[entry(5000, "a"), entry(5000, "b")]).unwrap_err();
        assert!(err.contains("forward #2") && err.contains("5000"), "{err}");
        assert!(forwards_from_config(&[entry(0, "db.internal")]).is_err(), "zero local port");
        assert!(forwards_from_config(&[entry(5000, "bad..host")]).is_err(), "bad host");

        let mut zero_remote = entry(5000, "db.internal");
        zero_remote.remote_port = 0;
        assert!(forwards_from_config(&[zero_remote]).is_err(), "zero remote port");

        let mut long_label = entry(5000, "db.internal");
        long_label.label = "x".repeat(65);
        assert!(forwards_from_config(&[long_label]).is_err(), "oversized label");
    }

    #[test]
    fn host_and_label_are_normalized() {
        let mut e = entry(5001, " [2001:db8::1] ");
        e.label = "  db  ".into();
        let f = forwards_from_config(&[e]).unwrap().remove(0);
        assert_eq!(f.label, "db");
        assert_eq!(f.remote_host, "2001:db8::1");
    }
}
