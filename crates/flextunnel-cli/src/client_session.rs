//! The headless `flextunnel client` session: proxy front-ends (both optional),
//! server-direct port forwards, and the control channel that `flextunnel
//! client status` attaches to.
//!
//! Mirrors the desktop client's per-profile session (`flextunnel-desktop`'s
//! `tunnel.rs`): bind the enabled listeners, run the reconnecting client, poll
//! routes/forward state on a ticker, and serve status/mutation commands — here
//! arriving over the IPC socket instead of a GUI channel.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

use flextunnel_core::forwards::{
    ForwardManager, ForwardState, ForwardStatus, PortForward, disable_failed_forwards,
    validate_label, validate_remote_host,
};
use flextunnel_core::proxy::{ClientConfig, ProxyClient, reserved};
use flextunnel_core::transport::endpoint::{ConnPath, ConnPathKind, create_client_endpoint};
use flextunnel_core::{app, auth, config};

use crate::ipc::{
    self, ForwardRow, ForwardRowState, IpcCmd, Mutation, Phase, StatusSnapshot, WireBridge,
    WireConnPath, WireForward, WireRoutes,
};
use crate::{forwards as store, instance, lock};

pub async fn run(r: config::ResolvedClient) -> Result<()> {
    let server_node_id = r.server_node_id.context(
        "The client requires a server node id (--server-node-id or server_node_id in the config).",
    )?;
    // A profile's server id never changes, so its prefix is the client's
    // on-disk identity: lock, control socket, and forwards file.
    let key = instance::instance_key(&server_node_id)?;

    if r.auth_token.is_some() && r.auth_token_file.is_some() {
        anyhow::bail!("Provide only one of auth_token or auth_token_file, not both");
    }
    let token = if let Some(token) = r.auth_token {
        auth::validate_client_token(&token).context("Invalid authentication token")?;
        token
    } else if let Some(path) = r.auth_token_file {
        auth::load_auth_token_from_file(&path, auth::CLIENT_TOKEN_PREFIX)
            .context("Failed to load authentication token from file")?
    } else {
        anyhow::bail!(
            "The client requires an authentication token.\n\
             Use --auth-token <TOKEN>, --auth-token-file <FILE>, or set \
             auth_token/auth_token_file in the config."
        );
    };

    // Held for the process lifetime; also what makes removing a stale control
    // socket safe (see ipc.rs).
    let _lock = lock::acquire_client(&key)?;

    // All forwards load disabled (`enabled` is never persisted) — enabling is
    // an explicit per-session action, like the desktop.
    let mut forwards = store::load(&key)?;
    if !forwards.is_empty() {
        log::info!(
            "Loaded {} port forward(s) (disabled) from {}",
            forwards.len(),
            store::forwards_path(&key)?.display()
        );
    }

    // The routed set (tunnel set) is configured on the server and pushed
    // during the handshake (see ProxyClient::handshake).

    let endpoint = create_client_endpoint(&r.relay_urls, r.dns_server.as_deref())
        .await
        .context("Failed to create iroh endpoint")?;
    log::info!("flextunnel client Node ID: {}", endpoint.id());

    let client = ProxyClient::new(ClientConfig {
        server_node_id: server_node_id.clone(),
        auth_token: token,
        socks_listen: r.socks_listen,
        http_listen: r.http_listen,
        relay_urls: r.relay_urls,
        auto_reconnect: r.auto_reconnect,
        max_reconnect_attempts: r.max_reconnect_attempts,
    });
    let routes = client.routes();

    // Bind the enabled proxy front-ends before anything else can take the
    // ports; a taken port fails startup with a clear message.
    let listeners = async {
        let socks = match r.socks_listen {
            Some(addr) => Some(bind_local(addr, "SOCKS").await?),
            None => None,
        };
        let http = match r.http_listen {
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
    if socks_addr.is_none() && http_addr.is_none() {
        log::info!("No local proxy listeners configured; running in port-forward-only mode");
    }

    // Forwards run for the whole session (including reconnect gaps); they die
    // with the manager when the session ends.
    let mut fwd_mgr = ForwardManager::new(
        tokio::runtime::Handle::current(),
        client.server_forwarder(),
        &forwards,
    );

    let (ipc_tx, mut ipc_rx) = mpsc::channel(8);
    // Like the listener binds above: any failure past endpoint creation must
    // still close the endpoint gracefully (fatal under panic=abort otherwise).
    let ipc_guard = match ipc::spawn_ipc_server(&key, ipc_tx) {
        Ok(guard) => guard,
        Err(e) => {
            drop(fwd_mgr);
            endpoint.close().await;
            return Err(e);
        }
    };

    let mut state = SessionState {
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
            }
            cmd = ipc_rx.recv() => match cmd {
                Some(IpcCmd::Status(reply)) => {
                    let _ = reply.send(state.snapshot(&client, &routes, &forwards, &fwd_mgr));
                }
                Some(IpcCmd::Mutate(mutation, reply)) => {
                    let result = state
                        .apply_mutation(mutation, &mut forwards, &mut fwd_mgr)
                        .map(|()| state.snapshot(&client, &routes, &forwards, &fwd_mgr));
                    let _ = reply.send(result);
                }
                // The IPC accept task never drops its sender while the guard
                // lives; treat a closed channel as a bug-tolerant no-op.
                None => {}
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

    // Tear the forward listeners and the control socket down with the session,
    // then close the endpoint gracefully before it is dropped (an ungraceful
    // drop aborts iroh's relay tasks, which is fatal under panic=abort).
    drop(fwd_mgr);
    drop(ipc_guard);
    endpoint.close().await;
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

/// Session-scoped status/mutation state shared by the ticker and the IPC arms.
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
    /// Retained bind-failure reasons of auto-disabled forwards, keyed by
    /// forward id; cleared when the forward is re-enabled, edited, or deleted.
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
        client: &ProxyClient,
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
            conn_paths: client.conn_paths().iter().map(wire_conn_path).collect(),
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

    /// Validate and apply one forward mutation, reconcile the listeners, and
    /// persist (Add/Update/Delete only — `enabled` is never persisted, so
    /// toggles don't touch the file).
    fn apply_mutation(
        &mut self,
        mutation: Mutation,
        forwards: &mut Vec<PortForward>,
        fwd_mgr: &mut ForwardManager,
    ) -> Result<(), String> {
        let persist = !matches!(mutation, Mutation::SetEnabled(..));
        match mutation {
            Mutation::Add(wire) => {
                let mut forward = validated(wire, forwards, None)?;
                if forward.id.is_empty() {
                    forward.id = PortForward::new_id();
                } else if forwards.iter().any(|f| f.id == forward.id) {
                    return Err(format!("A forward with id {:?} already exists", forward.id));
                }
                forwards.push(forward);
            }
            Mutation::Update(wire) => {
                let id = wire.id.clone();
                let forward = validated(wire, forwards, Some(&id))?;
                let slot = forwards
                    .iter_mut()
                    .find(|f| f.id == id)
                    .ok_or_else(|| format!("No forward with id {id:?}"))?;
                *slot = forward;
                self.disabled_reasons.remove(&id);
            }
            Mutation::Delete(id) => {
                let before = forwards.len();
                forwards.retain(|f| f.id != id);
                if forwards.len() == before {
                    return Err(format!("No forward with id {id:?}"));
                }
                self.disabled_reasons.remove(&id);
            }
            Mutation::SetEnabled(id, enabled) => {
                let forward = forwards
                    .iter_mut()
                    .find(|f| f.id == id)
                    .ok_or_else(|| format!("No forward with id {id:?}"))?;
                forward.enabled = enabled;
                if enabled {
                    self.disabled_reasons.remove(&id);
                }
            }
        }

        // Reconcile listeners first so the change is live even if persisting
        // fails; a failed save is reported but deliberately not rolled back
        // (the file wins on the next successful save).
        fwd_mgr.apply(forwards);
        if persist
            && let Err(e) = store::save(&self.instance, forwards)
        {
            log::warn!("Failed to persist port forwards: {e:#}");
            return Err(format!("Applied, but failed to save forwards: {e:#}"));
        }
        Ok(())
    }
}

/// Server-side (authoritative) validation of a wire forward; the TUI form
/// runs the same core validators for instant feedback.
fn validated(
    wire: WireForward,
    forwards: &[PortForward],
    editing_id: Option<&str>,
) -> Result<PortForward, String> {
    let label = validate_label(&wire.label)?;
    let remote_host = validate_remote_host(&wire.remote_host)?;
    if wire.local_port == 0 {
        return Err("Local port must be 1-65535".into());
    }
    if wire.remote_port == 0 {
        return Err("Remote port must be 1-65535".into());
    }
    if let Some(owner) = forwards
        .iter()
        .filter(|f| editing_id != Some(f.id.as_str()))
        .find(|f| f.local_port == wire.local_port)
    {
        return Err(format!(
            "Local port {} is already used by {}",
            wire.local_port,
            owner.display_name()
        ));
    }
    Ok(PortForward {
        id: wire.id,
        label,
        local_port: wire.local_port,
        remote_host,
        remote_port: wire.remote_port,
        enabled: wire.enabled,
    })
}

fn wire_forward(f: &PortForward) -> WireForward {
    WireForward {
        id: f.id.clone(),
        label: f.label.clone(),
        local_port: f.local_port,
        remote_host: f.remote_host.clone(),
        remote_port: f.remote_port,
        enabled: f.enabled,
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
    let agent_routes = routes
        .agent_states(Instant::now())
        .into_iter()
        .map(|(name, state)| (name, state.as_str().to_string()))
        .collect();
    WireRoutes {
        domains: routes.domains,
        cidrs: routes.cidrs,
        host_aliases: routes.host_aliases,
        agent_routes,
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

    fn wire(id: &str, local_port: u16) -> WireForward {
        WireForward {
            id: id.into(),
            label: String::new(),
            local_port,
            remote_host: "db.internal".into(),
            remote_port: 5432,
            enabled: false,
        }
    }

    fn existing(id: &str, local_port: u16) -> PortForward {
        PortForward {
            id: id.into(),
            label: String::new(),
            local_port,
            remote_host: "other.internal".into(),
            remote_port: 80,
            enabled: false,
        }
    }

    #[test]
    fn validated_enforces_ports_host_and_uniqueness() {
        let current = vec![existing("a", 5000)];

        assert!(validated(wire("", 5001), &current, None).is_ok());
        assert!(validated(wire("", 0), &current, None).is_err());
        assert!(validated(wire("", 5000), &current, None).is_err(), "taken port");
        // Updating the owner itself may keep its port.
        assert!(validated(wire("a", 5000), &current, Some("a")).is_ok());

        let mut bad_host = wire("", 5001);
        bad_host.remote_host = "bad..host".into();
        assert!(validated(bad_host, &current, None).is_err());

        let mut bad_remote = wire("", 5001);
        bad_remote.remote_port = 0;
        assert!(validated(bad_remote, &current, None).is_err());
    }

    #[test]
    fn host_and_label_are_normalized() {
        let mut w = wire("", 5001);
        w.label = "  db  ".into();
        w.remote_host = " [2001:db8::1] ".into();
        let f = validated(w, &[], None).unwrap();
        assert_eq!(f.label, "db");
        assert_eq!(f.remote_host, "2001:db8::1");
    }
}
