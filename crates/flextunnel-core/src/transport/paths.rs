//! Connection-path reporting (direct vs relay) and custom-relay health.
//!
//! A point-in-time [`connection_snapshot`] backs the on-demand status UIs (the
//! desktop "connection path" CTA, the CLI status TUI, and the iOS
//! `flextunnel_conn_path` sheet). [`watch_connection_paths`] logs the selected
//! path and re-logs whenever it changes (e.g. relay -> direct).

use crate::transport::endpoint::RelayConfig;
pub use flexaccess_iroh::relay_health::CustomRelayStatus;
use flexaccess_iroh::relay_health::probe_custom_relay_health;
use iroh::TransportAddr;
use iroh::endpoint::{Connection, PathList};
use n0_future::StreamExt;
use tokio::task::JoinHandle;

/// Which kind of transport a connection path uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnPathKind {
    /// A direct peer-to-peer path (holepunched UDP).
    Direct,
    /// A path relayed through an iroh relay server.
    Relay,
    /// Any other transport iroh reports (forward-compatible catch-all).
    Other,
}

/// A single connection path snapshot for status display, decoupled from iroh's
/// borrowed [`PathList`] so it can be stored and shown on demand (the desktop's
/// "connection path" CTA and the iOS `flextunnel_conn_path` sheet).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnPath {
    pub kind: ConnPathKind,
    /// Human line like `Direct 1.2.3.4:52186 (rtt 1ms)` or
    /// `Relay https://… (rtt 42ms)`.
    pub display: String,
    /// Whether iroh currently routes traffic over this path.
    pub selected: bool,
}

/// One on-demand snapshot for connection-status UIs. Both path discovery and
/// relay health are sampled only when this is requested; no watcher is retained.
#[derive(Clone, Debug, Default)]
pub struct ConnectionSnapshot {
    pub paths: Vec<ConnPath>,
    pub custom_relays: Vec<CustomRelayStatus>,
    /// UDP datagrams sent on this connection since it was established. On
    /// cellular, energy is per-wakeup rather than per-byte (every send buys
    /// ~10s of high-power radio tail), so datagram counts sampled across an
    /// interval are the cheap proxy for the connection's radio cost.
    pub udp_tx_datagrams: u64,
    /// UDP datagrams received on this connection since it was established.
    pub udp_rx_datagrams: u64,
}

/// Snapshot the current path(s) of a live connection for a status UI, showing
/// *all* paths (not just the selected one) so a direct path iroh has discovered
/// but not selected is still visible. [`Connection::paths`] is itself a
/// point-in-time snapshot, so this needs no background watcher. Empty while the
/// connection is down.
pub fn connection_paths(conn: &Connection) -> Vec<ConnPath> {
    connection_paths_from(&conn.paths())
}

fn connection_paths_from(paths: &PathList<'_>) -> Vec<ConnPath> {
    paths
        .iter()
        .map(|path| {
            let rtt = path.rtt();
            let selected = path.is_selected();
            let (kind, display) = match path.remote_addr() {
                TransportAddr::Ip(addr) => {
                    (ConnPathKind::Direct, format!("Direct {addr} (rtt {rtt:.0?})"))
                }
                TransportAddr::Relay(url) => {
                    (ConnPathKind::Relay, format!("Relay {url} (rtt {rtt:.0?})"))
                }
                other => (ConnPathKind::Other, format!("{other:?} (rtt {rtt:.0?})")),
            };
            ConnPath {
                kind,
                display,
                selected,
            }
        })
        .collect()
}

/// Snapshot the connection paths and probe configured custom-relay health.
///
/// The path snapshot is synchronous; the relay health is an on-demand `/healthz`
/// probe (async, all relays in parallel). This is only invoked when a status UI
/// asks for it (the iOS/desktop connection-path sheet, the CLI status TUI), so
/// the HTTP checks never run on the tunnel's hot path.
pub async fn connection_snapshot(
    conn: &Connection,
    relay_config: &RelayConfig,
) -> ConnectionSnapshot {
    let paths = connection_paths_from(&conn.paths());
    let custom_relays = probe_custom_relay_health(relay_config).await;
    let stats = conn.stats();
    ConnectionSnapshot {
        paths,
        custom_relays,
        udp_tx_datagrams: stats.udp_tx.datagrams,
        udp_rx_datagrams: stats.udp_rx.datagrams,
    }
}

/// Format the currently-selected path(s) of a connection for logging, e.g.
/// `Direct [2607:…]:52186 (rtt 1ms)` or `Relay https://… (rtt 42ms)`.
fn format_paths(paths: &PathList<'_>) -> String {
    if paths.is_empty() {
        return "establishing...".to_string();
    }
    let parts: Vec<String> = paths
        .iter()
        .filter(|p| p.is_selected())
        .map(|path| {
            let rtt = path.rtt();
            match path.remote_addr() {
                TransportAddr::Ip(addr) => format!("Direct {addr} (rtt {rtt:.0?})"),
                TransportAddr::Relay(url) => format!("Relay {url} (rtt {rtt:.0?})"),
                other => format!("{other:?} (rtt {rtt:.0?})"),
            }
        })
        .collect();
    if parts.is_empty() {
        "no selected path".to_string()
    } else {
        parts.join(", ")
    }
}

/// Key identifying the selected-path topology, excluding the volatile RTT, so
/// we only log when the path actually changes (not on every RTT update).
fn paths_key(paths: &PathList<'_>) -> (bool, Vec<String>) {
    let selected = paths
        .iter()
        .filter(|p| p.is_selected())
        .map(|p| format!("{:?}", p.remote_addr()))
        .collect();
    (paths.is_empty(), selected)
}

/// RAII guard that aborts the background path-watcher task on drop.
pub struct PathWatcherGuard(Option<JoinHandle<()>>);

impl Drop for PathWatcherGuard {
    fn drop(&mut self) {
        if let Some(handle) = &self.0 {
            handle.abort();
        }
    }
}

/// Log the connection's selected path and spawn a background task that logs
/// updates whenever the active path changes (e.g. relay -> direct).
///
/// Logging is the task's sole purpose, so when debug logging is disabled the
/// task is not spawned at all and the returned guard is inert.
///
/// The returned [`PathWatcherGuard`] aborts the background task when dropped;
/// callers must keep it alive for the duration of the connection.
pub fn watch_connection_paths(conn: &Connection) -> PathWatcherGuard {
    if !log::log_enabled!(log::Level::Debug) {
        return PathWatcherGuard(None);
    }
    let conn = conn.clone();
    PathWatcherGuard(Some(tokio::spawn(async move {
        // The stream yields the current snapshot on the first poll, then a
        // fresh snapshot whenever the open or selected paths change; it ends
        // when the connection closes.
        let mut stream = conn.paths_stream();
        let mut last_key = None;
        while let Some(paths) = stream.next().await {
            let key = paths_key(&paths);
            if last_key.as_ref() != Some(&key) {
                log::debug!("Connection: {}", format_paths(&paths));
                last_key = Some(key);
            }
        }
    })))
}
