//! Common endpoint helpers for iroh proxy connections.

use crate::transport::{ALPN, build_quic_transport_config};
use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use iroh::{
    Endpoint, EndpointId, RelayMap, RelayMode, RelayUrl, SecretKey, TransportAddr,
    address_lookup::{DnsAddressLookup, PkarrPublisher},
    endpoint::{Builder as EndpointBuilder, Connection, PathList, presets},
};
use iroh_mdns_address_lookup::MdnsAddressLookup;
use log::{debug, info};
use n0_future::StreamExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

pub const RELAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Load secret key from file (base64 encoded).
pub fn load_secret(path: &Path) -> Result<SecretKey> {
    if !path.exists() {
        anyhow::bail!(
            "Secret key file not found: {}\nGenerate one with: flextunnel generate-server-key --output {}",
            path.display(),
            path.display()
        );
    }

    let content = std::fs::read_to_string(path).context("Failed to read secret key file")?;
    load_secret_from_string(content.trim())
}

/// Load secret key from a base64-encoded string.
pub fn load_secret_from_string(base64_key: &str) -> Result<SecretKey> {
    let bytes = BASE64
        .decode(base64_key)
        .context("Invalid base64 in secret key")?;

    SecretKey::try_from(&bytes[..]).context("Invalid secret key (must be 32 bytes)")
}

/// Get public key (EndpointId) from secret key.
pub fn secret_to_endpoint_id(secret: &SecretKey) -> EndpointId {
    secret.public()
}

/// Parse relay URL strings into a RelayMode.
pub fn parse_relay_mode(relay_urls: &[String]) -> Result<RelayMode> {
    if relay_urls.is_empty() {
        Ok(RelayMode::Default)
    } else {
        let parsed_urls: Vec<RelayUrl> = relay_urls
            .iter()
            .map(|url| url.parse().context(format!("Invalid relay URL: {}", url)))
            .collect::<Result<Vec<_>>>()?;
        let relay_map = RelayMap::from_iter(parsed_urls);
        Ok(RelayMode::Custom(relay_map))
    }
}

/// Print relay configuration status messages.
fn print_relay_status(relay_urls: &[String], using_custom_relay: bool) {
    if using_custom_relay {
        if relay_urls.len() == 1 {
            info!("Using custom relay server");
        } else {
            info!(
                "Using {} custom relay servers (with failover)",
                relay_urls.len()
            );
        }
    }
}

/// Create a base endpoint builder with common configuration.
///
/// iroh peer discovery (the n0 discovery service — pkarr publishing + DNS-based
/// lookup) is always enabled, including when custom relays are configured.
/// (This is iroh peer discovery, not real DNS resolution.)
///
/// # Arguments
/// * `relay_mode` - The relay mode to use.
/// * `secret_key` - When present (a persistent identity), the endpoint also
///   publishes itself via pkarr; an ephemeral endpoint (no secret) only
///   resolves and never advertises itself.
fn create_endpoint_builder(
    relay_mode: RelayMode,
    secret_key: Option<&SecretKey>,
) -> Result<EndpointBuilder> {
    let transport_config = build_quic_transport_config()?;
    // iroh 1.0 requires the crypto provider to be set explicitly on the
    // builder when starting from the `Empty` preset — the `tls-ring` feature
    // only makes the ring backend available, it does not wire it in.
    let mut builder = Endpoint::builder(presets::Empty)
        .relay_mode(relay_mode)
        .transport_config(transport_config)
        .crypto_provider(Arc::new(rustls::crypto::ring::default_provider()));

    // Always resolve through n0 discovery, but only publish when we have a
    // persistent identity. An ephemeral endpoint (no secret) shouldn't
    // advertise itself.
    if secret_key.is_some() {
        builder = builder.address_lookup(PkarrPublisher::n0_dns());
    }
    builder = builder.address_lookup(DnsAddressLookup::n0_dns());
    // mDNS always enabled for local network discovery.
    builder = builder.address_lookup(MdnsAddressLookup::builder());

    Ok(builder)
}

/// Wait for the endpoint to come online (relay/discovery ready) with a timeout.
async fn wait_online(endpoint: &Endpoint) -> Result<()> {
    info!(
        "Waiting for endpoint to come online (timeout: {}s)...",
        RELAY_CONNECT_TIMEOUT.as_secs()
    );
    match tokio::time::timeout(RELAY_CONNECT_TIMEOUT, endpoint.online()).await {
        Ok(()) => Ok(()),
        Err(_) => anyhow::bail!(
            "Endpoint failed to come online after {}s - check relay server connectivity",
            RELAY_CONNECT_TIMEOUT.as_secs()
        ),
    }
}

/// Create a server endpoint with a persistent identity and the fixed ALPN.
pub async fn create_server_endpoint(relay_urls: &[String], secret: SecretKey) -> Result<Endpoint> {
    let relay_mode = parse_relay_mode(relay_urls)?;
    let using_custom_relay = !matches!(relay_mode, RelayMode::Default);
    print_relay_status(relay_urls, using_custom_relay);

    let builder = create_endpoint_builder(relay_mode, Some(&secret))?
        .alpns(vec![ALPN.to_vec()])
        .secret_key(secret);

    let endpoint = builder
        .bind()
        .await
        .context("Failed to create iroh endpoint")?;

    wait_online(&endpoint).await?;
    Ok(endpoint)
}

/// Create a client endpoint (ephemeral identity).
pub async fn create_client_endpoint(relay_urls: &[String]) -> Result<Endpoint> {
    let relay_mode = parse_relay_mode(relay_urls)?;
    let using_custom_relay = !matches!(relay_mode, RelayMode::Default);
    print_relay_status(relay_urls, using_custom_relay);

    let builder = create_endpoint_builder(relay_mode, None)?;

    let endpoint = builder
        .bind()
        .await
        .context("Failed to create iroh endpoint")?;

    wait_online(&endpoint).await?;
    Ok(endpoint)
}

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
/// borrowed [`PathList`] so it can be stored and shown on demand (e.g. the
/// desktop's "connection path" CTA, mirroring `ezvpn client status`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnPath {
    pub kind: ConnPathKind,
    /// Human line like `Direct 1.2.3.4:52186 (rtt 1ms)` or
    /// `Relay https://… (rtt 42ms)`.
    pub display: String,
    /// Whether iroh currently routes traffic over this path.
    pub selected: bool,
}

/// Snapshot the current path(s) of a live connection for a status UI, showing
/// *all* paths (not just the selected one) so a direct path iroh has discovered
/// but not selected is still visible. [`Connection::paths`] is itself a
/// point-in-time snapshot, so this needs no background watcher.
pub fn connection_paths(conn: &Connection) -> Vec<ConnPath> {
    snapshot_paths(&conn.paths())
}

/// Convert a borrowed [`PathList`] snapshot into owned [`ConnPath`]s.
fn snapshot_paths(paths: &PathList<'_>) -> Vec<ConnPath> {
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
                debug!("Connection: {}", format_paths(&paths));
                last_key = Some(key);
            }
        }
    })))
}
