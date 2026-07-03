//! Common endpoint helpers for iroh proxy connections.

use crate::transport::{ALPN, build_quic_transport_config};
use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use iroh::{
    Endpoint, EndpointId, RelayMap, RelayMode, RelayUrl, SecretKey, TransportAddr,
    address_lookup::{DnsAddressLookup, PkarrPublisher, PkarrResolver},
    endpoint::{Builder as EndpointBuilder, Connection, PathList, presets},
};
use iroh_mdns_address_lookup::MdnsAddressLookup;
use log::info;
use n0_future::StreamExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use url::Url;

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
fn create_endpoint_builder(
    relay_mode: RelayMode,
    dns_server: Option<&str>,
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

    // DNS-based peer discovery (can be disabled via dns_server="none")
    match dns_server {
        Some("none") => {
            info!("DNS discovery disabled (dns_server=none)");
        }
        Some(dns_url) => {
            // Custom DNS server with publishing and resolving via HTTP (pkarr)
            let pkarr_url: Url = dns_url.parse().context("Invalid DNS server URL")?;
            if secret_key.is_some() {
                info!("Using custom DNS server: {}", dns_url);
                builder = builder
                    .address_lookup(PkarrPublisher::builder(pkarr_url.clone()))
                    .address_lookup(PkarrResolver::builder(pkarr_url));
            } else {
                // Custom DNS server, resolve only via HTTP (no secret = can't publish)
                info!("Using custom DNS server (resolve only): {}", dns_url);
                builder = builder.address_lookup(PkarrResolver::builder(pkarr_url));
            }
        }
        None => {
            // Default n0 DNS: always resolve, but only publish when we have a
            // persistent identity. An ephemeral client (no secret) shouldn't
            // advertise its endpoint — mirrors the custom-DNS branch above.
            if secret_key.is_some() {
                builder = builder.address_lookup(PkarrPublisher::n0_dns());
            }
            builder = builder.address_lookup(DnsAddressLookup::n0_dns());
        }
    }
    // mDNS always enabled for local network discovery
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
pub async fn create_server_endpoint(
    relay_urls: &[String],
    secret: SecretKey,
    dns_server: Option<&str>,
) -> Result<Endpoint> {
    let relay_mode = parse_relay_mode(relay_urls)?;
    let using_custom_relay = !matches!(relay_mode, RelayMode::Default);
    print_relay_status(relay_urls, using_custom_relay);

    let builder = create_endpoint_builder(relay_mode, dns_server, Some(&secret))?
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
pub async fn create_client_endpoint(
    relay_urls: &[String],
    dns_server: Option<&str>,
) -> Result<Endpoint> {
    let relay_mode = parse_relay_mode(relay_urls)?;
    let using_custom_relay = !matches!(relay_mode, RelayMode::Default);
    print_relay_status(relay_urls, using_custom_relay);

    let builder = create_endpoint_builder(relay_mode, dns_server, None)?;

    let endpoint = builder
        .bind()
        .await
        .context("Failed to create iroh endpoint")?;

    wait_online(&endpoint).await?;
    Ok(endpoint)
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
pub struct PathWatcherGuard(JoinHandle<()>);

impl Drop for PathWatcherGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Log the connection's selected path and spawn a background task that logs
/// updates whenever the active path changes (e.g. relay -> direct).
///
/// The returned [`PathWatcherGuard`] aborts the background task when dropped;
/// callers must keep it alive for the duration of the connection.
pub fn watch_connection_paths(conn: &Connection) -> PathWatcherGuard {
    let conn = conn.clone();
    PathWatcherGuard(tokio::spawn(async move {
        // The stream yields the current snapshot on the first poll, then a
        // fresh snapshot whenever the open or selected paths change; it ends
        // when the connection closes.
        let mut stream = conn.paths_stream();
        let mut last_key = None;
        while let Some(paths) = stream.next().await {
            let key = paths_key(&paths);
            if last_key.as_ref() != Some(&key) {
                info!("Connection: {}", format_paths(&paths));
                last_key = Some(key);
            }
        }
    }))
}
