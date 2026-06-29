//! Common endpoint helpers for iroh proxy connections.

use crate::proxy::signaling;
use crate::transport::build_quic_transport_config;
use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use iroh::{
    Endpoint, EndpointId, RelayMap, RelayMode, RelayUrl, SecretKey,
    address_lookup::{DnsAddressLookup, PkarrPublisher, PkarrResolver},
    endpoint::{Builder as EndpointBuilder, presets},
};
use iroh_mdns_address_lookup::MdnsAddressLookup;
use log::info;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
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
            // Default n0 DNS
            builder = builder
                .address_lookup(PkarrPublisher::n0_dns())
                .address_lookup(DnsAddressLookup::n0_dns());
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
        .alpns(vec![signaling::ALPN.to_vec()])
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
