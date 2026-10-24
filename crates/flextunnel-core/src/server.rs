//! Server startup shared by every front-end that runs a flextunnel server —
//! the CLI's `server start` and the desktop app's built-in server — so both
//! validate and bind identically. Inputs arrive in memory ([`ServerOptions`]):
//! loading the identity key and the authorized-keys document from files is the
//! CLI's business, the desktop keeps them in its own store.
//!
//! Startup is split in three so a GUI can react between the steps:
//! [`prepare`] runs every check that needs no network (fails fast, binds
//! nothing), [`PreparedServer::bind`] creates the iroh endpoint (may take a
//! while — the relay online-wait), and [`RunningServer::serve`] runs until the
//! server ends. The caller owns shutdown: it races `serve` against its own
//! stop signal, then closes [`RunningServer::endpoint`] gracefully (an
//! ungraceful drop panics under panic=abort).

use crate::blocklist::BlockList;
use crate::config::BridgeConfig;
use crate::flexaccess_iroh::endpoint::CreatedEndpoint;
use crate::flexaccess_iroh::relay_failover::fail_over_home_relay;
use crate::lock::InstanceLock;
use crate::proxy::{
    BridgeUpstream, BridgeUpstreamConfig, DnsForwarder, ProxyServer, ProxyServerParams, RoutedSet,
};
use crate::secret::secret_to_endpoint_id;
use crate::transport::endpoint::{EndpointAllowlists, RelayConfig, create_server_endpoint};
use anyhow::{Context, Result};
use iroh::{Endpoint, EndpointId, RelayUrl, SecretKey};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Notify;

/// Everything a server needs, already loaded into memory.
pub struct ServerOptions {
    /// The server's persistent identity (or quick mode's ephemeral one).
    pub secret_key: SecretKey,
    /// Authorized client public keys. Required (non-empty) unless
    /// `quick_client` is set.
    pub authorized_keys: crate::auth::AuthorizedKeys,
    /// Quick mode: the single client endpoint id allowed over the quick ALPN —
    /// its whole credential (no client keys).
    pub quick_client: Option<EndpointId>,
    /// Fired on the first client connection (quick mode's idle-exit timer).
    pub first_client: Option<Arc<Notify>>,
    pub relay_urls: Vec<String>,
    /// Shared bearer token for custom relays (custom relays only).
    pub relay_auth_token: Option<String>,
    /// Server-side host aliases, keys lowercased.
    pub host_aliases: HashMap<String, String>,
    /// The tunnel set; the combined set must be non-empty.
    pub routed_domains: Vec<String>,
    pub routed_cidrs: Vec<String>,
    /// Conditional DNS-forwarding rules, suffix keys lowercased.
    pub dns_forwards: HashMap<String, Vec<String>>,
    /// Outbound bridge routes keyed by their friendly label.
    pub bridges: HashMap<String, BridgeConfig>,
    /// Endpoint ids allowed to bridge into this server.
    pub allowed_bridge_servers: Vec<String>,
    /// The duplicate-id blocklist (always
    /// [`crate::blocklist::default_blocklist_path`] outside tests).
    pub blocklist_file: PathBuf,
}

/// The per-user server lock path (`~/.config/flextunnel/server.lock`).
///
/// There is deliberately no temp-dir fallback: if the home dir is unavailable
/// the server fails fast rather than silently narrowing the guarantee to a
/// fallback lock that a second process could sidestep.
fn server_lock_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".config").join("flextunnel").join("server.lock"))
}

/// Acquire the per-user single-instance server lock: one flextunnel server
/// per user, whichever front-end runs it (a CLI server and a desktop server
/// profile contend for the same lock). Hold it for as long as the server runs.
pub fn acquire_server_lock() -> Result<InstanceLock> {
    let path = server_lock_path().context(
        "Could not determine the home directory, so the single-instance lock \
         (~/.config/flextunnel/server.lock) cannot be enforced",
    )?;
    InstanceLock::acquire(
        &path,
        "Another flextunnel server is already running for this user. \
         Only one server per user is allowed.",
    )
}

/// Reject any conditional DNS-forwarding suffix the routed set does not cover.
/// Such a forward is dead config: the server rejects off-list targets before
/// resolution, so a suffix no routed rule reaches would never fire.
fn validate_dns_forwards_coverage(forwarder: &DnsForwarder, routed_set: &RoutedSet) -> Result<()> {
    for suffix in forwarder.suffixes() {
        if !routed_set.covers_suffix(suffix) {
            anyhow::bail!(
                "[dns_forwards] suffix {suffix:?} is not covered by the routed set, so it \
                 would never be used: the server rejects off-list targets before resolving \
                 them. Add \"*.{suffix}\" (and/or \"{suffix}\") to routed_domains, or remove \
                 the forward."
            );
        }
    }
    Ok(())
}

/// A validated server, not yet bound to an endpoint.
pub struct PreparedServer {
    own_id: EndpointId,
    secret_key: SecretKey,
    server: Arc<ProxyServer>,
    relay_config: RelayConfig,
    allowlists: EndpointAllowlists,
}

/// Validate `opts` and build the server — everything short of binding the
/// endpoint, so a bad config fails before any network work.
pub fn prepare(opts: ServerOptions) -> Result<PreparedServer> {
    let ServerOptions {
        secret_key,
        authorized_keys,
        quick_client,
        first_client,
        relay_urls,
        relay_auth_token,
        host_aliases,
        routed_domains,
        routed_cidrs,
        dns_forwards,
        bridges: bridge_configs,
        allowed_bridge_servers,
        blocklist_file,
    } = opts;

    // A quick server runs without client keys: its single allowlisted client
    // id is the whole credential set (enforced natively by the endpoint's hook).
    if authorized_keys.is_empty() && quick_client.is_none() {
        anyhow::bail!(
            "The server requires at least one authorized client public key.\n\
             Each client generates a keypair with: flexaccess-keys generate-auth-key -o <FILE>\n\
             Put each key's authorized-key entry (one `ed25519-pub:...` per line, from \
             `flexaccess-keys show-auth-key --private-key-file <FILE>`) in the server's \
             authorized keys."
        );
    }
    match &quick_client {
        Some(id) => log::info!(
            "Quick mode: client {id} allowlisted (endpoint-id credential; no client keys)"
        ),
        None => log::info!("Loaded {} authorized client key(s)", authorized_keys.len()),
    }

    let own_id = secret_to_endpoint_id(&secret_key);

    // Load the duplicate-id blocklist and refuse to start if this server's own id
    // is recorded as a conflict (duplicate-server self-block guard). Done before
    // creating the endpoint so a self-blocked identity never binds.
    let blocklist = BlockList::load(blocklist_file.clone())
        .with_context(|| format!("Failed to load blocklist {}", blocklist_file.display()))?;
    if blocklist.is_server_conflicted(&own_id.to_string()) {
        anyhow::bail!(
            "Refusing to start: server id {own_id} is recorded as a duplicate-id conflict in \
             {}.\nAnother server was detected sharing this identity. Stop the other server, \
             then remove the entry from the blocklist to start again.",
            blocklist_file.display()
        );
    }

    let routed_set = RoutedSet::new(&routed_domains, &routed_cidrs)
        .context("Invalid routed-set configuration")?;
    // The tunnel set is required (VPN-style split tunnel): decide explicitly what
    // is routed through the tunnel. Use "*" (and 0.0.0.0/0, ::/0) for full tunnel.
    if routed_set.is_empty() {
        anyhow::bail!(
            "a tunnel set is required: configure routed_domains / routed_cidrs \
             (use \"*\" plus 0.0.0.0/0 and ::/0 to tunnel all traffic)"
        );
    }

    let dns_forwarder = DnsForwarder::new(&dns_forwards)
        .context("Invalid dns_forwards configuration")?;
    if let Some(forwarder) = &dns_forwarder {
        validate_dns_forwards_coverage(forwarder, &routed_set)?;
    }

    // Inbound bridging: parse the allowlist — the sole bridge credential,
    // enforced natively at the TLS handshake by the endpoint's allowlist hook.
    let allowed_bridge_servers = allowed_bridge_servers
        .iter()
        .map(|raw| {
            raw.parse::<EndpointId>()
                .map_err(|e| anyhow::anyhow!("invalid allowed_bridge_servers entry {raw:?}: {e}"))
        })
        .collect::<Result<HashSet<_>>>()?;
    if allowed_bridge_servers.contains(&own_id) {
        anyhow::bail!(
            "allowed_bridge_servers contains this server's own id ({own_id}); a server \
             cannot bridge to itself — this is likely a copy-paste mistake"
        );
    }
    if !allowed_bridge_servers.is_empty() {
        log::info!(
            "Inbound bridging enabled for {} server(s)",
            allowed_bridge_servers.len()
        );
    }

    // Resolve the relay config once. Its URLs are installed on the endpoint and
    // also attached as address hints when outbound bridges dial peer servers.
    // The relay auth token remains endpoint-level state in the relay map.
    let relay_config = RelayConfig::from_urls_with_token(&relay_urls, relay_auth_token)
        .context("Invalid relay configuration")?;

    // Outbound bridges: resolve each `[bridges.<name>]` entry (endpoint id,
    // rules) and reject rules the routed set never reaches — the server
    // rejects off-list targets before bridge routing, so such a rule is dead
    // config (same reasoning as the dns_forwards coverage check above).
    let mut bridges = Vec::with_capacity(bridge_configs.len());
    for (name, b) in &bridge_configs {
        let endpoint_id = b.endpoint_id.parse::<EndpointId>().map_err(|e| {
            anyhow::anyhow!("bridge '{name}' has an invalid endpoint_id {:?}: {e}", b.endpoint_id)
        })?;
        if endpoint_id == own_id {
            anyhow::bail!("bridge '{name}' targets this server itself ({own_id})");
        }
        let bridge_routed_set = RoutedSet::new(&b.domains, &b.cidrs)
            .with_context(|| format!("bridge '{name}' has invalid route rules"))?;
        routed_set
            .validate_rules_reachable(&b.domains, &b.cidrs)
            .with_context(|| {
                format!(
                    "bridge '{name}' has a rule the routed set never reaches, so it would \
                     never be used: the server rejects off-list targets before bridge \
                     routing. Add matching routed_domains/routed_cidrs, or remove the rule"
                )
            })?;
        bridges.push(BridgeUpstream::new(BridgeUpstreamConfig {
            name: name.clone(),
            endpoint_id,
            relay_urls: relay_config.custom_urls().to_vec(),
            routed_set: bridge_routed_set,
            domains: b.domains.clone(),
            cidrs: b.cidrs.clone(),
        }));
    }
    if !bridges.is_empty() {
        log::info!("Loaded {} bridge route(s)", bridges.len());
    }

    let allowlists = EndpointAllowlists {
        bridge_servers: allowed_bridge_servers.clone(),
        // Quick mode: the one entered client id, enforced natively at the TLS
        // handshake. Empty otherwise — the quick ALPN is then disabled.
        quick_clients: quick_client.into_iter().collect(),
    };

    if !host_aliases.is_empty() {
        log::info!("Loaded {} host alias(es)", host_aliases.len());
    }
    if !dns_forwards.is_empty() {
        log::info!(
            "Loaded {} conditional DNS-forwarding rule(s)",
            dns_forwards.len()
        );
    }
    log::info!(
        "Tunnel set: {} domain rule(s), {} CIDR(s) — off-list tunnel requests are rejected; pushed to clients on connect",
        routed_domains.len(),
        routed_cidrs.len()
    );
    let server = ProxyServer::new(ProxyServerParams {
        own_id,
        authorized_keys,
        allowed_bridge_servers,
        host_aliases,
        routed_set,
        routed_domains,
        routed_cidrs,
        dns_forwarder,
        bridges,
        blocklist,
        first_client,
    });
    Ok(PreparedServer {
        own_id,
        secret_key,
        server,
        relay_config,
        allowlists,
    })
}

impl PreparedServer {
    /// The endpoint id clients connect to.
    pub fn own_id(&self) -> EndpointId {
        self.own_id
    }

    /// Bind the iroh endpoint (with the relays that pass the startup probe).
    /// Can take several seconds (the relay online-wait).
    pub async fn bind(self) -> Result<RunningServer> {
        let CreatedEndpoint { endpoint, relays_left_out } =
            create_server_endpoint(&self.relay_config, self.secret_key, self.allowlists)
                .await
                .context("Failed to create iroh endpoint")?;
        log::info!("flextunnel server Node ID: {}", endpoint.id());
        Ok(RunningServer {
            endpoint,
            server: self.server,
            relay_config: self.relay_config,
            relays_left_out,
        })
    }

    /// Serve on a caller-built endpoint (hermetic loopback tests).
    #[cfg(test)]
    pub(crate) fn bind_on(self, endpoint: Endpoint) -> RunningServer {
        RunningServer {
            endpoint,
            server: self.server,
            relay_config: self.relay_config,
            relays_left_out: Vec::new(),
        }
    }
}

/// A bound server, ready to [`serve`](Self::serve).
pub struct RunningServer {
    endpoint: Endpoint,
    server: Arc<ProxyServer>,
    relay_config: RelayConfig,
    relays_left_out: Vec<RelayUrl>,
}

impl RunningServer {
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Serve until the server ends. Alongside, with custom relays, the shared
    /// home-relay failover keeps the server dialable: a custom-relay server is
    /// reachable from off the LAN only through its home relay (n0 discovery is
    /// off, clients dial by relay hint), and if that relay is lost for a minute
    /// without iroh re-homing on its own, the failover moves the endpoint onto
    /// another configured relay in place. Nothing is torn down: the identity,
    /// the allowlists, the direct paths, the established connections and the
    /// bridge tasks all stay. Relays the startup probe could not connect (the
    /// endpoint was bound without them) are put back by the same failover once
    /// they are. With the default relays the failover future is pending
    /// forever.
    ///
    /// Cancel-safe: drop the future to stop serving, then close
    /// [`endpoint`](Self::endpoint).
    pub async fn serve(&self) -> Result<()> {
        tokio::select! {
            res = Arc::clone(&self.server).run(&self.endpoint) => {
                res.map_err(|e| anyhow::anyhow!("Server error: {e}"))
            }
            () = fail_over_home_relay(&self.endpoint, &self.relay_config, &self.relays_left_out) => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn forwarder(suffix: &str) -> DnsForwarder {
        let mut m = HashMap::new();
        m.insert(suffix.to_string(), vec!["10.0.0.53".to_string()]);
        DnsForwarder::new(&m).unwrap().expect("one forward configured")
    }

    fn routed(domains: &[&str]) -> RoutedSet {
        let d: Vec<String> = domains.iter().map(|s| s.to_string()).collect();
        RoutedSet::new(&d, &[]).unwrap()
    }

    #[test]
    fn dns_forwards_coverage_accepts_covered_suffix() {
        let f = forwarder("local.168234.xyz");
        // A wildcard whose zone reaches the suffix makes the forward live.
        assert!(validate_dns_forwards_coverage(&f, &routed(&["*.local.168234.xyz"])).is_ok());
        assert!(validate_dns_forwards_coverage(&f, &routed(&["*"])).is_ok());
    }

    #[test]
    fn dns_forwards_coverage_rejects_uncovered_suffix() {
        let f = forwarder("local.168234.xyz");
        let err = validate_dns_forwards_coverage(&f, &routed(&["*.example.com"])).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("local.168234.xyz"), "{msg}");
        assert!(msg.contains("not covered"), "{msg}");
    }

    fn options(dir: &std::path::Path) -> ServerOptions {
        let client = crate::auth::ClientKey::generate().unwrap();
        ServerOptions {
            secret_key: SecretKey::generate(),
            authorized_keys: flexaccess_keys::parse_authorized_key_entries(
                &[client.public_str()],
                "test",
            )
            .unwrap(),
            quick_client: None,
            first_client: None,
            relay_urls: Vec::new(),
            relay_auth_token: None,
            host_aliases: HashMap::new(),
            routed_domains: vec!["*".into()],
            routed_cidrs: Vec::new(),
            dns_forwards: HashMap::new(),
            bridges: HashMap::new(),
            allowed_bridge_servers: Vec::new(),
            blocklist_file: dir.join("blocklist.json"),
        }
    }

    #[test]
    fn prepare_accepts_a_minimal_server() {
        let dir = tempfile::tempdir().unwrap();
        let opts = options(dir.path());
        let expected = secret_to_endpoint_id(&opts.secret_key);
        let prepared = prepare(opts).unwrap();
        assert_eq!(prepared.own_id(), expected);
    }

    #[test]
    fn prepare_requires_client_keys_unless_quick() {
        let dir = tempfile::tempdir().unwrap();
        let mut opts = options(dir.path());
        opts.authorized_keys = Default::default();
        let err = prepare(opts).err().expect("no client keys");
        assert!(err.to_string().contains("authorized client public key"), "{err}");

        let mut quick = options(dir.path());
        quick.authorized_keys = Default::default();
        quick.quick_client = Some(SecretKey::generate().public());
        assert!(prepare(quick).is_ok(), "quick mode needs no client keys");
    }

    #[test]
    fn prepare_requires_a_tunnel_set() {
        let dir = tempfile::tempdir().unwrap();
        let mut opts = options(dir.path());
        opts.routed_domains.clear();
        let err = prepare(opts).err().expect("empty tunnel set");
        assert!(err.to_string().contains("tunnel set is required"), "{err}");
    }

    #[test]
    fn prepare_rejects_a_self_bridge_allowlist() {
        let dir = tempfile::tempdir().unwrap();
        let mut opts = options(dir.path());
        opts.allowed_bridge_servers = vec![secret_to_endpoint_id(&opts.secret_key).to_string()];
        let err = prepare(opts).err().expect("own id allowlisted");
        assert!(err.to_string().contains("own id"), "{err}");
    }

    #[test]
    fn prepare_refuses_a_blocklisted_identity() {
        let dir = tempfile::tempdir().unwrap();
        let opts = options(dir.path());
        let own_id = secret_to_endpoint_id(&opts.secret_key).to_string();
        let mut blocklist = BlockList::load(opts.blocklist_file.clone()).unwrap();
        blocklist.add_conflicted_server(&own_id, "test");
        crate::blocklist::write_atomic(&opts.blocklist_file, &blocklist.to_json().unwrap())
            .unwrap();
        let err = prepare(opts).err().expect("self-blocked id");
        assert!(err.to_string().contains("Refusing to start"), "{err}");
    }
}
