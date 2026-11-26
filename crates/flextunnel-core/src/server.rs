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
//! stop signal, then awaits [`RunningServer::close`] (an ungraceful drop
//! panics under panic=abort).

use crate::blocklist::BlockList;
use crate::flexaccess_iroh::endpoint::CreatedEndpoint;
use crate::flexaccess_iroh::relay::RelayProbes;
use crate::flexaccess_iroh::relay_failover::fail_over_home_relay;
use crate::lock::InstanceLock;
use crate::proxy::{ProxyServer, ProxyServerParams, RoutedSet};
use crate::secret::secret_to_endpoint_id;
use crate::transport::endpoint::{
    self, PendingCloses, RelayConfig, create_server_endpoint, server_setup,
};
use anyhow::{Context, Result};
use iroh::endpoint::Builder as EndpointBuilder;
use iroh::{Endpoint, EndpointId, SecretKey};
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
    /// Whether the custom relays serve QUIC address discovery (custom relays
    /// only); `None` keeps the default, on.
    pub relay_quic_addr_discovery: Option<bool>,
    /// Server-side host aliases, keys lowercased.
    pub host_aliases: HashMap<String, String>,
    /// The tunnel set; may be empty (the server's own loopback and status
    /// page are reachable regardless).
    pub routed_domains: Vec<String>,
    pub routed_cidrs: Vec<String>,
    /// The duplicate-id blocklist (always
    /// [`crate::blocklist::default_blocklist_path`] outside tests).
    pub blocklist_file: PathBuf,
}

/// How much of the server's own EndpointId keys its lock file. 16 hex chars
/// (64 bits) cannot collide by accident between distinct identities.
const LOCK_KEY_LEN: usize = 16;

/// The per-identity server lock path
/// (`~/.config/flextunnel/server-<id prefix>.lock`).
///
/// There is deliberately no temp-dir fallback: if the home dir is unavailable
/// the server fails fast rather than silently narrowing the guarantee to a
/// fallback lock that a second process could sidestep.
fn server_lock_path(own_id: &EndpointId) -> Option<PathBuf> {
    let key = &own_id.to_string()[..LOCK_KEY_LEN];
    dirs::home_dir().map(|home| {
        home.join(".config")
            .join("flextunnel")
            .join(format!("server-{key}.lock"))
    })
}

/// Acquire the single-instance lock for the server identity `own_id`: one
/// flextunnel server per identity per user, whichever front-end runs it (a CLI
/// server and the desktop app's server contend for it when they share an
/// identity, and run side by side when they don't). Hold it for as long as the
/// server runs.
pub fn acquire_server_lock(own_id: &EndpointId) -> Result<InstanceLock> {
    let path = server_lock_path(own_id).context(
        "Could not determine the home directory, so the single-instance lock \
         (~/.config/flextunnel/server-<id>.lock) cannot be enforced",
    )?;
    InstanceLock::acquire(
        &path,
        &format!(
            "Another flextunnel server with this identity ({own_id}) is already \
             running for this user. Only one server per identity is allowed."
        ),
    )
}

/// A validated server, not yet bound to an endpoint.
pub struct PreparedServer {
    own_id: EndpointId,
    secret_key: SecretKey,
    server: Arc<ProxyServer>,
    relay_config: RelayConfig,
    /// Quick mode: the one entered client id, enforced natively at the TLS
    /// handshake. Empty otherwise — the quick ALPN is then disabled.
    quick_clients: HashSet<EndpointId>,
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
        relay_quic_addr_discovery,
        host_aliases,
        routed_domains,
        routed_cidrs,
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

    // The tunnel set may be empty: a client reaches the server's own loopback
    // and its status page regardless of it.
    let routed_set = RoutedSet::new(&routed_domains, &routed_cidrs)
        .context("Invalid routed-set configuration")?;

    let relay_config =
        endpoint::relay_config(&relay_urls, relay_auth_token, relay_quic_addr_discovery)
            .context("Invalid relay configuration")?;

    if !host_aliases.is_empty() {
        log::info!("Loaded {} host alias(es)", host_aliases.len());
    }
    log::info!(
        "Tunnel set: {} domain rule(s), {} CIDR(s) — off-list tunnel requests are rejected",
        routed_domains.len(),
        routed_cidrs.len()
    );
    let server = ProxyServer::new(ProxyServerParams {
        own_id,
        authorized_keys,
        host_aliases,
        routed_set,
        routed_domains,
        routed_cidrs,
        blocklist,
        first_client,
    });
    Ok(PreparedServer {
        own_id,
        secret_key,
        server,
        relay_config,
        quick_clients: quick_client.into_iter().collect(),
    })
}

impl PreparedServer {
    /// The endpoint id clients connect to.
    pub fn own_id(&self) -> EndpointId {
        self.own_id
    }

    /// This server's endpoint, built on `base`: its identity, the ALPNs and
    /// the quick-client allowlist. The only place the prepared identity and
    /// allowlist reach an endpoint, whichever way it is bound.
    fn endpoint_on(&self, base: EndpointBuilder) -> EndpointBuilder {
        server_setup(base, self.secret_key.clone(), self.quick_clients.clone())
    }

    /// Bind the iroh endpoint (with every configured relay; the startup probe
    /// runs beside it and takes out the relays that fail). Can take several
    /// seconds (the relay online-wait).
    pub async fn bind(self) -> Result<RunningServer> {
        let closes = PendingCloses::new();
        let CreatedEndpoint { endpoint, relays } =
            create_server_endpoint(&self.relay_config, &closes, |base| self.endpoint_on(base))
                .await
                .context("Failed to create iroh endpoint")?;
        log::info!("flextunnel server Node ID: {}", endpoint.id());
        Ok(RunningServer {
            endpoint,
            server: self.server,
            relay_config: self.relay_config,
            relays: Some(relays),
            closes,
        })
    }

    /// [`bind`](Self::bind) on a caller-built base instead of the relay
    /// setup, which needs a network (hermetic loopback tests). Like `bind`,
    /// the endpoint is [`endpoint_on`](Self::endpoint_on) that base.
    #[cfg(test)]
    pub(crate) async fn bind_with(self, base: EndpointBuilder) -> RunningServer {
        let endpoint = self
            .endpoint_on(base)
            .bind()
            .await
            .expect("bind the test endpoint");
        RunningServer {
            endpoint,
            server: self.server,
            relay_config: self.relay_config,
            relays: None,
            closes: PendingCloses::new(),
        }
    }
}

/// A bound server, ready to [`serve`](Self::serve).
pub struct RunningServer {
    endpoint: Endpoint,
    server: Arc<ProxyServer>,
    relay_config: RelayConfig,
    /// The startup relay probe the failover waits for and restores from;
    /// `None` on a test endpoint bound without the relay setup, which runs no
    /// failover.
    relays: Option<RelayProbes>,
    /// The startup probe's task and endpoints, which may outlast the bind,
    /// and any close the bind stopped waiting for: drained by [`Self::close`].
    closes: PendingCloses,
}

impl RunningServer {
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// The authorized keys of the clients connected right now (see
    /// [`ProxyServer::connected_client_keys`]).
    pub fn connected_client_keys(&self) -> Vec<String> {
        self.server.connected_client_keys()
    }

    /// Serve until the server ends. Alongside, with custom relays, the shared
    /// home-relay failover keeps the server dialable: a custom-relay server is
    /// reachable from off the LAN only through its home relay (n0 discovery is
    /// off, clients dial by relay hint), and if that relay is lost for a minute
    /// without iroh re-homing on its own, the failover moves the endpoint onto
    /// another configured relay in place (a single custom relay has none to
    /// move to). Nothing is torn down: the identity, the quick-client
    /// allowlist, the direct paths and the established connections all stay.
    /// Relays the startup probe could not connect (taken out of the relay map)
    /// are put back by the same failover once they are. With the default
    /// relays the failover future is pending forever.
    ///
    /// Cancel-safe: drop the future to stop serving, then await
    /// [`close`](Self::close).
    pub async fn serve(&self) -> Result<()> {
        tokio::select! {
            res = Arc::clone(&self.server).run(&self.endpoint) => {
                res.map_err(|e| anyhow::anyhow!("Server error: {e}"))
            }
            () = self.fail_over() => Ok(()),
        }
    }

    /// Close the endpoint gracefully, then wait for what its startup left
    /// running: the relay probe, whose probe endpoints are still open for up
    /// to [`RELAY_CONNECT_TIMEOUT`] after the start when a relay does not
    /// answer (the endpoint's close stops the probe, which closes them), and
    /// any close the bind stopped waiting for. A process or runtime that
    /// ended sooner would drop them without `close()`. Neither close has a
    /// deadline of its own: the caller bounds the whole.
    ///
    /// [`RELAY_CONNECT_TIMEOUT`]: crate::flexaccess_iroh::relay::RELAY_CONNECT_TIMEOUT
    pub async fn close(&self) {
        self.endpoint.close().await;
        self.closes.finished().await;
    }

    /// The home-relay failover, pending forever without a startup probe.
    async fn fail_over(&self) {
        match &self.relays {
            Some(relays) => fail_over_home_relay(&self.endpoint, &self.relay_config, relays).await,
            None => std::future::pending().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            relay_quic_addr_discovery: None,
            host_aliases: HashMap::new(),
            routed_domains: vec!["*".into()],
            routed_cidrs: Vec::new(),
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
        assert!(
            err.to_string().contains("authorized client public key"),
            "{err}"
        );

        let mut quick = options(dir.path());
        quick.authorized_keys = Default::default();
        quick.quick_client = Some(SecretKey::generate().public());
        assert!(prepare(quick).is_ok(), "quick mode needs no client keys");
    }

    #[test]
    fn prepare_accepts_an_empty_tunnel_set() {
        let dir = tempfile::tempdir().unwrap();
        let mut opts = options(dir.path());
        opts.routed_domains.clear();
        assert!(
            prepare(opts).is_ok(),
            "loopback and status need no routed set"
        );
    }

    /// One custom relay is reduced-redundancy mode (no failover), not an error.
    #[test]
    fn prepare_accepts_a_single_custom_relay() {
        let dir = tempfile::tempdir().unwrap();
        let mut opts = options(dir.path());
        opts.relay_urls = vec!["https://only.example".into()];
        let prepared = prepare(opts).unwrap();
        assert_eq!(prepared.relay_config.custom_urls().len(), 1);
        assert_eq!(prepared.relay_config.quic_addr_discovery(), Some(true));
    }

    /// QUIC address discovery follows the option for custom relays, and the
    /// option is refused with the default relays, which keep iroh's own.
    #[test]
    fn prepare_takes_the_relay_quic_addr_discovery_setting() {
        let dir = tempfile::tempdir().unwrap();
        let mut off = options(dir.path());
        off.relay_urls = vec!["https://only.example".into()];
        off.relay_quic_addr_discovery = Some(false);
        let prepared = prepare(off).unwrap();
        assert_eq!(prepared.relay_config.quic_addr_discovery(), Some(false));

        let mut stray = options(dir.path());
        stray.relay_quic_addr_discovery = Some(false);
        let err = prepare(stray).err().expect("default relays");
        assert!(format!("{err:#}").contains("relay_urls"), "{err:#}");
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

    #[test]
    fn server_lock_is_keyed_by_identity() {
        let a = SecretKey::generate().public();
        let b = SecretKey::generate().public();
        let path_a = server_lock_path(&a).unwrap();
        assert_eq!(path_a, server_lock_path(&a).unwrap());
        assert_ne!(path_a, server_lock_path(&b).unwrap());
        let name = path_a.file_name().unwrap().to_str().unwrap();
        assert_eq!(
            name,
            format!("server-{}.lock", &a.to_string()[..LOCK_KEY_LEN])
        );
    }
}
