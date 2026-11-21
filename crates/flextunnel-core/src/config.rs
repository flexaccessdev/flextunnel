//! TOML configuration files for the server and client.
//!
//! Both roles can be configured from a TOML file (`-c <FILE>` or
//! `--default-config` → `~/.config/flextunnel/{server,client}.toml`). CLI flags
//! always override file values; the file overrides built-in defaults. Unknown
//! keys are rejected (`deny_unknown_fields`) so typos fail loudly.
//!
//! The schema is flat: flextunnel has a single transport and the `server`/
//! `client` subcommands already determine the role, so there is no `[iroh]`
//! table or `role`/`mode` key.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Server config file schema. Every field is optional; CLI flags override these.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Path to the server's secret-key file (persistent identity). The only way
    /// to configure the key — there is no inline variant (quick mode's
    /// ephemeral identity never touches the config).
    pub secret_file: Option<PathBuf>,
    /// File of authorized client public keys (ssh-`authorized_keys` style: one
    /// `ed25519-pub:...` per line, optional trailing comment). Always a
    /// file — there is no inline list.
    pub authorized_keys_file: Option<PathBuf>,
    /// Custom relay URL(s) for failover.
    pub relay_urls: Option<Vec<String>>,
    /// Shared bearer token sent to every custom relay's WebSocket upgrade. Only
    /// valid with custom `relay_urls`; rejected with the default iroh relays.
    pub relay_auth_token: Option<String>,
    /// Hostname aliases resolved on the server side: a requested host that
    /// matches a key is rewritten to its value (an IP or another hostname on the
    /// server's network) before connecting. Keeps the requested port. Lets a
    /// client reach the server's loopback or internal hosts via a real name
    /// (e.g. `server.internal` → `127.0.0.1`), which also dodges Firefox's refusal
    /// to proxy literal `localhost`/`127.0.0.1`. A key is an exact host or a
    /// `*.suffix` wildcard (subdomains only), the same syntax as `routed_domains`;
    /// an exact key beats a wildcard and the most specific wildcard wins.
    pub host_aliases: Option<HashMap<String, String>>,
    /// Domains routed through the tunnel (the tunnel set). Exact (`example.com`),
    /// wildcard (`*.example.com`, subdomains only), or `*` to match every host
    /// (full tunnel). Optional — a client always reaches the server's own
    /// loopback (under the destination name it gives this server) and its
    /// status page, routed set or not. A target off this list is rejected;
    /// clients route by their own per-destination lists, so list here whatever
    /// they are meant to send. Keep in sync with `routed_cidrs`.
    pub routed_domains: Option<Vec<String>>,
    /// CIDRs / bare IPs routed through the tunnel (matched against IP targets).
    /// A default route (`0.0.0.0/0` / `::/0`) matches every IP. See
    /// `routed_domains`.
    pub routed_cidrs: Option<Vec<String>>,
    /// Conditional DNS forwarding (split-DNS), server-side. Each key is a bare
    /// domain suffix and each value a list of DNS servers (`IP` or `IP:port`,
    /// default port 53). A tunneled hostname that equals or is a subdomain of a
    /// key is resolved via that key's upstream server(s) instead of the server's
    /// system resolver; everything else uses the system resolver. Keys are
    /// matched most-specific-first. See [`crate::proxy::DnsForwarder`].
    pub dns_forwards: Option<HashMap<String, Vec<String>>>,
}

/// One `[[forwards]]` entry in the client config: a port forward
/// `localhost:local_port` → `remote_host:remote_port`, opened through the
/// destination that routes `remote_host` (that destination's server enforces
/// its routed set and resolves names). Config-file only — the CLI client's
/// forwards are declared here and nowhere else; the control panel only shows
/// them. Validated at startup (nonzero ports, valid host, unique local ports,
/// a destination that routes the host), like the rest of the config.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardConfig {
    /// Optional display label; the status rows show `remote_host:remote_port`
    /// when it is empty.
    #[serde(default)]
    pub label: String,
    /// Loopback port to listen on (binds `127.0.0.1`/`::1` only).
    pub local_port: u16,
    /// Host to connect to: a destination's own host (that server's loopback),
    /// or an IP literal or name on a destination's routed list, which its
    /// server resolves (host aliases apply). A host no destination routes is
    /// a startup error — a forward never connects directly.
    pub remote_host: String,
    pub remote_port: u16,
}

/// One `[[destinations]]` entry in the client config: a host name and the
/// server it stands for. Config-file only.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationEntry {
    /// The destination's name. `host:<port>` through the client reaches that
    /// port on the server's own loopback. Any host name that is not an IP
    /// address, `localhost`, or under `flextunnel.internal`.
    pub host: String,
    /// EndpointId of the server (from `flextunnel show-iroh-id`).
    pub server_node_id: String,
    /// Further domains sent through this server — an exact name, a
    /// `*.suffix` wildcard (subdomains only), or `*` for every hostname. The
    /// server must route them too (its own `routed_domains`).
    #[serde(default)]
    pub routed_domains: Vec<String>,
    /// Further networks or bare IPs sent through this server. The server must
    /// route them too (its own `routed_cidrs`).
    #[serde(default)]
    pub routed_cidrs: Vec<String>,
    /// Client key file for this destination, overriding the top-level
    /// `auth_key_file`.
    pub auth_key_file: Option<PathBuf>,
    /// Custom relay URL(s) for this destination, overriding the top-level
    /// `relay_urls` — and with them the top-level `relay_auth_token`: a
    /// destination that names its own relays uses only its own token.
    pub relay_urls: Option<Vec<String>>,
    /// Bearer token for this destination's own `relay_urls`. Only valid
    /// alongside them.
    pub relay_auth_token: Option<String>,
}

/// How long a destination's connection is kept with no stream open on it,
/// unless `idle_timeout_secs` says otherwise.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Client config file schema. Every field is optional except that a client
/// needs at least one `[[destinations]]` entry; CLI flags override the
/// top-level values.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// This client's instance name (e.g. "work", "home"): it keys the
    /// single-instance lock and the control socket, so several clients can run
    /// side by side under different names, and titles the status views.
    /// Lowercase letters, digits, `-` and `_`; defaults to `default`.
    pub name: Option<String>,
    /// Loopback port for the optional SOCKS5 listener (binds `127.0.0.1`
    /// only, like the desktop client — the front-ends are unauthenticated and
    /// never exposed beyond the local machine). Unset = SOCKS front-end
    /// disabled; with neither `socks_port` nor `http_port` the client runs in
    /// port-forward/control-panel-only mode.
    pub socks_port: Option<u16>,
    /// Loopback port for the optional HTTP proxy listener (CONNECT tunneling +
    /// absolute-URI plain-HTTP forwarding; binds `127.0.0.1` only). Unset =
    /// HTTP front-end disabled.
    pub http_port: Option<u16>,
    /// Inline client secret key (`ed25519-sec:...`) used to
    /// authenticate to the servers. Never settable from TOML (`serde(skip)` +
    /// `deny_unknown_fields` rejects it loudly) — carrier for the `--auth-key`
    /// CLI flag only; config files must use `auth_key_file`.
    #[serde(skip)]
    pub auth_key: Option<String>,
    /// File containing the client secret key (as generated by
    /// `flexaccess-keys generate-auth-key`), used for every destination that
    /// does not name its own. The only way to configure the key from a config
    /// file — there is no inline variant.
    pub auth_key_file: Option<PathBuf>,
    /// Custom relay URL(s) for failover, used for every destination that does
    /// not name its own.
    pub relay_urls: Option<Vec<String>>,
    /// Shared bearer token sent to every custom relay's WebSocket upgrade. Only
    /// valid with custom `relay_urls`; rejected with the default iroh relays.
    pub relay_auth_token: Option<String>,
    /// Close a destination's connection after this many seconds with no
    /// stream open on it (default [`DEFAULT_IDLE_TIMEOUT`]); `0` never closes
    /// one for idleness. Connections are opened on first use either way.
    pub idle_timeout_secs: Option<u64>,
    /// The servers this client reaches (`[[destinations]]` tables), each under
    /// its own host name. Config-file only — there is no CLI flag.
    pub destinations: Option<Vec<DestinationEntry>>,
    /// Port forwards (`[[forwards]]` tables). Config-file only — there is no
    /// CLI flag.
    pub forwards: Option<Vec<ForwardConfig>>,
}

/// Fully-resolved server settings (CLI > file > default), paths tilde-expanded.
#[derive(Debug)]
pub struct ResolvedServer {
    pub secret_file: Option<PathBuf>,
    pub authorized_keys_file: Option<PathBuf>,
    pub relay_urls: Vec<String>,
    /// Shared bearer token for custom relays (custom relays only).
    pub relay_auth_token: Option<String>,
    /// Server-side host aliases, keys lowercased for case-insensitive matching.
    pub host_aliases: HashMap<String, String>,
    /// Raw routed-set entries (parsed into a `RoutedSet` at startup).
    pub routed_domains: Vec<String>,
    pub routed_cidrs: Vec<String>,
    /// Conditional DNS-forwarding rules, suffix keys lowercased for
    /// case-insensitive matching (parsed into a `DnsForwarder` at startup).
    pub dns_forwards: HashMap<String, Vec<String>>,
    /// Path to the duplicate-id blocklist file. Always the fixed default
    /// (`~/.config/flextunnel/blocklist.json`); it is deliberately **not**
    /// configurable, since relocating this security guard rail would let it be
    /// bypassed. See [`crate::blocklist`].
    pub blocklist_file: PathBuf,
}

/// Fully-resolved client settings (CLI > file > default), paths tilde-expanded.
pub struct ResolvedClient {
    pub name: Option<String>,
    pub socks_port: Option<u16>,
    pub http_port: Option<u16>,
    /// The default credential: an inline key (CLI only) or a key file. A
    /// destination's own `auth_key_file` overrides it.
    pub auth_key: Option<String>,
    pub auth_key_file: Option<PathBuf>,
    /// The default relays. A destination's own `relay_urls` override them.
    pub relay_urls: Vec<String>,
    /// Shared bearer token for the default custom relays.
    pub relay_auth_token: Option<String>,
    /// `None`: never close a connection for idleness.
    pub idle_timeout: Option<Duration>,
    /// Declared destinations, in config order (validated by
    /// [`Self::proxy_config`]).
    pub destinations: Vec<DestinationEntry>,
    /// Declared port forwards, in config order (validated by the client at
    /// startup).
    pub forwards: Vec<ForwardConfig>,
}

impl ResolvedClient {
    /// Turn the resolved settings into the core client's configuration:
    /// parse each destination's server id, load its key (its own
    /// `auth_key_file`, else the default credential) and build its relay
    /// config (its own `relay_urls` + token, else the defaults). Errors name
    /// the destination at fault. Host and routing validation happens when the
    /// client is built from the result.
    pub fn proxy_config(&self) -> Result<crate::proxy::ClientConfig> {
        use crate::proxy::{ClientAuth, DestinationConfig};
        use crate::transport::endpoint::RelayConfig;

        if self.destinations.is_empty() {
            anyhow::bail!(
                "The client has no destinations: add at least one [[destinations]] table \
                 (host + server_node_id) to the config"
            );
        }
        if self.auth_key.is_some() && self.auth_key_file.is_some() {
            anyhow::bail!("Both an inline client key and a client key file are set; use one");
        }
        // The default credential and relays are loaded once, and only if some
        // destination actually falls back to them.
        let mut default_key: Option<crate::auth::ClientKey> = None;
        let mut default_relay: Option<RelayConfig> = None;

        let mut destinations = Vec::with_capacity(self.destinations.len());
        for entry in &self.destinations {
            let context = || format!("destination {:?}", entry.host);
            let server_id = entry
                .server_node_id
                .trim()
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid server_node_id: {e}"))
                .with_context(context)?;

            let key = match &entry.auth_key_file {
                Some(path) => crate::auth::load_client_key_from_file(path)
                    .with_context(|| format!("Failed to load client key file {}", path.display()))
                    .with_context(context)?,
                None => match &default_key {
                    Some(key) => key.clone(),
                    None => {
                        let key = self.load_default_key().with_context(context)?;
                        default_key.insert(key).clone()
                    }
                },
            };

            let relay = match &entry.relay_urls {
                Some(urls) => {
                    RelayConfig::from_urls_with_token(urls, entry.relay_auth_token.clone())
                        .with_context(context)?
                }
                None => {
                    if entry.relay_auth_token.is_some() {
                        anyhow::bail!(
                            "{}: relay_auth_token is set without relay_urls; a destination's \
                             token only applies to its own relays",
                            context()
                        );
                    }
                    match &default_relay {
                        Some(relay) => relay.clone(),
                        None => {
                            let relay = RelayConfig::from_urls_with_token(
                                &self.relay_urls,
                                self.relay_auth_token.clone(),
                            )?;
                            default_relay.insert(relay).clone()
                        }
                    }
                }
            };

            destinations.push(DestinationConfig {
                host: entry.host.clone(),
                server_id,
                auth: ClientAuth::Key(Box::new(key)),
                relay,
                routed_domains: entry.routed_domains.clone(),
                routed_cidrs: entry.routed_cidrs.clone(),
                keep_connected: false,
            });
        }
        Ok(crate::proxy::ClientConfig {
            destinations,
            idle_timeout: self.idle_timeout,
        })
    }

    /// Load the default credential: the inline key, else the key file.
    fn load_default_key(&self) -> Result<crate::auth::ClientKey> {
        match (&self.auth_key, &self.auth_key_file) {
            (Some(key), _) => crate::auth::ClientKey::from_secret_str(key.trim())
                .context("Invalid client auth key"),
            (None, Some(path)) => crate::auth::load_client_key_from_file(path)
                .with_context(|| format!("Failed to load client key file {}", path.display())),
            (None, None) => anyhow::bail!(
                "no client key: set auth_key_file (top level, or on this destination) \
                 or pass --auth-key-file"
            ),
        }
    }
}

/// Expand a leading `~` / `~/…` to the user's home directory.
pub fn expand_tilde(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    } else if s == "~"
        && let Some(home) = dirs::home_dir()
    {
        return home;
    }
    path.to_path_buf()
}

/// Default config path for a role file (e.g. `~/.config/flextunnel/server.toml`).
///
/// Always uses `~/.config` (not the platform config dir) to match tunnel-rs,
/// so the same location works across Linux and macOS.
fn default_config_path(file_name: &str) -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".config").join("flextunnel").join(file_name))
}

/// Read and parse a TOML config file, with the path in any error.
fn load_config<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path.display()))?;
    toml::from_str(&content)
        .with_context(|| format!("Failed to parse config file: {}", path.display()))
}

/// Resolve the config file to load, if any: an explicit `path`, else the default
/// location when `default_config` is set, else `None`.
fn resolve_config_path(
    path: Option<&Path>,
    default_config: bool,
    default_name: &str,
) -> Result<Option<PathBuf>> {
    if let Some(p) = path {
        Ok(Some(expand_tilde(p)))
    } else if default_config {
        Ok(Some(default_config_path(default_name).context(
            "Could not determine the default config directory; pass -c <FILE> instead",
        )?))
    } else {
        Ok(None)
    }
}

/// Load the server config file (explicit path or `--default-config`), or `None`.
pub fn load_server_config(path: Option<&Path>, default_config: bool) -> Result<Option<ServerConfig>> {
    match resolve_config_path(path, default_config, "server.toml")? {
        Some(p) => Ok(Some(load_config(&p)?)),
        None => Ok(None),
    }
}

/// Load the client config: an explicit path (error if missing), else the
/// default `~/.config/flextunnel/client.toml` when it exists, else `None`
/// (the caller then falls back to CLI flags / the interactive prompt).
pub fn load_client_config(path: Option<&Path>) -> Result<Option<ClientConfig>> {
    match path {
        Some(p) => Ok(Some(load_config(&expand_tilde(p))?)),
        None => match default_client_config_path() {
            Some(p) if p.exists() => Ok(Some(load_config(&p)?)),
            _ => Ok(None),
        },
    }
}

/// Where [`load_client_config`] looks when no path is given:
/// `~/.config/flextunnel/client.toml` (which need not exist). `None` only when
/// the home directory is unknown. Callers use it to name the file in errors.
pub fn default_client_config_path() -> Option<PathBuf> {
    default_config_path("client.toml")
}

/// Merge CLI-provided values over file values over defaults for the server.
///
/// `cli` carries the CLI flags as a `ServerConfig` (a field is `Some`/non-empty
/// only when the user passed it). For each field CLI wins, then the file; list
/// fields are replaced wholesale (not appended), matching tunnel-rs.
pub fn resolve_server(cli: ServerConfig, file: Option<ServerConfig>) -> Result<ResolvedServer> {
    let file = file.unwrap_or_default();

    let secret_file = cli.secret_file.or(file.secret_file);
    let authorized_keys_file = cli.authorized_keys_file.or(file.authorized_keys_file);

    // Host aliases are file-only (no CLI flag). Lowercase keys so matching is
    // case-insensitive against a lowercased requested host (DNS hostnames are
    // case-insensitive). Reject entries that collide only by case — silently
    // dropping one would shadow a distinct alias.
    let host_aliases = collect_lowercased(
        cli.host_aliases.or(file.host_aliases).unwrap_or_default(),
        "host_aliases",
    )?;
    // DNS-forward suffixes are matched case-insensitively too; lowercase the keys
    // and reject case-only duplicates for the same reason.
    let dns_forwards = collect_lowercased(
        cli.dns_forwards.or(file.dns_forwards).unwrap_or_default(),
        "dns_forwards",
    )?;
    // Alias keys are either an exact host or a `*.suffix` wildcard (same syntax
    // as the routed set); reject malformed patterns loudly at startup.
    for key in host_aliases.keys() {
        validate_alias_key(key, "host_aliases")?;
    }
    // The `flextunnel.internal` namespace is reserved by flextunnel itself: a
    // client answers it locally and never sends it to a server, so an alias
    // under it could never match.
    for key in host_aliases.keys() {
        if crate::proxy::reserved::is_reserved_host(key) {
            anyhow::bail!(
                "alias '{key}' uses the reserved flextunnel.internal namespace and \
                 cannot be used as a [host_aliases] name"
            );
        }
    }

    // Fixed at the default (~/.config/flextunnel/blocklist.json) and NOT
    // overridable via CLI or config: the blocklist is a security guard rail, and
    // letting it be pointed elsewhere would let it be bypassed. Fail fast if the
    // home dir can't be determined rather than silently falling back to a
    // cwd-relative path a later run from another directory wouldn't share.
    let blocklist_file = crate::blocklist::default_blocklist_path().context(
        "Could not determine the home directory for the duplicate-id blocklist \
         (~/.config/flextunnel/blocklist.json); set HOME",
    )?;

    Ok(ResolvedServer {
        secret_file: secret_file.map(|p| expand_tilde(&p)),
        authorized_keys_file: authorized_keys_file.map(|p| expand_tilde(&p)),
        relay_urls: cli.relay_urls.or(file.relay_urls).unwrap_or_default(),
        relay_auth_token: cli.relay_auth_token.or(file.relay_auth_token),
        host_aliases,
        routed_domains: cli
            .routed_domains
            .or(file.routed_domains)
            .unwrap_or_default(),
        routed_cidrs: cli.routed_cidrs.or(file.routed_cidrs).unwrap_or_default(),
        dns_forwards,
        blocklist_file,
    })
}

/// Lowercase each source key and collect into a map, failing if two source keys
/// normalize (ASCII-lowercase) to the same key. Aliases are matched
/// case-insensitively, so a case-only duplicate would otherwise let one entry
/// silently shadow the other.
/// Validate one `[host_aliases]` key. A key is either an exact hostname or a
/// `*.suffix` wildcard matching subdomains of `suffix` (the same syntax as
/// `routed_domains`; resolved by `proxy::server::resolve_alias`). A bare `*` is
/// rejected — an alias catch-all mapping every host to one target is almost
/// certainly a misconfiguration — as are malformed patterns like `*.*.x`,
/// `*..x`, or a `*` anywhere but a leading `*.`. Keys are already lowercased by
/// [`collect_lowercased`].
fn validate_alias_key(key: &str, what: &str) -> Result<()> {
    if let Some(suffix) = key.strip_prefix("*.") {
        if suffix.contains('*') || suffix.split('.').any(str::is_empty) {
            anyhow::bail!("invalid [{what}] wildcard pattern '{key}'");
        }
    } else if key.is_empty() || key.contains('*') {
        anyhow::bail!(
            "invalid [{what}] name '{key}': use an exact hostname or a '*.suffix' wildcard"
        );
    }
    Ok(())
}

fn collect_lowercased<V>(
    entries: impl IntoIterator<Item = (String, V)>,
    what: &str,
) -> Result<HashMap<String, V>> {
    let mut out = HashMap::new();
    for (k, v) in entries {
        let key = k.to_ascii_lowercase();
        if out.contains_key(&key) {
            anyhow::bail!(
                "duplicate [{what}] alias '{key}': aliases are matched case-insensitively, \
                 so entries differing only by case collide"
            );
        }
        out.insert(key, v);
    }
    Ok(out)
}

/// Merge CLI-provided values over file values over defaults for the client.
pub fn resolve_client(cli: ClientConfig, file: Option<ClientConfig>) -> ResolvedClient {
    let file = file.unwrap_or_default();

    // Credential group merged as a unit per source: if the CLI set either the
    // inline key or the key file, the CLI's group wins wholesale; otherwise the
    // file's does (a config file can only carry `auth_key_file` — the inline
    // field is CLI-only). This avoids a false "both set" conflict when e.g. the
    // CLI gives an inline key and the config file gives a key file.
    let (auth_key, auth_key_file) = if cli.auth_key.is_some() || cli.auth_key_file.is_some() {
        (cli.auth_key, cli.auth_key_file)
    } else {
        (None, file.auth_key_file)
    };

    let idle_timeout = match cli.idle_timeout_secs.or(file.idle_timeout_secs) {
        Some(0) => None,
        Some(secs) => Some(Duration::from_secs(secs)),
        None => Some(DEFAULT_IDLE_TIMEOUT),
    };
    let mut destinations = cli.destinations.or(file.destinations).unwrap_or_default();
    for destination in &mut destinations {
        destination.auth_key_file = destination.auth_key_file.as_deref().map(expand_tilde);
    }

    ResolvedClient {
        name: cli.name.or(file.name),
        // No defaults: each proxy front-end is off unless explicitly configured.
        socks_port: cli.socks_port.or(file.socks_port),
        http_port: cli.http_port.or(file.http_port),
        auth_key,
        auth_key_file: auth_key_file.map(|p| expand_tilde(&p)),
        relay_urls: cli.relay_urls.or(file.relay_urls).unwrap_or_default(),
        relay_auth_token: cli.relay_auth_token.or(file.relay_auth_token),
        idle_timeout,
        destinations,
        forwards: cli.forwards.or(file.forwards).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_server_config() {
        let toml = r#"
            secret_file = "./server.key"
            authorized_keys_file = "/etc/flextunnel/authorized_keys"
            relay_urls = ["https://relay.example"]
        "#;
        let cfg: ServerConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.secret_file, Some(PathBuf::from("./server.key")));
        assert_eq!(
            cfg.authorized_keys_file,
            Some(PathBuf::from("/etc/flextunnel/authorized_keys"))
        );
        assert_eq!(cfg.relay_urls.as_deref().map(<[_]>::len), Some(1));
    }

    #[test]
    fn parse_client_config() {
        let toml = r#"
            name = "work"
            socks_port = 1085
            auth_key_file = "~/.config/flextunnel/client.key"
            idle_timeout_secs = 60

            [[destinations]]
            host = "machine1.internal"
            server_node_id = "abc123"
            routed_domains = ["*.corp.example"]
            routed_cidrs = ["10.0.0.0/8"]

            [[destinations]]
            host = "machine2.internal"
            server_node_id = "def456"
            auth_key_file = "~/other.key"
            relay_urls = ["https://relay.example"]
            relay_auth_token = "t"
        "#;
        let cfg: ClientConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.name.as_deref(), Some("work"));
        assert_eq!(cfg.socks_port, Some(1085));
        assert_eq!(cfg.idle_timeout_secs, Some(60));
        let destinations = cfg.destinations.as_deref().expect("destinations parsed");
        assert_eq!(destinations.len(), 2);
        assert_eq!(destinations[0].host, "machine1.internal");
        assert_eq!(destinations[0].server_node_id, "abc123");
        assert_eq!(destinations[0].routed_domains, vec!["*.corp.example"]);
        assert_eq!(destinations[0].routed_cidrs, vec!["10.0.0.0/8"]);
        assert!(destinations[0].auth_key_file.is_none() && destinations[0].relay_urls.is_none());
        assert!(destinations[1].routed_domains.is_empty());
        assert_eq!(destinations[1].relay_auth_token.as_deref(), Some("t"));

        // Per-destination key paths are tilde-expanded like the top-level one.
        let resolved = resolve_client(ClientConfig::default(), Some(cfg));
        assert_eq!(resolved.idle_timeout, Some(Duration::from_secs(60)));
        if let Some(home) = dirs::home_dir() {
            assert_eq!(
                resolved.destinations[1].auth_key_file.as_deref(),
                Some(home.join("other.key").as_path())
            );
        }
    }

    #[test]
    fn single_server_keys_are_gone() {
        // The one-server schema is not accepted: its keys are unknown fields,
        // and a destination needs both a host and a server id.
        for stale in [
            "server_node_id = \"abc123\"",
            "auto_reconnect = false",
            "max_reconnect_attempts = 5",
        ] {
            let err = toml::from_str::<ClientConfig>(stale).unwrap_err();
            assert!(err.to_string().contains("unknown field"), "{stale}: {err}");
        }
        assert!(toml::from_str::<ClientConfig>("[[destinations]]\nhost = \"m1.internal\"").is_err());
        assert!(
            toml::from_str::<ClientConfig>("[[destinations]]\nserver_node_id = \"abc\"").is_err()
        );
        let err = toml::from_str::<ClientConfig>(
            "[[destinations]]\nhost = \"m1.internal\"\nserver_node_id = \"abc\"\nrouted = []",
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
    }

    /// A resolved client with these destinations and a generated default key.
    fn resolved_with(destinations: Vec<DestinationEntry>) -> ResolvedClient {
        let key = crate::auth::ClientKey::generate().unwrap();
        ResolvedClient {
            name: None,
            socks_port: None,
            http_port: None,
            auth_key: Some(key.secret_str()),
            auth_key_file: None,
            relay_urls: Vec::new(),
            relay_auth_token: None,
            idle_timeout: Some(DEFAULT_IDLE_TIMEOUT),
            destinations,
            forwards: Vec::new(),
        }
    }

    fn entry(host: &str, seed: u8) -> DestinationEntry {
        DestinationEntry {
            host: host.to_string(),
            server_node_id: iroh::SecretKey::from_bytes(&[seed; 32]).public().to_string(),
            routed_domains: Vec::new(),
            routed_cidrs: Vec::new(),
            auth_key_file: None,
            relay_urls: None,
            relay_auth_token: None,
        }
    }

    #[test]
    fn proxy_config_builds_every_destination() {
        let mut second = entry("m2.internal", 2);
        second.routed_domains = vec!["*.corp.example".to_string()];
        second.relay_urls = Some(vec![
            "https://relay-a.example".to_string(),
            "https://relay-b.example".to_string(),
        ]);
        second.relay_auth_token = Some("token".to_string());
        let config = resolved_with(vec![entry("m1.internal", 1), second])
            .proxy_config()
            .unwrap();
        assert_eq!(config.idle_timeout, Some(DEFAULT_IDLE_TIMEOUT));
        assert_eq!(config.destinations.len(), 2);
        // The first falls back to the default (iroh) relays; the second uses
        // its own.
        assert!(!config.destinations[0].relay.is_custom());
        assert_eq!(config.destinations[1].relay.custom_urls().len(), 2);
        assert_eq!(config.destinations[1].relay.relay_auth_token(), Some("token"));
        assert_eq!(config.destinations[1].routed_domains, vec!["*.corp.example"]);
        assert!(config.destinations.iter().all(|d| !d.keep_connected));
    }

    #[test]
    fn proxy_config_errors_name_the_destination() {
        let err = |resolved: ResolvedClient| match resolved.proxy_config() {
            Ok(_) => panic!("expected an error"),
            Err(e) => format!("{e:#}"),
        };

        assert!(err(resolved_with(Vec::new())).contains("no destinations"));

        let mut bad_id = entry("m1.internal", 1);
        bad_id.server_node_id = "not-an-id".to_string();
        let message = err(resolved_with(vec![bad_id]));
        assert!(message.contains("m1.internal") && message.contains("server_node_id"), "{message}");

        let mut stray_token = entry("m1.internal", 1);
        stray_token.relay_auth_token = Some("t".to_string());
        let message = err(resolved_with(vec![stray_token]));
        assert!(message.contains("m1.internal") && message.contains("relay_urls"), "{message}");

        let mut no_key = resolved_with(vec![entry("m1.internal", 1)]);
        no_key.auth_key = None;
        let message = err(no_key);
        assert!(message.contains("m1.internal") && message.contains("no client key"), "{message}");

        let mut both = resolved_with(vec![entry("m1.internal", 1)]);
        both.auth_key_file = Some(PathBuf::from("/nonexistent.key"));
        assert!(err(both).contains("use one"));

        let mut missing_file = entry("m1.internal", 1);
        missing_file.auth_key_file = Some(PathBuf::from("/nonexistent/flextunnel.key"));
        let message = err(resolved_with(vec![missing_file]));
        assert!(message.contains("m1.internal") && message.contains("flextunnel.key"), "{message}");
    }

    #[test]
    fn client_forwards_parse_with_optional_label() {
        let toml = r#"
            [[forwards]]
            local_port = 5432
            remote_host = "db.internal"
            remote_port = 5432

            [[forwards]]
            label = "nas"
            local_port = 8443
            remote_host = "10.0.0.7"
            remote_port = 443
        "#;
        let cfg: ClientConfig = toml::from_str(toml).unwrap();
        let forwards = cfg.forwards.expect("forwards parsed");
        assert_eq!(forwards.len(), 2);
        assert_eq!(forwards[0].label, "");
        assert_eq!(forwards[0].local_port, 5432);
        assert_eq!(forwards[1].label, "nas");
        assert_eq!(forwards[1].remote_host, "10.0.0.7");

        // Entries are strict too: a typo inside a table is a hard error, and a
        // forward without a remote host is incomplete.
        let err = toml::from_str::<ClientConfig>(
            "[[forwards]]\nlocal_port = 1\nremote_hots = \"x\"\nremote_port = 1",
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
        assert!(toml::from_str::<ClientConfig>("[[forwards]]\nlocal_port = 1\nremote_port = 1").is_err());
    }

    #[test]
    fn unknown_key_is_rejected() {
        // A misspelled key must be a hard error, not silently ignored.
        let err = toml::from_str::<ServerConfig>("authorized_keyz_file = \"x\"").unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
    }

    #[test]
    fn inline_private_keys_rejected_in_toml() {
        // Private keys must come from a file when a config file is used; the
        // inline fields are serde(skip)ped so TOML rejects them as unknown.
        let err = toml::from_str::<ServerConfig>("secret = \"aGVsbG8=\"").unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
        let err =
            toml::from_str::<ClientConfig>("auth_key = \"ed25519-sec:AAAA\"").unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
    }

    #[test]
    fn cli_overrides_file() {
        let file = ServerConfig {
            secret_file: Some(PathBuf::from("/file/server.key")),
            relay_urls: Some(vec!["https://file-relay".into()]),
            ..Default::default()
        };
        let cli = ServerConfig {
            secret_file: Some(PathBuf::from("/cli/server.key")),
            ..Default::default()
        };
        let r = resolve_server(cli, Some(file)).unwrap();
        // CLI wins where set; file fills the rest.
        assert_eq!(r.secret_file, Some(PathBuf::from("/cli/server.key")));
        assert_eq!(r.relay_urls, vec!["https://file-relay".to_string()]);
    }

    #[test]
    fn host_aliases_parsed_and_lowercased() {
        let toml = r#"
            [host_aliases]
            "Server.Internal" = "127.0.0.1"
            "node2.internal" = "192.168.1.50"
        "#;
        let file: ServerConfig = toml::from_str(toml).unwrap();
        let r = resolve_server(ServerConfig::default(), Some(file)).unwrap();
        // Keys are lowercased so matching against a lowercased host works.
        assert_eq!(r.host_aliases.get("server.internal").map(String::as_str), Some("127.0.0.1"));
        assert_eq!(r.host_aliases.get("node2.internal").map(String::as_str), Some("192.168.1.50"));
        assert!(!r.host_aliases.contains_key("Server.Internal"));
    }

    #[test]
    fn host_aliases_case_only_duplicate_is_rejected() {
        let toml = r#"
            [host_aliases]
            "Server.Internal" = "127.0.0.1"
            "server.internal" = "192.168.1.50"
        "#;
        let file: ServerConfig = toml::from_str(toml).unwrap();
        let err = resolve_server(ServerConfig::default(), Some(file)).unwrap_err();
        assert!(err.to_string().contains("host_aliases"), "{err}");
    }

    #[test]
    fn reserved_namespace_alias_is_rejected() {
        // The exact reserved host and any subdomain are refused as alias names.
        for name in ["flextunnel.internal", "status.flextunnel.internal"] {
            let toml = format!("[host_aliases]\n\"{name}\" = \"127.0.0.1\"\n");
            let file: ServerConfig = toml::from_str(&toml).unwrap();
            let err = resolve_server(ServerConfig::default(), Some(file)).unwrap_err();
            assert!(err.to_string().contains("reserved"), "{err}");
        }
    }

    #[test]
    fn wildcard_alias_keys_parsed_and_lowercased() {
        let toml = r#"
            [host_aliases]
            "*.Web.Internal" = "10.0.0.1"
        "#;
        let file: ServerConfig = toml::from_str(toml).unwrap();
        let r = resolve_server(ServerConfig::default(), Some(file)).unwrap();
        // The `*.` prefix survives lowercasing of the rest of the key.
        assert_eq!(r.host_aliases.get("*.web.internal").map(String::as_str), Some("10.0.0.1"));
    }

    #[test]
    fn malformed_wildcard_alias_is_rejected() {
        // A bare `*` catch-all, a doubled wildcard, an empty label, and a stray
        // `*` outside a leading `*.` are all rejected at config resolution.
        for (table, key) in [
            ("host_aliases", "*"),
            ("host_aliases", "*.*.internal"),
            ("host_aliases", "*..internal"),
            ("host_aliases", "web*.internal"),
        ] {
            let toml = format!("[{table}]\n\"{key}\" = \"10.0.0.1\"\n");
            let file: ServerConfig = toml::from_str(&toml).unwrap();
            let err = resolve_server(ServerConfig::default(), Some(file)).unwrap_err();
            assert!(err.to_string().contains(table), "key {key:?}: {err}");
        }
    }

    #[test]
    fn reserved_namespace_wildcard_alias_is_rejected() {
        // A `*.flextunnel.internal` wildcard collides with the reserved namespace.
        let toml = "[host_aliases]\n\"*.flextunnel.internal\" = \"127.0.0.1\"\n";
        let file: ServerConfig = toml::from_str(toml).unwrap();
        let err = resolve_server(ServerConfig::default(), Some(file)).unwrap_err();
        assert!(err.to_string().contains("reserved"), "{err}");
    }

    #[test]
    fn routed_keys_parsed_and_resolved() {
        let toml = r#"
            routed_domains = ["*.example.com", "httpbin.org"]
            routed_cidrs = ["10.0.0.0/8"]
        "#;
        let file: ServerConfig = toml::from_str(toml).unwrap();
        let r = resolve_server(ServerConfig::default(), Some(file)).unwrap();
        assert_eq!(r.routed_domains, vec!["*.example.com", "httpbin.org"]);
        assert_eq!(r.routed_cidrs, vec!["10.0.0.0/8"]);
        // Defaults to empty (inactive) when unset.
        let empty = resolve_server(ServerConfig::default(), None).unwrap();
        assert!(empty.routed_domains.is_empty());
        assert!(empty.routed_cidrs.is_empty());
    }

    #[test]
    fn dns_forwards_parsed_and_lowercased() {
        let toml = r#"
            [dns_forwards]
            "Local.168234.XYZ" = ["10.0.0.53"]
            "corp.example.com" = ["10.1.0.10:5353", "10.1.0.11"]
        "#;
        let file: ServerConfig = toml::from_str(toml).unwrap();
        let r = resolve_server(ServerConfig::default(), Some(file)).unwrap();
        // Keys lowercased for case-insensitive matching; values kept verbatim.
        assert_eq!(
            r.dns_forwards.get("local.168234.xyz").map(Vec::as_slice),
            Some(["10.0.0.53".to_string()].as_slice())
        );
        assert_eq!(r.dns_forwards.get("corp.example.com").map(Vec::len), Some(2));
        assert!(!r.dns_forwards.contains_key("Local.168234.XYZ"));
        // Defaults to empty (forwarding inactive) when unset.
        assert!(resolve_server(ServerConfig::default(), None).unwrap().dns_forwards.is_empty());
    }

    #[test]
    fn dns_forwards_case_only_duplicate_is_rejected() {
        let toml = r#"
            [dns_forwards]
            "Corp.Example.com" = ["10.0.0.1"]
            "corp.example.com" = ["10.0.0.2"]
        "#;
        let file: ServerConfig = toml::from_str(toml).unwrap();
        let err = resolve_server(ServerConfig::default(), Some(file)).unwrap_err();
        assert!(err.to_string().contains("dns_forwards"), "{err}");
    }

    #[test]
    fn client_defaults_applied() {
        let r = resolve_client(ClientConfig::default(), None);
        assert_eq!(r.socks_port, None);
        assert_eq!(r.idle_timeout, Some(DEFAULT_IDLE_TIMEOUT));
        assert!(r.destinations.is_empty());

        // `0` means "never close an idle connection"; the CLI value wins.
        let never = ClientConfig {
            idle_timeout_secs: Some(0),
            ..ClientConfig::default()
        };
        let file = ClientConfig {
            idle_timeout_secs: Some(90),
            ..ClientConfig::default()
        };
        assert_eq!(resolve_client(never, Some(file)).idle_timeout, None);
    }

    #[test]
    fn expand_tilde_handles_home() {
        if let Some(home) = dirs::home_dir() {
            assert_eq!(expand_tilde(Path::new("~/x")), home.join("x"));
            assert_eq!(expand_tilde(Path::new("~")), home);
        }
        // Non-tilde paths are unchanged.
        assert_eq!(expand_tilde(Path::new("/etc/x")), PathBuf::from("/etc/x"));
    }

    #[test]
    fn shipped_example_files_parse() {
        // The committed examples must always deserialize against the current
        // schema, so the docs can't drift from the structs (`deny_unknown_fields`
        // would reject a stale/renamed key).
        toml::from_str::<ServerConfig>(include_str!("../../../server.toml.example"))
            .expect("server.toml.example must parse");
        toml::from_str::<ClientConfig>(include_str!("../../../client.toml.example"))
            .expect("client.toml.example must parse");
    }

    #[test]
    fn examples_document_every_config_field() {
        // A maximal config exercising every documented key must parse with
        // deny_unknown_fields — catches a field renamed/removed in the struct but
        // left in the examples (or a new struct field the examples never mention).
        let server = r#"
            secret_file = "./server.key"
            authorized_keys_file = "/etc/flextunnel/authorized_keys"
            relay_urls = ["https://relay.example"]
            routed_domains = ["*.example.com"]
            routed_cidrs = ["10.0.0.0/8"]

            [host_aliases]
            "server.internal" = "127.0.0.1"

            [dns_forwards]
            "corp.example.com" = ["10.1.0.10:5353"]
        "#;
        let s: ServerConfig = toml::from_str(server).expect("maximal server config parses");
        assert!(s.secret_file.is_some() && s.dns_forwards.is_some());

        let client = r#"
            name = "work"
            socks_port = 1080
            http_port = 8081
            auth_key_file = "~/.config/flextunnel/client.key"
            relay_urls = ["https://relay.example"]
            relay_auth_token = "shared-relay-secret"
            idle_timeout_secs = 300

            [[destinations]]
            host = "machine1.internal"
            server_node_id = "<server endpoint id>"
            routed_domains = ["*.corp.example"]
            routed_cidrs = ["10.0.0.0/8"]
            auth_key_file = "~/.config/flextunnel/machine1.key"
            relay_urls = ["https://relay-a.example", "https://relay-b.example"]
            relay_auth_token = "machine1-relay-secret"

            [[forwards]]
            label = "db"
            local_port = 5432
            remote_host = "db.internal"
            remote_port = 5432
        "#;
        let c: ClientConfig = toml::from_str(client).expect("maximal client config parses");
        assert!(c.name.is_some() && c.idle_timeout_secs.is_some() && c.relay_auth_token.is_some());
        let destination = &c.destinations.as_deref().expect("destinations parsed")[0];
        assert!(destination.auth_key_file.is_some() && destination.relay_urls.is_some());
        assert_eq!(c.forwards.as_deref().map(<[_]>::len), Some(1));
    }
}
