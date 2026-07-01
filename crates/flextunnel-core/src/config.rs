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
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

/// One `[agent_routes]` reservation: an alias that resolves, server-side, to a
/// connected **agent** (by its stable machine id) rather than to a host on the
/// server's own network. When a client requests the alias, the server forwards
/// the stream over the agent's live connection and the agent dials
/// `127.0.0.1:<requested port>` on *its* network. Reverse routing is
/// **loopback-only** in v1. See `proxy::agent` and `proxy::server`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRoute {
    /// The agent's stable machine id (`/etc/machine-id`), as a string.
    pub machine_id: String,
}

/// Server config file schema. Every field is optional; CLI flags override these.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Path to the server's secret-key file (persistent identity).
    pub secret_file: Option<PathBuf>,
    /// Inline base64 secret key (alternative to `secret_file`).
    pub secret: Option<String>,
    /// Accepted client auth tokens (inline list).
    pub auth_tokens: Option<Vec<String>>,
    /// File of accepted client auth tokens (one per line).
    pub auth_tokens_file: Option<PathBuf>,
    /// Accepted agent auth tokens (inline list) — a separate pool from
    /// `auth_tokens`, using the `fta` prefix.
    pub agent_auth_tokens: Option<Vec<String>>,
    /// File of accepted agent auth tokens (one per line).
    pub agent_auth_tokens_file: Option<PathBuf>,
    /// Reverse-routing reservations: an alias resolved to a connected **agent**
    /// (by machine id) instead of to a host on the server's own network. A
    /// requested hostname matching a key is forwarded over the agent's live
    /// connection; the agent dials `127.0.0.1` on its own network, keeping the
    /// requested port. Checked *before* `host_aliases`; a name should appear in
    /// only one. See [`AgentRoute`].
    pub agent_routes: Option<HashMap<String, AgentRoute>>,
    /// Custom relay URL(s) for failover.
    pub relay_urls: Option<Vec<String>>,
    /// Custom discovery DNS server URL ("none" to disable).
    pub dns_server: Option<String>,
    /// Hostname aliases resolved on the server side: a requested host that
    /// matches a key is rewritten to its value (an IP or another hostname on the
    /// server's network) before connecting. Keeps the requested port. Lets a
    /// client reach the server's loopback or internal hosts via a real name
    /// (e.g. `server.ezvpn` → `127.0.0.1`), which also dodges Firefox's refusal
    /// to proxy literal `localhost`/`127.0.0.1`.
    pub host_aliases: Option<HashMap<String, String>>,
    /// Domains routed through the tunnel (the tunnel set). Exact (`example.com`),
    /// wildcard (`*.example.com`, subdomains only), or `*` to match every host
    /// (full tunnel). The tunnel set is required — a server with an empty set
    /// refuses to start. Off-list targets are rejected server-side and
    /// direct-connected client-side. Keep in sync with `routed_cidrs`.
    pub routed_domains: Option<Vec<String>>,
    /// CIDRs / bare IPs routed through the tunnel (matched against IP targets).
    /// A default route (`0.0.0.0/0` / `::/0`) matches every IP. See
    /// `routed_domains`.
    pub routed_cidrs: Option<Vec<String>>,
}

/// Client config file schema. Every field is optional; CLI flags override these.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// EndpointId of the server to connect to.
    pub server_node_id: Option<String>,
    /// Local address for the SOCKS5 listener.
    pub socks_listen: Option<SocketAddr>,
    /// Auth token to send to the server.
    pub auth_token: Option<String>,
    /// File containing the auth token.
    pub auth_token_file: Option<PathBuf>,
    /// Custom relay URL(s) for failover.
    pub relay_urls: Option<Vec<String>>,
    /// Custom discovery DNS server URL ("none" to disable).
    pub dns_server: Option<String>,
    /// Reconnect with backoff on a transient drop (default true).
    pub auto_reconnect: Option<bool>,
    /// Cap on reconnect attempts between successful connections.
    pub max_reconnect_attempts: Option<NonZeroU32>,
}

/// Fully-resolved server settings (CLI > file > default), paths tilde-expanded.
#[derive(Debug)]
pub struct ResolvedServer {
    pub secret_file: Option<PathBuf>,
    pub secret: Option<String>,
    pub auth_tokens: Vec<String>,
    pub auth_tokens_file: Option<PathBuf>,
    pub agent_auth_tokens: Vec<String>,
    pub agent_auth_tokens_file: Option<PathBuf>,
    /// Reverse-routing reservations, keys lowercased for case-insensitive
    /// matching, mapping an alias to an agent's machine id. See [`AgentRoute`].
    pub agent_routes: HashMap<String, String>,
    pub relay_urls: Vec<String>,
    pub dns_server: Option<String>,
    /// Server-side host aliases, keys lowercased for case-insensitive matching.
    pub host_aliases: HashMap<String, String>,
    /// Raw routed-set entries (parsed into a `RoutedSet` at startup).
    pub routed_domains: Vec<String>,
    pub routed_cidrs: Vec<String>,
    /// Path to the duplicate-id blocklist file. Always the fixed default
    /// (`~/.config/flextunnel/blocklist.json`); it is deliberately **not**
    /// configurable, since relocating this security guard rail would let it be
    /// bypassed. See [`crate::blocklist`].
    pub blocklist_file: PathBuf,
}

/// Fully-resolved client settings (CLI > file > default), paths tilde-expanded.
pub struct ResolvedClient {
    pub server_node_id: Option<String>,
    pub socks_listen: SocketAddr,
    pub auth_token: Option<String>,
    pub auth_token_file: Option<PathBuf>,
    pub relay_urls: Vec<String>,
    pub dns_server: Option<String>,
    pub auto_reconnect: bool,
    pub max_reconnect_attempts: Option<NonZeroU32>,
}

/// Default SOCKS5 listen address when neither CLI nor config sets one.
const DEFAULT_SOCKS_LISTEN: &str = "127.0.0.1:1080";

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

/// Load the client config file (explicit path or `--default-config`), or `None`.
pub fn load_client_config(path: Option<&Path>, default_config: bool) -> Result<Option<ClientConfig>> {
    match resolve_config_path(path, default_config, "client.toml")? {
        Some(p) => Ok(Some(load_config(&p)?)),
        None => Ok(None),
    }
}

/// Merge CLI-provided values over file values over defaults for the server.
///
/// `cli` carries the CLI flags as a `ServerConfig` (a field is `Some`/non-empty
/// only when the user passed it). For each field CLI wins, then the file; list
/// fields are replaced wholesale (not appended), matching tunnel-rs.
pub fn resolve_server(cli: ServerConfig, file: Option<ServerConfig>) -> Result<ResolvedServer> {
    let file = file.unwrap_or_default();

    // Credential groups are merged as a *unit* per source: if the CLI set any
    // part of a group, the CLI's group wins wholesale; otherwise the file's does.
    // This avoids a false "both set" conflict when e.g. the CLI gives a token and
    // the file gives a token-file.
    let (secret, secret_file) = if cli.secret.is_some() || cli.secret_file.is_some() {
        (cli.secret, cli.secret_file)
    } else {
        (file.secret, file.secret_file)
    };
    let (auth_tokens, auth_tokens_file) = if cli.auth_tokens.is_some() || cli.auth_tokens_file.is_some()
    {
        (cli.auth_tokens, cli.auth_tokens_file)
    } else {
        (file.auth_tokens, file.auth_tokens_file)
    };
    let (agent_auth_tokens, agent_auth_tokens_file) =
        if cli.agent_auth_tokens.is_some() || cli.agent_auth_tokens_file.is_some() {
            (cli.agent_auth_tokens, cli.agent_auth_tokens_file)
        } else {
            (file.agent_auth_tokens, file.agent_auth_tokens_file)
        };

    // File-only (no CLI flag). Lowercase keys so matching is case-insensitive
    // against a lowercased requested host. Reject entries that collide only by
    // case — silently dropping one would shadow a distinct reservation.
    let agent_routes = collect_lowercased(
        cli.agent_routes
            .or(file.agent_routes)
            .unwrap_or_default()
            .into_iter()
            .map(|(k, v)| (k, v.machine_id)),
        "agent_routes",
    )?;
    // Same treatment for host aliases (DNS hostnames are case-insensitive).
    let host_aliases = collect_lowercased(
        cli.host_aliases.or(file.host_aliases).unwrap_or_default(),
        "host_aliases",
    )?;
    // A name must not appear in both: agent_routes is checked first at request
    // time, so an overlap would silently shadow the host alias.
    for key in agent_routes.keys() {
        if host_aliases.contains_key(key) {
            anyhow::bail!(
                "alias '{key}' is defined in both [agent_routes] and [host_aliases]; \
                 a name may appear in only one"
            );
        }
    }

    Ok(ResolvedServer {
        secret_file: secret_file.map(|p| expand_tilde(&p)),
        secret,
        auth_tokens: auth_tokens.unwrap_or_default(),
        auth_tokens_file: auth_tokens_file.map(|p| expand_tilde(&p)),
        agent_auth_tokens: agent_auth_tokens.unwrap_or_default(),
        agent_auth_tokens_file: agent_auth_tokens_file.map(|p| expand_tilde(&p)),
        agent_routes,
        relay_urls: cli.relay_urls.or(file.relay_urls).unwrap_or_default(),
        dns_server: cli.dns_server.or(file.dns_server),
        host_aliases,
        routed_domains: cli
            .routed_domains
            .or(file.routed_domains)
            .unwrap_or_default(),
        routed_cidrs: cli.routed_cidrs.or(file.routed_cidrs).unwrap_or_default(),
        // Fixed at the default (~/.config/flextunnel/blocklist.json) and NOT
        // overridable via CLI or config: the blocklist is a security guard rail,
        // and letting it be pointed elsewhere would let it be bypassed. Fall back
        // to a cwd-relative name only if the home dir can't be determined.
        blocklist_file: crate::blocklist::default_blocklist_path()
            .unwrap_or_else(|| PathBuf::from("blocklist.json")),
    })
}

/// Lowercase each source key and collect into a map, failing if two source keys
/// normalize (ASCII-lowercase) to the same key. Aliases are matched
/// case-insensitively, so a case-only duplicate would otherwise let one entry
/// silently shadow the other.
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

    // Token group merged as a unit per source (see `resolve_server`).
    let (auth_token, auth_token_file) = if cli.auth_token.is_some() || cli.auth_token_file.is_some() {
        (cli.auth_token, cli.auth_token_file)
    } else {
        (file.auth_token, file.auth_token_file)
    };

    ResolvedClient {
        server_node_id: cli.server_node_id.or(file.server_node_id),
        socks_listen: cli
            .socks_listen
            .or(file.socks_listen)
            .unwrap_or_else(|| DEFAULT_SOCKS_LISTEN.parse().expect("valid default addr")),
        auth_token,
        auth_token_file: auth_token_file.map(|p| expand_tilde(&p)),
        relay_urls: cli.relay_urls.or(file.relay_urls).unwrap_or_default(),
        dns_server: cli.dns_server.or(file.dns_server),
        auto_reconnect: cli.auto_reconnect.or(file.auto_reconnect).unwrap_or(true),
        max_reconnect_attempts: cli.max_reconnect_attempts.or(file.max_reconnect_attempts),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_server_config() {
        let toml = r#"
            secret_file = "./server.key"
            auth_tokens = ["ftcAAA", "ftcBBB"]
            relay_urls = ["https://relay.example"]
            dns_server = "none"
        "#;
        let cfg: ServerConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.secret_file, Some(PathBuf::from("./server.key")));
        assert_eq!(cfg.auth_tokens.as_deref().map(<[_]>::len), Some(2));
        assert_eq!(cfg.dns_server.as_deref(), Some("none"));
        assert!(cfg.secret.is_none());
    }

    #[test]
    fn parse_client_config() {
        let toml = r#"
            server_node_id = "abc123"
            socks_listen = "127.0.0.1:1085"
            auth_token = "ftcTOKEN"
            auto_reconnect = false
            max_reconnect_attempts = 5
        "#;
        let cfg: ClientConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.server_node_id.as_deref(), Some("abc123"));
        assert_eq!(cfg.socks_listen, Some("127.0.0.1:1085".parse().unwrap()));
        assert_eq!(cfg.auto_reconnect, Some(false));
        assert_eq!(cfg.max_reconnect_attempts, NonZeroU32::new(5));
    }

    #[test]
    fn unknown_key_is_rejected() {
        // A misspelled key must be a hard error, not silently ignored.
        let err = toml::from_str::<ServerConfig>("auth_tokenz = []").unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
    }

    #[test]
    fn cli_overrides_file() {
        let file = ServerConfig {
            dns_server: Some("https://file.example".into()),
            relay_urls: Some(vec!["https://file-relay".into()]),
            ..Default::default()
        };
        let cli = ServerConfig {
            dns_server: Some("https://cli.example".into()),
            ..Default::default()
        };
        let r = resolve_server(cli, Some(file)).unwrap();
        // CLI wins where set; file fills the rest.
        assert_eq!(r.dns_server.as_deref(), Some("https://cli.example"));
        assert_eq!(r.relay_urls, vec!["https://file-relay".to_string()]);
    }

    #[test]
    fn host_aliases_parsed_and_lowercased() {
        let toml = r#"
            [host_aliases]
            "Server.EzVPN" = "127.0.0.1"
            "node2.ezvpn" = "192.168.1.50"
        "#;
        let file: ServerConfig = toml::from_str(toml).unwrap();
        let r = resolve_server(ServerConfig::default(), Some(file)).unwrap();
        // Keys are lowercased so matching against a lowercased host works.
        assert_eq!(r.host_aliases.get("server.ezvpn").map(String::as_str), Some("127.0.0.1"));
        assert_eq!(r.host_aliases.get("node2.ezvpn").map(String::as_str), Some("192.168.1.50"));
        assert!(!r.host_aliases.contains_key("Server.EzVPN"));
    }

    #[test]
    fn agent_routes_parsed_and_lowercased() {
        let toml = r#"
            agent_auth_tokens = ["ftaAAA"]

            [agent_routes]
            "Web.EzVPN" = { machine_id = "abc123def" }
            "nas.ezvpn" = { machine_id = "999888777" }
        "#;
        let file: ServerConfig = toml::from_str(toml).unwrap();
        let r = resolve_server(ServerConfig::default(), Some(file)).unwrap();
        // Keys lowercased for case-insensitive matching; values are machine ids.
        assert_eq!(r.agent_routes.get("web.ezvpn").map(String::as_str), Some("abc123def"));
        assert_eq!(r.agent_routes.get("nas.ezvpn").map(String::as_str), Some("999888777"));
        assert!(!r.agent_routes.contains_key("Web.EzVPN"));
        assert_eq!(r.agent_auth_tokens, vec!["ftaAAA".to_string()]);
    }

    #[test]
    fn agent_routes_case_only_duplicate_is_rejected() {
        let toml = r#"
            [agent_routes]
            "Web.EzVPN" = { machine_id = "abc" }
            "web.ezvpn" = { machine_id = "def" }
        "#;
        let file: ServerConfig = toml::from_str(toml).unwrap();
        let err = resolve_server(ServerConfig::default(), Some(file)).unwrap_err();
        assert!(err.to_string().contains("agent_routes"), "{err}");
    }

    #[test]
    fn host_aliases_case_only_duplicate_is_rejected() {
        let toml = r#"
            [host_aliases]
            "Server.EzVPN" = "127.0.0.1"
            "server.ezvpn" = "192.168.1.50"
        "#;
        let file: ServerConfig = toml::from_str(toml).unwrap();
        let err = resolve_server(ServerConfig::default(), Some(file)).unwrap_err();
        assert!(err.to_string().contains("host_aliases"), "{err}");
    }

    #[test]
    fn agent_route_and_host_alias_overlap_is_rejected() {
        let toml = r#"
            [agent_routes]
            "shared.ezvpn" = { machine_id = "abc" }

            [host_aliases]
            "Shared.EzVPN" = "127.0.0.1"
        "#;
        let file: ServerConfig = toml::from_str(toml).unwrap();
        let err = resolve_server(ServerConfig::default(), Some(file)).unwrap_err();
        assert!(err.to_string().contains("both"), "{err}");
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
    fn client_defaults_applied() {
        let r = resolve_client(ClientConfig::default(), None);
        assert_eq!(r.socks_listen, "127.0.0.1:1080".parse().unwrap());
        assert!(r.auto_reconnect);
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
}
