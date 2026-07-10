//! flextunnel
//!
//! A SOCKS5-over-QUIC proxy via iroh P2P connections. The client runs a local
//! SOCKS5 listener; each CONNECT is tunneled as a reliable QUIC bi-stream to the
//! server, which resolves DNS and connects to the target from its own network.
//! Uses a fixed ALPN for protocol selection, auth tokens for access control, and TLS 1.3/QUIC for
//! encryption. Neither side needs admin/root (no TUN device).

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::PathBuf;

mod lock;

use flextunnel_core::app;
use flextunnel_core::blocklist::BlockList;
use flextunnel_core::proxy::{ClientConfig, DnsForwarder, ProxyClient, ProxyServer, RoutedSet};
use flextunnel_core::transport::endpoint::{
    create_client_endpoint, create_server_endpoint, secret_to_endpoint_id,
};
use flextunnel_core::{auth, config, secret};

#[derive(Parser)]
#[command(name = "flextunnel")]
#[command(version)]
#[command(about = "SOCKS5-over-QUIC proxy via iroh P2P")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the proxy server.
    #[command(arg_required_else_help = true)]
    Server {
        /// Config file path (TOML). CLI flags override file values.
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,
        /// Load config from ~/.config/flextunnel/server.toml.
        #[arg(long)]
        default_config: bool,
        /// Secret key file for the server's persistent identity.
        #[arg(long)]
        secret_file: Option<PathBuf>,
        /// Accepted client auth token (repeatable).
        #[arg(long = "auth-token")]
        auth_tokens: Vec<String>,
        /// File of accepted client auth tokens (one per line).
        #[arg(long)]
        auth_tokens_file: Option<PathBuf>,
        /// Accepted agent auth token (repeatable). Separate pool from clients.
        #[arg(long = "agent-auth-token")]
        agent_auth_tokens: Vec<String>,
        /// File of accepted agent auth tokens (one per line).
        #[arg(long)]
        agent_auth_tokens_file: Option<PathBuf>,
        /// Custom relay server URL(s) for failover (repeatable).
        #[arg(long = "relay-url")]
        relay_urls: Vec<String>,
        /// Custom DNS server URL for peer discovery ("none" to disable).
        #[arg(long)]
        dns_server: Option<String>,
    },
    /// Start the proxy client (local SOCKS5 listener).
    #[command(arg_required_else_help = true)]
    Client {
        /// Config file path (TOML). CLI flags override file values.
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,
        /// Load config from ~/.config/flextunnel/client.toml.
        #[arg(long)]
        default_config: bool,
        /// Local address for the SOCKS5 listener (default 127.0.0.1:1080).
        #[arg(long)]
        socks_listen: Option<SocketAddr>,
        /// Also run an HTTP proxy listener (CONNECT + plain-HTTP forwarding) on
        /// this address, e.g. 127.0.0.1:8081. Disabled unless set; the SOCKS5
        /// listener stays on.
        #[arg(long)]
        http_listen: Option<SocketAddr>,
        /// EndpointId of the server to connect to.
        #[arg(short = 'n', long)]
        server_node_id: Option<String>,
        /// Authentication token to send to the server.
        #[arg(long)]
        auth_token: Option<String>,
        /// File containing the authentication token.
        #[arg(long)]
        auth_token_file: Option<PathBuf>,
        /// Custom relay server URL(s) for failover (repeatable).
        #[arg(long = "relay-url")]
        relay_urls: Vec<String>,
        /// Custom DNS server URL for peer discovery ("none" to disable).
        #[arg(long)]
        dns_server: Option<String>,
        /// Force auto-reconnect on (overrides `auto_reconnect = false` in the config).
        #[arg(long, conflicts_with = "no_auto_reconnect")]
        auto_reconnect: bool,
        /// Disable auto-reconnect (exit on the first disconnection).
        #[arg(long, conflicts_with = "auto_reconnect")]
        no_auto_reconnect: bool,
        /// Cap on reconnect attempts between successful connections (unlimited if unset).
        #[arg(long)]
        max_reconnect_attempts: Option<NonZeroU32>,
    },
    /// Generate a new private key for persistent server identity.
    GenerateServerKey {
        /// Path where to save the private key file ("-" for stdout).
        #[arg(short, long)]
        output: PathBuf,
        /// Overwrite existing file if it exists.
        #[arg(long)]
        force: bool,
    },
    /// Show the server's public EndpointId derived from a private key.
    #[command(arg_required_else_help = true)]
    ShowServerId {
        /// Config file path (TOML). CLI flags override file values.
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,
        /// Load config from ~/.config/flextunnel/server.toml.
        #[arg(long)]
        default_config: bool,
        /// Path to the private key file (overrides secret_file/secret in the config).
        #[arg(short, long)]
        secret_file: Option<PathBuf>,
    },
    /// Generate client authentication token(s).
    GenerateAuthToken {
        /// Number of tokens to generate.
        #[arg(short, long, default_value = "1")]
        count: usize,
    },
}

fn log_version() {
    app::log_version(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
}

fn main() -> Result<()> {
    let args = Args::parse();
    app::init_logger(app::DEFAULT_LOG_FILTER);

    match args.command {
        Command::GenerateServerKey { output, force } => secret::generate_secret(output, force),
        Command::ShowServerId {
            config,
            default_config,
            secret_file,
        } => {
            // Resolve the secret the same way the server does: an explicit
            // --secret-file wins, otherwise fall back to secret_file/secret in
            // the config file. Reuses `resolve_server` for the merge + tilde
            // expansion; no async runtime needed for this path.
            let cli = config::ServerConfig {
                secret_file,
                ..Default::default()
            };
            let file = config::load_server_config(config.as_deref(), default_config)?;
            let r = config::resolve_server(cli, file)?;
            secret::show_id(r.secret.as_deref(), r.secret_file.as_deref())
        }
        Command::GenerateAuthToken { count } => {
            for _ in 0..count {
                println!("{}", auth::generate_client_token());
            }
            Ok(())
        }
        command => app::build_runtime()?.block_on(run_async(command)),
    }
}

async fn run_async(command: Command) -> Result<()> {
    // Long-running proxy processes hold a socket per connection; lift the soft
    // fd limit (per-process, best-effort) so macOS's default 256 doesn't choke
    // a busy client/server.
    app::raise_fd_limit();
    match command {
        Command::Server {
            config: config_path,
            default_config,
            secret_file,
            auth_tokens,
            auth_tokens_file,
            agent_auth_tokens,
            agent_auth_tokens_file,
            relay_urls,
            dns_server,
        } => {
            log_version();
            let cli = config::ServerConfig {
                secret_file,
                secret: None, // no inline-secret CLI flag; config file only
                auth_tokens: (!auth_tokens.is_empty()).then_some(auth_tokens),
                auth_tokens_file,
                agent_auth_tokens: (!agent_auth_tokens.is_empty()).then_some(agent_auth_tokens),
                agent_auth_tokens_file,
                agent_routes: None, // config-file only; no CLI flag
                relay_urls: (!relay_urls.is_empty()).then_some(relay_urls),
                dns_server,
                host_aliases: None, // config-file only; no CLI flag
                routed_domains: None, // config-file only; no CLI flag
                routed_cidrs: None,   // config-file only; no CLI flag
                dns_forwards: None,   // config-file only; no CLI flag
            };
            let file = config::load_server_config(config_path.as_deref(), default_config)?;
            run_server(config::resolve_server(cli, file)?).await
        }
        Command::Client {
            config: config_path,
            default_config,
            socks_listen,
            http_listen,
            server_node_id,
            auth_token,
            auth_token_file,
            relay_urls,
            dns_server,
            auto_reconnect,
            no_auto_reconnect,
            max_reconnect_attempts,
        } => {
            log_version();
            // CLI precedence: --auto-reconnect → Some(true), --no-auto-reconnect →
            // Some(false), neither → None (defer to config file, then default).
            // The two flags are mutually exclusive (clap `conflicts_with`).
            let auto_reconnect = if auto_reconnect {
                Some(true)
            } else if no_auto_reconnect {
                Some(false)
            } else {
                None
            };
            let cli = config::ClientConfig {
                server_node_id,
                socks_listen,
                http_listen,
                auth_token,
                auth_token_file,
                relay_urls: (!relay_urls.is_empty()).then_some(relay_urls),
                dns_server,
                auto_reconnect,
                max_reconnect_attempts,
            };
            let file = config::load_client_config(config_path.as_deref(), default_config)?;
            run_client(config::resolve_client(cli, file)).await
        }
        _ => unreachable!("synchronous commands handled in main()"),
    }
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

async fn run_server(r: config::ResolvedServer) -> Result<()> {
    // Enforce one server per user before doing any work. Held for the process
    // lifetime; released automatically on exit or crash.
    let _lock = lock::acquire()?;

    let valid_tokens = auth::load_auth_tokens(
        &r.auth_tokens,
        r.auth_tokens_file.as_deref(),
        auth::CLIENT_TOKEN_PREFIX,
    )
    .context("Failed to load client authentication tokens")?;
    if valid_tokens.is_empty() {
        anyhow::bail!(
            "The server requires at least one client authentication token.\n\
             Generate one with: flextunnel generate-auth-token\n\
             Then pass --auth-token <TOKEN>, --auth-tokens-file <FILE>, or set \
             auth_tokens/auth_tokens_file in the config."
        );
    }
    log::info!("Loaded {} client authentication token(s)", valid_tokens.len());

    // Agent tokens are optional (a server may run no reverse routes). Loaded from
    // a separate pool with the `fta` prefix so a client token can't act as an agent.
    let agent_valid_tokens = auth::load_auth_tokens(
        &r.agent_auth_tokens,
        r.agent_auth_tokens_file.as_deref(),
        auth::AGENT_TOKEN_PREFIX,
    )
    .context("Failed to load agent authentication tokens")?;
    if !agent_valid_tokens.is_empty() {
        log::info!("Loaded {} agent authentication token(s)", agent_valid_tokens.len());
    }
    if !r.agent_routes.is_empty() {
        // Reverse routes forward to agents, which must authenticate with an agent
        // token. Routes with no agent token are unusable dead config — fail loudly
        // rather than start with reverse routes no agent can ever serve.
        if agent_valid_tokens.is_empty() {
            anyhow::bail!(
                "{} agent route(s) are configured but no agent authentication token was \
                 provided, so no agent can connect to serve them.\n\
                 Add at least one agent token (--agent-auth-token <TOKEN>, \
                 --agent-auth-tokens-file <FILE>, or agent_auth_tokens/agent_auth_tokens_file \
                 in the config), or remove the agent_routes.",
                r.agent_routes.len()
            );
        }
        log::info!("Loaded {} agent route(s)", r.agent_routes.len());
    }

    let secret_key = secret::resolve_secret_key(r.secret.as_deref(), r.secret_file.as_deref())?;
    let own_id = secret_to_endpoint_id(&secret_key);

    // Load the duplicate-id blocklist and refuse to start if this server's own id
    // is recorded as a conflict (duplicate-server self-block guard). Done before
    // creating the endpoint so a self-blocked identity never binds.
    let blocklist = BlockList::load(r.blocklist_file.clone())
        .with_context(|| format!("Failed to load blocklist {}", r.blocklist_file.display()))?;
    if blocklist.is_server_conflicted(&own_id.to_string()) {
        anyhow::bail!(
            "Refusing to start: server id {own_id} is recorded as a duplicate-id conflict in \
             {}.\nAnother server was detected sharing this identity. Stop the other server, \
             then remove the entry from the blocklist to start again.",
            r.blocklist_file.display()
        );
    }

    // Parse the routed set before creating the endpoint: a parse failure here must
    // not bypass the endpoint.close() cleanup below (an ungraceful drop panics
    // under panic=abort).
    let routed_set = RoutedSet::new(&r.routed_domains, &r.routed_cidrs)
        .context("Invalid routed-set configuration")?;
    // The tunnel set is required (VPN-style split tunnel): decide explicitly what
    // is routed through the tunnel. Use "*" (and 0.0.0.0/0, ::/0) for full tunnel.
    if routed_set.is_empty() {
        anyhow::bail!(
            "a tunnel set is required: configure routed_domains / routed_cidrs \
             (use \"*\" plus 0.0.0.0/0 and ::/0 to tunnel all traffic)"
        );
    }

    // Build the conditional DNS-forwarding table before creating the endpoint so
    // a bad server spec fails fast (same reasoning as the routed set above).
    let dns_forwarder = DnsForwarder::new(&r.dns_forwards)
        .context("Invalid dns_forwards configuration")?;
    if let Some(forwarder) = &dns_forwarder {
        validate_dns_forwards_coverage(forwarder, &routed_set)?;
    }

    let endpoint = create_server_endpoint(&r.relay_urls, secret_key, r.dns_server.as_deref())
        .await
        .context("Failed to create iroh endpoint")?;

    log::info!("flextunnel server Node ID: {}", endpoint.id());
    log::info!(
        "Clients connect with: flextunnel client --server-node-id {} --auth-token <TOKEN>",
        endpoint.id()
    );

    if !r.host_aliases.is_empty() {
        log::info!("Loaded {} host alias(es)", r.host_aliases.len());
    }
    if !r.dns_forwards.is_empty() {
        log::info!(
            "Loaded {} conditional DNS-forwarding rule(s)",
            r.dns_forwards.len()
        );
    }
    log::info!(
        "Tunnel set: {} domain rule(s), {} CIDR(s) — off-list tunnel requests are rejected; pushed to clients on connect",
        r.routed_domains.len(),
        r.routed_cidrs.len()
    );
    let server = ProxyServer::new(
        own_id,
        valid_tokens,
        agent_valid_tokens,
        r.agent_routes,
        r.host_aliases,
        routed_set,
        r.routed_domains,
        r.routed_cidrs,
        dns_forwarder,
        blocklist,
    );
    let run = async {
        server
            .run(&endpoint)
            .await
            .map_err(|e| anyhow::anyhow!("Server error: {e}"))
    };

    let res = tokio::select! {
        res = run => res,
        sig = app::shutdown_signal() => {
            sig?;
            log::info!("Received shutdown signal, stopping server");
            Ok(())
        }
    };

    // Close the endpoint gracefully before it is dropped. Skipping this makes
    // iroh tear down its relay tasks via an ungraceful abort, which panics
    // (`JoinSet::join_all` on a cancelled task) — fatal under panic=abort.
    endpoint.close().await;
    res
}

async fn run_client(r: config::ResolvedClient) -> Result<()> {
    let server_node_id = r.server_node_id.context(
        "The client requires a server node id (--server-node-id or server_node_id in the config).",
    )?;

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

    // The routed set (tunnel set) is no longer configured on the client; it is
    // pushed by the server during the handshake (see ProxyClient::handshake).

    let endpoint = create_client_endpoint(&r.relay_urls, r.dns_server.as_deref())
        .await
        .context("Failed to create iroh endpoint")?;
    log::info!("flextunnel client Node ID: {}", endpoint.id());

    let client = ProxyClient::new(ClientConfig {
        server_node_id,
        auth_token: token,
        socks_listen: r.socks_listen,
        http_listen: r.http_listen,
        relay_urls: r.relay_urls,
        auto_reconnect: r.auto_reconnect,
        max_reconnect_attempts: r.max_reconnect_attempts,
    });

    let run = async {
        client
            .run(&endpoint)
            .await
            .map_err(|e| anyhow::anyhow!("Client error: {e}"))
    };

    let res = tokio::select! {
        res = run => res,
        sig = app::shutdown_signal() => {
            sig?;
            log::info!("Received shutdown signal, stopping client");
            Ok(())
        }
    };

    // Close the endpoint gracefully before it is dropped (see run_server).
    endpoint.close().await;
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

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
}
