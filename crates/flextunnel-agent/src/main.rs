//! flextunnel-agent
//!
//! A reverse-routing exit point for flextunnel (Linux, macOS, and Windows).
//! Unlike the client it runs no local SOCKS5 listener: it dials the server with
//! an **ephemeral** iroh identity, identifies itself by its stable **machine id**,
//! and accepts the streams the server opens back to it, connecting each to
//! `127.0.0.1` on this machine (reverse routing is loopback-only in v1).
//!
//! The machine id is the OS-native per-install identifier (via the `machine-uid`
//! crate): `/etc/machine-id` on Linux, `IOPlatformUUID` on macOS, and
//! `MachineGuid` on Windows — no elevation required. The operator reserves this
//! agent's machine id in the server's `[agent_routes]` and gives it an agent auth
//! token (`fta` prefix, `flextunnel-agent generate-token`). Only one agent runs
//! per machine, enforced by a file lock.

mod lock;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use flextunnel_core::auth;
use flextunnel_core::config::expand_tilde;
use flextunnel_core::proxy::{AgentConfig, ProxyAgent};
use flextunnel_core::transport::endpoint::create_client_endpoint;

#[derive(Parser)]
#[command(name = "flextunnel-agent")]
#[command(version)]
#[command(about = "flextunnel reverse-routing agent")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the agent: connect to the server and serve reverse-routed streams.
    Run {
        /// Config file path (TOML). CLI flags override file values.
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,
        /// Load config from ~/.config/flextunnel/agent.toml.
        #[arg(long)]
        default_config: bool,
        /// EndpointId of the server to connect to.
        #[arg(short = 'n', long)]
        server_node_id: Option<String>,
        /// Agent authentication token to send to the server (an `fta` token).
        #[arg(long)]
        auth_token: Option<String>,
        /// File containing the agent authentication token.
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
    /// Generate agent authentication token(s) (prefix `fta`).
    GenerateToken {
        /// Number of tokens to generate.
        #[arg(short, long, default_value = "1")]
        count: usize,
    },
}

/// Agent config file schema. Every field is optional; CLI flags override these.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentFileConfig {
    /// EndpointId of the server to connect to.
    server_node_id: Option<String>,
    /// Agent auth token to send to the server.
    auth_token: Option<String>,
    /// File containing the agent auth token.
    auth_token_file: Option<PathBuf>,
    /// Custom relay URL(s) for failover.
    relay_urls: Option<Vec<String>>,
    /// Custom discovery DNS server URL ("none" to disable).
    dns_server: Option<String>,
    /// Reconnect with backoff on a transient drop (default true).
    auto_reconnect: Option<bool>,
    /// Cap on reconnect attempts between successful connections.
    max_reconnect_attempts: Option<NonZeroU32>,
}

/// Fully-resolved agent settings (CLI > file > default), paths tilde-expanded.
struct ResolvedAgent {
    server_node_id: Option<String>,
    auth_token: Option<String>,
    auth_token_file: Option<PathBuf>,
    relay_urls: Vec<String>,
    dns_server: Option<String>,
    auto_reconnect: bool,
    max_reconnect_attempts: Option<NonZeroU32>,
}

fn init_logger() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info,iroh=warn,tracing=warn"),
    )
    .init();
}

fn build_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(Into::into)
}

fn log_version() {
    log::info!("{} v{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
}

fn main() -> Result<()> {
    let args = Args::parse();
    init_logger();

    match args.command {
        Command::GenerateToken { count } => {
            for _ in 0..count {
                println!("{}", auth::generate_agent_token());
            }
            Ok(())
        }
        command => build_runtime()?.block_on(run_async(command)),
    }
}

async fn run_async(command: Command) -> Result<()> {
    match command {
        Command::Run {
            config: config_path,
            default_config,
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
            let auto_reconnect = if auto_reconnect {
                Some(true)
            } else if no_auto_reconnect {
                Some(false)
            } else {
                None
            };
            let cli = AgentFileConfig {
                server_node_id,
                auth_token,
                auth_token_file,
                relay_urls: (!relay_urls.is_empty()).then_some(relay_urls),
                dns_server,
                auto_reconnect,
                max_reconnect_attempts,
            };
            let file = load_agent_config(config_path.as_deref(), default_config)?;
            run_agent(resolve_agent(cli, file)).await
        }
        Command::GenerateToken { .. } => unreachable!("handled synchronously in main()"),
    }
}

async fn run_agent(r: ResolvedAgent) -> Result<()> {
    // Enforce a single agent process per machine before doing anything else. Held
    // for the whole run; released automatically on exit/crash.
    let _lock = lock::AgentLock::acquire()?;

    // The agent's identity is its stable machine id (its iroh node id is
    // ephemeral). This is what the server routes to and reserves in [agent_routes].
    let machine_id = read_machine_id()?;
    log::info!("Agent machine id: {machine_id}");

    let server_node_id = r.server_node_id.context(
        "The agent requires a server node id (--server-node-id or server_node_id in the config).",
    )?;

    if r.auth_token.is_some() && r.auth_token_file.is_some() {
        anyhow::bail!("Provide only one of auth_token or auth_token_file, not both");
    }
    let token = if let Some(token) = r.auth_token {
        auth::validate_agent_token(&token).context("Invalid agent authentication token")?;
        token
    } else if let Some(path) = r.auth_token_file {
        auth::load_auth_token_from_file(&path, auth::AGENT_TOKEN_PREFIX)
            .context("Failed to load agent authentication token from file")?
    } else {
        anyhow::bail!(
            "The agent requires an authentication token.\n\
             Use --auth-token <TOKEN>, --auth-token-file <FILE>, or set \
             auth_token/auth_token_file in the config.\n\
             Generate one with: flextunnel-agent generate-token"
        );
    };

    // Ephemeral iroh identity (like the client): no persistent secret key. The
    // agent is identified by its machine id, not its node id.
    let endpoint = create_client_endpoint(&r.relay_urls, r.dns_server.as_deref())
        .await
        .context("Failed to create iroh endpoint")?;
    log::info!("flextunnel agent Node ID (ephemeral): {}", endpoint.id());

    let agent = ProxyAgent::new(AgentConfig {
        server_node_id,
        machine_id,
        auth_token: token,
        relay_urls: r.relay_urls,
        auto_reconnect: r.auto_reconnect,
        max_reconnect_attempts: r.max_reconnect_attempts,
    });

    let run = async {
        agent
            .run(&endpoint)
            .await
            .map_err(|e| anyhow::anyhow!("Agent error: {e}"))
    };

    let res = tokio::select! {
        res = run => res,
        _ = shutdown_signal() => {
            log::info!("Received shutdown signal, stopping agent");
            Ok(())
        }
    };

    // Close the endpoint gracefully before it is dropped (see flextunnel-cli).
    endpoint.close().await;
    res
}

/// Read this machine's stable, OS-native id via the `machine-uid` crate
/// (`/etc/machine-id` on Linux, `IOPlatformUUID` on macOS, `MachineGuid` on
/// Windows). Errors if it can't be determined or is empty.
fn read_machine_id() -> Result<String> {
    // `machine_uid::get()` returns a `Box<dyn Error>` (not Send+Sync), so flatten
    // it to a message rather than propagating it directly through `anyhow`.
    let id = machine_uid::get()
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("Failed to determine this machine's id")?;
    let id = id.trim().to_string();
    if id.is_empty() {
        anyhow::bail!("The OS returned an empty machine id");
    }
    Ok(id)
}

/// Resolve the config file to load, if any (explicit path or `--default-config`).
fn resolve_config_path(path: Option<&Path>, default_config: bool) -> Result<Option<PathBuf>> {
    if let Some(p) = path {
        Ok(Some(expand_tilde(p)))
    } else if default_config {
        let home = dirs::home_dir()
            .context("Could not determine the default config directory; pass -c <FILE> instead")?;
        Ok(Some(home.join(".config").join("flextunnel").join("agent.toml")))
    } else {
        Ok(None)
    }
}

/// Load the agent config file (explicit path or `--default-config`), or `None`.
fn load_agent_config(path: Option<&Path>, default_config: bool) -> Result<Option<AgentFileConfig>> {
    match resolve_config_path(path, default_config)? {
        Some(p) => {
            let content = std::fs::read_to_string(&p)
                .with_context(|| format!("Failed to read config file: {}", p.display()))?;
            let cfg = toml::from_str(&content)
                .with_context(|| format!("Failed to parse config file: {}", p.display()))?;
            Ok(Some(cfg))
        }
        None => Ok(None),
    }
}

/// Merge CLI-provided values over file values over defaults.
fn resolve_agent(cli: AgentFileConfig, file: Option<AgentFileConfig>) -> ResolvedAgent {
    let file = file.unwrap_or_default();

    // Token group merged as a unit per source (mirrors flextunnel-core's config).
    let (auth_token, auth_token_file) = if cli.auth_token.is_some() || cli.auth_token_file.is_some() {
        (cli.auth_token, cli.auth_token_file)
    } else {
        (file.auth_token, file.auth_token_file)
    };

    ResolvedAgent {
        server_node_id: cli.server_node_id.or(file.server_node_id),
        auth_token,
        auth_token_file: auth_token_file.map(|p| expand_tilde(&p)),
        relay_urls: cli.relay_urls.or(file.relay_urls).unwrap_or_default(),
        dns_server: cli.dns_server.or(file.dns_server),
        auto_reconnect: cli.auto_reconnect.or(file.auto_reconnect).unwrap_or(true),
        max_reconnect_attempts: cli.max_reconnect_attempts.or(file.max_reconnect_attempts),
    }
}

/// Wait for a shutdown signal: SIGTERM/SIGINT on Unix, Ctrl-C elsewhere
/// (mirrors the CLI's handler).
#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    let mut int = signal(SignalKind::interrupt()).expect("install SIGINT handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
