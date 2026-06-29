//! flextunnel
//!
//! A SOCKS5-over-QUIC proxy via iroh P2P connections. The client runs a local
//! SOCKS5 listener; each CONNECT is tunneled as a reliable QUIC bi-stream to the
//! server, which resolves DNS and connects to the target from its own network.
//! Uses an ALPN "knock" + auth tokens for access control and TLS 1.3/QUIC for
//! encryption. Neither side needs admin/root (no TUN device).

mod auth;
mod config;
mod error;
mod proxy;
mod secret;
mod transport;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use crate::proxy::signaling::build_alpn;
use crate::proxy::{ClientConfig, ProxyClient, ProxyServer};
use crate::transport::endpoint::{
    create_client_endpoint, create_server_endpoint, load_secret, load_secret_from_string,
};

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
    /// Proxy server commands.
    Server {
        #[command(subcommand)]
        action: ServerAction,
    },
    /// Proxy client commands.
    Client {
        #[command(subcommand)]
        action: ClientAction,
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
    ShowServerId {
        /// Path to the private key file.
        #[arg(short, long)]
        secret_file: PathBuf,
    },
    /// Generate client authentication token(s).
    GenerateAuthToken {
        /// Number of tokens to generate.
        #[arg(short, long, default_value = "1")]
        count: usize,
    },
    /// Generate an ALPN token (shared pre-handshake "knock" secret).
    GenerateAlpnToken {
        /// Number of tokens to generate.
        #[arg(short, long, default_value = "1")]
        count: usize,
    },
}

#[derive(Subcommand)]
enum ServerAction {
    /// Start the proxy server.
    Start {
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
        /// ALPN token (shared "knock" secret; must match clients).
        #[arg(long)]
        alpn_token: Option<String>,
        /// File containing the ALPN token.
        #[arg(long)]
        alpn_token_file: Option<PathBuf>,
        /// Custom relay server URL(s) for failover (repeatable).
        #[arg(long = "relay-url")]
        relay_urls: Vec<String>,
        /// Custom DNS server URL for peer discovery ("none" to disable).
        #[arg(long)]
        dns_server: Option<String>,
    },
}

#[derive(Subcommand)]
enum ClientAction {
    /// Start the proxy client (local SOCKS5 listener).
    Start {
        /// Config file path (TOML). CLI flags override file values.
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,
        /// Load config from ~/.config/flextunnel/client.toml.
        #[arg(long)]
        default_config: bool,
        /// Local address for the SOCKS5 listener (default 127.0.0.1:1080).
        #[arg(long)]
        socks_listen: Option<SocketAddr>,
        /// EndpointId of the server to connect to.
        #[arg(short = 'n', long)]
        server_node_id: Option<String>,
        /// Authentication token to send to the server.
        #[arg(long)]
        auth_token: Option<String>,
        /// File containing the authentication token.
        #[arg(long)]
        auth_token_file: Option<PathBuf>,
        /// ALPN token (shared "knock" secret; must match the server).
        #[arg(long)]
        alpn_token: Option<String>,
        /// File containing the ALPN token.
        #[arg(long)]
        alpn_token_file: Option<PathBuf>,
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
}

/// Resolve and validate the required ALPN token from an inline value or a file.
fn resolve_alpn_token(inline: Option<&str>, file: Option<&Path>) -> Result<String> {
    if inline.is_some() && file.is_some() {
        anyhow::bail!("Provide only one of --alpn-token or --alpn-token-file, not both");
    }
    if let Some(token) = inline {
        auth::validate_alpn_token(token).context("Invalid ALPN token")?;
        Ok(token.to_string())
    } else if let Some(path) = file {
        auth::load_alpn_token_from_file(path).context("Failed to load ALPN token from file")
    } else {
        anyhow::bail!(
            "An ALPN token is required.\n\
             Generate one with: flextunnel generate-alpn-token\n\
             Then pass --alpn-token <TOKEN> or --alpn-token-file <FILE>."
        );
    }
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
        Command::GenerateServerKey { output, force } => secret::generate_secret(output, force),
        Command::ShowServerId { secret_file } => secret::show_id(secret_file),
        Command::GenerateAuthToken { count } => {
            for _ in 0..count {
                println!("{}", auth::generate_token());
            }
            Ok(())
        }
        Command::GenerateAlpnToken { count } => {
            for _ in 0..count {
                println!("{}", auth::generate_alpn_token());
            }
            Ok(())
        }
        command => build_runtime()?.block_on(run_async(command)),
    }
}

async fn run_async(command: Command) -> Result<()> {
    match command {
        Command::Server {
            action:
                ServerAction::Start {
                    config: config_path,
                    default_config,
                    secret_file,
                    auth_tokens,
                    auth_tokens_file,
                    alpn_token,
                    alpn_token_file,
                    relay_urls,
                    dns_server,
                },
        } => {
            log_version();
            let cli = config::ServerConfig {
                secret_file,
                secret: None, // no inline-secret CLI flag; config file only
                auth_tokens: (!auth_tokens.is_empty()).then_some(auth_tokens),
                auth_tokens_file,
                alpn_token,
                alpn_token_file,
                relay_urls: (!relay_urls.is_empty()).then_some(relay_urls),
                dns_server,
            };
            let file = config::load_server_config(config_path.as_deref(), default_config)?;
            run_server(config::resolve_server(cli, file)).await
        }
        Command::Client {
            action:
                ClientAction::Start {
                    config: config_path,
                    default_config,
                    socks_listen,
                    server_node_id,
                    auth_token,
                    auth_token_file,
                    alpn_token,
                    alpn_token_file,
                    relay_urls,
                    dns_server,
                    auto_reconnect,
                    no_auto_reconnect,
                    max_reconnect_attempts,
                },
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
                auth_token,
                auth_token_file,
                alpn_token,
                alpn_token_file,
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

async fn run_server(r: config::ResolvedServer) -> Result<()> {
    let valid_tokens = auth::load_auth_tokens(&r.auth_tokens, r.auth_tokens_file.as_deref())
        .context("Failed to load authentication tokens")?;
    if valid_tokens.is_empty() {
        anyhow::bail!(
            "The server requires at least one authentication token.\n\
             Generate one with: flextunnel generate-auth-token\n\
             Then pass --auth-token <TOKEN>, --auth-tokens-file <FILE>, or set \
             auth_tokens/auth_tokens_file in the config."
        );
    }
    log::info!("Loaded {} authentication token(s)", valid_tokens.len());

    let alpn_token = resolve_alpn_token(r.alpn_token.as_deref(), r.alpn_token_file.as_deref())?;
    let alpn = build_alpn(&alpn_token);

    let secret_key = match (r.secret.as_deref(), r.secret_file.as_deref()) {
        (Some(_), Some(_)) => anyhow::bail!("Provide only one of secret or secret_file, not both"),
        (Some(s), None) => load_secret_from_string(s).context("Invalid inline secret key")?,
        (None, Some(path)) => load_secret(path).context("Failed to load secret key")?,
        (None, None) => anyhow::bail!(
            "The server requires a secret key.\n\
             Generate one with: flextunnel generate-server-key -o <FILE>\n\
             Then pass --secret-file <FILE> or set secret_file/secret in the config."
        ),
    };

    let endpoint = create_server_endpoint(&r.relay_urls, secret_key, r.dns_server.as_deref(), &alpn)
        .await
        .context("Failed to create iroh endpoint")?;

    log::info!("flextunnel server Node ID: {}", endpoint.id());
    log::info!(
        "Clients connect with: flextunnel client start --server-node-id {} --auth-token <TOKEN> --alpn-token <ALPN_TOKEN>",
        endpoint.id()
    );

    let server = ProxyServer::new(valid_tokens);
    let run = async {
        server
            .run(&endpoint)
            .await
            .map_err(|e| anyhow::anyhow!("Server error: {e}"))
    };

    let res = tokio::select! {
        res = run => res,
        _ = shutdown_signal() => {
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
        auth::validate_token(&token).context("Invalid authentication token")?;
        token
    } else if let Some(path) = r.auth_token_file {
        auth::load_auth_token_from_file(&path)
            .context("Failed to load authentication token from file")?
    } else {
        anyhow::bail!(
            "The client requires an authentication token.\n\
             Use --auth-token <TOKEN>, --auth-token-file <FILE>, or set \
             auth_token/auth_token_file in the config."
        );
    };

    let alpn_token = resolve_alpn_token(r.alpn_token.as_deref(), r.alpn_token_file.as_deref())?;
    let alpn = build_alpn(&alpn_token);

    let endpoint = create_client_endpoint(&r.relay_urls, r.dns_server.as_deref())
        .await
        .context("Failed to create iroh endpoint")?;
    log::info!("flextunnel client Node ID: {}", endpoint.id());

    let client = ProxyClient::new(ClientConfig {
        server_node_id,
        auth_token: token,
        alpn,
        socks_listen: r.socks_listen,
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
        _ = shutdown_signal() => {
            log::info!("Received shutdown signal, stopping client");
            Ok(())
        }
    };

    // Close the endpoint gracefully before it is dropped (see run_server).
    endpoint.close().await;
    res
}

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
