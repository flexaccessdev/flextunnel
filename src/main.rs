//! flextunnel
//!
//! A SOCKS5-over-QUIC proxy via iroh P2P connections. The client runs a local
//! SOCKS5 listener; each CONNECT is tunneled as a reliable QUIC bi-stream to the
//! server, which resolves DNS and connects to the target from its own network.
//! Uses an ALPN "knock" + auth tokens for access control and TLS 1.3/QUIC for
//! encryption. Neither side needs admin/root (no TUN device).

mod auth;
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
use crate::transport::endpoint::{create_client_endpoint, create_server_endpoint, load_secret};

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
        /// Secret key file for the server's persistent identity.
        #[arg(long)]
        secret_file: PathBuf,
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
        /// Local address for the SOCKS5 listener.
        #[arg(long, default_value = "127.0.0.1:1080")]
        socks_listen: SocketAddr,
        /// EndpointId of the server to connect to.
        #[arg(short = 'n', long)]
        server_node_id: String,
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
        /// Disable auto-reconnect (exit on the first disconnection).
        #[arg(long)]
        no_auto_reconnect: bool,
        /// Cap on reconnect attempts between successful connections (unlimited if unset).
        #[arg(long)]
        max_reconnect_attempts: Option<NonZeroU32>,
    },
}

/// Resolve and validate the required ALPN token from an inline value or a file.
fn resolve_alpn_token(inline: Option<&str>, file: Option<&Path>) -> Result<String> {
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
            run_server(
                secret_file,
                auth_tokens,
                auth_tokens_file,
                alpn_token,
                alpn_token_file,
                relay_urls,
                dns_server,
            )
            .await
        }
        Command::Client {
            action:
                ClientAction::Start {
                    socks_listen,
                    server_node_id,
                    auth_token,
                    auth_token_file,
                    alpn_token,
                    alpn_token_file,
                    relay_urls,
                    dns_server,
                    no_auto_reconnect,
                    max_reconnect_attempts,
                },
        } => {
            log_version();
            run_client(
                socks_listen,
                server_node_id,
                auth_token,
                auth_token_file,
                alpn_token,
                alpn_token_file,
                relay_urls,
                dns_server,
                !no_auto_reconnect,
                max_reconnect_attempts,
            )
            .await
        }
        _ => unreachable!("synchronous commands handled in main()"),
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_server(
    secret_file: PathBuf,
    auth_tokens: Vec<String>,
    auth_tokens_file: Option<PathBuf>,
    alpn_token: Option<String>,
    alpn_token_file: Option<PathBuf>,
    relay_urls: Vec<String>,
    dns_server: Option<String>,
) -> Result<()> {
    let valid_tokens = auth::load_auth_tokens(&auth_tokens, auth_tokens_file.as_deref())
        .context("Failed to load authentication tokens")?;
    if valid_tokens.is_empty() {
        anyhow::bail!(
            "The server requires at least one authentication token.\n\
             Generate one with: flextunnel generate-auth-token\n\
             Then pass --auth-token <TOKEN> or --auth-tokens-file <FILE>."
        );
    }
    log::info!("Loaded {} authentication token(s)", valid_tokens.len());

    let alpn_token = resolve_alpn_token(alpn_token.as_deref(), alpn_token_file.as_deref())?;
    let alpn = build_alpn(&alpn_token);

    let secret_key = load_secret(&secret_file).context("Failed to load secret key")?;

    let endpoint = create_server_endpoint(&relay_urls, secret_key, dns_server.as_deref(), &alpn)
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

#[allow(clippy::too_many_arguments)]
async fn run_client(
    socks_listen: SocketAddr,
    server_node_id: String,
    auth_token: Option<String>,
    auth_token_file: Option<PathBuf>,
    alpn_token: Option<String>,
    alpn_token_file: Option<PathBuf>,
    relay_urls: Vec<String>,
    dns_server: Option<String>,
    auto_reconnect: bool,
    max_reconnect_attempts: Option<NonZeroU32>,
) -> Result<()> {
    let token = if let Some(token) = auth_token {
        auth::validate_token(&token).context("Invalid authentication token")?;
        token
    } else if let Some(path) = auth_token_file {
        auth::load_auth_token_from_file(&path)
            .context("Failed to load authentication token from file")?
    } else {
        anyhow::bail!(
            "The client requires an authentication token.\n\
             Use --auth-token <TOKEN> or --auth-token-file <FILE>."
        );
    };

    let alpn_token = resolve_alpn_token(alpn_token.as_deref(), alpn_token_file.as_deref())?;
    let alpn = build_alpn(&alpn_token);

    let endpoint = create_client_endpoint(&relay_urls, dns_server.as_deref())
        .await
        .context("Failed to create iroh endpoint")?;
    log::info!("flextunnel client Node ID: {}", endpoint.id());

    let client = ProxyClient::new(ClientConfig {
        server_node_id,
        auth_token: token,
        alpn,
        socks_listen,
        relay_urls,
        auto_reconnect,
        max_reconnect_attempts,
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
