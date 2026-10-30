//! flextunnel
//!
//! A SOCKS5/HTTP-proxy- and port-forward-over-QUIC split tunnel via iroh P2P
//! connections. The
//! client runs optional local SOCKS5/HTTP proxy listeners and server-direct
//! port forwards (declared in its config; `flextunnel client control` shows
//! their state); routed
//! targets are tunneled as reliable QUIC bi-streams to the server, which
//! resolves DNS and connects from its own network. Uses a fixed ALPN for
//! protocol selection, client keypairs (ed25519) for access control, and TLS
//! 1.3/QUIC for encryption. Neither side needs admin/root (no TUN device).

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::io::IsTerminal;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

mod client_session;
mod instance;
mod ipc;
mod lock;
mod nc;
#[cfg(windows)]
mod pipe_security;
mod prompt;
mod tui;

use flextunnel_core::app;
use flextunnel_core::iroh::{EndpointId, SecretKey};
use flextunnel_core::secret::secret_to_endpoint_id;
use flextunnel_core::{auth, config, secret, server};

#[derive(Parser)]
#[command(name = "flextunnel")]
#[command(version)]
#[command(about = "SOCKS5/HTTP proxy and port forwards over QUIC — split tunnel via iroh P2P")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the proxy server.
    #[command(arg_required_else_help = true)]
    Server {
        #[command(subcommand)]
        action: ServerAction,
    },
    /// Start or control the proxy client.
    #[command(arg_required_else_help = true)]
    Client {
        #[command(subcommand)]
        action: ClientAction,
    },
    /// Generate a new iroh private key for persistent server identity.
    GenerateIrohKey {
        /// Path where to save the private key file. Defaults to stdout ("-").
        #[arg(short, long, default_value = "-")]
        output: PathBuf,
        /// Overwrite existing file if it exists.
        #[arg(long)]
        force: bool,
        /// Print machine-readable JSON to stdout (for automation).
        #[arg(long)]
        json: bool,
    },
    /// Show the public iroh id (EndpointId) derived from an iroh private key.
    #[command(arg_required_else_help = true)]
    ShowIrohId {
        /// Config file path (TOML). CLI flags override file values.
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,
        /// Load config from ~/.config/flextunnel/server.toml.
        #[arg(long)]
        default_config: bool,
        /// Path to the private key file (overrides secret_file/secret in the config).
        #[arg(short, long)]
        secret_file: Option<PathBuf>,
        /// Print machine-readable JSON to stdout (for automation).
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum ServerAction {
    /// Start the proxy server (SOCKS5/HTTP proxy over QUIC). Needs at least one
    /// flag: `-c`/other options load a config (the default
    /// ~/.config/flextunnel/server.toml with --default-config), or `--quick`
    /// runs an ephemeral one-off server. Run with no arguments to print this help.
    #[command(arg_required_else_help = true)]
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
        /// File of authorized client public keys (ssh authorized_keys style:
        /// one `ed25519-pub:...` per line, optional trailing comment).
        #[arg(long)]
        authorized_keys_file: Option<PathBuf>,
        /// Custom relay server URL(s) for failover (repeatable).
        #[arg(long = "relay-url")]
        relay_urls: Vec<String>,
        /// Shared bearer token sent to every custom relay (custom relays only).
        #[arg(long)]
        relay_auth_token: Option<String>,
        /// Ephemeral one-off server. Run `client start --quick` FIRST — it
        /// prints the client's EndpointId; enter that id at this server's
        /// prompt to allowlist it as the only allowed client (no auth
        /// keypair). Generates an in-memory identity, full-tunnels all
        /// traffic, prints this server's EndpointId to enter back at the
        /// client's prompt, and exits if the client doesn't connect within 5
        /// minutes. Needs an interactive terminal. Nothing is persisted.
        #[arg(
            long,
            conflicts_with_all = ["config", "default_config", "secret_file",
                "authorized_keys_file"]
        )]
        quick: bool,
    },
}

#[derive(Subcommand)]
enum ClientAction {
    /// Start the proxy client (optional SOCKS5 + HTTP proxy listeners, plus the
    /// port forwards declared in the config). Needs at least one flag: `-c`/other options load a config (the
    /// default ~/.config/flextunnel/client.toml when no -c is given), or
    /// `--quick` prompts for the connection details without persisting them. Run
    /// with no arguments to print this help.
    #[command(arg_required_else_help = true)]
    Start {
        /// Config file path (TOML). CLI flags override file values. Without
        /// this, ~/.config/flextunnel/client.toml is used if it exists.
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,
        /// Loopback port for the optional SOCKS5 listener (binds 127.0.0.1
        /// only), e.g. 1080. Disabled unless set here or in the config.
        #[arg(long)]
        socks_port: Option<u16>,
        /// Loopback port for the optional HTTP proxy listener (CONNECT +
        /// plain-HTTP forwarding; binds 127.0.0.1 only), e.g. 8081. Disabled
        /// unless set.
        #[arg(long)]
        http_port: Option<u16>,
        /// EndpointId of the server to connect to.
        #[arg(short = 'n', long)]
        server_node_id: Option<String>,
        /// Inline client secret key (`ed25519-sec:...`) used to
        /// authenticate to the server.
        #[arg(long, conflicts_with = "auth_key_file")]
        auth_key: Option<String>,
        /// File containing the client secret key (from `flexaccess-keys
        /// generate-auth-key`).
        #[arg(long)]
        auth_key_file: Option<PathBuf>,
        /// Custom relay server URL(s) for failover (repeatable).
        #[arg(long = "relay-url")]
        relay_urls: Vec<String>,
        /// Shared bearer token sent to every custom relay (custom relays only).
        #[arg(long)]
        relay_auth_token: Option<String>,
        /// Force auto-reconnect on (overrides `auto_reconnect = false` in the config).
        #[arg(long, conflicts_with = "no_auto_reconnect")]
        auto_reconnect: bool,
        /// Disable auto-reconnect (exit on the first failed connection attempt or drop).
        #[arg(long, conflicts_with = "auto_reconnect")]
        no_auto_reconnect: bool,
        /// Cap on consecutive retries before giving up (unlimited if unset).
        #[arg(long)]
        max_reconnect_attempts: Option<NonZeroU32>,
        /// Ignore any saved config, print this client's EndpointId (enter it on
        /// the quick server, which allowlists it — no auth keypair), and
        /// prompt for the server EndpointId (pairs with `server start
        /// --quick`). Nothing is persisted.
        #[arg(long, conflicts_with_all = ["config", "auth_key", "auth_key_file"])]
        quick: bool,
    },
    /// Attach the read-only control panel to the running client for a profile:
    /// live status and the state of its config-declared port forwards (in this
    /// terminal). The client is
    /// identified by the profile's server node id; with no flags, the default
    /// config (~/.config/flextunnel/client.toml) selects it.
    Control {
        /// Config file path (TOML) of the profile to attach to. With no flags,
        /// ~/.config/flextunnel/client.toml selects the profile.
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,
        /// Attach by server EndpointId directly (overrides the config file).
        #[arg(short = 'n', long)]
        server_node_id: Option<String>,
    },
    /// Relay stdin/stdout through the running client to HOST:PORT on the
    /// server side, for SSH's `ProxyCommand`:
    /// `ProxyCommand flextunnel client nc -c <profile.toml> %h %p`. Like a port
    /// forward, the server enforces its routed set and resolves HOST. The
    /// client is picked the same way as for `client control`.
    #[command(arg_required_else_help = true)]
    Nc {
        /// Config file path (TOML) of the profile whose client to use. With
        /// no flags, ~/.config/flextunnel/client.toml selects the profile.
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,
        /// Use the client for this server EndpointId directly (overrides the
        /// config file).
        #[arg(short = 'n', long)]
        server_node_id: Option<String>,
        /// Target host, resolved by the server.
        host: String,
        /// Target port.
        port: u16,
    },
}

fn log_version() {
    app::log_version(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
}

/// Whether the command runs with the stderr logger. Not for `client start
/// --quick`, whose in-process TUI must own the terminal without a logger
/// writing over it, nor `client nc`, which runs under ssh and only reports
/// its own errors.
fn wants_logger(command: &Command) -> bool {
    !matches!(
        command,
        Command::Client {
            action: ClientAction::Start { quick: true, .. } | ClientAction::Nc { .. }
        }
    )
}

fn main() -> Result<()> {
    let args = Args::parse();
    // `log::*` calls are silent no-ops when the logger is not set.
    if wants_logger(&args.command) {
        app::init_logger(app::DEFAULT_LOG_FILTER);
    }

    match args.command {
        // The control panel drives the terminal with its own blocking event
        // loop (and a small runtime for the IPC calls), so it never enters the
        // shared multi-thread runtime below.
        Command::Client {
            action:
                ClientAction::Control {
                    config,
                    server_node_id,
                },
        } => tui::run(config, server_node_id),
        // Runs its own small runtime, like `client control`.
        Command::Client {
            action:
                ClientAction::Nc {
                    config,
                    server_node_id,
                    host,
                    port,
                },
        } => nc::run(config, server_node_id, host, port),
        Command::GenerateIrohKey { output, force, json } => {
            secret::generate_iroh_key(output, force, json)
        }
        Command::ShowIrohId {
            config,
            default_config,
            secret_file,
            json,
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
            secret::show_iroh_id(r.secret_file.as_deref(), json)
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
            action:
                ServerAction::Start {
                    config: config_path,
                    default_config,
                    secret_file,
                    authorized_keys_file,
                    relay_urls,
                    relay_auth_token,
                    quick,
                },
        } => {
            log_version();
            if quick {
                // Ephemeral one-off server: prompt for the client's endpoint id
                // and natively allowlist it as the only allowed (quick) client —
                // no auth keypair — then mint an in-memory identity, full-tunnel
                // everything, print the bootstrap, and exit if no client
                // connects within QUICK_IDLE_TIMEOUT. `--quick` conflicts with
                // the config/secret/token flags (clap-enforced), so the
                // ephemeral values are the whole configuration. The prompt
                // needs a TTY, so a piped `--quick` fails fast.
                if !std::io::stdin().is_terminal() {
                    anyhow::bail!("`server start --quick` needs an interactive terminal.");
                }
                println!(
                    "Quick mode — ephemeral server, full tunnel (all traffic routed). Nothing saved."
                );
                println!(
                    "Start the client first if you haven't: `flextunnel client start --quick` \
                     prints the client EndpointId to enter below."
                );
                let client_id = tokio::task::spawn_blocking(|| {
                    prompt::prompt_endpoint_id(
                        "Client EndpointId (shown by `flextunnel client start --quick`)",
                    )
                })
                .await??;
                let (cli, secret) = quick_server_config(relay_urls, relay_auth_token);
                print_quick_server_bootstrap(&secret_to_endpoint_id(&secret));
                return run_server(
                    config::resolve_server(cli, None)?,
                    Some(QuickServer { client_id, secret }),
                )
                .await;
            }
            let cli = config::ServerConfig {
                secret_file,
                authorized_keys_file,
                relay_urls: (!relay_urls.is_empty()).then_some(relay_urls),
                relay_auth_token,
                host_aliases: None, // config-file only; no CLI flag
                routed_domains: None, // config-file only; no CLI flag
                routed_cidrs: None,   // config-file only; no CLI flag
                dns_forwards: None,   // config-file only; no CLI flag
                bridges: None,        // config-file only; no CLI flag
                allowed_bridge_servers: None, // config-file only; no CLI flag
            };
            let file = config::load_server_config(config_path.as_deref(), default_config)?;
            run_server(config::resolve_server(cli, file)?, None).await
        }
        Command::Client {
            action:
                ClientAction::Start {
                    config: config_path,
                    socks_port,
                    http_port,
                    server_node_id,
                    auth_key,
                    auth_key_file,
                    relay_urls,
                    relay_auth_token,
                    auto_reconnect,
                    no_auto_reconnect,
                    max_reconnect_attempts,
                    quick,
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
            let mut cli = config::ClientConfig {
                server_node_id,
                name: None, // display name is config-file only; no CLI flag
                socks_port,
                http_port,
                auth_key,
                auth_key_file,
                relay_urls: (!relay_urls.is_empty()).then_some(relay_urls),
                relay_auth_token,
                auto_reconnect,
                max_reconnect_attempts,
                forwards: None, // config-file only; no CLI flag
            };
            // `--quick` is a self-contained ephemeral session: it ignores any
            // saved config, mints a session identity whose EndpointId is the
            // credential (printed here for the user to allowlist on the quick
            // server — no auth keypair), prompts for the remaining connection
            // details, and then runs a live control panel in this terminal
            // (pairs with `server start --quick`). Both the prompt and the
            // panel need a TTY, so a piped `--quick` fails fast instead of
            // hanging. Nothing is persisted and no control socket is exposed.
            // A bare `client start` never reaches here — clap prints help
            // (arg_required_else_help).
            if quick {
                if !std::io::stdin().is_terminal() {
                    anyhow::bail!("`client start --quick` needs an interactive terminal.");
                }
                let client_secret = SecretKey::generate();
                println!("Quick mode. Enter connection details (nothing will be saved):");
                println!(
                    "  Your client EndpointId: {}",
                    secret_to_endpoint_id(&client_secret)
                );
                println!(
                    "Enter it at the `flextunnel server start --quick` prompt — it is this \
                     client's credential (no auth keypair)."
                );
                cli = tokio::task::spawn_blocking(move || {
                    prompt::fill_client_config(&mut cli).map(|()| cli)
                })
                .await??;
                return client_session::run_quick(config::resolve_client(cli, None), client_secret)
                    .await;
            }
            let file = config::load_client_config(config_path.as_deref())?;
            client_session::run(config::resolve_client(cli, file)).await
        }
        _ => unreachable!("synchronous commands handled in main()"),
    }
}

/// How long a `server start --quick` server waits for its first client before
/// exiting on its own. A one-shot grace window: once a client connects the timer
/// is cancelled for the rest of the process's life.
const QUICK_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Quick-mode (`server start --quick`) parameters for [`run_server`]: `Some`
/// arms the idle-exit grace timer, skips the single-instance lock and the
/// client-token requirement, and natively allowlists the one entered client id.
struct QuickServer {
    /// The single client endpoint id allowed to connect (over the quick ALPN);
    /// entered at the prompt, enforced by the endpoint's allowlist hook.
    client_id: EndpointId,
    /// The server's ephemeral in-memory identity. Carried here — never through
    /// the config, which quick mode does not use for keys.
    secret: SecretKey,
}

/// How long to wait for a graceful `endpoint.close()` during shutdown before
/// forcing exit. iroh's close normally completes promptly, but a lingering
/// relay/connection teardown must never leave the process unkillable.
const SHUTDOWN_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Build the ephemeral `ServerConfig` for `server start --quick`: a full-tunnel
/// routed set (`routed_domains = ["*"]`, `routed_cidrs = ["0.0.0.0/0", "::/0"]`)
/// plus a freshly generated in-memory identity, returned *alongside* the config —
/// quick mode never goes through config files, so no key rides in the config.
/// No client keys — the allowlisted client endpoint id is the sole credential.
/// Nothing is written to disk. `--relay-url` stays compatible with `--quick`,
/// so any relays are kept.
fn quick_server_config(
    relay_urls: Vec<String>,
    relay_auth_token: Option<String>,
) -> (config::ServerConfig, SecretKey) {
    let secret = SecretKey::generate();
    let cli = config::ServerConfig {
        routed_domains: Some(vec!["*".to_string()]),
        routed_cidrs: Some(vec!["0.0.0.0/0".to_string(), "::/0".to_string()]),
        relay_urls: (!relay_urls.is_empty()).then_some(relay_urls),
        relay_auth_token,
        ..Default::default()
    };
    (cli, secret)
}

/// Print the bootstrap line for a quick-mode server: the EndpointId to enter at
/// the client's prompt. The client is already running at this point — it was
/// started first to show the id just entered here — and is sitting at its
/// "Server EndpointId" prompt.
fn print_quick_server_bootstrap(endpoint_id: &EndpointId) {
    println!("  Server EndpointId: {endpoint_id}");
    println!("Enter it at the client's \"Server EndpointId\" prompt to connect.");
    println!("Waiting for the client — will exit in 5 minutes if it does not connect.");
}

async fn run_server(
    r: config::ResolvedServer,
    quick: Option<QuickServer>,
) -> Result<()> {
    // A quick server's identity is the ephemeral in-memory key it carries;
    // a regular server's comes from its key file.
    let (secret_key, quick_client) = match &quick {
        Some(q) => (q.secret.clone(), Some(q.client_id)),
        None => (secret::resolve_secret_key(r.secret_file.as_deref())?, None),
    };
    // Enforce one server per identity before doing any other work (held for
    // the process lifetime; released automatically on exit or crash) — except
    // a quick server, whose identity is fresh and in-memory, so it can never
    // be running twice.
    let _lock = match &quick {
        Some(_) => None,
        None => Some(server::acquire_server_lock(&secret_key.public())?),
    };

    // A quick server runs without client keys: its single allowlisted client
    // id is the whole credential set (enforced natively by the endpoint's hook).
    let authorized_keys = match &r.authorized_keys_file {
        Some(path) => auth::load_authorized_keys(path)
            .context("Failed to load the authorized client keys")?,
        None => Default::default(),
    };
    // Quick mode arms an idle-exit timer; the server fires this on the first
    // client to cancel it. `None` for a normal server (the timer never runs).
    let first_client = quick.as_ref().map(|_| Arc::new(Notify::new()));
    let prepared = server::prepare(server::ServerOptions {
        secret_key,
        authorized_keys,
        quick_client,
        first_client: first_client.clone(),
        relay_urls: r.relay_urls,
        relay_auth_token: r.relay_auth_token,
        host_aliases: r.host_aliases,
        routed_domains: r.routed_domains,
        routed_cidrs: r.routed_cidrs,
        dns_forwards: r.dns_forwards,
        bridges: r.bridges,
        allowed_bridge_servers: r.allowed_bridge_servers,
        blocklist_file: r.blocklist_file,
    })?;
    let running = prepared.bind().await?;

    match &quick {
        Some(_) => log::info!(
            "Quick mode: enter this server's EndpointId ({}) at the waiting client's prompt",
            running.endpoint().id()
        ),
        None => log::info!(
            "Clients connect with: flextunnel client start --server-node-id {} --auth-key-file <KEY FILE>",
            running.endpoint().id()
        ),
    }

    // Quick-mode grace window: fire after `QUICK_IDLE_TIMEOUT` unless a client
    // connects first (which resolves `notified()` and parks this future
    // forever). `first_client` is `Some` exactly in quick mode; a normal server
    // parks here immediately, so the arm never fires. `notify_one` stores a
    // permit, so a client that connects before this future is first polled is
    // not missed.
    let grace = async {
        match &first_client {
            Some(notify) => {
                tokio::select! {
                    _ = notify.notified() => std::future::pending::<()>().await,
                    _ = tokio::time::sleep(QUICK_IDLE_TIMEOUT) => {}
                }
            }
            None => std::future::pending::<()>().await,
        }
    };

    // Serve until the server ends, a shutdown signal arrives, or the
    // quick-mode grace expires.
    let res = tokio::select! {
        res = running.serve() => res,
        sig = app::shutdown_signal() => sig.map(|()| {
            log::info!("Received shutdown signal, stopping server");
        }),
        _ = grace => {
            log::warn!("Quick mode: no client connected within 5 minutes — exiting");
            Ok(())
        }
    };

    close_endpoint_or_exit(running.endpoint()).await;
    res
}

/// Close `endpoint` gracefully before it is dropped — skipping the close makes
/// iroh tear down its relay tasks via an ungraceful abort, which panics
/// (`JoinSet::join_all` on a cancelled task), fatal under panic=abort. But never
/// let a slow teardown make the process unkillable: once we are already shutting
/// down, a second shutdown signal (e.g. another Ctrl-C) or `SHUTDOWN_CLOSE_TIMEOUT`
/// forces an immediate clean exit. `std::process::exit` skips destructors, so it
/// avoids the very ungraceful-drop panic the graceful close exists to prevent.
/// Shared by the server ([`run_server`]) and the client (`client_session`).
pub(crate) async fn close_endpoint_or_exit(endpoint: &flextunnel_core::iroh::Endpoint) {
    tokio::select! {
        _ = endpoint.close() => {}
        _ = app::shutdown_signal() => {
            log::warn!("Second shutdown signal — exiting now");
            std::process::exit(0);
        }
        _ = tokio::time::sleep(SHUTDOWN_CLOSE_TIMEOUT) => {
            log::warn!("Endpoint close is taking too long — exiting now");
            std::process::exit(0);
        }
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    use clap::error::ErrorKind;

    #[test]
    fn client_requires_an_action() {
        let Err(error) = Args::try_parse_from(["flextunnel", "client"]) else {
            panic!("client without an action must be rejected");
        };
        assert_eq!(
            error.kind(),
            ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );
    }

    #[test]
    fn client_start_accepts_startup_flags() {
        let args = Args::try_parse_from([
            "flextunnel",
            "client",
            "start",
            "--server-node-id",
            "server-id",
            "--auth-key",
            "ed25519-sec:XXXX",
        ])
        .unwrap_or_else(|error| panic!("client start should parse: {error}"));

        assert!(matches!(
            args.command,
            Command::Client {
                action: ClientAction::Start { .. }
            }
        ));
    }

    #[test]
    fn bare_start_subcommands_show_help() {
        // `client start` / `server start` with no flags print help rather than
        // starting (arg_required_else_help): there is nothing to run with.
        for args in [
            ["flextunnel", "client", "start"],
            ["flextunnel", "server", "start"],
        ] {
            let Err(error) = Args::try_parse_from(args) else {
                panic!("bare {args:?} must display help, not parse");
            };
            assert_eq!(
                error.kind(),
                ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand,
                "{args:?}"
            );
        }
    }

    #[test]
    fn start_subcommands_parse_with_one_flag() {
        // A single flag satisfies arg_required_else_help and reaches dispatch.
        Args::try_parse_from(["flextunnel", "client", "start", "--socks-port", "1080"])
            .unwrap_or_else(|error| panic!("client start with a flag should parse: {error}"));
        Args::try_parse_from(["flextunnel", "server", "start", "--default-config"])
            .unwrap_or_else(|error| panic!("server start with a flag should parse: {error}"));
    }

    #[test]
    fn client_rejects_removed_default_config_flag() {
        for action in ["start", "control"] {
            let Err(error) =
                Args::try_parse_from(["flextunnel", "client", action, "--default-config"])
            else {
                panic!("--default-config must be rejected for client {action}");
            };
            assert_eq!(error.kind(), ErrorKind::UnknownArgument);
        }
    }

    #[test]
    fn client_rejects_legacy_startup_flags() {
        let Err(error) = Args::try_parse_from([
            "flextunnel",
            "client",
            "--server-node-id",
            "server-id",
        ]) else {
            panic!("startup flags without the start action must be rejected");
        };
        assert_eq!(error.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn server_start_parses_quick_flag() {
        let args = Args::try_parse_from(["flextunnel", "server", "start", "--quick"])
            .unwrap_or_else(|error| panic!("server start --quick should parse: {error}"));
        assert!(matches!(
            args.command,
            Command::Server {
                action: ServerAction::Start { quick: true, .. }
            }
        ));
    }

    #[test]
    fn client_start_parses_quick_flag() {
        let args = Args::try_parse_from(["flextunnel", "client", "start", "--quick"])
            .unwrap_or_else(|error| panic!("client start --quick should parse: {error}"));
        assert!(matches!(
            args.command,
            Command::Client {
                action: ClientAction::Start { quick: true, .. }
            }
        ));
    }

    #[test]
    fn quick_conflicts_with_config_and_secret() {
        // `--quick` mints everything ephemerally, so it is mutually exclusive
        // with the config/secret/key flags on both sides.
        let cases = [
            vec!["flextunnel", "server", "start", "--quick", "-c", "server.toml"],
            vec!["flextunnel", "server", "start", "--quick", "--secret-file", "k.key"],
            vec!["flextunnel", "server", "start", "--quick", "--authorized-keys-file", "ak.txt"],
            vec!["flextunnel", "client", "start", "--quick", "-c", "client.toml"],
            // Quick mode has no keypair auth at all (the credential is the
            // client's endpoint id), so key flags are rejected too.
            vec!["flextunnel", "client", "start", "--quick", "--auth-key", "ed25519-sec:X"],
            vec!["flextunnel", "client", "start", "--quick", "--auth-key-file", "c.key"],
        ];
        for case in cases {
            let Err(error) = Args::try_parse_from(&case) else {
                panic!("expected a conflict for {case:?}");
            };
            assert_eq!(error.kind(), ErrorKind::ArgumentConflict, "{case:?}");
        }
    }

    #[test]
    fn quick_server_config_is_full_tunnel_without_client_keys() {
        let (cli, _secret) = quick_server_config(Vec::new(), None);
        // No keypair auth in quick mode: the allowlisted client endpoint id is
        // the sole credential. The ephemeral identity is returned alongside —
        // never through the config, which carries no key at all.
        assert_eq!(cli.authorized_keys_file, None);
        assert_eq!(cli.secret_file, None);
        // Full tunnel: the catch-alls for domains and both IP families.
        assert_eq!(cli.routed_domains.as_deref(), Some(["*".to_string()].as_slice()));
        assert_eq!(
            cli.routed_cidrs.as_deref(),
            Some(["0.0.0.0/0".to_string(), "::/0".to_string()].as_slice())
        );
        // The config resolves (validation passes).
        config::resolve_server(cli, None).expect("quick config must resolve");
    }

    #[test]
    fn client_help_lists_all_actions() {
        let Err(error) = Args::try_parse_from(["flextunnel", "client", "help"]) else {
            panic!("help is rendered as a clap display-help result");
        };
        assert_eq!(error.kind(), ErrorKind::DisplayHelp);
        let help = error.to_string();
        assert!(help.contains("start"));
        assert!(help.contains("control"));
        assert!(help.contains("help"));
    }
}
