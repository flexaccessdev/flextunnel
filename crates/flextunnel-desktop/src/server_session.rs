//! The server session: the app's one server runs in-process, on its own OS
//! thread with its own Tokio runtime whose threads are named `server` — so
//! every log line it emits (core internals included) is attributed to it by
//! thread name (see `logging`), like the client sessions in [`crate::tunnel`].
//! Startup is the core's shared path ([`flextunnel_core::server`]), the same
//! one `flextunnel server start` runs, so the app's server validates and
//! behaves exactly like a CLI server with the same settings — and takes the
//! same per-user lock. Status is published as a snapshot the UI polls each
//! frame.

use crate::config::ServerConfig;
use flextunnel_core::server::{self, ServerOptions};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// The server session's thread name, and so its log tag (`[server]`).
pub const THREAD_NAME: &str = "server";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ServerPhase {
    Stopped,
    /// Validating and binding the endpoint (up to ~10s: the relay
    /// online-wait).
    Starting,
    Running,
    /// Closing the endpoint; the identity (and the per-user server lock) is
    /// still held until this finishes.
    Stopping,
    Failed,
}

#[derive(Clone)]
pub struct ServerSnapshot {
    pub phase: ServerPhase,
    pub running_since: Option<Instant>,
    pub last_error: Option<String>,
}

impl Default for ServerSnapshot {
    fn default() -> Self {
        Self {
            phase: ServerPhase::Stopped,
            running_since: None,
            last_error: None,
        }
    }
}

pub(crate) enum ServerCmd {
    Stop,
    /// Stop, then leave the snapshot reset rather than Stopped/Failed: the
    /// server was deleted, so nothing of this session should outlive it.
    Remove,
    Shutdown,
}

pub(crate) type SharedServerSnapshot = Arc<Mutex<ServerSnapshot>>;

/// The shared snapshot, written by the session task.
#[derive(Clone)]
struct ServerSlot {
    shared: SharedServerSnapshot,
}

impl ServerSlot {
    fn update<F: FnOnce(&mut ServerSnapshot)>(&self, f: F) {
        let mut snapshot = match self.shared.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        f(&mut snapshot);
    }

    fn fail(&self, reason: String) {
        log::error!("{reason}");
        self.update(|s| {
            *s = ServerSnapshot {
                phase: ServerPhase::Failed,
                last_error: Some(reason),
                ..ServerSnapshot::default()
            };
        });
    }
}

pub(crate) struct ServerHandle {
    pub tx: mpsc::Sender<ServerCmd>,
    /// Resolves when the session's thread finishes. The session keeps its
    /// command receiver until then, so `tx.is_closed()` also means "done".
    pub done: tokio::sync::oneshot::Receiver<()>,
}

/// Build the core options from the server config — the in-memory equivalent
/// of what the CLI loads from `server.toml` and its key files.
fn options(server: &ServerConfig) -> anyhow::Result<ServerOptions> {
    let secret_key = flextunnel_core::secret::load_secret_from_string(server.secret.trim())?;
    let authorized_keys = flextunnel_core::flexaccess_keys::parse_authorized_keys(
        &server.authorized_keys,
        "authorized keys",
    )?;
    let blocklist_file = flextunnel_core::blocklist::default_blocklist_path().ok_or_else(|| {
        anyhow::anyhow!(
            "Could not determine the home directory for the duplicate-id blocklist \
             (~/.config/flextunnel/blocklist.json)"
        )
    })?;
    Ok(ServerOptions {
        secret_key,
        authorized_keys,
        quick_client: None,
        first_client: None,
        relay_urls: server.relay_urls.clone(),
        relay_auth_token: server.relay_auth_token.clone(),
        host_aliases: HashMap::new(),
        routed_domains: server.routed_domains.clone(),
        routed_cidrs: server.routed_cidrs.clone(),
        dns_forwards: HashMap::new(),
        bridges: HashMap::new(),
        allowed_bridge_servers: Vec::new(),
        blocklist_file,
    })
}

/// Spawn the server session on its own OS thread with its own runtime, all
/// threads named [`THREAD_NAME`]. `None` when the thread could not be spawned
/// (the snapshot is set to Failed instead).
pub(crate) fn spawn_server(
    server: ServerConfig,
    shared: &SharedServerSnapshot,
) -> Option<ServerHandle> {
    let (tx, rx) = mpsc::channel(8);
    let (done_tx, done) = tokio::sync::oneshot::channel();
    let slot = ServerSlot {
        shared: shared.clone(),
    };
    let error_slot = slot.clone();
    let spawned = std::thread::Builder::new().name(THREAD_NAME.into()).spawn(move || {
        // Unlike a client session the server accepts many connections, so it
        // gets the multi-threaded runtime's default worker count.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .thread_name(THREAD_NAME)
            .enable_all()
            .build();
        match runtime {
            Ok(rt) => rt.block_on(run_server(server, rx, slot)),
            Err(e) => slot.fail(format!("Failed to start: {e:#}")),
        }
        let _ = done_tx.send(());
    });
    match spawned {
        Ok(_) => Some(ServerHandle { tx, done }),
        Err(e) => {
            error_slot.fail(format!("Failed to start: {e:#}"));
            None
        }
    }
}

async fn run_server(server: ServerConfig, mut rx: mpsc::Receiver<ServerCmd>, slot: ServerSlot) {
    slot.update(|s| {
        *s = ServerSnapshot {
            phase: ServerPhase::Starting,
            ..ServerSnapshot::default()
        };
    });
    // One server per user, shared with the CLI: held until the endpoint is
    // closed, so a stop-then-start can never run two endpoints with one
    // identity.
    let _lock = match server::acquire_server_lock() {
        Ok(lock) => lock,
        Err(e) => return slot.fail(format!("{e:#}")),
    };
    let prepared = match options(&server).and_then(server::prepare) {
        Ok(prepared) => prepared,
        Err(e) => return slot.fail(format!("{e:#}")),
    };

    // Binding can block for up to ~10s (the relay online-wait), so it races
    // the command channel — otherwise a Stop issued during it would not show
    // until it finished. It runs as a spawned task rather than a raced future
    // because cancelling it by drop could drop a bound endpoint without
    // `close()`, which is fatal under panic=abort. For the same reason a stop
    // waits the bind out instead of giving up on it: returning early would
    // drop this runtime, and the task with it. (On app quit the process exits
    // without waiting for this thread, which drops nothing.)
    let mut bind = tokio::spawn(prepared.bind());
    let running = tokio::select! {
        bound = &mut bind => match bound.map_err(anyhow::Error::from) {
            Ok(Ok(running)) => running,
            Ok(Err(e)) | Err(e) => return slot.fail(format!("{e:#}")),
        },
        cmd = rx.recv() => {
            if matches!(cmd, Some(ServerCmd::Stop | ServerCmd::Remove)) {
                log::info!("Stopping the server");
            }
            slot.update(|s| s.phase = ServerPhase::Stopping);
            if let Ok(Ok(running)) = bind.await {
                close(&running).await;
            }
            return finish(&slot, cmd, Ok(()));
        }
    };
    log::info!("Server running — clients connect to {}", running.endpoint().id());
    slot.update(|s| {
        s.phase = ServerPhase::Running;
        s.running_since = Some(Instant::now());
    });

    let (cmd, result) = tokio::select! {
        res = running.serve() => (None, res),
        cmd = rx.recv() => {
            if matches!(cmd, Some(ServerCmd::Stop | ServerCmd::Remove)) {
                log::info!("Stopping the server");
            }
            (cmd, Ok(()))
        }
    };
    slot.update(|s| {
        s.phase = ServerPhase::Stopping;
        s.running_since = None;
    });
    close(&running).await;
    finish(&slot, cmd, result);
}

/// Close the endpoint gracefully before it is dropped (an ungraceful drop is
/// fatal under panic=abort), bounded so a slow relay teardown can't wedge the
/// session.
async fn close(running: &server::RunningServer) {
    let _ = tokio::time::timeout(Duration::from_secs(5), running.endpoint().close()).await;
}

/// The session's final snapshot write, once the endpoint is closed: reset
/// after a [`ServerCmd::Remove`], else Stopped or Failed.
fn finish(slot: &ServerSlot, cmd: Option<ServerCmd>, result: anyhow::Result<()>) {
    match (cmd, result) {
        (Some(ServerCmd::Remove), _) => slot.update(|s| *s = ServerSnapshot::default()),
        (_, Ok(())) => slot.update(|s| s.phase = ServerPhase::Stopped),
        (_, Err(e)) => slot.fail(format!("{e:#}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ServerConfig {
        let secret = flextunnel_core::iroh::SecretKey::generate();
        let client = flextunnel_core::auth::ClientKey::generate().unwrap();
        ServerConfig {
            endpoint_id: secret.public().to_string(),
            secret: base64_secret(&secret),
            authorized_keys: format!("# laptop\n{} laptop\n", client.public_str()),
            routed_domains: vec!["*".into()],
            routed_cidrs: Vec::new(),
            relay_urls: Vec::new(),
            relay_auth_token: None,
        }
    }

    fn base64_secret(secret: &flextunnel_core::iroh::SecretKey) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(secret.to_bytes())
    }

    #[test]
    fn options_carry_the_server_settings() {
        let server = config();
        let opts = options(&server).unwrap();
        assert_eq!(opts.secret_key.public().to_string(), server.endpoint_id);
        assert_eq!(opts.authorized_keys.len(), 1);
        assert_eq!(opts.routed_domains, server.routed_domains);
        assert!(opts.quick_client.is_none());
    }

    #[test]
    fn options_reject_a_bad_secret_or_key_document() {
        let mut bad_secret = config();
        bad_secret.secret = "not base64!".into();
        assert!(options(&bad_secret).is_err());

        let mut bad_keys = config();
        bad_keys.authorized_keys = "ed25519-pub:nope".into();
        assert!(options(&bad_keys).is_err());
    }
}
