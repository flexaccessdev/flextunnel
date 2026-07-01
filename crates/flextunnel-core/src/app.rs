//! Small process/runtime helpers shared by the binaries (server, client, agent)
//! and the iOS FFI: logger init, a multi-thread Tokio runtime, a version banner,
//! and a graceful-shutdown signal future. These are pure boilerplate that every
//! entry point needs; keeping one copy here avoids drift between crates.

use anyhow::Result;

/// Default `env_logger` filter for the binaries: flextunnel's own crates at
/// `info`, the noisy transport deps (iroh and its tracing bridge) at `warn`.
/// Overridable at runtime via `RUST_LOG`. The FFI passes its own filter instead.
pub const DEFAULT_LOG_FILTER: &str = "info,iroh=warn,tracing=warn";

/// Initialize `env_logger` with `default_filter` unless `RUST_LOG` overrides it.
/// Uses `try_init` so it is idempotent and safe to call more than once (the FFI
/// entry point may be invoked repeatedly).
pub fn init_logger(default_filter: &str) {
    let _ = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(default_filter),
    )
    .try_init();
}

/// Build the multi-threaded Tokio runtime the entry points block on.
pub fn build_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(Into::into)
}

/// Log the running binary's name and version. Callers pass their own crate's
/// `env!("CARGO_PKG_NAME")` / `env!("CARGO_PKG_VERSION")`, since those must be
/// resolved in the binary crate, not here.
pub fn log_version(pkg_name: &str, pkg_version: &str) {
    log::info!("{pkg_name} v{pkg_version}");
}

/// Resolve when a shutdown signal arrives: SIGTERM or SIGINT on Unix, Ctrl-C
/// elsewhere. Await this alongside the main task in a `tokio::select!`.
#[cfg(unix)]
pub async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    let mut int = signal(SignalKind::interrupt()).expect("install SIGINT handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}

/// Resolve when a shutdown signal arrives (non-Unix: Ctrl-C only).
#[cfg(not(unix))]
pub async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
