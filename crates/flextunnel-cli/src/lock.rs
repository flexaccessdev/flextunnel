//! Per-user client single-instance locks: one client per (user, target
//! server) — keyed by the server-id prefix (see `instance.rs`), so two clients
//! for the same server cannot run at once, while clients for different servers
//! coexist. (The server lock, likewise one per identity, is shared with the
//! desktop app and lives in [`flextunnel_core::server::acquire_server_lock`].)
//!
//! The lock files live under the user's own config dir
//! (`~/.config/flextunnel/`), so each user gets independent locks. This guards
//! against the accidental misconfiguration of launching two processes with
//! the same identity. The locking mechanics live in
//! [`flextunnel_core::lock`]; this module only picks the per-user paths.
//!
//! The client lock is deliberately a dedicated file rather than the control
//! socket: a Unix socket file persists after a crash and offers no
//! kernel-enforced liveness (probe-then-unlink-then-bind is a TOCTOU race). An
//! advisory lock on a stable file has neither problem and is auto-released on
//! crash.

use anyhow::{Context, Result};
use flextunnel_core::lock::InstanceLock;

use crate::instance;

/// Acquire the per-(user, server) client lock
/// (`~/.config/flextunnel/client-<key>.lock`, keyed by the server-id prefix),
/// held for the process lifetime. Holding it is also what makes removing a
/// stale control socket before bind safe (see `ipc.rs`).
pub fn acquire_client(key: &str) -> Result<InstanceLock> {
    let path = instance::instance_dir()
        .context("The client single-instance lock cannot be enforced")?
        .join(format!("client-{key}.lock"));
    InstanceLock::acquire(
        &path,
        &format!(
            "Another flextunnel client is already running for this server \
             (id prefix {key}). Only one client per server is allowed."
        ),
    )
}
