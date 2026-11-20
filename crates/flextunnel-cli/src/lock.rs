//! Per-user client single-instance locks: one client per (user, instance
//! name) — see `instance.rs` — so two clients started from the same config
//! cannot run at once, while clients with different names coexist. (The server
//! lock, one per identity, is shared with the desktop app and lives in
//! [`flextunnel_core::server::acquire_server_lock`].)
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

/// Acquire the per-(user, instance name) client lock
/// (`~/.config/flextunnel/client-<name>.lock`), held for the process lifetime.
/// Holding it is also what makes removing a stale control socket before bind
/// safe (see `ipc.rs`).
pub fn acquire_client(name: &str) -> Result<InstanceLock> {
    let path = instance::instance_dir()
        .context("The client single-instance lock cannot be enforced")?
        .join(format!("client-{name}.lock"));
    InstanceLock::acquire(
        &path,
        &format!(
            "Another flextunnel client named '{name}' is already running. To run a second \
             client alongside it, give this one a different `name` in its config."
        ),
    )
}
