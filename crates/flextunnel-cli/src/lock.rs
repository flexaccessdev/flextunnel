//! Per-user single-instance locks: one `flextunnel` server per user, and one
//! client per (user, instance name).
//!
//! The lock files live under the user's own config dir
//! (`~/.config/flextunnel/`), so each user gets independent locks — two
//! different users can each run a server, but one user cannot start a second.
//! This guards against the accidental misconfiguration of launching two
//! processes with the same identity. The locking mechanics live in
//! [`flextunnel_core::lock`]; this module only picks the per-user paths.
//!
//! The client lock is deliberately a dedicated file rather than the control
//! socket or the forwards JSON: a Unix socket file persists after a crash and
//! offers no kernel-enforced liveness (probe-then-unlink-then-bind is a TOCTOU
//! race), and the forwards file is rewritten via temp+rename, which replaces
//! the locked inode on every save. An advisory lock on a stable file has
//! neither problem and is auto-released on crash.

use anyhow::{Context, Result};
use flextunnel_core::lock::InstanceLock;
use std::path::PathBuf;

use crate::instance;

/// The per-user lock path (`~/.config/flextunnel/server.lock`), matching the
/// config-file convention in [`flextunnel_core::config`]. `None` if the home dir
/// is unknown.
///
/// There is deliberately no temp-dir fallback: if the home dir is unavailable the
/// server fails fast rather than silently narrowing the guarantee to a fallback
/// lock that a second process could sidestep.
fn user_lock_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".config").join("flextunnel").join("server.lock"))
}

/// Acquire the per-user single-instance lock, held for the process lifetime.
pub fn acquire() -> Result<InstanceLock> {
    let path = user_lock_path().context(
        "Could not determine the home directory, so the single-instance lock \
         (~/.config/flextunnel/server.lock) cannot be enforced",
    )?;
    InstanceLock::acquire(
        &path,
        "Another flextunnel server is already running for this user. \
         Only one server per user is allowed.",
    )
}

/// Acquire the per-(user, instance) client lock
/// (`~/.config/flextunnel/client-<instance>.lock`), held for the process
/// lifetime. Holding it is also what makes removing a stale control socket
/// before bind safe (see `ipc.rs`).
pub fn acquire_client(instance: &str) -> Result<InstanceLock> {
    let path = instance::instance_dir()
        .context("The client single-instance lock cannot be enforced")?
        .join(format!("client-{instance}.lock"));
    InstanceLock::acquire(
        &path,
        &format!(
            "Another flextunnel client is already running for instance \
             {instance:?}. Use --instance <name> to run a second client."
        ),
    )
}
