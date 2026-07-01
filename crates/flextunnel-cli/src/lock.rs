//! Per-user single-instance lock for the server: only one `flextunnel` server
//! per user.
//!
//! The lock file lives under the user's own config dir
//! (`~/.config/flextunnel/server.lock`), so each user gets an independent lock —
//! two different users can each run a server, but one user cannot start a second.
//! This guards against the accidental misconfiguration of launching two servers
//! with the same identity. The locking mechanics live in
//! [`flextunnel_core::lock`]; this module only picks the per-user path.

use anyhow::{Context, Result};
use flextunnel_core::lock::InstanceLock;
use std::path::PathBuf;

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
        // Per-user lock under the user's own config dir — no world-writability needed.
        false,
    )
}
