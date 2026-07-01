//! Machine-wide single-instance lock for the agent: only one
//! `flextunnel-agent` process per machine.
//!
//! The lock file lives at a machine-wide path (`/run` on Linux, `/var/run` on
//! macOS, `%ProgramData%\flextunnel` on Windows), so the guarantee is "one agent
//! per machine". This is the machine-local counterpart to the server's
//! duplicate-machine-id block: the lock stops a second *local* process; the
//! server block catches two *different* machines colliding on one machine id.
//! The locking mechanics live in [`flextunnel_core::lock`]; this module only
//! picks the machine-wide path.

use anyhow::{Context, Result};
use flextunnel_core::lock::InstanceLock;
use std::path::PathBuf;

/// The machine-wide lock path for this OS, if one exists. `/run` on Linux,
/// `/var/run` on macOS (both typically need privileges), and
/// `%ProgramData%\flextunnel` on Windows. `None` on other systems (e.g. BSD).
///
/// There is deliberately no per-user or temp-dir fallback: the single-instance
/// guarantee is "one agent per machine", so if this path is unavailable the agent
/// fails fast rather than silently narrowing the guarantee to a fallback lock
/// that a second process could sidestep.
fn machine_wide_lock_path() -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        Some(PathBuf::from("/run/flextunnel-agent.lock"))
    }
    #[cfg(target_os = "macos")]
    {
        Some(PathBuf::from("/var/run/flextunnel-agent.lock"))
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("ProgramData")
            .map(|p| PathBuf::from(p).join("flextunnel").join("agent.lock"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

/// Acquire the machine-wide single-instance lock, held for the process lifetime.
/// Fails fast if this OS has no machine-wide lock path, if the path cannot be
/// opened (e.g. insufficient privileges — no fallback is attempted), or if
/// another agent already holds the lock.
pub fn acquire() -> Result<InstanceLock> {
    let path = machine_wide_lock_path().context(
        "No machine-wide lock path is defined for this operating system, so the \
         single-instance guarantee cannot be enforced",
    )?;
    InstanceLock::acquire(
        &path,
        "Another flextunnel-agent is already running. Only one agent per machine is allowed.",
    )
}
