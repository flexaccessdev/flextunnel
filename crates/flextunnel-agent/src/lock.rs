//! Machine-wide single-instance lock for the agent: only one
//! `flextunnel-agent` process per machine.
//!
//! The lock file lives at a machine-wide path that an *ordinary user* can write
//! without privileges: `/tmp/flextunnel-agent.lock` on Unix (a world-writable,
//! sticky directory, so the lock spans all users on the machine) and
//! `%ProgramData%\flextunnel` on Windows. The guarantee is "one agent per
//! machine". This is the machine-local counterpart to the server's
//! duplicate-machine-id block: the lock stops a second *local* process; the
//! server block catches two *different* machines colliding on one machine id.
//!
//! Consistent with this project's trust model (clients and servers are trusted;
//! duplicate detections exist to catch *accidental* misconfiguration, not to
//! defend against an adversarial process), the lock lives in a world-writable dir
//! and is created mode `0666` so any user's agent can participate. A hostile
//! second process could of course sidestep it, but that is out of scope — the
//! goal is only to stop an operator from accidentally launching two agents.
//!
//! The locking mechanics live in [`flextunnel_core::lock`]; this module only
//! picks the machine-wide path.

use anyhow::{Context, Result};
use flextunnel_core::lock::InstanceLock;
use std::path::PathBuf;

/// The machine-wide lock path for this OS, if one exists.
/// `/tmp/flextunnel-agent.lock` on Unix (world-writable and machine-wide, so it
/// needs no privileges) and `%ProgramData%\flextunnel\agent.lock` on Windows.
/// `None` on other systems.
///
/// `/tmp` is hardcoded rather than derived from `TMPDIR`/`std::env::temp_dir()`
/// on purpose: on macOS `$TMPDIR` is a *per-user* directory, which would silently
/// narrow the guarantee from one-agent-per-machine to one-agent-per-user.
fn machine_wide_lock_path() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        Some(PathBuf::from("/tmp/flextunnel-agent.lock"))
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("ProgramData")
            .map(|p| PathBuf::from(p).join("flextunnel").join("agent.lock"))
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        None
    }
}

/// Acquire the machine-wide single-instance lock, held for the process lifetime.
/// Fails fast if this OS has no machine-wide lock path, if the path cannot be
/// opened, or if another agent already holds the lock. The lock file is created
/// world-writable (`0666`) so agents run by different users share it.
pub fn acquire() -> Result<InstanceLock> {
    let path = machine_wide_lock_path().context(
        "No machine-wide lock path is defined for this operating system, so the \
         single-instance guarantee cannot be enforced",
    )?;
    InstanceLock::acquire(
        &path,
        "Another flextunnel-agent is already running. Only one agent per machine is allowed.",
        true,
    )
}
