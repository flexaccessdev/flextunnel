//! Machine-wide single-instance lock for the agent: only one
//! `flextunnel-agent` process per machine.
//!
//! The agent is a machine-global, root-run daemon, so the lock lives in a
//! standard root-owned runtime location: `/var/run/flextunnel-agent.lock` on Unix
//! (`/var/run` exists and is root-writable on both Linux — a symlink to `/run` —
//! and macOS) and `%ProgramData%\flextunnel\agent.lock` on Windows. The guarantee
//! is "one agent per machine". This is the machine-local counterpart to the
//! server's duplicate-machine-id block: the lock stops a second *local* process;
//! the server block catches two *different* machines colliding on one machine id.
//!
//! Because the agent runs as root, the lock file needs no world-writable dance:
//! only root writes it, so ordinary umask-created permissions are fine. A non-root
//! invocation fails here (it cannot create the file under `/var/run`), which is
//! how the "run as root" expectation is enforced — there is no separate privilege
//! check in the code.
//!
//! The locking mechanics live in [`flextunnel_core::lock`]; this module only
//! picks the machine-wide path.

use anyhow::{Context, Result};
use flextunnel_core::lock::InstanceLock;
use std::path::PathBuf;

/// The machine-wide lock path for this OS, if one exists.
/// `/var/run/flextunnel-agent.lock` on Unix (a root-owned, machine-wide runtime
/// dir) and `%ProgramData%\flextunnel\agent.lock` on Windows. `None` on other
/// systems.
fn machine_wide_lock_path() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        Some(PathBuf::from("/var/run/flextunnel-agent.lock"))
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
/// opened (e.g. running as a non-root user, who cannot write under `/var/run`), or
/// if another agent already holds the lock.
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
