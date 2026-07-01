//! Single-instance file lock: only one `flextunnel-agent` process per machine.
//!
//! Uses std's native advisory file locking ([`std::fs::File::try_lock`], stable
//! since Rust 1.89) — no external crate. The lock is held for the process
//! lifetime via the open [`File`] and released automatically on exit or crash
//! (the OS drops the advisory lock when the fd closes), so a stale lock file
//! never wedges a restart. This is the machine-local counterpart to the server's
//! duplicate-machine-id block: the lock stops a second *local* process; the
//! server block catches two *different* machines colliding on one machine id.

use anyhow::{Context, Result};
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;

/// Holds the lock file open for the lifetime of the process. The lock is held by
/// the open file descriptor and released when this is dropped.
pub struct AgentLock {
    #[allow(dead_code)] // kept open to hold the advisory lock; released on drop
    file: File,
}

/// Candidate lock-file locations, most-preferred first. The machine-wide path
/// enforces "one agent per machine"; the fallbacks keep the agent usable when
/// that path is not writable (e.g. an unprivileged run on macOS/Windows), at
/// which point the guarantee narrows to "one agent per user".
fn candidate_lock_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(p) = machine_wide_lock_path() {
        paths.push(p);
    }
    // Per-user fallback under ~/.config/flextunnel (flextunnel uses ~/.config on
    // every platform for its config, so the lock lives alongside it).
    if let Some(home) = dirs::home_dir() {
        paths.push(home.join(".config").join("flextunnel").join("agent.lock"));
    }
    // Last resort: the temp dir.
    paths.push(std::env::temp_dir().join("flextunnel-agent.lock"));
    paths
}

/// The preferred machine-wide lock path for this OS, if one exists. `/run` on
/// Linux, `/var/run` on macOS (both typically need privileges, else we fall
/// back), and `%ProgramData%\flextunnel` on Windows. `None` on other systems
/// (e.g. BSD), which fall straight through to the per-user / temp candidates.
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

impl AgentLock {
    /// Acquire the single-instance lock, trying each candidate path until one can
    /// be opened. Fails if another agent already holds the lock, or if no
    /// candidate path could be opened.
    pub fn acquire() -> Result<Self> {
        let mut last_open_err = None;
        for path in candidate_lock_paths() {
            if let Some(parent) = path.parent() {
                // Best-effort: if we can't create the dir, this candidate is
                // simply unusable and we try the next one.
                let _ = std::fs::create_dir_all(parent);
            }
            // Open or create the lock file WITHOUT truncating — truncation must
            // happen only after we hold the lock, so a concurrent holder's PID
            // isn't clobbered.
            let mut file = match OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)
            {
                Ok(f) => f,
                Err(e) => {
                    last_open_err = Some((path, e));
                    continue;
                }
            };

            match file.try_lock() {
                Ok(()) => {
                    // We hold the lock: record our PID for operator visibility.
                    let _ = file.set_len(0);
                    let _ = file.seek(SeekFrom::Start(0));
                    let _ = writeln!(file, "{}", std::process::id());
                    log::debug!("Acquired agent lock: {}", path.display());
                    return Ok(Self { file });
                }
                Err(TryLockError::WouldBlock) => {
                    anyhow::bail!(
                        "Another flextunnel-agent is already running (lock held at {}). \
                         Only one agent per machine is allowed.",
                        path.display()
                    );
                }
                Err(TryLockError::Error(e)) => {
                    last_open_err = Some((path, e));
                    continue;
                }
            }
        }

        match last_open_err {
            Some((path, e)) => Err(e).with_context(|| {
                format!("Failed to acquire the single-instance lock ({})", path.display())
            }),
            None => anyhow::bail!("Failed to acquire the single-instance lock: no candidate path"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// While one `AgentLock` is held, a second acquisition must be rejected
    /// (advisory locks conflict across open file descriptions, even in one
    /// process); after the first is dropped, acquiring succeeds again.
    #[test]
    fn second_acquire_rejected_while_held() {
        // If the first acquire fails, the environment (e.g. a real agent already
        // running, or no writable candidate path) can't support this check —
        // don't turn that into a spurious failure.
        let Ok(first) = AgentLock::acquire() else {
            return;
        };
        assert!(
            AgentLock::acquire().is_err(),
            "a second acquire must fail while the lock is held"
        );
        drop(first);
        // Released: acquiring again should now succeed.
        assert!(
            AgentLock::acquire().is_ok(),
            "acquire should succeed after the lock is released"
        );
    }
}
