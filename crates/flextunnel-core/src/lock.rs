//! Advisory single-instance file lock, shared by the server and agent binaries.
//!
//! Uses std's native advisory file locking ([`std::fs::File::try_lock`], stable
//! since Rust 1.89) — no external crate. The lock is held for the process
//! lifetime via the open [`File`] and released automatically on exit or crash
//! (the OS drops the advisory lock when the fd closes), so a stale lock file
//! never wedges a restart.
//!
//! This module owns only the mechanics; each binary chooses the *scope* by
//! passing the lock path — the agent uses a machine-wide path (one agent per
//! machine), the server a per-user path (one server per user).

use anyhow::{Context, Result};
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

/// Holds the lock file open for the lifetime of the process. The lock is held by
/// the open file descriptor and released when this is dropped.
pub struct InstanceLock {
    #[allow(dead_code)] // kept open to hold the advisory lock; released on drop
    file: File,
}

impl InstanceLock {
    /// Acquire an advisory single-instance lock at `path`. Creates the parent
    /// directory and the file as needed, then records the current PID for
    /// operator visibility. Fails if the path can't be opened, or with
    /// `contended_msg` if another process already holds the lock.
    ///
    /// When `world_writable` is set (Unix only), the lock file is forced to mode
    /// `0666`. This is for a shared machine-wide lock in a world-writable dir like
    /// `/tmp`: without it, umask would leave the file `0644` and a *second* user's
    /// agent could not open the first user's lock file, silently defeating the
    /// one-agent-per-machine check. It is a no-op on Windows and for per-user locks.
    #[cfg_attr(not(unix), allow(unused_variables))]
    pub fn acquire(path: &Path, contended_msg: &str, world_writable: bool) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create the lock directory {}", parent.display())
            })?;
        }
        // Open or create the lock file WITHOUT truncating — truncation must happen
        // only after we hold the lock, so a concurrent holder's PID isn't clobbered.
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(false);
        #[cfg(unix)]
        if world_writable {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o666);
        }
        let mut file = opts
            .open(path)
            .with_context(|| format!("Failed to open the lock file {}", path.display()))?;

        match file.try_lock() {
            Ok(()) => {
                // Force 0666 even if umask masked the create mode above, so any user
                // can open the shared lock. Best-effort: only the file's owner can
                // chmod, but the file is already 0666 for everyone else.
                #[cfg(unix)]
                if world_writable {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = file.set_permissions(std::fs::Permissions::from_mode(0o666));
                }
                // We hold the lock: record our PID for operator visibility.
                let _ = file.set_len(0);
                let _ = file.seek(SeekFrom::Start(0));
                let _ = writeln!(file, "{}", std::process::id());
                log::debug!("Acquired single-instance lock: {}", path.display());
                Ok(Self { file })
            }
            Err(TryLockError::WouldBlock) => anyhow::bail!("{contended_msg}"),
            Err(TryLockError::Error(e)) => Err(e).with_context(|| {
                format!("Failed to acquire the single-instance lock ({})", path.display())
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// While one lock is held, a second acquisition of the same path must be
    /// rejected (advisory locks conflict across open file descriptions, even in
    /// one process); after the first is dropped, acquiring succeeds again.
    #[test]
    fn second_acquire_rejected_while_held() {
        let path = std::env::temp_dir().join("flextunnel-instance-lock-test.lock");
        let first = InstanceLock::acquire(&path, "held", true).expect("first acquire");
        assert!(
            InstanceLock::acquire(&path, "held", true).is_err(),
            "a second acquire must fail while the lock is held"
        );
        drop(first);
        // Released: acquiring again should now succeed.
        assert!(
            InstanceLock::acquire(&path, "held", true).is_ok(),
            "acquire should succeed after the lock is released"
        );
        let _ = std::fs::remove_file(&path);
    }
}
