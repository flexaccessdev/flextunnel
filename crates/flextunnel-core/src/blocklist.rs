//! Persistent duplicate-id blocklist for the server.
//!
//! The blocklist is a small JSON file (default
//! `~/.config/flextunnel/blocklist.json`) that records identities involved in a
//! **duplicate-id conflict** — a guard rail against accidental misconfiguration
//! (see `docs/architecture.md`, "Security model"). It holds two kinds of entry:
//!
//! * **`blocked_clients`** — iroh node ids the server saw as a *confirmed
//!   duplicate client* (two live processes presenting the same node id). Because
//!   client ids are ephemeral (a fresh key per process), such an id never
//!   recurs, so these entries are mostly an **audit record**; they are still
//!   rejected up-front if seen again.
//! * **`conflicted_server_ids`** — the server's *own* `EndpointId` when it
//!   detects it is a duplicate of another server sharing its secret key. On the
//!   next launch the server refuses to start if its id is listed here, forcing an
//!   operator to resolve the conflict and clear the entry.
//!
//! Writes are atomic (temp file + rename) so a crash can never leave a truncated
//! file, and the file loads as empty when absent (normal first run).

use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// One blocklist entry: an identity plus why/when it was recorded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEntry {
    /// The iroh `EndpointId`, as its canonical string form.
    pub id: String,
    /// Human-readable reason the id was blocked (for the operator).
    pub reason: String,
    /// Unix time (milliseconds) the conflict was detected.
    pub detected_at_ms: u64,
}

/// The serialized on-disk shape of the blocklist.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct BlockListData {
    blocked_clients: Vec<BlockEntry>,
    conflicted_server_ids: Vec<BlockEntry>,
}

/// In-memory blocklist bound to the file it was loaded from.
#[derive(Debug, Clone)]
pub struct BlockList {
    path: PathBuf,
    data: BlockListData,
}

/// Default blocklist path (`~/.config/flextunnel/blocklist.json`), matching the
/// config-file convention in [`crate::config`]. `None` if the home dir is
/// unknown.
pub fn default_blocklist_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| {
        home.join(".config")
            .join("flextunnel")
            .join("blocklist.json")
    })
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl BlockList {
    /// Load the blocklist from `path`. A missing file yields an empty blocklist
    /// (the normal first-run case); a present-but-unparseable file is an error so
    /// corruption fails loudly rather than silently dropping blocks.
    pub fn load(path: PathBuf) -> io::Result<Self> {
        let data = match std::fs::read_to_string(&path) {
            Ok(content) => serde_json::from_str(&content).map_err(|e| {
                io::Error::other(format!(
                    "Failed to parse blocklist {}: {e}",
                    path.display()
                ))
            })?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => BlockListData::default(),
            Err(e) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!("Failed to read blocklist {}: {e}", path.display()),
                ));
            }
        };
        Ok(Self { path, data })
    }

    /// The file this blocklist is backed by.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether a client node id is blocked.
    pub fn is_client_blocked(&self, id: &str) -> bool {
        self.data.blocked_clients.iter().any(|e| e.id == id)
    }

    /// Whether a server id is recorded as conflicted (self-block on startup).
    pub fn is_server_conflicted(&self, id: &str) -> bool {
        self.data.conflicted_server_ids.iter().any(|e| e.id == id)
    }

    /// Record a confirmed duplicate client id. Returns `true` if newly added
    /// (a caller should persist only when something changed).
    pub fn add_blocked_client(&mut self, id: &str, reason: impl Into<String>) -> bool {
        if self.is_client_blocked(id) {
            return false;
        }
        self.data.blocked_clients.push(BlockEntry {
            id: id.to_string(),
            reason: reason.into(),
            detected_at_ms: now_ms(),
        });
        true
    }

    /// Record the server's own id as conflicted. Returns `true` if newly added.
    pub fn add_conflicted_server(&mut self, id: &str, reason: impl Into<String>) -> bool {
        if self.is_server_conflicted(id) {
            return false;
        }
        self.data.conflicted_server_ids.push(BlockEntry {
            id: id.to_string(),
            reason: reason.into(),
            detected_at_ms: now_ms(),
        });
        true
    }

    /// Serialize the current state to pretty JSON (cheap; safe to call under a
    /// lock, then write the returned string outside it via [`write_atomic`]).
    pub fn to_json(&self) -> io::Result<String> {
        serde_json::to_string_pretty(&self.data).map_err(io::Error::other)
    }
}

/// Atomically write `json` to `path`: create parent dirs, write a sibling temp
/// file, then `rename` it into place so a reader never sees a partial file.
pub fn write_atomic(path: &Path, json: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Sibling temp in the same directory so the rename is atomic (same filesystem).
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("flextunnel-blocklist-test-{name}.json"))
    }

    #[test]
    fn missing_file_loads_empty() {
        let path = tmp_path("missing");
        let _ = std::fs::remove_file(&path);
        let bl = BlockList::load(path).unwrap();
        assert!(!bl.is_client_blocked("anything"));
        assert!(!bl.is_server_conflicted("anything"));
    }

    #[test]
    fn add_persist_and_reload_roundtrip() {
        let path = tmp_path("roundtrip");
        let _ = std::fs::remove_file(&path);

        let mut bl = BlockList::load(path.clone()).unwrap();
        assert!(bl.add_blocked_client("client-node-id", "duplicate client"));
        assert!(bl.add_conflicted_server("server-endpoint-id", "duplicate server"));
        // Idempotent: a repeat is not re-added.
        assert!(!bl.add_blocked_client("client-node-id", "again"));
        write_atomic(bl.path(), &bl.to_json().unwrap()).unwrap();

        let reloaded = BlockList::load(path.clone()).unwrap();
        assert!(reloaded.is_client_blocked("client-node-id"));
        assert!(reloaded.is_server_conflicted("server-endpoint-id"));
        assert!(!reloaded.is_client_blocked("other"));

        let _ = std::fs::remove_file(&path);
    }
}
