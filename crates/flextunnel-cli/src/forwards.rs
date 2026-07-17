//! Per-instance port-forward persistence.
//!
//! Forwards live in `~/.config/flextunnel/forwards-<instance>.json` — a
//! separate file from the client TOML, because the TOML is the hand-edited
//! profile while this file is program-written (from `flextunnel client
//! status` edits, applied by the running client). Only the running client
//! process writes it. The `enabled` flag is `#[serde(skip)]` on
//! [`PortForward`], so every forward loads disabled — enabling is an explicit
//! per-session action, exactly like the desktop client.

use anyhow::{Context, Result};
use flextunnel_core::forwards::PortForward;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::instance;

/// Wrapper object (not a bare array) so the schema can grow.
#[derive(Default, Serialize, Deserialize)]
struct ForwardsFile {
    #[serde(default)]
    forwards: Vec<PortForward>,
}

/// `~/.config/flextunnel/forwards-<instance>.json`.
pub fn forwards_path(instance: &str) -> Result<PathBuf> {
    Ok(instance::instance_dir()?.join(format!("forwards-{instance}.json")))
}

/// Load the instance's forwards; a missing file is an empty list, a corrupt
/// file is a startup error (matching the strict TOML config philosophy).
pub fn load(instance: &str) -> Result<Vec<PortForward>> {
    load_path(&forwards_path(instance)?)
}

/// Persist the instance's forwards (atomic temp + rename).
pub fn save(instance: &str, forwards: &[PortForward]) -> Result<()> {
    save_path(&forwards_path(instance)?, forwards)
}

fn load_path(path: &Path) -> Result<Vec<PortForward>> {
    match std::fs::read(path) {
        Ok(raw) => {
            let file: ForwardsFile = serde_json::from_slice(&raw)
                .with_context(|| format!("Failed to parse {}", path.display()))?;
            Ok(file.forwards)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e).with_context(|| format!("Failed to read {}", path.display())),
    }
}

/// Write via a temp file + rename so a crash mid-write can't truncate the file.
fn save_path(path: &Path, forwards: &[PortForward]) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("forwards path has no parent directory"))?;
    std::fs::create_dir_all(dir).with_context(|| format!("Failed to create {}", dir.display()))?;
    let file = ForwardsFile {
        forwards: forwards.to_vec(),
    };
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&file)?)
        .with_context(|| format!("Failed to write {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("Failed to persist {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn forward(enabled: bool) -> PortForward {
        PortForward {
            id: PortForward::new_id(),
            label: "db".into(),
            local_port: 5432,
            remote_host: "db.internal".into(),
            remote_port: 5432,
            enabled,
        }
    }

    #[test]
    fn missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_path(&dir.path().join("nope.json")).unwrap().is_empty());
    }

    #[test]
    fn corrupt_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("forwards.json");
        std::fs::write(&path, b"{ not json").unwrap();
        assert!(load_path(&path).is_err());
    }

    #[test]
    fn roundtrip_loads_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("forwards.json");
        let saved = vec![forward(true), forward(false)];
        save_path(&path, &saved).unwrap();

        // `enabled` is never serialized...
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("enabled"), "{raw}");

        // ...so everything loads disabled, with all other fields intact.
        let loaded = load_path(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        for (l, s) in loaded.iter().zip(&saved) {
            assert!(!l.enabled);
            assert_eq!(l.id, s.id);
            assert_eq!(l.label, s.label);
            assert_eq!(l.local_port, s.local_port);
            assert_eq!(l.remote_endpoint(), s.remote_endpoint());
        }
    }
}
