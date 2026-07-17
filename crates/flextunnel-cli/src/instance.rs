//! Client instance identity.
//!
//! A client *instance* is one running `flextunnel client start` process,
//! identified by the server it connects to: since a profile's `server_node_id` never
//! changes, its prefix keys every per-instance artifact — the single-instance
//! lock (`client-<key>.lock`), the control socket (`client-<key>.sock` /
//! `\\.\pipe\flextunnel-client-<key>`), and the persisted port forwards
//! (`forwards-<key>.json`). There is deliberately no way to override the key:
//! one client per server per user, and `flextunnel client control` finds the
//! right socket from the same config. The optional `name` in the config
//! ("aws", "home network") is display-only.

use anyhow::{Context, Result, bail};
use std::path::PathBuf;

/// How much of the server node id keys the on-disk artifacts. 16 hex chars
/// (64 bits) cannot collide by accident between distinct servers.
const KEY_LEN: usize = 16;

/// Derive the instance key from a profile's server node id: its first
/// [`KEY_LEN`] characters, lowercased. Errors on anything that cannot be a
/// node id (full validation happens when the id is parsed for dialing).
pub fn instance_key(server_node_id: &str) -> Result<String> {
    let id = server_node_id.trim();
    if id.len() < KEY_LEN || !id.bytes().all(|b| b.is_ascii_alphanumeric()) {
        bail!("server_node_id {id:?} does not look like a server EndpointId");
    }
    Ok(id[..KEY_LEN].to_ascii_lowercase())
}

/// The per-user directory holding all per-instance artifacts
/// (`~/.config/flextunnel`), matching the config-file convention in
/// [`flextunnel_core::config`]. Errors if the home dir is unknown — there is
/// deliberately no temp-dir fallback (see `lock.rs`).
pub fn instance_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not determine the home directory")?;
    Ok(home.join(".config").join("flextunnel"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_is_a_lowercased_prefix() {
        let id = "62E463A6D67FDEACc65e97464b2b51d7362e00436a8b81477a9cea46b11228ca";
        assert_eq!(instance_key(id).unwrap(), "62e463a6d67fdeac");
        assert_eq!(instance_key(&format!("  {id} ")).unwrap(), "62e463a6d67fdeac");
    }

    #[test]
    fn malformed_ids_are_rejected() {
        assert!(instance_key("").is_err());
        assert!(instance_key("short").is_err());
        assert!(instance_key("../escape/../../etc/passwd0000000").is_err());
        assert!(instance_key("62e463a6 67fdeacc65e97464b2b51d7").is_err());
    }
}
