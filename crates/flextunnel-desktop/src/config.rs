//! Client configuration, persisted as one JSON blob in a single system
//! keychain item (macOS Keychain / Windows Credential Manager) — no plaintext
//! token touches disk. Kept small by design: Windows caps credential blobs at
//! ~2.5 KB.
//!
//! Development escape hatch: setting `FLEXTUNNEL_DEV_CONFIG` swaps the keychain
//! for a plaintext JSON file, so a rebuild loop doesn't hit the macOS keychain
//! access prompt on every unsigned binary. Never set it for a real install —
//! the auth token is stored unencrypted.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const DEFAULT_SOCKS_PORT: u16 = 1080;

const KEYCHAIN_SERVICE: &str = "flextunnel-desktop";
const KEYCHAIN_ACCOUNT: &str = "config";

/// Set this (to `1`/`true` for the default dev path, or to an explicit file
/// path) to store config as plaintext JSON instead of the system keychain.
/// Development only — see the module docs.
const DEV_CONFIG_ENV: &str = "FLEXTUNNEL_DEV_CONFIG";

/// Chosen once by `init_store`; `File` when the dev env var is set, otherwise
/// the platform keychain via `keyring-core`.
enum Backend {
    Keychain,
    File(PathBuf),
}

static BACKEND: OnceLock<Backend> = OnceLock::new();

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppConfig {
    pub server_node_id: String,
    pub auth_token: String,
    #[serde(default = "default_socks_port")]
    pub socks_port: u16,
    /// Local HTTP proxy port; `None` leaves the HTTP front-end disabled.
    #[serde(default)]
    pub http_port: Option<u16>,
    #[serde(default)]
    pub relay_urls: Vec<String>,
}

fn default_socks_port() -> u16 {
    DEFAULT_SOCKS_PORT
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server_node_id: String::new(),
            auth_token: String::new(),
            socks_port: DEFAULT_SOCKS_PORT,
            http_port: None,
            relay_urls: Vec::new(),
        }
    }
}

/// Path to the plaintext dev config file when `FLEXTUNNEL_DEV_CONFIG` is set,
/// else `None`. `1`/`true` picks a default location under the local data dir;
/// any other value is treated as an explicit file path.
fn dev_config_path() -> Option<PathBuf> {
    let val = std::env::var(DEV_CONFIG_ENV).ok()?;
    match val.as_str() {
        "" => None,
        "1" | "true" => {
            dirs::data_local_dir().map(|d| d.join("flextunnel").join("dev-config.json"))
        }
        path => Some(PathBuf::from(path)),
    }
}

/// Choose the config backend. Must run before `load`/`save`; returns false
/// when no store is available.
pub fn init_store() -> bool {
    if let Some(path) = dev_config_path() {
        log::warn!(
            "{DEV_CONFIG_ENV} set: storing config UNENCRYPTED at {} (development only)",
            path.display()
        );
        let _ = BACKEND.set(Backend::File(path));
        return true;
    }
    #[cfg(target_os = "macos")]
    {
        match apple_native_keyring_store::keychain::Store::new() {
            Ok(store) => {
                keyring_core::set_default_store(store);
                let _ = BACKEND.set(Backend::Keychain);
                return true;
            }
            Err(e) => log::error!("Failed to open the macOS keychain store: {e}"),
        }
    }
    #[cfg(windows)]
    {
        match windows_native_keyring_store::Store::new() {
            Ok(store) => {
                keyring_core::set_default_store(store);
                let _ = BACKEND.set(Backend::Keychain);
                return true;
            }
            Err(e) => log::error!("Failed to open the Windows credential store: {e}"),
        }
    }
    false
}

fn entry() -> Result<keyring_core::Entry> {
    keyring_core::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
        .context("Failed to open keychain entry")
}

/// Load the stored config; `None` when nothing has been saved yet.
pub fn load() -> Result<Option<AppConfig>> {
    match BACKEND.get() {
        Some(Backend::File(path)) => load_file(path),
        _ => load_keychain(),
    }
}

pub fn save(config: &AppConfig) -> Result<()> {
    match BACKEND.get() {
        Some(Backend::File(path)) => save_file(path, config),
        _ => save_keychain(config),
    }
}

fn load_keychain() -> Result<Option<AppConfig>> {
    match entry()?.get_password() {
        Ok(json) => Ok(Some(
            serde_json::from_str(&json).context("Failed to parse the stored config")?,
        )),
        Err(keyring_core::Error::NoEntry) => Ok(None),
        Err(e) => Err(e).context("Failed to read the config from the keychain"),
    }
}

fn save_keychain(config: &AppConfig) -> Result<()> {
    entry()?
        .set_password(&serde_json::to_string(config)?)
        .context("Failed to write the config to the keychain")
}

fn load_file(path: &Path) -> Result<Option<AppConfig>> {
    match std::fs::read(path) {
        Ok(raw) => Ok(Some(
            serde_json::from_slice(&raw)
                .with_context(|| format!("Failed to parse {}", path.display()))?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("Failed to read {}", path.display())),
    }
}

/// Write via a temp file + rename so a crash mid-write can't truncate config.
fn save_file(path: &Path, config: &AppConfig) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("dev config path has no parent directory"))?;
    std::fs::create_dir_all(dir)
        .with_context(|| format!("Failed to create {}", dir.display()))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(config)?)
        .with_context(|| format!("Failed to write {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("Failed to persist {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_fields_default_when_absent() {
        let cfg: AppConfig =
            serde_json::from_str(r#"{"server_node_id":"abc","auth_token":"tok"}"#).unwrap();
        assert_eq!(cfg.socks_port, DEFAULT_SOCKS_PORT);
        assert_eq!(cfg.http_port, None);
        assert!(cfg.relay_urls.is_empty());
    }

    #[test]
    fn roundtrips_through_json() {
        let cfg = AppConfig {
            server_node_id: "node".into(),
            auth_token: "token".into(),
            socks_port: 1085,
            http_port: Some(8081),
            relay_urls: vec!["https://relay.example".into()],
        };
        let json = serde_json::to_string(&cfg).unwrap();
        assert_eq!(serde_json::from_str::<AppConfig>(&json).unwrap(), cfg);
    }

    #[test]
    fn file_backend_roundtrips_and_missing_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("dev-config.json");

        assert!(load_file(&path).unwrap().is_none());

        let cfg = AppConfig {
            server_node_id: "node".into(),
            auth_token: "token".into(),
            socks_port: 1085,
            http_port: Some(8081),
            relay_urls: vec!["https://relay.example".into()],
        };
        save_file(&path, &cfg).unwrap();
        assert_eq!(load_file(&path).unwrap(), Some(cfg));
    }
}
