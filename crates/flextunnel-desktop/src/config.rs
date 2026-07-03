//! Client configuration, persisted as one JSON blob in a single system
//! keychain item (macOS Keychain / Windows Credential Manager) — no plaintext
//! token ever touches disk. Kept small by design: Windows caps credential
//! blobs at ~2.5 KB.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub const DEFAULT_SOCKS_PORT: u16 = 1080;

const KEYCHAIN_SERVICE: &str = "flextunnel-desktop";
const KEYCHAIN_ACCOUNT: &str = "config";

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

/// Install the platform credential store as keyring-core's default. Must run
/// before `load`/`save`; returns false when no store is available.
pub fn init_store() -> bool {
    #[cfg(target_os = "macos")]
    {
        match apple_native_keyring_store::keychain::Store::new() {
            Ok(store) => {
                keyring_core::set_default_store(store);
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
    match entry()?.get_password() {
        Ok(json) => Ok(Some(
            serde_json::from_str(&json).context("Failed to parse the stored config")?,
        )),
        Err(keyring_core::Error::NoEntry) => Ok(None),
        Err(e) => Err(e).context("Failed to read the config from the keychain"),
    }
}

pub fn save(config: &AppConfig) -> Result<()> {
    entry()?
        .set_password(&serde_json::to_string(config)?)
        .context("Failed to write the config to the keychain")
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
}
