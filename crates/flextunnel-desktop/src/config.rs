//! Profile persistence. The non-secret profile data (name, server id, ports,
//! forwards) lives in a plaintext `profiles.json` under the local data dir —
//! same treatment as the iOS app's `forwards.json`. Auth tokens are the only
//! secret and are stored one keychain entry per profile (macOS Keychain /
//! Windows Credential Manager, account = profile id), which keeps every blob
//! tiny — Windows caps credential blobs at ~2.5 KB.
//!
//! Development escape hatch: setting `FLEXTUNNEL_DEV_CONFIG` swaps all of the
//! above for a single plaintext JSON file with the tokens inline, so a rebuild
//! loop doesn't hit the macOS keychain access prompt on every unsigned binary.
//! Never set it for a real install — the auth tokens are stored unencrypted.

use crate::forward::PortForward;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const DEFAULT_SOCKS_PORT: u16 = 1080;

const KEYCHAIN_SERVICE: &str = "flextunnel-desktop";

/// Set this (to `1`/`true` for the default dev path, or to an explicit file
/// path) to store profiles as plaintext JSON instead of the system keychain.
/// Development only — see the module docs.
const DEV_CONFIG_ENV: &str = "FLEXTUNNEL_DEV_CONFIG";

/// Chosen once by `init_store`; `File` when the dev env var is set, otherwise
/// the platform keychain via `keyring-core` for tokens + `profiles.json` for
/// the rest.
enum Backend {
    Keychain,
    File(PathBuf),
}

static BACKEND: OnceLock<Backend> = OnceLock::new();

/// One connection profile — the desktop equivalent of a `client.toml`. Each
/// active profile runs its own tunnel session with its own SOCKS5 proxy port
/// and its own port forwards.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub server_node_id: String,
    /// The one secret. Never serialized here: in keychain mode it lives in a
    /// per-profile keychain entry; the dev file backend re-adds it via
    /// [`StoredProfile`].
    #[serde(skip)]
    pub auth_token: String,
    #[serde(default = "default_socks_port")]
    pub socks_port: u16,
    /// Local HTTP proxy port; `None` leaves the HTTP front-end disabled.
    #[serde(default)]
    pub http_port: Option<u16>,
    #[serde(default)]
    pub relay_urls: Vec<String>,
    #[serde(default)]
    pub forwards: Vec<PortForward>,
}

impl Profile {
    pub fn new_id() -> String {
        format!("{:016x}", rand::random::<u64>())
    }

    /// Whether the profile can be connected: a missing token happens when its
    /// keychain entry was lost (the user re-enters it in the edit form).
    pub fn is_ready(&self) -> bool {
        !self.server_node_id.is_empty() && !self.auth_token.is_empty()
    }
}

fn default_socks_port() -> u16 {
    DEFAULT_SOCKS_PORT
}

/// Serialization wrapper for the dev file backend only: the token rides along
/// inline (plaintext, development only) since there is no keychain to hold it.
#[derive(Serialize, Deserialize)]
struct StoredProfile {
    #[serde(default)]
    auth_token: String,
    #[serde(flatten)]
    profile: Profile,
}

/// Path to the plaintext dev profiles file when `FLEXTUNNEL_DEV_CONFIG` is
/// set, else `None`. `1`/`true` picks a default location under the local data
/// dir; any other value is treated as an explicit file path.
fn dev_config_path() -> Option<PathBuf> {
    let val = std::env::var(DEV_CONFIG_ENV).ok()?;
    match val.as_str() {
        "" => None,
        "1" | "true" => {
            dirs::data_local_dir().map(|d| d.join("flextunnel").join("dev-profiles.json"))
        }
        path => Some(PathBuf::from(path)),
    }
}

fn profiles_path() -> Result<PathBuf> {
    dirs::data_local_dir()
        .map(|d| d.join("flextunnel").join("profiles.json"))
        .ok_or_else(|| anyhow::anyhow!("no local data directory to store profiles in"))
}

/// Choose the storage backend. Must run before any load/save; returns false
/// when no store is available.
pub fn init_store() -> bool {
    if let Some(path) = dev_config_path() {
        log::warn!(
            "{DEV_CONFIG_ENV} set: storing profiles (tokens included) UNENCRYPTED at {} \
             (development only)",
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

fn token_entry(profile_id: &str) -> Result<keyring_core::Entry> {
    keyring_core::Entry::new(KEYCHAIN_SERVICE, profile_id)
        .context("Failed to open keychain entry")
}

/// Load all profiles; an empty list when nothing has been saved yet. In
/// keychain mode each profile's token is filled from its keychain entry — a
/// missing entry loads as an empty token with a warning instead of failing.
pub fn load_profiles() -> Result<Vec<Profile>> {
    match BACKEND.get() {
        Some(Backend::File(path)) => load_dev_file(path),
        _ => {
            let mut profiles: Vec<Profile> = match read_json(&profiles_path()?)? {
                Some(profiles) => profiles,
                None => return Ok(Vec::new()),
            };
            for profile in &mut profiles {
                match token_entry(&profile.id)?.get_password() {
                    Ok(token) => profile.auth_token = token,
                    Err(keyring_core::Error::NoEntry) => log::warn!(
                        "No keychain token for profile \"{}\"; it must be re-entered",
                        profile.name
                    ),
                    Err(e) => return Err(e).context("Failed to read a token from the keychain"),
                }
            }
            Ok(profiles)
        }
    }
}

/// Persist the profile list (non-secret data only in keychain mode — tokens
/// are written separately by [`save_profile_secret`], so routine saves after
/// a forward toggle never touch the keychain).
pub fn save_profiles(profiles: &[Profile]) -> Result<()> {
    match BACKEND.get() {
        Some(Backend::File(path)) => save_dev_file(path, profiles),
        _ => write_json(&profiles_path()?, &profiles),
    }
}

/// Store one profile's token. Called only when the token itself changes (the
/// profile form is saved); a no-op in dev file mode where `save_profiles`
/// already wrote it inline.
pub fn save_profile_secret(profile_id: &str, token: &str) -> Result<()> {
    match BACKEND.get() {
        Some(Backend::File(_)) => Ok(()),
        _ => token_entry(profile_id)?
            .set_password(token)
            .context("Failed to write the token to the keychain"),
    }
}

/// Remove a deleted profile's keychain entry (no-op in dev file mode). Best
/// effort: a stale entry is harmless.
pub fn delete_profile_secret(profile_id: &str) {
    if let Some(Backend::File(_)) = BACKEND.get() {
        return;
    }
    match token_entry(profile_id) {
        Ok(entry) => match entry.delete_credential() {
            Ok(()) | Err(keyring_core::Error::NoEntry) => {}
            Err(e) => log::warn!("Failed to delete the keychain token: {e}"),
        },
        Err(e) => log::warn!("{e:#}"),
    }
}

fn load_dev_file(path: &Path) -> Result<Vec<Profile>> {
    let stored: Vec<StoredProfile> = match read_json(path)? {
        Some(stored) => stored,
        None => return Ok(Vec::new()),
    };
    Ok(stored
        .into_iter()
        .map(|s| Profile {
            auth_token: s.auth_token,
            ..s.profile
        })
        .collect())
}

fn save_dev_file(path: &Path, profiles: &[Profile]) -> Result<()> {
    let stored: Vec<StoredProfile> = profiles
        .iter()
        .map(|p| StoredProfile {
            auth_token: p.auth_token.clone(),
            profile: p.clone(),
        })
        .collect();
    write_json(path, &stored)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match std::fs::read(path) {
        Ok(raw) => Ok(Some(
            serde_json::from_slice(&raw)
                .with_context(|| format!("Failed to parse {}", path.display()))?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("Failed to read {}", path.display())),
    }
}

/// Write via a temp file + rename so a crash mid-write can't truncate the file.
fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("profiles path has no parent directory"))?;
    std::fs::create_dir_all(dir)
        .with_context(|| format!("Failed to create {}", dir.display()))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(value)?)
        .with_context(|| format!("Failed to write {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("Failed to persist {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> Profile {
        Profile {
            id: "00000000deadbeef".into(),
            name: "prod".into(),
            server_node_id: "node".into(),
            auth_token: "token".into(),
            socks_port: 1085,
            http_port: Some(8081),
            relay_urls: vec!["https://relay.example".into()],
            forwards: vec![PortForward {
                id: "aaaa".into(),
                label: "db".into(),
                local_port: 5432,
                remote_host: "db.internal".into(),
                remote_port: 5432,
                enabled: true,
            }],
        }
    }

    #[test]
    fn optional_fields_default_when_absent() {
        let p: Profile = serde_json::from_str(
            r#"{"id":"1","name":"n","server_node_id":"abc"}"#,
        )
        .unwrap();
        assert_eq!(p.socks_port, DEFAULT_SOCKS_PORT);
        assert_eq!(p.http_port, None);
        assert!(p.relay_urls.is_empty());
        assert!(p.forwards.is_empty());
        assert!(p.auth_token.is_empty());
    }

    #[test]
    fn token_never_serializes_in_profile() {
        let json = serde_json::to_string(&profile()).unwrap();
        assert!(!json.contains("token"), "token leaked: {json}");
        // `enabled` is runtime-only on forwards and must not leak either.
        assert!(!json.contains("enabled"), "enabled leaked: {json}");
    }

    #[test]
    fn dev_file_roundtrips_with_tokens_and_missing_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("dev-profiles.json");

        assert!(load_dev_file(&path).unwrap().is_empty());

        let mut profiles = vec![profile()];
        save_dev_file(&path, &profiles).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("\"auth_token\": \"token\""), "token missing: {raw}");

        // Forward `enabled` is runtime-only: comes back off.
        profiles[0].forwards[0].enabled = false;
        assert_eq!(load_dev_file(&path).unwrap(), profiles);
    }
}
