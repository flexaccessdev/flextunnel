//! Profile, server and auth-key persistence. Client auth keys live in a shared,
//! named list so several profiles can authenticate with the same keypair; each
//! profile references one by [`AuthKey::id`]. The optional [`ServerConfig`]
//! runs the one flextunnel server the app hosts in-process (one server per
//! user). The non-secret data (key names and public halves, profile names,
//! server ids, ports, forwards, the server's tunnel set and authorized keys)
//! lives in a plaintext `profiles.json` under the local data dir — same
//! treatment as the iOS app's `forwards.json`. The secrets (auth-key secret
//! halves, the server's identity key, and the profiles' and server's custom
//! relay auth tokens) ride in the same file, sealed the way
//! Chrome/Slack/Notion store their secrets: a single keychain entry
//! ("Flextunnel Safe Storage", macOS Keychain / Windows Credential Manager)
//! holds a random 256-bit master key, and the id → secret map (key ids, the
//! reserved [`SERVER_SECRET_ID`] and [`SERVER_RELAY_SECRET_ID`], and a
//! [`PROFILE_RELAY_PREFIX`]ed id per profile relay token) is
//! AES-256-GCM-encrypted with it into the file's `sealed_keys` blob. The
//! keychain holds one small fixed-size entry regardless of how many keys
//! exist, so a fresh install (or a rebuilt, differently-signed binary)
//! triggers at most one macOS keychain prompt per run — and none at all
//! until a secret actually needs sealing or unsealing.
//!
//! Development escape hatch: setting `FLEXTUNNEL_DEV_CONFIG` swaps all of the
//! above for a single plaintext JSON file with the secrets inline, so a rebuild
//! loop doesn't hit the macOS keychain access prompt on every unsigned binary.
//! Never set it for a real install — the secrets are stored unencrypted.
//!
//! `FLEXTUNNEL_KEYCHAIN=mock` keeps the sealed store but puts the Safe Storage
//! master key in keyring-core's in-memory store instead of the platform
//! keychain, for an end-to-end test or a QA run on a machine whose keychain
//! would answer with a system prompt (an unsigned build meets it again after
//! every rebuild). The master key is generated at start and gone at exit, so
//! the store is sealed into a `mock-profiles.json` of its own, emptied at start:
//! the account's keychain and `profiles.json` are never read or written.

use flextunnel_core::forwards::PortForward;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit};
use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const DEFAULT_SOCKS_PORT: u16 = 1080;
/// Suggested HTTP proxy port for the profile form. Deliberately high — 8080
/// is taken by half the dev servers in the world (mirrors the iOS FFI's
/// choice of 18080 for its SOCKS default).
pub const DEFAULT_HTTP_PORT: u16 = 18080;

/// The one keychain entry: it holds the random master key that seals the
/// auth-key secrets in `profiles.json` — never the secrets themselves. Named
/// after the "Chrome Safe Storage" / "Slack Safe Storage" convention so it's
/// recognizable in Keychain Access.
const SAFE_STORAGE_SERVICE: &str = "Flextunnel Safe Storage";
const SAFE_STORAGE_USER: &str = "Flextunnel";

/// The format of what is sealed into `sealed_keys`: which secrets it holds,
/// their ids in the map, and their encoding. Bump it on any change a store
/// sealed before would only half match, and a store sealed under another
/// version (or none) then loads with every sealed secret empty, to be
/// re-entered — one fresh start instead of some secrets loading and others
/// silently missing. The master key is not versioned: it is random bytes
/// whatever the format.
const SEALED_VERSION: u32 = 1;

/// Set this (to `1`/`true` for the default dev path, or to an explicit file
/// path) to store profiles as plaintext JSON instead of the system keychain.
/// Development only — see the module docs.
const DEV_CONFIG_ENV: &str = "FLEXTUNNEL_DEV_CONFIG";

/// The variable that, set to `mock`, keeps the Safe Storage master key in
/// memory rather than in the platform keychain. See the module docs.
const KEYCHAIN_ENV: &str = "FLEXTUNNEL_KEYCHAIN";

/// Where the store lives, set once by `init_store`. Unset (a refused
/// `FLEXTUNNEL_KEYCHAIN`, or both escape hatches at once), loads and saves fail
/// rather than reach the account's real store.
static BACKEND: OnceLock<Backend> = OnceLock::new();

enum Backend {
    /// `profiles.json`, its secrets sealed under the Safe Storage master key
    /// held by the platform keychain via `keyring-core`.
    Keychain,
    /// `mock-profiles.json`, sealed the same way under a master key kept in
    /// keyring-core's in-memory mock store (`FLEXTUNNEL_KEYCHAIN=mock`).
    MockKeychain,
    /// The plaintext dev file (`FLEXTUNNEL_DEV_CONFIG`).
    DevFile(PathBuf),
}

/// One named client auth keypair, shared across profiles: any number of
/// profiles can pick the same key to authenticate with (its public half then
/// only needs one line on each server's authorized-keys file).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthKey {
    pub id: String,
    pub name: String,
    /// Derived from the secret, but stored plaintext on purpose: the public
    /// half is not a secret (it's what goes on the server's authorized-keys
    /// file), and keeping it here lets the UI identify the key even when its
    /// keychain entry is lost.
    pub public_key: String,
    /// The secret half. Never serialized here: in keychain mode it rides in
    /// the store's encrypted `sealed_keys` blob; the dev file backend re-adds
    /// it via [`StoredKey`].
    #[serde(skip)]
    pub secret: String,
}

impl AuthKey {
    pub fn new_id() -> String {
        random_id()
    }
}

/// The key with the given id, if any (an empty id never matches).
pub fn find_key<'a>(keys: &'a [AuthKey], id: &str) -> Option<&'a AuthKey> {
    keys.iter().find(|k| k.id == id)
}

fn random_id() -> String {
    format!("{:016x}", rand::random::<u64>())
}

/// A well-formed profile or key name: 1-64 characters, words separated by
/// single spaces — no leading/trailing spaces, no consecutive spaces, no
/// other whitespace. The forms normalize into this shape; only a hand-edited
/// file can violate it.
pub fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().count() <= 64
        && !name.starts_with(' ')
        && !name.ends_with(' ')
        && !name.contains("  ")
        && !name.chars().any(|c| c.is_whitespace() && c != ' ')
}

/// One connection profile — the desktop equivalent of a `client.toml`. Each
/// active profile runs its own tunnel session with optional local proxy
/// front-ends and its own server-direct port forwards.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub server_node_id: String,
    /// Which shared [`AuthKey`] this profile authenticates with; empty when
    /// none is picked yet (fresh import). A plain reference, not a secret —
    /// it serializes with the rest of the profile.
    #[serde(default)]
    pub auth_key_id: String,
    /// Local SOCKS5 proxy port; `None` leaves that front-end disabled.
    #[serde(default)]
    pub socks_port: Option<u16>,
    /// Local HTTP proxy port; `None` leaves the HTTP front-end disabled.
    #[serde(default)]
    pub http_port: Option<u16>,
    #[serde(default)]
    pub relay_urls: Vec<String>,
    /// Shared bearer token sent to every custom relay (custom relays only).
    /// A secret, so never serialized here: in keychain mode it rides in the
    /// store's encrypted `sealed_keys` blob; the dev file backend re-adds it
    /// via [`StoredProfile`]. Never exported or imported either.
    #[serde(skip)]
    pub relay_auth_token: Option<String>,
    #[serde(default)]
    pub forwards: Vec<PortForward>,
}

impl Profile {
    pub fn new_id() -> String {
        random_id()
    }

    /// Whether the profile can be connected: it must reference a key whose
    /// secret is present. The secret goes missing when the key's keychain
    /// entry was lost (re-entered in the Keys pane).
    pub fn is_ready(&self, keys: &[AuthKey]) -> bool {
        !self.server_node_id.is_empty()
            && find_key(keys, &self.auth_key_id).is_some_and(|k| !k.secret.is_empty())
    }
}

/// The server's entry in the sealed id → secret map. Key ids are 16 hex
/// digits (see `random_id`), so this and the other reserved ids below can only
/// clash with a hand-edited key id, which `drop_invalid_keys` rejects.
const SERVER_SECRET_ID: &str = "server";
/// The server's custom relay auth token in the sealed map.
const SERVER_RELAY_SECRET_ID: &str = "server-relay";
/// A profile's custom relay auth token is sealed under this prefix plus the
/// profile id.
const PROFILE_RELAY_PREFIX: &str = "relay:";

fn profile_relay_secret_id(profile_id: &str) -> String {
    format!("{PROFILE_RELAY_PREFIX}{profile_id}")
}

/// Whether a key id would collide with a non-key entry of the sealed map.
fn is_reserved_secret_id(id: &str) -> bool {
    id == SERVER_SECRET_ID || id == SERVER_RELAY_SECRET_ID || id.starts_with(PROFILE_RELAY_PREFIX)
}

/// The app's one server — the desktop equivalent of a `server.toml`, core
/// settings only: an iroh identity, the authorized client keys, the tunnel set
/// and relays (no host aliases, DNS forwards or bridges). Runs in-process.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfig {
    /// The endpoint id clients connect to. Derived from the secret, but stored
    /// plaintext on purpose (it is public — clients need it) so the UI can
    /// show it even when the secret is lost.
    pub endpoint_id: String,
    /// The iroh identity secret, base64 (the secret line of a
    /// `flextunnel generate-iroh-key` file). Never serialized here: in
    /// keychain mode it rides in the store's encrypted `sealed_keys` blob; the
    /// dev file backend re-adds it via [`StoredServer`].
    #[serde(skip)]
    pub secret: String,
    /// The authorized client keys, as an authorized-keys document: one
    /// `ed25519-pub:...` per line, optional trailing comment, `#` lines and
    /// blank lines ignored.
    #[serde(default)]
    pub authorized_keys: String,
    /// The tunnel set; may be empty (the reserved `flextunnel.internal`
    /// namespace is always routed).
    #[serde(default)]
    pub routed_domains: Vec<String>,
    #[serde(default)]
    pub routed_cidrs: Vec<String>,
    #[serde(default)]
    pub relay_urls: Vec<String>,
    /// Shared bearer token sent to every custom relay (custom relays only).
    /// Sealed like [`Profile::relay_auth_token`]; the dev file re-adds it via
    /// [`StoredServer`].
    #[serde(skip)]
    pub relay_auth_token: Option<String>,
}

impl ServerConfig {
    /// Whether the server can start: its identity secret must be present (it
    /// goes missing when the keychain entry was lost — re-enter it).
    pub fn is_ready(&self) -> bool {
        !self.secret.is_empty()
    }
}

/// Everything the app persists: the shared key list plus the profiles that
/// reference into it, and the server. Saved as one JSON document so a
/// profile can never be written without the key list it points into.
#[derive(Default, Serialize, Deserialize)]
pub struct Store {
    #[serde(default)]
    pub keys: Vec<AuthKey>,
    #[serde(default)]
    pub profiles: Vec<Profile>,
    #[serde(default)]
    pub server: Option<ServerConfig>,
    /// Whether the first-launch login-item registration has happened (see
    /// `App::boot`). Set once and never cleared: from then on the OS
    /// registration is the truth, so a user who switched it off is never
    /// re-registered.
    #[serde(default)]
    pub login_item_set_up: bool,
    /// Set when the sealed secrets could not be unsealed (the keychain entry
    /// was replaced or lost): the secrets above are empty, and a save would
    /// replace the sealed blob with nothing — unrecoverable even once the
    /// keychain entry is restored. Never persisted.
    #[serde(skip)]
    pub unseal_failed: bool,
    /// Set when the sealed secrets were discarded for having been sealed under
    /// another [`SEALED_VERSION`]: the version they were sealed under (0 for
    /// before there was one). They are still on disk until the next save,
    /// which drops them for good. Never persisted.
    #[serde(skip)]
    pub sealed_reset_from: Option<u32>,
    /// The id → secret map (auth keys, the server identity and the relay auth
    /// tokens), sealed under the Safe Storage master key: base64 of 12-byte nonce ‖ AES-256-GCM
    /// ciphertext. Empty when nothing has a secret (and always in dev file
    /// mode, where secrets are inline).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    sealed_keys: String,
    /// The [`SEALED_VERSION`] `sealed_keys` was sealed under; 0 when absent.
    #[serde(default)]
    sealed_version: u32,
}

/// Borrowing twin of [`Store`] so saves don't clone the app state.
#[derive(Serialize)]
struct StoreRef<'a> {
    keys: &'a [AuthKey],
    profiles: &'a [Profile],
    server: Option<&'a ServerConfig>,
    login_item_set_up: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    sealed_keys: String,
    sealed_version: u32,
}

/// Serialization wrapper for the dev file backend only: the secret rides along
/// inline (plaintext, development only) since there is no keychain to hold it.
#[derive(Serialize, Deserialize)]
struct StoredKey {
    #[serde(default)]
    secret: String,
    #[serde(flatten)]
    key: AuthKey,
}

/// Dev file twin of [`StoredKey`] for a profile's relay auth token.
#[derive(Serialize, Deserialize)]
struct StoredProfile {
    #[serde(default)]
    relay_auth_token: Option<String>,
    #[serde(flatten)]
    profile: Profile,
}

/// Dev file twin of [`StoredKey`] for the server's identity secret and relay
/// auth token.
#[derive(Serialize, Deserialize)]
struct StoredServer {
    #[serde(default)]
    secret: String,
    #[serde(default)]
    relay_auth_token: Option<String>,
    #[serde(flatten)]
    server: ServerConfig,
}

/// The dev file's document shape: [`Store`] with secrets inlined.
#[derive(Default, Serialize, Deserialize)]
struct DevFile {
    #[serde(default)]
    keys: Vec<StoredKey>,
    #[serde(default)]
    profiles: Vec<StoredProfile>,
    #[serde(default)]
    server: Option<StoredServer>,
    #[serde(default)]
    login_item_set_up: bool,
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

/// Whether `FLEXTUNNEL_KEYCHAIN` asks for the in-memory mock keychain. It takes
/// `mock` or nothing: any other value is refused rather than read as the real
/// keychain.
fn mock_keychain(value: Option<&std::ffi::OsStr>) -> Result<bool> {
    match value {
        None => Ok(false),
        Some(value) if value == "mock" => Ok(true),
        Some(value) => {
            anyhow::bail!("{KEYCHAIN_ENV} is {value:?}; the only value it takes is \"mock\"")
        }
    }
}

/// The sealed store's file: `profiles.json`, or `mock-profiles.json` for the
/// mock keychain, whose secrets no other run's master key opens.
fn sealed_path(mock: bool) -> Result<PathBuf> {
    let name = if mock { "mock-profiles.json" } else { "profiles.json" };
    dirs::data_local_dir()
        .map(|d| d.join("flextunnel").join(name))
        .ok_or_else(|| anyhow::anyhow!("no local data directory to store profiles in"))
}

fn backend() -> Result<&'static Backend> {
    BACKEND
        .get()
        .context("No settings store: see the startup error in the log")
}

/// Whether a development store is in use — the plaintext dev file
/// (`FLEXTUNNEL_DEV_CONFIG`) or the mock keychain (`FLEXTUNNEL_KEYCHAIN=mock`)
/// — or none could be set up: no real install's state (its login item) is
/// touched then.
pub fn dev_store() -> bool {
    !matches!(BACKEND.get(), Some(Backend::Keychain))
}

/// Choose the storage backend: the dev file when `FLEXTUNNEL_DEV_CONFIG` is
/// set, the mock keychain when `FLEXTUNNEL_KEYCHAIN=mock`, else the platform
/// keychain (the macOS Keychain, Windows Credential Manager). Must run before
/// any load/save.
pub fn init_store() -> Result<()> {
    let mock = mock_keychain(std::env::var_os(KEYCHAIN_ENV).as_deref())?;
    if let Some(path) = dev_config_path() {
        anyhow::ensure!(!mock, "{DEV_CONFIG_ENV} and {KEYCHAIN_ENV}=mock are both set; pick one");
        log::warn!(
            "{DEV_CONFIG_ENV} set: storing profiles (secret keys included) UNENCRYPTED at {} \
             (development only)",
            path.display()
        );
        let _ = BACKEND.set(Backend::DevFile(path));
        return Ok(());
    }
    if mock {
        // The master key dies with the process, so the last mock run's file
        // could never be unsealed: every mock run starts empty.
        let path = sealed_path(true)?;
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("Failed to empty {}", path.display())),
        }
        log::warn!(
            "{KEYCHAIN_ENV}=mock: the Safe Storage key lives in memory and the store at {} \
             is emptied each run (testing only)",
            path.display()
        );
        keyring_core::set_default_store(
            keyring_core::mock::Store::new().context("Failed to open the mock keychain")?,
        );
        let _ = BACKEND.set(Backend::MockKeychain);
        return Ok(());
    }
    // Set before the keychain opens: a store without secrets still loads and
    // saves when it won't (see `load_store`).
    let _ = BACKEND.set(Backend::Keychain);
    #[cfg(target_os = "macos")]
    let store = apple_native_keyring_store::keychain::Store::new();
    #[cfg(windows)]
    let store = windows_native_keyring_store::Store::new();
    keyring_core::set_default_store(store.context("Failed to open the system keychain")?);
    Ok(())
}

/// The Safe Storage master key: read from its keychain entry, generated (and
/// stored) on first use, and cached for the process lifetime — so the
/// keychain is touched at most once per run, which on macOS means at most
/// one authorization prompt no matter how often the store saves.
fn safe_storage_key() -> Result<[u8; 32]> {
    static CACHE: std::sync::Mutex<Option<[u8; 32]>> = std::sync::Mutex::new(None);
    let mut cache = CACHE.lock().unwrap();
    if let Some(key) = *cache {
        return Ok(key);
    }
    let entry = keyring_core::Entry::new(SAFE_STORAGE_SERVICE, SAFE_STORAGE_USER)
        .context("Failed to open the Safe Storage keychain entry")?;
    let key = match entry.get_password() {
        Ok(b64) => BASE64
            .decode(&b64)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or_else(|| {
                anyhow::anyhow!("The {SAFE_STORAGE_SERVICE} entry is not a base64 32-byte key")
            })?,
        Err(keyring_core::Error::NoEntry) => {
            let key: [u8; 32] = rand::random();
            entry
                .set_password(&BASE64.encode(key))
                .context("Failed to store the Safe Storage key in the keychain")?;
            key
        }
        Err(e) => return Err(e).context("Failed to read the Safe Storage key from the keychain"),
    };
    *cache = Some(key);
    Ok(key)
}

/// The `(id, secret)` pairs sealed into `sealed_keys`: every auth key, every
/// profile's relay auth token, plus the server identity under
/// [`SERVER_SECRET_ID`] and its relay auth token under
/// [`SERVER_RELAY_SECRET_ID`].
fn secret_entries<'a>(
    keys: &'a [AuthKey],
    profiles: &'a [Profile],
    server: Option<&'a ServerConfig>,
) -> impl Iterator<Item = (String, &'a str)> {
    let relay = |token: &'a Option<String>| token.as_deref().unwrap_or_default();
    keys.iter()
        .map(|k| (k.id.clone(), k.secret.as_str()))
        .chain(
            profiles
                .iter()
                .map(move |p| (profile_relay_secret_id(&p.id), relay(&p.relay_auth_token))),
        )
        .chain(server.into_iter().flat_map(move |s| {
            [
                (SERVER_SECRET_ID.to_owned(), s.secret.as_str()),
                (SERVER_RELAY_SECRET_ID.to_owned(), relay(&s.relay_auth_token)),
            ]
        }))
}

/// Seal the id → secret map of `entries` into the `sealed_keys` blob.
/// Secretless entries (lost secrets, profiles without a relay token) are left
/// out so a later load warns about them again instead of loading an empty
/// secret; an all-secretless list seals to the empty string, which
/// `open_secrets` never sees.
fn seal_secrets<'a>(
    master: &[u8; 32],
    entries: impl Iterator<Item = (String, &'a str)>,
) -> Result<String> {
    let map: std::collections::BTreeMap<String, &str> =
        entries.filter(|(_, secret)| !secret.is_empty()).collect();
    if map.is_empty() {
        return Ok(String::new());
    }
    let cipher = Aes256Gcm::new(master.into());
    let nonce: [u8; 12] = rand::random();
    let ciphertext = cipher
        .encrypt((&nonce).into(), serde_json::to_vec(&map)?.as_slice())
        .map_err(|_| anyhow::anyhow!("Failed to encrypt the secrets"))?;
    Ok(BASE64.encode([&nonce[..], &ciphertext].concat()))
}

/// Decrypt a non-empty `sealed_keys` blob back into the id → secret map.
/// Fails when the blob is malformed or was sealed under a different master
/// key (i.e. the Safe Storage keychain entry was lost and regenerated).
fn open_secrets(
    master: &[u8; 32],
    sealed: &str,
) -> Result<std::collections::HashMap<String, String>> {
    let blob = BASE64
        .decode(sealed)
        .context("The sealed_keys blob is not base64")?;
    let (nonce, ciphertext) = blob
        .split_first_chunk::<12>()
        .context("The sealed_keys blob is too short")?;
    let cipher = Aes256Gcm::new(master.into());
    let plain = cipher
        .decrypt(nonce.into(), ciphertext)
        .map_err(|_| anyhow::anyhow!("Failed to decrypt the sealed secrets"))?;
    serde_json::from_slice(&plain).context("Failed to parse the unsealed secrets")
}

/// Drop structurally invalid keys from a (possibly hand-edited) store,
/// keeping the first occurrence of duplicates: an empty id would match
/// profiles with no key picked, duplicate ids break the profile references
/// and the keychain keying, malformed or duplicate names break the picker,
/// and a duplicate public key means the same keypair was accidentally added
/// twice. The form rejects all of these; this is the backstop.
fn drop_invalid_keys(keys: Vec<AuthKey>) -> Vec<AuthKey> {
    let mut ids = std::collections::HashSet::new();
    let mut names = std::collections::HashSet::new();
    let mut publics = std::collections::HashSet::new();
    keys.into_iter()
        .filter(|k| {
            // An empty id would match every profile that has no key picked
            // (`auth_key_id` defaults to empty) — see `find_key`.
            if k.id.is_empty() {
                log::error!("Ignoring key \"{}\": empty key id", k.name);
                return false;
            }
            if !ids.insert(k.id.clone()) {
                log::error!("Ignoring key \"{}\": duplicate key id {}", k.name, k.id);
                return false;
            }
            if is_reserved_secret_id(&k.id) {
                log::error!("Ignoring key \"{}\": reserved key id {}", k.name, k.id);
                return false;
            }
            if !is_valid_name(&k.name) {
                log::error!(
                    "Ignoring key {}: invalid name {:?} (1-64 chars, single spaces \
                     between words only)",
                    k.id,
                    k.name
                );
                return false;
            }
            if !names.insert(k.name.clone()) {
                log::error!("Ignoring a key: duplicate key name \"{}\"", k.name);
                return false;
            }
            if !publics.insert(k.public_key.clone()) {
                log::error!(
                    "Ignoring key \"{}\": another key already holds its public key",
                    k.name
                );
                return false;
            }
            true
        })
        .collect()
}

/// Drop structurally invalid entries from a (possibly hand-edited) profiles
/// file, keeping the first occurrence of duplicates: duplicate profile ids
/// break the session/snapshot keying, malformed or duplicate names break
/// everything keyed by name (session thread names / log attribution, tray
/// submenus), and duplicate server node ids mean two profiles for one server.
/// The form rejects all of these; this is the backstop.
fn drop_invalid(profiles: Vec<Profile>) -> Vec<Profile> {
    let mut ids = std::collections::HashSet::new();
    let mut names = std::collections::HashSet::new();
    let mut servers = std::collections::HashSet::new();
    profiles
        .into_iter()
        .filter(|p| {
            if !ids.insert(p.id.clone()) {
                log::error!("Ignoring profile \"{}\": duplicate profile id {}", p.name, p.id);
                return false;
            }
            if !is_valid_name(&p.name) {
                log::error!(
                    "Ignoring profile {}: invalid name {:?} (1-64 chars, single spaces \
                     between words only)",
                    p.id,
                    p.name
                );
                return false;
            }
            if !names.insert(p.name.clone()) {
                log::error!("Ignoring a profile: duplicate profile name \"{}\"", p.name);
                return false;
            }
            if !servers.insert(p.server_node_id.clone()) {
                log::error!(
                    "Ignoring profile \"{}\": another profile already uses its server node id",
                    p.name
                );
                return false;
            }
            true
        })
        .collect()
}

/// The id → secret map of a loaded sealed store. Empty with no keychain access
/// when there is no blob (a store without secrets never prompts) or it was
/// sealed under another [`SEALED_VERSION`]: those secrets are discarded
/// whole (`sealed_reset_from` set), and the next save drops the blob. Empty with `unseal_failed` set
/// when the blob will not open under the current master key.
fn unseal_store(store: &mut Store) -> Result<std::collections::HashMap<String, String>> {
    if store.sealed_keys.is_empty() {
        return Ok(Default::default());
    }
    if store.sealed_version != SEALED_VERSION {
        log::warn!(
            "The stored secrets were sealed by format version {}, this build reads version \
             {SEALED_VERSION}: starting fresh, every secret must be re-entered",
            store.sealed_version
        );
        store.sealed_reset_from = Some(store.sealed_version);
        return Ok(Default::default());
    }
    match open_secrets(&safe_storage_key()?, &store.sealed_keys) {
        Ok(map) => Ok(map),
        Err(e) => {
            log::error!(
                "Failed to unseal the stored secrets (was the \
                 \"{SAFE_STORAGE_SERVICE}\" keychain entry replaced?): {e:#}"
            );
            store.unseal_failed = true;
            Ok(Default::default())
        }
    }
}

/// Load the whole store; empty when nothing has been saved yet. In keychain
/// mode each key's and the server's secret, and every relay auth token, is
/// filled from the unsealed
/// `sealed_keys` blob — a missing secret (or a blob the current Safe Storage
/// key can't decrypt) loads as an empty secret with a warning instead of
/// failing. Structurally invalid keys and profiles are ignored (see the
/// `drop_invalid*` backstops); a profile referencing an unknown key is kept
/// but can't connect until a key is picked.
pub fn load_store() -> Result<Store> {
    let mut store = match backend()? {
        Backend::DevFile(path) => {
            let mut store = load_dev_file(path)?;
            store.keys = drop_invalid_keys(store.keys);
            store
        }
        backend => {
            let mock = matches!(backend, Backend::MockKeychain);
            let mut store: Store = read_json(&sealed_path(mock)?)?.unwrap_or_default();
            store.keys = drop_invalid_keys(store.keys);
            let secrets = unseal_store(&mut store)?;
            for key in &mut store.keys {
                match secrets.get(&key.id) {
                    Some(secret) => key.secret = secret.clone(),
                    None => log::warn!(
                        "No keychain secret for key \"{}\"; its secret must be re-entered",
                        key.name
                    ),
                }
            }
            // A relay token is optional, so a missing one is not lost.
            for profile in &mut store.profiles {
                profile.relay_auth_token =
                    secrets.get(&profile_relay_secret_id(&profile.id)).cloned();
            }
            if let Some(server) = &mut store.server {
                match secrets.get(SERVER_SECRET_ID) {
                    Some(secret) => server.secret = secret.clone(),
                    None => log::warn!(
                        "No keychain secret for the server; its identity key must be re-entered"
                    ),
                }
                server.relay_auth_token = secrets.get(SERVER_RELAY_SECRET_ID).cloned();
            }
            store
        }
    };
    store.profiles = drop_invalid(store.profiles);
    for profile in &store.profiles {
        if !profile.auth_key_id.is_empty() && find_key(&store.keys, &profile.auth_key_id).is_none()
        {
            log::warn!(
                "Profile \"{}\" references an unknown auth key; pick one to connect",
                profile.name
            );
        }
    }
    Ok(store)
}

/// Persist the key list, profiles and server, secrets sealed. This is the
/// whole save: one atomic file write covers adds, edits, and deletions alike.
/// The Safe Storage key is cached after its first use, so routine saves after
/// a forward toggle never touch the keychain (and a store holding no secrets
/// skips it entirely).
pub fn save_store(
    keys: &[AuthKey],
    profiles: &[Profile],
    server: Option<&ServerConfig>,
    login_item_set_up: bool,
) -> Result<()> {
    match backend()? {
        Backend::DevFile(path) => save_dev_file(path, keys, profiles, server, login_item_set_up),
        backend => {
            let sealed_keys =
                if secret_entries(keys, profiles, server).all(|(_, s)| s.is_empty()) {
                    String::new()
                } else {
                    seal_secrets(&safe_storage_key()?, secret_entries(keys, profiles, server))?
                };
            write_json(
                &sealed_path(matches!(backend, Backend::MockKeychain))?,
                &StoreRef {
                    keys,
                    profiles,
                    server,
                    login_item_set_up,
                    sealed_keys,
                    sealed_version: SEALED_VERSION,
                },
            )
        }
    }
}

/// Export all profiles to a user-chosen file. Non-secrets only, whatever the
/// backend: a profile's one secret, its relay auth token, never serializes.
/// Profile ids, forward ids, and the auth-key reference are
/// stripped too — they are app-local keys that mean nothing in another
/// install, not part of the portable data.
pub fn export_profiles(path: &Path, profiles: &[Profile]) -> Result<()> {
    let mut values = serde_json::to_value(profiles)?;
    for entry in values.as_array_mut().into_iter().flatten() {
        if let Some(profile) = entry.as_object_mut() {
            profile.remove("id");
            profile.remove("auth_key_id");
            for forward in forwards_of(profile) {
                forward.remove("id");
            }
        }
    }
    write_json(path, &values)
}

/// Read an export file back, applying the same structural validation as a
/// load (malformed names and in-file duplicates are dropped with logs). The
/// caller merges the result into the current profiles and assigns final ids;
/// missing ids (the normal export shape) get placeholders here so the entries
/// deserialize. No secret or key reference is imported: neither is ever in an
/// export, and a hand-written auth-key reference is dropped rather than
/// trusted (a hand-written relay auth token never deserializes), so imported
/// entries come back with both empty.
pub fn import_profiles(path: &Path) -> Result<Vec<Profile>> {
    let mut values: serde_json::Value = read_json(path)?
        .ok_or_else(|| anyhow::anyhow!("{} does not exist", path.display()))?;
    for entry in values.as_array_mut().into_iter().flatten() {
        if let Some(profile) = entry.as_object_mut() {
            profile
                .entry("id")
                .or_insert_with(|| Profile::new_id().into());
            profile.remove("auth_key_id");
            for forward in forwards_of(profile) {
                forward
                    .entry("id")
                    .or_insert_with(|| PortForward::new_id().into());
            }
        }
    }
    let profiles: Vec<Profile> = serde_json::from_value(values)
        .with_context(|| format!("Failed to parse {}", path.display()))?;
    Ok(drop_invalid(profiles))
}

/// The mutable forward objects of a profile JSON object (empty when absent).
fn forwards_of(
    profile: &mut serde_json::Map<String, serde_json::Value>,
) -> impl Iterator<Item = &mut serde_json::Map<String, serde_json::Value>> {
    profile
        .get_mut("forwards")
        .and_then(|f| f.as_array_mut())
        .into_iter()
        .flatten()
        .filter_map(|f| f.as_object_mut())
}

fn load_dev_file(path: &Path) -> Result<Store> {
    let stored: DevFile = read_json(path)?.unwrap_or_default();
    Ok(Store {
        keys: stored
            .keys
            .into_iter()
            .map(|s| AuthKey {
                secret: s.secret,
                ..s.key
            })
            .collect(),
        profiles: stored
            .profiles
            .into_iter()
            .map(|s| Profile {
                relay_auth_token: s.relay_auth_token,
                ..s.profile
            })
            .collect(),
        server: stored.server.map(|s| ServerConfig {
            secret: s.secret,
            relay_auth_token: s.relay_auth_token,
            ..s.server
        }),
        login_item_set_up: stored.login_item_set_up,
        unseal_failed: false,
        sealed_reset_from: None,
        sealed_keys: String::new(),
        sealed_version: 0,
    })
}

fn save_dev_file(
    path: &Path,
    keys: &[AuthKey],
    profiles: &[Profile],
    server: Option<&ServerConfig>,
    login_item_set_up: bool,
) -> Result<()> {
    let stored = DevFile {
        keys: keys
            .iter()
            .map(|k| StoredKey {
                secret: k.secret.clone(),
                key: k.clone(),
            })
            .collect(),
        profiles: profiles
            .iter()
            .map(|p| StoredProfile {
                relay_auth_token: p.relay_auth_token.clone(),
                profile: p.clone(),
            })
            .collect(),
        server: server.map(|s| StoredServer {
            secret: s.secret.clone(),
            relay_auth_token: s.relay_auth_token.clone(),
            server: s.clone(),
        }),
        login_item_set_up,
    };
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

    fn key() -> AuthKey {
        AuthKey {
            id: "key1".into(),
            name: "work laptop".into(),
            public_key: "ed25519-pub:abc".into(),
            // Distinctive sentinel so the leak-check assertions match the
            // secret *value* and don't collide with field names.
            secret: "ftc-secret-authtok".into(),
        }
    }

    fn server() -> ServerConfig {
        ServerConfig {
            endpoint_id: "endpoint".into(),
            secret: "ftc-secret-identity".into(),
            authorized_keys: "ed25519-pub:abc work laptop\n".into(),
            routed_domains: vec!["*.internal".into()],
            routed_cidrs: vec!["10.0.0.0/8".into()],
            relay_urls: vec!["https://relay.example".into()],
            relay_auth_token: Some("ftc-secret-serverpsk".into()),
        }
    }

    fn seal(master: &[u8; 32], keys: &[AuthKey]) -> String {
        seal_secrets(master, secret_entries(keys, &[], None)).unwrap()
    }

    fn profile() -> Profile {
        Profile {
            id: "00000000deadbeef".into(),
            name: "prod".into(),
            server_node_id: "node".into(),
            auth_key_id: "key1".into(),
            socks_port: Some(1085),
            http_port: Some(8081),
            relay_urls: vec!["https://relay.example".into()],
            relay_auth_token: Some("ftc-secret-relaypsk".into()),
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
        assert_eq!(p.socks_port, None);
        assert_eq!(p.http_port, None);
        assert!(p.relay_urls.is_empty());
        assert!(p.forwards.is_empty());
        assert!(p.auth_key_id.is_empty());
    }

    #[test]
    fn secret_never_serializes_in_store() {
        let json = serde_json::to_string(&StoreRef {
            keys: &[key()],
            profiles: &[profile()],
            server: Some(&server()),
            login_item_set_up: false,
            sealed_keys: String::new(),
            sealed_version: SEALED_VERSION,
        })
        .unwrap();
        assert!(!json.contains("ftc-secret-authtok"), "secret leaked: {json}");
        assert!(!json.contains("ftc-secret-identity"), "server secret leaked: {json}");
        // The server's public identity and settings persist.
        assert!(json.contains("\"endpoint_id\":\"endpoint\""), "endpoint id dropped: {json}");
        assert!(json.contains("*.internal"), "tunnel set dropped: {json}");
        // The non-secret halves of the key persist, as does the profile's
        // reference to it.
        assert!(json.contains("ed25519-pub:abc"), "public key dropped: {json}");
        assert!(json.contains("\"auth_key_id\":\"key1\""), "reference dropped: {json}");
        // `enabled` is runtime-only on forwards and must not leak either.
        assert!(!json.contains("enabled"), "enabled leaked: {json}");
        // The relay tokens are secrets: sealed, never plaintext.
        assert!(!json.contains("relay_auth_token"), "relay token field leaked: {json}");
        assert!(!json.contains("ftc-secret-relaypsk"), "profile relay token leaked: {json}");
        assert!(!json.contains("ftc-secret-serverpsk"), "server relay token leaked: {json}");
    }

    #[test]
    fn sealed_secrets_roundtrip_without_leaking_plaintext() {
        let master = [7u8; 32];
        let mut no_relay = profile();
        no_relay.id = "00000000feedface".into();
        no_relay.relay_auth_token = None;
        let (keys, profiles, server) = ([key()], [profile(), no_relay], server());
        let sealed =
            seal_secrets(&master, secret_entries(&keys, &profiles, Some(&server))).unwrap();
        assert!(!sealed.contains("ftc-secret-authtok"), "secret leaked: {sealed}");
        assert!(!sealed.contains("ftc-secret-identity"), "server secret leaked: {sealed}");
        assert!(!sealed.contains("ftc-secret-relaypsk"), "relay token leaked: {sealed}");
        let map = open_secrets(&master, &sealed).unwrap();
        // The profile without a relay token seals nothing.
        assert_eq!(map.len(), 4);
        assert_eq!(map.get("key1").map(String::as_str), Some("ftc-secret-authtok"));
        assert_eq!(map.get(SERVER_SECRET_ID).map(String::as_str), Some("ftc-secret-identity"));
        assert_eq!(
            map.get(SERVER_RELAY_SECRET_ID).map(String::as_str),
            Some("ftc-secret-serverpsk")
        );
        assert_eq!(
            map.get(&profile_relay_secret_id(&profile().id)).map(String::as_str),
            Some("ftc-secret-relaypsk")
        );
    }

    /// Secretless keys stay out of the seal (so a load warns about them),
    /// and an all-secretless list seals to the no-blob marker.
    #[test]
    fn secretless_keys_are_not_sealed() {
        let master = [7u8; 32];
        let mut lost = key();
        lost.secret = String::new();

        assert_eq!(seal(&master, &[lost.clone()]), "");

        let mut other = key();
        other.id = "key2".into();
        let sealed = seal(&master, &[lost, other]);
        let map = open_secrets(&master, &sealed).unwrap();
        assert_eq!(map.keys().collect::<Vec<_>>(), ["key2"]);
    }

    /// A blob sealed under another format version — or before there was one —
    /// is discarded whole, before the keychain is asked for the master key:
    /// no secret loads, and it is not an unseal failure.
    #[test]
    fn a_blob_of_another_sealed_version_starts_fresh() {
        for version in [0, SEALED_VERSION + 1] {
            let mut store = Store {
                sealed_keys: seal(&[7u8; 32], &[key()]),
                sealed_version: version,
                ..Default::default()
            };
            let secrets = unseal_store(&mut store).unwrap();
            assert!(secrets.is_empty(), "version {version}: {secrets:?}");
            assert!(!store.unseal_failed, "version {version}");
            assert_eq!(store.sealed_reset_from, Some(version));
        }
        let unversioned: Store = serde_json::from_str(r#"{"sealed_keys":"AAAA"}"#).unwrap();
        assert_eq!(unversioned.sealed_version, 0);
    }

    /// A blob sealed under a different master key (a replaced Safe Storage
    /// entry) or malformed base64 must fail loudly, not decrypt to garbage.
    #[test]
    fn unsealing_rejects_wrong_key_and_malformed_blobs() {
        let sealed = seal(&[7u8; 32], &[key()]);
        assert!(open_secrets(&[8u8; 32], &sealed).is_err(), "wrong master key");
        assert!(open_secrets(&[7u8; 32], "not base64!").is_err());
        assert!(open_secrets(&[7u8; 32], "AAAA").is_err(), "shorter than a nonce");
    }

    #[test]
    fn is_ready_requires_a_resolvable_secret() {
        let keys = [key()];
        assert!(profile().is_ready(&keys));

        let mut lost = key();
        lost.secret = String::new();
        assert!(!profile().is_ready(&[lost]), "lost keychain entry");

        assert!(!profile().is_ready(&[]), "dangling key reference");

        let mut unpicked = profile();
        unpicked.auth_key_id = String::new();
        assert!(!unpicked.is_ready(&keys), "no key picked");
    }

    #[test]
    fn invalid_and_duplicate_keys_are_dropped() {
        let a = key();
        let mut same_id = key();
        same_id.name = "other".into();
        same_id.public_key = "ed25519-pub:other".into();
        let mut same_name = key();
        same_name.id = "key2".into();
        same_name.public_key = "ed25519-pub:def".into();
        let mut same_public = key();
        same_public.id = "key3".into();
        same_public.name = "same pubkey".into();
        let mut bad_name = key();
        bad_name.id = "key4".into();
        bad_name.name = " padded ".into();
        bad_name.public_key = "ed25519-pub:ghi".into();
        let mut empty_id = key();
        empty_id.id = String::new();
        empty_id.name = "no id".into();
        empty_id.public_key = "ed25519-pub:mno".into();
        // The server's slot in the sealed secret map.
        let mut reserved_id = key();
        reserved_id.id = SERVER_SECRET_ID.into();
        reserved_id.name = "reserved".into();
        reserved_id.public_key = "ed25519-pub:pqr".into();
        // The relay tokens' slots: the server's and a profile's.
        let mut server_relay_id = key();
        server_relay_id.id = SERVER_RELAY_SECRET_ID.into();
        server_relay_id.name = "server relay".into();
        server_relay_id.public_key = "ed25519-pub:stu".into();
        let mut profile_relay_id = key();
        profile_relay_id.id = profile_relay_secret_id("00000000deadbeef");
        profile_relay_id.name = "profile relay".into();
        profile_relay_id.public_key = "ed25519-pub:vwx".into();
        let mut unique = key();
        unique.id = "key5".into();
        unique.name = "home".into();
        unique.public_key = "ed25519-pub:jkl".into();

        let kept = drop_invalid_keys(vec![
            a.clone(),
            same_id,
            same_name,
            same_public,
            bad_name,
            empty_id,
            reserved_id,
            server_relay_id,
            profile_relay_id,
            unique.clone(),
        ]);
        assert_eq!(kept, vec![a, unique]);
    }

    #[test]
    fn duplicate_ids_and_servers_are_dropped() {
        let a = profile();
        let mut same_server = profile();
        same_server.id = "b".into();
        same_server.name = "b".into();
        let mut same_id = profile();
        same_id.name = "c".into();
        same_id.server_node_id = "other".into();
        let mut same_name = profile();
        same_name.id = "n".into();
        same_name.server_node_id = "elsewhere".into();
        let mut bad_name = profile();
        bad_name.id = "w".into();
        bad_name.name = " padded ".into();
        bad_name.server_node_id = "padded-server".into();
        let mut unique = profile();
        unique.id = "d".into();
        unique.name = "d".into();
        unique.server_node_id = "unique".into();

        let kept = drop_invalid(vec![
            a.clone(),
            same_server,
            same_id,
            same_name,
            bad_name,
            unique.clone(),
        ]);
        assert_eq!(kept, vec![a, unique]);
    }

    #[test]
    fn export_strips_ids_and_import_regenerates_them() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.json");

        export_profiles(&path, &[profile()]).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("\"id\""), "ids leaked into the export: {raw}");
        assert!(
            !raw.contains("auth_key_id"),
            "app-local key reference leaked into the export: {raw}"
        );
        assert!(
            !raw.contains("ftc-secret-relaypsk") && !raw.contains("relay_auth_token"),
            "relay auth token leaked into the export: {raw}"
        );
        // The non-secret relay setting it pairs with still travels.
        assert!(raw.contains("https://relay.example"), "relay urls dropped: {raw}");

        let imported = import_profiles(&path).unwrap();
        assert_eq!(imported.len(), 1);
        let p = &imported[0];
        assert!(!p.id.is_empty(), "placeholder profile id assigned");
        assert!(p.auth_key_id.is_empty());
        assert_eq!(p.relay_auth_token, None);
        assert_eq!(p.relay_urls, profile().relay_urls);
        assert_eq!(p.name, profile().name);
        assert_eq!(p.socks_port, profile().socks_port);
        assert_eq!(p.forwards.len(), 1);
        assert!(!p.forwards[0].id.is_empty(), "placeholder forward id assigned");
        assert_eq!(p.forwards[0].local_port, profile().forwards[0].local_port);
    }

    /// Hand-written files can carry the relay token or an auth-key reference;
    /// both are dropped rather than trusted, same as if never written.
    #[test]
    fn import_drops_untrusted_fields_present_in_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.json");
        std::fs::write(
            &path,
            r#"[{"name":"prod","server_node_id":"node",
                 "auth_key_id":"key1",
                 "relay_urls":["https://relay.example"],
                 "relay_auth_token":"ftc-secret-relaypsk"}]"#,
        )
        .unwrap();

        let imported = import_profiles(&path).unwrap();
        assert_eq!(imported.len(), 1);
        assert!(imported[0].auth_key_id.is_empty());
        assert_eq!(imported[0].relay_auth_token, None);
        assert_eq!(imported[0].relay_urls, vec!["https://relay.example"]);
    }

    #[test]
    fn name_format_rules() {
        assert!(is_valid_name("prod"));
        assert!(is_valid_name("staging aws kube"));

        assert!(!is_valid_name(""));
        assert!(!is_valid_name(" prod"));
        assert!(!is_valid_name("prod "));
        assert!(!is_valid_name("staging  aws"));
        assert!(!is_valid_name("staging\taws"));
        assert!(!is_valid_name("staging\naws"));
        assert!(!is_valid_name(&"a".repeat(65)));
    }

    #[test]
    fn dev_file_roundtrips_with_secrets_and_missing_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("dev-profiles.json");

        let empty = load_dev_file(&path).unwrap();
        assert!(empty.keys.is_empty() && empty.profiles.is_empty() && empty.server.is_none());

        let keys = vec![key()];
        let mut profiles = vec![profile()];
        let server = server();
        save_dev_file(&path, &keys, &profiles, Some(&server), true).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            raw.contains("\"secret\": \"ftc-secret-authtok\""),
            "secret missing: {raw}"
        );
        assert!(
            raw.contains("\"secret\": \"ftc-secret-identity\""),
            "server secret missing: {raw}"
        );
        assert!(
            raw.contains("\"relay_auth_token\": \"ftc-secret-relaypsk\""),
            "profile relay token missing: {raw}"
        );
        assert!(
            raw.contains("\"relay_auth_token\": \"ftc-secret-serverpsk\""),
            "server relay token missing: {raw}"
        );

        // Forward `enabled` is runtime-only: comes back off.
        profiles[0].forwards[0].enabled = false;
        let loaded = load_dev_file(&path).unwrap();
        assert_eq!(loaded.keys, keys);
        assert_eq!(loaded.profiles, profiles);
        assert_eq!(loaded.server, Some(server));
        assert!(loaded.login_item_set_up);
    }

    /// `FLEXTUNNEL_KEYCHAIN` takes `mock` or nothing: a typo is not the real
    /// keychain.
    #[test]
    fn the_mock_keychain_is_asked_for_by_name_only() {
        use std::ffi::OsStr;
        assert!(!mock_keychain(None).unwrap());
        assert!(mock_keychain(Some(OsStr::new("mock"))).unwrap());
        for wrong in ["", "Mock", "memory", "1"] {
            let e = mock_keychain(Some(OsStr::new(wrong))).unwrap_err();
            assert!(format!("{e:#}").contains("only value it takes"), "{wrong:?}: {e:#}");
        }
    }

    /// On the mock keychain the Safe Storage key is generated on first use,
    /// kept in the store's entry, and sealed secrets open under it — the
    /// path a `FLEXTUNNEL_KEYCHAIN=mock` run takes. The only test that installs
    /// a keychain store, so the process-wide store and key cache are its own.
    #[test]
    fn the_mock_keychain_holds_the_safe_storage_key() {
        keyring_core::set_default_store(keyring_core::mock::Store::new().unwrap());
        let master = safe_storage_key().unwrap();
        let entry = keyring_core::Entry::new(SAFE_STORAGE_SERVICE, SAFE_STORAGE_USER).unwrap();
        assert_eq!(entry.get_password().unwrap(), BASE64.encode(master));
        let sealed = seal(&master, &[key()]);
        let opened = open_secrets(&safe_storage_key().unwrap(), &sealed).unwrap();
        assert_eq!(opened["key1"], "ftc-secret-authtok");
    }
}
