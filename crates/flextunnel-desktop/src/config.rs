//! Client, server and auth-key persistence. The app runs one client
//! ([`ClientSettings`]): its local proxy ports, its port forwards, and any
//! number of [`Destination`]s — a name for one flextunnel server each.
//! Client auth keys live in a shared, named list so several destinations can
//! authenticate with the same keypair; each destination references one by
//! [`AuthKey::id`]. The optional [`ServerConfig`] runs the one flextunnel
//! server the app hosts in-process. The non-secret data (key names and public
//! halves, destination names, server ids, routes, ports, forwards, the
//! server's tunnel set and authorized clients) lives in a plaintext
//! `profiles.json` under the local data dir — same treatment as the iOS app's
//! `forwards.json`. The secrets (auth-key secret halves, the server's identity
//! key, and the destinations' and server's custom relay auth tokens) ride in
//! the same file, sealed the way Chrome/Slack/Notion store their secrets: a
//! single keychain entry ("Flextunnel Safe Storage", macOS Keychain / Windows
//! Credential Manager) holds a random 256-bit master key, and the id → secret
//! map (key ids, the reserved [`SERVER_SECRET_ID`] and
//! [`SERVER_RELAY_SECRET_ID`], and a [`DESTINATION_RELAY_PREFIX`]ed id per
//! destination relay token) is
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

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit};
use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use flextunnel_core::forwards::{PortForward, validate_label, validate_remote_host};
use flextunnel_core::proxy::routed_set::Coverage;
use flextunnel_core::proxy::{
    DestinationStatus, RouteSpec, RouteTable, RoutedSet, validate_destination_name,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const DEFAULT_SOCKS_PORT: u16 = 1080;
/// Suggested HTTP proxy port for the proxy form. Deliberately high — 8080
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
/// path) to store the settings as plaintext JSON instead of the system keychain.
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

/// One named client auth keypair, shared across destinations: any number of
/// destinations can pick the same key to authenticate with (its public half
/// then only needs one line on each server's authorized-keys file).
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

/// A well-formed key or authorized-client name: 1-64 characters, words separated by
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

/// One destination of the client — the desktop equivalent of a
/// `[[destinations]]` table in `client.toml`: a name for one flextunnel
/// server, the key to authenticate with, and what else to send through it.
/// The client connects to it when something is first sent there.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Destination {
    pub id: String,
    /// The destination's name — one DNS label, unique among the
    /// destinations — in the core's stored (lowercased) form:
    /// `<name>.localhost.flextunnel.internal:<port>` through the client's
    /// proxy or a forward reaches that port on the server's own loopback.
    pub name: String,
    pub server_node_id: String,
    /// Further domains sent through the server (exact, `*.suffix`, or `*`).
    /// The server must route them too.
    #[serde(default)]
    pub routed_domains: Vec<String>,
    /// Further networks or bare IPs sent through the server. The server must
    /// route them too.
    #[serde(default)]
    pub routed_cidrs: Vec<String>,
    /// Which shared [`AuthKey`] this destination authenticates with; empty
    /// when none is picked yet (fresh import). A plain reference, not a
    /// secret — it serializes with the rest of the destination.
    #[serde(default)]
    pub auth_key_id: String,
    #[serde(default)]
    pub relay_urls: Vec<String>,
    /// Shared bearer token sent to every custom relay (custom relays only).
    /// A secret, so never serialized here: in keychain mode it rides in the
    /// store's encrypted `sealed_keys` blob; the dev file keeps it in
    /// [`DevFile::destination_relay_tokens`]. Never exported or imported.
    #[serde(skip)]
    pub relay_auth_token: Option<String>,
    /// Whether the custom relays serve QUIC address discovery, all of them or
    /// none (custom relays only; see [`relay_quic_addr_discovery_setting`]).
    /// Not a secret: it describes the relays, and travels with their URLs.
    #[serde(default = "on")]
    pub relay_quic_addr_discovery: bool,
}

/// Serde's default for a setting that is on unless stored otherwise.
fn on() -> bool {
    true
}

/// A stored `relay_quic_addr_discovery` as the core takes it: left unset
/// while on, which is the default, so that only turning it off is a setting.
/// The core refuses one without custom relays, as it does a relay auth token.
pub fn relay_quic_addr_discovery_setting(enabled: bool) -> Option<bool> {
    (!enabled).then_some(false)
}

impl Destination {
    pub fn new_id() -> String {
        random_id()
    }
}

/// The app's one client — the desktop equivalent of a `client.toml`: the local
/// proxy front-ends, the port forwards, and the destinations they reach. One
/// session serves them all, connecting to each destination on demand.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClientSettings {
    /// Whether the client is meant to run: an enabled client starts with the
    /// app, and once it becomes startable (its first destination added); a
    /// disabled one stays stopped, at every launch, until enabled again.
    pub enabled: bool,
    /// Local SOCKS5 proxy port; `None` leaves that front-end disabled.
    pub socks_port: Option<u16>,
    /// Local HTTP proxy port; `None` leaves the HTTP front-end disabled.
    pub http_port: Option<u16>,
    pub destinations: Vec<Destination>,
    pub forwards: Vec<PortForward>,
}

impl Default for ClientSettings {
    /// A fresh install's client: enabled, so it starts with its first
    /// destination, with the SOCKS5 proxy on its usual port.
    fn default() -> Self {
        Self {
            enabled: true,
            socks_port: Some(DEFAULT_SOCKS_PORT),
            http_port: None,
            destinations: Vec::new(),
            forwards: Vec::new(),
        }
    }
}

impl ClientSettings {
    pub fn destination(&self, id: &str) -> Option<&Destination> {
        self.destinations.iter().find(|d| d.id == id)
    }

    /// The client's routing as the core will see it: every destination's name
    /// and routes, validated together. The error names what to fix.
    pub fn route_table(&self) -> Result<RouteTable, String> {
        route_table_of(&self.destinations)
    }

    /// Why the client cannot start, if it can't: it has no destination, one of
    /// them lacks its server or a usable key (the secret goes missing when the
    /// key's keychain entry was lost — re-entered in the Keys pane), or the
    /// destinations' routes do not fit together. A destination that cannot be
    /// used blocks the whole client rather than being left out: its routes
    /// would otherwise quietly connect directly.
    pub fn start_blocker(&self, keys: &[AuthKey]) -> Option<String> {
        self.start_blocker_with(keys, || self.route_table().err())
    }

    /// [`Self::start_blocker`], with why the destinations' names and routes do
    /// not make a routing table (if they don't) from `routes_error`, asked
    /// only when nothing else blocks — the view takes it from its cached
    /// table instead of building one on every redraw.
    pub fn start_blocker_with(
        &self,
        keys: &[AuthKey],
        routes_error: impl FnOnce() -> Option<String>,
    ) -> Option<String> {
        if self.destinations.is_empty() {
            return Some("Add a destination to start the client.".into());
        }
        if let Some(blocker) = self
            .destinations
            .iter()
            .find_map(|destination| destination_blocker(destination, keys))
        {
            return Some(blocker);
        }
        routes_error().map(|e| format!("Fix the destinations' names and routes: {e}"))
    }

    pub fn is_ready(&self, keys: &[AuthKey]) -> bool {
        self.start_blocker(keys).is_none()
    }
}

/// Why `destination` cannot be used, if it can't: it lacks its server or a
/// usable key (the secret goes missing when the key's keychain entry was lost
/// — re-entered in the Keys pane).
pub fn destination_blocker(destination: &Destination, keys: &[AuthKey]) -> Option<String> {
    let name = &destination.name;
    if destination.server_node_id.is_empty() {
        return Some(format!(
            "Destination \"{name}\" has no server node id — edit it."
        ));
    }
    match find_key(keys, &destination.auth_key_id) {
        None => Some(format!(
            "Destination \"{name}\" has no auth key — edit it to pick one."
        )),
        Some(key) if key.secret.is_empty() => Some(format!(
            "The secret of key \"{}\" (used by \"{name}\") is missing — re-enter it in the \
             Keys pane.",
            key.name
        )),
        Some(_) => None,
    }
}

/// The core's routing table over `destinations`, in their order.
pub fn route_table_of<'a>(
    destinations: impl IntoIterator<Item = &'a Destination>,
) -> Result<RouteTable, String> {
    let specs: Vec<RouteSpec<'_>> = destinations
        .into_iter()
        .map(|d| RouteSpec {
            name: &d.name,
            routed_domains: &d.routed_domains,
            routed_cidrs: &d.routed_cidrs,
        })
        .collect();
    RouteTable::new(&specs).map_err(|e| format!("{e:#}"))
}

/// Where the destination at `dest` of `table` overlaps the others, one line
/// each: a rule of another destination's that takes part of one of its own,
/// or one of its own that takes part of another's. The narrower rule wins.
pub fn overlap_lines(table: &RouteTable, dest: usize) -> Vec<String> {
    let name = |i: usize| table.names().nth(i).unwrap_or_default().to_string();
    table
        .overlaps()
        .iter()
        .filter_map(|o| {
            if o.outer.dest == dest {
                Some(format!(
                    "{} contains {}'s narrower {}",
                    o.outer.rule,
                    name(o.inner.dest),
                    o.inner.rule
                ))
            } else if o.inner.dest == dest {
                Some(format!(
                    "{} is inside {}'s broader {}",
                    o.inner.rule,
                    name(o.outer.dest),
                    o.outer.rule
                ))
            } else {
                None
            }
        })
        .collect()
}

/// How much of one configured rule — a `routed_domains` entry, or a
/// `routed_cidrs` one when `cidr` — its server routes, as the running
/// destination (`status`) graded it when its latest connection read the
/// server's lists. `None` while that is not known: never connected, the
/// server's lists could not be read, or the rule is not the running one's.
pub fn server_coverage(
    status: Option<&DestinationStatus>,
    raw: &str,
    cidr: bool,
) -> Option<Coverage> {
    let one = vec![raw.to_string()];
    let own = if cidr {
        RoutedSet::new(&[], &one)
    } else {
        RoutedSet::new(&one, &[])
    }
    .ok()?;
    let rule = own.rules().into_iter().next()?;
    status?.server_coverage.get(&rule).copied()
}

/// The server's entry in the sealed id → secret map. Key ids are 16 hex
/// digits (see `random_id`), so this and the other reserved ids below can only
/// clash with a hand-edited key id, which `drop_invalid_keys` rejects.
const SERVER_SECRET_ID: &str = "server";
/// The server's custom relay auth token in the sealed map.
const SERVER_RELAY_SECRET_ID: &str = "server-relay";
/// A destination's custom relay auth token is sealed under this prefix plus
/// the destination id.
const DESTINATION_RELAY_PREFIX: &str = "relay:";

fn destination_relay_secret_id(destination_id: &str) -> String {
    format!("{DESTINATION_RELAY_PREFIX}{destination_id}")
}

/// Whether a key id would collide with a non-key entry of the sealed map.
fn is_reserved_secret_id(id: &str) -> bool {
    id == SERVER_SECRET_ID
        || id == SERVER_RELAY_SECRET_ID
        || id.starts_with(DESTINATION_RELAY_PREFIX)
}

/// One client the server lets in: the public half of the client's auth key,
/// under a name for it (the authorized-keys comment).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedClient {
    pub name: String,
    /// `ed25519-pub:...`, in its canonical token form.
    pub public_key: String,
}

/// The app's one server — the desktop equivalent of a `server.toml`, core
/// settings only: an iroh identity, the authorized clients, the tunnel set
/// and relays (no host aliases). Runs in-process.
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
    /// The clients allowed to connect. May be empty: the server is then set up
    /// but cannot start until one is added.
    #[serde(default)]
    pub authorized_clients: Vec<AuthorizedClient>,
    /// The tunnel set; may be empty (clients reach this machine's own
    /// loopback and the server's status page regardless).
    #[serde(default)]
    pub routed_domains: Vec<String>,
    #[serde(default)]
    pub routed_cidrs: Vec<String>,
    #[serde(default)]
    pub relay_urls: Vec<String>,
    /// Shared bearer token sent to every custom relay (custom relays only).
    /// Sealed like [`Destination::relay_auth_token`]; the dev file re-adds it via
    /// [`StoredServer`].
    #[serde(skip)]
    pub relay_auth_token: Option<String>,
    /// Whether the custom relays serve QUIC address discovery, as
    /// [`Destination::relay_quic_addr_discovery`].
    #[serde(default = "on")]
    pub relay_quic_addr_discovery: bool,
    /// Whether the server is meant to run: an enabled server starts with the
    /// app, and once it becomes startable; a disabled one stays stopped, at
    /// every launch, until enabled again.
    #[serde(default)]
    pub enabled: bool,
}

impl ServerConfig {
    /// Why the server cannot start, if it can't: its identity secret is
    /// missing (the keychain entry was lost — import it again), or no client
    /// is authorized yet (the core refuses a server nobody may use).
    pub fn start_blocker(&self) -> Option<&'static str> {
        if self.secret.is_empty() {
            Some(
                "The identity key is missing from the keychain — import it, or generate a new \
                 identity, under Endpoint ID.",
            )
        } else if self.authorized_clients.is_empty() {
            Some("Authorize at least one client to start the server.")
        } else {
            None
        }
    }

    pub fn is_ready(&self) -> bool {
        self.start_blocker().is_none()
    }
}

/// The canonical `ed25519-pub:...` token of a client public key, or why it
/// isn't one.
pub fn parse_client_public_key(value: &str) -> Result<String, String> {
    value
        .trim()
        .parse::<flextunnel_core::flexaccess_keys::PublicKey>()
        .map(|key| key.to_token())
        .map_err(|e| format!("Invalid public key: {e}"))
}

/// Drop structurally invalid authorized clients from a (possibly hand-edited)
/// store, keeping the first occurrence of duplicates: a malformed name or key
/// can't be loaded into the server, a duplicate name makes the list ambiguous,
/// and a duplicate key is the same client added twice. The form rejects all
/// of these; this is the backstop.
fn drop_invalid_clients(clients: Vec<AuthorizedClient>) -> Vec<AuthorizedClient> {
    let mut names = std::collections::HashSet::new();
    let mut publics = std::collections::HashSet::new();
    clients
        .into_iter()
        .filter(|c| {
            if !is_valid_name(&c.name) {
                log::error!("Ignoring an authorized client: invalid name {:?}", c.name);
                return false;
            }
            if parse_client_public_key(&c.public_key).as_deref() != Ok(c.public_key.as_str()) {
                log::error!(
                    "Ignoring authorized client \"{}\": not a canonical public key",
                    c.name
                );
                return false;
            }
            // Both checked before either is reserved: a dropped entry must
            // not shadow a later valid one sharing its name or key.
            if names.contains(&c.name) {
                log::error!(
                    "Ignoring an authorized client: duplicate name \"{}\"",
                    c.name
                );
                return false;
            }
            if publics.contains(&c.public_key) {
                log::error!(
                    "Ignoring authorized client \"{}\": another client already holds its key",
                    c.name
                );
                return false;
            }
            names.insert(c.name.clone());
            publics.insert(c.public_key.clone());
            true
        })
        .collect()
}

/// Everything the app persists: the shared key list plus the client whose
/// destinations reference into it, and the server. Saved as one JSON document
/// so a destination can never be written without the key list it points into.
#[derive(Default, Serialize, Deserialize)]
pub struct Store {
    #[serde(default)]
    pub keys: Vec<AuthKey>,
    #[serde(default)]
    pub client: ClientSettings,
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
    client: &'a ClientSettings,
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
    client: ClientSettings,
    /// Destination id → relay auth token, inline like the other secrets.
    #[serde(default)]
    destination_relay_tokens: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    server: Option<StoredServer>,
    #[serde(default)]
    login_item_set_up: bool,
}

/// Path to the plaintext dev settings file when `FLEXTUNNEL_DEV_CONFIG` is
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
    let name = if mock {
        "mock-profiles.json"
    } else {
        "profiles.json"
    };
    dirs::data_local_dir()
        .map(|d| d.join("flextunnel").join(name))
        .ok_or_else(|| anyhow::anyhow!("no local data directory to store settings in"))
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
        anyhow::ensure!(
            !mock,
            "{DEV_CONFIG_ENV} and {KEYCHAIN_ENV}=mock are both set; pick one"
        );
        log::warn!(
            "{DEV_CONFIG_ENV} set: storing settings (secret keys included) UNENCRYPTED at {} \
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
/// destination's relay auth token, plus the server identity under
/// [`SERVER_SECRET_ID`] and its relay auth token under
/// [`SERVER_RELAY_SECRET_ID`].
fn secret_entries<'a>(
    keys: &'a [AuthKey],
    destinations: &'a [Destination],
    server: Option<&'a ServerConfig>,
) -> impl Iterator<Item = (String, &'a str)> {
    let relay = |token: &'a Option<String>| token.as_deref().unwrap_or_default();
    keys.iter()
        .map(|k| (k.id.clone(), k.secret.as_str()))
        .chain(destinations.iter().map(move |d| {
            (
                destination_relay_secret_id(&d.id),
                relay(&d.relay_auth_token),
            )
        }))
        .chain(server.into_iter().flat_map(move |s| {
            [
                (SERVER_SECRET_ID.to_owned(), s.secret.as_str()),
                (
                    SERVER_RELAY_SECRET_ID.to_owned(),
                    relay(&s.relay_auth_token),
                ),
            ]
        }))
}

/// Seal the id → secret map of `entries` into the `sealed_keys` blob.
/// Secretless entries (lost secrets, destinations without a relay token) are left
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
/// destinations with no key picked, duplicate ids break the destinations' references
/// and the keychain keying, malformed or duplicate names break the picker,
/// and a duplicate public key means the same keypair was accidentally added
/// twice. The form rejects all of these; this is the backstop.
fn drop_invalid_keys(keys: Vec<AuthKey>) -> Vec<AuthKey> {
    let mut ids = std::collections::HashSet::new();
    let mut names = std::collections::HashSet::new();
    let mut publics = std::collections::HashSet::new();
    keys.into_iter()
        .filter(|k| {
            // An empty id would match every destination that has no key picked
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

/// Drop structurally invalid destinations from a (possibly hand-edited)
/// store, keeping the first occurrence of duplicates: duplicate ids break the
/// selection and the relay-token keying, a name the core would not store as
/// written (or a duplicate one) breaks everything keyed by name, and a
/// duplicate server node id means two destinations for one server, which the
/// core refuses. The form rejects all of these; this is the backstop.
fn drop_invalid(destinations: Vec<Destination>) -> Vec<Destination> {
    let mut ids = std::collections::HashSet::new();
    let mut names = std::collections::HashSet::new();
    let mut servers = std::collections::HashSet::new();
    destinations
        .into_iter()
        .filter(|d| {
            // Every check before anything is reserved: a dropped entry must
            // not shadow a later valid one sharing its id, name or server.
            if ids.contains(&d.id) {
                log::error!("Ignoring destination \"{}\": duplicate id {}", d.name, d.id);
                return false;
            }
            if validate_destination_name(&d.name).as_deref() != Ok(d.name.as_str()) {
                log::error!("Ignoring destination {}: invalid name {:?}", d.id, d.name);
                return false;
            }
            if names.contains(&d.name) {
                log::error!("Ignoring a destination: duplicate name \"{}\"", d.name);
                return false;
            }
            if servers.contains(&d.server_node_id) {
                log::error!(
                    "Ignoring destination \"{}\": another destination already uses its server \
                     node id",
                    d.name
                );
                return false;
            }
            ids.insert(d.id.clone());
            names.insert(d.name.clone());
            servers.insert(d.server_node_id.clone());
            true
        })
        .collect()
}

/// Drop forwards a (possibly hand-edited) store or import file gets wrong —
/// a field the form would reject, or a second forward on one local port —
/// keeping the first occurrence.
fn drop_invalid_forwards(forwards: Vec<PortForward>) -> Vec<PortForward> {
    let mut ids = std::collections::HashSet::new();
    let mut ports = std::collections::HashSet::new();
    forwards
        .into_iter()
        .filter(|f| {
            let well_formed = f.local_port != 0
                && f.remote_port != 0
                && validate_label(&f.label).as_deref() == Ok(f.label.as_str())
                && validate_remote_host(&f.remote_host).as_deref() == Ok(f.remote_host.as_str());
            if !well_formed {
                log::error!("Ignoring forward \"{}\": invalid entry", f.display_name());
                return false;
            }
            // Both checked before either is reserved: a forward dropped for
            // its port must not take its id from a later valid one.
            if ids.contains(&f.id) || ports.contains(&f.local_port) {
                log::error!(
                    "Ignoring forward \"{}\": duplicate id or local port {}",
                    f.display_name(),
                    f.local_port
                );
                return false;
            }
            ids.insert(f.id.clone());
            ports.insert(f.local_port);
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
/// failing. Structurally invalid keys, destinations and forwards are ignored (see the
/// `drop_invalid*` backstops); a destination referencing an unknown key is
/// kept, and the client can't start until a key is picked for it.
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
            for destination in &mut store.client.destinations {
                destination.relay_auth_token = secrets
                    .get(&destination_relay_secret_id(&destination.id))
                    .cloned();
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
    store.client.destinations = drop_invalid(std::mem::take(&mut store.client.destinations));
    store.client.forwards = drop_invalid_forwards(std::mem::take(&mut store.client.forwards));
    if let Some(server) = &mut store.server {
        let clients = std::mem::take(&mut server.authorized_clients);
        server.authorized_clients = drop_invalid_clients(clients);
    }
    for destination in &store.client.destinations {
        if !destination.auth_key_id.is_empty()
            && find_key(&store.keys, &destination.auth_key_id).is_none()
        {
            log::warn!(
                "Destination \"{}\" references an unknown auth key; pick one to use it",
                destination.name
            );
        }
    }
    Ok(store)
}

/// Persist the key list, client and server, secrets sealed. This is the
/// whole save: one atomic file write covers adds, edits, and deletions alike.
/// The Safe Storage key is cached after its first use, so routine saves after
/// a forward toggle never touch the keychain (and a store holding no secrets
/// skips it entirely).
pub fn save_store(
    keys: &[AuthKey],
    client: &ClientSettings,
    server: Option<&ServerConfig>,
    login_item_set_up: bool,
) -> Result<()> {
    match backend()? {
        Backend::DevFile(path) => save_dev_file(path, keys, client, server, login_item_set_up),
        backend => {
            let entries = || secret_entries(keys, &client.destinations, server);
            let sealed_keys = if entries().all(|(_, s)| s.is_empty()) {
                String::new()
            } else {
                seal_secrets(&safe_storage_key()?, entries())?
            };
            write_json(
                &sealed_path(matches!(backend, Backend::MockKeychain))?,
                &StoreRef {
                    keys,
                    client,
                    server,
                    login_item_set_up,
                    sealed_keys,
                    sealed_version: SEALED_VERSION,
                },
            )
        }
    }
}

/// What an export file carries and an import reads back: the client's
/// destinations and forwards. The proxy ports stay behind — which local ports
/// are free is this computer's business.
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Portable {
    #[serde(default)]
    pub destinations: Vec<Destination>,
    #[serde(default)]
    pub forwards: Vec<PortForward>,
}

/// Export the client's destinations and forwards to a user-chosen file.
/// Non-secrets only, whatever the backend: a destination's one secret, its
/// relay auth token, never serializes. Destination ids, forward ids, and the
/// auth-key reference are stripped too — they are app-local keys that mean
/// nothing in another install, not part of the portable data.
pub fn export_client(path: &Path, client: &ClientSettings) -> Result<()> {
    let mut doc = serde_json::json!({
        "destinations": client.destinations,
        "forwards": client.forwards,
    });
    for destination in objects_of(&mut doc, "destinations") {
        destination.remove("id");
        destination.remove("auth_key_id");
    }
    for forward in objects_of(&mut doc, "forwards") {
        forward.remove("id");
    }
    write_json(path, &doc)
}

/// Read an export file back. The destinations come back exactly as the file
/// has them — the caller's merge checks them strictly and refuses the import
/// over any that do not fit, rather than importing a file in part — while
/// forwards a load would drop (a bad field, a second one on a local port) are
/// dropped here too, with logs. The caller merges the result into the current
/// client and assigns final ids; missing ids (the normal export shape) get
/// placeholders here so the entries deserialize. No secret or key reference is
/// imported: neither is ever in an
/// export, and a hand-written auth-key reference is dropped rather than
/// trusted (a hand-written relay auth token never deserializes), so imported
/// destinations come back with both empty.
pub fn import_client(path: &Path) -> Result<Portable> {
    let mut doc: serde_json::Value =
        read_json(path)?.ok_or_else(|| anyhow::anyhow!("{} does not exist", path.display()))?;
    anyhow::ensure!(
        doc.is_object(),
        "{} is not a flextunnel export (destinations and forwards)",
        path.display()
    );
    for destination in objects_of(&mut doc, "destinations") {
        destination
            .entry("id")
            .or_insert_with(|| Destination::new_id().into());
        destination.remove("auth_key_id");
    }
    for forward in objects_of(&mut doc, "forwards") {
        forward
            .entry("id")
            .or_insert_with(|| PortForward::new_id().into());
    }
    let portable: Portable = serde_json::from_value(doc)
        .with_context(|| format!("Failed to parse {}", path.display()))?;
    Ok(Portable {
        destinations: portable.destinations,
        forwards: drop_invalid_forwards(portable.forwards),
    })
}

/// The mutable objects of the array at `key` of a JSON document (empty when
/// absent or not an array).
fn objects_of<'a>(
    doc: &'a mut serde_json::Value,
    key: &str,
) -> impl Iterator<Item = &'a mut serde_json::Map<String, serde_json::Value>> {
    doc.get_mut(key)
        .and_then(|v| v.as_array_mut())
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_object_mut())
}

fn load_dev_file(path: &Path) -> Result<Store> {
    let mut stored: DevFile = read_json(path)?.unwrap_or_default();
    let mut client = std::mem::take(&mut stored.client);
    for destination in &mut client.destinations {
        destination.relay_auth_token = stored.destination_relay_tokens.remove(&destination.id);
    }
    Ok(Store {
        keys: stored
            .keys
            .into_iter()
            .map(|s| AuthKey {
                secret: s.secret,
                ..s.key
            })
            .collect(),
        client,
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
    client: &ClientSettings,
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
        client: client.clone(),
        destination_relay_tokens: client
            .destinations
            .iter()
            .filter_map(|d| Some((d.id.clone(), d.relay_auth_token.clone()?)))
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
        Ok(raw) => {
            Ok(Some(serde_json::from_slice(&raw).with_context(|| {
                format!("Failed to parse {}", path.display())
            })?))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("Failed to read {}", path.display())),
    }
}

/// Write via a temp file + rename so a crash mid-write can't truncate the file.
fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("settings path has no parent directory"))?;
    std::fs::create_dir_all(dir).with_context(|| format!("Failed to create {}", dir.display()))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(value)?)
        .with_context(|| format!("Failed to write {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("Failed to persist {}", path.display()))?;
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

    fn client_public_key() -> String {
        flextunnel_core::auth::ClientKey::generate()
            .unwrap()
            .public_str()
    }

    fn server() -> ServerConfig {
        ServerConfig {
            endpoint_id: "endpoint".into(),
            secret: "ftc-secret-identity".into(),
            authorized_clients: vec![AuthorizedClient {
                name: "work laptop".into(),
                public_key: "ed25519-pub:abc".into(),
            }],
            routed_domains: vec!["*.internal".into()],
            routed_cidrs: vec!["10.0.0.0/8".into()],
            relay_urls: vec!["https://relay.example".into()],
            relay_auth_token: Some("ftc-secret-serverpsk".into()),
            relay_quic_addr_discovery: false,
            enabled: true,
        }
    }

    fn seal(master: &[u8; 32], keys: &[AuthKey]) -> String {
        seal_secrets(master, secret_entries(keys, &[], None)).unwrap()
    }

    fn destination() -> Destination {
        Destination {
            id: "00000000deadbeef".into(),
            name: "prod".into(),
            server_node_id: "node".into(),
            routed_domains: vec!["*.corp.example".into()],
            routed_cidrs: vec!["10.0.0.0/8".into()],
            auth_key_id: "key1".into(),
            relay_urls: vec!["https://relay.example".into()],
            relay_auth_token: Some("ftc-secret-relaypsk".into()),
            relay_quic_addr_discovery: false,
        }
    }

    fn forward() -> PortForward {
        PortForward {
            id: "aaaa".into(),
            label: "db".into(),
            local_port: 5432,
            remote_host: "db.internal".into(),
            remote_port: 5432,
            enabled: true,
        }
    }

    fn client() -> ClientSettings {
        ClientSettings {
            enabled: true,
            socks_port: Some(1085),
            http_port: Some(8081),
            destinations: vec![destination()],
            forwards: vec![forward()],
        }
    }

    #[test]
    fn optional_fields_default_when_absent() {
        let d: Destination =
            serde_json::from_str(r#"{"id":"1","name":"n","server_node_id":"abc"}"#).unwrap();
        assert!(d.routed_domains.is_empty() && d.routed_cidrs.is_empty());
        assert!(d.relay_urls.is_empty());
        assert!(d.auth_key_id.is_empty());
    }

    /// A store written before there was a client loads with a fresh one:
    /// enabled, SOCKS5 on its usual port, nothing to reach yet. A saved client
    /// keeps what it says, a switched-off proxy included.
    #[test]
    fn a_missing_client_is_a_fresh_one() {
        let store: Store = serde_json::from_str("{}").unwrap();
        assert_eq!(store.client, ClientSettings::default());
        assert!(store.client.enabled);
        assert_eq!(store.client.socks_port, Some(DEFAULT_SOCKS_PORT));
        assert_eq!(store.client.http_port, None);

        let store: Store =
            serde_json::from_str(r#"{"client":{"enabled":false,"socks_port":null}}"#).unwrap();
        assert!(!store.client.enabled);
        assert_eq!(store.client.socks_port, None);
    }

    #[test]
    fn secret_never_serializes_in_store() {
        let json = serde_json::to_string(&StoreRef {
            keys: &[key()],
            client: &client(),
            server: Some(&server()),
            login_item_set_up: false,
            sealed_keys: String::new(),
            sealed_version: SEALED_VERSION,
        })
        .unwrap();
        assert!(
            !json.contains("ftc-secret-authtok"),
            "secret leaked: {json}"
        );
        assert!(
            !json.contains("ftc-secret-identity"),
            "server secret leaked: {json}"
        );
        // The server's public identity and settings persist.
        assert!(
            json.contains("\"endpoint_id\":\"endpoint\""),
            "endpoint id dropped: {json}"
        );
        assert!(json.contains("*.internal"), "tunnel set dropped: {json}");
        // The non-secret halves of the key persist, as does the destination's
        // reference to it.
        assert!(
            json.contains("ed25519-pub:abc"),
            "public key dropped: {json}"
        );
        assert!(
            json.contains("\"auth_key_id\":\"key1\""),
            "reference dropped: {json}"
        );
        // `enabled` is runtime-only on forwards and must not leak either; the
        // server's is its persisted intent.
        let doc: serde_json::Value = serde_json::from_str(&json).unwrap();
        let forward = &doc["client"]["forwards"][0];
        assert_eq!(forward["local_port"], 5432);
        assert!(
            forward.get("enabled").is_none(),
            "forward enabled leaked: {json}"
        );
        assert_eq!(
            doc["server"]["enabled"], true,
            "server enabled dropped: {json}"
        );
        assert_eq!(
            doc["client"]["enabled"], true,
            "client enabled dropped: {json}"
        );
        assert_eq!(doc["client"]["destinations"][0]["name"], "prod");
        // The relay tokens are secrets: sealed, never plaintext.
        assert!(
            !json.contains("relay_auth_token"),
            "relay token field leaked: {json}"
        );
        assert!(
            !json.contains("ftc-secret-relaypsk"),
            "destination relay token leaked: {json}"
        );
        assert!(
            !json.contains("ftc-secret-serverpsk"),
            "server relay token leaked: {json}"
        );
    }

    #[test]
    fn sealed_secrets_roundtrip_without_leaking_plaintext() {
        let master = [7u8; 32];
        let mut no_relay = destination();
        no_relay.id = "00000000feedface".into();
        no_relay.relay_auth_token = None;
        let (keys, destinations, server) = ([key()], [destination(), no_relay], server());
        let sealed =
            seal_secrets(&master, secret_entries(&keys, &destinations, Some(&server))).unwrap();
        assert!(
            !sealed.contains("ftc-secret-authtok"),
            "secret leaked: {sealed}"
        );
        assert!(
            !sealed.contains("ftc-secret-identity"),
            "server secret leaked: {sealed}"
        );
        assert!(
            !sealed.contains("ftc-secret-relaypsk"),
            "relay token leaked: {sealed}"
        );
        let map = open_secrets(&master, &sealed).unwrap();
        // The destination without a relay token seals nothing.
        assert_eq!(map.len(), 4);
        assert_eq!(
            map.get("key1").map(String::as_str),
            Some("ftc-secret-authtok")
        );
        assert_eq!(
            map.get(SERVER_SECRET_ID).map(String::as_str),
            Some("ftc-secret-identity")
        );
        assert_eq!(
            map.get(SERVER_RELAY_SECRET_ID).map(String::as_str),
            Some("ftc-secret-serverpsk")
        );
        assert_eq!(
            map.get(&destination_relay_secret_id(&destination().id))
                .map(String::as_str),
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
        assert!(
            open_secrets(&[8u8; 32], &sealed).is_err(),
            "wrong master key"
        );
        assert!(open_secrets(&[7u8; 32], "not base64!").is_err());
        assert!(
            open_secrets(&[7u8; 32], "AAAA").is_err(),
            "shorter than a nonce"
        );
    }

    #[test]
    fn client_start_blockers() {
        let keys = [key()];
        assert_eq!(client().start_blocker(&keys), None);
        assert!(client().is_ready(&keys));

        let empty = ClientSettings::default();
        assert!(
            empty
                .start_blocker(&keys)
                .unwrap()
                .contains("Add a destination")
        );

        let mut lost = key();
        lost.secret = String::new();
        let blocker = client().start_blocker(&[lost]).unwrap();
        assert!(
            blocker.contains("work laptop") && blocker.contains("Keys pane"),
            "{blocker}"
        );

        assert!(
            client().start_blocker(&[]).unwrap().contains("no auth key"),
            "dangling key reference"
        );
        let mut unpicked = client();
        unpicked.destinations[0].auth_key_id = String::new();
        assert!(
            unpicked
                .start_blocker(&keys)
                .unwrap()
                .contains("no auth key")
        );

        let mut serverless = client();
        serverless.destinations[0].server_node_id = String::new();
        assert!(
            serverless
                .start_blocker(&keys)
                .unwrap()
                .contains("server node id")
        );

        // The destinations' routes are checked together, by the core's table.
        let mut bad_route = client();
        bad_route.destinations[0].routed_cidrs = vec!["not-a-cidr".into()];
        assert!(bad_route.start_blocker(&keys).unwrap().contains("routes"));
        let mut overlap = client();
        let mut second = destination();
        second.id = "second".into();
        second.name = "staging".into();
        second.server_node_id = "node-2".into();
        overlap.destinations.push(second);
        let blocker = overlap.start_blocker(&keys).unwrap();
        assert!(blocker.contains("both route"), "{blocker}");
        overlap.destinations[1].routed_domains.clear();
        overlap.destinations[1].routed_cidrs.clear();
        assert_eq!(overlap.start_blocker(&keys), None, "a host alone is enough");
        assert_eq!(overlap.route_table().unwrap().names().count(), 2);
    }

    /// Each destination sees the overlaps it takes part in, from its own
    /// side: what another destination takes from it, or what it takes.
    #[test]
    fn overlaps_are_told_from_each_side() {
        let dest = |host: &str, domains: &[&str], cidrs: &[&str]| Destination {
            id: host.into(),
            name: host.into(),
            server_node_id: format!("node-{host}"),
            routed_domains: domains.iter().map(|d| d.to_string()).collect(),
            routed_cidrs: cidrs.iter().map(|c| c.to_string()).collect(),
            auth_key_id: String::new(),
            relay_urls: Vec::new(),
            relay_auth_token: None,
            relay_quic_addr_discovery: true,
        };
        let destinations = [
            dest("nas", &["*.corp.example"], &["10.0.0.0/8"]),
            dest("lab", &["*.dev.corp.example"], &["10.1.0.0/16"]),
            dest("wiki", &["wiki.example"], &[]),
        ];
        let table = route_table_of(&destinations).unwrap();
        assert_eq!(
            overlap_lines(&table, 0),
            [
                "*.corp.example contains lab's narrower *.dev.corp.example",
                "10.0.0.0/8 contains lab's narrower 10.1.0.0/16",
            ]
        );
        assert_eq!(
            overlap_lines(&table, 1),
            [
                "*.dev.corp.example is inside nas's broader *.corp.example",
                "10.1.0.0/16 is inside nas's broader 10.0.0.0/8",
            ]
        );
        assert!(overlap_lines(&table, 2).is_empty());
    }

    /// A rule's server check is the running destination's grade of it from
    /// what the server said on its latest connection, and is unknown until
    /// one has, or for a rule the running destination does not have.
    #[test]
    fn a_rule_is_checked_against_the_servers_routes() {
        let mut status = DestinationStatus {
            name: "nas".into(),
            server_node_id: String::new(),
            state: flextunnel_core::proxy::DestinationState::Connected,
            connected_since: None,
            open_streams: 0,
            waiting: 0,
            client_node_id: None,
            failed_attempts: 0,
            next_attempt_at: None,
            last_error: None,
            routed_domains: Vec::new(),
            routed_cidrs: Vec::new(),
            relay_urls: Vec::new(),
            server_routes: None,
            server_routes_error: None,
            server_coverage: Default::default(),
            server_routes_pending: false,
        };
        assert_eq!(
            server_coverage(Some(&status), "*.corp.example", false),
            None
        );
        assert_eq!(server_coverage(None, "*.corp.example", false), None);
        let routes = flextunnel_core::proxy::ServerRoutes {
            routed_domains: vec!["*.corp.example".into()],
            routed_cidrs: vec!["10.0.0.0/16".into()],
        };
        let own = RoutedSet::new(
            &[
                "*.corp.example".into(),
                "api.corp.example".into(),
                "*".into(),
                "wiki.example".into(),
            ],
            &[
                "10.0.0.0/8".into(),
                "10.0.1.0/24".into(),
                "192.168.0.0/16".into(),
            ],
        )
        .unwrap();
        status.server_coverage = std::sync::Arc::new(routes.coverage_of(&own).unwrap());
        status.server_routes = Some(routes);
        assert_eq!(
            server_coverage(Some(&status), "*.other.example", false),
            None,
            "not a running rule"
        );
        for (rule, cidr, coverage) in [
            ("*.corp.example", false, Coverage::Full),
            ("api.corp.example", false, Coverage::Full),
            ("*", false, Coverage::Partial),
            ("wiki.example", false, Coverage::None),
            ("10.0.0.0/8", true, Coverage::Partial),
            ("10.0.1.0/24", true, Coverage::Full),
            ("192.168.0.0/16", true, Coverage::None),
        ] {
            assert_eq!(
                server_coverage(Some(&status), rule, cidr),
                Some(coverage),
                "{rule}"
            );
        }
    }

    #[test]
    fn server_start_blockers() {
        let mut ready = server();
        assert_eq!(ready.start_blocker(), None);
        ready.authorized_clients.clear();
        assert!(
            ready.start_blocker().unwrap().contains("Authorize"),
            "no client"
        );
        let mut lost = server();
        lost.secret = String::new();
        assert!(
            lost.start_blocker().unwrap().contains("identity"),
            "lost identity"
        );
    }

    #[test]
    fn invalid_and_duplicate_clients_are_dropped() {
        let (a_key, b_key) = (client_public_key(), client_public_key());
        let client = |name: &str, public_key: &str| AuthorizedClient {
            name: name.into(),
            public_key: public_key.into(),
        };
        let kept = drop_invalid_clients(vec![
            client("laptop", &a_key),
            client("laptop", &b_key),
            // Dropped for its key, so it doesn't reserve "phone".
            client("phone", &a_key),
            client(" padded", &b_key),
            client("garbage", "ed25519-pub:nope"),
            client("spaced", &format!(" {b_key}")),
            client("phone", &b_key),
        ]);
        assert_eq!(
            kept,
            vec![client("laptop", &a_key), client("phone", &b_key)]
        );
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
        // The relay tokens' slots: the server's and a destination's.
        let mut server_relay_id = key();
        server_relay_id.id = SERVER_RELAY_SECRET_ID.into();
        server_relay_id.name = "server relay".into();
        server_relay_id.public_key = "ed25519-pub:stu".into();
        let mut destination_relay_id = key();
        destination_relay_id.id = destination_relay_secret_id("00000000deadbeef");
        destination_relay_id.name = "destination relay".into();
        destination_relay_id.public_key = "ed25519-pub:vwx".into();
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
            destination_relay_id,
            unique.clone(),
        ]);
        assert_eq!(kept, vec![a, unique]);
    }

    #[test]
    fn invalid_and_duplicate_destinations_are_dropped() {
        let a = destination();
        let variant = |id: &str, host: &str, server: &str| Destination {
            id: id.into(),
            name: host.into(),
            server_node_id: server.into(),
            ..destination()
        };
        let unique = variant("d", "staging", "unique");
        // Dropped for its server, "late"; so neither its id nor its
        // host is taken from the entry after it.
        let late = variant("late", "late", "late-server");
        let kept = drop_invalid(vec![
            a.clone(),
            variant("b", "b", "node"),
            variant("00000000deadbeef", "c", "other"),
            variant("n", "prod", "elsewhere"),
            variant("late", "late", "node"),
            late.clone(),
            // Not the form the core stores: uppercase, an address, reserved.
            variant("u", "Upper", "upper"),
            variant("i", "10.0.0.1", "address"),
            variant("r", "flextunnel.internal", "reserved"),
            variant("e", "", "hostless"),
            unique.clone(),
        ]);
        assert_eq!(kept, vec![a, late, unique]);
    }

    #[test]
    fn invalid_and_duplicate_forwards_are_dropped() {
        let a = forward();
        let variant = |id: &str, local_port: u16, remote_host: &str| PortForward {
            id: id.into(),
            local_port,
            remote_host: remote_host.into(),
            ..forward()
        };
        let unique = variant("bbbb", 5433, "db.internal");
        // "cccc" is dropped for its port, which must not cost this one its id.
        let reused_id = variant("cccc", 5434, "db.internal");
        let kept = drop_invalid_forwards(vec![
            a.clone(),
            variant("cccc", 5432, "other.internal"),
            reused_id.clone(),
            variant("aaaa", 6000, "other.internal"),
            variant("dddd", 0, "db.internal"),
            variant("eeee", 7000, "bad..name"),
            variant("ffff", 7001, " padded "),
            unique.clone(),
        ]);
        assert_eq!(kept, vec![a, reused_id, unique]);
    }

    #[test]
    fn export_strips_ids_and_import_regenerates_them() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.json");

        export_client(&path, &client()).unwrap();
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
        // The proxy ports and the on/off switch are this computer's own.
        assert!(
            !raw.contains("socks_port") && !raw.contains("enabled"),
            "{raw}"
        );
        // The non-secret relay setting it pairs with still travels.
        assert!(
            raw.contains("https://relay.example"),
            "relay urls dropped: {raw}"
        );

        let imported = import_client(&path).unwrap();
        assert_eq!(imported.destinations.len(), 1);
        let d = &imported.destinations[0];
        assert!(!d.id.is_empty(), "placeholder destination id assigned");
        assert!(d.auth_key_id.is_empty());
        assert_eq!(d.relay_auth_token, None);
        assert_eq!(d.relay_urls, destination().relay_urls);
        // …and so does what it says of them.
        assert!(!destination().relay_quic_addr_discovery);
        assert!(!d.relay_quic_addr_discovery);
        assert_eq!(d.name, destination().name);
        assert_eq!(d.routed_domains, destination().routed_domains);
        assert_eq!(imported.forwards.len(), 1);
        assert!(
            !imported.forwards[0].id.is_empty(),
            "placeholder forward id assigned"
        );
        assert_eq!(imported.forwards[0].local_port, forward().local_port);
    }

    /// Hand-written files can carry the relay token or an auth-key reference;
    /// both are dropped rather than trusted, same as if never written.
    #[test]
    fn import_drops_untrusted_fields_present_in_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.json");
        std::fs::write(
            &path,
            r#"{"destinations":[{"name":"prod","server_node_id":"node",
                 "auth_key_id":"key1",
                 "relay_urls":["https://relay.example"],
                 "relay_auth_token":"ftc-secret-relaypsk"}]}"#,
        )
        .unwrap();

        let imported = import_client(&path).unwrap();
        assert_eq!(imported.destinations.len(), 1);
        assert!(imported.destinations[0].auth_key_id.is_empty());
        assert_eq!(imported.destinations[0].relay_auth_token, None);
        assert_eq!(
            imported.destinations[0].relay_urls,
            vec!["https://relay.example"]
        );
        // Left out of the file, QUIC address discovery is on.
        assert!(imported.destinations[0].relay_quic_addr_discovery);
        assert!(imported.forwards.is_empty());

        // A file of another shape — a bare list — is refused, not read as empty.
        std::fs::write(&path, r#"[{"name":"prod","server_node_id":"node"}]"#).unwrap();
        let e = import_client(&path).unwrap_err();
        assert!(
            format!("{e:#}").contains("not a flextunnel export"),
            "{e:#}"
        );
        assert!(import_client(&dir.path().join("missing.json")).is_err());
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
        assert!(empty.keys.is_empty() && empty.server.is_none());
        assert_eq!(empty.client, ClientSettings::default());

        let keys = vec![key()];
        let mut client = client();
        let server = server();
        save_dev_file(&path, &keys, &client, Some(&server), true).unwrap();
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
            raw.contains("\"00000000deadbeef\": \"ftc-secret-relaypsk\""),
            "destination relay token missing: {raw}"
        );
        assert!(
            raw.contains("\"relay_auth_token\": \"ftc-secret-serverpsk\""),
            "server relay token missing: {raw}"
        );

        // Forward `enabled` is runtime-only: comes back off.
        client.forwards[0].enabled = false;
        let loaded = load_dev_file(&path).unwrap();
        assert_eq!(loaded.keys, keys);
        assert_eq!(loaded.client, client);
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
            assert!(
                format!("{e:#}").contains("only value it takes"),
                "{wrong:?}: {e:#}"
            );
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
