//! The iced daemon state machine: a sidebar of the client, its destinations
//! and the app's server plus a detail pane, driven alongside the system tray.
//! The two roles weigh the same and either can go unused. The client is one
//! session over every destination — its optional proxy ports and its port
//! forwards — that connects to a destination when something is first sent to
//! it; the server is a flextunnel server run in-process (the app hosts one;
//! its lock, per identity, is shared with the CLI). Each is enabled or
//! disabled, started with the app while enabled, and restarted to apply
//! changed settings. The daemon owns all state, so closing the window (which
//! destroys it) loses nothing — the tray re-opens it on demand. Tray/menu
//! events are forwarded from tray-icon's handlers into a channel drained by a
//! [`Subscription`], so a tray click wakes the runtime even while no window
//! exists; a 500 ms tick keeps the snapshots and the tray state fresh the rest
//! of the time.

use crate::autostart;
use crate::config::{
    self, AuthKey, AuthorizedClient, ClientSettings, Destination, Portable, ServerConfig,
    DEFAULT_HTTP_PORT, DEFAULT_SOCKS_PORT,
};
use flextunnel_core::forwards::{
    PortForward, disable_failed_forwards, parse_port, validate_label, validate_remote_host,
};
use crate::icon;
use crate::logging;
use crate::server_session::{self, ServerPhase, ServerSnapshot};
use crate::tray::{self, Tray};
use crate::tunnel::{
    ClientPhase, ClientSnapshot, ClientSpec, Controller, DestinationId, CLIENT_THREAD_NAME,
};
use crate::view;
use flextunnel_core::proxy::{DestinationStatus, RouteSpec, RouteTable};
use flextunnel_core::transport::paths::ConnectionSnapshot;
use iced::futures::Stream;
use iced::{window, Element, Size, Subscription, Task};
use std::collections::HashMap;
use std::time::Duration;
use tray_icon::menu::MenuEvent;
use tray_icon::TrayIconEvent;

/// Why the saved store could not be used whole at launch (see
/// [`App::store_reset`]).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum StoreReset {
    /// Sealed under another sealed format version (see
    /// `config::Store::sealed_reset_from`), which this build discards.
    Version(u32),
    /// The blob does not open under the keychain's current master key (see
    /// `config::Store::unseal_failed`): the Safe Storage entry was deleted or
    /// replaced. Restoring it makes them readable again.
    Unsealable,
    /// The store did not load at all (the keychain could not be read, or
    /// `profiles.json` is unreadable): the app runs on an empty one, which a
    /// save would write over the whole file. The error, for the warning.
    Unreadable(String),
}

/// What the detail pane shows (the sidebar's selected row).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Selection {
    /// Nothing set up yet: the pane points at the sidebar, offering neither
    /// role as the one to pick.
    Empty,
    /// The client pane: its on/off switch, proxy ports and port forwards.
    Client,
    Destination(DestinationId),
    /// The server pane — or, with no server set up, its welcome, whose
    /// buttons open the setup form.
    Server,
    Keys,
    Logs,
}

/// How a destination stands in the client session right now.
pub enum DestinationLive<'a> {
    /// The client is not running: nothing reaches any destination.
    Stopped,
    /// The client runs, but not with this destination as saved — it was added
    /// or edited since the session started, and applies on a restart.
    Pending,
    /// The destination's state in the running session.
    Live(&'a DestinationStatus),
}

/// One entry of the destination form's auth-key picker. Keys are picked by name
/// (names are unique — see `drop_invalid_keys`); the id travels along so the
/// selection maps back to the key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyChoice {
    pub id: String,
    pub name: String,
}

impl std::fmt::Display for KeyChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name)
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    Tick,
    SetupTray,
    TrayMenu(String),
    TrayIcon(TrayIconEvent),
    WindowOpened,
    WindowClosed(window::Id),
    Select(Selection),
    CopyText(String),
    /// An edit attempt on a read-only field (shown in a text input only so
    /// its value can be selected and copied by hand): ignored.
    ReadOnlyEdited,
    /// Fetch the selected destination's current iroh connection path
    /// (relay/direct) once and open the modal showing it.
    ShowConnPath,
    /// Close the connection-path modal.
    DismissConnPath,
    /// Answers to the store reset warning (see [`App::store_reset`]): quit
    /// with what is on disk left untouched, or start fresh, saving the store
    /// without what could not be read.
    StoreResetQuit,
    StoreResetContinue,
    // Client
    /// The client pane's Enabled switch and the tray's Enable/Disable item —
    /// the client's only on/off control: enabled, it runs (starting with the
    /// app); disabled, it stops and stays stopped across launches.
    SetClientEnabled(bool),
    /// Restart the running client so changed settings take effect.
    RestartClient,
    /// Open the client pane's proxy-ports form.
    EditProxies,
    SocksEnabledToggled(bool),
    SocksPortChanged(String),
    HttpEnabledToggled(bool),
    HttpPortChanged(String),
    ProxyFormSave,
    ProxyFormCancel,
    ExportClient,
    ImportClient,
    ExportPicked(Option<std::path::PathBuf>),
    ImportPicked(Option<std::path::PathBuf>),
    // Destinations
    AddDestination,
    EditDestination(DestinationId),
    DeleteDestination(DestinationId),
    /// Ask the running client for one connection attempt to the destination
    /// now, instead of waiting for its first use.
    ConnectNow(DestinationId),
    // Destination form
    DestinationHostChanged(String),
    ServerNodeIdChanged(String),
    DestinationRoutedDomainsChanged(String),
    DestinationRoutedCidrsChanged(String),
    /// Pick a shared auth key for the destination being edited.
    AuthKeyPicked(KeyChoice),
    /// Open the destination form's "New key" prompt (a name field next to the
    /// picker).
    NewKeyPrompt,
    NewKeyNameChanged(String),
    /// Generate a keypair under the prompted name, add it to the shared list,
    /// and select it in the destination form.
    NewKeyCreate,
    NewKeyCancel,
    RelayUrlsChanged(String),
    RelayAuthTokenChanged(String),
    DestinationFormSave,
    DestinationFormCancel,
    // Auth keys (the Keys pane)
    AddKey,
    EditKey(String),
    DeleteKey(String),
    /// Copy the key's secret to the clipboard (two-click, like delete) so it
    /// can be imported on another device.
    ExportKey(String),
    KeyNameChanged(String),
    KeySecretChanged(String),
    /// Fill the key form's secret field with a freshly generated keypair.
    KeyGenerateSecret,
    KeyFormSave,
    KeyFormCancel,
    // Forwards
    AddForward,
    EditForward(String),
    DeleteForward(String),
    ToggleForward(String, bool),
    FormLabelChanged(String),
    FormLocalPortChanged(String),
    FormRemoteHostChanged(String),
    FormRemotePortChanged(String),
    FormEnabledToggled(bool),
    FormSave,
    FormCancel,
    // Server
    /// Show the server's welcome (or the server, once set up): the sidebar's
    /// "Set up server…" and the tray's.
    SetUpServer,
    /// Open the setup form from the welcome.
    BeginServerSetup,
    /// Open the server's settings form (tunnel set and relays).
    EditServer,
    DeleteServer,
    /// The server pane's Enabled switch and the tray's Enable/Disable item —
    /// the server's only on/off control: enabled, it runs (starting with the
    /// app); disabled, it stops and stays stopped across launches.
    SetServerEnabled(bool),
    /// Restart the running server so changed settings take effect.
    RestartServer,
    /// The setup form's identity: import an existing key (`true`) or use the
    /// generated one.
    ServerImportToggled(bool),
    ServerImportSecretChanged(String),
    /// The setup form's generated identity: roll a different one.
    ServerRegenerateIdentity,
    ServerRoutedDomainsChanged(String),
    ServerRoutedCidrsChanged(String),
    ServerRelayUrlsChanged(String),
    ServerRelayAuthTokenChanged(String),
    ServerFormSave,
    ServerFormCancel,
    // Authorized clients (the server pane)
    AuthorizeClient,
    ClientNameChanged(String),
    ClientPublicKeyChanged(String),
    /// Fill the client form with one of the app's own auth keys (for a client
    /// on another of the user's machines that shares it).
    ClientUseOwnKey(KeyChoice),
    ClientFormSave,
    ClientFormCancel,
    /// Two-click removal, by public key.
    RemoveClient(String),
    // Server identity
    /// Copy the identity secret to the clipboard (two-click), to move the
    /// server to another computer.
    ExportServerSecret,
    /// Open the identity form: a new identity, or (`true`) an imported key —
    /// how a lost identity is restored, or replaced when its key is gone for
    /// good.
    ReplaceIdentity(bool),
    IdentityImportToggled(bool),
    IdentitySecretChanged(String),
    IdentityRegenerate,
    IdentityFormSave,
    IdentityFormCancel,
    // Logs
    LogFilterChanged(LogFilter),
    OpenLogFolder,
    CopyLogs,
}

/// The Logs pane's filter: everything, the client session's threads
/// (`[client]`), or the server's (`[server]`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum LogFilter {
    #[default]
    All,
    Client,
    Server,
}

impl std::fmt::Display for LogFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LogFilter::All => "All",
            LogFilter::Client => "Client",
            LogFilter::Server => "Server",
        })
    }
}

/// A comma-separated list field, trimmed, empty entries dropped.
fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

/// Human description of what already occupies a local port of the client: one
/// of its proxy front-ends or a forward — they share one namespace.
/// `exclude_proxies` skips the proxy ports (their own form edits them);
/// `exclude_forward` skips the forward being edited.
fn port_owner(
    client: &ClientSettings,
    port: u16,
    exclude_proxies: bool,
    exclude_forward: Option<&str>,
) -> Option<String> {
    if !exclude_proxies {
        if client.socks_port == Some(port) {
            return Some("the SOCKS5 proxy".into());
        }
        if client.http_port == Some(port) {
            return Some("the HTTP proxy".into());
        }
    }
    client
        .forwards
        .iter()
        .find(|f| f.local_port == port && Some(f.id.as_str()) != exclude_forward)
        .map(|f| format!("forward \"{}\"", f.display_name()))
}

/// What an import changed, for its notice.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ImportSummary {
    pub destinations_added: usize,
    pub destinations_replaced: usize,
    pub forwards_added: usize,
    /// The ids of the forwards the import replaced (matched by local port).
    pub forwards_replaced: Vec<String>,
    /// Imported forwards left out: their local port is one of this computer's
    /// proxy ports.
    pub forwards_skipped: usize,
}

impl std::fmt::Display for ImportSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Imported: {} destination(s) added, {} replaced; {} forward(s) added, {} replaced",
            self.destinations_added,
            self.destinations_replaced,
            self.forwards_added,
            self.forwards_replaced.len()
        )?;
        match self.forwards_skipped {
            0 => f.write_str("."),
            n => write!(f, "; {n} skipped (local port used by a proxy here)."),
        }
    }
}

/// The client with an imported (already structurally validated) set of
/// destinations and forwards merged in, or why they do not fit. A destination
/// whose server node id is already here replaces that destination's settings
/// but keeps its id, auth-key reference and relay auth token; any other is
/// added with a fresh id, no key picked and no relay token — imports never
/// carry them. A forward on a local port already forwarded replaces that
/// forward (stopped, like any imported one); any other is added. The merged
/// destinations must still make one valid routing table — a host or a route
/// claimed twice rejects the whole import, leaving the client as it was.
fn merge_imported(
    client: &ClientSettings,
    imported: Portable,
) -> Result<(ClientSettings, ImportSummary), String> {
    let mut merged = client.clone();
    let mut summary = ImportSummary::default();
    for mut incoming in imported.destinations {
        match merged
            .destinations
            .iter()
            .position(|d| d.server_node_id == incoming.server_node_id)
        {
            Some(pos) => {
                let current = &merged.destinations[pos];
                incoming.id = current.id.clone();
                incoming.auth_key_id = current.auth_key_id.clone();
                incoming.relay_auth_token = current.relay_auth_token.clone();
                merged.destinations[pos] = incoming;
                summary.destinations_replaced += 1;
            }
            None => {
                incoming.id = Destination::new_id();
                incoming.auth_key_id = String::new();
                incoming.relay_auth_token = None;
                merged.destinations.push(incoming);
                summary.destinations_added += 1;
            }
        }
    }
    for mut incoming in imported.forwards {
        incoming.enabled = false;
        if port_owner(&merged, incoming.local_port, false, None)
            .is_some_and(|owner| owner.ends_with("proxy"))
        {
            summary.forwards_skipped += 1;
            continue;
        }
        match merged
            .forwards
            .iter()
            .position(|f| f.local_port == incoming.local_port)
        {
            Some(pos) => {
                incoming.id = merged.forwards[pos].id.clone();
                summary.forwards_replaced.push(incoming.id.clone());
                merged.forwards[pos] = incoming;
            }
            None => {
                incoming.id = PortForward::new_id();
                merged.forwards.push(incoming);
                summary.forwards_added += 1;
            }
        }
    }
    merged.route_table()?;
    Ok((merged, summary))
}

/// Editable destination buffers (the add/edit form). `editing_id` is `None`
/// when adding.
#[derive(Default)]
pub struct DestinationForm {
    editing_id: Option<DestinationId>,
    /// The destination's name: `<host>:<port>` is the server's own loopback.
    pub host: String,
    pub server_node_id: String,
    /// Comma-separated further domains sent through the server.
    pub routed_domains: String,
    /// Comma-separated further networks sent through the server.
    pub routed_cidrs: String,
    /// The picked shared key ([`AuthKey::id`]); empty while none is picked.
    pub auth_key_id: String,
    /// The "New key" prompt's name buffer; `None` while the prompt is closed.
    pub new_key_name: Option<String>,
    pub relay_urls: String,
    pub relay_auth_token: String,
}

impl DestinationForm {
    pub fn is_edit(&self) -> bool {
        self.editing_id.is_some()
    }

    fn edit(destination: &Destination) -> Self {
        Self {
            editing_id: Some(destination.id.clone()),
            host: destination.host.clone(),
            server_node_id: destination.server_node_id.clone(),
            routed_domains: destination.routed_domains.join(", "),
            routed_cidrs: destination.routed_cidrs.join(", "),
            auth_key_id: destination.auth_key_id.clone(),
            new_key_name: None,
            relay_urls: destination.relay_urls.join(", "),
            relay_auth_token: destination.relay_auth_token.clone().unwrap_or_default(),
        }
    }

    /// The destination this form describes, checked against the others: the
    /// host and routes are validated by the core's own routing table over
    /// every destination — the same check the session makes — so what saves
    /// here starts.
    pub fn validate(
        &self,
        destinations: &[Destination],
        keys: &[AuthKey],
    ) -> Result<Destination, String> {
        let editing = self.editing_id.as_deref();
        let others = || destinations.iter().filter(|d| Some(d.id.as_str()) != editing);
        if self.host.trim().is_empty() {
            return Err("Host is required — a name for this server, e.g. nas.internal".into());
        }
        let server_node_id = self.server_node_id.trim();
        if server_node_id.is_empty() {
            return Err("Server node id is required".into());
        }
        // One destination per server: a second name for the same server is an
        // accidental duplicate, not a use case (and the core refuses it).
        if let Some(other) = others().find(|d| d.server_node_id == server_node_id) {
            return Err(format!(
                "Destination \"{}\" already reaches this server",
                other.host
            ));
        }
        let routed_domains = split_list(&self.routed_domains);
        let routed_cidrs = split_list(&self.routed_cidrs);
        // This destination goes last, so its stored host is the table's last.
        let mut specs: Vec<RouteSpec<'_>> = others()
            .map(|d| RouteSpec {
                host: &d.host,
                routed_domains: &d.routed_domains,
                routed_cidrs: &d.routed_cidrs,
            })
            .collect();
        specs.push(RouteSpec {
            host: &self.host,
            routed_domains: &routed_domains,
            routed_cidrs: &routed_cidrs,
        });
        let host = RouteTable::new(&specs)
            .map_err(|e| format!("{e:#}"))?
            .hosts()
            .last()
            .map(String::from)
            .expect("the table has this destination");
        if config::find_key(keys, &self.auth_key_id).is_none() {
            return Err("Pick an auth key (or create one with New key)".into());
        }
        let relay_urls = split_list(&self.relay_urls);
        let relay_auth_token = {
            let token = self.relay_auth_token.trim();
            (!token.is_empty()).then(|| token.to_string())
        };
        // The core's own relay rules (how many URLs, a token only with custom
        // relays), so a destination that saves is one the client can start.
        flextunnel_core::transport::endpoint::RelayConfig::from_urls_with_token(
            &relay_urls,
            relay_auth_token.clone(),
        )
        .map_err(|e| format!("{e:#}"))?;
        Ok(Destination {
            id: self.editing_id.clone().unwrap_or_else(Destination::new_id),
            host,
            server_node_id: server_node_id.into(),
            routed_domains,
            routed_cidrs,
            auth_key_id: self.auth_key_id.clone(),
            relay_urls,
            relay_auth_token,
        })
    }
}

/// Editable buffers for the client's two proxy front-ends (the client pane's
/// inline form).
pub struct ProxyForm {
    pub socks_enabled: bool,
    pub socks_port: String,
    pub http_enabled: bool,
    pub http_port: String,
}

impl ProxyForm {
    fn edit(client: &ClientSettings) -> Self {
        Self {
            socks_enabled: client.socks_port.is_some(),
            socks_port: client.socks_port.unwrap_or(DEFAULT_SOCKS_PORT).to_string(),
            http_enabled: client.http_port.is_some(),
            http_port: client.http_port.unwrap_or(DEFAULT_HTTP_PORT).to_string(),
        }
    }

    /// The `(SOCKS5, HTTP)` ports this form gives the client; `None` leaves a
    /// front-end off. Neither may be a forward's local port.
    pub fn validate(&self, client: &ClientSettings) -> Result<(Option<u16>, Option<u16>), String> {
        let socks_port = if self.socks_enabled {
            let port = parse_port(&self.socks_port, "SOCKS5 port")?;
            if let Some(owner) = port_owner(client, port, true, None) {
                return Err(format!("SOCKS5 port {port} is already used by {owner}"));
            }
            Some(port)
        } else {
            None
        };
        let http_port = if self.http_enabled {
            let port = parse_port(&self.http_port, "HTTP port")?;
            if socks_port == Some(port) {
                return Err("HTTP port must differ from the SOCKS5 port".into());
            }
            if let Some(owner) = port_owner(client, port, true, None) {
                return Err(format!("HTTP port {port} is already used by {owner}"));
            }
            Some(port)
        } else {
            None
        };
        Ok((socks_port, http_port))
    }
}

/// Editable buffers for one shared auth key (the Keys pane's add/edit form).
/// `editing_id` is `None` when adding.
#[derive(Default)]
pub struct KeyForm {
    editing_id: Option<String>,
    pub name: String,
    pub secret: String,
}

impl KeyForm {
    pub fn is_edit(&self) -> bool {
        self.editing_id.is_some()
    }

    /// The id of the key being edited (`None` when adding), so the Keys pane
    /// can hide that key's card while its form is open.
    pub fn editing_id(&self) -> Option<&str> {
        self.editing_id.as_deref()
    }

    fn edit(key: &AuthKey) -> Self {
        Self {
            editing_id: Some(key.id.clone()),
            name: key.name.clone(),
            secret: key.secret.clone(),
        }
    }

    /// The public key derived from the form's secret, when it parses. The
    /// public half is never a secret — the UI shows it unmasked so it can be
    /// copied onto the server's authorized-keys file.
    pub fn public_key(&self) -> Option<String> {
        flextunnel_core::auth::ClientKey::from_secret_str(self.secret.trim())
            .ok()
            .map(|key| key.public_str())
    }

    pub fn validate(&self, keys: &[AuthKey]) -> Result<AuthKey, String> {
        let name = validate_key_name(&self.name, keys, self.editing_id.as_deref())?;
        let secret = self.secret.trim();
        if secret.is_empty() {
            return Err(
                "Secret key is required (generate one, or paste an ed25519-sec: key)".into(),
            );
        }
        let client_key = flextunnel_core::auth::ClientKey::from_secret_str(secret)
            .map_err(|e| format!("Invalid secret key: {e}"))?;
        let public_key = client_key.public_str();
        // The same keypair twice under two names is an accidental re-add, not
        // a use case — destinations share one entry instead.
        if let Some(other) = keys
            .iter()
            .find(|k| k.public_key == public_key && Some(k.id.as_str()) != self.editing_id.as_deref())
        {
            return Err(format!("Key \"{}\" already holds this secret", other.name));
        }
        Ok(AuthKey {
            id: self.editing_id.clone().unwrap_or_else(AuthKey::new_id),
            name,
            public_key,
            secret: secret.into(),
        })
    }
}

/// Normalize and validate a key name (see `config::is_valid_name`), rejecting
/// duplicates of any key other than `own_id`. Shared by the Keys form and the
/// destination form's New key prompt; unique names keep that form's picker
/// unambiguous.
pub fn validate_key_name(
    name: &str,
    keys: &[AuthKey],
    own_id: Option<&str>,
) -> Result<String, String> {
    let name = name.split_whitespace().collect::<Vec<_>>().join(" ");
    if name.is_empty() {
        return Err("Key name is required".into());
    }
    if name.chars().count() > 64 {
        return Err("Key name must be 64 characters or fewer".into());
    }
    if keys
        .iter()
        .any(|k| k.name == name && Some(k.id.as_str()) != own_id)
    {
        return Err(format!("Another key is already named \"{name}\""));
    }
    Ok(name)
}

/// Words separated by single spaces, nothing leading or trailing — the
/// stored shape of every name (see `config::is_valid_name`).
fn normalize_name(name: &str) -> String {
    name.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A fresh iroh identity secret, base64 — the secret line of a
/// `flextunnel generate-iroh-key` file.
pub fn generate_server_secret() -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .encode(flextunnel_core::iroh::SecretKey::generate().to_bytes())
}

/// A server identity being chosen — at setup, or to replace the current one:
/// a freshly generated key unless the user imports an existing one. The secret
/// is never shown; the endpoint id it gives is.
pub struct IdentityChoice {
    generated: String,
    /// `Some` while importing instead: the pasted secret.
    pub import: Option<String>,
}

impl IdentityChoice {
    fn new() -> Self {
        Self {
            generated: generate_server_secret(),
            import: None,
        }
    }

    fn importing() -> Self {
        Self {
            import: Some(String::new()),
            ..Self::new()
        }
    }

    /// Roll a different generated key (and so endpoint id).
    fn regenerate(&mut self) {
        self.generated = generate_server_secret();
    }

    fn secret(&self) -> &str {
        self.import.as_deref().unwrap_or(&self.generated).trim()
    }

    /// The `(secret, endpoint id)` this choice gives the server — the endpoint
    /// id is what clients enter as the server node id.
    pub fn resolve(&self) -> Result<(String, String), String> {
        let secret = self.secret();
        if secret.is_empty() {
            return Err("Paste the identity key to import".into());
        }
        let endpoint_id = flextunnel_core::secret::load_secret_from_string(secret)
            .map_err(|e| format!("Invalid identity key: {e:#}"))?
            .public()
            .to_string();
        Ok((secret.into(), endpoint_id))
    }
}

/// Editable buffers for the server's setup form and its settings form. The
/// identity is chosen at setup only (afterwards it is replaced through its own
/// form, see [`IdentityChoice`]), and the authorized clients are managed on
/// the server pane, not here. Which form it is follows whether the server
/// has an identity yet: without one, setup chooses it (`identity` is `Some`)
/// and creates the server; with one, it edits the tunnel set and relays.
#[derive(Default)]
pub struct ServerForm {
    /// `Some` when setting up (choosing the identity); `None` when editing the
    /// settings.
    pub identity: Option<IdentityChoice>,
    pub routed_domains: String,
    pub routed_cidrs: String,
    pub relay_urls: String,
    pub relay_auth_token: String,
}

impl ServerForm {
    fn add() -> Self {
        Self {
            identity: Some(IdentityChoice::new()),
            ..Self::default()
        }
    }

    fn edit(server: &ServerConfig) -> Self {
        Self {
            identity: None,
            routed_domains: server.routed_domains.join(", "),
            routed_cidrs: server.routed_cidrs.join(", "),
            relay_urls: server.relay_urls.join(", "),
            relay_auth_token: server.relay_auth_token.clone().unwrap_or_default(),
        }
    }

    /// The server this form describes: a new one (no clients yet) when
    /// setting up, else `current` with the form's settings.
    pub fn validate(&self, current: Option<&ServerConfig>) -> Result<ServerConfig, String> {
        let (secret, endpoint_id, authorized_clients, enabled) = match (&self.identity, current) {
            // A new server is enabled: it starts once it has a client.
            (Some(identity), _) => {
                let (secret, endpoint_id) = identity.resolve()?;
                (secret, endpoint_id, Vec::new(), true)
            }
            (None, Some(current)) => (
                current.secret.clone(),
                current.endpoint_id.clone(),
                current.authorized_clients.clone(),
                current.enabled,
            ),
            (None, None) => return Err("The server was deleted".into()),
        };
        let routed_domains = split_list(&self.routed_domains);
        let routed_cidrs = split_list(&self.routed_cidrs);
        flextunnel_core::proxy::RoutedSet::new(&routed_domains, &routed_cidrs)
            .map_err(|e| format!("Invalid tunnel set: {e:#}"))?;
        let relay_urls = split_list(&self.relay_urls);
        let relay_auth_token = {
            let token = self.relay_auth_token.trim();
            (!token.is_empty()).then(|| token.to_string())
        };
        if relay_auth_token.is_some() && relay_urls.is_empty() {
            return Err("A relay auth token requires at least one relay URL".into());
        }
        Ok(ServerConfig {
            endpoint_id,
            secret,
            authorized_clients,
            routed_domains,
            routed_cidrs,
            relay_urls,
            relay_auth_token,
            enabled,
        })
    }
}

/// Editable buffers for authorizing one client on the server pane: a name for
/// it and the public half of its auth key.
#[derive(Default)]
pub struct ClientForm {
    pub name: String,
    pub public_key: String,
}

impl ClientForm {
    /// Take the public key field's new value. A whole authorized-key entry
    /// (`ed25519-pub:... alice laptop`, as `flexaccess-keys show-auth-key`
    /// prints it) is split: the key stays in the field, and its comment names
    /// the client unless a name was typed already.
    fn set_public_key(&mut self, value: String) {
        match value.trim().split_once(char::is_whitespace) {
            Some((key, comment)) => {
                if self.name.trim().is_empty() {
                    self.name = normalize_name(comment);
                }
                self.public_key = key.into();
            }
            None => self.public_key = value,
        }
    }

    pub fn validate(&self, clients: &[AuthorizedClient]) -> Result<AuthorizedClient, String> {
        let name = normalize_name(&self.name);
        if name.is_empty() {
            return Err("Name the client (e.g. the device it runs on)".into());
        }
        if name.chars().count() > 64 {
            return Err("Client name must be 64 characters or fewer".into());
        }
        if clients.iter().any(|c| c.name == name) {
            return Err(format!("Another client is already named \"{name}\""));
        }
        if self.public_key.trim().is_empty() {
            return Err("Paste the client's public key (ed25519-pub:…)".into());
        }
        let public_key = config::parse_client_public_key(&self.public_key)?;
        if let Some(other) = clients.iter().find(|c| c.public_key == public_key) {
            return Err(format!("Client \"{}\" already has this key", other.name));
        }
        Ok(AuthorizedClient { name, public_key })
    }
}

/// Editable add/edit buffers for one port forward, mirroring the iOS sheet.
/// `editing_id` is `None` when adding.
pub struct ForwardForm {
    editing_id: Option<String>,
    pub label: String,
    pub local_port: String,
    pub remote_host: String,
    pub remote_port: String,
    pub enabled: bool,
}

impl ForwardForm {
    pub fn is_edit(&self) -> bool {
        self.editing_id.is_some()
    }

    fn add() -> Self {
        Self {
            editing_id: None,
            label: String::new(),
            local_port: String::new(),
            remote_host: String::new(),
            remote_port: String::new(),
            enabled: true,
        }
    }

    fn edit(forward: &PortForward) -> Self {
        Self {
            editing_id: Some(forward.id.clone()),
            label: forward.label.clone(),
            local_port: forward.local_port.to_string(),
            remote_host: forward.remote_host.clone(),
            remote_port: forward.remote_port.to_string(),
            enabled: forward.enabled,
        }
    }

    /// Validate against the client: its proxy ports and forwards share one
    /// namespace of local ports.
    pub fn validate(&self, client: &ClientSettings) -> Result<PortForward, String> {
        let label = validate_label(&self.label)?;
        let local_port = parse_port(&self.local_port, "Local port")?;
        let remote_host = validate_remote_host(&self.remote_host)?;
        let remote_port = parse_port(&self.remote_port, "Remote port")?;
        if let Some(owner) = port_owner(client, local_port, false, self.editing_id.as_deref()) {
            return Err(format!("Local port {local_port} is already used by {owner}"));
        }
        Ok(PortForward {
            id: self
                .editing_id
                .clone()
                .unwrap_or_else(PortForward::new_id),
            label,
            local_port,
            remote_host,
            remote_port,
            enabled: self.enabled,
        })
    }
}

pub fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}h {m:02}m {s:02}s")
    } else if m > 0 {
        format!("{m}m {s:02}s")
    } else {
        format!("{s}s")
    }
}

fn open_log_folder() {
    let Some(dir) = logging::log_dir() else {
        return;
    };
    #[cfg(target_os = "macos")]
    let result = std::process::Command::new("open").arg(&dir).spawn();
    #[cfg(windows)]
    let result = std::process::Command::new("explorer").arg(&dir).spawn();
    if let Err(e) = result {
        log::error!("Failed to open the log folder {}: {e}", dir.display());
    }
}

/// Menu-bar app with a Dock presence only while the window is open: Regular
/// (Dock icon, app switcher) when it exists, Accessory when it closes. winit
/// applies Regular during launch anyway (overriding the bundle's LSUIElement),
/// so this only has to run on the open/close transitions afterwards. No-op off
/// macOS.
fn set_activation_policy(regular: bool) {
    #[cfg(target_os = "macos")]
    {
        use objc2::MainThreadMarker;
        use objc2_app_kit::{NSApplication, NSApplicationActivationPolicy};
        match MainThreadMarker::new() {
            Some(mtm) => {
                let app = NSApplication::sharedApplication(mtm);
                app.setActivationPolicy(if regular {
                    NSApplicationActivationPolicy::Regular
                } else {
                    NSApplicationActivationPolicy::Accessory
                });
                if regular {
                    // Switching Accessory → Regular does not bring the app
                    // forward on its own.
                    #[allow(deprecated)]
                    app.activateIgnoringOtherApps(true);
                }
            }
            None => log::warn!("Not on the main thread; leaving the activation policy alone"),
        }
    }
    #[cfg(windows)]
    let _ = regular;
}

fn window_settings() -> window::Settings {
    let (rgba, width, height) = icon::window_icon_rgba(256);
    window::Settings {
        size: Size::new(860.0, 640.0),
        min_size: Some(Size::new(680.0, 500.0)),
        icon: window::icon::from_rgba(rgba, width, height).ok(),
        ..window::Settings::default()
    }
}

pub struct App {
    controller: Controller,
    tray: Option<Tray>,
    window: Option<window::Id>,
    /// The client — its proxy ports, forwards and destinations (in sidebar
    /// order); persisted via `config::save_store`.
    pub client: ClientSettings,
    /// The shared auth keys destinations reference into; persisted alongside.
    pub keys: Vec<AuthKey>,
    /// The app's one server, when configured; persisted alongside.
    pub server: Option<ServerConfig>,
    pub selection: Selection,
    /// The open destination add/edit form (replaces the detail pane).
    pub destination_form: Option<DestinationForm>,
    /// The client pane's open proxy-ports form.
    pub proxy_form: Option<ProxyForm>,
    /// The Keys pane's open add/edit form.
    pub key_form: Option<KeyForm>,
    /// The open server setup/settings form (replaces the detail pane, like
    /// the destination form).
    pub server_form: Option<ServerForm>,
    /// The server pane's open "authorize a client" form.
    pub client_form: Option<ClientForm>,
    /// The server pane's open "replace identity" form.
    pub identity_form: Option<IdentityChoice>,
    /// Two-click removal guard for an authorized client, by public key.
    pub confirm_remove_client: Option<String>,
    /// Two-click guard for copying the server's identity secret.
    pub confirm_export_server_secret: bool,
    /// The config the server session was last started with, so the pane can
    /// tell when the saved settings differ from the running ones.
    server_applied: Option<ServerConfig>,
    /// What the client session was last started with, so the panes can tell
    /// when the saved settings differ from the running ones.
    client_applied: Option<ClientSpec>,
    /// The client pane's open forward form.
    pub forward_form: Option<ForwardForm>,
    /// Two-click delete guard: the destination whose Delete was clicked once.
    pub confirm_delete: Option<DestinationId>,
    /// Two-click delete guard for the Keys pane.
    pub confirm_delete_key: Option<String>,
    /// Two-click delete guard for the server.
    pub confirm_delete_server: bool,
    /// Two-click export guard for the Keys pane: the key whose Export was
    /// clicked once; the second click copies its secret to the clipboard.
    pub confirm_export_key: Option<String>,
    /// Transient status line in the detail pane (save results/failures).
    pub notice: Option<String>,
    /// Open connection-path modal: a point-in-time path snapshot (`ezvpn
    /// status`-style), overlaid until dismissed. `None` when closed.
    pub conn_path_modal: Option<ConnectionSnapshot>,
    /// Transient export/import result shown in the sidebar.
    pub io_notice: Option<String>,
    /// Why this launch's store is not what is on disk — its sealed secrets
    /// all empty, or the whole store — until the user answers the warning
    /// modal. Nothing is saved meanwhile — a save would replace what is on
    /// disk with only what was entered since — so quitting leaves it there,
    /// for the build that sealed it or for once the cause is fixed.
    pub store_reset: Option<StoreReset>,
    /// Setup-failure reason per forward id, retained after the failed forward
    /// is auto-stopped (see [`disable_failed_forwards`]) so the row can keep
    /// showing why; cleared when the forward is started again or removed.
    pub forward_errors: HashMap<String, String>,
    /// The forwards' advisory routing table (which destination carries each,
    /// if any): rebuilt only when a destination's host or routes change.
    pub routed_cache: view::RoutedCache,
    log_revision: u64,
    /// Logs-pane filter (see [`LogFilter`]).
    pub log_filter: LogFilter,
    /// The in-memory log ring, filtered and joined for the Logs pane;
    /// rebuilt on revision or filter change only.
    pub log_text: String,
    clipboard: Option<arboard::Clipboard>,
    /// The client session's snapshot, refreshed by [`App::refresh`] on every
    /// tick, rendered by `view`.
    pub client_snapshot: ClientSnapshot,
    /// The server session's snapshot, refreshed alongside.
    pub server_snapshot: ServerSnapshot,
    /// Whether the app is registered as a login item — the OS's answer
    /// (`autostart::is_enabled`), re-read every tick so a change made in the
    /// system settings shows in the tray checkbox.
    pub launch_at_login: bool,
    /// Persisted with the store; see `config::Store::login_item_set_up`.
    login_item_set_up: bool,
}

impl App {
    pub fn boot() -> (Self, Task<Message>) {
        let controller = Controller::start();

        // A store that fails to load is replaced by an empty one, one whose
        // secrets failed to unseal or were sealed under another version runs
        // without them: nothing may be written back over what is on disk —
        // still recoverable, once the cause is fixed — until the user
        // chooses to start fresh (see `store_reset`).
        let (store, store_reset) = match config::load_store() {
            Ok(store) => {
                let reset = match (store.sealed_reset_from, store.unseal_failed) {
                    (Some(version), _) => Some(StoreReset::Version(version)),
                    (None, true) => Some(StoreReset::Unsealable),
                    (None, false) => None,
                };
                (store, reset)
            }
            Err(e) => {
                log::error!("{e:#}");
                (config::Store::default(), Some(StoreReset::Unreadable(format!("{e:#}"))))
            }
        };
        let store_intact = store_reset.is_none();
        // The client once it has somewhere to go, else the server — or, with
        // neither, the empty pane pointing at the sidebar.
        let selection = match (store.client.destinations.is_empty(), &store.server) {
            (false, _) => Selection::Client,
            (true, Some(_)) => Selection::Server,
            (true, None) => Selection::Empty,
        };

        let mut app = Self {
            controller,
            tray: None,
            window: None,
            client: store.client,
            keys: store.keys,
            server: store.server,
            selection,
            destination_form: None,
            proxy_form: None,
            key_form: None,
            server_form: None,
            client_form: None,
            identity_form: None,
            confirm_remove_client: None,
            confirm_export_server_secret: false,
            server_applied: None,
            client_applied: None,
            forward_form: None,
            confirm_delete: None,
            confirm_delete_key: None,
            confirm_delete_server: false,
            confirm_export_key: None,
            notice: None,
            conn_path_modal: None,
            io_notice: None,
            store_reset,
            forward_errors: HashMap::new(),
            routed_cache: view::RoutedCache::default(),
            // MAX so the first refresh always builds the log text.
            log_revision: u64::MAX,
            log_filter: LogFilter::All,
            log_text: String::new(),
            clipboard: None,
            client_snapshot: ClientSnapshot::default(),
            server_snapshot: ServerSnapshot::default(),
            launch_at_login: false,
            login_item_set_up: store.login_item_set_up,
        };
        // First launch of an install: start at login by default, as tray
        // apps do on both platforms. The OS registration is the truth from
        // then on, so a checkbox the user cleared is never re-ticked. A dev
        // store (`FLEXTUNNEL_DEV_CONFIG` or `FLEXTUNNEL_KEYCHAIN=mock`) never
        // touches the login item, so a debug or test binary neither becomes
        // one nor re-points a real install's.
        if config::dev_store() {
            log::info!("Dev store: leaving the login item alone");
        } else if !app.login_item_set_up {
            if !store_intact {
                log::warn!(
                    "The store did not load intact: login-item setup waits for a launch that does"
                );
            } else {
                // Recorded only once it worked, so a failure is retried next launch.
                match autostart::set_enabled(true) {
                    Ok(()) => {
                        log::info!("First launch: registered as a login item");
                        app.login_item_set_up = true;
                        app.persist_store();
                    }
                    Err(e) => log::error!("Failed to register as a login item: {e:#}"),
                }
            }
        } else if let Err(e) = autostart::refresh() {
            log::warn!("Failed to refresh the login item: {e:#}");
        }
        app.launch_at_login = autostart::is_enabled();
        // A configured server is meant to be running: it starts with the app.
        if let Some(server) = &app.server {
            match server.start_blocker() {
                _ if !server.enabled => log::info!("The server is disabled; not starting it"),
                None => log::info!("Starting the configured server"),
                Some(blocker) => log::warn!("Not starting the server yet: {blocker}"),
            }
            app.resume_server();
        }
        // So is an enabled client. Starting it binds its local ports only: it
        // connects to a destination when something is first sent there.
        if !app.client.destinations.is_empty() {
            match app.client.start_blocker(&app.keys) {
                _ if !app.client.enabled => log::info!("The client is disabled; not starting it"),
                None => log::info!("Starting the client"),
                Some(blocker) => log::warn!("Not starting the client yet: {blocker}"),
            }
            app.resume_client();
        }
        // Launched as a login item, the app stays in the tray; the window is
        // a click away — unless the store reset warning needs answering.
        let open = if autostart::launched_at_login() && app.store_reset.is_none() {
            Task::none()
        } else {
            app.open_window()
        };
        // The tray is created via a task so it lands on the main thread with
        // the event loop already running (a macOS requirement).
        (app, Task::batch([Task::done(Message::SetupTray), open]))
    }

    pub fn title(&self, _window: window::Id) -> String {
        "flextunnel".into()
    }

    pub fn style(&self, theme: &iced::Theme) -> iced::theme::Style {
        crate::style::app(theme)
    }

    pub fn subscription(&self) -> Subscription<Message> {
        Subscription::batch([
            // Steady heartbeat so the snapshots and tray state stay fresh even
            // while no window exists; tray events wake the runtime instantly.
            iced::time::every(Duration::from_millis(500)).map(|_| Message::Tick),
            window::close_events().map(Message::WindowClosed),
            Subscription::run(tray_events),
        ])
    }

    pub fn view(&self, _window: window::Id) -> Element<'_, Message> {
        view::root(self)
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Tick => {
                self.refresh();
                Task::none()
            }
            Message::SetupTray => {
                set_activation_policy(self.window.is_some());
                match Tray::new() {
                    Ok(tray) => {
                        tray.set_launch_at_login(self.launch_at_login);
                        self.tray = Some(tray);
                    }
                    Err(e) => log::error!("Failed to create the tray icon: {e:#}"),
                }
                self.refresh();
                Task::none()
            }
            Message::TrayMenu(id) => self.handle_menu_event(&id),
            Message::TrayIcon(event) => {
                // Windows convention: left click on the tray icon toggles the
                // window. On macOS the left click opens the menu natively.
                #[cfg(windows)]
                if let TrayIconEvent::Click {
                    button: tray_icon::MouseButton::Left,
                    button_state: tray_icon::MouseButtonState::Up,
                    ..
                } = event
                {
                    return match self.window.take() {
                        Some(id) => window::close(id),
                        None => self.open_window(),
                    };
                }
                let _ = event;
                Task::none()
            }
            Message::WindowOpened => Task::none(),
            Message::WindowClosed(id) => {
                // Closing the window destroys it; the app lives on in the
                // tray (and off the Dock). Quit comes from the tray menu.
                if self.window == Some(id) {
                    self.window = None;
                    set_activation_policy(false);
                }
                Task::none()
            }
            Message::Select(selection) => {
                self.selection = selection;
                self.close_forms();
                self.conn_path_modal = None;
                Task::none()
            }
            Message::ReadOnlyEdited => Task::none(),
            Message::CopyText(text) => {
                self.copy_text(text);
                Task::none()
            }
            Message::ShowConnPath => {
                // A one-shot readout shown in a dismissable modal overlay — a
                // point-in-time snapshot that sits above the layout (not in it)
                // so it can't be mistaken for a live field and leaves the pane
                // untouched.
                if let Selection::Destination(id) = &self.selection
                    && let Some(destination) = self.client.destination(id)
                {
                    let snapshot = self.controller.query_conn_path(&destination.host);
                    self.conn_path_modal = Some(snapshot);
                }
                Task::none()
            }
            Message::DismissConnPath => {
                self.conn_path_modal = None;
                Task::none()
            }
            Message::StoreResetQuit => {
                self.controller.shutdown();
                iced::exit()
            }
            Message::StoreResetContinue => {
                self.store_reset = None;
                self.persist_store();
                Task::none()
            }
            Message::SetClientEnabled(enabled) => self.set_client_enabled(enabled),
            Message::RestartClient => {
                self.restart_client();
                Task::none()
            }
            Message::EditProxies => {
                self.forward_form = None;
                self.notice = None;
                self.proxy_form = Some(ProxyForm::edit(&self.client));
                Task::none()
            }
            Message::SocksEnabledToggled(enabled) => {
                if let Some(form) = &mut self.proxy_form {
                    form.socks_enabled = enabled;
                }
                Task::none()
            }
            Message::SocksPortChanged(value) => {
                if let Some(form) = &mut self.proxy_form {
                    form.socks_port = value;
                }
                Task::none()
            }
            Message::HttpEnabledToggled(enabled) => {
                if let Some(form) = &mut self.proxy_form {
                    form.http_enabled = enabled;
                }
                Task::none()
            }
            Message::HttpPortChanged(value) => {
                if let Some(form) = &mut self.proxy_form {
                    form.http_port = value;
                }
                Task::none()
            }
            Message::ProxyFormSave => {
                self.save_proxy_form();
                Task::none()
            }
            Message::ProxyFormCancel => {
                self.proxy_form = None;
                Task::none()
            }
            Message::ExportClient => Task::perform(
                async {
                    rfd::AsyncFileDialog::new()
                        .add_filter("JSON", &["json"])
                        .set_file_name("flextunnel-destinations.json")
                        .save_file()
                        .await
                        .map(|file| file.path().to_path_buf())
                },
                Message::ExportPicked,
            ),
            Message::ImportClient => Task::perform(
                async {
                    rfd::AsyncFileDialog::new()
                        .add_filter("JSON", &["json"])
                        .pick_file()
                        .await
                        .map(|file| file.path().to_path_buf())
                },
                Message::ImportPicked,
            ),
            Message::ExportPicked(path) => {
                if let Some(path) = path {
                    self.io_notice = Some(match config::export_client(&path, &self.client) {
                        Ok(()) => format!(
                            "Exported {} destination(s), {} forward(s).",
                            self.client.destinations.len(),
                            self.client.forwards.len()
                        ),
                        Err(e) => {
                            log::error!("{e:#}");
                            format!("Export failed: {e:#}")
                        }
                    });
                }
                Task::none()
            }
            Message::ImportPicked(path) => {
                if let Some(path) = path {
                    self.import_client(&path);
                }
                Task::none()
            }
            Message::AddDestination => {
                self.close_forms();
                self.destination_form = Some(DestinationForm::default());
                Task::none()
            }
            Message::EditDestination(id) => {
                if let Some(destination) = self.client.destination(&id) {
                    let form = DestinationForm::edit(destination);
                    self.close_forms();
                    self.destination_form = Some(form);
                }
                Task::none()
            }
            Message::DeleteDestination(id) => {
                self.delete_destination(id);
                Task::none()
            }
            Message::ConnectNow(id) => {
                if let Some(destination) = self.client.destination(&id) {
                    self.controller.connect_now(&destination.host);
                }
                Task::none()
            }
            Message::DestinationHostChanged(value) => {
                if let Some(form) = &mut self.destination_form {
                    form.host = value;
                }
                Task::none()
            }
            Message::ServerNodeIdChanged(value) => {
                if let Some(form) = &mut self.destination_form {
                    form.server_node_id = value;
                }
                Task::none()
            }
            Message::DestinationRoutedDomainsChanged(value) => {
                if let Some(form) = &mut self.destination_form {
                    form.routed_domains = value;
                }
                Task::none()
            }
            Message::DestinationRoutedCidrsChanged(value) => {
                if let Some(form) = &mut self.destination_form {
                    form.routed_cidrs = value;
                }
                Task::none()
            }
            Message::AuthKeyPicked(choice) => {
                if let Some(form) = &mut self.destination_form {
                    form.auth_key_id = choice.id;
                }
                Task::none()
            }
            Message::NewKeyPrompt => {
                if let Some(form) = &mut self.destination_form
                    && form.new_key_name.is_none()
                {
                    form.new_key_name = Some(String::new());
                }
                Task::none()
            }
            Message::NewKeyNameChanged(value) => {
                if let Some(form) = &mut self.destination_form
                    && let Some(buffer) = &mut form.new_key_name
                {
                    *buffer = value;
                }
                Task::none()
            }
            Message::NewKeyCreate => {
                self.create_key_for_destination_form();
                Task::none()
            }
            Message::NewKeyCancel => {
                if let Some(form) = &mut self.destination_form {
                    form.new_key_name = None;
                }
                Task::none()
            }
            Message::RelayUrlsChanged(value) => {
                if let Some(form) = &mut self.destination_form {
                    form.relay_urls = value;
                }
                Task::none()
            }
            Message::RelayAuthTokenChanged(value) => {
                if let Some(form) = &mut self.destination_form {
                    form.relay_auth_token = value;
                }
                Task::none()
            }
            Message::DestinationFormSave => {
                self.save_destination_form();
                Task::none()
            }
            Message::DestinationFormCancel => {
                self.destination_form = None;
                Task::none()
            }
            Message::AddKey => {
                self.key_form = Some(KeyForm::default());
                self.confirm_delete_key = None;
                self.confirm_export_key = None;
                self.notice = None;
                Task::none()
            }
            Message::EditKey(id) => {
                if let Some(key) = config::find_key(&self.keys, &id) {
                    self.key_form = Some(KeyForm::edit(key));
                    self.confirm_delete_key = None;
                    self.confirm_export_key = None;
                    self.notice = None;
                }
                Task::none()
            }
            Message::DeleteKey(id) => {
                self.delete_key(id);
                Task::none()
            }
            Message::ExportKey(id) => {
                self.export_key(id);
                Task::none()
            }
            Message::KeyNameChanged(value) => {
                if let Some(form) = &mut self.key_form {
                    form.name = value;
                }
                Task::none()
            }
            Message::KeySecretChanged(value) => {
                if let Some(form) = &mut self.key_form {
                    form.secret = value;
                }
                Task::none()
            }
            Message::KeyGenerateSecret => {
                if let Some(form) = &mut self.key_form {
                    form.secret = flextunnel_core::auth::ClientKey::generate().expect("system RNG unavailable").secret_str();
                }
                Task::none()
            }
            Message::KeyFormSave => {
                self.save_key_form();
                Task::none()
            }
            Message::KeyFormCancel => {
                self.key_form = None;
                Task::none()
            }
            Message::AddForward => {
                self.proxy_form = None;
                self.forward_form = Some(ForwardForm::add());
                Task::none()
            }
            Message::EditForward(forward_id) => {
                if let Some(forward) = self.client.forwards.iter().find(|f| f.id == forward_id) {
                    self.proxy_form = None;
                    self.forward_form = Some(ForwardForm::edit(forward));
                }
                Task::none()
            }
            Message::DeleteForward(forward_id) => {
                let before = self.client.forwards.len();
                self.client.forwards.retain(|f| f.id != forward_id);
                if self.client.forwards.len() != before {
                    self.forward_errors.remove(&forward_id);
                    self.commit_forwards();
                }
                Task::none()
            }
            Message::ToggleForward(forward_id, enabled) => {
                if let Some(forward) =
                    self.client.forwards.iter_mut().find(|f| f.id == forward_id)
                {
                    // Desired state, but not a plain checkbox: enabling
                    // attempts the setup now, and a setup failure snaps the
                    // switch back off (see disable_failed_forwards).
                    forward.enabled = enabled;
                    if enabled {
                        // A fresh start attempt supersedes the old failure.
                        self.forward_errors.remove(&forward_id);
                    }
                    self.commit_forwards();
                }
                Task::none()
            }
            Message::FormLabelChanged(value) => {
                if let Some(form) = &mut self.forward_form {
                    form.label = value;
                }
                Task::none()
            }
            Message::FormLocalPortChanged(value) => {
                if let Some(form) = &mut self.forward_form {
                    form.local_port = value;
                }
                Task::none()
            }
            Message::FormRemoteHostChanged(value) => {
                if let Some(form) = &mut self.forward_form {
                    form.remote_host = value;
                }
                Task::none()
            }
            Message::FormRemotePortChanged(value) => {
                if let Some(form) = &mut self.forward_form {
                    form.remote_port = value;
                }
                Task::none()
            }
            Message::FormEnabledToggled(enabled) => {
                if let Some(form) = &mut self.forward_form {
                    form.enabled = enabled;
                }
                Task::none()
            }
            Message::FormSave => {
                self.save_forward_form();
                Task::none()
            }
            Message::FormCancel => {
                self.forward_form = None;
                Task::none()
            }
            Message::SetUpServer => self.set_up_server(),
            Message::BeginServerSetup => {
                if self.server.is_none() {
                    self.close_forms();
                    self.selection = Selection::Server;
                    self.server_form = Some(ServerForm::add());
                }
                Task::none()
            }
            Message::EditServer => {
                if let Some(server) = &self.server {
                    let form = ServerForm::edit(server);
                    self.close_forms();
                    self.server_form = Some(form);
                }
                Task::none()
            }
            Message::DeleteServer => {
                self.delete_server();
                Task::none()
            }
            Message::SetServerEnabled(enabled) => self.set_server_enabled(enabled),
            Message::RestartServer => {
                let Some(server) = self.server.clone() else {
                    return Task::none();
                };
                match server.start_blocker() {
                    None => {
                        self.controller.restart_server(server.clone());
                        self.server_applied = Some(server);
                    }
                    // E.g. the identity was lost: it would not start again, so
                    // stop the stale session rather than leave it running.
                    Some(blocker) => {
                        self.controller.stop_server();
                        self.notice = Some(blocker.into());
                    }
                }
                Task::none()
            }
            Message::ServerImportToggled(import) => {
                if let Some(identity) = self.server_form.as_mut().and_then(|f| f.identity.as_mut()) {
                    identity.import = import.then(String::new);
                }
                Task::none()
            }
            Message::ServerRegenerateIdentity => {
                if let Some(identity) = self.server_form.as_mut().and_then(|f| f.identity.as_mut()) {
                    identity.regenerate();
                }
                Task::none()
            }
            Message::ServerImportSecretChanged(value) => {
                if let Some(secret) = self
                    .server_form
                    .as_mut()
                    .and_then(|f| f.identity.as_mut())
                    .and_then(|i| i.import.as_mut())
                {
                    *secret = value;
                }
                Task::none()
            }
            Message::ServerRoutedDomainsChanged(value) => {
                if let Some(form) = &mut self.server_form {
                    form.routed_domains = value;
                }
                Task::none()
            }
            Message::ServerRoutedCidrsChanged(value) => {
                if let Some(form) = &mut self.server_form {
                    form.routed_cidrs = value;
                }
                Task::none()
            }
            Message::ServerRelayUrlsChanged(value) => {
                if let Some(form) = &mut self.server_form {
                    form.relay_urls = value;
                }
                Task::none()
            }
            Message::ServerRelayAuthTokenChanged(value) => {
                if let Some(form) = &mut self.server_form {
                    form.relay_auth_token = value;
                }
                Task::none()
            }
            Message::ServerFormSave => {
                self.save_server_form();
                Task::none()
            }
            Message::ServerFormCancel => {
                self.server_form = None;
                Task::none()
            }
            Message::AuthorizeClient => {
                self.client_form = Some(ClientForm::default());
                self.identity_form = None;
                self.confirm_remove_client = None;
                self.notice = None;
                Task::none()
            }
            Message::ClientNameChanged(value) => {
                if let Some(form) = &mut self.client_form {
                    form.name = value;
                }
                Task::none()
            }
            Message::ClientPublicKeyChanged(value) => {
                if let Some(form) = &mut self.client_form {
                    form.set_public_key(value);
                }
                Task::none()
            }
            Message::ClientUseOwnKey(choice) => {
                if let Some(form) = &mut self.client_form
                    && let Some(key) = config::find_key(&self.keys, &choice.id)
                {
                    form.name = key.name.clone();
                    form.public_key = key.public_key.clone();
                }
                Task::none()
            }
            Message::ClientFormSave => {
                self.save_client_form();
                Task::none()
            }
            Message::ClientFormCancel => {
                self.client_form = None;
                Task::none()
            }
            Message::RemoveClient(public_key) => {
                self.remove_client(public_key);
                Task::none()
            }
            Message::ExportServerSecret => {
                self.export_server_secret();
                Task::none()
            }
            Message::ReplaceIdentity(import) => {
                self.identity_form = Some(if import {
                    IdentityChoice::importing()
                } else {
                    IdentityChoice::new()
                });
                self.client_form = None;
                self.confirm_export_server_secret = false;
                self.notice = None;
                Task::none()
            }
            Message::IdentityImportToggled(import) => {
                if let Some(identity) = &mut self.identity_form {
                    identity.import = import.then(String::new);
                }
                Task::none()
            }
            Message::IdentityRegenerate => {
                if let Some(identity) = &mut self.identity_form {
                    identity.regenerate();
                }
                Task::none()
            }
            Message::IdentitySecretChanged(value) => {
                if let Some(secret) = self.identity_form.as_mut().and_then(|i| i.import.as_mut()) {
                    *secret = value;
                }
                Task::none()
            }
            Message::IdentityFormSave => {
                self.save_identity_form();
                Task::none()
            }
            Message::IdentityFormCancel => {
                self.identity_form = None;
                Task::none()
            }
            Message::LogFilterChanged(filter) => {
                self.log_filter = filter;
                self.rebuild_log_text();
                Task::none()
            }
            Message::OpenLogFolder => {
                open_log_folder();
                Task::none()
            }
            Message::CopyLogs => {
                let text = self.log_text.clone();
                self.copy_text(text);
                Task::none()
            }
        }
    }

    /// How `destination` stands in the client session: live only when the
    /// session was started with it exactly as saved.
    pub fn destination_live(&self, destination: &Destination) -> DestinationLive<'_> {
        if self.client_snapshot.phase != ClientPhase::Running {
            return DestinationLive::Stopped;
        }
        let applied = self
            .client_applied
            .as_ref()
            .is_some_and(|spec| spec.destinations.iter().any(|d| d.destination == *destination));
        if !applied {
            return DestinationLive::Pending;
        }
        match self
            .client_snapshot
            .destinations
            .iter()
            .find(|status| status.host == destination.host)
        {
            Some(status) => DestinationLive::Live(status),
            // Running, with its first status a poll away.
            None => DestinationLive::Stopped,
        }
    }

    fn open_window(&mut self) -> Task<Message> {
        let (id, open) = window::open(window_settings());
        self.window = Some(id);
        set_activation_policy(true);
        open.map(|_| Message::WindowOpened)
    }

    fn show_window(&mut self) -> Task<Message> {
        match self.window {
            Some(id) => window::gain_focus(id),
            None => self.open_window(),
        }
    }

    /// Whether the running client was started with other settings than the
    /// saved ones — its ports, its destinations or a key they use — so a
    /// restart is needed to apply them. Forwards never need one.
    pub fn client_needs_restart(&self) -> bool {
        // A client just disabled is stopping, not waiting for a restart.
        matches!(
            self.client_snapshot.phase,
            ClientPhase::Starting | ClientPhase::Running
        ) && self.client.enabled
            && self.client_applied != ClientSpec::resolve(&self.client, &self.keys)
    }

    /// Start a client session with the saved settings, if they resolve.
    fn start_client(&mut self) {
        if let Some(spec) = ClientSpec::resolve(&self.client, &self.keys) {
            self.controller
                .start_client(spec.clone(), self.client.forwards.clone());
            self.client_applied = Some(spec);
        }
    }

    /// Start the client if it is enabled, down, and can start: at launch, and
    /// after a change that may have made it startable — its first destination
    /// added, a lost key secret re-entered, a taken port changed. A client
    /// still stopping gets the start queued behind the stop.
    fn resume_client(&mut self) {
        let down = matches!(
            self.controller.client_snapshot().phase,
            ClientPhase::Stopped | ClientPhase::Failed | ClientPhase::Stopping
        );
        if down && self.client.enabled && self.client.is_ready(&self.keys) {
            self.start_client();
        }
    }

    /// Restart the running client with the saved settings — or, when they no
    /// longer start (the last destination deleted, a key lost), stop the stale
    /// session rather than leave it running.
    fn restart_client(&mut self) {
        self.notice = None;
        match self.client.start_blocker(&self.keys) {
            None => {
                if let Some(spec) = ClientSpec::resolve(&self.client, &self.keys) {
                    self.controller
                        .restart_client(spec.clone(), self.client.forwards.clone());
                    self.client_applied = Some(spec);
                }
            }
            Some(blocker) => {
                self.controller.stop_client();
                self.notice = Some(blocker);
            }
        }
    }

    /// Enable or disable the client, persisted: enabling starts it — or shows
    /// what it is missing — and disabling stops it and keeps it stopped.
    /// Switching it off and on again is also how a failed client is retried.
    fn set_client_enabled(&mut self, enabled: bool) -> Task<Message> {
        if self.client.enabled != enabled {
            self.client.enabled = enabled;
            self.notice = None;
            self.persist_store();
        }
        if !enabled {
            self.controller.stop_client();
            return Task::none();
        }
        let Some(blocker) = self.client.start_blocker(&self.keys) else {
            self.start_client();
            return Task::none();
        };
        // Show what is missing; with nowhere to go yet, that is a destination
        // (its form open).
        self.close_forms();
        self.selection = Selection::Client;
        if self.client.destinations.is_empty() {
            self.destination_form = Some(DestinationForm::default());
        }
        self.notice = Some(blocker);
        self.show_window()
    }

    fn delete_destination(&mut self, id: DestinationId) {
        if self.confirm_delete.as_deref() != Some(id.as_str()) {
            self.confirm_delete = Some(id);
            return;
        }
        self.confirm_delete = None;
        let Some(pos) = self.client.destinations.iter().position(|d| d.id == id) else {
            return;
        };
        // The referenced auth key stays — it's shared, managed in the Keys
        // pane. So do the forwards: one that pointed here now shows "no route".
        self.client.destinations.remove(pos);
        self.notice = None;
        self.persist_store();
        if self.selection == Selection::Destination(id) {
            self.selection = self
                .client
                .destinations
                .get(pos.min(self.client.destinations.len().saturating_sub(1)))
                .map(|d| Selection::Destination(d.id.clone()))
                .unwrap_or(Selection::Client);
        }
        // The running session still routes to it until it restarts (the
        // panes say so). Without any destination left there is nothing to
        // restart into: stop.
        if self.client.destinations.is_empty() {
            self.controller.stop_client();
        }
    }

    /// Close every form and two-click guard of the detail pane.
    fn close_forms(&mut self) {
        self.destination_form = None;
        self.proxy_form = None;
        self.key_form = None;
        self.server_form = None;
        self.client_form = None;
        self.identity_form = None;
        self.forward_form = None;
        self.confirm_delete = None;
        self.confirm_delete_key = None;
        self.confirm_delete_server = false;
        self.confirm_export_key = None;
        self.confirm_remove_client = None;
        self.confirm_export_server_secret = false;
        self.notice = None;
    }

    /// Show the server pane: with no server yet, its welcome — what a server
    /// is for and how setup goes — whose buttons open the setup form. There
    /// is only one server, so once set up this just selects it.
    fn set_up_server(&mut self) -> Task<Message> {
        // Already showing it (a setup form half filled in, say): left as is.
        if self.selection != Selection::Server || self.destination_form.is_some() {
            self.close_forms();
        }
        self.selection = Selection::Server;
        self.show_window()
    }

    /// Whether the running server was started with other settings than the
    /// saved ones, so a restart is needed to apply them.
    pub fn server_needs_restart(&self) -> bool {
        // A server just disabled is stopping, not waiting for a restart.
        matches!(
            self.server_snapshot.phase,
            ServerPhase::Starting | ServerPhase::Running
        ) && self.server.as_ref().is_some_and(|s| s.enabled)
            && self.server_applied.as_ref() != self.server.as_ref()
    }

    /// Start the server if it is enabled, down, and can start: at launch, and
    /// after a change that may have made it startable — the first client
    /// authorized, a lost identity re-imported. A server still stopping (its
    /// last client just removed) gets the start queued behind the stop.
    fn resume_server(&mut self) {
        let down = matches!(
            self.controller.server_snapshot().phase,
            ServerPhase::Stopped | ServerPhase::Failed | ServerPhase::Stopping
        );
        if down
            && let Some(server) = self
                .server
                .clone()
                .filter(|s| s.enabled && s.is_ready())
        {
            self.controller.start_server(server.clone());
            self.server_applied = Some(server);
        }
    }

    /// Enable or disable the server, persisted: enabling starts it — or shows
    /// what it is missing — and disabling stops it and keeps it stopped.
    /// Switching it off and on again is also how a failed server is retried.
    fn set_server_enabled(&mut self, enabled: bool) -> Task<Message> {
        let Some(server) = &mut self.server else {
            return Task::none();
        };
        if server.enabled != enabled {
            server.enabled = enabled;
            self.notice = None;
            self.persist_store();
        }
        if !enabled {
            self.controller.stop_server();
            return Task::none();
        }
        let Some(server) = self.server.clone() else {
            return Task::none();
        };
        if server.is_ready() {
            self.controller.start_server(server.clone());
            self.server_applied = Some(server);
            return Task::none();
        }
        // Show what is missing: the identity secret was lost from the
        // keychain (the pane offers importing it or a new identity), or no
        // client is authorized yet (its form open).
        self.selection = Selection::Server;
        self.close_forms();
        if !server.secret.is_empty() {
            self.client_form = Some(ClientForm::default());
        }
        self.notice = server.start_blocker().map(String::from);
        self.show_window()
    }

    fn delete_server(&mut self) {
        if !self.confirm_delete_server {
            self.confirm_delete_server = true;
            return;
        }
        self.confirm_delete_server = false;
        if self.server.take().is_none() {
            return;
        }
        self.controller.remove_server();
        self.server_snapshot = ServerSnapshot::default();
        self.server_applied = None;
        self.close_forms();
        if self.log_filter == LogFilter::Server {
            self.log_filter = LogFilter::All;
            self.rebuild_log_text();
        }
        // The sealed blob is rebuilt without the server, so this also erases
        // its identity secret.
        self.persist_store();
        if self.selection == Selection::Server {
            self.selection = if self.client.destinations.is_empty() {
                Selection::Empty
            } else {
                Selection::Client
            };
        }
    }

    /// Save the server form: setup creates the server with the chosen identity
    /// (no tunnel set, relays or clients yet — the tunnel set and relays are
    /// optional and edited any time), the settings form updates it. Either way
    /// a server without clients goes straight on to authorizing the first; it
    /// starts once there is one.
    fn save_server_form(&mut self) {
        let Some(form) = &self.server_form else {
            return;
        };
        let Ok(server) = form.validate(self.server.as_ref()) else {
            return;
        };
        let setting_up = self.server.is_none();
        self.server = Some(server);
        // A save failure's notice wins over the outcome below.
        self.notice = None;
        self.persist_store();
        self.selection = Selection::Server;
        self.server_form = None;
        if self.notice.is_some() {
            return;
        }
        if self.server.as_ref().is_some_and(|s| s.authorized_clients.is_empty()) {
            self.client_form = Some(ClientForm::default());
            self.notice = Some(if setting_up {
                "Server created. Authorize the first client to start it.".into()
            } else {
                "Saved. Authorize a client to start the server.".into()
            });
        } else {
            self.notice = Some("Saved.".into());
        }
    }

    fn save_client_form(&mut self) {
        let (Some(form), Some(server)) = (&self.client_form, &mut self.server) else {
            return;
        };
        let Ok(client) = form.validate(&server.authorized_clients) else {
            return;
        };
        let name = client.name.clone();
        server.authorized_clients.push(client);
        self.client_form = None;
        self.notice = None;
        self.persist_store();
        if self.notice.is_none() {
            self.notice = Some(format!("Authorized \"{name}\"."));
        }
        self.resume_server();
    }

    fn remove_client(&mut self, public_key: String) {
        self.confirm_export_server_secret = false;
        if self.confirm_remove_client.as_deref() != Some(public_key.as_str()) {
            self.confirm_remove_client = Some(public_key);
            return;
        }
        self.confirm_remove_client = None;
        let Some(server) = &mut self.server else {
            return;
        };
        let before = server.authorized_clients.len();
        server.authorized_clients.retain(|c| c.public_key != public_key);
        if server.authorized_clients.len() == before {
            return;
        }
        self.notice = None;
        self.persist_store();
        // A revocation can't wait for a restart: the running server still
        // lets the removed client in. Restart it without the client — which
        // also replaces a restart already in flight — or stop it when no
        // client is left (it starts again once one is added). The supervisor
        // leaves a server that is not running alone.
        if let Some(server) = self.server.clone().filter(|s| s.enabled) {
            if server.is_ready() {
                self.controller.restart_server(server.clone());
                self.server_applied = Some(server);
            } else {
                self.controller.stop_server();
            }
        }
    }

    /// Two-click export: the second click puts the identity secret on the
    /// clipboard, to import on another computer (or into a CLI server's key
    /// file). The clipboard is the export channel on purpose — the secret
    /// never lands in a file or on screen.
    fn export_server_secret(&mut self) {
        self.confirm_remove_client = None;
        if !self.confirm_export_server_secret {
            self.confirm_export_server_secret = true;
            return;
        }
        self.confirm_export_server_secret = false;
        let Some(secret) = self.server.as_ref().map(|s| s.secret.clone()) else {
            return;
        };
        if secret.is_empty() {
            return;
        }
        self.notice = Some(if self.copy_text(secret) {
            "Identity key copied — import it on the other computer, then delete the \
             server here: one identity must run on one server only."
                .into()
        } else {
            "Clipboard unavailable — the identity key was not copied.".into()
        });
    }

    fn save_identity_form(&mut self) {
        let (Some(identity), Some(server)) = (&self.identity_form, &mut self.server) else {
            return;
        };
        let Ok((secret, endpoint_id)) = identity.resolve() else {
            return;
        };
        let changed = endpoint_id != server.endpoint_id;
        server.secret = secret;
        server.endpoint_id = endpoint_id;
        self.identity_form = None;
        self.notice = None;
        self.persist_store();
        if self.notice.is_none() {
            self.notice = Some(if changed {
                "New identity saved — every client must switch to the new endpoint id.".into()
            } else {
                "Identity key restored.".into()
            });
        }
        // A re-imported identity makes a stopped server startable again.
        self.resume_server();
    }

    fn handle_menu_event(&mut self, id: &str) -> Task<Message> {
        match id {
            tray::MENU_OPEN => self.show_window(),
            tray::MENU_QUIT => {
                self.controller.shutdown();
                iced::exit()
            }
            tray::MENU_TOGGLE_CLIENT => self.set_client_enabled(!self.client.enabled),
            tray::MENU_TOGGLE_SERVER => match &self.server {
                Some(server) => self.set_server_enabled(!server.enabled),
                None => Task::none(),
            },
            tray::MENU_SET_UP_SERVER => self.set_up_server(),
            tray::MENU_COPY_SERVER_ID => {
                if let Some(endpoint_id) = self.server.as_ref().map(|s| s.endpoint_id.clone()) {
                    self.copy_text(endpoint_id);
                }
                Task::none()
            }
            tray::MENU_LAUNCH_AT_LOGIN => {
                // The dev store's checkbox is disabled; this is the backstop.
                if config::dev_store() {
                    log::warn!("Dev store: ignoring the start-at-login toggle");
                    return Task::none();
                }
                let enable = !self.launch_at_login;
                if let Err(e) = autostart::set_enabled(enable) {
                    let verb = if enable { "enable" } else { "disable" };
                    log::error!("Failed to {verb} start at login: {e:#}");
                }
                self.sync_launch_at_login(true);
                Task::none()
            }
            _ => Task::none(),
        }
    }

    /// Poll the session snapshots and derived state; runs on every tick and
    /// after the tray is created.
    fn refresh(&mut self) {
        self.client_snapshot = self.controller.client_snapshot();
        self.server_snapshot = self.controller.server_snapshot();
        self.sync_launch_at_login(false);

        // Runs every tick so a forward whose setup failed snaps back to
        // stopped promptly.
        let failed =
            disable_failed_forwards(&mut self.client.forwards, &self.client_snapshot.forwards);
        if !failed.is_empty() {
            self.forward_errors.extend(failed);
            self.controller.set_forwards(self.client.forwards.clone());
            self.persist_store();
        }
        view::refresh_routed_cache(&mut self.routed_cache, &self.client);

        let revision = logging::revision();
        if revision != self.log_revision {
            self.log_revision = revision;
            self.rebuild_log_text();
        }

        if let Some(tray) = &mut self.tray {
            tray.sync(
                &self.client,
                &self.client_snapshot,
                self.server.as_ref(),
                &self.server_snapshot,
            );
        }
    }

    fn save_destination_form(&mut self) {
        let Some(form) = &self.destination_form else {
            return;
        };
        let Ok(destination) = form.validate(&self.client.destinations, &self.keys) else {
            return;
        };
        let id = destination.id.clone();
        match self.client.destinations.iter_mut().find(|d| d.id == id) {
            Some(slot) => *slot = destination,
            None => self.client.destinations.push(destination),
        }
        // A save failure's notice wins over the outcome below.
        self.notice = None;
        self.persist_store();
        self.selection = Selection::Destination(id);
        self.destination_form = None;
        // The first destination is what an enabled client was waiting for.
        self.resume_client();
        if self.notice.is_none() {
            self.notice = self.saved_notice();
        }
    }

    /// Whether a save just now left a running client on the settings from
    /// before. Asks the controller rather than the polled snapshot, which a
    /// start made a moment ago has not reached yet.
    fn restart_pending(&self) -> bool {
        matches!(
            self.controller.client_snapshot().phase,
            ClientPhase::Starting | ClientPhase::Running
        ) && self.client.enabled
            && self.client_applied != ClientSpec::resolve(&self.client, &self.keys)
    }

    /// The notice for a save on a pane that shows the restart banner: "Saved."
    /// unless that banner is about to say more.
    fn saved_notice(&self) -> Option<String> {
        (!self.restart_pending()).then(|| "Saved.".into())
    }

    fn save_proxy_form(&mut self) {
        let Some(form) = &self.proxy_form else {
            return;
        };
        let Ok((socks_port, http_port)) = form.validate(&self.client) else {
            return;
        };
        self.client.socks_port = socks_port;
        self.client.http_port = http_port;
        self.proxy_form = None;
        self.notice = None;
        self.persist_store();
        // A taken port is what a failed client was waiting to have changed.
        self.resume_client();
        if self.notice.is_none() {
            self.notice = self.saved_notice();
        }
    }

    /// The destination form's "New key" prompt: generate a keypair under the
    /// entered name, add it to the shared list, and select it in the form.
    /// (Cancelling the destination form afterwards keeps the key — it's in
    /// the list, deletable from the Keys pane.)
    fn create_key_for_destination_form(&mut self) {
        let Some(name) = self.destination_form.as_ref().and_then(|f| f.new_key_name.clone()) else {
            return;
        };
        // The view disables Create on an invalid name; this is the backstop.
        let Ok(name) = validate_key_name(&name, &self.keys, None) else {
            return;
        };
        let client_key = flextunnel_core::auth::ClientKey::generate().expect("system RNG unavailable");
        let key = AuthKey {
            id: AuthKey::new_id(),
            name,
            public_key: client_key.public_str(),
            secret: client_key.secret_str(),
        };
        let id = key.id.clone();
        self.keys.push(key);
        self.persist_store();
        if let Some(form) = &mut self.destination_form {
            form.auth_key_id = id;
            form.new_key_name = None;
        }
    }

    fn save_key_form(&mut self) {
        let Some(form) = &self.key_form else {
            return;
        };
        let Ok(key) = form.validate(&self.keys) else {
            return;
        };
        match self.keys.iter_mut().find(|k| k.id == key.id) {
            Some(slot) => *slot = key,
            None => self.keys.push(key),
        }
        self.notice = None;
        self.persist_store();
        self.key_form = None;
        // A re-entered secret is what a client blocked on it was waiting for;
        // a running one takes an edited secret on its next restart, offered
        // on the client's pane — this one has no banner to say so.
        self.resume_client();
        if self.notice.is_none() {
            self.notice = Some(if self.restart_pending() {
                "Saved — restart the client (under Proxy & forwards) to apply.".into()
            } else {
                "Saved.".into()
            });
        }
    }

    fn delete_key(&mut self, id: String) {
        self.confirm_export_key = None;
        // Shared keys never delete out from under a destination; repoint or
        // delete the destinations first.
        if let Some(user) = self.client.destinations.iter().find(|d| d.auth_key_id == id) {
            self.notice = Some(format!(
                "This key is used by destination \"{}\" — repoint or delete that destination \
                 first.",
                user.host
            ));
            self.confirm_delete_key = None;
            return;
        }
        if self.confirm_delete_key.as_deref() != Some(id.as_str()) {
            self.confirm_delete_key = Some(id);
            return;
        }
        self.confirm_delete_key = None;
        self.keys.retain(|k| k.id != id);
        self.key_form = None;
        // The sealed blob is rebuilt from the retained keys, so this also
        // erases the deleted key's secret.
        self.persist_store();
    }

    /// Two-click export: the second click puts the key's secret on the
    /// clipboard, ready to paste into another install's key form (or the iOS
    /// app's key import). The clipboard is the export channel on purpose —
    /// no secret ever lands in a file.
    fn export_key(&mut self, id: String) {
        self.confirm_delete_key = None;
        if self.confirm_export_key.as_deref() != Some(id.as_str()) {
            self.confirm_export_key = Some(id);
            return;
        }
        self.confirm_export_key = None;
        // The view never offers export for a secretless key, but the list can
        // change between the two clicks.
        let Some(key) = config::find_key(&self.keys, &id).filter(|k| !k.secret.is_empty()) else {
            return;
        };
        let (name, secret) = (key.name.clone(), key.secret.clone());
        // Announce "copied" only when the clipboard write actually took —
        // a false success here would have the user paste nothing elsewhere.
        self.notice = Some(if self.copy_text(secret) {
            format!("Secret key of \"{name}\" copied — paste it into the key form of another install.")
        } else {
            "Clipboard unavailable — the secret key was not copied.".into()
        });
    }

    fn save_forward_form(&mut self) {
        let Some(form) = &self.forward_form else {
            return;
        };
        let Ok(saved) = form.validate(&self.client) else {
            return;
        };
        if saved.enabled {
            // The edit may fix what failed (e.g. a new local port); the fresh
            // start attempt supersedes the old failure.
            self.forward_errors.remove(&saved.id);
        }
        match self.client.forwards.iter_mut().find(|f| f.id == saved.id) {
            Some(slot) => *slot = saved,
            None => self.client.forwards.push(saved),
        }
        self.commit_forwards();
        self.forward_form = None;
    }

    /// Persist the forwards and push them to the client session (live apply).
    fn commit_forwards(&mut self) {
        self.persist_store();
        self.controller.set_forwards(self.client.forwards.clone());
    }

    fn import_client(&mut self, path: &std::path::Path) {
        let merged = config::import_client(path)
            .map_err(|e| format!("{e:#}"))
            .and_then(|imported| merge_imported(&self.client, imported));
        let (client, summary) = match merged {
            Ok(merged) => merged,
            Err(e) => {
                log::error!("Import failed: {e}");
                self.io_notice = Some(format!("Import failed: {e}"));
                return;
            }
        };
        self.client = client;
        // A replaced forward comes back stopped, like any fresh load; the
        // session (if live) reconciles to the merged list.
        for id in &summary.forwards_replaced {
            self.forward_errors.remove(id);
        }
        self.close_forms();
        self.persist_store();
        self.controller.set_forwards(self.client.forwards.clone());
        self.io_notice = Some(summary.to_string());
        // Added destinations still need an auth key picked, which the client
        // pane says; land there unless something that still exists is shown.
        let shown = match &self.selection {
            Selection::Destination(id) => self.client.destination(id).is_some(),
            Selection::Empty => false,
            _ => true,
        };
        if !shown {
            self.selection = Selection::Client;
        }
        self.resume_client();
    }

    /// Re-join the log ring for the Logs pane, keeping only the client's or
    /// the server's session-thread lines (`[client]` / `[server]`) when a
    /// filter is on.
    fn rebuild_log_text(&mut self) {
        let lines = logging::recent_lines();
        let tag = match &self.log_filter {
            LogFilter::All => None,
            LogFilter::Client => Some(format!("[{CLIENT_THREAD_NAME}]")),
            LogFilter::Server => Some(format!("[{}]", server_session::THREAD_NAME)),
        };
        self.log_text = match tag {
            Some(tag) => {
                lines
                    .iter()
                    .filter(|line| line.contains(&tag))
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join("\n")
            }
            None => lines.join("\n"),
        };
    }

    /// Re-read the login-item registration and push it to the tray checkbox
    /// when it changed — or unconditionally (`force`) after a toggle attempt,
    /// since the native checkbox flips on click even when the toggle failed.
    fn sync_launch_at_login(&mut self, force: bool) {
        let enabled = autostart::is_enabled();
        let changed = enabled != self.launch_at_login;
        self.launch_at_login = enabled;
        if (changed || force) && let Some(tray) = &self.tray {
            tray.set_launch_at_login(enabled);
        }
    }

    fn persist_store(&mut self) {
        // Backstop: the reset modal blocks the window, but nothing may write
        // over what is on disk before the user chooses to.
        if self.store_reset.is_some() {
            log::warn!("Not saving: the store reset is not confirmed yet");
            return;
        }
        if let Err(e) = config::save_store(
            &self.keys,
            &self.client,
            self.server.as_ref(),
            self.login_item_set_up,
        ) {
            log::error!("Failed to save the settings: {e:#}");
            self.notice = Some(format!("Failed to save the settings: {e:#}"));
        }
    }

    /// Copy `text` to the clipboard; false (with a log) when the clipboard is
    /// unavailable or rejects the write.
    fn copy_text(&mut self, text: String) -> bool {
        if self.clipboard.is_none() {
            match arboard::Clipboard::new() {
                Ok(clipboard) => self.clipboard = Some(clipboard),
                Err(e) => {
                    log::error!("Clipboard unavailable: {e}");
                    return false;
                }
            }
        }
        let Some(clipboard) = &mut self.clipboard else {
            return false;
        };
        match clipboard.set_text(text) {
            Ok(()) => true,
            Err(e) => {
                log::error!("Failed to copy to the clipboard: {e}");
                false
            }
        }
    }
}

/// Forward tray/menu events into the runtime. The handlers replace tray-icon's
/// default channel delivery; sending through the subscription channel wakes
/// the event loop even while no window exists. Runs (and installs the
/// handlers) once for the daemon's lifetime.
fn tray_events() -> impl Stream<Item = Message> {
    iced::stream::channel(32, async move |mut output| {
        use iced::futures::channel::mpsc;
        use iced::futures::{SinkExt, StreamExt};

        let (tx, mut rx) = mpsc::unbounded();
        let menu_tx = tx.clone();
        MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
            let _ = menu_tx.unbounded_send(Message::TrayMenu(event.id().as_ref().to_owned()));
        }));
        TrayIconEvent::set_event_handler(Some(move |event: TrayIconEvent| {
            let _ = tx.unbounded_send(Message::TrayIcon(event));
        }));
        while let Some(message) = rx.next().await {
            if output.send(message).await.is_err() {
                return;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> Vec<AuthKey> {
        vec![AuthKey {
            id: "k1".into(),
            name: "work laptop".into(),
            public_key: "ed25519-pub:abc".into(),
            secret: "ed25519-sec:xyz".into(),
        }]
    }

    fn valid_form() -> DestinationForm {
        DestinationForm {
            editing_id: None,
            host: " Prod.Internal ".into(),
            server_node_id: " node-id ".into(),
            routed_domains: " *.corp.example ,, db.internal ".into(),
            routed_cidrs: " 10.0.0.0/8 ".into(),
            auth_key_id: "k1".into(),
            new_key_name: None,
            relay_urls: " https://a.example ,, https://b.example ".into(),
            relay_auth_token: String::new(),
        }
    }

    fn valid_forward_form() -> ForwardForm {
        ForwardForm {
            editing_id: None,
            label: "  db  ".into(),
            local_port: "5432".into(),
            remote_host: " db.internal ".into(),
            remote_port: "5432".into(),
            enabled: true,
        }
    }

    fn existing_forward(id: &str, local_port: u16) -> PortForward {
        PortForward {
            id: id.into(),
            label: String::new(),
            local_port,
            remote_host: "other.internal".into(),
            remote_port: 80,
            enabled: true,
        }
    }

    /// A destination `<id>.internal` on server `node-<id>`, with no routes.
    fn existing_destination(id: &str) -> Destination {
        Destination {
            id: id.into(),
            host: format!("{id}.internal"),
            server_node_id: format!("node-{id}"),
            routed_domains: Vec::new(),
            routed_cidrs: Vec::new(),
            auth_key_id: "k1".into(),
            relay_urls: Vec::new(),
            relay_auth_token: None,
        }
    }

    fn client(socks_port: u16, forwards: Vec<PortForward>) -> ClientSettings {
        ClientSettings {
            enabled: true,
            socks_port: Some(socks_port),
            http_port: None,
            destinations: vec![existing_destination("p1")],
            forwards,
        }
    }

    #[test]
    fn forward_form_trims_and_builds() {
        let forward = valid_forward_form().validate(&client(1080, vec![])).expect("valid");
        assert_eq!(forward.label, "db");
        assert_eq!(forward.local_port, 5432);
        assert_eq!(forward.remote_host, "db.internal");
        assert_eq!(forward.remote_port, 5432);
        assert!(forward.enabled);
        assert!(!forward.id.is_empty());
    }

    #[test]
    fn forward_form_rejects_bad_input() {
        let base = client(1080, vec![]);

        let mut form = valid_forward_form();
        form.local_port = "0".into();
        assert!(form.validate(&base).is_err());

        let mut form = valid_forward_form();
        form.remote_host = "  ".into();
        assert!(form.validate(&base).is_err());

        let mut form = valid_forward_form();
        form.remote_host = "networking..internal".into();
        assert!(form.validate(&base).is_err());

        let mut form = valid_forward_form();
        form.label = "x".repeat(65);
        assert!(form.validate(&base).is_err());

        let mut form = valid_forward_form();
        form.remote_port = "70000".into();
        assert!(form.validate(&base).is_err());

        // Collisions with the client's proxy ports.
        let form = valid_forward_form();
        assert!(form.validate(&client(5432, vec![])).unwrap_err().contains("SOCKS5 proxy"));
        let mut http = client(1080, vec![]);
        http.http_port = Some(5432);
        assert!(form.validate(&http).unwrap_err().contains("HTTP proxy"));

        // Duplicate local port among the forwards…
        let taken = client(1080, vec![existing_forward("aaaa", 5432)]);
        assert!(form.validate(&taken).is_err());

        // …unless it is the forward being edited (id reused).
        let mut form = valid_forward_form();
        form.editing_id = Some("aaaa".into());
        let edited = form.validate(&taken).expect("editing the same forward");
        assert_eq!(edited.id, "aaaa");
    }

    #[test]
    fn proxy_ports_share_one_namespace_with_the_forwards() {
        let current = client(1080, vec![existing_forward("f1", 5000)]);
        let form = |socks: Option<&str>, http: Option<&str>| ProxyForm {
            socks_enabled: socks.is_some(),
            socks_port: socks.unwrap_or_default().into(),
            http_enabled: http.is_some(),
            http_port: http.unwrap_or_default().into(),
        };
        // The form opens on what is saved, with a suggestion for what is off.
        let open = ProxyForm::edit(&current);
        assert!(open.socks_enabled && !open.http_enabled);
        assert_eq!((open.socks_port.as_str(), open.http_port.as_str()), ("1080", "18080"));
        // The client's own current port is not a clash with itself.
        assert_eq!(open.validate(&current), Ok((Some(1080), None)));

        assert_eq!(form(Some("1081"), Some("8081")).validate(&current), Ok((Some(1081), Some(8081))));
        assert_eq!(form(None, None).validate(&current), Ok((None, None)), "forwards only");
        assert!(form(Some("0"), None).validate(&current).is_err());
        assert!(form(Some("1081"), Some("1081")).validate(&current).is_err(), "same port twice");
        // A forward's local port, as SOCKS or HTTP.
        assert!(form(Some("5000"), None).validate(&current).unwrap_err().contains("forward"));
        assert!(form(Some("1081"), Some("5000")).validate(&current).is_err());
        // A switched-off front-end's port buffer is not looked at.
        let mut off = form(None, None);
        off.socks_port = "garbage".into();
        assert!(off.validate(&current).is_ok());
    }

    #[test]
    fn import_merges_destinations_by_server_and_forwards_by_port() {
        // "p1.internal" (with a key and a relay token) and "p2.internal", one
        // forward on 5000, SOCKS on 1080.
        let mut current = client(1080, vec![existing_forward("f1", 5000)]);
        current.destinations.push(existing_destination("p2"));
        current.destinations[0].auth_key_id = "key-ref".into();
        current.destinations[0].relay_auth_token = Some("relay-psk".into());
        current.forwards[0].enabled = true;

        // Same server as p1: replaces its settings, keeps id + key + token. A
        // relay token on an incoming entry is never trusted (imports strip
        // it); pretend a hand-edited one slipped through to prove that.
        let mut same_server = existing_destination("x");
        same_server.server_node_id = "node-p1".into();
        same_server.host = "renamed.internal".into();
        same_server.routed_domains = vec!["*.corp.example".into()];
        same_server.relay_auth_token = Some("imported-psk".into());
        let mut new_server = existing_destination("y");
        new_server.relay_auth_token = Some("imported-psk".into());

        let mut replacing = existing_forward("f2", 5000);
        replacing.remote_host = "renamed.internal".into();
        replacing.enabled = true;
        let imported = Portable {
            destinations: vec![same_server, new_server],
            forwards: vec![replacing, existing_forward("f3", 6000), existing_forward("f4", 1080)],
        };

        let (merged, summary) = merge_imported(&current, imported).expect("fits");
        assert_eq!(
            summary,
            ImportSummary {
                destinations_added: 1,
                destinations_replaced: 1,
                forwards_added: 1,
                forwards_replaced: vec!["f1".to_string()],
                forwards_skipped: 1,
            }
        );
        assert_eq!(
            summary.to_string(),
            "Imported: 1 destination(s) added, 1 replaced; 1 forward(s) added, 1 replaced; \
             1 skipped (local port used by a proxy here)."
        );

        let p1 = &merged.destinations[0];
        assert_eq!(p1.id, "p1", "id kept");
        assert_eq!(p1.auth_key_id, "key-ref", "key reference kept");
        assert_eq!(
            p1.relay_auth_token.as_deref(),
            Some("relay-psk"),
            "existing relay token kept, not overwritten by the import"
        );
        assert_eq!(p1.host, "renamed.internal");
        assert_eq!(p1.routed_domains, ["*.corp.example"]);
        assert_eq!(merged.destinations[1], current.destinations[1], "untouched");

        let new = &merged.destinations[2];
        assert_eq!(new.host, "y.internal");
        assert!(new.auth_key_id.is_empty(), "no key reference in imports");
        assert_eq!(new.relay_auth_token, None, "no relay secret in imports");
        assert_ne!(new.id, "y", "imported destination ids are fresh");

        // The proxy ports are this computer's own; forwards come back stopped.
        assert_eq!((merged.socks_port, merged.http_port), (Some(1080), None));
        assert_eq!(merged.forwards.len(), 2);
        assert_eq!(merged.forwards[0].id, "f1", "a replaced forward keeps its id");
        assert_eq!(merged.forwards[0].remote_host, "renamed.internal");
        assert!(!merged.forwards[0].enabled);
        assert_eq!(merged.forwards[1].local_port, 6000);
        assert_ne!(merged.forwards[1].id, "f3", "imported forward ids are fresh");
    }

    /// Imported destinations must fit the ones already here: a host or a
    /// route claimed twice rejects the import whole.
    #[test]
    fn an_import_that_breaks_the_routing_changes_nothing() {
        let mut current = client(1080, vec![]);
        current.destinations[0].routed_domains = vec!["*.corp.example".into()];

        // Another server under a host already taken.
        let mut same_host = existing_destination("z");
        same_host.host = "p1.internal".into();
        let clash = Portable { destinations: vec![same_host], forwards: Vec::new() };
        assert!(merge_imported(&current, clash).unwrap_err().contains("more than once"));

        // Another server claiming a rule already routed.
        let mut same_rule = existing_destination("z");
        same_rule.routed_domains = vec!["*.corp.example".into()];
        let clash = Portable {
            destinations: vec![existing_destination("ok"), same_rule],
            forwards: vec![existing_forward("f", 6000)],
        };
        assert!(merge_imported(&current, clash).unwrap_err().contains("both route"));

        // Nothing to import is fine, and changes nothing.
        let (merged, summary) = merge_imported(&current, Portable::default()).unwrap();
        assert_eq!(merged, current);
        assert_eq!(summary, ImportSummary::default());
        assert!(summary.to_string().ends_with("0 replaced."));
    }

    #[test]
    fn validate_trims_and_parses() {
        let destination = valid_form().validate(&[], &test_keys()).expect("valid");
        assert_eq!(destination.server_node_id, "node-id");
        assert_eq!(destination.host, "prod.internal", "stored trimmed and lowercased");
        assert_eq!(destination.routed_domains, ["*.corp.example", "db.internal"]);
        assert_eq!(destination.routed_cidrs, ["10.0.0.0/8"]);
        assert_eq!(destination.auth_key_id, "k1");
        assert_eq!(
            destination.relay_urls,
            vec!["https://a.example".to_string(), "https://b.example".to_string()]
        );
        assert_eq!(destination.relay_auth_token, None);
        assert!(!destination.id.is_empty());

        // Editing keeps the id and reads back what was saved.
        let form = DestinationForm::edit(&destination);
        assert!(form.is_edit());
        assert_eq!(form.routed_domains, "*.corp.example, db.internal");
        let again = form.validate(std::slice::from_ref(&destination), &test_keys()).unwrap();
        assert_eq!(again, destination);
    }

    #[test]
    fn validate_rejects_bad_input() {
        let keys = test_keys();

        // No key picked, and a reference to a key that doesn't exist.
        let mut form = valid_form();
        form.auth_key_id = String::new();
        assert!(form.validate(&[], &keys).is_err());
        form.auth_key_id = "missing".into();
        assert!(form.validate(&[], &keys).is_err());

        let mut form = valid_form();
        form.server_node_id = "  ".into();
        assert!(form.validate(&[], &keys).is_err());

        // The host is required and must be a name the core accepts; the
        // routes must parse and must not contradict it.
        for host in ["  ", "10.0.0.1", "localhost", "flextunnel.internal", "bad..host"] {
            let mut form = valid_form();
            form.host = host.into();
            assert!(form.validate(&[], &keys).is_err(), "host {host:?}");
        }
        let mut form = valid_form();
        form.routed_domains = "*.*.example".into();
        assert!(form.validate(&[], &keys).is_err());
        let mut form = valid_form();
        form.routed_cidrs = "not-a-cidr".into();
        assert!(form.validate(&[], &keys).is_err());
        let mut form = valid_form();
        form.routed_domains = "prod.internal".into();
        assert!(form.validate(&[], &keys).unwrap_err().contains("own host"));
        // No extra routes at all is fine: the host alone reaches the server.
        let mut form = valid_form();
        form.routed_domains = String::new();
        form.routed_cidrs = String::new();
        assert!(form.validate(&[], &keys).is_ok());

        // The core's relay rules: custom relays come in pairs at least, and a
        // token needs them.
        let mut form = valid_form();
        form.relay_urls = "https://only.example".into();
        assert!(form.validate(&[], &keys).is_err(), "a single custom relay");
        let mut form = valid_form();
        form.relay_urls = String::new();
        assert!(form.validate(&[], &keys).is_ok(), "the default relays");
        form.relay_auth_token = "psk".into();
        assert!(form.validate(&[], &keys).is_err(), "token without relays");
    }

    /// A destination is checked against the others, with the core's own
    /// table: one host, one server and one owner per rule.
    #[test]
    fn destinations_must_fit_together() {
        let keys = test_keys();
        let mut existing = existing_destination("p1");
        existing.routed_domains = vec!["*.corp.example".into()];
        existing.routed_cidrs = vec!["10.0.0.0/8".into()];
        let existing = [existing];
        let fresh = || DestinationForm {
            routed_domains: String::new(),
            routed_cidrs: String::new(),
            ..valid_form()
        };
        assert!(fresh().validate(&existing, &keys).is_ok());

        // Another destination's host…
        let mut form = fresh();
        form.host = " P1.internal ".into();
        assert!(form.validate(&existing, &keys).unwrap_err().contains("more than once"));
        // …or its server…
        let mut form = fresh();
        form.server_node_id = "node-p1".into();
        let err = form.validate(&existing, &keys).unwrap_err();
        assert!(err.contains("\"p1.internal\" already reaches this server"), "{err}");
        // …or one of its rules, or its host as a routed domain.
        let mut form = fresh();
        form.routed_cidrs = "10.0.0.0/8".into();
        assert!(form.validate(&existing, &keys).unwrap_err().contains("both route"));
        let mut form = fresh();
        form.routed_domains = "p1.internal".into();
        assert!(form.validate(&existing, &keys).unwrap_err().contains("own host"));
        // A narrower rule inside another destination's is fine: it wins.
        let mut form = fresh();
        form.routed_domains = "db.corp.example".into();
        form.routed_cidrs = "10.1.0.0/16".into();
        assert!(form.validate(&existing, &keys).is_ok());

        // None of it applies to the destination being edited itself.
        let mut form = DestinationForm::edit(&existing[0]);
        form.routed_domains = "*.corp.example, extra.example".into();
        let edited = form.validate(&existing, &keys).expect("own host, server and rules");
        assert_eq!(edited.id, "p1");
    }

    #[test]
    fn key_form_validates() {
        let keys = test_keys();
        let secret = flextunnel_core::auth::ClientKey::generate().expect("system RNG unavailable").secret_str();

        let form = KeyForm {
            editing_id: None,
            name: "  home   nas ".into(),
            secret: format!(" {secret} "),
        };
        let key = form.validate(&keys).expect("valid");
        assert_eq!(key.name, "home nas");
        assert_eq!(key.secret, secret);
        assert!(!key.id.is_empty());
        assert_eq!(
            Some(key.public_key.clone()),
            form.public_key(),
            "stored public key matches the derived one"
        );

        // Empty name, empty secret, unparsable secret.
        let mut bad = KeyForm {
            editing_id: None,
            name: String::new(),
            secret: secret.clone(),
        };
        assert!(bad.validate(&keys).is_err());
        bad.name = "ok".into();
        bad.secret = String::new();
        assert!(bad.validate(&keys).is_err());
        bad.secret = "not-a-key".into();
        assert!(bad.validate(&keys).is_err());

        // Duplicate name…
        let mut dup = KeyForm {
            editing_id: None,
            name: "work laptop".into(),
            secret: secret.clone(),
        };
        assert!(dup.validate(&keys).is_err());
        // …unless it is the key being edited.
        dup.editing_id = Some("k1".into());
        let edited = dup.validate(&keys).expect("editing the same key");
        assert_eq!(edited.id, "k1");

        // The same keypair under a second name is an accidental re-add.
        let mut existing_pair = keys.clone();
        existing_pair.push(KeyForm {
            editing_id: None,
            name: "first".into(),
            secret: secret.clone(),
        }
        .validate(&keys)
        .unwrap());
        let readd = KeyForm {
            editing_id: None,
            name: "second".into(),
            secret,
        };
        assert!(readd.validate(&existing_pair).is_err());
    }

    fn valid_server_form() -> ServerForm {
        ServerForm {
            routed_domains: " *.internal ,, example.com ".into(),
            routed_cidrs: "10.0.0.0/8".into(),
            ..ServerForm::add()
        }
    }

    fn client_key() -> String {
        flextunnel_core::auth::ClientKey::generate().unwrap().public_str()
    }

    #[test]
    fn server_setup_generates_an_identity_and_starts_without_clients() {
        let form = valid_server_form();
        let server = form.validate(None).expect("valid");
        let (secret, endpoint_id) = form.identity.as_ref().unwrap().resolve().unwrap();
        assert_eq!((server.secret, server.endpoint_id), (secret, endpoint_id));
        assert_eq!(server.routed_domains, ["*.internal", "example.com"]);
        assert_eq!(server.routed_cidrs, ["10.0.0.0/8"]);
        assert!(server.authorized_clients.is_empty(), "clients come after setup");
        assert_ne!(
            ServerForm::add().validate(None).unwrap().endpoint_id,
            ServerForm::add().validate(None).unwrap().endpoint_id,
            "every setup generates its own identity"
        );
    }

    #[test]
    fn server_setup_regenerates_its_identity() {
        let mut identity = IdentityChoice::new();
        let (_, before) = identity.resolve().unwrap();
        identity.regenerate();
        let (_, after) = identity.resolve().unwrap();
        assert_ne!(before, after, "a regenerated identity gives a new endpoint id");
    }

    #[test]
    fn server_setup_imports_an_existing_identity() {
        let existing = valid_server_form().validate(None).unwrap();
        let mut form = valid_server_form();
        let identity = form.identity.as_mut().unwrap();
        identity.import = Some(String::new());
        assert!(form.validate(None).is_err(), "nothing pasted yet");
        form.identity.as_mut().unwrap().import = Some(format!(" {} ", existing.secret));
        let imported = form.validate(None).expect("valid");
        assert_eq!(imported.endpoint_id, existing.endpoint_id);
        assert_eq!(imported.secret, existing.secret);
        form.identity.as_mut().unwrap().import = Some("not base64!".into());
        assert!(form.validate(None).is_err());
    }

    #[test]
    fn server_settings_keep_the_identity_and_clients() {
        let mut current = valid_server_form().validate(None).unwrap();
        current.authorized_clients.push(AuthorizedClient {
            name: "laptop".into(),
            public_key: client_key(),
        });
        let mut form = ServerForm::edit(&current);
        assert!(form.identity.is_none());
        form.routed_domains = String::new();
        form.routed_cidrs = " , ".into();
        let edited = form.validate(Some(&current)).expect("an empty tunnel set is fine");
        assert!(edited.routed_domains.is_empty() && edited.routed_cidrs.is_empty());
        assert_eq!(edited.secret, current.secret);
        assert_eq!(edited.authorized_clients, current.authorized_clients);
        assert!(form.validate(None).is_err(), "server deleted meanwhile");
    }

    #[test]
    fn server_form_rejects_bad_input() {
        let mut form = valid_server_form();
        form.routed_cidrs = "10.0.0.0/33".into();
        assert!(form.validate(None).is_err(), "bad CIDR");

        let mut form = valid_server_form();
        form.relay_auth_token = "psk".into();
        assert!(form.validate(None).is_err(), "token without relays");
    }

    #[test]
    fn client_form_validates() {
        let key = client_key();
        let form = ClientForm {
            name: "  work   laptop ".into(),
            public_key: format!(" {key} "),
        };
        let client = form.validate(&[]).expect("valid");
        assert_eq!(client.name, "work laptop");
        assert_eq!(client.public_key, key);

        assert!(ClientForm { name: " ".into(), ..ClientForm::default() }.validate(&[]).is_err());
        let no_key = ClientForm { name: "phone".into(), public_key: String::new() };
        assert!(no_key.validate(&[]).is_err());
        let bad_key = ClientForm { name: "phone".into(), public_key: "ed25519-pub:nope".into() };
        assert!(bad_key.validate(&[]).is_err());

        let existing = [client];
        let same_name = ClientForm { name: "work laptop".into(), public_key: client_key() };
        assert!(same_name.validate(&existing).is_err(), "duplicate name");
        let same_key = ClientForm { name: "phone".into(), public_key: key.clone() };
        assert!(same_key.validate(&existing).is_err(), "duplicate key");
    }

    #[test]
    fn pasting_an_authorized_key_entry_names_the_client() {
        let key = client_key();
        let mut form = ClientForm::default();
        form.set_public_key(format!(" {key}  alice   laptop "));
        assert_eq!((form.name.as_str(), form.public_key.as_str()), ("alice laptop", key.as_str()));

        // A name already typed wins over the comment.
        let mut named = ClientForm { name: "phone".into(), ..ClientForm::default() };
        named.set_public_key(format!("{key} alice laptop"));
        assert_eq!((named.name.as_str(), named.public_key.as_str()), ("phone", key.as_str()));
        assert!(named.validate(&[]).is_ok());
    }
}
