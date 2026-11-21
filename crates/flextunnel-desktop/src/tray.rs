//! System tray icon + menu: the client's status line and its Enable/Disable
//! once it has destinations (they are managed in the window, not listed here),
//! then the server's status line and controls (Enable/Disable, Copy Endpoint
//! ID — or "Set Up Server…" while there is none), then the "start at login"
//! checkbox (see `autostart`). The icon's badge is the server's (see
//! [`tray_state`]). Created and mutated only on the main thread (from the iced
//! update loop); the tray-icon event handlers installed by the tray
//! subscription merely forward events and wake the runtime, since they may
//! fire off the main thread.

use crate::config::{self, ClientSettings, ServerConfig};
use crate::icon::{self, TrayState};
use crate::server_session::{ServerPhase, ServerSnapshot};
use crate::tunnel::{ClientPhase, ClientSnapshot};
use anyhow::Result;
use flextunnel_core::proxy::DestinationState;
use tray_icon::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem};
use tray_icon::{TrayIcon, TrayIconBuilder};

pub const MENU_OPEN: &str = "open";
pub const MENU_QUIT: &str = "quit";
/// Enable or Disable, by whether the client is enabled (see [`client_toggle`]).
pub const MENU_TOGGLE_CLIENT: &str = "toggle-client";
/// Enable or Disable, by whether the server is enabled (see [`server_toggle`]).
pub const MENU_TOGGLE_SERVER: &str = "toggle-server";
pub const MENU_COPY_SERVER_ID: &str = "copy-server-id";
pub const MENU_SET_UP_SERVER: &str = "set-up-server";
pub const MENU_LAUNCH_AT_LOGIN: &str = "launch-at-login";

/// The login-item checkbox, in each platform's own words for the feature.
#[cfg(target_os = "macos")]
const LAUNCH_AT_LOGIN_LABEL: &str = "Open at Login";
#[cfg(windows)]
const LAUNCH_AT_LOGIN_LABEL: &str = "Start with Windows";

/// "N clients connected", for the tray and the window alike.
pub fn clients_connected(count: usize) -> String {
    match count {
        0 => "no clients connected".into(),
        1 => "1 client connected".into(),
        n => format!("{n} clients connected"),
    }
}

/// The server's status line (or that there is none).
fn server_line(server: Option<(&ServerConfig, &ServerSnapshot)>) -> String {
    let Some((server, snapshot)) = server else {
        return "No server set up".into();
    };
    match snapshot.phase {
        ServerPhase::Stopped if !server.enabled => "Server disabled".into(),
        ServerPhase::Running => format!(
            "Server running · {}",
            clients_connected(snapshot.connected_clients.len())
        ),
        ServerPhase::Starting => "Server starting…".into(),
        ServerPhase::Stopping => "Server stopping…".into(),
        ServerPhase::Failed => "Server failed to start".into(),
        ServerPhase::Stopped if server.authorized_clients.is_empty() => {
            "Server stopped · no clients authorized".into()
        }
        ServerPhase::Stopped => "Server stopped".into(),
    }
}

/// The server toggle's label and whether it is clickable: Disable while
/// enabled, Enable while disabled — not while the server is still stopping.
fn server_toggle(server: &ServerConfig, phase: ServerPhase) -> (&'static str, bool) {
    let label = if server.enabled { "Disable Server" } else { "Enable Server" };
    (label, phase != ServerPhase::Stopping)
}

/// The client's status line; `None` while it has no destinations (the menu
/// then leaves the client out).
fn client_line(client: &ClientSettings, snapshot: &ClientSnapshot) -> Option<String> {
    if client.destinations.is_empty() {
        return None;
    }
    Some(match snapshot.phase {
        ClientPhase::Stopped if !client.enabled => "Client disabled".into(),
        ClientPhase::Running => {
            let connected = snapshot
                .destinations
                .iter()
                .filter(|d| d.state == DestinationState::Connected)
                .count();
            // What the session runs with, which a restart may yet change.
            match snapshot.destinations.len() {
                1 if connected == 1 => "Client running · connected".into(),
                1 => "Client running · not connected".into(),
                total => format!("Client running · {connected} of {total} connected"),
            }
        }
        ClientPhase::Starting => "Client starting…".into(),
        ClientPhase::Stopping => "Client stopping…".into(),
        ClientPhase::Failed => "Client failed to start".into(),
        ClientPhase::Stopped => "Client stopped".into(),
    })
}

/// The client toggle's label and whether it is clickable: Disable while
/// enabled, Enable while disabled — not while the client is still stopping.
fn client_toggle(client: &ClientSettings, phase: ClientPhase) -> (&'static str, bool) {
    let label = if client.enabled { "Disable Client" } else { "Enable Client" };
    (label, phase != ClientPhase::Stopping)
}

/// The icon: an enabled server's state (a dot while it starts or stops, a
/// checkmark while it runs) — the client never changes it then. Without a
/// server, or with a disabled one, the app is client-only, and the icon shows
/// by opacity alone whether the client is running (the badge means the
/// server); a disabled server with the client down shows an empty circle.
fn tray_state(
    server: Option<(&ServerConfig, &ServerSnapshot)>,
    client: ClientPhase,
) -> TrayState {
    // A running client is up — listening, each destination one use away —
    // whether or not anything is connected right now.
    let up = client == ClientPhase::Running;
    match server {
        // Just disabled: shown as stopping until it has.
        Some((_, snapshot)) if snapshot.phase == ServerPhase::Stopping => TrayState::Changing,
        Some((server, _)) if !server.enabled => {
            if up {
                TrayState::Active
            } else {
                TrayState::Disabled
            }
        }
        Some((_, snapshot)) => match snapshot.phase {
            ServerPhase::Running => TrayState::Running,
            ServerPhase::Starting | ServerPhase::Stopping => TrayState::Changing,
            ServerPhase::Stopped | ServerPhase::Failed => TrayState::Off,
        },
        None if up => TrayState::Active,
        None if matches!(client, ClientPhase::Starting | ClientPhase::Stopping) => TrayState::Busy,
        None => TrayState::Off,
    }
}

/// Which optional items the menu was built with: (server configured, the
/// client has destinations). A change rebuilds the menu.
type Layout = (bool, bool);

/// Retained handles into the menu, mutated in place on state changes.
struct Items {
    server_status: MenuItem,
    /// `Some` while a server is configured.
    server_toggle: Option<MenuItem>,
    /// `Some` while the client has destinations: its status line and toggle.
    client: Option<(MenuItem, MenuItem)>,
}

/// A toggle item's label and whether it is clickable.
type Toggle = (&'static str, bool);

/// Everything `sync` reacts to; native calls only happen when it changes.
type SyncKey = (TrayState, String, Option<String>, Option<Toggle>, Option<Toggle>);

pub struct Tray {
    tray: TrayIcon,
    /// Checked state owned by `App` (it mirrors the OS registration); set
    /// through [`Tray::set_launch_at_login`], never derived here.
    launch_at_login: CheckMenuItem,
    items: Items,
    layout: Option<Layout>,
    synced: Option<SyncKey>,
}

fn make_icon(state: TrayState) -> Result<tray_icon::Icon> {
    let (rgba, w, h) = icon::tray_rgba(state);
    Ok(tray_icon::Icon::from_rgba(rgba, w, h)?)
}

impl Tray {
    pub fn new() -> Result<Self> {
        // Disabled on a dev store: a debug binary must neither take over nor
        // remove a real install's login item.
        let launch_at_login = CheckMenuItem::with_id(
            MENU_LAUNCH_AT_LOGIN,
            LAUNCH_AT_LOGIN_LABEL,
            !config::dev_store(),
            false,
            None,
        );
        let off = make_icon(TrayState::Off)?;
        // macOS draws the alpha-only glyph as a template image so it adapts
        // to the menu bar, light or dark.
        #[cfg(target_os = "macos")]
        let builder = TrayIconBuilder::new().with_icon_templated(off);
        #[cfg(windows)]
        let builder = TrayIconBuilder::new().with_icon(off);
        let tray = builder
            .with_menu(Box::new(Menu::new()))
            .with_tooltip("flextunnel")
            // Windows convention: left click toggles the window (handled via
            // TrayIconEvent), right click opens the menu. macOS keeps the
            // native left-click menu.
            .with_menu_on_left_click(cfg!(target_os = "macos"))
            .build()?;

        Ok(Self {
            tray,
            launch_at_login,
            items: Items {
                server_status: MenuItem::with_id("server-status", "", false, None),
                server_toggle: None,
                client: None,
            },
            layout: None,
            synced: None,
        })
    }

    fn rebuild_menu(&mut self, (has_server, has_destinations): Layout) -> Result<()> {
        let menu = Menu::new();
        menu.append(&MenuItem::with_id(MENU_OPEN, "Open flextunnel…", true, None))?;
        menu.append(&PredefinedMenuItem::separator())?;

        let client = if has_destinations {
            let status = MenuItem::with_id("client-status", "", false, None);
            menu.append(&status)?;
            let toggle = MenuItem::with_id(MENU_TOGGLE_CLIENT, "Disable Client", false, None);
            menu.append(&toggle)?;
            menu.append(&PredefinedMenuItem::separator())?;
            Some((status, toggle))
        } else {
            None
        };

        let server_status = MenuItem::with_id("server-status", "", false, None);
        menu.append(&server_status)?;
        let server_toggle = if has_server {
            let toggle = MenuItem::with_id(MENU_TOGGLE_SERVER, "Disable Server", false, None);
            menu.append(&toggle)?;
            // The endpoint id is public and known even while stopped, so
            // copying it is always available.
            menu.append(&MenuItem::with_id(
                MENU_COPY_SERVER_ID,
                "Copy Endpoint ID",
                true,
                None,
            ))?;
            Some(toggle)
        } else {
            menu.append(&MenuItem::with_id(
                MENU_SET_UP_SERVER,
                "Set Up Server…",
                true,
                None,
            ))?;
            None
        };
        menu.append(&PredefinedMenuItem::separator())?;

        menu.append(&self.launch_at_login)?;
        menu.append(&PredefinedMenuItem::separator())?;
        menu.append(&MenuItem::with_id(
            "version",
            concat!("flextunnel v", env!("CARGO_PKG_VERSION")),
            false,
            None,
        ))?;
        menu.append(&MenuItem::with_id(MENU_QUIT, "Quit flextunnel", true, None))?;
        self.tray.set_menu(Some(Box::new(menu)));
        self.items = Items {
            server_status,
            server_toggle,
            client,
        };
        Ok(())
    }

    /// Show the login-item registration's state. Called on every change and
    /// after every toggle attempt: a click flips the native checkbox on its
    /// own, so a failed toggle has to be snapped back.
    pub fn set_launch_at_login(&self, enabled: bool) {
        self.launch_at_login.set_checked(enabled);
    }

    /// Reflect the client and server states in the icon/menu. Native calls
    /// only happen on a change; called every UI frame.
    pub fn sync(
        &mut self,
        client: &ClientSettings,
        client_snapshot: &ClientSnapshot,
        server: Option<&ServerConfig>,
        server_snapshot: &ServerSnapshot,
    ) {
        let client_line = client_line(client, client_snapshot);
        let layout = (server.is_some(), client_line.is_some());
        if self.layout != Some(layout) {
            if let Err(e) = self.rebuild_menu(layout) {
                log::error!("Failed to rebuild the tray menu: {e:#}");
                return;
            }
            self.layout = Some(layout);
            // Fresh items carry none of the synced state.
            self.synced = None;
        }

        let state = tray_state(server.map(|s| (s, server_snapshot)), client_snapshot.phase);
        let client_toggle = client_line
            .is_some()
            .then(|| client_toggle(client, client_snapshot.phase));
        let key: SyncKey = (
            state,
            server_line(server.map(|s| (s, server_snapshot))),
            client_line,
            server.map(|s| server_toggle(s, server_snapshot.phase)),
            client_toggle,
        );
        if self.synced.as_ref() == Some(&key) {
            return;
        }
        let icon_changed = self.synced.as_ref().map(|(s, ..)| *s) != Some(state);
        let (_, line, client_line, toggle, client_toggle) = &key;

        self.items.server_status.set_text(line);
        if let (Some(item), Some((label, enabled))) = (&self.items.server_toggle, toggle) {
            item.set_text(*label);
            item.set_enabled(*enabled);
        }
        if let (Some((status, item)), Some(line), Some((label, enabled))) =
            (&self.items.client, client_line, client_toggle)
        {
            status.set_text(line);
            item.set_text(*label);
            item.set_enabled(*enabled);
        }
        let tooltip = match client_line {
            Some(client_line) if server.is_none() => format!("flextunnel — {client_line}"),
            _ => format!("flextunnel — {line}"),
        };
        let _ = self.tray.set_tooltip(Some(tooltip));

        if icon_changed
            && let Ok(icon) = make_icon(state)
        {
            // `set_icon` alone re-sets the macOS image as non-template
            // (rendering it solid black instead of adapting to the menu
            // bar), so keep it a template there.
            #[cfg(target_os = "macos")]
            let _ = self.tray.set_icon_templated(Some(icon));
            #[cfg(windows)]
            let _ = self.tray.set_icon(Some(icon));
        }
        self.synced = Some(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(phase: ServerPhase, clients: usize) -> ServerSnapshot {
        ServerSnapshot {
            phase,
            connected_clients: (0..clients).map(|i| format!("ed25519-pub:{i}")).collect(),
            ..ServerSnapshot::default()
        }
    }

    fn server(enabled: bool) -> ServerConfig {
        ServerConfig {
            endpoint_id: "e".into(),
            secret: "s".into(),
            authorized_clients: Vec::new(),
            routed_domains: Vec::new(),
            routed_cidrs: Vec::new(),
            relay_urls: Vec::new(),
            relay_auth_token: None,
            enabled,
        }
    }

    fn destination(host: &str) -> crate::config::Destination {
        crate::config::Destination {
            id: host.into(),
            host: host.into(),
            server_node_id: format!("node-{host}"),
            routed_domains: Vec::new(),
            routed_cidrs: Vec::new(),
            auth_key_id: String::new(),
            relay_urls: Vec::new(),
            relay_auth_token: None,
        }
    }

    fn client(enabled: bool, hosts: &[&str]) -> ClientSettings {
        ClientSettings {
            enabled,
            destinations: hosts.iter().map(|host| destination(host)).collect(),
            ..ClientSettings::default()
        }
    }

    /// A client snapshot in `phase` whose destinations are in `states`.
    fn client_snapshot(phase: ClientPhase, states: &[DestinationState]) -> ClientSnapshot {
        let status = |(i, state): (usize, &DestinationState)| {
            flextunnel_core::proxy::DestinationStatus {
                host: format!("d{i}.internal"),
                server_node_id: String::new(),
                state: *state,
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
            }
        };
        ClientSnapshot {
            phase,
            destinations: states.iter().enumerate().map(status).collect(),
            ..ClientSnapshot::default()
        }
    }

    #[test]
    fn the_icon_follows_the_server_alone() {
        let on = server(true);
        let state = |phase, clients, client: ClientPhase| {
            tray_state(Some((&on, &snapshot(phase, clients))), client)
        };
        assert_eq!(
            state(ServerPhase::Running, 0, ClientPhase::Running),
            TrayState::Running,
            "checkmark: running, with or without clients — the client doesn't count"
        );
        assert_eq!(state(ServerPhase::Running, 2, ClientPhase::Stopped), TrayState::Running);
        assert_eq!(
            state(ServerPhase::Starting, 0, ClientPhase::Running),
            TrayState::Changing,
            "dot"
        );
        assert_eq!(state(ServerPhase::Stopping, 0, ClientPhase::Stopped), TrayState::Changing);
        assert_eq!(
            state(ServerPhase::Stopped, 0, ClientPhase::Running),
            TrayState::Off,
            "an enabled server that is down dims the icon whatever the client does"
        );
        assert_eq!(state(ServerPhase::Failed, 0, ClientPhase::Stopped), TrayState::Off);
    }

    #[test]
    fn a_disabled_server_is_client_only() {
        let off = server(false);
        let state =
            |phase, client: ClientPhase| tray_state(Some((&off, &snapshot(phase, 0))), client);
        assert_eq!(
            state(ServerPhase::Stopped, ClientPhase::Stopped),
            TrayState::Disabled,
            "empty-circle badge"
        );
        assert_eq!(state(ServerPhase::Failed, ClientPhase::Starting), TrayState::Disabled);
        assert_eq!(
            state(ServerPhase::Stopped, ClientPhase::Running),
            TrayState::Active,
            "the client running: active, as with no server"
        );
        // Just disabled: shown as stopping until it has.
        assert_eq!(state(ServerPhase::Stopping, ClientPhase::Running), TrayState::Changing);
    }

    #[test]
    fn without_a_server_the_client_shows_by_opacity_only() {
        assert_eq!(tray_state(None, ClientPhase::Stopped), TrayState::Off);
        assert_eq!(tray_state(None, ClientPhase::Failed), TrayState::Off);
        assert_eq!(tray_state(None, ClientPhase::Starting), TrayState::Busy);
        assert_eq!(tray_state(None, ClientPhase::Stopping), TrayState::Busy);
        // Running is up: listening, each destination one use away.
        assert_eq!(tray_state(None, ClientPhase::Running), TrayState::Active);
    }

    #[test]
    fn status_lines() {
        assert_eq!(server_line(None), "No server set up");
        let on = server(true);
        let stopped = snapshot(ServerPhase::Stopped, 0);
        assert_eq!(
            server_line(Some((&on, &stopped))),
            "Server stopped · no clients authorized"
        );
        assert_eq!(
            server_line(Some((&on, &snapshot(ServerPhase::Running, 1)))),
            "Server running · 1 client connected"
        );
        assert_eq!(server_toggle(&on, ServerPhase::Running), ("Disable Server", true));
        assert_eq!(server_toggle(&on, ServerPhase::Stopping), ("Disable Server", false));
        let off = server(false);
        assert_eq!(server_line(Some((&off, &stopped))), "Server disabled");
        assert_eq!(server_toggle(&off, ServerPhase::Stopped), ("Enable Server", true));
    }

    #[test]
    fn client_lines() {
        use DestinationState::{Connected, Connecting, Idle};
        let line = |client: &ClientSettings, phase, states: &[DestinationState]| {
            client_line(client, &client_snapshot(phase, states))
        };
        // No destinations: the menu leaves the client out.
        assert_eq!(line(&client(true, &[]), ClientPhase::Stopped, &[]), None);

        let two = client(true, &["a.internal", "b.internal"]);
        assert_eq!(
            line(&two, ClientPhase::Running, &[Connected, Idle]).as_deref(),
            Some("Client running · 1 of 2 connected")
        );
        assert_eq!(
            line(&two, ClientPhase::Running, &[Idle, Connecting]).as_deref(),
            Some("Client running · 0 of 2 connected"),
            "idle is the resting state of a running client, not a fault"
        );
        let one = client(true, &["a.internal"]);
        assert_eq!(
            line(&one, ClientPhase::Running, &[Connected]).as_deref(),
            Some("Client running · connected")
        );
        assert_eq!(
            line(&one, ClientPhase::Running, &[Idle]).as_deref(),
            Some("Client running · not connected")
        );
        assert_eq!(line(&one, ClientPhase::Failed, &[]).as_deref(), Some("Client failed to start"));
        assert_eq!(line(&one, ClientPhase::Stopped, &[]).as_deref(), Some("Client stopped"));
        assert_eq!(client_toggle(&one, ClientPhase::Running), ("Disable Client", true));
        assert_eq!(client_toggle(&one, ClientPhase::Stopping), ("Disable Client", false));

        let off = client(false, &["a.internal"]);
        assert_eq!(line(&off, ClientPhase::Stopped, &[]).as_deref(), Some("Client disabled"));
        assert_eq!(client_toggle(&off, ClientPhase::Stopped), ("Enable Client", true));
    }
}
