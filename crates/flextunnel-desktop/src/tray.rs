//! System tray icon + menu: the client connections' aggregate line when there
//! are any (they are connected from the window, not listed here), then the
//! server's status line and controls (Enable/Disable, Copy Endpoint ID — or "Set
//! Up Server…" while there is none), then the "start at login" checkbox (see
//! `autostart`). The icon's badge is the server's (see [`tray_state`]). Created
//! and mutated only on the main thread (from the iced update loop); the
//! tray-icon event handlers installed by the tray subscription merely forward
//! events and wake the runtime, since they may fire off the main thread.

use crate::config::{self, Profile, ServerConfig};
use crate::icon::{self, TrayState};
use crate::server_session::{ServerPhase, ServerSnapshot};
use crate::tunnel::{Phase, Snapshot};
use anyhow::Result;
use std::collections::HashMap;
use tray_icon::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem};
use tray_icon::{TrayIcon, TrayIconBuilder};

pub const MENU_OPEN: &str = "open";
pub const MENU_QUIT: &str = "quit";
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

/// The client connections' aggregate line; `None` without profiles.
fn connections_line(phases: &[Phase]) -> Option<String> {
    if phases.is_empty() {
        return None;
    }
    let connected = phases.iter().filter(|p| **p == Phase::Connected).count();
    Some(if connected > 0 {
        format!("Connections: {connected} of {} connected", phases.len())
    } else if phases.contains(&Phase::Failed) {
        "Connections: failed".into()
    } else if phases
        .iter()
        .any(|p| matches!(p, Phase::Connecting | Phase::Reconnecting))
    {
        "Connections: connecting…".into()
    } else {
        "Connections: none connected".into()
    })
}

/// The icon: an enabled server's state (a dot while it starts or stops, a
/// checkmark while it runs) — client connections never change it then.
/// Without a server, or with a disabled one, the app is client-only, and the
/// icon shows by opacity alone whether a connection is up (the badge means the
/// server); a disabled server with no connection up shows an empty circle.
fn tray_state(
    server: Option<(&ServerConfig, &ServerSnapshot)>,
    client_phases: &[Phase],
) -> TrayState {
    let connected = client_phases.contains(&Phase::Connected);
    match server {
        // Just disabled: shown as stopping until it has.
        Some((_, snapshot)) if snapshot.phase == ServerPhase::Stopping => TrayState::Changing,
        Some((server, _)) if !server.enabled => {
            if connected {
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
        None if connected => TrayState::Active,
        None if client_phases
            .iter()
            .any(|p| matches!(p, Phase::Connecting | Phase::Reconnecting)) =>
        {
            TrayState::Busy
        }
        None => TrayState::Off,
    }
}

/// Which optional items the menu was built with: (server configured, any
/// client profiles). A change rebuilds the menu.
type Layout = (bool, bool);

/// Retained handles into the menu, mutated in place on state changes.
struct Items {
    server_status: MenuItem,
    /// `Some` while a server is configured.
    server_toggle: Option<MenuItem>,
    /// `Some` while there are client profiles.
    connections: Option<MenuItem>,
}

/// Everything `sync` reacts to; native calls only happen when it changes.
type SyncKey = (TrayState, String, Option<String>, Option<(&'static str, bool)>);

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
                connections: None,
            },
            layout: None,
            synced: None,
        })
    }

    fn rebuild_menu(&mut self, (has_server, has_profiles): Layout) -> Result<()> {
        let menu = Menu::new();
        menu.append(&MenuItem::with_id(MENU_OPEN, "Open flextunnel…", true, None))?;
        menu.append(&PredefinedMenuItem::separator())?;

        let connections = if has_profiles {
            let item = MenuItem::with_id("connections", "", false, None);
            menu.append(&item)?;
            menu.append(&PredefinedMenuItem::separator())?;
            Some(item)
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
            connections,
        };
        Ok(())
    }

    /// Show the login-item registration's state. Called on every change and
    /// after every toggle attempt: a click flips the native checkbox on its
    /// own, so a failed toggle has to be snapped back.
    pub fn set_launch_at_login(&self, enabled: bool) {
        self.launch_at_login.set_checked(enabled);
    }

    /// Reflect the server and connection states in the icon/menu. Native
    /// calls only happen on a change; called every UI frame.
    pub fn sync(
        &mut self,
        profiles: &[Profile],
        snapshots: &HashMap<String, Snapshot>,
        server: Option<&ServerConfig>,
        server_snapshot: &ServerSnapshot,
    ) {
        let phases: Vec<Phase> = profiles
            .iter()
            .map(|p| snapshots.get(&p.id).map(|s| s.phase).unwrap_or(Phase::Idle))
            .collect();
        let layout = (server.is_some(), !phases.is_empty());
        if self.layout != Some(layout) {
            if let Err(e) = self.rebuild_menu(layout) {
                log::error!("Failed to rebuild the tray menu: {e:#}");
                return;
            }
            self.layout = Some(layout);
            // Fresh items carry none of the synced state.
            self.synced = None;
        }

        let state = tray_state(server.map(|s| (s, server_snapshot)), &phases);
        let key: SyncKey = (
            state,
            server_line(server.map(|s| (s, server_snapshot))),
            connections_line(&phases),
            server.map(|s| server_toggle(s, server_snapshot.phase)),
        );
        if self.synced.as_ref() == Some(&key) {
            return;
        }
        let icon_changed = self.synced.as_ref().map(|(s, ..)| *s) != Some(state);
        let (_, line, connections, toggle) = &key;

        self.items.server_status.set_text(line);
        if let (Some(item), Some((label, enabled))) = (&self.items.server_toggle, toggle) {
            item.set_text(*label);
            item.set_enabled(*enabled);
        }
        if let (Some(item), Some(connections)) = (&self.items.connections, connections) {
            item.set_text(connections);
        }
        let tooltip = match connections {
            Some(connections) if server.is_none() => format!("flextunnel — {connections}"),
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

    #[test]
    fn the_icon_follows_the_server_alone() {
        let on = server(true);
        let state = |phase, clients, connections: &[Phase]| {
            tray_state(Some((&on, &snapshot(phase, clients))), connections)
        };
        let connected = [Phase::Connected, Phase::Failed];
        assert_eq!(
            state(ServerPhase::Running, 0, &connected),
            TrayState::Running,
            "checkmark: running, with or without clients — client connections don't count"
        );
        assert_eq!(state(ServerPhase::Running, 2, &[]), TrayState::Running);
        assert_eq!(state(ServerPhase::Starting, 0, &connected), TrayState::Changing, "dot");
        assert_eq!(state(ServerPhase::Stopping, 0, &[]), TrayState::Changing);
        assert_eq!(
            state(ServerPhase::Stopped, 0, &connected),
            TrayState::Off,
            "an enabled server that is down dims the icon whatever the connections do"
        );
        assert_eq!(state(ServerPhase::Failed, 0, &[]), TrayState::Off);
    }

    #[test]
    fn a_disabled_server_is_client_only() {
        let off = server(false);
        let state = |phase, connections: &[Phase]| {
            tray_state(Some((&off, &snapshot(phase, 0))), connections)
        };
        assert_eq!(state(ServerPhase::Stopped, &[]), TrayState::Disabled, "empty-circle badge");
        assert_eq!(state(ServerPhase::Failed, &[Phase::Connecting]), TrayState::Disabled);
        assert_eq!(
            state(ServerPhase::Stopped, &[Phase::Connected, Phase::Idle]),
            TrayState::Active,
            "a connection up: active, as with no server"
        );
        // Just disabled: shown as stopping until it has.
        assert_eq!(state(ServerPhase::Stopping, &[Phase::Connected]), TrayState::Changing);
    }

    #[test]
    fn without_a_server_connections_show_by_opacity_only() {
        assert_eq!(tray_state(None, &[]), TrayState::Off);
        assert_eq!(tray_state(None, &[Phase::Idle, Phase::Failed]), TrayState::Off);
        assert_eq!(tray_state(None, &[Phase::Reconnecting]), TrayState::Busy);
        assert_eq!(tray_state(None, &[Phase::Connected, Phase::Connecting]), TrayState::Active);
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

        assert_eq!(connections_line(&[]), None);
        assert_eq!(
            connections_line(&[Phase::Connected, Phase::Idle]).as_deref(),
            Some("Connections: 1 of 2 connected")
        );
        assert_eq!(
            connections_line(&[Phase::Idle]).as_deref(),
            Some("Connections: none connected")
        );
    }
}
