//! System tray icon + menu: an aggregate status line over the profiles (which
//! are connected from the window, not listed here), a submenu for the server
//! when configured (status, Start, Stop, Copy Endpoint ID), then the "start at
//! login" checkbox (see `autostart`). Created and mutated only on the main
//! thread (from the iced update loop); the tray-icon event handlers installed
//! by the tray subscription merely forward events and wake the runtime, since
//! they may fire off the main thread.

use crate::config::{Profile, ServerConfig};
use crate::icon::{self, TrayState};
use crate::server_session::{ServerPhase, ServerSnapshot};
use crate::tunnel::{Phase, Snapshot};
use anyhow::Result;
use std::collections::HashMap;
use tray_icon::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tray_icon::{TrayIcon, TrayIconBuilder};

pub const MENU_OPEN: &str = "open";
pub const MENU_QUIT: &str = "quit";
pub const MENU_START_SERVER: &str = "start-server";
pub const MENU_STOP_SERVER: &str = "stop-server";
pub const MENU_COPY_SERVER_ID: &str = "copy-server-id";
pub const MENU_LAUNCH_AT_LOGIN: &str = "launch-at-login";

/// The login-item checkbox, in each platform's own words for the feature.
#[cfg(target_os = "macos")]
const LAUNCH_AT_LOGIN_LABEL: &str = "Open at Login";
#[cfg(windows)]
const LAUNCH_AT_LOGIN_LABEL: &str = "Start with Windows";
#[cfg(not(any(target_os = "macos", windows)))]
const LAUNCH_AT_LOGIN_LABEL: &str = "Start at Login";

pub fn server_status_line(phase: ServerPhase) -> &'static str {
    match phase {
        ServerPhase::Stopped => "Stopped",
        ServerPhase::Starting => "Starting…",
        ServerPhase::Running => "Running",
        ServerPhase::Stopping => "Stopping…",
        ServerPhase::Failed => "Failed to start",
    }
}

fn profile_phase(snapshots: &HashMap<String, Snapshot>, id: &str) -> Phase {
    snapshots.get(id).map(|s| s.phase).unwrap_or(Phase::Idle)
}

/// A server's phase in the icon's terms: running counts as connected, the
/// transitions as in progress.
fn server_as_phase(phase: ServerPhase) -> Phase {
    match phase {
        ServerPhase::Stopped => Phase::Idle,
        ServerPhase::Starting | ServerPhase::Stopping => Phase::Connecting,
        ServerPhase::Running => Phase::Connected,
        ServerPhase::Failed => Phase::Failed,
    }
}

/// The icon reflects the worst/most-notable state across profiles: a failure
/// beats connected beats in-progress beats idle. When at least one profile is
/// connected, the icon distinguishes "everything settled" ([`TrayState::AllConnected`],
/// checkmark) from "still working" ([`TrayState::Connected`], dot): the checkmark
/// shows only once no profile is still connecting or reconnecting.
fn aggregate_state(phases: &[Phase]) -> TrayState {
    if phases.contains(&Phase::Failed) {
        TrayState::Failed
    } else if phases.contains(&Phase::Connected) {
        let in_progress = phases
            .iter()
            .any(|p| matches!(p, Phase::Connecting | Phase::Reconnecting));
        if in_progress {
            TrayState::Connected
        } else {
            TrayState::AllConnected
        }
    } else if phases.contains(&Phase::Reconnecting) {
        TrayState::Reconnecting
    } else if phases.contains(&Phase::Connecting) {
        TrayState::Connecting
    } else {
        TrayState::Idle
    }
}

/// The status line: the profiles' aggregate, then the server when running.
fn aggregate_line(phases: &[Phase], server_running: bool) -> String {
    match (profiles_line(phases), server_running) {
        (Some(profiles), true) => format!("{profiles} · server running"),
        (Some(profiles), false) => profiles,
        (None, true) => "Server running".into(),
        (None, false) => "No profiles".into(),
    }
}

/// The client profiles' part of the status line; `None` without profiles.
fn profiles_line(phases: &[Phase]) -> Option<String> {
    if phases.is_empty() {
        return None;
    }
    let connected = phases.iter().filter(|p| **p == Phase::Connected).count();
    Some(if connected > 0 {
        format!("{connected} of {} connected", phases.len())
    } else if phases.contains(&Phase::Failed) {
        "Connection failed".into()
    } else if phases
        .iter()
        .any(|p| matches!(p, Phase::Connecting | Phase::Reconnecting))
    {
        "Connecting…".into()
    } else {
        "Disconnected".into()
    })
}

/// Retained handles into the server's submenu, mutated in place on phase
/// changes so the whole menu is only rebuilt when the server is added or
/// removed.
struct ServerItems {
    status: MenuItem,
    start: MenuItem,
    stop: MenuItem,
}

/// Everything `sync` reacts to; native calls only happen when it changes.
type SyncKey = (TrayState, String, Option<(ServerPhase, bool)>);

pub struct Tray {
    tray: TrayIcon,
    status: MenuItem,
    /// Checked state owned by `App` (it mirrors the OS registration); set
    /// through [`Tray::set_launch_at_login`], never derived here.
    launch_at_login: CheckMenuItem,
    /// `Some` while the menu was built with the server submenu; adding or
    /// removing the server rebuilds the menu.
    server_items: Option<ServerItems>,
    synced: Option<SyncKey>,
}

fn make_icon(state: TrayState) -> Result<tray_icon::Icon> {
    let (rgba, w, h) = icon::tray_rgba(state);
    Ok(tray_icon::Icon::from_rgba(rgba, w, h)?)
}

impl Tray {
    pub fn new() -> Result<Self> {
        let status = MenuItem::with_id("status", "Disconnected", false, None);
        let launch_at_login =
            CheckMenuItem::with_id(MENU_LAUNCH_AT_LOGIN, LAUNCH_AT_LOGIN_LABEL, true, false, None);
        let idle = make_icon(TrayState::Idle)?;
        // macOS draws the alpha-only glyph as a template image so it adapts
        // to the menu bar, light or dark.
        #[cfg(target_os = "macos")]
        let builder = TrayIconBuilder::new().with_icon_templated(idle);
        #[cfg(not(target_os = "macos"))]
        let builder = TrayIconBuilder::new().with_icon(idle);
        let tray = builder
            .with_menu(Box::new(Menu::new()))
            .with_tooltip("flextunnel — disconnected")
            // Windows convention: left click toggles the window (handled via
            // TrayIconEvent), right click opens the menu. macOS keeps the
            // native left-click menu.
            .with_menu_on_left_click(cfg!(target_os = "macos"))
            .build()?;

        let mut this = Self {
            tray,
            status,
            launch_at_login,
            server_items: None,
            synced: None,
        };
        this.rebuild_menu(None)?;
        Ok(this)
    }

    fn rebuild_menu(&mut self, server: Option<&ServerConfig>) -> Result<()> {
        let menu = Menu::new();
        menu.append(&MenuItem::with_id(MENU_OPEN, "Open flextunnel…", true, None))?;
        menu.append(&PredefinedMenuItem::separator())?;
        menu.append(&self.status)?;
        menu.append(&PredefinedMenuItem::separator())?;

        self.server_items = None;
        if server.is_some() {
            let status = MenuItem::with_id("server-status", "…", false, None);
            let start = MenuItem::with_id(MENU_START_SERVER, "Start Server", false, None);
            let stop = MenuItem::with_id(MENU_STOP_SERVER, "Stop Server", false, None);
            // The endpoint id is public and known even while stopped, so
            // copying it is always available.
            let copy_id = MenuItem::with_id(MENU_COPY_SERVER_ID, "Copy Endpoint ID", true, None);
            let submenu =
                Submenu::with_items("Server", true, &[&status, &start, &stop, &copy_id])?;
            menu.append(&submenu)?;
            menu.append(&PredefinedMenuItem::separator())?;
            self.server_items = Some(ServerItems { status, start, stop });
        }

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
        Ok(())
    }

    /// Show the login-item registration's state. Called on every change and
    /// after every toggle attempt: a click flips the native checkbox on its
    /// own, so a failed toggle has to be snapped back.
    pub fn set_launch_at_login(&self, enabled: bool) {
        self.launch_at_login.set_checked(enabled);
    }

    /// Reflect the tunnel states in the icon/menu. Native calls only happen on
    /// a change; called every UI frame.
    pub fn sync(
        &mut self,
        profiles: &[Profile],
        snapshots: &HashMap<String, Snapshot>,
        server: Option<&ServerConfig>,
        server_snapshot: &ServerSnapshot,
    ) {
        let phases: Vec<Phase> = profiles
            .iter()
            .map(|p| profile_phase(snapshots, &p.id))
            .collect();
        let server_phase = server.map(|_| server_snapshot.phase);
        let icon_phases: Vec<Phase> = phases
            .iter()
            .copied()
            .chain(server_phase.map(server_as_phase))
            .collect();
        let state = aggregate_state(&icon_phases);
        let line = aggregate_line(&phases, server_phase == Some(ServerPhase::Running));
        let key: SyncKey = (
            state,
            line.clone(),
            server.zip(server_phase).map(|(s, phase)| (phase, s.is_ready())),
        );
        if self.synced.as_ref() == Some(&key) {
            return;
        }
        let icon_changed = self.synced.as_ref().map(|(s, ..)| *s) != Some(state);
        self.synced = Some(key);

        if server.is_some() != self.server_items.is_some()
            && let Err(e) = self.rebuild_menu(server)
        {
            log::error!("Failed to rebuild the tray menu: {e:#}");
            return;
        }

        self.status.set_text(&line);

        if let (Some(items), Some(server), Some(phase)) = (&self.server_items, server, server_phase) {
            items.status.set_text(server_status_line(phase));
            items.start.set_enabled(
                matches!(phase, ServerPhase::Stopped | ServerPhase::Failed) && server.is_ready(),
            );
            items
                .stop
                .set_enabled(matches!(phase, ServerPhase::Starting | ServerPhase::Running));
        }

        if icon_changed
            && let Ok(icon) = make_icon(state)
        {
            // `set_icon` alone re-sets the macOS image as non-template
            // (rendering it solid black instead of adapting to the menu
            // bar), so keep it a template there.
            #[cfg(target_os = "macos")]
            let _ = self.tray.set_icon_templated(Some(icon));
            #[cfg(not(target_os = "macos"))]
            let _ = self.tray.set_icon(Some(icon));
        }
        let _ = self.tray.set_tooltip(Some(format!("flextunnel — {line}")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_line_counts_profiles_then_the_server() {
        assert_eq!(aggregate_line(&[], false), "No profiles");
        assert_eq!(aggregate_line(&[], true), "Server running");
        assert_eq!(aggregate_line(&[Phase::Idle], false), "Disconnected");
        assert_eq!(
            aggregate_line(&[Phase::Connected, Phase::Idle], true),
            "1 of 2 connected · server running"
        );
    }

    #[test]
    fn all_connected_only_without_in_progress_profiles() {
        // No profiles / none connected: never the connected states.
        assert_eq!(aggregate_state(&[]), TrayState::Idle);
        assert_eq!(aggregate_state(&[Phase::Connecting]), TrayState::Connecting);

        // Every connecting profile has connected → checkmark. Idle profiles
        // aren't "connecting", so they don't hold back the checkmark.
        assert_eq!(aggregate_state(&[Phase::Connected]), TrayState::AllConnected);
        assert_eq!(
            aggregate_state(&[Phase::Connected, Phase::Connected]),
            TrayState::AllConnected
        );
        assert_eq!(
            aggregate_state(&[Phase::Connected, Phase::Idle]),
            TrayState::AllConnected
        );

        // A profile still in progress keeps the plain dot.
        assert_eq!(
            aggregate_state(&[Phase::Connected, Phase::Connecting]),
            TrayState::Connected
        );
        assert_eq!(
            aggregate_state(&[Phase::Connected, Phase::Reconnecting]),
            TrayState::Connected
        );

        // A failure still dominates over connected profiles.
        assert_eq!(
            aggregate_state(&[Phase::Connected, Phase::Failed]),
            TrayState::Failed
        );
    }
}
