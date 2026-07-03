//! System tray icon + menu. Created and mutated only on the main thread (from
//! the egui update loop); the tray-icon event handlers installed in `App::new`
//! merely forward events and wake the UI, since they may fire off the main
//! thread.

use crate::icon::{self, TrayState};
use crate::tunnel::Phase;
use anyhow::Result;
use std::net::SocketAddr;
use tray_icon::menu::{Menu, MenuItem, PredefinedMenuItem};
use tray_icon::{TrayIcon, TrayIconBuilder};

pub const MENU_CONNECT: &str = "connect";
pub const MENU_DISCONNECT: &str = "disconnect";
pub const MENU_COPY_SOCKS: &str = "copy-socks";
pub const MENU_OPEN: &str = "open";
pub const MENU_QUIT: &str = "quit";

pub fn tray_state(phase: Phase) -> TrayState {
    match phase {
        Phase::Idle => TrayState::Idle,
        Phase::Connecting => TrayState::Connecting,
        Phase::Connected => TrayState::Connected,
        Phase::Reconnecting => TrayState::Reconnecting,
        Phase::Failed => TrayState::Failed,
    }
}

pub fn status_line(phase: Phase) -> &'static str {
    match phase {
        Phase::Idle => "Disconnected",
        Phase::Connecting => "Connecting…",
        Phase::Connected => "Connected",
        Phase::Reconnecting => "Reconnecting…",
        Phase::Failed => "Connection failed",
    }
}

pub struct Tray {
    tray: TrayIcon,
    status: MenuItem,
    connect: MenuItem,
    disconnect: MenuItem,
    copy_socks: MenuItem,
    synced: Option<(TrayState, bool, bool)>,
}

fn make_icon(state: TrayState) -> Result<tray_icon::Icon> {
    let (rgba, w, h) = icon::tray_rgba(state);
    Ok(tray_icon::Icon::from_rgba(rgba, w, h)?)
}

impl Tray {
    pub fn new() -> Result<Self> {
        let status = MenuItem::with_id("status", status_line(Phase::Idle), false, None);
        let connect = MenuItem::with_id(MENU_CONNECT, "Connect", false, None);
        let disconnect = MenuItem::with_id(MENU_DISCONNECT, "Disconnect", false, None);
        let copy_socks = MenuItem::with_id(MENU_COPY_SOCKS, "Copy SOCKS5 Address", false, None);
        let open = MenuItem::with_id(MENU_OPEN, "Open flextunnel…", true, None);
        let quit = MenuItem::with_id(MENU_QUIT, "Quit flextunnel", true, None);
        let menu = Menu::with_items(&[
            &open,
            &PredefinedMenuItem::separator(),
            &status,
            &PredefinedMenuItem::separator(),
            &connect,
            &disconnect,
            &copy_socks,
            &PredefinedMenuItem::separator(),
            &quit,
        ])?;

        let tray = TrayIconBuilder::new()
            .with_icon(make_icon(TrayState::Idle)?)
            .with_icon_as_template(icon::is_template())
            .with_menu(Box::new(menu))
            .with_tooltip("flextunnel — disconnected")
            // Windows convention: left click toggles the window (handled via
            // TrayIconEvent), right click opens the menu. macOS keeps the
            // native left-click menu.
            .with_menu_on_left_click(cfg!(target_os = "macos"))
            .build()?;

        Ok(Self {
            tray,
            status,
            connect,
            disconnect,
            copy_socks,
            synced: None,
        })
    }

    /// Reflect the tunnel state in the icon/menu. Native calls only happen on
    /// a change; called every UI frame.
    pub fn sync(&mut self, phase: Phase, can_connect: bool, socks_addr: Option<SocketAddr>) {
        let state = tray_state(phase);
        let key = (state, can_connect, socks_addr.is_some());
        if self.synced == Some(key) {
            return;
        }
        let icon_changed = self.synced.map(|(s, ..)| s) != Some(state);
        self.synced = Some(key);

        self.status.set_text(status_line(phase));
        self.connect
            .set_enabled(matches!(phase, Phase::Idle | Phase::Failed) && can_connect);
        self.disconnect.set_enabled(matches!(
            phase,
            Phase::Connecting | Phase::Connected | Phase::Reconnecting
        ));
        self.copy_socks
            .set_enabled(phase == Phase::Connected && socks_addr.is_some());

        if icon_changed {
            if let Ok(icon) = make_icon(state) {
                // `set_icon` alone re-sets the macOS image as non-template
                // (rendering it solid black instead of adapting to the menu
                // bar), so pass the template flag through explicitly.
                let _ = self
                    .tray
                    .set_icon_with_as_template(Some(icon), icon::is_template());
            }
            let _ = self
                .tray
                .set_tooltip(Some(format!("flextunnel — {}", status_line(phase))));
        }
    }
}
