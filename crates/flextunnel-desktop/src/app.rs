//! The iced daemon state machine: a Status / Forwards / Settings / Logs tabbed
//! window driven alongside the system tray. The daemon owns all state, so
//! closing the window (which destroys it) loses nothing — the tray re-opens
//! it on demand. Tray/menu events are forwarded from tray-icon's handlers into
//! a channel drained by a [`Subscription`], so a tray click wakes the runtime
//! even while no window exists; a 500 ms tick keeps the snapshot and the tray
//! state fresh the rest of the time.

use crate::config::{self, AppConfig};
use crate::forward::{self, ForwardState, ForwardStatus, PortForward};
use crate::icon;
use crate::logging;
use crate::tray::{self, Tray};
use crate::tunnel::{Controller, Phase, Snapshot};
use crate::view;
use iced::futures::Stream;
use iced::{window, Element, Size, Subscription, Task};
use std::collections::HashMap;
use std::time::Duration;
use tray_icon::menu::MenuEvent;
use tray_icon::TrayIconEvent;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tab {
    Status,
    Forwards,
    Settings,
    Logs,
}

#[derive(Debug, Clone)]
pub enum Message {
    Tick,
    SetupTray,
    TrayMenu(String),
    TrayIcon(TrayIconEvent),
    WindowOpened,
    WindowClosed(window::Id),
    TabSelected(Tab),
    Connect,
    Disconnect,
    CopyText(String),
    // Settings form
    ServerNodeIdChanged(String),
    AuthTokenChanged(String),
    SocksPortChanged(String),
    HttpEnabledToggled(bool),
    HttpPortChanged(String),
    RelayUrlsChanged(String),
    SaveSettings,
    // Forwards
    AddForward,
    EditForward(usize),
    DeleteForward(usize),
    ToggleForward(usize, bool),
    FormLabelChanged(String),
    FormLocalPortChanged(String),
    FormRemoteHostChanged(String),
    FormRemotePortChanged(String),
    FormEnabledToggled(bool),
    FormSave,
    FormCancel,
    // Logs
    OpenLogFolder,
    CopyLogs,
}

/// Editable settings buffers, mirroring the iOS setup form's validation.
#[derive(Default)]
pub struct SettingsForm {
    pub server_node_id: String,
    pub auth_token: String,
    pub socks_port: String,
    pub http_enabled: bool,
    pub http_port: String,
    pub relay_urls: String,
}

impl SettingsForm {
    fn from_config(config: &AppConfig) -> Self {
        Self {
            server_node_id: config.server_node_id.clone(),
            auth_token: config.auth_token.clone(),
            socks_port: config.socks_port.to_string(),
            http_enabled: config.http_port.is_some(),
            http_port: config
                .http_port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "8080".into()),
            relay_urls: config.relay_urls.join(", "),
        }
    }

    pub fn validate(&self) -> Result<AppConfig, String> {
        let server_node_id = self.server_node_id.trim();
        if server_node_id.is_empty() {
            return Err("Server node id is required".into());
        }
        let auth_token = self.auth_token.trim();
        if auth_token.is_empty() {
            return Err("Auth token is required".into());
        }
        flextunnel_core::auth::validate_client_token(auth_token)
            .map_err(|e| format!("Invalid auth token: {e}"))?;
        let socks_port = parse_port(&self.socks_port, "SOCKS5 port")?;
        let http_port = if self.http_enabled {
            let port = parse_port(&self.http_port, "HTTP port")?;
            if port == socks_port {
                return Err("HTTP port must differ from the SOCKS5 port".into());
            }
            Some(port)
        } else {
            None
        };
        let relay_urls = self
            .relay_urls
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
        Ok(AppConfig {
            server_node_id: server_node_id.into(),
            auth_token: auth_token.into(),
            socks_port,
            http_port,
            relay_urls,
        })
    }
}

fn parse_port(input: &str, what: &str) -> Result<u16, String> {
    input
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| format!("{what} must be 1-65535"))
}

/// Validate a forward's remote host — an IP literal (IPv4, IPv6, `[IPv6]`) or
/// a hostname — returning the normalized form to store (brackets stripped so
/// the wire sees a bare address). Hostname rules are deliberately permissive
/// (underscores allowed for internal names) but catch real typos: empty
/// labels (`a..b`, leading/trailing dots), bad characters, oversized labels.
fn validate_remote_host(input: &str) -> Result<String, String> {
    let host = input.trim();
    if host.is_empty() {
        return Err("Remote host is required".into());
    }
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if bare.parse::<std::net::IpAddr>().is_ok() {
        return Ok(bare.to_string());
    }
    // SOCKS5 ATYP_DOMAIN caps the name at 255 bytes; DNS at 253.
    if host.len() > 253 {
        return Err("Remote host is too long (253 characters max)".into());
    }
    for label in host.split('.') {
        if label.is_empty() {
            return Err("Remote host has an empty label — check the dots".into());
        }
        if label.len() > 63 {
            return Err("Remote host has a label longer than 63 characters".into());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("Remote host labels can't start or end with a hyphen".into());
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(
                "Remote host may only contain letters, digits, dots, hyphens and underscores"
                    .into(),
            );
        }
    }
    Ok(host.to_string())
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

    pub fn validate(
        &self,
        existing: &[PortForward],
        socks_port: u16,
        http_port: Option<u16>,
    ) -> Result<PortForward, String> {
        let label = self.label.trim();
        if label.len() > 64 {
            return Err("Label must be 64 characters or fewer".into());
        }
        let local_port = parse_port(&self.local_port, "Local port")?;
        let remote_host = validate_remote_host(&self.remote_host)?;
        let remote_port = parse_port(&self.remote_port, "Remote port")?;
        if local_port == socks_port {
            return Err(format!("Port {local_port} is the SOCKS5 proxy port"));
        }
        if Some(local_port) == http_port {
            return Err(format!("Port {local_port} is the HTTP proxy port"));
        }
        if existing
            .iter()
            .any(|f| f.local_port == local_port && Some(&f.id) != self.editing_id.as_ref())
        {
            return Err(format!("Another forward already uses local port {local_port}"));
        }
        Ok(PortForward {
            id: self
                .editing_id
                .clone()
                .unwrap_or_else(PortForward::new_id),
            label: label.to_string(),
            local_port,
            remote_host,
            remote_port,
            enabled: self.enabled,
        })
    }
}

/// Enable/disable semantics for the per-forward switch: a forward whose initial
/// setup failed (its listener could not bind — e.g. the local port is in use)
/// is flipped back off instead of sitting enabled-but-failed. `Failed` is only
/// ever set at bind time (see `forward::run_forward`), so every failed status
/// is a setup failure. Returns the `(id, reason)` pairs of the forwards
/// disabled, for display next to their rows.
fn disable_failed_forwards(
    forwards: &mut [PortForward],
    statuses: &[ForwardStatus],
) -> Vec<(String, String)> {
    let mut disabled = Vec::new();
    for status in statuses {
        if let ForwardState::Failed(reason) = &status.state
            && let Some(forward) = forwards
                .iter_mut()
                .find(|f| f.id == status.id && f.enabled)
        {
            forward.enabled = false;
            disabled.push((forward.id.clone(), reason.clone()));
        }
    }
    disabled
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
    #[cfg(not(any(target_os = "macos", windows)))]
    let result = std::process::Command::new("xdg-open").arg(&dir).spawn();
    if let Err(e) = result {
        log::error!("Failed to open the log folder {}: {e}", dir.display());
    }
}

/// Menu-bar app: no Dock icon, no app switcher entry. winit applies the
/// Regular policy during launch (overriding the bundle's LSUIElement), so this
/// runs afterwards, from the first update.
#[cfg(target_os = "macos")]
fn set_accessory_policy() {
    use objc2::MainThreadMarker;
    use objc2_app_kit::{NSApplication, NSApplicationActivationPolicy};
    match MainThreadMarker::new() {
        Some(mtm) => {
            NSApplication::sharedApplication(mtm)
                .setActivationPolicy(NSApplicationActivationPolicy::Accessory);
        }
        None => log::warn!("Not on the main thread; leaving the activation policy alone"),
    }
}

fn window_settings() -> window::Settings {
    let (rgba, width, height) = icon::window_icon_rgba(256);
    window::Settings {
        size: Size::new(500.0, 640.0),
        min_size: Some(Size::new(430.0, 500.0)),
        icon: window::icon::from_rgba(rgba, width, height).ok(),
        ..window::Settings::default()
    }
}

pub struct App {
    controller: Controller,
    tray: Option<Tray>,
    window: Option<window::Id>,
    pub tab: Tab,
    pub form: SettingsForm,
    pub saved: Option<AppConfig>,
    pub settings_notice: Option<String>,
    pub forwards: Vec<PortForward>,
    pub forward_form: Option<ForwardForm>,
    pub forwards_notice: Option<String>,
    /// Setup-failure reason per forward id, retained after the failed forward
    /// is auto-stopped (see [`disable_failed_forwards`]) so the row can keep
    /// showing why; cleared when the forward is started again or removed.
    pub forward_errors: HashMap<String, String>,
    /// Advisory-badge cache: the `RoutedSet` rebuilt only when the pushed
    /// domains/CIDRs change (`None` inside means the set failed to parse).
    pub routed_cache: view::RoutedCache,
    log_revision: u64,
    /// The in-memory log ring joined for the Logs tab, refreshed on revision
    /// change only.
    pub log_text: String,
    clipboard: Option<arboard::Clipboard>,
    /// Refreshed by [`App::refresh`] on every tick, rendered by `view`.
    pub snapshot: Snapshot,
}

impl App {
    pub fn boot() -> (Self, Task<Message>) {
        let controller = Controller::start();

        let saved = match config::load() {
            Ok(saved) => saved,
            Err(e) => {
                log::error!("{e:#}");
                None
            }
        };
        let form = SettingsForm::from_config(saved.as_ref().unwrap_or(&AppConfig::default()));
        let tab = if saved.is_some() {
            Tab::Status
        } else {
            Tab::Settings
        };

        // Push the persisted forwards to the tunnel thread up front. They all
        // load disabled (`enabled` is runtime-only), so nothing listens until
        // the user flips a forward on.
        let forwards = forward::load();
        controller.set_forwards(forwards.clone());

        let mut app = Self {
            controller,
            tray: None,
            window: None,
            tab,
            form,
            saved,
            settings_notice: None,
            forwards,
            forward_form: None,
            forwards_notice: None,
            forward_errors: HashMap::new(),
            routed_cache: None,
            log_revision: 0,
            log_text: String::new(),
            clipboard: None,
            snapshot: Snapshot::default(),
        };
        let open = app.open_window();
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
            // Steady heartbeat so the snapshot and tray state stay fresh even
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
                #[cfg(target_os = "macos")]
                set_accessory_policy();
                match Tray::new() {
                    Ok(tray) => self.tray = Some(tray),
                    Err(e) => log::error!("Failed to create the tray icon: {e:#}"),
                }
                self.refresh();
                Task::none()
            }
            Message::TrayMenu(id) => self.handle_menu_event(&id),
            Message::TrayIcon(event) => {
                // Windows convention: left click on the tray icon toggles the
                // window. On macOS the left click opens the menu natively.
                #[cfg(not(target_os = "macos"))]
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
                // tray. Quit comes from the tray menu.
                if self.window == Some(id) {
                    self.window = None;
                }
                Task::none()
            }
            Message::TabSelected(tab) => {
                self.tab = tab;
                Task::none()
            }
            Message::Connect => self.connect(),
            Message::Disconnect => {
                self.controller.disconnect();
                Task::none()
            }
            Message::CopyText(text) => {
                self.copy_text(text);
                Task::none()
            }
            Message::ServerNodeIdChanged(value) => {
                self.form.server_node_id = value;
                Task::none()
            }
            Message::AuthTokenChanged(value) => {
                self.form.auth_token = value;
                Task::none()
            }
            Message::SocksPortChanged(value) => {
                self.form.socks_port = value;
                Task::none()
            }
            Message::HttpEnabledToggled(enabled) => {
                self.form.http_enabled = enabled;
                Task::none()
            }
            Message::HttpPortChanged(value) => {
                self.form.http_port = value;
                Task::none()
            }
            Message::RelayUrlsChanged(value) => {
                self.form.relay_urls = value;
                Task::none()
            }
            Message::SaveSettings => {
                self.save_settings();
                Task::none()
            }
            Message::AddForward => {
                self.forward_form = Some(ForwardForm::add());
                Task::none()
            }
            Message::EditForward(i) => {
                if let Some(forward) = self.forwards.get(i) {
                    self.forward_form = Some(ForwardForm::edit(forward));
                }
                Task::none()
            }
            Message::DeleteForward(i) => {
                if i < self.forwards.len() {
                    let forward = self.forwards.remove(i);
                    self.forward_errors.remove(&forward.id);
                    self.commit_forwards();
                }
                Task::none()
            }
            Message::ToggleForward(i, enabled) => {
                if let Some(forward) = self.forwards.get_mut(i) {
                    // Desired state, but not a plain checkbox: enabling
                    // attempts the setup now, and a setup failure snaps the
                    // switch back off (see disable_failed_forwards).
                    forward.enabled = enabled;
                    let id = forward.id.clone();
                    if enabled {
                        // A fresh start attempt supersedes the old failure.
                        self.forward_errors.remove(&id);
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

    /// The proxy ports the forward form validates against (defaults while
    /// nothing is saved yet).
    pub fn proxy_ports(&self) -> (u16, Option<u16>) {
        let default = AppConfig::default();
        let config = self.saved.as_ref().unwrap_or(&default);
        (config.socks_port, config.http_port)
    }

    fn open_window(&mut self) -> Task<Message> {
        let (id, open) = window::open(window_settings());
        self.window = Some(id);
        open.map(|_| Message::WindowOpened)
    }

    fn show_window(&mut self) -> Task<Message> {
        match self.window {
            Some(id) => window::gain_focus(id),
            None => self.open_window(),
        }
    }

    fn connect(&mut self) -> Task<Message> {
        match &self.saved {
            Some(config) => {
                self.controller.connect(config.clone());
                Task::none()
            }
            None => {
                self.tab = Tab::Settings;
                self.settings_notice = Some("Configure and save the connection first.".into());
                self.show_window()
            }
        }
    }

    fn handle_menu_event(&mut self, id: &str) -> Task<Message> {
        match id {
            tray::MENU_CONNECT => self.connect(),
            tray::MENU_DISCONNECT => {
                self.controller.disconnect();
                Task::none()
            }
            tray::MENU_COPY_SOCKS => {
                if let Some(addr) = self.snapshot.socks_addr {
                    self.copy_text(format!("socks5://{addr}"));
                }
                Task::none()
            }
            tray::MENU_OPEN => self.show_window(),
            tray::MENU_QUIT => {
                self.controller.shutdown();
                iced::exit()
            }
            _ => Task::none(),
        }
    }

    /// Poll the tunnel snapshot and derived state; runs on every tick and
    /// after the tray is created.
    fn refresh(&mut self) {
        self.snapshot = self.controller.snapshot();

        // Runs every tick (not just on the Forwards tab) so a forward whose
        // setup failed snaps back to stopped promptly.
        let failed = disable_failed_forwards(&mut self.forwards, &self.snapshot.forwards);
        if !failed.is_empty() {
            self.forward_errors.extend(failed);
            self.commit_forwards();
        }

        view::refresh_routed_cache(&mut self.routed_cache, &self.snapshot.routes);

        let revision = logging::revision();
        if revision != self.log_revision || self.log_text.is_empty() {
            self.log_revision = revision;
            self.log_text = logging::recent_lines().join("\n");
        }

        if let Some(tray) = &mut self.tray {
            tray.sync(self.snapshot.phase, self.saved.is_some(), self.snapshot.socks_addr);
        }
    }

    fn save_settings(&mut self) {
        let Ok(config) = self.form.validate() else {
            return;
        };
        match config::save(&config) {
            Ok(()) => {
                let mut notice = if self.snapshot.phase == Phase::Idle {
                    "Saved.".to_string()
                } else {
                    "Saved — reconnect to apply.".to_string()
                };
                // Soft warning only — the hard guard is the forward's bind
                // failing visibly ("port N is in use").
                if let Some(forward) = self.forwards.iter().find(|f| {
                    f.enabled
                        && (f.local_port == config.socks_port
                            || Some(f.local_port) == config.http_port)
                }) {
                    notice.push_str(&format!(
                        " Forward \"{}\" uses port {} and will fail to bind.",
                        forward.display_name(),
                        forward.local_port
                    ));
                }
                self.saved = Some(config);
                self.settings_notice = Some(notice);
            }
            Err(e) => {
                log::error!("{e:#}");
                self.settings_notice = Some(format!("{e:#}"));
            }
        }
    }

    fn save_forward_form(&mut self) {
        let Some(form) = &self.forward_form else {
            return;
        };
        let (socks_port, http_port) = self.proxy_ports();
        let Ok(saved) = form.validate(&self.forwards, socks_port, http_port) else {
            return;
        };
        if saved.enabled {
            // The edit may fix what failed (e.g. a new local port); the fresh
            // start attempt supersedes the old failure.
            self.forward_errors.remove(&saved.id);
        }
        match self.forwards.iter_mut().find(|f| f.id == saved.id) {
            Some(slot) => *slot = saved,
            None => self.forwards.push(saved),
        }
        self.commit_forwards();
        self.forward_form = None;
    }

    /// Persist the forward list and push it to the tunnel thread (live apply).
    fn commit_forwards(&mut self) {
        match forward::save(&self.forwards) {
            Ok(()) => self.forwards_notice = None,
            Err(e) => {
                log::error!("Failed to save forwards: {e:#}");
                self.forwards_notice = Some(format!("Failed to save forwards: {e:#}"));
            }
        }
        self.controller.set_forwards(self.forwards.clone());
    }

    fn copy_text(&mut self, text: String) {
        if self.clipboard.is_none() {
            match arboard::Clipboard::new() {
                Ok(clipboard) => self.clipboard = Some(clipboard),
                Err(e) => {
                    log::error!("Clipboard unavailable: {e}");
                    return;
                }
            }
        }
        if let Some(clipboard) = &mut self.clipboard
            && let Err(e) = clipboard.set_text(text)
        {
            log::error!("Failed to copy to the clipboard: {e}");
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

    fn valid_form() -> SettingsForm {
        SettingsForm {
            server_node_id: " node-id ".into(),
            auth_token: flextunnel_core::auth::generate_client_token(),
            socks_port: "1080".into(),
            http_enabled: false,
            http_port: "8080".into(),
            relay_urls: " https://a.example ,, https://b.example ".into(),
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

    #[test]
    fn failed_forward_is_toggled_off() {
        let mut forwards = vec![existing_forward("a", 8080), existing_forward("b", 8081)];
        let statuses = vec![
            ForwardStatus {
                id: "a".into(),
                state: ForwardState::Failed("port 8080 is in use".into()),
                active: 0,
                last_conn_error: None,
            },
            ForwardStatus {
                id: "b".into(),
                state: ForwardState::Listening,
                active: 0,
                last_conn_error: None,
            },
        ];

        let disabled = disable_failed_forwards(&mut forwards, &statuses);
        assert_eq!(
            disabled,
            vec![("a".to_string(), "port 8080 is in use".to_string())]
        );
        assert!(!forwards[0].enabled, "failed forward flips off");
        assert!(forwards[1].enabled, "listening forward untouched");

        // Idempotent: an already-disabled forward is not reported again while
        // its stale Failed status lingers for a frame.
        assert!(disable_failed_forwards(&mut forwards, &statuses).is_empty());
    }

    #[test]
    fn forward_form_trims_and_builds() {
        let forward = valid_forward_form()
            .validate(&[], 1080, None)
            .expect("valid");
        assert_eq!(forward.label, "db");
        assert_eq!(forward.local_port, 5432);
        assert_eq!(forward.remote_host, "db.internal");
        assert_eq!(forward.remote_port, 5432);
        assert!(forward.enabled);
        assert!(!forward.id.is_empty());
    }

    #[test]
    fn remote_host_validation() {
        // Valid hostnames and IP literals, normalized where relevant.
        assert_eq!(validate_remote_host(" db.internal "), Ok("db.internal".into()));
        assert_eq!(
            validate_remote_host("net_dev-1.example.com"),
            Ok("net_dev-1.example.com".into())
        );
        assert_eq!(validate_remote_host("10.0.0.7"), Ok("10.0.0.7".into()));
        assert_eq!(validate_remote_host("::1"), Ok("::1".into()));
        assert_eq!(validate_remote_host("[2001:db8::1]"), Ok("2001:db8::1".into()));

        // The typo class that motivated this: empty labels.
        assert!(validate_remote_host("networking..internal").is_err());
        assert!(validate_remote_host(".internal").is_err());
        assert!(validate_remote_host("internal.").is_err());

        assert!(validate_remote_host("").is_err());
        assert!(validate_remote_host("has space.com").is_err());
        assert!(validate_remote_host("bad!char.com").is_err());
        assert!(validate_remote_host("-leading.com").is_err());
        assert!(validate_remote_host("trailing-.com").is_err());
        assert!(validate_remote_host(&"a".repeat(64)).is_err());
        assert!(validate_remote_host(&format!("{}.com", "a.".repeat(130))).is_err());
    }

    #[test]
    fn forward_form_rejects_bad_input() {
        let mut form = valid_forward_form();
        form.local_port = "0".into();
        assert!(form.validate(&[], 1080, None).is_err());

        let mut form = valid_forward_form();
        form.remote_host = "  ".into();
        assert!(form.validate(&[], 1080, None).is_err());

        let mut form = valid_forward_form();
        form.remote_host = "networking..internal".into();
        assert!(form.validate(&[], 1080, None).is_err());

        let mut form = valid_forward_form();
        form.label = "x".repeat(65);
        assert!(form.validate(&[], 1080, None).is_err());

        let mut form = valid_forward_form();
        form.remote_port = "70000".into();
        assert!(form.validate(&[], 1080, None).is_err());

        // Collisions with the proxy ports.
        let form = valid_forward_form();
        assert!(form.validate(&[], 5432, None).is_err());
        assert!(form.validate(&[], 1080, Some(5432)).is_err());

        // Duplicate local port among existing forwards…
        let taken = existing_forward("aaaa", 5432);
        assert!(form.validate(std::slice::from_ref(&taken), 1080, None).is_err());

        // …unless it is the forward being edited (id reused).
        let mut form = valid_forward_form();
        form.editing_id = Some("aaaa".into());
        let edited = form
            .validate(std::slice::from_ref(&taken), 1080, None)
            .expect("editing the same forward");
        assert_eq!(edited.id, "aaaa");
    }

    #[test]
    fn validate_trims_and_parses() {
        let config = valid_form().validate().expect("valid");
        assert_eq!(config.server_node_id, "node-id");
        assert_eq!(config.socks_port, 1080);
        assert_eq!(config.http_port, None);
        assert_eq!(
            config.relay_urls,
            vec!["https://a.example".to_string(), "https://b.example".to_string()]
        );
    }

    #[test]
    fn validate_rejects_bad_input() {
        let mut form = valid_form();
        form.auth_token = "not-a-token".into();
        assert!(form.validate().is_err());

        let mut form = valid_form();
        form.socks_port = "0".into();
        assert!(form.validate().is_err());

        let mut form = valid_form();
        form.http_enabled = true;
        form.http_port = form.socks_port.clone();
        assert!(form.validate().is_err());

        let mut form = valid_form();
        form.server_node_id = "  ".into();
        assert!(form.validate().is_err());
    }

    #[test]
    fn duration_formatting() {
        assert_eq!(format_duration(Duration::from_secs(59)), "59s");
        assert_eq!(format_duration(Duration::from_secs(61)), "1m 01s");
        assert_eq!(format_duration(Duration::from_secs(3725)), "1h 02m 05s");
    }
}
