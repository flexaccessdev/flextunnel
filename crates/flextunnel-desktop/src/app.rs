//! The egui application: a Status / Settings / Logs tabbed window that hides
//! (rather than exits) on close, driven alongside the system tray. Tray and
//! menu events are forwarded from tray-icon's handlers into channels and
//! drained here at the top of every frame; the handlers also request a repaint
//! so a tray click wakes the loop immediately even while the window is hidden.

use crate::config::{self, AppConfig};
use crate::icon;
use crate::logging;
use crate::tray::{self, Tray};
use crate::tunnel::{Controller, Phase, Snapshot};
use eframe::egui::{self, Color32, RichText, TextEdit, TextStyle, ViewportCommand};
use std::net::SocketAddr;
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;
use tray_icon::menu::MenuEvent;
use tray_icon::TrayIconEvent;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Status,
    Settings,
    Logs,
}

/// Editable settings buffers, mirroring the iOS setup form's validation.
#[derive(Default)]
struct SettingsForm {
    server_node_id: String,
    auth_token: String,
    show_token: bool,
    socks_port: String,
    http_enabled: bool,
    http_port: String,
    relay_urls: String,
}

impl SettingsForm {
    fn from_config(config: &AppConfig) -> Self {
        Self {
            server_node_id: config.server_node_id.clone(),
            auth_token: config.auth_token.clone(),
            show_token: false,
            socks_port: config.socks_port.to_string(),
            http_enabled: config.http_port.is_some(),
            http_port: config
                .http_port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "8080".into()),
            relay_urls: config.relay_urls.join(", "),
        }
    }

    fn validate(&self) -> Result<AppConfig, String> {
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

/// Everything is tunneled when the server pushes no routed set at all, a
/// wildcard domain, or an all-covering CIDR (mirrors the iOS derivation).
fn is_full_tunnel(routes: &flextunnel_core::proxy::TunnelRoutes) -> bool {
    (routes.domains.is_empty() && routes.cidrs.is_empty())
        || routes.domains.iter().any(|d| d == "*")
        || routes.cidrs.iter().any(|c| c == "0.0.0.0/0" || c == "::/0")
}

fn format_duration(d: Duration) -> String {
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

pub struct App {
    controller: Controller,
    tray: Option<Tray>,
    menu_rx: Receiver<MenuEvent>,
    tray_rx: Receiver<TrayIconEvent>,
    tab: Tab,
    form: SettingsForm,
    saved: Option<AppConfig>,
    settings_notice: Option<String>,
    log_revision: u64,
    log_lines: Vec<String>,
    window_visible: bool,
    quitting: bool,
    clipboard: Option<arboard::Clipboard>,
    /// Refreshed in `logic()` each frame, rendered by `ui()`.
    snapshot: Snapshot,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, controller: Controller) -> Self {
        // Forward tray/menu events into channels drained in update(). The
        // handlers replace tray-icon's default channel delivery, and the
        // repaint request wakes the loop even while the window is hidden.
        let (menu_tx, menu_rx) = channel();
        let ctx = cc.egui_ctx.clone();
        MenuEvent::set_event_handler(Some(move |event| {
            let _ = menu_tx.send(event);
            ctx.request_repaint();
        }));
        let (tray_tx, tray_rx) = channel();
        let ctx = cc.egui_ctx.clone();
        TrayIconEvent::set_event_handler(Some(move |event| {
            let _ = tray_tx.send(event);
            ctx.request_repaint();
        }));

        // Created here so it lands on the main thread with the event loop live
        // (a macOS requirement). Kept for the app's lifetime — dropping the
        // TrayIcon removes it from the tray.
        let tray = match Tray::new() {
            Ok(tray) => Some(tray),
            Err(e) => {
                log::error!("Failed to create the tray icon: {e:#}");
                None
            }
        };

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

        Self {
            controller,
            tray,
            menu_rx,
            tray_rx,
            tab,
            form,
            saved,
            settings_notice: None,
            log_revision: 0,
            log_lines: Vec::new(),
            window_visible: true,
            quitting: false,
            clipboard: None,
            snapshot: Snapshot::default(),
        }
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

    fn set_window_visible(&mut self, ctx: &egui::Context, visible: bool) {
        self.window_visible = visible;
        ctx.send_viewport_cmd(ViewportCommand::Visible(visible));
        if visible {
            ctx.send_viewport_cmd(ViewportCommand::Focus);
        }
    }

    fn connect(&mut self, ctx: &egui::Context) {
        match &self.saved {
            Some(config) => self.controller.connect(config.clone()),
            None => {
                self.tab = Tab::Settings;
                self.settings_notice = Some("Configure and save the connection first.".into());
                self.set_window_visible(ctx, true);
            }
        }
    }

    fn socks_proxy_string(snapshot: &Snapshot) -> Option<String> {
        snapshot.socks_addr.map(|a| format!("socks5://{a}"))
    }

    fn handle_menu_event(&mut self, ctx: &egui::Context, id: &str, snapshot: &Snapshot) {
        match id {
            tray::MENU_CONNECT => self.connect(ctx),
            tray::MENU_DISCONNECT => self.controller.disconnect(),
            tray::MENU_COPY_SOCKS => {
                if let Some(text) = Self::socks_proxy_string(snapshot) {
                    self.copy_text(text);
                }
            }
            tray::MENU_OPEN => self.set_window_visible(ctx, true),
            tray::MENU_QUIT => {
                self.quitting = true;
                ctx.send_viewport_cmd(ViewportCommand::Visible(true));
                ctx.send_viewport_cmd(ViewportCommand::Close);
            }
            _ => {}
        }
    }

    fn status_tab(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        let (color, heading) = match snapshot.phase {
            Phase::Idle => (Color32::GRAY, "Disconnected"),
            Phase::Connecting => (Color32::from_rgb(230, 160, 30), "Connecting…"),
            Phase::Connected => (Color32::from_rgb(60, 180, 90), "Connected"),
            Phase::Reconnecting => (Color32::from_rgb(230, 160, 30), "Reconnecting…"),
            Phase::Failed => (Color32::from_rgb(220, 70, 70), "Connection failed"),
        };
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::hover());
            ui.painter().circle_filled(rect.center(), 6.0, color);
            ui.heading(heading);
        });
        if let Some(since) = snapshot.connected_since {
            ui.label(format!("for {}", format_duration(since.elapsed())));
        }
        if let Some(error) = &snapshot.last_error {
            ui.colored_label(Color32::from_rgb(220, 70, 70), error);
        }

        ui.add_space(8.0);
        match snapshot.phase {
            Phase::Idle | Phase::Failed => {
                let can_connect = self.saved.is_some();
                if ui
                    .add_enabled(can_connect, egui::Button::new("Connect"))
                    .clicked()
                {
                    let ctx = ui.ctx().clone();
                    self.connect(&ctx);
                }
                if !can_connect {
                    ui.label("Save the connection settings first.");
                }
            }
            _ => {
                if ui.button("Disconnect").clicked() {
                    self.controller.disconnect();
                }
            }
        }

        ui.add_space(8.0);
        ui.separator();

        let node_id = self
            .saved
            .as_ref()
            .map(|c| c.server_node_id.clone())
            .unwrap_or_default();
        let socks = snapshot
            .socks_addr
            .or_else(|| {
                self.saved
                    .as_ref()
                    .map(|c| SocketAddr::from(([127, 0, 0, 1], c.socks_port)))
            })
            .map(|a| a.to_string())
            .unwrap_or_default();
        let http = snapshot
            .http_addr
            .or_else(|| {
                self.saved.as_ref().and_then(|c| {
                    c.http_port.map(|p| SocketAddr::from(([127, 0, 0, 1], p)))
                })
            })
            .map(|a| a.to_string());

        egui::Grid::new("status-grid")
            .num_columns(3)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                ui.label("Server node id");
                ui.monospace(if node_id.is_empty() { "—" } else { &node_id });
                if !node_id.is_empty() && ui.small_button("copy").clicked() {
                    self.copy_text(node_id.clone());
                }
                ui.end_row();

                ui.label("SOCKS5 proxy");
                ui.monospace(if socks.is_empty() { "—" } else { &socks });
                if !socks.is_empty() && ui.small_button("copy").clicked() {
                    self.copy_text(format!("socks5://{socks}"));
                }
                ui.end_row();

                if let Some(http) = &http {
                    ui.label("HTTP proxy");
                    ui.monospace(http);
                    if ui.small_button("copy").clicked() {
                        self.copy_text(format!("http://{http}"));
                    }
                    ui.end_row();
                }
            });

        if snapshot.phase == Phase::Connected {
            ui.add_space(8.0);
            ui.separator();
            egui::ScrollArea::vertical()
                .id_salt("routes")
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    if is_full_tunnel(&snapshot.routes) {
                        ui.label("Routing: everything through the tunnel");
                    } else {
                        ui.label(format!(
                            "Split tunnel — {} domain(s), {} CIDR(s) routed through the server:",
                            snapshot.routes.domains.len(),
                            snapshot.routes.cidrs.len()
                        ));
                        for domain in &snapshot.routes.domains {
                            ui.monospace(domain);
                        }
                        for cidr in &snapshot.routes.cidrs {
                            ui.monospace(cidr);
                        }
                    }
                    if !snapshot.routes.host_aliases.is_empty() {
                        ui.add_space(8.0);
                        ui.label(format!(
                            "Host aliases — {} resolved server-side:",
                            snapshot.routes.host_aliases.len()
                        ));
                        for (alias, target) in &snapshot.routes.host_aliases {
                            ui.monospace(format!("{alias} → {target}"));
                        }
                    }
                    if !snapshot.routes.agent_aliases.is_empty() {
                        ui.add_space(8.0);
                        ui.label(format!(
                            "Agent routes — {} via connected agents:",
                            snapshot.routes.agent_aliases.len()
                        ));
                        for alias in &snapshot.routes.agent_aliases {
                            ui.monospace(alias);
                        }
                    }
                });
        }
    }

    fn settings_tab(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        egui::Grid::new("settings-grid")
            .num_columns(2)
            .spacing([12.0, 8.0])
            .show(ui, |ui| {
                ui.label("Server node id");
                ui.add(
                    TextEdit::singleline(&mut self.form.server_node_id)
                        .desired_width(f32::INFINITY),
                );
                ui.end_row();

                ui.label("Auth token");
                ui.horizontal(|ui| {
                    ui.add(
                        TextEdit::singleline(&mut self.form.auth_token)
                            .password(!self.form.show_token)
                            .desired_width(240.0),
                    );
                    ui.checkbox(&mut self.form.show_token, "show");
                });
                ui.end_row();

                ui.label("SOCKS5 port");
                ui.add(TextEdit::singleline(&mut self.form.socks_port).desired_width(80.0));
                ui.end_row();

                ui.label("HTTP proxy");
                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.form.http_enabled, "enable");
                    if self.form.http_enabled {
                        ui.label("port");
                        ui.add(
                            TextEdit::singleline(&mut self.form.http_port).desired_width(80.0),
                        );
                    }
                });
                ui.end_row();

                ui.label("Relay URLs");
                ui.add(
                    TextEdit::singleline(&mut self.form.relay_urls)
                        .hint_text("comma-separated, optional")
                        .desired_width(f32::INFINITY),
                );
                ui.end_row();
            });

        ui.add_space(8.0);
        let validated = self.form.validate();
        let dirty = match (&validated, &self.saved) {
            (Ok(candidate), Some(saved)) => candidate != saved,
            (Ok(_), None) => true,
            (Err(_), _) => false,
        };
        if let Err(message) = &validated {
            ui.colored_label(Color32::from_rgb(230, 160, 30), message);
        }
        ui.horizontal(|ui| {
            if ui
                .add_enabled(validated.is_ok() && dirty, egui::Button::new("Save"))
                .clicked()
            {
                let config = validated.as_ref().expect("validated").clone();
                match config::save(&config) {
                    Ok(()) => {
                        self.saved = Some(config);
                        self.settings_notice = Some(if snapshot.phase == Phase::Idle {
                            "Saved.".into()
                        } else {
                            "Saved — reconnect to apply.".into()
                        });
                    }
                    Err(e) => {
                        log::error!("{e:#}");
                        self.settings_notice = Some(format!("{e:#}"));
                    }
                }
            }
            if let Some(notice) = &self.settings_notice {
                ui.label(notice.clone());
            }
        });
        ui.add_space(4.0);
        ui.label(
            RichText::new("Stored as a single item in the system keychain.")
                .small()
                .weak(),
        );
    }

    fn logs_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("Open log folder").clicked() {
                open_log_folder();
            }
            if ui.button("Copy all").clicked() {
                self.copy_text(self.log_lines.join("\n"));
            }
        });
        ui.separator();

        let revision = logging::revision();
        if revision != self.log_revision || self.log_lines.is_empty() {
            self.log_revision = revision;
            self.log_lines = logging::recent_lines();
        }
        let row_height = ui.text_style_height(&TextStyle::Monospace);
        egui::ScrollArea::both()
            .stick_to_bottom(true)
            .auto_shrink([false, false])
            .show_rows(ui, row_height, self.log_lines.len(), |ui, range| {
                for line in &self.log_lines[range] {
                    ui.label(RichText::new(line).monospace());
                }
            });
    }
}

impl eframe::App for App {
    // Runs before every `ui()` pass and also on repaint requests while the
    // window is hidden — which is what keeps tray clicks and the tray state
    // live when no window is showing.
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.snapshot = self.controller.snapshot();
        let snapshot = self.snapshot.clone();

        while let Ok(event) = self.tray_rx.try_recv() {
            // Windows convention: left click on the tray icon toggles the
            // window. On macOS the left click opens the menu natively.
            #[cfg(not(target_os = "macos"))]
            if let TrayIconEvent::Click {
                button: tray_icon::MouseButton::Left,
                button_state: tray_icon::MouseButtonState::Up,
                ..
            } = event
            {
                let visible = !self.window_visible;
                self.set_window_visible(ctx, visible);
            }
            let _ = event;
        }
        let menu_events: Vec<MenuEvent> = self.menu_rx.try_iter().collect();
        for event in menu_events {
            self.handle_menu_event(ctx, event.id().as_ref(), &snapshot);
        }

        if let Some(tray) = &mut self.tray {
            tray.sync(snapshot.phase, self.saved.is_some(), snapshot.socks_addr);
        }

        // Closing the window hides it; the app lives in the tray. Quit comes
        // from the tray menu.
        if ctx.input(|i| i.viewport().close_requested()) && !self.quitting {
            ctx.send_viewport_cmd(ViewportCommand::CancelClose);
            self.set_window_visible(ctx, false);
        }

        // Steady heartbeat so the tray state stays fresh while the window is
        // hidden; tray handlers additionally wake the loop instantly.
        ctx.request_repaint_after(Duration::from_millis(500));
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let snapshot = self.snapshot.clone();
        egui::Panel::top("tabs").show(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Status, "Status");
                ui.selectable_value(&mut self.tab, Tab::Settings, "Settings");
                ui.selectable_value(&mut self.tab, Tab::Logs, "Logs");
            });
            ui.add_space(2.0);
        });
        egui::CentralPanel::default().show(ui, |ui| match self.tab {
            Tab::Status => self.status_tab(ui, &snapshot),
            Tab::Settings => self.settings_tab(ui, &snapshot),
            Tab::Logs => self.logs_tab(ui),
        });
    }

    fn on_exit(&mut self) {
        self.controller.shutdown();
    }
}

/// The window icon (full-color badge, matching the iOS light appearance).
pub fn window_icon() -> egui::IconData {
    let (rgba, width, height) = icon::window_icon_rgba(256);
    egui::IconData {
        rgba,
        width,
        height,
    }
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
            ..Default::default()
        }
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
    fn full_tunnel_derivation() {
        use flextunnel_core::proxy::TunnelRoutes;
        let mut routes = TunnelRoutes::default();
        assert!(is_full_tunnel(&routes));
        routes.domains = vec!["example.com".into()];
        assert!(!is_full_tunnel(&routes));
        routes.domains.push("*".into());
        assert!(is_full_tunnel(&routes));
        routes.domains = vec!["example.com".into()];
        routes.cidrs = vec!["0.0.0.0/0".into()];
        assert!(is_full_tunnel(&routes));
    }

    #[test]
    fn duration_formatting() {
        assert_eq!(format_duration(Duration::from_secs(59)), "59s");
        assert_eq!(format_duration(Duration::from_secs(61)), "1m 01s");
        assert_eq!(format_duration(Duration::from_secs(3725)), "1h 02m 05s");
    }
}
