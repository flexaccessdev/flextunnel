//! The egui application: a Status / Settings / Logs tabbed window that hides
//! (rather than exits) on close, driven alongside the system tray. Tray and
//! menu events are forwarded from tray-icon's handlers into channels and
//! drained here at the top of every frame; the handlers also request a repaint
//! so a tray click wakes the loop immediately even while the window is hidden.

use crate::config::{self, AppConfig};
use crate::forward::{self, ForwardState, ForwardStatus, PortForward};
use crate::icon;
use crate::logging;
use crate::tray::{self, Tray};
use crate::tunnel::{Controller, Phase, Snapshot};
use eframe::egui::{self, Color32, RichText, TextEdit, TextStyle, ViewportCommand};
use flextunnel_core::proxy::signaling::Target;
use flextunnel_core::proxy::{reserved, AgentConnState, RoutedSet, TunnelRoutes};
use std::net::SocketAddr;
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};
use tray_icon::menu::MenuEvent;
use tray_icon::TrayIconEvent;

const GREEN: Color32 = Color32::from_rgb(60, 180, 90);
const AMBER: Color32 = Color32::from_rgb(230, 160, 30);
const RED: Color32 = Color32::from_rgb(220, 70, 70);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Status,
    Forwards,
    Settings,
    Logs,
}

/// Editable settings buffers, mirroring the iOS setup form's validation.
#[derive(Default)]
struct SettingsForm {
    server_node_id: String,
    auth_token: String,
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
struct ForwardForm {
    editing_id: Option<String>,
    label: String,
    local_port: String,
    remote_host: String,
    remote_port: String,
    enabled: bool,
}

impl ForwardForm {
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

    fn validate(
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

/// Everything is tunneled when the server pushes no routed set at all, a
/// wildcard domain, or an all-covering CIDR (mirrors the iOS derivation).
fn is_full_tunnel(routes: &TunnelRoutes) -> bool {
    (routes.domains.is_empty() && routes.cidrs.is_empty())
        || routes.domains.iter().any(|d| d == "*")
        || routes.cidrs.iter().any(|c| c == "0.0.0.0/0" || c == "::/0")
}

/// Advisory tunneled/direct badge for a forward (`None` = hidden). Mirrors the
/// core's routing decision — reserved hosts always tunnel, everything else per
/// the routed set — but never gates traffic; the core decides for real per
/// connection (like the iOS badge).
fn forward_badge(
    phase: Phase,
    routes: &TunnelRoutes,
    routed_set: Option<&RoutedSet>,
    forward: &PortForward,
) -> Option<bool> {
    if phase != Phase::Connected {
        return None;
    }
    if is_full_tunnel(routes) || reserved::is_reserved_host(&forward.remote_host) {
        return Some(true);
    }
    let set = routed_set?;
    Some(set.allows(&Target::Domain(
        forward.remote_host.clone(),
        forward.remote_port,
    )))
}

/// One-line live status for a forward row (text, color), mirroring the iOS
/// row: gray "off"/"stopped", green "listening (· N active)", red failure.
fn forward_status_line(
    forward: &PortForward,
    status: Option<&ForwardStatus>,
    phase: Phase,
) -> (String, Color32) {
    if !forward.enabled {
        return ("off".into(), Color32::GRAY);
    }
    match status {
        Some(status) => match &status.state {
            ForwardState::Listening if status.active > 0 => {
                (format!("listening · {} active", status.active), GREEN)
            }
            ForwardState::Listening => ("listening".into(), GREEN),
            ForwardState::Failed(reason) => (reason.clone(), RED),
        },
        // No status = no running session for this forward.
        None => match phase {
            Phase::Idle | Phase::Failed => ("stopped — connect to start".into(), Color32::GRAY),
            _ => ("stopped".into(), Color32::GRAY),
        },
    }
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
    forwards: Vec<PortForward>,
    forward_form: Option<ForwardForm>,
    forwards_notice: Option<String>,
    /// Advisory-badge cache: the `RoutedSet` rebuilt only when the pushed
    /// domains/CIDRs change (`None` inside means the set failed to parse).
    routed_cache: Option<(Vec<String>, Vec<String>, Option<RoutedSet>)>,
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

        // Push the persisted forwards to the tunnel thread up front so they
        // start with the first session.
        let forwards = forward::load();
        controller.set_forwards(forwards.clone());

        Self {
            controller,
            tray,
            menu_rx,
            tray_rx,
            tab,
            form,
            saved,
            settings_notice: None,
            forwards,
            forward_form: None,
            forwards_notice: None,
            routed_cache: None,
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
            Phase::Connecting => (AMBER, "Connecting…"),
            Phase::Connected => (GREEN, "Connected"),
            Phase::Reconnecting => (AMBER, "Reconnecting…"),
            Phase::Failed => (RED, "Connection failed"),
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
            ui.colored_label(RED, error);
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
                            "Agent routes — {} via agents:",
                            snapshot.routes.agent_aliases.len()
                        ));
                        for (alias, state) in snapshot.routes.agent_states(Instant::now()) {
                            let (label, color) = match state {
                                AgentConnState::Connected => {
                                    ("connected", egui::Color32::from_rgb(0x2e, 0xa0, 0x43))
                                }
                                AgentConnState::Disconnected => {
                                    ("disconnected", egui::Color32::from_rgb(0xc0, 0x39, 0x2b))
                                }
                                AgentConnState::Unknown => ("unknown", egui::Color32::GRAY),
                            };
                            ui.horizontal(|ui| {
                                ui.monospace(&alias);
                                ui.colored_label(color, label);
                            });
                        }
                    }
                });
        }
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

    /// Rebuild the advisory-badge `RoutedSet` only when the pushed routes change.
    fn refresh_routed_cache(&mut self, routes: &TunnelRoutes) {
        let fresh = matches!(&self.routed_cache,
            Some((domains, cidrs, _)) if *domains == routes.domains && *cidrs == routes.cidrs);
        if !fresh {
            let set = RoutedSet::new(&routes.domains, &routes.cidrs)
                .inspect_err(|e| log::debug!("Routed set unusable for the badge: {e:#}"))
                .ok();
            self.routed_cache = Some((routes.domains.clone(), routes.cidrs.clone(), set));
        }
    }

    fn forwards_tab(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        self.refresh_routed_cache(&snapshot.routes);

        ui.horizontal(|ui| {
            if ui.button("Add forward").clicked() {
                self.forward_form = Some(ForwardForm::add());
            }
            if let Some(notice) = &self.forwards_notice {
                ui.colored_label(AMBER, notice.clone());
            }
        });

        // Inline add/edit form — one at a time; an inline group fits the small
        // window better than a floating window.
        let mut save: Option<PortForward> = None;
        let mut close_form = false;
        if let Some(form) = &mut self.forward_form {
            let (socks_port, http_port) = {
                let default = AppConfig::default();
                let config = self.saved.as_ref().unwrap_or(&default);
                (config.socks_port, config.http_port)
            };
            ui.add_space(6.0);
            ui.group(|ui| {
                egui::Grid::new("forward-form")
                    .num_columns(2)
                    .spacing([12.0, 8.0])
                    .show(ui, |ui| {
                        ui.label("Label");
                        ui.add(
                            TextEdit::singleline(&mut form.label)
                                .hint_text("optional")
                                .desired_width(f32::INFINITY),
                        );
                        ui.end_row();

                        ui.label("Local port");
                        ui.add(TextEdit::singleline(&mut form.local_port).desired_width(80.0));
                        ui.end_row();

                        ui.label("Remote host");
                        ui.add(
                            TextEdit::singleline(&mut form.remote_host)
                                .hint_text("host or IP — resolved server-side")
                                .desired_width(f32::INFINITY),
                        );
                        ui.end_row();

                        ui.label("Remote port");
                        ui.add(TextEdit::singleline(&mut form.remote_port).desired_width(80.0));
                        ui.end_row();

                        ui.label("Enabled");
                        ui.checkbox(&mut form.enabled, "");
                        ui.end_row();
                    });
                let validated = form.validate(&self.forwards, socks_port, http_port);
                if let Err(message) = &validated {
                    ui.colored_label(AMBER, message);
                }
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(validated.is_ok(), egui::Button::new("Save"))
                        .clicked()
                    {
                        save = validated.ok();
                    }
                    if ui.button("Cancel").clicked() {
                        close_form = true;
                    }
                });
            });
        }
        if let Some(saved) = save {
            match self.forwards.iter_mut().find(|f| f.id == saved.id) {
                Some(slot) => *slot = saved,
                None => self.forwards.push(saved),
            }
            self.commit_forwards();
            close_form = true;
        }
        if close_form {
            self.forward_form = None;
        }

        ui.add_space(8.0);
        ui.separator();

        if self.forwards.is_empty() {
            ui.label(
                RichText::new(
                    "No port forwards. Add one to expose a remote service on localhost.",
                )
                .weak(),
            );
            return;
        }

        enum RowAction {
            Toggle(usize, bool),
            Edit(usize),
            Delete(usize),
        }
        let mut action: Option<RowAction> = None;
        let routed_set = self.routed_cache.as_ref().and_then(|(_, _, set)| set.as_ref());

        egui::ScrollArea::vertical()
            .id_salt("forwards")
            .auto_shrink([false, true])
            .show(ui, |ui| {
                for (i, forward) in self.forwards.iter().enumerate() {
                    let status = snapshot.forwards.iter().find(|s| s.id == forward.id);
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            let mut enabled = forward.enabled;
                            if ui.checkbox(&mut enabled, "").changed() {
                                action = Some(RowAction::Toggle(i, enabled));
                            }
                            ui.label(RichText::new(forward.display_name()).strong());
                            if let Some(tunneled) = forward_badge(
                                snapshot.phase,
                                &snapshot.routes,
                                routed_set,
                                forward,
                            ) {
                                let (text, color) = if tunneled {
                                    ("tunneled", GREEN)
                                } else {
                                    ("direct", AMBER)
                                };
                                ui.label(RichText::new(text).small().color(color));
                            }
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui.small_button("delete").clicked() {
                                        action = Some(RowAction::Delete(i));
                                    }
                                    if ui.small_button("edit").clicked() {
                                        action = Some(RowAction::Edit(i));
                                    }
                                },
                            );
                        });
                        ui.monospace(forward.route_description());
                        let (text, color) = forward_status_line(forward, status, snapshot.phase);
                        ui.label(RichText::new(text).small().color(color));
                        if forward.enabled
                            && let Some(error) = status.and_then(|s| s.last_conn_error.as_deref())
                        {
                            ui.label(RichText::new(error).small().color(AMBER));
                        }
                    });
                }
            });

        ui.add_space(4.0);
        ui.label(
            RichText::new(
                "Forwards listen on localhost only (127.0.0.1 and ::1) and relay through \
                 this app's SOCKS5 proxy while connected.",
            )
            .small()
            .weak(),
        );

        match action {
            Some(RowAction::Toggle(i, enabled)) => {
                self.forwards[i].enabled = enabled;
                self.commit_forwards();
            }
            Some(RowAction::Edit(i)) => {
                self.forward_form = Some(ForwardForm::edit(&self.forwards[i]));
            }
            Some(RowAction::Delete(i)) => {
                self.forwards.remove(i);
                self.commit_forwards();
            }
            None => {}
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
                ui.add(
                    TextEdit::singleline(&mut self.form.auth_token)
                        .password(true)
                        .desired_width(240.0),
                );
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
            ui.colored_label(AMBER, message);
        }
        ui.horizontal(|ui| {
            if ui
                .add_enabled(validated.is_ok() && dirty, egui::Button::new("Save"))
                .clicked()
            {
                let config = validated.as_ref().expect("validated").clone();
                match config::save(&config) {
                    Ok(()) => {
                        let mut notice = if snapshot.phase == Phase::Idle {
                            "Saved.".to_string()
                        } else {
                            "Saved — reconnect to apply.".to_string()
                        };
                        // Soft warning only — the hard guard is the forward's
                        // bind failing visibly ("port N is in use").
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
            // `show_rows` measures content width from only the visible rows, so
            // as lines of differing widths scroll past the bottom the horizontal
            // bar would flicker on/off, stealing vertical space and making the
            // stuck-to-bottom view jump. Always reserving both bars keeps the
            // viewport height stable.
            .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
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
                ui.selectable_value(&mut self.tab, Tab::Forwards, "Forwards");
                ui.selectable_value(&mut self.tab, Tab::Settings, "Settings");
                ui.selectable_value(&mut self.tab, Tab::Logs, "Logs");
            });
            ui.add_space(2.0);
        });
        egui::CentralPanel::default().show(ui, |ui| match self.tab {
            Tab::Status => self.status_tab(ui, &snapshot),
            Tab::Forwards => self.forwards_tab(ui, &snapshot),
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
