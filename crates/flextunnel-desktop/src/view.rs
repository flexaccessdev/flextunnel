//! Widget tree for the sidebar (the client connections, then the server) +
//! detail-pane window (or the first-run intro), rendered from
//! [`App`] state — all pure functions of `&App`, every mutation flows back
//! through a [`Message`]. The look (cards, pills, ghost buttons, sidebar rows)
//! comes from the design system in [`crate::style`].

use crate::app::{
    format_duration, App, ClientForm, ForwardForm, IdentityChoice, KeyChoice, KeyForm, LogFilter,
    Message, ProfileForm, Selection, ServerForm,
};
use crate::config::{self, AuthKey, AuthorizedClient, Profile, ServerConfig};
use crate::server_session::ServerPhase;
use crate::tray::clients_connected;
use flextunnel_core::forwards::{ForwardState, ForwardStatus, PortForward};
use crate::style::{self, AMBER, GRAY, GREEN, RED};
use crate::tunnel::{Phase, Snapshot};
use flextunnel_core::proxy::signaling::Target;
use flextunnel_core::proxy::{reserved, RoutedSet, TunnelRoutes};
use flextunnel_core::transport::paths::{ConnPathKind, ConnectionSnapshot, CustomRelayStatus};
use iced::widget::{
    button, center, checkbox, column, container, mouse_area, opaque, pick_list, row, scrollable,
    space, stack, text, text_input, toggler, Column,
};
use iced::{Center, Color, Element, Fill, Font};
use std::net::SocketAddr;

/// Advisory-badge cache: the `RoutedSet` rebuilt only when the pushed
/// domains/CIDRs change (`None` inside means the set failed to parse).
pub type RoutedCache = Option<(Vec<String>, Vec<String>, Option<RoutedSet>)>;

/// Rebuild the advisory-badge `RoutedSet` only when the pushed routes change.
pub fn refresh_routed_cache(cache: &mut RoutedCache, routes: &TunnelRoutes) {
    let fresh = matches!(cache,
        Some((domains, cidrs, _)) if *domains == routes.domains && *cidrs == routes.cidrs);
    if !fresh {
        let set = RoutedSet::new(&routes.domains, &routes.cidrs)
            .inspect_err(|e| log::debug!("Routed set unusable for the badge: {e:#}"))
            .ok();
        *cache = Some((routes.domains.clone(), routes.cidrs.clone(), set));
    }
}

/// Everything is tunneled when the server pushes a wildcard domain or an
/// all-covering CIDR. An empty set tunnels nothing but the reserved hosts.
fn is_full_tunnel(routes: &TunnelRoutes) -> bool {
    routes.domains.iter().any(|d| d == "*")
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

/// Live state pill for a forward row: gray "stopped", amber "starting…",
/// green "listening (· N)", red "failed" (the reason shows under the route).
fn forward_pill(
    forward: &PortForward,
    status: Option<&ForwardStatus>,
    phase: Phase,
) -> (String, Color) {
    if !forward.enabled {
        return ("stopped".into(), GRAY);
    }
    match status {
        Some(status) => match &status.state {
            ForwardState::Starting => ("starting…".into(), AMBER),
            ForwardState::Listening if status.active > 0 => {
                (format!("listening · {}", status.active), GREEN)
            }
            ForwardState::Listening => ("listening".into(), GREEN),
            ForwardState::Failed(_) => ("failed".into(), RED),
        },
        // No status = no running session for this forward. The profile's
        // connection banner explains the disconnected case in one place.
        None => match phase {
            Phase::Idle | Phase::Failed => ("stopped".into(), GRAY),
            _ => ("starting…".into(), AMBER),
        },
    }
}

fn phase_color(phase: Phase) -> Color {
    match phase {
        Phase::Idle => GRAY,
        Phase::Connecting | Phase::Reconnecting => AMBER,
        Phase::Connected => GREEN,
        Phase::Failed => RED,
    }
}

fn server_phase_color(phase: ServerPhase) -> Color {
    match phase {
        ServerPhase::Stopped => GRAY,
        ServerPhase::Starting | ServerPhase::Stopping => AMBER,
        ServerPhase::Running => GREEN,
        ServerPhase::Failed => RED,
    }
}

fn server_phase_label(phase: ServerPhase) -> &'static str {
    match phase {
        ServerPhase::Stopped => "stopped",
        ServerPhase::Starting => "starting…",
        ServerPhase::Running => "running",
        ServerPhase::Stopping => "stopping…",
        ServerPhase::Failed => "failed",
    }
}

/// Whether a full-pane form (profile or server) replaces the detail pane, so
/// no sidebar row reads as selected.
fn form_open(app: &App) -> bool {
    app.profile_form.is_some() || app.server_form.is_some()
}

fn phase_label(phase: Phase) -> &'static str {
    match phase {
        Phase::Idle => "disconnected",
        Phase::Connecting => "connecting…",
        Phase::Connected => "connected",
        Phase::Reconnecting => "reconnecting…",
        Phase::Failed => "failed",
    }
}

pub fn root(app: &App) -> Element<'_, Message> {
    let base: Element<'_, Message> = if app.intro {
        intro()
    } else {
        row![sidebar(app), detail_pane(app)].into()
    };
    // The reset warning must be answered, so it sits above everything and
    // its backdrop does nothing.
    if let Some(version) = app.secrets_reset_from {
        return modal(base, secrets_reset_modal(version), None);
    }
    match &app.conn_path_modal {
        Some(snapshot) => {
            modal(base, conn_path_modal(snapshot), Some(Message::DismissConnPath))
        }
        None => base,
    }
}

/// The first-run intro: what the app does — its two roles, side by side and
/// neither required — and one way on, into the window, where both are set up
/// from the sidebar. Not a choice that has to be made here.
fn intro() -> Element<'static, Message> {
    let role = |name: &'static str, body: &'static str| {
        column![
            text(name).size(14).font(semibold()),
            text(body).size(13).style(style::dim_text),
        ]
        .spacing(3)
    };
    let col = column![
        text("Welcome to flextunnel").size(22).font(semibold()),
        text("flextunnel does two things. Use either one, or both:").size(13),
        role(
            "Connections",
            "Reach flextunnel servers elsewhere from this computer, through local \
             proxies and port forwards — as many servers as you like.",
        ),
        role(
            "Server",
            "Let your other devices reach this computer, and the network it is on, \
             from anywhere.",
        ),
        text("Both are set up from the sidebar, any time.")
            .size(12)
            .style(style::faint_text),
        space().height(6),
        button(text("Continue").size(13).font(semibold()))
            .padding([7, 20])
            .style(style::primary)
            .on_press(Message::IntroContinue),
    ]
    .spacing(10)
    .max_width(520);
    center(col).padding(24).into()
}

/// Overlay `content`, centered on a dimmed backdrop, as a stack layer above
/// `base` — so it never touches `base`'s layout. Clicking the backdrop sends
/// `dismiss`, if any; the content card swallows its own clicks.
fn modal<'a>(
    base: impl Into<Element<'a, Message>>,
    content: impl Into<Element<'a, Message>>,
    dismiss: Option<Message>,
) -> Element<'a, Message> {
    let backdrop = mouse_area(center(opaque(content)).style(|_theme| container::Style {
        background: Some(Color { a: 0.7, ..Color::BLACK }.into()),
        ..container::Style::default()
    }));
    let backdrop = match dismiss {
        Some(message) => backdrop.on_press(message),
        None => backdrop,
    };
    stack![base.into(), opaque(backdrop)].into()
}

/// The startup warning when this build cannot read the stored secrets'
/// sealed format (`version` is the one they were sealed under): quit with
/// them left on disk, or start fresh and re-enter them.
fn secrets_reset_modal<'a>(version: u32) -> Element<'a, Message> {
    let sealed_by = match version {
        0 => "an earlier version of flextunnel".to_string(),
        v => format!("format version {v}"),
    };
    let card = column![
        text("Saved secrets can't be read").size(15).font(semibold()),
        text(format!(
            "Your secrets were saved by {sealed_by}, which this version stores \
             differently. The auth-key secrets, the server identity key and the \
             relay auth tokens will all be empty and must be re-entered."
        ))
        .size(12),
        text(
            "Quit now to leave them on disk untouched — the previous version of \
             flextunnel can still read them, for example to export the keys first. \
             Starting fresh deletes them for good."
        )
        .size(12)
        .color(AMBER),
        row![
            space().width(Fill),
            button(text("Quit").size(12))
                .padding([5, 14])
                .style(style::ghost)
                .on_press(Message::SecretsResetQuit),
            button(text("Start fresh").size(12))
                .padding([5, 14])
                .style(style::primary)
                .on_press(Message::SecretsResetContinue),
        ]
        .spacing(8)
        .align_y(Center),
    ]
    .spacing(10);
    container(card)
        .padding([16, 18])
        .max_width(480)
        .style(style::card)
        .into()
}

/// The connection-path modal card: a point-in-time snapshot of how the profile
/// reaches the server, each path dotted by transport (direct/relay) with the
/// active one pilled — mirrors `ezvpn client status`.
fn conn_path_modal(snapshot: &ConnectionSnapshot) -> Element<'_, Message> {
    let mut card = column![
        row![
            text("Connection path").size(15).font(semibold()),
            space().width(Fill),
            button(text("Close").size(12))
                .padding([3, 10])
                .style(style::ghost)
                .on_press(Message::DismissConnPath),
        ]
        .align_y(Center),
        text("Snapshot taken just now — how this profile reaches the server.")
            .size(11)
            .style(style::dim_text),
    ]
    .spacing(10);

    if snapshot.paths.is_empty() {
        card = card.push(
            text("No path available — close this and try again in a moment.")
                .size(12)
                .style(style::dim_text),
        );
    } else {
        for path in &snapshot.paths {
            let color = match path.kind {
                ConnPathKind::Direct => GREEN,
                ConnPathKind::Relay => AMBER,
                ConnPathKind::Other => GRAY,
            };
            let mut r = row![dot(color, 7.0), mono(path.display.clone())]
                .spacing(8)
                .align_y(Center);
            if path.selected {
                r = r.push(pill("active".to_string(), GREEN));
            }
            card = card.push(r);
        }
    }

    // Custom-relay health, from an on-demand /healthz probe. Empty with the
    // default iroh relays. /healthz is unauthenticated — it confirms the relay
    // is up, not that a relay auth token is accepted.
    if !snapshot.custom_relays.is_empty() {
        card = card.push(
            text("Custom relays")
                .size(12)
                .font(semibold())
                .style(style::dim_text),
        );
        for relay in &snapshot.custom_relays {
            card = card.push(custom_relay_row(relay));
        }
    }

    container(card)
        .padding([16, 18])
        .max_width(480)
        .style(style::card)
        .into()
}

/// One custom relay's health row: its URL plus a colored status derived from the
/// on-demand `/healthz` probe — `working` is `Some(true)` (up), `Some(false)`
/// (down, with the error), or `None` (the check could not run).
fn custom_relay_row(relay: &CustomRelayStatus) -> Element<'_, Message> {
    let (color, status) = match relay.working {
        Some(true) => (GREEN, "Reachable".to_string()),
        Some(false) => (
            RED,
            relay
                .error
                .clone()
                .map(|e| format!("Unreachable — {e}"))
                .unwrap_or_else(|| "Unreachable".to_string()),
        ),
        None => (GRAY, "Status unavailable".to_string()),
    };
    column![
        row![dot(color, 7.0), mono(relay.url.clone())]
            .spacing(8)
            .align_y(Center),
        text(status).size(11).color(color),
    ]
    .spacing(3)
    .into()
}

// ---------------------------------------------------------------------------
// Sidebar

fn sidebar(app: &App) -> Element<'_, Message> {
    // Client connections, then the server — one per user, so a single slot
    // rather than a list: its row, or the way to set it up. Neither is
    // required; each is set up here whenever wanted.
    let mut list = column![
        row![
            section_label("CONNECTIONS"),
            space().width(Fill),
            button(text("+").size(14).font(semibold()))
                .padding([1, 9])
                .style(style::tinted)
                .on_press(Message::AddProfile),
        ]
        .align_y(Center)
    ]
    .spacing(2);
    for profile in &app.profiles {
        list = list.push(sidebar_profile_row(app, profile));
    }
    if app.profiles.is_empty() {
        list = list.push(
            container(text("No connections yet.").size(11).style(style::faint_text))
                .padding([4, 10]),
        );
    }
    list = list.push(space().height(10));
    list = list.push(section_label("SERVER"));
    list = list.push(match &app.server {
        Some(server) => sidebar_server_row(app, server),
        None => button(text("Set up server…").size(13).style(style::dim_text))
            .padding([6, 10])
            .width(Fill)
            .style(style::sidebar_row(app.server_form.is_some()))
            .on_press(Message::SetUpServer)
            .into(),
    });

    let keys_selected = app.selection == Selection::Keys && !form_open(app);
    let keys_row = button(text("Keys").size(13))
        .padding([6, 10])
        .width(Fill)
        .style(style::sidebar_row(keys_selected))
        .on_press(Message::Select(Selection::Keys));

    let logs_selected = app.selection == Selection::Logs && !form_open(app);
    let logs_row = button(text("Logs").size(13))
        .padding([6, 10])
        .width(Fill)
        .style(style::sidebar_row(logs_selected))
        .on_press(Message::Select(Selection::Logs));

    let io_row = row![
        button(text("Export").size(11))
            .padding([3, 10])
            .style(style::ghost)
            .on_press_maybe((!app.profiles.is_empty()).then_some(Message::ExportProfiles)),
        button(text("Import").size(11))
            .padding([3, 10])
            .style(style::ghost)
            .on_press(Message::ImportProfiles),
    ]
    .spacing(4);

    let mut footer = column![keys_row, logs_row, io_row].spacing(6);
    if let Some(notice) = &app.io_notice {
        footer = footer.push(text(notice.as_str()).size(10).style(style::dim_text));
    }
    footer = footer.push(
        text(concat!("v", env!("CARGO_PKG_VERSION")))
            .size(10)
            .style(style::faint_text),
    );

    container(column![scrollable(list).height(Fill).spacing(4), footer].spacing(10))
        .padding([14, 12])
        .width(210)
        .height(Fill)
        .style(style::sidebar)
        .into()
}

fn sidebar_profile_row<'a>(app: &'a App, profile: &'a Profile) -> Element<'a, Message> {
    let snapshot = app.snapshot_for(&profile.id);
    let selected = app.selection == Selection::Profile(profile.id.clone()) && !form_open(app);

    let title = row![
        dot(phase_color(snapshot.phase), 8.0),
        text(profile.name.as_str()).size(13).font(semibold()),
    ]
    .spacing(7)
    .align_y(Center);

    let running = profile
        .forwards
        .iter()
        .filter(|f| {
            f.enabled
                && snapshot
                    .forwards
                    .iter()
                    .any(|s| s.id == f.id && s.state == ForwardState::Listening)
        })
        .count();
    let mut counts = format!(
        "{} forward{}",
        profile.forwards.len(),
        if profile.forwards.len() == 1 { "" } else { "s" }
    );
    if running > 0 {
        counts.push_str(&format!(" · {running} running"));
    }

    let mut content = column![title].spacing(3);
    content = content.push(
        row![
            space().width(15),
            text(counts).size(11).style(if running > 0 {
                |_: &iced::Theme| iced::widget::text::Style { color: Some(GREEN) }
            } else {
                style::faint_text
            }),
        ]
        .align_y(Center),
    );
    for forward in &profile.forwards {
        let status = snapshot.forwards.iter().find(|s| s.id == forward.id);
        let (_, color) = forward_pill(forward, status, snapshot.phase);
        content = content.push(
            row![
                space().width(15),
                dot(color, 5.0),
                text(forward.display_name()).size(11).style(style::dim_text),
            ]
            .spacing(6)
            .align_y(Center),
        );
    }

    button(content)
        .padding([7, 10])
        .width(Fill)
        .style(style::sidebar_row(selected))
        .on_press(Message::Select(Selection::Profile(profile.id.clone())))
        .into()
}

/// The server's one-line state for the sidebar: running with how many
/// clients, what it is waiting for, or its phase.
fn server_row_status(app: &App, server: &ServerConfig) -> String {
    let snapshot = &app.server_snapshot;
    match snapshot.phase {
        ServerPhase::Stopped if !server.enabled => "disabled".into(),
        ServerPhase::Running => match snapshot.connected_clients.len() {
            0 => "running · no clients".into(),
            n => format!("running · {n} connected"),
        },
        ServerPhase::Stopped if server.authorized_clients.is_empty() => {
            "needs a client".into()
        }
        phase => server_phase_label(phase).into(),
    }
}

fn sidebar_server_row<'a>(app: &'a App, server: &'a ServerConfig) -> Element<'a, Message> {
    let snapshot = &app.server_snapshot;
    let selected = app.selection == Selection::Server && !form_open(app);
    let content = column![
        row![
            dot(
                if server.enabled { server_phase_color(snapshot.phase) } else { GRAY },
                8.0,
            ),
            text("This computer").size(13).font(semibold()),
        ]
        .spacing(7)
        .align_y(Center),
        row![
            space().width(15),
            text(server_row_status(app, server))
                .size(11)
                .style(if snapshot.phase == ServerPhase::Running {
                    |_: &iced::Theme| iced::widget::text::Style { color: Some(GREEN) }
                } else {
                    style::faint_text
                }),
        ],
    ]
    .spacing(3);
    button(content)
        .padding([7, 10])
        .width(Fill)
        .style(style::sidebar_row(selected))
        .on_press(Message::Select(Selection::Server))
        .into()
}

// ---------------------------------------------------------------------------
// Detail pane

fn detail_pane(app: &App) -> Element<'_, Message> {
    let content: Element<'_, Message> = if let Some(form) = &app.profile_form {
        profile_form_view(app, form)
    } else if let Some(form) = &app.server_form {
        server_form_view(app, form)
    } else {
        match &app.selection {
            Selection::Keys => keys_pane(app),
            Selection::Logs => logs_pane(app),
            Selection::Profile(id) => match app.profile(id) {
                Some(profile) => profile_detail(app, profile),
                None => empty_state(),
            },
            Selection::Server => match &app.server {
                Some(server) => server_detail(app, server),
                None => empty_state(),
            },
        }
    };
    container(content).padding(16).width(Fill).height(Fill).into()
}

/// Nothing (or nothing existing) selected: point at the sidebar, where both
/// roles are set up — without offering either as the one to pick.
fn empty_state() -> Element<'static, Message> {
    container(
        column![
            text("Nothing selected").size(14).font(semibold()),
            text(
                "Use + next to Connections to reach a flextunnel server elsewhere, or \
                 Set up server… to let your other devices reach this computer. Use \
                 either one, or both.",
            )
            .size(12)
            .style(style::dim_text),
        ]
        .spacing(8)
        .max_width(420),
    )
    .width(Fill)
    .height(Fill)
    .align_x(Center)
    .align_y(Center)
    .into()
}

fn profile_detail<'a>(app: &'a App, profile: &'a Profile) -> Element<'a, Message> {
    let snapshot = app.snapshot_for(&profile.id);
    let ready = profile.is_ready(&app.keys);

    let mut hero = row![
        dot(phase_color(snapshot.phase), 12.0),
        text(profile.name.as_str()).size(20).font(semibold()),
        pill(phase_label(snapshot.phase).to_string(), phase_color(snapshot.phase)),
    ]
    .spacing(10)
    .align_y(Center);
    if let Some(since) = snapshot.connected_since {
        hero = hero.push(
            text(format!("for {}", format_duration(since.elapsed())))
                .size(13)
                .style(style::dim_text),
        );
    }
    hero = hero.push(space().width(Fill));
    hero = hero.push(match snapshot.phase {
        Phase::Idle | Phase::Failed => button(text("Connect").size(13).font(semibold()))
            .padding([7, 16])
            .style(style::primary)
            .on_press_maybe(ready.then(|| Message::Connect(profile.id.clone()))),
        _ => button(text("Disconnect").size(13))
            .padding([7, 16])
            .style(style::outlined)
            .on_press(Message::Disconnect(profile.id.clone())),
    });

    let mut col = column![hero].spacing(12);

    if let Some(notice) = &app.notice {
        col = col.push(text(notice.as_str()).size(12).style(style::dim_text));
    }
    if let Some(error) = &snapshot.last_error {
        col = col.push(text(error.as_str()).size(12).color(RED));
    }
    if !ready {
        let fix = match config::find_key(&app.keys, &profile.auth_key_id) {
            // The key exists but its secret was lost from the keychain.
            Some(key) => format!(
                "The secret of key \"{}\" is missing — re-enter it in the Keys pane.",
                key.name
            ),
            None => "No auth key picked — edit the profile to pick one.".into(),
        };
        col = col.push(text(fix).size(12).color(AMBER));
    }

    // CONNECTION card
    let node_id = profile.server_node_id.clone();
    let socks = snapshot
        .socks_addr
        .or_else(|| profile.socks_port.map(|p| SocketAddr::from(([127, 0, 0, 1], p))))
        .map(|addr| addr.to_string());
    let http = snapshot
        .http_addr
        .or_else(|| profile.http_port.map(|p| SocketAddr::from(([127, 0, 0, 1], p))))
        .map(|a| a.to_string());

    let copy_node = (!node_id.is_empty()).then(|| node_id.clone());
    let mut info = column![
        // The full id never fits (and iced has no ellipsis overflow); both
        // ends stay visible for eyeballing, Copy carries the whole thing.
        info_row("Server node id", truncate_middle(&node_id, 22), copy_node),
    ]
    .spacing(8);
    // The key's public half is not a secret — always shown unmasked so it can
    // be copied onto the server's authorized-keys file. (The secret never
    // appears anywhere in the UI.)
    if let Some(key) = config::find_key(&app.keys, &profile.auth_key_id) {
        info = info.push(info_row(
            "Auth key",
            format!("{} ({})", key.name, truncate_middle(&key.public_key, 14)),
            Some(key.public_key.clone()),
        ));
    }
    if let Some(socks) = socks {
        let copy = Some(format!("socks5://{socks}"));
        info = info.push(info_row("SOCKS5 proxy", socks, copy));
    }
    if let Some(http) = http {
        let copy = Some(format!("http://{http}"));
        info = info.push(info_row("HTTP proxy", http, copy));
    }
    let mut header = row![section_label("CONNECTION"), space().width(Fill)].align_y(Center);
    if snapshot.phase == Phase::Connected {
        // A one-shot readout of the live iroh path, shown in a dismissable
        // modal overlay (see `App::conn_path_modal`) — a point-in-time check
        // rather than a live field.
        header = header.push(
            button(text("Connection path").size(12))
                .padding([3, 10])
                .style(style::ghost)
                .on_press(Message::ShowConnPath),
        );
    }
    header = header.push(
        button(text("Edit").size(12))
            .padding([3, 10])
            .style(style::ghost)
            .on_press(Message::EditProfile(profile.id.clone())),
    );
    col = col.push(header);
    col = col.push(container(info).padding([12, 14]).width(Fill).style(style::card));

    if snapshot.phase == Phase::Connected {
        col = col.push(section_label("ROUTING"));
        col = col.push(
            container(routes_section(snapshot))
                .padding([12, 14])
                .width(Fill)
                .style(style::card),
        );
    }

    // FORWARDINGS
    if let Some(banner) = connection_banner(profile, ready, snapshot) {
        col = col.push(banner);
    }
    col = col.push(
        row![
            section_label(if profile.forwards.is_empty() {
                "PORT FORWARDS".to_string()
            } else {
                format!("PORT FORWARDS · {}", profile.forwards.len())
            }),
            space().width(Fill),
            button(text("+ Add").size(12).font(semibold()))
                .padding([4, 12])
                .style(style::tinted)
                .on_press(Message::AddForward(profile.id.clone())),
        ]
        .align_y(Center),
    );

    // Inline add/edit form — one at a time; an inline card fits the window
    // better than a separate one.
    if let Some((form_profile, form)) = &app.forward_form
        && *form_profile == profile.id
    {
        col = col.push(forward_form_view(app, form));
    }

    if profile.forwards.is_empty() {
        col = col.push(
            container(
                text("No port forwards yet. Add one to expose a remote service on localhost.")
                    .size(12)
                    .style(style::dim_text),
            )
            .padding(24)
            .width(Fill)
            .align_x(Center)
            .style(style::card),
        );
    } else {
        let routed_set = app
            .routed_caches
            .get(&profile.id)
            .and_then(|c| c.as_ref())
            .and_then(|(_, _, set)| set.as_ref());
        for forward in &profile.forwards {
            col = col.push(forward_card(app, profile, forward, snapshot, routed_set));
        }
        col = col.push(
            text(
                "Forwards listen on localhost only (127.0.0.1 and ::1) and open \
                 server-direct tunnel streams. The server rejects targets outside its tunnel set.",
            )
            .size(11)
            .style(style::faint_text),
        );
    }

    // Delete, tucked at the very bottom behind a two-click confirm.
    let confirming = app.confirm_delete.as_deref() == Some(profile.id.as_str());
    col = col.push(space().height(8));
    col = col.push(
        row![button(
            text(if confirming {
                "Click again to delete this profile"
            } else {
                "Delete profile…"
            })
            .size(12)
        )
        .padding([4, 12])
        .style(style::ghost_danger)
        .on_press(Message::DeleteProfile(profile.id.clone()))]
        .align_y(Center),
    );

    scrollable(col.padding([0, 4])).height(Fill).spacing(4).into()
}

/// One tinted banner explaining why forwards aren't live, with an inline
/// Connect button where that's the fix — instead of every row repeating it.
fn connection_banner<'a>(
    profile: &'a Profile,
    ready: bool,
    snapshot: &'a Snapshot,
) -> Option<Element<'a, Message>> {
    let (color, message, show_connect) = match snapshot.phase {
        Phase::Connected => return None,
        Phase::Idle => (
            AMBER,
            "Not connected — forwards are inactive until you connect.",
            true,
        ),
        Phase::Failed => (
            RED,
            "Connection failed — forwards are inactive until you reconnect.",
            true,
        ),
        Phase::Connecting => (AMBER, "Connecting — forwards start automatically.", false),
        Phase::Reconnecting => (AMBER, "Reconnecting — forwards resume automatically.", false),
    };
    let mut r = row![dot(color, 8.0), text(message).size(12)]
        .spacing(8)
        .align_y(Center);
    if show_connect {
        r = r.push(space().width(Fill));
        r = r.push(
            button(text("Connect").size(11).font(semibold()))
                .padding([3, 10])
                .style(style::tinted)
                .on_press_maybe(ready.then(|| Message::Connect(profile.id.clone()))),
        );
    }
    Some(
        container(r)
            .padding([9, 12])
            .width(Fill)
            .style(style::banner(color))
            .into(),
    )
}

fn forward_form_view<'a>(app: &'a App, form: &'a ForwardForm) -> Element<'a, Message> {
    let validated = form.validate(&app.profiles);

    let mut col = column![
        text(if form.is_edit() {
            "Edit forward"
        } else {
            "Add forward"
        })
        .size(13)
        .font(semibold()),
        form_row(
            "Label",
            input("optional", &form.label, Message::FormLabelChanged),
        ),
        form_row(
            "Local port",
            input("", &form.local_port, Message::FormLocalPortChanged).width(90),
        ),
        form_row(
            "Remote host",
            input(
                "host or IP — resolved server-side",
                &form.remote_host,
                Message::FormRemoteHostChanged,
            ),
        ),
        form_row(
            "Remote port",
            input("", &form.remote_port, Message::FormRemotePortChanged).width(90),
        ),
        form_row(
            "Enabled",
            checkbox(form.enabled)
                .on_toggle(Message::FormEnabledToggled)
                .style(style::check),
        ),
    ]
    .spacing(10);

    if let Err(message) = &validated {
        col = col.push(text(message.clone()).size(12).color(AMBER));
    }
    col = col.push(
        row![
            button(text("Save").size(13).font(semibold()))
                .padding([6, 16])
                .style(style::primary)
                .on_press_maybe(validated.is_ok().then_some(Message::FormSave)),
            button(text("Cancel").size(13))
                .padding([6, 16])
                .style(style::outlined)
                .on_press(Message::FormCancel),
        ]
        .spacing(8),
    );

    container(col)
        .padding([12, 14])
        .width(Fill)
        .style(style::card)
        .into()
}

fn forward_card<'a>(
    app: &'a App,
    profile: &'a Profile,
    forward: &'a PortForward,
    snapshot: &'a Snapshot,
    routed_set: Option<&RoutedSet>,
) -> Element<'a, Message> {
    let status = snapshot.forwards.iter().find(|s| s.id == forward.id);
    let (pill_text, pill_color) = forward_pill(forward, status, snapshot.phase);

    // The name stays prominent even while stopped — the pill and the switch
    // carry the state.
    let name = text(forward.display_name()).size(14).font(semibold());

    let mut title = row![name, pill(pill_text, pill_color)]
        .spacing(8)
        .align_y(Center);
    if let Some(tunneled) = forward_badge(snapshot.phase, &snapshot.routes, routed_set, forward) {
        let (badge, color) = if tunneled {
            ("server-direct", GREEN)
        } else {
            ("not routed", AMBER)
        };
        title = title.push(pill(badge.to_string(), color));
    }

    let route = arrow_copy_row(forward.local_endpoint(), forward.remote_endpoint(), true);

    let mut info = column![title, route].spacing(5).width(Fill);
    // A live bind failure (before the switch snaps back off), then the
    // retained reason after the auto-disable, then per-connection errors.
    if let Some(ForwardState::Failed(reason)) = status.map(|s| &s.state) {
        info = info.push(text(reason.clone()).size(11).color(RED));
    }
    if let Some(reason) = app.forward_errors.get(&forward.id) {
        info = info.push(text(reason.as_str()).size(11).color(RED));
    }
    if forward.enabled
        && let Some(error) = status.and_then(|s| s.last_conn_error.as_deref())
    {
        info = info.push(text(error).size(11).color(AMBER));
    }

    let profile_id = profile.id.clone();
    let forward_id = forward.id.clone();
    let controls = row![
        button(text("Edit").size(12))
            .padding([4, 10])
            .style(style::ghost)
            .on_press(Message::EditForward(profile.id.clone(), forward.id.clone())),
        button(text("Delete").size(12))
            .padding([4, 10])
            .style(style::ghost_danger)
            .on_press(Message::DeleteForward(profile.id.clone(), forward.id.clone())),
        // Desired state, but not a plain checkbox: enabling attempts the
        // setup now, and a setup failure snaps the switch back off (see
        // disable_failed_forwards).
        toggler(forward.enabled)
            .on_toggle(move |enabled| {
                Message::ToggleForward(profile_id.clone(), forward_id.clone(), enabled)
            })
            .size(20)
            .style(style::switch),
    ]
    .spacing(4)
    .align_y(Center);

    container(row![info, controls].spacing(12).align_y(Center))
        .padding([12, 14])
        .width(Fill)
        .style(style::card)
        .into()
}

fn routes_section(snapshot: &Snapshot) -> Element<'_, Message> {
    let routes = &snapshot.routes;
    let mut col = column![].spacing(3);
    if is_full_tunnel(routes) {
        col = col.push(text("Everything through the tunnel").size(12));
    } else {
        col = col.push(
            text(format!(
                "Split tunnel — {} domain(s), {} CIDR(s) routed through the server:",
                routes.domains.len(),
                routes.cidrs.len()
            ))
            .size(12),
        );
        for domain in &routes.domains {
            col = col.push(route_row(domain.clone(), None));
        }
        for cidr in &routes.cidrs {
            col = col.push(route_row(cidr.clone(), None));
        }
    }
    if !routes.host_aliases.is_empty() {
        col = col.push(space().height(8));
        col = col.push(
            text(format!(
                "Host aliases — {} resolved server-side:",
                routes.host_aliases.len()
            ))
            .size(12),
        );
        for (alias, target) in &routes.host_aliases {
            col = col.push(arrow_copy_row(alias.clone(), target.clone(), false));
        }
    }
    if !routes.dns_forwards.is_empty() {
        col = col.push(space().height(8));
        col = col.push(
            text(format!(
                "DNS forwards — {} resolved via upstream server(s):",
                routes.dns_forwards.len()
            ))
            .size(12),
        );
        for (suffix, servers) in &routes.dns_forwards {
            col = col.push(arrow_copy_row(
                format!("{suffix} (+ subdomains)"),
                servers.join(", "),
                false,
            ));
        }
    }
    if !routes.bridges.is_empty() {
        col = col.push(space().height(8));
        col = col.push(
            text(format!(
                "Bridge routes — {} forwarded via another server:",
                routes.bridges.len()
            ))
            .size(12),
        );
        for bridge in &routes.bridges {
            col = col.push(space().height(4));
            col = col.push(mono(format!("{}:", bridge.name)));
            col = col.push(
                row![
                    space().width(16),
                    text("endpoint id:").size(12).style(style::dim_text),
                    mono(bridge.endpoint_id.clone()),
                    copy_button(bridge.endpoint_id.clone()),
                ]
                .spacing(6)
                .align_y(Center),
            );
            if !bridge.domains.is_empty() {
                col = col.push(indented_label("routed domains:"));
                for d in &bridge.domains {
                    col = col.push(indented_item(d));
                }
            }
            if !bridge.cidrs.is_empty() {
                col = col.push(indented_label("routed CIDRs:"));
                for c in &bridge.cidrs {
                    col = col.push(indented_item(c));
                }
            }
        }
    }
    // The reserved hosts are always tunneled to the server, regardless of the
    // routed set — surface them so they're discoverable (and copyable).
    col = col.push(space().height(8));
    col = col.push(text("Server status page — always tunneled:").size(12));
    col = col.push(route_row(reserved::STATUS_HOST.to_string(), None));
    col = col.push(space().height(8));
    col = col.push(text("Server loopback — always tunneled:").size(12));
    col = col.push(route_row(reserved::LOCALHOST_HOST.to_string(), None));
    col.into()
}

// ---------------------------------------------------------------------------
// Profile form

fn profile_form_view<'a>(app: &'a App, form: &'a ProfileForm) -> Element<'a, Message> {
    let mut socks = row![checkbox(form.socks_enabled)
        .label("enable")
        .text_size(13)
        .on_toggle(Message::SocksEnabledToggled)
        .style(style::check)]
    .spacing(10)
    .align_y(Center);
    if form.socks_enabled {
        socks = socks.push(text("port").size(12).style(style::dim_text));
        socks = socks.push(input("", &form.socks_port, Message::SocksPortChanged).width(90));
    }
    let mut http = row![checkbox(form.http_enabled)
        .label("enable")
        .text_size(13)
        .on_toggle(Message::HttpEnabledToggled)
        .style(style::check)]
    .spacing(10)
    .align_y(Center);
    if form.http_enabled {
        http = http.push(text("port").size(12).style(style::dim_text));
        http = http.push(input("", &form.http_port, Message::HttpPortChanged).width(90));
    }

    let validated = form.validate(&app.profiles, &app.keys);

    let mut card = column![
        form_row("Name", input("e.g. prod", &form.name, Message::ProfileNameChanged)),
        form_row(
            "Server node id",
            input("", &form.server_node_id, Message::ServerNodeIdChanged),
        ),
    ]
    .spacing(10);
    if let Some(new_name) = &form.new_key_name {
        // The "New key" prompt replaces the picker and public-key rows while
        // open, so the form shows exactly one key flow at a time: name the
        // key, then Create generates the keypair, adds it to the shared list,
        // and selects it; Cancel returns to the picker.
        let name_check = crate::app::validate_key_name(new_name, &app.keys, None);
        card = card.push(form_row(
            "New key name",
            row![
                input("e.g. work laptop", new_name, Message::NewKeyNameChanged).width(240),
                button(text("Create").size(12).font(semibold()))
                    .padding([4, 10])
                    .style(style::primary)
                    .on_press_maybe(name_check.is_ok().then_some(Message::NewKeyCreate)),
                button(text("Cancel").size(12))
                    .padding([4, 10])
                    .style(style::outlined)
                    .on_press(Message::NewKeyCancel),
            ]
            .spacing(8)
            .align_y(Center),
        ));
        // Only nag once something was typed — an empty prompt just opened.
        if let Err(message) = &name_check
            && !new_name.is_empty()
        {
            card = card.push(text(message.clone()).size(12).color(AMBER));
        }
    } else {
        // Keys are shared across profiles: pick one from the list (managed in
        // the Keys pane), or mint a fresh one right here with "New key…".
        let choices: Vec<KeyChoice> = app
            .keys
            .iter()
            .map(|k| KeyChoice {
                id: k.id.clone(),
                name: k.name.clone(),
            })
            .collect();
        let selected = choices.iter().find(|c| c.id == form.auth_key_id).cloned();
        card = card.push(form_row(
            "Auth key",
            row![
                pick_list(choices, selected, Message::AuthKeyPicked)
                    .placeholder(if app.keys.is_empty() {
                        "no keys yet"
                    } else {
                        "pick a key"
                    })
                    .text_size(13)
                    .width(240),
                button(text("New key…").size(12))
                    .padding([4, 10])
                    .style(style::outlined)
                    .on_press(Message::NewKeyPrompt),
            ]
            .spacing(8)
            .align_y(Center),
        ));
        if let Some(key) = config::find_key(&app.keys, &form.auth_key_id) {
            card = card.push(form_row(
                "Public key",
                row![
                    text(truncate_middle(&key.public_key, 30)).size(12).font(Font::MONOSPACE),
                    copy_button(key.public_key.clone()),
                ]
                .spacing(8)
                .align_y(Center),
            ));
        }
    }
    card = card.extend([
        form_row("SOCKS5 proxy", socks),
        form_row("HTTP proxy", http),
        form_row(
            "Relay URLs",
            input(
                "comma-separated, optional",
                &form.relay_urls,
                Message::RelayUrlsChanged,
            ),
        ),
        form_row(
            "Relay auth token",
            input(
                "optional, custom relays only",
                &form.relay_auth_token,
                Message::RelayAuthTokenChanged,
            )
            .secure(true)
            .width(240),
        ),
    ]);

    if let Err(message) = &validated {
        card = card.push(text(message.clone()).size(12).color(AMBER));
    }
    let mut buttons = row![
        button(text("Save").size(13).font(semibold()))
            .padding([6, 16])
            .style(style::primary)
            .on_press_maybe(validated.is_ok().then_some(Message::ProfileFormSave)),
        button(text("Cancel").size(13))
            .padding([6, 16])
            .style(style::outlined)
            .on_press(Message::ProfileFormCancel),
    ]
    .spacing(8)
    .align_y(Center);
    if let Some(notice) = &app.notice {
        buttons = buttons.push(text(notice.as_str()).size(12).style(style::dim_text));
    }
    card = card.push(buttons);

    column![
        section_label(if form.is_edit() {
            "EDIT PROFILE"
        } else {
            "NEW PROFILE"
        }),
        container(card).padding([12, 14]).width(Fill).style(style::card),
        text("Auth keys are shared — any number of profiles can pick the same one (manage them \
              in the Keys pane). The server must authorize the key's public half: on a \
              flextunnel desktop server under Authorized clients, on a CLI server in its \
              authorized-keys file.")
            .size(11)
            .style(style::faint_text),
    ]
    .spacing(10)
    .into()
}

// ---------------------------------------------------------------------------
// Server

fn server_detail<'a>(app: &'a App, server: &'a ServerConfig) -> Element<'a, Message> {
    let snapshot = &app.server_snapshot;
    let running = snapshot.phase == ServerPhase::Running;

    // A disabled server that has stopped reads as "disabled", not "stopped".
    let disabled = !server.enabled && snapshot.phase == ServerPhase::Stopped;
    let (label, color) = if disabled {
        ("disabled", GRAY)
    } else {
        (server_phase_label(snapshot.phase), server_phase_color(snapshot.phase))
    };
    let mut hero = row![
        dot(color, 12.0),
        text("Server").size(20).font(semibold()),
        pill(label.to_string(), color),
    ]
    .spacing(10)
    .align_y(Center);
    if let Some(since) = snapshot.running_since {
        hero = hero.push(
            text(format!(
                "for {} · {}",
                format_duration(since.elapsed()),
                clients_connected(snapshot.connected_clients.len())
            ))
            .size(13)
            .style(style::dim_text),
        );
    }
    hero = hero.push(space().width(Fill));
    // The server's only on/off control, persisted: enabled, it runs (and
    // starts with the app); disabled, it stays stopped across launches. Not
    // switchable while the endpoint is still closing.
    let mut switch = toggler(server.enabled)
        .label("Enabled")
        .text_size(13)
        .size(20)
        .style(style::switch);
    if snapshot.phase != ServerPhase::Stopping {
        switch = switch.on_toggle(Message::SetServerEnabled);
    }
    hero = hero.push(switch);

    let mut col = column![hero].spacing(12);
    if let Some(notice) = &app.notice {
        col = col.push(text(notice.as_str()).size(12).style(style::dim_text));
    }
    if let Some(error) = &snapshot.last_error {
        col = col.push(text(error.as_str()).size(12).color(RED));
    }
    if server.enabled && snapshot.phase == ServerPhase::Failed {
        col = col.push(
            text("Switch it off and on again to retry.").size(12).style(style::dim_text),
        );
    }
    if let Some(blocker) = server.start_blocker()
        && !running
        && server.enabled
    {
        col = col.push(
            container(row![dot(AMBER, 8.0), text(blocker).size(12)].spacing(8).align_y(Center))
                .padding([9, 12])
                .width(Fill)
                .style(style::banner(AMBER)),
        );
    }
    if app.server_needs_restart() {
        col = col.push(
            container(
                row![
                    dot(AMBER, 8.0),
                    text("Saved changes apply once the server restarts.").size(12),
                    space().width(Fill),
                    button(text("Restart now").size(11).font(semibold()))
                        .padding([3, 10])
                        .style(style::tinted)
                        .on_press(Message::RestartServer),
                ]
                .spacing(8)
                .align_y(Center),
            )
            .padding([9, 12])
            .width(Fill)
            .style(style::banner(AMBER)),
        );
    }

    // The endpoint id is what clients need, so it leads: in full (it is
    // public), selectable, with a prominent Copy — and with it the identity
    // behind it, exported or replaced right here.
    col = col.push(section_label("ENDPOINT ID"));
    col = col.push(
        container(endpoint_card(app, server))
            .padding([12, 14])
            .width(Fill)
            .style(style::card),
    );

    col = col.push(
        row![
            section_label(if server.authorized_clients.is_empty() {
                "AUTHORIZED CLIENTS".to_string()
            } else {
                format!("AUTHORIZED CLIENTS · {}", server.authorized_clients.len())
            }),
            space().width(Fill),
            button(text("+ Authorize client").size(12).font(semibold()))
                .padding([4, 12])
                .style(style::tinted)
                .on_press(Message::AuthorizeClient),
        ]
        .align_y(Center),
    );
    if let Some(form) = &app.client_form {
        col = col.push(client_form_view(app, server, form));
    }
    if server.authorized_clients.is_empty() {
        if app.client_form.is_none() {
            col = col.push(
                container(
                    text(
                        "No clients yet. Each device that will connect has an auth key \
                         (in the flextunnel app: Keys); authorize its public key here.",
                    )
                    .size(12)
                    .style(style::dim_text),
                )
                .padding(24)
                .width(Fill)
                .align_x(Center)
                .style(style::card),
            );
        }
    } else {
        let mut clients = column![].spacing(10);
        for client in &server.authorized_clients {
            let connected = snapshot.connected_clients.contains(&client.public_key);
            clients = clients.push(authorized_client_row(app, client, running, connected));
        }
        col = col.push(container(clients).padding([12, 14]).width(Fill).style(style::card));
    }

    col = col.push(
        row![
            section_label("TUNNEL SET & RELAYS"),
            space().width(Fill),
            button(text("Edit").size(12))
                .padding([3, 10])
                .style(style::ghost)
                .on_press(Message::EditServer),
        ]
        .align_y(Center),
    );
    let mut tunnel = column![].spacing(6);
    if !server.routed_domains.is_empty() {
        tunnel = tunnel.push(indented_label("routed domains:"));
        for domain in &server.routed_domains {
            tunnel = tunnel.push(indented_item(domain));
        }
    }
    if !server.routed_cidrs.is_empty() {
        tunnel = tunnel.push(indented_label("routed CIDRs:"));
        for cidr in &server.routed_cidrs {
            tunnel = tunnel.push(indented_item(cidr));
        }
    }
    tunnel = tunnel.push(indented_label("always routed:"));
    tunnel = tunnel.push(indented_note_item(
        reserved::STATUS_HOST,
        "this server's status page",
    ));
    tunnel = tunnel.push(indented_note_item(
        reserved::LOCALHOST_HOST,
        "this machine's localhost, on any port",
    ));
    let relays = if server.relay_urls.is_empty() {
        "default".to_string()
    } else {
        server.relay_urls.join(", ")
    };
    tunnel = tunnel.push(space().height(4));
    tunnel = tunnel.push(info_row("Relays", relays, None));
    col = col.push(container(tunnel).padding([12, 14]).width(Fill).style(style::card));

    col = col.push(
        text(
            "The tunnel set is pushed to clients and enforced here. One server runs per \
             user — a CLI `flextunnel server` counts too.",
        )
        .size(11)
        .style(style::faint_text),
    );

    let confirming = app.confirm_delete_server;
    col = col.push(space().height(8));
    col = col.push(
        row![button(
            text(if confirming {
                "Click again to delete this server and its identity"
            } else {
                "Delete server…"
            })
            .size(12)
        )
        .padding([4, 12])
        .style(style::ghost_danger)
        .on_press(Message::DeleteServer)]
        .align_y(Center),
    );

    scrollable(col.padding([0, 4])).height(Fill).spacing(4).into()
}

/// One authorized client: a live dot while the server runs (green once the
/// client is connected), its name and public key, Copy and a two-click Remove.
fn authorized_client_row<'a>(
    app: &'a App,
    client: &'a AuthorizedClient,
    running: bool,
    connected: bool,
) -> Element<'a, Message> {
    let confirming = app.confirm_remove_client.as_deref() == Some(client.public_key.as_str());
    let mut title = row![
        dot(if connected { GREEN } else { GRAY }, 8.0),
        text(client.name.as_str()).size(13).font(semibold()),
    ]
    .spacing(8)
    .align_y(Center);
    if running {
        title = title.push(if connected {
            pill("connected", GREEN)
        } else {
            text("not connected").size(11).style(style::faint_text).into()
        });
    }
    // The app's own keys are recognizable: the user may be authorizing
    // another of their machines that shares one.
    if let Some(key) = app.keys.iter().find(|k| k.public_key == client.public_key) {
        title = title.push(
            text(format!("my key \"{}\"", key.name)).size(11).style(style::faint_text),
        );
    }
    row![
        column![
            title,
            row![
                space().width(16),
                text(truncate_middle(&client.public_key, 40))
                    .size(11)
                    .font(Font::MONOSPACE)
                    .style(style::dim_text),
            ],
        ]
        .spacing(3)
        .width(Fill),
        copy_button(client.public_key.clone()),
        button(text(if confirming { "Click again to remove" } else { "Remove…" }).size(12))
            .padding([3, 10])
            .style(style::ghost_danger)
            .on_press(Message::RemoveClient(client.public_key.clone())),
    ]
    .spacing(6)
    .align_y(Center)
    .into()
}

fn client_form_view<'a>(
    app: &'a App,
    server: &'a ServerConfig,
    form: &'a ClientForm,
) -> Element<'a, Message> {
    let validated = form.validate(&server.authorized_clients);
    let mut col = column![
        text("Authorize a client").size(13).font(semibold()),
        form_row(
            "Public key",
            input("ed25519-pub:…", &form.public_key, Message::ClientPublicKeyChanged),
        ),
        form_row("Name", input("e.g. alice laptop", &form.name, Message::ClientNameChanged)),
    ]
    .spacing(10);
    // Offer only the app's own keys not authorized yet.
    let own_keys: Vec<KeyChoice> = app
        .keys
        .iter()
        .filter(|k| !server.authorized_clients.iter().any(|c| c.public_key == k.public_key))
        .map(|k| KeyChoice {
            id: k.id.clone(),
            name: k.name.clone(),
        })
        .collect();
    if !own_keys.is_empty() {
        col = col.push(form_row(
            "",
            pick_list(own_keys, None::<KeyChoice>, Message::ClientUseOwnKey)
                .placeholder("or use one of my keys…")
                .text_size(12)
                .padding([3, 8])
                .style(style::picker)
                .menu_style(style::picker_menu),
        ));
    }
    col = col.push(
        text(
            "Only the public half of the client's auth key is needed — never its secret. \
             The flextunnel app shows it under Keys; `flexaccess-keys show-auth-key` prints \
             it as a whole entry, which can be pasted as is.",
        )
        .size(11)
        .style(style::faint_text),
    );
    // Only nag once something was typed — a fresh form just opened.
    if let Err(message) = &validated
        && !(form.name.is_empty() && form.public_key.is_empty())
    {
        col = col.push(text(message.clone()).size(12).color(AMBER));
    }
    col = col.push(
        row![
            button(text("Authorize").size(13).font(semibold()))
                .padding([6, 16])
                .style(style::primary)
                .on_press_maybe(validated.is_ok().then_some(Message::ClientFormSave)),
            button(text("Cancel").size(13))
                .padding([6, 16])
                .style(style::outlined)
                .on_press(Message::ClientFormCancel),
        ]
        .spacing(8),
    );
    container(col).padding([12, 14]).width(Fill).style(style::card).into()
}

/// The endpoint id in full, then the identity behind it: the secret, never
/// shown, which can be copied out (two clicks) to move the server, or
/// replaced — a new endpoint id, so clients must be told — through
/// [`identity_form_view`], opened in place.
fn endpoint_card<'a>(app: &'a App, server: &'a ServerConfig) -> Element<'a, Message> {
    let mut col = column![
        endpoint_field(&server.endpoint_id),
        text(
            "Share this with your clients: they enter it as the server node id when \
             adding a connection. It is public — the identity key behind it is sealed in \
             the system keychain and never shown.",
        )
        .size(11)
        .style(style::faint_text),
    ]
    .spacing(10);
    if let Some(identity) = &app.identity_form {
        col = col.push(space().height(2));
        col = col.push(identity_form_view(server, identity));
        return col.into();
    }
    let lost = server.secret.is_empty();
    if lost {
        col = col.push(
            text(
                "The identity key is missing from the keychain. Import it to start the \
                 server again with this endpoint id.",
            )
            .size(12)
            .color(AMBER),
        );
    }
    let exporting = app.confirm_export_server_secret;
    col = col.push(
        row![
            button(text(if lost { "Import key…" } else { "Replace identity…" }).size(12))
                .padding([4, 12])
                .style(style::outlined)
                .on_press(Message::ReplaceIdentity),
            button(
                text(if exporting {
                    "Click again to copy the key"
                } else {
                    "Export key…"
                })
                .size(12)
            )
            .padding([4, 12])
            .style(style::outlined)
            .on_press_maybe((!lost).then_some(Message::ExportServerSecret)),
        ]
        .spacing(8),
    );
    col.into()
}

/// An endpoint id in full, in a read-only field — iced text can't be
/// selected, so this is what lets it be selected and copied by hand — with a
/// Copy button.
fn endpoint_field<'a>(endpoint_id: &str) -> Element<'a, Message> {
    row![
        text_input("", endpoint_id)
            .on_input(|_| Message::ReadOnlyEdited)
            .font(Font::MONOSPACE)
            .size(12)
            .padding([6, 10])
            .style(style::input)
            .width(Fill),
        button(text("Copy").size(12).font(semibold()))
            .padding([5, 14])
            .style(style::tinted)
            .on_press(Message::CopyText(endpoint_id.to_owned())),
    ]
    .spacing(10)
    .align_y(Center)
    .into()
}

/// Two side-by-side choices, the picked one tinted.
fn segmented<'a>(
    left: (&'static str, Message),
    right: (&'static str, Message),
    right_picked: bool,
) -> Element<'a, Message> {
    let segment = |(label, message): (&'static str, Message), picked: bool| {
        button(text(label).size(12))
            .padding([4, 12])
            .style(if picked { style::tinted } else { style::ghost })
            .on_press(message)
    };
    row![segment(left, !right_picked), segment(right, right_picked)]
        .spacing(4)
        .into()
}

/// The identity picker shared by setup and replace: a generated key (only its
/// endpoint id shown) or a pasted one.
fn identity_picker<'a>(
    identity: &'a IdentityChoice,
    on_toggle: fn(bool) -> Message,
    on_secret: fn(String) -> Message,
) -> Column<'a, Message> {
    let mut col = column![form_row(
        "Identity",
        segmented(
            ("New identity", on_toggle(false)),
            ("Import existing key", on_toggle(true)),
            identity.import.is_some(),
        ),
    )]
    .spacing(10);
    if let Some(secret) = &identity.import {
        col = col.push(form_row(
            "Identity key",
            input("paste the key (base64)", secret, on_secret)
                .secure(true)
                .width(280),
        ));
    }
    match identity.resolve() {
        Ok((_, endpoint_id)) => {
            // Its own full-width line, so all 64 characters fit.
            col = col.push(
                column![
                    text("Endpoint id").size(12).style(style::dim_text),
                    endpoint_field(&endpoint_id),
                ]
                .spacing(6),
            );
        }
        Err(message) => {
            if identity.import.as_deref().is_some_and(|s| !s.trim().is_empty()) {
                col = col.push(text(message).size(12).color(AMBER));
            }
        }
    }
    col
}

fn identity_form_view<'a>(
    server: &'a ServerConfig,
    identity: &'a IdentityChoice,
) -> Element<'a, Message> {
    let resolved = identity.resolve();
    let mut col = column![
        text(if server.secret.is_empty() { "Import the identity key" } else { "Replace identity" })
            .size(13)
            .font(semibold()),
        identity_picker(identity, Message::IdentityImportToggled, Message::IdentitySecretChanged),
    ]
    .spacing(10);
    match &resolved {
        Ok((_, endpoint_id)) if *endpoint_id == server.endpoint_id => {
            col = col.push(
                text("Same endpoint id as now — clients need no change.")
                    .size(12)
                    .color(GREEN),
            );
        }
        Ok(_) => {
            col = col.push(
                container(
                    text(
                        "This changes the endpoint id. Clients connect by endpoint id, so \
                         every client must be updated to the new one; until then they \
                         cannot reach this server.",
                    )
                    .size(12),
                )
                .padding([9, 12])
                .width(Fill)
                .style(style::banner(AMBER)),
            );
        }
        Err(_) => {}
    }
    col = col.push(
        row![
            button(text("Save identity").size(13).font(semibold()))
                .padding([6, 16])
                .style(style::primary)
                .on_press_maybe(resolved.is_ok().then_some(Message::IdentityFormSave)),
            button(text("Cancel").size(13))
                .padding([6, 16])
                .style(style::outlined)
                .on_press(Message::IdentityFormCancel),
        ]
        .spacing(8),
    );
    col.into()
}

fn server_form_view<'a>(app: &'a App, form: &'a ServerForm) -> Element<'a, Message> {
    // Setup or settings, by whether the server has an identity yet.
    let (label, card, note) = match &form.identity {
        Some(identity) => (
            "SET UP SERVER",
            server_setup_card(app, identity),
            "The identity is the server's permanent address: clients connect to its \
             endpoint id. Next you authorize the clients; the tunnel set and relays \
             can be changed any time.",
        ),
        None => (
            "TUNNEL SET & RELAYS",
            server_settings_card(app, form),
            "The tunnel set decides what else clients may reach through this server; \
             both lists are optional, since flextunnel.internal (the status page) and \
             localhost.flextunnel.internal (this machine's localhost) are always \
             routed. Clients are authorized on the server pane.",
        ),
    };
    scrollable(
        column![
            section_label(label),
            container(card).padding([12, 14]).width(Fill).style(style::card),
            text(note).size(11).style(style::faint_text),
        ]
        .spacing(10)
        .padding([0, 4]),
    )
    .height(Fill)
    .spacing(4)
    .into()
}

/// Setup: the identity alone — a new one, or one imported to move a server
/// here — then Create server.
fn server_setup_card<'a>(app: &'a App, identity: &'a IdentityChoice) -> Element<'a, Message> {
    let mut card = column![
        identity_picker(
            identity,
            Message::ServerImportToggled,
            Message::ServerImportSecretChanged,
        ),
        text(if identity.import.is_some() {
            "Moving a server here: paste the identity key exported from the other \
             computer (or the secret line of a `flextunnel generate-iroh-key` file), so \
             its clients keep their endpoint id. Then stop the old server."
        } else {
            "A new identity for this computer. Its key stays sealed in the system \
             keychain."
        })
        .size(11)
        .style(style::faint_text),
    ]
    .spacing(10);
    let mut buttons = row![
        button(text("Create server").size(13).font(semibold()))
            .padding([6, 16])
            .style(style::primary)
            .on_press_maybe(identity.resolve().is_ok().then_some(Message::ServerFormSave)),
        button(text("Cancel").size(13))
            .padding([6, 16])
            .style(style::outlined)
            .on_press(Message::ServerFormCancel),
    ]
    .spacing(8)
    .align_y(Center);
    if let Some(notice) = &app.notice {
        buttons = buttons.push(text(notice.as_str()).size(12).style(style::dim_text));
    }
    card = card.push(buttons);
    card.into()
}

/// The existing server's tunnel set and relays.
fn server_settings_card<'a>(app: &'a App, form: &'a ServerForm) -> Element<'a, Message> {
    let validated = form.validate(app.server.as_ref());
    let mut card = column![].spacing(10);
    card = card.extend([
        form_row(
            "Routed domains",
            input(
                "optional, comma-separated, e.g. *.internal — * for all",
                &form.routed_domains,
                Message::ServerRoutedDomainsChanged,
            ),
        ),
        form_row(
            "Routed CIDRs",
            input(
                "optional, comma-separated, e.g. 10.0.0.0/8 — 0.0.0.0/0, ::/0 for all",
                &form.routed_cidrs,
                Message::ServerRoutedCidrsChanged,
            ),
        ),
        form_row(
            "Relay URLs",
            input(
                "comma-separated, optional",
                &form.relay_urls,
                Message::ServerRelayUrlsChanged,
            ),
        ),
        form_row(
            "Relay auth token",
            input(
                "optional, custom relays only",
                &form.relay_auth_token,
                Message::ServerRelayAuthTokenChanged,
            )
            .secure(true)
            .width(240),
        ),
    ]);
    if let Err(message) = &validated {
        card = card.push(text(message.clone()).size(12).color(AMBER));
    }
    let mut buttons = row![
        button(text("Save").size(13).font(semibold()))
            .padding([6, 16])
            .style(style::primary)
            .on_press_maybe(validated.is_ok().then_some(Message::ServerFormSave)),
        button(text("Cancel").size(13))
            .padding([6, 16])
            .style(style::outlined)
            .on_press(Message::ServerFormCancel),
    ]
    .spacing(8)
    .align_y(Center);
    if let Some(notice) = &app.notice {
        buttons = buttons.push(text(notice.as_str()).size(12).style(style::dim_text));
    }
    card = card.push(buttons);
    card.into()
}

// ---------------------------------------------------------------------------
// Keys pane

fn keys_pane(app: &App) -> Element<'_, Message> {
    let header = row![
        section_label(if app.keys.is_empty() {
            "AUTH KEYS".to_string()
        } else {
            format!("AUTH KEYS · {}", app.keys.len())
        }),
        space().width(Fill),
        button(text("+ Add key").size(12).font(semibold()))
            .padding([4, 12])
            .style(style::tinted)
            .on_press(Message::AddKey),
    ]
    .align_y(Center);

    let mut col = column![header].spacing(12);
    if let Some(notice) = &app.notice {
        col = col.push(text(notice.as_str()).size(12).style(style::dim_text));
    }
    if let Some(form) = &app.key_form {
        col = col.push(key_form_view(app, form));
    }

    if app.keys.is_empty() {
        col = col.push(
            container(
                text("No auth keys yet. Add one to authenticate profiles with — any number \
                      of profiles can share the same key.")
                    .size(12)
                    .style(style::dim_text),
            )
            .padding(24)
            .width(Fill)
            .align_x(Center)
            .style(style::card),
        );
    }
    for key in &app.keys {
        // The edited key is represented by the open form above, not its card.
        if let Some(form) = &app.key_form
            && form.editing_id() == Some(key.id.as_str())
        {
            continue;
        }
        col = col.push(key_card(app, key));
    }
    col = col.push(
        text("These are this computer's client keys, for its connections. Secret halves live \
              in the system keychain; names and public keys in a local file. Each server a \
              key connects to must authorize its public half.")
            .size(11)
            .style(style::faint_text),
    );

    scrollable(col.padding([0, 4])).height(Fill).spacing(4).into()
}

fn key_card<'a>(app: &'a App, key: &'a AuthKey) -> Element<'a, Message> {
    let users: Vec<&str> = app
        .profiles
        .iter()
        .filter(|p| p.auth_key_id == key.id)
        .map(|p| p.name.as_str())
        .collect();
    let confirming = app.confirm_delete_key.as_deref() == Some(key.id.as_str());
    let exporting = app.confirm_export_key.as_deref() == Some(key.id.as_str());

    let header = row![
        text(key.name.as_str()).size(14).font(semibold()),
        space().width(Fill),
        button(text("Edit").size(12))
            .padding([3, 10])
            .style(style::ghost)
            .on_press(Message::EditKey(key.id.clone())),
        // Disabled while the secret is missing from the keychain — the amber
        // line below already says why.
        button(
            text(if exporting { "Click again to copy secret" } else { "Export…" }).size(12)
        )
        .padding([3, 10])
        .style(style::ghost)
        .on_press_maybe(
            (!key.secret.is_empty()).then(|| Message::ExportKey(key.id.clone())),
        ),
        button(
            text(if confirming { "Click again to delete" } else { "Delete…" }).size(12)
        )
        .padding([3, 10])
        .style(style::ghost_danger)
        .on_press(Message::DeleteKey(key.id.clone())),
    ]
    .spacing(6)
    .align_y(Center);

    let mut card = column![
        header,
        info_row(
            "Public key",
            truncate_middle(&key.public_key, 30),
            Some(key.public_key.clone()),
        ),
    ]
    .spacing(8);
    if key.secret.is_empty() {
        card = card.push(
            text("Secret missing from the keychain — edit this key to re-enter it.")
                .size(12)
                .color(AMBER),
        );
    }
    card = card.push(
        text(if users.is_empty() {
            "Not used by any profile.".to_string()
        } else {
            format!("Used by: {}", users.join(", "))
        })
        .size(11)
        .style(style::faint_text),
    );

    container(card).padding([12, 14]).width(Fill).style(style::card).into()
}

fn key_form_view<'a>(app: &'a App, form: &'a KeyForm) -> Element<'a, Message> {
    let validated = form.validate(&app.keys);

    // The secret stays masked; the derived public key below is not a secret
    // and is always shown unmasked (it's what goes on the server's
    // authorized-keys file).
    let secret = row![
        input("ed25519-sec:…", &form.secret, Message::KeySecretChanged)
            .secure(true)
            .width(240),
        button(text("Generate").size(12))
            .padding([4, 10])
            .style(style::outlined)
            .on_press(Message::KeyGenerateSecret),
    ]
    .spacing(8)
    .align_y(Center);

    let mut col = column![
        text(if form.is_edit() { "Edit key" } else { "Add key" })
            .size(13)
            .font(semibold()),
        form_row("Name", input("e.g. work laptop", &form.name, Message::KeyNameChanged)),
        form_row("Secret key", secret),
    ]
    .spacing(10);
    // The validated key already carries the derived public half; deriving it
    // again is only needed when validation failed for another reason (e.g. a
    // name clash) but the secret itself parses.
    let public_key = match &validated {
        Ok(key) => Some(key.public_key.clone()),
        Err(_) => form.public_key(),
    };
    if let Some(public_key) = public_key {
        col = col.push(form_row(
            "Public key",
            row![
                text(truncate_middle(&public_key, 30)).size(12).font(Font::MONOSPACE),
                copy_button(public_key),
            ]
            .spacing(8)
            .align_y(Center),
        ));
    }

    if let Err(message) = &validated {
        col = col.push(text(message.clone()).size(12).color(AMBER));
    }
    col = col.push(
        row![
            button(text("Save").size(13).font(semibold()))
                .padding([6, 16])
                .style(style::primary)
                .on_press_maybe(validated.is_ok().then_some(Message::KeyFormSave)),
            button(text("Cancel").size(13))
                .padding([6, 16])
                .style(style::outlined)
                .on_press(Message::KeyFormCancel),
        ]
        .spacing(8)
        .align_y(Center),
    );

    container(col).padding([12, 14]).width(Fill).style(style::card).into()
}

// ---------------------------------------------------------------------------
// Logs

fn logs_pane(app: &App) -> Element<'_, Message> {
    let mut filter_options = vec![LogFilter::All];
    if app.server.is_some() {
        filter_options.push(LogFilter::Server);
    }
    filter_options.extend(app.profiles.iter().map(|p| LogFilter::Profile(p.name.clone())));
    let selected = app.log_filter.clone();

    let header = row![
        section_label("LOGS".to_string()),
        space().width(Fill),
        pick_list(filter_options, Some(selected), Message::LogFilterChanged)
            .text_size(12)
            .padding([3, 8])
            .style(style::picker)
            .menu_style(style::picker_menu),
        button(text("Open folder").size(12))
            .padding([4, 10])
            .style(style::ghost)
            .on_press(Message::OpenLogFolder),
        button(text("Copy all").size(12))
            .padding([4, 10])
            .style(style::ghost)
            .on_press(Message::CopyLogs),
    ]
    .spacing(4)
    .align_y(Center);

    let log = scrollable(
        text(app.log_text.as_str())
            .size(11)
            .font(Font::MONOSPACE)
            .width(Fill),
    )
    .direction(scrollable::Direction::Vertical(
        scrollable::Scrollbar::new().spacing(4),
    ))
    .anchor_bottom()
    .width(Fill)
    .height(Fill);

    column![
        header,
        container(log)
            .padding([8, 10])
            .width(Fill)
            .height(Fill)
            .style(style::card),
    ]
    .spacing(10)
    .into()
}

// ---------------------------------------------------------------------------
// Shared bits

fn info_row(label: &'static str, value: String, copy: Option<String>) -> Element<'static, Message> {
    let display = if value.is_empty() { "—".into() } else { value };
    let mut r = row![
        text(label).size(12).style(style::dim_text).width(110),
        text(display).size(12).font(Font::MONOSPACE),
    ]
    .spacing(10)
    .align_y(Center);
    if let Some(copy) = copy {
        r = r.push(space().width(Fill));
        r = r.push(copy_button(copy));
    }
    r.into()
}

/// Small quiet "Copy" button feeding `Message::CopyText` — iced `text` isn't
/// selectable, so this is the only way to lift a value out of the UI.
fn copy_button(value: String) -> Element<'static, Message> {
    button(text("Copy").size(11))
        .padding([2, 8])
        .style(style::ghost)
        .on_press(Message::CopyText(value))
        .into()
}

/// A `left → right` entry with its own Copy button on each side — used for host
/// aliases (alias / server-resolved target) and port forwards (local / remote
/// endpoint), where either side may be the value you want. `dim` renders the
/// values in the secondary text color (the forward route under its bold name).
fn arrow_copy_row<'a>(left: String, right: String, dim: bool) -> Element<'a, Message> {
    let cell = |value: String| -> Element<'static, Message> {
        let t = text(value).size(12).font(Font::MONOSPACE);
        if dim { t.style(style::dim_text).into() } else { t.into() }
    };
    row![
        cell(left.clone()),
        copy_button(left),
        cell("→".into()),
        cell(right.clone()),
        copy_button(right),
    ]
    .spacing(8)
    .align_y(Center)
    .into()
}

/// A dimmed sub-label indented under a route entry (e.g. "routed domains:").
fn indented_label<'a>(label: &'static str) -> Element<'a, Message> {
    row![space().width(16), text(label).size(12).style(style::dim_text)]
        .spacing(6)
        .align_y(Center)
        .into()
}

/// A monospace list item indented under a sub-label (rendered as "- value").
fn indented_item<'a>(value: &str) -> Element<'a, Message> {
    row![space().width(32), mono(format!("- {value}"))]
        .spacing(6)
        .align_y(Center)
        .into()
}

/// An [`indented_item`] followed by a dimmed note saying what it is for.
fn indented_note_item<'a>(value: &str, note: &'static str) -> Element<'a, Message> {
    row![
        space().width(32),
        mono(format!("- {value}")),
        text(format!("— {note}")).size(12).style(style::dim_text),
    ]
    .spacing(6)
    .align_y(Center)
    .into()
}

/// A monospace routing entry with a right-aligned Copy button. `trailing` is an
/// optional badge shown before the button.
fn route_row<'a>(value: String, trailing: Option<Element<'a, Message>>) -> Element<'a, Message> {
    let mut r = row![mono(value.clone())].spacing(8).align_y(Center);
    if let Some(trailing) = trailing {
        r = r.push(trailing);
    }
    r = r.push(space().width(Fill));
    r = r.push(copy_button(value));
    r.into()
}

fn form_row<'a>(
    label: &'static str,
    input: impl Into<Element<'a, Message>>,
) -> Element<'a, Message> {
    row![
        text(label).size(12).style(style::dim_text).width(100),
        input.into(),
    ]
    .spacing(10)
    .align_y(Center)
    .into()
}

fn input<'a>(
    placeholder: &'a str,
    value: &'a str,
    on_input: fn(String) -> Message,
) -> iced::widget::TextInput<'a, Message> {
    text_input(placeholder, value)
        .on_input(on_input)
        .size(13)
        .padding([6, 10])
        .style(style::input)
}

/// Shorten to `max` characters by replacing the middle with an ellipsis.
/// ASCII-safe inputs only (node ids, addresses).
fn truncate_middle(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.into();
    }
    let keep = (max - 1) / 2;
    format!("{}…{}", &s[..keep], &s[s.len() - keep..])
}

fn section_label(label: impl Into<String>) -> Element<'static, Message> {
    text(label.into())
        .size(11)
        .font(semibold())
        .style(style::dim_text)
        .into()
}

fn mono<'a>(fragment: impl text::IntoFragment<'a>) -> Element<'a, Message> {
    text(fragment).size(12).font(Font::MONOSPACE).into()
}

/// Small tinted pill badge (forward state, phase).
fn pill(label: impl Into<String>, color: Color) -> Element<'static, Message> {
    container(text(label.into()).size(11).font(semibold()).color(color))
        .padding([2, 8])
        .style(style::pill(color))
        .into()
}

/// Small filled status dot, vertically centered against the row text.
fn dot(color: Color, size: f32) -> Element<'static, Message> {
    container(space())
        .width(size)
        .height(size)
        .style(style::dot(color))
        .into()
}

fn semibold() -> Font {
    Font {
        weight: iced::font::Weight::Semibold,
        ..Font::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn middle_truncation() {
        assert_eq!(truncate_middle("short", 22), "short");
        let id = "feedfacefeedfacefeedfacefeedface";
        let shown = truncate_middle(id, 22);
        assert_eq!(shown, "feedfacefe…cefeedface");
        assert!(shown.chars().count() <= 22);
    }

    #[test]
    fn full_tunnel_derivation() {
        let mut routes = TunnelRoutes::default();
        assert!(!is_full_tunnel(&routes), "an empty set tunnels only the reserved hosts");
        routes.domains = vec!["example.com".into()];
        assert!(!is_full_tunnel(&routes));
        routes.domains.push("*".into());
        assert!(is_full_tunnel(&routes));
        routes.domains = vec!["example.com".into()];
        routes.cidrs = vec!["0.0.0.0/0".into()];
        assert!(is_full_tunnel(&routes));
    }
}
