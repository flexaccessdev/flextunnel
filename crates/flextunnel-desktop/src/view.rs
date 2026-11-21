//! Widget tree for the sidebar (the client and its destinations, then the
//! server) + detail-pane window, rendered from
//! [`App`] state — all pure functions of `&App`, every mutation flows back
//! through a [`Message`]. The look (cards, pills, ghost buttons, sidebar rows)
//! comes from the design system in [`crate::style`].

use crate::app::{
    format_duration, App, ClientForm, DestinationForm, DestinationLive, ForwardForm,
    IdentityChoice, KeyChoice, KeyForm, LogFilter, Message, ProxyForm, RoutesFetch, Selection,
    ServerForm, StoreReset,
};
use crate::config::{self, AuthKey, AuthorizedClient, Destination, ServerConfig};
use crate::server_session::ServerPhase;
use crate::tray::clients_connected;
use flextunnel_core::forwards::{ForwardState, ForwardStatus, PortForward};
use crate::style::{self, AMBER, GRAY, GREEN, RED};
use crate::tunnel::ClientPhase;
use flextunnel_core::proxy::signaling::Target;
use flextunnel_core::proxy::routed_set::Coverage;
use flextunnel_core::proxy::{DestinationState, Route, RouteTable, reserved};
use flextunnel_core::transport::paths::{ConnPathKind, ConnectionSnapshot, CustomRelayStatus};
use iced::widget::{
    button, center, checkbox, column, container, mouse_area, opaque, pick_list, row, scrollable,
    space, stack, text, text_input, toggler, Column,
};
use iced::{Center, Color, Element, Fill, Font};
use std::net::SocketAddr;

/// One destination's routing input: `(host, routed domains, routed CIDRs)`.
type RouteKey = (String, Vec<String>, Vec<String>);

/// The forwards' advisory routing table — which destination carries each, if
/// any — rebuilt only when a destination's host or routes change.
#[derive(Default)]
pub struct RoutedCache {
    /// What the table was built from, per destination; `None` before the
    /// first build.
    built_from: Option<Vec<RouteKey>>,
    /// `None` when the destinations do not make a valid table: the client
    /// then cannot start, and no badge is shown.
    pub table: Option<RouteTable>,
}

/// Rebuild the advisory routing table over `destinations` only when their
/// hosts or routes changed.
pub fn refresh_routed_cache<'a, I>(cache: &mut RoutedCache, destinations: I)
where
    I: IntoIterator<Item = &'a Destination>,
    I::IntoIter: Clone,
{
    let destinations = destinations.into_iter();
    let fresh = cache.built_from.as_ref().is_some_and(|built| {
        built.len() == destinations.clone().count()
            && built.iter().zip(destinations.clone()).all(|((host, domains, cidrs), d)| {
                *host == d.host && *domains == d.routed_domains && *cidrs == d.routed_cidrs
            })
    });
    if !fresh {
        cache.table = config::route_table_of(destinations.clone())
            .inspect_err(|e| log::debug!("Routes unusable for the forward badges: {e}"))
            .ok();
        cache.built_from = Some(
            destinations
                .map(|d| (d.host.clone(), d.routed_domains.clone(), d.routed_cidrs.clone()))
                .collect(),
        );
    }
}

/// Everything is tunneled only when a destination routes all three kinds of
/// target: every hostname (`*`), every IPv4 address and every IPv6 address.
/// Each rule covers its own kind alone — `0.0.0.0/0` says nothing about a
/// hostname or an IPv6 address.
fn is_full_tunnel(domains: &[String], cidrs: &[String]) -> bool {
    domains.iter().any(|d| d == "*")
        && cidrs.iter().any(|c| c == "0.0.0.0/0")
        && cidrs.iter().any(|c| c == "::/0")
}

/// The host of the destination that carries a forward, by the client's
/// routing: `Some(None)` when none does, `None` when unknown (no badge).
/// Mirrors the core's routing decision — a destination's own host, or a host
/// on its routed lists — and matters more for a forward than for the proxy: a
/// forward never connects directly, so one whose host nothing routes can only
/// fail.
fn forward_route<'a>(
    table: Option<&'a RouteTable>,
    forward: &PortForward,
) -> Option<Option<&'a str>> {
    let table = table?;
    let target = Target::Domain(forward.remote_host.clone(), forward.remote_port);
    Some(match table.route(&target) {
        Route::Tunnel { dest, .. } => table.hosts().nth(dest),
        _ => None,
    })
}

/// What a forward's row says about its route: the one in effect — by the
/// running client's table when there is one, else by the saved destinations,
/// which are what a start will use — and, when the running client routes it
/// differently than the saved destinations would, what a restart changes it
/// to. A saved route is never shown as the one a running forward takes.
fn forward_route_labels<'a>(
    running: Option<Option<&'a str>>,
    saved: Option<Option<&'a str>>,
) -> (Option<Option<&'a str>>, Option<String>) {
    let Some(running) = running else {
        return (saved, None);
    };
    let after_restart = saved.filter(|saved| *saved != running).map(|saved| match saved {
        Some(host) => format!("after restart: via {host}"),
        None => "after restart: no route".to_string(),
    });
    (Some(running), after_restart)
}

/// Live state pill for a forward row: gray "stopped", amber "starting…",
/// green "listening (· N)", red "failed" (the reason shows under the route).
fn forward_pill(
    forward: &PortForward,
    status: Option<&ForwardStatus>,
    phase: ClientPhase,
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
        // No status = no running session for this forward. The client's
        // banner explains the not-running case in one place.
        None => match phase {
            ClientPhase::Starting | ClientPhase::Running => ("starting…".into(), AMBER),
            _ => ("stopped".into(), GRAY),
        },
    }
}

fn client_phase_color(phase: ClientPhase) -> Color {
    match phase {
        ClientPhase::Stopped => GRAY,
        ClientPhase::Starting | ClientPhase::Stopping => AMBER,
        ClientPhase::Running => GREEN,
        ClientPhase::Failed => RED,
    }
}

fn client_phase_label(phase: ClientPhase) -> &'static str {
    match phase {
        ClientPhase::Stopped => "stopped",
        ClientPhase::Starting => "starting…",
        ClientPhase::Running => "running",
        ClientPhase::Stopping => "stopping…",
        ClientPhase::Failed => "failed",
    }
}

/// A destination's state word and color. Idle is the resting state of a
/// destination nobody is using — gray, not a fault — unless its last attempt
/// failed: the core rests it all the same once nothing is waiting (a refused
/// key, after its retry delay), and that must not read as healthy.
fn destination_state(live: &DestinationLive<'_>) -> (&'static str, Color) {
    match live {
        DestinationLive::Stopped => ("client off", GRAY),
        DestinationLive::Pending => ("restart to apply", AMBER),
        DestinationLive::Live(status) => match status.state {
            DestinationState::Idle if status.last_error.is_some() => {
                ("last attempt failed", AMBER)
            }
            DestinationState::Idle => ("idle", GRAY),
            DestinationState::Connecting => ("connecting…", AMBER),
            DestinationState::Connected => ("connected", GREEN),
            DestinationState::Backoff => ("retrying…", AMBER),
            DestinationState::Failed => ("refused", RED),
        },
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

/// Whether a full-pane form (destination or server) replaces the detail pane,
/// so no sidebar row reads as selected.
fn form_open(app: &App) -> bool {
    app.destination_form.is_some() || app.server_form.is_some()
}

pub fn root(app: &App) -> Element<'_, Message> {
    let base: Element<'_, Message> = row![sidebar(app), detail_pane(app)].into();
    // The reset warning must be answered, so it sits above everything and
    // its backdrop does nothing.
    if let Some(reset) = &app.store_reset {
        return modal(base, store_reset_modal(reset), None);
    }
    match &app.conn_path_modal {
        Some(snapshot) => {
            modal(base, conn_path_modal(snapshot), Some(Message::DismissConnPath))
        }
        None => base,
    }
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

/// The store reset warning (see [`App::store_reset`]): what could not be
/// read and why, then quit with it left on disk, or start fresh without it.
fn store_reset_modal(reset: &StoreReset) -> Element<'_, Message> {
    const SECRETS: &str = "The auth-key secrets, the server identity key and the relay auth \
                           tokens will all be empty and must be re-entered.";
    let (title, why, keep, lost) = match reset {
        StoreReset::Version(version) => {
            let sealed_by = match version {
                0 => "an earlier version of flextunnel".to_string(),
                v => format!("format version {v}"),
            };
            (
                "Saved secrets can't be read",
                format!(
                    "Your secrets were saved by {sealed_by}, which this version stores \
                     differently. {SECRETS}"
                ),
                "the previous version of flextunnel can still read them, for example to \
                 export the keys first.",
                "deletes them",
            )
        }
        StoreReset::Unsealable => (
            "Saved secrets can't be read",
            format!(
                "Your secrets are sealed in profiles.json under a master key kept in the \
                 system keychain (\"Flextunnel Safe Storage\"), and the key there no \
                 longer opens them: the entry was deleted or replaced. {SECRETS}"
            ),
            "they open again once the original keychain entry is restored, for example \
             from a backup.",
            "deletes them",
        ),
        StoreReset::Unreadable(error) => (
            "Saved settings can't be read",
            format!(
                "flextunnel couldn't load its settings: {error}. It is running with none: \
                 no destinations, keys or server."
            ),
            "fix the cause (for example, allow flextunnel to read its \"Flextunnel Safe \
             Storage\" keychain entry) and open flextunnel again.",
            "replaces them with empty settings, deleting every destination, key and the \
             server",
        ),
    };
    let card = column![
        text(title).size(15).font(semibold()),
        text(why).size(12),
        text(format!(
            "Quit now to leave them on disk untouched — {keep} Starting fresh {lost} for \
             good."
        ))
        .size(12)
        .color(AMBER),
        row![
            space().width(Fill),
            button(text("Quit").size(12))
                .padding([5, 14])
                .style(style::ghost)
                .on_press(Message::StoreResetQuit),
            button(text("Start fresh").size(12))
                .padding([5, 14])
                .style(style::primary)
                .on_press(Message::StoreResetContinue),
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

/// The connection-path modal card: a point-in-time snapshot of how the client
/// reaches a destination's server, each path dotted by transport (direct/relay) with the
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
        text("Snapshot taken just now — how the client reaches this server.")
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
    // The client — its one row, then the destinations it reaches — and the
    // server: one per user, so a single slot rather than a list: its row, or
    // the way to set it up. Neither role is required; each is set up here
    // whenever wanted.
    let mut list = column![section_label("CLIENT"), sidebar_client_row(app)].spacing(2);
    list = list.push(space().height(10));
    list = list.push(
        row![
            section_label("DESTINATIONS"),
            space().width(Fill),
            button(text("+").size(14).font(semibold()))
                .padding([1, 9])
                .style(style::tinted)
                .on_press(Message::AddDestination),
        ]
        .align_y(Center),
    );
    for destination in &app.client.destinations {
        list = list.push(sidebar_destination_row(app, destination));
    }
    if app.client.destinations.is_empty() {
        list = list.push(
            container(text("No destinations yet.").size(11).style(style::faint_text))
                .padding([4, 10]),
        );
    }
    list = list.push(space().height(10));
    list = list.push(section_label("SERVER"));
    // Unset, the slot leads to the server's welcome, and stays selected
    // through the setup form it opens.
    let welcome_selected = app.server_form.is_some()
        || (app.selection == Selection::Server && app.destination_form.is_none());
    list = list.push(match &app.server {
        Some(server) => sidebar_server_row(app, server),
        None => button(text("Set up server…").size(13).style(style::dim_text))
            .padding([6, 10])
            .width(Fill)
            .style(style::sidebar_row(welcome_selected))
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

    // Destinations and forwards, to move them to another computer.
    let exportable = !app.client.destinations.is_empty() || !app.client.forwards.is_empty();
    let io_row = row![
        button(text("Export").size(11))
            .padding([3, 10])
            .style(style::ghost)
            .on_press_maybe(exportable.then_some(Message::ExportClient)),
        button(text("Import").size(11))
            .padding([3, 10])
            .style(style::ghost)
            .on_press(Message::ImportClient),
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

/// The client's state word and color for its hero and sidebar row: a disabled
/// client that has stopped reads as "disabled", not "stopped".
fn client_state(app: &App) -> (&'static str, Color) {
    let phase = app.client_snapshot.phase;
    if !app.client.enabled && phase == ClientPhase::Stopped {
        ("disabled", GRAY)
    } else {
        (client_phase_label(phase), client_phase_color(phase))
    }
}

/// The client's one-line state for the sidebar: running with how many
/// destinations are connected, what it is waiting for, or its phase.
fn client_row_status(app: &App) -> String {
    let snapshot = &app.client_snapshot;
    match snapshot.phase {
        ClientPhase::Running => {
            let connected = snapshot
                .destinations
                .iter()
                .filter(|d| d.state == DestinationState::Connected)
                .count();
            match connected {
                0 => "running · none connected".into(),
                n => format!("running · {n} connected"),
            }
        }
        ClientPhase::Stopped if app.client.enabled && app.client.destinations.is_empty() => {
            "needs a destination".into()
        }
        _ => client_state(app).0.into(),
    }
}

fn sidebar_client_row(app: &App) -> Element<'_, Message> {
    let selected = app.selection == Selection::Client && !form_open(app);
    let running = app.client_snapshot.phase == ClientPhase::Running;
    let content = column![
        row![
            dot(client_state(app).1, 8.0),
            text("Proxy & forwards").size(13).font(semibold()),
        ]
        .spacing(7)
        .align_y(Center),
        row![
            space().width(15),
            text(client_row_status(app)).size(11).style(if running {
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
        .on_press(Message::Select(Selection::Client))
        .into()
}

fn sidebar_destination_row<'a>(
    app: &'a App,
    destination: &'a Destination,
) -> Element<'a, Message> {
    let live = app.destination_live(destination);
    let (label, color) = destination_state(&live);
    let selected =
        app.selection == Selection::Destination(destination.id.clone()) && !form_open(app);
    let mut status = label.to_string();
    if let DestinationLive::Live(live) = &live
        && live.open_streams > 0
    {
        status.push_str(&format!(" · {} open", live.open_streams));
    }
    let content = column![
        row![
            dot(color, 8.0),
            text(destination.host.as_str()).size(13).font(semibold()),
        ]
        .spacing(7)
        .align_y(Center),
        row![
            space().width(15),
            text(status).size(11).style(if color == GREEN {
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
        .on_press(Message::Select(Selection::Destination(destination.id.clone())))
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
    let content: Element<'_, Message> = if let Some(form) = &app.destination_form {
        destination_form_view(app, form)
    } else if let Some(form) = &app.server_form {
        server_form_view(app, form)
    } else {
        match &app.selection {
            Selection::Empty => empty_state(),
            Selection::Client => client_detail(app),
            Selection::Keys => keys_pane(app),
            Selection::Logs => logs_pane(app),
            Selection::Destination(id) => match app.client.destination(id) {
                Some(destination) => destination_detail(app, destination),
                None => empty_state(),
            },
            Selection::Server => match &app.server {
                Some(server) => server_detail(app, server),
                None => server_welcome(),
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
                "Use + next to Destinations to reach a flextunnel server elsewhere, or \
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

/// A tinted one-line banner: a dot, a message, and optionally a button.
fn banner<'a>(
    color: Color,
    message: impl text::IntoFragment<'a>,
    action: Option<(&'static str, Message)>,
) -> Element<'a, Message> {
    let mut r = row![dot(color, 8.0), text(message).size(12)]
        .spacing(8)
        .align_y(Center);
    if let Some((label, message)) = action {
        r = r.push(space().width(Fill));
        r = r.push(
            button(text(label).size(11).font(semibold()))
                .padding([3, 10])
                .style(style::tinted)
                .on_press(message),
        );
    }
    container(r)
        .padding([9, 12])
        .width(Fill)
        .style(style::banner(color))
        .into()
}

/// The banner offering the restart that applies saved settings to a running
/// client. Shown on the client pane and on every destination's.
fn restart_banner<'a>() -> Element<'a, Message> {
    banner(
        AMBER,
        "Saved changes apply once the client restarts, which closes its open connections.",
        Some(("Restart now", Message::RestartClient)),
    )
}

/// The client pane: its on/off switch and state, the proxy front-ends, and
/// the port forwards. Where it goes is the destinations' business.
fn client_detail(app: &App) -> Element<'_, Message> {
    let client = &app.client;
    let snapshot = &app.client_snapshot;
    let running = snapshot.phase == ClientPhase::Running;

    let (label, color) = client_state(app);
    let mut hero = row![
        dot(color, 12.0),
        text("Client").size(20).font(semibold()),
        pill(label.to_string(), color),
    ]
    .spacing(10)
    .align_y(Center);
    if let Some(since) = snapshot.running_since {
        hero = hero.push(
            text(format!("for {}", format_duration(since.elapsed())))
                .size(13)
                .style(style::dim_text),
        );
    }
    hero = hero.push(space().width(Fill));
    // The client's only on/off control, persisted: enabled, it runs (and
    // starts with the app); disabled, it stays stopped across launches. Not
    // switchable while its endpoints are still closing.
    let mut switch = toggler(client.enabled)
        .label("Enabled")
        .text_size(13)
        .size(20)
        .style(style::switch);
    if snapshot.phase != ClientPhase::Stopping {
        switch = switch.on_toggle(Message::SetClientEnabled);
    }
    hero = hero.push(switch);

    let mut col = column![hero].spacing(12);
    if let Some(notice) = &app.notice {
        col = col.push(text(notice.as_str()).size(12).style(style::dim_text));
    }
    if let Some(error) = &snapshot.last_error {
        col = col.push(text(error.as_str()).size(12).color(RED));
    }
    if client.enabled && snapshot.phase == ClientPhase::Failed {
        col = col.push(
            text("Change what failed, or switch it off and on again to retry.")
                .size(12)
                .style(style::dim_text),
        );
    }
    if client.enabled
        && !running
        && let Some(blocker) = client.start_blocker(&app.keys)
    {
        let add = client
            .destinations
            .is_empty()
            .then_some(("Add destination", Message::AddDestination));
        col = col.push(banner(AMBER, blocker, add));
    }
    if app.client_needs_restart() {
        col = col.push(restart_banner());
    }
    if running {
        col = col.push(
            text(
                "Listening. Each destination is connected when something is first sent to \
                 it, and disconnected again after five minutes without use.",
            )
            .size(12)
            .style(style::dim_text),
        );
    }

    // PROXIES card (or its form)
    col = col.push(
        row![
            section_label("PROXIES"),
            space().width(Fill),
            button(text("Edit").size(12))
                .padding([3, 10])
                .style(style::ghost)
                .on_press(Message::EditProxies),
        ]
        .align_y(Center),
    );
    if let Some(form) = &app.proxy_form {
        col = col.push(proxy_form_view(app, form));
    } else {
        let loopback = |port: u16| SocketAddr::from(([127, 0, 0, 1], port)).to_string();
        let mut info = column![].spacing(8);
        info = info.push(match client.socks_port.map(loopback) {
            Some(addr) => {
                let copy = Some(format!("socks5h://{addr}"));
                info_row("SOCKS5 proxy", addr, copy)
            }
            None => info_row("SOCKS5 proxy", "off".into(), None),
        });
        info = info.push(match client.http_port.map(loopback) {
            Some(addr) => {
                let copy = Some(format!("http://{addr}"));
                info_row("HTTP proxy", addr, copy)
            }
            None => info_row("HTTP proxy", "off".into(), None),
        });
        if client.socks_port.is_some() || client.http_port.is_some() {
            // The client's own status page lives under the reserved name,
            // answered locally through either proxy — surface it so it is
            // discoverable (and copyable).
            let page = format!("http://{}/", reserved::STATUS_HOST);
            info = info.push(info_row("Status page", page.clone(), Some(page)));
        }
        col = col.push(container(info).padding([12, 14]).width(Fill).style(style::card));
        col = col.push(
            text(
                "Point a proxy-aware app at either one. A request for a destination's host \
                 or one of its routes goes through that destination; anything else connects \
                 directly from this computer.",
            )
            .size(11)
            .style(style::faint_text),
        );
    }

    // PORT FORWARDS
    col = col.push(
        row![
            section_label(if client.forwards.is_empty() {
                "PORT FORWARDS".to_string()
            } else {
                format!("PORT FORWARDS · {}", client.forwards.len())
            }),
            space().width(Fill),
            button(text("+ Add").size(12).font(semibold()))
                .padding([4, 12])
                .style(style::tinted)
                .on_press(Message::AddForward),
        ]
        .align_y(Center),
    );
    if !client.forwards.is_empty()
        && !matches!(snapshot.phase, ClientPhase::Starting | ClientPhase::Running)
    {
        col = col.push(banner(
            GRAY,
            "The client is not running — forwards are inactive until it is.",
            None,
        ));
    }

    // Inline add/edit form — one at a time; an inline card fits the window
    // better than a separate one.
    if let Some(form) = &app.forward_form {
        col = col.push(forward_form_view(app, form));
    }

    if client.forwards.is_empty() {
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
        for forward in &client.forwards {
            col = col.push(forward_card(app, forward));
        }
        col = col.push(
            text(
                "Forwards listen on localhost only (127.0.0.1 and ::1) and always go \
                 through a destination, never directly — so the remote host must be a \
                 destination's host or one of its routes. That server rejects targets \
                 outside its tunnel set.",
            )
            .size(11)
            .style(style::faint_text),
        );
    }

    scrollable(col.padding([0, 4])).height(Fill).spacing(4).into()
}

fn proxy_form_view<'a>(app: &'a App, form: &'a ProxyForm) -> Element<'a, Message> {
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

    let validated = form.validate(&app.client);
    let mut col = column![form_row("SOCKS5 proxy", socks), form_row("HTTP proxy", http)]
        .spacing(10);
    if let Err(message) = &validated {
        col = col.push(text(message.clone()).size(12).color(AMBER));
    }
    col = col.push(
        row![
            button(text("Save").size(13).font(semibold()))
                .padding([6, 16])
                .style(style::primary)
                .on_press_maybe(validated.is_ok().then_some(Message::ProxyFormSave)),
            button(text("Cancel").size(13))
                .padding([6, 16])
                .style(style::outlined)
                .on_press(Message::ProxyFormCancel),
        ]
        .spacing(8),
    );
    container(col)
        .padding([12, 14])
        .width(Fill)
        .style(style::card)
        .into()
}

fn forward_form_view<'a>(app: &'a App, form: &'a ForwardForm) -> Element<'a, Message> {
    let validated = form.validate(&app.client);

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
                "a destination's host, or one of its routes",
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

fn forward_card<'a>(app: &'a App, forward: &'a PortForward) -> Element<'a, Message> {
    let snapshot = &app.client_snapshot;
    let status = snapshot.forwards.iter().find(|s| s.id == forward.id);
    let (pill_text, pill_color) = forward_pill(forward, status, snapshot.phase);

    // The name stays prominent even while stopped — the pill and the switch
    // carry the state.
    let name = text(forward.display_name()).size(14).font(semibold());

    let mut title = row![name, pill(pill_text, pill_color)]
        .spacing(8)
        .align_y(Center);
    // Which destination carries it — or the problem: nothing does. A running
    // client carries it by the destinations it started with, which saved
    // changes have not reached yet.
    let running = app.running_route_table().and_then(|table| forward_route(Some(table), forward));
    let saved = forward_route(app.routed_cache.table.as_ref(), forward);
    let (route, after_restart) = forward_route_labels(running, saved);
    match route {
        Some(Some(host)) => {
            title = title.push(text(format!("via {host}")).size(11).style(style::dim_text));
        }
        Some(None) => title = title.push(pill("no route".to_string(), AMBER)),
        None => {}
    }
    if let Some(after_restart) = after_restart {
        title = title.push(text(after_restart).size(11).color(AMBER));
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

    let forward_id = forward.id.clone();
    let controls = row![
        button(text("Edit").size(12))
            .padding([4, 10])
            .style(style::ghost)
            .on_press(Message::EditForward(forward.id.clone())),
        button(text("Delete").size(12))
            .padding([4, 10])
            .style(style::ghost_danger)
            .on_press(Message::DeleteForward(forward.id.clone())),
        // Desired state, but not a plain checkbox: enabling attempts the
        // setup now, and a setup failure snaps the switch back off (see
        // disable_failed_forwards).
        toggler(forward.enabled)
            .on_toggle(move |enabled| Message::ToggleForward(forward_id.clone(), enabled))
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

/// One destination's pane: how it stands right now, the server behind its
/// name, and what is sent through it.
fn destination_detail<'a>(app: &'a App, destination: &'a Destination) -> Element<'a, Message> {
    let live = app.destination_live(destination);
    let (label, color) = destination_state(&live);
    let status = match &live {
        DestinationLive::Live(status) => Some(*status),
        _ => None,
    };

    let mut hero = row![
        dot(color, 12.0),
        text(destination.host.as_str()).size(20).font(semibold()),
        pill(label.to_string(), color),
    ]
    .spacing(10)
    .align_y(Center);
    if let Some(since) = status.and_then(|s| s.connected_since) {
        hero = hero.push(
            text(format!("for {}", format_duration(since.elapsed())))
                .size(13)
                .style(style::dim_text),
        );
    }
    hero = hero.push(space().width(Fill));
    // Connecting is on demand; this asks for one attempt now, to see whether
    // the server is reachable without sending anything to it.
    if let Some(status) = status
        && matches!(
            status.state,
            DestinationState::Idle | DestinationState::Backoff | DestinationState::Failed
        )
    {
        hero = hero.push(
            button(text("Connect now").size(13).font(semibold()))
                .padding([7, 16])
                .style(style::primary)
                .on_press(Message::ConnectNow(destination.id.clone())),
        );
    }

    let mut col = column![hero].spacing(12);
    if let Some(notice) = &app.notice {
        col = col.push(text(notice.as_str()).size(12).style(style::dim_text));
    }
    match &live {
        DestinationLive::Stopped => {
            let why = if app.client.enabled {
                "The client is not running, so nothing reaches this destination — see \
                 Proxy & forwards."
            } else {
                "The client is disabled, so nothing reaches this destination — enable it \
                 under Proxy & forwards."
            };
            col = col.push(text(why).size(12).style(style::dim_text));
        }
        DestinationLive::Pending => {}
        DestinationLive::Live(status) => {
            if let Some(error) = &status.last_error {
                let color = if status.state == DestinationState::Failed { RED } else { AMBER };
                col = col.push(text(error.as_str()).size(12).color(color));
            }
            let explain = match status.state {
                DestinationState::Idle if status.last_error.is_some() => Some(
                    "Not connected: the last attempt failed. It is tried again when \
                     something next needs it, or with Connect now.",
                ),
                DestinationState::Idle => Some(
                    "Not connected right now — it connects when something is sent to it.",
                ),
                DestinationState::Backoff => {
                    Some("The last attempt failed — retrying while something is waiting for it.")
                }
                DestinationState::Failed => Some(
                    "The server refused this client: it must authorize the auth key's public \
                     half below. It is tried again when something next needs it.",
                ),
                DestinationState::Connecting | DestinationState::Connected => None,
            };
            if let Some(explain) = explain {
                col = col.push(text(explain).size(12).style(style::dim_text));
            }
        }
    }
    if app.client_needs_restart() {
        col = col.push(restart_banner());
    }

    // DESTINATION card
    let node_id = destination.server_node_id.clone();
    let copy_node = (!node_id.is_empty()).then(|| node_id.clone());
    let mut info = column![
        info_row("Host", destination.host.clone(), Some(destination.host.clone())),
        // The full id never fits (and iced has no ellipsis overflow); both
        // ends stay visible for eyeballing, Copy carries the whole thing.
        info_row("Server node id", truncate_middle(&node_id, 22), copy_node),
    ]
    .spacing(8);
    // The key's public half is not a secret — always shown unmasked so it can
    // be copied onto the server's authorized-keys file. (The secret never
    // appears anywhere in the UI.)
    info = info.push(match config::find_key(&app.keys, &destination.auth_key_id) {
        Some(key) => info_row(
            "Auth key",
            format!("{} ({})", key.name, truncate_middle(&key.public_key, 14)),
            Some(key.public_key.clone()),
        ),
        None => info_row("Auth key", "none picked — edit to pick one".into(), None),
    });
    let relays = if destination.relay_urls.is_empty() {
        "default".to_string()
    } else {
        destination.relay_urls.join(", ")
    };
    info = info.push(info_row("Relays", relays, None));
    if let Some(status) = status
        && status.state == DestinationState::Connected
    {
        info = info.push(info_row("Open streams", status.open_streams.to_string(), None));
    }
    let mut header = row![section_label("DESTINATION"), space().width(Fill)].align_y(Center);
    if status.is_some_and(|s| s.state == DestinationState::Connected) {
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
            .on_press(Message::EditDestination(destination.id.clone())),
    );
    col = col.push(header);
    col = col.push(container(info).padding([12, 14]).width(Fill).style(style::card));

    col = col.push(section_label("ROUTING"));
    col = col.push(
        container(routes_section(app, destination))
            .padding([12, 14])
            .width(Fill)
            .style(style::card),
    );
    col = col.push(
        text(
            "The server enforces its own tunnel set, so list a route here only if the \
             server allows it too. Where two destinations overlap, the more specific rule \
             wins.",
        )
        .size(11)
        .style(style::faint_text),
    );

    // Delete, tucked at the very bottom behind a two-click confirm.
    let confirming = app.confirm_delete.as_deref() == Some(destination.id.as_str());
    col = col.push(space().height(8));
    col = col.push(
        row![button(
            text(if confirming {
                "Click again to delete this destination"
            } else {
                "Delete destination…"
            })
            .size(12)
        )
        .padding([4, 12])
        .style(style::ghost_danger)
        .on_press(Message::DeleteDestination(destination.id.clone()))]
        .align_y(Center),
    );

    scrollable(col.padding([0, 4])).height(Fill).spacing(4).into()
}

fn routes_section<'a>(app: &'a App, destination: &'a Destination) -> Element<'a, Message> {
    let mut col = column![].spacing(3);
    // The destination's own name is always the server itself.
    col = col.push(text("This server's own loopback, on any port:").size(12));
    col = col.push(route_row(destination.host.clone(), None));

    col = col.push(space().height(8));
    let (domains, cidrs) = (&destination.routed_domains, &destination.routed_cidrs);
    if is_full_tunnel(domains, cidrs) {
        col = col.push(
            text(
                "Every hostname and address no other destination routes more specifically:",
            )
            .size(12),
        );
    } else if domains.is_empty() && cidrs.is_empty() {
        col = col.push(text("Nothing else is sent through this server.").size(12));
    } else {
        col = col.push(
            text(format!(
                "{} domain(s), {} CIDR(s) also sent through this server:",
                domains.len(),
                cidrs.len()
            ))
            .size(12),
        );
    }
    // Each rule with what its server said of it on the latest connection;
    // nothing is shown for a destination not connected yet.
    let status = match app.destination_live(destination) {
        DestinationLive::Live(status) => Some(status),
        _ => None,
    };
    let rules = domains.iter().map(|r| (r, false)).chain(cidrs.iter().map(|r| (r, true)));
    for (rule, cidr) in rules {
        let badge = config::server_coverage(status, rule, cidr).and_then(|coverage| {
            let color = match coverage {
                Coverage::Full => return None,
                Coverage::Partial => AMBER,
                Coverage::None => RED,
            };
            Some(text(format!("server: {}", coverage.as_str())).size(11).color(color).into())
        });
        col = col.push(route_row(rule.clone(), badge));
    }
    if let Some(error) = status.and_then(|s| s.server_routes_error.as_deref()) {
        col = col.push(
            text(format!("Could not read the server's routes: {error}"))
                .size(11)
                .style(style::faint_text),
        );
    }

    // Where another destination's rules nest with these: the narrower wins.
    let index = app.client.destinations.iter().position(|d| d.id == destination.id);
    if let (Ok(table), Some(index)) = (app.client.route_table(), index) {
        let lines = config::overlap_lines(&table, index);
        if !lines.is_empty() {
            col = col.push(space().height(8));
            col = col.push(text("Overlaps with other destinations:").size(12));
            for line in lines {
                col = col.push(text(line).size(11).style(style::dim_text));
            }
        }
    }

    // The server's own status page — its tunnel set, host aliases and DNS
    // forwards — is fetched through the client's status endpoint, so it
    // needs a proxy to ask through. Opening it connects the destination.
    if app.client.socks_port.is_some() || app.client.http_port.is_some() {
        col = col.push(space().height(8));
        col = col.push(text("The server's status page, through the client's proxy:").size(12));
        col = col.push(route_row(
            format!("http://{}/servers/{}/", reserved::STATUS_HOST, destination.host),
            None,
        ));
    }
    col.into()
}

// ---------------------------------------------------------------------------
// Destination form

fn destination_form_view<'a>(app: &'a App, form: &'a DestinationForm) -> Element<'a, Message> {
    let validated = form.validate(&app.client.destinations, &app.keys);

    let mut card = column![
        // The name this server goes by: `<host>:<port>` reaches the server's
        // own loopback.
        form_row(
            "Host",
            input("a name for this server, e.g. nas.internal", &form.host, Message::DestinationHostChanged),
        ),
        form_row(
            "Server node id",
            input("the server's endpoint id", &form.server_node_id, Message::ServerNodeIdChanged),
        ),
        form_row(
            "Routed domains",
            input(
                "comma-separated, optional — e.g. *.corp.example",
                &form.routed_domains,
                Message::DestinationRoutedDomainsChanged,
            ),
        ),
        form_row(
            "Routed CIDRs",
            input(
                "comma-separated, optional — e.g. 10.0.0.0/8",
                &form.routed_cidrs,
                Message::DestinationRoutedCidrsChanged,
            ),
        ),
        routes_fetch_row(app, form),
    ]
    .spacing(10);
    // Where these routes nest with another destination's — worth seeing
    // before saving, above all after a fill from the server.
    for line in form.overlaps(&app.client.destinations) {
        card = card.push(form_row("", text(line).size(11).style(style::dim_text).width(Fill)));
    }
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
        // Keys are shared across destinations: pick one from the list
        // (managed in the Keys pane), or mint a fresh one right here with
        // "New key…".
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
        form_row(
            "Relay URLs",
            input(
                "comma-separated, optional — at least two",
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
            .on_press_maybe(validated.is_ok().then_some(Message::DestinationFormSave)),
        button(text("Cancel").size(13))
            .padding([6, 16])
            .style(style::outlined)
            .on_press(Message::DestinationFormCancel),
    ]
    .spacing(8)
    .align_y(Center);
    if let Some(notice) = &app.notice {
        buttons = buttons.push(text(notice.as_str()).size(12).style(style::dim_text));
    }
    card = card.push(buttons);

    column![
        section_label(if form.is_edit() {
            "EDIT DESTINATION"
        } else {
            "NEW DESTINATION"
        }),
        container(card).padding([12, 14]).width(Fill).style(style::card),
        text("The host is your name for this server: host:port through the proxy, or as a \
              forward's remote host, reaches that port on the server machine itself. Auth \
              keys are shared — any number of destinations can pick the same one (manage \
              them in the Keys pane). The server must authorize the key's public half: on \
              a flextunnel desktop server under Authorized clients, on a CLI server in its \
              authorized-keys file.")
            .size(11)
            .style(style::faint_text),
    ]
    .spacing(10)
    .into()
}

/// Under the routed fields: the button that fills them with what the server
/// itself routes, and where that fetch stands. The server enforces its own
/// lists, so its answer is what this destination can usefully send it.
fn routes_fetch_row<'a>(app: &'a App, form: &'a DestinationForm) -> Element<'a, Message> {
    // What asking takes: the server's id and a key, with relays that parse.
    let askable = form.routes_query(&app.keys).map(|_| ());
    let fetching = matches!(form.routes_fetch, RoutesFetch::Fetching(_));
    let status = match (&form.routes_fetch, &askable) {
        (RoutesFetch::Fetching(_), _) => text("Asking the server…").style(style::dim_text),
        (RoutesFetch::Filled(filled), _) => text(filled.as_str()).style(style::dim_text),
        (RoutesFetch::Failed(reason), _) => text(reason.as_str()).color(AMBER),
        (RoutesFetch::Idle, Err(missing)) => text(missing.clone()).style(style::faint_text),
        (RoutesFetch::Idle, Ok(())) => {
            text("Fills the two fields above with what the server routes.").style(style::faint_text)
        }
    };
    form_row(
        "",
        row![
            button(text("Fetch from server").size(12))
                .padding([4, 10])
                .style(style::outlined)
                .on_press_maybe(
                    (!fetching && askable.is_ok()).then_some(Message::FetchServerRoutes)
                ),
            status.size(12).width(Fill),
        ]
        .spacing(8)
        .align_y(Center),
    )
}

// ---------------------------------------------------------------------------
// Server

/// No server yet: what one is for and how setup goes, then the way in.
fn server_welcome() -> Element<'static, Message> {
    let step = |n: &'static str, title: &'static str, body: &'static str| {
        row![
            container(text(n).size(12).font(semibold()))
                .width(24)
                .height(24)
                .align_x(Center)
                .align_y(Center)
                .style(style::step),
            column![
                text(title).size(13).font(semibold()),
                text(body).size(12).style(style::dim_text),
            ]
            .spacing(2),
        ]
        .spacing(12)
    };
    let steps = column![
        step(
            "1",
            "An identity",
            "This computer gets a permanent endpoint id — the address clients enter when \
             adding a connection. Its key is sealed in profiles.json under a master \
             key kept in the system keychain.",
        ),
        step(
            "2",
            "Authorized clients",
            "Only the devices you authorize can connect: each has an auth key (in the \
             flextunnel app: Keys), whose public half you add here. The server starts \
             with the first one.",
        ),
        step(
            "3",
            "What clients reach",
            "This computer's localhost always. Optionally more — domains or networks \
             reachable from here (the tunnel set), changeable any time.",
        ),
    ]
    .spacing(14);
    let col = column![
        text("Run a server on this computer").size(20).font(semibold()),
        text(
            "Let your other devices — a laptop, a phone — reach this computer, and the \
             network it is on, from anywhere. Nothing to open on your router: devices \
             connect directly when they can, through a relay when they can't.",
        )
        .size(13),
        space().height(4),
        section_label("HOW IT WORKS"),
        container(steps).padding([14, 16]).width(Fill).style(style::card),
        space().height(4),
        button(text("Set up server").size(13).font(semibold()))
            .padding([7, 20])
            .style(style::primary)
            .on_press(Message::BeginServerSetup),
    ]
    .spacing(10)
    .max_width(560);
    scrollable(container(col).center_x(Fill).padding([8, 4])).height(Fill).spacing(4).into()
}

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
    tunnel = tunnel.push(indented_label("always reachable by clients:"));
    tunnel = tunnel.push(indented_note_item(
        "<the client's name for this server>",
        "this machine's localhost, on any port",
    ));
    tunnel = tunnel.push(indented_note_item(
        "the server status page",
        "through the client's flextunnel.internal",
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
            "The tunnel set is enforced here. Clients route by their own lists, so a \
             client must list a route itself to send it to this server.",
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
             profiles.json under a master key kept in the system keychain, and never \
             shown.",
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
    // A lost key leaves two ways on, side by side: import it (from an export,
    // or the other computer it was moved from) to keep this endpoint id, or
    // start over with a new identity when it is gone for good.
    if server.secret.is_empty() {
        col = col.push(
            container(
                column![
                    text("The identity key is missing from the keychain").size(12).font(semibold()),
                    text(
                        "Import it, if you exported it, to keep this endpoint id. Otherwise \
                         generate a new identity: every client must then switch to the new \
                         endpoint id.",
                    )
                    .size(12),
                    row![
                        button(text("Import key…").size(12).font(semibold()))
                            .padding([4, 12])
                            .style(style::tinted)
                            .on_press(Message::ReplaceIdentity(true)),
                        button(text("Generate new identity…").size(12))
                            .padding([4, 12])
                            .style(style::outlined)
                            .on_press(Message::ReplaceIdentity(false)),
                    ]
                    .spacing(8),
                ]
                .spacing(8),
            )
            .padding([10, 12])
            .width(Fill)
            .style(style::banner(AMBER)),
        );
        return col.into();
    }
    let exporting = app.confirm_export_server_secret;
    col = col.push(
        row![
            button(text("Replace identity…").size(12))
                .padding([4, 12])
                .style(style::outlined)
                .on_press(Message::ReplaceIdentity(false)),
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
            .on_press(Message::ExportServerSecret),
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
/// endpoint id shown, with Regenerate to roll another) or a pasted one.
fn identity_picker<'a>(
    identity: &'a IdentityChoice,
    on_toggle: fn(bool) -> Message,
    on_secret: fn(String) -> Message,
    on_regenerate: Message,
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
            let mut field = row![endpoint_field(&endpoint_id)].spacing(8).align_y(Center);
            if identity.import.is_none() {
                field = field.push(
                    button(text("Regenerate").size(12))
                        .padding([5, 14])
                        .style(style::outlined)
                        .on_press(on_regenerate),
                );
            }
            col = col.push(
                column![text("Endpoint id").size(12).style(style::dim_text), field].spacing(6),
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
        text(match (server.secret.is_empty(), identity.import.is_some()) {
            (true, true) => "Restore the identity key",
            (true, false) => "Start over with a new identity",
            (false, _) => "Replace identity",
        })
            .size(13)
            .font(semibold()),
        identity_picker(
            identity,
            Message::IdentityImportToggled,
            Message::IdentitySecretChanged,
            Message::IdentityRegenerate,
        ),
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
             both lists are optional, since this machine's localhost (under the name \
             a client gives this server) and the server's status page are always \
             reachable. A client must list a route itself to send it here. Clients \
             are authorized on the server pane.",
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
            Message::ServerRegenerateIdentity,
        ),
        text(if identity.import.is_some() {
            "Moving a server here: paste the identity key exported from the other \
             computer (or the secret line of a `flextunnel generate-iroh-key` file), so \
             its clients keep their endpoint id. Then stop the old server."
        } else {
            "A new identity for this computer. Its key is sealed in profiles.json under \
             a master key kept in the system keychain."
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
                text("No auth keys yet. Add one to authenticate with — any number of \
                      destinations can share the same key.")
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
        text("These are this computer's client keys, for its destinations. Secret halves live \
              in the system keychain; names and public keys in a local file. Each server a \
              key connects to must authorize its public half.")
            .size(11)
            .style(style::faint_text),
    );

    scrollable(col.padding([0, 4])).height(Fill).spacing(4).into()
}

fn key_card<'a>(app: &'a App, key: &'a AuthKey) -> Element<'a, Message> {
    let users: Vec<&str> = app
        .client
        .destinations
        .iter()
        .filter(|d| d.auth_key_id == key.id)
        .map(|d| d.host.as_str())
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
            "Not used by any destination.".to_string()
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
    let mut filter_options = vec![LogFilter::All, LogFilter::Client];
    if app.server.is_some() {
        filter_options.push(LogFilter::Server);
    }
    let selected = app.log_filter;

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
/// Counted and cut in characters, so any text is safe — a hand-edited id
/// with something other than ASCII in it included.
fn truncate_middle(s: &str, max: usize) -> String {
    let len = s.chars().count();
    if len <= max {
        return s.into();
    }
    let keep = max.saturating_sub(1) / 2;
    let head: String = s.chars().take(keep).collect();
    let tail: String = s.chars().skip(len - keep).collect();
    format!("{head}…{tail}")
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
    use crate::config::ClientSettings;

    #[test]
    fn middle_truncation() {
        assert_eq!(truncate_middle("short", 22), "short");
        let id = "feedfacefeedfacefeedfacefeedface";
        let shown = truncate_middle(id, 22);
        assert_eq!(shown, "feedfacefe…cefeedface");
        assert!(shown.chars().count() <= 22);
    }

    /// Cuts fall between characters, never inside one: text with multibyte
    /// characters at the cut — either side of it — is shortened, not a panic.
    #[test]
    fn middle_truncation_keeps_characters_whole() {
        // Two bytes each, so a cut at byte 3 would land inside the second.
        let id = "ééééééééé";
        assert_eq!(truncate_middle(id, 7), "ééé…ééé");
        assert_eq!(truncate_middle(id, 9), id, "nine characters fit in nine");
        // The character on each side of the cut is a wide one.
        assert_eq!(truncate_middle("ab日本語cdefg日本h", 7), "ab日…日本h");
        assert_eq!(truncate_middle("日本語", 2), "…");
        assert_eq!(truncate_middle("", 0), "");
    }

    #[test]
    fn full_tunnel_derivation() {
        let strings = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(!is_full_tunnel(&[], &[]), "no routes: only the host is tunneled");
        assert!(!is_full_tunnel(&strings(&["example.com"]), &[]));
        // Each catch-all covers its own kind of target only.
        assert!(!is_full_tunnel(&strings(&["example.com", "*"]), &[]), "hostnames alone");
        assert!(!is_full_tunnel(&strings(&["example.com"]), &strings(&["0.0.0.0/0"])), "IPv4 alone");
        assert!(!is_full_tunnel(&strings(&["*"]), &strings(&["0.0.0.0/0"])), "no IPv6");
        assert!(is_full_tunnel(&strings(&["*"]), &strings(&["10.0.0.0/8", "0.0.0.0/0", "::/0"])));
    }

    /// A forward's row shows the route in use; the saved one is only ever
    /// shown as what a restart will bring, never as the running client's.
    #[test]
    fn a_forward_shows_the_running_route_and_the_pending_one() {
        let (a, b) = (Some(Some("a.internal")), Some(Some("b.internal")));
        // Not running: the saved destinations are what a start will use.
        assert_eq!(forward_route_labels(None, a), (a, None));
        assert_eq!(forward_route_labels(None, Some(None)), (Some(None), None));
        assert_eq!(forward_route_labels(None, None), (None, None), "no valid table: no badge");
        // Running with the saved settings: one route, nothing pending.
        assert_eq!(forward_route_labels(a, a), (a, None));
        // Running on older settings: the running route, and the change to come.
        assert_eq!(
            forward_route_labels(a, b),
            (a, Some("after restart: via b.internal".to_string()))
        );
        assert_eq!(
            forward_route_labels(a, Some(None)),
            (a, Some("after restart: no route".to_string()))
        );
        assert_eq!(
            forward_route_labels(Some(None), b),
            (Some(None), Some("after restart: via b.internal".to_string()))
        );
        // The saved destinations no longer make a table: only what runs.
        assert_eq!(forward_route_labels(a, None), (a, None));
    }

    #[test]
    fn a_forward_names_the_destination_that_carries_it() {
        let spec = |host, domains: &'static [String], cidrs: &'static [String]| {
            flextunnel_core::proxy::RouteSpec {
                host,
                routed_domains: domains,
                routed_cidrs: cidrs,
            }
        };
        let corp: &'static [String] = Box::leak(Box::new(["*.corp.example".to_string()]));
        let ten: &'static [String] = Box::leak(Box::new(["10.0.0.0/8".to_string()]));
        let table = RouteTable::new(&[
            spec("nas.internal", corp, &[]),
            spec("lab.internal", &[], ten),
        ])
        .unwrap();
        let forward = |host: &str| PortForward {
            id: "f".into(),
            label: String::new(),
            local_port: 5432,
            remote_host: host.into(),
            remote_port: 5432,
            enabled: true,
        };
        for (host, via) in [
            ("nas.internal", "nas.internal"),
            ("db.corp.example", "nas.internal"),
            ("lab.internal", "lab.internal"),
            ("10.1.2.3", "lab.internal"),
        ] {
            assert_eq!(forward_route(Some(&table), &forward(host)), Some(Some(via)), "{host}");
        }
        for unrouted in ["example.org", "192.168.1.1", "localhost"] {
            assert_eq!(forward_route(Some(&table), &forward(unrouted)), Some(None), "{unrouted}");
        }
        // Routes that do not validate: no verdict, no badge.
        assert_eq!(forward_route(None, &forward("nas.internal")), None);
    }

    /// A destination that rests after a failed attempt (a refused key, once
    /// its retry delay has passed) is idle to the core, but not healthy.
    #[test]
    fn an_idle_destination_shows_its_failed_attempt() {
        let status = |state, last_error: Option<&str>| flextunnel_core::proxy::DestinationStatus {
            host: "nas.internal".into(),
            server_node_id: String::new(),
            state,
            connected_since: None,
            open_streams: 0,
            waiting: 0,
            client_node_id: None,
            failed_attempts: 0,
            next_attempt_at: None,
            last_error: last_error.map(String::from),
            routed_domains: Vec::new(),
            routed_cidrs: Vec::new(),
            relay_urls: Vec::new(),
            server_routes: None,
            server_routes_error: None,
        };
        let word = |status: &flextunnel_core::proxy::DestinationStatus| {
            destination_state(&DestinationLive::Live(status))
        };
        assert_eq!(word(&status(DestinationState::Idle, None)), ("idle", GRAY));
        assert_eq!(
            word(&status(DestinationState::Idle, Some("Authentication failed"))),
            ("last attempt failed", AMBER)
        );
        assert_eq!(
            word(&status(DestinationState::Failed, Some("Authentication failed"))),
            ("refused", RED)
        );
        // A connection keeps no error; the word is the state's own.
        assert_eq!(word(&status(DestinationState::Connected, None)), ("connected", GREEN));
        assert_eq!(destination_state(&DestinationLive::Stopped), ("client off", GRAY));
        assert_eq!(destination_state(&DestinationLive::Pending), ("restart to apply", AMBER));
    }

    #[test]
    fn the_route_cache_rebuilds_only_on_a_routing_change() {
        let destination = |host: &str, domains: &[&str]| Destination {
            id: host.into(),
            host: host.into(),
            server_node_id: format!("node-{host}"),
            routed_domains: domains.iter().map(|d| d.to_string()).collect(),
            routed_cidrs: Vec::new(),
            auth_key_id: String::new(),
            relay_urls: Vec::new(),
            relay_auth_token: None,
        };
        let mut client = ClientSettings {
            destinations: vec![destination("nas.internal", &["*.corp.example"])],
            ..ClientSettings::default()
        };
        let mut cache = RoutedCache::default();
        refresh_routed_cache(&mut cache, &client.destinations);
        assert_eq!(cache.table.as_ref().unwrap().hosts().count(), 1);

        // Not a routing change: the table is kept as it is.
        client.destinations[0].auth_key_id = "k".into();
        client.socks_port = None;
        let before = cache.built_from.clone();
        refresh_routed_cache(&mut cache, &client.destinations);
        assert_eq!(cache.built_from, before);

        client.destinations.push(destination("lab.internal", &[]));
        refresh_routed_cache(&mut cache, &client.destinations);
        assert_eq!(cache.table.as_ref().unwrap().hosts().count(), 2);

        // Two destinations claiming one rule: no table, so no badges.
        client.destinations[1].routed_domains = vec!["*.corp.example".into()];
        refresh_routed_cache(&mut cache, &client.destinations);
        assert!(cache.table.is_none());
    }
}
