//! Widget tree for the single Status / Forwards / Settings / Logs window,
//! rendered from [`App`] state — all pure functions of `&App`, every mutation
//! flows back through a [`Message`].

use crate::app::{format_duration, App, ForwardForm, Message, Tab};
use crate::forward::{ForwardState, ForwardStatus, PortForward};
use crate::tunnel::{Phase, Snapshot};
use flextunnel_core::proxy::signaling::Target;
use flextunnel_core::proxy::{reserved, AgentConnState, RoutedSet, TunnelRoutes};
use iced::widget::{
    button, checkbox, column, container, row, rule, scrollable, space, text, text_input, toggler,
};
use iced::{border, Border, Center, Color, Element, Fill, Font, Theme};
use std::net::SocketAddr;
use std::time::Instant;

pub const GREEN: Color = Color::from_rgb(60.0 / 255.0, 180.0 / 255.0, 90.0 / 255.0);
pub const AMBER: Color = Color::from_rgb(230.0 / 255.0, 160.0 / 255.0, 30.0 / 255.0);
pub const RED: Color = Color::from_rgb(220.0 / 255.0, 70.0 / 255.0, 70.0 / 255.0);
pub const GRAY: Color = Color::from_rgb(160.0 / 255.0, 160.0 / 255.0, 160.0 / 255.0);

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

/// One-line live status for a forward row (text, color) — the color also
/// drives the row's status dot: gray "disabled"/"starts when connected",
/// amber "starting…", green "listening (· N active)", red failure.
fn forward_status_line(
    forward: &PortForward,
    status: Option<&ForwardStatus>,
    phase: Phase,
) -> (String, Color) {
    if !forward.enabled {
        return ("disabled".into(), GRAY);
    }
    match status {
        Some(status) => match &status.state {
            ForwardState::Listening if status.active > 0 => {
                (format!("listening · {} active", status.active), GREEN)
            }
            ForwardState::Listening => ("listening".into(), GREEN),
            ForwardState::Failed(reason) => (reason.clone(), RED),
        },
        // No status = no running session for this forward. The Forwards tab's
        // connection banner explains the disconnected case in one place.
        None => match phase {
            Phase::Idle | Phase::Failed => ("starts when connected".into(), GRAY),
            _ => ("starting…".into(), AMBER),
        },
    }
}

pub fn root(app: &App) -> Element<'_, Message> {
    let tabs = row![
        tab_button("Status", Tab::Status, app.tab),
        tab_button("Forwards", Tab::Forwards, app.tab),
        tab_button("Settings", Tab::Settings, app.tab),
        tab_button("Logs", Tab::Logs, app.tab),
    ]
    .spacing(6);

    let content = match app.tab {
        Tab::Status => status_tab(app),
        Tab::Forwards => forwards_tab(app),
        Tab::Settings => settings_tab(app),
        Tab::Logs => logs_tab(app),
    };

    column![
        container(tabs).padding([8, 12]),
        container(content).padding([4, 12]).width(Fill).height(Fill),
    ]
    .into()
}

fn tab_button(label: &'static str, tab: Tab, current: Tab) -> Element<'static, Message> {
    button(text(label).size(13))
        .padding([4, 10])
        .style(if tab == current {
            button::primary
        } else {
            button::text
        })
        .on_press(Message::TabSelected(tab))
        .into()
}

fn status_tab(app: &App) -> Element<'_, Message> {
    let snapshot = &app.snapshot;
    let (color, heading) = match snapshot.phase {
        Phase::Idle => (GRAY, "Disconnected"),
        Phase::Connecting => (AMBER, "Connecting…"),
        Phase::Connected => (GREEN, "Connected"),
        Phase::Reconnecting => (AMBER, "Reconnecting…"),
        Phase::Failed => (RED, "Connection failed"),
    };

    let mut col = column![
        row![dot(color, 12.0), text(heading).size(22)]
            .spacing(8)
            .align_y(Center),
    ]
    .spacing(6);

    if let Some(since) = snapshot.connected_since {
        col = col.push(text(format!("for {}", format_duration(since.elapsed()))).size(13));
    }
    if let Some(error) = &snapshot.last_error {
        col = col.push(text(error.as_str()).size(13).color(RED));
    }

    col = match snapshot.phase {
        Phase::Idle | Phase::Failed => {
            let mut col = col.push(
                button(text("Connect").size(14))
                    .on_press_maybe(app.saved.is_some().then_some(Message::Connect)),
            );
            if app.saved.is_none() {
                col = col.push(text("Save the connection settings first.").size(13));
            }
            col
        }
        _ => col.push(button(text("Disconnect").size(14)).on_press(Message::Disconnect)),
    };

    col = col.push(rule::horizontal(1));

    let node_id = app
        .saved
        .as_ref()
        .map(|c| c.server_node_id.clone())
        .unwrap_or_default();
    let socks = snapshot
        .socks_addr
        .or_else(|| {
            app.saved
                .as_ref()
                .map(|c| SocketAddr::from(([127, 0, 0, 1], c.socks_port)))
        })
        .map(|a| a.to_string())
        .unwrap_or_default();
    let http = snapshot
        .http_addr
        .or_else(|| {
            app.saved
                .as_ref()
                .and_then(|c| c.http_port.map(|p| SocketAddr::from(([127, 0, 0, 1], p))))
        })
        .map(|a| a.to_string());

    let copy_node = (!node_id.is_empty()).then(|| node_id.clone());
    col = col.push(info_row("Server node id", node_id, copy_node));
    let copy_socks = (!socks.is_empty()).then(|| format!("socks5://{socks}"));
    col = col.push(info_row("SOCKS5 proxy", socks, copy_socks));
    if let Some(http) = http {
        let copy = Some(format!("http://{http}"));
        col = col.push(info_row("HTTP proxy", http, copy));
    }

    if snapshot.phase == Phase::Connected {
        col = col.push(rule::horizontal(1));
        col = col.push(routes_section(snapshot));
    }

    col.into()
}

fn info_row(label: &'static str, value: String, copy: Option<String>) -> Element<'static, Message> {
    let display = if value.is_empty() { "—".into() } else { value };
    let mut r = row![
        text(label).size(13).width(110),
        text(display).size(13).font(Font::MONOSPACE),
    ]
    .spacing(12)
    .align_y(Center);
    if let Some(copy) = copy {
        r = r.push(small_button("copy", Message::CopyText(copy)));
    }
    r.into()
}

fn routes_section(snapshot: &Snapshot) -> Element<'_, Message> {
    let routes = &snapshot.routes;
    let mut col = column![].spacing(2);
    if is_full_tunnel(routes) {
        col = col.push(text("Routing: everything through the tunnel").size(13));
    } else {
        col = col.push(
            text(format!(
                "Split tunnel — {} domain(s), {} CIDR(s) routed through the server:",
                routes.domains.len(),
                routes.cidrs.len()
            ))
            .size(13),
        );
        for domain in &routes.domains {
            col = col.push(mono(domain.as_str()));
        }
        for cidr in &routes.cidrs {
            col = col.push(mono(cidr.as_str()));
        }
    }
    if !routes.host_aliases.is_empty() {
        col = col.push(space().height(8));
        col = col.push(
            text(format!(
                "Host aliases — {} resolved server-side:",
                routes.host_aliases.len()
            ))
            .size(13),
        );
        for (alias, target) in &routes.host_aliases {
            col = col.push(mono(format!("{alias} → {target}")));
        }
    }
    if !routes.agent_aliases.is_empty() {
        col = col.push(space().height(8));
        col = col.push(
            text(format!(
                "Agent routes — {} via agents:",
                routes.agent_aliases.len()
            ))
            .size(13),
        );
        for (alias, state) in routes.agent_states(Instant::now()) {
            let (label, color) = match state {
                AgentConnState::Connected => ("connected", GREEN),
                AgentConnState::Disconnected => ("disconnected", RED),
                AgentConnState::Unknown => ("unknown", GRAY),
            };
            col = col.push(row![mono(alias), pill(label, color)].spacing(8).align_y(Center));
        }
    }
    scrollable(col).height(Fill).into()
}

/// One tinted banner explaining why forwards aren't live, with an inline
/// Connect button where that's the fix — instead of every row repeating it.
fn connection_banner(app: &App) -> Option<Element<'_, Message>> {
    let (color, message, show_connect) = match app.snapshot.phase {
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
    let mut r = row![dot(color, 10.0), text(message).size(12)]
        .spacing(8)
        .align_y(Center);
    if show_connect {
        r = r.push(space().width(Fill));
        r = r.push(
            button(text("Connect").size(11))
                .padding([2, 8])
                .on_press_maybe(app.saved.is_some().then_some(Message::Connect)),
        );
    }
    Some(
        container(r)
            .padding([8, 10])
            .width(Fill)
            .style(move |_theme: &Theme| container::Style {
                background: Some(color.scale_alpha(0.12).into()),
                border: Border {
                    color: color.scale_alpha(0.5),
                    width: 1.0,
                    radius: 8.0.into(),
                },
                ..container::Style::default()
            })
            .into(),
    )
}

fn forwards_tab(app: &App) -> Element<'_, Message> {
    let mut col = column![].spacing(8);
    if let Some(banner) = connection_banner(app) {
        col = col.push(banner);
    }

    let mut header = row![button(text("Add forward").size(13)).on_press(Message::AddForward)]
        .spacing(8)
        .align_y(Center);
    if let Some(notice) = &app.forwards_notice {
        header = header.push(text(notice.as_str()).size(12).color(AMBER));
    }
    col = col.push(header);

    // Inline add/edit form — one at a time; an inline group fits the small
    // window better than a separate window.
    if let Some(form) = &app.forward_form {
        col = col.push(forward_form_view(app, form));
    }

    col = col.push(rule::horizontal(1));

    if app.forwards.is_empty() {
        col = col.push(
            text("No port forwards. Add one to expose a remote service on localhost.")
                .size(13)
                .color(GRAY),
        );
        return col.into();
    }

    let routed_set = app.routed_cache.as_ref().and_then(|(_, _, set)| set.as_ref());
    let mut list = column![].spacing(6);
    for (i, forward) in app.forwards.iter().enumerate() {
        list = list.push(forward_card(app, i, forward, routed_set));
    }
    col = col.push(scrollable(list).height(Fill));

    col = col.push(
        text(
            "Forwards listen on localhost only (127.0.0.1 and ::1) and relay through \
             this app's SOCKS5 proxy while connected.",
        )
        .size(11)
        .color(GRAY),
    );
    col.into()
}

fn forward_form_view<'a>(app: &'a App, form: &'a ForwardForm) -> Element<'a, Message> {
    let (socks_port, http_port) = app.proxy_ports();
    let validated = form.validate(&app.forwards, socks_port, http_port);

    let mut col = column![
        form_row(
            "Label",
            text_input("optional", &form.label)
                .on_input(Message::FormLabelChanged)
                .size(13),
        ),
        form_row(
            "Local port",
            text_input("", &form.local_port)
                .on_input(Message::FormLocalPortChanged)
                .size(13)
                .width(90),
        ),
        form_row(
            "Remote host",
            text_input("host or IP — resolved server-side", &form.remote_host)
                .on_input(Message::FormRemoteHostChanged)
                .size(13),
        ),
        form_row(
            "Remote port",
            text_input("", &form.remote_port)
                .on_input(Message::FormRemotePortChanged)
                .size(13)
                .width(90),
        ),
        form_row(
            "Enabled",
            checkbox(form.enabled).on_toggle(Message::FormEnabledToggled),
        ),
    ]
    .spacing(8);

    if let Err(message) = &validated {
        col = col.push(text(message.clone()).size(12).color(AMBER));
    }
    col = col.push(
        row![
            button(text("Save").size(13))
                .on_press_maybe(validated.is_ok().then_some(Message::FormSave)),
            button(text("Cancel").size(13))
                .style(button::secondary)
                .on_press(Message::FormCancel),
        ]
        .spacing(8),
    );

    container(col)
        .padding(10)
        .width(Fill)
        .style(group_style)
        .into()
}

fn forward_card<'a>(
    app: &'a App,
    i: usize,
    forward: &'a PortForward,
    routed_set: Option<&RoutedSet>,
) -> Element<'a, Message> {
    let snapshot = &app.snapshot;
    let status = snapshot.forwards.iter().find(|s| s.id == forward.id);
    let (status_text, status_color) = forward_status_line(forward, status, snapshot.phase);

    let mut name = text(forward.display_name()).size(14).font(bold());
    if !forward.enabled {
        name = name.color(GRAY);
    }

    let mut header = row![dot(status_color, 10.0), name].spacing(8).align_y(Center);
    if let Some(tunneled) = forward_badge(snapshot.phase, &snapshot.routes, routed_set, forward) {
        let (badge, color) = if tunneled {
            ("tunneled", GREEN)
        } else {
            ("direct", AMBER)
        };
        header = header.push(pill(badge, color));
    }
    header = header.push(space().width(Fill));
    // Desired state, but not a plain checkbox: enabling attempts the setup
    // now, and a setup failure snaps the switch back off (see
    // disable_failed_forwards).
    header = header.push(
        toggler(forward.enabled)
            .on_toggle(move |enabled| Message::ToggleForward(i, enabled))
            .size(18)
            .style(green_toggler),
    );

    let mut route = text(forward.route_description())
        .size(12)
        .font(Font::MONOSPACE);
    if !forward.enabled {
        route = route.color(GRAY);
    }

    let footer = row![
        text(status_text).size(11).color(status_color),
        space().width(Fill),
        small_button("Edit", Message::EditForward(i)),
        small_button("Delete", Message::DeleteForward(i)),
    ]
    .spacing(6)
    .align_y(Center);

    let mut card = column![header, route, footer].spacing(4);
    // The setup failure that auto-disabled this forward, kept visible until
    // it is enabled again or removed.
    if let Some(reason) = app.forward_errors.get(&forward.id) {
        card = card.push(text(reason.as_str()).size(11).color(RED));
    }
    if forward.enabled
        && let Some(error) = status.and_then(|s| s.last_conn_error.as_deref())
    {
        card = card.push(text(error).size(11).color(AMBER));
    }

    container(card)
        .padding([8, 10])
        .width(Fill)
        .style(card_style)
        .into()
}

fn settings_tab(app: &App) -> Element<'_, Message> {
    let form = &app.form;

    let mut http = row![
        checkbox(form.http_enabled)
            .label("enable")
            .on_toggle(Message::HttpEnabledToggled)
    ]
        .spacing(8)
        .align_y(Center);
    if form.http_enabled {
        http = http.push(text("port").size(13));
        http = http.push(
            text_input("", &form.http_port)
                .on_input(Message::HttpPortChanged)
                .size(13)
                .width(90),
        );
    }

    let validated = form.validate();
    let dirty = match (&validated, &app.saved) {
        (Ok(candidate), Some(saved)) => candidate != saved,
        (Ok(_), None) => true,
        (Err(_), _) => false,
    };

    let mut col = column![
        form_row(
            "Server node id",
            text_input("", &form.server_node_id)
                .on_input(Message::ServerNodeIdChanged)
                .size(13),
        ),
        form_row(
            "Auth token",
            text_input("", &form.auth_token)
                .secure(true)
                .on_input(Message::AuthTokenChanged)
                .size(13)
                .width(240),
        ),
        form_row(
            "SOCKS5 port",
            text_input("", &form.socks_port)
                .on_input(Message::SocksPortChanged)
                .size(13)
                .width(90),
        ),
        form_row("HTTP proxy", http),
        form_row(
            "Relay URLs",
            text_input("comma-separated, optional", &form.relay_urls)
                .on_input(Message::RelayUrlsChanged)
                .size(13),
        ),
    ]
    .spacing(8);

    if let Err(message) = &validated {
        col = col.push(text(message.clone()).size(12).color(AMBER));
    }
    let mut save_row = row![
        button(text("Save").size(13))
            .on_press_maybe((validated.is_ok() && dirty).then_some(Message::SaveSettings)),
    ]
    .spacing(8)
    .align_y(Center);
    if let Some(notice) = &app.settings_notice {
        save_row = save_row.push(text(notice.as_str()).size(12));
    }
    col = col.push(save_row);
    col = col.push(
        text("Stored as a single item in the system keychain.")
            .size(11)
            .color(GRAY),
    );
    col.into()
}

fn logs_tab(app: &App) -> Element<'_, Message> {
    column![
        row![
            button(text("Open log folder").size(13)).on_press(Message::OpenLogFolder),
            button(text("Copy all").size(13)).on_press(Message::CopyLogs),
        ]
        .spacing(8),
        rule::horizontal(1),
        scrollable(text(app.log_text.as_str()).size(11).font(Font::MONOSPACE))
            .direction(scrollable::Direction::Both {
                vertical: scrollable::Scrollbar::new(),
                horizontal: scrollable::Scrollbar::new(),
            })
            .anchor_bottom()
            .width(Fill)
            .height(Fill),
    ]
    .spacing(8)
    .into()
}

fn form_row<'a>(
    label: &'static str,
    input: impl Into<Element<'a, Message>>,
) -> Element<'a, Message> {
    row![text(label).size(13).width(110), input.into()]
        .spacing(12)
        .align_y(Center)
        .into()
}

fn small_button(label: &'static str, message: Message) -> Element<'static, Message> {
    button(text(label).size(11))
        .padding([2, 8])
        .style(button::secondary)
        .on_press(message)
        .into()
}

fn mono<'a>(fragment: impl text::IntoFragment<'a>) -> Element<'a, Message> {
    text(fragment).size(12).font(Font::MONOSPACE).into()
}

/// Small tinted pill badge ("tunneled", "direct", agent states).
fn pill(label: &'static str, color: Color) -> Element<'static, Message> {
    container(text(label).size(11).color(color))
        .padding([1, 6])
        .style(move |_theme: &Theme| container::Style {
            background: Some(color.scale_alpha(0.16).into()),
            border: border::rounded(8),
            ..container::Style::default()
        })
        .into()
}

/// Small filled status dot, vertically centered against the row text.
fn dot(color: Color, size: f32) -> Element<'static, Message> {
    container(space())
        .width(size)
        .height(size)
        .style(move |_theme: &Theme| container::Style {
            background: Some(color.into()),
            border: border::rounded(size / 2.0),
            ..container::Style::default()
        })
        .into()
}

fn bold() -> Font {
    Font {
        weight: iced::font::Weight::Bold,
        ..Font::DEFAULT
    }
}

/// The forward cards' faint background.
fn card_style(theme: &Theme) -> container::Style {
    container::Style {
        background: Some(theme.extended_palette().background.weak.color.into()),
        border: border::rounded(8),
        ..container::Style::default()
    }
}

/// Bordered group for the inline add/edit form.
fn group_style(theme: &Theme) -> container::Style {
    container::Style {
        border: Border {
            color: theme.extended_palette().background.strong.color,
            width: 1.0,
            radius: 8.0.into(),
        },
        ..container::Style::default()
    }
}

/// The per-forward switch, green when on (the app's "running" color) instead
/// of the theme accent.
fn green_toggler(theme: &Theme, status: toggler::Status) -> toggler::Style {
    let mut style = toggler::default(theme, status);
    if matches!(
        status,
        toggler::Status::Active { is_toggled: true } | toggler::Status::Hovered { is_toggled: true }
    ) {
        style.background = GREEN.into();
    }
    style
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_tunnel_derivation() {
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
}
