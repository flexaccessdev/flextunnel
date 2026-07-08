//! Widget tree for the single Status / Forwards / Settings / Logs window,
//! rendered from [`App`] state — all pure functions of `&App`, every mutation
//! flows back through a [`Message`]. The look (cards, pills, ghost buttons,
//! segmented tabs) comes from the design system in [`crate::style`].

use crate::app::{format_duration, App, ForwardForm, Message, Tab};
use crate::forward::{ForwardState, ForwardStatus, PortForward};
use crate::style::{self, AMBER, GRAY, GREEN, RED};
use crate::tunnel::{Phase, Snapshot};
use flextunnel_core::proxy::signaling::Target;
use flextunnel_core::proxy::{reserved, AgentConnState, RoutedSet, TunnelRoutes};
use iced::widget::{
    button, checkbox, column, container, row, scrollable, space, text, text_input, toggler,
};
use iced::{Center, Color, Element, Fill, Font};
use std::net::SocketAddr;
use std::time::Instant;

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
            ForwardState::Listening if status.active > 0 => {
                (format!("listening · {}", status.active), GREEN)
            }
            ForwardState::Listening => ("listening".into(), GREEN),
            ForwardState::Failed(_) => ("failed".into(), RED),
        },
        // No status = no running session for this forward. The Forwards tab's
        // connection banner explains the disconnected case in one place.
        None => match phase {
            Phase::Idle | Phase::Failed => ("stopped".into(), GRAY),
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
    .spacing(4);

    let content = match app.tab {
        Tab::Status => status_tab(app),
        Tab::Forwards => forwards_tab(app),
        Tab::Settings => settings_tab(app),
        Tab::Logs => logs_tab(app),
    };

    container(column![tabs, content].spacing(14))
        .padding(16)
        .width(Fill)
        .height(Fill)
        .into()
}

fn tab_button(label: &'static str, tab: Tab, current: Tab) -> Element<'static, Message> {
    button(text(label).size(13).font(semibold()))
        .padding([5, 12])
        .style(if tab == current {
            style::tinted
        } else {
            style::ghost
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

    let mut hero = row![dot(color, 12.0), text(heading).size(20).font(semibold())]
        .spacing(10)
        .align_y(Center);
    if let Some(since) = snapshot.connected_since {
        hero = hero.push(
            text(format!("for {}", format_duration(since.elapsed())))
                .size(13)
                .style(style::dim_text),
        );
    }

    let mut col = column![hero].spacing(12);

    if let Some(error) = &snapshot.last_error {
        col = col.push(text(error.as_str()).size(12).color(RED));
    }

    col = match snapshot.phase {
        Phase::Idle | Phase::Failed => {
            let mut col = col.push(
                row![button(text("Connect").size(13).font(semibold()))
                    .padding([7, 16])
                    .style(style::primary)
                    .on_press_maybe(app.saved.is_some().then_some(Message::Connect))],
            );
            if app.saved.is_none() {
                col = col.push(
                    text("Save the connection settings first.")
                        .size(12)
                        .style(style::faint_text),
                );
            }
            col
        }
        _ => col.push(
            row![button(text("Disconnect").size(13))
                .padding([7, 16])
                .style(style::outlined)
                .on_press(Message::Disconnect)],
        ),
    };

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
    let copy_socks = (!socks.is_empty()).then(|| format!("socks5://{socks}"));
    let mut info = column![
        info_row("Server node id", node_id, copy_node),
        info_row("SOCKS5 proxy", socks, copy_socks),
    ]
    .spacing(8);
    if let Some(http) = http {
        let copy = Some(format!("http://{http}"));
        info = info.push(info_row("HTTP proxy", http, copy));
    }

    col = col.push(section_label("CONNECTION"));
    col = col.push(container(info).padding([12, 14]).width(Fill).style(style::card));

    if snapshot.phase == Phase::Connected {
        col = col.push(section_label("ROUTING"));
        col = col.push(
            container(scrollable(routes_section(snapshot)).width(Fill).height(Fill))
                .padding([12, 14])
                .width(Fill)
                .height(Fill)
                .style(style::card),
        );
    }

    col.into()
}

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
        r = r.push(
            button(text("Copy").size(11))
                .padding([2, 8])
                .style(style::ghost)
                .on_press(Message::CopyText(copy)),
        );
    }
    r.into()
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
            .size(12),
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
            .size(12),
        );
        for (alias, state) in routes.agent_states(Instant::now()) {
            let (label, color) = match state {
                AgentConnState::Connected => ("connected", GREEN),
                AgentConnState::Disconnected => ("disconnected", RED),
                AgentConnState::Unknown => ("unknown", GRAY),
            };
            col = col.push(
                row![mono(alias), pill(label.to_string(), color)]
                    .spacing(8)
                    .align_y(Center),
            );
        }
    }
    col.into()
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
    let mut r = row![dot(color, 8.0), text(message).size(12)]
        .spacing(8)
        .align_y(Center);
    if show_connect {
        r = r.push(space().width(Fill));
        r = r.push(
            button(text("Connect").size(11).font(semibold()))
                .padding([3, 10])
                .style(style::tinted)
                .on_press_maybe(app.saved.is_some().then_some(Message::Connect)),
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

fn forwards_tab(app: &App) -> Element<'_, Message> {
    let mut col = column![].spacing(10);
    if let Some(banner) = connection_banner(app) {
        col = col.push(banner);
    }

    let header = row![
        section_label(if app.forwards.is_empty() {
            "PORT FORWARDS".to_string()
        } else {
            format!("PORT FORWARDS · {}", app.forwards.len())
        }),
        space().width(Fill),
        button(text("+ Add").size(12).font(semibold()))
            .padding([4, 12])
            .style(style::tinted)
            .on_press(Message::AddForward),
    ]
    .align_y(Center);
    col = col.push(header);

    if let Some(notice) = &app.forwards_notice {
        col = col.push(text(notice.as_str()).size(12).color(AMBER));
    }

    // Inline add/edit form — one at a time; an inline card fits the small
    // window better than a separate window.
    if let Some(form) = &app.forward_form {
        col = col.push(forward_form_view(app, form));
    }

    if app.forwards.is_empty() {
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
        return col.into();
    }

    let routed_set = app.routed_cache.as_ref().and_then(|(_, _, set)| set.as_ref());
    let mut list = column![].spacing(8);
    for (i, forward) in app.forwards.iter().enumerate() {
        list = list.push(forward_card(app, i, forward, routed_set));
    }
    col = col.push(scrollable(list).height(Fill).spacing(4));

    col = col.push(
        text(
            "Forwards listen on localhost only (127.0.0.1 and ::1) and relay through \
             this app's SOCKS5 proxy while connected.",
        )
        .size(11)
        .style(style::faint_text),
    );
    col.into()
}

fn forward_form_view<'a>(app: &'a App, form: &'a ForwardForm) -> Element<'a, Message> {
    let (socks_port, http_port) = app.proxy_ports();
    let validated = form.validate(&app.forwards, socks_port, http_port);

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
    i: usize,
    forward: &'a PortForward,
    routed_set: Option<&RoutedSet>,
) -> Element<'a, Message> {
    let snapshot = &app.snapshot;
    let status = snapshot.forwards.iter().find(|s| s.id == forward.id);
    let (pill_text, pill_color) = forward_pill(forward, status, snapshot.phase);

    let mut name = text(forward.display_name()).size(14).font(semibold());
    if !forward.enabled {
        name = name.style(style::dim_text);
    }

    let mut title = row![name, pill(pill_text, pill_color)]
        .spacing(8)
        .align_y(Center);
    if let Some(tunneled) = forward_badge(snapshot.phase, &snapshot.routes, routed_set, forward) {
        let (badge, color) = if tunneled {
            ("tunneled", GREEN)
        } else {
            ("direct", AMBER)
        };
        title = title.push(pill(badge.to_string(), color));
    }

    let route = text(forward.route_description())
        .size(12)
        .font(Font::MONOSPACE)
        .style(style::dim_text);

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

    let controls = row![
        button(text("Edit").size(12))
            .padding([4, 10])
            .style(style::ghost)
            .on_press(Message::EditForward(i)),
        button(text("Delete").size(12))
            .padding([4, 10])
            .style(style::ghost_danger)
            .on_press(Message::DeleteForward(i)),
        // Desired state, but not a plain checkbox: enabling attempts the
        // setup now, and a setup failure snaps the switch back off (see
        // disable_failed_forwards).
        toggler(forward.enabled)
            .on_toggle(move |enabled| Message::ToggleForward(i, enabled))
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

fn settings_tab(app: &App) -> Element<'_, Message> {
    let form = &app.form;

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

    let validated = form.validate();
    let dirty = match (&validated, &app.saved) {
        (Ok(candidate), Some(saved)) => candidate != saved,
        (Ok(_), None) => true,
        (Err(_), _) => false,
    };

    let mut card = column![
        form_row(
            "Server node id",
            input("", &form.server_node_id, Message::ServerNodeIdChanged),
        ),
        form_row(
            "Auth token",
            input("", &form.auth_token, Message::AuthTokenChanged)
                .secure(true)
                .width(240),
        ),
        form_row(
            "SOCKS5 port",
            input("", &form.socks_port, Message::SocksPortChanged).width(90),
        ),
        form_row("HTTP proxy", http),
        form_row(
            "Relay URLs",
            input(
                "comma-separated, optional",
                &form.relay_urls,
                Message::RelayUrlsChanged,
            ),
        ),
    ]
    .spacing(10);

    if let Err(message) = &validated {
        card = card.push(text(message.clone()).size(12).color(AMBER));
    }
    let mut save_row = row![button(text("Save").size(13).font(semibold()))
        .padding([6, 16])
        .style(style::primary)
        .on_press_maybe((validated.is_ok() && dirty).then_some(Message::SaveSettings))]
    .spacing(10)
    .align_y(Center);
    if let Some(notice) = &app.settings_notice {
        save_row = save_row.push(text(notice.as_str()).size(12).style(style::dim_text));
    }
    card = card.push(save_row);

    column![
        section_label("CONNECTION SETTINGS"),
        container(card).padding([12, 14]).width(Fill).style(style::card),
        text("Stored as a single item in the system keychain.")
            .size(11)
            .style(style::faint_text),
    ]
    .spacing(10)
    .into()
}

fn logs_tab(app: &App) -> Element<'_, Message> {
    let header = row![
        section_label("LOGS".to_string()),
        space().width(Fill),
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

    let log = scrollable(text(app.log_text.as_str()).size(11).font(Font::MONOSPACE))
        .direction(scrollable::Direction::Both {
            vertical: scrollable::Scrollbar::new(),
            horizontal: scrollable::Scrollbar::new(),
        })
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

fn section_label(label: impl Into<String>) -> Element<'static, Message> {
    text(label.into())
        .size(11)
        .font(semibold())
        .style(style::faint_text)
        .into()
}

fn mono<'a>(fragment: impl text::IntoFragment<'a>) -> Element<'a, Message> {
    text(fragment).size(12).font(Font::MONOSPACE).into()
}

/// Small tinted pill badge (forward state, "tunneled"/"direct", agent states).
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
