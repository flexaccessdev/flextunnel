//! Rendering for the control panel: the client header, the destinations with
//! their live state, the highlighted destination's details, and the
//! config-declared port forwards with their live state.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use crate::ipc::{
    DestState, DestinationRow, ForwardRow, ForwardRowState, StatusSnapshot, WireConnSnapshot,
};

use super::{App, Mode};

const DIM: Style = Style::new().fg(Color::DarkGray);

/// Most destination rows shown at once; a longer list scrolls with the
/// highlight.
const MAX_DESTINATION_ROWS: usize = 8;

pub fn draw(frame: &mut Frame, app: &App) {
    let s = &app.snapshot;

    let header_lines = header_lines(s);
    let destination_rows = s.destinations.len().clamp(1, MAX_DESTINATION_ROWS);
    let forwards_height = (s.forwards.len().max(1) + 2).min(8) as u16;
    let [header_area, destinations_area, details_area, forwards_area, footer_area] =
        Layout::vertical([
            Constraint::Length(header_lines.len() as u16 + 2),
            Constraint::Length(destination_rows as u16 + 2),
            Constraint::Min(3),
            Constraint::Length(forwards_height),
            Constraint::Length(1),
        ])
        .areas(frame.area());

    frame.render_widget(
        Paragraph::new(header_lines).block(titled_block("Client")),
        header_area,
    );

    // Keep the highlighted row in view: scroll just far enough to show it.
    let selected = app.selected.min(s.destinations.len().saturating_sub(1));
    let visible = destinations_area.height.saturating_sub(2) as usize;
    let first = (selected + 1).saturating_sub(visible.max(1));
    frame.render_widget(
        Paragraph::new(destination_lines(&s.destinations, selected))
            .scroll((first as u16, 0))
            .block(titled_block(&format!(
                "Destinations · {}  (↑/↓ to select)",
                s.destinations.len()
            ))),
        destinations_area,
    );

    let (details_title, details) = match app.selected_destination() {
        Some(d) => (
            format!("{}  ([/] to scroll)", d.host),
            details_lines(d, &s.status_page_host),
        ),
        None => ("Destination".to_string(), Vec::new()),
    };
    let max_scroll = (details.len() as u16).saturating_sub(details_area.height.saturating_sub(2));
    frame.render_widget(
        Paragraph::new(details)
            .scroll((app.details_scroll.min(max_scroll), 0))
            .block(titled_block(&details_title)),
        details_area,
    );

    let max_forwards_scroll =
        (s.forwards.len() as u16).saturating_sub(forwards_area.height.saturating_sub(2));
    frame.render_widget(
        Paragraph::new(forward_lines(&s.forwards))
            .scroll((app.forwards_scroll.min(max_forwards_scroll), 0))
            .block(titled_block(&format!(
                "Port forwards · {}  (PgUp/PgDn to scroll)",
                s.forwards.len()
            ))),
        forwards_area,
    );

    frame.render_widget(Paragraph::new(footer_line(app)), footer_area);

    match &app.mode {
        Mode::Normal => {}
        Mode::ConnPath { host, snapshot } => draw_conn_path(frame, host, snapshot),
    }
}

fn titled_block(title: &str) -> Block<'_> {
    Block::new()
        .borders(Borders::ALL)
        .border_style(DIM)
        .title(Span::styled(
            format!(" {title} "),
            Style::new().add_modifier(Modifier::BOLD),
        ))
}

fn state_style(state: DestState) -> Style {
    match state {
        DestState::Connected => Style::new().fg(Color::Green),
        DestState::Connecting | DestState::Backoff => Style::new().fg(Color::Yellow),
        DestState::Failed => Style::new().fg(Color::Red),
        // Idle is the resting state, not a problem.
        DestState::Idle => DIM,
    }
}

fn format_uptime(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}h {m:02}m {s:02}s")
    } else if m > 0 {
        format!("{m}m {s:02}s")
    } else {
        format!("{s}s")
    }
}

fn header_lines(s: &StatusSnapshot) -> Vec<Line<'static>> {
    let proxy = |name: &str, addr: Option<std::net::SocketAddr>| match addr {
        Some(addr) => Span::raw(format!("{name} {addr}")),
        None => Span::styled(format!("{name} off"), DIM),
    };
    let idle = match s.idle_timeout_secs {
        Some(secs) => format!("idle connections close after {}", format_uptime(secs)),
        None => "idle connections are kept".to_string(),
    };
    vec![
        Line::from(vec![
            Span::styled(s.name.clone(), Style::new().add_modifier(Modifier::BOLD)),
            Span::raw("   "),
            proxy("socks5", s.socks_addr),
            Span::raw("   "),
            proxy("http", s.http_addr),
        ]),
        Line::from(vec![
            Span::styled(format!("status page http://{}/", s.status_page_host), DIM),
            Span::styled(format!("   {idle}"), DIM),
        ]),
    ]
}

/// What goes next to a destination's state: its uptime, or how far the
/// retries have got — so a backoff step reads as waiting, not stuck.
fn state_detail(d: &DestinationRow) -> String {
    if let Some(secs) = d.connected_secs {
        return format!("for {}", format_uptime(secs));
    }
    if d.failed_attempts == 0 {
        return match d.state {
            DestState::Idle => "connects on first use".to_string(),
            _ => String::new(),
        };
    }
    let n = d.failed_attempts;
    let attempts = format!("{n} failed attempt{}", if n == 1 { "" } else { "s" });
    match (d.state, d.next_attempt_secs) {
        (DestState::Connecting, _) => format!("{attempts}, trying now"),
        // Idle after a failure: nothing retries until something asks.
        (DestState::Idle, _) => format!("{attempts}, retries on next use"),
        (_, Some(secs)) if secs > 0 => format!("{attempts}, next in {}", format_uptime(secs)),
        _ => attempts,
    }
}

/// One row per destination: host, state, detail, and the streams in flight.
fn destination_lines(destinations: &[DestinationRow], selected: usize) -> Vec<Line<'static>> {
    if destinations.is_empty() {
        return vec![Line::from(Span::styled("no destinations", DIM))];
    }
    let width = destinations.iter().map(|d| d.host.len()).max().unwrap_or(0);
    destinations
        .iter()
        .enumerate()
        .map(|(i, d)| {
            let marker = if i == selected { "▸ " } else { "  " };
            let mut spans = vec![
                Span::raw(marker),
                Span::styled(
                    format!("{:<width$}", d.host),
                    Style::new().add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                Span::styled(format!("● {}", d.state.label()), state_style(d.state)),
            ];
            let detail = state_detail(d);
            if !detail.is_empty() {
                spans.push(Span::styled(format!("  {detail}"), DIM));
            }
            if d.open_streams > 0 || d.waiting > 0 {
                let mut activity = format!("  {} open", d.open_streams);
                if d.waiting > 0 {
                    activity.push_str(&format!(", {} waiting", d.waiting));
                }
                spans.push(Span::raw(activity));
            }
            Line::from(spans)
        })
        .collect()
}

/// The highlighted destination in full: ids, the last error, what it reaches,
/// and where its server's own status page is.
fn details_lines(d: &DestinationRow, status_host: &str) -> Vec<Line<'static>> {
    let field = |label: &str, value: String| {
        Line::from(vec![Span::styled(format!("{label:<16}"), DIM), Span::raw(value)])
    };
    let mut lines = vec![
        field("server node id", d.server_node_id.clone()),
        match &d.client_node_id {
            Some(id) => field("client node id", id.clone()),
            None => Line::from(vec![
                Span::styled(format!("{:<16}", "client node id"), DIM),
                Span::styled("none while idle", DIM),
            ]),
        },
    ];
    if let Some(err) = &d.last_error {
        lines.push(Line::from(Span::styled(
            format!("error: {err}"),
            Style::new().fg(Color::Red),
        )));
    }

    lines.push(Line::default());
    lines.push(section("Reaches through this server:".to_string()));
    lines.push(Line::from(vec![
        Span::raw(format!("  {}:<port>", d.host)),
        Span::styled("  the server's own loopback", DIM),
    ]));
    for domain in &d.routed_domains {
        lines.push(item(domain.clone()));
    }
    for cidr in &d.routed_cidrs {
        lines.push(item(cidr.clone()));
    }

    if !d.relay_urls.is_empty() {
        lines.push(Line::default());
        lines.push(section("Custom relays:".to_string()));
        for relay in &d.relay_urls {
            lines.push(item(relay.clone()));
        }
    }

    lines.push(Line::default());
    lines.push(section("Server status page (opening it connects):".to_string()));
    lines.push(item(format!("http://{status_host}/servers/{}/", d.host)));
    lines
}

/// Lines for the on-demand connection-path overlay: the iroh path(s) and, when
/// custom relays are configured, their `/healthz` health.
fn conn_path_lines(snapshot: &WireConnSnapshot) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if snapshot.paths.is_empty() {
        lines.push(Line::from(Span::styled(
            "No path — this destination is not connected right now.",
            DIM,
        )));
    } else {
        for p in &snapshot.paths {
            let style = match p.kind.as_str() {
                "direct" => Style::new().fg(Color::Green),
                "relay" => Style::new().fg(Color::Yellow),
                _ => DIM,
            };
            let mut spans = vec![Span::styled(p.display.clone(), style)];
            if p.selected {
                spans.push(Span::styled(
                    "  ● active",
                    Style::new().fg(Color::Green).add_modifier(Modifier::BOLD),
                ));
            }
            lines.push(Line::from(spans));
        }
    }

    // Custom-relay health (empty with the default relays). /healthz is
    // unauthenticated — it confirms the relay is up, not that a relay auth token is accepted.
    if !snapshot.custom_relays.is_empty() {
        lines.push(Line::default());
        lines.push(section("Custom relays:".to_string()));
        for relay in &snapshot.custom_relays {
            let (style, status) = match relay.working {
                Some(true) => (Style::new().fg(Color::Green), "reachable".to_string()),
                Some(false) => (
                    Style::new().fg(Color::Red),
                    match &relay.error {
                        Some(e) => format!("unreachable — {e}"),
                        None => "unreachable".to_string(),
                    },
                ),
                None => (DIM, "status unavailable".to_string()),
            };
            lines.push(Line::from(vec![
                Span::raw(format!("  {}  ", relay.url)),
                Span::styled(format!("[{status}]"), style),
            ]));
        }
    }
    lines
}

/// The on-demand connection-path overlay (r refresh · Esc close), captured when
/// opened — mirrors the desktop connection-path modal and the iOS sheet.
fn draw_conn_path(frame: &mut Frame, host: &str, snapshot: &WireConnSnapshot) {
    let lines = conn_path_lines(snapshot);
    let height = (lines.len() as u16 + 2).clamp(3, frame.area().height.max(3));
    let area = centered(frame.area(), 74, height);
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(lines).block(titled_block(&format!(
            "Connection path · {host}  (r refresh · Esc close)"
        ))),
        area,
    );
}

fn section(title: String) -> Line<'static> {
    Line::from(Span::styled(title, Style::new().add_modifier(Modifier::BOLD)))
}

fn item(text: String) -> Line<'static> {
    Line::from(format!("  {text}"))
}

fn forward_state_span(row: &ForwardRow) -> Span<'static> {
    match row.state {
        ForwardRowState::Stopped => Span::styled("off", Style::new().fg(Color::Red)),
        ForwardRowState::Starting => Span::styled("starting", Style::new().fg(Color::Yellow)),
        ForwardRowState::Listening => Span::styled(
            format!("listening ({} active)", row.active),
            Style::new().fg(Color::Green),
        ),
        ForwardRowState::Failed => Span::styled("failed", Style::new().fg(Color::Red)),
    }
}

fn forward_lines(forwards: &[ForwardRow]) -> Vec<Line<'static>> {
    if forwards.is_empty() {
        return vec![Line::from(Span::styled(
            "no port forwards — declare them as [[forwards]] in the client config",
            DIM,
        ))];
    }
    forwards
        .iter()
        .map(|row| {
            let f = &row.forward;
            let mut spans = vec![
                Span::raw("  "),
                Span::styled(
                    format!("{:<20}", f.display_name()),
                    Style::new().add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!(
                    " localhost:{} → {}  ",
                    f.local_port,
                    flextunnel_core::forwards::format_host_port(&f.remote_host, f.remote_port)
                )),
                forward_state_span(row),
                Span::styled(format!("  via {}", row.destination), DIM),
            ];
            if let Some(err) = &row.error {
                spans.push(Span::styled(
                    format!("  {err}"),
                    Style::new().fg(Color::Red),
                ));
            } else if let Some(err) = &row.last_conn_error {
                spans.push(Span::styled(format!("  last error: {err}"), DIM));
            }
            Line::from(spans)
        })
        .collect()
}

fn footer_line(app: &App) -> Line<'static> {
    if let Some(notice) = &app.notice {
        return Line::from(Span::styled(
            notice.clone(),
            Style::new().fg(Color::Red),
        ));
    }
    let hints = match app.mode {
        Mode::Normal => "q quit · ↑/↓ destination · p its path · [/] scroll details · PgUp/PgDn forwards",
        Mode::ConnPath { .. } => "r refresh · Esc close",
    };
    Line::from(Span::styled(hints, DIM))
}

/// A centered `width` x `height` rect clamped to `area`.
fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn destination(host: &str, state: DestState) -> DestinationRow {
        DestinationRow {
            host: host.to_string(),
            server_node_id: "serverid".into(),
            state,
            connected_secs: None,
            open_streams: 0,
            waiting: 0,
            client_node_id: None,
            failed_attempts: 0,
            next_attempt_secs: None,
            last_error: None,
            routed_domains: vec!["*.corp.example".into()],
            routed_cidrs: vec!["10.0.0.0/8".into()],
            relay_urls: Vec::new(),
        }
    }

    fn text(lines: &[Line<'_>]) -> Vec<String> {
        lines
            .iter()
            .map(|line| line.spans.iter().map(|s| s.content.as_ref()).collect())
            .collect()
    }

    #[test]
    fn state_detail_says_what_happens_next() {
        let mut d = destination("m1.internal", DestState::Idle);
        assert_eq!(state_detail(&d), "connects on first use");

        d.state = DestState::Connected;
        d.connected_secs = Some(125);
        assert_eq!(state_detail(&d), "for 2m 05s");

        d.connected_secs = None;
        d.state = DestState::Backoff;
        d.failed_attempts = 3;
        d.next_attempt_secs = Some(4);
        assert_eq!(state_detail(&d), "3 failed attempts, next in 4s");

        d.state = DestState::Connecting;
        assert_eq!(state_detail(&d), "3 failed attempts, trying now");

        // Idle with a failure on record: nothing retries by itself.
        d.state = DestState::Idle;
        d.failed_attempts = 1;
        assert_eq!(state_detail(&d), "1 failed attempt, retries on next use");

        d.state = DestState::Failed;
        d.next_attempt_secs = Some(0);
        assert_eq!(state_detail(&d), "1 failed attempt");
    }

    #[test]
    fn destination_rows_mark_the_selection_and_show_activity() {
        let mut busy = destination("machine1.internal", DestState::Connected);
        busy.connected_secs = Some(7);
        busy.open_streams = 2;
        busy.waiting = 1;
        let rows = text(&destination_lines(
            &[busy, destination("m2.internal", DestState::Idle)],
            1,
        ));
        assert!(rows[0].starts_with("  machine1.internal  ● connected"), "{}", rows[0]);
        assert!(rows[0].ends_with("2 open, 1 waiting"), "{}", rows[0]);
        // The second row is selected, and hosts are padded to one column.
        assert!(rows[1].starts_with("▸ m2.internal        ● idle"), "{}", rows[1]);
        assert!(rows[1].contains("connects on first use"));

        assert_eq!(text(&destination_lines(&[], 0)), ["no destinations"]);
    }

    #[test]
    fn details_list_what_the_destination_reaches() {
        let mut d = destination("m1.internal", DestState::Failed);
        d.last_error = Some("Authentication failed: nope".into());
        d.relay_urls = vec!["https://relay.example/".into()];
        let lines = text(&details_lines(&d, "flextunnel.internal"));
        let all = lines.join("\n");
        assert!(all.contains("serverid"));
        assert!(all.contains("none while idle"));
        assert!(all.contains("error: Authentication failed: nope"));
        assert!(all.contains("m1.internal:<port>  the server's own loopback"));
        assert!(all.contains("  *.corp.example") && all.contains("  10.0.0.0/8"));
        assert!(all.contains("https://relay.example/"));
        assert!(all.contains("http://flextunnel.internal/servers/m1.internal/"));
    }
}

