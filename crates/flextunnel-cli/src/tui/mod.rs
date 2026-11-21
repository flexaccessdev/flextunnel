//! The ratatui control panel — the client's destinations with their live
//! connection state, the selected destination's details (routes, connection
//! paths), and the config-declared port forwards. Read-only: nothing about the
//! client can be changed from here, and looking never makes a destination
//! connect. Reachable two ways over the same UI:
//!
//! - `flextunnel client control`: attaches to a *running* client over its
//!   control socket (see `ipc.rs`), as a separate process. Detaching (q) never
//!   affects the client; the panel can re-attach any time, and several panels
//!   can attach at once. This is the [`IpcBackend`] path.
//! - `flextunnel client start --quick`: a *self-contained* session in this same
//!   process, driven over an in-process channel with no socket. Quitting (q)
//!   tears the session down — the tunnel disconnects. This is the
//!   [`InProcessBackend`] path (entry point [`run_quick_panel`]).
//!
//! Either way the panel runs a plain blocking event loop with per-request
//! round trips to a [`ControlBackend`]. This deliberately avoids crossterm's
//! `EventStream` so no separate crossterm dependency (with version-sync risk
//! against ratatui's re-export) is needed.

mod view;

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use tokio::sync::mpsc;

use crate::instance;
use crate::ipc::{
    DestinationRow, IpcClient, IpcCmd, Request, Response, StatusSnapshot, WireConnSnapshot,
};

/// The panel's transport to a client session: one request → one response,
/// blocking the UI thread. Implemented over the control socket (a separate
/// `client control` process) and over an in-process channel (the self-contained
/// `client start --quick` session).
trait ControlBackend {
    fn request(&mut self, request: Request) -> Result<Response>;
}

/// Socket transport: a current-thread runtime driving the async [`IpcClient`]
/// (each round trip bounded by the 2 s request timeout).
struct IpcBackend {
    rt: tokio::runtime::Runtime,
    client: IpcClient,
}

impl ControlBackend for IpcBackend {
    fn request(&mut self, request: Request) -> Result<Response> {
        self.rt.block_on(self.client.request(&request))
    }
}

/// In-process transport for the self-contained quick panel: drives the client
/// session running in this process over its command channel. A closed channel
/// (the session ended) surfaces as an error, which ends the panel loop; dropping
/// this backend on quit drops the sender, which tears the session down.
struct InProcessBackend {
    tx: mpsc::Sender<IpcCmd>,
}

impl ControlBackend for InProcessBackend {
    fn request(&mut self, request: Request) -> Result<Response> {
        crate::ipc::blocking_request(&self.tx, request).context("the tunnel session ended")
    }
}

/// How often the panel polls the client for a fresh snapshot.
const REFRESH: Duration = Duration::from_secs(1);

enum Mode {
    Normal,
    /// On-demand connection-path overlay for one destination: a point-in-time
    /// snapshot (paths + custom-relay health) captured when opened,
    /// refreshable, not polled — mirrors the desktop modal / iOS sheet.
    ConnPath {
        name: String,
        snapshot: WireConnSnapshot,
    },
}

struct App {
    snapshot: StatusSnapshot,
    /// Index of the highlighted destination, whose details the middle pane
    /// shows. Clamped against the destination count wherever it is read.
    selected: usize,
    details_scroll: u16,
    forwards_scroll: u16,
    mode: Mode,
    /// Transient error line (e.g. a failed path probe), cleared on next input.
    notice: Option<String>,
}

pub fn run(config_path: Option<PathBuf>, name: Option<String>) -> Result<()> {
    let located = instance::locate(config_path, name)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let Some(client) = rt.block_on(IpcClient::connect(&located.name))? else {
        eprintln!("{}", located.not_running());
        std::process::exit(1);
    };
    let mut backend = IpcBackend { rt, client };
    // First snapshot before touching terminal modes, so early failures print
    // as ordinary errors.
    let snapshot = request_snapshot(&mut backend, Request::Status)?;

    let app = App::new(snapshot);
    run_panel(app, &mut backend).context("Lost the connection to the client (did it stop?)")
}

/// Run the self-contained control panel for `client start --quick`: the same UI
/// as `client control`, but driving the session in this process over `tx`
/// instead of a socket. Quitting (q/Esc/Ctrl-C) returns, dropping `tx` — which
/// tears the session down, so the tunnel disconnects rather than detaching.
pub fn run_quick_panel(tx: mpsc::Sender<IpcCmd>, initial: StatusSnapshot) -> Result<()> {
    let mut backend = InProcessBackend { tx };
    run_panel(App::new(initial), &mut backend)
}

/// Drive the panel's event loop against `backend`, bracketing it with terminal
/// setup/teardown. `ratatui::init` installs a panic hook that restores the
/// terminal first — required under the workspace's `panic = "abort"` release
/// profile, where no unwinding drop guard would run.
fn run_panel(mut app: App, backend: &mut dyn ControlBackend) -> Result<()> {
    let mut terminal = ratatui::init();
    let res = app.run(&mut terminal, backend);
    ratatui::restore();
    res
}

fn request_snapshot(backend: &mut dyn ControlBackend, request: Request) -> Result<StatusSnapshot> {
    match backend.request(request)? {
        Response::Status(snapshot) => Ok(*snapshot),
        Response::Error { message } => anyhow::bail!("{message}"),
        other => anyhow::bail!("unexpected response to a status request: {other:?}"),
    }
}

impl App {
    fn new(snapshot: StatusSnapshot) -> Self {
        App {
            snapshot,
            selected: 0,
            details_scroll: 0,
            forwards_scroll: 0,
            mode: Mode::Normal,
            notice: None,
        }
    }

    /// The highlighted destination, if the client has any.
    fn selected_destination(&self) -> Option<&DestinationRow> {
        let destinations = &self.snapshot.destinations;
        destinations.get(self.selected.min(destinations.len().saturating_sub(1)))
    }

    /// Move the highlight by `delta` rows, stopping at either end.
    fn select(&mut self, delta: isize) {
        let last = self.snapshot.destinations.len().saturating_sub(1);
        let selected = self.selected.min(last).saturating_add_signed(delta).min(last);
        if selected != self.selected {
            self.selected = selected;
            // Another destination's details: start at their top.
            self.details_scroll = 0;
        }
    }

    fn run(
        &mut self,
        terminal: &mut ratatui::DefaultTerminal,
        backend: &mut dyn ControlBackend,
    ) -> Result<()> {
        let mut last_refresh = Instant::now();
        loop {
            terminal.draw(|frame| view::draw(frame, self))?;

            let timeout = REFRESH
                .saturating_sub(last_refresh.elapsed())
                .min(Duration::from_millis(250));
            if event::poll(timeout)?
                && let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                self.notice = None;
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    && key.code == KeyCode::Char('c')
                {
                    return Ok(());
                }
                let quit = match &self.mode {
                    Mode::Normal => self.handle_normal_key(key.code, backend)?,
                    Mode::ConnPath { .. } => {
                        self.handle_conn_path_key(key.code, backend)?;
                        false
                    }
                };
                if quit {
                    return Ok(());
                }
            }

            if last_refresh.elapsed() >= REFRESH {
                // Poll-based refresh, like the desktop's ticker.
                self.snapshot = request_snapshot(backend, Request::Status)?;
                last_refresh = Instant::now();
            }
        }
    }

    fn handle_normal_key(
        &mut self,
        code: KeyCode,
        backend: &mut dyn ControlBackend,
    ) -> Result<bool> {
        match code {
            KeyCode::Char('q') | KeyCode::Esc => return Ok(true),
            KeyCode::Up | KeyCode::Char('k') => self.select(-1),
            KeyCode::Down | KeyCode::Char('j') => self.select(1),
            // The scrolling panes clamp against their content height at
            // render time.
            KeyCode::Char('[') => {
                self.details_scroll = self.details_scroll.saturating_sub(3);
            }
            KeyCode::Char(']') => {
                self.details_scroll = self.details_scroll.saturating_add(3);
            }
            KeyCode::PageUp => {
                self.forwards_scroll = self.forwards_scroll.saturating_sub(1);
            }
            KeyCode::PageDown => {
                self.forwards_scroll = self.forwards_scroll.saturating_add(1);
            }
            // On-demand connection-path + custom-relay-health overlay for the
            // highlighted destination (not polled).
            KeyCode::Char('p') => {
                if let Some(name) = self.selected_destination().map(|d| d.name.clone()) {
                    match self.request_conn_path(&name, backend)? {
                        Ok(snapshot) => self.mode = Mode::ConnPath { name, snapshot },
                        Err(message) => self.notice = Some(message),
                    }
                }
            }
            _ => {}
        }
        Ok(false)
    }

    /// Fetch an on-demand connection snapshot for the destination `name`. The
    /// outer `Result` is a transport failure (ends the loop); the inner is a
    /// session-reported error to surface as a footer notice.
    fn request_conn_path(
        &mut self,
        name: &str,
        backend: &mut dyn ControlBackend,
    ) -> Result<std::result::Result<WireConnSnapshot, String>> {
        let request = Request::ConnPath {
            name: name.to_string(),
        };
        Ok(match backend.request(request)? {
            Response::ConnPath(snapshot) => Ok(snapshot),
            Response::Error { message } => Err(message),
            other => Err(format!("unexpected response to a conn-path request: {other:?}")),
        })
    }

    fn handle_conn_path_key(
        &mut self,
        code: KeyCode,
        backend: &mut dyn ControlBackend,
    ) -> Result<()> {
        let Mode::ConnPath { name, .. } = &self.mode else {
            return Ok(());
        };
        match code {
            // Re-probe in place (paths + relay /healthz).
            KeyCode::Char('r') => {
                let name = name.clone();
                match self.request_conn_path(&name, backend)? {
                    Ok(snapshot) => self.mode = Mode::ConnPath { name, snapshot },
                    Err(message) => {
                        self.notice = Some(message);
                        self.mode = Mode::Normal;
                    }
                }
            }
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => self.mode = Mode::Normal,
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::DestState;

    fn destination(name: &str) -> DestinationRow {
        DestinationRow {
            name: name.to_string(),
            server_node_id: "server".into(),
            state: DestState::Idle,
            connected_secs: None,
            open_streams: 0,
            waiting: 0,
            client_node_id: None,
            failed_attempts: 0,
            next_attempt_secs: None,
            last_error: None,
            routed_domains: Vec::new(),
            routed_cidrs: Vec::new(),
            relay_urls: Vec::new(),
        }
    }

    fn app(names: &[&str]) -> App {
        App::new(StatusSnapshot {
            name: "work".into(),
            socks_addr: None,
            http_addr: None,
            status_page_host: "flextunnel.internal".into(),
            idle_timeout_secs: Some(300),
            destinations: names.iter().map(|n| destination(n)).collect(),
            forwards: Vec::new(),
        })
    }

    #[test]
    fn selection_stops_at_both_ends_and_resets_the_details_scroll() {
        let mut app = app(&["m1", "m2", "m3"]);
        assert_eq!(app.selected_destination().unwrap().name, "m1");
        app.select(-1);
        assert_eq!(app.selected, 0, "already at the top");

        app.details_scroll = 6;
        app.select(1);
        assert_eq!(app.selected_destination().unwrap().name, "m2");
        assert_eq!(app.details_scroll, 0);
        app.select(5);
        assert_eq!(app.selected_destination().unwrap().name, "m3");

        // A stale index (the destination list never shrinks in practice, but
        // the panel must not panic if it did) reads as the last row.
        app.selected = 9;
        assert_eq!(app.selected_destination().unwrap().name, "m3");
        app.select(-1);
        assert_eq!(app.selected, 1);
    }

    #[test]
    fn no_destinations_selects_nothing() {
        let mut app = app(&[]);
        assert!(app.selected_destination().is_none());
        app.select(1);
        assert_eq!(app.selected, 0);
    }
}
