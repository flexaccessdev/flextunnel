//! The ratatui control panel — status (connection, routing, connection paths)
//! and the config-declared port forwards. Read-only: nothing about the client
//! can be changed from here. Reachable two ways over the same UI:
//!
//! - `flextunnel client control`: attaches to a *running* client over its
//!   control socket (see `ipc.rs`), as a separate process. Detaching (q) never
//!   affects the tunnel; the panel can re-attach any time, and several panels
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
use crate::ipc::{IpcClient, IpcCmd, Request, Response, StatusSnapshot, WireConnSnapshot};

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
    /// On-demand connection-path overlay: a point-in-time snapshot (paths +
    /// custom-relay health) captured when opened, refreshable, not polled —
    /// mirrors the desktop modal / iOS sheet.
    ConnPath(WireConnSnapshot),
}

struct App {
    snapshot: StatusSnapshot,
    routing_scroll: u16,
    forwards_scroll: u16,
    mode: Mode,
    /// Transient error line (e.g. a failed path probe), cleared on next input.
    notice: Option<String>,
}

pub fn run(config_path: Option<PathBuf>, server_node_id: Option<String>) -> Result<()> {
    let instance::Located { key, profile } =
        instance::locate(config_path, server_node_id, "client control")?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let Some(client) = rt.block_on(IpcClient::connect(&key))? else {
        eprintln!("The flextunnel client for {profile} is not running.");
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
            routing_scroll: 0,
            forwards_scroll: 0,
            mode: Mode::Normal,
            notice: None,
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
                let quit = match &mut self.mode {
                    Mode::Normal => self.handle_normal_key(key.code, backend)?,
                    Mode::ConnPath(_) => {
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
            // Both panes clamp against their content height at render time.
            KeyCode::Up | KeyCode::Char('k') => {
                self.forwards_scroll = self.forwards_scroll.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.forwards_scroll = self.forwards_scroll.saturating_add(1);
            }
            KeyCode::Char('[') | KeyCode::PageUp => {
                self.routing_scroll = self.routing_scroll.saturating_sub(3);
            }
            KeyCode::Char(']') | KeyCode::PageDown => {
                // Clamped against the content height at render time.
                self.routing_scroll = self.routing_scroll.saturating_add(3);
            }
            // On-demand connection-path + custom-relay-health overlay (not polled).
            KeyCode::Char('p') => match self.request_conn_path(backend)? {
                Ok(snapshot) => self.mode = Mode::ConnPath(snapshot),
                Err(message) => self.notice = Some(message),
            },
            _ => {}
        }
        Ok(false)
    }

    /// Fetch an on-demand connection snapshot. The outer `Result` is a transport
    /// failure (ends the loop); the inner is a session-reported error to surface
    /// as a footer notice.
    fn request_conn_path(
        &mut self,
        backend: &mut dyn ControlBackend,
    ) -> Result<std::result::Result<WireConnSnapshot, String>> {
        Ok(match backend.request(Request::ConnPath)? {
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
        match code {
            // Re-probe in place (paths + relay /healthz).
            KeyCode::Char('r') => match self.request_conn_path(backend)? {
                Ok(snapshot) => self.mode = Mode::ConnPath(snapshot),
                Err(message) => {
                    self.notice = Some(message);
                    self.mode = Mode::Normal;
                }
            },
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => self.mode = Mode::Normal,
            _ => {}
        }
        Ok(())
    }
}
