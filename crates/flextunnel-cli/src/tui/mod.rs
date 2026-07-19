//! `flextunnel client control` — a ratatui control panel attached to a
//! running client over its control socket (see `ipc.rs`).
//!
//! Read-only status (connection, routing, connection paths) plus editable
//! port forwards. Detaching (q) never affects the tunnel; the panel can
//! re-attach any time, and several panels can attach at once.
//!
//! The panel runs a plain blocking event loop on the main thread with a
//! current-thread tokio runtime for the IPC round trips (each is bounded by
//! the 2 s request timeout). This deliberately avoids crossterm's
//! `EventStream` so no separate crossterm dependency (with version-sync risk
//! against ratatui's re-export) is needed.

mod form;
mod view;

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use flextunnel_core::config;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};

use crate::instance;
use crate::ipc::{IpcClient, Request, Response, StatusSnapshot};
use form::{FIELD_ENABLED, FormState};

/// How often the panel polls the client for a fresh snapshot.
const REFRESH: Duration = Duration::from_secs(1);

enum Mode {
    Normal,
    Form(FormState),
    ConfirmDelete { id: String, name: String },
}

struct App {
    snapshot: StatusSnapshot,
    /// Selected row in the forwards table.
    selected: usize,
    routing_scroll: u16,
    mode: Mode,
    /// Transient error line (e.g. a rejected toggle), cleared on next input.
    notice: Option<String>,
}

pub fn run(config_path: Option<PathBuf>, server_node_id: Option<String>) -> Result<()> {
    // The running client is identified by the profile's server node id
    // (-n wins over the config file; bare `client control` reads the default
    // config), from which the same instance key as the client's is derived.
    // With -n and no -c, identify purely by server id (skip the config load).
    let file = if server_node_id.is_some() && config_path.is_none() {
        None
    } else {
        config::load_client_config(config_path.as_deref())
            .context("client control needs a profile: -c <file>, the default config, or -n <server id>")?
    };
    let cli = config::ClientConfig {
        server_node_id,
        ..Default::default()
    };
    let r = config::resolve_client(cli, file);
    let server_id = r.server_node_id.context(
        "The profile has no server node id (set server_node_id in the config or pass -n).",
    )?;
    let key = instance::instance_key(&server_id)?;
    let profile = r.name.unwrap_or_else(|| format!("server {key}…"));

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let Some(mut client) = rt.block_on(IpcClient::connect(&key))? else {
        eprintln!("The flextunnel client for {profile} is not running.");
        std::process::exit(1);
    };
    // First snapshot before touching terminal modes, so early failures print
    // as ordinary errors.
    let snapshot = request_snapshot(&rt, &mut client, &Request::Status)?;

    let mut app = App {
        snapshot,
        selected: 0,
        routing_scroll: 0,
        mode: Mode::Normal,
        notice: None,
    };

    // `ratatui::init` installs a panic hook that restores the terminal first —
    // required under the workspace's `panic = "abort"` release profile, where
    // no unwinding drop guard would run.
    let mut terminal = ratatui::init();
    let res = app.run(&mut terminal, &rt, &mut client);
    ratatui::restore();
    res.context("Lost the connection to the client (did it stop?)")
}

fn request_snapshot(
    rt: &tokio::runtime::Runtime,
    client: &mut IpcClient,
    request: &Request,
) -> Result<StatusSnapshot> {
    match rt.block_on(client.request(request))? {
        Response::Status(snapshot) => Ok(*snapshot),
        Response::Error { message } => anyhow::bail!("{message}"),
    }
}

impl App {
    fn run(
        &mut self,
        terminal: &mut ratatui::DefaultTerminal,
        rt: &tokio::runtime::Runtime,
        client: &mut IpcClient,
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
                    Mode::Normal => self.handle_normal_key(key.code, rt, client)?,
                    Mode::Form(_) => {
                        self.handle_form_key(key.code, rt, client)?;
                        false
                    }
                    Mode::ConfirmDelete { .. } => {
                        self.handle_confirm_key(key.code, rt, client)?;
                        false
                    }
                };
                if quit {
                    return Ok(());
                }
            }

            if last_refresh.elapsed() >= REFRESH {
                // Poll-based refresh, like the desktop's ticker. Mutations
                // also refresh inline via the returned snapshot.
                self.set_snapshot(request_snapshot(rt, client, &Request::Status)?);
                last_refresh = Instant::now();
            }
        }
    }

    fn set_snapshot(&mut self, snapshot: StatusSnapshot) {
        // Follow the selected forward by its stable id across the refresh: a
        // row added or removed above it shifts the index, so clamping alone
        // would silently move the selection to a different forward.
        let selected_id = self
            .selected_forward()
            .map(|row| row.forward.id.clone());
        self.snapshot = snapshot;
        self.selected = selected_id
            .and_then(|id| self.snapshot.forwards.iter().position(|r| r.forward.id == id))
            .unwrap_or_else(|| self.selected.min(self.snapshot.forwards.len().saturating_sub(1)));
    }

    /// Send a mutation; a fresh snapshot means success, an error message is
    /// returned for the caller to surface (form line or footer notice).
    fn mutate(
        &mut self,
        rt: &tokio::runtime::Runtime,
        client: &mut IpcClient,
        request: Request,
    ) -> Result<Option<String>> {
        match rt.block_on(client.request(&request))? {
            Response::Status(snapshot) => {
                self.set_snapshot(*snapshot);
                Ok(None)
            }
            Response::Error { message } => Ok(Some(message)),
        }
    }

    fn selected_forward(&self) -> Option<&crate::ipc::ForwardRow> {
        self.snapshot.forwards.get(self.selected)
    }

    fn handle_normal_key(
        &mut self,
        code: KeyCode,
        rt: &tokio::runtime::Runtime,
        client: &mut IpcClient,
    ) -> Result<bool> {
        match code {
            KeyCode::Char('q') | KeyCode::Esc => return Ok(true),
            KeyCode::Up | KeyCode::Char('k') => self.selected = self.selected.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => {
                self.selected = (self.selected + 1)
                    .min(self.snapshot.forwards.len().saturating_sub(1));
            }
            KeyCode::Char('[') | KeyCode::PageUp => {
                self.routing_scroll = self.routing_scroll.saturating_sub(3);
            }
            KeyCode::Char(']') | KeyCode::PageDown => {
                // Clamped against the content height at render time.
                self.routing_scroll = self.routing_scroll.saturating_add(3);
            }
            KeyCode::Char('a') => self.mode = Mode::Form(FormState::add()),
            KeyCode::Char('e') | KeyCode::Enter => {
                if let Some(row) = self.selected_forward() {
                    self.mode = Mode::Form(FormState::edit(&row.forward));
                }
            }
            KeyCode::Char('d') => {
                if let Some(row) = self.selected_forward() {
                    self.mode = Mode::ConfirmDelete {
                        id: row.forward.id.clone(),
                        name: form::display_name(&row.forward),
                    };
                }
            }
            KeyCode::Char(' ') => {
                if let Some(row) = self.selected_forward() {
                    let request = Request::SetForwardEnabled {
                        id: row.forward.id.clone(),
                        enabled: !row.forward.enabled,
                    };
                    self.notice = self.mutate(rt, client, request)?;
                }
            }
            _ => {}
        }
        Ok(false)
    }

    fn handle_form_key(
        &mut self,
        code: KeyCode,
        rt: &tokio::runtime::Runtime,
        client: &mut IpcClient,
    ) -> Result<()> {
        let Mode::Form(form) = &mut self.mode else {
            return Ok(());
        };
        match code {
            KeyCode::Esc => self.mode = Mode::Normal,
            KeyCode::Tab | KeyCode::Down => form.focus_next(),
            KeyCode::BackTab | KeyCode::Up => form.focus_prev(),
            KeyCode::Enter => {
                match form.validate(&self.snapshot.forwards) {
                    Err(message) => form.error = Some(message),
                    Ok(forward) => {
                        let request = if form.is_edit() {
                            Request::UpdateForward { forward }
                        } else {
                            Request::AddForward { forward }
                        };
                        match self.mutate(rt, client, request)? {
                            // The running client rejected it (it re-validates
                            // authoritatively): keep the form open.
                            Some(message) => {
                                if let Mode::Form(form) = &mut self.mode {
                                    form.error = Some(message);
                                }
                            }
                            None => self.mode = Mode::Normal,
                        }
                    }
                }
            }
            KeyCode::Char(' ') if form.focus == FIELD_ENABLED => form.enabled = !form.enabled,
            KeyCode::Char(c) => {
                if let Some(text) = form.focused_text() {
                    text.push(c);
                }
            }
            KeyCode::Backspace => {
                if let Some(text) = form.focused_text() {
                    text.pop();
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_confirm_key(
        &mut self,
        code: KeyCode,
        rt: &tokio::runtime::Runtime,
        client: &mut IpcClient,
    ) -> Result<()> {
        let Mode::ConfirmDelete { id, .. } = &self.mode else {
            return Ok(());
        };
        match code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                let request = Request::DeleteForward { id: id.clone() };
                self.mode = Mode::Normal;
                self.notice = self.mutate(rt, client, request)?;
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => self.mode = Mode::Normal,
            _ => {}
        }
        Ok(())
    }
}
