//! flextunnel-desktop: a tray app for flextunnel (macOS/Windows) with two
//! roles of equal weight, either optional: a client of any number of servers
//! elsewhere, and this computer's one flextunnel server, run in-process. Embeds
//! `flextunnel-core` directly — no FFI layer — and drives a sidebar window
//! (connections, then the server) plus a system tray icon that shows the
//! server's state. Each client profile is its
//! own client config and can run its own concurrent tunnel session with its own
//! optional local SOCKS5 and HTTP proxies plus server-direct port forwards;
//! connect is always manual.
//!
//! Built on iced's daemon runtime: the process keeps running with no window
//! open (the tray owns the lifecycle), the window is opened at launch and
//! re-opened from the tray, and closing it just destroys the window while all
//! state lives on in [`app::App`].

#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod autostart;
mod config;
mod icon;
mod logging;
mod server_session;
mod style;
mod tray;
mod tunnel;
mod view;

fn main() -> iced::Result {
    logging::init();
    flextunnel_core::app::log_version(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    flextunnel_core::app::raise_fd_limit();
    if let Err(e) = config::init_store() {
        log::error!("No settings store; settings cannot be loaded or saved: {e:#}");
    }

    iced::daemon(app::App::boot, app::App::update, app::App::view)
        .title(app::App::title)
        .style(app::App::style)
        .subscription(app::App::subscription)
        .run()
}
