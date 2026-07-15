//! flextunnel-desktop: a tray GUI for the flextunnel client (macOS/Windows).
//! Embeds `flextunnel-core` directly — no FFI layer — and drives a
//! profile-sidebar window plus a system tray icon. Each profile is its own
//! client config and can run its own concurrent tunnel session with its own
//! optional local SOCKS5 and HTTP proxies plus server-direct port forwards; connect is
//! always manual.
//!
//! Built on iced's daemon runtime: the process keeps running with no window
//! open (the tray owns the lifecycle), the window is opened at launch and
//! re-opened from the tray, and closing it just destroys the window while all
//! state lives on in [`app::App`].

#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod config;
mod forward;
mod icon;
mod logging;
mod style;
mod tray;
mod tunnel;
mod view;

fn main() -> iced::Result {
    logging::init();
    flextunnel_core::app::log_version(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    flextunnel_core::app::raise_fd_limit();
    if !config::init_store() {
        log::error!("No system keychain available; settings cannot be loaded or saved");
    }

    iced::daemon(app::App::boot, app::App::update, app::App::view)
        .title(app::App::title)
        .style(app::App::style)
        .subscription(app::App::subscription)
        .run()
}
