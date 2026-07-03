//! flextunnel-desktop: a tray GUI for the flextunnel client (macOS/Windows).
//! Embeds `flextunnel-core` directly — no FFI layer — and drives a single
//! Status/Settings/Logs window plus a system tray icon. v1 scope: establish
//! the local SOCKS5 (and optional HTTP) proxy; connect is always manual.

#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod config;
mod icon;
mod logging;
mod tray;
mod tunnel;

fn main() -> eframe::Result {
    logging::init();
    flextunnel_core::app::log_version(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    flextunnel_core::app::raise_fd_limit();
    if !config::init_store() {
        log::error!("No system keychain available; settings cannot be loaded or saved");
    }

    let controller = tunnel::Controller::start();

    #[allow(unused_mut)]
    let mut options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("flextunnel")
            .with_inner_size([460.0, 580.0])
            .with_min_inner_size([400.0, 440.0])
            .with_icon(app::window_icon()),
        ..Default::default()
    };
    // Menu-bar app: no Dock icon, no app switcher entry. The window still
    // shows/hides from the tray menu.
    #[cfg(target_os = "macos")]
    {
        use egui_winit::winit::platform::macos::{ActivationPolicy, EventLoopBuilderExtMacOS};
        options.event_loop_builder = Some(Box::new(|builder| {
            builder.with_activation_policy(ActivationPolicy::Accessory);
        }));
    }

    eframe::run_native(
        "flextunnel",
        options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc, controller)))),
    )
}
