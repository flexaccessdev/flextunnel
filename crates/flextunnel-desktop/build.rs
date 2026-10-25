//! flextunnel-desktop is macOS and Windows only (keychain + tray backends):
//! fail any other target here, before rustc sees a crate whose dependencies
//! are all gated away.

fn main() {
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if os != "macos" && os != "windows" {
        eprintln!("flextunnel-desktop supports macOS and Windows only (target os: {os})");
        std::process::exit(1);
    }
}
