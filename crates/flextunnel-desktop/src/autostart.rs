//! "Start at login": registering the app as a per-user login item, and the
//! hidden launch that results from it.
//!
//! The registration is OS-owned state with no copy in `profiles.json`: a
//! per-user LaunchAgent plist on macOS (`~/Library/LaunchAgents/<label>.plist`,
//! `RunAtLoad` without `KeepAlive`, so quitting the app does not respawn it)
//! and a `HKCU\…\CurrentVersion\Run` value on Windows. Both are what the OS's
//! own settings pages list (System Settings › General › Login Items; Settings ›
//! Apps › Startup, Task Manager › Startup apps), and [`is_enabled`] reads the OS
//! back rather than a cached flag, so a change made there shows up in the tray
//! checkbox. Neither registration is loaded immediately — launchd and Explorer
//! pick it up at the next login, which is the point: enabling it while the app
//! runs must not start a second instance.
//!
//! Both register the executable with [`LOGIN_ITEM_ARG`], which `App::boot`
//! reads to start in the tray without opening the window. The registered path
//! is rewritten on every launch while enabled ([`refresh`]) so an app that was
//! moved or updated keeps launching.

use anyhow::{Context, Result};
use std::path::PathBuf;

/// Passed on the registered command line; a launch carrying it stays in the
/// tray instead of opening the window.
pub const LOGIN_ITEM_ARG: &str = "--launched-at-login";

/// Whether this process was started by the login-item registration.
pub fn launched_at_login() -> bool {
    std::env::args().skip(1).any(|a| a == LOGIN_ITEM_ARG)
}

fn current_exe() -> Result<PathBuf> {
    std::env::current_exe().context("Failed to locate the running executable")
}

/// Re-register the current executable while enabled, so the registration
/// follows a moved or updated binary. A no-op while disabled.
pub fn refresh() -> Result<()> {
    if is_enabled() {
        register(&current_exe()?)?;
    }
    Ok(())
}

/// Register or remove the login item.
pub fn set_enabled(enabled: bool) -> Result<()> {
    if enabled {
        register(&current_exe()?)?;
        reenable();
    } else {
        unregister()?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub use macos::{is_enabled, reenable, register, unregister};
#[cfg(windows)]
pub use windows::{is_enabled, reenable, register, unregister};

/// Only ever built on macOS/Windows (see the crate manifest); the stub keeps
/// `cargo check` on another host honest about what it cannot do.
#[cfg(not(any(target_os = "macos", windows)))]
mod unsupported {
    use super::*;
    pub fn is_enabled() -> bool {
        false
    }
    pub fn register(_exe: &std::path::Path) -> Result<()> {
        anyhow::bail!("Start at login is not supported on this platform")
    }
    pub fn unregister() -> Result<()> {
        Ok(())
    }
    pub fn reenable() {}
}
#[cfg(not(any(target_os = "macos", windows)))]
pub use unsupported::{is_enabled, reenable, register, unregister};

#[cfg(any(target_os = "macos", test))]
mod macos {
    use super::*;
    use std::path::Path;

    /// The LaunchAgent label — the app's bundle identifier, so Login Items
    /// attributes the agent to the app.
    pub const LABEL: &str = "com.flextunnel.desktop";

    #[cfg(target_os = "macos")]
    fn plist_path() -> Result<PathBuf> {
        dirs::home_dir()
            .map(|h| h.join("Library/LaunchAgents").join(format!("{LABEL}.plist")))
            .context("No home directory to install the LaunchAgent in")
    }

    fn xml_escape(s: &str) -> String {
        s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
    }

    /// The agent: run the executable with [`LOGIN_ITEM_ARG`] once at login
    /// (`RunAtLoad`, no `KeepAlive`), only in GUI sessions
    /// (`LimitLoadToSessionType`), with interactive scheduling (`ProcessType`).
    pub fn plist_xml(exe: &Path) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{LABEL}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{}</string>
		<string>{LOGIN_ITEM_ARG}</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>LimitLoadToSessionType</key>
	<string>Aqua</string>
	<key>ProcessType</key>
	<string>Interactive</string>
</dict>
</plist>
"#,
            xml_escape(&exe.to_string_lossy())
        )
    }

    /// The plist's presence. A disable from System Settings ("Allow in the
    /// Background") lives in launchd's disabled list, which has no cheap
    /// read, so it is not reflected here; [`reenable`] clears it on the next
    /// enable from the app instead.
    #[cfg(target_os = "macos")]
    pub fn is_enabled() -> bool {
        plist_path().is_ok_and(|p| p.exists())
    }

    #[cfg(target_os = "macos")]
    pub fn register(exe: &Path) -> Result<()> {
        let path = plist_path()?;
        let dir = path.parent().context("LaunchAgent path has no parent")?;
        std::fs::create_dir_all(dir)
            .with_context(|| format!("Failed to create {}", dir.display()))?;
        // Temp file + rename: launchd never sees a half-written plist.
        let tmp = path.with_extension("plist.tmp");
        std::fs::write(&tmp, plist_xml(exe))
            .with_context(|| format!("Failed to write {}", tmp.display()))?;
        std::fs::rename(&tmp, &path)
            .with_context(|| format!("Failed to install {}", path.display()))?;
        Ok(())
    }

    /// Remove the plist only. Not `launchctl bootout`: when this very process
    /// was started by the agent, booting it out would terminate it.
    #[cfg(target_os = "macos")]
    pub fn unregister() -> Result<()> {
        let path = plist_path()?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("Failed to remove {}", path.display())),
        }
    }

    /// Clear a disable left by System Settings so a re-enable from the app
    /// takes effect at the next login. Best effort: the agent may simply not
    /// be known to launchd yet.
    #[cfg(target_os = "macos")]
    pub fn reenable() {
        // SAFETY: getuid has no preconditions and cannot fail.
        let uid = unsafe { libc::getuid() };
        match std::process::Command::new("launchctl")
            .args(["enable", &format!("gui/{uid}/{LABEL}")])
            .output()
        {
            Ok(out) if out.status.success() => {}
            Ok(out) => log::debug!(
                "launchctl enable: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
            Err(e) => log::debug!("launchctl unavailable: {e}"),
        }
    }
}

#[cfg(any(windows, test))]
mod windows {
    use super::*;
    use std::path::Path;

    /// The per-user startup list Explorer runs at login.
    #[cfg(windows)]
    pub const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    /// Where Settings › Apps › Startup and Task Manager record a user's
    /// enable/disable of a `Run` entry: a binary value per entry whose first
    /// byte is even when enabled and odd (0x03) when disabled.
    #[cfg(windows)]
    pub const STARTUP_APPROVED_KEY: &str =
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
    #[cfg(windows)]
    pub const VALUE_NAME: &str = "flextunnel";

    /// The registered command line: the quoted executable plus
    /// [`LOGIN_ITEM_ARG`].
    pub fn run_command(exe: &Path) -> String {
        format!("\"{}\" {LOGIN_ITEM_ARG}", exe.display())
    }

    /// Whether a `StartupApproved` record marks the entry disabled.
    pub fn approval_disabled(record: &[u8]) -> bool {
        record.first().is_some_and(|b| b & 1 == 1)
    }

    #[cfg(windows)]
    pub fn is_enabled() -> bool {
        use windows_registry::CURRENT_USER;
        let registered = CURRENT_USER
            .open(RUN_KEY)
            .and_then(|k| k.get_string(VALUE_NAME))
            .is_ok();
        registered
            && !CURRENT_USER
                .open(STARTUP_APPROVED_KEY)
                .and_then(|k| k.get_value(VALUE_NAME))
                .is_ok_and(|v| approval_disabled(&v))
    }

    #[cfg(windows)]
    pub fn register(exe: &Path) -> Result<()> {
        windows_registry::CURRENT_USER
            .create(RUN_KEY)
            .and_then(|k| k.set_string(VALUE_NAME, run_command(exe)))
            .with_context(|| format!(r"Failed to write HKCU\{RUN_KEY}\{VALUE_NAME}"))
    }

    #[cfg(windows)]
    pub fn unregister() -> Result<()> {
        let key = windows_registry::CURRENT_USER
            .create(RUN_KEY)
            .with_context(|| format!(r"Failed to open HKCU\{RUN_KEY}"))?;
        if key.get_value(VALUE_NAME).is_ok() {
            key.remove_value(VALUE_NAME)
                .with_context(|| format!(r"Failed to remove HKCU\{RUN_KEY}\{VALUE_NAME}"))?;
        }
        // The approval record is only meaningful alongside the entry.
        clear_approval();
        Ok(())
    }

    /// Clear a disable recorded by Settings/Task Manager so an enable from
    /// the app takes effect.
    #[cfg(windows)]
    pub fn reenable() {
        clear_approval();
    }

    #[cfg(windows)]
    fn clear_approval() {
        if let Ok(key) = windows_registry::CURRENT_USER.create(STARTUP_APPROVED_KEY)
            && key.get_value(VALUE_NAME).is_ok()
            && let Err(e) = key.remove_value(VALUE_NAME)
        {
            log::debug!(r"Failed to clear HKCU\{STARTUP_APPROVED_KEY}\{VALUE_NAME}: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_runs_the_exe_hidden_and_escapes_the_path() {
        let xml = macos::plist_xml(std::path::Path::new("/Apps/A&B/flextunnel-desktop"));
        assert!(xml.contains("<string>com.flextunnel.desktop</string>"));
        assert!(xml.contains("<string>/Apps/A&amp;B/flextunnel-desktop</string>"));
        assert!(xml.contains(&format!("<string>{LOGIN_ITEM_ARG}</string>")));
        assert!(xml.contains("<key>RunAtLoad</key>\n\t<true/>"));
        assert!(!xml.contains("KeepAlive"));
    }

    #[test]
    fn run_value_quotes_the_exe() {
        let cmd = windows::run_command(std::path::Path::new(r"C:\Program Files\flextunnel\a.exe"));
        assert_eq!(cmd, format!(r#""C:\Program Files\flextunnel\a.exe" {LOGIN_ITEM_ARG}"#));
    }

    #[test]
    fn startup_approval_reads_the_first_byte() {
        assert!(!windows::approval_disabled(&[]));
        assert!(!windows::approval_disabled(&[0x02, 0, 0, 0]));
        assert!(windows::approval_disabled(&[0x03, 0, 0, 0]));
        assert!(!windows::approval_disabled(&[0x06, 0, 0, 0]));
        assert!(windows::approval_disabled(&[0x07, 0, 0, 0]));
    }
}
