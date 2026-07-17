//! Client instance naming.
//!
//! A client *instance* is one running `flextunnel client` process. The
//! instance name — `--instance`, default [`DEFAULT_INSTANCE`] — namespaces
//! every per-instance artifact so multiple clients can run side by side:
//! the single-instance lock (`client-<name>.lock`), the control socket
//! (`client-<name>.sock` / `\\.\pipe\flextunnel-client-<name>`), and the
//! persisted port forwards (`forwards-<name>.json`). It is deliberately a
//! CLI-only concept: the config TOML describes the *profile* (where to
//! connect), not which local slot it runs in.

use anyhow::{Context, Result, bail};
use std::path::PathBuf;

pub const DEFAULT_INSTANCE: &str = "default";

/// Validate an instance name before it is spliced into file/pipe names:
/// nonempty, at most 64 characters, `[A-Za-z0-9_-]` only.
pub fn validate_instance_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("Instance name must not be empty");
    }
    if name.len() > 64 {
        bail!("Instance name is too long (64 characters max)");
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        bail!(
            "Invalid instance name {name:?}: only letters, digits, underscores \
             and hyphens are allowed"
        );
    }
    Ok(())
}

/// The per-user directory holding all per-instance artifacts
/// (`~/.config/flextunnel`), matching the config-file convention in
/// [`flextunnel_core::config`]. Errors if the home dir is unknown — there is
/// deliberately no temp-dir fallback (see `lock.rs`).
pub fn instance_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not determine the home directory")?;
    Ok(home.join(".config").join("flextunnel"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_name_rules() {
        assert!(validate_instance_name("default").is_ok());
        assert!(validate_instance_name("work_2-b").is_ok());
        assert!(validate_instance_name(&"a".repeat(64)).is_ok());

        assert!(validate_instance_name("").is_err());
        assert!(validate_instance_name(&"a".repeat(65)).is_err());
        assert!(validate_instance_name("has space").is_err());
        assert!(validate_instance_name("dot.name").is_err());
        assert!(validate_instance_name("slash/name").is_err());
        assert!(validate_instance_name("../escape").is_err());
    }
}
