//! Client instance identity.
//!
//! A client *instance* is one running `flextunnel client start` process,
//! identified by its **name**: the `name` in its config, or `default`. The name
//! keys every per-instance artifact — the single-instance lock
//! (`client-<name>.lock`) and the control socket (`client-<name>.sock` /
//! `\\.\pipe\flextunnel-client-<name>`) — so `flextunnel client control` and
//! `flextunnel client nc` find the right running client from the same config,
//! or from `-n <name>` alone.
//!
//! One client reaches any number of servers (its destinations), so a single
//! unnamed client is the common case. Names exist for running several at once
//! — say, two configs with different proxy ports — which each need their own.

use anyhow::{Context, Result, anyhow, bail};
use flextunnel_core::config;
use std::path::{Path, PathBuf};

/// The instance name of a client whose config sets none.
pub const DEFAULT_INSTANCE: &str = "default";

/// Longest instance name. With `~/.config/flextunnel/client-<name>.sock` this
/// keeps the socket path inside macOS's ~104-byte `sun_path` for any ordinary
/// home directory.
const MAX_NAME_LEN: usize = 32;

/// Resolve and validate an instance name: `name` when given, else
/// [`DEFAULT_INSTANCE`]. It becomes part of a file name and a Windows pipe
/// name, so only lowercase letters, digits, `-` and `_` are allowed.
pub fn instance_name(name: Option<&str>) -> Result<String> {
    let Some(name) = name else {
        return Ok(DEFAULT_INSTANCE.to_string());
    };
    let valid = !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    if !valid {
        bail!(
            "client name {name:?} is not usable: it names the lock and the control socket, so \
             it must be 1-{MAX_NAME_LEN} characters of a-z, 0-9, '-' or '_'"
        );
    }
    Ok(name.to_string())
}

/// The per-user directory holding all per-instance artifacts
/// (`~/.config/flextunnel`), matching the config-file convention in
/// [`flextunnel_core::config`]. Errors if the home dir is unknown — there is
/// deliberately no temp-dir fallback (see `lock.rs`).
pub fn instance_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not determine the home directory")?;
    Ok(home.join(".config").join("flextunnel"))
}

/// How an attaching command came by its instance name.
enum Source {
    /// `-n <name>`.
    Flag,
    /// `-c <file>`.
    Config(PathBuf),
    /// The default config file, which exists.
    DefaultConfig(PathBuf),
    /// Neither flag, and no default config: assumed [`DEFAULT_INSTANCE`].
    Assumed,
}

/// A running client as named on the command line of a command that attaches
/// to it (`client control`, `client nc`).
pub struct Located {
    /// The instance name its control socket is named by.
    pub name: String,
    source: Source,
}

/// Identify the running client to attach to: `-n` wins; otherwise the config
/// (`-c`, or the default `~/.config/flextunnel/client.toml` when it exists)
/// gives the name, exactly as it does for the client that was started from it;
/// with neither, the default name.
pub fn locate(config_path: Option<PathBuf>, name: Option<String>) -> Result<Located> {
    if let Some(name) = name {
        return Ok(Located {
            name: instance_name(Some(&name))?,
            source: Source::Flag,
        });
    }
    let default_path = config::default_client_config_path();
    let source = match (&config_path, &default_path) {
        (Some(path), _) => Source::Config(path.clone()),
        (None, Some(path)) if path.exists() => Source::DefaultConfig(path.clone()),
        (None, _) => Source::Assumed,
    };
    let file = config::load_client_config(config_path.as_deref())?;
    let name = instance_name(file.and_then(|f| f.name).as_deref())?;
    Ok(Located { name, source })
}

impl Located {
    /// The error for "nothing is listening for this instance", saying where
    /// the name came from. When it was only assumed — no flag, no default
    /// config, the usual shape where each client's config lives in its own
    /// file — name the configs that *are* there, so the fix is a copy-paste
    /// away.
    pub fn not_running(&self) -> anyhow::Error {
        let name = &self.name;
        match &self.source {
            Source::Flag => anyhow!("The flextunnel client named '{name}' is not running."),
            Source::Config(path) | Source::DefaultConfig(path) => anyhow!(
                "The flextunnel client named '{name}' (from {}) is not running.",
                path.display()
            ),
            Source::Assumed => {
                let mut msg = format!(
                    "The flextunnel client named '{name}' is not running. No -c <file> or \
                     -n <name> was given and there is no default client config, so the \
                     default name was assumed."
                );
                if let Some(path) = config::default_client_config_path()
                    && let Some(dir) = path.parent()
                    && let Some(found) = client_configs(dir)
                {
                    msg.push_str(&format!(
                        "\nConfigs in {}: {} — pass one with -c.",
                        dir.display(),
                        found.join(", ")
                    ));
                }
                anyhow!(msg)
            }
        }
    }
}

/// Config files in the flextunnel config dir that could be a client's, as bare
/// file names, sorted. `None` when there are none (or the directory is
/// unreadable) — the caller then says nothing rather than an empty list.
fn client_configs(dir: &Path) -> Option<Vec<String>> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".toml") && n != "server.toml")
        .collect();
    names.sort();
    (!names.is_empty()).then_some(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_configs_lists_candidate_configs() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "macintel.toml",
            "aws.toml",
            "server.toml",
            "client-default.lock",
            "client.key",
        ] {
            std::fs::write(dir.path().join(name), "").unwrap();
        }
        assert_eq!(
            client_configs(dir.path()).unwrap(),
            ["aws.toml", "macintel.toml"]
        );
    }

    #[test]
    fn no_configs_reports_nothing_to_list() {
        let dir = tempfile::tempdir().unwrap();
        assert!(client_configs(dir.path()).is_none());
        assert!(client_configs(&dir.path().join("missing")).is_none());
    }

    #[test]
    fn names_default_and_are_validated() {
        assert_eq!(instance_name(None).unwrap(), "default");
        for good in ["default", "work", "home-2", "a_b", "0", &"x".repeat(32)] {
            assert_eq!(instance_name(Some(good)).unwrap(), good);
        }
        for bad in [
            "",
            "Work",
            "has space",
            "dot.ted",
            "../escape",
            "slash/y",
            "pipe\\y",
            "ünï",
            &"x".repeat(33),
        ] {
            assert!(instance_name(Some(bad)).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn the_flag_names_the_instance_without_reading_a_config() {
        // The config path does not exist; `-n` must not try to load it.
        let located = locate(
            Some(PathBuf::from("/nonexistent/flextunnel-test.toml")),
            Some("work".to_string()),
        )
        .unwrap();
        assert_eq!(located.name, "work");
        assert!(located.not_running().to_string().contains("'work'"));
        assert!(locate(None, Some("Not Valid".to_string())).is_err());
    }

    #[test]
    fn a_config_names_the_instance() {
        let dir = tempfile::tempdir().unwrap();
        let named = dir.path().join("named.toml");
        std::fs::write(&named, "name = \"home\"\n").unwrap();
        let located = locate(Some(named.clone()), None).unwrap();
        assert_eq!(located.name, "home");
        let msg = located.not_running().to_string();
        assert!(msg.contains("'home'") && msg.contains("named.toml"), "{msg}");

        // No name in the config: the default instance.
        let unnamed = dir.path().join("unnamed.toml");
        std::fs::write(&unnamed, "socks_port = 1080\n").unwrap();
        assert_eq!(locate(Some(unnamed), None).unwrap().name, "default");

        // A config that does not parse is an error, not a silent default.
        let broken = dir.path().join("broken.toml");
        std::fs::write(&broken, "server_node_id = \"abc\"\n").unwrap();
        assert!(locate(Some(broken), None).is_err());
    }
}
