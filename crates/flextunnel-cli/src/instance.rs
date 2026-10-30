//! Client instance identity.
//!
//! A client *instance* is one running `flextunnel client start` process,
//! identified by the server it connects to: since a profile's `server_node_id` never
//! changes, its prefix keys every per-instance artifact — the single-instance
//! lock (`client-<key>.lock`) and the control socket (`client-<key>.sock` /
//! `\\.\pipe\flextunnel-client-<key>`). There is deliberately no way to
//! override the key:
//! one client per server per user, and `flextunnel client control` finds the
//! right socket from the same config. The optional `name` in the config
//! ("aws", "home network") is display-only.

use anyhow::{Context, Result, anyhow, bail};
use flextunnel_core::config;
use std::path::{Path, PathBuf};

/// How much of the server node id keys the on-disk artifacts. 16 hex chars
/// (64 bits) cannot collide by accident between distinct servers.
const KEY_LEN: usize = 16;

/// Derive the instance key from a profile's server node id: its first
/// [`KEY_LEN`] characters, lowercased. Errors on anything that cannot be a
/// node id (full validation happens when the id is parsed for dialing).
pub fn instance_key(server_node_id: &str) -> Result<String> {
    let id = server_node_id.trim();
    if id.len() < KEY_LEN || !id.bytes().all(|b| b.is_ascii_alphanumeric()) {
        bail!("server_node_id {id:?} does not look like a server EndpointId");
    }
    Ok(id[..KEY_LEN].to_ascii_lowercase())
}

/// The per-user directory holding all per-instance artifacts
/// (`~/.config/flextunnel`), matching the config-file convention in
/// [`flextunnel_core::config`]. Errors if the home dir is unknown — there is
/// deliberately no temp-dir fallback (see `lock.rs`).
pub fn instance_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not determine the home directory")?;
    Ok(home.join(".config").join("flextunnel"))
}

/// A running client as named on the command line of a command that attaches
/// to it (`client control`, `client nc`).
pub struct Located {
    /// The instance key its control socket is named by.
    pub key: String,
    /// The profile's display name, or `server <key>…` when it has none.
    pub profile: String,
}

/// Identify the running client to attach to: `-n` wins over the config file,
/// and with neither a bare `command` reads the default config, deriving the
/// same instance key as the client's. With `-n` and no `-c`, identify purely
/// by server id (no config load).
pub fn locate(
    config_path: Option<PathBuf>,
    server_node_id: Option<String>,
    command: &str,
) -> Result<Located> {
    let file = if server_node_id.is_some() && config_path.is_none() {
        None
    } else {
        config::load_client_config(config_path.as_deref())?
    };
    let cli = config::ClientConfig {
        server_node_id,
        ..Default::default()
    };
    let r = config::resolve_client(cli, file);
    let Some(server_id) = r.server_node_id else {
        return Err(no_profile_error(config_path.as_deref(), command));
    };
    let key = instance_key(&server_id)?;
    let profile = r.name.unwrap_or_else(|| format!("server {key}…"));
    Ok(Located { key, profile })
}

/// The error for an attaching `command` that has nothing to identify a client
/// by. The two cases read very differently and want different fixes: a config
/// file that exists but carries no `server_node_id`, versus no config file at
/// all — the usual shape under the systemd template (see `docs/systemd.md`),
/// where every profile lives in its own `<instance>.toml` and there is no
/// `client.toml` for a bare command to find. In that case name the profiles
/// that *are* there, so the fix is a copy-paste away.
fn no_profile_error(config_path: Option<&Path>, command: &str) -> anyhow::Error {
    if let Some(path) = config_path {
        return anyhow!(
            "The client config {} has no server_node_id, so it does not say which client to \
             attach to. Set server_node_id in it, or pass -n <server EndpointId>.",
            path.display()
        );
    }
    let Some(default_path) = config::default_client_config_path() else {
        return anyhow!(
            "Could not determine the default config directory. Pass -c <file> or \
             -n <server EndpointId>."
        );
    };
    if default_path.exists() {
        return anyhow!(
            "The default client config {} has no server_node_id, so it does not say which \
             client to attach to. Set server_node_id in it, pass -c <file> for another \
             profile, or pass -n <server EndpointId>.",
            default_path.display()
        );
    }
    let mut msg = format!(
        "There is no client config at {}, so `{command}` has no profile to attach to. \
         Pass the profile's config with -c <file>, or attach by server id with \
         -n <server EndpointId>.",
        default_path.display()
    );
    if let Some(dir) = default_path.parent()
        && let Some(found) = profile_configs(dir)
    {
        msg.push_str(&format!("\nProfiles in {}: {}", dir.display(), found.join(", ")));
    }
    anyhow!(msg)
}

/// Config files in the flextunnel config dir that could be a client profile,
/// as bare file names, sorted. `None` when there are none (or the directory is
/// unreadable) — the caller then says nothing rather than an empty list.
fn profile_configs(dir: &Path) -> Option<Vec<String>> {
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
    fn profile_configs_lists_candidate_client_configs() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "macintel.toml",
            "aws.toml",
            "server.toml",
            "client-abc.lock",
            "client.key",
        ] {
            std::fs::write(dir.path().join(name), "").unwrap();
        }
        assert_eq!(
            profile_configs(dir.path()).unwrap(),
            ["aws.toml", "macintel.toml"]
        );
    }

    #[test]
    fn no_profiles_reports_nothing_to_list() {
        let dir = tempfile::tempdir().unwrap();
        assert!(profile_configs(dir.path()).is_none());
        assert!(profile_configs(&dir.path().join("missing")).is_none());
    }

    #[test]
    fn a_named_config_without_a_server_id_names_that_file() {
        let msg = no_profile_error(Some(Path::new("/tmp/aws.toml")), "client nc").to_string();
        assert!(msg.contains("/tmp/aws.toml"), "{msg}");
        assert!(msg.contains("server_node_id"), "{msg}");
    }

    #[test]
    fn key_is_a_lowercased_prefix() {
        let id = "62E463A6D67FDEACc65e97464b2b51d7362e00436a8b81477a9cea46b11228ca";
        assert_eq!(instance_key(id).unwrap(), "62e463a6d67fdeac");
        assert_eq!(instance_key(&format!("  {id} ")).unwrap(), "62e463a6d67fdeac");
    }

    #[test]
    fn malformed_ids_are_rejected() {
        assert!(instance_key("").is_err());
        assert!(instance_key("short").is_err());
        assert!(instance_key("../escape/../../etc/passwd0000000").is_err());
        assert!(instance_key("62e463a6 67fdeacc65e97464b2b51d7").is_err());
    }
}
