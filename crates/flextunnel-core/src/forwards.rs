//! Persisted port-forward definitions shared by the desktop and CLI clients,
//! plus the thin adapter to the core's server-direct listener manager and the
//! validation rules both UIs apply to user input.

use crate::proxy::signaling::Target;
use crate::proxy::{ForwardManager as CoreForwardManager, ForwardSpec, ServerForwarder};
use serde::{Deserialize, Serialize};
use tokio::runtime::Handle;

pub use crate::proxy::{ForwardState, ForwardStatus};

/// One configured forward: `localhost:local_port` →
/// `remote_host:remote_port`, opened directly on the authenticated server
/// connection. The server enforces its routed-set whitelist and resolves names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortForward {
    pub id: String,
    #[serde(default)]
    pub label: String,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
    /// Runtime-only session state: never persisted.
    #[serde(skip)]
    pub enabled: bool,
}

impl PortForward {
    pub fn new_id() -> String {
        format!("{:016x}", rand::random::<u64>())
    }

    pub fn display_name(&self) -> String {
        let label = self.label.trim();
        if label.is_empty() {
            self.remote_endpoint()
        } else {
            label.to_string()
        }
    }

    pub fn local_endpoint(&self) -> String {
        format!("localhost:{}", self.local_port)
    }

    pub fn remote_endpoint(&self) -> String {
        format_host_port(&self.remote_host, self.remote_port)
    }

    fn spec(&self) -> ForwardSpec {
        ForwardSpec {
            id: self.id.clone(),
            local_port: self.local_port,
            // Keep the host as a name end-to-end. RoutedSet recognizes
            // IP-looking domain strings, while the server remains responsible
            // for aliases and DNS resolution.
            target: Target::Domain(self.remote_host.clone(), self.remote_port),
        }
    }
}

/// Enabled-only façade over the core listener manager: callers hand it the
/// whole forward list and it starts/stops listeners to match the enabled subset.
pub struct ForwardManager {
    inner: CoreForwardManager,
}

impl ForwardManager {
    pub fn new(runtime: Handle, forwarder: ServerForwarder, forwards: &[PortForward]) -> Self {
        Self {
            inner: CoreForwardManager::new(runtime, forwarder, &enabled_specs(forwards)),
        }
    }

    pub fn apply(&mut self, forwards: &[PortForward]) {
        self.inner.apply(&enabled_specs(forwards));
    }

    pub fn statuses(&self) -> Vec<ForwardStatus> {
        self.inner.statuses()
    }
}

fn enabled_specs(forwards: &[PortForward]) -> Vec<ForwardSpec> {
    forwards
        .iter()
        .filter(|forward| forward.enabled)
        .map(PortForward::spec)
        .collect()
}

/// Render a `host:port` endpoint unambiguously: bare IPv6 addresses (stored
/// bracket-less — see [`validate_remote_host`]) get brackets back so the port
/// separator can't be confused with the address's own colons.
pub fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Maximum label length accepted by [`validate_label`], in characters.
pub const MAX_LABEL_LEN: usize = 64;

/// Validate a forward's display label (returns the trimmed form to store).
pub fn validate_label(input: &str) -> Result<String, String> {
    let label = input.trim();
    if label.chars().count() > MAX_LABEL_LEN {
        return Err(format!("Label must be {MAX_LABEL_LEN} characters or fewer"));
    }
    Ok(label.to_string())
}

pub fn parse_port(input: &str, what: &str) -> Result<u16, String> {
    input
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| format!("{what} must be 1-65535"))
}

/// Validate a forward's remote host — an IP literal (IPv4, IPv6, `[IPv6]`) or
/// a hostname — returning the normalized form to store (brackets stripped so
/// the wire sees a bare address). Hostname rules are deliberately permissive
/// (underscores allowed for internal names) but catch real typos: empty
/// labels (`a..b`, leading/trailing dots), bad characters, oversized labels.
pub fn validate_remote_host(input: &str) -> Result<String, String> {
    let host = input.trim();
    if host.is_empty() {
        return Err("Remote host is required".into());
    }
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if bare.parse::<std::net::IpAddr>().is_ok() {
        return Ok(bare.to_string());
    }
    // SOCKS5 ATYP_DOMAIN caps the name at 255 bytes; DNS at 253.
    if host.len() > 253 {
        return Err("Remote host is too long (253 characters max)".into());
    }
    for label in host.split('.') {
        if label.is_empty() {
            return Err("Remote host has an empty label — check the dots".into());
        }
        if label.len() > 63 {
            return Err("Remote host has a label longer than 63 characters".into());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("Remote host labels can't start or end with a hyphen".into());
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(
                "Remote host may only contain letters, digits, dots, hyphens and underscores"
                    .into(),
            );
        }
    }
    Ok(host.to_string())
}

/// Enable/disable semantics for the per-forward switch: a forward whose initial
/// setup failed (its listener could not bind — e.g. the local port is in use)
/// is flipped back off instead of sitting enabled-but-failed. `Failed` is only
/// ever set at bind time (see `forward::run_forward`), so every failed status
/// is a setup failure. Returns the `(id, reason)` pairs of the forwards
/// disabled, for display next to their rows.
pub fn disable_failed_forwards(
    forwards: &mut [PortForward],
    statuses: &[ForwardStatus],
) -> Vec<(String, String)> {
    let mut disabled = Vec::new();
    for status in statuses {
        if let ForwardState::Failed(reason) = &status.state
            && let Some(forward) = forwards
                .iter_mut()
                .find(|f| f.id == status.id && f.enabled)
        {
            forward.enabled = false;
            disabled.push((forward.id.clone(), reason.clone()));
        }
    }
    disabled
}

#[cfg(test)]
mod tests {
    use super::*;

    fn forward() -> PortForward {
        PortForward {
            id: PortForward::new_id(),
            label: String::new(),
            local_port: 8080,
            remote_host: "echo.internal".into(),
            remote_port: 7,
            enabled: true,
        }
    }

    #[test]
    fn names_descriptions_and_server_target() {
        let mut forward = forward();
        assert_eq!(forward.display_name(), "echo.internal:7");
        assert_eq!(forward.local_endpoint(), "localhost:8080");
        assert_eq!(forward.remote_endpoint(), "echo.internal:7");
        assert_eq!(
            forward.spec().target,
            Target::Domain("echo.internal".into(), 7)
        );
        forward.label = "  echo  ".into();
        assert_eq!(forward.display_name(), "echo");

        // Bare IPv6 hosts render bracketed so the port stays unambiguous.
        forward.label = String::new();
        forward.remote_host = "2001:db8::1".into();
        assert_eq!(forward.remote_endpoint(), "[2001:db8::1]:7");
        assert_eq!(forward.display_name(), "[2001:db8::1]:7");
        assert_eq!(format_host_port("10.0.0.7", 80), "10.0.0.7:80");
    }

    #[test]
    fn disabled_forwards_are_not_started() {
        let mut forward = forward();
        forward.enabled = false;
        assert!(enabled_specs(&[forward]).is_empty());
    }

    #[test]
    fn enabled_is_never_persisted() {
        let json = serde_json::to_string(&forward()).unwrap();
        assert!(!json.contains("enabled"), "{json}");
        let restored: PortForward = serde_json::from_str(&json).unwrap();
        assert!(!restored.enabled);
    }

    #[test]
    fn failed_forwards_are_disabled_with_reason() {
        let mut forwards = vec![forward()];
        let statuses = vec![ForwardStatus {
            id: forwards[0].id.clone(),
            state: ForwardState::Failed("port in use".into()),
            active: 0,
            last_conn_error: None,
        }];
        let disabled = disable_failed_forwards(&mut forwards, &statuses);
        assert_eq!(disabled, vec![(forwards[0].id.clone(), "port in use".into())]);
        assert!(!forwards[0].enabled);
        // A second pass is a no-op: the forward is no longer enabled.
        assert!(disable_failed_forwards(&mut forwards, &statuses).is_empty());
    }

    #[test]
    fn listening_forwards_stay_enabled() {
        let mut forwards = vec![forward()];
        let statuses = vec![ForwardStatus {
            id: forwards[0].id.clone(),
            state: ForwardState::Listening,
            active: 1,
            last_conn_error: None,
        }];
        assert!(disable_failed_forwards(&mut forwards, &statuses).is_empty());
        assert!(forwards[0].enabled);
    }

    #[test]
    fn remote_host_rules() {
        assert_eq!(validate_remote_host(" db.internal "), Ok("db.internal".into()));
        assert_eq!(
            validate_remote_host("net_dev-1.example.com"),
            Ok("net_dev-1.example.com".into())
        );
        assert_eq!(validate_remote_host("10.0.0.7"), Ok("10.0.0.7".into()));
        assert_eq!(validate_remote_host("::1"), Ok("::1".into()));
        assert_eq!(validate_remote_host("[2001:db8::1]"), Ok("2001:db8::1".into()));

        assert!(validate_remote_host("networking..internal").is_err());
        assert!(validate_remote_host(".internal").is_err());
        assert!(validate_remote_host("internal.").is_err());
        assert!(validate_remote_host("").is_err());
        assert!(validate_remote_host("has space.com").is_err());
        assert!(validate_remote_host("bad!char.com").is_err());
        assert!(validate_remote_host("-leading.com").is_err());
        assert!(validate_remote_host("trailing-.com").is_err());
        assert!(validate_remote_host(&"a".repeat(64)).is_err());
        assert!(validate_remote_host(&format!("{}.com", "a.".repeat(130))).is_err());
    }

    #[test]
    fn port_and_label_rules() {
        assert_eq!(parse_port(" 8080 ", "Local port"), Ok(8080));
        assert!(parse_port("0", "Local port").is_err());
        assert!(parse_port("65536", "Local port").is_err());
        assert!(parse_port("", "Local port").is_err());

        assert_eq!(validate_label("  db  "), Ok("db".into()));
        assert!(validate_label(&"a".repeat(65)).is_err());
        // The cap counts characters, not UTF-8 bytes.
        assert!(validate_label(&"é".repeat(64)).is_ok());
        assert!(validate_label(&"é".repeat(65)).is_err());
    }
}
