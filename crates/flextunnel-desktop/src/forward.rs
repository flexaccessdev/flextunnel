//! Persisted desktop forward definitions and the thin adapter to the core's
//! server-direct listener manager.

use flextunnel_core::proxy::signaling::Target;
use flextunnel_core::proxy::{
    ForwardManager as CoreForwardManager, ForwardSpec, ServerForwarder,
};
use serde::{Deserialize, Serialize};
use tokio::runtime::Handle;

pub use flextunnel_core::proxy::{ForwardState, ForwardStatus};

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
            format!("{}:{}", self.remote_host, self.remote_port)
        } else {
            label.to_string()
        }
    }

    pub fn local_endpoint(&self) -> String {
        format!("localhost:{}", self.local_port)
    }

    pub fn remote_endpoint(&self) -> String {
        format!("{}:{}", self.remote_host, self.remote_port)
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
    }

    #[test]
    fn disabled_forwards_are_not_started() {
        let mut forward = forward();
        forward.enabled = false;
        assert!(enabled_specs(&[forward]).is_empty());
    }
}
