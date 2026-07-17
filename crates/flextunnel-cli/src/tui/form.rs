//! Add/edit buffers for one port forward, mirroring the desktop's form: the
//! same core validators run here for instant feedback, while the running
//! client re-validates authoritatively on apply.

use flextunnel_core::forwards::{parse_port, validate_label, validate_remote_host};

use crate::ipc::{ForwardRow, WireForward};

/// Order of the focusable fields.
pub const FIELDS: usize = 5;
pub const FIELD_LABEL: usize = 0;
pub const FIELD_LOCAL_PORT: usize = 1;
pub const FIELD_REMOTE_HOST: usize = 2;
pub const FIELD_REMOTE_PORT: usize = 3;
pub const FIELD_ENABLED: usize = 4;

pub struct FormState {
    /// `None` when adding; the id being edited otherwise.
    pub editing_id: Option<String>,
    pub label: String,
    pub local_port: String,
    pub remote_host: String,
    pub remote_port: String,
    pub enabled: bool,
    pub focus: usize,
    pub error: Option<String>,
}

impl FormState {
    pub fn add() -> Self {
        Self {
            editing_id: None,
            label: String::new(),
            local_port: String::new(),
            remote_host: String::new(),
            remote_port: String::new(),
            enabled: true,
            focus: FIELD_LABEL,
            error: None,
        }
    }

    pub fn edit(forward: &WireForward) -> Self {
        Self {
            editing_id: Some(forward.id.clone()),
            label: forward.label.clone(),
            local_port: forward.local_port.to_string(),
            remote_host: forward.remote_host.clone(),
            remote_port: forward.remote_port.to_string(),
            enabled: forward.enabled,
            focus: FIELD_LABEL,
            error: None,
        }
    }

    pub fn is_edit(&self) -> bool {
        self.editing_id.is_some()
    }

    pub fn focus_next(&mut self) {
        self.focus = (self.focus + 1) % FIELDS;
    }

    pub fn focus_prev(&mut self) {
        self.focus = (self.focus + FIELDS - 1) % FIELDS;
    }

    pub fn focused_text(&mut self) -> Option<&mut String> {
        match self.focus {
            FIELD_LABEL => Some(&mut self.label),
            FIELD_LOCAL_PORT => Some(&mut self.local_port),
            FIELD_REMOTE_HOST => Some(&mut self.remote_host),
            FIELD_REMOTE_PORT => Some(&mut self.remote_port),
            _ => None,
        }
    }

    /// Validate against the latest snapshot's forward list (local-port
    /// uniqueness excludes the forward being edited). On success returns the
    /// wire forward to submit — with an empty id on add; the running client
    /// assigns one.
    pub fn validate(&self, forwards: &[ForwardRow]) -> Result<WireForward, String> {
        let label = validate_label(&self.label)?;
        let local_port = parse_port(&self.local_port, "Local port")?;
        let remote_host = validate_remote_host(&self.remote_host)?;
        let remote_port = parse_port(&self.remote_port, "Remote port")?;
        if let Some(row) = forwards
            .iter()
            .filter(|r| Some(r.forward.id.as_str()) != self.editing_id.as_deref())
            .find(|r| r.forward.local_port == local_port)
        {
            return Err(format!(
                "Local port {local_port} is already used by {}",
                display_name(&row.forward)
            ));
        }
        Ok(WireForward {
            id: self.editing_id.clone().unwrap_or_default(),
            label,
            local_port,
            remote_host,
            remote_port,
            enabled: self.enabled,
        })
    }
}

/// Label if set, otherwise `host:port` — mirrors `PortForward::display_name`.
pub fn display_name(forward: &WireForward) -> String {
    let label = forward.label.trim();
    if label.is_empty() {
        flextunnel_core::forwards::format_host_port(&forward.remote_host, forward.remote_port)
    } else {
        label.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::ForwardRowState;

    fn row(id: &str, local_port: u16) -> ForwardRow {
        ForwardRow {
            forward: WireForward {
                id: id.into(),
                label: String::new(),
                local_port,
                remote_host: "other.internal".into(),
                remote_port: 80,
                enabled: false,
            },
            state: ForwardRowState::Stopped,
            error: None,
            active: 0,
            last_conn_error: None,
        }
    }

    fn filled() -> FormState {
        FormState {
            editing_id: None,
            label: " db ".into(),
            local_port: " 5432 ".into(),
            remote_host: " db.internal ".into(),
            remote_port: "5432".into(),
            enabled: true,
            focus: 0,
            error: None,
        }
    }

    #[test]
    fn validates_and_trims() {
        let wire = filled().validate(&[row("a", 9999)]).expect("valid");
        assert_eq!(wire.id, "");
        assert_eq!(wire.label, "db");
        assert_eq!(wire.local_port, 5432);
        assert_eq!(wire.remote_host, "db.internal");
        assert!(wire.enabled);
    }

    #[test]
    fn rejects_taken_port_except_own() {
        let mut form = filled();
        assert!(form.validate(&[row("a", 5432)]).is_err());
        form.editing_id = Some("a".into());
        assert!(form.validate(&[row("a", 5432)]).is_ok());
    }

    #[test]
    fn focus_cycles() {
        let mut form = filled();
        for _ in 0..FIELDS {
            form.focus_next();
        }
        assert_eq!(form.focus, 0);
        form.focus_prev();
        assert_eq!(form.focus, FIELDS - 1);
    }
}
