//! Deterministic, one-way **network machine id** for agents.
//!
//! An agent is identified to the server by a stable machine id. The raw OS id
//! (`/etc/machine-id`, `IOPlatformUUID`, `MachineGuid`) is a sensitive host
//! identifier, so it must never travel on the network. Instead the agent derives
//! a hash of it — the *network id* — and that is what appears in the handshake,
//! in the server's `[agent_routes]`, in logs, and in the blocklist. The server
//! treats the value as an opaque identity string, so it never learns the raw id.
//!
//! The value carries a **version identifier outside the hash** (the `1` in the
//! `ftm1` prefix), so the derivation scheme can change later (`ftm2…`) without
//! v1/v2 values ever colliding, and without versioning the hashed bytes.
//!
//! Format: `ftm` + `VERSION` + base64url-nopad(first 16 bytes of
//! `SHA-256(DOMAIN_SEP ++ raw_machine_id)`), e.g. `ftm1aGVsbG9tYWNoaWQx`.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

/// Type prefix, mirroring the `ftc`/`fta` auth-token convention in [`crate::auth`].
pub const NETWORK_ID_TYPE: &str = "ftm";

/// Derivation-scheme version. Lives **outside** the hash (in the prefix), so it
/// is the single, parseable source of truth for the scheme; bump it if the hash,
/// truncation, or encoding ever changes.
pub const NETWORK_ID_VERSION: u8 = 1;

/// Domain-separation tag mixed into the hash input so a network id can't match
/// another system's plain SHA-256 of the same machine id. Intentionally *not*
/// versioned — the version lives in the prefix, not the digest.
const DOMAIN_SEP: &[u8] = b"flextunnel-agent-machine-id\0";

/// Bytes of hash output kept (128 bits). Ample collision resistance for a
/// misconfiguration guard rail while keeping the value short (~26 chars).
const DIGEST_BYTES: usize = 16;

/// Derive the network machine id from a raw OS machine id. Deterministic: the
/// same `raw` always yields the same value.
pub fn network_machine_id(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_SEP);
    hasher.update(raw.as_bytes());
    let digest = hasher.finalize();
    let body = URL_SAFE_NO_PAD.encode(&digest[..DIGEST_BYTES]);
    format!("{NETWORK_ID_TYPE}{NETWORK_ID_VERSION}{body}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_deterministic() {
        assert_eq!(network_machine_id("abc-123"), network_machine_id("abc-123"));
    }

    #[test]
    fn distinct_inputs_differ() {
        assert_ne!(network_machine_id("machine-a"), network_machine_id("machine-b"));
    }

    #[test]
    fn has_versioned_prefix() {
        let id = network_machine_id("anything");
        assert!(id.starts_with("ftm1"), "unexpected id: {id}");
        // 4-char prefix + base64url of 16 bytes (no padding) = 4 + 22 = 26 chars.
        assert_eq!(id.len(), 26, "unexpected length: {id}");
    }

    #[test]
    fn known_answer_vector() {
        // Pins the scheme so an accidental change to hashing/truncation/encoding
        // (which would silently break every operator's [agent_routes]) fails here.
        assert_eq!(network_machine_id("test-machine-id"), "ftm1HKpypPhTDNLCtMS6MZjxYQ");
    }
}
