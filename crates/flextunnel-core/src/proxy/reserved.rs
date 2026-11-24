//! The reserved `flextunnel.internal` namespace.
//!
//! `flextunnel.internal` and every `*.flextunnel.internal` subdomain belong to
//! flextunnel itself and are handled by the **client**:
//!
//! * `flextunnel.internal` is the running client's own status endpoint (see
//!   [`super::client_status`]);
//! * `<name>.localhost.flextunnel.internal` is the own loopback of the server
//!   behind the destination called `<name>` (see [`loopback_name`]) — the
//!   one reserved name that is tunneled, as a loopback request;
//! * every other subdomain, including a `*.localhost.flextunnel.internal`
//!   name no destination has, is reserved for future use and answers with an
//!   HTTP 404.
//!
//! The client's own status and those 404s are served locally, without opening
//! any connection. The exceptions are a destination's loopback name and
//! `/servers/<name>/` on the status endpoint, which fetches that destination
//! server's status page; both connect to the destination if it is not
//! connected.
//!
//! The names never reach a server. A client destination may not use one as its
//! host, no `routed_domains` list — a client's or a server's — may name one,
//! and a server rejects them as `[host_aliases]` names (at config resolution)
//! and as stream targets, so no `routed_domains = ["*"]` or alias can capture
//! them.

use super::routed_set::routing_key;

/// The client status host: `http://flextunnel.internal` through a client's
/// proxy returns that client's status page.
pub const STATUS_HOST: &str = "flextunnel.internal";

/// The reserved subdomain suffix (matches `*.flextunnel.internal`).
const RESERVED_SUFFIX: &str = ".flextunnel.internal";

/// The suffix of the destinations' loopback names (see [`loopback_name`]).
const LOOPBACK_SUFFIX: &str = ".localhost.flextunnel.internal";

/// The host that reaches the loopback of the server behind the destination
/// called `name`: `<name>.localhost.flextunnel.internal`.
pub fn loopback_host(name: &str) -> String {
    format!("{name}{LOOPBACK_SUFFIX}")
}

/// The destination name in a loopback host — `machine1` in
/// `machine1.localhost.flextunnel.internal` (case-insensitive, with or
/// without the DNS root dot), lowercased — or `None` for any other host. The
/// name is a single label: `a.b.localhost.flextunnel.internal` is not one.
pub fn loopback_name(host: &str) -> Option<String> {
    let lower = routing_key(host).to_ascii_lowercase();
    let name = lower.strip_suffix(LOOPBACK_SUFFIX)?;
    (!name.is_empty() && !name.contains('.')).then(|| name.to_string())
}

/// True for `flextunnel.internal` and any `*.flextunnel.internal` subdomain
/// (case-insensitive). A bare `.flextunnel.internal` (empty label) does not
/// match, and `flextunnel.internal.evil.com` does not match.
pub fn is_reserved_host(host: &str) -> bool {
    if is_status_host(host) {
        return true;
    }
    let lower = routing_key(host).to_ascii_lowercase();
    // A non-empty subdomain label: strip the suffix and require something left.
    lower
        .strip_suffix(RESERVED_SUFFIX)
        .is_some_and(|label| !label.is_empty())
}

/// True only for the exact status host `flextunnel.internal` (case-insensitive).
pub fn is_status_host(host: &str) -> bool {
    routing_key(host).eq_ignore_ascii_case(STATUS_HOST)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_host_matches_exact_case_insensitive() {
        assert!(is_status_host("flextunnel.internal"));
        assert!(is_status_host("FlexTunnel.Internal"));
        assert!(is_reserved_host("flextunnel.internal"));
        assert!(is_reserved_host("FLEXTUNNEL.INTERNAL"));
        // The root dot names the same host.
        assert!(is_status_host("flextunnel.internal."));
        assert!(is_reserved_host("x.flextunnel.internal."));
        assert!(!is_status_host("x.flextunnel.internal."));
    }

    #[test]
    fn subdomains_are_reserved_but_not_status() {
        assert!(is_reserved_host("status.flextunnel.internal"));
        assert!(is_reserved_host("a.b.flextunnel.internal"));
        assert!(is_reserved_host("Foo.FlexTunnel.Internal"));
        assert!(is_reserved_host("localhost.flextunnel.internal"));
        assert!(!is_status_host("status.flextunnel.internal"));
    }

    #[test]
    fn loopback_names_are_single_labels_under_localhost() {
        assert_eq!(
            loopback_host("machine1"),
            "machine1.localhost.flextunnel.internal"
        );
        assert_eq!(
            loopback_name("machine1.localhost.flextunnel.internal").as_deref(),
            Some("machine1")
        );
        assert_eq!(
            loopback_name("NAS.LocalHost.FlexTunnel.Internal.").as_deref(),
            Some("nas")
        );
        for other in [
            "localhost.flextunnel.internal",
            ".localhost.flextunnel.internal",
            "a.b.localhost.flextunnel.internal",
            "machine1.flextunnel.internal",
            "machine1.localhost",
            "machine1.localhost.flextunnel.internal.evil.com",
        ] {
            assert_eq!(loopback_name(other), None, "{other:?}");
        }
        assert!(is_reserved_host(&loopback_host("machine1")));
    }

    #[test]
    fn non_reserved_hosts_do_not_match() {
        assert!(!is_reserved_host("flextunnel.internal.evil.com"));
        assert!(!is_reserved_host("internal"));
        assert!(!is_reserved_host("example.com"));
        // A bare suffix with no subdomain label must not match.
        assert!(!is_reserved_host(".flextunnel.internal"));
        // Not a subdomain boundary.
        assert!(!is_reserved_host("myflextunnel.internal"));
    }
}
