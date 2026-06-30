//! Destination whitelist shared by the client and server.
//!
//! A whitelist is the *tunnel set*: the destinations that are allowed to
//! traverse the QUIC tunnel. The client uses it to decide per-connection
//! whether to tunnel a target or connect directly from the device
//! (split-tunneling); the server uses the same rules to reject any tunnel
//! request for a target that is not on the list (defense in depth). For both
//! roles the lists should be kept in sync.
//!
//! Two independent lists are matched against the requested [`Target`] *as
//! presented* — a [`Target::Domain`] is only ever matched against domain rules
//! and a [`Target::Ip`] only against CIDR rules (no post-DNS re-check):
//!
//! * **Domains** — explicit-wildcard matching. A bare `example.com` matches that
//!   host exactly; a `*.example.com` entry matches any subdomain
//!   (`api.example.com`, `a.b.example.com`) but **not** the apex `example.com`.
//!   Matching is case-insensitive.
//! * **CIDRs** — an IP target matches if it falls in any configured network. A
//!   bare IP (`192.168.1.5`) is accepted as a single-host network (`/32`/`/128`).
//!
//! An empty whitelist is **inactive** ([`Whitelist::is_active`] is `false`),
//! which preserves the no-whitelist behavior: the client tunnels everything and
//! the server allows everything.

use crate::proxy::signaling::Target;
use anyhow::{Context, Result, bail};
use ipnetwork::IpNetwork;
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

/// A parsed destination whitelist (the tunnel set). See the module docs.
#[derive(Debug, Default, Clone)]
pub struct Whitelist {
    /// Exact domain names, lowercased.
    domains_exact: HashSet<String>,
    /// Suffixes from `*.example.com` entries, stored *with* the leading dot
    /// (`.example.com`) so a suffix match excludes the bare apex.
    domains_suffix: Vec<String>,
    /// Allowed networks (bare IPs are stored as single-host networks).
    cidrs: Vec<IpNetwork>,
}

impl Whitelist {
    /// Build a whitelist from raw config strings. Returns an error (with the
    /// offending entry) on a malformed domain pattern or CIDR so bad config
    /// fails loudly at startup.
    pub fn new(domains: &[String], cidrs: &[String]) -> Result<Self> {
        let mut domains_exact = HashSet::new();
        let mut domains_suffix = Vec::new();
        for raw in domains {
            let entry = raw.trim();
            if let Some(suffix) = entry.strip_prefix("*.") {
                // The remainder after `*.` must be a single valid domain: one or
                // more non-empty, wildcard-free labels. This rejects broken
                // patterns like `*.*.example.com` or `*..example.com` that would
                // otherwise become dead rules matching nothing.
                if suffix.contains('*') || suffix.split('.').any(str::is_empty) {
                    bail!("invalid whitelist wildcard pattern: {raw:?}");
                }
                domains_suffix.push(format!(".{}", suffix.to_ascii_lowercase()));
            } else if entry.is_empty() || entry.contains('*') {
                bail!("invalid whitelist domain pattern: {raw:?}");
            } else {
                domains_exact.insert(entry.to_ascii_lowercase());
            }
        }

        let mut nets = Vec::with_capacity(cidrs.len());
        for raw in cidrs {
            let entry = raw.trim();
            // Accept both `a.b.c.d/n` and a bare `a.b.c.d` (single host).
            let net = IpNetwork::from_str(entry)
                .or_else(|_| IpAddr::from_str(entry).map(IpNetwork::from))
                .with_context(|| format!("invalid whitelist CIDR: {raw:?}"))?;
            nets.push(net);
        }

        Ok(Self {
            domains_exact,
            domains_suffix,
            cidrs: nets,
        })
    }

    /// Whether any rule is configured. An inactive whitelist matches nothing and
    /// callers treat it as "no filtering" (client tunnels all, server allows all).
    pub fn is_active(&self) -> bool {
        !self.domains_exact.is_empty() || !self.domains_suffix.is_empty() || !self.cidrs.is_empty()
    }

    /// Whether `target` is on the whitelist (i.e. should be tunneled / allowed).
    /// A domain is matched only against domain rules, an IP only against CIDRs.
    pub fn allows(&self, target: &Target) -> bool {
        match target {
            Target::Domain(host, _) => self.allows_domain(host),
            Target::Ip(sa) => self.cidrs.iter().any(|net| net.contains(sa.ip())),
        }
    }

    fn allows_domain(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        self.domains_exact.contains(&host)
            || self
                .domains_suffix
                .iter()
                .any(|suffix| host.ends_with(suffix.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wl(domains: &[&str], cidrs: &[&str]) -> Whitelist {
        let d: Vec<String> = domains.iter().map(|s| s.to_string()).collect();
        let c: Vec<String> = cidrs.iter().map(|s| s.to_string()).collect();
        Whitelist::new(&d, &c).expect("valid whitelist")
    }

    fn domain(h: &str) -> Target {
        Target::Domain(h.to_string(), 443)
    }

    fn ip(s: &str) -> Target {
        Target::Ip(format!("{s}:443").parse().unwrap())
    }

    #[test]
    fn empty_is_inactive_and_allows_nothing() {
        let w = Whitelist::default();
        assert!(!w.is_active());
        assert!(!w.allows(&domain("example.com")));
        assert!(!w.allows(&ip("1.2.3.4")));
    }

    #[test]
    fn exact_domain_matches_only_itself() {
        let w = wl(&["example.com"], &[]);
        assert!(w.is_active());
        assert!(w.allows(&domain("example.com")));
        assert!(!w.allows(&domain("api.example.com")));
        assert!(!w.allows(&domain("notexample.com")));
    }

    #[test]
    fn wildcard_matches_subdomains_not_apex() {
        let w = wl(&["*.example.com"], &[]);
        assert!(w.allows(&domain("api.example.com")));
        assert!(w.allows(&domain("a.b.example.com")));
        assert!(!w.allows(&domain("example.com")));
        assert!(!w.allows(&domain("example.com.evil.com")));
        assert!(!w.allows(&domain("notexample.com")));
    }

    #[test]
    fn matching_is_case_insensitive() {
        let w = wl(&["Example.COM", "*.Internal.Corp"], &[]);
        assert!(w.allows(&domain("EXAMPLE.com")));
        assert!(w.allows(&domain("API.Internal.CORP")));
    }

    #[test]
    fn cidr_and_bare_ip() {
        let w = wl(&[], &["10.0.0.0/8", "192.168.1.5"]);
        assert!(w.allows(&ip("10.1.2.3")));
        assert!(!w.allows(&ip("11.0.0.1")));
        assert!(w.allows(&ip("192.168.1.5")));
        assert!(!w.allows(&ip("192.168.1.6")));
    }

    #[test]
    fn ipv6_cidr() {
        let w = wl(&[], &["fd00::/8"]);
        assert!(w.allows(&ip("[fd00::1]")));
        assert!(!w.allows(&ip("[fe80::1]")));
    }

    #[test]
    fn domains_and_ips_match_separate_lists() {
        let w = wl(&["example.com"], &["10.0.0.0/8"]);
        // A domain is never matched against CIDRs, and vice versa.
        assert!(!w.allows(&domain("10.0.0.1")));
        assert!(!w.allows(&ip("1.2.3.4")));
    }

    #[test]
    fn rejects_bad_patterns() {
        assert!(Whitelist::new(&["*.".to_string()], &[]).is_err());
        assert!(Whitelist::new(&["a*b.com".to_string()], &[]).is_err());
        assert!(Whitelist::new(&["*.*.example.com".to_string()], &[]).is_err());
        assert!(Whitelist::new(&["*..example.com".to_string()], &[]).is_err());
        assert!(Whitelist::new(&[], &["not-a-cidr".to_string()]).is_err());
    }
}
