//! Destination routed set shared by the client and server.
//!
//! A routed set is the *tunnel set*: the destinations that are routed through
//! the QUIC tunnel. The client uses it to decide per-connection whether to
//! tunnel a target or connect directly from the device (split-tunneling);
//! targets not on the set are **not** rejected client-side, they fall back to a
//! direct connection. The server, by contrast, enforces the same rules as a
//! **whitelist**: it rejects any tunnel request for a target that is not on the
//! set (defense in depth). For both roles the lists should be kept in sync.
//!
//! Two independent lists are matched against the requested [`Target`]. A
//! *hostname* is matched only against domain rules and an *IP* only against CIDR
//! rules. A numeric IP literal that arrives in domain form ([`Target::Domain`]
//! via SOCKS5 `ATYP_DOMAIN`) is recognized as an IP and gated by the CIDR rules
//! too — so it can't slip past a narrow CIDR set by masquerading as a hostname.
//! There is no post-DNS re-check: a genuine hostname that later resolves to an
//! IP is still matched only against the domain rules.
//!
//! * **Domains** — explicit-wildcard matching. A bare `example.com` matches that
//!   host exactly; a `*.example.com` entry matches any subdomain
//!   (`api.example.com`, `a.b.example.com`) but **not** the apex `example.com`; a
//!   lone `*` matches *every hostname* (the full-tunnel catch-all). Domain rules
//!   match hostnames only — an IP literal sent in domain form is gated by the
//!   CIDRs, never by `*`. Matching is case-insensitive.
//! * **CIDRs** — an IP target matches if it falls in any configured network. A
//!   bare IP (`192.168.1.5`) is accepted as a single-host network (`/32`/`/128`);
//!   a default route (`0.0.0.0/0` / `::/0`) matches every IP of its family.
//!
//! The routed set is a VPN-style split-tunnel "included routes" set and is
//! **required** — an empty routed set is rejected upstream (server startup /
//! client handshake), never treated as "tunnel everything". To tunnel *all*
//! traffic, use the catch-alls: `*` for hostnames and `0.0.0.0/0` (+ `::/0`) for
//! IPs.

use crate::proxy::signaling::Target;
use anyhow::{Context, Result, bail};
use ipnetwork::IpNetwork;
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

/// A parsed destination routed set (the tunnel set). See the module docs.
#[derive(Debug, Default, Clone)]
pub struct RoutedSet {
    /// Exact domain names, lowercased.
    domains_exact: HashSet<String>,
    /// Suffixes from `*.example.com` entries, stored *with* the leading dot
    /// (`.example.com`) so a suffix match excludes the bare apex.
    domains_suffix: Vec<String>,
    /// Routed networks (bare IPs are stored as single-host networks). A default
    /// route (`0.0.0.0/0` / `::/0`) naturally contains every IP of its family.
    cidrs: Vec<IpNetwork>,
    /// Set by a lone `*` domain entry — the full-tunnel catch-all for hostnames
    /// (browser CONNECTs arrive as domains, never CIDRs, so this is what tunnels
    /// all web traffic).
    domains_all: bool,
}

impl RoutedSet {
    /// Build a routed set from raw config strings. Returns an error (with the
    /// offending entry) on a malformed domain pattern or CIDR so bad config
    /// fails loudly at startup.
    pub fn new(domains: &[String], cidrs: &[String]) -> Result<Self> {
        let mut domains_exact = HashSet::new();
        let mut domains_suffix = Vec::new();
        let mut domains_all = false;
        for raw in domains {
            let entry = raw.trim();
            if entry == "*" {
                // Full-tunnel catch-all: match every hostname.
                domains_all = true;
            } else if let Some(suffix) = entry.strip_prefix("*.") {
                // The remainder after `*.` must be a single valid domain: one or
                // more non-empty, wildcard-free labels. This rejects broken
                // patterns like `*.*.example.com` or `*..example.com` that would
                // otherwise become dead rules matching nothing.
                if suffix.contains('*') || suffix.split('.').any(str::is_empty) {
                    bail!("invalid routed-domain wildcard pattern: {raw:?}");
                }
                domains_suffix.push(format!(".{}", suffix.to_ascii_lowercase()));
            } else if entry.is_empty() || entry.contains('*') {
                bail!("invalid routed-domain pattern: {raw:?}");
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
                .with_context(|| format!("invalid routed CIDR: {raw:?}"))?;
            nets.push(net);
        }

        Ok(Self {
            domains_exact,
            domains_suffix,
            cidrs: nets,
            domains_all,
        })
    }

    /// Whether no rule is configured. The routed set is required (a VPN-style
    /// tunnel set), so callers reject an empty one upstream rather than treating
    /// it as "no filtering".
    pub fn is_empty(&self) -> bool {
        !self.domains_all
            && self.domains_exact.is_empty()
            && self.domains_suffix.is_empty()
            && self.cidrs.is_empty()
    }

    /// Whether `target` is in the routed set (i.e. should be tunneled). A
    /// hostname is matched against the domain rules (with `*` matching every
    /// hostname); an IP — whether presented as [`Target::Ip`] or as a numeric
    /// [`Target::Domain`] — is matched against the CIDRs (with `0.0.0.0/0` /
    /// `::/0` matching all).
    pub fn allows(&self, target: &Target) -> bool {
        match target {
            Target::Domain(host, _) => self.allows_host(host),
            Target::Ip(sa) => self.allows_ip(sa.ip()),
        }
    }

    /// Match a host string from a domain-form target. A numeric IP literal
    /// (including a bracketed IPv6 form like `[::1]`) is gated by the CIDR rules
    /// rather than the domain rules, so `*` and other hostname rules never let an
    /// IP through in domain form.
    fn allows_host(&self, host: &str) -> bool {
        if let Some(ip) = parse_ip_literal(host) {
            return self.allows_ip(ip);
        }
        if self.domains_all {
            return true;
        }
        let host = host.to_ascii_lowercase();
        self.domains_exact.contains(&host)
            || self
                .domains_suffix
                .iter()
                .any(|suffix| host.ends_with(suffix.as_str()))
    }

    fn allows_ip(&self, ip: IpAddr) -> bool {
        self.cidrs.iter().any(|net| net.contains(ip))
    }
}

/// Parse a host string as an IP literal, tolerating a single bracketed IPv6 form
/// (`[2606:4700::1]`). Returns `None` for genuine hostnames.
fn parse_ip_literal(host: &str) -> Option<IpAddr> {
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    IpAddr::from_str(unbracketed).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rs(domains: &[&str], cidrs: &[&str]) -> RoutedSet {
        let d: Vec<String> = domains.iter().map(|s| s.to_string()).collect();
        let c: Vec<String> = cidrs.iter().map(|s| s.to_string()).collect();
        RoutedSet::new(&d, &c).expect("valid routed set")
    }

    fn domain(h: &str) -> Target {
        Target::Domain(h.to_string(), 443)
    }

    fn ip(s: &str) -> Target {
        Target::Ip(format!("{s}:443").parse().unwrap())
    }

    #[test]
    fn empty_is_empty_and_allows_nothing() {
        let w = RoutedSet::default();
        assert!(w.is_empty());
        assert!(!w.allows(&domain("example.com")));
        assert!(!w.allows(&ip("1.2.3.4")));
    }

    #[test]
    fn star_domain_matches_all_hosts() {
        // `*` is the full-tunnel catch-all for hostnames.
        let w = rs(&["*"], &[]);
        assert!(!w.is_empty());
        assert!(w.allows(&domain("anything.example")));
        assert!(w.allows(&domain("example.com")));
        // Domains and CIDRs are independent: `*` doesn't imply IP literals.
        assert!(!w.allows(&ip("8.8.8.8")));
    }

    #[test]
    fn default_route_cidr_matches_all_ips() {
        // `0.0.0.0/0` / `::/0` are the IP-side full-tunnel catch-alls.
        let v4 = rs(&[], &["0.0.0.0/0"]);
        assert!(v4.allows(&ip("8.8.8.8")));
        assert!(v4.allows(&ip("10.0.0.1")));
        let v6 = rs(&[], &["::/0"]);
        assert!(v6.allows(&ip("[2606:4700::1]")));

        // Full tunnel for everything: `*` + `0.0.0.0/0` + `::/0`.
        let full = rs(&["*"], &["0.0.0.0/0", "::/0"]);
        assert!(full.allows(&domain("anything.example")));
        assert!(full.allows(&ip("8.8.8.8")));
        assert!(full.allows(&ip("[2606:4700::1]")));
    }

    #[test]
    fn exact_domain_matches_only_itself() {
        let w = rs(&["example.com"], &[]);
        assert!(!w.is_empty());
        assert!(w.allows(&domain("example.com")));
        assert!(!w.allows(&domain("api.example.com")));
        assert!(!w.allows(&domain("notexample.com")));
    }

    #[test]
    fn wildcard_matches_subdomains_not_apex() {
        let w = rs(&["*.example.com"], &[]);
        assert!(w.allows(&domain("api.example.com")));
        assert!(w.allows(&domain("a.b.example.com")));
        assert!(!w.allows(&domain("example.com")));
        assert!(!w.allows(&domain("example.com.evil.com")));
        assert!(!w.allows(&domain("notexample.com")));
    }

    #[test]
    fn matching_is_case_insensitive() {
        let w = rs(&["Example.COM", "*.Internal.Corp"], &[]);
        assert!(w.allows(&domain("EXAMPLE.com")));
        assert!(w.allows(&domain("API.Internal.CORP")));
    }

    #[test]
    fn cidr_and_bare_ip() {
        let w = rs(&[], &["10.0.0.0/8", "192.168.1.5"]);
        assert!(w.allows(&ip("10.1.2.3")));
        assert!(!w.allows(&ip("11.0.0.1")));
        assert!(w.allows(&ip("192.168.1.5")));
        assert!(!w.allows(&ip("192.168.1.6")));
    }

    #[test]
    fn ipv6_cidr() {
        let w = rs(&[], &["fd00::/8"]);
        assert!(w.allows(&ip("[fd00::1]")));
        assert!(!w.allows(&ip("[fe80::1]")));
    }

    #[test]
    fn domains_and_ips_match_separate_lists() {
        let w = rs(&["example.com"], &["10.0.0.0/8"]);
        // A real hostname is matched only against domain rules; a bare IP only
        // against CIDRs. Neither rule set leaks into the other.
        assert!(!w.allows(&domain("other.com")));
        assert!(w.allows(&domain("example.com")));
        assert!(!w.allows(&ip("1.2.3.4")));
        assert!(w.allows(&ip("10.1.2.3")));
    }

    #[test]
    fn ip_literal_in_domain_form_is_gated_by_cidr() {
        // A numeric host sent as ATYP_DOMAIN is treated as an IP: matched against
        // the CIDRs, never the domain rules — not even the `*` catch-all.
        let w = rs(&["*"], &["10.0.0.0/8"]);
        assert!(w.allows(&domain("10.0.0.1"))); // inside the CIDR → allowed
        assert!(!w.allows(&domain("8.8.8.8"))); // `*` does NOT cover IP literals
        assert!(w.allows(&domain("real.hostname"))); // genuine host still matched by `*`

        // Bracketed and bare IPv6 literals in domain form are handled too.
        let w6 = rs(&["*"], &["fd00::/8"]);
        assert!(w6.allows(&domain("[fd00::1]")));
        assert!(w6.allows(&domain("fd00::1")));
        assert!(!w6.allows(&domain("[fe80::1]")));

        // With no CIDRs configured, an IP literal in domain form matches nothing
        // even under `*`.
        let w_dom_only = rs(&["*"], &[]);
        assert!(!w_dom_only.allows(&domain("10.0.0.1")));
        assert!(w_dom_only.allows(&domain("real.hostname")));
    }

    #[test]
    fn rejects_bad_patterns() {
        assert!(RoutedSet::new(&["*.".to_string()], &[]).is_err());
        assert!(RoutedSet::new(&["a*b.com".to_string()], &[]).is_err());
        assert!(RoutedSet::new(&["*.*.example.com".to_string()], &[]).is_err());
        assert!(RoutedSet::new(&["*..example.com".to_string()], &[]).is_err());
        assert!(RoutedSet::new(&[], &["not-a-cidr".to_string()]).is_err());
    }
}
