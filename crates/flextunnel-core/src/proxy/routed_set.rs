//! Destination routed set shared by the client and server.
//!
//! A routed set is a *tunnel set*: targets that are routed through a QUIC
//! tunnel. The two sides each configure their own, and nothing about routing
//! crosses the handshake:
//!
//! * The **client** holds one set per destination (see
//!   [`super::route_table`]) and uses them to decide per connection which
//!   server, if any, a target is tunneled to (split-tunneling); a target on no
//!   set is **not** rejected, it is dialed directly from the device.
//! * The **server** enforces its set as a **whitelist**: it rejects any tunnel
//!   request for a target that is not on it. A client route the server does
//!   not also list is therefore answered "not allowed" — the two lists should
//!   be kept in step.
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
//! **optional** — an empty routed set routes nothing, never "tunnel
//! everything". Two things reach a server outside of it: a client destination's
//! `<name>.localhost.flextunnel.internal`, which is that server's loopback,
//! and the server's status page
//! (see [`super::signaling::StreamRequest`]). To tunnel *all* traffic, use the
//! catch-alls: `*` for hostnames and `0.0.0.0/0` (+ `::/0`) for IPs.

use crate::proxy::reserved;
use crate::proxy::signaling::Target;
use anyhow::{Context, Result, bail};
use ipnetwork::IpNetwork;
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

/// How specifically a [`RoutedSet`] rule matches a target (see
/// [`RoutedSet::specificity`]). Ordered least to most specific: among hostname
/// rules the catch-all `*` loses to any `*.suffix`, a longer suffix beats a
/// shorter one, and an exact name beats them all; among networks a longer
/// prefix wins. Hostname and network rules never compete — a target is one or
/// the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Specificity {
    /// Matched by the `*` hostname catch-all.
    CatchAll,
    /// Matched by a `*.suffix` rule; the length of the stored `.suffix`.
    Suffix(usize),
    /// Matched by an exact domain rule.
    Exact,
    /// Matched by a network of this prefix length.
    Cidr(u8),
}

/// One rule of a [`RoutedSet`], normalized: lowercased, without the DNS root
/// dot, a network by its network address. Its [`Display`](std::fmt::Display)
/// form is the config syntax (`*`, `*.corp.example`, `db.example`,
/// `10.0.0.0/8`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Rule {
    /// `*`: every hostname.
    CatchAll,
    /// `*.zone`: every name under `zone` (not `zone` itself). Holds the zone.
    Suffix(String),
    /// Exactly this hostname.
    Exact(String),
    /// Every IP in this network.
    Cidr(IpNetwork),
}

impl std::fmt::Display for Rule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CatchAll => f.write_str("*"),
            Self::Suffix(zone) => write!(f, "*.{zone}"),
            Self::Exact(name) => f.write_str(name),
            Self::Cidr(net) => write!(f, "{}/{}", net.network(), net.prefix()),
        }
    }
}

impl Rule {
    /// How specific a match by this rule is (see [`Specificity`]).
    pub fn specificity(&self) -> Specificity {
        match self {
            Self::CatchAll => Specificity::CatchAll,
            // As [`RoutedSet`] measures it: the stored `.zone`.
            Self::Suffix(zone) => Specificity::Suffix(zone.len() + 1),
            Self::Exact(_) => Specificity::Exact,
            Self::Cidr(net) => Specificity::Cidr(net.prefix()),
        }
    }

    /// Whether this rule matches every target `inner` matches (a rule
    /// contains itself). Hostname rules and networks never contain each
    /// other: a target is one or the other.
    pub fn contains(&self, inner: &Rule) -> bool {
        match (self, inner) {
            (Self::CatchAll, Self::CatchAll | Self::Suffix(_) | Self::Exact(_)) => true,
            (Self::Suffix(zone), Self::Suffix(inner)) => in_zone(inner, zone) || inner == zone,
            (Self::Suffix(zone), Self::Exact(name)) => in_zone(name, zone),
            (Self::Exact(a), Self::Exact(b)) => a == b,
            (Self::Cidr(outer), Self::Cidr(inner)) => {
                outer.prefix() <= inner.prefix() && outer.contains(inner.network())
            }
            _ => false,
        }
    }

    /// Whether some target matches both rules. Zones and networks nest or are
    /// apart, never partly overlap, so two rules intersect exactly when one
    /// contains the other.
    pub fn intersects(&self, other: &Rule) -> bool {
        self.contains(other) || other.contains(self)
    }
}

/// Whether `name` is strictly under `zone` (`a.corp.example` under
/// `corp.example`; `corp.example` itself is not).
fn in_zone(name: &str, zone: &str) -> bool {
    name.len() > zone.len() + 1
        && name.ends_with(zone)
        && name.as_bytes()[name.len() - zone.len() - 1] == b'.'
}

/// How much of one rule's targets another set routes ([`RoutedSet::coverage`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    /// Every target the rule matches.
    Full,
    /// Some of them: a narrower rule inside it (`api.corp.example` of
    /// `*.corp.example`, `10.1.0.0/16` of `10.0.0.0/8`).
    Partial,
    /// None of them.
    None,
}

impl Coverage {
    /// A lowercase word for status output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "allowed",
            Self::Partial => "partly allowed",
            Self::None => "not allowed",
        }
    }
}

/// `net` by its network address (`10.0.0.1/8` is `10.0.0.0/8`).
fn normalized(net: IpNetwork) -> IpNetwork {
    IpNetwork::new(net.network(), net.prefix()).expect("a network's own prefix is valid")
}

/// Whether `nets` together cover all of `net`: one of them contains it, or
/// each of its two halves is covered in turn. Only the networks strictly
/// inside `net` are carried into its halves, and only while there are some,
/// so each level of the walk looks at every network at most once.
fn cidr_covered(net: IpNetwork, nets: &[IpNetwork]) -> bool {
    let rule = Rule::Cidr(net);
    let mut inside = Vec::new();
    for n in nets {
        if Rule::Cidr(*n).contains(&rule) {
            return true;
        }
        if n.prefix() > net.prefix() && net.contains(n.network()) {
            inside.push(*n);
        }
    }
    if inside.is_empty() {
        return false;
    }
    let prefix = net.prefix() + 1;
    let (low, high) = match net.network() {
        IpAddr::V4(addr) => {
            let base = u32::from(addr);
            let half = 1u32 << (32 - prefix);
            (
                IpAddr::from(std::net::Ipv4Addr::from(base)),
                IpAddr::from(std::net::Ipv4Addr::from(base | half)),
            )
        }
        IpAddr::V6(addr) => {
            let base = u128::from(addr);
            let half = 1u128 << (128 - prefix);
            (
                IpAddr::from(std::net::Ipv6Addr::from(base)),
                IpAddr::from(std::net::Ipv6Addr::from(base | half)),
            )
        }
    };
    let half = |addr| IpNetwork::new(addr, prefix).expect("a half's prefix is valid");
    cidr_covered(half(low), &inside) && cidr_covered(half(high), &inside)
}

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
            let entry = routing_key(raw.trim());
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
                if reserved::is_reserved_host(suffix) {
                    bail!(
                        "routed_domains entry {raw:?} is in the reserved flextunnel.internal namespace"
                    );
                }
                domains_suffix.push(format!(".{}", suffix.to_ascii_lowercase()));
            } else if entry.is_empty() || entry.contains('*') {
                bail!("invalid routed-domain pattern: {raw:?}");
            } else if parse_ip_literal(entry).is_some() {
                // A numeric target is always matched against the CIDRs, so
                // this entry would match nothing.
                bail!("routed_domains entry {raw:?} is an IP address: list it in routed_cidrs");
            } else if reserved::is_reserved_host(entry) {
                // The client answers the reserved names itself and a server
                // refuses them: the entry would match nothing.
                bail!(
                    "routed_domains entry {raw:?} is in the reserved flextunnel.internal namespace"
                );
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
        let host = routing_key(host).to_ascii_lowercase();
        self.domains_exact.contains(&host)
            || self
                .domains_suffix
                .iter()
                .any(|suffix| host.ends_with(suffix.as_str()))
    }

    fn allows_ip(&self, ip: IpAddr) -> bool {
        self.cidrs.iter().any(|net| net.contains(ip))
    }

    /// How specifically this set matches `target`, or `None` when it does not
    /// match at all (exactly when [`Self::allows`] is false). Lets a client
    /// holding several sets — one per destination — send a target to the one
    /// with the most specific rule (see [`super::route_table`]).
    pub fn specificity(&self, target: &Target) -> Option<Specificity> {
        match target {
            Target::Domain(host, _) => match parse_ip_literal(host) {
                Some(ip) => self.ip_specificity(ip),
                None => self.host_specificity(host),
            },
            Target::Ip(sa) => self.ip_specificity(sa.ip()),
        }
    }

    fn host_specificity(&self, host: &str) -> Option<Specificity> {
        let host = routing_key(host).to_ascii_lowercase();
        if self.domains_exact.contains(&host) {
            return Some(Specificity::Exact);
        }
        self.domains_suffix
            .iter()
            .filter(|suffix| host.ends_with(suffix.as_str()))
            .map(|suffix| Specificity::Suffix(suffix.len()))
            .max()
            .or(self.domains_all.then_some(Specificity::CatchAll))
    }

    fn ip_specificity(&self, ip: IpAddr) -> Option<Specificity> {
        self.cidrs
            .iter()
            .filter(|net| net.contains(ip))
            .map(|net| Specificity::Cidr(net.prefix()))
            .max()
    }

    /// The set's rules, normalized and in a stable order (sorted by their
    /// spelling): an exact domain, a `*.zone` wildcard, the `*` catch-all, a
    /// network by its network address. Two sets sharing a rule would route the
    /// same targets with equal specificity, so [`super::route_table`] compares
    /// these to reject the ambiguity at config load.
    pub fn rules(&self) -> Vec<Rule> {
        let mut rules: Vec<Rule> = self
            .domains_exact
            .iter()
            .cloned()
            .map(Rule::Exact)
            .collect();
        rules.extend(
            self.domains_suffix
                .iter()
                .map(|suffix| Rule::Suffix(suffix[1..].to_string())),
        );
        if self.domains_all {
            rules.push(Rule::CatchAll);
        }
        rules.extend(self.cidrs.iter().map(|net| Rule::Cidr(normalized(*net))));
        rules.sort_by_cached_key(Rule::to_string);
        rules.dedup();
        rules
    }

    /// How much of what `rule` matches this set routes (see [`Coverage`]).
    /// For a client's rule against its server's set, this says whether the
    /// server will accept what the client sends it under that rule. One pass
    /// over the set's rules; a client grades its rules once per answer from
    /// its server (see [`super::server_routes::ServerRoutes::coverage_of`]).
    pub fn coverage(&self, rule: &Rule) -> Coverage {
        let grade = |full: bool, partial: bool| match (full, partial) {
            (true, _) => Coverage::Full,
            (false, true) => Coverage::Partial,
            (false, false) => Coverage::None,
        };
        // A hostname rule is covered only by one rule containing it: a zone
        // has endless names, so no set of exact names or inner zones fills
        // it. Zones nest or are apart, so a rule it meets lies inside it.
        match rule {
            // Several networks can cover one between them (two /9s, a /8).
            Rule::Cidr(net) => grade(
                cidr_covered(*net, &self.cidrs),
                self.cidrs.iter().any(|n| Rule::Cidr(*n).intersects(rule)),
            ),
            _ if self.domains_all => Coverage::Full,
            Rule::CatchAll => grade(
                false,
                !self.domains_exact.is_empty() || !self.domains_suffix.is_empty(),
            ),
            Rule::Exact(name) => grade(self.allows_host(name), false),
            Rule::Suffix(zone) => {
                let dot_zone = format!(".{zone}");
                grade(
                    self.domains_suffix
                        .iter()
                        .any(|s| dot_zone.ends_with(s.as_str())),
                    self.domains_exact.iter().any(|e| e.ends_with(&dot_zone))
                        || self
                            .domains_suffix
                            .iter()
                            .any(|s| s.len() > dot_zone.len() && s.ends_with(&dot_zone)),
                )
            }
        }
    }
}

/// Parse a host string as an IP literal, tolerating a single bracketed IPv6 form
/// (`[2606:4700::1]`). Returns `None` for genuine hostnames.
/// The form of a hostname that routing compares: without the DNS root dot.
/// `db.internal.` and `db.internal` are one name, so they must select one
/// route — on the client's table, a server's routed set and the reserved
/// namespace alike. Only the comparison uses this; a target keeps its own
/// spelling for resolution.
pub(crate) fn routing_key(host: &str) -> &str {
    match host.strip_suffix('.') {
        // Only a dot that ends a label is the root: `*.` and `a..` are
        // malformed, and stay as written for their callers to reject.
        Some(name) if !name.is_empty() && !name.ends_with(['.', '*']) => name,
        _ => host,
    }
}

pub(crate) fn parse_ip_literal(host: &str) -> Option<IpAddr> {
    // `10.0.0.1.` is the same address: classified as an IP, it is gated by
    // the CIDRs alike everywhere — in config and in a target.
    let host = routing_key(host);
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
    fn empty_allows_nothing() {
        let w = RoutedSet::default();
        assert!(!w.allows(&domain("example.com")));
        assert!(!w.allows(&ip("1.2.3.4")));
    }

    #[test]
    fn star_domain_matches_all_hosts() {
        // `*` is the full-tunnel catch-all for hostnames.
        let w = rs(&["*"], &[]);
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

    /// The DNS root dot is not part of the name routing compares: a rule and
    /// a request match with or without it.
    #[test]
    fn the_root_dot_does_not_change_a_match() {
        let w = rs(&["example.com", "*.corp.example."], &[]);
        for host in [
            "example.com",
            "example.com.",
            "EXAMPLE.com.",
            "api.corp.example",
            "api.corp.example.",
        ] {
            assert!(w.allows(&domain(host)), "{host}");
        }
        assert_eq!(
            w.specificity(&domain("example.com.")),
            Some(Specificity::Exact)
        );
        assert!(
            !w.allows(&domain("corp.example.")),
            "the apex stays out of a wildcard"
        );
        assert!(!w.allows(&domain("other.example.")));
        let rules: Vec<String> = w.rules().iter().map(ToString::to_string).collect();
        assert_eq!(rules, ["*.corp.example", "example.com"]);
    }

    #[test]
    fn exact_domain_matches_only_itself() {
        let w = rs(&["example.com"], &[]);
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
        // With the root dot it is the same address, gated the same way.
        assert!(!w_dom_only.allows(&domain("10.0.0.1.")));
        assert!(w.allows(&domain("10.0.0.1.")));
        assert_eq!(
            w.specificity(&domain("10.0.0.1.")),
            Some(Specificity::Cidr(8))
        );
        assert!(w_dom_only.allows(&domain("real.hostname")));
    }

    /// The one rule `raw` (a domain entry, or a network when it parses as
    /// one) makes.
    fn rule(raw: &str) -> Rule {
        let set = if raw.contains('/') || raw.parse::<IpAddr>().is_ok() {
            rs(&[], &[raw])
        } else {
            rs(&[raw], &[])
        };
        let mut rules = set.rules();
        assert_eq!(rules.len(), 1, "{raw}");
        rules.remove(0)
    }

    #[test]
    fn rules_are_normalized_and_spelled_as_configured() {
        for (raw, spelled) in [
            ("*", "*"),
            ("*.Corp.Example.", "*.corp.example"),
            ("DB.example", "db.example"),
            ("10.0.0.1/8", "10.0.0.0/8"),
            ("192.168.1.5", "192.168.1.5/32"),
            ("fd00::1/8", "fd00::/8"),
        ] {
            assert_eq!(rule(raw).to_string(), spelled, "{raw}");
        }
    }

    #[test]
    fn rule_containment() {
        for (outer, inner) in [
            ("*", "*.corp.example"),
            ("*", "db.example"),
            ("*.corp.example", "*.dev.corp.example"),
            ("*.corp.example", "api.corp.example"),
            ("*.corp.example", "a.b.corp.example"),
            ("10.0.0.0/8", "10.1.0.0/16"),
            ("10.0.0.0/8", "10.9.9.9"),
            ("0.0.0.0/0", "192.168.0.0/16"),
            ("fd00::/8", "fd00:1::/32"),
        ] {
            let (outer, inner) = (rule(outer), rule(inner));
            assert!(outer.contains(&inner), "{outer} contains {inner}");
            assert!(!inner.contains(&outer), "{inner} does not contain {outer}");
            assert!(outer.intersects(&inner) && inner.intersects(&outer));
        }
        for (a, b) in [
            // The apex is not under its own wildcard.
            ("*.corp.example", "corp.example"),
            // A name that merely ends in the same letters is another zone.
            ("*.corp.example", "notcorp.example"),
            ("*.corp.example", "*.notcorp.example"),
            ("*.corp.example", "*.other.example"),
            ("a.example", "b.example"),
            ("10.0.0.0/8", "11.0.0.0/8"),
            // Hostnames and networks never meet, not even under the catch-alls.
            ("*", "10.0.0.0/8"),
            ("0.0.0.0/0", "db.example"),
            ("0.0.0.0/0", "::/0"),
        ] {
            let (a, b) = (rule(a), rule(b));
            assert!(!a.intersects(&b), "{a} and {b} are apart");
        }
        // Every rule contains itself.
        for raw in ["*", "*.corp.example", "db.example", "10.0.0.0/8"] {
            assert!(rule(raw).contains(&rule(raw)), "{raw}");
        }
    }

    /// How much of a client's rule a server's set routes: all of it, part
    /// of it, or none of it.
    #[test]
    fn coverage_of_a_rule_by_a_set() {
        let server = rs(
            &["*.corp.example", "wiki.example"],
            &["10.0.0.0/9", "10.128.0.0/9", "192.168.1.0/24"],
        );
        for (raw, coverage) in [
            ("*.corp.example", Coverage::Full),
            ("*.dev.corp.example", Coverage::Full),
            ("api.corp.example", Coverage::Full),
            ("wiki.example", Coverage::Full),
            // The server's rules are narrower than these.
            ("*", Coverage::Partial),
            ("*.example", Coverage::Partial),
            ("corp.example", Coverage::None),
            ("*.other.example", Coverage::None),
            // Two halves cover the whole network between them.
            ("10.0.0.0/8", Coverage::Full),
            ("10.200.0.0/16", Coverage::Full),
            ("192.168.0.0/16", Coverage::Partial),
            ("192.168.1.7", Coverage::Full),
            ("0.0.0.0/0", Coverage::Partial),
            ("172.16.0.0/12", Coverage::None),
            ("::/0", Coverage::None),
        ] {
            assert_eq!(server.coverage(&rule(raw)), coverage, "{raw}");
        }
        // Only the catch-all covers the catch-all.
        assert_eq!(rs(&["*"], &[]).coverage(&rule("*")), Coverage::Full);
        assert_eq!(
            rs(&["*"], &[]).coverage(&rule("10.0.0.0/8")),
            Coverage::None
        );
        // A set with holes in a network covers it only in part.
        let holey = rs(&[], &["10.0.0.0/9", "10.128.0.0/10"]);
        assert_eq!(holey.coverage(&rule("10.0.0.0/8")), Coverage::Partial);
        let full = rs(&[], &["0.0.0.0/0", "::/0"]);
        assert_eq!(full.coverage(&rule("::/0")), Coverage::Full);
        assert_eq!(full.coverage(&rule("2001:db8::/32")), Coverage::Full);
        assert_eq!(RoutedSet::default().coverage(&rule("*")), Coverage::None);
    }

    #[test]
    fn rejects_bad_patterns() {
        assert!(RoutedSet::new(&["*.".to_string()], &[]).is_err());
        assert!(RoutedSet::new(&["a*b.com".to_string()], &[]).is_err());
        assert!(RoutedSet::new(&["*.*.example.com".to_string()], &[]).is_err());
        assert!(RoutedSet::new(&["*..example.com".to_string()], &[]).is_err());
        assert!(RoutedSet::new(&[], &["not-a-cidr".to_string()]).is_err());
        // The client answers the reserved names itself and a server refuses
        // them, so no list may name them.
        for reserved in [
            "flextunnel.internal",
            "x.flextunnel.internal",
            "*.flextunnel.internal",
            "*.a.flextunnel.internal.",
        ] {
            let err = RoutedSet::new(&[reserved.to_string()], &[]).unwrap_err();
            assert!(err.to_string().contains("reserved"), "{reserved}: {err}");
        }
        assert!(RoutedSet::new(&["*.internal".to_string()], &[]).is_ok());
        // A numeric target is matched against the CIDRs, never a domain rule:
        // as a domain an address would be a rule that matches nothing.
        for numeric in ["10.0.0.1", "10.0.0.1.", "fd00::1", "[fd00::1]"] {
            let err = RoutedSet::new(&[numeric.to_string()], &[]).unwrap_err();
            assert!(err.to_string().contains("routed_cidrs"), "{numeric}: {err}");
        }
    }

    /// Many small networks tile a large one: the walk splits only where they
    /// lie, and a single missing piece leaves it partly covered.
    #[test]
    fn many_networks_cover_one_between_them() {
        let all: Vec<String> = (0..256).map(|i| format!("10.1.{i}.0/24")).collect();
        let tiled = RoutedSet::new(&[], &all).unwrap();
        assert_eq!(tiled.coverage(&rule("10.1.0.0/16")), Coverage::Full);
        assert_eq!(tiled.coverage(&rule("10.0.0.0/8")), Coverage::Partial);
        let holey = RoutedSet::new(&[], &all[1..]).unwrap();
        assert_eq!(holey.coverage(&rule("10.1.0.0/16")), Coverage::Partial);
        assert_eq!(holey.coverage(&rule("10.1.1.0/24")), Coverage::Full);
    }
}
