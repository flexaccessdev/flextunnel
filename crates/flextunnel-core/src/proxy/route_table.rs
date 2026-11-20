//! The client's routing table: which destination, if any, a requested target
//! is tunneled to.
//!
//! A client holds several *destinations*, each a hostname mapped to one
//! server. A destination's own name means that server's loopback
//! (`machine1.internal:22` is port 22 on the machine itself); each destination
//! may also carry a [`RoutedSet`] of further domains and networks to send
//! through its server. The table is static configuration, validated once at
//! load — nothing about it is learned from a server — so a request is routed
//! without any connection being open.
//!
//! Precedence, most specific first:
//!
//! 1. the reserved `flextunnel.internal` namespace, answered by the client
//!    itself (see [`super::reserved`]);
//! 2. a destination's own host name → that server's loopback;
//! 3. the routed-set rule that matches most specifically across all
//!    destinations — an exact domain, then the longest `*.suffix`, then `*`;
//!    for IP targets the longest network prefix (see [`Specificity`]);
//! 4. otherwise the target is not tunneled: proxy front-ends dial it directly
//!    from this device, port forwards and `nc` refuse it.
//!
//! Two destinations may nest (`*.corp` on one, `*.dev.corp` on the other) —
//! the more specific rule wins — but may not carry the *same* rule, which
//! would be a tie; that is rejected at load.

use crate::proxy::reserved;
use crate::proxy::routed_set::{RoutedSet, Specificity, routing_key};
use crate::proxy::signaling::{StreamRequest, Target};
use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::net::IpAddr;

/// Where a requested target goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// `flextunnel.internal`: the client's own status endpoint.
    ClientStatus,
    /// Another `*.flextunnel.internal` name: reserved, answered with a 404.
    Reserved,
    /// Tunnel to the destination at this index of the table, asking its server
    /// for `request`.
    Tunnel { dest: usize, request: StreamRequest },
    /// On no destination's list: not tunneled.
    Direct,
}

/// One destination as the table sees it.
#[derive(Debug, Clone)]
struct Entry {
    /// The destination's host name, lowercased.
    host: String,
    routed: RoutedSet,
}

/// The validated routing table (see the module docs). Destinations keep the
/// order they were given in; [`Route::Tunnel::dest`] indexes it.
#[derive(Debug, Clone, Default)]
pub struct RouteTable {
    entries: Vec<Entry>,
}

/// One destination's routing input: its host name and the raw routed-set
/// rules, exactly as configured.
pub struct RouteSpec<'a> {
    pub host: &'a str,
    pub routed_domains: &'a [String],
    pub routed_cidrs: &'a [String],
}

impl RouteTable {
    /// Build and validate the table. Errors name the destination(s) at fault:
    /// an invalid or duplicate host, a malformed rule, a rule shared by two
    /// destinations, or a destination's host listed as a routed domain.
    pub fn new(specs: &[RouteSpec<'_>]) -> Result<Self> {
        let mut entries: Vec<Entry> = Vec::with_capacity(specs.len());
        for spec in specs {
            let host = validate_destination_host(spec.host).map_err(anyhow::Error::msg)?;
            if entries.iter().any(|e| e.host == host) {
                bail!("destination {host:?} is configured more than once");
            }
            for raw in spec.routed_domains {
                validate_routed_domain(raw).map_err(|e| {
                    anyhow::anyhow!("destination {host:?}: routed_domains entry {raw:?}: {e}")
                })?;
            }
            let routed = RoutedSet::new(spec.routed_domains, spec.routed_cidrs)
                .with_context(|| format!("destination {host:?}"))?;
            entries.push(Entry { host, routed });
        }

        // A rule on two destinations is a tie no precedence can break.
        let mut owners: HashMap<String, &str> = HashMap::new();
        for entry in &entries {
            for rule in entry.routed.rules() {
                if let Some(other) = owners.insert(rule.clone(), &entry.host) {
                    bail!(
                        "destinations {other:?} and {:?} both route {rule:?}; \
                         a rule can belong to only one destination",
                        entry.host
                    );
                }
            }
        }
        // A destination's name is its server's loopback, so routing it as an
        // ordinary domain — on its own destination or another — contradicts it.
        for entry in &entries {
            if let Some(owner) = owners.get(&entry.host) {
                bail!(
                    "destination {owner:?} routes {:?}, which is a destination's own host \
                     (it always means that server's loopback)",
                    entry.host
                );
            }
        }
        // The reserved namespace is the client's own; a rule naming it is dead.
        for entry in &entries {
            for rule in entry.routed.rules() {
                let name = rule.strip_prefix("*.").unwrap_or(&rule);
                if reserved::is_reserved_host(name) {
                    bail!(
                        "destination {:?} routes {rule:?}, which is in the reserved \
                         flextunnel.internal namespace",
                        entry.host
                    );
                }
            }
        }
        Ok(Self { entries })
    }

    /// The destination host names, in table order.
    pub fn hosts(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|e| e.host.as_str())
    }

    /// The index of the destination named `host` (case-insensitive, with or
    /// without the DNS root dot).
    pub fn index_of(&self, host: &str) -> Option<usize> {
        let host = routing_key(host);
        self.entries
            .iter()
            .position(|e| e.host.eq_ignore_ascii_case(host))
    }

    /// Route `target` (see the module docs for the precedence).
    pub fn route(&self, target: &Target) -> Route {
        if let Target::Domain(host, port) = target {
            if reserved::is_status_host(host) {
                return Route::ClientStatus;
            }
            if reserved::is_reserved_host(host) {
                return Route::Reserved;
            }
            if let Some(dest) = self.index_of(host) {
                return Route::Tunnel {
                    dest,
                    request: StreamRequest::Loopback(*port),
                };
            }
        }
        let best: Option<(Specificity, usize)> = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(dest, entry)| Some((entry.routed.specificity(target)?, dest)))
            // Validation rules out equal specificity across destinations.
            .max_by_key(|(specificity, _)| *specificity);
        match best {
            Some((_, dest)) => Route::Tunnel {
                dest,
                request: StreamRequest::Connect(target.clone()),
            },
            None => Route::Direct,
        }
    }
}

/// Check one `routed_domains` entry: `*`, a hostname, or `*.` and a hostname.
/// [`RoutedSet::new`] only parses the rule's shape; a name no request could
/// ever carry — one with a space, say — would sit there as a dead rule, so it
/// is refused here, where the client's configuration is loaded.
fn validate_routed_domain(raw: &str) -> Result<(), String> {
    let entry = routing_key(raw.trim());
    if entry == "*" {
        return Ok(());
    }
    let name = entry.strip_prefix("*.").unwrap_or(entry);
    crate::forwards::validate_remote_host(name)
        .map(|_| ())
        .map_err(|e| e.replace("Remote host", "the name"))
}

/// Validate a destination's host name, returning the lowercased form to store.
/// It follows the same hostname rules as a forward's remote host
/// ([`crate::forwards::validate_remote_host`]) and additionally must be a name
/// the table can own: not an IP literal, not `localhost` (which every client
/// app resolves itself), and not in the reserved `flextunnel.internal`
/// namespace.
pub fn validate_destination_host(input: &str) -> Result<String, String> {
    let host = input.trim();
    if host.is_empty() {
        return Err("Destination host is required".into());
    }
    let host = crate::forwards::validate_remote_host(host)
        .map_err(|e| e.replace("Remote host", "Destination host"))?;
    if host.parse::<IpAddr>().is_ok() {
        return Err(format!(
            "Destination host {host:?} is an IP address; use a host name"
        ));
    }
    let host = host.to_ascii_lowercase();
    if host == "localhost" || host.ends_with(".localhost") {
        return Err(format!(
            "Destination host {host:?} is this machine's own loopback name; pick another"
        ));
    }
    if reserved::is_reserved_host(&host) {
        return Err(format!(
            "Destination host {host:?} is in the reserved flextunnel.internal namespace"
        ));
    }
    Ok(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    /// Build a table from `(host, domains, cidrs)` triples.
    fn table(specs: &[(&str, &[&str], &[&str])]) -> Result<RouteTable> {
        let owned: Vec<(String, Vec<String>, Vec<String>)> = specs
            .iter()
            .map(|(host, domains, cidrs)| (host.to_string(), strings(domains), strings(cidrs)))
            .collect();
        let specs: Vec<RouteSpec<'_>> = owned
            .iter()
            .map(|(host, domains, cidrs)| RouteSpec {
                host,
                routed_domains: domains,
                routed_cidrs: cidrs,
            })
            .collect();
        RouteTable::new(&specs)
    }

    fn domain(host: &str, port: u16) -> Target {
        Target::Domain(host.to_string(), port)
    }

    fn connect_to(dest: usize, target: Target) -> Route {
        Route::Tunnel {
            dest,
            request: StreamRequest::Connect(target),
        }
    }

    #[test]
    fn own_host_is_the_servers_loopback() {
        let t = table(&[("machine1.internal", &[], &[]), ("machine2.internal", &[], &[])]).unwrap();
        assert_eq!(
            t.route(&domain("machine1.internal", 22)),
            Route::Tunnel { dest: 0, request: StreamRequest::Loopback(22) }
        );
        assert_eq!(
            t.route(&domain("Machine2.Internal", 8080)),
            Route::Tunnel { dest: 1, request: StreamRequest::Loopback(8080) }
        );
        // A subdomain of a destination is not the destination.
        assert_eq!(t.route(&domain("a.machine1.internal", 22)), Route::Direct);
    }

    #[test]
    fn reserved_namespace_is_answered_by_the_client() {
        // Even a catch-all route never captures the reserved names.
        let t = table(&[("m1.internal", &["*"], &["0.0.0.0/0"])]).unwrap();
        assert_eq!(t.route(&domain("flextunnel.internal", 80)), Route::ClientStatus);
        assert_eq!(t.route(&domain("FlexTunnel.Internal", 80)), Route::ClientStatus);
        assert_eq!(t.route(&domain("x.flextunnel.internal", 80)), Route::Reserved);
        assert_eq!(t.route(&domain("localhost.flextunnel.internal", 80)), Route::Reserved);
    }

    #[test]
    fn routed_rules_pick_their_destination() {
        let t = table(&[
            ("m1.internal", &["*.corp.example", "db.internal"], &["10.0.0.0/8"]),
            ("m2.internal", &["wiki.example"], &["192.168.7.0/24"]),
        ])
        .unwrap();
        let api = domain("api.corp.example", 443);
        assert_eq!(t.route(&api), connect_to(0, api.clone()));
        let db = domain("DB.internal", 5432);
        assert_eq!(t.route(&db), connect_to(0, db.clone()));
        let wiki = domain("wiki.example", 443);
        assert_eq!(t.route(&wiki), connect_to(1, wiki.clone()));
        let ip = Target::Ip("192.168.7.9:80".parse().unwrap());
        assert_eq!(t.route(&ip), connect_to(1, ip.clone()));
        // An IP literal in domain form is matched by the networks.
        let literal = domain("10.1.2.3", 80);
        assert_eq!(t.route(&literal), connect_to(0, literal.clone()));
        // Off every list: direct.
        assert_eq!(t.route(&domain("example.org", 443)), Route::Direct);
        assert_eq!(t.route(&Target::Ip("8.8.8.8:53".parse().unwrap())), Route::Direct);
    }

    #[test]
    fn the_most_specific_rule_wins_across_destinations() {
        let t = table(&[
            ("m1.internal", &["*", "*.corp.example"], &["10.0.0.0/8"]),
            ("m2.internal", &["*.dev.corp.example", "exact.corp.example"], &["10.1.0.0/16"]),
        ])
        .unwrap();
        for (host, dest) in [
            ("anything.example", 0),      // only the catch-all matches
            ("api.corp.example", 0),      // the shorter suffix
            ("x.dev.corp.example", 1),    // the longer suffix beats it
            ("exact.corp.example", 1),    // an exact name beats a suffix
        ] {
            let target = domain(host, 443);
            assert_eq!(t.route(&target), connect_to(dest, target.clone()), "{host}");
        }
        for (ip, dest) in [("10.2.0.1:80", 0), ("10.1.0.1:80", 1)] {
            let target = Target::Ip(ip.parse().unwrap());
            assert_eq!(t.route(&target), connect_to(dest, target.clone()), "{ip}");
        }
        // `*` is a hostname catch-all only: an unlisted IP still goes direct.
        assert_eq!(t.route(&Target::Ip("8.8.8.8:53".parse().unwrap())), Route::Direct);
    }

    #[test]
    fn own_host_beats_a_wildcard_that_covers_it() {
        let t = table(&[("m1.internal", &[], &[]), ("m2.internal", &["*.internal"], &[])]).unwrap();
        assert_eq!(
            t.route(&domain("m1.internal", 22)),
            Route::Tunnel { dest: 0, request: StreamRequest::Loopback(22) }
        );
        let other = domain("nas.internal", 22);
        assert_eq!(t.route(&other), connect_to(1, other.clone()));
    }

    #[test]
    fn invalid_tables_are_rejected() {
        let err = |specs: &[(&str, &[&str], &[&str])]| table(specs).unwrap_err().to_string();

        assert!(err(&[("m1.internal", &[], &[]), ("M1.Internal", &[], &[])])
            .contains("more than once"));
        // The same rule on two destinations, in each rule form.
        for (domains, cidrs) in [
            (&["shared.example"][..], &[][..]),
            (&["*.shared.example"][..], &[][..]),
            (&["*"][..], &[][..]),
            (&[][..], &["10.0.0.0/8"][..]),
        ] {
            let message = err(&[("m1.internal", domains, cidrs), ("m2.internal", domains, cidrs)]);
            assert!(message.contains("both route"), "{message}");
        }
        // A bare IP and its /32 are the same rule.
        assert!(err(&[
            ("m1.internal", &[], &["10.0.0.5"]),
            ("m2.internal", &[], &["10.0.0.5/32"]),
        ])
        .contains("both route"));
        // A destination's host as a routed domain, on itself or another.
        assert!(err(&[("m1.internal", &["m1.internal"], &[])]).contains("own host"));
        assert!(err(&[("m1.internal", &[], &[]), ("m2.internal", &["m1.internal"], &[])])
            .contains("own host"));
        // Reserved-namespace rules.
        assert!(err(&[("m1.internal", &["flextunnel.internal"], &[])]).contains("reserved"));
        assert!(err(&[("m1.internal", &["*.flextunnel.internal"], &[])]).contains("reserved"));
        // Malformed rules name their destination.
        assert!(err(&[("m1.internal", &["*.*.example"], &[])]).contains("m1.internal"));
        assert!(err(&[("m1.internal", &[], &["not-a-cidr"])]).contains("m1.internal"));
    }

    /// A routed domain must be a name a request could carry; the error says
    /// which destination's field holds which value.
    #[test]
    fn malformed_routed_domains_are_rejected() {
        for bad in ["has space.example", "*.has space.example", "a..b", "", "*.", "-x.example", "ex*mple.com"] {
            let message = table(&[("m1.internal", &[bad], &[])]).unwrap_err().to_string();
            assert!(
                message.contains("\"m1.internal\"")
                    && message.contains("routed_domains")
                    && message.contains(&format!("{bad:?}")),
                "{bad:?}: {message}"
            );
        }
        // Every accepted form still is: the catch-all, exact names (internal
        // ones with underscores included), wildcards, an address in name form.
        table(&[(
            "m1.internal",
            &["*", "db.internal", "my_host", "*.corp.example", " Padded.Example ", "10.0.0.5", "fqdn.example."],
            &[],
        )])
        .unwrap();
    }

    /// A name with the DNS root dot is the same name: it takes the same route
    /// — a destination's own host, an exact rule, the reserved namespace —
    /// instead of falling through to another destination's catch-all. The
    /// target itself is forwarded as it was spelled.
    #[test]
    fn the_root_dot_selects_the_same_route() {
        let t = table(&[("a.internal", &["db.example"], &[]), ("b.internal", &["*"], &[])]).unwrap();
        for host in ["db.example", "db.example.", "DB.Example."] {
            let target = domain(host, 5432);
            assert_eq!(t.route(&target), connect_to(0, target.clone()), "{host}");
        }
        for host in ["a.internal", "a.internal."] {
            assert_eq!(
                t.route(&domain(host, 22)),
                Route::Tunnel { dest: 0, request: StreamRequest::Loopback(22) },
                "{host}"
            );
        }
        let other = domain("unrelated.example.", 443);
        assert_eq!(t.route(&other), connect_to(1, other.clone()));
        assert_eq!(t.route(&domain("flextunnel.internal.", 80)), Route::ClientStatus);
        assert_eq!(t.route(&domain("x.flextunnel.internal.", 80)), Route::Reserved);
    }

    #[test]
    fn destination_host_validation() {
        assert_eq!(validate_destination_host(" Machine1.Internal ").unwrap(), "machine1.internal");
        assert_eq!(validate_destination_host("nas").unwrap(), "nas");
        for bad in [
            "",
            "10.0.0.1",
            "::1",
            "[::1]",
            "localhost",
            "app.localhost",
            "flextunnel.internal",
            "x.flextunnel.internal",
            "a..b",
            "*",
            "*.example.com",
            "has space.example",
        ] {
            assert!(validate_destination_host(bad).is_err(), "{bad:?} should be rejected");
        }
    }
}
