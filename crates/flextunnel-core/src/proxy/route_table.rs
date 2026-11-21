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
//! would be a tie; that is rejected at load. Every nesting between two
//! destinations is found at load too ([`RouteTable::overlaps`]), so the client
//! can say which destination a shared stretch of names or addresses goes to
//! — the rules may have been typed in or filled in from each server's own
//! lists, and a fill can carry a server's broad rule over another's.

use crate::proxy::reserved;
use crate::proxy::routed_set::{RoutedSet, Rule, Specificity, routing_key};
use crate::proxy::signaling::{StreamRequest, Target};
use anyhow::{Result, bail};
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
    overlaps: Vec<Overlap>,
}

/// What one row of the table routes: a destination's own host, or one of its
/// routed rules.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TableRule {
    /// The destination's own name: its server's loopback.
    Host(String),
    Routed(Rule),
}

impl std::fmt::Display for TableRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Host(host) => f.write_str(host),
            Self::Routed(rule) => rule.fmt(f),
        }
    }
}

/// One row of the table: a rule and the destination (an index into the
/// table) it sends its matches to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TableRow {
    pub dest: usize,
    pub rule: TableRule,
}

/// Two destinations' rules that match some of the same targets. Where both
/// match, `inner` — the narrower rule — wins; `outer` keeps the rest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Overlap {
    pub outer: TableRow,
    pub inner: TableRow,
}

impl std::fmt::Display for Overlap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} is within {}", self.inner.rule, self.outer.rule)
    }
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
                .map_err(|e| anyhow::anyhow!("destination {host:?}: {e:#}"))?;
            entries.push(Entry { host, routed });
        }

        // A rule on two destinations is a tie no precedence can break.
        let mut owners: HashMap<String, &str> = HashMap::new();
        for entry in &entries {
            for rule in entry.routed.rules() {
                let rule = rule.to_string();
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
        let overlaps = find_overlaps(&entries);
        Ok(Self { entries, overlaps })
    }

    /// Every place two destinations' rules match the same targets, broadest
    /// rule first: a routed rule inside another destination's (`*.dev.corp`
    /// within `*.corp`, `10.1.0.0/16` within `10.0.0.0/8`), or a destination's
    /// own host under another's wildcard. Never an error — the narrower rule
    /// wins where they meet — but worth showing, since the broad one stops
    /// covering what the narrow one takes.
    pub fn overlaps(&self) -> &[Overlap] {
        &self.overlaps
    }

    /// Every row of the table, in the order a target is tried against them:
    /// the destinations' own hosts, then the hostname rules (exact names, the
    /// longer zone first, the catch-all last), then the networks (the longer
    /// prefix first). Ties within a kind keep destination order, then the
    /// rule's spelling.
    pub fn rows(&self) -> Vec<TableRow> {
        let mut rows: Vec<TableRow> = self
            .entries
            .iter()
            .enumerate()
            .map(|(dest, e)| TableRow { dest, rule: TableRule::Host(e.host.clone()) })
            .collect();
        let mut routed: Vec<(usize, Rule)> = self
            .entries
            .iter()
            .enumerate()
            .flat_map(|(dest, e)| e.routed.rules().into_iter().map(move |rule| (dest, rule)))
            .collect();
        // Hostname rules before networks; within each, the more specific first.
        routed.sort_by_key(|(dest, rule)| {
            let is_net = matches!(rule, Rule::Cidr(_));
            (is_net, std::cmp::Reverse(rule.specificity()), *dest, rule.to_string())
        });
        rows.extend(routed.into_iter().map(|(dest, rule)| TableRow { dest, rule: TableRule::Routed(rule) }));
        rows
    }

    /// The routed rules of the destination at `dest`, as [`RoutedSet::rules`]
    /// normalizes them.
    pub fn rules_of(&self, dest: usize) -> Vec<Rule> {
        self.entries.get(dest).map(|e| e.routed.rules()).unwrap_or_default()
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

/// The overlaps of validated `entries` (see [`RouteTable::overlaps`]): for
/// each pair of destinations, each rule of one inside a rule of the other.
/// Identical rules are refused before this runs, so containment is strict.
fn find_overlaps(entries: &[Entry]) -> Vec<Overlap> {
    // An overlap takes two destinations; one alone would only be compared
    // with itself, rule by rule, for nothing.
    if entries.len() < 2 {
        return Vec::new();
    }
    // Each destination's rows: its host first, then its routed rules.
    let groups: Vec<Vec<(TableRow, Rule)>> = entries
        .iter()
        .enumerate()
        .map(|(dest, e)| {
            let host = (
                TableRow { dest, rule: TableRule::Host(e.host.clone()) },
                Rule::Exact(e.host.clone()),
            );
            std::iter::once(host)
                .chain(e.routed.rules().into_iter().map(|rule| {
                    (TableRow { dest, rule: TableRule::Routed(rule.clone()) }, rule)
                }))
                .collect()
        })
        .collect();
    let mut overlaps = Vec::new();
    // Each pair of destinations once, each way round: one destination's rules
    // are never compared with each other.
    for (a, first) in groups.iter().enumerate() {
        for second in &groups[a + 1..] {
            for (outer_group, inner_group) in [(first, second), (second, first)] {
                for (outer, outer_rule) in outer_group {
                    // A host is the narrowest thing there is: nothing nests
                    // inside it.
                    if matches!(outer.rule, TableRule::Host(_)) {
                        continue;
                    }
                    for (inner, inner_rule) in inner_group {
                        if outer_rule.contains(inner_rule) {
                            overlaps.push(Overlap { outer: outer.clone(), inner: inner.clone() });
                        }
                    }
                }
            }
        }
    }
    // Broadest outer rule first: hostname rules, then networks.
    overlaps.sort_by_key(|o| {
        let (is_net, specificity) = match &o.outer.rule {
            TableRule::Routed(rule) => (matches!(rule, Rule::Cidr(_)), rule.specificity()),
            TableRule::Host(_) => (false, Specificity::Exact),
        };
        (is_net, specificity, o.outer.dest, o.inner.dest, o.inner.rule.to_string())
    });
    overlaps
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
    // An IP address or a reserved name is refused by [`RoutedSet::new`]
    // itself, on a server's lists as well as here.
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

    /// `(inner rule, inner destination, outer rule, outer destination)` for
    /// every overlap of `t`, in its order.
    fn overlaps(t: &RouteTable) -> Vec<(String, usize, String, usize)> {
        t.overlaps()
            .iter()
            .map(|o| (o.inner.rule.to_string(), o.inner.dest, o.outer.rule.to_string(), o.outer.dest))
            .collect()
    }

    /// Every nesting between two destinations is found, whichever way round
    /// and however the rules are spelled; rules that nest within one
    /// destination, or do not meet, are not overlaps.
    #[test]
    fn overlaps_between_destinations_are_found() {
        let t = table(&[
            ("m1.internal", &["*", "*.corp.example", "api.corp.example"], &["10.0.0.0/8"]),
            ("m2.internal", &["*.Dev.Corp.Example."], &["10.1.0.1/16", "192.168.0.0/16"]),
            ("nas.corp.example", &[], &[]),
        ])
        .unwrap();
        let s = |v: &str| v.to_string();
        assert_eq!(
            overlaps(&t),
            [
                // The catch-all first: everything named elsewhere is within it.
                (s("*.dev.corp.example"), 1, s("*"), 0),
                (s("m2.internal"), 1, s("*"), 0),
                (s("nas.corp.example"), 2, s("*"), 0),
                // Then the zone: another's inner zone, and a host in it.
                (s("*.dev.corp.example"), 1, s("*.corp.example"), 0),
                (s("nas.corp.example"), 2, s("*.corp.example"), 0),
                // Then the networks.
                (s("10.1.0.0/16"), 1, s("10.0.0.0/8"), 0),
            ]
        );
        // None of these meet another destination's rule.
        let apart = table(&[
            ("m1.internal", &["*.corp.example", "api.corp.example"], &["10.0.0.0/8", "10.1.0.0/16"]),
            ("m2.internal", &["corp.example", "*.notcorp.example"], &["11.0.0.0/8"]),
        ])
        .unwrap();
        assert!(apart.overlaps().is_empty(), "{:?}", overlaps(&apart));
        let overlap = &t.overlaps()[3];
        assert_eq!(overlap.to_string(), "*.dev.corp.example is within *.corp.example");
    }

    /// The rows are the table in the order a target is tried against it.
    #[test]
    fn rows_run_most_specific_first() {
        let t = table(&[
            ("m1.internal", &["*", "*.corp.example"], &["10.0.0.0/8", "fd00::/8"]),
            ("m2.internal", &["*.dev.corp.example", "wiki.example"], &["10.1.0.0/16"]),
        ])
        .unwrap();
        let rows: Vec<(String, usize)> = t.rows().iter().map(|r| (r.rule.to_string(), r.dest)).collect();
        let expected: Vec<(String, usize)> = [
            ("m1.internal", 0),
            ("m2.internal", 1),
            ("wiki.example", 1),
            ("*.dev.corp.example", 1),
            ("*.corp.example", 0),
            ("*", 0),
            ("10.1.0.0/16", 1),
            ("10.0.0.0/8", 0),
            ("fd00::/8", 0),
        ]
        .iter()
        .map(|(r, d)| (r.to_string(), *d))
        .collect();
        assert_eq!(rows, expected);
        assert!(matches!(t.rows()[0].rule, TableRule::Host(_)));
        // Each row routes as the table does.
        for row in t.rows() {
            if let TableRule::Routed(Rule::Exact(name)) = &row.rule {
                assert_eq!(t.route(&domain(name, 443)), connect_to(row.dest, domain(name, 443)));
            }
        }
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
        // ones with underscores included) and wildcards.
        table(&[(
            "m1.internal",
            &["*", "db.internal", "my_host", "*.corp.example", " Padded.Example ", "fqdn.example."],
            &[],
        )])
        .unwrap();
    }

    /// An address among the routed domains would never match — IP targets are
    /// routed by the networks only — and so would send what it was meant to
    /// tunnel out directly. It is refused, with where it belongs.
    #[test]
    fn an_address_is_not_a_routed_domain() {
        for address in ["10.20.30.40", " 10.20.30.40 ", "2001:db8::1", "[2001:db8::1]"] {
            let message = table(&[("m1.internal", &[address], &[])]).unwrap_err().to_string();
            assert!(
                message.contains("routed_domains")
                    && message.contains(&format!("{address:?}"))
                    && message.contains("routed_cidrs"),
                "{address:?}: {message}"
            );
        }
        // Where it belongs, it routes the address in either target form.
        let t = table(&[("m1.internal", &[], &["10.20.30.40"])]).unwrap();
        let literal = domain("10.20.30.40", 443);
        assert_eq!(t.route(&literal), connect_to(0, literal.clone()));
        let ip = Target::Ip("10.20.30.40:443".parse().unwrap());
        assert_eq!(t.route(&ip), connect_to(0, ip.clone()));
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
