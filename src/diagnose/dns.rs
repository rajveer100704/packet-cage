//! DNS: names that don't resolve, servers that don't answer, slow lookups.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;

use super::{Category, Context, Finding, Severity, count, frames_filter, ip_filter, list, quoted};
use crate::analyze::dns::{Lookup, Outcome, SLOW_SECS};
use crate::decode::dns::{self as wire, RCODE_NXDOMAIN, RCODE_REFUSED, RCODE_SERVFAIL};
use crate::names;
use crate::units;

pub(super) fn findings(ctx: &Context) -> Vec<Finding> {
    let log = &ctx.analyzer.dns;
    let end = log.capture_end();
    let lookups = log.lookups();
    let searched = search_domain_tries(lookups);

    let mut failed: BTreeMap<(String, u8), Vec<&Lookup>> = BTreeMap::new();
    let mut unanswered: BTreeMap<IpAddr, Vec<&Lookup>> = BTreeMap::new();
    let mut unreachable: BTreeMap<(IpAddr, String), Vec<&Lookup>> = BTreeMap::new();
    let mut unreadable: BTreeMap<IpAddr, Vec<&Lookup>> = BTreeMap::new();
    let mut slow: BTreeMap<IpAddr, Vec<&Lookup>> = BTreeMap::new();
    let mut per_server: HashMap<IpAddr, u64> = HashMap::new();
    for (i, lookup) in lookups.iter().enumerate() {
        let server = lookup.server.ip();
        *per_server.entry(server).or_default() += 1;
        match lookup.outcome(end) {
            Outcome::Failed(RCODE_NXDOMAIN) if searched.contains(&i) => {}
            Outcome::Failed(rcode) => failed
                .entry((name(lookup), rcode))
                .or_default()
                .push(lookup),
            Outcome::NoResponse => unanswered.entry(server).or_default().push(lookup),
            Outcome::Unreachable => {
                let icmp = lookup.icmp_error.expect("unreachable means an ICMP error");
                let what = names::icmp(icmp.v6, icmp.icmp_type, icmp.code);
                unreachable.entry((server, what)).or_default().push(lookup);
            }
            Outcome::Malformed => unreadable.entry(server).or_default().push(lookup),
            Outcome::Answered | Outcome::NoData | Outcome::Truncated => {
                if lookup.is_slow() || !lookup.retries.is_empty() {
                    slow.entry(server).or_default().push(lookup);
                }
            }
            Outcome::CaptureEnded => {}
        }
    }

    let mut out = Vec::new();
    for ((name, rcode), group) in failed {
        let (severity, what, hint) = match rcode {
            // Many addresses have no reverse name, and clients probe for
            // services that may not exist: neither is a failure as such.
            RCODE_NXDOMAIN if is_reverse(&name) => (
                Severity::Info,
                "no reverse DNS name for this address (NXDOMAIN".to_string(),
                None,
            ),
            RCODE_NXDOMAIN if name.starts_with('_') => (
                Severity::Warning,
                "no such service record (NXDOMAIN".to_string(),
                Some(
                    "clients look services up this way; check that the service is registered in DNS",
                ),
            ),
            RCODE_NXDOMAIN => (
                Severity::Error,
                "name does not exist (NXDOMAIN".to_string(),
                None,
            ),
            RCODE_SERVFAIL => (
                Severity::Error,
                "the DNS server could not get an answer (SERVFAIL".to_string(),
                Some(
                    "the servers responsible for this name did not answer, or DNSSEC validation failed",
                ),
            ),
            RCODE_REFUSED => (
                Severity::Error,
                "the DNS server refused to answer (REFUSED".to_string(),
                Some(
                    "this server does not answer this client or this name; check which DNS server the client uses",
                ),
            ),
            rcode => (
                Severity::Warning,
                format!("DNS error: {} (code {rcode}", wire::rcode_text(rcode)),
                None,
            ),
        };
        let queries = queries(&group);
        let text = if queries > 1 {
            format!("{what}, asked {queries} times)")
        } else {
            format!("{what})")
        };
        out.push(
            Finding::new(severity, Category::Dns, name.clone(), text)
                .maybe_hint(hint)
                .frames(
                    group
                        .iter()
                        .filter_map(|l| Some(l.response.as_ref()?.frame)),
                )
                .measure("queries", queries as f64)
                .filter(format!(
                    "lower(dns.qry.name) == {} && dns.flags.rcode == {rcode}",
                    quoted(&name)
                )),
        );
    }

    for (server, group) in unanswered {
        let total = per_server[&server];
        let n = group.len() as u64;
        let (severity, text, hint) = if n == total {
            (
                Severity::Error,
                format!("DNS server never answered ({})", asked(&group)),
                "the server is down or unreachable, or a firewall drops DNS",
            )
        } else {
            (
                Severity::Warning,
                format!(
                    "no answer to {} of {} lookups ({})",
                    units::count(n),
                    units::count(total),
                    names_of(&group)
                ),
                "queries or answers were lost on the way, or the server was overloaded",
            )
        };
        out.push(
            Finding::new(severity, Category::Dns, ctx.host(server), text)
                .hint(hint)
                .frames(
                    group
                        .iter()
                        .flat_map(|l| std::iter::once(l.query_frame).chain(l.retries.clone())),
                )
                .measure("lookups", n as f64)
                .filter(format!(
                    "dns.flags.response == 0 && !dns.response_in && {}",
                    ip_filter("dst", server)
                )),
        );
    }

    for ((server, what), group) in unreachable {
        let hint = what
            .contains("port unreachable")
            .then_some("nothing listens for DNS at that address");
        let icmp: Vec<u64> = group
            .iter()
            .filter_map(|l| Some(l.icmp_error?.frame))
            .collect();
        let what = what
            .strip_prefix("destination unreachable (")
            .and_then(|w| w.strip_suffix(')'))
            .unwrap_or(&what);
        out.push(
            Finding::new(
                Severity::Error,
                Category::Dns,
                ctx.host(server),
                format!("DNS server unreachable (ICMP {what}): {}", asked(&group)),
            )
            .maybe_hint(hint)
            .frames(icmp.iter().copied())
            .measure("lookups", group.len() as f64)
            .filter(frames_filter(&icmp)),
        );
    }

    for (server, group) in unreadable {
        let responses: Vec<u64> = group
            .iter()
            .filter_map(|l| Some(l.response.as_ref()?.frame))
            .collect();
        out.push(
            Finding::new(
                Severity::Warning,
                Category::Dns,
                ctx.host(server),
                format!(
                    "{} could not be read ({})",
                    count(group.len() as u64, "response", "responses"),
                    names_of(&group)
                ),
            )
            .frames(responses.iter().copied())
            .measure("lookups", group.len() as f64)
            .filter(frames_filter(&responses)),
        );
    }

    for (server, mut group) in slow {
        group.sort_by(|a, b| {
            b.latency()
                .unwrap_or(0.0)
                .total_cmp(&a.latency().unwrap_or(0.0))
        });
        let total = per_server[&server];
        let late = group.iter().filter(|l| l.is_slow()).count() as u64;
        let retried = group.iter().filter(|l| !l.retries.is_empty()).count() as u64;
        let worst = group[0];
        let mut text = if late > 0 {
            format!(
                "{} of {} lookups took over {:.0} ms (slowest: {}, {})",
                units::count(late),
                units::count(total),
                SLOW_SECS * 1000.0,
                name(worst),
                units::duration(worst.latency().unwrap_or(0.0))
            )
        } else {
            format!(
                "{} of {} lookups had to be sent again",
                units::count(retried),
                units::count(total)
            )
        };
        if late > 0 && retried > 0 {
            text.push_str(&format!("; {} had to be sent again", units::count(retried)));
        }
        let hint = if retried > 0 {
            "queries or answers were lost on the way to the DNS server"
        } else {
            "the DNS server is slow to answer"
        };
        out.push(
            Finding::new(Severity::Warning, Category::Dns, ctx.host(server), text)
                .hint(hint)
                .spans(group.iter().take(5).filter_map(|l| {
                    let response = l.response.as_ref()?;
                    Some((l.query_frame, response.frame))
                }))
                .measure("lookups", (late.max(retried)) as f64)
                .measure("slowest_secs", worst.latency().unwrap_or(0.0))
                .filter(frames_filter(&exchange_frames(&group))),
        );
    }

    if !log.malformed.is_empty() {
        out.push(
            Finding::new(
                Severity::Info,
                Category::Dns,
                "port 53",
                format!(
                    "{} sent to or from port 53 are not DNS",
                    count(log.malformed.len() as u64, "packet", "packets")
                ),
            )
            .frames(log.malformed.iter().copied())
            .measure("packets", log.malformed.len() as f64)
            .filter(frames_filter(&log.malformed)),
        );
    }
    out
}

/// Lookups that are a name with a search domain added. A resolver tries
/// "api.example.com.corp.local" along with "api.example.com"; the first
/// failing is the resolver at work, not a problem.
fn search_domain_tries(lookups: &[Lookup]) -> HashSet<usize> {
    let asked: HashSet<(IpAddr, String)> = lookups
        .iter()
        .filter(|l| l.question.is_some())
        .map(|l| (l.client.ip(), name(l)))
        .collect();
    lookups
        .iter()
        .enumerate()
        .filter(|(_, l)| {
            let full = name(l);
            full.match_indices('.')
                .any(|(i, _)| asked.contains(&(l.client.ip(), full[..i].to_string())))
        })
        .map(|(i, _)| i)
        .collect()
}

/// A reverse lookup: the name of an address.
fn is_reverse(name: &str) -> bool {
    name.ends_with(".in-addr.arpa") || name.ends_with(".ip6.arpa")
}

/// The name looked up, in lower case (DNS ignores case).
fn name(lookup: &Lookup) -> String {
    lookup
        .question
        .as_ref()
        .map_or_else(|| "?".to_string(), |q| q.name.to_ascii_lowercase())
}

/// Every query, retry and response of these lookups.
fn exchange_frames(group: &[&Lookup]) -> Vec<u64> {
    group
        .iter()
        .flat_map(|l| {
            std::iter::once(l.query_frame)
                .chain(l.retries.iter().copied())
                .chain(l.response.as_ref().map(|r| r.frame))
        })
        .collect()
}

/// Queries sent, retries included.
fn queries(group: &[&Lookup]) -> u64 {
    group.iter().map(|l| 1 + l.retries.len() as u64).sum()
}

/// "api.example.com, cdn.example.com and 3 more"
fn names_of(group: &[&Lookup]) -> String {
    let mut seen = HashSet::new();
    let names: Vec<String> = group
        .iter()
        .map(|l| name(l))
        .filter(|n| seen.insert(n.clone()))
        .collect();
    list(&names, 3)
}

/// "3 queries for api.example.com", "5 queries: a, b and 2 more"
fn asked(group: &[&Lookup]) -> String {
    let queries = count(queries(group), "query", "queries");
    let names = names_of(group);
    if group.iter().all(|l| name(l) == name(group[0])) {
        format!("{queries} for {names}")
    } else {
        format!("{queries}: {names}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::Timestamp;
    use crate::decode::dns::Question;

    fn lookup(client: &str, name: &str) -> Lookup {
        Lookup {
            client: client.parse().unwrap(),
            server: "10.0.0.53:53".parse().unwrap(),
            over_tcp: false,
            id: 1,
            question: Some(Question {
                name: name.to_string(),
                qtype: 1,
                qclass: 1,
            }),
            query_frame: 1,
            query_ts: Timestamp(0),
            retries: Vec::new(),
            last_query_ts: Timestamp(0),
            response: None,
            icmp_error: None,
        }
    }

    #[test]
    fn search_domain_tries_are_recognized() {
        let lookups = [
            lookup("10.0.0.5:5000", "api.example.com.corp.local"),
            lookup("10.0.0.5:5001", "API.example.com"),
            lookup("10.0.0.6:5000", "db.corp.local"),
            lookup("10.0.0.6:5001", "db.corp.local.corp.local"),
            // Another client asked for x.example.com, not this one.
            lookup("10.0.0.7:5000", "x.example.com.corp.local"),
            lookup("10.0.0.8:5000", "x.example.com"),
        ];
        assert_eq!(search_domain_tries(&lookups), HashSet::from([0, 3]));
    }
}
