//! Capture-wide numbers for `packet-cage stats`: protocol mix, busiest hosts
//! and conversations.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write;
use std::net::IpAddr;

use crate::analyze::Analyzer;
use crate::analyze::dns::{DnsLog, Lookup, Outcome, SLOW_SECS};
use crate::analyze::http::{self as http_analysis, Exchange};
use crate::analyze::tcp::TcpHealth;
use crate::analyze::tls::{Handshake, TlsResult};
use crate::capture::{Frame, Timestamp};
use crate::decode::dns as dns_wire;
use crate::decode::tls as tls_wire;
use crate::decode::{Link, Network, Packet, Problem, Transport};
use crate::flow::{Counter, Flow, FlowTable, ResetKind, Side, TcpConn, TcpStatus};
use crate::names;
use crate::units::{self, Align, Table};

#[derive(Debug, Default)]
pub struct Stats {
    pub total: Counter,
    pub first_ts: Option<Timestamp>,
    pub last_ts: Option<Timestamp>,
    /// Protocol hierarchy; the root itself is unnamed.
    pub protocols: ProtocolNode,
    pub hosts: HashMap<IpAddr, Host>,
    /// Packets the capture kept only the start of.
    pub snapped: Sample,
    /// The most bytes kept of a snapped packet: the capture's length limit.
    pub snaplen: u32,
    /// Packets that could not be decoded, as opposed to merely cut short.
    pub malformed: Sample,
}

/// Packets of one kind: how many, and the first few frame numbers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sample {
    pub count: u64,
    pub frames: Vec<u64>,
}

impl Sample {
    const KEEP: usize = 10;

    fn add(&mut self, frame: u64) {
        self.count += 1;
        if self.frames.len() < Self::KEEP {
            self.frames.push(frame);
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Host {
    pub sent: Counter,
    pub received: Counter,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ProtocolNode {
    pub name: String,
    pub count: Counter,
    pub children: Vec<ProtocolNode>,
}

impl ProtocolNode {
    fn add(&mut self, path: &[String], bytes: u64) {
        let Some((first, rest)) = path.split_first() else {
            return;
        };
        let i = match self.children.iter().position(|c| &c.name == first) {
            Some(i) => i,
            None => {
                self.children.push(ProtocolNode {
                    name: first.clone(),
                    ..Default::default()
                });
                self.children.len() - 1
            }
        };
        self.children[i].count.add(bytes);
        self.children[i].add(rest, bytes);
    }

    /// Children with the most bytes first.
    pub fn sorted_children(&self) -> Vec<&ProtocolNode> {
        let mut children: Vec<&ProtocolNode> = self.children.iter().collect();
        children.sort_by(|a, b| {
            b.count
                .bytes
                .cmp(&a.count.bytes)
                .then_with(|| a.name.cmp(&b.name))
        });
        children
    }
}

impl Stats {
    pub fn add(&mut self, frame: &Frame, pkt: &Packet<'_>) {
        let bytes = u64::from(frame.orig_len);
        self.total.add(bytes);
        self.first_ts = Some(self.first_ts.map_or(frame.ts, |t| t.min(frame.ts)));
        self.last_ts = Some(self.last_ts.map_or(frame.ts, |t| t.max(frame.ts)));
        self.protocols.add(&protocol_path(pkt), bytes);
        if let Some((src, dst)) = pkt.network.as_ref().and_then(Network::ip_addrs) {
            self.hosts.entry(src).or_default().sent.add(bytes);
            self.hosts.entry(dst).or_default().received.add(bytes);
        }
        let kept = u32::try_from(frame.data.len()).unwrap_or(u32::MAX);
        if kept < frame.orig_len {
            self.snapped.add(frame.number);
            self.snaplen = self.snaplen.max(kept);
        }
        if pkt
            .error
            .as_ref()
            .is_some_and(|e| e.problem != Problem::CutShort)
        {
            self.malformed.add(frame.number);
        }
    }

    pub fn duration_secs(&self) -> f64 {
        match (self.first_ts, self.last_ts) {
            (Some(first), Some(last)) => last.secs_since(first),
            _ => 0.0,
        }
    }

    /// Hosts by bytes sent plus received, largest first.
    pub fn busiest_hosts(&self) -> Vec<(IpAddr, Host)> {
        let mut hosts: Vec<(IpAddr, Host)> = self.hosts.iter().map(|(ip, h)| (*ip, *h)).collect();
        hosts.sort_by(|(a_ip, a), (b_ip, b)| {
            let total = |h: &Host| h.sent.bytes + h.received.bytes;
            total(b).cmp(&total(a)).then_with(|| a_ip.cmp(b_ip))
        });
        hosts
    }
}

/// Where a packet sits in the protocol tree, e.g. ["IPv4", "TCP"].
fn protocol_path(pkt: &Packet<'_>) -> Vec<String> {
    let mut path = Vec::new();
    match &pkt.network {
        Some(Network::Ipv4(h)) => {
            path.push("IPv4".to_string());
            if h.fragment_offset > 0 {
                path.push("fragments".to_string());
            }
        }
        Some(Network::Ipv6(h)) => {
            path.push("IPv6".to_string());
            if h.fragment.is_some_and(|f| f.offset > 0) {
                path.push("fragments".to_string());
            }
        }
        Some(Network::Arp(_)) => path.push("ARP".to_string()),
        Some(Network::Other { ethertype }) => path.push(names::ethertype(*ethertype)),
        // Decoding stopped at the link layer.
        None => match &pkt.link {
            Link::Ethernet { ethertype, .. } => path.push(names::ethertype(*ethertype)),
            Link::Unsupported(lt) => path.push(format!("link type {lt}")),
            Link::LinuxCooked | Link::Loopback | Link::RawIp => {}
        },
    }
    match &pkt.transport {
        Some(Transport::Tcp(_)) => path.push("TCP".to_string()),
        Some(Transport::Udp(_)) => path.push("UDP".to_string()),
        Some(Transport::Icmp(i)) => path.push(if i.v6 { "ICMPv6" } else { "ICMP" }.to_string()),
        Some(Transport::Other { protocol }) => path.push(names::ip_protocol(*protocol)),
        None => {}
    }
    if pkt.error.is_some() {
        path.push("malformed".to_string());
    }
    path
}

/// Text report for `packet-cage stats`; tables show at most `top` rows.
pub fn render(stats: &Stats, analyzer: &Analyzer, top: usize) -> String {
    let (flows, dns) = (&analyzer.flows, &analyzer.dns);
    let mut out = String::new();
    let duration = stats.duration_secs();
    let _ = writeln!(out, "Packets   {}", units::count(stats.total.packets));
    let _ = writeln!(out, "Bytes     {}", units::bytes(stats.total.bytes));
    if let Some(first) = stats.first_ts {
        let _ = writeln!(out, "Start     {}", units::utc(first));
        let _ = writeln!(out, "Duration  {}", units::duration(duration));
    }
    if duration > 0.0 {
        let _ = writeln!(
            out,
            "Rate      {:.1} packets/s, {}",
            stats.total.packets as f64 / duration,
            units::bitrate(stats.total.bytes as f64 * 8.0 / duration)
        );
    }

    let mut table = Table::new(&[
        ("Protocol", Align::Left),
        ("Packets", Align::Right),
        ("%", Align::Right),
        ("Bytes", Align::Right),
        ("%", Align::Right),
    ]);
    add_protocol_rows(&mut table, &stats.protocols, &stats.total, 0);
    let _ = write!(out, "\n{}", table.render());

    let hosts = stats.busiest_hosts();
    if !hosts.is_empty() {
        let shown = &hosts[..hosts.len().min(top)];
        let named = shown.iter().any(|(ip, _)| analyzer.name_of(*ip).is_some());
        let mut columns = vec![("Host", Align::Left)];
        if named {
            columns.push(("Name", Align::Left));
        }
        columns.extend([
            ("Packets sent", Align::Right),
            ("Bytes sent", Align::Right),
            ("Packets received", Align::Right),
            ("Bytes received", Align::Right),
        ]);
        let mut table = Table::new(&columns);
        for (ip, host) in shown {
            let mut row = vec![ip.to_string()];
            if named {
                row.push(analyzer.name_of(*ip).unwrap_or("").to_string());
            }
            row.extend([
                units::count(host.sent.packets),
                units::bytes(host.sent.bytes),
                units::count(host.received.packets),
                units::bytes(host.received.bytes),
            ]);
            table.row(row);
        }
        let _ = write!(
            out,
            "\n{}{}",
            heading("Hosts", hosts.len(), top, "by bytes"),
            table.render()
        );
    }

    for (name, tcp) in [("TCP", true), ("UDP", false)] {
        let mut list: Vec<(usize, &Flow)> = flows
            .flows()
            .iter()
            .enumerate()
            .filter(|(_, f)| f.tcp.is_some() == tcp)
            .collect();
        if list.is_empty() {
            continue;
        }
        list.sort_by(|(_, a), (_, b)| {
            b.bytes()
                .cmp(&a.bytes())
                .then_with(|| a.stream.cmp(&b.stream))
        });
        let named = list
            .iter()
            .take(top)
            .any(|(i, _)| analyzer.server_name(*i).is_some());
        let mut columns = vec![
            ("Stream", Align::Right),
            ("Client", Align::Left),
            ("Server", Align::Left),
        ];
        if named {
            columns.push(("Server name", Align::Left));
        }
        columns.extend([
            ("Packets", Align::Right),
            ("Client→Server", Align::Right),
            ("Server→Client", Align::Right),
            ("Duration", Align::Right),
        ]);
        if tcp {
            columns.push(("RTT", Align::Right));
            columns.push(("Wait", Align::Right));
            columns.push(("Retrans", Align::Right));
            columns.push(("State", Align::Left));
        }
        let mut table = Table::new(&columns);
        let mut joined_late = false;
        for &(index, flow) in list.iter().take(top) {
            let mut row = vec![
                flow.stream.to_string(),
                flow.client.to_string(),
                flow.server.to_string(),
            ];
            if named {
                row.push(analyzer.server_name(index).unwrap_or("").to_string());
            }
            row.extend([
                units::count(flow.packets()),
                units::bytes(flow.from_client.bytes),
                units::bytes(flow.from_server.bytes),
                units::duration(flow.duration_secs()),
            ]);
            if let Some(conn) = &flow.tcp {
                row.push(
                    conn.handshake_rtt()
                        .map_or("-".to_string(), |rtt| units::duration(rtt.total)),
                );
                row.push(
                    conn.longest_wait
                        .map_or("-".to_string(), |w| units::duration(w.secs)),
                );
                row.push(retransmissions(&combined(conn)));
                let mut state = conn.status().to_string();
                if conn.started_before_capture() {
                    state.push('*');
                    joined_late = true;
                }
                row.push(state);
            }
            table.row(row);
        }
        let title = format!("{name} conversations");
        let _ = write!(
            out,
            "\n{}{}",
            heading(&title, list.len(), top, "by bytes"),
            table.render()
        );
        if joined_late {
            let _ = writeln!(out, "* already open when the capture started");
        }
        if tcp {
            let _ = write!(out, "\n{}", tcp_problems(flows));
        }
    }
    out.push_str(&dns_section(dns, top));
    out.push_str(&tls_section(analyzer, top));
    out.push_str(&http_section(analyzer, top));
    out
}

/// HTTP requests by status, how long servers took, and the requests that
/// failed or were slow.
fn http_section(analyzer: &Analyzer, top: usize) -> String {
    let exchanges = analyzer.http.exchanges();
    if exchanges.is_empty() {
        return String::new();
    }
    let flows = analyzer.flows.flows();
    let conn = |e: &Exchange| flows[e.flow].tcp.as_ref().expect("HTTP runs over TCP");
    let connections: HashSet<usize> = exchanges.iter().map(|e| e.flow).collect();
    let mut out = format!(
        "\nHTTP: {} request{} on {} connection{}\n",
        units::count(exchanges.len() as u64),
        if exchanges.len() == 1 { "" } else { "s" },
        connections.len(),
        if connections.len() == 1 { "" } else { "s" }
    );

    // Status classes, with the individual codes for errors.
    let mut classes: BTreeMap<String, (u64, BTreeMap<u16, u64>)> = BTreeMap::new();
    for exchange in exchanges {
        let class = match &exchange.response {
            Some(r) => format!("{}xx", r.status / 100),
            None => "no response".to_string(),
        };
        let entry = classes.entry(class).or_default();
        entry.0 += 1;
        if let Some(r) = exchange.response.as_ref().filter(|r| r.status >= 400) {
            *entry.1.entry(r.status).or_default() += 1;
        }
    }
    let mut table = Table::new(&[
        ("Status", Align::Left),
        ("Count", Align::Right),
        ("", Align::Left),
    ]);
    for (class, (n, codes)) in &classes {
        let note = codes
            .iter()
            .map(|(code, n)| format!("{code}: {n}"))
            .collect::<Vec<_>>()
            .join(", ");
        table.row(vec![class.clone(), units::count(*n), note]);
    }
    out.push_str(&table.render());

    let mut server: Vec<f64> = exchanges
        .iter()
        .filter_map(|e| e.server_time(conn(e)))
        .collect();
    server.sort_by(f64::total_cmp);
    if !server.is_empty() {
        let _ = writeln!(
            out,
            "Server time: median {}, slowest {}",
            units::duration(server[server.len() / 2]),
            units::duration(server[server.len() - 1])
        );
    }

    let slow = |e: &Exchange| {
        let wait = e.server_time(conn(e)).or_else(|| e.time_to_first_byte());
        wait.is_some_and(|w| w > http_analysis::SLOW_SERVER_SECS)
    };
    let mut problems: Vec<&Exchange> = exchanges
        .iter()
        .filter(|e| {
            let failed = e.response.as_ref().is_some_and(|r| r.status >= 400);
            let unanswered = e.request.is_some() && e.response.is_none();
            failed || unanswered || slow(e)
        })
        .collect();
    if problems.is_empty() {
        return out;
    }
    // Server errors first, then the slowest.
    problems.sort_by(|a, b| {
        let status = |e: &Exchange| e.response.as_ref().map_or(1000, |r| r.status);
        let wait = |e: &Exchange| e.time_to_first_byte().unwrap_or(0.0);
        status(b)
            .cmp(&status(a))
            .then_with(|| wait(b).total_cmp(&wait(a)))
    });
    let mut table = Table::new(&[
        ("Request", Align::Left),
        ("Server", Align::Left),
        ("Status", Align::Left),
        ("First byte", Align::Right),
        ("Server time", Align::Right),
        ("Frame", Align::Right),
    ]);
    for exchange in problems.iter().take(top) {
        table.row(vec![
            exchange.label(),
            flows[exchange.flow].server.to_string(),
            exchange
                .response
                .as_ref()
                .map_or("no response".to_string(), |r| {
                    format!("{} {}", r.status, r.reason)
                }),
            exchange
                .time_to_first_byte()
                .map_or("-".to_string(), units::duration),
            exchange
                .server_time(conn(exchange))
                .map_or("-".to_string(), units::duration),
            exchange
                .request_frame
                .or(exchange.response_start.map(|a| a.frame))
                .map_or("-".to_string(), |f| f.to_string()),
        ]);
    }
    let _ = write!(
        out,
        "\n{}{}",
        heading("Problem requests", problems.len(), top, "worst first"),
        table.render()
    );
    out
}

/// How TLS handshakes ended, which versions were agreed, and the ones with
/// problems.
fn tls_section(analyzer: &Analyzer, top: usize) -> String {
    let handshakes = analyzer.tls.handshakes();
    if handshakes.is_empty() {
        return String::new();
    }
    let flows = analyzer.flows.flows();
    let conn = |h: &Handshake| flows[h.flow].tcp.as_ref().expect("TLS runs over TCP");
    let mut out = format!(
        "\nTLS: {} handshake{}\n",
        units::count(handshakes.len() as u64),
        if handshakes.len() == 1 { "" } else { "s" }
    );

    let mut results: BTreeMap<TlsResult, u64> = BTreeMap::new();
    let mut versions: BTreeMap<u16, u64> = BTreeMap::new();
    for handshake in handshakes {
        let result = handshake.result();
        *results.entry(result).or_default() += 1;
        if result == TlsResult::Completed
            && let Some(version) = handshake.version()
        {
            *versions.entry(version).or_default() += 1;
        }
    }
    let mut table = Table::new(&[
        ("Result", Align::Left),
        ("Count", Align::Right),
        ("", Align::Left),
    ]);
    for (result, n) in &results {
        let note = if *result == TlsResult::Completed {
            versions
                .iter()
                .rev()
                .map(|(v, n)| format!("{}: {n}", tls_wire::version_name(*v)))
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            String::new()
        };
        table.row(vec![result.to_string(), units::count(*n), note]);
    }
    out.push_str(&table.render());

    let problems: Vec<(&Handshake, Vec<String>)> = handshakes
        .iter()
        .map(|h| {
            (
                h,
                h.problems(conn(h))
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
            )
        })
        .filter(|(_, p)| !p.is_empty())
        .collect();
    if problems.is_empty() {
        return out;
    }
    let mut table = Table::new(&[
        ("Server", Align::Left),
        ("Name", Align::Left),
        ("Version", Align::Left),
        ("Problem", Align::Left),
        ("Hello delay", Align::Right),
        ("Frame", Align::Right),
    ]);
    for (handshake, found) in problems.iter().take(top) {
        let flow = &flows[handshake.flow];
        table.row(vec![
            flow.server.to_string(),
            handshake.server_name().unwrap_or("").to_string(),
            handshake
                .version()
                .map_or("-".to_string(), tls_wire::version_name),
            found.join("; "),
            handshake
                .server_hello_delay()
                .map_or("-".to_string(), units::duration),
            handshake
                .client_hello
                .as_ref()
                .map_or("-".to_string(), |(at, _)| at.frame.to_string()),
        ]);
    }
    let _ = write!(
        out,
        "\n{}{}",
        heading(
            "Problem handshakes",
            problems.len(),
            top,
            "in capture order"
        ),
        table.render()
    );
    out
}

/// Outcomes of all DNS lookups, then the ones that went wrong.
fn dns_section(log: &DnsLog, top: usize) -> String {
    let lookups = log.lookups();
    if lookups.is_empty() && log.unmatched_responses.is_empty() && log.malformed.is_empty() {
        return String::new();
    }
    let end = log.capture_end();
    let servers: HashSet<_> = lookups.iter().map(|l| l.server).collect();
    let mut out = format!(
        "\nDNS: {} lookup{} to {} server{}\n",
        units::count(lookups.len() as u64),
        if lookups.len() == 1 { "" } else { "s" },
        servers.len(),
        if servers.len() == 1 { "" } else { "s" }
    );

    let mut outcomes: BTreeMap<Outcome, u64> = BTreeMap::new();
    for lookup in lookups {
        *outcomes.entry(lookup.outcome(end)).or_default() += 1;
    }
    let mut latencies: Vec<f64> = lookups.iter().filter_map(Lookup::latency).collect();
    latencies.sort_by(f64::total_cmp);
    let mut table = Table::new(&[
        ("Result", Align::Left),
        ("Count", Align::Right),
        ("", Align::Left),
    ]);
    // Answers first, then problems in order of how bad they are.
    let routine = [Outcome::Answered, Outcome::NoData, Outcome::Truncated];
    let rest = outcomes.keys().copied().filter(|o| !routine.contains(o));
    for outcome in routine.into_iter().chain(rest) {
        let Some(&n) = outcomes.get(&outcome) else {
            continue;
        };
        let note = match outcome {
            Outcome::Answered if !latencies.is_empty() => format!(
                "response time: median {}, slowest {}",
                units::duration(latencies[latencies.len() / 2]),
                units::duration(latencies[latencies.len() - 1])
            ),
            _ => String::new(),
        };
        table.row(vec![outcome.to_string(), units::count(n), note]);
    }
    let retried = lookups.iter().filter(|l| !l.retries.is_empty()).count() as u64;
    let slow = lookups.iter().filter(|l| l.is_slow()).count() as u64;
    let extras = [
        ("Retried", retried, "query sent more than once".to_string()),
        (
            "Slow",
            slow,
            format!("answered after more than {}", units::duration(SLOW_SECS)),
        ),
        (
            "Query not captured",
            log.unmatched_responses.len() as u64,
            "response to a query sent before the capture began".to_string(),
        ),
        (
            "Malformed",
            log.malformed.len() as u64,
            "port 53 packets that are not valid DNS".to_string(),
        ),
    ];
    for (name, n, note) in extras {
        if n > 0 {
            table.row(vec![name.to_string(), units::count(n), note]);
        }
    }
    out.push_str(&table.render());

    let mut problems: Vec<&Lookup> = lookups
        .iter()
        .filter(|l| {
            let bad = !matches!(
                l.outcome(end),
                Outcome::Answered | Outcome::NoData | Outcome::Truncated | Outcome::CaptureEnded
            );
            bad || l.is_slow() || !l.retries.is_empty()
        })
        .collect();
    if problems.is_empty() {
        return out;
    }
    problems.sort_by(|a, b| {
        a.outcome(end)
            .cmp(&b.outcome(end))
            .then_with(|| {
                b.latency()
                    .unwrap_or(0.0)
                    .total_cmp(&a.latency().unwrap_or(0.0))
            })
            .then_with(|| a.query_frame.cmp(&b.query_frame))
    });
    let mut table = Table::new(&[
        ("Name", Align::Left),
        ("Type", Align::Left),
        ("Server", Align::Left),
        ("Result", Align::Left),
        ("Time", Align::Right),
        ("Sent", Align::Right),
        ("Frame", Align::Right),
    ]);
    for lookup in problems.iter().take(top) {
        let (name, qtype) = lookup.question.as_ref().map_or_else(
            || ("?".to_string(), "?".to_string()),
            |q| (q.name.clone(), dns_wire::type_name(q.qtype)),
        );
        table.row(vec![
            name,
            qtype,
            lookup.server.to_string(),
            lookup.outcome(end).to_string(),
            lookup.latency().map_or("-".to_string(), units::duration),
            (1 + lookup.retries.len()).to_string(),
            lookup.query_frame.to_string(),
        ]);
    }
    let _ = write!(
        out,
        "\n{}{}",
        heading("Problem lookups", problems.len(), top, "worst first"),
        table.render()
    );
    out
}

/// Both directions of a connection added together.
fn combined(conn: &TcpConn) -> TcpHealth {
    let mut health = conn.health(Side::Client).clone();
    health.add(conn.health(Side::Server));
    health
}

fn retransmissions(health: &TcpHealth) -> String {
    match health.retransmissions.count {
        0 => "-".to_string(),
        n => format!("{n} ({})", units::percent(u64::from(n), health.segments)),
    }
}

/// Totals over every TCP connection. Only problems that occurred are listed.
fn tcp_problems(flows: &FlowTable) -> String {
    let mut total = TcpHealth::default();
    let (mut retransmitting, mut refused, mut aborted, mut unanswered) = (0u64, 0u64, 0u64, 0u64);
    for conn in flows.flows().iter().filter_map(|f| f.tcp.as_ref()) {
        let health = combined(conn);
        if health.retransmissions.count > 0 {
            retransmitting += 1;
        }
        total.add(&health);
        match conn.reset.map(|r| r.kind) {
            Some(ResetKind::Refused) => refused += 1,
            Some(ResetKind::Aborted) => aborted += 1,
            Some(ResetKind::WhileClosing) | None => {}
        }
        if conn.status() == TcpStatus::NoAnswer {
            unanswered += 1;
        }
    }

    let mut retrans_note = format!(
        "{} of segments sent, in {} connection{}",
        units::percent(u64::from(total.retransmissions.count), total.segments),
        retransmitting,
        if retransmitting == 1 { "" } else { "s" }
    );
    let (fast, spurious) = (
        total.fast_retransmissions.count,
        total.spurious_retransmissions.count,
    );
    if fast > 0 || spurious > 0 {
        let _ = write!(retrans_note, "; {fast} fast, {spurious} spurious");
    }
    let rows: [(&str, u64, String); 10] = [
        (
            "Retransmissions",
            u64::from(total.retransmissions.count),
            retrans_note,
        ),
        (
            "Out-of-order segments",
            u64::from(total.out_of_order.count),
            String::new(),
        ),
        (
            "Duplicate ACKs",
            u64::from(total.duplicate_acks.count),
            String::new(),
        ),
        (
            "Zero window",
            u64::from(total.zero_windows.count),
            "receiver had no buffer space left".into(),
        ),
        (
            "Window full",
            u64::from(total.window_full.count),
            "sender had to wait for the receiver".into(),
        ),
        (
            "Not captured",
            u64::from(total.not_captured.count),
            "gaps in the sequence numbers".into(),
        ),
        (
            "ACKed, not captured",
            u64::from(total.acked_unseen.count),
            "acknowledged data the capture never saw".into(),
        ),
        (
            "Refused",
            refused,
            "connection attempts answered with RST".into(),
        ),
        (
            "Unanswered",
            unanswered,
            "connection attempts with no reply".into(),
        ),
        ("Aborted", aborted, "open connections ended by RST".into()),
    ];
    let mut table = Table::new(&[
        ("Problem", Align::Left),
        ("Count", Align::Right),
        ("", Align::Left),
    ]);
    let mut any = false;
    for (name, count, note) in rows {
        if count > 0 {
            table.row(vec![name.to_string(), units::count(count), note]);
            any = true;
        }
    }
    if any {
        format!("TCP problems\n{}", table.render())
    } else {
        "TCP problems: none found\n".to_string()
    }
}

fn add_protocol_rows(table: &mut Table, node: &ProtocolNode, total: &Counter, depth: usize) {
    for child in node.sorted_children() {
        table.row(vec![
            format!("{}{}", "  ".repeat(depth), child.name),
            units::count(child.count.packets),
            units::percent(child.count.packets, total.packets),
            units::bytes(child.count.bytes),
            units::percent(child.count.bytes, total.bytes),
        ]);
        add_protocol_rows(table, child, total, depth + 1);
    }
}

fn heading(title: &str, len: usize, top: usize, order: &str) -> String {
    if len > top {
        format!("{title}: {len}, showing top {top} {order}\n")
    } else {
        format!("{title}: {len}\n")
    }
}
