//! Turns what the analysis found into findings: what went wrong, in one
//! sentence, with the frames that show it. Each rule looks for one kind of
//! problem; connections no rule complains about count as healthy.

mod dns;
mod http;
mod slow;
mod tcp;
mod tls;

use std::collections::HashSet;
use std::fmt::Write;
use std::net::IpAddr;

use crate::analyze::Analyzer;
use crate::capture::Timestamp;
use crate::flow::{Flow, TcpConn};
use crate::stats::Stats;
use crate::units;

/// A query, request or connection attempt still unanswered this long before
/// the capture ended counts as unanswered; a later one may just have been
/// cut off by the end of the capture.
pub const GIVE_UP_SECS: f64 = 3.0;

/// Every measurement a finding can carry. Names ending in `_secs` are
/// durations and `_rate` fractions; the rest are counts.
pub const MEASUREMENTS: &[&str] = &[
    "attempts",
    "connections",
    "handshakes",
    "lookups",
    "network_rtt_secs",
    "packets",
    "queries",
    "requests",
    "retransmission_rate",
    "retransmissions",
    "segments",
    "server_secs",
    "slowest_secs",
    "wait_secs",
    "window_full",
    "zero_windows",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Worth knowing, but not a fault.
    Info,
    /// Something degraded: slow, lossy, or failing some of the time.
    Warning,
    /// Something failed.
    Error,
}

impl Severity {
    pub const ALL: [Severity; 3] = [Severity::Info, Severity::Warning, Severity::Error];

    pub fn name(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Category {
    Dns,
    /// Connections that failed to open or were cut.
    Tcp,
    /// Retransmissions and other signs of lost packets.
    Loss,
    /// Waiting on a server or a slow network.
    Slow,
    Tls,
    Http,
    /// The capture file itself.
    Capture,
}

impl Category {
    pub const ALL: [Category; 7] = [
        Category::Dns,
        Category::Tcp,
        Category::Loss,
        Category::Slow,
        Category::Tls,
        Category::Http,
        Category::Capture,
    ];

    /// Short label for reports.
    pub fn name(self) -> &'static str {
        match self {
            Category::Dns => "DNS",
            Category::Tcp => "TCP",
            Category::Loss => "LOSS",
            Category::Slow => "SLOW",
            Category::Tls => "TLS",
            Category::Http => "HTTP",
            Category::Capture => "FILE",
        }
    }

    /// Lower-case identifier for JSON.
    pub fn id(self) -> &'static str {
        match self {
            Category::Dns => "dns",
            Category::Tcp => "tcp",
            Category::Loss => "loss",
            Category::Slow => "slow",
            Category::Tls => "tls",
            Category::Http => "http",
            Category::Capture => "capture",
        }
    }
}

/// Frames `first` to `last`, both included.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Span {
    pub first: u64,
    pub last: u64,
}

/// A number behind a finding. The name carries the unit: `_secs`, `_rate`
/// (a fraction), or a count of what it names.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Measurement {
    pub name: &'static str,
    pub value: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub severity: Severity,
    pub category: Category,
    /// What it is about: a name, a server, a client and its server, or
    /// nothing for the capture itself.
    pub subject: String,
    /// What went wrong, in one sentence.
    pub text: String,
    /// What it most likely means, when the numbers point one way.
    pub hint: Option<String>,
    /// Frames that show it, in order, with neighbours merged.
    pub frames: Vec<Span>,
    pub measurements: Vec<Measurement>,
    /// A Wireshark display filter for the packets involved.
    pub filter: Option<String>,
    /// Connections it covers, by index in the flow table.
    pub flows: Vec<usize>,
}

impl Finding {
    fn new(
        severity: Severity,
        category: Category,
        subject: impl Into<String>,
        text: impl Into<String>,
    ) -> Self {
        Finding {
            severity,
            category,
            subject: subject.into(),
            text: text.into(),
            hint: None,
            frames: Vec::new(),
            measurements: Vec::new(),
            filter: None,
            flows: Vec::new(),
        }
    }

    fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    fn maybe_hint(mut self, hint: Option<impl Into<String>>) -> Self {
        self.hint = hint.map(Into::into);
        self
    }

    fn frames(mut self, frames: impl IntoIterator<Item = u64>) -> Self {
        self.frames
            .extend(frames.into_iter().map(|f| Span { first: f, last: f }));
        self
    }

    fn spans(mut self, spans: impl IntoIterator<Item = (u64, u64)>) -> Self {
        self.frames.extend(
            spans
                .into_iter()
                .map(|(a, b)| Span {
                    first: a.min(b),
                    last: a.max(b),
                })
                .filter(|s| s.first > 0),
        );
        self
    }

    fn measure(mut self, name: &'static str, value: f64) -> Self {
        debug_assert!(
            MEASUREMENTS.contains(&name),
            "{name} is not in MEASUREMENTS"
        );
        self.measurements.push(Measurement { name, value });
        self
    }

    fn filter(mut self, filter: impl Into<String>) -> Self {
        self.filter = Some(filter.into());
        self
    }

    fn flows(mut self, flows: impl IntoIterator<Item = usize>) -> Self {
        self.flows.extend(flows);
        self
    }

    /// Sorts and merges the frames, and drops frame 0 (unknown).
    fn tidy(mut self) -> Self {
        self.frames.retain(|s| s.first > 0);
        self.frames.sort();
        let mut merged: Vec<Span> = Vec::with_capacity(self.frames.len());
        for span in self.frames {
            match merged.last_mut() {
                Some(last) if span.first <= last.last + 1 => last.last = last.last.max(span.last),
                _ => merged.push(span),
            }
        }
        self.frames = merged;
        self.flows.sort_unstable();
        self.flows.dedup();
        self
    }

    /// The first frame it points at, for ordering.
    pub fn first_frame(&self) -> u64 {
        self.frames.first().map_or(u64::MAX, |s| s.first)
    }

    /// "frame 88", "frames 12, 40-41": at most `max` spans, then "…".
    pub fn frames_text(&self, max: usize) -> String {
        let mut out = String::new();
        let single = self.frames.len() == 1 && self.frames[0].first == self.frames[0].last;
        out.push_str(if single { "frame " } else { "frames " });
        for (i, span) in self.frames.iter().take(max).enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            if span.first == span.last {
                let _ = write!(out, "{}", span.first);
            } else {
                let _ = write!(out, "{}-{}", span.first, span.last);
            }
        }
        if self.frames.len() > max {
            out.push_str(", …");
        }
        out
    }
}

/// The capture at a glance, for the top and bottom of a report.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Overview {
    pub packets: u64,
    pub bytes: u64,
    pub start: Option<Timestamp>,
    pub duration_secs: f64,
    pub connections: usize,
    /// Connections that no warning or error is about.
    pub healthy_connections: usize,
    pub dns_lookups: usize,
    pub tls_handshakes: usize,
    pub http_requests: usize,
    /// The file ends partway through the packet after this many.
    pub cut_off_after: Option<u64>,
    /// Packets a live capture dropped because they weren't read in time.
    pub dropped: Option<u64>,
}

/// What reading the capture showed about it, apart from its packets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CaptureInfo {
    /// The file ends partway through the packet after this many.
    pub cut_off_after: Option<u64>,
    /// Packets a live capture dropped because they weren't read in time.
    pub dropped: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Diagnosis {
    /// Worst first, then in capture order.
    pub findings: Vec<Finding>,
    pub overview: Overview,
}

impl Diagnosis {
    pub fn count(&self, severity: Severity) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == severity)
            .count()
    }
}

/// Runs every rule over a fully analyzed capture.
pub fn diagnose(stats: &Stats, analyzer: &Analyzer, info: CaptureInfo) -> Diagnosis {
    let ctx = Context {
        analyzer,
        end: stats.last_ts.unwrap_or_default(),
    };
    let mut findings = dns::findings(&ctx);
    let tls = tls::findings(&ctx);
    let http = http::findings(&ctx);
    // Connections whose failure TLS or HTTP already explains; their resets
    // are not reported again.
    let explained: HashSet<usize> = tls
        .iter()
        .chain(&http)
        .filter(|f| f.severity == Severity::Error)
        .flat_map(|f| f.flows.iter().copied())
        .collect();
    findings.extend(tls);
    findings.extend(http);
    findings.extend(tcp::findings(&ctx, &explained));
    findings.extend(slow::findings(&ctx));
    findings.extend(capture_findings(stats, info));

    let mut findings: Vec<Finding> = findings.into_iter().map(Finding::tidy).collect();
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.first_frame().cmp(&b.first_frame()))
            .then_with(|| a.category.cmp(&b.category))
    });

    let flows = analyzer.flows.flows();
    let troubled: HashSet<usize> = findings
        .iter()
        .filter(|f| f.severity >= Severity::Warning)
        .flat_map(|f| f.flows.iter().copied())
        .collect();
    let tcp: Vec<usize> = (0..flows.len())
        .filter(|&i| flows[i].tcp.is_some())
        .collect();
    let overview = Overview {
        packets: stats.total.packets,
        bytes: stats.total.bytes,
        start: stats.first_ts,
        duration_secs: stats.duration_secs(),
        connections: tcp.len(),
        healthy_connections: tcp.iter().filter(|i| !troubled.contains(i)).count(),
        dns_lookups: analyzer.dns.lookups().len(),
        tls_handshakes: analyzer.tls.handshakes().len(),
        http_requests: analyzer.http.exchanges().len(),
        cut_off_after: info.cut_off_after,
        dropped: info.dropped,
    };
    Diagnosis { findings, overview }
}

/// Problems with the capture itself, which limit what the rest can see.
fn capture_findings(stats: &Stats, info: CaptureInfo) -> Vec<Finding> {
    let mut out = Vec::new();
    if let Some(frames) = info.cut_off_after {
        out.push(
            Finding::new(
                Severity::Warning,
                Category::Capture,
                "",
                format!(
                    "the file ends in the middle of packet {}; it was probably cut off while capturing",
                    units::count(frames + 1)
                ),
            )
            .frames([frames])
            .hint("everything before the cut was read; what happened after it is unknown"),
        );
    }
    if let Some(dropped) = info.dropped.filter(|&n| n > 0) {
        out.push(
            Finding::new(
                Severity::Warning,
                Category::Capture,
                "",
                format!(
                    "the capture dropped {} it couldn't keep up with",
                    count(dropped, "packet", "packets")
                ),
            )
            .measure("packets", dropped as f64)
            .hint("some loss reported here may be the capture's, not the network's; a capture filter keeps up better"),
        );
    }
    if stats.snapped.count > 0 {
        out.push(
            Finding::new(
                Severity::Info,
                Category::Capture,
                "",
                format!(
                    "the capture kept only the first {} bytes of {}",
                    stats.snaplen,
                    count(stats.snapped.count, "packet", "packets")
                ),
            )
            .frames(stats.snapped.frames.iter().copied())
            .measure("packets", stats.snapped.count as f64)
            .hint("headers were read, but what the packets carried was only partly seen")
            .filter("frame.len > frame.cap_len"),
        );
    }
    if stats.malformed.count > 0 {
        out.push(
            Finding::new(
                Severity::Info,
                Category::Capture,
                "",
                format!(
                    "{} could not be decoded",
                    count(stats.malformed.count, "packet", "packets")
                ),
            )
            .frames(stats.malformed.frames.iter().copied())
            .measure("packets", stats.malformed.count as f64)
            .filter("_ws.malformed"),
        );
    }
    out
}

/// What every rule needs: the analysis, and when the capture ended.
struct Context<'a> {
    analyzer: &'a Analyzer,
    end: Timestamp,
}

impl Context<'_> {
    fn flows(&self) -> &[Flow] {
        self.analyzer.flows.flows()
    }

    fn conn(&self, flow: usize) -> &TcpConn {
        self.flows()[flow]
            .tcp
            .as_ref()
            .expect("only TCP flows are asked for")
    }

    /// "api.example.com:443", or the address when no name is known.
    fn server(&self, flow: usize) -> String {
        let port = self.flows()[flow].server.port();
        match self.analyzer.server_name(flow) {
            Some(name) => format!("{name}:{port}"),
            None => self.flows()[flow].server.to_string(),
        }
    }

    /// An open connection with packets from only one side: the capture
    /// missed the other direction, so nothing can be said about its answers.
    fn one_sided(&self, flow: usize) -> bool {
        let f = &self.flows()[flow];
        f.tcp.as_ref().is_some_and(|c| c.established)
            && (f.from_client.packets == 0 || f.from_server.packets == 0)
    }

    /// A host's name, or its address.
    fn host(&self, ip: IpAddr) -> String {
        self.analyzer
            .name_of(ip)
            .map_or_else(|| ip.to_string(), str::to_string)
    }

    /// "10.0.0.5 → api.example.com:443"
    fn connection(&self, flow: usize) -> String {
        format!("{} → {}", self.flows()[flow].client.ip(), self.server(flow))
    }

    /// `tcp.stream in {1, 4..6}` for these connections.
    fn streams(&self, flows: &[usize]) -> String {
        set_filter(
            "tcp.stream",
            flows.iter().map(|&i| u64::from(self.flows()[i].stream)),
        )
    }
}

/// "1 lookup", "3 lookups"
fn count(n: u64, one: &str, many: &str) -> String {
    format!("{} {}", units::count(n), if n == 1 { one } else { many })
}

/// "a, b and c", or "a, b, c and 4 more" past `max` items.
fn list(items: &[String], max: usize) -> String {
    match items.len() {
        0 => String::new(),
        1 => items[0].clone(),
        n if n <= max => format!("{} and {}", items[..n - 1].join(", "), items[n - 1]),
        n => format!("{} and {} more", items[..max].join(", "), n - max),
    }
}

/// A string for a Wireshark filter, in double quotes.
fn quoted(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// `ip.src == 10.0.0.1` or `ipv6.src == ::1`; `field` is "src", "dst" or "addr".
fn ip_filter(field: &str, ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(_) => format!("ip.{field} == {ip}"),
        IpAddr::V6(_) => format!("ipv6.{field} == {ip}"),
    }
}

/// `frame.number in {1, 4..6}`
fn frames_filter(frames: &[u64]) -> String {
    set_filter("frame.number", frames.iter().copied())
}

/// `field == 3`, or `field in {1, 4..6}`: the set syntax of Wireshark 4.
fn set_filter(field: &str, values: impl IntoIterator<Item = u64>) -> String {
    let mut values: Vec<u64> = values.into_iter().collect();
    values.sort_unstable();
    values.dedup();
    if let [one] = values.as_slice() {
        return format!("{field} == {one}");
    }
    let mut runs: Vec<(u64, u64)> = Vec::new();
    for v in values {
        match runs.last_mut() {
            Some(run) if run.1 + 1 == v => run.1 = v,
            _ => runs.push((v, v)),
        }
    }
    let items: Vec<String> = runs
        .iter()
        .map(|&(a, b)| match b - a {
            0 => a.to_string(),
            1 => format!("{a}, {b}"),
            _ => format!("{a}..{b}"),
        })
        .collect();
    format!("{field} in {{{}}}", items.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_are_merged_and_shown_short() {
        let f = Finding::new(Severity::Info, Category::Tcp, "x", "y")
            .frames([41, 12, 40, 12])
            .spans([(101, 140), (120, 150), (0, 0)])
            .tidy();
        assert_eq!(f.frames_text(10), "frames 12, 40-41, 101-150");
        assert_eq!(f.frames_text(2), "frames 12, 40-41, …");
        let one = Finding::new(Severity::Info, Category::Tcp, "x", "y")
            .frames([88])
            .tidy();
        assert_eq!(one.frames_text(5), "frame 88");
    }

    #[test]
    fn lists_and_counts() {
        let items: Vec<String> = ["a", "b", "c", "d"].map(String::from).to_vec();
        assert_eq!(list(&items[..1], 3), "a");
        assert_eq!(list(&items[..3], 3), "a, b and c");
        assert_eq!(list(&items, 2), "a, b and 2 more");
        assert_eq!(count(1, "lookup", "lookups"), "1 lookup");
        assert_eq!(count(1200, "lookup", "lookups"), "1,200 lookups");
        assert_eq!(quoted(r#"a"b\c"#), r#""a\"b\\c""#);
        assert_eq!(frames_filter(&[3, 1, 3]), "frame.number in {1, 3}");
        assert_eq!(frames_filter(&[7]), "frame.number == 7");
        assert_eq!(
            set_filter("tcp.stream", [9, 1, 2, 3, 4, 7, 8, 12, 13]),
            "tcp.stream in {1..4, 7..9, 12, 13}"
        );
    }
}
