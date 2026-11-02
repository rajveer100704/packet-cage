//! The diagnosis report: what it finds in each zoo, the demo capture's report
//! (the example in README.md and PLAN.md), and the JSON and HTML formats.

mod common;

use std::path::Path;

use packet_cage::analyze::Analyzer;
use packet_cage::capture::{Capture, Frame};
use packet_cage::decode;
use packet_cage::diagnose::{self, Category, Diagnosis, Finding, Severity};
use packet_cage::report::{html, json, text};
use packet_cage::stats::Stats;

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

fn frames(file: &str) -> Vec<Frame> {
    let mut capture = Capture::open(&Path::new(ROOT).join(file)).unwrap();
    let mut frames = Vec::new();
    while let Some(frame) = capture.next_frame().unwrap() {
        frames.push(frame);
    }
    frames
}

fn diagnose_frames(frames: &[Frame]) -> Diagnosis {
    let mut analyzer = Analyzer::new();
    let mut stats = Stats::default();
    for frame in frames {
        let pkt = decode::decode(frame);
        analyzer.observe(frame, &pkt);
        stats.add(frame, &pkt);
    }
    diagnose::diagnose(&stats, &analyzer, Default::default())
}

fn diagnose_file(file: &str) -> Diagnosis {
    diagnose_frames(&frames(file))
}

/// The finding about `subject` in `category`; there must be exactly one.
fn find<'a>(d: &'a Diagnosis, category: Category, subject: &str) -> &'a Finding {
    let found: Vec<&Finding> = d
        .findings
        .iter()
        .filter(|f| f.category == category && f.subject == subject)
        .collect();
    assert_eq!(found.len(), 1, "{category:?} {subject}: {:#?}", d.findings);
    found[0]
}

fn check(d: &Diagnosis, category: Category, subject: &str, severity: Severity, text: &str) {
    let f = find(d, category, subject);
    assert_eq!(f.severity, severity, "{f:#?}");
    assert!(f.text.contains(text), "{subject}: {:?}", f.text);
}

#[test]
fn demo_report_is_the_documented_example() {
    let d = diagnose_file("examples/demo.pcap");
    let report = text::render("examples/demo.pcap", &d, Some(30));
    let plain = anstream::adapter::strip_str(&report).to_string();
    let expected = include_str!("../examples/demo.txt").replace("\r\n", "\n");
    assert_eq!(plain, expected);
    // The documents quote it.
    for doc in ["README.md", "PLAN.md"] {
        let doc = std::fs::read_to_string(Path::new(ROOT).join(doc))
            .unwrap()
            .replace("\r\n", "\n");
        let findings = expected.split_once("\n\n").unwrap().1;
        assert!(doc.contains(findings), "{doc} is out of date");
    }
}

#[test]
fn demo_findings() {
    let d = diagnose_file("examples/demo.pcap");
    check(
        &d,
        Category::Dns,
        "api.internal",
        Severity::Error,
        "NXDOMAIN, asked 3 times",
    );
    let tls = find(&d, Category::Tls, "pay.example.com:443");
    assert!(tls.text.contains("unknown_ca"), "{}", tls.text);
    assert_eq!(tls.frames_text(5), "frame 84");
    let slow = find(&d, Category::Slow, "api.example.com:443");
    assert_eq!(
        slow.text,
        "network RTT 40.0 ms, server took 2.10 s to answer"
    );
    assert_eq!(
        slow.hint.as_deref(),
        Some("the server is slow, not the network")
    );
    let loss = find(&d, Category::Loss, "10.0.0.5 → cdn.example.com:443");
    // tshark flags frames 206, 224, 243 and 261 as fast retransmissions.
    assert_eq!(loss.frames_text(5), "frames 206-261");
    assert_eq!(
        loss.filter.as_deref(),
        Some("tcp.analysis.retransmission && tcp.stream == 10")
    );
    assert_eq!(d.findings.len(), 4);
    assert_eq!(d.overview.connections, 14);
    assert_eq!(d.overview.healthy_connections, 11);
}

#[test]
fn tcp_zoo_findings() {
    let d = diagnose_file("tests/fixtures/tcp-zoo.pcap");
    check(
        &d,
        Category::Tcp,
        "10.0.8.2:443",
        Severity::Error,
        "connection refused",
    );
    check(
        &d,
        Category::Tcp,
        "10.0.11.2:443",
        Severity::Warning,
        "the server reset 1 connection",
    );
    check(
        &d,
        Category::Slow,
        "10.0.3.1 → 10.0.3.2:443",
        Severity::Warning,
        "the server ran out of receive buffer (3 zero-window packets)",
    );
    check(
        &d,
        Category::Capture,
        "",
        Severity::Info,
        "the capture missed 1 packet",
    );
    // Case 12 closed cleanly before its RST; the retransmissions in cases 1,
    // 2 and 9 are too few to matter.
    assert_eq!(d.findings.len(), 4, "{:#?}", d.findings);
}

#[test]
fn dns_zoo_findings() {
    let d = diagnose_file("tests/fixtures/dns-zoo.pcap");
    check(
        &d,
        Category::Dns,
        "nope.example",
        Severity::Error,
        "NXDOMAIN",
    );
    check(
        &d,
        Category::Dns,
        "broken.example",
        Severity::Error,
        "SERVFAIL",
    );
    check(
        &d,
        Category::Dns,
        "blocked.example",
        Severity::Error,
        "REFUSED",
    );
    check(
        &d,
        Category::Dns,
        "192.168.1.2",
        Severity::Error,
        "DNS server unreachable (ICMP port unreachable): 1 query for down.example",
    );
    let resolver: Vec<&Finding> = d
        .findings
        .iter()
        .filter(|f| f.subject == "192.168.1.1")
        .collect();
    let texts: Vec<&str> = resolver.iter().map(|f| f.text.as_str()).collect();
    assert_eq!(
        texts,
        [
            "2 of 13 lookups took over 500 ms (slowest: late.example, 5.51 s); 2 had to be sent again",
            "no answer to 1 of 13 lookups (lost.example)",
            "1 response could not be read (loop.example)",
        ]
    );
}

#[test]
fn tls_zoo_findings() {
    let d = diagnose_file("tests/fixtures/tls-zoo.pcap");
    for (server, severity, text) in [
        (
            "expired.example:443",
            Severity::Error,
            "certificate expired on 2021-01-01: the client rejected it (certificate_expired)",
        ),
        (
            "wrong.example:443",
            Severity::Error,
            "certificate is for other.example, not wrong.example: the client rejected it",
        ),
        (
            "selfsigned.example:443",
            Severity::Error,
            "certificate is self-signed: the client rejected it (unknown_ca)",
        ),
        (
            "notyet.example:443",
            Severity::Error,
            "certificate is not valid until 2030-01-01",
        ),
        (
            "legacy.example:443",
            Severity::Error,
            "server rejected the handshake: protocol_version",
        ),
        (
            "blocked.example:443",
            Severity::Error,
            "server reset the connection instead of answering the ClientHello",
        ),
        (
            "silent.example:443",
            Severity::Error,
            "no answer to the ClientHello",
        ),
        (
            "v13bad.example:443",
            Severity::Error,
            "client ended the handshake with an encrypted alert",
        ),
        (
            "slow.example:443",
            Severity::Warning,
            "server took 880.0 ms to answer the ClientHello",
        ),
        (
            "old.example:443",
            Severity::Warning,
            "uses TLS 1.0, which is outdated",
        ),
    ] {
        check(&d, Category::Tls, server, severity, text);
    }
    // The blocked handshake's reset is part of the TLS finding, not a TCP one.
    assert!(!d.findings.iter().any(|f| f.category == Category::Tcp));
}

#[test]
fn http_zoo_findings() {
    let d = diagnose_file("tests/fixtures/http-zoo.pcap");
    check(
        &d,
        Category::Http,
        "reports.example:80",
        Severity::Error,
        "500 Internal Server Error for GET /report?year=2025",
    );
    check(
        &d,
        Category::Http,
        "files.example:80",
        Severity::Warning,
        "404 Not Found for GET /missing",
    );
    check(
        &d,
        Category::Http,
        "stuck.example:80",
        Severity::Error,
        "no response to GET /hang: still waiting",
    );
    check(
        &d,
        Category::Slow,
        "reports.example:80",
        Severity::Warning,
        "network RTT 20.1 ms, server took 2.10 s to answer GET /report?year=2025",
    );
    check(
        &d,
        Category::Slow,
        "shop.example:80",
        Severity::Warning,
        "server took 1.50 s",
    );
    // "101 Switching Protocols" answered the WebSocket upgrade, and the
    // encrypted connections waited less than a second.
    assert!(!d.findings.iter().any(|f| f.subject.starts_with("ws.")));
    assert_eq!(d.findings.len(), 5, "{:#?}", d.findings);
}

#[test]
fn findings_are_ordered_and_tidy() {
    for file in [
        "examples/demo.pcap",
        "tests/fixtures/tcp-zoo.pcap",
        "tests/fixtures/dns-zoo.pcap",
        "tests/fixtures/tls-zoo.pcap",
        "tests/fixtures/http-zoo.pcap",
    ] {
        let d = diagnose_file(file);
        for pair in d.findings.windows(2) {
            assert!(
                pair[0].severity > pair[1].severity
                    || pair[0].severity == pair[1].severity
                        && pair[0].first_frame() <= pair[1].first_frame(),
                "{file}: {:?} before {:?}",
                pair[0].text,
                pair[1].text
            );
        }
        for f in &d.findings {
            assert!(!f.frames.is_empty(), "{file}: {f:?}");
            for pair in f.frames.windows(2) {
                assert!(pair[0].last + 1 < pair[1].first, "{file}: {f:?}");
            }
            assert!(f.filter.is_some(), "{file}: {f:?}");
        }
    }
}

#[test]
fn json_report() {
    let d = diagnose_file("examples/demo.pcap");
    let out = json::render("examples/demo.pcap", &d);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["schema"], 1);
    assert_eq!(v["file"], "examples/demo.pcap");
    assert_eq!(v["capture"]["packets"], 314);
    assert_eq!(v["capture"]["start"], "2025-10-09T08:53:20.000000Z");
    assert_eq!(v["summary"]["errors"], 2);
    assert_eq!(v["summary"]["warnings"], 2);
    assert_eq!(v["summary"]["healthy_connections"], 11);
    let findings = v["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 4);
    let loss = &findings[3];
    assert_eq!(loss["severity"], "warning");
    assert_eq!(loss["category"], "loss");
    assert_eq!(loss["frames"], serde_json::json!([[206, 261]]));
    assert_eq!(loss["measurements"]["retransmissions"], 4.0);
    let slow = &findings[2];
    assert_eq!(slow["measurements"]["server_secs"], 2.1);
    assert_eq!(slow["measurements"]["network_rtt_secs"], 0.04);
}

#[test]
fn html_report() {
    let d = diagnose_file("examples/demo.pcap");
    let out = html::render("examples/<demo>.pcap", &d);
    assert!(out.starts_with("<!doctype html>"));
    assert_eq!(out.matches("<section class=\"finding").count(), 4);
    assert!(out.contains("<section class=\"finding error\">"));
    assert!(out.contains("examples/&lt;demo&gt;.pcap"));
    assert!(out.contains("<code>tcp.analysis.retransmission &amp;&amp; tcp.stream == 10</code>"));
    assert!(!out.contains("<script"));
}

/// Corrupted copies of the captures must never panic the diagnosis or the
/// reports.
#[test]
fn mutated_captures_never_panic() {
    let mut rng = common::Rng(0x6d36);
    for file in [
        "examples/demo.pcap",
        "tests/fixtures/tcp-zoo.pcap",
        "tests/fixtures/dns-zoo.pcap",
        "tests/fixtures/tls-zoo.pcap",
        "tests/fixtures/http-zoo.pcap",
    ] {
        let originals = frames(file);
        for _ in 0..40 {
            let mut mutated = originals.clone();
            for frame in &mut mutated {
                for _ in 0..rng.below(3) {
                    let i = rng.below(frame.data.len());
                    frame.data[i] = rng.next() as u8;
                }
                if rng.below(5) == 0 {
                    frame.data.truncate(rng.below(frame.data.len() + 1));
                }
            }
            let d = diagnose_frames(&mutated);
            let _ = text::render(file, &d, None);
            let _ = json::render(file, &d);
            let _ = html::render(file, &d);
        }
    }
}
