//! DNS checked against Wireshark. `fixtures/dns-zoo.pcap` has one case every
//! 10 seconds (see gen_dns_zoo.py); `fixtures/dns-zoo.tshark.txt` is tshark
//! 4.6's view of every DNS message in it.

mod common;

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::Path;

use packet_cage::analyze::Analyzer;
use packet_cage::analyze::dns::{Lookup, Outcome, Seen};
use packet_cage::capture::Capture;
use packet_cage::decode;
use packet_cage::stats::{self, Stats};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// What tshark says about one DNS message.
#[derive(Debug)]
struct Expected {
    id: u16,
    response: bool,
    name: String,
    qtype: u16,
    rcode: Option<u8>,
    answers: u16,
    /// Seconds from the query, for matched responses.
    time: Option<f64>,
}

fn tshark() -> BTreeMap<u64, Expected> {
    let text = std::fs::read_to_string(Path::new(FIXTURES).join("dns-zoo.tshark.txt")).unwrap();
    text.lines()
        .map(|line| {
            let f: Vec<&str> = line.split('\t').collect();
            let expected = Expected {
                id: u16::from_str_radix(f[1].trim_start_matches("0x"), 16).unwrap(),
                response: f[2] == "True",
                name: f[3].to_string(),
                qtype: f[4].parse().unwrap(),
                rcode: f[5].parse().ok(),
                answers: f[6].parse().unwrap(),
                time: f[7].parse().ok(),
            };
            (f[0].parse().unwrap(), expected)
        })
        .collect()
}

/// Runs the zoo through the analyzer; returns it and the DNS messages by frame.
fn analyze() -> (Analyzer, Stats, BTreeMap<u64, Seen>) {
    let mut capture = Capture::open(&Path::new(FIXTURES).join("dns-zoo.pcap")).unwrap();
    let mut analyzer = Analyzer::new();
    let mut stats = Stats::default();
    let mut seen = BTreeMap::new();
    while let Some(frame) = capture.next_frame().unwrap() {
        let pkt = decode::decode(&frame);
        let found = analyzer.observe(&frame, &pkt);
        stats.add(&frame, &pkt);
        assert!(found.dns.messages.len() <= 1, "frame {}", frame.number);
        if let Some(message) = found.dns.messages.into_iter().next() {
            seen.insert(frame.number, message);
        }
    }
    (analyzer, stats, seen)
}

fn lookup<'a>(analyzer: &'a Analyzer, name: &str) -> &'a Lookup {
    analyzer
        .dns
        .lookups()
        .iter()
        .find(|l| l.question.as_ref().is_some_and(|q| q.name == name))
        .unwrap_or_else(|| panic!("no lookup for {name}"))
}

#[test]
fn every_message_matches_tshark() {
    let expected = tshark();
    let (_, _, seen) = analyze();
    assert_eq!(
        seen.keys().collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>()
    );
    for (frame, want) in &expected {
        let got = &seen[frame].message;
        let question = &got.questions[0];
        assert_eq!(got.id, want.id, "frame {frame}");
        assert_eq!(got.response, want.response, "frame {frame}");
        assert_eq!(
            (question.name.as_str(), question.qtype),
            (want.name.as_str(), want.qtype),
            "frame {frame}"
        );
        if want.response {
            assert_eq!(Some(got.rcode), want.rcode, "frame {frame}");
            // A malformed answer section can't be counted; tshark reports the header's count.
            if got.error.is_none() {
                assert_eq!(
                    got.answers.len(),
                    usize::from(want.answers),
                    "frame {frame}"
                );
            }
        }
    }
}

#[test]
fn response_times_match_tshark_except_late_retries() {
    let expected = tshark();
    let (_, _, seen) = analyze();
    for (frame, want) in &expected {
        let ours = seen[frame].latency;
        if *frame == 41 {
            // Retried after 5.5 s: Wireshark starts a new transaction for a
            // query repeated more than 5 s later and measures from the retry.
            // We measure from the first query, because the client was waiting
            // all along.
            assert!((want.time.unwrap() - 0.010).abs() < 1e-6);
            assert!((ours.unwrap() - 5.51).abs() < 1e-6);
            continue;
        }
        match (ours, want.time) {
            (Some(a), Some(b)) => assert!((a - b).abs() < 1e-6, "frame {frame}: {a} vs {b}"),
            (a, b) => assert_eq!(a.is_some(), b.is_some(), "frame {frame}"),
        }
    }
}

#[test]
fn outcomes() {
    let (analyzer, _, _) = analyze();
    let end = analyzer.dns.capture_end();
    let outcome = |name: &str| lookup(&analyzer, name).outcome(end);
    assert_eq!(outcome("www.example.com"), Outcome::Answered);
    assert_eq!(outcome("nope.example"), Outcome::Failed(3));
    assert_eq!(outcome("broken.example"), Outcome::Failed(2));
    assert_eq!(outcome("blocked.example"), Outcome::Failed(5));
    assert_eq!(outcome("lost.example"), Outcome::NoResponse);
    assert_eq!(outcome("down.example"), Outcome::Unreachable);
    assert_eq!(outcome("v6.example"), Outcome::Answered);
    assert_eq!(outcome("loop.example"), Outcome::Malformed);
    assert_eq!(outcome("pending.example"), Outcome::CaptureEnded);

    let aaaa = analyzer
        .dns
        .lookups()
        .iter()
        .find(|l| {
            l.question
                .as_ref()
                .is_some_and(|q| q.qtype == 28 && q.name == "www.example.com")
        })
        .unwrap();
    assert_eq!(aaaa.outcome(end), Outcome::NoData);

    let slow = lookup(&analyzer, "slow.example");
    assert_eq!(slow.retries, vec![15]);
    assert!(slow.is_slow());

    let lost = lookup(&analyzer, "lost.example");
    assert_eq!(lost.retries, vec![18, 19]);

    assert_eq!(
        lookup(&analyzer, "down.example").icmp_error.unwrap().frame,
        21
    );
    assert_eq!(analyzer.dns.unmatched_responses, vec![36]);
}

#[test]
fn truncated_udp_answer_then_tcp() {
    let (analyzer, _, _) = analyze();
    let big: Vec<&Lookup> = analyzer
        .dns
        .lookups()
        .iter()
        .filter(|l| l.question.as_ref().is_some_and(|q| q.name == "big.example"))
        .collect();
    assert_eq!(big.len(), 2);
    assert!(!big[0].over_tcp && big[0].response.as_ref().unwrap().truncated);
    let end = analyzer.dns.capture_end();
    assert_eq!(big[0].outcome(end), Outcome::Truncated);
    assert!(big[1].over_tcp);
    assert_eq!(big[1].response.as_ref().unwrap().answers.len(), 3);
}

#[test]
fn addresses_get_the_names_they_were_looked_up_by() {
    let (analyzer, _, _) = analyze();
    let name = |ip: &str| analyzer.dns.name_of(ip.parse::<IpAddr>().unwrap());
    assert_eq!(name("93.184.216.34"), Some("www.example.com"));
    // The forward lookup came first, so it wins over the PTR's web.example.com.
    assert_eq!(name("93.184.216.35"), Some("www.example.com"));
    assert_eq!(name("2001:db8::80"), Some("v6.example"));
    assert_eq!(name("203.0.113.2"), Some("big.example"));
    assert_eq!(name("198.51.100.99"), None);
}

#[test]
fn stats_report() {
    let (analyzer, stats, _) = analyze();
    let report = stats::render(&stats, &analyzer, 20);
    assert!(
        report.contains("DNS: 15 lookups to 3 servers\n"),
        "{report}"
    );
    let connection = report
        .lines()
        .find(|l| l.contains("93.184.216.34:443"))
        .expect("TCP conversation row");
    assert!(connection.contains("www.example.com"), "{connection}");
    for expected in [
        "no such name",
        "server failure",
        "refused",
        "server unreachable (ICMP)",
        "malformed response",
    ] {
        assert!(report.contains(expected), "missing {expected}: {report}");
    }
}

/// Corrupted copies of the zoo's packets must never panic the analysis,
/// whatever they do to the DNS parser, the TCP reassembly or ICMP quoting.
#[test]
fn mutated_packets_never_panic() {
    let mut capture = Capture::open(&Path::new(FIXTURES).join("dns-zoo.pcap")).unwrap();
    let mut frames = Vec::new();
    while let Some(frame) = capture.next_frame().unwrap() {
        frames.push(frame);
    }
    let mut rng = common::Rng(0x5eed);
    for _ in 0..300 {
        let mut analyzer = Analyzer::new();
        for original in &frames {
            let mut frame = original.clone();
            for _ in 0..rng.below(4) {
                let i = rng.below(frame.data.len());
                frame.data[i] = rng.next() as u8;
            }
            if rng.below(4) == 0 {
                frame.data.truncate(rng.below(frame.data.len() + 1));
            }
            let pkt = decode::decode(&frame);
            let found = analyzer.observe(&frame, &pkt);
            let _ = packet_cage::summary::describe_with(&pkt, &found, None);
        }
        let _ = stats::render(&Stats::default(), &analyzer, 10);
    }
}

/// A response cut off by the capture's length limit is incomplete, not
/// malformed: with the header present it still matches its query, and the
/// header's answer count says it was answered.
#[test]
fn responses_cut_by_snaplen_are_not_malformed() {
    let mut capture = Capture::open(&Path::new(FIXTURES).join("dns-zoo.pcap")).unwrap();
    let query = capture.next_frame().unwrap().unwrap();
    let response = capture.next_frame().unwrap().unwrap();
    // Ethernet + IPv4 + UDP is 42 bytes, then the 12-byte DNS header.
    for (keep, matched) in [(80, true), (60, true), (50, false)] {
        let mut cut = response.clone();
        cut.data.truncate(keep);
        let mut analyzer = Analyzer::new();
        analyzer.observe(&query, &decode::decode(&query));
        let pkt = decode::decode(&cut);
        let found = analyzer.observe(&cut, &pkt);
        assert!(analyzer.dns.malformed.is_empty(), "keep {keep}");
        let line = packet_cage::summary::describe_with(&pkt, &found, None);
        assert!(line.contains("[cut off by capture length limit]"), "{line}");
        let lookup = &analyzer.dns.lookups()[0];
        assert_eq!(lookup.response.is_some(), matched, "keep {keep}");
        if matched {
            assert_eq!(
                lookup.outcome(analyzer.dns.capture_end()),
                Outcome::Answered
            );
        }
    }
}
