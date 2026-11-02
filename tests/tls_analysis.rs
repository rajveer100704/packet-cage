//! TLS checked against Wireshark. `fixtures/tls-zoo.pcap` has one connection
//! per case (see gen_tls_zoo.py), with certificates from a test CA;
//! `fixtures/tls-zoo.tshark.txt` is tshark 4.6's view of its TLS records.

mod common;

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::Path;

use packet_cage::analyze::Analyzer;
use packet_cage::analyze::tls::{Handshake, TlsEvent, TlsProblem, TlsResult};
use packet_cage::capture::{Capture, Frame};
use packet_cage::decode;
use packet_cage::flow::{Side, TcpStatus};
use packet_cage::stats::{self, Stats};
use packet_cage::units;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn frames() -> Vec<Frame> {
    let mut capture = Capture::open(&Path::new(FIXTURES).join("tls-zoo.pcap")).unwrap();
    let mut frames = Vec::new();
    while let Some(frame) = capture.next_frame().unwrap() {
        frames.push(frame);
    }
    frames
}

fn analyze() -> (Analyzer, Stats, BTreeMap<u64, Vec<TlsEvent>>) {
    let mut analyzer = Analyzer::new();
    let mut stats = Stats::default();
    let mut events = BTreeMap::new();
    for frame in frames() {
        let pkt = decode::decode(&frame);
        let found = analyzer.observe(&frame, &pkt);
        stats.add(&frame, &pkt);
        if !found.tls.is_empty() {
            events.insert(frame.number, found.tls);
        }
    }
    (analyzer, stats, events)
}

fn handshake<'a>(analyzer: &'a Analyzer, name: &str) -> &'a Handshake {
    analyzer
        .tls
        .handshakes()
        .iter()
        .find(|h| h.server_name() == Some(name))
        .unwrap_or_else(|| panic!("no handshake for {name}"))
}

fn problems(analyzer: &Analyzer, name: &str) -> Vec<TlsProblem> {
    let h = handshake(analyzer, name);
    h.problems(analyzer.flows.flows()[h.flow].tcp.as_ref().unwrap())
}

#[test]
fn every_frame_matches_tshark() {
    let (_, _, ours) = analyze();
    let text = std::fs::read_to_string(Path::new(FIXTURES).join("tls-zoo.tshark.txt")).unwrap();
    let mut compared = 0;
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        let frame: u64 = f[0].parse().unwrap();
        let types: Vec<&str> = f[1].split(',').filter(|s| !s.is_empty()).collect();
        let records: Vec<&str> = f[3].split(',').collect();
        let count = |kind: &str| types.iter().filter(|t| **t == kind).count();
        let got = ours.get(&frame).map(Vec::as_slice).unwrap_or(&[]);
        let ours_count = |pick: fn(&TlsEvent) -> bool| got.iter().filter(|e| pick(e)).count();

        assert_eq!(
            ours_count(|e| matches!(e, TlsEvent::ClientHello(_))),
            count("1"),
            "frame {frame}"
        );
        assert_eq!(
            ours_count(|e| matches!(e, TlsEvent::ServerHello(_))),
            count("2"),
            "frame {frame}"
        );
        assert_eq!(
            ours_count(|e| matches!(e, TlsEvent::Certificate { .. })),
            count("11"),
            "frame {frame}"
        );
        let alerts = records.iter().filter(|r| **r == "21").count();
        if frame == 96 {
            // A 19-byte TLS 1.3 record we read as an encrypted alert; tshark
            // can't tell it from application data without the keys.
            assert_eq!(
                (alerts, ours_count(|e| matches!(e, TlsEvent::Alert(None)))),
                (0, 1)
            );
        } else {
            assert_eq!(
                ours_count(|e| matches!(e, TlsEvent::Alert(_))),
                alerts,
                "frame {frame}"
            );
        }
        if let Some(TlsEvent::ClientHello(hello)) =
            got.iter().find(|e| matches!(e, TlsEvent::ClientHello(_)))
        {
            assert_eq!(
                hello.server_name.as_deref(),
                Some(f[2]).filter(|s| !s.is_empty()),
                "frame {frame}"
            );
        }
        compared += 1;
    }
    assert_eq!(compared, 62);
}

#[test]
fn results_and_problems() {
    let (analyzer, _, _) = analyze();
    let result = |name: &str| handshake(&analyzer, name).result();

    assert_eq!(result("good.example"), TlsResult::Completed);
    assert!(problems(&analyzer, "good.example").is_empty());

    for (name, alert) in [
        ("expired.example", 45),
        ("wrong.example", 42),
        ("selfsigned.example", 48),
        ("notyet.example", 42),
    ] {
        assert_eq!(result(name), TlsResult::Rejected, "{name}");
        let found = problems(&analyzer, name);
        assert!(
            matches!(found[0], TlsProblem::Rejected { by: Side::Client, alert: Some(a) } if a.description == alert),
            "{name}: {found:?}"
        );
    }
    assert!(
        problems(&analyzer, "expired.example").contains(&TlsProblem::CertificateExpired {
            not_after: units::days_from_civil(2021, 1, 1) * 86_400
        })
    );
    assert!(
        problems(&analyzer, "wrong.example").contains(&TlsProblem::NameMismatch {
            host: "wrong.example".into(),
            names: "other.example".into()
        })
    );
    assert!(problems(&analyzer, "selfsigned.example").contains(&TlsProblem::SelfSigned));
    assert!(
        problems(&analyzer, "notyet.example").contains(&TlsProblem::CertificateNotYetValid {
            not_before: units::days_from_civil(2030, 1, 1) * 86_400
        })
    );

    let legacy = problems(&analyzer, "legacy.example");
    assert!(
        matches!(legacy[0], TlsProblem::Rejected { by: Side::Server, alert: Some(a) } if a.description == 70)
    );
    assert_eq!(
        problems(&analyzer, "blocked.example"),
        vec![TlsProblem::NoServerHello(TcpStatus::Reset(Side::Server))]
    );
    assert_eq!(
        problems(&analyzer, "silent.example"),
        vec![TlsProblem::NoServerHello(TcpStatus::Open)]
    );

    assert_eq!(result("v13.example"), TlsResult::Completed);
    assert_eq!(handshake(&analyzer, "v13.example").version(), Some(0x0304));
    let retry = handshake(&analyzer, "retry.example");
    assert!(retry.hello_retry);
    assert_eq!(retry.result(), TlsResult::Completed);
    assert_eq!(
        problems(&analyzer, "v13bad.example"),
        vec![TlsProblem::Rejected {
            by: Side::Client,
            alert: None
        }]
    );

    let slow = problems(&analyzer, "slow.example");
    assert!(
        matches!(slow[..], [TlsProblem::SlowServerHello(s)] if (s - 0.88).abs() < 1e-6),
        "{slow:?}"
    );
    assert_eq!(
        problems(&analyzer, "old.example"),
        vec![TlsProblem::OldVersion(0x0301)]
    );

    // A TLS 1.3 draft is TLS 1.3: the client's encrypted Finished ends it.
    assert_eq!(result("draft.example"), TlsResult::Completed);
    // Finished and an encrypted close_notify in the same packet.
    assert_eq!(result("coalesced.example"), TlsResult::Completed);
    assert!(problems(&analyzer, "coalesced.example").is_empty());

    // The ClientHello was split over records and segments; *.wild.example covers it.
    assert_eq!(result("api.wild.example"), TlsResult::Completed);
    assert!(problems(&analyzer, "api.wild.example").is_empty());
}

#[test]
fn plain_http_on_443_is_not_tls() {
    let (analyzer, _, _) = analyze();
    assert_eq!(analyzer.tls.handshakes().len(), 16);
    let plain = analyzer
        .flows
        .flows()
        .iter()
        .position(|f| f.client.port() == 50015)
        .unwrap();
    assert!(analyzer.tls.for_flow(plain).is_none());
}

#[test]
fn certificate_fields() {
    let (analyzer, _, _) = analyze();
    let cert = handshake(&analyzer, "good.example")
        .certificate
        .as_ref()
        .unwrap();
    assert_eq!(cert.chain_len, 2);
    let leaf = cert.leaf.as_ref().unwrap();
    assert_eq!(leaf.subject.common_name.as_deref(), Some("good.example"));
    assert_eq!(leaf.issuer.common_name.as_deref(), Some("Zoo Test CA"));
    assert_eq!(leaf.issuer.organization.as_deref(), Some("packet-cage"));
    assert_eq!(leaf.dns_names, vec!["good.example", "www.good.example"]);
    assert_eq!(leaf.not_after, units::days_from_civil(2027, 1, 1) * 86_400);
    assert!(!leaf.self_issued);
}

#[test]
fn servers_are_named_by_what_the_client_asked_for() {
    let (analyzer, stats, _) = analyze();
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    assert_eq!(analyzer.name_of(ip("10.1.1.20")), Some("good.example"));
    assert_eq!(analyzer.name_of(ip("10.1.14.20")), Some("api.wild.example"));

    let report = stats::render(&stats, &analyzer, 20);
    assert!(report.contains("TLS: 16 handshakes\n"), "{report}");
    for expected in [
        "client rejected the handshake: certificate_expired (a certificate has expired or is not valid yet)",
        "certificate is for other.example, not wrong.example",
        "server reset the connection instead of answering the ClientHello",
        "server took 880.0 ms to answer the ClientHello",
        "uses TLS 1.0, which is outdated",
    ] {
        assert!(report.contains(expected), "missing {expected:?}\n{report}");
    }
}

/// Corrupted copies of the zoo's packets must never panic the analysis.
#[test]
fn mutated_packets_never_panic() {
    let frames = frames();
    let mut rng = common::Rng(0x7157);
    for _ in 0..200 {
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
