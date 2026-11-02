//! HTTP checked against Wireshark. `fixtures/http-zoo.pcap` has one case per
//! connection, each with a 20 ms round trip (see gen_http_zoo.py);
//! `fixtures/http-zoo.tshark.txt` is tshark 4.6's view of it, with body
//! reassembly off so each message shows where its head completes, as here.

mod common;

use std::collections::BTreeMap;
use std::path::Path;

use packet_cage::analyze::Analyzer;
use packet_cage::analyze::http::{Exchange, HttpEvent};
use packet_cage::capture::{Capture, Frame};
use packet_cage::decode;
use packet_cage::stats::{self, Stats};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn frames() -> Vec<Frame> {
    let mut capture = Capture::open(&Path::new(FIXTURES).join("http-zoo.pcap")).unwrap();
    let mut frames = Vec::new();
    while let Some(frame) = capture.next_frame().unwrap() {
        frames.push(frame);
    }
    frames
}

fn analyze() -> (Analyzer, Stats, BTreeMap<u64, Vec<HttpEvent>>) {
    let mut analyzer = Analyzer::new();
    let mut stats = Stats::default();
    let mut events = BTreeMap::new();
    for frame in frames() {
        let pkt = decode::decode(&frame);
        let found = analyzer.observe(&frame, &pkt);
        stats.add(&frame, &pkt);
        if !found.http.is_empty() {
            events.insert(frame.number, found.http);
        }
    }
    (analyzer, stats, events)
}

fn exchange<'a>(analyzer: &'a Analyzer, target: &str) -> &'a Exchange {
    analyzer
        .http
        .exchanges()
        .iter()
        .find(|e| e.request.as_ref().is_some_and(|r| r.target == target))
        .unwrap_or_else(|| panic!("no exchange for {target}"))
}

#[test]
fn every_message_matches_tshark() {
    let (_, _, ours) = analyze();
    let text = std::fs::read_to_string(Path::new(FIXTURES).join("http-zoo.tshark.txt")).unwrap();
    let mut seen = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        let frame: u64 = f[0].parse().unwrap();
        let events = &ours[&frame];
        if !f[1].is_empty() {
            let request = events
                .iter()
                .find_map(|e| match e {
                    HttpEvent::Request(r) => Some(r),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("frame {frame}: no request"));
            assert_eq!(
                (request.method.as_str(), request.target.as_str()),
                (f[1], f[2]),
                "frame {frame}"
            );
            assert_eq!(request.host.as_deref(), Some(f[3]), "frame {frame}");
        }
        if !f[4].is_empty() {
            let (status, request_frame) = events
                .iter()
                .find_map(|e| match e {
                    HttpEvent::Response {
                        response,
                        request_frame,
                        ..
                    } => Some((response.status, *request_frame)),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("frame {frame}: no response"));
            assert_eq!(status.to_string(), f[4], "frame {frame}");
            assert_eq!(
                request_frame.map(|r| r.to_string()).as_deref(),
                Some(f[5]),
                "frame {frame}"
            );
        }
        seen.push(frame);
    }
    // With body reassembly off, tshark leaves the fields of a chunked
    // response empty (frame 8); every other HTTP frame is in its list.
    let extra: Vec<u64> = ours.keys().copied().filter(|f| !seen.contains(f)).collect();
    assert_eq!(extra, vec![8]);
}

#[test]
fn time_to_first_byte_and_server_time() {
    let (analyzer, _, _) = analyze();
    let flows = analyzer.flows.flows();
    for (target, ms) in [
        ("/index.html", 50.0),
        ("/style.css", 30.0),
        ("/api/orders", 40.0),
        ("/big.iso", 25.0),
        ("/logo.png", 25.0),
        ("/missing", 25.0),
        ("/report?year=2025", 2120.0),
        ("/search?q=shoes", 1520.0),
        ("/a", 30.0),
        ("/b", 30.0),
        ("/upload", 35.0),
        ("/legacy", 30.0),
        ("/split", 30.3),
        ("/health", 22.0),
    ] {
        let e = exchange(&analyzer, target);
        let ttfb = e.time_to_first_byte().unwrap() * 1000.0;
        assert!((ttfb - ms).abs() < 1e-6, "{target}: {ttfb} ms");
        // Captured at the client: the whole 20 ms round trip is network.
        let server = e.server_time(flows[e.flow].tcp.as_ref().unwrap()).unwrap() * 1000.0;
        assert!(
            (server - (ms - 20.0)).abs() < 1e-6,
            "{target}: server {server} ms"
        );
    }
}

#[test]
fn bodies_are_framed() {
    let (analyzer, _, _) = analyze();
    let bytes = |target: &str| exchange(&analyzer, target).response_bytes;
    assert_eq!(bytes("/index.html"), 2013);
    // Three chunks with their size lines and endings (10 + 14 + 6), then
    // the last chunk and blank line (5).
    assert_eq!(bytes("/style.css"), 35);
    assert_eq!(bytes("/big.iso"), 0);
    assert_eq!(bytes("/logo.png"), 0);
    // No length: the body ran until the server closed.
    assert_eq!(bytes("/legacy"), 1000);
    let legacy = exchange(&analyzer, "/legacy");
    assert!(legacy.response_end.unwrap().frame > legacy.response_start.unwrap().frame);
    // The POST's body came in its own segment; the request ends there.
    let post = exchange(&analyzer, "/api/orders");
    assert_eq!(post.request_frame, Some(16));
    assert_eq!(post.request_end.unwrap().frame, 17);
}

#[test]
fn no_response_and_upgrade() {
    let (analyzer, _, events) = analyze();
    assert!(exchange(&analyzer, "/hang").response.is_none());
    let chat = exchange(&analyzer, "/chat");
    // After "101 Switching Protocols" the bytes are WebSocket frames, even
    // one that happens to contain "GET /x HTTP/1.1".
    let on_chat = analyzer
        .http
        .exchanges()
        .iter()
        .filter(|e| e.flow == chat.flow)
        .count();
    assert_eq!(on_chat, 1);
    let interim: Vec<u16> = events
        .values()
        .flatten()
        .filter_map(|e| match e {
            HttpEvent::Response { response, .. } if response.status < 200 => Some(response.status),
            _ => None,
        })
        .collect();
    assert_eq!(interim, vec![100, 101]);
}

#[test]
fn waits_on_encrypted_connections() {
    let (analyzer, _, _) = analyze();
    let wait = |name: &str| {
        let h = analyzer
            .tls
            .handshakes()
            .iter()
            .find(|h| h.server_name() == Some(name))
            .unwrap();
        analyzer.flows.flows()[h.flow]
            .tcp
            .as_ref()
            .unwrap()
            .longest_wait
            .unwrap()
            .secs
    };
    // Session tickets after 20 ms, the answer after 920 ms: the answer counts.
    assert!((wait("slow-api.example") - 0.920).abs() < 1e-6);
    // The answer after 30 ms, then a close alert 5 s later: still 30 ms.
    assert!((wait("idle.example") - 0.030).abs() < 1e-6);
}

#[test]
fn stats_report() {
    let (analyzer, stats, _) = analyze();
    let report = stats::render(&stats, &analyzer, 20);
    assert!(
        report.contains("HTTP: 16 requests on 12 connections\n"),
        "{report}"
    );
    assert!(
        report.contains("Server time: median 10.0 ms, slowest 2.10 s\n"),
        "{report}"
    );
    for expected in [
        "GET reports.example/report?year=2025",
        "500 Internal Server Error",
        "GET shop.example/search?q=shoes",
        "404 Not Found",
        "GET stuck.example/hang",
        "no response",
    ] {
        assert!(report.contains(expected), "missing {expected:?}\n{report}");
    }
    // Hosts named after the HTTP Host header, without the port.
    let row = report
        .lines()
        .find(|l| l.contains("10.2.10.20:8080"))
        .unwrap();
    assert!(
        row.contains("internal.example") && !row.contains("internal.example:8080"),
        "{row}"
    );
}

/// Corrupted copies of the zoo's packets must never panic the analysis.
#[test]
fn mutated_packets_never_panic() {
    let frames = frames();
    let mut rng = common::Rng(0x4777);
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
