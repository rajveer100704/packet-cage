//! TCP analysis checked against Wireshark. `fixtures/tcp-zoo.pcap` holds one
//! connection per case (see gen_tcp_zoo.py) and `fixtures/tcp-zoo.tshark.txt`
//! is tshark 4.6's Info column for it, so these tests compare with tshark's
//! own labels without needing tshark installed.

use std::collections::BTreeMap;
use std::path::Path;

use packet_cage::capture::Capture;
use packet_cage::decode;
use packet_cage::flow::{FlowTable, ResetKind, Side, TcpStatus};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// The labels we compare: everything Wireshark's TCP sequence analysis adds.
fn is_analysis_label(label: &str) -> bool {
    const LABELS: [&str; 13] = [
        "TCP Retransmission",
        "TCP Fast Retransmission",
        "TCP Spurious Retransmission",
        "TCP Out-Of-Order",
        "TCP Previous segment not captured",
        "TCP ACKed unseen segment",
        "TCP ZeroWindow",
        "TCP ZeroWindowProbe",
        "TCP ZeroWindowProbeAck",
        "TCP Window Full",
        "TCP Window Update",
        "TCP Keep-Alive",
        "TCP Keep-Alive ACK",
    ];
    LABELS.contains(&label) || label.starts_with("TCP Dup ACK ")
}

/// "[TCP Dup ACK 9#1] 443 → ..." → {"TCP Dup ACK 9#1"}
fn labels_in(text: &str) -> Vec<String> {
    let mut labels: Vec<String> = text
        .split('[')
        .skip(1)
        .filter_map(|part| part.split_once(']').map(|(label, _)| label.to_string()))
        .filter(|label| is_analysis_label(label))
        .collect();
    labels.sort();
    labels
}

fn tshark_labels() -> BTreeMap<u64, Vec<String>> {
    let text = std::fs::read_to_string(Path::new(FIXTURES).join("tcp-zoo.tshark.txt")).unwrap();
    text.lines()
        .map(|line| {
            let (number, info) = line.split_once('\t').unwrap();
            (number.parse().unwrap(), labels_in(info))
        })
        .collect()
}

fn analyze_zoo() -> (FlowTable, BTreeMap<u64, Vec<String>>) {
    let mut capture = Capture::open(&Path::new(FIXTURES).join("tcp-zoo.pcap")).unwrap();
    let mut flows = FlowTable::new();
    let mut labels = BTreeMap::new();
    while let Some(frame) = capture.next_frame().unwrap() {
        let pkt = decode::decode(&frame);
        let observed = flows.observe(&frame, &pkt).unwrap();
        let mut found: Vec<String> = observed.tcp_events.iter().map(|e| e.to_string()).collect();
        found.sort();
        labels.insert(frame.number, found);
    }
    (flows, labels)
}

#[test]
fn every_frame_matches_tshark() {
    let expected = tshark_labels();
    let (_, ours) = analyze_zoo();
    assert_eq!(ours.len(), expected.len());
    let flagged = expected.values().filter(|l| !l.is_empty()).count();
    assert_eq!(flagged, 28, "fixture should exercise every kind of label");
    for (frame, labels) in &expected {
        assert_eq!(&ours[frame], labels, "frame {frame}");
    }
}

#[test]
fn health_counts_per_direction() {
    let (flows, _) = analyze_zoo();
    let conn = |stream: u32| flows.flows()[stream as usize].tcp.as_ref().unwrap();

    // 1: fast retransmission after three duplicate ACKs.
    let client = conn(0).health(Side::Client);
    // SYN, five data segments and the retransmission.
    assert_eq!(client.segments, 7);
    assert_eq!(client.retransmissions.count, 1);
    assert_eq!(client.fast_retransmissions.first_frame, 13);
    let server = conn(0).health(Side::Server);
    assert_eq!(server.duplicate_acks.count, 3);
    assert_eq!(
        (
            server.duplicate_acks.first_frame,
            server.duplicate_acks.last_frame
        ),
        (10, 12)
    );

    // 2: one timeout retransmission and one spurious one.
    let client = conn(1).health(Side::Client);
    assert_eq!(client.retransmissions.count, 2);
    assert_eq!(client.spurious_retransmissions.count, 1);

    // 3: the server advertised a zero window three times.
    assert_eq!(conn(2).health(Side::Server).zero_windows.count, 3);
}

#[test]
fn handshake_rtt_is_split_at_the_capture_point() {
    let (flows, _) = analyze_zoo();
    let rtt = flows.flows()[0]
        .tcp
        .as_ref()
        .unwrap()
        .handshake_rtt()
        .unwrap();
    // SYN → SYN-ACK 20 ms, SYN-ACK → ACK 0.1 ms.
    assert!((rtt.total - 0.0201).abs() < 1e-9, "{rtt:?}");
    assert!((rtt.server_side.unwrap() - 0.020).abs() < 1e-9, "{rtt:?}");
    assert!(
        (rtt.client_side().unwrap() - 0.0001).abs() < 1e-9,
        "{rtt:?}"
    );
}

#[test]
fn resets_are_classified() {
    let (flows, _) = analyze_zoo();
    let conn = |stream: usize| flows.flows()[stream].tcp.as_ref().unwrap();

    let refused = conn(7);
    assert_eq!(refused.status(), TcpStatus::Refused);
    assert_eq!(refused.reset.unwrap().kind, ResetKind::Refused);

    let aborted = conn(10);
    assert_eq!(aborted.status(), TcpStatus::Reset(Side::Server));
    assert_eq!(aborted.reset.unwrap().kind, ResetKind::Aborted);

    let closed = conn(11);
    assert_eq!(closed.status(), TcpStatus::Closed);
    assert_eq!(closed.reset.unwrap().kind, ResetKind::WhileClosing);
}
