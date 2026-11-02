mod common;

use std::net::IpAddr;

use common::*;
use packet_cage::analyze::Analyzer;
use packet_cage::capture::{Frame, Timestamp};
use packet_cage::decode::{self, link_type};
use packet_cage::stats::{self, Stats};

fn collect(packets: Vec<Vec<u8>>) -> (Stats, Analyzer) {
    let mut stats = Stats::default();
    let mut flows = Analyzer::new();
    for (i, data) in packets.into_iter().enumerate() {
        let frame = Frame {
            number: i as u64 + 1,
            ts: Timestamp(1_700_000_000_000_000_000 + i as u64 * 500_000_000),
            link_type: link_type::ETHERNET,
            orig_len: data.len() as u32,
            data,
        };
        let pkt = decode::decode(&frame);
        flows.observe(&frame, &pkt);
        stats.add(&frame, &pkt);
    }
    (stats, flows)
}

fn sample() -> Vec<Vec<u8>> {
    let (a, b, c) = ([10, 0, 0, 1], [10, 0, 0, 2], [10, 0, 0, 3]);
    let mut truncated = ethernet(0x0800, &ipv4(a, c, 6, &tcp(1, 2, 3, 4, ACK, &[])));
    truncated.truncate(40);
    vec![
        ethernet(0x0800, &ipv4(a, b, 6, &tcp(50000, 443, 1, 0, SYN, &[]))),
        ethernet(
            0x0800,
            &ipv4(b, a, 6, &tcp(443, 50000, 1, 2, SYN | ACK, &[])),
        ),
        ethernet(0x0800, &ipv4(a, c, 17, &udp(40000, 53, &[0; 30]))),
        ethernet(
            0x0806,
            &[
                0, 1, 8, 0, 6, 4, 0, 1, 2, 0, 0, 0, 0, 1, 10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 10, 0, 0,
                2,
            ],
        ),
        truncated,
    ]
}

#[test]
fn protocol_tree_and_hosts() {
    let (stats, _) = collect(sample());
    assert_eq!(stats.total.packets, 5);
    assert_eq!(stats.duration_secs(), 2.0);

    let mut tree = Vec::new();
    for node in stats.protocols.sorted_children() {
        tree.push((node.name.clone(), node.count.packets));
        for child in node.sorted_children() {
            tree.push((format!("{}/{}", node.name, child.name), child.count.packets));
        }
    }
    assert_eq!(
        tree,
        vec![
            ("IPv4".to_string(), 4),
            ("IPv4/TCP".to_string(), 2),
            ("IPv4/UDP".to_string(), 1),
            ("IPv4/malformed".to_string(), 1),
            ("ARP".to_string(), 1),
        ]
    );

    let hosts = stats.busiest_hosts();
    assert_eq!(hosts[0].0, IpAddr::from([10, 0, 0, 1]));
    // SYN, the DNS query, and the truncated packet (its IP header is intact).
    assert_eq!(hosts[0].1.sent.packets, 3);
    assert_eq!(hosts[0].1.received.packets, 1);
}

#[test]
fn rendered_report() {
    let (stats, flows) = collect(sample());
    let report = stats::render(&stats, &flows, 10);
    assert!(report.contains("Packets   5\n"), "{report}");
    assert!(
        report.contains("Start     2023-11-14 22:13:20.000 UTC\n"),
        "{report}"
    );
    assert!(report.contains("TCP conversations: 1\n"), "{report}");
    assert!(report.contains("UDP conversations: 1\n"), "{report}");
    let tcp_row = report
        .lines()
        .find(|l| l.contains("10.0.0.1:50000"))
        .expect("TCP conversation row");
    assert!(tcp_row.contains("10.0.0.2:443"), "{tcp_row}");
    assert!(tcp_row.ends_with("handshake incomplete"), "{tcp_row}");
}

#[test]
fn top_limits_rows() {
    let packets = (0..5)
        .map(|i| {
            ethernet(
                0x0800,
                &ipv4([10, 0, 0, 1], [10, 0, 1, i], 17, &udp(40000, 53, &[])),
            )
        })
        .collect();
    let (stats, flows) = collect(packets);
    let report = stats::render(&stats, &flows, 2);
    assert!(
        report.contains("UDP conversations: 5, showing top 2 by bytes\n"),
        "{report}"
    );
    assert!(
        report.contains("Hosts: 6, showing top 2 by bytes\n"),
        "{report}"
    );
}
