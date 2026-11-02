mod common;

use common::*;
use packet_cage::capture::{Frame, Timestamp};
use packet_cage::decode::{self, link_type};
use packet_cage::flow::{FlowRef, FlowTable, Side, TcpStatus};
use packet_cage::summary::describe;

const CLIENT: [u8; 4] = [10, 0, 0, 1];
const SERVER: [u8; 4] = [10, 0, 0, 2];

/// A TCP segment between CLIENT:50000 and SERVER:443.
fn seg(from_client: bool, seq: u32, ack: u32, flags: u8, payload_len: usize) -> Vec<u8> {
    let data = vec![0u8; payload_len];
    let (src, dst, sport, dport) = if from_client {
        (CLIENT, SERVER, 50000, 443)
    } else {
        (SERVER, CLIENT, 443, 50000)
    };
    ethernet(
        0x0800,
        &ipv4(src, dst, 6, &tcp(sport, dport, seq, ack, flags, &data)),
    )
}

fn frame(number: u64, data: Vec<u8>) -> Frame {
    Frame {
        number,
        ts: Timestamp(number * 1_000_000),
        link_type: link_type::ETHERNET,
        orig_len: data.len() as u32,
        data,
    }
}

/// Feeds packets through a flow table; returns the table and, per packet,
/// its flow and its `dump` line with relative sequence numbers.
fn run(packets: Vec<Vec<u8>>) -> (FlowTable, Vec<Option<FlowRef>>, Vec<String>) {
    let mut table = FlowTable::new();
    let mut refs = Vec::new();
    let mut lines = Vec::new();
    for (i, data) in packets.into_iter().enumerate() {
        let frame = frame(i as u64 + 1, data);
        let pkt = decode::decode(&frame);
        let r = table.observe(&frame, &pkt).map(|o| o.flow);
        lines.push(describe(&pkt, r.and_then(|r| table.seq_base(r))));
        refs.push(r);
    }
    (table, refs, lines)
}

fn status(table: &FlowTable, index: usize) -> TcpStatus {
    table.flows()[index].tcp.as_ref().unwrap().status()
}

#[test]
fn full_connection() {
    let (table, refs, lines) = run(vec![
        seg(true, 1000, 0, SYN, 0),
        seg(false, 5000, 1001, SYN | ACK, 0),
        seg(true, 1001, 5001, ACK, 0),
        seg(true, 1001, 5001, PSH | ACK, 100),
        seg(false, 5001, 1101, PSH | ACK, 300),
        seg(true, 1101, 5301, FIN | ACK, 0),
        seg(false, 5301, 1102, FIN | ACK, 0),
        seg(true, 1102, 5302, ACK, 0),
    ]);
    assert_eq!(table.flows().len(), 1);
    let flow = &table.flows()[0];
    assert_eq!(flow.stream, 0);
    assert_eq!(flow.client.to_string(), "10.0.0.1:50000");
    assert_eq!(flow.server.to_string(), "10.0.0.2:443");
    assert_eq!((flow.from_client.packets, flow.from_server.packets), (5, 3));
    assert_eq!((flow.first_frame, flow.last_frame), (1, 8));
    let conn = flow.tcp.as_ref().unwrap();
    assert_eq!(conn.status(), TcpStatus::Closed);
    assert!(!conn.started_before_capture());
    assert_eq!(conn.syn.map(|(frame, _)| frame), Some(1));
    assert_eq!(conn.syn_ack.map(|(frame, _)| frame), Some(2));
    assert_eq!(refs[1].unwrap().from, Side::Server);

    // Relative numbers, as Wireshark shows them.
    assert!(lines[0].contains("[SYN] seq=0 win"), "{}", lines[0]);
    assert!(lines[1].contains("[SYN, ACK] seq=0 ack=1 "), "{}", lines[1]);
    assert!(
        lines[3].contains("[PSH, ACK] seq=1 ack=1 win=64240 len=100"),
        "{}",
        lines[3]
    );
    assert!(
        lines[4].contains("[PSH, ACK] seq=1 ack=101 win=64240 len=300"),
        "{}",
        lines[4]
    );
    assert!(lines[7].contains("[ACK] seq=102 ack=302 "), "{}", lines[7]);
}

#[test]
fn relative_numbers_wrap_around() {
    let (_, _, lines) = run(vec![
        seg(true, u32::MAX - 10, 0, SYN, 0),
        seg(false, 7, u32::MAX - 9, SYN | ACK, 0),
        seg(true, u32::MAX - 9, 8, PSH | ACK, 50),
        seg(true, 40, 8, PSH | ACK, 10),
    ]);
    assert!(lines[2].contains("seq=1 ack=1 "), "{}", lines[2]);
    assert!(lines[3].contains("seq=51 ack=1 "), "{}", lines[3]);
}

#[test]
fn refused_connection() {
    let (table, _, _) = run(vec![
        seg(true, 1000, 0, SYN, 0),
        seg(false, 0, 1001, RST | ACK, 0),
    ]);
    assert_eq!(status(&table, 0), TcpStatus::Refused);
}

#[test]
fn unanswered_syn_retransmissions_stay_in_one_flow() {
    let (table, _, _) = run(vec![
        seg(true, 1000, 0, SYN, 0),
        seg(true, 1000, 0, SYN, 0),
        seg(true, 1000, 0, SYN, 0),
    ]);
    assert_eq!(table.flows().len(), 1);
    assert_eq!(table.flows()[0].from_client.packets, 3);
    assert_eq!(status(&table, 0), TcpStatus::NoAnswer);
}

#[test]
fn handshake_without_final_ack() {
    let (table, _, _) = run(vec![
        seg(true, 1000, 0, SYN, 0),
        seg(false, 5000, 1001, SYN | ACK, 0),
    ]);
    assert_eq!(status(&table, 0), TcpStatus::HandshakeIncomplete);
}

#[test]
fn reset_mid_connection() {
    let (table, _, _) = run(vec![
        seg(true, 1000, 0, SYN, 0),
        seg(false, 5000, 1001, SYN | ACK, 0),
        seg(true, 1001, 5001, ACK, 0),
        seg(true, 1001, 5001, RST | ACK, 0),
    ]);
    assert_eq!(status(&table, 0), TcpStatus::Reset(Side::Client));
}

#[test]
fn reset_after_both_fins_counts_as_closed() {
    let (table, _, _) = run(vec![
        seg(true, 1000, 0, SYN, 0),
        seg(false, 5000, 1001, SYN | ACK, 0),
        seg(true, 1001, 5001, FIN | ACK, 0),
        seg(false, 5001, 1002, FIN | ACK, 0),
        seg(true, 1002, 5002, RST, 0),
    ]);
    assert_eq!(status(&table, 0), TcpStatus::Closed);
}

#[test]
fn new_syn_after_close_starts_a_new_stream() {
    let (table, refs, _) = run(vec![
        seg(true, 1000, 0, SYN, 0),
        seg(false, 5000, 1001, SYN | ACK, 0),
        seg(true, 1001, 5001, FIN | ACK, 0),
        seg(false, 5001, 1002, FIN | ACK, 0),
        // Same ports, new initial sequence number.
        seg(true, 90_000, 0, SYN, 0),
        seg(false, 70_000, 90_001, SYN | ACK, 0),
    ]);
    assert_eq!(table.flows().len(), 2);
    assert_eq!(table.flows()[1].stream, 1);
    assert_eq!(refs[5].unwrap().index, 1);
    assert_eq!(status(&table, 0), TcpStatus::Closed);
    assert_eq!(status(&table, 1), TcpStatus::HandshakeIncomplete);
}

#[test]
fn connection_already_open_when_capture_started() {
    // First packet seen is data from the server.
    let (table, refs, lines) = run(vec![
        seg(false, 777_000, 333_000, PSH | ACK, 200),
        seg(true, 333_000, 777_200, ACK, 0),
    ]);
    let flow = &table.flows()[0];
    assert_eq!(flow.server.port(), 443);
    assert_eq!(refs[0].unwrap().from, Side::Server);
    let conn = flow.tcp.as_ref().unwrap();
    assert!(conn.started_before_capture());
    assert_eq!(conn.status(), TcpStatus::Open);
    assert!(lines[0].contains("seq=1 ack=1 "), "{}", lines[0]);
    assert!(lines[1].contains("seq=1 ack=201 "), "{}", lines[1]);
}

#[test]
fn udp_flows_have_their_own_stream_numbers() {
    let dns = |from_client: bool| {
        let (src, dst, sport, dport) = if from_client {
            (CLIENT, SERVER, 40000, 53)
        } else {
            (SERVER, CLIENT, 53, 40000)
        };
        ethernet(0x0800, &ipv4(src, dst, 17, &udp(sport, dport, b"dns")))
    };
    // The response arrives first, e.g. the query was sent before the capture started.
    let (table, refs, _) = run(vec![seg(true, 1, 0, SYN, 0), dns(false), dns(true)]);
    let flow = table.get(refs[1].unwrap());
    assert_eq!(flow.stream, 0);
    assert!(flow.tcp.is_none());
    assert_eq!(flow.server.port(), 53);
    assert_eq!((flow.from_client.packets, flow.from_server.packets), (1, 1));
}

#[test]
fn same_kind_of_ports_first_sender_is_client() {
    let packet = |src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16| {
        ethernet(0x0800, &ipv4(src, dst, 17, &udp(sport, dport, b"x")))
    };
    let (table, _, _) = run(vec![
        packet(CLIENT, SERVER, 50001, 61000),
        packet(SERVER, CLIENT, 61000, 50001),
    ]);
    assert_eq!(table.flows()[0].client.to_string(), "10.0.0.1:50001");
}

#[test]
fn non_ip_packets_have_no_flow() {
    let arp = ethernet(
        0x0806,
        &[
            0, 1, 8, 0, 6, 4, 0, 1, 2, 0, 0, 0, 0, 1, 10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 10, 0, 0, 2,
        ],
    );
    let (table, refs, _) = run(vec![arp]);
    assert_eq!(refs[0], None);
    assert!(table.flows().is_empty());
}

#[test]
fn rst_without_an_observed_syn_is_not_refused() {
    // The capture starts with the server's RST; the SYN it answered wasn't captured.
    let (table, _, _) = run(vec![seg(false, 0, 1001, RST | ACK, 0)]);
    assert_eq!(status(&table, 0), TcpStatus::Reset(Side::Server));
}

#[test]
fn server_port_in_linux_ephemeral_range_with_windows_client() {
    // Server listens on 40000; the Windows client uses 50000. The capture
    // starts with the server's response, so there's no SYN to go by.
    let packet = |src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16| {
        ethernet(0x0800, &ipv4(src, dst, 17, &udp(sport, dport, b"x")))
    };
    let (table, _, _) = run(vec![
        packet(SERVER, CLIENT, 40000, 50000),
        packet(CLIENT, SERVER, 50000, 40000),
    ]);
    assert_eq!(table.flows()[0].server.to_string(), "10.0.0.2:40000");
}

#[test]
fn linux_client_port_against_registered_server_port() {
    let packet = |src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16| {
        ethernet(0x0800, &ipv4(src, dst, 17, &udp(sport, dport, b"x")))
    };
    let (table, _, _) = run(vec![packet(SERVER, CLIENT, 8080, 35000)]);
    assert_eq!(table.flows()[0].server.to_string(), "10.0.0.2:8080");
}
