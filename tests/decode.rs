mod common;

use std::net::{IpAddr, Ipv4Addr};

use common::*;
use packet_cage::decode::{
    Link, Network, Packet, Problem, Tcp, TcpFlags, Transport, decode_bytes, link_type,
};
use packet_cage::summary::describe;

const CLIENT: [u8; 4] = [10, 0, 0, 1];
const SERVER: [u8; 4] = [93, 184, 216, 34];

fn decode_eth(frame: &[u8]) -> Packet<'_> {
    decode_bytes(link_type::ETHERNET, frame, frame.len() as u32)
}

fn tcp_of<'a>(pkt: &'a Packet<'_>) -> &'a Tcp {
    match &pkt.transport {
        Some(Transport::Tcp(tcp)) => tcp,
        other => panic!("expected TCP, got {other:?} (error: {:?})", pkt.error),
    }
}

#[test]
fn syn_with_options() {
    // MSS 1460, NOP, window scale 7, SACK permitted, timestamps 1/0.
    let opts = [
        2, 4, 0x05, 0xb4, 1, 3, 3, 7, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0,
    ];
    let frame = ethernet(
        0x0800,
        &ipv4(
            CLIENT,
            SERVER,
            6,
            &tcp_with_options(51234, 443, 1000, 0, SYN, &opts, &[]),
        ),
    );
    let pkt = decode_eth(&frame);
    assert_eq!(pkt.error, None);
    let tcp = tcp_of(&pkt);
    assert_eq!((tcp.src_port, tcp.dst_port, tcp.seq), (51234, 443, 1000));
    assert!(tcp.flags.has(TcpFlags::SYN) && !tcp.flags.has(TcpFlags::ACK));
    assert_eq!(tcp.options.mss, Some(1460));
    assert_eq!(tcp.options.window_scale, Some(7));
    assert!(tcp.options.sack_permitted);
    assert_eq!(tcp.options.timestamps, Some((1, 0)));
    assert_eq!(tcp.payload_len, 0);
    assert_eq!(
        describe(&pkt, None),
        "10.0.0.1:51234 → 93.184.216.34:443 TCP [SYN] seq=1000 win=64240 len=0 mss=1460 wscale=7 sack_perm"
    );
}

#[test]
fn ethernet_padding_is_not_payload() {
    // A bare ACK is 54 bytes; Ethernet pads it to the 60-byte minimum.
    let mut frame = ethernet(
        0x0800,
        &ipv4(CLIENT, SERVER, 6, &tcp(51234, 443, 1, 1, ACK, &[])),
    );
    frame.resize(60, 0);
    let pkt = decode_eth(&frame);
    assert_eq!(tcp_of(&pkt).payload_len, 0);
    assert!(pkt.payload.is_empty());
}

#[test]
fn snaplen_keeps_real_segment_length() {
    let data = vec![b'x'; 1000];
    let frame = ethernet(
        0x0800,
        &ipv4(CLIENT, SERVER, 6, &tcp(51234, 443, 1, 1, ACK, &data)),
    );
    // Captured with a 96-byte snaplen.
    let pkt = decode_bytes(link_type::ETHERNET, &frame[..96], frame.len() as u32);
    assert_eq!(pkt.error, None);
    assert_eq!(tcp_of(&pkt).payload_len, 1000);
    assert_eq!(pkt.payload.len(), 96 - 54);
}

#[test]
fn snaplen_inside_tcp_header_is_reported_as_cut_short() {
    let frame = ethernet(
        0x0800,
        &ipv4(CLIENT, SERVER, 6, &tcp(51234, 443, 1, 1, ACK, b"hello")),
    );
    let pkt = decode_bytes(link_type::ETHERNET, &frame[..40], frame.len() as u32);
    assert!(matches!(pkt.network, Some(Network::Ipv4(_))));
    assert_eq!(pkt.transport, None);
    let err = pkt.error.unwrap();
    assert_eq!((err.layer, err.problem), ("TCP", Problem::CutShort));
}

#[test]
fn truncated_without_snaplen_is_malformed() {
    let frame = ethernet(
        0x0800,
        &ipv4(CLIENT, SERVER, 6, &tcp(51234, 443, 1, 1, ACK, &[])),
    );
    let pkt = decode_eth(&frame[..40]);
    let err = pkt.error.unwrap();
    assert_eq!(err.layer, "TCP");
    assert_eq!(err.problem, Problem::Truncated { need: 20, have: 6 });
}

#[test]
fn zero_total_length_from_segmentation_offload() {
    let mut frame = ethernet(
        0x0800,
        &ipv4(CLIENT, SERVER, 6, &tcp(51234, 443, 1, 1, ACK, &[7; 3000])),
    );
    // IPv4 total length field is 0, as the NIC fills it in later.
    frame[16] = 0;
    frame[17] = 0;
    let pkt = decode_eth(&frame);
    assert_eq!(tcp_of(&pkt).payload_len, 3000);
}

#[test]
fn vlan_tagged_frame() {
    let ip = ipv4(CLIENT, SERVER, 17, &udp(5353, 53, b"query"));
    let frame = ethernet(0x8100, &vlan(100, 0x0800, &ip));
    let pkt = decode_eth(&frame);
    let Link::Ethernet { vlans, .. } = &pkt.link else {
        panic!("expected Ethernet")
    };
    assert_eq!(vlans, &[100]);
    let Some(Transport::Udp(udp)) = &pkt.transport else {
        panic!("expected UDP")
    };
    assert_eq!((udp.dst_port, udp.payload_len), (53, 5));
    assert_eq!(pkt.payload, b"query");
}

#[test]
fn ipv6_extension_headers_are_skipped() {
    // Hop-by-hop options header (8 bytes) in front of UDP.
    let mut payload = vec![17, 0, 1, 4, 0, 0, 0, 0];
    payload.extend(udp(40000, 53, b"q"));
    let frame = ethernet(0x86dd, &ipv6("2001:db8::1", "2001:db8::2", 0, &payload));
    let pkt = decode_eth(&frame);
    assert_eq!(pkt.error, None);
    let Some(Network::Ipv6(ip)) = &pkt.network else {
        panic!("expected IPv6")
    };
    assert_eq!(ip.protocol, 17);
    assert_eq!(
        describe(&pkt, None),
        "[2001:db8::1]:40000 → [2001:db8::2]:53 UDP len=1"
    );
}

#[test]
fn ipv6_later_fragment_has_no_transport_header() {
    // Fragment header: next header UDP, offset 1448 bytes, more fragments.
    let offset: u16 = 1448 | 1;
    let mut payload = vec![17, 0];
    payload.extend(offset.to_be_bytes());
    payload.extend(0xdead_beefu32.to_be_bytes());
    payload.extend([0u8; 100]);
    let frame = ethernet(0x86dd, &ipv6("2001:db8::1", "2001:db8::2", 44, &payload));
    let pkt = decode_eth(&frame);
    let Some(Network::Ipv6(ip)) = &pkt.network else {
        panic!("expected IPv6")
    };
    let frag = ip.fragment.unwrap();
    assert_eq!((frag.offset, frag.more, frag.id), (1448, true, 0xdead_beef));
    assert_eq!(pkt.transport, None);
    assert_eq!(pkt.error, None);
}

#[test]
fn ipv4_later_fragment_has_no_transport_header() {
    let mut ip = ipv4(CLIENT, SERVER, 17, &[0u8; 64]);
    ip[6] = 0x00; // flags: last fragment
    ip[7] = 185; // offset 185 * 8 = 1480 bytes
    let frame = ethernet(0x0800, &ip);
    let pkt = decode_eth(&frame);
    let Some(Network::Ipv4(h)) = &pkt.network else {
        panic!("expected IPv4")
    };
    assert_eq!(h.fragment_offset, 1480);
    assert_eq!(pkt.transport, None);
    assert!(describe(&pkt, None).contains("IPv4 fragment offset=1480 (UDP)"));
}

#[test]
fn linux_cooked_v1_and_v2() {
    let ip = ipv4(CLIENT, SERVER, 6, &tcp(1, 2, 3, 4, SYN, &[]));

    let mut sll = vec![0, 4, 0, 1, 0, 6, 2, 0, 0, 0, 0, 1, 0, 0];
    sll.extend(0x0800u16.to_be_bytes());
    sll.extend(&ip);
    let pkt = decode_bytes(link_type::LINUX_SLL, &sll, sll.len() as u32);
    assert_eq!(pkt.link, Link::LinuxCooked);
    assert_eq!(tcp_of(&pkt).dst_port, 2);

    let mut sll2 = 0x0800u16.to_be_bytes().to_vec();
    sll2.extend([0, 0, 0, 0, 0, 2, 0, 1, 4, 6, 2, 0, 0, 0, 0, 1, 0, 0]);
    sll2.extend(&ip);
    let pkt = decode_bytes(link_type::LINUX_SLL2, &sll2, sll2.len() as u32);
    assert_eq!(tcp_of(&pkt).dst_port, 2);
}

#[test]
fn loopback_in_either_byte_order() {
    let ip = ipv4([127, 0, 0, 1], [127, 0, 0, 1], 17, &udp(1, 2, &[]));
    for family in [2u32.to_le_bytes(), 2u32.to_be_bytes()] {
        let mut frame = family.to_vec();
        frame.extend(&ip);
        let pkt = decode_bytes(link_type::NULL, &frame, frame.len() as u32);
        assert_eq!(pkt.link, Link::Loopback);
        assert!(matches!(pkt.transport, Some(Transport::Udp(_))), "{pkt:?}");
    }
}

#[test]
fn raw_ip() {
    let ip = ipv6("::1", "::1", 58, &[128, 0, 0, 0, 0, 1, 0, 1]);
    let pkt = decode_bytes(link_type::RAW, &ip, ip.len() as u32);
    assert_eq!(pkt.link, Link::RawIp);
    assert_eq!(describe(&pkt, None), "::1 → ::1 ICMPv6 echo request");
}

#[test]
fn arp_request_and_reply() {
    let mut arp = vec![0, 1, 8, 0, 6, 4, 0, 1];
    arp.extend([0x02, 0, 0, 0, 0, 0x01, 10, 0, 0, 1]);
    arp.extend([0, 0, 0, 0, 0, 0, 10, 0, 0, 254]);
    let frame = ethernet(0x0806, &arp);
    let pkt = decode_eth(&frame);
    let Some(Network::Arp(a)) = &pkt.network else {
        panic!("expected ARP")
    };
    assert_eq!(a.sender_ip, Some(Ipv4Addr::new(10, 0, 0, 1)));
    assert_eq!(
        describe(&pkt, None),
        "ARP who has 10.0.0.254? tell 10.0.0.1"
    );

    arp[7] = 2;
    let frame = ethernet(0x0806, &arp);
    let pkt = decode_eth(&frame);
    assert_eq!(describe(&pkt, None), "ARP 10.0.0.1 is at 02:00:00:00:00:01");
}

#[test]
fn bad_ipv4_header_length_keeps_link_layer() {
    let mut ip = ipv4(CLIENT, SERVER, 6, &tcp(1, 2, 3, 4, SYN, &[]));
    ip[0] = 0x43; // header length 12 bytes
    let frame = ethernet(0x0800, &ip);
    let pkt = decode_eth(&frame);
    assert!(matches!(
        pkt.link,
        Link::Ethernet {
            ethertype: 0x0800,
            ..
        }
    ));
    assert_eq!(pkt.network, None);
    assert_eq!(
        describe(&pkt, None),
        "02:00:00:00:00:01 → 02:00:00:00:00:02 IPv4 [malformed IPv4: header length 12 is below the minimum of 20]"
    );
}

#[test]
fn ip_addresses_for_reports() {
    let frame = ethernet(0x0800, &ipv4(CLIENT, SERVER, 6, &tcp(1, 2, 3, 4, SYN, &[])));
    let pkt = decode_eth(&frame);
    let (src, dst) = pkt.network.as_ref().unwrap().ip_addrs().unwrap();
    assert_eq!(src, IpAddr::from(CLIENT));
    assert_eq!(dst, IpAddr::from(SERVER));
}

#[test]
fn unsupported_link_type_is_not_an_error() {
    let pkt = decode_bytes(147, &[1, 2, 3], 3);
    assert_eq!(pkt.error, None);
    assert_eq!(describe(&pkt, None), "link type 147 (not decoded)");
}

/// Mutated and truncated versions of valid packets must never panic. Starting
/// from valid packets reaches deeper layers than purely random bytes would.
#[test]
fn mutated_packets_never_panic() {
    let mut opts = vec![2, 4, 5, 0xb4, 5, 10, 0, 0, 0, 1, 0, 0, 0, 2, 1, 1];
    opts.resize(20, 1);
    let seeds = [
        ethernet(
            0x0800,
            &ipv4(
                CLIENT,
                SERVER,
                6,
                &tcp_with_options(1, 2, 3, 4, SYN, &opts, b"data"),
            ),
        ),
        ethernet(
            0x8100,
            &vlan(
                7,
                0x86dd,
                &ipv6(
                    "::1",
                    "::2",
                    0,
                    &[17, 0, 1, 4, 0, 0, 0, 0, 0, 1, 0, 2, 0, 9, 0, 0, 7],
                ),
            ),
        ),
        ethernet(
            0x0806,
            &[
                0, 1, 8, 0, 6, 4, 0, 1, 2, 0, 0, 0, 0, 1, 10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 10, 0, 0,
                2,
            ],
        ),
        ipv4(CLIENT, SERVER, 1, &[3, 3, 0, 0, 0, 0, 0, 0]),
    ];
    let link_types = [
        link_type::ETHERNET,
        link_type::RAW,
        link_type::NULL,
        link_type::LINUX_SLL,
        link_type::LINUX_SLL2,
    ];
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for _ in 0..50_000 {
        let mut data = seeds[rng.below(seeds.len())].clone();
        for _ in 0..1 + rng.below(4) {
            let i = rng.below(data.len());
            data[i] = rng.next() as u8;
        }
        data.truncate(rng.below(data.len() + 1));
        let link = link_types[rng.below(link_types.len())];
        let orig_len = (data.len() + rng.below(100)) as u32;
        let pkt = decode_bytes(link, &data, orig_len);
        let _ = describe(&pkt, None);
    }
}
