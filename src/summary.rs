//! One-line packet descriptions for `packet-cage dump`, in the spirit of
//! tcpdump and Wireshark's Info column.

use std::fmt::Write;
use std::net::SocketAddr;

use crate::analyze::PacketFindings;
use crate::decode::{Arp, Icmp, Link, Network, Packet, Tcp, TcpFlags, Transport};
use crate::names;

/// Values subtracted from a TCP segment's sequence and acknowledgement
/// numbers, so they count from the start of the connection the way Wireshark
/// shows them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SeqBase {
    pub seq: u32,
    pub ack: u32,
}

/// Describes `pkt` in one line. TCP numbers are shown relative to `seq_base`
/// when given, and as raw values otherwise.
pub fn describe(pkt: &Packet<'_>, seq_base: Option<SeqBase>) -> String {
    let mut line = match (&pkt.network, &pkt.transport) {
        (Some(net), Some(transport)) => {
            describe_transport(net, transport, seq_base.unwrap_or_default())
        }
        (Some(net), None) => describe_network(&pkt.link, net),
        (None, _) => describe_link(&pkt.link, pkt.error.is_some()),
    };
    if let Some(err) = &pkt.error {
        if !line.is_empty() {
            line.push(' ');
        }
        let _ = write!(line, "[{err}]");
    }
    line
}

/// The `dump` line for a packet, including what the analysis found: TCP
/// flags such as retransmissions, and DNS queries and responses.
pub fn describe_with(
    pkt: &Packet<'_>,
    found: &PacketFindings,
    seq_base: Option<SeqBase>,
) -> String {
    let dns = &found.dns;
    let dns_text = || -> String {
        let mut parts: Vec<String> = dns.messages.iter().map(|m| m.summary()).collect();
        if let Some(err) = &dns.error {
            parts.push(format!("[{err}]"));
        }
        if dns.cut_short {
            parts.push("[cut off by capture length limit]".to_string());
        }
        parts.join("; ")
    };
    let has_dns = !dns.messages.is_empty() || dns.error.is_some() || dns.cut_short;
    let mut line = match (
        &pkt.transport,
        pkt.network.as_ref().and_then(Network::ip_addrs),
    ) {
        // For DNS over UDP the DNS summary replaces "UDP len=N".
        (Some(Transport::Udp(udp)), Some((src, dst))) if has_dns => format!(
            "{} → {} DNS {}",
            SocketAddr::new(src, udp.src_port),
            SocketAddr::new(dst, udp.dst_port),
            dns_text()
        ),
        _ => describe(pkt, seq_base),
    };
    for event in found.flow.iter().flat_map(|o| &o.tcp_events) {
        let _ = write!(line, " [{event}]");
    }
    for event in &found.tls {
        let _ = write!(line, " TLS {event}");
    }
    for event in &found.http {
        let _ = write!(line, " HTTP {event}");
    }
    if has_dns && matches!(pkt.transport, Some(Transport::Tcp(_))) {
        let _ = write!(line, " DNS {}", dns_text());
    }
    if let Some(frame) = dns.icmp_about {
        let _ = write!(line, " [about the DNS query in frame {frame}]");
    }
    line
}

fn describe_transport(net: &Network, transport: &Transport, base: SeqBase) -> String {
    let Some((src, dst)) = net.ip_addrs() else {
        return String::new();
    };
    match transport {
        Transport::Tcp(tcp) => format!(
            "{} → {} TCP {}",
            SocketAddr::new(src, tcp.src_port),
            SocketAddr::new(dst, tcp.dst_port),
            tcp_info(tcp, base)
        ),
        Transport::Udp(udp) => format!(
            "{} → {} UDP len={}",
            SocketAddr::new(src, udp.src_port),
            SocketAddr::new(dst, udp.dst_port),
            udp.payload_len
        ),
        Transport::Icmp(icmp) => {
            let name = if icmp.v6 { "ICMPv6" } else { "ICMP" };
            format!("{src} → {dst} {name} {}", icmp_info(icmp))
        }
        Transport::Other { protocol } => format!("{src} → {dst} {}", names::ip_protocol(*protocol)),
    }
}

fn tcp_info(tcp: &Tcp, base: SeqBase) -> String {
    let mut s = format!("[{}] seq={}", tcp.flags, tcp.seq.wrapping_sub(base.seq));
    if tcp.flags.has(TcpFlags::ACK) {
        let _ = write!(s, " ack={}", tcp.ack.wrapping_sub(base.ack));
    }
    let _ = write!(s, " win={} len={}", tcp.window, tcp.payload_len);
    let opts = &tcp.options;
    if let Some(mss) = opts.mss {
        let _ = write!(s, " mss={mss}");
    }
    if let Some(ws) = opts.window_scale {
        let _ = write!(s, " wscale={ws}");
    }
    if opts.sack_permitted {
        s.push_str(" sack_perm");
    }
    // SACK edges acknowledge the other direction's data, like the ack field.
    for (left, right) in &opts.sack {
        let (left, right) = (left.wrapping_sub(base.ack), right.wrapping_sub(base.ack));
        let _ = write!(s, " sack={left}-{right}");
    }
    s
}

fn describe_network(link: &Link, net: &Network) -> String {
    match net {
        Network::Ipv4(h) if h.fragment_offset > 0 => format!(
            "{} → {} IPv4 fragment offset={} ({})",
            h.src,
            h.dst,
            h.fragment_offset,
            names::ip_protocol(h.protocol)
        ),
        Network::Ipv4(h) => format!("{} → {} {}", h.src, h.dst, names::ip_protocol(h.protocol)),
        Network::Ipv6(h) => match h.fragment {
            Some(frag) if frag.offset > 0 => format!(
                "{} → {} IPv6 fragment offset={} ({})",
                h.src,
                h.dst,
                frag.offset,
                names::ip_protocol(h.protocol)
            ),
            _ => format!("{} → {} {}", h.src, h.dst, names::ip_protocol(h.protocol)),
        },
        Network::Arp(arp) => arp_info(arp),
        Network::Other { ethertype } => match link {
            Link::Ethernet { src, dst, .. } => {
                format!("{src} → {dst} {}", names::ethertype(*ethertype))
            }
            _ => names::ethertype(*ethertype),
        },
    }
}

/// Used when decoding stopped at the link layer.
fn describe_link(link: &Link, has_error: bool) -> String {
    match link {
        Link::Ethernet {
            src,
            dst,
            ethertype,
            ..
        } => {
            format!("{src} → {dst} {}", names::ethertype(*ethertype))
        }
        Link::Unsupported(lt) if !has_error => format!("link type {lt} (not decoded)"),
        _ => String::new(),
    }
}

fn arp_info(arp: &Arp) -> String {
    match (arp.operation, arp.sender_ip, arp.target_ip, arp.sender_mac) {
        (1, Some(sender), Some(target), _) if sender.is_unspecified() => {
            format!("ARP probe for {target}")
        }
        (1, Some(sender), Some(target), _) if sender == target => {
            format!("ARP announcement for {target}")
        }
        (1, Some(sender), Some(target), _) => format!("ARP who has {target}? tell {sender}"),
        (2, Some(sender), _, Some(mac)) => format!("ARP {sender} is at {mac}"),
        (op, ..) => format!("ARP operation {op}"),
    }
}

fn icmp_info(icmp: &Icmp) -> String {
    names::icmp(icmp.v6, icmp.icmp_type, icmp.code)
}
