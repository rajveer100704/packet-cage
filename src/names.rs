//! Human-readable names for protocol numbers.

pub fn ip_protocol(protocol: u8) -> String {
    let name = match protocol {
        1 => "ICMP",
        2 => "IGMP",
        6 => "TCP",
        17 => "UDP",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        89 => "OSPF",
        103 => "PIM",
        112 => "VRRP",
        132 => "SCTP",
        p => return format!("IP protocol {p}"),
    };
    name.to_string()
}

pub fn ethertype(ethertype: u16) -> String {
    let name = match ethertype {
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x86dd => "IPv6",
        0x8035 => "RARP",
        0x8847 | 0x8848 => "MPLS",
        0x8863 => "PPPoE discovery",
        0x8864 => "PPPoE session",
        0x888e => "EAPOL (802.1X)",
        0x88cc => "LLDP",
        0x88e5 => "MACsec",
        t if t < 0x0600 => "802.3 LLC",
        t => return format!("EtherType {t:#06x}"),
    };
    name.to_string()
}

/// What an ICMP or ICMPv6 message is, from its type and code.
pub fn icmp(v6: bool, icmp_type: u8, code: u8) -> String {
    let text = if v6 {
        match (icmp_type, code) {
            (1, 1) => "destination unreachable (administratively prohibited)",
            (1, 3) => "destination unreachable (address unreachable)",
            (1, 4) => "destination unreachable (port unreachable)",
            (1, _) => "destination unreachable",
            (2, _) => "packet too big",
            (3, _) => "hop limit exceeded",
            (128, _) => "echo request",
            (129, _) => "echo reply",
            (133, _) => "router solicitation",
            (134, _) => "router advertisement",
            (135, _) => "neighbor solicitation",
            (136, _) => "neighbor advertisement",
            (137, _) => "redirect",
            (143, _) => "multicast listener report v2",
            (t, c) => return format!("type {t} code {c}"),
        }
    } else {
        match (icmp_type, code) {
            (0, _) => "echo reply",
            (3, 0) => "destination unreachable (network unreachable)",
            (3, 1) => "destination unreachable (host unreachable)",
            (3, 3) => "destination unreachable (port unreachable)",
            (3, 4) => "destination unreachable (fragmentation needed)",
            (3, 9 | 10 | 13) => "destination unreachable (administratively prohibited)",
            (3, _) => "destination unreachable",
            (5, _) => "redirect",
            (8, _) => "echo request",
            (11, 0) => "time exceeded (TTL expired in transit)",
            (11, _) => "time exceeded (fragment reassembly)",
            (t, c) => return format!("type {t} code {c}"),
        }
    };
    text.to_string()
}
