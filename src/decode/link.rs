//! Link layers: what comes before the IP header.

use std::fmt;

use super::{DecodeError, ETHERTYPE_IPV4, ETHERTYPE_IPV6, be16, invalid, need};

/// LINKTYPE_* values from <https://www.tcpdump.org/linktypes.html>.
pub mod link_type {
    pub const NULL: u16 = 0;
    pub const ETHERNET: u16 = 1;
    pub const RAW: u16 = 101;
    pub const LOOP: u16 = 108;
    pub const LINUX_SLL: u16 = 113;
    pub const IPV4: u16 = 228;
    pub const IPV6: u16 = 229;
    pub const LINUX_SLL2: u16 = 276;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Link {
    Ethernet {
        src: MacAddr,
        dst: MacAddr,
        /// EtherType after any VLAN tags. 1500 or less means an 802.3 length
        /// field (an LLC frame such as spanning tree), not an EtherType.
        ethertype: u16,
        /// VLAN IDs, outermost first.
        vlans: Vec<u16>,
        /// The type field after the addresses: `ethertype`, or the tag
        /// type (0x8100) of the first VLAN tag.
        outer_type: u16,
    },
    /// Linux "cooked" capture, which is what `tcpdump -i any` writes.
    LinuxCooked,
    /// Loopback captures on BSD, macOS and Windows (Npcap).
    Loopback,
    RawIp,
    /// A link type we don't decode.
    Unsupported(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        )
    }
}

/// Returns the link header, the EtherType of the next layer (`None` when
/// there's nothing we can decode further), and the bytes after the header.
pub(super) fn decode(
    link_type: u16,
    data: &[u8],
) -> Result<(Link, Option<u16>, &[u8]), DecodeError> {
    match link_type {
        link_type::ETHERNET => ethernet(data),
        link_type::LINUX_SLL => {
            need(data, 16, "Linux cooked")?;
            Ok((Link::LinuxCooked, Some(be16(data, 14)), &data[16..]))
        }
        link_type::LINUX_SLL2 => {
            need(data, 20, "Linux cooked")?;
            Ok((Link::LinuxCooked, Some(be16(data, 0)), &data[20..]))
        }
        link_type::NULL | link_type::LOOP => loopback(data),
        link_type::RAW | link_type::IPV4 | link_type::IPV6 => raw_ip(data),
        other => Ok((Link::Unsupported(other), None, &[])),
    }
}

fn ethernet(data: &[u8]) -> Result<(Link, Option<u16>, &[u8]), DecodeError> {
    need(data, 14, "Ethernet")?;
    let dst = MacAddr(data[0..6].try_into().unwrap());
    let src = MacAddr(data[6..12].try_into().unwrap());
    let outer_type = be16(data, 12);
    let mut ethertype = outer_type;
    let mut rest = &data[14..];
    let mut vlans = Vec::new();
    // 802.1Q, 802.1ad (QinQ) and the old pre-standard QinQ tag.
    while matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
        need(rest, 4, "VLAN")?;
        if vlans.len() == 8 {
            return Err(invalid("VLAN", "more than 8 nested tags"));
        }
        vlans.push(be16(rest, 0) & 0x0fff);
        ethertype = be16(rest, 2);
        rest = &rest[4..];
    }
    let next = (ethertype >= 0x0600).then_some(ethertype);
    Ok((
        Link::Ethernet {
            src,
            dst,
            ethertype,
            vlans,
            outer_type,
        },
        next,
        rest,
    ))
}

fn loopback(data: &[u8]) -> Result<(Link, Option<u16>, &[u8]), DecodeError> {
    need(data, 4, "loopback")?;
    let raw = [data[0], data[1], data[2], data[3]];
    // The address family is in the capturing machine's byte order, so take
    // whichever reading gives a small number.
    let le = u32::from_le_bytes(raw);
    let family = if le <= 0xffff {
        le
    } else {
        u32::from_be_bytes(raw)
    };
    let ethertype = match family {
        2 => ETHERTYPE_IPV4,
        // AF_INET6 differs by OS: Linux 10, Windows 23, Net/OpenBSD 24,
        // FreeBSD 28, macOS 30.
        10 | 23 | 24 | 28 | 30 => ETHERTYPE_IPV6,
        f => return Err(invalid("loopback", format!("unknown address family {f}"))),
    };
    Ok((Link::Loopback, Some(ethertype), &data[4..]))
}

fn raw_ip(data: &[u8]) -> Result<(Link, Option<u16>, &[u8]), DecodeError> {
    need(data, 1, "raw IP")?;
    let ethertype = match data[0] >> 4 {
        4 => ETHERTYPE_IPV4,
        6 => ETHERTYPE_IPV6,
        v => return Err(invalid("raw IP", format!("IP version {v}"))),
    };
    Ok((Link::RawIp, Some(ethertype), data))
}
