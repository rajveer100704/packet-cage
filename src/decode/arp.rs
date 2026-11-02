//! ARP (RFC 826).

use std::net::Ipv4Addr;

use super::{DecodeError, MacAddr, be16, need};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arp {
    /// 1 request, 2 reply.
    pub operation: u16,
    /// Addresses are only filled in for Ethernet + IPv4, the only pairing
    /// seen in practice.
    pub sender_mac: Option<MacAddr>,
    pub sender_ip: Option<Ipv4Addr>,
    pub target_ip: Option<Ipv4Addr>,
}

pub(super) fn decode(data: &[u8]) -> Result<Arp, DecodeError> {
    need(data, 8, "ARP")?;
    let hw_len = usize::from(data[4]);
    let proto_len = usize::from(data[5]);
    need(data, 8 + 2 * (hw_len + proto_len), "ARP")?;
    let mut arp = Arp {
        operation: be16(data, 6),
        sender_mac: None,
        sender_ip: None,
        target_ip: None,
    };
    if hw_len == 6 && proto_len == 4 {
        arp.sender_mac = Some(MacAddr(data[8..14].try_into().unwrap()));
        arp.sender_ip = Some(Ipv4Addr::new(data[14], data[15], data[16], data[17]));
        arp.target_ip = Some(Ipv4Addr::new(data[24], data[25], data[26], data[27]));
    }
    Ok(arp)
}
