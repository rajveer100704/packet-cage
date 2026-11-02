//! Turns raw frame bytes into protocol headers.
//!
//! Every decoder checks lengths before it reads, so malformed or cut-off
//! packets give a `DecodeError` instead of a panic. Layers decoded before the
//! error are kept: a packet with a broken TCP header still has its IP
//! addresses.
//!
//! Lengths come from the headers, not from the number of captured bytes.
//! That keeps Ethernet padding out of the payload and gives the real segment
//! size for captures that only kept the first bytes of each packet.

mod arp;
pub mod dns;
pub mod http;
mod ip;
mod link;
pub mod tls;
mod transport;
pub mod x509;

use std::fmt;
use std::net::IpAddr;

use crate::capture::Frame;

pub use arp::Arp;
pub use ip::{Ipv4, Ipv6, Ipv6Fragment};
pub use link::{Link, MacAddr, link_type};
pub use transport::{Icmp, Tcp, TcpFlags, TcpOptions, Udp};

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV6: u16 = 0x86dd;

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMPV6: u8 = 58;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet<'a> {
    pub link: Link,
    pub network: Option<Network>,
    pub transport: Option<Transport>,
    /// Captured bytes after the transport header. Shorter than the
    /// transport's `payload_len` when the capture used a snaplen.
    pub payload: &'a [u8],
    /// Why decoding stopped early, if it did.
    pub error: Option<DecodeError>,
    /// Where the layers start in the captured bytes.
    pub offsets: Offsets,
}

/// Byte offsets into the frame, for filters that search a layer's bytes
/// (`tcp contains "GET"`). Only meaningful for the layers that were decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Offsets {
    pub network: usize,
    pub transport: usize,
    /// End of the IP packet; Ethernet padding and trailers come after it.
    pub end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Network {
    Ipv4(Ipv4),
    Ipv6(Ipv6),
    Arp(Arp),
    Other { ethertype: u16 },
}

impl Network {
    /// Source and destination of an IP packet.
    pub fn ip_addrs(&self) -> Option<(IpAddr, IpAddr)> {
        match self {
            Network::Ipv4(h) => Some((h.src.into(), h.dst.into())),
            Network::Ipv6(h) => Some((h.src.into(), h.dst.into())),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    Tcp(Tcp),
    Udp(Udp),
    Icmp(Icmp),
    Other { protocol: u8 },
}

/// The start of the packet an ICMP error is about, which the error quotes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quoted<'a> {
    /// The quoted IP header.
    pub header: Network,
    pub protocol: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    /// Source and destination port, for TCP and UDP.
    pub ports: Option<(u16, u16)>,
    /// Whatever was quoted after the UDP header; empty for other protocols.
    pub udp_payload: &'a [u8],
    /// Everything quoted after the IP header.
    pub transport: &'a [u8],
}

impl<'a> Packet<'a> {
    /// For ICMP errors (destination unreachable, time exceeded and the
    /// like), the packet that caused the error.
    pub fn icmp_quoted(&self) -> Option<Quoted<'a>> {
        let Some(Transport::Icmp(icmp)) = &self.transport else {
            return None;
        };
        let is_error = if icmp.v6 {
            matches!(icmp.icmp_type, 1..=4)
        } else {
            matches!(icmp.icmp_type, 3 | 4 | 5 | 11 | 12)
        };
        if !is_error {
            return None;
        }
        // The rest of the 8-byte ICMP header, then the original IP packet.
        let inner = self.payload.get(4..)?;
        let (header, rest) = match inner.first()? >> 4 {
            4 => {
                let (h, rest, _) = ip::decode_v4(inner, 0).ok()?;
                if h.fragment_offset != 0 {
                    return None;
                }
                (Network::Ipv4(h), rest)
            }
            6 => {
                let (h, rest, _) = ip::decode_v6(inner, 0).ok()?;
                (Network::Ipv6(h), rest)
            }
            _ => return None,
        };
        let (src, dst) = header.ip_addrs()?;
        let protocol = match &header {
            Network::Ipv4(h) => h.protocol,
            Network::Ipv6(h) => h.protocol,
            _ => return None,
        };
        let ports = matches!(protocol, IPPROTO_TCP | IPPROTO_UDP)
            .then(|| (rest.len() >= 4).then(|| (be16(rest, 0), be16(rest, 2))))
            .flatten();
        let udp_payload = match protocol {
            IPPROTO_UDP => rest.get(8..).unwrap_or(&[]),
            _ => &[],
        };
        Some(Quoted {
            header,
            protocol,
            src,
            dst,
            ports,
            udp_payload,
            transport: rest,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError {
    pub layer: &'static str,
    pub problem: Problem,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    /// The packet ends before the header does.
    Truncated {
        need: usize,
        have: usize,
    },
    /// The header was cut off because the capture only kept the first bytes
    /// of each packet. The packet itself was fine on the wire.
    CutShort,
    Invalid(String),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let layer = self.layer;
        match &self.problem {
            Problem::Truncated { need, have } => {
                write!(f, "{layer} header truncated: {have} of {need} bytes")
            }
            Problem::CutShort => write!(f, "{layer} header cut off by capture length limit"),
            Problem::Invalid(msg) => write!(f, "malformed {layer}: {msg}"),
        }
    }
}

impl std::error::Error for DecodeError {}

pub fn decode(frame: &Frame) -> Packet<'_> {
    decode_bytes(frame.link_type, &frame.data, frame.orig_len)
}

/// Decodes `data`, the captured bytes of a packet that was `orig_len` bytes
/// long on the wire.
pub fn decode_bytes(link_type: u16, data: &[u8], orig_len: u32) -> Packet<'_> {
    // Bytes the capture dropped from the end of the packet.
    let missing = (orig_len as usize).saturating_sub(data.len());
    let mut pkt = Packet {
        link: Link::Unsupported(link_type),
        network: None,
        transport: None,
        payload: &[],
        error: None,
        offsets: Offsets::default(),
    };
    if let Err(mut err) = decode_layers(&mut pkt, link_type, data, missing) {
        if missing > 0 && matches!(err.problem, Problem::Truncated { .. }) {
            err.problem = Problem::CutShort;
        }
        pkt.error = Some(err);
    }
    pkt
}

fn decode_layers<'a>(
    pkt: &mut Packet<'a>,
    link_type: u16,
    data: &'a [u8],
    missing: usize,
) -> Result<(), DecodeError> {
    let (link, ethertype, rest) = link::decode(link_type, data)?;
    pkt.link = link;
    let Some(ethertype) = ethertype else {
        return Ok(());
    };
    let offset = |part: &[u8]| part.as_ptr() as usize - data.as_ptr() as usize;
    pkt.offsets.network = offset(rest);

    // Protocol, captured payload and payload length on the wire, unless this
    // is a fragment that doesn't start with the transport header.
    let upper = match ethertype {
        ETHERTYPE_IPV4 => {
            let (header, payload, len) = ip::decode_v4(rest, missing)?;
            pkt.offsets.transport = offset(payload);
            pkt.offsets.end = offset(payload) + payload.len();
            let upper = (header.fragment_offset == 0).then_some((header.protocol, payload, len));
            pkt.network = Some(Network::Ipv4(header));
            upper
        }
        ETHERTYPE_IPV6 => {
            let (header, payload, len) = ip::decode_v6(rest, missing)?;
            pkt.offsets.transport = offset(payload);
            pkt.offsets.end = offset(payload) + payload.len();
            let first = header.fragment.is_none_or(|f| f.offset == 0);
            let upper = first.then_some((header.protocol, payload, len));
            pkt.network = Some(Network::Ipv6(header));
            upper
        }
        ETHERTYPE_ARP => {
            pkt.network = Some(Network::Arp(arp::decode(rest)?));
            None
        }
        _ => {
            pkt.network = Some(Network::Other { ethertype });
            None
        }
    };
    let Some((protocol, payload, len)) = upper else {
        return Ok(());
    };
    let (transport, app) = transport::decode(protocol, payload, len)?;
    pkt.transport = Some(transport);
    pkt.payload = app;
    Ok(())
}

fn need(data: &[u8], len: usize, layer: &'static str) -> Result<(), DecodeError> {
    if data.len() < len {
        return Err(DecodeError {
            layer,
            problem: Problem::Truncated {
                need: len,
                have: data.len(),
            },
        });
    }
    Ok(())
}

fn invalid(layer: &'static str, msg: impl Into<String>) -> DecodeError {
    DecodeError {
        layer,
        problem: Problem::Invalid(msg.into()),
    }
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
