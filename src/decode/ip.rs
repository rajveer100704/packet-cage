//! IPv4 (RFC 791) and IPv6 (RFC 8200).

use std::net::{Ipv4Addr, Ipv6Addr};

use super::{DecodeError, be16, be32, invalid, need};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4 {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: u8,
    pub ttl: u8,
    pub id: u16,
    pub header_len: u8,
    /// As written in the header; 0 on captures taken on a host whose NIC
    /// does TCP segmentation offload.
    pub total_len: u16,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    /// Where this fragment's data goes in the original datagram, in bytes.
    pub fragment_offset: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6 {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub hop_limit: u8,
    /// Next header field of the fixed header: the first extension header,
    /// or the same as `protocol` when there are none.
    pub next_header: u8,
    /// Protocol after any extension headers (6 TCP, 17 UDP, 58 ICMPv6).
    pub protocol: u8,
    pub payload_len: u16,
    pub fragment: Option<Ipv6Fragment>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Fragment {
    pub offset: u16,
    pub more: bool,
    pub id: u32,
}

/// Returns the header, the captured payload, and the payload length on the wire.
pub(super) fn decode_v4(data: &[u8], missing: usize) -> Result<(Ipv4, &[u8], usize), DecodeError> {
    const LAYER: &str = "IPv4";
    need(data, 20, LAYER)?;
    let version = data[0] >> 4;
    if version != 4 {
        return Err(invalid(LAYER, format!("version field is {version}")));
    }
    let header_len = usize::from(data[0] & 0x0f) * 4;
    if header_len < 20 {
        return Err(invalid(
            LAYER,
            format!("header length {header_len} is below the minimum of 20"),
        ));
    }
    need(data, header_len, LAYER)?;
    let total_len = usize::from(be16(data, 2));
    // Bytes from the start of this header to the end of the frame on the wire.
    let on_wire = data.len() + missing;
    let end = match total_len {
        // With segmentation offload the NIC fills in the length after the
        // capture point, so the frame length is all we have.
        0 => on_wire,
        n if n < header_len => {
            return Err(invalid(
                LAYER,
                format!("total length {n} is shorter than the header ({header_len})"),
            ));
        }
        n => n.min(on_wire),
    };
    let flags = be16(data, 6);
    let header = Ipv4 {
        src: Ipv4Addr::new(data[12], data[13], data[14], data[15]),
        dst: Ipv4Addr::new(data[16], data[17], data[18], data[19]),
        protocol: data[9],
        ttl: data[8],
        id: be16(data, 4),
        header_len: header_len as u8,
        total_len: total_len as u16,
        dont_fragment: flags & 0x4000 != 0,
        more_fragments: flags & 0x2000 != 0,
        fragment_offset: (flags & 0x1fff) * 8,
    };
    // Stopping at `end` leaves out Ethernet padding and trailers.
    let payload = &data[header_len..end.min(data.len())];
    Ok((header, payload, end - header_len))
}

const HOP_BY_HOP: u8 = 0;
const ROUTING: u8 = 43;
const FRAGMENT: u8 = 44;
const AUTH: u8 = 51;
const DEST_OPTIONS: u8 = 60;
const MOBILITY: u8 = 135;
const HIP: u8 = 139;
const SHIM6: u8 = 140;

const MAX_EXTENSION_HEADERS: usize = 16;

/// Returns the header, the captured payload after any extension headers, and
/// that payload's length on the wire.
pub(super) fn decode_v6(data: &[u8], missing: usize) -> Result<(Ipv6, &[u8], usize), DecodeError> {
    const LAYER: &str = "IPv6";
    const EXT: &str = "IPv6 extension";
    need(data, 40, LAYER)?;
    let version = data[0] >> 4;
    if version != 6 {
        return Err(invalid(LAYER, format!("version field is {version}")));
    }
    let payload_len = be16(data, 4);
    let on_wire = data.len() - 40 + missing;
    // 0 means a jumbogram, or segmentation offload; use the frame length.
    let mut len = match usize::from(payload_len) {
        0 => on_wire,
        n => n.min(on_wire),
    };
    let mut rest = &data[40..data.len().min(40 + len)];
    let mut next = data[6];
    let mut fragment = None;
    let mut seen = 0;
    loop {
        let ext_len = match next {
            HOP_BY_HOP | ROUTING | DEST_OPTIONS | MOBILITY | HIP | SHIM6 => {
                need(rest, 2, EXT)?;
                (usize::from(rest[1]) + 1) * 8
            }
            FRAGMENT => 8,
            AUTH => {
                need(rest, 2, EXT)?;
                (usize::from(rest[1]) + 2) * 4
            }
            _ => break,
        };
        seen += 1;
        if seen > MAX_EXTENSION_HEADERS {
            return Err(invalid(
                EXT,
                format!("more than {MAX_EXTENSION_HEADERS} headers"),
            ));
        }
        need(rest, ext_len, EXT)?;
        if next == FRAGMENT {
            let field = be16(rest, 2);
            fragment = Some(Ipv6Fragment {
                offset: field & 0xfff8,
                more: field & 1 != 0,
                id: be32(rest, 4),
            });
        }
        next = rest[0];
        rest = &rest[ext_len..];
        len -= ext_len;
    }
    let header = Ipv6 {
        src: addr(&data[8..24]),
        dst: addr(&data[24..40]),
        hop_limit: data[7],
        next_header: data[6],
        protocol: next,
        payload_len,
        fragment,
    };
    Ok((header, rest, len))
}

fn addr(b: &[u8]) -> Ipv6Addr {
    let octets: [u8; 16] = b.try_into().unwrap();
    Ipv6Addr::from(octets)
}
