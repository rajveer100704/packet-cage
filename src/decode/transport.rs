//! TCP (RFC 9293), UDP (RFC 768), ICMP (RFC 792) and ICMPv6 (RFC 4443).

use std::fmt;

use super::{
    DecodeError, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP, Transport, be16, be32,
    invalid, need,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tcp {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
    /// Raw window field; multiply by 2^window_scale from the handshake.
    pub window: u16,
    pub header_len: u8,
    pub options: TcpOptions,
    /// Bytes of data in this segment, from the IP length. Larger than the
    /// captured payload when the capture used a snaplen.
    pub payload_len: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlags(pub u16);

impl TcpFlags {
    pub const FIN: u16 = 0x001;
    pub const SYN: u16 = 0x002;
    pub const RST: u16 = 0x004;
    pub const PSH: u16 = 0x008;
    pub const ACK: u16 = 0x010;
    pub const URG: u16 = 0x020;
    pub const ECE: u16 = 0x040;
    pub const CWR: u16 = 0x080;
    /// Accurate ECN (RFC 9768); was the NS flag.
    pub const AE: u16 = 0x100;

    pub fn has(self, flag: u16) -> bool {
        self.0 & flag != 0
    }
}

impl fmt::Display for TcpFlags {
    /// Same order and names as Wireshark, e.g. "SYN, ACK".
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = [
            (TcpFlags::FIN, "FIN"),
            (TcpFlags::SYN, "SYN"),
            (TcpFlags::RST, "RST"),
            (TcpFlags::PSH, "PSH"),
            (TcpFlags::ACK, "ACK"),
            (TcpFlags::URG, "URG"),
            (TcpFlags::ECE, "ECE"),
            (TcpFlags::CWR, "CWR"),
            (TcpFlags::AE, "AE"),
        ];
        let mut sep = "";
        for (bit, name) in names {
            if self.has(bit) {
                write!(f, "{sep}{name}")?;
                sep = ", ";
            }
        }
        if sep.is_empty() {
            f.write_str("<none>")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TcpOptions {
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub sack_permitted: bool,
    /// Selectively acknowledged ranges (left edge, right edge).
    pub sack: Vec<(u32, u32)>,
    /// (TSval, TSecr)
    pub timestamps: Option<(u32, u32)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Udp {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub payload_len: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Icmp {
    pub v6: bool,
    pub icmp_type: u8,
    pub code: u8,
}

/// Decodes the transport header of an IP payload that is `len` bytes long on
/// the wire, of which `data` was captured.
pub(super) fn decode(
    protocol: u8,
    data: &[u8],
    len: usize,
) -> Result<(Transport, &[u8]), DecodeError> {
    match protocol {
        IPPROTO_TCP => tcp(data, len).map(|(h, rest)| (Transport::Tcp(h), rest)),
        IPPROTO_UDP => udp(data, len).map(|(h, rest)| (Transport::Udp(h), rest)),
        IPPROTO_ICMP | IPPROTO_ICMPV6 => {
            let v6 = protocol == IPPROTO_ICMPV6;
            need(data, 4, if v6 { "ICMPv6" } else { "ICMP" })?;
            let icmp = Icmp {
                v6,
                icmp_type: data[0],
                code: data[1],
            };
            Ok((Transport::Icmp(icmp), &data[4..]))
        }
        _ => Ok((Transport::Other { protocol }, data)),
    }
}

fn tcp(data: &[u8], segment_len: usize) -> Result<(Tcp, &[u8]), DecodeError> {
    const LAYER: &str = "TCP";
    need(data, 20, LAYER)?;
    let header_len = usize::from(data[12] >> 4) * 4;
    if header_len < 20 {
        return Err(invalid(
            LAYER,
            format!("header length {header_len} is below the minimum of 20"),
        ));
    }
    need(data, header_len, LAYER)?;
    let tcp = Tcp {
        src_port: be16(data, 0),
        dst_port: be16(data, 2),
        seq: be32(data, 4),
        ack: be32(data, 8),
        flags: TcpFlags(be16(data, 12) & 0x01ff),
        window: be16(data, 14),
        header_len: header_len as u8,
        options: tcp_options(&data[20..header_len]),
        payload_len: segment_len.saturating_sub(header_len) as u32,
    };
    Ok((tcp, &data[header_len..]))
}

fn tcp_options(mut opts: &[u8]) -> TcpOptions {
    let mut out = TcpOptions::default();
    while let Some(&kind) = opts.first() {
        match kind {
            0 => break,
            1 => {
                opts = &opts[1..];
                continue;
            }
            _ => {}
        }
        // Everything else is kind, length, value. A bad length means the
        // rest can't be trusted, so stop there.
        let Some(&len) = opts.get(1) else { break };
        let len = usize::from(len);
        if len < 2 || len > opts.len() {
            break;
        }
        let value = &opts[2..len];
        match (kind, value.len()) {
            (2, 2) => out.mss = Some(be16(value, 0)),
            (3, 1) => out.window_scale = Some(value[0]),
            (4, 0) => out.sack_permitted = true,
            (5, _) => {
                let (blocks, _) = value.as_chunks::<8>();
                out.sack = blocks.iter().map(|b| (be32(b, 0), be32(b, 4))).collect();
            }
            (8, 8) => out.timestamps = Some((be32(value, 0), be32(value, 4))),
            _ => {}
        }
        opts = &opts[len..];
    }
    out
}

fn udp(data: &[u8], datagram_len: usize) -> Result<(Udp, &[u8]), DecodeError> {
    const LAYER: &str = "UDP";
    need(data, 8, LAYER)?;
    let length = be16(data, 4);
    let end = match usize::from(length) {
        // 0 is used by IPv6 jumbograms; the IP length is all we have then.
        0 => datagram_len,
        n if n < 8 => {
            return Err(invalid(
                LAYER,
                format!("length field {n} is below the header size of 8"),
            ));
        }
        n => n.min(datagram_len),
    };
    let udp = Udp {
        src_port: be16(data, 0),
        dst_port: be16(data, 2),
        length,
        payload_len: end.saturating_sub(8) as u32,
    };
    Ok((udp, &data[8..end.clamp(8, data.len())]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_display_like_wireshark() {
        assert_eq!(
            TcpFlags(TcpFlags::SYN | TcpFlags::ACK).to_string(),
            "SYN, ACK"
        );
        assert_eq!(
            TcpFlags(TcpFlags::FIN | TcpFlags::PSH | TcpFlags::ACK).to_string(),
            "FIN, PSH, ACK"
        );
        assert_eq!(TcpFlags(0).to_string(), "<none>");
    }

    #[test]
    fn options_parse_and_stop_at_bad_length() {
        // MSS 1460, NOP, NOP, SACK block 100-200, then an option with length 0.
        let opts = [
            2, 4, 0x05, 0xb4, 1, 1, 5, 10, 0, 0, 0, 100, 0, 0, 0, 200, 3, 0, 9,
        ];
        let parsed = tcp_options(&opts);
        assert_eq!(parsed.mss, Some(1460));
        assert_eq!(parsed.sack, vec![(100, 200)]);
        assert_eq!(parsed.window_scale, None);
    }

    #[test]
    fn option_running_past_the_header_is_ignored() {
        let parsed = tcp_options(&[2, 4, 0x05]);
        assert_eq!(parsed, TcpOptions::default());
    }
}
