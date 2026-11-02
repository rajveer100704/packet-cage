//! Builds packets and capture files in memory, so each test spells out the
//! exact bytes it needs.
#![allow(dead_code)]

use std::net::Ipv6Addr;

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;

pub const LINKTYPE_ETHERNET: u16 = 1;

/// A little-endian pcap file with microsecond timestamps.
pub struct Pcap {
    buf: Vec<u8>,
}

impl Pcap {
    pub fn new(link_type: u16) -> Self {
        let mut buf = Vec::new();
        buf.extend(0xa1b2_c3d4u32.to_le_bytes());
        buf.extend(2u16.to_le_bytes());
        buf.extend(4u16.to_le_bytes());
        buf.extend(0i32.to_le_bytes()); // thiszone
        buf.extend(0u32.to_le_bytes()); // sigfigs
        buf.extend(65535u32.to_le_bytes()); // snaplen
        buf.extend(u32::from(link_type).to_le_bytes());
        Pcap { buf }
    }

    pub fn packet(&mut self, ts_micros: u64, data: &[u8]) -> &mut Self {
        self.snapped(ts_micros, data, data.len())
    }

    /// Stores only the first `keep` bytes, like a capture with a snaplen.
    pub fn snapped(&mut self, ts_micros: u64, data: &[u8], keep: usize) -> &mut Self {
        let keep = keep.min(data.len());
        self.buf
            .extend(((ts_micros / 1_000_000) as u32).to_le_bytes());
        self.buf
            .extend(((ts_micros % 1_000_000) as u32).to_le_bytes());
        self.buf.extend((keep as u32).to_le_bytes());
        self.buf.extend((data.len() as u32).to_le_bytes());
        self.buf.extend(&data[..keep]);
        self
    }

    pub fn bytes(&self) -> Vec<u8> {
        self.buf.clone()
    }
}

/// A pcapng file, written in either byte order.
pub struct PcapNg {
    buf: Vec<u8>,
    big_endian: bool,
}

impl PcapNg {
    pub fn new(big_endian: bool) -> Self {
        let mut w = PcapNg {
            buf: Vec::new(),
            big_endian,
        };
        w.section();
        w
    }

    fn u16(&self, v: u16) -> [u8; 2] {
        if self.big_endian {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    }

    fn u32(&self, v: u32) -> [u8; 4] {
        if self.big_endian {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    }

    pub fn block(&mut self, block_type: u32, body: &[u8]) -> &mut Self {
        let padded = (body.len() + 3) & !3;
        let total = self.u32((12 + padded) as u32);
        let block_type = self.u32(block_type);
        self.buf.extend(block_type);
        self.buf.extend(total);
        self.buf.extend(body);
        self.buf.resize(self.buf.len() + padded - body.len(), 0);
        self.buf.extend(total);
        self
    }

    pub fn section(&mut self) -> &mut Self {
        let mut body = Vec::new();
        body.extend(self.u32(0x1a2b_3c4d));
        body.extend(self.u16(1));
        body.extend(self.u16(0));
        body.extend((-1i64).to_le_bytes()); // section length unknown
        self.block(0x0a0d_0d0a, &body)
    }

    /// `tsresol` is the raw if_tsresol option value (6 = µs, 9 = ns).
    pub fn interface(&mut self, link_type: u16, tsresol: Option<u8>) -> &mut Self {
        let mut body = Vec::new();
        body.extend(self.u16(link_type));
        body.extend(self.u16(0));
        body.extend(self.u32(0)); // no snaplen
        if let Some(res) = tsresol {
            body.extend(self.u16(9));
            body.extend(self.u16(1));
            body.extend([res, 0, 0, 0]);
            body.extend(self.u16(0)); // end of options
            body.extend(self.u16(0));
        }
        self.block(1, &body)
    }

    /// Enhanced packet block; `ts` is in the interface's units.
    pub fn packet(&mut self, iface: u32, ts: u64, data: &[u8]) -> &mut Self {
        let mut body = Vec::new();
        body.extend(self.u32(iface));
        body.extend(self.u32((ts >> 32) as u32));
        body.extend(self.u32(ts as u32));
        body.extend(self.u32(data.len() as u32));
        body.extend(self.u32(data.len() as u32));
        body.extend(data);
        self.block(6, &body)
    }

    pub fn simple_packet(&mut self, data: &[u8]) -> &mut Self {
        let mut body = Vec::new();
        body.extend(self.u32(data.len() as u32));
        body.extend(data);
        self.block(3, &body)
    }

    pub fn bytes(&self) -> Vec<u8> {
        self.buf.clone()
    }
}

pub fn ethernet(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0x02, 0, 0, 0, 0, 0x02, 0x02, 0, 0, 0, 0, 0x01];
    f.extend(ethertype.to_be_bytes());
    f.extend(payload);
    f
}

/// An 802.1Q tag followed by the inner EtherType; use as the payload of
/// `ethernet(0x8100, ..)`.
pub fn vlan(id: u16, ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = id.to_be_bytes().to_vec();
    f.extend(ethertype.to_be_bytes());
    f.extend(payload);
    f
}

pub fn ipv4(src: [u8; 4], dst: [u8; 4], protocol: u8, payload: &[u8]) -> Vec<u8> {
    let total = (20 + payload.len()) as u16;
    let mut p = vec![0x45, 0];
    p.extend(total.to_be_bytes());
    p.extend([0, 1, 0x40, 0, 64, protocol, 0, 0]);
    p.extend(src);
    p.extend(dst);
    p.extend(payload);
    p
}

pub fn ipv6(src: &str, dst: &str, next_header: u8, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0x60, 0, 0, 0];
    p.extend((payload.len() as u16).to_be_bytes());
    p.extend([next_header, 64]);
    p.extend(src.parse::<Ipv6Addr>().unwrap().octets());
    p.extend(dst.parse::<Ipv6Addr>().unwrap().octets());
    p.extend(payload);
    p
}

pub fn tcp(src_port: u16, dst_port: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    tcp_with_options(src_port, dst_port, seq, ack, flags, &[], payload)
}

pub fn tcp_with_options(
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    assert_eq!(options.len() % 4, 0, "pad TCP options to 4 bytes");
    let header_len = 20 + options.len();
    let mut s = Vec::new();
    s.extend(src_port.to_be_bytes());
    s.extend(dst_port.to_be_bytes());
    s.extend(seq.to_be_bytes());
    s.extend(ack.to_be_bytes());
    s.extend([((header_len / 4) as u8) << 4, flags]);
    s.extend(64240u16.to_be_bytes());
    s.extend([0, 0, 0, 0]); // checksum, urgent pointer
    s.extend(options);
    s.extend(payload);
    s
}

pub fn udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend(src_port.to_be_bytes());
    d.extend(dst_port.to_be_bytes());
    d.extend(((8 + payload.len()) as u16).to_be_bytes());
    d.extend([0, 0]);
    d.extend(payload);
    d
}

/// Small deterministic PRNG (xorshift64*) so the no-panic tests are repeatable.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}
