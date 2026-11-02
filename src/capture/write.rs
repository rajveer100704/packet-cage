//! Writes pcapng: one section, one interface, and a packet block per frame,
//! with nanosecond timestamps. Wireshark and every pcapng reader open it.

use std::io::{self, Write};

use super::Frame;

const BLOCK_SECTION_HEADER: u32 = 0x0a0d_0d0a;
const BLOCK_INTERFACE: u32 = 0x0000_0001;
const BLOCK_ENHANCED_PACKET: u32 = 0x0000_0006;
const BYTE_ORDER_MAGIC: u32 = 0x1a2b_3c4d;

const OPT_END: u16 = 0;
const OPT_SHB_USERAPPL: u16 = 4;
const OPT_IF_NAME: u16 = 2;
const OPT_IF_DESCRIPTION: u16 = 3;
const OPT_IF_TSRESOL: u16 = 9;
/// `if_tsresol` of 9: timestamps count nanoseconds.
const NANOSECONDS: u8 = 9;

/// The interface the packets were captured on, for the file's header.
pub struct InterfaceInfo<'a> {
    pub link_type: u16,
    pub snaplen: u32,
    pub name: &'a str,
    pub description: Option<&'a str>,
}

pub struct PcapNgWriter<W: Write> {
    w: W,
}

impl<W: Write> PcapNgWriter<W> {
    /// Writes the section header and the interface description.
    pub fn new(mut w: W, interface: &InterfaceInfo) -> io::Result<Self> {
        let app = format!("packet-cage {}", env!("CARGO_PKG_VERSION"));
        let mut body = Vec::new();
        body.extend(BYTE_ORDER_MAGIC.to_le_bytes());
        body.extend(1u16.to_le_bytes());
        body.extend(0u16.to_le_bytes());
        // Section length: not known in advance.
        body.extend((-1i64).to_le_bytes());
        option(&mut body, OPT_SHB_USERAPPL, app.as_bytes());
        option(&mut body, OPT_END, &[]);
        block(&mut w, BLOCK_SECTION_HEADER, &body)?;

        let mut body = Vec::new();
        body.extend(interface.link_type.to_le_bytes());
        body.extend(0u16.to_le_bytes());
        body.extend(interface.snaplen.to_le_bytes());
        option(&mut body, OPT_IF_NAME, interface.name.as_bytes());
        if let Some(description) = interface.description {
            option(&mut body, OPT_IF_DESCRIPTION, description.as_bytes());
        }
        option(&mut body, OPT_IF_TSRESOL, &[NANOSECONDS]);
        option(&mut body, OPT_END, &[]);
        block(&mut w, BLOCK_INTERFACE, &body)?;
        Ok(PcapNgWriter { w })
    }

    /// Adds a packet. `frame.number` and `frame.link_type` are not stored:
    /// the number is the packet's position, and the interface has the type.
    pub fn write(&mut self, frame: &Frame) -> io::Result<()> {
        let captured = u32::try_from(frame.data.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "packet too large"))?;
        let mut body = Vec::with_capacity(20 + frame.data.len() + 3);
        body.extend(0u32.to_le_bytes());
        body.extend(((frame.ts.0 >> 32) as u32).to_le_bytes());
        body.extend((frame.ts.0 as u32).to_le_bytes());
        body.extend(captured.to_le_bytes());
        body.extend(frame.orig_len.max(captured).to_le_bytes());
        body.extend(&frame.data);
        pad(&mut body);
        block(&mut self.w, BLOCK_ENHANCED_PACKET, &body)
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }

    pub fn into_inner(self) -> W {
        self.w
    }
}

/// Type, total length, body (already padded to 4 bytes), total length again.
fn block(w: &mut impl Write, kind: u32, body: &[u8]) -> io::Result<()> {
    let len = u32::try_from(body.len() + 12)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "block too large"))?;
    w.write_all(&kind.to_le_bytes())?;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(body)?;
    w.write_all(&len.to_le_bytes())
}

/// Code, length, value padded to 4 bytes. Values longer than an option can
/// hold are cut short.
fn option(out: &mut Vec<u8>, code: u16, value: &[u8]) {
    let value = &value[..value.len().min(usize::from(u16::MAX))];
    out.extend(code.to_le_bytes());
    out.extend((value.len() as u16).to_le_bytes());
    out.extend(value);
    pad(out);
}

fn pad(out: &mut Vec<u8>) {
    out.resize(out.len().next_multiple_of(4), 0);
}
