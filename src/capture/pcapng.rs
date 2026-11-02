//! pcapng: a sequence of typed blocks. A section header sets the byte order,
//! interface blocks describe each capture interface (link type, timestamp
//! resolution), and packet blocks point at an interface.
//! Spec: <https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-03.html>

use std::io::{self, Read};

use super::{CaptureError, Endian, Frame, MAX_PACKET_LEN, Timestamp, read_exactly, read_up_to};

/// The section header block type. It reads the same in both byte orders,
/// which is why it can come before the byte-order magic.
pub(super) const SECTION_HEADER_MAGIC: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];

const BLOCK_SECTION_HEADER: u32 = 0x0a0d_0d0a;
const BLOCK_INTERFACE: u32 = 0x0000_0001;
const BLOCK_OBSOLETE_PACKET: u32 = 0x0000_0002;
const BLOCK_SIMPLE_PACKET: u32 = 0x0000_0003;
const BLOCK_ENHANCED_PACKET: u32 = 0x0000_0006;

const BYTE_ORDER_MAGIC: u32 = 0x1a2b_3c4d;
const MAX_BLOCK_LEN: u32 = MAX_PACKET_LEN + 64 * 1024;

const OPT_END: u16 = 0;
const OPT_IF_TSRESOL: u16 = 9;
const OPT_IF_TSOFFSET: u16 = 14;

struct Interface {
    link_type: u16,
    snaplen: u32,
    /// `if_tsresol`: high bit clear means units of 10^-n seconds, set means 2^-n.
    tsresol: u8,
    /// `if_tsoffset`: seconds to add to every timestamp.
    tsoffset: i64,
}

impl Interface {
    fn timestamp(&self, units: u64) -> Timestamp {
        let units = u128::from(units);
        let n = u32::from(self.tsresol & 0x7f);
        let nanos = if self.tsresol & 0x80 == 0 {
            if n <= 9 {
                units * 10u128.pow(9 - n)
            } else {
                10u128.checked_pow(n - 9).map_or(0, |d| units / d)
            }
        } else {
            (units * 1_000_000_000) >> n
        };
        let nanos = nanos as i128 + i128::from(self.tsoffset) * 1_000_000_000;
        Timestamp(nanos.clamp(0, i128::from(u64::MAX)) as u64)
    }
}

pub(super) struct Reader<R> {
    r: R,
    endian: Endian,
    interfaces: Vec<Interface>,
    /// Simple packet blocks have no timestamp; they reuse the previous one.
    last_ts: Timestamp,
}

impl<R: Read> Reader<R> {
    /// `r` must be positioned just after the first block type.
    pub(super) fn new(r: R) -> Result<Self, CaptureError> {
        let mut reader = Reader {
            r,
            endian: Endian::Little,
            interfaces: Vec::new(),
            last_ts: Timestamp::default(),
        };
        reader.read_section_header()?;
        Ok(reader)
    }

    pub(super) fn next(&mut self) -> Result<Option<Frame>, CaptureError> {
        loop {
            let mut block_type = [0u8; 4];
            match read_up_to(&mut self.r, &mut block_type)? {
                0 => return Ok(None),
                4 => {}
                _ => return Err(CaptureError::Truncated),
            }
            let block_type = self.endian.u32(&block_type);
            if block_type == BLOCK_SECTION_HEADER {
                self.read_section_header()?;
                continue;
            }
            let mut len = [0u8; 4];
            if read_up_to(&mut self.r, &mut len)? < len.len() {
                return Err(CaptureError::Truncated);
            }
            let total_len = self.endian.u32(&len);
            if !(12..=MAX_BLOCK_LEN).contains(&total_len) {
                return Err(CaptureError::Corrupt(format!(
                    "block of type {block_type:#x} has invalid length {total_len}"
                )));
            }
            // Body, then a trailing copy of the length that we drop.
            let mut body = read_exactly(&mut self.r, total_len as usize - 8)?;
            body.truncate(body.len() - 4);
            match block_type {
                BLOCK_INTERFACE => self.read_interface(&body)?,
                BLOCK_ENHANCED_PACKET => {
                    let iface = self.endian.u32(&prefix(&body, 4, "enhanced packet")?[0..4]);
                    return self.timestamped_packet(body, iface).map(Some);
                }
                BLOCK_OBSOLETE_PACKET => {
                    let iface = self.endian.u16(&prefix(&body, 2, "packet")?[0..2]);
                    return self.timestamped_packet(body, u32::from(iface)).map(Some);
                }
                BLOCK_SIMPLE_PACKET => return self.simple_packet(body).map(Some),
                // Statistics, name resolution, decryption secrets, custom blocks.
                _ => {}
            }
        }
    }

    /// Reads a section header; the block type has already been consumed.
    fn read_section_header(&mut self) -> Result<(), CaptureError> {
        // Block length, then the byte-order magic that says how to read it.
        let mut head = [0u8; 8];
        if read_up_to(&mut self.r, &mut head)? < head.len() {
            return Err(CaptureError::Truncated);
        }
        self.endian = if Endian::Little.u32(&head[4..8]) == BYTE_ORDER_MAGIC {
            Endian::Little
        } else if Endian::Big.u32(&head[4..8]) == BYTE_ORDER_MAGIC {
            Endian::Big
        } else {
            return Err(CaptureError::Corrupt(
                "section header has an invalid byte-order magic".into(),
            ));
        };
        let total_len = self.endian.u32(&head[0..4]);
        if !(28..=MAX_BLOCK_LEN).contains(&total_len) {
            return Err(CaptureError::Corrupt(format!(
                "section header has invalid length {total_len}"
            )));
        }
        // Skip version, section length and options; nothing there affects decoding.
        let rest = u64::from(total_len) - 12;
        if io::copy(&mut self.r.by_ref().take(rest), &mut io::sink())? < rest {
            return Err(CaptureError::Truncated);
        }
        // Interface IDs are numbered per section.
        self.interfaces.clear();
        Ok(())
    }

    fn read_interface(&mut self, body: &[u8]) -> Result<(), CaptureError> {
        let body = prefix(body, 8, "interface description")?;
        let e = self.endian;
        let mut iface = Interface {
            link_type: e.u16(&body[0..2]),
            snaplen: e.u32(&body[4..8]),
            tsresol: 6,
            tsoffset: 0,
        };
        for (code, value) in options(e, &body[8..]) {
            match code {
                OPT_IF_TSRESOL if !value.is_empty() => iface.tsresol = value[0],
                OPT_IF_TSOFFSET if value.len() >= 8 => iface.tsoffset = e.i64(value),
                _ => {}
            }
        }
        self.interfaces.push(iface);
        Ok(())
    }

    /// Enhanced and obsolete packet blocks share this layout after the
    /// interface ID: timestamp (high, low), captured length, original length,
    /// then the packet data.
    fn timestamped_packet(
        &mut self,
        mut body: Vec<u8>,
        iface_id: u32,
    ) -> Result<Frame, CaptureError> {
        prefix(&body, 20, "packet")?;
        let e = self.endian;
        let ts_units = (u64::from(e.u32(&body[4..8])) << 32) | u64::from(e.u32(&body[8..12]));
        let captured_len = e.u32(&body[12..16]) as usize;
        let orig_len = e.u32(&body[16..20]);
        if 20 + captured_len > body.len() {
            return Err(CaptureError::Corrupt(format!(
                "packet claims {captured_len} bytes but its block holds {}",
                body.len() - 20
            )));
        }
        let iface = self.interface(iface_id)?;
        let (ts, link_type) = (iface.timestamp(ts_units), iface.link_type);
        body.truncate(20 + captured_len);
        body.drain(..20);
        self.last_ts = ts;
        Ok(Frame {
            number: 0,
            ts,
            link_type,
            orig_len: orig_len.max(captured_len as u32),
            data: body,
        })
    }

    fn simple_packet(&mut self, mut body: Vec<u8>) -> Result<Frame, CaptureError> {
        prefix(&body, 4, "simple packet")?;
        let orig_len = self.endian.u32(&body[0..4]);
        let iface = self.interface(0)?;
        // The block is padded, so the real captured length is the original
        // length, limited by the snaplen and by what the block holds.
        let mut captured_len = (orig_len as usize).min(body.len() - 4);
        if iface.snaplen > 0 {
            captured_len = captured_len.min(iface.snaplen as usize);
        }
        let link_type = iface.link_type;
        body.truncate(4 + captured_len);
        body.drain(..4);
        Ok(Frame {
            number: 0,
            ts: self.last_ts,
            link_type,
            orig_len: orig_len.max(captured_len as u32),
            data: body,
        })
    }

    fn interface(&self, id: u32) -> Result<&Interface, CaptureError> {
        self.interfaces.get(id as usize).ok_or_else(|| {
            CaptureError::Corrupt(format!(
                "packet refers to interface {id}, but the section defines {}",
                self.interfaces.len()
            ))
        })
    }
}

/// Checks that a block body holds at least `len` bytes.
fn prefix<'a>(body: &'a [u8], len: usize, block: &str) -> Result<&'a [u8], CaptureError> {
    if body.len() < len {
        return Err(CaptureError::Corrupt(format!("{block} block is too short")));
    }
    Ok(body)
}

/// Iterates over (code, value) options, each padded to 4 bytes.
fn options(e: Endian, mut data: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    std::iter::from_fn(move || {
        if data.len() < 4 {
            return None;
        }
        let code = e.u16(&data[0..2]);
        let len = usize::from(e.u16(&data[2..4]));
        if code == OPT_END || data.len() < 4 + len {
            return None;
        }
        let value = &data[4..4 + len];
        let padded = (4 + len + 3) & !3;
        data = &data[padded.min(data.len())..];
        Some((code, value))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(tsresol: u8, tsoffset: i64) -> Interface {
        Interface {
            link_type: 1,
            snaplen: 0,
            tsresol,
            tsoffset,
        }
    }

    #[test]
    fn timestamp_resolutions() {
        // Default: microseconds.
        assert_eq!(iface(6, 0).timestamp(1_500_000), Timestamp(1_500_000_000));
        assert_eq!(iface(9, 0).timestamp(42), Timestamp(42));
        // Picoseconds round down to nanoseconds.
        assert_eq!(iface(12, 0).timestamp(5_000_999), Timestamp(5_000));
        // 2^-10 seconds per unit: 1024 units is one second.
        assert_eq!(
            iface(0x80 | 10, 0).timestamp(1024),
            Timestamp(1_000_000_000)
        );
        assert_eq!(iface(6, 100).timestamp(0), Timestamp(100_000_000_000));
    }

    #[test]
    fn extreme_resolutions_do_not_overflow() {
        assert_eq!(iface(0x7f, 0).timestamp(u64::MAX), Timestamp(0));
        assert_eq!(iface(0xff, 0).timestamp(u64::MAX), Timestamp(0));
        assert_eq!(iface(0, 0).timestamp(u64::MAX), Timestamp(u64::MAX));
        assert_eq!(iface(6, i64::MIN).timestamp(1), Timestamp(0));
    }
}
