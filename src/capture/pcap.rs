//! Classic libpcap format: a 24-byte file header, then a 16-byte header before
//! each packet. Spec: <https://www.ietf.org/archive/id/draft-ietf-opsawg-pcap-04.html>

use std::io::Read;

use super::{CaptureError, Endian, Frame, MAX_PACKET_LEN, Timestamp, read_exactly, read_up_to};

#[derive(Debug, Clone, Copy)]
pub(super) struct Variant {
    endian: Endian,
    /// Timestamps in nanoseconds instead of microseconds.
    nanos: bool,
}

impl Variant {
    pub(super) fn from_magic(magic: [u8; 4]) -> Option<Variant> {
        let (endian, nanos) = match magic {
            [0xd4, 0xc3, 0xb2, 0xa1] => (Endian::Little, false),
            [0xa1, 0xb2, 0xc3, 0xd4] => (Endian::Big, false),
            [0x4d, 0x3c, 0xb2, 0xa1] => (Endian::Little, true),
            [0xa1, 0xb2, 0x3c, 0x4d] => (Endian::Big, true),
            _ => return None,
        };
        Some(Variant { endian, nanos })
    }
}

pub(super) struct Reader<R> {
    r: R,
    variant: Variant,
    link_type: u16,
}

impl<R: Read> Reader<R> {
    /// `r` must be positioned just after the 4-byte magic number.
    pub(super) fn new(mut r: R, variant: Variant) -> Result<Self, CaptureError> {
        // Rest of the file header: version (4), thiszone (4), sigfigs (4),
        // snaplen (4), link type (4).
        let mut header = [0u8; 20];
        if read_up_to(&mut r, &mut header)? < header.len() {
            return Err(CaptureError::Corrupt(
                "pcap file header is incomplete".into(),
            ));
        }
        // The upper bits of the link type field carry FCS details we don't use.
        let link_type = (variant.endian.u32(&header[16..20]) & 0xffff) as u16;
        Ok(Reader {
            r,
            variant,
            link_type,
        })
    }

    pub(super) fn next(&mut self) -> Result<Option<Frame>, CaptureError> {
        let mut header = [0u8; 16];
        match read_up_to(&mut self.r, &mut header)? {
            0 => return Ok(None),
            16 => {}
            _ => return Err(CaptureError::Truncated),
        }
        let e = self.variant.endian;
        let secs = u64::from(e.u32(&header[0..4]));
        let frac = u64::from(e.u32(&header[4..8]));
        let captured_len = e.u32(&header[8..12]);
        let orig_len = e.u32(&header[12..16]);
        if captured_len > MAX_PACKET_LEN {
            return Err(CaptureError::Corrupt(format!(
                "packet record claims {captured_len} bytes"
            )));
        }
        let data = read_exactly(&mut self.r, captured_len as usize)?;
        let frac_nanos = if self.variant.nanos {
            frac
        } else {
            frac * 1000
        };
        Ok(Some(Frame {
            number: 0,
            ts: Timestamp(secs * 1_000_000_000 + frac_nanos),
            link_type: self.link_type,
            orig_len: orig_len.max(captured_len),
            data,
        }))
    }
}
