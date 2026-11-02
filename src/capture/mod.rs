//! Reads capture files (pcap and pcapng) without libpcap, and writes pcapng.

mod pcap;
mod pcapng;
mod write;

use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

pub use write::{InterfaceInfo, PcapNgWriter};

/// Largest packet we accept. Real link layers stay far below this, so a
/// bigger value means the file is corrupt.
const MAX_PACKET_LEN: u32 = 16 * 1024 * 1024;

/// One captured packet, as stored in the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// 1-based position in the file; the same as Wireshark's `frame.number`.
    pub number: u64,
    pub ts: Timestamp,
    /// LINKTYPE_* value that says how to decode `data`.
    pub link_type: u16,
    /// Length of the packet on the wire. Larger than `data.len()` when the
    /// capture only kept the start of each packet (a snaplen).
    pub orig_len: u32,
    pub data: Vec<u8>,
}

/// Nanoseconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Timestamp(pub u64);

impl Timestamp {
    /// Seconds from `earlier` to `self`; negative if packets are out of order.
    pub fn secs_since(self, earlier: Timestamp) -> f64 {
        (i128::from(self.0) - i128::from(earlier.0)) as f64 / 1e9
    }
}

#[derive(Debug)]
pub enum CaptureError {
    Io(io::Error),
    Empty,
    /// The first bytes match neither pcap nor pcapng.
    UnknownFormat([u8; 4]),
    Compressed(&'static str),
    /// The file ends partway through a packet, usually because the capture
    /// was cut off. Packets before this point are fine.
    Truncated,
    Corrupt(String),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CaptureError::Io(e) => write!(f, "read error: {e}"),
            CaptureError::Empty => write!(f, "file is empty"),
            CaptureError::UnknownFormat(m) => write!(
                f,
                "not a pcap or pcapng file (starts with {:02x} {:02x} {:02x} {:02x})",
                m[0], m[1], m[2], m[3]
            ),
            CaptureError::Compressed(kind) => {
                write!(f, "file is {kind}-compressed; decompress it first")
            }
            CaptureError::Truncated => write!(f, "file ends in the middle of a packet"),
            CaptureError::Corrupt(msg) => write!(f, "corrupt capture: {msg}"),
        }
    }
}

impl std::error::Error for CaptureError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CaptureError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for CaptureError {
    fn from(e: io::Error) -> Self {
        CaptureError::Io(e)
    }
}

/// A capture file being read packet by packet.
pub struct Capture<R> {
    format: Format<R>,
    frames_read: u64,
}

enum Format<R> {
    Pcap(pcap::Reader<R>),
    PcapNg(pcapng::Reader<R>),
}

impl Capture<BufReader<File>> {
    pub fn open(path: &Path) -> Result<Self, CaptureError> {
        Self::from_reader(BufReader::with_capacity(1 << 16, File::open(path)?))
    }
}

impl<R: Read> Capture<R> {
    /// Detects the format from the first bytes and reads the file header.
    pub fn from_reader(mut r: R) -> Result<Self, CaptureError> {
        let mut magic = [0u8; 4];
        match read_up_to(&mut r, &mut magic)? {
            0 => return Err(CaptureError::Empty),
            4 => {}
            _ => {
                return Err(CaptureError::Corrupt(
                    "file is too short to be a capture".into(),
                ));
            }
        }
        let format = match magic {
            pcapng::SECTION_HEADER_MAGIC => Format::PcapNg(pcapng::Reader::new(r)?),
            [0x1f, 0x8b, ..] => return Err(CaptureError::Compressed("gzip")),
            [0x28, 0xb5, 0x2f, 0xfd] => return Err(CaptureError::Compressed("zstd")),
            _ => match pcap::Variant::from_magic(magic) {
                Some(variant) => Format::Pcap(pcap::Reader::new(r, variant)?),
                None => return Err(CaptureError::UnknownFormat(magic)),
            },
        };
        Ok(Capture {
            format,
            frames_read: 0,
        })
    }

    /// Returns the next packet, or `None` at the end of the file.
    pub fn next_frame(&mut self) -> Result<Option<Frame>, CaptureError> {
        let frame = match &mut self.format {
            Format::Pcap(r) => r.next()?,
            Format::PcapNg(r) => r.next()?,
        };
        Ok(frame.map(|mut frame| {
            self.frames_read += 1;
            frame.number = self.frames_read;
            frame
        }))
    }

    /// Number of packets returned so far.
    pub fn frames_read(&self) -> u64 {
        self.frames_read
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u16(self, b: &[u8]) -> u16 {
        let b = [b[0], b[1]];
        match self {
            Endian::Little => u16::from_le_bytes(b),
            Endian::Big => u16::from_be_bytes(b),
        }
    }

    fn u32(self, b: &[u8]) -> u32 {
        let b = [b[0], b[1], b[2], b[3]];
        match self {
            Endian::Little => u32::from_le_bytes(b),
            Endian::Big => u32::from_be_bytes(b),
        }
    }

    fn i64(self, b: &[u8]) -> i64 {
        let b: [u8; 8] = b[..8].try_into().unwrap();
        match self {
            Endian::Little => i64::from_le_bytes(b),
            Endian::Big => i64::from_be_bytes(b),
        }
    }
}

/// Fills `buf` as far as the input allows and returns how many bytes were
/// read. Unlike `read_exact`, this tells a clean end of file (0 bytes) apart
/// from a file that stops in the middle of a record.
fn read_up_to<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Reads exactly `len` bytes. Memory grows with the bytes actually read, so
/// a corrupt length field can't make us allocate gigabytes up front.
fn read_exactly<R: Read>(r: &mut R, len: usize) -> Result<Vec<u8>, CaptureError> {
    let mut buf = Vec::with_capacity(len.min(1 << 16));
    r.by_ref().take(len as u64).read_to_end(&mut buf)?;
    if buf.len() < len {
        return Err(CaptureError::Truncated);
    }
    Ok(buf)
}
