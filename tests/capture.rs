mod common;

use std::io::Cursor;

use common::*;
use packet_cage::capture::{Capture, CaptureError, Frame, InterfaceInfo, PcapNgWriter, Timestamp};

/// Reads every frame, and the error that stopped reading, if any.
fn read_all(bytes: Vec<u8>) -> (Vec<Frame>, Option<CaptureError>) {
    let mut capture = match Capture::from_reader(Cursor::new(bytes)) {
        Ok(c) => c,
        Err(e) => return (Vec::new(), Some(e)),
    };
    let mut frames = Vec::new();
    loop {
        match capture.next_frame() {
            Ok(Some(frame)) => frames.push(frame),
            Ok(None) => return (frames, None),
            Err(e) => return (frames, Some(e)),
        }
    }
}

fn read_ok(bytes: Vec<u8>) -> Vec<Frame> {
    let (frames, err) = read_all(bytes);
    assert!(err.is_none(), "unexpected error: {err:?}");
    frames
}

#[test]
fn pcap_frames_are_numbered_from_one() {
    let bytes = Pcap::new(LINKTYPE_ETHERNET)
        .packet(1_700_000_000_250_000, b"first")
        .snapped(1_700_000_001_000_000, b"second packet", 6)
        .bytes();
    let frames = read_ok(bytes);
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].number, 1);
    assert_eq!(frames[0].ts, Timestamp(1_700_000_000_250_000_000));
    assert_eq!(frames[0].data, b"first");
    assert_eq!(frames[1].number, 2);
    assert_eq!(frames[1].data, b"second");
    assert_eq!(frames[1].orig_len, 13);
    assert_eq!(frames[1].ts.secs_since(frames[0].ts), 0.75);
}

#[test]
fn big_endian_nanosecond_pcap() {
    let mut bytes = vec![0xa1, 0xb2, 0x3c, 0x4d, 0, 2, 0, 4];
    bytes.extend([0; 8]);
    bytes.extend(65535u32.to_be_bytes());
    bytes.extend(101u32.to_be_bytes());
    bytes.extend(10u32.to_be_bytes());
    bytes.extend(123_456_789u32.to_be_bytes());
    bytes.extend(2u32.to_be_bytes());
    bytes.extend(2u32.to_be_bytes());
    bytes.extend([0x45, 0]);
    let frames = read_ok(bytes);
    assert_eq!(frames[0].ts, Timestamp(10_123_456_789));
    assert_eq!(frames[0].link_type, 101);
}

#[test]
fn pcapng_interfaces_and_timestamp_resolutions() {
    let bytes = PcapNg::new(false)
        .interface(LINKTYPE_ETHERNET, None)
        .interface(101, Some(9))
        .packet(0, 2_000_000, b"eth")
        // Interface statistics block, which we skip.
        .block(5, &[0; 12])
        .packet(1, 3_500_000_000, b"raw")
        .simple_packet(b"simple")
        .bytes();
    let frames = read_ok(bytes);
    assert_eq!(frames.len(), 3);
    assert_eq!(
        (frames[0].link_type, frames[0].ts),
        (1, Timestamp(2_000_000_000))
    );
    assert_eq!(
        (frames[1].link_type, frames[1].ts),
        (101, Timestamp(3_500_000_000))
    );
    assert_eq!(frames[1].number, 2);
    // Simple packets belong to interface 0 and have no timestamp of their own.
    assert_eq!(frames[2].link_type, 1);
    assert_eq!(frames[2].data, b"simple");
    assert_eq!(frames[2].ts, frames[1].ts);
}

#[test]
fn pcapng_big_endian() {
    let bytes = PcapNg::new(true)
        .interface(LINKTYPE_ETHERNET, Some(3))
        .packet(0, 1500, b"x")
        .bytes();
    let frames = read_ok(bytes);
    assert_eq!(frames[0].ts, Timestamp(1_500_000_000));
}

#[test]
fn pcapng_new_section_starts_new_interfaces() {
    let mut w = PcapNg::new(false);
    w.interface(LINKTYPE_ETHERNET, None).packet(0, 1, b"a");
    w.section().interface(101, None).packet(0, 2, b"b");
    let frames = read_ok(w.bytes());
    assert_eq!(frames[0].link_type, 1);
    assert_eq!(frames[1].link_type, 101);
}

#[test]
fn packet_for_undefined_interface_is_corrupt() {
    let bytes = PcapNg::new(false).packet(0, 1, b"a").bytes();
    let (_, err) = read_all(bytes);
    assert!(matches!(err, Some(CaptureError::Corrupt(_))), "{err:?}");
}

#[test]
fn cut_off_file_keeps_complete_packets() {
    let pcap = Pcap::new(LINKTYPE_ETHERNET)
        .packet(0, &[1; 100])
        .packet(1, &[2; 100])
        .bytes();
    let pcapng = PcapNg::new(false)
        .interface(LINKTYPE_ETHERNET, None)
        .packet(0, 0, &[1; 100])
        .packet(0, 1, &[2; 100])
        .bytes();
    for bytes in [pcap, pcapng] {
        let cut = bytes.len() - 30;
        let (frames, err) = read_all(bytes[..cut].to_vec());
        assert_eq!(frames.len(), 1);
        assert!(matches!(err, Some(CaptureError::Truncated)), "{err:?}");
    }
}

#[test]
fn rejects_files_that_are_not_captures() {
    let cases: [(&[u8], &str); 4] = [
        (b"", "file is empty"),
        (
            b"PK\x03\x04 zip",
            "not a pcap or pcapng file (starts with 50 4b 03 04)",
        ),
        (
            &[0x1f, 0x8b, 8, 0, 0],
            "file is gzip-compressed; decompress it first",
        ),
        (
            &[0xd4, 0xc3, 0xb2, 0xa1, 2, 0],
            "corrupt capture: pcap file header is incomplete",
        ),
    ];
    for (bytes, message) in cases {
        let (_, err) = read_all(bytes.to_vec());
        assert_eq!(err.unwrap().to_string(), message);
    }
}

#[test]
fn absurd_packet_length_is_corrupt() {
    let mut bytes = Pcap::new(LINKTYPE_ETHERNET).bytes();
    bytes.extend([0; 8]);
    bytes.extend(u32::MAX.to_le_bytes());
    bytes.extend(u32::MAX.to_le_bytes());
    let (_, err) = read_all(bytes);
    assert!(matches!(err, Some(CaptureError::Corrupt(_))), "{err:?}");
}

/// What `live -w` writes reads back the same: data of every length (blocks
/// pad to 4 bytes), nanosecond timestamps, and lengths cut by a snaplen.
#[test]
fn written_pcapng_reads_back() {
    let frames: Vec<Frame> = (0..6u8)
        .map(|n| Frame {
            number: u64::from(n) + 1,
            ts: Timestamp(1_760_000_000_123_456_789 + u64::from(n) * 1_001),
            link_type: LINKTYPE_ETHERNET,
            orig_len: u32::from(n) + if n == 5 { 1000 } else { 0 },
            data: vec![n; usize::from(n)],
        })
        .collect();
    let interface = InterfaceInfo {
        link_type: LINKTYPE_ETHERNET,
        snaplen: 262_144,
        name: r"\Device\NPF_{4F1A}",
        description: Some("Wi-Fi"),
    };
    let mut writer = PcapNgWriter::new(Vec::new(), &interface).unwrap();
    for frame in &frames {
        writer.write(frame).unwrap();
    }
    let bytes = writer.into_inner();
    assert_eq!(bytes.len() % 4, 0);
    assert_eq!(read_ok(bytes), frames);
}

/// Corrupted capture files must give an error, never a panic or a huge
/// allocation.
#[test]
fn mutated_files_never_panic() {
    let packet = ethernet(
        0x0800,
        &ipv4([10, 0, 0, 1], [10, 0, 0, 2], 17, &udp(1, 2, b"x")),
    );
    let seeds = [
        Pcap::new(LINKTYPE_ETHERNET)
            .packet(0, &packet)
            .packet(5, &packet)
            .bytes(),
        PcapNg::new(false)
            .interface(LINKTYPE_ETHERNET, Some(9))
            .packet(0, 7, &packet)
            .simple_packet(&packet)
            .bytes(),
    ];
    let mut rng = Rng(42);
    for _ in 0..20_000 {
        let mut bytes = seeds[rng.below(seeds.len())].clone();
        for _ in 0..1 + rng.below(4) {
            let i = rng.below(bytes.len());
            bytes[i] = rng.next() as u8;
        }
        bytes.truncate(rng.below(bytes.len() + 1));
        let _ = read_all(bytes);
    }
}
