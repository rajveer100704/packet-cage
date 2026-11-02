//! Prints the values of filter fields for each packet, one line per packet
//! in the layout of `tshark -T fields -E occurrence=a -E aggregator='|'`.
//! It is how packet-cage's fields are compared with Wireshark's:
//!
//! ```text
//! cargo run --example fields -- capture.pcap frame.number tcp.port dns.qry.name
//! ```
//!
//! Numbers are decimal, times in nanoseconds, booleans 1 or 0, bytes hex,
//! and flags and protocols 1 when present.

use std::fmt::Write as _;
use std::path::Path;

use packet_cage::analyze::Analyzer;
use packet_cage::capture::{Capture, Frame};
use packet_cage::decode;
use packet_cage::filter::fields::{self, Kind};
use packet_cage::filter::{Field, PacketView, Source, Tracker, Value, Whole};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((path, names)) = args.split_first() else {
        eprintln!("usage: fields CAPTURE FIELD...");
        std::process::exit(2);
    };
    let fields: Vec<(fields::F, Kind)> = names
        .iter()
        .map(|n| fields::lookup(n).unwrap_or_else(|| panic!("unknown field {n}")))
        .collect();

    // Fields like dns.response_in need the whole capture first.
    let mut first = Analyzer::new();
    let mut whole = Whole::default();
    for frame in frames(Path::new(path)) {
        let pkt = decode::decode(&frame);
        let found = first.observe(&frame, &pkt);
        whole.observe(&frame, &pkt, &found);
    }
    whole.finish(&first);
    let mut analyzer = Analyzer::new();
    let mut tracker = Tracker::new(Some(whole));
    let mut out = String::new();
    for frame in frames(Path::new(path)) {
        let pkt = decode::decode(&frame);
        let found = analyzer.observe(&frame, &pkt);
        tracker.observe(&frame, &found);
        let view = PacketView::new(&frame, &pkt, &found, &analyzer, &tracker);
        let row: Vec<String> = fields
            .iter()
            .map(|&(f, kind)| {
                view.values(Field::Packet(f))
                    .iter()
                    .map(|v| show(v, kind))
                    .collect::<Vec<_>>()
                    .join("|")
            })
            .collect();
        let _ = writeln!(out, "{}", row.join("\t"));
    }
    print!("{out}");
}

fn frames(path: &Path) -> Vec<Frame> {
    let mut capture = Capture::open(path).expect("readable capture");
    let mut frames = Vec::new();
    while let Ok(Some(frame)) = capture.next_frame() {
        frames.push(frame);
    }
    frames
}

fn show(value: &Value<'_>, kind: Kind) -> String {
    match value {
        _ if kind == Kind::Protocol => "1".to_string(),
        Value::Present => "1".to_string(),
        Value::Bool(b) => u8::from(*b).to_string(),
        Value::UInt(n) => n.to_string(),
        Value::Time(ns) => ns.to_string(),
        Value::Str(s) => s.to_string(),
        Value::Ip(ip) => ip.to_string(),
        Value::Ether(m) => m
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
        Value::Bytes(b) => b.iter().map(|b| format!("{b:02x}")).collect(),
        Value::Number(x) => x.to_string(),
        Value::Severity(s) => s.name().to_string(),
    }
}
