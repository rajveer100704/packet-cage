//! Filters checked against Wireshark. `fixtures/filters.tshark.txt` holds the
//! frames tshark 4.6 picks (`tshark -2 -Y FILTER`, with out-of-order TCP
//! reassembly on and HTTP body reassembly off) for a set of filters on the
//! captures in this repository, and for every filter the report prints for
//! them. packet-cage has to pick the same frames.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use packet_cage::analyze::Analyzer;
use packet_cage::capture::{Capture, Frame};
use packet_cage::decode;
use packet_cage::diagnose::{self, Diagnosis, Severity};
use packet_cage::filter::{Filter, PacketView, Target, Tracker, Whole};
use packet_cage::stats::Stats;

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

/// Where packet-cage and Wireshark differ on purpose; see PLAN.md.
const KNOWN: &[(&str, &str)] = &[
    // Frame 35's answer has a name that points to itself. Wireshark still
    // shows the record's address; packet-cage stops at the broken name.
    ("dns-zoo.pcap", "dns.a == 0.0.0.0/0"),
];

fn path(capture: &str) -> PathBuf {
    let fixture = Path::new(ROOT).join("tests/fixtures").join(capture);
    if fixture.exists() {
        fixture
    } else {
        Path::new(ROOT).join("examples").join(capture)
    }
}

fn frames(capture: &str) -> Vec<Frame> {
    let mut capture = Capture::open(&path(capture)).unwrap();
    let mut frames = Vec::new();
    while let Some(frame) = capture.next_frame().unwrap() {
        frames.push(frame);
    }
    frames
}

/// The frames `filter` picks, as `dump -f` would.
fn select(frames: &[Frame], filter: &Filter) -> Vec<u64> {
    let whole = filter.needs_whole_capture().then(|| {
        let mut analyzer = Analyzer::new();
        let mut whole = Whole::default();
        for frame in frames {
            let pkt = decode::decode(frame);
            let found = analyzer.observe(frame, &pkt);
            whole.observe(frame, &pkt, &found);
        }
        whole.finish(&analyzer);
        whole
    });
    let mut analyzer = Analyzer::new();
    let mut tracker = Tracker::new(whole);
    let mut picked = Vec::new();
    for frame in frames {
        let pkt = decode::decode(frame);
        let found = analyzer.observe(frame, &pkt);
        tracker.observe(frame, &found);
        if filter.matches(&PacketView::new(frame, &pkt, &found, &analyzer, &tracker)) {
            picked.push(frame.number);
        }
    }
    picked
}

fn diagnosis(frames: &[Frame]) -> Diagnosis {
    let mut analyzer = Analyzer::new();
    let mut stats = Stats::default();
    for frame in frames {
        let pkt = decode::decode(frame);
        analyzer.observe(frame, &pkt);
        stats.add(frame, &pkt);
    }
    diagnose::diagnose(&stats, &analyzer, Default::default())
}

/// capture → [(filter, frames)]
fn answer_key() -> BTreeMap<String, Vec<(String, Vec<u64>)>> {
    let text =
        std::fs::read_to_string(Path::new(ROOT).join("tests/fixtures/filters.tshark.txt")).unwrap();
    let mut key: BTreeMap<String, Vec<(String, Vec<u64>)>> = BTreeMap::new();
    for line in text.lines() {
        let mut parts = line.split('\t');
        let (capture, filter, frames) = (
            parts.next().unwrap(),
            parts.next().unwrap(),
            parts.next().unwrap_or(""),
        );
        let frames = frames
            .split(',')
            .filter(|f| !f.is_empty())
            .map(|f| f.parse().unwrap())
            .collect();
        key.entry(capture.to_string())
            .or_default()
            .push((filter.to_string(), frames));
    }
    key
}

#[test]
fn filters_pick_what_wireshark_picks() {
    let mut compared = 0;
    let mut wrong = Vec::new();
    for (capture, filters) in answer_key() {
        let frames = frames(&capture);
        for (text, expected) in filters {
            let filter = Filter::parse(&text).unwrap_or_else(|e| panic!("{capture}: {e}"));
            assert_eq!(filter.target(), Target::Packets);
            let picked = select(&frames, &filter);
            let known = KNOWN.contains(&(capture.as_str(), text.as_str()));
            if (picked == expected) == known {
                wrong.push(format!(
                    "{capture}: {text}: picked {picked:?}, tshark {expected:?}"
                ));
            }
            compared += 1;
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    assert!(compared > 400, "only {compared} filters");
}

/// New findings must be added to the answer key, so their filters get
/// checked with tshark.
#[test]
fn report_filters_are_in_the_answer_key() {
    let key = answer_key();
    for (capture, filters) in &key {
        let diagnosis = diagnosis(&frames(capture));
        for finding in &diagnosis.findings {
            let Some(filter) = &finding.filter else {
                continue;
            };
            assert!(
                filters.iter().any(|(f, _)| f == filter),
                "{capture}: {filter} is not in filters.tshark.txt"
            );
        }
    }
}

#[test]
fn finding_filters() {
    let diagnosis = diagnosis(&frames("demo.pcap"));
    let pick = |text: &str| -> Vec<String> {
        let filter = Filter::parse(text).unwrap();
        assert_eq!(filter.target(), Target::Findings);
        diagnosis
            .findings
            .iter()
            .filter(|f| filter.matches(*f))
            .map(|f| format!("{} {}", f.category.id(), f.subject))
            .collect()
    };
    assert_eq!(
        pick("finding.severity == error"),
        ["dns api.internal", "tls pay.example.com:443"]
    );
    assert_eq!(
        pick("finding.severity >= warning && finding.category != dns"),
        [
            "tls pay.example.com:443",
            "slow api.example.com:443",
            "loss 10.0.0.5 → cdn.example.com:443"
        ]
    );
    assert_eq!(
        pick("finding.server_secs > 2"),
        ["slow api.example.com:443"]
    );
    assert_eq!(
        pick("finding.retransmission_rate < 0.05"),
        Vec::<String>::new()
    );
    assert_eq!(
        pick("finding.hint contains \"proxy\""),
        ["tls pay.example.com:443"]
    );
    assert_eq!(
        pick("finding.category in {dns, http}"),
        ["dns api.internal"]
    );
    assert_eq!(pick("finding.severity == info"), Vec::<String>::new());
    assert!(
        diagnosis
            .findings
            .iter()
            .all(|f| f.severity != Severity::Info)
    );
}

/// A small deterministic generator, so failures repeat.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

#[test]
fn the_parser_never_panics() {
    const PIECES: &[&str] = &[
        "tcp.port",
        "ip.addr",
        "dns.qry.name",
        "frame",
        "finding.severity",
        "lower(",
        "len(",
        "count(",
        ")",
        "(",
        "{",
        "}",
        ",",
        "..",
        "==",
        "!=",
        "===",
        "!==",
        ">",
        "<=",
        "&&",
        "||",
        "^^",
        "!",
        "not",
        "in",
        "contains",
        "matches",
        "~",
        "&",
        "443",
        "0x1",
        "10.0.0.0/8",
        "fe80::1",
        "02:00:00:00:00:01",
        r#""a\x41""#,
        r#"r"\d""#,
        "\"",
        "\\",
        "1.5",
        "-1",
        "error",
        "é",
        "=",
        "|",
        "'",
    ];
    let mut rng = Rng(7);
    for _ in 0..20_000 {
        let n = 1 + rng.below(8);
        let text: Vec<&str> = (0..n).map(|_| PIECES[rng.below(PIECES.len())]).collect();
        let _ = Filter::parse(&text.join(" "));
        let _ = Filter::parse(&text.concat());
    }
}

#[test]
fn every_field_of_mutated_packets_reads_without_panicking() {
    use packet_cage::filter::fields::FIELDS;
    use packet_cage::filter::{Field, Source};

    let mut rng = Rng(11);
    for capture in [
        "tcp-zoo.pcap",
        "dns-zoo.pcap",
        "tls-zoo.pcap",
        "http-zoo.pcap",
    ] {
        let mut frames = frames(capture);
        for frame in &mut frames {
            for _ in 0..rng.below(4) {
                if !frame.data.is_empty() {
                    let at = rng.below(frame.data.len());
                    frame.data[at] = rng.next() as u8;
                }
            }
            if rng.below(8) == 0 {
                let keep = rng.below(frame.data.len() + 1);
                frame.data.truncate(keep);
            }
        }
        let mut first = Analyzer::new();
        let mut whole = Whole::default();
        for frame in &frames {
            let pkt = decode::decode(frame);
            let found = first.observe(frame, &pkt);
            whole.observe(frame, &pkt, &found);
        }
        whole.finish(&first);
        let mut analyzer = Analyzer::new();
        let mut tracker = Tracker::new(Some(whole));
        for frame in &frames {
            let pkt = decode::decode(frame);
            let found = analyzer.observe(frame, &pkt);
            tracker.observe(frame, &found);
            let view = PacketView::new(frame, &pkt, &found, &analyzer, &tracker);
            for &(field, ..) in FIELDS {
                let _ = view.values(Field::Packet(field));
            }
        }
    }
}
