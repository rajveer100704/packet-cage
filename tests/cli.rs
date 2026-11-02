mod common;

use std::path::PathBuf;
use std::process::{Command, Output};

use common::*;

/// Writes `bytes` to a temp file named after the test and runs the binary on it.
fn run(name: &str, bytes: &[u8], args: &[&str]) -> Output {
    let path: PathBuf =
        std::env::temp_dir().join(format!("packet-cage-{}-{name}.pcap", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_packet-cage"))
        .args(args)
        .arg(&path)
        .output()
        .unwrap();
    std::fs::remove_file(&path).unwrap();
    output
}

fn handshake() -> Pcap {
    let (client, server) = ([10, 0, 0, 1], [10, 0, 0, 2]);
    let mut pcap = Pcap::new(LINKTYPE_ETHERNET);
    pcap.packet(
        0,
        &ethernet(
            0x0800,
            &ipv4(client, server, 6, &tcp(50000, 80, 100, 0, SYN, &[])),
        ),
    )
    .packet(
        1_500,
        &ethernet(
            0x0800,
            &ipv4(server, client, 6, &tcp(80, 50000, 900, 101, SYN | ACK, &[])),
        ),
    )
    .packet(
        1_900,
        &ethernet(
            0x0800,
            &ipv4(client, server, 6, &tcp(50000, 80, 101, 901, ACK, &[])),
        ),
    );
    pcap
}

#[test]
fn dump_prints_one_line_per_packet() {
    let out = run("dump", &handshake().bytes(), &["dump"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(
        lines[1],
        "     2    0.001500  10.0.0.2:80 → 10.0.0.1:50000 TCP [SYN, ACK] seq=0 ack=1 win=64240 len=0"
    );
}

#[test]
fn dump_count_limits_output() {
    let out = run("count", &handshake().bytes(), &["dump", "-c", "2"]);
    assert_eq!(String::from_utf8(out.stdout).unwrap().lines().count(), 2);
}

#[test]
fn cut_off_capture_warns_and_succeeds() {
    let bytes = handshake().bytes();
    let out = run("cutoff", &bytes[..bytes.len() - 10], &["dump"]);
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap().lines().count(), 2);
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("ends in the middle of packet 3"),
        "{stderr}"
    );
}

#[test]
fn non_capture_file_exits_with_2() {
    let out = run("garbage", b"definitely not a capture", &["dump"]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("not a pcap or pcapng file"), "{stderr}");
}

#[test]
fn absolute_flag_shows_raw_sequence_numbers() {
    let out = run("absolute", &handshake().bytes(), &["dump", "-S"]);
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("[SYN, ACK] seq=900 ack=101 "), "{stdout}");
}

#[test]
fn report_is_the_default_command() {
    let out = run("report", &handshake().bytes(), &["--color", "always"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(
        lines[0].contains(": 3 packets over 1.9 ms, from 1970-01-01"),
        "{stdout}"
    );
    assert_eq!(
        lines[2],
        "\u{1b}[32m✓\u{1b}[0m No problems found in 1 connection"
    );
}

#[test]
fn report_formats_and_output_file() {
    let json = run("json", &handshake().bytes(), &["--format", "json"]);
    let stdout = String::from_utf8(json.stdout).unwrap();
    assert!(stdout.starts_with("{\n  \"schema\": 1,"), "{stdout}");
    assert!(!stdout.contains('\u{1b}'));

    let path = std::env::temp_dir().join(format!("packet-cage-{}-report.html", std::process::id()));
    let html = run(
        "html",
        &handshake().bytes(),
        &["--format", "html", "-o", path.to_str().unwrap()],
    );
    assert!(html.status.success());
    assert!(html.stdout.is_empty());
    let written = std::fs::read_to_string(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(written.starts_with("<!doctype html>"), "{written}");
}

#[test]
fn report_of_a_cut_off_capture() {
    let bytes = handshake().bytes();
    let out = run(
        "report-cutoff",
        &bytes[..bytes.len() - 10],
        &["--color", "never"],
    );
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains(
            "⚠ FILE  the file ends in the middle of packet 3; it was probably cut off while capturing"
        ),
        "{stdout}"
    );
}

#[test]
fn one_direction_only() {
    // The client's side of a connection, without the server's.
    let (client, server) = ([10, 0, 0, 1], [10, 0, 0, 2]);
    let mut pcap = Pcap::new(LINKTYPE_ETHERNET);
    for (i, (flags, payload)) in [(ACK, &b""[..]), (PSH | ACK, &b"GET / HTTP/1.1\r\n\r\n"[..])]
        .into_iter()
        .enumerate()
    {
        // An empty ACK doesn't use up a sequence number.
        pcap.packet(
            i as u64 * 1000,
            &ethernet(
                0x0800,
                &ipv4(client, server, 6, &tcp(50000, 80, 101, 901, flags, payload)),
            ),
        );
    }
    let out = run("one-sided", &pcap.bytes(), &["--color", "never"]);
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("⚠ FILE  only one direction of 1 connection was captured"),
        "{stdout}"
    );
    assert!(!stdout.contains("no response"), "{stdout}");
}

#[test]
fn no_file_is_a_usage_error() {
    let out = Command::new(env!("CARGO_BIN_EXE_packet-cage"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn stats_lists_conversations() {
    let out = run("stats", &handshake().bytes(), &["stats"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("TCP conversations: 1\n"), "{stdout}");
    let row = stdout
        .lines()
        .find(|l| l.contains("10.0.0.1:50000"))
        .unwrap();
    assert!(
        row.contains("10.0.0.2:80") && row.ends_with("open"),
        "{row}"
    );
}

const DEMO: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/demo.pcap");

fn packet_cage(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_packet-cage"))
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

fn frames(stdout: &str) -> Vec<u64> {
    stdout
        .lines()
        .map(|l| l.split_whitespace().next().unwrap().parse().unwrap())
        .collect()
}

#[test]
fn dump_filter_selects_packets() {
    let out = run(
        "filter",
        &handshake().bytes(),
        &["dump", "-f", "tcp.flags.syn == 1"],
    );
    assert!(out.status.success());
    assert_eq!(frames(&String::from_utf8(out.stdout).unwrap()), vec![1, 2]);

    let (code, stdout, _) = packet_cage(&["dump", DEMO, "-f", "tcp.analysis.retransmission"]);
    assert_eq!(code, 0);
    assert_eq!(frames(&stdout), vec![206, 224, 243, 261]);
    // -c counts printed packets.
    let (_, stdout, _) = packet_cage(&["dump", DEMO, "-f", "dns", "-c", "2"]);
    assert_eq!(frames(&stdout).len(), 2);
    // A field pointing forward needs a second pass.
    let (_, stdout, _) = packet_cage(&["dump", DEMO, "-f", "dns.flags.rcode == 3"]);
    assert_eq!(frames(&stdout), vec![41, 42, 134]);
    let (_, stdout, _) = packet_cage(&["dump", DEMO, "-f", "dns.response_in == 41"]);
    assert_eq!(frames(&stdout).len(), 1);
}

#[test]
fn bad_filters_exit_with_2_and_show_where() {
    let (code, stdout, stderr) = packet_cage(&["dump", DEMO, "-f", "tcp.flags.rst"]);
    assert_eq!(code, 2);
    assert!(stdout.is_empty());
    assert_eq!(
        stderr,
        "error: unknown field \"tcp.flags.rst\"; did you mean \"tcp.flags.reset\"?\n  tcp.flags.rst\n  ^~~~~~~~~~~~~\n"
    );
    let (code, _, stderr) = packet_cage(&["dump", DEMO, "-f", "finding.severity == error"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("check --fail-on"), "{stderr}");
    let (code, _, _) = packet_cage(&["check", DEMO, "--fail-on", "tcp.port =="]);
    assert_eq!(code, 2);
}

#[test]
fn check_fails_on_errors_by_default() {
    let (code, stdout, _) = packet_cage(&["check", DEMO, "--color", "never"]);
    assert_eq!(code, 1);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines[0],
        format!("{DEMO}: 2 findings match finding.severity == error")
    );
    assert!(lines[1].starts_with("✗ DNS   api.internal: name does not exist"));
    assert!(lines[2].starts_with("✗ TLS   pay.example.com:443: client rejected"));
}

#[test]
fn check_passes_when_nothing_matches() {
    let (code, stdout, _) = packet_cage(&[
        "check",
        DEMO,
        "--fail-on",
        "finding.category == http",
        "--fail-on",
        "tcp.analysis.zero_window",
    ]);
    assert_eq!(code, 0, "{stdout}");
    assert_eq!(
        stdout,
        format!(
            "{DEMO}: nothing matches finding.category == http\n\
             {DEMO}: nothing matches tcp.analysis.zero_window\n"
        )
    );
}

#[test]
fn check_on_packets_and_measurements() {
    let (code, stdout, _) = packet_cage(&[
        "check",
        DEMO,
        "--color",
        "never",
        "--fail-on",
        "tcp.analysis.fast_retransmission",
        "--fail-on",
        "finding.retransmission_rate > 0.05",
    ]);
    assert_eq!(code, 1);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines[0],
        format!("{DEMO}: 4 packets match tcp.analysis.fast_retransmission")
    );
    assert!(lines[1].starts_with("   206 "), "{}", lines[1]);
    assert!(lines[1].ends_with("[TCP Fast Retransmission]"));
    assert_eq!(
        lines[5],
        format!("{DEMO}: 1 finding matches finding.retransmission_rate > 0.05")
    );
    assert!(lines[6].starts_with("⚠ LOSS"));
}

#[test]
fn check_annotates_for_github() {
    let (code, stdout, _) = packet_cage(&["check", DEMO, "--format", "github", "--color", "never"]);
    assert_eq!(code, 1);
    let annotations: Vec<&str> = stdout.lines().filter(|l| l.starts_with("::")).collect();
    assert_eq!(annotations.len(), 2, "{stdout}");
    let file = DEMO.replace(':', "%3A");
    assert_eq!(
        annotations[0],
        format!(
            "::error file={file},title=DNS api.internal::name does not exist (NXDOMAIN, asked 3 times) (frames 41-42, 134)"
        )
    );
    assert!(
        annotations[1].contains("%0Ausually a private CA"),
        "{}",
        annotations[1]
    );
}

#[test]
fn fields_lists_packet_and_finding_fields() {
    let (code, stdout, _) = packet_cage(&["fields"]);
    assert_eq!(code, 0);
    assert!(stdout.lines().any(|l| l.starts_with("tcp.port ")));
    assert!(stdout.lines().any(|l| l.starts_with("finding.severity ")));
    assert!(
        stdout
            .lines()
            .any(|l| l.starts_with("finding.server_secs "))
    );
}

#[test]
fn readme_shows_real_check_output() {
    let readme = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))
        .unwrap()
        .replace("\r\n", "\n");
    let block = readme
        .split("$ packet-cage check examples/demo.pcap\n")
        .nth(1)
        .and_then(|rest| rest.split("```").next())
        .expect("README shows a check example");
    let out = Command::new(env!("CARGO_BIN_EXE_packet-cage"))
        .args(["check", "examples/demo.pcap", "--color", "never"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    assert_eq!(String::from_utf8(out.stdout).unwrap(), block);
}

#[test]
fn live_checks_its_arguments_before_capturing() {
    let (code, _, stderr) = packet_cage(&["live", "-d", "soon"]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("expected a time such as 30s, 5m or 1h"),
        "{stderr}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn sandbox_run_help_lists_security_options() {
    let (code, stdout, stderr) = packet_cage(&["sandbox", "run", "--help"]);

    assert_eq!(code, 0, "{stderr}");

    for option in [
        "--cgroup-root",
        "--timeout",
        "--memory",
        "--cpu-quota",
        "--pids",
        "--format",
    ] {
        assert!(
            stdout.contains(option),
            "sandbox help is missing {option}:\n{stdout}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn sandbox_run_requires_cgroup_root() {
    let (code, stdout, stderr) = packet_cage(&["sandbox", "run", DEMO]);

    assert_eq!(code, 2);
    assert!(stdout.is_empty());
    assert!(
        stderr.contains("--cgroup-root"),
        "expected missing cgroup-root error:\n{stderr}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn sandbox_run_rejects_invalid_timeout() {
    let (code, stdout, stderr) = packet_cage(&[
        "sandbox",
        "run",
        DEMO,
        "--cgroup-root",
        "/tmp",
        "--timeout",
        "soon",
    ]);

    assert_eq!(code, 2);
    assert!(stdout.is_empty());
    assert!(
        stderr.contains("expected a time such as 30s, 5m or 1h"),
        "unexpected timeout validation error:\n{stderr}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn sandbox_run_rejects_invalid_memory_size() {
    let (code, stdout, stderr) = packet_cage(&[
        "sandbox",
        "run",
        DEMO,
        "--cgroup-root",
        "/tmp",
        "--memory",
        "12XB",
    ]);

    assert_eq!(code, 2);
    assert!(stdout.is_empty());
    assert!(
        stderr.contains("use B, KB, KiB, MB, MiB, GB or GiB"),
        "unexpected memory validation error:\n{stderr}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn sandbox_run_rejects_invalid_report_format() {
    let (code, stdout, stderr) = packet_cage(&[
        "sandbox",
        "run",
        DEMO,
        "--cgroup-root",
        "/tmp",
        "--format",
        "yaml",
    ]);

    assert_eq!(code, 2);
    assert!(stdout.is_empty());
    assert!(
        stderr.contains("possible values"),
        "unexpected format validation error:\n{stderr}"
    );
}
