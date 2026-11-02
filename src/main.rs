#[cfg(target_os = "linux")]
use std::ffi::OsStr;
#[cfg(target_os = "linux")]
use std::fs;
use std::fs::File;
use std::io::{self, BufWriter, IsTerminal, Write};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
#[cfg(target_os = "linux")]
use std::process::{Command as ProcessCommand, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use anyhow::ensure;
use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};

use packet_cage::analyze::{Analyzer, PacketFindings};
use packet_cage::capture::{Capture, CaptureError, Frame, InterfaceInfo, PcapNgWriter, Timestamp};
use packet_cage::decode::Packet;
use packet_cage::diagnose::{CaptureInfo, Diagnosis, Finding, Severity};
use packet_cage::filter::{self, Filter, PacketView, Target, Tracker, Whole};
use packet_cage::live::{self, Live};
use packet_cage::report::{html, json, text};
use packet_cage::stats::{self, Stats};
use packet_cage::{decode, diagnose, summary, units};

#[cfg(target_os = "linux")]
use packet_cage::sandbox::cgroup::{CgroupManager, JobCgroup, ResourceLimits};
#[cfg(target_os = "linux")]
use packet_cage::sandbox::launcher::wait_with_timeout;
#[cfg(target_os = "linux")]
use packet_cage::sandbox::namespaces::spawn_namespaced_in_cgroup;
#[cfg(target_os = "linux")]
use packet_cage::sandbox::rootfs::{RootFs, RootFsConfig, RootFsWorkspace};

/// Findings shown in text output unless `--all` is given.
const TEXT_FINDINGS: usize = 30;
/// Matching packets `check` prints per filter.
const CHECK_PACKETS: usize = 10;
/// What `check` fails on when no `--fail-on` is given.
const DEFAULT_FAIL_ON: &str = "finding.severity == error";
/// Bytes kept from each packet in a live capture: all of it, as tcpdump does.
const SNAPLEN: u32 = 262_144;

#[derive(Parser)]
#[command(
    version,
    about = "Reads a packet capture and tells you what went wrong",
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[command(flatten)]
    report: ReportArgs,
}

/// `packet-cage FILE`: the diagnosis report.
#[derive(Args)]
struct ReportArgs {
    /// Capture file (.pcap or .pcapng)
    #[arg(required = true)]
    file: Option<PathBuf>,
    #[command(flatten)]
    output: OutputArgs,
}

/// How to show a report.
#[derive(Args)]
struct OutputArgs {
    /// Output format
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
    /// Write the report to this file instead of the terminal
    #[arg(short, long, value_name = "PATH")]
    output: Option<PathBuf>,
    /// Show every finding; text output stops after 30 otherwise
    #[arg(short, long)]
    all: bool,
    /// When to color text output
    #[arg(long, value_enum, default_value_t = ColorWhen::Auto)]
    color: ColorWhen,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    Text,
    Json,
    Html,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ColorWhen {
    /// When writing to a terminal, unless NO_COLOR is set
    Auto,
    Always,
    Never,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CheckFormat {
    Text,
    /// Text, plus annotations for GitHub Actions
    Github,
}

#[derive(Subcommand)]
enum Command {
    /// Print one line per packet, like tcpdump
    Dump {
        /// Capture file (.pcap or .pcapng)
        file: PathBuf,
        /// Only packets that match this filter, in Wireshark's syntax:
        /// "tcp.port == 443 && !tcp.analysis.flags"
        #[arg(short = 'f', long, value_name = "FILTER")]
        filter: Option<String>,
        /// Stop after printing this many packets
        #[arg(short = 'c', long)]
        count: Option<u64>,
        /// Show raw TCP sequence numbers instead of counting from the start
        /// of each connection
        #[arg(short = 'S', long)]
        absolute: bool,
    },
    /// Summarize the capture: protocols, hosts, conversations, TCP and DNS problems
    Stats {
        /// Capture file (.pcap or .pcapng)
        file: PathBuf,
        /// Rows to show in the host and conversation tables
        #[arg(short = 'n', long, default_value_t = 10)]
        top: usize,
    },
    /// For CI: exit with status 1 when a capture has problems
    Check {
        /// Capture files (.pcap or .pcapng)
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Fail when a finding or packet matches this filter; give it more
        /// than once to check several things [default: "finding.severity ==
        /// error"]
        #[arg(long, value_name = "FILTER")]
        fail_on: Vec<String>,
        /// Output format
        #[arg(long, value_enum, default_value_t = CheckFormat::Text)]
        format: CheckFormat,
        /// When to color text output
        #[arg(long, value_enum, default_value_t = ColorWhen::Auto)]
        color: ColorWhen,
    },
    /// List the fields filters can use
    Fields,
    /// Capture from a network interface, then diagnose what was captured
    Live(LiveArgs),
    /// List the interfaces live can capture on
    Interfaces,

    /// Run packet-capture analysis in a Linux security sandbox
    #[cfg(target_os = "linux")]
    Sandbox(SandboxArgs),

    /// Internal worker entry point; not part of the public CLI
    #[cfg(target_os = "linux")]
    #[command(name = "__sandbox-worker", hide = true)]
    SandboxWorker(SandboxWorkerArgs),
}

#[derive(Args)]
struct LiveArgs {
    /// Interface: its name, its number in `packet-cage interfaces`, one of its
    /// addresses, or its description [default: the one with the route to
    /// the internet]
    #[arg(short, long, value_name = "IFACE")]
    interface: Option<String>,
    /// Stop after this long, such as 30s, 5m or 1h [default: at Ctrl-C]
    #[arg(short, long, value_name = "TIME", value_parser = duration_arg)]
    duration: Option<Duration>,
    /// Stop after this many packets
    #[arg(short = 'c', long)]
    count: Option<u64>,
    /// Also save the packets to this file (pcapng), to open in Wireshark
    #[arg(short, long, value_name = "PATH")]
    write: Option<PathBuf>,
    /// Capture only packets that match this filter, in tcpdump's syntax:
    /// "port 443", "host 10.0.0.5"
    #[arg(long, value_name = "BPF")]
    capture_filter: Option<String>,
    /// Also capture traffic between other machines, where the network
    /// shows it
    #[arg(long)]
    promisc: bool,
    #[command(flatten)]
    output: OutputArgs,
}

#[cfg(target_os = "linux")]
#[derive(Args)]
struct SandboxArgs {
    #[command(subcommand)]
    command: SandboxCommand,
}

#[cfg(target_os = "linux")]
#[derive(Subcommand)]
enum SandboxCommand {
    /// Analyze a capture in an isolated Linux environment
    Run(SandboxRunArgs),
}

#[cfg(target_os = "linux")]
#[derive(Args)]
struct SandboxRunArgs {
    /// Capture file (.pcap or .pcapng)
    file: PathBuf,

    /// Explicitly delegated cgroup v2 directory
    #[arg(long, value_name = "PATH")]
    cgroup_root: PathBuf,

    /// Wall-clock execution timeout (examples: 10s, 2m)
    #[arg(long, default_value = "10s", value_parser = duration_arg)]
    timeout: Duration,

    /// Maximum worker memory (examples: 512MiB, 1GiB)
    #[arg(long, default_value = "512MiB", value_parser = parse_memory_arg)]
    memory: u64,

    /// CPU quota in microseconds per 100000-microsecond period
    #[arg(long, default_value_t = 50_000)]
    cpu_quota: u64,

    /// Maximum number of processes in the workload
    #[arg(long, default_value_t = 64)]
    pids: u64,

    /// Report format
    #[arg(long, value_enum, default_value_t = Format::Json)]
    format: Format,
}

#[cfg(target_os = "linux")]
#[derive(Args)]
struct SandboxWorkerArgs {
    capture: PathBuf,
    workspace: PathBuf,

    #[arg(value_enum)]
    format: Format,
}

#[cfg(target_os = "linux")]
fn parse_memory_arg(value: &str) -> Result<u64, String> {
    let value = value.trim();
    let split = value
        .find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(value.len());

    let (number, unit) = value.split_at(split);
    if number.is_empty() {
        return Err("expected a positive memory size such as 512MiB".to_string());
    }

    let amount = number
        .parse::<u64>()
        .map_err(|_| "memory size is out of range".to_string())?;

    let multiplier: u64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" => 1_000,
        "kib" => 1_024,
        "m" | "mb" => 1_000_000,
        "mib" => 1_048_576,
        "g" | "gb" => 1_000_000_000,
        "gib" => 1_073_741_824,
        _ => return Err("use B, KB, KiB, MB, MiB, GB or GiB".to_string()),
    };

    let bytes = amount
        .checked_mul(multiplier)
        .ok_or_else(|| "memory size is out of range".to_string())?;

    if bytes == 0 {
        return Err("memory limit must be greater than zero".to_string());
    }

    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn format_name(format: Format) -> &'static str {
    match format {
        Format::Text => "text",
        Format::Json => "json",
        Format::Html => "html",
    }
}

#[cfg(target_os = "linux")]
fn find_chroot() -> Result<&'static str> {
    ["/usr/sbin/chroot", "/usr/bin/chroot"]
        .into_iter()
        .find(|candidate| Path::new(candidate).is_file())
        .ok_or_else(|| anyhow::anyhow!("cannot find /usr/sbin/chroot or /usr/bin/chroot"))
}

#[cfg(target_os = "linux")]
fn sandbox_worker(args: SandboxWorkerArgs) -> Result<()> {
    let executable = std::env::current_exe().context("cannot resolve the PacketCage executable")?;

    eprintln!("sandbox: constructing private root filesystem");

    let rootfs = RootFs::build_at(
        &executable,
        &args.capture,
        RootFsConfig::default(),
        &args.workspace,
    )?;

    // Setup and chroot happen before the analyzer installs its seccomp filter.
    let analysis_result = ProcessCommand::new(find_chroot()?)
        .arg(rootfs.root_path())
        .arg(rootfs.executable_guest_path())
        .arg("--format")
        .arg(format_name(args.format))
        .arg(rootfs.capture_guest_path())
        .env("PACKET_CAGE_SECCOMP", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("cannot execute PacketCage inside the private root filesystem");

    // Always attempt explicit rootfs cleanup after chroot exits.
    let cleanup_result = rootfs.cleanup();

    let status = analysis_result?;
    cleanup_result?;

    ensure!(
        status.success(),
        "PacketCage analysis process exited unsuccessfully: {status}"
    );

    Ok(())
}

#[cfg(target_os = "linux")]
fn cleanup_sandbox_cgroups(
    job: JobCgroup,
    manager: CgroupManager,
    base_path: PathBuf,
) -> Result<()> {
    let job_result = (|| -> Result<()> {
        if job.wait_for_empty(Duration::from_millis(100)).is_err() {
            job.kill_all()
                .context("cannot kill remaining sandbox processes")?;

            job.wait_for_empty(Duration::from_secs(5))
                .context("sandbox processes survived termination")?;
        }

        job.remove()
    })();

    drop(manager);

    let base_result = fs::remove_dir(&base_path)
        .with_context(|| format!("cannot remove cgroup manager {}", base_path.display()));

    job_result?;
    base_result?;

    Ok(())
}

#[cfg(target_os = "linux")]
fn sandbox_run(args: SandboxRunArgs) -> Result<()> {
    let capture = args
        .file
        .canonicalize()
        .with_context(|| format!("cannot resolve capture {}", args.file.display()))?;

    ensure!(capture.is_file(), "capture must be a regular file");

    let executable = std::env::current_exe()
        .context("cannot resolve the PacketCage executable")?
        .canonicalize()
        .context("cannot canonicalize the PacketCage executable")?;

    let base_name = format!("packet-cage-{}", std::process::id());

    // The parent owns this workspace, including cleanup after worker SIGKILL.
    let workspace =
        RootFsWorkspace::create().context("cannot create parent-owned rootfs workspace")?;
    let workspace_path = workspace.path().to_path_buf();

    eprintln!("sandbox: creating resource-limited workload");

    let manager = CgroupManager::new(&args.cgroup_root, &base_name)?;
    let base_path = manager.base_path().to_path_buf();

    let limits = ResourceLimits {
        cpu_quota_micros: Some(args.cpu_quota),
        cpu_period_micros: 100_000,
        memory_max_bytes: args.memory,
        pids_max: args.pids,
    };

    let job = match manager.create_job("worker", limits) {
        Ok(job) => job,
        Err(error) => {
            drop(manager);
            fs::remove_dir(&base_path)
                .with_context(|| format!("cannot remove {}", base_path.display()))?;
            return Err(error);
        }
    };

    let format = format_name(args.format);
    let worker_args = [
        OsStr::new("__sandbox-worker"),
        capture.as_os_str(),
        workspace_path.as_os_str(),
        OsStr::new(format),
    ];

    eprintln!("sandbox: launching isolated worker");

    let mut child = match spawn_namespaced_in_cgroup(&job, &executable, worker_args) {
        Ok(child) => child,
        Err(error) => {
            let cleanup = cleanup_sandbox_cgroups(job, manager, base_path);
            return match cleanup {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(error.context(format!(
                    "sandbox launch failed; cleanup also failed: {cleanup_error:#}"
                ))),
            };
        }
    };

    let wait_result = wait_with_timeout(&mut child, &job, args.timeout, Duration::from_secs(5));

    // Run cleanup regardless of success, non-zero exit, or timeout.
    let cleanup_result = cleanup_sandbox_cgroups(job, manager, base_path);

    let status = wait_result?;
    cleanup_result?;

    ensure!(
        status.success(),
        "sandbox worker exited unsuccessfully: {status}"
    );

    eprintln!("sandbox: worker and cgroups cleaned up");

    Ok(())
}

fn duration_arg(s: &str) -> Result<Duration, String> {
    units::parse_duration(s).ok_or_else(|| "expected a time such as 30s, 5m or 1h".to_string())
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    #[cfg(target_os = "linux")]
    if cli.command.is_none()
        && std::env::var_os("PACKET_CAGE_SECCOMP").as_deref() == Some(std::ffi::OsStr::new("1"))
        && let Err(error) = packet_cage::sandbox::seccomp::install_analysis_filter()
    {
        eprintln!("error: failed to install seccomp filter: {error:#}");
        return ExitCode::from(2);
    }
    let result = match cli.command {
        Some(Command::Dump {
            file,
            filter,
            count,
            absolute,
        }) => dump(&file, filter.as_deref(), count, absolute).map(|()| true),
        Some(Command::Stats { file, top }) => stats(&file, top).map(|()| true),
        Some(Command::Check {
            files,
            fail_on,
            format,
            color,
        }) => check(&files, &fail_on, format, color),
        Some(Command::Fields) => fields().map(|()| true),
        Some(Command::Live(args)) => live(args).map(|()| true),
        Some(Command::Interfaces) => interfaces().map(|()| true),
        #[cfg(target_os = "linux")]
        Some(Command::Sandbox(args)) => match args.command {
            SandboxCommand::Run(args) => sandbox_run(args).map(|()| true),
        },
        #[cfg(target_os = "linux")]
        Some(Command::SandboxWorker(args)) => sandbox_worker(args).map(|()| true),
        None => report(cli.report).map(|()| true),
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

/// The error shows the filter with a mark under the problem.
fn parse_filter(text: &str) -> Result<Filter> {
    Ok(Filter::parse(text)?)
}

fn dump(path: &Path, filter: Option<&str>, count: Option<u64>, absolute: bool) -> Result<()> {
    let filter = filter.map(parse_filter).transpose()?;
    if filter
        .as_ref()
        .is_some_and(|f| f.target() == Target::Findings)
    {
        bail!("dump -f takes a packet filter; finding.* fields are for check --fail-on");
    }
    let whole = match &filter {
        Some(f) if f.needs_whole_capture() => Some(first_pass(path)?),
        _ => None,
    };
    let mut out = BufWriter::new(io::stdout().lock());
    let mut analyzer = Analyzer::new();
    let mut tracker = Tracker::new(whole);
    let mut first_ts = None;
    let mut printed = 0;
    let end = read_frames(path, |frame| {
        if count.is_some_and(|c| printed >= c) {
            return Ok(ControlFlow::Break(()));
        }
        let start = *first_ts.get_or_insert(frame.ts);
        let pkt = decode::decode(&frame);
        let found = analyzer.observe(&frame, &pkt);
        tracker.observe(&frame, &found);
        if let Some(filter) = &filter
            && !filter.matches(&PacketView::new(&frame, &pkt, &found, &analyzer, &tracker))
        {
            return Ok(ControlFlow::Continue(()));
        }
        let line = writeln!(
            out,
            "{}",
            dump_line(&frame, &pkt, &found, &analyzer, start, absolute)
        );
        if is_broken_pipe(&line) {
            return Ok(ControlFlow::Break(()));
        }
        line?;
        printed += 1;
        Ok(ControlFlow::Continue(()))
    })?;
    ignore_broken_pipe(out.flush())?;
    end.warn(path);
    Ok(())
}

fn dump_line(
    frame: &Frame,
    pkt: &Packet<'_>,
    found: &PacketFindings,
    analyzer: &Analyzer,
    start: Timestamp,
    absolute: bool,
) -> String {
    let seq_base = match &found.flow {
        Some(o) if !absolute => analyzer.flows.seq_base(o.flow),
        _ => None,
    };
    format!(
        "{:>6} {:>11.6}  {}",
        frame.number,
        frame.ts.secs_since(start),
        summary::describe_with(pkt, found, seq_base)
    )
}

/// Reads the whole capture once, for filters that need to know what comes
/// later in it.
fn first_pass(path: &Path) -> Result<Whole> {
    let mut analyzer = Analyzer::new();
    let mut whole = Whole::default();
    read_frames(path, |frame| {
        let pkt = decode::decode(&frame);
        let found = analyzer.observe(&frame, &pkt);
        whole.observe(&frame, &pkt, &found);
        Ok(ControlFlow::Continue(()))
    })?;
    whole.finish(&analyzer);
    Ok(whole)
}

fn stats(path: &Path, top: usize) -> Result<()> {
    let mut stats = Stats::default();
    let mut analyzer = Analyzer::new();
    let end = read_frames(path, |frame| {
        let pkt = decode::decode(&frame);
        analyzer.observe(&frame, &pkt);
        stats.add(&frame, &pkt);
        Ok(ControlFlow::Continue(()))
    })?;
    let report = stats::render(&stats, &analyzer, top);
    ignore_broken_pipe(io::stdout().lock().write_all(report.as_bytes()))?;
    end.warn(path);
    Ok(())
}

/// Reads a capture and diagnoses it.
fn diagnose_file(path: &Path) -> Result<Diagnosis> {
    let mut stats = Stats::default();
    let mut analyzer = Analyzer::new();
    let end = read_frames(path, |frame| {
        let pkt = decode::decode(&frame);
        analyzer.observe(&frame, &pkt);
        stats.add(&frame, &pkt);
        Ok(ControlFlow::Continue(()))
    })?;
    let cut_off_after = match end {
        End::CutOff { frames } => Some(frames),
        End::Complete => None,
    };
    let info = CaptureInfo {
        cut_off_after,
        dropped: None,
    };
    Ok(diagnose::diagnose(&stats, &analyzer, info))
}

fn report(args: ReportArgs) -> Result<()> {
    let path = args.file.expect("clap requires a file");
    let diagnosis = diagnose_file(&path)?;
    show_report(&path.display().to_string(), &diagnosis, &args.output)
}

fn show_report(name: &str, diagnosis: &Diagnosis, args: &OutputArgs) -> Result<()> {
    let body = match args.format {
        Format::Text => text::render(name, diagnosis, (!args.all).then_some(TEXT_FINDINGS)),
        Format::Json => json::render(name, diagnosis),
        Format::Html => html::render(name, diagnosis),
    };
    if let Some(output) = &args.output {
        let body = match args.format {
            Format::Text => anstream::adapter::strip_str(&body).to_string(),
            Format::Json | Format::Html => body,
        };
        return std::fs::write(output, body)
            .with_context(|| format!("cannot write {}", output.display()));
    }
    let color = match args.format {
        Format::Text => args.color,
        Format::Json | Format::Html => ColorWhen::Never,
    };
    write_out(&body, color)
}

fn write_out(body: &str, color: ColorWhen) -> Result<()> {
    let choice = match color {
        ColorWhen::Auto => anstream::ColorChoice::Auto,
        ColorWhen::Always => anstream::ColorChoice::Always,
        ColorWhen::Never => anstream::ColorChoice::Never,
    };
    let mut out = anstream::AutoStream::new(io::stdout().lock(), choice);
    ignore_broken_pipe(out.write_all(body.as_bytes()).and_then(|()| out.flush()))
}

/// What one `--fail-on` filter matched in one capture.
enum Matched<'a> {
    Findings(Vec<&'a Finding>),
    Packets { count: u64, lines: Vec<String> },
}

impl Matched<'_> {
    fn count(&self) -> u64 {
        match self {
            Matched::Findings(f) => f.len() as u64,
            Matched::Packets { count, .. } => *count,
        }
    }
}

/// Returns whether every capture passed.
fn check(
    files: &[PathBuf],
    fail_on: &[String],
    format: CheckFormat,
    color: ColorWhen,
) -> Result<bool> {
    let texts = if fail_on.is_empty() {
        vec![DEFAULT_FAIL_ON.to_string()]
    } else {
        fail_on.to_vec()
    };
    let filters: Vec<Filter> = texts
        .iter()
        .map(|t| parse_filter(t))
        .collect::<Result<_>>()?;
    let mut out = String::new();
    let mut annotations = String::new();
    let mut passed = true;
    let findings_wanted = filters.iter().any(|f| f.target() == Target::Findings);
    for path in files {
        let diagnosis = findings_wanted.then(|| diagnose_file(path)).transpose()?;
        let packets = match_packets(path, &filters)?;
        let name = path.display().to_string();
        for (filter, packets) in filters.iter().zip(packets) {
            let matched = match (packets, &diagnosis) {
                (Some(packets), _) => packets,
                (None, Some(diagnosis)) => Matched::Findings(
                    diagnosis
                        .findings
                        .iter()
                        .filter(|f| filter.matches(*f))
                        .collect(),
                ),
                (None, None) => unreachable!("finding filters come with a diagnosis"),
            };
            if matched.count() > 0 {
                passed = false;
            }
            check_text(&mut out, &name, filter, &matched);
            if format == CheckFormat::Github {
                github_annotations(&mut annotations, &name, filter, &matched);
            }
        }
    }
    out.push_str(&annotations);
    write_out(&out, color)?;
    Ok(passed)
}

/// Runs the packet filters over a capture. Returns what each matched, or
/// `None` for the finding filters.
fn match_packets(path: &Path, filters: &[Filter]) -> Result<Vec<Option<Matched<'static>>>> {
    let mut matched: Vec<Option<Matched>> = filters
        .iter()
        .map(|f| {
            (f.target() == Target::Packets).then(|| Matched::Packets {
                count: 0,
                lines: Vec::new(),
            })
        })
        .collect();
    if matched.iter().all(Option::is_none) {
        return Ok(matched);
    }
    let whole = match filters.iter().any(Filter::needs_whole_capture) {
        true => Some(first_pass(path)?),
        false => None,
    };
    let mut analyzer = Analyzer::new();
    let mut tracker = Tracker::new(whole);
    let mut first_ts = None;
    read_frames(path, |frame| {
        let start = *first_ts.get_or_insert(frame.ts);
        let pkt = decode::decode(&frame);
        let found = analyzer.observe(&frame, &pkt);
        tracker.observe(&frame, &found);
        let view = PacketView::new(&frame, &pkt, &found, &analyzer, &tracker);
        for (filter, matched) in filters.iter().zip(&mut matched) {
            if let Some(Matched::Packets { count, lines }) = matched
                && filter.matches(&view)
            {
                *count += 1;
                if lines.len() < CHECK_PACKETS {
                    lines.push(dump_line(&frame, &pkt, &found, &analyzer, start, false));
                }
            }
        }
        Ok(ControlFlow::Continue(()))
    })?;
    Ok(matched)
}

fn check_text(out: &mut String, file: &str, filter: &Filter, matched: &Matched<'_>) {
    use std::fmt::Write as _;
    let n = matched.count();
    if n == 0 {
        let _ = writeln!(out, "{file}: nothing matches {filter}");
        return;
    }
    let what = match matched {
        Matched::Findings(_) => text::plural(n, "finding", "findings"),
        Matched::Packets { .. } => text::plural(n, "packet", "packets"),
    };
    let verb = if n == 1 { "matches" } else { "match" };
    let _ = writeln!(out, "{file}: {what} {verb} {filter}");
    match matched {
        Matched::Findings(findings) => out.push_str(&text::findings(findings.iter().copied())),
        Matched::Packets { lines, .. } => {
            for line in lines {
                let _ = writeln!(out, "{line}");
            }
            let more = n - lines.len() as u64;
            if more > 0 {
                let _ = writeln!(
                    out,
                    "… {more} more; packet-cage dump {file} -f '{filter}' shows them"
                );
            }
        }
    }
}

/// Workflow commands that make GitHub show each match as an annotation.
fn github_annotations(out: &mut String, file: &str, filter: &Filter, matched: &Matched<'_>) {
    use std::fmt::Write as _;
    match matched {
        Matched::Findings(findings) => {
            for f in findings {
                let level = match f.severity {
                    Severity::Error => "error",
                    Severity::Warning => "warning",
                    Severity::Info => "notice",
                };
                let mut message = f.text.clone();
                if !f.frames.is_empty() {
                    message = format!("{message} ({})", f.frames_text(4));
                }
                if let Some(hint) = &f.hint {
                    message = format!("{message}\n{hint}");
                }
                let title = match f.subject.as_str() {
                    "" => format!("{} in {file}", f.category.name()),
                    subject => format!("{} {subject}", f.category.name()),
                };
                let _ = writeln!(
                    out,
                    "::{level} file={},title={}::{}",
                    escape_property(file),
                    escape_property(&title),
                    escape_data(&message)
                );
            }
        }
        Matched::Packets { count: 0, .. } => {}
        Matched::Packets { count, lines } => {
            let first = lines.first().map(|l| l.trim_start()).unwrap_or_default();
            let message = format!(
                "{} {} {filter}, first: {first}",
                text::plural(*count, "packet", "packets"),
                if *count == 1 { "matches" } else { "match" },
            );
            let _ = writeln!(
                out,
                "::error file={},title=packet-cage check::{}",
                escape_property(file),
                escape_data(&message)
            );
        }
    }
}

fn escape_data(s: &str) -> String {
    s.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

fn escape_property(s: &str) -> String {
    escape_data(s).replace(':', "%3A").replace(',', "%2C")
}

fn fields() -> Result<()> {
    use std::fmt::Write as _;
    let mut out = String::from(
        "Fields for dump -f and check --fail-on. They have Wireshark's names and\n\
         meanings, so a filter works the same in both.\n\n",
    );
    let rows: Vec<_> = filter::all_fields().collect();
    let width = rows.iter().map(|(name, ..)| name.len()).max().unwrap_or(0);
    for (name, kind, help) in rows {
        if name == "finding.severity" {
            out.push_str("\nFields of findings, for check --fail-on:\n");
        }
        let _ = writeln!(out, "{name:<width$}  {:<15}  {help}", kind.describe());
    }
    ignore_broken_pipe(io::stdout().lock().write_all(out.as_bytes()))
}

/// Captures until the time or count runs out or Ctrl-C, analyzing as the
/// packets come, then prints the report.
fn live(args: LiveArgs) -> Result<()> {
    let list = live::interfaces()?;
    let chosen = match &args.interface {
        Some(wanted) => live::find(&list, wanted),
        None => Some(live::default_interface(&list).context(
            "no interface is up with an address; packet-cage interfaces lists them, and -i picks one",
        )?),
    };
    // A name libpcap knows but doesn't list, such as a VLAN device, is
    // still worth trying.
    let (device, label, description) = match chosen {
        Some(i) => (
            list[i].name.as_str(),
            list[i].label(),
            list[i].description.as_deref(),
        ),
        None => {
            let wanted = args
                .interface
                .as_deref()
                .expect("only a named interface is missing");
            (wanted, wanted, None)
        }
    };
    let options = live::Options {
        snaplen: SNAPLEN,
        promisc: args.promisc,
        filter: args.capture_filter.as_deref(),
    };
    let (mut capture, warning) = Live::open(device, &options)?;
    if let Some(warning) = warning {
        eprintln!("warning: {warning}");
    }
    let mut file = match &args.write {
        Some(path) => {
            let out =
                File::create(path).with_context(|| format!("cannot create {}", path.display()))?;
            let interface = InterfaceInfo {
                link_type: capture.link_type(),
                snaplen: SNAPLEN,
                name: device,
                description,
            };
            Some(PcapNgWriter::new(BufWriter::new(out), &interface)?)
        }
        None => None,
    };

    // The first Ctrl-C (or kill) ends the capture and shows the report; a
    // second one gives up on it. A signal sent to sudo and to us both
    // arrives twice at once, so the second must come a moment later.
    let stop = Arc::new(AtomicBool::new(false));
    let handler_stop = Arc::clone(&stop);
    let mut stopped_at = None;
    ctrlc::set_handler(move || match stopped_at {
        None => {
            stopped_at = Some(Instant::now());
            handler_stop.store(true, Ordering::SeqCst);
        }
        Some(at) if at.elapsed() > Duration::from_millis(500) => std::process::exit(130),
        Some(_) => {}
    })
    .context("cannot catch Ctrl-C")?;

    let started = Instant::now();
    let deadline = args.duration.map(|d| started + d);
    match args.duration {
        Some(d) => eprintln!(
            "Capturing on {label} for {}; Ctrl-C stops it sooner",
            plain_duration(d)
        ),
        None => eprintln!("Capturing on {label}; Ctrl-C stops it"),
    }
    let progress = io::stderr().is_terminal();
    let mut shown = started;
    let mut stats = Stats::default();
    let mut analyzer = Analyzer::new();
    let mut packets = 0u64;
    while !stop.load(Ordering::SeqCst)
        && deadline.is_none_or(|d| Instant::now() < d)
        && args.count.is_none_or(|c| packets < c)
    {
        if let Some(frame) = capture.next_frame()? {
            if let Some(file) = &mut file {
                file.write(&frame).context("cannot save the capture")?;
            }
            let pkt = decode::decode(&frame);
            analyzer.observe(&frame, &pkt);
            stats.add(&frame, &pkt);
            packets += 1;
        }
        if progress && shown.elapsed() >= Duration::from_secs(1) {
            eprint!("\r{} so far ", text::plural(packets, "packet", "packets"));
            shown = Instant::now();
        }
    }
    if progress {
        eprint!("\r{:30}\r", "");
    }
    let dropped = capture.dropped();
    drop(capture);
    if let Some(file) = &mut file {
        file.flush().context("cannot save the capture")?;
    }

    let info = CaptureInfo {
        cut_off_after: None,
        dropped,
    };
    let diagnosis = diagnose::diagnose(&stats, &analyzer, info);
    let name = match &args.write {
        Some(path) => path.display().to_string(),
        None => format!("{label} (live)"),
    };
    show_report(&name, &diagnosis, &args.output)?;
    if args.write.is_none() && !diagnosis.findings.is_empty() {
        eprintln!(
            "note: -w FILE saves the packets, so the frames above can be opened in Wireshark"
        );
    }
    Ok(())
}

/// "30 s" for whole seconds, as people type them.
fn plain_duration(d: Duration) -> String {
    match d.subsec_nanos() {
        0 => format!("{} s", d.as_secs()),
        _ => units::duration(d.as_secs_f64()),
    }
}

fn interfaces() -> Result<()> {
    use std::fmt::Write as _;
    let list = live::interfaces()?;
    let default = live::default_interface(&list);
    let mut out = format!("{}\n\n", live::library_version()?);
    for (i, iface) in list.iter().enumerate() {
        let _ = write!(out, "{:>2}. {}", i + 1, iface.name);
        if let Some(description) = &iface.description {
            let _ = write!(out, "  {description}");
        }
        if default == Some(i) {
            out.push_str("  (default)");
        }
        out.push('\n');
        let state = [
            (iface.loopback, "loopback"),
            (iface.wireless, "wireless"),
            (!iface.up, "down"),
            (iface.up && !iface.running, "not running"),
            (iface.disconnected, "disconnected"),
        ];
        let mut notes: Vec<String> = state
            .iter()
            .filter(|(on, _)| *on)
            .map(|(_, word)| word.to_string())
            .collect();
        let addresses: Vec<String> = iface.addresses.iter().map(|a| a.to_string()).collect();
        if !addresses.is_empty() {
            notes.push(addresses.join(", "));
        }
        if !notes.is_empty() {
            let _ = writeln!(out, "    {}", notes.join("; "));
        }
    }
    if list.is_empty() {
        out.push_str("No interfaces found. Listing them may need root, or administrator rights on Windows.\n");
    } else {
        out.push_str("\npacket-cage live -i NAME or -i NUMBER captures on one; without -i it uses the default.\n");
    }
    ignore_broken_pipe(io::stdout().lock().write_all(out.as_bytes()))
}

/// How reading a capture ended.
enum End {
    Complete,
    /// The file stops partway through a packet; `frames` were read before that.
    CutOff {
        frames: u64,
    },
}

impl End {
    fn warn(&self, path: &Path) {
        if let End::CutOff { frames } = self {
            eprintln!(
                "warning: {} ends in the middle of packet {}; it was probably cut off while capturing",
                path.display(),
                frames + 1
            );
        }
    }
}

/// Calls `each` for every packet in the file until it returns `Break`. A file
/// that was cut off mid-packet is not an error: everything before the cut is
/// still worth reading.
fn read_frames(path: &Path, mut each: impl FnMut(Frame) -> Result<ControlFlow<()>>) -> Result<End> {
    let mut capture =
        Capture::open(path).with_context(|| format!("cannot read {}", path.display()))?;
    loop {
        match capture.next_frame() {
            Ok(Some(frame)) => {
                if each(frame)?.is_break() {
                    return Ok(End::Complete);
                }
            }
            Ok(None) => return Ok(End::Complete),
            Err(CaptureError::Truncated) => {
                return Ok(End::CutOff {
                    frames: capture.frames_read(),
                });
            }
            Err(e) => {
                return Err(e).with_context(|| {
                    format!(
                        "{} is unreadable after packet {}",
                        path.display(),
                        capture.frames_read()
                    )
                });
            }
        }
    }
}

/// `packet-cage dump big.pcap | head` closes stdout early; that's not an error.
fn is_broken_pipe(result: &io::Result<()>) -> bool {
    matches!(result, Err(e) if e.kind() == io::ErrorKind::BrokenPipe)
}

fn ignore_broken_pipe(result: io::Result<()>) -> Result<()> {
    if is_broken_pipe(&result) {
        return Ok(());
    }
    Ok(result?)
}
