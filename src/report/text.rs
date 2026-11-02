//! The report for a terminal: one line per finding, worst first, with the
//! frames to look at lined up on the right.

use std::fmt::Write;

use anstyle::{AnsiColor, Style};

use crate::diagnose::{Diagnosis, Finding, Severity};
use crate::units;

/// Lines longer than this don't push the frame column further right.
const MAX_ALIGN: usize = 80;
/// Frame spans shown per finding.
const MAX_SPANS: usize = 4;

/// The report, with ANSI colors; strip them for output that isn't a
/// terminal. `max` limits how many findings are shown.
pub fn render(file: &str, diagnosis: &Diagnosis, max: Option<usize>) -> String {
    let o = &diagnosis.overview;
    let dim = Style::new().dimmed();
    let mut out = String::new();
    let _ = write!(out, "{}", file);
    match o.start {
        Some(start) => {
            let _ = writeln!(
                out,
                ": {} over {}, from {}",
                plural(o.packets, "packet", "packets"),
                units::duration(o.duration_secs),
                units::utc(start)
            );
        }
        None => out.push_str(": no packets\n"),
    }
    out.push('\n');

    let shown = &diagnosis.findings[..max.unwrap_or(usize::MAX).min(diagnosis.findings.len())];
    out.push_str(&findings(shown.iter()));
    let hidden = diagnosis.findings.len() - shown.len();
    if hidden > 0 {
        let _ = writeln!(
            out,
            "{}… {} more; --all shows them{}",
            dim.render(),
            plural(hidden as u64, "finding", "findings"),
            dim.render_reset()
        );
    }
    if let Some(line) = healthy_line(diagnosis) {
        let green = Style::new().fg_color(Some(AnsiColor::Green.into()));
        let _ = writeln!(out, "{}✓{} {line}", green.render(), green.render_reset());
    }
    out
}

/// One line per finding, with the frames lined up on the right, and the
/// hint below when there is one.
pub fn findings<'a>(findings: impl Iterator<Item = &'a Finding>) -> String {
    let dim = Style::new().dimmed();
    let findings: Vec<&Finding> = findings.collect();
    let lines: Vec<String> = findings.iter().map(|f| headline(f)).collect();
    let width = lines
        .iter()
        .map(|l| l.chars().count())
        .filter(|&w| w <= MAX_ALIGN)
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    for (finding, line) in findings.iter().zip(&lines) {
        let style = severity_style(finding.severity);
        let (glyph, rest) =
            line.split_at(line.char_indices().nth(1).map_or(line.len(), |(i, _)| i));
        let (category, rest) = rest.split_at(7.min(rest.len()));
        let _ = write!(
            out,
            "{}{glyph}{category}{}{rest}",
            style.render(),
            style.render_reset()
        );
        if !finding.frames.is_empty() {
            let pad = width.saturating_sub(line.chars().count()) + 2;
            let _ = write!(
                out,
                "{}{}{}{}",
                " ".repeat(pad),
                dim.render(),
                finding.frames_text(MAX_SPANS),
                dim.render_reset()
            );
        }
        out.push('\n');
        if let Some(hint) = &finding.hint {
            let _ = writeln!(out, "        → {hint}");
        }
    }
    out
}

/// "✗ DNS    api.internal: name does not exist", without colors.
fn headline(finding: &Finding) -> String {
    let glyph = match finding.severity {
        Severity::Error => '✗',
        Severity::Warning => '⚠',
        Severity::Info => '•',
    };
    let mut line = format!("{glyph} {:<6}", finding.category.name());
    if !finding.subject.is_empty() {
        line.push_str(&finding.subject);
        line.push_str(": ");
    }
    line.push_str(&finding.text);
    line
}

fn severity_style(severity: Severity) -> Style {
    let color = match severity {
        Severity::Error => AnsiColor::Red,
        Severity::Warning => AnsiColor::Yellow,
        Severity::Info => AnsiColor::Cyan,
    };
    Style::new().fg_color(Some(color.into())).bold()
}

/// What looked fine: "214 other connections look healthy".
fn healthy_line(diagnosis: &Diagnosis) -> Option<String> {
    let o = &diagnosis.overview;
    let problems = diagnosis
        .findings
        .iter()
        .any(|f| f.severity >= Severity::Warning);
    if !problems {
        let mut seen = Vec::new();
        if o.connections > 0 {
            seen.push(plural(o.connections as u64, "connection", "connections"));
        }
        if o.dns_lookups > 0 {
            seen.push(plural(o.dns_lookups as u64, "DNS lookup", "DNS lookups"));
        }
        return Some(match seen.as_slice() {
            [] => "No problems found".to_string(),
            _ => format!("No problems found in {}", seen.join(" and ")),
        });
    }
    if o.healthy_connections == 0 {
        return None;
    }
    let other = diagnosis
        .findings
        .iter()
        .any(|f| f.severity >= Severity::Warning && !f.flows.is_empty());
    let n = o.healthy_connections as u64;
    let (one, many) = if other {
        ("other connection", "other connections")
    } else {
        ("connection", "connections")
    };
    let verb = if n == 1 { "looks" } else { "look" };
    Some(format!("{} {verb} healthy", plural(n, one, many)))
}

pub fn plural(n: u64, one: &str, many: &str) -> String {
    format!("{} {}", units::count(n), if n == 1 { one } else { many })
}
