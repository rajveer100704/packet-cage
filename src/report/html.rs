//! The report as one self-contained HTML file, to attach to a ticket or send
//! to someone without packet-cage. No scripts, no external resources.

use std::fmt::Write;

use crate::diagnose::{Diagnosis, Finding, Measurement, Severity};
use crate::units;

const STYLE: &str = r#"
:root {
  --bg: #f7f7f5; --card: #ffffff; --text: #1d1d1b; --muted: #6b6b66; --line: #e3e3de;
  --error: #c62828; --warning: #b26a00; --info: #1565c0; --ok: #2e7d32; --code: #f0f0ec;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #161615; --card: #1f1f1d; --text: #ecece8; --muted: #a3a39c; --line: #34342f;
    --error: #ef6f6c; --warning: #f0b14a; --info: #6aa9f0; --ok: #6cc070; --code: #2a2a27;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main { max-width: 960px; margin: 0 auto; padding: 32px 16px 48px; }
h1 { font-size: 22px; margin: 0 0 4px; word-break: break-all; }
.meta { color: var(--muted); margin: 0 0 20px; }
.chips { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 24px; }
.chip { background: var(--card); border: 1px solid var(--line); border-radius: 999px;
  padding: 4px 12px; font-size: 14px; }
.chip b { font-variant-numeric: tabular-nums; }
.chip.error b { color: var(--error); } .chip.warning b { color: var(--warning); }
.chip.info b { color: var(--info); } .chip.ok b { color: var(--ok); }
.finding { background: var(--card); border: 1px solid var(--line); border-left: 4px solid var(--muted);
  border-radius: 8px; padding: 12px 16px; margin-bottom: 12px; }
.finding.error { border-left-color: var(--error); }
.finding.warning { border-left-color: var(--warning); }
.finding.info { border-left-color: var(--info); }
.head { display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap; }
.tag { font-size: 12px; font-weight: 700; letter-spacing: .04em; padding: 1px 6px; border-radius: 4px;
  color: var(--card); background: var(--muted); }
.error .tag { background: var(--error); } .warning .tag { background: var(--warning); }
.info .tag { background: var(--info); }
.subject { font-weight: 600; word-break: break-all; }
.hint { color: var(--muted); margin-top: 4px; }
dl { display: grid; grid-template-columns: max-content 1fr; gap: 2px 12px; margin: 10px 0 0; font-size: 14px; }
dt { color: var(--muted); } dd { margin: 0; min-width: 0; }
code { background: var(--code); padding: 1px 6px; border-radius: 4px; font-size: 13px;
  font-family: ui-monospace, SFMono-Regular, Consolas, monospace; word-break: break-all; }
.healthy { color: var(--ok); font-weight: 600; margin-top: 20px; }
footer { color: var(--muted); font-size: 13px; margin-top: 32px; }
"#;

pub fn render(file: &str, diagnosis: &Diagnosis) -> String {
    let o = &diagnosis.overview;
    let mut out = String::new();
    let _ = write!(
        out,
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>packet-cage: {}</title>\n<style>{STYLE}</style>\n</head>\n<body>\n<main>\n",
        escape(file)
    );
    let _ = writeln!(out, "<h1>{}</h1>", escape(file));
    let meta = match o.start {
        Some(start) => format!(
            "{} packets, {}, over {} from {}",
            units::count(o.packets),
            units::bytes(o.bytes),
            units::duration(o.duration_secs),
            units::utc(start)
        ),
        None => "no packets".to_string(),
    };
    let _ = writeln!(out, "<p class=\"meta\">{}</p>", escape(&meta));

    out.push_str("<div class=\"chips\">\n");
    for (class, n, one, many) in [
        ("error", diagnosis.count(Severity::Error), "error", "errors"),
        (
            "warning",
            diagnosis.count(Severity::Warning),
            "warning",
            "warnings",
        ),
        ("info", diagnosis.count(Severity::Info), "note", "notes"),
        (
            "ok",
            o.healthy_connections,
            "healthy connection",
            "healthy connections",
        ),
        ("", o.connections, "connection", "connections"),
        ("", o.dns_lookups, "DNS lookup", "DNS lookups"),
        ("", o.tls_handshakes, "TLS handshake", "TLS handshakes"),
        ("", o.http_requests, "HTTP request", "HTTP requests"),
    ] {
        if n == 0 && !matches!(class, "error" | "warning") {
            continue;
        }
        let _ = writeln!(
            out,
            "<span class=\"chip{}{class}\"><b>{}</b> {}</span>",
            if class.is_empty() { "" } else { " " },
            units::count(n as u64),
            if n == 1 { one } else { many }
        );
    }
    out.push_str("</div>\n");

    for f in &diagnosis.findings {
        finding(&mut out, f);
    }
    if !diagnosis
        .findings
        .iter()
        .any(|f| f.severity >= Severity::Warning)
    {
        out.push_str("<p class=\"healthy\">✓ No problems found</p>\n");
    }
    let _ = writeln!(
        out,
        "<footer>Made by packet-cage {} from {}. Frame numbers and filters work in Wireshark.</footer>",
        env!("CARGO_PKG_VERSION"),
        escape(file)
    );
    out.push_str("</main>\n</body>\n</html>\n");
    out
}

fn finding(out: &mut String, f: &Finding) {
    let class = f.severity.name();
    let _ = writeln!(out, "<section class=\"finding {class}\">");
    let _ = write!(
        out,
        "<div class=\"head\"><span class=\"tag\">{}</span><span>",
        f.category.name()
    );
    if !f.subject.is_empty() {
        let _ = write!(
            out,
            "<span class=\"subject\">{}</span>: ",
            escape(&f.subject)
        );
    }
    let _ = writeln!(out, "{}</span></div>", escape(&f.text));
    if let Some(hint) = &f.hint {
        let _ = writeln!(out, "<div class=\"hint\">→ {}</div>", escape(hint));
    }
    let mut rows: Vec<(&str, String)> = Vec::new();
    if !f.frames.is_empty() {
        let frames = f.frames_text(usize::MAX);
        let (label, list) = frames.split_once(' ').unwrap_or(("frames", &frames));
        rows.push((
            if label == "frame" { "Frame" } else { "Frames" },
            escape(list),
        ));
    }
    if let Some(filter) = &f.filter {
        rows.push((
            "Wireshark filter",
            format!("<code>{}</code>", escape(filter)),
        ));
    }
    if !f.measurements.is_empty() {
        let values: Vec<String> = f.measurements.iter().map(measurement).collect();
        rows.push(("Measured", escape(&values.join(", "))));
    }
    if !rows.is_empty() {
        out.push_str("<dl>");
        for (name, value) in rows {
            let _ = write!(out, "<dt>{name}</dt><dd>{value}</dd>");
        }
        out.push_str("</dl>\n");
    }
    out.push_str("</section>\n");
}

/// "server: 2.10 s", "retransmission rate: 6.0%", "queries: 3"
fn measurement(m: &Measurement) -> String {
    let (name, value) = if let Some(name) = m.name.strip_suffix("_secs") {
        (name, units::duration(m.value))
    } else if m.name.ends_with("_rate") {
        (m.name, format!("{:.1}%", m.value * 100.0))
    } else {
        (m.name, units::count(m.value.max(0.0) as u64))
    };
    format!("{}: {value}", name.replace('_', " ").replace("rtt", "RTT"))
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_markup() {
        assert_eq!(
            escape("<a href=\"x\">'&'</a>"),
            "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;"
        );
    }

    #[test]
    fn measurements_read_naturally() {
        let m = |name, value| measurement(&Measurement { name, value });
        assert_eq!(m("server_secs", 2.1), "server: 2.10 s");
        assert_eq!(m("retransmission_rate", 0.06), "retransmission rate: 6.0%");
        assert_eq!(m("queries", 3.0), "queries: 3");
    }
}
