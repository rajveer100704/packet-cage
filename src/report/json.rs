//! The report as JSON, for scripts and CI. `schema` goes up whenever a
//! field changes meaning or goes away; new fields may appear at any time.
//!
//! ```text
//! { "schema": 1, "file", "capture": {...}, "summary": {...},
//!   "findings": [{ "severity", "category", "subject", "text", "hint",
//!                  "frames": [[first, last], ...], "filter",
//!                  "measurements": { name: number } }] }
//! ```

use std::fmt::Write;

use crate::diagnose::{Diagnosis, Finding, Severity};
use crate::units;

pub const SCHEMA: u32 = 1;

pub fn render(file: &str, diagnosis: &Diagnosis) -> String {
    let o = &diagnosis.overview;
    let capture = Json::Object(vec![
        ("packets", Json::Int(o.packets)),
        ("bytes", Json::Int(o.bytes)),
        (
            "start",
            o.start
                .map_or(Json::Null, |ts| Json::String(units::rfc3339(ts))),
        ),
        ("duration_secs", Json::Number(o.duration_secs)),
        (
            "cut_off_after",
            o.cut_off_after.map_or(Json::Null, Json::Int),
        ),
        ("dropped", o.dropped.map_or(Json::Null, Json::Int)),
    ]);
    let summary = Json::Object(vec![
        ("errors", count(diagnosis.count(Severity::Error))),
        ("warnings", count(diagnosis.count(Severity::Warning))),
        ("info", count(diagnosis.count(Severity::Info))),
        ("connections", count(o.connections)),
        ("healthy_connections", count(o.healthy_connections)),
        ("dns_lookups", count(o.dns_lookups)),
        ("tls_handshakes", count(o.tls_handshakes)),
        ("http_requests", count(o.http_requests)),
    ]);
    let root = Json::Object(vec![
        ("schema", Json::Int(u64::from(SCHEMA))),
        (
            "tool",
            Json::Object(vec![
                ("name", Json::String("packet-cage".to_string())),
                (
                    "version",
                    Json::String(env!("CARGO_PKG_VERSION").to_string()),
                ),
            ]),
        ),
        ("file", Json::String(file.to_string())),
        ("capture", capture),
        ("summary", summary),
        (
            "findings",
            Json::Array(diagnosis.findings.iter().map(finding).collect()),
        ),
    ]);
    let mut out = String::new();
    root.write(&mut out, 0);
    out.push('\n');
    out
}

fn finding(f: &Finding) -> Json {
    let text = |s: &Option<String>| s.clone().map_or(Json::Null, Json::String);
    Json::Object(vec![
        ("severity", Json::String(f.severity.name().to_string())),
        ("category", Json::String(f.category.id().to_string())),
        ("subject", Json::String(f.subject.clone())),
        ("text", Json::String(f.text.clone())),
        ("hint", text(&f.hint)),
        (
            "frames",
            Json::Array(
                f.frames
                    .iter()
                    .map(|s| Json::Array(vec![Json::Int(s.first), Json::Int(s.last)]))
                    .collect(),
            ),
        ),
        ("filter", text(&f.filter)),
        (
            "measurements",
            Json::Object(
                f.measurements
                    .iter()
                    .map(|m| (m.name, Json::Number(m.value)))
                    .collect(),
            ),
        ),
    ])
}

fn count(n: usize) -> Json {
    Json::Int(n as u64)
}

enum Json {
    Null,
    Int(u64),
    Number(f64),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(&'static str, Json)>),
}

impl Json {
    /// Pretty-printed, two spaces per level. Arrays of plain values stay on
    /// one line.
    fn write(&self, out: &mut String, depth: usize) {
        let indent = |out: &mut String, depth: usize| out.push_str(&"  ".repeat(depth));
        match self {
            Json::Null => out.push_str("null"),
            Json::Int(n) => {
                let _ = write!(out, "{n}");
            }
            Json::Number(x) if x.is_finite() => {
                // Rounded to what any reader needs; avoids 0.30000000000000004.
                let rounded = (x * 1e6).round() / 1e6;
                let _ = write!(out, "{rounded}");
            }
            Json::Number(_) => out.push_str("null"),
            Json::String(s) => string(out, s),
            Json::Array(items) if items.is_empty() => out.push_str("[]"),
            Json::Array(items) if items.iter().all(Json::is_flat) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    item.write(out, depth);
                }
                out.push(']');
            }
            Json::Array(items) => {
                out.push_str("[\n");
                for (i, item) in items.iter().enumerate() {
                    indent(out, depth + 1);
                    item.write(out, depth + 1);
                    out.push_str(if i + 1 < items.len() { ",\n" } else { "\n" });
                }
                indent(out, depth);
                out.push(']');
            }
            Json::Object(fields) if fields.is_empty() => out.push_str("{}"),
            Json::Object(fields) => {
                out.push_str("{\n");
                for (i, (key, value)) in fields.iter().enumerate() {
                    indent(out, depth + 1);
                    string(out, key);
                    out.push_str(": ");
                    value.write(out, depth + 1);
                    out.push_str(if i + 1 < fields.len() { ",\n" } else { "\n" });
                }
                indent(out, depth);
                out.push('}');
            }
        }
    }

    /// Short enough to print inline: not an object, and holding no objects.
    fn is_flat(&self) -> bool {
        match self {
            Json::Object(_) => false,
            Json::Array(items) => items.iter().all(Json::is_flat),
            _ => true,
        }
    }
}

fn string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_are_escaped() {
        let mut out = String::new();
        string(&mut out, "a\"b\\c\nd\u{1}é");
        assert_eq!(out, r#""a\"b\\c\nd\u0001é""#);
    }

    #[test]
    fn layout() {
        let mut out = String::new();
        Json::Object(vec![
            (
                "a",
                Json::Array(vec![Json::Int(1), Json::Number(0.1 + 0.2)]),
            ),
            ("b", Json::Object(vec![])),
            ("c", Json::Number(f64::NAN)),
        ])
        .write(&mut out, 0);
        assert_eq!(out, "{\n  \"a\": [1, 0.3],\n  \"b\": {},\n  \"c\": null\n}");
    }
}
