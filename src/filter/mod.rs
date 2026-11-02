//! Display filters in Wireshark's syntax:
//! `tcp.port == 443 && !(ip.src == 10.0.0.0/8)`.
//!
//! A filter is parsed once. Every field name is looked up and every value is
//! read as the field's type, so a mistake is reported, with its position,
//! before the capture is read. The filter then tests packets (`dump -f`,
//! `check`) or findings (`check --fail-on "finding.severity == error"`).
//!
//! The rules are Wireshark 4.6's, checked with tshark:
//! - A field on its own tests that it is there: `tcp.flags.syn` matches
//!   every TCP packet, `tcp.flags.syn == 1` only SYNs.
//! - A packet can hold a field more than once (`ip.addr` is both addresses).
//!   `==` and the other comparisons match when any occurrence does, `!=` and
//!   `not in` only when every occurrence differs. A field that isn't there
//!   matches no comparison.
//! - `matches` ignores case; `==` and `contains` don't.
//! - `&&` binds tighter than `^^`, and `^^` tighter than `||`.

mod dns;
mod eval;
pub mod fields;
mod finding;
mod lexer;
mod names;
mod packet;
mod parser;

use std::fmt;

pub use eval::{Source, Value};
pub use fields::Kind;
pub use finding::FindingField;
pub use packet::{PacketView, Tracker, Whole};

/// Something a filter can test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Packet(fields::F),
    Finding(FindingField),
}

impl Field {
    pub fn name(self) -> String {
        match self {
            Field::Packet(f) => fields::name(f).to_string(),
            Field::Finding(f) => f.name(),
        }
    }

    pub fn kind(self) -> Kind {
        match self {
            Field::Packet(f) => fields::kind(f),
            Field::Finding(f) => f.kind(),
        }
    }
}

/// What a filter tests: packet fields, or `finding.*` fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Packets,
    Findings,
}

#[derive(Debug, Clone)]
pub struct Filter {
    text: String,
    expr: eval::Expr,
    target: Target,
    whole_capture: bool,
}

impl Filter {
    pub fn parse(text: &str) -> Result<Filter, FilterError> {
        let (expr, fields) = parser::parse(text).map_err(|e| e.in_filter(text))?;
        let packets = fields.iter().any(|f| matches!(f, Field::Packet(_)));
        let findings = fields.iter().any(|f| matches!(f, Field::Finding(_)));
        let target = match (packets, findings) {
            (true, true) => {
                return Err(FilterError::new(
                    "a filter tests packets or findings, not both; use one --fail-on for each",
                    0,
                    text.len(),
                )
                .in_filter(text));
            }
            (false, true) => Target::Findings,
            _ => Target::Packets,
        };
        let whole_capture = fields
            .iter()
            .any(|f| matches!(f, Field::Packet(p) if fields::needs_whole_capture(*p)));
        Ok(Filter {
            text: text.to_string(),
            expr,
            target,
            whole_capture,
        })
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn target(&self) -> Target {
        self.target
    }

    /// Uses a field that depends on later packets (`dns.response_in`), so
    /// the capture has to be read twice.
    pub fn needs_whole_capture(&self) -> bool {
        self.whole_capture
    }

    pub fn matches(&self, source: &dyn Source) -> bool {
        eval::test(&self.expr, source)
    }
}

impl fmt::Display for Filter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// A filter that doesn't parse. Shown with the filter and a mark under the
/// problem, as tshark does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterError {
    pub message: String,
    /// Byte range of the problem in the filter.
    pub start: usize,
    pub end: usize,
    filter: String,
}

impl FilterError {
    fn new(message: impl Into<String>, start: usize, end: usize) -> Self {
        FilterError {
            message: message.into(),
            start,
            end,
            filter: String::new(),
        }
    }

    fn in_filter(mut self, text: &str) -> Self {
        self.filter = text.to_string();
        self
    }
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)?;
        if self.filter.is_empty() {
            return Ok(());
        }
        let before = self.filter[..self.start].chars().count();
        let width = self.filter[self.start..self.end].chars().count().max(1);
        write!(
            f,
            "\n  {}\n  {}^{}",
            self.filter,
            " ".repeat(before),
            "~".repeat(width - 1)
        )
    }
}

impl std::error::Error for FilterError {}

/// Every field a filter can use, for `packet-cage fields`: name, kind and
/// what it holds.
pub fn all_fields() -> impl Iterator<Item = (String, Kind, &'static str)> {
    fields::FIELDS
        .iter()
        .map(|&(_, name, kind, help)| (name.to_string(), kind, help))
        .chain(FindingField::all().map(|f| (f.name(), f.kind(), f.help())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_show_where() {
        let err = Filter::parse("tcp.flags.rst && ip.src == 10.0.0.1").unwrap_err();
        assert_eq!(
            err.to_string(),
            "unknown field \"tcp.flags.rst\"; did you mean \"tcp.flags.reset\"?\n  \
             tcp.flags.rst && ip.src == 10.0.0.1\n  \
             ^~~~~~~~~~~~~"
        );
        let err = Filter::parse("ip.src == 10.0.0.300").unwrap_err();
        assert_eq!(
            err.to_string(),
            "\"10.0.0.300\" isn't an IPv4 address\n  ip.src == 10.0.0.300\n            ^~~~~~~~~~"
        );
    }

    #[test]
    fn packets_or_findings() {
        assert_eq!(Filter::parse("tcp").unwrap().target(), Target::Packets);
        assert_eq!(
            Filter::parse("finding.severity >= warning")
                .unwrap()
                .target(),
            Target::Findings
        );
        assert!(Filter::parse("tcp && finding.severity == error").is_err());
        assert!(
            Filter::parse("dns.response_in")
                .unwrap()
                .needs_whole_capture()
        );
        assert!(
            !Filter::parse("dns.flags.rcode == 3")
                .unwrap()
                .needs_whole_capture()
        );
    }
}
