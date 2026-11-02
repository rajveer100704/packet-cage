//! The fields of a finding, for `check --fail-on "finding.severity == error"`.

use std::borrow::Cow;

use super::eval::{Source, Value};
use super::{Field, Kind};
use crate::diagnose::{Finding, MEASUREMENTS};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingField {
    Severity,
    Category,
    Subject,
    Text,
    Hint,
    /// One of the numbers behind a finding, such as `finding.server_secs`.
    Measurement(&'static str),
}

const PREFIX: &str = "finding.";

impl FindingField {
    pub fn all() -> impl Iterator<Item = FindingField> {
        [
            FindingField::Severity,
            FindingField::Category,
            FindingField::Subject,
            FindingField::Text,
            FindingField::Hint,
        ]
        .into_iter()
        .chain(MEASUREMENTS.iter().map(|m| FindingField::Measurement(m)))
    }

    pub fn lookup(name: &str) -> Option<FindingField> {
        let rest = name.strip_prefix(PREFIX)?;
        Some(match rest {
            "severity" => FindingField::Severity,
            "category" => FindingField::Category,
            "subject" => FindingField::Subject,
            "text" => FindingField::Text,
            "hint" => FindingField::Hint,
            _ => FindingField::Measurement(MEASUREMENTS.iter().find(|m| **m == rest)?),
        })
    }

    pub fn name(self) -> String {
        let rest = match self {
            FindingField::Severity => "severity",
            FindingField::Category => "category",
            FindingField::Subject => "subject",
            FindingField::Text => "text",
            FindingField::Hint => "hint",
            FindingField::Measurement(m) => m,
        };
        format!("{PREFIX}{rest}")
    }

    pub fn kind(self) -> Kind {
        match self {
            FindingField::Severity => Kind::Severity,
            FindingField::Category
            | FindingField::Subject
            | FindingField::Text
            | FindingField::Hint => Kind::Str,
            FindingField::Measurement(_) => Kind::Number,
        }
    }

    pub fn help(self) -> &'static str {
        match self {
            FindingField::Severity => "error, warning or info; info < warning < error",
            FindingField::Category => "dns, tcp, loss, slow, tls, http or capture",
            FindingField::Subject => "what it is about: a name, a server or a connection",
            FindingField::Text => "the sentence in the report",
            FindingField::Hint => "what it most likely means, when the report says",
            FindingField::Measurement(m) if m.ends_with("_secs") => "measurement, in seconds",
            FindingField::Measurement(m) if m.ends_with("_rate") => "measurement, from 0 to 1",
            FindingField::Measurement(_) => "measurement, a count",
        }
    }
}

impl Source for Finding {
    fn values(&self, field: Field) -> Vec<Value<'_>> {
        let Field::Finding(field) = field else {
            return Vec::new();
        };
        let text = |s: &str| Value::Str(Cow::Owned(s.to_string()));
        match field {
            FindingField::Severity => vec![Value::Severity(self.severity)],
            FindingField::Category => vec![text(self.category.id())],
            FindingField::Subject => vec![Value::Str(Cow::Borrowed(&self.subject))],
            FindingField::Text => vec![Value::Str(Cow::Borrowed(&self.text))],
            FindingField::Hint => self
                .hint
                .iter()
                .map(|h| Value::Str(Cow::Borrowed(h)))
                .collect(),
            FindingField::Measurement(name) => self
                .measurements
                .iter()
                .filter(|m| m.name == name)
                .map(|m| Value::Number(m.value))
                .collect(),
        }
    }
}
