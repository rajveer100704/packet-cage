//! Just enough X.509 (RFC 5280) to check a server certificate: whom it is
//! for, who issued it and when it is valid.
//!
//! Certificates are DER: nested tag-length-value items. Every length is
//! checked against what is left, so a damaged certificate gives an error
//! rather than a panic.

use std::fmt;

use crate::units;

const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const INTEGER: u8 = 0x02;
const BOOLEAN: u8 = 0x01;
const OCTET_STRING: u8 = 0x04;
const OID: u8 = 0x06;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
const BMP_STRING: u8 = 0x1e;
/// [0] holding the version, [3] holding the extensions.
const VERSION: u8 = 0xa0;
const EXTENSIONS: u8 = 0xa3;
/// dNSName inside a subject alternative name.
const DNS_NAME: u8 = 0x82;

const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
const OID_ORGANIZATION: &[u8] = &[0x55, 0x04, 0x0a];
const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509Error(pub String);

impl fmt::Display for X509Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed certificate: {}", self.0)
    }
}

impl std::error::Error for X509Error {}

fn error(msg: impl Into<String>) -> X509Error {
    X509Error(msg.into())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub subject: Name,
    pub issuer: Name,
    /// Validity period, in seconds since the Unix epoch.
    pub not_before: i64,
    pub not_after: i64,
    /// DNS names from the subject alternative name extension.
    pub dns_names: Vec<String>,
    /// Subject and issuer are identical: nobody else vouches for it.
    pub self_issued: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Name {
    pub common_name: Option<String>,
    pub organization: Option<String>,
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.common_name, &self.organization) {
            (Some(cn), Some(o)) => write!(f, "CN={cn}, O={o}"),
            (Some(cn), None) => write!(f, "CN={cn}"),
            (None, Some(o)) => write!(f, "O={o}"),
            (None, None) => f.write_str("(no name)"),
        }
    }
}

impl Certificate {
    /// Whether the certificate covers `host` (RFC 6125): its subject
    /// alternative names if it has any, otherwise its common name. A "*" is
    /// allowed only as the whole leftmost label and stands for exactly one.
    pub fn matches_host(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let patterns: Vec<&String> = if self.dns_names.is_empty() {
            self.subject.common_name.iter().collect()
        } else {
            self.dns_names.iter().collect()
        };
        patterns
            .iter()
            .any(|p| name_matches(&p.trim_end_matches('.').to_ascii_lowercase(), &host))
    }

    /// The names it is valid for, for messages: "a.example.com, *.example.com".
    pub fn names(&self) -> String {
        if self.dns_names.is_empty() {
            return self
                .subject
                .common_name
                .clone()
                .unwrap_or_else(|| "(no name)".to_string());
        }
        let shown: Vec<&str> = self.dns_names.iter().take(3).map(String::as_str).collect();
        let more = self.dns_names.len().saturating_sub(3);
        if more > 0 {
            format!("{} and {more} more", shown.join(", "))
        } else {
            shown.join(", ")
        }
    }
}

fn name_matches(pattern: &str, host: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(rest) => host
            .split_once('.')
            .is_some_and(|(first, tail)| !first.is_empty() && tail == rest),
        None => pattern == host,
    }
}

pub fn parse(der: &[u8]) -> Result<Certificate, X509Error> {
    let certificate = Der::new(der).expect(SEQUENCE, "certificate")?;
    let mut tbs = Der::new(Der::new(certificate).expect(SEQUENCE, "certificate body")?);
    if tbs.peek() == Some(VERSION) {
        tbs.next()?;
    }
    tbs.expect(INTEGER, "serial number")?;
    tbs.expect(SEQUENCE, "signature algorithm")?;
    let issuer = tbs.expect(SEQUENCE, "issuer")?;
    let mut validity = Der::new(tbs.expect(SEQUENCE, "validity")?);
    let subject = tbs.expect(SEQUENCE, "subject")?;
    tbs.expect(SEQUENCE, "public key")?;
    let mut dns_names = Vec::new();
    while !tbs.is_empty() {
        let (tag, contents) = tbs.next()?;
        if tag == EXTENSIONS {
            dns_names = subject_alt_names(contents)?;
        }
    }
    Ok(Certificate {
        subject: name(subject)?,
        issuer: name(issuer)?,
        not_before: time(validity.next()?)?,
        not_after: time(validity.next()?)?,
        dns_names,
        self_issued: issuer == subject,
    })
}

fn name(der: &[u8]) -> Result<Name, X509Error> {
    let mut out = Name::default();
    let mut parts = Der::new(der);
    while !parts.is_empty() {
        let mut attributes = Der::new(parts.expect(SET, "name part")?);
        while !attributes.is_empty() {
            let mut attribute = Der::new(attributes.expect(SEQUENCE, "name attribute")?);
            let oid = attribute.expect(OID, "attribute type")?;
            let (tag, value) = attribute.next()?;
            match oid {
                OID_COMMON_NAME => out.common_name = Some(text(tag, value)),
                OID_ORGANIZATION => out.organization = Some(text(tag, value)),
                _ => {}
            }
        }
    }
    Ok(out)
}

fn subject_alt_names(extensions: &[u8]) -> Result<Vec<String>, X509Error> {
    let mut names = Vec::new();
    let mut list = Der::new(Der::new(extensions).expect(SEQUENCE, "extensions")?);
    while !list.is_empty() {
        let mut extension = Der::new(list.expect(SEQUENCE, "extension")?);
        let oid = extension.expect(OID, "extension type")?;
        let (mut tag, mut value) = extension.next()?;
        if tag == BOOLEAN {
            (tag, value) = extension.next()?; // the "critical" flag
        }
        if oid != OID_SUBJECT_ALT_NAME || tag != OCTET_STRING {
            continue;
        }
        let mut general_names = Der::new(Der::new(value).expect(SEQUENCE, "alternative names")?);
        while !general_names.is_empty() {
            let (tag, value) = general_names.next()?;
            if tag == DNS_NAME {
                names.push(text(tag, value));
            }
        }
    }
    Ok(names)
}

/// UTCTime "YYMMDDHHMMSSZ" or GeneralizedTime "YYYYMMDDHHMMSSZ", as seconds
/// since the Unix epoch.
fn time((tag, value): (u8, &[u8])) -> Result<i64, X509Error> {
    let digits = |s: &[u8]| -> Result<i64, X509Error> {
        s.iter().try_fold(0i64, |acc, b| {
            b.is_ascii_digit()
                .then(|| acc * 10 + i64::from(b - b'0'))
                .ok_or_else(|| error("time has a non-digit"))
        })
    };
    let (year, rest) = match (tag, value.len()) {
        (UTC_TIME, 13) => {
            // Two-digit years: 50-99 are 1950-1999, 00-49 are 2000-2049.
            let yy = digits(&value[..2])?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &value[2..])
        }
        (GENERALIZED_TIME, 15) => (digits(&value[..4])?, &value[4..]),
        _ => return Err(error("validity time is not in a supported format")),
    };
    if rest[10] != b'Z' {
        return Err(error("validity time is not in UTC"));
    }
    let month = digits(&rest[0..2])?;
    let day = digits(&rest[2..4])?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(error("validity date is out of range"));
    }
    let days = units::days_from_civil(year, month as u32, day as u32);
    Ok(days * 86_400
        + digits(&rest[4..6])? * 3600
        + digits(&rest[6..8])? * 60
        + digits(&rest[8..10])?)
}

/// Decodes a directory string. BMPString is UTF-16; the others in use are
/// ASCII or UTF-8.
fn text(tag: u8, value: &[u8]) -> String {
    let decoded = if tag == BMP_STRING {
        let (units, _) = value.as_chunks::<2>();
        String::from_utf16_lossy(
            &units
                .iter()
                .map(|u| u16::from_be_bytes(*u))
                .collect::<Vec<_>>(),
        )
    } else {
        String::from_utf8_lossy(value).into_owned()
    };
    decoded
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// Reads DER items one after another.
struct Der<'a> {
    data: &'a [u8],
}

impl<'a> Der<'a> {
    fn new(data: &'a [u8]) -> Self {
        Der { data }
    }

    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    fn peek(&self) -> Option<u8> {
        self.data.first().copied()
    }

    /// The next item's tag and contents.
    fn next(&mut self) -> Result<(u8, &'a [u8]), X509Error> {
        let [tag, first, ..] = *self.data else {
            return Err(error("item ends early"));
        };
        if tag & 0x1f == 0x1f {
            return Err(error("multi-byte tags are not supported"));
        }
        let (len, header) = match first {
            0..=0x7f => (usize::from(first), 2),
            0x81..=0x84 => {
                let n = usize::from(first & 0x7f);
                let bytes = self
                    .data
                    .get(2..2 + n)
                    .ok_or_else(|| error("length ends early"))?;
                let len = bytes
                    .iter()
                    .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
                (len, 2 + n)
            }
            _ => return Err(error("unsupported length encoding")),
        };
        let contents = header
            .checked_add(len)
            .and_then(|end| self.data.get(header..end))
            .ok_or_else(|| error("item runs past the end"))?;
        self.data = &self.data[header + len..];
        Ok((tag, contents))
    }

    fn expect(&mut self, tag: u8, what: &str) -> Result<&'a [u8], X509Error> {
        match self.next()? {
            (t, contents) if t == tag => Ok(contents),
            (t, _) => Err(error(format!("expected {what}, found tag {t:#04x}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert(dns_names: &[&str], cn: Option<&str>) -> Certificate {
        Certificate {
            subject: Name {
                common_name: cn.map(String::from),
                organization: None,
            },
            issuer: Name::default(),
            not_before: 0,
            not_after: 0,
            dns_names: dns_names.iter().map(|s| s.to_string()).collect(),
            self_issued: false,
        }
    }

    #[test]
    fn host_matching() {
        let c = cert(&["example.com", "*.example.com"], Some("ignored.test"));
        assert!(c.matches_host("example.com"));
        assert!(c.matches_host("API.Example.com."));
        assert!(!c.matches_host("a.b.example.com"));
        assert!(!c.matches_host("ignored.test"));
        assert!(!c.matches_host("badexample.com"));
        // No alternative names: fall back to the common name.
        assert!(cert(&[], Some("legacy.test")).matches_host("legacy.test"));
    }

    #[test]
    fn times() {
        assert_eq!(time((UTC_TIME, b"700101000000Z")), Ok(0));
        assert_eq!(time((UTC_TIME, b"491231235959Z")), Ok(2_524_607_999));
        assert_eq!(
            time((GENERALIZED_TIME, b"20240229120000Z")),
            Ok(1_709_208_000)
        );
        assert!(time((UTC_TIME, b"7001010000Z")).is_err());
        assert!(time((UTC_TIME, b"701301000000Z")).is_err());
    }

    #[test]
    fn garbage_fails_cleanly() {
        assert!(parse(&[]).is_err());
        assert!(parse(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]).is_err());
        assert!(parse(&[0x30, 0x03, 0x30, 0x01]).is_err());
    }
}
