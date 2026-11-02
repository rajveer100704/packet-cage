//! DNS messages (RFC 1035).
//!
//! Names can point back to earlier names in the message to save space
//! ("compression"). A malicious or broken message can make those pointers
//! loop, so pointers must go backwards and a name may not exceed 255 bytes,
//! which together guarantee the walk ends.

use std::fmt::{self, Write};
use std::net::{Ipv4Addr, Ipv6Addr};

use super::be16;

pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_MX: u16 = 15;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_DNAME: u16 = 39;

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_FORMERR: u8 = 1;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_NOTIMP: u8 = 4;
pub const RCODE_REFUSED: u8 = 5;

const MAX_NAME_LEN: usize = 255;
const MAX_POINTERS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    pub response: bool,
    /// 0 query, 4 notify, 5 update.
    pub opcode: u8,
    pub authoritative: bool,
    /// The response didn't fit in a UDP packet; the client should retry over TCP.
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub rcode: u8,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    /// The authority and additional sections, as far as they could be read.
    /// Damage there isn't an error: the answers are what matter.
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
    /// Answer count from the header. More than `answers.len()` when the
    /// answers are damaged or were cut off by the capture.
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
    /// Set when the answer section is damaged; the header and questions are
    /// still usable.
    pub error: Option<DnsError>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: RData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    /// CNAME, NS, PTR and DNAME all hold a single name.
    Name(String),
    Mx {
        preference: u16,
        exchange: String,
    },
    Other {
        len: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsError(pub String);

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed DNS: {}", self.0)
    }
}

impl std::error::Error for DnsError {}

fn error(msg: impl Into<String>) -> DnsError {
    DnsError(msg.into())
}

/// Parses one message. Fails if the header or questions are damaged; damage
/// in the answers is reported in `Message::error` instead.
pub fn parse(data: &[u8]) -> Result<Message, DnsError> {
    match parse_parts(data)? {
        (msg, None) => Ok(msg),
        (_, Some(question_error)) => Err(question_error),
    }
}

/// For a message the capture cut short: keeps whatever came before the cut,
/// with the damage in `Message::error`. Needs at least the 12-byte header.
pub fn parse_partial(data: &[u8]) -> Option<Message> {
    let (mut msg, question_error) = parse_parts(data).ok()?;
    if question_error.is_some() {
        msg.error = question_error;
    }
    Some(msg)
}

/// Parses the header (or fails), then as many questions and answers as
/// possible. Returns the error that stopped the questions, if any.
fn parse_parts(data: &[u8]) -> Result<(Message, Option<DnsError>), DnsError> {
    if data.len() < 12 {
        return Err(error(format!(
            "{} bytes is shorter than the 12-byte header",
            data.len()
        )));
    }
    let flags = be16(data, 2);
    let mut msg = Message {
        id: be16(data, 0),
        response: flags & 0x8000 != 0,
        opcode: ((flags >> 11) & 0x0f) as u8,
        authoritative: flags & 0x0400 != 0,
        truncated: flags & 0x0200 != 0,
        recursion_desired: flags & 0x0100 != 0,
        recursion_available: flags & 0x0080 != 0,
        rcode: (flags & 0x000f) as u8,
        questions: Vec::new(),
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
        answer_count: be16(data, 6),
        authority_count: be16(data, 8),
        additional_count: be16(data, 10),
        error: None,
    };
    let mut pos = 12;
    for _ in 0..be16(data, 4) {
        match read_question(data, pos) {
            Ok((question, next)) => {
                msg.questions.push(question);
                pos = next;
            }
            Err(e) => return Ok((msg, Some(e))),
        }
    }
    for _ in 0..msg.answer_count {
        match read_record(data, pos) {
            Ok((record, next)) => {
                msg.answers.push(record);
                pos = next;
            }
            Err(e) => {
                msg.error = Some(e);
                return Ok((msg, None));
            }
        }
    }
    let sections = [
        (msg.authority_count, &mut msg.authorities),
        (msg.additional_count, &mut msg.additionals),
    ];
    'sections: for (count, records) in sections {
        for _ in 0..count {
            match read_record(data, pos) {
                Ok((record, next)) => {
                    records.push(record);
                    pos = next;
                }
                Err(_) => break 'sections,
            }
        }
    }
    Ok((msg, None))
}

fn read_question(data: &[u8], pos: usize) -> Result<(Question, usize), DnsError> {
    let (name, next) = read_name(data, pos)?;
    let fixed = data
        .get(next..next + 4)
        .ok_or_else(|| error("question ends early"))?;
    let question = Question {
        name,
        qtype: be16(fixed, 0),
        qclass: be16(fixed, 2),
    };
    Ok((question, next + 4))
}

fn read_record(data: &[u8], pos: usize) -> Result<(Record, usize), DnsError> {
    let (name, next) = read_name(data, pos)?;
    let fixed = data
        .get(next..next + 10)
        .ok_or_else(|| error("record header ends early"))?;
    let rtype = be16(fixed, 0);
    let len = usize::from(be16(fixed, 8));
    let start = next + 10;
    let rdata = data
        .get(start..start + len)
        .ok_or_else(|| error(format!("record data claims {len} bytes past the end")))?;
    let parsed = match (rtype, len) {
        (TYPE_A, 4) => RData::A(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
        (TYPE_AAAA, 16) => RData::Aaaa(Ipv6Addr::from(<[u8; 16]>::try_from(rdata).unwrap())),
        (TYPE_CNAME | TYPE_NS | TYPE_PTR | TYPE_DNAME, _) => RData::Name(read_name(data, start)?.0),
        (TYPE_MX, 3..) => RData::Mx {
            preference: be16(rdata, 0),
            exchange: read_name(data, start + 2)?.0,
        },
        _ => RData::Other { len },
    };
    let record = Record {
        name,
        rtype,
        class: be16(fixed, 2),
        ttl: u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]),
        data: parsed,
    };
    Ok((record, start + len))
}

/// Reads the name at `pos`. Returns it in presentation form ("www.example.com",
/// "." for the root) and the position just after it in the message.
fn read_name(data: &[u8], mut pos: usize) -> Result<(String, usize), DnsError> {
    let mut name = String::new();
    let mut wire_len = 0;
    let mut after = None;
    let mut pointers = 0;
    loop {
        let len = usize::from(
            *data
                .get(pos)
                .ok_or_else(|| error("name runs past the end"))?,
        );
        match len & 0xc0 {
            0x00 if len == 0 => {
                pos += 1;
                break;
            }
            0x00 => {
                let label = data
                    .get(pos + 1..pos + 1 + len)
                    .ok_or_else(|| error("label runs past the end"))?;
                wire_len += len + 1;
                if wire_len > MAX_NAME_LEN {
                    return Err(error("name longer than 255 bytes"));
                }
                if !name.is_empty() {
                    name.push('.');
                }
                push_label(&mut name, label);
                pos += 1 + len;
            }
            0xc0 => {
                let low = *data
                    .get(pos + 1)
                    .ok_or_else(|| error("pointer runs past the end"))?;
                let target = ((len & 0x3f) << 8) | usize::from(low);
                if target >= pos {
                    return Err(error("compression pointer does not point backwards"));
                }
                pointers += 1;
                if pointers > MAX_POINTERS {
                    return Err(error("too many compression pointers"));
                }
                after.get_or_insert(pos + 2);
                pos = target;
            }
            _ => return Err(error(format!("unknown label type {:#04x}", len & 0xc0))),
        }
    }
    if name.is_empty() {
        name.push('.');
    }
    Ok((name, after.unwrap_or(pos)))
}

/// Appends a label, escaping dots, backslashes and unprintable bytes the way
/// dig does.
fn push_label(name: &mut String, label: &[u8]) {
    for &b in label {
        match b {
            b'.' | b'\\' => {
                name.push('\\');
                name.push(char::from(b));
            }
            0x21..=0x7e => name.push(char::from(b)),
            _ => {
                let _ = write!(name, "\\{b:03}");
            }
        }
    }
}

pub fn type_name(rtype: u16) -> String {
    let name = match rtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        13 => "HINFO",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        35 => "NAPTR",
        39 => "DNAME",
        41 => "OPT",
        43 => "DS",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        64 => "SVCB",
        65 => "HTTPS",
        252 => "AXFR",
        255 => "ANY",
        257 => "CAA",
        t => return format!("TYPE{t}"),
    };
    name.to_string()
}

/// How a response code reads in a report.
pub fn rcode_text(rcode: u8) -> String {
    let text = match rcode {
        RCODE_NOERROR => "no error",
        RCODE_FORMERR => "format error",
        RCODE_SERVFAIL => "server failure",
        RCODE_NXDOMAIN => "no such name",
        RCODE_NOTIMP => "not implemented",
        RCODE_REFUSED => "refused",
        6 => "name exists when it should not",
        7 => "record set exists when it should not",
        8 => "record set does not exist",
        9 => "not authoritative",
        10 => "name not in zone",
        r => return format!("error code {r}"),
    };
    text.to_string()
}

impl fmt::Display for RData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RData::A(ip) => write!(f, "{ip}"),
            RData::Aaaa(ip) => write!(f, "{ip}"),
            RData::Name(name) => f.write_str(name),
            RData::Mx {
                preference,
                exchange,
            } => write!(f, "{preference} {exchange}"),
            RData::Other { len } => write!(f, "<{len} bytes>"),
        }
    }
}

impl Message {
    /// One line for `dump`: "query 0x1a2b A example.com" or
    /// "response 0x1a2b A example.com → A 93.184.216.34".
    pub fn summary(&self) -> String {
        self.headline() + &self.notes()
    }

    /// The summary without the bracketed notes.
    pub fn headline(&self) -> String {
        let kind = match self.opcode {
            0 => "",
            4 => "notify ",
            5 => "update ",
            op => return format!("opcode {op} 0x{:04x}", self.id),
        };
        let mut s = format!(
            "{kind}{} 0x{:04x}",
            if self.response { "response" } else { "query" },
            self.id
        );
        for q in &self.questions {
            let _ = write!(s, " {} {}", type_name(q.qtype), q.name);
        }
        if self.response {
            if self.rcode != RCODE_NOERROR {
                let _ = write!(s, " → {}", rcode_text(self.rcode));
            } else if !self.answers.is_empty() {
                let shown: Vec<String> = self
                    .answers
                    .iter()
                    .take(4)
                    .map(|r| format!("{} {}", type_name(r.rtype), r.data))
                    .collect();
                let _ = write!(s, " → {}", shown.join(", "));
                if self.answers.len() > 4 {
                    let _ = write!(s, " (+{} more)", self.answers.len() - 4);
                }
            } else if self.error.is_none() {
                s.push_str(" → no records");
            }
        }
        s
    }

    /// " [truncated]", " [malformed DNS: ...]", or nothing.
    pub fn notes(&self) -> String {
        let mut s = String::new();
        if self.truncated {
            s.push_str(" [truncated]");
        }
        if let Some(err) = &self.error {
            let _ = write!(s, " [{err}]");
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A response for www.example.com: CNAME to web.example.com, then an A
    /// record, with the answer names compressed.
    fn sample() -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0];
        m.extend(b"\x03www\x07example\x03com\x00\x00\x01\x00\x01");
        // www.example.com (pointer to 12) CNAME web + pointer to example.com (16)
        m.extend([0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 6]);
        m.extend(b"\x03web\xc0\x10");
        // web.example.com (pointer to the CNAME data at 45) A 93.184.216.34
        m.extend([0xc0, 45, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        m
    }

    #[test]
    fn parses_compressed_response() {
        let msg = parse(&sample()).unwrap();
        assert_eq!((msg.id, msg.response, msg.rcode), (0x1234, true, 0));
        assert_eq!(msg.questions[0].name, "www.example.com");
        assert_eq!(msg.answers[0].data, RData::Name("web.example.com".into()));
        assert_eq!(msg.answers[1].name, "web.example.com");
        assert_eq!(
            msg.answers[1].data,
            RData::A(Ipv4Addr::new(93, 184, 216, 34))
        );
        assert_eq!(msg.error, None);
        assert_eq!(
            msg.summary(),
            "response 0x1234 A www.example.com → CNAME web.example.com, A 93.184.216.34"
        );
    }

    #[test]
    fn pointer_loops_and_forward_pointers_are_rejected() {
        // The CNAME data is "web" (offset 45) then a pointer (offset 49).
        // Pointing it back at 45 makes the name repeat forever.
        let mut looped = sample();
        looped[50] = 45;
        let msg = parse(&looped).unwrap();
        assert!(msg.answers.is_empty());
        assert!(msg.error.is_some());

        let mut to_itself = sample();
        to_itself[50] = 49;
        assert!(
            parse(&to_itself)
                .unwrap()
                .error
                .unwrap()
                .0
                .contains("backwards")
        );

        let mut forward = vec![0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        forward.extend([0xc0, 20, 0, 1, 0, 1]);
        assert!(parse(&forward).unwrap_err().0.contains("backwards"));
    }

    #[test]
    fn root_name_and_escapes() {
        let mut m = vec![0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0];
        m.extend([0, 0, 2, 0, 1]);
        m.extend(b"\x04a.b\x01\x00\x00\x01\x00\x01");
        let msg = parse(&m).unwrap();
        assert_eq!(msg.questions[0].name, ".");
        assert_eq!(msg.questions[1].name, "a\\.b\\001");
    }

    #[test]
    fn short_or_cut_messages() {
        assert!(parse(&[0; 11]).is_err());
        let full = sample();
        assert!(parse(&full[..20]).is_err());
        // Cut inside the answers: questions survive.
        let msg = parse(&full[..50]).unwrap();
        assert_eq!(msg.questions.len(), 1);
        assert!(msg.error.is_some());
    }

    #[test]
    fn overlong_names_are_rejected() {
        let mut m = vec![0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for _ in 0..5 {
            m.push(63);
            m.extend([b'a'; 63]);
        }
        m.extend([0, 0, 1, 0, 1]);
        assert!(parse(&m).unwrap_err().0.contains("255"));
    }
}
