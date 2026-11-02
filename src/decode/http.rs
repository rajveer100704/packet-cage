//! HTTP/1.x (RFC 9112): request and status lines, and the headers that say
//! where a message's body ends. Bodies themselves are skipped, not kept.

use crate::decode::tls::printable;

/// A message head longer than this is not HTTP we can follow.
pub const MAX_HEAD_LEN: usize = 64 * 1024;
/// Longest chunk-size line accepted in a chunked body.
const MAX_CHUNK_LINE: usize = 1024;

const METHODS: [&str; 9] = [
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub target: String,
    pub version: String,
    pub host: Option<String>,
    pub body: BodyHeaders,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub version: String,
    pub status: u16,
    pub reason: String,
    pub body: BodyHeaders,
}

/// The headers that decide where a body ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BodyHeaders {
    pub content_length: Option<u64>,
    /// Transfer-Encoding ends in "chunked".
    pub chunked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Head<T> {
    /// The parsed head, and how many bytes it took.
    Complete(T, usize),
    /// Not all of it has arrived.
    Incomplete,
    Invalid(String),
}

/// Whether `data` starts like a request: a method and a space. `None` while
/// too few bytes have arrived to tell.
pub fn starts_like_request(data: &[u8]) -> Option<bool> {
    let mut undecided = false;
    for method in METHODS {
        let token = [method.as_bytes(), b" "].concat();
        let n = token.len().min(data.len());
        if data[..n] == token[..n] {
            if n == token.len() {
                return Some(true);
            }
            undecided = true;
        }
    }
    if undecided { None } else { Some(false) }
}

/// Whether `data` starts like a response ("HTTP/1."). `None` while too few
/// bytes have arrived to tell.
pub fn starts_like_response(data: &[u8]) -> Option<bool> {
    const START: &[u8] = b"HTTP/1.";
    let n = START.len().min(data.len());
    if data[..n] != START[..n] {
        Some(false)
    } else if n < START.len() {
        None
    } else {
        Some(true)
    }
}

pub fn parse_request(data: &[u8]) -> Head<Request> {
    let (lines, len) = match head_lines(data) {
        Ok(Some(found)) => found,
        Ok(None) => return Head::Incomplete,
        Err(e) => return Head::Invalid(e),
    };
    let mut parts = lines[0].splitn(3, ' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Head::Invalid("request line needs a method, target and version".into());
    };
    if !METHODS.contains(&method) || !version.starts_with("HTTP/") {
        return Head::Invalid(format!("not a request line: {}", lines[0]));
    }
    let headers = match headers(&lines[1..]) {
        Ok(h) => h,
        Err(e) => return Head::Invalid(e),
    };
    let request = Request {
        method: method.to_string(),
        target: target.to_string(),
        version: version.to_string(),
        host: headers.host,
        body: headers.body,
    };
    Head::Complete(request, len)
}

pub fn parse_response(data: &[u8]) -> Head<Response> {
    let (lines, len) = match head_lines(data) {
        Ok(Some(found)) => found,
        Ok(None) => return Head::Incomplete,
        Err(e) => return Head::Invalid(e),
    };
    let mut parts = lines[0].splitn(3, ' ');
    let (Some(version), Some(code)) = (parts.next(), parts.next()) else {
        return Head::Invalid("status line needs a version and a status code".into());
    };
    let status = match code.parse::<u16>() {
        Ok(s) if version.starts_with("HTTP/") && (100..=999).contains(&s) && code.len() == 3 => s,
        _ => return Head::Invalid(format!("not a status line: {}", lines[0])),
    };
    let headers = match headers(&lines[1..]) {
        Ok(h) => h,
        Err(e) => return Head::Invalid(e),
    };
    let response = Response {
        version: version.to_string(),
        status,
        reason: parts.next().unwrap_or("").to_string(),
        body: headers.body,
    };
    Head::Complete(response, len)
}

/// The head's lines (without line endings) and its length including the
/// blank line, or `None` if the blank line hasn't arrived yet.
fn head_lines(data: &[u8]) -> Result<Option<(Vec<String>, usize)>, String> {
    let window = &data[..data.len().min(MAX_HEAD_LEN)];
    // The head ends at a blank line: "\r\n\r\n", or "\n\n" from lenient senders.
    let end = window
        .windows(2)
        .position(|w| w == b"\n\n")
        .map(|i| i + 2)
        .into_iter()
        .chain(
            window
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|i| i + 4),
        )
        .min();
    let Some(len) = end else {
        return if data.len() >= MAX_HEAD_LEN {
            Err("head longer than 64 KB".into())
        } else {
            Ok(None)
        };
    };
    let lines = data[..len]
        .split(|b| *b == b'\n')
        .map(|line| printable(line.strip_suffix(b"\r").unwrap_or(line)))
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if lines.is_empty() {
        return Err("empty head".into());
    }
    Ok(Some((lines, len)))
}

struct Headers {
    host: Option<String>,
    body: BodyHeaders,
}

fn headers(lines: &[String]) -> Result<Headers, String> {
    let mut out = Headers {
        host: None,
        body: BodyHeaders::default(),
    };
    for line in lines {
        // Obsolete line folding (a line starting with whitespace) only
        // continues a value; nothing we need.
        if line.starts_with([' ', '\t']) {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(format!("header line without a colon: {line}"));
        };
        let value = value.trim();
        match name.to_ascii_lowercase().as_str() {
            "host" => out.host = Some(value.to_string()),
            "content-length" => {
                let len = value
                    .parse::<u64>()
                    .map_err(|_| format!("bad Content-Length: {value}"))?;
                if out.body.content_length.is_some_and(|l| l != len) {
                    return Err("conflicting Content-Length headers".into());
                }
                out.body.content_length = Some(len);
            }
            "transfer-encoding" => {
                let last = value.rsplit(',').next().unwrap_or("").trim();
                out.body.chunked = last.eq_ignore_ascii_case("chunked");
            }
            _ => {}
        }
    }
    Ok(out)
}

/// Walks a chunked body as it arrives, keeping only its place, so a large
/// body never has to be held in memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Chunked {
    state: ChunkState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum ChunkState {
    /// Expecting a chunk-size line.
    #[default]
    Size,
    /// Inside a chunk, with this many bytes to go.
    Data(u64),
    /// Expecting the line ending after a chunk.
    DataEnd,
    /// After the last (zero-size) chunk: trailer lines up to a blank one.
    Trailers,
    Done,
}

impl Chunked {
    /// Consumes as much of `data` as it can. Returns the bytes used and
    /// whether the body has ended.
    pub fn feed(&mut self, data: &[u8]) -> Result<(usize, bool), String> {
        let mut used = 0;
        loop {
            let rest = &data[used..];
            match self.state {
                ChunkState::Done => return Ok((used, true)),
                ChunkState::Data(left) => {
                    let take = left.min(rest.len() as u64);
                    used += take as usize;
                    self.state = if take == left {
                        ChunkState::DataEnd
                    } else {
                        ChunkState::Data(left - take)
                    };
                    if take < left {
                        return Ok((used, false));
                    }
                }
                ChunkState::Size | ChunkState::DataEnd | ChunkState::Trailers => {
                    let Some(end) = rest.iter().position(|b| *b == b'\n') else {
                        if rest.len() > MAX_CHUNK_LINE {
                            return Err("chunk line too long".into());
                        }
                        return Ok((used, false));
                    };
                    let line = &rest[..end];
                    let line = line.strip_suffix(b"\r").unwrap_or(line);
                    used += end + 1;
                    self.state = match self.state {
                        ChunkState::DataEnd if line.is_empty() => ChunkState::Size,
                        ChunkState::DataEnd => return Err("chunk data longer than its size".into()),
                        ChunkState::Trailers if line.is_empty() => ChunkState::Done,
                        ChunkState::Trailers => ChunkState::Trailers,
                        _ => match chunk_size(line)? {
                            0 => ChunkState::Trailers,
                            n => ChunkState::Data(n),
                        },
                    };
                }
            }
        }
    }
}

/// "1a3f;ext=1" → 0x1a3f
fn chunk_size(line: &[u8]) -> Result<u64, String> {
    let digits = line.split(|b| *b == b';').next().unwrap_or(line);
    let text = String::from_utf8_lossy(digits);
    let text = text.trim();
    if text.is_empty() || text.len() > 15 {
        return Err(format!("bad chunk size: {text}"));
    }
    u64::from_str_radix(text, 16).map_err(|_| format!("bad chunk size: {text}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_head() {
        let data =
            b"GET /api/items?id=7 HTTP/1.1\r\nHost: api.example.com\r\nAccept: */*\r\n\r\nrest";
        let Head::Complete(req, len) = parse_request(data) else {
            panic!("expected a complete head")
        };
        assert_eq!(
            (req.method.as_str(), req.target.as_str()),
            ("GET", "/api/items?id=7")
        );
        assert_eq!(req.host.as_deref(), Some("api.example.com"));
        assert_eq!(&data[len..], b"rest");
        assert_eq!(parse_request(&data[..20]), Head::Incomplete);
    }

    #[test]
    fn response_head_and_body_headers() {
        let data = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 12\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";
        let Head::Complete(resp, _) = parse_response(data) else {
            panic!("expected a complete head")
        };
        assert_eq!(
            (resp.status, resp.reason.as_str()),
            (503, "Service Unavailable")
        );
        assert_eq!(
            resp.body,
            BodyHeaders {
                content_length: Some(12),
                chunked: true
            }
        );
        assert!(matches!(
            parse_response(b"HTTP/1.1 20 OK\r\n\r\n"),
            Head::Invalid(_)
        ));
        assert!(matches!(
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n"),
            Head::Invalid(_)
        ));
    }

    #[test]
    fn telling_http_apart_early() {
        assert_eq!(starts_like_request(b"GE"), None);
        assert_eq!(starts_like_request(b"GET /"), Some(true));
        assert_eq!(starts_like_request(b"OPTIONS * HTTP/1.1"), Some(true));
        assert_eq!(starts_like_request(&[0x16, 3, 1]), Some(false));
        assert_eq!(starts_like_request(b"GETX"), Some(false));
        assert_eq!(starts_like_response(b"HTTP/1.1 200"), Some(true));
        assert_eq!(starts_like_response(b"HTT"), None);
        assert_eq!(starts_like_response(b"SSH-2.0"), Some(false));
    }

    #[test]
    fn chunked_body_in_pieces() {
        let body =
            b"5\r\nhello\r\n1a;ext=x\r\nabcdefghijklmnopqrstuvwxyz\r\n0\r\nTrailer: 1\r\n\r\nNEXT";
        // Feed it a few bytes at a time, keeping unused bytes like a stream would.
        let mut chunked = Chunked::default();
        let mut pending: Vec<u8> = Vec::new();
        let mut total = 0;
        let mut done = false;
        for piece in body.chunks(3) {
            pending.extend_from_slice(piece);
            let (used, finished) = chunked.feed(&pending).unwrap();
            pending.drain(..used);
            total += used;
            if finished {
                done = true;
                break;
            }
        }
        assert!(done);
        // Everything but "NEXT", which belongs to whatever follows the body.
        assert_eq!(total, body.len() - 4);
        assert!(Chunked::default().feed(b"zz\r\n").is_err());
    }
}
