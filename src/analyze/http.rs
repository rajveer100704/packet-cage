//! HTTP/1.x exchanges: each request matched to its response, with timing
//! that separates the network's share of a wait from the server's.
//!
//! HTTP is recognized by content: a connection whose client starts with a
//! request line. Requests are answered in order (RFC 9112 section 9.3), so
//! pipelined requests wait in a queue for their responses.

use std::collections::{HashMap, VecDeque};
use std::fmt;

use crate::analyze::stream::{Arrival, Reassembler};
use crate::capture::Frame;
use crate::decode::Tcp;
use crate::decode::http::{self, Chunked, Head, Request, Response};
use crate::flow::{Observed, Side, TcpConn};
use crate::units;

/// A server taking longer than this to start answering is worth a mention.
pub const SLOW_SERVER_SECS: f64 = 0.5;
/// Unconsumed bytes allowed per direction: a whole head, plus slack.
const BUFFER_LIMIT: usize = http::MAX_HEAD_LEN + 16 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub struct Exchange {
    /// Index of the connection in the flow table.
    pub flow: usize,
    /// `None` when the request wasn't captured.
    pub request: Option<Request>,
    pub request_start: Option<Arrival>,
    /// The frame that completed the request head: where Wireshark shows the
    /// request, and where `dump` does.
    pub request_frame: Option<u64>,
    /// The request's last byte, body included.
    pub request_end: Option<Arrival>,
    pub response: Option<Response>,
    pub response_start: Option<Arrival>,
    /// The frame that completed the response head.
    pub response_frame: Option<u64>,
    /// The response's last byte, once its end has been seen.
    pub response_end: Option<Arrival>,
    /// Response body bytes seen.
    pub response_bytes: u64,
}

impl Exchange {
    fn new(flow: usize) -> Self {
        Exchange {
            flow,
            request: None,
            request_start: None,
            request_frame: None,
            request_end: None,
            response: None,
            response_start: None,
            response_frame: None,
            response_end: None,
            response_bytes: 0,
        }
    }

    /// At the capture point: from the request's last byte to the
    /// response's first.
    pub fn time_to_first_byte(&self) -> Option<f64> {
        Some(self.response_start?.ts.secs_since(self.request_end?.ts))
    }

    /// The server's share of that wait: the time to first byte minus the
    /// round trip between the capture point and the server, measured in the
    /// TCP handshake. A capture taken next to the server has almost no round
    /// trip to take out; one taken at the client takes out the whole network.
    pub fn server_time(&self, conn: &TcpConn) -> Option<f64> {
        let network = conn.handshake_rtt()?.server_side?;
        Some((self.time_to_first_byte()? - network).max(0.0))
    }

    /// "GET example.com/path", for reports.
    pub fn label(&self) -> String {
        match &self.request {
            Some(r) => format!(
                "{} {}{}",
                r.method,
                r.host.as_deref().unwrap_or(""),
                short(&r.target)
            ),
            None => "(request not captured)".to_string(),
        }
    }
}

/// Something worth a mention in `dump`.
#[derive(Debug, Clone, PartialEq)]
pub enum HttpEvent {
    Request(Request),
    /// A response head; `first_byte` is the time to first byte when the
    /// request was seen.
    Response {
        response: Response,
        /// Frame where the request it answers started.
        request_frame: Option<u64>,
        /// Target of that request.
        request_target: Option<String>,
        first_byte: Option<f64>,
    },
}

impl fmt::Display for HttpEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpEvent::Request(r) => {
                write!(f, "{} {} {}", r.method, short(&r.target), r.version)?;
                if let Some(host) = &r.host {
                    write!(f, " ({host})")?;
                }
                Ok(())
            }
            HttpEvent::Response {
                response,
                request_frame,
                first_byte,
                ..
            } => {
                write!(
                    f,
                    "{} {} {}",
                    response.version, response.status, response.reason
                )?;
                match (request_frame, first_byte) {
                    (Some(r), Some(t)) => write!(
                        f,
                        " (request in frame {r}, first byte after {})",
                        units::duration(*t)
                    ),
                    (Some(r), None) => write!(f, " (request in frame {r})"),
                    _ => Ok(()),
                }
            }
        }
    }
}

/// Long targets cut to keep lines readable.
fn short(target: &str) -> String {
    const MAX: usize = 80;
    if target.chars().count() <= MAX {
        return target.to_string();
    }
    let cut: String = target.chars().take(MAX - 1).collect();
    format!("{cut}…")
}

#[derive(Debug, Clone, Copy)]
enum BodyReader {
    Length(u64),
    Chunked(Chunked),
    /// No length given: the body ends when the server closes the connection.
    UntilClose,
}

#[derive(Debug, Default)]
struct Direction {
    bytes: Reassembler,
    /// Set while inside a body, which is skipped.
    body: Option<BodyReader>,
    /// The exchange whose body is being read.
    current: Option<usize>,
}

#[derive(Debug)]
enum Connection {
    /// Waiting for the first data to decide.
    Undecided([Direction; 2]),
    Http {
        dirs: [Direction; 2],
        /// Requests still waiting for a response, oldest first.
        waiting: VecDeque<usize>,
    },
    NotHttp,
}

#[derive(Debug, Default)]
pub struct HttpLog {
    exchanges: Vec<Exchange>,
    connections: HashMap<usize, Connection>,
}

impl HttpLog {
    pub fn exchanges(&self) -> &[Exchange] {
        &self.exchanges
    }

    /// The Host the first request on a connection asked for.
    pub fn host_for(&self, flow: usize) -> Option<&str> {
        self.exchanges
            .iter()
            .filter(|e| e.flow == flow)
            .find_map(|e| e.request.as_ref()?.host.as_deref())
    }

    pub fn observe(
        &mut self,
        frame: &Frame,
        tcp: &Tcp,
        payload: &[u8],
        flow: &Observed,
    ) -> Vec<HttpEvent> {
        let index = flow.flow.index;
        let side = flow.flow.from;
        let at = Arrival {
            frame: frame.number,
            ts: frame.ts,
        };
        let connection = self
            .connections
            .entry(index)
            .or_insert_with(|| Connection::Undecided(Default::default()));
        let dirs = match connection {
            Connection::NotHttp => return Vec::new(),
            Connection::Undecided(dirs) | Connection::Http { dirs, .. } => dirs,
        };
        let own = side_index(side);
        if dirs[own].bytes.push(tcp, payload, at, BUFFER_LIMIT) == 0 {
            return Vec::new();
        }
        if let Connection::Undecided(dirs) = connection {
            // A client starts with a request; if the capture joined late, the
            // first thing seen may be a response.
            let data = dirs[own].bytes.data();
            let looks = match side {
                Side::Client => http::starts_like_request(data),
                Side::Server => http::starts_like_response(data),
            };
            match looks {
                None => return Vec::new(),
                Some(false) => {
                    *connection = Connection::NotHttp;
                    return Vec::new();
                }
                Some(true) => {
                    let dirs = std::mem::take(dirs);
                    *connection = Connection::Http {
                        dirs,
                        waiting: VecDeque::new(),
                    };
                }
            }
        }
        let Connection::Http { dirs, waiting } = connection else {
            return Vec::new();
        };
        read(&mut self.exchanges, dirs, waiting, side, index)
    }
}

/// Reads every complete head, and skips every body, that `side` has sent.
fn read(
    exchanges: &mut Vec<Exchange>,
    dirs: &mut [Direction; 2],
    waiting: &mut VecDeque<usize>,
    side: Side,
    flow: usize,
) -> Vec<HttpEvent> {
    let mut events = Vec::new();
    let own = side_index(side);
    let mut stop_both = false;
    loop {
        let dir = &mut dirs[own];
        if !dir.bytes.is_following() || dir.bytes.data().is_empty() {
            break;
        }
        let offset = dir.bytes.offset();
        if let Some(reader) = dir.body.as_mut() {
            let data = dir.bytes.data();
            let (used, done) = match reader {
                BodyReader::Length(left) => {
                    let take = (*left).min(data.len() as u64);
                    *left -= take;
                    (take as usize, *left == 0)
                }
                BodyReader::Chunked(chunked) => match chunked.feed(data) {
                    Ok(progress) => progress,
                    Err(_) => {
                        dir.bytes.stop();
                        break;
                    }
                },
                BodyReader::UntilClose => (data.len(), false),
            };
            if used > 0 {
                let last = dir.bytes.arrival(offset + used as u64 - 1);
                if let Some(i) = dir.current {
                    let exchange = &mut exchanges[i];
                    match side {
                        Side::Client if done => exchange.request_end = last,
                        Side::Client => {}
                        Side::Server => {
                            exchange.response_bytes += used as u64;
                            // Until-close bodies end whenever the data stops.
                            if done || matches!(reader, BodyReader::UntilClose) {
                                exchange.response_end = last;
                            }
                        }
                    }
                }
                dir.bytes.consume(used);
            }
            if done {
                dir.body = None;
                dir.current = None;
            } else if used == 0 {
                break; // wait for more of the body
            }
            continue;
        }

        let parsed = match side {
            Side::Client => http::parse_request(dir.bytes.data()).map_parts(Message::Request),
            Side::Server => http::parse_response(dir.bytes.data()).map_parts(Message::Response),
        };
        let (message, len) = match parsed {
            Head::Complete(message, len) => (message, len),
            Head::Incomplete => break,
            Head::Invalid(_) => {
                // Not HTTP (any more): give up on this direction.
                dir.bytes.stop();
                break;
            }
        };
        let start = dir.bytes.arrival(offset);
        let end = dir.bytes.arrival(offset + len as u64 - 1);
        dir.bytes.consume(len);
        match message {
            Message::Request(request) => {
                let body = request_body(&request);
                let mut exchange = Exchange::new(flow);
                exchange.request = Some(request.clone());
                exchange.request_start = start;
                exchange.request_frame = end.map(|a| a.frame);
                exchange.request_end = if body.is_none() { end } else { None };
                exchanges.push(exchange);
                let i = exchanges.len() - 1;
                waiting.push_back(i);
                if request.method == "CONNECT" {
                    // A tunnel: whatever follows the response isn't HTTP.
                    dir.bytes.stop();
                } else if body.is_some() {
                    dir.body = body;
                    dir.current = Some(i);
                }
                events.push(HttpEvent::Request(request));
            }
            Message::Response(response) if response.status < 200 && response.status != 101 => {
                // Interim: "100 Continue" and friends; the final response
                // follows.
                let request = waiting.front().map(|&i| &exchanges[i]);
                events.push(HttpEvent::Response {
                    response,
                    request_frame: request.and_then(|e| e.request_frame),
                    request_target: request
                        .and_then(|e| e.request.as_ref())
                        .map(|r| r.target.clone()),
                    first_byte: None,
                });
                if stop_both {
                    break;
                }
            }
            Message::Response(response) => {
                let i = waiting.pop_front().unwrap_or_else(|| {
                    exchanges.push(Exchange::new(flow));
                    exchanges.len() - 1
                });
                let exchange = &mut exchanges[i];
                let method = exchange.request.as_ref().map(|r| r.method.clone());
                // "101 Switching Protocols" answers the request and leaves
                // HTTP behind: no body, and what follows is another protocol.
                let upgraded = response.status == 101;
                let body = (!upgraded)
                    .then(|| response_body(method.as_deref(), &response))
                    .flatten();
                exchange.response = Some(response.clone());
                exchange.response_start = start;
                exchange.response_frame = end.map(|a| a.frame);
                exchange.response_end = if body.is_none() { end } else { None };
                let first_byte = exchange.time_to_first_byte();
                let request_frame = exchange.request_frame;
                let request_target = exchange.request.as_ref().map(|r| r.target.clone());
                if upgraded || method.as_deref() == Some("CONNECT") && response.status / 100 == 2 {
                    stop_both = true;
                } else if body.is_some() {
                    dir.body = body;
                    dir.current = Some(i);
                }
                events.push(HttpEvent::Response {
                    response,
                    request_frame,
                    request_target,
                    first_byte,
                });
                if stop_both {
                    break;
                }
            }
        }
    }
    if stop_both {
        dirs[0].bytes.stop();
        dirs[1].bytes.stop();
    }
    events
}

enum Message {
    Request(Request),
    Response(Response),
}

trait MapParts<T> {
    fn map_parts<U>(self, f: impl FnOnce(T) -> U) -> Head<U>;
}

impl<T> MapParts<T> for Head<T> {
    fn map_parts<U>(self, f: impl FnOnce(T) -> U) -> Head<U> {
        match self {
            Head::Complete(value, len) => Head::Complete(f(value), len),
            Head::Incomplete => Head::Incomplete,
            Head::Invalid(e) => Head::Invalid(e),
        }
    }
}

/// Where a request's body ends (RFC 9112 section 6.3).
fn request_body(request: &Request) -> Option<BodyReader> {
    if request.body.chunked {
        return Some(BodyReader::Chunked(Chunked::default()));
    }
    match request.body.content_length {
        Some(n) if n > 0 => Some(BodyReader::Length(n)),
        _ => None,
    }
}

/// Where a response's body ends. Responses to HEAD, and 204 and 304
/// responses, never have one; without a length it runs until the close.
fn response_body(method: Option<&str>, response: &Response) -> Option<BodyReader> {
    if method == Some("HEAD") || matches!(response.status, 204 | 304) {
        return None;
    }
    if response.body.chunked {
        return Some(BodyReader::Chunked(Chunked::default()));
    }
    match response.body.content_length {
        Some(0) => None,
        Some(n) => Some(BodyReader::Length(n)),
        None => Some(BodyReader::UntilClose),
    }
}

fn side_index(side: Side) -> usize {
    match side {
        Side::Client => 0,
        Side::Server => 1,
    }
}
