//! DNS lookups: matching responses to queries, and finding failed, missing,
//! slow and retried ones. Answers also teach us which hostname each IP
//! address belongs to, so reports can name servers instead of numbering them.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::analyze::stream::{Arrival, Reassembler};
use crate::capture::{Frame, Timestamp};
use crate::decode::dns::{self, DnsError, Message, Question, RData, Record};
use crate::decode::{IPPROTO_UDP, Network, Packet, Quoted, Tcp, Transport};
use crate::flow::{Observed, Side};
use crate::units;

pub const DNS_PORT: u16 = 53;
/// A response slower than this is worth pointing out.
pub const SLOW_SECS: f64 = 0.5;
/// A query still unanswered this long before the capture ended counts as
/// lost; a later one may just have been cut off by the end of the capture.
pub const TIMEOUT_SECS: f64 = 3.0;
/// DNS over TCP messages are at most 65535 bytes plus the length prefix.
const MAX_TCP_BUFFER: usize = 65_537;

/// One query and what came back for it.
#[derive(Debug, Clone, PartialEq)]
pub struct Lookup {
    pub client: SocketAddr,
    pub server: SocketAddr,
    pub over_tcp: bool,
    pub id: u16,
    pub question: Option<Question>,
    /// The first query: frame number and time.
    pub query_frame: u64,
    pub query_ts: Timestamp,
    /// Frames where the same query was sent again before any response.
    pub retries: Vec<u64>,
    pub last_query_ts: Timestamp,
    pub response: Option<Response>,
    /// An ICMP error about the query, such as port unreachable.
    pub icmp_error: Option<IcmpError>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Response {
    pub frame: u64,
    pub ts: Timestamp,
    pub rcode: u8,
    pub truncated: bool,
    /// The answers could not be read.
    pub malformed: bool,
    /// From the header, so it is right even when the answers were cut off.
    pub answer_count: u16,
    pub answers: Vec<Record>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpError {
    pub frame: u64,
    pub v6: bool,
    pub icmp_type: u8,
    pub code: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Outcome {
    /// The server sent back an error code (NXDOMAIN, SERVFAIL, ...).
    Failed(u8),
    /// The response could not be read.
    Malformed,
    /// An ICMP error came back instead of a response.
    Unreachable,
    /// No response, although the capture went on long enough for one.
    NoResponse,
    /// The name exists but has no records of the type asked for.
    NoData,
    /// The answer didn't fit in UDP; the client should ask again over TCP.
    Truncated,
    Answered,
    /// Still waiting when the capture ended.
    CaptureEnded,
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Outcome::Failed(rcode) => f.write_str(&dns::rcode_text(*rcode)),
            Outcome::Malformed => f.write_str("malformed response"),
            Outcome::Unreachable => f.write_str("server unreachable (ICMP)"),
            Outcome::NoResponse => f.write_str("no response"),
            Outcome::NoData => f.write_str("no records of that type"),
            Outcome::Truncated => f.write_str("too big for UDP, retry over TCP"),
            Outcome::Answered => f.write_str("answered"),
            Outcome::CaptureEnded => f.write_str("no response before capture ended"),
        }
    }
}

impl Lookup {
    /// Seconds from the first query to the response.
    pub fn latency(&self) -> Option<f64> {
        self.response
            .as_ref()
            .map(|r| r.ts.secs_since(self.query_ts))
    }

    pub fn is_slow(&self) -> bool {
        self.latency().is_some_and(|l| l > SLOW_SECS)
    }

    pub fn outcome(&self, capture_end: Timestamp) -> Outcome {
        if let Some(response) = &self.response {
            return match (response.rcode, response.answer_count == 0) {
                (dns::RCODE_NOERROR, _) if response.malformed => Outcome::Malformed,
                (dns::RCODE_NOERROR, true) if response.truncated => Outcome::Truncated,
                (dns::RCODE_NOERROR, false) => Outcome::Answered,
                (dns::RCODE_NOERROR, true) => Outcome::NoData,
                (rcode, _) => Outcome::Failed(rcode),
            };
        }
        if self.icmp_error.is_some() {
            Outcome::Unreachable
        } else if capture_end.secs_since(self.last_query_ts) >= TIMEOUT_SECS {
            Outcome::NoResponse
        } else {
            Outcome::CaptureEnded
        }
    }
}

/// A DNS message seen in a packet, and what we learned by matching it.
#[derive(Debug, Clone, PartialEq)]
pub struct Seen {
    pub message: Message,
    /// For a repeated query: the frame of the first one.
    pub retry_of: Option<u64>,
    /// For a response: seconds since the query.
    pub latency: Option<f64>,
    /// A response whose query wasn't captured.
    pub unmatched: bool,
    /// A second response to the same query.
    pub duplicate: bool,
    /// The capture kept only the start of the packet, so the message is
    /// incomplete (not malformed).
    pub cut_short: bool,
}

impl Seen {
    /// One line for `dump`.
    pub fn summary(&self) -> String {
        let mut s = self.message.headline();
        if let Some(latency) = self.latency {
            s.push_str(&format!(" ({})", units::duration(latency)));
        }
        if let Some(frame) = self.retry_of {
            s.push_str(&format!(" [retry of frame {frame}]"));
        }
        if self.cut_short {
            if self.message.truncated {
                s.push_str(" [truncated]");
            }
            s.push_str(" [cut off by capture length limit]");
        } else {
            s.push_str(&self.message.notes());
        }
        if self.unmatched {
            s.push_str(" [query not captured]");
        }
        if self.duplicate {
            s.push_str(" [duplicate response]");
        }
        s
    }
}

/// DNS found in one packet.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DnsPacket {
    pub messages: Vec<Seen>,
    /// Port 53 traffic that didn't parse as DNS.
    pub error: Option<DnsError>,
    /// For an ICMP error about a DNS query: the query's frame.
    pub icmp_about: Option<u64>,
    /// DNS over UDP cut off by the capture before even the header.
    pub cut_short: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    client: SocketAddr,
    server: SocketAddr,
    id: u16,
}

#[derive(Debug, Default)]
pub struct DnsLog {
    lookups: Vec<Lookup>,
    /// The latest lookup for each client, server and query ID.
    by_key: HashMap<Key, usize>,
    /// DNS over TCP, per connection and direction.
    tcp: HashMap<(usize, Side), TcpStream>,
    names: HashMap<IpAddr, String>,
    /// Responses whose query wasn't captured (frame numbers).
    pub unmatched_responses: Vec<u64>,
    /// Port 53 packets that weren't valid DNS (frame numbers).
    pub malformed: Vec<u64>,
    last_ts: Timestamp,
}

impl DnsLog {
    pub fn lookups(&self) -> &[Lookup] {
        &self.lookups
    }

    /// The hostname an address was looked up as, if the capture shows it.
    pub fn name_of(&self, ip: IpAddr) -> Option<&str> {
        self.names.get(&ip).map(String::as_str)
    }

    /// Time of the last packet seen, which decides whether a query had time
    /// to be answered.
    pub fn capture_end(&self) -> Timestamp {
        self.last_ts
    }

    pub fn observe(
        &mut self,
        frame: &Frame,
        pkt: &Packet<'_>,
        flow: Option<&Observed>,
    ) -> DnsPacket {
        self.last_ts = self.last_ts.max(frame.ts);
        let mut out = DnsPacket::default();
        if let Some(quoted) = pkt.icmp_quoted() {
            out.icmp_about = self.icmp_error(frame, pkt, &quoted);
            return out;
        }
        let Some((src_ip, dst_ip)) = pkt.network.as_ref().and_then(Network::ip_addrs) else {
            return out;
        };
        let (payloads, over_tcp, src, dst) = match &pkt.transport {
            Some(Transport::Udp(udp)) if udp.src_port == DNS_PORT || udp.dst_port == DNS_PORT => {
                let src = SocketAddr::new(src_ip, udp.src_port);
                let dst = SocketAddr::new(dst_ip, udp.dst_port);
                if pkt.payload.len() < udp.payload_len as usize {
                    // Cut off by the capture's length limit: use what's there,
                    // which usually includes the header with the ID and rcode.
                    match dns::parse_partial(pkt.payload) {
                        Some(message) => {
                            let mut seen = self.record(frame, src, dst, false, message, true);
                            seen.cut_short = true;
                            out.messages.push(seen);
                        }
                        None => out.cut_short = true,
                    }
                    return out;
                }
                (vec![pkt.payload.to_vec()], false, src, dst)
            }
            Some(Transport::Tcp(tcp)) if tcp.src_port == DNS_PORT || tcp.dst_port == DNS_PORT => {
                let Some(observed) = flow else {
                    return out;
                };
                let stream = self
                    .tcp
                    .entry((observed.flow.index, observed.flow.from))
                    .or_default();
                (
                    stream.push(
                        tcp,
                        pkt.payload,
                        Arrival {
                            frame: frame.number,
                            ts: frame.ts,
                        },
                    ),
                    true,
                    SocketAddr::new(src_ip, tcp.src_port),
                    SocketAddr::new(dst_ip, tcp.dst_port),
                )
            }
            _ => return out,
        };
        for payload in payloads {
            match dns::parse(&payload) {
                Ok(message) => {
                    let seen = self.record(frame, src, dst, over_tcp, message, false);
                    out.messages.push(seen);
                }
                Err(e) => {
                    self.malformed.push(frame.number);
                    out.error = Some(e);
                }
            }
        }
        out
    }

    /// `cut_short`: the message is incomplete because the capture cut it off.
    fn record(
        &mut self,
        frame: &Frame,
        src: SocketAddr,
        dst: SocketAddr,
        over_tcp: bool,
        message: Message,
        cut_short: bool,
    ) -> Seen {
        let mut seen = Seen {
            message,
            retry_of: None,
            latency: None,
            unmatched: false,
            duplicate: false,
            cut_short,
        };
        let msg = &seen.message;
        if !msg.response {
            let key = Key {
                client: src,
                server: dst,
                id: msg.id,
            };
            let question = msg.questions.first().cloned();
            let earlier = self
                .by_key
                .get(&key)
                .map(|&i| &mut self.lookups[i])
                .filter(|l| l.response.is_none() && l.question == question);
            if let Some(lookup) = earlier {
                lookup.retries.push(frame.number);
                lookup.last_query_ts = frame.ts;
                seen.retry_of = Some(lookup.query_frame);
            } else {
                self.lookups.push(Lookup {
                    client: src,
                    server: dst,
                    over_tcp,
                    id: msg.id,
                    question,
                    query_frame: frame.number,
                    query_ts: frame.ts,
                    retries: Vec::new(),
                    last_query_ts: frame.ts,
                    response: None,
                    icmp_error: None,
                });
                self.by_key.insert(key, self.lookups.len() - 1);
            }
            return seen;
        }

        let key = Key {
            client: dst,
            server: src,
            id: msg.id,
        };
        match self.by_key.get(&key).map(|&i| &mut self.lookups[i]) {
            Some(lookup) if lookup.response.is_none() => {
                lookup.response = Some(Response {
                    frame: frame.number,
                    ts: frame.ts,
                    rcode: msg.rcode,
                    truncated: msg.truncated,
                    malformed: msg.error.is_some() && !cut_short,
                    answer_count: msg.answer_count,
                    answers: msg.answers.clone(),
                });
                seen.latency = lookup.latency();
            }
            Some(_) => seen.duplicate = true,
            None => {
                self.unmatched_responses.push(frame.number);
                seen.unmatched = true;
            }
        }
        if msg.rcode == dns::RCODE_NOERROR {
            self.learn_names(&seen.message);
        }
        seen
    }

    /// Remembers the name each answered address was asked for by. The name
    /// the client asked for beats the canonical name at the end of a CNAME
    /// chain: "api.example.com", not "d1234.cloudfront.net".
    fn learn_names(&mut self, msg: &Message) {
        let Some(question) = msg.questions.first() else {
            return;
        };
        for record in &msg.answers {
            match &record.data {
                RData::A(ip) => {
                    self.names
                        .entry(IpAddr::V4(*ip))
                        .or_insert_with(|| question.name.clone());
                }
                RData::Aaaa(ip) => {
                    self.names
                        .entry(IpAddr::V6(*ip))
                        .or_insert_with(|| question.name.clone());
                }
                RData::Name(target) if record.rtype == dns::TYPE_PTR => {
                    if let Some(ip) = reverse_name_to_ip(&record.name) {
                        self.names.entry(ip).or_insert_with(|| target.clone());
                    }
                }
                _ => {}
            }
        }
    }

    /// Attaches an ICMP error to the DNS query it quotes. Returns the
    /// query's frame.
    fn icmp_error(&mut self, frame: &Frame, pkt: &Packet<'_>, quoted: &Quoted<'_>) -> Option<u64> {
        let Some(Transport::Icmp(icmp)) = &pkt.transport else {
            return None;
        };
        let (sport, dport) = quoted.ports?;
        if quoted.protocol != IPPROTO_UDP || dport != DNS_PORT {
            return None;
        }
        let client = SocketAddr::new(quoted.src, sport);
        let server = SocketAddr::new(quoted.dst, dport);
        let index = match quoted.udp_payload {
            [hi, lo, ..] => self
                .by_key
                .get(&Key {
                    client,
                    server,
                    id: u16::from_be_bytes([*hi, *lo]),
                })
                .copied(),
            // Too little quoted to see the ID: take the latest unanswered query.
            _ => self
                .lookups
                .iter()
                .rposition(|l| l.client == client && l.server == server && l.response.is_none()),
        }?;
        let lookup = &mut self.lookups[index];
        lookup.icmp_error.get_or_insert(IcmpError {
            frame: frame.number,
            v6: icmp.v6,
            icmp_type: icmp.icmp_type,
            code: icmp.code,
        });
        Some(lookup.query_frame)
    }
}

/// "34.216.184.93.in-addr.arpa" → 93.184.216.34; also handles ip6.arpa names.
fn reverse_name_to_ip(name: &str) -> Option<IpAddr> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    if let Some(rest) = name.strip_suffix(".in-addr.arpa") {
        let mut octets = rest
            .split('.')
            .map(|p| p.parse::<u8>().ok())
            .collect::<Option<Vec<u8>>>()?;
        if octets.len() != 4 {
            return None;
        }
        octets.reverse();
        return Some(IpAddr::V4(Ipv4Addr::new(
            octets[0], octets[1], octets[2], octets[3],
        )));
    }
    let rest = name.strip_suffix(".ip6.arpa")?;
    let nibbles = rest
        .split('.')
        .map(|p| u8::from_str_radix(p, 16).ok().filter(|_| p.len() == 1))
        .collect::<Option<Vec<u8>>>()?;
    if nibbles.len() != 32 {
        return None;
    }
    let mut octets = [0u8; 16];
    for (i, pair) in nibbles.rchunks(2).enumerate() {
        octets[i] = (pair[1] << 4) | pair[0];
    }
    Some(IpAddr::V6(Ipv6Addr::from(octets)))
}

/// DNS over TCP: each message has a 2-byte length prefix and may be split
/// across segments.
#[derive(Debug, Default)]
struct TcpStream {
    bytes: Reassembler,
}

impl TcpStream {
    /// Adds a segment and returns the messages it completes.
    fn push(&mut self, tcp: &Tcp, payload: &[u8], at: Arrival) -> Vec<Vec<u8>> {
        self.bytes.push(tcp, payload, at, MAX_TCP_BUFFER);
        let mut messages = Vec::new();
        while let [hi, lo, ..] = *self.bytes.data() {
            let len = usize::from(u16::from_be_bytes([hi, lo]));
            let Some(message) = self.bytes.data().get(2..2 + len) else {
                break;
            };
            messages.push(message.to_vec());
            self.bytes.consume(2 + len);
        }
        messages
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{TcpFlags, TcpOptions};

    fn segment(seq: u32, flags: u16, payload_len: u32) -> Tcp {
        Tcp {
            src_port: 50000,
            dst_port: 53,
            seq,
            ack: 0,
            flags: TcpFlags(flags),
            window: 64240,
            header_len: 20,
            options: TcpOptions::default(),
            payload_len,
        }
    }

    fn at() -> Arrival {
        Arrival {
            frame: 1,
            ts: Timestamp(0),
        }
    }

    #[test]
    fn length_prefixed_messages() {
        let mut stream = TcpStream::default();
        // TCP Fast Open: the first message rides on the SYN.
        let syn = segment(100, TcpFlags::SYN, 5);
        assert_eq!(
            stream.push(&syn, &[0, 3, b'a', b'b', b'c'], at()),
            vec![b"abc".to_vec()]
        );
        // One message split across segments, then two in one segment.
        let first = segment(106, TcpFlags::ACK, 3);
        assert!(stream.push(&first, &[0, 4, b'w'], at()).is_empty());
        let second = segment(109, TcpFlags::ACK, 6);
        assert_eq!(
            stream.push(&second, &[b'x', b'y', b'z', 0, 1, b'q'], at()),
            vec![b"wxyz".to_vec(), b"q".to_vec()]
        );
    }

    #[test]
    fn reverse_names() {
        assert_eq!(
            reverse_name_to_ip("34.216.184.93.in-addr.arpa"),
            Some("93.184.216.34".parse().unwrap())
        );
        let v6 = "b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.ip6.arpa";
        assert_eq!(
            reverse_name_to_ip(v6),
            Some("4321:0:1:2:3:4:567:89ab".parse().unwrap())
        );
        assert_eq!(reverse_name_to_ip("example.com"), None);
        assert_eq!(reverse_name_to_ip("1.2.3.in-addr.arpa"), None);
    }
}
