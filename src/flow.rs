//! Groups packets into conversations (flows) and tracks TCP connection state.
//!
//! A flow is every TCP or UDP packet between two endpoints, in both
//! directions. Flows are numbered per protocol in order of first appearance,
//! which matches Wireshark's `tcp.stream` and `udp.stream`.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;

use crate::analyze::tcp::{TcpAnalyzer, TcpEvent, TcpHealth};
use crate::capture::{Frame, Timestamp};
use crate::decode::{IPPROTO_TCP, IPPROTO_UDP, Packet, Tcp, TcpFlags, Transport};
use crate::summary::SeqBase;

/// Burst-splitting silence when the round trip is unknown, and the least
/// used when it is very short.
const DEFAULT_QUIET_SECS: f64 = 0.2;
const MIN_QUIET_SECS: f64 = 0.05;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Side {
    Client,
    Server,
}

impl Side {
    pub fn other(self) -> Side {
        match self {
            Side::Client => Side::Server,
            Side::Server => Side::Client,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counter {
    pub packets: u64,
    /// Bytes on the wire, link-layer headers included (as Wireshark counts them).
    pub bytes: u64,
}

impl Counter {
    pub fn add(&mut self, bytes: u64) {
        self.packets += 1;
        self.bytes += bytes;
    }
}

#[derive(Debug, Clone)]
pub struct Flow {
    /// IP protocol: 6 for TCP, 17 for UDP.
    pub protocol: u8,
    /// Position among flows of the same protocol, like Wireshark's `tcp.stream`.
    pub stream: u32,
    pub client: SocketAddr,
    pub server: SocketAddr,
    pub from_client: Counter,
    pub from_server: Counter,
    pub first_frame: u64,
    pub last_frame: u64,
    pub first_ts: Timestamp,
    pub last_ts: Timestamp,
    /// Connection state; `None` for UDP.
    pub tcp: Option<TcpConn>,
}

impl Flow {
    pub fn packets(&self) -> u64 {
        self.from_client.packets + self.from_server.packets
    }

    pub fn bytes(&self) -> u64 {
        self.from_client.bytes + self.from_server.bytes
    }

    pub fn duration_secs(&self) -> f64 {
        self.last_ts.secs_since(self.first_ts)
    }

    /// A SYN on endpoints we've already seen starts a new connection (the
    /// client reused its port), unless it repeats the SYN that opened this one.
    fn is_new_connection(&self, tcp: &Tcp, src: SocketAddr) -> bool {
        let Some(conn) = &self.tcp else {
            return false;
        };
        if !tcp.flags.has(TcpFlags::SYN) || tcp.flags.has(TcpFlags::ACK) {
            return false;
        }
        let retransmitted =
            src == self.client && conn.syn.is_some() && conn.base_seq[0] == Some(tcp.seq);
        !retransmitted
    }
}

#[derive(Debug, Clone, Default)]
pub struct TcpConn {
    /// First SYN from the client: (frame number, time).
    pub syn: Option<(u64, Timestamp)>,
    /// First SYN-ACK from the server.
    pub syn_ack: Option<(u64, Timestamp)>,
    /// Set once anything other than SYN or RST is sent, which also covers
    /// connections that were already open when the capture started.
    pub established: bool,
    pub fin_from_client: bool,
    pub fin_from_server: bool,
    /// The first RST.
    pub reset: Option<Reset>,
    /// Problems in each direction: client to server, then server to client.
    health: [TcpHealth; 2],
    analyzer: TcpAnalyzer,
    /// Most recent SYN from the client.
    last_syn_ts: Option<Timestamp>,
    /// From that SYN to the first SYN-ACK.
    syn_to_syn_ack_ns: Option<u64>,
    /// The longest the client waited for the server; see `Wait`.
    pub longest_wait: Option<Wait>,
    waiting: WaitTracker,
    /// Sequence number that counts as 0, for the client and server directions.
    base_seq: [Option<u32>; 2],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reset {
    pub by: Side,
    pub frame: u64,
    pub kind: ResetKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetKind {
    /// The answer to a SYN: nothing listens on that port, or a firewall said no.
    Refused,
    /// One side gave up on a connection that was open or opening.
    Aborted,
    /// Sent while closing, after a FIN. Usually harmless.
    WhileClosing,
}

/// How long a client waited for its server: from the client's last data to
/// the start of the server's largest burst of data in reply.
///
/// The largest burst is almost always the real answer. A server may first
/// send something small at once (a TLS 1.3 session ticket, HTTP/2 settings)
/// or much later (a close alert when an idle connection times out), so the
/// first or last server data would mislead. This needs no decryption, so it
/// works for HTTPS. Bursts are split by silences longer than 1.5 round trips,
/// so the ordinary pauses in a large download stay in one burst; a silence
/// that ends in a retransmission, or while the client's window was closed, is
/// the network's or the client's doing and splits nothing.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Wait {
    /// The client's last data before the wait.
    pub request_frame: u64,
    /// The first frame of the server's largest burst in reply.
    pub response_frame: u64,
    pub secs: f64,
}

#[derive(Debug, Clone, Default)]
struct WaitTracker {
    /// End of the client's latest data: the request being answered.
    since: Option<(u64, Timestamp)>,
    /// The burst of server data now arriving.
    burst: Option<Burst>,
    /// Bytes in the largest burst so far in reply to this request.
    largest: u64,
    /// The client advertised a zero window since the last server data.
    client_window_closed: bool,
}

#[derive(Debug, Clone, Copy)]
struct Burst {
    frame: u64,
    start: Timestamp,
    last: Timestamp,
    bytes: u64,
}

/// Handshake timing. The capture point splits the round trip in two: SYN to
/// SYN-ACK is the part between the capture point and the server, SYN-ACK to
/// the client's ACK the part between the capture point and the client.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HandshakeRtt {
    /// The whole round trip between client and server, wherever the capture
    /// was taken: Wireshark's `tcp.analysis.initial_rtt`.
    pub total: f64,
    pub server_side: Option<f64>,
}

impl HandshakeRtt {
    pub fn client_side(&self) -> Option<f64> {
        self.server_side.map(|s| (self.total - s).max(0.0))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpStatus {
    /// Only SYNs were seen.
    NoAnswer,
    /// The server answered the SYN with RST: nothing listens on that port,
    /// or a firewall rejected it.
    Refused,
    /// The server sent SYN-ACK but the client never completed the handshake.
    HandshakeIncomplete,
    Open,
    /// One side has sent FIN.
    HalfClosed,
    Closed,
    Reset(Side),
}

impl fmt::Display for TcpStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TcpStatus::NoAnswer => "no answer",
            TcpStatus::Refused => "refused",
            TcpStatus::HandshakeIncomplete => "handshake incomplete",
            TcpStatus::Open => "open",
            TcpStatus::HalfClosed => "half-closed",
            TcpStatus::Closed => "closed",
            TcpStatus::Reset(Side::Client) => "reset by client",
            TcpStatus::Reset(Side::Server) => "reset by server",
        })
    }
}

impl TcpConn {
    pub fn status(&self) -> TcpStatus {
        // Both FINs means a clean close; an RST after that is a common way
        // to tear down the socket and not worth reporting.
        if self.fin_from_client && self.fin_from_server {
            return TcpStatus::Closed;
        }
        if let Some(reset) = self.reset {
            return match reset.kind {
                ResetKind::Refused => TcpStatus::Refused,
                ResetKind::Aborted | ResetKind::WhileClosing => TcpStatus::Reset(reset.by),
            };
        }
        if self.fin_from_client || self.fin_from_server {
            TcpStatus::HalfClosed
        } else if self.established {
            TcpStatus::Open
        } else if self.syn_ack.is_some() {
            TcpStatus::HandshakeIncomplete
        } else {
            TcpStatus::NoAnswer
        }
    }

    /// The capture began after this connection was opened.
    pub fn started_before_capture(&self) -> bool {
        self.syn.is_none() && self.syn_ack.is_none()
    }

    /// Retransmissions, duplicate ACKs and so on in data sent by `side`.
    pub fn health(&self, side: Side) -> &TcpHealth {
        &self.health[indexes(side).0]
    }

    /// Wireshark's `tcp.analysis.initial_rtt`, in nanoseconds.
    pub fn initial_rtt_ns(&self) -> Option<u64> {
        self.analyzer.initial_rtt_ns()
    }

    /// See [`TcpAnalyzer::last_analyzed`].
    pub fn last_analyzed(&self) -> bool {
        self.analyzer.last_analyzed()
    }

    /// See [`TcpAnalyzer::window_shift`].
    pub fn window_shift(&self, side: Side) -> u8 {
        self.analyzer.window_shift(side)
    }

    pub fn handshake_rtt(&self) -> Option<HandshakeRtt> {
        Some(HandshakeRtt {
            total: self.analyzer.initial_rtt()?,
            server_side: self.syn_to_syn_ack_ns.map(|ns| ns as f64 / 1e9),
        })
    }

    fn track_wait(&mut self, side: Side, tcp: &Tcp, frame: &Frame, events: &[TcpEvent]) {
        let resent = events.iter().any(|e| {
            matches!(
                e,
                TcpEvent::Retransmission
                    | TcpEvent::FastRetransmission
                    | TcpEvent::SpuriousRetransmission
                    | TcpEvent::OutOfOrder
            )
        });
        // A silence this long between server packets starts a new burst.
        let quiet = self
            .handshake_rtt()
            .map_or(DEFAULT_QUIET_SECS, |r| (1.5 * r.total).max(MIN_QUIET_SECS));
        let w = &mut self.waiting;
        if side == Side::Client && events.contains(&TcpEvent::ZeroWindow) {
            w.client_window_closed = true;
        }
        if tcp.payload_len == 0 {
            return;
        }
        match side {
            // Data sent again is not a new request.
            Side::Client if resent => {}
            Side::Client => {
                *w = WaitTracker {
                    since: Some((frame.number, frame.ts)),
                    ..WaitTracker::default()
                };
            }
            Side::Server => {
                let Some((request_frame, request_ts)) = w.since else {
                    return;
                };
                let new_burst = match &w.burst {
                    None => true,
                    Some(b) => {
                        frame.ts.secs_since(b.last) > quiet && !resent && !w.client_window_closed
                    }
                };
                if new_burst {
                    w.burst = Some(Burst {
                        frame: frame.number,
                        start: frame.ts,
                        last: frame.ts,
                        bytes: 0,
                    });
                }
                let burst = w.burst.as_mut().expect("set above");
                burst.bytes += u64::from(tcp.payload_len);
                burst.last = frame.ts;
                w.client_window_closed = false;
                if burst.bytes > w.largest {
                    w.largest = burst.bytes;
                    // Bursts come in time order, so a new largest one never
                    // shortens the wait already recorded for this request.
                    let secs = burst.start.secs_since(request_ts);
                    if self.longest_wait.is_none_or(|l| secs > l.secs) {
                        self.longest_wait = Some(Wait {
                            request_frame,
                            response_frame: burst.frame,
                            secs,
                        });
                    }
                }
            }
        }
    }

    /// What to subtract from a segment sent by `side` to show relative numbers.
    pub fn seq_base(&self, side: Side) -> SeqBase {
        let (own, other) = indexes(side);
        SeqBase {
            seq: self.base_seq[own].unwrap_or(0),
            ack: self.base_seq[other].unwrap_or(0),
        }
    }

    fn update(&mut self, side: Side, tcp: &Tcp, frame: &Frame) -> Vec<TcpEvent> {
        let flags = tcp.flags;
        let (own, other) = indexes(side);
        if flags.has(TcpFlags::SYN) {
            if self.base_seq[own].is_none() {
                self.base_seq[own] = Some(tcp.seq);
            }
            let seen = Some((frame.number, frame.ts));
            match (side, flags.has(TcpFlags::ACK)) {
                (Side::Client, false) => {
                    self.syn = self.syn.or(seen);
                    self.last_syn_ts = Some(frame.ts);
                }
                (Side::Server, true) if self.syn_ack.is_none() => {
                    self.syn_ack = seen;
                    self.syn_to_syn_ack_ns =
                        self.last_syn_ts.map(|syn| frame.ts.0.saturating_sub(syn.0));
                }
                _ => {}
            }
        } else {
            // Without the SYN, count from the first segment seen, which then
            // shows as 1. Wireshark does the same.
            if self.base_seq[own].is_none() {
                self.base_seq[own] = Some(tcp.seq.wrapping_sub(1));
            }
            if !flags.has(TcpFlags::RST) {
                self.established = true;
            }
        }
        if flags.has(TcpFlags::ACK) && self.base_seq[other].is_none() {
            self.base_seq[other] = Some(tcp.ack.wrapping_sub(1));
        }
        if flags.has(TcpFlags::RST) && self.reset.is_none() {
            // Only call it refused if we saw the SYN it answered; a capture
            // that starts with an RST is an abort we joined late.
            let kind = if side == Side::Server
                && self.syn.is_some()
                && !self.established
                && self.syn_ack.is_none()
            {
                ResetKind::Refused
            } else if self.fin_from_client || self.fin_from_server {
                ResetKind::WhileClosing
            } else {
                ResetKind::Aborted
            };
            self.reset = Some(Reset {
                by: side,
                frame: frame.number,
                kind,
            });
        }
        if flags.has(TcpFlags::FIN) {
            match side {
                Side::Client => self.fin_from_client = true,
                Side::Server => self.fin_from_server = true,
            }
        }
        let events = self.analyzer.segment(side, tcp, frame.number, frame.ts);
        self.health[own].record(tcp, frame.number, &events);
        self.track_wait(side, tcp, frame, &events);
        events
    }
}

fn indexes(side: Side) -> (usize, usize) {
    match side {
        Side::Client => (0, 1),
        Side::Server => (1, 0),
    }
}

/// The flow a packet belongs to, and which side sent it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowRef {
    pub index: usize,
    pub from: Side,
}

/// What `FlowTable::observe` learned about a packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    pub flow: FlowRef,
    /// Retransmissions, duplicate ACKs and so on; always empty for UDP.
    pub tcp_events: Vec<TcpEvent>,
}

/// Endpoints in a fixed order, so both directions map to the same key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    protocol: u8,
    low: SocketAddr,
    high: SocketAddr,
}

impl FlowKey {
    fn new(protocol: u8, x: SocketAddr, y: SocketAddr) -> Self {
        let (low, high) = if x <= y { (x, y) } else { (y, x) };
        FlowKey {
            protocol,
            low,
            high,
        }
    }
}

#[derive(Debug, Default)]
pub struct FlowTable {
    flows: Vec<Flow>,
    /// The current flow for each pair of endpoints. When a port is reused the
    /// entry moves to the new flow; the old one stays in `flows`.
    current: HashMap<FlowKey, usize>,
    tcp_streams: u32,
    udp_streams: u32,
}

impl FlowTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a TCP or UDP packet to its flow, starting a new flow if needed.
    /// Returns `None` for other packets, and for fragments that don't carry
    /// the transport header.
    pub fn observe(&mut self, frame: &Frame, pkt: &Packet<'_>) -> Option<Observed> {
        let (src_ip, dst_ip) = pkt.network.as_ref()?.ip_addrs()?;
        let (protocol, src_port, dst_port, tcp) = match pkt.transport.as_ref()? {
            Transport::Tcp(t) => (IPPROTO_TCP, t.src_port, t.dst_port, Some(t)),
            Transport::Udp(u) => (IPPROTO_UDP, u.src_port, u.dst_port, None),
            _ => return None,
        };
        let src = SocketAddr::new(src_ip, src_port);
        let dst = SocketAddr::new(dst_ip, dst_port);
        let key = FlowKey::new(protocol, src, dst);
        let index = match self.current.get(&key).copied() {
            Some(i) if !tcp.is_some_and(|t| self.flows[i].is_new_connection(t, src)) => i,
            _ => {
                let i = self.start_flow(protocol, src, dst, tcp, frame);
                self.current.insert(key, i);
                i
            }
        };

        let flow = &mut self.flows[index];
        let from = if src == flow.client {
            Side::Client
        } else {
            Side::Server
        };
        let bytes = u64::from(frame.orig_len);
        match from {
            Side::Client => flow.from_client.add(bytes),
            Side::Server => flow.from_server.add(bytes),
        }
        flow.last_frame = frame.number;
        flow.first_ts = flow.first_ts.min(frame.ts);
        flow.last_ts = flow.last_ts.max(frame.ts);
        let tcp_events = match (flow.tcp.as_mut(), tcp) {
            (Some(conn), Some(tcp)) => conn.update(from, tcp, frame),
            _ => Vec::new(),
        };
        Some(Observed {
            flow: FlowRef { index, from },
            tcp_events,
        })
    }

    pub fn flows(&self) -> &[Flow] {
        &self.flows
    }

    pub fn get(&self, r: FlowRef) -> &Flow {
        &self.flows[r.index]
    }

    /// The current flow between two endpoints, if there is one.
    pub fn find(&self, protocol: u8, a: SocketAddr, b: SocketAddr) -> Option<&Flow> {
        let index = *self.current.get(&FlowKey::new(protocol, a, b))?;
        Some(&self.flows[index])
    }

    /// Relative-numbering base for a TCP segment; `None` for UDP.
    pub fn seq_base(&self, r: FlowRef) -> Option<SeqBase> {
        self.get(r).tcp.as_ref().map(|conn| conn.seq_base(r.from))
    }

    fn start_flow(
        &mut self,
        protocol: u8,
        src: SocketAddr,
        dst: SocketAddr,
        tcp: Option<&Tcp>,
        frame: &Frame,
    ) -> usize {
        let (client, server) = client_and_server(src, dst, tcp);
        let counter = if protocol == IPPROTO_TCP {
            &mut self.tcp_streams
        } else {
            &mut self.udp_streams
        };
        let stream = *counter;
        *counter += 1;
        self.flows.push(Flow {
            protocol,
            stream,
            client,
            server,
            from_client: Counter::default(),
            from_server: Counter::default(),
            first_frame: frame.number,
            last_frame: frame.number,
            first_ts: frame.ts,
            last_ts: frame.ts,
            tcp: tcp.map(|_| TcpConn::default()),
        });
        self.flows.len() - 1
    }
}

/// Decides which end of a new flow is the client, from its first packet.
fn client_and_server(
    src: SocketAddr,
    dst: SocketAddr,
    tcp: Option<&Tcp>,
) -> (SocketAddr, SocketAddr) {
    if let Some(tcp) = tcp
        && tcp.flags.has(TcpFlags::SYN)
    {
        // The client sends SYN; the server answers with SYN-ACK.
        return if tcp.flags.has(TcpFlags::ACK) {
            (dst, src)
        } else {
            (src, dst)
        };
    }
    // Otherwise go by the ports: servers listen on well-known or registered
    // ports, clients send from ephemeral ones. Linux picks ephemeral ports
    // from 32768 up, Windows and macOS from 49152 up (the IANA range), so
    // 32768-49151 ranks between: a client port on Linux, but a server port
    // when the other end is a Windows client.
    let rank = |port: u16| match port {
        0..1024 => 0,
        1024..32768 => 1,
        32768..49152 => 2,
        _ => 3,
    };
    match rank(src.port()).cmp(&rank(dst.port())) {
        Ordering::Less => (dst, src),
        // Same kind of port on both ends: whoever spoke first is the client.
        Ordering::Greater | Ordering::Equal => (src, dst),
    }
}
