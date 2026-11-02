//! The values of packet fields, read from the decoded packet and from what
//! the analysis found in it.
//!
//! Like Wireshark, an ICMP error also carries the fields of the packet it
//! quotes: an unreachable DNS query matches `udp.port == 53` and
//! `dns.qry.name`.

use std::borrow::Cow;
use std::collections::HashMap;
use std::net::SocketAddr;

use super::Field;
use super::dns::{self, Conversation, Flavor, Transactions};
use super::eval::{Source, Value};
use super::fields::F;
use crate::analyze::dns::DNS_PORT;
use crate::analyze::http::HttpEvent;
use crate::analyze::tcp::TcpEvent;
use crate::analyze::tls::TlsEvent;
use crate::analyze::{Analyzer, PacketFindings};
use crate::capture::{Frame, Timestamp};
use crate::decode::dns::{self as wire, Message, RData, Record};
use crate::decode::{
    IPPROTO_TCP, IPPROTO_UDP, Ipv4, Ipv6, Link, Network, Packet, Quoted, Tcp, TcpFlags, Transport,
    Udp,
};
use crate::flow::Flow;

const DNS_TYPE_OPT: u16 = 41;

/// What only the whole capture tells, for fields that point forward: the
/// frame where a query's response arrived, or a connection's round trip
/// seen on its SYN-ACK. Built in a first pass over the capture.
#[derive(Debug, Default)]
pub struct Whole {
    dns: Transactions,
    http_response_in: HashMap<u64, Vec<u64>>,
    /// By flow index.
    initial_rtt: Vec<Option<u64>>,
}

impl Whole {
    /// Call for every packet of the first pass, after the analyzer.
    pub fn observe(&mut self, frame: &Frame, pkt: &Packet<'_>, found: &PacketFindings) {
        self.dns.observe(frame, pkt, found);
    }

    /// Call at the end of the first pass.
    pub fn finish(&mut self, analyzer: &Analyzer) {
        for exchange in analyzer.http.exchanges() {
            if let (Some(request), Some(response)) =
                (exchange.request_frame, exchange.response_frame)
            {
                self.http_response_in
                    .entry(request)
                    .or_default()
                    .push(response);
            }
        }
        self.initial_rtt = analyzer
            .flows
            .flows()
            .iter()
            .map(|f| f.tcp.as_ref().and_then(|c| c.initial_rtt_ns()))
            .collect();
    }
}

/// What filters remember from packet to packet.
#[derive(Debug, Default)]
pub struct Tracker {
    first: Option<Timestamp>,
    previous: Option<Timestamp>,
    current: Option<Timestamp>,
    /// When each HTTP request was seen, by frame, for `http.time`.
    requests: HashMap<u64, Timestamp>,
    whole: Option<Whole>,
}

impl Tracker {
    /// `whole` is needed by filters that use fields pointing forward in the
    /// capture; see [`super::Filter::needs_whole_capture`].
    pub fn new(whole: Option<Whole>) -> Self {
        Tracker {
            whole,
            ..Tracker::default()
        }
    }

    /// Call for every packet, after the analyzer has seen it.
    pub fn observe(&mut self, frame: &Frame, found: &PacketFindings) {
        self.first.get_or_insert(frame.ts);
        self.previous = self.current.replace(frame.ts);
        if found
            .http
            .iter()
            .any(|e| matches!(e, HttpEvent::Request(_)))
        {
            self.requests.insert(frame.number, frame.ts);
        }
    }
}

/// One packet, as a filter sees it.
pub struct PacketView<'a> {
    frame: &'a Frame,
    pkt: &'a Packet<'a>,
    found: &'a PacketFindings,
    analyzer: &'a Analyzer,
    tracker: &'a Tracker,
    /// For an ICMP error, the start of the packet it is about.
    quoted: Option<Quoted<'a>>,
    /// DNS messages the analysis doesn't keep: mDNS, LLMNR, and a query
    /// quoted in an ICMP error. The flag says whether Wireshark tracks the
    /// message's transaction.
    other_dns: Vec<(Message, Flavor, bool)>,
}

impl<'a> PacketView<'a> {
    pub fn new(
        frame: &'a Frame,
        pkt: &'a Packet<'a>,
        found: &'a PacketFindings,
        analyzer: &'a Analyzer,
        tracker: &'a Tracker,
    ) -> Self {
        let quoted = pkt.icmp_quoted();
        let quoted_dns = quoted
            .as_ref()
            .filter(|q| {
                q.protocol == IPPROTO_UDP
                    && q.ports.is_some_and(|(s, d)| s == DNS_PORT || d == DNS_PORT)
            })
            .and_then(|q| wire::parse_partial(q.udp_payload));
        let mut other_dns: Vec<_> = dns::multicast_message(pkt)
            .map(|(m, flavor)| (m, flavor, true))
            .into_iter()
            .collect();
        // Wireshark keeps no state for a message inside an ICMP error.
        other_dns.extend(quoted_dns.map(|m| (m, Flavor::Dns, false)));
        PacketView {
            frame,
            pkt,
            found,
            analyzer,
            tracker,
            quoted,
            other_dns,
        }
    }

    fn ipv4(&self) -> impl Iterator<Item = &Ipv4> {
        let outer = self.pkt.network.iter();
        let inner = self.quoted.iter().map(|q| &q.header);
        outer.chain(inner).filter_map(|n| match n {
            Network::Ipv4(h) => Some(h),
            _ => None,
        })
    }

    fn ipv6(&self) -> impl Iterator<Item = &Ipv6> {
        let outer = self.pkt.network.iter();
        let inner = self.quoted.iter().map(|q| &q.header);
        outer.chain(inner).filter_map(|n| match n {
            Network::Ipv6(h) => Some(h),
            _ => None,
        })
    }

    fn tcp(&self) -> Option<&Tcp> {
        match &self.pkt.transport {
            Some(Transport::Tcp(t)) => Some(t),
            _ => None,
        }
    }

    fn udp(&self) -> Option<&Udp> {
        match &self.pkt.transport {
            Some(Transport::Udp(u)) => Some(u),
            _ => None,
        }
    }

    /// The quoted packet, if it has this protocol.
    fn quoted(&self, protocol: u8) -> Option<&Quoted<'a>> {
        self.quoted.as_ref().filter(|q| q.protocol == protocol)
    }

    /// Source and destination ports, of this packet and of a quoted one.
    fn ports(&self, protocol: u8) -> Vec<(u16, u16)> {
        let outer = match &self.pkt.transport {
            Some(Transport::Tcp(t)) if protocol == IPPROTO_TCP => Some((t.src_port, t.dst_port)),
            Some(Transport::Udp(u)) if protocol == IPPROTO_UDP => Some((u.src_port, u.dst_port)),
            _ => None,
        };
        let inner = self.quoted(protocol).and_then(|q| q.ports);
        outer.into_iter().chain(inner).collect()
    }

    fn flow(&self) -> Option<&Flow> {
        let observed = self.found.flow.as_ref()?;
        Some(self.analyzer.flows.get(observed.flow))
    }

    /// Stream numbers of this packet's flow and of the quoted packet's.
    fn streams(&self, protocol: u8) -> Vec<u32> {
        let outer = self.flow().filter(|f| f.protocol == protocol);
        let inner = self.quoted(protocol).and_then(|q| {
            let (sport, dport) = q.ports?;
            self.analyzer.flows.find(
                protocol,
                SocketAddr::new(q.src, sport),
                SocketAddr::new(q.dst, dport),
            )
        });
        outer.into_iter().chain(inner).map(|f| f.stream).collect()
    }

    fn tcp_events(&self) -> impl Iterator<Item = &TcpEvent> {
        self.found.flow.iter().flat_map(|o| &o.tcp_events)
    }

    /// DNS messages: what Wireshark decodes as DNS, mDNS and LLMNR.
    fn dns(&self) -> impl Iterator<Item = (&Message, Flavor)> {
        let analyzed = self
            .found
            .dns
            .messages
            .iter()
            .map(|s| (&s.message, Flavor::Dns));
        analyzed.chain(self.other_dns.iter().map(|(m, f, _)| (m, *f)))
    }

    /// Wireshark's transaction state for each message that has one.
    fn dns_states(&self) -> Vec<dns::State> {
        let Some(whole) = self.whole() else {
            return Vec::new();
        };
        let analyzed = self
            .found
            .dns
            .messages
            .iter()
            .map(|s| (&s.message, Flavor::Dns, true));
        let other = self
            .other_dns
            .iter()
            .map(|(m, f, tracked)| (m, *f, *tracked));
        analyzed
            .chain(other)
            .filter(|(_, _, tracked)| *tracked)
            .filter_map(|(m, flavor, _)| {
                let conversation = Conversation::of(self.pkt, self.found, m, flavor)?;
                Some(whole.dns.state(conversation, self.frame, m))
            })
            .collect()
    }

    fn dns_records(&self) -> impl Iterator<Item = &Record> {
        self.dns()
            .flat_map(|(m, _)| m.answers.iter().chain(&m.authorities).chain(&m.additionals))
    }

    fn whole(&self) -> Option<&Whole> {
        self.tracker.whole.as_ref()
    }

    fn bytes(&self, from: usize, to: usize) -> Value<'_> {
        let data = &self.frame.data;
        Value::Bytes(Cow::Borrowed(
            data.get(from..to.min(data.len())).unwrap_or(&[]),
        ))
    }

    fn collect<'v>(&'v self, field: F, out: &mut Vec<Value<'v>>) {
        let frame = self.frame;
        let pkt = self.pkt;
        let uint = |n: u64| Value::UInt(n);
        let text = |s: &'v str| Value::Str(Cow::Borrowed(s));
        let name = |s: &'v str| {
            let root = s.is_empty() || s == ".";
            Value::Str(Cow::Borrowed(if root { "<Root>" } else { s }))
        };
        let tcp_flag = |out: &mut Vec<Value<'v>>, bit: u16| {
            out.extend(self.tcp().map(|t| Value::Bool(t.flags.has(bit))));
        };
        let has_event = |out: &mut Vec<Value<'v>>, wanted: fn(&TcpEvent) -> bool| {
            if self.tcp_events().any(wanted) {
                out.push(Value::Present);
            }
        };
        let since = |earlier: Option<Timestamp>| {
            earlier.map(|e| Value::Time((i128::from(frame.ts.0) - i128::from(e.0)) as i64))
        };
        let offsets = pkt.offsets;
        match field {
            F::Frame => out.push(self.bytes(0, frame.data.len())),
            F::FrameNumber => out.push(uint(frame.number)),
            F::FrameLen => out.push(uint(u64::from(frame.orig_len))),
            F::FrameCapLen => out.push(uint(frame.data.len() as u64)),
            F::FrameTimeRelative => out.extend(since(self.tracker.first)),
            F::FrameTimeDelta => out.extend(since(self.tracker.previous)),

            F::Eth => {
                if matches!(pkt.link, Link::Ethernet { .. }) {
                    out.push(self.bytes(0, frame.data.len()));
                }
            }
            F::EthSrc | F::EthDst | F::EthAddr => {
                if let Link::Ethernet { src, dst, .. } = &pkt.link {
                    let macs = match field {
                        F::EthSrc => vec![src],
                        F::EthDst => vec![dst],
                        _ => vec![dst, src],
                    };
                    out.extend(macs.into_iter().map(|m| Value::Ether(m.0)));
                }
            }
            F::EthType => {
                if let Link::Ethernet { outer_type, .. } = pkt.link
                    && outer_type >= 0x0600
                {
                    out.push(uint(u64::from(outer_type)));
                }
            }
            F::Vlan | F::VlanId => {
                if let Link::Ethernet { vlans, .. } = &pkt.link {
                    out.extend(vlans.iter().map(|&id| match field {
                        F::Vlan => Value::Present,
                        _ => uint(u64::from(id)),
                    }));
                }
            }

            F::Arp | F::ArpOpcode | F::ArpSrcHwMac | F::ArpSrcProtoIpv4 | F::ArpDstProtoIpv4 => {
                if let Some(Network::Arp(arp)) = &pkt.network {
                    out.extend(match field {
                        F::Arp => Some(Value::Present),
                        F::ArpOpcode => Some(uint(u64::from(arp.operation))),
                        F::ArpSrcHwMac => arp.sender_mac.map(|m| Value::Ether(m.0)),
                        F::ArpSrcProtoIpv4 => arp.sender_ip.map(|ip| Value::Ip(ip.into())),
                        _ => arp.target_ip.map(|ip| Value::Ip(ip.into())),
                    });
                }
            }

            F::Ip => {
                if let Some(Network::Ipv4(_)) = &pkt.network {
                    out.push(self.bytes(offsets.network, offsets.end));
                }
                // The quoted header is a second IP layer; its bytes aren't kept.
                if let Some(Network::Ipv4(_)) = self.quoted.as_ref().map(|q| &q.header) {
                    out.push(Value::Bytes(Cow::Borrowed(&[])));
                }
            }
            F::IpSrc => out.extend(self.ipv4().map(|h| Value::Ip(h.src.into()))),
            F::IpDst => out.extend(self.ipv4().map(|h| Value::Ip(h.dst.into()))),
            F::IpAddr => out.extend(
                self.ipv4()
                    .flat_map(|h| [Value::Ip(h.src.into()), Value::Ip(h.dst.into())]),
            ),
            F::IpProto => out.extend(self.ipv4().map(|h| uint(u64::from(h.protocol)))),
            F::IpTtl => out.extend(self.ipv4().map(|h| uint(u64::from(h.ttl)))),
            F::IpId => out.extend(self.ipv4().map(|h| uint(u64::from(h.id)))),
            F::IpLen => out.extend(self.ipv4().map(|h| uint(u64::from(h.total_len)))),
            F::IpHdrLen => out.extend(self.ipv4().map(|h| uint(u64::from(h.header_len)))),
            F::IpFlagsDf => out.extend(self.ipv4().map(|h| Value::Bool(h.dont_fragment))),
            F::IpFlagsMf => out.extend(self.ipv4().map(|h| Value::Bool(h.more_fragments))),

            F::Ipv6 => {
                if let Some(Network::Ipv6(_)) = &pkt.network {
                    out.push(self.bytes(offsets.network, offsets.end));
                }
                if let Some(Network::Ipv6(_)) = self.quoted.as_ref().map(|q| &q.header) {
                    out.push(Value::Bytes(Cow::Borrowed(&[])));
                }
            }
            F::Ipv6Src => out.extend(self.ipv6().map(|h| Value::Ip(h.src.into()))),
            F::Ipv6Dst => out.extend(self.ipv6().map(|h| Value::Ip(h.dst.into()))),
            F::Ipv6Addr => out.extend(
                self.ipv6()
                    .flat_map(|h| [Value::Ip(h.src.into()), Value::Ip(h.dst.into())]),
            ),
            F::Ipv6Nxt => out.extend(self.ipv6().map(|h| uint(u64::from(h.next_header)))),
            F::Ipv6Hlim => out.extend(self.ipv6().map(|h| uint(u64::from(h.hop_limit)))),
            F::Ipv6Plen => out.extend(self.ipv6().map(|h| uint(u64::from(h.payload_len)))),

            F::Tcp => {
                if self.tcp().is_some() {
                    out.push(self.bytes(offsets.transport, offsets.end));
                }
                if let Some(q) = self.quoted(IPPROTO_TCP) {
                    out.push(Value::Bytes(Cow::Borrowed(q.transport)));
                }
            }
            F::TcpSrcport | F::TcpDstport | F::TcpPort => {
                out.extend(ports(field, self.ports(IPPROTO_TCP)));
            }
            F::TcpStream => out.extend(
                self.streams(IPPROTO_TCP)
                    .into_iter()
                    .map(|s| uint(u64::from(s))),
            ),
            F::TcpLen => out.extend(self.tcp().map(|t| uint(u64::from(t.payload_len)))),
            F::TcpSeq | F::TcpAck | F::TcpNxtseq => {
                let (Some(t), Some(observed)) = (self.tcp(), &self.found.flow) else {
                    return;
                };
                let base = self
                    .analyzer
                    .flows
                    .seq_base(observed.flow)
                    .unwrap_or_default();
                let seq = t.seq.wrapping_sub(base.seq);
                out.push(uint(u64::from(match field {
                    F::TcpSeq => seq,
                    // Without the ACK flag there is nothing to count from.
                    F::TcpAck if t.flags.has(TcpFlags::ACK) => t.ack.wrapping_sub(base.ack),
                    F::TcpAck => t.ack,
                    _ => {
                        let syn_fin = u32::from(t.flags.has(TcpFlags::SYN))
                            + u32::from(t.flags.has(TcpFlags::FIN));
                        seq.wrapping_add(t.payload_len).wrapping_add(syn_fin)
                    }
                })));
            }
            F::TcpSeqRaw => out.extend(self.tcp().map(|t| uint(u64::from(t.seq)))),
            F::TcpAckRaw => out.extend(self.tcp().map(|t| uint(u64::from(t.ack)))),
            F::TcpHdrLen => out.extend(self.tcp().map(|t| uint(u64::from(t.header_len)))),
            F::TcpFlags => out.extend(self.tcp().map(|t| uint(u64::from(t.flags.0)))),
            F::TcpFlagsFin => tcp_flag(out, TcpFlags::FIN),
            F::TcpFlagsSyn => tcp_flag(out, TcpFlags::SYN),
            F::TcpFlagsReset => tcp_flag(out, TcpFlags::RST),
            F::TcpFlagsPush => tcp_flag(out, TcpFlags::PSH),
            F::TcpFlagsAck => tcp_flag(out, TcpFlags::ACK),
            F::TcpFlagsUrg => tcp_flag(out, TcpFlags::URG),
            F::TcpFlagsEce => tcp_flag(out, TcpFlags::ECE),
            F::TcpFlagsCwr => tcp_flag(out, TcpFlags::CWR),
            F::TcpFlagsAe => tcp_flag(out, TcpFlags::AE),
            F::TcpWindowSizeValue => out.extend(self.tcp().map(|t| uint(u64::from(t.window)))),
            F::TcpWindowSize => {
                let (Some(t), Some(observed)) = (self.tcp(), &self.found.flow) else {
                    return;
                };
                let shift = match &self.analyzer.flows.get(observed.flow).tcp {
                    Some(conn) if !t.flags.has(TcpFlags::SYN) => {
                        conn.window_shift(observed.flow.from)
                    }
                    _ => 0,
                };
                out.push(uint(u64::from(t.window) << shift));
            }
            F::TcpOptionsMssVal => {
                out.extend(
                    self.tcp()
                        .and_then(|t| t.options.mss)
                        .map(|m| uint(u64::from(m))),
                );
            }
            F::TcpOptionsWscaleShift => out.extend(
                self.tcp()
                    .and_then(|t| t.options.window_scale)
                    .map(|s| uint(u64::from(s))),
            ),
            // Wireshark shows the data of an RST as the reset's cause.
            F::TcpPayload => {
                if self.tcp().is_some_and(|t| !t.flags.has(TcpFlags::RST))
                    && !pkt.payload.is_empty()
                {
                    out.push(Value::Bytes(Cow::Borrowed(pkt.payload)));
                }
            }
            F::TcpAnalysisFlags => has_event(out, |_| true),
            // Wireshark flags fast and spurious retransmissions as both.
            F::TcpAnalysisRetransmission => has_event(out, |e| {
                matches!(
                    e,
                    TcpEvent::Retransmission
                        | TcpEvent::FastRetransmission
                        | TcpEvent::SpuriousRetransmission
                )
            }),
            F::TcpAnalysisFastRetransmission => {
                has_event(out, |e| *e == TcpEvent::FastRetransmission);
            }
            F::TcpAnalysisSpuriousRetransmission => {
                has_event(out, |e| *e == TcpEvent::SpuriousRetransmission);
            }
            F::TcpAnalysisOutOfOrder => has_event(out, |e| *e == TcpEvent::OutOfOrder),
            F::TcpAnalysisLostSegment => {
                has_event(out, |e| *e == TcpEvent::PreviousSegmentNotCaptured);
            }
            F::TcpAnalysisAckLostSegment => {
                has_event(out, |e| *e == TcpEvent::AckedUnseenSegment);
            }
            F::TcpAnalysisDuplicateAck => {
                has_event(out, |e| matches!(e, TcpEvent::DuplicateAck { .. }));
            }
            F::TcpAnalysisDuplicateAckNum | F::TcpAnalysisDuplicateAckFrame => {
                out.extend(self.tcp_events().filter_map(|e| match *e {
                    TcpEvent::DuplicateAck { number, .. }
                        if field == F::TcpAnalysisDuplicateAckNum =>
                    {
                        Some(uint(u64::from(number)))
                    }
                    TcpEvent::DuplicateAck { of_frame, .. } => Some(uint(of_frame)),
                    _ => None,
                }));
            }
            F::TcpAnalysisZeroWindow => has_event(out, |e| *e == TcpEvent::ZeroWindow),
            F::TcpAnalysisZeroWindowProbe => has_event(out, |e| *e == TcpEvent::ZeroWindowProbe),
            F::TcpAnalysisZeroWindowProbeAck => {
                has_event(out, |e| *e == TcpEvent::ZeroWindowProbeAck);
            }
            F::TcpAnalysisWindowFull => has_event(out, |e| *e == TcpEvent::WindowFull),
            F::TcpAnalysisWindowUpdate => has_event(out, |e| *e == TcpEvent::WindowUpdate),
            F::TcpAnalysisKeepAlive => has_event(out, |e| *e == TcpEvent::KeepAlive),
            F::TcpAnalysisKeepAliveAck => has_event(out, |e| *e == TcpEvent::KeepAliveAck),
            // Shown on segments with a SEQ/ACK analysis tree, from the first
            // pass: the SYN-ACK has it, though the round trip ends later.
            F::TcpAnalysisInitialRtt => {
                let (Some(observed), Some(whole)) = (&self.found.flow, self.whole()) else {
                    return;
                };
                let conn = self.analyzer.flows.get(observed.flow).tcp.as_ref();
                if let Some(Some(ns)) = whole.initial_rtt.get(observed.flow.index)
                    && conn.is_some_and(|c| c.last_analyzed())
                {
                    out.push(Value::Time(*ns as i64));
                }
            }

            F::Udp => {
                if self.udp().is_some() {
                    out.push(self.bytes(offsets.transport, offsets.end));
                }
                if let Some(q) = self.quoted(IPPROTO_UDP) {
                    out.push(Value::Bytes(Cow::Borrowed(q.transport)));
                }
            }
            F::UdpSrcport | F::UdpDstport | F::UdpPort => {
                out.extend(ports(field, self.ports(IPPROTO_UDP)));
            }
            F::UdpLength => {
                out.extend(self.udp().map(|u| uint(u64::from(u.length))));
                if let Some(&[_, _, _, _, hi, lo, ..]) =
                    self.quoted(IPPROTO_UDP).map(|q| q.transport)
                {
                    out.push(uint(u64::from(u16::from_be_bytes([hi, lo]))));
                }
            }
            F::UdpStream => out.extend(
                self.streams(IPPROTO_UDP)
                    .into_iter()
                    .map(|s| uint(u64::from(s))),
            ),
            F::UdpPayload => {
                if self.udp().is_some() && !pkt.payload.is_empty() {
                    out.push(Value::Bytes(Cow::Borrowed(pkt.payload)));
                }
                if let Some(q) = self.quoted(IPPROTO_UDP)
                    && !q.udp_payload.is_empty()
                {
                    out.push(Value::Bytes(Cow::Borrowed(q.udp_payload)));
                }
            }

            F::Icmp | F::IcmpType | F::IcmpCode | F::Icmpv6 | F::Icmpv6Type | F::Icmpv6Code => {
                let Some(Transport::Icmp(icmp)) = &pkt.transport else {
                    return;
                };
                let v6 = matches!(field, F::Icmpv6 | F::Icmpv6Type | F::Icmpv6Code);
                if icmp.v6 == v6 {
                    out.push(match field {
                        F::Icmp | F::Icmpv6 => Value::Present,
                        F::IcmpType | F::Icmpv6Type => uint(u64::from(icmp.icmp_type)),
                        _ => uint(u64::from(icmp.code)),
                    });
                }
            }

            F::Dns => {
                let dns = &self.found.dns;
                let plain = self.dns().any(|(_, f)| f == Flavor::Dns);
                if plain || dns.error.is_some() || dns.cut_short {
                    out.push(Value::Present);
                }
            }
            F::DnsId => out.extend(self.dns().map(|(m, _)| uint(u64::from(m.id)))),
            F::DnsFlagsResponse => out.extend(self.dns().map(|(m, _)| Value::Bool(m.response))),
            F::DnsFlagsOpcode => out.extend(self.dns().map(|(m, _)| uint(u64::from(m.opcode)))),
            F::DnsFlagsTruncated => out.extend(self.dns().map(|(m, _)| Value::Bool(m.truncated))),
            F::DnsFlagsRcode => out.extend(
                self.dns()
                    .filter(|(m, _)| m.response)
                    .map(|(m, _)| uint(u64::from(m.rcode))),
            ),
            // LLMNR has other flags in these bits. The last two are only in
            // responses.
            F::DnsFlagsRecdesired | F::DnsFlagsAuthoritative | F::DnsFlagsRecavail => {
                let shown = |m: &Message, f: Flavor| {
                    f != Flavor::Llmnr && (m.response || field == F::DnsFlagsRecdesired)
                };
                out.extend(self.dns().filter(|(m, f)| shown(m, *f)).map(|(m, _)| {
                    Value::Bool(match field {
                        F::DnsFlagsRecdesired => m.recursion_desired,
                        F::DnsFlagsAuthoritative => m.authoritative,
                        _ => m.recursion_available,
                    })
                }));
            }
            F::DnsQryName => out.extend(
                self.dns()
                    .flat_map(|(m, _)| m.questions.iter().map(|q| name(&q.name))),
            ),
            F::DnsQryType => out.extend(
                self.dns()
                    .flat_map(|(m, _)| m.questions.iter().map(|q| uint(u64::from(q.qtype)))),
            ),
            F::DnsQryClass => out.extend(
                self.dns()
                    .flat_map(|(m, _)| m.questions.iter().map(|q| uint(u64::from(q.qclass)))),
            ),
            F::DnsCountQueries => {
                out.extend(self.dns().map(|(m, _)| uint(m.questions.len() as u64)))
            }
            F::DnsCountAnswers => {
                out.extend(self.dns().map(|(m, _)| uint(u64::from(m.answer_count))))
            }
            F::DnsCountAuthRr => {
                out.extend(self.dns().map(|(m, _)| uint(u64::from(m.authority_count))));
            }
            F::DnsCountAddRr => {
                out.extend(self.dns().map(|(m, _)| uint(u64::from(m.additional_count))));
            }
            F::DnsRespName => out.extend(self.dns_records().map(|r| name(&r.name))),
            F::DnsRespType => out.extend(self.dns_records().map(|r| uint(u64::from(r.rtype)))),
            // OPT records use the TTL field for flags, so Wireshark shows none.
            F::DnsRespTtl => out.extend(
                self.dns_records()
                    .filter(|r| r.rtype != DNS_TYPE_OPT)
                    .map(|r| uint(u64::from(r.ttl))),
            ),
            F::DnsA => out.extend(self.dns_records().filter_map(|r| match r.data {
                RData::A(ip) => Some(Value::Ip(ip.into())),
                _ => None,
            })),
            F::DnsAaaa => out.extend(self.dns_records().filter_map(|r| match r.data {
                RData::Aaaa(ip) => Some(Value::Ip(ip.into())),
                _ => None,
            })),
            F::DnsCname | F::DnsPtrDomainName => {
                let rtype = if field == F::DnsCname {
                    wire::TYPE_CNAME
                } else {
                    wire::TYPE_PTR
                };
                out.extend(self.dns_records().filter_map(|r| match &r.data {
                    RData::Name(n) if r.rtype == rtype => Some(name(n)),
                    _ => None,
                }));
            }
            F::DnsTime
            | F::DnsResponseIn
            | F::DnsResponseTo
            | F::DnsRetransmission
            | F::DnsRetransmitRequestIn
            | F::DnsUnsolicited => {
                for state in self.dns_states() {
                    out.extend(match field {
                        F::DnsTime => state.time_ns.map(Value::Time),
                        F::DnsResponseIn => state.response_in.map(uint),
                        F::DnsResponseTo => state.response_to.map(uint),
                        F::DnsRetransmission => state.retransmission.then_some(Value::Bool(true)),
                        F::DnsRetransmitRequestIn => state.retransmit_request_in.map(uint),
                        _ => state.unsolicited.then_some(Value::Bool(true)),
                    });
                }
            }

            F::Tls => {
                if !self.found.tls_records.is_empty() {
                    out.push(Value::Present);
                }
            }
            F::TlsRecordContentType | F::TlsRecordOpaqueType => out.extend(
                self.found
                    .tls_records
                    .iter()
                    .filter(|r| r.opaque == (field == F::TlsRecordOpaqueType))
                    .map(|r| uint(u64::from(r.content_type))),
            ),
            F::TlsRecordVersion => {
                out.extend(
                    self.found
                        .tls_records
                        .iter()
                        .map(|r| uint(u64::from(r.version))),
                );
            }
            F::TlsRecordLength => {
                out.extend(
                    self.found
                        .tls_records
                        .iter()
                        .map(|r| uint(u64::from(r.length))),
                );
            }
            F::TlsHandshakeType => out.extend(
                self.found
                    .tls_records
                    .iter()
                    .flat_map(|r| &r.handshake_types)
                    .map(|&t| uint(u64::from(t))),
            ),
            F::TlsHandshakeVersion
            | F::TlsHandshakeExtensionsServerName
            | F::TlsHandshakeExtensionsSupportedVersion
            | F::TlsHandshakeExtensionsAlpnStr
            | F::TlsHandshakeCiphersuite => {
                for event in &self.found.tls {
                    match (field, event) {
                        (F::TlsHandshakeVersion, TlsEvent::ClientHello(h)) => {
                            out.push(uint(u64::from(h.legacy_version)));
                        }
                        (F::TlsHandshakeVersion, TlsEvent::ServerHello(h)) => {
                            out.push(uint(u64::from(h.legacy_version)));
                        }
                        (F::TlsHandshakeExtensionsServerName, TlsEvent::ClientHello(h)) => {
                            out.extend(h.server_name.as_deref().map(text));
                        }
                        (F::TlsHandshakeExtensionsSupportedVersion, TlsEvent::ClientHello(h)) => {
                            out.extend(h.supported_versions.iter().map(|&v| uint(u64::from(v))));
                        }
                        (F::TlsHandshakeExtensionsSupportedVersion, TlsEvent::ServerHello(h)) => {
                            out.extend(h.selected_version.map(|v| uint(u64::from(v))));
                        }
                        (F::TlsHandshakeExtensionsAlpnStr, TlsEvent::ClientHello(h)) => {
                            out.extend(h.alpn.iter().map(|a| text(a)));
                        }
                        (F::TlsHandshakeExtensionsAlpnStr, TlsEvent::ServerHello(h)) => {
                            out.extend(h.alpn.as_deref().map(text));
                        }
                        (F::TlsHandshakeCiphersuite, TlsEvent::ClientHello(h)) => {
                            out.extend(h.cipher_suites.iter().map(|&c| uint(u64::from(c))));
                        }
                        (F::TlsHandshakeCiphersuite, TlsEvent::ServerHello(h)) => {
                            out.push(uint(u64::from(h.cipher_suite)));
                        }
                        _ => {}
                    }
                }
            }
            F::TlsAlertMessageLevel | F::TlsAlertMessageDesc => {
                out.extend(self.found.tls.iter().filter_map(|e| match e {
                    TlsEvent::Alert(Some(a)) if field == F::TlsAlertMessageLevel => {
                        Some(uint(u64::from(a.level)))
                    }
                    TlsEvent::Alert(Some(a)) => Some(uint(u64::from(a.description))),
                    _ => None,
                }));
            }

            F::Http => out.extend(self.found.http.iter().map(|_| Value::Present)),
            F::HttpRequest | F::HttpRequestMethod | F::HttpRequestVersion | F::HttpHost => {
                for event in &self.found.http {
                    let HttpEvent::Request(r) = event else {
                        continue;
                    };
                    out.extend(match field {
                        F::HttpRequest => Some(Value::Bool(true)),
                        F::HttpRequestMethod => Some(text(&r.method)),
                        F::HttpRequestVersion => Some(text(&r.version)),
                        _ => r.host.as_deref().map(text),
                    });
                }
            }
            // A response repeats the URI of the request it answers.
            F::HttpRequestUri => {
                for event in &self.found.http {
                    out.extend(match event {
                        HttpEvent::Request(r) => Some(text(&r.target)),
                        HttpEvent::Response { request_target, .. } => {
                            request_target.as_deref().map(text)
                        }
                    });
                }
            }
            F::HttpResponse
            | F::HttpResponseCode
            | F::HttpResponsePhrase
            | F::HttpResponseVersion
            | F::HttpTime
            | F::HttpRequestIn => {
                for event in &self.found.http {
                    let HttpEvent::Response {
                        response,
                        request_frame,
                        ..
                    } = event
                    else {
                        continue;
                    };
                    out.extend(match field {
                        F::HttpResponse => Some(Value::Bool(true)),
                        F::HttpResponseCode => Some(uint(u64::from(response.status))),
                        F::HttpResponsePhrase => Some(text(&response.reason)),
                        F::HttpResponseVersion => Some(text(&response.version)),
                        F::HttpTime => request_frame
                            .and_then(|f| self.tracker.requests.get(&f).copied())
                            .and_then(|ts| since(Some(ts))),
                        _ => request_frame.map(uint),
                    });
                }
            }
            F::HttpContentLength => {
                out.extend(self.found.http.iter().filter_map(|e| {
                    let body = match e {
                        HttpEvent::Request(r) => r.body,
                        HttpEvent::Response { response, .. } => response.body,
                    };
                    body.content_length.map(uint)
                }));
            }
            F::HttpResponseIn => {
                let request = self
                    .found
                    .http
                    .iter()
                    .any(|e| matches!(e, HttpEvent::Request(_)));
                if let Some(responses) = self
                    .whole()
                    .and_then(|w| w.http_response_in.get(&frame.number))
                    && request
                {
                    out.extend(responses.iter().map(|&f| uint(f)));
                }
            }
        }
    }
}

/// Port fields: the source, the destination, or both.
fn ports(field: F, pairs: Vec<(u16, u16)>) -> Vec<Value<'static>> {
    pairs
        .into_iter()
        .flat_map(|(src, dst)| match field {
            F::TcpSrcport | F::UdpSrcport => vec![src],
            F::TcpDstport | F::UdpDstport => vec![dst],
            _ => vec![src, dst],
        })
        .map(|p| Value::UInt(u64::from(p)))
        .collect()
}

impl Source for PacketView<'_> {
    fn values(&self, field: Field) -> Vec<Value<'_>> {
        let Field::Packet(field) = field else {
            return Vec::new();
        };
        let mut out = Vec::new();
        self.collect(field, &mut out);
        out
    }
}
