//! The packet fields a filter can use, with Wireshark's names and types, so
//! a filter means the same here as in Wireshark.

use super::names;

/// What a field holds. It decides how a value in a filter is read and
/// which operators work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A protocol layer: there or not, and its bytes for `contains`.
    Protocol,
    /// There or not, with no value: a protocol whose bytes aren't kept
    /// apart, or one of Wireshark's analysis flags.
    Marker,
    Bool,
    UInt,
    /// Seconds, kept in nanoseconds.
    Time,
    Str,
    Ipv4,
    Ipv6,
    Ether,
    Bytes,
    /// A finding's measurement.
    Number,
    /// A finding's severity: info < warning < error.
    Severity,
}

impl Kind {
    pub fn describe(self) -> &'static str {
        match self {
            Kind::Protocol => "protocol",
            Kind::Marker => "flag",
            Kind::Bool => "boolean",
            Kind::UInt => "number",
            Kind::Time => "time in seconds",
            Kind::Str => "string",
            Kind::Ipv4 => "IPv4 address",
            Kind::Ipv6 => "IPv6 address",
            Kind::Ether => "MAC address",
            Kind::Bytes => "bytes",
            Kind::Number => "number",
            Kind::Severity => "severity",
        }
    }
}

macro_rules! fields {
    ($($id:ident $name:literal $kind:ident $help:literal,)*) => {
        /// A packet field.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum F {
            $($id,)*
        }

        /// Every packet field: name, kind and a short description.
        pub const FIELDS: &[(F, &str, Kind, &str)] = &[
            $((F::$id, $name, Kind::$kind, $help),)*
        ];
    };
}

fields! {
    Frame "frame" Protocol "the whole frame",
    FrameNumber "frame.number" UInt "position in the capture, from 1",
    FrameLen "frame.len" UInt "length on the wire",
    FrameCapLen "frame.cap_len" UInt "bytes captured",
    FrameTimeRelative "frame.time_relative" Time "seconds since the first packet",
    FrameTimeDelta "frame.time_delta" Time "seconds since the previous packet",

    Eth "eth" Protocol "Ethernet",
    EthSrc "eth.src" Ether "source MAC address",
    EthDst "eth.dst" Ether "destination MAC address",
    EthAddr "eth.addr" Ether "source or destination MAC address",
    EthType "eth.type" UInt "EtherType",
    Vlan "vlan" Marker "802.1Q VLAN tag",
    VlanId "vlan.id" UInt "VLAN ID",

    Arp "arp" Marker "ARP",
    ArpOpcode "arp.opcode" UInt "1 request, 2 reply",
    ArpSrcHwMac "arp.src.hw_mac" Ether "sender MAC address",
    ArpSrcProtoIpv4 "arp.src.proto_ipv4" Ipv4 "sender IP address",
    ArpDstProtoIpv4 "arp.dst.proto_ipv4" Ipv4 "target IP address",

    Ip "ip" Protocol "IPv4",
    IpSrc "ip.src" Ipv4 "source address",
    IpDst "ip.dst" Ipv4 "destination address",
    IpAddr "ip.addr" Ipv4 "source or destination address",
    IpProto "ip.proto" UInt "protocol inside: 6 TCP, 17 UDP, 1 ICMP",
    IpTtl "ip.ttl" UInt "time to live",
    IpId "ip.id" UInt "identification",
    IpLen "ip.len" UInt "total length",
    IpHdrLen "ip.hdr_len" UInt "header length",
    IpFlagsDf "ip.flags.df" Bool "don't fragment",
    IpFlagsMf "ip.flags.mf" Bool "more fragments",

    Ipv6 "ipv6" Protocol "IPv6",
    Ipv6Src "ipv6.src" Ipv6 "source address",
    Ipv6Dst "ipv6.dst" Ipv6 "destination address",
    Ipv6Addr "ipv6.addr" Ipv6 "source or destination address",
    Ipv6Nxt "ipv6.nxt" UInt "next header",
    Ipv6Hlim "ipv6.hlim" UInt "hop limit",
    Ipv6Plen "ipv6.plen" UInt "payload length",

    Tcp "tcp" Protocol "TCP",
    TcpSrcport "tcp.srcport" UInt "source port",
    TcpDstport "tcp.dstport" UInt "destination port",
    TcpPort "tcp.port" UInt "source or destination port",
    TcpStream "tcp.stream" UInt "connection number, from 0",
    TcpLen "tcp.len" UInt "payload length",
    TcpSeq "tcp.seq" UInt "sequence number, from the start of the connection",
    TcpSeqRaw "tcp.seq_raw" UInt "sequence number as sent",
    TcpAck "tcp.ack" UInt "acknowledgment number, from the start of the connection",
    TcpAckRaw "tcp.ack_raw" UInt "acknowledgment number as sent",
    TcpNxtseq "tcp.nxtseq" UInt "sequence number after this segment",
    TcpHdrLen "tcp.hdr_len" UInt "header length",
    TcpFlags "tcp.flags" UInt "all flags: 0x02 SYN, 0x12 SYN-ACK, 0x04 RST, ...",
    TcpFlagsFin "tcp.flags.fin" Bool "FIN",
    TcpFlagsSyn "tcp.flags.syn" Bool "SYN",
    TcpFlagsReset "tcp.flags.reset" Bool "RST",
    TcpFlagsPush "tcp.flags.push" Bool "PSH",
    TcpFlagsAck "tcp.flags.ack" Bool "ACK",
    TcpFlagsUrg "tcp.flags.urg" Bool "URG",
    TcpFlagsEce "tcp.flags.ece" Bool "ECE",
    TcpFlagsCwr "tcp.flags.cwr" Bool "CWR",
    TcpFlagsAe "tcp.flags.ae" Bool "AE (accurate ECN)",
    TcpWindowSizeValue "tcp.window_size_value" UInt "window field as sent",
    TcpWindowSize "tcp.window_size" UInt "window after scaling",
    TcpOptionsMssVal "tcp.options.mss_val" UInt "maximum segment size option",
    TcpOptionsWscaleShift "tcp.options.wscale.shift" UInt "window scale option",
    TcpPayload "tcp.payload" Bytes "payload bytes",
    TcpAnalysisFlags "tcp.analysis.flags" Marker "any of the tcp.analysis flags below",
    TcpAnalysisRetransmission "tcp.analysis.retransmission" Marker "data sent again",
    TcpAnalysisFastRetransmission "tcp.analysis.fast_retransmission" Marker "sent again after duplicate ACKs",
    TcpAnalysisSpuriousRetransmission "tcp.analysis.spurious_retransmission" Marker "sent again, though it had been acknowledged",
    TcpAnalysisOutOfOrder "tcp.analysis.out_of_order" Marker "arrived after a later segment",
    TcpAnalysisLostSegment "tcp.analysis.lost_segment" Marker "an earlier segment wasn't captured",
    TcpAnalysisAckLostSegment "tcp.analysis.ack_lost_segment" Marker "acknowledges data that wasn't captured",
    TcpAnalysisDuplicateAck "tcp.analysis.duplicate_ack" Marker "repeats the previous ACK",
    TcpAnalysisDuplicateAckNum "tcp.analysis.duplicate_ack_num" UInt "how many times the ACK was repeated",
    TcpAnalysisDuplicateAckFrame "tcp.analysis.duplicate_ack_frame" UInt "frame of the ACK it repeats",
    TcpAnalysisZeroWindow "tcp.analysis.zero_window" Marker "receiver has no buffer left",
    TcpAnalysisZeroWindowProbe "tcp.analysis.zero_window_probe" Marker "checks whether a zero window opened",
    TcpAnalysisZeroWindowProbeAck "tcp.analysis.zero_window_probe_ack" Marker "answers a zero window probe",
    TcpAnalysisWindowFull "tcp.analysis.window_full" Marker "fills the receiver's window",
    TcpAnalysisWindowUpdate "tcp.analysis.window_update" Marker "only changes the window",
    TcpAnalysisKeepAlive "tcp.analysis.keep_alive" Marker "keep-alive",
    TcpAnalysisKeepAliveAck "tcp.analysis.keep_alive_ack" Marker "answers a keep-alive",
    TcpAnalysisInitialRtt "tcp.analysis.initial_rtt" Time "round trip of the handshake",

    Udp "udp" Protocol "UDP",
    UdpSrcport "udp.srcport" UInt "source port",
    UdpDstport "udp.dstport" UInt "destination port",
    UdpPort "udp.port" UInt "source or destination port",
    UdpLength "udp.length" UInt "length field",
    UdpStream "udp.stream" UInt "conversation number, from 0",
    UdpPayload "udp.payload" Bytes "payload bytes",

    Icmp "icmp" Marker "ICMP",
    IcmpType "icmp.type" UInt "8 echo request, 0 reply, 3 unreachable, 11 time exceeded",
    IcmpCode "icmp.code" UInt "code",
    Icmpv6 "icmpv6" Marker "ICMPv6",
    Icmpv6Type "icmpv6.type" UInt "type",
    Icmpv6Code "icmpv6.code" UInt "code",

    Dns "dns" Marker "DNS",
    DnsId "dns.id" UInt "transaction ID",
    DnsFlagsResponse "dns.flags.response" Bool "a response, not a query",
    DnsFlagsOpcode "dns.flags.opcode" UInt "0 standard query",
    DnsFlagsRcode "dns.flags.rcode" UInt "response code: 0 no error, 2 server failure, 3 no such name, 5 refused",
    DnsFlagsAuthoritative "dns.flags.authoritative" Bool "authoritative answer",
    DnsFlagsTruncated "dns.flags.truncated" Bool "truncated",
    DnsFlagsRecdesired "dns.flags.recdesired" Bool "recursion desired",
    DnsFlagsRecavail "dns.flags.recavail" Bool "recursion available",
    DnsQryName "dns.qry.name" Str "name asked for",
    DnsQryType "dns.qry.type" UInt "type asked for: A, AAAA, ...",
    DnsQryClass "dns.qry.class" UInt "class asked for",
    DnsCountQueries "dns.count.queries" UInt "questions",
    DnsCountAnswers "dns.count.answers" UInt "answer records",
    DnsCountAuthRr "dns.count.auth_rr" UInt "authority records",
    DnsCountAddRr "dns.count.add_rr" UInt "additional records",
    DnsRespName "dns.resp.name" Str "record name",
    DnsRespType "dns.resp.type" UInt "record type",
    DnsRespTtl "dns.resp.ttl" UInt "record time to live",
    DnsA "dns.a" Ipv4 "IPv4 address in a record",
    DnsAaaa "dns.aaaa" Ipv6 "IPv6 address in a record",
    DnsCname "dns.cname" Str "canonical name in a record",
    DnsPtrDomainName "dns.ptr.domain_name" Str "name in a PTR record",
    DnsTime "dns.time" Time "response time",
    DnsResponseIn "dns.response_in" UInt "frame of the response to this query",
    DnsResponseTo "dns.response_to" UInt "frame of the query this answers",
    DnsRetransmission "dns.retransmission" Bool "a query or response sent again",
    DnsRetransmitRequestIn "dns.retransmit_request_in" UInt "frame of the first copy of this query",
    DnsUnsolicited "dns.unsolicited" Bool "a response to a query that wasn't captured",

    Tls "tls" Marker "TLS records",
    TlsRecordContentType "tls.record.content_type" UInt "22 handshake, 23 application data, 21 alert",
    TlsRecordOpaqueType "tls.record.opaque_type" UInt "outer type of an encrypted TLS 1.3 record, always 23",
    TlsRecordVersion "tls.record.version" UInt "record version",
    TlsRecordLength "tls.record.length" UInt "record length",
    TlsHandshakeType "tls.handshake.type" UInt "1 Client Hello, 2 Server Hello, 11 Certificate, ...",
    TlsHandshakeVersion "tls.handshake.version" UInt "version in a hello",
    TlsHandshakeExtensionsServerName "tls.handshake.extensions_server_name" Str "server name (SNI)",
    TlsHandshakeExtensionsSupportedVersion "tls.handshake.extensions.supported_version" UInt "versions offered, or the one chosen",
    TlsHandshakeExtensionsAlpnStr "tls.handshake.extensions_alpn_str" Str "application protocols offered, or the one chosen",
    TlsHandshakeCiphersuite "tls.handshake.ciphersuite" UInt "cipher suites offered, or the one chosen",
    TlsAlertMessageLevel "tls.alert_message.level" UInt "1 warning, 2 fatal",
    TlsAlertMessageDesc "tls.alert_message.desc" UInt "alert: 40 handshake failure, 48 unknown CA, ...",

    Http "http" Marker "HTTP request or response head",
    HttpRequest "http.request" Bool "a request",
    HttpResponse "http.response" Bool "a response",
    HttpRequestMethod "http.request.method" Str "method",
    HttpRequestUri "http.request.uri" Str "path and query",
    HttpRequestVersion "http.request.version" Str "version in the request",
    HttpHost "http.host" Str "Host header",
    HttpResponseCode "http.response.code" UInt "status code",
    HttpResponsePhrase "http.response.phrase" Str "reason phrase",
    HttpResponseVersion "http.response.version" Str "version in the response",
    HttpContentLength "http.content_length" UInt "Content-Length header",
    HttpTime "http.time" Time "seconds since the request",
    HttpRequestIn "http.request_in" UInt "frame of the request this answers",
    HttpResponseIn "http.response_in" UInt "frame of the response to this request",
}

pub fn lookup(name: &str) -> Option<(F, Kind)> {
    FIELDS
        .iter()
        .find(|(_, n, _, _)| *n == name)
        .map(|&(f, _, kind, _)| (f, kind))
}

pub fn name(field: F) -> &'static str {
    entry(field).1
}

pub fn kind(field: F) -> Kind {
    entry(field).2
}

fn entry(field: F) -> &'static (F, &'static str, Kind, &'static str) {
    FIELDS
        .iter()
        .find(|(f, ..)| *f == field)
        .expect("every field is in the table")
}

/// The names a field's numbers go by, which a filter may use instead.
pub fn value_names(field: F) -> &'static [(u64, &'static str)] {
    match field {
        F::DnsQryType | F::DnsRespType => names::DNS_TYPES,
        F::DnsQryClass => names::DNS_CLASSES,
        F::DnsFlagsRcode => names::DNS_RCODES,
        F::DnsFlagsOpcode => names::DNS_OPCODES,
        F::TlsHandshakeType => names::TLS_HANDSHAKE_TYPES,
        F::TlsRecordContentType => names::TLS_CONTENT_TYPES,
        F::TlsAlertMessageDesc => names::TLS_ALERTS,
        F::TlsAlertMessageLevel => names::TLS_ALERT_LEVELS,
        F::TlsRecordVersion
        | F::TlsHandshakeVersion
        | F::TlsHandshakeExtensionsSupportedVersion => names::TLS_VERSIONS,
        F::ArpOpcode => names::ARP_OPCODES,
        F::IcmpType => names::ICMP_TYPES,
        F::Icmpv6Type => names::ICMPV6_TYPES,
        _ => &[],
    }
}

/// Fields that need more of the capture than the packets before, such as
/// the frame a response arrived in. Filters using them read the capture
/// twice.
pub fn needs_whole_capture(field: F) -> bool {
    matches!(
        field,
        F::DnsTime
            | F::DnsResponseIn
            | F::DnsResponseTo
            | F::DnsRetransmission
            | F::DnsRetransmitRequestIn
            | F::DnsUnsolicited
            | F::HttpResponseIn
            | F::TcpAnalysisInitialRtt
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_unique_and_lowercase() {
        let mut seen = std::collections::HashSet::new();
        for (field, name, ..) in FIELDS {
            assert!(seen.insert(*name), "{name} twice");
            assert_eq!(lookup(name).unwrap().0, *field);
            assert!(!name.chars().any(|c| c.is_ascii_uppercase()), "{name}");
        }
    }

    #[test]
    fn value_names_are_for_numbers() {
        for (field, name, kind, _) in FIELDS {
            if !value_names(*field).is_empty() {
                assert_eq!(*kind, Kind::UInt, "{name}");
            }
        }
    }
}
