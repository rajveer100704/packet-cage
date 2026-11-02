//! DNS for filters: which packets carry DNS, and Wireshark's matching of
//! responses to queries behind `dns.time`, `dns.response_in` and the other
//! state fields.
//!
//! The report matches lookups its own way: a query sent again after five
//! seconds is still the same lookup, so its time counts from the first try.
//! Wireshark starts a new transaction then, and filters follow Wireshark so
//! they pick the same packets. The rules are from `dissect_dns_common` in
//! Wireshark 4.6's packet-dns.c.

use std::collections::HashMap;
use std::net::SocketAddr;

use crate::analyze::PacketFindings;
use crate::capture::{Frame, Timestamp};
use crate::decode::dns::{self as wire, Message};
use crate::decode::{Packet, Transport};

const MDNS_PORT: u16 = 5353;
const LLMNR_PORT: u16 = 5355;
/// A query repeated sooner than this, unanswered, is a retransmission.
const RETRANSMISSION_NS: u64 = 5_000_000_000;
const TYPE_IXFR: u16 = 251;
const TYPE_AXFR: u16 = 252;

/// Which protocol carries the DNS message. They share Wireshark's `dns.*`
/// fields, but only plain DNS matches `dns`, and LLMNR has other flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    Dns,
    Mdns,
    Llmnr,
}

/// An mDNS or LLMNR message, which the analysis leaves alone. Wireshark
/// decodes them on their own ports.
pub fn multicast_message(pkt: &Packet<'_>) -> Option<(Message, Flavor)> {
    let Some(Transport::Udp(udp)) = &pkt.transport else {
        return None;
    };
    let flavor = match (udp.src_port, udp.dst_port) {
        (MDNS_PORT, _) | (_, MDNS_PORT) => Flavor::Mdns,
        (LLMNR_PORT, _) | (_, LLMNR_PORT) => Flavor::Llmnr,
        _ => return None,
    };
    let mut message = wire::parse_partial(pkt.payload)?;
    if flavor == Flavor::Mdns {
        // The top bit of the class asks for a unicast answer.
        for q in &mut message.questions {
            q.qclass &= 0x7fff;
        }
    }
    Some((message, flavor))
}

/// What Wireshark shows about a message's transaction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct State {
    pub response_in: Option<u64>,
    pub response_to: Option<u64>,
    pub time_ns: Option<i64>,
    pub retransmission: bool,
    pub retransmit_request_in: Option<u64>,
    pub unsolicited: bool,
}

#[derive(Debug)]
struct Transaction {
    request_frame: u64,
    response_frame: Option<u64>,
    request_ts: Timestamp,
    /// Zone transfers are answered by several responses.
    many_responses: bool,
}

/// Where a transaction lives: the flow, or for LLMNR the address that asked,
/// since the query goes to a multicast group and the answer comes back
/// directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Conversation {
    Flow(usize),
    Asker(SocketAddr),
}

impl Conversation {
    pub fn of(
        pkt: &Packet<'_>,
        found: &PacketFindings,
        message: &Message,
        flavor: Flavor,
    ) -> Option<Conversation> {
        if flavor == Flavor::Llmnr {
            let (Some(Transport::Udp(udp)), Some((src, dst))) = (
                &pkt.transport,
                pkt.network.as_ref().and_then(|n| n.ip_addrs()),
            ) else {
                return None;
            };
            return Some(Conversation::Asker(if message.response {
                SocketAddr::new(dst, udp.dst_port)
            } else {
                SocketAddr::new(src, udp.src_port)
            }));
        }
        Some(Conversation::Flow(found.flow.as_ref()?.flow.index))
    }
}

/// Transactions by conversation and ID, built over the whole capture.
#[derive(Debug, Default)]
pub struct Transactions {
    by_key: HashMap<(Conversation, u16), Vec<Transaction>>,
}

impl Transactions {
    /// Records the DNS messages of a packet, in capture order.
    pub fn observe(&mut self, frame: &Frame, pkt: &Packet<'_>, found: &PacketFindings) {
        let multicast = multicast_message(pkt);
        let messages = found.dns.messages.iter().map(|s| (&s.message, Flavor::Dns));
        for (message, flavor) in messages.chain(multicast.iter().map(|(m, f)| (m, *f))) {
            if let Some(conversation) = Conversation::of(pkt, found, message, flavor) {
                self.first_pass(conversation, frame, message);
            }
        }
    }

    fn first_pass(&mut self, conversation: Conversation, frame: &Frame, message: &Message) {
        let list = self.by_key.entry((conversation, message.id)).or_default();
        let zone_transfer = message
            .questions
            .first()
            .is_some_and(|q| matches!(q.qtype, TYPE_AXFR | TYPE_IXFR));
        if !message.response {
            let repeat = list.last().is_some_and(|t| {
                t.response_frame.is_none()
                    && frame.ts.0.saturating_sub(t.request_ts.0) < RETRANSMISSION_NS
            });
            if !repeat {
                list.push(Transaction {
                    request_frame: frame.number,
                    response_frame: None,
                    request_ts: frame.ts,
                    many_responses: false,
                });
            }
        } else if let Some(t) = list.last_mut() {
            t.response_frame.get_or_insert(frame.number);
        }
        if !message.questions.is_empty()
            && let Some(t) = list.last_mut()
        {
            t.many_responses = zone_transfer;
        }
    }

    /// What Wireshark shows for `message` in `frame`, after the first pass.
    pub fn state(&self, conversation: Conversation, frame: &Frame, message: &Message) -> State {
        let mut state = State::default();
        let transaction = self
            .by_key
            .get(&(conversation, message.id))
            .and_then(|list| list.iter().rev().find(|t| t.request_frame <= frame.number));
        if !message.response {
            match transaction {
                Some(t) if t.request_frame != frame.number => {
                    state.retransmission = true;
                    state.retransmit_request_in = Some(t.request_frame);
                }
                Some(t) => state.response_in = t.response_frame,
                None => {}
            }
            return state;
        }
        match transaction {
            Some(t) if t.response_frame.is_some_and(|r| r != frame.number) && !t.many_responses => {
                state.retransmission = true;
            }
            Some(t) => {
                state.response_to = Some(t.request_frame);
                state.time_ns = Some((i128::from(frame.ts.0) - i128::from(t.request_ts.0)) as i64);
            }
            None => state.unsolicited = true,
        }
        state
    }
}
