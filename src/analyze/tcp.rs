//! TCP sequence analysis: retransmissions, out-of-order segments, duplicate
//! ACKs, zero windows and similar, decided per segment.
//!
//! The rules follow Wireshark's `tcp.analysis.*` flags (from
//! `tcp_analyze_sequence_number` in epan/dissectors/packet-tcp.c, 4.6) and
//! are checked in the same order, so results can be compared with tshark
//! frame by frame. Two small differences:
//! - SACK blocks are compared with raw sequence numbers on both sides.
//!   Wireshark stores them relative but compares them with raw numbers, so it
//!   never treats a segment as already SACKed.
//! - Acknowledged segments are only dropped from the unacked list when the ACK
//!   flag is set.
//!
//! Like Wireshark, a time that was never set counts as the Unix epoch. That
//! only matters for captures timestamped near 1970, such as generated ones.

use std::fmt;

use crate::capture::Timestamp;
use crate::decode::{Tcp, TcpFlags};
use crate::flow::Side;

/// Wireshark stops tracking unacknowledged segments past this many.
const MAX_UNACKED: usize = 10_000;
/// A retransmission this soon after the duplicate ACKs asking for it is a fast retransmission.
const FAST_RETRANSMISSION_NS: u64 = 20_000_000;
/// Out-of-order threshold when the handshake RTT is unknown.
const DEFAULT_OUT_OF_ORDER_NS: u64 = 3_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpEvent {
    /// Data sent again: the earlier copy was lost or not acknowledged in time.
    Retransmission,
    /// Retransmission triggered by duplicate ACKs rather than a timeout.
    FastRetransmission,
    /// Retransmission of data the receiver had already acknowledged.
    SpuriousRetransmission,
    /// Segment that arrived after one with a higher sequence number.
    OutOfOrder,
    /// A gap in the sequence numbers: data the capture never saw.
    PreviousSegmentNotCaptured,
    /// Acknowledges data the capture never saw.
    AckedUnseenSegment,
    /// Repeats the previous ACK, usually because the receiver is missing a
    /// segment. `number` counts repeats of the ACK sent in `of_frame`.
    DuplicateAck {
        number: u32,
        of_frame: u64,
    },
    /// The receiver has no buffer space left; the sender must stop.
    ZeroWindow,
    /// One byte sent to see whether a zero window has opened.
    ZeroWindowProbe,
    ZeroWindowProbeAck,
    /// The sender has filled the receiver's whole window.
    WindowFull,
    /// Pure ACK that only changes the window.
    WindowUpdate,
    KeepAlive,
    KeepAliveAck,
}

impl TcpEvent {
    fn bit(self) -> u16 {
        match self {
            TcpEvent::Retransmission => 1 << 0,
            TcpEvent::FastRetransmission => 1 << 1,
            TcpEvent::SpuriousRetransmission => 1 << 2,
            TcpEvent::OutOfOrder => 1 << 3,
            TcpEvent::PreviousSegmentNotCaptured => 1 << 4,
            TcpEvent::AckedUnseenSegment => 1 << 5,
            TcpEvent::DuplicateAck { .. } => 1 << 6,
            TcpEvent::ZeroWindow => 1 << 7,
            TcpEvent::ZeroWindowProbe => 1 << 8,
            TcpEvent::ZeroWindowProbeAck => 1 << 9,
            TcpEvent::WindowFull => 1 << 10,
            TcpEvent::WindowUpdate => 1 << 11,
            TcpEvent::KeepAlive => 1 << 12,
            TcpEvent::KeepAliveAck => 1 << 13,
        }
    }
}

impl fmt::Display for TcpEvent {
    /// The labels Wireshark shows in its Info column.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TcpEvent::Retransmission => f.write_str("TCP Retransmission"),
            TcpEvent::FastRetransmission => f.write_str("TCP Fast Retransmission"),
            TcpEvent::SpuriousRetransmission => f.write_str("TCP Spurious Retransmission"),
            TcpEvent::OutOfOrder => f.write_str("TCP Out-Of-Order"),
            TcpEvent::PreviousSegmentNotCaptured => {
                f.write_str("TCP Previous segment not captured")
            }
            TcpEvent::AckedUnseenSegment => f.write_str("TCP ACKed unseen segment"),
            TcpEvent::DuplicateAck { number, of_frame } => {
                write!(f, "TCP Dup ACK {of_frame}#{number}")
            }
            TcpEvent::ZeroWindow => f.write_str("TCP ZeroWindow"),
            TcpEvent::ZeroWindowProbe => f.write_str("TCP ZeroWindowProbe"),
            TcpEvent::ZeroWindowProbeAck => f.write_str("TCP ZeroWindowProbeAck"),
            TcpEvent::WindowFull => f.write_str("TCP Window Full"),
            TcpEvent::WindowUpdate => f.write_str("TCP Window Update"),
            TcpEvent::KeepAlive => f.write_str("TCP Keep-Alive"),
            TcpEvent::KeepAliveAck => f.write_str("TCP Keep-Alive ACK"),
        }
    }
}

/// Events found for one segment.
#[derive(Debug, Clone, Default)]
struct Events {
    list: Vec<TcpEvent>,
    bits: u16,
}

impl Events {
    fn add(&mut self, event: TcpEvent) {
        self.bits |= event.bit();
        self.list.push(event);
    }

    fn has(&self, event: TcpEvent) -> bool {
        self.bits & event.bit() != 0
    }

    fn remove(&mut self, event: TcpEvent) {
        self.bits &= !event.bit();
        self.list.retain(|e| e.bit() != event.bit());
    }
}

/// Counts of one kind of event, with the first and last frame for evidence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tally {
    pub count: u32,
    pub first_frame: u64,
    pub last_frame: u64,
}

impl Tally {
    fn add(&mut self, frame: u64) {
        if self.count == 0 {
            self.first_frame = frame;
        }
        self.count += 1;
        self.last_frame = frame;
    }
}

/// What went wrong in one direction of a connection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TcpHealth {
    /// Segments carrying data, SYN or FIN: the ones that can be
    /// retransmitted, so the denominator for retransmission rates.
    pub segments: u64,
    /// Every retransmission, including fast and spurious ones.
    pub retransmissions: Tally,
    pub fast_retransmissions: Tally,
    pub spurious_retransmissions: Tally,
    pub out_of_order: Tally,
    pub not_captured: Tally,
    pub acked_unseen: Tally,
    pub duplicate_acks: Tally,
    pub zero_windows: Tally,
    pub window_full: Tally,
}

impl TcpHealth {
    pub(crate) fn record(&mut self, tcp: &Tcp, frame: u64, events: &[TcpEvent]) {
        let flags = tcp.flags;
        if tcp.payload_len > 0 || flags.has(TcpFlags::SYN) || flags.has(TcpFlags::FIN) {
            self.segments += 1;
        }
        for event in events {
            match event {
                TcpEvent::Retransmission => self.retransmissions.add(frame),
                TcpEvent::FastRetransmission => {
                    self.retransmissions.add(frame);
                    self.fast_retransmissions.add(frame);
                }
                TcpEvent::SpuriousRetransmission => {
                    self.retransmissions.add(frame);
                    self.spurious_retransmissions.add(frame);
                }
                TcpEvent::OutOfOrder => self.out_of_order.add(frame),
                TcpEvent::PreviousSegmentNotCaptured => self.not_captured.add(frame),
                TcpEvent::AckedUnseenSegment => self.acked_unseen.add(frame),
                TcpEvent::DuplicateAck { .. } => self.duplicate_acks.add(frame),
                TcpEvent::ZeroWindow => self.zero_windows.add(frame),
                TcpEvent::WindowFull => self.window_full.add(frame),
                TcpEvent::ZeroWindowProbe
                | TcpEvent::ZeroWindowProbeAck
                | TcpEvent::WindowUpdate
                | TcpEvent::KeepAlive
                | TcpEvent::KeepAliveAck => {}
            }
        }
    }

    /// Adds `other`'s counts into this one, e.g. to total a whole capture.
    pub fn add(&mut self, other: &TcpHealth) {
        self.segments += other.segments;
        merge(&mut self.retransmissions, &other.retransmissions);
        merge(&mut self.fast_retransmissions, &other.fast_retransmissions);
        merge(
            &mut self.spurious_retransmissions,
            &other.spurious_retransmissions,
        );
        merge(&mut self.out_of_order, &other.out_of_order);
        merge(&mut self.not_captured, &other.not_captured);
        merge(&mut self.acked_unseen, &other.acked_unseen);
        merge(&mut self.duplicate_acks, &other.duplicate_acks);
        merge(&mut self.zero_windows, &other.zero_windows);
        merge(&mut self.window_full, &other.window_full);
    }
}

fn merge(into: &mut Tally, from: &Tally) {
    if from.count == 0 {
        return;
    }
    if into.count == 0 {
        *into = *from;
        return;
    }
    into.count += from.count;
    into.first_frame = into.first_frame.min(from.first_frame);
    into.last_frame = into.last_frame.max(from.last_frame);
}

/// Window scaling for one direction, learned from the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum WindowScale {
    /// The handshake wasn't seen.
    #[default]
    Unknown,
    /// Not negotiated; window fields are used as they are.
    Off,
    Shift(u8),
}

/// A segment sent but not yet acknowledged: sequence range `seq..end`.
#[derive(Debug, Clone, Copy)]
struct Unacked {
    seq: u32,
    end: u32,
}

/// What we know about one direction of the connection.
#[derive(Debug, Clone, Default)]
struct Direction {
    /// Sequence number after the highest byte sent so far.
    next_seq: Option<u32>,
    /// Highest sequence number sent without a gap before it.
    max_seq_to_be_acked: Option<u32>,
    /// Payload length of the segment that last moved `next_seq` forward.
    last_advance_len: u32,
    /// Acknowledgement number of the last segment, and when it was sent.
    last_ack: Option<u32>,
    /// Epoch until set, as in Wireshark.
    last_ack_ts: Timestamp,
    /// Raw window field of the last segment.
    window: Option<u16>,
    scale: WindowScale,
    /// True from this side's SYN until it sends its first ACK; the window
    /// field isn't scaled before that.
    before_first_ack: bool,
    dup_acks: u32,
    last_non_dup_ack_frame: u64,
    /// SACK blocks from the last segment.
    sack: Vec<(u32, u32)>,
    unacked: Vec<Unacked>,
    /// Events of the last segment (as bits).
    last_events: u16,
    /// Wireshark counts this side's bytes in flight once the other side has
    /// sent an ACK, and stops after a gap until the next one.
    counts_in_flight: bool,
}

impl Direction {
    fn last_was(&self, event: TcpEvent) -> bool {
        self.last_events & event.bit() != 0
    }
}

#[derive(Debug, Clone, Default)]
pub struct TcpAnalyzer {
    /// Indexed by side: client, server.
    dirs: [Direction; 2],
    /// Time of the most recent SYN (without ACK).
    last_syn: Option<Timestamp>,
    /// From the most recent SYN to the first ACK after it; Wireshark's
    /// `tcp.analysis.initial_rtt`.
    initial_rtt_ns: Option<u64>,
    /// The last segment acknowledged one of the other side's segments, which
    /// Wireshark shows as "This is an ACK to the segment in frame N".
    acked_segment: bool,
    /// The last segment had something for Wireshark's SEQ/ACK analysis tree.
    analyzed: bool,
}

impl TcpAnalyzer {
    /// Initial round-trip time in seconds.
    pub fn initial_rtt(&self) -> Option<f64> {
        self.initial_rtt_ns.map(|ns| ns as f64 / 1e9)
    }

    pub fn initial_rtt_ns(&self) -> Option<u64> {
        self.initial_rtt_ns
    }

    /// Whether Wireshark gives the last segment a SEQ/ACK analysis tree: it
    /// acknowledged a segment, carried data counted in flight, or got a
    /// flag. Fields such as `tcp.analysis.initial_rtt` are only shown there.
    pub fn last_analyzed(&self) -> bool {
        self.analyzed
    }

    /// How far `side`'s window field is shifted: what Wireshark multiplies
    /// it by for `tcp.window_size`. 0 unless the handshake turned scaling on.
    pub fn window_shift(&self, side: Side) -> u8 {
        match self.dirs[side_index(side)].scale {
            WindowScale::Shift(shift) => shift,
            WindowScale::Unknown | WindowScale::Off => 0,
        }
    }

    /// Analyzes one segment sent by `side`.
    pub fn segment(&mut self, side: Side, tcp: &Tcp, frame: u64, ts: Timestamp) -> Vec<TcpEvent> {
        let own = side_index(side);
        // Wireshark reads SACK blocks while dissecting options, after the
        // analysis, so the analysis only sees the other side's blocks.
        self.dirs[own].sack.clear();
        let mut events = self.analyze(side, tcp, frame, ts);
        self.learn_from_handshake(side, tcp, ts);

        let fwd = &mut self.dirs[own];
        fwd.sack = tcp.options.sack.iter().take(4).copied().collect();
        // A "window update" that carries SACK blocks is really a duplicate ACK.
        if !fwd.sack.is_empty() && events.has(TcpEvent::WindowUpdate) {
            events.remove(TcpEvent::WindowUpdate);
            fwd.dup_acks += 1;
            events.add(TcpEvent::DuplicateAck {
                number: fwd.dup_acks,
                of_frame: fwd.last_non_dup_ack_frame,
            });
        }
        let in_flight = tcp.payload_len > 0 && self.dirs[own].counts_in_flight;
        self.analyzed = self.acked_segment || in_flight || !events.list.is_empty();
        events.list
    }

    fn analyze(&mut self, side: Side, tcp: &Tcp, frame: u64, ts: Timestamp) -> Events {
        let ooo_threshold = self.initial_rtt_ns.unwrap_or(DEFAULT_OUT_OF_ORDER_NS);
        let [client, server] = &mut self.dirs;
        let (fwd, rev) = match side {
            Side::Client => (client, server),
            Side::Server => (server, client),
        };
        let (seq, ack, window, len) = (tcp.seq, tcp.ack, tcp.window, tcp.payload_len);
        let flags = tcp.flags;
        let syn_or_fin = flags.has(TcpFlags::SYN) || flags.has(TcpFlags::FIN);
        let control = syn_or_fin || flags.has(TcpFlags::RST);
        let mut ev = Events::default();
        if flags.has(TcpFlags::ACK) {
            rev.counts_in_flight = true;
        }

        'fwd: {
            if len == 1 && fwd.next_seq == Some(seq) && rev.window == Some(0) {
                ev.add(TcpEvent::ZeroWindowProbe);
                break 'fwd;
            }
            if window == 0 && !control {
                ev.add(TcpEvent::ZeroWindow);
            }
            if let Some(next) = fwd.next_seq
                && seq_gt(seq, next)
                && !flags.has(TcpFlags::RST)
            {
                ev.add(TcpEvent::PreviousSegmentNotCaptured);
                fwd.counts_in_flight = false;
            }
            if len <= 1 && fwd.next_seq.is_some_and(|n| seq == n.wrapping_sub(1)) && !control {
                ev.add(TcpEvent::KeepAlive);
            }
            // Pure ACK repeating the previous sequence and ack numbers.
            let repeat =
                len == 0 && !control && fwd.next_seq == Some(seq) && fwd.last_ack == Some(ack);
            if repeat && window != 0 && fwd.window != Some(window) {
                ev.add(TcpEvent::WindowUpdate);
            }
            if len > 0
                && !control
                && rev.scale != WindowScale::Unknown
                && let (Some(rev_ack), Some(rev_window)) = (rev.last_ack, rev.window)
            {
                let shift = match rev.scale {
                    WindowScale::Shift(s) if !rev.before_first_ack => u32::from(s),
                    _ => 0,
                };
                let window_end = rev_ack.wrapping_add(u32::from(rev_window) << shift);
                if seq.wrapping_add(len) == window_end {
                    ev.add(TcpEvent::WindowFull);
                }
            }
            if repeat
                && window != 0
                && fwd.window == Some(window)
                && rev.last_was(TcpEvent::KeepAlive)
            {
                ev.add(TcpEvent::KeepAliveAck);
                break 'fwd;
            }
            if len == 0
                && !control
                && window == 0
                && fwd.window == Some(0)
                && fwd.next_seq == Some(seq)
                && fwd
                    .last_ack
                    .is_some_and(|a| ack == a || ack == a.wrapping_add(1))
                && rev.last_was(TcpEvent::ZeroWindowProbe)
            {
                ev.add(TcpEvent::ZeroWindowProbeAck);
                // The receiver took the probe's byte after all.
                if fwd.last_ack.is_some_and(|a| ack == a.wrapping_add(1)) {
                    rev.next_seq = Some(ack);
                    rev.max_seq_to_be_acked = Some(ack);
                }
                break 'fwd;
            }
            if repeat && window != 0 && fwd.window == Some(window) {
                fwd.dup_acks += 1;
                ev.add(TcpEvent::DuplicateAck {
                    number: fwd.dup_acks,
                    of_frame: fwd.last_non_dup_ack_frame,
                });
            }
        }
        if fwd.last_ack != Some(ack) {
            fwd.last_non_dup_ack_frame = frame;
            fwd.dup_acks = 0;
        }

        if flags.has(TcpFlags::ACK)
            && let Some(max) = rev.max_seq_to_be_acked
            && seq_gt(ack, max)
        {
            let reopens_after_probe = fwd.last_ack.is_some_and(|a| ack == a.wrapping_add(1))
                && fwd.next_seq == Some(seq)
                && rev.last_was(TcpEvent::ZeroWindowProbe);
            if reopens_after_probe {
                rev.next_seq = Some(ack);
                rev.max_seq_to_be_acked = Some(ack);
                ev.add(TcpEvent::WindowUpdate);
            } else {
                rev.max_seq_to_be_acked = Some(acked_tail(&rev.unacked, ack));
                ev.add(TcpEvent::AckedUnseenSegment);
            }
        }

        if len > 0 || syn_or_fin {
            self::classify_resend(fwd, rev, &mut ev, tcp, ts, ooo_threshold);
        }

        // Record what this segment sent.
        let mut end = seq.wrapping_add(len);
        if syn_or_fin {
            end = end.wrapping_add(1);
        }
        if (len > 0 || syn_or_fin) && fwd.unacked.len() < MAX_UNACKED {
            fwd.unacked.push(Unacked { seq, end });
        }
        let advances = fwd.next_seq.is_none_or(|n| seq_gt(end, n));
        if fwd
            .next_seq
            .is_none_or(|n| seq_gt(end, n.wrapping_add(u32::from(syn_or_fin))))
        {
            fwd.last_advance_len = len;
        }
        let probe = ev.has(TcpEvent::ZeroWindowProbe);
        if advances && !probe {
            fwd.next_seq = Some(end);
        }
        if (fwd.max_seq_to_be_acked.is_none() || fwd.max_seq_to_be_acked == Some(seq)) && !probe {
            fwd.max_seq_to_be_acked = fwd.next_seq;
        }
        fwd.window = Some(window);
        fwd.last_ack = Some(ack);
        fwd.last_ack_ts = ts;
        fwd.last_events = ev.bits;
        // Wireshark looks for the segments this acknowledges, wholly or in
        // part, whatever the flags.
        self.acked_segment = rev
            .unacked
            .iter()
            .any(|u| seq_gt(ack, u.seq) && !seq_gt(ack, u.end));
        if flags.has(TcpFlags::ACK) {
            drop_acked(&mut rev.unacked, ack);
        }
        ev
    }

    /// Wireshark notes the SYN time, the initial RTT and window scaling after
    /// its sequence analysis, so they only affect later segments.
    fn learn_from_handshake(&mut self, side: Side, tcp: &Tcp, ts: Timestamp) {
        let flags = tcp.flags;
        let [client, server] = &mut self.dirs;
        let (fwd, rev) = match side {
            Side::Client => (client, server),
            Side::Server => (server, client),
        };
        if flags.has(TcpFlags::SYN) {
            if !flags.has(TcpFlags::ACK) {
                self.last_syn = Some(ts);
            }
            fwd.before_first_ack = true;
            if let Some(shift) = tcp.options.window_scale {
                fwd.scale = WindowScale::Shift(shift.min(14));
            }
            // Scaling only applies when both SYN and SYN-ACK offer it.
            if fwd.scale == WindowScale::Unknown {
                fwd.scale = WindowScale::Off;
                rev.scale = WindowScale::Off;
            } else if flags.has(TcpFlags::ACK) && rev.scale == WindowScale::Off {
                fwd.scale = WindowScale::Off;
            }
        } else if flags.has(TcpFlags::ACK) {
            // A SYN at time zero counts as no SYN, as in Wireshark.
            if let Some(syn) = self.last_syn
                && syn.0 != 0
                && self.initial_rtt_ns.is_none()
            {
                self.initial_rtt_ns = Some(ts.0.saturating_sub(syn.0));
            }
            fwd.before_first_ack = false;
        }
    }
}

/// Decides what kind of resend a segment carrying data (or SYN/FIN) is, if any.
fn classify_resend(
    fwd: &Direction,
    rev: &Direction,
    ev: &mut Events,
    tcp: &Tcp,
    ts: Timestamp,
    ooo_threshold: u64,
) {
    if ev.has(TcpEvent::KeepAlive) {
        return;
    }
    let (seq, len) = (tcp.seq, tcp.payload_len);
    let mut behind = fwd.next_seq.is_some_and(|n| seq_lt(seq, n));
    // New data starting one byte early, right after a zero window probe.
    if len > 1 && fwd.next_seq.is_some_and(|n| n.wrapping_sub(1) == seq) {
        behind = false;
    }
    let end = seq.wrapping_add(len);
    if len > 0 && rev.last_ack.is_some_and(|a| a != 0 && seq_le(end, a)) {
        ev.add(TcpEvent::SpuriousRetransmission);
        return;
    }
    if !behind {
        return;
    }
    // Time since the other side last sent anything (and so its last ACK).
    let since_rev_ack = ts.0.saturating_sub(rev.last_ack_ts.0);
    if since_rev_ack < FAST_RETRANSMISSION_NS && rev.dup_acks >= 2 {
        let asked_for = rev.last_ack == Some(seq);
        let sacked = rev
            .sack
            .iter()
            .any(|&(l, r)| seq_ge(seq, l) && seq_le(end, r));
        if asked_for || (!rev.sack.is_empty() && !sacked) {
            ev.add(TcpEvent::FastRetransmission);
            return;
        }
    }
    let already_sent = fwd
        .unacked
        .iter()
        .any(|u| seq_ge(seq, u.seq) && seq_le(end, u.end));
    if since_rev_ack < ooo_threshold && !already_sent {
        let syn_or_fin = tcp.flags.has(TcpFlags::SYN) || tcp.flags.has(TcpFlags::FIN);
        let fills_gap_exactly = fwd.next_seq == Some(end.wrapping_add(u32::from(syn_or_fin)));
        if !fills_gap_exactly || fwd.last_advance_len == 0 {
            ev.add(TcpEvent::OutOfOrder);
            return;
        }
    }
    ev.add(TcpEvent::Retransmission);
}

/// After an ACK for data we never saw, the receiver may also hold segments we
/// did see that continue right where that ACK ends. Returns the end of that
/// run, so the same gap isn't reported again for each of them.
fn acked_tail(unacked: &[Unacked], ack: u32) -> u32 {
    let (mut left, mut right) = (0u32, 0u32);
    // Newest first, as Wireshark walks its list.
    for u in unacked.iter().rev() {
        if left == right {
            left = u.seq;
            right = u.end;
        }
        if seq_ge(u.seq, ack) {
            if u.end == left {
                left = u.seq;
            } else {
                left = u.seq;
                right = u.end;
            }
        }
    }
    if left == ack && seq_gt(right, ack) {
        right
    } else {
        ack
    }
}

/// Removes segments that `ack` covers; trims one it covers in part.
fn drop_acked(unacked: &mut Vec<Unacked>, ack: u32) {
    unacked.retain_mut(|u| {
        if seq_gt(ack, u.seq) && seq_lt(ack, u.end) {
            u.seq = ack;
            true
        } else {
            seq_gt(u.end, ack)
        }
    });
}

fn side_index(side: Side) -> usize {
    match side {
        Side::Client => 0,
        Side::Server => 1,
    }
}

/// Sequence number comparisons that survive 32-bit wraparound (RFC 1982).
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

fn seq_gt(a: u32, b: u32) -> bool {
    seq_lt(b, a)
}

fn seq_le(a: u32, b: u32) -> bool {
    !seq_gt(a, b)
}

fn seq_ge(a: u32, b: u32) -> bool {
    !seq_lt(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_comparisons_wrap() {
        assert!(seq_lt(u32::MAX - 5, 3));
        assert!(seq_gt(3, u32::MAX - 5));
        assert!(seq_le(7, 7) && seq_ge(7, 7));
        assert!(!seq_lt(7, 7));
    }

    #[test]
    fn acked_segments_are_dropped_or_trimmed() {
        let mut list = vec![
            Unacked { seq: 100, end: 200 },
            Unacked { seq: 200, end: 300 },
            Unacked { seq: 300, end: 400 },
        ];
        drop_acked(&mut list, 250);
        assert_eq!(list.len(), 2);
        assert_eq!((list[0].seq, list[0].end), (250, 300));
        drop_acked(&mut list, 400);
        assert!(list.is_empty());
    }

    #[test]
    fn acked_tail_skips_over_segments_seen_after_the_gap() {
        // We saw 300..400 and 400..500 but never 200..300; the ACK says 300.
        let list = vec![
            Unacked { seq: 300, end: 400 },
            Unacked { seq: 400, end: 500 },
        ];
        assert_eq!(acked_tail(&list, 300), 500);
        assert_eq!(acked_tail(&list, 250), 250);
    }
}
