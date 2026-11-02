//! Puts one direction of a TCP connection back in order, for protocols whose
//! messages span segments: DNS over TCP, TLS, HTTP.
//!
//! Segments that arrive ahead of a gap wait until the gap fills, as happens
//! when a capture sees packets out of order. If it never fills (the capture
//! missed a segment) and too much piles up, the message boundaries are lost
//! and the direction is given up from there on.

use std::collections::{BTreeMap, VecDeque};

use crate::capture::Timestamp;
use crate::decode::{Tcp, TcpFlags};

/// When a byte of the stream arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arrival {
    pub frame: u64,
    pub ts: Timestamp,
}

/// Most segments held waiting for a gap to fill.
const MAX_EARLY_SEGMENTS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum State {
    #[default]
    Following,
    /// Data went missing: a gap, or a segment the capture cut short.
    Lost,
    /// The protocol parser needs nothing more.
    Stopped,
}

#[derive(Debug, Default)]
pub struct Reassembler {
    next_seq: Option<u32>,
    buf: Vec<u8>,
    /// Stream offset of `buf[0]`; the first byte of the stream is offset 0.
    start: u64,
    /// For each buffered segment: the stream offset just past it, and when
    /// it arrived. Oldest first.
    arrivals: VecDeque<(u64, Arrival)>,
    /// Segments that arrived ahead of a gap, by the stream offset where they
    /// start.
    early: BTreeMap<u64, Vec<u8>>,
    early_bytes: usize,
    state: State,
}

impl Reassembler {
    /// Adds a segment's payload and returns how many new bytes it added.
    /// More than `limit` unconsumed bytes counts as losing the stream, so a
    /// parser that never finds a message boundary can't hold unlimited memory.
    pub fn push(&mut self, tcp: &Tcp, payload: &[u8], at: Arrival, limit: usize) -> usize {
        let mut seq = tcp.seq;
        if tcp.flags.has(TcpFlags::SYN) {
            // The SYN takes one sequence number; data on it (TCP Fast Open)
            // starts right after.
            seq = seq.wrapping_add(1);
            *self = Reassembler {
                next_seq: Some(seq),
                ..Reassembler::default()
            };
        }
        if self.state != State::Following || tcp.payload_len == 0 {
            return 0;
        }
        if payload.len() < tcp.payload_len as usize {
            self.lose();
            return 0;
        }
        // Joined mid-connection: start wherever this segment starts.
        let next = *self.next_seq.get_or_insert(seq);
        let overlap = next.wrapping_sub(seq) as i32;
        if overlap < 0 {
            // Ahead of a gap: hold it until the gap fills.
            let full = self.early.len() >= MAX_EARLY_SEGMENTS
                || self.buf.len() + self.early_bytes + payload.len() > limit;
            if full {
                self.lose();
            } else {
                let offset = self.end() + u64::from(overlap.unsigned_abs());
                if let std::collections::btree_map::Entry::Vacant(slot) = self.early.entry(offset) {
                    self.early_bytes += payload.len();
                    slot.insert(payload.to_vec());
                }
            }
            return 0;
        }
        let Some(new) = payload.get(overlap as usize..).filter(|d| !d.is_empty()) else {
            return 0; // a retransmission of data we already have
        };
        if self.buf.len() + self.early_bytes + new.len() > limit {
            self.lose();
            return 0;
        }
        let mut added = self.append(new, at);
        // Early segments that now line up. Their bytes count as arriving now,
        // when they became readable in order.
        while let Some((&offset, _)) = self.early.first_key_value() {
            let end = self.end();
            if offset > end {
                break;
            }
            let (_, data) = self.early.pop_first().expect("checked above");
            self.early_bytes -= data.len();
            if let Some(rest) = data
                .get((end - offset) as usize..)
                .filter(|d| !d.is_empty())
            {
                added += self.append(rest, at);
            }
        }
        added
    }

    /// Stream offset just past the last byte received in order.
    fn end(&self) -> u64 {
        self.start + self.buf.len() as u64
    }

    fn append(&mut self, data: &[u8], at: Arrival) -> usize {
        self.buf.extend_from_slice(data);
        let next = self.next_seq.expect("set before appending");
        self.next_seq = Some(next.wrapping_add(data.len() as u32));
        self.arrivals.push_back((self.end(), at));
        data.len()
    }

    /// Bytes received in order and not yet consumed.
    pub fn data(&self) -> &[u8] {
        &self.buf
    }

    /// Stream offset of the first byte of `data()`.
    pub fn offset(&self) -> u64 {
        self.start
    }

    /// When the byte at stream `offset` arrived, if it is still buffered.
    pub fn arrival(&self, offset: u64) -> Option<Arrival> {
        if offset < self.start {
            return None;
        }
        self.arrivals
            .iter()
            .find(|(end, _)| offset < *end)
            .map(|(_, at)| *at)
    }

    /// Drops the first `n` bytes of `data()` once they have been parsed.
    pub fn consume(&mut self, n: usize) {
        let n = n.min(self.buf.len());
        self.buf.drain(..n);
        self.start += n as u64;
        while self
            .arrivals
            .front()
            .is_some_and(|(end, _)| *end <= self.start)
        {
            self.arrivals.pop_front();
        }
    }

    /// Stops following this direction and frees the buffer.
    pub fn stop(&mut self) {
        self.state = State::Stopped;
        self.release();
    }

    pub fn is_following(&self) -> bool {
        self.state == State::Following
    }

    /// Data went missing, so whatever came after is unreadable.
    pub fn lost_data(&self) -> bool {
        self.state == State::Lost
    }

    fn lose(&mut self) {
        self.state = State::Lost;
        self.release();
    }

    fn release(&mut self) {
        self.buf = Vec::new();
        self.arrivals.clear();
        self.early.clear();
        self.early_bytes = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::TcpOptions;

    fn segment(seq: u32, flags: u16, payload_len: u32) -> Tcp {
        Tcp {
            src_port: 50000,
            dst_port: 443,
            seq,
            ack: 0,
            flags: TcpFlags(flags),
            window: 64240,
            header_len: 20,
            options: TcpOptions::default(),
            payload_len,
        }
    }

    fn at(frame: u64) -> Arrival {
        Arrival {
            frame,
            ts: Timestamp(frame * 1000),
        }
    }

    #[test]
    fn in_order_overlap_and_arrivals() {
        let mut r = Reassembler::default();
        r.push(&segment(99, TcpFlags::SYN, 0), &[], at(1), 100);
        assert_eq!(
            r.push(&segment(100, TcpFlags::ACK, 3), b"abc", at(2), 100),
            3
        );
        // Retransmission, then a segment overlapping what we have.
        assert_eq!(
            r.push(&segment(100, TcpFlags::ACK, 3), b"abc", at(3), 100),
            0
        );
        assert_eq!(
            r.push(&segment(102, TcpFlags::ACK, 3), b"cde", at(4), 100),
            2
        );
        assert_eq!(r.data(), b"abcde");
        assert_eq!(r.arrival(1), Some(at(2)));
        assert_eq!(r.arrival(4), Some(at(4)));
        r.consume(3);
        assert_eq!((r.data(), r.offset()), (&b"de"[..], 3));
        assert_eq!(r.arrival(1), None);
        assert_eq!(r.arrival(3), Some(at(4)));
    }

    #[test]
    fn data_on_the_syn() {
        let mut r = Reassembler::default();
        assert_eq!(r.push(&segment(10, TcpFlags::SYN, 2), b"hi", at(1), 100), 2);
        assert_eq!(r.push(&segment(13, TcpFlags::ACK, 1), b"!", at(2), 100), 1);
        assert_eq!(r.data(), b"hi!");
    }

    #[test]
    fn out_of_order_segments_wait_for_the_gap() {
        let mut r = Reassembler::default();
        r.push(&segment(0, TcpFlags::ACK, 2), b"ab", at(1), 100);
        // Two segments arrive ahead of the one carrying "cd".
        assert_eq!(r.push(&segment(6, TcpFlags::ACK, 2), b"gh", at(2), 100), 0);
        assert_eq!(r.push(&segment(4, TcpFlags::ACK, 3), b"efg", at(3), 100), 0);
        assert_eq!(r.data(), b"ab");
        assert_eq!(r.push(&segment(2, TcpFlags::ACK, 2), b"cd", at(4), 100), 6);
        assert_eq!(r.data(), b"abcdefgh");
        // Released bytes count from the packet that filled the gap.
        assert_eq!(r.arrival(7), Some(at(4)));
    }

    #[test]
    fn gaps_that_never_fill_cuts_and_limits_lose_the_stream() {
        let mut gap = Reassembler::default();
        gap.push(&segment(0, TcpFlags::ACK, 2), b"ab", at(1), 10);
        for i in 0..3 {
            gap.push(&segment(10 + 3 * i, TcpFlags::ACK, 3), b"xyz", at(2), 10);
        }
        assert!(gap.lost_data());
        assert_eq!(gap.push(&segment(2, TcpFlags::ACK, 2), b"ef", at(3), 10), 0);

        let mut cut = Reassembler::default();
        cut.push(
            &segment(0, TcpFlags::ACK, 1000),
            b"only the start",
            at(1),
            2000,
        );
        assert!(cut.lost_data());

        let mut full = Reassembler::default();
        full.push(&segment(0, TcpFlags::ACK, 6), b"abcdef", at(1), 5);
        assert!(full.lost_data());
    }
}
