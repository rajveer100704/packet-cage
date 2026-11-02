#!/usr/bin/env python3
"""Writes tcp-zoo.pcap: one TCP connection per analysis case.

Each connection is on its own subnet (10.0.N.0) and starts 60 s after the
previous one. Frames are written in time order.

The expected labels come from tshark, not from packet-cage:

    python gen_tcp_zoo.py tcp-zoo.pcap
    tshark -r tcp-zoo.pcap -Y tcp -T fields -e frame.number -e _ws.col.info > tcp-zoo.tshark.txt
"""
import struct
import sys

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
START_US = 1_760_000_000 * 1_000_000  # any time well after 1970


def mss(value):
    return struct.pack("!BBH", 2, 4, value)


def wscale(shift):
    return struct.pack("!BBB", 3, 3, shift)


SACK_PERM = b"\x04\x02"


def sack(*blocks):
    body = b"".join(struct.pack("!II", l & 0xFFFFFFFF, r & 0xFFFFFFFF) for l, r in blocks)
    return b"\x01\x01" + struct.pack("!BB", 5, 2 + len(body)) + body


def frame(src, dst, sport, dport, seq, ack, flags, win, payload, opts):
    opts += b"\x00" * (-len(opts) % 4)
    header_len = 20 + len(opts)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                      (header_len // 4) << 4, flags, win, 0, 0) + opts + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0x4000, 64, 6, 0,
                     bytes(src), bytes(dst))
    return bytes.fromhex("020000000002020000000001") + b"\x08\x00" + ip + tcp


class Conn:
    """A connection between 10.0.N.1:5000N (client) and 10.0.N.2:443."""

    def __init__(self, frames, n):
        self.frames = frames
        self.t = START_US + n * 60_000_000
        self.client, self.server = (10, 0, n, 1), (10, 0, n, 2)
        self.cport, self.sport = 50000 + n, 443
        self.C, self.S = 1_000_000 * n, 7_000_000 * n  # initial sequence numbers

    def at(self, ms):
        self.t += round(ms * 1000)
        return self

    def c2s(self, seq, ack, flags, win=64240, data=0, opts=b""):
        self.frames.append((self.t, frame(self.client, self.server, self.cport, self.sport,
                                          seq, ack, flags, win, b"x" * data, opts)))
        return self

    def s2c(self, seq, ack, flags, win=64240, data=0, opts=b""):
        self.frames.append((self.t, frame(self.server, self.client, self.sport, self.cport,
                                          seq, ack, flags, win, b"y" * data, opts)))
        return self

    def handshake(self, syn_opts=b"", synack_opts=b"", server_win=64240):
        C, S = self.C, self.S
        self.c2s(C, 0, SYN, opts=mss(1460) + syn_opts)
        self.at(20).s2c(S, C + 1, SYN | ACK, win=server_win, opts=mss(1460) + synack_opts)
        self.at(0.1).c2s(C + 1, S + 1, ACK)
        return self


def build():
    frames = []

    # 1. Fast retransmission after three duplicate ACKs carrying SACK blocks.
    c = Conn(frames, 1)
    C, S = c.C, c.S
    c.handshake(SACK_PERM, SACK_PERM)
    for i in range(5):
        c.at(0.1).c2s(C + 1 + 1000 * i, S + 1, PSH | ACK, data=1000)
    c.at(20).s2c(S + 1, C + 1001, ACK)
    for right in (C + 3001, C + 4001, C + 5001):
        c.at(0.2).s2c(S + 1, C + 1001, ACK, opts=sack((C + 2001, right)))
    c.at(1).c2s(C + 1001, S + 1, PSH | ACK, data=1000)
    c.at(20).s2c(S + 1, C + 5001, ACK)

    # 2. Retransmission after a timeout, then a spurious one.
    c = Conn(frames, 2)
    C, S = c.C, c.S
    c.handshake()
    c.at(5).c2s(C + 1, S + 1, PSH | ACK, data=500)
    c.at(300).c2s(C + 1, S + 1, PSH | ACK, data=500)
    c.at(20).s2c(S + 1, C + 501, ACK)
    c.at(200).c2s(C + 1, S + 1, PSH | ACK, data=500)

    # 3. Zero window, probes and their ACKs, then the window opens.
    c = Conn(frames, 3)
    C, S = c.C, c.S
    c.handshake(server_win=3000)
    c.at(5).c2s(C + 1, S + 1, PSH | ACK, data=1000)
    c.at(0.1).c2s(C + 1001, S + 1, PSH | ACK, data=1000)
    c.at(20).s2c(S + 1, C + 2001, ACK, win=0)
    for _ in range(2):
        c.at(200).c2s(C + 2001, S + 1, ACK, data=1)
        c.at(20).s2c(S + 1, C + 2001, ACK, win=0)
    c.at(100).s2c(S + 1, C + 2001, ACK, win=4000)
    c.at(1).c2s(C + 2001, S + 1, PSH | ACK, data=1000)
    c.at(20).s2c(S + 1, C + 3001, ACK, win=4000)

    # 4. Sender fills the receiver's whole window (no window scaling).
    c = Conn(frames, 4)
    C, S = c.C, c.S
    c.handshake(server_win=4000)
    for i in range(4):
        c.at(0.1).c2s(C + 1 + 1000 * i, S + 1, PSH | ACK, data=1000)
    c.at(20).s2c(S + 1, C + 4001, ACK, win=4000)

    # 5. Same with window scaling: a raw window of 1000 means 4000 bytes.
    c = Conn(frames, 5)
    C, S = c.C, c.S
    c.handshake(wscale(2), wscale(2))
    c.at(1).s2c(S + 1, C + 1, ACK, win=1000)
    for i in range(4):
        c.at(0.1).c2s(C + 1 + 1000 * i, S + 1, PSH | ACK, win=16000, data=1000)
    c.at(20).s2c(S + 1, C + 4001, ACK, win=1000)

    # 6. Keep-alives (empty and one-byte) and their ACKs.
    c = Conn(frames, 6)
    C, S = c.C, c.S
    c.handshake()
    c.at(5).c2s(C + 1, S + 1, PSH | ACK, data=100)
    c.at(20).s2c(S + 1, C + 101, ACK)
    c.at(10_000).c2s(C + 100, S + 1, ACK)
    c.at(20).s2c(S + 1, C + 101, ACK)
    c.at(10_000).c2s(C + 100, S + 1, ACK, data=1)
    c.at(20).s2c(S + 1, C + 101, ACK)

    # 7. Download seen at the receiver: segment 3 arrives before segment 2.
    c = Conn(frames, 7)
    C, S = c.C, c.S
    c.handshake()
    c.at(5).s2c(S + 1, C + 1, PSH | ACK, data=1000)
    c.at(0.1).s2c(S + 2001, C + 1, PSH | ACK, data=1000)
    c.at(0.1).c2s(C + 1, S + 1001, ACK)
    c.at(0.3).s2c(S + 1001, C + 1, PSH | ACK, data=1000)
    c.at(0.1).c2s(C + 1, S + 3001, ACK)

    # 8. Unanswered SYN, retried twice, then refused.
    c = Conn(frames, 8)
    C = c.C
    c.c2s(C, 0, SYN, opts=mss(1460))
    c.at(1000).c2s(C, 0, SYN, opts=mss(1460))
    c.at(2000).c2s(C, 0, SYN, opts=mss(1460))
    c.at(1).s2c(0, C + 1, RST | ACK, win=0)

    # 9. A window change carrying SACK counts as a duplicate ACK; then a fast
    #    retransmission after just two of them.
    c = Conn(frames, 9)
    C, S = c.C, c.S
    c.handshake(SACK_PERM, SACK_PERM)
    for i in range(3):
        c.at(0.1).c2s(C + 1 + 1000 * i, S + 1, PSH | ACK, data=1000)
    c.at(20).s2c(S + 1, C + 1001, ACK, win=64000)
    c.at(0.2).s2c(S + 1, C + 1001, ACK, win=63000, opts=sack((C + 2001, C + 3001)))
    c.at(0.2).s2c(S + 1, C + 1001, ACK, win=63000, opts=sack((C + 2001, C + 3001)))
    c.at(1).c2s(C + 1001, S + 1, PSH | ACK, data=1000)
    c.at(20).s2c(S + 1, C + 3001, ACK)

    # 10. Capture missed segment 2: a gap, then an ACK for data never seen.
    c = Conn(frames, 10)
    C, S = c.C, c.S
    c.handshake()
    c.at(5).c2s(C + 1, S + 1, PSH | ACK, data=1000)
    c.at(0.1).c2s(C + 2001, S + 1, PSH | ACK, data=1000)
    c.at(20).s2c(S + 1, C + 3001, ACK)

    # 11. Server aborts an open connection.
    c = Conn(frames, 11)
    C, S = c.C, c.S
    c.handshake()
    c.at(5).c2s(C + 1, S + 1, PSH | ACK, data=200)
    c.at(30).s2c(S + 1, C + 201, RST | ACK, win=0)

    # 12. Clean close, then an RST from the client: still counts as closed.
    c = Conn(frames, 12)
    C, S = c.C, c.S
    c.handshake()
    c.at(5).c2s(C + 1, S + 1, FIN | ACK)
    c.at(20).s2c(S + 1, C + 2, FIN | ACK)
    c.at(0.1).c2s(C + 2, S + 2, RST)

    frames.sort(key=lambda f: f[0])
    return frames


def main(path):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for t, data in build():
            f.write(struct.pack("<IIII", t // 1_000_000, t % 1_000_000, len(data), len(data)))
            f.write(data)


if __name__ == "__main__":
    main(sys.argv[1])
