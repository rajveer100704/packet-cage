#!/usr/bin/env python3
"""Writes dns-zoo.pcap: one DNS case every 10 seconds.

Expected values for each message come from tshark, not from packet-cage:

    python gen_dns_zoo.py dns-zoo.pcap
    tshark -r dns-zoo.pcap -Y "dns && !icmp" -T fields -E occurrence=f \\
        -e frame.number -e dns.id -e dns.flags.response -e dns.qry.name \\
        -e dns.qry.type -e dns.flags.rcode -e dns.count.answers -e dns.time \\
        > dns-zoo.tshark.txt
"""
import socket
import struct
import sys

START_US = 1_760_000_000 * 1_000_000
CLIENT, RESOLVER, DEAD_RESOLVER = (192, 168, 1, 10), (192, 168, 1, 1), (192, 168, 1, 2)
CLIENT6, RESOLVER6 = "2001:db8::10", "2001:db8::53"
A, CNAME, SOA, PTR, AAAA = 1, 5, 6, 12, 28
QR, TC, RD, RA = 0x8000, 0x0200, 0x0100, 0x0080
NOERROR, SERVFAIL, NXDOMAIN, REFUSED = 0, 2, 3, 5


def encode_name(name):
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"


def message(ident, flags, questions, answers=(), authority=()):
    """questions: [(name, type)]; answers/authority: raw record bytes."""
    body = b"".join(encode_name(n) + struct.pack("!HH", t, 1) for n, t in questions)
    body += b"".join(answers) + b"".join(authority)
    return struct.pack("!HHHHHH", ident, flags, len(questions), len(answers), len(authority), 0) + body


def record(owner, rtype, rdata, ttl=300):
    """owner is raw name bytes, e.g. b"\\xc0\\x0c" to point at the question."""
    return owner + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata


def query(ident, name, qtype):
    return message(ident, RD, [(name, qtype)])


def response(ident, name, qtype, rcode=NOERROR, answers=(), authority=(), flags=0):
    return message(ident, QR | RD | RA | flags | rcode, [(name, qtype)], answers, authority)


ETH = bytes.fromhex("020000000002020000000001")


def ipv4(src, dst, proto, payload):
    return ETH + b"\x08\x00" + struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, proto, 0,
                                          bytes(src), bytes(dst)) + payload


def ipv6(src, dst, proto, payload):
    return ETH + b"\x86\xdd" + struct.pack("!IHBB", 0x60000000, len(payload), proto, 64) + \
        socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst) + payload


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(sport, dport, seq, ack, flags, payload=b""):
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0) + payload


class Zoo:
    def __init__(self):
        self.frames = []

    def at(self, case, ms):
        return START_US + case * 10_000_000 + round(ms * 1000)

    def udp4(self, t, src, dst, sport, dport, dns):
        self.frames.append((t, ipv4(src, dst, 17, udp(sport, dport, dns))))

    def ask(self, case, ms, port, ident, name, qtype, server=RESOLVER):
        self.udp4(self.at(case, ms), CLIENT, server, port, 53, query(ident, name, qtype))

    def answer(self, case, ms, port, msg, server=RESOLVER):
        self.udp4(self.at(case, ms), server, CLIENT, 53, port, msg)


def build():
    z = Zoo()

    # 1. CNAME chain to two addresses, then a connection to one of them.
    www = b"\xc0\x0c"
    web = encode_name("web.example.com")
    z.ask(1, 0, 40001, 0x0101, "www.example.com", A)
    z.answer(1, 15, 40001, response(0x0101, "www.example.com", A, answers=[
        record(www, CNAME, web),
        record(b"\xc0\x2d", A, bytes([93, 184, 216, 34])),
        record(b"\xc0\x2d", A, bytes([93, 184, 216, 35])),
    ]))
    for ms, src, dst, sport, dport, seq, ack, flags in [
        (20, CLIENT, (93, 184, 216, 34), 50001, 443, 100, 0, 0x02),
        (40, (93, 184, 216, 34), CLIENT, 443, 50001, 900, 101, 0x12),
        (40.1, CLIENT, (93, 184, 216, 34), 50001, 443, 101, 901, 0x10),
    ]:
        z.frames.append((z.at(1, ms), ipv4(src, dst, 6, tcp(sport, dport, seq, ack, flags))))

    # 2. The name exists but has no AAAA records.
    soa = record(b"\xc0\x10", SOA, encode_name("ns.example.com") + encode_name("admin.example.com")
                 + struct.pack("!IIIII", 1, 3600, 600, 86400, 300))
    z.ask(2, 0, 40002, 0x0202, "www.example.com", AAAA)
    z.answer(2, 14, 40002, response(0x0202, "www.example.com", AAAA, authority=[soa]))

    # 3-5. Error codes.
    for case, ident, name, rcode in [(3, 0x0303, "nope.example", NXDOMAIN),
                                     (4, 0x0404, "broken.example", SERVFAIL),
                                     (5, 0x0505, "blocked.example", REFUSED)]:
        z.ask(case, 0, 40000 + case, ident, name, A)
        z.answer(case, 20, 40000 + case, response(ident, name, A, rcode=rcode))

    # 6. Slow, with one retry before the answer.
    z.ask(6, 0, 40006, 0x0606, "slow.example", A)
    z.ask(6, 1000, 40006, 0x0606, "slow.example", A)
    z.answer(6, 1200, 40006, response(0x0606, "slow.example", A,
                                      answers=[record(b"\xc0\x0c", A, bytes([198, 51, 100, 6]))]))

    # 7. Never answered, retried twice.
    for ms in (0, 1000, 2000):
        z.ask(7, ms, 40007, 0x0707, "lost.example", A)

    # 8. Nothing listening on the server: ICMP port unreachable quoting the query.
    q = query(0x0808, "down.example", A)
    z.udp4(z.at(8, 0), CLIENT, DEAD_RESOLVER, 40008, 53, q)
    original = ipv4(CLIENT, DEAD_RESOLVER, 17, udp(40008, 53, q))[14:]
    icmp = struct.pack("!BBHI", 3, 3, 0, 0) + original
    z.frames.append((z.at(8, 1), ipv4(DEAD_RESOLVER, CLIENT, 1, icmp)))

    # 9. AAAA over IPv6.
    for ms, src, dst, sport, dport, msg in [
        (0, CLIENT6, RESOLVER6, 40009, 53, query(0x0909, "v6.example", AAAA)),
        (12, RESOLVER6, CLIENT6, 53, 40009, response(0x0909, "v6.example", AAAA, answers=[
            record(b"\xc0\x0c", AAAA, socket.inet_pton(socket.AF_INET6, "2001:db8::80"))])),
    ]:
        z.frames.append((z.at(9, ms), ipv6(src, dst, 17, udp(sport, dport, msg))))

    # 10. Truncated over UDP, so the client asks again over TCP. The TCP query
    #     is split across two segments.
    z.ask(10, 0, 40010, 0x0a0a, "big.example", A)
    z.answer(10, 10, 40010, response(0x0a0a, "big.example", A, flags=TC))
    tq = query(0x0a0b, "big.example", A)
    tq = struct.pack("!H", len(tq)) + tq
    tr = response(0x0a0b, "big.example", A, answers=[
        record(b"\xc0\x0c", A, bytes([203, 0, 113, i])) for i in (1, 2, 3)])
    tr = struct.pack("!H", len(tr)) + tr
    c, s = 5000, 9000
    for ms, from_client, seq, ack, flags, data in [
        (20, True, c, 0, 0x02, b""),
        (30, False, s, c + 1, 0x12, b""),
        (30.1, True, c + 1, s + 1, 0x10, b""),
        (30.2, True, c + 1, s + 1, 0x18, tq[:12]),
        (30.3, True, c + 13, s + 1, 0x18, tq[12:]),
        (45, False, s + 1, c + 1 + len(tq), 0x18, tr),
        (45.1, True, c + 1 + len(tq), s + 1 + len(tr), 0x11, b""),
        (55, False, s + 1 + len(tr), c + 2 + len(tq), 0x11, b""),
    ]:
        src, dst, sport, dport = (CLIENT, RESOLVER, 40011, 53) if from_client else (RESOLVER, CLIENT, 53, 40011)
        z.frames.append((z.at(10, ms), ipv4(src, dst, 6, tcp(sport, dport, seq, ack, flags, data))))

    # 11. Response whose answer name points at itself.
    bad = response(0x0b0b, "loop.example", A)
    bad = bad[:6] + b"\x00\x01" + bad[8:] + b"\xc0" + bytes([len(bad)]) + struct.pack("!HHIH", A, 1, 60, 4) + bytes(4)
    z.ask(11, 0, 40012, 0x0b0b, "loop.example", A)
    z.answer(11, 9, 40012, bad)

    # 12. A response whose query was sent before the capture started.
    z.answer(12, 0, 40013, response(0x0c0c, "orphan.example", A,
                                    answers=[record(b"\xc0\x0c", A, bytes([198, 51, 100, 12]))]))

    # 13. Reverse lookup.
    z.ask(13, 0, 40014, 0x0d0d, "35.216.184.93.in-addr.arpa", PTR)
    z.answer(13, 11, 40014, response(0x0d0d, "35.216.184.93.in-addr.arpa", PTR,
                                     answers=[record(b"\xc0\x0c", PTR, encode_name("web.example.com"))]))

    # 14. Retried after more than 5 s. Wireshark treats the retry as a new
    #     query (5.01 s apart, answered 10 ms later); packet-cage counts 5.51 s
    #     from the first one, because that is how long the client waited.
    z.ask(14, 0, 40015, 0x0e0e, "late.example", A)
    z.ask(14, 5500, 40015, 0x0e0e, "late.example", A)
    z.answer(14, 5510, 40015, response(0x0e0e, "late.example", A,
                                       answers=[record(b"\xc0\x0c", A, bytes([198, 51, 100, 14]))]))

    # 15. Sent just before the capture ended; may still have been answered.
    z.ask(15, 0, 40016, 0x0f0f, "pending.example", A)
    z.frames.append((z.at(15, 500), ipv4(CLIENT, RESOLVER, 1, struct.pack("!BBHHH", 8, 0, 0, 1, 1))))

    z.frames.sort(key=lambda f: f[0])
    return z.frames


def main(path):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for t, data in build():
            f.write(struct.pack("<IIII", t // 1_000_000, t % 1_000_000, len(data), len(data)))
            f.write(data)


if __name__ == "__main__":
    main(sys.argv[1])
