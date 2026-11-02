#!/usr/bin/env python3
"""Writes demo.pcap: a laptop (10.0.0.5) browsing for ten seconds, captured on
its office gateway. Most of it is healthy; four things go wrong:

- an app keeps looking up api.internal, a name that doesn't exist;
- pay.example.com is behind a TLS-inspecting proxy whose CA the laptop
  doesn't trust, so the laptop rejects the handshake;
- api.example.com takes two seconds to answer, over a 40 ms network;
- a download from cdn.example.com loses packets on the Wi-Fi, after the
  gateway, so the server has to send them again.

Needs the `cryptography` package, for the proxy's certificate.

    python gen_demo.py demo.pcap
"""
import datetime
import os
import struct
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

START_US = 1_760_000_000 * 1_000_000  # 2025-10-09 08:53:20 UTC
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
LAPTOP, GATEWAY = (10, 0, 0, 5), (10, 0, 0, 1)
LAPTOP_MAC, GATEWAY_MAC = bytes.fromhex("020000000005"), bytes.fromhex("020000000001")
# The gateway sits next to the laptop: half a millisecond to the laptop and
# back, 39.5 ms to the servers and back.
NEAR_MS, FAR_MS = 0.5, 39.5
SERVERS = {
    "www.example.com": (93, 184, 216, 34),
    "static.example.com": (93, 184, 216, 35),
    "fonts.example.net": (198, 51, 100, 7),
    "img.example.net": (198, 51, 100, 8),
    "pay.example.com": (198, 51, 100, 20),
    "api.example.com": (198, 51, 100, 10),
    "cdn.example.com": (203, 0, 113, 30),
}


class Capture:
    def __init__(self):
        self.frames = []
        self.port = 50100
        self.dns_id = 0x3a00

    def packet(self, ms, src, dst, proto, payload):
        to_laptop = dst == LAPTOP
        eth = (LAPTOP_MAC + GATEWAY_MAC) if to_laptop else (GATEWAY_MAC + LAPTOP_MAC)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0x4000, 64, proto, 0,
                         bytes(src), bytes(dst))
        self.frames.append((START_US + round(ms * 1000), eth + b"\x08\x00" + ip + payload))

    def next_port(self):
        self.port += 1
        return self.port

    def lookup(self, ms, name, qtype=1, answer=None):
        """The laptop asks the gateway's resolver; the answer takes 15 ms."""
        self.dns_id += 1
        port = self.next_port()
        question = encode_name(name) + struct.pack("!HH", qtype, 1)
        query = struct.pack("!HHHHHH", self.dns_id, 0x0100, 1, 0, 0, 0) + question
        self.packet(ms, LAPTOP, GATEWAY, 17, udp(port, 53, query))
        if answer is None:
            response = struct.pack("!HHHHHH", self.dns_id, 0x8183, 1, 0, 0, 0) + question
        else:
            record = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + bytes(answer)
            response = struct.pack("!HHHHHH", self.dns_id, 0x8180, 1, 1, 0, 0) + question + record
        self.packet(ms + 15, GATEWAY, LAPTOP, 17, udp(53, port, response))


class Conn:
    """A TCP connection from the laptop to `name`:443, as the gateway sees it."""

    def __init__(self, cap, ms, name):
        self.cap, self.t = cap, ms
        self.server = SERVERS[name]
        self.cport = cap.next_port()
        self.cseq, self.sseq = 1000 * self.cport, 7_000_000 + 1000 * self.cport

    def at(self, ms):
        self.t += ms
        return self

    def send(self, from_laptop, flags, data=b"", seq=None, ack=None):
        own = self.cseq if from_laptop else self.sseq
        if ack is None:
            ack = self.sseq if from_laptop else self.cseq
        tcp = struct.pack("!HHIIBBHHH", *((self.cport, 443) if from_laptop else (443, self.cport)),
                          own if seq is None else seq, ack if flags & ACK else 0,
                          5 << 4, flags, 64240, 0, 0) + data
        src, dst = (LAPTOP, self.server) if from_laptop else (self.server, LAPTOP)
        self.cap.packet(self.t, src, dst, 6, tcp)
        if seq is None:
            advance = len(data) + (1 if flags & (SYN | FIN) else 0)
            if from_laptop:
                self.cseq += advance
            else:
                self.sseq += advance
        return self

    def c(self, data=b"", flags=PSH | ACK):
        return self.send(True, flags, data)

    def s(self, data=b"", flags=PSH | ACK):
        return self.send(False, flags, data)

    def open(self):
        return self.c(flags=SYN).at(FAR_MS).s(flags=SYN | ACK).at(NEAR_MS).c(flags=ACK).at(0.1)

    def close(self):
        self.at(2).c(flags=FIN | ACK).at(FAR_MS).s(flags=FIN | ACK).at(NEAR_MS).c(flags=ACK)
        return self

    def tls13(self, name):
        """A TLS 1.3 handshake; the server's tickets follow the client's Finished."""
        self.c(client_hello(name, tls13=True))
        self.at(FAR_MS).s(record(22, server_hello(tls13=True)) + record(20, b"\x01") + record(23, os.urandom(1200)))
        self.at(0.2).s(record(23, os.urandom(700)))
        self.at(NEAR_MS).c(flags=ACK)
        self.at(1).c(record(20, b"\x01") + record(23, os.urandom(53)))
        return self

    def tickets(self):
        return self.s(record(23, os.urandom(240)) + record(23, os.urandom(240)))


def encode_name(name):
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def u16(n):
    return struct.pack("!H", n)


def vec(n, b):
    return struct.pack("!I", len(b))[4 - n:] + b


def record(content, body):
    return bytes([content]) + b"\x03\x03" + vec(2, body)


def handshake(kind, body):
    return bytes([kind]) + vec(3, body)


def client_hello(name, tls13):
    sni = b"\x00" + vec(2, name.encode())
    exts = u16(0) + vec(2, vec(2, sni))
    if tls13:
        exts += u16(43) + vec(2, vec(1, u16(0x0304) + u16(0x0303)))
    body = u16(0x0303) + os.urandom(32) + vec(1, os.urandom(32)) + vec(2, u16(0x1301) + u16(0xc02f)) + b"\x01\x00"
    return record(22, handshake(1, body + vec(2, exts)))


def server_hello(tls13):
    exts = u16(43) + vec(2, u16(0x0304)) if tls13 else b""
    body = u16(0x0303) + os.urandom(32) + vec(1, os.urandom(32)) + u16(0x1301 if tls13 else 0xc02f) + b"\x00"
    return handshake(2, body + (vec(2, exts) if exts else b""))


def proxy_chain(name):
    """A certificate for `name`, issued by a TLS-inspecting proxy's own CA."""
    ca_key, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Office Inspection Proxy CA")])
    start = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
    end = datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc)

    def build(subject, public_key, names):
        b = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name).public_key(public_key)
             .serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(end))
        if names:
            b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
        return b.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

    leaf = build(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]), key.public_key(), [name])
    return [leaf, build(ca_name, ca_key.public_key(), [])]


def healthy(cap, ms, name, server_ms=30, size=2000):
    """A page fetched over TLS 1.3 without trouble."""
    c = Conn(cap, ms, name).open().tls13(name)
    c.c(record(23, os.urandom(420))).at(FAR_MS).tickets()
    c.at(server_ms)
    while size > 0:
        part = min(size, 1400)
        c.s(record(23, os.urandom(part - 5))).at(0.3)
        size -= part
    c.at(NEAR_MS).c(flags=ACK)
    c.close()


def build():
    cap = Capture()
    cap.lookup(0, "www.example.com", answer=SERVERS["www.example.com"])
    healthy(cap, 20, "www.example.com", size=4000)
    cap.lookup(150, "static.example.com", answer=SERVERS["static.example.com"])
    healthy(cap, 170, "static.example.com", size=3000)

    # An app that can't find its backend asks for it, A and AAAA, and again
    # a few seconds later.
    cap.lookup(500, "api.internal")
    cap.lookup(502, "api.internal", qtype=28)

    healthy(cap, 600, "static.example.com", size=1500)
    cap.lookup(800, "fonts.example.net", answer=SERVERS["fonts.example.net"])
    healthy(cap, 820, "fonts.example.net", size=2500)

    # pay.example.com: the proxy's certificate, which the laptop rejects.
    cap.lookup(1000, "pay.example.com", answer=SERVERS["pay.example.com"])
    c = Conn(cap, 1020, "pay.example.com").open()
    c.c(client_hello("pay.example.com", tls13=False))
    chain = b"".join(vec(3, cert) for cert in proxy_chain("pay.example.com"))
    flight = record(22, server_hello(tls13=False) + handshake(11, vec(3, chain)) + handshake(14, b""))
    c.at(FAR_MS).s(flight)
    c.at(NEAR_MS).c(record(21, b"\x02\x30"))  # fatal unknown_ca
    c.close()

    healthy(cap, 1500, "www.example.com", size=2000)

    # api.example.com: answered in 2.1 s, over a 40 ms round trip.
    cap.lookup(2000, "api.example.com", answer=SERVERS["api.example.com"])
    c = Conn(cap, 2020, "api.example.com").open().tls13("api.example.com")
    c.c(record(23, os.urandom(380))).at(FAR_MS).tickets()
    c.at(2100).s(record(23, os.urandom(1395))).at(0.3).s(record(23, os.urandom(1395))).at(0.3).s(record(23, os.urandom(600)))
    c.at(NEAR_MS).c(flags=ACK)
    c.close()

    healthy(cap, 2600, "img.example.net", size=3000)
    cap.lookup(3000, "api.internal")
    healthy(cap, 3500, "static.example.com", size=1200)
    healthy(cap, 4000, "fonts.example.net", size=1500)

    # cdn.example.com: a download where the Wi-Fi drops four segments after
    # the gateway saw them. The laptop's duplicate ACKs bring them back.
    cap.lookup(5000, "cdn.example.com", answer=SERVERS["cdn.example.com"])
    c = Conn(cap, 5020, "cdn.example.com").open().tls13("cdn.example.com")
    c.c(record(23, os.urandom(400))).at(FAR_MS).tickets().at(10)
    lost = {4, 13, 22, 31}
    hole, dup_acks = None, 0
    sent = {}
    for i in range(40):
        sent[i] = c.sseq
        c.s(record(23, os.urandom(1395)))
        c.at(NEAR_MS)
        if i in lost:
            hole = i  # never reaches the laptop: no ACK
        elif hole is None:
            if i % 2:
                c.c(flags=ACK)
        else:
            # Out of order at the laptop: a duplicate ACK for the hole.
            c.send(True, ACK, ack=sent[hole])
            dup_acks += 1
        if hole is not None and dup_acks == 7:
            # The server resent the hole after the third duplicate ACK; it
            # arrives a round trip later, just after the seventh.
            c.at(1).send(False, PSH | ACK, record(23, os.urandom(1395)), seq=sent[hole])
            c.at(NEAR_MS).c(flags=ACK)
            hole, dup_acks = None, 0
        c.at(10 - NEAR_MS)
    c.close()

    healthy(cap, 6500, "www.example.com", size=2000)
    healthy(cap, 7200, "img.example.net", size=2500)
    healthy(cap, 8000, "static.example.com", size=1000)

    cap.frames.sort(key=lambda f: f[0])
    return cap.frames


def main(path):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        for t, data in build():
            f.write(struct.pack("<IIII", t // 1_000_000, t % 1_000_000, len(data), len(data)))
            f.write(data)


if __name__ == "__main__":
    main(sys.argv[1])
