#!/usr/bin/env python3
"""Writes tls-zoo.pcap: one TLS connection per case, 10 seconds apart.

Certificates are real, signed by a throwaway test CA, so every field can be
checked. Needs the `cryptography` package. Expected values come from tshark,
not from packet-cage:

    python gen_tls_zoo.py tls-zoo.pcap
    tshark -r tls-zoo.pcap -Y tls -T fields -E occurrence=a -E aggregator=, \\
        -e frame.number -e tls.handshake.type -e tls.handshake.extensions_server_name \\
        -e tls.record.content_type -e tls.alert_message.desc > tls-zoo.tshark.txt

Encrypted records hold random bytes: only their sizes and positions matter.
"""
import datetime
import os
import struct
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

START_US = 1_760_000_000 * 1_000_000  # 2025-10-09
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
CCS, ALERT, HANDSHAKE, APPDATA = 20, 21, 22, 23
TLS10, TLS12, TLS13 = 0x0301, 0x0303, 0x0304
HELLO_RETRY_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")


def day(y, m, d):
    return datetime.datetime(y, m, d, tzinfo=datetime.timezone.utc)


class Certs:
    def __init__(self):
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Zoo Test CA"),
                          x509.NameAttribute(NameOID.ORGANIZATION_NAME, "packet-cage")])
        self.ca_name = name
        self.ca = self.build(name, name, self.ca_key, self.ca_key, day(2024, 1, 1), day(2034, 1, 1), [])

    def build(self, subject, issuer, key, signer, start, end, names):
        b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
             .public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(start).not_valid_after(end))
        if names:
            b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
        return b.sign(signer, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

    def leaf(self, cn, names, start=day(2025, 1, 1), end=day(2027, 1, 1)):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        return [self.build(subject, self.ca_name, key, self.ca_key, start, end, names), self.ca]

    def self_signed(self, cn):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        return [self.build(name, name, key, key, day(2025, 1, 1), day(2027, 1, 1), [cn])]


def u16(n):
    return struct.pack("!H", n)


def u24(n):
    return struct.pack("!I", n)[1:]


def vec8(b):
    return bytes([len(b)]) + b


def vec16(b):
    return u16(len(b)) + b


def vec24(b):
    return u24(len(b)) + b


def ext(kind, data):
    return u16(kind) + vec16(data)


def record(content, body, version=TLS12):
    return bytes([content]) + u16(version) + vec16(body)


def handshake(kind, body):
    return bytes([kind]) + vec24(body)


def client_hello(sni, alpn=(), versions=(), legacy=TLS12, padding=0):
    exts = b""
    if sni:
        exts += ext(0, vec16(b"\x00" + vec16(sni.encode())))
    if alpn:
        exts += ext(16, vec16(b"".join(vec8(p.encode()) for p in alpn)))
    if versions:
        exts += ext(43, vec8(b"".join(u16(v) for v in versions)))
    if padding:
        exts += ext(21, bytes(padding))
    body = u16(legacy) + os.urandom(32) + vec8(os.urandom(32)) + vec16(u16(0x1301) + u16(0xc02f)) + b"\x01\x00"
    return handshake(1, body + vec16(exts))


def server_hello(version=TLS12, selected=None, alpn=None, retry=False):
    exts = b""
    if selected:
        exts += ext(43, u16(selected))
    if alpn:
        exts += ext(16, vec16(vec8(alpn.encode())))
    random = HELLO_RETRY_RANDOM if retry else os.urandom(32)
    body = u16(version) + random + vec8(os.urandom(32)) + u16(0xc02f) + b"\x00"
    return handshake(2, body + (vec16(exts) if exts else b""))


def certificate(chain):
    return handshake(11, vec24(b"".join(vec24(c) for c in chain)))


SERVER_HELLO_DONE = handshake(14, b"")


def alert(desc, level=2, version=TLS12):
    return record(ALERT, bytes([level, desc]), version)


def encrypted(content, size, version=TLS12):
    return record(content, os.urandom(size), version)


class Conn:
    """A TCP connection from 10.1.N.10 to 10.1.N.20:port with a 20 ms RTT."""

    def __init__(self, frames, n, port=443):
        self.frames, self.t = frames, START_US + n * 10_000_000
        self.client, self.server = (10, 1, n, 10), (10, 1, n, 20)
        self.cport, self.sport = 50000 + n, port
        self.cseq, self.sseq = 1000 * n, 500_000 * n

    def at(self, ms):
        self.t += round(ms * 1000)
        return self

    def send(self, from_client, flags, data=b""):
        src, dst = (self.client, self.server) if from_client else (self.server, self.client)
        sport, dport = (self.cport, self.sport) if from_client else (self.sport, self.cport)
        seq, ack = (self.cseq, self.sseq) if from_client else (self.sseq, self.cseq)
        tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack if flags & ACK else 0, 5 << 4, flags,
                          64240, 0, 0) + data
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0, bytes(src), bytes(dst))
        self.frames.append((self.t, bytes.fromhex("020000000002020000000001") + b"\x08\x00" + ip + tcp))
        advance = len(data) + (1 if flags & (SYN | FIN) else 0)
        if from_client:
            self.cseq += advance
        else:
            self.sseq += advance
        return self

    def c(self, data=b"", flags=PSH | ACK):
        return self.send(True, flags, data)

    def s(self, data=b"", flags=PSH | ACK):
        return self.send(False, flags, data)

    def open(self):
        return self.c(flags=SYN).at(20).s(flags=SYN | ACK).at(0.1).c(flags=ACK).at(0.2)

    def close(self):
        return self.at(5).c(flags=FIN | ACK).at(20).s(flags=FIN | ACK).at(0.1).c(flags=ACK)


def tls12_rejected(frames, n, certs, sni, chain, desc):
    """The server sends its certificate; the client refuses it."""
    c = Conn(frames, n).open()
    c.c(record(HANDSHAKE, client_hello(sni, ["h2", "http/1.1"])))
    c.at(20).s(record(HANDSHAKE, server_hello() + certificate(chain) + SERVER_HELLO_DONE))
    c.at(1).c(alert(desc))
    c.close()


def build():
    certs = Certs()
    frames = []

    # 1. TLS 1.2 that works, ending with encrypted close_notify alerts.
    c = Conn(frames, 1).open()
    c.c(record(HANDSHAKE, client_hello("good.example", ["h2", "http/1.1"], legacy=TLS12)))
    c.at(20).s(record(HANDSHAKE, server_hello(alpn="h2") + certificate(certs.leaf(
        "good.example", ["good.example", "www.good.example"])) + SERVER_HELLO_DONE))
    c.at(1).c(record(HANDSHAKE, handshake(16, os.urandom(66))) + record(CCS, b"\x01")
              + encrypted(HANDSHAKE, 40))
    c.at(20).s(record(CCS, b"\x01") + encrypted(HANDSHAKE, 40))
    c.at(1).c(encrypted(APPDATA, 300)).at(30).s(encrypted(APPDATA, 1200))
    c.at(50).c(encrypted(ALERT, 26)).at(1).s(encrypted(ALERT, 26))
    c.close()

    # 2-5. The client rejects the certificate.
    tls12_rejected(frames, 2, certs, "expired.example",
                   certs.leaf("expired.example", ["expired.example"], day(2020, 1, 1), day(2021, 1, 1)), 45)
    tls12_rejected(frames, 3, certs, "wrong.example", certs.leaf("other.example", ["other.example"]), 42)
    tls12_rejected(frames, 4, certs, "selfsigned.example", certs.self_signed("selfsigned.example"), 48)
    tls12_rejected(frames, 5, certs, "notyet.example",
                   certs.leaf("notyet.example", ["notyet.example"], day(2030, 1, 1), day(2031, 1, 1)), 42)

    # 6. The server refuses an old client.
    c = Conn(frames, 6).open()
    c.c(record(HANDSHAKE, client_hello("legacy.example", legacy=TLS10), TLS10))
    c.at(20).s(alert(70, version=TLS10)).at(0.1).s(flags=RST | ACK)

    # 7. Reset instead of a ServerHello (e.g. a firewall filtering by name).
    c = Conn(frames, 7).open()
    c.c(record(HANDSHAKE, client_hello("blocked.example", ["h2"], [TLS13, TLS12])))
    c.at(20).s(flags=RST | ACK)

    # 8. No answer at all.
    c = Conn(frames, 8).open()
    c.c(record(HANDSHAKE, client_hello("silent.example", ["h2"], [TLS13, TLS12])))

    # 9. TLS 1.3 that works. Everything after the ServerHello is encrypted.
    c = Conn(frames, 9).open()
    c.c(record(HANDSHAKE, client_hello("v13.example", ["h2", "http/1.1"], [0x0a0a, TLS13, TLS12]), TLS10))
    c.at(20).s(record(HANDSHAKE, server_hello(selected=TLS13)) + record(CCS, b"\x01")
               + encrypted(APPDATA, 2000))
    c.at(1).c(record(CCS, b"\x01") + encrypted(APPDATA, 53)).at(0.1).c(encrypted(APPDATA, 300))
    c.at(20).s(encrypted(APPDATA, 250)).at(30).s(encrypted(APPDATA, 1500))
    c.close()

    # 10. TLS 1.3 with a HelloRetryRequest first.
    c = Conn(frames, 10).open()
    c.c(record(HANDSHAKE, client_hello("retry.example", ["h2"], [TLS13])))
    c.at(20).s(record(HANDSHAKE, server_hello(selected=TLS13, retry=True)) + record(CCS, b"\x01"))
    c.at(1).c(record(CCS, b"\x01") + record(HANDSHAKE, client_hello("retry.example", ["h2"], [TLS13])))
    c.at(20).s(record(HANDSHAKE, server_hello(selected=TLS13)) + encrypted(APPDATA, 1800))
    c.at(1).c(encrypted(APPDATA, 53)).at(0.1).c(encrypted(APPDATA, 280))
    c.at(25).s(encrypted(APPDATA, 900))
    c.close()

    # 11. TLS 1.3, and the client rejects the (encrypted) certificate with an
    #     encrypted alert: a 19-byte record.
    c = Conn(frames, 11).open()
    c.c(record(HANDSHAKE, client_hello("v13bad.example", ["h2"], [TLS13, TLS12])))
    c.at(20).s(record(HANDSHAKE, server_hello(selected=TLS13)) + record(CCS, b"\x01")
               + encrypted(APPDATA, 2000))
    c.at(1).c(record(CCS, b"\x01") + encrypted(APPDATA, 19))
    c.close()

    # 12. The server takes 900 ms to answer the ClientHello.
    c = Conn(frames, 12).open()
    c.c(record(HANDSHAKE, client_hello("slow.example", ["http/1.1"])))
    c.at(900).s(record(HANDSHAKE, server_hello(alpn="http/1.1") + certificate(certs.leaf(
        "slow.example", ["slow.example"])) + SERVER_HELLO_DONE))
    c.at(1).c(record(HANDSHAKE, handshake(16, os.urandom(66))) + record(CCS, b"\x01")
              + encrypted(HANDSHAKE, 40))
    c.at(20).s(record(CCS, b"\x01") + encrypted(HANDSHAKE, 40))
    c.close()

    # 13. TLS 1.0 still gets agreed.
    c = Conn(frames, 13).open()
    c.c(record(HANDSHAKE, client_hello("old.example", legacy=TLS10), TLS10))
    c.at(20).s(record(HANDSHAKE, server_hello(TLS10) + certificate(certs.leaf(
        "old.example", ["old.example"])) + SERVER_HELLO_DONE, TLS10))
    c.at(1).c(record(HANDSHAKE, handshake(16, os.urandom(66)), TLS10) + record(CCS, b"\x01", TLS10)
              + encrypted(HANDSHAKE, 48, TLS10))
    c.at(20).s(record(CCS, b"\x01", TLS10) + encrypted(HANDSHAKE, 48, TLS10))
    c.close()

    # 14. Port 8443, a wildcard certificate, and a ClientHello split over two
    #     records and two TCP segments.
    c = Conn(frames, 14, port=8443).open()
    hello = client_hello("api.wild.example", ["h2"], padding=900)
    records = record(HANDSHAKE, hello[:400]) + record(HANDSHAKE, hello[400:])
    c.c(records[:300]).at(0.1).c(records[300:])
    c.at(20).s(record(HANDSHAKE, server_hello(alpn="h2") + certificate(certs.leaf(
        "wild.example", ["*.wild.example"])) + SERVER_HELLO_DONE))
    c.at(1).c(record(HANDSHAKE, handshake(16, os.urandom(66))) + record(CCS, b"\x01")
              + encrypted(HANDSHAKE, 40))
    c.at(20).s(record(CCS, b"\x01") + encrypted(HANDSHAKE, 40))
    c.close()

    # 15. Plain HTTP on port 443: not TLS.
    c = Conn(frames, 15).open()
    c.c(b"GET / HTTP/1.1\r\nHost: plain.example\r\n\r\n")
    c.at(20).s(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
    c.close()

    # 16. A TLS 1.3 draft (23): everything after the ServerHello is encrypted.
    c = Conn(frames, 16).open()
    c.c(record(HANDSHAKE, client_hello("draft.example", ["h2"], [0x7f17, TLS12])))
    c.at(20).s(record(HANDSHAKE, server_hello(selected=0x7f17)) + encrypted(APPDATA, 1900))
    c.at(1).c(encrypted(APPDATA, 53)).at(0.1).c(encrypted(APPDATA, 300))
    c.at(25).s(encrypted(APPDATA, 800))
    c.close()

    # 17. TLS 1.2 where the server sends its Finished and an encrypted
    #     close_notify in one packet: still a completed handshake.
    c = Conn(frames, 17).open()
    c.c(record(HANDSHAKE, client_hello("coalesced.example", ["http/1.1"])))
    c.at(20).s(record(HANDSHAKE, server_hello() + certificate(certs.leaf(
        "coalesced.example", ["coalesced.example"])) + SERVER_HELLO_DONE))
    c.at(1).c(record(HANDSHAKE, handshake(16, os.urandom(66))) + record(CCS, b"\x01")
              + encrypted(HANDSHAKE, 40))
    c.at(20).s(record(CCS, b"\x01") + encrypted(HANDSHAKE, 40) + encrypted(ALERT, 26))
    c.close()

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
