#!/usr/bin/env python3
"""Writes http-zoo.pcap: one HTTP case per connection, 10 seconds apart.

Every connection has a 20 ms round trip, seen from the client side, so the
server's own time is the time to first byte minus 20 ms. Expected values come
from tshark, not from packet-cage:

    python gen_http_zoo.py http-zoo.pcap
    tshark -r http-zoo.pcap -o http.desegment_body:FALSE -o http.dechunk_body:FALSE \\
        -o tcp.reassemble_out_of_order:TRUE \\
        -Y "http.request or http.response" -T fields -E occurrence=f \\
        -e frame.number -e http.request.method -e http.request.uri -e http.host \\
        -e http.response.code -e http.request_in > http-zoo.tshark.txt
"""
import os
import struct
import sys

START_US = 1_760_000_000 * 1_000_000
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


class Conn:
    """A TCP connection from 10.2.N.10 to 10.2.N.20:port."""

    def __init__(self, frames, n, port=80):
        self.frames, self.t = frames, START_US + n * 10_000_000
        self.client, self.server = (10, 2, n, 10), (10, 2, n, 20)
        self.cport, self.sport = 51000 + n, port
        self.cseq, self.sseq = 3000 * n, 800_000 * n

    def at(self, ms):
        self.t += round(ms * 1000)
        return self

    def send(self, from_client, flags, data=b"", seq=None):
        src, dst = (self.client, self.server) if from_client else (self.server, self.client)
        sport, dport = (self.cport, self.sport) if from_client else (self.sport, self.cport)
        own = self.cseq if from_client else self.sseq
        ack = self.sseq if from_client else self.cseq
        tcp = struct.pack("!HHIIBBHHH", sport, dport, own if seq is None else seq, ack if flags & ACK else 0,
                          5 << 4, flags, 64240, 0, 0) + data
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0, bytes(src), bytes(dst))
        self.frames.append((self.t, bytes.fromhex("020000000002020000000001") + b"\x08\x00" + ip + tcp))
        if seq is None:
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


def response(status, reason, body=b"", headers=b"", length=True):
    head = b"HTTP/1.1 %d %s\r\n" % (status, reason.encode()) + headers
    if length:
        head += b"Content-Length: %d\r\n" % len(body)
    return head + b"\r\n" + body


def chunked(*parts):
    return b"".join(b"%x\r\n%s\r\n" % (len(p), p) for p in parts) + b"0\r\n\r\n"


def tls(content, body):
    return bytes([content]) + b"\x03\x03" + struct.pack("!H", len(body)) + body


def client_hello(name):
    sni = b"\x00" + struct.pack("!H", len(name)) + name.encode()
    ext = struct.pack("!HH", 0, len(sni) + 2) + struct.pack("!H", len(sni)) + sni
    ext += struct.pack("!HH", 43, 3) + b"\x02\x03\x04"
    body = b"\x03\x03" + os.urandom(32) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + struct.pack("!H", len(ext)) + ext
    return tls(22, b"\x01" + struct.pack("!I", len(body))[1:] + body)


def server_hello():
    ext = struct.pack("!HH", 43, 2) + b"\x03\x04"
    body = b"\x03\x03" + os.urandom(32) + b"\x00" + b"\x13\x01\x00" + struct.pack("!H", len(ext)) + ext
    return tls(22, b"\x02" + struct.pack("!I", len(body))[1:] + body)


def build():
    frames = []
    page = b"<html>" + b"x" * 2000 + b"</html>"

    # 1. Keep-alive: a page with Content-Length in two segments, then a
    #    chunked stylesheet.
    c = Conn(frames, 1).open()
    c.c(b"GET /index.html HTTP/1.1\r\nHost: shop.example\r\n\r\n")
    whole = response(200, "OK", page, b"Content-Type: text/html\r\n")
    c.at(50).s(whole[:1400]).at(0.1).s(whole[1400:])
    c.at(1).c(b"GET /style.css HTTP/1.1\r\nHost: shop.example\r\n\r\n")
    whole = response(200, "OK", chunked(b"body{", b"color:red", b"}"), b"Transfer-Encoding: chunked\r\n", length=False)
    c.at(30).s(whole[:60]).at(0.1).s(whole[60:])
    c.close()

    # 2. A POST whose body follows the head in its own segment.
    c = Conn(frames, 2).open()
    body = b'{"item": 42, "qty": 1}' * 10
    c.c(b"POST /api/orders HTTP/1.1\r\nHost: api.example\r\nContent-Length: %d\r\n\r\n" % len(body))
    c.at(0.2).c(body)
    c.at(40).s(response(201, "Created", b'{"id": 7}'))
    c.close()

    # 3. HEAD: a length but no body; then 304 and 404 on the same connection.
    c = Conn(frames, 3).open()
    c.c(b"HEAD /big.iso HTTP/1.1\r\nHost: files.example\r\n\r\n")
    c.at(25).s(b"HTTP/1.1 200 OK\r\nContent-Length: 4000000000\r\n\r\n")
    c.at(1).c(b"GET /logo.png HTTP/1.1\r\nHost: files.example\r\nIf-None-Match: \"abc\"\r\n\r\n")
    c.at(25).s(b"HTTP/1.1 304 Not Modified\r\nContent-Length: 1234\r\n\r\n")
    c.at(1).c(b"GET /missing HTTP/1.1\r\nHost: files.example\r\n\r\n")
    c.at(25).s(response(404, "Not Found", b"no such file"))
    c.close()

    # 4. A slow server error.
    c = Conn(frames, 4).open()
    c.c(b"GET /report?year=2025 HTTP/1.1\r\nHost: reports.example\r\n\r\n")
    c.at(2120).s(response(500, "Internal Server Error", b"database timeout"))
    c.close()

    # 5. A slow success.
    c = Conn(frames, 5).open()
    c.c(b"GET /search?q=shoes HTTP/1.1\r\nHost: shop.example\r\n\r\n")
    c.at(1520).s(response(200, "OK", b"[]"))
    c.close()

    # 6. Pipelining: two requests in one segment, both responses in one.
    c = Conn(frames, 6).open()
    c.c(b"GET /a HTTP/1.1\r\nHost: pipe.example\r\n\r\nGET /b HTTP/1.1\r\nHost: pipe.example\r\n\r\n")
    c.at(30).s(response(200, "OK", b"aaa") + response(200, "OK", b"bbbbbb"))
    c.close()

    # 7. Expect: 100-continue.
    c = Conn(frames, 7).open()
    body = b"z" * 500
    c.c(b"PUT /upload HTTP/1.1\r\nHost: up.example\r\nContent-Length: 500\r\nExpect: 100-continue\r\n\r\n")
    c.at(21).s(b"HTTP/1.1 100 Continue\r\n\r\n")
    c.at(1).c(body)
    c.at(35).s(response(200, "OK", b"stored"))
    c.close()

    # 8. HTTP/1.0 response with no length: the body runs until the close.
    c = Conn(frames, 8).open()
    c.c(b"GET /legacy HTTP/1.0\r\nHost: old.example\r\n\r\n")
    c.at(30).s(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n" + b"y" * 800)
    c.at(1).s(b"y" * 200).at(1).s(flags=FIN | ACK).at(20).c(flags=FIN | ACK).at(0.1).s(flags=ACK)

    # 9. A request split over three segments, and a response whose two
    #    segments arrive in the wrong order.
    c = Conn(frames, 9).open()
    req = b"GET /split HTTP/1.1\r\nHost: split.example\r\nUser-Agent: zoo\r\n\r\n"
    c.c(req[:10]).at(0.2).c(req[10:30]).at(0.2).c(req[30:])
    whole = response(200, "OK", b"s" * 900)
    first = c.sseq
    c.at(30).send(False, PSH | ACK, whole[500:], seq=first + 500)
    c.at(0.3).send(False, PSH | ACK, whole[:500], seq=first)
    c.sseq += len(whole)
    c.close()

    # 10. HTTP on port 8080, Host with a port.
    c = Conn(frames, 10, port=8080).open()
    c.c(b"GET /health HTTP/1.1\r\nHost: internal.example:8080\r\n\r\n")
    c.at(22).s(response(200, "OK", b"ok"))
    c.close()

    # 11. No response at all.
    c = Conn(frames, 11).open()
    c.c(b"GET /hang HTTP/1.1\r\nHost: stuck.example\r\n\r\n")

    # 12. A WebSocket upgrade: what follows the 101 is not HTTP.
    c = Conn(frames, 12).open()
    c.c(b"GET /chat HTTP/1.1\r\nHost: ws.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
    c.at(21).s(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
    c.at(5).c(b"\x81\x85GET /x HTTP/1.1").at(20).s(b"\x81\x02hi")
    c.close()

    # 13. HTTPS (TLS 1.3): session tickets come right away, the answer
    #     900 ms later. The wait is the 920 ms to the answer.
    c = Conn(frames, 13, port=443).open()
    c.c(client_hello("slow-api.example"))
    c.at(20).s(server_hello() + tls(20, b"\x01") + tls(23, os.urandom(2500)))
    c.at(1).c(tls(20, b"\x01") + tls(23, os.urandom(53)) + tls(23, os.urandom(400)))
    c.at(20).s(tls(23, os.urandom(240)) + tls(23, os.urandom(240)))
    c.at(900).s(tls(23, os.urandom(1400))).at(0.2).s(tls(23, os.urandom(1400)))
    c.close()

    # 14. HTTPS where the answer comes in 30 ms, then the connection sits idle
    #     and the server closes it 5 s later. The wait is the 30 ms.
    c = Conn(frames, 14, port=443).open()
    c.c(client_hello("idle.example"))
    c.at(20).s(server_hello() + tls(20, b"\x01") + tls(23, os.urandom(2500)))
    c.at(1).c(tls(20, b"\x01") + tls(23, os.urandom(53)) + tls(23, os.urandom(400)))
    c.at(30).s(tls(23, os.urandom(1400))).at(0.2).s(tls(23, os.urandom(900)))
    c.at(5000).s(tls(23, os.urandom(19))).at(0.1).s(flags=FIN | ACK)
    c.at(20).c(flags=FIN | ACK).at(0.1).s(flags=ACK)

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
