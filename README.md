# PacketCage

Reads a packet capture and tells you what went wrong on the network, in plain English: failed DNS lookups, refused or reset connections, packet loss, TLS handshake failures, and whether a slow request was the network's fault or the server's.

```
$ packet-cage examples/demo.pcap
examples/demo.pcap: 314 packets over 8.19 s, from 2025-10-09 08:53:20.000 UTC

✗ DNS   api.internal: name does not exist (NXDOMAIN, asked 3 times)             frames 41-42, 134
✗ TLS   pay.example.com:443: client rejected the handshake: unknown_ca (the certificate's issuer is not trusted)  frame 84
        → usually a private CA, or a TLS-inspecting proxy whose CA the client does not have
⚠ SLOW  api.example.com:443: network RTT 40.0 ms, server took 2.10 s to answer  frames 114-166
        → the server is slow, not the network
⚠ LOSS  10.0.0.5 → cdn.example.com:443: 7.4% of segments retransmitted (4 of 54), mostly by the server  frames 206-261
        → the capture saw the first copies, so packets were lost between the capture point and the client
✓ 11 other connections look healthy
```

**PacketCage 0.2.0** is an independently maintained packet analysis tool with optional Linux sandbox execution. See [third-party notices](THIRD_PARTY_NOTICES.md) for applicable license and attribution information.

## Linux sandbox (experimental)

PacketCage provides `packet-cage sandbox run`, a Linux-only isolated analysis mode using namespaces, a private root filesystem, cgroup v2 resource limits, timeout cleanup and a seccomp syscall filter.

The sandbox is experimental. It has been runtime-tested in WSL2. Native Linux validation and further security review are still needed.
See `docs/SANDBOX.md` for delegated cgroup setup, usage, resource limits and security notes.

### Build dependencies

On Debian or Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libseccomp-dev
cargo build --release
```

### Run an analysis

```bash
packet-cage sandbox run --cgroup-root "$MANAGER" capture.pcap
```

The sandbox command is Linux-only. Other PacketCage commands remain available on supported platforms.

## Install

PacketCage is currently intended to be built from source. Prebuilt releases will be published through this repository once available.

Clone this repository and build:

```bash
git clone https://github.com/rajveer100704/packet-cage.git
cd packet-cage
cargo build --release
```

On Debian or Ubuntu, install the Linux sandbox dependencies first, as described in the Linux sandbox section above.


## Usage

`packet-cage FILE` prints the report above. Each finding is one sentence and the frames to look at in Wireshark. When the numbers point one way, a second line says what it most likely means. ✗ marks something that failed, ⚠ something degraded (slow, lossy, or failing some of the time), and • a note. [`examples/demo.pcap`](examples/demo.pcap) is a generated capture of a laptop browsing for ten seconds, to try it on.

It looks for:
- DNS: names that don't exist, server failures and refusals, servers that don't answer or can't be reached, slow and retried lookups
- TCP: refused and unanswered connections, connections the server reset, connects that needed a second SYN, receivers that ran out of buffer
- loss: how much was retransmitted, by whom, and whether it was lost before or after the capture point
- slow servers: the network's round trip against the server's own time, for HTTP and for encrypted connections alike
- TLS: rejected handshakes and why, certificate problems (expired, wrong name, self-signed), outdated versions, slow servers
- HTTP: error responses, and requests that never got one
- the capture itself: cut-off files, packets cut short, one-sided captures, and packets the capture missed

Options:
- `--format json`: for scripts. Each finding has its severity, frames, measurements, and a Wireshark filter that shows it. `schema` goes up when a field changes.
- `--format html -o report.html`: one self-contained page to attach to a ticket.
- `--all`: show every finding; text output stops after 30.
- `--color auto|always|never`: `NO_COLOR` is respected.

`dump` prints one line per packet:

```
$ packet-cage dump capture.pcap
     1    0.000000  172.16.5.1:49178 → 172.16.5.10:8443 TCP [SYN] seq=0 win=29200 len=0 mss=1460 wscale=7 sack_perm
     2    0.000289  172.16.5.10:8443 → 172.16.5.1:49178 TCP [SYN, ACK] seq=0 ack=1 win=28960 len=0 mss=1460 wscale=7 sack_perm
     3    0.000322  172.16.5.1:49178 → 172.16.5.10:8443 TCP [ACK] seq=1 ack=1 win=229 len=0
   ...
    14   50.000000  192.168.1.10:40006 → 192.168.1.1:53 DNS query 0x0606 A slow.example
    15   51.000000  192.168.1.10:40006 → 192.168.1.1:53 DNS query 0x0606 A slow.example [retry of frame 14]
    16   51.200000  192.168.1.1:53 → 192.168.1.10:40006 DNS response 0x0606 A slow.example → A 198.51.100.6 (1.20 s)
    20   70.000000  192.168.1.10:40008 → 192.168.1.2:53 DNS query 0x0808 A down.example
    21   70.001000  192.168.1.2 → 192.168.1.10 ICMP destination unreachable (port unreachable) [about the DNS query in frame 20]
```

- TCP sequence numbers count from the start of each connection, as in Wireshark; `-S` shows the raw values.
- TCP problems get Wireshark's labels, e.g. `[TCP Retransmission]` or `[TCP Dup ACK 9#2]`, decided by the same rules.
- DNS responses show their response time, and ICMP errors point back to the query that caused them.
- TLS handshakes show the server name, versions and ALPN, the certificate (before TLS 1.3, which encrypts it) and alerts.
- HTTP requests and responses show which request each response answers and the time to its first byte.

`stats` summarizes the whole capture:

```
$ packet-cage stats capture.pcap
...
Problem lookups: 8
Name             Type  Server          Result                        Time  Sent  Frame
broken.example   A     192.168.1.1:53  server failure             20.0 ms     1     10
nope.example     A     192.168.1.1:53  no such name               20.0 ms     1      8
blocked.example  A     192.168.1.1:53  refused                    20.0 ms     1     12
loop.example     A     192.168.1.1:53  malformed response          9.0 ms     1     34
down.example     A     192.168.1.2:53  server unreachable (ICMP)        -     1     20
```

It shows:
- the protocol mix
- the busiest hosts, with the names they were looked up by in DNS
- each TCP and UDP conversation, with round-trip time, retransmissions and state
- a summary of TCP problems
- DNS results
- HTTP results: status codes, server times, and the requests that failed or were slow
- for every TCP connection, its "wait": how long the client waited for the server's answer. This works for HTTPS too, without decrypting.
- TLS results, with problem handshakes explained, e.g. `client rejected the handshake: unknown_ca (the certificate's issuer is not trusted)` or `certificate is for other.example, not wrong.example`

Stream numbers match Wireshark's `tcp.stream` and `udp.stream`, so `tcp.stream == 1` in Wireshark shows the same connection.

Every field, flag and timing above is checked against tshark on real and generated captures. The few places where packet-cage differs are listed [below](#where-it-differs-from-wireshark).

Reads pcap and pcapng files directly, with no libpcap or Npcap needed. Supported link layers: Ethernet (with VLAN tags), Linux cooked (`tcpdump -i any`), loopback, and raw IP. Cut-off captures are read up to the last complete packet.

## Filters

`dump -f` takes a display filter in Wireshark's syntax, and a filter means the same in both tools:

```
$ packet-cage dump examples/demo.pcap -f 'tcp.analysis.retransmission'
   206    5.262300  203.0.113.30:443 → 10.0.0.5:50120 TCP [PSH, ACK] seq=8094 ack=589 win=64240 len=1400 [TCP Fast Retransmission]
   224    5.353800  203.0.113.30:443 → 10.0.0.5:50120 TCP [PSH, ACK] seq=20694 ack=589 win=64240 len=1400 [TCP Fast Retransmission]
   ...
```

- Fields have Wireshark's names and types: `ip.addr`, `tcp.port`, `tcp.flags.reset`, `dns.qry.name`, `tls.handshake.extensions_server_name`, `http.response.code`, the `tcp.analysis.*` flags and so on. `packet-cage fields` lists all 150.
- Operators: `==`, `!=`, `>`, `<`, `>=`, `<=`, `contains`, `matches` (a regular expression, ignoring case), `in {80, 443, 8000..8080}`, `&` for bits, and `&&`, `||`, `^^`, `!` (or `and`, `or`, `xor`, `not`). Addresses take networks, as in `ip.addr == 10.0.0.0/8`, and some numbers take names, as in `dns.qry.type == AAAA`. Functions: `lower()`, `upper()`, `len()`, `count()`.
- The rules are Wireshark's. A field on its own means it is there, so `tcp.flags.syn` matches every TCP packet and `tcp.flags.syn == 1` only SYNs. `!=` matches when no copy of the field is equal: `ip.addr != 10.0.0.1` leaves out packets to and from it.
- The filters in the report's JSON and HTML are filters like these, so `dump -f` shows the packets behind a finding.
- Mistakes are caught before the capture is read:
  ```
  $ packet-cage dump capture.pcap -f 'tcp.flags.rst'
  error: unknown field "tcp.flags.rst"; did you mean "tcp.flags.reset"?
    tcp.flags.rst
    ^~~~~~~~~~~~~
  ```

Every field is compared with tshark on every packet of 48 captures, and so are the packets that filters pick. The differences are listed in [PLAN.md](PLAN.md).

## In CI

`packet-cage check` exits with 1 when a capture has problems, 0 when it hasn't, and 2 when it can't read the capture or the filter:

```
$ packet-cage check examples/demo.pcap
examples/demo.pcap: 2 findings match finding.severity == error
✗ DNS   api.internal: name does not exist (NXDOMAIN, asked 3 times)  frames 41-42, 134
✗ TLS   pay.example.com:443: client rejected the handshake: unknown_ca (the certificate's issuer is not trusted)  frame 84
        → usually a private CA, or a TLS-inspecting proxy whose CA the client does not have
```

`--fail-on` says what fails, and can be given more than once. It takes a packet filter, or a filter on the report's findings: `finding.severity`, `finding.category`, `finding.text`, and the numbers behind each finding, such as `finding.server_secs` or `finding.retransmission_rate`.

```
packet-cage check capture.pcap \
  --fail-on 'finding.severity >= warning && finding.category != slow' \
  --fail-on 'finding.server_secs > 1' \
  --fail-on 'tcp.analysis.zero_window'
```

In GitHub Actions:

```yaml
- uses: rajveer100704/packet-cage@main
  with:
    captures: captures/*.pcapng
    fail-on: finding.severity == error
```

Each finding becomes an annotation on the run, and the report goes to the job summary. Pinned to a release, the action downloads that release's binary; `@main` builds from source, which takes about a minute.

## Live capture

`packet-cage live` captures from a network interface, then prints the same report. Here three downloads ran over a loopback link that Linux's `tc netem` made drop 2% of packets:

```
$ sudo packet-cage live -i lo -w loss.pcapng --capture-filter 'tcp port 8001'
Capturing on lo; Ctrl-C stops it
^C
loss.pcapng: 2,438 packets over 5.67 s, from 2026-10-14 13:36:35.733 UTC

⚠ LOSS  127.0.0.1 → 127.0.0.1:8001: 2.1% of segments retransmitted (36 of 1,738), mostly by the server, in 2 of 3 connections  frames 189-201, 272-2190
        → the first copies never reached the capture point, so packets were lost between the server and the capture point
✓ 1 other connection looks healthy
```

netem drops packets before the capture sees them, and the report places the loss there.

- `-i` takes the interface's name, its number in `packet-cage interfaces`, one of its addresses, or its description. Without `-i`, it captures on the interface with the route to the internet.
- `-d 30s` stops after a while and `-c 1000` after so many packets; Ctrl-C stops it any time. The report comes after.
- `-w capture.pcapng` keeps the packets, so the frames in the report can be opened in Wireshark.
- `--capture-filter 'port 443'` captures only what matches, in tcpdump's syntax. On a busy link that keeps the capture up to speed. If the system still drops packets, the report says how many, since a dropped packet looks like a lost one.
- It needs libpcap, which macOS has and Linux distributions package (`libpcap0.8` on Debian and Ubuntu), or [Npcap](https://npcap.com) on Windows. packet-cage loads it only for `live` and `interfaces`, so reading files never needs it.
- Capturing needs root (`sudo`) or administrator rights. On Linux, `sudo setcap cap_net_raw,cap_net_admin=eip $(which packet-cage)` lets it capture without root.

## Getting a capture

- `packet-cage live -w capture.pcapng`, above
- Linux/macOS: `sudo tcpdump -i any -w capture.pcap`
- Windows, with nothing to install (as administrator):
  ```
  pktmon start --capture --comp nics --pkt-size 0 --file-name capture.etl
  pktmon stop
  pktmon etl2pcap capture.etl --out capture.pcapng
  ```
  `--comp nics` records each packet once, at the network card, instead of at every layer it passes.
- Wireshark: File → Save As → pcapng

## packet-cage and Wireshark

Wireshark shows everything in a capture, which helps once you know what to look for. Its Expert Information for the demo capture has no errors and no warnings, only notes and chats:

```
$ tshark -r examples/demo.pcap -q -z expert
Notes (155)
=============
   Frequency      Group           Protocol  Summary
          14   Sequence                TCP  This frame initiates the connection closing
           4   Sequence                TCP  Duplicate ACK (#1)
   ...
           4   Sequence                TCP  This frame is a (suspected) fast retransmission
           4   Sequence                TCP  This frame is a (suspected) retransmission

Chats (82)
=============
   Frequency      Group           Protocol  Summary
          14   Sequence                TCP  Connection establish request (SYN): server port 443
   ...
```

The failed lookup, the rejected certificate and the server that took two seconds are all in the packets, but nothing there points at them. packet-cage's report, at the top of this page, starts with them. Each finding carries a display filter, so the packets behind it are one paste away in Wireshark.

### Where it differs from Wireshark

packet-cage uses Wireshark's field names and follows its rules, and is checked against tshark 4.6 on every capture in this repository and dozens of Wireshark's samples. Where the two differ:

- **TCP:** SACK blocks are compared using raw sequence numbers on both sides; Wireshark mixes relative and raw ones, so it never counts a segment as already SACKed. Acknowledged segments are dropped from tracking only when the ACK flag is set. Neither has changed a flag on any capture tested.
- **DNS:** a query sent again more than 5 seconds later is still the same lookup, so a 5-second stall shows up as a slow answer. Wireshark starts a new transaction, though the `dns.*` filter fields follow Wireshark's rule. A response must come from the server the query went to. DNS is read on port 53, and mDNS and LLMNR on 5353 and 5355; Wireshark also guesses at DNS on other UDP ports. Wireshark still shows the type and address of a record whose name is broken.
- **TLS:** captures that carry their own keys aren't decrypted. TLS is recognized from the ClientHello, so a connection that started before the capture isn't seen as TLS; Wireshark goes by port 443. SSLv2-format hellos aren't read. In TLS 1.3, a 19-byte encrypted record before the client's Finished is taken to be an alert; tshark can't tell without the keys.
- **HTTP:** fields are on the frame that ends the headers, as in Wireshark with "Reassemble HTTP bodies" off. Pipelined responses are always matched to their requests; Wireshark does so only when the requests came in separate segments.

The details, with the numbers behind each check, are in [PLAN.md](PLAN.md).

## Sample captures

Each one comes with what tshark says about it (`*.tshark.txt` next to it), and with the script that made it:

- [`examples/demo.pcap`](examples/demo.pcap): a laptop browsing for ten seconds, with a failed lookup, a rejected certificate, a slow server and a lossy download.
- [`tests/fixtures/tcp-zoo.pcap`](tests/fixtures/tcp-zoo.pcap): one connection for each TCP problem Wireshark flags: retransmissions of every kind, duplicate ACKs, out-of-order and lost segments, zero and full windows, keep-alives.
- [`tests/fixtures/dns-zoo.pcap`](tests/fixtures/dns-zoo.pcap): DNS error codes, servers that don't answer or can't be reached, retries, a truncated answer retried over TCP, IPv6, broken names.
- [`tests/fixtures/tls-zoo.pcap`](tests/fixtures/tls-zoo.pcap): 15 TLS handshakes, good and failed, with real certificates from a test CA.
- [`tests/fixtures/http-zoo.pcap`](tests/fixtures/http-zoo.pcap): HTTP/1.x requests and responses, from simple to pipelined, chunked, `100 Continue` and upgraded.

## Building

```
cargo build --release
cargo test
```

## License

MIT or Apache-2.0, at your option.
