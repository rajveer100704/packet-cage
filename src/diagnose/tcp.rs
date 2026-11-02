//! TCP: connections that never opened or were cut, slow connects, lost
//! packets, and receivers that could not keep up.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::IpAddr;

use super::{Category, Context, Finding, GIVE_UP_SECS, Severity, count, ip_filter, list};
use crate::analyze::tcp::{Tally, TcpHealth};
use crate::flow::{ResetKind, Side, TcpStatus};
use crate::units;

/// Retransmissions worth reporting: at least this many...
const LOSS_MIN_COUNT: u32 = 3;
/// ...and at least this share of the segments sent.
const LOSS_MIN_RATE: f64 = 0.02;
/// Loss this bad is an error, not a warning.
const LOSS_ERROR_RATE: f64 = 0.10;
const LOSS_ERROR_COUNT: u32 = 10;
/// A connect this much slower than the round trip means the SYN was sent again.
const SLOW_CONNECT_SECS: f64 = 0.5;
/// One client trying this many ports on a server looks like a port scan.
const SCAN_PORTS: usize = 10;
/// Times a sender has to fill the receive window before it is mentioned.
const WINDOW_FULL_MIN: u32 = 5;

pub(super) fn findings(ctx: &Context, explained: &HashSet<usize>) -> Vec<Finding> {
    let mut refused: BTreeMap<IpAddr, Vec<usize>> = BTreeMap::new();
    let mut no_answer: BTreeMap<IpAddr, Vec<usize>> = BTreeMap::new();
    let mut incomplete: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut server_resets: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut client_resets: BTreeMap<IpAddr, Vec<usize>> = BTreeMap::new();
    let mut one_sided: Vec<usize> = Vec::new();
    let mut slow_connect: BTreeMap<String, Vec<(usize, f64)>> = BTreeMap::new();
    let mut lossy: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut full: BTreeMap<(Side, String), Vec<usize>> = BTreeMap::new();
    let mut unseen: Vec<Tally> = Vec::new();

    for (i, flow) in ctx.flows().iter().enumerate() {
        let Some(conn) = &flow.tcp else {
            continue;
        };
        let server = flow.server.ip();
        if ctx.one_sided(i) {
            one_sided.push(i);
        }
        match conn.status() {
            TcpStatus::NoAnswer => {
                let gave_up = ctx.end.secs_since(flow.first_ts) >= GIVE_UP_SECS
                    || conn.health(Side::Client).retransmissions.count > 0;
                if gave_up {
                    no_answer.entry(server).or_default().push(i);
                }
            }
            TcpStatus::Refused => refused.entry(server).or_default().push(i),
            TcpStatus::HandshakeIncomplete if ctx.end.secs_since(flow.last_ts) >= GIVE_UP_SECS => {
                incomplete.entry(ctx.server(i)).or_default().push(i);
            }
            _ => {}
        }
        if let Some(reset) = conn.reset
            && reset.kind == ResetKind::Aborted
            && !explained.contains(&i)
            && !matches!(conn.status(), TcpStatus::Closed)
        {
            match reset.by {
                Side::Server => server_resets.entry(ctx.server(i)).or_default().push(i),
                Side::Client => client_resets.entry(flow.client.ip()).or_default().push(i),
            }
        }
        if let (Some((_, syn)), Some((_, syn_ack)), Some(rtt)) =
            (conn.syn, conn.syn_ack, conn.handshake_rtt())
        {
            let took = syn_ack.secs_since(syn);
            if took - rtt.server_side.unwrap_or(0.0) > SLOW_CONNECT_SECS {
                slow_connect
                    .entry(ctx.server(i))
                    .or_default()
                    .push((i, took + rtt.client_side().unwrap_or(0.0)));
            }
        }
        lossy.entry(ctx.connection(i)).or_default().push(i);
        for side in [Side::Client, Side::Server] {
            let health = conn.health(side);
            // A zero window is flagged on what the receiver sends; window
            // full on what the sender sends. Both are keyed by the receiver.
            if health.zero_windows.count > 0 {
                full.entry((side, ctx.connection(i))).or_default().push(i);
            }
            if health.window_full.count > 0 {
                full.entry((side.other(), ctx.connection(i)))
                    .or_default()
                    .push(i);
            }
            unseen.push(health.acked_unseen);
        }
    }

    let mut out = Vec::new();
    for (server, flows) in refused {
        out.push(unopened(ctx, server, &flows, Unopened::Refused));
    }
    for (server, flows) in no_answer {
        out.push(unopened(ctx, server, &flows, Unopened::NoAnswer));
    }
    for (server, flows) in incomplete {
        out.push(
            Finding::new(
                Severity::Warning,
                Category::Tcp,
                server,
                format!(
                    "the client never finished {} after the server's SYN-ACK",
                    count(flows.len() as u64, "handshake", "handshakes")
                ),
            )
            .hint("the SYN-ACK was lost on its way to the client, or the client gave up")
            .frames(flows.iter().filter_map(|&i| Some(ctx.conn(i).syn_ack?.0)))
            .filter(ctx.streams(&flows))
            .flows(flows),
        );
    }
    for (server, flows) in server_resets {
        let n = flows.len() as u64;
        out.push(
            Finding::new(
                Severity::Warning,
                Category::Tcp,
                server,
                format!(
                    "the server reset {} that {} open",
                    count(n, "connection", "connections"),
                    if n == 1 { "was" } else { "were" }
                ),
            )
            .hint(
                "the server, or a load balancer, proxy or firewall in between, cut the connection",
            )
            .frames(flows.iter().filter_map(|&i| Some(ctx.conn(i).reset?.frame)))
            .measure("connections", n as f64)
            .filter(format!("tcp.flags.reset == 1 && {}", ctx.streams(&flows)))
            .flows(flows),
        );
    }
    for (client, flows) in client_resets {
        let n = flows.len() as u64;
        let mut servers: Vec<String> = flows.iter().map(|&i| ctx.server(i)).collect();
        servers.dedup();
        out.push(
            Finding::new(
                Severity::Info,
                Category::Tcp,
                ctx.host(client),
                format!(
                    "reset {} to {} instead of closing {}",
                    count(n, "connection", "connections"),
                    list(&servers, 3),
                    if n == 1 { "it" } else { "them" }
                ),
            )
            .hint("usually an application closing in a hurry; harmless if its work was done")
            .frames(flows.iter().filter_map(|&i| Some(ctx.conn(i).reset?.frame)))
            .measure("connections", n as f64)
            .filter(format!("tcp.flags.reset == 1 && {}", ctx.streams(&flows)))
            .flows(flows),
        );
    }
    if !one_sided.is_empty() {
        let n = one_sided.len() as u64;
        out.push(
            Finding::new(
                Severity::Warning,
                Category::Capture,
                "",
                format!(
                    "only one direction of {} was captured",
                    count(n, "connection", "connections")
                ),
            )
            .hint("the capture point sees one side of the path (asymmetric routing, or a filter): answers may have been sent that it never saw")
            .frames(one_sided.iter().map(|&i| ctx.flows()[i].first_frame))
            .measure("connections", n as f64)
            .filter(ctx.streams(&one_sided))
            .flows(one_sided),
        );
    }
    for (server, conns) in slow_connect {
        let worst = conns.iter().map(|c| c.1).fold(0.0, f64::max);
        let flows: Vec<usize> = conns.iter().map(|c| c.0).collect();
        let text = if flows.len() == 1 {
            format!(
                "connecting took {}: the first SYN went unanswered and was sent again",
                units::duration(worst)
            )
        } else {
            format!(
                "{} took up to {} to open: the first SYN went unanswered and was sent again",
                count(flows.len() as u64, "connection", "connections"),
                units::duration(worst)
            )
        };
        out.push(
            Finding::new(Severity::Warning, Category::Tcp, server, text)
                .hint(
                    "SYNs or SYN-ACKs were lost, or the server was too busy to accept connections",
                )
                .spans(flows.iter().filter_map(|&i| {
                    let conn = ctx.conn(i);
                    Some((conn.syn?.0, conn.syn_ack?.0))
                }))
                .measure("connections", flows.len() as f64)
                .measure("slowest_secs", worst)
                .filter(format!("tcp.flags.syn == 1 && {}", ctx.streams(&flows)))
                .flows(flows),
        );
    }
    for (label, flows) in lossy {
        if let Some(finding) = loss(ctx, label, &flows) {
            out.push(finding);
        }
    }
    for ((side, label), mut flows) in full {
        // A connection with both a zero window and a full one was added twice.
        flows.dedup();
        out.extend(window(ctx, side, label, &flows));
    }

    let missed: u64 = unseen.iter().map(|t| u64::from(t.count)).sum();
    if missed > 0 {
        out.push(
            Finding::new(
                Severity::Info,
                Category::Capture,
                "",
                format!(
                    "the capture missed {} that reached the other side ({} acknowledged)",
                    count(missed, "packet", "packets"),
                    if missed == 1 { "it was" } else { "they were" }
                ),
            )
            .hint("the capture dropped packets: some loss reported here may be the capture's, not the network's")
            .spans(
                unseen
                    .iter()
                    .filter(|t| t.count > 0)
                    .map(|t| (t.first_frame, t.last_frame)),
            )
            .measure("packets", missed as f64)
            .filter("tcp.analysis.ack_lost_segment"),
        );
    }
    out
}

const REFUSED: &str = "nothing is listening on that port, or a firewall rejects the connection";
const NO_ANSWER: &str =
    "the server is down or unreachable, or a firewall silently drops the connection";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Unopened {
    Refused,
    NoAnswer,
}

/// Connection attempts to one server that were refused or got no answer.
fn unopened(ctx: &Context, server: IpAddr, flows: &[usize], how: Unopened) -> Finding {
    let attempts = flows.len() as u64;
    let ports: BTreeSet<u16> = flows
        .iter()
        .map(|&i| ctx.flows()[i].server.port())
        .collect();
    let clients: HashSet<IpAddr> = flows.iter().map(|&i| ctx.flows()[i].client.ip()).collect();
    let one_port = (ports.len() == 1)
        .then(|| ports.iter().next().copied())
        .flatten();
    let shown: Vec<String> = ports.iter().map(u16::to_string).collect();
    let (text, hint) = match (how, one_port) {
        (Unopened::Refused, Some(_)) if attempts == 1 => {
            ("connection refused".to_string(), REFUSED)
        }
        (Unopened::Refused, Some(_)) => (
            format!(
                "connection refused ({})",
                count(attempts, "attempt", "attempts")
            ),
            REFUSED,
        ),
        (Unopened::Refused, None) => (
            format!(
                "connections refused on {} ports ({})",
                ports.len(),
                list(&shown, 5)
            ),
            REFUSED,
        ),
        (Unopened::NoAnswer, Some(_)) if attempts == 1 => {
            ("no answer to the connection attempt".to_string(), NO_ANSWER)
        }
        (Unopened::NoAnswer, Some(_)) => (
            format!(
                "no answer to {} connection attempts",
                units::count(attempts)
            ),
            NO_ANSWER,
        ),
        (Unopened::NoAnswer, None) => (
            format!(
                "no answer to connection attempts on {} ports ({})",
                ports.len(),
                list(&shown, 5)
            ),
            NO_ANSWER,
        ),
    };
    let subject = match one_port {
        Some(port) => match ctx.analyzer.name_of(server) {
            Some(name) => format!("{name}:{port}"),
            None => ctx.flows()[flows[0]].server.to_string(),
        },
        None => ctx.host(server),
    };
    let scan = clients.len() == 1 && ports.len() >= SCAN_PORTS;
    let (severity, hint) = if scan {
        (
            Severity::Info,
            "one client tried many ports: this looks like a port scan".to_string(),
        )
    } else {
        (Severity::Error, hint.to_string())
    };
    let frames: Vec<u64> = flows
        .iter()
        .map(|&i| match ctx.conn(i).reset {
            Some(reset) => reset.frame,
            None => ctx.flows()[i].first_frame,
        })
        .collect();
    let filter = if flows.len() <= 30 {
        ctx.streams(flows)
    } else {
        format!("tcp.flags.syn == 1 && {}", ip_filter("dst", server))
    };
    Finding::new(severity, Category::Tcp, subject, text)
        .hint(hint)
        .frames(frames)
        .measure("attempts", attempts as f64)
        .filter(filter)
        .flows(flows.iter().copied())
}

/// Retransmissions between one client and one server.
fn loss(ctx: &Context, label: String, flows: &[usize]) -> Option<Finding> {
    let mut sides = [TcpHealth::default(), TcpHealth::default()];
    for &i in flows {
        let conn = ctx.conn(i);
        sides[0].add(conn.health(Side::Client));
        sides[1].add(conn.health(Side::Server));
    }
    let mut total = sides[0].clone();
    total.add(&sides[1]);
    let resent = total.retransmissions.count;
    let rate = f64::from(resent) / total.segments.max(1) as f64;
    if resent < LOSS_MIN_COUNT || rate < LOSS_MIN_RATE {
        return None;
    }
    let severity = if rate >= LOSS_ERROR_RATE && resent >= LOSS_ERROR_COUNT {
        Severity::Error
    } else {
        Severity::Warning
    };
    let mut text = format!(
        "{} of segments retransmitted ({} of {})",
        units::percent(u64::from(resent), total.segments),
        units::count(u64::from(resent)),
        units::count(total.segments)
    );
    // Who resent most, and whether the capture saw what they resent.
    let mostly = [(Side::Client, &sides[0]), (Side::Server, &sides[1])]
        .into_iter()
        .find(|(_, h)| h.retransmissions.count * 5 >= resent * 4);
    if let Some((side, _)) = mostly {
        text.push_str(match side {
            Side::Client => ", mostly by the client",
            Side::Server => ", mostly by the server",
        });
    }
    let hint = if total.spurious_retransmissions.count * 2 > resent {
        Some("most were spurious: the data had arrived, so ACKs were lost or the sender gave up waiting too soon".to_string())
    } else {
        mostly.map(|(side, health)| {
            let (sender, receiver) = match side {
                Side::Client => ("client", "server"),
                Side::Server => ("server", "client"),
            };
            if health.not_captured.count == 0 {
                format!("the capture saw the first copies, so packets were lost between the capture point and the {receiver}")
            } else {
                format!("the first copies never reached the capture point, so packets were lost between the {sender} and the capture point")
            }
        })
    };
    let mut spans: Vec<(u64, u64)> = Vec::new();
    for &i in flows {
        let conn = ctx.conn(i);
        for side in [Side::Client, Side::Server] {
            let t = conn.health(side).retransmissions;
            if t.count > 0 {
                spans.push((t.first_frame, t.last_frame));
            }
        }
    }
    let involved: Vec<usize> = flows
        .iter()
        .copied()
        .filter(|&i| {
            let conn = ctx.conn(i);
            conn.health(Side::Client).retransmissions.count
                + conn.health(Side::Server).retransmissions.count
                > 0
        })
        .collect();
    // The rate counts every connection between the two; say how many of
    // them resent anything.
    if involved.len() < flows.len() {
        text.push_str(&format!(
            ", in {} of {} connections",
            involved.len(),
            flows.len()
        ));
    } else if flows.len() > 1 {
        text.push_str(&format!(", over {} connections", flows.len()));
    }
    Some(
        Finding::new(severity, Category::Loss, label, text)
            .maybe_hint(hint)
            .spans(spans)
            .measure("retransmissions", f64::from(resent))
            .measure("segments", total.segments as f64)
            .measure("retransmission_rate", rate)
            .filter(format!(
                "tcp.analysis.retransmission && {}",
                ctx.streams(&involved)
            ))
            .flows(involved),
    )
}

/// A receiver that ran out of buffer space (zero window), or a sender that
/// kept filling the receiver's window. `side` is the receiver.
fn window(ctx: &Context, side: Side, label: String, flows: &[usize]) -> Option<Finding> {
    let mut zero = Tally::default();
    let mut filled = Tally::default();
    for &i in flows {
        let conn = ctx.conn(i);
        merge(&mut zero, conn.health(side).zero_windows);
        // Window full is flagged on the sender's segments.
        merge(&mut filled, conn.health(side.other()).window_full);
    }
    let receiver = match side {
        Side::Client => "client",
        Side::Server => "server",
    };
    let finding =
        if zero.count > 0 {
            Finding::new(
            Severity::Warning,
            Category::Slow,
            label,
            format!(
                "the {receiver} ran out of receive buffer ({})",
                count(u64::from(zero.count), "zero-window packet", "zero-window packets")
            ),
        )
        .hint(format!(
            "the application on the {receiver} reads too slowly: the network is not the bottleneck"
        ))
        .spans([(zero.first_frame, zero.last_frame)])
        .measure("zero_windows", f64::from(zero.count))
        .filter(format!("tcp.analysis.zero_window && {}", ctx.streams(flows)))
        } else if filled.count >= WINDOW_FULL_MIN {
            Finding::new(
                Severity::Info,
                Category::Slow,
                label,
                format!(
                    "the sender filled the {receiver}'s receive window {}",
                    times(filled.count)
                ),
            )
            .hint(format!(
                "throughput was limited by the {receiver}'s receive window, not the network"
            ))
            .spans([(filled.first_frame, filled.last_frame)])
            .measure("window_full", f64::from(filled.count))
            .filter(format!(
                "tcp.analysis.window_full && {}",
                ctx.streams(flows)
            ))
        } else {
            return None;
        };
    Some(finding.flows(flows.iter().copied()))
}

fn merge(into: &mut Tally, t: Tally) {
    if t.count == 0 {
        return;
    }
    if into.count == 0 {
        *into = t;
        return;
    }
    into.count += t.count;
    into.first_frame = into.first_frame.min(t.first_frame);
    into.last_frame = into.last_frame.max(t.last_frame);
}

fn times(n: u32) -> String {
    match n {
        1 => "once".to_string(),
        2 => "twice".to_string(),
        n => format!("{} times", units::count(u64::from(n))),
    }
}
