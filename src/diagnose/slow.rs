//! Slowness, and whether the server or the network is to blame. The TCP
//! handshake gives the network's round trip; whatever a client waited
//! beyond that, the server spent.

use std::collections::{BTreeMap, HashSet};

use super::{Category, Context, Finding, Severity, count};
use crate::analyze::dns::DNS_PORT;
use crate::analyze::http::SLOW_SERVER_SECS;
use crate::units;

/// For connections we can't read into (mostly encrypted ones), a wait this
/// long is reported. Higher than for HTTP, because without the requests we
/// can't tell a slow answer from one that was never asked for promptly.
pub const WAIT_SECS: f64 = 1.0;
/// A round trip this long slows every request on its own.
pub const HIGH_RTT_SECS: f64 = 0.25;
/// Interactive protocols, where a long wait is a person thinking.
const INTERACTIVE_PORTS: [u16; 4] = [22, 23, 3389, 5900];

struct Slow {
    flow: usize,
    /// The request, when it could be read.
    request: Option<String>,
    /// From the request to the first byte of the answer, at the capture point.
    wait: f64,
    /// The server's part of it, once the network round trip is known.
    server: Option<f64>,
    /// The whole round trip between client and server.
    rtt: Option<f64>,
    from: u64,
    to: u64,
}

impl Slow {
    fn took(&self) -> f64 {
        self.server.unwrap_or(self.wait)
    }
}

pub(super) fn findings(ctx: &Context) -> Vec<Finding> {
    let mut groups: BTreeMap<(String, bool), Vec<Slow>> = BTreeMap::new();
    let mut http_flows = HashSet::new();
    for exchange in ctx.analyzer.http.exchanges() {
        http_flows.insert(exchange.flow);
        let conn = ctx.conn(exchange.flow);
        let (Some(wait), Some(request), Some(response)) = (
            exchange.time_to_first_byte(),
            &exchange.request,
            exchange.response_start,
        ) else {
            continue;
        };
        let slow = Slow {
            flow: exchange.flow,
            request: Some(format!(
                "{} {}",
                request.method,
                super::http::short(&request.target)
            )),
            wait,
            server: exchange.server_time(conn),
            rtt: conn.handshake_rtt().map(|r| r.total),
            from: exchange.request_frame.unwrap_or(response.frame),
            to: response.frame,
        };
        if slow.took() > SLOW_SERVER_SECS {
            groups
                .entry((ctx.server(exchange.flow), true))
                .or_default()
                .push(slow);
        }
    }
    for (i, flow) in ctx.flows().iter().enumerate() {
        let Some(conn) = &flow.tcp else {
            continue;
        };
        let port = flow.server.port();
        if http_flows.contains(&i) || port == DNS_PORT || INTERACTIVE_PORTS.contains(&port) {
            continue;
        }
        let Some(wait) = conn.longest_wait else {
            continue;
        };
        // A wait for the ServerHello is the TLS rule's to report.
        let hello = ctx
            .analyzer
            .tls
            .for_flow(i)
            .and_then(|h| h.client_hello.as_ref());
        if hello.is_some_and(|(at, _)| at.frame == wait.request_frame) {
            continue;
        }
        let rtt = conn.handshake_rtt();
        let slow = Slow {
            flow: i,
            request: None,
            wait: wait.secs,
            server: rtt
                .and_then(|r| r.server_side)
                .map(|network| (wait.secs - network).max(0.0)),
            rtt: rtt.map(|r| r.total),
            from: wait.request_frame,
            to: wait.response_frame,
        };
        if slow.took() > WAIT_SECS {
            groups.entry((ctx.server(i), false)).or_default().push(slow);
        }
    }

    let mut out = Vec::new();
    let mut reported = HashSet::new();
    for ((server, http), mut group) in groups {
        group.sort_by(|a, b| b.took().total_cmp(&a.took()));
        reported.insert(server.clone());
        out.push(slow_server(ctx, server, http, &group));
    }
    out.extend(far_servers(ctx, &reported));
    out
}

fn slow_server(ctx: &Context, server: String, http: bool, group: &[Slow]) -> Finding {
    let worst = &group[0];
    let n = group.len() as u64;
    let many = if http {
        count(n, "request", "requests")
    } else {
        count(n, "connection", "connections")
    };
    let text = match (worst.server, worst.rtt) {
        (Some(took), Some(rtt)) => {
            let mut text = format!("network RTT {}, server took ", units::duration(rtt));
            match (&worst.request, n) {
                (Some(request), 1) => {
                    text.push_str(&format!("{} to answer {request}", units::duration(took)))
                }
                (None, 1) => text.push_str(&format!("{} to answer", units::duration(took))),
                (Some(request), _) => text.push_str(&format!(
                    "up to {} ({many}; slowest {request})",
                    units::duration(took)
                )),
                (None, _) => text.push_str(&format!("up to {} ({many})", units::duration(took))),
            }
            text
        }
        _ => match (&worst.request, n) {
            (Some(request), 1) => format!(
                "waited {} for the answer to {request}",
                units::duration(worst.wait)
            ),
            (None, 1) => format!("waited {} for the answer", units::duration(worst.wait)),
            (Some(request), _) => format!(
                "waited up to {} for answers ({many}; slowest {request})",
                units::duration(worst.wait)
            ),
            (None, _) => format!(
                "waited up to {} for answers ({many})",
                units::duration(worst.wait)
            ),
        },
    };
    let hint = match (worst.server, worst.rtt) {
        (Some(took), Some(rtt)) if took >= 2.0 * rtt => Some("the server is slow, not the network"),
        (Some(_), Some(_)) => Some("the server and the network round trip both add to the wait"),
        _ => None,
    };
    let flows: Vec<usize> = group.iter().map(|s| s.flow).collect();
    let mut finding = Finding::new(Severity::Warning, Category::Slow, server, text)
        .maybe_hint(hint)
        .spans(group.iter().take(5).map(|s| (s.from, s.to)))
        .measure("wait_secs", worst.wait);
    if let Some(took) = worst.server {
        finding = finding.measure("server_secs", took);
    }
    if let Some(rtt) = worst.rtt {
        finding = finding.measure("network_rtt_secs", rtt);
    }
    let filter = if http {
        format!("http.time > {SLOW_SERVER_SECS} && {}", ctx.streams(&flows))
    } else {
        ctx.streams(&flows)
    };
    finding
        .measure(if http { "requests" } else { "connections" }, n as f64)
        .filter(filter)
        .flows(flows)
}

/// Servers whose round trip alone makes everything slow.
fn far_servers(ctx: &Context, reported: &HashSet<String>) -> Vec<Finding> {
    let mut far: BTreeMap<String, Vec<(usize, f64)>> = BTreeMap::new();
    for (i, flow) in ctx.flows().iter().enumerate() {
        let Some(rtt) = flow.tcp.as_ref().and_then(|c| c.handshake_rtt()) else {
            continue;
        };
        let server = ctx.server(i);
        if rtt.total >= HIGH_RTT_SECS && !reported.contains(&server) {
            far.entry(server).or_default().push((i, rtt.total));
        }
    }
    far.into_iter()
        .map(|(server, conns)| {
            let rtt = conns.iter().map(|c| c.1).fold(0.0, f64::max);
            let flows: Vec<usize> = conns.iter().map(|c| c.0).collect();
            Finding::new(
                Severity::Info,
                Category::Slow,
                server,
                format!("network round trip of {}", units::duration(rtt)),
            )
            .hint("every handshake and request pays this; the server is far away or the path is congested")
            .frames(flows.iter().filter_map(|&i| ctx.conn(i).syn.map(|s| s.0)))
            .measure("network_rtt_secs", rtt)
            .filter(ctx.streams(&flows))
            .flows(flows)
        })
        .collect()
}
