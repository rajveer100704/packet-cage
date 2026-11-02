//! HTTP: error responses, and requests that never got one.

use std::collections::BTreeMap;

use super::{Category, Context, Finding, GIVE_UP_SECS, Severity, list};
use crate::analyze::http::Exchange;
use crate::flow::{Side, TcpStatus};
use crate::units;

pub(super) fn findings(ctx: &Context) -> Vec<Finding> {
    let mut failed: BTreeMap<(String, u16, String), Vec<&Exchange>> = BTreeMap::new();
    let mut unanswered: BTreeMap<(String, String), Vec<&Exchange>> = BTreeMap::new();
    for exchange in ctx.analyzer.http.exchanges() {
        let server = ctx.server(exchange.flow);
        match &exchange.response {
            Some(r) if r.status >= 400 => failed
                .entry((server, r.status, r.reason.clone()))
                .or_default()
                .push(exchange),
            Some(_) => {}
            None => {
                if exchange.request.is_some()
                    && !ctx.one_sided(exchange.flow)
                    && let Some(why) = no_response(ctx, exchange)
                {
                    unanswered.entry((server, why)).or_default().push(exchange);
                }
            }
        }
    }

    let mut out = Vec::new();
    for ((server, status, reason), group) in failed {
        let severity = if status >= 500 {
            Severity::Error
        } else {
            Severity::Warning
        };
        let text = format!("{status} {reason} for {}", requests(&group));
        let flows: Vec<usize> = group.iter().map(|e| e.flow).collect();
        out.push(
            Finding::new(severity, Category::Http, server, text)
                .maybe_hint(status_hint(status))
                .frames(group.iter().flat_map(|e| {
                    e.request_frame
                        .into_iter()
                        .chain(e.response_start.map(|a| a.frame))
                }))
                .measure("requests", group.len() as f64)
                .filter(format!(
                    "http.response.code == {status} && {}",
                    ctx.streams(&flows)
                ))
                .flows(flows),
        );
    }
    for ((server, why), group) in unanswered {
        let flows: Vec<usize> = group.iter().map(|e| e.flow).collect();
        out.push(
            Finding::new(
                Severity::Error,
                Category::Http,
                server,
                format!("no response to {}: {why}", requests(&group)),
            )
            .frames(group.iter().filter_map(|e| e.request_frame))
            .measure("requests", group.len() as f64)
            .filter(format!(
                "http.request && !http.response_in && {}",
                ctx.streams(&flows)
            ))
            .flows(flows),
        );
    }
    out
}

/// Why a request got no response, or `None` if the capture ended too soon
/// to tell.
fn no_response(ctx: &Context, exchange: &Exchange) -> Option<String> {
    let sent = exchange.request_end.or(exchange.request_start)?;
    let conn = ctx.conn(exchange.flow);
    Some(match conn.status() {
        TcpStatus::Reset(Side::Server) => "the server reset the connection".to_string(),
        TcpStatus::Reset(Side::Client) => "the client gave up and reset the connection".to_string(),
        TcpStatus::Closed | TcpStatus::HalfClosed => {
            "the connection was closed without one".to_string()
        }
        _ => {
            let waited = ctx.end.secs_since(sent.ts);
            if waited < GIVE_UP_SECS {
                return None;
            }
            format!(
                "still waiting {} later, when the capture ended",
                units::duration(waited)
            )
        }
    })
}

/// "GET /a", or "3 requests (GET /a, GET /b and POST /c)"
fn requests(group: &[&Exchange]) -> String {
    let mut labels: Vec<String> = Vec::new();
    for exchange in group {
        let label = match &exchange.request {
            Some(r) => format!("{} {}", r.method, short(&r.target)),
            None => "a request not captured".to_string(),
        };
        if !labels.contains(&label) {
            labels.push(label);
        }
    }
    if group.len() == 1 {
        labels.remove(0)
    } else {
        format!("{} requests ({})", group.len(), list(&labels, 3))
    }
}

pub(super) fn short(target: &str) -> String {
    const MAX: usize = 60;
    if target.chars().count() <= MAX {
        return target.to_string();
    }
    let cut: String = target.chars().take(MAX - 1).collect();
    format!("{cut}…")
}

fn status_hint(status: u16) -> Option<&'static str> {
    Some(match status {
        401 | 407 => "the request had no valid credentials",
        403 => "the server understood the request but will not allow it",
        429 => "the client is sending too many requests and is being rate limited",
        500 => "the server hit an error; its logs should say why",
        502 | 504 => "a proxy or load balancer got no good answer from the server behind it",
        503 => "the server is overloaded or down for maintenance",
        _ => return None,
    })
}
