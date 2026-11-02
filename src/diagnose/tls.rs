//! TLS: handshakes that failed, certificate problems, old versions and slow
//! servers.

use std::collections::BTreeMap;

use super::{Category, Context, Finding, GIVE_UP_SECS, Severity};
use crate::analyze::tls::{Handshake, TlsProblem};
use crate::decode::tls;
use crate::flow::{Side, TcpStatus};

/// The alert a client sends when it doesn't trust who signed the certificate.
const UNKNOWN_CA: u8 = 48;

pub(super) fn findings(ctx: &Context) -> Vec<Finding> {
    // Handshakes with the same problems on the same server are one finding.
    let mut groups: BTreeMap<(String, String), Group> = BTreeMap::new();
    for handshake in ctx.analyzer.tls.handshakes() {
        let conn = ctx.conn(handshake.flow);
        let problems: Vec<TlsProblem> = handshake
            .problems(conn)
            .into_iter()
            .filter(|p| !cut_off_by_capture_end(ctx, handshake, p))
            .collect();
        if problems.is_empty() {
            continue;
        }
        let text = describe(&problems);
        let group = groups
            .entry((ctx.server(handshake.flow), text))
            .or_insert_with(|| Group {
                severity: Severity::Info,
                hint: problems.iter().find_map(hint),
                flows: Vec::new(),
                frames: Vec::new(),
            });
        group.severity = group
            .severity
            .max(problems.iter().map(severity).max().expect("not empty"));
        group.flows.push(handshake.flow);
        group
            .frames
            .extend(problems.iter().filter_map(|p| evidence(handshake, p)));
        if let Some(reset) = conn.reset.filter(|_| handshake.server_hello.is_none()) {
            group.frames.push(reset.frame);
        }
    }

    groups
        .into_iter()
        .map(|((server, text), group)| {
            let n = group.flows.len();
            let text = if n > 1 {
                format!("{text} ({n} handshakes)")
            } else {
                text
            };
            Finding::new(group.severity, Category::Tls, server, text)
                .maybe_hint(group.hint)
                .frames(group.frames)
                .measure("handshakes", n as f64)
                .filter(ctx.streams(&group.flows))
                .flows(group.flows)
        })
        .collect()
}

struct Group {
    severity: Severity,
    hint: Option<&'static str>,
    flows: Vec<usize>,
    frames: Vec<u64>,
}

/// The problems in one sentence. A certificate problem the client rejected
/// comes first, with the rejection as its consequence.
fn describe(problems: &[TlsProblem]) -> String {
    let is_certificate = |p: &&TlsProblem| {
        matches!(
            p,
            TlsProblem::CertificateExpired { .. }
                | TlsProblem::CertificateNotYetValid { .. }
                | TlsProblem::NameMismatch { .. }
                | TlsProblem::SelfSigned
        )
    };
    let text = |list: Vec<&TlsProblem>| {
        list.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ")
    };
    let rejected = problems.iter().find_map(|p| match p {
        TlsProblem::Rejected {
            by: Side::Client,
            alert,
        } => Some(alert),
        _ => None,
    });
    let certificate: Vec<&TlsProblem> = problems.iter().filter(is_certificate).collect();
    let Some(alert) = rejected.filter(|_| !certificate.is_empty()) else {
        return text(problems.iter().collect());
    };
    let mut out = format!("{}: the client rejected it", text(certificate));
    if let Some(alert) = alert {
        out.push_str(&format!(" ({})", tls::alert_name(alert.description)));
    }
    let rest: Vec<&TlsProblem> = problems
        .iter()
        .filter(|p| !is_certificate(p) && !matches!(p, TlsProblem::Rejected { .. }))
        .collect();
    if !rest.is_empty() {
        out.push_str("; ");
        out.push_str(&text(rest));
    }
    out
}

/// A ClientHello still waiting for its answer when the capture ended, or
/// on a connection where the capture saw only the client.
fn cut_off_by_capture_end(ctx: &Context, handshake: &Handshake, problem: &TlsProblem) -> bool {
    let TlsProblem::NoServerHello(TcpStatus::Open) = problem else {
        return false;
    };
    if ctx.one_sided(handshake.flow) {
        return true;
    }
    handshake
        .client_hello
        .as_ref()
        .is_some_and(|(at, _)| ctx.end.secs_since(at.ts) < GIVE_UP_SECS)
}

fn severity(problem: &TlsProblem) -> Severity {
    match problem {
        TlsProblem::Rejected { .. }
        | TlsProblem::NoServerHello(_)
        | TlsProblem::CertificateExpired { .. }
        | TlsProblem::CertificateNotYetValid { .. }
        | TlsProblem::NameMismatch { .. } => Severity::Error,
        TlsProblem::SelfSigned
        | TlsProblem::OldVersion(_)
        | TlsProblem::SlowServerHello(_)
        | TlsProblem::Malformed(_) => Severity::Warning,
    }
}

fn hint(problem: &TlsProblem) -> Option<&'static str> {
    Some(match problem {
        TlsProblem::Rejected {
            by: Side::Client,
            alert: Some(alert),
        } if alert.description == UNKNOWN_CA => {
            "usually a private CA, or a TLS-inspecting proxy whose CA the client does not have"
        }
        TlsProblem::NoServerHello(TcpStatus::Reset(Side::Server)) => {
            "a firewall or proxy that filters by server name often does this"
        }
        TlsProblem::NameMismatch { .. } => {
            "the server sent the certificate for another site; check which certificate it serves for this name"
        }
        TlsProblem::SelfSigned => {
            "clients will not trust it unless it was installed on them by hand"
        }
        TlsProblem::OldVersion(_) => {
            "versions before TLS 1.2 are retired; clients and servers should move to TLS 1.2 or 1.3"
        }
        TlsProblem::SlowServerHello(_) => "the server is slow to start TLS, not the network",
        _ => return None,
    })
}

/// The frame that shows a problem.
fn evidence(handshake: &Handshake, problem: &TlsProblem) -> Option<u64> {
    match problem {
        TlsProblem::Rejected { .. } => Some(handshake.failure()?.arrival.frame),
        TlsProblem::NoServerHello(_) | TlsProblem::Malformed(_) => {
            Some(handshake.client_hello.as_ref()?.0.frame)
        }
        TlsProblem::CertificateExpired { .. }
        | TlsProblem::CertificateNotYetValid { .. }
        | TlsProblem::NameMismatch { .. }
        | TlsProblem::SelfSigned => Some(handshake.certificate.as_ref()?.arrival.frame),
        TlsProblem::OldVersion(_) | TlsProblem::SlowServerHello(_) => {
            Some(handshake.server_hello.as_ref()?.0.frame)
        }
    }
}
