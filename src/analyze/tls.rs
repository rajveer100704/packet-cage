//! TLS handshakes: which server and protocol the client asked for, what was
//! agreed, and how a handshake failed.
//!
//! TLS is recognized by content rather than port: a connection whose client
//! starts with a ClientHello record. Only the handshake is followed; after
//! it the traffic is encrypted.

use std::collections::HashMap;
use std::fmt;

use crate::analyze::stream::{Arrival, Reassembler};
use crate::capture::Frame;
use crate::decode::Tcp;
use crate::decode::tls::{self, Alert, ClientHello, ServerHello, TlsError};
use crate::decode::x509::{self, Certificate, X509Error};
use crate::flow::{Observed, Side, TcpConn, TcpStatus};
use crate::units;

/// A ServerHello slower than this, after taking out the network round trip,
/// means a busy or slow server.
pub const SLOW_SERVER_HELLO_SECS: f64 = 0.5;
/// A TLS 1.3 encrypted alert: 2 bytes of alert, 1 of content type and a
/// 16-byte authentication tag. Finished is always longer, so a record this
/// size before the handshake ends is taken for an alert. A heuristic: a
/// cipher with a different tag size would not match.
const ENCRYPTED_ALERT_LEN: usize = 19;
/// Unconsumed bytes allowed per direction: room for a record plus a long
/// certificate chain spread over several records.
const BUFFER_LIMIT: usize = 128 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub struct Handshake {
    /// Index of the connection in the flow table.
    pub flow: usize,
    pub client_hello: Option<(Arrival, ClientHello)>,
    pub server_hello: Option<(Arrival, ServerHello)>,
    /// The server first asked for a different key share (TLS 1.3).
    pub hello_retry: bool,
    /// The server's certificate chain. TLS 1.3 encrypts it, so this is only
    /// seen for earlier versions.
    pub certificate: Option<CertificateSeen>,
    /// Alerts either way. Encrypted ones show only that an alert happened.
    pub alerts: Vec<AlertSeen>,
    /// When the handshake completed: the second Finished before TLS 1.3, the
    /// client's Finished in 1.3.
    pub finished: Option<Arrival>,
    /// A handshake message that could not be read.
    pub error: Option<TlsError>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CertificateSeen {
    pub arrival: Arrival,
    /// Certificates in the chain, the server's own first.
    pub chain_len: usize,
    pub leaf: Result<Certificate, X509Error>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlertSeen {
    pub from: Side,
    pub arrival: Arrival,
    /// `None` when the alert was encrypted.
    pub alert: Option<Alert>,
    /// Sent before the handshake finished. Decided as records are read, in
    /// order, so an alert right after Finished in the same packet counts as
    /// after.
    pub during_handshake: bool,
}

impl AlertSeen {
    /// Fatal, or encrypted (which can't be told apart from fatal).
    fn may_be_fatal(&self) -> bool {
        self.alert.is_none_or(|a| a.is_fatal())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TlsProblem {
    /// A side ended the handshake with an alert (`None`: encrypted).
    Rejected {
        by: Side,
        alert: Option<Alert>,
    },
    /// No ServerHello came back; the connection ended up like this.
    NoServerHello(TcpStatus),
    CertificateExpired {
        not_after: i64,
    },
    CertificateNotYetValid {
        not_before: i64,
    },
    NameMismatch {
        host: String,
        names: String,
    },
    SelfSigned,
    OldVersion(u16),
    /// Seconds the server took to answer the ClientHello, beyond the round trip.
    SlowServerHello(f64),
    Malformed(TlsError),
}

impl fmt::Display for TlsProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let side = |s: &Side| match s {
            Side::Client => "client",
            Side::Server => "server",
        };
        match self {
            TlsProblem::Rejected {
                by,
                alert: Some(alert),
            } => {
                write!(
                    f,
                    "{} rejected the handshake: {}",
                    side(by),
                    tls::alert_name(alert.description)
                )?;
                if let Some(meaning) = tls::alert_meaning(alert.description) {
                    write!(f, " ({meaning})")?;
                }
                Ok(())
            }
            TlsProblem::Rejected { by, alert: None } => {
                write!(
                    f,
                    "{} ended the handshake with an encrypted alert",
                    side(by)
                )
            }
            TlsProblem::NoServerHello(status) => f.write_str(match status {
                TcpStatus::Reset(Side::Server) => {
                    "server reset the connection instead of answering the ClientHello"
                }
                TcpStatus::Reset(Side::Client) => {
                    "client reset the connection before the server answered"
                }
                TcpStatus::Closed | TcpStatus::HalfClosed => {
                    "connection closed without an answer to the ClientHello"
                }
                _ => "no answer to the ClientHello",
            }),
            TlsProblem::CertificateExpired { not_after } => {
                write!(f, "certificate expired on {}", units::date(*not_after))
            }
            TlsProblem::CertificateNotYetValid { not_before } => {
                write!(
                    f,
                    "certificate is not valid until {}",
                    units::date(*not_before)
                )
            }
            TlsProblem::NameMismatch { host, names } => {
                write!(f, "certificate is for {names}, not {host}")
            }
            TlsProblem::SelfSigned => f.write_str("certificate is self-signed"),
            TlsProblem::OldVersion(v) => {
                write!(f, "uses {}, which is outdated", tls::version_name(*v))
            }
            TlsProblem::SlowServerHello(secs) => {
                write!(
                    f,
                    "server took {} to answer the ClientHello",
                    units::duration(*secs)
                )
            }
            TlsProblem::Malformed(e) => write!(f, "{e}"),
        }
    }
}

/// How a handshake ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlsResult {
    Completed,
    /// A side ended it with an alert.
    Rejected,
    /// The ClientHello was never answered.
    NoServerHello,
    /// Started, but the capture doesn't show how it ended.
    Incomplete,
}

impl fmt::Display for TlsResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TlsResult::Completed => "completed",
            TlsResult::Rejected => "rejected with an alert",
            TlsResult::NoServerHello => "no ServerHello",
            TlsResult::Incomplete => "not finished in the capture",
        })
    }
}

impl Handshake {
    fn new(flow: usize) -> Self {
        Handshake {
            flow,
            client_hello: None,
            server_hello: None,
            hello_retry: false,
            certificate: None,
            alerts: Vec::new(),
            finished: None,
            error: None,
        }
    }

    pub fn result(&self) -> TlsResult {
        if self.failure().is_some() {
            TlsResult::Rejected
        } else if self.finished.is_some() {
            TlsResult::Completed
        } else if self.client_hello.is_some() && self.server_hello.is_none() {
            TlsResult::NoServerHello
        } else {
            TlsResult::Incomplete
        }
    }

    /// The hostname the client asked for (SNI).
    pub fn server_name(&self) -> Option<&str> {
        self.client_hello.as_ref()?.1.server_name.as_deref()
    }

    /// The agreed version, once the server has answered.
    pub fn version(&self) -> Option<u16> {
        Some(self.server_hello.as_ref()?.1.version())
    }

    /// The fatal (or encrypted) alert that ended the handshake, if any.
    pub fn failure(&self) -> Option<&AlertSeen> {
        self.alerts
            .iter()
            .find(|a| a.during_handshake && a.may_be_fatal())
    }

    /// Seconds from the ClientHello to the ServerHello.
    pub fn server_hello_delay(&self) -> Option<f64> {
        let (client, _) = self.client_hello.as_ref()?;
        let (server, _) = self.server_hello.as_ref()?;
        Some(server.ts.secs_since(client.ts))
    }

    /// Everything wrong with this handshake. `conn` is its TCP connection,
    /// for the round trip and for what happened when no ServerHello came.
    pub fn problems(&self, conn: &TcpConn) -> Vec<TlsProblem> {
        let mut problems = Vec::new();
        if let Some(alert) = self.failure() {
            problems.push(TlsProblem::Rejected {
                by: alert.from,
                alert: alert.alert,
            });
        } else if self.client_hello.is_some() && self.server_hello.is_none() {
            problems.push(TlsProblem::NoServerHello(conn.status()));
        }
        if let Some(e) = &self.error {
            problems.push(TlsProblem::Malformed(e.clone()));
        }
        if let (Some(cert), Some((hello, _))) = (&self.certificate, &self.client_hello)
            && let Ok(leaf) = &cert.leaf
        {
            let at = (hello.ts.0 / 1_000_000_000) as i64;
            if at > leaf.not_after {
                problems.push(TlsProblem::CertificateExpired {
                    not_after: leaf.not_after,
                });
            } else if at < leaf.not_before {
                problems.push(TlsProblem::CertificateNotYetValid {
                    not_before: leaf.not_before,
                });
            }
            if let Some(host) = self.server_name()
                && !leaf.matches_host(host)
            {
                problems.push(TlsProblem::NameMismatch {
                    host: host.to_string(),
                    names: leaf.names(),
                });
            }
            if leaf.self_issued && cert.chain_len == 1 {
                problems.push(TlsProblem::SelfSigned);
            }
        }
        if let Some(version) = self.version()
            && version < 0x0303
        {
            problems.push(TlsProblem::OldVersion(version));
        }
        if let Some(delay) = self.server_hello_delay() {
            // Take out the network time between the capture point and the server.
            let network = conn
                .handshake_rtt()
                .and_then(|r| r.server_side)
                .unwrap_or(0.0);
            let server = delay - network;
            if server > SLOW_SERVER_HELLO_SECS {
                problems.push(TlsProblem::SlowServerHello(server));
            }
        }
        problems
    }
}

/// Something worth a mention in `dump`.
#[derive(Debug, Clone, PartialEq)]
pub enum TlsEvent {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    Certificate {
        chain_len: usize,
        leaf: Result<Certificate, X509Error>,
    },
    Alert(Option<Alert>),
}

impl fmt::Display for TlsEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsEvent::ClientHello(hello) => {
                f.write_str("ClientHello")?;
                if let Some(name) = &hello.server_name {
                    write!(f, " {name}")?;
                }
                write!(f, " (up to {}", tls::version_name(hello.max_version()))?;
                if !hello.alpn.is_empty() {
                    write!(f, ", {}", hello.alpn.join(", "))?;
                }
                f.write_str(")")
            }
            TlsEvent::ServerHello(hello) if hello.hello_retry_request => {
                f.write_str("HelloRetryRequest")
            }
            TlsEvent::ServerHello(hello) => {
                write!(f, "ServerHello {}", tls::version_name(hello.version()))?;
                if let Some(alpn) = &hello.alpn {
                    write!(f, ", {alpn}")?;
                }
                Ok(())
            }
            TlsEvent::Certificate {
                chain_len,
                leaf: Ok(cert),
            } => write!(
                f,
                "Certificate {} until {} ({chain_len} in chain)",
                cert.subject,
                units::date(cert.not_after)
            ),
            TlsEvent::Certificate { leaf: Err(e), .. } => write!(f, "Certificate [{e}]"),
            TlsEvent::Alert(Some(alert)) => write!(
                f,
                "Alert ({}) {}",
                if alert.is_fatal() { "fatal" } else { "warning" },
                tls::alert_name(alert.description)
            ),
            TlsEvent::Alert(None) => f.write_str("Alert (encrypted)"),
        }
    }
}

/// A TLS record, in the frame that completed it, which is where Wireshark
/// shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsRecord {
    pub content_type: u8,
    /// In TLS 1.3 the outer type of an encrypted record is a placeholder,
    /// which Wireshark calls the opaque type.
    pub opaque: bool,
    pub version: u16,
    pub length: u16,
    /// Handshake messages that ended in this record. Empty once the
    /// handshake is encrypted.
    pub handshake_types: Vec<u8>,
}

/// What one TCP segment completed.
#[derive(Debug, Default)]
pub struct TlsSeen {
    pub events: Vec<TlsEvent>,
    pub records: Vec<TlsRecord>,
}

/// Where we are in one direction of a connection.
#[derive(Debug, Default)]
struct Direction {
    bytes: Reassembler,
    /// Handshake messages can span records, so they are collected here.
    handshake: Vec<u8>,
    /// From here on this side's records are encrypted.
    encrypted: bool,
    /// This side's Finished (or, in TLS 1.3, the client's first encrypted record).
    finished: Option<Arrival>,
}

#[derive(Debug)]
enum Connection {
    /// Waiting for the first data to decide.
    Undecided([Direction; 2]),
    Tls(usize, [Direction; 2]),
    NotTls,
}

#[derive(Debug, Default)]
pub struct TlsLog {
    handshakes: Vec<Handshake>,
    connections: HashMap<usize, Connection>,
}

impl TlsLog {
    pub fn handshakes(&self) -> &[Handshake] {
        &self.handshakes
    }

    /// The handshake on a connection, if it carried TLS.
    pub fn for_flow(&self, flow: usize) -> Option<&Handshake> {
        match self.connections.get(&flow) {
            Some(Connection::Tls(index, _)) => Some(&self.handshakes[*index]),
            _ => None,
        }
    }

    pub fn observe(
        &mut self,
        frame: &Frame,
        tcp: &Tcp,
        payload: &[u8],
        flow: &Observed,
    ) -> TlsSeen {
        let index = flow.flow.index;
        let side = flow.flow.from;
        let at = Arrival {
            frame: frame.number,
            ts: frame.ts,
        };
        let connection = self
            .connections
            .entry(index)
            .or_insert_with(|| Connection::Undecided(Default::default()));
        if matches!(connection, Connection::NotTls) {
            return TlsSeen::default();
        }
        let dirs = match connection {
            Connection::Undecided(dirs) | Connection::Tls(_, dirs) => dirs,
            Connection::NotTls => unreachable!(),
        };
        let own = side_index(side);
        if dirs[own].bytes.push(tcp, payload, at, BUFFER_LIMIT) == 0 {
            return TlsSeen::default();
        }
        if let Connection::Undecided(dirs) = connection {
            // TLS starts with the client's ClientHello, or with a server alert
            // refusing to talk. Deciding takes the 5-byte record header and
            // the handshake type, which may come a byte at a time.
            let data = dirs[own].bytes.data();
            if data.len() < 6 && dirs[own].bytes.is_following() {
                return TlsSeen::default();
            }
            let tls = match (side, tls::record_header(data)) {
                (Side::Client, Some(h)) => {
                    h.content_type == tls::HANDSHAKE && data.get(5) == Some(&tls::CLIENT_HELLO)
                }
                (Side::Server, Some(h)) => h.content_type == tls::ALERT,
                (_, None) => false,
            };
            if !tls {
                *connection = Connection::NotTls;
                return TlsSeen::default();
            }
            let dirs = std::mem::take(dirs);
            self.handshakes.push(Handshake::new(index));
            *connection = Connection::Tls(self.handshakes.len() - 1, dirs);
        }
        let Connection::Tls(handshake, dirs) = connection else {
            return TlsSeen::default();
        };
        let handshake = &mut self.handshakes[*handshake];
        read_records(handshake, dirs, side)
    }
}

/// Reads every complete record that `side` has sent so far.
fn read_records(handshake: &mut Handshake, dirs: &mut [Direction; 2], side: Side) -> TlsSeen {
    let mut seen = TlsSeen::default();
    let own = side_index(side);
    loop {
        let dir = &mut dirs[own];
        let data = dir.bytes.data();
        let Some(header) = tls::record_header(data) else {
            if data.len() >= 5 {
                // Not a record where one should start: lost track.
                dir.bytes.stop();
            }
            break;
        };
        let Some(body) = data.get(5..5 + header.len) else {
            break; // wait for the rest of the record
        };
        let body = body.to_vec();
        let end = dir.bytes.offset() + 5 + header.len as u64;
        let at = dir
            .bytes
            .arrival(end - 1)
            .expect("the record's last byte is buffered");
        dir.bytes.consume(5 + header.len);
        let mut handshake_types = Vec::new();
        record(
            handshake,
            dirs,
            side,
            header.content_type,
            &body,
            at,
            &mut seen.events,
            &mut handshake_types,
        );
        // Application data before the ServerHello, on a connection that
        // offers TLS 1.3, is 0-RTT early data: encrypted the same way.
        let early_data = side == Side::Client
            && handshake.server_hello.is_none()
            && handshake
                .client_hello
                .as_ref()
                .is_some_and(|(_, hello)| tls::is_tls13(hello.max_version()));
        let tls13 = early_data || handshake.version().is_some_and(tls::is_tls13);
        seen.records.push(TlsRecord {
            content_type: header.content_type,
            opaque: tls13 && header.content_type == tls::APPLICATION_DATA,
            version: header.version,
            length: header.len as u16,
            handshake_types,
        });
        if handshake.error.is_some() {
            dirs[own].bytes.stop();
            break;
        }
    }
    seen
}

#[allow(clippy::too_many_arguments)]
fn record(
    handshake: &mut Handshake,
    dirs: &mut [Direction; 2],
    side: Side,
    content_type: u8,
    body: &[u8],
    at: Arrival,
    events: &mut Vec<TlsEvent>,
    handshake_types: &mut Vec<u8>,
) {
    let own = side_index(side);
    let tls13 = handshake.version().is_some_and(tls::is_tls13);
    match content_type {
        // Before TLS 1.3, ChangeCipherSpec switches that side to encryption.
        // TLS 1.3 sends dummy ones for middlebox compatibility, even before
        // the ServerHello (after a HelloRetryRequest), so ignore those.
        tls::CHANGE_CIPHER_SPEC if handshake.server_hello.is_some() && !tls13 => {
            dirs[own].encrypted = true;
        }
        tls::ALERT => {
            let alert = if dirs[own].encrypted {
                None
            } else {
                tls::parse_alert(body)
            };
            handshake.alerts.push(AlertSeen {
                from: side,
                arrival: at,
                alert,
                during_handshake: handshake.finished.is_none(),
            });
            events.push(TlsEvent::Alert(alert));
        }
        tls::HANDSHAKE if dirs[own].encrypted => {
            // The first encrypted handshake message is Finished.
            dirs[own].finished.get_or_insert(at);
            note_finished(handshake, dirs, tls13);
        }
        tls::HANDSHAKE => {
            dirs[own].handshake.extend_from_slice(body);
            while let Some((kind, msg, len)) = tls::handshake_message(&dirs[own].handshake) {
                let msg = msg.to_vec();
                dirs[own].handshake.drain(..len);
                handshake_types.push(kind);
                handshake_message(handshake, dirs, side, kind, &msg, at, events);
                if handshake.error.is_some() {
                    return;
                }
            }
            let pending = tls::handshake_message_len(&dirs[own].handshake);
            if pending.is_some_and(|len| len > BUFFER_LIMIT) {
                handshake.error = Some(TlsError("handshake message too long".into()));
            }
        }
        tls::APPLICATION_DATA if tls13 && side == Side::Client && dirs[own].finished.is_none() => {
            if body.len() == ENCRYPTED_ALERT_LEN {
                // Too short for Finished: an alert, e.g. rejecting the
                // (encrypted, so unseen) certificate.
                handshake.alerts.push(AlertSeen {
                    from: side,
                    arrival: at,
                    alert: None,
                    during_handshake: true,
                });
                events.push(TlsEvent::Alert(None));
            } else {
                // TLS 1.3: the client's first encrypted record after the
                // ServerHello carries its Finished.
                dirs[own].finished = Some(at);
                note_finished(handshake, dirs, tls13);
            }
        }
        _ => {}
    }
}

fn handshake_message(
    handshake: &mut Handshake,
    dirs: &mut [Direction; 2],
    side: Side,
    kind: u8,
    body: &[u8],
    at: Arrival,
    events: &mut Vec<TlsEvent>,
) {
    match (side, kind) {
        (Side::Client, tls::CLIENT_HELLO) => match tls::parse_client_hello(body) {
            // After a HelloRetryRequest the client sends a second ClientHello;
            // keep the first for timing but the name is the same.
            Ok(hello) => {
                handshake.client_hello.get_or_insert((at, hello.clone()));
                events.push(TlsEvent::ClientHello(hello));
            }
            Err(e) => handshake.error = Some(e),
        },
        (Side::Server, tls::SERVER_HELLO) => match tls::parse_server_hello(body) {
            Ok(hello) => {
                if hello.hello_retry_request {
                    handshake.hello_retry = true;
                } else {
                    if tls::is_tls13(hello.version()) {
                        // Everything after the ServerHello is encrypted.
                        dirs[0].encrypted = true;
                        dirs[1].encrypted = true;
                    }
                    handshake.server_hello = Some((at, hello.clone()));
                }
                events.push(TlsEvent::ServerHello(hello));
            }
            Err(e) => handshake.error = Some(e),
        },
        (Side::Server, tls::CERTIFICATE) => match tls::parse_certificate_list(body) {
            Ok(chain) => {
                let leaf = chain.first().map_or_else(
                    || Err(X509Error("empty certificate list".into())),
                    |der| x509::parse(der),
                );
                handshake.certificate = Some(CertificateSeen {
                    arrival: at,
                    chain_len: chain.len(),
                    leaf: leaf.clone(),
                });
                events.push(TlsEvent::Certificate {
                    chain_len: chain.len(),
                    leaf,
                });
            }
            Err(e) => handshake.error = Some(e),
        },
        _ => {}
    }
}

/// The handshake is complete when both Finished messages have been sent
/// (TLS 1.2), or the client's has (TLS 1.3, where the server's is hidden).
fn note_finished(handshake: &mut Handshake, dirs: &[Direction; 2], tls13: bool) {
    if handshake.finished.is_some() {
        return;
    }
    let [client, server] = dirs;
    handshake.finished = match (tls13, client.finished, server.finished) {
        (true, Some(c), _) => Some(c),
        (false, Some(c), Some(s)) => Some(if c.frame >= s.frame { c } else { s }),
        _ => None,
    };
}

fn side_index(side: Side) -> usize {
    match side {
        Side::Client => 0,
        Side::Server => 1,
    }
}
