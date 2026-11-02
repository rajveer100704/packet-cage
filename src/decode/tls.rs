//! TLS records and handshake messages (RFC 5246 for TLS 1.2, RFC 8446 for
//! 1.3), as far as they can be read without decrypting: hellos, certificates
//! (before TLS 1.3, which encrypts them) and alerts.

use std::fmt;

pub const CHANGE_CIPHER_SPEC: u8 = 20;
pub const ALERT: u8 = 21;
pub const HANDSHAKE: u8 = 22;
pub const APPLICATION_DATA: u8 = 23;
const HEARTBEAT: u8 = 24;

pub const CLIENT_HELLO: u8 = 1;
pub const SERVER_HELLO: u8 = 2;
pub const CERTIFICATE: u8 = 11;

pub const TLS_1_3: u16 = 0x0304;

/// TLS 1.3, or one of the drafts (0x7fxx) used before it was final.
pub fn is_tls13(version: u16) -> bool {
    version == TLS_1_3 || (0x7f00..=0x7fff).contains(&version)
}

/// Largest record payload allowed: 2^14 plus room for compression and
/// encryption overhead (RFC 5246 section 6.2.3).
pub const MAX_RECORD_LEN: usize = 16_384 + 2048;

/// The random value that marks a ServerHello as a HelloRetryRequest
/// (RFC 8446 section 4.1.3).
const HELLO_RETRY_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsError(pub String);

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed TLS: {}", self.0)
    }
}

impl std::error::Error for TlsError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    pub content_type: u8,
    pub version: u16,
    pub len: usize,
}

/// Reads a record header if `data` starts with something that looks like
/// one: a known content type, version 3.x and a plausible length.
pub fn record_header(data: &[u8]) -> Option<RecordHeader> {
    let [content_type, major, minor, hi, lo, ..] = *data else {
        return None;
    };
    let len = usize::from(u16::from_be_bytes([hi, lo]));
    let known = (CHANGE_CIPHER_SPEC..=HEARTBEAT).contains(&content_type);
    if !known || major != 3 || minor > 4 || len > MAX_RECORD_LEN {
        return None;
    }
    Some(RecordHeader {
        content_type,
        version: u16::from_be_bytes([major, minor]),
        len,
    })
}

/// Splits the first complete handshake message off `data`: its type, its
/// body and how many bytes it took. `None` until all of it has arrived.
pub fn handshake_message(data: &[u8]) -> Option<(u8, &[u8], usize)> {
    let [kind, a, b, c, ..] = *data else {
        return None;
    };
    let len = (usize::from(a) << 16) | (usize::from(b) << 8) | usize::from(c);
    let body = data.get(4..4 + len)?;
    Some((kind, body, 4 + len))
}

/// Length of the handshake message at the start of `data`, from its header.
pub fn handshake_message_len(data: &[u8]) -> Option<usize> {
    let [_, a, b, c, ..] = *data else {
        return None;
    };
    Some(4 + ((usize::from(a) << 16) | (usize::from(b) << 8) | usize::from(c)))
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientHello {
    pub legacy_version: u16,
    /// Server name indication: the hostname the client wants to reach.
    pub server_name: Option<String>,
    /// Application protocols offered (ALPN), e.g. "h2", "http/1.1".
    pub alpn: Vec<String>,
    /// From the supported_versions extension, sent by TLS 1.3 clients,
    /// including any GREASE values.
    pub supported_versions: Vec<u16>,
    pub cipher_suites: Vec<u16>,
}

impl ClientHello {
    /// The highest version offered.
    pub fn max_version(&self) -> u16 {
        self.supported_versions
            .iter()
            .copied()
            .filter(|v| !is_grease(*v))
            .max()
            .unwrap_or(self.legacy_version)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServerHello {
    pub legacy_version: u16,
    pub cipher_suite: u16,
    /// From the supported_versions extension: how TLS 1.3 announces itself.
    pub selected_version: Option<u16>,
    /// The ALPN choice. TLS 1.3 sends it encrypted, so it's only visible
    /// for earlier versions.
    pub alpn: Option<String>,
    /// A TLS 1.3 HelloRetryRequest: the server wants a different key share
    /// and the client must send a new ClientHello.
    pub hello_retry_request: bool,
}

impl ServerHello {
    pub fn version(&self) -> u16 {
        self.selected_version.unwrap_or(self.legacy_version)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Alert {
    /// 1 warning, 2 fatal.
    pub level: u8,
    pub description: u8,
}

impl Alert {
    pub fn is_fatal(&self) -> bool {
        self.level == 2
    }
}

pub fn parse_alert(body: &[u8]) -> Option<Alert> {
    match *body {
        [level, description] => Some(Alert { level, description }),
        _ => None,
    }
}

pub fn parse_client_hello(body: &[u8]) -> Result<ClientHello, TlsError> {
    let mut r = Reader::new(body, "ClientHello");
    let legacy_version = r.u16()?;
    r.take(32)?; // random
    r.vec8()?; // session ID
    let (suites, _) = r.vec16()?.as_chunks::<2>();
    r.vec8()?; // compression methods
    let mut hello = ClientHello {
        legacy_version,
        cipher_suites: suites.iter().map(|s| u16::from_be_bytes(*s)).collect(),
        ..ClientHello::default()
    };
    if r.is_empty() {
        return Ok(hello); // no extensions: an old client
    }
    let mut extensions = Reader::new(r.vec16()?, "ClientHello extensions");
    while !extensions.is_empty() {
        let kind = extensions.u16()?;
        let data = extensions.vec16()?;
        match kind {
            0 => hello.server_name = parse_server_name(data)?,
            16 => hello.alpn = parse_alpn(data)?,
            43 => {
                let (versions, _) = Reader::new(data, "supported versions")
                    .vec8()?
                    .as_chunks::<2>();
                hello.supported_versions =
                    versions.iter().map(|v| u16::from_be_bytes(*v)).collect();
            }
            _ => {}
        }
    }
    Ok(hello)
}

pub fn parse_server_hello(body: &[u8]) -> Result<ServerHello, TlsError> {
    let mut r = Reader::new(body, "ServerHello");
    let legacy_version = r.u16()?;
    let random = r.take(32)?;
    // TLS 1.3 drafts before 22 dropped the session ID and compression
    // fields; draft 22 put them back so middleboxes would let 1.3 through.
    let early_draft = (0x7f00..0x7f16).contains(&legacy_version);
    if !early_draft {
        r.vec8()?; // session ID
    }
    let mut hello = ServerHello {
        legacy_version,
        cipher_suite: r.u16()?,
        hello_retry_request: random == HELLO_RETRY_RANDOM,
        ..ServerHello::default()
    };
    if !early_draft {
        r.u8()?; // compression method
    }
    if r.is_empty() {
        return Ok(hello);
    }
    let mut extensions = Reader::new(r.vec16()?, "ServerHello extensions");
    while !extensions.is_empty() {
        let kind = extensions.u16()?;
        let data = extensions.vec16()?;
        match kind {
            16 => hello.alpn = parse_alpn(data)?.into_iter().next(),
            43 => hello.selected_version = Some(Reader::new(data, "selected version").u16()?),
            _ => {}
        }
    }
    Ok(hello)
}

/// The DER certificates in a TLS 1.2 (or earlier) Certificate message,
/// server certificate first.
pub fn parse_certificate_list(body: &[u8]) -> Result<Vec<&[u8]>, TlsError> {
    let mut list = Reader::new(
        Reader::new(body, "Certificate").vec24()?,
        "certificate list",
    );
    let mut certificates = Vec::new();
    while !list.is_empty() {
        certificates.push(list.vec24()?);
    }
    Ok(certificates)
}

fn parse_server_name(data: &[u8]) -> Result<Option<String>, TlsError> {
    let mut list = Reader::new(
        Reader::new(data, "server name").vec16()?,
        "server name list",
    );
    while !list.is_empty() {
        let kind = list.u8()?;
        let name = list.vec16()?;
        if kind == 0 {
            return Ok(Some(printable(name)));
        }
    }
    Ok(None)
}

fn parse_alpn(data: &[u8]) -> Result<Vec<String>, TlsError> {
    let mut list = Reader::new(Reader::new(data, "ALPN").vec16()?, "ALPN list");
    let mut protocols = Vec::new();
    while !list.is_empty() {
        protocols.push(printable(list.vec8()?));
    }
    Ok(protocols)
}

/// GREASE values (RFC 8701) are random-looking placeholders that clients
/// send so servers learn to ignore unknown values: 0x0a0a, 0x1a1a, ...
fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff
}

/// Text from the wire, with anything unprintable escaped.
pub fn printable(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

pub fn version_name(version: u16) -> String {
    match version {
        0x0300 => "SSL 3.0".to_string(),
        0x0301 => "TLS 1.0".to_string(),
        0x0302 => "TLS 1.1".to_string(),
        0x0303 => "TLS 1.2".to_string(),
        0x0304 => "TLS 1.3".to_string(),
        0x7f00..=0x7fff => format!("TLS 1.3 draft {}", version & 0xff),
        v => format!("version {v:#06x}"),
    }
}

pub fn alert_name(description: u8) -> String {
    let name = match description {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        21 => "decryption_failed",
        22 => "record_overflow",
        30 => "decompression_failure",
        40 => "handshake_failure",
        41 => "no_certificate",
        42 => "bad_certificate",
        43 => "unsupported_certificate",
        44 => "certificate_revoked",
        45 => "certificate_expired",
        46 => "certificate_unknown",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        49 => "access_denied",
        50 => "decode_error",
        51 => "decrypt_error",
        60 => "export_restriction",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        86 => "inappropriate_fallback",
        90 => "user_canceled",
        100 => "no_renegotiation",
        109 => "missing_extension",
        110 => "unsupported_extension",
        112 => "unrecognized_name",
        113 => "bad_certificate_status_response",
        115 => "unknown_psk_identity",
        116 => "certificate_required",
        120 => "no_application_protocol",
        d => return format!("alert {d}"),
    };
    name.to_string()
}

/// What an alert usually means, in plain words.
pub fn alert_meaning(description: u8) -> Option<&'static str> {
    Some(match description {
        40 => "the two sides found no TLS settings they both accept",
        42 | 46 => "the certificate was rejected",
        43 => "the certificate is of a kind the peer does not support",
        44 => "the certificate has been revoked",
        45 => "a certificate has expired or is not valid yet",
        48 => "the certificate's issuer is not trusted",
        49 => "access was denied",
        70 => "no TLS version is supported by both sides",
        71 => "the server requires stronger security than the client offered",
        80 => "the peer hit an internal error",
        86 => "a downgrade to an older TLS version was refused",
        112 => "the server has no certificate for the requested name",
        116 => "the server requires a client certificate",
        120 => "no application protocol (ALPN) is supported by both sides",
        _ => return None,
    })
}

/// Reads length-prefixed TLS structures, failing cleanly at the end of input.
struct Reader<'a> {
    data: &'a [u8],
    what: &'static str,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8], what: &'static str) -> Self {
        Reader { data, what }
    }

    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], TlsError> {
        if self.data.len() < n {
            return Err(TlsError(format!("{} ends early", self.what)));
        }
        let (head, rest) = self.data.split_at(n);
        self.data = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, TlsError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, TlsError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn vec8(&mut self) -> Result<&'a [u8], TlsError> {
        let len = usize::from(self.u8()?);
        self.take(len)
    }

    fn vec16(&mut self) -> Result<&'a [u8], TlsError> {
        let len = usize::from(self.u16()?);
        self.take(len)
    }

    fn vec24(&mut self) -> Result<&'a [u8], TlsError> {
        let b = self.take(3)?;
        let len = (usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2]);
        self.take(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_len16(data: &[u8]) -> Vec<u8> {
        let mut out = (data.len() as u16).to_be_bytes().to_vec();
        out.extend(data);
        out
    }

    fn extension(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut out = kind.to_be_bytes().to_vec();
        out.extend(with_len16(data));
        out
    }

    /// A ClientHello with SNI, ALPN and supported_versions (with GREASE).
    fn client_hello() -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend([7; 32]);
        body.push(0); // no session ID
        body.extend(with_len16(&[0x13, 0x01, 0xc0, 0x2f]));
        body.extend([1, 0]); // null compression
        let mut sni = vec![0];
        sni.extend(with_len16(b"api.example.com"));
        let alpn = [
            2, b'h', b'2', 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
        ];
        let mut extensions = extension(0, &with_len16(&sni));
        extensions.extend(extension(16, &with_len16(&alpn)));
        extensions.extend(extension(43, &[6, 0x5a, 0x5a, 3, 4, 3, 3]));
        body.extend(with_len16(&extensions));
        body
    }

    #[test]
    fn client_hello_fields() {
        let hello = parse_client_hello(&client_hello()).unwrap();
        assert_eq!(hello.server_name.as_deref(), Some("api.example.com"));
        assert_eq!(hello.alpn, vec!["h2", "http/1.1"]);
        assert_eq!(hello.supported_versions, vec![0x5a5a, 0x0304, 0x0303]);
        assert_eq!(hello.max_version(), TLS_1_3);
        assert_eq!(hello.cipher_suites, vec![0x1301, 0xc02f]);
    }

    #[test]
    fn cut_hellos_fail_cleanly() {
        let full = client_hello();
        // Version, random, empty session ID, two cipher suites, compression.
        let without_extensions = 2 + 32 + 1 + 6 + 2;
        for len in 0..full.len() {
            let parsed = parse_client_hello(&full[..len]);
            // Old clients send no extensions at all, so that prefix is valid.
            assert_eq!(parsed.is_ok(), len == without_extensions, "length {len}");
        }
    }

    #[test]
    fn server_hello_version_and_retry() {
        let mut body = vec![3, 3];
        body.extend(HELLO_RETRY_RANDOM);
        body.push(0);
        body.extend([0x13, 0x01, 0]);
        body.extend(with_len16(&extension(43, &[3, 4])));
        let hello = parse_server_hello(&body).unwrap();
        assert_eq!(hello.version(), TLS_1_3);
        assert!(hello.hello_retry_request);
    }

    #[test]
    fn records_and_handshake_framing() {
        let header = record_header(&[22, 3, 1, 0, 5, 1, 0, 0, 1, 9]).unwrap();
        assert_eq!(
            (header.content_type, header.version, header.len),
            (22, 0x0301, 5)
        );
        assert_eq!(record_header(b"GET / HTTP/1.1"), None);
        assert_eq!(record_header(&[23, 3, 3, 0xff, 0xff]), None);
        assert_eq!(
            handshake_message(&[1, 0, 0, 1, 9, 9]),
            Some((1, &[9][..], 5))
        );
        assert_eq!(handshake_message(&[1, 0, 0, 2, 9]), None);
    }

    #[test]
    fn grease_and_names() {
        assert!(is_grease(0x0a0a) && is_grease(0xfafa) && !is_grease(0x0303));
        assert_eq!(version_name(0x7f14), "TLS 1.3 draft 20");
        assert!(is_tls13(0x0304) && is_tls13(0x7f17) && !is_tls13(0x0303));
        assert_eq!(alert_name(48), "unknown_ca");
        assert_eq!(printable(b"a\nb"), "a\\nb");
    }
}
