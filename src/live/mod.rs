//! Live capture through libpcap, or Npcap on Windows. The library is loaded
//! when a capture starts (see `ffi`), so reading files never needs it.

mod ffi;

use std::ffi::{CStr, CString, c_char, c_int};
use std::fmt;
use std::net::{IpAddr, UdpSocket};
use std::ptr;
use std::time::Duration;

use crate::capture::{Frame, Timestamp};
use crate::decode::link_type as linktype;
use ffi::{BpfProgram, ERRBUF_SIZE, Pcap, PcapStat, PcapT, PktHdr};

/// How long the system may hold packets back to hand them over in batches.
const READ_TIMEOUT_MS: c_int = 100;
/// Reads don't block, because a blocking read can wait forever for the
/// first packet (Linux's TPACKET_V3 ignores the timeout then). With nothing
/// to read, we sleep this long before asking again.
const IDLE: Duration = Duration::from_millis(20);
/// Kernel buffer for packets not yet read. libpcap's default (2 MB on
/// Linux, 1 MB with Npcap) overflows on a busy link while we analyze.
const BUFFER_BYTES: c_int = 16 * 1024 * 1024;

#[derive(Debug)]
pub enum LiveError {
    /// libpcap or Npcap isn't installed; says which files were tried.
    NoLibrary(String),
    /// Capturing needs more rights than this process has.
    PermissionDenied(String),
    NoSuchInterface(String),
    BadFilter(String),
    Other(String),
}

impl fmt::Display for LiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LiveError::NoLibrary(tried) => write!(f, "{}", no_library_help(tried)),
            LiveError::PermissionDenied(detail) => {
                write!(f, "{detail}\n{}", permission_help())
            }
            LiveError::NoSuchInterface(detail) => {
                write!(f, "{detail}; packet-cage interfaces lists them")
            }
            LiveError::BadFilter(detail) => write!(f, "bad capture filter: {detail}"),
            LiveError::Other(detail) => write!(f, "{detail}"),
        }
    }
}

impl std::error::Error for LiveError {}

#[cfg(windows)]
fn no_library_help(tried: &str) -> String {
    format!(
        "live capture needs Npcap, from https://npcap.com ({tried}).\n\
         Without it, Windows can capture by itself, as administrator:\n  \
         pktmon start --capture --comp nics --pkt-size 0 --file-name capture.etl\n  \
         pktmon stop\n  \
         pktmon etl2pcap capture.etl --out capture.pcapng\n  \
         packet-cage capture.pcapng"
    )
}

#[cfg(unix)]
fn no_library_help(tried: &str) -> String {
    format!(
        "live capture needs libpcap ({tried}); on Debian or Ubuntu: sudo apt install \
         libpcap0.8, on Fedora: sudo dnf install libpcap"
    )
}

#[cfg(windows)]
fn permission_help() -> String {
    "Npcap was installed for administrators only; run packet-cage as administrator".to_string()
}

#[cfg(target_vendor = "apple")]
fn permission_help() -> String {
    "capturing needs root: run it with sudo".to_string()
}

#[cfg(all(unix, not(target_vendor = "apple")))]
fn permission_help() -> String {
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "packet-cage".to_string());
    format!(
        "capturing needs root: run it with sudo, or let it capture without root:\n  \
         sudo setcap cap_net_raw,cap_net_admin=eip {exe}"
    )
}

/// The version libpcap or Npcap reports, such as "libpcap version 1.10.4".
pub fn library_version() -> Result<String, LiveError> {
    let pcap = load()?;
    // SAFETY: returns a static string.
    Ok(unsafe { text((pcap.lib_version)()) })
}

fn load() -> Result<&'static Pcap, LiveError> {
    ffi::pcap().map_err(|tried| LiveError::NoLibrary(tried.to_string()))
}

/// A network interface to capture on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    /// What libpcap opens: `eth0`, or `\Device\NPF_{...}` on Windows.
    pub name: String,
    pub description: Option<String>,
    pub addresses: Vec<IpAddr>,
    pub loopback: bool,
    pub up: bool,
    pub running: bool,
    pub wireless: bool,
    /// libpcap 1.9 and Npcap say when no cable or network is connected.
    pub disconnected: bool,
}

impl Interface {
    /// A name a person recognizes. Windows device names are GUIDs, so the
    /// description is better there.
    pub fn label(&self) -> &str {
        match &self.description {
            Some(d) if self.name.starts_with(r"\Device\") => d,
            _ => &self.name,
        }
    }
}

/// Every interface libpcap can capture on, in its order.
pub fn interfaces() -> Result<Vec<Interface>, LiveError> {
    let pcap = load()?;
    let mut errbuf = [0 as c_char; ERRBUF_SIZE];
    let mut list = ptr::null_mut();
    // SAFETY: on success `list` is a linked list we own until freealldevs.
    if unsafe { (pcap.findalldevs)(&mut list, errbuf.as_mut_ptr()) } != 0 {
        return Err(LiveError::Other(unsafe { text(errbuf.as_ptr()) }));
    }
    let mut out = Vec::new();
    let mut dev = list;
    while !dev.is_null() {
        // SAFETY: each node and its strings live until freealldevs.
        let d = unsafe { &*dev };
        let mut addresses = Vec::new();
        let mut a = d.addresses;
        while !a.is_null() {
            let addr = unsafe { &*a };
            if let Some(ip) = unsafe { sockaddr_ip(addr.addr) } {
                addresses.push(ip);
            }
            a = addr.next;
        }
        out.push(Interface {
            name: unsafe { text(d.name) },
            description: Some(unsafe { text(d.description) }).filter(|s| !s.is_empty()),
            addresses,
            loopback: d.flags & ffi::IF_LOOPBACK != 0,
            up: d.flags & ffi::IF_UP != 0,
            running: d.flags & ffi::IF_RUNNING != 0,
            wireless: d.flags & ffi::IF_WIRELESS != 0,
            disconnected: d.flags & ffi::IF_CONNECTION_STATUS == ffi::IF_DISCONNECTED,
        });
        dev = d.next;
    }
    unsafe { (pcap.freealldevs)(list) };
    Ok(out)
}

/// The interface `wanted` names: its name, its number in `interfaces()`
/// counting from 1, one of its addresses, or its description.
pub fn find(list: &[Interface], wanted: &str) -> Option<usize> {
    if let Some(i) = list.iter().position(|i| i.name == wanted) {
        return Some(i);
    }
    if let Ok(n) = wanted.parse::<usize>() {
        return (1..=list.len()).contains(&n).then(|| n - 1);
    }
    if let Ok(ip) = wanted.parse::<IpAddr>() {
        return list.iter().position(|i| i.addresses.contains(&ip));
    }
    let wanted = wanted.to_lowercase();
    let described = |exact: bool| {
        let matches: Vec<usize> = (0..list.len())
            .filter(|&i| {
                list[i].description.as_ref().is_some_and(|d| {
                    let d = d.to_lowercase();
                    if exact {
                        d == wanted
                    } else {
                        d.contains(&wanted)
                    }
                })
            })
            .collect();
        (matches.len() == 1).then(|| matches[0])
    };
    described(true).or_else(|| described(false))
}

/// The interface to capture on when none is named: the one this machine
/// reaches the internet through, or else the first that is up and has an
/// address.
pub fn default_interface(list: &[Interface]) -> Option<usize> {
    choose_default(list, route_source())
}

fn choose_default(list: &[Interface], route_source: Option<IpAddr>) -> Option<usize> {
    if let Some(ip) = route_source
        && let Some(i) = list.iter().position(|i| i.addresses.contains(&ip))
    {
        return Some(i);
    }
    list.iter().position(|i| {
        !i.loopback
            && i.up
            && i.running
            && !i.disconnected
            && i.addresses
                .iter()
                .any(|ip| !ip.is_loopback() && !link_local(ip))
    })
}

/// The address this machine sends from to reach the internet. Connecting a
/// UDP socket picks a route without sending anything; the targets are
/// documentation addresses that go wherever the default route goes.
fn route_source() -> Option<IpAddr> {
    [("0.0.0.0:0", "192.0.2.1:9"), ("[::]:0", "[2001:db8::1]:9")]
        .into_iter()
        .find_map(|(bind, target)| {
            let socket = UdpSocket::bind(bind).ok()?;
            socket.connect(target).ok()?;
            let ip = socket.local_addr().ok()?.ip();
            (!ip.is_unspecified()).then_some(ip)
        })
}

fn link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
    }
}

/// What to capture.
#[derive(Debug, Clone, Default)]
pub struct Options<'a> {
    /// Bytes kept from each packet.
    pub snaplen: u32,
    /// Also capture traffic between other machines, when the network shows it.
    pub promisc: bool,
    /// A capture filter in libpcap's syntax, such as `port 443`.
    pub filter: Option<&'a str>,
}

/// An open capture.
pub struct Live {
    pcap: &'static Pcap,
    p: *mut PcapT,
    link_type: u16,
    /// Whether timestamps are in nanoseconds rather than microseconds.
    nanos: bool,
    frames: u64,
}

impl Live {
    /// Starts capturing on `device`. Returns libpcap's warning too, if it
    /// gave one (such as promiscuous mode not being supported).
    pub fn open(device: &str, options: &Options) -> Result<(Live, Option<String>), LiveError> {
        let pcap = load()?;
        let name = CString::new(device)
            .map_err(|_| LiveError::NoSuchInterface(format!("no interface called {device:?}")))?;
        let mut errbuf = [0 as c_char; ERRBUF_SIZE];
        // SAFETY: both pointers are valid for the call.
        let p = unsafe { (pcap.create)(name.as_ptr(), errbuf.as_mut_ptr()) };
        if p.is_null() {
            return Err(LiveError::Other(unsafe { text(errbuf.as_ptr()) }));
        }
        // From here on, dropping `live` closes the handle.
        let mut live = Live {
            pcap,
            p,
            link_type: 0,
            nanos: false,
            frames: 0,
        };
        // SAFETY: `p` is a handle from pcap_create that isn't active yet.
        // These setters only fail on an active handle.
        unsafe {
            (pcap.set_snaplen)(p, c_int::try_from(options.snaplen).unwrap_or(c_int::MAX));
            (pcap.set_promisc)(p, c_int::from(options.promisc));
            (pcap.set_timeout)(p, READ_TIMEOUT_MS);
            (pcap.set_buffer_size)(p, BUFFER_BYTES);
            if let Some(set) = pcap.set_tstamp_precision {
                set(p, ffi::TSTAMP_PRECISION_NANO);
            }
        }
        let status = unsafe { (pcap.activate)(p) };
        if status < 0 {
            let detail = live.error_text(status);
            return Err(match status {
                ffi::ERROR_PERM_DENIED | ffi::ERROR_PROMISC_PERM_DENIED => {
                    LiveError::PermissionDenied(detail)
                }
                ffi::ERROR_NO_SUCH_DEVICE => {
                    LiveError::NoSuchInterface(format!("no interface called {device:?}: {detail}"))
                }
                ffi::ERROR_IFACE_NOT_UP => LiveError::Other(format!("{device} is down: {detail}")),
                _ => LiveError::Other(detail),
            });
        }
        let warning = (status > 0).then(|| live.error_text(status));
        live.nanos = pcap
            .get_tstamp_precision
            .is_some_and(|get| unsafe { get(p) } == ffi::TSTAMP_PRECISION_NANO);
        live.link_type = link_type(unsafe { (pcap.datalink)(p) });
        if let Some(filter) = options.filter {
            live.set_filter(filter)?;
        }
        if unsafe { (pcap.setnonblock)(p, 1, errbuf.as_mut_ptr()) } != 0 {
            return Err(LiveError::Other(unsafe { text(errbuf.as_ptr()) }));
        }
        Ok((live, warning))
    }

    /// LINKTYPE_* of the packets, for decoding and for the file header.
    pub fn link_type(&self) -> u16 {
        self.link_type
    }

    /// The next packet, or `None` after a short wait when there is none.
    pub fn next_frame(&mut self) -> Result<Option<Frame>, LiveError> {
        let mut hdr: *mut PktHdr = ptr::null_mut();
        let mut data: *const u8 = ptr::null();
        // SAFETY: on 1, both point at the packet until the next call.
        match unsafe { (self.pcap.next_ex)(self.p, &mut hdr, &mut data) } {
            1 => {}
            0 => {
                std::thread::sleep(IDLE);
                return Ok(None);
            }
            status => return Err(LiveError::Other(self.error_text(status))),
        }
        let (hdr, bytes) = unsafe {
            let hdr = &*hdr;
            (hdr, std::slice::from_raw_parts(data, hdr.caplen as usize))
        };
        let (secs, frac) = hdr.ts.parts();
        let frac_nanos = if self.nanos { frac } else { frac * 1000 };
        let nanos = (secs.max(0) as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(frac_nanos.max(0) as u64);
        self.frames += 1;
        Ok(Some(Frame {
            number: self.frames,
            ts: Timestamp(nanos),
            link_type: self.link_type,
            orig_len: hdr.len,
            data: bytes.to_vec(),
        }))
    }

    /// Packets the system threw away because they weren't read fast enough.
    /// Packets the interface itself dropped aren't counted: those were lost
    /// on the way in, as the rest of the machine saw it too.
    pub fn dropped(&self) -> Option<u64> {
        let mut stats = PcapStat::default();
        // SAFETY: `stats` has room for every platform's counters.
        let ok = unsafe { (self.pcap.stats)(self.p, &mut stats) } == 0;
        ok.then(|| u64::from(stats.drop))
    }

    fn set_filter(&mut self, filter: &str) -> Result<(), LiveError> {
        let text = CString::new(filter)
            .map_err(|_| LiveError::BadFilter(format!("{filter:?} has a NUL byte")))?;
        let mut program = BpfProgram {
            len: 0,
            insns: ptr::null_mut(),
        };
        // SAFETY: `program` is filled by compile and freed below.
        let compiled = unsafe {
            (self.pcap.compile)(self.p, &mut program, text.as_ptr(), 1, ffi::NETMASK_UNKNOWN)
        };
        if compiled != 0 {
            return Err(LiveError::BadFilter(format!("{filter}: {}", self.geterr())));
        }
        let set = unsafe { (self.pcap.setfilter)(self.p, &mut program) };
        unsafe { (self.pcap.freecode)(&mut program) };
        if set != 0 {
            return Err(LiveError::BadFilter(format!("{filter}: {}", self.geterr())));
        }
        Ok(())
    }

    fn geterr(&self) -> String {
        // SAFETY: returns a string inside the handle.
        unsafe { text((self.pcap.geterr)(self.p)) }
    }

    /// libpcap's message for a status, with the details it saved if any.
    fn error_text(&self, status: c_int) -> String {
        let detail = self.geterr();
        if !detail.is_empty() {
            return detail;
        }
        // SAFETY: returns a static string.
        unsafe { text((self.pcap.statustostr)(status)) }
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        // SAFETY: `p` came from pcap_create and is closed only here.
        unsafe { (self.pcap.close)(self.p) }
    }
}

/// DLT_* values are LINKTYPE_* values except for raw IP, which the file
/// formats moved to its own number.
fn link_type(dlt: c_int) -> u16 {
    match dlt {
        12 => linktype::RAW,
        other => u16::try_from(other).unwrap_or(u16::MAX),
    }
}

/// Copies a C string; null reads as empty.
unsafe fn text(s: *const c_char) -> String {
    if s.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(s) }.to_string_lossy().into_owned()
}

const AF_INET: u16 = 2;
#[cfg(any(target_os = "linux", target_os = "android"))]
const AF_INET6: u16 = 10;
#[cfg(target_vendor = "apple")]
const AF_INET6: u16 = 30;
#[cfg(windows)]
const AF_INET6: u16 = 23;
#[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
const AF_INET6: u16 = 28;
#[cfg(any(target_os = "openbsd", target_os = "netbsd"))]
const AF_INET6: u16 = 24;
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    windows,
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_os = "netbsd"
)))]
const AF_INET6: u16 = u16::MAX;

/// BSD-derived systems start `struct sockaddr` with a length byte, then a
/// one-byte family; others with a two-byte family.
const SOCKADDR_LEN_BYTE: bool = cfg!(any(
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_os = "netbsd"
));

/// Reads an IPv4 or IPv6 address out of a `struct sockaddr`.
unsafe fn sockaddr_ip(sa: *const u8) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    // SAFETY: every sockaddr has at least the two family bytes, and the
    // family says how long the rest is.
    let head = unsafe { std::slice::from_raw_parts(sa, 2) };
    let len = match family(head) {
        AF_INET => 8,
        AF_INET6 => 24,
        _ => return None,
    };
    parse_sockaddr(unsafe { std::slice::from_raw_parts(sa, len) })
}

fn family(b: &[u8]) -> u16 {
    if SOCKADDR_LEN_BYTE {
        u16::from(b[1])
    } else {
        u16::from_ne_bytes([b[0], b[1]])
    }
}

/// `sockaddr_in` has the address at byte 4, `sockaddr_in6` at byte 8,
/// after the family, port, and (for IPv6) flow label.
fn parse_sockaddr(b: &[u8]) -> Option<IpAddr> {
    match family(b) {
        AF_INET => Some(IpAddr::from(<[u8; 4]>::try_from(b.get(4..8)?).ok()?)),
        AF_INET6 => Some(IpAddr::from(<[u8; 16]>::try_from(b.get(8..24)?).ok()?)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, addresses: &[&str]) -> Interface {
        Interface {
            name: name.to_string(),
            description: None,
            addresses: addresses.iter().map(|a| a.parse().unwrap()).collect(),
            loopback: name == "lo",
            up: true,
            running: true,
            wireless: false,
            disconnected: false,
        }
    }

    fn sockaddr(family: u16, len: usize, addr_at: usize, addr: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; len];
        if SOCKADDR_LEN_BYTE {
            b[0] = len as u8;
            b[1] = family as u8;
        } else {
            b[..2].copy_from_slice(&family.to_ne_bytes());
        }
        b[2..4].copy_from_slice(&443u16.to_be_bytes());
        b[addr_at..addr_at + addr.len()].copy_from_slice(addr);
        b
    }

    #[test]
    fn reads_socket_addresses() {
        let v4 = sockaddr(AF_INET, 16, 4, &[192, 168, 1, 5]);
        assert_eq!(parse_sockaddr(&v4), Some("192.168.1.5".parse().unwrap()));
        let ip6: IpAddr = "2001:db8::7".parse().unwrap();
        let IpAddr::V6(v6) = ip6 else { unreachable!() };
        let b = sockaddr(AF_INET6, 28, 8, &v6.octets());
        assert_eq!(parse_sockaddr(&b), Some(ip6));
        assert_eq!(unsafe { sockaddr_ip(b.as_ptr()) }, Some(ip6));
        // A link-layer address (AF_PACKET, AF_LINK) is skipped.
        let other = sockaddr(17, 20, 4, &[1, 2, 3, 4]);
        assert_eq!(parse_sockaddr(&other), None);
        assert_eq!(unsafe { sockaddr_ip(ptr::null()) }, None);
    }

    #[test]
    fn finds_interfaces_by_name_number_address_or_description() {
        let mut wifi = iface(r"\Device\NPF_{4F1A}", &["192.168.1.5", "fe80::1"]);
        wifi.description = Some("Intel(R) Wi-Fi 6 AX201".to_string());
        let mut ethernet = iface(r"\Device\NPF_{9C2B}", &["10.0.0.7"]);
        ethernet.description = Some("Realtek PCIe GbE Family Controller".to_string());
        let list = vec![iface("lo", &["127.0.0.1"]), wifi, ethernet];
        assert_eq!(find(&list, "lo"), Some(0));
        assert_eq!(find(&list, "2"), Some(1));
        assert_eq!(find(&list, "4"), None);
        assert_eq!(find(&list, "10.0.0.7"), Some(2));
        assert_eq!(find(&list, "wi-fi"), Some(1));
        assert_eq!(find(&list, "realtek pcie gbe family controller"), Some(2));
        assert_eq!(find(&list, "eth9"), None);
        assert_eq!(list[1].label(), "Intel(R) Wi-Fi 6 AX201");
        assert_eq!(list[0].label(), "lo");
    }

    #[test]
    fn defaults_to_the_interface_with_the_route_out() {
        let mut down = iface("eth1", &["10.1.1.1"]);
        down.running = false;
        let list = vec![
            iface("lo", &["127.0.0.1"]),
            iface("docker0", &["169.254.3.3"]),
            down,
            iface("eth0", &["172.20.1.5"]),
            iface("wlan0", &["192.168.1.5"]),
        ];
        let routed = Some("192.168.1.5".parse().unwrap());
        assert_eq!(choose_default(&list, routed), Some(4));
        assert_eq!(choose_default(&list, None), Some(3));
        assert_eq!(choose_default(&list[..3], None), None);
    }

    #[test]
    fn raw_ip_gets_its_file_number() {
        assert_eq!(link_type(12), linktype::RAW);
        assert_eq!(link_type(1), linktype::ETHERNET);
        assert_eq!(link_type(276), linktype::LINUX_SLL2);
    }
}
