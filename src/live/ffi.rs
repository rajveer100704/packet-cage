//! The parts of libpcap's C API that live capture uses, loaded at run time.
//!
//! Linking libpcap at build time would make every packet-cage binary need it
//! (and Npcap on Windows) just to start, even to read a file. Loading it when
//! a capture starts keeps file reading free of it, and lets a missing library
//! be explained instead of crashing at startup.

use std::ffi::{c_char, c_int, c_uint, c_void};
use std::sync::OnceLock;

use libloading::Library;

/// `PCAP_ERRBUF_SIZE`: the size of the buffer libpcap writes errors into.
pub const ERRBUF_SIZE: usize = 256;

pub const IF_LOOPBACK: c_uint = 0x01;
pub const IF_UP: c_uint = 0x02;
pub const IF_RUNNING: c_uint = 0x04;
pub const IF_WIRELESS: c_uint = 0x08;
pub const IF_CONNECTION_STATUS: c_uint = 0x30;
pub const IF_DISCONNECTED: c_uint = 0x20;

pub const ERROR_NO_SUCH_DEVICE: c_int = -5;
pub const ERROR_PERM_DENIED: c_int = -8;
pub const ERROR_IFACE_NOT_UP: c_int = -9;
pub const ERROR_PROMISC_PERM_DENIED: c_int = -11;

pub const TSTAMP_PRECISION_NANO: c_int = 1;
/// "Any netmask": only matters for filters that test broadcast addresses.
pub const NETMASK_UNKNOWN: u32 = 0xffff_ffff;

/// `pcap_t`, which only libpcap looks inside.
#[repr(C)]
pub struct PcapT {
    _opaque: [u8; 0],
}

/// `pcap_if_t`: one entry in the list of interfaces.
#[repr(C)]
pub struct PcapIf {
    pub next: *mut PcapIf,
    pub name: *mut c_char,
    pub description: *mut c_char,
    pub addresses: *mut PcapAddr,
    pub flags: c_uint,
}

/// `pcap_addr_t`. The addresses are `struct sockaddr`, read by
/// [`super::sockaddr_ip`].
#[repr(C)]
pub struct PcapAddr {
    pub next: *mut PcapAddr,
    pub addr: *const u8,
    pub netmask: *const u8,
    pub broadaddr: *const u8,
    pub dstaddr: *const u8,
}

/// `struct timeval`, whose fields differ in size between systems.
#[cfg(target_vendor = "apple")]
#[repr(C)]
pub struct TimeVal {
    pub sec: i64,
    pub usec: i32,
}

#[cfg(not(target_vendor = "apple"))]
#[repr(C)]
pub struct TimeVal {
    pub sec: std::ffi::c_long,
    pub usec: std::ffi::c_long,
}

impl TimeVal {
    /// Seconds and the fraction, in whatever unit the capture uses.
    // c_long is 32 bits on Windows and 64 elsewhere.
    #[allow(clippy::useless_conversion)]
    pub fn parts(&self) -> (i64, i64) {
        (i64::from(self.sec), i64::from(self.usec))
    }
}

/// `struct pcap_pkthdr`. macOS adds fields after these; libpcap owns the
/// memory, so only the start is read.
#[repr(C)]
pub struct PktHdr {
    pub ts: TimeVal,
    pub caplen: u32,
    pub len: u32,
}

/// `struct pcap_stat`, with room for the extra counters Windows adds.
#[repr(C)]
#[derive(Default)]
pub struct PcapStat {
    pub recv: c_uint,
    pub drop: c_uint,
    pub ifdrop: c_uint,
    _windows: [c_uint; 3],
}

/// `struct bpf_program`: a compiled capture filter.
#[repr(C)]
pub struct BpfProgram {
    pub len: c_uint,
    pub insns: *mut c_void,
}

/// The functions packet-cage calls. The fn pointers stay valid because the
/// library is kept with them and never unloaded.
pub struct Pcap {
    pub lib_version: unsafe extern "C" fn() -> *const c_char,
    pub findalldevs: unsafe extern "C" fn(*mut *mut PcapIf, *mut c_char) -> c_int,
    pub freealldevs: unsafe extern "C" fn(*mut PcapIf),
    pub create: unsafe extern "C" fn(*const c_char, *mut c_char) -> *mut PcapT,
    pub set_snaplen: unsafe extern "C" fn(*mut PcapT, c_int) -> c_int,
    pub set_promisc: unsafe extern "C" fn(*mut PcapT, c_int) -> c_int,
    pub set_timeout: unsafe extern "C" fn(*mut PcapT, c_int) -> c_int,
    pub set_buffer_size: unsafe extern "C" fn(*mut PcapT, c_int) -> c_int,
    /// Missing before libpcap 1.5.
    pub set_tstamp_precision: Option<unsafe extern "C" fn(*mut PcapT, c_int) -> c_int>,
    pub get_tstamp_precision: Option<unsafe extern "C" fn(*mut PcapT) -> c_int>,
    pub activate: unsafe extern "C" fn(*mut PcapT) -> c_int,
    pub datalink: unsafe extern "C" fn(*mut PcapT) -> c_int,
    pub next_ex: unsafe extern "C" fn(*mut PcapT, *mut *mut PktHdr, *mut *const u8) -> c_int,
    pub geterr: unsafe extern "C" fn(*mut PcapT) -> *mut c_char,
    pub statustostr: unsafe extern "C" fn(c_int) -> *const c_char,
    pub stats: unsafe extern "C" fn(*mut PcapT, *mut PcapStat) -> c_int,
    pub compile:
        unsafe extern "C" fn(*mut PcapT, *mut BpfProgram, *const c_char, c_int, u32) -> c_int,
    pub setfilter: unsafe extern "C" fn(*mut PcapT, *mut BpfProgram) -> c_int,
    pub freecode: unsafe extern "C" fn(*mut BpfProgram),
    pub setnonblock: unsafe extern "C" fn(*mut PcapT, c_int, *mut c_char) -> c_int,
    pub close: unsafe extern "C" fn(*mut PcapT),
    _lib: Library,
}

/// libpcap, loaded on first use. The error says which files were tried.
pub fn pcap() -> Result<&'static Pcap, &'static str> {
    static PCAP: OnceLock<Result<Pcap, String>> = OnceLock::new();
    PCAP.get_or_init(load).as_ref().map_err(String::as_str)
}

fn load() -> Result<Pcap, String> {
    let mut tried = Vec::new();
    for name in candidates() {
        // SAFETY: loading runs the library's initializers; libpcap's only set
        // up its own state.
        match unsafe { open(&name) } {
            Ok(lib) => {
                // SAFETY: the types above match libpcap's declarations.
                return unsafe { Pcap::resolve(lib) }.map_err(|e| format!("{name}: {e}"));
            }
            Err(_) => tried.push(name),
        }
    }
    Err(format!("could not load {}", tried.join(" or ")))
}

impl Pcap {
    unsafe fn resolve(lib: Library) -> Result<Pcap, libloading::Error> {
        macro_rules! sym {
            ($name:literal) => {
                *unsafe { lib.get(concat!($name, "\0").as_bytes()) }?
            };
        }
        macro_rules! optional {
            ($name:literal) => {
                unsafe { lib.get(concat!($name, "\0").as_bytes()) }
                    .ok()
                    .map(|s| *s)
            };
        }
        Ok(Pcap {
            lib_version: sym!("pcap_lib_version"),
            findalldevs: sym!("pcap_findalldevs"),
            freealldevs: sym!("pcap_freealldevs"),
            create: sym!("pcap_create"),
            set_snaplen: sym!("pcap_set_snaplen"),
            set_promisc: sym!("pcap_set_promisc"),
            set_timeout: sym!("pcap_set_timeout"),
            set_buffer_size: sym!("pcap_set_buffer_size"),
            set_tstamp_precision: optional!("pcap_set_tstamp_precision"),
            get_tstamp_precision: optional!("pcap_get_tstamp_precision"),
            activate: sym!("pcap_activate"),
            datalink: sym!("pcap_datalink"),
            next_ex: sym!("pcap_next_ex"),
            geterr: sym!("pcap_geterr"),
            statustostr: sym!("pcap_statustostr"),
            stats: sym!("pcap_stats"),
            compile: sym!("pcap_compile"),
            setfilter: sym!("pcap_setfilter"),
            freecode: sym!("pcap_freecode"),
            setnonblock: sym!("pcap_setnonblock"),
            close: sym!("pcap_close"),
            _lib: lib,
        })
    }
}

/// Npcap installs into its own folder, which isn't on the DLL search path.
/// WinPcap, its predecessor, used System32. Full paths only, so a DLL that
/// happens to be in the current folder is never loaded.
#[cfg(windows)]
fn candidates() -> Vec<String> {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    vec![
        format!(r"{root}\System32\Npcap\wpcap.dll"),
        format!(r"{root}\System32\wpcap.dll"),
    ]
}

#[cfg(target_vendor = "apple")]
fn candidates() -> Vec<String> {
    vec!["libpcap.A.dylib".into(), "/usr/lib/libpcap.A.dylib".into()]
}

/// Debian and Ubuntu ship `libpcap.so.0.8`, other systems `libpcap.so.1`;
/// plain `libpcap.so` comes with the development package.
#[cfg(all(unix, not(target_vendor = "apple")))]
fn candidates() -> Vec<String> {
    vec![
        "libpcap.so.1".into(),
        "libpcap.so.0.8".into(),
        "libpcap.so".into(),
    ]
}

#[cfg(windows)]
unsafe fn open(path: &str) -> Result<Library, libloading::Error> {
    use libloading::os::windows::{LOAD_WITH_ALTERED_SEARCH_PATH, Library as WinLibrary};
    // wpcap.dll loads Packet.dll; this flag finds it next to wpcap.dll.
    unsafe { WinLibrary::load_with_flags(path, LOAD_WITH_ALTERED_SEARCH_PATH) }.map(Library::from)
}

#[cfg(unix)]
unsafe fn open(path: &str) -> Result<Library, libloading::Error> {
    unsafe { Library::new(path) }
}
