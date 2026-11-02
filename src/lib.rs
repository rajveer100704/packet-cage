//! packet-cage reads packet captures and explains what went wrong on the
//! network. See PLAN.md for where this is going.

pub mod analyze;
pub mod capture;
pub mod decode;
pub mod diagnose;
pub mod filter;
pub mod flow;
pub mod live;
pub mod names;
pub mod report;
pub mod stats;
pub mod summary;
pub mod units;

// Linux-only resource isolation primitives.
#[cfg(target_os = "linux")]
pub mod sandbox;
