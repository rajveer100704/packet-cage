//! Linux seccomp policy for the PacketCage analysis process.
//!
//! This is an initial, trace-derived policy. It must be exercised against
//! all supported capture formats and error paths before being treated as
//! a production policy.

use anyhow::{Context, Result};
use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};

/// Syscalls observed during a successful DNS PCAP analysis inside the
/// minimal chroot. Keep this list deliberately explicit.
const ANALYSIS_SYSCALLS: &[&str] = &[
    "access",
    "arch_prctl",
    "brk",
    "close",
    "exit_group",
    "fcntl",
    "fstat",
    "getrandom",
    "gettid",
    "mmap",
    "mprotect",
    "munmap",
    "newfstatat",
    "openat",
    "poll",
    "pread64",
    "prlimit64",
    "read",
    "rt_sigaction",
    "sched_getaffinity",
    "set_robust_list",
    "set_tid_address",
    "sigaltstack",
    "rseq",
    "write",
];

/// Install the initial default-deny filter for the analysis process.
///
/// Unlisted syscalls fail with EPERM. The filter is synchronized across
/// existing threads and no_new_privs is enabled before loading it.
pub fn install_analysis_filter() -> Result<()> {
    let mut filter = ScmpFilterContext::new(ScmpAction::Errno(libc::EPERM))
        .context("creating seccomp filter")?;

    for &name in ANALYSIS_SYSCALLS {
        let syscall = ScmpSyscall::from_name(name)
            .with_context(|| format!("resolving seccomp syscall {name}"))?;

        filter
            .add_rule(ScmpAction::Allow, syscall)
            .with_context(|| format!("allowing seccomp syscall {name}"))?;
    }

    filter
        .set_ctl_nnp(true)
        .context("enabling seccomp no_new_privs")?;

    filter
        .set_ctl_tsync(true)
        .context("enabling seccomp thread synchronization")?;

    filter.load().context("loading seccomp analysis filter")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn analysis_policy_is_non_empty() {
        assert!(!super::ANALYSIS_SYSCALLS.is_empty());
        assert!(super::ANALYSIS_SYSCALLS.contains(&"read"));
        assert!(super::ANALYSIS_SYSCALLS.contains(&"write"));
        assert!(super::ANALYSIS_SYSCALLS.contains(&"exit_group"));
    }
}
