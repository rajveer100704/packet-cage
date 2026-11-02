//! Linux namespace isolation using the util-linux `unshare` helper.
//!
//! The profile is deliberately fixed rather than user-configurable, so callers
//! cannot accidentally omit an isolation boundary. Filesystem restrictions
//! and seccomp are separate stages and are not provided by this module.

use std::ffi::{OsStr, OsString};
use std::path::Path;

use anyhow::{Context, Result};
use std::process::Child;

use super::cgroup::JobCgroup;
use super::launcher::spawn_in_cgroup;

const UNSHARE_CANDIDATES: [&str; 2] = ["/usr/bin/unshare", "/bin/unshare"];

const NAMESPACE_OPTIONS: &[&str] = &[
    "--user",
    "--map-root-user",
    "--mount",
    "--propagation",
    "private",
    "--pid",
    "--fork",
    "--mount-proc",
    "--net",
    "--ipc",
    "--uts",
    "--kill-child",
];

/// Starts a worker inside the fixed PacketCage namespace profile.
///
/// The unshare supervisor is first attached to `job` by the gated cgroup
/// launcher. Its namespace child inherits the same cgroup membership.
///
/// The worker receives:
/// - a new user namespace with the current user mapped to namespace root;
/// - private mount, PID, network, IPC, and UTS namespaces;
/// - a procfs mount associated with the new PID namespace;
/// - a private mount-propagation tree;
/// - parent-death handling for the namespace child.
///
/// This helper establishes namespaces only. The sandbox worker separately
/// configures the private root filesystem and installs the seccomp policy.
pub fn spawn_namespaced_in_cgroup<I, S>(
    job: &JobCgroup,
    program: impl AsRef<OsStr>,
    args: I,
) -> Result<Child>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let unshare = find_unshare()?;

    let mut command_args: Vec<OsString> = NAMESPACE_OPTIONS.iter().map(OsString::from).collect();

    command_args.push(OsString::from("--"));
    command_args.push(program.as_ref().to_os_string());

    for arg in args {
        command_args.push(arg.as_ref().to_os_string());
    }

    spawn_in_cgroup(job, unshare, command_args)
        .context("cannot start namespaced worker inside its cgroup")
}

fn find_unshare() -> Result<&'static str> {
    UNSHARE_CANDIDATES
        .iter()
        .copied()
        .find(|candidate| Path::new(candidate).is_file())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "cannot find util-linux unshare; checked {}",
                UNSHARE_CANDIDATES.join(", ")
            )
        })
}
