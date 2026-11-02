//! Starts a worker only after it has been attached to its resource cgroup.

use std::ffi::OsStr;
use std::io::Write;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use super::cgroup::JobCgroup;

const GATE_SCRIPT: &str = "IFS= read -r _packet_cage_gate || exit 125; exec \"$@\" </dev/null";

/// Starts `program` in `job`, releasing it only after cgroup attachment.
///
/// A small shell process waits on a private stdin pipe. The parent attaches
/// that process to the cgroup, then sends the release line. The shell replaces
/// itself with the requested program, preserving its PID and cgroup membership.
///
/// Worker stdin is redirected to `/dev/null`; stdout and stderr are inherited.
pub fn spawn_in_cgroup<I, S>(job: &JobCgroup, program: impl AsRef<OsStr>, args: I) -> Result<Child>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let program = program.as_ref();
    if program.is_empty() {
        bail!("worker program cannot be empty");
    }

    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg(GATE_SCRIPT)
        .arg("packet-cage-cgroup-gate")
        .arg(program);

    for arg in args {
        command.arg(arg.as_ref());
    }

    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("cannot start the cgroup worker gate")?;

    let setup = (|| -> Result<()> {
        job.attach_pid(child.id())
            .context("cannot attach gated worker to its cgroup")?;

        let mut gate = child
            .stdin
            .take()
            .context("worker gate stdin was not available")?;

        gate.write_all(b"release\n")
            .context("cannot release the cgroup worker")?;
        gate.flush()
            .context("cannot flush the cgroup worker release")?;

        Ok(())
    })();

    if let Err(error) = setup {
        // Closing the pipe makes a still-waiting gate exit; kill as a fallback.
        drop(child.stdin.take());
        let _ = child.kill();
        let _ = child.wait();
        return Err(error).context("failed to launch worker inside its cgroup");
    }

    Ok(child)
}

/// Waits for a worker to exit, enforcing a wall-clock timeout.
///
/// If the deadline expires, every process in the workload cgroup is killed
/// through cgroup v2 `cgroup.kill`. The supervisor is reaped and the cgroup
/// must become empty before the timeout is reported.
///
/// If the supervisor exits but leaves descendants behind, those processes
/// are also terminated rather than silently orphaned.
pub fn wait_with_timeout(
    child: &mut Child,
    job: &JobCgroup,
    timeout: Duration,
    cleanup_timeout: Duration,
) -> Result<ExitStatus> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .context("worker timeout is too large")?;

    loop {
        if let Some(status) = child.try_wait().context("cannot poll sandbox worker")? {
            if let Err(descendant_error) = job.wait_for_empty(cleanup_timeout) {
                job.kill_all()
                    .context("worker exited but descendant cleanup failed")?;

                job.wait_for_empty(cleanup_timeout)
                    .context("descendant processes survived cgroup termination")?;

                bail!(
                    "worker exited with {status} but left descendant processes; \
                     they were terminated: {descendant_error:#}"
                );
            }

            return Ok(status);
        }

        let now = Instant::now();

        if now >= deadline {
            let kill_result = job.kill_all();

            // Fallback for the direct supervisor if cgroup.kill is unavailable
            // or fails. The namespace helper also has parent-death handling.
            if kill_result.is_err() {
                let _ = child.kill();
            }

            let cleanup_deadline = Instant::now()
                .checked_add(cleanup_timeout)
                .context("worker cleanup timeout is too large")?;

            // Poll instead of using blocking wait(), so cleanup itself is bounded.
            let _supervisor_status = loop {
                if let Some(status) = child
                    .try_wait()
                    .context("cannot reap timed-out sandbox supervisor")?
                {
                    break status;
                }

                let now = Instant::now();
                if now >= cleanup_deadline {
                    bail!(
                        "worker exceeded {:?}, but its supervisor did not exit \
                         within cleanup timeout {:?}",
                        timeout,
                        cleanup_timeout
                    );
                }

                thread::sleep(
                    Duration::from_millis(10).min(cleanup_deadline.saturating_duration_since(now)),
                );
            };

            let remaining = cleanup_deadline.saturating_duration_since(Instant::now());

            // Check all processes, including descendants, before returning.
            job.wait_for_empty(remaining)
                .context("timed-out worker left processes after termination")?;

            kill_result.context("cgroup.kill failed while terminating timed-out worker")?;

            bail!("worker exceeded execution timeout of {timeout:?}");
        }

        thread::sleep(Duration::from_millis(10).min(deadline.saturating_duration_since(now)));
    }
}
