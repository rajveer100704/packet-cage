#[cfg(target_os = "linux")]
mod linux {
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::thread;
    use std::time::{Duration, Instant};

    use anyhow::{Context, Result, ensure};

    use packet_cage::sandbox::cgroup::{CgroupManager, ResourceLimits};
    use packet_cage::sandbox::launcher::wait_with_timeout;
    use packet_cage::sandbox::namespaces::spawn_namespaced_in_cgroup;

    fn wait_for_process_count(path: &Path, minimum: usize) -> Result<Vec<u32>> {
        let deadline = Instant::now() + Duration::from_secs(3);

        loop {
            let contents = fs::read_to_string(path.join("cgroup.procs"))
                .context("reading worker cgroup.procs")?;

            let pids: Vec<u32> = contents
                .split_whitespace()
                .map(str::parse)
                .collect::<std::result::Result<_, _>>()?;

            if pids.len() >= minimum {
                return Ok(pids);
            }

            ensure!(
                Instant::now() < deadline,
                "expected at least {minimum} processes in the workload cgroup; found {pids:?}"
            );

            thread::sleep(Duration::from_millis(10));
        }
    }

    fn run(cgroup_root: PathBuf) -> Result<()> {
        let cgroup_root = cgroup_root.canonicalize()?;
        let base_name = format!("packet-cage-timeout-{}", std::process::id());

        println!("1. Creating delegated cgroup manager...");
        let manager = CgroupManager::new(&cgroup_root, &base_name)?;
        let base_path = manager.base_path().to_path_buf();

        let limits = ResourceLimits {
            cpu_quota_micros: Some(50_000),
            cpu_period_micros: 100_000,
            memory_max_bytes: 256 * 1024 * 1024,
            pids_max: 64,
        };

        println!("2. Creating a workload with a child process...");
        let job = manager.create_job("worker", limits)?;
        let job_path = job.path().to_path_buf();

        let mut child = spawn_namespaced_in_cgroup(&job, "/bin/sh", ["-c", "sleep 30 & wait"])?;

        let supervisor_pid = child.id();
        let pids = wait_for_process_count(&job_path, 2)?;

        println!("   Supervisor PID: {supervisor_pid}");
        println!("   Workload PIDs: {pids:?}");

        ensure!(
            pids.len() >= 3,
            "expected namespace supervisor, worker shell, and background child; found {pids:?}"
        );

        ensure!(
            pids.iter().any(|pid| *pid != supervisor_pid),
            "the test workload did not create a descendant process"
        );

        println!("3. Enforcing a 300 ms execution timeout...");
        let result = wait_with_timeout(
            &mut child,
            &job,
            Duration::from_millis(300),
            Duration::from_secs(3),
        );

        let error = result.expect_err("long-running worker unexpectedly completed");
        let message = format!("{error:#}");

        ensure!(
            message.contains("exceeded execution timeout"),
            "unexpected timeout result: {message}"
        );

        println!("   PASS: timeout detected");
        println!("4. Verifying the entire workload has exited...");

        job.wait_for_empty(Duration::from_secs(1))?;

        for pid in &pids {
            ensure!(
                !Path::new(&format!("/proc/{pid}")).exists(),
                "process {pid} survived workload termination"
            );
        }

        println!("   PASS: supervisor and descendant no longer exist");

        println!("5. Removing workload and manager cgroups...");
        job.remove()?;
        drop(manager);
        fs::remove_dir(&base_path).with_context(|| format!("removing {}", base_path.display()))?;

        println!("   PASS: cgroups removed");
        println!();
        println!("Timeout and process-tree cleanup test passed.");

        Ok(())
    }

    pub(super) fn linux_main() -> std::process::ExitCode {
        let Some(root) = env::args_os().nth(1) else {
            eprintln!("Usage: timeout_smoke CGROUP_ROOT");
            return std::process::ExitCode::FAILURE;
        };

        match run(PathBuf::from(root)) {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("Timeout smoke test failed: {error:#}");
                std::process::ExitCode::FAILURE
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    linux::linux_main()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("timeout_smoke.rs is only available on Linux");
}
