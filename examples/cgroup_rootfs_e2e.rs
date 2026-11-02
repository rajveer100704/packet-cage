#[cfg(target_os = "linux")]
mod linux {
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use std::process::ExitCode;
    use std::thread;
    use std::time::Duration;

    use anyhow::{Context, Result, ensure};

    use packet_cage::sandbox::cgroup::{CgroupManager, ResourceLimits};
    use packet_cage::sandbox::namespaces::spawn_namespaced_in_cgroup;

    fn run(
        cgroup_root: PathBuf,
        executable: PathBuf,
        rootfs_runner: PathBuf,
        capture: PathBuf,
    ) -> Result<()> {
        let cgroup_root = cgroup_root.canonicalize()?;
        let executable = executable.canonicalize()?;
        let rootfs_runner = rootfs_runner.canonicalize()?;
        let capture = capture.canonicalize()?;

        let base_name = format!("packet-cage-e2e-{}", std::process::id());

        println!("1. Creating cgroup manager...");
        let manager = CgroupManager::new(&cgroup_root, &base_name)?;
        let base_path = manager.base_path().to_path_buf();

        let limits = ResourceLimits {
            cpu_quota_micros: Some(50_000),
            cpu_period_micros: 100_000,
            memory_max_bytes: 512 * 1024 * 1024,
            pids_max: 64,
        };

        println!("2. Creating resource-limited worker...");
        let job = manager.create_job("worker", limits)?;
        let job_path = job.path().to_path_buf();

        let mut child = match spawn_namespaced_in_cgroup(
            &job,
            &rootfs_runner,
            [executable.as_os_str(), capture.as_os_str()],
        ) {
            Ok(child) => child,
            Err(error) => {
                job.remove()?;
                drop(manager);
                fs::remove_dir(&base_path)?;
                return Err(error);
            }
        };

        println!("3. Checking worker cgroup membership...");

        let membership = fs::read_to_string(format!("/proc/{}/cgroup", child.id()))
            .context("cannot inspect namespace supervisor cgroup")?;

        let expected_suffix = format!("{base_name}/worker");

        println!("   {}", membership.trim());

        println!("4. Waiting for namespaced filesystem and PCAP analysis...");

        let status_result = child.wait();

        println!("5. Waiting for all worker processes to exit...");
        let empty_result = wait_for_empty_cgroup(&job_path);

        println!("6. Removing worker cgroup...");
        let remove_result = job.remove();

        drop(manager);

        let base_remove_result = fs::remove_dir(&base_path)
            .with_context(|| format!("cannot remove {}", base_path.display()));

        let status = status_result?;
        empty_result?;
        remove_result?;
        base_remove_result?;

        ensure!(
            membership
                .lines()
                .any(|line| line.ends_with(&expected_suffix)),
            "namespace supervisor was not attached to its resource cgroup: {membership}"
        );

        ensure!(
            status.success(),
            "sandbox workload exited unsuccessfully: {status}"
        );

        println!();
        println!("PASS: worker executed under cgroup resource limits");
        println!("PASS: namespace launcher executed successfully");
        println!("PASS: rootfs runner completed real PCAP analysis");
        println!("PASS: worker processes exited");
        println!("PASS: cgroups cleaned up");
        println!();
        println!("Combined cgroup + namespace + rootfs test passed.");

        Ok(())
    }

    fn wait_for_empty_cgroup(path: &std::path::Path) -> Result<()> {
        for _ in 0..300 {
            let processes = fs::read_to_string(path.join("cgroup.procs"))?;

            if processes.trim().is_empty() {
                return Ok(());
            }

            thread::sleep(Duration::from_millis(10));
        }

        let remaining = fs::read_to_string(path.join("cgroup.procs"))?;

        anyhow::bail!("worker cgroup still contains processes: {remaining}")
    }

    pub(super) fn linux_main() -> ExitCode {
        let args: Vec<PathBuf> = env::args_os().skip(1).map(PathBuf::from).collect();

        if args.len() != 4 {
            eprintln!("Usage: cgroup_rootfs_e2e CGROUP_ROOT PACKET_CAGE ROOTFS_RUNNER CAPTURE");
            return ExitCode::FAILURE;
        }

        match run(
            args[0].clone(),
            args[1].clone(),
            args[2].clone(),
            args[3].clone(),
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("Integration test failed: {error:#}");
                ExitCode::FAILURE
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
    eprintln!("cgroup_rootfs_e2e.rs is only available on Linux");
}
