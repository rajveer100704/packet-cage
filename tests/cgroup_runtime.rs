#![cfg(target_os = "linux")]

use std::error::Error;
use std::fs;
use std::thread;
use std::time::Duration;

use packet_cage::sandbox::cgroup::{CgroupManager, ResourceLimits};
use packet_cage::sandbox::namespaces::spawn_namespaced_in_cgroup;

const NAMESPACES: [&str; 6] = ["user", "mnt", "pid", "net", "ipc", "uts"];

#[test]
#[ignore = "requires an explicitly delegated cgroup v2 hierarchy and util-linux unshare"]
fn manages_a_real_namespaced_cgroup_worker() -> Result<(), Box<dyn Error>> {
    let root = std::env::var("PACKET_CAGE_TEST_CGROUP_ROOT")
        .expect("set PACKET_CAGE_TEST_CGROUP_ROOT to a delegated cgroup directory");

    let base_name = format!("packet-cage-test-{}", std::process::id());
    let manager = CgroupManager::new(root, &base_name)?;
    let base_path = manager.base_path().to_path_buf();

    let limits = ResourceLimits {
        cpu_quota_micros: Some(50_000),
        cpu_period_micros: 100_000,
        memory_max_bytes: 512 * 1024 * 1024,
        pids_max: 64,
    };

    let job = manager.create_job("worker", limits)?;
    let job_path = job.path().to_path_buf();

    // The worker stays alive while we inspect its namespaces.
    let mut supervisor = spawn_namespaced_in_cgroup(&job, "sleep", ["30"])?;

    let observations = (|| -> Result<_, Box<dyn Error>> {
        let worker_pid = wait_for_namespace_child(supervisor.id())?;

        let membership = fs::read_to_string(format!("/proc/{worker_pid}/cgroup"))?;

        let expected_suffix = format!("{base_name}/worker");
        let attached = membership
            .lines()
            .any(|line| line.ends_with(&expected_suffix));

        let mut namespace_results = Vec::new();

        for namespace in NAMESPACES {
            let host_namespace = fs::read_link(format!("/proc/self/ns/{namespace}"))?;
            let worker_namespace = fs::read_link(format!("/proc/{worker_pid}/ns/{namespace}"))?;

            namespace_results.push((
                namespace,
                host_namespace.display().to_string(),
                worker_namespace.display().to_string(),
                host_namespace != worker_namespace,
            ));
        }

        let cpu_max = fs::read_to_string(job_path.join("cpu.max"))?;
        let memory_max = fs::read_to_string(job_path.join("memory.max"))?;
        let pids_max = fs::read_to_string(job_path.join("pids.max"))?;

        Ok((
            worker_pid,
            membership,
            attached,
            namespace_results,
            cpu_max,
            memory_max,
            pids_max,
        ))
    })();

    // Killing the unshare supervisor triggers --kill-child for its worker.
    let _ = supervisor.kill();
    let _ = supervisor.wait();

    wait_for_empty_cgroup(&job_path)?;

    // Remove the leaf and manager cgroups after all processes have exited.
    job.remove()?;
    drop(manager);
    fs::remove_dir(&base_path)?;

    let (worker_pid, membership, attached, namespace_results, cpu_max, memory_max, pids_max) =
        observations?;

    eprintln!("Namespace worker PID: {worker_pid}");
    eprintln!("Worker cgroup membership: {}", membership.trim());

    assert!(
        attached,
        "worker was not found in its expected cgroup: {membership}"
    );

    for (namespace, host, worker, isolated) in namespace_results {
        eprintln!("{namespace}: host={host}, worker={worker}");
        assert!(
            isolated,
            "{namespace} namespace was not isolated: host={host}, worker={worker}"
        );
    }

    assert_eq!(cpu_max.trim(), "50000 100000");
    assert_eq!(memory_max.trim(), (512_u64 * 1024 * 1024).to_string());
    assert_eq!(pids_max.trim(), "64");

    Ok(())
}

fn wait_for_namespace_child(supervisor_pid: u32) -> Result<u32, Box<dyn Error>> {
    let children_path = format!("/proc/{supervisor_pid}/task/{supervisor_pid}/children");

    for _ in 0..200 {
        if let Ok(children) = fs::read_to_string(&children_path)
            && let Some(pid) = children.split_whitespace().next()
        {
            return Ok(pid.parse()?);
        }

        thread::sleep(Duration::from_millis(10));
    }

    Err(format!("namespace worker did not appear under supervisor PID {supervisor_pid}").into())
}

fn wait_for_empty_cgroup(path: &std::path::Path) -> Result<(), Box<dyn Error>> {
    for _ in 0..200 {
        let processes = fs::read_to_string(path.join("cgroup.procs"))?;

        if processes.trim().is_empty() {
            return Ok(());
        }

        thread::sleep(Duration::from_millis(10));
    }

    let remaining = fs::read_to_string(path.join("cgroup.procs"))?;
    Err(format!("cgroup still contains processes: {remaining}").into())
}
