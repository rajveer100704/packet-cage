//! Resource controls for a delegated cgroup v2 hierarchy.
//!
//! The caller must provide an explicitly delegated cgroup directory whose
//! available controllers include `cpu`, `memory`, and `pids`. This module
//! deliberately does not discover or modify a system-wide cgroup root.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

const REQUIRED_CONTROLLERS: [&str; 3] = ["cpu", "memory", "pids"];

/// Hard limits applied to one sandbox workload.
///
/// CPU quota and period are measured in microseconds, as required by
/// cgroup v2's `cpu.max` interface. Memory is measured in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceLimits {
    pub cpu_quota_micros: Option<u64>,
    pub cpu_period_micros: u64,
    pub memory_max_bytes: u64,
    pub pids_max: u64,
}

impl ResourceLimits {
    pub fn validate(&self) -> Result<()> {
        if self.cpu_period_micros == 0 {
            bail!("CPU period must be greater than zero");
        }
        if self.cpu_quota_micros == Some(0) {
            bail!("CPU quota must be greater than zero");
        }
        if self.memory_max_bytes == 0 {
            bail!("memory maximum must be greater than zero");
        }
        if self.pids_max == 0 {
            bail!("pids maximum must be greater than zero");
        }
        Ok(())
    }

    fn cpu_max_value(&self) -> Option<String> {
        self.cpu_quota_micros
            .map(|quota| format!("{quota} {}", self.cpu_period_micros))
    }
}

/// Manager for a dedicated child hierarchy beneath a delegated cgroup v2
/// directory.
///
/// The manager directory itself must contain no processes. Workloads are
/// created as child cgroups beneath it, leaving the caller free to run the
/// manager process in a separate sibling cgroup.
#[derive(Debug)]
pub struct CgroupManager {
    base: PathBuf,
}

impl CgroupManager {
    /// Creates or opens `base_name` beneath an explicitly delegated cgroup.
    ///
    /// `root` must be the delegated directory, not `/sys/fs/cgroup` unless
    /// that exact directory has been delegated to the caller.
    pub fn new(root: impl AsRef<Path>, base_name: &str) -> Result<Self> {
        validate_name(base_name)?;

        let root = fs::canonicalize(root.as_ref())
            .with_context(|| format!("cannot resolve cgroup root {}", root.as_ref().display()))?;

        if !root.join("cgroup.controllers").exists()
            || !root.join("cgroup.subtree_control").exists()
        {
            bail!(
                "{} does not look like a cgroup v2 directory",
                root.display()
            );
        }

        let base = root.join(base_name);
        let created = match fs::create_dir(&base) {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let metadata = fs::symlink_metadata(&base)
                    .with_context(|| format!("cannot inspect {}", base.display()))?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    bail!("{} exists but is not a real directory", base.display());
                }
                false
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("cannot create cgroup directory {}", base.display()));
            }
        };

        let setup = (|| -> Result<()> {
            let available = read_words(&base.join("cgroup.controllers"))?;
            let missing: Vec<_> = REQUIRED_CONTROLLERS
                .iter()
                .copied()
                .filter(|controller| !available.iter().any(|word| word == controller))
                .collect();

            if !missing.is_empty() {
                bail!(
                    "required controllers are not delegated to {}: {}",
                    base.display(),
                    missing.join(", ")
                );
            }

            let procs = fs::read_to_string(base.join("cgroup.procs"))
                .with_context(|| format!("cannot read {}/cgroup.procs", base.display()))?;
            if !procs.trim().is_empty() {
                bail!(
                    "{} contains processes; refusing to enable child controllers",
                    base.display()
                );
            }

            let enabled = read_words(&base.join("cgroup.subtree_control"))?;
            let to_enable: Vec<_> = REQUIRED_CONTROLLERS
                .iter()
                .copied()
                .filter(|controller| !enabled.iter().any(|word| word == controller))
                .map(|controller| format!("+{controller}"))
                .collect();

            if !to_enable.is_empty() {
                write_control(&base.join("cgroup.subtree_control"), &to_enable.join(" "))
                    .with_context(|| {
                        format!("cannot enable child controllers beneath {}", base.display())
                    })?;
            }

            Ok(())
        })();

        if let Err(error) = setup {
            if created {
                let _ = fs::remove_dir(&base);
            }
            return Err(error).with_context(|| {
                format!("failed to initialize cgroup directory {}", base.display())
            });
        }

        Ok(Self { base })
    }

    /// Returns the dedicated parent directory for workload cgroups.
    pub fn base_path(&self) -> &Path {
        &self.base
    }

    /// Creates and configures one leaf cgroup for a workload.
    pub fn create_job(&self, name: &str, limits: ResourceLimits) -> Result<JobCgroup> {
        validate_name(name)?;
        limits.validate()?;

        let path = self.base.join(name);
        fs::create_dir(&path)
            .with_context(|| format!("cannot create workload cgroup {}", path.display()))?;

        let configured = (|| -> Result<()> {
            if let Some(cpu_max) = limits.cpu_max_value() {
                write_control(&path.join("cpu.max"), &cpu_max)
                    .context("cannot configure CPU quota")?;
            }

            write_control(
                &path.join("memory.max"),
                &limits.memory_max_bytes.to_string(),
            )
            .context("cannot configure memory maximum")?;

            write_control(&path.join("pids.max"), &limits.pids_max.to_string())
                .context("cannot configure process-count maximum")?;

            Ok(())
        })();

        if let Err(error) = configured {
            // The cgroup is still empty because no PID has been attached yet.
            let _ = fs::remove_dir(&path);
            return Err(error).with_context(|| {
                format!("failed to configure workload cgroup {}", path.display())
            });
        }

        Ok(JobCgroup { path })
    }
}

/// A configured leaf cgroup for one workload.
#[derive(Debug)]
pub struct JobCgroup {
    path: PathBuf,
}

impl JobCgroup {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Moves a process into this cgroup. The process must already exist.
    pub fn attach_pid(&self, pid: u32) -> Result<()> {
        if pid == 0 {
            bail!("PID must be greater than zero");
        }

        write_control(&self.path.join("cgroup.procs"), &pid.to_string())
            .with_context(|| format!("cannot attach PID {pid} to {}", self.path.display()))
    }

    /// Requests termination of every process in this cgroup and its descendants.
    ///
    /// This uses the cgroup v2 `cgroup.kill` control file. It is preferable to
    /// killing only the supervisor PID because workloads can create descendants.
    pub fn kill_all(&self) -> Result<()> {
        let mut control = OpenOptions::new()
            .write(true)
            .open(self.path.join("cgroup.kill"))
            .with_context(|| {
                format!(
                    "cannot open cgroup.kill for workload {}",
                    self.path.display()
                )
            })?;

        control
            .write_all(b"1")
            .with_context(|| format!("cannot terminate workload in {}", self.path.display()))
    }

    /// Waits until the cgroup and all descendant cgroups have no processes.
    ///
    /// The cgroup v2 `cgroup.events` populated field accounts for descendants,
    /// unlike checking only the immediate `cgroup.procs` file.
    pub fn wait_for_empty(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .context("cgroup wait timeout is too large")?;

        loop {
            let events = fs::read_to_string(self.path.join("cgroup.events"))
                .with_context(|| format!("cannot inspect {}", self.path.display()))?;

            let populated = events.lines().find_map(|line| {
                let mut parts = line.split_whitespace();
                if parts.next() == Some("populated") {
                    parts.next()?.parse::<u8>().ok()
                } else {
                    None
                }
            });

            match populated {
                Some(0) => return Ok(()),
                Some(1) => {}
                Some(value) => bail!(
                    "unexpected populated value {value} in {}/cgroup.events",
                    self.path.display()
                ),
                None => bail!(
                    "missing or invalid populated field in {}/cgroup.events",
                    self.path.display()
                ),
            }

            let now = Instant::now();
            if now >= deadline {
                let processes = fs::read_to_string(self.path.join("cgroup.procs"))
                    .unwrap_or_else(|error| format!("<unavailable: {error}>"));

                bail!(
                    "workload cgroup {} did not become empty within {:?}; cgroup.procs: {}",
                    self.path.display(),
                    timeout,
                    processes.trim()
                );
            }

            thread::sleep(Duration::from_millis(10).min(deadline.saturating_duration_since(now)));
        }
    }

    /// Removes this cgroup. It must contain no processes or populated descendants.
    pub fn remove(self) -> Result<()> {
        self.wait_for_empty(Duration::ZERO)?;

        fs::remove_dir(&self.path)
            .with_context(|| format!("cannot remove cgroup {}", self.path.display()))
    }
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        bail!("invalid cgroup name {name:?}; use only ASCII letters, digits, '-' and '_'");
    }
    Ok(())
}

fn read_words(path: &Path) -> Result<Vec<String>> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("cannot read cgroup control file {}", path.display()))?;
    Ok(contents.split_whitespace().map(str::to_owned).collect())
}

fn write_control(path: &Path, value: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .with_context(|| format!("cannot open cgroup control file {}", path.display()))?;

    file.write_all(value.as_bytes())
        .with_context(|| format!("cannot write cgroup control file {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_limits() -> ResourceLimits {
        ResourceLimits {
            cpu_quota_micros: Some(50_000),
            cpu_period_micros: 100_000,
            memory_max_bytes: 512 * 1024 * 1024,
            pids_max: 64,
        }
    }

    #[test]
    fn formats_cpu_quota_for_cgroup_v2() {
        assert_eq!(
            valid_limits().cpu_max_value().as_deref(),
            Some("50000 100000")
        );
    }

    #[test]
    fn omits_cpu_quota_when_unlimited() {
        let mut limits = valid_limits();
        limits.cpu_quota_micros = None;
        assert_eq!(limits.cpu_max_value(), None);
        assert!(limits.validate().is_ok());
    }

    #[test]
    fn rejects_zero_resource_limits() {
        let mut limits = valid_limits();
        limits.cpu_quota_micros = Some(0);
        assert!(limits.validate().is_err());

        let mut limits = valid_limits();
        limits.cpu_period_micros = 0;
        assert!(limits.validate().is_err());

        let mut limits = valid_limits();
        limits.memory_max_bytes = 0;
        assert!(limits.validate().is_err());

        let mut limits = valid_limits();
        limits.pids_max = 0;
        assert!(limits.validate().is_err());
    }

    #[test]
    fn accepts_safe_cgroup_names() {
        assert!(validate_name("job-123").is_ok());
        assert!(validate_name("packet-cage_worker_1").is_ok());
    }

    #[test]
    fn rejects_unsafe_cgroup_names() {
        for name in ["", ".", "..", "../escape", "job/name", "job name", "job;rm"] {
            assert!(validate_name(name).is_err(), "accepted {name:?}");
        }
    }
}
