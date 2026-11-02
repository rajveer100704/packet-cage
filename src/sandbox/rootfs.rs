//! Minimal Linux root filesystem for isolated PacketCage execution.
//!
//! This builder is intended for a trusted PacketCage executable. It discovers
//! its dynamic dependencies with `ldd`, copies them into private tmpfs storage,
//! and stages an untrusted capture as a read-only input mount.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail, ensure};

use super::filesystem::MountStack;

const LDD_CANDIDATES: [&str; 2] = ["/usr/bin/ldd", "/bin/ldd"];

static NEXT_ROOT_ID: AtomicU64 = AtomicU64::new(1);

const EXECUTABLE_IN_ROOT: &str = "/packet-cage";
const CAPTURE_IN_ROOT: &str = "/input/capture.pcap";

/// Storage limits for a sandbox root filesystem.
#[derive(Debug, Clone)]
pub struct RootFsConfig {
    pub root_size_bytes: u64,
    pub input_size_bytes: u64,
    pub tmp_size_bytes: u64,
    pub max_capture_bytes: u64,
}

impl Default for RootFsConfig {
    fn default() -> Self {
        Self {
            root_size_bytes: 128 * 1024 * 1024,
            input_size_bytes: 64 * 1024 * 1024,
            tmp_size_bytes: 16 * 1024 * 1024,
            max_capture_bytes: 64 * 1024 * 1024,
        }
    }
}

impl RootFsConfig {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.root_size_bytes > 0,
            "root filesystem size must be positive"
        );
        ensure!(
            self.input_size_bytes > 0,
            "input filesystem size must be positive"
        );
        ensure!(
            self.tmp_size_bytes > 0,
            "temporary filesystem size must be positive"
        );
        ensure!(
            self.max_capture_bytes > 0,
            "maximum capture size must be positive"
        );
        ensure!(
            self.max_capture_bytes <= self.input_size_bytes,
            "maximum capture size cannot exceed input filesystem size"
        );
        Ok(())
    }
}

/// Host-owned directory reserved for one sandbox root filesystem.
///
/// The parent creates this before launching the worker. Its Drop implementation
/// removes the directory after the worker exits, including after SIGKILL.
#[derive(Debug)]
pub struct RootFsWorkspace {
    path: PathBuf,
}

impl RootFsWorkspace {
    /// Creates a unique, private workspace directory.
    pub fn create() -> Result<Self> {
        Ok(Self {
            path: create_root_directory()?,
        })
    }

    /// Returns the absolute host-visible workspace path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Explicitly removes the workspace. A worker may already have removed
    /// it after normal rootfs cleanup, which is treated as success.
    pub fn cleanup(mut self) -> Result<()> {
        if !self.path.as_os_str().is_empty() {
            match fs::remove_dir(&self.path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("cannot remove rootfs workspace {}", self.path.display())
                    });
                }
            }

            self.path.clear();
        }

        Ok(())
    }
}

impl Drop for RootFsWorkspace {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let _ = fs::remove_dir(&self.path);
        }
    }
}

/// A constructed minimal filesystem.
///
/// The root, input and proc mounts are read-only. The separate `/tmp` mount
/// remains writable. Mounts are detached when this object is dropped.
#[derive(Debug)]
pub struct RootFs {
    root: PathBuf,
    capture: PathBuf,
    mounts: MountStack,
}

impl RootFs {
    /// Builds a minimal filesystem for the trusted PacketCage executable and
    /// one untrusted capture file.
    ///
    /// This function must run inside the sandbox's private mount namespace.
    pub fn build(
        executable: impl AsRef<Path>,
        capture: impl AsRef<Path>,
        config: RootFsConfig,
    ) -> Result<Self> {
        let workspace = create_root_directory()?;
        let result = Self::build_at(executable, capture, config, &workspace);

        if result.is_err() {
            let _ = fs::remove_dir(&workspace);
        }

        result
    }

    /// Builds a root filesystem inside an existing, empty workspace directory.
    ///
    /// This is intended for a worker whose parent owns the workspace lifecycle.
    /// The parent can remove the underlying directory after the worker exits,
    /// even if the worker is terminated without running Rust destructors.
    pub fn build_at(
        executable: impl AsRef<Path>,
        capture: impl AsRef<Path>,
        config: RootFsConfig,
        workspace: impl AsRef<Path>,
    ) -> Result<Self> {
        config.validate()?;

        let executable = executable.as_ref().canonicalize().with_context(|| {
            format!(
                "cannot resolve PacketCage executable {}",
                executable.as_ref().display()
            )
        })?;

        ensure!(
            executable.is_file(),
            "PacketCage executable is not a regular file"
        );

        let workspace_metadata = fs::symlink_metadata(workspace.as_ref()).with_context(|| {
            format!(
                "cannot inspect rootfs workspace {}",
                workspace.as_ref().display()
            )
        })?;

        ensure!(
            workspace_metadata.is_dir() && !workspace_metadata.file_type().is_symlink(),
            "rootfs workspace must be a real directory"
        );

        let root = workspace.as_ref().canonicalize().with_context(|| {
            format!(
                "cannot resolve rootfs workspace {}",
                workspace.as_ref().display()
            )
        })?;

        ensure!(
            fs::read_dir(&root)?.next().is_none(),
            "rootfs workspace must be empty"
        );

        let capture_path = root.join("input/capture.pcap");

        let mut filesystem = Self {
            root: root.clone(),
            capture: capture_path.clone(),
            mounts: MountStack::new(),
        };

        // Mount the private root first.
        filesystem
            .mounts
            .mount_tmpfs(&root, config.root_size_bytes, false)?;

        let input_dir = root.join("input");
        let proc_dir = root.join("proc");
        let tmp_dir = root.join("tmp");

        fs::create_dir_all(&input_dir)?;
        fs::create_dir_all(&proc_dir)?;
        fs::create_dir_all(&tmp_dir)?;

        // These nested mounts remain independent when the root is made
        // read-only.
        filesystem
            .mounts
            .mount_tmpfs(&input_dir, config.input_size_bytes, true)?;

        filesystem.mounts.mount_proc(&proc_dir)?;

        filesystem
            .mounts
            .mount_tmpfs(&tmp_dir, config.tmp_size_bytes, true)?;

        // Stage the executable and its runtime libraries.
        copy_executable(&executable, &root.join("packet-cage"))?;

        let dependencies = discover_runtime_dependencies(&executable)?;
        for dependency in dependencies {
            copy_runtime_file(&dependency, &root)?;
        }

        // Stage the untrusted capture only after the input tmpfs is mounted.
        stage_capture(capture.as_ref(), &capture_path, config.max_capture_bytes)?;

        // Apply read-only attributes to each protected mount.
        filesystem.mounts.make_read_only(&input_dir)?;
        filesystem.mounts.make_read_only(&proc_dir)?;
        filesystem.mounts.make_read_only(&root)?;

        Ok(filesystem)
    }

    /// Host-side path of the private root mount.
    pub fn root_path(&self) -> &Path {
        &self.root
    }

    /// Host-side path of the staged capture file.
    pub fn capture_host_path(&self) -> &Path {
        &self.capture
    }

    /// Path to the capture as seen after chroot.
    pub fn capture_guest_path(&self) -> &'static str {
        CAPTURE_IN_ROOT
    }

    /// Path to the executable as seen after chroot.
    pub fn executable_guest_path(&self) -> &'static str {
        EXECUTABLE_IN_ROOT
    }

    /// Explicitly detaches all mounts and removes the underlying directory.
    pub fn cleanup(mut self) -> Result<()> {
        self.mounts
            .unmount_all()
            .context("cannot detach root filesystem mounts")?;

        fs::remove_dir(&self.root)
            .with_context(|| format!("cannot remove root directory {}", self.root.display()))?;

        // Prevent Drop from attempting a second directory removal.
        self.root.clear();
        Ok(())
    }
}

impl Drop for RootFs {
    fn drop(&mut self) {
        let _ = self.mounts.unmount_all();

        if !self.root.as_os_str().is_empty() {
            let _ = fs::remove_dir(&self.root);
        }
    }
}

fn create_root_directory() -> Result<PathBuf> {
    let temp = std::env::temp_dir();

    for _ in 0..32 {
        let id = NEXT_ROOT_ID.fetch_add(1, Ordering::Relaxed);
        let path = temp.join(format!("packet-cage-rootfs-{}-{id}", std::process::id()));

        match fs::create_dir(&path) {
            Ok(()) => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .with_context(|| format!("cannot restrict {}", path.display()))?;

                return path
                    .canonicalize()
                    .with_context(|| format!("cannot resolve {}", path.display()));
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("cannot create {}", path.display()));
            }
        }
    }

    bail!("could not allocate a unique root filesystem directory")
}

fn find_ldd() -> Result<&'static str> {
    LDD_CANDIDATES
        .iter()
        .copied()
        .find(|path| Path::new(path).is_file())
        .ok_or_else(|| anyhow::anyhow!("cannot find ldd"))
}

fn discover_runtime_dependencies(executable: &Path) -> Result<Vec<PathBuf>> {
    let output = Command::new(find_ldd()?)
        .arg(executable)
        .output()
        .context("cannot execute ldd for the trusted PacketCage binary")?;

    if !output.status.success() {
        bail!(
            "ldd failed for {}: {}",
            executable.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let stdout = String::from_utf8(output.stdout).context("ldd returned non-UTF-8 output")?;

    let mut dependencies = BTreeSet::new();

    for line in stdout.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with("linux-vdso") {
            continue;
        }

        if line.contains("not found") {
            bail!("unresolved runtime dependency: {line}");
        }

        let candidate = if let Some((_, right)) = line.split_once("=>") {
            right.split_whitespace().next().unwrap_or("")
        } else {
            line.split_whitespace().next().unwrap_or("")
        };

        if candidate.starts_with('/') {
            let path = PathBuf::from(candidate);

            ensure!(
                path.is_file(),
                "runtime dependency is not a regular file: {}",
                path.display()
            );

            dependencies.insert(path);
        }
    }

    Ok(dependencies.into_iter().collect())
}

fn copy_executable(source: &Path, destination: &Path) -> Result<()> {
    fs::copy(source, destination).with_context(|| {
        format!(
            "cannot stage executable {} at {}",
            source.display(),
            destination.display()
        )
    })?;

    fs::set_permissions(destination, fs::Permissions::from_mode(0o555))?;
    Ok(())
}

fn copy_runtime_file(source: &Path, root: &Path) -> Result<()> {
    let relative = source
        .strip_prefix("/")
        .context("runtime dependency must have an absolute path")?;

    let destination = root.join(relative);

    let metadata = fs::metadata(source)
        .with_context(|| format!("cannot inspect runtime dependency {}", source.display()))?;

    ensure!(
        metadata.is_file(),
        "runtime dependency is not a regular file: {}",
        source.display()
    );

    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::copy(source, &destination)
        .with_context(|| format!("cannot copy runtime dependency {}", source.display()))?;

    fs::set_permissions(&destination, fs::Permissions::from_mode(0o555))?;
    Ok(())
}

/// Copies at most `max_bytes + 1` bytes.
///
/// Reading one additional byte makes it possible to detect an input that
/// grows after its initial metadata check without copying the entire file.
fn copy_bounded(input: &mut impl Read, output: &mut impl Write, max_bytes: u64) -> Result<u64> {
    let read_limit = max_bytes
        .checked_add(1)
        .context("maximum capture size is too large")?;

    io::copy(&mut input.take(read_limit), output)
        .context("cannot copy capture into private input filesystem")
}

fn stage_capture(source: &Path, destination: &Path, max_bytes: u64) -> Result<()> {
    let metadata = fs::symlink_metadata(source)
        .with_context(|| format!("cannot inspect capture {}", source.display()))?;

    ensure!(
        !metadata.file_type().is_symlink(),
        "capture path must not be a symbolic link"
    );

    ensure!(
        metadata.is_file(),
        "capture must be a regular file: {}",
        source.display()
    );

    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(source)
        .with_context(|| format!("cannot open capture {}", source.display()))?;

    let input_metadata = input.metadata()?;

    ensure!(input_metadata.is_file(), "capture is not a regular file");
    ensure!(
        input_metadata.len() <= max_bytes,
        "capture size {} exceeds configured maximum {}",
        input_metadata.len(),
        max_bytes
    );

    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)
        .with_context(|| format!("cannot create staged capture {}", destination.display()))?;

    let copied = copy_bounded(&mut input, &mut output, max_bytes)?;

    ensure!(
        copied <= max_bytes,
        "capture grew beyond the configured size limit while copying"
    );

    output.sync_all()?;
    output.set_permissions(fs::Permissions::from_mode(0o444))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_is_removed_when_parent_guard_drops() {
        let workspace = RootFsWorkspace::create().unwrap();
        let path = workspace.path().to_path_buf();

        assert!(path.is_dir());

        drop(workspace);

        assert!(!path.exists());
    }

    #[test]
    fn bounded_copy_reads_only_one_byte_over_limit() {
        let source = b"abcdefgh";
        let mut input = source.as_slice();
        let mut output = Vec::new();

        let copied = copy_bounded(&mut input, &mut output, 4).unwrap();

        assert_eq!(copied, 5);
        assert_eq!(output, b"abcde");
    }

    #[test]
    fn default_rootfs_limits_are_consistent() {
        let config = RootFsConfig::default();
        assert!(config.validate().is_ok());
        assert!(config.max_capture_bytes <= config.input_size_bytes);
    }

    #[test]
    fn rejects_zero_sizes() {
        let config = RootFsConfig {
            root_size_bytes: 0,
            ..RootFsConfig::default()
        };
        assert!(config.validate().is_err());

        let config = RootFsConfig {
            input_size_bytes: 0,
            ..RootFsConfig::default()
        };
        assert!(config.validate().is_err());

        let config = RootFsConfig {
            tmp_size_bytes: 0,
            ..RootFsConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_capture_limit_larger_than_input_mount() {
        let mut config = RootFsConfig::default();
        config.max_capture_bytes = config.input_size_bytes + 1;
        assert!(config.validate().is_err());
    }
}
