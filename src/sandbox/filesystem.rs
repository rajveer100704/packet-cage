//! Linux filesystem isolation primitives.
//!
//! These operations require a suitable mount namespace and the necessary
//! capabilities within it. They do not modify the host mount namespace.

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

const MOUNT_ATTR_RDONLY: u64 = 0x00000001;

/// Tracks mounts created by a sandbox filesystem setup.
///
/// Mounts are detached in reverse order when this value is dropped.
#[derive(Debug, Default)]
pub struct MountStack {
    mounted: Vec<PathBuf>,
}

impl MountStack {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mounts a private tmpfs at an existing directory.
    ///
    /// Every tmpfs is `nosuid,nodev`. `noexec` is useful for writable
    /// directories and input staging, but must be disabled for the root
    /// filesystem containing the application executable.
    pub fn mount_tmpfs(
        &mut self,
        target: impl AsRef<Path>,
        size_bytes: u64,
        noexec: bool,
    ) -> Result<()> {
        if size_bytes == 0 {
            bail!("tmpfs size must be greater than zero");
        }

        let target_path = canonical_mountpoint(target.as_ref())?;
        let target = CString::new(target_path.as_os_str().as_bytes())?;
        let source = CString::new("tmpfs")?;
        let filesystem = CString::new("tmpfs")?;
        let options = CString::new(format!("size={size_bytes}"))?;

        let mut flags = libc::MS_NOSUID | libc::MS_NODEV;
        if noexec {
            flags |= libc::MS_NOEXEC;
        }

        // SAFETY: All C strings are NUL-terminated and remain alive for the
        // duration of the mount syscall. The target is an existing directory.
        let result = unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                filesystem.as_ptr(),
                flags,
                options.as_ptr().cast(),
            )
        };

        if result != 0 {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("cannot mount tmpfs at {}", target_path.display()));
        }

        self.mounted.push(target_path);
        Ok(())
    }

    /// Mounts a proc filesystem for the current PID namespace.
    pub fn mount_proc(&mut self, target: impl AsRef<Path>) -> Result<()> {
        let target_path = canonical_mountpoint(target.as_ref())?;
        let target = CString::new(target_path.as_os_str().as_bytes())?;
        let source = CString::new("proc")?;
        let filesystem = CString::new("proc")?;

        let flags = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;

        // SAFETY: The C strings remain alive during the syscall; target is
        // an existing directory in the caller's private mount namespace.
        let result = unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                filesystem.as_ptr(),
                flags,
                std::ptr::null(),
            )
        };

        if result != 0 {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("cannot mount proc at {}", target_path.display()));
        }

        self.mounted.push(target_path);
        Ok(())
    }

    /// Marks one mount read-only without changing nested mounts.
    ///
    /// This uses mount_setattr rather than the legacy remount operation,
    /// which was rejected by the tested WSL environment.
    pub fn make_read_only(&self, target: impl AsRef<Path>) -> Result<()> {
        let target = target
            .as_ref()
            .canonicalize()
            .with_context(|| format!("cannot resolve mount {}", target.as_ref().display()))?;

        let path = CString::new(target.as_os_str().as_bytes())?;

        #[repr(C)]
        struct MountAttr {
            attr_set: u64,
            attr_clr: u64,
            propagation: u64,
            userns_fd: u64,
        }

        let attr = MountAttr {
            attr_set: MOUNT_ATTR_RDONLY,
            attr_clr: 0,
            propagation: 0,
            userns_fd: 0,
        };

        // SAFETY: `path` is NUL-terminated, `attr` has the kernel ABI layout,
        // and the pointer and size match the mount_setattr syscall contract.
        let result = unsafe {
            libc::syscall(
                libc::SYS_mount_setattr,
                libc::AT_FDCWD,
                path.as_ptr(),
                0u32,
                &attr as *const MountAttr,
                std::mem::size_of::<MountAttr>(),
            )
        };

        if result != 0 {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("cannot make mount {} read-only", target.display()));
        }

        Ok(())
    }

    /// Detaches tracked mounts in reverse creation order.
    pub fn unmount_all(&mut self) -> Result<()> {
        let mut failures = Vec::new();
        let mut still_mounted = Vec::new();

        while let Some(path) = self.mounted.pop() {
            let path_c = CString::new(path.as_os_str().as_bytes())?;

            // SAFETY: The path is a valid NUL-terminated mountpoint string.
            let result = unsafe { libc::umount2(path_c.as_ptr(), libc::MNT_DETACH) };

            if result != 0 {
                let error = io::Error::last_os_error();
                failures.push(format!("{}: {}", path.display(), error));
                still_mounted.push(path);
            }
        }

        // Preserve creation order so the next cleanup attempt also unmounts
        // children before their parents.
        still_mounted.reverse();
        self.mounted = still_mounted;

        if !failures.is_empty() {
            bail!("failed to detach mounts: {}", failures.join("; "));
        }

        Ok(())
    }
}

impl Drop for MountStack {
    fn drop(&mut self) {
        let _ = self.unmount_all();
    }
}

fn canonical_mountpoint(path: &Path) -> Result<PathBuf> {
    let resolved = path
        .canonicalize()
        .with_context(|| format!("cannot resolve mountpoint {}", path.display()))?;

    if !resolved.is_dir() {
        bail!("mountpoint {} is not a directory", resolved.display());
    }

    Ok(resolved)
}
