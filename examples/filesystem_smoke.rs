#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::path::Path;
    use std::process::ExitCode;

    use anyhow::{Context, Result, bail};
    use packet_cage::sandbox::filesystem::MountStack;

    fn exercise_mounts(root: &Path) -> Result<()> {
        let mut mounts = MountStack::new();

        // Create the private root filesystem.
        mounts.mount_tmpfs(root, 128 * 1024 * 1024, false)?;

        let input = root.join("input");
        let proc = root.join("proc");
        let tmp = root.join("tmp");

        fs::create_dir_all(&input)?;
        fs::create_dir_all(&proc)?;
        fs::create_dir_all(&tmp)?;

        // Input and temporary directories are separate mounts.
        mounts.mount_tmpfs(&input, 4 * 1024 * 1024, true)?;
        mounts.mount_proc(&proc)?;
        mounts.mount_tmpfs(&tmp, 16 * 1024 * 1024, true)?;

        let capture = input.join("sample.pcap");
        fs::write(&capture, b"PacketCage isolated input test")?;

        // Protect input and proc individually, then protect the root.
        mounts.make_read_only(&input)?;
        mounts.make_read_only(&proc)?;
        mounts.make_read_only(root)?;

        // Existing root files remain readable.
        let contents = fs::read(&capture)?;
        if contents != b"PacketCage isolated input test" {
            bail!("input content changed unexpectedly");
        }

        // Writes to root and input must fail.
        if fs::write(root.join("forbidden"), b"write").is_ok() {
            bail!("read-only root accepted a write");
        }

        if fs::write(input.join("forbidden"), b"write").is_ok() {
            bail!("read-only input accepted a write");
        }

        // Private /tmp must remain writable.
        fs::write(tmp.join("allowed"), b"temporary data")
            .context("private /tmp should be writable")?;

        if fs::read_to_string(proc.join("self/status")).is_err() {
            bail!("isolated procfs is not readable");
        }

        // Verify reverse-order detach.
        mounts.unmount_all()?;

        println!("PASS: private root tmpfs created");
        println!("PASS: input mount is read-only");
        println!("PASS: procfs is readable and read-only");
        println!("PASS: root mount rejects writes");
        println!("PASS: private /tmp accepts writes");
        println!("PASS: mounts detached in reverse order");

        Ok(())
    }

    pub(super) fn linux_main() -> ExitCode {
        let root =
            std::env::temp_dir().join(format!("packet-cage-fs-smoke-{}", std::process::id()));

        if let Err(error) = fs::create_dir(&root) {
            eprintln!("Cannot create test directory: {error}");
            return ExitCode::FAILURE;
        }

        let result = exercise_mounts(&root);
        let cleanup = fs::remove_dir(&root)
            .with_context(|| format!("cannot remove test directory {}", root.display()));

        match (result, cleanup) {
            (Ok(()), Ok(())) => {
                println!("Filesystem runtime smoke test passed.");
                ExitCode::SUCCESS
            }
            (Err(error), _) => {
                eprintln!("Filesystem test failed: {error:#}");
                ExitCode::FAILURE
            }
            (_, Err(error)) => {
                eprintln!("Filesystem cleanup failed: {error:#}");
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
    eprintln!("filesystem_smoke.rs is only available on Linux");
}
