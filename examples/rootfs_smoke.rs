#[cfg(target_os = "linux")]
mod linux {
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use std::process::{Command, ExitCode};

    use anyhow::{Context, Result, bail, ensure};
    use packet_cage::sandbox::rootfs::{RootFs, RootFsConfig};

    fn run(executable: PathBuf, capture: PathBuf) -> Result<()> {
        let executable = executable.canonicalize()?;
        let capture = capture.canonicalize()?;

        let original_capture = fs::read(&capture)?;

        let config = RootFsConfig {
            root_size_bytes: 128 * 1024 * 1024,
            input_size_bytes: 8 * 1024 * 1024,
            tmp_size_bytes: 8 * 1024 * 1024,
            max_capture_bytes: 4 * 1024 * 1024,
        };

        println!("1. Building Rust-managed root filesystem...");

        let rootfs = RootFs::build(&executable, &capture, config)?;

        let root = rootfs.root_path().to_path_buf();
        let staged_capture = rootfs.capture_host_path().to_path_buf();

        println!("   Root: {}", root.display());
        println!("   Capture: {}", rootfs.capture_guest_path());

        println!("2. Verifying staged capture...");

        ensure!(
            fs::read(&staged_capture)? == original_capture,
            "staged capture differs from original"
        );

        if fs::write(&staged_capture, b"unauthorized modification").is_ok() {
            bail!("read-only capture accepted a write");
        }

        println!("   PASS: capture contents preserved and writes denied");

        println!("3. Verifying root filesystem permissions...");

        if fs::write(root.join("forbidden"), b"write").is_ok() {
            bail!("root filesystem accepted a write");
        }

        fs::write(root.join("tmp/write-test"), b"private temporary data")
            .context("private /tmp should be writable")?;

        println!("   PASS: root is read-only; private /tmp is writable");

        println!("4. Running PacketCage inside chroot...");

        let status = Command::new("/usr/sbin/chroot")
            .arg(&root)
            .arg(rootfs.executable_guest_path())
            .arg("--format")
            .arg("json")
            .arg("--output")
            .arg("/tmp/dns-report.json")
            .arg(rootfs.capture_guest_path())
            .status()
            .context("cannot launch PacketCage inside chroot")?;

        ensure!(status.success(), "PacketCage exited with status {status}");

        println!("5. Checking generated JSON report...");

        let report = fs::read(root.join("tmp/dns-report.json"))?;

        ensure!(!report.is_empty(), "generated report is empty");
        let parsed: serde_json::Value =
            serde_json::from_slice(&report).context("PacketCage output is not valid JSON")?;

        println!("   PASS: valid JSON report ({} bytes)", report.len());

        // Keep the parsed value alive until after the filesystem has been removed.
        drop(parsed);

        println!("6. Cleaning up root filesystem mounts...");

        rootfs.cleanup()?;

        ensure!(
            !root.exists(),
            "root filesystem directory still exists after cleanup"
        );

        println!("   PASS: root filesystem and mounts cleaned up");
        println!();
        println!("End-to-end rootfs execution test passed.");

        Ok(())
    }

    pub(super) fn linux_main() -> ExitCode {
        let mut args = env::args_os().skip(1);

        let executable = match args.next() {
            Some(path) => PathBuf::from(path),
            None => {
                eprintln!("Usage: rootfs_smoke EXECUTABLE CAPTURE");
                return ExitCode::FAILURE;
            }
        };

        let capture = match args.next() {
            Some(path) => PathBuf::from(path),
            None => {
                eprintln!("Usage: rootfs_smoke EXECUTABLE CAPTURE");
                return ExitCode::FAILURE;
            }
        };

        if args.next().is_some() {
            eprintln!("Too many arguments.");
            return ExitCode::FAILURE;
        }

        match run(executable, capture) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("Rootfs test failed: {error:#}");
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
    eprintln!("rootfs_smoke.rs is only available on Linux");
}
