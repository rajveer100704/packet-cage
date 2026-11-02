#[cfg(target_os = "linux")]
mod linux {
    use anyhow::{Context, ensure};

    pub(super) fn linux_main() -> anyhow::Result<()> {
        println!("1. Installing seccomp analysis filter...");

        packet_cage::sandbox::seccomp::install_analysis_filter()
            .context("installing analysis filter")?;

        println!("2. Testing an allowed syscall...");

        let mut byte = 0_u8;
        let random_result =
            unsafe { libc::syscall(libc::SYS_getrandom, &mut byte as *mut u8, 1_usize, 0_u32) };

        ensure!(random_result == 1, "getrandom was not allowed");

        println!("3. Testing a prohibited syscall...");

        // getpid normally succeeds for an unprivileged Linux process,
        // but is deliberately absent from our seccomp allowlist.
        let pid_result = unsafe { libc::syscall(libc::SYS_getpid) };

        ensure!(pid_result == -1, "getpid unexpectedly succeeded");

        let error = std::io::Error::last_os_error();

        ensure!(
            error.raw_os_error() == Some(libc::EPERM),
            "getpid returned an unexpected error: {error}"
        );

        println!("PASS: getrandom allowed");
        println!("PASS: getpid denied with EPERM");
        println!("Seccomp smoke test passed.");

        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    linux::linux_main()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("seccomp_smoke.rs is only available on Linux");
}
