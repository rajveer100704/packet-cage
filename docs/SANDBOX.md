# Linux sandbox setup

## Requirements

- Linux with cgroup v2 enabled.
- Delegated cpu, memory and pids controllers.
- util-linux unshare and mount namespace support.
- libseccomp development library.
- Permission to create and manage child cgroups.

## Create a delegated cgroup scope

Start a delegated interactive shell:

```bash
systemd-run --user --scope --property=Delegate=yes bash -i
```

In the new shell, configure the delegated hierarchy:

```bash
CGROUP_REL=$(awk -F: '$1 == "0" {print $3}' /proc/self/cgroup)
SCOPE_ROOT="/sys/fs/cgroup${CGROUP_REL}"
MANAGER="$SCOPE_ROOT/manager"
mkdir "$MANAGER"
printf "%s" "$$" > "$MANAGER/cgroup.procs"
printf "+cpu +memory +pids" > "$SCOPE_ROOT/cgroup.subtree_control"
SESSION="$MANAGER/session"
mkdir "$SESSION"
printf "%s" "$$" > "$SESSION/cgroup.procs"
printf "+cpu +memory +pids" > "$MANAGER/cgroup.subtree_control"
cat "$MANAGER/cgroup.controllers"
cat "$MANAGER/cgroup.subtree_control"
```

Both controller outputs should include cpu, memory and pids. Keep this shell open while running sandbox commands.

## Run a capture

Build the binary:

```bash
cargo build --release
```

Run an analysis from the delegated shell:

```bash
./target/release/packet-cage sandbox run \
  --cgroup-root "$MANAGER" \
  --timeout 10s \
  --memory 512MiB \
  --cpu-quota 50000 \
  --pids 64 \
  --format json \
  tests/fixtures/dns-zoo.pcap
```

## Resource limits

| Option | Default | Meaning |
|---|---:|---|
| `--timeout` | `10s` | Wall-clock execution timeout |
| `--memory` | `512MiB` | Maximum worker memory |
| `--cpu-quota` | `50000` | CPU quota in microseconds per 100,000-microsecond period |
| `--pids` | `64` | Maximum number of processes in the workload |
| `--format` | `json` | Report format: `text`, `json` or `html` |

The default maximum staged capture size is 64 MiB. The root filesystem, input filesystem and temporary filesystem have separate size limits.

## Isolation model and limitations

- User, mount, PID, network, IPC and UTS namespaces isolate the worker from the host namespaces.
- The capture is staged into a private input filesystem and exposed read-only to the analysis process.
- The worker is constrained by cgroup v2 CPU, memory and process-count controls.
- A seccomp default-deny filter restricts analysis-process syscalls.
- Timeout cleanup kills the workload cgroup, including descendants.

This implementation is experimental. Runtime testing so far has been performed in WSL2; native Linux validation is still needed. The seccomp allowlist, namespace setup, mount handling and cleanup paths require independent security review. This is defense in depth, not a complete security boundary against kernel vulnerabilities, privileged host processes or container-runtime escapes.

Do not treat this as a hardened multi-tenant sandbox until it has received a dedicated security review.


## Runtime dependency for Linux binaries

The Linux executable dynamically links to libseccomp.so.2. On Debian or Ubuntu, install the runtime package before running a prebuilt binary:

```bash
sudo apt-get install -y libseccomp2
```
