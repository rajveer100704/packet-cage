# Upstream attribution

This repository is a modified derivative of **PCAPDoctor**, originally
developed by Anish Mehta.

- Original project: https://github.com/anishmehta24/pcapdoctor
- Original author: Anish Mehta
- Upstream license: MIT OR Apache-2.0

The original `LICENSE-MIT` and `LICENSE-APACHE` files are retained unchanged.
Existing PCAPDoctor source and documentation remain subject to the applicable
upstream license terms and notices.

## Changes in this repository

This repository adds an experimental Linux sandbox execution path around the
PCAPDoctor analyzer, including:

- cgroup v2 resource management and worker cleanup;
- Linux namespace-based process isolation;
- a private temporary root filesystem and staged capture input;
- a seccomp syscall filter;
- the `packet-cage sandbox run` CLI command;
- sandbox-specific tests and documentation.

This is an independent derivative, not the official upstream PCAPDoctor
repository or an upstream-maintained release. The sandbox addition has its
own implementation and integration work; it does not make the inherited
PCAPDoctor code newly authored.
