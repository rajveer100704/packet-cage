//! Linux sandboxing primitives.
//!
//! This module is Linux-only. It combines cgroup v2 resource controls,
//! gated process launch and timeout handling, namespace isolation, private
//! filesystem/rootfs setup, and seccomp filtering.

pub mod cgroup;

pub mod launcher;

pub mod namespaces;

pub mod filesystem;

pub mod rootfs;
pub mod seccomp;
