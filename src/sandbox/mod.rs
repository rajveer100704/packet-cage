//! Linux sandboxing primitives.
//!
//! This module is Linux-only. It starts with cgroup v2 resource controls;
//! process and namespace isolation are added in later stages.

pub mod cgroup;

pub mod launcher;

pub mod namespaces;

pub mod filesystem;

pub mod rootfs;
pub mod seccomp;
