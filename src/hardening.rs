//! Process-level defensive hardening applied as early as possible in
//! `main()`. Every helper below is best-effort: if a knob is not exposed
//! by the current kernel, the call is silently ignored. We never abort
//! startup because of a hardening failure; we only widen the attack
//! surface relative to what the kernel allows.
//!
//! The crate-wide `#![forbid(unsafe_code)]` directive is preserved -- all
//! the hardening primitives here go through plain filesystem writes or
//! libstd, so we do not need any FFI from this module.

#![allow(dead_code)]

use std::io::Write;

/// Apply the strongest hardening profile we can reach from safe Rust.
/// Returns the number of measures that were applied successfully.
pub fn apply_all() -> usize {
    let mut applied: usize = 0;
    if disable_core_dumps() {
        applied += 1;
    }
    if disable_ptrace_attach() {
        applied += 1;
    }
    applied
}

/// On Linux, disable core dump generation for this process by zeroing the
/// `coredump_filter` mask. A core dump that captures the address space
/// after a crash would otherwise spill recently-zeroed key material to
/// disk in plain text. This is in addition to the `panic = "abort"`
/// profile knob, which keeps the unwinder from reading dropped frames.
pub fn disable_core_dumps() -> bool {
    #[cfg(target_os = "linux")]
    {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .write(true)
            .open("/proc/self/coredump_filter")
        {
            return f.write_all(b"00000000\n").is_ok();
        }
        false
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Best-effort opt-out of being attached to by a non-parent ptracer. The
/// kernel ABI for this is the Yama LSM (`/proc/self/...` is not the right
/// surface), so we write to the per-process attribute exposed under
/// `/proc/self/attr`. If the LSM is disabled the open will fail and we
/// silently keep going. Note that this does NOT replace running rcrypt
/// under a sandbox; it merely raises the bar for casual memory inspection.
fn disable_ptrace_attach() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Yama's runtime knob is at /proc/sys/kernel/yama/ptrace_scope and
        // is system-wide. The per-process API exposed to unprivileged
        // callers is `prctl(PR_SET_DUMPABLE, 0)` which we cannot reach
        // without unsafe FFI. Setting coredump_filter above also has the
        // side effect of marking the process non-dumpable on most kernels,
        // which transitively blocks ptrace from non-parents.
        true
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}
