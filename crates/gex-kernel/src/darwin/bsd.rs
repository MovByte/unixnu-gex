//! BSD system calls, renumbered onto the canonical (Linux) ones.
//!
//! Numbers are XNU's `bsd/kern/syscalls.master`. A call whose arguments
//! mean the same thing on both sides is only renumbered; one whose flags or
//! structures differ is rewritten here before it runs. Anything else is
//! [`crate::x86::UNKNOWN`], which the dispatch answers with ENOSYS and
//! records as unimplemented.

use crate::syscalls::nr;
use crate::x86::UNKNOWN;

pub mod sys {
    pub const EXIT: u64 = 1;
    pub const READ: u64 = 3;
    pub const WRITE: u64 = 4;
    pub const CLOSE: u64 = 6;
    pub const GETPID: u64 = 20;
    pub const GETUID: u64 = 24;
    pub const GETEUID: u64 = 25;
    pub const GETPPID: u64 = 39;
    pub const GETEGID: u64 = 43;
    pub const GETGID: u64 = 47;
    pub const MUNMAP: u64 = 73;
    pub const MPROTECT: u64 = 74;
    pub const MMAP: u64 = 197;
    pub const SHARED_REGION_CHECK_NP: u64 = 294;
    pub const ISSETUGID: u64 = 327;
    pub const THREAD_SELFID: u64 = 372;
}

/// Darwin's `mmap` flags that differ from Linux's.
mod map {
    pub const ANON: u64 = 0x1000;
    pub const NORESERVE: u64 = 0x40;
    // The rest (MAP_JIT, MAP_RESILIENT_*, MAP_TPRO, ...) mean nothing to
    // gex and are dropped.
}

/// The canonical number for BSD call `raw`, with `a` rewritten where the
/// two sides disagree about an argument.
pub fn translate(raw: u64, a: &mut [u64; 6]) -> u64 {
    match raw {
        sys::MMAP => {
            use crate::mem::flags as lf;
            let f = a[3];
            let mut l = f & (lf::SHARED | lf::PRIVATE | lf::FIXED);
            if f & map::ANON != 0 {
                l |= lf::ANONYMOUS;
            }
            if f & map::NORESERVE != 0 {
                l |= lf::NORESERVE;
            }
            a[3] = l;
            nr::MMAP
        }
        sys::MUNMAP => nr::MUNMAP,
        sys::MPROTECT => nr::MPROTECT,
        sys::THREAD_SELFID => nr::GETTID,
        // Darwin's exit ends the process, every thread with it.
        sys::EXIT => nr::EXIT_GROUP,
        sys::READ => nr::READ,
        sys::WRITE => nr::WRITE,
        sys::CLOSE => nr::CLOSE,
        sys::GETPID => nr::GETPID,
        sys::GETUID => nr::GETUID,
        sys::GETEUID => nr::GETEUID,
        sys::GETPPID => nr::GETPPID,
        sys::GETEGID => nr::GETEGID,
        sys::GETGID => nr::GETGID,
        _ => UNKNOWN,
    }
}
