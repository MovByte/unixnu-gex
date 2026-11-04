//! BSD system calls, renumbered onto the canonical (Linux) ones.
//!
//! Numbers are XNU's ([`super::sysno`]). A call whose arguments mean the
//! same thing on both sides is only renumbered; one whose flags or
//! directory descriptor differ is rewritten here before it runs. Calls with
//! no canonical counterpart are [`super::kern`]'s. Anything else is
//! [`crate::x86::UNKNOWN`], which the dispatch answers with ENOSYS and
//! records as unimplemented.

pub use super::sysno as sys;
use crate::syscalls::nr;
use crate::x86::UNKNOWN;

/// Darwin's `AT_FDCWD`; Linux's is -100.
pub const AT_FDCWD: i64 = -2;
const LINUX_AT_FDCWD: u64 = -100i64 as u64;

/// A directory descriptor argument in Linux's terms.
pub fn dirfd(fd: u64) -> u64 {
    if fd as i32 as i64 == AT_FDCWD {
        LINUX_AT_FDCWD
    } else {
        fd
    }
}

/// Darwin `open` flags, as the canonical (AArch64 Linux) ones.
pub fn open_flags(f: u64) -> u64 {
    // (Darwin bit, Linux bit): O_NONBLOCK, O_APPEND, O_CREAT, O_TRUNC,
    // O_EXCL, O_NOFOLLOW, O_NOCTTY, O_DIRECTORY, O_CLOEXEC, O_DSYNC, O_SYNC.
    const MAP: [(u64, u64); 11] = [
        (0x4, 0x800),
        (0x8, 0x400),
        (0x200, 0x40),
        (0x400, 0x200),
        (0x800, 0x80),
        (0x100, 0x8000),
        (0x20000, 0x100),
        (0x10_0000, 0x4000),
        (0x100_0000, 0x8_0000),
        (0x40_0000, 0x1000),
        (0x80, 0x10_1000),
    ];
    let mut l = f & 3;
    for (d, x) in MAP {
        if f & d != 0 {
            l |= x;
        }
    }
    l
}

/// Linux `open` status flags back in Darwin's terms (`F_GETFL`).
pub fn open_flags_back(l: u64) -> u64 {
    let mut d = l & 3;
    for (dbit, lbit) in [(0x4u64, 0x800u64), (0x8, 0x400)] {
        if l & lbit != 0 {
            d |= dbit;
        }
    }
    d
}

/// Darwin `AT_*` flags as Linux's: AT_SYMLINK_NOFOLLOW, AT_SYMLINK_FOLLOW,
/// AT_REMOVEDIR, AT_EACCESS.
pub fn at_flags(f: u64) -> u64 {
    let mut l = 0;
    for (d, x) in [(0x20u64, 0x100u64), (0x40, 0x400), (0x80, 0x200), (0x10, 0x200)] {
        if f & d != 0 {
            l |= x;
        }
    }
    l
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
        // Darwin's exit ends the process, every thread with it; so do the
        // payload aborts once [`super::kern`] has said why.
        sys::EXIT => nr::EXIT_GROUP,
        sys::ABORT_WITH_PAYLOAD | sys::TERMINATE_WITH_PAYLOAD => {
            a[0] = 128 + 6;
            nr::EXIT_GROUP
        }
        sys::READ | sys::READ_NOCANCEL => nr::READ,
        sys::WRITE | sys::WRITE_NOCANCEL => nr::WRITE,
        sys::CLOSE | sys::CLOSE_NOCANCEL => nr::CLOSE,
        sys::DUP => nr::DUP,
        sys::PREAD | sys::PREAD_NOCANCEL => nr::PREAD64,
        sys::PWRITE | sys::PWRITE_NOCANCEL => nr::PWRITE64,
        sys::LSEEK => nr::LSEEK,
        sys::OPEN | sys::OPEN_NOCANCEL => {
            *a = [LINUX_AT_FDCWD, a[0], open_flags(a[1]), a[2], 0, 0];
            nr::OPENAT
        }
        sys::OPENAT | sys::OPENAT_NOCANCEL => {
            *a = [dirfd(a[0]), a[1], open_flags(a[2]), a[3], 0, 0];
            nr::OPENAT
        }
        sys::ACCESS => {
            *a = [LINUX_AT_FDCWD, a[0], a[1], 0, 0, 0];
            nr::FACCESSAT
        }
        sys::FACCESSAT => {
            *a = [dirfd(a[0]), a[1], a[2], at_flags(a[3]), 0, 0];
            nr::FACCESSAT
        }
        sys::READLINK => {
            *a = [LINUX_AT_FDCWD, a[0], a[1], a[2], 0, 0];
            nr::READLINKAT
        }
        sys::READLINKAT => {
            a[0] = dirfd(a[0]);
            nr::READLINKAT
        }
        // The struct stat layout is Darwin's where the kernel writes one
        // for a Darwin process (`Stat::encode_darwin`).
        sys::STAT64 => {
            *a = [LINUX_AT_FDCWD, a[0], a[1], 0, 0, 0];
            nr::NEWFSTATAT
        }
        sys::LSTAT64 => {
            *a = [LINUX_AT_FDCWD, a[0], a[1], 0x100, 0, 0];
            nr::NEWFSTATAT
        }
        sys::FSTAT64 => nr::FSTAT,
        sys::FSTATAT64 => {
            *a = [dirfd(a[0]), a[1], a[2], at_flags(a[3]), 0, 0];
            nr::NEWFSTATAT
        }
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
        sys::GETPID => nr::GETPID,
        sys::GETUID => nr::GETUID,
        sys::GETEUID => nr::GETEUID,
        sys::GETPPID => nr::GETPPID,
        sys::GETEGID => nr::GETEGID,
        sys::GETGID => nr::GETGID,
        _ => UNKNOWN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_flags_map_onto_linux() {
        // O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC
        assert_eq!(open_flags(0x2 | 0x200 | 0x400 | 0x100_0000), 0x2 | 0x40 | 0x200 | 0x8_0000);
        assert_eq!(open_flags(0), 0);
        assert_eq!(open_flags_back(0x800 | 0x2), 0x4 | 0x2);
    }

    #[test]
    fn open_becomes_openat_from_the_cwd() {
        let mut a = [0x1000, 0x100, 0o644, 0, 0, 0];
        assert_eq!(translate(sys::OPEN, &mut a), nr::OPENAT);
        assert_eq!(a[0] as i64, -100);
        assert_eq!(a[2], 0x8000);
        let mut b = [-2i64 as u64, 0x1000, 0, 0, 0, 0];
        translate(sys::OPENAT, &mut b);
        assert_eq!(b[0] as i64, -100);
    }
}
