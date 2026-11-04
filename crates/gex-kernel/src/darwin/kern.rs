//! Darwin calls that have no Linux counterpart to renumber onto, or whose
//! results or structures need the kernel's state to translate.

use super::bsd::{open_flags, open_flags_back, sys};
use crate::errno::Errno;
use super::ipc::{KQueue, Kq, WorkQueue, Wq};
use crate::syscalls::{nr, Kernel};
use crate::GuestMem;

fn neg(e: Errno) -> u64 {
    (-(e.0 as i64)) as u64
}

fn res(r: Result<u64, Errno>) -> u64 {
    r.unwrap_or_else(neg)
}

/// Darwin signal `d` as Linux's number, or 0 where Linux has none (SIGEMT,
/// SIGINFO).
pub fn signal_to_linux(d: u32) -> u32 {
    match d {
        7 | 29 => 0,
        10 => 7,
        12 => 31,
        16 => 23,
        17 => 19,
        18 => 20,
        19 => 18,
        20 => 17,
        23 => 29,
        30 => 10,
        31 => 12,
        s => s,
    }
}

/// A Darwin signal mask (`sigset_t`, 32 bits) as a Linux one, and back.
pub fn mask_to_linux(m: u32) -> u64 {
    (1..=31u32).filter(|s| m & (1 << (s - 1)) != 0).map(signal_to_linux).filter(|&l| l != 0).fold(0, |acc, l| acc | 1u64 << (l - 1))
}

pub fn mask_from_linux(m: u64) -> u32 {
    (1..=31u32).filter(|&d| {
        let l = signal_to_linux(d);
        l != 0 && m & (1 << (l - 1)) != 0
    })
    .fold(0, |acc, d| acc | 1 << (d - 1))
}

/// `fcntl` commands Darwin and Linux number differently, and Darwin's own.
mod f {
    pub const GETFL: u64 = 3;
    pub const SETFL: u64 = 4;
    pub const GETOWN: u64 = 5;
    pub const SETOWN: u64 = 6;
    pub const GETLK: u64 = 7;
    pub const SETLK: u64 = 8;
    pub const SETLKW: u64 = 9;
    pub const PREALLOCATE: u64 = 42;
    pub const RDADVISE: u64 = 44;
    pub const NOCACHE: u64 = 48;
    pub const GETPATH: u64 = 50;
    pub const FULLFSYNC: u64 = 51;
    pub const ADDSIGS: u64 = 59;
    pub const ADDFILESIGS: u64 = 61;
    pub const GETPROTECTIONCLASS: u64 = 63;
    pub const SETPROTECTIONCLASS: u64 = 64;
    pub const DUPFD_CLOEXEC: u64 = 67;
    pub const SETNOSIGPIPE: u64 = 73;
    pub const GETNOSIGPIPE: u64 = 74;
    pub const BARRIERFSYNC: u64 = 85;
    pub const ADDFILESIGS_RETURN: u64 = 97;
    pub const CHECK_LV: u64 = 98;
    pub const SPECULATIVE_READ: u64 = 101;
}

/// `MAXPATHLEN`.
const MAXPATHLEN: usize = 1024;

/// AMFI's `__mac_syscall` for dyld's policy: every relaxation allowed
/// (paths, path variables, fallback paths, printing, interposing).
const AMFI_DYLD_POLICY_SELF: u64 = 90;
const AMFI_DYLD_OUTPUT_ALL: u64 = 0xff;

/// The Sandbox policy's `__mac_syscall` for `sandbox_get_container_expected`.
const SANDBOX_CONTAINER_EXPECTED: u64 = 67;

/// A mount, as `getfsstat64` reports it.
pub struct Mount {
    pub on: &'static str,
    pub from: &'static str,
    pub fsid: u64,
    pub flags: u32,
}

/// `MNT_RDONLY`, `MNT_ROOTFS`, `MNT_DONTBROWSE`.
const MNT_RDONLY: u32 = 0x1;
const MNT_ROOTFS: u32 = 0x4000;
const MNT_DONTBROWSE: u32 = 0x10_0000;

/// What an iOS 17 system has mounted: the system volume and the SystemOS
/// cryptex the shared cache is in, by the filesystem id its dynamic data
/// names.
pub const MOUNTS: &[Mount] = &[
    Mount { on: "/", from: "/dev/disk0s1s1", fsid: 0x0100_0002, flags: MNT_RDONLY | MNT_ROOTFS },
    Mount { on: "/System/Cryptexes/OS", from: "/dev/disk3s1", fsid: super::CACHE_FS_ID, flags: MNT_RDONLY | MNT_DONTBROWSE },
];

/// `sizeof(struct statfs64)`.
pub const STATFS64_SIZE: usize = 2168;

/// What the volumes report of themselves, in `statfs` and `getattrlist`
/// alike: the block size, the preferred transfer size and the counts.
pub mod vfsstat {
    pub const BSIZE: u32 = 4096;
    pub const IOSIZE: u32 = 1 << 20;
    pub const BLOCKS: u64 = 8 << 20;
    pub const BFREE: u64 = 4 << 20;
    pub const BAVAIL: u64 = 4 << 20;
    pub const FILES: u64 = 1 << 24;
    pub const FFREE: u64 = 1 << 23;
    /// `vfs_typenum` of APFS: `f_type`, and the second word of `f_fsid`.
    pub const APFS_TYPENUM: u32 = 0x1a;
}

/// The mount a path is on: the one with the longest mount point that
/// holds it.
pub fn mount_of(path: &str) -> &'static Mount {
    MOUNTS
        .iter()
        .filter(|mt| path == mt.on || path.starts_with(&format!("{}/", mt.on.trim_end_matches('/'))))
        .max_by_key(|mt| mt.on.len())
        .unwrap_or(&MOUNTS[0])
}

/// One `struct statfs64` for `mnt`, as an APFS volume.
pub fn statfs64(mnt: &Mount) -> Vec<u8> {
    let mut b = vec![0u8; STATFS64_SIZE];
    let mut put = |o: usize, v: &[u8]| b[o..o + v.len()].copy_from_slice(v);
    put(0, &vfsstat::BSIZE.to_le_bytes());
    put(4, &vfsstat::IOSIZE.to_le_bytes());
    put(8, &vfsstat::BLOCKS.to_le_bytes());
    put(16, &vfsstat::BFREE.to_le_bytes());
    put(24, &vfsstat::BAVAIL.to_le_bytes());
    put(32, &vfsstat::FILES.to_le_bytes());
    put(40, &vfsstat::FFREE.to_le_bytes());
    // The mount's device number, and the filesystem type beside it.
    put(48, &(mnt.fsid as u32).to_le_bytes());
    put(52, &vfsstat::APFS_TYPENUM.to_le_bytes());
    put(60, &vfsstat::APFS_TYPENUM.to_le_bytes());
    put(64, &mnt.flags.to_le_bytes());
    put(72, b"apfs");
    put(88, mnt.on.as_bytes());
    put(1112, mnt.from.as_bytes());
    b
}

/// `gettimeofday(tp, tzp, mach_absolute_time)`: a 64-bit `timeval` (seconds,
/// then 32-bit microseconds), a zero timezone, and the absolute time taken
/// with it.
fn darwin_gettimeofday(m: &mut GuestMem<'_>, tp: u64, tzp: u64, abs: u64) -> Result<u64, Errno> {
    if tp != 0 {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        let mut tv = [0u8; 16];
        tv[..8].copy_from_slice(&(now.as_secs() as i64).to_le_bytes());
        tv[8..12].copy_from_slice(&(now.subsec_micros() as i32).to_le_bytes());
        m.write(tp, &tv)?;
        if abs != 0 {
            m.write_u64(abs, super::mach::absolute_time())?;
        }
    }
    if tzp != 0 {
        m.write(tzp, &[0u8; 8])?;
    }
    Ok(0)
}

impl Kernel {
    /// Answer a Darwin call that the renumbering in
    /// [`super::bsd::translate`] cannot, or `None` to leave it to that.
    /// The result is in the canonical encoding (`-errno` on failure).
    pub(crate) fn darwin_call(&mut self, m: &mut GuestMem<'_>, raw: u64, a: &[u64; 6]) -> Option<u64> {
        Some(match raw {
            // dyld asks where the shared cache is mapped; the kernel mapped
            // it before the process started.
            sys::SHARED_REGION_CHECK_NP => match self.darwin_region {
                (0, _) => neg(Errno::EINVAL),
                (start, _) => res(m.write_u64(a[0], start).map(|_| 0)),
            },
            // No set-id programs here.
            sys::ISSETUGID => 0,
            sys::GETENTROPY => res(self.canonical(m, nr::GETRANDOM, [a[0], a[1], 0, 0, 0, 0]).map(|_| 0)),
            sys::FCNTL | sys::FCNTL_NOCANCEL => self.darwin_fcntl(m, a),
            sys::FSGETPATH => res(self.darwin_fsgetpath(m, a)),
            sys::PROC_INFO => res(self.darwin_proc_info(m, a)),
            sys::GETTIMEOFDAY => res(darwin_gettimeofday(m, a[0], a[1], a[2])),
            // A new mapping's entries have the default maximum protection.
            // MAP_ANON is 0x1000: a file mapping has a descriptor to look at
            // (a POSIX shared memory object's checks).
            sys::MMAP => {
                if a[3] & 0x1000 == 0 && (a[4] as i32) >= 0 {
                    if let Err(e) = self.darwin_shm_mmap_check(a) {
                        return Some(neg(e));
                    }
                }
                let mut b = *a;
                let n = super::bsd::translate(raw, &mut b);
                match self.canonical(m, n, b) {
                    Ok(at) => {
                        use super::mach::PAGE_MASK;
                        let end = at.saturating_add(a[1]).saturating_add(PAGE_MASK) & !PAGE_MASK;
                        self.dtask.maxprot.clear(at & !PAGE_MASK, end);
                        at
                    }
                    Err(e) => neg(e),
                }
            }
            // munmap and mprotect (`kern_mman.c`) are mach_vm_deallocate
            // and mach_vm_protect, with the address page aligned.
            sys::MUNMAP => {
                use super::mach::PAGE_MASK;
                if a[0] & PAGE_MASK != 0 || a[0].checked_add(a[1]).is_none() || a[1] == 0 {
                    return Some(neg(Errno::EINVAL));
                }
                match self.darwin_vm_deallocate(m, a[0], a[1]) {
                    0 => 0,
                    _ => neg(Errno::EINVAL),
                }
            }
            sys::MPROTECT => {
                use super::mach::{prot, PAGE_MASK};
                const VM_PROT_TRUSTED: u64 = 0x20;
                const VM_PROT_STRIP_READ: u64 = 0x80;
                let mut p = a[2] as u32 as u64 & (prot::ALL | VM_PROT_TRUSTED | VM_PROT_STRIP_READ);
                if a[0].checked_add(a[1]).is_none() || a[0] & PAGE_MASK != 0 {
                    return Some(neg(Errno::EINVAL));
                }
                if p & (prot::EXECUTE | prot::WRITE) != 0 {
                    p |= prot::READ;
                }
                // CONFIG_DYNAMIC_CODE_SIGNING is not in a RELEASE kernel.
                if p & VM_PROT_TRUSTED != 0 {
                    return Some(neg(Errno::EOPNOTSUPP));
                }
                // VM_PROT_STRIP_READ goes on to mach_vm_protect, which takes
                // no such bit.
                match self.vm_protect(m, a[0], a[1], false, p) {
                    0 => 0,
                    2 => neg(Errno::EACCES),
                    1 => neg(Errno::ENOMEM),
                    _ => neg(Errno::EINVAL),
                }
            }
            // No descriptor is a terminal to a Darwin process yet: stdio
            // buffers fully, and termios structures need not be converted.
            sys::IOCTL => neg(Errno::ENOTTY),
            // gettid(uidp, gidp): a thread's own credentials, which only
            // settid gives it (settid is not served, so none has them).
            sys::GETTID => neg(Errno::ESRCH),
            // kill(pid, signum, posix): a process or a group as Linux's
            // kill reaches them, the signal renumbered. A broadcast is
            // killpg1's, which includes the caller only when posix is set.
            sys::KILL => {
                let (pid, signum, posix) = (a[0] as i32, a[1] as u32, a[2] as i32);
                if signum >= 32 {
                    neg(Errno::EINVAL)
                } else if signum != 0 && signal_to_linux(signum) == 0 {
                    self.darwin_unimplemented(format!("kill with Darwin signal {signum}, which Linux has no number for"));
                    neg(Errno::EINVAL)
                } else if pid == -1 {
                    self.darwin_unimplemented(format!("a broadcast kill (killpg1, posix {posix})"));
                    neg(Errno::EINVAL)
                } else {
                    res(self.canonical(m, nr::KILL, [pid as i64 as u64, u64::from(signal_to_linux(signum)), 0, 0, 0, 0]))
                }
            }
            sys::KQUEUE => res(<Kq as KQueue>::kqueue(self)),
            sys::KQUEUE_WORKLOOP_CTL => {
                let r = <Kq as KQueue>::workloop_ctl(self, m, a);
                <Kq as KQueue>::settle(self, m);
                res(r)
            }
            sys::BSDTHREAD_REGISTER => res(self.darwin_bsdthread_register(m, a)),
            sys::PTHREAD_MARKCANCEL => res(self.darwin_markcancel(m, a[0] as u32)),
            sys::PTHREAD_CANCELED => res(self.darwin_canceled(a[0])),
            // A thread on its way out takes no more signals or cancels.
            sys::DISABLE_THREADSIGNAL => {
                let c = &mut self.dtask.threads.map.entry(self.tid).or_default().cancel;
                c.no_sigmask = true;
                c.disable = true;
                0
            }
            // QoS overrides and the like: no scheduler classes to apply.
            sys::BSDTHREAD_CTL => res(<Wq as WorkQueue>::bsdthread_ctl(self, m, a)),
            // A signal to a thread by its Mach port; signal 0 only asks
            // whether the thread is there.
            sys::PTHREAD_KILL => {
                let sig = signal_to_linux(a[1] as u32);
                let target = self.darwin_name_to_thread(a[0] as u32);
                let no_sigmask = target.is_some_and(|t| self.dtask.threads.map.get(&t).is_some_and(|d| d.cancel.no_sigmask));
                // A workqueue thread takes signals only if it allowed it, or
                // the process allowed some (BSDTHREAD_CTL_WORKQ_ALLOW_*).
                let workq_refuses = target.is_some_and(|t| self.darwin_workq_refuses_kill(t));
                match target {
                    Some(_) if (a[1] as u32) >= 32 => neg(Errno::EINVAL),
                    _ if no_sigmask => neg(Errno::ESRCH),
                    Some(_) if workq_refuses => neg(Errno::EOPNOTSUPP),
                    Some(_) if sig == 0 => 0,
                    Some(tid) => res(self.canonical(m, nr::TGKILL, [self.pid as u64, tid as u64, u64::from(sig), 0, 0, 0])),
                    None => neg(Errno::ESRCH),
                }
            }
            sys::PIPE => res(self.darwin_pipe(m)),
            // Process groups and sessions: the same rules as Linux's, but
            // setpgid's target may be any descendant (inferior()), where
            // Linux's must be a child.
            sys::GETPGRP => res(self.canonical(m, nr::GETPGID, [0, 0, 0, 0, 0, 0])),
            sys::GETPGID => res(self.canonical(m, nr::GETPGID, [a[0] as i32 as i64 as u64, 0, 0, 0, 0, 0])),
            sys::GETSID => res(self.canonical(m, nr::GETSID, [a[0] as i32 as i64 as u64, 0, 0, 0, 0, 0])),
            sys::SETSID => res(self.canonical(m, nr::SETSID, [0; 6])),
            sys::SETPGID => {
                let pid = a[0] as i32;
                if pid != 0 && pid != self.pid {
                    self.darwin_unimplemented("setpgid of another process (a descendant, as inferior() allows)".into());
                    neg(Errno::ESRCH)
                } else {
                    res(self.canonical(m, nr::SETPGID, [0, a[1] as i32 as i64 as u64, 0, 0, 0, 0]))
                }
            }
            // unlink(path) and unlinkat(fd, path, flag): Linux's unlinkat,
            // but a directory is EPERM (vn_authorize_unlink), and
            // AT_REMOVEDIR is rmdirat_internal.
            sys::UNLINK | sys::UNLINKAT => {
                const AT_REMOVEDIR: u64 = 0x80;
                const AT_REMOVEDIR_DATALESS: u64 = 0x100;
                const AT_SYMLINK_NOFOLLOW_ANY: u64 = 0x800;
                let (fd, path, flag) = if raw == sys::UNLINK { (super::bsd::dirfd(super::bsd::AT_FDCWD as u64), a[0], 0) } else { (super::bsd::dirfd(a[0]), a[1], a[2] as u32 as u64) };
                if flag & !(AT_REMOVEDIR | AT_REMOVEDIR_DATALESS | AT_SYMLINK_NOFOLLOW_ANY) != 0 {
                    neg(Errno::EINVAL)
                } else if flag & (AT_REMOVEDIR_DATALESS | AT_SYMLINK_NOFOLLOW_ANY) != 0 {
                    self.darwin_unimplemented(format!("unlinkat flags {flag:#x} (dataless directories, AT_SYMLINK_NOFOLLOW_ANY)"));
                    neg(Errno::EINVAL)
                } else if flag & AT_REMOVEDIR != 0 {
                    res(self.canonical(m, nr::UNLINKAT, [fd, path, 0x200, 0, 0, 0]))
                } else {
                    match self.canonical(m, nr::UNLINKAT, [fd, path, 0, 0, 0, 0]) {
                        Err(Errno::EISDIR) => neg(Errno::EPERM),
                        r => res(r),
                    }
                }
            }
            sys::FSTAT64 if self.darwin_pipe_of(a[0]).is_some() => res(self.darwin_pipe_stat(m, a[0], a[1])),
            sys::SIGACTION => res(self.darwin_sigaction(m, a[0], a[1], a[2])),
            sys::SIGALTSTACK => res(self.darwin_sigaltstack(m, a[0], a[1])),
            sys::GETFSSTAT64 => res(self.darwin_getfsstat(m, a[0], a[1])),
            sys::SHM_OPEN => res(self.darwin_shm_open(m, a)),
            sys::SHM_UNLINK => res(self.darwin_shm_unlink(m, a)),
            // An object takes one size and has no read or write; a mapping
            // of it is checked before it is made.
            sys::FTRUNCATE if self.darwin_shm_fd(a[0]) => res(self.darwin_shm_ftruncate(a)),
            sys::READ | sys::READ_NOCANCEL | sys::PREAD | sys::PREAD_NOCANCEL | sys::READV | sys::READV_NOCANCEL | sys::PREADV | sys::PREADV_NOCANCEL
                if self.darwin_shm_fd(a[0]) =>
            {
                neg(self.darwin_shm_io(a[0], false))
            }
            sys::WRITE | sys::WRITE_NOCANCEL | sys::PWRITE | sys::PWRITE_NOCANCEL | sys::WRITEV | sys::WRITEV_NOCANCEL | sys::PWRITEV | sys::PWRITEV_NOCANCEL
                if self.darwin_shm_fd(a[0]) =>
            {
                neg(self.darwin_shm_io(a[0], true))
            }
            // A family or an option this kernel has no Linux counterpart for
            // is refused where the caller is told, and said.
            sys::SOCKET | sys::SOCKETPAIR if !matches!(a[0], 0..=2) => {
                if super::sockaddr::family_exists(a[0]) {
                    self.darwin_unimplemented(format!("socket domain {} (AF_* of Darwin's bsd/sys/socket.h)", a[0]));
                }
                neg(Errno::EAFNOSUPPORT)
            }
            sys::SETSOCKOPT | sys::GETSOCKOPT => match super::sockaddr::sockopt_to_linux(a[1], a[2]) {
                Ok(_) => return None,
                Err(what) => {
                    self.darwin_unimplemented(format!("{} {what}", if raw == sys::SETSOCKOPT { "setsockopt" } else { "getsockopt" }));
                    neg(Errno::ENOPROTOOPT)
                }
            },
            sys::GETATTRLIST => res(self.darwin_getattrlist(m, a)),
            sys::FGETATTRLIST => res(self.darwin_fgetattrlist(m, a)),
            sys::GETATTRLISTAT => res(self.darwin_getattrlistat(m, a)),
            sys::GETATTRLISTBULK => res(self.darwin_getattrlistbulk(m, a)),
            sys::STATFS64 => res(self.darwin_statfs(m, Some(a[0]), a[1])),
            sys::FSTATFS64 => res(self.darwin_statfs(m, None, a[1])),
            sys::SYSCTL => res(self.darwin_sysctl(m, a)),
            sys::SYSCTLBYNAME => res(self.darwin_sysctlbyname(m, a)),
            // dup3 refuses to copy a descriptor onto itself; dup2 checks it
            // is open and returns it.
            sys::DUP2 if a[0] == a[1] => match self.canonical(m, nr::FCNTL, [a[0], 1, 0, 0, 0, 0]) {
                Ok(_) => a[1],
                Err(e) => neg(e),
            },
            sys::DUP2 => res(self.canonical(m, nr::DUP3, [a[0], a[1], 0, 0, 0, 0])),
            sys::SIGPROCMASK | sys::PTHREAD_SIGMASK => res(self.darwin_sigprocmask(m, a[0], a[1], a[2])),
            sys::CSOPS | sys::CSOPS_AUDITTOKEN => res(self.darwin_csops(m, a[1], a[2], a[3])),
            sys::MAC_SYSCALL => res(self.darwin_mac_syscall(m, a[0], a[1], a[2])),
            // The reason a process aborts: said, then the process ends
            // through the renumbering (exit status 134).
            sys::ABORT_WITH_PAYLOAD | sys::TERMINATE_WITH_PAYLOAD => {
                let (code, text) = if raw == sys::ABORT_WITH_PAYLOAD { (a[1], a[4]) } else { (a[2], a[5]) };
                let mut buf = [0u8; 1024];
                let reason = match m.read_cstr_into(text, &mut buf) {
                    Ok(Some(n)) => String::from_utf8_lossy(&buf[..n]).into_owned(),
                    _ => String::from("(no reason)"),
                };
                eprintln!("[gex:{}] darwin abort (code {code:#x}): {reason}", self.pid);
                return None;
            }
            _ => return None,
        })
    }

    fn darwin_fcntl(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> u64 {
        let fd = a[0];
        let canon = |k: &mut Kernel, m: &mut GuestMem<'_>, cmd: u64, arg: u64| res(k.canonical(m, nr::FCNTL, [fd, cmd, arg, 0, 0, 0]));
        match a[1] {
            // F_DUPFD, F_GETFD, F_SETFD: the same on both sides.
            c @ 0..=2 => canon(self, m, c, a[2]),
            f::GETFL => match self.canonical(m, nr::FCNTL, [fd, 3, 0, 0, 0, 0]) {
                Ok(l) => open_flags_back(l),
                Err(e) => neg(e),
            },
            f::SETFL => canon(self, m, 4, open_flags(a[2])),
            f::GETOWN => canon(self, m, 9, 0),
            f::SETOWN => canon(self, m, 8, a[2]),
            f::DUPFD_CLOEXEC => canon(self, m, 1030, a[2]),
            // Record locks: one process's view of its files; granted.
            f::GETLK | f::SETLK | f::SETLKW => 0,
            f::GETPATH => {
                let path = self.fds.list().into_iter().find(|&(n, _)| n as u64 == fd).map(|(_, p)| p);
                match path {
                    Some(p) if p.len() < MAXPATHLEN => {
                        let mut b = p.into_bytes();
                        b.push(0);
                        res(m.write(a[2], &b).map(|_| 0))
                    }
                    Some(_) => neg(Errno::ENAMETOOLONG),
                    None => neg(Errno::EBADF),
                }
            }
            // A signature covering the whole file: fs_file_start, the end
            // of what the signature covers, is the largest offset.
            f::ADDFILESIGS_RETURN => res(m.write_u64(a[2], i64::MAX as u64).map(|_| 0)),
            f::ADDSIGS | f::ADDFILESIGS | f::CHECK_LV => 0,
            f::NOCACHE | f::RDADVISE | f::FULLFSYNC | f::BARRIERFSYNC | f::PREALLOCATE | f::SPECULATIVE_READ => 0,
            // FG_NOSIGPIPE on the open file; a socket's is its SO_NOSIGPIPE.
            f::SETNOSIGPIPE | f::GETNOSIGPIPE => match self.fds.get(fd as i32) {
                Err(e) => neg(e),
                Ok(file) if file.handle.metadata().is_ok_and(|md| md.file_type == crate::vfs::FileType::Socket) => {
                    self.darwin_unimplemented("F_SETNOSIGPIPE and F_GETNOSIGPIPE on a socket (SO_NOSIGPIPE)".into());
                    neg(Errno::EINVAL)
                }
                Ok(file) => {
                    use std::sync::atomic::Ordering::AcqRel;
                    let bit = super::pipe::FG_NOSIGPIPE;
                    if a[1] == f::SETNOSIGPIPE {
                        if a[2] as i32 != 0 {
                            file.darwin_lflags.fetch_or(bit, AcqRel);
                        } else {
                            file.darwin_lflags.fetch_and(!bit, AcqRel);
                        }
                        0
                    } else {
                        u64::from(file.darwin_lflags.load(std::sync::atomic::Ordering::Acquire) & bit != 0)
                    }
                }
            },
            f::SETPROTECTIONCLASS => 0,
            f::GETPROTECTIONCLASS => 0,
            _ => neg(Errno::EINVAL),
        }
    }

    /// `proc_info(callnum, pid, flavor, arg, buffer, buffersize)`.
    fn darwin_proc_info(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        const CALL_PIDINFO: u64 = 2;
        const CALL_SET_DYLD_IMAGES: u64 = 15;
        const PIDPATHINFO: u64 = 11;
        const UNIQIDENTIFIERINFO: u64 = 17;
        let (call, pid, flavor, buf, size) = (a[0], a[1] as i32, a[2] as u32 as u64, a[4], a[5] as u32 as usize);
        let me = pid == self.pid || pid == 0;
        match (call, flavor) {
            // dyld says where its image list is (`buf`, `size` bytes),
            // which task_info(TASK_DYLD_INFO) reports from then on.
            (CALL_SET_DYLD_IMAGES, _) if me => {
                if buf == 0 || size == 0 {
                    return Err(Errno::EINVAL);
                }
                self.darwin_dyld_infos = buf;
                Ok(0)
            }
            // proc_uniqidentifierinfo: a uuid, the unique id and the
            // parent's, an id version.
            // The struct has grown over releases; fill what the caller has
            // room for.
            (CALL_PIDINFO, UNIQIDENTIFIERINFO) if me => {
                if size < 32 {
                    return Err(Errno::ENOMEM);
                }
                let mut b = [0u8; 64];
                b[16..24].copy_from_slice(&(self.pid as u64).to_le_bytes());
                b[24..32].copy_from_slice(&1u64.to_le_bytes());
                let n = size.min(b.len());
                m.write(buf, &b[..n])?;
                Ok(n as u64)
            }
            // proc_pidpath: the program's path.
            (CALL_PIDINFO, PIDPATHINFO) if me => {
                let mut p = self.exe_path.clone().into_bytes();
                p.push(0);
                if size < p.len() {
                    return Err(Errno::ENOMEM);
                }
                m.write(buf, &p)?;
                Ok(p.len() as u64 - 1)
            }
            _ => {
                if self.trace {
                    eprintln!("[gex:{}] proc_info call {call} flavor {flavor} pid {pid} is not answered", self.pid);
                }
                Err(Errno::EOPNOTSUPP)
            }
        }
    }

    /// `fsgetpath(buf, size, fsid, objid)`: the path of a file named by its
    /// filesystem and object ids. Only the shared cache is named so.
    fn darwin_fsgetpath(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        let fs = u64::from(m.read_u32(a[2])?) | u64::from(m.read_u32(a[2] + 4)?) << 32;
        if (fs, a[3]) != (super::CACHE_FS_ID, super::CACHE_OBJ_ID) || self.darwin_region.0 == 0 {
            return Err(Errno::ENOENT);
        }
        let mut b = super::CACHE_PATH.as_bytes().to_vec();
        b.push(0);
        if (a[1] as usize) < b.len() {
            return Err(Errno::ENOSPC);
        }
        m.write(a[0], &b)?;
        Ok(b.len() as u64)
    }

    /// `getfsstat64(buf, bufsize, flags)`: the mounts, or how many there
    /// are when `buf` is null.
    fn darwin_getfsstat(&mut self, m: &mut GuestMem<'_>, buf: u64, size: u64) -> Result<u64, Errno> {
        let mounts = MOUNTS;
        if buf == 0 {
            return Ok(mounts.len() as u64);
        }
        let n = (size as usize / STATFS64_SIZE).min(mounts.len());
        for (i, mnt) in mounts.iter().take(n).enumerate() {
            m.write(buf + (i * STATFS64_SIZE) as u64, &statfs64(mnt))?;
        }
        Ok(n as u64)
    }

    /// `statfs64(path, buf)` or `fstatfs64(fd, buf)`: the mount with the
    /// longest prefix of the file's path.
    fn darwin_statfs(&mut self, m: &mut GuestMem<'_>, path: Option<u64>, buf: u64) -> Result<u64, Errno> {
        let _ = path;
        let p = match path {
            Some(at) => {
                let mut b = [0u8; MAXPATHLEN];
                let n = m.read_cstr_into(at, &mut b)?.ok_or(Errno::ENAMETOOLONG)?;
                String::from_utf8_lossy(&b[..n]).into_owned()
            }
            None => String::from("/"),
        };
        let mnt = mount_of(&p);
        m.write(buf, &statfs64(mnt))?;
        Ok(0)
    }

    /// `sysctl(name, namelen, old, oldlenp, new, newlen)`. Nodes are
    /// read-only, except that a write is accepted and ignored where the
    /// node exists.
    fn darwin_sysctl(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        use super::sysctl;
        let n = a[1] as usize;
        if !(1..=24).contains(&n) {
            return Err(Errno::EINVAL);
        }
        let mut oid = Vec::with_capacity(n);
        for i in 0..n {
            oid.push(m.read_u32(a[0] + 4 * i as u64)? as i32);
        }
        // {0, 3}: the OID of the name in `new`.
        let value = if oid == [0, 3] {
            let mut buf = [0u8; 256];
            let len = (a[5] as usize).min(buf.len() - 1);
            let name = m.read(a[4], len)?;
            buf[..len].copy_from_slice(name);
            let name = std::str::from_utf8(&buf[..len]).map_err(|_| Errno::EINVAL)?.trim_end_matches('\0');
            let Some(o) = sysctl::oid(name) else {
                if self.trace {
                    eprintln!("[gex:{}] sysctl: no node {name}", self.pid);
                }
                return Err(Errno::ENOENT);
            };
            o.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>()
        } else {
            match sysctl::get(&oid) {
                Some(v) => v.bytes(),
                None => {
                    if self.trace {
                        eprintln!("[gex:{}] sysctl: no node {oid:?}", self.pid);
                    }
                    return Err(Errno::ENOENT);
                }
            }
        };
        self.sysctl_out(m, a[2], a[3], &value)
    }

    /// `sysctlbyname(name, namelen, old, oldlenp, new, newlen)`.
    fn darwin_sysctlbyname(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        use super::sysctl;
        let len = (a[1] as usize).min(255);
        let name = String::from_utf8_lossy(m.read(a[0], len)?).trim_end_matches('\0').to_string();
        let Some(v) = sysctl::oid(&name).and_then(|o| sysctl::get(&o)) else {
            if self.trace {
                eprintln!("[gex:{}] sysctlbyname: no node {name}", self.pid);
            }
            return Err(Errno::ENOENT);
        };
        self.sysctl_out(m, a[2], a[3], &v.bytes())
    }

    /// Copy a node's value out: the size alone when `old` is null, ENOMEM
    /// (with the size) when the buffer is short.
    fn sysctl_out(&mut self, m: &mut GuestMem<'_>, old: u64, oldlenp: u64, value: &[u8]) -> Result<u64, Errno> {
        if oldlenp == 0 {
            return Ok(0);
        }
        let room = m.read_u64(oldlenp)? as usize;
        m.write_u64(oldlenp, value.len() as u64)?;
        if old == 0 {
            return Ok(0);
        }
        if room < value.len() {
            return Err(Errno::ENOMEM);
        }
        m.write(old, value)?;
        Ok(0)
    }

    fn darwin_sigprocmask(&mut self, m: &mut GuestMem<'_>, how: u64, set: u64, old: u64) -> Result<u64, Errno> {
        // The old mask is the one before the call, copied out after the new
        // one is read (they may be the same word).
        let blocked = self.signals.blocked();
        if set != 0 {
            let mask = mask_to_linux(m.read_u32(set)?);
            let next = match how {
                1 => blocked | mask,
                2 => blocked & !mask,
                3 => (blocked & !mask_to_linux(!0)) | mask,
                _ => return Err(Errno::EINVAL),
            };
            let unblockable = (1u64 << (crate::signal::sig::SIGKILL - 1)) | (1u64 << (crate::signal::sig::SIGSTOP - 1));
            self.signals.set_blocked(next & !unblockable);
        }
        if old != 0 {
            m.write_u32(old, mask_from_linux(blocked))?;
        }
        Ok(0)
    }

    /// Code signing status: every program is valid, signed and a platform
    /// binary, which is what AMFI would have enforced.
    fn darwin_csops(&mut self, m: &mut GuestMem<'_>, ops: u64, addr: u64, size: u64) -> Result<u64, Errno> {
        const CS_OPS_STATUS: u64 = 0;
        const CS_VALID: u32 = 0x1;
        const CS_SIGNED: u32 = 0x2000_0000;
        const CS_PLATFORM_BINARY: u32 = 0x400_0000;
        if addr == 0 {
            return Ok(0);
        }
        m.zero(addr, size.min(4096) as usize)?;
        if ops == CS_OPS_STATUS && size >= 4 {
            m.write_u32(addr, CS_VALID | CS_SIGNED | CS_PLATFORM_BINARY)?;
        }
        Ok(0)
    }

    fn darwin_mac_syscall(&mut self, m: &mut GuestMem<'_>, policy: u64, call: u64, arg: u64) -> Result<u64, Errno> {
        let mut buf = [0u8; 64];
        let name = match m.read_cstr_into(policy, &mut buf)? {
            Some(n) => String::from_utf8_lossy(&buf[..n]).into_owned(),
            None => return Err(Errno::EINVAL),
        };
        match (name.as_str(), call) {
            ("AMFI", AMFI_DYLD_POLICY_SELF) => {
                let out = m.read_u64(arg + 8)?;
                m.write_u64(out, AMFI_DYLD_OUTPUT_ALL)?;
                Ok(0)
            }
            // sandbox_get_container_expected: two out pointers, a container
            // expected and the other flag beside it; neither, for a program
            // that is not a containerised app.
            ("Sandbox", SANDBOX_CONTAINER_EXPECTED) => {
                for i in 0..2 {
                    let out = m.read_u64(arg + 8 * i)?;
                    if out != 0 {
                        m.write_u64(out, 0)?;
                    }
                }
                Ok(0)
            }
            _ => {
                if self.trace {
                    eprintln!("[gex:{}] __mac_syscall({name}, {call}) is not answered", self.pid);
                }
                Err(Errno::ENOSYS)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_masks_round_trip() {
        // SIGUSR1 (30) and SIGCHLD (20) on Darwin are 10 and 17 on Linux.
        let d = (1 << 29) | (1 << 19);
        let l = mask_to_linux(d);
        assert_eq!(l, (1 << 9) | (1 << 16));
        assert_eq!(mask_from_linux(l), d);
    }
}
