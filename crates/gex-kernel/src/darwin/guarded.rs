//! Guarded file descriptors (`bsd/kern/kern_guarded.c`): a descriptor a
//! guard value protects from the calls its attributes name. A call that
//! breaks one fails with EPERM and its thread takes EXC_GUARD on the way
//! back to user space.

use super::bsd::sys;
use super::reason::{flag, ns, OsReason};
use super::signal::dsig;
use crate::errno::Errno;
use crate::file::FdGuard;
use crate::signal::Note;
use crate::syscalls::{Kernel, SyscallOutcome};
use crate::GuestMem;
use std::sync::Arc;

/// `GUARD_*` (`bsd/sys/guarded.h`).
pub mod attr {
    pub const CLOSE: u16 = 1 << 0;
    pub const DUP: u16 = 1 << 1;
    pub const SOCKET_IPC: u16 = 1 << 2;
    pub const FILEPORT: u16 = 1 << 3;
    pub const WRITE: u16 = 1 << 4;
    /// `GUARD_REQUIRED`, `GUARD_ALL`.
    pub const REQUIRED: u32 = DUP as u32;
    pub const ALL: u32 = (CLOSE | DUP | SOCKET_IPC | FILEPORT | WRITE) as u32;
}

/// `kGUARD_EXC_*` for a descriptor.
pub mod flavor {
    pub const CLOSE: u32 = 1 << 0;
    pub const DUP: u32 = 1 << 1;
    pub const NOCLOEXEC: u32 = 1 << 2;
    pub const SOCKET_IPC: u32 = 1 << 3;
    pub const FILEPORT: u32 = 1 << 4;
    pub const WRITE: u32 = 1 << 6;
}

/// `GUARD_TYPE_FD`, `EXC_GUARD`.
const GUARD_TYPE_FD: u64 = 2;
const EXC_GUARD: i32 = super::exception::EXC_GUARD as i32;

const F_DUPFD: u64 = 0;
const F_SETFD: u64 = 2;
const F_DUPFD_CLOEXEC: u64 = 67;
const FD_CLOEXEC: u32 = 1;
const FD_CLOFORK: u32 = 2;
const O_WRONLY: u64 = 0x1;
const O_RDWR: u64 = 0x2;
const O_CREAT: u64 = 0x200;
const O_CLOEXEC: u64 = 0x0100_0000;
const O_CLOFORK: u64 = 0x0800_0000;
const O_NOFOLLOW: u64 = 0x100;
const O_SYMLINK: u64 = 0x0020_0000;
const O_NOFOLLOW_ANY: u64 = 0x2000_0000;
pub(crate) const O_LOCKS: u64 = 0x30;
/// `O_EXEC` (`FEXEC`), and with O_DIRECTORY `O_SEARCH`.
const O_EXEC: u64 = 0x4000_0000;
const O_DIRECTORY: u64 = 0x10_0000;
/// The open flags a plain renumbering does not carry, which
/// [`Kernel::darwin_open_finish`] carries out itself.
pub(crate) const OPEN_FINISHED: u64 = O_LOCKS | O_CLOFORK | O_SYMLINK | O_NOFOLLOW_ANY | O_EXEC;
const O_DP_GETRAWENCRYPTED: u64 = 0x1;
const O_DP_GETRAWUNENCRYPTED: u64 = 0x2;
const O_DP_AUTHENTICATE: u64 = 0x4;

/// `struct msghdr`'s `msg_control` and `msg_controllen`, and `struct
/// cmsghdr`'s size.
const MSG_CONTROL: u64 = 32;
const MSG_CONTROLLEN: u64 = 40;
const CMSG_HDR: u32 = 12;
const SOL_SOCKET: u32 = 0xffff;
const SCM_RIGHTS: u32 = 1;

impl Kernel {
    /// `fp_guard_exception`: what breaking guard `g` on `fd` returns, and
    /// the exception the calling thread takes (`thread_guard_violation`:
    /// the first of them stands).
    pub(crate) fn darwin_fp_guard_exception(&mut self, fd: i32, g: FdGuard, flavor: u32) -> Errno {
        let code = (GUARD_TYPE_FD << 61) | (u64::from(flavor) << 32) | u64::from(fd as u32);
        self.dtask.fd_guard.get_or_insert((code, g.guard));
        Errno::EPERM
    }

    /// `fd_guard_ast`: a guard broken in this call ends the process. Without
    /// Developer Mode no handler may hold a fatal EXC_GUARD
    /// (`task_exception_notify` refuses), so it goes straight to
    /// `exit_with_guard_exception`: SIGKILL for an OS_REASON_GUARD reason
    /// that asks for a crash report.
    pub(crate) fn darwin_fd_guard_ast(&mut self) {
        let Some((code, subcode)) = self.dtask.fd_guard.take() else { return };
        if super::kobject::DEVELOPER_MODE {
            self.darwin_unimplemented("a synchronous EXC_GUARD for a descriptor under Developer Mode (task_exception_notify)".into());
        }
        eprintln!("[gex:{}] EXC_GUARD (GUARD_TYPE_FD, code {code:#x}, guard {subcode:#x}): the task is killed", self.pid);
        let th = self.dtask.threads.map.entry(self.tid).or_default();
        th.uu_exception = EXC_GUARD;
        th.uu_code = code as i64;
        th.uu_subcode = subcode as i64;
        let mut r = OsReason::new(ns::GUARD, code);
        r.flags |= flag::GENERATE_CRASH_REPORT;
        let note: Note = Arc::new(r);
        if let Some(ts) = self.thread_signals.get(self.tid) {
            ts.set_exit_reason_if_none(|| note);
            ts.raise(super::kern::signal_to_linux(dsig::SIGKILL), None);
        }
    }

    /// `dup2`'s guards: the old descriptor's GUARD_DUP, then, once the new
    /// number is known to be another in range, its GUARD_CLOSE.
    pub(crate) fn darwin_dup2_guards(&mut self, old: i32, new: i32) -> Result<(), Errno> {
        if let Some(g) = self.fds.guard(old).filter(|g| g.has(attr::DUP)) {
            return Err(self.darwin_fp_guard_exception(old, g, flavor::DUP));
        }
        if self.fds.get(old).is_err() || new < 0 || new as usize >= self.fds.limit() || old == new {
            return Ok(());
        }
        if let Some(g) = self.fds.guard(new).filter(|g| g.has(attr::CLOSE)) {
            return Err(self.darwin_fp_guard_exception(new, g, flavor::CLOSE));
        }
        Ok(())
    }

    /// `close_nocancel`'s guard.
    pub(crate) fn darwin_close_guard(&mut self, fd: i32) -> Result<(), Errno> {
        if let Some(g) = self.fds.guard(fd).filter(|g| g.has(attr::CLOSE)) {
            return Err(self.darwin_fp_guard_exception(fd, g, flavor::CLOSE));
        }
        Ok(())
    }

    /// The guards a call meets on its way in. A guarded write that passes
    /// its guard goes on as the plain call, which is returned; a call that
    /// breaks a guard is refused.
    pub(crate) fn darwin_fd_guards(&mut self, m: &mut GuestMem<'_>, raw: u64, a: &mut [u64; 6]) -> Result<u64, Errno> {
        let fd = a[0] as i32;
        match raw {
            sys::GUARDED_WRITE_NP | sys::GUARDED_PWRITE_NP | sys::GUARDED_WRITEV_NP => {
                let uguard = m.read_u64(a[1])?;
                // write_internal's limit and writev_uio's vector come first.
                if raw == sys::GUARDED_WRITEV_NP {
                    self.darwin_uio_copyin(m, a[2], a[3] as i32)?;
                } else if a[3] > i32::MAX as u64 {
                    return Err(Errno::EINVAL);
                }
                self.darwin_fp_lookup_guarded(fd, uguard)?;
                let call = match raw {
                    sys::GUARDED_WRITE_NP => sys::WRITE_NOCANCEL,
                    sys::GUARDED_PWRITE_NP => sys::PWRITE_NOCANCEL,
                    _ => sys::WRITEV_NOCANCEL,
                };
                *a = [a[0], a[2], a[3], a[4], 0, 0];
                return Ok(call);
            }
            sys::CLOSE | sys::CLOSE_NOCANCEL => self.darwin_close_guard(fd)?,
            sys::DUP => {
                if let Some(g) = self.fds.guard(fd).filter(|g| g.has(attr::DUP)) {
                    return Err(self.darwin_fp_guard_exception(fd, g, flavor::DUP));
                }
            }
            sys::DUP2 => self.darwin_dup2_guards(fd, a[1] as i32)?,
            sys::FCNTL | sys::FCNTL_NOCANCEL => {
                let Some(g) = self.fds.guard(fd) else { return Ok(raw) };
                match a[1] {
                    F_DUPFD | F_DUPFD_CLOEXEC if g.has(attr::DUP) => return Err(self.darwin_fp_guard_exception(fd, g, flavor::DUP)),
                    F_SETFD if a[2] as u32 & FD_CLOEXEC == 0 => return Err(self.darwin_fp_guard_exception(fd, g, flavor::NOCLOEXEC)),
                    _ => {}
                }
            }
            // preparefilewrite, EBADF first, once the length or vector
            // has passed.
            sys::WRITE | sys::WRITE_NOCANCEL | sys::PWRITE | sys::PWRITE_NOCANCEL | sys::WRITEV | sys::WRITEV_NOCANCEL | sys::PWRITEV | sys::PWRITEV_NOCANCEL => {
                let passed = if super::fsops::vectored(raw).is_some() { self.darwin_uio_copyin(m, a[1], a[2] as i32).is_ok() } else { a[2] <= i32::MAX as u64 };
                if let Some(g) = self.fds.guard(fd).filter(|g| passed && g.has(attr::WRITE)) {
                    if self.fds.get(fd).is_ok_and(|f| f.writable) {
                        return Err(self.darwin_fp_guard_exception(fd, g, flavor::WRITE));
                    }
                }
            }
            sys::SENDMSG | sys::SENDMSG_NOCANCEL => self.darwin_unp_internalize_guards(m, fd, a[1])?,
            _ => {}
        }
        Ok(raw)
    }

    /// `unp_internalize`'s guards on the descriptors a unix socket's
    /// `sendmsg` carries, in order; those it would refuse otherwise are
    /// left for the send to.
    fn darwin_unp_internalize_guards(&mut self, m: &GuestMem<'_>, sock: i32, msg: u64) -> Result<(), Errno> {
        // A unix stream's send internalizes its control in its own order
        // ([`super::unixsock`]).
        if self.darwin_xnu_stream(sock as u64).is_some() {
            return Ok(());
        }
        let Ok(socket) = self.fds.get(sock) else { return Ok(()) };
        let h = &socket.handle;
        if Arc::clone(h).as_unix_socket().is_none() && Arc::clone(h).as_unix_dgram().is_none() && Arc::clone(h).as_remote_unix().is_none() {
            return Ok(());
        }
        let Ok(control) = m.read_u64(msg + MSG_CONTROL) else { return Ok(()) };
        let Ok(len) = m.read_u32(msg + MSG_CONTROLLEN) else { return Ok(()) };
        if control == 0 || len < CMSG_HDR {
            return Ok(());
        }
        let (Ok(cmsg_len), Ok(level), Ok(ty)) = (m.read_u32(control), m.read_u32(control + 4), m.read_u32(control + 8)) else { return Ok(()) };
        if ty != SCM_RIGHTS || level != SOL_SOCKET || cmsg_len != len {
            return Ok(());
        }
        for i in 0..u64::from((cmsg_len - CMSG_HDR) / 4) {
            let Ok(fd) = m.read_u32(control + u64::from(CMSG_HDR) + i * 4) else { return Ok(()) };
            let fd = fd as i32;
            let Ok(file) = self.fds.get(fd) else { return Ok(()) };
            if Arc::clone(&file.handle).as_kqueue().is_some() {
                return Ok(());
            }
            if let Some(g) = self.fds.guard(fd).filter(|g| g.has(attr::SOCKET_IPC)) {
                return Err(self.darwin_fp_guard_exception(fd, g, flavor::SOCKET_IPC));
            }
        }
        Ok(())
    }

    /// `fp_lookup_guarded`: EINVAL for an unguarded descriptor, EPERM (not
    /// an exception) for the wrong guard.
    fn darwin_fp_lookup_guarded(&mut self, fd: i32, guard: u64) -> Result<(), Errno> {
        self.fds.get(fd)?;
        match self.fds.guard(fd) {
            None => Err(Errno::EINVAL),
            Some(g) if g.guard != guard => Err(Errno::EPERM),
            Some(_) => Ok(()),
        }
    }

    /// A guard from a call's arguments: `guardflags` must hold what is
    /// required and nothing unknown, and the value cannot be zero.
    fn darwin_guard_copyin(&mut self, m: &GuestMem<'_>, at: u64, guardflags: u32) -> Result<FdGuard, Errno> {
        if guardflags & attr::REQUIRED != attr::REQUIRED || guardflags & !attr::ALL != 0 {
            return Err(Errno::EINVAL);
        }
        let guard = m.read_u64(at)?;
        if guard == 0 {
            return Err(Errno::EINVAL);
        }
        Ok(FdGuard { guard, attrs: guardflags as u16 })
    }

    /// `open1` for an `open` or `openat` a plain renumbering cannot do:
    /// An open's O_EXLOCK or O_SHLOCK once its file is open, or its
    /// descriptor.
    pub(crate) fn darwin_open_finish_locks(&mut self, m: &mut GuestMem<'_>, fd: i32, dflags: u64) -> SyscallOutcome {
        if dflags & O_LOCKS != 0 {
            return self.darwin_open_lock(m, fd, dflags);
        }
        let _ = super::set_result(m, self.ctx_addr, fd as u64);
        SyscallOutcome::Continue
    }

    /// [`Kernel::darwin_open1`], then O_EXLOCK or O_SHLOCK taken after.
    pub(crate) fn darwin_open_finish(&mut self, m: &mut GuestMem<'_>, raw: u64, a: [u64; 6], guard: Option<FdGuard>) -> SyscallOutcome {
        let at = if raw == sys::OPEN || raw == sys::OPEN_NOCANCEL { 1 } else { 2 };
        let dflags = a[at];
        match self.darwin_open1(m, raw, a, guard) {
            Ok(fd) => {
                // A devfs node's vn_open: its access, its device's open.
                if let Err(e) = self.darwin_devnode_open(fd) {
                    let _ = self.fds.close(fd);
                    let _ = super::set_result(m, self.ctx_addr, e.as_return());
                    return SyscallOutcome::Continue;
                }
                // spec_open: a terminal device's own open, which may wait.
                if self.darwin_tty_of(fd as u64).is_some_and(|(_, d)| !d.is_open()) {
                    if let Some(out) = self.darwin_tty_open(m, fd, dflags) {
                        return out;
                    }
                }
                if dflags & O_LOCKS != 0 {
                    return self.darwin_open_lock(m, fd, dflags);
                }
                let _ = super::set_result(m, self.ctx_addr, fd as u64);
            }
            Err(e) => {
                let _ = super::set_result(m, self.ctx_addr, e.as_return());
            }
        }
        SyscallOutcome::Continue
    }

    /// `open1` up to the lock (`open`, `openat`, or a spawn's PSFA_OPEN, as
    /// `raw` and its arguments `a`): the access mode's checks,
    /// `vn_open_auth`'s O_NOFOLLOW_ANY and O_SYMLINK, the open, then
    /// O_CLOFORK and the guard set before the descriptor is seen.
    pub(crate) fn darwin_open1(&mut self, m: &mut GuestMem<'_>, raw: u64, a: [u64; 6], guard: Option<FdGuard>) -> Result<i32, Errno> {
        let at = if raw == sys::OPEN || raw == sys::OPEN_NOCANCEL { 1 } else { 2 };
        let dflags = a[at];
        self.darwin_open_mode(dflags)?;
        // A creation whose last component ends in a slash: namei's ENOENT.
        let (dirfd, path) = if at == 1 { (super::bsd::AT_FDCWD as u64, a[0]) } else { (a[0], a[1]) };
        if dflags & super::kern::DARWIN_O_CREAT != 0 && self.darwin_slash_creation(m, dirfd, path) {
            return Err(Errno::ENOENT);
        }
        let symlink = self.darwin_open_links(m, at, &a)?;
        let mut la = a;
        la[at] &= !OPEN_FINISHED;
        // openat_internal's creation mode, `cmode & ACCESSPERMS`: what the
        // umask leaves of the access permissions, never a set-id or the
        // sticky bit.
        la[at + 1] &= super::fsops::ACCESSPERMS;
        let n = super::bsd::translate(raw, &mut la);
        if symlink {
            // The translated call is openat's. The name is opened, not
            // what it names.
            la[2] = (la[2] & !3) | crate::fs::oflags::O_PATH | 0x8000;
        }
        let fd = self.canonical(m, n, la)? as i32;
        if dflags & O_CLOFORK != 0 {
            let _ = self.fds.set_clofork(fd, true);
        }
        if let Some(g) = guard {
            let _ = self.fds.change_guard(fd, |slot, _, _| {
                *slot = Some(g);
                Ok(())
            });
        }
        Ok(fd)
    }

    /// `open1`'s access mode: both bits (O_ACCMODE), or O_EXEC with a read
    /// or write mode (FEXEC cannot be told from FREAD), are EINVAL. An
    /// execute-only open's descriptor (FEXEC, or O_SEARCH's FSEARCH)
    /// neither reads nor writes yet keeps the vnode's other operations,
    /// which no descriptor here does; it is reported.
    fn darwin_open_mode(&mut self, flags: u64) -> Result<(), Errno> {
        let amode = flags & 3;
        if amode == 3 || (amode != 0 && flags & O_EXEC != 0) {
            return Err(Errno::EINVAL);
        }
        if flags & O_EXEC != 0 {
            let what = if flags & O_DIRECTORY != 0 { "O_SEARCH (a search-only descriptor)" } else { "O_EXEC (an execute-only descriptor)" };
            self.darwin_unimplemented(format!("an open with {what}"));
            return Err(Errno::EINVAL);
        }
        Ok(())
    }

    /// `vn_open_auth`'s walk of an open's path for O_NOFOLLOW_ANY (ELOOP at
    /// the first link in it), and whether O_SYMLINK finds a link at its end.
    fn darwin_open_links(&mut self, m: &GuestMem<'_>, at: usize, a: &[u64; 6]) -> Result<bool, Errno> {
        const MAXPATHLEN: usize = 1024;
        let flags = a[at];
        if flags & (O_SYMLINK | O_NOFOLLOW_ANY) == 0 {
            return Ok(false);
        }
        if flags & O_NOFOLLOW_ANY != 0 && flags & (O_SYMLINK | O_NOFOLLOW) != 0 {
            return Err(Errno::EINVAL);
        }
        let (dir, path) = if at == 1 { (super::bsd::AT_FDCWD as u64, a[0]) } else { (a[0], a[1]) };
        let raw = m.read_cstr(path, MAXPATHLEN)?;
        let given = std::str::from_utf8(&raw).map_err(|_| Errno::EINVAL)?;
        let abs = self.path_io().at_path_str(super::bsd::dirfd(dir) as i32, given)?;
        if flags & O_NOFOLLOW_ANY != 0 {
            let mut prefix = String::new();
            for part in abs.split('/').filter(|p| !p.is_empty()) {
                prefix.push('/');
                prefix.push_str(part);
                match self.vfs.metadata_nofollow(&prefix) {
                    Ok(md) if md.file_type == crate::vfs::FileType::Symlink => return Err(Errno::ELOOP),
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
        Ok(flags & O_SYMLINK != 0 && self.vfs.metadata_nofollow(&abs).is_ok_and(|md| md.file_type == crate::vfs::FileType::Symlink))
    }

    /// `guarded_open_np`, `guarded_open_dprotected_np`,
    /// `open_dprotected_np` and `openat_dprotected_np`. The filesystems
    /// here keep no data protection class: a class for a file the open
    /// makes is reported, as F_SETPROTECTIONCLASS is, and so is opening a
    /// file's raw or authenticated contents.
    pub(crate) fn darwin_open_protected(&mut self, m: &mut GuestMem<'_>, raw: u64, a: &[u64; 6]) -> SyscallOutcome {
        match self.darwin_open_protected_args(m, raw, a) {
            Ok((call, args, guard)) => self.darwin_open_finish(m, call, args, guard),
            Err(e) => {
                let _ = super::set_result(m, self.ctx_addr, e.as_return());
                SyscallOutcome::Continue
            }
        }
    }

    #[allow(clippy::type_complexity)]
    fn darwin_open_protected_args(&mut self, m: &GuestMem<'_>, raw: u64, a: &[u64; 6]) -> Result<(u64, [u64; 6], Option<FdGuard>), Errno> {
        // A seventh argument is in the register after the sixth.
        let seventh = |k: &Kernel, m: &GuestMem<'_>| m.read_u64(k.ctx_addr + gex_abi::ctx::x(k.darwin_arg_base + 6) as u64).unwrap_or(0);
        let raw_dp = |k: &mut Kernel, flags: u64, dpflags: u64, kinds: u64| -> Result<(), Errno> {
            if dpflags & kinds == 0 {
                return Ok(());
            }
            if flags & (O_RDWR | O_WRONLY) != 0 {
                return Err(Errno::EINVAL);
            }
            k.darwin_unimplemented(format!("an open of a file's raw or authenticated contents (dpflags {dpflags:#x}, content protection)"));
            Err(Errno::EINVAL)
        };
        // A class for a file the open makes (openat_dprotected_internal's
        // va_dataprotect_class): the key store's, which the filesystems
        // here have no attribute for. An existing file keeps its own, and
        // PROTECTION_CLASS_DEFAULT asks for none.
        let new_class = |k: &mut Kernel, m: &GuestMem<'_>, dir: u64, path: u64, flags: u64, class: u64| -> Result<(), Errno> {
            const PROTECTION_CLASS_DEFAULT: i32 = -1;
            if flags & O_CREAT == 0 || class as u32 as i32 == PROTECTION_CLASS_DEFAULT {
                return Ok(());
            }
            let abs = k.path_io().at_path(m, super::bsd::dirfd(dir) as i32, path)?;
            if k.vfs.metadata(&abs).is_ok() {
                return Ok(());
            }
            k.darwin_unimplemented(format!("a new file's data protection class {} (the key store's)", class as u32 as i32));
            Err(Errno::EINVAL)
        };
        let cwd = super::bsd::AT_FDCWD as u64;
        let rawness = O_DP_GETRAWENCRYPTED | O_DP_GETRAWUNENCRYPTED;
        match raw {
            sys::GUARDED_OPEN_NP | sys::GUARDED_OPEN_DPROTECTED_NP => {
                let flags = a[3] & 0xffff_ffff;
                if flags & O_CLOEXEC == 0 {
                    return Err(Errno::EINVAL);
                }
                let g = self.darwin_guard_copyin(m, a[1], a[2] as u32)?;
                let mode = if raw == sys::GUARDED_OPEN_NP {
                    a[4]
                } else {
                    new_class(self, m, cwd, a[0], flags, a[4])?;
                    raw_dp(self, flags, a[5] & 0xffff_ffff, rawness)?;
                    seventh(self, m)
                };
                Ok((sys::OPEN_NOCANCEL, [a[0], flags | O_CLOFORK, mode, 0, 0, 0], Some(g)))
            }
            sys::OPEN_DPROTECTED_NP => {
                if a[3] & O_DP_AUTHENTICATE != 0 {
                    return Err(Errno::EINVAL);
                }
                new_class(self, m, cwd, a[0], a[1] & 0xffff_ffff, a[2])?;
                raw_dp(self, a[1], a[3] & 0xffff_ffff, rawness)?;
                Ok((sys::OPEN_NOCANCEL, [a[0], a[1] & 0xffff_ffff, a[4], 0, 0, 0], None))
            }
            _ => {
                // openat_dprotected_np(fd, path, flags, class, dpflags, mode, authfd).
                let (flags, dpflags) = (a[2] & 0xffff_ffff, a[4] & 0xffff_ffff);
                if dpflags & O_DP_AUTHENTICATE != 0 && flags & O_CREAT != 0 {
                    return Err(Errno::EINVAL);
                }
                new_class(self, m, a[0], a[1], flags, a[3])?;
                raw_dp(self, flags, dpflags, rawness | O_DP_AUTHENTICATE)?;
                Ok((sys::OPENAT_NOCANCEL, [a[0], a[1], flags, a[5], 0, 0], None))
            }
        }
    }

    /// `guarded_kqueue_np(guard, guardflags)`.
    pub(crate) fn darwin_guarded_kqueue(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        use super::ipc::{KQueue, Kq};
        let g = self.darwin_guard_copyin(m, a[0], a[1] as u32)?;
        let fd = <Kq as KQueue>::kqueue(self)?;
        self.fds.change_guard(fd as i32, |slot, _, _| {
            *slot = Some(g);
            Ok(())
        })?;
        Ok(fd)
    }

    /// `guarded_close_np(fd, guard)`.
    pub(crate) fn darwin_guarded_close(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        let fd = a[0] as i32;
        let uguard = m.read_u64(a[1])?;
        self.darwin_fp_lookup_guarded(fd, uguard)?;
        self.darwin_closing(fd);
        self.canonical(m, crate::syscalls::nr::CLOSE, [a[0], 0, 0, 0, 0, 0])
    }

    /// `change_fdguard_np(fd, guard, guardflags, nguard, nguardflags,
    /// fdflagsp)`.
    pub(crate) fn darwin_change_fdguard(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        let (fd, guard, guardflags, nguard, nguardflags, fdflagsp) = (a[0] as i32, a[1], a[2] as u32, a[3], a[4] as u32, a[5]);
        let oldg = if guard != 0 { m.read_u64(guard)? } else { 0 };
        let newg = if nguard != 0 { m.read_u64(nguard)? } else { 0 };
        let nfdflags = if fdflagsp != 0 { m.read_u32(fdflagsp)? } else { 0 };
        let file = self.fds.get(fd)?;
        if fdflagsp != 0 {
            let mut ofl = 0;
            if self.fds.cloexec(fd)? {
                ofl |= FD_CLOEXEC;
            }
            if self.fds.clofork(fd) {
                ofl |= FD_CLOFORK;
            }
            m.write_u32(fdflagsp, ofl)?;
        }
        // DTYPE_VNODE, PIPE, SOCKET and KQUEUE: not a POSIX shared memory
        // object.
        let guardable = Arc::clone(&file.handle).as_posix_shm().is_none();
        self.fds.change_guard(fd, |slot, cloexec, clofork| {
            if slot.is_some() {
                if guard == 0 || guardflags == 0 {
                    return Err(Errno::EINVAL);
                }
                if oldg == 0 {
                    return Err(Errno::EPERM);
                }
            } else if guard != 0 || guardflags != 0 {
                return Err(Errno::EINVAL);
            }
            if nguard != 0 {
                if newg == 0 || nguardflags & attr::REQUIRED != attr::REQUIRED || nguardflags & !attr::ALL != 0 {
                    return Err(Errno::EINVAL);
                }
                let new = FdGuard { guard: newg, attrs: nguardflags as u16 };
                match *slot {
                    Some(g) if oldg == g.guard && guardflags == u32::from(g.attrs) => {
                        // FD_CLOFORK may be asked for; GUARD_CLOSE implies it.
                        if g.has(attr::CLOSE) {
                            *clofork = false;
                        }
                        *slot = Some(new);
                        if new.has(attr::CLOSE) || nfdflags & FD_CLOFORK != 0 {
                            *clofork = true;
                        }
                    }
                    Some(_) => return Err(Errno::EPERM),
                    None if !guardable => return Err(Errno::EOPNOTSUPP),
                    None => {
                        *slot = Some(new);
                        if new.has(attr::CLOSE) {
                            *clofork = true;
                        }
                        *cloexec = true;
                    }
                }
                return Ok(0);
            }
            let Some(g) = *slot else { return Err(Errno::EINVAL) };
            if nguardflags != 0 {
                return Err(Errno::EINVAL);
            }
            if oldg != g.guard || guardflags != u32::from(g.attrs) {
                return Err(Errno::EPERM);
            }
            *slot = None;
            *clofork = nfdflags & FD_CLOFORK != 0;
            *cloexec = nfdflags & FD_CLOEXEC != 0;
            Ok(0)
        })
    }
}
