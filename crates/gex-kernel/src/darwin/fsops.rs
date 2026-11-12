//! The filesystem calls that change names, modes and times, by the rules
//! of XNU's `bsd/vfs/vfs_syscalls.c`, and `getdirentries64`.
//!
//! The filesystems here keep no file owners and check no permissions
//! (`vnode_authorize` has nothing to go by), so the `chown` family is
//! refused and reported rather than answered.

use super::bsd::dirfd;
use super::sysno as sys;
use crate::errno::Errno;
use crate::syscalls::{nr, Kernel};
use crate::GuestMem;

/// Darwin's `AT_*` (`bsd/sys/fcntl.h`).
const AT_SYMLINK_NOFOLLOW: u64 = 0x20;
const AT_SYMLINK_FOLLOW: u64 = 0x40;
const AT_SYMLINK_NOFOLLOW_ANY: u64 = 0x800;
/// Linux's.
const L_AT_SYMLINK_FOLLOW: u64 = 0x400;
const L_AT_REMOVEDIR: u64 = 0x200;

/// `renameatx_np`'s flags (`bsd/sys/stdio.h`).
const RENAME_SECLUDE: u64 = 0x1;
const RENAME_SWAP: u64 = 0x2;
const RENAME_EXCL: u64 = 0x4;
const RENAME_NOFOLLOW_ANY: u64 = 0x10;

/// `ACCESSPERMS`, `ALLPERMS`.
pub(super) const ACCESSPERMS: u64 = 0o777;
const ALLPERMS: u64 = 0o7777;

/// `GETDIRENTRIES64_EXTENDED_BUFSIZE`, `GETDIRENTRIES_MAXBUFSIZE`,
/// `GETDIRENTRIES64_EOF`.
const GETDIRENTRIES64_EXTENDED_BUFSIZE: u64 = 1024;
const GETDIRENTRIES_MAXBUFSIZE: u64 = 128 * 1024 * 1024;
const GETDIRENTRIES64_EOF: u32 = 1;

/// `DIRENT64_LEN(namlen)`: `struct direntry` is 1048 bytes with its
/// 1024-byte name, 8-aligned.
fn dirent64_len(namlen: usize) -> usize {
    (1048 + namlen - 1023 + 7) & !7
}

/// `DIRENT_LEN(namlen)`: the 4-aligned 32-bit `struct dirent` a filesystem
/// without extended readdir fills (264 bytes with its 256-byte name).
fn dirent_len(namlen: usize) -> usize {
    (264 + (namlen + 1) - 256 + 3) & !3
}

/// Whether `raw` is a vectored read (false) or write (true).
pub(crate) fn vectored(raw: u64) -> Option<bool> {
    match raw {
        sys::READV | sys::READV_NOCANCEL | sys::PREADV | sys::PREADV_NOCANCEL => Some(false),
        sys::WRITEV | sys::WRITEV_NOCANCEL | sys::PWRITEV | sys::PWRITEV_NOCANCEL => Some(true),
        _ => None,
    }
}

impl Kernel {
    /// `kdebug_typefilter(addr, size)`: the filter's page, read-only, its
    /// zeros saying no event passes (ktrace is off here, and the memory
    /// entry of the real thing would be shared with it).
    pub(crate) fn darwin_kdebug_typefilter(&mut self, m: &mut GuestMem<'_>, addr: u64, size: u64) -> Result<u64, Errno> {
        const TYPEFILTER_ALLOC_SIZE: u64 = 16384;
        if addr == 0 || size == 0 {
            return Err(Errno::EINVAL);
        }
        let at = self.darwin_vm_allocate_anywhere(m, TYPEFILTER_ALLOC_SIZE).map_err(|_| Errno::ENOMEM)?;
        self.vm_protect(m, at, TYPEFILTER_ALLOC_SIZE, false, super::mach::prot::READ);
        self.dtask.vm.update(at, at + TYPEFILTER_ALLOC_SIZE, |a| a.inherit = super::vm::inherit::SHARE);
        m.write_u64(addr, at)?;
        Ok(0)
    }

    /// `readv_uio`'s and `writev_uio`'s count and copyin of the vector.
    pub(crate) fn darwin_uio_copyin(&self, m: &GuestMem<'_>, iov: u64, cnt: i32) -> Result<Vec<(u64, u64)>, Errno> {
        const UIO_MAXIOV: i32 = 1024;
        if cnt <= 0 || cnt > UIO_MAXIOV {
            return Err(Errno::EINVAL);
        }
        let mut v = Vec::with_capacity(cnt as usize);
        for i in 0..u64::from(cnt as u32) {
            v.push((m.read_u64(iov + 16 * i)?, m.read_u64(iov + 16 * i + 8)?));
        }
        Ok(v)
    }

    /// A vectored call's way in: its vector, the descriptor and its access
    /// (`preparefileread`, `preparefilewrite`), then
    /// `uio_calculateresid_user`'s limit on its lengths.
    pub(crate) fn darwin_uio_check(&mut self, m: &GuestMem<'_>, write: bool, a: &[u64; 6]) -> Result<(), Errno> {
        let vecs = self.darwin_uio_copyin(m, a[1], a[2] as i32)?;
        let file = self.fds.get(a[0] as i32)?;
        if !(if write { file.writable } else { file.readable }) {
            return Err(Errno::EBADF);
        }
        let mut resid = 0u64;
        for (_, len) in vecs {
            if len > i64::MAX as u64 {
                return Err(Errno::EINVAL);
            }
            resid += len;
            if resid > i64::MAX as u64 {
                return Err(Errno::EINVAL);
            }
        }
        Ok(())
    }

    /// `sys_preadv` and `sys_pwritev`: `valid_for_random_access`, then each
    /// vector transferred at the offset the ones before it reached. Bytes
    /// already moved make an interrupted call a short one (`fp_readv`).
    pub(crate) fn darwin_prwv(&mut self, m: &mut GuestMem<'_>, write: bool, a: &[u64; 6]) -> Result<u64, Errno> {
        let fd = a[0] as i32;
        let file = self.fds.get(fd)?;
        if !(if write { file.writable } else { file.readable }) {
            return Err(Errno::EBADF);
        }
        let random_access = !matches!(file.handle.metadata().map(|md| md.file_type), Err(_) | Ok(crate::vfs::FileType::Socket | crate::vfs::FileType::Fifo))
            && std::sync::Arc::clone(&file.handle).as_kqueue().is_none()
            && std::sync::Arc::clone(&file.handle).as_posix_shm().is_none();
        if !random_access {
            return Err(Errno::ESPIPE);
        }
        if file.is_tty() {
            return Err(Errno::ENXIO);
        }
        let call = if write { nr::PWRITE64 } else { nr::PREAD64 };
        let mut total = 0u64;
        for (base, len) in self.darwin_uio_copyin(m, a[1], a[2] as i32)? {
            if len == 0 {
                continue;
            }
            match self.canonical(m, call, [a[0], base, len, a[3].wrapping_add(total), 0, 0]) {
                Ok(n) => {
                    total += n;
                    if n < len {
                        break;
                    }
                }
                Err(e) if total > 0 && matches!(e, Errno::EINTR | Errno::EAGAIN) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(total)
    }

    /// `__pthread_chdir(path)`: this thread's own working directory
    /// (`uu_cdir`), which a failed call leaves unset.
    pub(crate) fn darwin_pthread_chdir(&mut self, m: &mut GuestMem<'_>, path: u64) -> Result<u64, Errno> {
        let me = self.ctx_addr;
        let had = self.thread_fs.of(me).is_some();
        if !had {
            self.thread_fs.set(me, Some(std::sync::Arc::new(self.proc_fs.copy())));
        }
        let r = self.canonical(m, nr::CHDIR, [path, 0, 0, 0, 0, 0]);
        if r.is_err() && !had {
            self.thread_fs.set(me, None);
        }
        r
    }

    /// `__pthread_fchdir(fd)`: this thread's directory set from a
    /// descriptor, or with -1 back to the process's, EBADF if it had none.
    pub(crate) fn darwin_pthread_fchdir(&mut self, m: &mut GuestMem<'_>, fd: i32) -> Result<u64, Errno> {
        let me = self.ctx_addr;
        let had = self.thread_fs.of(me).is_some();
        if fd == -1 {
            if !had {
                return Err(Errno::EBADF);
            }
            self.thread_fs.set(me, None);
            return Ok(0);
        }
        if !had {
            self.thread_fs.set(me, Some(std::sync::Arc::new(self.proc_fs.copy())));
        }
        let r = self.canonical(m, nr::FCHDIR, [fd as u64, 0, 0, 0, 0, 0]);
        if r.is_err() && !had {
            self.thread_fs.set(me, None);
        }
        r
    }

    /// `renameatx_np`'s RENAME_SWAP: neither final link followed, both
    /// names exchanged by the volume in one step.
    fn darwin_rename_swap(&mut self, m: &GuestMem<'_>, a: &[u64; 6], nofollow_any: bool) -> Result<u64, Errno> {
        if nofollow_any {
            self.darwin_no_link_on_the_way(m, a[0], a[1])?;
            self.darwin_no_link_on_the_way(m, a[2], a[3])?;
        }
        let from = self.path_io().at_path(m, dirfd(a[0]) as i32, a[1])?;
        let to = self.path_io().at_path(m, dirfd(a[2]) as i32, a[3])?;
        self.vfs.metadata_nofollow(&from)?;
        self.vfs.metadata_nofollow(&to)?;
        match self.vfs.swap_names(&from, &to) {
            Ok(()) => Ok(0),
            Err(Errno::EOPNOTSUPP) => {
                self.darwin_unimplemented("RENAME_SWAP on a filesystem with no exchange of names".into());
                Err(Errno::EOPNOTSUPP)
            }
            Err(e) => Err(e),
        }
    }

    /// `mount(type, dir, flags, data)`, of a bind mount; another file
    /// system's is reported.
    pub(crate) fn darwin_mount(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        const MFSNAMELEN: usize = 15;
        const MAXPATHLEN: usize = 1024;
        const MNT_UPDATE: u64 = 0x0001_0000;
        const BINDFS_ENTITLEMENT: &str = "com.apple.private.bindfs-allow";
        let fstype = m.read_cstr(a[0], MFSNAMELEN)?;
        let dir = String::from_utf8_lossy(&m.read_cstr(a[1], MAXPATHLEN)?).into_owned();
        let at = self.path_io().at_path_str(dirfd(super::bsd::AT_FDCWD as u64) as i32, &dir)?;
        if self.vfs.metadata(&at)?.file_type != crate::vfs::FileType::Directory {
            return Err(Errno::ENOTDIR);
        }
        self.darwin_suser()?;
        if fstype != b"bindfs" {
            self.darwin_unimplemented(format!("mount of {:?} at {dir}", String::from_utf8_lossy(&fstype)));
            return Err(Errno::EOPNOTSUPP);
        }
        if a[2] & MNT_UPDATE != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        if !self.darwin_task_entitled(BINDFS_ENTITLEMENT) {
            return Err(Errno::EPERM);
        }
        let from = String::from_utf8_lossy(&m.read_cstr(a[3], MAXPATHLEN - 1)?).into_owned();
        let from = self.path_io().at_path_str(dirfd(super::bsd::AT_FDCWD as u64) as i32, &from)?;
        self.vfs.metadata(&from)?;
        match self.vfs.bound_subtree(&from)? {
            Some(fs) => {
                self.vfs.mount(&at, fs);
                Ok(0)
            }
            None => {
                self.darwin_unimplemented(format!("a bind mount of {from}, which is on a file system with no subtree to give"));
                Err(Errno::EOPNOTSUPP)
            }
        }
    }

    /// `fsctl(path, cmd, data, options)`.
    pub(crate) fn darwin_fsctl(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        const MAXPATHLEN: usize = 1024;
        const FSOPT_NOFOLLOW: u64 = 1;
        // A file that is not open cannot be open only once.
        const FSIOC_FD_ONLY_OPEN_ONCE: u64 = 0xc004_4115;
        let (path, cmd, data, options) = (a[0], a[1], a[2], a[3]);
        if cmd == FSIOC_FD_ONLY_OPEN_ONCE {
            return Err(Errno::EINVAL);
        }
        let raw = m.read_cstr(path, MAXPATHLEN)?;
        let given = std::str::from_utf8(&raw).map_err(|_| Errno::EINVAL)?;
        let abs = self.path_io().at_path_str(dirfd(super::bsd::AT_FDCWD as u64) as i32, given)?;
        let md = if options & FSOPT_NOFOLLOW == 0 { self.vfs.metadata(&abs) } else { self.vfs.metadata_nofollow(&abs) }?;
        self.darwin_fsctl_checked(m, md.file_type, cmd, data)
    }

    /// `ffsctl(fd, cmd, data, options)`.
    pub(crate) fn darwin_ffsctl(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        let file = self.fds.get(a[0] as i32)?;
        // `file_vnode`'s refusal of what is not one.
        if self.darwin_vnode_of(&file).is_none() {
            return Err(Errno::EINVAL);
        }
        let md = file.handle.metadata()?;
        self.darwin_fsctl_checked(m, md.file_type, a[1], a[2])
    }

    /// `mac_mount_check_fsctl`, then `fsctl_internal`.
    fn darwin_fsctl_checked(&mut self, m: &mut GuestMem<'_>, kind: crate::vfs::FileType, cmd: u64, data: u64) -> Result<u64, Errno> {
        const IOCPARM_MASK: u64 = 0x1fff;
        const IOCPARM_MAX: u64 = IOCPARM_MASK + 1;
        const IOC_OUT: u64 = 0x4000_0000;
        const IOC_IN: u64 = 0x8000_0000;
        // What APFS answers itself: whether the volume's device reaches the
        // kernel through a "Virtual Interface", as a disk image's does. The
        // root's is the machine's own storage.
        const APFSIOC_VIRTUAL_INTERFACE: u64 = 0x4008_4a6a;
        let e = self.darwin_mac_check_fsctl(cmd);
        if e != 0 {
            return Err(super::errno::errno_of(e as i32));
        }
        if kind == crate::vfs::FileType::CharDevice {
            return Err(Errno::ENOTTY);
        }
        let size = (cmd >> 16) & IOCPARM_MASK;
        if size > IOCPARM_MAX {
            return Err(Errno::EINVAL);
        }
        // Copied in before anything looks at the command.
        if cmd & IOC_IN != 0 && size != 0 {
            m.read(data, size as usize)?;
        }
        if cmd != APFSIOC_VIRTUAL_INTERFACE {
            self.darwin_unimplemented(format!("fsctl command {cmd:#x}"));
            return Err(Errno::ENOTTY);
        }
        if cmd & IOC_OUT != 0 {
            m.write(data, &0u64.to_le_bytes())?;
        }
        Ok(0)
    }

    /// `fsync_common`: a vnode's writes pushed to its file (ENOTSUP for what
    /// is not one, as `fp_getfvp` says it). VNOP_FSYNC pushes the file's
    /// dirty pages, mapped ones among them, so this process's shared
    /// mappings of it are written back; what it has written goes through
    /// to the file already.
    pub(crate) fn darwin_fsync(&mut self, m: &mut GuestMem<'_>, fd: i32) -> Result<u64, Errno> {
        let file = self.fds.get(fd)?;
        if self.darwin_vnode_of(&file).is_none() {
            return Err(Errno::EOPNOTSUPP);
        }
        let mapped: Vec<(u64, u64)> = self.mem.lock().log.shared_maps.iter().filter(|s| s.file.same_file(&file)).map(|s| (s.start, s.len)).collect();
        for (start, len) in mapped {
            self.map_io().flush_shared(m, start, len)?;
        }
        Ok(0)
    }

    /// The filesystem calls this file serves; `None` for any other.
    pub(crate) fn darwin_fs_call(&mut self, m: &mut GuestMem<'_>, raw: u64, a: &[u64; 6]) -> Option<Result<u64, Errno>> {
        let cwd = dirfd(super::bsd::AT_FDCWD as u64);
        Some(match raw {
            // mkdir: the mode's ACCESSPERMS under the umask.
            sys::MKDIR => self.canonical(m, nr::MKDIRAT, [cwd, a[0], a[1] & ACCESSPERMS, 0, 0, 0]),
            sys::MKDIRAT => self.canonical(m, nr::MKDIRAT, [dirfd(a[0]), a[1], a[2] & ACCESSPERMS, 0, 0, 0]),
            sys::RMDIR => self.canonical(m, nr::UNLINKAT, [cwd, a[0], L_AT_REMOVEDIR, 0, 0, 0]),
            sys::CHDIR => self.canonical(m, nr::CHDIR, [a[0], 0, 0, 0, 0, 0]),
            sys::FCHDIR => self.canonical(m, nr::FCHDIR, [a[0], 0, 0, 0, 0, 0]),
            // umask1: ALLPERMS of it kept; the old one back.
            sys::UMASK => self.canonical(m, nr::UMASK, [a[0] & ALLPERMS, 0, 0, 0, 0, 0]),
            sys::SYMLINK => self.darwin_creating(m, cwd, a[1]).and_then(|()| self.canonical(m, nr::SYMLINKAT, [a[0], cwd, a[1], 0, 0, 0])),
            sys::SYMLINKAT => self.darwin_creating(m, a[1], a[2]).and_then(|()| self.canonical(m, nr::SYMLINKAT, [a[0], dirfd(a[1]), a[2], 0, 0, 0])),
            // link follows a symlink it names, as linkat with
            // AT_SYMLINK_FOLLOW does; linkat takes that flag alone.
            sys::LINK => self.darwin_creating(m, cwd, a[1]).and_then(|()| self.canonical(m, nr::LINKAT, [cwd, a[0], cwd, a[1], L_AT_SYMLINK_FOLLOW, 0])),
            sys::LINKAT => {
                if a[4] & !AT_SYMLINK_FOLLOW != 0 {
                    Err(Errno::EINVAL)
                } else {
                    let f = if a[4] & AT_SYMLINK_FOLLOW != 0 { L_AT_SYMLINK_FOLLOW } else { 0 };
                    self.darwin_creating(m, a[2], a[3]).and_then(|()| self.canonical(m, nr::LINKAT, [dirfd(a[0]), a[1], dirfd(a[2]), a[3], f, 0]))
                }
            }
            sys::RENAME => self.darwin_renaming(m, cwd, a[0], cwd, a[1]).and_then(|()| self.canonical(m, nr::RENAMEAT2, [cwd, a[0], cwd, a[1], 0, 0])),
            sys::RENAMEAT => self.darwin_renaming(m, a[0], a[1], a[2], a[3]).and_then(|()| self.canonical(m, nr::RENAMEAT2, [dirfd(a[0]), a[1], dirfd(a[2]), a[3], 0, 0])),
            // RENAME_EXCL is Linux's RENAME_NOREPLACE.
            sys::RENAMEATX_NP => {
                let flags = a[4] as u32 as u64;
                if flags & !(RENAME_SECLUDE | RENAME_EXCL | RENAME_SWAP | RENAME_NOFOLLOW_ANY) != 0 || flags & (RENAME_EXCL | RENAME_SWAP) == RENAME_EXCL | RENAME_SWAP {
                    Err(Errno::EINVAL)
                } else if flags & RENAME_SECLUDE != 0 {
                    self.darwin_unimplemented(format!("renameatx_np flags {flags:#x} (RENAME_SECLUDE)"));
                    Err(Errno::EINVAL)
                } else if flags & RENAME_SWAP != 0 {
                    self.darwin_rename_swap(m, a, flags & RENAME_NOFOLLOW_ANY != 0)
                } else {
                    // RENAME_NOFOLLOW_ANY: both lookups NAMEI_NOFOLLOW_ANY,
                    // neither following its last component.
                    let r = if flags & RENAME_NOFOLLOW_ANY != 0 { self.darwin_no_link_on_the_way(m, a[0], a[1]).and_then(|()| self.darwin_no_link_on_the_way(m, a[2], a[3])) } else { Ok(()) };
                    let l = if flags & RENAME_EXCL != 0 { 1 } else { 0 };
                    r.and_then(|()| self.darwin_renaming(m, a[0], a[1], a[2], a[3])).and_then(|()| self.canonical(m, nr::RENAMEAT2, [dirfd(a[0]), a[1], dirfd(a[2]), a[3], l, 0]))
                }
            }
            // The mode's ALLPERMS.
            sys::CHMOD => self.canonical(m, nr::FCHMODAT, [cwd, a[0], a[1] & ALLPERMS, 0, 0, 0]),
            sys::FCHMOD => self.canonical(m, nr::FCHMOD, [a[0], a[1] & ALLPERMS, 0, 0, 0, 0]),
            sys::FCHMODAT => {
                let flag = a[3] as u32 as u64;
                if flag & !(AT_SYMLINK_NOFOLLOW | AT_SYMLINK_NOFOLLOW_ANY) != 0 {
                    Err(Errno::EINVAL)
                } else {
                    // chmodat: AT_SYMLINK_NOFOLLOW_ANY looks up without
                    // following the last component and with no link on the
                    // way. A symlink's own mode (lchmod) is refused as the
                    // filesystems here keep none.
                    let r = if flag & AT_SYMLINK_NOFOLLOW_ANY != 0 { self.darwin_no_link_on_the_way(m, a[0], a[1]) } else { Ok(()) };
                    r.and_then(|()| self.canonical(m, nr::FCHMODAT, [dirfd(a[0]), a[1], a[2] & ALLPERMS, if flag & (AT_SYMLINK_NOFOLLOW | AT_SYMLINK_NOFOLLOW_ANY) != 0 { 0x100 } else { 0 }, 0, 0]))
                }
            }
            sys::CHOWN | sys::LCHOWN | sys::FCHOWN | sys::FCHOWNAT => self.darwin_chown(m, raw, a),
            sys::TRUNCATE => self.darwin_truncate(m, a[0], a[1] as i64),
            sys::MKFIFO | sys::MKFIFOAT | sys::MKNOD | sys::MKNODAT => {
                self.darwin_unimplemented("mkfifo and mknod (no named FIFO or device nodes in the filesystems here)".into());
                Err(Errno::EOPNOTSUPP)
            }
            sys::UTIMES => self.darwin_utimes(m, cwd as i32, a[0], a[1]),
            sys::FUTIMES => self.darwin_utimes(m, a[0] as i32, 0, a[1]),
            sys::GETDIRENTRIES64 => self.darwin_getdirentries64(m, a[0] as i32, a[1], a[2], a[3]),
            sys::GETDIRENTRIES => self.darwin_getdirentries(m, a[0] as i32, a[1], a[2], a[3]),
            // A directory's offset is where its next entry is read from;
            // a vnode's lseek is its knotes' NOTE_NONE (what it may read
            // changed).
            sys::LSEEK => {
                let Ok(file) = self.fds.get(a[0] as i32) else { return None };
                let ty = file.handle.metadata().map(|md| md.file_type);
                let dir = ty == Ok(crate::vfs::FileType::Directory);
                if !dir && (ty != Ok(crate::vfs::FileType::Regular) || a[2] > 2) {
                    return None;
                }
                let r = file.seek(a[1] as i64, a[2] as u32);
                if let Ok(pos) = r {
                    if dir {
                        file.set_dir_cursor(pos as usize);
                    }
                    if crate::vnote::any() {
                        if let Some(key) = self.darwin_vnote_key(&file) {
                            crate::vnote::post(key, crate::vnote::note::NONE);
                        }
                    }
                }
                r
            }
            _ => return None,
        })
    }

    /// `truncate(path, length)`: `truncate_validate_common`, then the file's
    /// size set.
    /// NAMEI_NOFOLLOW_ANY's check of the path at `path` from directory
    /// `fd` (Darwin's numbering), its last component not followed.
    /// `lookup_validate_creation_path` for a name being made that is not to
    /// be a directory: with a trailing slash, where nothing is, ENOENT.
    fn darwin_creating(&mut self, m: &GuestMem<'_>, fd: u64, path: u64) -> Result<(), Errno> {
        if self.darwin_slash_creation(m, fd, path) {
            return Err(Errno::ENOENT);
        }
        Ok(())
    }

    /// The same for a rename's new name, unless what moves is a directory
    /// (`WILLBEDIR`).
    fn darwin_renaming(&mut self, m: &GuestMem<'_>, from_fd: u64, from: u64, to_fd: u64, to: u64) -> Result<(), Errno> {
        if !self.darwin_is_dir(m, from_fd, from) && self.darwin_slash_creation(m, to_fd, to) {
            return Err(Errno::ENOENT);
        }
        Ok(())
    }

    /// `chown`, `lchown`, `fchown` and `fchownat` (`vn_chown_internal`):
    /// the file looked up as the call names it; an owner and group of -1
    /// (VNOVAL) each set nothing, which needs no authorization and changes
    /// nothing. Another owner or group is reported: the filesystems here
    /// keep none.
    fn darwin_chown(&mut self, m: &GuestMem<'_>, raw: u64, a: &[u64; 6]) -> Result<u64, Errno> {
        const VNOVAL: u32 = u32::MAX;
        let cwd = super::bsd::AT_FDCWD as u64;
        let (uid, gid) = match raw {
            sys::FCHOWNAT => (a[2] as u32, a[3] as u32),
            _ => (a[1] as u32, a[2] as u32),
        };
        match raw {
            sys::FCHOWN => {
                let file = self.fds.get(a[0] as i32)?;
                if self.darwin_vnode_of(&file).is_none() {
                    return Err(Errno::EINVAL);
                }
            }
            _ => {
                let (fd, path, follow) = match raw {
                    sys::CHOWN => (cwd, a[0], true),
                    sys::LCHOWN => (cwd, a[0], false),
                    _ => {
                        let flag = a[4] as u32 as u64;
                        if flag & !(AT_SYMLINK_NOFOLLOW | AT_SYMLINK_NOFOLLOW_ANY) != 0 {
                            return Err(Errno::EINVAL);
                        }
                        if flag & AT_SYMLINK_NOFOLLOW_ANY != 0 {
                            self.darwin_no_link_on_the_way(m, a[0], a[1])?;
                        }
                        (a[0], a[1], flag & (AT_SYMLINK_NOFOLLOW | AT_SYMLINK_NOFOLLOW_ANY) == 0)
                    }
                };
                let abs = self.path_io().at_path(m, dirfd(fd) as i32, path)?;
                if follow {
                    self.vfs.metadata(&abs)?;
                } else {
                    self.vfs.metadata_nofollow(&abs)?;
                }
            }
        }
        if uid == VNOVAL && gid == VNOVAL {
            return Ok(0);
        }
        self.darwin_unimplemented("the chown family setting an owner or group (the filesystems here keep none)".into());
        Err(Errno::EOPNOTSUPP)
    }

    pub(crate) fn darwin_no_link_on_the_way(&mut self, m: &GuestMem<'_>, fd: u64, path: u64) -> Result<(), Errno> {
        const MAXPATHLEN: usize = 1024;
        let raw = m.read_cstr(path, MAXPATHLEN)?;
        let given = std::str::from_utf8(&raw).map_err(|_| Errno::EINVAL)?;
        let pio = self.path_io();
        let base = if given.starts_with('/') { "/".to_string() } else { pio.at_path_str(dirfd(fd) as i32, ".")? };
        super::attrcall::no_link_on_the_way(&pio, &base, given, false)
    }

    fn darwin_truncate(&mut self, m: &mut GuestMem<'_>, path: u64, len: i64) -> Result<u64, Errno> {
        if len < 0 {
            return Err(Errno::EINVAL);
        }
        let fd = self.canonical(m, nr::OPENAT, [dirfd(super::bsd::AT_FDCWD as u64), path, crate::fs::oflags::O_WRONLY | 0x8_0000, 0, 0, 0])?;
        let r = self.canonical(m, nr::FTRUNCATE, [fd, len as u64, 0, 0, 0, 0]);
        let _ = self.fds.close(fd as i32);
        r
    }

    /// `utimes(path, tptr)` and `futimes(fd, tptr)`: two timevals, or now.
    fn darwin_utimes(&mut self, m: &mut GuestMem<'_>, dirfd: i32, path: u64, tptr: u64) -> Result<u64, Errno> {
        let (atime, mtime) = if tptr == 0 {
            let (s, ns) = (self.clock)();
            (Some((s as i64, ns as u32)), Some((s as i64, ns as u32)))
        } else {
            let tv = |at: u64| -> Result<(i64, u32), Errno> {
                let (s, us) = (m.read_u64(at)? as i64, m.read_u32(at + 8)? as i32);
                // setutimes takes the microseconds as they are; a time
                // with more than a second of them has no nanoseconds here.
                if !(0..1_000_000).contains(&us) {
                    return Err(Errno::EINVAL);
                }
                Ok((s, us as u32 * 1000))
            };
            (Some(tv(tptr)?), Some(tv(tptr + 16)?))
        };
        self.path_io().set_times_at(m, dirfd, path, atime, mtime, true)
    }

    /// `getdirentries_common`'s checks: a readable descriptor of a
    /// directory, and the buffer's size at most GETDIRENTRIES_MAXBUFSIZE.
    fn darwin_readdir_file(&mut self, fd: i32, bufsize: u64) -> Result<(std::sync::Arc<crate::file::OpenFile>, u64), Errno> {
        let file = self.fds.get(fd)?;
        if !file.readable {
            return Err(Errno::EBADF);
        }
        let bufsize = bufsize.min(GETDIRENTRIES_MAXBUFSIZE);
        if file.handle.metadata()?.file_type != crate::vfs::FileType::Directory {
            return Err(Errno::EINVAL);
        }
        Ok((file, bufsize))
    }

    /// `VNOP_READDIR` without extended entries, as the filesystems here
    /// answer it: from the directory's offset, each entry whose 32-bit
    /// `struct dirent` still fits in `room` bytes, handed to `put`; EINVAL
    /// when not even the first fits. The offset it started at, the one past
    /// them (which [`Self::darwin_readdir_done`] moves to once they are
    /// copied out), and whether the end was reached, come back.
    fn darwin_readdir(file: &crate::file::OpenFile, room: usize, mut put: impl FnMut(&crate::vfs::DirEntry)) -> Result<(usize, usize, bool), Errno> {
        let loff = file.dir_cursor();
        let mut used = 0;
        let mut at = loff;
        let eof = loop {
            let Some(e) = file.dir_entry(at)? else {
                break true;
            };
            let dl = dirent_len(e.name.len());
            if used + dl > room {
                break false;
            }
            used += dl;
            put(&e);
            at += 1;
        };
        // A buffer too small for the next entry (VNOP_READDIR's EINVAL).
        if at == loff && !eof {
            return Err(Errno::EINVAL);
        }
        Ok((loff, at, eof))
    }

    /// The directory's offset past what was read.
    fn darwin_readdir_done(file: &crate::file::OpenFile, at: usize) {
        file.set_dir_cursor(at);
        let _ = file.seek(at as i64, 0);
    }

    /// `getdirentries64(fd, buf, bufsize, position)`, as `vnode_readdir64`
    /// does for a filesystem without extended readdir: the 32-bit dirents
    /// that fit in 3/8 of the buffer, each made a `struct direntry`.
    fn darwin_getdirentries64(&mut self, m: &mut GuestMem<'_>, fd: i32, buf: u64, ubufsize: u64, position: u64) -> Result<u64, Errno> {
        let bufsize = if ubufsize >= GETDIRENTRIES64_EXTENDED_BUFSIZE { ubufsize - 4 } else { ubufsize };
        let (file, bufsize) = self.darwin_readdir_file(fd, bufsize)?;
        let room = 3 * (bufsize.min(87371) as usize) / 8;
        let mut out = Vec::new();
        let (loff, at, eof) = Self::darwin_readdir(&file, room, |e| {
            let name = e.name.as_bytes();
            let rec = dirent64_len(name.len());
            let mut r = vec![0u8; rec];
            r[0..8].copy_from_slice(&e.ino.to_le_bytes());
            r[16..18].copy_from_slice(&(rec as u16).to_le_bytes());
            r[18..20].copy_from_slice(&(name.len() as u16).to_le_bytes());
            r[20] = e.file_type.dirent_type();
            r[21..21 + name.len()].copy_from_slice(name);
            out.extend_from_slice(&r);
        })?;
        m.write(buf, &out)?;
        Self::darwin_readdir_done(&file, at);
        m.write_u64(position, loff as u64)?;
        if ubufsize >= GETDIRENTRIES64_EXTENDED_BUFSIZE {
            m.write_u32(buf + bufsize, if eof { GETDIRENTRIES64_EOF } else { 0 })?;
        }
        Ok(out.len() as u64)
    }

    /// `getdirentries(fd, buf, count, basep)`: `VNOP_READDIR`'s 32-bit
    /// dirents themselves, in the whole buffer, and the offset they were
    /// read from as a long.
    fn darwin_getdirentries(&mut self, m: &mut GuestMem<'_>, fd: i32, buf: u64, count: u64, basep: u64) -> Result<u64, Errno> {
        let (file, bufsize) = self.darwin_readdir_file(fd, count as u32 as u64)?;
        let mut out = Vec::new();
        let (loff, at, _) = Self::darwin_readdir(&file, bufsize as usize, |e| {
            let name = e.name.as_bytes();
            let rec = dirent_len(name.len());
            let mut r = vec![0u8; rec];
            r[0..4].copy_from_slice(&(e.ino as u32).to_le_bytes());
            r[4..6].copy_from_slice(&(rec as u16).to_le_bytes());
            r[6] = e.file_type.dirent_type();
            r[7] = name.len() as u8;
            r[8..8 + name.len()].copy_from_slice(name);
            out.extend_from_slice(&r);
        })?;
        m.write(buf, &out)?;
        Self::darwin_readdir_done(&file, at);
        m.write_u64(basep, loff as u64)?;
        Ok(out.len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_are_xnus_sizes() {
        // A one-character name: 32 bytes as a direntry, 16 as a dirent.
        assert_eq!(dirent64_len(1), 32);
        assert_eq!(dirent_len(1), 12);
        assert_eq!(dirent64_len(11), 40);
    }
}
