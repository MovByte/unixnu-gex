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
const ACCESSPERMS: u64 = 0o777;
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

impl Kernel {
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
            sys::SYMLINK => self.canonical(m, nr::SYMLINKAT, [a[0], cwd, a[1], 0, 0, 0]),
            sys::SYMLINKAT => self.canonical(m, nr::SYMLINKAT, [a[0], dirfd(a[1]), a[2], 0, 0, 0]),
            // link follows a symlink it names, as linkat with
            // AT_SYMLINK_FOLLOW does; linkat takes that flag alone.
            sys::LINK => self.canonical(m, nr::LINKAT, [cwd, a[0], cwd, a[1], L_AT_SYMLINK_FOLLOW, 0]),
            sys::LINKAT => {
                if a[4] & !AT_SYMLINK_FOLLOW != 0 {
                    Err(Errno::EINVAL)
                } else {
                    let f = if a[4] & AT_SYMLINK_FOLLOW != 0 { L_AT_SYMLINK_FOLLOW } else { 0 };
                    self.canonical(m, nr::LINKAT, [dirfd(a[0]), a[1], dirfd(a[2]), a[3], f, 0])
                }
            }
            sys::RENAME => self.canonical(m, nr::RENAMEAT2, [cwd, a[0], cwd, a[1], 0, 0]),
            sys::RENAMEAT => self.canonical(m, nr::RENAMEAT2, [dirfd(a[0]), a[1], dirfd(a[2]), a[3], 0, 0]),
            // RENAME_EXCL is Linux's RENAME_NOREPLACE.
            sys::RENAMEATX_NP => {
                let flags = a[4] as u32 as u64;
                if flags & !(RENAME_SECLUDE | RENAME_EXCL | RENAME_SWAP | RENAME_NOFOLLOW_ANY) != 0 || flags & (RENAME_EXCL | RENAME_SWAP) == RENAME_EXCL | RENAME_SWAP {
                    Err(Errno::EINVAL)
                } else if flags & (RENAME_SECLUDE | RENAME_NOFOLLOW_ANY | RENAME_SWAP) != 0 {
                    // The filesystems here have no atomic exchange.
                    self.darwin_unimplemented(format!("renameatx_np flags {flags:#x} (RENAME_SWAP, RENAME_SECLUDE, RENAME_NOFOLLOW_ANY)"));
                    Err(Errno::EINVAL)
                } else {
                    let l = if flags & RENAME_EXCL != 0 { 1 } else { 0 };
                    self.canonical(m, nr::RENAMEAT2, [dirfd(a[0]), a[1], dirfd(a[2]), a[3], l, 0])
                }
            }
            // The mode's ALLPERMS.
            sys::CHMOD => self.canonical(m, nr::FCHMODAT, [cwd, a[0], a[1] & ALLPERMS, 0, 0, 0]),
            sys::FCHMOD => self.canonical(m, nr::FCHMOD, [a[0], a[1] & ALLPERMS, 0, 0, 0, 0]),
            sys::FCHMODAT => {
                let flag = a[3] as u32 as u64;
                if flag & !(AT_SYMLINK_NOFOLLOW | AT_SYMLINK_NOFOLLOW_ANY) != 0 {
                    Err(Errno::EINVAL)
                } else if flag & AT_SYMLINK_NOFOLLOW_ANY != 0 {
                    self.darwin_unimplemented("fchmodat AT_SYMLINK_NOFOLLOW_ANY".into());
                    Err(Errno::EINVAL)
                } else {
                    // A symlink's own mode (lchmod) is refused as the
                    // filesystems here keep none.
                    self.canonical(m, nr::FCHMODAT, [dirfd(a[0]), a[1], a[2] & ALLPERMS, if flag & AT_SYMLINK_NOFOLLOW != 0 { 0x100 } else { 0 }, 0, 0])
                }
            }
            sys::CHOWN | sys::LCHOWN | sys::FCHOWN | sys::FCHOWNAT => {
                self.darwin_unimplemented("the chown family (the filesystems here keep no owners)".into());
                Err(Errno::EOPNOTSUPP)
            }
            sys::TRUNCATE => self.darwin_truncate(m, a[0], a[1] as i64),
            sys::MKFIFO | sys::MKFIFOAT | sys::MKNOD | sys::MKNODAT => {
                self.darwin_unimplemented("mkfifo and mknod (no named FIFO or device nodes in the filesystems here)".into());
                Err(Errno::EOPNOTSUPP)
            }
            sys::UTIMES => self.darwin_utimes(m, cwd as i32, a[0], a[1]),
            sys::FUTIMES => self.darwin_utimes(m, a[0] as i32, 0, a[1]),
            sys::GETDIRENTRIES64 => self.darwin_getdirentries64(m, a[0] as i32, a[1], a[2], a[3]),
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

    /// `getdirentries64(fd, buf, bufsize, position)`, as `vnode_readdir64`
    /// does for a filesystem without extended readdir: the 32-bit dirents
    /// that fit in 3/8 of the buffer, each made a `struct direntry`.
    fn darwin_getdirentries64(&mut self, m: &mut GuestMem<'_>, fd: i32, buf: u64, ubufsize: u64, position: u64) -> Result<u64, Errno> {
        let mut bufsize = if ubufsize >= GETDIRENTRIES64_EXTENDED_BUFSIZE { ubufsize - 4 } else { ubufsize };
        let file = self.fds.get(fd)?;
        if !file.readable {
            return Err(Errno::EBADF);
        }
        bufsize = bufsize.min(GETDIRENTRIES_MAXBUFSIZE);
        if file.handle.metadata()?.file_type != crate::vfs::FileType::Directory {
            return Err(Errno::EINVAL);
        }
        let loff = file.dir_cursor();
        let room = 3 * (bufsize.min(87371) as usize) / 8;
        let mut used = 0;
        let mut out = Vec::new();
        let mut at = loff;
        let mut eof = false;
        loop {
            let Some(e) = file.dir_entry(at)? else {
                eof = true;
                break;
            };
            let name = e.name.as_bytes();
            let dl = dirent_len(name.len());
            if used + dl > room {
                break;
            }
            used += dl;
            let rec = dirent64_len(name.len());
            let mut r = vec![0u8; rec];
            r[0..8].copy_from_slice(&e.ino.to_le_bytes());
            r[16..18].copy_from_slice(&(rec as u16).to_le_bytes());
            r[18..20].copy_from_slice(&(name.len() as u16).to_le_bytes());
            r[20] = e.file_type.dirent_type();
            r[21..21 + name.len()].copy_from_slice(name);
            out.extend_from_slice(&r);
            at += 1;
        }
        // A buffer too small for the next entry (VNOP_READDIR's EINVAL).
        if out.is_empty() && !eof {
            return Err(Errno::EINVAL);
        }
        m.write(buf, &out)?;
        file.set_dir_cursor(at);
        let _ = file.seek(at as i64, 0);
        m.write_u64(position, loff as u64)?;
        if ubufsize >= GETDIRENTRIES64_EXTENDED_BUFSIZE {
            m.write_u32(buf + bufsize, if eof { GETDIRENTRIES64_EOF } else { 0 })?;
        }
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
