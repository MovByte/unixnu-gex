//! `pathconf` and `fpathconf` (`vn_pathconf`, `bsd/kern/kern_descrip.c`), and
//! `freadlink`.
//!
//! The file system's own answers are what a volume's `VNOP_PATHCONF` gives:
//! APFS's, measured on an APFS volume of a macOS 27 machine, but for
//! `_PC_CASE_SENSITIVE`, which an iOS volume sets; devfs's and specfs's and
//! fifofs's are their source's.

use crate::errno::Errno;
use crate::syscalls::Kernel;
use crate::vfs::FileType;
use crate::GuestMem;
use std::sync::Arc;

const MAXPATHLEN: usize = 1024;
const PIPE_BUF: u64 = 512;

mod pc {
    pub const LINK_MAX: i32 = 1;
    pub const MAX_CANON: i32 = 2;
    pub const MAX_INPUT: i32 = 3;
    pub const NAME_MAX: i32 = 4;
    pub const PATH_MAX: i32 = 5;
    pub const PIPE_BUF: i32 = 6;
    pub const CHOWN_RESTRICTED: i32 = 7;
    pub const NO_TRUNC: i32 = 8;
    pub const VDISABLE: i32 = 9;
    pub const NAME_CHARS_MAX: i32 = 10;
    pub const CASE_SENSITIVE: i32 = 11;
    pub const CASE_PRESERVING: i32 = 12;
    pub const EXTENDED_SECURITY_NP: i32 = 13;
    pub const AUTH_OPAQUE_NP: i32 = 14;
    pub const SYMLINKS_2: i32 = 15;
    pub const ALLOC_SIZE_MIN: i32 = 16;
    pub const ASYNC_IO: i32 = 17;
    pub const FILESIZEBITS: i32 = 18;
    pub const PRIO_IO: i32 = 19;
    pub const REC_INCR_XFER_SIZE: i32 = 20;
    pub const REC_MAX_XFER_SIZE: i32 = 21;
    pub const REC_MIN_XFER_SIZE: i32 = 22;
    pub const REC_XFER_ALIGN: i32 = 23;
    pub const SYMLINK_MAX: i32 = 24;
    pub const SYNC_IO: i32 = 25;
    pub const XATTR_SIZE_BITS: i32 = 26;
    pub const MIN_HOLE_SIZE: i32 = 27;
}

/// Whose `VNOP_PATHCONF` answers for a vnode.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fs {
    Apfs,
    /// A fifo (on an APFS volume).
    Fifo,
    /// A device node of devfs.
    Spec,
    /// A directory of devfs.
    Devfs,
}

fn fs_of(path: &str, ty: FileType) -> Fs {
    match ty {
        FileType::CharDevice => Fs::Spec,
        FileType::Fifo => Fs::Fifo,
        FileType::Directory if path == "/dev" || path.starts_with("/dev/") => Fs::Devfs,
        _ => Fs::Apfs,
    }
}

/// `vn_pathconf`: `AD_XATTR_SIZE_BITS` for a volume without native extended
/// attributes, as devfs is.
fn vn_pathconf(fs: Fs, name: i32) -> Result<u64, Errno> {
    use pc::*;
    Ok(match name {
        EXTENDED_SECURITY_NP => u64::from(!matches!(fs, Fs::Spec | Fs::Devfs)),
        AUTH_OPAQUE_NP => 0,
        SYMLINKS_2 | ALLOC_SIZE_MIN | ASYNC_IO => 1,
        PRIO_IO | SYNC_IO => 0,
        REC_INCR_XFER_SIZE | REC_MIN_XFER_SIZE | REC_XFER_ALIGN => 4096,
        REC_MAX_XFER_SIZE => 65536,
        SYMLINK_MAX => 255,
        XATTR_SIZE_BITS if matches!(fs, Fs::Spec | Fs::Devfs) => 31,
        _ => return vnop_pathconf(fs, name),
    })
}

/// A file system's `VNOP_PATHCONF`.
fn vnop_pathconf(fs: Fs, name: i32) -> Result<u64, Errno> {
    use pc::*;
    Ok(match (fs, name) {
        (Fs::Apfs | Fs::Fifo | Fs::Spec | Fs::Devfs, LINK_MAX) => 32767,
        (Fs::Apfs | Fs::Fifo | Fs::Spec, PIPE_BUF) => super::pathconf::PIPE_BUF,
        (Fs::Apfs | Fs::Fifo | Fs::Spec | Fs::Devfs, CHOWN_RESTRICTED) => 200112,
        (Fs::Spec, MAX_CANON | MAX_INPUT) => 1024,
        (Fs::Spec, VDISABLE) => 0xff,
        (Fs::Apfs, NAME_MAX | NAME_CHARS_MAX) => 255,
        (Fs::Apfs, PATH_MAX) => 1024,
        (Fs::Apfs, NO_TRUNC) => 200112,
        (Fs::Apfs | Fs::Devfs, CASE_SENSITIVE | CASE_PRESERVING) => 1,
        (Fs::Apfs, FILESIZEBITS | XATTR_SIZE_BITS) => 56,
        (Fs::Apfs, MIN_HOLE_SIZE) => 4096,
        (Fs::Devfs, NAME_MAX) => 31,
        (Fs::Devfs, PATH_MAX) => 127,
        (Fs::Devfs, NO_TRUNC) => 0,
        _ => return Err(Errno::EINVAL),
    })
}

impl Kernel {
    /// `pathconf(path, name)`.
    pub(crate) fn darwin_pathconf(&mut self, m: &GuestMem<'_>, path: u64, name: i32) -> Result<u64, Errno> {
        let raw = m.read_cstr(path, MAXPATHLEN)?;
        let given = std::str::from_utf8(&raw).map_err(|_| Errno::EINVAL)?;
        let abs = self.path_io().at_path_str(super::bsd::dirfd(super::bsd::AT_FDCWD as u64) as i32, given)?;
        let md = self.vfs.metadata(&abs)?;
        vn_pathconf(fs_of(&abs, md.file_type), name)
    }

    /// `fpathconf(fd, name)`: a socket and a pipe answer only for PIPE_BUF,
    /// and what is neither they nor a vnode for nothing.
    pub(crate) fn darwin_fpathconf(&mut self, fd: i32, name: i32) -> Result<u64, Errno> {
        let file = self.fds.get(fd)?;
        let pipe = file.handle.pipe_end().is_some() && file.path.starts_with("pipe:[");
        let ty = file.handle.metadata().map(|md| md.file_type);
        if pipe || ty == Ok(FileType::Socket) {
            return if name == pc::PIPE_BUF { Ok(PIPE_BUF) } else { Err(Errno::EINVAL) };
        }
        if Arc::clone(&file.handle).as_kqueue().is_some() || Arc::clone(&file.handle).as_posix_shm().is_some() {
            return Err(Errno::EINVAL);
        }
        vn_pathconf(fs_of(&file.path, ty?), name)
    }

    /// `freadlink(fd, buf, bufsize)`: the link an O_SYMLINK open holds.
    pub(crate) fn darwin_freadlink(&mut self, m: &mut GuestMem<'_>, fd: i32, buf: u64, bufsize: u64) -> Result<u64, Errno> {
        let file = self.fds.get(fd)?;
        let pipe = file.handle.pipe_end().is_some() && file.path.starts_with("pipe:[");
        let ty = file.handle.metadata().map(|md| md.file_type);
        if pipe || ty == Ok(FileType::Socket) || Arc::clone(&file.handle).as_kqueue().is_some() || Arc::clone(&file.handle).as_posix_shm().is_some() {
            return Err(Errno::EINVAL);
        }
        if bufsize > i32::MAX as u64 {
            return Err(Errno::EINVAL);
        }
        if ty? != FileType::Symlink {
            return Err(Errno::EINVAL);
        }
        let target = self.vfs.read_link(&file.path)?;
        let n = target.len().min(bufsize as usize);
        m.write(buf, &target.as_bytes()[..n])?;
        Ok(n as u64)
    }
}
