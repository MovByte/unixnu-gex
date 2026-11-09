//! The extended attribute calls (`bsd/vfs/vfs_syscalls.c`, `vfs_xattr.c`).
//! An attribute keeps its Darwin name behind the filesystems' `user.`
//! prefix; a resource fork's offset and the DAC check on the file are not
//! here, and the first is reported.

use super::errno::errno_of;
use crate::errno::Errno;
use crate::syscalls::Kernel;
use crate::vfs::XattrOp;
use crate::GuestMem;

const XATTR_NOFOLLOW: u64 = 0x1;
const XATTR_CREATE: u64 = 0x2;
const XATTR_REPLACE: u64 = 0x4;
const XATTR_NOSECURITY: u64 = 0x8;
const XATTR_NODEFAULT: u64 = 0x10;
const XATTR_MAXNAMELEN: usize = 127;
const XATTR_MAXSIZE: u64 = i32::MAX as u64;
/// `ENOATTR`.
const ENOATTR: i32 = 93;
const KAUTH_FILESEC_XATTR: &str = "com.apple.system.Security";
const FILESEC_ACCESS_ENTITLEMENT: &str = "com.apple.private.vfs.filesec-access";
const PREFIX: &str = "user.";

/// `xattr_protected`.
fn protected(name: &str) -> bool {
    name.starts_with("com.apple.system.")
}

/// What an attribute call works on.
enum Target {
    Path(String, bool),
    File(std::sync::Arc<crate::file::OpenFile>),
}

impl Kernel {
    fn darwin_xattr_name(&self, m: &GuestMem<'_>, at: u64) -> Result<String, Errno> {
        let raw = m.read_cstr(at, XATTR_MAXNAMELEN + 2)?;
        if raw.len() > XATTR_MAXNAMELEN {
            return Err(Errno::ENAMETOOLONG);
        }
        let name = String::from_utf8(raw).map_err(|_| Errno::EINVAL)?;
        if name.is_empty() {
            return Err(Errno::EINVAL);
        }
        Ok(name)
    }

    /// `xattr_entitlement_check`.
    fn darwin_xattr_protected(&mut self, name: &str, setting: bool) -> Result<(), Errno> {
        if protected(name) && !(name == KAUTH_FILESEC_XATTR && ((!setting && self.dtask.cred.uid == 0) || self.darwin_task_entitled(FILESEC_ACCESS_ENTITLEMENT))) {
            return Err(Errno::EPERM);
        }
        Ok(())
    }

    /// The path or descriptor a call names: `file_vnode`'s EINVAL for what
    /// is not a vnode.
    fn darwin_xattr_target(&mut self, m: &GuestMem<'_>, by_fd: bool, arg: u64, options: u64) -> Result<Target, Errno> {
        if by_fd {
            if options & XATTR_NOFOLLOW != 0 {
                return Err(Errno::EINVAL);
            }
            let file = self.fds.get(arg as i32)?;
            if self.darwin_vnode_of(&file).is_none() {
                return Err(Errno::EINVAL);
            }
            return Ok(Target::File(file));
        }
        let path = self.path_io().at_path(m, super::bsd::dirfd(super::bsd::AT_FDCWD as u64) as i32, arg)?;
        self.vfs.metadata(&path)?;
        Ok(Target::Path(path, options & XATTR_NOFOLLOW == 0))
    }

    fn darwin_xattr_op(&self, target: &Target, op: XattrOp<'_>) -> Result<usize, Errno> {
        match target {
            Target::Path(p, follow) => self.path_io().ns.xattr(p, *follow, op),
            Target::File(f) => f.handle.xattr(op).unwrap_or(Err(Errno::EOPNOTSUPP)),
        }
    }

    /// `setattrlist_setfinderinfo`: `vn_setxattr` with XATTR_NOSECURITY.
    pub(crate) fn darwin_set_finderinfo(&mut self, fd: i32, path: Option<&str>, follow: bool, info: &[u8; 32]) -> Result<(), Errno> {
        let target = match path {
            Some(p) => Target::Path(p.to_string(), follow),
            None => Target::File(self.fds.get(fd)?),
        };
        let name = format!("{PREFIX}com.apple.FinderInfo");
        self.darwin_xattr_op(&target, XattrOp::Set { name: &name, value: info, flags: 0 }).map(|_| ()).map_err(xattr_errno)
    }

    /// `getxattr` and `fgetxattr`: the value or, with no buffer, its size.
    pub(crate) fn darwin_getxattr(&mut self, m: &mut GuestMem<'_>, by_fd: bool, a: &[u64; 6]) -> Result<u64, Errno> {
        let (value, size, position, options) = (a[2], a[3], a[4] as u32, a[5] as u32 as u64);
        if options & (XATTR_NOSECURITY | XATTR_NODEFAULT) != 0 {
            return Err(Errno::EINVAL);
        }
        let target = self.darwin_xattr_target(m, by_fd, a[0], options)?;
        let name = self.darwin_xattr_name(m, a[1])?;
        self.darwin_xattr_protected(&name, false)?;
        if position != 0 {
            if name == "com.apple.ResourceFork" {
                self.darwin_unimplemented("a resource fork's offset".into());
            }
            return Err(Errno::EINVAL);
        }
        let full = format!("{PREFIX}{name}");
        let no_buffer = size == 0xffff_ffff || size == u64::MAX || value == 0;
        let got = if no_buffer {
            self.darwin_xattr_op(&target, XattrOp::Get { name: &full, buf: &mut [] })
        } else {
            let mut buf = vec![0u8; size.min(XATTR_MAXSIZE) as usize];
            let n = self.darwin_xattr_op(&target, XattrOp::Get { name: &full, buf: &mut buf });
            match n {
                Ok(n) => {
                    m.write(value, &buf[..n])?;
                    Ok(n)
                }
                e => e,
            }
        };
        got.map(|n| n as u64).map_err(xattr_errno)
    }

    /// `setxattr` and `fsetxattr`.
    pub(crate) fn darwin_setxattr(&mut self, m: &mut GuestMem<'_>, by_fd: bool, a: &[u64; 6]) -> Result<u64, Errno> {
        let (value, size, position, options) = (a[2], a[3], a[4] as u32, a[5] as u32 as u64);
        if options & (XATTR_NOSECURITY | XATTR_NODEFAULT) != 0 {
            return Err(Errno::EINVAL);
        }
        let name = self.darwin_xattr_name(m, a[1])?;
        self.darwin_xattr_protected(&name, true)?;
        if size != 0 && value == 0 {
            return Err(Errno::EINVAL);
        }
        if size > i32::MAX as u64 {
            return Err(Errno::E2BIG);
        }
        let target = self.darwin_xattr_target(m, by_fd, a[0], options)?;
        if position != 0 {
            if name == "com.apple.ResourceFork" {
                self.darwin_unimplemented("a resource fork's offset".into());
            }
            return Err(Errno::EINVAL);
        }
        if options & XATTR_CREATE != 0 && options & XATTR_REPLACE != 0 {
            return Err(Errno::EINVAL);
        }
        let flags = u32::from(options & XATTR_CREATE != 0) | u32::from(options & XATTR_REPLACE != 0) << 1;
        let bytes = m.read(value, size as usize)?.to_vec();
        let full = format!("{PREFIX}{name}");
        self.darwin_xattr_op(&target, XattrOp::Set { name: &full, value: &bytes, flags }).map(|_| 0).map_err(xattr_errno)
    }

    /// `removexattr` and `fremovexattr`.
    pub(crate) fn darwin_removexattr(&mut self, m: &mut GuestMem<'_>, by_fd: bool, a: &[u64; 6]) -> Result<u64, Errno> {
        let options = a[2] as u32 as u64;
        if options & (XATTR_NOSECURITY | XATTR_NODEFAULT) != 0 {
            return Err(Errno::EINVAL);
        }
        let name = self.darwin_xattr_name(m, a[1])?;
        self.darwin_xattr_protected(&name, true)?;
        let target = self.darwin_xattr_target(m, by_fd, a[0], options)?;
        let full = format!("{PREFIX}{name}");
        self.darwin_xattr_op(&target, XattrOp::Remove { name: &full }).map(|_| 0).map_err(xattr_errno)
    }

    /// `listxattr` and `flistxattr`: the names, NUL-terminated, without the
    /// prefix they are kept under.
    pub(crate) fn darwin_listxattr(&mut self, m: &mut GuestMem<'_>, by_fd: bool, a: &[u64; 6]) -> Result<u64, Errno> {
        let (namebuf, bufsize, options) = (a[1], a[2], a[3] as u32 as u64);
        if options & (XATTR_NOSECURITY | XATTR_NODEFAULT) != 0 {
            return Err(Errno::EINVAL);
        }
        let target = self.darwin_xattr_target(m, by_fd, a[0], options)?;
        let size = self.darwin_xattr_op(&target, XattrOp::List { buf: &mut [] }).map_err(xattr_errno)?;
        let mut raw = vec![0u8; size];
        let n = self.darwin_xattr_op(&target, XattrOp::List { buf: &mut raw }).map_err(xattr_errno)?;
        let mut names = Vec::new();
        for full in raw[..n].split(|&c| c == 0).filter(|s| !s.is_empty()) {
            if let Some(name) = full.strip_prefix(PREFIX.as_bytes()) {
                names.extend_from_slice(name);
                names.push(0);
            }
        }
        if namebuf == 0 || bufsize == 0 {
            return Ok(names.len() as u64);
        }
        if names.len() as u64 > bufsize {
            return Err(Errno::ERANGE);
        }
        m.write(namebuf, &names)?;
        Ok(names.len() as u64)
    }
}

/// An attribute that is not there is ENOATTR, the filesystem's ENODATA.
fn xattr_errno(e: Errno) -> Errno {
    if e == Errno::ENODATA {
        errno_of(ENOATTR)
    } else {
        e
    }
}
