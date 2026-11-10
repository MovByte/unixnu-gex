//! The calls that take a file security argument (`open_extended` and its
//! family, behind `openx_np` and `statx_np`). The filesystems here keep no
//! access control lists: every file has none, one that is given is
//! reported, and so is an owner, which they cannot set either.

use super::bsd::sys;
use crate::errno::Errno;
use crate::syscalls::{Kernel, SyscallOutcome};
use crate::GuestMem;

/// `KAUTH_UID_NONE` and `KAUTH_GID_NONE`.
const NO_ID: u32 = !0 - 100;
/// `_FILESEC_REMOVE_ACL`.
const REMOVE_ACL: u64 = 1;

impl Kernel {
    /// Asked for an owner, or for a list to be set: reported.
    fn darwin_filesec_refused(&mut self, what: &str, uid: u64, gid: u64, xsecurity: u64, chmod: bool) -> Option<Errno> {
        if uid as u32 != NO_ID || gid as u32 != NO_ID {
            self.darwin_unimplemented(format!("{what} setting an owner"));
            return Some(Errno::EINVAL);
        }
        if xsecurity != 0 && !(chmod && xsecurity == REMOVE_ACL) {
            self.darwin_unimplemented(format!("{what} with an access control list (the filesystems here keep none)"));
            return Some(Errno::EINVAL);
        }
        None
    }

    /// A call by its plain number, as a guest would make it.
    fn darwin_plain_call(&mut self, m: &mut GuestMem<'_>, raw: u64, mut la: [u64; 6]) -> Result<u64, Errno> {
        match self.darwin_call(m, raw, &la) {
            Some(ret) => match ret as i64 {
                e @ -4095..=-1 => Err(Errno(-e as i32)),
                _ => Ok(ret),
            },
            None => {
                let n = super::bsd::translate(raw, &mut la);
                self.canonical(m, n, la)
            }
        }
    }

    /// The call, if it is one of these. `open_extended` is
    /// [`Self::darwin_open_extended`]'s.
    pub(crate) fn darwin_filesec_call(&mut self, m: &mut GuestMem<'_>, raw: u64, a: &[u64; 6]) -> Option<Result<u64, Errno>> {
        Some(match raw {
            sys::STAT64_EXTENDED | sys::LSTAT64_EXTENDED | sys::FSTAT64_EXTENDED => {
                let plain = match raw {
                    sys::STAT64_EXTENDED => sys::STAT64,
                    sys::LSTAT64_EXTENDED => sys::LSTAT64,
                    _ => sys::FSTAT64,
                };
                self.darwin_plain_call(m, plain, [a[0], a[1], 0, 0, 0, 0]).and_then(|r| {
                    // fstatat_internal: no list, its size is zero.
                    if a[2] != 0 {
                        m.write_u64(a[3], 0)?;
                    }
                    Ok(r)
                })
            }
            sys::UMASK_EXTENDED => match self.darwin_filesec_refused("umask_extended", u64::from(NO_ID), u64::from(NO_ID), a[1], false) {
                Some(e) => Err(e),
                None => self.darwin_plain_call(m, sys::UMASK, [a[0], 0, 0, 0, 0, 0]),
            },
            sys::MKDIR_EXTENDED => match self.darwin_filesec_refused("mkdir_extended", a[1], a[2], a[4], false) {
                Some(e) => Err(e),
                None => self.darwin_plain_call(m, sys::MKDIR, [a[0], a[3], 0, 0, 0, 0]),
            },
            sys::CHMOD_EXTENDED | sys::FCHMOD_EXTENDED => {
                let chmod = raw == sys::CHMOD_EXTENDED;
                let what = if chmod { "chmod_extended" } else { "fchmod_extended" };
                match self.darwin_filesec_refused(what, a[1], a[2], a[4], true) {
                    Some(e) => Err(e),
                    // A mode of -1 leaves it: only the lookup can fail.
                    None if a[3] as i32 == -1 => {
                        if chmod {
                            self.path_io().at_path(m, super::bsd::dirfd(super::bsd::AT_FDCWD as u64) as i32, a[0]).and_then(|p| self.vfs.metadata(&p)).map(|_| 0)
                        } else {
                            self.fds.get(a[0] as i32).map(|_| 0)
                        }
                    }
                    None => self.darwin_plain_call(m, if chmod { sys::CHMOD } else { sys::FCHMOD }, [a[0], a[3], 0, 0, 0, 0]),
                }
            }
            _ => return None,
        })
    }

    /// `open_extended(path, flags, uid, gid, mode, xsecurity)`, which is not
    /// a cancellation point.
    pub(crate) fn darwin_open_extended(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> SyscallOutcome {
        if let Some(e) = self.darwin_filesec_refused("open_extended", a[2], a[3], a[5], false) {
            super::thread::bsd_result(m, self.ctx_addr, Err(e), false);
            return SyscallOutcome::Continue;
        }
        self.darwin_open_finish(m, sys::OPEN_NOCANCEL, [a[0], a[1], a[4], 0, 0, 0], None)
    }
}
