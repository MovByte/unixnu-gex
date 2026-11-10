//! Calls whose result on an arm64 RELEASE kernel is settled before any work
//! is done: those built as a stub (`CONFIG_KAS_INFO`, `QUOTA`,
//! `CONFIG_SEARCHFS` and `CONFIG_DEBUG_SYSCALL_REJECTION` are not in it), and
//! those a caller without root, an entitlement or the right kind of task is
//! refused. A caller who passes such a check is reported: what the call
//! goes on to do is not here.

use super::bsd::sys;
use crate::errno::Errno;
use crate::syscalls::Kernel;
use crate::GuestMem;

/// `CROSSARCH_MAX_VALID_NAMESPACE`.
const CROSSARCH_MAX_VALID_NAMESPACE: u64 = 0;

impl Kernel {
    fn darwin_entitled(&self, name: &str) -> bool {
        self.dtask.codesign.as_ref().is_some_and(|c| c.entitled(name))
    }

    /// The call, if it is one of these.
    pub(crate) fn darwin_fixed_call(&mut self, m: &GuestMem<'_>, raw: u64, a: &[u64; 6]) -> Option<Result<u64, Errno>> {
        let root = self.dtask.cred.uid == 0;
        // suser() or an entitlement: refused, or reported.
        let gated = |k: &mut Kernel, allowed: bool, what: &str| -> Result<u64, Errno> {
            if !allowed {
                return Err(Errno::EPERM);
            }
            k.darwin_unimplemented(format!("{what} for a caller allowed to make it"));
            Err(Errno::EINVAL)
        };
        Some(match raw {
            sys::CROSSARCH_TRAP => Err(if a[0] as u32 as u64 > CROSSARCH_MAX_VALID_NAMESPACE { Errno::EINVAL } else { Errno::EOPNOTSUPP }),
            sys::SWAPON | sys::UNDELETE | sys::SEARCHFS | sys::KAS_INFO | sys::DEBUG_SYSCALL_REJECT | sys::DEBUG_SYSCALL_REJECT_CONFIG => Err(Errno::EOPNOTSUPP),
            sys::QUOTACTL => Err(super::errno::EOPNOTSUPP),
            sys::REVOKE => self.darwin_revoke(m, a[0]),
            sys::SETPRIVEXEC => {
                let was = self.dtask.p_debugger;
                self.dtask.p_debugger = a[0] as i32 != 0;
                Ok(u64::from(was))
            }
            // vfs_purge drops what the filesystems cache and the file-backed
            // pagers hold; nothing here is held for it to drop.
            sys::VFS_PURGE => {
                if root {
                    Ok(0)
                } else {
                    Err(Errno::EPERM)
                }
            }
            sys::ACCT => gated(self, root, "acct"),
            sys::REBOOT => gated(self, root, "reboot"),
            sys::CHROOT => gated(self, root, "chroot"),
            sys::MICROSTACKSHOT => gated(self, root, "microstackshot"),
            sys::USRCTL => gated(self, self.pid == 1, "usrctl"),
            sys::PANIC_WITH_DATA => {
                let ok = self.darwin_entitled("com.apple.private.allow-ext_paniclog");
                gated(self, ok, "panic_with_data")
            }
            sys::TRACKER_ACTION => {
                let ok = self.darwin_entitled("com.apple.private.ip-domain-table");
                gated(self, ok, "tracker_action")
            }
            sys::GRAFTDMG | sys::UNGRAFTDMG => {
                let ok = self.darwin_entitled("com.apple.private.vfs.graftdmg");
                gated(self, ok, "graftdmg and ungraftdmg")
            }
            sys::RECORD_SYSTEM_EVENT => {
                let ok = self.darwin_entitled("com.apple.private.record_system_event");
                gated(self, ok, "record_system_event")
            }
            sys::OPENBYID_NP => {
                let ok = self.dtask.codesign.as_ref().is_some_and(|c| c.platform_binary) || self.darwin_entitled("com.apple.private.vfs.open-by-id");
                gated(self, ok, "openbyid_np")
            }
            sys::LOG_DATA => {
                let driver = self.darwin_policy().requested.apptype == super::taskpolicy::apptype::DRIVER;
                gated(self, driver, "log_data")
            }
            _ => return None,
        })
    }

    /// `revoke(path)`: only of a device.
    fn darwin_revoke(&mut self, m: &GuestMem<'_>, path: u64) -> Result<u64, Errno> {
        let abs = self.path_io().at_path(m, super::bsd::dirfd(super::bsd::AT_FDCWD as u64) as i32, path)?;
        if self.vfs.metadata(&abs)?.file_type != crate::vfs::FileType::CharDevice {
            return Err(Errno::EOPNOTSUPP);
        }
        self.darwin_unimplemented("revoke of a device".into());
        Err(Errno::EINVAL)
    }
}
