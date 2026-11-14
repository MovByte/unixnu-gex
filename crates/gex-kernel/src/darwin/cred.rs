//! A process's POSIX credential (`struct posix_cred`, `kern_credential.c`)
//! and the system calls that read and change it (`kern_prot.c`): the
//! effective, real and saved user ids, the group list whose first entry is
//! the effective group id, the real and saved group ids, and the user the
//! group list follows (`cr_gmuid`). A change by one of the set*id calls
//! marks the process P_SUGID (`issetugid`).

use crate::errno::Errno;
use crate::syscalls::Kernel;
use crate::GuestMem;

/// `KAUTH_UID_NONE`, `KAUTH_GID_NONE`.
pub const UID_NONE: u32 = u32::MAX - 100;
pub const GID_NONE: u32 = u32::MAX - 100;
/// `NGROUPS`.
pub const NGROUPS: usize = 16;
/// `CRF_NOMEMBERD`: the group list is not the user's default.
pub const CRF_NOMEMBERD: u32 = 0x1;
/// `MAXLOGNAME`.
pub const MAXLOGNAME: usize = 255;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cred {
    /// `cr_uid`, `cr_ruid`, `cr_svuid`.
    pub uid: u32,
    pub ruid: u32,
    pub svuid: u32,
    /// `cr_groups[0..cr_ngroups]`: the effective group id, then the
    /// supplementary groups.
    pub groups: Vec<u32>,
    pub rgid: u32,
    pub svgid: u32,
    pub gmuid: u32,
    pub flags: u32,
}

/// Until a process's creator gives it one: the kernel's (`kauth_cred_init`'s
/// template), root's.
impl Default for Cred {
    fn default() -> Cred {
        Cred { uid: 0, ruid: 0, svuid: 0, groups: vec![0], rgid: 0, svgid: 0, gmuid: 0, flags: CRF_NOMEMBERD }
    }
}

impl Cred {
    /// A credential of one user and group, as its creator sets a user's
    /// process up (`initgroups` then `setgid` and `setuid`): every id that
    /// user's and that group's, one group, the group list the user's.
    pub fn of(uid: u32, gid: u32) -> Cred {
        Cred { uid, ruid: uid, svuid: uid, groups: vec![gid], rgid: gid, svgid: gid, gmuid: uid, flags: 0 }
    }

    /// `cr_gid`, the effective group id.
    pub fn gid(&self) -> u32 {
        self.groups[0]
    }

    /// `kauth_cred_model_setresuid`: whether the credential changed.
    pub fn setresuid(&mut self, ruid: u32, euid: u32, svuid: u32, gmuid: u32) -> bool {
        let mut updated = false;
        if euid != UID_NONE && self.uid != euid {
            self.uid = euid;
            updated = true;
        }
        if ruid != UID_NONE && self.ruid != ruid {
            self.ruid = ruid;
            updated = true;
        }
        if svuid != UID_NONE && self.svuid != svuid {
            self.svuid = svuid;
            updated = true;
        }
        if self.gmuid != gmuid {
            self.gmuid = gmuid;
            if gmuid == UID_NONE {
                self.flags |= CRF_NOMEMBERD;
            }
            updated = true;
        }
        updated
    }

    /// `kauth_cred_model_setuidgid`: `uid` as every user id and `gid` as
    /// every group id and the only group, the group list following the
    /// user unless it opted out of memberd; whether that changed it.
    pub fn setuidgid(&mut self, uid: u32, gid: u32) -> bool {
        let gmuid = if self.flags & CRF_NOMEMBERD != 0 { UID_NONE } else { uid };
        let new = Cred { uid, ruid: uid, svuid: uid, groups: vec![gid], rgid: gid, svgid: gid, gmuid, flags: self.flags };
        if *self == new {
            return false;
        }
        *self = new;
        true
    }

    /// `kauth_cred_model_setresgid`.
    pub fn setresgid(&mut self, rgid: u32, egid: u32, svgid: u32) -> bool {
        let mut updated = false;
        if egid != GID_NONE && self.gid() != egid {
            if self.change_egid(egid) {
                self.flags |= CRF_NOMEMBERD;
                self.gmuid = UID_NONE;
            }
            updated = true;
        }
        if rgid != GID_NONE && self.rgid != rgid {
            self.rgid = rgid;
            updated = true;
        }
        if svgid != GID_NONE && self.svgid != svgid {
            self.svgid = svgid;
            updated = true;
        }
        updated
    }

    /// `kauth_cred_change_egid`: the new effective group takes the first
    /// place; if it was a supplementary group, the old one takes its place.
    /// Whether it displaced the list (was not in it).
    fn change_egid(&mut self, egid: u32) -> bool {
        let old = self.gid();
        let mut displaced = true;
        for g in self.groups.iter_mut().skip(1) {
            if *g == egid {
                *g = old;
                displaced = false;
                break;
            }
        }
        self.groups[0] = egid;
        displaced
    }

    /// `kauth_cred_copy_real`: the credential with the real user and group
    /// as its effective ones (a supplementary group the real group
    /// displaces opts it out of memberd), as `access` checks.
    pub fn copy_real(&self) -> Cred {
        let mut c = self.clone();
        if c.ruid == c.uid && c.rgid == c.gid() {
            return c;
        }
        c.uid = c.ruid;
        if c.change_egid(c.rgid) {
            c.flags |= CRF_NOMEMBERD;
            c.gmuid = UID_NONE;
        }
        if c.gmuid != UID_NONE {
            c.gmuid = c.ruid;
        }
        c
    }

    /// `kauth_cred_ismember_gid`: the credential's own group list, which
    /// is the whole answer on a kernel without an external resolver
    /// (iOS's has none: no `CONFIG_EXT_RESOLVER`).
    pub fn is_member(&self, gid: u32) -> bool {
        self.groups.contains(&gid)
    }

    /// `kauth_cred_model_setgroups`.
    pub fn setgroups(&mut self, groups: &[u32], gmuid: u32) -> bool {
        let groups = &groups[..groups.len().min(NGROUPS)];
        if self.gmuid == gmuid && self.groups == groups {
            return false;
        }
        self.gmuid = gmuid;
        self.groups = groups.to_vec();
        if gmuid == UID_NONE {
            self.flags |= CRF_NOMEMBERD;
        } else {
            self.flags &= !CRF_NOMEMBERD;
        }
        true
    }
}

/// The login names of the sessions (`s_login`), by session id.
fn logins() -> &'static std::sync::Mutex<std::collections::HashMap<i32, Vec<u8>>> {
    static L: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<i32, Vec<u8>>>> = std::sync::OnceLock::new();
    L.get_or_init(Default::default)
}

impl Kernel {
    /// `suser`: the credential is root's.
    pub(crate) fn darwin_suser(&self) -> Result<(), Errno> {
        if self.dtask.cred.uid != 0 {
            return Err(Errno::EPERM);
        }
        // proc_suser: the process has used its privilege.
        self.dtask.live.acflag.fetch_or(super::kinfo::ac::ASU, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// `kauth_cred_proc_update(p, PROC_SETTOKEN_SETUGID, ...)` with a
    /// changed credential: the process is marked P_SUGID, and the task's
    /// security tokens follow (the effective ids the kernel's own checks
    /// use, and the real uid the process table counts by).
    pub(crate) fn darwin_cred_changed(&mut self) {
        self.dtask.sugid = true;
        self.darwin_cred_tokens();
    }

    /// `set_security_token`: the identity the rest of the kernel sees.
    pub fn darwin_cred_tokens(&mut self) {
        let c = &self.dtask.cred;
        self.creds.set_uid(c.uid);
        self.creds.set_gid(c.gid());
        self.procs.set_uid(self.pid, c.ruid);
        self.darwin_publish();
    }

    /// The credential calls; none for another call.
    pub(crate) fn darwin_cred_syscall(&mut self, m: &mut GuestMem<'_>, nr: u64, a: &[u64; 6]) -> Option<Result<u64, Errno>> {
        use super::sysno as sys;
        let c = self.dtask.cred.clone();
        Some(match nr {
            sys::GETUID => Ok(u64::from(c.ruid)),
            sys::GETEUID => Ok(u64::from(c.uid)),
            sys::GETGID => Ok(u64::from(c.rgid)),
            sys::GETEGID => Ok(u64::from(c.gid())),
            sys::GETGROUPS => self.darwin_getgroups(m, a[0] as i32, a[1]),
            sys::GETSGROUPS | sys::GETWGROUPS | sys::SETSGROUPS | sys::SETWGROUPS => Err(super::errno::errno_of(45)),
            sys::ISSETUGID => Ok(u64::from(self.dtask.sugid)),
            sys::SETUID => self.darwin_setuid(a[0] as u32),
            sys::SETEUID => self.darwin_seteuid(a[0] as u32),
            sys::SETREUID => self.darwin_setreuid(a[0] as u32, a[1] as u32),
            sys::SETGID => self.darwin_setgid(a[0] as u32),
            sys::SETEGID => self.darwin_setegid(a[0] as u32),
            sys::SETREGID => self.darwin_setregid(a[0] as u32, a[1] as u32),
            sys::SETGROUPS => self.darwin_setgroups1(m, a[0] as u32, a[1], UID_NONE),
            sys::INITGROUPS => self.darwin_setgroups1(m, a[0] as u32, a[1], a[2] as u32),
            // No thread runs with an identity of its own.
            sys::GETTID => Err(Errno::ESRCH),
            sys::SETTID => self.darwin_settid(a[0] as u32),
            sys::SETTID_WITH_PID => {
                let (pid, assume) = (a[0] as i32, a[1] as i32);
                if assume == 0 {
                    self.darwin_settid(UID_NONE)
                } else if pid == 0 {
                    Err(Errno::ESRCH)
                } else {
                    // kauth_cred_proc_ref_for_pid: the credential of the
                    // process in the pid hash (proc_find_noref_smr), one
                    // that has exited or is a zombie too; its uid and gid
                    // are this thread's to take.
                    let Some((target, _)) = self.darwin_public(pid) else { return Some(Err(Errno::ESRCH)) };
                    self.darwin_settid(target.cred.uid)
                }
            }
            sys::GETLOGIN => self.darwin_getlogin(m, a[0], a[1] as u32),
            sys::SETLOGIN => self.darwin_setlogin(m, a[0]),
            _ => return None,
        })
    }

    /// `getgroups(gidsetsize, gidset)`: the count for a size of 0; EINVAL
    /// for a set too small.
    fn darwin_getgroups(&mut self, m: &mut GuestMem<'_>, size: i32, at: u64) -> Result<u64, Errno> {
        let g = self.dtask.cred.groups.clone();
        if size == 0 {
            return Ok(g.len() as u64);
        }
        if size < g.len() as i32 {
            return Err(Errno::EINVAL);
        }
        let bytes: Vec<u8> = g.iter().flat_map(|x| x.to_le_bytes()).collect();
        m.write(at, &bytes)?;
        Ok(g.len() as u64)
    }

    /// `setuid(uid)`: the real or saved uid, or any for root, who sets the
    /// real and saved ones too; the group list follows the new user unless
    /// it opted out.
    pub(crate) fn darwin_setuid(&mut self, want: u32) -> Result<u64, Errno> {
        let cur = self.dtask.cred.clone();
        if want != cur.ruid && want != cur.svuid {
            self.darwin_suser()?;
        }
        let root = self.darwin_suser().is_ok();
        let (ruid, svuid) = if root { (want, want) } else { (UID_NONE, UID_NONE) };
        let gmuid = if cur.flags & CRF_NOMEMBERD == 0 { want } else { UID_NONE };
        if self.dtask.cred.setresuid(ruid, want, svuid, gmuid) {
            self.darwin_cred_changed();
        }
        Ok(0)
    }

    /// `seteuid(euid)`: the real or saved uid, or any for root.
    fn darwin_seteuid(&mut self, want: u32) -> Result<u64, Errno> {
        let cur = self.dtask.cred.clone();
        if want != cur.ruid && want != cur.svuid {
            self.darwin_suser()?;
        }
        if self.dtask.cred.setresuid(UID_NONE, want, UID_NONE, cur.gmuid) {
            self.darwin_cred_changed();
        }
        Ok(0)
    }

    /// `setreuid(ruid, euid)`: each (-1 for no change) one of the current
    /// ids, or any for root; the saved uid becomes the new effective one
    /// unless one of the asked ids is it.
    fn darwin_setreuid(&mut self, ruid: u32, euid: u32) -> Result<u64, Errno> {
        let (raw_r, raw_e) = (ruid, euid);
        let ruid = if ruid == u32::MAX { UID_NONE } else { ruid };
        let euid = if euid == u32::MAX { UID_NONE } else { euid };
        let cur = self.dtask.cred.clone();
        let bad_r = ruid != UID_NONE && ruid != cur.ruid && ruid != cur.uid && ruid != cur.svuid;
        let bad_e = euid != UID_NONE && euid != cur.uid && euid != cur.ruid && euid != cur.svuid;
        if bad_r || bad_e {
            self.darwin_suser()?;
        }
        let new_euid = if euid != UID_NONE && cur.uid != euid { euid } else { cur.uid };
        let svuid = if cur.svuid != raw_r && cur.svuid != raw_e { new_euid } else { UID_NONE };
        if self.dtask.cred.setresuid(ruid, euid, svuid, cur.gmuid) {
            self.darwin_cred_changed();
        }
        Ok(0)
    }

    /// `setgid(gid)`: the real or saved gid, or any for root, who sets the
    /// real and saved ones too.
    pub(crate) fn darwin_setgid(&mut self, want: u32) -> Result<u64, Errno> {
        let cur = self.dtask.cred.clone();
        if want != cur.rgid && want != cur.svgid {
            self.darwin_suser()?;
        }
        let root = self.darwin_suser().is_ok();
        let (rgid, svgid) = if root { (want, want) } else { (GID_NONE, GID_NONE) };
        if self.dtask.cred.setresgid(rgid, want, svgid) {
            self.darwin_cred_changed();
        }
        Ok(0)
    }

    /// `setegid(egid)`.
    fn darwin_setegid(&mut self, want: u32) -> Result<u64, Errno> {
        let cur = self.dtask.cred.clone();
        if want != cur.rgid && want != cur.svgid {
            self.darwin_suser()?;
        }
        if self.dtask.cred.setresgid(GID_NONE, want, GID_NONE) {
            self.darwin_cred_changed();
        }
        Ok(0)
    }

    /// `setregid(rgid, egid)`.
    fn darwin_setregid(&mut self, rgid: u32, egid: u32) -> Result<u64, Errno> {
        let rgid = if rgid == u32::MAX { GID_NONE } else { rgid };
        let egid = if egid == u32::MAX { GID_NONE } else { egid };
        let cur = self.dtask.cred.clone();
        let bad_r = rgid != GID_NONE && rgid != cur.rgid && rgid != cur.gid() && rgid != cur.svgid;
        let bad_e = egid != GID_NONE && egid != cur.groups[0] && egid != cur.gid() && egid != cur.rgid && egid != cur.svgid;
        if bad_r || bad_e {
            self.darwin_suser()?;
        }
        let new_egid = if egid != GID_NONE && cur.gid() != egid { egid } else { cur.gid() };
        let svgid = if cur.svgid != rgid && cur.svgid != egid { new_egid } else { GID_NONE };
        if self.dtask.cred.setresgid(rgid, egid, svgid) {
            self.darwin_cred_changed();
        }
        Ok(0)
    }

    /// `setgroups1`: at most NGROUPS groups, for root; none sets group 0.
    fn darwin_setgroups1(&mut self, m: &mut GuestMem<'_>, n: u32, at: u64, gmuid: u32) -> Result<u64, Errno> {
        if n as usize > NGROUPS {
            return Err(Errno::EINVAL);
        }
        let groups: Vec<u32> = if n >= 1 { m.read(at, 4 * n as usize)?.chunks(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect() } else { Vec::new() };
        self.darwin_setgroups_internal(groups, gmuid)
    }

    /// `setgroups_internal`: root's, the list (none for just gid 0).
    pub(crate) fn darwin_setgroups_internal(&mut self, mut groups: Vec<u32>, gmuid: u32) -> Result<u64, Errno> {
        self.darwin_suser()?;
        if groups.is_empty() {
            groups.push(0);
        }
        if self.dtask.cred.setgroups(&groups, gmuid) {
            self.darwin_cred_changed();
        }
        Ok(0)
    }

    /// `kern_settid`: `mac_proc_check_settid` first, then for root a
    /// thread identity of its own, or back to the process's.
    fn darwin_settid(&mut self, uid: u32) -> Result<u64, Errno> {
        self.darwin_mac_proc_check_settid()?;
        self.darwin_suser()?;
        if uid == UID_NONE {
            // The thread has no identity of its own to drop.
            return Err(Errno::EPERM);
        }
        self.darwin_unimplemented("settid: a thread's own identity (the per-thread credential the file system checks)".into());
        Err(Errno::EPERM)
    }

    /// `mac_proc_check_settid`: the policies' `mpo_proc_check_settid`.
    /// None of this kernel's policies has one: AMFI's operations
    /// (filled in by its start, `0xfffffff005ab4b2c` on), Sandbox's
    /// (`0xfffffff006f8b9b8`) and AppleImage4's (`0xfffffff006cf33a8`, its
    /// sysctl check alone) leave slot 197 of `struct mac_policy_ops` NULL,
    /// so the check allows.
    fn darwin_mac_proc_check_settid(&mut self) -> Result<(), Errno> {
        Ok(())
    }

    /// `getlogin(namebuf, namelen)`: the session's login name, `namelen`
    /// bytes of it (at most MAXLOGNAME).
    fn darwin_getlogin(&mut self, m: &mut GuestMem<'_>, at: u64, len: u32) -> Result<u64, Errno> {
        let len = (len as usize).min(MAXLOGNAME);
        let sid = self.procs.sid(self.pid, self.pid).unwrap_or(0);
        let mut buf = vec![0u8; MAXLOGNAME];
        if let Some(l) = logins().lock().unwrap_or_else(|e| e.into_inner()).get(&sid) {
            buf[..l.len()].copy_from_slice(l);
        }
        m.write(at, &buf[..len])?;
        Ok(0)
    }

    /// `setlogin(namebuf)`: root's; a name that does not fit MAXLOGNAME - 1
    /// bytes with its NUL is EINVAL, what was copied kept.
    fn darwin_setlogin(&mut self, m: &mut GuestMem<'_>, at: u64) -> Result<u64, Errno> {
        self.darwin_suser()?;
        let mut buf = vec![0u8; MAXLOGNAME - 1];
        let (name, err) = match m.read_cstr_into(at, &mut buf)? {
            Some(n) => (buf[..n].to_vec(), None),
            // copyinstr's ENAMETOOLONG: what it copied is kept.
            None => (buf.clone(), Some(Errno::EINVAL)),
        };
        let sid = self.procs.sid(self.pid, self.pid).unwrap_or(0);
        logins().lock().unwrap_or_else(|e| e.into_inner()).insert(sid, name);
        match err {
            Some(e) => Err(e),
            None => Ok(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_effective_group_takes_a_supplementary_ones_place() {
        let mut c = Cred::of(501, 20);
        c.setgroups(&[20, 12, 61], 501);
        assert!(c.setresgid(GID_NONE, 12, GID_NONE));
        assert_eq!(c.groups, vec![12, 20, 61]);
        assert_eq!(c.gmuid, 501);
        // One not in the list displaces it.
        assert!(c.setresgid(GID_NONE, 7, GID_NONE));
        assert_eq!(c.groups, vec![7, 20, 61]);
        assert_eq!((c.gmuid, c.flags & CRF_NOMEMBERD), (UID_NONE, CRF_NOMEMBERD));
    }

    #[test]
    fn setresuid_reports_a_change() {
        let mut c = Cred::of(0, 0);
        assert!(!c.setresuid(UID_NONE, 0, UID_NONE, 0));
        assert!(c.setresuid(501, 501, 501, 501));
        assert_eq!((c.uid, c.ruid, c.svuid), (501, 501, 501));
    }
}

/// `posix_cred_access`: whether `cred` may have `mode_req` (in owner bits,
/// `S_IRUSR` and the like) of an object with this owner, group and mode.
/// The owner falls through to the group and world bits; root is the
/// caller's to let past first.
pub fn posix_cred_access(cred: &Cred, uid: u32, gid: u32, mode: u32, mode_req: u32) -> Result<(), crate::errno::Errno> {
    let owner = mode & 0o700;
    let group = (mode & 0o070) << 3;
    let world = (mode & 0o007) << 6;
    if cred.uid == uid && mode_req & owner == mode_req {
        return Ok(());
    }
    if mode_req & group & world == mode_req {
        return Ok(());
    }
    let member = cred.groups.contains(&gid);
    let allowed = if mode_req & group != mode_req {
        // A member is refused by the group bits, and world's cannot help.
        !member && mode_req & world == mode_req
    } else {
        member || mode_req & world == mode_req
    };
    if allowed {
        Ok(())
    } else {
        Err(crate::errno::Errno::EACCES)
    }
}
