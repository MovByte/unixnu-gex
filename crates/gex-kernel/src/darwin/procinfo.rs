//! `proc_info` (`bsd/kern/proc_info.c`): what one process may learn of
//! another, by call and flavor.
//!
//! The process table keeps each Darwin process's [`Public`] record, the
//! parts of its `struct proc` the calls report, until the process is
//! reaped (a zombie's is read too). A process republishes it as it changes
//! (its credential, its image).

use crate::errno::Errno;
use crate::syscalls::Kernel;
use crate::GuestMem;
use std::sync::Arc;

/// What other processes read of a Darwin process.
#[derive(Clone, Debug, Default)]
pub struct Public {
    pub cred: super::cred::Cred,
    pub sugid: bool,
    /// `p_comm` and `p_name`: the image's file name, cut to MAXCOMLEN and to
    /// twice that.
    pub comm: Vec<u8>,
    pub name: Vec<u8>,
    /// `p_start`: when its fork made it (seconds, microseconds).
    pub start: (u64, u64),
    pub uuid: [u8; 16],
    pub uniqueid: u64,
    pub puniqueid: u64,
    pub pidversion: i32,
    /// `proc_platform`, `p_cputype`, `p_cpusubtype`.
    pub platform: u32,
    pub cputype: u32,
    pub cpusubtype: u32,
    /// The image's path (`proc_pidpath`).
    pub path: Vec<u8>,
    /// Its descriptor table, while it lives.
    pub fds: Option<Arc<crate::file::FdTable>>,
}

/// `MAXCOMLEN`.
const MAXCOMLEN: usize = 16;

/// The wall clock now, as `microtime` gives it.
pub fn microtime() -> (u64, u64) {
    let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    (d.as_secs(), u64::from(d.subsec_micros()))
}

/// `PROC_INFO_CALL_*`.
pub mod call {
    pub const LISTPIDS: u64 = 1;
    pub const PIDINFO: u64 = 2;
    pub const PIDFDINFO: u64 = 3;
    pub const SETCONTROL: u64 = 5;
    pub const PIDFILEPORTINFO: u64 = 6;
    pub const DIRTYCONTROL: u64 = 8;
    pub const PIDRUSAGE: u64 = 9;
    pub const SET_DYLD_IMAGES: u64 = 15;
}

/// `PROC_PID*` flavors.
mod flavor {
    pub const LISTFDS: u32 = 1;
    pub const TASKALLINFO: u32 = 2;
    pub const TBSDINFO: u32 = 3;
    pub const TASKINFO: u32 = 4;
    pub const THREADINFO: u32 = 5;
    pub const LISTTHREADS: u32 = 6;
    pub const REGIONINFO: u32 = 7;
    pub const REGIONPATHINFO: u32 = 8;
    pub const VNODEPATHINFO: u32 = 9;
    pub const THREADPATHINFO: u32 = 10;
    pub const PATHINFO: u32 = 11;
    pub const WORKQUEUEINFO: u32 = 12;
    pub const T_SHORTBSDINFO: u32 = 13;
    pub const LISTFILEPORTS: u32 = 14;
    pub const THREADID64INFO: u32 = 15;
    pub const UNIQIDENTIFIERINFO: u32 = 17;
    pub const T_BSDINFOWITHUNIQID: u32 = 18;
    pub const ARCHINFO: u32 = 19;
    pub const COALITIONINFO: u32 = 20;
    pub const NOTEEXIT: u32 = 21;
    pub const REGIONPATHINFO2: u32 = 22;
    pub const REGIONPATHINFO3: u32 = 23;
    pub const EXITREASONINFO: u32 = 24;
    pub const EXITREASONBASICINFO: u32 = 25;
    pub const LISTUPTRS: u32 = 26;
    pub const LISTDYNKQUEUES: u32 = 27;
    pub const LISTTHREADIDS: u32 = 28;
    pub const VMRTFAULTINFO: u32 = 29;
    pub const PLATFORMINFO: u32 = 30;
    pub const REGIONPATH: u32 = 31;
    pub const IPCTABLEINFO: u32 = 32;
    pub const THREADSCHEDINFO: u32 = 33;
    pub const THREADCOUNTS: u32 = 34;
}

/// A flavor's structure size (`proc_pidinfo`'s table), and whether a null
/// buffer asks for nothing (a list's count); none for no flavor.
fn flavor_size(f: u32) -> Option<(u32, bool)> {
    use flavor::*;
    Some(match f {
        LISTFDS => (8, true),
        TBSDINFO => (136, false),
        TASKINFO => (96, false),
        TASKALLINFO => (232, false),
        THREADINFO => (112, false),
        THREADCOUNTS => (8, false),
        LISTTHREADIDS => (8, false),
        LISTTHREADS => (8, false),
        REGIONINFO => (96, false),
        REGIONPATHINFO | REGIONPATHINFO2 | REGIONPATHINFO3 => (1272, false),
        VNODEPATHINFO => (2352, false),
        THREADPATHINFO => (1288, false),
        PATHINFO => (1024, false),
        WORKQUEUEINFO => (16, false),
        T_SHORTBSDINFO => (64, false),
        LISTFILEPORTS => (8, true),
        THREADID64INFO => (112, false),
        UNIQIDENTIFIERINFO => (56, false),
        T_BSDINFOWITHUNIQID => (192, false),
        ARCHINFO => (8, false),
        COALITIONINFO => (40, false),
        NOTEEXIT => (4, false),
        EXITREASONINFO => (32, false),
        EXITREASONBASICINFO => (24, false),
        LISTUPTRS => (8, true),
        LISTDYNKQUEUES => (8, true),
        // sizeof(vm_rtfault_record_t)
        VMRTFAULTINFO => (40, true),
        PLATFORMINFO => (4, false),
        REGIONPATH => (1040, false),
        IPCTABLEINFO => (8, false),
        THREADSCHEDINFO => (8, false),
        _ => return None,
    })
}

/// `proc_info`'s and `proc_pidinfo`'s errors as Darwin numbers them.
mod e {
    pub const EPERM: i32 = 1;
    pub const ESRCH: i32 = 3;
    pub const ENOMEM: i32 = 12;
    pub const EINVAL: i32 = 22;
    pub const EOVERFLOW: i32 = 84;
}

impl Kernel {
    /// This process's record, made from its state now.
    fn darwin_public_now(&self) -> Public {
        let path = self.exe_path.as_bytes();
        let base = path.rsplit(|&c| c == b'/').next().unwrap_or(path);
        let cut = |n: usize| base[..base.len().min(n)].to_vec();
        Public {
            cred: self.dtask.cred.clone(),
            sugid: self.dtask.sugid,
            comm: cut(MAXCOMLEN),
            name: cut(2 * MAXCOMLEN),
            start: self.dtask.start,
            uuid: self.dtask.uuid,
            uniqueid: self.dtask.uniqueid,
            puniqueid: self.dtask.puniqueid,
            pidversion: self.dtask.pidversion,
            platform: self.dtask.platform.0,
            cputype: self.dtask.cputype.0,
            cpusubtype: self.dtask.cputype.1,
            path: path.to_vec(),
            fds: Some(Arc::clone(&self.fds)),
        }
    }

    /// Publish this process's record for the others.
    pub fn darwin_publish(&mut self) {
        let r: Arc<dyn std::any::Any + Send + Sync> = Arc::new(self.darwin_public_now());
        self.procs.set_darwin(self.pid, r);
    }

    /// Process `pid`'s record (this process's as it is now) and whether it
    /// is a zombie; none for no Darwin process of that pid.
    fn darwin_public(&self, pid: i32) -> Option<(Public, bool)> {
        if pid == self.pid {
            return Some((self.darwin_public_now(), false));
        }
        let (r, zombie) = self.procs.darwin(pid)?;
        r.downcast::<Public>().ok().map(|p| ((*p).clone(), zombie))
    }

    /// `proc_info(callnum, pid, flavor, arg, buffer, buffersize)`.
    pub(crate) fn darwin_proc_info(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        let (callnum, pid, fl, arg, buf, size) = (a[0], a[1] as i32, a[2] as u32, a[3], a[4], a[5] as u32);
        let r = match callnum {
            call::PIDINFO => self.darwin_proc_pidinfo(m, pid, fl, arg, buf, size),
            call::DIRTYCONTROL => return self.darwin_dirtycontrol(pid, fl, arg),
            // proc_set_dyld_images: dyld says where its image list is
            // (`buf`, `size` bytes), which task_info(TASK_DYLD_INFO)
            // reports from then on (task_set_dyld_info: it moves from one
            // range to another once).
            call::SET_DYLD_IMAGES => {
                if pid != self.pid || buf == 0 || buf.checked_add(u64::from(size)).is_none() || self.darwin_dyld_final {
                    return Err(Errno::EINVAL);
                }
                let current = self.darwin_dyld_infos != 0 || self.darwin_dyld_infos_size != 0;
                self.darwin_dyld_infos = buf;
                self.darwin_dyld_infos_size = u64::from(size);
                if current {
                    self.darwin_dyld_final = true;
                }
                Ok(0)
            }
            _ => {
                self.darwin_unimplemented(format!("proc_info call {callnum} (flavor {fl})"));
                Err(e::EINVAL)
            }
        };
        r.map_err(super::errno::errno_of)
    }

    /// `proc_security_policy`: the MAC policies' `proc_check_proc_info`
    /// (Sandbox's operation for the call), then for most flavors the
    /// caller's euid the target's, or root.
    fn darwin_proc_info_policy(&mut self, target: &Public, callnum: u64, same_user: bool) -> Result<(), i32> {
        let op = match callnum {
            call::LISTPIDS => 127,
            call::PIDINFO => 128,
            call::PIDFDINFO => 129,
            call::SETCONTROL => 133,
            call::PIDFILEPORTINFO => 130,
            call::DIRTYCONTROL => 125,
            call::PIDRUSAGE => 131,
            _ => 0,
        };
        if op != 0 {
            let a = super::mac::SbArgs { kind: super::sandbox::kind::PROCESS, ..Default::default() };
            let r = self.darwin_sb_evaluate(op, &a);
            if r != 0 {
                return Err(r as i32);
            }
        }
        if same_user && self.dtask.cred.uid != target.cred.uid && self.dtask.cred.uid != 0 {
            return Err(e::EPERM);
        }
        Ok(())
    }

    /// `proc_pidinfo(pid, 0, 0, flavor, arg, buffer, buffersize)`.
    fn darwin_proc_pidinfo(&mut self, m: &mut GuestMem<'_>, pid: i32, fl: u32, arg: u64, buf: u64, bufsize: u32) -> Result<u64, i32> {
        use flavor::*;
        if pid == 0 {
            match fl {
                WORKQUEUEINFO => return Err(e::EINVAL),
                REGIONPATH | REGIONINFO | REGIONPATHINFO | REGIONPATHINFO2 | REGIONPATHINFO3 if self.pid != 0 => return Err(e::EPERM),
                _ => {}
            }
        }
        let (size, list) = flavor_size(fl).ok_or(e::EINVAL)?;
        let size = if list && buf == 0 { 0 } else { size };
        if bufsize < size {
            return Err(e::ENOMEM);
        }
        if fl == PATHINFO && bufsize > 4 * 1024 {
            return Err(e::EOVERFLOW);
        }
        let findzomb = (matches!(fl, TBSDINFO | T_SHORTBSDINFO | T_BSDINFOWITHUNIQID | UNIQIDENTIFIERINFO) && arg != 0) || matches!(fl, NOTEEXIT | EXITREASONINFO | EXITREASONBASICINFO | PLATFORMINFO);
        if pid == 0 {
            self.darwin_unimplemented(format!("proc_pidinfo of the kernel's process (flavor {fl})"));
            return Err(e::ESRCH);
        }
        let Some((target, zombie)) = self.darwin_public(pid) else { return Err(e::ESRCH) };
        if zombie && !findzomb {
            return Err(e::ESRCH);
        }
        let same_user = !matches!(fl, T_SHORTBSDINFO | UNIQIDENTIFIERINFO | PATHINFO | COALITIONINFO | PLATFORMINFO);
        self.darwin_proc_info_policy(&target, call::PIDINFO, same_user)?;
        let fault = |_| 14;
        match fl {
            UNIQIDENTIFIERINFO => {
                let b = uniqidentifierinfo(&target);
                m.write(buf, &b).map_err(fault)?;
                Ok(b.len() as u64)
            }
            T_SHORTBSDINFO | TBSDINFO | T_BSDINFOWITHUNIQID => {
                let b = match fl {
                    T_SHORTBSDINFO => self.darwin_shortbsdinfo(pid, &target, zombie)?,
                    TBSDINFO => self.darwin_bsdinfo(pid, &target, zombie)?,
                    _ => {
                        let mut b = self.darwin_bsdinfo(pid, &target, zombie)?;
                        b.extend_from_slice(&uniqidentifierinfo(&target));
                        b
                    }
                };
                m.write(buf, &b).map_err(fault)?;
                Ok(b.len() as u64)
            }
            // proc_pidpath: the image's path, its NUL counted out.
            PATHINFO => {
                let mut p = target.path.clone();
                p.push(0);
                if (bufsize as usize) < p.len() {
                    return Err(e::ENOMEM);
                }
                m.write(buf, &p).map_err(fault)?;
                Ok(p.len() as u64 - 1)
            }
            // proc_archinfo: the image's CPU type and subtype.
            ARCHINFO => {
                let mut b = [0u8; 8];
                b[..4].copy_from_slice(&target.cputype.to_le_bytes());
                b[4..].copy_from_slice(&target.cpusubtype.to_le_bytes());
                m.write(buf, &b).map_err(fault)?;
                Ok(8)
            }
            PLATFORMINFO => {
                m.write(buf, &target.platform.to_le_bytes()).map_err(fault)?;
                Ok(4)
            }
            _ => {
                self.darwin_unimplemented(format!("proc_pidinfo flavor {fl}"));
                Err(e::EINVAL)
            }
        }
    }

    /// `p_stat`: SRUN, SSTOP for a stopped process, SZOMB.
    fn darwin_pstat(&self, pid: i32, zombie: bool) -> (u32, u32) {
        const SRUN: u32 = 2;
        const SSTOP: u32 = 4;
        const SZOMB: u32 = 5;
        if zombie {
            return (SZOMB, 0);
        }
        match self.procs.job(pid).map(|j| *j.lock().unwrap_or_else(|e| e.into_inner())) {
            Some(j) if j.stopped => (SSTOP, j.xstat),
            Some(j) => (SRUN, j.xstat),
            None => (SRUN, 0),
        }
    }

    /// `proc_pidshortbsdinfo` (64 bytes).
    fn darwin_shortbsdinfo(&mut self, pid: i32, p: &Public, zombie: bool) -> Result<Vec<u8>, i32> {
        let mut b = vec![0u8; 64];
        let w = |b: &mut Vec<u8>, at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_le_bytes());
        let (stat, _) = self.darwin_pstat(pid, zombie);
        w(&mut b, 0, pid as u32);
        w(&mut b, 4, self.procs.ppid(pid) as u32);
        w(&mut b, 8, self.procs.pgid(pid, pid).unwrap_or(0) as u32);
        w(&mut b, 12, stat);
        b[16..16 + p.comm.len().min(MAXCOMLEN - 1)].copy_from_slice(&p.comm[..p.comm.len().min(MAXCOMLEN - 1)]);
        w(&mut b, 32, self.darwin_pbi_flags(pid, p, zombie)?);
        for (i, v) in [p.cred.uid, p.cred.gid(), p.cred.ruid, p.cred.rgid, p.cred.svuid, p.cred.svgid].into_iter().enumerate() {
            w(&mut b, 36 + 4 * i, v);
        }
        Ok(b)
    }

    /// `proc_pidbsdinfo` (136 bytes).
    fn darwin_bsdinfo(&mut self, pid: i32, p: &Public, zombie: bool) -> Result<Vec<u8>, i32> {
        let mut b = vec![0u8; 136];
        let w = |b: &mut Vec<u8>, at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_le_bytes());
        let (stat, xstat) = self.darwin_pstat(pid, zombie);
        w(&mut b, 0, self.darwin_pbi_flags(pid, p, zombie)?);
        w(&mut b, 4, stat);
        w(&mut b, 8, xstat);
        w(&mut b, 12, pid as u32);
        w(&mut b, 16, self.procs.ppid(pid) as u32);
        for (i, v) in [p.cred.uid, p.cred.gid(), p.cred.ruid, p.cred.rgid, p.cred.svuid, p.cred.svgid].into_iter().enumerate() {
            w(&mut b, 20 + 4 * i, v);
        }
        b[48..48 + p.comm.len().min(MAXCOMLEN - 1)].copy_from_slice(&p.comm[..p.comm.len().min(MAXCOMLEN - 1)]);
        b[64..64 + p.name.len().min(2 * MAXCOMLEN - 1)].copy_from_slice(&p.name[..p.name.len().min(2 * MAXCOMLEN - 1)]);
        // fd_nfiles, a live process's.
        if !zombie {
            w(&mut b, 96, p.fds.as_ref().map_or(0, |f| f.nfiles()) as u32);
        }
        // e_tdev: NODEV without a controlling terminal.
        let pgid = self.procs.pgid(pid, pid).unwrap_or(0);
        w(&mut b, 100, pgid as u32);
        w(&mut b, 104, self.darwin_pjobc(pgid));
        w(&mut b, 108, u32::MAX);
        let nice = self.procs.live_nice(pid).map_or(0, |(_, n)| n);
        b[116..120].copy_from_slice(&nice.to_le_bytes());
        b[120..128].copy_from_slice(&p.start.0.to_le_bytes());
        b[128..136].copy_from_slice(&p.start.1.to_le_bytes());
        Ok(b)
    }

    /// `pg_jobc` of group `pgid`.
    fn darwin_pjobc(&self, pgid: i32) -> u32 {
        self.procs.jobc(pgid).max(0) as u32
    }

    /// `pbi_flags`.
    fn darwin_pbi_flags(&mut self, pid: i32, p: &Public, zombie: bool) -> Result<u32, i32> {
        const PROC_FLAG_LP64: u32 = 0x10;
        const PROC_FLAG_SLEADER: u32 = 0x20;
        const PROC_FLAG_PSUGID: u32 = 0x2000;
        const PROC_FLAG_EXEC: u32 = 0x4000;
        let mut f = PROC_FLAG_LP64;
        if p.sugid {
            f |= PROC_FLAG_PSUGID;
        }
        if self.procs.execed(pid) {
            f |= PROC_FLAG_EXEC;
        }
        if self.procs.sid(pid, pid).ok() == Some(pid) {
            f |= PROC_FLAG_SLEADER;
        }
        // The background and application bits of its task's policy.
        if !zombie {
            f |= self.darwin_bgstate(pid)?;
        }
        Ok(f)
    }

    /// `proc_get_darwinbgstate` of process `pid`'s task.
    fn darwin_bgstate(&mut self, pid: i32) -> Result<u32, i32> {
        use super::taskpolicy::apptype;
        const DARWINBG: u32 = 0x8000;
        const EXT_DARWINBG: u32 = 0x10000;
        const IOS_APPLEDAEMON: u32 = 0x20000;
        const IOS_IMPPROMOTION: u32 = 0x80000;
        const ADAPTIVE: u32 = 0x100000;
        const ADAPTIVE_IMPORTANT: u32 = 0x200000;
        const IMPORTANCE_DONOR: u32 = 0x400000;
        const SUPPRESSED: u32 = 0x800000;
        const APPLICATION: u32 = 0x1000000;
        let Some(p) = self.procs.task_policy(pid) else { return Ok(0) };
        let p = p.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let (r, ef) = (&p.requested, &p.effective);
        let mut f = 0;
        if r.ext_darwinbg {
            f |= EXT_DARWINBG;
        }
        if r.int_darwinbg {
            f |= DARWINBG;
        }
        if r.apptype == apptype::DAEMON_BACKGROUND {
            f |= IOS_APPLEDAEMON;
        }
        if r.apptype == apptype::DAEMON_ADAPTIVE {
            f |= IOS_IMPPROMOTION | ADAPTIVE;
            if r.boosted {
                f |= ADAPTIVE_IMPORTANT;
            }
        }
        if matches!(r.apptype, apptype::APP_DEFAULT | apptype::APP_TAL) {
            f |= APPLICATION;
        }
        // task_is_importance_donor: a marked donor, or a receiver holding
        // assertions (which its boost reflects).
        if p.imp.donor || (p.imp.receiver && r.boosted) {
            f |= IMPORTANCE_DONOR;
        }
        if ef.sup_active {
            f |= SUPPRESSED;
        }
        Ok(f)
    }
}

/// `proc_piduniqidentifierinfo` (56 bytes).
fn uniqidentifierinfo(p: &Public) -> [u8; 56] {
    let mut b = [0u8; 56];
    b[..16].copy_from_slice(&p.uuid);
    b[16..24].copy_from_slice(&p.uniqueid.to_le_bytes());
    b[24..32].copy_from_slice(&p.puniqueid.to_le_bytes());
    b[32..36].copy_from_slice(&p.pidversion.to_le_bytes());
    b
}
