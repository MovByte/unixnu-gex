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
    /// Its threads, while it lives.
    pub threads: Option<Arc<crate::signal::ThreadSigs>>,
    /// `p_pcaction`.
    pub pcaction: Arc<std::sync::atomic::AtomicU32>,
    /// `p_persona`.
    pub persona: Option<Arc<super::persona::Persona>>,
    /// `p_csflags`.
    pub csflags: Arc<std::sync::atomic::AtomicU32>,
}

/// `p_lflag`'s termination bits.
pub(crate) const P_LTERM_DECRYPTFAIL: u32 = 0x0400_0000;
pub(crate) const P_LTERM_JETSAM: u32 = 0x0800_0000;
pub(crate) const P_JETSAM_VMPAGESHORTAGE: u32 = 0x0000_0000;
pub(crate) const P_JETSAM_VMTHRASHING: u32 = 0x1000_0000;
pub(crate) const P_JETSAM_HIWAT: u32 = 0x2000_0000;
pub(crate) const P_JETSAM_PID: u32 = 0x3000_0000;
pub(crate) const P_JETSAM_IDLEEXIT: u32 = 0x4000_0000;
pub(crate) const P_JETSAM_VNODE: u32 = 0x5000_0000;
pub(crate) const P_JETSAM_FCTHRASHING: u32 = 0x6000_0000;
const P_JETSAM_MASK: u32 = 0x7000_0000;

/// What ended a process, as NOTE_EXIT_DETAIL says it (`filt_procevent`
/// and `proc_pidnoteexit`): a decryption failure, a jetsam kill and its
/// cause, a code signing kill.
pub(crate) fn exit_detail(lterm: u32, csflags: u32) -> u32 {
    const NOTE_EXIT_DECRYPTFAIL: u32 = 0x0001_0000;
    const NOTE_EXIT_MEMORY: u32 = 0x0002_0000;
    const NOTE_EXIT_CSERROR: u32 = 0x0004_0000;
    const NOTE_EXIT_MEMORY_VMPAGESHORTAGE: u32 = 0x8000_0000;
    const NOTE_EXIT_MEMORY_VMTHRASHING: u32 = 0x4000_0000;
    const NOTE_EXIT_MEMORY_HIWAT: u32 = 0x2000_0000;
    const NOTE_EXIT_MEMORY_PID: u32 = 0x1000_0000;
    const NOTE_EXIT_MEMORY_IDLE: u32 = 0x0800_0000;
    const NOTE_EXIT_MEMORY_VNODE: u32 = 0x0400_0000;
    const NOTE_EXIT_MEMORY_FCTHRASHING: u32 = 0x0200_0000;
    let mut d = 0;
    if lterm & P_LTERM_DECRYPTFAIL != 0 {
        d |= NOTE_EXIT_DECRYPTFAIL;
    }
    if lterm & P_LTERM_JETSAM != 0 {
        d |= NOTE_EXIT_MEMORY;
        d |= match lterm & P_JETSAM_MASK {
            P_JETSAM_VMPAGESHORTAGE => NOTE_EXIT_MEMORY_VMPAGESHORTAGE,
            P_JETSAM_VMTHRASHING => NOTE_EXIT_MEMORY_VMTHRASHING,
            P_JETSAM_FCTHRASHING => NOTE_EXIT_MEMORY_FCTHRASHING,
            P_JETSAM_VNODE => NOTE_EXIT_MEMORY_VNODE,
            P_JETSAM_HIWAT => NOTE_EXIT_MEMORY_HIWAT,
            P_JETSAM_PID => NOTE_EXIT_MEMORY_PID,
            P_JETSAM_IDLEEXIT => NOTE_EXIT_MEMORY_IDLE,
            _ => 0,
        };
    }
    if csflags & super::amfi::cs::KILLED != 0 {
        d |= NOTE_EXIT_CSERROR;
    }
    d
}

/// `p_pcaction`'s states (`P_PC*`): the control in its low bits, the action
/// taken from bit 16.
pub(crate) const P_PCTHROTTLE: u32 = 1;
pub(crate) const P_PCSUSP: u32 = 2;
pub(crate) const P_PCKILL: u32 = 3;
const P_PCMAX: u32 = 3;
const PROC_ACTION_MASK: u32 = 0xffff_0000;

/// `PROC_SELFSET_*`.
mod selfset {
    pub const PCONTROL: u32 = 1;
    pub const THREADNAME: u32 = 2;
    pub const VMRSRCOWNER: u32 = 3;
    pub const DELAYIDLESLEEP: u32 = 4;
}

/// `MAXTHREADNAMESIZE`.
const MAXTHREADNAMESIZE: u32 = 64;

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
    pub const TERMINATE: u64 = 7;
    pub const DIRTYCONTROL: u64 = 8;
    pub const PIDRUSAGE: u64 = 9;
    pub const PIDORIGINATORINFO: u64 = 10;
    pub const SET_DYLD_IMAGES: u64 = 15;
    pub const SIGNAL_AUDITTOKEN: u64 = 0x11;
    pub const TERMINATE_AUDITTOKEN: u64 = 0x12;
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
    pub const EACCES: i32 = 13;
    pub const EFAULT: i32 = 14;
    pub const ENAMETOOLONG: i32 = 63;
    pub const ENOTSUP: i32 = 45;
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
            threads: Some(Arc::clone(&self.thread_signals)),
            pcaction: Arc::clone(&self.dtask.pcaction),
            persona: self.dtask.persona.clone(),
            csflags: Arc::clone(&self.dtask.csflags),
        }
    }

    /// Publish this process's record for the others.
    pub fn darwin_publish(&mut self) {
        let r: Arc<dyn std::any::Any + Send + Sync> = Arc::new(self.darwin_public_now());
        self.procs.set_darwin(self.pid, r);
    }

    /// Process `pid`'s record (this process's as it is now) and whether it
    /// is a zombie; none for no Darwin process of that pid.
    pub(crate) fn darwin_public(&self, pid: i32) -> Option<(Public, bool)> {
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
            // (`pid` is the list's type, `flavor` its argument.)
            call::LISTPIDS => self.darwin_listpids(m, pid as u32, fl, buf, size),
            call::PIDINFO => self.darwin_proc_pidinfo(m, pid, fl, arg, buf, size),
            call::DIRTYCONTROL => return self.darwin_dirtycontrol(pid, fl, arg),
            call::SETCONTROL => self.darwin_setcontrol(m, pid, fl, arg, buf, size),
            call::TERMINATE => return self.darwin_proc_terminate(m, pid),
            // (`flavor` is the signal, `buffer` the token.)
            call::SIGNAL_AUDITTOKEN => return self.darwin_signal_audittoken(m, buf, fl).map(|()| 0),
            call::TERMINATE_AUDITTOKEN => {
                let pid = self.darwin_audittoken_proc(m, buf)?;
                return self.darwin_terminate_with_proc(m, pid);
            }
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
            call::PIDORIGINATORINFO => self.darwin_pidoriginatorinfo(m, pid, fl, buf, size),
            // PIDFDINFO, KERNMSGBUF, PIDFILEPORTINFO, PIDRUSAGE,
            // LISTCOALITIONS, CANUSEFGHW, PIDDYNKQUEUEINFO, TERMINATE_RSR.
            3 | 4 | 6 | 9 | 11..=13 | 16 => {
                self.darwin_unimplemented(format!("proc_info call {callnum} (flavor {fl})"));
                Err(e::EINVAL)
            }
            // Any other (UDATA_INFO is CONFIG_PROC_UDATA_STORAGE's, macOS's).
            _ => Err(e::EINVAL),
        };
        r.map_err(super::errno::errno_of)
    }

    /// `proc_listpids(type, typeinfo, buffer, buffersize)`: the pids of the
    /// processes of a group, a parent, a terminal, an effective or real
    /// user, or all (the live ones, the latest first and the kernel's
    /// last, then the zombies); for no buffer, room for twenty more than
    /// there are.
    fn darwin_listpids(&mut self, m: &mut GuestMem<'_>, ty: u32, info: u32, buf: u64, bufsize: u32) -> Result<u64, i32> {
        const ALL_PIDS: u32 = 1;
        const PGRP_ONLY: u32 = 2;
        const TTY_ONLY: u32 = 3;
        const UID_ONLY: u32 = 4;
        const RUID_ONLY: u32 = 5;
        const PPID_ONLY: u32 = 6;
        const KDBG_ONLY: u32 = 7;
        self.darwin_proc_info_policy(None, call::LISTPIDS, false)?;
        let mut all = self.procs.listing();
        let nprocs = all.len() as u32;
        if buf == 0 {
            return Ok(u64::from((nprocs + 20) * 4));
        }
        if bufsize < 4 {
            return Err(e::ENOMEM);
        }
        let numprocs = (nprocs + 20).min(bufsize / 4) as usize;
        // The kernel's own process, made first, ends the live ones.
        let live = all.iter().take_while(|p| !p.3).count();
        all.insert(live, (0, 0, 0, false));
        let mut out = Vec::new();
        for (pid, ppid, pgid, _) in all {
            let keep = match ty {
                ALL_PIDS => true,
                PGRP_ONLY => pgid == info as i32,
                PPID_ONLY => ppid == info as i32,
                // No process has a controlling terminal, nor kdebug tracing.
                TTY_ONLY | KDBG_ONLY => false,
                UID_ONLY | RUID_ONLY => {
                    let c = if pid == 0 { Some(super::cred::Cred::default()) } else { self.darwin_public(pid).map(|(p, _)| p.cred) };
                    c.is_some_and(|c| (if ty == UID_ONLY { c.uid } else { c.ruid }) == info)
                }
                _ => false,
            };
            if keep {
                out.extend_from_slice(&pid.to_le_bytes());
            }
            if out.len() / 4 >= numprocs {
                break;
            }
        }
        m.write(buf, &out).map_err(|_| 14)?;
        Ok(out.len() as u64)
    }

    /// `proc_pidoriginatorinfo(pid, flavor, buffer, buffersize)`: of the
    /// calling process (pid 0 or its own), the originator of the current
    /// thread's voucher: its executable's UUID, or that and its pid.
    fn darwin_pidoriginatorinfo(&mut self, m: &mut GuestMem<'_>, pid: i32, fl: u32, buf: u64, bufsize: u32) -> Result<u64, i32> {
        const UUID: u32 = 1;
        const BGSTATE: u32 = 2;
        const PID_UUID: u32 = 3;
        let size = match fl {
            UUID => 16,
            BGSTATE => 4,
            // sizeof(struct proc_originatorinfo).
            PID_UUID => 48,
            _ => return Err(e::EINVAL),
        };
        if bufsize < size {
            return Err(e::ENOMEM);
        }
        if pid != 0 && pid != self.pid {
            return Err(e::EINVAL);
        }
        // proc_get_originatorbgstate: background if the thread is, not if
        // the process is an application; else as the originator's task is.
        if fl == BGSTATE {
            const PROC_FLAG_APPLICATION: u32 = 0x100_0000;
            let mut bg = u32::from(self.darwin_thread_darwinbg(self.tid));
            if bg == 0 && self.darwin_bgstate(self.pid)? & PROC_FLAG_APPLICATION == 0 {
                let origin = self.darwin_voucher_origin_pid()?;
                // proc_pidbackgrounded: a live process's task's DARWIN_BG.
                if self.darwin_public(origin).is_none_or(|(_, zombie)| zombie) {
                    return Err(e::ESRCH);
                }
                let tp = if origin == self.pid { Some(self.darwin_policy()) } else { self.procs.task_policy(origin).map(|c| *c.lock().unwrap_or_else(|e| e.into_inner())) };
                bg = u32::from(tp.is_some_and(|p| p.effective.darwinbg));
            }
            m.write(buf, &bg.to_le_bytes()).map_err(|_| 14)?;
            return Ok(4);
        }
        let origin = self.darwin_voucher_origin_pid()?;
        // proc_piduuidinfo: its executable's UUID, a zombie's too.
        let (p, _) = self.darwin_public(origin).ok_or(e::ESRCH)?;
        let mut b = p.uuid.to_vec();
        if fl == PID_UUID {
            b.extend_from_slice(&origin.to_le_bytes());
            b.resize(48, 0);
        }
        m.write(buf, &b).map_err(|_| 14)?;
        Ok(u64::from(size))
    }

    /// `thread_get_current_voucher_origin_pid`: the bank's
    /// BANK_ORIGINATOR_PID of the current thread's voucher, as the errno
    /// its callers make of a failure (none: EINVAL).
    fn darwin_voucher_origin_pid(&mut self) -> Result<i32, i32> {
        // thread_get_current_voucher_origin_pid: the bank's
        // BANK_ORIGINATOR_PID of the thread's voucher (none: EINVAL).
        const ENOATTR: i32 = 93;
        let voucher = self.dtask.threads.map.get(&self.tid).and_then(|t| t.voucher);
        let Some(v) = voucher else { return Err(e::EINVAL) };
        match self.mach_voucher_attr_command(v, super::voucher::key::BANK, super::voucher::bank::ORIGINATOR_PID, &[], 4) {
            Ok(b) => Ok(i32::from_le_bytes(b[..4].try_into().unwrap())),
            Err(super::voucher::vkr::INVALID_TASK) => Err(e::ESRCH),
            Err(super::voucher::vkr::INVALID_VALUE) => Err(ENOATTR),
            Err(_) => Err(e::EINVAL),
        }
    }

    /// `proc_terminate(pid)`: another process the caller may SIGKILL,
    /// marked terminated for memorystatus and in its task's policy, sent
    /// the signal `memorystatus_on_terminate` picks, which is the answer.
    fn darwin_proc_terminate(&mut self, m: &mut GuestMem<'_>, pid: i32) -> Result<u64, Errno> {
        if pid <= 0 {
            return Err(Errno::EINVAL);
        }
        // proc_find: not a zombie.
        if self.darwin_public(pid).is_none_or(|(_, zombie)| zombie) {
            return Err(Errno::ESRCH);
        }
        self.darwin_terminate_with_proc(m, pid)
    }

    /// The live process an audit token names: its pid (`val[5]`, EINVAL
    /// unless positive) with the token's pidversion (`val[7]`, ESRCH
    /// otherwise).
    fn darwin_audittoken_proc(&mut self, m: &GuestMem<'_>, at: u64) -> Result<i32, Errno> {
        if at == 0 {
            return Err(Errno::EINVAL);
        }
        let t = m.read(at, 32).map_err(|_| Errno::EFAULT)?;
        let val = |i: usize| i32::from_le_bytes(t[4 * i..4 * i + 4].try_into().unwrap());
        let pid = val(5);
        if pid <= 0 {
            return Err(Errno::EINVAL);
        }
        match self.darwin_public(pid) {
            Some((p, false)) if p.pidversion == val(7) => Ok(pid),
            _ => Err(Errno::ESRCH),
        }
    }

    /// `proc_signal_with_audittoken`: signal `signum` (1 to 31) to the
    /// process the token names, if the caller may signal it.
    fn darwin_signal_audittoken(&mut self, m: &mut GuestMem<'_>, at: u64, signum: u32) -> Result<(), Errno> {
        use crate::syscalls::nr;
        if signum == 0 || signum >= 32 {
            return Err(Errno::EINVAL);
        }
        let pid = self.darwin_audittoken_proc(m, at)?;
        let sig = super::kern::signal_to_linux(signum);
        if sig == 0 {
            self.darwin_unimplemented(format!("a signal by audit token with Darwin signal {signum}, which Linux has no number for"));
            return Err(Errno::EINVAL);
        }
        // cansignal, then psignal: kill's check and post.
        self.canonical(m, nr::KILL, [pid as u64, u64::from(sig), 0, 0, 0, 0]).map(|_| ())
    }

    /// `proc_terminate_with_proc` of process `pid`.
    fn darwin_terminate_with_proc(&mut self, m: &mut GuestMem<'_>, pid: i32) -> Result<u64, Errno> {
        use crate::syscalls::nr;
        // cansignal(.., SIGKILL), as kill's own check makes it.
        self.canonical(m, nr::KILL, [pid as u64, 0, 0, 0, 0, 0])?;
        if pid == self.pid {
            return Err(Errno::EPERM);
        }
        let sig = self.procs.jetsam().on_terminate(pid);
        // proc_set_task_policy(TASK_POLICY_ATTRIBUTE, TASK_POLICY_TERMINATED).
        if let Some(cell) = self.procs.task_policy(pid) {
            let mut p = cell.lock().unwrap_or_else(|e| e.into_inner());
            p.requested.terminated = true;
            p.update(false);
        }
        self.canonical(m, nr::KILL, [pid as u64, u64::from(super::kern::signal_to_linux(sig)), 0, 0, 0, 0])?;
        Ok(u64::from(sig))
    }

    /// `proc_setcontrol(pid, flavor, arg, buffer, buffersize)`: the calling
    /// process's own process control, its thread's name, its standing as
    /// the VM resource owner (root's alone), or its idle-sleep delay (not
    /// configured on iOS).
    fn darwin_setcontrol(&mut self, m: &mut GuestMem<'_>, pid: i32, fl: u32, arg: u64, buf: u64, bufsize: u32) -> Result<u64, i32> {
        use std::sync::atomic::Ordering;
        if pid != self.pid {
            return Err(e::EINVAL);
        }
        self.darwin_proc_info_policy(None, call::SETCONTROL, false)?;
        match fl {
            selfset::PCONTROL => {
                let pcontrol = arg as u32;
                if pcontrol > P_PCMAX {
                    return Err(e::EINVAL);
                }
                // The control state replaced, the action state kept.
                let pc = &self.dtask.pcaction;
                let _ = pc.fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| Some((v & PROC_ACTION_MASK) | pcontrol));
            }
            // bsd_setthreadname: at most MAXTHREADNAMESIZE - 1 bytes, up to
            // their first NUL.
            selfset::THREADNAME => {
                if bufsize > MAXTHREADNAMESIZE - 1 {
                    return Err(e::ENAMETOOLONG);
                }
                let raw = if bufsize == 0 { Vec::new() } else { m.read(buf, bufsize as usize).map_err(|_| e::EFAULT)?.to_vec() };
                let name = raw.split(|&c| c == 0).next().unwrap_or(&[]).to_vec();
                self.signals.thread().set_name(Some(name));
            }
            selfset::VMRSRCOWNER => {
                if self.dtask.cred.uid != 0 {
                    return Err(e::EPERM);
                }
                self.dtask.vmrsrcowner = true;
            }
            // CONFIG_DELAY_IDLE_SLEEP is macOS's.
            selfset::DELAYIDLESLEEP => return Err(e::ENOTSUP),
            _ => return Err(e::ENOTSUP),
        }
        Ok(0)
    }

    /// `proc_security_policy`: the MAC policies' `proc_check_proc_info`
    /// (Sandbox's operation for the call), then for most flavors the
    /// caller's euid the target's, or root.
    fn darwin_proc_info_policy(&mut self, target: Option<&Public>, callnum: u64, same_user: bool) -> Result<(), i32> {
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
        let Some(target) = target else { return Ok(()) };
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
        self.darwin_proc_info_policy(Some(&target), call::PIDINFO, same_user)?;
        let fault = |_| 14;
        match fl {
            // proc_pidfdlist: each open descriptor and its type, as many
            // as fit; for no buffer, room for the table and twenty more.
            LISTFDS => {
                let Some(fds) = target.fds.as_ref() else { return Ok(0) };
                let nfiles = fds.nfiles() as u64;
                if buf == 0 {
                    return Ok((nfiles + 20) * 8);
                }
                let numfds = nfiles.min(u64::from(bufsize) / 8) as usize;
                let mut b = Vec::new();
                for (fd, f, _) in fds.entries().into_iter().take(numfds) {
                    b.extend_from_slice(&fd.to_le_bytes());
                    b.extend_from_slice(&fdtype(&f).to_le_bytes());
                }
                m.write(buf, &b).map_err(fault)?;
                Ok(b.len() as u64)
            }
            // proc_pidlistthreads: fill_taskthreadlist's each thread's
            // thread id, or its TSD base (`cthread_self`), in the order
            // they were made, as many as fit of the threads and ten more.
            LISTTHREADIDS | LISTTHREADS => {
                let Some(threads) = target.threads.as_ref() else { return Ok(0) };
                let list: Vec<_> = threads.tids_in_order().into_iter().filter_map(|t| threads.get(t)).collect();
                let numthreads = (list.len() + 10).min(bufsize as usize / 8);
                let mut b = Vec::new();
                for t in list.iter().take(numthreads) {
                    let v = if fl == LISTTHREADIDS { t.darwin_id() } else { t.tsd() };
                    b.extend_from_slice(&v.to_le_bytes());
                }
                m.write(buf, &b).map_err(fault)?;
                Ok(b.len() as u64)
            }
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
            NOTEEXIT => {
                let data = self.darwin_pidnoteexit(pid, &target, zombie, arg)?;
                m.write(buf, &data.to_le_bytes()).map_err(fault)?;
                Ok(4)
            }
            _ => {
                self.darwin_unimplemented(format!("proc_pidinfo flavor {fl}"));
                Err(e::EINVAL)
            }
        }
    }

    /// `proc_pidnoteexit`: for its parent only, what a NOTE_EXIT knote
    /// with `flags` (NOTE_EXITSTATUS, NOTE_EXIT_DETAIL) would carry. (No
    /// process is traced here, so no parent-in-waiting asks.)
    fn darwin_pidnoteexit(&self, pid: i32, p: &Public, zombie: bool, flags: u64) -> Result<u32, i32> {
        use crate::procnote::note;
        let flags = flags as u32;
        if self.procs.ppid(pid) != self.pid {
            return Err(e::EACCES);
        }
        let mut data = 0;
        if flags & note::EXITSTATUS != 0 {
            let xstat = if zombie {
                self.procs.exit_status(pid).map_or(0, |w| super::exit::status_from_linux(w as u32) & 0xffff)
            } else {
                self.darwin_pstat(pid, false).1
            };
            data |= xstat & note::PDATAMASK;
        }
        if flags & note::EXIT_DETAIL != 0 {
            data |= exit_detail(self.procs.lterm(pid), p.csflags.load(std::sync::atomic::Ordering::Acquire));
        }
        Ok(data)
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
        // PROC_CONTROL_STATE and PROC_ACTION_STATE.
        const PROC_FLAG_PC_THROTTLE: u32 = 0x200;
        const PROC_FLAG_PC_SUSP: u32 = 0x400;
        const PROC_FLAG_PC_KILL: u32 = 0x600;
        const PROC_FLAG_PA_THROTTLE: u32 = 0x800;
        const PROC_FLAG_PA_SUSP: u32 = 0x1000;
        let pc = p.pcaction.load(std::sync::atomic::Ordering::Acquire);
        f |= match pc & P_PCMAX {
            P_PCTHROTTLE => PROC_FLAG_PC_THROTTLE,
            P_PCSUSP => PROC_FLAG_PC_SUSP,
            P_PCKILL => PROC_FLAG_PC_KILL,
            _ => 0,
        };
        f |= match (pc >> 16) & P_PCMAX {
            P_PCTHROTTLE => PROC_FLAG_PA_THROTTLE,
            P_PCSUSP => PROC_FLAG_PA_SUSP,
            _ => 0,
        };
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

/// A descriptor's `PROX_FDTYPE_*` (its file glob's `DTYPE_*`).
fn fdtype(f: &Arc<crate::file::OpenFile>) -> u32 {
    const VNODE: u32 = 1;
    const SOCKET: u32 = 2;
    const PSHM: u32 = 3;
    const KQUEUE: u32 = 5;
    const PIPE: u32 = 6;
    if f.handle.pipe_end().is_some() {
        PIPE
    } else if Arc::clone(&f.handle).as_kqueue().is_some() {
        KQUEUE
    } else if Arc::clone(&f.handle).as_posix_shm().is_some() {
        PSHM
    } else if f.handle.metadata().is_ok_and(|md| md.file_type == crate::vfs::FileType::Socket) {
        SOCKET
    } else {
        VNODE
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
