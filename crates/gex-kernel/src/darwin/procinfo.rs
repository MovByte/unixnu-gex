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
    /// The signature on its executable (`p_textvp`'s blob at `p_textoff`).
    pub codesign: Option<Arc<super::codesign::CodeSign>>,
    /// `p_name`, all of it.
    pub p_name: super::reason::PName,
    /// Its signal dispositions, real timer and accounting flags.
    pub live: Arc<super::kinfo::Live>,
}

impl Public {
    /// The kernel's own process (`bsd_init`'s `kernproc`): `kernel_task`,
    /// root's, started at boot.
    pub fn kernel() -> Public {
        let boot = super::mach::boottime_usec();
        Public {
            cred: Default::default(),
            sugid: false,
            comm: b"kernel_task".to_vec(),
            name: b"kernel_task".to_vec(),
            start: (boot / 1_000_000, boot % 1_000_000),
            uuid: [0; 16],
            uniqueid: 0,
            puniqueid: 0,
            pidversion: 0,
            platform: 0,
            cputype: 0,
            cpusubtype: 0,
            path: Vec::new(),
            fds: None,
            threads: None,
            pcaction: Default::default(),
            persona: None,
            csflags: Default::default(),
            codesign: None,
            p_name: Default::default(),
            live: Default::default(),
        }
    }
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
    pub const EBADF: i32 = 9;
    pub const EACCES: i32 = 13;
    pub const EFAULT: i32 = 14;
    pub const ENAMETOOLONG: i32 = 63;
    pub const ENOTSUP: i32 = 45;
    pub const EOPNOTSUPP: i32 = 102;
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
            codesign: self.dtask.codesign.clone().map(Arc::new),
            p_name: self.dtask.p_name,
            live: Arc::clone(&self.dtask.live),
        }
    }

    /// Publish this process's record for the others.
    pub fn darwin_publish(&mut self) {
        self.darwin_live_sigmasks();
        self.darwin_live_realtimer();
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
            call::PIDFDINFO => self.darwin_proc_pidfdinfo(m, pid, fl, arg as i32, buf, size),
            call::DIRTYCONTROL => return self.darwin_dirtycontrol(pid, fl, arg),
            call::SETCONTROL => self.darwin_setcontrol(m, pid, fl, arg, buf, size),
            call::TERMINATE => return self.darwin_proc_terminate(pid),
            // (`flavor` is the signal, `buffer` the token.)
            call::SIGNAL_AUDITTOKEN => return self.darwin_signal_audittoken(m, buf, fl).map(|()| 0),
            call::TERMINATE_AUDITTOKEN => {
                let pid = self.darwin_audittoken_proc(m, buf)?;
                return self.darwin_terminate_with_proc(pid);
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
            // proc_listcoalitions: the pid argument is its flavor, the
            // flavor its coalition type.
            11 => self.darwin_listcoalitions(m, pid, fl as i32, buf, size),
            12 => self.darwin_can_use_foreground_hw(m, pid, buf, size),
            call::PIDFILEPORTINFO => self.darwin_proc_pidfileportinfo(m, pid, fl, arg as u32, buf, size),
            // KERNMSGBUF, PIDRUSAGE, PIDDYNKQUEUEINFO, TERMINATE_RSR.
            4 | 9 | 13 | 16 => {
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
                // Its session's terminal device, while it has it.
                TTY_ONLY => pid != 0 && super::ctty::proc_tty(&self.procs, pid).is_some_and(|(dev, _)| dev == info),
                // No process is traced by kdebug.
                KDBG_ONLY => false,
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
        if fl == BGSTATE {
            let bg = self.darwin_originator_bgstate()?;
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

    /// `proc_listcoalitions(flavor, type, buffer, buffersize)`: each
    /// coalition (of one type) as `struct procinfo_coalinfo`, as many as
    /// fit; with no buffer, the room they take.
    fn darwin_listcoalitions(&mut self, m: &mut GuestMem<'_>, flavor: i32, k: i32, buf: u64, size: u32) -> Result<u64, i32> {
        const ALL_COALS: i32 = 1;
        const SINGLE_TYPE: i32 = 2;
        const ELEM: u64 = 16;
        let k = match flavor {
            ALL_COALS => -1,
            SINGLE_TYPE => k,
            _ => return Err(e::EINVAL),
        };
        let list = super::coalition::list(k);
        if list.is_empty() || buf == 0 || size == 0 {
            return Ok(list.len() as u64 * ELEM);
        }
        let mut b = Vec::with_capacity(list.len() * ELEM as usize);
        for (id, ty, tasks) in list {
            b.extend_from_slice(&id.to_le_bytes());
            b.extend_from_slice(&ty.to_le_bytes());
            b.extend_from_slice(&tasks.to_le_bytes());
        }
        b.truncate((size as usize).min(b.len()));
        m.write(buf, &b).map_err(|_| 14)?;
        Ok(b.len() as u64)
    }

    /// `proc_get_originatorbgstate`: background if the thread is, not if
    /// the process is an application; else as the originator's task is.
    fn darwin_originator_bgstate(&mut self) -> Result<u32, i32> {
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
        Ok(bg)
    }

    /// `proc_can_use_foreground_hw(pid, reason, reasonsize)`: whether the
    /// process may use foreground hardware, and why. The leader of its
    /// jetsam coalition, an application, may while it is a UI one and not
    /// in the background. (Another member finds no leader: the kernel's
    /// look-up of its coalition's leader starts from no coalition.) Else a
    /// process asking for itself may by the originator of the voucher it
    /// adopted.
    fn darwin_can_use_foreground_hw(&mut self, m: &mut GuestMem<'_>, pid: i32, u_reason: u64, reasonsize: u32) -> Result<u64, i32> {
        const OK: u32 = 0;
        const DAEMON_OK: u32 = 1;
        const DAEMON_LEADER: u32 = 10;
        const LEADER_NONUI: u32 = 11;
        const LEADER_BACKGROUND: u32 = 12;
        const DAEMON_NO_VOUCHER: u32 = 13;
        const NO_VOUCHER_ATTR: u32 = 14;
        const NO_ORIGINATOR: u32 = 15;
        const ORIGINATOR_BACKGROUND: u32 = 16;
        const VOUCHER_ERROR: u32 = 98;
        const ERROR: u32 = 99;
        const PROC_FLAG_APPLICATION: u32 = 0x100_0000;
        const ENOATTR: i32 = 93;
        let mut reason = ERROR;
        let mut ret = 0;
        let r: Result<(), i32> = 'out: {
            if pid <= 0 {
                break 'out Err(e::EINVAL);
            }
            if self.darwin_public(pid).is_none_or(|(_, zombie)| zombie) {
                break 'out Err(e::ESRCH);
            }
            if pid != self.pid && self.creds.uid() != 0 {
                break 'out Err(e::EPERM);
            }
            if super::coalition::leader(pid).1 {
                let flags = match self.darwin_bgstate(pid) {
                    Ok(f) => f,
                    Err(x) => break 'out Err(x),
                };
                if flags & PROC_FLAG_APPLICATION == PROC_FLAG_APPLICATION {
                    let tp = if pid == self.pid { Some(self.darwin_policy()) } else { self.procs.task_policy(pid).map(|c| *c.lock().unwrap_or_else(|e| e.into_inner())) };
                    let ef = tp.map(|p| p.effective).unwrap_or_default();
                    if ef.darwinbg {
                        reason = LEADER_BACKGROUND;
                        break 'out Ok(());
                    }
                    use super::taskpolicy::role;
                    if matches!(ef.role, role::FOREGROUND_APPLICATION | role::BACKGROUND_APPLICATION) {
                        ret = 1;
                        reason = OK;
                    } else {
                        reason = LEADER_NONUI;
                    }
                    break 'out Ok(());
                }
                reason = DAEMON_LEADER;
            }
            if pid != self.pid {
                break 'out Err(e::EINVAL);
            }
            match self.darwin_originator_bgstate() {
                Ok(0) => {
                    reason = DAEMON_OK;
                    ret = 1;
                    Ok(())
                }
                Ok(_) => {
                    reason = ORIGINATOR_BACKGROUND;
                    Ok(())
                }
                Err(x) if x == e::ESRCH => {
                    reason = NO_ORIGINATOR;
                    Ok(())
                }
                Err(ENOATTR) => {
                    reason = NO_VOUCHER_ATTR;
                    Ok(())
                }
                Err(x) if x == e::EINVAL => {
                    reason = DAEMON_NO_VOUCHER;
                    Ok(())
                }
                Err(x) => {
                    reason = VOUCHER_ERROR;
                    Err(x)
                }
            }
        };
        if reasonsize >= 4 && u_reason != 0 {
            let _ = m.write(u_reason, &reason.to_le_bytes());
        }
        r.map(|()| ret)
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
    fn darwin_proc_terminate(&mut self, pid: i32) -> Result<u64, Errno> {
        if pid <= 0 {
            return Err(Errno::EINVAL);
        }
        // proc_find: not a zombie.
        if self.darwin_public(pid).is_none_or(|(_, zombie)| zombie) {
            return Err(Errno::ESRCH);
        }
        self.darwin_terminate_with_proc(pid)
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
        if signum == 0 || signum >= 32 {
            return Err(Errno::EINVAL);
        }
        let pid = self.darwin_audittoken_proc(m, at)?;
        let sig = super::kern::signal_to_linux(signum);
        if sig == 0 {
            self.darwin_unimplemented(format!("a signal by audit token with Darwin signal {signum}, which Linux has no number for"));
            return Err(Errno::EINVAL);
        }
        if !self.darwin_cansignal(pid, signum, true) {
            return Err(Errno::EPERM);
        }
        self.darwin_kill_post(pid, signum);
        Ok(())
    }

    /// `proc_terminate_with_proc` of process `pid`.
    fn darwin_terminate_with_proc(&mut self, pid: i32) -> Result<u64, Errno> {
        // Who may SIGKILL it may SIGTERM it too.
        if !self.darwin_cansignal(pid, super::signal::dsig::SIGKILL, true) {
            return Err(Errno::EPERM);
        }
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
        self.darwin_kill_post(pid, sig);
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
    /// caller's euid the target's, or the privilege to see other users'
    /// processes.
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
        // Another user's process: the caller's PRIV_GLOBAL_PROC_INFO.
        const PRIV_GLOBAL_PROC_INFO: u32 = 1002;
        if same_user && self.dtask.cred.uid != target.cred.uid && self.darwin_priv_check_cred(PRIV_GLOBAL_PROC_INFO, 0).is_err() {
            return Err(e::EPERM);
        }
        Ok(())
    }

    /// The process `proc_find(pid)` finds: none for one that has exited
    /// (`P_REF_DEAD`), and `kernproc` for 0.
    fn darwin_proc_find(&self, pid: i32) -> Option<Public> {
        if pid == 0 {
            return Some(Public::kernel());
        }
        match self.darwin_public(pid) {
            Some((p, false)) => Some(p),
            _ => None,
        }
    }

    /// `proc_pidfdinfo(pid, flavor, fd, buffer, buffersize)`.
    fn darwin_proc_pidfdinfo(&mut self, m: &mut GuestMem<'_>, pid: i32, fl: u32, fd: i32, buf: u64, bufsize: u32) -> Result<u64, i32> {
        let (kind, size) = match fl {
            1 => (Info::Vnode, 176),
            2 => (Info::VnodePath, 1200),
            4 => (Info::Psem, 1184),
            5 => (Info::Pshm, 1192),
            3 | 6..=10 => {
                self.darwin_unimplemented(format!("proc_pidfdinfo flavor {fl} (a socket, pipe, kqueue or channel)"));
                return Err(e::EINVAL);
            }
            _ => return Err(e::EINVAL),
        };
        if bufsize < size {
            return Err(e::ENOMEM);
        }
        let Some(target) = self.darwin_proc_find(pid) else { return Err(e::ESRCH) };
        self.darwin_proc_info_policy(Some(&target), call::PIDFDINFO, true)?;
        let fds = match target.fds.as_ref() {
            Some(fds) => fds,
            // kernproc's table holds no file.
            None if pid == 0 => return Err(e::EBADF),
            None => {
                self.darwin_unimplemented("proc_pidfdinfo of a process in another memory".into());
                return Err(e::EINVAL);
            }
        };
        let Ok(file) = fds.get(fd) else { return Err(e::EBADF) };
        // fp_get_ftype: a descriptor of another type is EBADF.
        if fdtype(&file) != kind.dtype() {
            return Err(e::EBADF);
        }
        let out = self.darwin_file_info(kind, &file, Some((fds, fd)))?;
        debug_assert_eq!(out.len(), size as usize);
        m.write(buf, &out).map_err(|_| 14)?;
        Ok(u64::from(size))
    }

    /// `proc_pidfileportinfo(pid, flavor, name, buffer, buffersize)`: the
    /// file of the file port `name` in the process's space, described as
    /// `proc_fileport_info` does with no process (and so no descriptor's
    /// state).
    fn darwin_proc_pidfileportinfo(&mut self, m: &mut GuestMem<'_>, pid: i32, fl: u32, name: u32, buf: u64, bufsize: u32) -> Result<u64, i32> {
        const VNODEPATHINFO: u32 = 2;
        const SOCKETINFO: u32 = 3;
        const PSHMINFO: u32 = 5;
        const PIPEINFO: u32 = 6;
        let size: u32 = match fl {
            VNODEPATHINFO => 1200,
            SOCKETINFO => 792,
            PSHMINFO => 1192,
            PIPEINFO => 184,
            _ => return Err(e::EINVAL),
        };
        if bufsize < size {
            return Err(e::ENOMEM);
        }
        let Some(target) = self.darwin_proc_find(pid) else { return Err(e::ESRCH) };
        self.darwin_proc_info_policy(Some(&target), call::PIDFILEPORTINFO, true)?;
        // fileport_invoke: anything but a file port's send right is EINVAL.
        let Ok(file) = self.darwin_fileport_file_in(pid, name) else { return Err(e::EINVAL) };
        let ty = fdtype(&file);
        let kind = match fl {
            VNODEPATHINFO if ty != dtype::VNODE => return Err(e::ENOTSUP),
            VNODEPATHINFO => Info::VnodePath,
            SOCKETINFO if ty != dtype::SOCKET => return Err(e::EOPNOTSUPP),
            PSHMINFO if ty != dtype::PSXSHM => return Err(e::EBADF),
            PSHMINFO => Info::Pshm,
            PIPEINFO if ty != dtype::PIPE => return Err(e::EBADF),
            _ => {
                self.darwin_unimplemented(format!("proc_pidfileportinfo flavor {fl} (a socket's or pipe's state)"));
                return Err(e::EINVAL);
            }
        };
        let out = self.darwin_file_info(kind, &file, None)?;
        debug_assert_eq!(out.len(), size as usize);
        m.write(buf, &out).map_err(|_| 14)?;
        Ok(u64::from(size))
    }

    /// A file's `proc_fileinfo`, then its object's: `pid_vnodeinfo`,
    /// `pid_vnodeinfopath`, `pid_pseminfo` or `pid_pshminfo`. `desc` is
    /// the process's descriptor of it, when there is a process.
    fn darwin_file_info(&mut self, kind: Info, file: &Arc<crate::file::OpenFile>, desc: Option<(&crate::file::FdTable, i32)>) -> Result<Vec<u8>, i32> {
        const MAXPATHLEN: usize = 1024;
        let mut out = Vec::with_capacity(1200);
        match kind {
            Info::Psem => {
                let Some(p) = Arc::clone(&file.handle).as_posix_sem() else { return Err(e::EBADF) };
                out.extend_from_slice(&fileinfo(desc, file, dtype::PSXSEM));
                // fill_pseminfo: mode, owner and group, the use count as
                // the size, and the name.
                out.extend_from_slice(&ipc_stat(p.mode, p.uid, p.gid, u64::from(p.usecount())));
                out.extend_from_slice(&ipc_name(&p.name, MAXPATHLEN));
            }
            Info::Pshm => {
                let Some(h) = Arc::clone(&file.handle).as_posix_shm() else { return Err(e::EBADF) };
                out.extend_from_slice(&fileinfo(desc, file, dtype::PSXSHM));
                // fill_pshminfo: mode, owner and group, the length as the
                // size, this open's mapping, and the name.
                let p = &h.0;
                out.extend_from_slice(&ipc_stat(p.mode, p.uid, p.gid, p.length()));
                out.extend_from_slice(&h.mapp_addr().to_le_bytes());
                out.extend_from_slice(&ipc_name(&p.name, MAXPATHLEN));
            }
            Info::Vnode | Info::VnodePath => {
                let Ok(md) = file.metadata() else { return Err(e::EBADF) };
                out.extend_from_slice(&fileinfo(desc, file, dtype::VNODE));
                let path = self.vfs.canonical(&file.path);
                let mnt = super::kern::mount_of(&path);
                let st = crate::fs::Stat { uid: self.creds.uid(), gid: self.creds.gid(), dev: u64::from(mnt.fsid as u32), ..Kernel::stat_from(&md) }.encode_darwin();
                out.extend_from_slice(&vnode_info(&st, md.file_type, mnt.fsid as u32, super::kern::vfsstat::APFS_TYPENUM));
                if kind == Info::VnodePath {
                    let mut p = [0u8; MAXPATHLEN];
                    let n = path.len().min(MAXPATHLEN - 1);
                    p[..n].copy_from_slice(&path.as_bytes()[..n]);
                    out.extend_from_slice(&p);
                }
            }
        }
        Ok(out)
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
            EXITREASONINFO | EXITREASONBASICINFO => self.darwin_pidexitreasoninfo(m, pid, buf, fl == EXITREASONBASICINFO),
            // proc_pidcoalitioninfo: its coalitions' ids, by type (none, 0).
            COALITIONINFO => {
                let (ids, _) = super::coalition::membership(pid);
                let mut b = Vec::with_capacity(40);
                for id in ids {
                    b.extend_from_slice(&id.to_le_bytes());
                }
                b.resize(40, 0);
                m.write(buf, &b).map_err(fault)?;
                Ok(40)
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
            data |= self.darwin_pstat(pid, zombie).1 & note::PDATAMASK;
        }
        if flags & note::EXIT_DETAIL != 0 {
            data |= exit_detail(self.procs.lterm(pid), p.csflags.load(std::sync::atomic::Ordering::Acquire));
        }
        Ok(data)
    }

    /// `p_stat` and `p_xstat`: SRUN, SSTOP for a stopped process, SZOMB.
    pub(crate) fn darwin_pstat(&self, pid: i32, zombie: bool) -> (u32, u32) {
        const SRUN: u32 = 2;
        const SSTOP: u32 = 4;
        const SZOMB: u32 = 5;
        if zombie {
            return (SZOMB, self.procs.xstat(pid).unwrap_or(0));
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
        let pgid = self.procs.pgid(pid, pid).unwrap_or(0);
        w(&mut b, 100, pgid as u32);
        w(&mut b, 104, self.darwin_pjobc(pgid));
        // e_tdev and e_tpgid: the session's terminal while the process has
        // it, else NODEV.
        w(&mut b, 108, super::ctty::NODEV);
        if let Some((tdev, tpgid)) = super::ctty::proc_tty(&self.procs, pid) {
            w(&mut b, 108, tdev);
            w(&mut b, 112, tpgid as u32);
        }
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
        const PROC_FLAG_CONTROLT: u32 = 0x80;
        if self.procs.controlt(pid) {
            f |= PROC_FLAG_CONTROLT;
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
/// `fill_vnodeinfo`'s `struct vnode_info`: `vinfo_stat` from the descriptor's
/// `stat64`, as `munge_vinfo_stat` lays it out, then the vnode's type and
/// its mount's `f_fsid`.
fn vnode_info(st: &[u8], ty: crate::vfs::FileType, fsid: u32, fsid2: u32) -> [u8; 152] {
    use crate::vfs::FileType as T;
    let mut v = [0u8; 152];
    v[..24].copy_from_slice(&st[..24]);
    // The times, then size and blocks.
    v[24..104].copy_from_slice(&st[32..112]);
    // blksize, flags, gen, then rdev.
    v[104..116].copy_from_slice(&st[112..124]);
    v[116..120].copy_from_slice(&st[24..28]);
    let vtype: u32 = match ty {
        T::Regular => 1,
        T::Directory => 2,
        T::CharDevice => 4,
        T::Symlink => 5,
        T::Socket => 6,
        T::Fifo => 7,
    };
    v[136..140].copy_from_slice(&vtype.to_le_bytes());
    v[144..148].copy_from_slice(&fsid.to_le_bytes());
    v[148..152].copy_from_slice(&fsid2.to_le_bytes());
    v
}

/// `DTYPE_*`: a file's kind.
mod dtype {
    pub const VNODE: u32 = 1;
    pub const SOCKET: u32 = 2;
    pub const PSXSHM: u32 = 3;
    pub const PSXSEM: u32 = 4;
    pub const KQUEUE: u32 = 5;
    pub const PIPE: u32 = 6;
}

/// `fg_sendable`: a vnode, socket, pipe or shared memory object, which a
/// unix socket's message may carry (none is `FG_CONFINED` here).
pub(crate) fn fg_sendable(f: &Arc<crate::file::OpenFile>) -> bool {
    matches!(fdtype(f), dtype::VNODE | dtype::SOCKET | dtype::PIPE | dtype::PSXSHM)
}

fn fdtype(f: &Arc<crate::file::OpenFile>) -> u32 {
    if f.handle.pipe_end().is_some() {
        dtype::PIPE
    } else if Arc::clone(&f.handle).as_kqueue().is_some() {
        dtype::KQUEUE
    } else if Arc::clone(&f.handle).as_posix_shm().is_some() {
        dtype::PSXSHM
    } else if Arc::clone(&f.handle).as_posix_sem().is_some() {
        dtype::PSXSEM
    } else if f.handle.metadata().is_ok_and(|md| md.file_type == crate::vfs::FileType::Socket) {
        dtype::SOCKET
    } else {
        dtype::VNODE
    }
}

/// What `proc_pidfdinfo` and `proc_pidfileportinfo` describe of a file.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Info {
    Vnode,
    VnodePath,
    Psem,
    Pshm,
}

impl Info {
    fn dtype(self) -> u32 {
        match self {
            Info::Vnode | Info::VnodePath => dtype::VNODE,
            Info::Psem => dtype::PSXSEM,
            Info::Pshm => dtype::PSXSHM,
        }
    }
}

/// `fill_fileinfo` (`struct proc_fileinfo`, 24 bytes): the file's flags as
/// fg_flag has them (FFLAGS), its offset and type, whether more than one
/// descriptor, file port or message holds it, and with a process the descriptor's own state and its guard's.
fn fileinfo(desc: Option<(&crate::file::FdTable, i32)>, file: &Arc<crate::file::OpenFile>, ty: u32) -> [u8; 24] {
    let lflags = file.darwin_lflags.load(std::sync::atomic::Ordering::Acquire) & (super::lockf::FWASLOCKED | super::ioctl::fflag::FNOCACHE | super::ioctl::fflag::FNORDAHEAD | super::ioctl::fflag::FNODIRECT | super::ioctl::fflag::FSINGLE_WRITER);
    let openflags = (super::bsd::open_flags_back(file.flags()) + 1) as u32 | lflags;
    let mut status: u32 = 0;
    if file.fg_count() > 1 {
        status |= 1;
    }
    let mut guardflags: u32 = 0;
    if let Some((fds, fd)) = desc {
        if fds.cloexec(fd).unwrap_or(false) {
            status |= 2;
        }
        if fds.clofork(fd) {
            status |= 8;
        }
        if let Some(g) = fds.guard(fd) {
            use super::guarded::attr;
            status |= 4;
            for (a, bit) in [(attr::CLOSE, 1), (attr::DUP, 2), (attr::SOCKET_IPC, 4), (attr::FILEPORT, 8)] {
                if g.has(a) {
                    guardflags |= bit;
                }
            }
        }
    }
    let mut b = [0u8; 24];
    b[0..4].copy_from_slice(&openflags.to_le_bytes());
    b[4..8].copy_from_slice(&status.to_le_bytes());
    b[8..16].copy_from_slice(&file.offset().to_le_bytes());
    b[16..20].copy_from_slice(&ty.to_le_bytes());
    b[20..24].copy_from_slice(&guardflags.to_le_bytes());
    b
}

/// A semaphore's or shared memory object's `vinfo_stat` (136 bytes): its
/// mode, owner, group and size, the rest zero.
fn ipc_stat(mode: u32, uid: u32, gid: u32, size: u64) -> [u8; 136] {
    let mut st = [0u8; 136];
    st[4..6].copy_from_slice(&(mode as u16).to_le_bytes());
    st[16..20].copy_from_slice(&uid.to_le_bytes());
    st[20..24].copy_from_slice(&gid.to_le_bytes());
    st[88..96].copy_from_slice(&size.to_le_bytes());
    st
}

/// A semaphore's or shared memory object's name in a `MAXPATHLEN` field:
/// its `PSEMNAMLEN + 1` (or `PSHMNAMLEN + 1`) bytes copied, the rest zero.
fn ipc_name(name: &str, len: usize) -> Vec<u8> {
    const NAMLEN: usize = 31;
    let mut b = vec![0u8; len];
    for (i, c) in name.chars().take(NAMLEN).enumerate() {
        b[i] = c as u32 as u8;
    }
    b
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
