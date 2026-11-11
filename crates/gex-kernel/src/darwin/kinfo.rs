//! `kern.proc.*`: the process table as `struct kinfo_proc` records
//! (`sysctl_prochandle`, `fill_user64_proc` in `bsd/kern/kern_sysctl.c`).

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;

use super::itimer::Itimerval;
use super::kern::SysctlReq;
use super::procinfo::Public;
use crate::errno::Errno;
use crate::syscalls::Kernel;
use crate::GuestMem;

/// `sizeof(struct user64_kinfo_proc)`.
const KINFO_SIZE: usize = 648;
/// `KERN_PROCSLOP`: the room a size query leaves for processes to come.
const KERN_PROCSLOP: u64 = 5 * KINFO_SIZE as u64;

/// `p_flag` (`bsd/sys/proc.h`).
mod pf {
    pub const CONTROLT: u32 = 0x2;
    pub const LP64: u32 = 0x4;
    pub const NOCLDSTOP: u32 = 0x8;
    pub const SUGID: u32 = 0x100;
    pub const SYSTEM: u32 = 0x200;
    pub const WEXIT: u32 = 0x2000;
    pub const EXEC: u32 = 0x4000;
    pub const NOCLDWAIT: u32 = 0x4000_0000;
}

/// `p_acflag` (`bsd/sys/acct.h`).
pub(crate) mod ac {
    pub const AFORK: u32 = 0x01;
    pub const ASU: u32 = 0x02;
}

const SRUN: u32 = 2;
const EPROC_SLEADER: u32 = 0x02;
/// `NODEV`: no controlling terminal's device.
const NODEV: u32 = u32::MAX;
const NGROUPS: usize = 16;

/// What other processes read of this one and the rest of the kernel state
/// does not hold where they can reach it: its signal dispositions, its real
/// timer, its accounting flags.
#[derive(Debug, Default)]
pub struct Live {
    pub sigignore: AtomicU32,
    pub sigcatch: AtomicU32,
    pub realtimer: Mutex<(Itimerval, u64)>,
    pub acflag: AtomicU32,
    /// `p_argc`, `p_argslen`, `user_stack`: where its strings are.
    pub argc: AtomicU32,
    pub argslen: AtomicU32,
    pub user_stack: AtomicU64,
}

fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

/// A `struct user64_timeval` of `us` microseconds.
fn put_timeval(b: &mut [u8], at: usize, us: u64) {
    b[at..at + 8].copy_from_slice(&((us / 1_000_000) as i64).to_le_bytes());
    put32(b, at + 8, (us % 1_000_000) as u32);
}

impl Kernel {
    /// `kern.proc.{all,pid,pgrp,tty,uid,ruid}`.
    pub(crate) fn darwin_sysctl_proc(&mut self, m: &mut GuestMem<'_>, path: &str, tail: &[i32], req: &mut SysctlReq) -> Result<(), Errno> {
        let cmd = path.rsplit('.').next().unwrap_or(path);
        if tail.len() != 1 && !(tail.is_empty() && cmd == "all") {
            return Err(Errno::EINVAL);
        }
        if !matches!(cmd, "all" | "pid" | "pgrp" | "tty" | "uid" | "ruid") {
            return Err(super::errno::errno_of(45));
        }
        let arg = tail.first().copied().unwrap_or(0);
        let mut dp = req.old;
        let mut buflen = if req.old != 0 { req.oldlen } else { 0 };
        let mut needed = 0u64;
        // proc_iterate over the live processes, the kernel's last of them,
        // then the zombies.
        let mut all = self.procs.listing();
        let live = all.iter().take_while(|p| !p.3).count();
        all.insert(live, (0, 0, 0, false));
        let records: Vec<(i32, i32, i32, bool, Public)> = all
            .into_iter()
            .filter_map(|(pid, ppid, pgid, zombie)| {
                let p = if pid == 0 { Public::kernel() } else { self.darwin_public(pid)?.0 };
                Some((pid, ppid, pgid, zombie, p))
            })
            .collect();
        for (pid, ppid, pgid, zombie, p) in &records {
            // proc_iterate's filter, whether or not there is room.
            match cmd {
                "pid" if *pid != arg => continue,
                "pgrp" if *pgid != arg => continue,
                _ => {}
            }
            if buflen >= KINFO_SIZE as u64 {
                match cmd {
                    // Its session's terminal device, while it has it.
                    "tty" if super::ctty::proc_tty(&self.procs, *pid).is_none_or(|(dev, _)| dev == NODEV || dev != arg as u32) =>
                    {
                        continue
                    }
                    "uid" if p.cred.uid != arg as u32 => continue,
                    "ruid" if p.cred.ruid != arg as u32 => continue,
                    _ => {}
                }
                let refs = records.iter().filter(|r| r.4.cred == p.cred).count() as u32;
                let k = self.darwin_kinfo(*pid, *ppid, *pgid, *zombie, p, refs);
                m.write(dp, &k)?;
                dp += KINFO_SIZE as u64;
                buflen -= KINFO_SIZE as u64;
            }
            needed += KINFO_SIZE as u64;
        }
        if req.old != 0 {
            req.oldlen = dp - req.old;
            if needed > req.oldlen {
                return Err(Errno::ENOMEM);
            }
        } else {
            req.oldlen = needed + KERN_PROCSLOP;
        }
        req.oldidx += req.oldlen;
        Ok(())
    }

    /// `fill_user64_proc`. `refs` is `cr_ref`: credentials are shared, one
    /// reference for each process holding this one.
    fn darwin_kinfo(&self, pid: i32, ppid: i32, pgid: i32, zombie: bool, p: &Public, refs: u32) -> [u8; KINFO_SIZE] {
        let mut b = [0u8; KINFO_SIZE];
        put_timeval(&mut b, 0, p.start.0 * 1_000_000 + p.start.1);
        let (stat, xstat) = if pid == 0 { (SRUN, 0) } else { self.darwin_pstat(pid, zombie) };
        put32(&mut b, 32, self.darwin_p_flag(pid, p));
        b[36] = stat as u8;
        put32(&mut b, 40, pid as u32);
        let (itv, rtime) = *p.live.realtimer.lock().unwrap_or_else(|e| e.into_inner());
        put_timeval(&mut b, 120, itv.interval);
        put_timeval(&mut b, 136, itv.value);
        put_timeval(&mut b, 152, rtime);
        put32(&mut b, 232, p.live.sigignore.load(Ordering::Relaxed));
        put32(&mut b, 236, p.live.sigcatch.load(Ordering::Relaxed));
        b[242] = self.procs.live_nice(pid).map_or(0, |(_, n)| n) as u8;
        let comm = p.comm.len().min(16);
        b[243..243 + comm].copy_from_slice(&p.comm[..comm]);
        b[280..282].copy_from_slice(&(xstat.min(0xffff) as u16).to_le_bytes());
        b[282..284].copy_from_slice(&(p.live.acflag.load(Ordering::Relaxed) as u16).to_le_bytes());
        // The eproc.
        for (i, v) in [p.cred.ruid, p.cred.svuid, p.cred.rgid, p.cred.svgid].into_iter().enumerate() {
            put32(&mut b, 392 + 4 * i, v);
        }
        put32(&mut b, 416, refs);
        put32(&mut b, 420, p.cred.uid);
        b[424..426].copy_from_slice(&(p.cred.groups.len() as u16).to_le_bytes());
        for (i, g) in p.cred.groups.iter().take(NGROUPS).enumerate() {
            put32(&mut b, 428 + 4 * i, *g);
        }
        put32(&mut b, 560, ppid as u32);
        put32(&mut b, 564, pgid as u32);
        put32(&mut b, 568, self.procs.jobc(pgid).max(0) as u32);
        // e_tdev and e_tpgid: the session's terminal while the process
        // has it.
        put32(&mut b, 572, NODEV);
        if let Some((tdev, tpgid)) = (pid != 0).then(|| super::ctty::proc_tty(&self.procs, pid)).flatten() {
            put32(&mut b, 572, tdev);
            put32(&mut b, 576, tpgid as u32);
        }
        if pid != 0 && self.procs.sid(pid, pid).ok() == Some(pid) {
            put32(&mut b, 612, EPROC_SLEADER);
        }
        b
    }

    /// `kern.procargs2.<pid>` (`sysctl_procargsx`): a word of `argc`, then
    /// the top of the process's stack, from its executable's path on: the
    /// strings `exec_copyout_strings` put there. A restricted process's
    /// environment is left out for anyone else.
    pub(crate) fn darwin_sysctl_procargs2(&mut self, m: &mut GuestMem<'_>, tail: &[i32], req: &mut SysctlReq) -> Result<(), Errno> {
        const EXECUTABLE_KEY_LEN: u64 = b"executable_path=".len() as u64;
        const CS_RESTRICT: u32 = 0x800;
        const INT: u64 = 4;
        let &[pid, ..] = tail else { return Err(Errno::EINVAL) };
        let where_ = req.old;
        // The word for argc comes off the room first; a size under a word
        // wraps, past ARG_MAX.
        let buflen = if where_ != 0 { req.oldlen } else { 0 }.wrapping_sub(INT);
        if where_ != 0 && (buflen == 0 || buflen > super::rlimit::ARG_MAX) {
            return Err(Errno::EINVAL);
        }
        // proc_find: no zombies; the kernel's process has no user stack.
        if pid == 0 {
            return Err(Errno::EINVAL);
        }
        let Some((p, false)) = self.darwin_public(pid) else { return Err(Errno::EINVAL) };
        let omit_env = pid != self.pid
            && p.csflags.load(Ordering::Relaxed) & CS_RESTRICT != 0
            && !self.darwin_task_entitled("com.apple.private.read-environment-variables");
        let user_stack = p.live.user_stack.load(Ordering::Relaxed);
        if user_stack == 0 {
            return Err(Errno::EINVAL);
        }
        let argc = p.live.argc.load(Ordering::Relaxed);
        let mut argslen = u64::from(p.live.argslen.load(Ordering::Relaxed)) - EXECUTABLE_KEY_LEN;
        let mut size = 0u64;
        if where_ != 0 || omit_env {
            if p.cred.uid != self.dtask.cred.uid {
                self.darwin_suser().map_err(|_| Errno::EINVAL)?;
            }
            // The stack's top pages, as vm_map_copyin takes them.
            let arg_size = (argslen + super::mach::PAGE_MASK) & !super::mach::PAGE_MASK;
            let arg_addr = user_stack - arg_size;
            let mut copy = vec![0u8; arg_size as usize];
            if pid == self.pid {
                let bytes = m.kernel();
                let at = arg_addr as usize;
                copy.copy_from_slice(bytes.bytes.get(at..at + arg_size as usize).ok_or(Errno::EIO)?);
            } else {
                let peer = self.procs.vm(pid).map_err(|_| Errno::EINVAL)?;
                if !peer.mem.read(arg_addr, &mut copy) {
                    return Err(Errno::EIO);
                }
            }
            let mut end = copy.len();
            if omit_env {
                // argc + 1 strings: the path (with the NULs that align what
                // follows it) and the arguments.
                let area = &copy[end - argslen as usize..];
                let mut argvsize = 0usize;
                let mut index = 0u32;
                while index < argc + 1 && argvsize < area.len() {
                    let cur = &area[argvsize..];
                    let mut len = cur.iter().position(|&b| b == 0).unwrap_or(cur.len());
                    if len < cur.len() {
                        len += 1;
                        if index == 0 {
                            while len < cur.len() && cur[len] == 0 {
                                len += 1;
                            }
                        }
                    }
                    argvsize += len;
                    index += 1;
                }
                end = end - argslen as usize + argvsize;
                argslen = argvsize as u64;
            }
            if where_ != 0 {
                let take = argslen.min(buflen);
                // A short buffer gets the end of what would fit.
                let data = &copy[end - take as usize..end];
                m.write_u32(where_, argc)?;
                m.write(where_ + INT, data)?;
                size = take + INT;
            }
        }
        if where_ == 0 {
            size = argslen + INT;
            size += (INT - (size & (INT - 1))) & (INT - 1);
        }
        // sysctl_doprocargs2: the size is what was consumed.
        req.oldlen = size;
        req.oldidx += size;
        Ok(())
    }

    /// `p_flag`, for the bits this kernel's processes can have.
    fn darwin_p_flag(&self, pid: i32, p: &Public) -> u32 {
        if pid == 0 {
            return pf::SYSTEM | pf::LP64;
        }
        let mut f = pf::LP64;
        if p.sugid {
            f |= pf::SUGID;
        }
        if self.procs.execed(pid) {
            f |= pf::EXEC;
        }
        if self.procs.exiting(pid) {
            f |= pf::WEXIT;
        }
        if self.procs.controlt(pid) {
            f |= pf::CONTROLT;
        }
        let (nocldstop, nocldwait) = self.procs.nocld(pid);
        if nocldstop {
            f |= pf::NOCLDSTOP;
        }
        if nocldwait {
            f |= pf::NOCLDWAIT;
        }
        f
    }
}
