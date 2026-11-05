//! `getpriority` and `setpriority` (`bsd/kern/kern_resource.c`): the nice
//! value of a process, a group or a user's processes, which is its task's
//! importance (`resetpriority`), and the `PRIO_DARWIN_*` controls of a
//! thread's or a process's background, its GPU access, its role and its
//! game mode.
//!
//! A process here has one uid, its real and effective alike, so XNU's
//! checks against the caller's real uid and its uid are one check.

use crate::errno::Errno;
use crate::syscalls::Kernel;

/// `PRIO_*`.
mod which {
    pub const PROCESS: u32 = 0;
    pub const PGRP: u32 = 1;
    pub const USER: u32 = 2;
    pub const DARWIN_THREAD: u32 = 3;
    pub const DARWIN_PROCESS: u32 = 4;
    pub const DARWIN_GPU: u32 = 5;
    pub const DARWIN_ROLE: u32 = 6;
    pub const DARWIN_GAME_MODE: u32 = 7;
}

const PRIO_MIN: i32 = -20;
const PRIO_MAX: i32 = 20;
const PRIO_DARWIN_BG: i32 = 0x1000;
const PRIO_DARWIN_NONUI: i32 = 0x1001;
const PRIO_DARWIN_GPU_ALLOW: i32 = 0x1;
const PRIO_DARWIN_GPU_DENY: i32 = 0x2;

impl Kernel {
    /// The target `who` names: this process for 0, else a live process
    /// (`proc_find`), with its uid.
    fn prio_target(&self, who: u32) -> Option<(i32, u32)> {
        if who == 0 {
            return Some((self.pid, self.creds.uid()));
        }
        self.procs.live_nice(who as i32).map(|(uid, _)| (who as i32, uid))
    }

    /// The checks kern_resource.c makes of the caller against a target's
    /// uid: a superuser, or one whose uid is the target's.
    fn prio_may(&self, target_uid: u32) -> bool {
        let u = self.creds.uid();
        u == 0 || u == target_uid
    }

    /// `getpriority(which, who)`.
    pub(crate) fn darwin_getpriority(&mut self, which: u32, who: u32) -> Result<u64, Errno> {
        if who > 0x7fff_ffff {
            return Err(Errno::EINVAL);
        }
        let mut low = PRIO_MAX + 1;
        match which {
            which::PROCESS => {
                let pid = if who == 0 { self.pid } else { who as i32 };
                if let Some((_, n)) = self.procs.live_nice(pid) {
                    low = n;
                }
            }
            which::PGRP => {
                let pgid = if who == 0 { self.procs.pgid(self.pid, 0)? } else { who as i32 };
                for (_, _, n, _) in self.procs.pgrp_members(pgid) {
                    low = low.min(n);
                }
            }
            which::USER => {
                let uid = if who == 0 { self.creds.uid() } else { who };
                for (_, u, n) in self.procs.all_live() {
                    if u == uid {
                        low = low.min(n);
                    }
                }
            }
            which::DARWIN_THREAD => {
                if who != 0 {
                    return Err(Errno::EINVAL);
                }
                low = i32::from(self.darwin_me().policy.int_darwinbg);
            }
            // get_background_proc reads the caller's own task's background,
            // internal or external by whether the target is the caller.
            which::DARWIN_PROCESS => {
                if let Some((pid, uid)) = self.prio_target(who) {
                    if !self.prio_may(uid) {
                        return Err(Errno::EPERM);
                    }
                    let r = self.darwin_policy().requested;
                    low = i32::from(if pid == self.pid { r.int_darwinbg } else { r.ext_darwinbg });
                }
            }
            which::DARWIN_ROLE => {
                if let Some((pid, uid)) = self.prio_target(who) {
                    if !self.prio_may(uid) {
                        return Err(Errno::EPERM);
                    }
                    let r = self.procs.task_policy(pid).map_or(0, |p| p.lock().unwrap_or_else(|e| e.into_inner()).requested.role);
                    low = super::taskpolicy::task_role_to_darwin_role(r);
                }
            }
            which::DARWIN_GAME_MODE => {
                if let Some((pid, uid)) = self.prio_target(who) {
                    let root = self.creds.uid() == 0;
                    if !root && !self.prio_game_mode_entitled() {
                        return Err(Errno::EPERM);
                    }
                    if !root && self.creds.uid() != uid {
                        return Err(Errno::EPERM);
                    }
                    low = i32::from(self.procs.task_policy(pid).is_some_and(|p| p.lock().unwrap_or_else(|e| e.into_inner()).game_mode));
                }
            }
            _ => return Err(Errno::EINVAL),
        }
        if low == PRIO_MAX + 1 {
            return Err(Errno::ESRCH);
        }
        Ok(low as i64 as u64)
    }

    /// `setpriority(which, who, prio)`: -2 when a thread's QoS policy was
    /// stripped for its background (EIDRM).
    pub(crate) fn darwin_setpriority(&mut self, which: u32, who: u32, prio: i32) -> Result<u64, Errno> {
        if who > 0x7fff_ffff {
            return Err(Errno::EINVAL);
        }
        let mut found = 0;
        let mut error: Result<bool, Errno> = Ok(false);
        match which {
            which::PROCESS => {
                if let Some((pid, uid)) = self.prio_target(who) {
                    error = self.donice(pid, uid, prio).map(|()| false);
                    found += 1;
                }
            }
            // pgrp_iterate and proc_iterate visit live processes.
            which::PGRP | which::USER => {
                let targets: Vec<(i32, u32)> = if which == which::PGRP {
                    let pgid = if who == 0 { self.procs.pgid(self.pid, 0)? } else { who as i32 };
                    self.procs.pgrp_members(pgid).into_iter().filter(|m| m.3).map(|m| (m.0, m.1)).collect()
                } else {
                    let uid = if who == 0 { self.creds.uid() } else { who };
                    self.procs.all_live().into_iter().filter(|p| p.1 == uid).map(|p| (p.0, p.1)).collect()
                };
                for (pid, uid) in targets {
                    error = self.donice(pid, uid, prio).map(|()| false);
                    found += 1;
                }
            }
            which::DARWIN_THREAD => {
                if who != 0 {
                    return Err(Errno::EINVAL);
                }
                error = self.do_background_thread(prio);
                found += 1;
            }
            which::DARWIN_PROCESS => {
                if let Some((pid, uid)) = self.prio_target(who) {
                    error = self.do_background_proc(pid, uid, prio).map(|()| false);
                    found += 1;
                }
            }
            which::DARWIN_GPU => {
                if who == 0 {
                    return Err(Errno::EINVAL);
                }
                if let Some((pid, uid)) = self.prio_target(who) {
                    error = self.set_gpudeny_proc(pid, uid, prio).map(|()| false);
                    found += 1;
                }
            }
            which::DARWIN_ROLE => {
                if let Some((pid, uid)) = self.prio_target(who) {
                    error = self.proc_set_darwin_role(pid, uid, prio).map(|()| false);
                    found += 1;
                }
            }
            which::DARWIN_GAME_MODE => {
                if let Some((pid, uid)) = self.prio_target(who) {
                    error = self.proc_set_game_mode(pid, uid, prio).map(|()| false);
                    found += 1;
                }
            }
            _ => return Err(Errno::EINVAL),
        }
        if found == 0 {
            return Err(Errno::ESRCH);
        }
        match error {
            Ok(true) => Ok(-2i64 as u64),
            Ok(false) => Ok(0),
            Err(e) => Err(e),
        }
    }

    /// `donice`: the nice value clamped to PRIO_MIN..PRIO_MAX, lowered only
    /// by the superuser (EACCES), then `resetpriority`: the task's
    /// importance its negation.
    fn donice(&mut self, pid: i32, uid: u32, n: i32) -> Result<(), Errno> {
        if !self.prio_may(uid) {
            return Err(Errno::EPERM);
        }
        let n = n.clamp(PRIO_MIN, PRIO_MAX);
        let cur = self.procs.live_nice(pid).map_or(0, |(_, c)| c);
        if n < cur && self.creds.uid() != 0 {
            return Err(Errno::EACCES);
        }
        self.procs.set_nice(pid, n);
        if let Some(p) = self.procs.task_policy(pid) {
            // task_importance's refusal for a control application is not
            // the caller's error.
            let _ = p.lock().unwrap_or_else(|e| e.into_inner()).set_importance(-n);
        }
        Ok(())
    }

    /// `do_background_thread` for the calling thread: not a workqueue
    /// thread's (EPERM); a QoS policy is stripped first (`Ok(true)`, EIDRM).
    fn do_background_thread(&mut self, prio: i32) -> Result<bool, Errno> {
        let me = self.darwin_me();
        if me.wq.is_some() {
            return Err(Errno::EPERM);
        }
        let mut stripped = false;
        if me.policy.qos != super::workq::qos::UNSPECIFIED {
            me.policy.qos = super::workq::qos::UNSPECIFIED;
            me.policy.relpri = 0;
            stripped = true;
        }
        me.policy.int_darwinbg = prio == PRIO_DARWIN_BG;
        Ok(stripped)
    }

    /// `do_background_proc`: the target's background, internal for the
    /// caller itself, external for another; PRIO_DARWIN_NONUI is ignored.
    fn do_background_proc(&mut self, pid: i32, uid: u32, prio: i32) -> Result<(), Errno> {
        if !self.prio_may(uid) {
            return Err(Errno::EPERM);
        }
        let on = match prio {
            PRIO_DARWIN_BG => true,
            PRIO_DARWIN_NONUI => return Ok(()),
            _ => false,
        };
        if let Some(p) = self.procs.task_policy(pid) {
            p.lock().unwrap_or_else(|e| e.into_inner()).set_darwinbg(pid != self.pid, on);
        }
        Ok(())
    }

    /// `set_gpudeny_proc`: another process's GPU access.
    fn set_gpudeny_proc(&mut self, pid: i32, uid: u32, prio: i32) -> Result<(), Errno> {
        if !self.prio_may(uid) || pid == self.pid {
            return Err(Errno::EPERM);
        }
        let deny = match prio {
            PRIO_DARWIN_GPU_DENY => true,
            PRIO_DARWIN_GPU_ALLOW => false,
            _ => return Err(Errno::EINVAL),
        };
        if let Some(p) = self.procs.task_policy(pid) {
            p.lock().unwrap_or_else(|e| e.into_inner()).gpu_denied = deny;
        }
        Ok(())
    }

    /// `proc_set_darwin_role`: an application's role (ENOTSUP for any other
    /// process, EINVAL for no such role).
    fn proc_set_darwin_role(&mut self, pid: i32, uid: u32, prio: i32) -> Result<(), Errno> {
        if !self.prio_may(uid) {
            // priv_check_cred(PRIV_SETPRIORITY_DARWIN_ROLE): a grant a MAC
            // policy makes.
            self.darwin_unimplemented("setpriority(PRIO_DARWIN_ROLE) of another user's process (a MAC policy's privilege grant)".into());
            return Err(Errno::EPERM);
        }
        let Some(p) = self.procs.task_policy(pid) else { return Ok(()) };
        let mut p = p.lock().unwrap_or_else(|e| e.into_inner());
        if !p.is_app() {
            return Err(Errno::EOPNOTSUPP);
        }
        let role = super::taskpolicy::darwin_role_to_task_role(prio as u32).ok_or(Errno::EINVAL)?;
        p.set_role(role);
        Ok(())
    }

    /// The entitlement game mode takes.
    fn prio_game_mode_entitled(&self) -> bool {
        self.dtask.codesign.as_ref().is_some_and(|c| c.entitled("com.apple.private.set-game-mode"))
    }

    /// `proc_set_game_mode`.
    fn proc_set_game_mode(&mut self, pid: i32, uid: u32, prio: i32) -> Result<(), Errno> {
        if !self.prio_game_mode_entitled() {
            return Err(Errno::EPERM);
        }
        if self.creds.uid() != 0 && self.creds.uid() != uid {
            return Err(Errno::EPERM);
        }
        let on = match prio {
            0 => false,
            1 => true,
            _ => return Err(Errno::EINVAL),
        };
        if let Some(p) = self.procs.task_policy(pid) {
            p.lock().unwrap_or_else(|e| e.into_inner()).game_mode = on;
        }
        Ok(())
    }
}
