//! `process_policy` (`bsd/kern/process_policy.c`): a process's policies for
//! background work, resource use, its app's lifecycle and importance, set
//! or read for itself or, with the credentials and the Sandbox's leave,
//! another process. (ENOTSUP is Darwin's number for EOPNOTSUPP.)

use super::mac::op;
use crate::errno::Errno;
use crate::syscalls::Kernel;
use crate::GuestMem;

/// `PROC_POLICY_SCOPE_*`.
pub mod scope {
    pub const PROCESS: i32 = 1;
    pub const THREAD: i32 = 2;
}

/// `PROC_POLICY_ACTION_*`.
pub mod action {
    pub const APPLY: i32 = 1;
    pub const RESTORE: i32 = 2;
    pub const ENABLE: i32 = 5;
    pub const SET: i32 = 10;
    pub const HOLD: i32 = 14;
    pub const DROP: i32 = 15;
}

/// The policies (`PROC_POLICY_*`).
pub mod policy {
    pub const BACKGROUND: i32 = 1;
    pub const HARDWARE_ACCESS: i32 = 2;
    pub const RESOURCE_STARVATION: i32 = 3;
    pub const RESOURCE_USAGE: i32 = 4;
    pub const APP_LIFECYCLE: i32 = 5;
    pub const APPTYPE: i32 = 6;
    pub const BOOST: i32 = 7;
    pub const NO_SMT: i32 = 8;
    pub const TECS: i32 = 9;
}

/// `PROC_POLICY_RS_*`, `PROC_POLICY_RUSAGE_*`, `PROC_POLICY_APPLIFE_*`,
/// `PROC_POLICY_IOS_*` and `PROC_POLICY_IMP_*`.
pub mod sub {
    pub const RS_NONE: i32 = 0;
    pub const RS_VIRTUALMEM: i32 = 1;
    pub const RUSAGE_NONE: i32 = 0;
    pub const RUSAGE_WIREDMEM: i32 = 1;
    pub const RUSAGE_VIRTMEM: i32 = 2;
    pub const RUSAGE_CPU: i32 = 3;
    pub const RUSAGE_DISK: i32 = 4;
    pub const RUSAGE_NETWORK: i32 = 5;
    pub const RUSAGE_POWER: i32 = 6;
    pub const APPLIFE_NONE: i32 = 0;
    pub const APPLIFE_STATE: i32 = 1;
    pub const APPLIFE_DEVSTATUS: i32 = 2;
    pub const APPLIFE_PIDBIND: i32 = 3;
    pub const IOS_DONATEIMP: i32 = 6;
    pub const IOS_HOLDIMP: i32 = 7;
    pub const IOS_DROPIMP: i32 = 8;
    pub const IMP_IMPORTANT: i32 = 1;
    pub const IMP_DONATION: i32 = 3;
}

impl Kernel {
    /// `process_policy(scope, action, policy, policy_subtype, attrp,
    /// target_pid, target_threadid)`: the target (0 or the caller's pid is
    /// the caller) found (ESRCH), the caller allowed it (iOS: root, a
    /// caller whose real uid is root, or one whose effective or real uid is
    /// the target's effective uid; else EPERM), the Sandbox's system-sched
    /// asked but for the policies that ask their own, then the policy.
    pub(crate) fn darwin_process_policy(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        let (sc, act, pol, subtype, attrp) = (a[0] as i32, a[1] as i32, a[2] as i32, a[3] as i32, a[4]);
        // The seventh argument, target_threadid, is in x6.
        let target_tid = m.read_u64(self.ctx_addr + gex_abi::ctx::x(6) as u64).unwrap_or(0);
        if sc != scope::PROCESS && sc != scope::THREAD {
            return Err(Errno::EINVAL);
        }
        let target_pid = a[5] as i32;
        let target = if target_pid == 0 || target_pid == self.pid { self.pid } else { target_pid };
        let target_uid = if target == self.pid {
            self.dtask.cred.uid
        } else {
            match self.darwin_public(target) {
                Some((p, false)) => p.cred.uid,
                _ => return Err(Errno::ESRCH),
            }
        };
        let me = &self.dtask.cred;
        if me.uid != 0 && me.ruid != 0 && me.uid != target_uid && me.ruid != target_uid {
            return Err(Errno::EPERM);
        }
        // These ask the MAC policies themselves where they must.
        if !matches!(pol, policy::BOOST | policy::RESOURCE_USAGE | policy::APPTYPE | policy::APP_LIFECYCLE) {
            let e = self.darwin_mac_check_sched(target);
            if e != 0 {
                return Err(super::errno::errno_of(e as i32));
            }
        }
        match pol {
            policy::BACKGROUND | policy::HARDWARE_ACCESS => Err(Errno::EOPNOTSUPP),
            policy::RESOURCE_STARVATION => self.darwin_policy_lowresource(act, subtype, target),
            policy::RESOURCE_USAGE => match subtype {
                sub::RUSAGE_NONE | sub::RUSAGE_WIREDMEM | sub::RUSAGE_VIRTMEM | sub::RUSAGE_DISK | sub::RUSAGE_NETWORK | sub::RUSAGE_POWER => Err(Errno::EOPNOTSUPP),
                sub::RUSAGE_CPU => {
                    self.darwin_unimplemented(format!("process_policy's CPU usage monitor (handle_cpuuse, action {act}, pid {target})"));
                    Err(Errno::EINVAL)
                }
                _ => Err(Errno::EINVAL),
            },
            policy::APP_LIFECYCLE => self.darwin_policy_applifecycle(m, act, subtype, attrp, target, target_tid),
            policy::APPTYPE => self.darwin_policy_apptype(sc, act, subtype, target),
            policy::BOOST => self.darwin_policy_boost(sc, act, subtype, target),
            // There is no SMT on the A10, and no CPU vulnerability arm64
            // answers for (machine_csv): each sets nothing.
            policy::NO_SMT | policy::TECS => {
                if act != action::APPLY {
                    return Err(Errno::EINVAL);
                }
                match sc {
                    scope::PROCESS if target != self.pid => Err(Errno::EINVAL),
                    scope::THREAD if target_tid != self.signals.thread().darwin_id() => Err(Errno::EINVAL),
                    _ => Ok(0),
                }
            }
            _ => Err(Errno::EINVAL),
        }
    }

    /// `handle_lowresource`: RESTORE is `proc_resetpcontrol` (a resource
    /// owner's or root's), else EINVAL. The action it would undo is the
    /// paging space shortage's (`no_paging_space_action`), which a jetsam
    /// kernel never takes: there is none to undo.
    fn darwin_policy_lowresource(&mut self, act: i32, subtype: i32, target: i32) -> Result<u64, Errno> {
        if subtype != sub::RS_NONE && subtype != sub::RS_VIRTUALMEM {
            return Err(Errno::EINVAL);
        }
        if act != action::RESTORE {
            return Err(Errno::EINVAL);
        }
        if !self.dtask.vmrsrcowner && self.dtask.cred.uid != 0 {
            return Err(Errno::EPERM);
        }
        if target != self.pid && self.darwin_public(target).is_none_or(|(_, zombie)| zombie) {
            return Err(Errno::ESRCH);
        }
        Ok(0)
    }

    /// `handle_applifecycle`: NONE does nothing; STATE is no longer
    /// supported; DEVSTATUS (with the Sandbox's system-suspend-resume)
    /// wakes the freezer; PIDBIND (likewise) binds a thread to another
    /// process's app state (taskwatch).
    fn darwin_policy_applifecycle(&mut self, m: &mut GuestMem<'_>, act: i32, subtype: i32, attrp: u64, target: i32, target_tid: u64) -> Result<u64, Errno> {
        match subtype {
            sub::APPLIFE_NONE => Ok(0),
            sub::APPLIFE_STATE => Err(Errno::EOPNOTSUPP),
            sub::APPLIFE_DEVSTATUS => {
                if self.darwin_mac_check_suspend_resume() != 0 {
                    return Err(Errno::EPERM);
                }
                if act != action::APPLY {
                    return Err(Errno::EINVAL);
                }
                // memorystatus_on_inactivity: this kernel has the freezer
                // (CONFIG_FREEZE), whose thread the hint wakes.
                self.darwin_unimplemented(format!("process_policy DEVSTATUS for pid {target}: the freezer thread's wakeup (memorystatus_on_inactivity); the freezer is not modelled"));
                Err(Errno::EINVAL)
            }
            sub::APPLIFE_PIDBIND => {
                if self.darwin_mac_check_suspend_resume() != 0 {
                    return Err(Errno::EPERM);
                }
                let _state = m.read_u32(attrp)?;
                if act != action::APPLY {
                    return Err(Errno::EINVAL);
                }
                self.darwin_unimplemented(format!("process_policy PIDBIND of thread {target_tid} to pid {target}'s app state (proc_lf_pidbind, the task watchers)"));
                Err(Errno::EINVAL)
            }
            _ => Err(Errno::EINVAL),
        }
    }

    /// `handle_apptype`, its old importance calls for the caller itself:
    /// DONATEIMP marks it a donor (`task_importance_mark_donor`); HOLDIMP
    /// and DROPIMP take and give back a legacy external assertion.
    fn darwin_policy_apptype(&mut self, sc: i32, act: i32, subtype: i32, target: i32) -> Result<u64, Errno> {
        if sc != scope::PROCESS {
            return Err(Errno::EINVAL);
        }
        match subtype {
            sub::IOS_DONATEIMP | sub::IOS_HOLDIMP | sub::IOS_DROPIMP => {
                if act != action::ENABLE || target != self.pid {
                    return Err(Errno::EINVAL);
                }
                if subtype == sub::IOS_DONATEIMP {
                    self.darwin_policy_with(|p| p.imp.donor = true);
                    return Ok(0);
                }
                self.darwin_legacy_external_assertion(subtype == sub::IOS_HOLDIMP)
            }
            _ => Err(Errno::EINVAL),
        }
    }

    /// `handle_boost`, for the caller itself: IMPORTANT holds or drops a
    /// legacy external assertion (a task that receives importance only,
    /// else EINVAL); DONATION, with the Sandbox's system-sched, marks it a
    /// donor.
    fn darwin_policy_boost(&mut self, sc: i32, act: i32, subtype: i32, target: i32) -> Result<u64, Errno> {
        if sc != scope::PROCESS || target != self.pid {
            return Err(Errno::EINVAL);
        }
        match subtype {
            sub::IMP_IMPORTANT => {
                // task_is_importance_receiver_type.
                let imp = self.darwin_policy().imp;
                if !imp.receiver && !imp.denap_receiver {
                    return Err(Errno::EINVAL);
                }
                match act {
                    action::HOLD | action::DROP => self.darwin_legacy_external_assertion(act == action::HOLD),
                    _ => Err(Errno::EINVAL),
                }
            }
            sub::IMP_DONATION => {
                let e = self.darwin_mac_check_sched(target);
                if e != 0 {
                    return Err(super::errno::errno_of(e as i32));
                }
                if act != action::SET {
                    return Err(Errno::EINVAL);
                }
                self.darwin_policy_with(|p| p.imp.donor = true);
                Ok(0)
            }
            _ => Err(Errno::EINVAL),
        }
    }

    /// `task_importance_hold_legacy_external_assertion` (`hold`) or
    /// `..._drop_...` of one assertion on the caller's task.
    fn darwin_legacy_external_assertion(&mut self, hold: bool) -> Result<u64, Errno> {
        let what = if hold { "hold" } else { "drop" };
        self.darwin_unimplemented(format!("process_policy's {what} of a legacy external importance assertion (ipc_importance_task_{what}_legacy_external_assertion): importance assertions are not modelled"));
        Err(Errno::EINVAL)
    }
}

/// The Sandbox operations `process_policy` asks.
impl Kernel {
    /// `mac_proc_check_sched` of process `pid` (Sandbox's system-sched, the
    /// target its argument; AMFI has no hook).
    pub(crate) fn darwin_mac_check_sched(&mut self, pid: i32) -> u32 {
        let a = super::mac::SbArgs { kind: super::sandbox::kind::PROCESS, target: Some(pid), ..Default::default() };
        self.darwin_sb_evaluate(op::SYSTEM_SCHED, &a)
    }

    /// `mac_proc_check_suspend_resume` (Sandbox's system-suspend-resume,
    /// with no argument: the target and the request are not asked about;
    /// AMFI has no hook).
    pub(crate) fn darwin_mac_check_suspend_resume(&mut self) -> u32 {
        self.darwin_sb_evaluate(op::SYSTEM_SUSPEND_RESUME, &super::mac::SbArgs::default())
    }
}
