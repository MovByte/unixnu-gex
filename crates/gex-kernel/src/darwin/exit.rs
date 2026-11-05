//! A Darwin parent's view of its children's ends (`bsd/kern/kern_exit.c`):
//! `wait4`'s and `waitid`'s choice of child, by pid or process group, and
//! the status in Darwin's encoding and siginfo.

use crate::errno::Errno;
use crate::syscalls::{BlockOp, Kernel, SyscallOutcome};
use crate::GuestMem;

/// The wait options (`bsd/sys/wait.h`).
const WNOHANG: i32 = 0x1;
const WEXITED: i32 = 0x4;
const WSTOPPED: i32 = 0x8;
const WCONTINUED: i32 = 0x10;
const WNOWAIT: i32 = 0x20;

/// `idtype_t`.
const P_PID: u64 = 1;
const P_PGID: u64 = 2;

/// `sizeof(user64_siginfo_t)`.
const SIGINFO_SIZE: usize = 104;
/// `CLD_EXITED`, `CLD_KILLED`, `CLD_DUMPED`.
const CLD_EXITED: u32 = 1;
const CLD_KILLED: u32 = 2;
const CLD_DUMPED: u32 = 3;

/// `WAIT_ANY`.
const WAIT_ANY: i32 = -1;

/// A status in the host's (Linux's) encoding as Darwin's: the same layout
/// (`W_EXITCODE`, `W_STOPCODE`, `WCOREFLAG`), with Darwin's signal
/// numbers; a continue is `W_STOPCODE(SIGCONT)`.
pub fn status_from_linux(w: u32) -> u32 {
    let to = |l: u32| super::signal::signal_from_linux(l).unwrap_or(l);
    if w == 0xffff {
        return 0x7f | (super::signal::dsig::SIGCONT << 8);
    }
    match w & 0x7f {
        0 => w & 0xff00,
        0x7f => 0x7f | (to((w >> 8) & 0xff) << 8),
        sig => to(sig) | (w & 0x80),
    }
}

/// `waitid`'s siginfo for child `pid` that ended with `word` (the host's
/// encoding): cleared, then SIGCHLD, the pid, CLD_EXITED and the exit
/// code, or CLD_KILLED (CLD_DUMPED with a core) and the signal. For no
/// child yet (`pid` 0) it is left as it was. The status carries the top
/// byte of the exit value where the child still has it.
pub fn waitid_report(m: &mut GuestMem<'_>, info: u64, pid: i32, word: u32, xhighbits: u8) -> Result<u64, Errno> {
    if pid <= 0 {
        return Ok(0);
    }
    let w = status_from_linux(word);
    let (code, status) = if w & 0x7f == 0 {
        (CLD_EXITED, ((w >> 8) & 0xff) | u32::from(xhighbits) << 24)
    } else if w & 0x80 != 0 {
        (CLD_DUMPED, (w & 0x7f) | u32::from(xhighbits) << 24)
    } else {
        (CLD_KILLED, (w & 0x7f) | u32::from(xhighbits) << 24)
    };
    let mut b = [0u8; SIGINFO_SIZE];
    b[0..4].copy_from_slice(&super::signal::dsig::SIGCHLD.to_le_bytes());
    b[8..12].copy_from_slice(&code.to_le_bytes());
    b[12..16].copy_from_slice(&(pid as u32).to_le_bytes());
    b[20..24].copy_from_slice(&status.to_le_bytes());
    m.write(info, &b)?;
    Ok(0)
}

impl Kernel {
    /// `waitid(idtype, id, infop, options)` and `waitid_nocancel`. Only an
    /// end can be waited for here: no child stops or continues yet.
    pub(crate) fn darwin_waitid(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> SyscallOutcome {
        let fail = |k: &mut Kernel, m: &mut GuestMem<'_>, e: Errno| {
            let _ = super::set_result(m, k.ctx_addr, e.as_return());
            SyscallOutcome::Continue
        };
        let (idtype, id, info, options) = (a[0] as u32 as u64, a[1] as u32 as i32, a[2], a[3] as i32);
        if options == 0 || options & !(WNOHANG | WNOWAIT | WCONTINUED | WSTOPPED | WEXITED) != 0 {
            return fail(self, m, Errno::EINVAL);
        }
        if (idtype == P_PID || idtype == P_PGID) && id < 0 {
            return fail(self, m, Errno::EINVAL);
        }
        // Any other idtype matches every child, as in kern_exit.c.
        let children: Vec<_> = self
            .procs
            .children(self.pid)
            .into_iter()
            .filter(|c| match idtype {
                P_PID => c.pid == id,
                P_PGID => self.procs.pgid(self.pid, c.pid) == Ok(id),
                _ => true,
            })
            .collect();
        if children.is_empty() {
            return fail(self, m, Errno::ECHILD);
        }
        if options & WEXITED == 0 {
            if options & WNOHANG != 0 {
                let _ = super::set_result(m, self.ctx_addr, 0);
                return SyscallOutcome::Continue;
            }
            self.darwin_unimplemented("waitid for a stop or a continue only (stopped and continued children)".into());
            return fail(self, m, Errno::EINVAL);
        }
        SyscallOutcome::Blocking(BlockOp::WaitChild {
            children,
            procs: std::sync::Arc::clone(&self.procs),
            ppid: self.pid,
            want: 0,
            wstatus: 0,
            nohang: options & WNOHANG != 0,
            waitid: Some(crate::syscalls::WaitidOut { info, nowait: options & WNOWAIT != 0, compat: false, darwin: true }),
        })
    }

    /// `wait4(pid, status, options, rusage)` and `wait4_nocancel`: the
    /// caller's children that `pid` names (one, any, or a process group's,
    /// zero for its own group), waited for unless `WNOHANG`.
    pub(crate) fn darwin_wait4(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> SyscallOutcome {
        let fail = |k: &mut Kernel, m: &mut GuestMem<'_>, e: Errno| {
            let _ = super::set_result(m, k.ctx_addr, e.as_return());
            SyscallOutcome::Continue
        };
        let (mut pid, status, options, rusage) = (a[0] as i32, a[1], a[2] as i32, a[3]);
        if pid == 0 {
            match self.procs.pgid(self.pid, 0) {
                Ok(g) => pid = -g,
                Err(e) => return fail(self, m, e),
            }
        }
        if pid == i32::MIN {
            return fail(self, m, Errno::EINVAL);
        }
        if rusage != 0 {
            self.darwin_unimplemented("wait4's rusage (the child's resource usage at its end)".into());
            return fail(self, m, Errno::EINVAL);
        }
        let children: Vec<_> = self
            .procs
            .children(self.pid)
            .into_iter()
            .filter(|c| pid == WAIT_ANY || c.pid == pid || (pid < -1 && self.procs.pgid(self.pid, c.pid) == Ok(-pid)))
            .collect();
        if children.is_empty() {
            return fail(self, m, Errno::ECHILD);
        }
        self.darwin_wait4 = Some(status);
        SyscallOutcome::Blocking(BlockOp::WaitChild {
            children,
            procs: std::sync::Arc::clone(&self.procs),
            ppid: self.pid,
            want: 0,
            wstatus: status,
            nohang: options & WNOHANG != 0,
            waitid: None,
        })
    }

    /// A `wait4` that collected a child: its status in Darwin's encoding,
    /// and, the last child reaped, a pending SIGCHLD the thread masks
    /// dropped.
    pub(crate) fn darwin_wait4_done(&mut self, m: &mut GuestMem<'_>, status: u64, r: &Result<u64, Errno>) {
        let Ok(pid) = r else { return };
        if *pid == 0 {
            return;
        }
        if status != 0 {
            if let Ok(w) = m.read_u32(status) {
                let _ = m.write_u32(status, status_from_linux(w) & 0xffff);
            }
        }
        if self.procs.children(self.pid).is_empty() {
            let l = super::kern::signal_to_linux(super::signal::dsig::SIGCHLD);
            if self.signals.blocked() & (1 << (l - 1)) != 0 {
                self.collect_signals();
                self.signals.discard_everywhere(l, &self.thread_signals);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_take_darwin_signal_numbers() {
        // exit(3); SIGUSR1 (Linux 10, Darwin 30) with a core; stopped by
        // SIGTSTP (Linux 20, Darwin 18); continued.
        assert_eq!(status_from_linux(3 << 8), 3 << 8);
        assert_eq!(status_from_linux(10 | 0x80), 30 | 0x80);
        assert_eq!(status_from_linux(0x7f | (20 << 8)), 0x7f | (18 << 8));
        assert_eq!(status_from_linux(0xffff), 0x7f | (19 << 8));
    }
}
