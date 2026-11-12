//! Signals as XNU takes them: dispositions (`sigaction`, `setsigvec`,
//! `bsd/kern/kern_sig.c`), the alternate stack, and the arm64 handler
//! frame and its return (`sendsig`, `sigreturn`, `bsd/dev/arm/unix_signal.c`).
//!
//! The signal layer keeps what is pending and blocked in Linux's numbering
//! for every personality; this keeps XNU's `sigacts` beside it, in Darwin's,
//! and mirrors each disposition into the layer's so that its wakeups and
//! restarts follow the same rules. Delivery is XNU's: `postsig_locked`'s
//! bookkeeping, then a `user_sigframe64` on the stack and the thread sent to
//! the action's trampoline.

use super::kern::{mask_from_linux, mask_to_linux, signal_to_linux};
use crate::errno::Errno;
use super::reason::OsReason;
use crate::signal::{self, sa, DefaultAction, Delivery, Note, SigAction, Source, SIG_DFL, SIG_IGN};
use std::sync::Arc;
use crate::syscalls::{Kernel, SyscallOutcome};
use crate::GuestMem;
use gex_abi::ctx;

/// `NSIG`.
pub const NSIG: usize = 32;

/// Darwin's signal numbers (`bsd/sys/signal.h`) that this code names.
pub mod dsig {
    pub const SIGHUP: u32 = 1;
    pub const SIGILL: u32 = 4;
    pub const SIGABRT: u32 = 6;
    pub const SIGEMT: u32 = 7;
    pub const SIGSYS: u32 = 12;
    pub const SIGPIPE: u32 = 13;
    pub const SIGTRAP: u32 = 5;
    pub const SIGFPE: u32 = 8;
    pub const SIGKILL: u32 = 9;
    pub const SIGBUS: u32 = 10;
    pub const SIGSEGV: u32 = 11;
    pub const SIGSTOP: u32 = 17;
    pub const SIGTSTP: u32 = 18;
    pub const SIGCONT: u32 = 19;
    pub const SIGTTIN: u32 = 21;
    pub const SIGTTOU: u32 = 22;
    pub const SIGCHLD: u32 = 20;
    pub const SIGALRM: u32 = 14;
    pub const SIGXCPU: u32 = 24;
    pub const SIGVTALRM: u32 = 26;
    pub const SIGPROF: u32 = 27;
}

/// `sigaction` flags (`bsd/sys/signal.h`).
mod saf {
    pub const ONSTACK: u32 = 0x0001;
    pub const RESTART: u32 = 0x0002;
    pub const RESETHAND: u32 = 0x0004;
    pub const NOCLDSTOP: u32 = 0x0008;
    pub const NODEFER: u32 = 0x0010;
    pub const NOCLDWAIT: u32 = 0x0020;
    pub const SIGINFO: u32 = 0x0040;
    pub const VALIDATE_SIGRETURN_FROM_SIGTRAMP: u32 = 0x0400;
    pub const USERSPACE_MASK: u32 = ONSTACK | RESTART | RESETHAND | NOCLDSTOP | NODEFER | NOCLDWAIT | SIGINFO;
    /// `SA_DISABLE` (`SS_DISABLE`): an alternate stack's flag.
    pub const DISABLE: u32 = 0x0004;
}

/// `sigprop` bits (`bsd/sys/signalvar.h`).
pub(super) mod prop {
    pub const KILL: u8 = 0x01;
    pub const CORE: u8 = 0x02;
    pub const STOP: u8 = 0x04;
    pub const TTYSTOP: u8 = 0x08;
    pub const IGNORE: u8 = 0x10;
    pub const CONT: u8 = 0x20;
}

/// `sigprop[NSIG]`: what each signal does by default.
pub(super) const SIGPROP: [u8; NSIG] = {
    use prop::*;
    [
        0,
        KILL,               // SIGHUP
        KILL,               // SIGINT
        KILL | CORE,        // SIGQUIT
        KILL | CORE,        // SIGILL
        KILL | CORE,        // SIGTRAP
        KILL | CORE,        // SIGABRT
        KILL | CORE,        // SIGEMT
        KILL | CORE,        // SIGFPE
        KILL,               // SIGKILL
        KILL | CORE,        // SIGBUS
        KILL | CORE,        // SIGSEGV
        KILL | CORE,        // SIGSYS
        KILL,               // SIGPIPE
        KILL,               // SIGALRM
        KILL,               // SIGTERM
        IGNORE,             // SIGURG
        STOP,               // SIGSTOP
        STOP | TTYSTOP,     // SIGTSTP
        IGNORE | CONT,      // SIGCONT
        IGNORE,             // SIGCHLD
        STOP | TTYSTOP,     // SIGTTIN
        STOP | TTYSTOP,     // SIGTTOU
        IGNORE,             // SIGIO
        KILL,               // SIGXCPU
        KILL,               // SIGXFSZ
        KILL,               // SIGVTALRM
        KILL,               // SIGPROF
        IGNORE,             // SIGWINCH
        IGNORE,             // SIGINFO
        KILL,               // SIGUSR1
        KILL,               // SIGUSR2
    ]
};

/// `sigmask(sig)`.
/// `sigcantmask`: what no mask holds.
const SIGCANTMASK: u32 = sigmask(dsig::SIGKILL) | sigmask(dsig::SIGSTOP);

pub(super) const fn sigmask(d: u32) -> u32 {
    1 << (d - 1)
}

/// `sigcantmask`.
const CANTMASK: u32 = sigmask(dsig::SIGKILL) | sigmask(dsig::SIGSTOP);

/// `ps_sigreturn_validation`'s states.
mod validation {
    pub const DEFAULT: u32 = 0;
    pub const ENABLED: u32 = 1;
    pub const DISABLED: u32 = 2;
}

/// The handler's `infostyle` and `sigreturn`'s alternate-stack requests.
const UC_TRAD: u64 = 1;
const UC_FLAVOR: u64 = 30;
const UC_SET_ALT_STACK: u64 = 0x4000_0000;
const UC_RESET_ALT_STACK: u64 = 0x8000_0000;

/// `user_sigframe64`: a `user64_siginfo_t`, a `user_ucontext64`, and the
/// `mcontext64` (exception, thread and NEON state) it points to.
mod frame {
    pub const SINFO: u64 = 0;
    pub const SINFO_SIZE: u64 = 104;
    pub const UCTX: u64 = SINFO_SIZE;
    pub const UCTX_SIZE: u64 = 56;
    pub const MCTX: u64 = UCTX + UCTX_SIZE;
    /// `UC_FLAVOR_SIZE64`: `(ARM_THREAD_STATE64_COUNT +
    /// ARM_EXCEPTION_STATE64_COUNT + ARM_NEON_STATE64_COUNT) * 4`.
    pub const MCTX_SIZE: u64 = (68 + 4 + 132) * 4;
    pub const SIZE: u64 = MCTX + MCTX_SIZE;
    /// `C_64_REDZONE_LEN`.
    pub const REDZONE: u64 = 128;

    // In the mcontext: `__es`, `__ss`, `__ns`.
    pub const ES_FAR: u64 = 0;
    pub const ES_ESR: u64 = 8;
    pub const ES_EXCEPTION: u64 = 12;
    pub const SS: u64 = 16;
    pub const SS_FP: u64 = SS + 29 * 8;
    pub const SS_LR: u64 = SS_FP + 8;
    pub const SS_SP: u64 = SS_LR + 8;
    pub const SS_PC: u64 = SS_SP + 8;
    pub const SS_CPSR: u64 = SS_PC + 8;
    pub const SS_FLAGS: u64 = SS_CPSR + 4;
    pub const NS: u64 = 288;
    pub const NS_FPSR: u64 = NS + 32 * 16;
    pub const NS_FPCR: u64 = NS_FPSR + 4;
}

/// `si_code`s `sendsig` gives the faults.
const ILL_ILLTRP: u32 = 2;
const FPE_NOOP: u32 = 0;
const BUS_ADRALN: u32 = 1;
const SEGV_ACCERR: u32 = 2;

/// `PSR64_USER64_DEFAULT` on the A10X (no SSBS): EL0t, AArch64.
const PSR64_USER64_DEFAULT: u64 = 0;

/// The ESR of `svc #imm` from AArch64 EL0: EC 0x15, IL set, ISS the
/// immediate.
const fn esr_svc(imm: u32) -> u32 {
    (0x15 << 26) | (1 << 25) | (imm & 0xffff)
}

/// A Linux signal's Darwin number, if it has one.
pub fn signal_from_linux(l: u32) -> Option<u32> {
    let d = match l {
        7 => 10,
        31 => 12,
        23 => 16,
        19 => 17,
        20 => 18,
        18 => 19,
        17 => 20,
        29 => 23,
        10 => 30,
        12 => 31,
        1..=6 | 8 | 9 | 11 | 13..=15 | 21 | 22 | 24..=28 => l,
        _ => return None,
    };
    Some(d)
}

/// What a signal (by its Linux number) does by default in a Darwin
/// process: its `sigprop`, for the signal layer's wakeups. A stop is a stop
/// (there is no core file: `CONFIG_COREDUMP` is a development option on iOS).
pub fn default_action(l: u32) -> DefaultAction {
    let Some(d) = signal_from_linux(l) else { return signal::default_action(l) };
    let p = SIGPROP[d as usize];
    if p & prop::STOP != 0 {
        DefaultAction::Stop
    } else if p & prop::IGNORE != 0 {
        DefaultAction::Ignore
    } else {
        DefaultAction::Terminate
    }
}

/// A process's `sigacts` and the `p_sigignore` and `P_NOCLD*` bits beside
/// it, indexed by Darwin signal.
#[derive(Clone, Debug)]
pub struct Sigacts {
    pub handler: [u64; NSIG],
    pub tramp: [u64; NSIG],
    pub catchmask: [u32; NSIG],
    pub siginfo: u32,
    pub sigintr: u32,
    pub sigonstack: u32,
    pub sigreset: u32,
    pub signodefer: u32,
    pub sigignore: u32,
    pub nocldstop: bool,
    pub nocldwait: bool,
    pub sigreturn_validation: u32,
    /// `p->si_pid`, `si_uid`, `si_status`, `si_code` and `p_xhighbits`:
    /// who posted the last signal that was caught and not held when posted,
    /// or the last child that ended, until a handler frame takes it.
    pub si: Option<Si>,
}

impl Default for Sigacts {
    /// `siginit`: what is ignored by default is in `p_sigignore`, but for
    /// SIGCONT.
    fn default() -> Self {
        let mut sigignore = 0;
        for d in 1..NSIG as u32 {
            if SIGPROP[d as usize] & prop::IGNORE != 0 && d != dsig::SIGCONT {
                sigignore |= sigmask(d);
            }
        }
        Sigacts {
            handler: [SIG_DFL; NSIG],
            tramp: [0; NSIG],
            catchmask: [0; NSIG],
            siginfo: 0,
            sigintr: 0,
            sigonstack: 0,
            sigreset: 0,
            signodefer: 0,
            sigignore,
            nocldstop: false,
            nocldwait: false,
            sigreturn_validation: validation::DEFAULT,
            si: None,
        }
    }
}

/// A thread's alternate stack (`uu_sigstk`, `UT_ALTSTACK`) and its pending
/// `sigreturn`s' token (`uu_sigreturn_token`, `uu_pending_sigreturn`), and
/// the exception state its last trap left (`far`, `esr`).
#[derive(Clone, Copy, Debug, Default)]
pub struct ThreadSig {
    pub ss_sp: u64,
    pub ss_size: u64,
    pub ss_flags: u32,
    pub altstack: bool,
    pub sigreturn_token: u64,
    pub pending_sigreturn: u32,
    pub far: u64,
    pub esr: u32,
    /// The last trap was a fault whose ESR this kernel cannot give.
    pub esr_unknown: bool,
}

/// The process's record of a signal's origin (`p->si_*`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Si {
    pub pid: i32,
    pub uid: u32,
    /// A wait status in Darwin's encoding: `W_EXITCODE(signum, 0)` for a
    /// posted signal, the child's for its end.
    pub status: u32,
    pub code: u32,
    pub xhighbits: u8,
}

/// `CLD_EXITED`, `CLD_KILLED`, `CLD_DUMPED`.
const CLD_EXITED: u32 = 1;
const CLD_KILLED: u32 = 2;
const CLD_DUMPED: u32 = 3;
const CLD_STOPPED: u32 = 5;

/// `__sigaction`, as a 64-bit process passes it.
struct NewAction {
    handler: u64,
    tramp: u64,
    mask: u32,
    flags: u32,
}

impl Kernel {
    /// Set the signal layer up for a Darwin process: Darwin's defaults, and
    /// told of every process-directed signal posted (for its knotes).
    pub fn darwin_signals_init(&mut self) {
        // Its uid, for other processes' checks against it.
        self.procs.set_uid(self.pid, self.creds.uid());
        self.signals.process().set_defaults(default_action);
        self.procs.record_posts(self.pid);
        let bell = self.darwin_timer_bell();
        self.signals.process().set_post_hook(Box::new(move || bell.ring()));
    }

    /// A new process's SIGCHLD flags: forkproc copies no P_NOCLDSTOP or
    /// P_NOCLDWAIT into the child's p_flag.
    pub(crate) fn darwin_fork_signals(&mut self) {
        self.dtask.sigacts.nocldstop = false;
        self.dtask.sigacts.nocldwait = false;
        self.darwin_sig_mirror(dsig::SIGCHLD);
    }

    fn darwin_sig(&mut self) -> &mut ThreadSig {
        &mut self.darwin_me().sig
    }

    /// A Darwin call was made with `svc #imm` (the instruction at `pc`):
    /// what its exception state says (`fleh_synchronous` saves ESR and FAR,
    /// and `sleh_synchronous` clears a FAR that an SVC leaves unknown).
    pub(crate) fn darwin_note_svc(&mut self, m: &GuestMem<'_>, pc: u64) {
        let insn = m.read_u32(pc).unwrap_or(0);
        let s = self.darwin_sig();
        s.esr = esr_svc(insn >> 5);
        s.far = 0;
        s.esr_unknown = false;
    }

    /// The Linux side of signal `d`'s disposition, from `sigacts`.
    /// `kern.proc`'s view of the dispositions: what is ignored
    /// (`p_sigignore`) and what is caught (`p_sigcatch`).
    pub(crate) fn darwin_live_sigmasks(&self) {
        let ps = &self.dtask.sigacts;
        let mut catch = 0u32;
        for d in 1..NSIG as u32 {
            let h = ps.handler[d as usize];
            if h != SIG_DFL && h != SIG_IGN {
                catch |= sigmask(d);
            }
        }
        let live = &self.dtask.live;
        live.sigignore.store(ps.sigignore, std::sync::atomic::Ordering::Relaxed);
        live.sigcatch.store(catch, std::sync::atomic::Ordering::Relaxed);
    }

    fn darwin_sig_mirror(&mut self, d: u32) {
        self.darwin_live_sigmasks();
        let l = signal_to_linux(d);
        if l == 0 {
            return;
        }
        let ps = &self.dtask.sigacts;
        let bit = sigmask(d);
        let mut flags = 0;
        if ps.sigonstack & bit != 0 {
            flags |= sa::ONSTACK;
        }
        if ps.sigintr & bit == 0 {
            flags |= sa::RESTART;
        }
        if ps.siginfo & bit != 0 {
            flags |= sa::SIGINFO;
        }
        if ps.signodefer & bit != 0 {
            flags |= sa::NODEFER;
        }
        if ps.sigreset & bit != 0 {
            flags |= sa::RESETHAND;
        }
        if d == dsig::SIGCHLD {
            if ps.nocldstop {
                flags |= sa::NOCLDSTOP;
            }
            if ps.nocldwait {
                flags |= sa::NOCLDWAIT;
            }
        }
        let a = SigAction { handler: ps.handler[d as usize], flags, restorer: ps.tramp[d as usize], mask: mask_to_linux(ps.catchmask[d as usize]) };
        let _ = self.signals.set_action(l, a);
    }

    /// Drop signal `d` wherever it is pending (`clear_procsiglist`).
    fn darwin_sig_discard(&mut self, d: u32) {
        let l = signal_to_linux(d);
        if l == 0 {
            return;
        }
        self.collect_signals();
        self.signals.discard_everywhere(l, &self.thread_signals);
    }

    /// `sigaction(signum, nsa, osa)`.
    pub(crate) fn darwin_sigaction(&mut self, m: &mut GuestMem<'_>, signum: u64, nsa: u64, osa: u64) -> Result<u64, Errno> {
        let d = signum as i32;
        if d <= 0 || d >= NSIG as i32 || d as u32 == dsig::SIGKILL || d as u32 == dsig::SIGSTOP {
            return Err(Errno::EINVAL);
        }
        let d = d as u32;
        let mut want_validation = validation::DEFAULT;
        let new = if nsa != 0 {
            let mut v = NewAction { handler: m.read_u64(nsa)?, tramp: m.read_u64(nsa + 8)?, mask: m.read_u32(nsa + 16)?, flags: m.read_u32(nsa + 20)? };
            want_validation = if v.flags & saf::VALIDATE_SIGRETURN_FROM_SIGTRAMP != 0 { validation::ENABLED } else { validation::DISABLED };
            v.flags &= saf::USERSPACE_MASK;
            // signal_is_restricted: only watchOS restricts any.
            Some(v)
        } else {
            None
        };
        if osa != 0 {
            let ps = &self.dtask.sigacts;
            let bit = sigmask(d);
            let mut flags = 0;
            if ps.sigonstack & bit != 0 {
                flags |= saf::ONSTACK;
            }
            if ps.sigintr & bit == 0 {
                flags |= saf::RESTART;
            }
            if ps.siginfo & bit != 0 {
                flags |= saf::SIGINFO;
            }
            if ps.signodefer & bit != 0 {
                flags |= saf::NODEFER;
            }
            if d == dsig::SIGCHLD && ps.nocldstop {
                flags |= saf::NOCLDSTOP;
            }
            if d == dsig::SIGCHLD && ps.nocldwait {
                flags |= saf::NOCLDWAIT;
            }
            let (handler, mask) = (ps.handler[d as usize], ps.catchmask[d as usize]);
            m.write_u64(osa, handler)?;
            m.write_u32(osa + 8, mask)?;
            m.write_u32(osa + 12, flags)?;
        }
        if let Some(v) = new {
            let ps = &mut self.dtask.sigacts;
            if ps.sigreturn_validation == validation::DEFAULT {
                ps.sigreturn_validation = want_validation;
            }
            self.darwin_setsigvec(d, &v);
        }
        Ok(0)
    }

    /// `setsigvec`.
    fn darwin_setsigvec(&mut self, d: u32, v: &NewAction) {
        let bit = sigmask(d);
        let ps = &mut self.dtask.sigacts;
        let was_ignored = ps.sigignore & bit != 0 || ps.handler[d as usize] == SIG_IGN;
        ps.handler[d as usize] = v.handler;
        ps.tramp[d as usize] = v.tramp;
        ps.catchmask[d as usize] = v.mask & !CANTMASK;
        let set = |word: &mut u32, on: bool| if on { *word |= bit } else { *word &= !bit };
        set(&mut ps.siginfo, v.flags & saf::SIGINFO != 0);
        set(&mut ps.sigintr, v.flags & saf::RESTART == 0);
        set(&mut ps.sigonstack, v.flags & saf::ONSTACK != 0);
        set(&mut ps.sigreset, v.flags & saf::RESETHAND != 0);
        set(&mut ps.signodefer, v.flags & saf::NODEFER != 0);
        if d == dsig::SIGCHLD {
            ps.nocldstop = v.flags & saf::NOCLDSTOP != 0;
            ps.nocldwait = v.flags & saf::NOCLDWAIT != 0 || v.handler == SIG_IGN;
            let (nocldstop, nocldwait) = (ps.nocldstop, ps.nocldwait);
            self.procs.set_nocldstop(self.pid, nocldstop);
            self.procs.set_nocldwait(self.pid, nocldwait);
        }
        let ignored = v.handler == SIG_IGN || (SIGPROP[d as usize] & prop::IGNORE != 0 && v.handler == SIG_DFL);
        if ignored {
            if d != dsig::SIGCONT {
                ps.sigignore |= bit;
            }
        } else {
            ps.sigignore &= !bit;
        }
        self.darwin_sig_mirror(d);
        // An ignored signal is dropped when it is posted (psignal checks
        // p_sigignore), and an action that ignores one drops what is
        // pending of it. The signal layer drops ignored ones when it would
        // deliver them instead, so what it holds of one that was ignored
        // until now goes here.
        if ignored || was_ignored {
            self.darwin_sig_discard(d);
        }
    }

    /// `execsigs`: the new image's signal state. A caught signal's action
    /// goes back to the default (its mask and flags stay); one whose
    /// default is to ignore it is ignored from now on (SIGCONT aside) and
    /// what is pending of it dropped. The signal stack is the user stack.
    pub(crate) fn darwin_execsigs(&mut self) {
        for d in 1..NSIG as u32 {
            let h = self.dtask.sigacts.handler[d as usize];
            if h == SIG_DFL || h == SIG_IGN {
                continue;
            }
            self.dtask.sigacts.handler[d as usize] = SIG_DFL;
            if SIGPROP[d as usize] & prop::IGNORE != 0 {
                if d != dsig::SIGCONT {
                    self.dtask.sigacts.sigignore |= sigmask(d);
                }
                self.darwin_sig_discard(d);
            }
        }
        let ps = &mut self.dtask.sigacts;
        ps.sigreturn_validation = validation::DEFAULT;
        ps.sigonstack = 0;
        for d in 1..NSIG as u32 {
            self.darwin_sig_mirror(d);
        }
        let s = self.darwin_sig();
        s.ss_flags = saf::DISABLE;
        s.ss_size = 0;
        s.ss_sp = 0;
        s.altstack = false;
    }

    /// A spawn's `POSIX_SPAWN_SETSIGMASK`: the thread's mask, less what
    /// cannot be masked.
    pub(crate) fn darwin_set_sigmask(&mut self, mask: u32) {
        self.signals.set_blocked(super::kern::mask_to_linux(mask & !CANTMASK));
    }

    /// A spawn's `POSIX_SPAWN_SETSIGDEF`: `setsigvec` to the default, with
    /// no mask or flags, for each signal in `set`.
    pub(crate) fn darwin_sigdefault(&mut self, set: u32) {
        for d in 1..NSIG as u32 {
            if set & sigmask(d) != 0 {
                self.darwin_setsigvec(d, &NewAction { handler: SIG_DFL, tramp: 0, mask: 0, flags: 0 });
            }
        }
    }

    /// `sigaltstack(nss, oss)`.
    pub(crate) fn darwin_sigaltstack(&mut self, m: &mut GuestMem<'_>, nss: u64, oss: u64) -> Result<u64, Errno> {
        let s = self.darwin_sig();
        if !s.altstack {
            s.ss_flags |= saf::DISABLE;
        }
        let cur = *s;
        let onstack = cur.ss_flags & saf::ONSTACK;
        if oss != 0 {
            m.write_u64(oss, cur.ss_sp)?;
            m.write_u64(oss + 8, cur.ss_size)?;
            m.write_u32(oss + 16, cur.ss_flags)?;
            m.write_u32(oss + 20, 0)?;
        }
        if nss == 0 {
            return Ok(0);
        }
        let (sp, size, flags) = (m.read_u64(nss)?, m.read_u64(nss + 8)?, m.read_u32(nss + 16)?);
        if flags & !saf::DISABLE != 0 {
            return Err(Errno::EINVAL);
        }
        let s = self.darwin_sig();
        if flags & saf::DISABLE != 0 {
            if s.ss_flags & saf::ONSTACK != 0 {
                return Err(Errno::EINVAL);
            }
            s.altstack = false;
            s.ss_flags = flags;
            return Ok(0);
        }
        if onstack != 0 {
            return Err(Errno::EPERM);
        }
        // OLDMINSIGSTKSZ.
        if size < 8 * 1024 {
            return Err(Errno::ENOMEM);
        }
        s.altstack = true;
        s.ss_sp = sp;
        s.ss_size = size;
        s.ss_flags = flags;
        Ok(0)
    }

    /// Deliver what is pending to the running thread, as `bsd_ast` does
    /// on the way back to user space: `issignal` takes the lowest-numbered
    /// signal not blocked, and `postsig_locked` acts on it, until none is
    /// left. An ignored signal is dropped, a default one ends the process
    /// (or is dropped, or would stop it), and a caught one gets a handler
    /// frame, each on top of the one before.
    pub(crate) fn darwin_deliver(&mut self, m: &mut GuestMem<'_>) -> Delivery {
        self.darwin_assign_signals();
        let mut resume = None;
        loop {
            let ready = self.signals.pending_raw() & !self.signals.blocked();
            if ready == 0 {
                break;
            }
            let darwin = mask_from_linux(ready);
            if darwin == 0 {
                let l = ready.trailing_zeros() + 1;
                let _ = self.signals.claim(l);
                self.darwin_unimplemented(format!("Linux signal {l}, which Darwin has no number for, sent to a Darwin process"));
                continue;
            }
            let d = darwin.trailing_zeros() + 1;
            let l = signal_to_linux(d);
            let Some(source) = self.signals.claim(l) else { continue };
            let ps = &self.dtask.sigacts;
            let handler = ps.handler[d as usize];
            if handler == SIG_IGN || ps.sigignore & sigmask(d) != 0 {
                continue;
            }
            if handler == SIG_DFL {
                let p = SIGPROP[d as usize];
                if p & prop::STOP != 0 {
                    self.darwin_issignal_stop(d);
                    continue;
                }
                if p & prop::IGNORE != 0 {
                    continue;
                }
                self.darwin_signal_exit(d);
                return Delivery::Terminate { signal: l, core: false };
            }
            match self.darwin_postsig(m, d, handler, Some(source)) {
                Delivery::Resume(pc) => resume = Some(pc),
                Delivery::None => {}
                end @ Delivery::Terminate { .. } => return end,
            }
        }
        resume.map_or(Delivery::None, Delivery::Resume)
    }

    /// `get_signalthread` for each process-directed signal pending: the
    /// first thread (a pthread before a workqueue thread) that takes
    /// signals and does not block it, or else the first thread, gets it on
    /// its own list (`uu_siglist`). A signal caught and not held there is
    /// psignal's record of who sent it.
    pub(crate) fn darwin_assign_signals(&mut self) {
        // Each post in order (the pending set keeps one bit a signal, and a
        // stop then a continue is not a continue then a stop), then any
        // signal pending with no post recorded.
        let mut order = self.signals.process().take_to_assign();
        let mut rest = self.signals.process().shared();
        for &(l, _) in &order {
            if (1..=64).contains(&l) {
                rest &= !(1u64 << (l - 1));
            }
        }
        while rest != 0 {
            order.push((rest.trailing_zeros() + 1, None));
            rest &= rest - 1;
        }
        if order.is_empty() {
            return;
        }
        let tids = self.thread_signals.tids_in_order();
        for (l, note) in order {
            if !(1..=64).contains(&l) {
                continue;
            }
            let bit = 1u64 << (l - 1);
            let willing = |k: &Kernel, t: i32, skip_wq: bool| {
                let d = k.dtask.threads.map.get(&t);
                let no_sigmask = d.is_some_and(|d| d.cancel.no_sigmask);
                let wq = d.is_some_and(|d| d.wq.is_some());
                let blocked = k.thread_signals.get(t).is_none_or(|s| s.blocked() & bit != 0);
                !no_sigmask && !blocked && !(skip_wq && wq)
            };
            let tid = tids.iter().copied().find(|&t| willing(self, t, true)).or_else(|| tids.iter().copied().find(|&t| willing(self, t, false))).or_else(|| tids.first().copied());
            let Some(tid) = tid else { continue };
            let Some(ts) = self.thread_signals.get(tid) else { continue };
            // The reason the post carries, for the thread it is given to
            // (one the kernel posted with none: the kernel's own process
            // sent it).
            if let Some(d) = signal_from_linux(l) {
                if self.darwin_signal_kills(tid, &ts, d, false) {
                    ts.set_exit_reason_if_none(|| note.unwrap_or_else(|| {
                        let (pid, name) = super::reason::kernproc();
                        Arc::new(OsReason::signal(d, pid, &name, None))
                    }));
                }
            }
            match self.signals.process().take_shared(l) {
                Some(source) => {
                    if l == crate::signal::sig::SIGCHLD {
                        self.darwin_note_child_end();
                    }
                    if ts.blocked() & bit == 0 {
                        self.darwin_note_sender(l, source);
                    }
                    ts.raise(l, source);
                }
                // A second post of one already moved: pending again where
                // the work at the first took it away (a stop, a continue).
                None if ts.pending() & bit == 0 => ts.raise(l, None),
                None => {}
            }
            self.darwin_psignal(tid, l, false);
        }
    }

    /// `__sigwait(set, sig)` and `__sigwait_nocancel`: a signal of the set
    /// already on some thread's list (the threads in the order they were
    /// made) is taken from it, the lowest; else the thread masks all but the
    /// set (SIGKILL and SIGSTOP cannot be masked) and sleeps until one is
    /// given it (KERN_SIG_WAIT), its mask back after. EINVAL for no set, or
    /// one of only those two.
    pub(crate) fn darwin_sigwait(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> SyscallOutcome {
        let done = |k: &mut Kernel, m: &mut GuestMem<'_>, r: Result<u64, Errno>| {
            let _ = super::set_result(m, k.ctx_addr, r.unwrap_or_else(|e| e.as_return()));
            SyscallOutcome::Continue
        };
        if a[0] == 0 {
            return done(self, m, Err(Errno::EINVAL));
        }
        let Ok(mask) = m.read_u32(a[0]) else { return done(self, m, Err(Errno::EFAULT)) };
        let siglist = mask & !SIGCANTMASK;
        if siglist == 0 {
            return done(self, m, Err(Errno::EINVAL));
        }
        self.collect_signals();
        self.darwin_assign_signals();
        for tid in self.thread_signals.tids_in_order() {
            let Some(ts) = self.thread_signals.get(tid) else { continue };
            let sigw = mask_from_linux(ts.pending()) & siglist;
            if sigw != 0 {
                let d = sigw.trailing_zeros() + 1;
                ts.discard_mask(1u64 << (signal_to_linux(d) - 1));
                let r = Self::darwin_sigwait_out(m, a[1], d);
                return done(self, m, r);
            }
        }
        let old = self.signals.blocked();
        let me = self.dtask.threads.map.entry(self.tid).or_default();
        me.sigwait = siglist;
        me.sigwait_got = 0;
        me.sigwait_oldmask = old;
        self.signals.set_blocked(mask_to_linux(!(siglist | SIGCANTMASK)));
        self.darwin_block(m, super::wait::Wait { deadline: None, cont: super::thread::Finish::Sigwait { siglist, sig: a[1] } })
    }

    /// `__sigwait`'s signal number copied out, when asked for.
    fn darwin_sigwait_out(m: &mut GuestMem<'_>, at: u64, d: u32) -> Result<u64, Errno> {
        if at != 0 {
            m.write_u32(at, d)?;
        }
        Ok(0)
    }

    /// `__sigwait`'s sleep ended: the signal given it (what was posted while
    /// it slept, given first), or EINTR for a signal it may take; anything
    /// else (a signal another thread was given) leaves it asleep.
    pub(crate) fn darwin_sigwait_done(&mut self, m: &mut GuestMem<'_>, siglist: u32, sig: u64, res: super::wait::WaitResult) -> Option<SyscallOutcome> {
        self.collect_signals();
        self.darwin_assign_signals();
        let tid = self.tid;
        let got = self.dtask.threads.map.get(&tid).map_or(0, |t| t.sigwait_got) & siglist;
        if got == 0 && !(res == super::wait::WaitResult::Interrupted && self.signals.would_deliver()) {
            return Some(self.darwin_block(m, super::wait::Wait { deadline: None, cont: super::thread::Finish::Sigwait { siglist, sig } }));
        }
        let me = self.dtask.threads.map.entry(tid).or_default();
        let old = me.sigwait_oldmask;
        me.sigwait = 0;
        me.sigwait_got = 0;
        me.sigwait_oldmask = 0;
        self.signals.set_blocked(old);
        let r = if got == 0 { Err(Errno::EINTR) } else { Self::darwin_sigwait_out(m, sig, got.trailing_zeros() + 1) };
        let _ = super::set_result(m, self.ctx_addr, r.unwrap_or_else(|e| e.as_return()));
        None
    }

    /// Whether thread `tid`'s `__sigwait` has been given a signal (its sleep
    /// is over).
    pub(crate) fn darwin_sigwait_given(&self, tid: i32) -> bool {
        self.dtask.threads.map.get(&tid).is_some_and(|t| t.sigwait_got != 0)
    }

    /// `build_signal_reason(d, NULL)` with this process the sender.
    pub(crate) fn darwin_signal_reason(&self, d: u32) -> Note {
        Arc::new(OsReason::signal(d, self.pid, &self.dtask.p_name.0, None))
    }

    /// `psignal_internal`'s test for giving thread `tid` (`ts`) an exit
    /// reason for Darwin signal `d` (`thread_directed`: posted to it,
    /// PSIG_THREAD): SIGKILL, or a signal neither ignored, waited for
    /// (KERN_SIG_WAIT), held nor caught whose default kills -- but a
    /// thread-directed one to a stopped process.
    pub(crate) fn darwin_signal_kills(&self, tid: i32, ts: &crate::signal::ThreadSig, d: u32, thread_directed: bool) -> bool {
        if d == dsig::SIGKILL {
            return true;
        }
        let ps = &self.dtask.sigacts;
        let l = signal_to_linux(d);
        let waited = self.dtask.threads.map.get(&tid).is_some_and(|t| t.sigwait & sigmask(d) != 0);
        if ps.sigignore & sigmask(d) != 0 || waited || l == 0 || ts.blocked() & (1u64 << (l - 1)) != 0 || ps.handler[d as usize] != SIG_DFL {
            return false;
        }
        if SIGPROP[d as usize] & prop::KILL == 0 {
            return false;
        }
        !(thread_directed && self.procs.job(self.pid).is_some_and(|j| j.lock().unwrap_or_else(|e| e.into_inner()).stopped))
    }

    /// `psignal_uthread(thread, d)` from this process: the reason it gives
    /// thread `tid` when the signal would kill it there.
    pub(crate) fn darwin_thread_reason(&self, tid: i32, d: u32) {
        let Some(ts) = self.thread_signals.get(tid) else { return };
        if self.darwin_signal_kills(tid, &ts, d, true) {
            let note = self.darwin_signal_reason(d);
            ts.set_exit_reason_if_none(|| note);
        }
    }

    /// `exit_with_reason` for a death by Darwin signal `d`'s default action
    /// on this thread: the thread's exit reason is the process's unless
    /// its exit has begun; then `proc_prepareexit`'s report of a crash.
    fn darwin_signal_exit(&mut self, d: u32) {
        let reason = self.thread_signals.get(self.tid).and_then(|t| t.exit_reason());
        self.procs.begin_exit(self.pid, reason);
        self.darwin_prepareexit(d);
    }

    /// `proc_prepareexit`'s crash report for an end by Darwin signal `d`
    /// (0 for none): unless the exit reason says no report, a core signal,
    /// a code signing kill or a reason that asks for a report tells the
    /// EXC_CRASH handlers (`task_exception_notify`), its code the signal
    /// and the thread's last exception. The host's own handler takes it
    /// and nothing is seen, unless a handler was set; that one is sent it
    /// on the way out of a call.
    pub(crate) fn darwin_prepareexit(&mut self, d: u32) {
        if self.dtask.crash_behavior != 0 {
            self.darwin_unimplemented(format!("a process spawned with crash behavior {:#x} ending (signal {d}): the system would panic", self.dtask.crash_behavior));
        }
        use super::reason::flag;
        let flags = self.procs.exit_reason(self.pid).and_then(|n| super::reason::of(&n)).map(|r| r.flags);
        let killed = self.dtask.csflags.load(std::sync::atomic::Ordering::Acquire) & super::amfi::cs::KILLED != 0;
        let core = d != 0 && SIGPROP[d as usize] & prop::CORE != 0;
        if flags.is_some_and(|f| f & flag::NO_CRASH_REPORT != 0) || !(core || killed || flags.is_some_and(|f| f & flag::GENERATE_CRASH_REPORT != 0)) {
            return;
        }
        use super::exception as exc;
        if self.darwin_exc_handled(exc::EXC_CRASH) {
            let th = self.dtask.threads.map.get(&self.tid).map(|t| (t.uu_exception, t.uu_code, t.uu_subcode)).unwrap_or_default();
            let code = (i64::from(d & 0xff) << 24) | (i64::from(th.0 & 0x0f) << 20) | (th.1 & 0xfffff);
            if self.dtask.syscall_exit {
                self.dtask.crash_notify = Some((code, th.2));
            } else {
                self.darwin_unimplemented(format!("telling the EXC_CRASH handler of a death by Darwin signal {d} taken outside a call"));
            }
        }
    }

    /// psignal's `si_pid`, `si_uid` for a caught signal (but SIGCHLD): the
    /// sender, or the process the kernel posted it from (an interval
    /// timer's SIGALRM, from the kernel's own thread call).
    pub(crate) fn darwin_note_sender(&mut self, l: u32, source: Option<Source>) {
        let Some(d) = signal_from_linux(l) else { return };
        let ps = &self.dtask.sigacts;
        let caught = ps.handler[d as usize] != SIG_DFL && ps.handler[d as usize] != SIG_IGN && ps.sigignore & sigmask(d) == 0;
        if !caught || d == dsig::SIGCHLD {
            return;
        }
        let (pid, uid) = match source {
            Some(src) => (src.pid, src.uid),
            None if d == dsig::SIGALRM => (0, 0),
            None => (self.pid, self.creds.uid()),
        };
        self.dtask.sigacts.si = Some(Si { pid, uid, status: d << 8, code: 0, xhighbits: 0 });
    }

    /// `proc_exit`'s record in the parent of a child that ended (its pid,
    /// status, real uid and the top byte of its exit value), as CLD_EXITED.
    pub(crate) fn darwin_note_child_end(&mut self) {
        if let Some(end) = self.procs.take_child_end(self.pid) {
            if end.stopped {
                self.dtask.sigacts.si = Some(Si { pid: end.pid, uid: end.uid, status: end.status as u32, code: CLD_STOPPED, xhighbits: 0 });
                return;
            }
            let status = super::exit::status_from_linux(end.status as u32) & 0xffff;
            self.dtask.sigacts.si = Some(Si { pid: end.pid, uid: end.uid, status, code: CLD_EXITED, xhighbits: end.xhighbits });
        }
    }

    /// `sigpending(osv)`: the calling thread's own list.
    pub(crate) fn darwin_sigpending(&mut self, m: &mut GuestMem<'_>, osv: u64) -> Result<u64, Errno> {
        self.collect_signals();
        self.darwin_assign_signals();
        if osv != 0 {
            m.write_u32(osv, mask_from_linux(self.signals.thread().pending()))?;
        }
        Ok(0)
    }

    /// A fault the running instruction raised, as `ux_exception` makes it a
    /// signal when no exception handler takes it (`exception_triage`
    /// asks the thread's, the task's and the host's first: sending it
    /// there is not done here, and fails loudly).
    /// An access the instruction at `pc` made at `addr` that its page does
    /// not allow (`write`: a store's or an atomic's), as `vm_fault` answers
    /// `handle_user_abort`: KERN_INVALID_ADDRESS where nothing is mapped,
    /// which `ux_exception` makes SIGSEGV, else KERN_PROTECTION_FAILURE,
    /// SIGBUS. The fault raised; the (Linux-numbered) signal with it.
    ///
    /// A store to a page whose write bit a kernel object took from the
    /// protection table to see the store (an IOSurface view's) is noted by
    /// it, the bit given back, and the instruction runs again: no fault,
    /// signal 0. The access may begin on the page before.
    pub fn darwin_access_fault(&mut self, m: &mut GuestMem<'_>, pc: u64, addr: u64, write: bool) -> (Delivery, u32) {
        if write {
            let page = addr >> gex_abi::PERM_PAGE_SHIFT;
            if super::iosurface::note_store(self, m, page) || super::iosurface::note_store(self, m, page + 1) {
                self.darwin_flush_perms(m);
                return (Delivery::Resume(pc), 0);
            }
        }
        let prot = if addr >= gex_abi::DARWIN_GUEST_FLOOR { self.mem.lock().vma_at(addr).map(|v| v.prot) } else { None };
        let l = match prot {
            None => crate::signal::sig::SIGSEGV,
            Some(p) => {
                if p & if write { crate::mem::prot::WRITE } else { crate::mem::prot::READ } != 0 {
                    self.darwin_unimplemented(format!("an access check at {addr:#x} (pc {pc:#x}) failed for a page whose protection {p:#x} allows it: the protection table is out of date"));
                }
                crate::signal::sig::SIGBUS
            }
        };
        (self.raise_fault(m, l, pc, addr), l)
    }

    pub(crate) fn darwin_raise_fault(&mut self, m: &mut GuestMem<'_>, l: u32, pc: u64, fault_address: u64) -> Delivery {
        let Some(d) = signal_from_linux(l) else { return Delivery::Terminate { signal: l, core: false } };
        use super::exception as exc;
        let ty = match d {
            dsig::SIGSEGV | dsig::SIGBUS => Some(exc::EXC_BAD_ACCESS),
            dsig::SIGILL => Some(exc::EXC_BAD_INSTRUCTION),
            dsig::SIGFPE => Some(exc::EXC_ARITHMETIC),
            dsig::SIGTRAP => Some(exc::EXC_BREAKPOINT),
            _ => None,
        };
        if let Some(ty) = ty.filter(|&t| self.darwin_exc_handled(t)) {
            self.darwin_unimplemented(format!("sending exception {ty} (Darwin signal {d}) to its exception handler (exception_triage)"));
        }
        // threadsignal: the thread's exit reason, if it has none, is the
        // signal, sent by this process as "exc handler".
        if let Some(ts) = self.thread_signals.get(self.tid) {
            let (pid, name) = (self.pid, self.dtask.p_name.0);
            ts.set_exit_reason_if_none(|| Arc::new(OsReason::signal(d, pid, &name, Some(b"exc handler"))));
        }
        let blocked = self.signals.blocked() & (1u64 << (l - 1)) != 0;
        let handler = self.dtask.sigacts.handler[d as usize];
        // threadsignal of a blocked or ignored fault: the thread would take
        // it again on return, so it ends the process as the default does.
        if handler == SIG_DFL || handler == SIG_IGN || blocked {
            self.darwin_signal_exit(d);
            return Delivery::Terminate { signal: l, core: false };
        }
        if m.write_u64(self.ctx_addr + ctx::PC as u64, pc).is_err() {
            return Delivery::Terminate { signal: l, core: false };
        }
        self.darwin_unimplemented(format!("a handler for Darwin signal {d} raised by a fault: the fault's ESR is not known here, so its frame says 0"));
        let s = self.darwin_sig();
        s.far = fault_address;
        s.esr = 0;
        s.esr_unknown = true;
        self.signals.clear_pending(l);
        self.darwin_postsig(m, d, handler, None)
    }

    /// `postsig_locked`'s caught case, then `sendsig`.
    fn darwin_postsig(&mut self, m: &mut GuestMem<'_>, d: u32, catcher: u64, source: Option<Option<Source>>) -> Delivery {
        let l = signal_to_linux(d);
        let bit = sigmask(d);
        // The mask before a sigsuspend (UT_SAS_OLDMASK), else the current.
        let return_l = self.signals.take_suspend_restore().unwrap_or(self.signals.blocked());
        let ps = &self.dtask.sigacts;
        let mut blocked = self.signals.blocked() | mask_to_linux(ps.catchmask[d as usize]);
        if ps.signodefer & bit == 0 {
            blocked |= 1u64 << (l - 1);
        }
        self.signals.set_blocked(blocked);
        let siginfo = ps.siginfo;
        if d != dsig::SIGILL && d != dsig::SIGTRAP && ps.sigreset & bit != 0 {
            let ps = &mut self.dtask.sigacts;
            if d != dsig::SIGCONT && SIGPROP[d as usize] & prop::IGNORE != 0 {
                ps.sigignore |= bit;
            }
            ps.handler[d as usize] = SIG_DFL;
            ps.siginfo &= !bit;
            ps.signodefer &= !bit;
            self.darwin_sig_mirror(d);
        }
        match self.darwin_sendsig(m, catcher, d, mask_from_linux(return_l), siginfo, source) {
            Ok(pc) => Delivery::Resume(pc),
            Err(_) => {
                // bad: the process takes a SIGILL with the default action.
                let s = self.darwin_sig();
                s.pending_sigreturn = s.pending_sigreturn.saturating_sub(1);
                let ill = sigmask(dsig::SIGILL);
                let ps = &mut self.dtask.sigacts;
                ps.handler[dsig::SIGILL as usize] = SIG_DFL;
                ps.sigignore &= !ill;
                self.darwin_sig_mirror(dsig::SIGILL);
                let ill_l = signal_to_linux(dsig::SIGILL);
                self.signals.set_blocked(self.signals.blocked() & !(1u64 << (ill_l - 1)));
                let note = self.darwin_signal_reason(dsig::SIGILL);
                self.signals.process().raise_noted(ill_l, None, Some(note));
                Delivery::None
            }
        }
    }

    /// `sendsig`: the frame below the stack (or at the top of the
    /// alternate one), the registers set for the trampoline. Where to
    /// resume.
    fn darwin_sendsig(&mut self, m: &mut GuestMem<'_>, catcher: u64, d: u32, mask: u32, siginfo: u32, source: Option<Option<Source>>) -> Result<u64, Errno> {
        let c = self.ctx_addr;
        let infostyle = if siginfo & sigmask(d) != 0 { UC_FLAVOR } else { UC_TRAD };
        let trampact = self.dtask.sigacts.tramp[d as usize];
        let sigonstack = self.dtask.sigacts.sigonstack & sigmask(d) != 0;
        if self.darwin_sig().pending_sigreturn == 0 {
            let token = self.darwin_read_random()?;
            self.darwin_sig().sigreturn_token = token;
        }
        let s = self.darwin_sig();
        s.pending_sigreturn += 1;
        let oonstack = s.ss_flags & saf::ONSTACK;

        let thread_sp = m.read_u64(c + ctx::SP as u64)?;
        let thread_pc = m.read_u64(c + ctx::PC as u64)?;
        let s = self.darwin_sig();
        let (far, esr) = (s.far, s.esr);
        let (mut sp, stack_size) = if s.altstack && oonstack == 0 && sigonstack {
            s.ss_flags |= saf::ONSTACK;
            (s.ss_sp + s.ss_size, s.ss_size)
        } else {
            (thread_sp, 0)
        };
        sp = (sp - frame::SIZE - frame::REDZONE) & !15;

        // The siginfo.
        let mut info = [0u8; frame::SINFO_SIZE as usize];
        let put32 = |b: &mut [u8], o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
        let put64 = |b: &mut [u8], o: usize, v: u64| b[o..o + 8].copy_from_slice(&v.to_le_bytes());
        put32(&mut info, 0, d);
        put64(&mut info, 24, thread_pc);
        put64(&mut info, 48, thread_sp);
        match d {
            dsig::SIGILL => put32(&mut info, 8, ILL_ILLTRP),
            dsig::SIGFPE => {
                self.darwin_unimplemented("SIGFPE's si_code from the exception's code (uu_code)".into());
                put32(&mut info, 8, FPE_NOOP);
            }
            dsig::SIGBUS => {
                put64(&mut info, 24, far);
                put32(&mut info, 8, BUS_ADRALN);
            }
            dsig::SIGSEGV => {
                put64(&mut info, 24, far);
                put32(&mut info, 8, SEGV_ACCERR);
            }
            _ => {
                // The record (p->si_*), taken: a child's end gets its
                // CLD_* code from its status, and the status shifted out to
                // the child's exit code or signal; zeros once a frame took
                // it.
                let _ = source;
                let si = self.dtask.sigacts.si.take().unwrap_or_default();
                let (mut code, mut status) = (si.code, si.status);
                if code == CLD_EXITED {
                    let (exited, signaled) = (status & 0x7f == 0, status & 0x7f != 0x7f && status & 0x7f != 0);
                    if !exited && signaled {
                        code = if status & 0x80 != 0 { CLD_DUMPED } else { CLD_KILLED };
                        // W_EXITCODE(status, status)
                        status = (status << 8) | status;
                    }
                }
                put32(&mut info, 8, code);
                put32(&mut info, 12, si.pid as u32);
                put32(&mut info, 16, si.uid);
                put32(&mut info, 20, ((status >> 8) & 0xff) | (u32::from(si.xhighbits) << 24));
            }
        }

        // The ucontext.
        let mut uctx = [0u8; frame::UCTX_SIZE as usize];
        put32(&mut uctx, 0, oonstack);
        put32(&mut uctx, 4, mask);
        put64(&mut uctx, 8, sp);
        put64(&mut uctx, 16, stack_size);
        put32(&mut uctx, 24, if oonstack != 0 { saf::ONSTACK } else { 0 });
        put64(&mut uctx, 40, frame::MCTX_SIZE);
        put64(&mut uctx, 48, sp + frame::MCTX);

        // The machine context.
        let mut mc = vec![0u8; frame::MCTX_SIZE as usize];
        put64(&mut mc, frame::ES_FAR as usize, far);
        put32(&mut mc, frame::ES_ESR as usize, esr);
        put32(&mut mc, frame::ES_EXCEPTION as usize, 0);
        for i in 0..29u8 {
            put64(&mut mc, (frame::SS + 8 * i as u64) as usize, m.read_u64(c + ctx::x(i) as u64)?);
        }
        put64(&mut mc, frame::SS_FP as usize, m.read_u64(c + ctx::x(29) as u64)?);
        put64(&mut mc, frame::SS_LR as usize, m.read_u64(c + ctx::x(30) as u64)?);
        put64(&mut mc, frame::SS_SP as usize, thread_sp);
        put64(&mut mc, frame::SS_PC as usize, thread_pc);
        put32(&mut mc, frame::SS_CPSR as usize, signal::read_pstate(m, c)? as u32);
        put32(&mut mc, frame::SS_FLAGS as usize, 0);
        for n in 0..32u8 {
            let o = (frame::NS + 16 * n as u64) as usize;
            mc[o..o + 16].copy_from_slice(m.read(c + ctx::v(n) as u64, 16)?);
        }
        put32(&mut mc, frame::NS_FPSR as usize, m.read_u32(c + ctx::FPSR as u64)?);
        put32(&mut mc, frame::NS_FPCR as usize, m.read_u32(c + ctx::FPCR as u64)?);

        let p_uctx = sp + frame::UCTX;
        let token = p_uctx ^ self.darwin_sig().sigreturn_token;
        // The frame's copyout, held to the stack's pages as copyout is: a
        // stack it cannot be written on is sendsig's `bad`.
        let prev = m.set_user(Some((c, c + ctx::SIZE as u64)));
        let copied = m.write(sp + frame::SINFO, &info).and_then(|()| m.write(p_uctx, &uctx)).and_then(|()| m.write(sp + frame::MCTX, &mc));
        m.set_user(prev);
        copied?;

        // sendsig_set_thread_state64.
        m.write_u64(c + ctx::x(0) as u64, catcher)?;
        m.write_u64(c + ctx::x(1) as u64, infostyle)?;
        m.write_u64(c + ctx::x(2) as u64, u64::from(d))?;
        m.write_u64(c + ctx::x(3) as u64, sp + frame::SINFO)?;
        m.write_u64(c + ctx::x(4) as u64, p_uctx)?;
        m.write_u64(c + ctx::x(5) as u64, token)?;
        m.write_u64(c + ctx::PC as u64, trampact)?;
        signal::write_pstate(m, c, PSR64_USER64_DEFAULT)?;
        m.write_u64(c + ctx::SP as u64, sp)?;
        Ok(trampact)
    }

    /// `read_random` for a 64-bit value.
    pub(crate) fn darwin_read_random(&self) -> Result<u64, Errno> {
        let h = self.vfs.open("/dev/urandom", crate::fs::oflags::O_RDONLY, 0)?;
        let mut b = [0u8; 8];
        h.read_at(0, &mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    /// `sigreturn(uctx, infostyle, token)`.
    pub(crate) fn darwin_sigreturn(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> SyscallOutcome {
        match self.darwin_sigreturn_inner(m, a) {
            Ok(pc) => SyscallOutcome::Resume(pc),
            Err(None) => {
                let _ = super::set_result(m, self.ctx_addr, 0);
                SyscallOutcome::Continue
            }
            Err(Some(e)) => {
                let _ = super::set_result(m, self.ctx_addr, e.as_return());
                SyscallOutcome::Continue
            }
        }
    }

    /// The restored context's pc; `Err(None)` for a call that answers 0
    /// (an alternate-stack request), `Err(Some)` for an error.
    fn darwin_sigreturn_inner(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Option<Errno>> {
        let (uctx, infostyle, utoken) = (a[0], a[1] as u32 as u64, a[2]);
        let s = self.darwin_sig();
        if infostyle == UC_SET_ALT_STACK {
            s.ss_flags |= saf::ONSTACK;
            return Err(None);
        }
        if infostyle == UC_RESET_ALT_STACK {
            s.ss_flags &= !saf::ONSTACK;
            return Err(None);
        }
        // sigreturn_copyin_ctx64.
        let u = m.read(uctx, frame::UCTX_SIZE as usize)?.to_vec();
        let get32 = |b: &[u8], o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let get64 = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        if get64(&u, 40) != frame::MCTX_SIZE {
            return Err(Some(Errno::EINVAL));
        }
        let mc = m.read(get64(&u, 48), frame::MCTX_SIZE as usize)?.to_vec();
        let (onstack, sigmask) = (get32(&u, 0), get32(&u, 4));

        let s = self.darwin_sig();
        if onstack & 1 != 0 {
            s.ss_flags |= saf::ONSTACK;
        } else {
            s.ss_flags &= !saf::ONSTACK;
        }
        // The Darwin mask, keeping what the layer blocks of the signals
        // Darwin has no number for.
        let darwin_bits = mask_to_linux(!0);
        let blocked = (self.signals.blocked() & !darwin_bits) | mask_to_linux(sigmask & !CANTMASK);
        self.signals.set_blocked(blocked);

        let validation = self.dtask.sigacts.sigreturn_validation;
        let token = uctx ^ self.darwin_sig().sigreturn_token;
        if utoken != token && validation != validation::DISABLED {
            return Err(Some(Errno::EINVAL));
        }

        // sigreturn_set_state64: the general registers, NZCV from cpsr (the
        // mode bits reset to EL0), then the NEON state.
        let c = self.ctx_addr;
        for i in 0..29u8 {
            m.write_u64(c + ctx::x(i) as u64, get64(&mc, (frame::SS + 8 * i as u64) as usize))?;
        }
        m.write_u64(c + ctx::x(29) as u64, get64(&mc, frame::SS_FP as usize))?;
        m.write_u64(c + ctx::x(30) as u64, get64(&mc, frame::SS_LR as usize))?;
        m.write_u64(c + ctx::SP as u64, get64(&mc, frame::SS_SP as usize))?;
        let pc = get64(&mc, frame::SS_PC as usize);
        m.write_u64(c + ctx::PC as u64, pc)?;
        signal::write_pstate(m, c, u64::from(get32(&mc, frame::SS_CPSR as usize)))?;
        for n in 0..32u8 {
            let o = (frame::NS + 16 * n as u64) as usize;
            m.write(c + ctx::v(n) as u64, &mc[o..o + 16])?;
        }
        m.write_u32(c + ctx::FPSR as u64, get32(&mc, frame::NS_FPSR as usize))?;
        m.write_u32(c + ctx::FPCR as u64, get32(&mc, frame::NS_FPCR as usize))?;

        let s = self.darwin_sig();
        s.pending_sigreturn = s.pending_sigreturn.saturating_sub(1);
        Ok(pc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_frame_is_as_long_as_xnus() {
        assert_eq!(frame::MCTX_SIZE, 816);
        assert_eq!(frame::SIZE, 976);
        assert_eq!(frame::NS % 16, 0);
        assert_eq!(frame::SS_CPSR, 16 + 33 * 8);
    }

    #[test]
    fn signal_numbers_round_trip() {
        for d in 1..32u32 {
            let l = signal_to_linux(d);
            if l != 0 {
                assert_eq!(signal_from_linux(l), Some(d), "darwin {d}");
            }
        }
    }

    #[test]
    fn sigio_is_ignored_by_default() {
        // Linux ends the process; XNU ignores it.
        assert_eq!(default_action(29), DefaultAction::Ignore);
        assert_eq!(default_action(signal::sig::SIGUSR1), DefaultAction::Terminate);
        assert_eq!(default_action(signal::sig::SIGSEGV), DefaultAction::Terminate);
    }

    #[test]
    fn svc_0x80_has_xnus_syndrome() {
        assert_eq!(esr_svc(0x80), 0x5600_0080);
    }
}
