//! Darwin threads, as libpthread's kernel side (`kern_support.c`) makes
//! them: `bsdthread_register`, `bsdthread_create` starting a thread at the
//! registered entry, `bsdthread_terminate`; and `ulock` (`sys_ulock.c`),
//! the wait and wake under `os_unfair_lock` and joins.

use super::bsd::sys;
use super::ipc::{KQueue, Kq, MachIpc, Mach, WorkQueue, Wq};
use super::wait::{Wait, WaitResult};
use crate::errno::Errno;
use crate::syscalls::{Kernel, SpawnRequest, SyscallOutcome};
use crate::GuestMem;
use gex_abi::ctx;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// `PTHREAD_START_*`: `bsdthread_create`'s flags (`kern_support.c`).
mod start {
    pub const CUSTOM: u64 = 0x0100_0000;
    pub const SETSCHED: u64 = 0x0200_0000;
    pub const QOSCLASS: u64 = 0x0800_0000;
    pub const TSD_BASE_SET: u64 = 0x1000_0000;
    pub const SUSPENDED: u64 = 0x2000_0000;
    pub const QOSCLASS_MASK: u64 = 0x00ff_ffff;
    pub const POLICY_BITSHIFT: u64 = 16;
    pub const POLICY_MASK: u64 = 0xff;
    pub const IMPORTANCE_MASK: u64 = 0xffff;
}

/// `PTHREAD_FEATURE_SUPPORTED`: what `bsdthread_register` answers.
pub const PTHREAD_FEATURE_SUPPORTED: u64 = 0x01 // DISPATCHFUNC
    | 0x02 // FINEPRIO
    | 0x04 // BSDTHREADCTL
    | 0x08 // SETSELF
    | 0x10 // QOS_MAINTENANCE
    | 0x4000_0000 // QOS_DEFAULT
    | 0x40 // KEVENT
    | 0x80 // WORKLOOP
    | 0x100; // COOPERATIVE_WORKQ

/// `MAX_PTHREAD_SIZE`.
const MAX_PTHREAD_SIZE: u64 = 64 * 1024;
/// `PTH_DEFAULT_STACKSIZE`.
pub const PTH_DEFAULT_STACKSIZE: u64 = 512 * 1024;
/// `sizeof(struct _pthread_registration_data)` (packed).
const REGISTRATION_SIZE: u64 = 56;
/// `BASEPRI_DEFAULT`.
const BASEPRI_DEFAULT: i32 = 31;
/// `SCHED_OTHER` on Darwin.
const SCHED_OTHER: u64 = 1;

/// Thread QoS tiers (`THREAD_QOS_*`).
pub mod qos {
    pub const UNSPECIFIED: u8 = 0;
    pub const LEGACY: u8 = 4;
    pub const LAST: u8 = 7;
    /// `THREAD_QOS_MIN_TIER_IMPORTANCE`.
    pub const MIN_TIER_IMPORTANCE: i32 = -15;
}

/// `pthread_priority_t` (`bsd/pthread/priority_private.h`).
pub mod pp {
    pub const QOS_CLASS_SHIFT: u32 = 8;
    pub const VALID_QOS_CLASS_MASK: u64 = 0x0000_3f00;
    pub const PRIORITY_MASK: u64 = 0xff;
    pub const FLAGS_MASK: u64 = 0xff00_0000;
    pub const SCHED_PRI_FLAG: u64 = 0x2000_0000;
    pub const SCHED_PRI_MASK: u64 = 0x0000_ffff;
    pub const EVENT_MANAGER_FLAG: u64 = 0x0200_0000;
    pub const OVERCOMMIT_FLAG: u64 = 0x8000_0000;
    pub const COOPERATIVE_FLAG: u64 = 0x0800_0000;
    pub const OVERRIDE_QOS_FLAG: u64 = 0x0080_0000;
    pub const VALID_OVERRIDE_QOS_MASK: u64 = 0x003f_c000;
    pub const QOS_OVERRIDE_SHIFT: u32 = 14;

    /// `_pthread_priority_has_override_qos`.
    pub fn has_override_qos(p: u64) -> bool {
        p & (SCHED_PRI_FLAG | EVENT_MANAGER_FLAG) == 0 && p & OVERRIDE_QOS_FLAG != 0 && p & VALID_OVERRIDE_QOS_MASK != 0
    }

    /// `_pthread_priority_thread_override_qos`.
    pub fn override_qos(p: u64) -> u8 {
        if !has_override_qos(p) {
            return 0;
        }
        let v = (p & VALID_OVERRIDE_QOS_MASK) >> QOS_OVERRIDE_SHIFT;
        v.trailing_zeros() as u8 + 1
    }

    /// `_pthread_priority_make_from_thread_qos`.
    pub fn from_qos(qos: u8, relpri: i32, flags: u64) -> u64 {
        let mut p = flags & FLAGS_MASK;
        if qos != 0 && qos < super::qos::LAST {
            p |= 1 << (QOS_CLASS_SHIFT + u32::from(qos) - 1);
            p |= u64::from((relpri as u8).wrapping_sub(1)) & PRIORITY_MASK;
        }
        p
    }

    /// `_pthread_priority_has_qos`.
    fn has_qos(p: u64) -> bool {
        p & (SCHED_PRI_FLAG | EVENT_MANAGER_FLAG) == 0 && p & VALID_QOS_CLASS_MASK != 0
    }

    /// `_pthread_priority_thread_qos`.
    pub fn qos(p: u64) -> u8 {
        if !has_qos(p) {
            return 0;
        }
        ((p & VALID_QOS_CLASS_MASK) >> QOS_CLASS_SHIFT).trailing_zeros() as u8 + 1
    }

    /// `_pthread_priority_relpri`.
    pub fn relpri(p: u64) -> i32 {
        if !has_qos(p) {
            return 0;
        }
        i32::from(p as u8 as i8) + 1
    }
}

/// What libpthread registered for the process (`proc_set_*` in XNU).
#[derive(Clone, Copy, Debug, Default)]
pub struct Registration {
    pub registered: bool,
    pub threadstart: u64,
    pub wqthread: u64,
    pub pthsize: u64,
    pub tsd_offset: u64,
    pub dispatch_queue_offset: u64,
    pub return_to_kernel_offset: u64,
    pub mach_thread_self_offset: u64,
    pub wq_quantum_offset: u64,
    pub stack_addr_hint: u64,
}

/// A thread's scheduling policy, as `thread_policy_set` left it.
#[derive(Clone, Copy, Debug, Default)]
pub struct Policy {
    /// `THREAD_QOS_POLICY`: tier and importance.
    pub qos: u8,
    pub relpri: i32,
    /// `THREAD_EXTENDED_POLICY`'s timeshare and `THREAD_PRECEDENCE_POLICY`'s
    /// importance, once set.
    pub timeshare: Option<bool>,
    pub importance: Option<i32>,
    /// `thrp_int_darwinbg` (PRIO_DARWIN_THREAD's, or THREAD_BACKGROUND_
    /// POLICY's from the thread itself) and `thrp_ext_darwinbg` (from
    /// another of its task's threads).
    pub int_darwinbg: bool,
    pub ext_darwinbg: bool,
    /// `thrp_latency_qos` and `thrp_through_qos`, `QOS_EXTRACT`ed.
    pub latency_qos: u8,
    pub through_qos: u8,
}

/// A thread's cancellation state: XNU's `UT_CANCEL*` bits of `uu_flag`.
#[derive(Clone, Copy, Debug, Default)]
pub struct Cancel {
    /// `UT_CANCEL`: a cancel is pending.
    pub cancel: bool,
    /// `UT_CANCELED`: the thread has acted on it.
    pub canceled: bool,
    /// `UT_CANCELDISABLE`.
    pub disable: bool,
    /// `UT_NOTCANCELPT`: in a call that is not a cancellation point (set
    /// on entry, cleared by one that is and on return).
    pub notcancelpt: bool,
    /// `UT_NO_SIGMASK`: `__pthread_kill` no longer reaches it.
    pub no_sigmask: bool,
    /// An abort (`thread_abort_safely`) that found the thread not waiting:
    /// its next wait in this call ends at once, interrupted.
    pub abort_safely: bool,
}

impl Cancel {
    /// `uthread_is_cancelled`: a cancel pending and acted on when it can be.
    pub fn is_cancelled(&self) -> bool {
        self.cancel && !self.canceled && !self.disable
    }
}

/// The BSD calls that are cancellation points: each has a `_nocancel`
/// twin and starts with `__pthread_testcancel(1)`.
pub const CANCEL_POINTS: &[u64] = &[
    sys::READ, sys::WRITE, sys::OPEN, sys::CLOSE, sys::WAIT4, sys::RECVMSG, sys::SENDMSG, sys::RECVFROM, sys::ACCEPT, sys::MSYNC, sys::FCNTL, sys::SELECT, sys::FSYNC, sys::CONNECT, sys::SIGSUSPEND, sys::READV, sys::WRITEV, sys::SENDTO, sys::PREAD, sys::PWRITE, sys::WAITID, sys::POLL, sys::SEM_WAIT, sys::AIO_SUSPEND, sys::SIGWAIT, sys::OPENAT, sys::PREADV, sys::PWRITEV, sys::PSELECT,
];

/// A Darwin thread's kernel state.
#[derive(Debug, Default)]
pub struct DThread {
    /// The last exception made a signal for it (`uu_exception`,
    /// `uu_code`, `uu_subcode`).
    pub uu_exception: i32,
    pub uu_code: i64,
    pub uu_subcode: i64,
    pub policy: Policy,
    pub cancel: Cancel,
    /// `thread_suspend` count. A thread made with `PTHREAD_START_SUSPENDED`
    /// starts at 1, not yet run.
    pub suspend: u32,
    /// `uu_sigwait`: the signals `__sigwait` waits for while it sleeps;
    /// the one given it (KERN_SIG_WAIT), and the mask to go back to.
    pub sigwait: u32,
    pub sigwait_got: u32,
    pub sigwait_oldmask: u64,
    /// Its times when the task's virtual timers were last brought up to
    /// date (`vtimer_user_save`, `vtimer_prof_save`, `vtimer_rlim_save`),
    /// in Mach time units.
    pub vtimer_saves: [u64; 3],
    /// Its CPU time ledger (`t_threadledger`'s cpu_time) once a limit
    /// made one, and its time (Mach units) credited to it so far.
    pub cpu_ledger: Option<super::cpumon::CpuLedger>,
    pub cpu_credited: u64,
    /// TH_MODE_REALTIME's time constraints, while it is in that mode.
    pub realtime: Option<super::threadpolicy::Realtime>,
    /// `thread_abort` of it while its task is held: it takes its signals.
    pub job_abort: bool,
    /// Off its CPU: parked by a hold, or waiting in a call (what
    /// `thread_wait` waits for).
    pub offcpu: bool,
    /// Where its registers are kept while it is in the kernel.
    pub ctx_addr: u64,
    /// thread_get_state's and thread_set_state's holds (thread_stop).
    pub stop_holds: u32,
    /// Its registers were set: it goes back to user space at its pc.
    pub redirect: bool,
    /// The thread, made but not started (created suspended).
    pub unstarted: Option<SpawnRequest>,
    /// A workqueue thread's state (`THREAD_TAG_WORKQUEUE`).
    pub wq: Option<Box<super::workq::WqThread>>,
    /// The QoS overrides others put on it (`thread->overrides`).
    pub overrides: Vec<super::workq::QosOverride>,
    /// The BSD call it is in or last made (`uu_syscall_code`).
    pub syscall_code: u64,
    /// `AST_KEVENT_*` owed on its way back to user space.
    pub astkevent: u16,
    /// The voucher it adopted (`ith_voucher`) and the name it gave
    /// (`ith_voucher_name`).
    pub voucher: Option<super::voucher::VoucherId>,
    pub voucher_name: u32,
    /// The kevent override (an owner's or a workqueue kqueue servicer's)
    /// and the servicer override (a workloop's) on its QoS.
    pub kevent_override: u8,
    pub servicer_override: u8,
    /// Its alternate stack, sigreturn token and last exception state.
    pub sig: super::signal::ThreadSig,
}

/// Every Darwin thread of the process, by tid.
#[derive(Debug, Default)]
pub struct Threads {
    pub map: HashMap<i32, DThread>,
}

/// `UL_*` operations and `ULF_*` flags (`bsd/sys/ulock.h`).
mod ul {
    pub const COMPARE_AND_WAIT: u8 = 1;
    pub const UNFAIR_LOCK: u8 = 2;
    pub const COMPARE_AND_WAIT_SHARED: u8 = 3;
    pub const COMPARE_AND_WAIT64: u8 = 5;
    pub const COMPARE_AND_WAIT64_SHARED: u8 = 6;
    pub const OPCODE_MASK: u64 = 0xff;
    pub const FLAGS_MASK: u64 = 0xffff_ff00;
    pub const WAKE_ALL: u64 = 0x100;
    pub const WAKE_THREAD: u64 = 0x200;
    pub const WAKE_ALLOW_NON_OWNER: u64 = 0x400;
    pub const WAIT_WORKQ_DATA_CONTENTION: u64 = 0x1_0000;
    pub const WAIT_CANCEL_POINT: u64 = 0x2_0000;
    pub const WAIT_ADAPTIVE_SPIN: u64 = 0x4_0000;
    pub const NO_ERRNO: u64 = 0x0100_0000;
    pub const DEADLINE: u64 = 0x0200_0000;
    pub const WAIT_MASK: u64 = NO_ERRNO | DEADLINE | WAIT_WORKQ_DATA_CONTENTION | WAIT_CANCEL_POINT | WAIT_ADAPTIVE_SPIN;
    pub const WAKE_MASK: u64 = NO_ERRNO | WAKE_ALL | WAKE_THREAD | WAKE_ALLOW_NON_OWNER;
}

/// A user lock the kernel knows while it has waiters (`ull_t`), by
/// address. A shared (cross-process) lock is keyed by address too: every
/// Darwin process is a tenant of one address space here, so an address
/// names one object.
#[derive(Clone, Debug, Default)]
struct Ull {
    opcode: u8,
    nwaiters: u32,
    owner: Option<i32>,
    /// Sleeping waiters, in arrival order (the turnstile orders by
    /// priority; every waiter here has the same).
    queue: VecDeque<i32>,
}

/// The process's user locks with waiters.
#[derive(Debug, Default)]
pub struct Ulocks {
    map: HashMap<u64, Ull>,
}

/// How a Darwin call that blocked turns the wait's end into its result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Finish {
    /// `ulock_wait`.
    Ulock { addr: u64, no_errno: bool },
    /// A psynch wait.
    Psynch(super::psynch::Cont),
    /// A `mach_msg` send or receive.
    MachMsg(super::mach_msg::Cont),
    /// A semaphore wait.
    Sema(super::sema::Cont),
    /// A trap's sleep (`mach_wait_until`, `thread_switch`).
    Sleep(super::mach::Sleep),
    /// A workqueue thread parked (`workq_unpark_continue`).
    WorkqPark,
    /// A kevent call's scan, or a workloop's synchronous wait.
    Kevent(super::kevent::Cont),
    /// An advisory lock's wait (`lf_setlock`).
    Lockf(super::lockf::Cont),
    /// An exception's handler's reply (`exception_deliver`).
    Exception(super::triage::Pending),
    /// `__sigwait`: the signals waited for, where the one taken goes.
    Sigwait { siglist: u32, sig: u64 },
}

/// `wait_result_to_return_code` (`sys_ulock.c`).
fn ulock_errno(r: WaitResult) -> Option<Errno> {
    match r {
        WaitResult::Awakened => None,
        WaitResult::TimedOut => Some(Errno::ETIMEDOUT),
        WaitResult::Interrupted | WaitResult::Restart => Some(Errno::EINTR),
    }
}

/// A BSD call's result written back, `ULF_NO_ERRNO` style when asked: an
/// error is its negated Darwin errno with carry clear.
pub(crate) fn bsd_result(m: &mut GuestMem<'_>, ctx_addr: u64, r: Result<u64, Errno>, no_errno: bool) {
    match r {
        Ok(v) => {
            let _ = super::set_result(m, ctx_addr, v);
        }
        Err(e) if no_errno => {
            let darwin = i64::from(super::errno::to_darwin(e.0));
            let _ = m.write_u64(ctx_addr + ctx::x(0) as u64, (-darwin) as u64);
            let _ = m.write(ctx_addr + ctx::CF as u64, &[0]);
        }
        Err(e) => {
            let _ = super::set_result(m, ctx_addr, (-(e.0 as i64)) as u64);
        }
    }
}

impl Kernel {
    /// The Darwin calls that may start a thread or block, which need
    /// outcomes the plain path cannot give. `None` for the rest.
    pub(crate) fn darwin_thread_call(&mut self, m: &mut GuestMem<'_>, raw: u64, a: &[u64; 6]) -> Option<SyscallOutcome> {
        match raw {
            // A priority may be negative, and setpriority's EIDRM is -2: a
            // value with the carry clear, not an errno.
            sys::GETPRIORITY | sys::SETPRIORITY => {
                let r = if raw == sys::GETPRIORITY { self.darwin_getpriority(a[0] as u32, a[1] as u32) } else { self.darwin_setpriority(a[0] as u32, a[1] as u32, a[2] as i32) };
                match r {
                    Ok(v) => {
                        let _ = m.write_u64(self.ctx_addr + ctx::x(0) as u64, v);
                        let _ = m.write(self.ctx_addr + ctx::CF as u64, &[0]);
                    }
                    Err(e) => {
                        let _ = super::set_result(m, self.ctx_addr, (-(e.0 as i64)) as u64);
                    }
                }
                Some(SyscallOutcome::Continue)
            }
            sys::BSDTHREAD_CREATE => Some(self.darwin_bsdthread_create(m, a)),
            sys::BSDTHREAD_TERMINATE => {
                self.darwin_bsdthread_terminate(m, a);
                None
            }
            // `ulock_wait` is `ulock_wait2` with its timeout in microseconds.
            sys::ULOCK_WAIT => {
                let a2 = [a[0], a[1], a[2], (a[3] & 0xffff_ffff) * 1000, 0, 0];
                Some(self.darwin_ulock_wait(m, &a2))
            }
            sys::ULOCK_WAIT2 => Some(self.darwin_ulock_wait(m, a)),
            sys::SEMWAIT_SIGNAL => Some(self.darwin_semwait_signal(m, a, true)),
            sys::WORKQ_OPEN => {
                let r = <Wq as WorkQueue>::open(self);
                bsd_result(m, self.ctx_addr, r, false);
                Some(SyscallOutcome::Continue)
            }
            sys::WORKQ_KERNRETURN => Some(<Wq as WorkQueue>::kernreturn(self, m, a)),
            // sigsuspend_nocancel: the mask (by value) until a signal is
            // taken, the old one back after; the call ends with EINTR.
            sys::SIGSUSPEND | sys::SIGSUSPEND_NOCANCEL => {
                let unblockable = (1u64 << (crate::signal::sig::SIGKILL - 1)) | (1u64 << (crate::signal::sig::SIGSTOP - 1));
                let restore_mask = self.signals.blocked();
                self.signals.set_blocked(super::kern::mask_to_linux(a[0] as u32) & !unblockable);
                self.restore_sigmask = Some(restore_mask);
                Some(SyscallOutcome::Blocking(crate::syscalls::BlockOp::SigSuspend { restore_mask }))
            }
            sys::SIGRETURN => Some(self.darwin_sigreturn(m, a)),
            sys::SIGWAIT | sys::SIGWAIT_NOCANCEL => Some(self.darwin_sigwait(m, a)),
            sys::EXECVE => Some(self.darwin_execve(m, a, false)),
            sys::MAC_EXECVE => Some(self.darwin_execve(m, a, true)),
            sys::POSIX_SPAWN => Some(self.darwin_posix_spawn(m, a)),
            sys::FORK => Some(self.darwin_fork(m)),
            sys::WAIT4 | sys::WAIT4_NOCANCEL => Some(self.darwin_wait4(m, a)),
            sys::WAITID | sys::WAITID_NOCANCEL => Some(self.darwin_waitid(m, a)),
            sys::FCNTL | sys::FCNTL_NOCANCEL if super::lockf::is_lock_cmd(a[1]) => Some(self.darwin_fcntl_lock(m, a)),
            sys::FLOCK => Some(self.darwin_flock(m, a)),
            // open1's O_EXLOCK and O_SHLOCK: the open, then the lock.
            sys::OPEN | sys::OPEN_NOCANCEL | sys::OPENAT | sys::OPENAT_NOCANCEL if (if raw == sys::OPEN || raw == sys::OPEN_NOCANCEL { a[1] } else { a[2] }) & super::guarded::OPEN_FINISHED != 0 => Some(self.darwin_open_finish(m, raw, *a, None)),
            sys::GUARDED_OPEN_NP | sys::GUARDED_OPEN_DPROTECTED_NP | sys::OPEN_DPROTECTED_NP | sys::OPENAT_DPROTECTED_NP => Some(self.darwin_open_protected(m, raw, a)),
            sys::WRITE | sys::WRITE_NOCANCEL | sys::WRITEV | sys::WRITEV_NOCANCEL if self.darwin_pipe_of(a[0]).is_some() => Some(self.darwin_pipe_write(m, raw, a)),
            sys::KEVENT => Some(<Kq as KQueue>::kevent_legacy(self, m, a, false)),
            sys::POLL | sys::POLL_NOCANCEL => Some(self.darwin_poll(m, a)),
            sys::OPEN_EXTENDED => Some(self.darwin_open_extended(m, a)),
            sys::SELECT | sys::SELECT_NOCANCEL => Some(self.darwin_select(m, a, false)),
            sys::PSELECT | sys::PSELECT_NOCANCEL => Some(self.darwin_select(m, a, true)),
            sys::KEVENT64 => Some(<Kq as KQueue>::kevent_legacy(self, m, a, true)),
            sys::KEVENT_QOS => Some(<Kq as KQueue>::kevent_qos(self, m, a)),
            sys::KEVENT_ID => Some(<Kq as KQueue>::kevent_id(self, m, a)),
            sys::SEMWAIT_SIGNAL_NOCANCEL => Some(self.darwin_semwait_signal(m, a, false)),
            sys::ULOCK_WAKE => {
                let no_errno = a[0] & ul::NO_ERRNO != 0;
                let r = self.darwin_ulock_wake(m, a[0], a[1], a[2]).map(|()| 0);
                bsd_result(m, self.ctx_addr, r, no_errno);
                Some(SyscallOutcome::Continue)
            }
            _ => None,
        }
    }

    /// `bsdthread_register(threadstart, wqthread, pthsize, data, data_size,
    /// dispatchqueue_offset)` (`_bsdthread_register`).
    pub(crate) fn darwin_bsdthread_register(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        let (threadstart, wqthread, pthsize, data_at, data_size) = (a[0], a[1], a[2] as i32 as i64, a[3], a[4]);
        if pthsize < 0 || pthsize as u64 > MAX_PTHREAD_SIZE {
            return Err(Errno::EINVAL);
        }
        let pthsize = pthsize as u64;
        let mut data = [0u8; REGISTRATION_SIZE as usize];
        let mut init_sz = 0;
        if data_at != 0 {
            if data_size < 8 {
                return Err(Errno::EINVAL);
            }
            init_sz = REGISTRATION_SIZE.min(data_size) as usize;
            data[..init_sz].copy_from_slice(m.read(data_at, init_sz).map_err(|_| Errno::EFAULT)?);
            if u64::from_le_bytes(data[0..8].try_into().unwrap()) != data_size {
                return Err(Errno::EINVAL);
            }
        } else {
            data[8..16].copy_from_slice(&a[5].to_le_bytes());
        }
        let u64_at = |d: &[u8], o: usize| u64::from_le_bytes(d[o..o + 8].try_into().unwrap());
        let u32_at = |d: &[u8], o: usize| u64::from(u32::from_le_bytes(d[o..o + 4].try_into().unwrap()));

        // `stack_addr_hint` on arm64: the main thread's stack top.
        let page = u64::from(super::mig::machine::PAGE_SIZE);
        let r = &mut self.dtask.pthread;
        r.stack_addr_hint = self.darwin_user_stack & !(page - 1);
        if r.registered {
            return Err(Errno::EINVAL);
        }
        r.threadstart = threadstart;
        r.wqthread = wqthread;
        r.pthsize = pthsize;
        r.registered = true;

        let slot = 8;
        let mut tsd_offset = u32_at(&data, 24);
        let max_tsd_offset = if pthsize >= slot && tsd_offset <= pthsize - slot {
            pthsize - tsd_offset - slot
        } else {
            tsd_offset = 0;
            0
        };
        let bounded = |v: u64| if v > max_tsd_offset { 0 } else { v };
        r.tsd_offset = tsd_offset;
        r.dispatch_queue_offset = bounded(u64_at(&data, 8));
        r.return_to_kernel_offset = bounded(u32_at(&data, 28));
        r.mach_thread_self_offset = bounded(u32_at(&data, 32));
        r.wq_quantum_offset = bounded(u32_at(&data, 52));
        let reg = *r;

        if data_at != 0 {
            let mut out = data;
            out[0..8].copy_from_slice(&REGISTRATION_SIZE.to_le_bytes());
            out[8..16].copy_from_slice(&reg.dispatch_queue_offset.to_le_bytes());
            out[24..28].copy_from_slice(&(reg.tsd_offset as u32).to_le_bytes());
            out[28..32].copy_from_slice(&(reg.return_to_kernel_offset as u32).to_le_bytes());
            out[32..36].copy_from_slice(&(reg.mach_thread_self_offset as u32).to_le_bytes());
            out[52..56].copy_from_slice(&(reg.wq_quantum_offset as u32).to_le_bytes());
            // The main thread's QoS; one with none is put at the legacy
            // tier.
            let main = self.dtask.threads.map.entry(self.tid).or_default();
            if main.policy.qos == qos::UNSPECIFIED {
                main.policy.qos = qos::LEGACY;
                main.policy.relpri = 0;
            }
            let main_qos = pp::from_qos(main.policy.qos, 0, 0);
            out[16..24].copy_from_slice(&main_qos.to_le_bytes());
            out[36..44].copy_from_slice(&reg.stack_addr_hint.to_le_bytes());
            // `pthread_mutex_default_policy`: 0 unless a boot-arg sets it,
            // which leaves libpthread its own defaults.
            out[44..48].copy_from_slice(&0u32.to_le_bytes());
            m.write(data_at, &out[..init_sz]).map_err(|_| Errno::EINVAL)?;
        }
        Ok(PTHREAD_FEATURE_SUPPORTED)
    }

    /// `bsdthread_create(func, arg, stack, pthread, flags)`
    /// (`_bsdthread_create`): a thread that starts at libpthread's
    /// `thread_start` with the pthread, its port, the function, its
    /// argument, the stack and the flags in x0-x5, on `stack`, its TSD at
    /// the pthread's TSD offset. The caller gets the pthread back.
    fn darwin_bsdthread_create(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> SyscallOutcome {
        match self.darwin_bsdthread_create_inner(m, a) {
            Ok(req) => {
                bsd_result(m, self.ctx_addr, Ok(a[3]), false);
                match req {
                    Some(req) => SyscallOutcome::SpawnThread { ctx_addr: req.ctx_addr, tid: req.tid },
                    None => SyscallOutcome::Continue,
                }
            }
            Err(e) => {
                bsd_result(m, self.ctx_addr, Err(e), false);
                SyscallOutcome::Continue
            }
        }
    }

    /// `task_findtid`: this task's thread whose thread id is `id`.
    pub(crate) fn darwin_findtid(&self, id: u64) -> Option<i32> {
        self.thread_signals.tids_in_order().into_iter().find(|&t| self.thread_signals.get(t).is_some_and(|s| s.darwin_id() == id))
    }

    fn darwin_bsdthread_create_inner(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<Option<SpawnRequest>, Errno> {
        use crate::syscalls::clone_flags as cf;
        let (func, arg, stack, pthread, mut flags) = (a[0], a[1], a[2], a[3], a[4] & 0xffff_ffff);
        let reg = self.dtask.pthread;
        if !reg.registered {
            return Err(Errno::EINVAL);
        }
        let suspended = flags & start::SUSPENDED != 0;
        let clone = cf::VM | cf::FS | cf::FILES | cf::SIGHAND | cf::THREAD | cf::SYSVSEM;
        let req = self.darwin_clone(m, [clone, stack.max(1), 0, 0, 0, 0]).map_err(|_| Errno::ENOMEM)?;
        // The thread's self port, copied out and pinned; a full space is
        // EMFILE (`!MACH_PORT_VALID`).
        let pport = self.darwin_thread_ports(req.tid).1;
        self.ipc().make_send(pport);
        let port = self.darwin_copyout_send_pinned(pport);
        if !super::ipc::name_valid(port) {
            self.darwin_unmake_thread(m, req, port);
            return Err(Errno::EMFILE);
        }
        if flags & start::CUSTOM == 0 {
            self.darwin_unmake_thread(m, req, port);
            return Err(Errno::EINVAL);
        }
        let mut thread = DThread { ctx_addr: req.ctx_addr, ..DThread::default() };
        if reg.tsd_offset != 0 {
            if let Some(t) = self.thread_signals.get(req.tid) {
                let _ = super::set_tsd_base(m, req.ctx_addr, &t, pthread + reg.tsd_offset, self.darwin_map_max());
            }
            flags |= start::TSD_BASE_SET;
        }
        flags &= !start::SUSPENDED;
        let c = req.ctx_addr;
        let regs = [(ctx::x(0), pthread), (ctx::x(1), u64::from(port)), (ctx::x(2), func), (ctx::x(3), arg), (ctx::x(4), stack), (ctx::x(5), flags)];
        // The new thread's context is the kernel's.
        let mut k = m.kernel();
        for (slot, v) in regs {
            let _ = k.write_u64(c + slot as u64, v);
        }
        let _ = k.write_u64(c + ctx::SP as u64, stack);
        let _ = k.write_u64(c + ctx::PC as u64, reg.threadstart);
        if flags & start::SETSCHED != 0 {
            let importance = (flags & start::IMPORTANCE_MASK) as i32;
            let policy = (flags >> start::POLICY_BITSHIFT) & start::POLICY_MASK;
            thread.policy.timeshare = Some(policy == SCHED_OTHER);
            thread.policy.importance = Some(importance - BASEPRI_DEFAULT);
        } else if flags & start::QOSCLASS != 0 {
            let p = flags & start::QOSCLASS_MASK;
            let (tier, relpri) = (pp::qos(p), pp::relpri(p));
            if tier == qos::UNSPECIFIED || relpri > 0 || relpri < qos::MIN_TIER_IMPORTANCE {
                self.darwin_unmake_thread(m, req, port);
                return Err(Errno::EINVAL);
            }
            thread.policy.qos = tier;
            thread.policy.relpri = relpri;
        }
        if reg.mach_thread_self_offset != 0 && reg.tsd_offset != 0 {
            let at = pthread + reg.tsd_offset + reg.mach_thread_self_offset;
            if m.write_u64(at, u64::from(port)).is_err() {
                self.darwin_unmake_thread(m, req, port);
                return Err(Errno::EFAULT);
            }
        }
        if self.trace {
            let how = if suspended { ", suspended" } else { "" };
            eprintln!("[gex:{}] bsdthread_create(func {func:#x}, stack {stack:#x}) = thread {} (port {port:#x}){how}", self.pid, req.tid);
        }
        if suspended {
            thread.suspend = 1;
            thread.unstarted = Some(req);
            self.dtask.threads.map.insert(req.tid, thread);
            return Ok(None);
        }
        self.dtask.threads.map.insert(req.tid, thread);
        Ok(Some(req))
    }

    /// A create that failed after making its thread: its port name is
    /// deallocated (a pinned right refuses, as on XNU), then the thread is
    /// terminated before it ever ran, its ports with it.
    fn darwin_unmake_thread(&mut self, m: &mut GuestMem<'_>, req: SpawnRequest, port: u32) {
        let _ = self.ipc().mach_port_deallocate(port);
        self.darwin_thread_ports_terminate(req.tid);
        self.darwin_ipc_settle(m);
        self.darwin_discard_thread(m, req);
    }

    /// `bsdthread_terminate(freeaddr, freesize, kport, joinsem)`: the
    /// stack goes (the main thread's is made reusable and inaccessible
    /// instead), the joiner's semaphore is signalled and the thread's port
    /// name deallocated. The thread's end is `exit`'s
    /// ([`super::bsd::translate`]).
    fn darwin_bsdthread_terminate(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) {
        let (freeaddr, freesize, kport, sem) = (a[0], a[1], a[2] as u32, a[3] as u32);
        if freesize != 0 && freeaddr != 0 {
            if self.tid == self.pid {
                // Reusable, then inaccessible once it is.
                let page = u64::from(super::mig::machine::PAGE_SIZE);
                let size = (freesize - 1) & !(page - 1);
                if self.darwin_behavior_set(m, freeaddr, size, super::mman::act::REUSABLE) == super::ipc::kr::SUCCESS {
                    let _ = self.vm_protect(m, freeaddr, size, false, 0);
                }
            } else {
                let _ = self.darwin_vm_deallocate(m, freeaddr, freesize);
            }
        }
        // thread_terminate_pinned: the self port is unpinned as the thread
        // ends, so its name can then be deallocated.
        let tid = self.tid;
        if let Some(&(_, pport)) = self.dtask.kports.threads.get(&tid) {
            self.ipc().port_mut(pport).pinned = false;
        }
        if sem != 0 {
            let _ = self.darwin_semaphore_signal_name(m, sem);
        }
        if kport != 0 {
            let _ = self.ipc().mach_port_deallocate(kport);
        }
        self.darwin_thread_ports_terminate(tid);
        if let Some(v) = self.dtask.threads.map.get_mut(&tid).and_then(|t| t.voucher.take()) {
            self.ipc_voucher_release(v);
        }
        self.darwin_ipc_settle(m);
        self.darwin_workq_thread_terminate(self.tid);
        self.darwin_workq_settle(m);
        self.dtask.threads.map.remove(&self.tid);
        self.dtask.waits.forget(self.tid);
        // Gone, so off its CPU: thread_wait on it ends.
        let tid = self.tid;
        self.darwin_pending_replies(m, tid);
    }

    /// `ulock_wait2(operation, addr, value, timeout_ns, value2)`
    /// (`sys_ulock_wait2`).
    fn darwin_ulock_wait(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> SyscallOutcome {
        let (op, addr, value, timeout) = (a[0] & 0xffff_ffff, a[1], a[2], a[3]);
        let opcode = (op & ul::OPCODE_MASK) as u8;
        let flags = op & ul::FLAGS_MASK;
        let no_errno = flags & ul::NO_ERRNO != 0;
        let done = |k: &mut Kernel, m: &mut GuestMem<'_>, r: Result<u64, Errno>| {
            bsd_result(m, k.ctx_addr, r, no_errno);
            SyscallOutcome::Continue
        };
        if flags & ul::WAIT_CANCEL_POINT != 0 && self.darwin_testcancel(true) {
            return done(self, m, Err(Errno::EINTR));
        }
        if flags & ul::WAIT_MASK != flags {
            return done(self, m, Err(Errno::EINVAL));
        }
        let (set_owner, size) = match opcode {
            ul::UNFAIR_LOCK => (true, 4),
            ul::COMPARE_AND_WAIT | ul::COMPARE_AND_WAIT_SHARED => (false, 4),
            ul::COMPARE_AND_WAIT64 | ul::COMPARE_AND_WAIT64_SHARED => (false, 8),
            _ => return done(self, m, Err(Errno::EINVAL)),
        };
        if addr == 0 || addr & (size - 1) != 0 {
            return done(self, m, Err(Errno::EINVAL));
        }
        let ull = self.dtask.ulocks.map.entry(addr).or_default();
        ull.nwaiters += 1;
        if ull.opcode == 0 {
            ull.opcode = opcode;
        } else if ull.opcode != opcode {
            self.darwin_ulock_wait_cleanup(addr);
            return done(self, m, Err(Errno::EDOM));
        }
        let current = if size == 4 { m.read_u32(addr).map(u64::from) } else { m.read_u64(addr) };
        let Ok(current) = current else {
            self.darwin_ulock_wait_cleanup(addr);
            return done(self, m, Err(Errno::EFAULT));
        };
        let want = if size == 4 { value & 0xffff_ffff } else { value };
        if current != want {
            let left = self.darwin_ulock_wait_cleanup(addr);
            return done(self, m, Ok(u64::from(left)));
        }
        if set_owner {
            // The owner's thread port name is the lock word, its low two
            // bits (userland's flags) restored (`ipc_entry_name_mask`). A
            // dead name leaves no owner; anything else that is not another
            // thread's port is EOWNERDEAD.
            let name = (want as u32) | 3;
            let owner = match self.darwin_name_to_thread(name) {
                Some(t) if t != self.tid => Some(t),
                _ if name == u32::MAX => None,
                _ => {
                    self.darwin_ulock_wait_cleanup(addr);
                    return done(self, m, Err(Errno::EOWNERDEAD));
                }
            };
            self.dtask.ulocks.map.get_mut(&addr).expect("made above").owner = owner;
        }
        let deadline = match timeout {
            0 => None,
            t if flags & ul::DEADLINE != 0 => {
                // An absolute deadline, in mach_absolute_time.
                Some(super::mach::abs_to_instant(t))
            }
            t => Some(Instant::now() + Duration::from_nanos(t)),
        };
        self.dtask.ulocks.map.get_mut(&addr).expect("made above").queue.push_back(self.tid);
        self.darwin_block(m, Wait { deadline, cont: Finish::Ulock { addr, no_errno } })
    }

    /// `ulock_wait_cleanup`: this waiter leaves, the lock forgotten with
    /// its last. The waiters left.
    fn darwin_ulock_wait_cleanup(&mut self, addr: u64) -> u32 {
        let Some(ull) = self.dtask.ulocks.map.get_mut(&addr) else { return 0 };
        ull.nwaiters -= 1;
        let left = ull.nwaiters;
        if left == 0 {
            self.dtask.ulocks.map.remove(&addr);
        }
        left
    }

    /// `ulock_wake(operation, addr, wake_value)`.
    fn darwin_ulock_wake(&mut self, m: &mut GuestMem<'_>, op: u64, addr: u64, wake_value: u64) -> Result<(), Errno> {
        let op = op & 0xffff_ffff;
        let opcode = (op & ul::OPCODE_MASK) as u8;
        let flags = op & ul::FLAGS_MASK;
        let set_owner = match opcode {
            ul::UNFAIR_LOCK => true,
            ul::COMPARE_AND_WAIT | ul::COMPARE_AND_WAIT64 | ul::COMPARE_AND_WAIT_SHARED | ul::COMPARE_AND_WAIT64_SHARED => false,
            _ => return Err(Errno::EINVAL),
        };
        if flags & ul::WAKE_MASK != flags {
            return Err(Errno::EINVAL);
        }
        if flags & ul::WAKE_THREAD != 0 && (flags & ul::WAKE_ALL != 0 || set_owner) {
            return Err(Errno::EINVAL);
        }
        let allow_non_owner = flags & ul::WAKE_ALLOW_NON_OWNER != 0;
        if allow_non_owner && !set_owner {
            return Err(Errno::EINVAL);
        }
        if addr == 0 {
            return Err(Errno::EINVAL);
        }
        let wake_thread = if flags & ul::WAKE_THREAD != 0 {
            match self.darwin_name_to_thread(wake_value as u32) {
                Some(t) if t != self.tid => Some(t),
                _ => return Err(Errno::ESRCH),
            }
        } else {
            None
        };
        let me = self.tid;
        let Some(ull) = self.dtask.ulocks.map.get_mut(&addr) else { return Err(Errno::ENOENT) };
        if ull.opcode != opcode {
            return Err(Errno::EDOM);
        }
        if set_owner && ull.owner != Some(me) && !allow_non_owner {
            // A late wake: the kernel already knows the owner, who will
            // wake again.
            return Ok(());
        }
        let woken: Vec<i32> = if let Some(t) = wake_thread {
            match ull.queue.iter().position(|&w| w == t) {
                Some(i) => {
                    ull.queue.remove(i);
                    vec![t]
                }
                None => return Err(Errno::EALREADY),
            }
        } else if flags & ul::WAKE_ALL != 0 {
            ull.queue.drain(..).collect()
        } else {
            ull.queue.pop_front().into_iter().collect()
        };
        if set_owner {
            // Waking all leaves no owner; waking one makes it the owner.
            ull.owner = if flags & ul::WAKE_ALL != 0 { None } else { woken.first().copied() };
        }
        for t in woken {
            self.darwin_wake(m, t, WaitResult::Awakened);
        }
        Ok(())
    }

    /// A blocked thread call's wait has ended: its result, written back.
    pub(crate) fn darwin_thread_wait_done(&mut self, m: &mut GuestMem<'_>, f: Finish, res: WaitResult) -> Option<SyscallOutcome> {
        match f {
            Finish::MachMsg(c) => return <Mach as MachIpc>::wait_done(self, m, c, res),
            Finish::Sema(c) => self.darwin_sema_wait_done(m, c, res),
            Finish::Sleep(s) => self.darwin_sleep_done(m, s, res),
            Finish::WorkqPark => return <Wq as WorkQueue>::wait_done(self, m, res),
            Finish::Kevent(c) => return <Kq as KQueue>::wait_done(self, m, c, res),
            Finish::Lockf(c) => return self.darwin_lockf_wait_done(m, c, res),
            Finish::Exception(p) => return self.darwin_exc_wait_done(m, p, res),
            Finish::Psynch(c) => self.darwin_psynch_wait_done(m, c, res),
            Finish::Sigwait { siglist, sig } => return self.darwin_sigwait_done(m, siglist, sig, res),
            Finish::Ulock { addr, no_errno } => {
                // A waiter that was not woken is still on the queue.
                if res != WaitResult::Awakened {
                    if let Some(ull) = self.dtask.ulocks.map.get_mut(&addr) {
                        ull.queue.retain(|&t| t != self.tid);
                    }
                }
                let left = self.darwin_ulock_wait_cleanup(addr);
                let r = match ulock_errno(res) {
                    None => Ok(u64::from(left)),
                    Some(e) => Err(e),
                };
                bsd_result(m, self.ctx_addr, r, no_errno);
            }
        }
        None
    }
}

impl Kernel {
    /// The calling thread's Darwin state, made on first use.
    pub(crate) fn darwin_me(&mut self) -> &mut DThread {
        self.dtask.threads.map.entry(self.tid).or_default()
    }

    /// A Darwin call begins: not a cancellation point unless it says so.
    pub(crate) fn darwin_syscall_enter(&mut self) {
        super::pipe::set_caller(self.pid);
        self.darwin_me().cancel.notcancelpt = true;
    }

    /// A Darwin call has returned to the program: an abort it did not wait
    /// for is spent, the knotes of descriptors it closed are gone
    /// (`knote_fdclose`), and kevent's ASTs are taken.
    pub(crate) fn darwin_syscall_exit(&mut self, m: &mut GuestMem<'_>) {
        self.darwin_fd_guard_ast();
        let c = &mut self.darwin_me().cancel;
        c.notcancelpt = false;
        c.abort_safely = false;
        self.darwin_knote_fdcheck();
        self.darwin_lock_wakes(m);
        if self.darwin_pipe_knotes() | self.darwin_vnode_knotes() | self.darwin_proc_knotes() {
            self.darwin_kevent_settle(m);
        }
        self.darwin_kevent_ast(m);
    }

    /// The BSD call the thread last made.
    pub(crate) fn darwin_uu_syscall_code(&mut self) -> u64 {
        self.darwin_me().syscall_code
    }

    /// The BSD call the thread is in (`uu_syscall_code`).
    pub(crate) fn darwin_set_syscall_code(&mut self, code: u64) {
        self.darwin_me().syscall_code = code;
    }

    /// `__pthread_testcancel(presyscall)`: this call is a cancellation
    /// point. With a cancel pending, one about to start (`presyscall`)
    /// fails with EINTR (true); one in progress has its next wait aborted.
    pub(crate) fn darwin_testcancel(&mut self, presyscall: bool) -> bool {
        let me = self.tid;
        let c = &mut self.darwin_me().cancel;
        c.notcancelpt = false;
        if c.is_cancelled() {
            if presyscall {
                return true;
            }
            self.darwin_abort_safely(me);
        }
        false
    }

    /// `__pthread_testcancel(0)`, for a call that waits after it.
    pub(crate) fn darwin_testcancel_abort(&mut self) {
        self.darwin_testcancel(false);
    }

    /// `thread_abort_safely`: end `tid`'s abort-safe wait, interrupted; one
    /// not waiting has its next wait in its current or next call end so.
    fn darwin_abort_safely(&mut self, tid: i32) {
        if self.dtask.waits.waiting(tid) {
            return;
        }
        let blocked_in_bsd = self.thread_calls.get(&tid).is_some_and(|c| c.block_pc != 0) || (tid == self.tid && self.block_pc != 0);
        if blocked_in_bsd {
            self.darwin_unimplemented("cancelling a thread blocked in a BSD call".into());
        }
        self.dtask.threads.map.entry(tid).or_default().cancel.abort_safely = true;
    }

    /// `__pthread_markcancel(thread_port)`.
    pub(crate) fn darwin_markcancel(&mut self, m: &mut GuestMem<'_>, port: u32) -> Result<u64, Errno> {
        let Some(tid) = self.darwin_name_to_thread(port) else { return Err(Errno::ESRCH) };
        let c = &mut self.dtask.threads.map.entry(tid).or_default().cancel;
        if !c.cancel && !c.canceled {
            c.cancel = true;
            c.no_sigmask = true;
            if !c.notcancelpt && !c.disable {
                if self.dtask.waits.waiting(tid) {
                    self.darwin_wake(m, tid, WaitResult::Interrupted);
                } else {
                    self.darwin_abort_safely(tid);
                }
            }
        }
        Ok(0)
    }

    /// `__pthread_canceled(action)`: 1 enables cancellation, 2 disables it,
    /// 0 acts on a pending cancel (EINVAL with none).
    pub(crate) fn darwin_canceled(&mut self, action: u64) -> Result<u64, Errno> {
        let c = &mut self.darwin_me().cancel;
        match action as i32 {
            1 => {
                c.disable = false;
                Ok(0)
            }
            2 => {
                c.disable = true;
                Ok(0)
            }
            _ => {
                if c.is_cancelled() {
                    c.cancel = false;
                    c.canceled = true;
                    c.no_sigmask = true;
                    Ok(0)
                } else {
                    Err(Errno::EINVAL)
                }
            }
        }
    }
}
