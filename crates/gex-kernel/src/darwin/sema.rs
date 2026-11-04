//! Mach semaphores (`osfmk/kern/sync_sema.c`) and `__semwait_signal`
//! (`bsd/kern/kern_sig.c`), which `nanosleep` and the condition-variable
//! fallbacks sit on.
//!
//! A semaphore's count goes negative, to -1, while threads wait; a signal
//! with waiters hands the wakeup to one of them instead of counting.

use super::ipc::{kr, ObjId};
use super::wait::{Wait, WaitResult};
use crate::errno::Errno;
use crate::syscalls::{Kernel, SyscallOutcome};
use crate::GuestMem;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// `SYNC_POLICY_REVERSED`, `SYNC_POLICY_USER_MASK`.
const SYNC_POLICY_REVERSED: i32 = 0x2;
const SYNC_POLICY_USER_MASK: i32 = 0x2 | 0x4;
const NSEC_PER_SEC: i64 = 1_000_000_000;

/// A semaphore (`struct semaphore`), by its port.
#[derive(Clone, Debug, Default)]
pub struct Sema {
    pub count: i32,
    /// Waiting threads in arrival order.
    pub waiters: VecDeque<i32>,
    /// `owner != TASK_NULL`: destroyed semaphores have none.
    pub active: bool,
    /// LIFO wakeups (`SYNC_POLICY_REVERSED`).
    pub lifo: bool,
}

/// The process's semaphores.
#[derive(Debug, Default)]
pub struct Semas {
    pub map: HashMap<ObjId, Sema>,
}

/// How a semaphore wait finishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cont {
    /// A Mach trap: the `kern_return_t` in x0.
    Trap { sema: ObjId },
    /// `__semwait_signal`: an errno, EINTR for a truncated timeout.
    Semwait { sema: ObjId, truncated: bool },
}

/// `SEMAPHORE_*` signal options.
#[derive(Clone, Copy, Debug, Default)]
struct SignalOpts {
    all: bool,
    prepost: bool,
}

/// `semaphore_convert_wait_result`.
fn wait_kr(r: WaitResult) -> u64 {
    match r {
        WaitResult::Awakened => kr::SUCCESS,
        WaitResult::TimedOut => kr::OPERATION_TIMED_OUT,
        WaitResult::Interrupted => kr::ABORTED,
        WaitResult::Restart => kr::TERMINATED,
    }
}

impl Kernel {
    /// `semaphore_create(task, policy, value)` with its port
    /// (`convert_semaphore_to_port`, no-senders armed): the port.
    pub(crate) fn semaphore_create(&mut self, policy: i32, value: i32) -> Result<ObjId, u64> {
        if value < 0 || policy & !SYNC_POLICY_USER_MASK != 0 {
            return Err(kr::INVALID_ARGUMENT);
        }
        let ipc = &mut self.dtask.ipc;
        let port = ipc.kobject_port(super::ipc::Kobject::Semaphore);
        ipc.port_mut(port).nsrequest_kobject = true;
        ipc.make_send(port);
        self.dtask.semas.map.insert(port, Sema { count: value, waiters: VecDeque::new(), active: true, lifo: policy & SYNC_POLICY_REVERSED != 0 });
        Ok(port)
    }

    /// `semaphore_destroy_internal`: ownerless and empty; waiters wake
    /// with `THREAD_RESTART`.
    fn semaphore_destroy_internal(&mut self, m: Option<&mut GuestMem<'_>>, port: ObjId) {
        let Some(s) = self.dtask.semas.map.get_mut(&port) else { return };
        s.active = false;
        let old = s.count;
        s.count = 0;
        if old < 0 {
            let waiters: Vec<i32> = s.waiters.drain(..).collect();
            for t in waiters {
                self.dtask.sema_wake.push((t, WaitResult::Restart));
            }
        }
        if let Some(m) = m {
            self.semaphore_settle(m);
        }
    }

    /// `semaphore_destroy(task, semaphore)`.
    pub(crate) fn semaphore_destroy(&mut self, port: ObjId) -> u64 {
        match self.dtask.semas.map.get(&port) {
            None => kr::INVALID_ARGUMENT,
            Some(s) => {
                if s.active {
                    self.semaphore_destroy_internal(None, port);
                }
                kr::SUCCESS
            }
        }
    }

    /// `semaphore_no_senders`: the last send right went; the semaphore is
    /// freed, destroyed if it was still owned.
    pub(crate) fn semaphore_no_senders(&mut self, port: ObjId) {
        if self.dtask.semas.map.get(&port).is_some_and(|s| s.active) {
            self.semaphore_destroy_internal(None, port);
        }
        self.dtask.semas.map.remove(&port);
        self.dtask.ipc.port_mut(port).active = false;
        self.dtask.ipc.release(port);
    }

    /// Wake the threads semaphore operations woke.
    fn semaphore_settle(&mut self, m: &mut GuestMem<'_>) {
        for (t, r) in std::mem::take(&mut self.dtask.sema_wake) {
            self.darwin_wake(m, t, r);
        }
    }

    /// `port_name_to_semaphore`.
    fn name_to_semaphore(&mut self, name: u32) -> Result<ObjId, u64> {
        if !super::ipc::name_valid(name) {
            return Err(kr::INVALID_NAME);
        }
        let port = self.dtask.ipc.translate_send(name)?;
        if self.dtask.semas.map.contains_key(&port) {
            Ok(port)
        } else {
            Err(kr::INVALID_CAPABILITY)
        }
    }

    /// `semaphore_signal_internal`: `thread`'s wait only, or one, or all.
    fn semaphore_signal_internal(&mut self, port: ObjId, thread: Option<i32>, o: SignalOpts) -> u64 {
        let s = self.dtask.semas.map.get_mut(&port).expect("a semaphore");
        if !s.active {
            return kr::TERMINATED;
        }
        if let Some(t) = thread {
            if s.count < 0 {
                if let Some(i) = s.waiters.iter().position(|&w| w == t) {
                    s.waiters.remove(i);
                    self.dtask.sema_wake.push((t, WaitResult::Awakened));
                    return kr::SUCCESS;
                }
            }
            return kr::NOT_WAITING;
        }
        if o.all {
            if s.count < 0 {
                s.count = 0;
                let waiters: Vec<i32> = s.waiters.drain(..).collect();
                let any = !waiters.is_empty();
                for t in waiters {
                    self.dtask.sema_wake.push((t, WaitResult::Awakened));
                }
                return if any { kr::SUCCESS } else { kr::NOT_WAITING };
            }
            if o.prepost {
                s.count += 1;
            }
            return kr::SUCCESS;
        }
        if s.count < 0 {
            let w = if s.lifo { s.waiters.pop_back() } else { s.waiters.pop_front() };
            match w {
                Some(t) => {
                    self.dtask.sema_wake.push((t, WaitResult::Awakened));
                    return kr::SUCCESS;
                }
                None => s.count = 0,
            }
        }
        if o.prepost {
            s.count += 1;
        }
        kr::NOT_WAITING
    }

    /// `semaphore_signal_internal_trap`: what `bsdthread_terminate` signals
    /// a joiner with.
    pub(crate) fn darwin_semaphore_signal_name(&mut self, m: &mut GuestMem<'_>, name: u32) -> u64 {
        let r = match self.name_to_semaphore(name) {
            Ok(p) => match self.semaphore_signal_internal(p, None, SignalOpts { all: false, prepost: true }) {
                kr::NOT_WAITING => kr::SUCCESS,
                r => r,
            },
            Err(e) => e,
        };
        self.semaphore_settle(m);
        r
    }

    /// The semaphore traps (`semaphore_*_trap`), `None` for other traps.
    pub(crate) fn darwin_semaphore_trap(&mut self, m: &mut GuestMem<'_>, t: i32, a: &[u64; 6]) -> Option<SyscallOutcome> {
        use super::mach::trap;
        let done = |k: &mut Kernel, m: &mut GuestMem<'_>, r: u64| {
            k.semaphore_settle(m);
            let _ = super::set_mach_result(m, k.ctx_addr, r);
            SyscallOutcome::Continue
        };
        let prepost = SignalOpts { all: false, prepost: true };
        Some(match t {
            trap::SEMAPHORE_SIGNAL | trap::SEMAPHORE_SIGNAL_ALL => {
                let r = match self.name_to_semaphore(a[0] as u32) {
                    Ok(p) => {
                        let o = if t == trap::SEMAPHORE_SIGNAL_ALL { SignalOpts { all: true, prepost: false } } else { prepost };
                        match self.semaphore_signal_internal(p, None, o) {
                            kr::NOT_WAITING => kr::SUCCESS,
                            r => r,
                        }
                    }
                    Err(e) => e,
                };
                done(self, m, r)
            }
            trap::SEMAPHORE_SIGNAL_THREAD => {
                let thread = if a[1] as u32 != 0 {
                    match self.darwin_name_to_thread(a[1] as u32) {
                        Some(t) => Some(t),
                        None => return Some(done(self, m, kr::INVALID_ARGUMENT)),
                    }
                } else {
                    None
                };
                let r = match self.name_to_semaphore(a[0] as u32) {
                    Ok(p) => self.semaphore_signal_internal(p, thread, SignalOpts::default()),
                    Err(e) => e,
                };
                done(self, m, r)
            }
            trap::SEMAPHORE_WAIT => match self.name_to_semaphore(a[0] as u32) {
                Ok(p) => self.semaphore_wait(m, p, None, None, false, Cont::Trap { sema: p }),
                Err(e) => done(self, m, e),
            },
            trap::SEMAPHORE_WAIT_SIGNAL => {
                let sig = match self.name_to_semaphore(a[1] as u32) {
                    Ok(p) => p,
                    Err(e) => return Some(done(self, m, e)),
                };
                match self.name_to_semaphore(a[0] as u32) {
                    Ok(p) => self.semaphore_wait(m, p, Some(sig), None, false, Cont::Trap { sema: p }),
                    Err(e) => done(self, m, e),
                }
            }
            trap::SEMAPHORE_TIMEDWAIT | trap::SEMAPHORE_TIMEDWAIT_SIGNAL => {
                let signal = t == trap::SEMAPHORE_TIMEDWAIT_SIGNAL;
                let (sec, nsec) = if signal { (a[2] as u32, a[3] as i32) } else { (a[1] as u32, a[2] as i32) };
                if !(0..NSEC_PER_SEC as i32).contains(&nsec) {
                    return Some(done(self, m, kr::INVALID_VALUE));
                }
                let sig = if signal {
                    match self.name_to_semaphore(a[1] as u32) {
                        Ok(p) => Some(p),
                        Err(e) => return Some(done(self, m, e)),
                    }
                } else {
                    None
                };
                match self.name_to_semaphore(a[0] as u32) {
                    Ok(p) => {
                        let noblock = sec == 0 && nsec == 0;
                        let deadline = (!noblock).then(|| Instant::now() + Duration::new(u64::from(sec), nsec as u32));
                        self.semaphore_wait(m, p, sig, deadline, noblock, Cont::Trap { sema: p })
                    }
                    Err(e) => done(self, m, e),
                }
            }
            _ => return None,
        })
    }

    /// `semaphore_wait_internal`: take one, or wait for one (signalling
    /// `signal` once queued).
    fn semaphore_wait(&mut self, m: &mut GuestMem<'_>, port: ObjId, signal: Option<ObjId>, deadline: Option<Instant>, noblock: bool, cont: Cont) -> SyscallOutcome {
        let me = self.tid;
        let s = self.dtask.semas.map.get_mut(&port).expect("a semaphore");
        let mut r = None;
        let mut waiting = false;
        if !s.active {
            r = Some(kr::TERMINATED);
        } else if s.count > 0 {
            s.count -= 1;
            r = Some(kr::SUCCESS);
        } else if noblock {
            r = Some(kr::OPERATION_TIMED_OUT);
        } else {
            s.count = -1;
            s.waiters.push_back(me);
            waiting = true;
        }
        if let Some(sig) = signal {
            let sr = self.semaphore_signal_internal(sig, None, SignalOpts { all: false, prepost: true });
            if sr == kr::TERMINATED && waiting {
                // clear_wait(THREAD_INTERRUPTED): KERN_ABORTED, which a
                // dead signal semaphore makes KERN_TERMINATED.
                if let Some(s) = self.dtask.semas.map.get_mut(&port) {
                    s.waiters.retain(|&t| t != me);
                }
                r = Some(kr::TERMINATED);
                waiting = false;
            }
        }
        self.semaphore_settle(m);
        if !waiting {
            let r = r.expect("decided");
            return self.semaphore_finish(m, cont, r);
        }
        self.darwin_block(m, Wait { deadline, cont: super::thread::Finish::Sema(cont) })
    }

    /// A semaphore wait's result written back.
    fn semaphore_finish(&mut self, m: &mut GuestMem<'_>, cont: Cont, r: u64) -> SyscallOutcome {
        match cont {
            Cont::Trap { .. } => {
                let _ = super::set_mach_result(m, self.ctx_addr, r);
            }
            Cont::Semwait { truncated, .. } => {
                // __semwait_signal_nocancel's mapping.
                let e = match r {
                    kr::SUCCESS if !truncated => None,
                    kr::SUCCESS | kr::ABORTED => Some(Errno::EINTR),
                    kr::OPERATION_TIMED_OUT => Some(Errno::ETIMEDOUT),
                    _ => Some(Errno::EINVAL),
                };
                let ret = match e {
                    None => 0,
                    Some(e) => e.as_return(),
                };
                let _ = super::set_result(m, self.ctx_addr, ret);
            }
        }
        SyscallOutcome::Continue
    }

    /// A blocked semaphore wait has ended.
    pub(crate) fn darwin_sema_wait_done(&mut self, m: &mut GuestMem<'_>, cont: Cont, res: WaitResult) {
        let sema = match cont {
            Cont::Trap { sema } | Cont::Semwait { sema, .. } => sema,
        };
        if res != WaitResult::Awakened && res != WaitResult::Restart {
            if let Some(s) = self.dtask.semas.map.get_mut(&sema) {
                s.waiters.retain(|&t| t != self.tid);
            }
        }
        let _ = self.semaphore_finish(m, cont, wait_kr(res));
    }

    /// `__semwait_signal(cond_sem, mutex_sem, timeout, relative, tv_sec,
    /// tv_nsec)` and its `_nocancel` twin.
    pub(crate) fn darwin_semwait_signal(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6], cancel: bool) -> SyscallOutcome {
        if cancel {
            self.darwin_testcancel_abort();
        }
        let (cond, mutex, timeout, relative) = (a[0] as u32, a[1] as u32, a[2] as i32 != 0, a[3] as i32 != 0);
        let (mut sec, mut nsec) = (a[4] as i64, a[5] as i32 as i64);
        let einval = |k: &mut Kernel, m: &mut GuestMem<'_>| {
            let _ = super::set_result(m, k.ctx_addr, Errno::EINVAL.as_return());
            SyscallOutcome::Continue
        };
        let mut truncated = false;
        let mut deadline = None;
        let mut noblock = false;
        if timeout {
            if sec as u64 & 0xffff_ffff_0000_0000 != 0 {
                sec = 0xffff_ffff;
                nsec = 0;
                truncated = true;
            }
            let (then_sec, then_nsec) = if relative {
                (sec as u32 as i64, nsec as i32 as i64)
            } else {
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
                let (ns, nn) = (now.as_secs() as i64, i64::from(now.subsec_nanos()));
                if if ns == sec { nn > nsec } else { ns > sec } {
                    (0, 0)
                } else {
                    let (mut s, mut n) = ((sec - ns) as u32 as i64, nsec - nn);
                    if n < 0 {
                        n += NSEC_PER_SEC;
                        s -= 1;
                    }
                    (s, n)
                }
            };
            if !(0..NSEC_PER_SEC).contains(&then_nsec) {
                return einval(self, m);
            }
            if then_sec == 0 && then_nsec == 0 {
                noblock = true;
            } else {
                deadline = Some(Instant::now() + Duration::new(then_sec as u64, then_nsec as u32));
            }
        }
        let sig = if mutex != 0 {
            match self.name_to_semaphore(mutex) {
                Ok(p) => Some(p),
                Err(_) => return einval(self, m),
            }
        } else {
            None
        };
        match self.name_to_semaphore(cond) {
            Ok(p) => self.semaphore_wait(m, p, sig, deadline, noblock, Cont::Semwait { sema: p, truncated }),
            Err(_) => einval(self, m),
        }
    }
}
