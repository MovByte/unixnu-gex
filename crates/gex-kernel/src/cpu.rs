//! Processor time: what each guest thread has used, read from the host
//! thread that runs it. Its time in the kernel (a call or a trap, from its
//! entry to its return) is its system time and the rest its user time; the
//! host's wait in a blocked call is neither, as a blocked thread runs on no
//! processor.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

/// Guest thread `tid`'s host thread's processor time in nanoseconds, by the
/// host's per-thread clocks (`darwin::workq::set_thread_time`); none
/// without them, or once that thread has gone.
fn host_time(tid: i32) -> Option<u64> {
    crate::darwin::workq::host_thread_ns(tid)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum State {
    /// Not yet run on its host thread.
    #[default]
    Unstarted,
    User,
    Kernel,
    /// In a call that blocked: the host's wait is not the thread's time.
    Blocked,
    /// The host translating the thread's code: the runtime's work, which
    /// the device has no counterpart of.
    Host,
    Ended,
}

#[derive(Debug, Default)]
struct Inner {
    user: u64,
    sys: u64,
    /// The host thread's time when the state last changed.
    last: u64,
    state: State,
    tid: i32,
    /// How deep the host's work on the thread is ([`ThreadCpu::pause`]),
    /// and the state it interrupted.
    paused: u32,
    resumes: State,
}

/// One guest thread's processor time.
#[derive(Debug, Default)]
pub struct ThreadCpu(Arc<Mutex<Inner>>);

/// The threads running on host threads, by tid: what a host thread that
/// ends takes its last sample of ([`host_thread_ending`]).
fn running() -> std::sync::MutexGuard<'static, HashMap<i32, Weak<Mutex<Inner>>>> {
    static R: std::sync::OnceLock<Mutex<HashMap<i32, Weak<Mutex<Inner>>>>> = std::sync::OnceLock::new();
    R.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner())
}

/// Guest thread `tid`'s host thread is ending, however its thread ended (a
/// process killed has no exit call of each thread's): its last stretch,
/// read while the host's clock still knows it.
pub fn host_thread_ending(tid: i32) {
    let Some(inner) = running().remove(&tid).and_then(|w| w.upgrade()) else { return };
    ThreadCpu(inner).end();
}

impl ThreadCpu {
    /// The time since the last change charged to the state it was in, then
    /// the next state. Called on the thread's own host thread.
    fn sample(&self, next: State) {
        let mut i = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let Some(now) = host_time(i.tid) else { return };
        match i.state {
            State::Unstarted => {}
            State::User => i.user += now.saturating_sub(i.last),
            State::Kernel => i.sys += now.saturating_sub(i.last),
            State::Blocked | State::Host | State::Ended => {}
        }
        if i.state != State::Ended {
            i.last = now;
            i.state = next;
        }
    }

    /// Thread `tid` begins to run its program on this host thread.
    pub fn start(&self, tid: i32) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).tid = tid;
        running().insert(tid, Arc::downgrade(&self.0));
        self.sample(State::User);
    }

    /// A call or a trap begins.
    pub fn enter(&self) {
        self.sample(State::Kernel);
    }

    /// The call returns to the program, or it blocked.
    pub fn leave(&self, blocked: bool) {
        self.sample(if blocked { State::Blocked } else { State::User });
    }

    /// Its times so far, taken: it counts again from zero (an exec's new
    /// thread), the times rolled into its task's.
    pub fn rollover(&self) -> Option<(u64, u64)> {
        let t = self.times()?;
        let mut i = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(now) = host_time(i.tid) {
            i.last = now;
        }
        i.user = 0;
        i.sys = 0;
        Some(t)
    }

    /// Another handle on the same thread's time (the host's, for
    /// [`Self::pause`]).
    pub fn handle(&self) -> ThreadCpu {
        ThreadCpu(Arc::clone(&self.0))
    }

    /// The host begins work of its own on the thread (translating its
    /// code): not the thread's time, until [`Self::resume`]. Nests.
    pub fn pause(&self) {
        let state = {
            let mut i = self.0.lock().unwrap_or_else(|e| e.into_inner());
            i.paused += 1;
            if i.paused > 1 {
                return;
            }
            i.state
        };
        if matches!(state, State::User | State::Kernel) {
            self.0.lock().unwrap_or_else(|e| e.into_inner()).resumes = state;
            self.sample(State::Host);
        } else {
            self.0.lock().unwrap_or_else(|e| e.into_inner()).resumes = state;
        }
    }

    /// The host's work on the thread is done: its time counts again, in
    /// the state it was in.
    pub fn resume(&self) {
        let back = {
            let mut i = self.0.lock().unwrap_or_else(|e| e.into_inner());
            if i.paused == 0 {
                return;
            }
            i.paused -= 1;
            if i.paused > 0 || i.state != State::Host {
                return;
            }
            i.resumes
        };
        self.sample(back);
    }

    /// The thread ends; its times are final.
    pub fn end(&self) {
        self.sample(State::Ended);
    }

    /// Its user and system time so far, in nanoseconds: a running thread's
    /// current stretch read from its host thread. None without the host's
    /// clocks.
    pub fn times(&self) -> Option<(u64, u64)> {
        crate::darwin::workq::host_clocks()?;
        let i = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let (mut user, mut sys) = (i.user, i.sys);
        if matches!(i.state, State::User | State::Kernel) {
            if let Some(now) = host_time(i.tid) {
                let d = now.saturating_sub(i.last);
                if i.state == State::User {
                    user += d;
                } else {
                    sys += d;
                }
            }
        }
        Some((user, sys))
    }
}

/// `absolutetime_to_microtime` of a time kept in nanoseconds: its Mach
/// time's whole seconds (`rtclock_sec_divisor`) and the microseconds past
/// them (`rtclock_usec_divisor`).
fn microtime(ns: u64) -> (u64, u32) {
    let (numer, denom) = crate::darwin::mach::TIMEBASE;
    let abs = (u128::from(ns) * u128::from(denom) / u128::from(numer)) as u64;
    let sec_divisor = 1_000_000_000 * u64::from(denom) / u64::from(numer);
    let secs = abs / sec_divisor;
    (secs, ((abs - secs * sec_divisor) / (sec_divisor / 1_000_000)) as u32)
}

/// `time_value_add` (and `timeradd`): seconds and microseconds, carried.
fn tv_add(a: (u64, u32), b: (u64, u32)) -> (u64, u32) {
    let (mut s, mut us) = (a.0 + b.0, a.1 + b.1);
    if us >= 1_000_000 {
        us -= 1_000_000;
        s += 1;
    }
    (s, us)
}

/// `calcru`: a process's user and system time as `timeval`s, from its
/// ended threads' times (`MACH_TASK_BASIC_INFO`'s, converted once) and each
/// live thread's (`TASK_THREAD_TIMES_INFO`'s, converted thread by thread and
/// added), all in nanoseconds.
pub(crate) fn calcru(dead: (u64, u64), live: &[(u64, u64)]) -> [(u64, u32); 2] {
    let (mut user, mut sys) = ((0, 0), (0, 0));
    for &(u, s) in live {
        user = tv_add(user, microtime(u));
        sys = tv_add(sys, microtime(s));
    }
    [tv_add(microtime(dead.0), user), tv_add(microtime(dead.1), sys)]
}

/// Every thread's of `threads` user and system time so far, in
/// nanoseconds; None without the host's clocks.
pub(crate) fn live_times(threads: &crate::signal::ThreadSigs) -> Option<Vec<(u64, u64)>> {
    let mut v = Vec::new();
    for tid in threads.tids() {
        if let Some(t) = threads.get(tid) {
            v.push(t.cpu.times()?);
        }
    }
    Some(v)
}

impl crate::syscalls::Kernel {
    /// This task's user and system time (`calcru`): its threads that have
    /// ended, and each of the others so far. None without the host's
    /// clocks.
    pub(crate) fn task_times(&self) -> Option<(u64, u64)> {
        let (mut user, mut sys) = self.procs.dead_cpu(self.pid);
        for tid in self.thread_signals.tids() {
            if let Some(t) = self.thread_signals.get(tid) {
                let (u, s) = t.cpu.times()?;
                user += u;
                sys += s;
            }
        }
        Some((user, sys))
    }

    /// `getrusage(who, rusage)`: this process's (RUSAGE_SELF, its times
    /// from `calcru`), or its reaped children's (RUSAGE_CHILDREN); EINVAL
    /// for anything else.
    pub(crate) fn darwin_getrusage(&mut self, m: &mut crate::GuestMem<'_>, who: i32, at: u64) -> Result<u64, crate::Errno> {
        const RUSAGE_SELF: i32 = 0;
        const RUSAGE_CHILDREN: i32 = -1;
        let tvs = match who {
            RUSAGE_SELF => match live_times(&self.thread_signals) {
                Some(live) => calcru(self.procs.dead_cpu(self.pid), &live),
                None => {
                    self.darwin_unimplemented("getrusage's times on a host without per-thread clocks".into());
                    return Err(crate::Errno::ENOSYS);
                }
            },
            RUSAGE_CHILDREN => {
                let (user, sys) = self.procs.children_cpu(self.pid);
                [user, sys].map(|ns| (ns / 1_000_000_000, (ns % 1_000_000_000 / 1000) as u32))
            }
            _ => return Err(crate::Errno::EINVAL),
        };
        // struct user64_rusage: the two timevals, then fourteen longs.
        let mut b = [0u8; 144];
        for (i, (secs, usecs)) in tvs.into_iter().enumerate() {
            b[16 * i..16 * i + 8].copy_from_slice(&secs.to_le_bytes());
            b[16 * i + 8..16 * i + 12].copy_from_slice(&usecs.to_le_bytes());
        }
        m.write(at, &b)?;
        Ok(0)
    }

    /// `thread_selfusage()`: the calling thread's user and system time, in
    /// Mach time units (`thread_get_runtime_self`).
    pub(crate) fn darwin_thread_selfusage(&mut self) -> Result<u64, crate::Errno> {
        let Some((u, s)) = self.signals.thread().cpu.times() else {
            self.darwin_unimplemented("thread_selfusage on a host without per-thread clocks".into());
            return Err(crate::Errno::ENOSYS);
        };
        let (numer, denom) = crate::darwin::mach::TIMEBASE;
        Ok((u128::from(u + s) * u128::from(denom) / u128::from(numer)) as u64)
    }
}
