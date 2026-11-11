//! The kernel's thread calls (`osfmk/kern/thread_call.c`): work the kernel
//! itself does at a deadline (a Mach timer's expiry message, a kevent
//! timer firing), not on behalf of any thread's call.
//!
//! The host runs a thread for the process that sleeps until the earliest
//! deadline, or until one earlier is armed ([`Bell`]), and then fires what
//! is due with the kernel locked ([`Kernel::darwin_thread_calls`]).

use crate::syscalls::Kernel;
use crate::GuestMem;
use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

/// What a thread call does when it fires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// `mk_timer_expire` for the timer whose port this is.
    MkTimer(super::ipc::ObjId),
    /// One of the workqueue's thread calls.
    Workq(super::workq::Call),
    /// An `EVFILT_TIMER` knote's thread call (`filt_timerexpire`), armed
    /// in the timer state given.
    Knote(super::kevent::KnId, u32),
    /// The real interval timer's (`realitexpire`).
    RealTimer,
}

/// How the thread-call thread learns that an earlier deadline was armed, or
/// that the process is gone.
#[derive(Debug, Default)]
pub struct Bell {
    state: Mutex<(u64, bool)>,
    cv: Condvar,
}

impl Bell {
    /// The count of rings so far.
    pub fn generation(&self) -> u64 {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).0
    }

    pub fn ring(&self) {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).0 += 1;
        self.cv.notify_all();
    }

    fn close(&self) {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).1 = true;
        self.cv.notify_all();
    }

    /// Sleep until `until`, or until a ring after `seen`; false once the
    /// process is gone.
    pub fn wait(&self, seen: u64, until: Option<Instant>) -> bool {
        let mut g = self.state.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if g.1 {
                return false;
            }
            if g.0 != seen {
                return true;
            }
            match until {
                None => g = self.cv.wait(g).unwrap_or_else(|e| e.into_inner()),
                Some(t) => {
                    let now = Instant::now();
                    if now >= t {
                        return true;
                    }
                    g = self.cv.wait_timeout(g, t - now).unwrap_or_else(|e| e.into_inner()).0;
                }
            }
        }
    }
}

/// The armed thread calls, by deadline (and a sequence number, so two at
/// the same instant both stay).
#[derive(Debug, Default)]
pub struct Timers {
    armed: BTreeMap<(Instant, u64), Action>,
    next: u64,
    bell: Arc<Bell>,
}

impl Drop for Timers {
    fn drop(&mut self) {
        self.bell.close();
    }
}

impl Timers {
    /// Arm `action` for `at`; the key it can be cancelled by.
    pub fn arm(&mut self, at: Instant, action: Action) -> (Instant, u64) {
        self.next += 1;
        let key = (at, self.next);
        self.armed.insert(key, action);
        if self.armed.keys().next() == Some(&key) {
            self.bell.ring();
        }
        key
    }

    /// Cancel the call armed as `key`; whether it was still armed
    /// (`thread_call_cancel`).
    pub fn cancel(&mut self, key: (Instant, u64)) -> bool {
        self.armed.remove(&key).is_some()
    }

    pub fn bell(&self) -> Arc<Bell> {
        Arc::clone(&self.bell)
    }
}

impl Kernel {
    /// The thread calls that are due, run; when the next one is.
    pub fn darwin_thread_calls(&mut self, m: &mut GuestMem<'_>) -> Option<Instant> {
        // The thread-call thread is runnable while it runs them.
        self.procs.sched.callout(true);
        let out = self.darwin_thread_calls_body(m);
        self.procs.sched.callout(false);
        self.darwin_ipc_leave();
        // What they mapped (a workqueue thread's stack) is in force for
        // every thread now.
        self.darwin_flush_perms(m);
        out
    }

    /// Fire every thread call that is due; the next deadline.
    fn darwin_thread_calls_body(&mut self, m: &mut GuestMem<'_>) -> Option<Instant> {
        // Other tasks' IPC with this one's threads and ports.
        self.darwin_ipc_remote(m);
        // Signals posted, and pipes changed, from outside a call: their
        // knotes are told.
        if self.darwin_signal_knotes() | self.darwin_pipe_knotes() | self.darwin_vnode_knotes() | self.darwin_proc_knotes() {
            self.darwin_kevent_settle(m);
        }
        self.darwin_lock_wakes(m);
        // memorystatus' idle demotion call, which every task's thread calls
        // wake for.
        let jetsam = if self.darwin { self.darwin_jetsam_tick() } else { None };
        let footprint = if self.darwin { self.darwin_footprint_tick(m) } else { None };
        let jetsam = match (jetsam, footprint) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let own = loop {
            let now = Instant::now();
            let Some((&key, _)) = self.dtask.timers.armed.first_key_value() else { break None };
            if key.0 > now {
                break Some(key.0);
            }
            match self.dtask.timers.armed.remove(&key).expect("first key") {
                Action::MkTimer(port) => self.mk_timer_expire(m, port, key),
                Action::Workq(c) => self.darwin_workq_call(m, c),
                Action::RealTimer => self.darwin_realitexpire(),
                Action::Knote(n, state) => {
                    self.filt_timerexpire(n, state);
                    self.darwin_kevent_settle(m);
                }
            }
        };
        match (own, jetsam) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// The bell the host's thread-call thread sleeps on.
    pub fn darwin_timer_bell(&self) -> Arc<Bell> {
        self.dtask.timers.bell()
    }
}
