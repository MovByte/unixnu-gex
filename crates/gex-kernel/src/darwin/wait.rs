//! How a Darwin thread waits in the kernel, as XNU's wait queues do: the
//! thread goes on an object's queue of waiters and sleeps until another
//! thread wakes it with a result, its deadline passes, or a signal
//! interrupts it.
//!
//! Each waiting thread sleeps on a futex word of its own, in a page the
//! kernel keeps for these words. A wakeup stores the thread's result under
//! the kernel lock, then bumps the word and wakes it. The sleeper read the
//! word under the same lock before it slept, so a wakeup between that read
//! and the sleep is not lost: the word no longer holds what it read.

use crate::errno::Errno;
use crate::syscalls::{BlockOp, Kernel, SyscallOutcome};
use crate::GuestMem;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// XNU's `wait_result_t`: why a wait ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitResult {
    /// `THREAD_AWAKENED`: another thread woke this one.
    Awakened,
    /// `THREAD_TIMED_OUT`: the deadline passed.
    TimedOut,
    /// `THREAD_INTERRUPTED`: a signal (or the process ending) ended it.
    Interrupted,
    /// `THREAD_RESTART`: the object waited on went away.
    Restart,
}

/// The size of the page of wait words, and so the most threads that can
/// wait at once.
const PAGE: u64 = 64 * 1024;

/// A thread's wait slot.
#[derive(Clone, Copy, Debug, Default)]
struct Slot {
    word: u64,
    /// Whether the thread is on some object's queue of waiters.
    waiting: bool,
    /// The result a waker left, until the thread takes it.
    result: Option<WaitResult>,
}

/// Every thread's wait slot.
#[derive(Debug, Default)]
pub struct Waits {
    page: u64,
    next: u64,
    free: Vec<u64>,
    slots: HashMap<i32, Slot>,
}

impl Waits {
    /// Whether `tid` is waiting.
    pub fn waiting(&self, tid: i32) -> bool {
        self.slots.get(&tid).is_some_and(|s| s.waiting)
    }

    /// How many threads are in a wait.
    pub fn waiting_count(&self) -> usize {
        self.slots.values().filter(|s| s.waiting).count()
    }

    /// Forget a thread that has ended, its word back to the free list.
    pub fn forget(&mut self, tid: i32) {
        if let Some(s) = self.slots.remove(&tid) {
            self.free.push(s.word);
        }
    }
}

/// A wait, as the call that made it gives it: when it gives up, and what
/// runs when it ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wait {
    pub deadline: Option<Instant>,
    pub cont: super::thread::Finish,
}

impl Kernel {
    /// The word `tid` sleeps on, from the kernel's page (mapped on the
    /// first wait).
    fn darwin_wait_word(&mut self, m: &mut GuestMem<'_>, tid: i32) -> Result<u64, Errno> {
        if let Some(s) = self.dtask.waits.slots.get(&tid) {
            return Ok(s.word);
        }
        let w = &mut self.dtask.waits;
        let word = match w.free.pop() {
            Some(word) => word,
            None => {
                if w.page == 0 {
                    use crate::mem::flags as mf;
                    let at = self.canonical(m, crate::syscalls::nr::MMAP, [0, PAGE, 3, mf::PRIVATE | mf::ANONYMOUS, u64::MAX, 0])?;
                    self.dtask.waits.page = at;
                }
                let w = &mut self.dtask.waits;
                if w.next + 4 > PAGE {
                    return Err(Errno::EAGAIN);
                }
                let word = w.page + w.next;
                w.next += 4;
                word
            }
        };
        self.dtask.waits.slots.insert(tid, Slot { word, ..Default::default() });
        Ok(word)
    }

    /// Put the calling thread to sleep for `wait`. The caller has already
    /// queued the thread on whatever it waits for; `wait.cont` runs when
    /// the wait ends ([`Self::darwin_wait_done`]).
    pub(crate) fn darwin_block(&mut self, m: &mut GuestMem<'_>, wait: Wait) -> SyscallOutcome {
        let tid = self.tid;
        let word = match self.darwin_wait_word(m, tid) {
            Ok(w) => w,
            Err(_) => panic!("gex: Darwin thread {tid}: no wait word left"),
        };
        let slot = self.dtask.waits.slots.get_mut(&tid).expect("slot made above");
        slot.waiting = true;
        slot.result = None;
        // An abort the thread did not wait for ends this wait at once.
        let me = self.dtask.threads.map.entry(tid).or_default();
        if me.cancel.abort_safely {
            me.cancel.abort_safely = false;
            self.dtask.waits.slots.get_mut(&tid).expect("slot made above").waiting = false;
            self.darwin_wait_done(m, wait, WaitResult::Interrupted);
            return SyscallOutcome::Continue;
        }
        self.darwin_sleep(m, word, wait)
    }

    /// Sleep on `word` (again) until `wait`'s deadline or the next timer
    /// the kernel must fire, whichever is first.
    fn darwin_sleep(&mut self, m: &mut GuestMem<'_>, word: u64, wait: Wait) -> SyscallOutcome {
        let val = m.read_u32(word).unwrap_or(0);
        let now = Instant::now();
        let deadline = wait.deadline.map(|t| t.saturating_duration_since(now));
        self.darwin_finish = Some(wait);
        let table = std::sync::Arc::clone(&self.futexes);
        let parked = Some(table.park(word));
        SyscallOutcome::Blocking(BlockOp::FutexWait { table, uaddr: word, val, deadline, parked })
    }

    /// Wake `tid` with `result` if it is waiting; whether it was.
    pub(crate) fn darwin_wake(&mut self, m: &mut GuestMem<'_>, tid: i32, result: WaitResult) -> bool {
        let Some(slot) = self.dtask.waits.slots.get_mut(&tid) else { return false };
        if !slot.waiting {
            return false;
        }
        slot.waiting = false;
        slot.result = Some(result);
        let word = slot.word;
        let v = m.read_u32(word).unwrap_or(0).wrapping_add(1);
        let _ = m.write_u32(word, v);
        self.futexes.wake(word, u32::MAX);
        true
    }

    /// A blocked Darwin wait's end: the result a waker left, or else the
    /// deadline or a signal. A wake with no result (one meant for an earlier
    /// wait of the thread) sleeps again.
    pub(crate) fn darwin_wait_end(&mut self, r: Result<u64, Errno>) -> End {
        let Some(wait) = self.darwin_finish.take() else { return End::NotDarwin };
        let tid = self.tid;
        let slot = self.dtask.waits.slots.get_mut(&tid).expect("a waiting thread has a slot");
        if let Some(res) = slot.result.take() {
            return End::Done(wait, res);
        }
        let own_deadline = wait.deadline.is_some_and(|d| Instant::now() >= d);
        let res = match r {
            Err(e) if e == Errno::EINTR => WaitResult::Interrupted,
            _ if own_deadline => WaitResult::TimedOut,
            _ => {
                self.darwin_finish = Some(wait);
                return End::Again;
            }
        };
        slot.waiting = false;
        End::Done(wait, res)
    }

    /// Run an ended wait's continuation: the blocked call's result.
    pub(crate) fn darwin_wait_done(&mut self, m: &mut GuestMem<'_>, wait: Wait, res: WaitResult) -> Option<SyscallOutcome> {
        self.darwin_thread_wait_done(m, wait.cont, res)
    }

    /// Sleep again for a wait that has not ended ([`End::Again`]).
    pub(crate) fn darwin_sleep_again(&mut self, m: &mut GuestMem<'_>) -> SyscallOutcome {
        let wait = self.darwin_finish.take().expect("a pending wait");
        let word = self.dtask.waits.slots.get(&self.tid).expect("a waiting thread has a slot").word;
        self.darwin_sleep(m, word, wait)
    }
}

/// How a blocked call's wait ended ([`Kernel::darwin_wait_end`]).
pub enum End {
    /// The call was not a Darwin wait.
    NotDarwin,
    /// Nothing ended it: it sleeps again ([`Kernel::darwin_sleep_again`]).
    Again,
    /// It ended, for this reason.
    Done(Wait, WaitResult),
}

/// A relative timeout as a deadline from now.
pub fn deadline_in(d: Duration) -> Instant {
    Instant::now() + d
}
