//! Mach eventlinks (`osfmk/ipc/ipc_eventlink.c`, `bsd/kern/sys_eventlink.c`,
//! xnu-10063.141.1).
//!
//! An eventlink is a pair of ends, each a port (IKOT_EVENTLINK) whose
//! signals the other end counts. A thread associated with an end (or any
//! one, with MELA_OPTION_ASSOCIATE_ON_WAIT) waits there until the count
//! passes the one it gives. The ends may be in different processes: a
//! waiter is woken as an advisory lock's is, its thread on its process's
//! list and its bell rung. The handoff to the woken thread is a scheduling
//! hint with no effect here.

use super::ipc::Kobject;
use super::lockf::Waker;
use super::sysno as sys;
use super::wait::{Wait, WaitResult};
use crate::syscalls::{Kernel, SyscallOutcome};
use crate::GuestMem;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

/// `kern_return_t`s.
pub mod kr {
    pub const SUCCESS: u64 = 0;
    pub const INVALID_ARGUMENT: u64 = 4;
    pub const NAME_EXISTS: u64 = 13;
    pub const ABORTED: u64 = 14;
    pub const INVALID_NAME: u64 = 15;
    pub const INVALID_CAPABILITY: u64 = 20;
    pub const TERMINATED: u64 = 37;
    pub const NOT_WAITING: u64 = 48;
    pub const OPERATION_TIMED_OUT: u64 = 49;
}

/// MELC_OPTION_NO_COPYIN, MELA_OPTION_*, MELD_OPTION_NONE,
/// MELSW_OPTION_NO_WAIT, KERN_CLOCK_MACH_ABSOLUTE_TIME.
const MELC_OPTION_NO_COPYIN: u32 = 0x1;
const MELA_OPTION_NONE: u32 = 0;
const MELA_OPTION_ASSOCIATE_ON_WAIT: u32 = 0x1;
const MELD_OPTION_NONE: u32 = 0;
const MELSW_OPTION_NO_WAIT: u32 = 0x1;
const KERN_CLOCK_MACH_ABSOLUTE_TIME: u32 = 1;

/// `encode_eventlink_count_and_error`.
fn encode(count: u64, error: u64) -> u64 {
    (count & 0x00ff_ffff_ffff_ffff) | ((error & 0xff) << 56)
}

/// A waiter's state: waiting, woken by a signal (THREAD_AWAKENED), woken
/// by a destroy or disassociate (THREAD_RESTART), or gone (its time ran
/// out, or a signal took it out, first).
const WAITING: u8 = 0;
const AWAKENED: u8 = 1;
const RESTART: u8 = 2;
const GONE: u8 = 3;

struct Waiter {
    waker: Waker,
    state: Arc<AtomicU8>,
}

/// `el_thread`: none, THREAD_ASSOCIATE_WILD, or a thread by its id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
enum Assoc {
    #[default]
    None,
    Wild,
    Thread(i32),
}

/// `struct ipc_eventlink`: one end.
struct End {
    thread: Assoc,
    sync_counter: u64,
    wait_counter: u64,
    waiter: Option<Waiter>,
}

impl Default for End {
    fn default() -> End {
        End { thread: Assoc::None, sync_counter: 0, wait_counter: u64::MAX, waiter: None }
    }
}

/// `struct ipc_eventlink_base`.
struct Inner {
    /// Its waitq still valid (`ipc_eventlink_active`).
    active: bool,
    ends: [End; 2],
    ports: [super::ipc::ObjId; 2],
}

pub struct Base {
    inner: Mutex<Inner>,
}

impl Base {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// `ipc_eventlink_signal_internal_locked`: a force wakeup (destroy,
/// disassociate) wakes every waiter with THREAD_RESTART; a signal counts,
/// and wakes the waiter once the count passes the one it waits for.
fn signal_locked(end: &mut End, force: bool) -> u64 {
    if force {
        end.wait_counter = u64::MAX;
        return wake(end, RESTART);
    }
    end.sync_counter += 1;
    if end.sync_counter > end.wait_counter {
        end.wait_counter = u64::MAX;
        return wake(end, AWAKENED);
    }
    kr::NOT_WAITING
}

/// `waitq_wakeup64_*_locked`: the end's waiter, if one is still there.
fn wake(end: &mut End, how: u8) -> u64 {
    match end.waiter.take() {
        Some(w) if w.state.compare_exchange(WAITING, how, Ordering::AcqRel, Ordering::Acquire).is_ok() => {
            w.waker.inbox.lock().unwrap_or_else(|e| e.into_inner()).push(w.waker.tid);
            w.waker.bell.ring();
            kr::SUCCESS
        }
        _ => kr::NOT_WAITING,
    }
}

/// The eventlinks by number, as their ports name them.
fn bases() -> &'static Mutex<HashMap<u64, Arc<Base>>> {
    static BASES: OnceLock<Mutex<HashMap<u64, Arc<Base>>>> = OnceLock::new();
    BASES.get_or_init(Default::default)
}

static NEXT: AtomicU64 = AtomicU64::new(1);

/// A wait in progress: the eventlink, the end, the count it was asked
/// with and the one it found, its deadline and its state.
pub struct Waiting {
    base: Arc<Base>,
    end: usize,
    count: u64,
    old_signal_count: u64,
    deadline: Option<std::time::Instant>,
    state: Arc<AtomicU8>,
}

impl std::fmt::Debug for Waiting {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Waiting").field("end", &self.end).field("count", &self.count).finish()
    }
}

/// An eventlink wait's continuation (its state is in [`Waiting`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cont;

impl Kernel {
    /// `convert_port_to_eventlink_locked`: the eventlink and end a kernel
    /// object is, KERN_TERMINATED once destroyed, KERN_INVALID_CAPABILITY
    /// for another object.
    pub(crate) fn darwin_eventlink_of(obj: &Kobject) -> Result<(Arc<Base>, usize), u64> {
        let Kobject::Eventlink(id, end) = *obj else { return Err(kr::INVALID_CAPABILITY) };
        let base = bases().lock().unwrap_or_else(|e| e.into_inner()).get(&id).cloned().ok_or(kr::TERMINATED)?;
        if !base.lock().active {
            return Err(kr::TERMINATED);
        }
        Ok((base, end as usize))
    }

    /// The same for a port, which must be alive.
    fn darwin_eventlink_of_port(&mut self, port: super::ipc::ObjId) -> Result<(Arc<Base>, usize), u64> {
        let p = self.ipc().port(port);
        match (p.active, p.kobject.clone()) {
            (true, Some(obj)) => Self::darwin_eventlink_of(&obj),
            _ => Err(kr::INVALID_CAPABILITY),
        }
    }

    /// `port_name_to_eventlink`.
    fn darwin_eventlink_of_name(&mut self, name: u32) -> Result<(Arc<Base>, usize), u64> {
        if !super::ipc::name_valid(name) {
            return Err(kr::INVALID_NAME);
        }
        let port = self.ipc().translate_send(name)?;
        self.darwin_eventlink_of_port(port)
    }

    /// `mach_eventlink_create(task, option, &pair)`: the two ends' ports,
    /// each with a send right for the caller and a no-senders request.
    pub(crate) fn darwin_eventlink_create(&mut self, option: u32) -> Result<[super::ipc::ObjId; 2], u64> {
        if option != MELC_OPTION_NO_COPYIN {
            return Err(kr::INVALID_ARGUMENT);
        }
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let mut ports = [0; 2];
        for (i, p) in ports.iter_mut().enumerate() {
            let ipc = &mut self.ipc();
            *p = ipc.kobject_port(Kobject::Eventlink(id, i as u8));
            ipc.make_send(*p);
            ipc.port_mut(*p).nsrequest_kobject = true;
        }
        let base = Arc::new(Base { inner: Mutex::new(Inner { active: true, ends: Default::default(), ports }) });
        bases().lock().unwrap_or_else(|e| e.into_inner()).insert(id, base);
        Ok(ports)
    }

    /// `ipc_eventlink_destroy_internal`: every waiter woken, the end's own
    /// port destroyed and the other's left with no eventlink behind it.
    fn darwin_eventlink_destroy_internal(&mut self, base: &Arc<Base>, end: usize) -> u64 {
        let port = {
            let mut i = base.lock();
            if !i.active {
                return kr::TERMINATED;
            }
            for e in i.ends.iter_mut() {
                if e.thread != Assoc::None {
                    e.thread = Assoc::None;
                    signal_locked(e, true);
                }
            }
            i.active = false;
            i.ports[end]
        };
        bases().lock().unwrap_or_else(|e| e.into_inner()).retain(|_, b| !Arc::ptr_eq(b, base));
        self.ipc().port_destroy(port);
        kr::SUCCESS
    }

    /// `mach_eventlink_destroy(eventlink)`: succeeds for one already
    /// destroyed, and for what is no eventlink.
    pub(crate) fn darwin_eventlink_destroy(&mut self, obj: &Kobject) -> u64 {
        if let Ok((base, end)) = Self::darwin_eventlink_of(obj) {
            self.darwin_eventlink_destroy_internal(&base, end);
        }
        kr::SUCCESS
    }

    /// `ipc_eventlink_no_senders`: the last send right to an end went; the
    /// eventlink is destroyed, or the port alone where it already was.
    pub(crate) fn darwin_eventlink_no_senders(&mut self, port: super::ipc::ObjId) {
        if !self.ipc().port(port).active {
            return;
        }
        match self.darwin_eventlink_of_port(port) {
            Ok((base, end)) => {
                self.darwin_eventlink_destroy_internal(&base, end);
            }
            Err(_) => self.ipc().port_destroy(port),
        }
    }

    /// `mach_eventlink_associate(eventlink, thread, addrs and masks,
    /// option)`: no copyin, a thread or any one on wait, one at a time.
    pub(crate) fn darwin_eventlink_associate(&mut self, obj: &Kobject, thread: Option<i32>, copyin: [u64; 4], option: u32) -> u64 {
        let Ok((base, end)) = Self::darwin_eventlink_of(obj) else { return kr::TERMINATED };
        if copyin != [0; 4] {
            return kr::INVALID_ARGUMENT;
        }
        if (thread.is_none() && option == MELA_OPTION_NONE) || (thread.is_some() && option == MELA_OPTION_ASSOCIATE_ON_WAIT) {
            return kr::INVALID_ARGUMENT;
        }
        let mut i = base.lock();
        if !i.active {
            return kr::TERMINATED;
        }
        let e = &mut i.ends[end];
        if e.thread != Assoc::None {
            return kr::NAME_EXISTS;
        }
        e.thread = match thread {
            Some(t) if option != MELA_OPTION_ASSOCIATE_ON_WAIT => Assoc::Thread(t),
            _ => Assoc::Wild,
        };
        kr::SUCCESS
    }

    /// `mach_eventlink_disassociate(eventlink, option)`: the thread waiting
    /// there, if it is, woken.
    pub(crate) fn darwin_eventlink_disassociate(&mut self, obj: &Kobject, option: u32) -> u64 {
        let Ok((base, end)) = Self::darwin_eventlink_of(obj) else { return kr::TERMINATED };
        if option != MELD_OPTION_NONE {
            return kr::INVALID_ARGUMENT;
        }
        let mut i = base.lock();
        if !i.active {
            return kr::TERMINATED;
        }
        let e = &mut i.ends[end];
        if e.thread == Assoc::None {
            return kr::INVALID_ARGUMENT;
        }
        e.thread = Assoc::None;
        signal_locked(e, true);
        kr::SUCCESS
    }

    /// `mach_eventlink_signal(eventlink_port, signal_count)`: the other end
    /// counts.
    fn darwin_eventlink_signal(&mut self, name: u32) -> u64 {
        let kr = match self.darwin_eventlink_of_name(name) {
            Ok((base, end)) => {
                let mut i = base.lock();
                if !i.active {
                    kr::TERMINATED
                } else {
                    match signal_locked(&mut i.ends[1 - end], false) {
                        kr::NOT_WAITING => kr::SUCCESS,
                        r => r,
                    }
                }
            }
            Err(e) => e,
        };
        encode(0, kr)
    }

    /// `mach_eventlink_wait_until` and `mach_eventlink_signal_wait_until`
    /// (`ipc_eventlink_signal_wait_until_trap_internal`): the other end
    /// signalled first for the second, then a wait unless the count is
    /// already past the one given.
    pub(crate) fn darwin_eventlink_wait(&mut self, m: &mut GuestMem<'_>, raw: u64, a: &[u64; 6]) -> SyscallOutcome {
        let signal = raw == sys::MACH_EVENTLINK_SIGNAL_WAIT_UNTIL;
        // syscalls.master's order: the port, the count, (the signal count,)
        // the deadline, the clock and the option.
        let (name, mut count) = (a[0] as u32, a[1]);
        let (deadline, clock_id, option) = if signal { (a[3], a[4] as u32, a[5] as u32) } else { (a[2], a[3] as u32, a[4] as u32) };
        let done = |k: &mut Kernel, m: &mut GuestMem<'_>, count: u64, r: u64| {
            super::thread::bsd_result(m, k.ctx_addr, Ok(encode(count, r)), false);
            SyscallOutcome::Continue
        };
        if clock_id != KERN_CLOCK_MACH_ABSOLUTE_TIME {
            return done(self, m, count, kr::INVALID_ARGUMENT);
        }
        let (base, end) = match self.darwin_eventlink_of_name(name) {
            Ok(v) => v,
            Err(e) => return done(self, m, count, e),
        };
        let state = Arc::new(AtomicU8::new(WAITING));
        let old_signal_count;
        {
            let mut i = base.lock();
            if !i.active {
                return done(self, m, count, kr::TERMINATED);
            }
            let me = Assoc::Thread(self.tid);
            let e = &mut i.ends[end];
            if e.thread != Assoc::Wild && e.thread != me {
                return done(self, m, count, kr::INVALID_ARGUMENT);
            }
            if e.thread == Assoc::Wild && e.wait_counter != u64::MAX {
                return done(self, m, count, kr::INVALID_ARGUMENT);
            }
            let kr = if count < e.sync_counter {
                count = e.sync_counter;
                Some(kr::SUCCESS)
            } else if option & MELSW_OPTION_NO_WAIT != 0 {
                count = e.sync_counter;
                Some(kr::OPERATION_TIMED_OUT)
            } else {
                e.wait_counter = count;
                e.waiter = Some(Waiter { waker: self.darwin_waker(), state: Arc::clone(&state) });
                None
            };
            old_signal_count = e.sync_counter;
            if signal {
                signal_locked(&mut i.ends[1 - end], false);
            }
            if let Some(r) = kr {
                return done(self, m, count, r);
            }
        }
        let deadline = (deadline != 0).then(|| super::mach::abs_to_instant(deadline));
        self.dtask.eventlink_waits.insert(self.tid, Waiting { base, end, count, old_signal_count, deadline, state });
        self.darwin_block(m, Wait { deadline, cont: super::thread::Finish::Eventlink(Cont) })
    }

    /// A wait's end (`ipc_eventlink_convert_wait_result`): the count one
    /// past the one given when signalled; otherwise the one found, and why.
    pub(crate) fn darwin_eventlink_wait_done(&mut self, m: &mut GuestMem<'_>, res: WaitResult) -> Option<SyscallOutcome> {
        let w = self.dtask.eventlink_waits.remove(&self.tid).expect("an eventlink wait");
        let r = match res {
            WaitResult::Awakened => match w.state.load(Ordering::Acquire) {
                // Woken for something else: still waiting.
                WAITING => {
                    let deadline = w.deadline;
                    self.dtask.eventlink_waits.insert(self.tid, w);
                    return Some(self.darwin_block(m, Wait { deadline, cont: super::thread::Finish::Eventlink(Cont) }));
                }
                AWAKENED => kr::SUCCESS,
                _ => kr::TERMINATED,
            },
            // THREAD_TIMED_OUT and THREAD_INTERRUPTED, unless a wakeup came
            // first; out of the waitq, the wait counter left as it was set.
            _ => match w.state.compare_exchange(WAITING, GONE, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => {
                    let mut i = w.base.lock();
                    if i.ends[w.end].waiter.as_ref().is_some_and(|x| Arc::ptr_eq(&x.state, &w.state)) {
                        i.ends[w.end].waiter = None;
                    }
                    if res == WaitResult::TimedOut {
                        kr::OPERATION_TIMED_OUT
                    } else {
                        kr::ABORTED
                    }
                }
                Err(AWAKENED) => kr::SUCCESS,
                Err(_) => kr::TERMINATED,
            },
        };
        let count = if r == kr::SUCCESS { w.count + 1 } else { w.old_signal_count };
        super::thread::bsd_result(m, self.ctx_addr, Ok(encode(count, r)), false);
        None
    }

    /// The call that answers at once.
    pub(crate) fn darwin_eventlink_call(&mut self, raw: u64, a: &[u64; 6]) -> Option<u64> {
        (raw == sys::MACH_EVENTLINK_SIGNAL).then(|| self.darwin_eventlink_signal(a[0] as u32))
    }
}
