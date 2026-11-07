//! The workqueue (`bsd/pthread/pthread_workqueue.c`, with libpthread's
//! kernel side, `kern_support.c`): the pool of threads that runs a
//! process's dispatch queues.
//!
//! User space asks for threads at a QoS (`workq_kernreturn`'s
//! `WQOPS_QUEUE_REQTHREADS`); the kernel admits requests against the
//! machine's parallelism and the constrained-thread limit, binds idle
//! threads to them, makes new ones when there are none, and starts each at
//! libpthread's `_pthread_wqthread` with the request's flags. A thread done
//! with its work returns (`WQOPS_THREAD_RETURN`) and takes the next request
//! or parks. The scheduler's view of how many threads of each QoS are
//! running (`wq_thactive`) is kept from the moments a workqueue thread
//! blocks in the kernel and wakes again.
//!
//! A new thread is made parked, as `thread_create_workq_waiting` makes it:
//! its host thread is started when it is first woken, and its first act is
//! the kernel's continuation (`workq_unpark_continue`), before any guest
//! code.

use super::ipc::kr;
use super::thread::{pp, qos as tq};
use super::wait::{Wait, WaitResult};
use crate::errno::Errno;
use crate::syscalls::{Kernel, SpawnRequest, SyscallOutcome};
use crate::GuestMem;
use gex_abi::ctx;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Thread QoS classes (`thread_qos_t`).
pub mod qos {
    pub const UNSPECIFIED: u8 = 0;
    pub const MAINTENANCE: u8 = 1;
    pub const BACKGROUND: u8 = 2;
    pub const UTILITY: u8 = 3;
    pub const LEGACY: u8 = 4;
    pub const USER_INITIATED: u8 = 5;
    pub const USER_INTERACTIVE: u8 = 6;
    pub const LAST: u8 = 7;
}

const QOS_MIN: u8 = qos::MAINTENANCE;
const QOS_MAX: u8 = qos::LAST;
const QOS_CLEANUP: u8 = qos::LEGACY;
const QOS_ABOVEUI: u8 = qos::LAST;
pub(crate) const QOS_MANAGER: u8 = qos::LAST + 1;
const NUM_QOS_BUCKETS: usize = (QOS_MAX - 1) as usize;
const NUM_BUCKETS: usize = NUM_QOS_BUCKETS + 1;

/// `_wq_bucket`: maintenance and background share the lowest bucket.
fn bucket(q: u8) -> usize {
    match q {
        qos::MAINTENANCE => 0,
        q => q as usize - 2,
    }
}

/// `wq_thactive`'s layout: a 16-bit count per bucket, the best constrained
/// request's QoS above them.
const THACTIVE_BUCKET_WIDTH: u32 = 16;
const THACTIVE_QOS_SHIFT: u32 = 7 * THACTIVE_BUCKET_WIDTH;
const THACTIVE_BUCKET_MASK: u128 = (1 << THACTIVE_BUCKET_WIDTH) - 1;
const THACTIVE_BUCKET_HALF: u32 = 1 << (THACTIVE_BUCKET_WIDTH - 1);

/// `UT_WORKQ_*`.
mod ut {
    pub const NEW: u16 = 0x01;
    pub const RUNNING: u16 = 0x02;
    pub const DYING: u16 = 0x04;
    pub const OVERCOMMIT: u16 = 0x08;
    pub const OUTSIDE_QOS: u16 = 0x10;
    pub const IDLE_CLEANUP: u16 = 0x20;
    pub const EARLY_BOUND: u16 = 0x40;
    pub const CPUPERCENT: u16 = 0x80;
    pub const COOPERATIVE: u16 = 0x100;
}

/// `WORKQ_TR_FLAG_*` and `WORKQ_TR_STATE_*`.
pub(crate) mod tr {
    pub const KEVENT: u8 = 0x01;
    pub const WORKLOOP: u8 = 0x02;
    pub const OVERCOMMIT: u8 = 0x04;
    pub const WL_PARAMS: u8 = 0x08;
    pub const WL_OUTSIDE_QOS: u8 = 0x10;
    pub const COOPERATIVE: u8 = 0x20;

    pub const IDLE: u8 = 0;
    pub const NEW: u8 = 1;
    pub const QUEUED: u8 = 2;
    pub const CANCELED: u8 = 3;
    /// Preposted for a bind (kevent only).
    pub const BINDING: u8 = 4;
    /// Bound to a thread (kevent only).
    pub const BOUND: u8 = 5;
}

/// `WQ_FLAG_THREAD_*`: the upcall flags `_pthread_wqthread` is given.
pub mod upcall {
    pub const PRIO_QOS: u32 = 0x0000_4000;
    pub const OVERCOMMIT: u32 = 0x0001_0000;
    pub const REUSE: u32 = 0x0002_0000;
    pub const NEWSPI: u32 = 0x0004_0000;
    pub const KEVENT: u32 = 0x0008_0000;
    pub const EVENT_MANAGER: u32 = 0x0010_0000;
    pub const TSD_BASE_SET: u32 = 0x0020_0000;
    pub const WORKLOOP: u32 = 0x0040_0000;
    pub const OUTSIDEQOS: u32 = 0x0080_0000;
    pub const COOPERATIVE: u32 = 0x0100_0000;
}

/// `WQOPS_*`.
mod wqops {
    pub const THREAD_RETURN: u64 = 0x004;
    pub const QUEUE_NEWSPISUPP: u64 = 0x010;
    pub const QUEUE_REQTHREADS: u64 = 0x020;
    pub const QUEUE_REQTHREADS2: u64 = 0x030;
    pub const THREAD_KEVENT_RETURN: u64 = 0x040;
    pub const SET_EVENT_MANAGER_PRIORITY: u64 = 0x080;
    pub const THREAD_WORKLOOP_RETURN: u64 = 0x100;
    pub const SHOULD_NARROW: u64 = 0x200;
    pub const SETUP_DISPATCH: u64 = 0x400;
}

/// `WQ_SETUP_*`.
mod setup {
    pub const NONE: u32 = 0;
    pub const FIRST_USE: u32 = 1;
    pub const CLEAR_VOUCHER: u32 = 2;
    pub const EXIT_THREAD: u32 = 8;
}

/// `wq_flags`.
mod wqf {
    pub const EXITING: u32 = 0x0001;
    pub const PROC_SUSPENDED: u32 = 0x0002;
    pub const DEATH_CALL_SCHEDULED: u32 = 0x0004;
    pub const DELAYED_CALL_SCHEDULED: u32 = 0x0010;
    pub const DELAYED_CALL_PENDED: u32 = 0x0020;
    pub const IMMEDIATE_CALL_SCHEDULED: u32 = 0x0040;
    pub const IMMEDIATE_CALL_PENDED: u32 = 0x0080;
}

/// `workq_kern_threadreq_flags_t`.
pub(crate) mod kflags {
    pub const NONE: u32 = 0;
    pub const SET_AST_ON_FAILURE: u32 = 0x01;
    pub const ATTEMPT_REBIND: u32 = 0x02;
    pub const CAN_CREATE_THREADS: u32 = 0x04;
    pub const MAKE_OVERCOMMIT: u32 = 0x08;
}

/// `TRP_*`: a workloop's thread parameters.
pub(crate) const TRP_PRIORITY: u16 = 0x1;
pub(crate) const TRP_POLICY: u16 = 0x2;
pub(crate) const TRP_CPUPERCENT: u16 = 0x4;

const WORKQUEUE_MAXTHREADS: u32 = 512;
const WORKQUEUE_CONSTRAINED_FACTOR: u32 = 5;
/// `wq_stalled_window`, `wq_reduce_pool_window`, `wq_max_timer_interval`.
const STALLED_WINDOW: Duration = Duration::from_micros(200);
const REDUCE_POOL_WINDOW: Duration = Duration::from_micros(5_000_000);
const MAX_TIMER_INTERVAL: Duration = Duration::from_micros(50_000);

/// `PTH_DEFAULT_STACKSIZE`, `PTHREAD_T_OFFSET` (arm64), `C_WORKQ_STK_ALIGN`.
const PTH_DEFAULT_STACKSIZE: u64 = 512 * 1024;
const PTHREAD_T_OFFSET: u64 = 12 * 1024;
const STK_ALIGN: u64 = 16;
/// `WORKQ_EXIT_THREAD_NKEVENT`.
const EXIT_THREAD_NKEVENT: i32 = -1;
/// `WQ_KEVENT_LIST_LEN`, `WQ_KEVENT_DATA_SIZE`: the events and their data
/// a workqueue thread is started with, on its stack.
const WQ_KEVENT_LIST_LEN: i32 = 16;
const WQ_KEVENT_DATA_SIZE: u64 = 32 * 1024;
/// `VM_MAKE_TAG(VM_MEMORY_STACK)`, `VM_FLAGS_ANYWHERE`.
const VM_TAG_STACK: u64 = 30 << 24;

/// Darwin signals' bits (`sigmask`), for the workqueue's thread masks.
mod dsig {
    const fn m(n: u32) -> u32 {
        1 << (n - 1)
    }
    const ILL: u32 = m(4);
    const TRAP: u32 = m(5);
    const ABRT: u32 = m(6);
    const EMT: u32 = m(7);
    const FPE: u32 = m(8);
    const KILL: u32 = m(9);
    const BUS: u32 = m(10);
    const SEGV: u32 = m(11);
    const SYS: u32 = m(12);
    const PIPE: u32 = m(13);
    const STOP: u32 = m(17);
    const PROF: u32 = m(27);
    const THREADMASK: u32 = ILL | TRAP | ABRT | EMT | FPE | BUS | SEGV | SYS | PIPE | KILL;
    const CANTMASK: u32 = KILL | STOP;
    /// `workq_threadmask`.
    pub const WORKQ_THREADMASK: u32 = (THREADMASK | CANTMASK | PROF) & !ABRT;
}

/// The scheduler's priority for a QoS (`thread_qos_policy_params.qos_pri`).
fn qos_pri(q: u8) -> u8 {
    [0, 4, 4, 20, 31, 37, 46][q as usize]
}

/// `thread_user_promotion_qos_for_pri`.
pub(crate) fn promotion_qos_for_pri(pri: u8) -> u8 {
    let mut q = qos::USER_INTERACTIVE;
    while q > qos::MAINTENANCE {
        if qos_pri(q) <= pri {
            return q;
        }
        q -= 1;
    }
    qos::MAINTENANCE
}

/// `thread_workq_qos_for_pri`.
fn qos_for_pri(pri: u8) -> u8 {
    if pri > qos_pri(qos::USER_INTERACTIVE) {
        return qos::UNSPECIFIED;
    }
    let mut q = qos::USER_INTERACTIVE;
    while q > qos::MAINTENANCE {
        if qos_pri(q - 1) < pri {
            return q;
        }
        q -= 1;
    }
    qos::MAINTENANCE
}

/// `uu_workq_pri`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pri {
    pub qos_req: u8,
    pub qos_max: u8,
    pub qos_override: u8,
    pub qos_bucket: u8,
}

impl Pri {
    fn init(q: u8) -> Pri {
        Pri { qos_req: q, qos_bucket: q, ..Pri::default() }
    }

    /// `workq_pri_bucket`.
    fn bucket(self) -> u8 {
        self.qos_req.max(self.qos_max).max(self.qos_override)
    }

    /// `workq_pri_override`.
    fn override_(self) -> u8 {
        self.bucket().max(self.qos_bucket)
    }
}

/// `uu_save.uus_workq_park_data`.
#[derive(Clone, Copy, Debug, Default)]
pub struct ParkData {
    pub idle_stamp: u64,
    pub fulfilled_snapshot: u32,
    pub yields: u32,
    pub upcall_flags: u32,
    pub has_stack: bool,
    pub qos: u8,
    pub workloop_params: u64,
    pub thread_request: Option<ReqId>,
}

/// A workqueue thread's state (`uu_workq_*`).
#[derive(Clone, Debug, Default)]
pub struct WqThread {
    pub flags: u16,
    pub pri: Pri,
    pub stackaddr: u64,
    /// Its register context.
    pub ctx: u64,
    pub thport: u32,
    pub kill_allowed: bool,
    pub park: ParkData,
    pub kqr_bound: Option<ReqId>,
    /// `uu_kqueue_override`: the QoS a workloop it services overrides it
    /// to.
    pub kqueue_override: u8,
    /// Made parked and not yet run: its host thread starts when woken.
    pub unstarted: Option<SpawnRequest>,
    /// Its next entry is the kernel's (`workq_unpark_continue`).
    pub enter_kernel: bool,
    /// `thread_sched_call(th, workq_sched_callback)`.
    pub sched_call: bool,
    /// When it last started running (`thread_last_run_time`).
    pub last_run: u64,
    /// `thread_set_workq_pri`: the QoS (or priority) and policy the
    /// scheduler runs it at; `thread_set_workq_override`'s override.
    pub sched_qos: u8,
    pub sched_pri: u8,
    pub sched_policy: u8,
    pub sched_override: u8,
    /// `workq_quantum_deadline`, in the thread's own running time, and an
    /// expiry not yet delivered (`AST_KEVENT_WORKQ_QUANTUM_EXPIRED`).
    pub quantum_deadline: u64,
    pub quantum_expired: bool,
    pub quantum_call: Option<(Instant, u64)>,
}

pub type ReqId = u64;

/// A thread request (`struct workq_threadreq_s`).
#[derive(Clone, Copy, Debug, Default)]
pub struct Req {
    pub count: u16,
    pub flags: u8,
    pub state: u8,
    pub qos: u8,
    pub kq_override_index: u8,
    pub kq_qos_index: u8,
    /// `tr_thread` while binding or bound.
    pub thread: Option<i32>,
    /// The kqueue whose request this is (`kqr_kqueue`): the workqueue
    /// kqueue's per-QoS requests and a workloop's one.
    pub kq: Option<u64>,
    /// Its priority in a priority queue, and its arrival.
    pri: u8,
    seq: u64,
}

/// A `priority_queue_sched_max` of requests: the highest priority first,
/// the earliest of equal ones.
#[derive(Debug, Default)]
struct PrioQueue {
    items: Vec<ReqId>,
}

impl PrioQueue {
    fn max(&self, reqs: &HashMap<ReqId, Req>) -> Option<ReqId> {
        self.items.iter().copied().max_by(|a, b| {
            let (ra, rb) = (&reqs[a], &reqs[b]);
            ra.pri.cmp(&rb.pri).then(rb.seq.cmp(&ra.seq))
        })
    }

    /// Whether the new one is now the highest.
    fn insert(&mut self, id: ReqId, reqs: &HashMap<ReqId, Req>) -> bool {
        let before = self.max(reqs);
        self.items.push(id);
        self.max(reqs) != before
    }

    /// Whether the removed one was the highest.
    fn remove(&mut self, id: ReqId, reqs: &HashMap<ReqId, Req>) -> bool {
        let was = self.max(reqs) == Some(id);
        self.items.retain(|&x| x != id);
        was
    }
}

/// Who the workqueue's turnstile pushes on (`wq_inheritor`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Inheritor {
    #[default]
    Null,
    Workq,
    Thread(i32),
}

/// A process's workqueue (`struct workqueue`).
#[derive(Debug, Default)]
pub struct Workq {
    flags: u32,
    fulfilled: u32,
    creations: u32,
    timer_interval: u64,
    thread_call_last_run: u64,
    pub event_manager_priority: u32,
    reqcount: u32,
    thdying_count: u16,
    threads_scheduled: u16,
    constrained_threads_scheduled: u16,
    nthreads: u16,
    thidlecount: u16,
    thscheduled_count: [u16; NUM_BUCKETS],
    event_manager_threadreq: Option<ReqId>,
    thactive: u128,
    lastblocked_ts: [u64; NUM_QOS_BUCKETS],
    creator: Option<i32>,
    inheritor: Inheritor,
    thrunlist: VecDeque<i32>,
    thnewlist: VecDeque<i32>,
    thidlelist: VecDeque<i32>,
    overcommit_queue: PrioQueue,
    constrained_queue: PrioQueue,
    special_queue: PrioQueue,
    coop_scheduled: [u8; NUM_QOS_BUCKETS],
    coop_best_req_qos: u8,
    coop_limited: bool,
    coop_queue: [VecDeque<ReqId>; NUM_QOS_BUCKETS],
    /// Enqueue order, for requests of equal priority.
    next_seq: u64,
    /// The thread whose context new threads are made from (the one that
    /// opened the workqueue).
    template_ctx: u64,
    delayed_call: Option<(Instant, u64)>,
    immediate_call: Option<(Instant, u64)>,
    death_call: Option<(Instant, u64)>,
}

/// The system's workqueue limits (`workq_open`'s first-use setup), from the
/// machine: 3 CPUs, `CONFIG_THREAD_MAX` 1536.
struct Limits {
    max_threads: u32,
    max_constrained: u32,
    death_max_load: u16,
    max_parallelism: u32,
    max_cooperative: u32,
}

fn limits() -> Limits {
    let ncpus = super::mig::machine::NCPUS;
    let max_threads = WORKQUEUE_MAXTHREADS.min(THACTIVE_BUCKET_HALF).min(super::mig::machine::CONFIG_THREAD_MAX - 20);
    Limits {
        max_threads,
        max_constrained: (WORKQUEUE_MAXTHREADS / 8).max(ncpus * WORKQUEUE_CONSTRAINED_FACTOR),
        // fls(num_cpus) + 1
        death_max_load: (32 - ncpus.leading_zeros()) as u16 + 1,
        // qos_max_parallelism(qos, QOS_PARALLELISM_COUNT_LOGICAL): the
        // clutch scheduler answers host_info's logical CPU count.
        max_parallelism: ncpus,
        max_cooperative: ncpus,
    }
}

/// A duration in absolute time (`clock_interval_to_absolutetime_interval`).
pub(crate) fn abs_time(d: Duration) -> u64 {
    abs(d)
}

fn abs(d: Duration) -> u64 {
    (d.as_nanos() * u128::from(super::mach::TIMEBASE.1) / u128::from(super::mach::TIMEBASE.0)) as u64
}

/// The thread calls the workqueue arms (`wq_delayed_call`,
/// `wq_immediate_call`, `wq_death_call`), and a thread's quantum check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Call {
    Delayed,
    Immediate,
    Death,
    Quantum(i32),
}

impl Kernel {
    fn wq(&mut self) -> &mut Workq {
        self.dtask.workq.as_mut().expect("an open workqueue")
    }

    /// The workqueue and every thread request, borrowed together.
    fn wq_and_reqs(&mut self) -> (&mut Workq, &mut HashMap<ReqId, Req>) {
        let d = &mut self.dtask;
        (d.workq.as_mut().expect("an open workqueue"), &mut d.threadreqs)
    }

    /// A new thread request.
    fn threadreq_alloc(&mut self, r: Req) -> ReqId {
        self.dtask.next_threadreq += 1;
        let id = self.dtask.next_threadreq;
        self.dtask.threadreqs.insert(id, r);
        id
    }

    fn wqt(&mut self, tid: i32) -> &mut WqThread {
        self.dtask.threads.map.get_mut(&tid).and_then(|t| t.wq.as_mut()).expect("a workqueue thread")
    }

    fn wq_exiting(&mut self) -> bool {
        self.wq().flags & wqf::EXITING != 0
    }

    /// Whether `tid` is a workqueue thread (`THREAD_TAG_WORKQUEUE`).
    pub(crate) fn darwin_is_wq_thread(&self, tid: i32) -> bool {
        self.dtask.threads.map.get(&tid).is_some_and(|t| t.wq.is_some())
    }

    // -- wq_thactive --------------------------------------------------------

    fn thactive_offset(q: u8) -> u128 {
        1u128 << (bucket(q) as u32 * THACTIVE_BUCKET_WIDTH)
    }

    fn thactive_inc(&mut self, q: u8) -> u128 {
        let wq = self.wq();
        let old = wq.thactive;
        wq.thactive = old.wrapping_add(Self::thactive_offset(q));
        old
    }

    fn thactive_dec(&mut self, q: u8) -> u128 {
        let wq = self.wq();
        let old = wq.thactive;
        wq.thactive = old.wrapping_sub(Self::thactive_offset(q));
        old
    }

    fn thactive_move(&mut self, old: u8, new: u8) {
        let wq = self.wq();
        wq.thactive = wq.thactive.wrapping_add(Self::thactive_offset(new)).wrapping_sub(Self::thactive_offset(old));
        wq.thscheduled_count[bucket(old)] -= 1;
        wq.thscheduled_count[bucket(new)] += 1;
    }

    fn best_constrained_req_qos(v: u128) -> u8 {
        (v >> THACTIVE_QOS_SHIFT) as u8
    }

    fn thactive_refresh_best_constrained_req_qos(&mut self) {
        let (wq, reqs) = self.wq_and_reqs();
        let new = wq.constrained_queue.max(reqs).map_or(qos::UNSPECIFIED, |r| reqs[&r].qos);
        let old = Self::best_constrained_req_qos(wq.thactive);
        if old != new {
            let base = wq.thactive & !(0xffu128 << THACTIVE_QOS_SHIFT);
            wq.thactive = base | (u128::from(new) << THACTIVE_QOS_SHIFT);
        }
    }

    /// `_wq_thactive_aggregate_downto_qos`: the threads active at `q` and
    /// above, and how many of those buckets are busy.
    fn thactive_aggregate_downto(&mut self, v: u128, q: u8, want_busy: bool) -> (u32, u32, u32) {
        let now = super::mach::absolute_time();
        let wq = self.wq();
        let (mut count, mut busy) = (0u32, 0u32);
        let max_busy = u32::from(qos::LAST - q);
        let mut i = bucket(q);
        let mut v = v >> (i as u32 * THACTIVE_BUCKET_WIDTH);
        while i < NUM_QOS_BUCKETS {
            let active = (v & THACTIVE_BUCKET_MASK) as u32;
            count += active;
            if want_busy && u32::from(wq.thscheduled_count[i]) > active && workq_thread_is_busy(now, wq.lastblocked_ts[i]) {
                busy += 1;
            }
            i += 1;
            v >>= THACTIVE_BUCKET_WIDTH;
        }
        (count, busy, max_busy)
    }

    // -- thread priorities ----------------------------------------------------

    /// `workq_thread_update_bucket`.
    fn workq_thread_update_bucket(&mut self, tid: i32, old: Pri, mut new: Pri, force_run: bool) {
        let (old_bucket, new_bucket) = (old.qos_bucket, new.bucket());
        if old_bucket != new_bucket {
            self.thactive_move(old_bucket, new_bucket);
        }
        new.qos_bucket = new_bucket;
        let t = self.wqt(tid);
        t.pri = new;
        if old.qos_override != new.qos_override {
            t.sched_override = new.qos_override;
        }
        if self.wq().reqcount != 0 && (old_bucket > new_bucket || force_run) {
            let flags = if old_bucket > new_bucket { kflags::NONE } else { kflags::CAN_CREATE_THREADS };
            self.workq_schedule_creator(flags);
        }
    }

    /// `workq_thread_reset_cpupercent`: CPU limits come only with workloop
    /// parameters.
    fn workq_thread_reset_cpupercent(&mut self, req: Option<ReqId>, tid: i32) {
        let trp = match req {
            Some(r) if self.req(r).flags & tr::WL_PARAMS != 0 => self.workloop_param(r),
            _ => 0,
        };
        let t = self.wqt(tid);
        if t.flags & ut::CPUPERCENT != 0 {
            t.flags &= !ut::CPUPERCENT;
        }
        if trp as u16 & TRP_CPUPERCENT != 0 {
            self.darwin_unimplemented("a workloop's CPU percent limit".into());
        }
    }

    /// `workq_thread_reset_pri`.
    fn workq_thread_reset_pri(&mut self, tid: i32, req: Option<ReqId>, unpark: bool) {
        let mut q = req.map_or(QOS_CLEANUP, |r| self.dtask.threadreqs[&r].qos);
        let trp = match req {
            Some(r) if self.req(r).flags & tr::WL_PARAMS != 0 => self.workloop_param(r),
            _ => 0,
        };
        let (trp_flags, trp_pri, trp_pol) = (trp as u16, (trp >> 16) as u8, (trp >> 24) as u8);
        let mut priority = 31u8;
        let mut policy = 1u8;
        let mgr_pri = self.wq().event_manager_priority;
        let t = self.wqt(tid);
        t.pri = Pri::init(q);
        t.flags &= !ut::OUTSIDE_QOS;
        if unpark {
            t.park.workloop_params = trp;
            t.park.qos = q;
        }
        if q == QOS_MANAGER {
            if u64::from(mgr_pri) & pp::SCHED_PRI_FLAG != 0 {
                self.thread_set_workq_pri(tid, qos::UNSPECIFIED, (u64::from(mgr_pri) & pp::SCHED_PRI_MASK) as u8, 1);
                return;
            }
            q = pp::qos(u64::from(mgr_pri));
        } else {
            if trp_flags & TRP_PRIORITY != 0 {
                q = qos::UNSPECIFIED;
                priority = trp_pri;
                self.wqt(tid).flags |= ut::OUTSIDE_QOS;
            }
            if trp_flags & TRP_POLICY != 0 {
                policy = trp_pol;
            }
        }
        self.thread_set_workq_pri(tid, q, priority, policy);
    }

    /// `thread_set_workq_pri`: the thread's requested QoS (relative
    /// priority 0) and base priority and policy, its workqueue override
    /// cleared.
    fn thread_set_workq_pri(&mut self, tid: i32, q: u8, priority: u8, policy: u8) {
        let t = self.wqt(tid);
        t.sched_qos = q;
        t.sched_pri = priority;
        t.sched_policy = policy;
        t.sched_override = qos::UNSPECIFIED;
        let p = &mut self.dtask.threads.map.entry(tid).or_default().policy;
        p.qos = q;
        p.relpri = 0;
    }

    /// `thread_get_requested_qos`.
    pub(crate) fn darwin_thread_requested_qos(&self, tid: i32) -> (u8, i32) {
        self.dtask.threads.map.get(&tid).map_or((qos::UNSPECIFIED, 0), |t| (t.policy.qos, t.policy.relpri))
    }

    /// A thread's base priority (`thread_recompute_priority`): from its
    /// effective QoS (its requested QoS and overrides under its task's
    /// clamp and ceiling), else a workqueue thread's set priority, else its
    /// precedence importance on the task's priority; within the task's
    /// range.
    pub(crate) fn darwin_thread_base_pri(&self, tid: i32) -> u8 {
        use super::taskpolicy::{pri, thread_base_priority, thread_effective_qos};
        let tp = &self.darwin_policy();
        let Some(t) = self.dtask.threads.map.get(&tid) else { return tp.priority as u8 };
        // TH_MODE_REALTIME.
        if let Some(rt) = t.realtime {
            return (super::threadpolicy::BASEPRI_RTQUEUES + i32::from(rt.priority_offset)) as u8;
        }
        let overrides = t.overrides.iter().map(|o| o.qos).max().unwrap_or(qos::UNSPECIFIED);
        let (q, relpri, urgent, terminated) = thread_effective_qos(t.policy.qos, t.policy.relpri, overrides, t.policy.int_darwinbg || t.policy.ext_darwinbg, &tp.effective);
        if q == qos::UNSPECIFIED {
            if let Some(w) = &t.wq {
                return (i32::from(w.sched_pri)).min(tp.max_priority).max(pri::MAXPRI_THROTTLE) as u8;
            }
        }
        thread_base_priority(q, relpri, urgent, terminated, t.policy.importance.unwrap_or(0), tp) as u8
    }

    // -- idle threads -----------------------------------------------------------

    fn workq_oldest_killable_idle_thread(&mut self) -> Option<i32> {
        let last = *self.wq().thidlelist.back()?;
        if !self.wqt(last).park.has_stack {
            let n = self.wq().thidlelist.len();
            return if n >= 2 { Some(self.wq().thidlelist[n - 2]) } else { None };
        }
        Some(last)
    }

    fn workq_kill_delay_for_idle_thread(&mut self) -> u64 {
        let l = limits();
        let delay = abs(REDUCE_POOL_WINDOW);
        let idle = self.wq().thidlecount;
        if idle <= l.death_max_load {
            return delay;
        }
        let mut delay = delay;
        let over = u32::from(idle - l.death_max_load);
        if l.max_constrained > over {
            delay *= u64::from(l.max_constrained - over);
        }
        delay / u64::from(l.max_constrained)
    }

    fn workq_death_call_schedule(&mut self, deadline: u64) {
        let wq = self.wq();
        if wq.flags & (wqf::EXITING | wqf::DEATH_CALL_SCHEDULED) != 0 {
            return;
        }
        wq.flags |= wqf::DEATH_CALL_SCHEDULED;
        // The leeway lets the call run later, not sooner.
        let key = self.dtask.timers.arm(super::mach::abs_to_instant(deadline), super::timer::Action::Workq(Call::Death));
        self.wq().death_call = Some(key);
    }

    /// `workq_death_policy_evaluate`.
    fn workq_death_policy_evaluate(&mut self, decrement: u16) {
        let wq = self.wq();
        wq.thdying_count -= decrement;
        if wq.thdying_count > 0 || wq.thidlecount <= 1 {
            return;
        }
        let Some(tid) = self.workq_oldest_killable_idle_thread() else { return };
        let now = super::mach::absolute_time();
        let delay = self.workq_kill_delay_for_idle_thread();
        let stamp = self.wqt(tid).park.idle_stamp;
        if now.wrapping_sub(stamp) > delay {
            self.wq().thdying_count += 1;
            let t = self.wqt(tid);
            t.flags |= ut::DYING;
            if t.flags & ut::IDLE_CLEANUP == 0 {
                self.workq_thread_wakeup(tid);
            }
            return;
        }
        self.workq_death_call_schedule(stamp + delay);
    }

    /// `workq_thread_terminate`: a workqueue thread ends.
    pub(crate) fn darwin_workq_thread_terminate(&mut self, tid: i32) {
        if self.dtask.workq.is_none() || !self.darwin_is_wq_thread(tid) {
            return;
        }
        self.wq().thrunlist.retain(|&t| t != tid);
        if self.wqt(tid).flags & ut::DYING != 0 {
            self.workq_death_policy_evaluate(1);
        }
        let max = limits().max_threads as u16;
        let wq = self.wq();
        let was = wq.nthreads;
        wq.nthreads -= 1;
        if was == max && wq.reqcount != 0 {
            self.workq_schedule_creator(kflags::CAN_CREATE_THREADS);
        }
        if let Some(key) = self.wqt(tid).quantum_call.take() {
            self.dtask.timers.cancel(key);
        }
    }

    fn workq_kill_old_threads_call(&mut self) {
        self.wq().flags &= !wqf::DEATH_CALL_SCHEDULED;
        self.wq().death_call = None;
        self.workq_death_policy_evaluate(0);
    }

    /// `workq_pop_idle_thread`; whether it needs waking.
    fn workq_pop_idle_thread(&mut self, uu_flags: u16) -> (i32, bool) {
        let wq = self.wq();
        let tid = match wq.thidlelist.pop_front() {
            Some(t) => t,
            None => wq.thnewlist.pop_front().expect("an idle thread"),
        };
        wq.thrunlist.push_back(tid);
        if uu_flags & ut::OVERCOMMIT == 0 {
            wq.constrained_threads_scheduled += 1;
        }
        wq.threads_scheduled += 1;
        wq.thidlecount -= 1;
        let t = self.wqt(tid);
        t.flags |= ut::RUNNING | uu_flags;
        if t.flags & ut::DYING != 0 {
            t.flags ^= ut::DYING;
            self.workq_death_policy_evaluate(1);
            (tid, false)
        } else if t.flags & ut::IDLE_CLEANUP != 0 {
            (tid, false)
        } else {
            (tid, true)
        }
    }

    /// `workq_add_new_idle_thread`: a stack and a thread, made parked.
    fn workq_add_new_idle_thread(&mut self, m: &mut GuestMem<'_>) -> bool {
        self.wq().nthreads += 1;
        let stack = match self.workq_create_threadstack(m) {
            Ok(s) => s,
            Err(_) => {
                self.wq().nthreads -= 1;
                return false;
            }
        };
        let parent = self.wq().template_ctx;
        let req = match self.darwin_clone_from(m, parent) {
            Ok(r) => r,
            Err(_) => {
                let size = self.workq_thread_allocsize();
                self.darwin_vm_deallocate(m, stack, size);
                self.wq().nthreads -= 1;
                return false;
            }
        };
        let tid = req.tid;
        // workq_thread_init_and_wq_lock and uthread_init: no inherited
        // signal mask.
        if let Some(sig) = self.thread_signals.get(tid) {
            sig.set_blocked(super::kern::mask_to_linux(!dsig::WORKQ_THREADMASK));
        }
        let t = WqThread { flags: ut::NEW, pri: Pri::init(qos::LEGACY), stackaddr: stack, ctx: req.ctx_addr, unstarted: Some(req), enter_kernel: true, sched_qos: qos::LEGACY, ..WqThread::default() };
        self.dtask.threads.map.entry(tid).or_default().wq = Some(Box::new(t));
        let wq = self.wq();
        wq.creations += 1;
        wq.thidlecount += 1;
        wq.thnewlist.push_back(tid);
        true
    }

    /// `workq_thread_allocsize`.
    fn workq_thread_allocsize(&self) -> u64 {
        let page = super::mach::PAGE_MASK + 1;
        let pthsize = (self.dtask.pthread.pthsize + PTHREAD_T_OFFSET + page - 1) & !(page - 1);
        page + PTH_DEFAULT_STACKSIZE + pthsize
    }

    /// `workq_create_threadstack`: guard page, stack and `pthread_t`, from
    /// the stack hint up.
    fn workq_create_threadstack(&mut self, m: &mut GuestMem<'_>) -> Result<u64, u64> {
        let size = self.workq_thread_allocsize();
        let guard = super::mach::PAGE_MASK + 1;
        let mut addr = self.dtask.pthread.stack_addr_hint;
        let r = self.darwin_vm_map_anon(m, &mut addr, size, super::mach::PAGE_MASK, VM_TAG_STACK | 1);
        if r != kr::SUCCESS {
            return Err(r);
        }
        let r = self.vm_protect(m, addr, guard, false, 0);
        if r != kr::SUCCESS {
            self.darwin_vm_deallocate(m, addr, size);
            return Err(r);
        }
        Ok(addr)
    }

    fn workq_thread_is_overcommit(&mut self, tid: i32) -> bool {
        self.wqt(tid).flags & ut::OVERCOMMIT != 0
    }

    fn workq_thread_is_nonovercommit(&mut self, tid: i32) -> bool {
        self.wqt(tid).flags & (ut::OVERCOMMIT | ut::COOPERATIVE) == 0
    }

    fn workq_thread_is_cooperative(&mut self, tid: i32) -> bool {
        self.wqt(tid).flags & ut::COOPERATIVE != 0
    }

    fn workq_thread_set_type(&mut self, tid: i32, flags: u16) {
        let t = self.wqt(tid);
        t.flags &= !(ut::OVERCOMMIT | ut::COOPERATIVE);
        t.flags |= flags;
    }

    /// `workq_unpark_for_death_and_unlock`: the thread goes back to user
    /// space told to exit (`WQ_SETUP_EXIT_THREAD`).
    fn workq_unpark_for_death(&mut self, m: &mut GuestMem<'_>, tid: i32, was_idle: bool, setup_flags: u32) -> SyscallOutcome {
        let mut q = self.wqt(tid).pri.override_();
        let first_use = self.wqt(tid).flags & ut::NEW != 0;
        if q > QOS_CLEANUP {
            self.workq_thread_reset_pri(tid, None, true);
            q = QOS_CLEANUP;
        }
        self.workq_thread_reset_cpupercent(None, tid);
        if was_idle {
            let wq = self.wq();
            wq.thidlecount -= 1;
            if first_use {
                wq.thnewlist.retain(|&t| t != tid);
            } else {
                wq.thidlelist.retain(|&t| t != tid);
            }
        }
        self.wq().thrunlist.push_back(tid);
        let mut flags = upcall::NEWSPI | u32::from(q) | upcall::PRIO_QOS;
        if !first_use {
            flags |= upcall::REUSE;
        }
        let (stack, port) = (self.wqt(tid).stackaddr, self.wqt(tid).thport);
        let _ = setup_flags;
        self.workq_setup_thread(m, tid, stack, port, setup::EXIT_THREAD, flags)
    }

    fn workq_turnstile_update_inheritor(&mut self, inheritor: Inheritor) {
        // The turnstile's push is priority inheritance, which the host's
        // scheduler does not take; who it would push on is kept.
        self.wq().inheritor = inheritor;
    }

    /// `workq_push_idle_thread`; `Some` when the thread goes to die instead.
    fn workq_push_idle_thread(&mut self, m: &mut GuestMem<'_>, tid: i32, setup_flags: u32) -> Option<SyscallOutcome> {
        let now = super::mach::absolute_time();
        let is_creator = self.wq().creator == Some(tid);
        if self.workq_thread_is_cooperative(tid) {
            let q = self.wqt(tid).pri.qos_req;
            self.wq().coop_scheduled[bucket(q)] -= 1;
        } else if self.workq_thread_is_nonovercommit(tid) {
            self.wq().constrained_threads_scheduled -= 1;
        }
        let t = self.wqt(tid);
        t.flags &= !(ut::RUNNING | ut::OVERCOMMIT | ut::COOPERATIVE);
        let wq = self.wq();
        wq.thrunlist.retain(|&t| t != tid);
        wq.threads_scheduled -= 1;
        if is_creator {
            wq.creator = None;
        }
        if wq.inheritor == Inheritor::Thread(tid) {
            let next = if wq.reqcount != 0 { Inheritor::Workq } else { Inheritor::Null };
            self.workq_turnstile_update_inheritor(next);
        }
        if self.wqt(tid).flags & ut::NEW != 0 {
            let wq = self.wq();
            wq.thnewlist.push_back(tid);
            wq.thidlecount += 1;
            return None;
        }
        if !is_creator {
            let b = self.wqt(tid).pri.qos_bucket;
            self.thactive_dec(b);
            self.wq().thscheduled_count[bucket(b)] -= 1;
            self.wqt(tid).flags |= ut::IDLE_CLEANUP;
        }
        self.wqt(tid).park.idle_stamp = now;
        let oldest = self.workq_oldest_killable_idle_thread();
        let cur_idle = self.wq().thidlecount;
        let l = limits();
        let kill_oldest = self.wq().thdying_count == 0
            && oldest.is_some_and(|o| {
                let stamp = self.wqt(o).park.idle_stamp;
                now.wrapping_sub(stamp) > self.workq_kill_delay_for_idle_thread()
            });
        if u32::from(cur_idle) >= l.max_constrained || kill_oldest {
            if let Some(o) = oldest {
                self.wqt(o).park.idle_stamp = now;
                let wq = self.wq();
                wq.thidlelist.retain(|&t| t != o);
                wq.thidlelist.push_front(o);
            }
            self.wq().thdying_count += 1;
            let t = self.wqt(tid);
            t.flags |= ut::DYING;
            t.flags &= !ut::IDLE_CLEANUP;
            return Some(self.workq_unpark_for_death(m, tid, false, setup_flags));
        }
        let tail = self.wq().thidlelist.back().copied();
        let cur_idle = cur_idle + 1;
        self.wq().thidlecount = cur_idle;
        if cur_idle >= l.death_max_load && tail.is_some_and(|t| self.wqt(t).park.has_stack) {
            self.wqt(tid).park.has_stack = false;
            self.wq().thidlelist.push_back(tid);
        } else {
            self.wqt(tid).park.has_stack = true;
            self.wq().thidlelist.push_front(tid);
        }
        if tail.is_none() {
            let delay = self.workq_kill_delay_for_idle_thread();
            self.workq_death_call_schedule(now + delay);
        }
        None
    }

    // -- thread requests ---------------------------------------------------------

    fn req(&mut self, id: ReqId) -> &mut Req {
        self.dtask.threadreqs.get_mut(&id).expect("a thread request")
    }

    fn tr_is_overcommit(f: u8) -> bool {
        f & tr::OVERCOMMIT != 0
    }

    fn tr_is_nonovercommit(f: u8) -> bool {
        f & (tr::OVERCOMMIT | tr::COOPERATIVE) == 0
    }

    fn tr_is_cooperative(f: u8) -> bool {
        f & tr::COOPERATIVE != 0
    }

    /// `workq_priority_for_req`.
    fn workq_priority_for_req(&mut self, id: ReqId) -> u8 {
        let r = *self.req(id);
        if r.flags & tr::WL_OUTSIDE_QOS != 0 {
            return (self.workloop_param(id) >> 16) as u8;
        }
        qos_pri(r.qos)
    }

    fn queue_for(wq: &mut Workq, flags: u8) -> &mut PrioQueue {
        if flags & tr::WL_OUTSIDE_QOS != 0 {
            &mut wq.special_queue
        } else if Self::tr_is_overcommit(flags) {
            &mut wq.overcommit_queue
        } else {
            &mut wq.constrained_queue
        }
    }

    fn coop_scheduled_to_qos(&mut self, q: u8) -> u64 {
        let wq = self.wq();
        let mut n = 0u64;
        let mut cur = QOS_MAX;
        while cur >= q {
            n += u64::from(wq.coop_scheduled[bucket(cur)]);
            cur -= 1;
        }
        n
    }

    fn coop_max_size(&mut self) -> u64 {
        if self.wq().coop_limited { 1 } else { u64::from(limits().max_cooperative) }
    }

    /// `_wq_cooperative_queue_refresh_best_req_qos`.
    fn coop_refresh_best_req_qos(&mut self) -> bool {
        let max_size = self.coop_max_size();
        let wq = self.wq();
        let old = wq.coop_best_req_qos;
        let (mut no_sched, mut with_width, mut highest) = (qos::UNSPECIFIED, qos::UNSPECIFIED, qos::UNSPECIFIED);
        let mut till = 0u64;
        let mut q = QOS_MAX;
        while q >= QOS_MIN {
            let b = bucket(q);
            let sched = wq.coop_scheduled[b];
            till += u64::from(sched);
            if !wq.coop_queue[b].is_empty() {
                highest = highest.max(q);
                if till < max_size {
                    with_width = with_width.max(q);
                }
                if sched == 0 {
                    no_sched = no_sched.max(q);
                }
            }
            q -= 1;
        }
        wq.coop_best_req_qos = no_sched.max(with_width);
        if wq.coop_best_req_qos == qos::UNSPECIFIED {
            wq.coop_best_req_qos = highest;
        }
        old != wq.coop_best_req_qos
    }

    /// `workq_cooperative_allowance`.
    fn workq_cooperative_allowance(&mut self, q: u8, tid: Option<i32>, may_start_timer: bool) -> bool {
        let exclude = tid.filter(|&t| self.workq_thread_is_cooperative(t));
        if let Some(t) = exclude {
            let rq = self.wqt(t).pri.qos_req;
            self.wq().coop_scheduled[bucket(rq)] -= 1;
        }
        let max_size = self.coop_max_size();
        let total = self.coop_scheduled_to_qos(QOS_MIN);
        let passed = if total < max_size {
            true
        } else {
            let b = bucket(q);
            if self.wq().coop_scheduled[b] == 0 && !self.wq().coop_queue[b].is_empty() {
                true
            } else {
                let p = self.coop_scheduled_to_qos(q) < max_size;
                if !p && may_start_timer {
                    self.workq_schedule_delayed_thread_creation(0);
                }
                p
            }
        };
        if let Some(t) = exclude {
            let rq = self.wqt(t).pri.qos_req;
            self.wq().coop_scheduled[bucket(rq)] += 1;
        }
        passed
    }

    /// `workq_threadreq_enqueue`: whether the highest request changed.
    fn workq_threadreq_enqueue(&mut self, id: ReqId) -> bool {
        let r = *self.req(id);
        self.req(id).state = tr::QUEUED;
        self.wq().reqcount += u32::from(r.count);
        if r.qos == QOS_MANAGER {
            self.wq().event_manager_threadreq = Some(id);
            return true;
        }
        if Self::tr_is_cooperative(r.flags) {
            self.wq().coop_queue[bucket(r.qos)].push_back(id);
            return self.coop_refresh_best_req_qos();
        }
        let pri = self.workq_priority_for_req(id);
        let (wq, reqs) = self.wq_and_reqs();
        wq.next_seq += 1;
        let rr = reqs.get_mut(&id).expect("a request");
        rr.pri = pri;
        rr.seq = wq.next_seq;
        let new_max = Self::queue_for(wq, r.flags).insert(id, reqs);
        if new_max {
            if Self::tr_is_nonovercommit(r.flags) {
                self.thactive_refresh_best_constrained_req_qos();
            }
            return true;
        }
        false
    }

    /// `workq_threadreq_dequeue`: whether the next highest request changed.
    fn workq_threadreq_dequeue(&mut self, id: ReqId, coop_changed: bool) -> bool {
        self.wq().reqcount -= 1;
        let mut changed = false;
        let r = self.req(id);
        r.count -= 1;
        let r = *r;
        if r.count == 0 {
            if r.qos == QOS_MANAGER {
                self.wq().event_manager_threadreq = None;
                if coop_changed {
                    self.coop_refresh_best_req_qos();
                }
                return true;
            }
            if Self::tr_is_cooperative(r.flags) {
                self.wq().coop_queue[bucket(r.qos)].pop_front();
            }
            if coop_changed {
                changed = self.coop_refresh_best_req_qos();
            }
            if !Self::tr_is_cooperative(r.flags) {
                let (wq, reqs) = self.wq_and_reqs();
                let was_max = Self::queue_for(wq, r.flags).remove(id, reqs);
                if was_max {
                    changed = true;
                    if Self::tr_is_nonovercommit(r.flags) {
                        self.thactive_refresh_best_constrained_req_qos();
                    }
                }
            }
        }
        changed
    }

    /// `workq_threadreq_destroy`.
    fn workq_threadreq_destroy(&mut self, id: ReqId) {
        self.req(id).state = tr::CANCELED;
        if self.req(id).flags & (tr::WORKLOOP | tr::KEVENT) != 0 {
            self.kqueue_threadreq_cancel(id);
        } else {
            self.dtask.threadreqs.remove(&id);
        }
    }

    // -- thread creation calls ------------------------------------------------------

    /// `workq_thread_call_prepost`.
    fn workq_thread_call_prepost(&mut self, sched: u32, pend: u32, fail_mask: u32) -> bool {
        let wq = self.wq();
        let old = wq.flags;
        if old & (wqf::EXITING | sched | pend | fail_mask) != 0 {
            return false;
        }
        wq.flags = if old & wqf::PROC_SUSPENDED != 0 { old | pend } else { old | sched };
        old & wqf::PROC_SUSPENDED == 0
    }

    /// `workq_schedule_delayed_thread_creation`.
    fn workq_schedule_delayed_thread_creation(&mut self, flags: u32) -> bool {
        const RESTART: u32 = 0x1;
        if !self.workq_thread_call_prepost(wqf::DELAYED_CALL_SCHEDULED, wqf::DELAYED_CALL_PENDED, wqf::IMMEDIATE_CALL_PENDED | wqf::IMMEDIATE_CALL_SCHEDULED) {
            return false;
        }
        let now = super::mach::absolute_time();
        let (stalled, max) = (abs(STALLED_WINDOW), abs(MAX_TIMER_INTERVAL));
        let wq = self.wq();
        if flags & RESTART != 0 {
        } else if now.wrapping_sub(wq.thread_call_last_run) <= wq.timer_interval {
            wq.timer_interval = (wq.timer_interval * 2).min(max);
        } else if now.wrapping_sub(wq.thread_call_last_run) > 2 * wq.timer_interval {
            wq.timer_interval = (wq.timer_interval / 2).max(stalled);
        }
        let deadline = now + wq.timer_interval;
        let key = self.dtask.timers.arm(super::mach::abs_to_instant(deadline), super::timer::Action::Workq(Call::Delayed));
        self.wq().delayed_call = Some(key);
        true
    }

    /// `workq_schedule_immediate_thread_creation`.
    fn workq_schedule_immediate_thread_creation(&mut self) {
        if self.workq_thread_call_prepost(wqf::IMMEDIATE_CALL_SCHEDULED, wqf::IMMEDIATE_CALL_PENDED, 0) {
            let key = self.dtask.timers.arm(Instant::now(), super::timer::Action::Workq(Call::Immediate));
            self.wq().immediate_call = Some(key);
        }
    }

    /// `workq_add_new_threads_call`.
    fn workq_add_new_threads_call(&mut self, m: &mut GuestMem<'_>, my_flag: u32) {
        if self.dtask.workq.is_none() {
            return;
        }
        let wq = self.wq();
        wq.thread_call_last_run = super::mach::absolute_time();
        wq.flags &= !my_flag;
        if my_flag == wqf::DELAYED_CALL_SCHEDULED {
            wq.delayed_call = None;
        } else {
            wq.immediate_call = None;
        }
        self.workq_schedule_creator_m(m, kflags::CAN_CREATE_THREADS);
    }

    /// A workqueue thread call has come due.
    pub(crate) fn darwin_workq_call(&mut self, m: &mut GuestMem<'_>, c: Call) {
        match c {
            Call::Delayed => self.workq_add_new_threads_call(m, wqf::DELAYED_CALL_SCHEDULED),
            Call::Immediate => self.workq_add_new_threads_call(m, wqf::IMMEDIATE_CALL_SCHEDULED),
            Call::Death => {
                if self.dtask.workq.is_some() {
                    self.workq_kill_old_threads_call();
                }
            }
            Call::Quantum(tid) => self.workq_quantum_check(m, tid),
        }
        self.workq_start_woken(m);
    }

    // -- thread state tracking ---------------------------------------------------------

    /// `workq_sched_callback(SCHED_CALL_BLOCK)`: the calling workqueue
    /// thread blocks in the kernel.
    pub(crate) fn darwin_workq_sched_block(&mut self) {
        let tid = self.tid;
        if self.dtask.workq.is_none() || !self.darwin_is_wq_thread(tid) || !self.wqt(tid).sched_call {
            return;
        }
        let q = self.wqt(tid).pri.qos_bucket;
        if q == QOS_MANAGER {
            return;
        }
        let old = self.thactive_dec(q);
        let req_qos = Self::best_constrained_req_qos(old);
        let last_run = self.wqt(tid).last_run;
        self.wq().lastblocked_ts[bucket(q)] = last_run;
        if req_qos == qos::UNSPECIFIED || q < req_qos {
            return;
        }
        let (old_req_count, _, max_busy) = self.thactive_aggregate_downto(old, req_qos, false);
        let conc = limits().max_parallelism;
        if old_req_count <= conc && conc <= old_req_count + max_busy {
            self.workq_schedule_delayed_thread_creation(0);
        }
    }

    /// `workq_sched_callback(SCHED_CALL_UNBLOCK)`: it runs again.
    pub(crate) fn darwin_workq_sched_unblock(&mut self) {
        let tid = self.tid;
        if self.dtask.workq.is_none() || !self.darwin_is_wq_thread(tid) || !self.wqt(tid).sched_call {
            return;
        }
        self.wqt(tid).last_run = super::mach::absolute_time();
        let q = self.wqt(tid).pri.qos_bucket;
        if q == QOS_MANAGER {
            return;
        }
        self.thactive_inc(q);
    }

    /// `workq_mark_exiting`: the process is exiting; its calls are
    /// cancelled and its thread requests destroyed.
    pub(crate) fn darwin_workq_mark_exiting(&mut self) {
        if self.dtask.workq.is_none() {
            return;
        }
        let wq = self.wq();
        assert!(wq.flags & wqf::EXITING == 0, "workq_mark_exiting called twice");
        wq.flags |= wqf::EXITING;
        let calls = [wq.immediate_call.take(), wq.delayed_call.take(), wq.death_call.take()];
        for key in calls.into_iter().flatten() {
            self.dtask.timers.cancel(key);
        }
        let wq = self.wq();
        let mgr = wq.event_manager_threadreq.take();
        wq.reqcount = 0;
        wq.creator = None;
        self.workq_turnstile_update_inheritor(Inheritor::Null);
        if let Some(r) = mgr {
            self.kqueue_threadreq_cancel(r);
        }
        let wq = self.wq();
        let mut all: Vec<ReqId> = Vec::new();
        for q in [&mut wq.overcommit_queue, &mut wq.constrained_queue, &mut wq.special_queue] {
            all.append(&mut q.items);
        }
        for id in all {
            self.workq_threadreq_destroy(id);
        }
    }

    // -- workq_open, workq_kernreturn, bsdthread_ctl ---------------------------------------

    /// `workq_open`.
    pub(crate) fn darwin_workq_open(&mut self) -> Result<u64, Errno> {
        if !self.dtask.pthread.registered {
            return Err(Errno::EINVAL);
        }
        if self.dtask.workq.is_none() {
            let mgr = super::thread::pp::from_qos(self.darwin_default_manager_qos(), 0, 0);
            let wq = Workq { event_manager_priority: mgr as u32, timer_interval: abs(STALLED_WINDOW), template_ctx: self.ctx_addr, ..Workq::default() };
            self.dtask.workq = Some(Box::new(wq));
        }
        Ok(0)
    }

    /// `task_get_default_manager_qos`: the main thread's QoS by the task's
    /// app type, user-initiated for a legacy one.
    fn darwin_default_manager_qos(&self) -> u8 {
        let primordial = self.darwin_main_thread_qos();
        if primordial == qos::LEGACY { qos::USER_INITIATED } else { primordial }
    }

    /// `task_compute_main_thread_qos`.
    pub(crate) fn darwin_main_thread_qos(&self) -> u8 {
        self.darwin_policy().main_thread_qos(self.pid == 1)
    }

    /// `workq_kernreturn(options, item, affinity, prio)`.
    pub(crate) fn darwin_workq_kernreturn(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> SyscallOutcome {
        let (options, item, arg2, arg3) = (a[0] as u32 as u64, a[1], a[2] as i32, a[3] as i32);
        let done = |k: &mut Kernel, m: &mut GuestMem<'_>, r: Result<u64, Errno>| {
            k.workq_start_woken(m);
            super::thread::bsd_result(m, k.ctx_addr, r, false);
            SyscallOutcome::Continue
        };
        if !self.dtask.pthread.registered {
            return done(self, m, Err(Errno::EINVAL));
        }
        let have_wq = self.dtask.workq.is_some();
        let r = match options {
            wqops::QUEUE_NEWSPISUPP => {
                self.dtask.dispatchqueue_serialno_offset = arg2 as u64;
                Ok(0)
            }
            wqops::QUEUE_REQTHREADS => self.workq_reqthreads(m, arg2, arg3 as u32, false),
            wqops::QUEUE_REQTHREADS2 => self.workq_reqthreads(m, arg2, arg3 as u32, true),
            wqops::SET_EVENT_MANAGER_PRIORITY => {
                if !have_wq {
                    Err(Errno::EINVAL)
                } else {
                    let mut pri = arg2 as u32 as u64;
                    let mut bad = false;
                    if pri & pp::SCHED_PRI_FLAG != 0 {
                        pri &= pp::SCHED_PRI_MASK | pp::SCHED_PRI_FLAG;
                    } else {
                        let (q, relpri) = (pp::qos(pri), pp::relpri(pri));
                        if relpri > 0 || relpri < tq::MIN_TIER_IMPORTANCE || q == qos::UNSPECIFIED {
                            bad = true;
                        }
                        pri &= !pp::FLAGS_MASK;
                    }
                    if bad {
                        Err(Errno::EINVAL)
                    } else {
                        let wq = self.wq();
                        if wq.event_manager_priority < pri as u32 {
                            wq.event_manager_priority = pri as u32;
                        }
                        Ok(0)
                    }
                }
            }
            wqops::THREAD_KEVENT_RETURN | wqops::THREAD_WORKLOOP_RETURN | wqops::THREAD_RETURN => {
                if !have_wq {
                    return done(self, m, Err(Errno::EINVAL));
                }
                return match self.workq_thread_return(m, item, arg2) {
                    Ok(out) => {
                        self.workq_start_woken(m);
                        out
                    }
                    Err(e) => done(self, m, Err(e)),
                };
            }
            wqops::SHOULD_NARROW => {
                let tid = self.tid;
                if !have_wq || !self.darwin_is_wq_thread(tid) || self.wqt(tid).flags & (ut::DYING | ut::OVERCOMMIT) != 0 {
                    Err(Errno::EINVAL)
                } else {
                    let q = pp::qos(arg2 as u32 as u64);
                    if q == qos::UNSPECIFIED {
                        Err(Errno::EINVAL)
                    } else {
                        Ok(u64::from(self.workq_constrained_allowance(q, Some(tid), false) == 0))
                    }
                }
            }
            wqops::SETUP_DISPATCH => {
                // struct workq_dispatch_config: version, flags, serialno
                // offset, label offset (packed).
                let n = (arg2 as u32 as usize).min(24);
                let mut cfg = [0u8; 24];
                match m.read(item, n) {
                    Err(_) => Err(Errno::EFAULT),
                    Ok(b) => {
                        cfg[..n].copy_from_slice(b);
                        let (version, flags) = (u32::from_le_bytes(cfg[0..4].try_into().unwrap()), u32::from_le_bytes(cfg[4..8].try_into().unwrap()));
                        if flags != 0 || version < 1 {
                            Err(Errno::EOPNOTSUPP)
                        } else {
                            self.dtask.dispatchqueue_serialno_offset = u64::from_le_bytes(cfg[8..16].try_into().unwrap());
                            if version >= 2 {
                                self.dtask.dispatchqueue_label_offset = u64::from_le_bytes(cfg[16..24].try_into().unwrap());
                            }
                            Ok(0)
                        }
                    }
                }
            }
            _ => Err(Errno::EINVAL),
        };
        done(self, m, r)
    }

    /// `workq_reqthreads`.
    fn workq_reqthreads(&mut self, m: &mut GuestMem<'_>, reqcount: i32, pp_: u32, cooperative: bool) -> Result<u64, Errno> {
        let q = pp::qos(u64::from(pp_));
        if self.dtask.workq.is_none() || reqcount <= 0 || reqcount > i32::from(u16::MAX) || q == qos::UNSPECIFIED {
            return Err(Errno::EINVAL);
        }
        let mut reqcount = reqcount as u32;
        let mut upcall_flags = upcall::NEWSPI;
        let mut flags = 0u8;
        if u64::from(pp_) & pp::OVERCOMMIT_FLAG != 0 {
            flags |= tr::OVERCOMMIT;
            upcall_flags |= upcall::OVERCOMMIT;
        }
        if cooperative {
            flags |= tr::COOPERATIVE;
            upcall_flags |= upcall::COOPERATIVE;
            if reqcount > 1 {
                return Err(Errno::EOPNOTSUPP);
            }
        }
        if Self::tr_is_cooperative(flags) && Self::tr_is_overcommit(flags) {
            return Err(Errno::EINVAL);
        }
        let id = self.threadreq_alloc(Req { state: tr::NEW, qos: q, flags, ..Req::default() });
        let l = limits();
        loop {
            if self.wq_exiting() {
                self.dtask.threadreqs.remove(&id);
                return Ok(0);
            }
            let mut unpaced = reqcount - 1;
            if reqcount > 1 && Self::tr_is_nonovercommit(flags) {
                unpaced = self.workq_constrained_allowance(q, None, false).min(reqcount - 1);
            }
            while unpaced > 0 && self.wq().thidlecount != 0 {
                let mut uu = ut::EARLY_BOUND;
                if Self::tr_is_overcommit(flags) {
                    uu |= ut::OVERCOMMIT;
                }
                let (tid, needs_wakeup) = self.workq_pop_idle_thread(uu);
                self.thactive_inc(q);
                self.wq().thscheduled_count[bucket(q)] += 1;
                self.workq_thread_reset_pri(tid, Some(id), true);
                self.wq().fulfilled += 1;
                let t = self.wqt(tid);
                t.park.upcall_flags = upcall_flags;
                t.park.thread_request = Some(id);
                if needs_wakeup {
                    self.workq_thread_wakeup(tid);
                }
                unpaced -= 1;
                reqcount -= 1;
            }
            if !(unpaced != 0 && u32::from(self.wq().nthreads) < l.max_threads && self.workq_add_new_idle_thread(m)) {
                break;
            }
        }
        if self.wq_exiting() {
            self.dtask.threadreqs.remove(&id);
            return Ok(0);
        }
        self.req(id).count = reqcount as u16;
        if self.workq_threadreq_enqueue(id) {
            self.workq_schedule_creator_m(m, kflags::CAN_CREATE_THREADS);
        }
        Ok(0)
    }

    /// `workq_thread_return`: the calling thread is done; it takes another
    /// request or parks.
    fn workq_thread_return(&mut self, m: &mut GuestMem<'_>, eventlist: u64, nevents: i32) -> Result<SyscallOutcome, Errno> {
        let tid = self.tid;
        if !self.darwin_is_wq_thread(tid) || self.wqt(tid).flags & ut::DYING != 0 {
            return Err(Errno::EINVAL);
        }
        let kqr = self.wqt(tid).kqr_bound;
        if eventlist != 0 && nevents != 0 && kqr.is_none() {
            return Err(Errno::EINVAL);
        }
        // Signals the process has not allowed workqueue threads are blocked
        // again.
        let allow = self.dtask.workq_allow_sigmask;
        let mask = super::kern::mask_from_linux(self.signals.blocked());
        if mask & !allow != !dsig::WORKQ_THREADMASK {
            let next = mask | (!dsig::WORKQ_THREADMASK & !allow);
            self.signals.set_blocked(super::kern::mask_to_linux(next));
        }
        let trp = match kqr {
            Some(r) if self.req(r).flags & tr::WL_PARAMS != 0 => self.workloop_param(r),
            _ => 0,
        };
        if let Some(r) = kqr {
            let mut upcall_flags = upcall::NEWSPI | upcall::REUSE;
            if self.req(r).flags & tr::WORKLOOP != 0 {
                upcall_flags |= upcall::WORKLOOP | upcall::KEVENT;
            } else {
                upcall_flags |= upcall::KEVENT;
            }
            if self.wqt(tid).pri.qos_bucket == QOS_MANAGER {
                upcall_flags |= upcall::EVENT_MANAGER;
            } else {
                if self.workq_thread_is_overcommit(tid) {
                    upcall_flags |= upcall::OVERCOMMIT;
                }
                if self.wqt(tid).flags & ut::OUTSIDE_QOS != 0 {
                    upcall_flags |= upcall::OUTSIDEQOS;
                } else {
                    upcall_flags |= u32::from(self.wqt(tid).pri.qos_req) | upcall::PRIO_QOS;
                }
            }
            if let Some(out) = self.workq_handle_stack_events(m, tid, eventlist, nevents, upcall_flags)? {
                return Ok(out);
            }
            // KEVENT_FLAG_PARKING either returned events, failed, or
            // unbound the thread.
            assert!(self.wqt(tid).kqr_bound.is_none(), "a parking thread unbinds");
        }
        let t = self.wqt(tid);
        t.sched_call = false;
        t.park.workloop_params = trp;
        Ok(self.workq_select_threadreq_or_park(m, tid, setup::CLEAR_VOUCHER))
    }

    /// `workq_park_and_unlock`.
    fn workq_park(&mut self, m: &mut GuestMem<'_>, tid: i32, setup_flags: u32) -> SyscallOutcome {
        if let Some(out) = self.workq_push_idle_thread(m, tid, setup_flags) {
            return out;
        }
        self.workq_thread_reset_cpupercent(None, tid);
        let mut setup_flags = setup_flags;
        let t = self.wqt(tid);
        if t.flags & ut::IDLE_CLEANUP != 0 && t.flags & ut::DYING == 0 {
            // The thread's stack, if it gave it up, becomes reusable
            // memory (workq_markfree_threadstack's VM_BEHAVIOR_REUSABLE):
            // its contents may be discarded.
            if !t.park.has_stack {
                let page = super::mach::PAGE_MASK + 1;
                let free = t.stackaddr + page;
                let size = ((PTH_DEFAULT_STACKSIZE + page + PTHREAD_T_OFFSET - 1) & !(page - 1)) - page;
                let _ = self.darwin_behavior_set(m, free, size, super::mman::act::REUSABLE);
            }
            let t = self.wqt(tid);
            t.flags &= !ut::IDLE_CLEANUP;
            setup_flags &= !setup::CLEAR_VOUCHER;
        }
        let t = self.wqt(tid);
        if t.flags & ut::RUNNING != 0 {
            return self.workq_unpark_select_threadreq_or_park(m, tid, setup_flags);
        }
        if t.flags & ut::DYING != 0 {
            return self.workq_unpark_for_death(m, tid, true, setup_flags);
        }
        self.workq_disarm_quantum(tid);
        let t = self.wqt(tid);
        t.enter_kernel = true;
        // assert_wait(THREAD_INTERRUPTIBLE) then thread_block with
        // workq_unpark_continue.
        if tid == self.tid {
            return self.darwin_block(m, Wait { deadline: None, cont: super::thread::Finish::WorkqPark });
        }
        SyscallOutcome::Continue
    }

    fn workq_may_start_event_mgr_thread(&mut self, tid: Option<i32>) -> bool {
        self.wq().thscheduled_count[bucket(QOS_MANAGER)] == 0 || tid.is_some_and(|t| self.wqt(t).pri.qos_bucket == QOS_MANAGER)
    }

    /// `workq_constrained_allowance`.
    fn workq_constrained_allowance(&mut self, at_qos: u8, tid: Option<i32>, may_start_timer: bool) -> u32 {
        let l = limits();
        let mut max_count = u32::from(self.wq().constrained_threads_scheduled);
        if let Some(t) = tid {
            if self.workq_thread_is_nonovercommit(t) {
                max_count -= 1;
            }
        }
        if max_count >= l.max_constrained {
            return 0;
        }
        let max_count = l.max_constrained - max_count;
        let v = self.wq().thactive;
        let (mut thactive, busy, _) = self.thactive_aggregate_downto(v, at_qos, true);
        if let Some(t) = tid {
            let b = self.wqt(t).pri.qos_bucket;
            if b != QOS_MANAGER && at_qos <= b {
                thactive -= 1;
            }
        }
        let count = l.max_parallelism;
        if count > thactive + busy {
            return (count - (thactive + busy)).min(max_count);
        }
        if may_start_timer {
            self.workq_schedule_delayed_thread_creation(0);
        }
        0
    }

    /// `workq_cooperative_queue_best_req`.
    fn workq_cooperative_queue_best_req(&mut self, tid: Option<i32>) -> Option<ReqId> {
        if let Some(t) = tid.filter(|&t| self.workq_thread_is_cooperative(t)) {
            let rq = self.wqt(t).pri.qos_req;
            self.wq().coop_scheduled[bucket(rq)] -= 1;
            self.coop_refresh_best_req_qos();
            self.wq().coop_scheduled[bucket(rq)] += 1;
        }
        let q = self.wq().coop_best_req_qos;
        if q == qos::UNSPECIFIED {
            return None;
        }
        self.wq().coop_queue[bucket(q)].front().copied()
    }

    fn manager_pri(&mut self) -> u8 {
        let mgr = u64::from(self.wq().event_manager_priority);
        if mgr & pp::SCHED_PRI_FLAG != 0 {
            (mgr & pp::SCHED_PRI_MASK) as u8
        } else {
            qos_pri(pp::qos(mgr))
        }
    }

    /// `workq_threadreq_select_for_creator`.
    fn workq_threadreq_select_for_creator(&mut self) -> Option<ReqId> {
        let (wq, reqs) = self.wq_and_reqs();
        let req_pri = wq.special_queue.max(reqs);
        let pri = req_pri.map_or(0, |r| reqs[&r].pri);
        if let Some(mgr) = self.wq().event_manager_threadreq {
            if self.workq_may_start_event_mgr_thread(None) {
                return if self.manager_pri() >= pri { Some(mgr) } else { req_pri };
            }
        }
        let (wq, reqs) = self.wq_and_reqs();
        let mut req_qos = wq.overcommit_queue.max(reqs);
        let mut q = req_qos.map_or(qos::UNSPECIFIED, |r| reqs[&r].qos);
        if let Some(t) = self.workq_cooperative_queue_best_req(None) {
            let tq_ = self.req(t).qos;
            if q <= tq_ && self.workq_cooperative_allowance(tq_, None, true) {
                req_qos = Some(t);
                q = tq_;
            }
        }
        let (wq, reqs) = self.wq_and_reqs();
        if let Some(t) = wq.constrained_queue.max(reqs) {
            let tq_ = reqs[&t].qos;
            if q < tq_ {
                if pri != 0 && pri >= qos_pri(tq_) {
                    return req_pri;
                }
                if self.workq_constrained_allowance(tq_, None, true) != 0 {
                    return Some(t);
                }
            }
        }
        if pri != 0 && (q == 0 || pri >= qos_pri(q)) {
            return req_pri;
        }
        // A turnstile push from a workloop's waiters would make a request
        // here (turnstile_workq_proprietor_of_max_turnstile); without the
        // scheduler's priority inheritance there is none.
        req_qos
    }

    /// `workq_adjust_cooperative_constrained_schedule_counts`.
    fn workq_adjust_schedule_counts(&mut self, tid: i32, old_qos: u8, tr_flags: u8) -> bool {
        let new_qos = self.wqt(tid).pri.qos_req;
        let mut changed = false;
        if self.workq_thread_is_overcommit(tid) {
            if Self::tr_is_nonovercommit(tr_flags) {
                self.wq().constrained_threads_scheduled += 1;
            } else if Self::tr_is_cooperative(tr_flags) {
                self.wq().coop_scheduled[bucket(new_qos)] += 1;
                changed = true;
            }
        } else if self.workq_thread_is_cooperative(tid) {
            if Self::tr_is_overcommit(tr_flags) {
                self.wq().coop_scheduled[bucket(old_qos)] -= 1;
            } else if Self::tr_is_nonovercommit(tr_flags) {
                self.wq().coop_scheduled[bucket(old_qos)] -= 1;
                self.wq().constrained_threads_scheduled += 1;
            } else {
                self.wq().coop_scheduled[bucket(old_qos)] -= 1;
                self.wq().coop_scheduled[bucket(new_qos)] += 1;
            }
            changed = true;
        } else if Self::tr_is_overcommit(tr_flags) {
            self.wq().constrained_threads_scheduled -= 1;
        } else if Self::tr_is_cooperative(tr_flags) {
            self.wq().constrained_threads_scheduled -= 1;
            self.wq().coop_scheduled[bucket(new_qos)] += 1;
            changed = true;
        }
        changed
    }

    /// `workq_threadreq_select`.
    fn workq_threadreq_select(&mut self, tid: i32) -> Option<ReqId> {
        let uth = if self.wq().creator == Some(tid) { None } else { Some(tid) };
        // No turnstile pushes (see workq_threadreq_select_for_creator).
        let (wq, reqs) = self.wq_and_reqs();
        let req_pri = wq.special_queue.max(reqs);
        let pri = req_pri.map_or(0, |r| reqs[&r].pri);
        if let Some(mgr) = self.wq().event_manager_threadreq {
            if self.workq_may_start_event_mgr_thread(uth) {
                return if self.manager_pri() >= pri { Some(mgr) } else { req_pri };
            }
        }
        let (wq, reqs) = self.wq_and_reqs();
        let mut req_qos = wq.overcommit_queue.max(reqs);
        let mut q = req_qos.map_or(qos::UNSPECIFIED, |r| reqs[&r].qos);
        if let Some(t) = self.workq_cooperative_queue_best_req(uth) {
            let tq_ = self.req(t).qos;
            if q <= tq_ && self.workq_cooperative_allowance(tq_, uth, true) {
                req_qos = Some(t);
                q = tq_;
            }
        }
        let (wq, reqs) = self.wq_and_reqs();
        if let Some(t) = wq.constrained_queue.max(reqs) {
            let tq_ = reqs[&t].qos;
            if q < tq_ {
                if pri != 0 && pri >= qos_pri(tq_) {
                    return req_pri;
                }
                if self.workq_constrained_allowance(tq_, uth, true) != 0 {
                    return Some(t);
                }
            }
        }
        if req_pri.is_some() && (q == 0 || pri >= qos_pri(q)) {
            return req_pri;
        }
        req_qos
    }

    /// `workq_schedule_creator`, from inside a call (no new thread can be
    /// made without guest memory).
    fn workq_schedule_creator(&mut self, flags: u32) {
        self.dtask.workq_creator_pending = Some(self.dtask.workq_creator_pending.map_or(flags, |f| f | flags));
    }

    /// Run a creator pass a caller without guest memory asked for.
    fn workq_run_pending_creator(&mut self, m: &mut GuestMem<'_>) {
        while let Some(flags) = self.dtask.workq_creator_pending.take() {
            if self.dtask.workq.is_some() {
                self.workq_schedule_creator_m(m, flags);
            }
        }
    }

    /// `workq_schedule_creator`.
    fn workq_schedule_creator_m(&mut self, m: &mut GuestMem<'_>, mut flags: u32) {
        loop {
            let uth = self.wq().creator;
            if self.wq().reqcount == 0 {
                if uth.is_none() {
                    self.workq_turnstile_update_inheritor(Inheritor::Null);
                }
                return;
            }
            let Some(req) = self.workq_threadreq_select_for_creator() else {
                if uth.is_none() {
                    self.workq_turnstile_update_inheritor(Inheritor::Workq);
                }
                return;
            };
            if let Some(t) = uth {
                if self.workq_thread_needs_priority_change(req, t) {
                    self.workq_thread_reset_pri(t, Some(req), true);
                }
                return;
            }
            if self.wq().thidlecount != 0 {
                let (t, needs_wakeup) = self.workq_pop_idle_thread(ut::OVERCOMMIT);
                self.wq().creator = Some(t);
                self.workq_thread_reset_pri(t, Some(req), true);
                self.workq_turnstile_update_inheritor(Inheritor::Thread(t));
                let fulfilled = self.wq().fulfilled;
                let th = self.wqt(t);
                th.park.fulfilled_snapshot = fulfilled;
                th.park.yields = 0;
                if needs_wakeup {
                    self.workq_thread_wakeup(t);
                }
                return;
            }
            let l = limits();
            if u32::from(self.wq().nthreads) >= l.max_threads {
                flags = kflags::NONE;
            } else if flags & kflags::SET_AST_ON_FAILURE != 0 {
                let me = self.tid;
                self.darwin_set_astkevent(me, super::kevent::ast::REDRIVE_THREADREQ);
            } else if flags & kflags::CAN_CREATE_THREADS == 0 {
                self.workq_schedule_immediate_thread_creation();
            } else if self.workq_add_new_idle_thread(m) {
                continue;
            } else {
                self.workq_schedule_delayed_thread_creation(0);
            }
            let me = self.tid;
            if flags & kflags::SET_AST_ON_FAILURE == 0 && self.wq().inheritor == Inheritor::Thread(me) {
                self.workq_turnstile_update_inheritor(Inheritor::Null);
            }
            return;
        }
    }

    /// `workq_thread_needs_priority_change`.
    fn workq_thread_needs_priority_change(&mut self, req: ReqId, tid: i32) -> bool {
        let cur = self.wqt(tid).park.workloop_params;
        let want = if self.req(req).flags & tr::WL_PARAMS != 0 { self.workloop_param(req) } else { 0 };
        let (cf, rf) = (cur as u16 & !TRP_CPUPERCENT, want as u16 & !TRP_CPUPERCENT);
        if cf != 0 || rf != 0 {
            if rf != cf || (rf & TRP_PRIORITY != 0 && (want >> 16) as u8 != (cur >> 16) as u8) || (rf & TRP_POLICY != 0 && (want >> 24) as u8 != (cur >> 24) as u8) {
                return true;
            }
        }
        self.req(req).qos != self.wqt(tid).pri.override_()
    }

    /// `workq_select_threadreq_or_park_and_unlock`.
    fn workq_select_threadreq_or_park(&mut self, m: &mut GuestMem<'_>, tid: i32, mut setup_flags: u32) -> SyscallOutcome {
        let is_creator = self.wq().creator == Some(tid);
        if self.wq_exiting() || self.wq().reqcount == 0 {
            return self.workq_park(m, tid, setup_flags);
        }
        let Some(req) = self.workq_threadreq_select(tid) else { return self.workq_park(m, tid, setup_flags) };
        let old_pri = self.wqt(tid).pri;
        let r = *self.req(req);
        if is_creator {
            self.wq().creator = None;
            self.thactive_inc(r.qos);
            self.wq().thscheduled_count[bucket(r.qos)] += 1;
        } else if old_pri.qos_bucket != r.qos {
            self.thactive_move(old_pri.qos_bucket, r.qos);
        }
        self.workq_thread_reset_pri(tid, Some(req), true);
        let coop_changed = self.workq_adjust_schedule_counts(tid, old_pri.qos_req, r.flags);
        if Self::tr_is_overcommit(r.flags) {
            self.workq_thread_set_type(tid, ut::OVERCOMMIT);
        } else if Self::tr_is_cooperative(r.flags) {
            self.workq_thread_set_type(tid, ut::COOPERATIVE);
        } else {
            self.workq_thread_set_type(tid, 0);
        }
        // thread_unfreeze_base_pri: the base priority moves only by policy
        // changes this kernel does not make while a thread is frozen.
        self.wq().fulfilled += 1;
        let schedule_creator = self.workq_threadreq_dequeue(req, coop_changed);
        self.workq_thread_reset_cpupercent(Some(req), tid);
        let mut free_req = None;
        if r.flags & (tr::KEVENT | tr::WORKLOOP) != 0 {
            self.kqueue_threadreq_bind_prepost(req, tid);
        } else if self.req(req).count == 0 {
            free_req = Some(req);
        }
        if self.wqt(tid).flags & ut::NEW != 0 {
            self.wqt(tid).flags ^= ut::NEW;
            setup_flags |= setup::FIRST_USE;
        }
        if is_creator || schedule_creator {
            self.workq_schedule_creator_m(m, kflags::CAN_CREATE_THREADS);
        }
        if let Some(id) = free_req {
            self.dtask.threadreqs.remove(&id);
        }
        let mut upcall_flags = upcall::NEWSPI;
        if self.wqt(tid).pri.qos_bucket == QOS_MANAGER {
            upcall_flags |= upcall::EVENT_MANAGER;
        } else if Self::tr_is_overcommit(r.flags) {
            upcall_flags |= upcall::OVERCOMMIT;
        } else if Self::tr_is_cooperative(r.flags) {
            upcall_flags |= upcall::COOPERATIVE;
        }
        if r.flags & tr::KEVENT != 0 {
            upcall_flags |= upcall::KEVENT;
        }
        if r.flags & tr::WORKLOOP != 0 {
            upcall_flags |= upcall::WORKLOOP | upcall::KEVENT;
        }
        self.wqt(tid).park.upcall_flags = upcall_flags;
        if r.flags & (tr::KEVENT | tr::WORKLOOP) != 0 {
            self.kqueue_threadreq_bind_commit(tid);
        }
        self.workq_setup_and_run(m, tid, setup_flags)
    }

    /// `workq_unpark_select_threadreq_or_park_and_unlock`.
    fn workq_unpark_select_threadreq_or_park(&mut self, m: &mut GuestMem<'_>, tid: i32, mut setup_flags: u32) -> SyscallOutcome {
        let t = self.wqt(tid);
        if t.flags & ut::EARLY_BOUND != 0 {
            if t.flags & ut::NEW != 0 {
                setup_flags |= setup::FIRST_USE;
            }
            t.flags &= !(ut::NEW | ut::EARLY_BOUND);
            return self.workq_setup_and_run(m, tid, setup_flags);
        }
        self.workq_select_threadreq_or_park(m, tid, setup_flags)
    }

    /// `workq_creator_should_yield`.
    fn workq_creator_should_yield(&mut self, tid: i32) -> bool {
        let q = self.wqt(tid).pri.override_();
        if q >= qos::USER_INTERACTIVE {
            return false;
        }
        let snapshot = self.wqt(tid).park.fulfilled_snapshot;
        let wq = self.wq();
        if wq.fulfilled == snapshot {
            return false;
        }
        let conc = limits().max_parallelism;
        if wq.fulfilled.wrapping_sub(snapshot) > conc {
            return true;
        }
        let cnt: u32 = (bucket(q)..NUM_QOS_BUCKETS).map(|i| u32::from(wq.thscheduled_count[i])).sum();
        conc <= cnt
    }

    /// `workq_unpark_continue`: a parked thread runs again.
    fn workq_unpark_continue(&mut self, m: &mut GuestMem<'_>, tid: i32, wr: WaitResult) -> SyscallOutcome {
        self.wqt(tid).enter_kernel = false;
        if self.wq().creator == Some(tid) && self.workq_creator_should_yield(tid) {
            let fulfilled = self.wq().fulfilled;
            let t = self.wqt(tid);
            t.park.fulfilled_snapshot = fulfilled;
            t.park.yields += 1;
            // thread_yield_with_continuation: the processor goes to another
            // thread, then this one continues the same way.
            std::thread::yield_now();
            return self.workq_unpark_continue(m, tid, WaitResult::Awakened);
        }
        if self.wqt(tid).flags & ut::RUNNING != 0 {
            return self.workq_unpark_select_threadreq_or_park(m, tid, setup::NONE);
        }
        if wr != WaitResult::Awakened {
            // Interrupted while idle: the thread goes away.
            self.wq().thdying_count += 1;
            self.wqt(tid).flags |= ut::DYING;
        }
        self.workq_unpark_for_death(m, tid, true, setup::NONE)
    }

    /// `workq_setup_and_run`.
    fn workq_setup_and_run(&mut self, m: &mut GuestMem<'_>, tid: i32, setup_flags: u32) -> SyscallOutcome {
        let t = self.wqt(tid);
        let mut upcall_flags = t.park.upcall_flags;
        if setup_flags & setup::FIRST_USE == 0 {
            upcall_flags |= upcall::REUSE;
        }
        if t.flags & ut::OUTSIDE_QOS != 0 {
            upcall_flags |= upcall::OUTSIDEQOS;
        } else {
            upcall_flags |= u32::from(t.park.qos) | upcall::PRIO_QOS;
        }
        if t.thport == 0 {
            let pport = self.darwin_thread_ports(tid).1;
            self.ipc().make_send(pport);
            let name = self.darwin_copyout_send_pinned(pport);
            self.wqt(tid).thport = name;
        }
        if self.thread_supports_cooperative_workqueue(tid) {
            self.workq_arm_quantum(tid);
        } else {
            self.workq_disarm_quantum(tid);
        }
        let coop = self.workq_thread_is_cooperative(tid);
        let t = self.wqt(tid);
        t.sched_call = !coop;
        t.last_run = super::mach::absolute_time();
        let (stack, port) = (t.stackaddr, t.thport);
        self.workq_setup_thread(m, tid, stack, port, setup_flags, upcall_flags)
    }

    /// libpthread's `workq_setup_thread`: the thread's registers for
    /// `_pthread_wqthread(self, kport, stackaddr, keventlist, upcall_flags,
    /// nkevents)` on its stack, then back to user space there.
    fn workq_setup_thread(&mut self, m: &mut GuestMem<'_>, tid: i32, stackaddr: u64, kport: u32, setup_flags: u32, mut upcall_flags: u32) -> SyscallOutcome {
        let page = super::mach::PAGE_MASK + 1;
        let this = self.darwin_ctx_of(tid);
        let selfp = stackaddr + PTH_DEFAULT_STACKSIZE + page + PTHREAD_T_OFFSET;
        let mut stack_top = selfp & !(STK_ALIGN - 1);
        let stack_bottom = stackaddr + page;
        if setup_flags & setup::FIRST_USE != 0 {
            let tsd_offset = self.dtask.pthread.tsd_offset;
            if tsd_offset != 0 {
                if let Some(t) = self.thread_signals.get(tid) {
                    let _ = super::set_tsd_base(m, this, &t, selfp + tsd_offset, self.darwin_map_max());
                }
                upcall_flags |= upcall::TSD_BASE_SET;
            }
        }
        let (mut kevent_list, mut kevent_count) = (0u64, 0i32);
        if setup_flags & setup::EXIT_THREAD != 0 {
            kevent_count = EXIT_THREAD_NKEVENT;
        } else if upcall_flags & upcall::KEVENT != 0 {
            // The events are the thread's own: it is the one running here.
            assert_eq!(tid, self.tid, "a workqueue thread takes its events itself");
            let flags = super::kevent::kf::STACK_DATA | super::kevent::kf::IMMEDIATE;
            let (_, list, count, top) = self.workq_kevent(m, selfp, 0, 0, flags);
            kevent_list = list;
            kevent_count = count;
            if let Some(t) = top {
                stack_top = t;
            }
        }
        self.workq_set_register_state(m, tid, selfp, stack_top, stack_bottom, kport, kevent_list, upcall_flags, kevent_count)
    }

    /// libpthread's `workq_set_register_state`: the registers for
    /// `_pthread_wqthread`, and back to user space there.
    #[allow(clippy::too_many_arguments)]
    fn workq_set_register_state(&mut self, m: &mut GuestMem<'_>, tid: i32, selfp: u64, stack_top: u64, stack_bottom: u64, kport: u32, kevent_list: u64, upcall_flags: u32, kevent_count: i32) -> SyscallOutcome {
        let this = self.darwin_ctx_of(tid);
        let wqthread = self.dtask.pthread.wqthread;
        let regs = [(ctx::x(0), selfp), (ctx::x(1), u64::from(kport)), (ctx::x(2), stack_bottom), (ctx::x(3), kevent_list), (ctx::x(4), u64::from(upcall_flags)), (ctx::x(5), kevent_count as i64 as u64), (ctx::sp_slot(false), stack_top), (ctx::PC, wqthread)];
        for (slot, v) in regs {
            let _ = m.write_u64(this + slot as u64, v);
        }
        if tid == self.tid {
            SyscallOutcome::Resume(wqthread)
        } else {
            SyscallOutcome::Continue
        }
    }

    // -- waking and starting threads -------------------------------------------------

    /// `workq_thread_wakeup`: a parked thread is woken, or a new one's host
    /// thread is started.
    fn workq_thread_wakeup(&mut self, tid: i32) {
        self.dtask.workq_wake.push(tid);
    }

    /// What the workqueue owes after a call outside it: a creator pass, and
    /// threads to wake.
    pub(crate) fn darwin_workq_settle(&mut self, m: &mut GuestMem<'_>) {
        self.workq_start_woken(m);
    }

    /// Wake the threads the workqueue woke.
    fn workq_start_woken(&mut self, m: &mut GuestMem<'_>) {
        self.workq_run_pending_creator(m);
        for tid in std::mem::take(&mut self.dtask.workq_wake) {
            let Some(t) = self.dtask.threads.map.get_mut(&tid).and_then(|t| t.wq.as_mut()) else { continue };
            match t.unstarted.take() {
                Some(req) => self.dtask.spawns.push(req),
                None => {
                    self.darwin_wake(m, tid, WaitResult::Awakened);
                }
            }
        }
    }

    /// The first entry of a thread whose first act is the kernel's: a new
    /// workqueue thread runs `workq_unpark_continue`.
    pub(crate) fn workq_thread_entry(&mut self, m: &mut GuestMem<'_>) -> Option<SyscallOutcome> {
        let tid = self.tid;
        if !self.darwin_is_wq_thread(tid) || !self.wqt(tid).enter_kernel {
            return None;
        }
        let out = self.workq_unpark_continue(m, tid, WaitResult::Awakened);
        self.workq_start_woken(m);
        Some(out)
    }

    /// A parked workqueue thread has been woken.
    pub(crate) fn darwin_workq_wait_done(&mut self, m: &mut GuestMem<'_>, res: WaitResult) -> Option<SyscallOutcome> {
        let tid = self.tid;
        let out = self.workq_unpark_continue(m, tid, res);
        self.workq_start_woken(m);
        Some(out)
    }

    // -- the workqueue quantum ----------------------------------------------------------

    /// `thread_supports_cooperative_workqueue`.
    fn thread_supports_cooperative_workqueue(&mut self, tid: i32) -> bool {
        let part = (self.workq_thread_is_cooperative(tid) || self.workq_thread_is_nonovercommit(tid)) && self.wqt(tid).pri.qos_bucket != QOS_MANAGER;
        self.dtask.pthread.wq_quantum_offset != 0 && part
    }

    /// The thread's quantum (`sched_clutch_thread_quantum` for its base
    /// priority's bucket on iOS) halved (`thread_workq_quantum_size`).
    fn workq_quantum_size(&mut self, tid: i32) -> u64 {
        let t = self.wqt(tid);
        let pri = if t.sched_qos != qos::UNSPECIFIED { qos_pri(t.sched_qos) } else { t.sched_pri };
        let us: u64 = if pri > 37 {
            10_000
        } else if pri > 31 {
            8_000
        } else if pri > 20 {
            6_000
        } else if pri > 4 {
            4_000
        } else {
            2_000
        };
        abs(Duration::from_micros(us)) / 2
    }

    /// `thread_arm_workqueue_quantum`: the deadline in the thread's running
    /// time, checked by a thread call.
    fn workq_arm_quantum(&mut self, tid: i32) {
        let size = self.workq_quantum_size(tid);
        let Some(runtime) = thread_runtime(tid) else {
            self.darwin_unimplemented("a thread's running time (the workqueue quantum)".into());
            return;
        };
        self.workq_disarm_quantum(tid);
        let t = self.wqt(tid);
        t.quantum_deadline = runtime + size;
        t.quantum_expired = false;
        let key = self.dtask.timers.arm(Instant::now() + Duration::from_nanos(abs_to_ns(size)), super::timer::Action::Workq(Call::Quantum(tid)));
        self.wqt(tid).quantum_call = Some(key);
    }

    /// `thread_disarm_workqueue_quantum`.
    fn workq_disarm_quantum(&mut self, tid: i32) {
        let t = self.wqt(tid);
        t.quantum_deadline = 0;
        t.quantum_expired = false;
        if let Some(key) = t.quantum_call.take() {
            self.dtask.timers.cancel(key);
        }
    }

    /// The quantum's check (the scheduler's at quantum expiry): an expired
    /// quantum (`runtime > deadline`, thread_evaluate_workqueue_quantum_
    /// expiry) is delivered (`kevent_ast`'s
    /// `workq_kern_quantum_expiry_reevaluate`), an unexpired one checked
    /// again when it could next expire, once the thread has run past the
    /// deadline.
    fn workq_quantum_check(&mut self, m: &mut GuestMem<'_>, tid: i32) {
        if !self.darwin_is_wq_thread(tid) {
            return;
        }
        self.wqt(tid).quantum_call = None;
        let deadline = self.wqt(tid).quantum_deadline;
        if deadline == 0 {
            return;
        }
        let Some(runtime) = thread_runtime(tid) else { return };
        if runtime <= deadline {
            let left = deadline - runtime + 1;
            let key = self.dtask.timers.arm(Instant::now() + Duration::from_nanos(abs_to_ns(left)), super::timer::Action::Workq(Call::Quantum(tid)));
            self.wqt(tid).quantum_call = Some(key);
            return;
        }
        self.workq_kern_quantum_expiry_reevaluate(m, tid);
    }

    /// `workq_kern_quantum_expiry_reevaluate`.
    fn workq_kern_quantum_expiry_reevaluate(&mut self, m: &mut GuestMem<'_>, tid: i32) {
        const NARROW: u64 = 0x1;
        const SHUFFLE: u64 = 0x2;
        if self.wqt(tid).flags & ut::DYING != 0 {
            return;
        }
        let q = self.wqt(tid).pri.qos_bucket;
        let mut flags = 0u64;
        if self.workq_thread_is_cooperative(tid) {
            flags |= if self.workq_cooperative_allowance(q, Some(tid), false) { SHUFFLE } else { NARROW };
        } else if self.workq_thread_is_nonovercommit(tid) && self.workq_constrained_allowance(q, Some(tid), false) == 0 {
            flags |= NARROW;
        }
        // kevent_set_workq_quantum_expiry_user_tsd: at the thread's TSD.
        if flags != 0 {
            let tsd = m.read_u64(self.darwin_ctx_of(tid) + ctx::TPIDRRO as u64).unwrap_or(0);
            if tsd != 0 {
                let _ = m.write_u64(tsd + self.dtask.pthread.wq_quantum_offset, flags);
            }
        }
        self.workq_arm_quantum(tid);
    }

    // -- the kqueue side: kevent's thread requests ------------------------------------------

    /// `kqueue_threadreq_workloop_param`.
    fn workloop_param(&mut self, id: ReqId) -> u64 {
        assert!(self.req(id).flags & tr::WORKLOOP != 0, "a workloop's request");
        self.kqueue_threadreq_workloop_param(id)
    }

    /// A kqueue's thread request, idle (`kqwq_request`, `kqwl_request`).
    pub(crate) fn darwin_workq_new_req(&mut self, flags: u8, qos_index: u8, kq: u64) -> ReqId {
        self.threadreq_alloc(Req { flags, kq_qos_index: qos_index, kq: Some(kq), ..Req::default() })
    }

    /// A kqueue's thread request is freed with its kqueue.
    pub(crate) fn darwin_workq_free_req(&mut self, id: ReqId) {
        self.dtask.threadreqs.remove(&id);
    }

    pub(crate) fn darwin_workq_req(&self, id: ReqId) -> Req {
        self.dtask.threadreqs[&id]
    }

    pub(crate) fn darwin_workq_req_mut(&mut self, id: ReqId) -> &mut Req {
        self.req(id)
    }

    /// The request a thread is bound to (`uu_kqr_bound`).
    pub(crate) fn darwin_kqr_bound(&self, tid: i32) -> Option<ReqId> {
        self.dtask.threads.map.get(&tid).and_then(|t| t.wq.as_ref()).and_then(|w| w.kqr_bound)
    }

    pub(crate) fn darwin_set_kqr_bound(&mut self, tid: i32, req: Option<ReqId>) {
        self.wqt(tid).kqr_bound = req;
    }

    /// `workq_is_exiting`.
    pub(crate) fn darwin_workq_is_exiting(&self) -> bool {
        self.dtask.workq.as_ref().map_or(true, |w| w.flags & wqf::EXITING != 0)
    }

    /// `workq_threadreq_admissible`.
    fn workq_threadreq_admissible(&mut self, tid: i32, req: ReqId) -> bool {
        let r = *self.req(req);
        if r.qos == QOS_MANAGER {
            return self.workq_may_start_event_mgr_thread(Some(tid));
        }
        if Self::tr_is_cooperative(r.flags) {
            return self.workq_cooperative_allowance(r.qos, Some(tid), true);
        }
        if Self::tr_is_nonovercommit(r.flags) {
            return self.workq_constrained_allowance(r.qos, Some(tid), true) != 0;
        }
        true
    }

    /// `workq_kern_threadreq_initiate`: a kqueue asks for a thread at
    /// `q`; false when the workqueue is going away.
    pub(crate) fn darwin_workq_threadreq_initiate(&mut self, req: ReqId, mut q: u8, flags: u32) -> bool {
        if self.req(req).flags & tr::WL_OUTSIDE_QOS != 0 {
            let trp = self.workloop_param(req);
            q = qos_for_pri((trp >> 16) as u8);
            if q == qos::UNSPECIFIED {
                q = QOS_ABOVEUI;
            }
        }
        let r = self.req(req);
        r.count = 1;
        r.state = tr::NEW;
        r.qos = q;
        // ATTEMPT_REBIND: the thread unbinding from this workloop may take
        // the request again at once.
        let uth = if flags & kflags::ATTEMPT_REBIND != 0 { Some(self.tid) } else { None };
        if self.dtask.workq.is_none() || self.wq_exiting() {
            self.req(req).state = tr::IDLE;
            return false;
        }
        match uth {
            Some(t) if self.workq_threadreq_admissible(t, req) => {
                let bucket_ = self.wqt(t).pri.qos_bucket;
                if bucket_ != q {
                    self.thactive_move(bucket_, q);
                    self.workq_thread_reset_pri(t, Some(req), false);
                }
                self.wq().fulfilled += 1;
                self.kqueue_threadreq_bind(req, t);
            }
            _ => {
                if self.workq_threadreq_enqueue(req) {
                    self.workq_schedule_creator(flags);
                }
            }
        }
        true
    }

    /// `workq_kern_threadreq_modify`: a queued kqueue request moves to
    /// `q`, or becomes overcommit.
    pub(crate) fn darwin_workq_threadreq_modify(&mut self, req: ReqId, q: u8, flags: u32) {
        if self.req(req).flags & tr::WL_OUTSIDE_QOS != 0 {
            return;
        }
        if self.req(req).state == tr::BINDING {
            let t = self.req(req).thread.expect("a binding request's thread");
            self.kqueue_threadreq_bind(req, t);
            return;
        }
        let make_overcommit = flags & kflags::MAKE_OVERCOMMIT != 0 && Self::tr_is_nonovercommit(self.req(req).flags);
        if self.wq_exiting() || (self.req(req).qos == q && !make_overcommit) {
            return;
        }
        assert_eq!(self.req(req).state, tr::QUEUED, "a thread request being modified is queued");
        let flags0 = self.req(req).flags;
        let (wq, reqs) = self.wq_and_reqs();
        if Self::queue_for(wq, flags0).remove(req, reqs) && Self::tr_is_nonovercommit(flags0) {
            self.thactive_refresh_best_constrained_req_qos();
        }
        if make_overcommit {
            self.req(req).flags ^= tr::OVERCOMMIT;
        }
        self.req(req).qos = q;
        let flags1 = self.req(req).flags;
        let (wq, reqs) = self.wq_and_reqs();
        if let Some(max) = Self::queue_for(wq, flags1).max(reqs) {
            if reqs[&max].qos >= q {
                let pri = self.workq_priority_for_req(req);
                let (wq, reqs) = self.wq_and_reqs();
                wq.next_seq += 1;
                let r = reqs.get_mut(&req).expect("a request");
                r.pri = pri;
                r.seq = wq.next_seq;
                Self::queue_for(wq, flags1).insert(req, reqs);
                return;
            }
        }
        // The request becomes the highest of its queue: it is put back as
        // new, which may run the creator.
        self.wq().reqcount -= 1;
        self.req(req).state = tr::NEW;
        if self.workq_threadreq_enqueue(req) {
            self.workq_schedule_creator(flags);
        }
    }

    /// `workq_kern_threadreq_redrive`.
    pub(crate) fn darwin_workq_threadreq_redrive(&mut self, m: &mut GuestMem<'_>, flags: u32) {
        if self.dtask.workq.is_some() {
            self.workq_schedule_creator_m(m, flags);
        }
    }

    /// `workq_thread_set_max_qos`: the bound thread delivers events of a
    /// workloop whose requested QoS is this.
    pub(crate) fn darwin_workq_thread_set_max_qos(&mut self, req: ReqId) {
        let tid = self.tid;
        let q = self.req(req).kq_qos_index;
        if self.wqt(tid).pri.qos_max == q {
            return;
        }
        let old = self.wqt(tid).pri;
        let mut new = old;
        new.qos_max = q;
        self.workq_thread_update_bucket(tid, old, new, false);
    }

    /// The override a kqueue puts on the thread servicing it
    /// (`uu_kqueue_override`).
    pub(crate) fn darwin_kqueue_override(&self, tid: i32) -> u8 {
        self.dtask.threads.map.get(&tid).and_then(|t| t.wq.as_ref()).map_or(0, |w| w.kqueue_override)
    }

    pub(crate) fn darwin_set_kqueue_override(&mut self, tid: i32, q: u8) {
        self.wqt(tid).kqueue_override = q;
    }

    /// libpthread's `workq_kevent`: the events delivered to a thread on
    /// its way to user space, below its `pthread_t` on its stack; their
    /// address and count, with the stack's new top. `None` and no events
    /// when there are none or the call failed.
    fn workq_kevent(&mut self, m: &mut GuestMem<'_>, selfp: u64, eventlist: u64, nevents: i32, flags: u32) -> (Result<(), Errno>, u64, i32, Option<u64>) {
        let kevent_list = selfp - WQ_KEVENT_LIST_LEN as u64 * super::kevent::Kev::QOS_SIZE as u64;
        let data_buf = kevent_list - WQ_KEVENT_DATA_SIZE;
        let mut data_available = WQ_KEVENT_DATA_SIZE;
        let r = self.darwin_kevent_workq_internal(m, eventlist, nevents, kevent_list, WQ_KEVENT_LIST_LEN, data_buf, &mut data_available, flags);
        match r {
            Ok(n) if n != -1 => (Ok(()), kevent_list, n, Some((data_buf + data_available) & !(STK_ALIGN - 1))),
            Ok(_) => (Ok(()), 0, 0, None),
            Err(e) => (Err(e), 0, 0, None),
        }
    }

    /// libpthread's `workq_handle_stack_events`: a kevent-bound thread
    /// returns with events to deliver and acknowledges what it handled;
    /// with more ready it goes straight back to user space with them.
    fn workq_handle_stack_events(&mut self, m: &mut GuestMem<'_>, tid: i32, eventlist: u64, nevents: i32, upcall_flags: u32) -> Result<Option<SyscallOutcome>, Errno> {
        let page = super::mach::PAGE_MASK + 1;
        let stackaddr = self.wqt(tid).stackaddr;
        let kport = self.wqt(tid).thport;
        let selfp = stackaddr + PTH_DEFAULT_STACKSIZE + page + PTHREAD_T_OFFSET;
        let flags = super::kevent::kf::STACK_DATA | super::kevent::kf::IMMEDIATE | super::kevent::kf::PARKING;
        let (r, list, count, top) = self.workq_kevent(m, selfp, eventlist, nevents, flags);
        r?;
        if count == 0 {
            return Ok(None);
        }
        // thread_set_voucher_name(MACH_PORT_NULL): the thread adopts no
        // voucher; it holds none, vouchers not being made by this kernel.
        let stack_top = top.unwrap_or(selfp & !(STK_ALIGN - 1));
        Ok(Some(self.workq_set_register_state(m, tid, selfp, stack_top, stackaddr + page, kport, list, upcall_flags, count)))
    }

    // -- bsdthread_ctl --------------------------------------------------------------------

    /// `bsdthread_ctl(cmd, arg1, arg2, arg3)`.
    pub(crate) fn darwin_bsdthread_ctl(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        const SET_QOS: u64 = 0x10;
        const QOS_OVERRIDE_START: u64 = 0x40;
        const QOS_OVERRIDE_END: u64 = 0x80;
        const SET_SELF: u64 = 0x100;
        const QOS_OVERRIDE_RESET: u64 = 0x200;
        const QOS_OVERRIDE_DISPATCH: u64 = 0x400;
        const QOS_DISPATCH_ASYNCHRONOUS_OVERRIDE_ADD: u64 = 0x401;
        const QOS_DISPATCH_ASYNCHRONOUS_OVERRIDE_RESET: u64 = 0x402;
        const QOS_MAX_PARALLELISM: u64 = 0x800;
        const WORKQ_ALLOW_KILL: u64 = 0x1000;
        const DISPATCH_APPLY_ATTR: u64 = 0x2000;
        const WORKQ_ALLOW_SIGMASK: u64 = 0x4000;
        let (cmd, arg1, arg2, arg3) = (a[0], a[1], a[2], a[3]);
        let r = match cmd {
            QOS_OVERRIDE_START => self.bsdthread_add_explicit_override(arg1 as u32, arg2, arg3),
            QOS_OVERRIDE_END => {
                if arg3 != 0 {
                    return Err(Errno::EINVAL);
                }
                self.bsdthread_remove_explicit_override(arg1 as u32, arg2)
            }
            QOS_OVERRIDE_DISPATCH => self.workq_thread_add_dispatch_override(m, arg1 as u32, arg2, arg3),
            QOS_OVERRIDE_RESET => self.workq_thread_reset_dispatch_override(),
            SET_SELF => self.bsdthread_set_self(arg1, arg2 as u32, arg3 as u32),
            QOS_MAX_PARALLELISM => {
                if arg3 != 0 {
                    return Err(Errno::EINVAL);
                }
                bsdthread_get_max_parallelism(arg1 as u8, arg2)
            }
            WORKQ_ALLOW_KILL => {
                if arg2 != 0 || arg3 != 0 {
                    return Err(Errno::EINVAL);
                }
                let tid = self.tid;
                if self.darwin_is_wq_thread(tid) {
                    self.wqt(tid).kill_allowed = arg1 != 0;
                }
                Ok(0)
            }
            // thread_shared_rsrc_policy_set: cluster shared-resource
            // policies exist only on AMP machines.
            DISPATCH_APPLY_ATTR => match arg1 {
                1 => Err(Errno::EOPNOTSUPP),
                2 => Err(Errno::EINVAL),
                _ => Err(Errno::EINVAL),
            },
            WORKQ_ALLOW_SIGMASK => {
                let mask = arg1 as i32 as u32;
                if mask & dsig::WORKQ_THREADMASK != 0 {
                    Err(Errno::EINVAL)
                } else {
                    self.dtask.workq_allow_sigmask |= mask;
                    Ok(0)
                }
            }
            SET_QOS | QOS_DISPATCH_ASYNCHRONOUS_OVERRIDE_ADD | QOS_DISPATCH_ASYNCHRONOUS_OVERRIDE_RESET => Err(Errno::EOPNOTSUPP),
            _ => Err(Errno::EINVAL),
        };
        self.workq_start_woken(m);
        r
    }

    /// Whether `__pthread_kill` refuses thread `tid`: a workqueue thread
    /// that has not allowed it, in a process that allowed no signals.
    pub(crate) fn darwin_workq_refuses_kill(&self, tid: i32) -> bool {
        let allowed = self.dtask.threads.map.get(&tid).and_then(|t| t.wq.as_ref()).map(|t| t.kill_allowed);
        matches!(allowed, Some(false)) && self.dtask.workq_allow_sigmask == 0
    }

    /// `bsdthread_add_explicit_override`.
    fn bsdthread_add_explicit_override(&mut self, kport: u32, pp_: u64, resource: u64) -> Result<u64, Errno> {
        let q = pp::qos(pp_);
        if q == qos::UNSPECIFIED {
            return Err(Errno::EINVAL);
        }
        let Some(tid) = self.darwin_name_to_thread(kport) else { return Err(Errno::ESRCH) };
        self.darwin_qos_add_override(tid, q, true, resource, OVERRIDE_TYPE_PTHREAD_EXPLICIT_OVERRIDE);
        Ok(0)
    }

    /// `bsdthread_remove_explicit_override`.
    fn bsdthread_remove_explicit_override(&mut self, kport: u32, resource: u64) -> Result<u64, Errno> {
        let Some(tid) = self.darwin_name_to_thread(kport) else { return Err(Errno::ESRCH) };
        self.darwin_qos_remove_override(tid, resource, OVERRIDE_TYPE_PTHREAD_EXPLICIT_OVERRIDE, false);
        Ok(0)
    }

    /// `workq_thread_add_dispatch_override`.
    fn workq_thread_add_dispatch_override(&mut self, m: &mut GuestMem<'_>, kport: u32, pp_: u64, ulock_addr: u64) -> Result<u64, Errno> {
        let q = pp::qos(pp_);
        if q == qos::UNSPECIFIED {
            return Err(Errno::EINVAL);
        }
        let Some(tid) = self.darwin_name_to_thread(kport) else { return Err(Errno::ESRCH) };
        if !self.darwin_is_wq_thread(tid) {
            return Err(Errno::EPERM);
        }
        if ulock_addr != 0 {
            // ulock_owner_value_to_port_name: the owner's name, its low two
            // bits set back.
            if let Ok(v) = m.read_u32(ulock_addr) {
                if v | 3 != kport {
                    return Ok(0);
                }
            }
        }
        let old = self.wqt(tid).pri;
        if old.qos_override >= q {
        } else if tid == self.tid {
            let new = Pri { qos_override: q, ..old };
            self.workq_thread_update_bucket(tid, old, new, false);
        } else {
            let t = self.wqt(tid);
            t.pri.qos_override = q;
            if q > old.override_() {
                t.sched_override = q;
            }
        }
        Ok(0)
    }

    /// `workq_thread_reset_dispatch_override` for the calling thread.
    fn workq_thread_reset_dispatch_override(&mut self) -> Result<u64, Errno> {
        let tid = self.tid;
        if !self.darwin_is_wq_thread(tid) {
            return Err(Errno::EPERM);
        }
        let old = self.wqt(tid).pri;
        let new = Pri { qos_override: qos::UNSPECIFIED, ..old };
        self.workq_thread_update_bucket(tid, old, new, false);
        Ok(0)
    }

    /// `bsdthread_set_self(priority, voucher, flags)`.
    fn bsdthread_set_self(&mut self, priority: u64, voucher: u32, flags: u32) -> Result<u64, Errno> {
        const QOS_FLAG: u32 = 0x01;
        const VOUCHER_FLAG: u32 = 0x02;
        const FIXEDPRIORITY_FLAG: u32 = 0x04;
        const TIMESHARE_FLAG: u32 = 0x08;
        const WQ_KEVENT_UNBIND: u32 = 0x10;
        const QOS_OVERRIDE_FLAG: u32 = 0x40;
        let tid = self.tid;
        let is_wq = self.darwin_is_wq_thread(tid);
        let (mut unbind_rv, mut qos_rv, mut voucher_rv, mut fixedpri_rv) = (None, None, None, None);
        if flags & WQ_KEVENT_UNBIND != 0 {
            if !is_wq || self.wqt(tid).pri.qos_bucket == QOS_MANAGER {
                unbind_rv = Some(Errno::EINVAL);
            } else {
                let bound = self.wqt(tid).kqr_bound;
                match bound {
                    None => unbind_rv = Some(Errno::EALREADY),
                    Some(r) if self.req(r).flags & tr::WORKLOOP != 0 => unbind_rv = Some(Errno::EINVAL),
                    Some(r) => self.kqueue_threadreq_unbind(r),
                }
            }
        }
        if flags & (QOS_FLAG | QOS_OVERRIDE_FLAG) != 0 {
            qos_rv = self.bsdthread_set_self_qos(tid, is_wq, priority, flags & QOS_OVERRIDE_FLAG != 0).err();
        }
        if flags & VOUCHER_FLAG != 0 && self.thread_set_voucher_name(voucher) != 0 {
            voucher_rv = Some(Errno::ENOENT);
        }
        if qos_rv.is_none() {
            if flags & (FIXEDPRIORITY_FLAG | TIMESHARE_FLAG) != 0 {
                if is_wq {
                    fixedpri_rv = Some(Errno::EOPNOTSUPP);
                } else {
                    let ts = flags & FIXEDPRIORITY_FLAG == 0;
                    self.dtask.threads.map.entry(tid).or_default().policy.timeshare = Some(ts);
                }
            }
        }
        if qos_rv.is_some() && voucher_rv.is_some() {
            return Err(Errno::EBADMSG);
        }
        if let Some(e) = unbind_rv.or(qos_rv).or(voucher_rv).or(fixedpri_rv) {
            return Err(e);
        }
        Ok(0)
    }

    /// `bsdthread_set_self`'s QoS part.
    fn bsdthread_set_self_qos(&mut self, tid: i32, is_wq: bool, priority: u64, as_override: bool) -> Result<(), Errno> {
        let (q, relpri) = (pp::qos(priority), pp::relpri(priority));
        if q == qos::UNSPECIFIED || relpri > 0 || relpri < tq::MIN_TIER_IMPORTANCE {
            return Err(Errno::EINVAL);
        }
        let mut qos_override = qos::UNSPECIFIED;
        if as_override {
            if !pp::has_override_qos(priority) || priority & pp::COOPERATIVE_FLAG == 0 {
                return Err(Errno::EINVAL);
            }
            qos_override = pp::override_qos(priority);
        } else if pp::has_override_qos(priority) {
            return Err(Errno::EINVAL);
        }
        let coop_pp = priority & pp::COOPERATIVE_FLAG != 0;
        let over_pp = priority & pp::OVERCOMMIT_FLAG != 0;
        if !is_wq {
            if self.dtask.threads.map.get(&tid).map_or(qos::UNSPECIFIED, |t| t.policy.qos) == qos::UNSPECIFIED {
                return Err(Errno::EPERM);
            }
        } else {
            let b = self.wqt(tid).pri.qos_bucket;
            if b == QOS_MANAGER || b == QOS_ABOVEUI {
                return Err(Errno::EINVAL);
            }
            if (self.workq_thread_is_overcommit(tid) && coop_pp) || (self.workq_thread_is_cooperative(tid) && !coop_pp) || (self.workq_thread_is_nonovercommit(tid) && coop_pp) {
                return Err(Errno::EINVAL);
            }
            let old = self.wqt(tid).pri;
            let mut new = old;
            new.qos_req = q;
            if old.qos_override < qos_override {
                new.qos_override = qos_override;
            }
            let mut force_run = false;
            if self.workq_thread_is_overcommit(tid) && !coop_pp && !over_pp {
                self.workq_thread_set_type(tid, 0);
                self.wq().constrained_threads_scheduled += 1;
            } else if self.workq_thread_is_nonovercommit(tid) && over_pp {
                self.workq_thread_set_type(tid, ut::OVERCOMMIT);
                let wq = self.wq();
                force_run = u32::from(wq.constrained_threads_scheduled) == limits().max_constrained;
                wq.constrained_threads_scheduled -= 1;
            } else if self.workq_thread_is_cooperative(tid) {
                self.wq().coop_scheduled[bucket(old.qos_req)] -= 1;
                self.wq().coop_scheduled[bucket(new.qos_req)] += 1;
                force_run = self.coop_refresh_best_req_qos();
            }
            self.workq_thread_update_bucket(tid, old, new, force_run);
            if self.workq_thread_is_overcommit(tid) {
                self.workq_disarm_quantum(tid);
            } else if self.thread_supports_cooperative_workqueue(tid) {
                self.workq_arm_quantum(tid);
            }
        }
        // thread_policy_set_internal(THREAD_QOS_POLICY)
        let p = &mut self.dtask.threads.map.entry(tid).or_default().policy;
        p.qos = q;
        p.relpri = relpri;
        Ok(())
    }

    /// `proc_thread_qos_add_override_internal` (the fine-grained mode with
    /// one override for every mutex).
    fn darwin_qos_add_override(&mut self, tid: i32, q: u8, first: bool, mut resource: u64, rtype: i32) {
        if rtype == OVERRIDE_TYPE_PTHREAD_MUTEX {
            resource = 0;
        }
        let ov = &mut self.dtask.threads.map.entry(tid).or_default().overrides;
        let pos = ov.iter().position(|o| o.resource == resource && o.rtype == rtype);
        let i = match (first, pos) {
            (true, Some(i)) => {
                ov[i].count += 1;
                Some(i)
            }
            (true, None) => {
                ov.insert(0, QosOverride { resource, rtype, count: 1, qos: qos::UNSPECIFIED });
                Some(0)
            }
            (false, p) => p,
        };
        if let Some(i) = i {
            ov[i].qos = if ov[i].qos == qos::UNSPECIFIED { q } else { ov[i].qos.max(q) };
        }
    }

    /// `proc_thread_qos_remove_override_internal`.
    fn darwin_qos_remove_override(&mut self, tid: i32, mut resource: u64, rtype: i32, reset: bool) {
        const RESOURCE_WILDCARD: u64 = !0;
        const TYPE_WILDCARD: i32 = 5;
        if rtype == OVERRIDE_TYPE_PTHREAD_MUTEX {
            resource = 0;
        }
        let ov = &mut self.dtask.threads.map.entry(tid).or_default().overrides;
        let mut i = 0;
        while i < ov.len() {
            if (resource == RESOURCE_WILDCARD || ov[i].resource == resource) && (rtype == TYPE_WILDCARD || ov[i].rtype == rtype) {
                if reset {
                    ov[i].count = 0;
                } else {
                    ov[i].count -= 1;
                }
                if ov[i].count == 0 {
                    ov.remove(i);
                } else {
                    i += 1;
                }
                if resource != RESOURCE_WILDCARD {
                    return;
                }
            } else {
                i += 1;
            }
        }
    }

    /// The context of thread `tid`.
    pub(crate) fn darwin_ctx_of(&self, tid: i32) -> u64 {
        if tid == self.tid {
            return self.ctx_addr;
        }
        self.dtask.threads.map.get(&tid).and_then(|t| t.wq.as_ref()).map(|t| t.ctx).expect("a workqueue thread's context")
    }
}

/// `THREAD_QOS_OVERRIDE_TYPE_*`.
const OVERRIDE_TYPE_PTHREAD_MUTEX: i32 = 1;
const OVERRIDE_TYPE_PTHREAD_EXPLICIT_OVERRIDE: i32 = 3;

/// A QoS override on a thread (`struct thread_qos_override`).
#[derive(Clone, Copy, Debug)]
pub struct QosOverride {
    pub resource: u64,
    pub rtype: i32,
    pub count: u32,
    pub qos: u8,
}

/// `bsdthread_get_max_parallelism`.
fn bsdthread_get_max_parallelism(q: u8, flags: u64) -> Result<u64, Errno> {
    const COUNT_LOGICAL: u64 = 0x1;
    const REALTIME: u64 = 0x2;
    const CLUSTER_SHARED_RESOURCE: u64 = 0x4;
    if flags & !(REALTIME | COUNT_LOGICAL | CLUSTER_SHARED_RESOURCE) != 0 {
        return Err(Errno::EINVAL);
    }
    if flags & CLUSTER_SHARED_RESOURCE != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    if flags & REALTIME != 0 {
        if q != 0 {
            return Err(Errno::EINVAL);
        }
    } else if q == qos::UNSPECIFIED || q >= qos::LAST {
        return Err(Errno::EINVAL);
    }
    // sched_qos_max_parallelism: host_info's logical or physical CPUs, both
    // the machine's 3.
    let _ = qos_for_pri;
    Ok(u64::from(super::mig::machine::NCPUS))
}

/// `workq_thread_is_busy`.
fn workq_thread_is_busy(now: u64, lastblocked: u64) -> bool {
    if now <= lastblocked {
        return true;
    }
    now - lastblocked < abs(STALLED_WINDOW)
}

fn abs_to_ns(a: u64) -> u64 {
    (u128::from(a) * u128::from(super::mach::TIMEBASE.0) / u128::from(super::mach::TIMEBASE.1)) as u64
}

/// The running time of thread `tid`, in absolute time, from the host
/// ([`set_thread_time`]).
fn thread_runtime(tid: i32) -> Option<u64> {
    let ns = (THREAD_TIME.get()?.runtime)(tid)?;
    Some((u128::from(ns) * u128::from(super::mach::TIMEBASE.1) / u128::from(super::mach::TIMEBASE.0)) as u64)
}

struct ThreadTime {
    started: fn(i32),
    ended: fn(i32),
    runtime: fn(i32) -> Option<u64>,
}

static THREAD_TIME: std::sync::OnceLock<ThreadTime> = std::sync::OnceLock::new();

/// The host's per-thread clocks: what a guest thread's host thread notes as
/// it starts and forgets as it ends, and its running time in nanoseconds.
pub fn set_thread_time(started: fn(i32), ended: fn(i32), runtime: fn(i32) -> Option<u64>) {
    let _ = THREAD_TIME.set(ThreadTime { started, ended, runtime });
}

/// A guest thread starts on the calling host thread.
pub fn thread_started(tid: i32) {
    if let Some(t) = THREAD_TIME.get() {
        (t.started)(tid);
    }
}

/// Guest thread `tid` has ended.
pub fn thread_ended(tid: i32) {
    if let Some(t) = THREAD_TIME.get() {
        (t.ended)(tid);
    }
}
