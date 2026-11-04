//! psynch: the kernel half of libpthread's mutexes, condition variables
//! and read-write locks, ported from libpthread's `kern/kern_synch.c`.
//!
//! Userland keeps each object's sequence words (L, U and S) and comes to
//! the kernel only to wait or to hand the object on. The kernel keeps a
//! wait queue per object address (`ksyn_wait_queue`) with the waiters in
//! sequence order, preposts for wakeups that arrived before their waiter,
//! and interrupted-wakeup records, and answers with update bits userland
//! folds back into its words.

use super::bsd::sys;
use super::thread::bsd_result;
use super::wait::{Wait, WaitResult};
use crate::errno::Errno;
use crate::syscalls::{Kernel, SyscallOutcome};
use crate::GuestMem;
use gex_abi::ctx;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

// Sequence words (`synch_internal.h`).
const PTHRW_COUNT_SHIFT: u32 = 8;
const PTHRW_INC: u32 = 1 << PTHRW_COUNT_SHIFT;
const PTHRW_BIT_MASK: u32 = PTHRW_INC - 1;
const PTHRW_COUNT_MASK: u32 = !PTHRW_BIT_MASK;
const PTHRW_MAX_READERS: u32 = PTHRW_COUNT_MASK;

const PTH_RWL_KBIT: u32 = 0x01;
const PTH_RWL_EBIT: u32 = 0x02;
const PTH_RWL_WBIT: u32 = 0x04;
const PTH_RWL_MTX_WAIT: u32 = 0x20;
const PTH_RWL_MBIT: u32 = 0x40;
const PTH_RWL_IBIT: u32 = 0x80;
const PTHRW_RWL_INIT: u32 = PTH_RWL_IBIT;

const PTH_RWS_SBIT: u32 = 0x01;
const PTH_RWS_CV_CBIT: u32 = PTH_RWS_SBIT;
const PTH_RWS_CV_PBIT: u32 = 0x02;
const PTH_RWS_CV_MBIT: u32 = PTH_RWL_MBIT;
const PTH_RWS_WSVBIT: u32 = 0x04;
const PTHRW_RWS_SAVEMASK: u32 = PTH_RWS_WSVBIT;
const PTHRW_RWS_INIT: u32 = PTH_RWS_SBIT;

// Mutex and object option flags.
const PTHREAD_PROCESS_SHARED: u32 = 0x010;
const PTHREAD_PSHARED_FLAGS_MASK: u32 = 0x30;
const POLICY_FIRSTFIT: u32 = 0x080;
const POLICY_MASK: u32 = 0x1c0;
const MTX_OPT_MUTEX: u32 = 0x2000;

// Read-write lock types.
const PTH_RW_TYPE_READ: u32 = 0x01;
const PTH_RW_TYPE_WRITE: u32 = 0x04;
const PTH_RW_TYPE_MASK: u32 = 0xff;
const PTH_RWSHFT_TYPE_READ: u32 = 0x0100;
const PTH_RWSHFT_TYPE_WRITE: u32 = 0x0400;
const PTH_RWSHFT_TYPE_MASK: u32 = 0xff00;

const KW_UNLOCK_PREPOST: u32 = 0x01;
const KW_UNLOCK_PREPOST_READLOCK: u32 = 0x08;
const KW_UNLOCK_PREPOST_WRLOCK: u32 = 0x20;

/// Condition-variable wait's extra results.
const ECVCLEARED: i32 = 0x100;
const ECVPREPOST: i32 = 0x200;

/// How long an idle read-write lock queue is kept (seconds).
const KSYN_CLEANUP_DEADLINE: u64 = 10;

fn is_seqlower(x: u32, y: u32) -> bool {
    let (x, y) = (x & PTHRW_COUNT_MASK, y & PTHRW_COUNT_MASK);
    if x < y {
        (y - x) < (PTHRW_MAX_READERS / 2)
    } else {
        (x - y) > (PTHRW_MAX_READERS / 2)
    }
}

fn is_seqlower_eq(x: u32, y: u32) -> bool {
    (x & PTHRW_COUNT_MASK) == (y & PTHRW_COUNT_MASK) || is_seqlower(x, y)
}

fn is_seqhigher(x: u32, y: u32) -> bool {
    let (x, y) = (x & PTHRW_COUNT_MASK, y & PTHRW_COUNT_MASK);
    if x > y {
        (x - y) < (PTHRW_MAX_READERS / 2)
    } else {
        (y - x) > (PTHRW_MAX_READERS / 2)
    }
}

fn is_seqhigher_eq(x: u32, y: u32) -> bool {
    (x & PTHRW_COUNT_MASK) == (y & PTHRW_COUNT_MASK) || is_seqhigher(x, y)
}

fn diff_genseq(x: u32, y: u32) -> u32 {
    let (x, y) = (x & PTHRW_COUNT_MASK, y & PTHRW_COUNT_MASK);
    if x == y {
        0
    } else if x > y {
        x - y
    } else {
        (PTHRW_MAX_READERS - y).wrapping_add(x).wrapping_add(PTHRW_INC)
    }
}

fn find_diff(upto: u32, lowest: u32) -> u32 {
    if upto == lowest {
        return 0;
    }
    let diff = if is_seqlower(upto, lowest) { diff_genseq(lowest, upto) } else { diff_genseq(upto, lowest) };
    diff >> PTHRW_COUNT_SHIFT
}

/// What a wait queue holds a sequence number for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KweState {
    /// A thread waiting.
    InWait,
    /// A signal that arrived before its waiter.
    Prepost,
    /// A broadcast that arrived before its waiters.
    Broadcast,
}

/// A wait queue element (`ksyn_waitq_element`): a waiting thread, or a
/// prepost standing in for one.
#[derive(Clone, Copy, Debug)]
struct Kwe {
    state: KweState,
    lockseq: u32,
    count: u32,
    /// The waiting thread (`InWait`).
    tid: Option<i32>,
}

/// One of a queue's two lists (`ksyn_queue`).
#[derive(Clone, Debug, Default)]
struct Ksynq {
    list: VecDeque<Kwe>,
    firstnum: u32,
    lastnum: u32,
}

const READ: usize = 0;
const WRITE: usize = 1;

/// Which kind of object a queue serves (`KSYN_WQTYPE_*`).
mod wqtype {
    pub const INWAIT: u32 = 0x1000;
    pub const INDROP: u32 = 0x2000;
    pub const MTX: u32 = 0x01;
    pub const CVAR: u32 = 0x02;
    pub const RWLOCK: u32 = 0x04;
    pub const MASK: u32 = 0xff;
    pub const MUTEXDROP: u32 = INDROP | MTX;
}

// `kw_kflags`.
const KSYN_KWF_INITCLEARED: u32 = 0x1;
const KSYN_KWF_ZEROEDOUT: u32 = 0x2;
const KSYN_KWF_OVERLAP_GUARD: u32 = 0x8;

/// The interrupted-wakeup kinds (`kwq_intr_type_t`).
const KWQ_INTR_NONE: u32 = 0;
const KWQ_INTR_READ: u32 = 0x1;
const KWQ_INTR_WRITE: u32 = 0x2;

#[derive(Clone, Copy, Debug, Default)]
struct Prepost {
    count: u32,
    lseq: u32,
    sseq: u32,
}

#[derive(Clone, Copy, Debug, Default)]
struct Intr {
    kind: u32,
    count: u32,
    seq: u32,
    returnbits: u32,
}

/// A psynch object's kernel wait queue (`ksyn_wait_queue`).
#[derive(Clone, Debug, Default)]
struct Kwq {
    owner: Option<i32>,
    iocount: u32,
    dropcount: u32,
    kind: u32,
    kflags: u32,
    inqueue: u32,
    fakecount: u32,
    highseq: u32,
    lowseq: u32,
    lword: u32,
    uword: u32,
    sword: u32,
    lastunlockseq: u32,
    lastseqword: u32,
    nextseqword: u32,
    prepost: Prepost,
    intr: Intr,
    queues: [Ksynq; 2],
    /// On the free list since this many seconds of uptime.
    freed_at: Option<u64>,
}

/// A waiting thread's element as it left it: the update bits a signal
/// gave it, and whether it is still queued.
#[derive(Clone, Copy, Debug, Default)]
struct UuKwe {
    retval: u32,
    queued: bool,
}

/// The process's psynch wait queues, by address.
#[derive(Debug, Default)]
pub struct Psynch {
    kwqs: HashMap<u64, Kwq>,
    /// Per thread: its element (`uu_kwe`).
    uukwe: HashMap<i32, UuKwe>,
    /// The delayed cleanup of idle queues (`psynch_wq_cleanup`): when it
    /// next runs, in seconds of uptime.
    cleanup_at: Option<u64>,
}

/// Seconds of uptime, as `microuptime` gives them.
fn uptime_secs() -> u64 {
    super::mach::uptime().as_secs()
}

/// How a blocked psynch call finishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cont {
    Mutex { addr: u64 },
    Cv { addr: u64 },
    Rw { addr: u64, kqi: u8 },
}

impl Kwq {
    fn is_used(&self) -> bool {
        self.inqueue != 0 || self.prepost.count != 0 || self.intr.count != 0
    }

    fn clear_preposted_wakeup(&mut self) {
        self.prepost = Prepost { count: 0, lseq: 0, sseq: PTHRW_RWS_INIT };
    }

    fn mark_preposted_wakeup(&mut self, count: u32, lseq: u32, sseq: u32) {
        self.prepost = Prepost { count, lseq, sseq };
    }

    fn clear_interrupted_wakeup(&mut self) {
        self.intr = Intr { kind: KWQ_INTR_NONE, count: 0, seq: 0, returnbits: 0 };
    }

    fn mark_interrupted_wakeup(&mut self, kind: u32, count: u32, seq: u32, returnbits: u32) {
        self.intr = Intr { kind, count, seq, returnbits };
    }

    /// `CLEAR_REINIT_BITS`.
    fn clear_reinit_bits(&mut self) {
        if self.kind & wqtype::MASK == wqtype::RWLOCK {
            self.nextseqword = PTHRW_RWS_INIT;
            self.kflags &= !KSYN_KWF_OVERLAP_GUARD;
        }
        self.clear_preposted_wakeup();
        self.lastunlockseq = PTHRW_RWL_INIT;
        self.lastseqword = PTHRW_RWS_INIT;
        self.clear_interrupted_wakeup();
        self.lword = 0;
        self.uword = 0;
        self.sword = PTHRW_RWS_INIT;
    }

    /// `UPDATE_CVKWQ`.
    fn update_cv(&mut self, mgen: u32, ugen: u32, rw_wc: u32) {
        let sinit = rw_wc & PTH_RWS_CV_CBIT != 0;
        if self.kflags & KSYN_KWF_ZEROEDOUT != 0 {
            self.lword = mgen;
            self.uword = ugen;
            self.sword = rw_wc;
            self.kflags &= !KSYN_KWF_ZEROEDOUT;
        } else {
            if is_seqhigher(mgen, self.lword) {
                self.lword = mgen;
            }
            if is_seqhigher(ugen, self.uword) {
                self.uword = ugen;
            }
            if sinit && is_seqhigher(rw_wc, self.sword) {
                self.sword = rw_wc;
            }
        }
        if sinit && is_seqlower(self.lastunlockseq, rw_wc) {
            self.lastunlockseq = rw_wc & PTHRW_COUNT_MASK;
        }
    }

    /// `_ksyn_check_init`.
    fn check_init(&mut self, lgenval: u32) -> bool {
        let res = lgenval & PTHRW_RWL_INIT != 0;
        if res && self.kflags & KSYN_KWF_INITCLEARED == 0 {
            self.clear_reinit_bits();
            self.kflags |= KSYN_KWF_INITCLEARED;
        }
        res
    }

    fn update_low_high(&mut self, lockseq: u32) {
        if self.inqueue == 1 {
            self.lowseq = lockseq;
            self.highseq = lockseq;
        } else {
            if is_seqlower(lockseq, self.lowseq) {
                self.lowseq = lockseq;
            }
            if is_seqhigher(lockseq, self.highseq) {
                self.highseq = lockseq;
            }
        }
    }

    fn find_nextlowseq(&self) -> u32 {
        let mut lowest = None;
        for q in &self.queues {
            if !q.list.is_empty() {
                let current = q.firstnum;
                if lowest.is_none_or(|l| is_seqlower(current, l)) {
                    lowest = Some(current);
                }
            }
        }
        lowest.unwrap_or(0)
    }

    fn find_nexthighseq(&self) -> u32 {
        let mut highest = None;
        for q in &self.queues {
            if !q.list.is_empty() {
                let current = q.lastnum;
                if highest.is_none_or(|h| is_seqhigher(current, h)) {
                    highest = Some(current);
                }
            }
        }
        highest.unwrap_or(0)
    }

    /// `ksyn_queue_insert`; `firstfit` appends rather than ordering by
    /// sequence. `Err` is the errno a refused element gets.
    fn insert(&mut self, kqi: usize, kwe: Kwe, mgen: u32, firstfit: bool, cancelled: &dyn Fn(i32) -> bool) -> Result<(), Errno> {
        let lockseq = mgen & PTHRW_COUNT_MASK;
        let q = &mut self.queues[kqi];
        if q.list.is_empty() {
            q.list.push_front(kwe);
            q.firstnum = lockseq;
            q.lastnum = lockseq;
        } else if firstfit {
            q.list.push_back(kwe);
            if is_seqlower(lockseq, q.firstnum) {
                q.firstnum = lockseq;
            }
            if is_seqhigher(lockseq, q.lastnum) {
                q.lastnum = lockseq;
            }
        } else if lockseq == q.firstnum || lockseq == q.lastnum {
            // A prepost may take the place of a cancelled waiter's.
            let mut ok = false;
            if kwe.state == KweState::Prepost {
                let found = q.list.iter().find(|k| k.lockseq & PTHRW_COUNT_MASK == lockseq);
                if let Some(t) = found.and_then(|k| k.tid) {
                    if cancelled(t) {
                        q.list.push_back(kwe);
                        ok = true;
                    }
                }
            }
            if !ok {
                return Err(Errno::EBUSY);
            }
        } else if is_seqlower(q.lastnum, lockseq) {
            q.list.push_back(kwe);
            q.lastnum = lockseq;
        } else if is_seqlower(lockseq, q.firstnum) {
            q.list.push_front(kwe);
            q.firstnum = lockseq;
        } else {
            match q.list.iter().position(|k| is_seqhigher(k.lockseq, lockseq)) {
                Some(i) => q.list.insert(i, kwe),
                None => return Err(Errno::ESRCH),
            }
        }
        self.inqueue += 1;
        self.update_low_high(lockseq);
        Ok(())
    }

    /// `ksyn_queue_remove_item`, by position.
    fn remove_at(&mut self, kqi: usize, i: usize) -> Kwe {
        let q = &mut self.queues[kqi];
        let kwe = q.list.remove(i).expect("removing an element that is there");
        if let (Some(first), Some(last)) = (q.list.front(), q.list.back()) {
            q.firstnum = first.lockseq & PTHRW_COUNT_MASK;
            q.lastnum = last.lockseq & PTHRW_COUNT_MASK;
        } else {
            q.firstnum = 0;
            q.lastnum = 0;
        }
        self.inqueue -= 1;
        if self.inqueue > 0 {
            let curseq = kwe.lockseq & PTHRW_COUNT_MASK;
            if self.lowseq == curseq {
                self.lowseq = self.find_nextlowseq();
            }
            if self.highseq == curseq {
                self.highseq = self.find_nexthighseq();
            }
        } else {
            self.lowseq = 0;
            self.highseq = 0;
        }
        kwe
    }

    /// Remove thread `tid`'s waiting element, if queued.
    fn remove_thread(&mut self, kqi: usize, tid: i32) -> bool {
        match self.queues[kqi].list.iter().position(|k| k.state == KweState::InWait && k.tid == Some(tid)) {
            Some(i) => {
                self.remove_at(kqi, i);
                true
            }
            None => false,
        }
    }

    fn find_seq(&self, kqi: usize, seq: u32) -> Option<usize> {
        self.queues[kqi].list.iter().position(|k| k.lockseq & PTHRW_COUNT_MASK == seq)
    }

    /// `ksyn_queue_find_cvpreposeq`.
    fn find_cvpreposeq(&self, cgen: u32) -> Option<usize> {
        let lgen = cgen & PTHRW_COUNT_MASK;
        for (i, k) in self.queues[WRITE].list.iter().enumerate() {
            if is_seqhigher_eq(k.lockseq, cgen) {
                if k.state == KweState::InWait && k.lockseq & PTHRW_COUNT_MASK != lgen {
                    return None;
                }
                return Some(i);
            }
        }
        None
    }

    /// `ksyn_queue_find_signalseq`.
    fn find_signalseq(&self, uptoseq: u32, signalseq: u32, cancelled: &dyn Fn(i32) -> bool) -> Option<usize> {
        let mut result = None;
        for (i, k) in self.queues[WRITE].list.iter().enumerate() {
            match k.state {
                KweState::Prepost | KweState::Broadcast => {
                    if k.state == KweState::Prepost && is_seqhigher(k.lockseq, uptoseq) {
                        return result;
                    }
                    if is_seqlower(k.lockseq, uptoseq) {
                        continue;
                    }
                    return Some(i);
                }
                KweState::InWait => {
                    if is_seqhigher(k.lockseq, uptoseq) {
                        return result;
                    }
                    if !cancelled(k.tid.expect("a waiting element has a thread")) {
                        if is_seqhigher_eq(k.lockseq, signalseq) {
                            return Some(i);
                        }
                        if result.is_none() {
                            result = Some(i);
                        }
                    }
                }
            }
        }
        result
    }

    /// `ksyn_queue_count_tolowest`.
    fn count_tolowest(&self, kqi: usize, upto: u32) -> u32 {
        let q = &self.queues[kqi];
        if q.list.is_empty() || is_seqhigher(q.firstnum, upto) {
            return 0;
        }
        if upto == q.firstnum {
            return 1;
        }
        let mut i = 0;
        for k in &q.list {
            let curval = k.lockseq & PTHRW_COUNT_MASK;
            if is_seqhigher(curval, upto) {
                break;
            }
            i += 1;
            if upto == curval {
                break;
            }
        }
        i
    }

    /// `find_seq_till`.
    fn find_seq_till(&self, upto: u32, nwaiters: u32) -> (bool, u32) {
        let mut count = 0;
        for kqi in [READ, WRITE] {
            count += self.count_tolowest(kqi, upto);
            if count >= nwaiters {
                break;
            }
        }
        (count != 0 && count >= nwaiters, count)
    }

    /// `kwq_find_rw_lowest`.
    fn find_rw_lowest(&self, flags: u32, premgen: u32) -> (u32, [u32; 2]) {
        let mut ty = 0;
        let mut lowest = [0u32; 2];
        let mut numbers = Vec::new();
        if !self.queues[READ].list.is_empty() || flags & KW_UNLOCK_PREPOST_READLOCK != 0 {
            ty |= PTH_RWSHFT_TYPE_READ;
            let mut fr = premgen;
            if !self.queues[READ].list.is_empty() {
                fr = self.queues[READ].firstnum;
                if flags & KW_UNLOCK_PREPOST_READLOCK != 0 && is_seqlower(premgen, fr) {
                    fr = premgen;
                }
            }
            lowest[READ] = fr;
            numbers.push((fr, PTH_RW_TYPE_READ));
        }
        if !self.queues[WRITE].list.is_empty() || flags & KW_UNLOCK_PREPOST_WRLOCK != 0 {
            ty |= PTH_RWSHFT_TYPE_WRITE;
            let mut fwr = premgen;
            if !self.queues[WRITE].list.is_empty() {
                fwr = self.queues[WRITE].firstnum;
                if flags & KW_UNLOCK_PREPOST_WRLOCK != 0 && is_seqlower(premgen, fwr) {
                    fwr = premgen;
                }
            }
            lowest[WRITE] = fwr;
            numbers.push((fwr, PTH_RW_TYPE_WRITE));
        }
        let (mut low, mut lowtype) = numbers.first().copied().unwrap_or((0, 0));
        for &(n, t) in numbers.iter().skip(1) {
            if is_seqlower(n, low) {
                low = n;
                lowtype = t;
            }
        }
        (ty | lowtype, lowest)
    }
}

/// What a signal did: the thread to wake with these update bits.
type Wakes = Vec<(i32, u32)>;

impl Psynch {
    /// `ksyn_signal`: take element `i` (or the first) off queue `kqi` and
    /// give its thread `updateval`. Whether a thread was there to wake.
    fn signal(&mut self, addr: u64, kqi: usize, i: Option<usize>, updateval: u32, wakes: &mut Wakes) -> bool {
        let kwq = self.kwqs.get_mut(&addr).expect("signalled queue exists");
        let i = i.unwrap_or(0);
        let kwe = kwq.remove_at(kqi, i);
        assert_eq!(kwe.state, KweState::InWait, "ksyn_signal: signalling a non-waiting element");
        let tid = kwe.tid.expect("waiting element has a thread");
        let u = self.uukwe.entry(tid).or_default();
        u.retval = updateval;
        u.queued = false;
        wakes.push((tid, updateval));
        true
    }

    /// `ksyn_mtxsignal`: grant the mutex to element `i` (or the first
    /// waiter), who becomes the owner.
    fn mtxsignal(&mut self, addr: u64, i: Option<usize>, updateval: u32, wakes: &mut Wakes) -> bool {
        let tid = {
            let kwq = &self.kwqs[&addr];
            kwq.queues[WRITE].list[i.unwrap_or(0)].tid
        };
        let ok = self.signal(addr, WRITE, i, updateval, wakes);
        let kwq = self.kwqs.get_mut(&addr).expect("signalled queue exists");
        kwq.owner = if ok { tid } else { None };
        ok
    }

    /// `ksyn_prepost`: queue a stand-in element.
    fn prepost(&mut self, addr: u64, state: KweState, lockseq: u32) {
        let kwq = self.kwqs.get_mut(&addr).expect("queue exists");
        let kwe = Kwe { state, lockseq, count: 1, tid: None };
        let _ = kwq.insert(WRITE, kwe, lockseq, false, &|_| false);
        kwq.fakecount += 1;
    }

    /// `ksyn_queue_free_items`.
    fn free_items(&mut self, addr: u64, kqi: usize, upto: u32, all: bool, wakes: &mut Wakes) {
        let tseq = upto & PTHRW_COUNT_MASK;
        loop {
            let kwq = self.kwqs.get_mut(&addr).expect("queue exists");
            let Some(kwe) = kwq.queues[kqi].list.front().copied() else { break };
            if !all && is_seqhigher(kwe.lockseq, tseq) {
                break;
            }
            if kwe.state == KweState::InWait {
                self.signal(addr, kqi, Some(0), PTHRW_INC | PTH_RWS_CV_MBIT | PTH_RWL_MTX_WAIT, wakes);
            } else {
                kwq.remove_at(kqi, 0);
                kwq.fakecount -= 1;
            }
        }
    }

    /// `ksyn_handle_cvbroad`.
    fn handle_cvbroad(&mut self, addr: u64, upto: u32, updatep: &mut u32, cancelled: &dyn Fn(i32) -> bool, wakes: &mut Wakes) {
        let mut updatebits = 0;
        let mut i = 0;
        loop {
            let kwq = self.kwqs.get_mut(&addr).expect("queue exists");
            let Some(kwe) = kwq.queues[WRITE].list.get(i).copied() else { break };
            if is_seqhigher(kwe.lockseq, upto) {
                break;
            }
            match kwe.state {
                KweState::InWait => {
                    if !cancelled(kwe.tid.expect("waiting element has a thread")) {
                        self.signal(addr, WRITE, Some(i), PTH_RWL_MTX_WAIT, wakes);
                        updatebits += PTHRW_INC;
                    } else {
                        i += 1;
                    }
                }
                KweState::Broadcast | KweState::Prepost => {
                    kwq.remove_at(WRITE, i);
                    kwq.fakecount -= 1;
                }
            }
        }
        let kwq = &self.kwqs[&addr];
        if diff_genseq(kwq.lword, kwq.sword) != 0 {
            self.prepost(addr, KweState::Broadcast, upto);
        }
        *updatep |= updatebits;
    }

    /// `ksyn_cvupdate_fixup`.
    fn cvupdate_fixup(&mut self, addr: u64, updatebits: &mut u32, wakes: &mut Wakes) {
        let kwq = &self.kwqs[&addr];
        if kwq.lword & PTHRW_COUNT_MASK == kwq.sword & PTHRW_COUNT_MASK {
            if kwq.inqueue != 0 {
                let lword = kwq.lword;
                self.free_items(addr, WRITE, lword, false, wakes);
            }
            let kwq = self.kwqs.get_mut(&addr).expect("queue exists");
            kwq.lword = 0;
            kwq.uword = 0;
            kwq.sword = 0;
            kwq.kflags |= KSYN_KWF_ZEROEDOUT;
            *updatebits |= PTH_RWS_CV_CBIT;
        } else if kwq.inqueue != 0 && kwq.fakecount == kwq.inqueue {
            *updatebits |= PTH_RWS_CV_PBIT;
        }
    }

    /// `ksyn_wakeupreaders`: the failed wakeups.
    fn wakeupreaders(&mut self, addr: u64, limitread: u32, allreaders: bool, updatebits: u32, wakes: &mut Wakes) -> u32 {
        loop {
            let kwq = &self.kwqs[&addr];
            let q = &kwq.queues[READ];
            if q.list.is_empty() || !(allreaders || is_seqlower(q.firstnum, limitread)) {
                break;
            }
            self.signal(addr, READ, None, updatebits, wakes);
        }
        0
    }

    /// `kwq_handle_unlock`: who the lock goes to next. Answers the update
    /// bits and whether the caller (a prepost) blocks; the caller's own
    /// grant, when it gets one, is in its element's return value.
    fn handle_unlock(&mut self, addr: u64, rw_wc: u32, flags: u32, premgen: u32, me: i32, wakes: &mut Wakes) -> (u32, bool) {
        let prepost = flags & KW_UNLOCK_PREPOST != 0;
        let kwq = self.kwqs.get_mut(&addr).expect("queue exists");
        kwq.lastseqword = rw_wc;
        kwq.lastunlockseq = rw_wc & PTHRW_COUNT_MASK;
        kwq.kflags &= !KSYN_KWF_OVERLAP_GUARD;
        let (rwtype, lowest) = kwq.find_rw_lowest(flags, premgen);
        let low_writer = lowest[WRITE];
        let mut updatebits = 0;
        let mut block = true;
        match rwtype & PTH_RW_TYPE_MASK {
            PTH_RW_TYPE_READ => {
                if rwtype & PTH_RWSHFT_TYPE_MASK != 0 && rwtype & PTH_RWSHFT_TYPE_WRITE != 0 {
                    updatebits |= PTH_RWL_WBIT | PTH_RWL_KBIT;
                }
                let mut limitrdnum = 0;
                let mut allreaders = false;
                let mut numneeded = 0;
                let mut curthreturns = false;
                if rwtype & PTH_RWSHFT_TYPE_WRITE != 0 {
                    limitrdnum = low_writer;
                    numneeded = kwq.count_tolowest(READ, limitrdnum);
                    if flags & KW_UNLOCK_PREPOST_READLOCK != 0 && is_seqlower(premgen, limitrdnum) {
                        curthreturns = true;
                        numneeded += 1;
                    }
                } else {
                    allreaders = true;
                    kwq.kflags |= KSYN_KWF_OVERLAP_GUARD;
                    numneeded += kwq.queues[READ].list.len() as u32;
                    if flags & KW_UNLOCK_PREPOST_READLOCK != 0 {
                        curthreturns = true;
                        numneeded += 1;
                    }
                }
                updatebits = updatebits.wrapping_add(numneeded << PTHRW_COUNT_SHIFT);
                kwq.nextseqword = (rw_wc & PTHRW_COUNT_MASK).wrapping_add(updatebits);
                if curthreturns {
                    block = false;
                    self.uukwe.entry(me).or_default().retval = updatebits;
                }
                let nfailed = self.wakeupreaders(addr, limitrdnum, allreaders, updatebits, wakes);
                if nfailed != 0 {
                    self.kwqs.get_mut(&addr).expect("queue exists").mark_interrupted_wakeup(KWQ_INTR_READ, nfailed, limitrdnum, updatebits);
                }
            }
            PTH_RW_TYPE_WRITE => {
                updatebits |= PTHRW_INC | PTH_RWL_KBIT | PTH_RWL_EBIT;
                if flags & KW_UNLOCK_PREPOST_WRLOCK != 0 && low_writer == premgen {
                    block = false;
                    if !kwq.queues[WRITE].list.is_empty() {
                        updatebits |= PTH_RWL_WBIT;
                    }
                    debug_assert!(prepost);
                    self.uukwe.entry(me).or_default().retval = updatebits;
                } else {
                    if kwq.queues[WRITE].list.len() > 1 || flags & KW_UNLOCK_PREPOST_WRLOCK != 0 {
                        updatebits |= PTH_RWL_WBIT;
                    }
                    self.signal(addr, WRITE, None, updatebits, wakes);
                }
                self.kwqs.get_mut(&addr).expect("queue exists").nextseqword = (rw_wc & PTHRW_COUNT_MASK).wrapping_add(updatebits);
            }
            t => panic!("rwunlock: invalid type {t:#x} for lock grants"),
        }
        (updatebits, block)
    }

    /// `_kwq_handle_preposted_wakeup`.
    fn handle_preposted_wakeup(&mut self, addr: u64, ty: u32, lseq: u32, me: i32, wakes: &mut Wakes) -> Option<u32> {
        let kwq = self.kwqs.get_mut(&addr).expect("queue exists");
        if kwq.prepost.count == 0 || !is_seqlower_eq(lseq, kwq.prepost.lseq) {
            return None;
        }
        kwq.prepost.count -= 1;
        if kwq.prepost.count > 0 {
            return None;
        }
        let pp_sseq = kwq.prepost.sseq;
        kwq.clear_preposted_wakeup();
        kwq.kflags &= !KSYN_KWF_INITCLEARED;
        let (updatebits, block) = self.handle_unlock(addr, pp_sseq, ty | KW_UNLOCK_PREPOST, lseq, me, wakes);
        if block {
            return None;
        }
        Some(updatebits)
    }

    /// `_kwq_handle_overlap`.
    fn handle_overlap(&mut self, addr: u64, ty: u32, lgenval: u32, rw_wc: u32) -> Option<u32> {
        if ty != PTH_RW_TYPE_READ {
            return None;
        }
        let kwq = self.kwqs.get_mut(&addr).expect("queue exists");
        if kwq.kflags & KSYN_KWF_OVERLAP_GUARD != 0 && rw_wc & PTHRW_RWS_SAVEMASK == 0 && lgenval & PTH_RWL_WBIT == 0 && (is_seqlower_eq(rw_wc, kwq.nextseqword) || is_seqhigher_eq(kwq.lastseqword, rw_wc)) {
            kwq.nextseqword = kwq.nextseqword.wrapping_add(PTHRW_INC);
            return Some(PTHRW_INC | (kwq.nextseqword & PTHRW_BIT_MASK) | PTH_RWL_MBIT);
        }
        None
    }

    /// `_kwq_handle_interrupted_wakeup`.
    fn handle_interrupted_wakeup(&mut self, addr: u64, kind: u32, lseq: u32) -> Option<u32> {
        let kwq = self.kwqs.get_mut(&addr).expect("queue exists");
        if kwq.intr.count != 0 && kwq.intr.kind == kind && (kwq.intr.seq == 0 || is_seqlower_eq(lseq, kwq.intr.seq)) {
            kwq.intr.count -= 1;
            let r = kwq.intr.returnbits;
            if kwq.intr.returnbits == 0 {
                kwq.clear_interrupted_wakeup();
            }
            return Some(r);
        }
        None
    }

    /// `psynch_wq_cleanup`, run as of every time it was due up to `now`.
    fn run_cleanup(&mut self, now: u64) {
        while let Some(at) = self.cleanup_at {
            if now < at {
                break;
            }
            let mut reschedule = false;
            let mut gone = Vec::new();
            for (&addr, kwq) in &self.kwqs {
                let Some(stamp) = kwq.freed_at else { continue };
                if kwq.is_used() || kwq.iocount != 0 {
                    continue;
                }
                if at.abs_diff(stamp) >= KSYN_CLEANUP_DEADLINE {
                    gone.push(addr);
                } else {
                    reschedule = true;
                }
            }
            for addr in gone {
                self.kwqs.remove(&addr);
            }
            self.cleanup_at = if reschedule { Some(at + KSYN_CLEANUP_DEADLINE) } else { None };
        }
    }

    /// `ksyn_wqfind`: the queue for `addr`, made if new, with a reference
    /// taken.
    fn wqfind(&mut self, addr: u64, mgen: u32, ugen: u32, sgen: u32, wq: u32) -> Result<(), Errno> {
        self.run_cleanup(uptime_secs());
        let kwq = self.kwqs.entry(addr).or_default();
        kwq.freed_at = None;
        if kwq.kind != 0 && kwq.kind & wqtype::MASK != wq & wqtype::MASK {
            if !kwq.is_used() {
                if kwq.iocount == 0 {
                    kwq.kind = 0;
                } else if kwq.iocount == 1 && kwq.dropcount == kwq.iocount {
                    // XNU sleeps until the dropping thread is done with the
                    // queue; under the one kernel lock it always is.
                    unreachable!("ksyn_wqfind: a drop in progress under the kernel lock");
                } else {
                    return Err(Errno::EINVAL);
                }
            } else {
                return Err(Errno::EINVAL);
            }
        }
        if kwq.kind == 0 {
            kwq.kind = wq & wqtype::MASK;
            kwq.clear_reinit_bits();
            kwq.lword = mgen;
            kwq.uword = ugen;
            kwq.sword = sgen;
            kwq.owner = None;
            kwq.kflags = 0;
        }
        kwq.iocount += 1;
        if wq == wqtype::MUTEXDROP {
            kwq.dropcount += 1;
        }
        Ok(())
    }

    /// `ksyn_wqrelease`: drop the reference; an idle queue is freed now or,
    /// with `qfreenow` false, after a delay.
    fn wqrelease(&mut self, addr: u64, qfreenow: bool, wq: u32) {
        let now = uptime_secs();
        let Some(kwq) = self.kwqs.get_mut(&addr) else { return };
        if wq == wqtype::MUTEXDROP {
            kwq.dropcount -= 1;
        }
        kwq.iocount -= 1;
        if kwq.iocount == 0 && !kwq.is_used() {
            if !qfreenow {
                kwq.freed_at = Some(now);
                if self.cleanup_at.is_none() {
                    self.cleanup_at = Some(now + KSYN_CLEANUP_DEADLINE);
                }
            } else {
                self.kwqs.remove(&addr);
            }
        }
    }
}

impl Kernel {
    /// The psynch calls; `None` for the rest.
    pub(crate) fn darwin_psynch_call(&mut self, m: &mut GuestMem<'_>, raw: u64, a: &[u64; 6]) -> Option<SyscallOutcome> {
        let x = |m: &GuestMem<'_>, k: &Kernel, i: u8| m.read_u64(k.ctx_addr + ctx::x(k.darwin_arg_base + i) as u64).unwrap_or(0);
        let r = match raw {
            sys::PSYNCH_MUTEXWAIT => return Some(self.psynch_mutexwait(m, a[0], a[1] as u32, a[2] as u32, a[3], a[4] as u32)),
            sys::PSYNCH_MUTEXDROP => self.psynch_mutexdrop(m, a[0], a[1] as u32, a[2] as u32, a[4] as u32).map(u64::from),
            sys::PSYNCH_CVBROAD => {
                // (cv, cvlsgen, cvudgen, flags, mutex, mugen, tid)
                let (cvlsgen, cvudgen, flags) = (a[1], a[2], a[3] as u32);
                let diffgen = cvudgen as u32;
                let count = diffgen >> PTHRW_COUNT_SHIFT;
                if count > self.darwin_task_threadmax() {
                    Err(Errno::EBUSY)
                } else {
                    self.psynch_cvsignal(m, a[0], cvlsgen as u32, (cvudgen >> 32) as u32, (cvlsgen >> 32) as u32, flags, true, 0).map(u64::from)
                }
            }
            sys::PSYNCH_CVSIGNAL => {
                // (cv, cvlsgen, cvugen, thread_port, mutex, mugen, tid, flags)
                let flags = x(m, self, 7) as u32;
                let cvlsgen = a[1];
                self.psynch_cvsignal(m, a[0], cvlsgen as u32, a[2] as u32, (cvlsgen >> 32) as u32, flags, false, a[3] as u32).map(u64::from)
            }
            sys::PSYNCH_CVWAIT => {
                // (cv, cvlsgen, cvugen, mutex, mugen, flags, sec, nsec)
                let (sec, nsec) = (x(m, self, 6) as i64, x(m, self, 7) as u32);
                return Some(self.psynch_cvwait(m, a[0], a[1], a[2] as u32, a[3], a[4], a[5] as u32, sec, nsec));
            }
            sys::PSYNCH_CVCLRPREPOST => {
                // (cv, cvgen, cvugen, cvsgen, prepocnt, preposeq, flags)
                let flags = x(m, self, 6) as u32;
                self.psynch_cvclrprepost(m, a[0], a[1] as u32, a[2] as u32, a[3] as u32, a[5] as u32, flags).map(|()| 0)
            }
            sys::PSYNCH_RW_RDLOCK => return Some(self.psynch_rw_lock(m, PTH_RW_TYPE_READ, a)),
            sys::PSYNCH_RW_WRLOCK => return Some(self.psynch_rw_lock(m, PTH_RW_TYPE_WRITE, a)),
            sys::PSYNCH_RW_UNLOCK => self.psynch_rw_unlock(m, a[0], a[1] as u32, a[2] as u32, a[3] as u32, a[4] as u32).map(u64::from),
            sys::PSYNCH_RW_LONGRDLOCK | sys::PSYNCH_RW_YIELDWRLOCK => Err(Errno::ESRCH),
            sys::PSYNCH_RW_UNLOCK2 => Err(Errno::EOPNOTSUPP),
            sys::PSYNCH_RW_UPGRADE | sys::PSYNCH_RW_DOWNGRADE => Ok(0),
            _ => return None,
        };
        bsd_result(m, self.ctx_addr, r, false);
        Some(SyscallOutcome::Continue)
    }

    /// The most threads a task may have (`get_task_threadmax`, XNU's
    /// `task_threadmax`).
    fn darwin_task_threadmax(&self) -> u32 {
        // `CONFIG_THREAD_MAX` on embedded: 2560 threads per task.
        2560
    }

    /// A psynch object's address and its sharing: process-shared objects
    /// are keyed by their address too, every Darwin process being a tenant
    /// of its own memory here; one shared with another process cannot be
    /// waited for across them yet.
    fn psynch_key(&mut self, addr: u64, flags: u32) -> u64 {
        if flags & PTHREAD_PSHARED_FLAGS_MASK == PTHREAD_PROCESS_SHARED {
            self.darwin_unimplemented("a process-shared psynch object across processes".into());
        }
        addr
    }

    /// Wake the threads a psynch operation handed the object to.
    fn psynch_wake(&mut self, m: &mut GuestMem<'_>, wakes: Wakes) {
        for (tid, _) in wakes {
            self.darwin_wake(m, tid, WaitResult::Awakened);
        }
    }

    /// Put the caller on `addr`'s queue `kqi` and block (`ksyn_wait`).
    fn psynch_wait(&mut self, m: &mut GuestMem<'_>, addr: u64, kqi: usize, lockseq: u32, firstfit: bool, deadline: Option<Instant>, cont: Cont) -> Result<SyscallOutcome, Errno> {
        let me = self.tid;
        let kwe = Kwe { state: KweState::InWait, lockseq: lockseq & PTHRW_COUNT_MASK, count: 1, tid: Some(me) };
        let cancelled = |t: i32| self.dtask.threads.map.get(&t).is_some_and(|d| d.cancel.is_cancelled());
        let kwq = self.dtask.psynch.kwqs.get_mut(&addr).expect("queue exists");
        kwq.insert(kqi, kwe, lockseq, firstfit, &cancelled)?;
        self.dtask.psynch.uukwe.insert(me, UuKwe { retval: 0, queued: true });
        Ok(self.darwin_block(m, Wait { deadline, cont: super::thread::Finish::Psynch(cont) }))
    }

    /// `psynch_mutexwait(mutex, mgen, ugen, tid, flags)`.
    fn psynch_mutexwait(&mut self, m: &mut GuestMem<'_>, mutex: u64, mgen: u32, ugen: u32, tid_hint: u64, flags: u32) -> SyscallOutcome {
        let done = |k: &mut Kernel, m: &mut GuestMem<'_>, r: Result<u64, Errno>| {
            bsd_result(m, k.ctx_addr, r, false);
            SyscallOutcome::Continue
        };
        let addr = self.psynch_key(mutex, flags);
        let firstfit = flags & POLICY_MASK == POLICY_FIRSTFIT;
        let lseq = mgen & PTHRW_COUNT_MASK;
        let me = self.tid;
        if let Err(e) = self.dtask.psynch.wqfind(addr, mgen, ugen, 0, wqtype::INWAIT | wqtype::MTX) {
            return done(self, m, Err(e));
        }
        let ps = &mut self.dtask.psynch;
        if let Some(r) = ps.handle_interrupted_wakeup(addr, KWQ_INTR_WRITE, lseq) {
            ps.kwqs.get_mut(&addr).expect("found").owner = Some(me);
            ps.wqrelease(addr, true, wqtype::INWAIT | wqtype::MTX);
            return done(self, m, Ok(u64::from(r)));
        }
        let kwq = ps.kwqs.get_mut(&addr).expect("found");
        if kwq.prepost.count != 0 && (firstfit || lseq == kwq.prepost.lseq) {
            kwq.prepost.count -= 1;
            if !firstfit {
                if kwq.prepost.count > 0 {
                    kwq.prepost.lseq = kwq.prepost.lseq.wrapping_add(PTHRW_INC);
                    ps.wqrelease(addr, true, wqtype::INWAIT | wqtype::MTX);
                    return done(self, m, Err(Errno::EINVAL));
                }
                kwq.clear_preposted_wakeup();
            }
            let mut updatebits = if kwq.inqueue == 0 { lseq } else { kwq.highseq & PTHRW_COUNT_MASK } | (PTH_RWL_KBIT | PTH_RWL_EBIT);
            updatebits &= !PTH_RWL_MTX_WAIT;
            kwq.owner = Some(me);
            ps.wqrelease(addr, true, wqtype::INWAIT | wqtype::MTX);
            return done(self, m, Ok(u64::from(updatebits)));
        }
        // The owner hint userland passes: trusted unless the kernel knows
        // better (no hint, a stale one, or an unlock in flight).
        let owner_tid = kwq.owner.map(|t| t as u64);
        if Some(tid_hint) == owner_tid || tid_hint == 0 || (kwq.lastunlockseq != PTHRW_RWL_INIT && is_seqlower(ugen, kwq.lastunlockseq)) || tid_hint == u64::MAX {
        } else if self.dtask.threads.map.contains_key(&(tid_hint as i32)) || tid_hint as i32 == self.pid {
            self.dtask.psynch.kwqs.get_mut(&addr).expect("found").owner = Some(tid_hint as i32);
        }
        match self.psynch_wait(m, addr, WRITE, mgen, firstfit, None, Cont::Mutex { addr }) {
            Ok(out) => out,
            Err(e) => {
                self.dtask.psynch.wqrelease(addr, true, wqtype::INWAIT | wqtype::MTX);
                done(self, m, Err(e))
            }
        }
    }

    /// `psynch_mutexdrop(mutex, mgen, ugen, tid, flags)`
    /// (`_psynch_mutexdrop_internal`).
    fn psynch_mutexdrop(&mut self, m: &mut GuestMem<'_>, mutex: u64, mgen: u32, ugen: u32, flags: u32) -> Result<u32, Errno> {
        let addr = self.psynch_key(mutex, flags);
        self.dtask.psynch.wqfind(addr, mgen, ugen, 0, wqtype::MUTEXDROP)?;
        let mut wakes = Wakes::new();
        let ps = &mut self.dtask.psynch;
        let firstfit = flags & POLICY_MASK == POLICY_FIRSTFIT;
        let nextgen = ugen.wrapping_add(PTHRW_INC);
        ps.kwqs.get_mut(&addr).expect("found").lastunlockseq = ugen & PTHRW_COUNT_MASK;
        loop {
            let kwq = ps.kwqs.get_mut(&addr).expect("found");
            let updatebits = (kwq.highseq & PTHRW_COUNT_MASK) | (PTH_RWL_EBIT | PTH_RWL_KBIT);
            if firstfit {
                if kwq.inqueue == 0 {
                    let count = kwq.prepost.count + 1;
                    kwq.mark_preposted_wakeup(count, mgen & PTHRW_COUNT_MASK, 0);
                    kwq.owner = None;
                } else {
                    ps.mtxsignal(addr, None, updatebits, &mut wakes);
                }
                break;
            }
            let mut prepost = false;
            if kwq.inqueue == 0 {
                prepost = true;
            } else {
                let low_writer = kwq.queues[WRITE].firstnum & PTHRW_COUNT_MASK;
                if low_writer == nextgen {
                    ps.mtxsignal(addr, None, updatebits | PTH_RWL_MTX_WAIT, &mut wakes);
                } else if is_seqhigher(low_writer, nextgen) {
                    prepost = true;
                } else {
                    match kwq.find_seq(WRITE, nextgen) {
                        Some(i) => {
                            ps.mtxsignal(addr, Some(i), updatebits | PTH_RWL_MTX_WAIT, &mut wakes);
                        }
                        None => prepost = true,
                    }
                }
            }
            if prepost {
                let kwq = ps.kwqs.get_mut(&addr).expect("found");
                if kwq.prepost.count == 0 {
                    kwq.mark_preposted_wakeup(1, nextgen & PTHRW_COUNT_MASK, 0);
                }
                kwq.owner = None;
            }
            break;
        }
        ps.wqrelease(addr, true, wqtype::MUTEXDROP);
        self.psynch_wake(m, wakes);
        Ok(0)
    }

    /// `__psynch_cvsignal`: signal (one, or `threadport`'s thread) or
    /// broadcast.
    #[allow(clippy::too_many_arguments)]
    fn psynch_cvsignal(&mut self, m: &mut GuestMem<'_>, cv: u64, cgen: u32, cugen: u32, csgen: u32, flags: u32, mut broadcast: bool, threadport: u32) -> Result<u32, Errno> {
        let uptoseq = cgen & PTHRW_COUNT_MASK;
        let fromseq = (cugen & PTHRW_COUNT_MASK).wrapping_add(PTHRW_INC);
        if (threadport == 0 && is_seqhigher(fromseq, uptoseq)) || is_seqhigher(csgen, uptoseq) {
            return Err(Errno::EINVAL);
        }
        let th = if threadport != 0 {
            match self.darwin_name_to_thread(threadport) {
                Some(t) => Some(t),
                _ => return Err(Errno::ESRCH),
            }
        } else {
            None
        };
        let addr = self.psynch_key(cv, flags);
        self.dtask.psynch.wqfind(addr, cgen, cugen, csgen, wqtype::CVAR | wqtype::INDROP)?;
        let cancelled_set: Vec<i32> = self.dtask.threads.map.iter().filter(|(_, d)| d.cancel.is_cancelled()).map(|(&t, _)| t).collect();
        let cancelled = |t: i32| cancelled_set.contains(&t);
        let mut wakes = Wakes::new();
        let ps = &mut self.dtask.psynch;
        let mut updatebits = 0u32;
        ps.kwqs.get_mut(&addr).expect("found").update_cv(cgen, cugen, csgen);
        if !broadcast {
            let kwq = &ps.kwqs[&addr];
            if diff_genseq(kwq.lword, kwq.sword) != 0 {
                match th {
                    Some(t) => {
                        // `_ksyn_cvsignal_thread`.
                        let pos = kwq.queues[WRITE].list.iter().position(|k| k.state == KweState::InWait && k.tid == Some(t));
                        match pos {
                            None => broadcast = true,
                            Some(i) => {
                                let lockseq = kwq.queues[WRITE].list[i].lockseq;
                                ps.signal(addr, WRITE, Some(i), PTH_RWL_MTX_WAIT, &mut wakes);
                                if is_seqhigher(lockseq, uptoseq) || is_seqlower(lockseq, fromseq) {
                                    broadcast = true;
                                } else {
                                    updatebits = updatebits.wrapping_add(PTHRW_INC);
                                }
                            }
                        }
                    }
                    None => {
                        // `_ksyn_cvsignal_any`.
                        match kwq.find_signalseq(uptoseq, fromseq, &cancelled) {
                            Some(i) => {
                                let kwe = kwq.queues[WRITE].list[i];
                                match kwe.state {
                                    KweState::InWait => {
                                        if is_seqlower(kwe.lockseq, fromseq) {
                                            broadcast = true;
                                        } else {
                                            ps.signal(addr, WRITE, Some(i), PTH_RWL_MTX_WAIT, &mut wakes);
                                            updatebits = updatebits.wrapping_add(PTHRW_INC);
                                        }
                                    }
                                    KweState::Prepost => {
                                        ps.kwqs.get_mut(&addr).expect("found").queues[WRITE].list[i].count += 1;
                                    }
                                    KweState::Broadcast => {}
                                }
                            }
                            None => ps.prepost(addr, KweState::Prepost, uptoseq),
                        }
                    }
                }
            }
        }
        if broadcast {
            ps.handle_cvbroad(addr, uptoseq, &mut updatebits, &cancelled, &mut wakes);
        }
        let kwq = ps.kwqs.get_mut(&addr).expect("found");
        kwq.sword = kwq.sword.wrapping_add(updatebits & PTHRW_COUNT_MASK);
        ps.cvupdate_fixup(addr, &mut updatebits, &mut wakes);
        ps.wqrelease(addr, true, wqtype::INDROP | wqtype::CVAR);
        self.psynch_wake(m, wakes);
        Ok(updatebits)
    }

    /// `psynch_cvwait(cv, cvlsgen, cvugen, mutex, mugen, flags, sec, nsec)`.
    #[allow(clippy::too_many_arguments)]
    fn psynch_cvwait(&mut self, m: &mut GuestMem<'_>, cv: u64, cvlsgen: u64, cvugen: u32, mutex: u64, mugen: u64, flags: u32, sec: i64, nsec: u32) -> SyscallOutcome {
        let done = |k: &mut Kernel, m: &mut GuestMem<'_>, r: Result<u64, Errno>| {
            bsd_result(m, k.ctx_addr, r, false);
            SyscallOutcome::Continue
        };
        self.darwin_testcancel_abort();
        let csgen = (cvlsgen >> 32) as u32;
        let cgen = cvlsgen as u32;
        let ugen = (mugen >> 32) as u32;
        let mgen = mugen as u32;
        let lockseq = cgen & PTHRW_COUNT_MASK;
        if is_seqhigher_eq(csgen, lockseq) {
            return done(self, m, Err(Errno::EINVAL));
        }
        let addr = self.psynch_key(cv, flags);
        if let Err(e) = self.dtask.psynch.wqfind(addr, cgen, cvugen, csgen, wqtype::CVAR | wqtype::INWAIT) {
            return done(self, m, Err(e));
        }
        if mutex != 0 {
            if let Err(e) = self.psynch_mutexdrop(m, mutex, mgen, ugen, flags) {
                self.dtask.psynch.wqrelease(addr, true, wqtype::INWAIT | wqtype::CVAR);
                return done(self, m, Err(e));
            }
        }
        let mut wakes = Wakes::new();
        let cancelled_set: Vec<i32> = self.dtask.threads.map.iter().filter(|(_, d)| d.cancel.is_cancelled()).map(|(&t, _)| t).collect();
        let cancelled = |t: i32| cancelled_set.contains(&t);
        let ps = &mut self.dtask.psynch;
        ps.kwqs.get_mut(&addr).expect("found").update_cv(cgen, cvugen, csgen);
        let kwq = &ps.kwqs[&addr];
        let mut updatebits = 0u32;
        let r = if let Some(i) = kwq.find_cvpreposeq(lockseq) {
            let kwe = kwq.queues[WRITE].list[i];
            let mut err = None;
            match kwe.state {
                KweState::Prepost => {
                    if kwe.lockseq & PTHRW_COUNT_MASK == lockseq {
                        let kwq = ps.kwqs.get_mut(&addr).expect("found");
                        kwq.queues[WRITE].list[i].count -= 1;
                        if kwq.queues[WRITE].list[i].count == 0 {
                            kwq.remove_at(WRITE, i);
                            kwq.fakecount -= 1;
                        }
                    } else {
                        // A prepost for a later sequence: it was a broadcast.
                        ps.handle_cvbroad(addr, kwe.lockseq, &mut updatebits, &cancelled, &mut wakes);
                    }
                }
                KweState::Broadcast => {}
                KweState::InWait => err = Some(Errno::EBUSY),
            }
            match err {
                Some(e) => Err(e),
                None => {
                    updatebits |= PTHRW_INC;
                    let kwq = ps.kwqs.get_mut(&addr).expect("found");
                    kwq.sword = kwq.sword.wrapping_add(PTHRW_INC);
                    ps.cvupdate_fixup(addr, &mut updatebits, &mut wakes);
                    Ok(u64::from(updatebits))
                }
            }
        } else {
            let deadline = if sec != 0 || nsec & 0x3fff_ffff != 0 {
                let ns = (sec as u64).wrapping_mul(1_000_000_000).wrapping_add(u64::from(nsec & 0x3fff_ffff));
                Some(Instant::now() + Duration::from_nanos(ns))
            } else {
                None
            };
            self.psynch_wake(m, wakes);
            return match self.psynch_wait(m, addr, WRITE, cgen, false, deadline, Cont::Cv { addr }) {
                Ok(out) => out,
                Err(e) => {
                    self.dtask.psynch.wqrelease(addr, true, wqtype::INWAIT | wqtype::CVAR);
                    done(self, m, Err(e))
                }
            };
        };
        self.dtask.psynch.wqrelease(addr, true, wqtype::INWAIT | wqtype::CVAR);
        self.psynch_wake(m, wakes);
        done(self, m, r)
    }

    /// `psynch_cvclrprepost(cv, cvgen, cvugen, cvsgen, prepocnt, preposeq,
    /// flags)`.
    #[allow(clippy::too_many_arguments)]
    fn psynch_cvclrprepost(&mut self, m: &mut GuestMem<'_>, cv: u64, cvgen: u32, cvugen: u32, cvsgen: u32, preposeq: u32, flags: u32) -> Result<(), Errno> {
        let mutex = flags & MTX_OPT_MUTEX != 0;
        let wq = if mutex { wqtype::MTX } else { wqtype::CVAR } | wqtype::INDROP;
        let addr = self.psynch_key(cv, flags);
        self.dtask.psynch.wqfind(addr, cvgen, cvugen, if mutex { 0 } else { cvsgen }, wq)?;
        let mut wakes = Wakes::new();
        let ps = &mut self.dtask.psynch;
        if mutex {
            let firstfit = flags & POLICY_MASK == POLICY_FIRSTFIT;
            let kwq = ps.kwqs.get_mut(&addr).expect("found");
            if firstfit && kwq.prepost.count != 0 && is_seqlower_eq(kwq.prepost.lseq, cvgen) {
                kwq.clear_preposted_wakeup();
            }
        } else {
            ps.free_items(addr, WRITE, preposeq, false, &mut wakes);
        }
        ps.wqrelease(addr, true, wq);
        self.psynch_wake(m, wakes);
        Ok(())
    }

    /// `__psynch_rw_lock`: rdlock or wrlock (rwlock, lgenval, ugenval,
    /// rw_wc, flags).
    fn psynch_rw_lock(&mut self, m: &mut GuestMem<'_>, ty: u32, a: &[u64; 6]) -> SyscallOutcome {
        let (rwlock, lgenval, ugenval, rw_wc, flags) = (a[0], a[1] as u32, a[2] as u32, a[3] as u32, a[4] as u32);
        let done = |k: &mut Kernel, m: &mut GuestMem<'_>, r: Result<u64, Errno>| {
            bsd_result(m, k.ctx_addr, r, false);
            SyscallOutcome::Continue
        };
        let lockseq = lgenval & PTHRW_COUNT_MASK;
        let (prepost_type, kqi) = if ty == PTH_RW_TYPE_READ { (KW_UNLOCK_PREPOST_READLOCK, READ) } else { (KW_UNLOCK_PREPOST_WRLOCK, WRITE) };
        let addr = self.psynch_key(rwlock, flags);
        if let Err(e) = self.dtask.psynch.wqfind(addr, lgenval, ugenval, rw_wc, wqtype::INWAIT | wqtype::RWLOCK) {
            return done(self, m, Err(e));
        }
        let me = self.tid;
        let mut wakes = Wakes::new();
        let ps = &mut self.dtask.psynch;
        ps.kwqs.get_mut(&addr).expect("found").check_init(lgenval);
        // The interrupted-wakeup kind is matched against the lock type, as
        // XNU passes it (a reader's matches KWQ_INTR_READ; a writer's 0x04
        // matches neither kind).
        let granted = ps.handle_interrupted_wakeup(addr, ty, lockseq).or_else(|| ps.handle_overlap(addr, ty, lgenval, rw_wc)).or_else(|| ps.handle_preposted_wakeup(addr, prepost_type, lockseq, me, &mut wakes));
        if let Some(r) = granted {
            ps.wqrelease(addr, false, wqtype::INWAIT | wqtype::RWLOCK);
            self.psynch_wake(m, wakes);
            return done(self, m, Ok(u64::from(r)));
        }
        self.psynch_wake(m, wakes);
        match self.psynch_wait(m, addr, kqi, lgenval, false, None, Cont::Rw { addr, kqi: kqi as u8 }) {
            Ok(out) => out,
            Err(e) => {
                self.dtask.psynch.wqrelease(addr, false, wqtype::INWAIT | wqtype::RWLOCK);
                done(self, m, Err(e))
            }
        }
    }

    /// `psynch_rw_unlock(rwlock, lgenval, ugenval, rw_wc, flags)`.
    fn psynch_rw_unlock(&mut self, m: &mut GuestMem<'_>, rwlock: u64, lgenval: u32, ugenval: u32, rw_wc: u32, flags: u32) -> Result<u32, Errno> {
        let curgen = lgenval & PTHRW_COUNT_MASK;
        let addr = self.psynch_key(rwlock, flags);
        self.dtask.psynch.wqfind(addr, lgenval, ugenval, rw_wc, wqtype::INDROP | wqtype::RWLOCK)?;
        let me = self.tid;
        let mut wakes = Wakes::new();
        let ps = &mut self.dtask.psynch;
        let kwq = ps.kwqs.get_mut(&addr).expect("found");
        let isinit = kwq.check_init(lgenval);
        let mut clearedkflags = false;
        let mut updatebits = 0;
        let stale = kwq.lastunlockseq != PTHRW_RWL_INIT && is_seqlower(ugenval, kwq.lastunlockseq);
        if !stale {
            let diff = find_diff(lgenval, ugenval);
            let (enough, count) = kwq.find_seq_till(curgen, diff);
            if !enough && (count == 0 || count < diff) {
                // prepost
                if kwq.prepost.sseq & PTH_RWS_SBIT != 0 || is_seqhigher_eq(rw_wc, kwq.prepost.sseq) {
                    kwq.mark_preposted_wakeup(diff - count, curgen, rw_wc);
                    updatebits = lgenval;
                }
            } else {
                if isinit && kwq.kflags & KSYN_KWF_INITCLEARED != 0 {
                    kwq.kflags &= !KSYN_KWF_INITCLEARED;
                    clearedkflags = true;
                }
                kwq.clear_preposted_wakeup();
                let (u, _) = ps.handle_unlock(addr, rw_wc, 0, 0, me, &mut wakes);
                updatebits = u;
            }
        }
        let kwq = ps.kwqs.get_mut(&addr).expect("found");
        if clearedkflags && kwq.intr.count > 0 {
            kwq.kflags |= KSYN_KWF_INITCLEARED;
        }
        ps.wqrelease(addr, false, wqtype::INDROP | wqtype::RWLOCK);
        self.psynch_wake(m, wakes);
        Ok(updatebits)
    }

    /// A blocked psynch wait has ended (`psynch_mtxcontinue`,
    /// `psynch_cvcontinue`, `_psynch_rw_continue`).
    pub(crate) fn darwin_psynch_wait_done(&mut self, m: &mut GuestMem<'_>, c: Cont, res: WaitResult) {
        let me = self.tid;
        let error = match res {
            WaitResult::Awakened | WaitResult::Restart => None,
            WaitResult::TimedOut => Some(Errno::ETIMEDOUT),
            WaitResult::Interrupted => Some(Errno::EINTR),
        };
        let uu = self.dtask.psynch.uukwe.get(&me).copied().unwrap_or_default();
        let mut wakes = Wakes::new();
        let r: Result<u64, Errno> = match c {
            Cont::Mutex { addr } => {
                let ps = &mut self.dtask.psynch;
                let r = match error {
                    Some(e) => {
                        if uu.queued {
                            ps.kwqs.get_mut(&addr).expect("waited queue").remove_thread(WRITE, me);
                        }
                        Err(e)
                    }
                    None => Ok(u64::from(uu.retval & !PTH_RWL_MTX_WAIT)),
                };
                ps.wqrelease(addr, true, wqtype::INWAIT | wqtype::MTX);
                r
            }
            Cont::Cv { addr } => {
                let ps = &mut self.dtask.psynch;
                let r = match error {
                    Some(e) => {
                        let retval = uu.retval;
                        if uu.queued {
                            ps.kwqs.get_mut(&addr).expect("waited queue").remove_thread(WRITE, me);
                        }
                        if retval & PTH_RWL_MTX_WAIT != 0 {
                            // Signalled after all: the wait succeeded.
                            Ok(u64::from(retval))
                        } else {
                            let kwq = ps.kwqs.get_mut(&addr).expect("waited queue");
                            kwq.sword = kwq.sword.wrapping_add(PTHRW_INC);
                            let mut extra = 0;
                            if kwq.lword & PTHRW_COUNT_MASK == kwq.sword & PTHRW_COUNT_MASK {
                                extra |= ECVCLEARED;
                                if kwq.inqueue != 0 {
                                    let lword = kwq.lword;
                                    ps.free_items(addr, WRITE, lword, true, &mut wakes);
                                }
                                let kwq = ps.kwqs.get_mut(&addr).expect("waited queue");
                                kwq.lword = 0;
                                kwq.uword = 0;
                                kwq.sword = 0;
                                kwq.kflags |= KSYN_KWF_ZEROEDOUT;
                            } else if kwq.inqueue != 0 && kwq.fakecount == kwq.inqueue {
                                extra |= ECVPREPOST;
                            }
                            // The error with the cleared/prepost bits, and
                            // the return value the waker left.
                            ps.wqrelease(addr, true, wqtype::INWAIT | wqtype::CVAR);
                            ps.uukwe.remove(&me);
                            self.psynch_wake(m, wakes);
                            let errno = super::errno::to_darwin(e.0) | extra;
                            let _ = m.write_u64(self.ctx_addr + ctx::x(0) as u64, errno as u64);
                            let _ = m.write(self.ctx_addr + ctx::CF as u64, &[1]);
                            let _ = retval;
                            return;
                        }
                    }
                    None => {
                        let val = if uu.retval & PTH_RWS_CV_MBIT != 0 { PTHRW_INC | PTH_RWS_CV_CBIT } else { 0 };
                        Ok(u64::from(val))
                    }
                };
                ps.wqrelease(addr, true, wqtype::INWAIT | wqtype::CVAR);
                r
            }
            Cont::Rw { addr, kqi } => {
                let ps = &mut self.dtask.psynch;
                let r = match error {
                    Some(e) => {
                        if uu.queued {
                            ps.kwqs.get_mut(&addr).expect("waited queue").remove_thread(kqi as usize, me);
                        }
                        Err(e)
                    }
                    None => Ok(u64::from(uu.retval)),
                };
                ps.wqrelease(addr, false, wqtype::INWAIT | wqtype::RWLOCK);
                r
            }
        };
        self.dtask.psynch.uukwe.remove(&me);
        self.psynch_wake(m, wakes);
        bsd_result(m, self.ctx_addr, r, false);
    }
}
