//! Advisory locks, as XNU keeps them (`bsd/kern/kern_lockf.c`): each
//! vnode's list of granted byte-range locks, and on each lock the requests
//! blocked behind it. POSIX record locks belong to a process, `flock`'s to
//! an open file, OFD locks to an open file under another id; all three are
//! on the one list, which every process on the system shares.
//!
//! A request that has to wait is left on its blocker's list while its
//! thread sleeps ([`Kernel::darwin_block`]); `lf_wakelock`'s wakeup is a
//! note in the sleeper's process's list of threads to wake and a ring of
//! its thread-call bell, which another process can do as well as its own.

use super::sysno as sys;
use super::thread::Finish;
use super::wait::{Wait, WaitResult};
use crate::errno::Errno;
use crate::file::OpenFile;
use crate::syscalls::{Kernel, SyscallOutcome};
use crate::GuestMem;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};

/// `F_RDLCK`, `F_UNLCK`, `F_WRLCK`.
pub const F_RDLCK: i16 = 1;
pub const F_UNLCK: i16 = 2;
pub const F_WRLCK: i16 = 3;

/// The lock flags (`bsd/sys/fcntl.h`).
pub mod lf {
    pub const F_WAIT: u32 = 0x010;
    pub const F_FLOCK: u32 = 0x020;
    pub const F_POSIX: u32 = 0x040;
    pub const F_WAKE1_SAFE: u32 = 0x100;
    pub const F_OFD_LOCK: u32 = 0x400;
}

/// `fcntl`'s lock commands (`bsd/sys/fcntl.h`).
pub mod cmd {
    pub const F_GETLK: u64 = 7;
    pub const F_SETLK: u64 = 8;
    pub const F_SETLKW: u64 = 9;
    pub const F_SETLKWTIMEOUT: u64 = 10;
    pub const F_GETLKPID: u64 = 66;
    pub const F_OFD_SETLK: u64 = 90;
    pub const F_OFD_SETLKW: u64 = 91;
    pub const F_OFD_GETLK: u64 = 92;
    pub const F_OFD_SETLKWTIMEOUT: u64 = 93;
    pub const F_OFD_GETLKPID: u64 = 94;
}

/// `LOCK_*` (`flock`).
const LOCK_SH: u64 = 0x01;
const LOCK_EX: u64 = 0x02;
const LOCK_NB: u64 = 0x04;
const LOCK_UN: u64 = 0x08;

/// `fg_flag`'s `FWASLOCKED`, `fg_lflags`'s `FG_HAS_OFDLOCK`, kept in the
/// open file's [`OpenFile::darwin_lflags`].
pub const FWASLOCKED: u32 = 0x4000;
pub const FG_HAS_OFDLOCK: u32 = 0x400;

const SEEK_SET: i16 = 0;
const SEEK_CUR: i16 = 1;
const SEEK_END: i16 = 2;

/// A vnode: its mount and inode.
pub type Vnode = (u64, u64);

/// `lf_id`: the process, or the open file (`fileglob`) for `flock`, or
/// `ofd_to_id` of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Id {
    Proc(i32),
    Flock(usize),
    Ofd(usize),
}

/// Who to wake for a request that sleeps: its thread, in the process whose
/// list of threads to wake and bell these are.
#[derive(Clone)]
pub struct Waker {
    pub pid: i32,
    pub tid: i32,
    pub inbox: Arc<Mutex<Vec<i32>>>,
    pub bell: Arc<super::timer::Bell>,
}

/// `struct lockf`.
struct Lockf {
    start: i64,
    /// -1 for the end of the file.
    end: i64,
    id: Id,
    ty: i16,
    flags: u32,
    /// `lf_owner`'s pid, where the owner is known.
    owner: Option<i32>,
    vnode: Vnode,
    /// A blocked request's blocker.
    next: Option<u64>,
    /// `lf_blkhd`.
    blkhd: VecDeque<u64>,
    waker: Option<Waker>,
}

/// `LF_END`.
fn lf_end(l: &Lockf) -> i64 {
    if l.end == -1 {
        i64::MAX
    } else {
        l.end
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Ovl {
    None,
    EqualsLock,
    ContainsLock,
    ContainedByLock,
    StartsBeforeLock,
    EndsAfterLock,
}

#[derive(Default)]
struct Table {
    locks: HashMap<u64, Lockf>,
    /// Each vnode's `v_lockf` list, in order.
    lists: HashMap<Vnode, Vec<u64>>,
    next: u64,
}

fn table() -> &'static Mutex<Table> {
    static T: OnceLock<Mutex<Table>> = OnceLock::new();
    T.get_or_init(Default::default)
}

/// `struct flock` (`l_start`, `l_len`, `l_pid`, `l_type`, `l_whence`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flock {
    pub start: i64,
    pub len: i64,
    pub pid: i32,
    pub ty: i16,
    pub whence: i16,
}

impl Flock {
    fn read(m: &GuestMem<'_>, at: u64) -> Result<Flock, Errno> {
        let tw = m.read_u32(at + 20)?;
        Ok(Flock { start: m.read_u64(at)? as i64, len: m.read_u64(at + 8)? as i64, pid: m.read_u32(at + 16)? as i32, ty: tw as u16 as i16, whence: (tw >> 16) as u16 as i16 })
    }

    fn write(&self, m: &mut GuestMem<'_>, at: u64) -> Result<(), Errno> {
        m.write_u64(at, self.start as u64)?;
        m.write_u64(at + 8, self.len as u64)?;
        m.write_u32(at + 16, self.pid as u32)?;
        m.write_u32(at + 20, u32::from(self.ty as u16) | u32::from(self.whence as u16) << 16)
    }
}

/// What a set request came to.
pub enum Step {
    Done(Result<(), Errno>),
    /// Asleep behind another lock: the request, to resume.
    Blocked(u64),
}

impl Table {
    fn alloc(&mut self, l: Lockf) -> u64 {
        self.next += 1;
        self.locks.insert(self.next, l);
        self.next
    }

    fn l(&mut self, id: u64) -> &mut Lockf {
        self.locks.get_mut(&id).expect("a live lockf")
    }

    fn list(&mut self, v: Vnode) -> &mut Vec<u64> {
        self.lists.entry(v).or_default()
    }

    /// `lf_findoverlap` from position `from` of the vnode's list: the case,
    /// and the overlap's position (or where the walk ended).
    fn findoverlap(&self, v: Vnode, from: usize, lock: u64, selfish: bool) -> (Ovl, usize) {
        let empty = Vec::new();
        let list = self.lists.get(&v).unwrap_or(&empty);
        let me = &self.locks[&lock];
        let (start, end) = (me.start, lf_end(me));
        let mut found_self = false;
        let mut i = from;
        while i < list.len() {
            let lf = &self.locks[&list[i]];
            if (selfish && lf.id != me.id) || (!selfish && lf.id == me.id) {
                if selfish && found_self {
                    return (Ovl::None, i);
                }
                i += 1;
                continue;
            }
            if selfish {
                found_self = true;
            }
            let (lfstart, lfend) = (lf.start, lf_end(lf));
            if start > lfend || lfstart > end {
                if selfish && lfstart > end {
                    return (Ovl::None, i);
                }
                i += 1;
                continue;
            }
            let case = if lfstart == start && lfend == end {
                Ovl::EqualsLock
            } else if lfstart <= start && lfend >= end {
                Ovl::ContainsLock
            } else if start <= lfstart && end >= lfend {
                Ovl::ContainedByLock
            } else if lfstart < start && lfend >= start {
                Ovl::StartsBeforeLock
            } else if lfstart > start && lfend > end {
                Ovl::EndsAfterLock
            } else {
                panic!("lf_findoverlap: default");
            };
            return (case, i);
        }
        (Ovl::None, list.len())
    }

    /// `lf_getblock`: the first lock of another owner that blocks `lock`.
    fn getblock(&self, lock: u64, matchpid: i32) -> Option<u64> {
        let v = self.locks[&lock].vnode;
        let mut pos = 0;
        loop {
            let (case, i) = self.findoverlap(v, pos, lock, false);
            if case == Ovl::None {
                return None;
            }
            let ov = self.lists[&v][i];
            pos = i + 1;
            let o = &self.locks[&ov];
            if matchpid != -1 && o.flags & (lf::F_POSIX | lf::F_OFD_LOCK) != 0 && o.owner != Some(matchpid) {
                continue;
            }
            if self.locks[&lock].ty == F_WRLCK || o.ty == F_WRLCK {
                return Some(ov);
            }
        }
    }

    /// `lf_move_blocked`.
    fn move_blocked(&mut self, to: u64, from: u64) {
        let moved: Vec<u64> = self.l(from).blkhd.drain(..).collect();
        for &t in &moved {
            self.l(t).next = Some(to);
        }
        self.l(to).blkhd.extend(moved);
    }

    /// `lf_wakelock`: the requests blocked behind `head` are woken, all of
    /// them or, where one is enough, the first with the rest behind it.
    fn wakelock(&mut self, head: u64, force_all: bool) {
        let wake_all = force_all || self.l(head).flags & lf::F_WAKE1_SAFE == 0;
        while let Some(w) = self.l(head).blkhd.pop_front() {
            self.l(w).next = None;
            if !wake_all && !self.l(head).blkhd.is_empty() {
                self.move_blocked(w, head);
            }
            if let Some(k) = self.l(w).waker.clone() {
                k.inbox.lock().unwrap_or_else(|e| e.into_inner()).push(k.tid);
                k.bell.ring();
            }
            if !wake_all {
                break;
            }
        }
    }

    fn free(&mut self, id: u64) {
        self.locks.remove(&id);
    }

    /// `lf_split`, for a lock contained in `lock1` at `i`: `lock2` goes in
    /// after it, and the part of `lock1` past `lock2` after that.
    fn split(&mut self, i: usize, lock1: u64, lock2: u64) {
        let v = self.l(lock1).vnode;
        let (s1, e1) = (self.l(lock1).start, lf_end(self.l(lock1)));
        let (s2, e2) = (self.l(lock2).start, lf_end(self.l(lock2)));
        if s1 == s2 {
            self.l(lock1).start = e2 + 1;
            self.list(v).insert(i, lock2);
            return;
        }
        if e1 == e2 {
            self.l(lock1).end = s2 - 1;
            self.list(v).insert(i + 1, lock2);
            return;
        }
        let l1 = &self.locks[&lock1];
        let split = Lockf { start: e2 + 1, end: l1.end, id: l1.id, ty: l1.ty, flags: l1.flags, owner: l1.owner, vnode: v, next: None, blkhd: VecDeque::new(), waker: None };
        let sid = self.alloc(split);
        self.l(lock1).end = s2 - 1;
        let list = self.list(v);
        list.insert(i + 1, lock2);
        list.insert(i + 2, sid);
    }

    /// `lf_coalesce_adjacent`.
    fn coalesce_adjacent(&mut self, lock: u64) {
        let v = self.l(lock).vnode;
        let mut i = 0;
        while i < self.list(v).len() {
            let id = self.lists[&v][i];
            let (same, other_end, other_start) = {
                let (a, b) = (&self.locks[&id], &self.locks[&lock]);
                (id != lock && a.id == b.id && a.ty == b.ty, lf_end(a), a.start)
            };
            if !same {
                i += 1;
                continue;
            }
            if other_end < i64::MAX && other_end + 1 == self.l(lock).start {
                self.l(lock).start = other_start;
                self.move_blocked(lock, id);
                self.free(id);
                self.list(v).remove(i);
                i = self.lists[&v].iter().position(|&x| x == lock).map_or(i, |p| p + 1);
                continue;
            }
            let lend = lf_end(self.l(lock));
            if lend < i64::MAX && lend + 1 == other_start {
                self.l(lock).end = self.l(id).end;
                self.move_blocked(lock, id);
                self.free(id);
                self.list(v).remove(i);
                i = self.lists[&v].iter().position(|&x| x == lock).map_or(i, |p| p + 1);
                continue;
            }
            i += 1;
        }
    }

    /// `lf_setlock`'s scan: blocked (asleep), failed, or on to the grant.
    fn setlock_scan(&mut self, lock: u64) -> Step {
        while let Some(block) = self.getblock(lock, -1) {
            if self.l(lock).flags & lf::F_WAIT == 0 {
                self.free(lock);
                return Step::Done(Err(Errno::EAGAIN));
            }
            // POSIX locks look for a cycle through a thread of the
            // blocker's owner asleep on a POSIX lock whose blocker is ours.
            if self.l(lock).flags & self.l(block).flags & lf::F_POSIX != 0 {
                let (wproc, me) = (self.l(block).owner, self.l(lock).owner);
                let deadlocked = self.locks.values().any(|w| {
                    w.flags & lf::F_POSIX != 0
                        && w.waker.as_ref().map(|k| Some(k.pid)) == Some(wproc)
                        && w.next.is_some_and(|n| self.locks.get(&n).is_some_and(|nb| nb.flags & lf::F_POSIX != 0 && nb.owner == me))
                });
                if deadlocked {
                    self.free(lock);
                    return Step::Done(Err(Errno::EDEADLK));
                }
            }
            // A flock waiting for an exclusive lock gives up its shared one.
            if self.l(lock).flags & lf::F_FLOCK != 0 && self.l(lock).ty == F_WRLCK {
                self.l(lock).ty = F_UNLCK;
                self.clearlock(lock);
                self.l(lock).ty = F_WRLCK;
            }
            self.l(lock).next = Some(block);
            self.l(block).blkhd.push_back(lock);
            if self.l(lock).flags & lf::F_FLOCK == 0 {
                self.l(block).flags &= !lf::F_WAKE1_SAFE;
            }
            return Step::Blocked(lock);
        }
        self.grant(lock);
        Step::Done(Ok(()))
    }

    /// `lf_setlock` after the sleep: `err` is how it ended.
    fn setlock_resume(&mut self, lock: u64, err: Option<Errno>) -> Step {
        if let Some(n) = self.l(lock).next.take() {
            // Woken early (a signal, a timeout): off the blocker's list;
            // with no error, it was spurious and the scan goes on.
            if let Some(b) = self.locks.get_mut(&n) {
                b.blkhd.retain(|&x| x != lock);
            }
            if err.is_none() {
                return self.setlock_scan(lock);
            }
        }
        if !self.l(lock).blkhd.is_empty() {
            if let Some(block) = self.getblock(lock, -1) {
                self.move_blocked(block, lock);
            }
        }
        if let Some(e) = err {
            if !self.l(lock).blkhd.is_empty() {
                self.wakelock(lock, true);
            }
            self.free(lock);
            return Step::Done(Err(if e == Errno::EAGAIN { Errno::ETIMEDOUT } else { e }));
        }
        self.setlock_scan(lock)
    }

    /// `lf_setlock`'s grant: the owner's overlapping locks upgraded,
    /// downgraded, split or replaced, then adjacent ones coalesced.
    fn grant(&mut self, lock0: u64) {
        let mut lock = lock0;
        // Held now: nobody to wake.
        self.l(lock).waker = None;
        let v = self.l(lock).vnode;
        let mut pos = 0;
        let mut needtolink = true;
        loop {
            let lkend = lf_end(self.l(lock));
            let (case, i) = self.findoverlap(v, pos, lock, true);
            let ov = self.lists.get(&v).and_then(|l| l.get(i)).copied();
            match case {
                Ovl::None => {
                    if needtolink {
                        self.list(v).insert(i, lock);
                    }
                    break;
                }
                Ovl::EqualsLock => {
                    let ov = ov.unwrap();
                    if self.l(lock).ty == F_RDLCK && self.l(ov).ty == F_WRLCK {
                        self.wakelock(ov, true);
                    }
                    self.l(ov).ty = self.l(lock).ty;
                    self.move_blocked(ov, lock);
                    self.free(lock);
                    lock = ov;
                    break;
                }
                Ovl::ContainsLock => {
                    let ov = ov.unwrap();
                    if self.l(ov).ty == self.l(lock).ty {
                        self.move_blocked(ov, lock);
                        self.free(lock);
                        lock = ov;
                        break;
                    }
                    if self.l(ov).start == self.l(lock).start {
                        self.list(v).insert(i, lock);
                        self.l(ov).start = lkend + 1;
                    } else {
                        self.split(i, ov, lock);
                    }
                    self.wakelock(ov, true);
                    break;
                }
                Ovl::ContainedByLock => {
                    let ov = ov.unwrap();
                    if self.l(lock).ty == F_RDLCK && self.l(ov).ty == F_WRLCK {
                        self.wakelock(ov, true);
                    } else {
                        self.move_blocked(lock, ov);
                    }
                    if needtolink {
                        self.list(v)[i] = lock;
                        needtolink = false;
                        pos = i + 1;
                    } else {
                        self.list(v).remove(i);
                        pos = i;
                    }
                    self.free(ov);
                    continue;
                }
                Ovl::StartsBeforeLock => {
                    let ov = ov.unwrap();
                    self.list(v).insert(i + 1, lock);
                    self.l(ov).end = self.l(lock).start - 1;
                    pos = i + 2;
                    self.wakelock(ov, true);
                    needtolink = false;
                    continue;
                }
                Ovl::EndsAfterLock => {
                    let ov = ov.unwrap();
                    if needtolink {
                        self.list(v).insert(i, lock);
                    }
                    self.l(ov).start = lkend + 1;
                    self.wakelock(ov, true);
                    break;
                }
            }
        }
        self.coalesce_adjacent(lock);
    }

    /// `lf_clearlock`: the owner's locks over `unlock`'s range removed or
    /// cut back, and whoever waited on them woken.
    fn clearlock(&mut self, unlock: u64) {
        let v = self.l(unlock).vnode;
        let mut pos = 0;
        loop {
            let (case, i) = self.findoverlap(v, pos, unlock, true);
            if case == Ovl::None {
                break;
            }
            let ov = self.lists[&v][i];
            let unlkend = lf_end(self.l(unlock));
            self.wakelock(ov, false);
            match case {
                Ovl::None => break,
                Ovl::EqualsLock => {
                    self.list(v).remove(i);
                    self.free(ov);
                    break;
                }
                Ovl::ContainsLock => {
                    if self.l(ov).start == self.l(unlock).start {
                        self.l(ov).start = unlkend + 1;
                        break;
                    }
                    // lf_split, then the unlock taken back out.
                    self.split(i, ov, unlock);
                    self.list(v).retain(|&x| x != unlock);
                    break;
                }
                Ovl::ContainedByLock => {
                    self.list(v).remove(i);
                    self.free(ov);
                    pos = i;
                    continue;
                }
                Ovl::StartsBeforeLock => {
                    self.l(ov).end = self.l(unlock).start - 1;
                    pos = i + 1;
                    continue;
                }
                Ovl::EndsAfterLock => {
                    self.l(ov).start = unlkend + 1;
                    break;
                }
            }
        }
        if self.lists.get(&v).is_some_and(|l| l.is_empty()) {
            self.lists.remove(&v);
        }
    }

    /// `lf_getlock`: the first lock that would block `lock`, or F_UNLCK.
    fn getlock(&mut self, lock: u64, fl: &mut Flock, matchpid: i32) {
        match self.getblock(lock, matchpid) {
            Some(b) => {
                let b = &self.locks[&b];
                fl.ty = b.ty;
                fl.whence = SEEK_SET;
                fl.start = b.start;
                fl.len = if b.end == -1 || (b.start == 0 && lf_end(b) == i64::MAX) { 0 } else { lf_end(b) - b.start + 1 };
                fl.pid = b.owner.unwrap_or(-1);
            }
            None => fl.ty = F_UNLCK,
        }
    }
}

/// `lf_advlock`'s range: `fl` (its start already absolute for SEEK_CUR) as
/// a start and an end (-1 for the end of the file).
fn range(fl: &Flock, size: impl FnOnce() -> Result<i64, Errno>) -> Result<(i64, i64), Errno> {
    let mut start = match fl.whence {
        SEEK_SET | SEEK_CUR => fl.start,
        SEEK_END => {
            let size = size()?;
            if fl.start > 0 && size > i64::MAX - fl.start {
                return Err(Errno::EOVERFLOW);
            }
            size + fl.start
        }
        _ => return Err(Errno::EINVAL),
    };
    if start < 0 {
        return Err(Errno::EINVAL);
    }
    let end;
    if fl.len < 0 {
        if start == 0 {
            return Err(Errno::EINVAL);
        }
        end = start - 1;
        start += fl.len;
        if start < 0 {
            return Err(Errno::EINVAL);
        }
    } else if fl.len == 0 {
        end = -1;
    } else {
        let oadd = fl.len - 1;
        if oadd > i64::MAX - start {
            return Err(Errno::EOVERFLOW);
        }
        end = start + oadd;
    }
    Ok((start, end))
}

/// The operation `lf_advlock` is asked for.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Op {
    SetLk,
    Unlck,
    GetLk,
    GetLkPid,
}

/// `lf_advlock`. A set that has to wait comes back [`Step::Blocked`].
pub fn advlock(v: Vnode, id: Id, op: Op, fl: &mut Flock, flags: u32, owner: Option<i32>, waker: Option<Waker>, size: impl FnOnce() -> Result<i64, Errno>) -> Step {
    let mut t = table().lock().unwrap_or_else(|e| e.into_inner());
    if t.lists.get(&v).is_none_or(|l| l.is_empty()) && op != Op::SetLk {
        fl.ty = F_UNLCK;
        return Step::Done(Ok(()));
    }
    let (start, end) = match range(fl, size) {
        Ok(r) => r,
        Err(e) => return Step::Done(Err(e)),
    };
    let mut flags = flags;
    if flags & lf::F_FLOCK != 0 {
        flags |= lf::F_WAKE1_SAFE;
    }
    let lock = t.alloc(Lockf { start, end, id, ty: fl.ty, flags, owner, vnode: v, next: None, blkhd: VecDeque::new(), waker });
    match op {
        Op::SetLk => t.setlock_scan(lock),
        Op::Unlck => {
            t.clearlock(lock);
            t.free(lock);
            Step::Done(Ok(()))
        }
        Op::GetLk | Op::GetLkPid => {
            let matchpid = if op == Op::GetLkPid { fl.pid } else { -1 };
            t.getlock(lock, fl, matchpid);
            t.free(lock);
            Step::Done(Ok(()))
        }
    }
}

/// A blocked set's sleep ended (`err`: why, if not a wakeup).
pub fn resume(lock: u64, err: Option<Errno>) -> Step {
    let mut t = table().lock().unwrap_or_else(|e| e.into_inner());
    if !t.locks.contains_key(&lock) {
        return Step::Done(Err(Errno::EBADF));
    }
    t.setlock_resume(lock, err)
}

/// Unlock the whole of `v` for `id` (a close's `VNOP_ADVLOCK(F_UNLCK)`).
pub fn unlock_all(v: Vnode, id: Id, flags: u32) {
    let mut fl = Flock { whence: SEEK_SET, ty: F_UNLCK, ..Default::default() };
    let _ = advlock(v, id, Op::Unlck, &mut fl, flags, None, None, || Ok(0));
}

/// A process is gone: every POSIX lock it held released, and its sleeping
/// requests dropped.
pub fn process_gone(pid: i32) {
    let vnodes: Vec<Vnode> = {
        let t = table().lock().unwrap_or_else(|e| e.into_inner());
        t.locks.values().filter(|l| l.id == Id::Proc(pid) && l.waker.is_none()).map(|l| l.vnode).collect()
    };
    for v in vnodes {
        unlock_all(v, Id::Proc(pid), lf::F_POSIX);
    }
    let mut t = table().lock().unwrap_or_else(|e| e.into_inner());
    let asleep: Vec<u64> = t.locks.iter().filter(|(_, l)| l.waker.as_ref().is_some_and(|k| k.pid == pid)).map(|(&k, _)| k).collect();
    let asleep: Vec<u64> = asleep.into_iter().filter(|r| !t.lists.get(&t.locks[r].vnode).is_some_and(|l| l.contains(r))).collect();
    for r in asleep {
        let _ = t.setlock_resume(r, Some(Errno::EINTR));
    }
}

/// A process execs: `fg_transfer_filelocks` moves its POSIX locks on the
/// files it keeps open (`keep`) to the new image, and the old image's end
/// releases the rest; the other threads' requests are gone with them.
pub fn exec_keep(pid: i32, keep: &[Vnode]) {
    let vnodes: Vec<Vnode> = {
        let t = table().lock().unwrap_or_else(|e| e.into_inner());
        t.locks.values().filter(|l| l.id == Id::Proc(pid) && l.waker.is_none() && !keep.contains(&l.vnode)).map(|l| l.vnode).collect()
    };
    for v in vnodes {
        unlock_all(v, Id::Proc(pid), lf::F_POSIX);
    }
    let mut t = table().lock().unwrap_or_else(|e| e.into_inner());
    let asleep: Vec<u64> = t.locks.iter().filter(|(_, l)| l.waker.as_ref().is_some_and(|k| k.pid == pid)).map(|(&k, _)| k).collect();
    let asleep: Vec<u64> = asleep.into_iter().filter(|r| !t.lists.get(&t.locks[r].vnode).is_some_and(|l| l.contains(r))).collect();
    for r in asleep {
        let _ = t.setlock_resume(r, Some(Errno::EINTR));
    }
}

/// An open file's last close (`vn_closefile`): its flock and OFD locks.
pub fn last_close(file: &OpenFile) {
    use std::sync::atomic::Ordering;
    let flags = file.darwin_lflags.load(Ordering::Acquire);
    let Some(&v) = file.darwin_lock_key.get() else { return };
    let fg = file as *const OpenFile as usize;
    if flags & FWASLOCKED != 0 {
        unlock_all(v, Id::Flock(fg), lf::F_FLOCK);
        funlock(file);
    }
    if flags & FG_HAS_OFDLOCK != 0 {
        unlock_all(v, Id::Ofd(fg), lf::F_OFD_LOCK);
        funlock(file);
    }
}

/// VNOP_ADVLOCK's NOTE_FUNLOCK for a flock or OFD unlock.
fn funlock(file: &OpenFile) {
    if let Some(&key) = file.darwin_vnote_key.get() {
        crate::vnote::post(key, crate::vnote::note::FUNLOCK);
    }
}

/// What kind of file a lock call is on.
enum Target {
    /// A vnode that keeps lockf lists: a regular file or a directory.
    Lockf(Vnode),
    /// A vnode whose filesystem refuses advisory locks (a device's or a
    /// fifo's `err_advlock`).
    NoAdvlock,
    /// Not a vnode at all.
    NotVnode,
}

/// A blocked lock call's continuation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cont {
    pub req: u64,
    /// Set for an open with O_EXLOCK or O_SHLOCK: the descriptor it made,
    /// the call's answer once the lock is held (and closed if it is not).
    pub open_fd: Option<i32>,
    /// The open file, for FWASLOCKED or FG_HAS_OFDLOCK once it is held.
    pub fg: usize,
    pub mark: u32,
}

impl Kernel {
    /// `fp`'s vnode for locking, and what kind it is.
    fn darwin_lock_target(&mut self, file: &Arc<OpenFile>) -> Target {
        if file.handle.pipe_end().is_some() || Arc::clone(&file.handle).as_kqueue().is_some() || Arc::clone(&file.handle).as_posix_shm().is_some() {
            return Target::NotVnode;
        }
        let Ok(md) = file.handle.metadata() else { return Target::NotVnode };
        match md.file_type {
            crate::vfs::FileType::Socket => Target::NotVnode,
            crate::vfs::FileType::Regular | crate::vfs::FileType::Directory => {
                let key = *file.darwin_lock_key.get_or_init(|| (self.vfs.mount_id_of(&file.path), md.ino));
                // For the NOTE_FUNLOCK its unlocks post.
                let _ = self.darwin_vnote_key(file);
                Target::Lockf(key)
            }
            _ => Target::NoAdvlock,
        }
    }

    pub(crate) fn darwin_waker(&mut self) -> Waker {
        Waker { pid: self.pid, tid: self.tid, inbox: Arc::clone(&self.dtask.lock_wakes), bell: self.darwin_timer_bell() }
    }

    /// Wake the threads whose lock requests were granted a turn.
    pub(crate) fn darwin_lock_wakes(&mut self, m: &mut GuestMem<'_>) {
        let tids = std::mem::take(&mut *self.dtask.lock_wakes.lock().unwrap_or_else(|e| e.into_inner()));
        for tid in tids {
            self.darwin_wake(m, tid, WaitResult::Awakened);
        }
    }

    /// The `fcntl` lock commands; a blocking one may sleep.
    pub(crate) fn darwin_fcntl_lock(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> SyscallOutcome {
        let r = self.darwin_fcntl_lock_inner(m, a);
        self.darwin_lock_outcome(m, r)
    }

    fn darwin_lock_outcome(&mut self, m: &mut GuestMem<'_>, r: Result<Option<(Cont, Option<std::time::Instant>)>, Errno>) -> SyscallOutcome {
        match r {
            Ok(None) => {
                let _ = super::set_result(m, self.ctx_addr, 0);
                SyscallOutcome::Continue
            }
            Ok(Some((c, deadline))) => self.darwin_block(m, Wait { deadline, cont: Finish::Lockf(c) }),
            Err(e) => {
                let _ = super::set_result(m, self.ctx_addr, e.as_return());
                SyscallOutcome::Continue
            }
        }
    }

    fn darwin_fcntl_lock_inner(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<Option<(Cont, Option<std::time::Instant>)>, Errno> {
        let (fd, c, argp) = (a[0] as i32, a[1], a[2]);
        let file = self.fds.get(fd)?;
        let Target::Lockf(v) = (match self.darwin_lock_target(&file) {
            Target::NotVnode => return Err(Errno::EBADF),
            t => t,
        }) else {
            // VNOP_ADVLOCK of a vnode without lockf lists: err_advlock,
            // once the arguments are read and checked.
            let fl = Flock::read(m, argp)?;
            check_file_seek_range(&fl, file.offset() as i64)?;
            return Err(Errno::EOPNOTSUPP);
        };
        let offset = file.offset() as i64;
        let fg = Arc::as_ptr(&file) as usize;
        let size = || file.handle.metadata().map(|md| md.size as i64);
        match c {
            cmd::F_GETLK | cmd::F_OFD_GETLK | cmd::F_GETLKPID | cmd::F_OFD_GETLKPID => {
                let mut fl = Flock::read(m, argp)?;
                check_file_seek_range(&fl, offset)?;
                if fl.whence == SEEK_SET && fl.start < 0 {
                    return Err(Errno::EINVAL);
                }
                if !matches!(fl.ty, F_RDLCK | F_UNLCK | F_WRLCK) || !matches!(fl.whence, SEEK_SET | SEEK_CUR | SEEK_END) {
                    return Err(Errno::EINVAL);
                }
                if fl.whence == SEEK_CUR {
                    fl.start += offset;
                }
                let (id, op) = match c {
                    cmd::F_OFD_GETLK => (Id::Ofd(fg), Op::GetLk),
                    cmd::F_OFD_GETLKPID => (Id::Ofd(fg), Op::GetLkPid),
                    cmd::F_GETLKPID => (Id::Proc(self.pid), Op::GetLkPid),
                    _ => (Id::Proc(self.pid), Op::GetLk),
                };
                let flags = if matches!(id, Id::Ofd(_)) { lf::F_OFD_LOCK } else { lf::F_POSIX };
                match advlock(v, id, op, &mut fl, flags, None, None, size) {
                    Step::Done(r) => r?,
                    Step::Blocked(_) => unreachable!("a lock query never sleeps"),
                }
                fl.write(m, argp)?;
                Ok(None)
            }
            _ => {
                let wait = matches!(c, cmd::F_SETLKW | cmd::F_SETLKWTIMEOUT | cmd::F_OFD_SETLKW | cmd::F_OFD_SETLKWTIMEOUT);
                let timed = matches!(c, cmd::F_SETLKWTIMEOUT | cmd::F_OFD_SETLKWTIMEOUT);
                let mut fl = Flock::read(m, argp)?;
                let deadline = if timed {
                    let (sec, nsec) = (m.read_u64(argp + 24)? as i64, m.read_u64(argp + 32)? as i64);
                    Some(std::time::Instant::now() + std::time::Duration::new(sec.max(0) as u64, nsec.clamp(0, 999_999_999) as u32))
                } else {
                    None
                };
                check_file_seek_range(&fl, offset)?;
                if fl.whence == SEEK_CUR {
                    fl.start += offset;
                }
                let ofd = matches!(c, cmd::F_OFD_SETLK | cmd::F_OFD_SETLKW | cmd::F_OFD_SETLKWTIMEOUT);
                let (id, base, owner, mark) = if ofd { (Id::Ofd(fg), lf::F_OFD_LOCK, None, FG_HAS_OFDLOCK) } else { (Id::Proc(self.pid), lf::F_POSIX, Some(self.pid), 0) };
                let op = match fl.ty {
                    F_RDLCK if !file.readable => return Err(Errno::EBADF),
                    F_WRLCK if !file.writable => return Err(Errno::EBADF),
                    F_RDLCK | F_WRLCK => Op::SetLk,
                    F_UNLCK => Op::Unlck,
                    _ => return Err(Errno::EINVAL),
                };
                if op == Op::SetLk && !ofd {
                    self.dtask.ladvlock = true;
                }
                let flags = base | if wait && op == Op::SetLk { lf::F_WAIT } else { 0 };
                let waker = Some(self.darwin_waker());
                match advlock(v, id, op, &mut fl, flags, owner, waker, size) {
                    Step::Done(r) => {
                        r?;
                        if op == Op::Unlck && ofd {
                            funlock(&file);
                        }
                        if op == Op::SetLk && mark != 0 {
                            file.darwin_lflags.fetch_or(mark, std::sync::atomic::Ordering::AcqRel);
                        }
                        Ok(None)
                    }
                    Step::Blocked(req) => Ok(Some((Cont { req, open_fd: None, fg, mark }, deadline))),
                }
            }
        }
    }

    /// `flock(fd, how)`.
    pub(crate) fn darwin_flock(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> SyscallOutcome {
        let r = self.darwin_flock_inner(a[0] as i32, a[1]);
        self.darwin_lock_outcome(m, r)
    }

    fn darwin_flock_inner(&mut self, fd: i32, how: u64) -> Result<Option<(Cont, Option<std::time::Instant>)>, Errno> {
        let file = self.fds.get(fd)?;
        let v = match self.darwin_lock_target(&file) {
            Target::Lockf(v) => v,
            Target::NoAdvlock => return Err(Errno::EOPNOTSUPP),
            Target::NotVnode => return Err(Errno::EOPNOTSUPP),
        };
        let ty = if how & LOCK_UN != 0 {
            F_UNLCK
        } else if how & LOCK_EX != 0 {
            F_WRLCK
        } else if how & LOCK_SH != 0 {
            F_RDLCK
        } else {
            return Err(Errno::EBADF);
        };
        let wait = if how & LOCK_NB == 0 { lf::F_WAIT } else { 0 };
        self.darwin_flock_set(&file, v, ty, wait, None)
    }

    /// A flock lock (`flock`, or `open`'s O_EXLOCK and O_SHLOCK).
    fn darwin_flock_set(&mut self, file: &Arc<OpenFile>, v: Vnode, ty: i16, wait: u32, open_fd: Option<i32>) -> Result<Option<(Cont, Option<std::time::Instant>)>, Errno> {
        let fg = Arc::as_ptr(file) as usize;
        let mut fl = Flock { whence: SEEK_SET, ty, ..Default::default() };
        if ty == F_UNLCK {
            if let Step::Done(r) = advlock(v, Id::Flock(fg), Op::Unlck, &mut fl, lf::F_FLOCK, None, None, || Ok(0)) {
                r?;
            }
            funlock(file);
            return Ok(None);
        }
        let waker = Some(self.darwin_waker());
        match advlock(v, Id::Flock(fg), Op::SetLk, &mut fl, lf::F_FLOCK | wait, None, waker, || Ok(0)) {
            Step::Done(r) => {
                r?;
                file.darwin_lflags.fetch_or(FWASLOCKED, std::sync::atomic::Ordering::AcqRel);
                Ok(None)
            }
            Step::Blocked(req) => Ok(Some((Cont { req, open_fd, fg, mark: FWASLOCKED }, None))),
        }
    }

    /// `open1`'s O_EXLOCK or O_SHLOCK on the descriptor an open just made:
    /// what the call answers (the descriptor, or the lock's error with the
    /// descriptor closed), or a sleep for the lock.
    pub(crate) fn darwin_open_lock(&mut self, m: &mut GuestMem<'_>, fd: i32, dflags: u64) -> SyscallOutcome {
        const O_SHLOCK: u64 = 0x10;
        const O_EXLOCK: u64 = 0x20;
        const O_NONBLOCK: u64 = 0x4;
        let r = (|| {
            let file = self.fds.get(fd)?;
            let v = match self.darwin_lock_target(&file) {
                Target::Lockf(v) => v,
                Target::NoAdvlock => return Err(Errno::EOPNOTSUPP),
                Target::NotVnode => return Ok(None),
            };
            let ty = if dflags & O_EXLOCK != 0 { F_WRLCK } else if dflags & O_SHLOCK != 0 { F_RDLCK } else { return Ok(None) };
            let wait = if dflags & O_NONBLOCK == 0 { lf::F_WAIT } else { 0 };
            self.darwin_flock_set(&file, v, ty, wait, Some(fd))
        })();
        match r {
            Ok(None) => {
                let _ = super::set_result(m, self.ctx_addr, fd as u64);
                SyscallOutcome::Continue
            }
            Ok(Some((c, d))) => self.darwin_block(m, Wait { deadline: d, cont: Finish::Lockf(c) }),
            Err(e) => {
                let _ = self.fds.close(fd);
                let _ = super::set_result(m, self.ctx_addr, e.as_return());
                SyscallOutcome::Continue
            }
        }
    }

    /// A blocked lock call's sleep has ended.
    pub(crate) fn darwin_lockf_wait_done(&mut self, m: &mut GuestMem<'_>, c: Cont, res: WaitResult) -> Option<SyscallOutcome> {
        let err = match res {
            WaitResult::Awakened => None,
            // msleep's EWOULDBLOCK, which lf_setlock makes ETIMEDOUT.
            WaitResult::TimedOut => Some(Errno::EAGAIN),
            WaitResult::Interrupted | WaitResult::Restart => {
                // PCATCH: ERESTART for a signal whose action restarts calls.
                if self.signals.restarts(crate::signal::Restart::SaRestart) {
                    let _ = resume(c.req, Some(Errno::EINTR));
                    if let Some(fd) = c.open_fd {
                        let _ = self.fds.close(fd);
                    }
                    let pc = m.read_u64(self.ctx_addr + gex_abi::ctx::PC as u64).ok()?;
                    let back = crate::syscalls::restart_call(m, self.ctx_addr, pc, false)?;
                    return Some(SyscallOutcome::Resume(back));
                }
                Some(Errno::EINTR)
            }
        };
        match resume(c.req, err) {
            Step::Blocked(_) => Some(self.darwin_block(m, Wait { deadline: None, cont: Finish::Lockf(c) })),
            Step::Done(r) => {
                if r.is_ok() {
                    if let Ok(file) = self.fds_by_ptr(c.fg) {
                        file.darwin_lflags.fetch_or(c.mark, std::sync::atomic::Ordering::AcqRel);
                    }
                }
                let ret = match (r, c.open_fd) {
                    (Ok(()), Some(fd)) => fd as u64,
                    (Ok(()), None) => 0,
                    (Err(e), fd) => {
                        if let Some(fd) = fd {
                            let _ = self.fds.close(fd);
                        }
                        e.as_return()
                    }
                };
                let _ = super::set_result(m, self.ctx_addr, ret);
                Some(SyscallOutcome::Continue)
            }
        }
    }

    /// The open file at address `fg` among the process's descriptors.
    fn fds_by_ptr(&self, fg: usize) -> Result<Arc<OpenFile>, Errno> {
        self.fds.list().into_iter().find_map(|(fd, _)| self.fds.get(fd).ok().filter(|f| Arc::as_ptr(f) as usize == fg)).ok_or(Errno::EBADF)
    }

    /// The vnodes the process's descriptors reach, for an exec's
    /// [`exec_keep`].
    pub(crate) fn darwin_lock_vnodes_open(&mut self) -> Vec<Vnode> {
        let files: Vec<Arc<OpenFile>> = self.fds.entries().into_iter().map(|(_, f, _)| f).collect();
        files.iter().filter_map(|f| match self.darwin_lock_target(f) {
            Target::Lockf(v) => Some(v),
            _ => None,
        }).collect()
    }

    /// A descriptor of this process is about to close: its POSIX locks on
    /// the file go with it (`closef_locked`), whichever descriptor took them.
    pub(crate) fn darwin_closing(&mut self, fd: i32) {
        if !self.dtask.ladvlock {
            return;
        }
        if let Ok(file) = self.fds.get(fd) {
            if let Target::Lockf(v) = self.darwin_lock_target(&file) {
                unlock_all(v, Id::Proc(self.pid), lf::F_POSIX);
            }
        }
    }
}

/// `check_file_seek_range`.
fn check_file_seek_range(fl: &Flock, cur: i64) -> Result<(), Errno> {
    if fl.whence == SEEK_CUR {
        let Some(s) = fl.start.checked_add(cur) else {
            return Err(if fl.start < 0 { Errno::EINVAL } else { Errno::EOVERFLOW });
        };
        if s < 0 {
            return Err(Errno::EINVAL);
        }
        if fl.len > 0 && s.checked_add(fl.len - 1).is_none() {
            return Err(Errno::EOVERFLOW);
        }
        if fl.len <= 0 && s + fl.len < 0 {
            return Err(Errno::EINVAL);
        }
    } else if fl.whence == SEEK_SET {
        if fl.start < 0 {
            return Err(Errno::EINVAL);
        }
        if fl.len > 0 && fl.start.checked_add(fl.len - 1).is_none() {
            return Err(Errno::EOVERFLOW);
        }
        if fl.len < 0 && fl.start + fl.len < 0 {
            return Err(Errno::EINVAL);
        }
    }
    Ok(())
}

/// The lock commands `fcntl` passes here.
pub fn is_lock_cmd(c: u64) -> bool {
    matches!(c, cmd::F_GETLK | cmd::F_SETLK | cmd::F_SETLKW | cmd::F_SETLKWTIMEOUT | cmd::F_GETLKPID | cmd::F_OFD_SETLK | cmd::F_OFD_SETLKW | cmd::F_OFD_GETLK | cmd::F_OFD_SETLKWTIMEOUT | cmd::F_OFD_GETLKPID)
}

/// The calls that are `flock` (for the thread-call dispatch).
pub const FLOCK: u64 = sys::FLOCK;

#[cfg(test)]
mod tests {
    use super::*;

    fn v(n: u64) -> Vnode {
        (0xdead, n)
    }

    fn set(vn: Vnode, pid: i32, ty: i16, start: i64, len: i64) -> Result<(), Errno> {
        let mut fl = Flock { start, len, ty, whence: SEEK_SET, pid: 0 };
        match advlock(vn, Id::Proc(pid), if ty == F_UNLCK { Op::Unlck } else { Op::SetLk }, &mut fl, lf::F_POSIX, Some(pid), None, || Ok(0)) {
            Step::Done(r) => r,
            Step::Blocked(_) => panic!("blocked"),
        }
    }

    fn get(vn: Vnode, pid: i32, ty: i16, start: i64, len: i64) -> Flock {
        let mut fl = Flock { start, len, ty, whence: SEEK_SET, pid: 0 };
        let _ = advlock(vn, Id::Proc(pid), Op::GetLk, &mut fl, lf::F_POSIX, None, None, || Ok(0));
        fl
    }

    fn ranges(vn: Vnode) -> Vec<(i64, i64, i16, Id)> {
        let t = table().lock().unwrap();
        t.lists.get(&vn).map_or(Vec::new(), |l| l.iter().map(|i| (t.locks[i].start, t.locks[i].end, t.locks[i].ty, t.locks[i].id)).collect())
    }

    #[test]
    fn locks_conflict_split_and_coalesce() {
        let vn = v(1);
        assert_eq!(set(vn, 10, F_WRLCK, 0, 100), Ok(()));
        assert_eq!(set(vn, 11, F_RDLCK, 50, 10), Err(Errno::EAGAIN));
        let g = get(vn, 11, F_RDLCK, 50, 10);
        assert_eq!((g.ty, g.start, g.len, g.pid), (F_WRLCK, 0, 100, 10));
        // An unlock in the middle splits the lock in two.
        assert_eq!(set(vn, 10, F_UNLCK, 40, 20), Ok(()));
        assert_eq!(ranges(vn), vec![(0, 39, F_WRLCK, Id::Proc(10)), (60, 99, F_WRLCK, Id::Proc(10))]);
        assert_eq!(set(vn, 11, F_RDLCK, 45, 10), Ok(()));
        // Relocking the gap coalesces the owner's three locks into one.
        assert_eq!(set(vn, 11, F_UNLCK, 0, 0), Ok(()));
        assert_eq!(set(vn, 10, F_WRLCK, 40, 20), Ok(()));
        assert_eq!(ranges(vn), vec![(0, 99, F_WRLCK, Id::Proc(10))]);
        // A downgrade of part of it splits it into three.
        assert_eq!(set(vn, 10, F_RDLCK, 10, 10), Ok(()));
        assert_eq!(ranges(vn), vec![(0, 9, F_WRLCK, Id::Proc(10)), (10, 19, F_RDLCK, Id::Proc(10)), (20, 99, F_WRLCK, Id::Proc(10))]);
        assert_eq!(get(vn, 12, F_RDLCK, 10, 10).ty, F_UNLCK);
        assert_eq!(set(vn, 10, F_UNLCK, 0, 0), Ok(()));
        assert!(ranges(vn).is_empty());
    }

    #[test]
    fn a_range_is_checked_as_lf_advlock_does() {
        let fl = Flock { start: 5, len: -10, ..Default::default() };
        assert_eq!(range(&fl, || Ok(0)), Err(Errno::EINVAL));
        let fl = Flock { start: 10, len: -5, ..Default::default() };
        assert_eq!(range(&fl, || Ok(0)), Ok((5, 9)));
        let fl = Flock { start: -3, len: 0, whence: SEEK_END, ..Default::default() };
        assert_eq!(range(&fl, || Ok(100)), Ok((97, -1)));
        let fl = Flock { start: i64::MAX, len: 2, ..Default::default() };
        assert_eq!(range(&fl, || Ok(0)), Err(Errno::EOVERFLOW));
    }
}
