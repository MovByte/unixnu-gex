//! Asynchronous I/O (`bsd/kern/kern_aio.c`, xnu-10063.141.1).
//!
//! A request is checked and put on the process's active queue as
//! `aio_queue_async_request` does, against the configured limits (the
//! iPhoneOS kernel's `xsmall` CONFIG_AIO_MAX, CONFIG_AIO_PROCESS_MAX). The
//! work queue is then run by the call that filled it, before it returns, as
//! a worker that took the requests at once would: each read, write or sync
//! is the descriptor's own, and its completion moves it to the done queue,
//! posts its signal and wakes `aio_suspend` and `lio_listio`. A request
//! only `aio_return` (or the process's exit or exec) takes off counts
//! against the limits until then.

use super::sysno as sys;
use super::wait::{Wait, WaitResult};
use crate::errno::Errno;
use crate::syscalls::{nr, Kernel, SyscallOutcome};
use crate::GuestMem;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

/// CONFIG_AIO_MAX, CONFIG_AIO_PROCESS_MAX (`config/MASTER`'s `xsmall`, which
/// MASTER.arm64.iPhoneOS's KERNEL_BASE names) and AIO_LISTIO_MAX.
pub const AIO_MAX: i32 = 20;
pub const AIO_PROCESS_MAX: usize = 8;
pub const AIO_THREAD_COUNT: i32 = 2;
const AIO_LISTIO_MAX: u64 = 16;

/// `aio_cancel`'s answers.
const AIO_ALLDONE: u64 = 0x1;
/// `lio_listio`'s modes and opcodes.
const LIO_NOWAIT: u64 = 0x1;
const LIO_WAIT: u64 = 0x2;
const LIO_NOP: i32 = 0x0;
const LIO_READ: i32 = 0x1;
const LIO_WRITE: i32 = 0x2;
/// `aio_fsync`'s operations.
const O_SYNC: u64 = 0x80;
const O_DSYNC: u64 = 0x40_0000;
/// `sigev_notify`.
const SIGEV_NONE: i32 = 0;
const SIGEV_SIGNAL: i32 = 1;
const NSIG: i32 = 32;
const SIGKILL: i32 = 9;
const SIGSTOP: i32 = 17;
const INT_MAX: u64 = i32::MAX as u64;
/// `sizeof(struct user64_aiocb)` and `sizeof(struct user64_sigevent)`.
const AIOCB_SIZE: usize = 80;
const SIGEVENT_SIZE: usize = 32;

/// `aio_anchor.aio_total_count`: every process's requests, until returned.
static TOTAL: AtomicI32 = AtomicI32::new(0);

/// `aio_entry_flags_t`.
mod flag {
    pub const READ: u32 = 0x1;
    pub const WRITE: u32 = 0x2;
    pub const FSYNC: u32 = 0x4;
    pub const DSYNC: u32 = 0x8;
    pub const LIO: u32 = 0x10;
}

/// `struct user_sigevent`, as far as AIO reads it.
#[derive(Clone, Copy, Debug, Default)]
struct Sigevent {
    notify: i32,
    signo: i32,
}

impl Sigevent {
    fn parse(b: &[u8]) -> Sigevent {
        let i = |o: usize| i32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        Sigevent { notify: i(0), signo: i(4) }
    }

    /// `aio_sigev_validate`: SIGEV_NONE, or SIGEV_SIGNAL with a signal that
    /// may be sent; SIGEV_THREAD is not supported.
    fn validate(&self) -> Result<(), Errno> {
        match self.notify {
            SIGEV_SIGNAL if self.signo <= 0 || self.signo >= NSIG || self.signo == SIGKILL || self.signo == SIGSTOP => Err(Errno::EINVAL),
            SIGEV_SIGNAL | SIGEV_NONE => Ok(()),
            _ => Err(Errno::EINVAL),
        }
    }
}

/// `struct user64_aiocb`.
#[derive(Clone, Copy, Debug)]
struct Aiocb {
    fildes: i32,
    offset: i64,
    buf: u64,
    nbytes: u64,
    sigevent: Sigevent,
    lio_opcode: i32,
}

impl Aiocb {
    fn read(m: &GuestMem<'_>, at: u64) -> Result<Aiocb, Errno> {
        let b = m.read(at, AIOCB_SIZE)?;
        let u = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let i = |o: usize| i32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        Ok(Aiocb { fildes: i(0), offset: u(8) as i64, buf: u(16), nbytes: u(24), sigevent: Sigevent::parse(&b[40..40 + SIGEVENT_SIZE]), lio_opcode: i(72) })
    }
}

/// `aio_workq_entry`.
#[derive(Clone, Debug)]
struct Entry {
    uaiocbp: u64,
    cb: Aiocb,
    flags: u32,
    errorval: i32,
    returnval: i64,
    /// The `lio_listio` call it came in, by number.
    group: Option<u64>,
}

/// A process's requests (`p_aio_activeq`, `p_aio_doneq`) and the threads
/// in `aio_suspend`.
#[derive(Debug, Default)]
pub struct Aio {
    active: VecDeque<Entry>,
    done: Vec<Entry>,
    /// Each `lio_listio` group's requests not yet done (`lio_pending`).
    pending: Vec<(u64, u32)>,
    next_group: u64,
    /// A thread in `aio_suspend`: the list it waits on and its deadline.
    pub(super) suspended: std::collections::HashMap<i32, (Vec<u64>, Option<Instant>)>,
}

/// A fork's child has no requests of its own.
impl Clone for Aio {
    fn clone(&self) -> Aio {
        Aio::default()
    }
}

/// `_aio_exit` (and `_aio_exec`): what was never returned stops counting.
impl Drop for Aio {
    fn drop(&mut self) {
        TOTAL.fetch_sub((self.active.len() + self.done.len()) as i32, Ordering::Relaxed);
    }
}

fn has_any_work() -> bool {
    TOTAL.load(Ordering::Relaxed) != 0
}

/// `aio_suspend`'s wait in progress (its list is in [`Aio::suspended`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cont;

impl Kernel {
    /// `aio_create_queue_entry`: the control block copied in and
    /// `aio_validate`d. Any failure is the caller's EAGAIN.
    fn darwin_aio_entry(&mut self, m: &GuestMem<'_>, uaiocbp: u64, mut flags: u32) -> Option<Entry> {
        let cb = Aiocb::read(m, uaiocbp).ok()?;
        if flags & flag::LIO != 0 {
            match cb.lio_opcode {
                LIO_READ => flags |= flag::READ,
                LIO_WRITE => flags |= flag::WRITE,
                LIO_NOP => return Some(Entry { uaiocbp, cb, flags, errorval: 0, returnval: 0, group: None }),
                _ => return None,
            }
        }
        let write = flags & (flag::WRITE | flag::FSYNC | flag::DSYNC) != 0;
        if flags & (flag::READ | flag::WRITE) != 0 && (cb.nbytes > INT_MAX || cb.buf == 0 || cb.offset < 0) {
            return None;
        }
        cb.sigevent.validate().ok()?;
        let file = self.fds.get(cb.fildes).ok()?;
        if (write && !file.writable) || (!write && !file.readable) {
            return None;
        }
        // DTYPE_VNODE: not a pipe, socket, kqueue or POSIX IPC object.
        let posix_ipc = std::sync::Arc::clone(&file.handle).as_posix_shm().is_some() || std::sync::Arc::clone(&file.handle).as_posix_sem().is_some();
        if posix_ipc || self.darwin_vnode_of(&file).is_none() {
            return None;
        }
        Some(Entry { uaiocbp, cb, flags, errorval: 0, returnval: 0, group: None })
    }

    /// `aio_try_enqueue_work_locked`: on the process's active queue, within
    /// the limits, and not a control block already there.
    fn darwin_aio_enqueue(&mut self, mut e: Entry, group: Option<u64>) -> bool {
        let a = &mut self.dtask.aio;
        if a.active.len() + a.done.len() >= AIO_PROCESS_MAX {
            return false;
        }
        if a.active.iter().chain(a.done.iter()).any(|x| x.uaiocbp == e.uaiocbp) {
            return false;
        }
        if TOTAL.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |t| (t < AIO_MAX).then_some(t + 1)).is_err() {
            return false;
        }
        if let Some(g) = group {
            match a.pending.iter_mut().find(|p| p.0 == g) {
                Some(p) => p.1 += 1,
                None => a.pending.push((g, 1)),
            }
        }
        e.group = group;
        a.active.push_back(e);
        true
    }

    /// The work queue run: each request done in order, then completed.
    fn darwin_aio_work(&mut self, m: &mut GuestMem<'_>) {
        while let Some(mut e) = self.dtask.aio.active.pop_front() {
            let fd = e.cb.fildes as u64;
            let r = if e.flags & flag::READ != 0 {
                self.darwin_aio_io(m, &e, false)
            } else if e.flags & flag::WRITE != 0 {
                self.darwin_aio_io(m, &e, true)
            } else if e.flags & (flag::FSYNC | flag::DSYNC) != 0 {
                let call = if e.flags & flag::FSYNC != 0 { nr::FSYNC } else { nr::FDATASYNC };
                self.canonical(m, call, [fd, 0, 0, 0, 0, 0]).map_err(|e| (e, -1))
            } else {
                Err((Errno::EINVAL, 0))
            };
            match r {
                Ok(n) => (e.errorval, e.returnval) = (0, n as i64),
                Err((err, ret)) => (e.errorval, e.returnval) = (super::errno::to_darwin(err.0), ret),
            }
            self.darwin_aio_completion(m, e);
        }
    }

    /// `do_aio_read` and `do_aio_write`: `dofileread` and `dofilewrite` at
    /// the request's offset, or the descriptor's for an O_APPEND write.
    fn darwin_aio_io(&mut self, m: &mut GuestMem<'_>, e: &Entry, write: bool) -> Result<u64, (Errno, i64)> {
        let fd = e.cb.fildes;
        let file = self.fds.get(fd).map_err(|err| (err, 0))?;
        if (write && !file.writable) || (!write && !file.readable) {
            return Err((Errno::EBADF, 0));
        }
        if file.is_tty() {
            self.darwin_unimplemented("an asynchronous read or write of a terminal (a worker thread waiting on it)".into());
            return Err((Errno::EINVAL, 0));
        }
        let (fd, buf, n, off) = (fd as u64, e.cb.buf, e.cb.nbytes, e.cb.offset as u64);
        let r = if write && file.flags() & crate::fs::oflags::O_APPEND != 0 {
            self.canonical(m, nr::WRITE, [fd, buf, n, 0, 0, 0])
        } else {
            self.canonical(m, if write { nr::PWRITE64 } else { nr::PREAD64 }, [fd, buf, n, off, 0, 0])
        };
        r.map_err(|err| (err, 0))
    }

    /// `do_aio_completion_and_unlock`: on the done queue; the signal for one
    /// alone or the last of its `lio_listio`; `aio_suspend` woken.
    fn darwin_aio_completion(&mut self, m: &mut GuestMem<'_>, e: Entry) {
        let mut last = true;
        if let Some(g) = e.group {
            let a = &mut self.dtask.aio;
            if let Some(i) = a.pending.iter().position(|p| p.0 == g) {
                a.pending[i].1 -= 1;
                last = a.pending[i].1 == 0;
                if last {
                    a.pending.remove(i);
                }
            }
        }
        let signal = (e.cb.sigevent.notify == SIGEV_SIGNAL && last).then_some(e.cb.sigevent.signo as u32);
        self.dtask.aio.done.push(e);
        if let Some(s) = signal {
            self.darwin_kill_post(self.pid, s);
        }
        let waiting: Vec<i32> = self.dtask.aio.suspended.keys().copied().collect();
        for tid in waiting {
            self.darwin_wake(m, tid, WaitResult::Awakened);
        }
    }

    /// `aio_read`, `aio_write` and `aio_fsync`.
    fn darwin_aio_queue(&mut self, m: &mut GuestMem<'_>, uaiocbp: u64, flags: u32) -> Result<u64, Errno> {
        let e = self.darwin_aio_entry(m, uaiocbp, flags).ok_or(Errno::EAGAIN)?;
        if !self.darwin_aio_enqueue(e, None) {
            return Err(Errno::EAGAIN);
        }
        self.darwin_aio_work(m);
        Ok(0)
    }

    /// `aio_error(aiocbp)`.
    fn darwin_aio_error(&mut self, a: &[u64; 6]) -> Result<u64, Errno> {
        if !has_any_work() {
            return Err(Errno::EINVAL);
        }
        let q = &self.dtask.aio;
        if let Some(e) = q.done.iter().find(|e| e.uaiocbp == a[0]) {
            return Ok(e.errorval as u32 as u64);
        }
        if q.active.iter().any(|e| e.uaiocbp == a[0]) {
            return Ok(36); // EINPROGRESS
        }
        Err(Errno::EINVAL)
    }

    /// `aio_return(aiocbp)`: the request off the done queue.
    fn darwin_aio_return(&mut self, a: &[u64; 6]) -> Result<u64, Errno> {
        if !has_any_work() {
            return Err(Errno::EINVAL);
        }
        let q = &mut self.dtask.aio;
        if let Some(i) = q.done.iter().position(|e| e.uaiocbp == a[0]) {
            let e = q.done.remove(i);
            TOTAL.fetch_sub(1, Ordering::Relaxed);
            return Ok(e.returnval as u64);
        }
        if q.active.iter().any(|e| e.uaiocbp == a[0]) {
            return Err(Errno::EINPROGRESS);
        }
        Err(Errno::EINVAL)
    }

    /// `aio_cancel(fd, aiocbp)`: nothing is left on the work queue to take
    /// back, so a match is AIO_ALLDONE and none is EBADF.
    fn darwin_aio_cancel(&mut self, m: &GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        if !has_any_work() {
            return Ok(AIO_ALLDONE);
        }
        let (fd, aiocbp) = (a[0] as i32, a[1]);
        if aiocbp != 0 {
            let cb = Aiocb::read(m, aiocbp).map_err(|_| Errno::EAGAIN)?;
            if cb.fildes != fd {
                return Err(Errno::EBADF);
            }
        }
        let matches = |e: &Entry| e.cb.fildes == fd && (aiocbp == 0 || e.uaiocbp == aiocbp);
        if self.dtask.aio.done.iter().any(matches) {
            Ok(AIO_ALLDONE)
        } else {
            Err(Errno::EBADF)
        }
    }

    /// `aio_fsync(op, aiocbp)`.
    fn darwin_aio_fsync(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        let kind = match a[0] as u32 as u64 {
            O_SYNC | 0 => flag::FSYNC,
            O_DSYNC => flag::DSYNC,
            _ => return Err(Errno::EINVAL),
        };
        self.darwin_aio_queue(m, a[1], kind)
    }

    /// `lio_listio(mode, aiocblist, nent, sigp)`.
    fn darwin_lio_listio(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        let (mode, list, nent, sigp) = (a[0] as u32 as u64, a[1], a[2] as i32, a[3]);
        if mode != LIO_NOWAIT && mode != LIO_WAIT {
            return Err(Errno::EINVAL);
        }
        if nent < 1 || nent as u64 > AIO_LISTIO_MAX {
            return Err(Errno::EINVAL);
        }
        let mut sigev = Sigevent::default();
        if sigp != 0 {
            sigev = Sigevent::parse(&m.read(sigp, SIGEVENT_SIZE).map_err(|_| Errno::EAGAIN)?);
            sigev.validate()?;
        }
        let ptrs = m.read(list, nent as usize * 8).map_err(|_| Errno::EAGAIN)?.to_vec();
        let mut entries = Vec::new();
        for p in ptrs.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).filter(|&p| p != 0) {
            let mut e = self.darwin_aio_entry(m, p, flag::LIO).ok_or(Errno::EAGAIN)?;
            if mode == LIO_NOWAIT {
                e.cb.sigevent = sigev;
            }
            entries.push(e);
        }
        if entries.is_empty() {
            return Ok(0);
        }
        let group = self.dtask.aio.next_group;
        self.dtask.aio.next_group += 1;
        let mut result = Ok(0);
        for e in entries {
            if !self.darwin_aio_enqueue(e, Some(group)) {
                result = Err(Errno::EAGAIN);
            }
        }
        // The group's last request is done before this returns, so a
        // LIO_WAIT has nothing left to wait for.
        self.darwin_aio_work(m);
        result
    }

    /// The calls that answer at once.
    pub(crate) fn darwin_aio_call(&mut self, m: &mut GuestMem<'_>, raw: u64, a: &[u64; 6]) -> Option<Result<u64, Errno>> {
        Some(match raw {
            sys::AIO_READ => self.darwin_aio_queue(m, a[0], flag::READ),
            sys::AIO_WRITE => self.darwin_aio_queue(m, a[0], flag::WRITE),
            sys::AIO_FSYNC => self.darwin_aio_fsync(m, a),
            sys::AIO_ERROR => self.darwin_aio_error(a),
            sys::AIO_RETURN => self.darwin_aio_return(a),
            sys::AIO_CANCEL => self.darwin_aio_cancel(m, a),
            sys::LIO_LISTIO => self.darwin_lio_listio(m, a),
            _ => return None,
        })
    }

    /// Whether one of the listed requests is done.
    fn darwin_aio_any_done(&self, list: &[u64]) -> bool {
        list.iter().any(|&p| p != 0 && self.dtask.aio.done.iter().any(|e| e.uaiocbp == p))
    }

    /// `aio_suspend(aiocblist, nent, timeoutp)` and its `_nocancel` form.
    pub(crate) fn darwin_aio_suspend(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> SyscallOutcome {
        match self.darwin_aio_suspend_start(m, a) {
            Ok(Some(deadline)) => self.darwin_block(m, Wait { deadline, cont: super::thread::Finish::AioSuspend(Cont) }),
            Ok(None) => {
                super::thread::bsd_result(m, self.ctx_addr, Ok(0), false);
                SyscallOutcome::Continue
            }
            Err(e) => {
                super::thread::bsd_result(m, self.ctx_addr, Err(e), false);
                SyscallOutcome::Continue
            }
        }
    }

    /// The checks, then `Some(deadline)` to wait or `None` when one is done.
    fn darwin_aio_suspend_start(&mut self, m: &GuestMem<'_>, a: &[u64; 6]) -> Result<Option<Option<Instant>>, Errno> {
        if !has_any_work() {
            return Err(Errno::EINVAL);
        }
        let nent = a[1] as i32;
        if nent < 1 || nent as usize > AIO_PROCESS_MAX {
            return Err(Errno::EINVAL);
        }
        let mut deadline = None;
        if a[2] != 0 {
            let (sec, nsec) = match (m.read_u64(a[2]), m.read_u64(a[2] + 8)) {
                (Ok(s), Ok(n)) => (s as i64, n as i64),
                _ => return Err(Errno::EAGAIN),
            };
            if sec < 0 || nsec < 0 || nsec >= 1_000_000_000 {
                return Err(Errno::EINVAL);
            }
            deadline = Instant::now().checked_add(Duration::from_secs(sec as u64) + Duration::from_nanos(nsec as u64));
        }
        let list: Vec<u64> = m.read(a[0], nent as usize * 8).map_err(|_| Errno::EAGAIN)?.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
        if self.darwin_aio_any_done(&list) {
            return Ok(None);
        }
        self.dtask.aio.suspended.insert(self.tid, (list, deadline));
        Ok(Some(deadline))
    }

    /// An `aio_suspend` woken: done if one of its requests is, otherwise
    /// asleep again; EAGAIN at its deadline, EINTR for a signal.
    pub(crate) fn darwin_aio_suspend_done(&mut self, m: &mut GuestMem<'_>, res: WaitResult) -> Option<SyscallOutcome> {
        let (list, deadline) = self.dtask.aio.suspended.remove(&self.tid).expect("an aio_suspend");
        let r = match res {
            WaitResult::Awakened if self.darwin_aio_any_done(&list) => Ok(0),
            WaitResult::Awakened => {
                self.dtask.aio.suspended.insert(self.tid, (list, deadline));
                return Some(self.darwin_block(m, Wait { deadline, cont: super::thread::Finish::AioSuspend(Cont) }));
            }
            WaitResult::TimedOut => Err(Errno::EAGAIN),
            WaitResult::Interrupted | WaitResult::Restart => Err(Errno::EINTR),
        };
        super::thread::bsd_result(m, self.ctx_addr, r, false);
        None
    }
}
