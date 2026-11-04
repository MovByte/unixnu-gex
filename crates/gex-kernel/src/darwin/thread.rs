//! Darwin threads and the waits they make: `bsdthread_create` starting a
//! thread at libpthread's registered entry, `bsdthread_terminate`, and the
//! `ulock` wait and wake that `os_unfair_lock`, mutexes and joins sit on.

use super::bsd::sys;
use crate::errno::Errno;
use crate::syscalls::{Kernel, SyscallOutcome};
use crate::GuestMem;
use gex_abi::ctx;

/// `PTHREAD_START_CUSTOM`: the caller allocated the stack and the pthread.
const PTHREAD_START_CUSTOM: u64 = 0x0100_0000;
/// `PTHREAD_START_TSD_BASE_SET`: the kernel pointed the new thread's TSD
/// base at its pthread; `_pthread_start` traps without it.
const PTHREAD_START_TSD_BASE_SET: u64 = 0x1000_0000;
/// `PTHREAD_START_SUSPENDED`, which the kernel strips to show it is known.
const PTHREAD_START_SUSPENDED: u64 = 0x0200_0000;

/// `UL_*` operations and `ULF_*` flags (`bsd/sys/ulock.h`).
mod ul {
    pub const OPCODE_MASK: u64 = 0xff;
    pub const COMPARE_AND_WAIT64: u64 = 5;
    pub const COMPARE_AND_WAIT64_SHARED: u64 = 6;
    pub const WAKE_ALL: u64 = 0x100;
    pub const NO_ERRNO: u64 = 0x0100_0000;
}

/// How a Darwin call that blocked turns the wait's result into its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Finish {
    /// `ulock_wait`: woken or a changed word is 0; with `ULF_NO_ERRNO` an
    /// error is a negative value with carry clear.
    Ulock { no_errno: bool },
}

/// Write `r` back as `ulock` returns it.
fn ulock_result(m: &mut GuestMem<'_>, ctx_addr: u64, r: Result<u64, Errno>, no_errno: bool) {
    let r = match r {
        // EAGAIN is the word having changed before the wait began.
        Err(e) if e == Errno::EAGAIN => Ok(0),
        r => r,
    };
    match r {
        Ok(v) => {
            let _ = super::set_result(m, ctx_addr, v);
        }
        Err(e) if no_errno => {
            let darwin = super::errno::to_darwin(e.0);
            let _ = m.write_u64(ctx_addr + ctx::x(0) as u64, (-(darwin as i64)) as u64);
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
            sys::BSDTHREAD_CREATE => Some(self.darwin_bsdthread_create(m, a)),
            // `bsdthread_terminate(freeaddr, freesize, kport, joinsem)`:
            // the stack goes and the joiner's semaphore is signalled here;
            // the thread's end is `exit`'s ([`super::bsd::translate`]).
            sys::BSDTHREAD_TERMINATE => {
                if a[1] != 0 {
                    let _ = self.canonical(m, crate::syscalls::nr::MUNMAP, [a[0], a[1], 0, 0, 0, 0]);
                }
                if a[3] != 0 {
                    self.semaphore_signal(a[3] as u32);
                }
                None
            }
            sys::ULOCK_WAIT | sys::ULOCK_WAIT2 => Some(self.darwin_ulock_wait(m, raw, a)),
            sys::ULOCK_WAKE => {
                let no_errno = a[0] & ul::NO_ERRNO != 0;
                let n = if a[0] & ul::WAKE_ALL != 0 { u32::MAX } else { 1 };
                let woke = self.futexes.wake(a[1], n);
                let r = if woke == 0 { Err(Errno::ENOENT) } else { Ok(0) };
                ulock_result(m, self.ctx_addr, r, no_errno);
                Some(SyscallOutcome::Continue)
            }
            _ => None,
        }
    }

    /// `bsdthread_create(func, arg, stack, pthread, flags)`: a thread that
    /// starts at libpthread's `thread_start` with the pthread, its port, the
    /// function, its argument and the flags in x0-x5, on `stack`, with its
    /// TSD at the pthread's TSD offset. The caller gets the pthread back.
    fn darwin_bsdthread_create(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> SyscallOutcome {
        use crate::syscalls::clone_flags as cf;
        let (func, arg, stack, pthread, flags) = (a[0], a[1], a[2], a[3], a[4]);
        let fail = |k: &Kernel, m: &mut GuestMem<'_>, e: Errno| {
            let _ = super::set_result(m, k.ctx_addr, (-(e.0 as i64)) as u64);
            SyscallOutcome::Continue
        };
        if flags & PTHREAD_START_CUSTOM == 0 || self.darwin_thread_entry.0 == 0 {
            return fail(self, m, Errno::EINVAL);
        }
        let clone = cf::VM | cf::FS | cf::FILES | cf::SIGHAND | cf::THREAD | cf::SYSVSEM;
        let req = match self.darwin_clone(m, [clone, stack, 0, 0, 0, 0]) {
            Ok(r) => r,
            Err(e) => return fail(self, m, e),
        };
        let port = self.darwin_ports.thread(req.tid);
        let c = req.ctx_addr;
        let tsd = pthread + self.darwin_tsd_offset;
        if self.darwin_port_offset != 0 {
            let _ = m.write_u32(tsd + self.darwin_port_offset, port);
        }
        let flags = (flags | PTHREAD_START_TSD_BASE_SET) & !PTHREAD_START_SUSPENDED;
        let regs = [(ctx::x(0), pthread), (ctx::x(1), u64::from(port)), (ctx::x(2), func), (ctx::x(3), arg), (ctx::x(4), 0), (ctx::x(5), flags)];
        for (slot, v) in regs {
            let _ = m.write_u64(c + slot as u64, v);
        }
        let _ = m.write_u64(c + ctx::x(29) as u64, 0);
        let _ = m.write_u64(c + ctx::x(30) as u64, 0);
        let _ = m.write_u64(c + ctx::SP as u64, stack);
        let _ = m.write_u64(c + ctx::PC as u64, self.darwin_thread_entry.0);
        let _ = m.write_u64(c + ctx::TPIDRRO as u64, tsd);
        let _ = super::set_result(m, self.ctx_addr, pthread);
        if self.trace {
            eprintln!("[gex:{}] bsdthread_create(func {func:#x}, stack {stack:#x}) = thread {} (port {port:#x})", self.pid, req.tid);
        }
        SyscallOutcome::SpawnThread { ctx_addr: req.ctx_addr, tid: req.tid }
    }

    /// `ulock_wait(op, addr, value, timeout_us)` and `ulock_wait2(op, addr,
    /// value, timeout_ns, value2)`.
    fn darwin_ulock_wait(&mut self, m: &mut GuestMem<'_>, raw: u64, a: &[u64; 6]) -> SyscallOutcome {
        let (op, addr, value) = (a[0], a[1], a[2]);
        let no_errno = op & ul::NO_ERRNO != 0;
        let wide = matches!(op & ul::OPCODE_MASK, ul::COMPARE_AND_WAIT64 | ul::COMPARE_AND_WAIT64_SHARED);
        let current = if wide { m.read_u64(addr) } else { m.read_u32(addr).map(u64::from) };
        let current = match current {
            Ok(v) => v,
            Err(e) => {
                ulock_result(m, self.ctx_addr, Err(e), no_errno);
                return SyscallOutcome::Continue;
            }
        };
        let want = if wide { value } else { value & 0xffff_ffff };
        if current != want {
            ulock_result(m, self.ctx_addr, Ok(0), no_errno);
            return SyscallOutcome::Continue;
        }
        let deadline = match (raw, a[3]) {
            (_, 0) => None,
            (sys::ULOCK_WAIT, us) => Some(std::time::Duration::from_micros(us & 0xffff_ffff)),
            (_, ns) => Some(std::time::Duration::from_nanos(ns)),
        };
        let mapped = |at: u64, len: u64| self.mem.lock().vma_at(at).is_some_and(|v| at + len <= v.end);
        let cx = self.futex_cx(&mapped);
        match crate::syscalls::futex_wait_op(&cx, m, addr, current as u32, deadline) {
            Some(op) => {
                self.darwin_finish = Some(Finish::Ulock { no_errno });
                SyscallOutcome::Blocking(op)
            }
            None => {
                ulock_result(m, self.ctx_addr, Ok(0), no_errno);
                SyscallOutcome::Continue
            }
        }
    }

    /// Write a blocked Darwin call's result its own way; `false` when the
    /// call was not one that needs it.
    pub(crate) fn darwin_finish_blocking(&mut self, m: &mut GuestMem<'_>, r: Result<u64, Errno>) -> bool {
        match self.darwin_finish.take() {
            Some(Finish::Ulock { no_errno }) => {
                ulock_result(m, self.ctx_addr, r, no_errno);
                true
            }
            None => false,
        }
    }
}
