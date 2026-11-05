//! The Darwin personality: a Mach-O process's system calls.
//!
//! Darwin enters the kernel with `svc #0x80` and the number in x16, and its
//! numbering says which kernel answers: a positive number is a BSD system
//! call, a negative one a Mach trap, and `0x8000_0000` the machine-dependent
//! calls (the thread's TSD pointer). BSD calls with a Linux counterpart are
//! renumbered onto it ([`bsd::translate`]) and run through the same
//! dispatch as a Linux process's, as the i386 and x86-64 numberings are;
//! the result goes back Darwin's way, with the carry flag set and a Darwin
//! errno in x0 on failure ([`set_result`]).

use crate::errno::Errno;
use crate::GuestMem;
use gex_abi::ctx;

pub mod attrcall;
pub mod attrlist;
pub mod bsd;
pub mod codesign;
pub mod commpage;
pub mod errno;
pub mod exec;
pub mod exit;
pub mod execve;
pub mod fsops;
pub mod ioctl;
pub mod ipc;
pub mod kern;
pub mod kevent;
pub mod kfilt;
pub mod kobject;
pub mod lockf;
pub mod mach;
pub mod mach_msg;
pub mod mig;
pub mod mk_timer;
pub mod mwl;
pub mod pipe;
pub mod psynch;
pub mod rlimit;
pub mod sema;
pub mod shm;
pub mod signal;
pub mod sockaddr;
pub mod spawn;
pub mod sysctl;
pub mod sysno;
pub mod thread;
pub mod timer;
pub mod vm;
pub mod voucher;
pub mod wait;
pub mod workq;

/// A Darwin process's kernel state beyond the BSD side's: its threads and
/// what they wait on.
#[derive(Debug, Default)]
pub struct Task {
    pub pthread: thread::Registration,
    pub threads: thread::Threads,
    pub waits: wait::Waits,
    pub ulocks: thread::Ulocks,
    pub psynch: psynch::Psynch,
    pub timers: timer::Timers,
    /// Threads made by a call (resumed, or the workqueue's) for the host to
    /// start after it ([`crate::syscalls::Kernel::take_spawns`]).
    pub spawns: Vec<crate::syscalls::SpawnRequest>,
    /// `GEX_DARWIN_STRICT=1`: stop the process at the first thing it asks
    /// for that this kernel does not do.
    pub strict: bool,
    /// The program's `LC_BUILD_VERSION` platform and SDK (`p_platform`,
    /// `p_sdk`).
    pub platform: (u32, u32),
    /// The task's IPC.
    pub ipc: ipc::Ipc,
    /// The kernel objects' ports.
    pub kports: kobject::Kports,
    pub semas: sema::Semas,
    pub mk_timers: mk_timer::MkTimers,
    /// `p_idversion`, from the system's `nextpidversion` at exec.
    pub pidversion: i32,
    /// The workqueue, once opened (`p_wqptr`), and what it owes: threads
    /// to wake or start, a creator pass.
    pub workq: Option<Box<workq::Workq>>,
    pub workq_wake: Vec<i32>,
    pub workq_creator_pending: Option<u32>,
    /// Every thread request: the workqueue's (`workq_kernreturn`'s) and
    /// the kqueues' (`kqwq_request`, `kqwl_request`).
    pub threadreqs: std::collections::HashMap<workq::ReqId, workq::Req>,
    pub next_threadreq: u64,
    /// The process's kqueues and knotes.
    pub kevents: kevent::Kevents,
    /// The process's vouchers and their attribute managers' state.
    pub vouchers: voucher::Vouchers,
    /// The program's code signature, when it has one.
    pub codesign: Option<codesign::CodeSign>,
    /// `P_LADVLOCK`: the process has taken a POSIX record lock.
    pub ladvlock: bool,
    /// Threads whose lock requests another thread or process woke.
    pub lock_wakes: std::sync::Arc<std::sync::Mutex<Vec<i32>>>,
    /// `p_sigacts` and `p_sigignore`.
    pub sigacts: signal::Sigacts,
    /// `p_limit`.
    pub rlimits: rlimit::Rlimits,
    /// `P_LCUSTOM_STACK`: the main stack's size came from `LC_MAIN`.
    pub custom_stack: bool,
    /// `p_disallow_map_with_linking`: dyld said it is done mapping with
    /// linking.
    pub disallow_mwl: bool,
    /// `p_workq_allow_sigmask`.
    pub workq_allow_sigmask: u32,
    /// `p_dispatchqueue_serialno_offset`, `p_dispatchqueue_label_offset`.
    pub dispatchqueue_serialno_offset: u64,
    pub dispatchqueue_label_offset: u64,
    /// The task's app type (`trp_apptype`).
    pub apptype: workq::AppType,
    /// Maximum protections lowered from `VM_PROT_ALL`.
    pub maxprot: vm::MaxProt,
    /// Threads a semaphore operation woke, and how.
    pub sema_wake: Vec<(i32, wait::WaitResult)>,
    /// A blocked send's message and its send buffer, by thread.
    pub pending_send: std::collections::HashMap<i32, Box<ipc::msg::Kmsg>>,
    pub pending_send_buf: std::collections::HashMap<i32, (u64, u32)>,
    /// A fatal guard exception was raised: the task is killed when the call
    /// returns.
    pub guard_kill: bool,
    /// What has been reported as not done, so each is said once.
    said: std::collections::HashSet<String>,
    /// Under strict mode, the unimplemented thing that stops the process
    /// when the call returns.
    stop: Option<String>,
}

impl Task {
    /// A new process's task: it takes the next pidversion.
    pub fn new_process() -> Task {
        Task { pidversion: next_pidversion(), ..Default::default() }
    }
}

impl crate::syscalls::Kernel {
    /// Something a Darwin program asked for that this kernel does not do.
    /// It is said once per kind; under strict mode the process stops with
    /// SIGSYS when the call returns ([`Self::darwin_strict_stop`]).
    pub(crate) fn darwin_unimplemented(&mut self, what: String) {
        if self.dtask.said.insert(what.clone()) || self.trace {
            eprintln!("[gex:{}] Darwin: not implemented: {what}", self.pid);
        }
        if self.dtask.strict && self.dtask.stop.is_none() {
            self.dtask.stop = Some(what);
        }
    }

    /// The strict-mode stop a call left, taken.
    pub(crate) fn darwin_strict_stop(&mut self) -> Option<String> {
        self.dtask.stop.take()
    }

    /// The task's audit token (`proc_calc_audit_token`): auid, euid, egid,
    /// ruid, rgid, pid, asid, pidversion. A process launchd has put in no
    /// session has the default one (`AU_DEFAUDITID`, `AU_DEFAUDITSID`); gex
    /// keeps one identity, so the real ids are the effective ones.
    pub(crate) fn darwin_audit_token(&self) -> [u32; 8] {
        const AU_DEFAUDITID: u32 = u32::MAX;
        const AU_DEFAUDITSID: u32 = 0;
        let (uid, gid) = (self.creds.uid(), self.creds.gid());
        [AU_DEFAUDITID, uid, gid, uid, gid, self.pid as u32, AU_DEFAUDITSID, self.dtask.pidversion as u32]
    }

    /// A fatal Mach port guard exception was raised: with no exception
    /// handler the task exits as `exit_with_mach_exception` makes it, killed
    /// by SIGKILL.
    pub(crate) fn darwin_guard_kill(&mut self) -> Option<crate::syscalls::SyscallOutcome> {
        std::mem::take(&mut self.dtask.guard_kill).then_some(crate::syscalls::SyscallOutcome::Killed { signal: crate::signal::sig::SIGKILL as u32, core: false })
    }
}

/// `nextpidversion`: one counter for the system, taken at each exec
/// (`OSIncrementAtomic` returns the value before).
pub fn next_pidversion() -> i32 {
    static NEXT: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Where iOS 17 keeps the shared cache, inside the SystemOS cryptex.
pub const CACHE_PATH: &str = "/System/Cryptexes/OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64";

/// The ids the shared cache's dynamic data names it by, which
/// `fsgetpath` answers with [`CACHE_PATH`].
pub const CACHE_FS_ID: u64 = 0x0100_0004;
pub const CACHE_OBJ_ID: u64 = 0x0dcc_0001;

/// Where a Darwin thread puts its system call number.
pub const NR_SLOT: usize = ctx::x(16);

/// The machine-dependent call class (`PLATFORM_SYSCALL_TRAP_NO`'s x16).
pub const PLATFORM: u64 = 0x8000_0000;

/// `machdep_call` numbers in x3 under [`PLATFORM`].
pub mod machdep {
    pub const ICACHE_INVALIDATE: u64 = 0;
    pub const DCACHE_FLUSH: u64 = 1;
    pub const THREAD_SET_TSD: u64 = 2;
}

/// A call answered here without going through the Linux dispatch: the
/// machine-dependent class. `None` for everything else.
pub fn direct(m: &mut GuestMem<'_>, ctx_addr: u64, raw: u64) -> Option<u64> {
    if raw as u32 as u64 != PLATFORM {
        return None;
    }
    let code = m.read_u64(ctx_addr + ctx::x(3) as u64).unwrap_or(!0);
    Some(match code {
        // gex keeps no instruction cache to invalidate, and its data
        // writes are already visible.
        machdep::ICACHE_INVALIDATE | machdep::DCACHE_FLUSH => 0,
        machdep::THREAD_SET_TSD => {
            let tsd = m.read_u64(ctx_addr + ctx::x(0) as u64).unwrap_or(0);
            match m.write_u64(ctx_addr + ctx::TPIDRRO as u64, tsd) {
                Ok(()) => 0,
                Err(e) => neg(e),
            }
        }
        _ => neg(Errno::ENOSYS),
    })
}

fn neg(e: Errno) -> u64 {
    (-(e.0 as i64)) as u64
}

/// Whether x16's number is a Mach trap: negative as the 32-bit value
/// libsyscall loads (`mov w16, #-n`), the machine-dependent class aside.
/// What a BSD call number comes to (`unix_syscall`).
pub enum Bsd {
    /// Call `nr`; its arguments start at register `first` (x1 for an
    /// indirect call through call 0, x0 otherwise).
    Call { nr: u64, first: u8 },
    /// An `enosys` entry: ENOSYS.
    Enosys,
    /// `nosys` (a retired entry, or past the table): SIGSYS, then ENOSYS.
    Nosys,
}

/// Resolve x16 as XNU does: zero means the number is in x0 and the
/// arguments follow it; the number is truncated to 16 bits, and one past
/// the table is `SYS_invalid`, a `nosys` entry.
pub fn bsd_call(m: &GuestMem<'_>, ctx_addr: u64, raw: u64) -> Bsd {
    let (code, first) = if raw != 0 {
        (raw as u16 as u64, 0)
    } else {
        (m.read_u64(ctx_addr + ctx::x(0) as u64).unwrap_or(0) as u16 as u64, 1)
    };
    if code >= sysno::NSYSENT {
        Bsd::Nosys
    } else if sysno::ENOSYS.contains(&code) {
        Bsd::Enosys
    } else if sysno::name(code).is_none() {
        Bsd::Nosys
    } else {
        Bsd::Call { nr: code, first }
    }
}

pub fn mach_trap_number(raw: u64) -> Option<i32> {
    let t = raw as u32 as i32;
    (t < 0 && raw as u32 as u64 != PLATFORM).then_some(t)
}

/// Write a Mach trap's result: x0 only.
pub fn set_mach_result(m: &mut GuestMem<'_>, ctx_addr: u64, kr: u64) -> Result<(), Errno> {
    m.write_u64(ctx_addr + ctx::x(0) as u64, kr)
}

/// Write a result in the canonical encoding (a value, or `-errno` with a
/// Linux errno) back the way Darwin returns it: on success the value in x0
/// and carry clear, on failure the Darwin errno in x0 and carry set.
pub fn set_result(m: &mut GuestMem<'_>, ctx_addr: u64, ret: u64) -> Result<(), Errno> {
    let r = ret as i64;
    let (x0, carry) = if (-4095..0).contains(&r) { (errno::to_darwin(-r as i32) as u64, 1u8) } else { (ret, 0u8) };
    m.write_u64(ctx_addr + ctx::x(0) as u64, x0)?;
    m.write(ctx_addr + ctx::CF as u64, &[carry])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_mem() -> Vec<u8> {
        vec![0u8; ctx::TPIDRRO + 64]
    }

    #[test]
    fn success_clears_carry() {
        let mut b = ctx_mem();
        b[ctx::CF] = 1;
        let mut m = GuestMem::new(&mut b);
        set_result(&mut m, 0, 18).unwrap();
        assert_eq!(m.read_u64(ctx::x(0) as u64).unwrap(), 18);
        assert_eq!(b[ctx::CF], 0);
    }

    #[test]
    fn failure_sets_carry_and_the_darwin_errno() {
        let mut b = ctx_mem();
        let mut m = GuestMem::new(&mut b);
        // Linux EAGAIN (11) is Darwin's 35.
        set_result(&mut m, 0, (-11i64) as u64).unwrap();
        assert_eq!(m.read_u64(ctx::x(0) as u64).unwrap(), 35);
        assert_eq!(b[ctx::CF], 1);
    }

    #[test]
    fn thread_set_tsd_writes_tpidrro() {
        let mut b = ctx_mem();
        let mut m = GuestMem::new(&mut b);
        m.write_u64(ctx::x(0) as u64, 0x2_0000_8000).unwrap();
        m.write_u64(ctx::x(3) as u64, machdep::THREAD_SET_TSD).unwrap();
        assert_eq!(direct(&mut m, 0, PLATFORM), Some(0));
        assert_eq!(m.read_u64(ctx::TPIDRRO as u64).unwrap(), 0x2_0000_8000);
        assert_eq!(direct(&mut m, 0, 4), None);
    }
}
