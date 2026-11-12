//! Mach traps: the negative system call numbers (`osfmk/kern/syscall_sw.c`
//! of the profile's XNU, `osfmk/arm64/bsd_arm64.c`'s `mach_syscall`).
//!
//! A trap returns a `kern_return_t` (or a port name) in x0 and leaves the
//! carry flag alone. A number with no trap raises `EXC_SYSCALL`, which the
//! host's own handler makes SIGSYS. The `_kernelrpc_*` traps are
//! `osfmk/ipc/mach_kernelrpc.c`'s.

use super::ipc::kr;
use super::ipc::{MachIpc, Mach};
use super::wait::{Wait, WaitResult};
use crate::errno::Errno;
use crate::syscalls::{nr, Kernel, SyscallOutcome};
use crate::GuestMem;
use std::time::{Duration, Instant};

/// `kern_return_t`s and `mach_msg_return_t`s the traps return beyond
/// [`kr`].
pub mod kr2 {
    pub const PROTECTION_FAILURE: u64 = 2;
    pub const MEMORY_ERROR: u64 = 10;
    pub const NOT_SUPPORTED: u64 = 46;
    pub const SEND_INVALID_DEST: u64 = 0x1000_0003;
    /// `MIG_ARRAY_TOO_LARGE`.
    pub const MIG_ARRAY_TOO_LARGE: u64 = (-307i64) as u64;
}

/// The trap numbers (`mach_trap_table`).
pub mod trap {
    pub const MACH_ABSOLUTE_TIME: i32 = -3;
    pub const MACH_CONTINUOUS_TIME: i32 = -4;
    pub const MACH_VM_ALLOCATE: i32 = -10;
    pub const MACH_VM_PURGABLE_CONTROL: i32 = -11;
    pub const MACH_VM_DEALLOCATE: i32 = -12;
    pub const TASK_DYLD_PROCESS_INFO_NOTIFY_GET: i32 = -13;
    pub const MACH_VM_PROTECT: i32 = -14;
    pub const MACH_VM_MAP: i32 = -15;
    pub const MACH_PORT_ALLOCATE: i32 = -16;
    pub const MACH_PORT_DEALLOCATE: i32 = -18;
    pub const MACH_PORT_MOD_REFS: i32 = -19;
    pub const MACH_PORT_MOVE_MEMBER: i32 = -20;
    pub const MACH_PORT_INSERT_RIGHT: i32 = -21;
    pub const MACH_PORT_INSERT_MEMBER: i32 = -22;
    pub const MACH_PORT_EXTRACT_MEMBER: i32 = -23;
    pub const MACH_PORT_CONSTRUCT: i32 = -24;
    pub const MACH_PORT_DESTRUCT: i32 = -25;
    pub const MACH_REPLY_PORT: i32 = -26;
    pub const THREAD_SELF: i32 = -27;
    pub const TASK_SELF: i32 = -28;
    pub const HOST_SELF: i32 = -29;
    pub const MACH_MSG: i32 = -31;
    pub const MACH_MSG_OVERWRITE: i32 = -32;
    pub const SEMAPHORE_SIGNAL: i32 = -33;
    pub const SEMAPHORE_SIGNAL_ALL: i32 = -34;
    pub const SEMAPHORE_SIGNAL_THREAD: i32 = -35;
    pub const SEMAPHORE_WAIT: i32 = -36;
    pub const SEMAPHORE_WAIT_SIGNAL: i32 = -37;
    pub const SEMAPHORE_TIMEDWAIT: i32 = -38;
    pub const SEMAPHORE_TIMEDWAIT_SIGNAL: i32 = -39;
    pub const MACH_PORT_GET_ATTRIBUTES: i32 = -40;
    pub const MACH_PORT_GUARD: i32 = -41;
    pub const MACH_PORT_UNGUARD: i32 = -42;
    pub const MACH_GENERATE_ACTIVITY_ID: i32 = -43;
    pub const TASK_NAME_FOR_PID: i32 = -44;
    pub const TASK_FOR_PID: i32 = -45;
    pub const PID_FOR_TASK: i32 = -46;
    pub const MACH_MSG2: i32 = -47;
    pub const MACX_SWAPON: i32 = -48;
    pub const MACX_SWAPOFF: i32 = -49;
    pub const THREAD_GET_SPECIAL_REPLY_PORT: i32 = -50;
    pub const MACX_TRIGGERS: i32 = -51;
    pub const MACX_BACKING_STORE_SUSPEND: i32 = -52;
    pub const MACX_BACKING_STORE_RECOVERY: i32 = -53;
    pub const PFZ_EXIT: i32 = -58;
    pub const SWTCH_PRI: i32 = -59;
    pub const SWTCH: i32 = -60;
    pub const THREAD_SWITCH: i32 = -61;
    pub const CLOCK_SLEEP: i32 = -62;
    pub const HOST_CREATE_MACH_VOUCHER: i32 = -70;
    pub const MACH_VOUCHER_EXTRACT_ATTR_RECIPE: i32 = -72;
    pub const MACH_PORT_TYPE: i32 = -76;
    pub const MACH_PORT_REQUEST_NOTIFICATION: i32 = -77;
    pub const EXCLAVES_CTL: i32 = -88;
    pub const MACH_TIMEBASE_INFO: i32 = -89;
    pub const MACH_WAIT_UNTIL: i32 = -90;
    pub const MK_TIMER_CREATE: i32 = -91;
    pub const MK_TIMER_DESTROY: i32 = -92;
    pub const MK_TIMER_ARM: i32 = -93;
    pub const MK_TIMER_CANCEL: i32 = -94;
    pub const MK_TIMER_ARM_LEEWAY: i32 = -95;
    pub const DEBUG_CONTROL_PORT_FOR_PID: i32 = -96;
    pub const IOKIT_USER_CLIENT: i32 = -100;
    /// `MACH_TRAP_TABLE_COUNT`.
    pub const COUNT: i32 = 128;
}

/// The device's time base: a 24 MHz counter, which `mach_timebase_info`
/// gives as 125/3 nanoseconds per tick.
pub const TIMEBASE: (u32, u32) = (125, 3);

/// The counter's origin, which is this system's boot, and the calendar
/// time then.
fn origin() -> (Instant, std::time::SystemTime) {
    static START: std::sync::OnceLock<(Instant, std::time::SystemTime)> = std::sync::OnceLock::new();
    *START.get_or_init(|| (Instant::now(), std::time::SystemTime::now()))
}

fn time_origin() -> Instant {
    origin().0
}

/// `clock_get_boottime_microtime`: the calendar time at boot, in
/// microseconds since the epoch.
pub(crate) fn boottime_usec() -> u64 {
    origin().1.duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_micros() as u64)
}

/// Time since the counter's origin.
pub(crate) fn uptime() -> Duration {
    time_origin().elapsed()
}

/// `mach_absolute_time`: counter ticks, what `CNTVCT_EL0` reads.
pub fn absolute_time() -> u64 {
    (uptime().as_nanos() * u128::from(TIMEBASE.1) / u128::from(TIMEBASE.0)) as u64
}

/// `clock_get_system_nanotime`: the counter in whole seconds and the
/// nanoseconds past them (`rtclock_sec_divisor`, its ticks per second).
pub(crate) fn system_nanotime() -> (u64, u32) {
    let abs = absolute_time();
    let divisor = 1_000_000_000 * u64::from(TIMEBASE.1) / u64::from(TIMEBASE.0);
    let secs = abs / divisor;
    let rest = abs - secs * divisor;
    (secs, (u128::from(rest) * 1_000_000_000 / u128::from(divisor)) as u32)
}

/// `msleep`'s deadline for a timespec: none for a zero one (no timeout);
/// else its nanoseconds as `(uint64_t)tv_sec * NSEC_PER_SEC + tv_nsec`
/// computes them (wrapping), as counter ticks after now, saturating
/// (`clock_absolutetime_interval_to_deadline`).
pub(crate) fn msleep_deadline(sec: i64, nsec: i64) -> Option<Instant> {
    if sec == 0 && nsec == 0 {
        return None;
    }
    let ns = (sec as u64).wrapping_mul(1_000_000_000).wrapping_add(nsec as u64);
    let divisor = 1_000_000_000 * u64::from(TIMEBASE.1) / u64::from(TIMEBASE.0);
    let whole = ns / 1_000_000_000;
    let ticks = whole * divisor + (ns - whole * 1_000_000_000) * divisor / 1_000_000_000;
    let deadline = absolute_time().checked_add(ticks).unwrap_or(u64::MAX);
    // Past what an instant here can name (centuries on): no deadline.
    let ns = u128::from(deadline) * u128::from(TIMEBASE.0) / u128::from(TIMEBASE.1);
    time_origin().checked_add(Duration::from_nanos(ns.min(u128::from(u64::MAX)) as u64))
}

/// `nanoseconds_to_absolutetime`.
pub(crate) fn ns_to_abs(ns: u64) -> u64 {
    (u128::from(ns) * u128::from(TIMEBASE.1) / u128::from(TIMEBASE.0)).min(u128::from(u64::MAX)) as u64
}

/// The instant an absolute time names.
pub(crate) fn abs_to_instant(abs: u64) -> Instant {
    let ns = u128::from(abs) * u128::from(TIMEBASE.0) / u128::from(TIMEBASE.1);
    time_origin() + Duration::from_nanos(ns.min(u128::from(u64::MAX)) as u64)
}

/// `VM_FLAGS_*` and the masks the traps check them against.
mod vmf {
    pub const ANYWHERE: u64 = 0x1;
    pub const PURGABLE: u64 = 0x2;
    pub const CHUNK_4GB: u64 = 0x4;
    pub const RANDOM_ADDR: u64 = 0x8;
    pub const NO_CACHE: u64 = 0x10;
    pub const PERMANENT: u64 = 0x80;
    pub const TPRO: u64 = 0x1000;
    pub const OVERWRITE: u64 = 0x4000;
    pub const SUPERPAGE_MASK: u64 = 0x70000;
    pub const RETURN_DATA_ADDR: u64 = 0x10_0000;
    pub const RETURN_4K_DATA_ADDR: u64 = 0x80_0000;
    pub const ALIAS_MASK: u64 = 0xff00_0000;
    pub const USER_ALLOCATE: u64 = ANYWHERE | PURGABLE | CHUNK_4GB | RANDOM_ADDR | NO_CACHE | PERMANENT | OVERWRITE | SUPERPAGE_MASK | TPRO | ALIAS_MASK;
    pub const USER_MAP: u64 = USER_ALLOCATE | RETURN_4K_DATA_ADDR | RETURN_DATA_ADDR;
    /// What this kernel's VM does not do yet.
    pub const UNDONE: u64 = PURGABLE | CHUNK_4GB | PERMANENT | TPRO;
}

/// `VM_PROT_*`.
pub(crate) mod prot {
    pub const WRITE: u64 = 0x2;
    pub const EXECUTE: u64 = 0x4;
    pub const ALL: u64 = 0x7;
    pub const COPY: u64 = 0x10;
    pub const READ: u64 = 0x1;
}

/// The map's page mask (`VM_MAP_PAGE_MASK`): arm64 iOS's 16 KiB pages.
pub(crate) const PAGE_MASK: u64 = 0x3fff;

/// `VM_PURGABLE_*` controls and the state masks.
mod purgable {
    pub const SET_STATE: u64 = 0;
    pub const GET_STATE: u64 = 1;
    pub const PURGE_ALL: u64 = 2;
    pub const SET_STATE_FROM_KERNEL: u64 = 3;
    pub const STATE_MASK: i32 = 3;
    /// `VM_PURGABLE_ALL_MASKS`.
    pub const ALL_MASKS: i32 = 3 | (1 << 4) | (1 << 5) | (1 << 6) | (7 << 8) | (3 << 12) | (1 << 16);
}

/// `SWITCH_OPTION_*`.
mod switch {
    pub const NONE: u64 = 0;
    pub const DEPRESS: u64 = 1;
    pub const WAIT: u64 = 2;
    pub const DISPATCH_CONTENTION: u64 = 3;
    pub const OSLOCK_DEPRESS: u64 = 4;
    pub const OSLOCK_WAIT: u64 = 5;
}

/// A trap's sleep that nothing wakes: it ends at its deadline or when the
/// thread is aborted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sleep {
    /// `mach_wait_until`: `KERN_ABORTED` when interrupted.
    WaitUntil,
    /// `thread_switch` with a wait option: `KERN_SUCCESS` either way.
    Switch,
}

/// Darwin's errno values the BSD-side traps return in x0 as they are
/// (`bsd/sys/errno.h`).
mod derrno {
    pub const EPERM: u64 = 1;
    pub const EFAULT: u64 = 14;
    pub const ENOTSUP: u64 = 45;
}

/// `MACH_ACTIVITY_ID_COUNT_MAX`.
const ACTIVITY_ID_COUNT_MAX: u32 = 16;

/// `voucher_activity_id`: one counter for the system, starting at 1.
static ACTIVITY_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// `offsetof(struct user64_dyld_all_image_infos, notifyMachPorts)`
/// (`osfmk/kdp/kdp_dyld.h`).
const NOTIFY_MACH_PORTS_OFFSET: u64 = 0xc8;

impl Kernel {
    /// Run Mach trap `t` (negative), writing its result.
    pub(crate) fn mach_trap(&mut self, m: &mut GuestMem<'_>, t: i32, a: &[u64; 6]) -> SyscallOutcome {
        let r = match t {
            trap::MACH_MSG2 => return <Mach as MachIpc>::mach_msg2(self, m, a),
            trap::MACH_MSG => return <Mach as MachIpc>::mach_msg_trap(self, m, a, false),
            trap::MACH_MSG_OVERWRITE => return <Mach as MachIpc>::mach_msg_trap(self, m, a, true),
            trap::MACH_WAIT_UNTIL => return self.mach_wait_until(m, a[0]),
            trap::THREAD_SWITCH => return self.thread_switch(m, a[0] as u32, a[1] as u32 as u64, a[2] as u32),
            _ => {
                if let Some(out) = self.darwin_semaphore_trap(m, t, a) {
                    return out;
                }
                match self.mach_trap_simple(m, t, a) {
                    Some(r) => r,
                    None => {
                        // kern_invalid, or past the table: EXC_SYSCALL with
                        // the call's number (the host's handler makes it
                        // SIGSYS); x0 is left alone.
                        let call = -i64::from(t);
                        return self.darwin_exception_triage(m, super::exception::EXC_SYSCALL, &[call], super::triage::Then::Return);
                    }
                }
            }
        };
        self.darwin_ipc_settle(m);
        let _ = super::set_mach_result(m, self.ctx_addr, r);
        SyscallOutcome::Continue
    }

    /// The traps that answer at once; `None` for a number with no trap.
    fn mach_trap_simple(&mut self, m: &mut GuestMem<'_>, t: i32, a: &[u64; 6]) -> Option<u64> {
        let x = |m: &GuestMem<'_>, k: &Kernel, i: u8| m.read_u64(k.ctx_addr + gex_abi::ctx::x(i) as u64).unwrap_or(0);
        let w = |i: usize| a[i] as u32;
        let copyout32 = |m: &mut GuestMem<'_>, at: u64, v: u32| if m.write_u32(at, v).is_ok() { kr::SUCCESS } else { kr2::MEMORY_ERROR };
        Some(match t {
            // sleh.c's fast traps.
            trap::MACH_ABSOLUTE_TIME | trap::MACH_CONTINUOUS_TIME => absolute_time(),
            trap::MACH_TIMEBASE_INFO => {
                let ok = m.write_u32(a[0], TIMEBASE.0).and_then(|_| m.write_u32(a[0] + 4, TIMEBASE.1));
                if ok.is_ok() { kr::SUCCESS } else { kr2::MEMORY_ERROR }
            }
            trap::MACH_VM_ALLOCATE => {
                if !self.darwin_name_is_task(w(0)) {
                    return Some(kr2::SEND_INVALID_DEST);
                }
                let Ok(mut addr) = m.read_u64(a[1]) else { return Some(kr2::MEMORY_ERROR) };
                match self.vm_allocate(m, &mut addr, a[2], 0, a[3] as u32 as u64, prot::READ | prot::WRITE) {
                    kr::SUCCESS => {
                        if m.write_u64(a[1], addr).is_ok() { kr::SUCCESS } else { kr2::MEMORY_ERROR }
                    }
                    e => e,
                }
            }
            // _kernelrpc_mach_vm_map_trap(target, addr, size, mask, flags,
            // cur_protection): anonymous memory, max protection VM_PROT_ALL.
            trap::MACH_VM_MAP => {
                if !self.darwin_name_is_task(w(0)) {
                    return Some(kr2::SEND_INVALID_DEST);
                }
                let Ok(mut addr) = m.read_u64(a[1]) else { return Some(kr2::MEMORY_ERROR) };
                let flags = a[4] as u32 as u64;
                if flags & !vmf::USER_MAP != 0 {
                    return Some(kr::INVALID_ARGUMENT);
                }
                let cur = a[5] as u32 as u64;
                if cur & !prot::ALL != 0 || a[2] == 0 {
                    return Some(kr::INVALID_ARGUMENT);
                }
                // An executable mapping is readable.
                let cur = if cur & prot::EXECUTE != 0 { cur | prot::READ } else { cur };
                match self.vm_allocate(m, &mut addr, a[2], a[3], flags & !(vmf::RETURN_DATA_ADDR | vmf::RETURN_4K_DATA_ADDR), cur) {
                    kr::SUCCESS => {
                        if m.write_u64(a[1], addr).is_ok() { kr::SUCCESS } else { kr2::MEMORY_ERROR }
                    }
                    e => e,
                }
            }
            trap::MACH_VM_DEALLOCATE => {
                if !self.darwin_name_is_task(w(0)) {
                    return Some(kr2::SEND_INVALID_DEST);
                }
                self.darwin_vm_deallocate(m, a[1], a[2])
            }
            // _kernelrpc_mach_vm_protect_trap(target, address, size,
            // set_maximum, new_protection)
            trap::MACH_VM_PROTECT => {
                if !self.darwin_name_is_task(w(0)) {
                    return Some(kr2::SEND_INVALID_DEST);
                }
                self.vm_protect(m, a[1], a[2], w(3) != 0, a[4] as u32 as u64)
            }
            trap::MACH_VM_PURGABLE_CONTROL => {
                // The read flavor suffices to get the state.
                if !self.darwin_name_is_task(w(0)) {
                    return Some(kr2::SEND_INVALID_DEST);
                }
                let Ok(state) = m.read_u32(a[3]) else { return Some(kr2::MEMORY_ERROR) };
                self.vm_purgable_control(a[1], a[2] as u32 as u64, state as i32)
            }
            trap::TASK_DYLD_PROCESS_INFO_NOTIFY_GET => self.dyld_process_info_notify_get(m, a[0], a[1]),
            trap::MACH_PORT_ALLOCATE => {
                if !self.darwin_name_is_task(w(0)) {
                    return Some(kr2::SEND_INVALID_DEST);
                }
                match self.ipc().mach_port_allocate(w(1), None) {
                    Ok(name) => copyout32(m, a[2], name),
                    Err(e) => e,
                }
            }
            trap::MACH_PORT_DEALLOCATE => self.task_op(w(0), |k| k.ipc().mach_port_deallocate(w(1))),
            trap::MACH_PORT_MOD_REFS => self.task_op(w(0), |k| k.ipc().mach_port_mod_refs(w(1), w(2), w(3) as i32)),
            trap::MACH_PORT_MOVE_MEMBER => self.task_op(w(0), |k| k.ipc().mach_port_move_member(w(1), w(2))),
            trap::MACH_PORT_INSERT_MEMBER => self.task_op(w(0), |k| k.ipc().mach_port_insert_member(w(1), w(2))),
            trap::MACH_PORT_EXTRACT_MEMBER => self.task_op(w(0), |k| k.ipc().mach_port_extract_member(w(1), w(2))),
            trap::MACH_PORT_INSERT_RIGHT => {
                if !self.darwin_name_is_task(w(0)) {
                    return Some(kr2::SEND_INVALID_DEST);
                }
                self.port_insert_right(w(1), w(2), w(3))
            }
            // _kernelrpc_mach_port_construct_trap(target, options, context,
            // name): mach_port_options_t is flags, mpl_qlimit, then a
            // 64-bit union (reserved / work_interval / service fields).
            trap::MACH_PORT_CONSTRUCT => {
                if !self.darwin_name_is_task(w(0)) {
                    return Some(kr2::SEND_INVALID_DEST);
                }
                // mach_port_options_t: flags, mpl_qlimit, and a union at 8.
                let Ok(opts) = m.read(a[1], 16).map(|b| b.to_vec()) else { return Some(kr2::MEMORY_ERROR) };
                let word = |at: usize| u32::from_le_bytes(opts[at..at + 4].try_into().unwrap());
                let (flags, qlimit, union_word) = (word(0), word(4), u64::from(word(8)) | u64::from(word(12)) << 32);
                let (hardened, initproc) = (self.darwin_hardened(), self.pid == crate::proc::INIT_PID);
                let privileged = super::coalition::privileged(self.pid, super::coalition::ty::JETSAM);
                let read = |at: u64| m.read(at, 256).ok().map(<[u8]>::to_vec);
                match self.ipc().mach_port_construct(flags, qlimit, union_word, a[2], hardened, initproc, privileged, read) {
                    Ok(name) => copyout32(m, a[3], name),
                    Err(e) => e,
                }
            }
            trap::MACH_PORT_DESTRUCT => self.task_op(w(0), |k| k.ipc().mach_port_destruct(w(1), w(2) as i32, a[3])),
            trap::MACH_PORT_GUARD => self.task_op(w(0), |k| k.ipc().mach_port_guard(w(1), a[2], u64::from(w(3) != 0))),
            trap::MACH_PORT_UNGUARD => self.task_op(w(0), |k| k.ipc().mach_port_unguard(w(1), a[2])),
            trap::MACH_PORT_TYPE => {
                if !self.darwin_name_is_task(w(0)) {
                    return Some(kr2::SEND_INVALID_DEST);
                }
                match self.ipc().mach_port_type(w(1)) {
                    Ok(ty) => copyout32(m, a[2], ty),
                    Err(e) => e,
                }
            }
            // _kernelrpc_mach_port_get_attributes_trap(target, name, flavor,
            // info, count): the count is clamped to what the reply carries
            // (`mach_port_info_t`, `array[*:17] of integer_t`).
            trap::MACH_PORT_GET_ATTRIBUTES => {
                const MAX_COUNT: u32 = 17;
                if !self.darwin_name_is_task(w(0)) {
                    return Some(kr2::SEND_INVALID_DEST);
                }
                let Ok(count) = m.read_u32(a[4]) else { return Some(kr2::MEMORY_ERROR) };
                let count = count.min(MAX_COUNT);
                match self.ipc().mach_port_get_attributes(w(1), w(2) as i32, count) {
                    Ok(info) => {
                        if m.write_u32(a[4], info.len() as u32).is_err() {
                            return Some(kr2::MEMORY_ERROR);
                        }
                        let bytes: Vec<u8> = info.iter().flat_map(|v| v.to_le_bytes()).collect();
                        if !bytes.is_empty() && m.write(a[3], &bytes).is_err() {
                            return Some(kr2::MEMORY_ERROR);
                        }
                        kr::SUCCESS
                    }
                    Err(e) => e,
                }
            }
            // _kernelrpc_mach_port_request_notification_trap(target, name,
            // msgid, sync, notify, notifyPoly, previous). Its result starts
            // as MACH_SEND_INVALID_DEST, which a null notify port leaves in
            // place: libsyscall then asks the MIG routine.
            trap::MACH_PORT_REQUEST_NOTIFICATION => {
                let (name, msgid, sync, notify, poly, previous) = (w(1), w(2) as i32, w(3), w(4), w(5), x(m, self, 6));
                if !self.darwin_name_is_task(w(0)) {
                    return Some(kr2::SEND_INVALID_DEST);
                }
                use super::ipc::right::msgt;
                if msgt::copyin_type(poly) != msgt::PORT_SEND_ONCE {
                    return Some(kr2::SEND_INVALID_DEST);
                }
                if !super::ipc::name_valid(notify) {
                    return Some(kr2::SEND_INVALID_DEST);
                }
                let ipc = &mut self.ipc();
                let right = match ipc.object_copyin(notify, poly, Default::default(), 0, None) {
                    Ok(c) => c,
                    Err(e) => return Some(e),
                };
                match ipc.mach_port_request_notification(name, msgid, sync, right) {
                    Ok(prev) => {
                        let mut pname = 0;
                        if let Some(p) = prev {
                            match ipc.object_copyout(super::ipc::right::Carried::Port(p), msgt::PORT_SEND_ONCE, None) {
                                Ok(n) => pname = n,
                                Err(e) => return Some(e),
                            }
                        }
                        copyout32(m, previous, pname)
                    }
                    Err(e) => {
                        ipc.object_destroy(right, msgt::PORT_SEND_ONCE);
                        e
                    }
                }
            }
            trap::MACH_REPLY_PORT => match self.ipc().port_alloc(false) {
                Ok((name, _)) => u64::from(name),
                Err(_) => 0,
            },
            trap::THREAD_GET_SPECIAL_REPLY_PORT => {
                let tid = self.tid;
                // The thread's previous special reply port is unbound.
                self.dtask.kports.special_reply.remove(&tid);
                match self.ipc().port_alloc(true) {
                    Ok((name, port)) => {
                        // IPC_PORT_INIT_SPECIAL_REPLY: a reply port in a
                        // hardened task, else a provisional one.
                        let hardened = self.darwin_hardened();
                        let p = self.ipc().port_mut(port);
                        p.specialreply = true;
                        if hardened {
                            p.immovable_receive = true;
                            p.reply_semantics = super::ipc::ReplySemantics::ReplyPort;
                        } else {
                            p.reply_semantics = super::ipc::ReplySemantics::Provisional;
                        }
                        self.dtask.kports.special_reply.insert(tid, port);
                        u64::from(name)
                    }
                    Err(_) => 0,
                }
            }
            trap::TASK_SELF => {
                let p = self.darwin_task_self_port();
                self.ipc().make_send(p);
                u64::from(self.darwin_copyout_send(p))
            }
            trap::THREAD_SELF => {
                let p = self.darwin_thread_ports(self.tid).1;
                self.ipc().make_send(p);
                u64::from(self.darwin_copyout_send(p))
            }
            trap::HOST_SELF => {
                let p = self.darwin_itk_host();
                self.ipc().make_send(p);
                u64::from(self.darwin_copyout_send(p))
            }
            trap::PID_FOR_TASK => {
                // port_name_to_task_name: any flavor of this task's ports.
                let owner = if super::ipc::name_valid(w(0)) {
                    self.ipc().translate_send(w(0)).ok().and_then(|p| {
                        let p = self.ipc().port(p);
                        (p.active && matches!(p.kobject, Some(super::ipc::Kobject::Task | super::ipc::Kobject::TaskName))).then_some(p.owner)
                    })
                } else {
                    None
                };
                // The pid of the task the port is, this one's or another's.
                let my_pid = self.pid;
                let ipc = self.ipc();
                let pid = owner.and_then(|o| if o == ipc.task { Some(my_pid) } else { ipc.links.get(&o).map(|l| l.pid) });
                let (pid, r) = match pid {
                    Some(pid) => (pid, kr::SUCCESS),
                    None => (-1, kr::FAILURE),
                };
                let _ = m.write_u32(a[1], pid as u32);
                r
            }
            trap::MACH_GENERATE_ACTIVITY_ID => {
                let count = w(1);
                if count == 0 || count > ACTIVITY_ID_COUNT_MAX {
                    return Some(kr::INVALID_ARGUMENT);
                }
                let id = ACTIVITY_ID.fetch_add(u64::from(count), std::sync::atomic::Ordering::Relaxed);
                // A copyout's failure is its errno.
                if m.write_u64(a[2], id).is_ok() { kr::SUCCESS } else { derrno::EFAULT }
            }
            trap::MK_TIMER_CREATE => u64::from(self.mk_timer_create()),
            trap::MK_TIMER_DESTROY => self.mk_timer_destroy(w(0)),
            trap::MK_TIMER_ARM => self.mk_timer_arm(w(0), a[1], 0, 0),
            trap::MK_TIMER_ARM_LEEWAY => self.mk_timer_arm(w(0), a[2], a[3], a[1]),
            trap::MK_TIMER_CANCEL => self.mk_timer_cancel(m, w(0), a[1]),
            // swtch and swtch_pri: give up the processor; whether another
            // thread wants it (`thread_should_yield`).
            trap::SWTCH | trap::SWTCH_PRI => {
                std::thread::yield_now();
                u64::from(self.darwin_others_runnable())
            }
            trap::PFZ_EXIT => kr::SUCCESS,
            // CONFIG_EXCLAVES is not in the iPhoneOS kernel configuration.
            trap::EXCLAVES_CTL => kr2::NOT_SUPPORTED,
            // dp_backing_file.c: no swap on iOS.
            trap::MACX_SWAPON | trap::MACX_SWAPOFF | trap::MACX_BACKING_STORE_SUSPEND | trap::MACX_BACKING_STORE_RECOVERY => derrno::ENOTSUP,
            trap::MACX_TRIGGERS => {
                const SWAP_COMPACT_DISABLE: u32 = 0x1;
                const SWAP_COMPACT_ENABLE: u32 = 0x2;
                if w(0) & (SWAP_COMPACT_DISABLE | SWAP_COMPACT_ENABLE) == 0 {
                    derrno::ENOTSUP
                } else if self.creds.uid() != 0 {
                    derrno::EPERM
                } else {
                    self.darwin_unimplemented("macx_triggers swap compaction".into());
                    kr::FAILURE
                }
            }
            trap::HOST_CREATE_MACH_VOUCHER => self.host_create_mach_voucher_trap(m, w(0), a[1], a[2] as i32, a[3]),
            trap::MACH_VOUCHER_EXTRACT_ATTR_RECIPE => self.mach_voucher_extract_attr_recipe_trap(m, w(0), w(1), a[2], a[3]),
            trap::TASK_NAME_FOR_PID => self.task_name_for_pid(m, w(0), a[1] as i32, a[2]),
            trap::TASK_FOR_PID => self.task_for_pid(m, w(0), a[1] as i32, a[2]),
            trap::IOKIT_USER_CLIENT => self.darwin_iokit_user_client_trap(a) as u32 as u64,
            trap::CLOCK_SLEEP | trap::DEBUG_CONTROL_PORT_FOR_PID => {
                self.darwin_unimplemented(format!("Mach trap {t}"));
                kr::FAILURE
            }
            _ => return None,
        })
    }

    /// `task_name_for_pid(target_tport, pid, t)` (vm_unix.c): a send right
    /// to process `pid`'s task name port, for a caller holding some task's
    /// control port, when the process is live and is the caller, or the
    /// caller is root, or both have the same uid (and real uid: a process
    /// has one uid here), or the caller has the
    /// com.apple.system-task-ports.name.safe entitlement; else null and
    /// KERN_FAILURE.
    fn task_name_for_pid(&mut self, m: &mut GuestMem<'_>, target: u32, pid: i32, at: u64) -> u64 {
        let ipc = self.ipc();
        // port_name_to_task: any task's control port.
        let is_task = super::ipc::name_valid(target)
            && ipc.translate_send(target).is_ok_and(|p| {
                let p = ipc.port(p);
                p.active && p.kobject == Some(super::ipc::Kobject::Task)
            });
        if !is_task {
            let _ = m.write_u32(at, 0);
            return kr::FAILURE;
        }
        let me = self.pid;
        let uid = self.creds.uid();
        let allowed = self.procs.live_nice(pid).is_some_and(|(tuid, _)| pid == me || uid == 0 || tuid == uid || self.darwin_task_entitled("com.apple.system-task-ports.name.safe"));
        if !allowed {
            let _ = m.write_u32(at, 0);
            return kr::FAILURE;
        }
        // proc_task: the process's task, if it has one here; the policies'
        // say on its name port.
        let ipc = self.ipc();
        let task = if pid == me { Some(ipc.task) } else { ipc.links.iter().find(|(_, l)| l.pid == pid).map(|(&t, _)| t) };
        if task.is_some() && self.darwin_mac_check_get_task(pid, super::amfi::flavor::NAME) != 0 {
            let _ = m.write_u32(at, 0);
            return kr::FAILURE;
        }
        let ipc = self.ipc();
        let port = task.and_then(|t| ipc.task_name_port(t));
        // convert_task_name_to_port, ipc_port_copyout_send.
        let name = match port {
            Some(p) => {
                self.ipc().make_send(p);
                self.darwin_copyout_send(p)
            }
            None => 0,
        };
        let _ = m.write_u32(at, name);
        kr::SUCCESS
    }

    /// `port_name_to_task`: the name is a send right to some task's control
    /// port.
    fn darwin_name_is_some_task(&mut self, target: u32) -> bool {
        let ipc = self.ipc();
        super::ipc::name_valid(target)
            && ipc.translate_send(target).is_ok_and(|p| {
                let p = ipc.port(p);
                p.active && p.kobject == Some(super::ipc::Kobject::Task)
            })
    }

    /// `task_for_pid_posix_check` (KERN_TFP_POLICY_DEFAULT): a live
    /// target, and a caller that is root or the target itself; else one
    /// whose effective uid is all the target's user ids, with the target's
    /// groups among its own (`kauth_cred_gid_subset`; no external resolver
    /// on iOS) unless the target is a third party's debuggable driver, and
    /// the target not having changed identity (P_SUGID).
    pub(crate) fn darwin_tfp_posix_check(&mut self, pid: i32) -> bool {
        let Some((target, false)) = self.darwin_public(pid) else { return false };
        let me = self.dtask.cred.clone();
        if me.uid == 0 || pid == self.pid {
            return true;
        }
        if !self.darwin_third_party_debuggable_driver(pid) {
            let t = &target.cred;
            if t.uid != me.uid || t.ruid != me.uid || t.svuid != me.uid {
                return false;
            }
            // kauth_cred_ismember_gid: the credential's own list.
            let member = |g: u32| me.groups.contains(&g) || g == me.rgid || g == me.svgid;
            if !t.groups.iter().all(|&g| member(g)) || !member(t.rgid) || !member(t.svgid) {
                return false;
            }
        }
        !target.sugid
    }

    /// `proc_is_third_party_debuggable_driver` (iOS): a driver task, not a
    /// platform binary, entitled to DriverKit and allowed get-task.
    pub(crate) fn darwin_third_party_debuggable_driver(&mut self, pid: i32) -> bool {
        let driver = self.procs.task_policy(pid).is_some_and(|c| c.lock().unwrap_or_else(|e| e.into_inner()).requested.apptype == super::taskpolicy::apptype::DRIVER);
        let Some(link) = self.ipc().links.values().find(|l| l.pid == pid).cloned() else { return false };
        let csflags = link.csflags.load(std::sync::atomic::Ordering::Acquire);
        let sig = link.codesign.as_ref();
        driver && !sig.is_some_and(|c| c.platform_binary) && sig.is_some_and(|c| c.entitled("com.apple.developer.driverkit")) && csflags & super::amfi::cs::GET_TASK_ALLOW != 0
    }

    /// `task_for_pid(target_tport, pid, t)` (vm_unix.c): process `pid`'s
    /// task control port, for a caller holding some task's control port,
    /// that passes the POSIX check and the policies' (AMFI allows it only
    /// with Developer Mode); the caller's own is its pinned self port,
    /// another's is dead without Developer Mode (task_conversion_eval).
    /// The name, or null, is copied out either way.
    fn task_for_pid(&mut self, m: &mut GuestMem<'_>, target: u32, pid: i32, at: u64) -> u64 {
        let fail = |m: &mut GuestMem<'_>, r: u64| {
            let _ = m.write_u32(at, 0);
            r
        };
        if pid == 0 || !self.darwin_name_is_some_task(target) {
            return fail(m, kr::FAILURE);
        }
        if self.procs.live_nice(pid).is_none() || !self.darwin_tfp_posix_check(pid) {
            return fail(m, kr::FAILURE);
        }
        if self.darwin_mac_check_get_task(pid, super::amfi::flavor::CONTROL) != 0 {
            return fail(m, kr::FAILURE);
        }
        let name = if pid == self.pid {
            let p = self.darwin_task_self_port();
            self.ipc().make_send(p);
            self.darwin_copyout_send(p)
        } else if !super::amfi::DEVELOPER_MODE {
            super::ipc::PORT_DEAD
        } else {
            self.darwin_unimplemented("task_for_pid of another process (its task access port and control port)".into());
            return fail(m, kr::FAILURE);
        };
        let _ = m.write_u32(at, name);
        kr::SUCCESS
    }

    /// `task_read_for_pid` and `task_inspect_for_pid` (system calls with
    /// errnos): the read or inspect port of process `pid`, after the POSIX
    /// check and the policies'.
    pub(crate) fn darwin_task_flavor_for_pid(&mut self, m: &mut GuestMem<'_>, target: u32, pid: i32, at: u64, f: u32) -> Result<u64, crate::errno::Errno> {
        use crate::errno::Errno;
        let out = |m: &mut GuestMem<'_>, name: u32| m.write_u32(at, name);
        if pid == 0 {
            out(m, 0)?;
            return Err(Errno::EPERM);
        }
        if !self.darwin_name_is_some_task(target) {
            out(m, 0)?;
            return Err(Errno::EINVAL);
        }
        if self.procs.live_nice(pid).is_none() {
            out(m, 0)?;
            return Err(Errno::ESRCH);
        }
        if !self.darwin_tfp_posix_check(pid) || self.darwin_mac_check_get_task(pid, f) != 0 {
            out(m, 0)?;
            return Err(Errno::EPERM);
        }
        if pid != self.pid {
            self.darwin_unimplemented("task_read_for_pid/task_inspect_for_pid of another process (its task access port and flavored port)".into());
            out(m, 0)?;
            return Err(Errno::EPERM);
        }
        let p = self.darwin_task_flavor_port(if f == super::amfi::flavor::READ { super::kobject::flavor::READ } else { super::kobject::flavor::INSPECT });
        let name = self.darwin_copyout_send(p);
        out(m, name)?;
        Ok(0)
    }

    /// A `_kernelrpc` trap on the task's space, after the target check.
    fn task_op(&mut self, target: u32, f: impl FnOnce(&mut Kernel) -> u64) -> u64 {
        if !self.darwin_name_is_task(target) {
            return kr2::SEND_INVALID_DEST;
        }
        f(self)
    }

    /// `_kernelrpc_mach_port_insert_right_trap(target, name, poly,
    /// polyPoly)`.
    fn port_insert_right(&mut self, name: u32, poly: u32, poly_poly: u32) -> u64 {
        use super::ipc::right::{msgt, CopyinFlags};
        let ipc = &mut self.ipc();
        if name == poly && (poly_poly == msgt::MAKE_SEND || poly_poly == msgt::COPY_SEND) {
            return ipc.insert_send_right(poly, poly_poly);
        }
        let flags = CopyinFlags { allow_immovable_send: true, ..Default::default() };
        let right = match ipc.object_copyin(poly, poly_poly, flags, 0, None) {
            Ok(c) => c,
            Err(e) => return e,
        };
        let disp = msgt::copyin_type(poly_poly);
        let r = ipc.mach_port_insert_right(name, right, disp);
        if r != kr::SUCCESS {
            ipc.object_destroy(right, disp);
        }
        r
    }

    /// Whether some other thread of the task is runnable: the host
    /// schedules threads, so the nearest view of a run queue is the threads
    /// not blocked in a Darwin wait.
    fn darwin_others_runnable(&self) -> bool {
        let live = self.live_threads.load(std::sync::atomic::Ordering::Acquire) as usize;
        let waiting = self.dtask.waits.waiting_count();
        live.saturating_sub(waiting) > 1
    }

    /// `mach_wait_until_trap(deadline)`.
    fn mach_wait_until(&mut self, m: &mut GuestMem<'_>, deadline: u64) -> SyscallOutcome {
        if deadline <= absolute_time() {
            let _ = super::set_mach_result(m, self.ctx_addr, kr::SUCCESS);
            return SyscallOutcome::Continue;
        }
        self.darwin_block(m, Wait { deadline: Some(abs_to_instant(deadline)), cont: super::thread::Finish::Sleep(Sleep::WaitUntil) })
    }

    /// `thread_switch(thread_name, option, option_time)`. The host runs
    /// every thread on its own processor, so a hint names no thread to hand
    /// the processor to and a depression changes no order; a wait option
    /// sleeps for its time.
    fn thread_switch(&mut self, m: &mut GuestMem<'_>, thread_name: u32, option: u64, option_time: u32) -> SyscallOutcome {
        let scale = match option {
            switch::NONE | switch::DEPRESS | switch::OSLOCK_DEPRESS => None,
            switch::WAIT | switch::OSLOCK_WAIT => Some(1_000_000u64),
            switch::DISPATCH_CONTENTION => Some(1_000),
            _ => {
                let _ = super::set_mach_result(m, self.ctx_addr, kr::INVALID_ARGUMENT);
                return SyscallOutcome::Continue;
            }
        };
        let _ = thread_name;
        match scale {
            Some(ns) => {
                let d = Duration::from_nanos(u64::from(option_time) * ns);
                self.darwin_block(m, Wait { deadline: Some(Instant::now() + d), cont: super::thread::Finish::Sleep(Sleep::Switch) })
            }
            None => {
                std::thread::yield_now();
                let _ = super::set_mach_result(m, self.ctx_addr, kr::SUCCESS);
                SyscallOutcome::Continue
            }
        }
    }

    /// A trap's sleep has ended.
    pub(crate) fn darwin_sleep_done(&mut self, m: &mut GuestMem<'_>, s: Sleep, res: WaitResult) {
        let r = match (s, res) {
            (Sleep::WaitUntil, WaitResult::Interrupted) => kr::ABORTED,
            _ => kr::SUCCESS,
        };
        let _ = super::set_mach_result(m, self.ctx_addr, r);
    }

    /// `task_dyld_process_info_notify_get_trap(names_addr,
    /// names_count_addr)`: no notifier is registered
    /// (`task_dyld_process_info_notify_register` is not served), so the
    /// image infos' port array is cleared and the count is 0.
    fn dyld_process_info_notify_get(&mut self, m: &mut GuestMem<'_>, names: u64, count_addr: u64) -> u64 {
        if names == 0 || count_addr == 0 {
            return kr::INVALID_ARGUMENT;
        }
        let Ok(n) = m.read_u32(count_addr) else { return kr2::MEMORY_ERROR };
        if n == 0 {
            return kr::NO_SPACE;
        }
        if self.darwin_dyld_infos != 0 {
            let _ = m.write_u32(self.darwin_dyld_infos + NOTIFY_MACH_PORTS_OFFSET, 0);
        }
        if m.write_u32(count_addr, 0).is_ok() { kr::SUCCESS } else { kr2::MEMORY_ERROR }
    }

    /// `mach_vm_allocate_kernel` and the anonymous case of
    /// `vm_map_enter_mem_object`: `size` bytes of `cur` protection at
    /// `*addr` (fixed) or anywhere, aligned to `mask + 1`, with the user
    /// tag in the flags' top byte.
    fn vm_allocate(&mut self, m: &mut GuestMem<'_>, addr: &mut u64, size: u64, mask: u64, flags: u64, cur: u64) -> u64 {
        use crate::mem::flags as mf;
        if flags & !vmf::USER_ALLOCATE != 0 {
            return kr::INVALID_ARGUMENT;
        }
        if size == 0 {
            *addr = 0;
            return kr::SUCCESS;
        }
        // vm_map_enter: arm64 has no superpage size.
        if flags & vmf::SUPERPAGE_MASK != 0 {
            return kr::INVALID_ARGUMENT;
        }
        if flags & vmf::UNDONE != 0 {
            self.darwin_unimplemented(format!("mach_vm_allocate/mach_vm_map flags {:#x}", flags & vmf::UNDONE));
            return kr::FAILURE;
        }
        let fixed = flags & vmf::ANYWHERE == 0;
        let start = if fixed { *addr & !PAGE_MASK } else { 0 };
        let Some(len) = size.checked_add(PAGE_MASK).map(|s| s & !PAGE_MASK).filter(|&l| l != 0) else { return kr::INVALID_ARGUMENT };
        // vm_map_enter on an iOS map (VM_MAP_POLICY_WX_STRIP_X): a writable
        // and executable protection loses execute.
        let cur = if cur & prot::WRITE != 0 && cur & prot::EXECUTE != 0 { cur & !prot::EXECUTE } else { cur };
        let p = (cur & prot::ALL) as u64;
        let linux_prot = (p & 1) | (p & 2) | (p & 4);
        let attrs = super::vm::Attrs { alias: (flags >> 24) as u8, no_cache: flags & vmf::NO_CACHE != 0, ..Default::default() };
        if fixed {
            // vm_map_enter: the address meets the mask, then it is within
            // bounds.
            if start & mask != 0 {
                return kr::NO_SPACE;
            }
            if start < self.dtask.map_min || start.checked_add(len).is_none_or(|e| e > self.darwin_map_max()) {
                return kr::INVALID_ADDRESS;
            }
            // Without VM_FLAGS_OVERWRITE a fixed request over anything
            // mapped fails.
            if flags & vmf::OVERWRITE == 0 && self.mem.lock().vmas().iter().any(|v| v.start < start + len && start < v.end) {
                return kr::NO_SPACE;
            }
            return match self.canonical(m, nr::MMAP, [start, len, linux_prot, mf::PRIVATE | mf::ANONYMOUS | mf::FIXED, u64::MAX, 0]) {
                Ok(_) => {
                    self.darwin_vm_enter_anon(start, start + len, attrs, p);
                    *addr = start;
                    kr::SUCCESS
                }
                Err(_) => kr::NO_SPACE,
            };
        }
        let mask = mask & !PAGE_MASK;
        // vm_map_locate_space with VM_FLAGS_RANDOM_ADDR: from a random hint
        // with room after it, the first fit.
        if flags & vmf::RANDOM_ADDR != 0 {
            let hint = match self.darwin_random_address_for_size(len) {
                Ok(h) => h,
                Err(k) => return k,
            };
            let (_, limit) = self.darwin_effective_range();
            let Some(start) = self.darwin_find_space(hint, limit, len, mask) else { return kr::NO_SPACE };
            return match self.canonical(m, nr::MMAP, [start, len, linux_prot, mf::PRIVATE | mf::ANONYMOUS | mf::FIXED, u64::MAX, 0]) {
                Ok(_) => {
                    self.darwin_vm_enter_anon(start, start + len, attrs, p);
                    *addr = start;
                    kr::SUCCESS
                }
                Err(_) => kr::NO_SPACE,
            };
        }
        // Anywhere: from the map's minimum (mach_vm_allocate's hint), the
        // first fit.
        let start = match self.darwin_locate_space(0, len, mask) {
            Ok(s) => s,
            Err(k) => return k,
        };
        match self.canonical(m, nr::MMAP, [start, len, linux_prot, mf::PRIVATE | mf::ANONYMOUS | mf::FIXED, u64::MAX, 0]) {
            Ok(_) => {
                self.darwin_vm_enter_anon(start, start + len, attrs, p);
                *addr = start;
                kr::SUCCESS
            }
            Err(_) => kr::NO_SPACE,
        }
    }

    /// `vm_map_locate_space` for an anywhere request without a random
    /// address: from `hint`, raised to the effective range's start, the
    /// first fit of `size` bytes aligned to `mask` below the range's end;
    /// KERN_NO_SPACE without one.
    pub(crate) fn darwin_locate_space(&self, hint: u64, size: u64, mask: u64) -> Result<u64, u64> {
        let (min, max) = self.darwin_effective_range();
        let hint = hint.max(min);
        if max <= hint {
            return Err(kr::NO_SPACE);
        }
        self.darwin_find_space(hint, max, size, mask).ok_or(kr::NO_SPACE)
    }

    /// The range a map's anywhere allocations are made in
    /// (`vm_map_get_range` of a map without user ranges: from its minimum
    /// or its first page to its end), within the memory gex backs, its high
    /// arena.
    pub(crate) fn darwin_effective_range(&self) -> (u64, u64) {
        (gex_abi::HIGH_ARENA_BASE.max(self.dtask.map_min).max(PAGE_MASK + 1), self.darwin_map_max().min(gex_abi::LIMIT64))
    }

    /// `vm_map_random_address_for_size`: up to 1000 random page-aligned
    /// addresses of the effective range (`random()`'s 31 bits in pages),
    /// the first that starts a hole of `size` bytes; KERN_NO_SPACE without
    /// one.
    pub(crate) fn darwin_random_address_for_size(&self, size: u64) -> Result<u64, u64> {
        const MAX_TRIES_TO_GET_RANDOM_ADDRESS: usize = 1000;
        const VM_MAP_PAGE_SHIFT: u32 = 14;
        let (min, max) = self.darwin_effective_range();
        let space = max.saturating_sub(min);
        if size >= space {
            return Err(kr::NO_SPACE);
        }
        let space = space - size;
        let map_max = self.darwin_map_max();
        let mm = self.mem.lock();
        let vmas = mm.vmas();
        for _ in 0..MAX_TRIES_TO_GET_RANDOM_ADDRESS {
            let mut b = [0u8; 4];
            crate::vfs::devfs::fill_random(&mut b);
            let r = u64::from(u32::from_le_bytes(b) & 0x7fff_ffff) << VM_MAP_PAGE_SHIFT;
            let addr = (min + r % space) & !PAGE_MASK;
            if mm.vma_at(addr).is_some() {
                continue;
            }
            let hole_end = vmas.get(vmas.partition_point(|v| v.start <= addr)).map_or(map_max, |v| v.start);
            if hole_end - addr >= size {
                return Ok(addr);
            }
        }
        Err(kr::NO_SPACE)
    }

    /// `vm_map_store_find_space` from `hint`: the first `size` bytes free
    /// at or after it, aligned to `mask`, ending by `limit`.
    pub(crate) fn darwin_find_space(&self, hint: u64, limit: u64, size: u64, mask: u64) -> Option<u64> {
        let mm = self.mem.lock();
        let mut at = hint.checked_add(mask)? & !mask;
        loop {
            let end = at.checked_add(size)?;
            if end > limit {
                return None;
            }
            match mm.vmas().iter().find(|v| v.start < end && at < v.end) {
                Some(v) => at = v.end.checked_add(mask)? & !mask,
                None => return Some(at),
            }
        }
    }

    /// `mach_vm_map` of anonymous memory, read and write.
    pub(crate) fn darwin_vm_map_anon(&mut self, m: &mut GuestMem<'_>, addr: &mut u64, size: u64, mask: u64, flags: u64) -> u64 {
        self.vm_allocate(m, addr, size, mask, flags, prot::READ | prot::WRITE)
    }

    /// Memory for a received message's out-of-line data (`vm_map_copyout`):
    /// anywhere, read and write.
    pub(crate) fn darwin_vm_allocate_anywhere(&mut self, m: &mut GuestMem<'_>, len: u64) -> Result<u64, u64> {
        let mut addr = 0;
        match self.vm_allocate(m, &mut addr, len, 0, vmf::ANYWHERE, prot::READ | prot::WRITE) {
            kr::SUCCESS => Ok(addr),
            e => Err(e),
        }
    }

    /// An IOKit mapping of kernel memory into the task
    /// (`IOMemoryDescriptorMapAlloc`'s `vm_map_enter_mem_object` for a user
    /// map): `len` bytes anywhere, tagged VM_MEMORY_IOKIT, with `cur` as
    /// both its protection and its maximum, inherited by no child.
    pub(crate) fn darwin_iokit_map(&mut self, m: &mut GuestMem<'_>, len: u64, cur: u64) -> Result<u64, u64> {
        const VM_MEMORY_IOKIT: u64 = 21;
        let mut addr = 0;
        match self.vm_allocate(m, &mut addr, len, 0, vmf::ANYWHERE | VM_MEMORY_IOKIT << 24, cur) {
            kr::SUCCESS => {}
            e => return Err(e),
        }
        match self.vm_protect(m, addr, len, true, cur) {
            kr::SUCCESS => {}
            e => return Err(e),
        }
        match self.darwin_vm_inherit(addr, len, u32::from(super::vm::inherit::NONE)) {
            kr::SUCCESS => Ok(addr),
            e => Err(e),
        }
    }

    /// `vm_map_region`'s entry reports. The `*_COUNT` a caller has too
    /// little room for is KERN_INVALID_ARGUMENT, as is another flavor.
    pub(crate) fn darwin_vm_map_region(&mut self, addr: u64, flavor: i32, count: u32) -> Result<(u64, u64, Vec<u32>), super::kobject::Reply> {
        use super::kobject::Reply;
        use super::vm::{kind, region};
        const KERN_INVALID_ADDRESS: i32 = 1;
        const KERN_INVALID_ARGUMENT: i32 = 4;
        let (need, basic64) = match flavor {
            region::BASIC_INFO_64 => (region::BASIC_INFO_COUNT_64, true),
            region::BASIC_INFO => (region::BASIC_INFO_COUNT, false),
            // VM_REGION_EXTENDED_INFO and TOP_INFO count an entry's pages
            // (`vm_map_region_walk`), which take a per-page model.
            region::EXTENDED_INFO | region::EXTENDED_INFO_LEGACY | region::TOP_INFO => {
                let mut r = Reply::err(KERN_INVALID_ARGUMENT);
                r.unimplemented = Some(format!("mach_vm_region flavor {flavor} (its resident and shared page counts)"));
                return Err(r);
            }
            _ => return Err(Reply::err(KERN_INVALID_ARGUMENT)),
        };
        if count < need {
            return Err(Reply::err(KERN_INVALID_ARGUMENT));
        }
        let Some(e) = self.dtask.vm.at_or_after(addr) else { return Err(Reply::err(KERN_INVALID_ADDRESS)) };
        // The shared region's entry is a submap: entered read-only
        // (`vm_shared_region_enter`), its own pages' protections apart.
        let submap = e.attrs.kind == kind::SUBMAP;
        let cur = if submap { prot::READ as u32 } else { self.mem.lock().vma_at(e.start).map_or(0, |v| v.prot) };
        let max = if submap { prot::READ as u32 } else { u32::from(e.attrs.max) };
        let mut info = vec![cur, max, u32::from(e.attrs.inherit), u32::from(e.attrs.shared && !submap), u32::from(submap)];
        info.push(e.offset as u32);
        if basic64 {
            info.push((e.offset >> 32) as u32);
        }
        // behavior; user_wired_count.
        info.push(u32::from(e.attrs.behavior));
        info.push(u32::from(e.attrs.user_wired));
        Ok((e.start, e.end - e.start, info))
    }

    /// `f` with this task's memory, for a routine that came as a message:
    /// none on a host whose processes cannot see each other's.
    pub(crate) fn darwin_own_memory<R>(&mut self, f: impl FnOnce(&mut Kernel, &mut GuestMem<'_>) -> R) -> Result<R, super::kobject::Reply> {
        const KERN_FAILURE: i32 = 5;
        let peer = match self.procs.vm(self.pid) {
            Ok(p) => p,
            Err(e) => {
                let mut r = super::kobject::Reply::err(KERN_FAILURE);
                r.unimplemented = Some(format!("a VM routine sent as a message, on a host with no view of the task's memory ({e:?})"));
                return Err(r);
            }
        };
        let (mut f, mut out) = (Some(f), None);
        peer.mem.with_guest(&mut |m| out = f.take().map(|f| f(self, m)));
        Ok(out.expect("with_guest calls its function"))
    }

    /// `vm_map_machine_attribute` on arm: only `MATTR_CACHE` has an
    /// implementation (`pmap_attribute` is KERN_INVALID_ADDRESS), and every
    /// value of it is `cache_sync_page` of the resident pages.
    pub(crate) fn darwin_vm_machine_attribute(&mut self, addr: u64, size: u64, attribute: i32) -> i32 {
        const KERN_INVALID_ADDRESS: i32 = 1;
        const KERN_INVALID_ARGUMENT: i32 = 4;
        const KERN_FAILURE: i32 = 5;
        const MATTR_CACHE: i32 = 1;
        let Some(last) = addr.checked_add(size) else { return KERN_INVALID_ARGUMENT };
        if size == 0 {
            return 0;
        }
        let (start, end) = (addr & !PAGE_MASK, last.wrapping_add(PAGE_MASK) & !PAGE_MASK);
        if start < self.dtask.map_min || end > self.darwin_map_max() || end <= start || attribute != MATTR_CACHE {
            return KERN_INVALID_ADDRESS;
        }
        let vmas: Vec<(u64, u64, u32)> = {
            let mm = self.mem.lock();
            let mut v: Vec<_> = mm.vmas().iter().filter(|v| v.end > start && v.start < end).map(|v| (v.start.max(start), v.end.min(end), v.prot)).collect();
            v.sort();
            v
        };
        let mut at = start;
        for (s, e, p) in vmas {
            if s > at {
                return KERN_FAILURE;
            }
            // What is executable is fetched again.
            if p & crate::mem::prot::EXEC != 0 {
                self.map_io().retire_code_why(s, e - s, "machine_attribute", p);
            }
            at = e;
        }
        if at < end { KERN_FAILURE } else { 0 }
    }

    /// `vm_map_copyin` from this task's map: a copy of `[addr, addr + size)`.
    /// A page with no entry is KERN_INVALID_ADDRESS, an entry that cannot be
    /// read KERN_PROTECTION_FAILURE.
    pub(crate) fn darwin_vm_copyin(&mut self, addr: u64, size: u64) -> Result<Vec<u8>, super::kobject::Reply> {
        use super::kobject::Reply;
        const KERN_INVALID_ADDRESS: i32 = 1;
        const KERN_PROTECTION_FAILURE: i32 = 2;
        if size == 0 {
            return Ok(Vec::new());
        }
        let end = addr.checked_add(size).ok_or_else(|| Reply::err(KERN_INVALID_ADDRESS))?;
        {
            let mm = self.mem.lock();
            let mut at = addr & !PAGE_MASK;
            let stop = (end + PAGE_MASK) & !PAGE_MASK;
            while at < stop {
                let v = mm.vma_at(at).ok_or_else(|| Reply::err(KERN_INVALID_ADDRESS))?;
                if v.prot & crate::mem::prot::READ == 0 {
                    return Err(Reply::err(KERN_PROTECTION_FAILURE));
                }
                at = v.end;
            }
        }
        self.darwin_own_memory(|_, m| m.read(addr, size as usize).map(<[u8]>::to_vec))?.map_err(|_| Reply::err(KERN_INVALID_ADDRESS))
    }

    /// `vm_map_copy_overwrite` of this task's map at `dst`: the range must
    /// be mapped (KERN_INVALID_ADDRESS) and writable
    /// (KERN_PROTECTION_FAILURE).
    pub(crate) fn darwin_vm_copy_overwrite(&mut self, dst: u64, data: &[u8]) -> Result<(), super::kobject::Reply> {
        use super::kobject::Reply;
        const KERN_INVALID_ADDRESS: i32 = 1;
        const KERN_PROTECTION_FAILURE: i32 = 2;
        if data.is_empty() {
            return Ok(());
        }
        let end = dst.checked_add(data.len() as u64).ok_or_else(|| Reply::err(KERN_INVALID_ADDRESS))?;
        let mut code = false;
        {
            let mm = self.mem.lock();
            let mut at = dst & !PAGE_MASK;
            let stop = (end + PAGE_MASK) & !PAGE_MASK;
            while at < stop {
                let v = mm.vma_at(at).ok_or_else(|| Reply::err(KERN_INVALID_ADDRESS))?;
                if v.prot & crate::mem::prot::WRITE == 0 {
                    return Err(Reply::err(KERN_PROTECTION_FAILURE));
                }
                code |= v.prot & crate::mem::prot::EXEC != 0;
                at = v.end;
            }
        }
        self.darwin_own_memory(|_, m| m.write(dst, data))?.map_err(|_| Reply::err(KERN_INVALID_ADDRESS))?;
        if code {
            self.map_io().retire_code_why(dst, end - dst, "vm_write", crate::mem::prot::EXEC);
        }
        Ok(())
    }

    /// `vm_map_enter` of anonymous memory at a place already chosen, the
    /// entry below looked at for its protection (`cur`).
    pub(crate) fn darwin_vm_enter_anon(&mut self, start: u64, end: u64, attrs: super::vm::Attrs, cur: u64) {
        let below = self.mem.lock().vma_at(start.wrapping_sub(1)).map(|v| u64::from(v.prot)) == Some(cur);
        self.dtask.vm.enter_anon(start, end, attrs, below);
    }

    /// `mach_vm_deallocate`: unmapped parts of the range are skipped
    /// (`vm_map_delete` raises a non-fatal `kGUARD_EXC_DEALLOC_GAP`, which a
    /// task without VM guard behavior drops).
    pub(crate) fn darwin_vm_deallocate(&mut self, m: &mut GuestMem<'_>, start: u64, size: u64) -> u64 {
        let Some(end) = start.checked_add(size) else { return kr::INVALID_ARGUMENT };
        if size == 0 {
            return kr::SUCCESS;
        }
        let (s, e) = (start & !PAGE_MASK, end.checked_add(PAGE_MASK).map_or(0, |e| e & !PAGE_MASK));
        if e == 0 {
            return kr::SUCCESS;
        }
        self.dtask.vm.clear(s, e);
        match self.canonical(m, nr::MUNMAP, [s, e - s, 0, 0, 0, 0]) {
            Ok(_) => kr::SUCCESS,
            Err(_) => kr::INVALID_ARGUMENT,
        }
    }

    /// `mach_vm_protect` and `vm_map_protect`. Every page must be mapped
    /// and allow the protection; an iOS map strips execute from a writable
    /// request (`VM_MAP_POLICY_WX_STRIP_X`) on each entry but its JIT
    /// region (no `pmap_has_prot_policy` on a device without PPL).
    pub(crate) fn vm_protect(&mut self, m: &mut GuestMem<'_>, start: u64, size: u64, set_max: bool, new: u64) -> u64 {
        if start.checked_add(size).is_none() || new & !(prot::ALL | prot::COPY) != 0 {
            return kr::INVALID_ARGUMENT;
        }
        if size == 0 {
            return kr::SUCCESS;
        }
        // An executable VM_PROT_COPY is refused only by a map with
        // VM_MAP_POLICY_WX_FAIL, which an iOS map is not.
        let (s, e) = (start & !PAGE_MASK, (start + size + PAGE_MASK) & !PAGE_MASK);
        let vmas: Vec<(u64, u64, u64)> = {
            let mm = self.mem.lock();
            let mut v: Vec<_> = mm.vmas().iter().filter(|v| v.end > s && v.start < e).map(|v| (v.start.max(s), v.end.min(e), u64::from(v.prot) & prot::ALL)).collect();
            v.sort();
            v
        };
        // vm_map_protect's first pass: entry by entry, a hole before it is
        // KERN_INVALID_ADDRESS and a protection its maximum does not allow
        // KERN_PROTECTION_FAILURE, whichever comes first. A copy is remapped
        // before that, its holes found then.
        let copy = new & prot::COPY != 0;
        let want = new & prot::ALL;
        let pieces = self.dtask.vm.pieces(s, e);
        let mut at = s;
        for &(vs, ve, _) in &vmas {
            if vs > at {
                return kr::INVALID_ADDRESS;
            }
            if !copy && pieces.iter().any(|&(ps, pe, a)| ps < ve && vs < pe && want & u64::from(a.max) != want) {
                return kr2::PROTECTION_FAILURE;
            }
            at = at.max(ve);
        }
        if at < e {
            return kr::INVALID_ADDRESS;
        }
        if copy {
            // vm_map_remap in place, copy on write: the range's entries
            // become this task's own memory, with write access allowed,
            // their file-backed pages no longer written back. The shared
            // region's entry is cut around the copy.
            self.mem.lock().log.shared_maps.cut(s, e - s);
            self.dtask.vm.clip_range(s, e);
            self.dtask.vm.update(s, e, |a| {
                a.kind = super::vm::kind::ANON;
                a.max |= prot::WRITE as u8;
                a.cow = false;
                a.jit = false;
                a.shared = false;
            });
        }
        let new = new & prot::ALL;
        let pieces = self.dtask.vm.pieces(s, e);
        if pieces.iter().any(|(_, _, a)| new & u64::from(a.max) != new) {
            return kr2::PROTECTION_FAILURE;
        }
        // vm_map_protect clips what it is about to change.
        self.dtask.vm.clip_range(s, e);
        let wx = new & prot::WRITE != 0 && new & prot::EXECUTE != 0;
        let entry_prot = |jit: bool| if wx && !jit { new & !prot::EXECUTE } else { new };
        if set_max {
            // The current protection keeps only what the new maximum allows.
            for (vs, ve, cur) in vmas {
                for &(ps, pe, a) in pieces.iter().filter(|p| p.0 < ve && vs < p.1) {
                    let (ps, pe) = (ps.max(vs), pe.min(ve));
                    if self.canonical(m, nr::MPROTECT, [ps, pe - ps, cur & entry_prot(a.jit), 0, 0, 0]).is_err() {
                        return kr::INVALID_ADDRESS;
                    }
                }
            }
            for (ps, pe, a) in pieces {
                let max = entry_prot(a.jit) as u8;
                self.dtask.vm.update(ps, pe, |a| a.max = max);
            }
            return kr::SUCCESS;
        }
        for (ps, pe, a) in pieces {
            if self.canonical(m, nr::MPROTECT, [ps, pe - ps, entry_prot(a.jit), 0, 0, 0]).is_err() {
                return kr::INVALID_ADDRESS;
            }
        }
        kr::SUCCESS
    }

    /// `mach_vm_purgable_control` and `vm_map_purgable_control`: no memory
    /// here is purgeable (`VM_FLAGS_PURGABLE` is reported as not done), so
    /// a mapped address is `VM_PURGABLE_DENY`.
    fn vm_purgable_control(&mut self, address: u64, control: u64, state: i32) -> u64 {
        use purgable::*;
        if !matches!(control, SET_STATE | GET_STATE | PURGE_ALL | SET_STATE_FROM_KERNEL) {
            return kr::INVALID_ARGUMENT;
        }
        if control == PURGE_ALL {
            return kr::SUCCESS;
        }
        if (control == SET_STATE || control == SET_STATE_FROM_KERNEL) && (state & !ALL_MASKS != 0 || (state & STATE_MASK) > STATE_MASK) {
            return kr::INVALID_ARGUMENT;
        }
        let mm = self.mem.lock();
        let Some(v) = mm.vma_at(address) else { return kr::INVALID_ADDRESS };
        if v.prot & 2 == 0 && control != GET_STATE {
            return kr2::PROTECTION_FAILURE;
        }
        kr::INVALID_ARGUMENT
    }

    /// Run canonical call `n` from inside a Darwin call.
    pub(crate) fn canonical(&mut self, m: &mut GuestMem<'_>, n: u64, a: [u64; 6]) -> Result<u64, Errno> {
        match self.dispatch(m, n, a) {
            Ok(r) => r,
            Err(_) => Err(Errno::EINVAL),
        }
    }
}
