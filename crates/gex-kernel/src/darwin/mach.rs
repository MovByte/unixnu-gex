//! Mach traps: the negative system call numbers.
//!
//! A trap returns a `kern_return_t` in x0 and leaves the carry flag alone.
//! Port names live in the task's [`Space`]. This is the trap surface
//! libsystem's start-up uses; messages (`mach_msg`) are not delivered yet.

use crate::errno::Errno;
use crate::syscalls::{nr, Kernel};
use crate::GuestMem;

/// `kern_return_t`.
pub mod kr {
    pub const SUCCESS: u64 = 0;
    pub const INVALID_ADDRESS: u64 = 1;
    pub const PROTECTION_FAILURE: u64 = 2;
    pub const NO_SPACE: u64 = 3;
    pub const INVALID_ARGUMENT: u64 = 4;
    pub const FAILURE: u64 = 5;
    pub const INVALID_NAME: u64 = 15;
    pub const INVALID_RIGHT: u64 = 17;
    pub const INVALID_VALUE: u64 = 18;
    /// `MACH_SEND_INVALID_DEST`: what `mach_msg` answers until messages are
    /// delivered.
    pub const ABORTED: u64 = 14;
    pub const OPERATION_TIMED_OUT: u64 = 49;
    pub const SEND_INVALID_DEST: u64 = 0x1000_0003;
    /// `MACH_RCV_TOO_LARGE`: the reply does not fit the receive buffer.
    pub const RCV_TOO_LARGE: u64 = 0x1000_4004;
}

/// Trap numbers, negated (XNU's `osfmk/kern/syscall_sw.c`).
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
    pub const MACH_PORT_GUARD: i32 = -41;
    pub const MACH_PORT_UNGUARD: i32 = -42;
    pub const MACH_MSG2: i32 = -47;
    pub const THREAD_GET_SPECIAL_REPLY_PORT: i32 = -50;
    pub const SWTCH_PRI: i32 = -59;
    pub const SWTCH: i32 = -60;
    pub const THREAD_SWITCH: i32 = -61;
    pub const MACH_TIMEBASE_INFO: i32 = -89;
    pub const MACH_WAIT_UNTIL: i32 = -90;
    pub const MK_TIMER_CREATE: i32 = -91;
    pub const MK_TIMER_DESTROY: i32 = -92;
    pub const MK_TIMER_ARM: i32 = -93;
    pub const MK_TIMER_CANCEL: i32 = -94;
}

/// What a port name denotes in this task.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Port {
    Task,
    Thread(i32),
    Host,
    /// A receive right this task allocated (a reply port, a port set member).
    Receive,
    PortSet,
    Timer,
    /// The system clock (`host_get_clock_service`).
    Clock,
    /// A semaphore and its count.
    Semaphore(i64),
}

/// A task's port name space. Names are `index << 8 | 3`, as XNU's look.
#[derive(Clone, Debug, Default)]
pub struct Space {
    names: std::collections::BTreeMap<u32, Port>,
    next: u32,
}

/// The fixed names every task starts with.
pub const TASK_SELF_NAME: u32 = 0x103;
pub const HOST_SELF_NAME: u32 = 0x203;

impl Space {
    fn fresh(&mut self, p: Port) -> u32 {
        if self.names.is_empty() {
            self.names.insert(TASK_SELF_NAME, Port::Task);
            self.names.insert(HOST_SELF_NAME, Port::Host);
            self.next = 3;
        }
        let name = (self.next << 8) | 3;
        self.next += 1;
        self.names.insert(name, p);
        name
    }

    /// The name for this thread's own port, made on first use.
    pub fn thread(&mut self, tid: i32) -> u32 {
        if let Some((&n, _)) = self.names.iter().find(|(_, p)| **p == Port::Thread(tid)) {
            return n;
        }
        self.fresh(Port::Thread(tid))
    }

    /// The task's name for the system clock, made on first use.
    pub fn clock(&mut self) -> u32 {
        if let Some((&n, _)) = self.names.iter().find(|(_, p)| **p == Port::Clock) {
            return n;
        }
        self.fresh(Port::Clock)
    }

    /// A new semaphore with `value`, by its name.
    pub fn semaphore(&mut self, value: i64) -> u32 {
        self.fresh(Port::Semaphore(value))
    }

    /// Forget `name`.
    pub fn remove(&mut self, name: u32) -> bool {
        self.names.remove(&name).is_some()
    }

    pub fn get_mut(&mut self, name: u32) -> Option<&mut Port> {
        self.names.get_mut(&name)
    }

    pub fn get(&self, name: u32) -> Option<&Port> {
        match name {
            TASK_SELF_NAME => Some(&Port::Task),
            HOST_SELF_NAME => Some(&Port::Host),
            _ => self.names.get(&name),
        }
    }
}

/// A monotonic nanosecond count, from the first time it is asked: what
/// `mach_absolute_time` returns, with the 1/1 timebase.
pub(crate) fn monotonic_ns() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START.get_or_init(std::time::Instant::now).elapsed().as_nanos() as u64
}

/// `MACH_PORT_RIGHT_*`.
const RIGHT_RECEIVE: u64 = 1;
const RIGHT_PORT_SET: u64 = 3;

/// `VM_FLAGS_ANYWHERE`: the kernel picks the address.
const VM_FLAGS_ANYWHERE: u64 = 1;

impl Kernel {
    /// Run Mach trap `t` (negative); the value is the `kern_return_t` or
    /// port name for x0.
    pub(crate) fn mach_trap(&mut self, m: &mut GuestMem<'_>, t: i32, a: &[u64; 6]) -> u64 {
        let tid = self.tid;
        let space = &mut self.darwin_ports;
        match t {
            trap::TASK_SELF => {
                space.fresh(Port::Task);
                u64::from(TASK_SELF_NAME)
            }
            trap::HOST_SELF => u64::from(HOST_SELF_NAME),
            trap::THREAD_SELF => u64::from(space.thread(tid)),
            trap::MACH_REPLY_PORT | trap::THREAD_GET_SPECIAL_REPLY_PORT => u64::from(space.fresh(Port::Receive)),
            trap::MACH_PORT_ALLOCATE => {
                let p = match a[1] {
                    RIGHT_RECEIVE => Port::Receive,
                    RIGHT_PORT_SET => Port::PortSet,
                    _ => return kr::INVALID_VALUE,
                };
                let name = space.fresh(p);
                match m.write_u32(a[2], name) {
                    Ok(()) => kr::SUCCESS,
                    Err(_) => kr::INVALID_ADDRESS,
                }
            }
            trap::MACH_PORT_CONSTRUCT => {
                let name = space.fresh(Port::Receive);
                match m.write_u32(a[3], name) {
                    Ok(()) => kr::SUCCESS,
                    Err(_) => kr::INVALID_ADDRESS,
                }
            }
            trap::MK_TIMER_CREATE => u64::from(space.fresh(Port::Timer)),
            // Rights are not counted yet: every name stays valid.
            trap::MACH_PORT_DEALLOCATE
            | trap::MACH_PORT_MOD_REFS
            | trap::MACH_PORT_DESTRUCT
            | trap::MACH_PORT_INSERT_RIGHT
            | trap::MACH_PORT_MOVE_MEMBER
            | trap::MACH_PORT_INSERT_MEMBER
            | trap::MACH_PORT_EXTRACT_MEMBER
            | trap::MACH_PORT_GUARD
            | trap::MACH_PORT_UNGUARD
            | trap::MK_TIMER_DESTROY
            | trap::MK_TIMER_CANCEL
            | trap::MK_TIMER_ARM => kr::SUCCESS,
            // Nanoseconds since the process's first call, as the 1/1
            // timebase says (libsystem asks the kernel because the
            // commpage offers no user timebase).
            trap::MACH_ABSOLUTE_TIME | trap::MACH_CONTINUOUS_TIME => monotonic_ns(),
            trap::MACH_TIMEBASE_INFO => {
                // mach_absolute_time counts nanoseconds: 1/1.
                let ok = m.write_u32(a[0], 1).and_then(|_| m.write_u32(a[0] + 4, 1));
                if ok.is_ok() {
                    kr::SUCCESS
                } else {
                    kr::INVALID_ADDRESS
                }
            }
            trap::SWTCH_PRI | trap::SWTCH | trap::THREAD_SWITCH => {
                std::thread::yield_now();
                kr::SUCCESS
            }
            trap::MACH_VM_ALLOCATE => self.vm_allocate(m, a[1], a[2], 0, a[3]),
            // _kernelrpc_mach_vm_map_trap(target, address, size, mask, flags, prot)
            trap::MACH_VM_MAP => self.vm_allocate(m, a[1], a[2], a[3], a[4]),
            trap::MACH_VM_DEALLOCATE => match self.canonical(m, nr::MUNMAP, [a[1], a[2], 0, 0, 0, 0]) {
                Ok(_) => kr::SUCCESS,
                Err(_) => kr::INVALID_ADDRESS,
            },
            trap::MACH_VM_PROTECT => match self.canonical(m, nr::MPROTECT, [a[1], a[2], a[4] & 7, 0, 0, 0]) {
                Ok(_) => kr::SUCCESS,
                Err(_) => kr::PROTECTION_FAILURE,
            },
            trap::MACH_VM_PURGABLE_CONTROL => kr::SUCCESS,
            trap::SEMAPHORE_SIGNAL | trap::SEMAPHORE_SIGNAL_ALL | trap::SEMAPHORE_SIGNAL_THREAD => self.semaphore_signal(a[0] as u32),
            trap::SEMAPHORE_WAIT | trap::SEMAPHORE_TIMEDWAIT => self.semaphore_wait(a[0] as u32, t == trap::SEMAPHORE_TIMEDWAIT),
            // Signal one, then wait on the other.
            trap::SEMAPHORE_WAIT_SIGNAL | trap::SEMAPHORE_TIMEDWAIT_SIGNAL => match self.semaphore_signal(a[1] as u32) {
                kr::SUCCESS => self.semaphore_wait(a[0] as u32, t == trap::SEMAPHORE_TIMEDWAIT_SIGNAL),
                e => e,
            },
            trap::MACH_MSG2 => self.mach_msg2(m, a),
            trap::MACH_MSG | trap::MACH_MSG_OVERWRITE => {
                self.darwin_unimplemented("mach_msg (trap -31/-32)".into());
                kr::SEND_INVALID_DEST
            }
            _ => {
                if !self.unimplemented.contains(&(t as i64 as u64)) {
                    self.unimplemented.push(t as i64 as u64);
                }
                self.darwin_unimplemented(format!("Mach trap {t}"));
                kr::FAILURE
            }
        }
    }

    pub(crate) fn semaphore_signal(&mut self, name: u32) -> u64 {
        match self.darwin_ports.get_mut(name) {
            Some(Port::Semaphore(v)) => {
                *v += 1;
                kr::SUCCESS
            }
            _ => kr::INVALID_ARGUMENT,
        }
    }

    /// Take one from the count. With none and only this thread to give
    /// one, nothing ever will: a timed wait times out, a wait is aborted.
    fn semaphore_wait(&mut self, name: u32, timed: bool) -> u64 {
        match self.darwin_ports.get_mut(name) {
            Some(Port::Semaphore(v)) if *v > 0 => {
                *v -= 1;
                kr::SUCCESS
            }
            Some(Port::Semaphore(_)) if timed => kr::OPERATION_TIMED_OUT,
            Some(Port::Semaphore(_)) => kr::ABORTED,
            _ => kr::INVALID_ARGUMENT,
        }
    }

    /// `mach_msg2(data, options, bits|send_size, remote|local,
    /// voucher|id, desc_count|rcv_name, rcv_size|priority, timeout)`. A
    /// send and receive to a kernel object is a MIG call, answered into
    /// the same buffer; anything else is not delivered yet.
    fn mach_msg2(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> u64 {
        const SEND: u64 = 0x1;
        const RCV: u64 = 0x2;
        let opts = a[1];
        let send_size = (a[2] >> 32) as usize;
        let (remote, local) = (a[3] as u32, (a[3] >> 32) as u32);
        let id = (a[4] >> 32) as u32 as i32;
        let rcv_size = m.read_u64(self.ctx_addr + gex_abi::ctx::x(6) as u64).unwrap_or(0) as u32 as usize;
        let obj = match self.darwin_ports.get(remote) {
            Some(Port::Task) => Some(super::mig::Object::Task),
            Some(Port::Host) => Some(super::mig::Object::Host),
            Some(Port::Thread(t)) => Some(super::mig::Object::Thread(*t)),
            Some(Port::Clock) => Some(super::mig::Object::Clock),
            _ => None,
        };
        let (Some(obj), true) = (obj, opts & (SEND | RCV) == SEND | RCV) else {
            self.darwin_unimplemented(format!("mach_msg2 delivery (options {opts:#x}, id {id})"));
            return kr::SEND_INVALID_DEST;
        };
        let header = super::mig::HEADER;
        let body = match m.read(a[0] + header as u64, send_size.saturating_sub(header)) {
            Ok(b) => b.to_vec(),
            Err(_) => return kr::INVALID_ADDRESS,
        };
        let task = super::mig::Task {
            dyld_infos: self.darwin_dyld_infos,
            ports: &mut self.darwin_ports,
            threads: &mut self.dtask.threads,
            spawns: &mut self.dtask.spawns,
        };
        let reply = super::mig::serve(obj, id, &body, task);
        if self.trace {
            eprintln!("[gex:{}] mig {obj:?} id {id} -> {}", self.pid, reply.ret);
        }
        if reply.ret == super::mig::MIG_BAD_ID {
            self.darwin_unimplemented(format!("MIG routine {id} on {obj:?}"));
        }
        if let Some(what) = &reply.unimplemented {
            self.darwin_unimplemented(what.clone());
        }
        let msg = reply.message(id, local);
        if msg.len() > rcv_size {
            return kr::RCV_TOO_LARGE;
        }
        match m.write(a[0], &msg) {
            Ok(()) => kr::SUCCESS,
            Err(_) => kr::INVALID_ADDRESS,
        }
    }

    /// `mach_vm_allocate`/`mach_vm_map` of anonymous memory: the address at
    /// `*addr_p` when the flags fix it, anywhere otherwise, aligned to
    /// `mask + 1` (libmalloc finds a region from a pointer by masking).
    fn vm_allocate(&mut self, m: &mut GuestMem<'_>, addr_p: u64, size: u64, mask: u64, flags: u64) -> u64 {
        use crate::mem::flags as mf;
        let want = m.read_u64(addr_p).unwrap_or(0);
        let fixed = flags & VM_FLAGS_ANYWHERE == 0;
        let f = mf::PRIVATE | mf::ANONYMOUS | if fixed { mf::FIXED } else { 0 };
        let hint = if fixed { want } else { 0 };
        // Below a page the kernel's own alignment does.
        let mask = if fixed { 0 } else { mask & !0xfff };
        let len = size + mask;
        let at = match self.canonical(m, nr::MMAP, [hint, len, 3, f, u64::MAX, 0]) {
            Ok(at) => at,
            Err(_) => return kr::NO_SPACE,
        };
        let start = (at + mask) & !mask;
        // Trim what the alignment left over, before and after.
        if start > at {
            let _ = self.canonical(m, nr::MUNMAP, [at, start - at, 0, 0, 0, 0]);
        }
        let end = at + len;
        let page_end = (start + size + 0xfff) & !0xfff;
        if end > page_end {
            let _ = self.canonical(m, nr::MUNMAP, [page_end, end - page_end, 0, 0, 0, 0]);
        }
        match m.write_u64(addr_p, start) {
            Ok(()) => kr::SUCCESS,
            Err(_) => kr::INVALID_ADDRESS,
        }
    }

    /// Run canonical call `n` from inside a Darwin call.
    pub(crate) fn canonical(&mut self, m: &mut GuestMem<'_>, n: u64, a: [u64; 6]) -> Result<u64, Errno> {
        match self.dispatch(m, n, a) {
            Ok(r) => r,
            Err(_) => Err(Errno::EINVAL),
        }
    }
}
