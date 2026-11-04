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
    pub const SEND_INVALID_DEST: u64 = 0x1000_0003;
}

/// Trap numbers, negated (XNU's `osfmk/kern/syscall_sw.c`).
pub mod trap {
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
    pub const SEMAPHORE_WAIT: i32 = -36;
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
    fn thread(&mut self, tid: i32) -> u32 {
        if let Some((&n, _)) = self.names.iter().find(|(_, p)| **p == Port::Thread(tid)) {
            return n;
        }
        self.fresh(Port::Thread(tid))
    }

    pub fn get(&self, name: u32) -> Option<&Port> {
        match name {
            TASK_SELF_NAME => Some(&Port::Task),
            HOST_SELF_NAME => Some(&Port::Host),
            _ => self.names.get(&name),
        }
    }
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
            trap::MACH_VM_ALLOCATE => self.vm_allocate(m, a[1], a[2], a[3]),
            trap::MACH_VM_MAP => self.vm_allocate(m, a[1], a[2], a[4]),
            trap::MACH_VM_DEALLOCATE => match self.canonical(m, nr::MUNMAP, [a[1], a[2], 0, 0, 0, 0]) {
                Ok(_) => kr::SUCCESS,
                Err(_) => kr::INVALID_ADDRESS,
            },
            trap::MACH_VM_PROTECT => match self.canonical(m, nr::MPROTECT, [a[1], a[2], a[4] & 7, 0, 0, 0]) {
                Ok(_) => kr::SUCCESS,
                Err(_) => kr::PROTECTION_FAILURE,
            },
            trap::MACH_VM_PURGABLE_CONTROL => kr::SUCCESS,
            trap::MACH_MSG | trap::MACH_MSG_OVERWRITE | trap::MACH_MSG2 => kr::SEND_INVALID_DEST,
            _ => {
                if self.trace || !self.unimplemented.contains(&(t as i64 as u64)) {
                    eprintln!("[gex:{}] unimplemented Mach trap {t}", self.pid);
                    self.unimplemented.push(t as i64 as u64);
                }
                kr::FAILURE
            }
        }
    }

    /// `mach_vm_allocate`/`mach_vm_map` of anonymous memory: the address at
    /// `*addr_p` when the flags fix it, anywhere otherwise.
    fn vm_allocate(&mut self, m: &mut GuestMem<'_>, addr_p: u64, size: u64, flags: u64) -> u64 {
        use crate::mem::flags as mf;
        let want = m.read_u64(addr_p).unwrap_or(0);
        let fixed = flags & VM_FLAGS_ANYWHERE == 0;
        let f = mf::PRIVATE | mf::ANONYMOUS | if fixed { mf::FIXED } else { 0 };
        let hint = if fixed { want } else { 0 };
        match self.canonical(m, nr::MMAP, [hint, size, 3, f, u64::MAX, 0]) {
            Ok(at) => match m.write_u64(addr_p, at) {
                Ok(()) => kr::SUCCESS,
                Err(_) => kr::INVALID_ADDRESS,
            },
            Err(_) => kr::NO_SPACE,
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
