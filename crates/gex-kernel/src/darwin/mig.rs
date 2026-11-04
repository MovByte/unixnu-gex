//! The kernel's MIG servers: requests sent to a kernel object's port (the
//! task, the host, a thread), answered in place.
//!
//! A client sends a request and receives the reply in one `mach_msg`; the
//! reply goes back into its receive buffer with the request's id plus 100,
//! an NDR record, the return code and the routine's out arguments, laid out
//! as MIG's generated client code checks them.

/// `mach_msg_header_t` and the NDR record after it.
pub const HEADER: usize = 24;
pub const NDR: usize = 8;

/// The NDR record every MIG message carries: little-endian, IEEE floats.
pub const NDR_RECORD: [u8; 8] = [0, 0, 0, 0, 1, 0, 0, 0];

/// `MACH_MSGH_BITS(0, MACH_MSG_TYPE_PORT_SEND_ONCE)`: a reply as received.
pub const REPLY_BITS: u32 = 18 << 8;
/// `MACH_MSGH_BITS_COMPLEX`: descriptors follow the header.
pub const COMPLEX: u32 = 0x8000_0000;
/// `MACH_MSG_TYPE_PORT_SEND`: a send right, as a receiver sees one moved
/// to it.
pub const PORT_SEND: u8 = 17;

/// `MIG_BAD_ID`: no such routine.
pub const MIG_BAD_ID: i32 = -303;

/// `kern_return_t`s routines return.
pub const KERN_SUCCESS: i32 = 0;
pub const KERN_INVALID_ARGUMENT: i32 = 4;

/// The kernel object a request was sent to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Object {
    Task,
    Host,
    Thread(i32),
    Clock,
}

/// A routine's outcome: its return code and the out arguments after it,
/// or (a routine that returns rights) the send rights it hands back.
pub struct Reply {
    pub ret: i32,
    pub out: Vec<u8>,
    pub ports: Vec<u32>,
}

impl Reply {
    fn ok(out: Vec<u8>) -> Reply {
        Reply { ret: KERN_SUCCESS, out, ports: Vec::new() }
    }

    fn err(ret: i32) -> Reply {
        Reply { ret, out: Vec::new(), ports: Vec::new() }
    }

    fn port(name: u32) -> Reply {
        Reply { ret: KERN_SUCCESS, out: Vec::new(), ports: vec![name] }
    }

    /// The whole reply message, to the request's reply port `local`. A
    /// successful reply carrying rights is complex: a descriptor count and
    /// one port descriptor per right, with no return code.
    pub fn message(&self, id: i32, local: u32) -> Vec<u8> {
        if self.ret == KERN_SUCCESS && !self.ports.is_empty() {
            let size = HEADER + 4 + 12 * self.ports.len() + self.out.len();
            let mut m = Vec::with_capacity(size);
            for w in [REPLY_BITS | COMPLEX, size as u32, 0, local, 0, (id + 100) as u32, self.ports.len() as u32] {
                m.extend_from_slice(&w.to_le_bytes());
            }
            for &name in &self.ports {
                m.extend_from_slice(&name.to_le_bytes());
                m.extend_from_slice(&0u32.to_le_bytes());
                m.extend_from_slice(&0u16.to_le_bytes());
                m.push(PORT_SEND);
                m.push(0); // MACH_MSG_PORT_DESCRIPTOR
            }
            m.extend_from_slice(&self.out);
            return m;
        }
        let size = HEADER + NDR + 4 + self.out.len();
        let mut m = Vec::with_capacity(size);
        m.extend_from_slice(&REPLY_BITS.to_le_bytes());
        m.extend_from_slice(&(size as u32).to_le_bytes());
        m.extend_from_slice(&0u32.to_le_bytes());
        m.extend_from_slice(&local.to_le_bytes());
        m.extend_from_slice(&0u32.to_le_bytes());
        m.extend_from_slice(&(id + 100).to_le_bytes());
        m.extend_from_slice(&NDR_RECORD);
        m.extend_from_slice(&self.ret.to_le_bytes());
        m.extend_from_slice(&self.out);
        m
    }
}

fn i32_at(b: &[u8], o: usize) -> i32 {
    b.get(o..o + 4).map_or(0, |s| i32::from_le_bytes(s.try_into().unwrap()))
}

/// An out array of `integer_t`s, MIG-style: its count, then the words.
fn words(w: &[u32]) -> Vec<u8> {
    let mut o = (w.len() as u32).to_le_bytes().to_vec();
    for x in w {
        o.extend_from_slice(&x.to_le_bytes());
    }
    o
}

/// The machine the profile describes, as the host routines report it.
pub mod machine {
    pub const NCPUS: u32 = 2;
    pub const MEMORY: u64 = 4 << 30;
    pub const CPU_TYPE_ARM64: u32 = 0x0100_000c;
    pub const PAGE_SIZE: u32 = 4096;
}

/// What the routines read of the process, and where they make names.
pub struct Task<'a> {
    /// dyld's `dyld_all_image_infos`, once registered.
    pub dyld_infos: u64,
    pub ports: &'a mut super::mach::Space,
}

/// Answer request `id` with body `body` (after the header) sent to `obj`.
pub fn serve(obj: Object, id: i32, body: &[u8], task: Task<'_>) -> Reply {
    // The in arguments start after the NDR record.
    let arg = |i: usize| i32_at(body, NDR + 4 * i);
    match (obj, id) {
        // host_info(host, flavor, out, count)
        (Object::Host, 200) => host_info(arg(0)),
        // host_page_size(host) -> vm_size_t
        (Object::Host, 202) => Reply::ok(u64::from(machine::PAGE_SIZE).to_le_bytes().to_vec()),
        // task_info(task, flavor, out, count)
        (Object::Task, 3405) => task_info(arg(0), task.dyld_infos),
        // semaphore_create(task, policy, value) -> semaphore_t
        (Object::Task, 3418) => Reply::port(task.ports.semaphore(i64::from(arg(1)))),
        // semaphore_destroy(task, semaphore): the name is in the
        // request's port descriptor, after the descriptor count.
        (Object::Task, 3419) => {
            let name = i32_at(body, 4) as u32;
            if task.ports.remove(name) {
                Reply::ok(Vec::new())
            } else {
                Reply::err(KERN_INVALID_ARGUMENT)
            }
        }
        // task_get_special_port(task, which) -> port. The task's own and the
        // host's are real; the bootstrap port (launchd's) and the rest are
        // MACH_PORT_NULL until launchd runs.
        (Object::Task, 3409) => {
            const TASK_KERNEL_PORT: i32 = 1;
            const TASK_HOST_PORT: i32 = 2;
            const TASK_NAME_PORT: i32 = 3;
            match arg(0) {
                TASK_KERNEL_PORT | TASK_NAME_PORT => Reply::port(super::mach::TASK_SELF_NAME),
                TASK_HOST_PORT => Reply::port(super::mach::HOST_SELF_NAME),
                _ => Reply::port(0),
            }
        }
        // task_set_special_port(task, which, port): nothing reads them back
        // but task_get_special_port, which answers from its own table.
        (Object::Task, 3410) => Reply::ok(Vec::new()),
        // task_restartable_ranges_register / _synchronize: code the kernel
        // must restart if it preempts a thread inside. Nothing is
        // preempted mid-block here, so there is nothing to restart.
        (Object::Task, 8000) | (Object::Task, 8001) => Reply::ok(Vec::new()),
        // host_get_clock_service(host, clock_id) -> clock_serv_t
        (Object::Host, 206) => Reply::port(task.ports.clock()),
        // clock_get_time(clock) -> mach_timespec_t
        (Object::Clock, 1000) => {
            let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
            let mut o = (t.as_secs() as u32).to_le_bytes().to_vec();
            o.extend_from_slice(&(t.subsec_nanos() as i32).to_le_bytes());
            Reply::ok(o)
        }
        _ => Reply::err(MIG_BAD_ID),
    }
}

fn host_info(flavor: i32) -> Reply {
    use machine::*;
    const HOST_BASIC_INFO: i32 = 1;
    const HOST_SCHED_INFO: i32 = 3;
    const HOST_PRIORITY_INFO: i32 = 5;
    const HOST_PREFERRED_USER_ARCH: i32 = 12;
    let mem32 = MEMORY.min(u64::from(u32::MAX)) as u32;
    match flavor {
        // max_cpus, avail_cpus, memory_size, cpu_type, cpu_subtype,
        // cpu_threadtype, physical_cpu, physical_cpu_max, logical_cpu,
        // logical_cpu_max, max_mem (two words).
        HOST_BASIC_INFO => Reply::ok(words(&[
            NCPUS,
            NCPUS,
            mem32,
            CPU_TYPE_ARM64,
            0,
            0,
            NCPUS,
            NCPUS,
            NCPUS,
            NCPUS,
            MEMORY as u32,
            (MEMORY >> 32) as u32,
        ])),
        // min_timeout, min_quantum (milliseconds).
        HOST_SCHED_INFO => Reply::ok(words(&[10, 10])),
        // kernel, system, server, user, depress, idle, minimum, maximum.
        HOST_PRIORITY_INFO => Reply::ok(words(&[95, 81, 63, 31, 0, 0, 0, 127])),
        HOST_PREFERRED_USER_ARCH => Reply::ok(words(&[CPU_TYPE_ARM64, 0])),
        _ => Reply::err(KERN_INVALID_ARGUMENT),
    }
}

fn task_info(flavor: i32, dyld_infos: u64) -> Reply {
    const TASK_DYLD_INFO: i32 = 17;
    /// `sizeof(struct dyld_all_image_infos)` for a 64-bit process.
    const ALL_IMAGE_INFOS_SIZE: u32 = 0x170;
    match flavor {
        // all_image_info_addr, all_image_info_size (8 bytes each),
        // all_image_info_format (TASK_DYLD_ALL_IMAGE_INFO_64).
        TASK_DYLD_INFO => {
            let a = dyld_infos;
            let size = if a == 0 { 0 } else { ALL_IMAGE_INFOS_SIZE };
            Reply::ok(words(&[a as u32, (a >> 32) as u32, size, 0, 1]))
        }
        _ => Reply::err(KERN_INVALID_ARGUMENT),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_basic_info_replies_as_mig_expects() {
        let mut body = NDR_RECORD.to_vec();
        body.extend_from_slice(&1i32.to_le_bytes());
        body.extend_from_slice(&12u32.to_le_bytes());
        let mut sp = super::super::mach::Space::default();
        let r = serve(Object::Host, 200, &body, Task { dyld_infos: 0, ports: &mut sp });
        assert_eq!(r.ret, KERN_SUCCESS);
        let m = r.message(200, 0x703);
        assert_eq!(i32_at(&m, 20), 300, "id + 100");
        assert_eq!(i32_at(&m, 4) as usize, m.len(), "msgh_size");
        assert_eq!(i32_at(&m, 12), 0x703, "to the reply port");
        assert_eq!(i32_at(&m, HEADER + NDR), 0, "RetCode");
        assert_eq!(i32_at(&m, HEADER + NDR + 4), 12, "count");
        assert_eq!(i32_at(&m, HEADER + NDR + 8), 2, "max_cpus");
    }

    #[test]
    fn an_unknown_routine_is_mig_bad_id() {
        let mut sp = super::super::mach::Space::default();
        let r = serve(Object::Task, 9999, &NDR_RECORD, Task { dyld_infos: 0, ports: &mut sp });
        assert_eq!(r.ret, MIG_BAD_ID);
        assert_eq!(r.message(9999, 1).len(), HEADER + NDR + 4);
    }

    #[test]
    fn a_returned_right_makes_a_complex_reply() {
        let mut sp = super::super::mach::Space::default();
        let r = serve(Object::Host, 206, &NDR_RECORD, Task { dyld_infos: 0, ports: &mut sp });
        let m = r.message(206, 0x703);
        assert_eq!(m.len(), 40);
        assert_eq!(i32_at(&m, 0) as u32 & COMPLEX, COMPLEX);
        assert_eq!(i32_at(&m, 24), 1, "one descriptor");
        assert_eq!(m[24 + 4 + 10], PORT_SEND);
        assert_eq!(sp.get(i32_at(&m, 28) as u32), Some(&super::super::mach::Port::Clock));
    }
}
