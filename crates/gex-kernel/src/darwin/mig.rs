//! The kernel's MIG routines: requests sent to the task's, host's, a
//! thread's, the clock's or a semaphore's port, decoded from the request
//! message and answered as MIG's generated kernel server code answers them.

use super::ipc::msg::{Desc, Kmsg};
use super::ipc::right::Carried;
use super::ipc::{kr, Kobject};
use super::kobject::{Reply, MIG_BAD_ID};
use crate::syscalls::Kernel;

/// `mach_msg_header_t` and the NDR record after it.
pub const HEADER: usize = 24;
pub const NDR: usize = 8;

/// The NDR record every MIG message carries: little-endian, IEEE floats.
pub const NDR_RECORD: [u8; 8] = [0, 0, 0, 0, 1, 0, 0, 0];

/// `kern_return_t`s as MIG return codes.
const KERN_SUCCESS: i32 = 0;
const KERN_INVALID_ARGUMENT: i32 = 4;
const KERN_FAILURE: i32 = 5;
const KERN_RESOURCE_SHORTAGE: i32 = 6;
const KERN_NO_ACCESS: i32 = 8;
const KERN_INVALID_RIGHT: i32 = 17;
const KERN_INVALID_VALUE: i32 = 18;
const KERN_NOT_SUPPORTED: i32 = 46;
/// `MIG_BAD_ARGUMENTS`: a request without the routine's shape.
const MIG_BAD_ARGUMENTS: i32 = -304;

/// The machine the profile describes, as the host routines report it.
pub mod machine {
    /// J120's device tree: `cpu0`..`cpu2` (`#main-cpus` 3).
    pub const NCPUS: u32 = 3;
    /// The iPad Pro (12.9-inch, 2nd generation)'s 4 GiB.
    pub const MEMORY: u64 = 4 << 30;
    /// `task_threadmax` after `scale_setup`: `CONFIG_TASK_MAX` is 512 for
    /// the xsmall memory tag, and a machine with at least 3 GiB (and under
    /// 8) doubles it.
    pub const TASK_THREADMAX: u32 = 1024;
    /// `CONFIG_THREAD_MAX` for the xsmall memory tag.
    pub const CONFIG_THREAD_MAX: u32 = 1536;
    pub const CPU_TYPE_ARM64: u32 = 0x0100_000c;
    /// `cpu_subtype` of an ARMv8 core without pointer authentication
    /// (`CPU_SUBTYPE_ARM64_V8`), what `cpu_machine_init` gives the A10X.
    pub const CPU_SUBTYPE: u32 = 1;
    pub const PAGE_SIZE: u32 = 4096;
}

fn i32_at(b: &[u8], o: usize) -> Option<i32> {
    b.get(o..o + 4).map(|s| i32::from_le_bytes(s.try_into().unwrap()))
}

/// An out array of `integer_t`s, MIG-style: its count, then the words.
fn words(w: &[u32]) -> Vec<u8> {
    let mut o = (w.len() as u32).to_le_bytes().to_vec();
    for x in w {
        o.extend_from_slice(&x.to_le_bytes());
    }
    o
}

/// The `i`th in argument after the NDR record of a simple request.
fn arg(req: &Kmsg, i: usize) -> Option<i32> {
    i32_at(&req.body, NDR + 4 * i)
}

/// The right in a complex request's `i`th port descriptor.
fn desc_port(req: &Kmsg, i: usize) -> Option<(Option<Carried>, u32)> {
    match req.descs.get(i)? {
        Desc::Port { right, disp, .. } => Some((*right, *disp)),
        _ => None,
    }
}

/// The `i`th in argument after a complex request's descriptors (and their
/// NDR record).
fn arg_after(req: &Kmsg, ndesc: usize, i: usize) -> Option<i32> {
    i32_at(&req.body, 4 + 12 * ndesc + NDR + 4 * i)
}

/// Answer request `req` sent to kernel object `obj`.
pub fn serve(k: &mut Kernel, obj: &Kobject, req: &Kmsg) -> Reply {
    let bad = || Reply::err(MIG_BAD_ARGUMENTS);
    match (obj, req.id) {
        // host_info(host, flavor, out, &count)
        (Kobject::Host | Kobject::HostPriv, 200) => match (arg(req, 0), arg(req, 1)) {
            (Some(flavor), Some(count)) => host_info(flavor, count as u32),
            _ => bad(),
        },
        // host_page_size(host) -> vm_size_t
        (Kobject::Host | Kobject::HostPriv, 202) => Reply::ok(u64::from(machine::PAGE_SIZE).to_le_bytes().to_vec()),
        // host_get_clock_service(host, clock_id) -> clock_serv_t: the system
        // clock (SYSTEM_CLOCK) or the calendar (CALENDAR_CLOCK).
        (Kobject::Host | Kobject::HostPriv, 206) => match arg(req, 0) {
            Some(0) | Some(1) => {
                let p = k.darwin_clock_port();
                k.dtask.ipc.make_send(p);
                Reply::port(Carried::Port(p))
            }
            Some(_) => Reply::err(KERN_INVALID_ARGUMENT),
            None => bad(),
        },
        // host_get_special_port(host_priv, node, which) -> port
        (Kobject::Host | Kobject::HostPriv, 412) => match (arg(req, 0), arg(req, 1)) {
            (Some(_node), Some(which)) => host_get_special_port(k, obj, req.dest, which),
            _ => bad(),
        },
        // mach_voucher_extract_attr_content(voucher, key, out content)
        (Kobject::Voucher(v), 5400) => match (arg(req, 0), arg(req, 1)) {
            (Some(key), Some(cnt)) => {
                let n = (cnt as u32).min(4096);
                voucher_reply(k.with_voucher(*v, |k, v| k.mach_voucher_extract_attr_content(v, key as u32, n)))
            }
            _ => bad(),
        },
        // mach_voucher_extract_attr_recipe(voucher, key, out recipe)
        (Kobject::Voucher(v), 5401) => match (arg(req, 0), arg(req, 1)) {
            (Some(key), Some(cnt)) => {
                let n = (cnt as u32).min(4096);
                voucher_reply(k.with_voucher(*v, |k, v| k.mach_voucher_extract_attr_recipe(v, key as u32, n)))
            }
            _ => bad(),
        },
        // mach_voucher_extract_all_attr_recipes(voucher, out recipes)
        (Kobject::Voucher(v), 5402) => match arg(req, 0) {
            Some(cnt) => {
                let n = (cnt as u32).min(5120);
                voucher_reply(k.with_voucher(*v, |k, v| k.mach_voucher_extract_all_attr_recipes(v, n)))
            }
            None => bad(),
        },
        // mach_voucher_attr_command(voucher, key, command, in_content,
        // out out_content)
        (Kobject::Voucher(v), 5403) => {
            let (Some(key), Some(command), Some(in_cnt)) = (arg(req, 0), arg(req, 1), arg(req, 2)) else { return bad() };
            if in_cnt as u32 > 4096 {
                return bad();
            }
            let at = NDR + 12;
            let padded = (in_cnt as usize + 3) & !3;
            let (Some(input), Some(out_cnt)) = (req.body.get(at..at + in_cnt as usize), i32_at(&req.body, at + padded)) else { return bad() };
            if req.body.len() != at + padded + 4 {
                return bad();
            }
            let input = input.to_vec();
            let n = (out_cnt as u32).min(4096);
            voucher_reply(k.with_voucher(*v, |k, v| k.mach_voucher_attr_command(v, key as u32, command as u32, &input, n)))
        }
        // mach_voucher_debug_info(task, voucher_name, out recipes): only in
        // DEVELOPMENT and DEBUG kernels.
        // _kernelrpc_mach_ports_register3(task, port1, port2, port3): the
        // stash swapped in, an immovable right refused, the old released.
        (Kobject::Task, 3403) => {
            let mut ports = [None; 3];
            for (i, slot) in ports.iter_mut().enumerate() {
                match desc_port(req, i) {
                    Some((Some(Carried::Port(p)), _)) => *slot = Some(p),
                    Some((None, _)) => {}
                    _ => return bad(),
                }
            }
            if ports.iter().flatten().any(|&p| k.dtask.ipc.port(p).immovable_send) {
                return Reply::err(KERN_INVALID_RIGHT);
            }
            let old = std::mem::replace(&mut k.dtask.kports.registered, ports);
            for p in old.into_iter().flatten() {
                k.dtask.ipc.release_send(p);
            }
            Reply::ok(Vec::new())
        }
        // _kernelrpc_mach_ports_lookup3(task) -> port1, port2, port3: a copy
        // of each stashed right (a dead name for a port that died).
        (Kobject::Task, 3404) => {
            let mut r = Reply::ok(Vec::new());
            for slot in k.dtask.kports.registered {
                r = match slot {
                    Some(p) if k.dtask.ipc.port(p).active => {
                        k.dtask.ipc.copy_send(p);
                        r.ports.push(super::kobject::PortOut::Right(Carried::Port(p), super::ipc::right::msgt::PORT_SEND));
                        r
                    }
                    Some(_) => r.with_null_port(super::ipc::PORT_DEAD),
                    None => r.with_null_port(0),
                };
            }
            r
        }
        // mach_port_allocate_name(task, right, name): mach_port_allocate_full
        // with the name asked for; a dead name takes any.
        (Kobject::Task, 3203) => match (arg(req, 0), arg(req, 1)) {
            (Some(right), Some(name)) => {
                let name = name as u32;
                if !super::ipc::name_valid(name) {
                    return Reply::err(KERN_INVALID_VALUE);
                }
                let r = right as u32;
                let named = (r != super::ipc::port_right::DEAD_NAME).then_some(name);
                match k.dtask.ipc.mach_port_allocate(r, named) {
                    Ok(_) => Reply::ok(Vec::new()),
                    Err(e) => Reply::err(e as i32),
                }
            }
            _ => bad(),
        },
        (Kobject::Task, 5404) => Reply::err(KERN_NOT_SUPPORTED),
        // clock_get_time(clock) -> mach_timespec_t
        (Kobject::Clock, 1000) => {
            let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
            let mut o = (t.as_secs() as u32).to_le_bytes().to_vec();
            o.extend_from_slice(&(t.subsec_nanos() as i32).to_le_bytes());
            Reply::ok(o)
        }
        // task_info(task, flavor, out, &count)
        (Kobject::Task, 3405) => match (arg(req, 0), arg(req, 1)) {
            (Some(flavor), Some(count)) => task_info(flavor, count as u32, k.darwin_dyld_infos, k.darwin_audit_token()),
            _ => bad(),
        },
        // task_get_special_port(task, which) -> port
        (Kobject::Task, 3409) => match arg(req, 0) {
            Some(which) => task_get_special_port(k, which),
            None => bad(),
        },
        // task_set_special_port(task, which, port)
        (Kobject::Task, 3410) => match (desc_port(req, 0), arg_after(req, 1, 0)) {
            (Some((right, _)), Some(which)) => task_set_special_port(k, which, right),
            _ => bad(),
        },
        // semaphore_create(task, policy, value) -> semaphore_t
        (Kobject::Task, 3418) => match (arg(req, 0), arg(req, 1)) {
            (Some(policy), Some(value)) => match k.semaphore_create(policy, value) {
                Ok(p) => Reply::port(Carried::Port(p)),
                Err(e) => Reply::err(e as i32),
            },
            _ => bad(),
        },
        // semaphore_destroy(task, semaphore): the send right in the request
        // is consumed.
        (Kobject::Task, 3419) => match desc_port(req, 0) {
            Some((Some(Carried::Port(p)), disp)) => {
                let r = k.semaphore_destroy(p);
                if r == kr::SUCCESS {
                    k.dtask.ipc.object_destroy(Carried::Port(p), disp);
                }
                Reply::err(r as i32)
            }
            Some(_) => Reply::err(KERN_INVALID_ARGUMENT),
            None => bad(),
        },
        // task_restartable_ranges_register(task, ranges, count) and
        // task_restartable_ranges_synchronize(task).
        (Kobject::Task, 8000) => restartable_register(k, req),
        (Kobject::Task, 8001) => Reply::ok(Vec::new()),
        // thread_suspend(thread) (`thread_act.defs`): one more user stop. A
        // thread made suspended has not run, so nothing waits for it to
        // stop; one that runs would have to be stopped where it is.
        (Kobject::Thread(t), 3605) => {
            let th = k.dtask.threads.map.entry(*t).or_default();
            if th.unstarted.is_none() {
                let mut r = Reply::err(KERN_FAILURE);
                r.unimplemented = Some("thread_suspend of a running thread".into());
                return r;
            }
            th.suspend += 1;
            Reply::ok(Vec::new())
        }
        // thread_resume(thread): one user stop fewer; at none, a thread that
        // has never run starts.
        (Kobject::Thread(t), 3606) => {
            let th = k.dtask.threads.map.entry(*t).or_default();
            if th.suspend == 0 {
                return Reply::err(KERN_FAILURE);
            }
            th.suspend -= 1;
            if th.suspend == 0 {
                if let Some(r) = th.unstarted.take() {
                    k.dtask.spawns.push(r);
                }
            }
            Reply::ok(Vec::new())
        }
        (o, id) => {
            let mut r = Reply::err(MIG_BAD_ID);
            r.unimplemented = Some(format!("MIG routine {id} on {o:?}"));
            r
        }
    }
}

/// `host_info`, with the caller's count checked as XNU checks it.
fn host_info(flavor: i32, count: u32) -> Reply {
    use machine::*;
    const HOST_BASIC_INFO: i32 = 1;
    const HOST_SCHED_INFO: i32 = 3;
    const HOST_RESOURCE_SIZES: i32 = 4;
    const HOST_PRIORITY_INFO: i32 = 5;
    const HOST_SEMAPHORE_TRAPS: i32 = 7;
    const HOST_MACH_MSG_TRAP: i32 = 8;
    const HOST_PREFERRED_USER_ARCH: i32 = 12;
    let mem32 = MEMORY.min(u64::from(u32::MAX)) as u32;
    match flavor {
        // max_cpus, avail_cpus, memory_size, cpu_type, cpu_subtype, then
        // with room cpu_threadtype, physical_cpu, physical_cpu_max,
        // logical_cpu, logical_cpu_max, max_mem.
        HOST_BASIC_INFO => {
            if count < 5 {
                return Reply::err(KERN_FAILURE);
            }
            let mut w = vec![NCPUS, NCPUS, mem32, CPU_TYPE_ARM64, machine::CPU_SUBTYPE];
            if count >= 12 {
                w.extend([0, NCPUS, NCPUS, NCPUS, NCPUS, MEMORY as u32, (MEMORY >> 32) as u32]);
            }
            Reply::ok(words(&w))
        }
        // min_timeout, min_quantum: the 10 ms quantum, in milliseconds.
        HOST_SCHED_INFO => {
            if count < 2 {
                return Reply::err(KERN_FAILURE);
            }
            Reply::ok(words(&[10, 10]))
        }
        HOST_RESOURCE_SIZES => Reply::err(if count < 5 { KERN_FAILURE } else { KERN_INVALID_ARGUMENT }),
        // MINPRI_KERNEL, MINPRI_KERNEL, MINPRI_RESERVED, BASEPRI_DEFAULT,
        // DEPRESSPRI, IDLEPRI, MINPRI_USER, MAXPRI_RESERVED.
        HOST_PRIORITY_INFO => {
            if count < 8 {
                return Reply::err(KERN_FAILURE);
            }
            Reply::ok(words(&[80, 80, 64, 31, 0, 0, 0, 79]))
        }
        HOST_SEMAPHORE_TRAPS | HOST_MACH_MSG_TRAP => Reply::ok(words(&[])),
        HOST_PREFERRED_USER_ARCH => {
            if count < 2 {
                return Reply::err(KERN_FAILURE);
            }
            Reply::ok(words(&[CPU_TYPE_ARM64, machine::CPU_SUBTYPE]))
        }
        _ => Reply::err(KERN_INVALID_ARGUMENT),
    }
}

/// `task_info`, with the caller's count checked as XNU checks it.
fn task_info(flavor: i32, count: u32, dyld_infos: u64, audit: [u32; 8]) -> Reply {
    const TASK_AUDIT_TOKEN: i32 = 15;
    const TASK_AUDIT_TOKEN_COUNT: u32 = 8;
    const TASK_DYLD_INFO: i32 = 17;
    const TASK_DYLD_INFO_COUNT: u32 = 5;
    const TASK_LEGACY_DYLD_INFO_COUNT: u32 = 4;
    /// `sizeof(struct dyld_all_image_infos)` for a 64-bit process.
    const ALL_IMAGE_INFOS_SIZE: u32 = 0x170;
    match flavor {
        // all_image_info_addr and all_image_info_size (8 bytes each), and
        // with room all_image_info_format (TASK_DYLD_ALL_IMAGE_INFO_64).
        TASK_DYLD_INFO => {
            if count < TASK_LEGACY_DYLD_INFO_COUNT {
                return Reply::err(KERN_INVALID_ARGUMENT);
            }
            let a = dyld_infos;
            let size = if a == 0 { 0 } else { ALL_IMAGE_INFOS_SIZE };
            let mut w = vec![a as u32, (a >> 32) as u32, size, 0];
            if count >= TASK_DYLD_INFO_COUNT {
                w.push(1);
            }
            Reply::ok(words(&w))
        }
        TASK_AUDIT_TOKEN => {
            if count < TASK_AUDIT_TOKEN_COUNT {
                return Reply::err(KERN_INVALID_ARGUMENT);
            }
            Reply::ok(words(&audit))
        }
        _ => {
            let mut r = Reply::err(KERN_INVALID_ARGUMENT);
            r.unimplemented = Some(format!("task_info flavor {flavor}"));
            r
        }
    }
}

/// `task_get_special_port_internal` for the control flavor.
fn task_get_special_port(k: &mut Kernel, which: i32) -> Reply {
    const TASK_KERNEL_PORT: i32 = 1;
    const TASK_HOST_PORT: i32 = 2;
    const TASK_NAME_PORT: i32 = 3;
    const TASK_BOOTSTRAP_PORT: i32 = 4;
    const TASK_INSPECT_PORT: i32 = 5;
    const TASK_READ_PORT: i32 = 6;
    const TASK_ACCESS_PORT: i32 = 9;
    const TASK_DEBUG_CONTROL_PORT: i32 = 10;
    const TASK_RESOURCE_NOTIFY_PORT: i32 = 11;
    match which {
        TASK_KERNEL_PORT => {
            let p = k.darwin_task_port();
            k.dtask.ipc.copy_send(p);
            Reply::port(Carried::Port(p))
        }
        TASK_HOST_PORT => {
            let p = k.darwin_itk_host();
            k.dtask.ipc.copy_send(p);
            Reply::port(Carried::Port(p))
        }
        TASK_NAME_PORT => {
            let p = match k.dtask.kports.task_name {
                Some(p) => p,
                None => {
                    let p = k.dtask.ipc.kobject_port(Kobject::TaskName);
                    k.dtask.kports.task_name = Some(p);
                    p
                }
            };
            k.dtask.ipc.make_send(p);
            Reply::port(Carried::Port(p))
        }
        // ipc_port_copy_send_mqueue: a copy of what was set; null when
        // nothing was, dead when it died.
        TASK_BOOTSTRAP_PORT | TASK_ACCESS_PORT | TASK_DEBUG_CONTROL_PORT | TASK_RESOURCE_NOTIFY_PORT => match k.dtask.kports.special.get(&which).copied() {
            Some(p) if k.dtask.ipc.port(p).active => {
                k.dtask.ipc.copy_send(p);
                Reply::port(Carried::Port(p))
            }
            Some(_) => Reply { ret: KERN_SUCCESS, out: Vec::new(), ports: Vec::new(), unimplemented: None }.with_null_port(super::ipc::PORT_DEAD),
            None => Reply { ret: KERN_SUCCESS, out: Vec::new(), ports: Vec::new(), unimplemented: None }.with_null_port(0),
        },
        TASK_INSPECT_PORT | TASK_READ_PORT => {
            let mut r = Reply::err(KERN_INVALID_ARGUMENT);
            r.unimplemented = Some("task inspect and read ports".into());
            r
        }
        _ => Reply::err(KERN_INVALID_ARGUMENT),
    }
}

/// A voucher routine's reply: its inline array (count, bytes, padded to
/// a word), or its error.
fn voucher_reply(r: Result<Vec<u8>, u32>) -> Reply {
    match r {
        Ok(b) => {
            let mut o = (b.len() as u32).to_le_bytes().to_vec();
            o.extend_from_slice(&b);
            o.resize((o.len() + 3) & !3, 0);
            Reply::ok(o)
        }
        Err(kr) => Reply::err(kr as i32),
    }
}

/// `host_get_special_port_from_user`: `convert_port_to_host_priv` takes
/// only the task's own host port, and only when it is the privilege port.
fn host_get_special_port(k: &mut Kernel, obj: &Kobject, port: super::ipc::ObjId, id: i32) -> Reply {
    const HOST_SECURITY_PORT: i32 = 0;
    const HOST_PORT: i32 = 1;
    const HOST_PRIV_PORT: i32 = 2;
    const HOST_IO_MAIN_PORT: i32 = 3;
    const HOST_MAX_SPECIAL_PORT: i32 = 7 + 27;
    let host_priv = matches!(obj, Kobject::HostPriv) && port == k.darwin_itk_host();
    if !host_priv || id == HOST_SECURITY_PORT || !(HOST_SECURITY_PORT..=HOST_MAX_SPECIAL_PORT).contains(&id) {
        return Reply::err(KERN_INVALID_ARGUMENT);
    }
    let p = match id {
        HOST_PORT => k.darwin_host_port(),
        HOST_PRIV_PORT => k.darwin_host_priv_port(),
        HOST_IO_MAIN_PORT => {
            let mut r = Reply::err(KERN_INVALID_ARGUMENT);
            r.unimplemented = Some("the IOKit main port (HOST_IO_MAIN_PORT)".into());
            return r;
        }
        _ => {
            // realhost.special: launchd's ports, which no task here has
            // set (host_set_special_port).
            return Reply::ok(Vec::new()).with_null_port(0);
        }
    };
    k.dtask.ipc.copy_send(p);
    Reply::port(Carried::Port(p))
}

/// `task_set_special_port`: KERNEL and HOST are refused (no CSR on iOS);
/// the rest replace what was set, the old send right released.
fn task_set_special_port(k: &mut Kernel, which: i32, right: Option<Carried>) -> Reply {
    const TASK_KERNEL_PORT: i32 = 1;
    const TASK_HOST_PORT: i32 = 2;
    const TASK_BOOTSTRAP_PORT: i32 = 4;
    const TASK_ACCESS_PORT: i32 = 9;
    const TASK_DEBUG_CONTROL_PORT: i32 = 10;
    const TASK_RESOURCE_NOTIFY_PORT: i32 = 11;
    let port = match right {
        Some(Carried::Port(p)) => Some(p),
        _ => None,
    };
    if let Some(p) = port {
        if k.dtask.ipc.port(p).immovable_send {
            return Reply::err(KERN_INVALID_RIGHT);
        }
    }
    match which {
        TASK_KERNEL_PORT | TASK_HOST_PORT => Reply::err(KERN_NO_ACCESS),
        TASK_BOOTSTRAP_PORT | TASK_DEBUG_CONTROL_PORT | TASK_RESOURCE_NOTIFY_PORT | TASK_ACCESS_PORT => {
            if which == TASK_ACCESS_PORT && k.dtask.kports.special.get(&which).is_some_and(|&p| k.dtask.ipc.port(p).active) {
                return Reply::err(KERN_NO_ACCESS);
            }
            let old = match port {
                Some(p) => k.dtask.kports.special.insert(which, p),
                None => k.dtask.kports.special.remove(&which),
            };
            if let Some(o) = old {
                k.dtask.ipc.release_send(o);
            }
            Reply::ok(Vec::new())
        }
        _ => Reply::err(KERN_INVALID_ARGUMENT),
    }
}

/// `task_restartable_ranges_register(task, ranges, count)`
/// (`osfmk/kern/restartable.c`): ranges of `task_restartable_range_t`
/// {location u64, length u16, recovery_offs u16, flags u32}, validated
/// sorted, registered while the task has one thread and only once.
fn restartable_register(k: &mut Kernel, req: &Kmsg) -> Reply {
    const RR_RANGES_MAX: usize = 64;
    const TASK_RESTARTABLE_OFFSET_MAX: u16 = 4096;
    let Some(count) = arg(req, 0) else { return Reply::err(MIG_BAD_ARGUMENTS) };
    let count = count as usize;
    let base = NDR + 4;
    let mut ranges = Vec::with_capacity(count);
    for i in 0..count {
        let o = base + 16 * i;
        let Some(b) = req.body.get(o..o + 16) else { return Reply::err(MIG_BAD_ARGUMENTS) };
        ranges.push((u64::from_le_bytes(b[0..8].try_into().unwrap()), u16::from_le_bytes([b[8], b[9]]), u16::from_le_bytes([b[10], b[11]]), u32::from_le_bytes(b[12..16].try_into().unwrap())));
    }
    // _ranges_validate
    ranges.sort_by_key(|r| r.0);
    if count == 0 {
        return Reply::err(KERN_INVALID_ARGUMENT);
    }
    for (i, &(loc, len, rec, flags)) in ranges.iter().enumerate() {
        if len > TASK_RESTARTABLE_OFFSET_MAX || rec > TASK_RESTARTABLE_OFFSET_MAX || flags != 0 {
            return Reply::err(KERN_INVALID_ARGUMENT);
        }
        let (Some(end), Some(_)) = (loc.checked_add(u64::from(len)), loc.checked_add(u64::from(rec))) else {
            return Reply::err(KERN_INVALID_ARGUMENT);
        };
        if ranges.get(i + 1).is_some_and(|n| end > n.0) {
            return Reply::err(KERN_INVALID_ARGUMENT);
        }
    }
    if k.live_threads.load(std::sync::atomic::Ordering::Acquire) > 1 || !k.dtask.kports.restartable.is_empty() {
        return Reply::err(KERN_NOT_SUPPORTED);
    }
    if ranges.len() > RR_RANGES_MAX {
        return Reply::err(KERN_RESOURCE_SHORTAGE);
    }
    k.dtask.kports.restartable = ranges.into_iter().map(|(l, n, r, f)| (l, n, r, f)).collect();
    Reply::ok(Vec::new())
}
