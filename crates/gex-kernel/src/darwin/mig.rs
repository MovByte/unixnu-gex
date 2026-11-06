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
const KERN_TERMINATED: i32 = 37;
const KERN_RESOURCE_SHORTAGE: i32 = 6;
const KERN_NO_ACCESS: i32 = 8;
const KERN_INVALID_RIGHT: i32 = 17;
const KERN_INVALID_VALUE: i32 = 18;
const KERN_NOT_SUPPORTED: i32 = 46;
/// `MIG_BAD_ARGUMENTS`: a request without the routine's shape.
pub(crate) const MIG_BAD_ARGUMENTS: i32 = -304;

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
    pub const PAGE_SIZE: u32 = 16384;
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
pub(crate) fn arg(req: &Kmsg, i: usize) -> Option<i32> {
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
pub(crate) fn arg_after(req: &Kmsg, ndesc: usize, i: usize) -> Option<i32> {
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
                k.ipc().make_send(p);
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
            let mut kports = std::mem::take(&mut k.dtask.kports);
            let r = ports_register(&mut kports, k.ipc(), ports);
            k.dtask.kports = kports;
            Reply::err(r)
        }
        // _kernelrpc_mach_ports_lookup3(task) -> port1, port2, port3: a copy
        // of each stashed right (a dead name for a port that died).
        (Kobject::Task, 3404) => {
            let mut r = Reply::ok(Vec::new());
            for slot in k.dtask.kports.registered {
                r = match slot {
                    Some(p) if k.ipc().port(p).active => {
                        k.ipc().copy_send(p);
                        r.ports.push(super::kobject::PortOut::Right(Carried::Port(p), super::ipc::right::msgt::PORT_SEND));
                        r
                    }
                    Some(_) => r.with_null_port(super::ipc::PORT_DEAD),
                    None => r.with_null_port(0),
                };
            }
            r
        }
        // task_policy_set(task, flavor, policy_info[policy_infoCnt]): at
        // most TASK_POLICY_INFO_MAX (16) words.
        (Kobject::Task, 3420) => match (arg(req, 0), arg(req, 1)) {
            (Some(flavor), Some(cnt)) if (cnt as u32) <= 16 => {
                let info: Option<Vec<i32>> = (0..cnt as usize).map(|i| arg(req, 2 + i)).collect();
                match info {
                    Some(info) => Reply::err(k.darwin_policy_with(|p| p.set(flavor, &info, true))),
                    None => bad(),
                }
            }
            _ => bad(),
        },
        // task_policy_get(task, flavor, &policy_infoCnt, &get_default) ->
        // policy_info[policy_infoCnt], get_default: the count asked for, at
        // most 16.
        (Kobject::Task, 3421) => match (arg(req, 0), arg(req, 1), arg(req, 2)) {
            (Some(flavor), Some(cnt), Some(get_default)) => {
                let cnt = (cnt as u32).min(16);
                // task_is_privileged: the security token's uid (one uid here, real and
                // effective).
                let privileged = k.creds.uid() == 0;
                match k.darwin_policy().get(flavor, cnt, get_default != 0, privileged) {
                    Some(Ok(w)) => {
                        let mut out = words(&w.iter().map(|&x| x as u32).collect::<Vec<u32>>());
                        out.extend_from_slice(&get_default.to_le_bytes());
                        Reply::ok(out)
                    }
                    Some(Err(e)) => Reply::err(e),
                    None => {
                        let mut r = Reply::err(KERN_FAILURE);
                        r.unimplemented = Some("task_policy_get's TASK_POLICY_STATE (the importance subsystem's counts and marks)".into());
                        r
                    }
                }
            }
            _ => bad(),
        },
        // task_set_exception_ports, task_get_exception_ports,
        // task_swap_exception_ports, and the thread's and host's.
        (Kobject::Task, 3413) => k.darwin_exc_set(super::exception::Level::Task, 0, req, false),
        (Kobject::Task, 3414) => k.darwin_exc_get(super::exception::Level::Task, 0, req),
        (Kobject::Task, 3415) => k.darwin_exc_set(super::exception::Level::Task, 0, req, true),
        (Kobject::Thread(t), 3613) => k.darwin_exc_set(super::exception::Level::Thread, *t, req, false),
        (Kobject::Thread(t), 3614) => k.darwin_exc_get(super::exception::Level::Thread, *t, req),
        (Kobject::Thread(t), 3615) => k.darwin_exc_set(super::exception::Level::Thread, *t, req, true),
        (Kobject::HostPriv, 414) => k.darwin_exc_set(super::exception::Level::Host, 0, req, false),
        (Kobject::HostPriv, 415) => k.darwin_exc_get(super::exception::Level::Host, 0, req),
        (Kobject::HostPriv, 416) => k.darwin_exc_set(super::exception::Level::Host, 0, req, true),
        // The host port is not the privileged one: HOST_PRIV_NULL.
        (Kobject::Host, 414..=416) => Reply::err(KERN_INVALID_ARGUMENT),
        // mach_port_get_refs(task, name, right) -> refs
        (Kobject::Task, 3207) => match (arg(req, 0), arg(req, 1)) {
            (Some(name), Some(right)) => match k.ipc().mach_port_get_refs(name as u32, right as u32) {
                Ok(n) => Reply::ok(n.to_le_bytes().to_vec()),
                Err(e) => Reply::err(e as i32),
            },
            _ => bad(),
        },
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
                match k.ipc().mach_port_allocate(r, named) {
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
        // task_info(task_name, flavor, out, &count): task_info_from_user
        // takes any flavor of port, but TASK_DYLD_INFO needs the read port
        // at least (a name port gives TASK_NULL).
        (Kobject::Task | Kobject::TaskName, 3405) => match (arg(req, 0), arg(req, 1)) {
            (Some(17), Some(_)) if matches!(obj, Kobject::TaskName) => Reply::err(KERN_INVALID_ARGUMENT),
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
                    k.ipc().object_destroy(Carried::Port(p), disp);
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
        // task_suspend(task): a legacy hold, the caller given a send right
        // to the task's resume port (whose no-senders releases the legacy
        // holds left), then a wait for the other threads to stop.
        (Kobject::Task, 3407) => {
            let first = k.darwin_place_task_hold(super::jobctl::HoldMode::Legacy);
            let port = match k.dtask.kports.resume {
                Some(p) => p,
                None => {
                    let p = k.ipc().kobject_port(Kobject::TaskResume);
                    k.dtask.kports.resume = Some(p);
                    p
                }
            };
            // ipc_kobject_make_send_nsrequest, then the right moved out
            // into the caller's space.
            k.ipc().port_mut(port).nsrequest_kobject = true;
            k.ipc().make_send(port);
            let caller = k.dtask.kcaller;
            k.ipc().with_space(caller, |ipc| {
                let _ = ipc.object_copyout(Carried::Port(port), super::ipc::right::msgt::PORT_SEND, None);
            });
            let mut r = Reply::ok(Vec::new());
            if first {
                r.defer = Some((k.tid, super::kobject::Deferred::TaskWait { token: None }));
            }
            r
        }
        // task_resume(task): a legacy hold released, and a send right to
        // the resume port in the caller's space given up (all of them if
        // the release failed).
        (Kobject::Task, 3408) => {
            let ok = k.darwin_release_task_hold(super::jobctl::HoldMode::Legacy);
            // The right is the caller's, in the caller's space.
            let (resume, caller) = (k.dtask.kports.resume, k.dtask.kcaller);
            k.ipc().with_space(caller, |ipc| {
                if let Some(name) = resume.and_then(|p| ipc.space.hash_lookup(p)) {
                    if ok {
                        ipc.right_dealloc(name);
                    } else {
                        ipc.right_destroy(name, false, 0);
                    }
                }
            });
            Reply::err(if ok { 0 } else { KERN_FAILURE })
        }
        // task_suspend2(task) -> suspension token: a hold, answered once the
        // other threads stop with a send-once right to the resume port
        // (destroyed unused, it resumes the task).
        (Kobject::Task, 3436) => {
            let first = k.darwin_place_task_hold(super::jobctl::HoldMode::Normal);
            let port = match k.dtask.kports.resume {
                Some(p) => p,
                None => {
                    let p = k.ipc().kobject_port(Kobject::TaskResume);
                    k.dtask.kports.resume = Some(p);
                    p
                }
            };
            k.ipc().make_sonce(port);
            if first {
                let mut r = Reply::ok(Vec::new());
                r.defer = Some((k.tid, super::kobject::Deferred::TaskWait { token: Some(port) }));
                return r;
            }
            let mut r = Reply::ok(Vec::new());
            r.ports.push(super::kobject::PortOut::Right(Carried::Port(port), super::ipc::right::msgt::PORT_SEND_ONCE));
            r
        }
        // task_resume2(token), sent to the token itself: its hold
        // released; the token, the request's destination, is consumed
        // with it (task_suspension_token_deallocate), unnotified.
        (Kobject::TaskResume, 3437) => {
            let ok = k.darwin_release_task_hold(super::jobctl::HoldMode::Normal);
            Reply::err(if ok { 0 } else { KERN_FAILURE })
        }
        // thread_get_state(thread, flavor, &old_stateCnt) -> old_state[]
        // (at most THREAD_STATE_MAX, 1296 words).
        (Kobject::Thread(t), 3603) => match (arg(req, 0), arg(req, 1)) {
            (Some(flavor), Some(cnt)) => k.darwin_thread_state(*t, flavor, (cnt as u32).min(1296), None),
            _ => bad(),
        },
        // thread_set_state(thread, flavor, new_state[new_stateCnt]).
        (Kobject::Thread(t), 3604) => match (arg(req, 0), arg(req, 1)) {
            (Some(flavor), Some(cnt)) if (cnt as u32) <= 1296 => {
                let w: Option<Vec<u32>> = (0..cnt as usize).map(|i| arg(req, 2 + i).map(|x| x as u32)).collect();
                match w {
                    Some(w) => k.darwin_thread_state(*t, flavor, cnt as u32, Some(w)),
                    None => bad(),
                }
            }
            _ => bad(),
        },
        // thread_policy_set(thread, flavor, policy_info[policy_infoCnt]): at
        // most THREAD_POLICY_INFO_MAX (16) words.
        (Kobject::Thread(t), 3617) => match (arg(req, 0), arg(req, 1)) {
            (Some(flavor), Some(cnt)) if (cnt as u32) <= 16 => {
                let info: Option<Vec<i32>> = (0..cnt as usize).map(|i| arg(req, 2 + i)).collect();
                let caller = k.tid;
                match info {
                    Some(info) => Reply::err(k.darwin_thread_policy_set(*t, caller, flavor, &info)),
                    None => bad(),
                }
            }
            _ => bad(),
        },
        // thread_policy_get(thread, flavor, &policy_infoCnt, &get_default)
        // -> policy_info[policy_infoCnt], get_default.
        (Kobject::Thread(t), 3618) => match (arg(req, 0), arg(req, 1), arg(req, 2)) {
            (Some(flavor), Some(cnt), Some(get_default)) => match k.darwin_thread_policy_get(*t, flavor, (cnt as u32).min(16), get_default != 0) {
                Some(Ok((w, def))) => {
                    let mut out = words(&w.iter().map(|&x| x as u32).collect::<Vec<u32>>());
                    out.extend_from_slice(&u32::from(def).to_le_bytes());
                    Reply::ok(out)
                }
                Some(Err(e)) => Reply::err(e),
                None => {
                    let mut r = Reply::err(KERN_FAILURE);
                    r.unimplemented = Some(format!("thread_policy_get flavor {flavor} (the thread's policy bitfields and override counts)"));
                    r
                }
            },
            _ => bad(),
        },
        // thread_suspend(thread) (`thread_act.defs`): one more user stop
        // (thread_hold at the first), then, for another thread, its caller
        // waits for it to be off its CPU (thread_wait): held at its next
        // return to user space, or waiting in a call.
        (Kobject::Thread(t), 3605) => {
            let t = *t;
            if !k.darwin_thread_alive(t) {
                return Reply::err(KERN_TERMINATED);
            }
            k.dtask.threads.map.entry(t).or_default().suspend += 1;
            let mut r = Reply::ok(Vec::new());
            if t != k.tid && !k.darwin_offcpu(t) {
                r.defer = Some((t, super::kobject::Deferred::ThreadWait));
            }
            r
        }
        // thread_resume(thread): one user stop fewer (KERN_FAILURE with
        // none); at none, the thread is let go (one made suspended starts).
        (Kobject::Thread(t), 3606) => {
            let t = *t;
            if !k.darwin_thread_alive(t) {
                return Reply::err(KERN_TERMINATED);
            }
            let th = k.dtask.threads.map.entry(t).or_default();
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
            k.ipc().copy_send(p);
            Reply::port(Carried::Port(p))
        }
        TASK_HOST_PORT => {
            let p = k.darwin_itk_host();
            k.ipc().copy_send(p);
            Reply::port(Carried::Port(p))
        }
        TASK_NAME_PORT => {
            let ipc = k.ipc();
            let me = ipc.task;
            let p = ipc.task_name_port(me).expect("a task holding the table has its link");
            k.ipc().make_send(p);
            Reply::port(Carried::Port(p))
        }
        // ipc_port_copy_send_mqueue: a copy of what was set; null when
        // nothing was, dead when it died.
        TASK_BOOTSTRAP_PORT | TASK_ACCESS_PORT | TASK_DEBUG_CONTROL_PORT | TASK_RESOURCE_NOTIFY_PORT => match k.dtask.kports.special.get(&which).copied() {
            Some(p) if k.ipc().port(p).active => {
                k.ipc().copy_send(p);
                Reply::port(Carried::Port(p))
            }
            Some(_) => Reply { ret: KERN_SUCCESS, defer: None, out: Vec::new(), ports: Vec::new(), unimplemented: None }.with_null_port(super::ipc::PORT_DEAD),
            None => Reply { ret: KERN_SUCCESS, defer: None, out: Vec::new(), ports: Vec::new(), unimplemented: None }.with_null_port(0),
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
    k.ipc().copy_send(p);
    Reply::port(Carried::Port(p))
}

/// `task_set_special_port`: KERNEL and HOST are refused (no CSR on iOS);
/// the rest replace what was set, the old send right released.
fn task_set_special_port(k: &mut Kernel, which: i32, right: Option<Carried>) -> Reply {
    let port = match right {
        Some(Carried::Port(p)) => Some(p),
        _ => None,
    };
    let mut kports = std::mem::take(&mut k.dtask.kports);
    let r = set_special_port(&mut kports, k.ipc(), which, port);
    k.dtask.kports = kports;
    Reply::err(r)
}

/// `task_set_special_port` (the kernel's, which `posix_spawn`'s port
/// actions call too) on the task whose ports are `kports`: the send right
/// `port` stored as its special port `which`, the old one released.
pub(crate) fn set_special_port(kports: &mut super::kobject::Kports, ipc: &mut super::ipc::Ipc, which: i32, port: Option<super::ipc::ObjId>) -> i32 {
    const TASK_KERNEL_PORT: i32 = 1;
    const TASK_HOST_PORT: i32 = 2;
    const TASK_BOOTSTRAP_PORT: i32 = 4;
    const TASK_ACCESS_PORT: i32 = 9;
    const TASK_DEBUG_CONTROL_PORT: i32 = 10;
    const TASK_RESOURCE_NOTIFY_PORT: i32 = 11;
    if let Some(p) = port {
        if ipc.port(p).immovable_send {
            return KERN_INVALID_RIGHT;
        }
    }
    match which {
        TASK_KERNEL_PORT | TASK_HOST_PORT => KERN_NO_ACCESS,
        TASK_BOOTSTRAP_PORT | TASK_DEBUG_CONTROL_PORT | TASK_RESOURCE_NOTIFY_PORT | TASK_ACCESS_PORT => {
            if which == TASK_ACCESS_PORT && kports.special.get(&which).copied().is_some_and(|p| ipc.port(p).active) {
                return KERN_NO_ACCESS;
            }
            let old = match port {
                Some(p) => kports.special.insert(which, p),
                None => kports.special.remove(&which),
            };
            if let Some(o) = old {
                ipc.release_send(o);
            }
            0
        }
        _ => KERN_INVALID_ARGUMENT,
    }
}

/// `mach_ports_register` on the task whose ports are `kports`: the send
/// rights `ports` registered (an immovable one refused), the old ones
/// released.
pub(crate) fn ports_register(kports: &mut super::kobject::Kports, ipc: &mut super::ipc::Ipc, ports: [Option<super::ipc::ObjId>; 3]) -> i32 {
    if ports.iter().flatten().any(|&p| ipc.port(p).immovable_send) {
        return KERN_INVALID_RIGHT;
    }
    let old = std::mem::replace(&mut kports.registered, ports);
    for p in old.into_iter().flatten() {
        ipc.release_send(p);
    }
    0
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
