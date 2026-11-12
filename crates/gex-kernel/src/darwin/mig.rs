//! The kernel's MIG routines: requests sent to the task's, host's, a
//! thread's, the clock's or a semaphore's port, decoded from the request
//! message and answered as MIG's generated kernel server code answers them.

use super::ipc::msg::{Desc, Kmsg};
use super::ipc::right::Carried;
use super::ipc::{kr, Kobject};
use super::kobject::{PortOut, Reply, MIG_BAD_ID};
use crate::syscalls::Kernel;

/// `mach_msg_header_t` and the NDR record after it.
pub const HEADER: usize = 24;
pub const NDR: usize = 8;

/// The NDR record every MIG message carries: little-endian, IEEE floats.
pub const NDR_RECORD: [u8; 8] = [0, 0, 0, 0, 1, 0, 0, 0];

/// `kern_return_t`s as MIG return codes.
const KERN_SUCCESS: i32 = 0;
const KERN_INVALID_ADDRESS: i32 = 1;
const KERN_INVALID_ARGUMENT: i32 = 4;
const KERN_FAILURE: i32 = 5;
const KERN_TERMINATED: i32 = 37;
const KERN_RESOURCE_SHORTAGE: i32 = 6;
const KERN_NO_ACCESS: i32 = 8;
const KERN_INVALID_RIGHT: i32 = 17;
const KERN_INVALID_VALUE: i32 = 18;
const KERN_INVALID_TASK: i32 = 16;
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

/// The 64-bit in argument at the `i`th word.
fn arg64(req: &Kmsg, i: usize) -> Option<u64> {
    Some(u64::from(arg(req, i)? as u32) | (u64::from(arg(req, i + 1)? as u32) << 32))
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

/// An out `io_name_t` as MIG sends it: an unused offset, the count with its
/// terminator, the characters padded.
/// io_registry_entry_get_child_iterator / _parent_iterator(entry, plane):
/// an iterator over the entry's links in the plane (`getChildIterator`).
fn link_iterator(k: &mut Kernel, req: &Kmsg, i: u32, parents: bool) -> Reply {
    let Some((plane, _)) = inline_cstr(req, 0, 128) else { return Reply::err(MIG_BAD_ARGUMENTS) };
    let links = super::iokit::plane(plane).and_then(|p| super::iokit::links(super::iokit::tree(), i, p, parents));
    match links {
        Ok(l) => {
            let id = super::iokit::iterator_new(l);
            let port = k.ipc().global_port(Kobject::IoIterator(id));
            k.ipc().copy_send(port);
            Reply::port(Carried::Port(port))
        }
        Err(what) => {
            let mut r = Reply { ret: KERN_SUCCESS, defer: None, out: Vec::new(), ports: Vec::new(), unimplemented: None }.with_null_port(0);
            r.unimplemented = Some(format!("the {} links of an entry: {what}", if parents { "parent" } else { "child" }));
            r
        }
    }
}

/// `IORegistryIterator::iterateOver(entry, plane, options)` for a task.
fn registry_iterator(k: &mut Kernel, req: &Kmsg, entry: u32) -> Reply {
    let Some((plane, next)) = inline_cstr(req, 0, 128) else { return Reply::err(MIG_BAD_ARGUMENTS) };
    let Some(options) = i32_at(&req.body, next) else { return Reply::err(MIG_BAD_ARGUMENTS) };
    match super::iokit::plane(plane) {
        Ok(p) => {
            let id = super::iokit::registry_iterator_new(entry, p, options as u32);
            let port = k.ipc().global_port(Kobject::IoIterator(id));
            k.ipc().copy_send(port);
            Reply::port(Carried::Port(port))
        }
        Err(what) => {
            let mut r = Reply::err(0xe00002c2_u32 as i32);
            r.unimplemented = Some(format!("an IORegistryIterator in {what}"));
            r
        }
    }
}

fn io_name_reply(name: &str) -> Vec<u8> {
    let bytes = name.as_bytes();
    let n = (bytes.len() + 1) as u32;
    let mut o = 0u32.to_le_bytes().to_vec();
    o.extend_from_slice(&n.to_le_bytes());
    o.extend_from_slice(bytes);
    o.push(0);
    o.resize((o.len() + 3) & !3, 0);
    o
}

/// `IOKIT_SERVER_VERSION`.
const IOKIT_SERVER_VERSION: u64 = 20210810;

/// The inline C string at the `i`th argument after the NDR record (MIG's
/// `offset`, `count`, then the characters in a buffer of `max`), and the
/// body offset past its padded characters.
fn inline_cstr(req: &Kmsg, i: usize, max: usize) -> Option<(&[u8], usize)> {
    inline_cstr_at(req, NDR + 4 * i, max)
}

/// [`inline_cstr`] at a body offset already known.
fn inline_cstr_at(req: &Kmsg, at: usize, max: usize) -> Option<(&[u8], usize)> {
    let count = i32_at(&req.body, at + 4)? as u32 as usize;
    if count > max {
        return None;
    }
    let bytes = req.body.get(at + 8..at + 8 + count)?;
    let end = bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len());
    Some((&bytes[..end], at + 8 + ((count + 3) & !3)))
}

/// Answer request `req` sent to kernel object `obj`.
pub fn serve(k: &mut Kernel, obj: &Kobject, req: &Kmsg) -> Reply {
    let bad = || Reply::err(MIG_BAD_ARGUMENTS);
    // A read or inspect port takes the routines its flavor satisfies
    // (task_port_kotype_valid_for_flavor): its own arms, or the control
    // port's whose port type asks no more; for the others the routine's
    // conversion finds no task. A routine not served here goes on as the
    // control port's would.
    use super::kobject::flavor;
    let as_control;
    let obj = match obj {
        Kobject::TaskRead | Kobject::TaskInspect | Kobject::ThreadRead(_) | Kobject::ThreadInspect(_) => {
            let thread = matches!(obj, Kobject::ThreadRead(_) | Kobject::ThreadInspect(_));
            let f = if matches!(obj, Kobject::TaskRead | Kobject::ThreadRead(_)) { flavor::READ } else { flavor::INSPECT };
            let need = if thread { thread_routine_flavor(req.id) } else { task_routine_flavor(req.id) };
            match need {
                // The arms that read the port's flavor themselves.
                Some(_) if !thread && matches!(req.id, 3402 | 3405 | 3409) => obj,
                Some(_) if thread && req.id == 3610 => obj,
                Some(n) if f > n => return Reply::err(if (3200..3300).contains(&req.id) { KERN_INVALID_TASK } else { KERN_INVALID_ARGUMENT }),
                // task_conversion_eval, for a read port's conversion.
                _ if f == flavor::READ && !k.darwin_read_conversion_ok() => return Reply::err(KERN_INVALID_ARGUMENT),
                _ => {
                    as_control = match obj {
                        Kobject::ThreadRead(t) | Kobject::ThreadInspect(t) => Kobject::Thread(*t),
                        _ => Kobject::Task,
                    };
                    &as_control
                }
            }
        }
        // convert_port_to_task_policy_mig: a name port takes task_policy_set
        // and _get only for a caller entitled to com.apple.private.task_policy
        // (and a thread port never); else TASK_NULL, KERN_INVALID_ARGUMENT.
        Kobject::TaskName if matches!(req.id, 3420 | 3421) => {
            let own = k.dtask.kcaller == 0 || k.dtask.kcaller == k.ipc().task;
            if !own {
                let mut r = Reply::err(KERN_INVALID_ARGUMENT);
                r.unimplemented = Some("task_policy through another task's name port (its caller's com.apple.private.task_policy)".into());
                return r;
            }
            if !k.darwin_entitled("com.apple.private.task_policy") {
                return Reply::err(KERN_INVALID_ARGUMENT);
            }
            as_control = Kobject::Task;
            &as_control
        }
        _ => obj,
    };
    match (obj, req.id) {
        // host_info(host, flavor, out, &count)
        (Kobject::Host | Kobject::HostPriv, 200) => match (arg(req, 0), arg(req, 1)) {
            (Some(HOST_VM_PURGABLE), Some(_)) => {
                k.darwin_unimplemented("host_info HOST_VM_PURGABLE (purgeable memory has no page model here)".into());
                Reply::err(KERN_FAILURE)
            }
            (Some(flavor), Some(count)) => host_info(flavor, count as u32),
            _ => bad(),
        },
        // host_statistics(host, flavor, out, &count) and host_statistics64
        // (host_statistics_from_user, host_statistics64_from_user).
        (Kobject::Host | Kobject::HostPriv, id @ (216 | 219)) => match (arg(req, 0), arg(req, 1)) {
            (Some(flavor), Some(count)) => host_statistics(k, id == 219, flavor, count as u32),
            _ => bad(),
        },
        // host_page_size(host) -> vm_size_t
        (Kobject::Host | Kobject::HostPriv, 202) => Reply::ok(u64::from(machine::PAGE_SIZE).to_le_bytes().to_vec()),
        // host_get_io_main(host) -> io_main_t.
        (Kobject::Host | Kobject::HostPriv, 205) => {
            let p = k.ipc().global_port(Kobject::IoMain);
            k.ipc().copy_send(p);
            Reply::port(Carried::Port(p))
        }
        // host_get_clock_service(host, clock_id) -> clock_serv_t: the system
        // clock (SYSTEM_CLOCK) or the calendar (CALENDAR_CLOCK).
        (Kobject::Host | Kobject::HostPriv, 206) => match arg(req, 0) {
            Some(id @ (0 | 1)) => {
                let p = k.darwin_clock_port(id as u8);
                k.ipc().make_send(p);
                Reply::port(Carried::Port(p))
            }
            Some(_) => Reply::err(KERN_INVALID_ARGUMENT),
            None => bad(),
        },
        // host_set_atm_diagnostic_flag(host, diagnostic_flag): for a task
        // entitled to it, atm_set_diagnostic_config (CONFIG_ATM; ATM is not
        // disabled by a boot argument or /defaults).
        (Kobject::Host | Kobject::HostPriv, 225) => match arg(req, 0) {
            Some(flag) => {
                if !k.darwin_entitled("com.apple.private.set-atm-diagnostic-flag") {
                    return Reply::err(KERN_NO_ACCESS);
                }
                super::commpage::set_atm_diagnostic_config(flag as u32);
                Reply::ok(Vec::new())
            }
            None => bad(),
        },
        // host_create_mach_voucher(host, recipes) -> voucher: the raw
        // recipes, counted and padded (MIG's `_WALIGN_`).
        (Kobject::Host | Kobject::HostPriv, 222) => {
            const MAX_RAW_RECIPE_ARRAY_SIZE: usize = 5120;
            let Some(n) = arg(req, 0) else { return bad() };
            let n = n as u32 as usize;
            let at = NDR + 4;
            let padded = (n + 3) & !3;
            if n > MAX_RAW_RECIPE_ARRAY_SIZE || req.body.len() != at + padded {
                return bad();
            }
            let raw = req.body[at..at + n].to_vec();
            match k.host_create_mach_voucher(&raw) {
                Ok(Some(v)) => {
                    let p = k.convert_voucher_to_port(v);
                    Reply::port(Carried::Port(p))
                }
                Ok(None) => Reply { ret: KERN_SUCCESS, defer: None, out: Vec::new(), ports: Vec::new(), unimplemented: None }.with_null_port(0),
                Err(kr) => Reply::err(kr as i32),
            }
        }
        // host_set_special_port(host_priv, which, port)
        (Kobject::Host | Kobject::HostPriv, 413) => match (desc_port(req, 0), arg_after(req, 1, 0)) {
            (Some((right, _)), Some(which)) => host_set_special_port(k, obj, req.dest, which, right),
            _ => bad(),
        },
        // io_server_version(main_port) -> version.
        (Kobject::IoMain, 2877) => Reply::ok(IOKIT_SERVER_VERSION.to_le_bytes().to_vec()),
        // io_registry_entry_from_path(main_port, path) -> registry_entry.
        (Kobject::IoMain, 2809) => {
            let Some(path) = inline_cstr(req, 0, 512) else { return bad() };
            let p = String::from_utf8_lossy(path.0).into_owned();
            match super::iokit::from_path(super::iokit::tree(), &p) {
                Ok(Some(i)) => {
                    let port = k.ipc().global_port(Kobject::IoEntry(i));
                    k.ipc().copy_send(port);
                    Reply::port(Carried::Port(port))
                }
                Ok(None) => Reply { ret: KERN_SUCCESS, defer: None, out: Vec::new(), ports: Vec::new(), unimplemented: None }.with_null_port(0),
                Err(what) => {
                    let mut r = Reply { ret: KERN_SUCCESS, defer: None, out: Vec::new(), ports: Vec::new(), unimplemented: None }.with_null_port(0);
                    r.unimplemented = Some(format!("IORegistryEntry::fromPath: {what}"));
                    r
                }
            }
        }
        // io_registry_entry_get_property_bytes(entry, name, dataCnt) ->
        // data: the property's own bytes, kIOReturnNoResources for none,
        // kIOReturnIPCError for too little room.
        (Kobject::IoEntry(i), 2812) => {
            const K_IO_RETURN_NO_RESOURCES: i32 = 0xe00002be_u32 as i32;
            const K_IO_RETURN_IPC_ERROR: i32 = 0xe00002bf_u32 as i32;
            const IO_STRUCT_INBAND_MAX: usize = 4096;
            let Some((name, next)) = inline_cstr(req, 0, 128) else { return bad() };
            let Some(cnt) = i32_at(&req.body, next) else { return bad() };
            const K_IO_RETURN_BAD_ARGUMENT: i32 = 0xe00002c2_u32 as i32;
            let Some(node) = super::iokit::tree().get(*i as usize) else { return bad() };
            let name = String::from_utf8_lossy(name);
            // An OSString's bytes and its NUL, an OSBoolean's "Yes" or "No",
            // an OSNumber's or OSData's bytes; a collection is not bytes.
            let typed = node.service_props.iter().find(|(k, _)| *k == name).map(|(_, p)| super::iokit::prop_bytes(p));
            let value = match (typed, node.props.iter().find(|(k, _)| *k == name)) {
                (Some(Some(v)), _) => v,
                (Some(None), _) => return Reply::err(K_IO_RETURN_BAD_ARGUMENT),
                (None, Some(_)) if node.kernel_only => Vec::new(),
                (None, Some((_, v))) => v.clone(),
                (None, None) => {
                    let mut r = Reply::err(K_IO_RETURN_NO_RESOURCES);
                    let root = Some(*i) == super::iokit::root();
                    if (!node.class.is_empty() || *i == 0) && !(root && !super::iokit::root_has(&name)) {
                        r.unimplemented = Some(format!("the {} property {name:?}", super::iokit::name(super::iokit::tree(), *i)));
                    }
                    return r;
                }
            };
            if (cnt as u32 as usize).min(IO_STRUCT_INBAND_MAX) < value.len() {
                return Reply::err(K_IO_RETURN_IPC_ERROR);
            }
            let mut o = (value.len() as u32).to_le_bytes().to_vec();
            o.extend_from_slice(&value);
            o.resize((o.len() + 3) & !3, 0);
            Reply::ok(o)
        }
        // io_registry_entry_get_property_bin_buf(entry, plane, name, options,
        // buf, bufsize) -> properties, bufsize: the property serialized in
        // OSSerializeBinary, into `buf` when it fits, else out of line.
        (Kobject::IoEntry(i), 2889) => {
            const K_IO_RETURN_NOT_FOUND: i32 = 0xe00002f0_u32 as i32;
            const K_IO_REGISTRY_ITERATE_RECURSIVELY: u32 = 1;
            let Some((plane, next)) = inline_cstr(req, 0, 128) else { return bad() };
            let Some((name, next)) = inline_cstr_at(req, next, 128) else { return bad() };
            let (Some(options), Some(buf), Some(bufsize)) = (i32_at(&req.body, next), req.body.get(next + 4..next + 12), req.body.get(next + 12..next + 20)) else { return bad() };
            let (buf, bufsize) = (u64::from_le_bytes(buf.try_into().unwrap()), u64::from_le_bytes(bufsize.try_into().unwrap()));
            let Some(node) = super::iokit::tree().get(*i as usize) else { return bad() };
            let name = String::from_utf8_lossy(name).into_owned();
            if options as u32 & K_IO_REGISTRY_ITERATE_RECURSIVELY != 0 && !plane.is_empty() || name == "IORegistryEntryPropertyKeys" {
                let mut r = Reply::err(K_IO_RETURN_NOT_FOUND);
                r.unimplemented = Some(format!("io_registry_entry_get_property_bin_buf of {name} (recursion or the property keys)"));
                return r;
            }
            let bin = if let Some((_, p)) = node.service_props.iter().find(|(k, _)| *k == name) {
                super::iokit::serialize_prop(p)
            } else if let Some((_, value)) = node.props.iter().find(|(k, _)| *k == name) {
                super::iokit::serialize_data(if node.kernel_only { &[] } else { value })
            } else {
                // The platform expert device has the platform's properties
                // besides the device tree's.
                let mut r = Reply::err(K_IO_RETURN_NOT_FOUND);
                let root = Some(*i) == super::iokit::root();
                if (!node.class.is_empty() || *i == 0) && !(root && !super::iokit::root_has(&name)) {
                    r.unimplemented = Some(format!("the {} property {name:?}", super::iokit::name(super::iokit::tree(), *i)));
                }
                return r;
            };
            let mut out = NDR_RECORD.to_vec();
            if buf != 0 && bin.len() as u64 <= bufsize {
                match k.darwin_vm_copy_overwrite(buf, &bin) {
                    Ok(()) => {}
                    Err(r) => return r,
                }
                out.extend_from_slice(&(bin.len() as u64).to_le_bytes());
                out.extend_from_slice(&0u32.to_le_bytes());
                let mut r = Reply::ok(out);
                r.ports.push(PortOut::Ool(Vec::new()));
                r
            } else {
                out.extend_from_slice(&0u64.to_le_bytes());
                out.extend_from_slice(&(bin.len() as u32).to_le_bytes());
                let mut r = Reply::ok(out);
                r.ports.push(PortOut::Ool(bin));
                r
            }
        }
        // io_service_get_matching_services_bin(main_port, matching, cnt) ->
        // existing: an iterator of what the dictionary matches.
        (Kobject::IoMain, 2881) => {
            const K_IO_RETURN_NOT_READY: i32 = 0xe00002d8_u32 as i32;
            let Some(n) = arg(req, 0) else { return bad() };
            let n = n as u32 as usize;
            let Some(bytes) = req.body.get(NDR + 4..NDR + 4 + n) else { return bad() };
            let Some(dict) = super::iokit::unserialize_dict(bytes) else {
                let mut r = Reply::err(K_IO_RETURN_NOT_READY);
                r.unimplemented = Some(format!("a matching dictionary of nested or other kinds: {:x?}", &bytes[..bytes.len().min(160)]));
                return r;
            };
            match super::iokit::matching(super::iokit::tree(), &dict) {
                Ok(items) => {
                    let id = super::iokit::iterator_new(items);
                    let port = k.ipc().global_port(Kobject::IoIterator(id));
                    k.ipc().copy_send(port);
                    Reply::port(Carried::Port(port))
                }
                Err(what) => {
                    let mut r = Reply::err(K_IO_RETURN_NOT_READY);
                    r.unimplemented = Some(format!("IOService matching: {what}"));
                    r
                }
            }
        }
        // io_registry_entry_get_registry_entry_id(entry) -> id. The kernel's
        // ids are the entries' own; these name the same entries for as long.
        (Kobject::IoEntry(i), 2871) => Reply::ok(super::iokit::registry_id(*i).to_le_bytes().to_vec()),
        // io_registry_entry_get_parent_iterator(entry, plane) -> iterator.
        (Kobject::IoEntry(i), 2814) => link_iterator(k, req, *i, true),
        // io_service_get_matching_service_bin(main_port, matching) -> first
        // service, of the dictionary's matches.
        (Kobject::IoMain, 2880) => {
            const K_IO_RETURN_NOT_READY: i32 = 0xe00002d8_u32 as i32;
            let Some(n) = arg(req, 0) else { return bad() };
            let n = n as u32 as usize;
            let Some(bytes) = req.body.get(NDR + 4..NDR + 4 + n) else { return bad() };
            let Some(dict) = super::iokit::unserialize_dict(bytes) else {
                let mut r = Reply::err(K_IO_RETURN_NOT_READY);
                r.unimplemented = Some(format!("a matching dictionary of nested or other kinds: {:x?}", &bytes[..bytes.len().min(300)]));
                return r;
            };
            match super::iokit::matching(super::iokit::tree(), &dict) {
                Ok(items) => match items.first() {
                    Some(&i) => {
                        let port = k.ipc().global_port(Kobject::IoEntry(i));
                        k.ipc().copy_send(port);
                        Reply::port(Carried::Port(port))
                    }
                    None => Reply::err(0xe00002f0_u32 as i32),
                },
                Err(what) => {
                    let mut r = Reply::err(K_IO_RETURN_NOT_READY);
                    r.unimplemented = Some(format!("IOService matching: {what}"));
                    r
                }
            }
        }
        // io_registry_entry_get_child_iterator(entry, plane) -> iterator.
        (Kobject::IoEntry(i), 2813) => link_iterator(k, req, *i, false),
        // io_registry_get_root_entry(main_port) -> root.
        (Kobject::IoMain, 2827) => match super::iokit::root() {
            Some(r) => {
                let port = k.ipc().global_port(Kobject::IoEntry(r));
                k.ipc().copy_send(port);
                Reply::port(Carried::Port(port))
            }
            None => {
                let mut r = Reply::err(0xe00002c7_u32 as i32);
                r.unimplemented = Some("the registry root with no device tree".to_string());
                r
            }
        },
        // io_registry_create_iterator(main_port, plane, options) and
        // io_registry_entry_create_iterator(entry, plane, options) ->
        // iterator: an IORegistryIterator over the root's links, or the
        // entry's, in the plane.
        (Kobject::IoMain, 2806) => match super::iokit::root() {
            Some(r) => registry_iterator(k, req, r),
            None => {
                let mut r = Reply::err(0xe00002c7_u32 as i32);
                r.unimplemented = Some("the registry root with no device tree".to_string());
                r
            }
        },
        (Kobject::IoEntry(i), 2833) => registry_iterator(k, req, *i),
        // io_registry_iterator_enter_entry and _exit_entry: on a registry
        // iterator only (kIOReturnBadArgument), the exit kIOReturnNoDevice
        // at the start.
        (Kobject::IoIterator(id), 2807) => match super::iokit::iterator_enter(*id) {
            true => Reply::ok(Vec::new()),
            false => Reply::err(0xe00002c2_u32 as i32),
        },
        (Kobject::IoIterator(id), 2808) => match super::iokit::iterator_exit(*id) {
            Some(true) => Reply::ok(Vec::new()),
            Some(false) => Reply::err(0xe00002c0_u32 as i32),
            None => Reply::err(0xe00002c2_u32 as i32),
        },
        (Kobject::IoNotification(_), 2807 | 2808) => Reply::err(0xe00002c2_u32 as i32),
        // io_object_conforms_to(object, className) -> conforms.
        (Kobject::IoEntry(i), 2801) => {
            let Some((name, _)) = inline_cstr(req, 0, 128) else { return bad() };
            match super::iokit::conforms(super::iokit::tree(), *i, &String::from_utf8_lossy(name)) {
                Ok(yes) => Reply::ok(u32::from(yes).to_le_bytes().to_vec()),
                Err(what) => {
                    let mut r = Reply::err(0xe00002c7_u32 as i32);
                    r.unimplemented = Some(what);
                    r
                }
            }
        }
        // io_object_get_class(object) -> className.
        (Kobject::IoEntry(i), 2800) => {
            match super::iokit::class(super::iokit::tree(), *i) {
                Ok(c) => Reply::ok(io_name_reply(c)),
                Err(what) => {
                    let mut r = Reply::err(0xe00002c7_u32 as i32);
                    r.unimplemented = Some(what);
                    r
                }
            }
        }
        // io_registry_entry_get_name(entry) -> name.
        (Kobject::IoEntry(i), 2810) => Reply::ok(io_name_reply(&super::iokit::name(super::iokit::tree(), *i))),
        // io_registry_entry_get_name_in_plane(entry, plane) -> name: the
        // entry's name there, which only the device tree root has its own
        // of (`device-tree`); no plane is the entry's name.
        (Kobject::IoEntry(i), 2843) => {
            let Some((plane, _)) = inline_cstr(req, 0, 128) else { return bad() };
            let t = super::iokit::tree();
            if plane.is_empty() {
                return Reply::ok(io_name_reply(&super::iokit::name(t, *i)));
            }
            match super::iokit::plane(plane) {
                Ok(super::iokit::Plane::DeviceTree) if *i == 0 => Reply::ok(io_name_reply(&t[0].name)),
                Ok(_) => Reply::ok(io_name_reply(&super::iokit::name(t, *i))),
                Err(what) => {
                    let mut r = Reply::err(0xe00002c7_u32 as i32);
                    r.unimplemented = Some(format!("an entry's name in {what}"));
                    r
                }
            }
        }
        // io_registry_entry_get_location_in_plane(entry, plane) -> location:
        // a volume's index in its container.
        (Kobject::IoEntry(i), 2854) => {
            let Some(node) = super::iokit::tree().get(*i as usize) else { return bad() };
            match super::iokit::location(node) {
                Some(l) => Reply::ok(io_name_reply(&l)),
                None => Reply::err(0xe00002f0_u32 as i32),
            }
        }
        // io_service_open_extended(service, owningTask, type, ndr,
        // properties) -> connection, result: a new user client of the
        // service, made by its newUserClient.
        (Kobject::IoEntry(i), 2862) => io_service_open(k, req, *i),
        // The routines of a user client (io_connect_t).
        (Kobject::IoConnect(id), n @ (2800 | 2801 | 2810 | 2812 | 2816 | 2817 | 2820 | 2821 | 2852 | 2863 | 2864 | 2865 | 2866 | 2867 | 2871 | 2872 | 2889)) => connect_routine(k, req, *id, n),
        // io_service_add_notification_bin(main_port, notification_type,
        // matching, wake_port, reference) -> notification: an
        // IOServiceUserNotification over what the dictionary matches now
        // (internal_io_service_add_notification). It keeps the wake port's
        // send right until it is freed.
        (Kobject::IoMain, 2884) => {
            const K_IO_RETURN_NO_RESOURCES: i32 = 0xe00002be_u32 as i32;
            const K_IO_RETURN_UNSUPPORTED: i32 = 0xe00002c7_u32 as i32;
            const K_IO_RETURN_NOT_READY: i32 = 0xe00002d8_u32 as i32;
            // sizeof(OSAsyncReference64).
            const ASYNC_REF64: usize = 8 * 8;
            let Some((wake, _)) = desc_port(req, 0) else { return bad() };
            let Some((ty, at)) = inline_cstr_at(req, 4 + 12 + NDR, 128) else { return bad() };
            let Some(n) = i32_at(&req.body, at) else { return bad() };
            let n = n as u32 as usize;
            let Some(bytes) = req.body.get(at + 4..at + 4 + n) else { return bad() };
            let ref_at = at + 4 + ((n + 3) & !3);
            let Some(refs) = i32_at(&req.body, ref_at) else { return bad() };
            // A dictionary not read here, whether malformed (xnu's
            // kIOReturnBadArgument) or of kinds this reader lacks, is said.
            let Some(dict) = super::iokit::unserialize_dict(bytes) else {
                let mut r = Reply::err(K_IO_RETURN_NOT_READY);
                r.unimplemented = Some(format!("a matching dictionary of nested or other kinds: {:x?}", &bytes[..bytes.len().min(300)]));
                return r;
            };
            // IOServiceUserNotification::init: no bigger a reference than
            // an OSAsyncReference64.
            if refs as u32 as usize * 8 > ASYNC_REF64 {
                return Reply::err(K_IO_RETURN_NO_RESOURCES);
            }
            // doInstallNotification: which services already there it is
            // handed (those published, or matched; terminated ones none),
            // and no other kind of notification.
            let existing = match ty {
                b"IOServicePublish" | b"IOServiceFirstPublish" | b"IOServiceMatched" | b"IOServiceFirstMatch" => true,
                b"IOServiceTerminate" | b"IOServiceWillTerminate" => false,
                _ => return Reply::err(K_IO_RETURN_UNSUPPORTED),
            };
            let items = if existing {
                match super::iokit::matching(super::iokit::tree(), &dict) {
                    Ok(items) => items,
                    Err(what) => {
                        let mut r = Reply::err(K_IO_RETURN_NOT_READY);
                        r.unimplemented = Some(format!("IOService matching: {what}"));
                        return r;
                    }
                }
            } else {
                Vec::new()
            };
            let wake = match wake {
                Some(Carried::Port(p)) => Some(p),
                _ => None,
            };
            let id = super::iokit::notification_new(items, wake);
            let port = k.ipc().kobject_port(Kobject::IoNotification(id));
            k.ipc().port_mut(port).owner = 0;
            k.ipc().make_send(port);
            k.ipc().port_mut(port).nsrequest_kobject = true;
            Reply::port(Carried::Port(port))
        }
        // io_iterator_next, io_iterator_reset and io_iterator_is_valid on
        // a notification: its services from the last handed; a reset does
        // nothing, and it is always valid.
        (Kobject::IoNotification(id), 2802) => match super::iokit::notification_next(*id) {
            Some(i) => {
                let port = k.ipc().global_port(Kobject::IoEntry(i));
                k.ipc().copy_send(port);
                Reply::port(Carried::Port(port))
            }
            None => Reply::err(0xe00002c0_u32 as i32),
        },
        (Kobject::IoNotification(_), 2803) => Reply::ok(Vec::new()),
        // io_iterator_reset and io_iterator_is_valid on an iterator over a
        // set of entries: back to its first; and valid, its set never
        // changing (no entry comes or goes once the registry is built).
        (Kobject::IoIterator(id), 2803) => {
            super::iokit::iterator_reset(*id);
            Reply::ok(Vec::new())
        }
        (Kobject::IoIterator(_), 2834) => Reply::ok(1u32.to_le_bytes().to_vec()),
        (Kobject::IoNotification(_), 2834) => Reply::ok(1u32.to_le_bytes().to_vec()),
        // io_iterator_next(iterator) -> object, or kIOReturnNoDevice for
        // none left.
        (Kobject::IoIterator(id), 2802) => match super::iokit::iterator_next(*id) {
            Ok(Some(i)) => {
                let port = k.ipc().global_port(Kobject::IoEntry(i));
                k.ipc().copy_send(port);
                Reply::port(Carried::Port(port))
            }
            Ok(None) => Reply::err(0xe00002c0_u32 as i32),
            Err(what) => {
                let mut r = Reply::err(0xe00002c0_u32 as i32);
                r.unimplemented = Some(format!("an IORegistryIterator reaching {what}"));
                r
            }
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
        // task_policy_set and _get through a thread's port: no task.
        (Kobject::Thread(_), 3420 | 3421) => Reply::err(KERN_INVALID_ARGUMENT),
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
                        r.unimplemented = Some("task_policy_get's TASK_POLICY_STATE (the requested and effective policies' bitfield encodings)".into());
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
        // mach_port_set_attributes(task, name, flavor, port_info[
        // port_infoCnt]): at most 17 words.
        (Kobject::Task, 3218) => match (arg(req, 0), arg(req, 1), arg(req, 2)) {
            (Some(name), Some(flavor), Some(cnt)) if (cnt as u32) <= 17 => {
                let info: Option<Vec<u32>> = (0..cnt as usize).map(|i| arg(req, 3 + i).map(|x| x as u32)).collect();
                match info {
                    Some(info) => Reply::err(k.ipc().mach_port_set_attributes(name as u32, flavor, &info) as i32),
                    None => bad(),
                }
            }
            _ => bad(),
        },
        // mach_port_allocate_name(task, right, name): mach_port_allocate_full
        // with the name asked for; a dead name takes any.
        // mach_port_extract_right(task, name, msgt_name) -> poly: the right
        // taken from the space as if the space had sent it; an immovable
        // send right may be copied out of the caller's own space.
        (Kobject::Task, 3215) => match (arg(req, 0), arg(req, 1)) {
            (Some(name), Some(t)) => {
                let (name, t) = (name as u32, t as u32);
                if !super::ipc::right::msgt::any(t) {
                    return Reply::err(KERN_INVALID_VALUE);
                }
                if !super::ipc::name_valid(name) {
                    return Reply::err(KERN_INVALID_RIGHT);
                }
                let own = k.dtask.kcaller == 0 || k.dtask.kcaller == k.ipc().task;
                let flags = super::ipc::right::CopyinFlags { allow_immovable_send: own && t == super::ipc::right::msgt::COPY_SEND, ..Default::default() };
                match k.ipc().object_copyin(name, t, flags, 0, None) {
                    Ok(c) => {
                        let mut r = Reply::ok(Vec::new());
                        r.ports.push(PortOut::Right(c, super::ipc::right::msgt::copyin_type(t)));
                        r
                    }
                    Err(e) => Reply::err(e as i32),
                }
            }
            _ => bad(),
        },
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
        // mach_port_get_context_from_user(task, name) -> context.
        (Kobject::Task | Kobject::TaskRead, 3228) => match arg(req, 0) {
            Some(name) => match k.ipc().mach_port_get_context(name as u32) {
                Ok(c) => Reply::ok(c.to_le_bytes().to_vec()),
                Err(e) => Reply::err(e as i32),
            },
            _ => bad(),
        },
        // mach_port_set_context(task, name, context).
        (Kobject::Task, 3229) => match (arg(req, 0), arg64(req, 1)) {
            (Some(name), Some(c)) => Reply::err(k.ipc().mach_port_set_context(name as u32, c) as i32),
            _ => bad(),
        },
        (Kobject::Task, 5404) => Reply::err(KERN_NOT_SUPPORTED),
        // clock_get_time(clock) -> mach_timespec_t: the system clock's
        // rtclock_gettime (the time since boot, clock_get_system_nanotime),
        // the calendar's calend_gettime.
        (Kobject::Clock(id), 1000) => {
            let (secs, nsecs) = if *id == 0 {
                super::mach::system_nanotime()
            } else {
                let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
                (t.as_secs(), t.subsec_nanos())
            };
            let mut o = (secs as u32).to_le_bytes().to_vec();
            o.extend_from_slice(&(nsecs as i32).to_le_bytes());
            Reply::ok(o)
        }
        // task_info(task_name, flavor, out, &count): task_info_from_user
        // takes any flavor of port, but TASK_DYLD_INFO needs the read port
        // at least (a name port gives TASK_NULL).
        // task_info_from_user: TASK_DYLD_INFO wants a read port, the rest
        // any.
        (Kobject::Task | Kobject::TaskRead | Kobject::TaskInspect | Kobject::TaskName, 3405) => match (arg(req, 0), arg(req, 1)) {
            (Some(17), Some(_)) if matches!(obj, Kobject::TaskName | Kobject::TaskInspect) => Reply::err(KERN_INVALID_ARGUMENT),
            (Some(17), Some(_)) if matches!(obj, Kobject::TaskRead) && !k.darwin_read_conversion_ok() => Reply::err(KERN_INVALID_ARGUMENT),
            (Some(flavor), Some(count)) => task_info(flavor, count as u32, (k.darwin_dyld_infos, k.darwin_dyld_infos_size), k.darwin_audit_token()),
            _ => bad(),
        },
        // task_get_special_port(task, which) -> port
        (Kobject::Task | Kobject::TaskRead | Kobject::TaskInspect, 3409) => match arg(req, 0) {
            Some(which) => {
                let f = match obj {
                    Kobject::TaskRead => flavor::READ,
                    Kobject::TaskInspect => flavor::INSPECT,
                    _ => flavor::CONTROL,
                };
                task_get_special_port(k, which, f)
            }
            None => bad(),
        },
        // task_threads(task) -> act_list[]: the thread ports of the flavor
        // of the task port it was asked by.
        (Kobject::Task | Kobject::TaskRead | Kobject::TaskInspect, 3402) => {
            let f = match obj {
                Kobject::TaskRead => flavor::READ,
                Kobject::TaskInspect => flavor::INSPECT,
                _ => flavor::CONTROL,
            };
            task_threads(k, f)
        }
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
        // mach_eventlink_create(task, option) -> eventlink_pair: the kernel's
        // send right to each end moved out.
        (Kobject::Task, 716200) => match arg(req, 0) {
            Some(option) => match k.darwin_eventlink_create(option as u32) {
                Ok(ports) => {
                    let mut r = Reply::ok(Vec::new());
                    for p in ports {
                        r.ports.push(PortOut::Right(Carried::Port(p), super::ipc::right::msgt::PORT_SEND));
                    }
                    r
                }
                Err(e) => Reply::err(e as i32),
            },
            None => bad(),
        },
        // mach_eventlink_destroy, _associate and _disassociate go to the
        // eventlink's port; any other kernel object converts to none. The
        // thread port's right is released once converted.
        (o, 716201) => Reply::err(k.darwin_eventlink_destroy(o) as i32),
        // mach_eventlink_associate(eventlink, thread, copyin_addr_wait,
        // copyin_mask_wait, copyin_addr_signal, copyin_mask_signal, option).
        (o, 716202) => match (desc_port(req, 0), arg_after(req, 1, 0), arg_after(req, 1, 1), arg_after(req, 1, 2), arg_after(req, 1, 3), arg_after(req, 1, 4), arg_after(req, 1, 5), arg_after(req, 1, 6), arg_after(req, 1, 7), arg_after(req, 1, 8)) {
            (Some((right, disp)), Some(w0), Some(w1), Some(w2), Some(w3), Some(w4), Some(w5), Some(w6), Some(w7), Some(option)) => {
                let u = |lo: i32, hi: i32| u64::from(lo as u32) | u64::from(hi as u32) << 32;
                let thread = match right {
                    Some(Carried::Port(p)) => {
                        let port = k.ipc().port(p);
                        match port.kobject {
                            Some(Kobject::Thread(t)) if port.active => Some(t),
                            _ => None,
                        }
                    }
                    _ => None,
                };
                let r = k.darwin_eventlink_associate(o, thread, [u(w0, w1), u(w2, w3), u(w4, w5), u(w6, w7)], option as u32);
                // A failure's right is the server's to destroy.
                if r == 0 {
                    if let Some(c) = right {
                        k.ipc().object_destroy(c, disp);
                    }
                }
                Reply::err(r as i32)
            }
            _ => bad(),
        },
        (o, 716203) => match arg(req, 0) {
            Some(option) => Reply::err(k.darwin_eventlink_disassociate(o, option as u32) as i32),
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
        // thread_info(thread, flavor, &thread_info_outCnt) ->
        // thread_info_out[] (at most THREAD_INFO_MAX, 32 words).
        (Kobject::Thread(t), 3612) => match (arg(req, 0), arg(req, 1)) {
            (Some(flavor), Some(cnt)) => thread_info(k, *t, flavor, (cnt as u32).min(32)),
            _ => bad(),
        },
        // thread_get_mach_voucher(thread, which) -> voucher: a send right
        // for the thread's voucher, or none.
        (Kobject::Thread(t), 3625) => {
            let v = k.dtask.threads.map.get(t).and_then(|d| d.voucher);
            match v {
                Some(v) => {
                    k.ipc_voucher_reference(v);
                    let p = k.convert_voucher_to_port(v);
                    Reply::port(Carried::Port(p))
                }
                None => Reply::ok(Vec::new()).with_null_port(0),
            }
        }
        // thread_set_mach_voucher(thread, voucher): the calling thread, or
        // one not yet started, takes a reference on the voucher (none
        // clears it); the request's right and its reference are released
        // when it does.
        (Kobject::Thread(t), 3626) => match desc_port(req, 0) {
            Some((right, disp)) => {
                let own = k.dtask.kcaller == 0 || k.dtask.kcaller == k.ipc().task;
                let started = k.dtask.threads.map.get(t).is_none_or(|d| d.unstarted.is_none());
                let r = if (!own || *t != k.tid) && started {
                    KERN_INVALID_ARGUMENT
                } else {
                    let voucher = match right {
                        Some(Carried::Port(p)) => k.convert_port_to_voucher(p),
                        _ => None,
                    };
                    if let Some(v) = voucher {
                        k.ipc_voucher_reference(v);
                    }
                    let d = k.dtask.threads.map.entry(*t).or_default();
                    let old = std::mem::replace(&mut d.voucher, voucher);
                    d.voucher_name = 0;
                    if let Some(o) = old {
                        k.ipc_voucher_release(o);
                    }
                    // MIG's destructor for the converted reference.
                    if let Some(v) = voucher {
                        k.ipc_voucher_release(v);
                    }
                    0
                };
                // A failure's right is the server's to destroy.
                if r == 0 {
                    if let Some(c) = right {
                        k.ipc().object_destroy(c, disp);
                    }
                }
                Reply::err(r)
            }
            None => bad(),
        },
        // thread_get_special_port(thread, which) -> port.
        (Kobject::Thread(t) | Kobject::ThreadRead(t) | Kobject::ThreadInspect(t), 3610) => match arg(req, 0) {
            Some(which) => {
                let f = match obj {
                    Kobject::ThreadRead(_) => flavor::READ,
                    Kobject::ThreadInspect(_) => flavor::INSPECT,
                    _ => flavor::CONTROL,
                };
                thread_get_special_port(k, *t, which, f)
            }
            None => bad(),
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
        // mach_vm_region, and vm_region_64 of the older subsystem: the
        // legacy flavor is the 64-bit one; vm_region takes what it asks for.
        (Kobject::Task, id @ (4816 | 3824 | 3800)) => match (arg64(req, 0), arg(req, 2), arg(req, 3)) {
            (Some(address), Some(flavor), Some(count)) => {
                let flavor = if id != 3800 && flavor == super::vm::region::BASIC_INFO { super::vm::region::BASIC_INFO_64 } else { flavor };
                match k.darwin_vm_map_region(address, flavor, count as u32) {
                    Ok((start, size, info)) => {
                        // vm_region_64 and vm_region answer in vm_address_t:
                        // past VM_MAX_ADDRESS the call fails after the walk.
                        if id != 4816 && start + size > super::vm::MACH_VM_MAX_ADDRESS {
                            return Reply::err(KERN_INVALID_ADDRESS);
                        }
                        let mut out = NDR_RECORD.to_vec();
                        out.extend_from_slice(&start.to_le_bytes());
                        out.extend_from_slice(&size.to_le_bytes());
                        out.extend_from_slice(&words(&info));
                        Reply::ok(out).with_null_port(0)
                    }
                    Err(e) => e,
                }
            }
            _ => bad(),
        },
        // mach_vm_read and vm_read: the bytes, out of line.
        (Kobject::Task, 4804 | 3805) => match (arg64(req, 0), arg64(req, 2)) {
            (Some(address), Some(size)) => {
                if size > u64::from(u32::MAX) {
                    return Reply::err(KERN_INVALID_ARGUMENT);
                }
                match k.darwin_vm_copyin(address, size) {
                    Ok(data) => {
                        let mut out = NDR_RECORD.to_vec();
                        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
                        let mut r = Reply::ok(out);
                        r.ports.push(PortOut::Ool(data));
                        r
                    }
                    Err(r) => r,
                }
            }
            _ => bad(),
        },
        // mach_vm_write and vm_write: the request's out-of-line bytes over
        // the range at `address` (after the body count, the descriptor and
        // the NDR record).
        (Kobject::Task, 4806 | 3807) => {
            const ADDRESS: usize = 4 + 16 + NDR;
            match (req.body.get(ADDRESS..ADDRESS + 8), req.descs.first()) {
                (Some(a), Some(Desc::Ool { data, .. })) => {
                    let address = u64::from_le_bytes(a.try_into().unwrap());
                    k.darwin_vm_copy_overwrite(address, data).map_or_else(|r| r, |()| Reply::ok(Vec::new()))
                }
                _ => bad(),
            }
        }
        // mach_vm_copy and vm_copy.
        (Kobject::Task, 4807 | 3808) => match (arg64(req, 0), arg64(req, 2), arg64(req, 4)) {
            (Some(src), Some(size), Some(dst)) => k.darwin_vm_copyin(src, size).and_then(|d| k.darwin_vm_copy_overwrite(dst, &d)).map_or_else(|r| r, |()| Reply::ok(Vec::new())),
            _ => bad(),
        },
        // mach_vm_read_overwrite and vm_read_overwrite: into this task's
        // memory at `data`.
        (Kobject::Task, 4808 | 3809) => match (arg64(req, 0), arg64(req, 2), arg64(req, 4)) {
            (Some(address), Some(size), Some(data)) => k.darwin_vm_copyin(address, size).and_then(|b| k.darwin_vm_copy_overwrite(data, &b)).map_or_else(|r| r, |()| Reply::ok(size.to_le_bytes().to_vec())),
            _ => bad(),
        },
        // mach_vm_msync and vm_msync.
        (Kobject::Task, 4809 | 3810) => match (arg64(req, 0), arg64(req, 2), arg(req, 4)) {
            (Some(address), Some(size), Some(flags)) => match k.darwin_own_memory(|k, m| k.darwin_vm_msync(m, address, size, flags as u32)) {
                Ok(ret) => Reply { ret: ret as i32, defer: None, out: Vec::new(), ports: Vec::new(), unimplemented: None },
                Err(r) => r,
            },
            _ => bad(),
        },
        // mach_vm_machine_attribute and vm_machine_attribute: the value
        // comes back as it went.
        (Kobject::Task, 4812 | 3813) => match (arg64(req, 0), arg64(req, 2), arg(req, 4), arg(req, 5)) {
            (Some(address), Some(size), Some(attribute), Some(value)) => match k.darwin_vm_machine_attribute(address, size, attribute) {
                0 => Reply::ok(value.to_le_bytes().to_vec()),
                e => Reply::err(e),
            },
            _ => bad(),
        },
        // mach_vm_inherit and vm_inherit.
        (Kobject::Task, 4803 | 3804) => match (arg64(req, 0), arg64(req, 2), arg(req, 4)) {
            (Some(address), Some(size), Some(new)) => Reply { ret: k.darwin_vm_inherit(address, size, new as u32) as i32, defer: None, out: Vec::new(), ports: Vec::new(), unimplemented: None },
            _ => bad(),
        },
        // mach_vm_behavior_set and vm_behavior_set.
        (Kobject::Task, 4810 | 3811) => match (arg64(req, 0), arg64(req, 2), arg(req, 4)) {
            (Some(address), Some(size), Some(new)) => match k.darwin_own_memory(|k, m| k.darwin_behavior_set(m, address, size, new)) {
                Ok(ret) => Reply { ret: ret as i32, defer: None, out: Vec::new(), ports: Vec::new(), unimplemented: None },
                Err(r) => r,
            },
            _ => bad(),
        },
        (o, id) => {
            let mut r = Reply::err(MIG_BAD_ID);
            r.unimplemented = Some(format!("MIG routine {id} on {o:?}"));
            r
        }
    }
}

/// `host_info`, with the caller's count checked as XNU checks it.
const HOST_VM_PURGABLE: i32 = 9;

fn host_info(flavor: i32, count: u32) -> Reply {
    use machine::*;
    // PE_i_can_has_debugger: /chosen's debug-enabled, zero on a production
    // device.
    const HOST_CAN_HAS_DEBUGGER: i32 = 11;
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
        HOST_CAN_HAS_DEBUGGER => {
            if count < 1 {
                return Reply::err(KERN_FAILURE);
            }
            Reply::ok(words(&[0]))
        }
        // HOST_DEBUG_INFO_INTERNAL: a DEVELOPMENT or DEBUG kernel's only;
        // this is a release kernel.
        10 => Reply::err(KERN_NOT_SUPPORTED),
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
fn task_info(flavor: i32, count: u32, dyld_infos: (u64, u64), audit: [u32; 8]) -> Reply {
    const TASK_AUDIT_TOKEN: i32 = 15;
    const TASK_AUDIT_TOKEN_COUNT: u32 = 8;
    const TASK_DYLD_INFO: i32 = 17;
    const TASK_DYLD_INFO_COUNT: u32 = 5;
    const TASK_LEGACY_DYLD_INFO_COUNT: u32 = 4;
    /// `sizeof(struct dyld_all_image_infos)` for a 64-bit process.
    match flavor {
        // all_image_info_addr and all_image_info_size (8 bytes each), and
        // with room all_image_info_format (TASK_DYLD_ALL_IMAGE_INFO_64).
        TASK_DYLD_INFO => {
            if count < TASK_LEGACY_DYLD_INFO_COUNT {
                return Reply::err(KERN_INVALID_ARGUMENT);
            }
            let (a, size) = dyld_infos;
            let mut w = vec![a as u32, (a >> 32) as u32, size as u32, (size >> 32) as u32];
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

/// `thread_info` of thread `t`: KERN_TERMINATED once it has ended, else
/// `thread_info_internal` with the caller's count checked as XNU checks it.
/// `host_statistics`'s flavors (`mach/host_info.h`).
mod hstat {
    pub const LOAD_INFO: i32 = 1;
    pub const VM_INFO: i32 = 2;
    pub const CPU_LOAD_INFO: i32 = 3;
    pub const VM_INFO64: i32 = 4;
    pub const EXTMOD_INFO64: i32 = 5;
    pub const EXPIRED_TASK_INFO: i32 = 6;
    /// `HOST_LOAD_INFO_COUNT`: `avenrun[3]` and `mach_factor[3]`.
    pub const LOAD_INFO_COUNT: u32 = 6;
}

/// `g_host_stats_cache[HOST_LOAD_INFO_REV0]`: the window a third-party
/// task's requests are counted in, and what the last one was given.
struct StatsCache {
    last_access: u64,
    current_requests: u64,
    max_requests: u64,
    data: [u32; 6],
}

static LOAD_CACHE: std::sync::Mutex<StatsCache> = std::sync::Mutex::new(StatsCache { last_access: 0, current_requests: 0, max_requests: 0, data: [0; 6] });

/// `host_statistics_from_user` and `host_statistics64_from_user`: a task
/// that is not a platform binary is rate limited (`rate_limit_host_
/// statistics`: a random 2 to 10 requests in each second, past which it is
/// given what the last request was), then `host_statistics64` (whose own
/// flavors are the VM's) or `host_statistics`.
fn host_statistics(k: &mut Kernel, is64: bool, flavor: i32, count: u32) -> Reply {
    use hstat::*;
    // MIG's bound on the out array: HOST_INFO64_MAX or HOST_INFO_MAX.
    let count = count.min(if is64 { 256 } else { 1024 });
    let unkept = match flavor {
        VM_INFO => Some("HOST_VM_INFO (the VM's page counts and events)"),
        CPU_LOAD_INFO => Some("HOST_CPU_LOAD_INFO (each CPU's ticks by state)"),
        EXPIRED_TASK_INFO => Some("HOST_EXPIRED_TASK_INFO (the ended tasks' power usage)"),
        VM_INFO64 if is64 => Some("HOST_VM_INFO64 (the VM's page counts and events)"),
        EXTMOD_INFO64 if is64 => Some("HOST_EXTMOD_INFO64 (the counts of other tasks' changes to tasks)"),
        _ => None,
    };
    if let Some(what) = unkept {
        k.darwin_unimplemented(format!("host_statistics {what}"));
        return Reply::err(KERN_NOT_SUPPORTED);
    }
    let limited = !k.darwin_task_platform_binary();
    if limited {
        // get_host_info_data_index.
        match flavor {
            LOAD_INFO if count < LOAD_INFO_COUNT => return Reply::err(KERN_FAILURE),
            LOAD_INFO => {}
            _ => return Reply::err(KERN_INVALID_ARGUMENT),
        }
        // mach_continuous_time: no sleep is kept here, so it is the
        // absolute time. HOST_STATISTICS_TIME_WINDOW is a second.
        let mut c = LOAD_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        let window = 24_000_000u64;
        let mut set_last_access = true;
        if c.last_access > super::mach::absolute_time().wrapping_sub(window) {
            set_last_access = false;
            let n = c.current_requests;
            c.current_requests += 1;
            if n >= c.max_requests {
                return Reply::ok(words(&c.data));
            }
        }
        if set_last_access {
            c.current_requests = 1;
            // HOST_STATISTICS_MIN_REQUESTS to HOST_STATISTICS_MAX_REQUESTS.
            c.max_requests = super::mach::absolute_time() % (10 - 2 + 1) + 2;
            c.last_access = super::mach::absolute_time();
        }
    }
    // host_statistics.
    let data = match flavor {
        LOAD_INFO => {
            if count < LOAD_INFO_COUNT {
                return Reply::err(KERN_FAILURE);
            }
            let (avenrun, mach_factor) = match k.procs.sched.host_load() {
                Ok(l) => l,
                Err(why) => {
                    k.darwin_unimplemented(why.into());
                    return Reply::err(KERN_NOT_SUPPORTED);
                }
            };
            [avenrun[0], avenrun[1], avenrun[2], mach_factor[0], mach_factor[1], mach_factor[2]]
        }
        _ => return Reply::err(KERN_INVALID_ARGUMENT),
    };
    // cache_host_statistics: a third party's answer is the one the limit
    // gives back.
    if limited {
        LOAD_CACHE.lock().unwrap_or_else(|e| e.into_inner()).data = data;
    }
    Reply::ok(words(&data))
}

fn thread_info(k: &mut Kernel, t: i32, flavor: i32, count: u32) -> Reply {
    const THREAD_IDENTIFIER_INFO: i32 = 4;
    const THREAD_IDENTIFIER_INFO_COUNT: u32 = 6;
    const KERN_TERMINATED: i32 = 37;
    let Some(th) = k.thread_signals.get(t) else { return Reply::err(KERN_TERMINATED) };
    match flavor {
        // thread_id, thread_handle (cthread_self) and dispatch_qaddr
        // (thread_dispatchqaddr: the handle plus the process's dispatch
        // queue offset, none without a handle).
        THREAD_IDENTIFIER_INFO => {
            if count < THREAD_IDENTIFIER_INFO_COUNT {
                return Reply::err(KERN_INVALID_ARGUMENT);
            }
            let handle = th.tsd();
            let qaddr = if handle == 0 { 0 } else { handle.wrapping_add(k.dtask.pthread.dispatch_queue_offset) };
            let mut w = Vec::with_capacity(6);
            for v in [th.darwin_id(), handle, qaddr] {
                w.extend_from_slice(&[v as u32, (v >> 32) as u32]);
            }
            Reply::ok(words(&w))
        }
        _ => {
            let mut r = Reply::err(KERN_INVALID_ARGUMENT);
            r.unimplemented = Some(format!("thread_info flavor {flavor}"));
            r
        }
    }
}

/// The weakest flavor of task port each routine served here takes (its MIG
/// port type: `task_t`, `task_read_t`, `task_inspect_t`, `task_name_t`).
fn task_routine_flavor(id: i32) -> Option<u8> {
    use super::kobject::flavor::*;
    Some(match id {
        // task_info (task_name_t), task_get_special_port (an inspect port
        // or better), task_policy_get (task_policy_get_t: inspect).
        3405 => NAME,
        3402 | 3409 | 3421 => INSPECT,
        4816 | 3824 | 3800 | 4804 | 3805 | 4808 | 3809 => READ,
        4803 | 3804 | 4810 | 3811 | 4806 | 3807 | 4807 | 3808 | 4809 | 3810 | 4812 | 3813 => CONTROL,
        3403 | 3404 | 3410 | 3413 | 3414 | 3415 | 3418 | 3419 | 3420 | 3203 | 3207 | 5404 | 8000 => CONTROL,
        _ => return None,
    })
}

/// The same for thread ports: thread_get_state, thread_suspend and
/// thread_resume take `thread_read_t`, thread_policy_get
/// `thread_inspect_t`.
fn thread_routine_flavor(id: i32) -> Option<u8> {
    use super::kobject::flavor::*;
    Some(match id {
        3603 | 3605 | 3606 | 3625 => READ,
        3610 | 3612 | 3618 => INSPECT,
        3604 | 3613 | 3614 | 3615 | 3617 | 3626 => CONTROL,
        _ => return None,
    })
}

/// `task_threads_internal` for a task port of flavor `f`: each of the
/// task's threads, in the order made, as a send right of that flavor
/// (`convert_thread_array_to_ports`). A control port asked by the task
/// itself gives the threads' self ports; asked from another task, each is
/// dead without Developer Mode, or when a platform binary's threads go to
/// a task that is not one (`task_conversion_eval_out_trans`).
fn task_threads(k: &mut Kernel, f: u8) -> Reply {
    use super::kobject::flavor;
    use super::kobject::PortOut;
    let mut tids = k.thread_signals.tids_in_order();
    tids.extend(k.dtask.threads.map.keys().copied());
    tids.sort_unstable();
    tids.dedup();
    let own = k.dtask.kcaller == 0 || k.dtask.kcaller == k.ipc().task;
    let mut rights = Vec::with_capacity(tids.len());
    for t in tids {
        let p = match f {
            flavor::CONTROL if own => {
                let p = k.darwin_thread_ports(t).1;
                k.ipc().make_send(p);
                p
            }
            flavor::CONTROL if !super::kobject::DEVELOPER_MODE || !k.darwin_read_conversion_ok() => {
                rights.push((None, super::ipc::PORT_DEAD));
                continue;
            }
            flavor::CONTROL => {
                let p = k.darwin_thread_ports(t).0;
                k.ipc().make_send(p);
                p
            }
            f => k.darwin_thread_flavor_port(t, f),
        };
        rights.push((Some(Carried::Port(p)), 0));
    }
    let count = rights.len() as u32;
    let mut out = NDR_RECORD.to_vec();
    out.extend_from_slice(&count.to_le_bytes());
    let mut r = Reply::ok(out);
    r.ports.push(PortOut::Array(rights, super::ipc::right::msgt::PORT_SEND));
    r
}

/// `thread_get_special_port_from_user` and
/// `thread_get_special_port_internal` for thread `t`'s port of flavor `f`
/// (`special_port_allowed_with_thread_flavor`).
fn thread_get_special_port(k: &mut Kernel, t: i32, which: i32, f: u8) -> Reply {
    use super::kobject::flavor;
    const KERN_INVALID_CAPABILITY: i32 = 20;
    const THREAD_KERNEL_PORT: i32 = 1;
    const THREAD_INSPECT_PORT: i32 = 2;
    const THREAD_READ_PORT: i32 = 3;
    if !k.darwin_thread_alive(t) {
        return Reply::err(KERN_INVALID_ARGUMENT);
    }
    let own = k.dtask.kcaller == 0 || k.dtask.kcaller == k.ipc().task;
    if which == THREAD_KERNEL_PORT && own {
        // mac_task_check_get_movable_control_port (AMFI's policy), then for
        // a control port a movable send-once substitute of it
        // (ipc_kobject_alloc_subst_once); a read or inspect port goes on to
        // the flavor check.
        let mut r = Reply::err(KERN_FAILURE);
        r.unimplemented = Some("thread_get_special_port(THREAD_KERNEL_PORT) of the task's own thread (the movable control port policy and IKOT_PORT_SUBST_ONCE)".into());
        return r;
    }
    let allowed = match f {
        flavor::CONTROL => true,
        flavor::READ => matches!(which, THREAD_READ_PORT | THREAD_INSPECT_PORT),
        _ => which == THREAD_INSPECT_PORT,
    };
    if !allowed {
        return Reply::err(KERN_INVALID_CAPABILITY);
    }
    match which {
        // ipc_kobject_copy_send of the control port (no CONFIG_CSR).
        THREAD_KERNEL_PORT => {
            let p = k.darwin_thread_ports(t).0;
            k.ipc().copy_send(p);
            Reply::port(Carried::Port(p))
        }
        THREAD_READ_PORT | THREAD_INSPECT_PORT => {
            let p = k.darwin_thread_flavor_port(t, if which == THREAD_READ_PORT { flavor::READ } else { flavor::INSPECT });
            Reply::port(Carried::Port(p))
        }
        _ => Reply::err(KERN_INVALID_ARGUMENT),
    }
}

/// `task_get_special_port_internal` for a port of flavor `f`
/// (`special_port_allowed_with_task_flavor`).
fn task_get_special_port(k: &mut Kernel, which: i32, f: u8) -> Reply {
    use super::kobject::flavor;
    const KERN_INVALID_CAPABILITY: i32 = 20;
    const TASK_KERNEL_PORT: i32 = 1;
    const TASK_HOST_PORT: i32 = 2;
    const TASK_NAME_PORT: i32 = 3;
    const TASK_BOOTSTRAP_PORT: i32 = 4;
    const TASK_INSPECT_PORT: i32 = 5;
    const TASK_READ_PORT: i32 = 6;
    const TASK_ACCESS_PORT: i32 = 9;
    const TASK_DEBUG_CONTROL_PORT: i32 = 10;
    const TASK_RESOURCE_NOTIFY_PORT: i32 = 11;
    let allowed = match f {
        flavor::CONTROL => true,
        flavor::READ => matches!(which, TASK_READ_PORT | TASK_INSPECT_PORT | TASK_NAME_PORT),
        _ => matches!(which, TASK_INSPECT_PORT | TASK_NAME_PORT),
    };
    if !allowed {
        return Reply::err(KERN_INVALID_CAPABILITY);
    }
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
        TASK_BOOTSTRAP_PORT | TASK_ACCESS_PORT | TASK_DEBUG_CONTROL_PORT | TASK_RESOURCE_NOTIFY_PORT if k.dtask.kports.special_dead.contains(&which) => {
            Reply { ret: KERN_SUCCESS, defer: None, out: Vec::new(), ports: Vec::new(), unimplemented: None }.with_null_port(super::ipc::PORT_DEAD)
        }
        TASK_BOOTSTRAP_PORT | TASK_ACCESS_PORT | TASK_DEBUG_CONTROL_PORT | TASK_RESOURCE_NOTIFY_PORT => match k.dtask.kports.special.get(&which).copied() {
            Some(p) if k.ipc().port(p).active => {
                k.ipc().copy_send(p);
                Reply::port(Carried::Port(p))
            }
            Some(_) => Reply { ret: KERN_SUCCESS, defer: None, out: Vec::new(), ports: Vec::new(), unimplemented: None }.with_null_port(super::ipc::PORT_DEAD),
            None => Reply { ret: KERN_SUCCESS, defer: None, out: Vec::new(), ports: Vec::new(), unimplemented: None }.with_null_port(0),
        },
        TASK_INSPECT_PORT | TASK_READ_PORT => {
            let p = k.darwin_task_flavor_port(if which == TASK_READ_PORT { flavor::READ } else { flavor::INSPECT });
            Reply::port(Carried::Port(p))
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
        HOST_IO_MAIN_PORT => k.ipc().global_port(Kobject::IoMain),
        _ => {
            // realhost.special: what launchd set.
            match k.ipc().host_special.iter().find(|&&(w, _)| w == id).map(|&(_, p)| p) {
                Some(p) => {
                    k.ipc().copy_send(p);
                    return Reply::port(Carried::Port(p));
                }
                None => return Reply::ok(Vec::new()).with_null_port(0),
            }
        }
    };
    k.ipc().copy_send(p);
    Reply::port(Carried::Port(p))
}

/// `host_set_special_port_from_user`, then `host_set_special_port`: a user
/// port, not an immovable right, and only launchd may. Its Sandbox check is
/// no check for launchd, which has no profile.
fn host_set_special_port(k: &mut Kernel, obj: &Kobject, _port: super::ipc::ObjId, id: i32, right: Option<Carried>) -> Reply {
    const HOST_MAX_SPECIAL_KERNEL_PORT: i32 = 7;
    const HOST_MAX_SPECIAL_PORT: i32 = 7 + 27;
    const KERN_NO_ACCESS: i32 = 8;
    const KERN_INVALID_RIGHT: i32 = 17;
    let port = match right {
        Some(Carried::Port(p)) => Some(p),
        _ => None,
    };
    if !matches!(obj, Kobject::HostPriv) || id <= HOST_MAX_SPECIAL_KERNEL_PORT || id > HOST_MAX_SPECIAL_PORT {
        return Reply::err(KERN_INVALID_ARGUMENT);
    }
    if let Some(p) = port {
        let port = k.ipc().port(p);
        if port.immovable_receive || port.immovable_send {
            return Reply::err(KERN_INVALID_RIGHT);
        }
    }
    if k.pid != crate::proc::INIT_PID {
        return Reply::err(KERN_NO_ACCESS);
    }
    let ipc = k.ipc();
    let old = ipc.host_special.iter().position(|&(w, _)| w == id).map(|i| ipc.host_special.remove(i).1);
    if let Some(p) = port {
        ipc.host_special.push((id, p));
    }
    if let Some(p) = old {
        ipc.release_send(p);
    }
    Reply::ok(Vec::new())
}

/// `task_set_special_port`: KERNEL and HOST are refused (no CSR on iOS);
/// the rest replace what was set, the old send right released.
fn task_set_special_port(k: &mut Kernel, which: i32, right: Option<Carried>) -> Reply {
    let port = match right {
        Some(Carried::Port(p)) => Some(p),
        _ => None,
    };
    let dead = matches!(right, Some(Carried::Dead));
    let mut kports = std::mem::take(&mut k.dtask.kports);
    let r = set_special_port(&mut kports, k.ipc(), which, port, dead);
    k.dtask.kports = kports;
    Reply::err(r)
}

/// `task_set_special_port` (the kernel's, which `posix_spawn`'s port
/// actions call too) on the task whose ports are `kports`: the send right
/// `port` (or `IP_DEAD`, when `dead`) stored as its special port `which`,
/// the old one released.
pub(crate) fn set_special_port(kports: &mut super::kobject::Kports, ipc: &mut super::ipc::Ipc, which: i32, port: Option<super::ipc::ObjId>, dead: bool) -> i32 {
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
            // Never overwritten once set, even after its port dies
            // (IP_VALID of the right kept).
            if which == TASK_ACCESS_PORT && kports.special.contains_key(&which) {
                return KERN_NO_ACCESS;
            }
            let old = match port {
                Some(p) => kports.special.insert(which, p),
                None => kports.special.remove(&which),
            };
            if dead {
                kports.special_dead.insert(which);
            } else {
                kports.special_dead.remove(&which);
            }
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

/// `MIG_TYPE_ERROR`: a descriptor of the wrong kind or disposition.
const MIG_TYPE_ERROR: i32 = -300;

/// The task port `right` names, when it is the calling task's own (its
/// control port or its self port): what `convert_port_to_task` and the
/// routines' `owningTask == current_task()` checks take.
fn is_own_task(k: &mut Kernel, right: Option<Carried>) -> bool {
    let Some(Carried::Port(p)) = right else { return false };
    let (task, me) = (k.darwin_task_port(), k.darwin_task_self_port());
    p == task || p == me
}

/// `is_io_service_open_extended`: the caller's own task must own the
/// client, and properties are not taken (kIOReturnUnsupported). A user
/// client is made by the service's newUserClient; its failure is the
/// `result` beside a null connection.
fn io_service_open(k: &mut Kernel, req: &Kmsg, service: u32) -> Reply {
    use super::iokit::ret;
    if super::iokit::conforms(super::iokit::tree(), service, "IOService") != Ok(true) {
        return Reply::err(ret::BAD_ARGUMENT);
    }
    // owningTask's port descriptor (12 bytes) and properties' out-of-line
    // one (16), then the NDR record and connect_type.
    let (Some((task, task_disp)), Some(super::ipc::msg::Desc::Ool { data, .. })) = (desc_port(req, 0), req.descs.get(1)) else {
        return Reply::err(MIG_BAD_ARGUMENTS);
    };
    let Some(ty) = i32_at(&req.body, 4 + 12 + 16 + NDR) else { return Reply::err(MIG_BAD_ARGUMENTS) };
    if !is_own_task(k, task) {
        return Reply::err(ret::BAD_ARGUMENT);
    }
    if !data.is_empty() {
        return Reply::err(ret::UNSUPPORTED);
    }
    // The task right was converted to the task, and is let go.
    if let Some(t) = task {
        k.ipc().object_destroy(t, task_disp);
    }
    let result = match super::iokit::open_user_client(k, service, ty as u32) {
        Ok(id) => {
            let port = k.ipc().kobject_port(Kobject::IoConnect(id));
            k.ipc().port_mut(port).owner = 0;
            k.ipc().make_send(port);
            k.ipc().port_mut(port).nsrequest_kobject = true;
            let mut r = Reply::port(Carried::Port(port));
            r.out = NDR_RECORD.to_vec();
            r.out.extend_from_slice(&0i32.to_le_bytes());
            return r;
        }
        Err(e) => e,
    };
    let mut r = Reply { ret: KERN_SUCCESS, defer: None, out: NDR_RECORD.to_vec(), ports: Vec::new(), unimplemented: None }.with_null_port(0);
    r.out.extend_from_slice(&result.to_le_bytes());
    r
}

/// The arguments of io_connect_method, io_connect_async_method and
/// io_connect_method_var_output from their variable-sized request: the
/// fixed part (`fixed`, header included) before the scalars, their count
/// (at most 16), the inband input (at most 4096, word aligned) and the
/// fields after it, checked against the message's size as MIG checks it.
/// `None`: MIG_BAD_ARGUMENTS.
fn method_args(req: &Kmsg, at: usize, fixed: u32, tail: usize) -> Option<(super::iokit::MethodArgs, usize)> {
    let b = &req.body;
    let selector = i32_at(b, at)? as u32;
    let nscalar = i32_at(b, at + 4)? as u32;
    if nscalar > 16 || req.size < fixed + 8 * nscalar {
        return None;
    }
    let scalars = (0..nscalar as usize).map(|n| u64::from_le_bytes(b[at + 8 + 8 * n..at + 16 + 8 * n].try_into().unwrap())).collect::<Vec<u64>>();
    let at = at + 8 + 8 * nscalar as usize;
    let ninband = i32_at(b, at)? as u32;
    let padded = (ninband + 3) & !3;
    if ninband > 4096 || req.size != fixed + 8 * nscalar + padded {
        return None;
    }
    let inband = b.get(at + 4..at + 4 + ninband as usize)?.to_vec();
    let rest = at + 4 + padded as usize;
    b.get(rest..rest + tail)?;
    Some((super::iokit::MethodArgs { selector, scalar_in: scalars, struct_in: inband, ..Default::default() }, rest))
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// The reply of a method that ran: the inband output (its count, the
/// bytes padded), the scalar output (count, values), then
/// `ool_output_size`.
fn method_reply(a: &super::iokit::MethodArgs, ool_size: Option<u64>) -> Reply {
    let mut o = (a.struct_out.len() as u32).to_le_bytes().to_vec();
    o.extend_from_slice(&a.struct_out);
    o.resize((o.len() + 3) & !3, 0);
    o.extend_from_slice(&(a.scalar_out.len() as u32).to_le_bytes());
    for s in &a.scalar_out {
        o.extend_from_slice(&s.to_le_bytes());
    }
    if let Some(n) = ool_size {
        o.extend_from_slice(&n.to_le_bytes());
    }
    Reply::ok(o)
}

/// A routine sent to user client `id`.
fn connect_routine(k: &mut Kernel, req: &Kmsg, id: u32, n: i32) -> Reply {
    use super::iokit::ret;
    let bad = || Reply::err(MIG_BAD_ARGUMENTS);
    let Some(cell) = super::iokit::client(id) else {
        // A connection whose client is gone converts to none (CHECK).
        return Reply::err(ret::BAD_ARGUMENT);
    };
    let mut c = cell.lock().unwrap_or_else(|e| e.into_inner());
    let r = match n {
        // io_object_get_class, io_object_conforms_to, io_registry_entry_get_name
        // and _get_registry_entry_id: the client is a registry entry, named
        // by its class.
        2800 | 2810 => Reply::ok(io_name_reply(c.class)),
        2801 => match inline_cstr(req, 0, 128) {
            Some((name, _)) => {
                let chain = super::iokit::superclasses(c.class);
                if chain.is_empty() {
                    let mut r = Reply::err(ret::UNSUPPORTED);
                    r.unimplemented = Some(format!("the superclasses of the user client class {}", c.class));
                    r
                } else {
                    Reply::ok(u32::from(chain.contains(&String::from_utf8_lossy(name).as_ref())).to_le_bytes().to_vec())
                }
            }
            None => bad(),
        },
        2871 => Reply::ok(c.id.to_le_bytes().to_vec()),
        // io_registry_entry_get_property_bytes.
        2812 => match inline_cstr(req, 0, 128) {
            Some((name, next)) => {
                let Some(cnt) = i32_at(&req.body, next) else { return bad() };
                match super::iokit::client_property(&c, &String::from_utf8_lossy(name)).map(|p| p.map(|p| super::iokit::prop_bytes(&p))) {
                    Err(what) => {
                        let mut r = Reply::err(ret::NO_RESOURCES);
                        r.unimplemented = Some(what);
                        r
                    }
                    Ok(None) => Reply::err(ret::NO_RESOURCES),
                    Ok(Some(p)) => match p {
                        None => Reply::err(ret::BAD_ARGUMENT),
                        Some(v) if (cnt as u32 as usize).min(super::iokit::STRUCT_INBAND_MAX) < v.len() => Reply::err(ret::IPC_ERROR),
                        Some(v) => {
                            let mut o = (v.len() as u32).to_le_bytes().to_vec();
                            o.extend_from_slice(&v);
                            o.resize((o.len() + 3) & !3, 0);
                            Reply::ok(o)
                        }
                    },
                }
            }
            None => bad(),
        },
        // io_registry_entry_get_property_bin_buf.
        2889 => client_property_bin_buf(k, req, &c),
        // io_service_close: clientClose, once (a shared instance aside);
        // a second close is ignored. Always kIOReturnSuccess.
        2816 => {
            if !c.closed {
                c.closed = true;
                super::iokit::client_close(k, &mut c);
            }
            Reply::ok(Vec::new())
        }
        // io_connect_get_service: getService, which IOUserClient answers
        // with none (kIOReturnUnsupported) unless the client says.
        2817 => match super::iokit::client_service(&c) {
            Some(s) => {
                let port = k.ipc().global_port(Kobject::IoEntry(s));
                k.ipc().copy_send(port);
                Reply::port(Carried::Port(port))
            }
            None => Reply::err(ret::UNSUPPORTED),
        },
        // io_connect_add_client(connection, connect_to): IOUserClient's
        // connectClient takes none (kIOReturnUnsupported); a connect_to that
        // is no user client is kIOReturnBadArgument.
        2820 => match desc_port(req, 0) {
            Some((right, disp)) => {
                let to = match right {
                    Some(Carried::Port(p)) => matches!(k.ipc().port(p).kobject, Some(Kobject::IoConnect(_))),
                    _ => false,
                };
                if to {
                    if let Some(r) = right {
                        k.ipc().object_destroy(r, disp);
                    }
                    Reply::err(ret::UNSUPPORTED)
                } else {
                    Reply::err(ret::BAD_ARGUMENT)
                }
            }
            None => bad(),
        },
        // io_connect_set_properties: is_io_registry_entry_set_properties,
        // which unserializes the properties (OSUnserializeXML) before the
        // client's setProperties sees them.
        2821 => {
            let mut r = Reply::err(ret::UNSUPPORTED);
            r.unimplemented = Some(format!("io_connect_set_properties on {} (OSUnserializeXML of the properties)", c.class));
            r
        }
        // io_connect_get_notification_semaphore: IOUserClient's default.
        2852 => Reply::err(ret::UNSUPPORTED),
        // io_connect_map_memory_into_task(connection, memory_type, into_task,
        // address, size, flags) and io_connect_unmap_memory_from_task
        // (connection, memory_type, from_task, address): the client's
        // clientMemoryForType for the type. A client with none maps nothing
        // (kIOReturnBadArgument) and unmaps with clientMemoryForType's
        // error. The task must be one (any task's control port).
        2863 | 2864 => {
            let Some((task, _)) = desc_port(req, 0) else { return bad() };
            let Some(ty) = i32_at(&req.body, 4 + 12 + NDR) else { return bad() };
            let is_task = match task {
                Some(Carried::Port(p)) => k.ipc().port(p).kobject == Some(Kobject::Task),
                _ => false,
            };
            if !is_task {
                Reply::err(ret::BAD_ARGUMENT)
            } else {
                match super::iokit::client_memory_for_type(k, &mut c, ty as u32) {
                    Ok(never) => match never {},
                    Err(e) => Reply::err(if n == 2863 { ret::BAD_ARGUMENT } else { e }),
                }
            }
        }
        // io_connect_method and io_connect_method_var_output.
        2865 | 2872 => {
            // The fixed part: header, NDR, selector, the two counts, then
            // ool_input and its size, the two output counts, and for
            // io_connect_method ool_output and its size.
            let tail = if n == 2865 { 8 + 8 + 4 + 4 + 8 + 8 } else { 8 + 8 + 4 + 4 };
            let fixed = (HEADER + NDR + 4 + 4 + 4 + tail) as u32;
            if req.bits & super::ipc::msg::bits::COMPLEX != 0 {
                return bad();
            }
            match method_args(req, NDR, fixed, tail) {
                Some((a, at)) => connect_method(k, &mut c, a, &req.body[at..], n == 2865),
                None => bad(),
            }
        }
        // io_connect_async_method(connection, wake_port, reference, ...).
        2866 => {
            if req.bits & super::ipc::msg::bits::COMPLEX == 0 || req.descs.len() != 1 {
                return bad();
            }
            let Some((wake, disp)) = desc_port(req, 0) else { return Reply::err(MIG_TYPE_ERROR) };
            if disp != super::ipc::right::msgt::PORT_SEND {
                return Reply::err(MIG_TYPE_ERROR);
            }
            let at = 4 + 12 + NDR;
            let Some(nref) = i32_at(&req.body, at) else { return bad() };
            let nref = nref as u32;
            let tail = 8 + 8 + 4 + 4 + 8 + 8;
            let fixed = (HEADER + 4 + 12 + NDR + 4 + 4 + 4 + 4 + tail) as u32;
            if nref > 8 || req.size < fixed + 8 * nref {
                return bad();
            }
            let refs: Vec<u64> = (0..nref as usize).map(|i| u64_at(&req.body, at + 4 + 8 * i)).collect();
            let fixed = fixed + 8 * nref;
            match method_args(req, at + 4 + 8 * nref as usize, fixed, tail) {
                Some((mut a, rest)) => {
                    // referenceCnt < 1: kIOReturnBadArgument.
                    if refs.is_empty() {
                        Reply::err(ret::BAD_ARGUMENT)
                    } else {
                        a.is_async = true;
                        a.reference = refs;
                        a.wake = match wake {
                            Some(Carried::Port(p)) => Some(p),
                            _ => None,
                        };
                        connect_method(k, &mut c, a, &req.body[rest..], true)
                    }
                }
                None => bad(),
            }
        }
        // io_connect_set_notification_port(connection, notification_type,
        // port, reference): registerNotificationPort. The client keeps the
        // port's right when it succeeds; a failed request's goes with it.
        2867 => {
            let Some((port, _)) = desc_port(req, 0) else { return bad() };
            let at = 4 + 12 + NDR;
            let (Some(ty), Some(reference)) = (i32_at(&req.body, at), req.body.get(at + 4..at + 12).map(|s| u64::from_le_bytes(s.try_into().unwrap()))) else {
                return bad();
            };
            let p = match port {
                Some(Carried::Port(p)) => Some(p),
                _ => None,
            };
            Reply::err(super::iokit::register_notification_port(k, &mut c, p, ty as u32, reference))
        }
        _ => unreachable!(),
    };
    r
}

/// is_io_connect_method's argument checks, the client's externalMethod,
/// and its reply. `tail`: the request's fields after the inband input.
fn connect_method(k: &mut Kernel, c: &mut super::iokit::UserClient, mut a: super::iokit::MethodArgs, tail: &[u8], ool_out_field: bool) -> Reply {
    use super::iokit::ret;
    let (ool_in, ool_in_size) = (u64_at(tail, 0), u64_at(tail, 8));
    let inband_out = (i32_at(tail, 16).unwrap_or(0) as u32).min(4096);
    let scalar_out = (i32_at(tail, 20).unwrap_or(0) as u32).min(16);
    let (ool_out, ool_out_size) = if ool_out_field { (u64_at(tail, 24), u64_at(tail, 32)) } else { (0, 0) };
    if ool_in != 0 && ool_in_size <= super::iokit::STRUCT_INBAND_MAX as u64 {
        return Reply::err(ret::IPC_ERROR);
    }
    if ool_out != 0 && (ool_out_size <= super::iokit::STRUCT_INBAND_MAX as u64 || ool_out_size > u64::from(u32::MAX)) {
        return Reply::err(ret::IPC_ERROR);
    }
    if ool_in != 0 {
        a.ool_in = Some((ool_in, ool_in_size));
    }
    if ool_out != 0 {
        a.ool_out = Some((ool_out, ool_out_size));
    }
    a.scalar_out = vec![0; scalar_out as usize];
    a.struct_out = vec![0; inband_out as usize];
    // The wake port's right is the routine's once it succeeds: a client
    // keeps it in its async reference (and lets it go with
    // releaseAsyncReference64); a failed request's goes with the request.
    let r = super::iokit::external_method(k, c, &mut a);
    if r != ret::SUCCESS {
        return Reply::err(r);
    }
    if !ool_out_field {
        // io_connect_method_var_output: no client here gives variable
        // output, which is kIOReturnUnderrun.
        return Reply::err(ret::UNDERRUN);
    }
    method_reply(&a, Some(a.ool_out.map_or(0, |(_, n)| n)))
}

/// io_registry_entry_get_property_bin_buf of a user client's property.
fn client_property_bin_buf(k: &mut Kernel, req: &Kmsg, c: &super::iokit::UserClient) -> Reply {
    let Some((_, next)) = inline_cstr(req, 0, 128) else { return Reply::err(MIG_BAD_ARGUMENTS) };
    let Some((name, next)) = inline_cstr_at(req, next, 128) else { return Reply::err(MIG_BAD_ARGUMENTS) };
    let (Some(_options), Some(buf), Some(bufsize)) = (i32_at(&req.body, next), req.body.get(next + 4..next + 12), req.body.get(next + 12..next + 20)) else { return Reply::err(MIG_BAD_ARGUMENTS) };
    let (buf, bufsize) = (u64::from_le_bytes(buf.try_into().unwrap()), u64::from_le_bytes(bufsize.try_into().unwrap()));
    let p = match super::iokit::client_property(c, &String::from_utf8_lossy(name)) {
        Ok(Some(p)) => p,
        Ok(None) => return Reply::err(super::iokit::ret::NOT_FOUND),
        Err(what) => {
            let mut r = Reply::err(super::iokit::ret::NOT_FOUND);
            r.unimplemented = Some(what);
            return r;
        }
    };
    let bin = super::iokit::serialize_prop(&p);
    let mut out = NDR_RECORD.to_vec();
    if buf != 0 && bin.len() as u64 <= bufsize {
        if let Err(r) = k.darwin_vm_copy_overwrite(buf, &bin) {
            return r;
        }
        out.extend_from_slice(&(bin.len() as u64).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        let mut r = Reply::ok(out);
        r.ports.push(PortOut::Ool(Vec::new()));
        r
    } else {
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&(bin.len() as u32).to_le_bytes());
        let mut r = Reply::ok(out);
        r.ports.push(PortOut::Ool(bin));
        r
    }
}
