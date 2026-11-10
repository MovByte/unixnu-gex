//! Work intervals (`bsd/kern/sys_work_interval.c`,
//! `osfmk/kern/work_interval.c`, xnu-10063.141.1).
//!
//! A work interval is created by a thread, which joins it at once unless
//! it is joinable, when a send right to its port is what other threads join
//! it by. The iPhoneOS kernel has thread groups but neither
//! CONFIG_SCHED_AUTO_JOIN nor CONFIG_SCHED_RT_ALLOW, and no workload
//! configuration is loaded here (`kern.workload_config`), so a workload ID
//! is taken as `workload_config_available` false takes it. What a thread
//! group and a notification tell the performance controller has no effect
//! here; nothing a program sees depends on it.

use super::bsd::sys;
use super::ipc::Kobject;
use crate::errno::Errno;
use crate::syscalls::Kernel;
use crate::GuestMem;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// `WORK_INTERVAL_OPERATION_*`.
mod op {
    pub const CREATE: u32 = 0x1;
    pub const DESTROY: u32 = 0x2;
    pub const NOTIFY: u32 = 0x3;
    pub const CREATE2: u32 = 0x4;
    pub const JOIN: u32 = 0x5;
    pub const GET_FLAGS: u32 = 0x9;
    pub const SET_NAME: u32 = 0xa;
    pub const SET_WORKLOAD_ID: u32 = 0xb;
}

/// `WORK_INTERVAL_FLAG_*` and `WORK_INTERVAL_TYPE_*`.
mod flag {
    pub const JOINABLE: u32 = 0x1;
    pub const GROUP: u32 = 0x2;
    pub const HAS_WORKLOAD_ID: u32 = 0x80;
    pub const TYPE_MASK: u32 = 0xf000_0000;
    pub const TYPE_DEFAULT: u32 = 0x0 << 28;
    pub const TYPE_COREAUDIO: u32 = 0x1 << 28;
    pub const TYPE_CA_CLIENT: u32 = 0x3 << 28;
}

/// `WORK_INTERVAL_WORKLOAD_ID_*`.
mod wlid {
    pub const HAS_ID: u32 = 1 << 0;
    pub const RT_ALLOWED: u32 = 1 << 1;
    pub const ALREADY_JOINED: u32 = 1 << 31;
}

/// `TH_WORK_INTERVAL_FLAGS_*`: what a thread keeps of its interval's
/// workload ID.
pub mod thflag {
    pub const HAS_WORKLOAD_ID: u32 = 0x2;
    pub const RT_ALLOWED: u32 = 0x4;
}

/// WORK_INTERVAL_NAME_MAX, WORK_INTERVAL_WORKLOAD_ID_NAME_MAX.
const NAME_MAX: usize = 32;
const WORKLOAD_ID_NAME_MAX: usize = 64;
/// `sizeof(struct work_interval_create_params)`,
/// `sizeof(struct work_interval_notification)`,
/// `sizeof(struct work_interval_workload_id_params)`.
const CREATE_PARAMS_SIZE: u64 = 16;
const NOTIFICATION_SIZE: u64 = 40;
const WORKLOAD_ID_PARAMS_SIZE: u64 = 32;

/// `KERN_FAILURE`, `KERN_RESOURCE_SHORTAGE`, `KERN_INVALID_ARGUMENT`,
/// `KERN_NOT_SUPPORTED`, `KERN_INVALID_NAME`, `KERN_INVALID_CAPABILITY`.
mod kr {
    pub const FAILURE: u64 = 5;
    pub const RESOURCE_SHORTAGE: u64 = 6;
    pub const INVALID_ARGUMENT: u64 = 4;
    pub const NOT_SUPPORTED: u64 = 46;
    pub const INVALID_NAME: u64 = 15;
    pub const INVALID_CAPABILITY: u64 = 20;
}

/// The entitlement PRIV_WORK_INTERVAL is granted by (`sys/work_interval.h`).
const ENTITLEMENT: &str = "com.apple.private.kernel.work-interval";

/// `struct work_interval`.
#[derive(Debug)]
pub struct WorkInterval {
    pub id: u64,
    create_flags: u32,
    creator_uniqueid: u64,
    creator_pidversion: i32,
    /// Whether `wi_group` is there: not while a group's creation waits for
    /// the workload ID.
    group: AtomicBool,
    /// WORK_INTERVAL_GROUP_FLAGS_THREAD_JOINED.
    thread_joined: AtomicBool,
    wlid_flags: AtomicU32,
}

/// `unique_work_interval_id`: 0 names no interval, and the first is 2
/// (`os_atomic_inc` gives the new value).
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// The intervals the joinable ones' ports hold, by id. One stays for as
/// long as its port has a send right.
fn ported() -> &'static Mutex<HashMap<u64, Arc<WorkInterval>>> {
    static PORTED: OnceLock<Mutex<HashMap<u64, Arc<WorkInterval>>>> = OnceLock::new();
    PORTED.get_or_init(Default::default)
}

/// `work_interval_port_no_senders`: the port's reference goes.
pub fn work_interval_no_senders(id: u64) {
    ported().lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
}

impl Kernel {
    /// `port_name_to_work_interval`.
    pub(crate) fn darwin_port_work_interval(&mut self, name: u32) -> Result<Arc<WorkInterval>, u64> {
        if !super::ipc::name_valid(name) {
            return Err(kr::INVALID_NAME);
        }
        let ipc = &mut self.ipc();
        let port = ipc.translate_send(name)?;
        let Some(Kobject::WorkInterval(id)) = ipc.port(port).kobject else { return Err(kr::INVALID_CAPABILITY) };
        ported().lock().unwrap_or_else(|e| e.into_inner()).get(&id).cloned().ok_or(kr::INVALID_CAPABILITY)
    }

    /// The calling thread's interval.
    fn darwin_thread_work_interval(&mut self) -> Option<Arc<WorkInterval>> {
        self.dtask.threads.map.get(&self.tid).and_then(|t| t.work_interval.clone())
    }

    /// Whether the calling thread is in TH_MODE_REALTIME (or was, and is
    /// demoted from it: `saved_mode`).
    fn darwin_thread_realtime(&mut self) -> bool {
        self.dtask.threads.map.get(&self.tid).is_some_and(|t| t.realtime.is_some())
    }

    /// `thread_set_work_interval` with THREAD_WI_EXPLICIT_JOIN_POLICY, the
    /// calling thread's: a deferred group, or a Core Audio interval for a
    /// thread that is not realtime, refused.
    fn darwin_set_work_interval(&mut self, wi: Option<Arc<WorkInterval>>) -> Result<(), u64> {
        if let Some(w) = &wi {
            if !w.group.load(Ordering::Relaxed) {
                return Err(kr::INVALID_ARGUMENT);
            }
            let mut ty = w.create_flags & flag::TYPE_MASK;
            // No workload ID can be set after a thread has joined.
            let before = match w.wlid_flags.compare_exchange(0, wlid::ALREADY_JOINED, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(v) | Err(v) => v,
            };
            if before & wlid::RT_ALLOWED != 0 {
                ty = flag::TYPE_DEFAULT;
            }
            if ty == flag::TYPE_COREAUDIO && !self.darwin_thread_realtime() {
                return Err(kr::INVALID_ARGUMENT);
            }
            w.thread_joined.store(true, Ordering::Relaxed);
        }
        let wl = wi.as_ref().map_or(0, |w| w.wlid_flags.load(Ordering::Relaxed));
        let t = self.dtask.threads.map.entry(self.tid).or_default();
        t.work_interval = wi;
        t.wi_flags &= !(thflag::HAS_WORKLOAD_ID | thflag::RT_ALLOWED);
        if wl & wlid::HAS_ID != 0 {
            t.wi_flags |= thflag::HAS_WORKLOAD_ID;
            if wl & wlid::RT_ALLOWED != 0 {
                t.wi_flags |= thflag::RT_ALLOWED;
            }
        }
        Ok(())
    }

    /// `kern_work_interval_create`.
    fn darwin_work_interval_create(&mut self, create_flags: u32) -> Result<(u64, u32), u64> {
        let joinable = create_flags & flag::JOINABLE != 0;
        if !joinable && self.darwin_thread_work_interval().is_some() {
            return Err(kr::FAILURE);
        }
        if create_flags & flag::TYPE_MASK == flag::TYPE_CA_CLIENT {
            if create_flags & flag::GROUP != 0 {
                return Err(kr::FAILURE);
            }
            // On iOS an application type is a hard requirement.
            if !self.darwin_policy().is_app() {
                return Err(kr::NOT_SUPPORTED);
            }
            // task_set_ca_client_wi: one for each task, for good.
            if std::mem::replace(&mut self.dtask.ca_client_wi, true) {
                return Err(kr::FAILURE);
            }
        }
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed) + 1;
        // A group whose flags wait for the workload ID is made then.
        let deferred = create_flags & (flag::GROUP | flag::HAS_WORKLOAD_ID) == flag::GROUP | flag::HAS_WORKLOAD_ID;
        let wi = Arc::new(WorkInterval {
            id,
            create_flags,
            creator_uniqueid: self.dtask.uniqueid,
            creator_pidversion: self.dtask.pidversion,
            group: AtomicBool::new(!deferred),
            thread_joined: AtomicBool::new(false),
            wlid_flags: AtomicU32::new(0),
        });
        if joinable {
            ported().lock().unwrap_or_else(|e| e.into_inner()).insert(id, wi);
            let ipc = &mut self.ipc();
            let port = ipc.kobject_port(Kobject::WorkInterval(id));
            ipc.make_send(port);
            ipc.port_mut(port).nsrequest_kobject = true;
            let name = self.darwin_copyout_send(port);
            if !super::ipc::name_valid(name) {
                return Err(kr::RESOURCE_SHORTAGE);
            }
            Ok((id, name))
        } else {
            self.darwin_set_work_interval(Some(wi))?;
            Ok((id, 0))
        }
    }

    /// `kern_work_interval_destroy`: the calling thread leaves the interval
    /// it is in, if that is `id`.
    fn darwin_work_interval_destroy(&mut self, id: u64) -> Result<(), u64> {
        if id == 0 || self.darwin_thread_work_interval().is_none_or(|w| w.id != id) {
            return Err(kr::INVALID_ARGUMENT);
        }
        self.darwin_set_work_interval(None)
    }

    /// `kern_work_interval_set_workload_id`, with no workload configuration
    /// loaded: the type the caller says must be the interval's, real-time is
    /// allowed, and a deferred group is made. A second call asks what the
    /// first set.
    fn darwin_work_interval_set_workload_id(&mut self, name: u32, wl_name: &[u8], flags_in: u32, wicreate_flags: u32) -> Result<(u32, u32), u64> {
        if wl_name.is_empty() {
            return Err(kr::INVALID_ARGUMENT);
        }
        let w = self.darwin_port_work_interval(name)?;
        if w.create_flags & flag::JOINABLE == 0 || w.create_flags & flag::HAS_WORKLOAD_ID == 0 {
            return Err(kr::INVALID_ARGUMENT);
        }
        // workload_config_lookup_default finds nothing.
        if wicreate_flags & flag::TYPE_MASK != w.create_flags & flag::TYPE_MASK {
            return Err(kr::INVALID_ARGUMENT);
        }
        let set = wlid::RT_ALLOWED | wlid::HAS_ID;
        match w.wlid_flags.compare_exchange(0, set, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => {
                if w.create_flags & flag::GROUP != 0 {
                    w.group.store(true, Ordering::Relaxed);
                }
                Ok((flags_in, w.create_flags))
            }
            Err(had) if had & wlid::ALREADY_JOINED != 0 => Err(kr::INVALID_ARGUMENT),
            Err(had) => Ok((had, w.create_flags)),
        }
    }

    /// `work_interval_ctl(operation, work_interval_id, arg, len)`.
    fn darwin_work_interval_ctl(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        let (operation, wi_id, arg, len) = (a[0] as u32, a[1], a[2], a[3]);
        let port_name = wi_id as u32;
        match operation {
            op::CREATE => Err(Errno::EOPNOTSUPP),
            op::CREATE2 => {
                if arg == 0 || wi_id != 0 || len < CREATE_PARAMS_SIZE {
                    return Err(Errno::EINVAL);
                }
                let p = m.read(arg, CREATE_PARAMS_SIZE as usize)?;
                let create_flags = u32::from_le_bytes(p[12..16].try_into().unwrap());
                // priv_check_cred(PRIV_WORK_INTERVAL): root, or the
                // entitlement.
                let entitled = self.dtask.codesign.as_ref().is_some_and(|c| c.entitled(ENTITLEMENT));
                if self.creds.uid() != 0 && !entitled {
                    return Err(Errno::EPERM);
                }
                let (id, port) = match self.darwin_work_interval_create(create_flags) {
                    Ok(v) => v,
                    Err(kr::FAILURE) => return Err(Errno::EALREADY),
                    Err(kr::RESOURCE_SHORTAGE) => return Err(Errno::ENOMEM),
                    Err(_) => return Err(Errno::EINVAL),
                };
                let mut out = [0u8; CREATE_PARAMS_SIZE as usize];
                out[0..8].copy_from_slice(&id.to_le_bytes());
                out[8..12].copy_from_slice(&port.to_le_bytes());
                out[12..16].copy_from_slice(&create_flags.to_le_bytes());
                if m.write(arg, &out).is_err() {
                    let _ = self.darwin_work_interval_destroy(id);
                    return Err(Errno::EFAULT);
                }
                Ok(0)
            }
            op::GET_FLAGS => {
                if arg == 0 || len < CREATE_PARAMS_SIZE || !super::ipc::name_valid(port_name) {
                    return Err(Errno::EINVAL);
                }
                let w = self.darwin_port_work_interval(port_name).map_err(|_| Errno::EINVAL)?;
                let mut out = [0u8; CREATE_PARAMS_SIZE as usize];
                out[8..12].copy_from_slice(&port_name.to_le_bytes());
                out[12..16].copy_from_slice(&w.create_flags.to_le_bytes());
                m.write(arg, &out)?;
                Ok(0)
            }
            op::SET_NAME => {
                if arg == 0 || len < NAME_MAX as u64 || !super::ipc::name_valid(port_name) {
                    return Err(Errno::EINVAL);
                }
                let mut b = [0u8; NAME_MAX];
                m.read_cstr_into(arg, &mut b)?.ok_or(Errno::ENAMETOOLONG)?;
                // kern_work_interval_set_name: before any thread has joined,
                // and with a group to name.
                let w = self.darwin_port_work_interval(port_name).map_err(|_| Errno::EINVAL)?;
                if w.thread_joined.load(Ordering::Relaxed) || !w.group.load(Ordering::Relaxed) {
                    return Err(Errno::EINVAL);
                }
                Ok(0)
            }
            op::SET_WORKLOAD_ID => {
                if arg == 0 || len < WORKLOAD_ID_PARAMS_SIZE || !super::ipc::name_valid(port_name) {
                    return Err(Errno::EINVAL);
                }
                let p = m.read(arg, WORKLOAD_ID_PARAMS_SIZE as usize)?.to_vec();
                let u32_ = |o: usize| u32::from_le_bytes(p[o..o + 4].try_into().unwrap());
                let (flags_in, wicreate_flags) = (u32_(0), u32_(4));
                let name_at = u64::from_le_bytes(p[8..16].try_into().unwrap());
                let mut b = [0u8; WORKLOAD_ID_NAME_MAX];
                let n = if name_at != 0 { m.read_cstr_into(name_at, &mut b)?.ok_or(Errno::ENAMETOOLONG)? } else { 0 };
                let (flags_out, create_flags) = self.darwin_work_interval_set_workload_id(port_name, &b[..n], flags_in, wicreate_flags).map_err(|_| Errno::EINVAL)?;
                // The name's address is not written back, and no call is
                // filtered (wlidp_syscall_mask).
                let mut out = [0u8; WORKLOAD_ID_PARAMS_SIZE as usize];
                out[0..4].copy_from_slice(&flags_out.to_le_bytes());
                out[4..8].copy_from_slice(&create_flags.to_le_bytes());
                m.write(arg, &out)?;
                Ok(0)
            }
            op::DESTROY => {
                if arg != 0 || wi_id == 0 {
                    return Err(Errno::EINVAL);
                }
                self.darwin_work_interval_destroy(wi_id).map(|_| 0).map_err(|_| Errno::EINVAL)
            }
            op::NOTIFY => {
                if arg == 0 || wi_id == 0 || len < NOTIFICATION_SIZE {
                    return Err(Errno::EINVAL);
                }
                m.read(arg, NOTIFICATION_SIZE as usize)?;
                // kern_work_interval_notify: by a thread in the interval, of
                // the task that made it.
                let w = self.darwin_thread_work_interval().filter(|w| w.id == wi_id).ok_or(Errno::EINVAL)?;
                if w.creator_uniqueid != self.dtask.uniqueid || w.creator_pidversion != self.dtask.pidversion {
                    return Err(Errno::EINVAL);
                }
                Ok(0)
            }
            op::JOIN => {
                if arg != 0 {
                    return Err(Errno::EINVAL);
                }
                // kern_work_interval_join: a null name leaves.
                let wi = if port_name == 0 { None } else { Some(self.darwin_port_work_interval(port_name).map_err(|_| Errno::EINVAL)?) };
                self.darwin_set_work_interval(wi).map(|_| 0).map_err(|_| Errno::EINVAL)
            }
            _ => Err(Errno::EOPNOTSUPP),
        }
    }

    /// The call, if it is this one.
    pub(crate) fn darwin_work_interval_call(&mut self, m: &mut GuestMem<'_>, raw: u64, a: &[u64; 6]) -> Option<Result<u64, Errno>> {
        (raw == sys::WORK_INTERVAL_CTL).then(|| self.darwin_work_interval_ctl(m, a))
    }
}
