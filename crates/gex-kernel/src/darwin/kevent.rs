//! kqueues and kevent (`bsd/kern/kern_event.c`): knotes registered on a
//! kqueue, activated by their filters, queued by QoS and delivered by
//! `kevent`, `kevent64`, `kevent_qos` and `kevent_id`.
//!
//! A kqueue is one of three kinds: a file kqueue (`kqueue()`), the
//! process's workqueue kqueue, whose events go to workqueue threads bound
//! to the thread request of a QoS bucket, and a workloop, a dynamic kqueue
//! with one thread request and an owner, whose events go to the one thread
//! bound to it. The thread requests are the workqueue's
//! ([`super::workq`]); the filters are in [`super::kfilt`].
//!
//! Everything here runs under the kernel lock, as XNU's kqueue and knote
//! locks would let it: a knote is never seen half-processed. Threads a
//! wakeup owes are woken when the call settles ([`Kernel::darwin_kevent_settle`]).

use super::ipc::ObjId;
use super::thread::pp;
use super::wait::{Wait, WaitResult};
use super::workq::{kflags, qos, tr, ReqId};
use crate::errno::Errno;
use crate::syscalls::{Kernel, SyscallOutcome};
use crate::GuestMem;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub type KqId = u64;
pub type KnId = u64;

/// `EVFILT_*`.
pub mod evfilt {
    pub const READ: i16 = -1;
    pub const WRITE: i16 = -2;
    pub const AIO: i16 = -3;
    pub const VNODE: i16 = -4;
    pub const PROC: i16 = -5;
    pub const SIGNAL: i16 = -6;
    pub const TIMER: i16 = -7;
    pub const MACHPORT: i16 = -8;
    pub const FS: i16 = -9;
    pub const USER: i16 = -10;
    pub const VM: i16 = -12;
    pub const SOCK: i16 = -13;
    pub const MEMORYSTATUS: i16 = -14;
    pub const EXCEPT: i16 = -15;
    pub const NW_CHANNEL: i16 = -16;
    pub const WORKLOOP: i16 = -17;
    pub const EXCLAVES_NOTIFICATION: i16 = -18;
    pub const SYSCOUNT: i16 = 18;
}

/// A knote's filter (`kn_filtid`): `~filter` for the public ones, then the
/// `EVFILTID_*` a filter moves a knote to.
pub mod filtid {
    pub const KQREAD: u8 = 18;
    pub const PIPE_N: u8 = 19;
    pub const PIPE_R: u8 = 20;
    pub const PIPE_W: u8 = 21;
    pub const VN: u8 = 34;
    pub const MACH_PORT: u8 = 37;
    pub const MACH_PORT_SET: u8 = 38;
    pub const DETACHED: u8 = 39;
}

/// `EV_*`.
pub mod ev {
    pub const ADD: u16 = 0x0001;
    pub const DELETE: u16 = 0x0002;
    pub const ENABLE: u16 = 0x0004;
    pub const DISABLE: u16 = 0x0008;
    pub const ONESHOT: u16 = 0x0010;
    pub const CLEAR: u16 = 0x0020;
    pub const RECEIPT: u16 = 0x0040;
    pub const DISPATCH: u16 = 0x0080;
    pub const UDATA_SPECIFIC: u16 = 0x0100;
    pub const DISPATCH2: u16 = DISPATCH | UDATA_SPECIFIC;
    pub const VANISHED: u16 = 0x0200;
    pub const SYSFLAGS: u16 = 0xf000;
    pub const ERROR: u16 = 0x4000;
    pub const EOF: u16 = 0x8000;
}

/// `KEVENT_FLAG_*`.
pub mod kf {
    pub const IMMEDIATE: u32 = 0x000001;
    pub const ERROR_EVENTS: u32 = 0x000002;
    pub const STACK_DATA: u32 = 0x000008;
    pub const POLL: u32 = 0x000010;
    pub const WORKQ: u32 = 0x000020;
    pub const LEGACY32: u32 = 0x000040;
    pub const LEGACY64: u32 = 0x000080;
    pub const PROC64: u32 = 0x000100;
    pub const WORKLOOP: u32 = 0x000400;
    pub const PARKING: u32 = 0x000800;
    pub const KERNEL: u32 = 0x001000;
    pub const DYNAMIC_KQUEUE: u32 = 0x002000;
    pub const NEEDS_END_PROCESSING: u32 = 0x004000;
    pub const DYNAMIC_KQ_MUST_EXIST: u32 = 0x020000;
    pub const DYNAMIC_KQ_MUST_NOT_EXIST: u32 = 0x040000;
    pub const USER: u32 = IMMEDIATE | ERROR_EVENTS | STACK_DATA | WORKQ | WORKLOOP | DYNAMIC_KQ_MUST_EXIST | DYNAMIC_KQ_MUST_NOT_EXIST;
    pub const ID_USER: u32 = WORKLOOP | DYNAMIC_KQ_MUST_EXIST | DYNAMIC_KQ_MUST_NOT_EXIST;
}

/// `KN_*`: a knote's status.
pub mod kn {
    pub const ACTIVE: u32 = 0x001;
    pub const QUEUED: u32 = 0x002;
    pub const DISABLED: u32 = 0x004;
    pub const DROPPING: u32 = 0x008;
    pub const LOCKED: u32 = 0x010;
    pub const POSTING: u32 = 0x020;
    pub const DEFERDELETE: u32 = 0x080;
    pub const MERGE_QOS: u32 = 0x100;
    pub const REQVANISH: u32 = 0x200;
    pub const VANISHED: u32 = 0x400;
    pub const SUPPRESSED: u32 = 0x800;
}

/// `KQ_*`: a kqueue's state.
pub mod kq {
    pub const SLEEP: u16 = 0x0002;
    pub const PROCWAIT: u16 = 0x0004;
    pub const KEV32: u16 = 0x0008;
    pub const KEV64: u16 = 0x0010;
    pub const KEV_QOS: u16 = 0x0020;
    pub const WORKQ: u16 = 0x0040;
    pub const WORKLOOP: u16 = 0x0080;
    pub const PROCESSING: u16 = 0x0100;
    pub const DRAIN: u16 = 0x0200;
    pub const DYNAMIC: u16 = 0x0800;
    pub const R2K_ARMED: u16 = 0x1000;
}

/// `FILTER_*`: what a filter routine answers.
pub mod filter {
    pub const ACTIVE: u32 = 0x0000_0001;
    pub const REGISTER_WAIT: u32 = 0x0000_0002;
    pub const UPDATE_REQ_QOS: u32 = 0x0000_0004;
    pub const ADJUST_EVENT_QOS_BIT: u32 = 0x0000_0008;
    pub const ADJUST_EVENT_QOS_SHIFT: u32 = 4;
    pub const RESET_EVENT_QOS: u32 = ADJUST_EVENT_QOS_BIT;
    pub const THREADREQ_NODEFEER: u32 = 0x0000_0080;

    /// `FILTER_ADJUST_EVENT_QOS`.
    pub fn adjust_event_qos(q: u8) -> u32 {
        ((u32::from(q) << ADJUST_EVENT_QOS_SHIFT) & 0x70) | ADJUST_EVENT_QOS_BIT
    }
}

/// `AST_KEVENT_*`: what a thread does for kevent on its way back to user
/// space (`kevent_ast`).
pub mod ast {
    pub const RETURN_TO_KERNEL: u16 = 0x0001;
    pub const REDRIVE_THREADREQ: u16 = 0x0002;
}

/// `R2K_WORKLOOP_PENDING_EVENTS`.
const R2K_WORKLOOP_PENDING_EVENTS: u64 = 0x1;
/// `KQWQ_QOS_MANAGER`, `KQWQ_NBUCKETS`, `KQWL_NBUCKETS`.
pub const KQWQ_QOS_MANAGER: u8 = qos::LAST;
const KQWQ_NBUCKETS: usize = KQWQ_QOS_MANAGER as usize;
const KQWL_NBUCKETS: usize = (qos::LAST - 1) as usize;
/// `TRP_RELEASED`.
const TRP_RELEASED: u16 = 0x8000;
/// `_PTHREAD_PRIORITY_FALLBACK_FLAG`.
const PP_FALLBACK_FLAG: u64 = 0x0400_0000;
/// `_PTHREAD_PRIORITY_QOS_CLASS_MASK`.
const PP_QOS_CLASS_MASK: u64 = 0x003f_ff00;

/// `struct kevent_qos_s`, the kernel's form of every event.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Kev {
    pub ident: u64,
    pub filter: i16,
    pub flags: u16,
    pub qos: i32,
    pub udata: u64,
    pub fflags: u32,
    pub xflags: u32,
    pub data: i64,
    pub ext: [u64; 4],
}

impl Kev {
    pub const QOS_SIZE: usize = 72;

    fn from_qos(b: &[u8]) -> Kev {
        let u64_ = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let u32_ = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        Kev {
            ident: u64_(0),
            filter: i16::from_le_bytes([b[8], b[9]]),
            flags: u16::from_le_bytes([b[10], b[11]]),
            qos: u32_(12) as i32,
            udata: u64_(16),
            fflags: u32_(24),
            xflags: u32_(28),
            data: u64_(32) as i64,
            ext: [u64_(40), u64_(48), u64_(56), u64_(64)],
        }
    }

    fn to_qos(self) -> [u8; 72] {
        let mut b = [0u8; 72];
        b[0..8].copy_from_slice(&self.ident.to_le_bytes());
        b[8..10].copy_from_slice(&self.filter.to_le_bytes());
        b[10..12].copy_from_slice(&self.flags.to_le_bytes());
        b[12..16].copy_from_slice(&self.qos.to_le_bytes());
        b[16..24].copy_from_slice(&self.udata.to_le_bytes());
        b[24..28].copy_from_slice(&self.fflags.to_le_bytes());
        b[28..32].copy_from_slice(&self.xflags.to_le_bytes());
        b[32..40].copy_from_slice(&self.data.to_le_bytes());
        for (i, e) in self.ext.iter().enumerate() {
            b[40 + 8 * i..48 + 8 * i].copy_from_slice(&e.to_le_bytes());
        }
        b
    }

    /// An error into `data`, in Darwin's numbering.
    pub(crate) fn set_error(&mut self, e: Errno) {
        self.flags |= ev::ERROR;
        self.data = i64::from(super::errno::to_darwin(e.0));
    }
}

/// A Darwin errno a filter left in an event or a knote, as an [`Errno`].
fn kev_errno(data: i64) -> Errno {
    Errno(super::errno::from_darwin(data as i32))
}

/// A knote (`struct knote`).
#[derive(Clone, Debug, Default)]
pub struct Knote {
    pub kq: KqId,
    /// `kn_kevent`: ident, filter, flags, qos, udata, the fflags it has
    /// collected (`kn_fflags`), the ones registered (`kn_sfflags`), data
    /// (`kn_sdata`) and ext.
    pub ident: u64,
    pub filter: i16,
    pub flags: u16,
    pub qos: i32,
    pub udata: u64,
    pub fflags: u32,
    pub sfflags: u32,
    pub sdata: i64,
    pub ext: [u64; 4],
    pub status: u32,
    pub filtid: u8,
    pub qos_index: u8,
    pub qos_override: u8,
    pub hook32: u32,
    pub is_fd: bool,
    pub fp: Option<Arc<crate::file::OpenFile>>,
    /// `kn_thread`: a workloop's synchronous waiter.
    pub thread: Option<i32>,
    /// `kn_ipc_port` / `kn_ipc_pset`.
    pub ipc: Option<ObjId>,
    /// A file kqueue a kqread knote watches.
    pub kqread: Option<KqId>,
    /// A pipe knote: its pipe's wakeup count when last told
    /// ([`crate::vfs::FileHandle::wakes`]).
    pub seen: Option<u64>,
    /// A vnode knote's place on its vnode's list (`v_knotes`,
    /// [`crate::vnote::listen`]).
    pub vnote: Option<u64>,
    /// `kn_thcall`, while armed.
    pub thcall: Option<(Instant, u64)>,
}

impl Knote {
    /// `knote_fill_kevent_with_sdata`: the event as the knote holds it; an
    /// `EV_CLEAR` knote's collected fflags are reset.
    pub(crate) fn fill_kevent_with_sdata(&mut self) -> Kev {
        let k = Kev { ident: self.ident, filter: self.filter, flags: self.flags, qos: self.qos, udata: self.udata, fflags: self.fflags, xflags: 0, data: self.sdata, ext: self.ext };
        if self.flags & ev::CLEAR != 0 {
            self.fflags = 0;
        }
        k
    }

    /// `knote_fill_kevent`.
    pub(crate) fn fill_kevent(&mut self, data: i64) -> Kev {
        let mut k = self.fill_kevent_with_sdata();
        k.data = data;
        k
    }

    /// `knote_set_error`: a filter's attach failed.
    pub(crate) fn set_error(&mut self, e: Errno) {
        self.flags |= ev::ERROR;
        self.sdata = i64::from(super::errno::to_darwin(e.0));
    }
}

/// A kqueue (`struct kqueue` with its `kqfile`, `kqworkq` or `kqworkloop`).
#[derive(Debug, Default)]
pub struct Kqueue {
    pub state: u16,
    pub count: u32,
    pub level: u16,
    queues: Vec<VecDeque<KnId>>,
    suppressed: Vec<VecDeque<KnId>>,
    /// A file kqueue's sleepers (`KQ_SLEEP` on `kqf_count`), and the
    /// knotes of other kqueues on it (`kqf_sel.si_note`).
    sleepers: Vec<i32>,
    pub sel: Vec<KnId>,
    /// The workqueue kqueue's requests, one per QoS bucket (`kqwq_request`).
    requests: Vec<ReqId>,
    /// A workloop's id, retains, parameters, owner, wakeup QoS and request.
    pub dynamicid: u64,
    pub retains: u32,
    pub params: u64,
    pub owner: Option<i32>,
    pub wakeup_qos: u8,
    pub request: Option<ReqId>,
    /// What the kqueue's descriptor shows of it.
    shared: Option<Arc<KqShared>>,
}

/// What a file kqueue's descriptor sees of it.
#[derive(Debug, Default)]
pub struct KqShared {
    count: AtomicU32,
    id: KqId,
    /// Kqueues whose last descriptor closed, for the kernel to free.
    closed: Arc<Mutex<Vec<KqId>>>,
}

/// The descriptor of a file kqueue (`DTYPE_KQUEUE`, `kqueueops`).
#[derive(Debug)]
pub struct KqueueHandle(Arc<KqShared>);

impl KqueueHandle {
    pub fn id(&self) -> KqId {
        self.0.id
    }
}

impl crate::vfs::FileHandle for KqueueHandle {
    /// `fo_no_read`.
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> crate::errno::SysResult {
        Err(Errno::ENXIO)
    }

    /// `fo_no_write`.
    fn write_at(&self, _offset: u64, _buf: &[u8]) -> crate::errno::SysResult {
        Err(Errno::ENXIO)
    }

    /// `kqueue_stat`: a FIFO the size of the count of queued events.
    fn metadata(&self) -> Result<crate::vfs::Metadata, Errno> {
        Ok(crate::vfs::Metadata {
            file_type: crate::vfs::FileType::Fifo,
            size: u64::from(self.0.count.load(Ordering::Acquire)),
            mode: 0,
            ino: 0,
            mtime: 0,
            nlink: 1,
            rdev: 0,
            times: Default::default(),
        })
    }

    fn is_stream(&self) -> bool {
        true
    }

    /// `kqueue_select`: readable with events queued.
    fn poll_readable(&self) -> bool {
        self.0.count.load(Ordering::Acquire) > 0
    }

    fn as_kqueue(self: Arc<Self>) -> Option<Arc<KqueueHandle>> {
        Some(self)
    }
}

impl Drop for KqueueHandle {
    /// `kqueue_close`: the last descriptor is gone.
    fn drop(&mut self) {
        self.0.closed.lock().unwrap_or_else(|e| e.into_inner()).push(self.0.id);
    }
}

/// The process's kqueues and knotes (`p_fd`'s `fd_knlist`, `fd_knhash`,
/// `fd_kqhash` and `fd_wqkqueue`).
#[derive(Debug, Default)]
pub struct Kevents {
    pub kqs: HashMap<KqId, Kqueue>,
    next_kq: u64,
    pub knotes: HashMap<KnId, Knote>,
    next_kn: u64,
    knlist: HashMap<u64, Vec<KnId>>,
    knhash: HashMap<u64, Vec<KnId>>,
    kqhash: HashMap<u64, KqId>,
    pub wqkqueue: Option<KqId>,
    /// `ip_klist` / `ips_klist`: the EVFILT_MACHPORT knotes on each port
    /// and set, in the order `filt_machport_link` keeps.
    pub port_klist: HashMap<ObjId, Vec<KnId>>,
    /// `p_klist`'s EVFILT_SIGNAL knotes.
    pub sig_klist: Vec<KnId>,
    /// `memorystatus_klist`: the process's EVFILT_MEMORYSTATUS knotes.
    pub memorystatus_klist: Vec<KnId>,
    /// The knotes on pipes (each pipe's `pipe_sel.si_note`), and how many
    /// there are, for a host thread that says when descriptors may have
    /// changed.
    pub pipe_klist: Vec<KnId>,
    pub pipe_watch: Arc<std::sync::atomic::AtomicUsize>,
    /// The vnode notes posted to the process's vnode knotes, to tell them.
    pub vnote_inbox: Arc<Mutex<Vec<(KnId, u32)>>>,
    /// The process notes posted to the process's EVFILT_PROC knotes.
    pub proc_inbox: Arc<Mutex<Vec<(KnId, u32)>>>,
    closed: Arc<Mutex<Vec<KqId>>>,
    /// Threads to wake when the call settles.
    wake: Vec<(i32, WaitResult)>,
}

/// `kevent_ctx_s`: a call's data buffer and scan.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ctx {
    pub data_out: u64,
    pub data_avail: u64,
    pub data_size: u64,
    pub data_resid: u64,
    pub deadline: Option<Instant>,
    pub fd: i32,
    pub process_flags: u32,
    pub process_nevents: i32,
    pub process_noutputs: i32,
    pub process_eventlist: u64,
}

/// A blocked kevent call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cont {
    /// `kqueue_scan_continue` on file kqueue `kq`.
    Scan { kq: KqId, ctx: Ctx },
    /// `filt_wlwait_continue`: a workloop's synchronous waiter
    /// (`struct _kevent_register`).
    WlWait { kqwl: KqId, kev: Kev, eventout: i32, ueventlist: u64 },
}

/// The output format (`kevent_legacy_callback`, `kevent_modern_callback`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Out {
    Legacy,
    Modern,
}

/// `KQWL_UTQ_*`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Utq {
    None,
    UpdateWakeupQos,
    RecomputeWakeupQos,
    Unbinding,
    Parking,
    UpdateWakeupOverride,
    ResetWakeupOverride,
    SetQosIndex,
    RedriveEvents,
}

/// `kqwl_unbind_locked_mode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OverrideDrop {
    Immediately,
    Delayed,
}

impl Kernel {
    fn kev(&mut self) -> &mut Kevents {
        &mut self.dtask.kevents
    }

    pub(crate) fn kq(&mut self, id: KqId) -> &mut Kqueue {
        self.dtask.kevents.kqs.get_mut(&id).expect("a kqueue")
    }

    pub(crate) fn knote(&mut self, id: KnId) -> &mut Knote {
        self.dtask.kevents.knotes.get_mut(&id).expect("a knote")
    }

    pub(crate) fn knote_exists(&self, id: KnId) -> bool {
        self.dtask.kevents.knotes.contains_key(&id)
    }

    pub(crate) fn kq_state(&self, id: KqId) -> u16 {
        self.dtask.kevents.kqs.get(&id).map_or(0, |k| k.state)
    }

    pub(crate) fn kq_exists(&self, id: KqId) -> bool {
        self.dtask.kevents.kqs.contains_key(&id)
    }

    /// Wake `tid` with `wr` once the call settles.
    pub(crate) fn kevent_wake_later(&mut self, tid: i32, wr: WaitResult) {
        self.kev().wake.push((tid, wr));
    }

    // -- the thread's kevent state ----------------------------------------------------

    /// `act_set_astkevent`.
    pub(crate) fn darwin_set_astkevent(&mut self, tid: i32, bits: u16) {
        self.dtask.threads.map.entry(tid).or_default().astkevent |= bits;
    }

    /// `act_clear_astkevent`: whether any of `bits` were set.
    pub(crate) fn darwin_clear_astkevent(&mut self, tid: i32, bits: u16) -> bool {
        let t = self.dtask.threads.map.entry(tid).or_default();
        let was = t.astkevent & bits;
        t.astkevent &= !bits;
        was != 0
    }

    /// `kevent_ast`: the calling thread is returning to user space.
    pub(crate) fn darwin_kevent_ast(&mut self, m: &mut GuestMem<'_>) {
        let tid = self.tid;
        let bits = std::mem::take(&mut self.dtask.threads.map.entry(tid).or_default().astkevent);
        if bits & ast::REDRIVE_THREADREQ != 0 {
            self.darwin_workq_threadreq_redrive(m, kflags::CAN_CREATE_THREADS);
            self.darwin_kevent_settle(m);
        }
        if bits & ast::RETURN_TO_KERNEL != 0 {
            self.kevent_set_return_to_kernel_user_tsd(m, tid);
        }
    }

    /// `kevent_set_return_to_kernel_user_tsd`: a bound thread is told it
    /// has events waiting.
    fn kevent_set_return_to_kernel_user_tsd(&mut self, m: &mut GuestMem<'_>, tid: i32) {
        if self.darwin_kqr_bound(tid).is_none() {
            return;
        }
        let offset = self.dtask.pthread.return_to_kernel_offset;
        let tsd = m.read_u64(self.darwin_ctx_of(tid) + gex_abi::ctx::TPIDRRO as u64).unwrap_or(0);
        if tsd == 0 || offset == 0 {
            return;
        }
        if m.write_u64(tsd + offset, R2K_WORKLOOP_PENDING_EVENTS).is_err() {
            eprintln!("[gex:{}] pid {} (tid:{tid}): copyout of return_to_kernel ast flags failed with ast_addr = {}", self.pid, self.pid, tsd + offset);
        }
    }

    /// The kevent override on a thread (`thread_add_kevent_override`,
    /// `thread_update_kevent_override`, `thread_drop_kevent_override`):
    /// the QoS an owner or a workqueue kqueue's servicer is raised to.
    fn thread_set_kevent_override(&mut self, tid: i32, q: u8) {
        self.dtask.threads.map.entry(tid).or_default().kevent_override = q;
    }

    /// The servicer override (`thread_add_servicer_override` and its kin).
    fn thread_set_servicer_override(&mut self, tid: i32, q: u8) {
        self.dtask.threads.map.entry(tid).or_default().servicer_override = q;
    }

    // -- allocation -----------------------------------------------------------------------

    fn kq_new(&mut self, state: u16, nqueues: usize, nsuppressed: usize) -> KqId {
        let ev = self.kev();
        ev.next_kq += 1;
        let id = ev.next_kq;
        let k = Kqueue { state, queues: vec![VecDeque::new(); nqueues], suppressed: vec![VecDeque::new(); nsuppressed], ..Kqueue::default() };
        ev.kqs.insert(id, k);
        id
    }

    /// `kqueue()`: a file kqueue on a new descriptor, closed on exec and
    /// on fork.
    pub(crate) fn darwin_kqueue(&mut self) -> Result<u64, Errno> {
        let id = self.kq_new(0, 1, 1);
        let closed = Arc::clone(&self.kev().closed);
        let shared = Arc::new(KqShared { count: AtomicU32::new(0), id, closed });
        self.kq(id).shared = Some(Arc::clone(&shared));
        let handle: Arc<dyn crate::vfs::FileHandle> = Arc::new(KqueueHandle(shared));
        let file = crate::file::OpenFile::new(handle, "kqueue".into(), 0, true, true);
        match self.fd_io().fds.insert(file, true) {
            Ok(fd) => Ok(fd as u64),
            Err(e) => {
                self.kev().kqs.remove(&id);
                Err(e)
            }
        }
    }

    /// Free the file kqueues whose last descriptor went: `kqueue_drain`
    /// (its sleepers restart), then `kqueue_dealloc` (its knotes dropped).
    pub(crate) fn darwin_kqueue_reap(&mut self) {
        let closed = std::mem::take(&mut *self.kev().closed.lock().unwrap_or_else(|e| e.into_inner()));
        for id in closed {
            if !self.kq_exists(id) {
                continue;
            }
            self.kq(id).state |= kq::DRAIN;
            self.kqfile_wakeup(id, true);
            let mine: Vec<KnId> = self.kev().knotes.iter().filter(|(_, k)| k.kq == id).map(|(&n, _)| n).collect();
            for n in mine {
                if self.knote_exists(n) {
                    self.knote_drop(n);
                }
            }
            self.kev().kqs.remove(&id);
        }
    }

    /// `kqworkq_alloc`: the process's workqueue kqueue, its requests idle.
    /// Every bucket's request is overcommit: XNU compares the bucket's
    /// index with `KQWQ_QOS_MANAGER`, which no index equals.
    fn kqworkq_alloc(&mut self, flags: u32) -> KqId {
        let state = kq::WORKQ | if flags & kf::LEGACY64 != 0 { kq::KEV64 } else { kq::KEV_QOS };
        let id = self.kq_new(state, KQWQ_NBUCKETS, KQWQ_NBUCKETS);
        for i in 0..KQWQ_NBUCKETS {
            let r = self.darwin_workq_new_req(tr::KEVENT | tr::OVERCOMMIT, i as u8 + 1, id);
            self.kq(id).requests.push(r);
        }
        self.kev().wqkqueue = Some(id);
        id
    }

    /// `kqworkq_get_request`.
    fn kqworkq_get_request(&mut self, kqwq: KqId, qos_index: u8) -> ReqId {
        assert!(qos_index > 0 && qos_index as usize <= KQWQ_NBUCKETS);
        self.kq(kqwq).requests[qos_index as usize - 1]
    }

    /// `kqworkloop_get_or_create`.
    fn kqworkloop_get_or_create(&mut self, id: u64, trp: Option<u64>, flags: u32) -> Result<KqId, Errno> {
        if id == 0 || id == u64::MAX {
            return Err(Errno::EINVAL);
        }
        if let Some(&kqwl) = self.kev().kqhash.get(&id) {
            if flags & kf::DYNAMIC_KQ_MUST_NOT_EXIST != 0 {
                return Err(Errno::EEXIST);
            }
            self.kq(kqwl).retains += 1;
            return Ok(kqwl);
        }
        if flags & kf::DYNAMIC_KQ_MUST_EXIST != 0 {
            return Err(Errno::ENOENT);
        }
        // kqworkloop_init
        let kqwl = self.kq_new(kq::WORKLOOP | kq::DYNAMIC | kq::KEV_QOS, KQWL_NBUCKETS, 1);
        let mut tr_flags = tr::WORKLOOP;
        if let Some(t) = trp {
            let trp_flags = t as u16;
            if trp_flags & super::workq::TRP_PRIORITY != 0 {
                tr_flags |= tr::WL_OUTSIDE_QOS;
            }
            if trp_flags != 0 {
                tr_flags |= tr::WL_PARAMS;
            }
        }
        let req = self.darwin_workq_new_req(tr_flags, 0, kqwl);
        let k = self.kq(kqwl);
        k.retains = 1;
        k.dynamicid = id;
        k.params = trp.unwrap_or(0);
        k.request = Some(req);
        self.kev().kqhash.insert(id, kqwl);
        Ok(kqwl)
    }

    fn kqworkloop_retain(&mut self, kqwl: KqId) {
        self.kq(kqwl).retains += 1;
    }

    /// `kqworkloop_release`: the last retain frees it.
    pub(crate) fn kqworkloop_release(&mut self, kqwl: KqId) {
        let k = self.kq(kqwl);
        k.retains -= 1;
        if k.retains == 0 {
            self.kqworkloop_dealloc(kqwl);
        }
    }

    /// `kqworkloop_release_live`: a release that is never the last.
    fn kqworkloop_release_live(&mut self, kqwl: KqId) {
        let k = self.kq(kqwl);
        assert!(k.retains > 1, "a live release is not the last");
        k.retains -= 1;
    }

    fn kqueue_retain(&mut self, kqid: KqId) {
        if self.kq_state(kqid) & kq::DYNAMIC != 0 {
            self.kqworkloop_retain(kqid);
        }
    }

    fn kqueue_release(&mut self, kqid: KqId) {
        if self.kq_state(kqid) & kq::DYNAMIC != 0 {
            self.kqworkloop_release(kqid);
        }
    }

    fn kqueue_release_live(&mut self, kqid: KqId) {
        if self.kq_state(kqid) & kq::DYNAMIC != 0 {
            self.kqworkloop_release_live(kqid);
        }
    }

    /// `kqworkloop_dealloc`.
    fn kqworkloop_dealloc(&mut self, kqwl: KqId) {
        if let Some(owner) = self.kq(kqwl).owner.take() {
            if self.kqworkloop_override(kqwl) != qos::UNSPECIFIED {
                self.thread_set_kevent_override(owner, qos::UNSPECIFIED);
            }
        }
        let (id, req) = (self.kq(kqwl).dynamicid, self.kq(kqwl).request);
        assert!(self.kq(kqwl).suppressed[0].is_empty(), "a workloop freed with suppressed knotes");
        self.kev().kqhash.remove(&id);
        if let Some(r) = req {
            self.darwin_workq_free_req(r);
        }
        self.kev().kqs.remove(&kqwl);
    }

    /// The kqueue of a thread request (`kqr_kqueue`).
    pub(crate) fn kqr_kqueue(&self, req: ReqId) -> KqId {
        self.darwin_workq_req(req).kq.expect("a kqueue's request")
    }

    // -- knote queues -------------------------------------------------------------------------

    /// `knote_get_tailq`: the queue an active knote waits on.
    fn knote_tailq(&self, n: KnId) -> (KqId, usize) {
        let k = &self.dtask.kevents.knotes[&n];
        let st = self.kq_state(k.kq);
        let idx = if st & (kq::WORKLOOP | kq::WORKQ) != 0 { k.qos_index as usize - 1 } else { 0 };
        (k.kq, idx)
    }

    /// `kqueue_get_suppressed_queue`.
    fn suppressed_queue(&self, n: KnId) -> (KqId, usize) {
        let k = &self.dtask.kevents.knotes[&n];
        let st = self.kq_state(k.kq);
        let idx = if st & kq::WORKQ != 0 { k.qos_index as usize - 1 } else { 0 };
        (k.kq, idx)
    }

    fn kq_publish(&mut self, kqid: KqId) {
        let q = self.kq(kqid);
        if let Some(s) = &q.shared {
            s.count.store(q.count, Ordering::Release);
        }
    }

    /// `knote_enqueue`.
    pub(crate) fn knote_enqueue(&mut self, n: KnId) {
        let k = self.knote(n);
        if k.status & kn::ACTIVE == 0 || k.status & (kn::DISABLED | kn::SUPPRESSED | kn::DROPPING | kn::QUEUED) != 0 {
            return;
        }
        let qi = k.qos_index;
        let (kqid, idx) = self.knote_tailq(n);
        let q = self.kq(kqid);
        let wakeup = q.queues[idx].is_empty();
        q.queues[idx].push_back(n);
        q.count += 1;
        self.knote(n).status |= kn::QUEUED;
        self.kq_publish(kqid);
        if wakeup {
            let st = self.kq_state(kqid);
            if st & kq::WORKLOOP != 0 {
                self.kqworkloop_wakeup(kqid, qi);
            } else if st & kq::WORKQ != 0 {
                self.kqworkq_wakeup(kqid, qi);
            } else {
                self.kqfile_wakeup(kqid, false);
            }
        }
    }

    /// `knote_dequeue`.
    pub(crate) fn knote_dequeue(&mut self, n: KnId) {
        if self.knote(n).status & kn::QUEUED == 0 {
            return;
        }
        let (kqid, idx) = self.knote_tailq(n);
        let q = self.kq(kqid);
        q.queues[idx].retain(|&x| x != n);
        q.count -= 1;
        self.knote(n).status &= !kn::QUEUED;
        self.kq_publish(kqid);
    }

    /// `knote_suppress`.
    fn knote_suppress(&mut self, n: KnId) {
        assert!(self.knote(n).status & kn::SUPPRESSED == 0);
        self.knote_dequeue(n);
        let k = self.knote(n);
        k.status &= !kn::ACTIVE;
        k.status |= kn::SUPPRESSED;
        let (kqid, idx) = self.suppressed_queue(n);
        self.kq(kqid).suppressed[idx].push_back(n);
    }

    /// `knote_unsuppress_noqueue`.
    fn knote_unsuppress_noqueue(&mut self, n: KnId) {
        assert!(self.knote(n).status & kn::SUPPRESSED != 0);
        let (kqid, idx) = self.suppressed_queue(n);
        self.kq(kqid).suppressed[idx].retain(|&x| x != n);
        let k = self.knote(n);
        k.status &= !kn::SUPPRESSED;
        if k.status & kn::ACTIVE == 0 && knote_has_qos(k) {
            k.qos_override = pp::qos(k.qos as u32 as u64);
        }
        k.qos_index = k.qos_override;
    }

    /// `knote_unsuppress`.
    fn knote_unsuppress(&mut self, n: KnId) {
        self.knote_unsuppress_noqueue(n);
        self.knote_enqueue(n);
    }

    /// `knote_activate`.
    pub(crate) fn knote_activate(&mut self, n: KnId, result: u32) {
        assert!(result & filter::ACTIVE != 0);
        if result & filter::ADJUST_EVENT_QOS_BIT != 0 {
            self.knote_adjust_qos(n, result);
        }
        self.knote(n).status |= kn::ACTIVE;
        self.knote_enqueue(n);
    }

    /// `knote_post`: a filter's event, with `hint`.
    pub(crate) fn knote_post(&mut self, n: KnId, hint: i64) {
        if self.knote(n).status & (kn::DROPPING | kn::VANISHED) != 0 {
            return;
        }
        assert!(self.knote(n).status & kn::POSTING == 0, "KNOTE() called concurrently on knote");
        self.knote(n).status |= kn::POSTING;
        let result = self.filt_event(n, hint);
        let dropping = self.knote(n).status & (kn::DROPPING | kn::VANISHED) != 0;
        if !dropping && result & filter::ACTIVE != 0 {
            self.knote_activate(n, result);
        }
        let k = self.knote(n);
        if k.status & kn::LOCKED == 0 {
            k.status &= !(kn::POSTING | kn::MERGE_QOS);
        } else {
            k.status &= !kn::POSTING;
        }
    }

    /// `KNOTE(list, hint)`.
    pub(crate) fn knote_list(&mut self, list: &[KnId], hint: i64) {
        for &n in list {
            if self.knote_exists(n) {
                self.knote_post(n, hint);
            }
        }
    }

    /// `knote_vanish`: what the knotes watch is gone.
    pub(crate) fn knote_vanish(&mut self, list: &[KnId], make_active: bool) {
        for &n in list {
            if !self.knote_exists(n) {
                continue;
            }
            let k = self.knote(n);
            if k.status & kn::REQVANISH != 0 {
                k.status |= kn::VANISHED;
            } else {
                k.flags |= ev::EOF | ev::ONESHOT;
            }
            if make_active {
                self.knote_activate(n, filter::ACTIVE);
            }
        }
    }

    /// `knote_reset_priority`.
    fn knote_reset_priority(&mut self, n: KnId, pp_: i32) {
        let kqid = self.knote(n).kq;
        let st = self.kq_state(kqid);
        let mut q = pp::qos(pp_ as u32 as u64);
        let p = if st & kq::WORKLOOP != 0 {
            assert!(pp_ as u32 as u64 & pp::EVENT_MANAGER_FLAG == 0);
            pp_normalize(pp_ as u32 as u64)
        } else if st & kq::WORKQ != 0 {
            if q == qos::UNSPECIFIED {
                // On the workqueue kqueue, no QoS means the event manager.
                q = KQWQ_QOS_MANAGER;
                pp::EVENT_MANAGER_FLAG
            } else {
                pp_normalize(pp_ as u32 as u64)
            }
        } else {
            q = qos::UNSPECIFIED;
            0
        };
        let k = self.knote(n);
        k.qos = p as u32 as i32;
        if k.status & kn::MERGE_QOS == 0 || q > k.qos_override {
            k.qos_override = q;
        }
        if k.status & kn::SUPPRESSED != 0 {
            self.kqueue_update_override(kqid, n, q);
        } else if self.knote(n).qos_index != q {
            self.knote_dequeue(n);
            self.knote(n).qos_index = q;
        }
    }

    /// `knote_adjust_qos`.
    fn knote_adjust_qos(&mut self, n: KnId, result: u32) {
        let mut qi = ((result >> filter::ADJUST_EVENT_QOS_SHIFT) & 7) as u8;
        assert!(qi < qos::LAST);
        let k = self.knote(n).clone();
        assert!(filt_adjusts_qos(k.filtid), "filter {} cannot change QoS", k.filtid);
        if !knote_has_qos(&k) {
            return;
        }
        let req_qos = pp::qos(k.qos as u32 as u64);
        if k.qos as u32 as u64 & PP_FALLBACK_FLAG != 0 {
            if qi == qos::UNSPECIFIED {
                qi = req_qos;
            }
        } else if qi < req_qos {
            qi = req_qos;
        }
        if k.status & kn::MERGE_QOS != 0 && qi < k.qos_override {
            return;
        }
        if k.status & kn::LOCKED != 0 && k.status & kn::POSTING != 0 {
            self.knote(n).status |= kn::MERGE_QOS;
        }
        if k.qos_override == qi {
            return;
        }
        self.knote(n).qos_override = qi;
        if k.status & kn::SUPPRESSED != 0 {
            self.kqueue_update_override(k.kq, n, qi);
        } else if k.qos_index != qi {
            self.knote_dequeue(n);
            self.knote(n).qos_index = qi;
        }
    }

    /// `knote_apply_touch`.
    fn knote_apply_touch(&mut self, m: &mut GuestMem<'_>, n: KnId, kev: &Kev, result: u32) {
        let kqid = self.knote(n).kq;
        if kev.flags & ev::ENABLE != 0 && self.knote(n).status & kn::DISABLED != 0 {
            self.knote(n).status &= !kn::DISABLED;
            if self.knote(n).status & kn::SUPPRESSED != 0 && self.kq_state(kqid) & kq::PROCESSING == 0 {
                self.knote_unsuppress_noqueue(n);
            }
        }
        if result & filter::UPDATE_REQ_QOS != 0 && kev.qos != 0 && kev.qos != self.knote(n).qos {
            self.knote_reset_priority(n, kev.qos);
        }
        if result & filter::ACTIVE != 0 {
            self.knote_activate(n, result);
        } else {
            self.knote_enqueue(n);
        }
        let me = self.tid;
        if result & filter::THREADREQ_NODEFEER != 0 && self.darwin_clear_astkevent(me, ast::REDRIVE_THREADREQ) {
            self.darwin_workq_threadreq_redrive(m, kflags::NONE);
        }
    }

    /// `knote_drop`.
    pub(crate) fn knote_drop(&mut self, n: KnId) {
        assert!(self.knote(n).status & kn::DROPPING == 0);
        self.knote(n).status |= kn::DROPPING;
        if self.knote(n).status & kn::SUPPRESSED != 0 {
            self.knote_unsuppress_noqueue(n);
        } else {
            self.knote_dequeue(n);
        }
        self.filt_detach(n);
        // kq_remove_knote
        let k = self.kev().knotes.remove(&n).expect("a knote");
        let ev_ = self.kev();
        let list = if k.is_fd { ev_.knlist.get_mut(&k.ident) } else { ev_.knhash.get_mut(&k.ident) };
        if let Some(l) = list {
            l.retain(|&x| x != n);
        }
        if self.kq_state(k.kq) & kq::DYNAMIC != 0 {
            self.kqworkloop_release(k.kq);
        }
    }

    /// `knote_fdclose`: descriptor `fd` is closing; its knotes are dropped,
    /// or vanish for those that asked to.
    pub(crate) fn darwin_knote_fdclose(&mut self, fd: i32) {
        let list = self.kev().knlist.get(&(fd as u64)).cloned().unwrap_or_default();
        for n in list {
            if !self.knote_exists(n) || self.knote(n).status & kn::VANISHED != 0 {
                continue;
            }
            if self.knote(n).status & kn::REQVANISH != 0 {
                self.knote(n).status |= kn::VANISHED;
                self.filt_detach(n);
                let k = self.knote(n);
                k.fp = None;
                k.filtid = filtid::DETACHED;
                self.knote_activate(n, filter::ACTIVE);
            } else {
                self.knote_drop(n);
            }
        }
    }

    /// The descriptors with knotes that no longer hold their knotes' file
    /// were closed (or replaced by `dup2`): `knote_fdclose` for each.
    pub(crate) fn darwin_knote_fdcheck(&mut self) {
        if self.kev().knlist.is_empty() {
            return;
        }
        let mut closed = Vec::new();
        for (&fd, list) in &self.dtask.kevents.knlist {
            let held = self.fd_io().fds.get(fd as i32).ok();
            let gone = list.iter().any(|n| {
                let fp = self.dtask.kevents.knotes[n].fp.as_ref();
                match (fp, &held) {
                    (Some(a), Some(b)) => !Arc::ptr_eq(a, b),
                    (Some(_), None) => true,
                    (None, _) => false,
                }
            });
            if gone {
                closed.push(fd as i32);
            }
        }
        for fd in closed {
            self.darwin_knote_fdclose(fd);
        }
        self.kev().knlist.retain(|_, l| !l.is_empty());
    }

    /// `knote_fdfind`.
    fn knote_fdfind(&self, kqid: KqId, kev: &Kev, is_fd: bool) -> Option<KnId> {
        let ev_ = &self.dtask.kevents;
        let list = if is_fd { ev_.knlist.get(&kev.ident) } else { ev_.knhash.get(&kev.ident) }?;
        list.iter().copied().find(|n| {
            let k = &ev_.knotes[n];
            k.kq == kqid
                && k.ident == kev.ident
                && k.filter == kev.filter
                && if kev.flags & ev::UDATA_SPECIFIC != 0 { k.flags & ev::UDATA_SPECIFIC != 0 && kev.udata == k.udata } else { k.flags & ev::UDATA_SPECIFIC == 0 }
        })
    }

    // -- registration ---------------------------------------------------------------------------

    /// `kevent_register_validate_priority`.
    fn kevent_register_validate_priority(&self, kqid: KqId, n: Option<KnId>, kev: &Kev) -> Result<(), Errno> {
        if kev.flags & (ev::DISABLE | ev::DELETE) == 0 && self.kq_state(kqid) & kq::WORKLOOP != 0 {
            let q = match n {
                Some(n) if kev.flags & ev::ADD == 0 || kev.qos == 0 => self.dtask.kevents.knotes[&n].qos,
                _ => kev.qos,
            };
            if pp::qos(q as u32 as u64) == qos::UNSPECIFIED {
                return Err(Errno::ERANGE);
            }
        }
        Ok(())
    }

    /// `kevent_register`: change `kev` on `kqid`. The filter's result, and
    /// the knote that waits when it asks to.
    fn kevent_register(&mut self, m: &mut GuestMem<'_>, kqid: KqId, kev: &mut Kev) -> (u32, Option<KnId>) {
        let kev_flags = kev.flags;
        let mut result = 0u32;
        let mut wait_kn = None;
        let error: Result<(), Errno> = 'out: {
            if !(kev.filter < 0 && kev.filter + evfilt::SYSCOUNT >= 0) {
                break 'out Err(Errno::EINVAL);
            }
            if kev.flags & ev::VANISHED != 0 && kev.flags & (ev::ADD | ev::DISPATCH2) != (ev::ADD | ev::DISPATCH2) {
                break 'out Err(Errno::EINVAL);
            }
            if kev.flags & ev::DELETE != 0 {
                kev.flags &= !ev::ADD;
            }
            if kev.flags & ev::DISABLE != 0 {
                kev.flags &= !ev::ENABLE;
            }
            let fid = (!kev.filter) as u8;
            let is_fd = filt_isfd(fid);
            let found = self.knote_fdfind(kqid, kev, is_fd);
            if let Err(e) = self.kevent_register_validate_priority(kqid, found, kev) {
                break 'out Err(e);
            }
            let n = match found {
                None if kev.flags & ev::ADD == 0 => {
                    // EV_ADD|EV_DELETE of a knote that is not there is no
                    // error on a workloop.
                    if kev_flags & ev::ADD != 0 && kev_flags & ev::DELETE != 0 && self.kq_state(kqid) & kq::WORKLOOP != 0 {
                        break 'out Ok(());
                    }
                    break 'out Err(Errno::ENOENT);
                }
                None => {
                    let mut fp = None;
                    if is_fd {
                        match self.fd_io().fds.get(kev.ident as i32) {
                            Ok(f) => fp = Some(f),
                            Err(e) => break 'out Err(e),
                        }
                    }
                    let mut k = Knote { kq: kqid, fp, is_fd, ..Knote::default() };
                    if kev.flags & ev::VANISHED != 0 {
                        kev.flags &= !ev::VANISHED;
                        k.status |= kn::REQVANISH;
                    }
                    if kev.flags & ev::DISABLE != 0 {
                        k.status |= kn::DISABLED;
                    }
                    k.ident = kev.ident;
                    k.filter = kev.filter;
                    k.flags = kev.flags;
                    k.qos = kev.qos;
                    k.udata = kev.udata;
                    k.sdata = kev.data;
                    k.ext = kev.ext;
                    k.sfflags = kev.fflags;
                    k.filtid = fid;
                    k.fflags = 0;
                    // kq_add_knote
                    if is_fd && kev.ident >= self.fd_io().fds.limit() as u64 {
                        break 'out Err(Errno::EINVAL);
                    }
                    let ev_ = self.kev();
                    ev_.next_kn += 1;
                    let n = ev_.next_kn;
                    ev_.knotes.insert(n, k);
                    let list = if is_fd { ev_.knlist.entry(kev.ident).or_default() } else { ev_.knhash.entry(kev.ident).or_default() };
                    list.insert(0, n);
                    self.knote_reset_priority(n, kev.qos);
                    self.knote(n).status |= kn::LOCKED;
                    self.kqueue_retain(kqid);
                    result = self.filt_attach(m, n, kev);
                    if result != 0 && !filt_extended_codes(self.knote(n).filtid) {
                        result = filter::ACTIVE;
                    }
                    if self.knote(n).flags & ev::ERROR != 0 {
                        // The attach failed (an error of 0: it asked not to
                        // be attached, without an error).
                        self.knote(n).filtid = filtid::DETACHED;
                        let e = self.knote(n).sdata;
                        self.knote(n).status &= !kn::LOCKED;
                        self.knote_drop(n);
                        result = 0;
                        break 'out if e == 0 { Ok(()) } else { Err(kev_errno(e)) };
                    }
                    if self.knote(n).qos as u32 as u64 & pp::OVERCOMMIT_FLAG != 0 && self.kq_state(kqid) & kq::WORKLOOP != 0 {
                        self.kqworkloop_set_overcommit(kqid);
                    }
                    n
                }
                Some(n) if kev.flags & ev::DELETE != 0 => {
                    self.knote(n).status |= kn::LOCKED;
                    if filt_has_allow_drop(self.knote(n).filtid) && !self.filt_allow_drop(m, n, kev) {
                        self.knote(n).status &= !kn::LOCKED;
                        break 'out Ok(());
                    }
                    let k = self.knote(n);
                    if kev.flags & ev::ENABLE == 0 && k.flags & ev::DISPATCH2 == ev::DISPATCH2 && k.status & kn::DISABLED != 0 {
                        k.status |= kn::DEFERDELETE;
                        k.status &= !kn::LOCKED;
                        break 'out Err(Errno::EINPROGRESS);
                    }
                    self.knote(n).status &= !kn::LOCKED;
                    self.knote_drop(n);
                    break 'out Ok(());
                }
                Some(n) => {
                    self.knote(n).status |= kn::LOCKED;
                    if self.knote(n).status & (kn::DEFERDELETE | kn::VANISHED) != 0 {
                        if kev.flags & ev::ENABLE != 0 {
                            result = filter::ACTIVE;
                        }
                    } else {
                        result = self.filt_touch(m, n, kev);
                        if result != 0 && !filt_extended_codes(self.knote(n).filtid) {
                            result = filter::ACTIVE;
                        }
                    }
                    if kev.flags & ev::ERROR != 0 {
                        self.knote(n).status &= !kn::LOCKED;
                        result = 0;
                        break 'out Ok(());
                    }
                    let k = self.knote(n);
                    if k.flags & ev::UDATA_SPECIFIC == 0 && k.udata != kev.udata {
                        k.udata = kev.udata;
                    }
                    if kev.flags & ev::DISABLE != 0 && k.status & kn::DISABLED == 0 {
                        k.status |= kn::DISABLED;
                        self.knote_dequeue(n);
                    }
                    n
                }
            };
            self.knote_apply_touch(m, n, kev, result);
            self.knote(n).status &= !(kn::LOCKED | kn::MERGE_QOS);
            if result & filter::REGISTER_WAIT != 0 {
                wait_kn = Some(n);
            }
            Ok(())
        };
        if let Err(e) = error {
            kev.set_error(e);
        }
        (result, wait_kn)
    }

    // -- processing -------------------------------------------------------------------------------

    /// `knote_process`: deliver one queued knote. `Err` stops the scan
    /// (the event list is full, or a copyout failed).
    fn knote_process(&mut self, m: &mut GuestMem<'_>, n: KnId, ctx: &mut Ctx, out: Out) -> Result<(), Errno> {
        if self.knote(n).status & kn::QUEUED == 0 {
            return Ok(());
        }
        self.knote(n).status |= kn::LOCKED;
        self.knote_suppress(n);
        let k = self.knote(n).clone();
        let mut result = filter::ACTIVE;
        let mut kev = if k.status & (kn::DEFERDELETE | kn::VANISHED) != 0 {
            let mut f = ev::DISPATCH2 | ev::ONESHOT;
            f |= if k.status & kn::DEFERDELETE != 0 { ev::DELETE } else { ev::VANISHED };
            Kev { filter: k.filter, ident: k.ident, flags: f, udata: k.udata, ..Kev::default() }
        } else {
            let mut kev = Kev::default();
            result = self.filt_process(m, n, &mut kev, ctx);
            if result != 0 && !filt_extended_codes(self.knote(n).filtid) {
                result = filter::ACTIVE;
            }
            kev
        };
        if result & filter::ACTIVE == 0 {
            if self.knote(n).status & kn::ACTIVE == 0 {
                self.knote_unsuppress(n);
            }
            self.knote(n).status &= !(kn::LOCKED | kn::MERGE_QOS);
            return Ok(());
        }
        if result & filter::ADJUST_EVENT_QOS_BIT != 0 {
            self.knote_adjust_qos(n, result);
        }
        let k = self.knote(n).clone();
        kev.qos = pp_combine(k.qos as u32 as u64, k.qos_override) as u32 as i32;
        let mut drop = false;
        if kev.flags & ev::ONESHOT != 0 {
            if k.flags & ev::DISPATCH2 == ev::DISPATCH2 && k.status & kn::DEFERDELETE == 0 {
                self.knote(n).status |= kn::DEFERDELETE | kn::DISABLED;
            } else {
                drop = true;
            }
        } else if k.flags & ev::DISPATCH != 0 {
            self.knote(n).status |= kn::DISABLED;
        } else if k.flags & ev::CLEAR == 0 {
            self.knote_activate(n, filter::ACTIVE);
        }
        self.knote(n).status &= !(kn::LOCKED | kn::MERGE_QOS);
        if drop {
            self.knote_drop(n);
        }
        self.kevent_callback(m, &kev, ctx, out)
    }

    /// `kevent_legacy_callback`, `kevent_modern_callback`: copy an event
    /// out; `EWOULDBLOCK` once the list is full.
    fn kevent_callback(&mut self, m: &mut GuestMem<'_>, kev: &Kev, ctx: &mut Ctx, out: Out) -> Result<(), Errno> {
        match out {
            Out::Legacy => kevent_legacy_copyout(m, kev, &mut ctx.process_eventlist, ctx.process_flags)?,
            Out::Modern => kevent_modern_copyout(m, kev, &mut ctx.process_eventlist)?,
        }
        ctx.process_noutputs += 1;
        if ctx.process_noutputs == ctx.process_nevents {
            return Err(Errno::EWOULDBLOCK);
        }
        Ok(())
    }

    /// `kqueue_process`: deliver what is queued. `Err(EWOULDBLOCK)` when
    /// events were delivered.
    fn kqueue_process(&mut self, m: &mut GuestMem<'_>, kqid: KqId, mut flags: u32, ctx: &mut Ctx, out: Out) -> Result<(), Errno> {
        let st = self.kq_state(kqid);
        let kqr = self.darwin_kqr_bound(self.tid);
        let mut rc = if st & kq::WORKQ != 0 {
            self.kqworkq_begin_processing(kqid, kqr.expect("a bound thread"), flags)
        } else if st & kq::WORKLOOP != 0 {
            self.kqworkloop_begin_processing(kqid, flags)
        } else {
            self.kqfile_begin_processing(kqid)?
        };
        loop {
            if rc == -1 {
                return Ok(());
            }
            let queues: Vec<usize> = if st & kq::WORKQ != 0 {
                let r = kqr.expect("a bound thread");
                vec![self.darwin_workq_req(r).kq_qos_index as usize - 1]
            } else if st & kq::WORKLOOP != 0 {
                (0..KQWL_NBUCKETS).rev().collect()
            } else {
                vec![0]
            };
            let mut error = Ok(());
            'stop: for qi in queues {
                while let Some(&n) = self.kq(kqid).queues[qi].front() {
                    if let Err(e) = self.knote_process(m, n, ctx, out) {
                        error = Err(e);
                        break 'stop;
                    }
                }
            }
            if error.is_ok() && ctx.process_noutputs != 0 {
                error = Err(Errno::EWOULDBLOCK);
            }
            if error.is_err() {
                flags &= !kf::PARKING;
            }
            let end = if st & kq::WORKQ != 0 {
                Ok(self.kqworkq_end_processing(kqid, kqr.expect("a bound thread"), flags))
            } else if st & kq::WORKLOOP != 0 {
                Ok(self.kqworkloop_end_processing(kqid, kq::PROCESSING, flags))
            } else {
                self.kqfile_end_processing(kqid)
            };
            error?;
            rc = end?;
            if rc >= 0 {
                return Ok(());
            }
            if st & (kq::WORKQ | kq::WORKLOOP) != 0 {
                assert!(flags & kf::PARKING != 0);
                rc = 0;
            } else {
                rc = self.kqfile_begin_processing(kqid)?;
            }
        }
    }

    /// `kqueue_scan`: deliver, or wait for something to deliver.
    fn kqueue_scan(&mut self, m: &mut GuestMem<'_>, kqid: KqId, flags: u32, ctx: &mut Ctx, out: Out) -> Result<Option<SyscallOutcome>, Errno> {
        match self.kqueue_process(m, kqid, flags, ctx, out) {
            Err(e) if e == Errno::EWOULDBLOCK => return Ok(None),
            Err(e) => return Err(e),
            Ok(()) if flags & kf::IMMEDIATE != 0 => return Ok(None),
            Ok(()) => {}
        }
        assert!(self.kq_state(kqid) & (kq::WORKQ | kq::WORKLOOP) == 0);
        let tid = self.tid;
        let q = self.kq(kqid);
        q.state |= kq::SLEEP;
        q.sleepers.push(tid);
        let wait = Wait { deadline: ctx.deadline, cont: super::thread::Finish::Kevent(Cont::Scan { kq: kqid, ctx: *ctx }) };
        self.darwin_kevent_settle(m);
        Ok(Some(self.darwin_block(m, wait)))
    }

    /// `kqfile_wakeup`: a file kqueue has something to deliver
    /// (`revoke`: it is draining, its sleepers restart).
    fn kqfile_wakeup(&mut self, kqid: KqId, revoke: bool) {
        let wr = if revoke { WaitResult::Restart } else { WaitResult::Awakened };
        let q = self.kq(kqid);
        let mut sleepers = Vec::new();
        if q.state & kq::SLEEP != 0 {
            q.state &= !kq::SLEEP;
            sleepers = std::mem::take(&mut q.sleepers);
        }
        let sel = q.sel.clone();
        for t in sleepers {
            self.kevent_wake_later(t, wr);
        }
        if !revoke {
            self.knote_list(&sel, 0);
        }
    }

    /// `kqfile_begin_processing`; -1 with nothing queued.
    fn kqfile_begin_processing(&mut self, kqid: KqId) -> Result<i32, Errno> {
        let q = self.kq(kqid);
        // Another thread processing the kqueue holds the kernel lock until
        // it is done: KQ_PROCESSING is never seen here.
        assert!(q.state & kq::PROCESSING == 0);
        if q.state & kq::DRAIN != 0 {
            return Err(Errno::EBADF);
        }
        if q.count == 0 {
            return Ok(-1);
        }
        q.state |= kq::PROCESSING;
        Ok(0)
    }

    /// `kqfile_end_processing`; -1 when more came in.
    fn kqfile_end_processing(&mut self, kqid: KqId) -> Result<i32, Errno> {
        while let Some(&n) = self.kq(kqid).suppressed[0].front() {
            self.knote_unsuppress(n);
        }
        let q = self.kq(kqid);
        q.state &= !(kq::PROCESSING | kq::PROCWAIT);
        if q.state & kq::DRAIN != 0 {
            return Err(Errno::EBADF);
        }
        Ok(if q.count != 0 { -1 } else { 0 })
    }

    // -- the workqueue kqueue ---------------------------------------------------------------------

    /// `kqworkq_wakeup`.
    fn kqworkq_wakeup(&mut self, kqwq: KqId, qos_index: u8) {
        let req = self.kqworkq_get_request(kqwq, qos_index);
        if self.darwin_workq_req(req).state == tr::IDLE {
            self.kqueue_threadreq_initiate(kqwq, req, qos_index, 0);
        }
    }

    /// `kqworkq_acknowledge_events`; -1 when the thread unbinds.
    fn kqworkq_acknowledge_events(&mut self, kqwq: KqId, req: ReqId, kevent_flags: u32, unbind_op: bool) -> i32 {
        let idx = self.darwin_workq_req(req).kq_qos_index as usize - 1;
        while let Some(&n) = self.kq(kqwq).suppressed[idx].front() {
            self.knote_unsuppress(n);
        }
        let unbind = if unbind_op {
            true
        } else if kevent_flags & kf::PARKING == 0 {
            false
        } else {
            self.kq(kqwq).queues[idx].is_empty()
        };
        if !unbind {
            return 0;
        }
        let thread = self.darwin_workq_req(req).thread.expect("a bound request's thread");
        let old_override = self.kqworkq_unbind_locked(kqwq, req, thread);
        if !self.kq(kqwq).queues[idx].is_empty() {
            let qi = self.darwin_workq_req(req).kq_qos_index;
            self.kqueue_threadreq_initiate(kqwq, req, qi, 0);
        }
        if old_override != 0 {
            self.thread_set_kevent_override(thread, qos::UNSPECIFIED);
        }
        -1
    }

    fn kqworkq_begin_processing(&mut self, kqwq: KqId, req: ReqId, flags: u32) -> i32 {
        self.kqworkq_acknowledge_events(kqwq, req, flags, false)
    }

    /// `kqworkq_end_processing`; -1 when the parking thread has more.
    fn kqworkq_end_processing(&mut self, kqwq: KqId, req: ReqId, flags: u32) -> i32 {
        if flags & kf::PARKING != 0 && self.kqworkq_acknowledge_events(kqwq, req, flags, false) == 0 {
            return -1;
        }
        0
    }

    /// `kqworkq_unbind_locked`: the request's old override.
    fn kqworkq_unbind_locked(&mut self, kqwq: KqId, req: ReqId, thread: i32) -> u8 {
        let old = self.darwin_workq_req(req).kq_override_index;
        assert_eq!(self.darwin_kqr_bound(thread), Some(req));
        self.darwin_set_kqr_bound(thread, None);
        let r = self.darwin_workq_req_mut(req);
        r.thread = None;
        r.state = tr::IDLE;
        r.kq_override_index = qos::UNSPECIFIED;
        self.kq(kqwq).state &= !kq::R2K_ARMED;
        old
    }

    /// `kqworkq_update_override`.
    fn kqworkq_update_override(&mut self, kqwq: KqId, n: KnId, override_index: u8) {
        let queue_index = self.knote(n).qos_index;
        if override_index <= queue_index {
            return;
        }
        let req = self.kqworkq_get_request(kqwq, queue_index);
        let r = self.darwin_workq_req(req);
        let old = r.kq_override_index;
        if override_index > r.kq_qos_index.max(old) {
            self.darwin_workq_req_mut(req).kq_override_index = override_index;
            if let Some(s) = self.kqr_thread(req) {
                self.thread_set_kevent_override(s, override_index);
            }
        }
    }

    /// `kqueue_update_override`.
    fn kqueue_update_override(&mut self, kqid: KqId, n: KnId, q: u8) {
        if self.kq_state(kqid) & kq::WORKLOOP != 0 {
            self.kqworkloop_update_threads_qos(kqid, Utq::UpdateWakeupOverride, q);
        } else {
            self.kqworkq_update_override(kqid, n, q);
        }
    }

    // -- workloops -----------------------------------------------------------------------------------

    pub(crate) fn wl_req(&mut self, kqwl: KqId) -> ReqId {
        self.kq(kqwl).request.expect("a workloop's request")
    }

    /// `kqworkloop_override`.
    pub(crate) fn kqworkloop_override(&mut self, kqwl: KqId) -> u8 {
        let req = self.wl_req(kqwl);
        let r = self.darwin_workq_req(req);
        r.kq_qos_index.max(r.kq_override_index)
    }

    /// `kqr_thread`: the thread bound to the request.
    pub(crate) fn kqr_thread(&self, req: ReqId) -> Option<i32> {
        let r = self.darwin_workq_req(req);
        if r.state == tr::BOUND { r.thread } else { None }
    }

    /// `kqr_thread_requested`.
    fn kqr_thread_requested(&self, req: ReqId) -> bool {
        self.darwin_workq_req(req).state != tr::IDLE
    }

    /// `kqr_thread_requested_pending`.
    pub(crate) fn kqr_thread_requested_pending(&self, req: ReqId) -> bool {
        let s = self.darwin_workq_req(req).state;
        s > tr::IDLE && s < tr::BOUND
    }

    /// `kqworkloop_update_threads_qos`.
    pub(crate) fn kqworkloop_update_threads_qos(&mut self, kqwl: KqId, op: Utq, mut qos_: u8) {
        let req = self.wl_req(kqwl);
        let old_override = self.kqworkloop_override(kqwl);
        let mut recompute = true;
        match op {
            Utq::UpdateWakeupQos => {
                self.kq(kqwl).wakeup_qos = qos_;
                self.kqworkloop_request_fire_r2k(kqwl);
            }
            Utq::ResetWakeupOverride => self.darwin_workq_req_mut(req).kq_override_index = qos_,
            Utq::Parking | Utq::Unbinding | Utq::RecomputeWakeupQos => {
                if op != Utq::RecomputeWakeupQos {
                    self.darwin_workq_req_mut(req).kq_override_index = qos_;
                } else {
                    assert_eq!(qos_, qos::UNSPECIFIED);
                }
                if self.kq(kqwl).suppressed[0].is_empty() {
                    self.darwin_workq_req_mut(req).kq_override_index = qos::UNSPECIFIED;
                }
                self.kq(kqwl).wakeup_qos = 0;
                for i in (1..=KQWL_NBUCKETS).rev() {
                    if !self.kq(kqwl).queues[i - 1].is_empty() {
                        self.kq(kqwl).wakeup_qos = i as u8;
                        self.kqworkloop_request_fire_r2k(kqwl);
                        break;
                    }
                }
            }
            Utq::UpdateWakeupOverride => {}
            Utq::RedriveEvents => recompute = false,
            Utq::SetQosIndex => {
                self.darwin_workq_req_mut(req).kq_qos_index = qos_;
                recompute = false;
            }
            Utq::None => panic!("unknown kqwl thread qos update operation"),
        }
        if recompute {
            let wq_ = self.kq(kqwl).wakeup_qos;
            if qos_ < wq_ {
                qos_ = wq_;
            }
            let r = self.darwin_workq_req_mut(req);
            if r.kq_override_index < qos_ {
                r.kq_override_index = qos_;
            }
        }
        let owner = self.kq(kqwl).owner;
        let servicer = self.kqr_thread(req);
        let new_override = self.kqworkloop_override(kqwl);
        if let Some(o) = owner {
            if new_override != old_override {
                self.thread_set_kevent_override(o, new_override);
            }
        }
        if !self.kqr_thread_requested(req) {
            if owner.is_none() && self.kq(kqwl).wakeup_qos != 0 {
                let f = if op == Utq::Unbinding { kflags::ATTEMPT_REBIND } else { 0 };
                self.kqueue_threadreq_initiate(kqwl, req, new_override, f);
            }
        } else if let Some(s) = servicer {
            if self.darwin_kqueue_override(s) != new_override {
                self.thread_set_servicer_override(s, new_override);
                self.darwin_set_kqueue_override(s, new_override);
            }
        } else if new_override == qos::UNSPECIFIED {
            // No events to deliver any more: the servicer finds the
            // request has nothing for it.
        } else if old_override != new_override {
            self.kqueue_threadreq_modify(kqwl, req, new_override, kflags::NONE);
        }
    }

    /// `kqworkloop_request_fire_r2k_notification`.
    fn kqworkloop_request_fire_r2k(&mut self, kqwl: KqId) {
        if self.kq(kqwl).state & kq::R2K_ARMED == 0 {
            return;
        }
        self.kq(kqwl).state &= !kq::R2K_ARMED;
        let req = self.wl_req(kqwl);
        let t = self.darwin_workq_req(req).thread.expect("an armed workloop's servicer");
        self.darwin_set_astkevent(t, ast::RETURN_TO_KERNEL);
    }

    /// `kqworkloop_wakeup`.
    fn kqworkloop_wakeup(&mut self, kqwl: KqId, q: u8) {
        if q <= self.kq(kqwl).wakeup_qos {
            return;
        }
        let req = self.wl_req(kqwl);
        if self.kq(kqwl).state & kq::PROCESSING != 0 && self.kqr_thread(req) == Some(self.tid) {
            // The servicer is processing: it sees the event.
            return;
        }
        self.kqworkloop_update_threads_qos(kqwl, Utq::UpdateWakeupQos, q);
    }

    /// `kqworkloop_acknowledge_events`.
    fn kqworkloop_acknowledge_events(&mut self, kqwl: KqId) -> u8 {
        let mut q = qos::UNSPECIFIED;
        let supp: Vec<KnId> = self.kq(kqwl).suppressed[0].iter().copied().collect();
        for n in supp {
            let k = self.knote(n).clone();
            if filt_adjusts_qos(k.filtid) && k.status & kn::DISABLED != 0 && k.status & kn::DROPPING == 0 && k.flags & (ev::DISPATCH | ev::DISABLE) == ev::DISPATCH {
                q = q.max(k.qos_override);
                continue;
            }
            self.knote_unsuppress(n);
        }
        q
    }

    /// `kqworkloop_begin_processing`; -1 when the thread unbound.
    fn kqworkloop_begin_processing(&mut self, kqwl: KqId, flags: u32) -> i32 {
        let req = self.wl_req(kqwl);
        assert!(self.kq(kqwl).state & kq::PROCESSING == 0);
        self.kq(kqwl).state |= kq::PROCESSING;
        let op = if flags & kf::PARKING != 0 {
            if self.darwin_workq_req(req).flags & tr::OVERCOMMIT != 0 { Utq::Parking } else { Utq::Unbinding }
        } else if !self.kq(kqwl).suppressed[0].is_empty() {
            Utq::ResetWakeupOverride
        } else {
            Utq::None
        };
        if op == Utq::None {
            return 0;
        }
        let thread = self.darwin_workq_req(req).thread.expect("a bound workloop");
        let qo = self.kqworkloop_acknowledge_events(kqwl);
        if op == Utq::Unbinding {
            self.kqworkloop_unbind_locked(kqwl, thread, OverrideDrop::Immediately);
            self.kqworkloop_release_live(kqwl);
        }
        self.kqworkloop_update_threads_qos(kqwl, op, qo);
        let mut rc = 0;
        if op == Utq::Parking && (self.kq(kqwl).count == 0 || self.kq(kqwl).owner.is_some()) {
            self.kqworkloop_unbind_locked(kqwl, thread, OverrideDrop::Delayed);
            self.kqworkloop_release_live(kqwl);
            rc = -1;
        } else if op == Utq::Unbinding && self.kqr_thread(req) != Some(thread) {
            rc = -1;
        }
        if rc == -1 {
            self.kq(kqwl).state &= !kq::PROCESSING;
            self.kqworkloop_unbind_delayed_override_drop(thread);
        }
        rc
    }

    /// `kqworkloop_end_processing`; -1 when the parking thread has more.
    fn kqworkloop_end_processing(&mut self, kqwl: KqId, flags: u16, kevent_flags: u32) -> i32 {
        let req = self.wl_req(kqwl);
        if kevent_flags & kf::PARKING != 0 {
            let thread = self.darwin_workq_req(req).thread.expect("a bound workloop");
            assert!(flags & kq::PROCESSING != 0);
            let qo = self.kqworkloop_acknowledge_events(kqwl);
            self.kqworkloop_update_threads_qos(kqwl, Utq::Parking, qo);
            if self.kq(kqwl).wakeup_qos != 0 && self.kq(kqwl).owner.is_none() {
                return -1;
            }
            self.kqworkloop_unbind_locked(kqwl, thread, OverrideDrop::Delayed);
            self.kqworkloop_release_live(kqwl);
            self.kq(kqwl).state &= !flags;
            self.kqworkloop_unbind_delayed_override_drop(thread);
        } else {
            let q = self.kq(kqwl);
            q.state &= !flags;
            q.state |= kq::R2K_ARMED;
            self.kqworkloop_update_threads_qos(kqwl, Utq::RecomputeWakeupQos, 0);
        }
        0
    }

    /// `kqworkloop_unbind_locked`.
    fn kqworkloop_unbind_locked(&mut self, kqwl: KqId, thread: i32, how: OverrideDrop) {
        let req = self.wl_req(kqwl);
        assert_eq!(self.darwin_kqr_bound(thread), Some(req));
        self.darwin_set_kqr_bound(thread, None);
        if how == OverrideDrop::Immediately && self.darwin_kqueue_override(thread) != qos::UNSPECIFIED {
            self.thread_set_servicer_override(thread, qos::UNSPECIFIED);
            self.darwin_set_kqueue_override(thread, qos::UNSPECIFIED);
        }
        let r = self.darwin_workq_req_mut(req);
        r.thread = None;
        r.state = tr::IDLE;
        self.kq(kqwl).state &= !kq::R2K_ARMED;
    }

    /// `kqworkloop_unbind_delayed_override_drop`.
    fn kqworkloop_unbind_delayed_override_drop(&mut self, thread: i32) {
        assert!(self.darwin_kqr_bound(thread).is_none());
        if self.darwin_kqueue_override(thread) != qos::UNSPECIFIED {
            self.thread_set_servicer_override(thread, qos::UNSPECIFIED);
            self.darwin_set_kqueue_override(thread, qos::UNSPECIFIED);
        }
    }

    /// `kqworkloop_unbind`: the bound thread leaves its workloop.
    fn kqworkloop_unbind(&mut self, kqwl: KqId) {
        let req = self.wl_req(kqwl);
        let thread = self.darwin_workq_req(req).thread.expect("a bound workloop");
        assert_eq!(thread, self.tid);
        let mut qo = qos::UNSPECIFIED;
        assert!(self.kq(kqwl).state & kq::PROCESSING == 0);
        if !self.kq(kqwl).suppressed[0].is_empty() {
            self.kq(kqwl).state |= kq::PROCESSING;
            qo = self.kqworkloop_acknowledge_events(kqwl);
            self.kq(kqwl).state &= !kq::PROCESSING;
        }
        self.kqworkloop_unbind_locked(kqwl, thread, OverrideDrop::Delayed);
        self.kqworkloop_update_threads_qos(kqwl, Utq::Parking, qo);
        self.kqworkloop_unbind_delayed_override_drop(thread);
        self.kqworkloop_release(kqwl);
    }

    /// `kqworkloop_set_overcommit`.
    fn kqworkloop_set_overcommit(&mut self, kqwl: KqId) {
        let req = self.wl_req(kqwl);
        if self.darwin_workq_req(req).flags & tr::OVERCOMMIT != 0 {
            return;
        }
        if self.kqr_thread_requested_pending(req) {
            let q = self.darwin_workq_req(req).qos;
            self.kqueue_threadreq_modify(kqwl, req, q, kflags::MAKE_OVERCOMMIT);
        } else {
            self.darwin_workq_req_mut(req).flags |= tr::OVERCOMMIT;
        }
    }

    // -- thread requests -------------------------------------------------------------------------------

    /// `kqueue_threadreq_can_use_ast`: the calling thread is in one of the
    /// calls that redrive a thread request on their way out.
    fn kqueue_threadreq_can_use_ast(&self) -> bool {
        use super::sysno as sys;
        let code = self.dtask.threads.map.get(&self.tid).map_or(0, |t| t.syscall_code);
        matches!(code, sys::KEVENT_QOS | sys::KEVENT_ID | sys::WORKQ_KERNRETURN | sys::BSDTHREAD_CTL)
    }

    /// `kqueue_threadreq_initiate`.
    fn kqueue_threadreq_initiate(&mut self, kqid: KqId, req: ReqId, mut q: u8, mut flags: u32) {
        assert!(self.kqr_thread(req).is_none());
        assert!(!self.kqr_thread_requested(req));
        if self.darwin_workq_is_exiting() {
            return;
        }
        if self.kq_state(kqid) & kq::WORKLOOP != 0 {
            assert!(self.kq(kqid).owner.is_none());
            self.kqworkloop_retain(kqid);
        }
        if self.kqueue_threadreq_can_use_ast() {
            flags |= kflags::SET_AST_ON_FAILURE;
        }
        if q == KQWQ_QOS_MANAGER {
            q = super::workq::QOS_MANAGER;
        }
        if !self.darwin_workq_threadreq_initiate(req, q, flags) {
            self.kq(kqid).state &= !kq::R2K_ARMED;
            self.kqueue_release_live(kqid);
        }
    }

    /// `kqueue_threadreq_modify`.
    fn kqueue_threadreq_modify(&mut self, _kqid: KqId, req: ReqId, q: u8, mut flags: u32) {
        assert!(self.kqr_thread_requested_pending(req));
        if self.kqueue_threadreq_can_use_ast() {
            flags |= kflags::SET_AST_ON_FAILURE;
        }
        self.darwin_workq_threadreq_modify(req, q, flags);
    }

    /// `kqueue_threadreq_bind_prepost`.
    pub(crate) fn kqueue_threadreq_bind_prepost(&mut self, req: ReqId, tid: i32) {
        self.darwin_set_kqr_bound(tid, Some(req));
        let r = self.darwin_workq_req_mut(req);
        r.thread = Some(tid);
        r.state = tr::BINDING;
    }

    /// `kqueue_threadreq_bind_commit`.
    pub(crate) fn kqueue_threadreq_bind_commit(&mut self, tid: i32) {
        let req = self.darwin_kqr_bound(tid).expect("a preposted bind");
        if self.darwin_workq_req(req).state == tr::BINDING {
            self.kqueue_threadreq_bind(req, tid);
        }
    }

    /// `kqueue_threadreq_bind`.
    pub(crate) fn kqueue_threadreq_bind(&mut self, req: ReqId, tid: i32) {
        let kqid = self.kqr_kqueue(req);
        assert_eq!(self.darwin_kqueue_override(tid), 0);
        if self.darwin_workq_req(req).state == tr::BINDING {
            assert_eq!(self.darwin_kqr_bound(tid), Some(req));
        } else {
            assert!(self.kqr_thread_requested_pending(req));
            assert!(self.darwin_kqr_bound(tid).is_none());
            self.darwin_set_kqr_bound(tid, Some(req));
            self.darwin_workq_req_mut(req).thread = Some(tid);
        }
        self.darwin_workq_req_mut(req).state = tr::BOUND;
        if self.kq_state(kqid) & kq::WORKLOOP != 0 {
            if self.kq(kqid).owner == Some(tid) {
                // The owner became the servicer: its kevent override goes.
                self.kq(kqid).owner = None;
                if self.kqworkloop_override(kqid) != 0 {
                    self.thread_set_kevent_override(tid, qos::UNSPECIFIED);
                }
            }
            let o = self.darwin_workq_req(req).kq_override_index;
            self.darwin_set_kqueue_override(tid, o);
            if o != 0 {
                self.thread_set_servicer_override(tid, o);
            }
        } else {
            assert_eq!(self.darwin_workq_req(req).kq_override_index, 0);
        }
    }

    /// `kqueue_threadreq_cancel`.
    pub(crate) fn kqueue_threadreq_cancel(&mut self, req: ReqId) {
        let kqid = self.kqr_kqueue(req);
        self.kqueue_release(kqid);
    }

    /// `kqueue_threadreq_workloop_param`.
    pub(crate) fn kqueue_threadreq_workloop_param(&self, req: ReqId) -> u64 {
        let kqid = self.kqr_kqueue(req);
        self.dtask.kevents.kqs[&kqid].params
    }

    /// `kqueue_threadreq_unbind`.
    pub(crate) fn kqueue_threadreq_unbind(&mut self, req: ReqId) {
        let kqid = self.kqr_kqueue(req);
        if self.darwin_workq_req(req).flags & tr::WORKLOOP != 0 {
            self.kqworkloop_unbind(kqid);
        } else {
            let rc = self.kqworkq_acknowledge_events(kqid, req, 0, true);
            assert_eq!(rc, -1);
        }
    }

    // -- the calls ---------------------------------------------------------------------------------------

    /// `kevent_internal`: `Ok(Ok(n))` the events out, `Ok(Err(block))` a
    /// wait.
    #[allow(clippy::too_many_arguments)]
    fn kevent_internal(&mut self, m: &mut GuestMem<'_>, kqid: KqId, mut changelist: u64, mut nchanges: i32, mut ueventlist: u64, nevents: i32, mut flags: u32, ctx: &mut Ctx, out: Out) -> Result<Result<i32, SyscallOutcome>, Errno> {
        let mut noutputs = 0i32;
        if out == Out::Modern && flags & kf::WORKLOOP != 0 {
            if flags & kf::KERNEL != 0 {
                // kevent_workq_internal: the workloop's id goes just before
                // the events, out of the data buffer.
                let id = self.kq(kqid).dynamicid;
                let r = m.write_u64(ueventlist - 8, id);
                ctx.data_resid -= 8;
                if let Err(e) = r {
                    return self.kevent_cleanup(m, kqid, flags, Err(e), ctx).map(|()| Ok(0));
                }
            }
            if requesting_events(flags, nevents) {
                self.kq(kqid).state &= !kq::R2K_ARMED;
                flags |= kf::NEEDS_END_PROCESSING;
            }
        }
        let mut error: Result<(), Errno> = Ok(());
        while nchanges > 0 && error.is_ok() {
            let copied = match out {
                Out::Legacy => kevent_legacy_copyin(m, &mut changelist, flags),
                Out::Modern => kevent_modern_copyin(m, &mut changelist),
            };
            let mut kev = match copied {
                Ok(k) => k,
                Err(e) => {
                    error = Err(e);
                    break;
                }
            };
            let (rc, wait_kn) = self.kevent_register(m, kqid, &mut kev);
            if out == Out::Modern && rc & filter::REGISTER_WAIT != 0 {
                let me = self.tid;
                if self.darwin_clear_astkevent(me, ast::REDRIVE_THREADREQ) {
                    self.darwin_workq_threadreq_redrive(m, kflags::NONE);
                }
                if nchanges == 1 && noutputs < nevents && flags & (kf::KERNEL | kf::PARKING) == 0 && flags & kf::ERROR_EVENTS != 0 && flags & kf::WORKLOOP != 0 {
                    let n = wait_kn.expect("the knote that waits");
                    let block = self.filt_wlpost_register_wait(m, kqid, n, kev, noutputs, ueventlist);
                    return Ok(Err(block));
                }
                kev.set_error(Errno::EOPNOTSUPP);
            }
            if noutputs < nevents && kev.flags & (ev::ERROR | ev::RECEIPT) != 0 {
                if kev.flags & ev::ERROR == 0 {
                    kev.flags |= ev::ERROR;
                    kev.data = 0;
                }
                let r = match out {
                    Out::Legacy => kevent_legacy_copyout(m, &kev, &mut ueventlist, flags),
                    Out::Modern => kevent_modern_copyout(m, &kev, &mut ueventlist),
                };
                match r {
                    Ok(()) => noutputs += 1,
                    Err(e) => error = Err(e),
                }
            } else if kev.flags & ev::ERROR != 0 {
                error = Err(kev_errno(kev.data));
            }
            nchanges -= 1;
        }
        if flags & kf::ERROR_EVENTS == 0 && nevents > 0 && noutputs == 0 && error.is_ok() {
            ctx.process_flags = flags;
            ctx.process_nevents = nevents;
            ctx.process_noutputs = 0;
            ctx.process_eventlist = ueventlist;
            match self.kqueue_scan(m, kqid, flags, ctx, out) {
                Ok(Some(block)) => return Ok(Err(block)),
                Ok(None) => {}
                Err(e) => error = Err(e),
            }
            noutputs = ctx.process_noutputs;
        } else if out == Out::Modern && flags & kf::NEEDS_END_PROCESSING != 0 {
            // kqueue_scan did not run kqworkloop_end_processing.
            self.kqworkloop_end_processing(kqid, 0, 0);
        }
        self.kevent_cleanup(m, kqid, flags, error, ctx).map(|()| Ok(noutputs))
    }

    /// `kevent_cleanup`.
    fn kevent_cleanup(&mut self, m: &mut GuestMem<'_>, kqid: KqId, flags: u32, error: Result<(), Errno>, ctx: &mut Ctx) -> Result<(), Errno> {
        if flags & kf::WORKLOOP != 0 {
            self.kqworkloop_release(kqid);
        }
        if error.is_ok() {
            // A failed copyout of the residual size abandons no output.
            let _ = kevent_put_data_size(m, flags, ctx);
        }
        error
    }

    /// `kevent_get_data_size`.
    fn kevent_get_data_size(m: &GuestMem<'_>, data_avail: u64, data_out: u64, ctx: &mut Ctx) -> Result<(), Errno> {
        if data_avail == 0 || data_out == 0 {
            ctx.data_size = 0;
            ctx.data_resid = 0;
        } else {
            let size = m.read_u64(data_avail)?;
            ctx.data_size = size;
            ctx.data_resid = size;
        }
        ctx.data_out = data_out;
        ctx.data_avail = data_avail;
        Ok(())
    }

    /// `kevent_get_kqfile`.
    fn kevent_get_kqfile(&mut self, fd: i32, flags: u32) -> Result<KqId, Errno> {
        let f = self.fd_io().fds.get(fd)?;
        let Some(h) = Arc::clone(&f.handle).as_kqueue() else { return Err(Errno::EBADF) };
        let kqid = h.id();
        let q = self.kq(kqid);
        if q.state & (kq::KEV32 | kq::KEV64 | kq::KEV_QOS) == 0 {
            q.state |= if flags & kf::LEGACY32 != 0 {
                kq::KEV32
            } else if flags & kf::LEGACY64 != 0 {
                kq::KEV64
            } else {
                kq::KEV_QOS
            };
        }
        // A kqueue is used through kevent() or the other calls, not both.
        if (flags & kf::LEGACY32 != 0) != (q.state & kq::KEV32 != 0) {
            return Err(Errno::EINVAL);
        }
        Ok(kqid)
    }

    /// `kevent_get_kqwq`.
    fn kevent_get_kqwq(&mut self, flags: u32, nevents: i32) -> Result<KqId, Errno> {
        if requesting_events(flags, nevents) {
            return Err(Errno::EINVAL);
        }
        Ok(match self.kev().wqkqueue {
            Some(k) => k,
            None => self.kqworkq_alloc(flags),
        })
    }

    fn kevent_finish(&mut self, m: &mut GuestMem<'_>, r: Result<Result<i32, SyscallOutcome>, Errno>) -> SyscallOutcome {
        match r {
            Ok(Err(block)) => block,
            Ok(Ok(n)) => {
                self.darwin_kevent_settle(m);
                super::thread::bsd_result(m, self.ctx_addr, Ok(n as u32 as u64), false);
                SyscallOutcome::Continue
            }
            Err(e) => {
                self.darwin_kevent_settle(m);
                super::thread::bsd_result(m, self.ctx_addr, Err(e), false);
                SyscallOutcome::Continue
            }
        }
    }

    /// An argument past the sixth, from its register.
    fn bsd_arg_reg(&self, m: &GuestMem<'_>, i: u8) -> u64 {
        m.read_u64(self.ctx_addr + gex_abi::ctx::x(self.darwin_arg_base + i) as u64).unwrap_or(0)
    }

    /// `kevent_qos(fd, changelist, nchanges, eventlist, nevents, data_out,
    /// data_available, flags)`.
    pub(crate) fn darwin_kevent_qos(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> SyscallOutcome {
        let (data_available, uflags) = (self.bsd_arg_reg(m, 6), self.bsd_arg_reg(m, 7) as u32);
        let mut flags = uflags & kf::USER;
        let r = (|| {
            if flags & kf::ID_USER != 0 {
                return Err(Errno::EINVAL);
            }
            flags |= kf::PROC64;
            let mut ctx = Ctx { fd: a[0] as i32, ..Ctx::default() };
            Self::kevent_get_data_size(m, data_available, a[5], &mut ctx)?;
            let kqid = if flags & kf::WORKQ != 0 { self.kevent_get_kqwq(flags, a[4] as i32)? } else { self.kevent_get_kqfile(a[0] as i32, flags)? };
            self.kevent_internal(m, kqid, a[1], a[2] as i32, a[3], a[4] as i32, flags, &mut ctx, Out::Modern)
        })();
        self.kevent_finish(m, r)
    }

    /// `kevent_id(id, changelist, nchanges, eventlist, nevents, data_out,
    /// data_available, flags)`.
    pub(crate) fn darwin_kevent_id(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> SyscallOutcome {
        let (data_available, uflags) = (self.bsd_arg_reg(m, 6), self.bsd_arg_reg(m, 7) as u32);
        let mut flags = uflags & kf::USER;
        let r = (|| {
            flags |= kf::PROC64 | kf::DYNAMIC_KQUEUE;
            if flags & (kf::WORKQ | kf::WORKLOOP) != kf::WORKLOOP {
                return Err(Errno::EINVAL);
            }
            let mut ctx = Ctx { fd: -1, ..Ctx::default() };
            Self::kevent_get_data_size(m, data_available, a[5], &mut ctx)?;
            let id = a[0];
            let bound = self.darwin_kqr_bound(self.tid).filter(|&r| self.darwin_workq_req(r).flags & tr::WORKLOOP != 0).map(|r| self.kqr_kqueue(r));
            let kqwl = match bound {
                Some(k) if self.kq(k).dynamicid == id => {
                    if flags & kf::DYNAMIC_KQ_MUST_NOT_EXIST != 0 {
                        return Err(Errno::EEXIST);
                    }
                    self.kqworkloop_retain(k);
                    k
                }
                // Only a bound thread receives a workloop's events.
                _ if requesting_events(flags, a[4] as i32) => return Err(Errno::EXDEV),
                _ => self.kqworkloop_get_or_create(id, None, flags)?,
            };
            self.kevent_internal(m, kqwl, a[1], a[2] as i32, a[3], a[4] as i32, flags, &mut ctx, Out::Modern)
        })();
        self.kevent_finish(m, r)
    }

    /// `kevent(fd, changelist, nchanges, eventlist, nevents, timeout)` and
    /// `kevent64(fd, changelist, nchanges, eventlist, nevents, flags,
    /// timeout)`.
    pub(crate) fn darwin_kevent_legacy(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6], kev64: bool) -> SyscallOutcome {
        let (uflags, timeout) = if kev64 { (a[5] as u32, self.bsd_arg_reg(m, 6)) } else { (0, a[5]) };
        let mut flags = if kev64 { (uflags & kf::USER) | kf::LEGACY64 } else { kf::LEGACY32 };
        let r = (|| {
            if uflags & kf::ID_USER != 0 {
                return Err(Errno::EINVAL);
            }
            flags |= kf::PROC64;
            let mut ctx = Ctx { fd: a[0] as i32, ..Ctx::default() };
            if timeout != 0 && flags & kf::IMMEDIATE == 0 {
                // kevent_legacy_get_deadline: a user64_timespec.
                let (s, ns) = (m.read_u64(timeout)? as i64, m.read_u64(timeout + 8)? as i64);
                if s < 0 || !(0..1_000_000_000).contains(&ns) {
                    return Err(Errno::EINVAL);
                }
                ctx.deadline = Some(Instant::now() + std::time::Duration::new(s as u64, ns as u32));
            }
            let kqid = if flags & kf::WORKQ != 0 { self.kevent_get_kqwq(flags, a[4] as i32)? } else { self.kevent_get_kqfile(a[0] as i32, flags)? };
            self.kevent_internal(m, kqid, a[1], a[2] as i32, a[3], a[4] as i32, flags, &mut ctx, Out::Legacy)
        })();
        self.kevent_finish(m, r)
    }

    /// `kevent_workq_internal`: the events a bound workqueue thread is
    /// started with or parks with, onto its stack (libpthread's
    /// `workq_kevent`). The count of events out.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn darwin_kevent_workq_internal(&mut self, m: &mut GuestMem<'_>, changelist: u64, nchanges: i32, eventlist: u64, nevents: i32, data_out: u64, data_available: &mut u64, flags: u32) -> Result<i32, Errno> {
        assert!(flags == kf::STACK_DATA | kf::IMMEDIATE || flags == kf::STACK_DATA | kf::IMMEDIATE | kf::PARKING);
        let req = self.darwin_kqr_bound(self.tid).expect("a bound workqueue thread");
        let mut ctx = Ctx { data_out, data_avail: 0, data_size: *data_available, data_resid: *data_available, deadline: None, fd: -1, ..Ctx::default() };
        let mut flags = flags | kf::PROC64;
        let kqid = if self.darwin_workq_req(req).flags & tr::WORKLOOP != 0 {
            let k = self.kqr_kqueue(req);
            self.kqworkloop_retain(k);
            flags |= kf::WORKLOOP | kf::DYNAMIC_KQUEUE | kf::KERNEL;
            k
        } else {
            flags |= kf::WORKQ | kf::KERNEL;
            self.kev().wqkqueue.expect("the workqueue kqueue")
        };
        let r = self.kevent_internal(m, kqid, changelist, nchanges, eventlist, nevents, flags, &mut ctx, Out::Modern);
        // kevent_put_data_size, for a call in the kernel.
        *data_available = ctx.data_resid;
        self.darwin_kevent_settle(m);
        match r {
            Ok(Ok(n)) => Ok(n),
            Ok(Err(_)) => panic!("a workqueue thread's kevent never blocks"),
            Err(e) => Err(e),
        }
    }

    /// `kqueue_workloop_ctl(cmd, options, addr, sz)`.
    pub(crate) fn darwin_kqueue_workloop_ctl(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        const CREATE: u64 = 0x01;
        const DESTROY: u64 = 0x02;
        const SCHED_PRI: i32 = 0x01;
        const SCHED_POL: i32 = 0x02;
        const CPU_PERCENT: i32 = 0x04;
        const WORK_INTERVAL: i32 = 0x08;
        let (cmd, addr, sz) = (a[0], a[2], a[3]);
        // struct kqueue_workloop_params (packed): version, flags, id,
        // sched_pri, sched_pol, cpu_percent, cpu_refillms, wi_port.
        const PSIZE: u64 = 4 + 4 + 8 + 4 + 4 + 4 + 4 + 4;
        if sz < 4 {
            return Err(Errno::EINVAL);
        }
        let mut p = [0u8; PSIZE as usize];
        let n = sz.min(PSIZE) as usize;
        p[..n].copy_from_slice(m.read(addr, n)?);
        let i32_ = |o: usize| i32::from_le_bytes(p[o..o + 4].try_into().unwrap());
        let (version, pflags, id) = (i32_(0), i32_(4), u64::from_le_bytes(p[8..16].try_into().unwrap()));
        let (sched_pri, sched_pol, cpu_percent, cpu_refillms) = (i32_(16), i32_(20), i32_(24), i32_(28));
        if version != sz as i32 {
            return Err(Errno::EINVAL);
        }
        match cmd {
            CREATE => {
                if pflags == 0 {
                    return Err(Errno::EINVAL);
                }
                if pflags & SCHED_PRI != 0 && !(1..=63).contains(&sched_pri) {
                    return Err(Errno::EINVAL);
                }
                // invalid_policy: POLICY_TIMESHARE (1), POLICY_RR (2) and
                // POLICY_FIFO (4) are the policies.
                if pflags & SCHED_POL != 0 && !matches!(sched_pol, 1 | 2 | 4) {
                    return Err(Errno::EINVAL);
                }
                if pflags & CPU_PERCENT != 0 && (cpu_percent <= 0 || cpu_percent > 100 || cpu_refillms <= 0 || cpu_refillms > 0x00ff_ffff) {
                    return Err(Errno::EINVAL);
                }
                if pflags & WORK_INTERVAL != 0 {
                    // kern_work_interval_get_policy_from_port.
                    self.darwin_unimplemented("workloops with work intervals".into());
                    return Err(Errno::EINVAL);
                }
                let (mut tf, mut pri, mut pol, mut cpu, mut refill) = (0u16, 0u8, 0u8, 0u8, 0u32);
                if pflags & SCHED_PRI != 0 {
                    tf |= super::workq::TRP_PRIORITY;
                    pri = sched_pri as u8;
                }
                if pflags & SCHED_POL != 0 {
                    tf |= super::workq::TRP_POLICY;
                    pol = sched_pol as u8;
                }
                if pflags & CPU_PERCENT != 0 {
                    tf |= super::workq::TRP_CPUPERCENT;
                    cpu = cpu_percent as u8;
                    refill = cpu_refillms as u32;
                }
                // workq_threadreq_param_t: flags, pri, pol, then the CPU
                // percent and refill (8 and 24 bits).
                let trp = u64::from(tf) | u64::from(pri) << 16 | u64::from(pol) << 24 | u64::from(cpu) << 32 | u64::from(refill & 0x00ff_ffff) << 40;
                self.kqworkloop_get_or_create(id, Some(trp), kf::DYNAMIC_KQUEUE | kf::WORKLOOP | kf::DYNAMIC_KQ_MUST_NOT_EXIST)?;
                Ok(0)
            }
            DESTROY => {
                let kqwl = self.kqworkloop_get_or_create(id, None, kf::DYNAMIC_KQUEUE | kf::WORKLOOP | kf::DYNAMIC_KQ_MUST_EXIST)?;
                let trp = self.kq(kqwl).params;
                let tf = trp as u16;
                let r = if tf != 0 && tf & TRP_RELEASED == 0 {
                    self.kq(kqwl).params = (trp & !0xffff) | u64::from(tf | TRP_RELEASED);
                    self.kqworkloop_release_live(kqwl);
                    Ok(0)
                } else {
                    Err(Errno::EINVAL)
                };
                self.kqworkloop_release(kqwl);
                r
            }
            _ => Ok(0),
        }
    }

    /// A blocked kevent call has woken.
    pub(crate) fn darwin_kevent_wait_done(&mut self, m: &mut GuestMem<'_>, c: Cont, res: WaitResult) -> Option<SyscallOutcome> {
        match c {
            Cont::Scan { kq: kqid, mut ctx } => {
                // kqueue_scan_continue
                let tid = self.tid;
                if let Some(q) = self.kev().kqs.get_mut(&kqid) {
                    q.sleepers.retain(|&t| t != tid);
                }
                let flags = ctx.process_flags;
                let r = match res {
                    WaitResult::Awakened => {
                        let out = if flags & (kf::LEGACY32 | kf::LEGACY64) != 0 { Out::Legacy } else { Out::Modern };
                        match self.kqueue_scan(m, kqid, flags, &mut ctx, out) {
                            Ok(Some(block)) => return Some(block),
                            Ok(None) => Ok(()),
                            Err(e) => Err(e),
                        }
                    }
                    WaitResult::TimedOut => Ok(()),
                    WaitResult::Interrupted => Err(Errno::EINTR),
                    WaitResult::Restart => Err(Errno::EBADF),
                };
                let r = self.kevent_cleanup(m, kqid, flags, r, &mut ctx).map(|()| ctx.process_noutputs as u32 as u64);
                self.darwin_kevent_settle(m);
                super::thread::bsd_result(m, self.ctx_addr, r, false);
                None
            }
            Cont::WlWait { kqwl, mut kev, mut eventout, mut ueventlist } => {
                // filt_wlwait_continue, then kevent_register_wait_return.
                match res {
                    WaitResult::Interrupted => kev.set_error(Errno::EINTR),
                    WaitResult::Awakened => {}
                    r => panic!("Unexpected wait result: {r:?}"),
                }
                let mut error = Ok(());
                if kev.flags & (ev::ERROR | ev::RECEIPT) != 0 {
                    if kev.flags & ev::ERROR == 0 {
                        kev.flags |= ev::ERROR;
                        kev.data = 0;
                    }
                    error = kevent_modern_copyout(m, &kev, &mut ueventlist);
                    if error.is_ok() {
                        eventout += 1;
                    }
                }
                self.kqworkloop_release(kqwl);
                self.darwin_kevent_settle(m);
                super::thread::bsd_result(m, self.ctx_addr, error.map(|()| eventout as u32 as u64), false);
                None
            }
        }
    }

    /// What kevent owes after a call: closed kqueues freed, then what IPC
    /// owes (its notifications, the Mach port knotes, the threads woken,
    /// the workqueue settled: [`Self::darwin_ipc_settle`]).
    pub(crate) fn darwin_kevent_settle(&mut self, m: &mut GuestMem<'_>) {
        self.darwin_kqueue_reap();
        self.darwin_ipc_settle(m);
    }

    /// The knotes the IPC layer owes posted, and the threads kevent woke
    /// woken.
    pub(crate) fn darwin_kevent_owed(&mut self, m: &mut GuestMem<'_>) {
        self.darwin_machport_knotes();
        self.darwin_signal_knotes();
        for (t, wr) in std::mem::take(&mut self.kev().wake) {
            self.darwin_wake(m, t, wr);
        }
    }
}

/// `kevent_args_requesting_events`.
fn requesting_events(flags: u32, nevents: i32) -> bool {
    flags & kf::ERROR_EVENTS == 0 && nevents > 0
}

/// `knote_has_qos`.
fn knote_has_qos(k: &Knote) -> bool {
    k.qos_override > 0 && k.qos_override < qos::LAST
}

/// `_pthread_priority_normalize`.
pub(crate) fn pp_normalize(p: u64) -> u64 {
    if p & pp::EVENT_MANAGER_FLAG != 0 {
        return pp::EVENT_MANAGER_FLAG;
    }
    if pp::qos(p) != 0 {
        let mut p = p;
        let relpri = pp::relpri(p);
        if relpri > 0 || relpri < super::thread::qos::MIN_TIER_IMPORTANCE {
            p |= pp::PRIORITY_MASK;
        }
        return p & (pp::OVERCOMMIT_FLAG | PP_FALLBACK_FLAG | PP_QOS_CLASS_MASK | pp::PRIORITY_MASK);
    }
    0
}

/// `_pthread_priority_combine`.
fn pp_combine(base: u64, q: u8) -> u64 {
    if base & pp::EVENT_MANAGER_FLAG != 0 {
        return pp::EVENT_MANAGER_FLAG;
    }
    if base & PP_FALLBACK_FLAG != 0 {
        if q == 0 {
            return base;
        }
    } else if q < pp::qos(base) {
        return base;
    }
    pp::from_qos(q, 0, base & pp::OVERCOMMIT_FLAG)
}

/// The filters on descriptors (`f_isfd`): `file_filtops`'.
fn filt_isfd(fid: u8) -> bool {
    [evfilt::READ, evfilt::WRITE, evfilt::VNODE, evfilt::SOCK, evfilt::EXCEPT, evfilt::NW_CHANNEL].iter().any(|&f| (!f) as u8 == fid)
}

/// `f_adjusts_qos`: the Mach port filters.
pub(crate) fn filt_adjusts_qos(fid: u8) -> bool {
    fid == (!evfilt::MACHPORT) as u8 || fid == filtid::MACH_PORT || fid == filtid::MACH_PORT_SET
}

/// `f_extended_codes`: the filters whose results are `FILTER_*` bits; any
/// other's nonzero result means active.
fn filt_extended_codes(fid: u8) -> bool {
    [evfilt::TIMER, evfilt::USER, evfilt::WORKLOOP, evfilt::MACHPORT].iter().any(|&f| (!f) as u8 == fid) || fid == filtid::MACH_PORT || fid == filtid::MACH_PORT_SET
}

/// `f_allow_drop`: the workloop filter's.
fn filt_has_allow_drop(fid: u8) -> bool {
    fid == (!evfilt::WORKLOOP) as u8
}

/// `kevent_legacy_copyin`.
fn kevent_legacy_copyin(m: &GuestMem<'_>, addr: &mut u64, flags: u32) -> Result<Kev, Errno> {
    let u64_ = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    if flags & kf::LEGACY64 != 0 {
        // struct kevent64_s: ident, filter, flags, fflags, data, udata, ext[2].
        let b = m.read(*addr, 48)?;
        let k = Kev {
            ident: u64_(b, 0),
            filter: i16::from_le_bytes([b[8], b[9]]),
            flags: u16::from_le_bytes([b[10], b[11]]) & !ev::SYSFLAGS,
            fflags: u32::from_le_bytes(b[12..16].try_into().unwrap()),
            data: u64_(b, 16) as i64,
            udata: u64_(b, 24),
            ext: [u64_(b, 32), u64_(b, 40), 0, 0],
            ..Kev::default()
        };
        *addr += 48;
        return Ok(k);
    }
    // struct user64_kevent: ident, filter, flags, fflags, data, udata.
    let b = m.read(*addr, 32)?;
    let k = Kev {
        ident: u64_(b, 0),
        filter: i16::from_le_bytes([b[8], b[9]]),
        flags: u16::from_le_bytes([b[10], b[11]]) & !ev::SYSFLAGS,
        fflags: u32::from_le_bytes(b[12..16].try_into().unwrap()),
        data: u64_(b, 16) as i64,
        udata: u64_(b, 24),
        ..Kev::default()
    };
    *addr += 32;
    Ok(k)
}

/// `kevent_modern_copyin`.
fn kevent_modern_copyin(m: &GuestMem<'_>, addr: &mut u64) -> Result<Kev, Errno> {
    let mut k = Kev::from_qos(m.read(*addr, Kev::QOS_SIZE)?);
    *addr += Kev::QOS_SIZE as u64;
    k.flags &= !ev::SYSFLAGS;
    Ok(k)
}

/// `kevent_legacy_copyout`.
fn kevent_legacy_copyout(m: &mut GuestMem<'_>, k: &Kev, addr: &mut u64, flags: u32) -> Result<(), Errno> {
    let mut b = Vec::with_capacity(48);
    b.extend_from_slice(&k.ident.to_le_bytes());
    b.extend_from_slice(&k.filter.to_le_bytes());
    b.extend_from_slice(&k.flags.to_le_bytes());
    b.extend_from_slice(&k.fflags.to_le_bytes());
    b.extend_from_slice(&k.data.to_le_bytes());
    b.extend_from_slice(&k.udata.to_le_bytes());
    if flags & kf::LEGACY64 != 0 {
        b.extend_from_slice(&k.ext[0].to_le_bytes());
        b.extend_from_slice(&k.ext[1].to_le_bytes());
    }
    m.write(*addr, &b)?;
    *addr += b.len() as u64;
    Ok(())
}

/// `kevent_modern_copyout`.
fn kevent_modern_copyout(m: &mut GuestMem<'_>, k: &Kev, addr: &mut u64) -> Result<(), Errno> {
    m.write(*addr, &k.to_qos())?;
    *addr += Kev::QOS_SIZE as u64;
    Ok(())
}

/// `kevent_put_data_size`: the data size left, when some was used; a call
/// in the kernel reads it from the context itself.
fn kevent_put_data_size(m: &mut GuestMem<'_>, flags: u32, ctx: &Ctx) -> Result<(), Errno> {
    if ctx.data_resid == ctx.data_size || flags & kf::KERNEL != 0 {
        return Ok(());
    }
    m.write_u64(ctx.data_avail, ctx.data_resid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kevent_qos_round_trips_through_its_72_bytes() {
        let k = Kev { ident: 7, filter: evfilt::USER, flags: ev::ADD | ev::CLEAR, qos: 0x22ff, udata: 0x1234, fflags: 0x0100_0000, xflags: 0, data: -3, ext: [1, 2, 3, 4] };
        assert_eq!(Kev::from_qos(&k.to_qos()), k);
    }

    #[test]
    fn the_descriptor_filters_are_files_ones() {
        assert!(filt_isfd((!evfilt::READ) as u8));
        assert!(filt_isfd((!evfilt::VNODE) as u8));
        assert!(!filt_isfd((!evfilt::MACHPORT) as u8));
        assert!(!filt_isfd((!evfilt::USER) as u8));
    }

    #[test]
    fn combining_a_priority_raises_its_qos_to_the_override() {
        let ut = pp::from_qos(qos::UTILITY, 0, 0);
        assert_eq!(pp::qos(pp_combine(ut, qos::USER_INITIATED)), qos::USER_INITIATED);
        assert_eq!(pp_combine(ut, qos::BACKGROUND), ut);
        assert_eq!(pp_combine(pp::EVENT_MANAGER_FLAG, qos::USER_INITIATED), pp::EVENT_MANAGER_FLAG);
    }
}
