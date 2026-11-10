//! Mach IPC, ported from XNU's `osfmk/ipc` at the tag the profile pins:
//! ports and port sets, the rights a task's name space holds to them, and
//! the notifications rights changes send.
//!
//! Objects live in one table for the task; an entry in the task's
//! [`space::Space`] names an object and says which rights it holds. As in
//! XNU, a send right to a port that has died is noticed when the entry is
//! next used ([`Ipc::right_check`]), which turns it into a dead name.

pub mod msg;
pub mod port;
pub mod right;
pub mod space;

use crate::errno::Errno;
use crate::syscalls::{Kernel, SyscallOutcome};
use crate::GuestMem;

/// Mach messaging as the system calls reach it: the traps, a blocked
/// message's continuation, and what an operation owes when it is done.
///
/// This, [`KQueue`] and [`WorkQueue`] are where the Darwin system calls
/// meet the IPC, kqueue and workqueue they use. [`Native`] is the port of
/// XNU's code here; a build of XNU's own `osfmk/ipc` and `bsd/kern` can
/// take its place by implementing them and being named in [`Mach`],
/// [`Kq`] and [`Wq`].
pub trait MachIpc {
    /// `mach_msg2_trap`.
    fn mach_msg2(k: &mut Kernel, m: &mut GuestMem<'_>, a: &[u64; 6]) -> SyscallOutcome;
    /// `mach_msg_trap` and `mach_msg_overwrite_trap`.
    fn mach_msg_trap(k: &mut Kernel, m: &mut GuestMem<'_>, a: &[u64; 6], overwrite: bool) -> SyscallOutcome;
    /// A blocked send or receive has woken.
    fn wait_done(k: &mut Kernel, m: &mut GuestMem<'_>, c: crate::darwin::mach_msg::Cont, res: crate::darwin::wait::WaitResult) -> Option<SyscallOutcome>;
    /// What an IPC operation owes: notifications sent, threads woken.
    fn settle(k: &mut Kernel, m: &mut GuestMem<'_>);
}

/// The kqueue calls (`bsd/kern/kern_event.c`).
pub trait KQueue {
    /// `kqueue()`.
    fn kqueue(k: &mut Kernel) -> Result<u64, Errno>;
    /// `kevent` (`kev64` false) and `kevent64`.
    fn kevent_legacy(k: &mut Kernel, m: &mut GuestMem<'_>, a: &[u64; 6], kev64: bool) -> SyscallOutcome;
    fn kevent_qos(k: &mut Kernel, m: &mut GuestMem<'_>, a: &[u64; 6]) -> SyscallOutcome;
    fn kevent_id(k: &mut Kernel, m: &mut GuestMem<'_>, a: &[u64; 6]) -> SyscallOutcome;
    fn workloop_ctl(k: &mut Kernel, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno>;
    /// A blocked kevent call has woken.
    fn wait_done(k: &mut Kernel, m: &mut GuestMem<'_>, c: crate::darwin::kevent::Cont, res: crate::darwin::wait::WaitResult) -> Option<SyscallOutcome>;
    /// What kevent owes after a call.
    fn settle(k: &mut Kernel, m: &mut GuestMem<'_>);
}

/// The workqueue (`bsd/pthread/pthread_workqueue.c`).
pub trait WorkQueue {
    fn open(k: &mut Kernel) -> Result<u64, Errno>;
    fn kernreturn(k: &mut Kernel, m: &mut GuestMem<'_>, a: &[u64; 6]) -> SyscallOutcome;
    fn bsdthread_ctl(k: &mut Kernel, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno>;
    /// A parked workqueue thread has woken.
    fn wait_done(k: &mut Kernel, m: &mut GuestMem<'_>, res: crate::darwin::wait::WaitResult) -> Option<SyscallOutcome>;
    /// A new thread's first entry, when it is the kernel's.
    fn thread_entry(k: &mut Kernel, m: &mut GuestMem<'_>) -> Option<SyscallOutcome>;
}

/// The IPC, kqueue and workqueue ported here.
pub struct Native;

/// The implementations the system calls use.
pub type Mach = Native;
pub type Kq = Native;
pub type Wq = Native;

impl MachIpc for Native {
    fn mach_msg2(k: &mut Kernel, m: &mut GuestMem<'_>, a: &[u64; 6]) -> SyscallOutcome {
        k.darwin_mach_msg2(m, a)
    }
    fn mach_msg_trap(k: &mut Kernel, m: &mut GuestMem<'_>, a: &[u64; 6], overwrite: bool) -> SyscallOutcome {
        k.darwin_mach_msg_trap(m, a, overwrite)
    }
    fn wait_done(k: &mut Kernel, m: &mut GuestMem<'_>, c: crate::darwin::mach_msg::Cont, res: crate::darwin::wait::WaitResult) -> Option<SyscallOutcome> {
        k.darwin_mach_msg_wait_done(m, c, res)
    }
    fn settle(k: &mut Kernel, m: &mut GuestMem<'_>) {
        k.darwin_ipc_settle(m)
    }
}

impl KQueue for Native {
    fn kqueue(k: &mut Kernel) -> Result<u64, Errno> {
        k.darwin_kqueue()
    }
    fn kevent_legacy(k: &mut Kernel, m: &mut GuestMem<'_>, a: &[u64; 6], kev64: bool) -> SyscallOutcome {
        k.darwin_kevent_legacy(m, a, kev64)
    }
    fn kevent_qos(k: &mut Kernel, m: &mut GuestMem<'_>, a: &[u64; 6]) -> SyscallOutcome {
        k.darwin_kevent_qos(m, a)
    }
    fn kevent_id(k: &mut Kernel, m: &mut GuestMem<'_>, a: &[u64; 6]) -> SyscallOutcome {
        k.darwin_kevent_id(m, a)
    }
    fn workloop_ctl(k: &mut Kernel, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        k.darwin_kqueue_workloop_ctl(m, a)
    }
    fn wait_done(k: &mut Kernel, m: &mut GuestMem<'_>, c: crate::darwin::kevent::Cont, res: crate::darwin::wait::WaitResult) -> Option<SyscallOutcome> {
        k.darwin_kevent_wait_done(m, c, res)
    }
    fn settle(k: &mut Kernel, m: &mut GuestMem<'_>) {
        k.darwin_kevent_settle(m)
    }
}

impl WorkQueue for Native {
    fn open(k: &mut Kernel) -> Result<u64, Errno> {
        k.darwin_workq_open()
    }
    fn kernreturn(k: &mut Kernel, m: &mut GuestMem<'_>, a: &[u64; 6]) -> SyscallOutcome {
        k.darwin_workq_kernreturn(m, a)
    }
    fn bsdthread_ctl(k: &mut Kernel, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        k.darwin_bsdthread_ctl(m, a)
    }
    fn wait_done(k: &mut Kernel, m: &mut GuestMem<'_>, res: crate::darwin::wait::WaitResult) -> Option<SyscallOutcome> {
        k.darwin_workq_wait_done(m, res)
    }
    fn thread_entry(k: &mut Kernel, m: &mut GuestMem<'_>) -> Option<SyscallOutcome> {
        k.workq_thread_entry(m)
    }
}

impl Kernel {
    /// The first entry of a new Darwin thread: the kernel's, for a new
    /// workqueue thread ([`WorkQueue::thread_entry`]).
    pub fn darwin_thread_entry(&mut self, m: &mut GuestMem<'_>) -> Option<SyscallOutcome> {
        <Wq as WorkQueue>::thread_entry(self, m)
    }
}

use space::{bits, Space};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex};

/// An object's identity in the task's object table.
pub type ObjId = u64;

/// `kern_return_t`s the IPC layer answers.
pub mod kr {
    pub const SUCCESS: u64 = 0;
    pub const INVALID_ADDRESS: u64 = 1;
    pub const NO_SPACE: u64 = 3;
    pub const INVALID_ARGUMENT: u64 = 4;
    pub const FAILURE: u64 = 5;
    pub const RESOURCE_SHORTAGE: u64 = 6;
    pub const NAME_EXISTS: u64 = 13;
    pub const ABORTED: u64 = 14;
    pub const INVALID_NAME: u64 = 15;
    pub const INVALID_TASK: u64 = 16;
    pub const INVALID_RIGHT: u64 = 17;
    pub const INVALID_VALUE: u64 = 18;
    pub const UREFS_OVERFLOW: u64 = 19;
    pub const INVALID_CAPABILITY: u64 = 20;
    pub const RIGHT_EXISTS: u64 = 21;
    pub const NOT_IN_SET: u64 = 12;
    pub const OPERATION_TIMED_OUT: u64 = 49;
    pub const TERMINATED: u64 = 37;
    pub const NOT_WAITING: u64 = 48;
    pub const ALREADY_IN_SET: u64 = 11;
    pub const DENIED: u64 = 53;
}

/// `IPR_SOR_*_MASK`: a request's send-possible bits.
pub const IPR_SOR_SPARM_MASK: u32 = 0x01;
pub const IPR_SOR_SPREQ_MASK: u32 = 0x02;

/// `MACH_PORT_RIGHT_*`.
pub mod port_right {
    pub const SEND: u32 = 0;
    pub const RECEIVE: u32 = 1;
    pub const SEND_ONCE: u32 = 2;
    pub const PORT_SET: u32 = 3;
    pub const DEAD_NAME: u32 = 4;
    pub const LABELH: u32 = 5;
    pub const NUMBER: u32 = 6;
}

/// `MACH_PORT_TYPE_*`.
pub mod ty {
    pub const NONE: u32 = 0;
    pub const SEND: u32 = 1 << 16;
    pub const RECEIVE: u32 = 1 << 17;
    pub const SEND_ONCE: u32 = 1 << 18;
    pub const PORT_SET: u32 = 1 << 19;
    pub const DEAD_NAME: u32 = 1 << 20;
    /// `MACH_PORT_TYPE_EX_RECEIVE` (the obsolete LABELH bit, reused).
    pub const EX_RECEIVE: u32 = 1 << 21;
    pub const SEND_RECEIVE: u32 = SEND | RECEIVE;
    pub const SEND_RIGHTS: u32 = SEND | SEND_ONCE;
    pub const PORT_RIGHTS: u32 = SEND_RIGHTS | RECEIVE;
    pub const PORT_OR_DEAD: u32 = PORT_RIGHTS | DEAD_NAME;
    pub const ALL_RIGHTS: u32 = PORT_OR_DEAD | PORT_SET;
    pub const DNREQUEST: u32 = 0x8000_0000;
    pub const SPREQUEST: u32 = 0x4000_0000;
    pub const SPREQUEST_DELAYED: u32 = 0x2000_0000;
}

/// `MACH_PORT_UREFS_MAX`.
pub const UREFS_MAX: u32 = 0xffff;
/// `MACH_PORT_DEAD`.
pub const PORT_DEAD: u32 = !0;
/// `MACH_PORT_QLIMIT_*`.
pub const QLIMIT_DEFAULT: u32 = 5;
pub const QLIMIT_MAX: u32 = 1024;
pub const QLIMIT_KERNEL: u32 = 65534;

/// `MACH_PORT_VALID`.
pub fn name_valid(name: u32) -> bool {
    name != 0 && name != PORT_DEAD
}

/// What the kernel side of a port is (`ipc_kobject_type_t`), for a port
/// the kernel receives on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kobject {
    Task,
    /// IKOT_TASK_READ, IKOT_TASK_INSPECT: the task's read and inspect
    /// ports (`itk_task_ports[TASK_FLAVOR_READ]`, `[TASK_FLAVOR_INSPECT]`).
    TaskRead,
    TaskInspect,
    TaskName,
    Thread(i32),
    /// IKOT_THREAD_READ, IKOT_THREAD_INSPECT.
    ThreadRead(i32),
    ThreadInspect(i32),
    Host,
    HostPriv,
    Clock,
    Semaphore,
    Timer,
    Voucher(super::voucher::VoucherId),
    /// IKOT_TASK_RESUME: the task's resume port (`itk_resume`).
    TaskResume,
    /// IKOT_UX_HANDLER: the kernel's handler that makes an exception a
    /// signal (`ux_handler_port`).
    UxHandler,
    /// IKOT_MAIN_DEVICE: IOKit's main port, `main_device_port`.
    IoMain,
    /// IKOT_IOKIT_OBJECT: a registry entry, by its place in the device tree.
    IoEntry(u32),
    /// IKOT_FILEPORT: a file port ([`super::fileport`]), by its number.
    FilePort(u32),
    /// An `io_iterator_t`.
    IoIterator(u32),
    /// IKOT_IOKIT_CONNECT: a user client of service `0`.
    IoConnect(u32),
    /// A thread's kernel reply port (`ith_rpc_reply`): the reply to an RPC
    /// the kernel made for it.
    RpcReply(i32),
    /// IKOT_WORK_INTERVAL: a joinable work interval, by its id.
    WorkInterval(u64),
}

/// A port's reply semantics (`ip_reply_port_semantics`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ReplySemantics {
    #[default]
    None,
    /// `PORT_MARK_REPLY_PORT`: a reply port, of a hardened task; only a
    /// send-once right is made from it.
    ReplyPort,
    /// `PORT_ENFORCE_REPLY_PORT_SEMANTICS`: a message to it must name a
    /// reply port, or a provisional one, as its reply.
    Enforce,
    /// `PORT_MARK_PROVISIONAL_REPLY_PORT`: what would be a reply port, in
    /// a task that is not hardened.
    Provisional,
    /// `PORT_ENFORCE_RIGID_REPLY_PORT_SEMANTICS`.
    EnforceRigid,
    /// `PORT_ID_PROTECTED_OPT_OUT`.
    IdProtOptOut,
}

/// Where a port's receive right is (`ip_receiver` / `ip_destination`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Receiver {
    /// In the task's space, under this name.
    Space(u32),
    /// The kernel's: a kernel object's port.
    Kernel,
    /// In a message, not yet received.
    Transit,
    /// The port is dead.
    None,
}

/// A request for a notification when a name dies, or sending becomes
/// possible (`struct ipc_port_request`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Request {
    /// The name the request is for; 0 on a free slot.
    pub name: u32,
    /// The send-once right the notification goes to.
    pub notify: Option<ObjId>,
    /// `IPR_SOR_SPREQ_MASK` and `IPR_SOR_SPARM_MASK`.
    pub spreq: bool,
    pub sparm: bool,
    /// The free list's next slot while free.
    pub next: u32,
}

/// A port (`struct ipc_port`).
#[derive(Clone, Debug)]
pub struct Port {
    pub active: bool,
    pub receiver: Receiver,
    /// The task whose space holds the receive right, or whose kernel
    /// serves the object: where its waiters and knotes are.
    pub owner: TaskKey,
    pub kobject: Option<Kobject>,
    pub mscount: u32,
    pub srights: u32,
    pub sorights: u32,
    pub seqno: u32,
    pub qlimit: u32,
    pub context: u64,
    pub guarded: bool,
    pub strict_guard: bool,
    pub immovable_receive: bool,
    pub immovable_send: bool,
    pub pinned: bool,
    pub specialreply: bool,
    /// `ip_reply_port_semantics`, set when the port is made.
    pub reply_semantics: ReplySemantics,
    pub tempowner: bool,
    pub impdonation: bool,
    pub no_grant: bool,
    pub service_port: bool,
    /// A service port labeled as a bootstrap port
    /// (`ipc_service_port_label_is_bootstrap_port`).
    pub bootstrap_port: bool,
    /// A libxpc connection port (`ip_is_libxpc_connection_port`).
    pub connection_port: bool,
    /// `ip_splabel` of a service port.
    pub splabel: Option<ServiceLabel>,
    /// `IPC_PORT_INIT_FILTER_MESSAGE`. Only a Sandbox profile of a task's
    /// own filters messages, and tasks have none yet.
    pub filter_msg: bool,
    /// `ip_sprequests`: a send-possible request is armed.
    pub sprequests: bool,
    /// `ip_nsrequest`: the send-once right a no-senders notification goes
    /// to, or the kernel's own arming for a kernel object.
    pub nsrequest: Option<ObjId>,
    pub nsrequest_kobject: bool,
    /// A labeled control port's immovable equivalent (`ikol_alt_port`,
    /// `IPC_LABEL_SUBST_TASK`/`_THREAD`): what a send right to it becomes
    /// when copied out into its own task's space.
    pub subst: Option<ObjId>,
    /// `ip_klist`: the EVFILT_MACHPORT knotes on the port.
    pub knotes: u32,
    /// `ip_pdrequest`: where the receive right goes when destroyed.
    pub pdrequest: Option<ObjId>,
    /// `ip_requests`: the dead-name and send-possible request table, slot
    /// 0 its free list's head; `None` before the first request.
    pub requests: Option<Vec<Request>>,
    /// The sets the port is a member of.
    pub psets: Vec<ObjId>,
    /// Queued messages (`ip_messages`).
    pub messages: VecDeque<Box<msg::Kmsg>>,
    /// `imq_msgcount`: room reserved, for messages queued or on their way.
    pub msgcount: u32,
    /// `ip_fullwaiters`: a sender waits for room.
    pub fullwaiters: bool,
    /// `ip_reply_context`.
    pub reply_context: u64,
    /// `ip_timestamp`: when the port died.
    pub timestamp: u32,
    /// Kernel references (`io_references`).
    pub refs: u32,
}

impl Port {
    pub(crate) fn new(receiver: Receiver) -> Port {
        Port {
            active: true,
            receiver,
            owner: 0,
            kobject: None,
            mscount: 0,
            srights: 0,
            sorights: 0,
            seqno: 0,
            qlimit: QLIMIT_DEFAULT,
            context: 0,
            guarded: false,
            strict_guard: false,
            immovable_receive: false,
            immovable_send: false,
            pinned: false,
            specialreply: false,
            reply_semantics: ReplySemantics::None,
            tempowner: false,
            impdonation: false,
            no_grant: false,
            service_port: false,
            bootstrap_port: false,
            connection_port: false,
            splabel: None,
            filter_msg: false,
            sprequests: false,
            nsrequest: None,
            nsrequest_kobject: false,
            subst: None,
            knotes: 0,
            pdrequest: None,
            requests: None,
            psets: Vec::new(),
            messages: VecDeque::new(),
            msgcount: 0,
            fullwaiters: false,
            reply_context: 0,
            timestamp: 0,
            refs: 1,
        }
    }
}

/// A port set (`struct ipc_pset`).
#[derive(Clone, Debug, Default)]
pub struct Pset {
    pub active: bool,
    /// The task whose space it is in (a set never leaves it).
    pub owner: TaskKey,
    pub name: u32,
    pub members: Vec<ObjId>,
    pub refs: u32,
    /// `ips_klist`: the EVFILT_MACHPORT knotes on the set.
    pub knotes: u32,
}

/// An IPC object.
#[derive(Clone, Debug)]
pub enum Object {
    Port(Port),
    Pset(Pset),
}

/// A notification a rights change owes, sent as a message by the message
/// layer (`osfmk/ipc/ipc_notify.c`): to the send-once right `to`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notify {
    /// `MACH_NOTIFY_PORT_DELETED` for `name`.
    PortDeleted { to: ObjId, name: u32 },
    /// `MACH_NOTIFY_SEND_POSSIBLE` for `name`.
    SendPossible { to: ObjId, name: u32 },
    /// A kernel object's port was destroyed (`iko_op_destroy`).
    KobjectDestroyed { port: ObjId },
    /// `MACH_NOTIFY_PORT_DESTROYED`, carrying the receive right to `port`.
    PortDestroyed { to: ObjId, port: ObjId },
    /// `MACH_NOTIFY_NO_SENDERS` with the make-send count.
    NoSenders { to: ObjId, mscount: u32 },
    /// A kernel object's port lost its last send right.
    KobjectNoSenders { port: ObjId, mscount: u32 },
    /// `MACH_NOTIFY_SEND_ONCE`: a send-once right was destroyed unused.
    SendOnce { to: ObjId },
    /// A send-once right to a kernel object's port destroyed unused
    /// (`ipc_kobject_notify_send_once_and_unlock`); the port's reference
    /// goes with it.
    KobjectSendOnce { port: ObjId },
    /// `MACH_NOTIFY_DEAD_NAME` for `name`.
    DeadName { to: ObjId, name: u32 },
}

/// `kGUARD_EXC_*`: the guard exceptions IPC misuse raises.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Guard {
    Destroy = 1,
    ModRefs = 2,
    InvalidOptions = 3,
    SetContext = 4,
    /// `kGUARD_EXC_EXCEPTION_BEHAVIOR_ENFORCE`: a handler that is not
    /// identity protected set for a hardened task.
    ExceptionBehaviorEnforce = 6,
    Unguarded = 1 << 3,
    IncorrectGuard = 1 << 4,
    Immovable = 1 << 5,
    StrictReply = 1 << 6,
    InvalidRight = 1 << 8,
    InvalidName = 1 << 9,
    InvalidValue = 1 << 10,
    InvalidArgument = 1 << 11,
    RightExists = 1 << 12,
    KernNoSpace = 1 << 13,
    KernFailure = 1 << 14,
    KernResource = 1 << 15,
    SendInvalidReply = 1 << 16,
    SendInvalidVoucher = 1 << 17,
    SendInvalidRight = 1 << 18,
    RcvInvalidName = 1 << 19,
    ModRefsNonFatal = 1 << 21,
    RequireReplyPortSemantics = 1 << 23,
}

/// `MPG_FLAGS_MOD_REFS_PINNED_*`: what was done to a pinned right.
pub mod mpg_pinned {
    pub const DEALLOC: u64 = 0x01 << 56;
    pub const DESTROY: u64 = 0x02 << 56;
    pub const COPYIN: u64 = 0x04 << 56;
}

/// A task's IPC state: its name space, and, while the task holds the
/// system's table ([`IpcCell`]), every port and set and the other tasks'
/// spaces.
#[derive(Debug, Default)]
pub struct Ipc {
    pub objects: BTreeMap<ObjId, Object>,
    next_id: ObjId,
    pub space: Space,
    /// The other tasks' spaces, by task, while this task holds the table.
    pub others: HashMap<TaskKey, Space>,
    /// This task's key among the spaces (0: none taken yet).
    pub task: TaskKey,
    /// The task is the system's first (`initproc`).
    pub initproc: bool,
    /// The system's table, once this task has taken it.
    cell: Option<Arc<IpcCell>>,
    /// Whether this task holds the table now.
    pub held: bool,
    /// The table's task key counter while this task holds it.
    next_task_hint: TaskKey,
    /// Every task's link, while this task holds the table.
    pub links: HashMap<TaskKey, Arc<TaskLink>>,
    /// This task's own link, kept for emptying its mailbox.
    pub link: Option<Arc<TaskLink>>,
    /// The kernel's own objects every task names alike (the host, host
    /// privilege and clock ports), while this task holds the table.
    globals: Vec<(Kobject, ObjId)>,
    /// `realhost.special`: the send rights launchd stored, while this task
    /// holds the table.
    pub host_special: Vec<(i32, ObjId)>,
    /// The host's exception actions (`realhost.exc_actions`), while this
    /// task holds the table.
    pub host_exc: super::exception::ExcActions,
    /// Notifications owed, oldest first.
    pub outbox: Vec<Notify>,
    /// Guard exceptions raised, for the kernel to deliver.
    pub guards: Vec<(u32, Guard, u64)>,
    /// Message queues' waiters and results.
    pub queues: msg::Queues,
    /// `ipc_port_timestamp`: a counter dead ports are stamped with.
    timestamp: u32,
    /// `TASK_CONTROL_PORT_PINNED_HARD`: a pinned right's misuse is fatal.
    pub pinned_hard: bool,
}

impl Drop for Ipc {
    /// A task gone in the middle of a call leaves the table for the rest.
    fn drop(&mut self) {
        self.check_in();
    }
}

/// A task's key among the system's spaces.
pub type TaskKey = u64;

/// `struct ipc_service_port_label`, and `ISPL_FLAGS_*`.
#[derive(Clone, Debug, Default)]
pub struct ServiceLabel {
    pub name: Vec<u8>,
    pub domain: u8,
    pub flags: u32,
    pub launchd_name: u32,
    pub launchd_context: u64,
}

pub mod ispl {
    pub const SPECIAL_PDREQUEST: u32 = 1;
    pub const SEND_PD_NOTIFICATION: u32 = 1 << 1;
    pub const BOOTSTRAP_PORT: u32 = 1 << 2;
    pub const THROTTLED: u32 = 1 << 3;
}

/// A thread waiting on a queue, as every task names it: its task's key
/// and its thread id.
pub type Waiter = u64;

/// The task of waiter `w`.
pub fn waiter_task(w: Waiter) -> TaskKey {
    w >> 32
}

/// The thread id of waiter `w`.
pub fn waiter_tid(w: Waiter) -> i32 {
    w as u32 as i32
}

/// What a task is told of another task's IPC, for its own kernel to act
/// on: a thread of its own a queue woke, or a port or set of its own whose
/// knotes have work.
#[derive(Debug)]
pub enum Remote {
    Wake(i32),
    Knote(ObjId),
    PsetKnote(ObjId, ObjId),
    /// A request to one of its kernel objects, from task `caller`.
    Kobject { kmsg: Box<msg::Kmsg>, options: u64, caller: TaskKey },
}

/// How other tasks reach a task: its mailbox, and the bell of the thread
/// that empties it.
#[derive(Debug)]
pub struct TaskLink {
    pub mailbox: Mutex<Vec<Remote>>,
    pub bell: Arc<super::timer::Bell>,
    /// The task's process.
    pub pid: i32,
    /// Its name port (`itk_task_ports[TASK_FLAVOR_NAME]`), once made.
    pub name_port: Mutex<Option<ObjId>>,
    /// Its code signature, for its entitlements.
    pub codesign: Option<super::codesign::CodeSign>,
    /// Its process's `p_csflags`, `p_idversion` and `p_textoff`.
    pub csflags: Arc<std::sync::atomic::AtomicU32>,
    pub pidversion: i32,
    pub textoff: i64,
    /// Its process's `p_uniqueid`.
    pub uniqueid: u64,
}

/// What every task shares: the ports and sets (XNU's are kernel objects,
/// named from any space), and the spaces of tasks not running a call.
#[derive(Debug, Default)]
pub struct IpcShared {
    objects: BTreeMap<ObjId, Object>,
    next_id: ObjId,
    timestamp: u32,
    spaces: HashMap<TaskKey, Space>,
    next_task: TaskKey,
    queues: msg::Queues,
    links: HashMap<TaskKey, Arc<TaskLink>>,
    globals: Vec<(Kobject, ObjId)>,
    host_exc: super::exception::ExcActions,
    host_special: Vec<(i32, ObjId)>,
}

/// The system's IPC table, taken by one task at a time for the length of a
/// kernel call.
#[derive(Debug)]
pub struct IpcCell {
    table: Mutex<Option<IpcShared>>,
    free: Condvar,
}

impl Default for IpcCell {
    fn default() -> IpcCell {
        IpcCell { table: Mutex::new(Some(IpcShared::default())), free: Condvar::new() }
    }
}

impl IpcCell {
    /// Take the table, waiting for the task holding it.
    fn take(&self) -> IpcShared {
        let mut t = self.table.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(s) = t.take() {
                return s;
            }
            let (g, timeout) = self.free.wait_timeout(t, std::time::Duration::from_secs(120)).unwrap_or_else(|e| e.into_inner());
            t = g;
            if timeout.timed_out() && t.is_none() {
                panic!("gex: the Darwin IPC table has been held for 120 s: a task did not give it back");
            }
        }
    }

    fn put(&self, s: IpcShared) {
        *self.table.lock().unwrap_or_else(|e| e.into_inner()) = Some(s);
        self.free.notify_one();
    }
}

/// `ipc_port_request_table_next_size(2, osize, 16)` in entries (16-byte
/// requests).
fn request_table_grow(ocount: usize) -> usize {
    const REQ_SIZE: u64 = 16;
    let osize = ocount as u64 * REQ_SIZE;
    let size = if osize != 0 { osize + REQ_SIZE - 1 } else { 2 * REQ_SIZE - 1 };
    let size = if size < 16 {
        16
    } else if size < 32 {
        32
    } else {
        let scale = 63 - size.leading_zeros();
        let step = 1u64 << (scale - 1);
        (size + step) & !(step - 1)
    };
    // CONFIG_IPC_TABLE_REQUEST_SIZE_MAX (xsmall): 1 MiB.
    (size.min(1 << 20) / REQ_SIZE) as usize
}

impl Ipc {
    /// Take the system's table from `cell` for this task: its space comes
    /// out of the shared spaces (a task taking it the first time gets its
    /// key and keeps the space it has).
    pub fn check_out(&mut self, cell: &Arc<IpcCell>) {
        debug_assert!(!self.held);
        let mut s = cell.take();
        self.cell.get_or_insert_with(|| Arc::clone(cell));
        self.objects = std::mem::take(&mut s.objects);
        self.next_id = s.next_id;
        self.timestamp = s.timestamp;
        if self.task == 0 {
            s.next_task += 1;
            self.task = s.next_task;
        } else if let Some(sp) = s.spaces.remove(&self.task) {
            self.space = sp;
        }
        self.others = std::mem::take(&mut s.spaces);
        self.queues = std::mem::take(&mut s.queues);
        self.links = std::mem::take(&mut s.links);
        self.globals = std::mem::take(&mut s.globals);
        self.host_exc = s.host_exc;
        self.host_special = std::mem::take(&mut s.host_special);
        self.held = true;
        if !self.globals.iter().any(|(g, _)| *g == Kobject::UxHandler) {
            self.ux_handler_setup();
        }
        // What stays in `s` is its key counter.
        self.next_task_hint = s.next_task;
    }

    /// Give the table back.
    pub fn check_in(&mut self) {
        if !self.held {
            return;
        }
        let cell = Arc::clone(self.cell.as_ref().expect("a held table has its cell"));
        let mut spaces = std::mem::take(&mut self.others);
        spaces.insert(self.task, std::mem::take(&mut self.space));
        let s = IpcShared { objects: std::mem::take(&mut self.objects), next_id: self.next_id, timestamp: self.timestamp, spaces, next_task: self.next_task_hint, queues: std::mem::take(&mut self.queues), links: std::mem::take(&mut self.links), globals: std::mem::take(&mut self.globals), host_special: std::mem::take(&mut self.host_special), host_exc: std::mem::take(&mut self.host_exc) };
        self.held = false;
        cell.put(s);
    }

    /// The task has ended: its (terminated) space leaves the table, and the
    /// task gives up its key.
    pub fn space_leave(&mut self) {
        debug_assert!(self.held);
        self.links.remove(&self.task);
        self.link = None;
        self.space = Space::new();
        self.task = 0;
        let cell = self.cell.take();
        self.held = false;
        if let Some(cell) = cell {
            let spaces = std::mem::take(&mut self.others);
            let s = IpcShared { objects: std::mem::take(&mut self.objects), next_id: self.next_id, timestamp: self.timestamp, spaces, next_task: self.next_task_hint, queues: std::mem::take(&mut self.queues), links: std::mem::take(&mut self.links), globals: std::mem::take(&mut self.globals), host_special: std::mem::take(&mut self.host_special), host_exc: std::mem::take(&mut self.host_exc) };
            cell.put(s);
        }
    }

    /// The calling task's thread `tid` as a waiter.
    pub fn waiter(&self, tid: i32) -> Waiter {
        (self.task << 32) | u64::from(tid as u32)
    }

    /// Tell task `task` of `r`, and ring the bell of its thread that acts
    /// on it (a task that has ended hears nothing).
    pub fn remote(&self, task: TaskKey, r: Remote) -> bool {
        let Some(l) = self.links.get(&task) else { return false };
        l.mailbox.lock().unwrap_or_else(|e| e.into_inner()).push(r);
        l.bell.ring();
        true
    }

    /// Task `task`'s name port, made (as that task's object) if it has
    /// none yet.
    pub fn task_name_port(&mut self, task: TaskKey) -> Option<ObjId> {
        let link = Arc::clone(self.links.get(&task)?);
        let mut slot = link.name_port.lock().unwrap_or_else(|e| e.into_inner());
        Some(*slot.get_or_insert_with(|| {
            let p = self.kobject_port(Kobject::TaskName);
            self.port_mut(p).owner = task;
            p
        }))
    }

    /// This task's name port taken from its link, for its end.
    pub fn task_name_port_take(&mut self) -> Option<ObjId> {
        self.link.as_ref()?.name_port.lock().unwrap_or_else(|e| e.into_inner()).take()
    }

    /// Run `f` on task `task`'s space, as if it were this task's (this
    /// task's own for its own key).
    pub fn with_space<R>(&mut self, task: TaskKey, f: impl FnOnce(&mut Ipc) -> R) -> Option<R> {
        if task == 0 || task == self.task {
            return Some(f(self));
        }
        let space = self.others.remove(&task)?;
        let own = std::mem::replace(&mut self.space, space);
        let me = std::mem::replace(&mut self.task, task);
        let r = f(self);
        self.task = me;
        let space = std::mem::replace(&mut self.space, own);
        self.others.insert(task, space);
        Some(r)
    }

    pub(crate) fn new_id_pub(&mut self) -> ObjId {
        self.new_id()
    }

    fn new_id(&mut self) -> ObjId {
        self.next_id += 1;
        self.next_id
    }

    pub fn port(&self, id: ObjId) -> &Port {
        match &self.objects[&id] {
            Object::Port(p) => p,
            Object::Pset(_) => panic!("object {id} is a port set"),
        }
    }

    pub fn port_mut(&mut self, id: ObjId) -> &mut Port {
        match self.objects.get_mut(&id) {
            Some(Object::Port(p)) => p,
            _ => panic!("object {id} is not a port"),
        }
    }

    pub fn pset(&self, id: ObjId) -> &Pset {
        match self.objects.get(&id) {
            Some(Object::Pset(p)) => p,
            _ => panic!("object {id} is not a port set"),
        }
    }

    pub fn pset_mut(&mut self, id: ObjId) -> &mut Pset {
        match self.objects.get_mut(&id) {
            Some(Object::Pset(p)) => p,
            _ => panic!("object {id} is not a port set"),
        }
    }

    pub fn is_port(&self, id: ObjId) -> bool {
        matches!(self.objects.get(&id), Some(Object::Port(_)))
    }

    /// Take a reference on `id` (`ip_reference`).
    pub fn reference(&mut self, id: ObjId) {
        match self.objects.get_mut(&id) {
            Some(Object::Port(p)) => p.refs += 1,
            Some(Object::Pset(s)) => s.refs += 1,
            None => panic!("referencing a freed object"),
        }
    }

    /// Drop a reference (`ip_release`); the last frees a dead object.
    pub fn release(&mut self, id: ObjId) {
        let gone = match self.objects.get_mut(&id) {
            Some(Object::Port(p)) => {
                p.refs -= 1;
                p.refs == 0
            }
            Some(Object::Pset(s)) => {
                s.refs -= 1;
                s.refs == 0
            }
            None => panic!("releasing a freed object"),
        };
        if gone {
            self.objects.remove(&id);
        }
    }

    /// The port of the kernel's object `k`, one for every task (made on
    /// first use; owned by no task, so any task's kernel serves it).
    /// `ux_handler_setup`: the host's handler for every exception but
    /// RPC alerts (Instruments') and guards, `EXCEPTION_DEFAULT |
    /// MACH_EXCEPTION_CODES`, each action with a send right of its own.
    fn ux_handler_setup(&mut self) {
        use super::exception as exc;
        let p = self.global_port(Kobject::UxHandler);
        for t in 1..exc::EXC_TYPES_COUNT {
            if t == exc::EXC_RPC_ALERT || t == exc::EXC_GUARD {
                continue;
            }
            self.make_send(p);
            self.host_exc[t] = exc::ExcAction { port: Some(right::Carried::Port(p)), behavior: exc::EXCEPTION_DEFAULT | exc::MACH_EXCEPTION_CODES, flavor: 0, privileged: true };
        }
    }

    pub fn global_port(&mut self, k: Kobject) -> ObjId {
        if let Some(&(_, p)) = self.globals.iter().find(|(g, _)| *g == k) {
            return p;
        }
        let p = self.kobject_port(k.clone());
        self.port_mut(p).owner = 0;
        self.globals.push((k, p));
        p
    }

    /// A new port whose receive right is the kernel's (a kernel object).
    pub fn kobject_port(&mut self, k: Kobject) -> ObjId {
        let id = self.new_id();
        let mut p = Port::new(Receiver::Kernel);
        p.owner = self.task;
        p.kobject = Some(k);
        p.qlimit = QLIMIT_KERNEL;
        self.objects.insert(id, Object::Port(p));
        id
    }

    /// `ipc_port_alloc`: a port with its receive right (and a send right,
    /// with `make_send`) under a new name. `Err` is `KERN_NO_SPACE`.
    pub fn port_alloc(&mut self, make_send: bool) -> Result<(u32, ObjId), u64> {
        let id = self.new_id();
        let name = self.space.alloc(Some(id)).ok_or(kr::NO_SPACE)?;
        let mut p = Port::new(Receiver::Space(name));
        p.owner = self.task;
        let mut t = ty::RECEIVE;
        if make_send {
            p.srights = 1;
            p.mscount = 1;
            t |= ty::SEND;
        }
        self.objects.insert(id, Object::Port(p));
        let e = self.space.lookup_mut_any(name);
        e.bits |= t | u32::from(make_send);
        Ok((name, id))
    }

    /// `ipc_pset_alloc`: a port set under a new name.
    pub fn pset_alloc(&mut self) -> Result<(u32, ObjId), u64> {
        let id = self.new_id();
        let name = self.space.alloc(Some(id)).ok_or(kr::NO_SPACE)?;
        self.objects.insert(id, Object::Pset(Pset { active: true, owner: self.task, name, members: Vec::new(), refs: 1, knotes: 0 }));
        self.space.lookup_mut_any(name).bits |= ty::PORT_SET;
        Ok((name, id))
    }

    /// `ipc_port_request_alloc`, growing the table as `ipc_right_request_alloc`
    /// does. The slot's index.
    fn port_request_alloc(&mut self, port: ObjId, name: u32, notify: ObjId, spreq: bool, sparm: bool) -> u32 {
        let p = self.port_mut(port);
        loop {
            if let Some(table) = &mut p.requests {
                let index = table[0].next;
                if index != 0 {
                    let next = table[index as usize].next;
                    table[0].next = next;
                    table[index as usize] = Request { name, notify: Some(notify), spreq, sparm, next: 0 };
                    if spreq && sparm && !p.sprequests {
                        p.sprequests = true;
                    }
                    return index;
                }
            }
            // ipc_port_request_grow
            let ocount = p.requests.as_ref().map_or(0, |t| t.len());
            let ncount = request_table_grow(ocount);
            let table = p.requests.get_or_insert_with(Vec::new);
            let (start, mut free) = if ocount == 0 { (1, 0) } else { (ocount, table[0].next) };
            table.resize(ncount, Request::default());
            for i in start..ncount {
                table[i].next = free;
                free = i as u32;
            }
            table[0].next = free;
        }
    }

    /// `ipc_port_request_cancel`: free slot `index`; the send-once right
    /// it held.
    fn port_request_cancel(&mut self, port: ObjId, index: u32) -> Option<ObjId> {
        let p = self.port_mut(port);
        let table = p.requests.as_mut().expect("a request table");
        let request = table[index as usize].notify;
        let head = table[0].next;
        table[index as usize] = Request { next: head, ..Default::default() };
        table[0].next = index;
        request
    }

    /// `ipc_port_request_type`: the request bits slot `index` adds to a
    /// name's type.
    fn port_request_type(&self, port: ObjId, index: u32) -> u32 {
        let r = self.port(port).requests.as_ref().expect("a request table")[index as usize];
        let mut t = 0;
        if r.notify.is_some() {
            t |= ty::DNREQUEST;
            if r.spreq {
                t |= ty::SPREQUEST;
                if !r.sparm {
                    t |= ty::SPREQUEST_DELAYED;
                }
            }
        }
        t
    }

    /// `ipc_right_request_cancel_macro`: an entry's request cancelled.
    pub(crate) fn right_request_cancel_pub(&mut self, port: ObjId, name: u32) -> Option<ObjId> {
        let req = self.space.lookup(name).map_or(0, |e| e.request);
        if req == 0 {
            return None;
        }
        let r = self.port_request_cancel(port, req);
        if let Some(e) = self.space.lookup_mut(name) {
            e.request = 0;
        }
        r
    }

    /// `ipc_notify_no_senders_prepare`: the no-senders request, taken.
    pub(crate) fn no_senders_prepare_pub(&mut self, port: ObjId) -> Option<Notify> {
        let p = self.port_mut(port);
        if p.nsrequest_kobject {
            p.nsrequest_kobject = false;
            return p.active.then_some(Notify::KobjectNoSenders { port, mscount: p.mscount });
        }
        let to = p.nsrequest.take()?;
        Some(Notify::NoSenders { to, mscount: p.mscount })
    }

    /// `ipc_notify_no_senders_emit`.
    fn no_senders_emit(&mut self, n: Option<Notify>) {
        if let Some(n) = n {
            self.outbox.push(n);
        }
    }

    /// `ipc_notify_send_once_and_unlock`: a send-once right to `port`
    /// destroyed unused.
    fn send_once_notify(&mut self, port: ObjId) {
        let p = self.port_mut(port);
        p.sorights -= 1;
        // A thread's kernel reply port is a queue, not a kernel object.
        let rpc_reply = matches!(p.kobject, Some(Kobject::RpcReply(_)));
        if p.active && p.receiver == Receiver::Kernel && p.kobject.is_some() && !rpc_reply {
            self.outbox.push(Notify::KobjectSendOnce { port });
            return;
        }
        if p.active && (p.receiver != Receiver::Kernel || rpc_reply) {
            self.outbox.push(Notify::SendOnce { to: port });
        }
        self.release(port);
    }

    /// `mach_port_guard_exception`: recorded for the kernel to raise.
    /// `ipc_port_request_sparm`: arm the send-possible request at `index`
    /// (a sender found the port full).
    /// With `MACH_SEND_OVERRIDE`, the message at the queue's head takes
    /// the sender's QoS (`ipc_mqueue_override_send_locked`).
    pub fn request_sparm(&mut self, port: ObjId, index: u32, options: u64, qos_ovr: u8) {
        let p = self.port_mut(port);
        let r = &mut p.requests.as_mut().expect("a request table")[index as usize];
        if r.spreq {
            r.sparm = true;
            p.sprequests = true;
            if options & msg::opt::SEND_OVERRIDE != 0 && qos_ovr != 0 {
                self.mqueue_override_send(port, qos_ovr);
            }
        }
    }

    /// `ipc_port_spnotify`: the port has room; every armed send-possible
    /// request fires.
    pub fn spnotify(&mut self, port: ObjId) {
        if !self.port(port).sprequests {
            return;
        }
        let p = self.port_mut(port);
        p.sprequests = false;
        if !p.active {
            return;
        }
        let Some(table) = p.requests.as_mut() else { return };
        let mut fired = Vec::new();
        for r in table.iter_mut().skip(1) {
            if name_valid(r.name) && r.sparm {
                if let Some(to) = r.notify.take() {
                    fired.push((to, r.name));
                }
            }
        }
        for (to, name) in fired {
            self.outbox.push(Notify::SendPossible { to, name });
        }
    }

    /// `mach_port_guard_exception_pinned`: a pinned control port's last
    /// send right was asked to go.
    pub fn guard_pinned(&mut self, name: u32, what: u64) {
        let g = if self.pinned_hard { Guard::ModRefs } else { Guard::ModRefsNonFatal };
        self.guard_exception(name, g, what);
    }

    pub fn guard_exception(&mut self, name: u32, guard: Guard, portguard: u64) {
        self.guards.push((name, guard, portguard));
    }

    /// `ipc_right_check`: whether `name`'s port has died, turning the
    /// entry into a dead name (with an extra user reference for a pending
    /// dead-name request) if so.
    pub fn right_check(&mut self, name: u32, allow_dead_send_once: bool) -> bool {
        let e = *self.space.lookup(name).expect("checked name in use");
        let port = e.object.expect("a port right names a port");
        let p = self.port(port);
        if p.active || (allow_dead_send_once && e.request == 0 && e.bits & ty::SEND_ONCE != 0) {
            return false;
        }
        let mut b = e.bits;
        if b & ty::SEND != 0 {
            self.port_mut(port).srights -= 1;
            self.space.hash_delete(port);
        } else {
            self.port_mut(port).sorights -= 1;
        }
        b = (b & !bits::TYPE_MASK) | ty::DEAD_NAME;
        if e.request != 0 {
            if self.port_request_type(port, e.request) != 0 && b & bits::UREFS_MASK < UREFS_MAX {
                b += 1;
            }
        }
        let entry = self.space.lookup_mut(name).expect("checked name in use");
        entry.request = 0;
        entry.bits = b;
        entry.object = None;
        self.release(port);
        true
    }

    /// `ipc_port_destroy`: a port's receive right destroyed. Its messages
    /// go; its receive right goes to its port-destroyed request if any,
    /// else it dies: dead-name requests fire and a pending no-senders
    /// request is answered with a send-once notification.
    pub fn port_destroy(&mut self, port: ObjId) {
        let p = self.port_mut(port);
        p.reply_context = 0;
        let pdrequest = if !p.specialreply { p.pdrequest.take() } else { None };
        if pdrequest.is_some() {
            p.tempowner = true;
            // The notification carries a service port home to launchd.
            if p.service_port {
                if let Some(l) = p.splabel.as_mut().filter(|l| l.flags & ispl::SPECIAL_PDREQUEST != 0) {
                    l.flags |= ispl::SEND_PD_NOTIFICATION;
                }
            }
        } else {
            // A port that dies has no label left to speak of.
            p.splabel = None;
            p.service_port = false;
            p.connection_port = false;
        }
        let should_destroy = pdrequest.is_none();
        self.clear_receiver_pub(port, should_destroy);
        if let Some(to) = pdrequest {
            self.outbox.push(Notify::PortDestroyed { to, port });
            return;
        }
        if let Some(n) = self.no_senders_prepare_pub(port) {
            match n {
                Notify::NoSenders { to, .. } => self.send_once_notify(to),
                Notify::KobjectNoSenders { .. } => self.release(port),
                _ => unreachable!(),
            }
        }
        // ipc_port_dnnotify
        if let Some(table) = self.port(port).requests.clone() {
            for r in table.iter().skip(1) {
                if name_valid(r.name) {
                    if let Some(to) = r.notify {
                        self.outbox.push(Notify::DeadName { to, name: r.name });
                    }
                }
            }
        }
        // ipc_kobject_destroy: the object's destroy op (an mk_timer's).
        if self.port(port).kobject == Some(Kobject::Timer) {
            self.outbox.push(Notify::KobjectDestroyed { port });
        }
        self.release(port);
    }

    /// `ipc_port_clear_receiver`: out of its sets and its receiver's
    /// space; with `destroy`, dead and its messages gone.
    pub(crate) fn clear_receiver_pub(&mut self, port: ObjId, destroy: bool) {
        let psets = std::mem::take(&mut self.port_mut(port).psets);
        for s in psets {
            if let Some(Object::Pset(set)) = self.objects.get_mut(&s) {
                set.members.retain(|&m| m != port);
            }
        }
        self.timestamp = self.timestamp.wrapping_add(1);
        let ts = self.timestamp;
        let p = self.port_mut(port);
        p.mscount = 0;
        p.seqno = 0;
        p.context = 0;
        p.guarded = false;
        p.strict_guard = false;
        if destroy {
            p.active = false;
            p.receiver = Receiver::None;
            p.timestamp = ts;
            let msgs: Vec<_> = p.messages.drain(..).collect();
            p.msgcount = 0;
            self.mqueue_changed(port);
            self.mqueue_senders_restart(port);
            for k in msgs {
                self.kmsg_destroy(k, false);
            }
        } else {
            p.immovable_receive = false;
            p.receiver = Receiver::Transit;
            self.mqueue_changed(port);
        }
    }

    /// `ipc_pset_destroy`.
    pub fn pset_destroy(&mut self, pset: ObjId) {
        let members = std::mem::take(&mut self.pset_mut(pset).members);
        for m in members {
            if let Some(Object::Port(p)) = self.objects.get_mut(&m) {
                p.psets.retain(|&s| s != pset);
            }
        }
        self.pset_mut(pset).active = false;
        self.mqueue_changed(pset);
        self.queues.preposts.remove(&pset);
        self.release(pset);
    }

    /// `ipc_right_destroy`: every right `name` holds, gone. With
    /// `check_guard`, a guarded receive right needs `guard`.
    pub fn right_destroy(&mut self, name: u32, check_guard: bool, guard: u64) -> u64 {
        let e = *self.space.lookup(name).expect("destroyed name in use");
        let t = e.ty();
        match t {
            ty::DEAD_NAME => self.space.dealloc(name),
            ty::PORT_SET => {
                let pset = e.object.expect("a set");
                self.space.dealloc(name);
                self.pset_destroy(pset);
            }
            ty::SEND | ty::RECEIVE | ty::SEND_RECEIVE | ty::SEND_ONCE => {
                let port = e.object.expect("a port");
                if t == ty::SEND {
                    if self.port(port).pinned {
                        self.guard_pinned(name, mpg_pinned::DESTROY);
                        return kr::INVALID_CAPABILITY;
                    }
                    self.space.hash_delete(port);
                }
                if !self.port(port).active {
                    self.space.dealloc(name);
                    self.release(port);
                    return kr::SUCCESS;
                }
                let p = self.port(port);
                if t & ty::RECEIVE != 0 && check_guard && p.guarded && guard != p.context {
                    let portguard = p.context;
                    self.guard_exception(name, Guard::Destroy, portguard);
                    return kr::INVALID_RIGHT;
                }
                let request = self.right_request_cancel_pub(port, name);
                self.space.dealloc(name);
                let mut ns = None;
                if t & ty::SEND != 0 {
                    let p = self.port_mut(port);
                    p.srights -= 1;
                    if p.srights == 0 {
                        ns = self.no_senders_prepare_pub(port);
                    }
                }
                if t & ty::RECEIVE != 0 {
                    self.port_destroy(port);
                } else if t & ty::SEND_ONCE != 0 {
                    self.port_mut(port).reply_context = 0;
                    self.send_once_notify(port);
                } else {
                    self.release(port);
                }
                self.no_senders_emit(ns);
                if let Some(to) = request {
                    self.outbox.push(Notify::PortDeleted { to, name });
                }
            }
            _ => panic!("ipc_right_destroy: strange type {t:#x}"),
        }
        kr::SUCCESS
    }

    /// `ipc_space_terminate`: every entry's right ended as
    /// `ipc_right_terminate` ends it, in index order, and the space left
    /// empty. Its notifications are owed to the ports that asked for them
    /// (one whose receiver has gone takes the message no further).
    pub fn space_terminate(&mut self) {
        let names: Vec<(u32, space::Entry)> = self.space.names().map(|(n, e)| (n, *e)).collect();
        self.space = Space::new();
        for (name, e) in names {
            self.right_terminate(name, &e);
        }
    }

    /// `ipc_right_terminate`.
    fn right_terminate(&mut self, name: u32, e: &space::Entry) {
        let t = e.ty();
        match t {
            ty::DEAD_NAME => {}
            ty::PORT_SET => self.pset_destroy(e.object.expect("a set")),
            ty::SEND | ty::RECEIVE | ty::SEND_RECEIVE | ty::SEND_ONCE => {
                let port = e.object.expect("a port");
                if !self.port(port).active {
                    self.release(port);
                    return;
                }
                let request = if e.request != 0 { self.port_request_cancel(port, e.request) } else { None };
                let mut ns = None;
                if t & ty::SEND != 0 {
                    let p = self.port_mut(port);
                    p.srights -= 1;
                    if p.srights == 0 {
                        ns = self.no_senders_prepare_pub(port);
                    }
                }
                if t & ty::RECEIVE != 0 {
                    self.port_destroy(port);
                } else if t & ty::SEND_ONCE != 0 {
                    self.port_mut(port).reply_context = 0;
                    self.send_once_notify(port);
                } else {
                    self.release(port);
                }
                self.no_senders_emit(ns);
                if let Some(to) = request {
                    self.outbox.push(Notify::PortDeleted { to, name });
                }
            }
            _ => panic!("ipc_right_terminate: strange type {t:#x}"),
        }
    }

    /// `ipc_right_dealloc`: one user reference of `name`'s right gone.
    pub fn right_dealloc(&mut self, name: u32) -> u64 {
        let e = *self.space.lookup(name).expect("deallocated name in use");
        let mut t = e.ty();
        if matches!(t, ty::SEND | ty::SEND_ONCE) && self.right_check(name, false) {
            t = ty::DEAD_NAME;
        }
        let e = *self.space.lookup(name).expect("deallocated name in use");
        match t {
            ty::PORT_SET => {
                let pset = e.object.expect("a set");
                self.space.dealloc(name);
                self.pset_destroy(pset);
            }
            ty::DEAD_NAME => {
                if e.urefs() == 1 {
                    self.space.dealloc(name);
                } else if e.urefs() < UREFS_MAX {
                    self.space.lookup_mut(name).expect("in use").bits -= 1;
                }
            }
            ty::SEND_ONCE => {
                let port = e.object.expect("a port");
                self.port_mut(port).reply_context = 0;
                let request = self.right_request_cancel_pub(port, name);
                self.space.dealloc(name);
                self.send_once_notify(port);
                if let Some(to) = request {
                    self.outbox.push(Notify::PortDeleted { to, name });
                }
            }
            ty::SEND => {
                let port = e.object.expect("a port");
                let mut ns = None;
                let mut request = None;
                if e.urefs() == 1 {
                    if self.port(port).pinned {
                        self.guard_pinned(name, mpg_pinned::DEALLOC);
                        return kr::INVALID_CAPABILITY;
                    }
                    let p = self.port_mut(port);
                    p.srights -= 1;
                    if p.srights == 0 {
                        ns = self.no_senders_prepare_pub(port);
                    }
                    request = self.right_request_cancel_pub(port, name);
                    self.space.hash_delete(port);
                    self.space.dealloc(name);
                    self.release(port);
                } else if e.urefs() < UREFS_MAX {
                    self.space.lookup_mut(name).expect("in use").bits -= 1;
                }
                self.no_senders_emit(ns);
                if let Some(to) = request {
                    self.outbox.push(Notify::PortDeleted { to, name });
                }
            }
            ty::SEND_RECEIVE => {
                let port = e.object.expect("a port");
                let mut ns = None;
                let entry = self.space.lookup_mut(name).expect("in use");
                if e.urefs() == 1 {
                    entry.bits = e.bits & !(bits::UREFS_MASK | ty::SEND);
                    let p = self.port_mut(port);
                    p.srights -= 1;
                    if p.srights == 0 {
                        ns = self.no_senders_prepare_pub(port);
                    }
                } else if e.urefs() < UREFS_MAX {
                    entry.bits = e.bits - 1;
                }
                self.no_senders_emit(ns);
            }
            _ => {
                self.guard_exception(name, Guard::InvalidRight, 0);
                return kr::INVALID_RIGHT;
            }
        }
        kr::SUCCESS
    }

    /// `ipc_right_delta`: change `name`'s user references for `right` by
    /// `delta` (`mach_port_mod_refs`).
    pub fn right_delta(&mut self, name: u32, right: u32, mut delta: i32) -> u64 {
        let e = *self.space.lookup(name).expect("modified name in use");
        let b = e.bits;
        let invalid_value = |ipc: &mut Ipc| {
            ipc.guard_exception(name, Guard::InvalidValue, 0);
            kr::INVALID_VALUE
        };
        match right {
            port_right::PORT_SET => {
                if b & ty::PORT_SET == 0 {
                    self.guard_exception(name, Guard::InvalidRight, 0);
                    return kr::INVALID_RIGHT;
                }
                if delta == 0 {
                    return kr::SUCCESS;
                }
                if delta != -1 {
                    return invalid_value(self);
                }
                let pset = e.object.expect("a set");
                self.space.dealloc(name);
                self.pset_destroy(pset);
            }
            port_right::RECEIVE => {
                if b & ty::RECEIVE == 0 {
                    if b & ty::EX_RECEIVE == 0 {
                        self.guard_exception(name, Guard::InvalidRight, 0);
                    }
                    return kr::INVALID_RIGHT;
                }
                if delta == 0 {
                    return kr::SUCCESS;
                }
                if delta != -1 {
                    return invalid_value(self);
                }
                let port = e.object.expect("a port");
                if self.port(port).guarded {
                    let g = self.port(port).context;
                    self.guard_exception(name, Guard::ModRefs, g);
                    return kr::INVALID_RIGHT;
                }
                self.receive_right_goes(name, port);
            }
            port_right::SEND_ONCE => {
                if b & ty::SEND_ONCE == 0 {
                    return kr::INVALID_RIGHT;
                }
                let port = e.object.expect("a port");
                if self.right_check(name, false) {
                    self.guard_exception(name, Guard::InvalidRight, 0);
                    return kr::INVALID_RIGHT;
                }
                if !(-1..=0).contains(&delta) {
                    return invalid_value(self);
                }
                if delta == 0 {
                    return kr::SUCCESS;
                }
                self.port_mut(port).reply_context = 0;
                let request = self.right_request_cancel_pub(port, name);
                self.space.dealloc(name);
                self.send_once_notify(port);
                if let Some(to) = request {
                    self.outbox.push(Notify::PortDeleted { to, name });
                }
            }
            port_right::DEAD_NAME => {
                let mut b = b;
                if b & ty::SEND_RIGHTS != 0 {
                    if !self.right_check(name, false) {
                        self.guard_exception(name, Guard::InvalidRight, 0);
                        return kr::INVALID_RIGHT;
                    }
                    b = self.space.lookup(name).expect("in use").bits;
                } else if b & ty::DEAD_NAME == 0 {
                    self.guard_exception(name, Guard::InvalidRight, 0);
                    return kr::INVALID_RIGHT;
                }
                if delta > UREFS_MAX as i32 || delta < -(UREFS_MAX as i32) {
                    return invalid_value(self);
                }
                let urefs = b & bits::UREFS_MASK;
                if urefs == UREFS_MAX {
                    if delta != -(UREFS_MAX as i32) {
                        delta = 0;
                    }
                } else {
                    if (urefs as i32) + delta < 0 {
                        return invalid_value(self);
                    }
                    if (urefs as i32) + delta > UREFS_MAX as i32 {
                        delta = (UREFS_MAX - urefs) as i32;
                    }
                }
                if urefs as i32 + delta == 0 {
                    self.space.dealloc(name);
                } else if delta != 0 {
                    self.space.lookup_mut(name).expect("in use").bits = (b as i32 + delta) as u32;
                }
            }
            port_right::SEND => {
                if b & ty::SEND == 0 {
                    // A make-send on a receive right with delta 1 is let
                    // through without a guard (AE_MAKESENDRIGHT_FIXED unset).
                    if b & ty::DEAD_NAME == 0 && (b & ty::RECEIVE == 0 || delta != 1) {
                        self.guard_exception(name, Guard::InvalidRight, 0);
                    }
                    return kr::INVALID_RIGHT;
                }
                let port = e.object.expect("a port");
                if self.right_check(name, false) {
                    return kr::INVALID_RIGHT;
                }
                if delta > UREFS_MAX as i32 || delta < -(UREFS_MAX as i32) {
                    return invalid_value(self);
                }
                let urefs = b & bits::UREFS_MASK;
                if urefs == UREFS_MAX {
                    if delta != -(UREFS_MAX as i32) {
                        delta = 0;
                    }
                } else {
                    if (urefs as i32) + delta < 0 {
                        return invalid_value(self);
                    }
                    if (urefs as i32) + delta > UREFS_MAX as i32 {
                        delta = (UREFS_MAX - urefs) as i32;
                    }
                }
                if urefs as i32 + delta == 0 {
                    if self.port(port).pinned {
                        self.guard_pinned(name, mpg_pinned::DEALLOC);
                        return kr::INVALID_CAPABILITY;
                    }
                    let p = self.port_mut(port);
                    p.srights -= 1;
                    let ns = if p.srights == 0 { self.no_senders_prepare_pub(port) } else { None };
                    let mut request = None;
                    if b & ty::RECEIVE != 0 {
                        self.space.lookup_mut(name).expect("in use").bits = b & !(bits::UREFS_MASK | ty::SEND);
                    } else {
                        request = self.right_request_cancel_pub(port, name);
                        self.space.hash_delete(port);
                        self.space.dealloc(name);
                        self.release(port);
                    }
                    self.no_senders_emit(ns);
                    if let Some(to) = request {
                        self.outbox.push(Notify::PortDeleted { to, name });
                    }
                } else if delta != 0 {
                    self.space.lookup_mut(name).expect("in use").bits = (b as i32 + delta) as u32;
                }
            }
            port_right::LABELH => return kr::INVALID_RIGHT,
            _ => panic!("ipc_right_delta: strange right {right}"),
        }
        kr::SUCCESS
    }

    /// A receive right's name gives it up (`ipc_right_delta` RECEIVE and
    /// `ipc_right_destruct`): a remaining send right stays, as a send right
    /// to a port with a port-destroyed request or else as a dead name; the
    /// port is destroyed.
    fn receive_right_goes(&mut self, name: u32, port: ObjId) {
        let e = *self.space.lookup(name).expect("in use");
        let mut b = e.bits;
        let mut request = None;
        if b & ty::SEND != 0 {
            if self.port(port).pdrequest.is_some() {
                // The send right stays named, with a reference of its own:
                // port_destroy consumes the one the receive right had.
                b &= !ty::RECEIVE;
                b |= ty::EX_RECEIVE;
                self.space.hash_insert(port, name);
                self.space.lookup_mut(name).expect("in use").bits = b;
                self.reference(port);
            } else {
                b &= !bits::TYPE_MASK;
                b |= ty::DEAD_NAME | ty::EX_RECEIVE;
                let entry = self.space.lookup_mut(name).expect("in use");
                if entry.request != 0 {
                    entry.request = 0;
                    if b & bits::UREFS_MASK < UREFS_MAX {
                        b += 1;
                    }
                }
                entry.object = None;
                entry.bits = b;
            }
        } else {
            request = self.right_request_cancel_pub(port, name);
            self.space.dealloc(name);
        }
        self.port_destroy(port);
        if let Some(to) = request {
            self.outbox.push(Notify::PortDeleted { to, name });
        }
    }

    /// `ipc_right_destruct`: the receive right (and `srdelta` send
    /// references) given up, with the guard checked.
    pub fn right_destruct(&mut self, name: u32, mut srdelta: i32, guard: u64) -> u64 {
        let e = *self.space.lookup(name).expect("destructed name in use");
        let b = e.bits;
        if b & ty::RECEIVE == 0 {
            if b & ty::EX_RECEIVE == 0 {
                self.guard_exception(name, Guard::InvalidRight, 0);
            }
            return kr::INVALID_RIGHT;
        }
        if srdelta != 0 && b & ty::SEND == 0 {
            self.guard_exception(name, Guard::InvalidRight, 0);
            return kr::INVALID_RIGHT;
        }
        if srdelta > 0 {
            self.guard_exception(name, Guard::InvalidValue, 0);
            return kr::INVALID_VALUE;
        }
        let port = e.object.expect("a port");
        let p = self.port(port);
        if p.guarded && guard != p.context {
            let g = p.context;
            self.guard_exception(name, Guard::Destroy, g);
            return kr::INVALID_ARGUMENT;
        }
        let mut ns = None;
        if srdelta != 0 {
            let urefs = b & bits::UREFS_MASK;
            if (urefs as i32) + srdelta < 0 {
                self.guard_exception(name, Guard::InvalidValue, 0);
                return kr::INVALID_VALUE;
            }
            if urefs == UREFS_MAX && srdelta != -(UREFS_MAX as i32) {
                srdelta = 0;
            }
            let entry = self.space.lookup_mut(name).expect("in use");
            if urefs as i32 + srdelta == 0 {
                entry.bits = b & !(bits::UREFS_MASK | ty::SEND);
                let p = self.port_mut(port);
                p.srights -= 1;
                if p.srights == 0 {
                    ns = self.no_senders_prepare_pub(port);
                }
            } else {
                entry.bits = (b as i32 + srdelta) as u32;
            }
        }
        self.no_senders_emit(ns);
        self.receive_right_goes(name, port);
        kr::SUCCESS
    }

    /// `ipc_right_info`: `name`'s type (with request bits) and user
    /// references.
    pub fn right_info(&mut self, name: u32) -> (u32, u32) {
        let e = *self.space.lookup(name).expect("in use");
        let mut t = 0;
        let mut b = e.bits;
        if b & ty::RECEIVE != 0 {
            if e.request != 0 {
                t |= self.port_request_type(e.object.expect("a port"), e.request);
            }
        } else if b & ty::SEND_RIGHTS != 0 {
            let port = e.object.expect("a port");
            if !self.right_check(name, false) {
                if e.request != 0 {
                    t |= self.port_request_type(port, e.request);
                }
            } else {
                b = self.space.lookup(name).expect("in use").bits;
            }
        }
        t |= b & bits::TYPE_MASK;
        (t, b & bits::UREFS_MASK)
    }

    /// `ipc_right_request_alloc`: arm (or with no `notify`, cancel)
    /// `name`'s dead-name request, or a send-possible one. The previous
    /// request's send-once right, for the caller to return.
    pub fn right_request_alloc(&mut self, name: u32, opts: u32, notify: Option<ObjId>) -> Result<Option<ObjId>, u64> {
        let spreq = opts & IPR_SOR_SPREQ_MASK != 0;
        let sparm = opts & IPR_SOR_SPARM_MASK != 0;
        let e = *self.space.lookup(name).ok_or(kr::INVALID_NAME)?;
        let prev = e.request;
        if notify.is_none() && prev == 0 {
            return Ok(None);
        }
        if e.bits & ty::PORT_RIGHTS != 0 {
            let port = e.object.expect("a port");
            if !self.right_check(name, false) {
                let mut previous = None;
                let Some(n) = notify else {
                    if prev != 0 {
                        previous = self.port_request_cancel(port, prev);
                        self.space.lookup_mut(name).expect("in use").request = 0;
                    }
                    return Ok(previous);
                };
                let p = self.port(port);
                // ip_full: the queue's count, reservations included.
                let full = p.msgcount >= p.qlimit;
                if spreq && sparm && (e.bits & ty::SEND_ONCE != 0 || p.receiver == Receiver::Kernel || !full) {
                    if prev != 0 {
                        previous = self.port_request_cancel(port, prev);
                        self.space.lookup_mut(name).expect("in use").request = 0;
                    }
                    self.outbox.push(Notify::SendPossible { to: n, name });
                    return Ok(previous);
                }
                if prev != 0 {
                    previous = self.port_request_cancel(port, prev);
                }
                let index = self.port_request_alloc(port, name, n, spreq, sparm);
                self.space.lookup_mut(name).expect("in use").request = index;
                return Ok(previous);
            }
        }
        let e = *self.space.lookup(name).expect("in use");
        if opts != 0 && notify.is_some() && e.bits & ty::DEAD_NAME != 0 {
            if e.urefs() < UREFS_MAX {
                self.space.lookup_mut(name).expect("in use").bits += 1;
            }
            self.outbox.push(Notify::DeadName { to: notify.expect("checked"), name });
            return Ok(None);
        }
        Err(if e.bits & ty::PORT_OR_DEAD != 0 { kr::INVALID_ARGUMENT } else { kr::INVALID_RIGHT })
    }
}

impl Space {
    /// An entry just claimed by [`Space::alloc`], before its type is set.
    pub(crate) fn lookup_mut_any(&mut self, name: u32) -> &mut space::Entry {
        self.entry_at(space::index(name))
    }
}
