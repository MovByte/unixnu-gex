//! Messages in the kernel (`ipc_kmsg`) and the queues they wait in
//! (`ipc_mqueue`): a message holds the rights its sender moved, queued on
//! its destination until a receiver takes it or handed straight to a
//! receiver already waiting.

use super::right::{msgt, Carried};
use super::{Ipc, Object, ObjId, Receiver};
use std::collections::{HashMap, VecDeque};

/// `mach_msg_return_t`s.
pub mod mr {
    pub const SUCCESS: u32 = 0;
    pub const SEND_IN_PROGRESS: u32 = 0x1000_0001;
    pub const SEND_INVALID_DATA: u32 = 0x1000_0002;
    pub const SEND_INVALID_DEST: u32 = 0x1000_0003;
    pub const SEND_TIMED_OUT: u32 = 0x1000_0004;
    pub const SEND_INVALID_VOUCHER: u32 = 0x1000_0005;
    pub const SEND_INTERRUPTED: u32 = 0x1000_0007;
    pub const SEND_MSG_TOO_SMALL: u32 = 0x1000_0008;
    pub const SEND_INVALID_REPLY: u32 = 0x1000_0009;
    pub const SEND_INVALID_RIGHT: u32 = 0x1000_000a;
    pub const SEND_INVALID_NOTIFY: u32 = 0x1000_000b;
    pub const SEND_INVALID_MEMORY: u32 = 0x1000_000c;
    pub const SEND_NO_BUFFER: u32 = 0x1000_000d;
    pub const SEND_TOO_LARGE: u32 = 0x1000_000e;
    pub const SEND_INVALID_TYPE: u32 = 0x1000_000f;
    pub const SEND_INVALID_HEADER: u32 = 0x1000_0010;
    pub const SEND_INVALID_TRAILER: u32 = 0x1000_0011;
    pub const SEND_INVALID_OPTIONS: u32 = 0x1000_0013;
    pub const SEND_AUX_TOO_SMALL: u32 = 0x1000_0018;
    pub const SEND_AUX_TOO_LARGE: u32 = 0x1000_0019;
    pub const RCV_IN_PROGRESS: u32 = 0x1000_4001;
    pub const RCV_INVALID_NAME: u32 = 0x1000_4002;
    pub const RCV_TIMED_OUT: u32 = 0x1000_4003;
    pub const RCV_TOO_LARGE: u32 = 0x1000_4004;
    pub const RCV_INTERRUPTED: u32 = 0x1000_4005;
    pub const RCV_PORT_CHANGED: u32 = 0x1000_4006;
    pub const RCV_INVALID_NOTIFY: u32 = 0x1000_4007;
    pub const RCV_INVALID_DATA: u32 = 0x1000_4008;
    pub const RCV_PORT_DIED: u32 = 0x1000_4009;
    pub const RCV_HEADER_ERROR: u32 = 0x1000_400b;
    pub const RCV_BODY_ERROR: u32 = 0x1000_400c;
    pub const RCV_INVALID_TYPE: u32 = 0x1000_400d;
    pub const RCV_INVALID_TRAILER: u32 = 0x1000_400f;
    pub const RCV_INVALID_REPLY: u32 = 0x1000_4012;
    pub const RCV_INVALID_ARGUMENTS: u32 = 0x1000_4013;
    /// `MACH_MSG_IPC_SPACE`, `MACH_MSG_VM_SPACE`, `MACH_MSG_IPC_KERNEL`,
    /// `MACH_MSG_VM_KERNEL`: the extra bits a body error carries.
    pub const MSG_IPC_SPACE: u32 = 0x0000_2000;
    pub const MSG_VM_SPACE: u32 = 0x0000_1000;
    pub const MSG_IPC_KERNEL: u32 = 0x0000_0800;
    pub const MSG_VM_KERNEL: u32 = 0x0000_0400;
    pub const MSG_MASK: u32 = 0x0000_3e00;
    pub const KERN_NOT_SUPPORTED: u32 = 46;
}

/// `MACH_MSGH_BITS_*`.
pub mod bits {
    pub const REMOTE_MASK: u32 = 0x0000_001f;
    pub const LOCAL_MASK: u32 = 0x0000_1f00;
    pub const VOUCHER_MASK: u32 = 0x001f_0000;
    pub const PORTS_MASK: u32 = REMOTE_MASK | LOCAL_MASK | VOUCHER_MASK;
    pub const COMPLEX: u32 = 0x8000_0000;
    pub const USER: u32 = 0x801f_1f1f;
    pub const RAISEIMP: u32 = 0x2000_0000;
    pub const CIRCULAR: u32 = 0x1000_0000;

    pub fn remote(b: u32) -> u32 {
        b & REMOTE_MASK
    }

    pub fn local(b: u32) -> u32 {
        (b & LOCAL_MASK) >> 8
    }

    pub fn voucher(b: u32) -> u32 {
        (b & VOUCHER_MASK) >> 16
    }

    /// `MACH_MSGH_BITS_SET`.
    pub fn set(remote: u32, local: u32, voucher: u32, other: u32) -> u32 {
        (remote & 0x1f) | ((local & 0x1f) << 8) | ((voucher & 0x1f) << 16) | (other & !PORTS_MASK)
    }
}

/// `mach_msg_option64_t` bits this layer reads.
pub mod opt {
    pub const SEND_MSG: u64 = 0x1;
    pub const RCV_MSG: u64 = 0x2;
    pub const RCV_LARGE: u64 = 0x4;
    pub const RCV_LARGE_IDENTITY: u64 = 0x8;
    pub const SEND_TIMEOUT: u64 = 0x10;
    pub const SEND_OVERRIDE: u64 = 0x20;
    pub const SEND_INTERRUPT: u64 = 0x40;
    pub const SEND_NOTIFY: u64 = 0x80;
    pub const RCV_TIMEOUT: u64 = 0x100;
    pub const RCV_INTERRUPT: u64 = 0x400;
    pub const RCV_VOUCHER: u64 = 0x800;
    pub const RCV_GUARDED_DESC: u64 = 0x1000;
    pub const RCV_SYNC_WAIT: u64 = 0x4000;
    pub const RCV_SYNC_PEEK: u64 = 0x8000;
    pub const SEND_ALWAYS: u64 = 0x1_0000;
    pub const SEND_FILTER_NONFATAL: u64 = 0x1_0000;
    pub const SEND_TRAILER: u64 = 0x2_0000;
    pub const SEND_NOIMPORTANCE: u64 = 0x4_0000;
    pub const SEND_SYNC_OVERRIDE: u64 = 0x10_0000;
    pub const SEND_PROPAGATE_QOS: u64 = 0x20_0000;
    pub const SEND_SYNC_BOOTSTRAP_CHECKIN: u64 = 0x80_0000;
    pub const MSG_STRICT_REPLY: u64 = 0x200;
    pub const MSG_VECTOR: u64 = 0x1_0000_0000;
    pub const SEND_KOBJECT_CALL: u64 = 0x2_0000_0000;
    pub const SEND_MQ_CALL: u64 = 0x4_0000_0000;
    pub const SEND_ANY: u64 = 0x8_0000_0000;
    pub const SEND_DK_CALL: u64 = 0x10_0000_0000;
    pub const CFI_MASK: u64 = SEND_KOBJECT_CALL | SEND_MQ_CALL | SEND_ANY | SEND_DK_CALL;
    pub const RCV_TRAILER_TYPE_SHIFT: u32 = 28;
    pub const RCV_TRAILER_ELEMENTS_SHIFT: u32 = 24;
}

/// The trailer a receive asks for: its size by the elements requested
/// (`REQUESTED_TRAILER_SIZE` for a 64-bit task).
pub fn trailer_size(options: u64) -> u32 {
    match (options >> opt::RCV_TRAILER_ELEMENTS_SHIFT) & 0xf {
        0 => 8,
        1 => 12,
        2 => 20,
        3 => 52,
        4 => 60,
        7 => 64,
        _ => 68,
    }
}

/// A sender's identity, as its trailer reports it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sender {
    /// `security_token_t`: effective uid and gid.
    pub sec: [u32; 2],
    /// `audit_token_t`: auid, euid, egid, ruid, rgid, pid, asid,
    /// pidversion.
    pub audit: [u32; 8],
}

impl Sender {
    /// `KERNEL_SECURITY_TOKEN_VALUE`, `KERNEL_AUDIT_TOKEN_VALUE`.
    pub const KERNEL: Sender = Sender { sec: [0, 1], audit: [0; 8] };
}

/// A descriptor of a complex message, at its offset in the body.
#[derive(Clone, Debug)]
pub enum Desc {
    /// A port right, or a name that is not one (null or dead) carried as
    /// it is.
    Port { off: usize, right: Option<Carried>, raw: u32, disp: u32 },
    /// Out-of-line memory, copied at send.
    Ool { off: usize, data: Vec<u8>, copy: u8 },
    /// An array of rights.
    OolPorts { off: usize, rights: Vec<(Option<Carried>, u32)>, disp: u32, copy: u8 },
    /// A receive right with its guard (`MACH_MSG_GUARDED_PORT_DESCRIPTOR`).
    Guarded { off: usize, right: Option<Carried>, raw: u32, disp: u32, flags: u32 },
}

/// A message in the kernel (`struct ipc_kmsg`).
#[derive(Clone, Debug)]
pub struct Kmsg {
    /// `msgh_bits`, its rights' types as copied in.
    pub bits: u32,
    /// The user message's size (`msgh_size`).
    pub size: u32,
    pub dest: ObjId,
    pub reply: Option<Carried>,
    /// The voucher's port, sent with `MACH_MSG_TYPE_MOVE_SEND`.
    pub voucher: Option<ObjId>,
    /// `msgh_voucher_port` as sent when no voucher right went with it.
    pub voucher_raw: u32,
    pub id: i32,
    /// Everything after the 24-byte header, in the user's layout.
    pub body: Vec<u8>,
    pub descs: Vec<Desc>,
    pub sender: Sender,
    /// Auxiliary data (`MACH64_MSG_VECTOR`'s second vector).
    pub aux: Vec<u8>,
    /// A kept-alive kernel message (`IPC_KMSG_ALLOC_USE_KEEP_ALIVE`): an
    /// mk_timer's expiry message, reused once received.
    pub keep_alive: bool,
}

/// What a receive came to, for the receiving thread
/// (`ith_state`/`ith_kmsg`).
#[derive(Clone, Debug)]
pub struct Received {
    pub state: u32,
    pub kmsg: Option<Box<Kmsg>>,
    pub seqno: u32,
    pub msize: u32,
    pub asize: u32,
    /// The receive right's name the message came on.
    pub receiver_name: u32,
}

/// A thread waiting to receive (`ith_*` while blocked in
/// `ipc_mqueue_receive`).
#[derive(Clone, Copy, Debug)]
pub struct RcvWait {
    pub object: ObjId,
    pub options: u64,
    pub rcv_size: u32,
    pub aux_size: u32,
}

/// The message queues' waiters (`ip_messages` waitqs).
#[derive(Debug, Default)]
pub struct Queues {
    /// Threads waiting to receive, by object (a port or a set), in the
    /// order they came.
    pub receivers: HashMap<ObjId, VecDeque<i32>>,
    pub rcv_wait: HashMap<i32, RcvWait>,
    /// Threads waiting for room on a full port, in the order they came.
    pub senders: HashMap<ObjId, VecDeque<i32>>,
    /// Receives that have ended, waiting for their thread to take them.
    pub received: HashMap<i32, Received>,
    /// Sends a receiver made room for: the waiter's reservation is held.
    pub send_ready: HashMap<i32, bool>,
    /// For each set, its members with messages in the order they got
    /// them (`waitq_set` preposts).
    pub preposts: HashMap<ObjId, VecDeque<ObjId>>,
    /// Threads woken by a queue operation, for the kernel to wake.
    pub wake: Vec<i32>,
    /// Ports whose queue gained a message with no receiver waiting,
    /// for kevent's EVFILT_MACHPORT (`KNOTE(&port->ip_klist)`).
    pub knotes: Vec<ObjId>,
}

/// `ipc_mqueue_msg_too_large` for a non-linear receive.
fn too_large(msize: u32, tsize: u32, asize: u32, w: &RcvWait) -> bool {
    w.rcv_size < msize + tsize || (w.options & opt::MSG_VECTOR != 0 && w.aux_size < asize)
}

impl Ipc {
    /// `imq_full`: the queue's reservations at its limit.
    fn full(&self, port: ObjId) -> bool {
        let p = self.port(port);
        p.msgcount >= p.qlimit
    }

    /// `imq_full_kernel`.
    fn full_kernel(&self, port: ObjId) -> bool {
        self.port(port).msgcount >= super::QLIMIT_KERNEL
    }

    /// `ipc_mqueue_send_locked`'s first half: reserve room for `kmsg`. `Ok`
    /// to post now, `Err(None)` to wait for room, `Err(Some(mr))` to fail.
    pub fn mqueue_reserve(&mut self, port: ObjId, send_once: bool, options: u64, timeout_zero: bool) -> Result<(), Option<u32>> {
        if !self.full(port) || (!self.full_kernel(port) && (options & opt::SEND_ALWAYS != 0 || send_once)) {
            self.port_mut(port).msgcount += 1;
            return Ok(());
        }
        if options & opt::SEND_TIMEOUT != 0 && timeout_zero {
            return Err(Some(mr::SEND_TIMED_OUT));
        }
        if self.full_kernel(port) {
            return Err(Some(mr::SEND_NO_BUFFER));
        }
        self.port_mut(port).fullwaiters = true;
        Err(None)
    }

    /// Wait for room on `port` (the sending thread `tid`).
    pub fn mqueue_wait_room(&mut self, port: ObjId, tid: i32) {
        self.queues.senders.entry(port).or_default().push_back(tid);
    }

    /// A room wait that ended without room (timed out, interrupted).
    pub fn mqueue_cancel_room(&mut self, port: ObjId, tid: i32) {
        if let Some(q) = self.queues.senders.get_mut(&port) {
            q.retain(|&t| t != tid);
        }
        self.queues.send_ready.remove(&tid);
    }

    /// `ipc_mqueue_release_msgcount`: one reservation done; a sender
    /// waiting for room gets it.
    fn release_msgcount(&mut self, port: ObjId) {
        self.port_mut(port).msgcount -= 1;
        if !self.full(port) && self.port(port).fullwaiters {
            match self.queues.senders.get_mut(&port).and_then(|q| q.pop_front()) {
                Some(t) => {
                    self.port_mut(port).msgcount += 1;
                    self.queues.send_ready.insert(t, true);
                    self.queues.wake.push(t);
                }
                None => self.port_mut(port).fullwaiters = false,
            }
        }
        if self.port(port).messages.is_empty() {
            for s in self.port(port).psets.clone() {
                if let Some(q) = self.queues.preposts.get_mut(&s) {
                    q.retain(|&m| m != port);
                }
            }
        }
    }

    /// `ipc_mqueue_set_qlimit_locked`: a higher limit lets waiting senders
    /// in.
    pub fn mqueue_set_qlimit(&mut self, port: ObjId, qlimit: u32) {
        let old = self.port(port).qlimit;
        if qlimit > old {
            for _ in 0..qlimit - old {
                match self.queues.senders.get_mut(&port).and_then(|q| q.pop_front()) {
                    Some(t) => {
                        self.port_mut(port).msgcount += 1;
                        self.queues.send_ready.insert(t, true);
                        self.queues.wake.push(t);
                    }
                    None => {
                        self.port_mut(port).fullwaiters = false;
                        break;
                    }
                }
            }
        }
        self.port_mut(port).qlimit = qlimit;
    }

    /// The thread that should get a message posted to `port`: one waiting
    /// on the port itself, then one waiting on a set it is in.
    fn identify_receiver(&mut self, port: ObjId, skip: &[i32]) -> Option<(i32, ObjId)> {
        let mut objs = vec![port];
        objs.extend(self.port(port).psets.iter().copied());
        for o in objs {
            if let Some(q) = self.queues.receivers.get(&o) {
                if let Some(&t) = q.iter().find(|t| !skip.contains(t)) {
                    return Some((t, o));
                }
            }
        }
        None
    }

    /// `ipc_mqueue_post`: `kmsg` (its room reserved) to a waiting receiver,
    /// or onto the queue.
    pub fn mqueue_post(&mut self, port: ObjId, kmsg: Box<Kmsg>, copyout_size: u32) {
        let mut skip = Vec::new();
        loop {
            let Some((t, obj)) = self.identify_receiver(port, &skip) else {
                let p = self.port_mut(port);
                p.messages.push_back(kmsg);
                let has_knotes = p.knotes != 0;
                for s in p.psets.clone() {
                    let q = self.queues.preposts.entry(s).or_default();
                    if !q.contains(&port) {
                        q.push_back(port);
                    }
                }
                if has_knotes {
                    self.queues.knotes.push(port);
                }
                return;
            };
            let w = self.queues.rcv_wait[&t];
            let tsize = trailer_size(w.options);
            let asize = kmsg.aux.len() as u32;
            let receiver_name = match self.port(port).receiver {
                Receiver::Space(n) => n,
                _ => 0,
            };
            let big = too_large(copyout_size, tsize, asize, &w);
            if !big || w.options & opt::RCV_LARGE == 0 {
                let seqno = self.port(port).seqno;
                self.port_mut(port).seqno = seqno.wrapping_add(1);
                let state = if big { mr::RCV_TOO_LARGE } else { mr::SUCCESS };
                self.receiver_done(t, obj, Received { state, kmsg: Some(kmsg), seqno, msize: copyout_size, asize, receiver_name });
                self.release_msgcount(port);
                return;
            }
            // Too large for a receiver that wants to know: it learns the
            // size, and the message goes on to the next.
            self.receiver_done(t, obj, Received { state: mr::RCV_TOO_LARGE, kmsg: None, seqno: 0, msize: copyout_size, asize, receiver_name });
            skip.push(t);
        }
    }

    /// `ipc_mqueue_add_locked`'s hand-off: `port`, just linked to `set`,
    /// gives its queued messages to the set's waiting receivers, and
    /// preposts the set with what is left.
    pub fn mqueue_link_messages(&mut self, port: ObjId, set: ObjId) {
        let mut skip = Vec::new();
        while let Some(kmsg) = self.port(port).messages.front() {
            let msize = kmsg.size;
            let asize = kmsg.aux.len() as u32;
            let Some(&t) = self.queues.receivers.get(&set).and_then(|q| q.iter().find(|t| !skip.contains(*t))) else {
                let q = self.queues.preposts.entry(set).or_default();
                if !q.contains(&port) {
                    q.push_back(port);
                }
                break;
            };
            let w = self.queues.rcv_wait[&t];
            let receiver_name = match self.port(port).receiver {
                Receiver::Space(n) => n,
                _ => 0,
            };
            let big = too_large(msize, trailer_size(w.options), asize, &w);
            if big && w.options & opt::RCV_LARGE != 0 {
                self.receiver_done(t, set, Received { state: mr::RCV_TOO_LARGE, kmsg: None, seqno: 0, msize, asize, receiver_name });
                skip.push(t);
                continue;
            }
            let kmsg = self.port_mut(port).messages.pop_front().expect("checked");
            self.release_msgcount(port);
            let seqno = self.port(port).seqno;
            self.port_mut(port).seqno = seqno.wrapping_add(1);
            let state = if big { mr::RCV_TOO_LARGE } else { mr::SUCCESS };
            self.receiver_done(t, set, Received { state, kmsg: Some(kmsg), seqno, msize, asize, receiver_name });
        }
    }

    /// A waiting receiver's wait ends with `r`.
    fn receiver_done(&mut self, t: i32, obj: ObjId, r: Received) {
        if let Some(q) = self.queues.receivers.get_mut(&obj) {
            q.retain(|&x| x != t);
        }
        self.queues.rcv_wait.remove(&t);
        self.queues.received.insert(t, r);
        self.queues.wake.push(t);
    }

    /// `ipc_mqueue_copyin`: the port or set `name` receives on.
    pub fn mqueue_copyin(&mut self, name: u32) -> Result<ObjId, u32> {
        let Some(e) = self.space.lookup(name).copied() else { return Err(mr::RCV_INVALID_NAME) };
        if e.bits & (super::ty::RECEIVE | super::ty::PORT_SET) != 0 {
            let o = e.object.expect("a receive or set right names an object");
            self.reference(o);
            Ok(o)
        } else {
            if e.bits & super::ty::EX_RECEIVE == 0 {
                self.guard_exception(name, super::Guard::RcvInvalidName, 0);
            }
            Err(mr::RCV_INVALID_NAME)
        }
    }

    /// The port a receive on `object` takes a message from now, if any
    /// (`ipc_mqueue_receive_on_thread_and_unlock`'s look at the queue).
    fn ready_port(&self, object: ObjId) -> Option<ObjId> {
        match &self.objects[&object] {
            Object::Port(p) => (!p.messages.is_empty()).then_some(object),
            Object::Pset(_) => self.queues.preposts.get(&object).and_then(|q| q.iter().copied().find(|&m| !self.port(m).messages.is_empty())),
        }
    }

    /// `ipc_mqueue_select_on_thread_locked`: take the first message from
    /// `port` for a receive with these limits.
    fn select(&mut self, port: ObjId, w: &RcvWait, msize_of: &dyn Fn(&Kmsg) -> u32) -> Received {
        let kmsg = self.port(port).messages.front().expect("a ready port has a message");
        let msize = msize_of(kmsg);
        let asize = kmsg.aux.len() as u32;
        let receiver_name = match self.port(port).receiver {
            Receiver::Space(n) => n,
            _ => 0,
        };
        let big = too_large(msize, trailer_size(w.options), asize, w);
        if big && w.options & opt::RCV_LARGE != 0 {
            return Received { state: mr::RCV_TOO_LARGE, kmsg: None, seqno: 0, msize, asize, receiver_name };
        }
        let kmsg = self.port_mut(port).messages.pop_front().expect("checked");
        self.release_msgcount(port);
        let seqno = self.port(port).seqno;
        self.port_mut(port).seqno = seqno.wrapping_add(1);
        Received { state: if big { mr::RCV_TOO_LARGE } else { mr::SUCCESS }, kmsg: Some(kmsg), seqno, msize, asize, receiver_name }
    }

    /// Receive on `object` now or wait. `Some` when the receive has ended
    /// (a message, or a timeout of zero); `None` when the thread waits.
    pub fn mqueue_receive(&mut self, tid: i32, object: ObjId, w: RcvWait, timeout_zero: bool, msize_of: &dyn Fn(&Kmsg) -> u32) -> Option<Received> {
        if let Some(port) = self.ready_port(object) {
            return Some(self.select(port, &w, msize_of));
        }
        let alive = match &self.objects[&object] {
            Object::Port(p) => p.active,
            Object::Pset(s) => s.active,
        };
        if !alive {
            return Some(Received { state: mr::RCV_PORT_CHANGED, kmsg: None, seqno: 0, msize: 0, asize: 0, receiver_name: 0 });
        }
        if w.options & opt::RCV_TIMEOUT != 0 && timeout_zero {
            return Some(Received { state: mr::RCV_TIMED_OUT, kmsg: None, seqno: 0, msize: 0, asize: 0, receiver_name: 0 });
        }
        self.queues.receivers.entry(object).or_default().push_back(tid);
        self.queues.rcv_wait.insert(tid, w);
        None
    }

    /// A receive wait that ended without a message (timed out,
    /// interrupted): the thread leaves the queue.
    pub fn mqueue_cancel_receive(&mut self, tid: i32) {
        if let Some(w) = self.queues.rcv_wait.remove(&tid) {
            if let Some(q) = self.queues.receivers.get_mut(&w.object) {
                q.retain(|&t| t != tid);
            }
        }
    }

    /// `ipc_mqueue_changed`: an object's receivers lose it (the port died
    /// or left the space); each wakes with `MACH_RCV_PORT_CHANGED`.
    pub fn mqueue_changed(&mut self, object: ObjId) {
        let waiters: Vec<i32> = self.queues.receivers.remove(&object).map(|q| q.into_iter().collect()).unwrap_or_default();
        for t in waiters {
            self.queues.rcv_wait.remove(&t);
            self.queues.received.insert(t, Received { state: mr::RCV_PORT_CHANGED, kmsg: None, seqno: 0, msize: 0, asize: 0, receiver_name: 0 });
            self.queues.wake.push(t);
        }
    }

    /// Senders waiting on a port that died wake to find it gone
    /// (`THREAD_RESTART`: `MACH_SEND_INVALID_DEST`).
    pub fn mqueue_senders_restart(&mut self, port: ObjId) {
        let waiters: Vec<i32> = self.queues.senders.remove(&port).map(|q| q.into_iter().collect()).unwrap_or_default();
        for t in waiters {
            self.queues.send_ready.insert(t, false);
            self.queues.wake.push(t);
        }
    }

    /// `ipc_kmsg_destroy`: every right a message holds, destroyed.
    pub fn kmsg_destroy(&mut self, kmsg: Box<Kmsg>, skip_remote: bool) {
        if !skip_remote {
            self.object_destroy(Carried::Port(kmsg.dest), bits::remote(kmsg.bits));
        }
        if let Some(r) = kmsg.reply {
            self.object_destroy(r, bits::local(kmsg.bits));
        }
        if let Some(v) = kmsg.voucher {
            self.object_destroy(Carried::Port(v), msgt::PORT_SEND);
        }
        self.descs_destroy(&kmsg.descs);
    }

    /// `ipc_kmsg_clean_descriptors`.
    pub fn descs_destroy(&mut self, descs: &[Desc]) {
        for d in descs {
            match d {
                Desc::Port { right: Some(r), disp, .. } | Desc::Guarded { right: Some(r), disp, .. } => self.object_destroy(*r, *disp),
                Desc::OolPorts { rights, disp, .. } => {
                    for (r, _) in rights {
                        if let Some(r) = r {
                            self.object_destroy(*r, *disp);
                        }
                    }
                }
                _ => {}
            }
        }
    }
}
