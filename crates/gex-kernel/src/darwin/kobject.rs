//! Kernel objects' ports (`osfmk/kern/ipc_kobject.c`, `ipc_tt.c`): the
//! task's, the host's, each thread's, and the ports of semaphores, timers
//! and the clock; and the server that answers MIG requests sent to them.

use super::ipc::msg::{bits, Desc, Kmsg, Sender};
use super::ipc::right::{msgt, Carried};
use super::ipc::{Kobject, ObjId, Receiver};
use super::jobctl::HoldMode;
use crate::syscalls::Kernel;
use std::collections::HashMap;

/// The task's kernel object ports.
///
/// An iOS task's control ports are immovable and pinned (the default
/// `ipc_control_port_options`: immovable for first and third parties,
/// pinned hard for the first, soft for the third). Its control port is
/// then a labeled port whose send rights, copied out into the task's own
/// space, become those of an immovable equivalent, the self port
/// (`ipc_task_set_immovable_pinned`, `ipc_thread_init`).
#[derive(Debug, Default)]
pub struct Kports {
    /// `itk_task_ports[TASK_FLAVOR_CONTROL]` and `itk_self`.
    pub task: Option<(ObjId, ObjId)>,
    pub task_name: Option<ObjId>,
    /// Each thread's control port and self port.
    pub threads: HashMap<i32, (ObjId, ObjId)>,
    /// Each thread's special reply port (`ith_special_reply_port`).
    pub special_reply: HashMap<i32, ObjId>,
    /// `task_set_special_port`'s ports, by which (send rights held).
    pub special: HashMap<i32, ObjId>,
    /// `itk_registered`: `mach_ports_register`'s ports (send rights held).
    pub registered: [Option<ObjId>; 3],
    /// `itk_resume`: the task's resume port, once a suspension made it.
    pub resume: Option<ObjId>,
    /// `task_restartable_ranges_register`'s ranges.
    pub restartable: Vec<(u64, u16, u16, u32)>,
}

/// `MIG_NO_REPLY`, `MIG_BAD_ID`.
pub const MIG_NO_REPLY: i32 = -305;
pub const MIG_BAD_ID: i32 = -303;

impl Kernel {
    /// The task's control port and self port, made with the task.
    fn task_ports(&mut self) -> (ObjId, ObjId) {
        if let Some(t) = self.dtask.kports.task {
            return t;
        }
        let ipc = &mut self.ipc();
        let pport = ipc.kobject_port(Kobject::Task);
        let pp = ipc.port_mut(pport);
        pp.immovable_send = true;
        pp.pinned = true;
        let kport = ipc.kobject_port(Kobject::Task);
        ipc.port_mut(kport).subst = Some(pport);
        self.dtask.kports.task = Some((kport, pport));
        (kport, pport)
    }

    /// The task's control port (`itk_task_ports[TASK_FLAVOR_CONTROL]`).
    pub(crate) fn darwin_task_port(&mut self) -> ObjId {
        self.task_ports().0
    }

    /// The task's self port (`itk_self`), what `mach_task_self` names.
    pub(crate) fn darwin_task_self_port(&mut self) -> ObjId {
        self.task_ports().1
    }

    /// The host port (`realhost.special[HOST_PORT]`).
    pub(crate) fn darwin_host_port(&mut self) -> ObjId {
        self.ipc().global_port(Kobject::Host)
    }

    /// The host privilege port.
    pub(crate) fn darwin_host_priv_port(&mut self) -> ObjId {
        self.ipc().global_port(Kobject::HostPriv)
    }

    /// The task's host port (`itk_host`), as `set_security_token` sets it
    /// with each change of identity: the host privilege port for root,
    /// the host port for anyone else. No MAC policy here takes it from
    /// root (`mac_system_check_host_priv`).
    pub(crate) fn darwin_itk_host(&mut self) -> ObjId {
        if self.creds.uid() == 0 { self.darwin_host_priv_port() } else { self.darwin_host_port() }
    }

    /// The system clock's port.
    pub(crate) fn darwin_clock_port(&mut self) -> ObjId {
        self.ipc().global_port(Kobject::Clock)
    }

    /// Thread `tid`'s control port and self port (`ipc_thread_init`),
    /// made with the thread: the main thread's self port is pinned at once
    /// (`ipc_main_thread_set_immovable_pinned`), another's when its port is
    /// first copied out pinned.
    pub(crate) fn darwin_thread_ports(&mut self, tid: i32) -> (ObjId, ObjId) {
        if let Some(&p) = self.dtask.kports.threads.get(&tid) {
            return p;
        }
        let main = tid == self.pid;
        let ipc = &mut self.ipc();
        let pport = ipc.kobject_port(Kobject::Thread(tid));
        let pp = ipc.port_mut(pport);
        pp.immovable_send = true;
        pp.pinned = main;
        let kport = ipc.kobject_port(Kobject::Thread(tid));
        ipc.port_mut(kport).subst = Some(pport);
        self.dtask.kports.threads.insert(tid, (kport, pport));
        (kport, pport)
    }

    /// `ipc_port_copyout_send`: a send right copied out into the task's
    /// space; dead when the port has died, null when the space is full.
    pub(crate) fn darwin_copyout_send(&mut self, p: ObjId) -> u32 {
        match self.ipc().object_copyout(Carried::Port(p), msgt::PORT_SEND, None) {
            Ok(n) => n,
            Err(e) if e == super::ipc::kr::INVALID_CAPABILITY => super::ipc::PORT_DEAD,
            Err(_) => 0,
        }
    }

    /// `ipc_port_copyout_send_pinned`: a thread's self port copied out and
    /// pinned (the task's ports are pinned).
    pub(crate) fn darwin_copyout_send_pinned(&mut self, p: ObjId) -> u32 {
        self.ipc().port_mut(p).pinned = true;
        self.darwin_copyout_send(p)
    }

    /// `port_name_to_thread`: the thread a send right names.
    pub(crate) fn darwin_name_to_thread(&mut self, name: u32) -> Option<i32> {
        if !super::ipc::name_valid(name) {
            return None;
        }
        let p = self.ipc().translate_send(name).ok()?;
        let port = self.ipc().port(p);
        match port.kobject {
            Some(Kobject::Thread(t)) if port.active => Some(t),
            _ => None,
        }
    }

    /// `port_name_to_current_task_noref` and its read flavor: the name is a
    /// send right to this task's control port. (The read flavor would also
    /// take a task read port; none is made here, `task_get_special_port`
    /// reports asking for one.)
    pub(crate) fn darwin_name_is_task(&mut self, name: u32) -> bool {
        if !super::ipc::name_valid(name) {
            return false;
        }
        let Ok(p) = self.ipc().translate_send(name) else { return false };
        let ipc = self.ipc();
        let port = ipc.port(p);
        if !port.active || port.kobject != Some(Kobject::Task) {
            return false;
        }
        if port.owner != ipc.task {
            let owner = port.owner;
            self.darwin_unimplemented(format!("a call on another task's IPC space (task key {owner})"));
            return false;
        }
        true
    }

    /// `ipc_thread_disable` and `ipc_thread_terminate`: a thread's ports
    /// die with it, its special reply port is unbound.
    pub(crate) fn darwin_thread_ports_terminate(&mut self, tid: i32) {
        self.dtask.kports.special_reply.remove(&tid);
        if let Some((kport, pport)) = self.dtask.kports.threads.remove(&tid) {
            let ipc = &mut self.ipc();
            for p in [kport, pport] {
                ipc.port_mut(p).kobject = None;
                ipc.port_mut(p).pinned = false;
                ipc.port_destroy(p);
            }
        }
    }

    /// `task_terminate_internal`'s IPC, for a task that has ended: its
    /// semaphores destroyed (`semaphore_destroy_all`), its threads' sends
    /// still waiting for room abandoned, its threads' and its own ports
    /// dead (`ipc_thread_terminate`, `ipc_task_terminate`), the send
    /// rights it held (special, registered) released, and its space
    /// ended (`ipc_space_terminate`), every right in it with the
    /// notifications that owes; then its space leaves the system's table.
    pub fn darwin_task_terminate(&mut self) {
        if !self.darwin || self.dtask.ipc_raw.task == 0 {
            return;
        }
        let semas: Vec<ObjId> = self.dtask.semas.map.iter().filter(|(_, s)| s.active).map(|(&p, _)| p).collect();
        for p in semas {
            self.semaphore_destroy_internal(None, p);
        }
        let waiting: Vec<(i32, Box<Kmsg>)> = self.dtask.pending_send.drain().collect();
        for (tid, kmsg) in waiting {
            let ipc = self.ipc();
            let port = kmsg.dest;
            let me = ipc.waiter(tid);
            ipc.mqueue_cancel_room(port, me);
            ipc.release(port);
            ipc.kmsg_destroy(kmsg, true);
        }
        let tids: Vec<i32> = self.dtask.kports.threads.keys().copied().collect();
        for t in tids {
            self.darwin_thread_ports_terminate(t);
        }
        let k = std::mem::take(&mut self.dtask.kports);
        let task_ports: Vec<ObjId> = k.task.map(|(a, b)| vec![a, b]).unwrap_or_default().into_iter().chain(k.task_name).chain(k.resume).collect();
        let sends: Vec<ObjId> = k.special.values().copied().chain(k.registered.into_iter().flatten()).collect();
        let ipc = self.ipc();
        for p in task_ports {
            ipc.port_mut(p).kobject = None;
            ipc.port_mut(p).pinned = false;
            ipc.port_destroy(p);
        }
        for p in sends {
            ipc.release_send(p);
        }
        ipc.space_terminate();
        self.darwin_ipc_notify_drain();
        self.ipc().space_leave();
        self.darwin_ipc_leave();
    }

    /// `ipc_kobject_server`: answer the request `req` sent to kernel port
    /// `port`. The request's destination right is consumed; a successful
    /// routine keeps what it took of the body, a failed one has the body's
    /// rights destroyed. The reply, if any, for sending.
    pub(crate) fn kobject_server(&mut self, port: ObjId, req: Box<Kmsg>) -> Option<Box<Kmsg>> {
        let obj = self.ipc().port(port).kobject.clone().expect("a kernel port");
        let reply = super::mig::serve(self, &obj, &req);
        let ipc = &mut self.ipc();
        match bits::remote(req.bits) {
            msgt::PORT_SEND => ipc.release_send(port),
            msgt::PORT_SEND_ONCE => {
                ipc.port_mut(port).sorights -= 1;
                ipc.release(port);
            }
            t => panic!("ipc_kobject_server: strange destination rights {t}"),
        }
        if let Some(v) = req.voucher {
            ipc.release_send(v);
        }
        if let Some(u) = &reply.unimplemented {
            let u = u.clone();
            self.darwin_unimplemented(u);
        }
        // A reply that waits for a thread to stop (thread_wait): its port
        // kept for it.
        if let Some((target, op)) = reply.defer {
            match req.reply {
                Some(Carried::Port(rport)) => {
                    let pending = PendingReply { id: req.id, rport, rtype: bits::local(req.bits), target, op };
                    self.dtask.pending_replies.push(pending);
                }
                Some(r) => self.ipc().object_destroy(r, bits::local(req.bits)),
                None => {}
            }
            return None;
        }
        let ipc = &mut self.ipc();
        let status = reply.ret;
        if status != 0 && status != MIG_NO_REPLY {
            ipc.descs_destroy(&req.descs);
        }
        if status == MIG_NO_REPLY {
            if let Some(r) = req.reply {
                ipc.object_destroy(r, bits::local(req.bits));
            }
            return None;
        }
        let Some(rport) = req.reply else {
            reply.destroy_ports(ipc);
            return None;
        };
        let reply_type = bits::local(req.bits);
        let rport = match rport {
            Carried::Port(p) => p,
            Carried::Dead => {
                reply.destroy_ports(ipc);
                return None;
            }
        };
        let k = reply.message(req.id, rport, reply_type);
        // A reply to a kernel port is refused.
        if ipc.port(rport).receiver == Receiver::Kernel {
            ipc.kmsg_destroy(Box::new(k), false);
            return None;
        }
        Some(Box::new(k))
    }

    /// `ipc_kobject_notify_send_once_and_unlock`: a send-once right to a
    /// kernel port destroyed unused; the resume port's releases the hold
    /// it stood for (`task_suspension_send_once`).
    pub(crate) fn kobject_send_once(&mut self, port: ObjId) {
        if self.ipc().port(port).kobject == Some(Kobject::TaskResume) {
            self.darwin_release_task_hold(HoldMode::Normal);
        }
        self.ipc().release(port);
    }

    /// `ipc_kobject_notify_no_senders`: a kernel port's last send right went
    /// (the kernel armed the request for its object).
    pub(crate) fn kobject_no_senders(&mut self, port: ObjId, mscount: u32) {
        let k = self.ipc().port(port).kobject.clone();
        match k {
            Some(Kobject::Semaphore) => self.semaphore_no_senders(port),
            // task_suspension_no_senders: with no new send right made since
            // (ipc_kobject_nsrequest fails), every legacy hold left goes;
            // else the request is armed again.
            Some(Kobject::TaskResume) => {
                let p = self.ipc().port_mut(port);
                if p.srights == 0 && p.mscount == mscount {
                    self.darwin_release_task_hold(HoldMode::LegacyAll);
                } else {
                    p.nsrequest_kobject = true;
                }
            }
            Some(Kobject::Voucher(v)) => self.ipc_voucher_no_senders(v),
            other => self.darwin_unimplemented(format!("no-senders for kernel object {other:?}")),
        }
    }
}

/// What a deferred reply waits to answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Deferred {
    /// `thread_suspend`'s `thread_wait`: success, once the thread is off
    /// its CPU.
    ThreadWait,
    /// `task_suspend`'s and `task_suspend2`'s `task_wait_locked`: once
    /// every thread but the caller is off its CPU (`token`: task_suspend2's
    /// send-once right to the resume port, answered with the reply).
    TaskWait { token: Option<ObjId> },
    /// `thread_get_state` and `thread_set_state` of a thread held to stop.
    /// (`held`: a stop hold was put on it for this.)
    GetState { flavor: i32, count: u32, held: bool },
    SetState { flavor: i32, state: Vec<u32>, held: bool },
}

/// A request answered once a thread is off its CPU.
#[derive(Clone, Debug)]
pub struct PendingReply {
    pub id: i32,
    pub rport: ObjId,
    pub rtype: u32,
    pub target: i32,
    pub op: Deferred,
}

impl Kernel {
    /// Thread `tid` going off its CPU (`off`), or back on: the replies
    /// waiting for it sent.
    pub(crate) fn darwin_set_offcpu(&mut self, m: &mut crate::GuestMem<'_>, tid: i32, off: bool) {
        if let Some(t) = self.dtask.threads.map.get_mut(&tid) {
            t.offcpu = off;
        }
        if off {
            self.darwin_pending_replies(m, tid);
        }
    }

    /// The replies waiting for thread `tid`: those ready now sent.
    pub(crate) fn darwin_pending_replies(&mut self, m: &mut crate::GuestMem<'_>, _tid: i32) {
        self.darwin_pending_ready(m);
    }

    /// Whether a deferred reply can be answered: its thread off its CPU or
    /// gone (or the caller itself, on its call's way out); for a task wait,
    /// every other thread.
    fn pending_is_ready(&self, p: &PendingReply) -> bool {
        match p.op {
            Deferred::TaskWait { .. } => self.thread_signals.tids_in_order().into_iter().filter(|&t| t != p.target).all(|t| self.darwin_offcpu(t)),
            _ => p.target == self.tid || !self.darwin_thread_alive(p.target) || self.darwin_offcpu(p.target),
        }
    }

    /// Answer the deferred replies that are ready.
    fn darwin_pending_answer(&mut self, m: &mut crate::GuestMem<'_>) -> bool {
        let pending = std::mem::take(&mut self.dtask.pending_replies);
        let (ready, rest): (Vec<PendingReply>, Vec<PendingReply>) = pending.into_iter().partition(|p| self.pending_is_ready(p));
        self.dtask.pending_replies = rest;
        if ready.is_empty() {
            return false;
        }
        for p in ready {
            let tid = p.target;
            let reply = match p.op {
                Deferred::ThreadWait => Reply::ok(Vec::new()),
                Deferred::TaskWait { token: None } => Reply::ok(Vec::new()),
                Deferred::TaskWait { token: Some(port) } => Reply { ret: 0, defer: None, out: Vec::new(), ports: vec![PortOut::Right(Carried::Port(port), msgt::PORT_SEND_ONCE)], unimplemented: None },
                Deferred::GetState { flavor, count, .. } => self.darwin_thread_state_now(m, tid, flavor, count, None),
                Deferred::SetState { flavor, ref state, .. } => self.darwin_thread_state_now(m, tid, flavor, 0, Some(state.clone())),
            };
            if matches!(p.op, Deferred::GetState { held: true, .. } | Deferred::SetState { held: true, .. }) {
                // thread_unstop, thread_release.
                if let Some(t) = self.dtask.threads.map.get_mut(&tid) {
                    t.stop_holds = t.stop_holds.saturating_sub(1);
                }
            }
            if let Some(u) = &reply.unimplemented {
                let u = u.clone();
                self.darwin_unimplemented(u);
            }
            let k = reply.message(p.id, p.rport, p.rtype);
            self.darwin_kernel_send(Box::new(k));
        }
        self.darwin_ipc_settle(m);
        true
    }

    /// The replies whose thread is off its CPU now, or is the caller: what
    /// a call that made them answers on its way out.
    pub(crate) fn darwin_pending_ready(&mut self, m: &mut crate::GuestMem<'_>) {
        if !self.dtask.pending_replies.is_empty() {
            self.darwin_pending_answer(m);
        }
    }

    /// Whether thread `tid` is still there (`thread->active`).
    pub(crate) fn darwin_thread_alive(&self, tid: i32) -> bool {
        self.dtask.threads.map.contains_key(&tid) || self.thread_signals.contains(tid)
    }

    /// Whether thread `tid` is off its CPU: not started, parked, waiting
    /// in a call, or gone.
    pub(crate) fn darwin_offcpu(&self, tid: i32) -> bool {
        match self.dtask.threads.map.get(&tid) {
            Some(t) => t.offcpu || t.unstarted.is_some(),
            None => !self.thread_signals.contains(tid),
        }
    }
}

/// A right a reply returns, or a name carried as it is.
#[derive(Clone, Copy, Debug)]
pub enum PortOut {
    Right(Carried, u32),
    Raw(u32),
}

/// What a MIG routine answers: its return code and out data, or the rights
/// it hands back (a complex reply).
pub struct Reply {
    pub ret: i32,
    /// Answered later, once thread `.0` is off its CPU.
    pub defer: Option<(i32, Deferred)>,
    pub out: Vec<u8>,
    /// Rights returned, each with the type it goes as, or a name carried
    /// as it is (null, dead).
    pub ports: Vec<PortOut>,
    pub unimplemented: Option<String>,
}

impl Reply {
    pub fn ok(out: Vec<u8>) -> Reply {
        Reply { ret: 0, defer: None, out, ports: Vec::new(), unimplemented: None }
    }

    pub fn err(ret: i32) -> Reply {
        Reply { ret, defer: None, out: Vec::new(), ports: Vec::new(), unimplemented: None }
    }

    pub fn port(c: Carried) -> Reply {
        Reply { ret: 0, defer: None, out: Vec::new(), ports: vec![PortOut::Right(c, msgt::PORT_SEND)], unimplemented: None }
    }

    /// A reply returning a name that is not a right (null, dead).
    pub fn with_null_port(mut self, raw: u32) -> Reply {
        self.ports.push(PortOut::Raw(raw));
        self
    }

    /// The rights a reply that goes nowhere held, destroyed.
    fn destroy_ports(self, ipc: &mut super::ipc::Ipc) {
        for p in self.ports {
            if let PortOut::Right(c, t) = p {
                ipc.object_destroy(c, t);
            }
        }
    }

    /// The reply message (`ipc_kobject_init_reply` and the routine's
    /// packing): a successful reply with rights is complex, its port
    /// descriptors then the out data; otherwise NDR, RetCode, out data.
    fn message(self, id: i32, dest: ObjId, reply_type: u32) -> Kmsg {
        let ndr = super::mig::NDR_RECORD;
        let (body, descs, complex) = if self.ret == 0 && !self.ports.is_empty() {
            let mut b = (self.ports.len() as u32).to_le_bytes().to_vec();
            let mut descs = Vec::new();
            for p in &self.ports {
                let off = b.len();
                b.extend_from_slice(&[0u8; 12]);
                let (right, raw, t) = match *p {
                    PortOut::Right(c, t) => (Some(c), 0, t),
                    PortOut::Raw(n) => (None, n, msgt::PORT_SEND),
                };
                b[off + 10] = t as u8;
                descs.push(Desc::Port { off, right, raw, disp: t });
            }
            b.extend_from_slice(&self.out);
            (b, descs, bits::COMPLEX)
        } else {
            let mut b = ndr.to_vec();
            b.extend_from_slice(&self.ret.to_le_bytes());
            if self.ret == 0 {
                b.extend_from_slice(&self.out);
            }
            (b, Vec::new(), 0)
        };
        Kmsg { bits: bits::set(reply_type, 0, 0, complex), size: 24 + body.len() as u32, dest, reply: None, voucher: None, voucher_raw: 0, id: id + 100, body, descs, sender: Sender::KERNEL, aux: Vec::new(), keep_alive: false, ppriority: 0, qos_override: 0 }
    }
}
