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
    /// Each thread's control port and self port.
    pub threads: HashMap<i32, (ObjId, ObjId)>,
    /// The task's read and inspect ports, made when first asked for and
    /// gone at their last send right's.
    pub flavored: [Option<ObjId>; 2],
    /// Each thread's, the same way.
    pub thread_flavored: HashMap<(i32, u8), ObjId>,
    /// Each thread's special reply port (`ith_special_reply_port`).
    pub special_reply: HashMap<i32, ObjId>,
    /// `task_set_special_port`'s ports, by which (send rights held).
    pub special: HashMap<i32, ObjId>,
    /// The special ports that are `IP_DEAD`: a dead name set, or a dead
    /// port's right inherited (`ipc_port_copy_send_mqueue`). Read back
    /// dead, they are not `IP_VALID`.
    pub special_dead: std::collections::HashSet<i32>,
    /// `itk_registered`: `mach_ports_register`'s ports (send rights held).
    pub registered: [Option<ObjId>; 3],
    /// `itk_resume`: the task's resume port, once a suspension made it.
    pub resume: Option<ObjId>,
    /// `exc_actions`: the task's exception handlers.
    pub exc: super::exception::ExcActions,
    /// Each thread's exception handlers, once set (`tro_exc_actions`).
    pub thread_exc: HashMap<i32, super::exception::ExcActions>,
    /// `task_restartable_ranges_register`'s ranges.
    pub restartable: Vec<(u64, u16, u16, u32)>,
}

/// `mach_task_flavor_t`, `mach_thread_flavor_t`.
pub mod flavor {
    pub const CONTROL: u8 = 0;
    pub const READ: u8 = 1;
    pub const INSPECT: u8 = 2;
    pub const NAME: u8 = 3;
}

/// `developer_mode_state()`: off, as an iPad leaves it.
pub const DEVELOPER_MODE: bool = false;

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

    /// `convert_task_to_port_with_flavor` for the read (`flavor::READ`) or
    /// inspect flavor: a send right to the task's port of that flavor, made
    /// immovable and with a no-senders request when it is new. Without
    /// Developer Mode a read port, copied out into the task's own space,
    /// is its self port (IPC_LABEL_SUBST_TASK_READ).
    pub(crate) fn darwin_task_flavor_port(&mut self, f: u8) -> ObjId {
        let i = usize::from(f - flavor::READ);
        let kind = if f == flavor::READ { Kobject::TaskRead } else { Kobject::TaskInspect };
        let self_port = self.darwin_task_self_port();
        let slot = self.dtask.kports.flavored[i];
        let p = self.darwin_flavor_port(slot, kind, (f == flavor::READ && !DEVELOPER_MODE).then_some(self_port));
        self.dtask.kports.flavored[i] = Some(p);
        p
    }

    /// The same for thread `tid` (`convert_thread_to_port_with_flavor`).
    pub(crate) fn darwin_thread_flavor_port(&mut self, tid: i32, f: u8) -> ObjId {
        let kind = if f == flavor::READ { Kobject::ThreadRead(tid) } else { Kobject::ThreadInspect(tid) };
        let self_port = self.darwin_thread_ports(tid).1;
        let slot = self.dtask.kports.thread_flavored.get(&(tid, f)).copied();
        let p = self.darwin_flavor_port(slot, kind, (f == flavor::READ && !DEVELOPER_MODE).then_some(self_port));
        self.dtask.kports.thread_flavored.insert((tid, f), p);
        p
    }

    fn darwin_flavor_port(&mut self, slot: Option<ObjId>, kind: Kobject, subst: Option<ObjId>) -> ObjId {
        let ipc = self.ipc();
        let p = match slot {
            Some(p) => p,
            None => {
                let p = ipc.kobject_port(kind);
                let pp = ipc.port_mut(p);
                pp.immovable_send = true;
                pp.subst = subst;
                p
            }
        };
        ipc.make_send(p);
        ipc.port_mut(p).nsrequest_kobject = true;
        p
    }

    /// `task_port_with_flavor_no_senders`: a read or inspect port with no
    /// send right left goes, to be made anew when next asked for.
    fn darwin_flavor_port_no_senders(&mut self, port: ObjId) {
        if self.ipc().port(port).srights > 0 {
            return;
        }
        let k = &mut self.dtask.kports;
        for s in k.flavored.iter_mut() {
            if *s == Some(port) {
                *s = None;
            }
        }
        k.thread_flavored.retain(|_, p| *p != port);
        let ipc = self.ipc();
        ipc.port_mut(port).kobject = None;
        ipc.port_destroy(port);
    }

    /// `task_conversion_eval` of a read port from the task asking: without
    /// Developer Mode, a platform binary's task is not another's to read
    /// unless that task is a platform binary too.
    pub(crate) fn darwin_read_conversion_ok(&mut self) -> bool {
        let caller = self.dtask.kcaller;
        if caller == 0 || caller == self.ipc().task || !self.darwin_task_platform_binary() {
            return true;
        }
        self.ipc().links.get(&caller).and_then(|l| l.codesign.as_ref()).is_some_and(|c| c.platform != 0)
    }

    /// The task's read and inspect ports, and its threads', taken for the
    /// task's end.
    pub(crate) fn darwin_flavor_ports_take(&mut self) -> Vec<ObjId> {
        let k = &mut self.dtask.kports;
        let mut v: Vec<ObjId> = k.flavored.iter_mut().filter_map(Option::take).collect();
        v.extend(k.thread_flavored.drain().map(|(_, p)| p));
        v
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
    /// with each change of identity: the host privilege port for root
    /// unless a MAC policy takes it (`mac_system_check_host_priv`:
    /// Sandbox's mach-priv-host-port, quietly; the platform profile allows
    /// it), the host port for anyone else. The answer is the one the
    /// credential's last token got: its sandbox changes only with a new
    /// token (an exec) or by `sandbox_init`, which revokes the port on the
    /// same question.
    pub(crate) fn darwin_itk_host(&mut self) -> ObjId {
        let a = super::mac::SbArgs { quiet: true, ..Default::default() };
        if self.creds.uid() == 0 && self.darwin_sb_evaluate(super::mac::op::MACH_PRIV_HOST_PORT, &a) == 0 {
            self.darwin_host_priv_port()
        } else {
            self.darwin_host_port()
        }
    }

    /// Clock `id`'s port: the system clock (0) or the calendar (1), each
    /// its own.
    pub(crate) fn darwin_clock_port(&mut self, id: u8) -> ObjId {
        self.ipc().global_port(Kobject::Clock(id))
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
        // port_name_to_current_task_noref: a trap acts on the calling task
        // only (libsystem sends another task's request as a message).
        port.owner == ipc.task
    }

    /// `ipc_thread_disable` and `ipc_thread_terminate`: a thread's ports
    /// die with it, its special reply port is unbound.
    pub(crate) fn darwin_thread_ports_terminate(&mut self, tid: i32) {
        self.dtask.kports.special_reply.remove(&tid);
        if let Some(a) = self.dtask.kports.thread_exc.remove(&tid) {
            super::exception::release_all(self.ipc(), &a);
        }
        let flavored: Vec<ObjId> = [flavor::READ, flavor::INSPECT].iter().filter_map(|&f| self.dtask.kports.thread_flavored.remove(&(tid, f))).collect();
        let ipc = &mut self.ipc();
        for p in flavored {
            ipc.port_mut(p).kobject = None;
            ipc.port_destroy(p);
        }
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
    /// rights it held (special, registered, a spawn's watch ports not yet
    /// bound) released, and its space ended (`ipc_space_terminate`), every
    /// right in it with the notifications that owes; then its space and
    /// its link leave the system's table. Once for a task: a spawn's child
    /// that never ran is ended so too. Its process is past
    /// `proc_prepareexit` first (`P_REF_DEAD`, if its end did not say so
    /// already), so `proc_find` no longer finds it, as XNU's exit
    /// terminates the task only after that.
    pub fn darwin_task_terminate(&mut self) {
        if !self.darwin || self.dtask.ipc_raw.ended {
            return;
        }
        self.procs.set_exited(self.pid);
        // coalitions_remove_task, launchd told of those it emptied.
        self.darwin_coalitions_task_end();
        // Its threads' vouchers, its importance (ipc_importance_disconnect_task)
        // and its bank context (task_bank_reset).
        self.darwin_threads_vouchers_release();
        let me = self.ipc().task;
        self.ipc().imp_remove_watchports(me);
        self.ipc().imp_disconnect_task(me);
        self.darwin_bank_task_destroy();
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
        let flavored = self.darwin_flavor_ports_take();
        let k = std::mem::take(&mut self.dtask.kports);
        let name = self.ipc().task_name_port_take();
        let task_ports: Vec<ObjId> = k.task.map(|(a, b)| vec![a, b]).unwrap_or_default().into_iter().chain(name).chain(k.resume).chain(flavored).collect();
        let watch = self.dtask.pending_watchports.take().map(|(w, _)| w).unwrap_or_default();
        let sends: Vec<ObjId> = k.special.values().copied().chain(k.registered.into_iter().flatten()).chain(watch.into_iter().flatten()).collect();
        let ipc = self.ipc();
        for p in task_ports {
            ipc.port_mut(p).kobject = None;
            ipc.port_mut(p).pinned = false;
            ipc.port_destroy(p);
        }
        for p in sends {
            ipc.release_send(p);
        }
        super::exception::release_all(ipc, &k.exc);
        for a in k.thread_exc.values() {
            super::exception::release_all(ipc, a);
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
        // The MAC filter of the sender's kernel MIG mask: a refusal is the
        // reply's error, the routine not run.
        let reply = match self.darwin_kobj_filter(req.id as u32) {
            Some(kr) => Reply::err(kr),
            None => super::mig::serve(self, &obj, &req),
        };
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
                    let blank = matches!(op, Deferred::IomfbSwapWait { .. });
                    let pending = PendingReply { id: req.id, rport, rtype: bits::local(req.bits), target, op };
                    self.dtask.pending_replies.push(pending);
                    // A swap wait is answered at a vertical blank.
                    if blank {
                        self.darwin_iomfb_arm();
                    }
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
            Some(Kobject::FilePort(id)) => super::fileport::fileport_no_senders(id),
            // The notification is freed with its port's last send right:
            // its notifier removed and the wake port's right let go.
            Some(Kobject::IoNotification(id)) => {
                if let Some(p) = super::iokit::notification_free(id) {
                    self.ipc().release_send(p);
                }
            }
            // iokit_client_died: the user client's clientDied, and the
            // client is gone with its connection.
            Some(Kobject::IoConnect(id)) => super::iokit::client_died(self, id),
            // iokit_no_senders for IKOT_IOKIT_IDENT: the object goes with
            // the port's last send right, unless one was made since
            // (IOMachPort::noMoreSendersForObject compares the make-send
            // count).
            Some(Kobject::IoIdent(id)) => {
                let p = self.ipc().port_mut(port);
                if p.srights == 0 && p.mscount == mscount {
                    super::iosurface::send_right_no_senders(self, id);
                } else {
                    p.nsrequest_kobject = true;
                }
            }
            Some(Kobject::WorkInterval(id)) => super::workinterval::work_interval_no_senders(id),
            Some(Kobject::Eventlink(..)) => self.darwin_eventlink_no_senders(port),
            Some(Kobject::TaskRead | Kobject::TaskInspect | Kobject::ThreadRead(_) | Kobject::ThreadInspect(_)) => self.darwin_flavor_port_no_senders(port),
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
    /// IOMobileFramebuffer's blocking swap wait (selector 6): io_connect_method's
    /// reply once the swap is where the wait's options ask, or the client
    /// that waits is stopped (kIOReturnAborted).
    IomfbSwapWait { client: u32, swap: u32, options: u32 },
    /// A user client's method that answers later, by its token
    /// ([`super::mig::later_reply`]); answered by
    /// [`Kernel::darwin_answer_later`], not by a thread stopping.
    Later(u64),
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
        // Into TH_RUN or out of it: a wait at the interrupt level its
        // call set (THREAD_UNINT for task_exception_notify's), or parked.
        let unint = tid == self.tid && self.darwin_finish.as_ref().is_some_and(|w| w.uninterruptible());
        if let Some(t) = self.dtask.threads.map.get_mut(&tid) {
            if t.offcpu != off || !t.sched_seen {
                t.sched_seen = true;
                use super::sched::RunState;
                let state = if !off {
                    RunState::Run
                } else if unint {
                    RunState::Unint
                } else {
                    RunState::Wait
                };
                self.procs.sched.set_state(self.pid, tid, state);
            }
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
            Deferred::Later(_) => false,
            Deferred::TaskWait { .. } => self.thread_signals.tids_in_order().into_iter().filter(|&t| t != p.target).all(|t| self.darwin_offcpu(t)),
            Deferred::IomfbSwapWait { client, swap, options } => super::iokit::iomfb_wait_outcome(client, swap, options).is_some(),
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
                // io_connect_method's reply with no output: the inband and
                // scalar counts and the out-of-line size, all zero.
                Deferred::IomfbSwapWait { client, swap, options } => match super::iokit::iomfb_wait_outcome(client, swap, options) {
                    Some(0) => Reply::ok(vec![0; 16]),
                    Some(r) => Reply::err(r),
                    None => unreachable!("a swap wait answered before it is done"),
                },
                Deferred::Later(_) => unreachable!("a method's later reply is never ready by itself"),
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

    /// Answer the routine whose method answers later with `token`: `reply`
    /// sent to its reply port. Nothing when no routine waits for it (it
    /// had no reply port).
    pub(crate) fn darwin_answer_later(&mut self, m: &mut crate::GuestMem<'_>, token: u64, reply: Reply) {
        let Some(i) = self.dtask.pending_replies.iter().position(|p| p.op == Deferred::Later(token)) else { return };
        let p = self.dtask.pending_replies.remove(i);
        let k = reply.message(p.id, p.rport, p.rtype);
        self.darwin_kernel_send(Box::new(k));
        self.darwin_ipc_settle(m);
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
#[derive(Clone, Debug)]
pub enum PortOut {
    Right(Carried, u32),
    Raw(u32),
    /// An array of rights of one type (an out-of-line ports descriptor),
    /// each a right or a name carried as it is.
    Array(Vec<(Option<Carried>, u32)>, u32),
    /// Out-of-line memory (an out `pointer_t`), a copy of the task's bytes.
    Ool(Vec<u8>),
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
            match p {
                PortOut::Right(c, t) => ipc.object_destroy(c, t),
                PortOut::Array(v, t) => {
                    for c in v.into_iter().filter_map(|(c, _)| c) {
                        ipc.object_destroy(c, t);
                    }
                }
                PortOut::Raw(_) | PortOut::Ool(_) => {}
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
            for p in self.ports {
                let off = b.len();
                let (right, raw, t) = match p {
                    PortOut::Right(c, t) => (Some(c), 0, t),
                    PortOut::Raw(n) => (None, n, msgt::PORT_SEND),
                    // MIG's template: deallocate TRUE, MACH_MSG_VIRTUAL_COPY.
                    PortOut::Ool(data) => {
                        const MACH_MSG_OOL_DESCRIPTOR: u8 = 1;
                        const VIRTUAL_COPY: u8 = 1;
                        b.extend_from_slice(&[0u8; 16]);
                        b[off + 11] = MACH_MSG_OOL_DESCRIPTOR;
                        descs.push(Desc::Ool { off, data, copy: VIRTUAL_COPY });
                        continue;
                    }
                    // MIG's template: deallocate FALSE, MACH_MSG_PHYSICAL_COPY.
                    PortOut::Array(rights, t) => {
                        const MACH_MSG_OOL_PORTS_DESCRIPTOR: u8 = 2;
                        b.extend_from_slice(&[0u8; 16]);
                        b[off + 10] = t as u8;
                        b[off + 11] = MACH_MSG_OOL_PORTS_DESCRIPTOR;
                        descs.push(Desc::OolPorts { off, rights, disp: t, copy: 0 });
                        continue;
                    }
                };
                b.extend_from_slice(&[0u8; 12]);
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
        Kmsg { bits: bits::set(reply_type, 0, 0, complex), size: 24 + body.len() as u32, dest, reply: None, voucher: None, voucher_raw: 0, id: id + 100, body, descs, sender: Sender::KERNEL, aux: Vec::new(), keep_alive: false, ppriority: 0, qos_override: 0, imp: None }
    }
}
