//! Kernel objects' ports (`osfmk/kern/ipc_kobject.c`, `ipc_tt.c`): the
//! task's, the host's, each thread's, and the ports of semaphores, timers
//! and the clock; and the server that answers MIG requests sent to them.

use super::ipc::msg::{bits, Desc, Kmsg, Sender};
use super::ipc::right::{msgt, Carried};
use super::ipc::{Kobject, ObjId, Receiver};
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
    pub host: Option<ObjId>,
    pub host_priv: Option<ObjId>,
    pub clock: Option<ObjId>,
    /// Each thread's control port and self port.
    pub threads: HashMap<i32, (ObjId, ObjId)>,
    /// Each thread's special reply port (`ith_special_reply_port`).
    pub special_reply: HashMap<i32, ObjId>,
    /// `task_set_special_port`'s ports, by which (send rights held).
    pub special: HashMap<i32, ObjId>,
    /// `task_restartable_ranges_register`'s ranges.
    pub restartable: Vec<(u64, u16, u16, u32)>,
}

/// `MIG_NO_REPLY`, `MIG_BAD_ID`.
pub const MIG_NO_REPLY: i32 = -305;
pub const MIG_BAD_ID: i32 = -303;

impl Kernel {
    fn kport(&mut self, f: fn(&mut Kports) -> &mut Option<ObjId>, k: Kobject) -> ObjId {
        if let Some(p) = *f(&mut self.dtask.kports) {
            return p;
        }
        let p = self.dtask.ipc.kobject_port(k);
        *f(&mut self.dtask.kports) = Some(p);
        p
    }

    /// The task's control port and self port, made with the task.
    fn task_ports(&mut self) -> (ObjId, ObjId) {
        if let Some(t) = self.dtask.kports.task {
            return t;
        }
        let ipc = &mut self.dtask.ipc;
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
        self.kport(|k| &mut k.host, Kobject::Host)
    }

    /// The host privilege port.
    pub(crate) fn darwin_host_priv_port(&mut self) -> ObjId {
        self.kport(|k| &mut k.host_priv, Kobject::HostPriv)
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
        self.kport(|k| &mut k.clock, Kobject::Clock)
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
        let ipc = &mut self.dtask.ipc;
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
        match self.dtask.ipc.object_copyout(Carried::Port(p), msgt::PORT_SEND, None) {
            Ok(n) => n,
            Err(e) if e == super::ipc::kr::INVALID_CAPABILITY => super::ipc::PORT_DEAD,
            Err(_) => 0,
        }
    }

    /// `ipc_port_copyout_send_pinned`: a thread's self port copied out and
    /// pinned (the task's ports are pinned).
    pub(crate) fn darwin_copyout_send_pinned(&mut self, p: ObjId) -> u32 {
        self.dtask.ipc.port_mut(p).pinned = true;
        self.darwin_copyout_send(p)
    }

    /// `port_name_to_thread`: the thread a send right names.
    pub(crate) fn darwin_name_to_thread(&mut self, name: u32) -> Option<i32> {
        if !super::ipc::name_valid(name) {
            return None;
        }
        let p = self.dtask.ipc.translate_send(name).ok()?;
        match self.dtask.ipc.port(p).kobject {
            Some(Kobject::Thread(t)) if self.dtask.ipc.port(p).active => Some(t),
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
        match self.dtask.ipc.translate_send(name) {
            Ok(p) => self.dtask.ipc.port(p).active && self.dtask.ipc.port(p).kobject == Some(Kobject::Task),
            Err(_) => false,
        }
    }

    /// `ipc_thread_disable` and `ipc_thread_terminate`: a thread's ports
    /// die with it, its special reply port is unbound.
    pub(crate) fn darwin_thread_ports_terminate(&mut self, tid: i32) {
        self.dtask.kports.special_reply.remove(&tid);
        if let Some((kport, pport)) = self.dtask.kports.threads.remove(&tid) {
            let ipc = &mut self.dtask.ipc;
            for p in [kport, pport] {
                ipc.port_mut(p).kobject = None;
                ipc.port_mut(p).pinned = false;
                ipc.port_destroy(p);
            }
        }
    }

    /// `ipc_kobject_server`: answer the request `req` sent to kernel port
    /// `port`. The request's destination right is consumed; a successful
    /// routine keeps what it took of the body, a failed one has the body's
    /// rights destroyed. The reply, if any, for sending.
    pub(crate) fn kobject_server(&mut self, port: ObjId, req: Box<Kmsg>) -> Option<Box<Kmsg>> {
        let obj = self.dtask.ipc.port(port).kobject.clone().expect("a kernel port");
        let reply = super::mig::serve(self, &obj, &req);
        let ipc = &mut self.dtask.ipc;
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
        let ipc = &mut self.dtask.ipc;
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

    /// `ipc_kobject_notify_no_senders`: a kernel port's last send right went
    /// (the kernel armed the request for its object).
    pub(crate) fn kobject_no_senders(&mut self, port: ObjId, mscount: u32) {
        let k = self.dtask.ipc.port(port).kobject.clone();
        let _ = mscount;
        match k {
            Some(Kobject::Semaphore) => self.semaphore_no_senders(port),
            Some(Kobject::Voucher(v)) => self.ipc_voucher_no_senders(v),
            other => self.darwin_unimplemented(format!("no-senders for kernel object {other:?}")),
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
    pub out: Vec<u8>,
    /// Rights returned, each with the type it goes as, or a name carried
    /// as it is (null, dead).
    pub ports: Vec<PortOut>,
    pub unimplemented: Option<String>,
}

impl Reply {
    pub fn ok(out: Vec<u8>) -> Reply {
        Reply { ret: 0, out, ports: Vec::new(), unimplemented: None }
    }

    pub fn err(ret: i32) -> Reply {
        Reply { ret, out: Vec::new(), ports: Vec::new(), unimplemented: None }
    }

    pub fn port(c: Carried) -> Reply {
        Reply { ret: 0, out: Vec::new(), ports: vec![PortOut::Right(c, msgt::PORT_SEND)], unimplemented: None }
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
