//! Rights moving between a name space and a message
//! (`ipc_right_copyin`/`ipc_right_copyout`, `ipc_object_copyin`/
//! `ipc_object_copyout`): a disposition takes a right out of the space,
//! and a received right goes back in under a name.

use super::space::bits;
use super::{kr, ty, Guard, Ipc, Notify, ObjId, Receiver, UREFS_MAX};

/// `MACH_MSG_TYPE_*`: dispositions a sender names, and the rights a
/// message carries.
pub mod msgt {
    pub const NONE: u32 = 0;
    pub const PORT_NAME: u32 = 15;
    pub const MOVE_RECEIVE: u32 = 16;
    pub const MOVE_SEND: u32 = 17;
    pub const MOVE_SEND_ONCE: u32 = 18;
    pub const COPY_SEND: u32 = 19;
    pub const MAKE_SEND: u32 = 20;
    pub const MAKE_SEND_ONCE: u32 = 21;
    pub const COPY_RECEIVE: u32 = 22;
    pub const DISPOSE_RECEIVE: u32 = 24;
    pub const DISPOSE_SEND: u32 = 25;
    pub const DISPOSE_SEND_ONCE: u32 = 26;
    pub const PORT_RECEIVE: u32 = MOVE_RECEIVE;
    pub const PORT_SEND: u32 = MOVE_SEND;
    pub const PORT_SEND_ONCE: u32 = MOVE_SEND_ONCE;

    /// `MACH_MSG_TYPE_PORT_ANY_SEND`.
    pub fn any_send(t: u32) -> bool {
        (MOVE_SEND..=MAKE_SEND_ONCE).contains(&t)
    }

    /// `MACH_MSG_TYPE_PORT_ANY_RIGHT`.
    pub fn any_right(t: u32) -> bool {
        (MOVE_RECEIVE..=MOVE_SEND_ONCE).contains(&t)
    }

    /// `MACH_MSG_TYPE_PORT_ANY`.
    pub fn any(t: u32) -> bool {
        (MOVE_RECEIVE..=MAKE_SEND_ONCE).contains(&t)
    }

    /// `ipc_object_copyin_type`: the right a disposition puts in a message.
    pub fn copyin_type(t: u32) -> u32 {
        match t {
            MOVE_RECEIVE => PORT_RECEIVE,
            MOVE_SEND_ONCE | MAKE_SEND_ONCE => PORT_SEND_ONCE,
            MOVE_SEND | MAKE_SEND | COPY_SEND => PORT_SEND,
            _ => NONE,
        }
    }
}

/// A right in flight: the port, or a dead name (`IO_DEAD`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carried {
    Port(ObjId),
    Dead,
}

/// `IPC_OBJECT_COPYIN_FLAGS_*`.
#[derive(Clone, Copy, Debug, Default)]
pub struct CopyinFlags {
    pub deadok: bool,
    pub allow_immovable_send: bool,
    pub allow_immovable_receive: bool,
    pub allow_reply_make_send_once: bool,
    pub allow_reply_move_send_once: bool,
    pub allow_dead_send_once: bool,
    /// `IPC_OBJECT_COPYIN_FLAGS_ALLOW_CONN_IMMOVABLE_RECEIVE`: a message's
    /// descriptors may move a libxpc connection port's receive right.
    pub allow_conn_immovable_receive: bool,
}

/// `MACH_MSG_GUARD_FLAGS_*`.
pub mod guard_flags {
    pub const IMMOVABLE_RECEIVE: u32 = 0x01;
    pub const UNGUARDED_ON_SEND: u32 = 0x02;
}

impl Ipc {
    /// `ipc_port_make_send_any_locked`.
    pub fn make_send(&mut self, port: ObjId) {
        let p = self.port_mut(port);
        p.mscount += 1;
        p.srights += 1;
        p.refs += 1;
    }

    /// `ipc_port_copy_send_any_locked`.
    pub fn copy_send(&mut self, port: ObjId) {
        let p = self.port_mut(port);
        p.srights += 1;
        p.refs += 1;
    }

    /// `ipc_port_make_sonce_locked`.
    pub fn make_sonce(&mut self, port: ObjId) {
        let p = self.port_mut(port);
        p.sorights += 1;
        p.refs += 1;
    }

    /// `ipc_port_release_send`: a send right in flight, gone.
    pub fn release_send(&mut self, port: ObjId) {
        let p = self.port_mut(port);
        p.srights -= 1;
        let ns = if p.srights == 0 { self.no_senders_prepare_pub(port) } else { None };
        self.release(port);
        if let Some(n) = ns {
            self.outbox.push(n);
        }
    }

    /// `ipc_port_release_receive`: a receive right in flight, gone.
    pub fn release_receive(&mut self, port: ObjId) {
        self.port_destroy(port);
    }

    /// `ipc_object_destroy`: a carried right of type `t` destroyed.
    pub fn object_destroy(&mut self, c: Carried, t: u32) {
        let Carried::Port(port) = c else { return };
        match t {
            msgt::PORT_SEND => self.release_send(port),
            msgt::PORT_SEND_ONCE => self.send_once_destroyed(port),
            msgt::PORT_RECEIVE => self.release_receive(port),
            _ => panic!("ipc_object_destroy: strange rights {t}"),
        }
    }

    /// A send-once right destroyed unused (`ipc_notify_send_once_and_unlock`).
    pub fn send_once_destroyed(&mut self, port: ObjId) {
        let p = self.port_mut(port);
        p.sorights -= 1;
        // A thread's kernel reply port is a queue, not a kernel object.
        let rpc_reply = matches!(p.kobject, Some(super::Kobject::RpcReply(_)));
        if p.active && p.receiver == Receiver::Kernel && p.kobject.is_some() && !rpc_reply {
            self.outbox.push(Notify::KobjectSendOnce { port });
            return;
        }
        if p.active && (p.receiver != Receiver::Kernel || rpc_reply) && (p.messages.len() as u32) < super::QLIMIT_KERNEL {
            self.outbox.push(Notify::SendOnce { to: port });
        }
        self.release(port);
    }

    /// Whether `port` is a reply port (`ip_is_reply_port`).
    fn is_reply_port(&self, port: ObjId) -> bool {
        self.port(port).reply_semantics == super::ReplySemantics::ReplyPort
    }

    /// `ipc_right_copyin`: take `msgt` out of `name`. The carried right,
    /// and a dead-name request's send-once right to notify of the deleted
    /// name.
    pub fn right_copyin(&mut self, name: u32, t: u32, flags: CopyinFlags, context: u64, guard: Option<&mut u32>) -> Result<(Carried, Option<ObjId>), u64> {
        let e = *self.space.lookup(name).ok_or(kr::INVALID_NAME)?;
        let b = e.bits;
        let invalid = Err(kr::INVALID_RIGHT);
        match t {
            msgt::MAKE_SEND => {
                if b & ty::RECEIVE == 0 {
                    return invalid;
                }
                let port = e.object.expect("a port");
                if self.is_reply_port(port) {
                    self.guard_exception(name, Guard::InvalidRight, 0);
                    return Err(kr::INVALID_CAPABILITY);
                }
                self.make_send(port);
                Ok((Carried::Port(port), None))
            }
            msgt::MAKE_SEND_ONCE => {
                if b & ty::RECEIVE == 0 {
                    return invalid;
                }
                let port = e.object.expect("a port");
                if self.is_reply_port(port) && !flags.allow_reply_make_send_once {
                    self.guard_exception(name, Guard::InvalidRight, 0);
                    return Err(kr::INVALID_CAPABILITY);
                }
                self.make_sonce(port);
                Ok((Carried::Port(port), None))
            }
            msgt::MOVE_RECEIVE => {
                if b & ty::RECEIVE == 0 {
                    return invalid;
                }
                let port = e.object.expect("a port");
                let p = self.port(port);
                if p.kobject.is_some() {
                    self.guard_exception(name, Guard::Immovable, 0);
                    return Err(kr::INVALID_CAPABILITY);
                }
                // Only a service port that is not a bootstrap port, or a
                // libxpc connection port, may have its immovable receive
                // right moved, and only when the caller allows it.
                let allow_imm_recv = if p.service_port && !p.bootstrap_port {
                    flags.allow_immovable_receive
                } else if p.connection_port {
                    flags.allow_conn_immovable_receive
                } else {
                    false
                };
                if (!allow_imm_recv && p.immovable_receive) || p.reply_semantics == super::ReplySemantics::ReplyPort || p.specialreply {
                    self.guard_exception(name, Guard::Immovable, 0);
                    return Err(kr::INVALID_CAPABILITY);
                }
                if let Some(gf) = &guard {
                    let p = self.port(port);
                    let ok = (**gf & guard_flags::UNGUARDED_ON_SEND != 0 && !p.guarded && context == 0) || (p.guarded && p.context == context);
                    if !ok {
                        let pc = p.context;
                        self.guard_exception(name, Guard::IncorrectGuard, pc);
                        return Err(kr::INVALID_ARGUMENT);
                    }
                }
                let mut request = None;
                if b & ty::SEND != 0 {
                    // The entry keeps its send right and its reference; the
                    // receive right in flight takes one of its own.
                    let entry = self.space.lookup_mut(name).expect("in use");
                    entry.bits = (b & !ty::RECEIVE) | ty::EX_RECEIVE;
                    self.space.hash_insert(port, name);
                    self.reference(port);
                } else {
                    request = self.right_request_cancel_pub(port, name);
                    self.space.dealloc(name);
                }
                self.clear_receiver_pub(port, false);
                if let Some(gf) = guard {
                    *gf |= guard_flags::UNGUARDED_ON_SEND;
                }
                self.port_mut(port).tempowner = true;
                Ok((Carried::Port(port), request))
            }
            msgt::COPY_SEND | msgt::MOVE_SEND | msgt::MOVE_SEND_ONCE => {
                let mut b = b;
                let mut dead = b & ty::DEAD_NAME != 0;
                if !dead {
                    if b & ty::SEND_RIGHTS == 0 {
                        return invalid;
                    }
                    let check_flags = t == msgt::MOVE_SEND_ONCE && flags.allow_dead_send_once;
                    if self.right_check(name, check_flags) {
                        b = self.space.lookup(name).expect("in use").bits;
                        dead = true;
                    }
                }
                if dead {
                    if !flags.deadok {
                        return invalid;
                    }
                    if t != msgt::COPY_SEND {
                        if b & bits::UREFS_MASK == 1 {
                            self.space.dealloc(name);
                        } else if b & bits::UREFS_MASK < UREFS_MAX {
                            self.space.lookup_mut(name).expect("in use").bits = b - 1;
                        }
                    }
                    return Ok((Carried::Dead, None));
                }
                let port = e.object.expect("a port");
                let need = if t == msgt::MOVE_SEND_ONCE { ty::SEND_ONCE } else { ty::SEND };
                if b & need == 0 {
                    return invalid;
                }
                let reply_ok = t == msgt::MOVE_SEND_ONCE && flags.allow_reply_move_send_once;
                if self.is_reply_port(port) && !reply_ok {
                    self.guard_exception(name, Guard::InvalidRight, 0);
                    return Err(kr::INVALID_CAPABILITY);
                }
                if !flags.allow_immovable_send && self.port(port).immovable_send {
                    self.guard_exception(name, Guard::Immovable, 0);
                    return Err(kr::INVALID_CAPABILITY);
                }
                match t {
                    msgt::COPY_SEND => {
                        self.copy_send(port);
                        Ok((Carried::Port(port), None))
                    }
                    msgt::MOVE_SEND => {
                        let mut request = None;
                        if b & bits::UREFS_MASK == 1 {
                            if b & ty::RECEIVE != 0 {
                                self.space.lookup_mut(name).expect("in use").bits = b & !(bits::UREFS_MASK | ty::SEND);
                                self.reference(port);
                            } else {
                                if self.port(port).pinned {
                                    self.guard_pinned(name, super::mpg_pinned::COPYIN);
                                    return Err(kr::INVALID_CAPABILITY);
                                }
                                request = self.right_request_cancel_pub(port, name);
                                self.space.hash_delete(port);
                                self.space.dealloc(name);
                            }
                        } else {
                            self.copy_send(port);
                            if b & bits::UREFS_MASK < UREFS_MAX {
                                self.space.lookup_mut(name).expect("in use").bits = b - 1;
                            }
                        }
                        Ok((Carried::Port(port), request))
                    }
                    _ => {
                        let request = self.right_request_cancel_pub(port, name);
                        self.space.dealloc(name);
                        Ok((Carried::Port(port), request))
                    }
                }
            }
            _ => invalid,
        }
    }

    /// `ipc_object_copyin`: [`Self::right_copyin`] with dead names allowed
    /// and a deleted name's dead-name request notified.
    pub fn object_copyin(&mut self, name: u32, t: u32, mut flags: CopyinFlags, context: u64, guard: Option<&mut u32>) -> Result<Carried, u64> {
        flags.deadok = true;
        let (c, soright) = self.right_copyin(name, t, flags, context, guard)?;
        if let Some(to) = soright {
            self.outbox.push(Notify::PortDeleted { to, name });
        }
        Ok(c)
    }

    /// `ipc_right_copyin_two`: two dispositions from one name (a message's
    /// destination and reply, or destination and voucher).
    pub fn right_copyin_two(&mut self, name: u32, one: u32, two: u32) -> Result<(Carried, Option<ObjId>), u64> {
        if one == msgt::MOVE_SEND_ONCE || two == msgt::MOVE_SEND_ONCE {
            return Err(kr::INVALID_RIGHT);
        }
        let makes = |t: u32| t == msgt::MAKE_SEND || t == msgt::MAKE_SEND_ONCE;
        if makes(one) || makes(two) {
            let f1 = CopyinFlags { allow_immovable_send: true, ..Default::default() };
            let (c, so) = self.right_copyin(name, one, f1, 0, None)?;
            let (_c2, so2) = self.right_copyin(name, two, CopyinFlags::default(), 0, None)?;
            return Ok((c, so.or(so2)));
        }
        if one == msgt::MOVE_SEND && two == msgt::MOVE_SEND {
            // ipc_right_copyin_two_move_sends
            let e = *self.space.lookup(name).ok_or(kr::INVALID_NAME)?;
            let b = e.bits;
            if b & ty::SEND == 0 || b & bits::UREFS_MASK < 2 {
                return Err(kr::INVALID_RIGHT);
            }
            let port = e.object.expect("a port");
            if self.is_reply_port(port) {
                self.guard_exception(name, Guard::InvalidRight, 0);
                return Err(kr::INVALID_CAPABILITY);
            }
            if self.right_check(name, false) {
                return Err(kr::INVALID_RIGHT);
            }
            let mut request = None;
            if b & bits::UREFS_MASK > 2 {
                self.copy_send(port);
                self.copy_send(port);
                if b & bits::UREFS_MASK < UREFS_MAX {
                    self.space.lookup_mut(name).expect("in use").bits = b - 2;
                }
            } else {
                self.copy_send(port);
                if b & ty::RECEIVE != 0 {
                    self.space.lookup_mut(name).expect("in use").bits = b & !(bits::UREFS_MASK | ty::SEND);
                    self.reference(port);
                } else {
                    request = self.right_request_cancel_pub(port, name);
                    self.space.hash_delete(port);
                    self.space.dealloc(name);
                }
            }
            return Ok((Carried::Port(port), request));
        }
        let t = if one == msgt::MOVE_SEND || two == msgt::MOVE_SEND { msgt::MOVE_SEND } else { msgt::COPY_SEND };
        let f = CopyinFlags { allow_immovable_send: true, ..Default::default() };
        let (c, so) = self.right_copyin(name, t, f, 0, None)?;
        if let Carried::Port(port) = c {
            self.copy_send(port);
        }
        Ok((c, so))
    }

    /// `ipc_right_reverse`: the name this space already has for `port`'s
    /// receive right or a send right to it.
    fn right_reverse(&self, port: ObjId) -> Option<u32> {
        let p = self.port(port);
        if let Receiver::Space(n) = p.receiver {
            if p.owner == self.task {
                return Some(n);
            }
        }
        self.space.hash_lookup(port)
    }

    /// `ipc_right_copyout`: carried right `t` to `port` into `name`'s
    /// entry. A receive right takes a guard when asked
    /// (`MACH_MSG_GUARD_FLAGS_IMMOVABLE_RECEIVE`), its context the receive
    /// buffer's address.
    fn right_copyout(&mut self, name: u32, t: u32, port: ObjId, guard: Option<(&mut u32, &mut u64, u64)>) {
        let b = self.space.lookup_mut_any(name).bits;
        match t {
            msgt::PORT_SEND_ONCE => {
                self.space.lookup_mut_any(name).bits = b | ty::SEND_ONCE | 1;
            }
            msgt::PORT_SEND => {
                if b & ty::SEND != 0 {
                    let urefs = b & bits::UREFS_MASK;
                    self.port_mut(port).srights -= 1;
                    self.release(port);
                    if urefs == UREFS_MAX {
                        return;
                    }
                } else if b & ty::RECEIVE != 0 {
                    self.release(port);
                } else {
                    self.space.hash_insert(port, name);
                }
                self.space.lookup_mut_any(name).bits = (b | ty::SEND) + 1;
            }
            msgt::PORT_RECEIVE => {
                let task = self.task;
                let p = self.port_mut(port);
                p.receiver = Receiver::Space(name);
                p.owner = task;
                if p.connection_port {
                    p.immovable_receive = true;
                }
                // `ipc_right_copyout`: only a port-destroyed notification
                // brings launchd back a service port's receive right with
                // its guard, under the name it had.
                let initproc = self.initproc;
                let p = self.port_mut(port);
                if p.service_port {
                    if let Some(l) = p.splabel.as_mut().filter(|l| l.flags & super::ispl::SEND_PD_NOTIFICATION != 0) {
                        l.flags &= !super::ispl::SEND_PD_NOTIFICATION;
                        if initproc {
                            assert_eq!(name, l.launchd_name, "a service port's name in launchd");
                            let context = l.launchd_context;
                            if context != 0 {
                                p.guarded = true;
                                p.strict_guard = true;
                                p.context = context;
                            }
                        }
                    }
                }
                let p = self.port_mut(port);
                if let Some((gf, ctx, recv_addr)) = guard {
                    if *gf & guard_flags::IMMOVABLE_RECEIVE != 0 {
                        p.guarded = true;
                        p.strict_guard = false;
                        p.immovable_receive = true;
                        p.context = recv_addr;
                        *ctx = recv_addr;
                        *gf &= !guard_flags::UNGUARDED_ON_SEND;
                    }
                }
                self.space.lookup_mut_any(name).bits = b | ty::RECEIVE;
                if b & ty::SEND != 0 {
                    self.release(port);
                    self.space.hash_delete(port);
                }
            }
            _ => panic!("ipc_right_copyout: strange rights {t}"),
        }
    }

    /// `ipc_object_copyout`: carried right `t` into the space, under the
    /// name it already has there (send rights coalesce) or a new one.
    pub fn object_copyout(&mut self, c: Carried, t: u32, guard: Option<(&mut u32, &mut u64, u64)>) -> Result<u32, u64> {
        let Carried::Port(mut port) = c else { return Ok(super::PORT_DEAD) };
        if !self.port(port).active {
            self.object_destroy(c, t);
            return Err(kr::INVALID_CAPABILITY);
        }
        // ipc_kobject_label_check: any right but a send right to a labeled
        // control port is refused; a send right is substituted by the
        // immovable equivalent when the space is the object's task's.
        if let Some(alt) = self.port(port).subst {
            if t != msgt::PORT_SEND {
                self.object_destroy(c, t);
                return Err(kr::INVALID_CAPABILITY);
            }
            if self.port(port).owner == self.task {
                self.release_send(port);
                self.make_send(alt);
                port = alt;
            }
        }
        let name = match (t != msgt::PORT_SEND_ONCE).then(|| self.right_reverse(port)).flatten() {
            Some(n) => n,
            None => match self.space.alloc(Some(port)) {
                Some(n) => n,
                None => {
                    self.object_destroy(c, t);
                    return Err(kr::NO_SPACE);
                }
            },
        };
        self.right_copyout(name, t, port, guard);
        Ok(name)
    }

    /// `ipc_object_copyout_name`: carried right `t` under exactly `name`.
    pub fn object_copyout_name(&mut self, c: Carried, t: u32, name: u32) -> Result<(), u64> {
        let Carried::Port(port) = c else { return Err(kr::INVALID_CAPABILITY) };
        let claimed = self.space.alloc_name(name)?;
        let in_use = !claimed;
        if !self.port(port).active {
            if !in_use {
                self.space.dealloc(name);
            }
            return Err(kr::INVALID_CAPABILITY);
        }
        if t != msgt::PORT_SEND_ONCE {
            if let Some(oname) = self.right_reverse(port) {
                if name != oname {
                    if !in_use {
                        self.space.dealloc(name);
                    }
                    return Err(kr::RIGHT_EXISTS);
                }
                self.right_copyout(name, t, port, None);
                return Ok(());
            }
        }
        if in_use {
            return Err(kr::NAME_EXISTS);
        }
        self.space.lookup_mut_any(name).object = Some(port);
        if t == msgt::PORT_RECEIVE {
            self.port_mut(port).tempowner = false;
        }
        self.right_copyout(name, t, port, None);
        Ok(())
    }

    /// `ipc_object_copyout_dest`: a received message's destination right,
    /// consumed; the receive right's name if it is in this space.
    pub fn object_copyout_dest(&mut self, port: ObjId, t: u32) -> u32 {
        let p = self.port(port);
        let in_space = match p.receiver {
            Receiver::Space(n) if p.owner == self.task => Some(n),
            _ => None,
        };
        match t {
            msgt::PORT_SEND => {
                let name = in_space.unwrap_or(0);
                let p = self.port_mut(port);
                p.srights -= 1;
                let ns = if p.srights == 0 { self.no_senders_prepare_pub(port) } else { None };
                if let Some(n) = ns {
                    self.outbox.push(n);
                }
                self.release(port);
                name
            }
            msgt::PORT_SEND_ONCE => match in_space {
                Some(n) => {
                    self.port_mut(port).sorights -= 1;
                    self.release(port);
                    n
                }
                None => {
                    self.send_once_destroyed(port);
                    0
                }
            },
            _ => panic!("ipc_object_copyout_dest: strange rights {t}"),
        }
    }

    /// `ipc_object_insert_send_right` (`mach_port_insert_right` with the
    /// right already in place): another user reference, or a send right
    /// made from the receive right.
    pub fn insert_send_right(&mut self, name: u32, t: u32) -> u64 {
        let Some(e) = self.space.lookup(name).copied() else { return kr::INVALID_NAME };
        let Some(port) = e.object else { return kr::INVALID_CAPABILITY };
        let mut b = e.bits;
        if b & ty::PORT_RIGHTS == 0 {
            return kr::INVALID_RIGHT;
        }
        if !self.port(port).active {
            return kr::INVALID_CAPABILITY;
        }
        if t == msgt::MAKE_SEND {
            if b & ty::RECEIVE == 0 {
                return kr::INVALID_RIGHT;
            }
            let p = self.port_mut(port);
            p.mscount += 1;
            if b & ty::SEND == 0 {
                p.srights += 1;
                b |= ty::SEND;
            }
            if b & bits::UREFS_MASK < UREFS_MAX {
                b += 1;
            }
            self.space.lookup_mut(name).expect("in use").bits = b;
            kr::SUCCESS
        } else if b & ty::SEND != 0 {
            if b & bits::UREFS_MASK < UREFS_MAX {
                self.space.lookup_mut(name).expect("in use").bits = b + 1;
            }
            kr::SUCCESS
        } else {
            kr::INVALID_RIGHT
        }
    }
}
