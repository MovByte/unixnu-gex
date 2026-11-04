//! Mach timers (`osfmk/kern/mk_timer.c`): a receive right whose port the
//! kernel sends an expiry message to when an armed deadline passes.
//!
//! The expiry message is preallocated and kept alive: while one is still
//! queued (or handed to a receiver and not yet copied out), an expiry sends
//! nothing.

use super::ipc::msg::{bits, Kmsg, Sender};
use super::ipc::right::msgt;
use super::ipc::{kr, Kobject, ObjId};
use super::timer::Action;
use crate::syscalls::Kernel;
use crate::GuestMem;
use std::collections::HashMap;
use std::time::Instant;

/// `sizeof(mk_timer_expire_msg_t)`: a header and three unused `uint64_t`s.
const EXPIRE_MSG_SIZE: u32 = 24 + 24;
/// `MK_TIMER_CRITICAL`.
const MK_TIMER_CRITICAL: u64 = 1;

/// `struct mk_timer`, by its port.
#[derive(Debug)]
pub struct MkTimer {
    /// The send right the timer holds to its port.
    port: ObjId,
    is_armed: bool,
    is_dead: bool,
    /// Calls entered and not yet run or cancelled.
    active: i32,
    /// The armed thread call and its deadline in absolute time.
    call: Option<((Instant, u64), u64)>,
}

#[derive(Debug, Default)]
pub struct MkTimers {
    map: HashMap<ObjId, MkTimer>,
}

impl Kernel {
    /// `mk_timer_create_trap`: the name of a new timer's receive right, or
    /// null.
    pub(crate) fn mk_timer_create(&mut self) -> u32 {
        let ipc = &mut self.dtask.ipc;
        let Ok((name, port)) = ipc.port_alloc(false) else { return 0 };
        let p = ipc.port_mut(port);
        p.immovable_receive = true;
        p.kobject = Some(Kobject::Timer);
        ipc.make_send(port);
        self.dtask.mk_timers.map.insert(port, MkTimer { port, is_armed: false, is_dead: false, active: 0, call: None });
        name
    }

    /// The timer whose receive right `name` is: `ipc_port_translate_receive`
    /// then the `IKOT_TIMER` check.
    fn mk_timer_lookup(&mut self, name: u32) -> Result<ObjId, u64> {
        let port = self.dtask.ipc.translate_receive(name)?;
        if self.dtask.mk_timers.map.get(&port).is_some_and(|_| self.dtask.ipc.port(port).kobject == Some(Kobject::Timer)) {
            Ok(port)
        } else {
            Err(kr::INVALID_ARGUMENT)
        }
    }

    /// `mk_timer_destroy_trap`.
    pub(crate) fn mk_timer_destroy(&mut self, name: u32) -> u64 {
        // ipc_right_lookup_write
        let Some(e) = self.dtask.ipc.space.lookup(name).copied() else { return kr::INVALID_NAME };
        if e.bits & super::ipc::ty::RECEIVE == 0 {
            return kr::INVALID_RIGHT;
        }
        let port = e.object.expect("a receive right names a port");
        if self.dtask.ipc.port(port).kobject != Some(Kobject::Timer) {
            return kr::INVALID_ARGUMENT;
        }
        self.dtask.ipc.right_destroy(name, true, 0)
    }

    /// `mk_timer_port_destroy`: the timer's port died.
    pub(crate) fn mk_timer_port_destroy(&mut self, port: ObjId) {
        let Some(t) = self.dtask.mk_timers.map.get_mut(&port) else { return };
        if let Some((key, _)) = t.call.take() {
            if self.dtask.timers.cancel(key) {
                t.active -= 1;
            }
        }
        t.is_armed = false;
        t.is_dead = true;
        if t.active == 0 {
            self.mk_timer_free(port);
        }
    }

    /// `mk_timer_unlock_and_destroy`: the timer goes, and its send right.
    fn mk_timer_free(&mut self, port: ObjId) {
        let t = self.dtask.mk_timers.map.remove(&port).expect("a timer");
        self.dtask.ipc.release_send(t.port);
    }

    /// `mk_timer_arm_trap` and `mk_timer_arm_leeway_trap`: `expire` is in
    /// absolute time.
    pub(crate) fn mk_timer_arm(&mut self, name: u32, expire: u64, leeway: u64, flags: u64) -> u64 {
        // The leeway and MK_TIMER_CRITICAL only let the call fire later or
        // be coalesced less; firing at the deadline is within both.
        let _ = (leeway, flags & MK_TIMER_CRITICAL);
        let port = match self.mk_timer_lookup(name) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let t = self.dtask.mk_timers.map.get_mut(&port).expect("a timer");
        if t.is_dead {
            return kr::SUCCESS;
        }
        t.is_armed = true;
        // thread_call_enter_delayed (or thread_call_enter1 for a deadline
        // already past): a call already entered moves, else one more is
        // active.
        let at = if expire > super::mach::absolute_time() { super::mach::abs_to_instant(expire) } else { Instant::now() };
        let was = t.call.take();
        let entered = match was {
            Some((key, _)) => self.dtask.timers.cancel(key),
            None => false,
        };
        let key = self.dtask.timers.arm(at, Action::MkTimer(port));
        let t = self.dtask.mk_timers.map.get_mut(&port).expect("a timer");
        if !entered {
            t.active += 1;
        }
        t.call = Some((key, expire));
        kr::SUCCESS
    }

    /// `mk_timer_cancel_trap`: the armed deadline (0 when not armed) to
    /// `result_time`.
    pub(crate) fn mk_timer_cancel(&mut self, m: &mut GuestMem<'_>, name: u32, result_time: u64) -> u64 {
        let port = match self.mk_timer_lookup(name) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let t = self.dtask.mk_timers.map.get_mut(&port).expect("a timer");
        let mut armed_time = 0;
        if t.is_armed {
            if let Some((key, abs)) = t.call.take() {
                armed_time = abs;
                if self.dtask.timers.cancel(key) {
                    t.active -= 1;
                }
            }
            t.is_armed = false;
        }
        if result_time != 0 && m.write_u64(result_time, armed_time).is_err() {
            return kr::FAILURE;
        }
        kr::SUCCESS
    }

    /// `mk_timer_expire`: the deadline passed; one expiry message is sent
    /// if the last one has been received.
    pub(crate) fn mk_timer_expire(&mut self, m: &mut GuestMem<'_>, port: ObjId, key: (Instant, u64)) {
        let Some(t) = self.dtask.mk_timers.map.get_mut(&port) else { return };
        if t.call.is_some_and(|c| c.0 == key) {
            t.call = None;
        }
        if t.is_armed && t.active == 1 {
            t.is_armed = false;
            let in_use = self.mk_timer_message_in_use(port);
            if !in_use {
                let k = Kmsg {
                    bits: bits::set(msgt::PORT_SEND, 0, 0, 0),
                    size: EXPIRE_MSG_SIZE,
                    dest: port,
                    reply: None,
                    voucher: None,
                    voucher_raw: 0,
                    id: 0,
                    body: vec![0; (EXPIRE_MSG_SIZE - 24) as usize],
                    descs: Vec::new(),
                    sender: Sender::KERNEL,
                    aux: Vec::new(),
                    keep_alive: true,
                };
                // kernel_mach_msg_send_kmsg: a copy of the timer's send
                // right goes with the message.
                self.dtask.ipc.copy_send(port);
                self.darwin_kernel_send(Box::new(k));
            }
        }
        let t = self.dtask.mk_timers.map.get_mut(&port).expect("a timer");
        t.active -= 1;
        if t.active == 0 && t.is_dead {
            self.mk_timer_free(port);
        }
        self.darwin_ipc_settle(m);
    }

    /// `ipc_kmsg_keep_alive_try_reusing` fails while the timer's last
    /// message is still queued or held by a receiver that has not copied it
    /// out.
    fn mk_timer_message_in_use(&self, port: ObjId) -> bool {
        let ipc = &self.dtask.ipc;
        ipc.port(port).messages.iter().any(|k| k.keep_alive) || ipc.queues.received.values().any(|r| r.kmsg.as_ref().is_some_and(|k| k.keep_alive && k.dest == port))
    }
}
