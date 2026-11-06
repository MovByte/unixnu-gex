//! An exception sent to its handlers (`exception.c`): `exception_triage`
//! tries the thread's, the task's and the host's handler in turn, each by
//! `exception_deliver`'s RPC (`mach_exception_raise*`, `exc.defs` and
//! `mach_exc.defs`), the raising thread waiting for the reply on its own
//! kernel reply port (`ith_rpc_reply`). The host's handler for most types
//! is the kernel's (`ux_handler`), which makes the exception a signal
//! (`handle_ux_exception`).

use super::exception::{self as exc, ExcAction, ExcActions};
use super::ipc::msg::{bits, Kmsg, Sender};
use super::ipc::right::{msgt, Carried};
use super::ipc::{kr, Kobject, ObjId, Receiver};
use super::wait::{Wait, WaitResult};
use crate::syscalls::{Kernel, SyscallOutcome};
use crate::GuestMem;

const HEADER: u32 = 24;
const KERN_FAILURE: u64 = 5;
/// `MACH_RCV_PORT_DIED`.
const RCV_PORT_DIED: u64 = 0x1000_4009;
/// `MIG_TYPE_ERROR`, `MIG_REPLY_MISMATCH`, `MIG_SERVER_DIED`.
const MIG_TYPE_ERROR: i32 = -300;
const MIG_REPLY_MISMATCH: i32 = -301;
const MIG_SERVER_DIED: i32 = -308;
/// `MACH_NOTIFY_SEND_ONCE`: the reply right was destroyed unanswered.
const NOTIFY_SEND_ONCE: i32 = 0o107;
/// `THREAD_STATE_MAX`.
const STATE_MAX: u32 = 1296;

/// `exc.defs` (2401) and `mach_exc.defs` (2405): `*_raise`, `*_state`,
/// `*_state_identity`.
const EXC_BASE: i32 = 2401;
const MACH_EXC_BASE: i32 = 2405;

/// What the raising thread does once the exception is handled
/// (`exception_triage_thread`'s end).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Then {
    /// `thread_exception_return`: back to user space as the thread stands.
    Return,
    /// `proc_prepareexit`'s EXC_CRASH: the process goes on to die of
    /// `signal`.
    Exit { signal: u32, core: bool },
}

/// An exception on its way through the levels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Triage {
    pub exc: usize,
    pub codes: [i64; 2],
    pub count: u32,
    /// The next level to try: thread, task, host.
    level: u8,
    pub then: Then,
}

/// A delivery waiting for its handler's reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pending {
    t: Triage,
    id: i32,
}

/// One level's delivery: done with a result, or sent and awaited.
enum Delivered {
    Done(u64),
    Sent(Pending),
}

impl Kernel {
    /// `exception_triage(exception, code, codeCnt)` for the calling thread.
    pub(crate) fn darwin_exception_triage(&mut self, m: &mut GuestMem<'_>, exc: usize, codes: &[i64], then: Then) -> SyscallOutcome {
        let mut c = [0i64; 2];
        for (d, s) in c.iter_mut().zip(codes) {
            *d = *s;
        }
        self.darwin_triage_from(m, Triage { exc, codes: c, count: codes.len().min(2) as u32, level: 0, then })
    }

    /// The levels from `t.level` on, until one takes the exception.
    fn darwin_triage_from(&mut self, m: &mut GuestMem<'_>, mut t: Triage) -> SyscallOutcome {
        let mut last = KERN_FAILURE;
        while t.level < 3 {
            let actions: Option<ExcActions> = match t.level {
                0 => self.dtask.kports.thread_exc.get(&self.tid).copied(),
                1 => Some(self.dtask.kports.exc),
                _ => Some(self.ipc().host_exc),
            };
            t.level += 1;
            let Some(actions) = actions else { continue };
            if !self.darwin_exc_receiver_independent(t.exc, &actions) {
                continue;
            }
            match self.darwin_exception_deliver(m, &t, &actions[t.exc]) {
                Delivered::Done(r) => {
                    last = r;
                    if r == kr::SUCCESS || r == RCV_PORT_DIED {
                        break;
                    }
                }
                Delivered::Sent(p) => return self.darwin_exc_await(m, p),
            }
        }
        self.darwin_triage_end(m, t.then, last)
    }

    /// `check_exc_receiver_dependency`: an EXC_CRASH is not sent to a
    /// handler in the crashing task's own space.
    fn darwin_exc_receiver_independent(&mut self, ty: usize, actions: &ExcActions) -> bool {
        if ty != exc::EXC_CRASH {
            return true;
        }
        let Some(Carried::Port(p)) = actions[ty].port else { return true };
        let ipc = self.ipc();
        !(ipc.port(p).owner == ipc.task && matches!(ipc.port(p).receiver, Receiver::Space(_)))
    }

    fn darwin_triage_end(&mut self, _m: &mut GuestMem<'_>, then: Then, kr: u64) -> SyscallOutcome {
        match then {
            Then::Return => SyscallOutcome::Continue,
            Then::Exit { signal, core } => {
                // No handler took it: a corpse, for its notification
                // handler (with none, the corpse goes unseen).
                if kr != kr::SUCCESS && self.darwin_task_exc_handled(exc::EXC_CORPSE_NOTIFY) {
                    self.darwin_unimplemented("a corpse of a crashed task for its EXC_CORPSE_NOTIFY handler (corpses)".into());
                }
                SyscallOutcome::Killed { signal, core }
            }
        }
    }

    /// `exception_deliver` at one level.
    fn darwin_exception_deliver(&mut self, m: &mut GuestMem<'_>, t: &Triage, a: &ExcAction) -> Delivered {
        let Some(Carried::Port(port)) = a.port else { return Delivered::Done(KERN_FAILURE) };
        let ux = self.ipc().global_port(Kobject::UxHandler);
        if port == ux {
            return Delivered::Done(self.darwin_handle_ux_exception(m, t.exc, t.codes[0], t.codes[1]));
        }
        let code64 = a.behavior & exc::MACH_EXCEPTION_CODES != 0;
        let behavior = a.behavior & !exc::MACH_EXCEPTION_MASK;
        let base = if code64 { MACH_EXC_BASE } else { EXC_BASE };
        match behavior {
            exc::EXCEPTION_STATE => {
                let ctx = self.ctx_addr;
                let old_state = match self.machine_thread_get_state(m, self.tid, ctx, a.flavor, STATE_MAX) {
                    Ok(s) => s,
                    Err(e) => return Delivered::Done(e as u32 as u64),
                };
                let id = base + 1;
                let mut body = super::mig::NDR_RECORD.to_vec();
                body.extend_from_slice(&(t.exc as i32).to_le_bytes());
                body.extend_from_slice(&t.count.to_le_bytes());
                for &c in &t.codes[..t.count as usize] {
                    if code64 {
                        body.extend_from_slice(&c.to_le_bytes());
                    } else {
                        body.extend_from_slice(&(c as i32).to_le_bytes());
                    }
                }
                body.extend_from_slice(&a.flavor.to_le_bytes());
                body.extend_from_slice(&(old_state.len() as u32).to_le_bytes());
                for w in &old_state {
                    body.extend_from_slice(&w.to_le_bytes());
                }
                self.darwin_exc_send(port, id, body);
                Delivered::Sent(Pending { t: *t, id })
            }
            exc::EXCEPTION_DEFAULT | exc::EXCEPTION_STATE_IDENTITY => {
                // The thread's and task's read ports go with it (Developer
                // Mode off: convert_*_read_to_port).
                self.darwin_unimplemented(format!("exception {} to a handler of behavior {behavior} (thread and task read ports)", t.exc));
                Delivered::Done(KERN_FAILURE)
            }
            exc::EXCEPTION_IDENTITY_PROTECTED => {
                self.darwin_unimplemented(format!("exception {} to an EXCEPTION_IDENTITY_PROTECTED handler (task identity tokens)", t.exc));
                Delivered::Done(KERN_FAILURE)
            }
            _ => Delivered::Done(KERN_FAILURE),
        }
    }

    /// The request, with a copy of the handler's send right and a
    /// send-once right to the thread's reply port, as the kernel sends it.
    fn darwin_exc_send(&mut self, port: ObjId, id: i32, body: Vec<u8>) {
        let reply = self.darwin_rpc_reply_port();
        let ipc = self.ipc();
        ipc.copy_send(port);
        ipc.make_sonce(reply);
        let k = Kmsg { bits: bits::set(msgt::PORT_SEND, msgt::PORT_SEND_ONCE, 0, 0), size: HEADER + body.len() as u32, dest: port, reply: Some(Carried::Port(reply)), voucher: None, voucher_raw: 0, id, body, descs: Vec::new(), sender: Sender::KERNEL, aux: Vec::new(), keep_alive: false, ppriority: 0, qos_override: 0 };
        self.darwin_kernel_send(Box::new(k));
        self.darwin_ipc_notify_drain();
    }

    /// The thread's kernel reply port (`ith_rpc_reply`), made at its first
    /// RPC.
    fn darwin_rpc_reply_port(&mut self) -> ObjId {
        let tid = self.tid;
        if let Some(&p) = self.dtask.rpc_reply.get(&tid) {
            return p;
        }
        let ipc = self.ipc();
        let p = ipc.kobject_port(Kobject::RpcReply(tid));
        ipc.port_mut(p).owner = ipc.task;
        self.dtask.rpc_reply.insert(tid, p);
        p
    }

    /// A message to a thread's reply port: kept for the thread, which is
    /// woken to take it.
    pub(crate) fn darwin_rpc_reply_arrived(&mut self, port: ObjId, tid: i32, k: Box<Kmsg>) {
        let ipc = self.ipc();
        if bits::remote(k.bits) == msgt::PORT_SEND_ONCE {
            ipc.port_mut(port).sorights -= 1;
        } else {
            ipc.port_mut(port).srights -= 1;
        }
        ipc.release(port);
        if let Some(old) = self.dtask.rpc_replies.insert(tid, k) {
            self.ipc().kmsg_destroy(old, true);
        }
        let w = self.ipc().waiter(tid);
        self.ipc().queues.wake.push(w);
    }

    /// Wait for the reply, unless it is here already.
    fn darwin_exc_await(&mut self, m: &mut GuestMem<'_>, p: Pending) -> SyscallOutcome {
        // The handler waiting for the request is woken.
        self.darwin_ipc_settle(m);
        if self.dtask.rpc_replies.contains_key(&self.tid) {
            return self.darwin_exc_wait_done(m, p, WaitResult::Awakened).unwrap_or(SyscallOutcome::Continue);
        }
        self.darwin_block(m, Wait { deadline: None, cont: super::thread::Finish::Exception(p) })
    }

    /// The handler answered (or the wait was cut short).
    pub(crate) fn darwin_exc_wait_done(&mut self, m: &mut GuestMem<'_>, p: Pending, _res: WaitResult) -> Option<SyscallOutcome> {
        // mach_msg_rpc_from_kernel waits through interruptions.
        let Some(k) = self.dtask.rpc_replies.remove(&self.tid) else {
            return Some(self.darwin_block(m, Wait { deadline: None, cont: super::thread::Finish::Exception(p) }));
        };
        let r = self.darwin_exc_reply(m, &p, &k);
        self.ipc().kmsg_destroy(k, true);
        self.darwin_ipc_settle(m);
        if r == kr::SUCCESS || r == RCV_PORT_DIED {
            return Some(self.darwin_triage_end(m, p.t.then, r));
        }
        Some(self.darwin_triage_from(m, p.t))
    }

    /// The MIG client's check of a reply, and for a state behavior the new
    /// state set (`thread_setstatus_from_user`, but not for a corpse
    /// notification).
    fn darwin_exc_reply(&mut self, m: &mut GuestMem<'_>, p: &Pending, k: &Kmsg) -> u64 {
        let err = |e: i32| e as u32 as u64;
        if k.id != p.id + 100 {
            return err(if k.id == NOTIFY_SEND_ONCE { MIG_SERVER_DIED } else { MIG_REPLY_MISMATCH });
        }
        let b = &k.body;
        let i32_at = |o: usize| b.get(o..o + 4).map(|s| i32::from_le_bytes(s.try_into().unwrap()));
        if k.bits & bits::COMPLEX != 0 || b.len() < 12 {
            return err(MIG_TYPE_ERROR);
        }
        let ret = i32_at(8).unwrap_or(MIG_TYPE_ERROR);
        if ret != 0 {
            return err(ret);
        }
        let (Some(flavor), Some(cnt)) = (i32_at(12), i32_at(16).map(|c| c as u32)) else { return err(MIG_TYPE_ERROR) };
        if cnt > STATE_MAX || b.len() != 20 + cnt as usize * 4 {
            return err(MIG_TYPE_ERROR);
        }
        let new: Vec<u32> = (0..cnt as usize).map(|i| i32_at(20 + i * 4).unwrap() as u32).collect();
        if p.t.exc == exc::EXC_CORPSE_NOTIFY {
            return kr::SUCCESS;
        }
        let ctx = self.ctx_addr;
        self.machine_thread_set_state(m, self.tid, ctx, flavor, &new) as u32 as u64
    }

    /// `handle_ux_exception`: the signal the exception means
    /// (`ux_exception`), sent to the thread.
    fn darwin_handle_ux_exception(&mut self, m: &mut GuestMem<'_>, ty: usize, code: i64, subcode: i64) -> u64 {
        use super::signal::dsig;
        const KERN_INVALID_ADDRESS: i64 = 1;
        const EXC_EMULATION: usize = 4;
        const EXC_SOFTWARE: usize = 5;
        let d = match ty {
            exc::EXC_BAD_INSTRUCTION => dsig::SIGILL,
            exc::EXC_ARITHMETIC => dsig::SIGFPE,
            exc::EXC_BAD_ACCESS if code == KERN_INVALID_ADDRESS => dsig::SIGSEGV,
            exc::EXC_BAD_ACCESS => dsig::SIGBUS,
            exc::EXC_SYSCALL => dsig::SIGSYS,
            EXC_EMULATION => dsig::SIGEMT,
            EXC_SOFTWARE => match code {
                0x10000 => dsig::SIGSYS,
                0x10001 => dsig::SIGPIPE,
                0x10002 => dsig::SIGABRT,
                0x10003 => dsig::SIGKILL,
                _ => 0,
            },
            exc::EXC_BREAKPOINT => dsig::SIGTRAP,
            _ => 0,
        };
        if d != 0 {
            // uu_exception and uu_subcode, and threadsignal's uu_code.
            let th = self.dtask.threads.map.entry(self.tid).or_default();
            th.uu_exception = ty as i32;
            th.uu_code = code;
            th.uu_subcode = subcode;
            let l = super::kern::signal_to_linux(d);
            if l == 0 {
                self.darwin_unimplemented(format!("Darwin signal {d}, which has no Linux number here, from exception {ty}"));
            } else {
                let _ = self.canonical(m, crate::syscalls::nr::TGKILL, [self.pid as u64, self.tid as u64, u64::from(l), 0, 0, 0]);
            }
        }
        kr::SUCCESS
    }
}
