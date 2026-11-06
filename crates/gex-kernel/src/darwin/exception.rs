//! Exception ports (`ipc_tt.c`, `ipc_host.c`): the handler a thread's, its
//! task's and the host's exceptions of each type go to, with the behavior
//! and thread state flavor of the message, and how they are set, swapped,
//! read back and inherited.

use super::ipc::msg::Kmsg;
use super::ipc::right::{msgt, Carried};
use super::ipc::{Guard, Ipc};
use super::kobject::{PortOut, Reply};
use crate::syscalls::Kernel;

/// `EXC_TYPES_COUNT`: exception types 1 to 13, and 0, which is none.
pub const EXC_TYPES_COUNT: usize = 14;
const FIRST_EXCEPTION: usize = 1;
pub const EXC_BAD_ACCESS: usize = 1;
pub const EXC_BAD_INSTRUCTION: usize = 2;
pub const EXC_ARITHMETIC: usize = 3;
pub const EXC_BREAKPOINT: usize = 6;
pub const EXC_CRASH: usize = 10;
pub const EXC_CORPSE_NOTIFY: usize = 13;
/// `EXC_MASK_VALID`: every type's bit, 1 to 13.
const EXC_MASK_VALID: u32 = 0x3ffe;

const EXCEPTION_DEFAULT: i32 = 1;
const EXCEPTION_STATE: i32 = 2;
const EXCEPTION_STATE_IDENTITY: i32 = 3;
const EXCEPTION_IDENTITY_PROTECTED: i32 = 4;
const MACH_EXCEPTION_BACKTRACE_PREFERRED: i32 = 0x2000_0000;
const MACH_EXCEPTION_ERRORS: i32 = 0x4000_0000;
const MACH_EXCEPTION_CODES: i32 = 0x8000_0000_u32 as i32;
const MACH_EXCEPTION_MASK: i32 = MACH_EXCEPTION_CODES | MACH_EXCEPTION_ERRORS | MACH_EXCEPTION_BACKTRACE_PREFERRED;

/// The most entries a get or swap reply holds (`exception_*_array_t`).
const ARRAY_MAX: usize = 32;

/// Entitlements that let a task set any handler on a hardened task.
const SET_EXCEPTION_ENTITLEMENT: &str = "com.apple.private.set-exception-port";
const THREAD_SET_STATE_ENTITLEMENT: &str = "com.apple.private.thread-set-state";

const KERN_INVALID_ARGUMENT: i32 = 4;
const KERN_FAILURE: i32 = 5;
const KERN_NO_ACCESS: i32 = 8;
const KERN_INVALID_RIGHT: i32 = 17;

/// `struct exception_action`: a send right to the handler (dead when it
/// was copied from a dead port), the message's behavior and flavor, and
/// whether a privileged task set it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExcAction {
    pub port: Option<Carried>,
    pub behavior: i32,
    pub flavor: i32,
    pub privileged: bool,
}

/// One exception action per type.
pub type ExcActions = [ExcAction; EXC_TYPES_COUNT];

/// Whose handlers are being set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Task,
    Thread,
    Host,
}

/// `VALID_THREAD_STATE_FLAVOR` for arm: thread, VFP, exception and debug
/// state in any width, NEON, none, and pagein.
fn valid_flavor(f: i32) -> bool {
    matches!(f, 1..=7 | 9 | 14..=17 | 27)
}

/// `exception_port_copy_send` (`ipc_port_copy_send_mqueue`): another send
/// right, or a dead one when the port has died.
pub fn copy_send(ipc: &mut Ipc, c: Option<Carried>) -> Option<Carried> {
    match c {
        Some(Carried::Port(p)) if ipc.port(p).active => {
            ipc.copy_send(p);
            Some(Carried::Port(p))
        }
        Some(_) => Some(Carried::Dead),
        None => None,
    }
}

/// `ipc_port_release_send` of what an action held.
pub fn release(ipc: &mut Ipc, c: Option<Carried>) {
    if let Some(Carried::Port(p)) = c {
        ipc.release_send(p);
    }
}

/// What a set or swap is allowed, as its caller sees it.
pub struct Setter {
    /// `task_is_privileged(current_task())`: the caller's effective uid
    /// is 0.
    pub privileged: bool,
    /// The caller holds either entitlement that lifts the hardening check.
    pub entitled: bool,
    /// The task whose handlers these are is a hardened binary.
    pub hardened: bool,
}

/// The checks `task_`, `thread_` and `host_set_exception_ports` share,
/// with `set_exception_behavior_allowed`: `Err` is the return code, and
/// `Ok(false)` a hardening violation, which raises the fatal guard
/// exception `kGUARD_EXC_EXCEPTION_BEHAVIOR_ENFORCE` and is refused with
/// KERN_NO_ACCESS (`thid_should_crash` is set).
fn check(ipc: &Ipc, level: Level, mask: u32, new: Option<Carried>, behavior: i32, flavor: i32, s: &Setter) -> Result<bool, i32> {
    if mask & !EXC_MASK_VALID != 0 {
        return Err(KERN_INVALID_ARGUMENT);
    }
    let port = match new {
        Some(Carried::Port(p)) => Some(p),
        _ => None,
    };
    if port.is_some() && !matches!(behavior & !MACH_EXCEPTION_MASK, EXCEPTION_DEFAULT | EXCEPTION_STATE | EXCEPTION_STATE_IDENTITY | EXCEPTION_IDENTITY_PROTECTED) {
        return Err(KERN_INVALID_ARGUMENT);
    }
    let opted_out = port.is_some_and(|p| ipc.port(p).reply_semantics == super::ipc::ReplySemantics::IdProtOptOut);
    if let Some(p) = port {
        let p = ipc.port(p);
        // A thread's handler may be an opted-out port with an immovable
        // receive right; the host's is not checked.
        let refused = match level {
            Level::Task => p.immovable_receive || p.immovable_send,
            Level::Thread => (!opted_out && p.immovable_receive) || p.immovable_send,
            Level::Host => false,
        };
        if refused {
            return Err(KERN_INVALID_RIGHT);
        }
    }
    if flavor != 0 && !valid_flavor(flavor) {
        return Err(KERN_INVALID_ARGUMENT);
    }
    if ((behavior & !MACH_EXCEPTION_MASK) == EXCEPTION_IDENTITY_PROTECTED || behavior & MACH_EXCEPTION_BACKTRACE_PREFERRED != 0) && behavior & MACH_EXCEPTION_CODES == 0 {
        return Err(KERN_INVALID_ARGUMENT);
    }
    // exception_exposes_protected_ports: a handler for a hardened task's
    // exceptions, or for the host's (every task's).
    let exposes = port.is_some() && (level == Level::Host || s.hardened);
    let protected = (behavior & !MACH_EXCEPTION_MASK) == EXCEPTION_IDENTITY_PROTECTED;
    Ok(!(exposes && !protected && !opted_out && !s.entitled))
}

/// Store `new` (a copy of it) as the handler of every type in `mask`,
/// releasing the old ones; the request's own right is the caller's to
/// release. With `old`, the old actions are first gathered as
/// `task_swap_exception_ports` reports them.
fn set(ipc: &mut Ipc, actions: &mut ExcActions, mask: u32, new: Option<Carried>, behavior: i32, flavor: i32, privileged: bool, mut old: Option<&mut Vec<(u32, ExcAction)>>) {
    let mut released = Vec::new();
    for (i, a) in actions.iter_mut().enumerate().skip(FIRST_EXCEPTION) {
        if mask & (1 << i) == 0 {
            continue;
        }
        if let Some(old) = old.as_deref_mut() {
            if old.len() >= ARRAY_MAX {
                break;
            }
            match old.iter_mut().find(|(_, o)| o.port == a.port && o.behavior == a.behavior && o.flavor == a.flavor) {
                Some((m, _)) => *m |= 1 << i,
                None => {
                    let port = copy_send(ipc, a.port);
                    old.push((1 << i, ExcAction { port, ..*a }));
                }
            }
        }
        released.push(a.port);
        *a = ExcAction { port: copy_send(ipc, new), behavior, flavor, privileged };
    }
    for p in released {
        release(ipc, p);
    }
}

/// The whole of a set or swap on `actions` (the checks, the hardening
/// guard on the calling task, the store): `Ok` with the old entries of a
/// swap. The caller keeps its right to `new`.
#[allow(clippy::too_many_arguments)]
pub fn set_port(ipc: &mut Ipc, actions: &mut ExcActions, level: Level, mask: u32, new: Option<Carried>, behavior: i32, flavor: i32, s: &Setter, swap: bool) -> Result<Vec<(u32, ExcAction)>, i32> {
    if !check(ipc, level, mask, new, behavior, flavor, s)? {
        ipc.guard_exception(0, Guard::ExceptionBehaviorEnforce, 0);
        return Err(KERN_NO_ACCESS);
    }
    let mut old = Vec::new();
    let privileged = level != Level::Host && s.privileged;
    set(ipc, actions, mask, new, behavior, flavor, privileged, swap.then_some(&mut old));
    Ok(old)
}

/// Copies of every action's right (`ipc_task_init`'s inheritance).
pub fn copy_all(ipc: &mut Ipc, actions: &ExcActions) -> ExcActions {
    let mut out = *actions;
    for a in out.iter_mut() {
        a.port = copy_send(ipc, a.port);
    }
    out
}

/// Every action's right released (`ipc_task_terminate`,
/// `ipc_thread_destroy_exc_actions`).
pub fn release_all(ipc: &mut Ipc, actions: &ExcActions) {
    for a in actions {
        release(ipc, a.port);
    }
}

/// `task_get_exception_ports_internal`: the actions for the types in
/// `mask`, those alike merged into one entry with their types' bits, each
/// with a copy of its send right.
fn get(ipc: &mut Ipc, actions: &ExcActions, mask: u32) -> Vec<(u32, ExcAction)> {
    let mut out: Vec<(u32, ExcAction)> = Vec::new();
    for (i, a) in actions.iter().enumerate().skip(FIRST_EXCEPTION) {
        if mask & (1 << i) == 0 {
            continue;
        }
        let full = out.len() >= ARRAY_MAX;
        match out.iter_mut().find(|(_, o)| o.port == a.port && o.behavior == a.behavior && o.flavor == a.flavor) {
            Some((m, _)) => *m |= 1 << i,
            None if !full => {
                let port = copy_send(ipc, a.port);
                out.push((1 << i, ExcAction { port, ..*a }));
            }
            None => {}
        }
    }
    out
}

/// The get and swap reply: 32 handler descriptors (null past the count),
/// then the count and, packed at it, the masks, behaviors and flavors.
fn reply(entries: Vec<(u32, ExcAction)>) -> Reply {
    let mut r = Reply::ok(Vec::new());
    let mut out = super::mig::NDR_RECORD.to_vec();
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (m, _) in &entries {
        out.extend_from_slice(&m.to_le_bytes());
    }
    for (_, a) in &entries {
        out.extend_from_slice(&a.behavior.to_le_bytes());
    }
    for (_, a) in &entries {
        out.extend_from_slice(&a.flavor.to_le_bytes());
    }
    for (_, a) in &entries {
        r.ports.push(match a.port {
            Some(Carried::Port(p)) => PortOut::Right(Carried::Port(p), msgt::PORT_SEND),
            Some(Carried::Dead) => PortOut::Raw(super::ipc::PORT_DEAD),
            None => PortOut::Raw(0),
        });
    }
    while r.ports.len() < ARRAY_MAX {
        r.ports.push(PortOut::Raw(0));
    }
    r.out = out;
    r
}

/// The request's handler right, as the set and swap requests carry it.
fn request_port(req: &Kmsg) -> Option<Option<Carried>> {
    match req.descs.first()? {
        super::ipc::msg::Desc::Port { right, .. } => Some(*right),
        _ => None,
    }
}

impl Kernel {
    /// `task_is_hardened_binary`: a platform binary, or one holding one of
    /// the web browser engine entitlements that mark the hardened runtime
    /// (`hardened_runtime_binary`, from the kernelcache's
    /// kCSWebBrowser*Entitlement strings).
    pub(crate) fn darwin_hardened(&self) -> bool {
        const HR: [&str; 4] = [
            "com.apple.developer.web-browser-engine.host",
            "com.apple.developer.web-browser-engine.rendering",
            "com.apple.developer.web-browser-engine.networking",
            "com.apple.developer.web-browser-engine.webcontent",
        ];
        self.darwin_task_platform_binary() || HR.iter().any(|e| self.darwin_task_entitled(e))
    }

    /// What the task making this request may do (the caller: this task, or
    /// the one whose request it serves).
    fn exc_setter(&mut self, req: &Kmsg, hardened: bool) -> Setter {
        let caller = self.dtask.kcaller;
        let entitled = if caller == 0 || caller == self.ipc().task {
            self.darwin_task_entitled(SET_EXCEPTION_ENTITLEMENT) || self.darwin_task_entitled(THREAD_SET_STATE_ENTITLEMENT)
        } else {
            self.ipc().links.get(&caller).is_some_and(|l| l.codesign.as_ref().is_some_and(|c| c.entitled(SET_EXCEPTION_ENTITLEMENT) || c.entitled(THREAD_SET_STATE_ENTITLEMENT)))
        };
        Setter { privileged: req.sender.sec[0] == 0, entitled, hardened }
    }

    /// `task_`, `thread_` or `host_set_exception_ports` (`swap`: the
    /// swap) for the actions `level` and `tid` name, from request `req`;
    /// the request's right is consumed.
    pub(crate) fn darwin_exc_set(&mut self, level: Level, tid: i32, req: &Kmsg, swap: bool) -> Reply {
        let (Some(new), Some(mask), Some(behavior), Some(flavor)) = (request_port(req), super::mig::arg_after(req, 1, 0), super::mig::arg_after(req, 1, 1), super::mig::arg_after(req, 1, 2)) else {
            return Reply::err(super::mig::MIG_BAD_ARGUMENTS);
        };
        let hardened = level != Level::Host && self.darwin_hardened();
        let s = self.exc_setter(req, hardened);
        match self.darwin_exc_set_port(level, tid, mask as u32, new, behavior, flavor, &s, swap) {
            // The request's send right is consumed (a failed request's
            // rights are destroyed with it).
            Ok(old) => {
                release(self.ipc(), new);
                if swap { reply(old) } else { Reply::ok(Vec::new()) }
            }
            Err(e) => Reply::err(e),
        }
    }

    /// The set (or swap) itself, for `posix_spawn` too; `Ok` with the old
    /// entries of a swap. The caller keeps its right to `new`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn darwin_exc_set_port(&mut self, level: Level, tid: i32, mask: u32, new: Option<Carried>, behavior: i32, flavor: i32, s: &Setter, swap: bool) -> Result<Vec<(u32, ExcAction)>, i32> {
        if level == Level::Thread && !self.darwin_thread_alive(tid) {
            // Checked after the arguments, as thread_set_exception_ports does.
            check(self.ipc(), level, mask, new, behavior, flavor, s)?;
            return Err(KERN_FAILURE);
        }
        let mut actions = self.exc_actions_take(level, tid);
        let r = set_port(self.ipc(), &mut actions, level, mask, new, behavior, flavor, s, swap);
        self.exc_actions_put(level, tid, actions);
        r
    }

    /// `task_`, `thread_` or `host_get_exception_ports`.
    pub(crate) fn darwin_exc_get(&mut self, level: Level, tid: i32, req: &Kmsg) -> Reply {
        let Some(mask) = super::mig::arg(req, 0) else { return Reply::err(super::mig::MIG_BAD_ARGUMENTS) };
        if mask as u32 & !EXC_MASK_VALID != 0 {
            return Reply::err(KERN_INVALID_ARGUMENT);
        }
        if level == Level::Thread && !self.darwin_thread_alive(tid) {
            return Reply::err(KERN_FAILURE);
        }
        let actions = self.exc_actions_take(level, tid);
        let entries = get(self.ipc(), &actions, mask as u32);
        self.exc_actions_put(level, tid, actions);
        reply(entries)
    }

    fn exc_actions_take(&mut self, level: Level, tid: i32) -> ExcActions {
        match level {
            Level::Task => self.dtask.kports.exc,
            Level::Thread => self.dtask.kports.thread_exc.get(&tid).copied().unwrap_or_default(),
            Level::Host => self.ipc().host_exc,
        }
    }

    fn exc_actions_put(&mut self, level: Level, tid: i32, a: ExcActions) {
        match level {
            Level::Task => self.dtask.kports.exc = a,
            Level::Thread => {
                self.dtask.kports.thread_exc.insert(tid, a);
            }
            Level::Host => self.ipc().host_exc = a,
        }
    }

    /// Whether an exception of type `exc` taken by the calling thread has a
    /// handler to go to: the thread's, its task's or the host's.
    pub(crate) fn darwin_exc_handled(&mut self, exc: usize) -> bool {
        let valid = |a: &ExcActions| matches!(a[exc].port, Some(Carried::Port(_)));
        let tid = self.tid;
        self.dtask.kports.thread_exc.get(&tid).is_some_and(valid) || valid(&self.dtask.kports.exc) || valid(&self.ipc().host_exc)
    }

    /// Whether an exception of type `exc` the task raises (a corpse's, no
    /// thread's) has a handler: the task's or the host's.
    pub(crate) fn darwin_task_exc_handled(&mut self, exc: usize) -> bool {
        let valid = |a: &ExcActions| matches!(a[exc].port, Some(Carried::Port(_)));
        valid(&self.dtask.kports.exc) || valid(&self.ipc().host_exc)
    }
}
