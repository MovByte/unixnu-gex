//! The WebMetal connection: the accelerator's user client of type 0, over
//! which the WebMetal plugin exchanges wire protocol records with the host
//! executor (WebMetal `wire/README.md`, "Channels" and "Transport"). It
//! presents as the device client Metal's driver opens on the device, an
//! `AGXDeviceUserClient` (its class, superclasses and properties); its
//! methods are WebMetal's.
//!
//! Its selectors take and return 64-bit scalars:
//!
//! | Selector | Inputs | Outputs |
//! | --- | --- | --- |
//! | 0 `control` | request address, request length, reply address, reply capacity | reply length |
//! | 1 `fetch_reply` | reply address, reply capacity | reply length |
//! | 2 `register_event_port` (asynchronous) | queue handle (0: device-level events) | |
//!
//! A control request is read from the caller's memory and handed to the
//! host executor ([`super::host`]), which runs on a thread of its own; the
//! call is answered when the executor is done, as a driver's method that
//! sleeps until its hardware finishes returns then. Its reply record goes
//! into the caller's reply buffer when it fits there; otherwise it stays
//! pending for `fetch_reply`. A connection's calls run one after another,
//! as one user client's calls do under IOUserClient's locking: a call made
//! while a control request is with the executor waits for it.
//!
//! The executor queues event records per command queue and rings the
//! queue's doorbell: the connection sends the async completion of the
//! queue's `register_event_port` (`IOUserClient::sendAsyncResult64`, the
//! queue handle its one argument), and the guest collects the records with
//! a FetchEvents request.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use super::super::iokit::{dispatch_check, no_method, ret, Dispatch, MethodArgs, ASYNC_REF64_COUNT};
use super::super::ipc::{ObjId, TaskLink};
use super::host::{self, Done, Fault, FaultKind, Outcome, TaskMemory};
use crate::syscalls::Kernel;
use crate::GuestMem;

/// The connection's type.
pub const TYPE: u32 = 0;

/// The selectors' argument counts: scalars in, structure in, scalars out,
/// structure out.
const METHODS: [Dispatch; 3] = [
    Dispatch { scalar_in: 4, struct_in: 0, scalar_out: 1, struct_out: 0 },
    Dispatch { scalar_in: 2, struct_in: 0, scalar_out: 1, struct_out: 0 },
    Dispatch { scalar_in: 1, struct_in: 0, scalar_out: 0, struct_out: 0 },
];

/// The record header's size: opcode, flags, length.
const HEADER: u64 = 8;


/// A registration of `register_event_port`: the queue handle, the wake
/// port's send right (the async reference's port) and the reference, which
/// the completion carries back.
#[derive(Debug)]
struct EventPort {
    queue: u64,
    wake: ObjId,
    reference: [u64; ASYNC_REF64_COUNT],
}

/// A call waiting its turn, or with the executor.
#[derive(Debug)]
enum Call {
    /// `control(request, length, reply, capacity)`.
    Control { token: u64, request: (u64, u64), reply: (u64, u64) },
    /// `fetch_reply(reply, capacity)`.
    Fetch { token: u64, reply: (u64, u64) },
}

impl Call {
    fn token(&self) -> u64 {
        match self {
            Call::Control { token, .. } | Call::Fetch { token, .. } => *token,
        }
    }
}

/// A connection's state, which its task's kernel changes (in its calls,
/// and as the executor's answers reach it).
#[derive(Debug, Default)]
struct State {
    /// `clientClose` has run.
    closed: bool,
    events: Vec<EventPort>,
    /// The reply of the last control call, while it is pending: it did
    /// not fit its caller's buffer and `fetch_reply` has not written it.
    pending: Option<Vec<u8>>,
    /// The calls in order: the first is the one being served (a control
    /// request with the executor), the rest wait for it.
    calls: VecDeque<Call>,
}

/// A connection as its user client and the executor's answers share it.
#[derive(Debug)]
struct Shared {
    conn: u64,
    /// Its task's memory, for the executor and the requests and replies.
    memory: TaskMemory,
    /// Its task's mailbox, through which the executor's answers reach its
    /// kernel.
    link: Arc<TaskLink>,
    state: Mutex<State>,
}

impl Shared {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The connections' numbers, never reused.
static NEXT_CONN: AtomicU64 = AtomicU64::new(1);


/// The open connections, by number: what the executor's rings and reports
/// reach.
static CONNS: Mutex<Option<HashMap<u64, Arc<Shared>>>> = Mutex::new(None);

fn conns<R>(f: impl FnOnce(&mut HashMap<u64, Arc<Shared>>) -> R) -> R {
    f(CONNS.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_with(HashMap::new))
}

/// What the executor's thread leaves for a connection's task, which its
/// kernel acts on ([`Kernel::darwin_accel_note`]).
#[derive(Debug)]
pub enum Note {
    /// The call `token` was answered.
    Done { shared: SharedRef, token: u64, outcome: Outcome },
    /// Events for command queue `queue` (0: device-level events) are
    /// pending.
    Ring { conn: u64, queue: u64 },
    /// The executor could not do what a request of the task asked.
    Report(String),
}

/// A connection's shared state, as a note carries it.
#[derive(Debug)]
pub struct SharedRef(Arc<Shared>);

/// Leave `note` for the connection's task and wake its kernel.
fn send(link: &TaskLink, note: Note) {
    link.mailbox.lock().unwrap_or_else(|e| e.into_inner()).push(super::super::ipc::Remote::Accel(note));
    link.bell.ring();
}

/// The executor has events pending for command queue `queue` (0:
/// device-level events) of connection `conn`: ring the queue's doorbell.
/// A connection that is gone has none.
pub fn ring(conn: u64, queue: u64) {
    if let Some(s) = conns(|c| c.get(&conn).cloned()) {
        send(&s.link, Note::Ring { conn, queue });
    }
}

/// The executor could not do what a request of connection `conn` asked
/// (something it does not implement, or a capability the host lacks): its
/// task reports it as the kernel reports what it does not implement.
pub fn report(conn: u64, what: String) {
    if let Some(s) = conns(|c| c.get(&conn).cloned()) {
        send(&s.link, Note::Report(what));
    }
}

/// The connection's state: its number and what it shares with the
/// executor's answers; none when it could not be set up (reported at its
/// first call).
pub struct Wire {
    shared: Result<Arc<Shared>, String>,
}

impl Wire {
    /// A new connection of the calling task, given to the executor.
    pub fn new(k: &mut Kernel) -> Wire {
        let conn = NEXT_CONN.fetch_add(1, Ordering::Relaxed);
        let Some(memory) = TaskMemory::of(&k.procs, k.pid) else {
            return Wire { shared: Err("a WebMetal connection on a host that shares no process's memory with the kernel".to_string()) };
        };
        let Some(link) = k.ipc().link.clone() else {
            return Wire { shared: Err("a WebMetal connection of a task with no IPC link".to_string()) };
        };
        let shared = Arc::new(Shared { conn, memory: memory.clone(), link, state: Mutex::new(State::default()) });
        conns(|c| c.insert(conn, Arc::clone(&shared)));
        if let Some(h) = host::host() {
            h.open(conn, memory);
        }
        Wire { shared: Ok(shared) }
    }

    /// The connection's number.
    pub fn conn(&self) -> Option<u64> {
        self.shared.as_ref().ok().map(|s| s.conn)
    }

    /// The client's methods.
    pub fn external_method(&mut self, k: &mut Kernel, a: &mut MethodArgs) -> i32 {
        let Some(d) = METHODS.get(a.selector as usize) else { return no_method(a) };
        if let Err(e) = dispatch_check(d, a) {
            return e;
        }
        let asynchronous = a.is_async;
        match (a.selector, asynchronous) {
            (0 | 1, false) => self.call(k, a),
            (2, true) => self.register_event_port(k, a),
            (s, _) => {
                k.darwin_unimplemented(format!("WebMetal selector {s} called {} (the wire protocol defines it {})", if asynchronous { "asynchronously" } else { "synchronously" }, if s == 2 { "asynchronous" } else { "synchronous" }));
                ret::BAD_ARGUMENT
            }
        }
    }

    /// `control` and `fetch_reply`: served now when no control request is
    /// with the executor, else answered in turn.
    fn call(&mut self, k: &mut Kernel, a: &mut MethodArgs) -> i32 {
        let shared = match &self.shared {
            Ok(s) => Arc::clone(s),
            Err(why) => {
                k.darwin_unimplemented(why.clone());
                return ret::UNSUPPORTED;
            }
        };
        // A request in another task's memory: the routine came from a task
        // that is not the connection's (its send right was passed on), and
        // the protocol reads the caller's memory, which this kernel, serving
        // the connection's own task, does not reach.
        if k.dtask.kcaller != 0 {
            k.darwin_unimplemented("a WebMetal call from a task that did not open the connection (the wire protocol reads the caller's memory)".to_string());
            return ret::UNSUPPORTED;
        }
        let token = super::super::mig::later_token();
        let call = match a.selector {
            0 => Call::Control { token, request: (a.scalar_in[0], a.scalar_in[1]), reply: (a.scalar_in[2], a.scalar_in[3]) },
            _ => Call::Fetch { token, reply: (a.scalar_in[0], a.scalar_in[1]) },
        };
        let mut st = shared.state();
        // `IOGPUDeviceUserClient::externalMethod` (the class the connection
        // presents as) answers a client that is stopped with
        // kIOReturnNotReady.
        if st.closed {
            return ret::NOT_READY;
        }
        if !st.calls.is_empty() {
            st.calls.push_back(call);
            a.later = Some(token);
            return ret::SUCCESS;
        }
        match serve(k, &shared, &mut st, call) {
            Served::Now(r, len) => {
                if r == ret::SUCCESS {
                    a.scalar_out[0] = len;
                }
                r
            }
            Served::Later => {
                a.later = Some(token);
                ret::SUCCESS
            }
        }
    }

    /// `register_event_port(queue)`: the async reference kept, to complete
    /// with the queue handle when the executor has events for that queue;
    /// a queue registered again keeps the new port.
    fn register_event_port(&mut self, k: &mut Kernel, a: &mut MethodArgs) -> i32 {
        let shared = match &self.shared {
            Ok(s) => Arc::clone(s),
            Err(why) => {
                k.darwin_unimplemented(why.clone());
                return ret::UNSUPPORTED;
            }
        };
        if shared.state().closed {
            return ret::NOT_READY;
        }
        // A null wake port: no port to send the completion to.
        let Some(wake) = a.wake.take() else {
            k.darwin_unimplemented("WebMetal register_event_port with a null wake port (the wire protocol defines no answer for it)".to_string());
            return ret::BAD_ARGUMENT;
        };
        // is_io_connect_async_method reads the reference as the 8 words of
        // an OSAsyncReference64 from the request, whatever its count: the
        // words past a shorter one are the request's next fields. (The wake
        // port's right goes with the failed request.)
        if a.reference.len() < ASYNC_REF64_COUNT {
            k.darwin_unimplemented(format!("WebMetal register_event_port with an async reference of {} words (the kernel reads the request's next fields as the rest)", a.reference.len()));
            return ret::BAD_ARGUMENT;
        }
        let mut reference = [0u64; ASYNC_REF64_COUNT];
        reference.copy_from_slice(&a.reference[..ASYNC_REF64_COUNT]);
        let queue = a.scalar_in[0];
        let old = {
            let mut st = shared.state();
            let old = st.events.iter().position(|e| e.queue == queue).map(|i| st.events.remove(i));
            st.events.push(EventPort { queue, wake, reference });
            old
        };
        if let Some(old) = old {
            k.ipc().release_send(old.wake);
        }
        ret::SUCCESS
    }

    /// `clientClose`: the async references let go
    /// (`releaseAsyncReference64`), and the executor told; calls still
    /// waiting are answered as a stopped client's.
    pub fn close(&mut self, k: &mut Kernel) {
        let Ok(shared) = &self.shared else { return };
        let events = {
            let mut st = shared.state();
            if st.closed {
                return;
            }
            st.closed = true;
            std::mem::take(&mut st.events)
        };
        for e in events {
            k.ipc().release_send(e.wake);
        }
        conns(|c| c.remove(&shared.conn));
        if let Some(h) = host::host() {
            h.close(shared.conn);
        }
    }
}

/// How a call was served.
enum Served {
    /// Answered: its return code and, on success, the reply length.
    Now(i32, u64),
    /// With the executor, to be answered when it is done.
    Later,
}

/// Serve `call`, the first of the connection's calls: a control request
/// is read from the caller's memory and handed to the executor (it stays
/// first until answered); a fetch is answered from the pending reply.
fn serve(k: &mut Kernel, shared: &Arc<Shared>, st: &mut State, call: Call) -> Served {
    match call {
        Call::Fetch { reply, .. } => {
            let Some(bytes) = st.pending.take() else {
                // No request has left a reply pending.
                k.darwin_unimplemented("WebMetal fetch_reply with no reply pending (the wire protocol defines no answer for it)".to_string());
                return Served::Now(ret::NOT_READY, 0);
            };
            let len = bytes.len() as u64;
            match put_reply(k, shared, reply, &bytes) {
                Ok(true) => Served::Now(ret::SUCCESS, len),
                Ok(false) => {
                    st.pending = Some(bytes);
                    Served::Now(ret::SUCCESS, len)
                }
                Err(r) => {
                    st.pending = Some(bytes);
                    Served::Now(r, 0)
                }
            }
        }
        Call::Control { token, request, reply } => {
            let Some(h) = host::host() else {
                k.darwin_unimplemented(format!("a WebMetal control request ({} bytes): no host executor is attached to run it", request.1));
                return Served::Now(ret::UNSUPPORTED, 0);
            };
            let bytes = match read_request(shared, request) {
                Ok(b) => b,
                Err(why) => {
                    k.darwin_unimplemented(format!("a WebMetal control request the host cannot read ({why}; the wire protocol defines no answer for it)"));
                    return Served::Now(ret::BAD_ARGUMENT, 0);
                }
            };
            // The surfaces the request gives the GPU are the GPU's from
            // now on, with every task's writes to them so far.
            for id in h.surfaces(&bytes) {
                if let Err(why) = super::super::iosurface::bind_gpu(k, id) {
                    k.darwin_unimplemented(why);
                }
            }
            st.calls.push_front(Call::Control { token, request, reply });
            let (link, sref) = (Arc::clone(&shared.link), Arc::clone(shared));
            h.control(shared.conn, bytes, Done::new(move |outcome| send(&link, Note::Done { shared: SharedRef(sref), token, outcome })));
            Served::Later
        }
    }
}

/// The request at `(addr, len)` in the caller's memory: at least a record
/// header, every byte readable.
fn read_request(shared: &Shared, (addr, len): (u64, u64)) -> Result<Vec<u8>, String> {
    if len < HEADER {
        return Err(format!("{len} bytes at {addr:#x}, shorter than a record header"));
    }
    // Every page is checked before anything is allocated for it.
    let mut header = [0u8; HEADER as usize];
    shared.memory.read(addr, &mut header).map_err(|f| describe(f, addr, len))?;
    let n = usize::try_from(len).map_err(|_| format!("{len} bytes at {addr:#x}"))?;
    let mut bytes = vec![0u8; n];
    shared.memory.read(addr, &mut bytes).map_err(|f| describe(f, addr, len))?;
    Ok(bytes)
}

fn describe(f: Fault, addr: u64, len: u64) -> String {
    let what = match f.kind {
        FaultKind::Unmapped => "unmapped",
        FaultKind::Protection => "not permitted",
        FaultKind::Gone => "in a task that is gone",
        FaultKind::Code => "in an executable mapping",
    };
    format!("{len} bytes at {addr:#x}: {:#x} {what}", f.addr)
}

/// Write the reply `bytes` to the caller's buffer `(addr, capacity)` when
/// it fits: whether it was written. A buffer that cannot be written is
/// reported (the protocol defines no answer for it) and refused.
fn put_reply(k: &mut Kernel, shared: &Shared, (addr, capacity): (u64, u64), bytes: &[u8]) -> Result<bool, i32> {
    if bytes.len() as u64 > capacity {
        return Ok(false);
    }
    match shared.memory.write(addr, bytes) {
        Ok(()) => Ok(true),
        Err(f) => {
            k.darwin_unimplemented(format!("a WebMetal reply buffer the host cannot write ({}; the wire protocol defines no answer for it)", describe(f, addr, capacity)));
            Err(ret::BAD_ARGUMENT)
        }
    }
}

impl Kernel {
    /// What the executor left for this task: a call answered (its reply
    /// written and the caller's routine answered, then the connection's
    /// next call served), a doorbell to ring, or a report.
    pub(crate) fn darwin_accel_note(&mut self, m: &mut GuestMem<'_>, note: Note) {
        match note {
            Note::Report(what) => self.darwin_unimplemented(what),
            Note::Ring { conn, queue } => {
                let Some(shared) = conns(|c| c.get(&conn).cloned()) else { return };
                let st = shared.state();
                if let Some(e) = st.events.iter().find(|e| e.queue == queue) {
                    let (wake, reference) = (e.wake, e.reference);
                    drop(st);
                    self.darwin_io_async_result(wake, &reference, ret::SUCCESS, &[queue], false);
                    self.darwin_ipc_settle(m);
                }
            }
            Note::Done { shared, token, outcome } => self.darwin_accel_done(m, &shared.0, token, outcome),
        }
    }

    /// Control request `token` of `shared` answered with `outcome`.
    fn darwin_accel_done(&mut self, m: &mut GuestMem<'_>, shared: &Arc<Shared>, token: u64, outcome: Outcome) {
        let mut st = shared.state();
        let Some(Call::Control { reply, .. }) = st.calls.front() else { return };
        if st.calls.front().map(Call::token) != Some(token) {
            return;
        }
        let reply = *reply;
        st.calls.pop_front();
        let answer = match outcome {
            Outcome::Reply(bytes) => {
                let len = bytes.len() as u64;
                st.pending = None;
                match put_reply(self, shared, reply, &bytes) {
                    Ok(true) => (ret::SUCCESS, len),
                    Ok(false) => {
                        st.pending = Some(bytes);
                        (ret::SUCCESS, len)
                    }
                    Err(r) => {
                        st.pending = Some(bytes);
                        (r, 0)
                    }
                }
            }
            Outcome::Refused(why) => {
                self.darwin_unimplemented(format!("a WebMetal control request the host executor refused: {why}"));
                (ret::UNSUPPORTED, 0)
            }
        };
        self.darwin_accel_answer(m, token, answer);
        // The calls that waited, in turn, until one is with the executor.
        while let Some(next) = st.calls.pop_front() {
            let token = next.token();
            if st.closed {
                self.darwin_accel_answer(m, token, (ret::NOT_READY, 0));
                continue;
            }
            match serve(self, shared, &mut st, next) {
                Served::Now(r, len) => self.darwin_accel_answer(m, token, (r, len)),
                Served::Later => break,
            }
        }
    }

    /// Answer deferred call `token` with its return code and reply length.
    fn darwin_accel_answer(&mut self, m: &mut GuestMem<'_>, token: u64, (r, len): (i32, u64)) {
        let Some(reply) = super::super::mig::later_reply(token, r, &[len]) else { return };
        self.darwin_answer_later(m, token, reply);
    }
}
