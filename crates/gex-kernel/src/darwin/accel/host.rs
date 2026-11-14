//! The host executor behind the WebMetal connections: what the kernel
//! hands it and how it answers. The embedder installs it ([`install`]); a
//! connection made before one is installed has no executor to run its
//! requests.
//!
//! The executor runs on a host thread of its own. The kernel gives it each
//! connection with its task's memory ([`TaskMemory`]), each control request
//! read from the caller's memory with what to call when it is answered
//! ([`Done`]), and each connection's end. In the other direction it rings a
//! connection's event doorbells ([`super::wire::ring`]) and reports what it
//! could not do ([`super::wire::report`]); both reach the connection's task
//! through its kernel, which acts on them as the task's own (its mailbox,
//! [`super::super::ipc::Remote`]).

use std::sync::{Arc, OnceLock};

use crate::mem::prot;
use crate::proc::{PeerVm, ProcTable};

/// Why an access to a task's memory failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultKind {
    /// No mapping holds the address.
    Unmapped,
    /// The mapping does not allow the access.
    Protection,
    /// The task is gone (it exited, or its `execve` replaced its address
    /// space).
    Gone,
    /// A write into an executable mapping: the kernel's own copies into
    /// one retire what was translated of it, which a copy from the
    /// executor's thread has nothing to do with (reported).
    Code,
}

/// A failed access: the first address that could not be reached, and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault {
    pub addr: u64,
    pub kind: FaultKind,
}

/// A connection's task as the executor reaches its memory: the address
/// space the task had when it opened the connection. Each access is
/// checked against the task's mappings as a driver's `IOMemoryDescriptor`
/// over the task's range would be when prepared: every page mapped, and
/// readable for a read, writable for a write.
#[derive(Clone)]
pub struct TaskMemory {
    procs: Arc<ProcTable>,
    pid: i32,
    vm: Arc<PeerVm>,
}

impl std::fmt::Debug for TaskMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TaskMemory(pid {})", self.pid)
    }
}

impl TaskMemory {
    /// The memory of process `pid`, as the process table publishes it;
    /// none on a host that shares no process's memory with the kernel.
    pub fn of(procs: &Arc<ProcTable>, pid: i32) -> Option<TaskMemory> {
        let vm = procs.vm(pid).ok()?;
        Some(TaskMemory { procs: Arc::clone(procs), pid, vm })
    }

    /// The task's process id.
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// The address space, while it is still the task's.
    fn live(&self) -> Result<&PeerVm, Fault> {
        match self.procs.vm(self.pid) {
            Ok(now) if Arc::ptr_eq(&now, &self.vm) => Ok(&self.vm),
            _ => Err(Fault { addr: 0, kind: FaultKind::Gone }),
        }
    }

    /// Check `[addr, addr + len)` against the task's mappings for `need`.
    fn check(&self, vm: &PeerVm, addr: u64, len: u64, need: u32) -> Result<(), Fault> {
        if len == 0 {
            return Ok(());
        }
        let end = addr.checked_add(len).ok_or(Fault { addr, kind: FaultKind::Unmapped })?;
        let mm = vm.mm.lock();
        let mut at = addr;
        while at < end {
            let Some(v) = mm.vma_at(at) else { return Err(Fault { addr: at, kind: FaultKind::Unmapped }) };
            if v.prot & need != need {
                return Err(Fault { addr: at, kind: FaultKind::Protection });
            }
            if need & prot::WRITE != 0 && v.prot & prot::EXEC != 0 {
                return Err(Fault { addr: at, kind: FaultKind::Code });
            }
            at = v.end;
        }
        Ok(())
    }

    /// Copy `dst.len()` bytes at `addr` into `dst`.
    pub fn read(&self, addr: u64, dst: &mut [u8]) -> Result<(), Fault> {
        let vm = self.live()?;
        self.check(vm, addr, dst.len() as u64, prot::READ)?;
        if !vm.mem.read(addr, dst) {
            return Err(Fault { addr, kind: FaultKind::Unmapped });
        }
        Ok(())
    }

    /// Copy `src` to `addr`.
    pub fn write(&self, addr: u64, src: &[u8]) -> Result<(), Fault> {
        let vm = self.live()?;
        self.check(vm, addr, src.len() as u64, prot::WRITE)?;
        if !vm.mem.write(addr, src) {
            return Err(Fault { addr, kind: FaultKind::Unmapped });
        }
        Ok(())
    }
}

/// A control request's outcome.
#[derive(Debug)]
pub enum Outcome {
    /// The reply record.
    Reply(Vec<u8>),
    /// No reply record: the bytes are not a control request the executor
    /// can read, or the executor cannot run (why).
    Refused(String),
}

/// What to call when a control request is answered: once, from any
/// thread. One dropped unanswered (its executor gone) answers that the
/// request was refused, so that no caller waits for ever.
pub struct Done(Option<Box<dyn FnOnce(Outcome) + Send>>);

impl Done {
    pub(crate) fn new(f: impl FnOnce(Outcome) + Send + 'static) -> Done {
        Done(Some(Box::new(f)))
    }

    /// Answer the request.
    pub fn answer(mut self, outcome: Outcome) {
        if let Some(f) = self.0.take() {
            f(outcome)
        }
    }
}

impl Drop for Done {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f(Outcome::Refused("the host executor dropped the request unanswered".to_string()))
        }
    }
}

impl std::fmt::Debug for Done {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Done")
    }
}

/// The host executor.
pub trait Host: Send + Sync {
    /// Connection `conn` (a number no other connection has had) was opened
    /// by the task whose memory is `memory`.
    fn open(&self, conn: u64, memory: TaskMemory);

    /// The IOSurfaces `request` hands to the GPU (by their ids), which the
    /// kernel binds to the GPU before the request runs
    /// ([`crate::darwin::iosurface::bind_gpu`]).
    fn surfaces(&self, request: &[u8]) -> Vec<u32>;

    /// Run one control request of `conn`; `done` is called once with its
    /// outcome. The connection's requests come one at a time.
    fn control(&self, conn: u64, request: Vec<u8>, done: Done);

    /// The connection was closed: its objects are gone, and requests of it
    /// that have not been answered need not be.
    fn close(&self, conn: u64);
}

static HOST: OnceLock<Box<dyn Host>> = OnceLock::new();

/// Install the embedder's executor, once.
pub fn install(h: Box<dyn Host>) -> Result<(), Box<dyn Host>> {
    HOST.set(h)
}

/// The executor, if an embedder installed one.
pub fn host() -> Option<&'static dyn Host> {
    HOST.get().map(|b| b.as_ref())
}
