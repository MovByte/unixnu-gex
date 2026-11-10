//! POSIX semaphores (`bsd/kern/posix_sem.c`, xnu-10063.141.1).
//!
//! The names live in one table for the host process, as shared memory's
//! do. Each is a counting semaphore with FIFO wakeups, as the Mach
//! semaphore `semaphore_create(SYNC_POLICY_FIFO)` makes for it, and each
//! open is a descriptor (`DTYPE_PSXSEM`). A waiter in another process is
//! woken as an advisory lock's is: its thread on its process's list, and
//! its bell rung.

use super::lockf::Waker;
use super::sysno as sys;
use super::wait::{Wait, WaitResult};
use crate::errno::{Errno, SysResult};
use crate::file::OpenFile;
use crate::syscalls::{Kernel, SyscallOutcome};
use crate::vfs::{FileHandle, Metadata};
use crate::GuestMem;
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

/// `PSEMNAMLEN`: the name with its NUL is at most this long.
pub const PSEMNAMLEN: usize = 31;
/// `SEM_VALUE_MAX`.
const SEM_VALUE_MAX: u64 = 32767;
/// `MAXPATHLEN`, what `copyinstr` takes the name into.
const MAXPATHLEN: usize = 1024;
const FREAD: u32 = 1;
const FWRITE: u32 = 2;
const O_CREAT: u32 = 0x200;
const O_EXCL: u32 = 0x800;
const ALLPERMS: u32 = 0o7777;

/// A waiter's state: still waiting, handed the wakeup, or gone (a signal
/// took it out first).
const WAITING: u8 = 0;
const HANDED: u8 = 1;
const GONE: u8 = 2;

struct Waiter {
    waker: Waker,
    state: Arc<AtomicU8>,
}

#[derive(Default)]
struct Inner {
    count: u64,
    waiters: VecDeque<Waiter>,
    /// `psem_usecount`: the name's reference and each open's.
    usecount: u32,
    /// `PSEM_REMOVED`: unlinked while still open.
    removed: bool,
}

/// A semaphore (`struct pseminfo`).
pub struct Psem {
    pub name: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// `psem_creator_pid`.
    pub creator: i32,
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for Psem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Psem").field("name", &self.name).field("mode", &self.mode).finish_non_exhaustive()
    }
}

impl Psem {
    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `semaphore_signal`: the first waiter still waiting is handed the
    /// wakeup; with none, the count goes up.
    fn signal(&self) {
        let mut i = self.inner();
        while let Some(w) = i.waiters.pop_front() {
            if w.state.compare_exchange(WAITING, HANDED, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                w.waker.inbox.lock().unwrap_or_else(|e| e.into_inner()).push(w.waker.tid);
                w.waker.bell.ring();
                return;
            }
        }
        i.count += 1;
    }
}

/// The host process's names (`psemhashtbl`).
static NAMES: Mutex<BTreeMap<String, Arc<Psem>>> = Mutex::new(BTreeMap::new());

fn names() -> std::sync::MutexGuard<'static, BTreeMap<String, Arc<Psem>>> {
    NAMES.lock().unwrap_or_else(|e| e.into_inner())
}

/// An open of a semaphore (`struct psemnode`), which `psem_close` lets go
/// of when its last descriptor closes.
#[derive(Debug)]
pub struct PsemHandle(pub Arc<Psem>);

impl Drop for PsemHandle {
    fn drop(&mut self) {
        // psem_close: with the name gone and no open left, it is deleted,
        // which is the last reference going.
        let _names = names();
        self.0.inner().usecount -= 1;
    }
}

impl FileHandle for PsemHandle {
    fn as_posix_sem(self: Arc<Self>) -> Option<Arc<Psem>> {
        Some(Arc::clone(&self.0))
    }

    /// `fo_no_read` and `fo_no_write`.
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> SysResult {
        Err(Errno::ENXIO)
    }

    fn write_at(&self, _offset: u64, _buf: &[u8]) -> SysResult {
        Err(Errno::ENXIO)
    }

    /// `fstat1` has no case for it.
    fn metadata(&self) -> Result<Metadata, Errno> {
        Err(Errno::EBADF)
    }
}

/// A semaphore wait in progress: the thread's entry in
/// [`super::DTask::psem_waits`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cont;

/// What a waiting thread waits on, and its place in the queue.
pub type Waiting = (Arc<Psem>, Arc<AtomicU8>);

impl Kernel {
    /// The name, as `copyinstr` into MAXPATHLEN gives it, no longer than
    /// PSEMNAMLEN with its NUL.
    fn darwin_psem_name(&self, m: &GuestMem<'_>, at: u64) -> Result<String, Errno> {
        let mut buf = vec![0u8; MAXPATHLEN];
        let n = m.read_cstr_into(at, &mut buf)?.ok_or(Errno::ENAMETOOLONG)?;
        if n + 1 > PSEMNAMLEN {
            return Err(Errno::ENAMETOOLONG);
        }
        Ok(buf[..n].iter().map(|&b| char::from(b)).collect())
    }

    /// The Sandbox's answer for an operation on a semaphore of this name.
    fn darwin_psem_mac(&mut self, op: &str, name: &str) -> Result<(), Errno> {
        let op = super::mac::OPERATION_NAMES.iter().position(|n| *n == op).expect("a Sandbox operation");
        let a = super::mac::SbArgs { kind: super::sandbox::kind::POSIX_IPC, string: Some(name.chars().map(|c| c as u8).collect()), ..Default::default() };
        match self.darwin_sb_evaluate(op, &a) {
            0 => Ok(()),
            e => Err(super::errno::errno_of(e as i32)),
        }
    }

    /// `psem_access`: root may; anyone else as `posix_cred_access` says.
    fn darwin_psem_access(&self, p: &Psem, fmode: u32) -> Result<(), Errno> {
        let cred = &self.dtask.cred;
        if cred.uid == 0 {
            return Ok(());
        }
        let req = (if fmode & FREAD != 0 { 0o400 } else { 0 }) | (if fmode & FWRITE != 0 { 0o200 } else { 0 });
        super::cred::posix_cred_access(cred, p.uid, p.gid, p.mode, req)
    }

    /// `sem_open(name, oflag, mode, value)`: a descriptor's number.
    fn darwin_sem_open(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        let name = self.darwin_psem_name(m, a[0])?;
        // falloc's refusal comes before the rest.
        if self.fds.list().len() >= self.fds.limit() {
            return Err(Errno::EMFILE);
        }
        let mut fmode = (a[1] as u32).wrapping_add(1);
        let (cmode, value) = (a[2] as u32 & ALLPERMS, a[3] as u32 as u64);
        if fmode & O_CREAT != 0 && value > SEM_VALUE_MAX {
            return Err(Errno::EINVAL);
        }
        let found = names().get(&name).cloned();
        if fmode & (O_CREAT | O_EXCL) == O_CREAT | O_EXCL && found.is_some() {
            return Err(Errno::EEXIST);
        }
        if fmode & (O_CREAT | O_EXCL) == O_CREAT && found.is_some() {
            fmode &= !O_CREAT;
        }
        let p = if fmode & O_CREAT != 0 {
            self.darwin_psem_mac("ipc-posix-sem-create", &name)?;
            let cred = &self.dtask.cred;
            let p = Arc::new(Psem {
                name: name.clone(),
                mode: cmode,
                uid: cred.uid,
                gid: cred.groups.first().copied().unwrap_or(0),
                creator: self.pid,
                inner: Mutex::new(Inner { count: value, usecount: 1, ..Inner::default() }),
            });
            let mut n = names();
            // Another process's create between the look and now is the
            // name it finds.
            match n.get(&name) {
                Some(_) if fmode & O_EXCL != 0 => return Err(Errno::EEXIST),
                Some(other) => Arc::clone(other),
                None => {
                    n.insert(name.clone(), Arc::clone(&p));
                    p
                }
            }
        } else {
            let p = found.ok_or(Errno::ENOENT)?;
            self.darwin_psem_mac("ipc-posix-sem-open", &name)?;
            self.darwin_psem_access(&p, fmode)?;
            p
        };
        {
            let _n = names();
            p.inner().usecount += 1;
        }
        let handle: Arc<dyn FileHandle> = Arc::new(PsemHandle(p));
        let file = OpenFile::new(handle, format!("/psem:{name}"), 0, fmode & FREAD != 0, fmode & FWRITE != 0);
        self.fds.insert(file, false).map(|fd| fd as u64)
    }

    /// `sem_unlink(name)`: the name goes; the semaphore lives while open.
    fn darwin_sem_unlink(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        let name = self.darwin_psem_name(m, a[0])?;
        let p = names().get(&name).cloned().ok_or(Errno::ENOENT)?;
        self.darwin_psem_mac("ipc-posix-sem-unlink", &name)?;
        // psem_access with the semaphore's own mode as the open mode.
        self.darwin_psem_access(&p, p.mode)?;
        let mut n = names();
        if n.get(&name).is_some_and(|q| Arc::ptr_eq(q, &p)) {
            n.remove(&name);
            let mut i = p.inner();
            i.usecount -= 1;
            i.removed = i.usecount != 0;
        }
        Ok(0)
    }

    /// The semaphore a descriptor is (`fp_get_ftype(DTYPE_PSXSEM)`).
    fn darwin_psem_of(&self, fd: u64) -> Result<Arc<Psem>, Errno> {
        let f = self.fds.get(fd as i32)?;
        Arc::clone(&f.handle).as_posix_sem().ok_or(Errno::EBADF)
    }

    /// `sem_close(sem)`.
    fn darwin_sem_close(&mut self, a: &[u64; 6]) -> Result<u64, Errno> {
        self.darwin_psem_of(a[0])?;
        self.fds.close(a[0] as i32).map(|_| 0)
    }

    /// `sem_trywait(sem)`: `semaphore_timedwait` of no time.
    fn darwin_sem_trywait(&mut self, a: &[u64; 6]) -> Result<u64, Errno> {
        let p = self.darwin_psem_of(a[0])?;
        self.darwin_psem_mac("ipc-posix-sem-wait", &p.name)?;
        let mut i = p.inner();
        if i.count == 0 {
            return Err(Errno::EAGAIN);
        }
        i.count -= 1;
        Ok(0)
    }

    /// `sem_post(sem)`.
    fn darwin_sem_post(&mut self, a: &[u64; 6]) -> Result<u64, Errno> {
        let p = self.darwin_psem_of(a[0])?;
        self.darwin_psem_mac("ipc-posix-sem-post", &p.name)?;
        p.signal();
        Ok(0)
    }

    /// The calls that answer at once.
    pub(crate) fn darwin_psem_call(&mut self, m: &mut GuestMem<'_>, raw: u64, a: &[u64; 6]) -> Option<Result<u64, Errno>> {
        Some(match raw {
            sys::SEM_OPEN => self.darwin_sem_open(m, a),
            sys::SEM_UNLINK => self.darwin_sem_unlink(m, a),
            sys::SEM_CLOSE => self.darwin_sem_close(a),
            sys::SEM_TRYWAIT => self.darwin_sem_trywait(a),
            sys::SEM_POST => self.darwin_sem_post(a),
            _ => return None,
        })
    }

    /// `sem_wait(sem)` and `sem_wait_nocancel`: `semaphore_wait`, which a
    /// signal ends (KERN_ABORTED, EINTR).
    pub(crate) fn darwin_sem_wait(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> SyscallOutcome {
        let r = self.darwin_psem_of(a[0]).and_then(|p| self.darwin_psem_mac("ipc-posix-sem-wait", &p.name).map(|()| p));
        let p = match r {
            Ok(p) => p,
            Err(e) => {
                super::thread::bsd_result(m, self.ctx_addr, Err(e), false);
                return SyscallOutcome::Continue;
            }
        };
        let state = Arc::new(AtomicU8::new(WAITING));
        {
            let mut i = p.inner();
            if i.count > 0 {
                i.count -= 1;
                drop(i);
                super::thread::bsd_result(m, self.ctx_addr, Ok(0), false);
                return SyscallOutcome::Continue;
            }
            i.waiters.push_back(Waiter { waker: self.darwin_waker(), state: Arc::clone(&state) });
        }
        self.dtask.psem_waits.insert(self.tid, (p, state));
        self.darwin_block(m, Wait { deadline: None, cont: super::thread::Finish::Psem(Cont) })
    }

    /// A wait's end: handed the wakeup, or taken out by a signal, unless the
    /// wakeup came first.
    pub(crate) fn darwin_psem_wait_done(&mut self, m: &mut GuestMem<'_>, c: Cont, res: WaitResult) -> Option<SyscallOutcome> {
        let (psem, state) = self.dtask.psem_waits.remove(&self.tid).expect("a semaphore wait");
        let r = match res {
            WaitResult::Awakened if state.load(Ordering::Acquire) == HANDED => Ok(0),
            // Woken for something else: still waiting.
            WaitResult::Awakened => {
                self.dtask.psem_waits.insert(self.tid, (psem, state));
                return Some(self.darwin_block(m, Wait { deadline: None, cont: super::thread::Finish::Psem(c) }));
            }
            _ => {
                if state.compare_exchange(WAITING, GONE, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                    psem.inner().waiters.retain(|w| !Arc::ptr_eq(&w.state, &state));
                    Err(Errno::EINTR)
                } else {
                    Ok(0)
                }
            }
        };
        super::thread::bsd_result(m, self.ctx_addr, r, false);
        None
    }
}
