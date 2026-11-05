//! Process notes: what XNU's `proc_knote` posts to a process's knotes
//! (`p_klist`): its exit with the status, its reap, a fork with the child,
//! an exec, a signal posted to it. Said where the process table and the
//! Darwin kernel make the change, for a Darwin process's EVFILT_PROC knotes
//! on the process, which may be in any process.
//!
//! Hints are XNU's: `NOTE_*` in the top bits, the data (a pid, a signal, a
//! wait status) in `NOTE_PDATAMASK`, with Darwin's numbers.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// `NOTE_*` for EVFILT_PROC (`bsd/sys/event.h`).
pub mod note {
    pub const EXIT: u32 = 0x8000_0000;
    pub const FORK: u32 = 0x4000_0000;
    pub const EXEC: u32 = 0x2000_0000;
    pub const REAP: u32 = 0x1000_0000;
    pub const SIGNAL: u32 = 0x0800_0000;
    pub const EXITSTATUS: u32 = 0x0400_0000;
    pub const EXIT_DETAIL: u32 = 0x0200_0000;
    pub const PDATAMASK: u32 = 0x000f_ffff;
    pub const TRACK: u32 = 0x1;
    pub const TRACKERR: u32 = 0x2;
    pub const CHILD: u32 = 0x4;
}

/// Who hears a process's notes.
pub type Listener = Arc<dyn Fn(u32) + Send + Sync>;

#[derive(Default)]
struct Registry {
    by_pid: HashMap<i32, Vec<(u64, Listener)>>,
    pids: HashMap<u64, i32>,
    next: u64,
}

static LISTENERS: AtomicUsize = AtomicUsize::new(0);

fn registry() -> std::sync::MutexGuard<'static, Registry> {
    static R: OnceLock<Mutex<Registry>> = OnceLock::new();
    R.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner())
}

/// Whether anyone listens.
#[inline]
pub fn any() -> bool {
    LISTENERS.load(Ordering::Relaxed) != 0
}

/// Hear `pid`'s notes; the id to stop with.
pub fn listen(pid: i32, f: Listener) -> u64 {
    let mut r = registry();
    r.next += 1;
    let id = r.next;
    r.by_pid.entry(pid).or_default().push((id, f));
    r.pids.insert(id, pid);
    LISTENERS.fetch_add(1, Ordering::Relaxed);
    id
}

pub fn unlisten(id: u64) {
    let mut r = registry();
    if let Some(pid) = r.pids.remove(&id) {
        if let Some(v) = r.by_pid.get_mut(&pid) {
            v.retain(|(i, _)| *i != id);
            if v.is_empty() {
                r.by_pid.remove(&pid);
            }
        }
        LISTENERS.fetch_sub(1, Ordering::Relaxed);
    }
}

/// `proc_knote(pid, hint)`.
pub fn post(pid: i32, hint: u32) {
    if !any() {
        return;
    }
    let who: Vec<Listener> = registry().by_pid.get(&pid).map(|v| v.iter().map(|(_, f)| Arc::clone(f)).collect()).unwrap_or_default();
    for f in who {
        f(hint);
    }
}
