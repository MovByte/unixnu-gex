//! The process table: pids, parents, process groups and sessions.
//!
//! Shared across every process, because three things cannot be answered from
//! inside a single process: pids must be unique system-wide (a per-kernel
//! counter offset by a thousand collides for a long-lived init); orphans must
//! be reparented to pid 1 and reaped there; and groups and sessions span
//! processes by definition (`kill(-pgid)`).
//!
//! Not modelled: controlling terminals, orphaned-process-group handling, and
//! session keyrings. A guest that asks gets plausible answers, not Linux's.

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};

/// The signal a parent is owed when a child ends.
const SIGCHLD: u32 = crate::signal::sig::SIGCHLD;
const SIGKILL: u32 = crate::signal::sig::SIGKILL;
const SIGHUP: u32 = crate::signal::sig::SIGHUP;
const SIGCONT: u32 = crate::signal::sig::SIGCONT;
use std::sync::{Arc, Mutex};

use crate::errno::Errno;
use crate::syscalls::{Child, ChildHandle};

/// The pid the kernel gives the first process, and the one orphans go to.
pub const INIT_PID: i32 = 1;

/// The process table when it is not in this process's memory.
///
/// Between the *threads* of one process the table above is shared directly.
/// Between processes it lives elsewhere: a second wasm module every Worker
/// instantiates against one `SharedArrayBuffer`, so its `Vec<Proc>` is the same
/// bytes for all of them. A process reaches it through calls, not pointers -- so
/// this is the call surface, plain function pointers a host fills in, every
/// argument a scalar because an `Arc` is an address in a memory the other side
/// cannot read. `None` is the single-process default.
#[derive(Clone, Copy)]
pub struct Remote {
    pub spawn: extern "C" fn(ppid: i32) -> i32,
    pub exit: extern "C" fn(pid: i32, status: i32),
    pub reap: extern "C" fn(pid: i32),
    /// Collect a finished child: pid in the high 32 bits, wait status in the low
    /// 32, or zero if none. Packed into one return because two Workers may
    /// collect at once and a status left between calls belongs to whoever asked
    /// last. `nowait` non-zero (`waitid`'s `WNOWAIT`) reports the child and
    /// leaves it to be collected.
    pub wait: extern "C" fn(ppid: i32, want: i32, nowait: i32) -> i64,
    pub has_children: extern "C" fn(ppid: i32) -> i32,
    pub kill: extern "C" fn(caller: i32, target: i32, signo: u32) -> i32,
    /// Signal every process in a group, naming it *positively*.
    ///
    /// `kill(-pgid)` cannot: a target of -1 is POSIX's "everyone", so group 1
    /// has no negative spelling -- and the demos run a shell as pid 1, so `^C`
    /// to the foreground group is exactly this case.
    pub kill_group: extern "C" fn(caller: i32, pgid: i32, signo: u32) -> i32,
    pub take_signals: extern "C" fn(pid: i32) -> u64,
    /// Of `taken`, the signals `kill` sent (see [`ProcTable::take_kill_senders`]).
    pub take_kill_signals: extern "C" fn(pid: i32, taken: u64) -> u64,
    pub kill_sender: extern "C" fn(pid: i32, signo: u32) -> i32,
    pub has_signals: extern "C" fn(pid: i32) -> i32,
    /// `tgkill` to a thread of another process (see [`ProcTable::tkill`]).
    pub tkill: extern "C" fn(caller: i32, pid: i32, tid: i32, signo: u32) -> i32,
    /// One thread-directed signal for `pid`, packed as
    /// [`ProcTable::take_thread_signals`] unpacks it, or zero if none.
    pub take_thread_signal: extern "C" fn(pid: i32, tid: i32) -> i64,
    pub ppid: extern "C" fn(pid: i32) -> i32,
    pub pgid: extern "C" fn(caller: i32, of: i32) -> i32,
    pub sid: extern "C" fn(caller: i32, of: i32) -> i32,
    pub setsid: extern "C" fn(pid: i32) -> i32,
    pub setpgid: extern "C" fn(caller: i32, target: i32, pgid: i32) -> i32,
    /// Would a `wait4` answer now? See [`ProcTable::wait_ready`].
    pub wait_ready: extern "C" fn(ppid: i32, want: i32) -> i32,
    pub request_halt: extern "C" fn(code: i32),
    pub halt_code: extern "C" fn() -> i32,
    /// The process's wait queue. See [`ProcTable::queue`].
    pub queue: extern "C" fn(pid: i32) -> u32,
    /// What `/proc/<pid>` says about a process: see [`ProcTable::set_info`].
    pub set_info: extern "C" fn(pid: i32, at: crate::PAddr, len: u32),
    /// Every process, encoded by [`encode_entries`], into `cap` bytes at `at`;
    /// returns the full length (larger than `cap`: ask again with more room).
    pub snapshot: extern "C" fn(at: crate::PAddr, cap: u32) -> i32,
    /// A new thread of `pid`, numbered with the processes: see
    /// [`ProcTable::new_tid`].
    pub new_tid: extern "C" fn(pid: i32) -> i32,
    /// See [`ProcTable::end_tid`].
    pub end_tid: extern "C" fn(tid: i32),
    /// See [`ProcTable::task_owner`]; zero for no such task.
    pub task_owner: extern "C" fn(id: i32) -> i32,
}

/// One process as another process's `/proc` sees it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcEntry {
    pub pid: i32,
    pub ppid: i32,
    pub pgid: i32,
    pub sid: i32,
    /// Exited and not yet collected by its parent.
    pub zombie: bool,
    /// What the process published: its name, a newline, then its command
    /// line (NUL-separated arguments). Empty until it has said.
    pub info: Vec<u8>,
    /// Its threads besides the first (whose id is the pid), in order.
    pub tids: Vec<i32>,
}

impl ProcEntry {
    /// The name `/proc/<pid>/comm` and `stat` give (at most 15 bytes).
    pub fn comm(&self) -> String {
        let end = self.info.iter().position(|&b| b == b'\n').unwrap_or(self.info.len());
        let name = String::from_utf8_lossy(&self.info[..end]).into_owned();
        if name.is_empty() {
            return "gex".into();
        }
        name.chars().take(15).collect()
    }
    /// Every task of the process: the first thread, then the others.
    pub fn tasks(&self) -> Vec<i32> {
        std::iter::once(self.pid).chain(self.tids.iter().copied()).collect()
    }
    /// `/proc/<pid>/cmdline`.
    pub fn cmdline(&self) -> &[u8] {
        match self.info.iter().position(|&b| b == b'\n') {
            Some(i) => &self.info[i + 1..],
            None => &[],
        }
    }
}

/// The wire form of a process list: per entry five `i32`s (pid, ppid, pgid,
/// sid, zombie), the thread count and the info's length, the thread ids, the
/// info, padded to four bytes.
pub fn encode_entries(entries: &[ProcEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    for e in entries {
        for v in [e.pid, e.ppid, e.pgid, e.sid, i32::from(e.zombie), e.tids.len() as i32, e.info.len() as i32] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for t in &e.tids {
            out.extend_from_slice(&t.to_le_bytes());
        }
        out.extend_from_slice(&e.info);
        while out.len() % 4 != 0 {
            out.push(0);
        }
    }
    out
}

pub fn decode_entries(mut b: &[u8]) -> Vec<ProcEntry> {
    let mut out = Vec::new();
    let word = |b: &[u8], i: usize| i32::from_le_bytes([b[i * 4], b[i * 4 + 1], b[i * 4 + 2], b[i * 4 + 3]]);
    while b.len() >= 28 {
        let (t, n) = (word(b, 5).max(0) as usize, word(b, 6).max(0) as usize);
        let at = 28 + 4 * t;
        if b.len() < at + n {
            break;
        }
        out.push(ProcEntry {
            pid: word(b, 0),
            ppid: word(b, 1),
            pgid: word(b, 2),
            sid: word(b, 3),
            zombie: word(b, 4) != 0,
            tids: (0..t).map(|i| word(b, 7 + i)).collect(),
            info: b[at..at + n].to_vec(),
        });
        b = &b[(at + n + 3) & !3..];
    }
    out
}

/// A child's end, as its parent's record holds it (XNU's `proc_exit`), or
/// its stop (`psignal`'s and `issignal`'s `CLD_STOPPED` record).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChildEnd {
    pub pid: i32,
    /// Its wait status, in the table's (Linux's) encoding; for a stop, the
    /// `si_status` XNU records, in Darwin's.
    pub status: i32,
    pub uid: u32,
    pub xhighbits: u8,
    pub stopped: bool,
}

/// A Darwin process's job control state, beside its exit status.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Job {
    /// `p_stat == SSTOP`.
    pub stopped: bool,
    /// `p_xstat`: the Darwin signal that stopped it, or SIGCONT once a
    /// default SIGCONT continued it.
    pub xstat: u32,
    /// `P_LWAITED`: a wait has reported the stop.
    pub waited: bool,
    /// `P_CONTINUED`, and `p_contproc`.
    pub continued: bool,
    pub contproc: i32,
    /// The task's `user_stop_count`: its threads are held while it is not
    /// zero (`task_suspend_internal`, `task_resume_internal`).
    pub holds: u32,
    /// The task's `legacy_stop_count`: task_suspend's holds among them.
    pub legacy: u32,
}

/// One process, as the table sees it.
struct Proc {
    pid: i32,
    ppid: i32,
    /// Process group. A group leader has `pgid == pid`.
    pgid: i32,
    /// Session. A session leader has `sid == pid`.
    sid: i32,
    /// The exit-status cell a `wait4` collects. The root process has one too,
    /// so nothing has to special-case it, even though nobody waits on it.
    child: Child,
    /// Signals sent to this process by another, as a bitmask of `1 << (signo-1)`.
    ///
    /// The sender can't deliver -- the target's signal state is behind its own
    /// lock and it may be running or blocked -- so it leaves the bit here and the
    /// target picks it up at its next syscall, as Linux delivers at a point the
    /// target chooses.
    pending: Arc<AtomicU64>,
    /// The part of `pending` that `kill` sent, which the target reports as
    /// `SI_USER` (the rest -- `SIGCHLD`, a terminal's `^C` -- the kernel
    /// raised), and the pid that sent each. Under the table's lock.
    killed: u64,
    senders: [i32; 64],
    /// Every signal `kill` posted to it, in order and each time (where
    /// `pending` keeps one bit a signal), for a process that asked
    /// ([`ProcTable::record_posts`]): Darwin's knotes count each post.
    /// Under the table's lock.
    posts: Option<Vec<u32>>,
    /// Darwin's `p_xhighbits`, the top byte of the value it exited with,
    /// and the real uid it ended with: for its parent's record of its end.
    xhighbits: u8,
    uid: u32,
    /// Darwin's `p_lflag` termination bits: `P_LTERM_JETSAM` and the
    /// jetsam cause (`P_JETSAM_MASK`), set by a jetsam kill.
    lterm: u32,
    /// The value a Darwin process gave `exit()`, all of it, and its
    /// `p_xstat` once it has ended (`exit1`'s `W_EXITCODE(rval, 0)`, or the
    /// signal that ended it).
    rval: Option<u32>,
    xstat: u32,
    /// Darwin's `P_LEXIT`: its exit has begun (`exit()`, or a jetsam
    /// kill's `exit_with_reason`).
    lexit: bool,
    /// Darwin's `p_persona`'s id: the id it is counted against
    /// (`chgproccnt`) instead of its real uid.
    persona: Option<u32>,
    /// Darwin's `si_pid`, `si_status`, `si_uid` and `p_xhighbits` record of
    /// the last child that ended or stopped, for its SIGCHLD
    /// ([`ProcTable::take_child_end`]).
    child_end: Option<ChildEnd>,
    /// Darwin's `P_EXEC` (it has exec'd since its fork) and `P_NOCLDSTOP`
    /// (its SIGCHLD action has SA_NOCLDSTOP).
    execed: bool,
    nocldstop: bool,
    /// `p_nice`.
    nice: i32,
    /// Signals `tgkill` sent to one thread of this process from another
    /// process: (tid, signo, sender), in the order sent. Thread ids are the
    /// process's own, so the table cannot check one; a thread that is gone
    /// by collection time drops its signal. Under the table's lock.
    to_threads: Vec<(i32, u32, i32)>,
    /// The process's own wait queue (`crate::wait`), on which each of its
    /// threads keeps its wait slot registered for as long as it runs: a
    /// signal for the process, a child's exit or a halt notifies it.
    queue: crate::wait::Queue,
    /// See [`ProcTable::set_info`].
    info: Vec<u8>,
    /// Its address space, for another process's `process_vm_readv` and
    /// `process_vm_writev`: see [`ProcTable::set_vm`]. `None` once it exits.
    vm: Option<Arc<PeerVm>>,
    /// Started by the host as a child of the virtual init, which the host
    /// collects (with `wait` as pid 1) rather than the table at its exit.
    host_child: bool,
    /// A Darwin process's own record (`crate::darwin::procinfo::Public`),
    /// which other processes read until it is reaped.
    darwin: Option<Arc<dyn std::any::Any + Send + Sync>>,
    /// When it became a zombie, in the order processes did (XNU's
    /// `zombproc` list has the latest first); 0 while it lives.
    zseq: u64,
}

/// Another process's memory as a host holds it: bytes at a guest address,
/// copied out or in. `false` when the range is past the memory's end.
pub trait PeerMem: Send + Sync {
    fn read(&self, addr: u64, out: &mut [u8]) -> bool;
    fn write(&self, addr: u64, data: &[u8]) -> bool;
}

/// A process's address space as another process reaches it: its memory map,
/// which says what is mapped and how, and its memory. Replaced whole at an
/// `execve`, so a holder that still has the old one is told by
/// [`ProcTable::vm`] no longer handing it out.
pub struct PeerVm {
    pub mm: crate::mem::Mm,
    pub mem: Arc<dyn PeerMem>,
}

struct Table {
    /// The next task id, a process's or a thread's: one numbering, as
    /// Linux's pids and tids are one, so an id names exactly one task.
    next_pid: i32,
    procs: Vec<Proc>,
    /// The last zombie's [`Proc::zseq`].
    zseq: u64,
    /// Each live thread that is not its process's first, and its process.
    threads: std::collections::HashMap<i32, i32>,
    /// Each process group's `pg_jobc`: how many of its members have a
    /// parent in another group of its session (`fixjobc`).
    jobc: std::collections::HashMap<i32, i32>,
}

impl Table {
    /// `fixjobc(p, pgrp, entering)`: process `pid` entering or leaving group
    /// `pgid` of session `sess`. Its parent qualifies it for its group when
    /// in another group of the session, and it qualifies each child in
    /// another group of the session (a zombie still counts, as
    /// `proc_childrenwalk` walks it); each count that reaches zero on the
    /// way down is a group made orphaned, for `orphanpg`.
    fn fixjobc(&mut self, pid: i32, pgid: i32, sess: i32, entering: bool, orphaned: &mut Vec<i32>) {
        let ppid = self.procs.iter().find(|p| p.pid == pid).map(|p| p.ppid);
        let parent = ppid.and_then(|pp| self.procs.iter().find(|p| p.pid == pp)).map(|p| (p.pgid, p.sid));
        let mut qualified = Vec::new();
        if let Some((hispg, hissess)) = parent {
            if hispg != pgid && hissess == sess {
                qualified.push(pgid);
            }
        }
        for c in self.procs.iter().filter(|c| c.ppid == pid && c.pid != pid) {
            if c.pgid != pgid && c.sid == sess {
                qualified.push(c.pgid);
            }
        }
        for g in qualified {
            let n = self.jobc.entry(g).or_insert(0);
            if entering {
                *n += 1;
            } else {
                *n -= 1;
                if *n == 0 {
                    orphaned.push(g);
                }
            }
        }
    }

    /// `enterpgrp(p, pgid, mksess)` after its checks: a group that does not
    /// exist is made (in a new session for `setsid`), with a count of
    /// zero; the counts are fixed up, entering first, then the process
    /// moves. Joining its own group again does nothing.
    fn enterpgrp(&mut self, pid: i32, pgid: i32, mksess: bool, orphaned: &mut Vec<i32>) {
        let Some((mypgid, mysid)) = self.procs.iter().find(|p| p.pid == pid).map(|p| (p.pgid, p.sid)) else { return };
        let existing = self.procs.iter().find(|p| p.pgid == pgid).map(|p| p.sid);
        let sess = match existing {
            Some(_) if pgid == mypgid => return,
            Some(s) => s,
            None => {
                self.jobc.insert(pgid, 0);
                if mksess { pid } else { mysid }
            }
        };
        self.fixjobc(pid, pgid, sess, true, orphaned);
        self.fixjobc(pid, mypgid, mysid, false, orphaned);
        if let Some(p) = self.procs.iter_mut().find(|p| p.pid == pid) {
            p.pgid = pgid;
            p.sid = sess;
        }
    }
}

/// Moved after every signal left in a process's inbox (`kill`, a group's
/// signal, a child's SIGCHLD), once the bit is set: a thread that saw it
/// unmoved has nothing new to collect ([`ProcTable::take_signals`]), and one
/// that saw it move finds the bit there. For the threads that ask without
/// the kernel lock; the table's own (a page's kernel module) is the one that
/// counts.
static SIGNAL_SEQ: AtomicU32 = AtomicU32::new(0);

/// [`SIGNAL_SEQ`].
pub fn signal_seq() -> u32 {
    SIGNAL_SEQ.load(Ordering::Acquire)
}

/// The system's processes.
pub struct ProcTable {
    inner: Mutex<Table>,
    /// Set once some process has called `reboot` with a shutdown command.
    ///
    /// A halt is not addressed to a process: rather than signal each, every
    /// process notices at its next syscall and exits, and waiters notice on the
    /// poll they already do. So it takes effect soon, and never mid-syscall.
    halting: AtomicBool,
    halt_code: AtomicI32,
    /// Where the table really is, when it is not here. See [`Remote`].
    remote: Option<Remote>,
    /// Pid 1 is the kernel's own, with no program ([`ProcTable::set_virtual_init`]).
    virtual_init: AtomicBool,
    /// The Darwin tasks' ports and spaces, shared by every task here.
    pub darwin_ipc: std::sync::Arc<crate::darwin::ipc::IpcCell>,
    /// Every process's memorystatus state and the jetsam bands.
    pub jetsam: Mutex<crate::darwin::memorystatus::Jetsam>,
}

impl std::fmt::Debug for ProcTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let t = self.lock();
        f.debug_struct("ProcTable")
            .field("live", &t.procs.len())
            .field("next_pid", &t.next_pid)
            .finish()
    }
}

impl Default for ProcTable {
    fn default() -> ProcTable {
        ProcTable::new()
    }
}

impl ProcTable {
    /// A table holding just the init process, which is its own group and
    /// session leader and whose parent is the kernel that is not there.
    pub fn new() -> ProcTable {
        let t = ProcTable {
            jetsam: Default::default(),
            halting: AtomicBool::new(false),
            halt_code: AtomicI32::new(0),
            remote: None,
            virtual_init: AtomicBool::new(false),
            darwin_ipc: Default::default(),
            inner: Mutex::new(Table {
                next_pid: INIT_PID + 1,
                threads: std::collections::HashMap::new(),
                jobc: std::collections::HashMap::new(),
                zseq: 0,
                procs: vec![Proc {
                    pid: INIT_PID,
                    ppid: 0,
                    pgid: INIT_PID,
                    sid: INIT_PID,
                    child: Child::new(INIT_PID),
                    pending: Arc::new(AtomicU64::new(0)),
                    killed: 0,
                    senders: [0; 64],
                    posts: None,
                    xhighbits: 0,
                    uid: 0,
                    lterm: 0,
                    rval: None,
                    xstat: 0,
                    lexit: false,
                    persona: None,
                    child_end: None,
                    execed: false,
                    nocldstop: false,
                    nice: 0,
                    to_threads: Vec::new(),
                    queue: crate::wait::Queue::new(),
                    info: Vec::new(),
                    vm: None,
                    host_child: false,
                    darwin: None,
                    zseq: 0,
                }],
            }),
        };
        // forkproc's cloning of initproc: init is internal, in no band.
        t.jetsam().add(INIT_PID, 0, true, crate::darwin::memorystatus::relaunch::UNKNOWN);
        t
    }

    /// The memorystatus state, locked.
    pub fn jetsam(&self) -> std::sync::MutexGuard<'_, crate::darwin::memorystatus::Jetsam> {
        self.jetsam.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Table> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Register a child of `ppid` and return its pid. It joins its parent's
    /// group and session, so a shell can later `setpgid` a whole pipeline into
    /// one group.
    pub fn spawn(&self, ppid: i32) -> i32 {
        if let Some(r) = self.remote {
            return (r.spawn)(ppid);
        }
        let mut t = self.lock();
        let pid = t.next_pid;
        t.next_pid += 1;
        let (pgid, sid) = match t.procs.iter().find(|p| p.pid == ppid) {
            Some(p) => (p.pgid, p.sid),
            None => (pid, pid),
        };
        // forkproc's copy of p_nice, the uid and the persona, and
        // task_create's task_policy_create from the parent's policy, with
        // resetpriority for a nice value the child inherits.
        let persona = t.procs.iter().find(|p| p.pid == ppid).and_then(|p| p.persona);
        let (nice, uid, policy) = match t.procs.iter().find(|p| p.pid == ppid) {
            Some(p) => {
                let parent = *p.child.policy.lock().unwrap_or_else(|e| e.into_inner());
                let mut policy = crate::darwin::taskpolicy::TaskPolicy::create(&parent, false);
                if p.nice != 0 {
                    policy.set_importance(-p.nice);
                }
                (p.nice, p.uid, policy)
            }
            None => (0, 0, crate::darwin::taskpolicy::TaskPolicy::default()),
        };
        let child = Child::new(pid);
        *child.policy.lock().unwrap_or_else(|e| e.into_inner()) = policy;
        // The virtual init runs nothing, so a child of it is the host's.
        let host_child = ppid == INIT_PID && self.virtual_init.load(Ordering::Acquire);
        t.procs.push(Proc {
            pid,
            ppid,
            pgid,
            sid,
            child,
            pending: Arc::new(AtomicU64::new(0)),
            killed: 0,
            senders: [0; 64],
            posts: None,
            xhighbits: 0,
            uid,
            lterm: 0,
            rval: None,
            xstat: 0,
            lexit: false,
            persona,
            child_end: None,
            execed: false,
            nocldstop: false,
            nice,
            to_threads: Vec::new(),
            queue: crate::wait::Queue::new(),
            info: Vec::new(),
            vm: None,
            host_child,
            darwin: None,
            zseq: 0,
        });
        drop(t);
        // forkproc's memorystatus init, then memorystatus_add.
        self.jetsam().add(pid, ppid, false, crate::darwin::memorystatus::relaunch::UNKNOWN);
        pid
    }

    /// Publish `pid`'s address space for other processes (at its start and
    /// at each `execve`), or withdraw it. A table that is somewhere else
    /// keeps none: there each process's memory is its own Worker's.
    pub fn set_vm(&self, pid: i32, vm: Option<Arc<PeerVm>>) {
        if self.remote.is_some() {
            return;
        }
        let mut t = self.lock();
        if let Some(p) = t.procs.iter_mut().find(|p| p.pid == pid) {
            p.vm = vm;
        }
    }

    /// `pid`'s address space as last published: `ESRCH` for no such process
    /// or one that has exited, `ENOSYS` where the table keeps none.
    pub fn vm(&self, pid: i32) -> Result<Arc<PeerVm>, Errno> {
        if self.remote.is_some() {
            return Err(Errno::ENOSYS);
        }
        let t = self.lock();
        t.procs.iter().find(|p| p.pid == pid).and_then(|p| p.vm.clone()).ok_or(Errno::ESRCH)
    }

    /// A new thread of `pid`, and its id: from the numbering the processes'
    /// come from, so no thread shares a number with a process or with a
    /// thread of another (a per-process count did both: `tkill(3)` meant pid
    /// 2's second thread and pid 3 alike). `kill`, `tgkill` and `/proc` find
    /// its process by it ([`Self::task_owner`]) until [`Self::end_tid`].
    pub fn new_tid(&self, pid: i32) -> i32 {
        if let Some(r) = self.remote {
            return (r.new_tid)(pid);
        }
        let mut t = self.lock();
        let tid = t.next_pid;
        t.next_pid += 1;
        t.threads.insert(tid, pid);
        tid
    }

    /// Thread `tid` has ended (`exit`, or the others at an `execve`).
    pub fn end_tid(&self, tid: i32) {
        if let Some(r) = self.remote {
            return (r.end_tid)(tid);
        }
        self.lock().threads.remove(&tid);
    }

    /// The process task `id` is part of: `id` itself when it is a process
    /// (its first thread's id is its pid), the process of a thread
    /// otherwise; `None` when neither is in the table.
    pub fn task_owner(&self, id: i32) -> Option<i32> {
        if let Some(r) = self.remote {
            return Some((r.task_owner)(id)).filter(|&p| p > 0);
        }
        let t = self.lock();
        if t.procs.iter().any(|p| p.pid == id) {
            return Some(id);
        }
        t.threads.get(&id).copied()
    }

    /// What `/proc/<pid>` shows for `pid` in every other process: its name
    /// and command line (see [`ProcEntry`]), said by the process itself when
    /// it starts and again when it execs.
    pub fn set_info(&self, pid: i32, info: &[u8]) {
        let info = &info[..info.len().min(4096)];
        if let Some(r) = self.remote {
            return (r.set_info)(pid, info.as_ptr() as usize as crate::PAddr, info.len() as u32);
        }
        if let Some(p) = self.lock().procs.iter_mut().find(|p| p.pid == pid) {
            p.info = info.to_vec();
        }
    }

    /// Every process in the table, for `/proc`'s listing.
    pub fn entries(&self) -> Vec<ProcEntry> {
        if let Some(r) = self.remote {
            let mut cap = 16 * 1024usize;
            for _ in 0..4 {
                let mut buf = vec![0u8; cap];
                let n = (r.snapshot)(buf.as_mut_ptr() as usize as crate::PAddr, cap as u32);
                if n < 0 {
                    return Vec::new();
                }
                if n as usize <= cap {
                    buf.truncate(n as usize);
                    return decode_entries(&buf);
                }
                cap = n as usize;
            }
            return Vec::new();
        }
        // Each status is read after the table is let go: a `wait4` that
        // collects holds its child's status and then takes the table (to
        // forget the child), so holding them in this order deadlocks with
        // it. A process descriptor's poll asks here each time.
        let rows: Vec<_> = {
            let t = self.lock();
            t.procs
                .iter()
                .map(|p| {
                    let mut tids: Vec<i32> = t.threads.iter().filter(|&(_, &o)| o == p.pid).map(|(&tid, _)| tid).collect();
                    tids.sort_unstable();
                    let e = ProcEntry { pid: p.pid, ppid: p.ppid, pgid: p.pgid, sid: p.sid, zombie: false, info: p.info.clone(), tids };
                    (e, Arc::clone(&p.child.status))
                })
                .collect()
        };
        rows.into_iter()
            .map(|(mut e, st)| {
                e.zombie = st.lock().map(|s| s.is_some()).unwrap_or(false);
                e
            })
            .collect()
    }

    /// The handle a host needs to publish `pid`'s exit status.
    pub fn handle(&self, pid: i32) -> Option<ChildHandle> {
        self.lock()
            .procs
            .iter()
            .find(|p| p.pid == pid)
            .map(|p| p.child.handle())
    }

    /// Every child of `ppid` that has not yet been collected by a `wait4`.
    pub fn children(&self, ppid: i32) -> Vec<ChildHandle> {
        self.lock()
            .procs
            .iter()
            .filter(|p| p.ppid == ppid && !p.child.reaped.load(Ordering::Acquire))
            .map(|p| p.child.handle())
            .collect()
    }

    /// Whether `pid` has any child at all, reaped or not.
    ///
    /// `wait4` needs this to tell "no children" (`ECHILD`) from "children, all
    /// already collected" -- which is also `ECHILD`, but reaching it by a
    /// different route matters for the trace.
    pub fn has_children(&self, ppid: i32) -> bool {
        if let Some(r) = self.remote {
            return (r.has_children)(ppid) != 0;
        }
        self.lock().procs.iter().any(|p| p.ppid == ppid)
    }

    /// Record that `pid` has exited, wake anyone waiting on it, and give its
    /// surviving children to init.
    pub fn exit(&self, pid: i32, status: i32) {
        if let Some(r) = self.remote {
            return (r.exit)(pid, status);
        }
        // proc_exit's memorystatus_remove.
        self.jetsam().remove(pid);
        let virtual_init = self.virtual_init.load(Ordering::Acquire);
        let mut jobc_orphaned = Vec::new();
        let (cell, done, was_ppid, own_q, orphans) = {
            let mut t = self.lock();
            t.zseq += 1;
            let zs = t.zseq;
            if let Some(p) = t.procs.iter_mut().find(|p| p.pid == pid) {
                p.zseq = zs;
            }
            let ppid = t.procs.iter().find(|p| p.pid == pid).map(|p| p.ppid);
            // proc_exit's fixjobc, before its children go to init.
            if let Some((pgid, sid)) = t.procs.iter().find(|p| p.pid == pid).map(|p| (p.pgid, p.sid)) {
                t.fixjobc(pid, pgid, sid, false, &mut jobc_orphaned);
            }
            let mut orphans = Vec::new();
            for p in t.procs.iter_mut() {
                if p.ppid == pid {
                    p.ppid = INIT_PID;
                    if virtual_init {
                        orphans.push((p.pid, Arc::clone(&p.child.status)));
                    }
                }
            }
            // Its threads went with it.
            t.threads.retain(|_, p| *p != pid);
            match t.procs.iter_mut().find(|p| p.pid == pid) {
                Some(p) => {
                    p.vm = None;
                    (Arc::clone(&p.child.status), Arc::clone(&p.child.done), ppid, p.queue.id(), orphans)
                }
                None => return,
            }
        };
        // Its children that had ended already and are given to a virtual
        // init: nobody will collect them, so they go now. (Each status is
        // read with the table let go, as in `entries`.)
        let ended: Vec<i32> = orphans
            .into_iter()
            .filter(|(_, st)| st.lock().map(|s| s.is_some()).unwrap_or(false))
            .map(|(pid, _)| pid)
            .collect();
        if !ended.is_empty() {
            self.lock().procs.retain(|p| !(ended.contains(&p.pid) && p.ppid == INIT_PID));
        }
        // Published outside the table lock: a waiter wakes on `done` then wants
        // the table, so holding both here in the other order deadlocks.
        let detail = self.exit_detail(pid);
        let xstat = {
            let mut t = self.lock();
            let p = t.procs.iter_mut().find(|p| p.pid == pid);
            let w = status as u32;
            let x = match p.as_ref().and_then(|p| p.rval) {
                // Its own exit(), not a signal that came first.
                Some(rval) if w & 0x7f == 0 && (w >> 8) & 0xff == rval & 0xff => rval.wrapping_shl(8),
                _ => crate::darwin::exit::status_from_linux(w),
            };
            if let Some(p) = p {
                p.xstat = x;
            }
            x
        };
        *cell.lock().unwrap_or_else(|e| e.into_inner()) = Some(status);
        self.orphanpg(pid, &jobc_orphaned);
        done.notify_all();
        // proc_exit's NOTE_EXIT, with the low half of `p_xstat`, and what
        // ended it, read now while it is there.
        crate::procnote::post_exit(pid, crate::procnote::note::EXIT | (xstat & 0xffff), detail);
        // The parent is owed a SIGCHLD. A `wait4` parked on the condvar
        // doesn't need one, but a parent that polls `WNOHANG` and sleeps in
        // `sigsuspend` between polls has nothing else to wake it -- coreutils
        // `timeout` does exactly that. Raised only now that the child is
        // collectable: a handler's `WNOHANG` wait would otherwise find it
        // still running and wait for a SIGCHLD that has already come (as
        // dbus-daemon's activation helper does).
        let parent_q = {
            let mut t = self.lock();
            // its parent now (it may have been given to init since), or, if
            // a parked `wait4` has collected it already, the one it had
            let ppid = t.procs.iter().find(|p| p.pid == pid).map(|p| p.ppid).or(was_ppid);
            match ppid {
                // Under a virtual init, which wants no SIGCHLD: the host
                // collects what it started, from pid 1's queue; an orphan
                // is let go now.
                Some(INIT_PID) if virtual_init => match t.procs.iter().position(|p| p.pid == pid) {
                    Some(i) if t.procs[i].host_child => t.procs.iter().find(|p| p.pid == INIT_PID).map_or(0, |p| p.queue.id()),
                    Some(i) => {
                        t.procs[i].child.reaped.store(true, Ordering::Release);
                        t.procs.remove(i);
                        0
                    }
                    None => 0,
                },
                _ => match ppid {
                Some(ppid) if t.procs.iter().any(|p| p.pid == ppid) => {
                    // proc_exit: the parent's record of this end, the top
                    // byte of the exit value moved to it but for pid 1's.
                    let (uid, xhighbits) = t.procs.iter().find(|p| p.pid == pid).map_or((0, 0), |p| (p.uid, p.xhighbits));
                    if ppid != INIT_PID {
                        if let Some(c) = t.procs.iter_mut().find(|p| p.pid == pid) {
                            c.xhighbits = 0;
                        }
                    }
                    let parent = t.procs.iter_mut().find(|p| p.pid == ppid).expect("the parent");
                    if ppid != INIT_PID {
                        parent.child_end = Some(ChildEnd { pid, status, uid, xhighbits, stopped: false });
                    }
                    parent.pending.fetch_or(1u64 << (SIGCHLD - 1), Ordering::AcqRel);
                    SIGNAL_SEQ.fetch_add(1, Ordering::Release);
                    parent.queue.id()
                }
                _ => 0,
                },
            }
        };
        // The parent's `wait4`, and its SIGCHLD.
        crate::wait::notify(parent_q);
        if parent_q != 0 {
            if let Some(ppid) = self.lock().procs.iter().find(|p| p.pid == pid).map(|p| p.ppid).or(was_ppid) {
                post_signal(&[ppid], SIGCHLD);
            }
        }
        // A process descriptor for it (`crate::pidfd`), wherever it is held.
        crate::wait::notify(own_q);
    }

    /// Forget a collected process, so a long-lived init doesn't accumulate a
    /// record per respawn.
    pub fn reap(&self, pid: i32) {
        if let Some(r) = self.remote {
            return (r.reap)(pid);
        }
        {
            let mut t = self.lock();
            t.procs.retain(|p| p.pid != pid);
        }
        // A process reaped unseen (a spawn that failed) leaves the bands.
        self.jetsam().remove(pid);
        // reap_child_locked's NOTE_REAP.
        crate::procnote::post(pid, crate::procnote::note::REAP);
    }

    pub fn ppid(&self, pid: i32) -> i32 {
        if let Some(r) = self.remote {
            return (r.ppid)(pid);
        }
        self.lock()
            .procs
            .iter()
            .find(|p| p.pid == pid)
            .map_or(0, |p| p.ppid)
    }

    /// `getpgid`. A pid of zero means the caller, as it does in Linux.
    pub fn pgid(&self, caller: i32, of: i32) -> Result<i32, Errno> {
        if let Some(r) = self.remote {
            return errno_or(( r.pgid)(caller, of));
        }
        let want = if of == 0 { caller } else { of };
        self.lock()
            .procs
            .iter()
            .find(|p| p.pid == want)
            .map(|p| p.pgid)
            .ok_or(Errno::ESRCH)
    }

    /// `getsid`, with the same zero-means-me rule.
    pub fn sid(&self, caller: i32, of: i32) -> Result<i32, Errno> {
        if let Some(r) = self.remote {
            return errno_or((r.sid)(caller, of));
        }
        let want = if of == 0 { caller } else { of };
        self.lock()
            .procs
            .iter()
            .find(|p| p.pid == want)
            .map(|p| p.sid)
            .ok_or(Errno::ESRCH)
    }

    /// `setsid`: become leader of a new session and group. `EPERM` if the caller
    /// already leads a group (it would split across two sessions) -- a shell
    /// forks first so the child is not a leader.
    pub fn setsid(&self, pid: i32) -> Result<i32, Errno> {
        if let Some(r) = self.remote {
            return errno_or((r.setsid)(pid));
        }
        let mut t = self.lock();
        if t.procs.iter().any(|p| p.pgid == pid) {
            return Err(Errno::EPERM);
        }
        if !t.procs.iter().any(|p| p.pid == pid) {
            return Err(Errno::ESRCH);
        }
        let mut orphaned = Vec::new();
        t.enterpgrp(pid, pid, true, &mut orphaned);
        drop(t);
        self.orphanpg(pid, &orphaned);
        Ok(pid)
    }

    /// `setpgid(target, pgid)`, either zero meaning the caller. You may move
    /// only yourself or a child, never across a session boundary, never a
    /// session leader.
    pub fn setpgid(&self, caller: i32, target: i32, pgid: i32) -> Result<(), Errno> {
        if let Some(r) = self.remote {
            return errno_or((r.setpgid)(caller, target, pgid)).map(|_| ());
        }
        let target = if target == 0 { caller } else { target };
        let pgid = if pgid == 0 { target } else { pgid };
        if pgid < 0 {
            return Err(Errno::EINVAL);
        }
        let mut t = self.lock();
        let (t_sid, t_ppid, t_is_leader) = match t.procs.iter().find(|p| p.pid == target) {
            Some(p) => (p.sid, p.ppid, p.sid == p.pid),
            None => return Err(Errno::ESRCH),
        };
        if target != caller && t_ppid != caller {
            return Err(Errno::ESRCH);
        }
        if t_is_leader {
            return Err(Errno::EPERM);
        }
        // Joining an existing group is only allowed within one session;
        // `pgid == target` is the create-a-group case and always in session.
        if pgid != target {
            match t.procs.iter().find(|p| p.pgid == pgid) {
                Some(p) if p.sid == t_sid => {}
                Some(_) => return Err(Errno::EPERM),
                None => return Err(Errno::EPERM),
            }
        }
        let mut orphaned = Vec::new();
        t.enterpgrp(target, pgid, false, &mut orphaned);
        drop(t);
        self.orphanpg(caller, &orphaned);
        Ok(())
    }

    /// Darwin's `setpgid(pid, pgid)` (kern_prot.c): the caller or one of its
    /// descendants (`inferior`) that is in its session and has not exec'd
    /// (EACCES); never a session leader; a group joined must exist in the
    /// caller's session.
    pub fn darwin_setpgid(&self, caller: i32, pid: i32, pgid: i32) -> Result<(), Errno> {
        let mut t = self.lock();
        let alive = |t: &Table, pid: i32| t.procs.iter().find(|p| p.pid == pid && p.child.status.lock().map(|s| s.is_none()).unwrap_or(false)).map(|p| (p.pid, p.ppid, p.pgid, p.sid, p.execed));
        let Some(cur) = alive(&t, caller) else { return Err(Errno::ESRCH) };
        let targ = if pid != 0 && pid != caller {
            let Some(targ) = alive(&t, pid) else { return Err(Errno::ESRCH) };
            // inferior(): up its parents to the caller, failing at the top.
            let mut p = targ.0;
            while p != caller {
                match t.procs.iter().find(|q| q.pid == p) {
                    Some(q) if q.pid != 0 && q.ppid != 0 => p = q.ppid,
                    _ => return Err(Errno::ESRCH),
                }
            }
            if targ.3 != cur.3 {
                return Err(Errno::EPERM);
            }
            if targ.4 {
                return Err(Errno::EACCES);
            }
            targ
        } else {
            cur
        };
        if targ.3 == targ.0 {
            return Err(Errno::EPERM);
        }
        if pgid < 0 {
            return Err(Errno::EINVAL);
        }
        let pgid = if pgid == 0 { targ.0 } else { pgid };
        if pgid != targ.0 {
            match t.procs.iter().find(|p| p.pgid == pgid) {
                Some(p) if p.sid == cur.3 => {}
                _ => return Err(Errno::EPERM),
            }
        }
        let mut orphaned = Vec::new();
        t.enterpgrp(targ.0, pgid, false, &mut orphaned);
        drop(t);
        self.orphanpg(caller, &orphaned);
        Ok(())
    }

    /// `orphanpg` for each group in `pgids` (made orphaned by `by`): if any
    /// member is stopped, every live member is sent SIGHUP, then SIGCONT.
    fn orphanpg(&self, by: i32, pgids: &[i32]) {
        for &g in pgids {
            let members: Vec<(i32, Arc<Mutex<Option<i32>>>, Arc<Mutex<Job>>)> = self
                .lock()
                .procs
                .iter()
                .filter(|p| p.pgid == g)
                .map(|p| (p.pid, Arc::clone(&p.child.status), Arc::clone(&p.child.job)))
                .collect();
            let live = |st: &Arc<Mutex<Option<i32>>>| st.lock().map(|s| s.is_none()).unwrap_or(false);
            if !members.iter().any(|(_, st, job)| live(st) && job.lock().is_ok_and(|j| j.stopped)) {
                continue;
            }
            for (pid, st, _) in &members {
                if live(st) {
                    let _ = self.kill(by, *pid, SIGHUP);
                    let _ = self.kill(by, *pid, SIGCONT);
                }
            }
        }
    }

    /// `pid`'s task policy, a zombie's too.
    pub fn task_policy(&self, pid: i32) -> Option<Arc<Mutex<crate::darwin::taskpolicy::TaskPolicy>>> {
        self.lock().procs.iter().find(|p| p.pid == pid).map(|p| Arc::clone(&p.child.policy))
    }

    /// A live process's uid and `p_nice` (`proc_find`'s: no zombie).
    /// How many processes there are (`nprocs`, zombies too) and how many of
    /// them are `uid`'s (`chgproccnt`'s count).
    pub fn counts(&self, uid: u32) -> (usize, usize) {
        let t = self.lock();
        (t.procs.len(), t.procs.iter().filter(|p| p.persona.unwrap_or(p.uid) == uid).count())
    }

    /// Every process in `proc_listpids`' order: the live ones, the latest
    /// made first, then the zombies, the latest first: (pid, ppid, pgid,
    /// zombie).
    pub fn listing(&self) -> Vec<(i32, i32, i32, bool)> {
        let t = self.lock();
        let mut live: Vec<&Proc> = t.procs.iter().filter(|p| p.zseq == 0).collect();
        live.reverse();
        let mut dead: Vec<&Proc> = t.procs.iter().filter(|p| p.zseq != 0).collect();
        dead.sort_by_key(|p| std::cmp::Reverse(p.zseq));
        live.into_iter().map(|p| (p.pid, p.ppid, p.pgid, false)).chain(dead.into_iter().map(|p| (p.pid, p.ppid, p.pgid, true))).collect()
    }

    /// Set process `pid`'s Darwin record.
    pub fn set_darwin(&self, pid: i32, r: Arc<dyn std::any::Any + Send + Sync>) {
        if let Some(p) = self.lock().procs.iter_mut().find(|p| p.pid == pid) {
            p.darwin = Some(r);
        }
    }

    /// Process `pid`'s Darwin record, a zombie's too, and whether it is one.
    pub fn darwin(&self, pid: i32) -> Option<(Arc<dyn std::any::Any + Send + Sync>, bool)> {
        let t = self.lock();
        let p = t.procs.iter().find(|p| p.pid == pid)?;
        let zombie = !p.child.status.lock().map(|s| s.is_none()).unwrap_or(false);
        p.darwin.clone().map(|r| (r, zombie))
    }

    pub fn live_nice(&self, pid: i32) -> Option<(u32, i32)> {
        let t = self.lock();
        let p = t.procs.iter().find(|p| p.pid == pid)?;
        let live = p.child.status.lock().map(|s| s.is_none()).unwrap_or(false);
        live.then_some((p.uid, p.nice))
    }

    /// Set `pid`'s `p_nice`.
    pub fn set_nice(&self, pid: i32, n: i32) {
        if let Some(p) = self.lock().procs.iter_mut().find(|p| p.pid == pid) {
            p.nice = n;
        }
    }

    /// The members of group `pgid` (zombies too, as `PGMEMBERS_FOREACH`
    /// walks them), or of none: (pid, uid, nice, live).
    pub fn pgrp_members(&self, pgid: i32) -> Vec<(i32, u32, i32, bool)> {
        self.lock()
            .procs
            .iter()
            .filter(|p| p.pgid == pgid)
            .map(|p| (p.pid, p.uid, p.nice, p.child.status.lock().map(|s| s.is_none()).unwrap_or(false)))
            .collect()
    }

    /// Every live process (`allproc`): (pid, uid, nice).
    pub fn all_live(&self) -> Vec<(i32, u32, i32)> {
        self.lock()
            .procs
            .iter()
            .filter(|p| p.child.status.lock().map(|s| s.is_none()).unwrap_or(false))
            .map(|p| (p.pid, p.uid, p.nice))
            .collect()
    }

    /// Mark `pid` as having exec'd (`P_EXEC`).
    /// `P_EXEC`: `pid` has exec'd since its fork.
    pub fn execed(&self, pid: i32) -> bool {
        self.lock().procs.iter().find(|p| p.pid == pid).is_some_and(|p| p.execed)
    }

    /// Group `pgid`'s `pg_jobc`.
    pub fn jobc(&self, pgid: i32) -> i32 {
        self.lock().jobc.get(&pgid).copied().unwrap_or(0)
    }

    pub fn set_execed(&self, pid: i32) {
        if let Some(p) = self.lock().procs.iter_mut().find(|p| p.pid == pid) {
            p.execed = true;
        }
    }

    /// `pid`'s `P_NOCLDSTOP`, kept from its SIGCHLD action.
    pub fn set_nocldstop(&self, pid: i32, on: bool) {
        if let Some(p) = self.lock().procs.iter_mut().find(|p| p.pid == pid) {
            p.nocldstop = on;
        }
    }

    /// Whether `pid`'s group is orphaned (`pg_jobc == 0`).
    pub fn orphaned(&self, pid: i32) -> bool {
        let t = self.lock();
        t.procs.iter().find(|p| p.pid == pid).is_some_and(|p| t.jobc.get(&p.pgid).copied().unwrap_or(0) == 0)
    }

    /// `pid`'s job control state, as its waiting parent sees it.
    pub fn job(&self, pid: i32) -> Option<Arc<Mutex<Job>>> {
        self.lock().procs.iter().find(|p| p.pid == pid).map(|p| Arc::clone(&p.child.job))
    }

    /// A stop's or a continue's news for `pid`'s waiting parent: its wait
    /// woken (`stop`'s `wakeup(parent)`).
    pub fn job_changed(&self, pid: i32) {
        let t = self.lock();
        if let Some(p) = t.procs.iter().find(|p| p.pid == pid) {
            p.child.done.notify_all();
            if let Some(pp) = t.procs.iter().find(|q| q.pid == p.ppid) {
                pp.queue.notify();
            }
        }
    }

    /// A signal the kernel posts to `pid` (no sender): pending for it, and
    /// its waiters woken.
    pub fn post_kernel(&self, pid: i32, signo: u32) {
        {
            let mut t = self.lock();
            let Some(p) = t.procs.iter_mut().find(|p| p.pid == pid) else { return };
            if let Some(v) = &mut p.posts {
                v.push(signo);
            }
            p.pending.fetch_or(1u64 << (signo - 1), Ordering::AcqRel);
            SIGNAL_SEQ.fetch_add(1, Ordering::Release);
            p.queue.notify();
        }
        post_signal(&[pid], signo);
    }

    /// `jetsam_do_kill`'s `exit_with_reason(p, W_EXITCODE(0, SIGKILL))`:
    /// unless `pid` has ended already, its `p_lflag` gains `flags` (the
    /// jetsam bits) and it ends as SIGKILL ends it. No signal is posted,
    /// so its knotes hear no NOTE_SIGNAL.
    pub fn jetsam_kill(&self, pid: i32, flags: u32) {
        let mut t = self.lock();
        let Some(p) = t.procs.iter_mut().find(|p| p.pid == pid) else { return };
        if p.lexit || p.child.status.lock().map(|s| s.is_some()).unwrap_or(true) {
            return;
        }
        p.lexit = true;
        p.lterm |= flags;
        p.pending.fetch_or(1u64 << (SIGKILL - 1), Ordering::AcqRel);
        SIGNAL_SEQ.fetch_add(1, Ordering::Release);
        p.queue.notify();
    }

    /// `proc_exiting(pid)`: its exit has begun, or it has ended.
    pub fn exiting(&self, pid: i32) -> bool {
        let Some((lexit, cell)) = self.lock().procs.iter().find(|p| p.pid == pid).map(|p| (p.lexit, Arc::clone(&p.child.status))) else { return false };
        lexit || cell.lock().map(|s| s.is_some()).unwrap_or(false)
    }

    /// `pid`'s `p_lflag` termination bits ([`ProcTable::jetsam_kill`]),
    /// a zombie's too.
    pub fn lterm(&self, pid: i32) -> u32 {
        self.lock().procs.iter().find(|p| p.pid == pid).map_or(0, |p| p.lterm)
    }

    /// Darwin's `p_xstat` for `pid` once it has ended, until it is reaped.
    pub fn xstat(&self, pid: i32) -> Option<u32> {
        let (cell, x) = self.lock().procs.iter().find(|p| p.pid == pid).map(|p| (Arc::clone(&p.child.status), p.xstat))?;
        let ended = cell.lock().map(|s| s.is_some()).unwrap_or(false);
        ended.then_some(x)
    }

    /// `filt_procevent`'s NOTE_EXIT_DETAIL bits for `pid`, from its
    /// termination bits and its code signing flags.
    fn exit_detail(&self, pid: i32) -> u32 {
        let (lterm, record) = {
            let t = self.lock();
            let Some(p) = t.procs.iter().find(|p| p.pid == pid) else { return 0 };
            (p.lterm, p.darwin.clone())
        };
        let csflags = record
            .and_then(|r| r.downcast::<crate::darwin::procinfo::Public>().ok())
            .map_or(0, |p| p.csflags.load(Ordering::Acquire));
        crate::darwin::procinfo::exit_detail(lterm, csflags)
    }

    /// psignal's stop of `pid` told to its parent: unless the parent has
    /// `P_NOCLDSTOP`, its record of the stop (`si_status` as given) and a
    /// SIGCHLD the kernel posts.
    pub fn stopped_to_parent(&self, pid: i32, si_status: i32, uid: u32) {
        let ppid = {
            let mut t = self.lock();
            let Some(ppid) = t.procs.iter().find(|p| p.pid == pid).map(|p| p.ppid) else { return };
            let Some(parent) = t.procs.iter_mut().find(|p| p.pid == ppid) else { return };
            if parent.nocldstop {
                return;
            }
            parent.child_end = Some(ChildEnd { pid, status: si_status, uid, xhighbits: 0, stopped: true });
            parent.pending.fetch_or(1u64 << (SIGCHLD - 1), Ordering::AcqRel);
            SIGNAL_SEQ.fetch_add(1, Ordering::Release);
            parent.queue.notify();
            ppid
        };
        post_signal(&[ppid], SIGCHLD);
    }

    /// Every live process in group `pgid`, for `kill(-pgid, sig)`.
    pub fn group_members(&self, pgid: i32) -> Vec<i32> {
        self.lock()
            .procs
            .iter()
            .filter(|p| p.pgid == pgid)
            .map(|p| p.pid)
            .collect()
    }

    /// Deliver `signo` as `kill` addresses it: to one process, a group, or
    /// everything. Returns how many it reached. `signo` zero sends nothing and
    /// only reports whether there was anyone -- what `kill(pid, 0)` is for.
    pub fn kill(&self, caller: i32, target: i32, signo: u32) -> Result<usize, Errno> {
        if let Some(r) = self.remote {
            return errno_or((r.kill)(caller, target, signo)).map(|n| n as usize);
        }
        if signo > 64 {
            return Err(Errno::EINVAL);
        }
        let mut t = self.lock();
        let hits: Vec<usize> = match target {
            // Everything but init: killing pid 1 stops the machine (use `reboot`
            // for that). The caller is included, as Linux includes it.
            -1 => (0..t.procs.len()).filter(|&i| t.procs[i].pid != INIT_PID).collect(),
            // A negative pid is the group of that number; zero is the
            // caller's own group.
            n if n <= 0 => {
                let pgid = if n == 0 {
                    t.procs
                        .iter()
                        .find(|p| p.pid == caller)
                        .map_or(caller, |p| p.pgid)
                } else {
                    -n
                };
                (0..t.procs.len()).filter(|&i| t.procs[i].pgid == pgid).collect()
            }
            // A thread's id is its process, as on Linux (`kill` is
            // process-directed whichever of its tasks it names).
            n => {
                let n = t.threads.get(&n).copied().unwrap_or(n);
                (0..t.procs.len()).filter(|&i| t.procs[i].pid == n).collect()
            }
        };
        if hits.is_empty() {
            return Err(Errno::ESRCH);
        }
        if signo > 0 {
            let bit = 1u64 << (signo - 1);
            let virtual_init = self.virtual_init.load(Ordering::Acquire);
            for &i in &hits {
                let p = &mut t.procs[i];
                if virtual_init && p.pid == INIT_PID {
                    continue;
                }
                p.killed |= bit;
                p.senders[signo as usize - 1] = caller;
                if let Some(v) = &mut p.posts {
                    v.push(signo);
                }
                p.pending.fetch_or(bit, Ordering::AcqRel);
            }
            SIGNAL_SEQ.fetch_add(1, Ordering::Release);
            // A signal ends a wait: wake each target's waiting threads.
            for &i in &hits {
                t.procs[i].queue.notify();
            }
            let pids: Vec<i32> = hits.iter().map(|&i| t.procs[i].pid).collect();
            drop(t);
            post_signal(&pids, signo);
        }
        Ok(hits.len())
    }

    /// Signal every process in group `pgid`, which is named positively.
    ///
    /// See [`Remote::kill_group`] for why this is not `kill(-pgid)`.
    pub fn kill_group(&self, caller: i32, pgid: i32, signo: u32) -> Result<usize, Errno> {
        if let Some(r) = self.remote {
            return errno_or((r.kill_group)(caller, pgid, signo)).map(|n| n as usize);
        }
        if signo > 64 {
            return Err(Errno::EINVAL);
        }
        let mut t = self.lock();
        let hits: Vec<usize> = (0..t.procs.len()).filter(|&i| t.procs[i].pgid == pgid).collect();
        if hits.is_empty() {
            return Err(Errno::ESRCH);
        }
        if signo > 0 {
            let bit = 1u64 << (signo - 1);
            for &i in &hits {
                let p = &mut t.procs[i];
                if let Some(v) = &mut p.posts {
                    v.push(signo);
                }
                p.pending.fetch_or(bit, Ordering::AcqRel);
            }
            SIGNAL_SEQ.fetch_add(1, Ordering::Release);
            for &i in &hits {
                t.procs[i].queue.notify();
            }
            let pids: Vec<i32> = hits.iter().map(|&i| t.procs[i].pid).collect();
            drop(t);
            post_signal(&pids, signo);
        }
        Ok(hits.len())
    }

    /// `tgkill(pid, tid, signo)` from another process: for that thread
    /// alone, as Linux delivers it. A Wine server's `SIGUSR1` for a system
    /// APC has to reach the thread that queued the async; sent to the whole
    /// process it wakes whichever thread is free, and the one parked in a
    /// wait never fetches its APC.
    pub fn tkill(&self, caller: i32, pid: i32, tid: i32, signo: u32) -> Result<(), Errno> {
        if let Some(r) = self.remote {
            return errno_or((r.tkill)(caller, pid, tid, signo)).map(|_| ());
        }
        if signo > 64 || tid <= 0 {
            return Err(Errno::EINVAL);
        }
        let mut t = self.lock();
        let p = t.procs.iter_mut().find(|p| p.pid == pid).ok_or(Errno::ESRCH)?;
        if signo > 0 {
            p.to_threads.push((tid, signo, caller));
            // As `kill`: move the sequence the lock-free askers watch, and
            // end the target's waits so the thread collects it.
            SIGNAL_SEQ.fetch_add(1, Ordering::Release);
            p.queue.notify();
        }
        Ok(())
    }

    /// Take the thread-directed signals sent to `pid`'s thread `tid`, or
    /// (`tid` 0) to any of its threads: (tid, signo, sender). A page's Worker
    /// takes its own thread's without the kernel lock (shims/browser sigs.rs),
    /// as it has no other thread's signal state; the kernel takes them all.
    pub fn take_thread_signals(&self, pid: i32, tid: i32) -> Vec<(i32, u32, i32)> {
        if let Some(r) = self.remote {
            let mut out = Vec::new();
            loop {
                let v = (r.take_thread_signal)(pid, tid);
                if v == 0 {
                    return out;
                }
                out.push(unpack_thread_signal(v));
            }
        }
        match self.lock().procs.iter_mut().find(|p| p.pid == pid) {
            Some(p) if tid == 0 => std::mem::take(&mut p.to_threads),
            Some(p) => {
                let (mine, rest) = std::mem::take(&mut p.to_threads).into_iter().partition(|s| s.0 == tid);
                p.to_threads = rest;
                mine
            }
            None => Vec::new(),
        }
    }

    /// One of [`ProcTable::take_thread_signals`], packed for a remote call.
    pub fn take_thread_signal_packed(&self, pid: i32, tid: i32) -> i64 {
        let mut t = self.lock();
        let Some(p) = t.procs.iter_mut().find(|p| p.pid == pid) else { return 0 };
        match p.to_threads.iter().position(|s| tid == 0 || s.0 == tid) {
            Some(i) => {
                let (tid, signo, from) = p.to_threads.remove(i);
                ((tid as i64) << 32) | (((from as i64) & 0xff_ffff) << 8) | signo as i64
            }
            _ => 0,
        }
    }

    /// Take everything sent to `pid` since the last call.
    /// What a Darwin process ending will say of itself: the value it gave
    /// `exit()` (whose top byte is `p_xhighbits`) and its real uid.
    pub fn set_end(&self, pid: i32, rval: u32, uid: u32) {
        if self.remote.is_some() {
            return;
        }
        if let Some(p) = self.lock().procs.iter_mut().find(|p| p.pid == pid) {
            p.xhighbits = (rval >> 24) as u8;
            p.rval = Some(rval);
            p.lexit = true;
            p.uid = uid;
        }
    }

    /// The record of `pid`'s last child to end, taken.
    pub fn take_child_end(&self, pid: i32) -> Option<ChildEnd> {
        if self.remote.is_some() {
            return None;
        }
        self.lock().procs.iter_mut().find(|p| p.pid == pid).and_then(|p| p.child_end.take())
    }

    /// The top byte of `pid`'s exit value still its own, taken: what
    /// `waitid` reports of a child whose parent did not take it (pid 1's),
    /// and once only.
    pub fn xhighbits(&self, pid: i32) -> u8 {
        if self.remote.is_some() {
            return 0;
        }
        self.lock().procs.iter_mut().find(|p| p.pid == pid).map_or(0, |p| std::mem::take(&mut p.xhighbits))
    }

    /// `pid`'s real uid: as it runs (for another process's checks against
    /// it), and the one it ended with (for its parent's record).
    /// Darwin process `pid` is in a persona, counted against its id, or in
    /// none.
    pub fn set_persona(&self, pid: i32, persona: Option<u32>) {
        if self.remote.is_some() {
            return;
        }
        if let Some(p) = self.lock().procs.iter_mut().find(|p| p.pid == pid) {
            p.persona = persona;
        }
    }

    pub fn set_uid(&self, pid: i32, uid: u32) {
        if self.remote.is_some() {
            return;
        }
        if let Some(p) = self.lock().procs.iter_mut().find(|p| p.pid == pid) {
            p.uid = uid;
        }
    }

    /// Keep a list of every signal posted to `pid` from now on
    /// ([`ProcTable::take_posts`]).
    pub fn record_posts(&self, pid: i32) {
        if self.remote.is_some() {
            return;
        }
        if let Some(p) = self.lock().procs.iter_mut().find(|p| p.pid == pid) {
            p.posts.get_or_insert_with(Vec::new);
        }
    }

    /// The signals posted to `pid` since the last take, in order, if it
    /// keeps the list; `None` if it does not (a remote table keeps none).
    pub fn take_posts(&self, pid: i32) -> Option<Vec<u32>> {
        if self.remote.is_some() {
            return None;
        }
        self.lock().procs.iter_mut().find(|p| p.pid == pid).and_then(|p| p.posts.as_mut().map(std::mem::take))
    }

    pub fn take_signals(&self, pid: i32) -> u64 {
        if let Some(r) = self.remote {
            return (r.take_signals)(pid);
        }
        match self.lock().procs.iter().find(|p| p.pid == pid) {
            Some(p) => p.pending.swap(0, Ordering::AcqRel),
            None => 0,
        }
    }

    /// Of the signals in `taken` (what [`ProcTable::take_signals`] just
    /// returned), those `kill` sent, each with the pid that sent it; the rest
    /// the kernel raised. Clears what it reports.
    pub fn take_kill_senders(&self, pid: i32, taken: u64) -> Vec<(u32, i32)> {
        let mut out = Vec::new();
        if let Some(r) = self.remote {
            let mut killed = (r.take_kill_signals)(pid, taken);
            while killed != 0 {
                let signo = killed.trailing_zeros() + 1;
                killed &= killed - 1;
                out.push((signo, (r.kill_sender)(pid, signo)));
            }
            return out;
        }
        let mut t = self.lock();
        if let Some(p) = t.procs.iter_mut().find(|p| p.pid == pid) {
            let mut killed = p.killed & taken;
            p.killed &= !taken;
            while killed != 0 {
                let signo = killed.trailing_zeros() + 1;
                killed &= killed - 1;
                out.push((signo, p.senders[signo as usize - 1]));
            }
        }
        out
    }

    /// For [`Remote::take_kill_signals`]: clear and return the bits of `taken`
    /// that `kill` sent to `pid`.
    pub fn take_kill_signals(&self, pid: i32, taken: u64) -> u64 {
        let mut t = self.lock();
        match t.procs.iter_mut().find(|p| p.pid == pid) {
            Some(p) => {
                let k = p.killed & taken;
                p.killed &= !taken;
                k
            }
            None => 0,
        }
    }

    /// For [`Remote::kill_sender`]: who last sent `signo` to `pid` by `kill`.
    pub fn kill_sender(&self, pid: i32, signo: u32) -> i32 {
        if signo == 0 || signo > 64 {
            return 0;
        }
        self.lock().procs.iter().find(|p| p.pid == pid).map_or(0, |p| p.senders[signo as usize - 1])
    }

    /// Whether anything is waiting for `pid`, without taking it. Cheap enough
    /// to ask on every syscall.
    pub fn has_signals(&self, pid: i32) -> bool {
        if let Some(r) = self.remote {
            return (r.has_signals)(pid) != 0;
        }
        self.lock()
            .procs
            .iter()
            .find(|p| p.pid == pid)
            .is_some_and(|p| p.pending.load(Ordering::Acquire) != 0 || !p.to_threads.is_empty())
    }

    /// Stop the machine. Every process exits with `code` at its next syscall.
    pub fn request_halt(&self, code: i32) {
        if let Some(r) = self.remote {
            return (r.request_halt)(code);
        }
        self.halt_code.store(code, Ordering::Release);
        self.halting.store(true, Ordering::Release);
        // Every waiter notices the halt on its way out of its wait.
        for p in self.lock().procs.iter() {
            p.queue.notify();
        }
    }

    /// `pid`'s wait queue, 0 for none: a thread of `pid` keeps its wait slot
    /// on it while it runs (see [`Proc::queue`]).
    pub fn queue(&self, pid: i32) -> u32 {
        if let Some(r) = self.remote {
            return (r.queue)(pid);
        }
        self.lock().procs.iter().find(|p| p.pid == pid).map_or(0, |p| p.queue.id())
    }

    /// Pid 1 is the kernel's own (`on`): no program runs as it. What the
    /// host starts as its child the host collects; an orphan that ends is
    /// let go at once; a signal to it is ignored, as a real init ignores
    /// what it has no handler for. Otherwise a program is pid 1 and
    /// collects its orphans itself, as on Linux.
    pub fn set_virtual_init(&self, on: bool) {
        self.virtual_init.store(on, Ordering::Release);
    }

    /// The exit code the machine is halting with, if it is.
    pub fn halt_code(&self) -> Option<i32> {
        if let Some(r) = self.remote {
            // -1 for "nobody has asked", because a halt code is a status and
            // a status is unsigned; there is no legal -1 to be confused with.
            let c = (r.halt_code)();
            return (c >= 0).then_some(c);
        }
        self.halting
            .load(Ordering::Acquire)
            .then(|| self.halt_code.load(Ordering::Acquire))
    }

    /// Whether `pid` names a live process, for `kill(pid, 0)`.
    pub fn exists(&self, pid: i32) -> bool {
        self.lock().procs.iter().any(|p| p.pid == pid)
    }

    /// Whether `pid` is in the table and has not exited: [`ProcTable::exists`]
    /// without the zombies, which are in the table until reaped.
    pub fn alive(&self, pid: i32) -> bool {
        // (the status read after the table is let go, as in `entries`)
        let st = self.lock().procs.iter().find(|p| p.pid == pid).map(|p| Arc::clone(&p.child.status));
        st.is_some_and(|st| st.lock().map(|s| s.is_none()).unwrap_or(true))
    }

    /// Whether a `wait4` by `ppid` for `want` would answer now: a child with a
    /// status ready, or no matching child at all (`ECHILD`). Separate from
    /// `collect`, which *takes* the child -- asking must not reap.
    pub fn wait_ready(&self, ppid: i32, want: i32) -> bool {
        if let Some(r) = self.remote {
            return (r.wait_ready)(ppid, want) != 0;
        }
        let mut any = false;
        for c in self
            .children(ppid)
            .iter()
            .filter(|c| want <= 0 || c.pid == want)
        {
            any = true;
            if c.status.lock().map(|st| st.is_some()).unwrap_or(true) {
                return true;
            }
        }
        !any
    }

    /// A table that is really somewhere else. See [`Remote`]. The local `Table`
    /// is still built and still holds init, so methods with no remote
    /// counterpart keep working.
    pub fn shared(remote: Remote) -> ProcTable {
        ProcTable {
            remote: Some(remote),
            ..ProcTable::new()
        }
    }

    /// Whether this table's answers come from somewhere else. Callers must know
    /// because `wait4` differs: a local table hands out `ChildHandle`s to park
    /// on, a remote one has none -- its children are in another memory.
    pub fn is_shared(&self) -> bool {
        self.remote.is_some()
    }

    /// Collect a finished child of `ppid` from a remote table. `Some((pid,
    /// status))` when ready, `None` when none -- distinguish `ECHILD` with
    /// `wait_ready`. Also `None` if the table is local: check `is_shared` first.
    /// `nowait` leaves the child there (`WNOWAIT`).
    pub fn collect(&self, ppid: i32, want: i32, nowait: bool) -> Option<(i32, i32)> {
        let r = self.remote?;
        let packed = (r.wait)(ppid, want, nowait as i32);
        let pid = (packed >> 32) as i32;
        (pid > 0).then(|| (pid, packed as u32 as i32))
    }
}

/// psignal's `proc_knote(p, NOTE_SIGNAL | signum)` for each process a
/// signal was posted to, by Darwin's number.
fn post_signal(pids: &[i32], signo: u32) {
    let Some(d) = crate::darwin::signal::signal_from_linux(signo) else { return };
    for &pid in pids {
        crate::procnote::post(pid, crate::procnote::note::SIGNAL | d);
    }
}

fn unpack_thread_signal(v: i64) -> (i32, u32, i32) {
    ((v >> 32) as i32, (v & 0xff) as u32, ((v >> 8) & 0xff_ffff) as i32)
}

/// A remote call's `i32`: negative is a negated errno, as the kernel's own
/// syscall returns are.
fn errno_or(v: i32) -> Result<i32, Errno> {
    if v < 0 {
        Err(Errno(-v))
    } else {
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_host_collects_what_it_started_and_a_virtual_init_its_orphans() {
        let t = ProcTable::new();
        t.set_virtual_init(true);
        let a = t.spawn(INIT_PID);
        let b = t.spawn(a);
        let c = t.spawn(a);
        // c ends first and is a zombie of a's; then a ends: c is given to
        // pid 1 and, ended already, let go; b is given to pid 1, alive.
        t.exit(c, 0);
        t.exit(a, 3);
        assert!(!t.exists(c));
        assert_eq!(t.ppid(b), INIT_PID);
        // a, the host's, waits for the host.
        assert!(t.exists(a));
        assert_eq!(t.children(INIT_PID).iter().map(|c| c.pid).collect::<Vec<_>>(), vec![a, b]);
        // b ends under the virtual init: gone, and pid 1 has no SIGCHLD.
        t.exit(b, 0);
        assert!(!t.exists(b));
        assert!(!t.has_signals(INIT_PID));
        // A signal to pid 1 reaches it and does nothing.
        assert_eq!(t.kill(a, INIT_PID, 15), Ok(1));
        assert!(!t.has_signals(INIT_PID));
    }

    #[test]
    fn a_real_init_collects_its_orphans() {
        let t = ProcTable::new();
        let a = t.spawn(INIT_PID);
        let b = t.spawn(a);
        t.exit(a, 0);
        t.exit(b, 0);
        // A zombie of pid 1's, and pid 1 has its SIGCHLD.
        assert!(t.exists(b));
        assert_eq!(t.ppid(b), INIT_PID);
        assert!(t.has_signals(INIT_PID));
    }

    /// Threads and processes are numbered from one count, so no id names
    /// two tasks; a thread's id finds its process for `kill` and `/proc`
    /// until it ends, and a process's ending takes its threads' ids along.
    #[test]
    fn thread_ids_are_numbered_with_the_processes() {
        let t = ProcTable::new();
        let a = t.spawn(INIT_PID);
        let a2 = t.new_tid(a);
        let b = t.spawn(INIT_PID);
        let b2 = t.new_tid(b);
        let ids = [INIT_PID, a, a2, b, b2];
        for (i, x) in ids.iter().enumerate() {
            assert!(!ids[i + 1..].contains(x), "{x} names two tasks: {ids:?}");
        }
        assert_eq!(t.task_owner(a), Some(a));
        assert_eq!(t.task_owner(a2), Some(a));
        assert_eq!(t.task_owner(b2), Some(b));
        assert_eq!(t.task_owner(b2 + 100), None);
        // `kill` of a thread's id is its process's signal, and only its.
        assert_eq!(t.kill(INIT_PID, a2, 10), Ok(1));
        assert_eq!(t.take_signals(a), 1 << 9);
        assert_eq!(t.take_signals(b), 0);
        t.end_tid(a2);
        assert_eq!(t.task_owner(a2), None);
        assert_eq!(t.kill(INIT_PID, a2, 10), Err(Errno::ESRCH));
        t.exit(b, 0);
        assert_eq!(t.task_owner(b2), None);
        assert_eq!(t.kill(INIT_PID, b2, 0), Err(Errno::ESRCH));
    }

    #[test]
    fn the_table_lists_processes_with_what_they_said() {
        let t = ProcTable::new();
        let a = t.spawn(INIT_PID);
        t.set_info(a, b"sh\n/bin/sh\0-c\0x\0");
        let e = t.entries();
        assert_eq!(e.len(), 2);
        let mine = e.iter().find(|e| e.pid == a).unwrap();
        assert_eq!(mine.comm(), "sh");
        assert_eq!(mine.cmdline(), b"/bin/sh\0-c\0x\0");
        assert_eq!(decode_entries(&encode_entries(&e)), e);
        // with its threads, in order
        let (t2, t1) = (t.new_tid(a), t.new_tid(a));
        let e = t.entries();
        let mine = e.iter().find(|e| e.pid == a).unwrap();
        assert_eq!(mine.tasks(), vec![a, t2.min(t1), t2.max(t1)]);
        assert_eq!(decode_entries(&encode_entries(&e)), e);
        t.end_tid(t2);
        assert_eq!(t.entries().iter().find(|e| e.pid == a).unwrap().tids, vec![t1]);
        t.exit(a, 0);
        assert!(t.entries().iter().find(|e| e.pid == a).unwrap().zombie);
    }

    #[test]
    fn a_child_inherits_its_parents_group_and_session() {
        let t = ProcTable::new();
        let a = t.spawn(INIT_PID);
        assert_eq!(t.pgid(a, 0), Ok(INIT_PID));
        assert_eq!(t.sid(a, 0), Ok(INIT_PID));
        assert_eq!(t.ppid(a), INIT_PID);
    }

    #[test]
    fn setsid_makes_a_leader_of_both() {
        let t = ProcTable::new();
        let a = t.spawn(INIT_PID);
        assert_eq!(t.setsid(a), Ok(a));
        assert_eq!(t.sid(a, 0), Ok(a));
        assert_eq!(t.pgid(a, 0), Ok(a));
        // Now a group leader, so a second call must fail.
        assert_eq!(t.setsid(a), Err(Errno::EPERM));
    }

    #[test]
    fn setpgid_puts_a_pipeline_in_one_group() {
        let t = ProcTable::new();
        let sh = t.spawn(INIT_PID);
        t.setsid(sh).unwrap();
        let first = t.spawn(sh);
        let second = t.spawn(sh);
        // The shell makes the first child a group leader and the second joins.
        assert_eq!(t.setpgid(sh, first, first), Ok(()));
        assert_eq!(t.setpgid(sh, second, first), Ok(()));
        assert_eq!(t.group_members(first), vec![first, second]);
    }

    #[test]
    fn a_group_may_not_be_joined_across_a_session() {
        let t = ProcTable::new();
        let a = t.spawn(INIT_PID);
        t.setsid(a).unwrap();
        let b = t.spawn(INIT_PID);
        assert_eq!(t.setpgid(INIT_PID, b, a), Err(Errno::EPERM));
    }

    #[test]
    fn orphans_are_reparented_to_init() {
        let t = ProcTable::new();
        let parent = t.spawn(INIT_PID);
        let orphan = t.spawn(parent);
        assert_eq!(t.ppid(orphan), parent);
        t.exit(parent, 0);
        assert_eq!(t.ppid(orphan), INIT_PID);
        // And init can now see it as something to wait for.
        let seen: Vec<i32> = t.children(INIT_PID).iter().map(|c| c.pid).collect();
        assert!(seen.contains(&orphan));
    }

    #[test]
    fn a_reaped_child_stops_being_waitable() {
        let t = ProcTable::new();
        let c = t.spawn(INIT_PID);
        t.exit(c, 0);
        let h = t.handle(c).unwrap();
        assert_eq!(*h.status.lock().unwrap(), Some(0));
        h.reaped.store(true, Ordering::Release);
        assert!(t.children(INIT_PID).iter().all(|x| x.pid != c));
        assert!(t.has_children(INIT_PID));
        t.reap(c);
        assert!(!t.has_children(INIT_PID));
    }

    #[test]
    fn kill_reaches_one_process() {
        let t = ProcTable::new();
        let a = t.spawn(INIT_PID);
        let b = t.spawn(INIT_PID);
        assert_eq!(t.kill(INIT_PID, a, 15), Ok(1));
        assert_eq!(t.take_signals(a), 1 << 14);
        assert_eq!(t.take_signals(b), 0);
        // And taking is destructive.
        assert_eq!(t.take_signals(a), 0);
    }

    #[test]
    fn a_group_can_be_named_even_when_it_is_group_one() {
        // The case `kill(-pgid)` cannot express: -1 is "everyone", so group 1
        // has no negative spelling. A shell started first is in it.
        let t = ProcTable::new();
        let child = t.spawn(INIT_PID);
        let outsider = t.spawn(INIT_PID);
        t.setsid(outsider).unwrap();
        assert_eq!(t.kill_group(INIT_PID, INIT_PID, 2), Ok(2));
        assert_eq!(t.take_signals(INIT_PID), 1 << 1);
        assert_eq!(t.take_signals(child), 1 << 1);
        assert_eq!(t.take_signals(outsider), 0, "a different session is untouched");
    }

    #[test]
    fn kill_reaches_a_whole_group() {
        let t = ProcTable::new();
        let lead = t.spawn(INIT_PID);
        t.setsid(lead).unwrap();
        let member = t.spawn(lead);
        let outsider = t.spawn(INIT_PID);
        assert_eq!(t.kill(INIT_PID, -lead, 9), Ok(2));
        assert_eq!(t.take_signals(lead), 1 << 8);
        assert_eq!(t.take_signals(member), 1 << 8);
        assert_eq!(t.take_signals(outsider), 0);
    }

    #[test]
    fn kill_to_everyone_spares_init_but_not_the_sender() {
        let t = ProcTable::new();
        let sender = t.spawn(INIT_PID);
        let other = t.spawn(INIT_PID);
        assert_eq!(t.kill(sender, -1, 15), Ok(2));
        assert_eq!(t.take_signals(other), 1 << 14);
        assert_eq!(t.take_signals(sender), 1 << 14);
        // Init is the one process `kill(-1)` may not reach.
        assert_eq!(t.take_signals(INIT_PID), 0);
    }

    #[test]
    fn signal_zero_only_asks_whether_anyone_is_there() {
        let t = ProcTable::new();
        let a = t.spawn(INIT_PID);
        assert_eq!(t.kill(INIT_PID, a, 0), Ok(1));
        assert_eq!(t.take_signals(a), 0);
        assert_eq!(t.kill(INIT_PID, 12345, 0), Err(Errno::ESRCH));
    }

    #[test]
    fn a_halt_is_visible_to_every_process() {
        let t = ProcTable::new();
        assert_eq!(t.halt_code(), None);
        t.request_halt(3);
        assert_eq!(t.halt_code(), Some(3));
    }

    #[test]
    fn pids_are_unique_across_the_whole_tree() {
        let t = ProcTable::new();
        let a = t.spawn(INIT_PID);
        let b = t.spawn(a);
        let c = t.spawn(b);
        let d = t.spawn(INIT_PID);
        let all = [INIT_PID, a, b, c, d];
        for (i, x) in all.iter().enumerate() {
            assert!(!all[..i].contains(x), "pid {x} handed out twice");
        }
    }
}
