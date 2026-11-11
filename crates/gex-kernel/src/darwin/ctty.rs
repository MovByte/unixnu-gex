//! Sessions and process groups as a terminal sees them (`struct session`
//! and `struct pgrp`, `bsd/kern/kern_proc.c`): a session's controlling
//! terminal (`s_ttyvp`, `s_ttyp`, `s_ttypgrpid`, `s_ttydev`), its leader,
//! and the identity of a process group a terminal holds as its foreground
//! group.
//!
//! The process table keeps the members of each session and group by
//! number. A session here is the object a number named when it was made:
//! a terminal holds the session it was attached to, and a later session
//! of the same number is another one (`tp->t_session == sessp` compares
//! the objects). A group is named by its number and the serial the table
//! gave it when it was made, for the same reason.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use super::tty::TtyCell;

/// `NODEV`.
pub const NODEV: u32 = u32::MAX;
/// `NO_PID`.
pub const NO_PID: i32 = -1;

/// A process group: its number and the serial of the group that number
/// names now (the table's, made when the group was).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Pgrp {
    pub id: i32,
    pub serial: u64,
}

/// The vnode a session's controlling terminal was attached through
/// (`s_ttyvp`, `s_ttyvid`): the device's node and the generation it had,
/// which a revoke moves on (`vnode_getwithvid` failing after it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TtyVnode {
    pub dev: u32,
    pub vid: u64,
}

/// `struct session`'s terminal state, under `s_mlock`.
#[derive(Default)]
pub struct SessionState {
    /// `s_leader`: the session leader while it lives.
    pub leader: Option<i32>,
    /// `s_ttyvp` and `s_ttyvid`.
    pub ttyvp: Option<TtyVnode>,
    /// `s_ttyp`.
    pub ttyp: Option<Arc<TtyCell>>,
    /// `s_ttypgrpid`.
    pub ttypgrpid: i32,
    /// `s_ttydev`.
    pub ttydev: u32,
    /// `S_CTTYREF`: `/dev/tty` has opened the terminal for the session.
    pub cttyref: bool,
}

/// `struct session`.
pub struct Session {
    pub sid: i32,
    state: Mutex<SessionState>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session").field("sid", &self.sid).finish()
    }
}

impl Session {
    pub fn new(sid: i32, leader: Option<i32>) -> Arc<Session> {
        Arc::new(Session { sid, state: Mutex::new(SessionState { leader, ttypgrpid: NO_PID, ttydev: NODEV, ..Default::default() }) })
    }

    /// `session_lock`.
    pub fn lock(&self) -> MutexGuard<'_, SessionState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl SessionState {
    /// `session_set_tty_locked`: the terminal the session now has; the one
    /// it had before.
    pub fn set_tty(&mut self, tp: &Arc<TtyCell>, dev: u32) -> Option<Arc<TtyCell>> {
        self.ttydev = dev;
        self.ttyp.replace(Arc::clone(tp))
    }

    /// `session_clear_tty_locked`: the terminal the session had.
    pub fn clear_tty(&mut self) -> Option<Arc<TtyCell>> {
        self.ttyvp = None;
        self.ttypgrpid = NO_PID;
        self.ttydev = NODEV;
        self.ttyp.take()
    }
}

/// Every session by number: the one `setsid` (or the first process) made
/// for that number. A number stays a session's while a process of it
/// lives, so the table's own reuse of numbers never meets one in use.
static SESSIONS: Mutex<Option<HashMap<i32, Arc<Session>>>> = Mutex::new(None);

/// The session numbered `sid`, made with `leader` if the table has none
/// of that number yet (the first process's, which no `setsid` made).
pub fn session(sid: i32, leader: Option<i32>) -> Arc<Session> {
    let mut g = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    Arc::clone(g.get_or_insert_with(HashMap::new).entry(sid).or_insert_with(|| Session::new(sid, leader)))
}

/// `setsid`'s new session for `pid`, in place of any older one of that
/// number.
pub fn new_session(pid: i32) -> Arc<Session> {
    let s = Session::new(pid, Some(pid));
    SESSIONS.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_with(HashMap::new).insert(pid, Arc::clone(&s));
    s
}
