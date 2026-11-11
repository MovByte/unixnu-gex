//! Pseudo-terminals as XNU makes them (`bsd/kern/tty_ptmx.c`, the cloning
//! `/dev/ptmx` and its `/dev/ttysNNN` replicas, and `bsd/kern/tty_dev.c`,
//! the driver both sides share): each open of `/dev/ptmx` takes the
//! lowest free minor number, a terminal for it, and a replica node of that
//! number; the primary's reads take the terminal's output and its writes
//! are the terminal's input.
//!
//! Like the line discipline, each function here runs with its terminal
//! locked, returns [`Io::Sleep`] where XNU's sleeps, and goes on where
//! XNU's does when called again with how the sleep ended.

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};

use super::tty::{self, cc, cmd, iflag, lflag, ts, Caller, Chan, Env, Io, IoctlState, ReadState, SleepReq, Tty, TtyCell, Uio, Woke, WriteState, FREAD, FWRITE, IO_NDELAY, TTYHOG, VDISABLE};
use crate::errno::Errno;

/// The majors `cdevsw_add(-15, ...)` gives `/dev/ptmx` and the replicas:
/// the first two free slots from 15, which the pseudo-devices before
/// `ptmx_init` leave free.
pub const PTMX_MAJOR: u32 = 15;
pub const PTSD_MAJOR: u32 = 16;

/// `makedev(major, minor)`.
pub const fn makedev(major: u32, minor: u32) -> u32 {
    (major << 24) | (minor & 0x00ff_ffff)
}

/// `pt_flags` (`bsd/kern/tty_dev.h`).
pub mod pf {
    pub const PKT: u32 = 0x0008;
    pub const STOPPED: u32 = 0x0010;
    pub const NOSTOP: u32 = 0x0040;
    pub const UCNTL: u32 = 0x0080;
    pub const UNLOCKED: u32 = 0x0100;
    pub const OPEN_M: u32 = 0x0200;
    pub const OPEN_S: u32 = 0x0400;
}

/// `TIOCPKT_*`.
pub mod pkt {
    pub const STOP: u8 = 0x04;
    pub const START: u8 = 0x08;
    pub const NOSTOP: u8 = 0x10;
    pub const DOSTOP: u8 = 0x20;
    pub const IOCTL: u8 = 0x40;
}

/// `UID_ROOT`, `GID_TTY`.
const UID_ROOT: u32 = 0;
pub const GID_TTY: u32 = 4;

/// A replica's devfs node (`pt_devhandle`): its owner, group and mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PtsNode {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

/// `struct ptmx_ioctl`, but for the open bits, which `_state` keeps: the
/// driver's state beside its terminal, under the terminal's lock.
pub struct Pti {
    /// `pt_flags` (PKT, STOPPED, NOSTOP, UCNTL, UNLOCKED).
    pub flags: u32,
    /// `pt_selr`, `pt_selw`: the primary's readers and writers.
    pub selr: crate::wait::Queue,
    pub selw: crate::wait::Queue,
    /// NOTE_REVOKEs posted to the knotes on them.
    pub selr_revokes: u64,
    pub selw_revokes: u64,
    pub send: u8,
    pub ucntl: u8,
    /// The minor number, which names the replica.
    pub minor: u32,
}

/// `_state`'s slot: the terminal and `PF_OPEN_M` and `PF_OPEN_S`.
struct Slot {
    tty: Arc<TtyCell>,
    open: u32,
    /// `pt_devhandle`.
    node: Option<PtsNode>,
}

/// `struct _ptmx_ioctl_state`.
struct State {
    /// `pis_ioctl_list`, `pis_total` its length.
    list: Vec<Option<Slot>>,
    /// `pis_free`.
    free: usize,
}

/// `DEVFS_LOCK` over `_state`.
static STATE: Mutex<State> = Mutex::new(State { list: Vec::new(), free: 0 });

/// `PTMX_MAX_DEFAULT`, `PTMX_MAX_HARD`.
pub const PTMX_MAX_DEFAULT: i32 = 511;
pub const PTMX_MAX_HARD: i32 = 999;
/// `PTMX_GROW_VECTOR`.
const PTMX_GROW_VECTOR: usize = 16;

/// `ptmx_max`: `kern.tty.ptmx_max`.
static PTMX_MAX: AtomicI32 = AtomicI32::new(PTMX_MAX_DEFAULT);

/// `sysctl_ptmx_max`: the value, and a new one in (0, PTMX_MAX_HARD].
pub fn ptmx_max(new: Option<i32>) -> Result<i32, Errno> {
    let old = PTMX_MAX.load(Ordering::Relaxed);
    if let Some(v) = new {
        if v > 0 && v <= PTMX_MAX_HARD {
            PTMX_MAX.store(v, Ordering::Relaxed);
        } else {
            return Err(Errno::EINVAL);
        }
    }
    Ok(old)
}

fn state() -> std::sync::MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

/// `ptmx_clone(dev, DEVFS_CLONE_ALLOC)`: the minor a lookup of
/// `/dev/ptmx` gives its vnode, the first free slot or the next one.
pub fn ptmx_clone() -> u32 {
    let s = state();
    s.list.iter().position(|e| e.is_none()).unwrap_or(s.list.len()) as u32
}

/// What `ptmx_get_ioctl` answers.
pub enum Got {
    /// The slot's terminal.
    Tty(Arc<TtyCell>),
    /// No such slot, or none could be made.
    None,
    /// Another open took the minor first (`(struct ptmx_ioctl *)-1`).
    Raced,
}

/// `ptmx_get_ioctl(minor, open_flag)`: the minor's terminal, made for the
/// primary's first open (with the replica's node), marked for the
/// replica's.
pub fn ptmx_get_ioctl(minor: u32, open_flag: u32) -> Got {
    let mut s = state();
    if open_flag & pf::OPEN_M != 0 {
        // The administrative limit, counted in slots used.
        if (s.list.len() - s.free) as i32 >= PTMX_MAX.load(Ordering::Relaxed) {
            return Got::None;
        }
        if s.free == 0 {
            let n = s.list.len() + PTMX_GROW_VECTOR;
            s.list.resize_with(n, || None);
            s.free += PTMX_GROW_VECTOR;
        }
        let m = minor as usize;
        if m >= s.list.len() {
            return Got::None;
        }
        if s.list[m].is_some() {
            return Got::Raced;
        }
        let tty = TtyCell::new();
        {
            let mut tp = tty.lock();
            tp.pti = Some(Pti { flags: 0, selr: crate::wait::Queue::new(), selw: crate::wait::Queue::new(), selr_revokes: 0, selw_revokes: 0, send: 0, ucntl: 0, minor });
        }
        // The replica's node: /dev/ttysNNN, root's, group tty, 0620.
        s.list[m] = Some(Slot { tty, open: pf::OPEN_M, node: Some(PtsNode { uid: UID_ROOT, gid: GID_TTY, mode: 0o620 }) });
        s.free -= 1;
    }
    match s.list.get_mut(minor as usize) {
        Some(Some(slot)) => {
            if open_flag & pf::OPEN_S != 0 {
                slot.open |= pf::OPEN_S;
            }
            Got::Tty(Arc::clone(&slot.tty))
        }
        _ => Got::None,
    }
}

/// `ptmx_free_ioctl(minor, open_flag)`: the side's open bit cleared, and
/// the slot, its terminal and its node gone when neither side is open.
pub fn ptmx_free_ioctl(minor: u32, open_flag: u32) -> i32 {
    let mut s = state();
    let m = minor as usize;
    if m >= s.list.len() {
        return -1;
    }
    let Some(slot) = s.list[m].as_mut() else { return -1 };
    slot.open &= !open_flag;
    if slot.open & (pf::OPEN_M | pf::OPEN_S) == 0 {
        s.list[m] = None;
        s.free += 1;
    }
    0
}

/// `ptmx_get_name`: the replica's path.
pub fn ptmx_get_name(minor: u32) -> String {
    format!("/dev/ttys{minor:03}")
}

/// The replicas' nodes that exist: their minors and attributes, for
/// devfs.
pub fn pts_nodes() -> Vec<(u32, PtsNode)> {
    state().list.iter().enumerate().filter_map(|(i, e)| e.as_ref().and_then(|s| s.node.map(|n| (i as u32, n)))).collect()
}

/// The replica node of `minor`, if it exists.
pub fn pts_node(minor: u32) -> Option<PtsNode> {
    state().list.get(minor as usize).and_then(|e| e.as_ref()).and_then(|s| s.node)
}

/// `_devfs_setattr(pt_devhandle, mode, uid, gid)`: the replica's node
/// set, or ERESTART when there is none (a grant that lost a race with the
/// clone).
fn devfs_setattr(minor: u32, mode: u32, uid: u32, gid: u32) -> Result<(), Errno> {
    let mut s = state();
    match s.list.get_mut(minor as usize).and_then(|e| e.as_mut()).and_then(|s| s.node.as_mut()) {
        Some(n) => {
            n.uid = uid;
            n.gid = gid;
            n.mode = mode & 0o7777;
            Ok(())
        }
        None => Err(tty::ERESTART),
    }
}

fn pti(tp: &mut Tty) -> &mut Pti {
    tp.pti.as_mut().expect("a pty's terminal has its ptmx_ioctl")
}

/// `ptsstart`: `t_oproc`, the primary's readers woken.
pub fn ptsstart(tp: &mut Tty) {
    if tp.pti.is_none() || tp.state & ts::TTSTOP != 0 {
        return;
    }
    let p = pti(tp);
    if p.flags & pf::STOPPED != 0 {
        p.flags &= !pf::STOPPED;
        p.send = pkt::START;
    }
    ptcwakeup(tp, FREAD);
}

/// `ptcwakeup`: the primary's readers and/or writers woken.
pub fn ptcwakeup(tp: &mut Tty, flag: i32) {
    if tp.pti.is_none() {
        return;
    }
    if flag & FREAD != 0 {
        pti(tp).selr.notify();
        tp.wakeup(Chan::PtcRead);
    }
    if flag & FWRITE != 0 {
        pti(tp).selw.notify();
        tp.wakeup(Chan::PtcWrite);
    }
}

/// `ptsstop`: the replica's `d_stop`, which tells the primary in packet
/// mode.
pub fn ptsstop(tp: &mut Tty, flush: i32) {
    if tp.pti.is_none() {
        return;
    }
    let mut flush = flush;
    let p = pti(tp);
    // FLUSHREAD and FLUSHWRITE are FREAD and FWRITE.
    if flush == 0 {
        flush = i32::from(pkt::STOP);
        p.flags |= pf::STOPPED;
    } else {
        p.flags &= !pf::STOPPED;
    }
    p.send |= flush as u8;
    // A change of perspective.
    let mut flag = 0;
    if flush & FREAD != 0 {
        flag |= FWRITE;
    }
    if flush & FWRITE != 0 {
        flag |= FREAD;
    }
    ptcwakeup(tp, flag);
}

/// Where a replica's open is: the terminal, once `ptmx_get_ioctl` gave
/// it and it was set up.
#[derive(Clone, Debug, Default)]
pub struct PtsOpen {
    tty: Option<Arc<TtyCell>>,
}

/// `ptsopen`: a replica opened, once its primary is (`TS_CARR_ON`).
#[allow(clippy::too_many_arguments)]
pub fn ptsopen(minor: u32, flag: i32, p: &Caller, env: &mut dyn Env, st: &mut PtsOpen, resumed: Option<(SleepReq, Woke)>) -> Io<Result<Arc<TtyCell>, Errno>> {
    let begun = st.tty.is_some();
    let cell = match &st.tty {
        Some(t) => Arc::clone(t),
        None => match ptmx_get_ioctl(minor, pf::OPEN_S) {
            Got::Tty(t) => t,
            _ => return Io::Done(Err(Errno::ENXIO)),
        },
    };
    let fail = |e: Errno| {
        ptmx_free_ioctl(minor, pf::OPEN_S);
        Io::Done(Err(e))
    };
    let mut tp = cell.lock();
    if !begun {
        if pti(&mut tp).flags & pf::UNLOCKED == 0 {
            drop(tp);
            return fail(Errno::EAGAIN);
        }
        if tp.state & ts::ISOPEN == 0 {
            tp.termios.cc = tty::TTYDEFCHARS;
            tp.termios.iflag = tty::TTYDEF_IFLAG;
            tp.termios.oflag = tty::TTYDEF_OFLAG;
            tp.termios.lflag = tty::TTYDEF_LFLAG;
            tp.termios.cflag = tty::TTYDEF_CFLAG;
            tp.termios.ispeed = tty::TTYDEF_SPEED;
            tp.termios.ospeed = tty::TTYDEF_SPEED;
            tp.ttsetwater();
        } else if tp.state & ts::XCLUDE != 0 && p.suser {
            drop(tp);
            return fail(Errno::EBUSY);
        }
        if tp.oproc {
            // The primary is still there.
            tp.ttymodem(true, env);
        }
        st.tty = Some(Arc::clone(&cell));
    } else if let Some((req, woke)) = resumed {
        if let Err(e) = tp.slept(&req, woke) {
            drop(tp);
            return fail(e);
        }
    }
    while tp.state & ts::CARR_ON == 0 {
        if flag & tty::FNONBLOCK != 0 {
            break;
        }
        match tp.sleep(Chan::CarrOn, 0, true) {
            Ok(req) => return Io::Sleep(req),
            Err(e) => {
                drop(tp);
                return fail(e);
            }
        }
    }
    let error = tp.ttyopen(makedev(PTSD_MAJOR, minor));
    // Open by the replica now.
    tp.state &= !ts::IOCTL_NOT_OK;
    if error == 0 {
        ptcwakeup(&mut tp, FREAD | FWRITE);
    }
    drop(tp);
    Io::Done(Ok(cell))
}

/// What a replica's close keeps across its drain: the `t_timeout` it
/// put aside.
#[derive(Clone, Copy, Debug, Default)]
pub struct PtsClose {
    save_timeout: Option<i32>,
}

/// `ptsclose`: the replica's last close, or its revoke.
#[allow(clippy::too_many_arguments)]
pub fn ptsclose(cell: &Arc<TtyCell>, minor: u32, flag: i32, revoke: bool, env: &mut dyn Env, st: &mut PtsClose, resumed: Option<(SleepReq, Woke)>) -> Io<i32> {
    let mut tp = cell.lock();
    // FIX_VSX_HANG: the drain bounded at sixty ticks.
    let save_timeout = match st.save_timeout {
        Some(t) => t,
        None => {
            let t = tp.timeout;
            st.save_timeout = Some(t);
            tp.timeout = 60;
            t
        }
    };
    let err = match tp.ttylclose(flag, env, resumed) {
        Io::Sleep(r) => return Io::Sleep(r),
        Io::Done(e) => e,
    };
    tp.ttyclose(env, cell);
    // The primary told, its waiters woken.
    ptsstop(&mut tp, FREAD | FWRITE);
    tp.timeout = save_timeout;
    if revoke {
        ptsd_revoke_knotes(&mut tp, env);
    }
    drop(tp);
    ptmx_free_ioctl(minor, pf::OPEN_S);
    Io::Done(err)
}

/// `ptsd_revoke_knotes`: a revoke's wakeups, with NOTE_REVOKE.
fn ptsd_revoke_knotes(tp: &mut Tty, env: &mut dyn Env) {
    tp.ttwakeup(env);
    tp.rsel_revokes += 1;
    tp.rsel.notify();
    tp.ttwwakeup();
    tp.wsel_revokes += 1;
    tp.wsel.notify();
}

/// `ptsread`: the line discipline's read, the primary's writers woken
/// after.
#[allow(clippy::too_many_arguments)]
pub fn ptsread(tp: &mut Tty, uio: &mut dyn Uio, flag: i32, p: &Caller, env: &mut dyn Env, st: &mut ReadState, resumed: Option<(SleepReq, Woke)>) -> Io<Result<(), Errno>> {
    let mut r = Ok(());
    if tp.oproc || resumed.is_some() {
        match tp.ttread(uio, flag, p, env, st, resumed) {
            Io::Sleep(s) => return Io::Sleep(s),
            Io::Done(e) => r = e,
        }
    }
    ptcwakeup(tp, FWRITE);
    Io::Done(r)
}

/// `ptswrite`: the line discipline's write; EIO with no primary.
#[allow(clippy::too_many_arguments)]
pub fn ptswrite(tp: &mut Tty, uio: &mut dyn Uio, flag: i32, p: &Caller, env: &mut dyn Env, st: &mut WriteState, resumed: Option<(SleepReq, Woke)>) -> Io<Result<(), Errno>> {
    if !tp.oproc && resumed.is_none() {
        return Io::Done(Err(Errno::EIO));
    }
    tp.ttwrite(uio, flag, p, env, st, resumed)
}

/// `ptcopen`: the primary of `minor` opened (the clone's minor).
pub fn ptcopen(minor: u32, env: &mut dyn Env) -> Result<Arc<TtyCell>, Errno> {
    let cell = match ptmx_get_ioctl(minor, pf::OPEN_M) {
        Got::Tty(t) => t,
        Got::None => return Err(Errno::ENXIO),
        // EREDRIVEOPEN: the open is made again, with a new clone.
        Got::Raced => return Err(EREDRIVEOPEN),
    };
    let mut tp = cell.lock();
    // A primary open, or a replica still draining: busy.
    if tp.oproc || tp.state & ts::ISOPEN != 0 {
        let oproc = tp.oproc;
        drop(tp);
        if !oproc {
            ptmx_free_ioctl(minor, pf::OPEN_M);
        }
        return Err(Errno::EBUSY);
    }
    tp.oproc = true;
    tp.state &= !ts::ZOMBIE;
    tp.state |= ts::IOCTL_NOT_OK;
    tp.ttymodem(true, env);
    tp.termios.lflag &= !lflag::EXTPROC;
    drop(tp);
    Ok(cell)
}

/// `EREDRIVEOPEN`: an open to be made again.
pub const EREDRIVEOPEN: Errno = Errno(-6);

/// An open of `/dev/ptmx` as `vn_open` makes it: a lookup that clones a
/// minor, then the primary's open, made again with a new clone when
/// another open took the minor first.
pub fn ptmx_open(env: &mut dyn Env) -> Result<(u32, Arc<TtyCell>), Errno> {
    loop {
        let minor = ptmx_clone();
        match ptcopen(minor, env) {
            Err(e) if e == EREDRIVEOPEN => continue,
            r => return r.map(|t| (minor, t)),
        }
    }
}

/// `ptcclose`: the primary's close: the replica hung up.
pub fn ptcclose(cell: &Arc<TtyCell>, minor: u32, env: &mut dyn Env) {
    let mut tp = cell.lock();
    // The console's terminal no more (KMIOCDISABLCONS is nothing here).
    tty::clear_constty_if(cell);
    // ttymodem's carrier loss, SIGHUP to the session leader included;
    // then what it would have done with MDMBUF or CLOCAL too.
    tp.ttymodem(false, env);
    if tp.state & ts::ISOPEN != 0 {
        tp.state &= !(ts::CARR_ON | ts::CONNECTED);
        tp.state |= ts::ZOMBIE;
        tp.ttyflush(FREAD | FWRITE, env);
    }
    // No more starting the replica's output.
    tp.oproc = false;
    let p = pti(&mut tp);
    p.selr_revokes += 1;
    p.selr.notify();
    p.selw_revokes += 1;
    p.selw.notify();
    drop(tp);
    ptmx_free_ioctl(minor, pf::OPEN_M);
}

/// `ptcread`: the terminal's output to the primary, after any packet.
pub fn ptcread(tp: &mut Tty, uio: &mut dyn Uio, flag: i32, resumed: Option<(SleepReq, Woke)>) -> Io<Result<(), Errno>> {
    if let Some((req, woke)) = resumed {
        if let Err(e) = tp.slept(&req, woke) {
            return Io::Done(Err(e));
        }
    }
    // Until the replica is open and there is something to read; EOF when
    // the replica is gone, EWOULDBLOCK when the read may not wait.
    loop {
        if tp.state & ts::ISOPEN != 0 {
            let (flags, send, ucntl) = {
                let p = pti(tp);
                (p.flags, p.send, p.ucntl)
            };
            if flags & pf::PKT != 0 && send != 0 {
                if let Err(e) = uio.move_out(&[send]) {
                    return Io::Done(Err(e));
                }
                if send & pkt::IOCTL != 0 {
                    // The termios after it; its uiomove's error is not
                    // the read's.
                    let mut b = [0u8; tty::TERMIOS_SIZE];
                    tp.termios.to_bytes(&mut b);
                    let n = uio.resid().min(b.len());
                    let _ = uio.move_out(&b[..n]);
                }
                pti(tp).send = 0;
                return Io::Done(Ok(()));
            }
            if flags & pf::UCNTL != 0 && ucntl != 0 {
                let r = uio.move_out(&[ucntl]);
                if r.is_ok() {
                    pti(tp).ucntl = 0;
                }
                return Io::Done(r);
            }
            if !tp.outq.is_empty() && tp.state & ts::TTSTOP == 0 {
                break;
            }
        }
        if tp.state & ts::CONNECTED == 0 {
            // EOF.
            return Io::Done(Ok(()));
        }
        if flag & IO_NDELAY != 0 {
            return Io::Done(Err(Errno::EWOULDBLOCK));
        }
        return match tp.sleep(Chan::PtcRead, 0, true) {
            Ok(req) => Io::Sleep(req),
            Err(e) => Io::Done(Err(e)),
        };
    }
    let mut error = Ok(());
    if pti(tp).flags & (pf::PKT | pf::UCNTL) != 0 {
        error = uio.move_out(&[0]);
    }
    while uio.resid() > 0 && error.is_ok() {
        let mut buf = [0u8; BUFSIZ];
        let n = uio.resid().min(BUFSIZ);
        let cc = tp.outq.q_to_b(&mut buf[..n]);
        if cc == 0 {
            break;
        }
        error = uio.move_out(&buf[..cc]);
    }
    // l_start: ttwwakeup.
    tp.ttwwakeup();
    Io::Done(error)
}

/// `BUFSIZ`: the driver's piece of a primary's read or write.
const BUFSIZ: usize = 100;

/// What a primary's write keeps across its sleeps.
#[derive(Clone, Debug, Default)]
pub struct PtcWrite {
    /// `locbuf` from `cp` on: taken from the caller, not yet input.
    buf: Vec<u8>,
    cp: usize,
    /// `wcnt`.
    wcnt: usize,
}

/// `ptcwrite`: the primary's bytes input to the terminal, a character at
/// a time, sleeping while the input lists are full.
pub fn ptcwrite(tp: &mut Tty, uio: &mut dyn Uio, flag: i32, env: &mut dyn Env, st: &mut PtcWrite, resumed: Option<(SleepReq, Woke)>) -> Io<Result<(), Errno>> {
    if let Some((req, woke)) = resumed {
        if let Err(e) = tp.slept(&req, woke) {
            // What was taken and not written goes back.
            uio.give_back(st.buf.len() - st.cp);
            return Io::Done(Err(e));
        }
    }
    {
        if tp.state & ts::ISOPEN != 0 {
            while uio.resid() > 0 || st.cp < st.buf.len() {
                if st.cp == st.buf.len() {
                    let n = uio.resid().min(BUFSIZ);
                    match uio.move_in(n) {
                        Ok(b) => {
                            st.buf = b;
                            st.cp = 0;
                        }
                        Err(e) => return Io::Done(Err(e)),
                    }
                    // Checked again, for safety.
                    if tp.state & ts::ISOPEN == 0 {
                        uio.give_back(st.buf.len() - st.cp);
                        return Io::Done(Err(Errno::EIO));
                    }
                }
                while st.cp < st.buf.len() {
                    if tp.rawq.len() + tp.canq.len() >= TTYHOG - 2 && (!tp.canq.is_empty() || tp.termios.lflag & lflag::ICANON == 0) {
                        tp.wakeup(Chan::HupOrInput);
                        break;
                    }
                    let c = st.buf[st.cp];
                    st.cp += 1;
                    tp.ttyinput(i32::from(c), env);
                    st.wcnt += 1;
                }
                if st.cp < st.buf.len() {
                    break;
                }
            }
            if uio.resid() == 0 && st.cp == st.buf.len() {
                return Io::Done(Ok(()));
            }
        }
        // `block:` for the replica to open, or for room in the input.
        let cc = st.buf.len() - st.cp;
        if tp.state & ts::CONNECTED == 0 {
            uio.give_back(cc);
            return Io::Done(Err(Errno::EIO));
        }
        if flag & IO_NDELAY != 0 {
            uio.give_back(cc);
            return Io::Done(if st.wcnt == 0 { Err(Errno::EWOULDBLOCK) } else { Ok(()) });
        }
        match tp.sleep(Chan::PtcWrite, 0, true) {
            Ok(req) => Io::Sleep(req),
            Err(e) => {
                uio.give_back(cc);
                Io::Done(Err(e))
            }
        }
    }
}

/// Where a pty ioctl is: in the line discipline's part, after the
/// driver's.
#[derive(Clone, Debug, Default)]
pub struct PtyIoctl {
    tt: Option<IoctlState>,
}

/// `ptyioctl`: both sides' ioctls; `primary` for `/dev/ptmx`'s.
#[allow(clippy::too_many_arguments)]
pub fn ptyioctl(cell: &Arc<TtyCell>, tp: &mut Tty, primary: bool, com: u64, data: &mut [u8], flag: i32, p: &Caller, env: &mut dyn Env, st: &mut PtyIoctl, resumed: Option<(SleepReq, Woke)>) -> Io<Result<(), Errno>> {
    let minor = pti(tp).minor;
    if st.tt.is_none() {
        // The primary's extended ioctls wait for the replica's first open.
        let allow_ext_ioctl = !(primary && tp.state & ts::IOCTL_NOT_OK != 0);
        // A controller's stty must flush, or ttywflush would hang on the
        // output.
        if com == cmd::TIOCEXT && allow_ext_ioctl {
            let on = i32::from_le_bytes(data[..4].try_into().unwrap()) != 0;
            if on {
                if pti(tp).flags & pf::PKT != 0 {
                    pti(tp).send |= pkt::IOCTL;
                    ptcwakeup(tp, FREAD);
                }
                tp.termios.lflag |= lflag::EXTPROC;
            } else {
                if tp.termios.lflag & lflag::EXTPROC != 0 && pti(tp).flags & pf::PKT != 0 {
                    pti(tp).send |= pkt::IOCTL;
                    ptcwakeup(tp, FREAD);
                }
                tp.termios.lflag &= !lflag::EXTPROC;
            }
            return Io::Done(Ok(()));
        } else if primary {
            let int = |d: &[u8]| i32::from_le_bytes(d[..4].try_into().unwrap());
            match com {
                // Not through ttioctl, where the terminal would have to be
                // the controlling one.
                cmd::TIOCGPGRP => {
                    let v = tp.pgrp.map_or(0, |g| g.id);
                    data[..4].copy_from_slice(&v.to_le_bytes());
                    return Io::Done(Ok(()));
                }
                cmd::TIOCPKT => {
                    let pt = pti(tp);
                    if int(data) != 0 {
                        if pt.flags & pf::UCNTL != 0 {
                            return Io::Done(Err(Errno::EINVAL));
                        }
                        pt.flags |= pf::PKT;
                    } else {
                        pt.flags &= !pf::PKT;
                    }
                    return Io::Done(Ok(()));
                }
                cmd::TIOCUCNTL => {
                    let pt = pti(tp);
                    if int(data) != 0 {
                        if pt.flags & pf::PKT != 0 {
                            return Io::Done(Err(Errno::EINVAL));
                        }
                        pt.flags |= pf::UCNTL;
                    } else {
                        pt.flags &= !pf::UCNTL;
                    }
                    return Io::Done(Ok(()));
                }
                cmd::TIOCSETP | cmd::TIOCSETN | cmd::TIOCSETD | cmd::TIOCSETA_32 | cmd::TIOCSETAW_32 | cmd::TIOCSETAF_32 | cmd::TIOCSETA_64 | cmd::TIOCSETAW_64 | cmd::TIOCSETAF_64 => {
                    let n = tp.outq.len();
                    if n != 0 {
                        tp.outq.ndflush(n);
                    }
                }
                cmd::TIOCSIG => {
                    let s = u32::from_le_bytes(data[..4].try_into().unwrap());
                    if s >= tty::sig::NSIG || s == 0 {
                        return Io::Done(Err(Errno::EINVAL));
                    }
                    if tp.termios.lflag & lflag::NOFLSH == 0 {
                        tp.ttyflush(FREAD | FWRITE, env);
                    }
                    if s == tty::sig::SIGINFO && tp.termios.lflag & lflag::NOKERNINFO == 0 {
                        tp.ttyinfo_locked(env);
                    }
                    if let Some(pg) = tp.pgrp {
                        env.pgsignal(pg, s, true);
                    }
                    return Io::Done(Ok(()));
                }
                cmd::TIOCPTYGRANT => {
                    // grantpt(3): the replica the caller's, group tty, 0620,
                    // by its name in the caller's namespace. Under MAC the
                    // grant's error stands.
                    if pts_node(minor).is_none() {
                        return Io::Done(Err(tty::ERESTART));
                    }
                    if let Err(e) = env.namei(&ptmx_get_name(minor)) {
                        return Io::Done(Err(e));
                    }
                    return Io::Done(devfs_setattr(minor, 0o620, p.uid, GID_TTY));
                }
                cmd::TIOCPTYGNAME => {
                    // ptsname(3), as devfs_make_node's template made it.
                    let name = ptmx_get_name(minor);
                    let n = name.len().min(127);
                    data[..128].fill(0);
                    data[..n].copy_from_slice(&name.as_bytes()[..n]);
                    return Io::Done(Ok(()));
                }
                cmd::TIOCPTYUNLK => {
                    // unlockpt(3).
                    pti(tp).flags |= pf::UNLOCKED;
                    return Io::Done(Ok(()));
                }
                _ => {}
            }
            // A primary is no serial device but while its replica is open.
            if !allow_ext_ioctl {
                return Io::Done(Err(Errno::ENOTTY));
            }
        }
        st.tt = Some(IoctlState::default());
    }
    // l_ioctl (ENOTTY for termios), then ttioctl_locked.
    let mut tst = st.tt.take().unwrap();
    let r = match tp.ttioctl_locked(cell, com, data, flag, p, env, &mut tst, resumed) {
        Io::Sleep(s) => {
            st.tt = Some(tst);
            return Io::Sleep(s);
        }
        Io::Done(r) => r,
    };
    let r = match r {
        Err(Errno::ENOTTY) => {
            if pti(tp).flags & pf::UCNTL != 0 && com & !0xff == cmd::UIOCCMD0 {
                // The UIOCCMD group.
                if com & 0xff != 0 {
                    pti(tp).ucntl = com as u8;
                    ptcwakeup(tp, FREAD);
                }
                return Io::Done(Ok(()));
            } else if com == tty_cmd::TIOCSBRK || com == tty_cmd::TIOCCBRK {
                // A pty has no break to set or clear; POSIX has it succeed.
                return Io::Done(Ok(()));
            }
            Err(Errno::ENOTTY)
        }
        r => r,
    };
    // Under external processing in packet mode, a termios change is a
    // packet.
    if tp.termios.lflag & lflag::EXTPROC != 0 && pti(tp).flags & pf::PKT != 0 {
        use cmd::*;
        if matches!(com, TIOCSETA_32 | TIOCSETAW_32 | TIOCSETAF_32 | TIOCSETA_64 | TIOCSETAW_64 | TIOCSETAF_64 | TIOCSETP | TIOCSETN | TIOCSETC | TIOCSLTC | TIOCLBIS | TIOCLBIC | TIOCLSET) {
            pti(tp).send |= pkt::IOCTL;
            ptcwakeup(tp, FREAD);
        }
    }
    let k = tp.termios.cc;
    let ctrl = |c: u8| c & 0o37;
    let cceq = |val: u8, c: u8| c == val && val != VDISABLE;
    let stop = tp.termios.iflag & iflag::IXON != 0 && cceq(k[cc::VSTOP], ctrl(b's')) && cceq(k[cc::VSTART], ctrl(b'q'));
    let pt = pti(tp);
    if pt.flags & pf::NOSTOP != 0 {
        if stop {
            pt.send &= !pkt::NOSTOP;
            pt.send |= pkt::DOSTOP;
            pt.flags &= !pf::NOSTOP;
            ptcwakeup(tp, FREAD);
        }
    } else if !stop {
        pt.send &= !pkt::DOSTOP;
        pt.send |= pkt::NOSTOP;
        pt.flags |= pf::NOSTOP;
        ptcwakeup(tp, FREAD);
    }
    Io::Done(r)
}

use tty::cmd as tty_cmd;

/// `ptsselect`: whether the replica is readable (`rw` FREAD) or writable.
pub fn ptsselect(tp: &mut Tty, rw: i32, env: &mut dyn Env) -> i32 {
    match rw {
        FREAD => {
            if tp.state & ts::ZOMBIE != 0 {
                return 1;
            }
            tp.ttnread(env)
        }
        FWRITE => {
            if tp.state & ts::ZOMBIE != 0 {
                return 1;
            }
            if tp.outq.len() as i32 <= tp.lowat && tp.state & ts::CONNECTED != 0 {
                return tp.hiwat - tp.outq.len() as i32;
            }
            0
        }
        _ => 0,
    }
}

/// `ptcselect`: whether the primary is readable (FREAD), has an
/// exceptional condition (0), or is writable (FWRITE).
pub fn ptcselect(tp: &mut Tty, rw: i32) -> i32 {
    if tp.state & ts::CONNECTED == 0 {
        return 1;
    }
    let isopen = tp.state & ts::ISOPEN != 0;
    match rw {
        FREAD if isopen && !tp.outq.is_empty() && tp.state & ts::TTSTOP == 0 => {
            // fix_7828447: the count, not 1.
            tp.outq.len() as i32
        }
        FREAD | 0 => {
            let p = pti(tp);
            i32::from(isopen && ((p.flags & pf::PKT != 0 && p.send != 0) || (p.flags & pf::UCNTL != 0 && p.ucntl != 0)))
        }
        FWRITE => {
            if isopen {
                let room = (TTYHOG - 2) as i32 - (tp.rawq.len() + tp.canq.len()) as i32;
                if room > 0 {
                    return room;
                }
                if tp.canq.is_empty() && tp.termios.lflag & lflag::ICANON != 0 {
                    return 1;
                }
            }
            0
        }
        _ => 0,
    }
}

/// `ptsd_kqops_common`: a replica knote's readiness and data, and whether
/// it is at EOF.
pub fn ptsd_kqops(tp: &mut Tty, read: bool, env: &mut dyn Env) -> (bool, i64, bool) {
    let (mut ready, mut data) = (false, 0i64);
    if read {
        data = i64::from(tp.ttnread(env));
        ready = data > 0;
    } else if tp.outq.len() as i32 <= tp.lowat && tp.state & ts::CONNECTED != 0 {
        data = (tp.outq.capacity() - tp.outq.len()) as i64;
        ready = true;
    }
    let eof = tp.state & ts::ZOMBIE != 0;
    (ready || eof, data, eof)
}

/// `ptmx_kqops_common`: a primary knote's readiness and data, and whether
/// it is at EOF.
pub fn ptmx_kqops(tp: &mut Tty, read: bool) -> (bool, i64, bool) {
    let (mut ready, mut data) = (false, 0i64);
    if read {
        if !tp.outq.is_empty() && tp.state & ts::TTSTOP == 0 {
            data = tp.outq.len() as i64;
            ready = data > 0;
        } else {
            let p = pti(tp);
            if (p.flags & pf::PKT != 0 && p.send != 0) || (p.flags & pf::UCNTL != 0 && p.ucntl != 0) {
                ready = true;
            }
        }
    } else {
        let mut r = (TTYHOG - 2) as i64 - (tp.rawq.len() + tp.canq.len()) as i64;
        if tp.canq.is_empty() && tp.termios.lflag & lflag::ICANON != 0 {
            r = 1;
        }
        ready = r > 0;
    }
    // A disconnect is EOF.
    let eof = tp.state & ts::CONNECTED == 0 || tp.state & ts::ZOMBIE != 0;
    (ready || eof, data, eof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::darwin::ctty::{Pgrp, Session};
    use crate::darwin::tty::{FgInfo, ReadState, WriteState};

    /// An Env that records the signals posted.
    #[derive(Default)]
    struct Rec {
        sigs: Vec<(i32, u32)>,
    }

    impl Env for Rec {
        fn pgsignal(&mut self, pg: Pgrp, signum: u32, _checkctty: bool) {
            self.sigs.push((pg.id, signum));
        }
        fn psignal(&mut self, pid: i32, signum: u32) {
            self.sigs.push((-pid, signum));
        }
        fn pgrp_find(&mut self, _pgid: i32) -> Option<(Pgrp, Arc<Session>)> {
            None
        }
        fn loadavg(&mut self) -> u32 {
            0
        }
        fn fg_pick(&mut self, _pg: Pgrp) -> Option<i32> {
            None
        }
        fn fg_info(&mut self, _pid: i32) -> Option<Result<FgInfo, ()>> {
            None
        }
        fn set_controlt(&mut self) {}
        fn session_leader(&mut self, _s: &Arc<Session>) -> Option<i32> {
            None
        }
        fn namei(&mut self, _path: &str) -> Result<(), Errno> {
            Ok(())
        }
    }

    /// A uio over a buffer: `data` to write, `out` read into up to `cap`.
    struct VecUio {
        data: Vec<u8>,
        pos: usize,
        out: Vec<u8>,
        cap: usize,
    }

    impl VecUio {
        fn reader(cap: usize) -> VecUio {
            VecUio { data: Vec::new(), pos: 0, out: Vec::new(), cap }
        }
        fn writer(b: &[u8]) -> VecUio {
            VecUio { data: b.to_vec(), pos: 0, out: Vec::new(), cap: 0 }
        }
    }

    impl Uio for VecUio {
        fn resid(&self) -> usize {
            if self.cap > 0 {
                self.cap - self.out.len()
            } else {
                self.data.len() - self.pos
            }
        }
        fn move_out(&mut self, b: &[u8]) -> Result<(), Errno> {
            self.out.extend_from_slice(b);
            Ok(())
        }
        fn move_in(&mut self, n: usize) -> Result<Vec<u8>, Errno> {
            let v = self.data[self.pos..self.pos + n].to_vec();
            self.pos += n;
            Ok(v)
        }
        fn give_back(&mut self, n: usize) {
            self.pos -= n;
        }
        fn finish(&mut self) {
            self.pos = self.data.len();
        }
    }

    fn caller() -> Caller {
        Caller { pid: 10, pgrp: Some(Pgrp { id: 10, serial: 1 }), pg_jobc: 1, session: None, controlt: false, ttin_ignored: false, ttin_masked: false, ttou_ignored: false, ttou_masked: false, lppwait: false, suser: false, uid: 501 }
    }

    /// A pair: the primary open, unlocked, the replica open.
    fn pair(env: &mut Rec) -> (u32, Arc<TtyCell>) {
        let (minor, cell) = ptmx_open(env).unwrap();
        let p = caller();
        let mut st = PtyIoctl::default();
        let mut d = [0u8; 8];
        assert_eq!(ptyioctl(&cell, &mut cell.lock(), true, cmd::TIOCPTYUNLK, &mut d, 0, &p, env, &mut st, None), Io::Done(Ok(())));
        let mut ost = PtsOpen::default();
        match ptsopen(minor, 0, &p, env, &mut ost, None) {
            Io::Done(Ok(_)) => {}
            r => panic!("ptsopen: {:?}", r.map_err()),
        }
        (minor, cell)
    }

    impl<T> Io<Result<T, Errno>> {
        fn map_err(self) -> Option<Errno> {
            match self {
                Io::Done(Err(e)) => Some(e),
                _ => None,
            }
        }
    }

    fn master_write(cell: &Arc<TtyCell>, env: &mut Rec, b: &[u8]) {
        let mut u = VecUio::writer(b);
        let mut st = PtcWrite::default();
        assert_eq!(ptcwrite(&mut cell.lock(), &mut u, IO_NDELAY, env, &mut st, None), Io::Done(Ok(())));
    }

    fn master_read(cell: &Arc<TtyCell>) -> Vec<u8> {
        let mut u = VecUio::reader(1024);
        match ptcread(&mut cell.lock(), &mut u, IO_NDELAY, None) {
            Io::Done(Ok(())) | Io::Done(Err(Errno::EWOULDBLOCK)) => u.out,
            r => panic!("ptcread: {:?}", r.map_err()),
        }
    }

    fn slave_read(cell: &Arc<TtyCell>, env: &mut Rec) -> Result<Vec<u8>, Errno> {
        let mut u = VecUio::reader(1024);
        let mut st = ReadState::default();
        match ptsread(&mut cell.lock(), &mut u, IO_NDELAY, &caller(), env, &mut st, None) {
            Io::Done(Ok(())) => Ok(u.out),
            Io::Done(Err(e)) => Err(e),
            Io::Sleep(_) => panic!("a non-blocking read slept"),
        }
    }

    #[test]
    fn a_line_typed_is_read_whole_and_echoed() {
        let mut env = Rec::default();
        let (minor, cell) = pair(&mut env);
        master_write(&cell, &mut env, b"hel");
        assert_eq!(slave_read(&cell, &mut env), Err(Errno::EWOULDBLOCK), "no line yet");
        master_write(&cell, &mut env, b"lp\x7fo\r");
        assert_eq!(slave_read(&cell, &mut env).unwrap(), b"hello\n");
        // The echo: the erase as "\b \b", the CR as ICRNL's NL, out as ONLCR's CRNL.
        assert_eq!(master_read(&cell), b"hellp\x08 \x08o\r\n");
        // The replica's output goes to the primary with ONLCR.
        let mut u = VecUio::writer(b"out\n");
        let mut ws = WriteState::default();
        assert_eq!(ptswrite(&mut cell.lock(), &mut u, 0, &caller(), &mut env, &mut ws, None), Io::Done(Ok(())));
        assert_eq!(master_read(&cell), b"out\r\n");
        let mut cs = PtsClose::default();
        assert_eq!(ptsclose(&cell, minor, 0, false, &mut env, &mut cs, None), Io::Done(0));
        ptcclose(&cell, minor, &mut env);
    }

    #[test]
    fn interrupt_signals_the_foreground_group() {
        let mut env = Rec::default();
        let (minor, cell) = pair(&mut env);
        cell.lock().pgrp = Some(Pgrp { id: 77, serial: 3 });
        master_write(&cell, &mut env, b"ab\x03");
        assert_eq!(env.sigs, vec![(77, tty::sig::SIGINT)]);
        // The flush takes the half line and its echo; the ^C echoes as ^C.
        assert_eq!(master_read(&cell), b"^C");
        assert_eq!(slave_read(&cell, &mut env), Err(Errno::EWOULDBLOCK));
        let mut cs = PtsClose::default();
        ptsclose(&cell, minor, 0, false, &mut env, &mut cs, None);
        ptcclose(&cell, minor, &mut env);
    }

    #[test]
    fn a_locked_replica_will_not_open_and_the_minor_comes_back() {
        let mut env = Rec::default();
        let (minor, cell) = ptmx_open(&mut env).unwrap();
        let mut ost = PtsOpen::default();
        assert_eq!(ptsopen(minor, 0, &caller(), &mut env, &mut ost, None).map_err(), Some(Errno::EAGAIN));
        assert!(pts_node(minor).is_some());
        ptcclose(&cell, minor, &mut env);
        // The slot is free again, its replica node gone.
        assert!(pts_node(minor).is_none());
    }

    #[test]
    fn the_water_marks_follow_the_speed() {
        let mut env = Rec::default();
        let (minor, cell) = pair(&mut env);
        {
            let tp = cell.lock();
            assert_eq!((tp.lowat, tp.hiwat), (256, 1248));
        }
        let mut cs = PtsClose::default();
        ptsclose(&cell, minor, 0, false, &mut env, &mut cs, None);
        ptcclose(&cell, minor, &mut env);
    }

    #[test]
    fn packet_mode_heads_each_read() {
        let mut env = Rec::default();
        let (minor, cell) = pair(&mut env);
        let mut d = [0u8; 8];
        d[..4].copy_from_slice(&1i32.to_le_bytes());
        let mut st = PtyIoctl::default();
        assert_eq!(ptyioctl(&cell, &mut cell.lock(), true, cmd::TIOCPKT, &mut d, 0, &caller(), &mut env, &mut st, None), Io::Done(Ok(())));
        let mut u = VecUio::writer(b"z");
        let mut ws = WriteState::default();
        ptswrite(&mut cell.lock(), &mut u, 0, &caller(), &mut env, &mut ws, None);
        assert_eq!(master_read(&cell), b"\0z");
        let mut cs = PtsClose::default();
        ptsclose(&cell, minor, 0, false, &mut env, &mut cs, None);
        ptcclose(&cell, minor, &mut env);
    }

    #[test]
    fn the_replica_hangs_up_when_the_primary_closes() {
        let mut env = Rec::default();
        let (minor, cell) = pair(&mut env);
        ptcclose(&cell, minor, &mut env);
        // EOF on the replica, and EIO for its writes.
        assert_eq!(slave_read(&cell, &mut env).unwrap(), b"");
        let mut u = VecUio::writer(b"x");
        let mut ws = WriteState::default();
        assert_eq!(ptswrite(&mut cell.lock(), &mut u, 0, &caller(), &mut env, &mut ws, None), Io::Done(Err(Errno::EIO)));
        let mut cs = PtsClose::default();
        ptsclose(&cell, minor, 0, false, &mut env, &mut cs, None);
        assert!(pts_node(minor).is_none());
    }
}
