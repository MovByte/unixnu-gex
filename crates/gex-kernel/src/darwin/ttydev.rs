//! The terminal devices' vnodes and the calls on them: devfs's nodes for
//! `/dev/ptmx`, `/dev/ttysNNN` and `/dev/tty` (`bsd/miscfs/devfs`),
//! specfs's open and last close of a device (`spec_open`, `spec_close`),
//! `/dev/tty`'s indirection to the session's terminal (`tty_tty.c`),
//! `/dev/console`'s to the console's terminal ([`super::km`]), and
//! `read`, `write`, `ioctl` on them (`sys_generic.c`, `vfs_vnops.c`), with
//! the line discipline's sleeps as the thread's waits.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::ctty::{self, Pgrp, Session, TtyVnode};
use super::km::{self, CONSOLE_MAJOR};
use super::ptmx::{self, makedev, PTC_MAJOR, PTMX_MAJOR, PTSD_MAJOR, PTS_MAJOR};
use super::thread::Finish;
use super::tty::{self, Caller, Env, FgInfo, Io, SleepReq, TtyCell, Uio, Woke};
use super::wait::{Wait, WaitResult};
use crate::errno::Errno;
use crate::file::OpenFile;
use crate::proc::ProcTable;
use crate::syscalls::{Kernel, SyscallOutcome};
use crate::vfs::{FileHandle, FileType, Metadata};
use crate::GuestMem;

/// `/dev/tty`'s major (cdevsw slot 2, `cttyopen`).
pub const CTTY_MAJOR: u32 = 2;

/// A Darwin device number in Linux's encoding, which `stat` turns back.
pub fn linux_rdev(dev: u32) -> u64 {
    let (major, minor) = (u64::from(dev >> 24), u64::from(dev & 0x00ff_ffff));
    (minor & 0xff) | ((major & 0xfff) << 8) | ((minor & !0xff) << 12) | ((major & !0xfff) << 32)
}

/// A devfs node of a terminal device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Node {
    /// `/dev/ptmx`, which clones.
    Ptmx,
    /// `/dev/ttysNNN`.
    Pts(u32),
    /// A BSD pty's `/dev/ttypN`: cdevsw's PTS_MAJOR, whose functions are
    /// the primary's.
    Ttyp(u32),
    /// A BSD pty's `/dev/ptypN`: PTC_MAJOR, the replica's.
    Ptyp(u32),
    /// `/dev/tty`.
    Ctty,
    /// `/dev/console`.
    Console,
}

/// The driver a call on a terminal's vnode reaches (its cdevsw entry's).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Drv {
    /// A pty's primary (`ptcopen` and the rest).
    Ptc,
    /// A pty's replica (`ptsopen` and the rest).
    Pts,
    /// The kernel's console terminal (`kmopen` and the rest).
    Km,
}

/// devfs's `/dev/console` node ([`super::devfs`]'s, made in `devfs_init`).
fn console_node() -> &'static super::devfs::Node {
    super::devfs::lookup("console").expect("devfs_init's console node")
}

/// What devfs and specfs keep of a device: its vnodes' use count
/// (`vcount`), the generation a revoke moves on (`v_id`), and its devnode's
/// times with the access and change marks the reads and writes leave.
#[derive(Clone, Copy, Debug)]
struct Dev {
    opens: u32,
    vid: u64,
    times: super::devfs::DnTimes,
    ino: u64,
    /// A revoke is reclaiming its vnode (`VL_TERMINATE`).
    terminating: bool,
}

static DEVS: Mutex<Option<HashMap<u32, Dev>>> = Mutex::new(None);
/// A node's inode number and times: a boot node's own, else a new one's.
fn made(dev: u32) -> (u64, super::devfs::DnTimes) {
    let minor = dev & 0x00ff_ffff;
    let name = match dev >> 24 {
        PTMX_MAJOR => Some("ptmx".to_string()),
        CTTY_MAJOR => Some("tty".to_string()),
        CONSOLE_MAJOR => Some("console".to_string()),
        PTS_MAJOR => Some(bsd_name("tty", minor)),
        PTC_MAJOR => Some(bsd_name("pty", minor)),
        _ => None,
    };
    match name.and_then(|n| super::devfs::ino_of(&n)) {
        Some(i) => (i, super::devfs::DnTimes::made_at_boot()),
        None => (super::devfs::later_ino(), super::devfs::DnTimes::made_now()),
    }
}

/// The record of device `dev`'s node, made with it.
fn with_dev<R>(dev: u32, f: impl FnOnce(&mut Dev) -> R) -> R {
    let mut g = DEVS.lock().unwrap_or_else(|e| e.into_inner());
    let map = g.get_or_insert_with(HashMap::new);
    let d = map.entry(dev).or_insert_with(|| {
        let (ino, times) = made(dev);
        Dev { opens: 0, vid: 1, times, ino, terminating: false }
    });
    f(d)
}

/// Device `dev`'s record as it is, if its node has one: its opens (the
/// vnode's use count), its `v_id`, and whether a revoke is reclaiming it.
fn peek_dev(dev: u32) -> Option<(u32, u64, bool)> {
    let g = DEVS.lock().unwrap_or_else(|e| e.into_inner());
    g.as_ref()?.get(&dev).map(|d| (d.opens, d.vid, d.terminating))
}

/// The sleep of a call that came to a vnode being revoked: until the
/// reclaim, uninterruptibly.
fn reclaim_wait(cell: &Arc<TtyCell>) -> SleepReq {
    SleepReq { chan: tty::Chan::Reclaim, timo: 0, pcatch: false, gen: cell.lock().gen }
}

/// A call in a terminal's vnode (its iocount), for as long as it runs.
struct IoRef {
    cell: Arc<TtyCell>,
    v: tty::Vnode,
}

impl IoRef {
    fn enter(cell: &Arc<TtyCell>, v: tty::Vnode) -> IoRef {
        cell.lock().io_enter(v);
        IoRef { cell: Arc::clone(cell), v }
    }
}

impl Drop for IoRef {
    fn drop(&mut self) {
        self.cell.lock().io_leave(self.v);
    }
}

/// The node a device's times are kept on: the ptmx node for every clone.
fn node_dev(dev: u32) -> u32 {
    if dev >> 24 == PTMX_MAJOR {
        makedev(PTMX_MAJOR, 0)
    } else {
        dev
    }
}

/// A replica's node is made new with its slot: its record starts over.
fn pts_node_made(minor: u32) {
    let dev = makedev(PTSD_MAJOR, minor);
    let mut g = DEVS.lock().unwrap_or_else(|e| e.into_inner());
    let map = g.get_or_insert_with(HashMap::new);
    let vid = map.get(&dev).map_or(1, |d| d.vid + 1);
    let (ino, times) = made(dev);
    map.insert(dev, Dev { opens: 0, vid, times, ino, terminating: false });
}

/// devfs's attributes of a terminal node (`devfs_getattr`).
pub fn node_metadata(node: Node, dev: u32) -> Metadata {
    if node == Node::Console {
        // devfs keeps the console node's times with the boot's others.
        return super::devfs::metadata(console_node());
    }
    let mode = node_attrs(node).2;
    let ndev = match node {
        Node::Ptmx => node_dev(dev),
        Node::Ctty => makedev(CTTY_MAJOR, 0),
        _ => dev,
    };
    let (ino, (mtime, times)) = with_dev(ndev, |d| (d.ino, d.times.getattr()));
    Metadata {
        file_type: FileType::CharDevice,
        size: 0,
        mode,
        ino,
        mtime,
        nlink: 1,
        rdev: linux_rdev(dev),
        times,
    }
}

/// A terminal node's owner, group and mode: `ptmx` root's, group tty,
/// 0666; `tty` root's, group wheel, 0666; a ptmx replica's and a BSD
/// pty's `ttypN` as made and as a grant changed them; `ptypN` root's,
/// group wheel, 0666; `console` as `devfs_init` made it.
pub fn node_attrs(node: Node) -> (u32, u32, u32) {
    match node {
        Node::Ptmx => (0, ptmx::GID_TTY, 0o666),
        Node::Ctty => (0, 0, 0o666),
        Node::Pts(m) => ptmx::pts_node(m).map_or((0, ptmx::GID_TTY, 0o620), |n| (n.uid, n.gid, n.mode)),
        Node::Ttyp(m) => ptmx::bsd_node(m).map_or((0, 0, 0o666), |n| (n.uid, n.gid, n.mode)),
        Node::Ptyp(_) => (0, 0, 0o666),
        Node::Console => {
            let n = console_node();
            (n.uid, n.gid, n.mode)
        }
    }
}

/// The owner and group of the terminal node of device `rdev` (Linux's
/// encoding, as a stat has it).
/// The Darwin device number of terminal node `md`, if it is one kept here.
fn tty_dev_of(md: &Metadata) -> Option<u32> {
    if md.file_type != FileType::CharDevice {
        return None;
    }
    let major = (((md.rdev >> 8) & 0xfff) | ((md.rdev >> 32) & !0xfff)) as u32;
    let minor = ((md.rdev & 0xff) | ((md.rdev >> 12) & !0xff)) as u32;
    let dev = makedev(major, minor);
    dev_node(dev).map(|_| dev)
}

/// Whether node `md` is a terminal's (`VISTTY`): a character device whose
/// major's `cdevsw` entry is D_TTY, the console's (0) or one kept here.
pub fn vnode_is_tty(md: &Metadata) -> bool {
    md.file_type == FileType::CharDevice && (tty_dev_of(md).is_some() || super::attrcall::darwin_dev(md.rdev) >> 24 == 0)
}

/// The node of terminal device `dev`.
fn dev_node(dev: u32) -> Option<Node> {
    let (major, minor) = (dev >> 24, dev & 0x00ff_ffff);
    Some(match major {
        PTMX_MAJOR => Node::Ptmx,
        PTSD_MAJOR => Node::Pts(minor),
        PTS_MAJOR if minor < ptmx::NPTY => Node::Ttyp(minor),
        PTC_MAJOR if minor < ptmx::NPTY => Node::Ptyp(minor),
        CTTY_MAJOR if minor == 0 => Node::Ctty,
        CONSOLE_MAJOR if minor == 0 => Node::Console,
        _ => return None,
    })
}

pub fn node_owner(md: &Metadata) -> Option<(u32, u32)> {
    let node = dev_node(tty_dev_of(md)?)?;
    let (uid, gid, _) = node_attrs(node);
    Some((uid, gid))
}

/// A BSD pty's node name: `pty_init`'s `tty%c%x` or `pty%c%x`.
fn bsd_name(prefix: &str, minor: u32) -> String {
    format!("{prefix}{}{:x}", (b'p' + (minor / 16) as u8) as char, minor % 16)
}

/// devfs's terminal nodes by name: `ptmx`, `ttysNNN` while its slot is
/// used, and `tty`.
pub fn lookup(name: &str) -> Option<Node> {
    match name {
        "ptmx" => Some(Node::Ptmx),
        "tty" => Some(Node::Ctty),
        "console" => Some(Node::Console),
        _ if name.len() == 5 && (name.starts_with("ttyp") || name.starts_with("ptyp")) => {
            let minor = u32::from_str_radix(&name[4..], 16).ok()?;
            if minor >= ptmx::NPTY || bsd_name(&name[..3], minor) != name {
                return None;
            }
            Some(if name.starts_with("tty") { Node::Ttyp(minor) } else { Node::Ptyp(minor) })
        }
        _ => {
            let n = name.strip_prefix("ttys")?;
            if n.len() < 3 || !n.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let minor: u32 = n.parse().ok()?;
            // The template's name, `ttys%03d`, is the only one.
            if format!("ttys{minor:03}") != name {
                return None;
            }
            ptmx::pts_node(minor).map(|_| Node::Pts(minor))
        }
    }
}

/// The device a lookup of `node` gives its vnode: for `/dev/ptmx` a new
/// clone's (`ptmx_clone`).
pub fn lookup_dev(node: Node) -> u32 {
    match node {
        Node::Ptmx => makedev(PTMX_MAJOR, ptmx::ptmx_clone()),
        Node::Pts(minor) => makedev(PTSD_MAJOR, minor),
        Node::Ttyp(minor) => makedev(PTS_MAJOR, minor),
        Node::Ptyp(minor) => makedev(PTC_MAJOR, minor),
        Node::Ctty => makedev(CTTY_MAJOR, 0),
        Node::Console => makedev(CONSOLE_MAJOR, 0),
    }
}

/// devfs's listing of the terminal nodes, with their inode numbers.
pub fn list() -> Vec<(String, u64)> {
    let mut out = vec![("ptmx".to_string(), with_dev(makedev(PTMX_MAJOR, 0), |d| d.ino)), ("tty".to_string(), with_dev(makedev(CTTY_MAJOR, 0), |d| d.ino))];
    for m in 0..ptmx::NPTY {
        out.push((bsd_name("tty", m), with_dev(makedev(PTS_MAJOR, m), |d| d.ino)));
        out.push((bsd_name("pty", m), with_dev(makedev(PTC_MAJOR, m), |d| d.ino)));
    }
    for (minor, _) in ptmx::pts_nodes() {
        out.push((format!("ttys{minor:03}"), with_dev(makedev(PTSD_MAJOR, minor), |d| d.ino)));
    }
    out
}

/// The terminal a descriptor's vnode opened.
#[derive(Clone)]
pub struct Opened {
    pub cell: Arc<TtyCell>,
    /// The vnode's generation when it opened: another means a revoke has
    /// made it dead (deadfs).
    pub vid: u64,
    /// `fg_flag`'s FREAD, FWRITE, FNONBLOCK as `ttylclose` takes them.
    pub fflag: i32,
}

/// A device's close a close(2) takes on as its own call, which may sleep.
pub struct CloseJob {
    cell: Arc<TtyCell>,
    dev: u32,
    fflag: i32,
}

/// A terminal device's vnode as a descriptor holds it.
pub struct TtyDev {
    pub node: Node,
    /// `v_rdev`: a clone's own for `/dev/ptmx`.
    dev: Mutex<u32>,
    opened: Mutex<Option<Opened>>,
    procs: Mutex<Option<Arc<ProcTable>>>,
    /// A close(2) is closing it: its device's close is that call's.
    defer: std::sync::atomic::AtomicBool,
    deferred: Mutex<Option<CloseJob>>,
}

impl std::fmt::Debug for TtyDev {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TtyDev").field("node", &self.node).field("dev", &self.dev()).finish()
    }
}

impl TtyDev {
    /// A vnode from a lookup of `node`, not yet opened.
    pub fn new(node: Node) -> Arc<TtyDev> {
        Arc::new(TtyDev { node, dev: Mutex::new(lookup_dev(node)), opened: Mutex::new(None), procs: Mutex::new(None), defer: Default::default(), deferred: Mutex::new(None) })
    }

    /// `v_rdev`.
    pub fn dev(&self) -> u32 {
        *self.dev.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The terminal it opened, while its vnode is not dead.
    pub fn opened(&self) -> Option<Opened> {
        let o = self.opened.lock().unwrap_or_else(|e| e.into_inner()).clone()?;
        let live = with_dev(self.dev(), |d| d.vid) == o.vid;
        live.then_some(o)
    }

    /// Whether a revoke is reclaiming the vnode: a call that comes to it
    /// waits (`vnode_getiocount`).
    pub fn terminating(&self) -> bool {
        peek_dev(self.dev()).is_some_and(|d| d.2)
    }

    /// Whether a revoke has made the vnode dead.
    pub fn dead(&self) -> bool {
        let o = self.opened.lock().unwrap_or_else(|e| e.into_inner()).clone();
        o.is_some_and(|o| with_dev(self.dev(), |d| d.vid) != o.vid)
    }

    /// Whether `spec_open` has run for it (or, for `/dev/tty`, none is
    /// needed after the first).
    pub fn is_open(&self) -> bool {
        self.opened.lock().unwrap_or_else(|e| e.into_inner()).is_some() || (self.node == Node::Ctty && self.procs.lock().unwrap_or_else(|e| e.into_inner()).is_some())
    }

    /// Whether its device's functions are the primary's (`ptcopen`):
    /// `/dev/ptmx`'s, or a BSD pty's `ttypN`.
    pub fn primary(&self) -> bool {
        matches!(self.node, Node::Ptmx | Node::Ttyp(_))
    }

    /// `spec_open`'s success: the device's use count and the terminal.
    fn set_opened(&self, cell: Arc<TtyCell>, fflag: i32, procs: Arc<ProcTable>) {
        let dev = self.dev();
        let vid = with_dev(dev, |d| {
            d.opens += 1;
            d.vid
        });
        *self.opened.lock().unwrap_or_else(|e| e.into_inner()) = Some(Opened { cell, vid, fflag });
        *self.procs.lock().unwrap_or_else(|e| e.into_inner()) = Some(procs);
    }

    /// `devfsspec_read`'s access, or `devfsspec_write`'s change and
    /// modification, of the node.
    fn mark(&self, write: bool) {
        use super::devfs::{UPDATE_ACCESS, UPDATE_CHANGE, UPDATE_MOD};
        let flags = if write { UPDATE_CHANGE | UPDATE_MOD } else { UPDATE_ACCESS };
        if self.node == Node::Console {
            super::devfs::touch(console_node(), flags);
            return;
        }
        with_dev(node_dev(self.dev()), |d| d.times.consider(flags));
    }

    /// What `select` sees of it (the device's `d_select`): readable,
    /// writable, at EOF.
    pub fn select_ready(&self) -> (bool, bool, bool) {
        self.ready()
    }

    /// What poll and select see of it: readable, writable, at EOF.
    fn ready(&self) -> (bool, bool, bool) {
        if self.node == Node::Ctty {
            // `/dev/tty` selects its session's terminal, or is ready
            // (cttyselect's 1) with none.
            let procs = self.procs.lock().unwrap_or_else(|e| e.into_inner()).clone();
            return match procs.and_then(|p| cttyvp_of(&p, super::pipe::caller())) {
                Some(t) => t.ready(),
                None => (true, true, false),
            };
        }
        let Some(o) = self.opened() else {
            // deadfs: always ready.
            return (true, true, true);
        };
        let procs = self.procs.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let mut env = KEnv::new(procs, super::pipe::caller());
        if self.node == Node::Console {
            // cnselect: the select of the device the console's calls go
            // to now.
            let r = match km::cn_dev() {
                Ok((km::Cn::Km, _, cell)) => {
                    let mut tp = cell.lock();
                    // ttselect.
                    let r = tp.ttyselect(tty::FREAD, &mut env) > 0;
                    let w = tp.ttyselect(tty::FWRITE, &mut env) > 0;
                    (r, w, tp.ttyselect(0, &mut env) > 0)
                }
                Ok((km::Cn::Pts, _, cell)) => {
                    let mut tp = cell.lock();
                    let r = ptmx::ptsselect(&mut tp, tty::FREAD, &mut env) > 0;
                    let w = ptmx::ptsselect(&mut tp, tty::FWRITE, &mut env) > 0;
                    (r, w, tp.state & tty::ts::ZOMBIE != 0)
                }
                Err(why) => {
                    super::note_unimplemented(why);
                    (true, true, true)
                }
            };
            env.finish();
            return r;
        }
        let r = {
            let mut tp = o.cell.lock();
            if self.primary() {
                let r = ptmx::ptcselect(&mut tp, tty::FREAD) > 0;
                let w = ptmx::ptcselect(&mut tp, tty::FWRITE) > 0;
                let eof = tp.state & tty::ts::CONNECTED == 0 || tp.state & tty::ts::ZOMBIE != 0;
                (r, w, eof)
            } else {
                let r = ptmx::ptsselect(&mut tp, tty::FREAD, &mut env) > 0;
                let w = ptmx::ptsselect(&mut tp, tty::FWRITE, &mut env) > 0;
                (r, w, tp.state & tty::ts::ZOMBIE != 0)
            }
        };
        env.finish();
        r
    }

    /// For `/dev/tty`, the session terminal it stands for in this thread's
    /// process now (`cttyvp`).
    pub fn ctty_target(&self) -> Option<Arc<TtyDev>> {
        let procs = self.procs.lock().unwrap_or_else(|e| e.into_inner()).clone()?;
        cttyvp_of(&procs, super::pipe::caller())
    }

    /// `kqueue`'s view (`ptmx_kqops_common`, `ptsd_kqops_common`): ready,
    /// its data, and EV_EOF; and the revokes posted on its selinfo.
    pub fn knote(&self, read: bool) -> (bool, i64, bool, u64) {
        if self.node == Node::Ctty {
            // cttyselect: the session's terminal's, or ready with none.
            return match self.ctty_target() {
                Some(t) => t.knote(read),
                None => (true, 0, false, 0),
            };
        }
        let Some(o) = self.opened() else { return (true, 0, true, u64::MAX) };
        if self.node == Node::Console {
            // A console knote is filt_spec's, through cnselect.
            let (r, w, eof) = self.ready();
            return (if read { r } else { w }, 0, eof, 0);
        }
        let procs = self.procs.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let mut env = KEnv::new(procs, super::pipe::caller());
        let r = {
            let mut tp = o.cell.lock();
            if self.primary() {
                let revokes = tp.pti.as_ref().map_or(0, |p| if read { p.selr_revokes } else { p.selw_revokes });
                let (ready, data, eof) = ptmx::ptmx_kqops(&mut tp, read);
                (ready, data, eof, revokes)
            } else {
                let revokes = if read { tp.rsel_revokes } else { tp.wsel_revokes };
                let (ready, data, eof) = ptmx::ptsd_kqops(&mut tp, read, &mut env);
                (ready, data, eof, revokes)
            }
        };
        env.finish();
        r
    }

    /// The last close of the vnode, or a revoke: the device's `d_close`
    /// once no vnode of it is open (`spec_close`).
    fn close(&self, revoke: bool) {
        if self.node == Node::Ctty {
            // cttyclose is nulldev.
            return;
        }
        let Some(o) = self.opened.lock().unwrap_or_else(|e| e.into_inner()).take() else { return };
        let dev = self.dev();
        let (live, last) = with_dev(dev, |d| {
            if d.vid != o.vid {
                // Dead already: the revoke closed it.
                return (false, false);
            }
            d.opens = d.opens.saturating_sub(1);
            (true, d.opens == 0)
        });
        if !live {
            return;
        }
        let procs = self.procs.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let caller = super::pipe::caller();
        // A controlling terminal's last vnode closed by a process of its
        // session: the session loses it.
        if last {
            if let Some(p) = procs.as_ref() {
                if let Ok(sid) = p.sid(caller, caller) {
                    let s = ctty::session(sid, None);
                    let mut st = s.lock();
                    if st.ttyvp.is_some_and(|v| v.dev == dev && v.vid == o.vid) {
                        st.clear_tty();
                    }
                }
            }
        }
        if last || revoke {
            // A replica's close a close(2) is making waits as that call.
            if !revoke && !self.primary() && self.defer.load(Ordering::Acquire) {
                *self.deferred.lock().unwrap_or_else(|e| e.into_inner()) = Some(CloseJob { cell: o.cell, dev, fflag: o.fflag });
                return;
            }
            d_close(&o.cell, dev, o.fflag, revoke, procs, caller);
        }
    }
}

/// The device's `d_close` outside any call that can wait as a thread does
/// (an exit, a descriptor replaced): the drain sleeps here, at most its
/// timeout.
fn d_close(cell: &Arc<TtyCell>, dev: u32, fflag: i32, revoke: bool, procs: Option<Arc<ProcTable>>, caller: i32) {
    let mut env = KEnv::new(procs, caller);
    let flag = if revoke { fflag | tty::FNONBLOCK } else { fflag };
    if dev >> 24 == CONSOLE_MAJOR {
        // cnclose: the close of the device the console's calls go to now.
        match km::cn_dev() {
            Ok((km::Cn::Km, _, k)) => {
                let mut resumed = None;
                while let Io::Sleep(req) = km::kmclose(&k, flag, &mut env, resumed.take()) {
                    resumed = Some((req, sync_sleep(&k, &req)));
                }
            }
            Ok((km::Cn::Pts, pdev, c)) => pts_close_now(&c, pdev, flag, revoke, &mut env),
            Err(why) => super::note_unimplemented(why),
        }
    } else if ptmx::is_ptc(dev) {
        ptmx::ptcclose(cell, dev, &mut env);
    } else {
        pts_close_now(cell, dev, flag, revoke, &mut env);
    }
    env.finish();
}

/// `ptsclose`, its drain's sleeps taken here and now.
fn pts_close_now(cell: &Arc<TtyCell>, dev: u32, flag: i32, revoke: bool, env: &mut KEnv) {
    let mut st = ptmx::PtsClose::default();
    let mut resumed = None;
    while let Io::Sleep(req) = ptmx::ptsclose(cell, dev, flag, revoke, env, &mut st, resumed.take()) {
        resumed = Some((req, sync_sleep(cell, &req)));
    }
}

/// A sleep on the terminal's channel taken here and now: woken, or out of
/// time.
fn sync_sleep(cell: &Arc<TtyCell>, req: &SleepReq) -> Woke {
    let w = Arc::new(tty::SyncWake::default());
    let token = cell.lock().enqueue_sync(req, Arc::clone(&w));
    let until = (req.timo > 0).then(|| Instant::now() + Duration::from_millis(req.timo as u64 * 1000 / tty::HZ as u64));
    let woke = if w.wait(until) { Woke::Awakened } else { Woke::TimedOut };
    cell.lock().unsleep(token);
    woke
}

/// `cttyvp(p)`: the vnode of `pid`'s session's terminal while it has
/// P_CONTROLT, and while that vnode is not revoked.
fn cttyvp_of(procs: &ProcTable, pid: i32) -> Option<Arc<TtyDev>> {
    if !procs.controlt(pid) {
        return None;
    }
    let sid = procs.sid(pid, pid).ok()?;
    let s = ctty::session(sid, None);
    let v = s.lock().ttyvp?;
    ttyvp_handle(&v)
}

impl FileHandle for TtyDev {
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> crate::errno::SysResult {
        // A Darwin read of a terminal is the line discipline's
        // ([`Kernel::darwin_tty_rw`]).
        Err(Errno::ENXIO)
    }

    fn write_at(&self, _offset: u64, _buf: &[u8]) -> crate::errno::SysResult {
        Err(Errno::ENXIO)
    }

    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(node_metadata(self.node, self.dev()))
    }

    fn is_stream(&self) -> bool {
        true
    }

    fn is_tty(&self) -> bool {
        true
    }

    fn poll_readable(&self) -> bool {
        self.ready().0
    }

    fn poll_writable(&self) -> bool {
        self.ready().1
    }

    fn poll_hup(&self) -> bool {
        self.ready().2
    }

    fn wait_queue(&self) -> u32 {
        if self.node == Node::Ctty {
            return self.ctty_target().map_or(0, |t| t.wait_queue());
        }
        let Some(o) = self.opened() else { return 0 };
        if self.node == Node::Console {
            return km::cn_dev().map_or(0, |(_, _, cell)| cell.lock().rsel.id());
        }
        let tp = o.cell.lock();
        if self.primary() {
            tp.pti.as_ref().map_or(0, |p| p.selr.id())
        } else {
            tp.rsel.id()
        }
    }

    fn wakes(&self) -> Option<u64> {
        if self.node == Node::Ctty {
            return self.ctty_target().and_then(|t| t.wakes());
        }
        let o = self.opened()?;
        if self.node == Node::Console {
            let (_, _, cell) = km::cn_dev().ok()?;
            let tp = cell.lock();
            return Some(tp.rsel.wakes() + tp.wsel.wakes());
        }
        let tp = o.cell.lock();
        if self.primary() {
            tp.pti.as_ref().map(|p| p.selr.wakes() + p.selw.wakes())
        } else {
            Some(tp.rsel.wakes() + tp.wsel.wakes())
        }
    }

    fn darwin_tty(self: Arc<Self>) -> Option<Arc<TtyDev>> {
        Some(self)
    }

    fn vn_close(&self) {
        self.close(false);
    }
}

/// The vnode of the session terminal `v`, as `/dev/tty` reaches it: a new
/// vnode of the device, opened as that one was.
fn ttyvp_handle(v: &TtyVnode) -> Option<Arc<TtyDev>> {
    let node = dev_node(v.dev).filter(|n| *n != Node::Ctty)?;
    if with_dev(v.dev, |d| d.vid) != v.vid {
        // Revoked: vnode_getwithvid fails.
        return None;
    }
    let slot_tty = dev_tty(v.dev)?;
    let h = Arc::new(TtyDev { node, dev: Mutex::new(v.dev), opened: Mutex::new(None), procs: Mutex::new(None), defer: Default::default(), deferred: Mutex::new(None) });
    *h.opened.lock().unwrap_or_else(|e| e.into_inner()) = Some(Opened { cell: slot_tty, vid: v.vid, fflag: tty::FREAD | tty::FWRITE });
    Some(h)
}

/// The terminal a call on device `dev`'s vnode reaches: its pty's, or for
/// the console the one its calls go to now.
fn dev_tty(dev: u32) -> Option<Arc<TtyCell>> {
    if dev >> 24 == CONSOLE_MAJOR {
        return km::cn_dev().ok().map(|(_, _, cell)| cell);
    }
    match ptmx::get_ioctl(dev, 0) {
        ptmx::Got::Tty(t) => Some(t),
        _ => None,
    }
}

/// The line discipline's view of the kernel: the process table, the
/// signals to post once the terminal is unlocked, and what the call could
/// not do.
pub struct KEnv {
    procs: Option<Arc<ProcTable>>,
    pid: i32,
    pg: Vec<(Pgrp, u32, bool)>,
    ps: Vec<(i32, u32)>,
    controlt: bool,
    /// `namei` of the replica's name for a grant, looked up beforehand.
    pub namei: Option<Result<(), Errno>>,
    /// The caller is root, for `suser(cred, &p->p_acflag)`; and whether
    /// the check ran and succeeded, for its ASU.
    pub root: bool,
    pub used_root: bool,
    /// What the call met that is not modelled.
    pub unimplemented: Vec<String>,
}

impl KEnv {
    pub fn new(procs: Option<Arc<ProcTable>>, pid: i32) -> KEnv {
        KEnv { procs, pid, pg: Vec::new(), ps: Vec::new(), controlt: false, namei: None, root: false, used_root: false, unimplemented: Vec::new() }
    }

    /// The signals posted, the caller's P_CONTROLT set: what waited for the
    /// terminal's lock to go.
    pub fn finish(&mut self) {
        let Some(procs) = self.procs.clone() else { return };
        for (pg, s, checkctty) in self.pg.drain(..) {
            let l = super::kern::signal_to_linux(s);
            if l != 0 {
                procs.pgsignal(pg.id, pg.serial, l, checkctty);
            }
        }
        for (pid, s) in self.ps.drain(..) {
            let l = super::kern::signal_to_linux(s);
            if l != 0 {
                procs.post_kernel(pid, l);
            }
        }
        if std::mem::take(&mut self.controlt) {
            procs.set_controlt(self.pid, true);
        }
    }
}

impl Env for KEnv {
    fn pgsignal(&mut self, pg: Pgrp, signum: u32, checkctty: bool) {
        self.pg.push((pg, signum, checkctty));
    }

    fn psignal(&mut self, pid: i32, signum: u32) {
        self.ps.push((pid, signum));
    }

    fn pgrp_find(&mut self, pgid: i32) -> Option<(Pgrp, Arc<Session>)> {
        let procs = self.procs.as_ref()?;
        let serial = procs.pgrp_serial(pgid)?;
        let sid = procs.pgrp_sid(pgid)?;
        Some((Pgrp { id: pgid, serial }, ctty::session(sid, None)))
    }

    fn loadavg(&mut self) -> Option<u32> {
        let Some(procs) = self.procs.as_ref() else {
            self.unimplemented.push("the load average a terminal's status line prints, with no process table to count from".into());
            return None;
        };
        match procs.darwin_loadavg() {
            Ok(l) => Some(l[0]),
            Err(why) => {
                self.unimplemented.push(why.into());
                None
            }
        }
    }

    fn fg_pick(&mut self, pg: Pgrp) -> Option<i32> {
        let procs = self.procs.as_ref()?;
        if procs.pgrp_serial(pg.id) != Some(pg.serial) {
            return None;
        }
        // proc_compare over the members (zombies too): a runnable one
        // (SRUN) over the rest, a live one over a zombie, else the highest
        // pid (estcpu and slptime are not kept: _PROC_HAS_SCHEDINFO_ is
        // off).
        let mut pick: Option<(i32, bool, bool)> = None;
        for (pid, _, _, live) in procs.pgrp_members(pg.id) {
            let stopped = live && procs.job(pid).is_some_and(|j| j.lock().unwrap_or_else(|e| e.into_inner()).stopped);
            let (run, zomb) = (live && !stopped, !live);
            let better = match pick {
                None => true,
                Some((p1, run1, zomb1)) => match (run1, run) {
                    (true, false) => false,
                    (false, true) => true,
                    (true, true) => pid > p1,
                    (false, false) => match (zomb1, zomb) {
                        (true, false) => true,
                        (false, true) => false,
                        _ => pid > p1,
                    },
                },
            };
            if better {
                pick = Some((pid, run, zomb));
            }
        }
        pick.map(|p| p.0)
    }

    fn fg_info(&mut self, pid: i32) -> Option<Result<FgInfo, ()>> {
        let Some(procs) = self.procs.clone() else {
            self.unimplemented.push("a terminal's status line's foreground process, with no process table to find it in".into());
            return None;
        };
        if procs.is_shared() {
            self.unimplemented.push("a terminal's status line's foreground process in another of the browser's Workers".into());
            return None;
        }
        // proc_find: nothing for a process that is gone, or a zombie.
        let (record, zombie) = procs.darwin(pid)?;
        if zombie {
            return None;
        }
        let public = record.downcast::<super::procinfo::Public>().ok()?;
        // p_uthlist's first: its oldest thread.
        let Some(threads) = public.threads.clone() else { return Some(Err(())) };
        let Some(&first) = threads.tids_in_order().first() else { return Some(Err(())) };
        // thread_info's run state; a thread that has not yet come into the
        // kernel is running.
        let run_state = procs.sched.state(first).map_or(1, super::sched::RunState::th_state);
        let Some(live) = crate::cpu::live_times(&threads) else {
            self.unimplemented.push("a terminal's status line's process times on a host without per-thread clocks".into());
            return None;
        };
        let [u, s] = crate::cpu::calcru(procs.dead_cpu(pid), &live);
        Some(Ok(FgInfo {
            comm: String::from_utf8_lossy(&public.comm).into_owned(),
            pid,
            run_state,
            utime: (u.0 as i64, u.1 as i32),
            stime: (s.0 as i64, s.1 as i32),
        }))
    }

    fn set_controlt(&mut self) {
        self.controlt = true;
    }

    fn session_leader(&mut self, s: &Arc<Session>) -> Option<i32> {
        s.lock().leader
    }

    fn namei(&mut self, _path: &str) -> Result<(), Errno> {
        self.namei.unwrap_or(Err(Errno::ENOENT))
    }

    fn suser_acflag(&mut self) -> bool {
        if self.root {
            self.used_root = true;
        }
        self.root
    }
}

/// A uio over the caller's vectors: where it is in them across sleeps.
#[derive(Clone, Debug, Default)]
pub struct Iov {
    iov: Vec<(u64, u64)>,
    total: usize,
    /// Bytes moved so far.
    pos: usize,
}

impl Iov {
    fn new(iov: Vec<(u64, u64)>) -> Iov {
        let total = iov.iter().map(|v| v.1 as usize).sum();
        Iov { iov, total, pos: 0 }
    }

    /// The (address, length) pieces from `pos` for `n` bytes.
    fn pieces(&self, n: usize) -> Vec<(u64, usize)> {
        let mut out = Vec::new();
        let (mut skip, mut left) = (self.pos, n);
        for &(base, len) in &self.iov {
            let len = len as usize;
            if skip >= len {
                skip -= len;
                continue;
            }
            let take = (len - skip).min(left);
            out.push((base + skip as u64, take));
            left -= take;
            skip = 0;
            if left == 0 {
                break;
            }
        }
        out
    }
}

struct GuestUio<'a, 'b> {
    m: &'a mut GuestMem<'b>,
    c: &'a mut Iov,
}

impl Uio for GuestUio<'_, '_> {
    fn resid(&self) -> usize {
        self.c.total - self.c.pos
    }

    fn move_out(&mut self, b: &[u8]) -> Result<(), Errno> {
        let mut at = 0;
        for (addr, n) in self.c.pieces(b.len()) {
            self.m.write(addr, &b[at..at + n]).map_err(|_| Errno::EFAULT)?;
            at += n;
        }
        self.c.pos += at;
        Ok(())
    }

    fn move_in(&mut self, n: usize) -> Result<Vec<u8>, Errno> {
        let mut v = Vec::with_capacity(n);
        for (addr, k) in self.c.pieces(n) {
            v.extend_from_slice(self.m.read(addr, k).map_err(|_| Errno::EFAULT)?);
        }
        self.c.pos += v.len();
        Ok(v)
    }

    fn give_back(&mut self, n: usize) {
        self.c.pos -= n;
    }

    fn finish(&mut self) {
        self.c.pos = self.c.total;
    }
}

/// A terminal call asleep: what it goes on with.
#[derive(Debug)]
pub enum Op {
    Read { fd: i32, iov: Iov, st: tty::ReadState },
    Write { fd: i32, iov: Iov, st: tty::WriteState, ptc: ptmx::PtcWrite },
    Ioctl { fd: i32, com: u64, data: Vec<u8>, udata: u64, st: ptmx::PtyIoctl },
    Open { fd: i32, dflags: u64, pdev: u32, st: ptmx::PtsOpen },
    Close { pdev: u32, fflag: i32, st: ptmx::PtsClose },
    /// `revoke(2)`'s drain of the vnode.
    Revoke { r: Revoking },
}

/// A sleeping call, its terminal, the sleep and the thread's place on the
/// channel.
pub struct Pending {
    op: Op,
    dev: Arc<TtyDev>,
    cell: Arc<TtyCell>,
    req: SleepReq,
    token: u64,
    /// The vnode the call sleeps in.
    via: Option<tty::Vnode>,
}

impl std::fmt::Debug for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pending").field("op", &self.op).field("req", &self.req).finish()
    }
}

/// `UIO_MAXIOV`.
const UIO_MAXIOV: u64 = 1024;

/// Darwin's `FREAD`, `FWRITE` and `FNONBLOCK` of an open file.
fn fflag(file: &OpenFile) -> i32 {
    let mut f = 0;
    if file.readable {
        f |= tty::FREAD;
    }
    if file.writable {
        f |= tty::FWRITE;
    }
    if file.flags() & crate::fs::oflags::O_NONBLOCK != 0 {
        f |= tty::FNONBLOCK;
    }
    f
}

impl Kernel {
    /// The terminal device descriptor `fd` is, if it is one.
    pub(crate) fn darwin_tty_of(&self, fd: u64) -> Option<(Arc<OpenFile>, Arc<TtyDev>)> {
        let file = self.fds.get(fd as i32).ok()?;
        let dev = Arc::clone(&file.handle).darwin_tty()?;
        Some((file, dev))
    }

    /// The device `/dev/tty` stands for in this call: the session's
    /// terminal while the process has it (`cttyvp`).
    fn darwin_cttyvp(&self) -> Option<Arc<TtyDev>> {
        cttyvp_of(&self.procs, self.pid)
    }

    /// `forkproc`: the child has the terminal as its parent does, while
    /// the session has one.
    pub(crate) fn darwin_fork_controlt(&self, child: i32) {
        if !self.procs.controlt(self.pid) {
            return;
        }
        let Ok(sid) = self.procs.sid(self.pid, self.pid) else { return };
        if ctty::session(sid, None).lock().ttyvp.is_some() {
            self.procs.set_controlt(child, true);
        }
    }

    /// The process as the line discipline sees it.
    pub(crate) fn darwin_tty_caller(&self) -> Caller {
        use super::signal::{dsig, sigmask};
        let pid = self.pid;
        let pgid = self.procs.pgid(pid, pid).unwrap_or(pid);
        let sid = self.procs.sid(pid, pid).unwrap_or(pid);
        let leader = (sid == pid).then_some(pid);
        let blocked = self.signals.blocked();
        let masked = |d: u32| {
            let l = super::kern::signal_to_linux(d);
            l != 0 && blocked & (1u64 << (l - 1)) != 0
        };
        let ign = self.dtask.sigacts.sigignore;
        Caller {
            pid,
            pgrp: self.procs.pgrp_serial(pgid).map(|serial| Pgrp { id: pgid, serial }),
            pg_jobc: self.procs.jobc(pgid),
            session: Some(ctty::session(sid, leader)),
            controlt: self.procs.controlt(pid),
            ttin_ignored: ign & sigmask(dsig::SIGTTIN) != 0,
            ttin_masked: masked(dsig::SIGTTIN),
            ttou_ignored: ign & sigmask(dsig::SIGTTOU) != 0,
            ttou_masked: masked(dsig::SIGTTOU),
            // No vfork parent waits here: vfork is fork's.
            lppwait: false,
            suser: self.dtask.cred.uid == 0,
            uid: self.dtask.cred.uid,
        }
    }

    fn darwin_tty_env(&self) -> KEnv {
        let mut env = KEnv::new(Some(Arc::clone(&self.procs)), self.pid);
        env.root = self.dtask.cred.uid == 0;
        env
    }

    /// What the call's environment owes once the terminal is unlocked.
    fn darwin_tty_env_done(&mut self, mut env: KEnv) {
        env.finish();
        if env.used_root {
            self.dtask.live.acflag.fetch_or(super::kinfo::ac::ASU, Ordering::Relaxed);
        }
        for what in env.unimplemented.drain(..) {
            self.darwin_unimplemented(what);
        }
    }

    /// `spec_open` of a terminal node an open just found: the device's
    /// open, which may sleep (a replica waiting for its carrier).
    pub(crate) fn darwin_tty_open(&mut self, m: &mut GuestMem<'_>, fd: i32, dflags: u64) -> Option<SyscallOutcome> {
        let (file, dev) = self.darwin_tty_of(fd as u64)?;
        if dev.opened.lock().unwrap_or_else(|e| e.into_inner()).is_some() {
            return None;
        }
        let ff = fflag(&file);
        // vn_authorize_open_existing: the node's owner, group and mode.
        if let Err(e) = self.darwin_node_access(node_attrs(dev.node), file.readable, file.writable) {
            return Some(self.darwin_tty_open_end(m, fd, dflags, Err(e)));
        }
        let r = match dev.node {
            Node::Pts(_) | Node::Ptyp(_) => {
                let pdev = dev.dev();
                return Some(self.darwin_pts_open(m, fd, dflags, dev, pdev, ptmx::PtsOpen::default(), None));
            }
            Node::Console => match self.darwin_cn_dev() {
                // cnopen: the d_open of the console's terminal, a pty
                // replica's (which may wait for its carrier).
                Ok((Drv::Pts, pdev, _)) => return Some(self.darwin_pts_open(m, fd, dflags, dev, pdev, ptmx::PtsOpen::default(), None)),
                Ok((_, kdev, _)) => self.darwin_kmopen(&dev, kdev, ff),
                Err(e) => Err(e),
            },
            _ => self.darwin_tty_open_primary(&dev, ff),
        };
        Some(self.darwin_tty_open_end(m, fd, dflags, r))
    }

    /// The device `/dev/console`'s calls go to now (`cn_dev`), reported
    /// when it is one the console cannot reach.
    fn darwin_cn_dev(&mut self) -> Result<(Drv, u32, Arc<TtyCell>), Errno> {
        match km::cn_dev() {
            Ok((km::Cn::Km, d, c)) => Ok((Drv::Km, d, c)),
            Ok((km::Cn::Pts, d, c)) => Ok((Drv::Pts, d, c)),
            Err(why) => {
                self.darwin_unimplemented(why);
                Err(Errno::ENXIO)
            }
        }
    }

    /// cnopen's `kmopen` of km's device `kdev` for the console's vnode.
    fn darwin_kmopen(&mut self, dev: &Arc<TtyDev>, kdev: u32, ff: i32) -> Result<(), Errno> {
        let mut env = self.darwin_tty_env();
        let r = km::kmopen(kdev, &mut env).map(|cell| dev.set_opened(cell, ff, Arc::clone(&self.procs)));
        self.darwin_tty_env_done(env);
        r
    }

    /// The open of a node that never sleeps in it: a primary (ptmx's, made
    /// again with a new clone as vn_open redrives it; a BSD pty's
    /// `ttypN`), or `/dev/tty`.
    fn darwin_tty_open_primary(&mut self, dev: &Arc<TtyDev>, ff: i32) -> Result<(), Errno> {
        match dev.node {
            Node::Ptmx => {
                let mut env = self.darwin_tty_env();
                let r = ptmx::ptmx_open(&mut env).map(|(minor, cell)| {
                    *dev.dev.lock().unwrap_or_else(|e| e.into_inner()) = makedev(PTMX_MAJOR, minor);
                    pts_node_made(minor);
                    dev.set_opened(cell, ff, Arc::clone(&self.procs));
                });
                self.darwin_tty_env_done(env);
                r
            }
            Node::Ttyp(_) => {
                let mut env = self.darwin_tty_env();
                let r = ptmx::ptcopen(dev.dev(), &mut env).map(|cell| dev.set_opened(cell, ff, Arc::clone(&self.procs)));
                self.darwin_tty_env_done(env);
                r
            }
            Node::Ctty => self.darwin_cttyopen(dev, ff),
            Node::Pts(_) | Node::Ptyp(_) | Node::Console => unreachable!("a replica's open is ptsopen's, the console's cnopen's"),
        }
    }

    /// `spec_open` of a terminal node where the open cannot wait (a
    /// spawn's PSFA_OPEN in the child): a replica whose primary is gone
    /// would sleep for its carrier there, which is reported.
    pub(crate) fn darwin_tty_open_now(&mut self, fd: i32) -> Result<(), Errno> {
        let Some((file, dev)) = self.darwin_tty_of(fd as u64) else { return Ok(()) };
        if dev.is_open() {
            return Ok(());
        }
        let ff = fflag(&file);
        self.darwin_node_access(node_attrs(dev.node), file.readable, file.writable)?;
        let pdev = match dev.node {
            Node::Pts(_) | Node::Ptyp(_) => Some(dev.dev()),
            Node::Console => match self.darwin_cn_dev()? {
                (Drv::Pts, pdev, _) => Some(pdev),
                (_, kdev, _) => return self.darwin_kmopen(&dev, kdev, ff),
            },
            _ => None,
        };
        match pdev {
            Some(pdev) => {
                let p = self.darwin_tty_caller();
                let mut env = self.darwin_tty_env();
                let mut st = ptmx::PtsOpen::default();
                let r = ptmx::ptsopen(pdev, ff, &p, &mut env, &mut st, None);
                self.darwin_tty_env_done(env);
                match r {
                    Io::Done(Ok(cell)) => {
                        dev.set_opened(cell, ff, Arc::clone(&self.procs));
                        Ok(())
                    }
                    Io::Done(Err(e)) => Err(e),
                    Io::Sleep(_) => {
                        ptmx::free_ioctl(pdev, ptmx::pf::OPEN_S);
                        self.darwin_unimplemented("a spawn's PSFA_OPEN of a terminal replica waiting for its primary (ptsopen's sleep in the child)".into());
                        Err(Errno::EIO)
                    }
                }
            }
            None => self.darwin_tty_open_primary(&dev, ff),
        }
    }

    /// `vn_open` of a devfs node of [`super::devfs`]'s: its owner, group
    /// and mode checked, then the device's open, which for a device not
    /// modelled is reported.
    pub(crate) fn darwin_devnode_open(&mut self, fd: i32) -> Result<(), Errno> {
        let Ok(file) = self.fds.get(fd) else { return Ok(()) };
        let Some(n) = file.handle.darwin_devnode() else { return Ok(()) };
        self.darwin_node_access((n.uid, n.gid, n.mode), file.readable, file.writable)?;
        if let super::devfs::Kind::Unmodelled(what) = n.kind {
            self.darwin_unimplemented(format!("opening /dev/{}: {what}", n.name));
            return Err(Errno::ENXIO);
        }
        Ok(())
    }

    /// open1's end for a terminal: one opened without O_NOCTTY by a
    /// process with no controlling terminal becomes its own if it can
    /// (TIOCSCTTY through `fo_ioctl`, whose error is ignored: a process
    /// that is no session leader keeps none).
    pub(crate) fn darwin_open_ctty(&mut self, fd: i32, dflags: u64) {
        const O_NOCTTY: u64 = 0x2_0000;
        if dflags & O_NOCTTY != 0 || self.procs.controlt(self.pid) {
            return;
        }
        let Some((file, dev)) = self.darwin_tty_of(fd as u64) else { return };
        let mut d = [0u8; 8];
        let _ = self.darwin_tty_vn_ioctl(&dev, &file, tty::cmd::TIOCSCTTY, &mut d);
    }

    /// The open's end: the descriptor, or the error with the descriptor
    /// closed.
    fn darwin_tty_open_end(&mut self, m: &mut GuestMem<'_>, fd: i32, dflags: u64, r: Result<(), Errno>) -> SyscallOutcome {
        match r {
            // open1's lock, after vn_open: a terminal's vnode takes none
            // (spec_advlock is err_advlock), so the open fails there.
            Ok(()) if dflags & super::guarded::O_LOCKS != 0 => self.darwin_open_finish_locks(m, fd, dflags),
            Ok(()) => {
                self.darwin_open_ctty(fd, dflags);
                self.darwin_open_finish_locks(m, fd, dflags)
            }
            Err(e) => {
                let _ = self.fds.close(fd);
                let _ = super::set_result(m, self.ctx_addr, e.as_return());
                SyscallOutcome::Continue
            }
        }
    }

    /// `ptsopen` through the open of `fd`.
    #[allow(clippy::too_many_arguments)]
    fn darwin_pts_open(&mut self, m: &mut GuestMem<'_>, fd: i32, dflags: u64, dev: Arc<TtyDev>, pdev: u32, mut st: ptmx::PtsOpen, resumed: Option<(SleepReq, Woke)>) -> SyscallOutcome {
        let file = match self.fds.get(fd) {
            Ok(f) => f,
            Err(e) => {
                let _ = super::set_result(m, self.ctx_addr, e.as_return());
                return SyscallOutcome::Continue;
            }
        };
        let flag = fflag(&file);
        let p = self.darwin_tty_caller();
        let mut env = self.darwin_tty_env();
        let r = ptmx::ptsopen(pdev, flag, &p, &mut env, &mut st, resumed);
        self.darwin_tty_env_done(env);
        match r {
            Io::Done(Ok(cell)) => {
                dev.set_opened(cell, flag, Arc::clone(&self.procs));
                self.darwin_tty_open_end(m, fd, dflags, Ok(()))
            }
            Io::Done(Err(e)) => self.darwin_tty_open_end(m, fd, dflags, Err(e)),
            Io::Sleep(req) => {
                let cell = match ptmx::get_ioctl(pdev, 0) {
                    ptmx::Got::Tty(t) => t,
                    _ => return self.darwin_tty_open_end(m, fd, dflags, Err(Errno::ENXIO)),
                };
                self.darwin_tty_sleep(m, Op::Open { fd, dflags, pdev, st }, dev, cell, req)
            }
        }
    }

    /// `vnode_authorize` of a read and/or write of a devfs node by its
    /// owner, group and mode: root may; else the owner's bits, a member's
    /// of its group, or everyone's.
    pub(crate) fn darwin_node_access(&self, (uid, gid, mode): (u32, u32, u32), read: bool, write: bool) -> Result<(), Errno> {
        let c = &self.dtask.cred;
        if c.uid == 0 {
            return Ok(());
        }
        let bits = if c.uid == uid {
            mode >> 6
        } else if c.gid() == gid || c.groups.contains(&gid) {
            mode >> 3
        } else {
            mode
        };
        if (read && bits & 4 == 0) || (write && bits & 2 == 0) {
            return Err(Errno::EACCES);
        }
        Ok(())
    }

    /// `cttyopen`: the session's terminal opened for it once (S_CTTYREF),
    /// ENXIO without one.
    fn darwin_cttyopen(&mut self, dev: &Arc<TtyDev>, ff: i32) -> Result<(), Errno> {
        let Some(tv) = self.darwin_cttyvp() else { return Err(Errno::ENXIO) };
        let sid = self.procs.sid(self.pid, self.pid).map_err(|_| Errno::ENXIO)?;
        let s = ctty::session(sid, None);
        let first = !s.lock().cttyref;
        if first {
            // VNOP_OPEN of the terminal's vnode, and the vnode_ref that
            // keeps it open until the session leader's exit revokes it.
            let o = tv.opened().ok_or(Errno::ENXIO)?;
            let pdev = match tv.node {
                // cnopen: kmopen, or the console's pty's ptsopen.
                Node::Console => match self.darwin_cn_dev()? {
                    (Drv::Pts, pdev, _) => Some(pdev),
                    (_, kdev, _) => {
                        let mut env = self.darwin_tty_env();
                        let r = km::kmopen(kdev, &mut env);
                        self.darwin_tty_env_done(env);
                        r?;
                        None
                    }
                },
                _ if tv.primary() => None,
                _ => Some(tv.dev()),
            };
            if tv.primary() {
                let tp = o.cell.lock();
                if tp.oproc != tty::Oproc::None || tp.state & tty::ts::ISOPEN != 0 {
                    // ptcopen of an open primary: EBUSY.
                    return Err(Errno::EBUSY);
                }
                drop(tp);
            } else if let Some(pdev) = pdev {
                let p = self.darwin_tty_caller();
                let mut env = self.darwin_tty_env();
                let mut st = ptmx::PtsOpen::default();
                let r = ptmx::ptsopen(pdev, ff | tty::FNONBLOCK, &p, &mut env, &mut st, None);
                self.darwin_tty_env_done(env);
                match r {
                    Io::Done(Ok(_)) => {}
                    Io::Done(Err(e)) => return Err(e),
                    Io::Sleep(_) => unreachable!("a non-blocking replica open never sleeps"),
                }
            }
            let mut st = s.lock();
            if st.cttyref {
                // Another open set it first: this one's open is closed.
                drop(st);
                tv.close(false);
            } else {
                st.cttyref = true;
                drop(st);
                with_dev(tv.dev(), |d| d.opens += 1);
            }
        }
        *dev.procs.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::clone(&self.procs));
        Ok(())
    }

    /// Queue the thread on the terminal's channel and wait: the call goes
    /// on in [`Self::darwin_tty_wait_done`].
    fn darwin_tty_sleep(&mut self, m: &mut GuestMem<'_>, op: Op, dev: Arc<TtyDev>, cell: Arc<TtyCell>, req: SleepReq) -> SyscallOutcome {
        // A call asleep in the terminal's vnode keeps its iocount; a call
        // waiting to come into one, or a revoke's drain, has none.
        let via = if matches!(op, Op::Revoke { .. }) || req.chan == tty::Chan::Reclaim { None } else { self.darwin_tty_vnode(&dev) };
        let token = cell.lock().enqueue(&req, self.darwin_waker(), via);
        self.dtask.ttyops.insert(self.tid, Pending { op, dev, cell, req, token, via });
        let deadline = (req.timo > 0).then(|| super::wait::deadline_in(Duration::from_millis(req.timo as u64 * 1000 / tty::HZ as u64)));
        self.darwin_block(m, Wait { deadline, cont: Finish::Tty })
    }

    /// A terminal call's sleep ended: it goes on from its `ttysleep`.
    pub(crate) fn darwin_tty_wait_done(&mut self, m: &mut GuestMem<'_>, res: WaitResult) -> Option<SyscallOutcome> {
        let Pending { op, dev, cell, req, token, via } = self.dtask.ttyops.remove(&self.tid)?;
        // Back in its call, it is in the vnode as a running call before it
        // stops being a sleeper in it.
        let _io = via.map(|v| IoRef::enter(&cell, v));
        cell.lock().unsleep(token);
        let woke = match res {
            WaitResult::Awakened => Woke::Awakened,
            WaitResult::TimedOut => Woke::TimedOut,
            // PCATCH: ERESTART for a signal whose action restarts calls.
            WaitResult::Interrupted | WaitResult::Restart => {
                Woke::Interrupted(if self.signals.restarts(crate::signal::Restart::SaRestart) { tty::ERESTART } else { Errno::EINTR })
            }
        };
        let resumed = Some((req, woke));
        Some(match op {
            Op::Read { fd, iov, st } => self.darwin_tty_read_step(m, fd, dev, iov, st, resumed, Some(cell)),
            Op::Write { fd, iov, st, ptc } => self.darwin_tty_write_step(m, fd, dev, iov, st, ptc, resumed, Some(cell)),
            Op::Ioctl { fd, com, data, udata, st } => self.darwin_tty_ioctl_step(m, fd, dev, com, data, udata, st, resumed, Some(cell)),
            Op::Open { fd, dflags, pdev, st } => self.darwin_pts_open(m, fd, dflags, dev, pdev, st, resumed),
            Op::Close { pdev, fflag, st } => self.darwin_pts_close_step(m, dev, cell, pdev, fflag, st, resumed),
            Op::Revoke { r } => self.darwin_revoke_step(m, dev, cell, r),
        })
    }

    /// `close` of a replica's or the console's descriptor: the descriptor
    /// goes, and if that was the device's last open file, its close runs
    /// as this call, draining the output as long as it may (`ttylclose`).
    pub(crate) fn darwin_tty_close(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> SyscallOutcome {
        let Some((_, dev)) = self.darwin_tty_of(a[0]) else { return self.darwin_tty_result(m, Err(Errno::EBADF)) };
        if self.dtask.ladvlock {
            // The process's POSIX locks on it go first.
            self.darwin_closing(a[0] as i32);
        }
        dev.defer.store(true, Ordering::Release);
        let r = self.canonical(m, crate::syscalls::nr::CLOSE, [a[0], 0, 0, 0, 0, 0]);
        dev.defer.store(false, Ordering::Release);
        if let Err(e) = r {
            return self.darwin_tty_result(m, Err(e));
        }
        let job = dev.deferred.lock().unwrap_or_else(|e| e.into_inner()).take();
        let Some(j) = job else { return self.darwin_tty_result(m, Ok(0)) };
        // cnclose: the close of the device the console's calls go to now.
        let (cell, pdev) = if j.dev >> 24 == CONSOLE_MAJOR {
            match self.darwin_cn_dev() {
                Ok((_, pdev, cell)) => (cell, pdev),
                Err(_) => return self.darwin_tty_result(m, Ok(0)),
            }
        } else {
            (j.cell, j.dev)
        };
        self.darwin_pts_close_step(m, dev, cell, pdev, j.fflag, ptmx::PtsClose::default(), None)
    }

    /// A device's last close as a close(2) (`ptsclose`, or the console's
    /// `kmclose`), until it ends or sleeps; the call's result is 0
    /// (`ttylclose`'s).
    #[allow(clippy::too_many_arguments)]
    fn darwin_pts_close_step(&mut self, m: &mut GuestMem<'_>, dev: Arc<TtyDev>, cell: Arc<TtyCell>, pdev: u32, fflag: i32, mut st: ptmx::PtsClose, resumed: Option<(SleepReq, Woke)>) -> SyscallOutcome {
        let mut env = self.darwin_tty_env();
        let r = if km::is_km(&cell) { km::kmclose(&cell, fflag, &mut env, resumed) } else { ptmx::ptsclose(&cell, pdev, fflag, false, &mut env, &mut st, resumed) };
        self.darwin_tty_env_done(env);
        match r {
            Io::Done(_) => self.darwin_tty_result(m, Ok(0)),
            Io::Sleep(req) => self.darwin_tty_sleep(m, Op::Close { pdev, fflag, st }, dev, cell, req),
        }
    }

    /// A call's end: its result, or its restart (ERESTART).
    fn darwin_tty_result(&mut self, m: &mut GuestMem<'_>, r: Result<u64, Errno>) -> SyscallOutcome {
        match r {
            Err(e) if e == tty::ERESTART => {
                let Ok(pc) = m.read_u64(self.ctx_addr + gex_abi::ctx::PC as u64) else { return SyscallOutcome::Continue };
                match crate::syscalls::restart_call(m, self.ctx_addr, pc, false) {
                    Some(back) => SyscallOutcome::Resume(back),
                    None => SyscallOutcome::Continue,
                }
            }
            r => {
                let _ = super::set_result(m, self.ctx_addr, r.unwrap_or_else(|e| e.as_return()));
                SyscallOutcome::Continue
            }
        }
    }

    /// `read`, `readv`, `write` or `writev` (`raw`) of a terminal.
    pub(crate) fn darwin_tty_rw(&mut self, m: &mut GuestMem<'_>, raw: u64, a: &[u64; 6]) -> SyscallOutcome {
        use super::sysno as sys;
        let write = matches!(raw, sys::WRITE | sys::WRITE_NOCANCEL | sys::WRITEV | sys::WRITEV_NOCANCEL);
        let vec = matches!(raw, sys::READV | sys::READV_NOCANCEL | sys::WRITEV | sys::WRITEV_NOCANCEL);
        let r = (|| -> Result<(i32, Arc<TtyDev>, Iov), Errno> {
            let (file, dev) = self.darwin_tty_of(a[0]).ok_or(Errno::EBADF)?;
            if (write && !file.writable) || (!write && !file.readable) {
                return Err(Errno::EBADF);
            }
            let iov = if vec {
                let (base, cnt) = (a[1], a[2] as u32 as u64);
                if cnt == 0 || cnt > UIO_MAXIOV {
                    return Err(Errno::EINVAL);
                }
                let mut v = Vec::new();
                let mut total = 0u64;
                for i in 0..cnt {
                    let (b, l) = (m.read_u64(base + 16 * i)?, m.read_u64(base + 16 * i + 8)?);
                    total += l;
                    if l > i64::MAX as u64 || total > i32::MAX as u64 {
                        return Err(Errno::EINVAL);
                    }
                    v.push((b, l));
                }
                v
            } else {
                if a[2] > i32::MAX as u64 {
                    return Err(Errno::EINVAL);
                }
                vec![(a[1], a[2])]
            };
            Ok((a[0] as i32, dev, Iov::new(iov)))
        })();
        match r {
            Err(e) => self.darwin_tty_result(m, Err(e)),
            Ok((fd, dev, iov)) => {
                if write {
                    self.darwin_tty_write_step(m, fd, dev, iov, tty::WriteState::default(), ptmx::PtcWrite::default(), None, None)
                } else {
                    self.darwin_tty_read_step(m, fd, dev, iov, tty::ReadState::default(), None, None)
                }
            }
        }
    }

    /// The device a descriptor's call goes to: the vnode's own, or for
    /// `/dev/tty` the session's terminal's (EIO with none).
    fn darwin_tty_target(&self, dev: &Arc<TtyDev>) -> Result<Arc<TtyDev>, Errno> {
        if dev.node == Node::Ctty {
            return self.darwin_cttyvp().ok_or(Errno::EIO);
        }
        Ok(Arc::clone(dev))
    }

    /// The driver a call on vnode `target` reaches, the device it is
    /// called with, and its terminal: the pty's own; for the console, the
    /// device its calls go to now, or for a call back from a sleep, the
    /// terminal it slept in (`slept_in`).
    fn darwin_tty_driver(&mut self, target: &TtyDev, o: &Opened, slept_in: Option<&Arc<TtyCell>>) -> Result<(Drv, u32, Arc<TtyCell>), Errno> {
        if target.node != Node::Console {
            let drv = if target.primary() { Drv::Ptc } else { Drv::Pts };
            return Ok((drv, target.dev(), Arc::clone(&o.cell)));
        }
        let Some(cell) = slept_in else { return self.darwin_cn_dev() };
        let dev = cell.lock().dev;
        match km::cn_of(cell, dev) {
            Ok(km::Cn::Km) => Ok((Drv::Km, dev, Arc::clone(cell))),
            Ok(km::Cn::Pts) => Ok((Drv::Pts, dev, Arc::clone(cell))),
            Err(why) => {
                self.darwin_unimplemented(why);
                Err(Errno::ENXIO)
            }
        }
    }

    /// `fo_read` of a terminal (`vn_read`, `spec_read`, then the driver's
    /// `d_read`), until it ends or sleeps.
    #[allow(clippy::too_many_arguments)]
    fn darwin_tty_read_step(&mut self, m: &mut GuestMem<'_>, fd: i32, dev: Arc<TtyDev>, mut iov: Iov, mut st: tty::ReadState, resumed: Option<(SleepReq, Woke)>, slept_in: Option<Arc<TtyCell>>) -> SyscallOutcome {
        let file = match self.fds.get(fd) {
            Ok(f) => f,
            Err(e) => return self.darwin_tty_result(m, Err(e)),
        };
        let target = match self.darwin_tty_target(&dev) {
            Ok(t) => t,
            Err(e) => return self.darwin_tty_result(m, Err(e)),
        };
        // deadfs: a revoked character device reads as EOF.
        let Some(o) = target.opened() else { return self.darwin_tty_result(m, Ok(0)) };
        // A call that comes to a vnode being revoked waits for its reclaim
        // (vnode_getiocount), then finds it dead.
        let (resumed, slept_in) = match resumed {
            Some((r, _)) if r.chan == tty::Chan::Reclaim => (None, None),
            r => (r, slept_in),
        };
        let (drv, _, cell) = match self.darwin_tty_driver(&target, &o, slept_in.as_ref()) {
            Ok(d) => d,
            Err(e) => return self.darwin_tty_result(m, Err(e)),
        };
        if resumed.is_none() && target.terminating() {
            let req = reclaim_wait(&cell);
            return self.darwin_tty_sleep(m, Op::Read { fd, iov, st }, dev, cell, req);
        }
        let _io = IoRef::enter(&cell, (target.dev(), o.vid));
        let count = iov.total;
        if count == 0 {
            // spec_read: nothing asked, nothing done.
            return self.darwin_tty_result(m, Ok(0));
        }
        let flag = if file.flags() & crate::fs::oflags::O_NONBLOCK != 0 { tty::IO_NDELAY } else { 0 };
        let p = self.darwin_tty_caller();
        let mut env = self.darwin_tty_env();
        let r = {
            let mut tp = cell.lock();
            let mut u = GuestUio { m: &mut *m, c: &mut iov };
            let r = match drv {
                Drv::Ptc => ptmx::ptcread(&mut tp, &mut u, flag, resumed),
                Drv::Pts => ptmx::ptsread(&mut tp, &mut u, flag, &p, &mut env, &mut st, resumed),
                // kmread: l_read.
                Drv::Km => tp.ttread(&mut u, flag, &p, &mut env, &mut st, resumed),
            };
            if let Io::Sleep(req) = r {
                drop(tp);
                self.darwin_tty_env_done(env);
                return self.darwin_tty_sleep(m, Op::Read { fd, iov, st }, dev, cell, req);
            }
            r
        };
        self.darwin_tty_env_done(env);
        target.mark(false);
        let Io::Done(r) = r else { unreachable!("handled above") };
        self.darwin_tty_result(m, partial(r, count, iov.total - iov.pos))
    }

    /// `fo_write` of a terminal, until it ends or sleeps.
    #[allow(clippy::too_many_arguments)]
    fn darwin_tty_write_step(&mut self, m: &mut GuestMem<'_>, fd: i32, dev: Arc<TtyDev>, mut iov: Iov, mut st: tty::WriteState, mut ptc: ptmx::PtcWrite, resumed: Option<(SleepReq, Woke)>, slept_in: Option<Arc<TtyCell>>) -> SyscallOutcome {
        let file = match self.fds.get(fd) {
            Ok(f) => f,
            Err(e) => return self.darwin_tty_result(m, Err(e)),
        };
        let target = match self.darwin_tty_target(&dev) {
            Ok(t) => t,
            Err(e) => return self.darwin_tty_result(m, Err(e)),
        };
        // deadfs: EIO.
        let Some(o) = target.opened() else { return self.darwin_tty_result(m, Err(Errno::EIO)) };
        let (resumed, slept_in) = match resumed {
            Some((r, _)) if r.chan == tty::Chan::Reclaim => (None, None),
            r => (r, slept_in),
        };
        let (drv, _, cell) = match self.darwin_tty_driver(&target, &o, slept_in.as_ref()) {
            Ok(d) => d,
            Err(e) => return self.darwin_tty_result(m, Err(e)),
        };
        if resumed.is_none() && target.terminating() {
            let req = reclaim_wait(&cell);
            return self.darwin_tty_sleep(m, Op::Write { fd, iov, st, ptc }, dev, cell, req);
        }
        let _io = IoRef::enter(&cell, (target.dev(), o.vid));
        let count = iov.total;
        let flag = if file.flags() & crate::fs::oflags::O_NONBLOCK != 0 { tty::IO_NDELAY } else { 0 };
        let p = self.darwin_tty_caller();
        let mut env = self.darwin_tty_env();
        let r = {
            let mut tp = cell.lock();
            let mut u = GuestUio { m: &mut *m, c: &mut iov };
            let r = match drv {
                Drv::Ptc => ptmx::ptcwrite(&mut tp, &mut u, flag, &mut env, &mut ptc, resumed),
                Drv::Pts => ptmx::ptswrite(&mut tp, &mut u, flag, &p, &mut env, &mut st, resumed),
                // kmwrite: l_write.
                Drv::Km => tp.ttwrite(&mut u, flag, &p, &mut env, &mut st, resumed),
            };
            if let Io::Sleep(req) = r {
                drop(tp);
                self.darwin_tty_env_done(env);
                return self.darwin_tty_sleep(m, Op::Write { fd, iov, st, ptc }, dev, cell, req);
            }
            r
        };
        self.darwin_tty_env_done(env);
        target.mark(true);
        let Io::Done(r) = r else { unreachable!("handled above") };
        self.darwin_tty_result(m, partial(r, count, iov.total - iov.pos))
    }

    /// `ioctl` of a terminal: the generic commands as `ioctl` and
    /// `vn_ioctl` take them, then the device's (`ptyioctl`), which may
    /// sleep. None when `fd` is no terminal.
    pub(crate) fn darwin_tty_ioctl(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Option<SyscallOutcome> {
        const IOCPARM_MASK: u64 = 0x1fff;
        const IOC_VOID: u64 = 0x2000_0000;
        const IOC_OUT: u64 = 0x4000_0000;
        const IOC_IN: u64 = 0x8000_0000;
        let (_, dev) = self.darwin_tty_of(a[0])?;
        let (com, udata) = (a[1] as u32 as u64, a[2]);
        // The generic ioctl's own commands go its way.
        if matches!(com, super::ioctl::cmd::FIOCLEX | super::ioctl::cmd::FIONCLEX | super::ioctl::cmd::FIONBIO | super::ioctl::cmd::FIOASYNC | super::ioctl::cmd::FIOSETOWN | super::ioctl::cmd::FIOGETOWN) {
            return None;
        }
        let size = (com >> 16) & IOCPARM_MASK;
        let mut data = vec![0u8; (size as usize).max(8)];
        if com & IOC_IN != 0 {
            if size != 0 {
                match m.read(udata, size as usize) {
                    Ok(b) => data[..size as usize].copy_from_slice(b),
                    Err(e) => return Some(self.darwin_tty_result(m, Err(e))),
                }
            } else {
                data[..8].copy_from_slice(&udata.to_le_bytes());
            }
        } else if com & IOC_VOID != 0 {
            data[..8].copy_from_slice(&udata.to_le_bytes());
        }
        let _ = IOC_OUT;
        Some(self.darwin_tty_ioctl_step(m, a[0] as i32, dev, com, data, udata, ptmx::PtyIoctl::default(), None, None))
    }

    /// `VNOP_IOCTL` of a terminal's vnode with command `com`, which has no
    /// argument (`sys_fcntl_nocancel`'s default, which sends a command it
    /// does not know down to the vnode with an empty argument and flag 0):
    /// through `/dev/tty` to the session's terminal. A revoked vnode is
    /// VBAD on the dead mount, so VNOP_IOCTL refuses a 64-bit caller's
    /// argument for it (ENOTTY) before deadfs is reached.
    pub(crate) fn darwin_tty_vnop_ioctl(&mut self, fd: i32, com: u32) -> Option<Result<u64, Errno>> {
        let (_, dev) = self.darwin_tty_of(fd as u64)?;
        let target = match self.darwin_tty_target(&dev) {
            Ok(t) => t,
            Err(e) => return Some(Err(e)),
        };
        if dev.dead() {
            return Some(Err(Errno::ENOTTY));
        }
        if target.terminating() {
            self.darwin_unimplemented("fcntl of a terminal being revoked (vnode_getwithref's wait for the reclaim)".into());
            return Some(Err(Errno::EINVAL));
        }
        let Some(o) = target.opened() else { return Some(Err(Errno::ENOTTY)) };
        let (drv, ddev, cell) = match self.darwin_tty_driver(&target, &o, None) {
            Ok(d) => d,
            Err(e) => return Some(Err(e)),
        };
        let p = self.darwin_tty_caller();
        let mut env = self.darwin_tty_env();
        let mut data = vec![0u8; 8];
        let mut st = ptmx::PtyIoctl::default();
        let r = {
            let mut tp = cell.lock();
            d_ioctl(drv, &cell, &mut tp, ddev, u64::from(com), &mut data, 0, &p, &mut env, &mut st, None)
        };
        self.darwin_tty_env_done(env);
        Some(match r {
            Io::Done(r) => r.map(|()| 0),
            Io::Sleep(_) => {
                self.darwin_unimplemented(format!("fcntl {com} of a terminal, which sleeps in its driver"));
                Err(Errno::EINVAL)
            }
        })
    }

    /// `revoke(path)`: of a character device that the caller owns, or as
    /// the superuser, after the MAC check; VNOP_REVOKE while it is in use,
    /// the call waiting for the vnode's drain.
    pub(crate) fn darwin_revoke(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> SyscallOutcome {
        let dev = match self.darwin_revoke_check(m, a[0]) {
            Ok(Some(d)) => d,
            Ok(None) => return self.darwin_tty_result(m, Ok(0)),
            Err(e) => return self.darwin_tty_result(m, Err(e)),
        };
        let Some((cell, r)) = revoke_begin(dev) else { return self.darwin_tty_result(m, Ok(0)) };
        let node = TtyDev::new(dev_node(dev).expect("a terminal's device"));
        self.darwin_revoke_step(m, node, cell, r)
    }

    /// `revoke`'s checks, in its order: the lookup, a character device
    /// (ENOTSUP otherwise), `mac_vnode_check_revoke`, then the owner
    /// (`va_uid`) or `suser`. The terminal device to revoke, or none when
    /// nothing has it in use.
    fn darwin_revoke_check(&mut self, m: &mut GuestMem<'_>, path: u64) -> Result<Option<u32>, Errno> {
        self.darwin_sb_namei(m, super::bsd::AT_FDCWD as u64, path, true, false)?;
        let abs = self.path_io().at_path(m, super::bsd::dirfd(super::bsd::AT_FDCWD as u64) as i32, path)?;
        let md = self.vfs.metadata(&abs)?;
        // (No block device is kept here: there is none mounted on.)
        if md.file_type != FileType::CharDevice {
            return Err(Errno::EOPNOTSUPP);
        }
        let canonical = self.vfs.canonical(&abs);
        let tty_dev = tty_dev_of(&md);
        let owner = node_owner(&md).or_else(|| super::devfs::node_of(&md).map(|n| (n.uid, n.gid)));
        // VCHR, a terminal's with VISTTY; a devfs node has no file flags.
        let e = self.darwin_mac_check_vnode_revoke(super::macvfs::sb_vnode(&canonical, &md));
        if e != 0 {
            return Err(super::errno::errno_of(e as i32));
        }
        let Some((uid, _)) = owner else {
            self.darwin_unimplemented(format!("revoke of {canonical}: its owner (va_uid)"));
            return Err(Errno::EOPNOTSUPP);
        };
        if self.dtask.cred.uid != uid {
            self.darwin_suser()?;
        }
        match tty_dev {
            Some(dev) if !matches!(dev_node(dev), Some(Node::Ptmx | Node::Ctty)) => Ok(Some(dev)),
            _ => {
                self.darwin_unimplemented(format!("revoke of {canonical} (deadfs for its descriptors)"));
                Err(Errno::EOPNOTSUPP)
            }
        }
    }

    /// `revoke`'s drain, then the rest of the revoke.
    fn darwin_revoke_step(&mut self, m: &mut GuestMem<'_>, node: Arc<TtyDev>, cell: Arc<TtyCell>, r: Revoking) -> SyscallOutcome {
        if let Err(req) = revoke_drained(&cell, &r) {
            return self.darwin_tty_sleep(m, Op::Revoke { r }, node, cell, req);
        }
        revoke_finish(cell, r, Some(Arc::clone(&self.procs)), self.pid);
        self.darwin_tty_result(m, Ok(0))
    }

    /// The vnode a call on `dev` is in: the terminal's (the controlling
    /// terminal's for `/dev/tty`), its device and `v_id`.
    fn darwin_tty_vnode(&self, dev: &Arc<TtyDev>) -> Option<tty::Vnode> {
        let target = self.darwin_tty_target(dev).ok()?;
        let d = target.dev();
        let vid = match target.opened() {
            Some(o) => o.vid,
            None => peek_dev(d)?.1,
        };
        Some((d, vid))
    }

    /// `vn_ioctl` and `ptyioctl` of a terminal, until they end or sleep.
    #[allow(clippy::too_many_arguments)]
    fn darwin_tty_ioctl_step(&mut self, m: &mut GuestMem<'_>, fd: i32, dev: Arc<TtyDev>, com: u64, mut data: Vec<u8>, udata: u64, mut st: ptmx::PtyIoctl, resumed: Option<(SleepReq, Woke)>, slept_in: Option<Arc<TtyCell>>) -> SyscallOutcome {
        const IOCPARM_MASK: u64 = 0x1fff;
        const IOC_OUT: u64 = 0x4000_0000;
        const D_TTY: i32 = 3;
        const DKIOCSETBLOCKSIZE: u64 = 0x8004_6418;
        const FSIOC_AUTH_FS: u64 = 0x8004_6865;
        let file = match self.fds.get(fd) {
            Ok(f) => f,
            Err(e) => return self.darwin_tty_result(m, Err(e)),
        };
        if !file.readable && !file.writable {
            return self.darwin_tty_result(m, Err(Errno::EBADF));
        }
        let (resumed, slept_in) = match resumed {
            Some((r, _)) if r.chan == tty::Chan::Reclaim => (None, None),
            r => (r, slept_in),
        };
        if resumed.is_none() {
            if let Some(t) = self.darwin_tty_target(&dev).ok().filter(|t| t.terminating()) {
                if let Some(o) = t.opened() {
                    let cell = match self.darwin_tty_driver(&t, &o, None) {
                        Ok((_, _, c)) => c,
                        Err(e) => return self.darwin_tty_result(m, Err(e)),
                    };
                    let req = reclaim_wait(&cell);
                    return self.darwin_tty_sleep(m, Op::Ioctl { fd, com, data, udata, st }, dev, cell, req);
                }
            }
        }
        let size = (com >> 16) & IOCPARM_MASK;
        let r: Result<(), Errno> = if resumed.is_none() && dev.dead() {
            // vn_ioctl: a revoked vnode is VBAD, which its switch sends to
            // ENOTTY whatever the command.
            Err(Errno::ENOTTY)
        } else if resumed.is_none() && matches!(com, tty::cmd::TIOCREVOKE | tty::cmd::TIOCREVOKECLEAR) {
            // vn_ioctl: a revoke's commands are the kernel's.
            Err(Errno::ENOTTY)
        } else if resumed.is_none() && com == DKIOCSETBLOCKSIZE {
            Err(Errno::EPERM)
        } else if resumed.is_none() && com == FSIOC_AUTH_FS {
            Err(Errno::ENOTTY)
        } else if resumed.is_none() && com == super::ioctl::cmd::FIODTYPE {
            data[..4].copy_from_slice(&D_TTY.to_le_bytes());
            Ok(())
        } else if dev.node == Node::Ctty && com == tty::cmd::TIOCSCTTY {
            // Not to the controlling terminal: infinite recursion.
            match self.darwin_cttyvp() {
                None => Err(Errno::EIO),
                Some(_) => Err(Errno::EINVAL),
            }
        } else if dev.node == Node::Ctty && com == tty::cmd::TIOCNOTTY {
            // A process that is not the session leader gives up the
            // terminal; the leader cannot.
            match self.darwin_cttyvp() {
                None => Err(Errno::EIO),
                Some(_) => {
                    let sid = self.procs.sid(self.pid, self.pid).unwrap_or(0);
                    if sid != self.pid {
                        self.procs.set_controlt(self.pid, false);
                        Ok(())
                    } else {
                        Err(Errno::EINVAL)
                    }
                }
            }
        } else {
            let target = match self.darwin_tty_target(&dev) {
                Ok(t) => t,
                Err(e) => return self.darwin_tty_result(m, Err(e)),
            };
            match target.opened() {
                // Revoked since: VBAD's ENOTTY.
                None => Err(Errno::ENOTTY),
                // cnioctl: TIOCCONS while the console has a terminal of
                // its own takes the console's output back, for the
                // superuser.
                Some(_) if resumed.is_none() && target.node == Node::Console && com == tty::cmd::TIOCCONS && tty::copy_constty().is_some() => self.darwin_suser().map(|()| tty::set_constty(None)),
                Some(o) => {
                    let (drv, ddev, cell) = match self.darwin_tty_driver(&target, &o, slept_in.as_ref()) {
                        Ok(d) => d,
                        Err(e) => return self.darwin_tty_result(m, Err(e)),
                    };
                    let _io = IoRef::enter(&cell, (target.dev(), o.vid));
                    let p = self.darwin_tty_caller();
                    let mut env = self.darwin_tty_env();
                    if com == tty::cmd::TIOCPTYGRANT {
                        env.namei = Some(self.vfs.metadata(&ptmx::devhandle_path(target.dev())).map(|_| ()));
                    }
                    let ff = fflag(&file);
                    let r = {
                        let mut tp = cell.lock();
                        let r = d_ioctl(drv, &cell, &mut tp, ddev, com, &mut data, ff, &p, &mut env, &mut st, resumed);
                        if let Io::Sleep(req) = r {
                            drop(tp);
                            self.darwin_tty_env_done(env);
                            return self.darwin_tty_sleep(m, Op::Ioctl { fd, com, data, udata, st }, dev, cell, req);
                        }
                        r
                    };
                    self.darwin_tty_env_done(env);
                    let Io::Done(r) = r else { unreachable!("handled above") };
                    self.darwin_constty_check(com, &r);
                    // vn_ioctl: a TIOCSCTTY's session has this vnode.
                    if r.is_ok() && com == tty::cmd::TIOCSCTTY {
                        let sid = self.procs.sid(self.pid, self.pid).unwrap_or(self.pid);
                        let s = ctty::session(sid, None);
                        s.lock().ttyvp = Some(TtyVnode { dev: target.dev(), vid: o.vid });
                    }
                    r
                }
            }
        };
        match r {
            Ok(()) => {
                if com & IOC_OUT != 0 && size != 0 {
                    if let Err(e) = m.write(udata, &data[..size as usize]) {
                        return self.darwin_tty_result(m, Err(e));
                    }
                }
                self.darwin_tty_result(m, Ok(0))
            }
            Err(e) => self.darwin_tty_result(m, Err(e)),
        }
    }

    /// After a `TIOCCONS` made a terminal the console's: one whose `t_dev`
    /// the console's calls cannot go to is reported now (on the device
    /// the console's next call recurses).
    fn darwin_constty_check(&mut self, com: u64, r: &Result<(), Errno>) {
        use tty::cmd::{OTIOCCONS, TIOCCONS, TIOCSCONS};
        if r.is_err() || !matches!(com, TIOCCONS | TIOCSCONS | OTIOCCONS) {
            return;
        }
        if let Err(why) = km::cn_dev() {
            self.darwin_unimplemented(why);
        }
    }

    /// A terminal's `fo_ioctl` for the generic commands (FIONBIO, FIOASYNC,
    /// and FIOSETOWN's and FIOGETOWN's TIOCSPGRP and TIOCGPGRP), which
    /// never sleep.
    pub(crate) fn darwin_tty_fo_ioctl(&mut self, dev: &Arc<TtyDev>, file: &Arc<OpenFile>, com: u64, data: &mut [u8]) -> Result<(), Errno> {
        self.darwin_tty_vn_ioctl(dev, file, com, data)
    }

    /// `vn_ioctl` of a terminal for a command that never sleeps, a
    /// TIOCSCTTY's session given the vnode.
    fn darwin_tty_vn_ioctl(&mut self, dev: &Arc<TtyDev>, file: &Arc<OpenFile>, com: u64, data: &mut [u8]) -> Result<(), Errno> {
        // A revoked vnode is VBAD: ENOTTY whatever the command.
        if dev.dead() {
            return Err(Errno::ENOTTY);
        }
        if dev.node == Node::Ctty && com == tty::cmd::TIOCSCTTY {
            return Err(if self.darwin_cttyvp().is_some() { Errno::EINVAL } else { Errno::EIO });
        }
        let target = self.darwin_tty_target(dev)?;
        if target.terminating() {
            self.darwin_unimplemented("an ioctl of a terminal being revoked (vnode_getwithref's wait for the reclaim)".into());
            return Err(Errno::EINVAL);
        }
        let o = target.opened().ok_or(Errno::ENOTTY)?;
        let (drv, ddev, cell) = self.darwin_tty_driver(&target, &o, None)?;
        let p = self.darwin_tty_caller();
        let mut env = self.darwin_tty_env();
        let mut st = ptmx::PtyIoctl::default();
        let r = {
            let mut tp = cell.lock();
            d_ioctl(drv, &cell, &mut tp, ddev, com, data, fflag(file), &p, &mut env, &mut st, None)
        };
        self.darwin_tty_env_done(env);
        let r = match r {
            Io::Done(r) => r,
            Io::Sleep(_) => unreachable!("FIONBIO, FIOASYNC, TIOCSPGRP, TIOCGPGRP and TIOCSCTTY never sleep"),
        };
        if r.is_ok() && com == tty::cmd::TIOCSCTTY {
            let sid = self.procs.sid(self.pid, self.pid).unwrap_or(self.pid);
            ctty::session(sid, None).lock().ttyvp = Some(TtyVnode { dev: target.dev(), vid: o.vid });
        }
        r
    }

    /// A Darwin process's exit as its session's leader (`proc_exit`): the
    /// foreground group hung up, the terminal drained and revoked, and the
    /// session left without a leader.
    pub(crate) fn darwin_tty_proc_exit(&self) {
        // Its threads' calls asleep in terminals end with them, their
        // iocounts given up.
        for p in self.dtask.ttyops.values() {
            p.cell.lock().unsleep(p.token);
        }
        let Ok(sid) = self.procs.sid(self.pid, self.pid) else { return };
        if sid != self.pid {
            return;
        }
        let s = ctty::session(sid, Some(self.pid));
        let (ttyvp, tp, tpgrp, cttyref) = {
            let mut st = s.lock();
            let Some(v) = st.ttyvp else {
                st.leader = None;
                return;
            };
            let tp = st.ttyp.clone();
            let tpgrp = tp.as_ref().and_then(|t| {
                let g = t.lock();
                g.session.as_ref().is_some_and(|ts| Arc::ptr_eq(ts, &s)).then_some(g.pgrp).flatten()
            });
            let cttyref = std::mem::take(&mut st.cttyref);
            let tp = st.clear_tty();
            (v, tp, tpgrp, cttyref)
        };
        if let Some(pg) = tpgrp {
            let l = super::kern::signal_to_linux(tty::sig::SIGHUP);
            self.procs.pgsignal(pg.id, pg.serial, l, true);
        }
        if with_dev(ttyvp.dev, |d| d.vid) == ttyvp.vid {
            if let Some(cell) = &tp {
                // ttywait: the drain, at most its timeout each sleep.
                let mut resumed = None;
                loop {
                    let r = cell.lock().ttywait(resumed.take());
                    match r {
                        Io::Done(_) => break,
                        Io::Sleep(req) => resumed = Some((req, sync_sleep(cell, &req))),
                    }
                }
            }
            revoke(ttyvp.dev, Some(Arc::clone(&self.procs)), self.pid);
            let _ = cttyref;
        }
        s.lock().leader = None;
    }
}

/// A device's `d_ioctl` for a call on its vnode: `ptyioctl`, or
/// `kmioctl`. What km meets that is not modelled is reported.
#[allow(clippy::too_many_arguments)]
fn d_ioctl(drv: Drv, cell: &Arc<TtyCell>, tp: &mut tty::Tty, dev: u32, com: u64, data: &mut [u8], flag: i32, p: &Caller, env: &mut KEnv, st: &mut ptmx::PtyIoctl, resumed: Option<(SleepReq, Woke)>) -> Io<Result<(), Errno>> {
    if drv != Drv::Km {
        return ptmx::ptyioctl(cell, tp, dev, com, data, flag, p, env, st, resumed);
    }
    if resumed.is_none() {
        use tty::cmd::{OTIOCCONS, TIOCCONS, TIOCGWINSZ, TIOCSCONS};
        let on = com != TIOCCONS || i32::from_le_bytes(data[..4].try_into().unwrap()) != 0;
        if matches!(com, TIOCCONS | TIOCSCONS | OTIOCCONS) && !(on && !p.suser) {
            // ttioctl sends KMIOCDISABLCONS to km (constty is none when
            // a console ioctl reaches km), whose kmioctl takes the lock
            // ttioctl holds: XNU panics (a mutex unexpectedly owned).
            env.unimplemented.push("TIOCCONS on the console's own terminal (KMIOCDISABLCONS to km under km's lock: a kernel panic)".into());
            return Io::Done(Err(Errno::ENXIO));
        }
        if matches!(com, km::KMIOCSIZE | TIOCGWINSZ) {
            if let Some(why) = km::size_unknown() {
                env.unimplemented.push(format!("the console's window size (kmopen's): {why}"));
                return Io::Done(Err(Errno::ENXIO));
            }
        }
    }
    let mut tst = st.tt.take().unwrap_or_default();
    let r = km::kmioctl(cell, tp, com, data, flag, p, env, &mut tst, resumed);
    if let Io::Sleep(_) = r {
        st.tt = Some(tst);
    }
    r
}

/// A revoke of a terminal device's vnode under way
/// (`vnode_reclaim_internal` with REVOKEALL): the vnode, and whether
/// TIOCREVOKE was sent to the terminal.
#[derive(Clone, Copy, Debug)]
pub struct Revoking {
    v: tty::Vnode,
    sent: bool,
}

/// A revoke's start: the vnode marked as being reclaimed (VL_TERMINATE),
/// and, with a call in it, TIOCREVOKE sent to wake its readers. None when
/// nothing has the device in use, when a revoke of it is under way
/// already, or when it has no terminal (its vnode is then reclaimed here).
fn revoke_begin(dev: u32) -> Option<(Arc<TtyCell>, Revoking)> {
    let (opens, vid, terminating) = peek_dev(dev)?;
    if opens == 0 || terminating {
        return None;
    }
    let Some(cell) = dev_tty(dev) else {
        reclaim(dev, None);
        return None;
    };
    with_dev(dev, |d| d.terminating = true);
    let v = (dev, vid);
    let sent = cell.lock().revoke_begin(v);
    Some((cell, Revoking { v, sent }))
}

/// `vnode_drain`: done when no other call is in the vnode, else the sleep
/// until one leaves it (uninterruptible).
fn revoke_drained(cell: &Arc<TtyCell>, r: &Revoking) -> Result<(), SleepReq> {
    let tp = cell.lock();
    if tp.vnode_busy(r.v) {
        return Err(SleepReq { chan: tty::Chan::Drain, timo: 0, pcatch: false, gen: tp.gen });
    }
    Ok(())
}

/// A revoke's end: TIOCREVOKECLEAR, the device closed once (vclean's
/// VNOP_CLOSE with IO_NDELAY and IO_REVOKE), and the vnode reclaimed.
fn revoke_finish(cell: Arc<TtyCell>, r: Revoking, procs: Option<Arc<ProcTable>>, caller: i32) {
    cell.lock().revoke_end(r.sent);
    d_close(&cell, r.v.0, tty::FREAD | tty::FWRITE | tty::FNONBLOCK, true, procs, caller);
    reclaim(r.v.0, Some(&cell));
}

/// `vnode_reclaim_internal`'s end: the vnode dead with a new `v_id`, its
/// use count gone, and the calls that waited for it woken.
fn reclaim(dev: u32, cell: Option<&Arc<TtyCell>>) {
    with_dev(dev, |d| {
        d.opens = 0;
        d.vid += 1;
        d.terminating = false;
    });
    if let Some(c) = cell {
        c.lock().wakeup(tty::Chan::Reclaim);
    }
}

/// `VNOP_REVOKE(vp, REVOKEALL)` of a terminal device, its drain waited for
/// here and now (a process's exit).
pub fn revoke(dev: u32, procs: Option<Arc<ProcTable>>, caller: i32) {
    let Some((cell, r)) = revoke_begin(dev) else { return };
    while let Err(req) = revoke_drained(&cell, &r) {
        sync_sleep(&cell, &req);
    }
    revoke_finish(cell, r, procs, caller);
}

/// `fp_readv`'s and `fp_writev`'s rule: an interrupted or would-block
/// transfer that moved something is a success of what it moved.
fn partial(r: Result<(), Errno>, count: usize, resid: usize) -> Result<u64, Errno> {
    match r {
        Err(e) if (e == tty::ERESTART || e == Errno::EINTR || e == Errno::EWOULDBLOCK) && resid != count => Ok((count - resid) as u64),
        Err(e) => Err(e),
        Ok(()) => Ok((count - resid) as u64),
    }
}
