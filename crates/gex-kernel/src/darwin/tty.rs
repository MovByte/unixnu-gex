//! Terminals as XNU keeps them (`bsd/kern/tty.c`, `tty_compat.c`,
//! `tty_conf.c`): `struct tty` with its raw, canonical and output
//! character lists, the termios line discipline (`ttyinput`, `ttyoutput`,
//! `ttread`, `ttwrite`, `ttioctl_locked`, and the echo, erase and retype
//! work under them), and the 4.3BSD ioctls `ttcompat` turns into termios.
//!
//! A terminal's lock is its `Mutex`: every function here runs with it
//! held, as XNU's do with `tty_lock`. What a function would do outside the
//! terminal (signal a process group, look at a process) goes through
//! [`Env`]; what it would copy to or from the caller goes through [`Uio`].
//! A function that would sleep (`ttysleep`) returns [`Io::Sleep`] with the
//! channel and timeout instead, the state it needs to go on kept by its
//! caller, and is called again when the sleep ends with how it ended:
//! where it goes on is where XNU's goes on after its `ttysleep` returns.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use super::clist::{Clist, TTYCLSIZE, TTY_CHARMASK, TTY_QUOTE};
use super::lockf::Waker;
use super::ctty::{Pgrp, Session, NO_PID};
use crate::errno::Errno;

/// XNU's `ERESTART`: the call is to be made again from its start.
pub const ERESTART: Errno = Errno(-1);

/// `c_iflag` bits (`bsd/sys/termios.h`).
pub mod iflag {
    pub const IGNBRK: u64 = 0x0000_0001;
    pub const BRKINT: u64 = 0x0000_0002;
    pub const IGNPAR: u64 = 0x0000_0004;
    pub const PARMRK: u64 = 0x0000_0008;
    pub const INPCK: u64 = 0x0000_0010;
    pub const ISTRIP: u64 = 0x0000_0020;
    pub const INLCR: u64 = 0x0000_0040;
    pub const IGNCR: u64 = 0x0000_0080;
    pub const ICRNL: u64 = 0x0000_0100;
    pub const IXON: u64 = 0x0000_0200;
    pub const IXOFF: u64 = 0x0000_0400;
    pub const IXANY: u64 = 0x0000_0800;
    pub const IMAXBEL: u64 = 0x0000_2000;
    pub const IUTF8: u64 = 0x0000_4000;
}

/// `c_oflag` bits.
pub mod oflag {
    pub const OPOST: u64 = 0x0000_0001;
    pub const ONLCR: u64 = 0x0000_0002;
    pub const OXTABS: u64 = 0x0000_0004;
    pub const ONOEOT: u64 = 0x0000_0008;
    pub const OCRNL: u64 = 0x0000_0010;
    pub const ONOCR: u64 = 0x0000_0020;
}

/// `c_cflag` bits.
pub mod cflag {
    pub const CIGNORE: u64 = 0x0000_0001;
    pub const CSIZE: u64 = 0x0000_0300;
    pub const CS7: u64 = 0x0000_0200;
    pub const CS8: u64 = 0x0000_0300;
    pub const CREAD: u64 = 0x0000_0800;
    pub const PARENB: u64 = 0x0000_1000;
    pub const PARODD: u64 = 0x0000_2000;
    pub const HUPCL: u64 = 0x0000_4000;
    pub const CLOCAL: u64 = 0x0000_8000;
    pub const CRTS_IFLOW: u64 = 0x0002_0000;
    pub const MDMBUF: u64 = 0x0010_0000;
}

/// `c_lflag` bits.
pub mod lflag {
    pub const ECHOKE: u64 = 0x0000_0001;
    pub const ECHOE: u64 = 0x0000_0002;
    pub const ECHOK: u64 = 0x0000_0004;
    pub const ECHO: u64 = 0x0000_0008;
    pub const ECHONL: u64 = 0x0000_0010;
    pub const ECHOPRT: u64 = 0x0000_0020;
    pub const ECHOCTL: u64 = 0x0000_0040;
    pub const ISIG: u64 = 0x0000_0080;
    pub const ICANON: u64 = 0x0000_0100;
    pub const ALTWERASE: u64 = 0x0000_0200;
    pub const IEXTEN: u64 = 0x0000_0400;
    pub const EXTPROC: u64 = 0x0000_0800;
    pub const TOSTOP: u64 = 0x0040_0000;
    pub const FLUSHO: u64 = 0x0080_0000;
    pub const NOKERNINFO: u64 = 0x0200_0000;
    pub const PENDIN: u64 = 0x2000_0000;
    pub const NOFLSH: u64 = 0x8000_0000;
}

/// `c_cc` indices.
pub mod cc {
    pub const VEOF: usize = 0;
    pub const VEOL: usize = 1;
    pub const VEOL2: usize = 2;
    pub const VERASE: usize = 3;
    pub const VWERASE: usize = 4;
    pub const VKILL: usize = 5;
    pub const VREPRINT: usize = 6;
    pub const VINTR: usize = 8;
    pub const VQUIT: usize = 9;
    pub const VSUSP: usize = 10;
    pub const VDSUSP: usize = 11;
    pub const VSTART: usize = 12;
    pub const VSTOP: usize = 13;
    pub const VLNEXT: usize = 14;
    pub const VDISCARD: usize = 15;
    pub const VMIN: usize = 16;
    pub const VTIME: usize = 17;
    pub const VSTATUS: usize = 18;
    pub const NCCS: usize = 20;
}

/// `_POSIX_VDISABLE`.
pub const VDISABLE: u8 = 0xff;

/// `t_state` bits (`bsd/sys/tty.h`).
pub mod ts {
    pub const SO_OLOWAT: u32 = 0x00001;
    pub const ASYNC: u32 = 0x00002;
    pub const BUSY: u32 = 0x00004;
    pub const CARR_ON: u32 = 0x00008;
    pub const ISOPEN: u32 = 0x00020;
    pub const TBLOCK: u32 = 0x00040;
    pub const TTSTOP: u32 = 0x00100;
    pub const XCLUDE: u32 = 0x00400;
    pub const BKSL: u32 = 0x00800;
    pub const CNTTB: u32 = 0x01000;
    pub const ERASE: u32 = 0x02000;
    pub const LNCH: u32 = 0x04000;
    pub const TYPEN: u32 = 0x08000;
    pub const LOCAL: u32 = BKSL | CNTTB | ERASE | LNCH | TYPEN;
    pub const CONNECTED: u32 = 0x020000;
    pub const SO_OCOMPLETE: u32 = 0x080000;
    pub const ZOMBIE: u32 = 0x100000;
    pub const CAR_OFLOW: u32 = 0x200000;
    pub const IOCTL_NOT_OK: u32 = 0x1000000;
    pub const REVOKE: u32 = 0x2000000;
}

/// The flags of a character passed to `ttyinput`.
pub const TTY_ERRORMASK: i32 = 0xff00_0000_u32 as i32;
pub const TTY_FE: i32 = 0x0100_0000;
pub const TTY_PE: i32 = 0x0200_0000;
pub const TTY_BI: i32 = 0x0800_0000;

/// The `FREAD` and `FWRITE` of a flush or a select.
pub const FREAD: i32 = 0x1;
pub const FWRITE: i32 = 0x2;
/// `FNONBLOCK`, as `ttylclose` is given it.
pub const FNONBLOCK: i32 = 0x4;
/// `IO_NDELAY`: a non-blocking read or write.
pub const IO_NDELAY: i32 = 0x0004;

/// `hz`.
pub const HZ: i32 = 100;
/// `MAX_INPUT`.
pub const MAX_INPUT: usize = 1024;
/// `TTYHOG`.
pub const TTYHOG: usize = 1024;
/// `OBUFSIZ`.
const OBUFSIZ: usize = 100;
/// `IBUFSIZ`.
const IBUFSIZ: usize = 384;
/// `CBSIZE`: `CBLOCK` (64) less a cblock pointer and its quote bytes.
const CBSIZE: u32 = 64 - 8 - 64 / 8;
const fn roundup(x: u32, y: u32) -> u32 {
    x.div_ceil(y) * y
}
const TTMAXHIWAT: u32 = roundup(2048, CBSIZE);
const TTMINHIWAT: u32 = roundup(100, CBSIZE);
const TTMAXLOWAT: u32 = 256;
const TTMINLOWAT: u32 = 32;
/// `I_HIGH_WATER` and `I_LOW_WATER`.
const I_HIGH_WATER: usize = TTYHOG - 2 * 256;
const I_LOW_WATER: usize = (TTYHOG - 2 * 256) * 7 / 8;

/// `TTYDEF_*` (`bsd/sys/ttydefaults.h`).
pub const TTYDEF_IFLAG: u64 = iflag::BRKINT | iflag::ICRNL | iflag::IMAXBEL | iflag::IXON | iflag::IXANY;
pub const TTYDEF_OFLAG: u64 = oflag::OPOST | oflag::ONLCR;
pub const TTYDEF_LFLAG: u64 = lflag::ECHO | lflag::ICANON | lflag::ISIG | lflag::IEXTEN | lflag::ECHOE | lflag::ECHOKE | lflag::ECHOCTL;
pub const TTYDEF_CFLAG: u64 = cflag::CREAD | cflag::CS8 | cflag::HUPCL;
pub const TTYDEF_SPEED: u64 = 9600;

const fn ctrl(c: u8) -> u8 {
    c & 0o37
}

/// `ttydefchars`.
pub const TTYDEFCHARS: [u8; cc::NCCS] = [
    ctrl(b'd'), // CEOF
    0xff,       // CEOL
    0xff,       // CEOL
    0o177,      // CERASE
    ctrl(b'w'), // CWERASE
    ctrl(b'u'), // CKILL
    ctrl(b'r'), // CREPRINT
    VDISABLE,
    ctrl(b'c'), // CINTR
    0o34,       // CQUIT
    ctrl(b'z'), // CSUSP
    ctrl(b'y'), // CDSUSP
    ctrl(b'q'), // CSTART
    ctrl(b's'), // CSTOP
    ctrl(b'v'), // CLNEXT
    ctrl(b'o'), // CDISCARD
    1,          // CMIN
    0,          // CTIME
    ctrl(b't'), // CSTATUS
    VDISABLE,
];

/// `CEOT`.
const CEOT: i32 = 4;

/// The Darwin signals the line discipline raises.
pub mod sig {
    pub const SIGHUP: u32 = 1;
    pub const SIGINT: u32 = 2;
    pub const SIGQUIT: u32 = 3;
    pub const SIGIO: u32 = 23;
    pub const SIGTSTP: u32 = 18;
    pub const SIGTTIN: u32 = 21;
    pub const SIGTTOU: u32 = 22;
    pub const SIGWINCH: u32 = 28;
    pub const SIGINFO: u32 = 29;
    pub const NSIG: u32 = 32;
}

/// `struct termios` of a 64-bit process (`struct user_termios`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Termios {
    pub iflag: u64,
    pub oflag: u64,
    pub cflag: u64,
    pub lflag: u64,
    pub cc: [u8; cc::NCCS],
    pub ispeed: u64,
    pub ospeed: u64,
}

/// Its size, and `struct termios32`'s.
pub const TERMIOS_SIZE: usize = 72;
pub const TERMIOS32_SIZE: usize = 44;

impl Termios {
    /// A `struct user_termios` as the process laid it out.
    pub fn from_bytes(b: &[u8]) -> Termios {
        let w = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        let mut cc = [0; cc::NCCS];
        cc.copy_from_slice(&b[32..52]);
        Termios { iflag: w(0), oflag: w(8), cflag: w(16), lflag: w(24), cc, ispeed: w(56), ospeed: w(64) }
    }

    pub fn to_bytes(&self, b: &mut [u8]) {
        b[..TERMIOS_SIZE].fill(0);
        for (i, v) in [self.iflag, self.oflag, self.cflag, self.lflag].iter().enumerate() {
            b[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        b[32..52].copy_from_slice(&self.cc);
        b[56..64].copy_from_slice(&self.ispeed.to_le_bytes());
        b[64..72].copy_from_slice(&self.ospeed.to_le_bytes());
    }

    /// `termios32to64`.
    pub fn from_bytes32(b: &[u8]) -> Termios {
        let w = |i: usize| u64::from(u32::from_le_bytes(b[i..i + 4].try_into().unwrap()));
        let mut cc = [0; cc::NCCS];
        cc.copy_from_slice(&b[16..36]);
        Termios { iflag: w(0), oflag: w(4), cflag: w(8), lflag: w(12), cc, ispeed: w(36), ospeed: w(40) }
    }

    /// `termios64to32`.
    pub fn to_bytes32(&self, b: &mut [u8]) {
        b[..TERMIOS32_SIZE].fill(0);
        for (i, v) in [self.iflag, self.oflag, self.cflag, self.lflag].iter().enumerate() {
            b[i * 4..i * 4 + 4].copy_from_slice(&(*v as u32).to_le_bytes());
        }
        b[16..36].copy_from_slice(&self.cc);
        b[36..40].copy_from_slice(&(self.ispeed.min(u64::from(u32::MAX)) as u32).to_le_bytes());
        b[40..44].copy_from_slice(&(self.ospeed.min(u64::from(u32::MAX)) as u32).to_le_bytes());
    }
}

/// `struct winsize`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Winsize {
    pub row: u16,
    pub col: u16,
    pub xpixel: u16,
    pub ypixel: u16,
}

impl Winsize {
    pub fn from_bytes(b: &[u8]) -> Winsize {
        let h = |i: usize| u16::from_le_bytes([b[i], b[i + 1]]);
        Winsize { row: h(0), col: h(2), xpixel: h(4), ypixel: h(6) }
    }

    pub fn to_bytes(&self, b: &mut [u8]) {
        for (i, v) in [self.row, self.col, self.xpixel, self.ypixel].iter().enumerate() {
            b[i * 2..i * 2 + 2].copy_from_slice(&v.to_le_bytes());
        }
    }
}

/// `char_type`: each character's parity (0x80), whether it is alphameric
/// or `_` (0x40, for ALTWERASE), and its output class (the low six bits).
const E: u8 = 0x00;
const O: u8 = 0x80;
const ALPHA: u8 = 0x40;
const CCLASSMASK: u8 = 0x3f;
const ORDINARY: u8 = 0;
const CONTROL: u8 = 1;
const BACKSPACE: u8 = 2;
const NEWLINE: u8 = 3;
const TAB: u8 = 4;
const VTAB: u8 = 5;
const RETURN: u8 = 6;
const CC: u8 = CONTROL;
const BS: u8 = BACKSPACE;
const CR: u8 = RETURN;
const NA: u8 = ORDINARY | ALPHA;
const NL: u8 = NEWLINE;
const NO: u8 = ORDINARY;
const TB: u8 = TAB;
const VT: u8 = VTAB;

#[rustfmt::skip]
static CHAR_TYPE: [u8; 256] = [
    E | CC, O | CC, O | CC, E | CC, O | CC, E | CC, E | CC, O | CC, // nul - bel
    O | BS, E | TB, E | NL, O | CC, E | VT, O | CR, O | CC, E | CC, // bs - si
    O | CC, E | CC, E | CC, O | CC, E | CC, O | CC, O | CC, E | CC, // dle - etb
    E | CC, O | CC, O | CC, E | CC, O | CC, E | CC, E | CC, O | CC, // can - us
    O | NO, E | NO, E | NO, O | NO, E | NO, O | NO, O | NO, E | NO, // sp - '
    E | NO, O | NO, O | NO, E | NO, O | NO, E | NO, E | NO, O | NO, // ( - /
    E | NA, O | NA, O | NA, E | NA, O | NA, E | NA, E | NA, O | NA, // 0 - 7
    O | NA, E | NA, E | NO, O | NO, E | NO, O | NO, O | NO, E | NO, // 8 - ?
    O | NO, E | NA, E | NA, O | NA, E | NA, O | NA, O | NA, E | NA, // @ - G
    E | NA, O | NA, O | NA, E | NA, O | NA, E | NA, E | NA, O | NA, // H - O
    E | NA, O | NA, O | NA, E | NA, O | NA, E | NA, E | NA, O | NA, // P - W
    O | NA, E | NA, E | NA, O | NO, E | NO, O | NO, O | NO, O | NA, // X - _
    E | NO, O | NA, O | NA, E | NA, O | NA, E | NA, E | NA, O | NA, // ` - g
    O | NA, E | NA, E | NA, O | NA, E | NA, O | NA, O | NA, E | NA, // h - o
    O | NA, E | NA, E | NA, O | NA, E | NA, O | NA, O | NA, E | NA, // p - w
    E | NA, O | NA, O | NA, E | NO, O | NO, E | NO, E | NO, O | CC, // x - del
    // Meta characters, all ordinary.
    NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
    NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
    NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
    NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
    NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
    NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
    NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
    NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
];

fn isalpha(c: i32) -> u8 {
    CHAR_TYPE[(c & TTY_CHARMASK) as usize] & ALPHA
}

fn cclass(c: i32) -> u8 {
    CHAR_TYPE[(c & 0xff) as usize] & CCLASSMASK
}

/// `CCONT`: a UTF-8 continuation byte.
fn ccont(c: i32) -> bool {
    c & 0xc0 == 0x80
}

/// `CCEQ(val, c)`.
fn cceq(val: u8, c: i32) -> bool {
    c == i32::from(val) && val != VDISABLE
}

/// `scanc(size, cp, char_type, CCLASSMASK)`: how many of `cp` are left
/// from the first that has an output class.
fn scanc(cp: &[u8]) -> usize {
    cp.len() - cp.iter().position(|&b| CHAR_TYPE[b as usize] & CCLASSMASK != 0).unwrap_or(cp.len())
}

/// `tk_nin`, `tk_nout`, `tk_cancc`, `tk_rawcc`: every terminal's counts.
static TK_NIN: AtomicI64 = AtomicI64::new(0);
static TK_NOUT: AtomicI64 = AtomicI64::new(0);
static TK_CANCC: AtomicI64 = AtomicI64::new(0);
static TK_RAWCC: AtomicI64 = AtomicI64::new(0);

fn tk(c: &AtomicI64, n: i64) {
    c.fetch_add(n, Ordering::Relaxed);
}

/// A terminal's wait channels: the addresses XNU sleeps on (`TSA_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chan {
    /// `TSA_CARR_ON`: `&t_rawq`.
    CarrOn,
    /// `TSA_HUP_OR_INPUT`: `&t_rawq.c_cf`.
    HupOrInput,
    /// `TSA_OCOMPLETE`: `&t_outq.c_cl`.
    OComplete,
    /// `TSA_OLOWAT`: `&t_outq`.
    OLowat,
    /// `TSA_PTC_READ`: `&t_outq.c_cf`.
    PtcRead,
    /// `TSA_PTC_WRITE`: `&t_rawq.c_cl`.
    PtcWrite,
    /// `&ttread`, which nothing wakes: `ttread`'s delayed-suspend nap.
    Ttread,
}

/// A thread asleep on one of the terminal's channels.
struct Sleeper {
    chan: Chan,
    token: u64,
    waker: Waker,
}

/// A sleep a function asks for (`ttysleep(tp, chan, pri, wmesg, timo)`):
/// the channel, the timeout in ticks (0 for none), whether a signal may
/// end it (`PCATCH`), and the generation it began in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SleepReq {
    pub chan: Chan,
    pub timo: i32,
    pub pcatch: bool,
    pub gen: i32,
}

/// How a sleep ended, as `msleep0` reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Woke {
    /// A wakeup: 0.
    Awakened,
    /// The timeout: EWOULDBLOCK.
    TimedOut,
    /// A signal: EINTR, or ERESTART for one whose action restarts calls.
    Interrupted(Errno),
}

/// A line discipline function's outcome: done, or asleep.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Io<T> {
    Done(T),
    Sleep(SleepReq),
}

/// Where a terminal function copies the caller's data (`struct uio`).
pub trait Uio {
    /// `uio_resid`.
    fn resid(&self) -> usize;
    /// `uiomove` out: `b` to the caller.
    fn move_out(&mut self, b: &[u8]) -> Result<(), Errno>;
    /// `uiomove` in: the next `n` of the caller's bytes.
    fn move_in(&mut self, n: usize) -> Result<Vec<u8>, Errno>;
    /// `uio_setresid(uio, uio_resid(uio) + n)`: the last `n` bytes moved
    /// in count as not moved.
    fn give_back(&mut self, n: usize);
    /// `uio_setresid(uio, 0)`.
    fn finish(&mut self);
}

/// The process a terminal function runs for: what `current_proc()` and
/// `current_uthread()` answer, taken before the terminal is locked.
#[derive(Clone, Debug)]
pub struct Caller {
    pub pid: i32,
    /// `p_pgrp`, when the process has one.
    pub pgrp: Option<Pgrp>,
    /// Its group's `pg_jobc`.
    pub pg_jobc: i32,
    /// Its session.
    pub session: Option<Arc<Session>>,
    /// `P_CONTROLT`.
    pub controlt: bool,
    /// `p_sigignore` and the thread's `uu_sigmask` for SIGTTIN and SIGTTOU.
    pub ttin_ignored: bool,
    pub ttin_masked: bool,
    pub ttou_ignored: bool,
    pub ttou_masked: bool,
    /// `P_LPPWAIT`: a vfork parent waiting for its child.
    pub lppwait: bool,
    /// `suser(kauth_cred_get(), ...)` succeeds.
    pub suser: bool,
    pub uid: u32,
}

/// What a foreground process looks like to `ttyinfo_locked`.
#[derive(Clone, Debug)]
pub struct FgInfo {
    pub comm: String,
    pub pid: i32,
    /// `TH_STATE_*` of its first thread.
    pub run_state: i32,
    /// `calcru`'s user and system times, in seconds and microseconds.
    pub utime: (i64, i32),
    pub stime: (i64, i32),
}

/// What the line discipline needs from outside the terminal.
pub trait Env {
    /// `pgsignal(pg, signum, checkctty)`, run once the terminal is
    /// unlocked (`tty_pgsignal_locked` drops the lock around it).
    fn pgsignal(&mut self, pg: Pgrp, signum: u32, checkctty: bool);
    /// `psignal(p, signum)`, run once the terminal is unlocked.
    fn psignal(&mut self, pid: i32, signum: u32);
    /// `pgrp_find(pgid)` and the group's session.
    fn pgrp_find(&mut self, pgid: i32) -> Option<(Pgrp, Arc<Session>)>;
    /// `averunnable.ldavg[0]`, fixed-point with `FSHIFT` 11.
    fn loadavg(&mut self) -> u32;
    /// The group member `proc_compare` picks, if the group has members.
    fn fg_pick(&mut self, pg: Pgrp) -> Option<i32>;
    /// That process's command, its first thread's state and its times, if
    /// it is still there with a thread.
    fn fg_info(&mut self, pid: i32) -> Option<Result<FgInfo, ()>>;
    /// `os_atomic_or(&p->p_flag, P_CONTROLT)` on the caller.
    fn set_controlt(&mut self);
    /// The pid of a session's leader, if it has one.
    fn session_leader(&mut self, s: &Arc<Session>) -> Option<i32>;
    /// `namei` of `path` in the caller's namespace: whether it is there.
    fn namei(&mut self, path: &str) -> Result<(), Errno>;
}

/// `constty`: the terminal the console's output goes to (`TIOCCONS`).
static CONSTTY: Mutex<Option<Arc<TtyCell>>> = Mutex::new(None);

/// `copy_constty`.
fn copy_constty() -> Option<Arc<TtyCell>> {
    CONSTTY.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// `set_constty`.
fn set_constty(tp: Option<Arc<TtyCell>>) {
    *CONSTTY.lock().unwrap_or_else(|e| e.into_inner()) = tp;
}

/// A closing terminal is the console's no more (`set_constty(NULL)` when
/// `copy_constty() == tp`).
pub fn clear_constty_if(me: &Arc<TtyCell>) {
    let mut g = CONSTTY.lock().unwrap_or_else(|e| e.into_inner());
    if g.as_ref().is_some_and(|c| Arc::ptr_eq(c, me)) {
        *g = None;
    }
}

/// `struct tty`.
pub struct Tty {
    pub rawq: Clist,
    pub rawcc: i64,
    pub canq: Clist,
    pub cancc: i64,
    pub outq: Clist,
    pub outcc: i64,
    /// `t_line`.
    pub line: i32,
    /// `t_dev`.
    pub dev: u32,
    /// `t_state`.
    pub state: u32,
    /// `t_flags`: the 4.3BSD flags `ttcompat` keeps.
    pub flags: i32,
    /// `t_timeout`: `ttywait`'s, in ticks.
    pub timeout: i32,
    /// `t_pgrp`.
    pub pgrp: Option<Pgrp>,
    /// `t_session`.
    pub session: Option<Arc<Session>>,
    /// `t_rsel`, `t_wsel`: whoever waits for the terminal to be readable
    /// or writable.
    pub rsel: crate::wait::Queue,
    pub wsel: crate::wait::Queue,
    /// NOTE_REVOKEs posted to the knotes on `t_rsel` and `t_wsel`.
    pub rsel_revokes: u64,
    pub wsel_revokes: u64,
    pub termios: Termios,
    pub winsize: Winsize,
    /// `t_oproc` is set: the pty's primary is open (`ptsstart`).
    pub oproc: bool,
    pub column: i32,
    pub rocount: i32,
    pub rocol: i32,
    pub hiwat: i32,
    pub lowat: i32,
    pub gen: i32,
    /// The pty state the driver keeps beside it (`struct ptmx_ioctl`).
    pub pti: Option<super::ptmx::Pti>,
    sleepers: Vec<Sleeper>,
    next_token: u64,
}

/// A terminal and its lock.
pub struct TtyCell {
    tty: Mutex<Tty>,
    /// `t_state` as the terminal's last holder left it: what XNU reads of
    /// another terminal without its lock (`constty->t_state`).
    state: std::sync::atomic::AtomicU32,
}

impl std::fmt::Debug for TtyCell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TtyCell").finish()
    }
}

/// A locked terminal (`tty_lock` to `tty_unlock`).
pub struct TtyGuard<'a> {
    g: MutexGuard<'a, Tty>,
    cell: &'a TtyCell,
}

impl std::ops::Deref for TtyGuard<'_> {
    type Target = Tty;
    fn deref(&self) -> &Tty {
        &self.g
    }
}

impl std::ops::DerefMut for TtyGuard<'_> {
    fn deref_mut(&mut self) -> &mut Tty {
        &mut self.g
    }
}

impl Drop for TtyGuard<'_> {
    fn drop(&mut self) {
        self.cell.state.store(self.g.state, Ordering::Release);
    }
}

impl TtyCell {
    /// `ttymalloc`.
    pub fn new() -> Arc<TtyCell> {
        Arc::new(TtyCell { tty: Mutex::new(Tty::new()), state: std::sync::atomic::AtomicU32::new(0) })
    }

    /// `tty_lock`.
    pub fn lock(&self) -> TtyGuard<'_> {
        TtyGuard { g: self.tty.lock().unwrap_or_else(|e| e.into_inner()), cell: self }
    }

    /// `t_state`, read without the lock.
    pub fn state_unlocked(&self) -> u32 {
        self.state.load(Ordering::Acquire)
    }
}

/// Wake a sleeper: its thread, by its process's inbox.
fn wake(w: &Waker) {
    w.inbox.lock().unwrap_or_else(|e| e.into_inner()).push(w.tid);
    w.bell.ring();
}

impl Tty {
    /// `ttymalloc`: the raw and canonical lists keep quote bits, the
    /// output list none.
    fn new() -> Tty {
        Tty {
            rawq: Clist::alloc(TTYCLSIZE, true),
            rawcc: 0,
            canq: Clist::alloc(TTYCLSIZE, true),
            cancc: 0,
            outq: Clist::alloc(TTYCLSIZE, false),
            outcc: 0,
            line: 0,
            dev: 0,
            state: 0,
            flags: 0,
            timeout: 0,
            pgrp: None,
            session: None,
            rsel: crate::wait::Queue::new(),
            wsel: crate::wait::Queue::new(),
            rsel_revokes: 0,
            wsel_revokes: 0,
            termios: Termios::default(),
            winsize: Winsize::default(),
            oproc: false,
            column: 0,
            rocount: 0,
            rocol: 0,
            hiwat: 0,
            lowat: 0,
            gen: 0,
            pti: None,
            sleepers: Vec::new(),
            next_token: 1,
        }
    }

    // --- Sleeping and waking.

    /// `ttysleep`'s start: ERESTART for a terminal being revoked, else the
    /// sleep to take.
    pub fn sleep(&self, chan: Chan, timo: i32, pcatch: bool) -> Result<SleepReq, Errno> {
        if self.state & ts::REVOKE != 0 {
            return Err(ERESTART);
        }
        Ok(SleepReq { chan, timo, pcatch, gen: self.gen })
    }

    /// Queue the calling thread on `req`'s channel; the token that
    /// [`Self::unsleep`] takes it off with.
    pub fn enqueue(&mut self, req: &SleepReq, waker: Waker) -> u64 {
        let token = self.next_token;
        self.next_token += 1;
        self.sleepers.push(Sleeper { chan: req.chan, token, waker });
        token
    }

    /// Take a thread whose sleep ended some other way off its channel.
    pub fn unsleep(&mut self, token: u64) {
        self.sleepers.retain(|s| s.token != token);
    }

    /// `ttysleep`'s end: `msleep0`'s error, or ERESTART when the terminal
    /// changed (its generation moved) while the thread slept.
    pub fn slept(&self, req: &SleepReq, woke: Woke) -> Result<(), Errno> {
        match woke {
            Woke::Awakened => {}
            Woke::TimedOut => return Err(Errno::EWOULDBLOCK),
            Woke::Interrupted(e) => return Err(e),
        }
        if self.gen == req.gen {
            Ok(())
        } else {
            Err(ERESTART)
        }
    }

    /// `wakeup(chan)`.
    pub fn wakeup(&mut self, chan: Chan) {
        let mut i = 0;
        while i < self.sleepers.len() {
            if self.sleepers[i].chan == chan {
                let s = self.sleepers.swap_remove(i);
                wake(&s.waker);
            } else {
                i += 1;
            }
        }
    }

    /// `pgsignal` of the foreground group (`tty_pgsignal_locked`).
    fn pgsignal(&self, env: &mut dyn Env, signum: u32, checkctty: bool) {
        if let Some(pg) = self.pgrp {
            env.pgsignal(pg, signum, checkctty);
        }
    }

    // --- The driver under the terminal.

    /// `ttstart`: the driver's `t_oproc`.
    pub fn ttstart(&mut self) -> i32 {
        if self.oproc {
            super::ptmx::ptsstart(self);
        }
        0
    }

    /// `ttystop`: the device's `d_stop`.
    fn ttystop(&mut self, rw: i32) {
        if self.dev >> 24 == super::ptmx::PTSD_MAJOR {
            super::ptmx::ptsstop(self, rw);
        }
    }

    // --- Open and close (`ttyopen`, `ttyclose`, `ttylclose`).

    /// `ttyopen`.
    pub fn ttyopen(&mut self, device: u32) -> i32 {
        self.dev = device;
        if self.state & ts::ISOPEN == 0 {
            self.state |= ts::ISOPEN;
            if self.termios.cflag & cflag::CLOCAL != 0 {
                self.state |= ts::CONNECTED;
            }
            self.winsize = Winsize::default();
        }
        0
    }

    /// `ttyclose`: flushed and set to its first state, with a new
    /// generation; the session that had it loses it.
    pub fn ttyclose(&mut self, env: &mut dyn Env, me: &Arc<TtyCell>) {
        if copy_constty().is_some_and(|c| Arc::ptr_eq(&c, me)) {
            // The console's output stops coming here (KMIOCDISABLCONS to a
            // pty is nothing).
            set_constty(None);
        }
        self.ttyflush(FREAD | FWRITE, env);
        self.gen += 1;
        self.line = 0;
        if let Some(s) = self.session.take() {
            s.lock().clear_tty();
        }
        self.pgrp = None;
        self.state = 0;
        // The knotes are revoked and taken off the terminal.
        self.rsel_revokes += 1;
        self.wsel_revokes += 1;
        self.wsel.notify();
        self.rsel.notify();
    }

    /// `ttylclose`: the output drained unless the close is non-blocking or
    /// the drain fails, which flushes.
    pub fn ttylclose(&mut self, flag: i32, env: &mut dyn Env, resumed: Option<(SleepReq, Woke)>) -> Io<i32> {
        if flag & FNONBLOCK != 0 {
            self.ttyflush(FREAD | FWRITE, env);
            return Io::Done(0);
        }
        match self.ttywflush(env, resumed) {
            Io::Sleep(r) => return Io::Sleep(r),
            Io::Done(Ok(())) => {}
            Io::Done(Err(_)) => self.ttyflush(FREAD | FWRITE, env),
        }
        Io::Done(0)
    }

    /// `ttymodem`: the carrier on (`flag`) or lost; 0 when the line should
    /// be turned off.
    pub fn ttymodem(&mut self, flag: bool, env: &mut dyn Env) -> i32 {
        if self.state & ts::CARR_ON != 0 && self.termios.cflag & cflag::MDMBUF != 0 {
            // MDMBUF: carrier flow control.
            if flag {
                self.state &= !(ts::CAR_OFLOW | ts::TTSTOP);
                self.ttstart();
            } else if self.state & ts::CAR_OFLOW == 0 {
                self.state |= ts::CAR_OFLOW | ts::TTSTOP;
                self.ttystop(0);
            }
        } else if !flag {
            self.state &= !ts::CARR_ON;
            if self.state & ts::ISOPEN != 0 && self.termios.cflag & cflag::CLOCAL == 0 {
                self.state |= ts::ZOMBIE;
                self.state &= !ts::CONNECTED;
                if let Some(s) = &self.session {
                    if let Some(leader) = env.session_leader(s) {
                        env.psignal(leader, sig::SIGHUP);
                    }
                }
                self.ttyflush(FREAD | FWRITE, env);
                return 0;
            }
        } else {
            self.state |= ts::CARR_ON;
            if self.state & ts::ZOMBIE == 0 {
                self.state |= ts::CONNECTED;
            }
            self.wakeup(Chan::CarrOn);
            self.ttwakeup(env);
            self.ttwwakeup();
        }
        1
    }

    // --- Input.

    /// `ttypend`: the raw characters input again after a mode change.
    fn ttypend(&mut self, env: &mut dyn Env) {
        self.termios.lflag &= !lflag::PENDIN;
        self.state |= ts::TYPEN;
        // The old list is read from the buffer the new input goes into.
        let mut tq = self.rawq.detach();
        loop {
            let c = self.rawq.getc_detached(&mut tq);
            if c < 0 {
                break;
            }
            self.ttyinput(c, env);
        }
        self.state &= !ts::TYPEN;
    }

    /// `ttyblock`: input stopped at its high water.
    pub fn ttyblock(&mut self) {
        self.state |= ts::TBLOCK;
        if self.termios.iflag & iflag::IXOFF != 0 && self.termios.cc[cc::VSTOP] != VDISABLE && !self.outq.putc(i32::from(self.termios.cc[cc::VSTOP])) {
            self.state &= !ts::TBLOCK;
        }
        self.ttstart();
    }

    /// `ttyunblock`: input started again at its low water.
    pub fn ttyunblock(&mut self) {
        self.state &= !ts::TBLOCK;
        if self.termios.iflag & iflag::IXOFF != 0 && self.termios.cc[cc::VSTART] != VDISABLE && !self.outq.putc(i32::from(self.termios.cc[cc::VSTART])) {
            self.state |= ts::TBLOCK;
        }
        self.ttstart();
    }

    /// `TTBREAKC(c, lflag)`: whether `c` ends a line.
    fn ttbreakc(&self, c: i32, lf: u64) -> bool {
        let k = &self.termios.cc;
        c == i32::from(b'\n') || ((c == i32::from(k[cc::VEOF]) || c == i32::from(k[cc::VEOL]) || (c == i32::from(k[cc::VEOL2]) && lf & lflag::IEXTEN != 0)) && c != i32::from(VDISABLE))
    }

    /// `ttyinput`: one character received.
    pub fn ttyinput(&mut self, c: i32, env: &mut dyn Env) -> i32 {
        let mut c = c;
        let lf = self.termios.lflag;
        if lf & lflag::PENDIN != 0 {
            self.ttypend(env);
        }
        if lf & lflag::ICANON != 0 {
            tk(&TK_CANCC, 1);
            self.cancc += 1;
        } else {
            tk(&TK_RAWCC, 1);
            self.rawcc += 1;
        }
        tk(&TK_NIN, 1);

        // Input flow control at the high water (3 left for PARMRK).
        let ifl = self.termios.iflag;
        if self.rawq.len() + self.canq.len() > I_HIGH_WATER - 3
            && (lf & lflag::ICANON == 0 || !self.canq.is_empty())
            && (self.termios.cflag & cflag::CRTS_IFLOW != 0 || ifl & iflag::IXOFF != 0)
            && self.state & ts::TBLOCK == 0
        {
            self.ttyblock();
        }

        let next = self.ttyinput_scan(&mut c, lf, ifl, env);
        let next = match next {
            Next::Out => return 0,
            Next::Store => self.ttyinput_store(c, lf, ifl, env),
            n => n,
        };
        match next {
            Next::Out => 0,
            Next::Endcase => {
                // IXANY lets any character start output again.
                if self.state & ts::TTSTOP != 0 && ifl & iflag::IXANY == 0 && self.termios.cc[cc::VSTART] != self.termios.cc[cc::VSTOP] {
                    return 0;
                }
                self.termios.lflag &= !lflag::FLUSHO;
                self.state &= !ts::TTSTOP;
                self.ttstart()
            }
            Next::Restartoutput => {
                self.termios.lflag &= !lflag::FLUSHO;
                self.state &= !ts::TTSTOP;
                self.ttstart()
            }
            Next::Startoutput => self.ttstart(),
            Next::Store => unreachable!("stored above"),
        }
    }

    /// `ttyinput`'s exceptional conditions and special characters, down to
    /// where a character is stored.
    fn ttyinput_scan(&mut self, c: &mut i32, lf: u64, ifl: u64, env: &mut dyn Env) -> Next {
        let err = *c & TTY_ERRORMASK;
        if err != 0 {
            *c &= !TTY_ERRORMASK;
            let mut parmrk = false;
            if err & TTY_BI != 0 {
                if ifl & iflag::IGNBRK != 0 {
                    return Next::Out;
                }
                if ifl & iflag::BRKINT != 0 {
                    self.ttyflush(FREAD | FWRITE, env);
                    self.pgsignal(env, sig::SIGINT, true);
                    return Next::Endcase;
                }
                if ifl & iflag::PARMRK != 0 {
                    parmrk = true;
                }
            } else if (err & TTY_PE != 0 && ifl & iflag::INPCK != 0) || err & TTY_FE != 0 {
                if ifl & iflag::IGNPAR != 0 {
                    return Next::Out;
                } else if ifl & iflag::PARMRK != 0 {
                    parmrk = true;
                } else {
                    *c = 0;
                }
            }
            if parmrk {
                if self.rawq.len() + self.canq.len() > MAX_INPUT - 3 {
                    return self.input_overflow(ifl);
                }
                self.rawq.putc(0o377 | TTY_QUOTE);
                self.rawq.putc(TTY_QUOTE);
                self.rawq.putc(*c | TTY_QUOTE);
                return Next::Endcase;
            }
        }

        if self.state & ts::TYPEN == 0 && ifl & iflag::ISTRIP != 0 {
            *c &= !0x80;
        }
        if lf & lflag::EXTPROC == 0 {
            // Literal next, first of all.
            if self.state & ts::LNCH != 0 {
                *c |= TTY_QUOTE;
                self.state &= !ts::LNCH;
            }
            let k = self.termios.cc;
            // The control characters ICANON, ISIG and IXON do not govern.
            if lf & lflag::IEXTEN != 0 {
                if cceq(k[cc::VLNEXT], *c) {
                    if lf & lflag::ECHO != 0 {
                        if lf & lflag::ECHOE != 0 {
                            self.ttyoutput(i32::from(b'^'));
                            self.ttyoutput(i32::from(b'\x08'));
                        } else {
                            self.ttyecho(*c);
                        }
                    }
                    self.state |= ts::LNCH;
                    return Next::Endcase;
                }
                if cceq(k[cc::VDISCARD], *c) {
                    if lf & lflag::FLUSHO != 0 {
                        self.termios.lflag &= !lflag::FLUSHO;
                    } else {
                        self.ttyflush(FWRITE, env);
                        self.ttyecho(*c);
                        if self.rawq.len() + self.canq.len() != 0 {
                            self.ttyretype();
                        }
                        self.termios.lflag |= lflag::FLUSHO;
                    }
                    return Next::Startoutput;
                }
            }
            // Signals.
            if lf & lflag::ISIG != 0 {
                if cceq(k[cc::VINTR], *c) || cceq(k[cc::VQUIT], *c) {
                    if lf & lflag::NOFLSH == 0 {
                        self.ttyflush(FREAD | FWRITE, env);
                    }
                    self.ttyecho(*c);
                    let s = if cceq(k[cc::VINTR], *c) { sig::SIGINT } else { sig::SIGQUIT };
                    self.pgsignal(env, s, true);
                    return Next::Endcase;
                }
                if cceq(k[cc::VSUSP], *c) {
                    if lf & lflag::NOFLSH == 0 {
                        self.ttyflush(FREAD, env);
                    }
                    self.ttyecho(*c);
                    self.pgsignal(env, sig::SIGTSTP, true);
                    return Next::Endcase;
                }
            }
            // Start and stop.
            if ifl & iflag::IXON != 0 {
                if cceq(k[cc::VSTOP], *c) {
                    if self.state & ts::TTSTOP == 0 {
                        self.state |= ts::TTSTOP;
                        self.ttystop(0);
                        return Next::Out;
                    }
                    if !cceq(k[cc::VSTART], *c) {
                        return Next::Out;
                    }
                    // VSTART the same as VSTOP: a toggle.
                    return Next::Endcase;
                }
                if cceq(k[cc::VSTART], *c) {
                    return Next::Restartoutput;
                }
            }
            // IGNCR, ICRNL and INLCR.
            if *c == i32::from(b'\r') {
                if ifl & iflag::IGNCR != 0 {
                    return Next::Out;
                } else if ifl & iflag::ICRNL != 0 {
                    *c = i32::from(b'\n');
                }
            } else if *c == i32::from(b'\n') && ifl & iflag::INLCR != 0 {
                *c = i32::from(b'\r');
            }
        }
        if self.termios.lflag & lflag::EXTPROC == 0 && lf & lflag::ICANON != 0 {
            // Canonical processing from here down.
            let k = self.termios.cc;
            if cceq(k[cc::VERASE], *c) {
                if !self.rawq.is_empty() {
                    if ifl & iflag::IUTF8 != 0 {
                        loop {
                            *c = self.rawq.unputc();
                            self.ttyrub(*c);
                            if self.rawq.is_empty() || !ccont(*c) {
                                break;
                            }
                        }
                    } else {
                        let r = self.rawq.unputc();
                        self.ttyrub(r);
                    }
                }
                return Next::Endcase;
            }
            if cceq(k[cc::VKILL], *c) {
                if lf & lflag::ECHOKE != 0 && self.rawq.len() as i32 == self.rocount && lf & lflag::ECHOPRT == 0 {
                    while !self.rawq.is_empty() {
                        let r = self.rawq.unputc();
                        self.ttyrub(r);
                    }
                } else {
                    self.ttyecho(*c);
                    if lf & lflag::ECHOK != 0 || lf & lflag::ECHOKE != 0 {
                        self.ttyecho(i32::from(b'\n'));
                    }
                    let n = self.rawq.len();
                    if n != 0 {
                        self.rawq.ndflush(n);
                    }
                    self.rocount = 0;
                }
                self.state &= !ts::LOCAL;
                return Next::Endcase;
            }
            if cceq(k[cc::VWERASE], *c) && lf & lflag::IEXTEN != 0 {
                let is_blank = |c: i32| c == i32::from(b' ') || c == i32::from(b'\t');
                // The blanks.
                loop {
                    *c = self.rawq.unputc();
                    if !is_blank(*c) {
                        break;
                    }
                    self.ttyrub(*c);
                }
                if *c == -1 {
                    return Next::Endcase;
                }
                // The word's last character, and the next one's type.
                self.ttyrub(*c);
                *c = self.rawq.unputc();
                if *c == -1 {
                    return Next::Endcase;
                }
                if is_blank(*c) {
                    self.rawq.putc(*c);
                    return Next::Endcase;
                }
                let ctype = isalpha(*c);
                // The rest of the word.
                loop {
                    self.ttyrub(*c);
                    *c = self.rawq.unputc();
                    if *c == -1 {
                        return Next::Endcase;
                    }
                    if is_blank(*c) || (lf & lflag::ALTWERASE != 0 && isalpha(*c) != ctype) {
                        break;
                    }
                }
                self.rawq.putc(*c);
                return Next::Endcase;
            }
            if cceq(k[cc::VREPRINT], *c) && lf & lflag::IEXTEN != 0 {
                self.ttyretype();
                return Next::Endcase;
            }
            if cceq(k[cc::VSTATUS], *c) && lf & lflag::IEXTEN != 0 {
                if lf & lflag::ISIG != 0 {
                    self.pgsignal(env, sig::SIGINFO, true);
                }
                if lf & lflag::NOKERNINFO == 0 {
                    self.ttyinfo_locked(env);
                }
                return Next::Endcase;
            }
        }
        if self.rawq.len() + self.canq.len() >= MAX_INPUT {
            return self.input_overflow(ifl);
        }
        Next::Store
    }

    /// `input_overflow`: a bell if there is room for one.
    fn input_overflow(&mut self, ifl: u64) -> Next {
        if ifl & iflag::IMAXBEL != 0 && (self.outq.len() as i32) < self.hiwat {
            self.ttyoutput(i32::from(ctrl(b'g')));
        }
        Next::Endcase
    }

    /// `ttyinput`'s store: the character in the raw list, a line moved to
    /// the canonical list at its end, and the echo.
    fn ttyinput_store(&mut self, c: i32, lf: u64, ifl: u64, env: &mut dyn Env) -> Next {
        if c == 0o377 && ifl & iflag::PARMRK != 0 && ifl & iflag::ISTRIP == 0 && ifl & (iflag::IGNBRK | iflag::IGNPAR) != (iflag::IGNBRK | iflag::IGNPAR) {
            self.rawq.putc(0o377 | TTY_QUOTE);
        }
        if self.rawq.putc(c) {
            if lf & lflag::ICANON == 0 {
                self.ttwakeup(env);
                self.ttyecho(c);
                return Next::Endcase;
            }
            if self.ttbreakc(c, lf) {
                self.rocount = 0;
                let mut raw = std::mem::take(&mut self.rawq);
                self.canq.catq(&mut raw);
                self.rawq = raw;
                self.ttwakeup(env);
            } else {
                let was = self.rocount;
                self.rocount += 1;
                if was == 0 {
                    self.rocol = self.column;
                }
            }
            if self.state & ts::ERASE != 0 {
                // The end of a printed erase \.../.
                self.state &= !ts::ERASE;
                self.ttyoutput(i32::from(b'/'));
            }
            let mut i = self.column;
            self.ttyecho(c);
            if cceq(self.termios.cc[cc::VEOF], c) && lf & lflag::ECHO != 0 {
                // The cursor over the ^ of the ^D.
                i = 2.min(self.column - i);
                while i > 0 {
                    self.ttyoutput(i32::from(b'\x08'));
                    i -= 1;
                }
            }
        }
        Next::Endcase
    }

    // --- Output.

    /// `ttyoutput`: one character out, processed: -1 when it went, else
    /// the character to send again.
    fn ttyoutput(&mut self, c: i32) -> i32 {
        let mut c = c;
        let ofl = self.termios.oflag;
        if ofl & oflag::OPOST == 0 {
            if self.termios.lflag & lflag::FLUSHO != 0 {
                return -1;
            }
            if !self.outq.putc(c) {
                return c;
            }
            tk(&TK_NOUT, 1);
            self.outcc += 1;
            return -1;
        }
        // Tabs expanded with OXTABS, but not under external processing,
        // which would do it.
        c &= TTY_CHARMASK;
        if c == i32::from(b'\t') && ofl & oflag::OXTABS != 0 && self.termios.lflag & lflag::EXTPROC == 0 {
            let col = 8 - (self.column & 7);
            let mut n = col;
            if self.termios.lflag & lflag::FLUSHO == 0 {
                n -= self.outq.b_to_q(&b"        "[..n as usize]) as i32;
                tk(&TK_NOUT, i64::from(n));
                self.outcc += i64::from(n);
            }
            self.column += n;
            return if n == col { -1 } else { i32::from(b'\t') };
        }
        if c == CEOT && ofl & oflag::ONOEOT != 0 {
            return -1;
        }
        if c == i32::from(b'\n') && ofl & oflag::ONLCR != 0 {
            // ONLCR: "\r\n".
            tk(&TK_NOUT, 1);
            self.outcc += 1;
            if !self.outq.putc(i32::from(b'\r')) {
                return c;
            }
        } else if c == i32::from(b'\r') && ofl & oflag::OCRNL != 0 {
            c = i32::from(b'\n');
        } else if c == i32::from(b'\r') && ofl & oflag::ONOCR != 0 && self.column == 0 {
            return -1;
        }
        tk(&TK_NOUT, 1);
        self.outcc += 1;
        if self.termios.lflag & lflag::FLUSHO == 0 && !self.outq.putc(c) {
            return c;
        }
        let mut col = self.column;
        match cclass(c) {
            BACKSPACE => {
                if col > 0 {
                    col -= 1;
                }
            }
            CONTROL => {}
            NEWLINE | RETURN => col = 0,
            ORDINARY => col += 1,
            TAB => col = (col + 8) & !7,
            _ => {}
        }
        self.column = col;
        -1
    }

    /// `ttyecho`: a typed character echoed.
    fn ttyecho(&mut self, c: i32) {
        let mut c = c;
        if self.state & ts::CNTTB == 0 {
            self.termios.lflag &= !lflag::FLUSHO;
        }
        let lf = self.termios.lflag;
        if (lf & lflag::ECHO == 0 && (c != i32::from(b'\n') || lf & lflag::ECHONL == 0)) || lf & lflag::EXTPROC != 0 {
            return;
        }
        if lf & lflag::ECHOCTL != 0 && (((c & TTY_CHARMASK) <= 0o37 && c != i32::from(b'\t') && c != i32::from(b'\n')) || (c & TTY_CHARMASK) == 0o177) {
            self.ttyoutput(i32::from(b'^'));
            c &= TTY_CHARMASK;
            if c == 0o177 {
                c = i32::from(b'?');
            } else {
                c += i32::from(b'A') - 1;
            }
        }
        self.ttyoutput(c);
    }

    /// `ttyrub`: one character rubbed out of the echo.
    fn ttyrub(&mut self, c: i32) {
        let mut c = c;
        let lf = self.termios.lflag;
        if lf & lflag::ECHO == 0 || lf & lflag::EXTPROC != 0 {
            return;
        }
        self.termios.lflag &= !lflag::FLUSHO;
        if lf & lflag::ECHOE != 0 {
            if self.rocount == 0 {
                // Messed up by ttwrite: retyped.
                self.ttyretype();
                return;
            }
            if c == (i32::from(b'\t') | TTY_QUOTE) || c == (i32::from(b'\n') | TTY_QUOTE) {
                self.ttyrubo(2);
            } else {
                c &= TTY_CHARMASK;
                match cclass(c) {
                    ORDINARY => {
                        if !(self.termios.iflag & iflag::IUTF8 != 0 && ccont(c)) {
                            self.ttyrubo(1);
                        }
                    }
                    BACKSPACE | CONTROL | NEWLINE | RETURN | VTAB => {
                        if self.termios.lflag & lflag::ECHOCTL != 0 {
                            self.ttyrubo(2);
                        }
                    }
                    TAB => {
                        if (self.rocount as usize) < self.rawq.len() {
                            self.ttyretype();
                            return;
                        }
                        let mut savecol = self.column;
                        self.state |= ts::CNTTB;
                        self.termios.lflag |= lflag::FLUSHO;
                        self.column = self.rocol;
                        let raw: Vec<i32> = self.rawq.iter().collect();
                        for tabc in raw {
                            self.ttyecho(tabc);
                        }
                        self.termios.lflag &= !lflag::FLUSHO;
                        self.state &= !ts::CNTTB;
                        // savecol is now the tab's width.
                        savecol -= self.column;
                        self.column += savecol;
                        if savecol > 8 {
                            savecol = 8;
                        }
                        loop {
                            savecol -= 1;
                            if savecol < 0 {
                                break;
                            }
                            self.ttyoutput(i32::from(b'\x08'));
                        }
                    }
                    // XNU prints "ttyrub: would panic" for any other class;
                    // the table has none.
                    _ => {}
                }
            }
        } else if lf & lflag::ECHOPRT != 0 {
            if self.state & ts::ERASE == 0 {
                self.state |= ts::ERASE;
                self.ttyoutput(i32::from(b'\\'));
            }
            self.ttyecho(c);
        } else {
            self.ttyecho(i32::from(self.termios.cc[cc::VERASE]));
        }
        self.rocount -= 1;
    }

    /// `ttyrubo`: back over `count` characters, erasing them.
    fn ttyrubo(&mut self, count: i32) {
        for _ in 0..count {
            self.ttyoutput(i32::from(b'\x08'));
            self.ttyoutput(i32::from(b' '));
            self.ttyoutput(i32::from(b'\x08'));
        }
    }

    /// `ttyretype`: the line reprinted.
    fn ttyretype(&mut self) {
        if self.termios.cc[cc::VREPRINT] != VDISABLE {
            self.ttyecho(i32::from(self.termios.cc[cc::VREPRINT]));
        }
        self.ttyoutput(i32::from(b'\n'));
        let can: Vec<i32> = self.canq.iter().collect();
        for c in can {
            self.ttyecho(c);
        }
        let raw: Vec<i32> = self.rawq.iter().collect();
        for c in raw {
            self.ttyecho(c);
        }
        self.state &= !ts::ERASE;
        self.rocount = self.rawq.len() as i32;
        self.rocol = 0;
    }

    /// `tputchar`: a character out, console style.
    fn tputchar(&mut self, c: u8) -> i32 {
        if self.state & ts::CONNECTED == 0 {
            return -1;
        }
        if c == b'\n' {
            self.ttyoutput(i32::from(b'\r'));
        }
        self.ttyoutput(i32::from(c));
        self.ttstart();
        0
    }

    /// `ttyprintf`.
    fn ttyprintf(&mut self, s: &str) {
        for b in s.bytes() {
            self.tputchar(b);
        }
    }

    // --- Wakeups.

    /// `ttwakeup`: readers woken, and SIGIO under TS_ASYNC.
    pub fn ttwakeup(&mut self, env: &mut dyn Env) {
        self.rsel.notify();
        if self.state & ts::ASYNC != 0 {
            self.pgsignal(env, sig::SIGIO, true);
        }
        self.wakeup(Chan::HupOrInput);
    }

    /// `ttwwakeup`: writers woken at the low water, and a drain's waiters
    /// once the output is out.
    pub fn ttwwakeup(&mut self) {
        if self.outq.len() as i32 <= self.lowat {
            self.wsel.notify();
        }
        if self.state & (ts::BUSY | ts::SO_OCOMPLETE) == ts::SO_OCOMPLETE && self.outq.is_empty() {
            self.state &= !ts::SO_OCOMPLETE;
            self.wakeup(Chan::OComplete);
        }
        if self.state & ts::SO_OLOWAT != 0 && self.outq.len() as i32 <= self.lowat {
            self.state &= !ts::SO_OLOWAT;
            self.wakeup(Chan::OLowat);
        }
    }

    /// `ttsetwater`: about a second of output from high water to low.
    pub fn ttsetwater(&mut self) {
        let clamp = |x: u32, h: u32, l: u32| if x > h { h } else if x < l { l } else { x };
        let cps = (self.termios.ospeed / 10).min(u64::from(u32::MAX)) as u32;
        let mut x = clamp(cps / 2, TTMAXLOWAT, TTMINLOWAT);
        self.lowat = x as i32;
        x = x.wrapping_add(cps);
        x = clamp(x, TTMAXHIWAT, TTMINHIWAT);
        self.hiwat = roundup(x, CBSIZE) as i32;
    }

    // --- Flushing and draining.

    /// `ttyflush`: the read and/or write lists flushed, their waiters told.
    pub fn ttyflush(&mut self, rw: i32, env: &mut dyn Env) {
        if rw & FWRITE != 0 {
            flushq(&mut self.outq);
            self.state &= !ts::TTSTOP;
        }
        self.ttystop(rw);
        if rw & FREAD != 0 {
            flushq(&mut self.canq);
            flushq(&mut self.rawq);
            self.termios.lflag &= !lflag::PENDIN;
            self.rocount = 0;
            self.rocol = 0;
            self.state &= !ts::LOCAL;
            self.ttwakeup(env);
            if self.state & ts::TBLOCK != 0 {
                if rw & FWRITE != 0 {
                    flushq(&mut self.outq);
                }
                self.ttyunblock();
                self.state &= !ts::TBLOCK;
            }
        }
        if rw & FWRITE != 0 {
            flushq(&mut self.outq);
            self.ttwwakeup();
        }
    }

    /// `ttywait`: the output drained, or EIO when it cannot be (no
    /// connection, or `t_timeout` passed).
    pub fn ttywait(&mut self, resumed: Option<(SleepReq, Woke)>) -> Io<Result<(), Errno>> {
        let mut error = Ok(());
        let mut resumed = resumed;
        loop {
            if let Some((req, woke)) = resumed.take() {
                if let Err(e) = self.slept(&req, woke) {
                    error = Err(if e == Errno::EWOULDBLOCK { Errno::EIO } else { e });
                    break;
                }
            }
            if !((!self.outq.is_empty() || self.state & ts::BUSY != 0) && self.state & ts::CONNECTED != 0 && self.oproc) {
                break;
            }
            self.ttstart();
            if (!self.outq.is_empty() || self.state & ts::BUSY != 0) && self.state & ts::CONNECTED != 0 {
                self.state |= ts::SO_OCOMPLETE;
                match self.sleep(Chan::OComplete, self.timeout, true) {
                    Ok(req) => return Io::Sleep(req),
                    Err(e) => {
                        error = Err(e);
                        break;
                    }
                }
            } else {
                break;
            }
        }
        if error.is_ok() && (!self.outq.is_empty() || self.state & ts::BUSY != 0) {
            error = Err(Errno::EIO);
        }
        Io::Done(error)
    }

    /// `ttywflush`: drained, then the input flushed.
    fn ttywflush(&mut self, env: &mut dyn Env, resumed: Option<(SleepReq, Woke)>) -> Io<Result<(), Errno>> {
        match self.ttywait(resumed) {
            Io::Sleep(r) => Io::Sleep(r),
            Io::Done(Ok(())) => {
                self.ttyflush(FREAD, env);
                Io::Done(Ok(()))
            }
            Io::Done(e) => Io::Done(e),
        }
    }

    // --- Who the caller is to the terminal.

    /// `isbackground`.
    pub fn isbackground(&self, p: &Caller) -> bool {
        let Some(pg) = self.pgrp else { return false };
        if Some(pg) == p.pgrp {
            return false;
        }
        let Some(s) = &self.session else { return false };
        p.session.as_ref().is_some_and(|ps| ps.sid == s.sid) && p.controlt
    }

    /// `isctty`: this is the caller's controlling terminal.
    pub fn isctty(&self, p: &Caller) -> bool {
        match (&p.session, &self.session) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b) && p.controlt,
            _ => false,
        }
    }

    /// `ttnread`: what a read would return now.
    pub fn ttnread(&mut self, env: &mut dyn Env) -> i32 {
        if self.termios.lflag & lflag::PENDIN != 0 {
            self.ttypend(env);
        }
        let mut nread = self.canq.len() as i32;
        if self.termios.lflag & lflag::ICANON == 0 {
            nread += self.rawq.len() as i32;
            if nread < i32::from(self.termios.cc[cc::VMIN]) && self.termios.cc[cc::VTIME] == 0 {
                nread = 0;
            }
        }
        nread
    }

    // --- Read.

    /// `ttread`: a read of the terminal. `st` keeps what the read has
    /// learned across its sleeps.
    pub fn ttread(&mut self, uio: &mut dyn Uio, flag: i32, p: &Caller, env: &mut dyn Env, st: &mut ReadState, resumed: Option<(SleepReq, Woke)>) -> Io<Result<(), Errno>> {
        if let Some((req, woke)) = resumed {
            let r = self.slept(&req, woke);
            match st.at {
                ReadSleep::Input => match r {
                    Ok(()) | Err(Errno::EWOULDBLOCK) => {}
                    Err(e) => return Io::Done(Err(e)),
                },
                // The delayed suspend's nap: any error (its timeout too)
                // ends the read, through `out:`.
                ReadSleep::Dsusp => {
                    if let Err(e) = r {
                        if self.state & ts::TBLOCK != 0 && self.rawq.len() + self.canq.len() <= I_LOW_WATER {
                            self.ttyunblock();
                        }
                        return Io::Done(Err(e));
                    }
                }
            }
            // Another reader may have taken input meanwhile; the timer
            // state goes on as XNU's does.
            st.slp = 0;
        }
        loop {
            // `loop:`
            let mut lf = self.termios.lflag;
            if lf & lflag::PENDIN != 0 {
                self.ttypend(env);
                lf = self.termios.lflag;
            }
            // A background read is signalled; when the terminal is being
            // revoked every reader is in the background.
            if self.isbackground(p) || self.state & ts::REVOKE != 0 {
                if p.ttin_ignored || p.ttin_masked || p.lppwait {
                    return Io::Done(Err(Errno::EIO));
                }
                let Some(pg) = p.pgrp else { return Io::Done(Err(Errno::EIO)) };
                if p.pg_jobc == 0 {
                    return Io::Done(Err(Errno::EIO));
                }
                env.pgsignal(pg, sig::SIGTTIN, true);
                // As if a sleep were interrupted by the signal sent.
                return Io::Done(Err(Errno::EINTR));
            }
            if self.state & ts::ZOMBIE != 0 {
                // EOF.
                return Io::Done(Ok(()));
            }
            let canon = lf & lflag::ICANON != 0;
            let qlen = if canon { self.canq.len() } else { self.rawq.len() };
            let k = self.termios.cc;
            let mut sleep = false;
            let mut read = false;
            if flag & IO_NDELAY != 0 {
                if qlen > 0 {
                    read = true;
                } else {
                    if canon || k[cc::VMIN] != 0 {
                        return Io::Done(Err(Errno::EWOULDBLOCK));
                    }
                    // Polling: 0.
                    return Io::Done(Ok(()));
                }
            } else if !canon {
                let m = usize::from(k[cc::VMIN]);
                let t = i64::from(k[cc::VTIME]);
                if t == 0 {
                    if qlen < m {
                        sleep = true;
                    } else if qlen > 0 {
                        read = true;
                    } else {
                        // m, t and the count all 0: enough input.
                        return Io::Done(Ok(()));
                    }
                } else {
                    let t = t * 100_000;
                    let now = super::mach::system_nanotime();
                    let now_us = now.0 as i64 * 1_000_000 + i64::from(now.1 / 1000);
                    if m > 0 {
                        if qlen == 0 {
                            sleep = true;
                        } else if qlen >= m {
                            read = true;
                        } else {
                            if st.etime.is_none() || qlen > st.last_cc {
                                // The first character or another: the timer starts.
                                st.etime = Some(now_us + t);
                                st.slp = t;
                            } else if st.etime.unwrap() <= now_us {
                                read = true;
                            } else {
                                st.slp = st.etime.unwrap() - now_us;
                            }
                            st.last_cc = qlen;
                            if !read {
                                st.slp = ticks(st.slp);
                                sleep = true;
                            }
                        }
                    } else if qlen > 0 {
                        read = true;
                    } else {
                        match st.etime {
                            None => {
                                st.etime = Some(now_us + t);
                                st.slp = t;
                            }
                            Some(e) if e <= now_us => {
                                // Timed out, and 0 is enough input.
                                return Io::Done(Ok(()));
                            }
                            Some(e) => st.slp = e - now_us,
                        }
                        st.slp = ticks(st.slp);
                        sleep = true;
                    }
                }
            } else if qlen == 0 {
                sleep = true;
            } else {
                read = true;
            }
            if sleep && !read {
                // No input, or not enough, and the read may block.
                st.at = ReadSleep::Input;
                return match self.sleep(Chan::HupOrInput, st.slp as i32, true) {
                    Ok(req) => Io::Sleep(req),
                    Err(e) => Io::Done(Err(e)),
                };
            }
            // `read:` input present.
            let mut first = true;
            let mut error = Ok(());
            if canon || lf & (lflag::IEXTEN | lflag::ISIG) == (lflag::IEXTEN | lflag::ISIG) {
                // The slow case: a character at a time.
                let mut again = false;
                loop {
                    let qp = if canon { &mut self.canq } else { &mut self.rawq };
                    let c = qp.getc();
                    if c < 0 {
                        if first {
                            again = true;
                        }
                        break;
                    }
                    // Delayed suspend (^Y).
                    if cceq(k[cc::VDSUSP], c) && lf & (lflag::IEXTEN | lflag::ISIG) == (lflag::IEXTEN | lflag::ISIG) {
                        self.pgsignal(env, sig::SIGTSTP, true);
                        if first {
                            st.at = ReadSleep::Dsusp;
                            return match self.sleep(Chan::Ttread, HZ, true) {
                                Ok(req) => Io::Sleep(req),
                                Err(e) => Io::Done(Err(e)),
                            };
                        }
                        break;
                    }
                    // EOF only in canonical mode.
                    if cceq(k[cc::VEOF], c) && canon {
                        break;
                    }
                    if let Err(e) = uio.move_out(&[c as u8]) {
                        error = Err(e);
                        break;
                    }
                    if uio.resid() == 0 {
                        break;
                    }
                    // The end of a line, in canonical mode.
                    if canon && self.ttbreakc(c, lf) {
                        break;
                    }
                    first = false;
                }
                if again {
                    continue;
                }
            } else {
                let mut again = false;
                loop {
                    let size = uio.resid();
                    let mut ibuf = [0u8; IBUFSIZ];
                    let icc = size.min(IBUFSIZ);
                    let icc = self.rawq.q_to_b(&mut ibuf[..icc]);
                    if icc == 0 {
                        if first {
                            again = true;
                        }
                        break;
                    }
                    if let Err(e) = uio.move_out(&ibuf[..icc]) {
                        error = Err(e);
                        break;
                    }
                    if uio.resid() == 0 {
                        break;
                    }
                    first = false;
                }
                if again {
                    continue;
                }
            }
            // `out:` input unblocked now that the lists are lower.
            if self.state & ts::TBLOCK != 0 && self.rawq.len() + self.canq.len() <= I_LOW_WATER {
                self.ttyunblock();
            }
            return Io::Done(error);
        }
    }

    // --- Write.

    /// `ttwrite`: a write to the terminal. `st` keeps the characters taken
    /// from the caller and not yet put out across the write's sleeps.
    pub fn ttwrite(&mut self, uio: &mut dyn Uio, flag: i32, p: &Caller, env: &mut dyn Env, st: &mut WriteState, resumed: Option<(SleepReq, Woke)>) -> Io<Result<(), Errno>> {
        if st.count.is_none() {
            st.count = Some(uio.resid());
            st.hiwat = self.hiwat;
        }
        let count = st.count.unwrap();
        if let Some((req, woke)) = resumed {
            let r = self.slept(&req, woke);
            match st.at {
                WriteSleep::Carrier => {
                    if let Err(e) = r {
                        return self.ttwrite_out(uio, st, Err(e));
                    }
                }
                WriteSleep::Ovhiwat => {
                    if let Err(e) = r {
                        let e = if e == Errno::EWOULDBLOCK { Errno::EIO } else { e };
                        return self.ttwrite_out(uio, st, Err(e));
                    }
                }
            }
        }
        'lp: loop {
            // `loop:`
            if self.state & ts::ZOMBIE != 0 {
                let e = if uio.resid() == count { Err(Errno::EIO) } else { Ok(()) };
                return self.ttwrite_out(uio, st, e);
            }
            if self.state & ts::CONNECTED == 0 {
                if flag & IO_NDELAY != 0 {
                    return self.ttwrite_out(uio, st, Err(Errno::EWOULDBLOCK));
                }
                st.at = WriteSleep::Carrier;
                return match self.sleep(Chan::CarrOn, 0, true) {
                    Ok(req) => Io::Sleep(req),
                    Err(e) => self.ttwrite_out(uio, st, Err(e)),
                };
            }
            // A background writer is signalled under TOSTOP.
            if self.isbackground(p) && self.termios.lflag & lflag::TOSTOP != 0 && !p.lppwait && !p.ttou_ignored && !p.ttou_masked {
                let Some(pg) = p.pgrp else { return self.ttwrite_out(uio, st, Err(Errno::EIO)) };
                if p.pg_jobc == 0 {
                    return self.ttwrite_out(uio, st, Err(Errno::EIO));
                }
                env.pgsignal(pg, sig::SIGTTOU, true);
                return self.ttwrite_out(uio, st, Err(Errno::EINTR));
            }
            // The data in pieces of OBUFSIZ at most, translated, sleeping
            // at the high water for the device to take some.
            let mut overfull = false;
            let mut ovhiwat = false;
            while uio.resid() > 0 || st.left() > 0 {
                if self.termios.lflag & lflag::FLUSHO != 0 {
                    uio.finish();
                    st.clear();
                    return Io::Done(Ok(()));
                }
                if self.outq.len() as i32 > st.hiwat {
                    ovhiwat = true;
                    break;
                }
                if st.left() == 0 {
                    let cc = uio.resid().min(OBUFSIZ);
                    match uio.move_in(cc) {
                        Ok(b) => {
                            st.obuf = b;
                            st.cp = 0;
                        }
                        Err(e) => return self.ttwrite_out(uio, st, Err(e)),
                    }
                }
                let mut stop = false;
                while st.left() > 0 {
                    let rest = &st.obuf[st.cp..];
                    let ce = if self.termios.oflag & oflag::OPOST == 0 {
                        rest.len()
                    } else {
                        let ce = rest.len() - scanc(rest);
                        // None plain: this one goes through ttyoutput.
                        if ce == 0 {
                            self.rocount = 0;
                            let ch = i32::from(rest[0]);
                            if self.ttyoutput(ch) >= 0 {
                                overfull = true;
                                stop = true;
                                break;
                            }
                            st.cp += 1;
                            if self.termios.lflag & lflag::FLUSHO != 0 || self.outq.len() as i32 > st.hiwat {
                                ovhiwat = true;
                                stop = true;
                                break;
                            }
                            continue;
                        }
                        ce
                    };
                    // A run of plain characters, all at once.
                    self.rocount = 0;
                    let i = self.outq.b_to_q(&st.obuf[st.cp..st.cp + ce]);
                    let ce = ce - i;
                    self.column += ce as i32;
                    st.cp += ce;
                    tk(&TK_NOUT, ce as i64);
                    self.outcc += ce as i64;
                    if i > 0 {
                        overfull = true;
                        stop = true;
                        break;
                    }
                    if self.termios.lflag & lflag::FLUSHO != 0 || self.outq.len() as i32 > st.hiwat {
                        break;
                    }
                }
                if stop {
                    break;
                }
                self.ttstart();
            }
            if !overfull && !ovhiwat {
                return self.ttwrite_out(uio, st, Ok(()));
            }
            if overfull {
                // The ring is full: someone set the high water wrong, so
                // it is set here.
                st.hiwat = self.outq.len() as i32 - 1;
            }
            // `ovhiwat:`
            self.ttstart();
            // Only with FLUSHO, or a driver that takes output at once.
            if self.outq.len() as i32 <= st.hiwat {
                continue 'lp;
            }
            if flag & IO_NDELAY != 0 {
                uio.give_back(st.left());
                st.clear();
                return Io::Done(if uio.resid() == count { Err(Errno::EWOULDBLOCK) } else { Ok(()) });
            }
            self.state |= ts::SO_OLOWAT;
            st.at = WriteSleep::Ovhiwat;
            return match self.sleep(Chan::OLowat, self.timeout, true) {
                Ok(req) => Io::Sleep(req),
                Err(e) => self.ttwrite_out(uio, st, Err(e)),
            };
        }
    }

    /// `ttwrite`'s `out:`: what was taken and not put out goes back.
    fn ttwrite_out(&mut self, uio: &mut dyn Uio, st: &mut WriteState, r: Result<(), Errno>) -> Io<Result<(), Errno>> {
        uio.give_back(st.left());
        st.clear();
        Io::Done(r)
    }

    // --- ^T.

    /// `ttycheckoutq(tp, 0)`: room for a kernel message.
    fn ttycheckoutq(&mut self) -> bool {
        let hiwat = self.hiwat;
        if self.outq.len() as i32 > hiwat + OBUFSIZ as i32 + 100 {
            while self.outq.len() as i32 > hiwat {
                self.ttstart();
                if self.outq.len() as i32 <= hiwat {
                    break;
                }
                return false;
            }
        }
        true
    }

    /// `ttyinfo_locked`: the foreground group's state, printed.
    pub fn ttyinfo_locked(&mut self, env: &mut dyn Env) {
        if !self.ttycheckoutq() {
            return;
        }
        // FSHIFT 11.
        let load = ((u64::from(env.loadavg()) * 100 + 1024) >> 11) as i64;
        self.ttyprintf(&format!("load: {}.{:02} ", load / 100, load % 100));
        if self.session.is_none() {
            self.ttyprintf("not a controlling terminal\n");
            self.rocount = 0;
            return;
        }
        let Some(pg) = self.pgrp else {
            self.ttyprintf("no foreground process group\n");
            self.rocount = 0;
            return;
        };
        let Some(pick) = env.fg_pick(pg) else { return };
        let info = match env.fg_info(pick) {
            None => return,
            Some(Err(())) => {
                self.ttyprintf("foreground process without thread\n");
                self.rocount = 0;
                return;
            }
            Some(Ok(i)) => i,
        };
        let state = match info.run_state {
            1 => "running",
            2 => "stopped",
            3 => "waiting",
            4 => "uninterruptible",
            5 => "halted",
            _ => "unknown",
        };
        self.ttyprintf(&format!(" cmd: {} {} {} {}.{:02}u {}.{:02}s\n", info.comm, info.pid, state, info.utime.0, info.utime.1 / 10000, info.stime.0, info.stime.1 / 10000));
        self.rocount = 0;
    }
}

/// `FLUSHQ`.
fn flushq(q: &mut Clist) {
    let n = q.len();
    if n != 0 {
        q.ndflush(n);
    }
}

/// Where `ttyinput` goes after its scan (its labels).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Next {
    Out,
    Store,
    Endcase,
    Restartoutput,
    Startoutput,
}

/// `ttread`'s microseconds as ticks, rounded up: `((u_int32_t)slp * hz +
/// 999999) / 1000000` in XNU's 32-bit arithmetic.
fn ticks(slp: i64) -> i64 {
    i64::from((slp as u32).wrapping_mul(HZ as u32).wrapping_add(999_999)) / 1_000_000
}

/// Which of `ttread`'s sleeps it is in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ReadSleep {
    /// `ttyin` or `ttyhup`: for input.
    #[default]
    Input,
    /// `ttybg3`: after a delayed suspend.
    Dsusp,
}

/// What a read keeps across its sleeps: its VMIN/VTIME timer.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReadState {
    /// `etime`, when `has_etime`: the deadline in microseconds of uptime.
    pub etime: Option<i64>,
    pub last_cc: usize,
    /// `slp`: the sleep's timeout, in ticks once computed.
    pub slp: i64,
    pub at: ReadSleep,
}

/// Which of `ttwrite`'s sleeps it is in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WriteSleep {
    /// `ttydcd`: for the carrier.
    #[default]
    Carrier,
    /// `ttywri`: for the output to fall to the low water.
    Ovhiwat,
}

/// What a write keeps across its sleeps.
#[derive(Clone, Debug, Default)]
pub struct WriteState {
    /// `count`: the resid it began with.
    pub count: Option<usize>,
    /// `hiwat`, which an overfull ring lowers.
    pub hiwat: i32,
    /// `obuf` and `cp`: taken from the caller, out up to `cp`.
    pub obuf: Vec<u8>,
    pub cp: usize,
    pub at: WriteSleep,
}

impl WriteState {
    /// `cc`: what is taken and not out.
    fn left(&self) -> usize {
        self.obuf.len() - self.cp
    }

    fn clear(&mut self) {
        self.obuf.clear();
        self.cp = 0;
    }
}

/// The terminal ioctls (`bsd/sys/ttycom.h`, `filio.h`, `ioctl_compat.h`),
/// as a 64-bit process numbers them.
pub mod cmd {
    pub const FIOASYNC: u64 = 0x8004_667d;
    pub const FIONBIO: u64 = 0x8004_667e;
    pub const FIONREAD: u64 = 0x4004_667f;
    pub const TIOCEXCL: u64 = 0x2000_740d;
    pub const TIOCNXCL: u64 = 0x2000_740e;
    pub const TIOCFLUSH: u64 = 0x8004_7410;
    pub const TIOCGETA_32: u64 = 0x402c_7413;
    pub const TIOCGETA_64: u64 = 0x4048_7413;
    pub const TIOCSETA_32: u64 = 0x802c_7414;
    pub const TIOCSETA_64: u64 = 0x8048_7414;
    pub const TIOCSETAW_32: u64 = 0x802c_7415;
    pub const TIOCSETAW_64: u64 = 0x8048_7415;
    pub const TIOCSETAF_32: u64 = 0x802c_7416;
    pub const TIOCSETAF_64: u64 = 0x8048_7416;
    pub const TIOCGETD: u64 = 0x4004_741a;
    pub const TIOCSETD: u64 = 0x8004_741b;
    pub const TIOCIXON: u64 = 0x2000_7481;
    pub const TIOCIXOFF: u64 = 0x2000_7480;
    pub const TIOCSBRK: u64 = 0x2000_747b;
    pub const TIOCCBRK: u64 = 0x2000_747a;
    pub const TIOCGPGRP: u64 = 0x4004_7477;
    pub const TIOCSPGRP: u64 = 0x8004_7476;
    pub const TIOCOUTQ: u64 = 0x4004_7473;
    pub const TIOCSTI: u64 = 0x8001_7472;
    pub const TIOCNOTTY: u64 = 0x2000_7471;
    pub const TIOCPKT: u64 = 0x8004_7470;
    pub const TIOCSTOP: u64 = 0x2000_746f;
    pub const TIOCSTART: u64 = 0x2000_746e;
    pub const TIOCGWINSZ: u64 = 0x4008_7468;
    pub const TIOCSWINSZ: u64 = 0x8008_7467;
    pub const TIOCUCNTL: u64 = 0x8004_7466;
    pub const TIOCSTAT: u64 = 0x2000_7465;
    pub const TIOCSCONS: u64 = 0x2000_7463;
    pub const TIOCCONS: u64 = 0x8004_7462;
    pub const TIOCSCTTY: u64 = 0x2000_7461;
    pub const TIOCEXT: u64 = 0x8004_7460;
    pub const TIOCSIG: u64 = 0x2000_745f;
    pub const TIOCDRAIN: u64 = 0x2000_745e;
    pub const TIOCSDRAINWAIT: u64 = 0x8004_7457;
    pub const TIOCGDRAINWAIT: u64 = 0x4004_7456;
    pub const TIOCPTYGRANT: u64 = 0x2000_7454;
    pub const TIOCPTYGNAME: u64 = 0x4080_7453;
    pub const TIOCPTYUNLK: u64 = 0x2000_7452;
    pub const TIOCREVOKE: u64 = 0x2000_7451;
    pub const TIOCREVOKECLEAR: u64 = 0x2000_7450;
    /// `UIOCCMD(0)`: `_IO('u', 0)`.
    pub const UIOCCMD0: u64 = 0x2000_7500;
    // ioctl_compat.h.
    pub const OTIOCGETD: u64 = 0x4004_7400;
    pub const OTIOCSETD: u64 = 0x8004_7401;
    pub const TIOCHPCL: u64 = 0x2000_7402;
    pub const TIOCGETP: u64 = 0x4006_7408;
    pub const TIOCSETP: u64 = 0x8006_7409;
    pub const TIOCSETN: u64 = 0x8006_740a;
    pub const TIOCSETC: u64 = 0x8006_7411;
    pub const TIOCGETC: u64 = 0x4006_7412;
    pub const TIOCLBIS: u64 = 0x8004_747f;
    pub const TIOCLBIC: u64 = 0x8004_747e;
    pub const TIOCLSET: u64 = 0x8004_747d;
    pub const TIOCLGET: u64 = 0x4004_747c;
    pub const TIOCSLTC: u64 = 0x8006_7475;
    pub const TIOCGLTC: u64 = 0x4006_7474;
    pub const OTIOCCONS: u64 = 0x2000_7462;
    pub const TIOCGSID: u64 = 0x4004_7463;
}

/// `nlinesw`: the line disciplines `linesw` has room for, of which 0
/// (termios) and 2 (NTTYDISC, the same) open; the rest are `NODISC`.
const NLINESW: i32 = 8;

fn int(data: &[u8]) -> i32 {
    i32::from_le_bytes(data[..4].try_into().unwrap())
}

fn put_int(data: &mut [u8], v: i32) {
    data[..4].copy_from_slice(&v.to_le_bytes());
}

/// Where an ioctl that sleeps is: the command it is carrying out (a
/// compat command's termios one) with its data, and that its background
/// check is behind it.
#[derive(Clone, Debug, Default)]
pub struct IoctlState {
    pub inner: Option<(u64, Vec<u8>)>,
}

impl Tty {
    /// `ttioctl_locked`: the ioctls of every terminal.
    #[allow(clippy::too_many_arguments)]
    pub fn ttioctl_locked(&mut self, me: &Arc<TtyCell>, com: u64, data: &mut [u8], flag: i32, p: &Caller, env: &mut dyn Env, st: &mut IoctlState, resumed: Option<(SleepReq, Woke)>) -> Io<Result<(), Errno>> {
        if let Some((icom, mut idata)) = st.inner.take() {
            // Back from a drain: on where it slept, past the checks.
            let r = self.ttioctl_cmd(me, icom, &mut idata, flag, p, env, resumed);
            if let Io::Sleep(_) = r {
                st.inner = Some((icom, idata));
            }
            return r;
        }
        if let Some(e) = self.ttioctl_bg(com, p, env) {
            return Io::Done(Err(e));
        }
        // ttcompat's commands that are others: through ttioctl_locked
        // again as those (and its background check).
        let redirect = match com {
            cmd::TIOCSETP | cmd::TIOCSETN | cmd::TIOCSETC | cmd::TIOCSLTC | cmd::TIOCLBIS | cmd::TIOCLBIC | cmd::TIOCLSET => {
                let mut term = self.termios;
                let mut ncom = com;
                if let Err(e) = self.ttsetcompat(&mut ncom, data, &mut term) {
                    return Io::Done(Err(e));
                }
                let mut tb = vec![0u8; TERMIOS_SIZE];
                term.to_bytes(&mut tb);
                Some((ncom, tb))
            }
            cmd::OTIOCSETD => {
                let v = int(data);
                let mut d = vec![0u8; 8];
                put_int(&mut d, if v == 2 { 0 } else { v });
                Some((cmd::TIOCSETD, d))
            }
            cmd::OTIOCCONS => {
                let mut d = vec![0u8; 8];
                put_int(&mut d, 1);
                Some((cmd::TIOCCONS, d))
            }
            _ => None,
        };
        if let Some((ncom, mut nd)) = redirect {
            if let Some(e) = self.ttioctl_bg(ncom, p, env) {
                return Io::Done(Err(e));
            }
            let r = self.ttioctl_cmd(me, ncom, &mut nd, flag, p, env, None);
            if let Io::Sleep(_) = r {
                st.inner = Some((ncom, nd));
            }
            return r;
        }
        let r = self.ttioctl_cmd(me, com, data, flag, p, env, None);
        if let Io::Sleep(_) = r {
            st.inner = Some((com, data.to_vec()));
        }
        r
    }

    /// `ttioctl_locked`'s first switch: a command that changes the
    /// terminal, from the background, signals the group (and is EINTR).
    fn ttioctl_bg(&mut self, com: u64, p: &Caller, env: &mut dyn Env) -> Option<Errno> {
        use cmd::*;
        let changes = matches!(
            com,
            TIOCIXON
                | TIOCIXOFF
                | TIOCDRAIN
                | TIOCFLUSH
                | TIOCSTOP
                | TIOCSTART
                | TIOCSETA_32
                | TIOCSETA_64
                | TIOCSETD
                | TIOCSETAF_32
                | TIOCSETAF_64
                | TIOCSETAW_32
                | TIOCSETAW_64
                | TIOCSPGRP
                | TIOCSTAT
                | TIOCSTI
                | TIOCSWINSZ
                | TIOCLBIC
                | TIOCLBIS
                | TIOCLSET
                | TIOCSETC
                | OTIOCSETD
                | TIOCSETN
                | TIOCSETP
                | TIOCSLTC
        );
        if changes && self.isbackground(p) && !p.lppwait && !p.ttou_ignored && !p.ttou_masked {
            let Some(pg) = p.pgrp else { return Some(Errno::EIO) };
            if p.pg_jobc == 0 {
                return Some(Errno::EIO);
            }
            env.pgsignal(pg, sig::SIGTTOU, true);
            // As if a sleep were interrupted by the signal sent.
            return Some(Errno::EINTR);
        }
        None
    }

    /// `ttioctl_locked`'s second switch: the command itself.
    #[allow(clippy::too_many_arguments)]
    fn ttioctl_cmd(&mut self, me: &Arc<TtyCell>, com: u64, data: &mut [u8], flag: i32, p: &Caller, env: &mut dyn Env, resumed: Option<(SleepReq, Woke)>) -> Io<Result<(), Errno>> {
        use cmd::*;
        let done = |r: Result<(), Errno>| Io::Done(r);
        match com {
            FIOASYNC => {
                if int(data) != 0 {
                    self.state |= ts::ASYNC;
                } else {
                    self.state &= !ts::ASYNC;
                }
            }
            FIONBIO => {}
            FIONREAD => {
                let n = self.ttnread(env);
                put_int(data, n);
            }
            TIOCEXCL => self.state |= ts::XCLUDE,
            TIOCFLUSH => {
                let mut flags = int(data);
                if flags == 0 {
                    flags = FREAD | FWRITE;
                } else {
                    flags &= FREAD | FWRITE;
                }
                self.ttyflush(flags, env);
            }
            TIOCSCONS | TIOCCONS => {
                let on = com == TIOCSCONS || int(data) != 0;
                let constty = copy_constty();
                let is_me = constty.as_ref().is_some_and(|c| Arc::ptr_eq(c, me));
                if on {
                    if constty.as_ref().is_some_and(|c| !Arc::ptr_eq(c, me) && c.state_unlocked() & ts::CONNECTED != 0) {
                        return done(Err(Errno::EBUSY));
                    }
                    if !p.suser {
                        return done(Err(Errno::EPERM));
                    }
                    if !is_me {
                        set_constty(Some(Arc::clone(me)));
                    }
                } else if is_me {
                    set_constty(None);
                }
                // KMIOCDISABLCONS to the console's device or this one: a
                // pty's ptyioctl takes it as nothing.
            }
            TIOCDRAIN => match self.ttywait(resumed) {
                Io::Sleep(r) => return Io::Sleep(r),
                Io::Done(Err(e)) => return done(Err(e)),
                Io::Done(Ok(())) => {}
            },
            TIOCGETA_32 => self.termios.to_bytes32(data),
            TIOCGETA_64 => self.termios.to_bytes(data),
            TIOCGETD => put_int(data, self.line),
            TIOCGWINSZ => self.winsize.to_bytes(data),
            TIOCGPGRP => {
                if !self.isctty(p) {
                    return done(Err(Errno::ENOTTY));
                }
                put_int(data, self.pgrp.map_or(NO_PID, |g| g.id));
            }
            TIOCHPCL => self.termios.cflag |= cflag::HUPCL,
            TIOCNXCL => self.state &= !ts::XCLUDE,
            TIOCOUTQ => put_int(data, self.outq.len() as i32),
            TIOCSETA_32 | TIOCSETA_64 | TIOCSETAW_32 | TIOCSETAW_64 | TIOCSETAF_32 | TIOCSETAF_64 => {
                let mut t = if matches!(com, TIOCSETA_32 | TIOCSETAW_32 | TIOCSETAF_32) { Termios::from_bytes32(data) } else { Termios::from_bytes(data) };
                if t.ispeed == 0 {
                    t.ispeed = t.ospeed;
                }
                let af = matches!(com, TIOCSETAF_32 | TIOCSETAF_64);
                if matches!(com, TIOCSETAW_32 | TIOCSETAF_32 | TIOCSETAW_64 | TIOCSETAF_64) {
                    match self.ttywait(resumed) {
                        Io::Sleep(r) => return Io::Sleep(r),
                        Io::Done(Err(e)) => return done(Err(e)),
                        Io::Done(Ok(())) => {}
                    }
                    if af {
                        self.ttyflush(FREAD, env);
                    }
                }
                if t.cflag & cflag::CIGNORE == 0 {
                    // The device's hardware: a pty has no t_param.
                    if t.cflag & cflag::CLOCAL != 0 && self.termios.cflag & cflag::CLOCAL == 0 {
                        // Getting rid of a disconnection, the only other
                        // way being the session leader's exit.
                        self.state &= !ts::ZOMBIE;
                        self.wakeup(Chan::CarrOn);
                        self.ttwakeup(env);
                        self.ttwwakeup();
                    }
                    if (self.state & ts::CARR_ON != 0 || t.cflag & cflag::CLOCAL != 0) && self.state & ts::ZOMBIE == 0 {
                        self.state |= ts::CONNECTED;
                    } else {
                        self.state &= !ts::CONNECTED;
                    }
                    self.termios.cflag = t.cflag;
                    self.termios.ispeed = t.ispeed;
                    self.termios.ospeed = t.ospeed;
                    self.ttsetwater();
                }
                if t.lflag & lflag::ICANON != self.termios.lflag & lflag::ICANON && !af {
                    if t.lflag & lflag::ICANON != 0 {
                        self.termios.lflag |= lflag::PENDIN;
                    } else {
                        // Whatever is in the canonical list joins the raw
                        // one, and the lists change places.
                        let mut raw = std::mem::take(&mut self.rawq);
                        self.canq.catq(&mut raw);
                        self.rawq = raw;
                        std::mem::swap(&mut self.rawq, &mut self.canq);
                        self.termios.lflag &= !lflag::PENDIN;
                    }
                    self.ttwakeup(env);
                }
                self.termios.iflag = t.iflag;
                self.termios.oflag = t.oflag;
                // EXTPROC is read-only.
                if self.termios.lflag & lflag::EXTPROC != 0 {
                    t.lflag |= lflag::EXTPROC;
                } else {
                    t.lflag &= !lflag::EXTPROC;
                }
                self.termios.lflag = t.lflag | (self.termios.lflag & lflag::PENDIN);
                if t.cc[cc::VMIN] != self.termios.cc[cc::VMIN] || t.cc[cc::VTIME] != self.termios.cc[cc::VTIME] {
                    self.ttwakeup(env);
                }
                self.termios.cc = t.cc;
            }
            TIOCSETD => {
                let t = int(data);
                if t >= NLINESW || t < 0 {
                    return done(Err(Errno::ENXIO));
                }
                if t != self.line {
                    // The old discipline's l_close, then the new one's
                    // l_open: only 0 and 2 (both termios) open.
                    match self.ttylclose(flag, env, resumed) {
                        Io::Sleep(r) => return Io::Sleep(r),
                        Io::Done(_) => {}
                    }
                    if t != 0 && t != 2 {
                        // enodev; the old discipline opened again.
                        let dev = self.dev;
                        self.ttyopen(dev);
                        return done(Err(Errno::ENODEV));
                    }
                    let dev = self.dev;
                    self.ttyopen(dev);
                    self.line = t;
                }
            }
            TIOCSTART => {
                if self.state & ts::TTSTOP != 0 || self.termios.lflag & lflag::FLUSHO != 0 {
                    self.termios.lflag &= !lflag::FLUSHO;
                    self.state &= !ts::TTSTOP;
                    self.ttstart();
                }
            }
            TIOCSTI => {
                if !p.suser && flag & FREAD == 0 {
                    return done(Err(Errno::EPERM));
                }
                if !p.suser && !self.isctty(p) {
                    return done(Err(Errno::EACCES));
                }
                self.ttyinput(i32::from(data[0]), env);
            }
            TIOCSTOP => {
                if self.state & ts::TTSTOP == 0 {
                    self.state |= ts::TTSTOP;
                    self.ttystop(0);
                }
            }
            TIOCIXON => self.ttyunblock(),
            TIOCIXOFF => self.ttyblock(),
            TIOCSCTTY => {
                // The session's vnode is set by the caller (vn_ioctl) on
                // success.
                let (Some(pg), Some(sess)) = (p.pgrp, p.session.clone()) else {
                    return done(Err(Errno::EPERM));
                };
                // Only a session leader.
                if env.session_leader(&sess) != Some(p.pid) {
                    return done(Err(Errno::EPERM));
                }
                // Already this session's terminal: nothing to do.
                if self.session.as_ref().is_some_and(|s| Arc::ptr_eq(s, &sess)) {
                    return done(Ok(()));
                }
                // Another session's terminal, or a session with a terminal.
                let mut s = sess.lock();
                if s.ttyvp.is_some() || self.session.is_some() {
                    return done(Err(Errno::EPERM));
                }
                s.ttypgrpid = pg.id;
                s.set_tty(me, self.dev);
                drop(s);
                self.pgrp = Some(pg);
                self.session = Some(sess);
                env.set_controlt();
            }
            TIOCSPGRP => {
                if !self.isctty(p) {
                    return done(Err(Errno::ENOTTY));
                }
                let Some((pgrp, psess)) = env.pgrp_find(int(data)) else {
                    return done(Err(Errno::EINVAL));
                };
                if !p.session.as_ref().is_some_and(|s| Arc::ptr_eq(s, &psess)) {
                    return done(Err(Errno::EPERM));
                }
                self.pgrp = Some(pgrp);
                if let Some(s) = &p.session {
                    s.lock().ttypgrpid = pgrp.id;
                }
                // Readers check again whether they are in the foreground.
                self.wakeup(Chan::HupOrInput);
            }
            TIOCSTAT => self.ttyinfo_locked(env),
            TIOCSWINSZ => {
                let w = Winsize::from_bytes(data);
                if w != self.winsize {
                    self.winsize = w;
                    self.pgsignal(env, sig::SIGWINCH, true);
                }
            }
            TIOCSDRAINWAIT => {
                if !p.suser {
                    return done(Err(Errno::EPERM));
                }
                self.timeout = int(data).wrapping_mul(HZ);
                self.wakeup(Chan::OComplete);
                self.wakeup(Chan::OLowat);
            }
            TIOCGDRAINWAIT => put_int(data, self.timeout / HZ),
            TIOCREVOKE => {
                self.state |= ts::REVOKE;
                self.gen += 1;
                // Only ttread's channel: it is the one that has hung.
                self.wakeup(Chan::HupOrInput);
            }
            TIOCREVOKECLEAR => self.state &= !ts::REVOKE,
            _ => return done(self.ttcompat(com, data, env)),
        }
        done(Ok(()))
    }

    /// `ttcompat`'s gets, and the commands it turns into others.
    fn ttcompat(&mut self, com: u64, data: &mut [u8], env: &mut dyn Env) -> Result<(), Errno> {
        use cmd::*;
        match com {
            TIOCGETP => {
                let k = self.termios.cc;
                let ospeed = ttcompatspeedtab(self.termios.ospeed) as i8;
                let ispeed = if self.termios.ispeed == 0 { ospeed } else { ttcompatspeedtab(self.termios.ispeed) as i8 };
                self.flags = self.ttcompatgetflags();
                data[0] = ispeed as u8;
                data[1] = ospeed as u8;
                data[2] = k[cc::VERASE];
                data[3] = k[cc::VKILL];
                data[4..6].copy_from_slice(&(self.flags as i16).to_le_bytes());
            }
            TIOCGETC => {
                let k = self.termios.cc;
                data[..6].copy_from_slice(&[k[cc::VINTR], k[cc::VQUIT], k[cc::VSTART], k[cc::VSTOP], k[cc::VEOF], k[cc::VEOL]]);
            }
            TIOCGLTC => {
                let k = self.termios.cc;
                data[..6].copy_from_slice(&[k[cc::VSUSP], k[cc::VDSUSP], k[cc::VREPRINT], k[cc::VDISCARD], k[cc::VWERASE], k[cc::VLNEXT]]);
            }
            TIOCLGET => {
                self.flags = ((self.ttcompatgetflags() as u32 & 0xffff_0000) | (self.flags as u32 & 0xffff)) as i32;
                put_int(data, self.flags >> 16);
            }
            OTIOCGETD => put_int(data, if self.line != 0 { self.line } else { 2 }),
            TIOCGSID => {
                let Some(s) = self.session.clone() else { return Err(Errno::ENOTTY) };
                let Some(leader) = env.session_leader(&s) else { return Err(Errno::ENOTTY) };
                put_int(data, leader);
            }
            _ => return Err(Errno::ENOTTY),
        }
        Ok(())
    }

    /// `ttsetcompat`: a 4.3BSD set as the termios it means; the command
    /// becomes TIOCSETA or TIOCSETAF.
    fn ttsetcompat(&mut self, com: &mut u64, data: &[u8], term: &mut Termios) -> Result<(), Errno> {
        use cmd::*;
        match *com {
            TIOCSETP | TIOCSETN => {
                let (sg_ispeed, sg_ospeed) = (data[0] as i8, data[1] as i8);
                if sg_ispeed < 0 {
                    return Err(Errno::EINVAL);
                }
                let ispeed = sg_ispeed as u32;
                if ispeed > MAX_SPEED {
                    return Err(Errno::EINVAL);
                }
                term.ispeed = if ispeed != ttcompatspeedtab(self.termios.ispeed) { COMPATSPCODES[ispeed as usize] } else { self.termios.ispeed };
                if sg_ospeed < 0 {
                    return Err(Errno::EINVAL);
                }
                let ospeed = sg_ospeed as u32;
                if ospeed > MAX_SPEED {
                    return Err(Errno::EINVAL);
                }
                term.ospeed = if ospeed != ttcompatspeedtab(self.termios.ospeed) { COMPATSPCODES[ospeed as usize] } else { self.termios.ospeed };
                term.cc[cc::VERASE] = data[2];
                term.cc[cc::VKILL] = data[3];
                let sg_flags = i16::from_le_bytes([data[4], data[5]]);
                self.flags = ((self.flags as u32 & 0xffff_0000) | (sg_flags as i32 as u32 & 0xffff)) as i32;
                self.ttcompatsetflags(term);
                *com = if *com == TIOCSETP { TIOCSETAF_64 } else { TIOCSETA_64 };
            }
            TIOCSETC => {
                let k = &mut term.cc;
                k[cc::VINTR] = data[0];
                k[cc::VQUIT] = data[1];
                k[cc::VSTART] = data[2];
                k[cc::VSTOP] = data[3];
                k[cc::VEOF] = data[4];
                k[cc::VEOL] = data[5];
                if data[5] as i8 == -1 {
                    k[cc::VEOL2] = VDISABLE;
                }
                *com = TIOCSETA_64;
            }
            TIOCSLTC => {
                let k = &mut term.cc;
                k[cc::VSUSP] = data[0];
                k[cc::VDSUSP] = data[1];
                k[cc::VREPRINT] = data[2];
                k[cc::VDISCARD] = data[3];
                k[cc::VWERASE] = data[4];
                k[cc::VLNEXT] = data[5];
                *com = TIOCSETA_64;
            }
            TIOCLBIS | TIOCLBIC | TIOCLSET => {
                let set = int(data);
                if *com == TIOCLSET {
                    self.flags = ((self.flags as u32 & 0xffff) | ((set as u32) << 16)) as i32;
                } else {
                    self.flags = ((self.ttcompatgetflags() as u32 & 0xffff_0000) | (self.flags as u32 & 0xffff)) as i32;
                    if *com == TIOCLBIS {
                        self.flags |= set << 16;
                    } else {
                        self.flags &= !(set << 16);
                    }
                }
                self.ttcompatsetlflags(term);
                *com = TIOCSETA_64;
            }
            _ => {}
        }
        Ok(())
    }

    /// `ttcompatgetflags`: the termios state as 4.3BSD flags.
    fn ttcompatgetflags(&self) -> i32 {
        use cflag::*;
        use compat::*;
        use iflag::*;
        use lflag::*;
        use oflag::*;
        let (ifl, lf, ofl, cfl) = (self.termios.iflag, self.termios.lflag, self.termios.oflag, self.termios.cflag);
        let mut flags: u32 = 0;
        if ifl & IXOFF != 0 {
            flags |= TANDEM;
        }
        if ifl & ICRNL != 0 || ofl & ONLCR != 0 {
            flags |= CRMOD;
        }
        if cfl & CSIZE == CS8 {
            flags |= PASS8;
            if ifl & ISTRIP != 0 {
                flags |= ANYP;
            }
        } else if cfl & PARENB != 0 {
            if ifl & INPCK != 0 {
                if cfl & PARODD != 0 {
                    flags |= ODDP;
                } else {
                    flags |= EVENP;
                }
            } else {
                flags |= EVENP | ODDP;
            }
        }
        if lf & ICANON == 0 {
            // A fudge.
            if ifl & (INPCK | ISTRIP | IXON) != 0 || lf & (IEXTEN | ISIG) != 0 || cfl & (CSIZE | PARENB) != CS8 {
                flags |= CBREAK;
            } else {
                flags |= RAW;
            }
        }
        if flags & RAW == 0 && ofl & OPOST == 0 && cfl & (CSIZE | PARENB) == CS8 {
            flags |= LITOUT;
        }
        if cfl & cflag::MDMBUF != 0 {
            flags |= compat::MDMBUF;
        }
        if cfl & HUPCL == 0 {
            flags |= NOHANG;
        }
        if ofl & OXTABS != 0 {
            flags |= XTABS;
        }
        if lf & ECHOE != 0 {
            flags |= CRTERA | CRTBS;
        }
        if lf & ECHOKE != 0 {
            flags |= CRTKIL | CRTBS;
        }
        if lf & ECHOPRT != 0 {
            flags |= PRTERA;
        }
        if lf & ECHOCTL != 0 {
            flags |= CTLECH;
        }
        if ifl & IXANY == 0 {
            flags |= DECCTQ;
        }
        flags |= (lf & (lflag::ECHO | lflag::TOSTOP | lflag::FLUSHO | lflag::PENDIN | lflag::NOFLSH)) as u32;
        flags as i32
    }

    /// `ttcompatsetflags`: TIOCSETP's flags as termios.
    fn ttcompatsetflags(&self, t: &mut Termios) {
        use cflag::*;
        use compat::*;
        use iflag::*;
        use lflag::*;
        use oflag::*;
        let flags = self.flags as u32;
        let (mut ifl, mut ofl, mut lf, mut cfl) = (t.iflag, t.oflag, t.lflag, t.cflag);
        if flags & RAW != 0 {
            ifl = IGNBRK;
            lf &= !(ECHOCTL | ISIG | ICANON | IEXTEN);
        } else {
            ifl &= !(PARMRK | IGNPAR | IGNCR | INLCR);
            ifl |= BRKINT | IXON | IMAXBEL;
            lf |= ISIG | IEXTEN | ECHOCTL;
            if flags & XTABS != 0 {
                ofl |= OXTABS;
            } else {
                ofl &= !OXTABS;
            }
            if flags & CBREAK != 0 {
                lf &= !ICANON;
            } else {
                lf |= ICANON;
            }
            if flags & CRMOD != 0 {
                ifl |= ICRNL;
                ofl |= ONLCR;
            } else {
                ifl &= !ICRNL;
                ofl &= !ONLCR;
            }
        }
        if flags & compat::ECHO != 0 {
            lf |= lflag::ECHO;
        } else {
            lf &= !lflag::ECHO;
        }
        csize_flags(flags, &mut ifl, &mut ofl, &mut cfl);
        if flags & (EVENP | ODDP) == EVENP {
            ifl |= INPCK;
            cfl &= !PARODD;
        } else if flags & (EVENP | ODDP) == ODDP {
            ifl |= INPCK;
            cfl |= PARODD;
        } else {
            ifl &= !INPCK;
        }
        if flags & TANDEM != 0 {
            ifl |= IXOFF;
        } else {
            ifl &= !IXOFF;
        }
        if flags & DECCTQ == 0 {
            ifl |= IXANY;
        } else {
            ifl &= !IXANY;
        }
        t.iflag = ifl;
        t.oflag = ofl;
        t.lflag = lf;
        t.cflag = cfl;
    }

    /// `ttcompatsetlflags`: the local mode word as termios.
    fn ttcompatsetlflags(&self, t: &mut Termios) {
        use cflag::*;
        use compat::*;
        use iflag::*;
        use lflag::*;
        let flags = self.flags as u32;
        let (mut ifl, mut ofl, mut lf, mut cfl) = (t.iflag, t.oflag, t.lflag, t.cflag);
        ifl &= !(PARMRK | IGNPAR | IGNCR | INLCR);
        let set = |on: bool, v: &mut u64, bit: u64| if on { *v |= bit } else { *v &= !bit };
        set(flags & CRTERA != 0, &mut lf, ECHOE);
        set(flags & CRTKIL != 0, &mut lf, ECHOKE);
        set(flags & PRTERA != 0, &mut lf, ECHOPRT);
        set(flags & CTLECH != 0, &mut lf, ECHOCTL);
        set(flags & TANDEM != 0, &mut ifl, IXOFF);
        set(flags & DECCTQ == 0, &mut ifl, IXANY);
        set(flags & compat::MDMBUF != 0, &mut cfl, cflag::MDMBUF);
        set(flags & NOHANG == 0, &mut cfl, HUPCL);
        lf &= !(lflag::TOSTOP | lflag::FLUSHO | lflag::PENDIN | lflag::NOFLSH);
        lf |= u64::from(flags) & (lflag::TOSTOP | lflag::FLUSHO | lflag::PENDIN | lflag::NOFLSH);
        csize_flags(flags, &mut ifl, &mut ofl, &mut cfl);
        t.iflag = ifl;
        t.oflag = ofl;
        t.lflag = lf;
        t.cflag = cfl;
    }
}

/// The character size, ISTRIP and OPOST the RAW, LITOUT and PASS8 flags
/// mean (both of `ttcompatsetflags` and `ttcompatsetlflags`).
fn csize_flags(flags: u32, ifl: &mut u64, ofl: &mut u64, cfl: &mut u64) {
    use compat::*;
    *cfl &= !(cflag::CSIZE | cflag::PARENB);
    if flags & (RAW | LITOUT | PASS8) != 0 {
        *cfl |= cflag::CS8;
        if flags & (RAW | PASS8) == 0 || flags & (RAW | PASS8 | ANYP) == (PASS8 | ANYP) {
            *ifl |= iflag::ISTRIP;
        } else {
            *ifl &= !iflag::ISTRIP;
        }
        if flags & (RAW | LITOUT) != 0 {
            *ofl &= !oflag::OPOST;
        } else {
            *ofl |= oflag::OPOST;
        }
    } else {
        *cfl |= cflag::CS7 | cflag::PARENB;
        *ifl |= iflag::ISTRIP;
        *ofl |= oflag::OPOST;
    }
}

/// The 4.3BSD terminal flags (`bsd/sys/ioctl_compat.h`).
mod compat {
    pub const TANDEM: u32 = 0x0000_0001;
    pub const CBREAK: u32 = 0x0000_0002;
    pub const ECHO: u32 = 0x0000_0008;
    pub const CRMOD: u32 = 0x0000_0010;
    pub const RAW: u32 = 0x0000_0020;
    pub const ODDP: u32 = 0x0000_0040;
    pub const EVENP: u32 = 0x0000_0080;
    pub const ANYP: u32 = 0x0000_00c0;
    pub const XTABS: u32 = 0x0000_0c00;
    pub const CRTBS: u32 = 0x0001_0000;
    pub const PRTERA: u32 = 0x0002_0000;
    pub const CRTERA: u32 = 0x0004_0000;
    pub const MDMBUF: u32 = 0x0010_0000;
    pub const LITOUT: u32 = 0x0020_0000;
    pub const NOHANG: u32 = 0x0100_0000;
    pub const CRTKIL: u32 = 0x0400_0000;
    pub const PASS8: u32 = 0x0800_0000;
    pub const CTLECH: u32 = 0x1000_0000;
    pub const DECCTQ: u32 = 0x4000_0000;
}

/// `MAX_SPEED`, `compatspcodes`.
const MAX_SPEED: u32 = 17;
const COMPATSPCODES: [u64; 18] = [0, 50, 75, 110, 134, 150, 200, 300, 600, 1200, 1800, 2400, 4800, 9600, 19200, 38400, 57600, 115200];

/// `ttcompatspeedtab(speed, compatspeeds)`: the code of the nearest speed
/// at or under `speed`.
fn ttcompatspeedtab(speed: u64) -> u32 {
    if speed == 0 {
        return 0;
    }
    for code in (1..=MAX_SPEED).rev() {
        if COMPATSPCODES[code as usize] <= speed {
            return code;
        }
    }
    1
}
