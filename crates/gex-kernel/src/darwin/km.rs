//! The console: `/dev/console` (cdevsw 0, `bsd/dev/arm/cons.c`), whose
//! calls go to the terminal `TIOCCONS` made the console's (`constty`) or
//! else to the kernel's own console terminal, `km_tty[0]` (cdevsw 12,
//! `bsd/dev/arm/km.c`), whose output is the console's
//! (`console_write`, `osfmk/console/serial_console.c`).
//!
//! The console's output is the host's standard error here, as the
//! device's serial port carries it when the `serial` boot-arg turns its
//! output on. The device itself boots with no boot-args (`serialmode` 0),
//! and with the boot logo up its graphics console sets
//! `disableConsoleOutput` (`gc_pause`), so there nothing shows what the
//! console was given; no call can see the difference.

use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};

use super::ptmx::{makedev, PTC_MAJOR, PTSD_MAJOR};
use super::tty::{self, cflag, cmd, ts, Caller, Env, Io, IoctlState, Oproc, SleepReq, Tty, TtyCell, Woke};
use crate::errno::Errno;

/// The console's major (`cdevsw[0]`, `cnopen` and the rest).
pub const CONSOLE_MAJOR: u32 = 0;
/// km's major: `kminit`'s `makedev(12, 0)`, `cdevsw[12]`.
pub const KM_MAJOR: u32 = 12;

/// `KMIOCSIZE`: `_IOR('k', 11, struct winsize)`.
pub const KMIOCSIZE: u64 = 0x4008_6b0b;

/// `km_tty[0]`, which `kminit` makes at boot with `t_dev` makedev(12, 0).
static KM_TTY: OnceLock<Arc<TtyCell>> = OnceLock::new();

/// `km_tty[0]`.
pub fn km_tty() -> Arc<TtyCell> {
    Arc::clone(KM_TTY.get_or_init(|| {
        let tp = TtyCell::new();
        tp.lock().dev = makedev(KM_MAJOR, 0);
        tp
    }))
}

/// Whether `cell` is `km_tty[0]`.
pub fn is_km(cell: &Arc<TtyCell>) -> bool {
    KM_TTY.get().is_some_and(|k| Arc::ptr_eq(k, cell))
}

/// The driver a console call reaches: its cdevsw entry's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cn {
    /// km's.
    Km,
    /// A pty replica's (`ptsopen` and the rest), the console's terminal by
    /// `TIOCCONS`.
    Pts,
}

/// The device a console call goes to (`cnopen`, `cnclose`, `cnread`,
/// `cnwrite`, `cnioctl`, `cnselect`): `constty->t_dev` while there is a
/// `constty`, else `km_tty[0]->t_dev`; its driver and its terminal.
pub fn cn_dev() -> Result<(Cn, u32, Arc<TtyCell>), String> {
    match tty::copy_constty() {
        None => {
            let k = km_tty();
            let dev = k.lock().dev;
            Ok((Cn::Km, dev, k))
        }
        Some(c) => {
            let dev = c.lock().dev;
            cn_of(&c, dev).map(|cn| (cn, dev, c))
        }
    }
}

/// The driver of terminal `cell` as the console's, its `t_dev` `dev`.
pub fn cn_of(cell: &Arc<TtyCell>, dev: u32) -> Result<Cn, String> {
    if is_km(cell) {
        return Ok(Cn::Km);
    }
    match dev >> 24 {
        // A replica's open set it (ttyopen).
        PTSD_MAJOR | PTC_MAJOR => Ok(Cn::Pts),
        CONSOLE_MAJOR => Err("a console call while the console's terminal is a pty no replica has opened (its t_dev 0 is the console's: cnopen and the rest call themselves until the kernel's stack overflows)".into()),
        m => Err(format!("a console call to the console's terminal of major {m}")),
    }
}

/// Why `kmopen` could not size the window, while it could not.
static SIZE_UNKNOWN: Mutex<Option<String>> = Mutex::new(None);

/// What `KMIOCSIZE` and `TIOCGWINSZ` on km would read that is not known.
pub fn size_unknown() -> Option<String> {
    SIZE_UNKNOWN.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// `kmopen`: unit 0 only; the terminal set up on its first open, opened
/// (`l_open`), its carrier always on, and its window the serial console's
/// or the video console's size in 8x16 cells.
pub fn kmopen(dev: u32, env: &mut dyn Env) -> Result<Arc<TtyCell>, Errno> {
    if dev & 0x00ff_ffff >= 1 {
        return Err(Errno::ENXIO);
    }
    let cell = km_tty();
    let mut tp = cell.lock();
    tp.oproc = Oproc::Kmstart;
    tp.dev = dev;
    if tp.state & ts::ISOPEN == 0 {
        tp.termios.iflag = tty::TTYDEF_IFLAG;
        tp.termios.oflag = tty::TTYDEF_OFLAG;
        tp.termios.cflag = cflag::CREAD | cflag::CS8 | cflag::CLOCAL;
        tp.termios.lflag = tty::TTYDEF_LFLAG;
        tp.termios.ispeed = tty::TTYDEF_SPEED;
        tp.termios.ospeed = tty::TTYDEF_SPEED;
        tp.termios.cc = tty::TTYDEFCHARS;
        tp.ttsetwater();
    } else if tp.state & ts::XCLUDE != 0 && !env.suser_acflag() {
        // proc_suser: EBUSY for all but the superuser.
        return Err(Errno::EBUSY);
    }
    tp.state |= ts::CARR_ON;
    // l_open: both termios disciplines' ttyopen.
    tp.ttyopen(dev);
    // CHARWIDTH and CHARHEIGHT.
    tp.winsize.xpixel = 8;
    tp.winsize.ypixel = 16;
    let mut unknown = None;
    if super::pe::serialmode() & super::pe::SERIALMODE_OUTPUT != 0 {
        tp.winsize.col = 80;
        tp.winsize.row = 24;
    } else {
        match super::pe::current_console() {
            Ok((w, h)) if w != 0 && h != 0 => {
                tp.winsize.col = (w / 8) as u16;
                tp.winsize.row = (h / 16) as u16;
            }
            Ok(_) => {
                tp.winsize.col = 100;
                tp.winsize.row = 36;
            }
            Err(why) => unknown = Some(why),
        }
    }
    *SIZE_UNKNOWN.lock().unwrap_or_else(|e| e.into_inner()) = unknown;
    drop(tp);
    Ok(cell)
}

/// `kmclose`: `l_close` (`ttylclose`, which may drain), then `ttyclose`.
pub fn kmclose(cell: &Arc<TtyCell>, flag: i32, env: &mut dyn Env, resumed: Option<(SleepReq, Woke)>) -> Io<i32> {
    let mut tp = cell.lock();
    let ret = match tp.ttylclose(flag, env, resumed) {
        Io::Sleep(r) => return Io::Sleep(r),
        Io::Done(e) => e,
    };
    tp.ttyclose(env, cell);
    Io::Done(ret)
}

/// `kmioctl`: the window's size for `KMIOCSIZE`, a size that cannot be
/// set, CLOCAL forced into a new termios; the rest `l_ioctl`'s (none for
/// termios: ENOTTY), then `ttioctl_locked`'s.
#[allow(clippy::too_many_arguments)]
pub fn kmioctl(cell: &Arc<TtyCell>, tp: &mut Tty, com: u64, data: &mut [u8], flag: i32, p: &Caller, env: &mut dyn Env, st: &mut IoctlState, resumed: Option<(SleepReq, Woke)>) -> Io<Result<(), Errno>> {
    if resumed.is_none() {
        match com {
            KMIOCSIZE => {
                tp.winsize.to_bytes(data);
                return Io::Done(Ok(()));
            }
            // So that login keeps the console's size.
            cmd::TIOCSWINSZ => return Io::Done(Err(Errno::EINVAL)),
            // The km device is always local.
            cmd::TIOCSETA_32 | cmd::TIOCSETAW_32 | cmd::TIOCSETAF_32 => {
                let c = u32::from_le_bytes(data[8..12].try_into().unwrap()) | cflag::CLOCAL as u32;
                data[8..12].copy_from_slice(&c.to_le_bytes());
            }
            cmd::TIOCSETA_64 | cmd::TIOCSETAW_64 | cmd::TIOCSETAF_64 => {
                let c = u64::from_le_bytes(data[16..24].try_into().unwrap()) | cflag::CLOCAL;
                data[16..24].copy_from_slice(&c.to_le_bytes());
            }
            _ => {}
        }
    }
    tp.ttioctl_locked(cell, com, data, flag, p, env, st, resumed)
}

/// `kmstart` (`t_oproc`): nothing to send while the output waits or is
/// stopped, or is empty (then `l_start`, `ttwwakeup`); else all of it out
/// now (`kmoutput`: the low-water timeout is compiled out).
pub fn kmstart(tp: &mut Tty) {
    if tp.state & (ts::TIMEOUT | ts::BUSY | ts::TTSTOP) != 0 || tp.outq.is_empty() {
        tp.ttwwakeup();
        return;
    }
    tp.state |= ts::BUSY;
    kmoutput(tp);
}

/// `kmoutput`: the output queue to the console up to 80 bytes at a time,
/// seven bits each; then `l_start`.
fn kmoutput(tp: &mut Tty) {
    let mut buf = [0u8; 80];
    while !tp.outq.is_empty() {
        let cc = tp.outq.ndqb(0);
        if cc == 0 {
            break;
        }
        let cc = cc.min(buf.len());
        tp.outq.q_to_b(&mut buf[..cc]);
        for b in &mut buf[..cc] {
            *b &= 0x7f;
        }
        if cc > 1 {
            console_write(&buf[..cc]);
        } else {
            kmputc(buf[0]);
        }
    }
    // ndqb(q, 0) is the queue's first run, so nothing is left for
    // kmtimeout.
    tp.state &= !ts::BUSY;
    tp.ttwwakeup();
}

/// `kmputc`: a newline after a return (OCRNL), each a `console_write_char`.
fn kmputc(c: u8) {
    if c == b'\n' {
        console_write(b"\r");
    }
    console_write(&[c]);
}

/// `console_write`: the bytes to the console, which sends each newline
/// after a return (`_cnputc`).
pub fn console_write(s: &[u8]) {
    let mut out = Vec::with_capacity(s.len() + s.len() / 8);
    for &c in s {
        if c == b'\n' {
            out.push(b'\r');
        }
        out.push(c);
    }
    let mut e = std::io::stderr().lock();
    let _ = e.write_all(&out);
    let _ = e.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoEnv;
    impl Env for NoEnv {
        fn pgsignal(&mut self, _: super::super::ctty::Pgrp, _: u32, _: bool) {}
        fn psignal(&mut self, _: i32, _: u32) {}
        fn pgrp_find(&mut self, _: i32) -> Option<(super::super::ctty::Pgrp, Arc<super::super::ctty::Session>)> {
            None
        }
        fn loadavg(&mut self) -> Option<u32> {
            None
        }
        fn fg_pick(&mut self, _: super::super::ctty::Pgrp) -> Option<i32> {
            None
        }
        fn fg_info(&mut self, _: i32) -> Option<Result<tty::FgInfo, ()>> {
            None
        }
        fn set_controlt(&mut self) {}
        fn session_leader(&mut self, _: &Arc<super::super::ctty::Session>) -> Option<i32> {
            None
        }
        fn namei(&mut self, _: &str) -> Result<(), Errno> {
            Err(Errno::ENOENT)
        }
        fn suser_acflag(&mut self) -> bool {
            false
        }
    }

    #[test]
    fn kmopen_sets_the_console_terminal_up() {
        assert_eq!(kmopen(makedev(KM_MAJOR, 1), &mut NoEnv).err(), Some(Errno::ENXIO));
        let cell = kmopen(makedev(KM_MAJOR, 0), &mut NoEnv).unwrap();
        assert!(is_km(&cell));
        let tp = cell.lock();
        assert_eq!(tp.oproc, Oproc::Kmstart);
        assert_eq!(tp.termios.cflag, cflag::CREAD | cflag::CS8 | cflag::CLOCAL);
        assert_ne!(tp.state & (ts::ISOPEN | ts::CARR_ON | ts::CONNECTED), 0);
        assert_eq!((tp.winsize.xpixel, tp.winsize.ypixel), (8, 16));
        drop(tp);
        // The video console's size is not known: it is reported where it
        // is read.
        assert!(size_unknown().is_some());
    }

    #[test]
    fn kmstart_waits_while_the_output_is_stopped() {
        let cell = km_tty();
        let mut tp = cell.lock();
        let state = tp.state;
        tp.state |= ts::TTSTOP;
        tp.outq.b_to_q(b"stopped");
        kmstart(&mut tp);
        assert_eq!(tp.outq.len(), 7);
        assert_eq!(tp.state & ts::BUSY, 0);
        let mut drop_out = [0u8; 7];
        tp.outq.q_to_b(&mut drop_out);
        tp.state = state;
    }
}
