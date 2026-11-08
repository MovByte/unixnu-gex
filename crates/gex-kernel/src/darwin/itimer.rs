//! Interval timers (`bsd/kern/kern_time.c`): `getitimer`, `setitimer` and
//! the real timer's thread call (`realitexpire`), which posts SIGALRM and
//! re-arms itself by its interval. Times are timevals: microseconds of
//! uptime (`microuptime`).
//!
//! The virtual and profiling timers count down the task's user time, and
//! its user and system time, as `bsd_ast` charges them; this kernel does
//! not divide a thread's time so, and arming one fails loudly.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::errno::Errno;
use crate::syscalls::Kernel;
use crate::GuestMem;

const ITIMER_REAL: u32 = 0;
const ITIMER_PROF: u32 = 2;

/// A `struct timeval`, in microseconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Itimerval {
    pub interval: u64,
    pub value: u64,
}

/// The process's real timer: `p_realtimer`, `p_rtime` (its deadline, 0 for
/// none) and its thread call (`p_rcall`).
#[derive(Clone, Copy, Debug, Default)]
pub struct RealTimer {
    pub itv: Itimerval,
    pub rtime: u64,
    pub call: Option<(Instant, u64)>,
}

/// `microuptime`, from the first time it is asked.
fn microuptime() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_micros() as u64
}

/// The instant a microsecond of uptime falls at.
fn uptime_instant(us: u64) -> Instant {
    let now = microuptime();
    Instant::now() + Duration::from_micros(us.saturating_sub(now))
}

/// `itimerfix`: a second count of 0 to 100000000 and microseconds under a
/// second.
fn itimerfix(sec: i64, usec: i32) -> Result<u64, Errno> {
    if !(0..=100_000_000).contains(&sec) || !(0..1_000_000).contains(&usec) {
        return Err(Errno::EINVAL);
    }
    Ok(sec as u64 * 1_000_000 + usec as u64)
}

/// A `struct user64_itimerval` (two timevals of a 64-bit second count and
/// a 32-bit microsecond count, 16 bytes each).
fn write_itimerval(m: &mut GuestMem<'_>, at: u64, v: Itimerval) -> Result<(), Errno> {
    let mut b = [0u8; 32];
    for (i, us) in [v.interval, v.value].into_iter().enumerate() {
        b[16 * i..16 * i + 8].copy_from_slice(&((us / 1_000_000) as i64).to_le_bytes());
        b[16 * i + 8..16 * i + 12].copy_from_slice(&((us % 1_000_000) as i32).to_le_bytes());
    }
    m.write(at, &b)
}

impl Kernel {
    /// `getitimer(which, itv)`.
    pub(crate) fn darwin_getitimer(&mut self, m: &mut GuestMem<'_>, which: u32, itv: u64) -> Result<u64, Errno> {
        if which > ITIMER_PROF {
            return Err(Errno::EINVAL);
        }
        let v = self.darwin_itimer_now(which);
        write_itimerval(m, itv, v)?;
        Ok(0)
    }

    /// What `getitimer` reports: the real timer's interval and the time to
    /// its deadline (none once it has passed); the others as set.
    fn darwin_itimer_now(&mut self, which: u32) -> Itimerval {
        if which != ITIMER_REAL {
            return self.dtask.vtimers[which as usize - 1];
        }
        let rt = self.dtask.realtimer;
        let mut v = rt.itv;
        v.value = 0;
        if rt.rtime != 0 {
            let now = microuptime();
            if rt.rtime >= now {
                v.value = rt.rtime - now;
            }
        }
        v
    }

    /// `setitimer(which, itv, oitv)`: the new value read, the old one
    /// reported, then the new one checked and set.
    pub(crate) fn darwin_setitimer(&mut self, m: &mut GuestMem<'_>, which: u32, itv: u64, oitv: u64) -> Result<u64, Errno> {
        if which > ITIMER_PROF {
            return Err(Errno::EINVAL);
        }
        let raw = if itv != 0 { Some(m.read(itv, 32)?.to_vec()) } else { None };
        if oitv != 0 {
            self.darwin_getitimer(m, which, oitv)?;
        }
        let Some(b) = raw else { return Ok(0) };
        let sec = |o: usize| i64::from_le_bytes(b[o..o + 8].try_into().expect("8 bytes"));
        let usec = |o: usize| i32::from_le_bytes(b[o..o + 4].try_into().expect("4 bytes"));
        let value = itimerfix(sec(16), usec(24));
        let interval = itimerfix(sec(0), usec(8));
        let (Ok(value), Ok(interval)) = (value, interval) else { return Err(Errno::EINVAL) };
        let v = Itimerval { interval, value };
        if which == ITIMER_REAL {
            if let Some(key) = self.dtask.realtimer.call.take() {
                self.dtask.timers.cancel(key);
            }
            self.dtask.realtimer.itv = v;
            if value != 0 {
                self.dtask.realtimer.rtime = microuptime() + value;
                self.darwin_realtimer_arm();
            } else {
                self.dtask.realtimer.rtime = 0;
            }
        } else {
            if value != 0 {
                let name = if which == 1 { "ITIMER_VIRTUAL" } else { "ITIMER_PROF" };
                self.darwin_unimplemented(format!("setitimer({name}), counted in the task's user and system time"));
                return Err(Errno::EINVAL);
            }
            self.dtask.vtimers[which as usize - 1] = v;
        }
        Ok(0)
    }

    /// The real timer's thread call, at its deadline.
    fn darwin_realtimer_arm(&mut self) {
        let at = uptime_instant(self.dtask.realtimer.rtime);
        let key = self.dtask.timers.arm(at, super::timer::Action::RealTimer);
        self.dtask.realtimer.call = Some(key);
    }

    /// `realitexpire`: SIGALRM, then, for an interval, the next deadline
    /// (an interval on from the last, past now; one interval from now if
    /// it fell more than two seconds behind).
    pub(crate) fn darwin_realitexpire(&mut self) {
        self.dtask.realtimer.call = None;
        // psignal from the kernel's thread call: posted as the kernel
        // posts to a process, for whichever thread takes it, the kernel's
        // own process its sender.
        let alrm = super::kern::signal_to_linux(super::signal::dsig::SIGALRM);
        let (pid, name) = super::reason::kernproc();
        let note = std::sync::Arc::new(super::reason::OsReason::signal(super::signal::dsig::SIGALRM, pid, &name, None));
        self.procs.post_kernel_noted(self.pid, alrm, Some(note));
        let rt = &mut self.dtask.realtimer;
        if rt.itv.interval == 0 {
            rt.rtime = 0;
            return;
        }
        let now = microuptime();
        rt.rtime += rt.itv.interval;
        if rt.rtime <= now {
            if rt.rtime / 1_000_000 + 2 >= now / 1_000_000 {
                while rt.rtime <= now {
                    rt.rtime += rt.itv.interval;
                }
            } else {
                rt.rtime = now + rt.itv.interval;
            }
        }
        self.darwin_realtimer_arm();
    }

    /// `proc_inherit_itimers` at an exec: the real timer runs on from now
    /// for what its value was set to, the others as they were.
    pub(crate) fn darwin_inherit_itimers(&mut self, real: RealTimer, vtimers: [Itimerval; 2]) {
        self.dtask.vtimers = vtimers;
        self.dtask.realtimer = RealTimer { itv: real.itv, rtime: 0, call: None };
        if real.itv.value != 0 {
            self.dtask.realtimer.rtime = microuptime() + real.itv.value;
            self.darwin_realtimer_arm();
        }
    }
}
