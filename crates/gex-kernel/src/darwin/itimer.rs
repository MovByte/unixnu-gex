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
            let bit = if which == 1 { vt::USER } else { vt::PROF };
            if value != 0 {
                self.darwin_vtimer_set(bit);
            } else {
                self.darwin_vtimer_clear(bit);
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
        for (i, bit) in [(0, vt::USER), (1, vt::PROF)] {
            if vtimers[i].value != 0 {
                self.darwin_vtimer_set(bit);
            } else {
                self.darwin_vtimer_clear(bit);
            }
        }
        self.dtask.vtimers = vtimers;
        self.dtask.realtimer = RealTimer { itv: real.itv, rtime: 0, call: None };
        if real.itv.value != 0 {
            self.dtask.realtimer.rtime = microuptime() + real.itv.value;
            self.darwin_realtimer_arm();
        }
    }
}

/// `forkproc`'s `p_rlim_cpu` for a new process (an exec's too): its
/// RLIMIT_CPU in whole seconds (at most INT_MAX), none for no limit.
pub fn fork_rlim_cpu(cur: u64) -> (i64, i32) {
    if cur == super::rlimit::RLIM_INFINITY {
        (0, 0)
    } else {
        (cur.min(i32::MAX as u64) as i64, 0)
    }
}

/// `TASK_VTIMER_*`.
pub mod vt {
    pub const USER: u32 = 0x01;
    pub const PROF: u32 = 0x02;
    pub const RLIM: u32 = 0x04;
}

/// `rtclock_sec_divisor` and `rtclock_usec_divisor`: the 24 MHz timebase.
const SEC_DIVISOR: u64 = 24_000_000;
const USEC_DIVISOR: u64 = 24;

/// `itimerdecr`: `usec` off a timer's value (seconds, microseconds); false
/// when that ends it, its value then its interval's (less the overrun,
/// when the interval has whole seconds) or none.
fn itimerdecr(v: &mut Itimerval, usec: u32) -> bool {
    let (mut sec, mut us) = ((v.value / 1_000_000) as i64, (v.value % 1_000_000) as i64);
    let mut usec = i64::from(usec as i32);
    let mut expire = false;
    if us < usec {
        if sec == 0 {
            // Ended, and already into the next interval.
            usec -= us;
            expire = true;
        } else {
            us += 1_000_000;
            sec -= 1;
        }
    }
    if !expire {
        us -= usec;
        usec = 0;
        if sec != 0 || us != 0 {
            v.value = (sec * 1_000_000 + us) as u64;
            return true;
        }
    }
    if v.interval != 0 {
        let (mut isec, mut ius) = ((v.interval / 1_000_000) as i64, (v.interval % 1_000_000) as i64);
        if isec > 0 {
            ius -= usec;
            if ius < 0 {
                ius += 1_000_000;
                isec -= 1;
            }
        }
        v.value = (isec * 1_000_000 + ius) as u64;
    } else {
        v.value = 0;
    }
    false
}

impl Kernel {
    /// Thread `tid`'s user time and its user and system time, in Mach time
    /// units.
    fn darwin_thread_abs(&self, tid: i32) -> Option<(u64, u64)> {
        let (u, s) = self.thread_signals.get(tid)?.cpu.times()?;
        let (numer, denom) = super::mach::TIMEBASE;
        let abs = |ns: u64| (u128::from(ns) * u128::from(denom) / u128::from(numer)) as u64;
        Some((abs(u), abs(u + s)))
    }

    /// `task_vtimer_set(task, which)`: each thread's time now its save.
    pub(crate) fn darwin_vtimer_set(&mut self, which: u32) {
        self.dtask.vtimer_bits |= which;
        let i = match which {
            vt::USER => 0,
            vt::PROF => 1,
            _ => 2,
        };
        for tid in self.thread_signals.tids() {
            let Some((user, total)) = self.darwin_thread_abs(tid) else {
                self.darwin_unimplemented("a virtual timer on a host without per-thread clocks".into());
                continue;
            };
            self.dtask.threads.map.entry(tid).or_default().vtimer_saves[i] = if which == vt::USER { user } else { total };
        }
    }

    /// `task_vtimer_clear(task, which)`.
    pub(crate) fn darwin_vtimer_clear(&mut self, which: u32) {
        self.dtask.vtimer_bits &= !which;
    }

    /// `task_vtimer_update(task, which, &microsecs)` on this thread: the
    /// microseconds (whole seconds dropped, as `absolutetime_to_microtime`
    /// gives them apart) of its time since its save, which moves up to now
    /// (for the profiling timer, only when a microsecond has passed).
    fn darwin_vtimer_update(&mut self, which: u32) -> u32 {
        if self.dtask.vtimer_bits & which != which {
            return 0;
        }
        let tid = self.tid;
        let Some((user, total)) = self.darwin_thread_abs(tid) else { return 0 };
        let i = match which {
            vt::USER => 0,
            vt::PROF => 1,
            _ => 2,
        };
        let tsum = if which == vt::USER { user } else { total };
        let t = self.dtask.threads.map.entry(tid).or_default();
        let tdelt = u64::from(tsum.wrapping_sub(t.vtimer_saves[i]) as u32);
        let usec = ((tdelt - tdelt / SEC_DIVISOR * SEC_DIVISOR) / USEC_DIVISOR) as u32;
        if which != vt::PROF || usec != 0 {
            t.vtimer_saves[i] = tsum;
        }
        usec
    }

    /// `bsd_ast`'s timers, as this thread returns to its program while the
    /// task has any (`task_vtimer_check`): the virtual and profiling timers
    /// counted down by its time since they last were (SIGVTALRM, SIGPROF
    /// to it when one ends), and what is left under RLIMIT_CPU (SIGXCPU).
    pub(crate) fn darwin_vtimer_ast(&mut self) {
        if self.dtask.vtimer_bits == 0 {
            return;
        }
        use super::signal::dsig;
        for (i, which, d) in [(0usize, vt::USER, dsig::SIGVTALRM), (1, vt::PROF, dsig::SIGPROF)] {
            if self.dtask.vtimers[i].value == 0 {
                continue;
            }
            let usec = self.darwin_vtimer_update(which);
            let mut v = self.dtask.vtimers[i];
            let running = itimerdecr(&mut v, usec);
            self.dtask.vtimers[i] = v;
            if !running {
                if v.value != 0 {
                    self.darwin_vtimer_set(which);
                } else {
                    self.darwin_vtimer_clear(which);
                }
                self.darwin_psignal_try_thread(d, None);
            }
        }
        let (sec, usec) = self.dtask.rlim_cpu;
        if sec != 0 || usec != 0 {
            let used = self.darwin_vtimer_update(vt::RLIM) as i32;
            if sec > 0 || usec > used {
                let mut left = (sec, usec - used);
                if left.1 < 0 {
                    left.1 += 1_000_000;
                    left.0 -= 1;
                }
                self.dtask.rlim_cpu = left;
            } else {
                self.dtask.rlim_cpu = (0, 0);
                self.darwin_vtimer_clear(vt::RLIM);
                self.darwin_psignal_try_thread(dsig::SIGXCPU, None);
            }
        }
    }

    /// `dosetrlimit`'s RLIMIT_CPU: none for an infinite limit; else the
    /// limit's seconds less the task's time so far, its timer started, or
    /// SIGXCPU now when none is left.
    pub(crate) fn darwin_rlimit_cpu(&mut self, cur: u64) -> Result<(), Errno> {
        if cur == super::rlimit::RLIM_INFINITY {
            self.darwin_vtimer_clear(vt::RLIM);
            self.dtask.rlim_cpu = (0, 0);
            return Ok(());
        }
        let Some((user, sys)) = self.task_times() else {
            self.darwin_unimplemented("setrlimit(RLIMIT_CPU) on a host without per-thread clocks".into());
            return Err(Errno::EINVAL);
        };
        // task_absolutetime_info, as microseconds.
        let (numer, denom) = super::mach::TIMEBASE;
        let abs = (u128::from(user + sys) * u128::from(denom) / u128::from(numer)) as u64;
        let (tsec, tusec) = ((abs / SEC_DIVISOR) as i64, ((abs % SEC_DIVISOR) / USEC_DIVISOR) as i32);
        let lsec = cur.min(i32::MAX as u64) as i64;
        let mut left = (lsec - tsec, -tusec);
        if left.1 < 0 {
            left.1 += 1_000_000;
            left.0 -= 1;
        }
        if left.0 > 0 || (left.0 == 0 && left.1 > 0) {
            self.dtask.rlim_cpu = left;
            self.darwin_vtimer_set(vt::RLIM);
        } else {
            self.darwin_vtimer_clear(vt::RLIM);
            self.dtask.rlim_cpu = (0, 0);
            let note = self.darwin_signal_reason(super::signal::dsig::SIGXCPU);
            self.signals.process().raise_noted(super::kern::signal_to_linux(super::signal::dsig::SIGXCPU), None, Some(note));
        }
        Ok(())
    }
}
