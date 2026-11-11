//! The scheduler's averages (`osfmk/kern/sched_average.c`,
//! `sched_timeshare_maintenance_continue` in `sched_prim.c`, and
//! `compute_averunnable` in `bsd/kern/kern_synch.c`): how many threads are
//! runnable, sampled about every scheduler tick, and the load averages and
//! Mach factors made from that.
//!
//! `sched_run_buckets[TH_BUCKET_RUN]` counts the threads in `TH_RUN`: here,
//! every Darwin thread that is on its CPU (not waiting in a call, not
//! parked by a hold, not created suspended and still unstarted), the
//! kernel's thread calls while they run, and the maintenance thread itself
//! while it computes. Thread ids are unique across the system, so each
//! thread's state is kept by its id, with its process for that process's
//! end, where any process can read it (`thread_info`'s run state).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use super::mach::absolute_time;
use super::mig::machine::NCPUS;

/// `SCHED_TICK_SHIFT`: eight ticks a second.
const SCHED_TICK_SHIFT: u32 = 3;
/// `SCHED_TICK_MAX_DELTA`: the most ticks one maintenance pass catches up.
const SCHED_TICK_MAX_DELTA: u64 = 8;
/// `sched_one_second_interval` and `sched_tick_interval`
/// (`USEC_PER_SEC >> SCHED_TICK_SHIFT`), in Mach time units (24 MHz).
const ONE_SECOND: u64 = 24_000_000;
const TICK_INTERVAL: u64 = ONE_SECOND >> SCHED_TICK_SHIFT;
/// `LOAD_SCALE` (`mach/processor_info.h`).
const LOAD_SCALE: u32 = 1000;
/// `FSHIFT` and `FSCALE` (`sys/param.h`).
pub const FSHIFT: u32 = 11;
pub const FSCALE: u32 = 1 << FSHIFT;

/// `fract`: `((base(n) - 1) * LOAD_SCALE) / base(n)` with
/// `base(n) = n << SCHED_TICK_SHIFT`, for the 5 second, 30 second and
/// 1 minute averages.
const FRACT: [u32; 3] = [frac(5), frac(30), frac(60)];

const fn frac(n: u32) -> u32 {
    let base = n << SCHED_TICK_SHIFT;
    ((base - 1) * LOAD_SCALE) / base
}

/// `cexp`: exp(-1/12), exp(-1/60) and exp(-1/180) as `fixpt_t`, for the
/// 1, 5 and 15 minute averages sampled every 5 seconds
/// (`(fixpt_t)(x * FSCALE)`, truncated).
const CEXP: [u32; 3] = [1884, 2014, 2036];

/// `sched_average[]`'s `compute_averunnable` entry: its period in seconds.
const AVERUNNABLE_PERIOD: u64 = 5;

/// A thread's scheduling state, as `retrieve_thread_basic_info` reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunState {
    /// `TH_RUN`.
    Run,
    /// `TH_WAIT`, interruptibly.
    Wait,
    /// `TH_WAIT | TH_UNINT`: a wait at `THREAD_UNINT`, or a thread made
    /// and not yet started.
    Unint,
}

impl RunState {
    /// `TH_STATE_RUNNING`, `TH_STATE_WAITING`, `TH_STATE_UNINTERRUPTIBLE`.
    pub fn th_state(self) -> i32 {
        match self {
            RunState::Run => 1,
            RunState::Wait => 3,
            RunState::Unint => 4,
        }
    }
}

/// The averages and what they are made from.
#[derive(Debug, Default)]
struct State {
    /// Every Darwin thread's state, by id, with its process.
    threads: HashMap<i32, (i32, RunState)>,
    /// The processes that have ended (ids are not given out again here): a
    /// thread of one let out of a wait as it is torn down is not counted.
    ended: std::collections::HashSet<i32>,
    /// The kernel's thread calls running now.
    callouts: u32,
    /// `sched_tick_last_abstime`, `sched_tick`.
    tick_last: u64,
    tick: u64,
    /// `sched_nrun`, `sched_load_average`, `sched_mach_factor`.
    nrun: u32,
    load_average: u32,
    mach_factor_now: u32,
    /// `avenrun[3]`, `mach_factor[3]`.
    avenrun: [u32; 3],
    mach_factor: [u32; 3],
    /// `averunnable.ldavg`.
    ldavg: [u32; 3],
    /// `compute_averunnable`'s deadline in `sched_average[]`.
    averunnable_deadline: u64,
}

/// The scheduler's averages for the whole system.
#[derive(Debug, Default)]
pub struct Sched {
    state: Mutex<State>,
    /// Whether a host thread runs the maintenance here.
    driven: AtomicBool,
}

impl Sched {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Thread `tid` of process `pid` is now in `state` (into `TH_RUN` or
    /// out of it: `sched_run_incr`, `sched_run_decr`).
    pub fn set_state(&self, pid: i32, tid: i32, state: RunState) {
        let mut s = self.lock();
        if !s.ended.contains(&pid) {
            s.threads.insert(tid, (pid, state));
        }
    }

    /// Thread `tid`'s state, if the scheduler has it.
    pub fn state(&self, tid: i32) -> Option<RunState> {
        self.lock().threads.get(&tid).map(|t| t.1)
    }

    /// Thread `tid` has ended.
    pub fn thread_gone(&self, tid: i32) {
        self.lock().threads.remove(&tid);
    }

    /// Process `pid` has ended, every thread of it with it.
    pub fn task_gone(&self, pid: i32) {
        let mut s = self.lock();
        s.threads.retain(|_, t| t.0 != pid);
        s.ended.insert(pid);
    }

    /// One of the kernel's thread calls starts (`run`) or finishes running.
    pub fn callout(&self, run: bool) {
        let mut s = self.lock();
        if run {
            s.callouts += 1;
        } else {
            s.callouts = s.callouts.saturating_sub(1);
        }
    }

    /// Claim the running of the maintenance: true for the one caller that
    /// is to run [`Sched::maintenance_thread`].
    pub fn claim_driver(&self) -> bool {
        !self.driven.swap(true, Ordering::AcqRel)
    }

    /// The maintenance thread's loop (`sched_timeshare_maintenance_continue`):
    /// woken once a tick has passed since it last ran
    /// (`sched_timeshare_consider_maintenance`, which every context switch
    /// and quantum expiry asks; the next deadline is a tick on from when it
    /// is woken), then the averages are brought up to date.
    pub fn maintenance_thread(&self) -> ! {
        let mut deadline = 0u64;
        loop {
            let now = absolute_time();
            if now >= deadline {
                deadline = now + TICK_INTERVAL;
                self.maintenance();
            }
            let left = deadline.saturating_sub(absolute_time());
            // Mach time units are 1/24 µs.
            std::thread::sleep(std::time::Duration::from_nanos(left * 125 / 3));
        }
    }

    /// One pass of `sched_timeshare_maintenance_continue`: the ticks since
    /// the last (at least one, at most `SCHED_TICK_MAX_DELTA`), and the
    /// averages over them.
    pub fn maintenance(&self) {
        let mut s = self.lock();
        let ctime = absolute_time();
        let delta = if s.tick_last == 0 {
            s.tick_last = ctime;
            1
        } else {
            let late = ctime - s.tick_last;
            s.tick_last = ctime;
            (late / TICK_INTERVAL).clamp(1, SCHED_TICK_MAX_DELTA)
        };
        s.tick += delta;
        // The maintenance thread is running as it counts.
        let running = s.threads.values().filter(|t| t.1 == RunState::Run).count() as u32;
        let run_bucket = running + s.callouts + 1;
        compute_averages(&mut s, run_bucket, delta);
    }

    /// `averunnable.ldavg`, or what keeps it from being kept here.
    pub fn averunnable(&self) -> Result<[u32; 3], &'static str> {
        self.check()?;
        Ok(self.lock().ldavg)
    }

    /// `avenrun` and `mach_factor` (`HOST_LOAD_INFO`), or what keeps them
    /// from being kept here.
    pub fn host_load(&self) -> Result<([u32; 3], [u32; 3]), &'static str> {
        self.check()?;
        let s = self.lock();
        Ok((s.avenrun, s.mach_factor))
    }

    fn check(&self) -> Result<(), &'static str> {
        if !self.driven.load(Ordering::Acquire) {
            return Err("the scheduler's averages: no maintenance thread runs here (sched_timeshare_maintenance_continue)");
        }
        Ok(())
    }
}

/// `compute_averages(stdelta)` with `sched_run_buckets[TH_BUCKET_RUN]` at
/// `run_bucket`, then `compute_averunnable` as `sched_average[]` has it
/// run. (The timeshare priority shifts it also sets, and its other entries'
/// VM and zone bookkeeping, are not kept here.)
fn compute_averages(s: &mut State, run_bucket: u32, stdelta: u64) {
    let nthreads = run_bucket.wrapping_sub(1);
    let ncpus = NCPUS;
    s.nrun = nthreads;
    let average_now = nthreads.wrapping_mul(LOAD_SCALE);
    let factor_now = if nthreads > ncpus { (ncpus * LOAD_SCALE) / (nthreads + 1) } else { (ncpus - nthreads) * LOAD_SCALE };
    for _ in 0..stdelta {
        s.mach_factor_now = ((s.mach_factor_now << 2).wrapping_add(factor_now)) / 5;
        s.load_average = ((s.load_average << 2).wrapping_add(average_now)) / 5;
    }
    for _ in 0..stdelta {
        for i in 0..3 {
            s.mach_factor[i] = (s.mach_factor[i].wrapping_mul(FRACT[i]).wrapping_add(factor_now.wrapping_mul(LOAD_SCALE - FRACT[i]))) / LOAD_SCALE;
            s.avenrun[i] = (s.avenrun[i].wrapping_mul(FRACT[i]).wrapping_add(average_now.wrapping_mul(LOAD_SCALE - FRACT[i]))) / LOAD_SCALE;
        }
    }
    let abstime = absolute_time();
    if abstime >= s.averunnable_deadline {
        let period = AVERUNNABLE_PERIOD * ONE_SECOND;
        let ninvokes = (1 + (abstime - s.averunnable_deadline) / period).min(SCHED_TICK_MAX_DELTA);
        for _ in 0..ninvokes {
            compute_averunnable(&mut s.ldavg, s.nrun);
        }
        s.averunnable_deadline = abstime + period;
    }
}

/// `compute_averunnable`, in `fixpt_t`'s 32-bit arithmetic.
fn compute_averunnable(ldavg: &mut [u32; 3], nrun: u32) {
    for i in 0..3 {
        ldavg[i] = (CEXP[i].wrapping_mul(ldavg[i]).wrapping_add(nrun.wrapping_mul(FSCALE).wrapping_mul(FSCALE - CEXP[i]))) >> FSHIFT;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants() {
        assert_eq!(FRACT, [975, 995, 997]);
        let exact = [(-1.0f64 / 12.0).exp(), (-1.0f64 / 60.0).exp(), (-1.0f64 / 180.0).exp()];
        for i in 0..3 {
            assert_eq!(CEXP[i], (exact[i] * f64::from(FSCALE)) as u32);
        }
        assert_eq!(TICK_INTERVAL, 3_000_000);
    }

    #[test]
    fn averunnable_steps() {
        // Two runnable threads from rest: the first step is
        // 2 * 2048 * (2048 - 1884) >> 11.
        let mut l = [0u32; 3];
        compute_averunnable(&mut l, 2);
        assert_eq!(l, [328, 68, 24]);
        compute_averunnable(&mut l, 2);
        assert_eq!(l[0], (1884 * 328 + 2 * 2048 * 164) >> 11);
    }

    #[test]
    fn ended_tasks() {
        let s = Sched::default();
        s.set_state(7, 8, RunState::Run);
        s.task_gone(7);
        // A thread of it woken as it is torn down.
        s.set_state(7, 9, RunState::Run);
        assert_eq!(s.state(8), None);
        assert_eq!(s.state(9), None);
    }

    #[test]
    fn averages() {
        let mut s = State::default();
        // Four runnable and the maintenance thread: three is the CPUs'
        // count, so the factor is 3 * 1000 / 5.
        compute_averages(&mut s, 5, 1);
        assert_eq!(s.nrun, 4);
        assert_eq!(s.load_average, 4000 / 5);
        assert_eq!(s.mach_factor_now, 600 / 5);
        assert_eq!(s.avenrun[0], 4000 * 25 / 1000);
        assert_eq!(s.mach_factor[2], 600 * 3 / 1000);
        // Idle: one CPU's worth of factor for each idle CPU.
        let mut s = State::default();
        compute_averages(&mut s, 1, 2);
        assert_eq!(s.nrun, 0);
        assert_eq!(s.mach_factor_now, ((3000 / 5) * 4 + 3000) / 5);
    }
}
