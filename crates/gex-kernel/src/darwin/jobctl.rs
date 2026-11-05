//! Job control in a Darwin process (`bsd/kern/kern_sig.c`): what posting a
//! signal does to a stopped or running process (`psignal_internal`), the
//! stop taken on the way back to user space (`issignal`), and the hold that
//! keeps a stopped task's threads from running (`task_suspend_internal`,
//! `thread_apc_ast`).
//!
//! A stop is the task's: every thread is held at its next return to user
//! space (the end of a call, a safepoint) until the task is resumed. A
//! thread asleep in a call stays asleep; it is held when the call ends. An
//! abort (`thread_abort`, for SIGKILL or a default kill) lets one held
//! thread take what is pending, which ends the process.

use std::sync::{Arc, Mutex};

use super::kern::signal_to_linux;
use super::signal::{dsig, prop, sigmask, signal_from_linux, SIGPROP};
use crate::proc::Job;
use crate::signal::{SIG_DFL, SIG_IGN};
use crate::syscalls::Kernel;

/// `stopsigmask`.
const STOPSIGMASK: u32 = sigmask(dsig::SIGSTOP) | sigmask(dsig::SIGTSTP) | sigmask(dsig::SIGTTIN) | sigmask(dsig::SIGTTOU);

/// `TASK_HOLD_*`: what kind of hold a suspension places or releases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HoldMode {
    /// A kernel suspension (a stop, task_suspend2).
    Normal,
    /// task_suspend's, counted apart (`legacy_stop_count`).
    Legacy,
    /// Every legacy hold left (the resume port's no-senders).
    LegacyAll,
}

/// What a thread on its way back to user space does next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hold {
    /// Not held: it runs.
    Run,
    /// Held: it waits for the task to be resumed.
    Park,
    /// Held but aborted: it takes its signals (`bsd_ast` before
    /// `thread_apc_ast`), then asks again.
    Deliver,
    /// Not held, its registers set while it was in the kernel: it goes on
    /// at this pc.
    Resume(u64),
}

/// A Darwin signal set as Linux's.
fn linux_bits(mask: u32) -> u64 {
    let mut out = 0u64;
    let mut m = mask;
    while m != 0 {
        let d = m.trailing_zeros() + 1;
        m &= m - 1;
        let l = signal_to_linux(d);
        if l != 0 {
            out |= 1u64 << (l - 1);
        }
    }
    out
}

impl Kernel {
    /// This process's job state: its cell in the process table.
    pub(crate) fn darwin_job(&mut self) -> Arc<Mutex<Job>> {
        if let Some(j) = &self.dtask.job {
            return Arc::clone(j);
        }
        let j = self.procs.job(self.pid).unwrap_or_default();
        self.dtask.job = Some(Arc::clone(&j));
        j
    }

    fn darwin_job_with<R>(&mut self, f: impl FnOnce(&mut Job) -> R) -> R {
        let j = self.darwin_job();
        let mut g = j.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut g)
    }

    /// psignal_internal's work for signal `l` (Linux's number), just made
    /// pending on thread `tid`: an ignored signal is forgotten; a continue
    /// clears the stops pending there and resumes a stopped process; a stop
    /// clears the continue pending there, is discarded at its default
    /// action as a terminal stop in an orphaned group, and otherwise at its
    /// default action stops the process unless the thread holds it; a kill
    /// at its default action makes a stopped process runnable and aborts
    /// the thread so it can take it. `thread` is a thread-directed post
    /// (PSIG_THREAD).
    pub(crate) fn darwin_psignal(&mut self, tid: i32, l: u32, thread: bool) {
        let Some(d) = signal_from_linux(l) else { return };
        let Some(ts) = self.thread_signals.get(tid) else { return };
        let p = SIGPROP[d as usize];
        let lbit = 1u64 << (l - 1);
        let ps = &self.dtask.sigacts;
        // p_sigignore never holds SIGCONT: one set to SIG_IGN acts at its
        // default.
        if ps.sigignore & sigmask(d) != 0 {
            ts.discard_mask(lbit);
            return;
        }
        let handler = ps.handler[d as usize];
        let held = ts.blocked() & lbit != 0;
        let default = !held && (handler == SIG_DFL || handler == SIG_IGN);
        if p & prop::CONT != 0 {
            ts.discard_mask(linux_bits(STOPSIGMASK));
        }
        if p & prop::STOP != 0 {
            if p & prop::TTYSTOP != 0 && default && self.procs.orphaned(self.pid) {
                ts.discard_mask(lbit);
                return;
            }
            ts.discard_mask(linux_bits(sigmask(dsig::SIGCONT)));
        }
        let stopped = self.darwin_job_with(|j| j.stopped);
        if held && (p & prop::CONT == 0 || !stopped) {
            return;
        }
        if !default {
            // Caught, or a held continue of a stopped process: a continue
            // resumes it; anything else waits for it to be continued.
            if p & prop::CONT != 0 {
                self.darwin_job_with(|j| {
                    j.continued = true;
                    j.stopped = false;
                });
                self.darwin_task_resume();
            }
            return;
        }
        if STOPSIGMASK & sigmask(d) != 0 {
            ts.discard_mask(lbit);
            if !stopped {
                self.darwin_stop(d, true);
            }
            return;
        }
        match d {
            dsig::SIGKILL => {
                self.darwin_job_with(|j| j.stopped = false);
                self.darwin_thread_abort(tid);
            }
            dsig::SIGCONT => {
                let pid = self.pid;
                self.darwin_job_with(|j| {
                    j.continued = true;
                    j.contproc = pid;
                    j.xstat = dsig::SIGCONT;
                });
                self.darwin_task_resume();
                ts.discard_mask(lbit);
                self.darwin_job_with(|j| j.stopped = false);
            }
            // A default kill acts like SIGKILL (a thread-directed one to a
            // stopped process waits, as before PSIG_THREAD exit reasons).
            _ if p & prop::KILL != 0 && !(thread && stopped) => {
                self.darwin_job_with(|j| j.stopped = false);
                self.darwin_thread_abort(tid);
            }
            _ => {}
        }
    }

    /// The process stops for Darwin signal `d`: `p_xstat`, SSTOP, the wait
    /// record cleared, then `stop()` (P_CONTINUED cleared, the parent woken,
    /// the task held), and the parent's SIGCHLD with its CLD_STOPPED record
    /// unless it set SA_NOCLDSTOP. psignal records SIGSTOP's status as
    /// `W_EXITCODE(signum, signum)` and any other's, as issignal records
    /// every one, as `WEXITSTATUS(p_xstat)`.
    pub(crate) fn darwin_stop(&mut self, d: u32, posted: bool) {
        self.darwin_job_with(|j| {
            j.xstat = d;
            j.stopped = true;
            j.continued = false;
            j.waited = false;
            j.holds += 1;
        });
        self.procs.job_changed(self.pid);
        let status = if posted && d == dsig::SIGSTOP { (d << 8) | d } else { (d >> 8) & 0xff };
        self.procs.stopped_to_parent(self.pid, status as i32, self.creds.uid());
    }

    /// `task_resume_internal`: one hold fewer (none to release is no
    /// error), and the held threads let go at none.
    fn darwin_task_resume(&mut self) {
        let _ = self.darwin_release_task_hold(HoldMode::Normal);
    }

    /// `place_task_hold`: one more user stop (a legacy one counted too);
    /// whether the task was running (and its threads must now be waited
    /// for, task_wait_locked).
    pub(crate) fn darwin_place_task_hold(&mut self, mode: HoldMode) -> bool {
        self.darwin_job_with(|j| {
            if mode == HoldMode::Legacy {
                j.legacy += 1;
            }
            j.holds += 1;
            j.holds == 1
        })
    }

    /// `release_task_hold`: KERN_FAILURE (`false`) with no hold to
    /// release; a legacy release takes a legacy hold, and LegacyAll takes
    /// all of them.
    pub(crate) fn darwin_release_task_hold(&mut self, mode: HoldMode) -> bool {
        let ok = self.darwin_job_with(|j| {
            if j.holds == 0 {
                return false;
            }
            if mode == HoldMode::LegacyAll {
                if j.legacy >= j.holds {
                    j.holds = 0;
                } else {
                    j.holds -= j.legacy;
                }
                j.legacy = 0;
            } else {
                if mode == HoldMode::Legacy && j.legacy > 0 {
                    j.legacy -= 1;
                }
                j.holds -= 1;
            }
            true
        });
        // Held threads wait on the host's readiness wake.
        self.fd_activity = true;
        ok
    }

    /// `thread_abort`: a held thread is let go to take its signals.
    fn darwin_thread_abort(&mut self, tid: i32) {
        self.dtask.threads.map.entry(tid).or_default().job_abort = true;
        self.fd_activity = true;
    }

    /// Whether thread `tid`, on its way back to user space, is held (its
    /// task stopped, or itself suspended), with the signals posted since
    /// it last asked acted on first.
    pub fn darwin_hold(&mut self, m: &mut crate::GuestMem<'_>, tid: i32) -> Hold {
        if !self.darwin || self.procs.halt_code().is_some() {
            return Hold::Run;
        }
        self.collect_signals();
        self.darwin_assign_signals();
        // thread_hold: the task's, or the thread's own (thread_suspend).
        let thread_held = self.dtask.threads.map.get(&tid).is_some_and(|t| t.suspend > 0 || t.stop_holds > 0);
        if self.darwin_job_with(|j| j.holds) == 0 && !thread_held {
            self.darwin_set_offcpu(m, tid, false);
            let me = self.dtask.threads.map.entry(tid).or_default();
            if std::mem::take(&mut me.redirect) {
                let pc = m.read_u64(me.ctx_addr + gex_abi::ctx::PC as u64).unwrap_or(0);
                return Hold::Resume(pc);
            }
            return Hold::Run;
        }
        let me = self.dtask.threads.map.entry(tid).or_default();
        if std::mem::take(&mut me.job_abort) {
            self.darwin_set_offcpu(m, tid, false);
            return Hold::Deliver;
        }
        self.darwin_set_offcpu(m, tid, true);
        Hold::Park
    }

    /// issignal's stop: a stop signal taken at its default action stops the
    /// process unless it is a terminal stop in an orphaned group, which is
    /// ignored.
    pub(crate) fn darwin_issignal_stop(&mut self, d: u32) {
        if SIGPROP[d as usize] & prop::TTYSTOP != 0 && self.procs.orphaned(self.pid) {
            return;
        }
        if !self.darwin_job_with(|j| j.stopped) {
            self.darwin_stop(d, false);
        }
    }
}
