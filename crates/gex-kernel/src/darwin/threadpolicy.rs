//! `thread_policy_set` and `thread_policy_get` (`osfmk/kern/thread_policy.c`)
//! by their flavors, on embedded: timesharing or fixed priority, realtime
//! time constraints, precedence, background, the latency and throughput QoS
//! tiers and the QoS policy (which user space may not set).

use std::time::Duration;

use super::workq::qos;
use crate::syscalls::Kernel;

/// `thread_policy_flavor_t`s.
mod flavor {
    pub const EXTENDED: i32 = 1;
    pub const TIME_CONSTRAINT: i32 = 2;
    pub const PRECEDENCE: i32 = 3;
    pub const AFFINITY: i32 = 4;
    pub const BACKGROUND: i32 = 5;
    pub const POLICY_STATE: i32 = 6;
    pub const LATENCY_QOS: i32 = 7;
    pub const THROUGHPUT_QOS: i32 = 8;
    pub const QOS: i32 = 9;
    pub const TIME_CONSTRAINT_WITH_PRIORITY: i32 = 10;
    pub const REQUESTED_STATE: i32 = 11;
}

/// `kern_return_t`s.
const KERN_PROTECTION_FAILURE: i32 = 2;
const KERN_INVALID_ARGUMENT: i32 = 4;
const KERN_INVALID_POLICY: i32 = 28;
const KERN_NOT_SUPPORTED: i32 = 46;
const KERN_POLICY_STATIC: i32 = 51;

/// `BASEPRI_RTQUEUES`, `MAXPRI`.
pub const BASEPRI_RTQUEUES: i32 = 97;
const MAXPRI: i32 = 127;
/// `THREAD_QOS_MIN_TIER_IMPORTANCE`.
const MIN_TIER_IMPORTANCE: i32 = -15;
/// `THREAD_BACKGROUND_POLICY_DARWIN_BG`.
const BACKGROUND_DARWIN_BG: i32 = 0x1000;

/// A realtime thread's time constraints (`thread->realtime`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Realtime {
    pub period: u32,
    pub computation: u32,
    pub constraint: u32,
    pub preemptible: bool,
    pub priority_offset: u8,
}

/// `std_quantum` (1/DEFAULT_PREEMPTION_RATE, 100 a second), and
/// `min_rt_quantum` (50 us) and `max_rt_quantum` (50 ms), in absolute time.
fn std_quantum() -> u32 {
    super::workq::abs_time(Duration::from_micros(10_000)) as u32
}
fn min_rt_quantum() -> u32 {
    super::workq::abs_time(Duration::from_micros(50)) as u32
}
fn max_rt_quantum() -> u32 {
    super::workq::abs_time(Duration::from_millis(50)) as u32
}

/// `qos_latency_policy_validate`'s and `qos_throughput_policy_validate`'s
/// tiers (0 is unspecified).
fn tier_valid(t: u32, base: u32) -> bool {
    t == 0 || (base | 1..=base | 6).contains(&t)
}
const LATENCY_TIER: u32 = 0xFF << 16;
const THROUGHPUT_TIER: u32 = 0xFE << 16;

impl Kernel {
    /// `thread_policy_set` on thread `tid`, the caller's (`caller`) or
    /// another of its task's: a workqueue thread's parameters are static,
    /// the QoS policy is not for user space, and a realtime priority must
    /// be BASEPRI_RTQUEUES (allow_qos_policy_set is off); a QoS policy is
    /// removed while another is applied, and put back if that fails.
    pub(crate) fn darwin_thread_policy_set(&mut self, tid: i32, caller: i32, flavor: i32, info: &[i32]) -> i32 {
        let th = self.dtask.threads.map.entry(tid).or_default();
        if th.wq.is_some() {
            return KERN_POLICY_STATIC;
        }
        if flavor == flavor::QOS {
            return KERN_INVALID_ARGUMENT;
        }
        if flavor == flavor::TIME_CONSTRAINT_WITH_PRIORITY && (info.len() < 5 || info[4] != BASEPRI_RTQUEUES) {
            return KERN_INVALID_ARGUMENT;
        }
        let saved = (th.policy.qos != qos::UNSPECIFIED).then_some((th.policy.qos, th.policy.relpri));
        if saved.is_some() {
            th.policy.qos = qos::UNSPECIFIED;
            th.policy.relpri = 0;
        }
        let kr = self.thread_policy_set_internal(tid, caller, flavor, info);
        if let (Some((q, r)), true) = (saved, kr != 0) {
            let p = &mut self.dtask.threads.map.entry(tid).or_default().policy;
            p.qos = q;
            p.relpri = r;
        }
        kr
    }

    /// `thread_policy_set_internal`.
    fn thread_policy_set_internal(&mut self, tid: i32, caller: i32, flavor: i32, info: &[i32]) -> i32 {
        let th = self.dtask.threads.map.entry(tid).or_default();
        let n = info.len();
        match flavor {
            flavor::EXTENDED => {
                let timeshare = if n >= 1 { info[0] != 0 } else { true };
                th.realtime = None;
                th.policy.timeshare = Some(timeshare);
            }
            flavor::TIME_CONSTRAINT | flavor::TIME_CONSTRAINT_WITH_PRIORITY => {
                let min = if flavor == flavor::TIME_CONSTRAINT { 4 } else { 5 };
                if n < min {
                    return KERN_INVALID_ARGUMENT;
                }
                let (period, mut computation, constraint) = (info[0] as u32, info[1] as u32, info[2] as u32);
                let (lo, hi) = (min_rt_quantum(), max_rt_quantum());
                if constraint < computation || computation > hi || computation < lo {
                    return KERN_INVALID_ARGUMENT;
                }
                if computation < constraint / 2 {
                    computation = (constraint / 2).min(hi);
                }
                let mut offset = 0;
                if flavor == flavor::TIME_CONSTRAINT_WITH_PRIORITY {
                    let p = info[4];
                    if !(BASEPRI_RTQUEUES..=MAXPRI).contains(&p) {
                        return KERN_INVALID_ARGUMENT;
                    }
                    offset = (p - BASEPRI_RTQUEUES) as u8;
                }
                th.realtime = Some(Realtime { period, computation, constraint, preemptible: info[3] != 0, priority_offset: offset });
            }
            flavor::PRECEDENCE => {
                if n < 1 {
                    return KERN_INVALID_ARGUMENT;
                }
                th.policy.importance = Some(info[0]);
            }
            // affinity_sets_enabled is off on embedded.
            flavor::AFFINITY => return KERN_INVALID_POLICY,
            flavor::BACKGROUND => {
                if n < 1 {
                    return KERN_INVALID_ARGUMENT;
                }
                let on = info[0] == BACKGROUND_DARWIN_BG;
                if tid == caller {
                    th.policy.int_darwinbg = on;
                } else {
                    th.policy.ext_darwinbg = on;
                }
            }
            flavor::THROUGHPUT_QOS | flavor::LATENCY_QOS => {
                if n < 1 {
                    return KERN_INVALID_ARGUMENT;
                }
                let t = info[0] as u32;
                let base = if flavor == flavor::LATENCY_QOS { LATENCY_TIER } else { THROUGHPUT_TIER };
                if !tier_valid(t, base) {
                    return KERN_INVALID_ARGUMENT;
                }
                if flavor == flavor::LATENCY_QOS {
                    th.policy.latency_qos = (t & 0xFF) as u8;
                } else {
                    th.policy.through_qos = (t & 0xFF) as u8;
                }
            }
            flavor::QOS => {
                if n < 2 {
                    return KERN_INVALID_ARGUMENT;
                }
                let (tier, imp) = (info[0], info[1]);
                if !(0..i32::from(qos::LAST)).contains(&tier) || imp > 0 || imp < MIN_TIER_IMPORTANCE || (tier == 0 && imp != 0) {
                    return KERN_INVALID_ARGUMENT;
                }
                th.policy.qos = tier as u8;
                th.policy.relpri = imp;
            }
            _ => return KERN_INVALID_ARGUMENT,
        }
        0
    }

    /// `thread_policy_get` on thread `tid`: the flavor's words (`count` of
    /// them) and `get_default` as it leaves it, or the error; `None` for
    /// what this kernel does not keep as XNU does.
    pub(crate) fn darwin_thread_policy_get(&mut self, tid: i32, flavor: i32, count: u32, mut get_default: bool) -> Option<Result<(Vec<i32>, bool), i32>> {
        let privileged = self.creds.uid() == 0;
        let th = self.dtask.threads.map.entry(tid).or_default();
        let mut out = vec![0i32; count as usize];
        match flavor {
            flavor::EXTENDED => {
                let mut timeshare = true;
                if !get_default {
                    if th.realtime.is_none() {
                        timeshare = th.policy.timeshare.unwrap_or(true);
                    } else {
                        get_default = true;
                    }
                }
                if count >= 1 {
                    out[0] = i32::from(timeshare);
                }
            }
            flavor::TIME_CONSTRAINT | flavor::TIME_CONSTRAINT_WITH_PRIORITY => {
                let with = flavor == flavor::TIME_CONSTRAINT_WITH_PRIORITY;
                if count < if with { 5 } else { 4 } {
                    return Some(Err(KERN_INVALID_ARGUMENT));
                }
                match th.realtime.filter(|_| !get_default) {
                    Some(rt) => {
                        out[..4].copy_from_slice(&[rt.period as i32, rt.computation as i32, rt.constraint as i32, i32::from(rt.preemptible)]);
                        if with {
                            out[4] = i32::from(rt.priority_offset) + BASEPRI_RTQUEUES;
                        }
                    }
                    None => {
                        get_default = true;
                        // default_timeshare_computation and _constraint.
                        let q = std_quantum();
                        out[..4].copy_from_slice(&[0, (q / 2) as i32, q as i32, 1]);
                        if with {
                            out[4] = BASEPRI_RTQUEUES;
                        }
                    }
                }
            }
            flavor::PRECEDENCE => {
                if count < 1 {
                    return Some(Err(KERN_INVALID_ARGUMENT));
                }
                out[0] = if get_default { 0 } else { th.policy.importance.unwrap_or(0) };
            }
            // ml_get_max_affinity_sets is 0 on arm.
            flavor::AFFINITY => return Some(Err(KERN_NOT_SUPPORTED)),
            flavor::POLICY_STATE => {
                if count < 16 {
                    return Some(Err(KERN_INVALID_ARGUMENT));
                }
                if !privileged {
                    return Some(Err(KERN_PROTECTION_FAILURE));
                }
                if !get_default {
                    return None;
                }
            }
            flavor::REQUESTED_STATE => {
                if count < 7 {
                    return Some(Err(KERN_INVALID_ARGUMENT));
                }
                return None;
            }
            flavor::LATENCY_QOS | flavor::THROUGHPUT_QOS => {
                if count < 1 {
                    return Some(Err(KERN_INVALID_ARGUMENT));
                }
                let (v, base) = if flavor == flavor::LATENCY_QOS { (th.policy.latency_qos, LATENCY_TIER) } else { (th.policy.through_qos, THROUGHPUT_TIER) };
                let v = if get_default { 0 } else { v };
                out[0] = if v == 0 { 0 } else { (base | u32::from(v)) as i32 };
            }
            flavor::QOS => {
                if count < 2 {
                    return Some(Err(KERN_INVALID_ARGUMENT));
                }
                if !get_default {
                    out[0] = i32::from(th.policy.qos);
                    out[1] = th.policy.relpri;
                }
            }
            _ => return Some(Err(KERN_INVALID_ARGUMENT)),
        }
        Some(Ok((out, get_default)))
    }
}
