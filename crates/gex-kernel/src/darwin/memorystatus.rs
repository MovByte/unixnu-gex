//! Memorystatus (`kern_memorystatus.c`, CONFIG_JETSAM): every process's
//! jetsam band, its requested and assertion priorities, its memory limits
//! and their fatality, its dirty state for idle exit, and the aging bands a
//! clean process passes through on its way to the idle band; the
//! `memorystatus_control` commands and `proc_info`'s dirty control.
//!
//! The bands are system-wide, kept on the process table. A limit the
//! policy applies is a write to the task's `phys_footprint` ledger, handed
//! to the caller as a [`LedgerWrite`].

use crate::errno::Errno;
use std::collections::{HashMap, VecDeque};

pub const JETSAM_PRIORITY_IDLE_HEAD: i32 = -2;
pub const JETSAM_PRIORITY_IDLE: i32 = 0;
const JETSAM_PRIORITY_ENTITLED_MAX: i32 = 9;
pub const JETSAM_PRIORITY_ELEVATED_INACTIVE: i32 = 40;
pub const JETSAM_PRIORITY_FOREGROUND: i32 = 100;
pub const JETSAM_PRIORITY_DRIVER_APPLE: i32 = 150;
pub const JETSAM_PRIORITY_MAX: i32 = 210;
pub const JETSAM_PRIORITY_INTERNAL: i32 = 999;
pub const JETSAM_PRIORITY_DEFAULT: i32 = 180;
/// `MEMSTAT_BUCKET_COUNT`.
const BUCKETS: usize = JETSAM_PRIORITY_MAX as usize + 1;

/// Embedded's aging bands (`JETSAM_PRIORITY_AGING_BAND1`, `_BAND2`).
const SYSTEM_PROCS_AGING_BAND: i32 = 10;
const APPLICATIONS_AGING_BAND: i32 = 20;

/// `DEFERRED_IDLE_EXIT_TIME_SECS`, and the idle delay ratios by relaunch
/// behavior (`kJetsamSysProcsIdleDelayTime*Ratio`, `kJetsamAppsIdleDelayTimeRatio`).
const DEFERRED_IDLE_EXIT_TIME_SECS: u64 = 10;
const SYSPROCS_IDLE_RATIO_LOW: u64 = 5;
const SYSPROCS_IDLE_RATIO_MED: u64 = 2;
const SYSPROCS_IDLE_RATIO_HIGH: u64 = 1;
const APPS_IDLE_RATIO: u64 = SYSPROCS_IDLE_RATIO_LOW;

/// The device tree's `kern.max_task_pmem` for j120ap: the system-wide task
/// limit, in MB. `kern.entitled_max_task_pmem` is absent (0).
pub const MAX_TASK_FOOTPRINT_MB: i32 = 3072;
const ENTITLED_MAX_TASK_FOOTPRINT_MB: i32 = 0;
/// `legacy_footprint_bonus_mb`, with `legacy_footprint_entitlement_mode`
/// at its default, LEGACY_FOOTPRINT_ENTITLEMENT_LIMIT_INCREASE.
const LEGACY_FOOTPRINT_BONUS_MB: i32 = 50;
const IOS13EXTENDED_FOOTPRINT_LIMIT_MB: i32 = 1800;

pub mod state {
    pub const SUSPENDED: u32 = 0x1;
    pub const FROZEN: u32 = 0x2;
    pub const FREEZE_DISABLED: u32 = 0x4;
    pub const TERMINATED: u32 = 0x20;
    pub const PRIORITYUPDATED: u32 = 0x80;
    pub const REFREEZE_ELIGIBLE: u32 = 0x400;
    pub const MANAGED: u32 = 0x800;
    pub const INTERNAL: u32 = 0x1000;
    pub const FATAL_MEMLIMIT: u32 = 0x2000;
    pub const MEMLIMIT_ACTIVE_FATAL: u32 = 0x4000;
    pub const MEMLIMIT_INACTIVE_FATAL: u32 = 0x8000;
    pub const USE_ELEVATED_INACTIVE_BAND: u32 = 0x10000;
    pub const PRIORITY_ASSERTION: u32 = 0x20000;
}

/// `P_DIRTY_*`.
pub mod dirty {
    pub const TRACK: u32 = 0x1;
    pub const ALLOW_IDLE_EXIT: u32 = 0x2;
    pub const DEFER: u32 = 0x4;
    pub const DIRTY: u32 = 0x8;
    pub const SHUTDOWN: u32 = 0x10;
    pub const TERMINATED: u32 = 0x20;
    pub const MARKED: u32 = 0x80;
    pub const AGING_IN_PROGRESS: u32 = 0x100;
    pub const LAUNCH_IN_PROGRESS: u32 = 0x200;
    pub const DEFER_ALWAYS: u32 = 0x400;
    pub const IS_DIRTY: u32 = DIRTY | SHUTDOWN;
    pub const IDLE_EXIT_ENABLED: u32 = TRACK | ALLOW_IDLE_EXIT;
}

/// `PROC_DIRTY_*`: the dirty control's flags in and out.
pub mod pdirty {
    pub const TRACK: u32 = 0x1;
    pub const ALLOW_IDLE_EXIT: u32 = 0x2;
    pub const DEFER: u32 = 0x4;
    pub const LAUNCH_IN_PROGRESS: u32 = 0x8;
    pub const DEFER_ALWAYS: u32 = 0x10;
    pub const TRACKED: u32 = 0x1;
    pub const ALLOWS_IDLE_EXIT: u32 = 0x2;
    pub const IS_DIRTY: u32 = 0x4;
    pub const LAUNCH_IS_IN_PROGRESS: u32 = 0x8;
}

/// `P_MEMSTAT_RELAUNCH_*`.
pub mod relaunch {
    pub const UNKNOWN: u32 = 0x0;
    pub const LOW: u32 = 0x1;
    pub const MED: u32 = 0x2;
    pub const HIGH: u32 = 0x4;
}

/// `kMemorystatus*` state bits of a priority entry.
mod entry_state {
    pub const SUSPENDED: u32 = 0x1;
    pub const FROZEN: u32 = 0x2;
    pub const WAS_THAWED: u32 = 0x4;
    pub const TRACKED: u32 = 0x8;
    pub const SUPPORTS_IDLE_EXIT: u32 = 0x10;
    pub const DIRTY: u32 = 0x20;
    pub const ASSERTION: u32 = 0x40;
}

/// `MEMORYSTATUS_MEMLIMIT_ATTR_FATAL`.
pub const MEMLIMIT_ATTR_FATAL: u32 = 0x1;

/// A process's memorystatus fields (`p_memstat_*`).
#[derive(Clone, Debug, Default)]
pub struct Memstat {
    pub state: u32,
    pub dirty: u32,
    pub effective: i32,
    pub requested: i32,
    pub assertion: i32,
    pub userdata: u64,
    pub idle_start: u64,
    pub idle_delta: u64,
    pub idledeadline: u64,
    pub memlimit: i32,
    pub memlimit_active: i32,
    pub memlimit_inactive: i32,
    pub relaunch: u32,
    pub ppid: i32,
    /// The task's entitlements that raise its default limit.
    pub entitled: Entitled,
}

/// The entitlements `memorystatus_get_default_task_active_limit` asks of
/// the task.
#[derive(Clone, Copy, Debug, Default)]
pub struct Entitled {
    pub increased_memory_limit: bool,
    pub legacy_footprint: bool,
    pub ios13extended_footprint: bool,
}

/// `task_set_phys_footprint_limit_internal`'s arguments: the limit in MB
/// (-1 for the system-wide one), and whether it is the active one and is
/// fatal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LedgerWrite {
    pub pid: i32,
    pub limit_mb: i32,
    pub active: bool,
    pub fatal: bool,
}

/// What a memorystatus operation leaves its caller to do outside the
/// process list: the ledger writes it made, and the processes it kills
/// (SIGKILL, from `memorystatus_dirty_set`).
#[derive(Debug, Default)]
pub struct Effects {
    pub ledger: Vec<LedgerWrite>,
    pub kill: Vec<i32>,
    /// The idle demotion call was rescheduled.
    pub rescheduled: bool,
}

/// The system's memorystatus state (`memstat_bucket[]` and the counters).
#[derive(Debug)]
pub struct Jetsam {
    procs: HashMap<i32, Memstat>,
    buckets: Vec<VecDeque<i32>>,
    list_count: u32,
    demotions_sysprocs: i32,
    demotions_apps: i32,
    /// `memstat_idle_demotion_deadline`: when the demotion call runs, 0
    /// when not scheduled.
    pub demotion_deadline: u64,
    dirty_count: u32,
    /// `memorystatus_aggressive_jetsam_lenient`.
    lenient: bool,
    /// Tasks that are privileged memory pressure listeners.
    listeners: Vec<i32>,
    pub effects: Effects,
    /// Each task's `phys_footprint` ledger entry and limit state.
    pub ledgers: HashMap<i32, super::footprint::Ledger>,
    /// `memorystatus_hwm_candidates`: a task is past a soft limit.
    pub hwm_candidates: bool,
}

impl Default for Jetsam {
    fn default() -> Jetsam {
        Jetsam { procs: HashMap::new(), buckets: vec![VecDeque::new(); BUCKETS], list_count: 0, demotions_sysprocs: 0, demotions_apps: 0, demotion_deadline: 0, dirty_count: 0, lenient: false, listeners: Vec::new(), effects: Effects::default(), ledgers: HashMap::new(), hwm_candidates: false }
    }
}

fn now() -> u64 {
    super::mach::absolute_time()
}

fn is_app(p: &Memstat) -> bool {
    p.state & state::MANAGED != 0 || p.dirty & dirty::TRACK == 0
}

fn is_sysproc(p: &Memstat) -> bool {
    p.state & state::MANAGED == 0 || p.dirty & dirty::TRACK != 0
}

fn in_aging_bands(p: &Memstat) -> bool {
    (is_sysproc(p) && p.effective == SYSTEM_PROCS_AGING_BAND) || (is_app(p) && p.effective == APPLICATIONS_AGING_BAND)
}

/// `memorystatus_sysprocs_idle_time` and `memorystatus_apps_idle_time`.
fn idle_time(p: &Memstat) -> u64 {
    let delay = super::mach::ns_to_abs(DEFERRED_IDLE_EXIT_TIME_SECS * 1_000_000_000);
    if is_sysproc(p) {
        delay
            / match p.relaunch {
                relaunch::MED => SYSPROCS_IDLE_RATIO_MED,
                relaunch::HIGH => SYSPROCS_IDLE_RATIO_HIGH,
                _ => SYSPROCS_IDLE_RATIO_LOW,
            }
    } else {
        delay / APPS_IDLE_RATIO
    }
}

/// `proc_jetsam_state_is_active_locked`.
fn is_active(p: &Memstat) -> bool {
    if p.state & state::USE_ELEVATED_INACTIVE_BAND != 0 && p.effective == JETSAM_PRIORITY_ELEVATED_INACTIVE {
        true
    } else if p.dirty & dirty::TRACK != 0 {
        p.dirty & dirty::IS_DIRTY != 0
    } else {
        p.effective >= JETSAM_PRIORITY_FOREGROUND
    }
}

/// `CACHE_ACTIVE_LIMITS_LOCKED`: the fatality of the limit now in use.
fn cache_active(p: &mut Memstat) -> bool {
    p.memlimit = p.memlimit_active;
    let fatal = p.state & state::MEMLIMIT_ACTIVE_FATAL != 0;
    set_bit(&mut p.state, state::FATAL_MEMLIMIT, fatal);
    fatal
}

/// `CACHE_INACTIVE_LIMITS_LOCKED`.
fn cache_inactive(p: &mut Memstat) -> bool {
    p.memlimit = p.memlimit_inactive;
    let fatal = p.state & state::MEMLIMIT_INACTIVE_FATAL != 0;
    set_bit(&mut p.state, state::FATAL_MEMLIMIT, fatal);
    fatal
}

fn set_bit(v: &mut u32, bit: u32, on: bool) {
    if on {
        *v |= bit;
    } else {
        *v &= !bit;
    }
}

/// `memorystatus_get_default_task_active_limit` (and the inactive one,
/// which is the same): -1 (the system-wide limit) unless an entitlement
/// raises it.
fn default_task_limit(p: &Memstat) -> i32 {
    let mut limit = -1;
    // memorystatus_task_has_increased_memory_limit_entitlement: not
    // supported with no entitled_max_task_pmem.
    if p.entitled.increased_memory_limit && ENTITLED_MAX_TASK_FOOTPRINT_MB != 0 {
        limit = limit.max(ENTITLED_MAX_TASK_FOOTPRINT_MB);
    }
    if p.entitled.legacy_footprint {
        limit = limit.max(MAX_TASK_FOOTPRINT_MB + LEGACY_FOOTPRINT_BONUS_MB);
    }
    // ios13extended_footprint is only for 2 GB devices; this one has 4.
    let max_mem: u64 = 4 << 30;
    if p.entitled.ios13extended_footprint && (1500 << 20..=2 << 30).contains(&max_mem) {
        limit = limit.max(IOS13EXTENDED_FOOTPRINT_LIMIT_MB);
    }
    limit
}

/// `task_convert_phys_footprint_limit`: -1 is the system-wide limit.
fn convert_limit(limit: i32) -> i32 {
    if limit == -1 {
        MAX_TASK_FOOTPRINT_MB
    } else {
        limit
    }
}

impl Jetsam {
    pub fn get(&self, pid: i32) -> Option<&Memstat> {
        self.procs.get(&pid)
    }

    fn p(&mut self, pid: i32) -> &mut Memstat {
        self.procs.get_mut(&pid).expect("a listed process")
    }

    /// The `phys_footprint` ledger write `task_set_phys_footprint_limit_internal`
    /// makes, of the process's cached limit.
    fn ledger_write(&mut self, pid: i32, active: bool, fatal: bool) {
        let m = self.procs[&pid].memlimit;
        self.effects.ledger.push(LedgerWrite { pid, limit_mb: if m > 0 { m } else { -1 }, active, fatal });
    }

    /// forkproc's memorystatus init and `memorystatus_add`: a new process
    /// at the default band, or internal (no band) for init's clone or the
    /// exec of an internal process.
    pub fn add(&mut self, pid: i32, ppid: i32, internal: bool, relaunch: u32) {
        let mut p = Memstat { effective: JETSAM_PRIORITY_DEFAULT, requested: JETSAM_PRIORITY_DEFAULT, ppid, relaunch, ..Default::default() };
        // The new task's ledger.
        self.ledgers.insert(pid, super::footprint::Ledger::default());
        if internal {
            p.state |= state::INTERNAL;
            p.effective = JETSAM_PRIORITY_INTERNAL;
            p.requested = JETSAM_PRIORITY_INTERNAL;
            self.procs.insert(pid, p);
            return;
        }
        if is_sysproc(&p) {
            p.state |= state::FREEZE_DISABLED;
        }
        if p.effective == JETSAM_PRIORITY_IDLE {
            p.idle_start = now();
        }
        let b = p.effective as usize;
        self.procs.insert(pid, p);
        self.buckets[b].push_back(pid);
        self.list_count += 1;
    }

    /// Whether `pid`'s process is internal (no band of its own).
    pub fn internal(&self, pid: i32) -> bool {
        self.procs.get(&pid).is_some_and(|p| p.state & state::INTERNAL != 0)
    }

    /// `memorystatus_remove`, at the process's exit.
    pub fn remove(&mut self, pid: i32) {
        self.ledgers.remove(&pid);
        let Some(p) = self.procs.get(&pid).cloned() else { return };
        if p.state & state::INTERNAL != 0 {
            self.procs.remove(&pid);
            return;
        }
        let reschedule = in_aging_bands(&p);
        if p.effective == JETSAM_PRIORITY_IDLE {
            let t = now();
            if t > p.idle_start {
                self.p(pid).idle_delta = t - p.idle_start;
            }
        }
        let b = &mut self.buckets[p.effective as usize];
        b.retain(|&x| x != pid);
        self.list_count -= 1;
        if reschedule {
            self.invalidate_idle_demotion(pid, true);
        }
        if p.dirty & dirty::IS_DIRTY != 0 {
            self.dirty_count -= 1;
        }
        self.procs.remove(&pid);
        self.listeners.retain(|&x| x != pid);
        if reschedule {
            self.reschedule_idle_demotion();
        }
    }

    /// The entitlements a process holds for its default limit, as its image
    /// gives them.
    pub fn set_entitled(&mut self, pid: i32, e: Entitled) {
        if let Some(p) = self.procs.get_mut(&pid) {
            p.entitled = e;
        }
    }

    /// `memorystatus_update_priority_locked`.
    fn update_priority(&mut self, pid: i32, mut priority: i32, head_insert: bool, skip_demotion_check: bool) {
        let p = self.procs[&pid].clone();
        if !skip_demotion_check {
            if is_sysproc(&p) {
                if p.state & state::USE_ELEVATED_INACTIVE_BAND != 0 && priority <= JETSAM_PRIORITY_ELEVATED_INACTIVE {
                    priority = JETSAM_PRIORITY_ELEVATED_INACTIVE;
                }
            } else if is_app(&p) {
                if p.state & state::USE_ELEVATED_INACTIVE_BAND != 0 {
                    if priority <= JETSAM_PRIORITY_ELEVATED_INACTIVE {
                        priority = JETSAM_PRIORITY_ELEVATED_INACTIVE;
                    }
                } else if priority <= APPLICATIONS_AGING_BAND {
                    priority = APPLICATIONS_AGING_BAND;
                    self.schedule_idle_demotion(pid, true);
                }
            }
        }
        let old = self.procs[&pid].effective as usize;
        self.buckets[old].retain(|&x| x != pid);
        if head_insert {
            self.buckets[priority as usize].push_front(pid);
        } else {
            self.buckets[priority as usize].push_back(pid);
        }
        // memorystatus_highwater_enabled: the cached limit follows an
        // active <--> inactive (FG <--> BG) move; a dirty-tracked process's
        // follows its dirty state instead, but for the move to idle.
        let pm = self.p(pid);
        let update = if pm.dirty & dirty::TRACK != 0 {
            (skip_demotion_check && priority == JETSAM_PRIORITY_IDLE).then(|| (false, cache_inactive(pm)))
        } else if priority >= JETSAM_PRIORITY_FOREGROUND && pm.effective < JETSAM_PRIORITY_FOREGROUND {
            Some((true, cache_active(pm)))
        } else if priority < JETSAM_PRIORITY_FOREGROUND && pm.effective >= JETSAM_PRIORITY_FOREGROUND {
            Some((false, cache_inactive(pm)))
        } else {
            None
        };
        if let Some((active, fatal)) = update {
            self.ledger_write(pid, active, fatal);
        }
        let pm = self.p(pid);
        if pm.effective != priority {
            if pm.effective == JETSAM_PRIORITY_IDLE {
                let t = now();
                if t > pm.idle_start {
                    pm.idle_delta = t - pm.idle_start;
                }
            } else if priority == JETSAM_PRIORITY_IDLE {
                pm.idle_start = now();
            }
        }
        pm.effective = priority;
    }

    /// `memorystatus_schedule_idle_demotion_locked`.
    fn schedule_idle_demotion(&mut self, pid: i32, set_state: bool) {
        let p = &self.procs[&pid];
        if p.state & (state::USE_ELEVATED_INACTIVE_BAND | state::PRIORITY_ASSERTION) != 0 {
            return;
        }
        let present_sys = in_aging_bands(p) && is_sysproc(p);
        let present_app = in_aging_bands(p) && !is_sysproc(p) && is_app(p);
        let delay = idle_time(p);
        let sys = is_sysproc(p);
        let app = is_app(p);
        let pm = self.p(pid);
        if set_state {
            pm.dirty |= dirty::AGING_IN_PROGRESS;
            pm.idledeadline = now() + delay;
        }
        if sys && !present_sys {
            self.demotions_sysprocs += 1;
        } else if app && !present_app {
            self.demotions_apps += 1;
        }
    }

    /// `memorystatus_invalidate_idle_demotion_locked`.
    fn invalidate_idle_demotion(&mut self, pid: i32, clear_state: bool) {
        let p = &self.procs[&pid];
        if p.dirty & dirty::AGING_IN_PROGRESS == 0 {
            return;
        }
        let (present_sys, present_app) = if in_aging_bands(p) {
            if is_sysproc(p) { (true, false) } else { (false, is_app(p)) }
        } else {
            (false, false)
        };
        let sys = is_sysproc(p);
        let app = is_app(p);
        if clear_state {
            let pm = self.p(pid);
            pm.idledeadline = 0;
            pm.dirty &= !dirty::AGING_IN_PROGRESS;
        }
        if sys && present_sys {
            self.demotions_sysprocs -= 1;
        } else if app && present_app {
            self.demotions_apps -= 1;
        }
    }

    /// `memorystatus_reschedule_idle_demotion_locked`: the demotion call
    /// moved to the earliest deadline at the head of an aging band.
    fn reschedule_idle_demotion(&mut self) {
        let deadline = if self.demotions_sysprocs + self.demotions_apps == 0 {
            0
        } else {
            let head = |b: i32| self.buckets[b as usize].front().map(|pid| self.procs[pid].idledeadline);
            match (head(SYSTEM_PROCS_AGING_BAND), head(APPLICATIONS_AGING_BAND)) {
                (Some(a), Some(b)) => a.min(b),
                (Some(a), None) | (None, Some(a)) => a,
                (None, None) => self.demotion_deadline,
            }
        };
        if deadline != self.demotion_deadline {
            self.demotion_deadline = deadline;
            self.effects.rescheduled = true;
        }
    }

    /// `memorystatus_perform_idle_demotion`: the demotion call, at `now`.
    /// No task holds an importance assertion (`task_has_assertions`):
    /// importance boosts are not made here.
    pub fn perform_idle_demotion(&mut self, now: u64) {
        for band in [SYSTEM_PROCS_AGING_BAND, APPLICATIONS_AGING_BAND] {
            let pids: Vec<i32> = self.buckets[band as usize].iter().copied().collect();
            for pid in pids {
                let p = &self.procs[&pid];
                if now < p.idledeadline {
                    break;
                }
                if is_sysproc(p) && p.dirty & (dirty::IDLE_EXIT_ENABLED | dirty::IS_DIRTY) != dirty::IDLE_EXIT_ENABLED {
                    let d = idle_time(p);
                    self.p(pid).idledeadline += d;
                } else {
                    self.invalidate_idle_demotion(pid, true);
                    self.update_priority(pid, JETSAM_PRIORITY_IDLE, false, true);
                }
            }
        }
        self.demotion_deadline = 0;
        self.reschedule_idle_demotion();
    }

    /// `memorystatus_update_idle_priority_locked`.
    fn update_idle_priority(&mut self, pid: i32) {
        let p = &self.procs[&pid];
        let mut priority = if p.dirty & (dirty::IDLE_EXIT_ENABLED | dirty::IS_DIRTY) == dirty::IDLE_EXIT_ENABLED {
            if p.dirty & dirty::AGING_IN_PROGRESS != 0 { SYSTEM_PROCS_AGING_BAND } else { JETSAM_PRIORITY_IDLE }
        } else {
            p.requested
        };
        if p.state & state::PRIORITY_ASSERTION != 0 && p.assertion > priority {
            priority = p.assertion;
        }
        if priority != p.effective {
            self.update_priority(pid, priority, false, false);
        }
    }

    /// `memorystatus_update`: `Err` is the errno. `entitled_range`: the
    /// caller may use bands 1 to 9 (`current_task_can_use_entitled_range`).
    #[allow(clippy::too_many_arguments)]
    pub fn update(&mut self, pid: i32, mut priority: i32, user_data: u64, is_assertion: bool, effective: bool, memlimit: Option<(i32, bool, i32, bool)>, entitled_range: bool) -> Result<(), Errno> {
        let mut head_insert = false;
        if priority == -1 {
            priority = JETSAM_PRIORITY_DEFAULT;
        } else if priority > JETSAM_PRIORITY_IDLE && priority <= APPLICATIONS_AGING_BAND {
            if priority > JETSAM_PRIORITY_ENTITLED_MAX || !entitled_range {
                priority = JETSAM_PRIORITY_IDLE;
            }
        } else if priority == JETSAM_PRIORITY_IDLE_HEAD {
            priority = JETSAM_PRIORITY_IDLE;
            head_insert = true;
        } else if priority < 0 || priority as usize >= BUCKETS {
            return Err(Errno::EINVAL);
        }
        let Some(p) = self.procs.get(&pid) else { return Err(Errno::EBUSY) };
        if effective && p.state & state::PRIORITYUPDATED != 0 {
            return Err(Errno::EALREADY);
        }
        if p.state & state::TERMINATED != 0 {
            return Err(Errno::EBUSY);
        }
        let pm = self.p(pid);
        pm.state |= state::PRIORITYUPDATED;
        pm.userdata = user_data;
        if is_assertion {
            if priority == JETSAM_PRIORITY_IDLE {
                if pm.state & state::PRIORITY_ASSERTION != 0 {
                    pm.state &= !state::PRIORITY_ASSERTION;
                } else {
                    // Not previously controlled by assertions: ignored.
                    return Ok(());
                }
            } else {
                pm.state |= state::PRIORITY_ASSERTION;
            }
            pm.assertion = priority;
            let flags = Self::dirty_get_of(pm);
            if flags != 0 {
                let maxp = if flags & pdirty::IS_DIRTY != 0 {
                    pm.assertion.max(pm.requested)
                } else if flags & pdirty::ALLOWS_IDLE_EXIT != 0 {
                    let mut newp = JETSAM_PRIORITY_IDLE;
                    if pm.dirty & (dirty::IDLE_EXIT_ENABLED | dirty::IS_DIRTY) == dirty::IDLE_EXIT_ENABLED && pm.dirty & dirty::AGING_IN_PROGRESS != 0 {
                        newp = SYSTEM_PROCS_AGING_BAND;
                    }
                    let m = pm.assertion.max(newp);
                    if newp == SYSTEM_PROCS_AGING_BAND {
                        self.schedule_idle_demotion(pid, false);
                    }
                    m
                } else {
                    pm.assertion.max(pm.requested)
                };
                priority = maxp;
            }
        } else {
            pm.requested = priority;
        }
        if let Some((mut active, mut active_fatal, mut inactive, mut inactive_fatal)) = memlimit {
            if active <= 0 {
                if active < 0 {
                    active = -1;
                }
                active_fatal = true;
            }
            if inactive <= 0 {
                inactive = -1;
                inactive_fatal = true;
            }
            let pm = self.p(pid);
            pm.memlimit_active = active;
            set_bit(&mut pm.state, state::MEMLIMIT_ACTIVE_FATAL, active_fatal);
            pm.memlimit_inactive = inactive;
            set_bit(&mut pm.state, state::MEMLIMIT_INACTIVE_FATAL, inactive_fatal);
            let use_active = is_active(pm);
            let fatal = if use_active { cache_active(pm) } else { cache_inactive(pm) };
            self.ledger_write(pid, use_active, fatal);
        }
        if in_aging_bands(&self.procs[&pid]) {
            let app_up = is_app(&self.procs[&pid]) && priority > APPLICATIONS_AGING_BAND;
            self.invalidate_idle_demotion(pid, app_up);
            self.update_priority(pid, JETSAM_PRIORITY_IDLE, false, true);
        }
        self.update_priority(pid, priority, head_insert, false);
        Ok(())
    }

    fn dirty_get_of(p: &Memstat) -> u32 {
        let mut r = 0;
        if p.dirty & dirty::TRACK != 0 {
            r |= pdirty::TRACKED;
            if p.dirty & dirty::ALLOW_IDLE_EXIT != 0 {
                r |= pdirty::ALLOWS_IDLE_EXIT;
            }
            if p.dirty & dirty::DIRTY != 0 {
                r |= pdirty::IS_DIRTY;
            }
            if p.dirty & dirty::LAUNCH_IN_PROGRESS != 0 {
                r |= pdirty::LAUNCH_IS_IN_PROGRESS;
            }
        }
        r
    }

    /// `memorystatus_dirty_get`.
    pub fn dirty_get(&self, pid: i32) -> Option<u32> {
        self.procs.get(&pid).map(Self::dirty_get_of)
    }

    /// `memorystatus_dirty_track`.
    pub fn dirty_track(&mut self, pid: i32, pcontrol: u32) -> Result<(), Errno> {
        let Some(p) = self.procs.get(&pid) else { return Err(Errno::EBUSY) };
        if p.state & state::INTERNAL != 0 {
            return Err(Errno::EPERM);
        }
        // memorystatus_validate_track_flags.
        if p.dirty & dirty::TERMINATED != 0 {
            return Err(Errno::EBUSY);
        }
        if pcontrol & (pdirty::ALLOW_IDLE_EXIT | pdirty::LAUNCH_IN_PROGRESS) != 0 && pcontrol & pdirty::TRACK == 0 {
            return Err(Errno::EINVAL);
        }
        if pcontrol & pdirty::DEFER != 0 && pcontrol & pdirty::DEFER_ALWAYS != 0 {
            return Err(Errno::EINVAL);
        }
        // (PROC_DIRTY_ALLOWS_IDLE_EXIT is the output flag, of the same
        // value as PROC_DIRTY_ALLOW_IDLE_EXIT.)
        if pcontrol & (pdirty::DEFER | pdirty::DEFER_ALWAYS) != 0 && pcontrol & pdirty::ALLOWS_IDLE_EXIT == 0 {
            return Err(Errno::EINVAL);
        }
        let old = p.dirty;
        let pm = self.p(pid);
        if pcontrol & pdirty::TRACK != 0 {
            // An app (managed, with no fatal limit) may not turn dirty
            // tracking on: silently refused.
            if pm.state & state::MANAGED != 0 && pm.state & state::FATAL_MEMLIMIT == 0 {
                return Ok(());
            }
            pm.dirty |= dirty::TRACK;
        }
        if pcontrol & pdirty::ALLOW_IDLE_EXIT != 0 {
            pm.dirty |= dirty::ALLOW_IDLE_EXIT;
        }
        if pcontrol & pdirty::LAUNCH_IN_PROGRESS != 0 {
            pm.dirty |= dirty::LAUNCH_IN_PROGRESS;
        }
        let already_deferred = old & dirty::AGING_IN_PROGRESS != 0;
        let mut defer_now = false;
        if pcontrol & (pdirty::DEFER | pdirty::DEFER_ALWAYS) != 0 {
            if pcontrol & pdirty::DEFER != 0 && old & dirty::DEFER == 0 {
                pm.dirty |= dirty::DEFER;
            }
            if pcontrol & pdirty::DEFER_ALWAYS != 0 && old & dirty::DEFER_ALWAYS == 0 {
                pm.dirty |= dirty::DEFER_ALWAYS;
            }
            defer_now = true;
        }
        let mut reschedule = false;
        let d = pm.dirty;
        if d & dirty::IS_DIRTY == 0 {
            if d & dirty::IDLE_EXIT_ENABLED == dirty::IDLE_EXIT_ENABLED {
                if defer_now && !already_deferred {
                    self.schedule_idle_demotion(pid, true);
                    reschedule = true;
                } else if !defer_now {
                    if already_deferred {
                        self.invalidate_idle_demotion(pid, true);
                    } else {
                        self.schedule_idle_demotion(pid, true);
                    }
                    reschedule = true;
                }
            }
        } else {
            self.invalidate_idle_demotion(pid, true);
            reschedule = true;
        }
        self.update_idle_priority(pid);
        if reschedule {
            self.reschedule_idle_demotion();
        }
        Ok(())
    }

    /// `memorystatus_dirty_set` (`self_`: the process marks itself, else
    /// it is the shutdown flag another sets).
    pub fn dirty_set(&mut self, pid: i32, self_: bool, pcontrol: u32) -> Result<(), Errno> {
        let Some(p) = self.procs.get(&pid) else { return Err(Errno::EBUSY) };
        if p.state & state::INTERNAL != 0 {
            return Err(Errno::EPERM);
        }
        let was_dirty = p.dirty & dirty::IS_DIRTY != 0;
        let mut kill = false;
        if p.dirty & dirty::TRACK == 0 {
            return Err(Errno::EINVAL);
        }
        if pcontrol != 0 && p.dirty & dirty::TERMINATED != 0 {
            return Err(Errno::EBUSY);
        }
        let flag = if self_ { dirty::DIRTY } else { dirty::SHUTDOWN };
        let pm = self.p(pid);
        if pcontrol != 0 && pm.dirty & flag == 0 {
            pm.dirty |= flag | dirty::MARKED;
            self.dirty_count += 1;
        } else if pcontrol == 0 && pm.dirty & flag != 0 {
            if flag == dirty::SHUTDOWN && pm.dirty & dirty::DIRTY == 0 {
                pm.dirty |= dirty::TERMINATED;
                kill = true;
            } else if flag == dirty::DIRTY && pm.dirty & dirty::TERMINATED != 0 {
                kill = true;
            }
            pm.dirty &= !flag;
            self.dirty_count -= 1;
        } else {
            return Err(Errno::EALREADY);
        }
        let pm = self.p(pid);
        let now_dirty = pm.dirty & dirty::IS_DIRTY != 0;
        if was_dirty != now_dirty {
            let mut reschedule = false;
            if pm.dirty & dirty::IDLE_EXIT_ENABLED == dirty::IDLE_EXIT_ENABLED {
                if now_dirty {
                    self.invalidate_idle_demotion(pid, true);
                } else {
                    self.schedule_idle_demotion(pid, true);
                }
                reschedule = true;
            }
            self.update_idle_priority(pid);
            let pm = self.p(pid);
            if is_active(pm) {
                let fatal = cache_active(pm);
                self.ledger_write(pid, true, fatal);
            } else if pm.dirty & dirty::ALLOW_IDLE_EXIT == 0 {
                let fatal = cache_inactive(pm);
                self.ledger_write(pid, false, fatal);
            }
            if reschedule {
                self.reschedule_idle_demotion();
            }
        }
        if kill {
            self.effects.kill.push(pid);
        }
        Ok(())
    }

    /// `memorystatus_dirty_clear`.
    pub fn dirty_clear(&mut self, pid: i32, pcontrol: u32) -> Result<(), Errno> {
        let Some(p) = self.procs.get(&pid) else { return Err(Errno::EBUSY) };
        if p.state & state::INTERNAL != 0 {
            return Err(Errno::EPERM);
        }
        if p.dirty & dirty::TRACK == 0 {
            return Err(Errno::EINVAL);
        }
        if pcontrol == 0 || pcontrol & (pdirty::LAUNCH_IN_PROGRESS | pdirty::DEFER | pdirty::DEFER_ALWAYS) == 0 {
            return Err(Errno::EINVAL);
        }
        let pm = self.p(pid);
        if pcontrol & pdirty::LAUNCH_IN_PROGRESS != 0 {
            pm.dirty &= !dirty::LAUNCH_IN_PROGRESS;
        }
        if pcontrol & (pdirty::DEFER | pdirty::DEFER_ALWAYS) != 0 {
            pm.dirty &= !(dirty::DEFER | dirty::DEFER_ALWAYS);
            self.invalidate_idle_demotion(pid, true);
            self.update_idle_priority(pid);
            self.reschedule_idle_demotion();
        }
        Ok(())
    }

    /// `memorystatus_build_state`.
    fn build_state(p: &Memstat) -> u32 {
        let mut s = 0;
        if p.state & state::SUSPENDED != 0 {
            s |= entry_state::SUSPENDED;
        }
        if p.state & state::FROZEN != 0 {
            s |= entry_state::FROZEN;
        }
        if p.state & state::REFREEZE_ELIGIBLE != 0 {
            s |= entry_state::WAS_THAWED;
        }
        if p.state & state::PRIORITY_ASSERTION != 0 {
            s |= entry_state::ASSERTION;
        }
        if p.dirty & dirty::TRACK != 0 {
            s |= entry_state::TRACKED;
        }
        if p.dirty & dirty::IDLE_EXIT_ENABLED == dirty::IDLE_EXIT_ENABLED {
            s |= entry_state::SUPPORTS_IDLE_EXIT;
        }
        if p.dirty & dirty::IS_DIRTY != 0 {
            s |= entry_state::DIRTY;
        }
        s
    }

    /// A `memorystatus_priority_entry_t` (pid, priority, user_data, limit,
    /// state: 24 bytes); `limit` of a process on the system-wide limit is
    /// its ledger's (`task_get_phys_footprint_limit`).
    fn entry(&self, pid: i32, ledger_limit: &dyn Fn(i32) -> i32) -> [u8; 24] {
        let p = &self.procs[&pid];
        let mut b = [0u8; 24];
        b[0..4].copy_from_slice(&pid.to_le_bytes());
        b[4..8].copy_from_slice(&p.effective.to_le_bytes());
        b[8..16].copy_from_slice(&p.userdata.to_le_bytes());
        let limit = if p.memlimit <= 0 { ledger_limit(pid) } else { p.memlimit };
        b[16..20].copy_from_slice(&limit.to_le_bytes());
        b[20..24].copy_from_slice(&Self::build_state(p).to_le_bytes());
        b
    }

    /// `memorystatus_get_priority_list`: every listed process, band by
    /// band, in its band's order.
    pub fn priority_list(&self, ledger_limit: &dyn Fn(i32) -> i32) -> Vec<u8> {
        let mut out = Vec::with_capacity(24 * self.list_count as usize);
        for b in &self.buckets {
            for &pid in b {
                out.extend_from_slice(&self.entry(pid, ledger_limit));
            }
        }
        out
    }

    pub fn list_count(&self) -> u32 {
        self.list_count
    }

    /// `memorystatus_get_priority_pid`.
    pub fn priority_entry(&self, pid: i32, ledger_limit: &dyn Fn(i32) -> i32) -> Option<[u8; 24]> {
        self.procs.contains_key(&pid).then(|| self.entry(pid, ledger_limit))
    }

    /// `memorystatus_set_memlimit_properties` (with the internal half):
    /// a limit of 0 or less is the default task limit, always fatal.
    pub fn set_memlimit_properties(&mut self, pid: i32, mut active: i32, active_attr: u32, mut inactive: i32, inactive_attr: u32) -> Result<(), Errno> {
        let Some(p) = self.procs.get(&pid) else { return Err(Errno::ESRCH) };
        if active_attr & !MEMLIMIT_ATTR_FATAL != 0 || inactive_attr & !MEMLIMIT_ATTR_FATAL != 0 {
            return Err(Errno::EINVAL);
        }
        let mut active_fatal = active_attr & MEMLIMIT_ATTR_FATAL != 0;
        let mut inactive_fatal = inactive_attr & MEMLIMIT_ATTR_FATAL != 0;
        if active <= 0 {
            active = default_task_limit(p);
            active_fatal = true;
        }
        if inactive <= 0 {
            inactive = default_task_limit(p);
            inactive_fatal = true;
        }
        let pm = self.p(pid);
        pm.memlimit_active = active;
        set_bit(&mut pm.state, state::MEMLIMIT_ACTIVE_FATAL, active_fatal);
        pm.memlimit_inactive = inactive;
        set_bit(&mut pm.state, state::MEMLIMIT_INACTIVE_FATAL, inactive_fatal);
        let use_active = is_active(pm);
        let fatal = if use_active { cache_active(pm) } else { cache_inactive(pm) };
        self.ledger_write(pid, use_active, fatal);
        Ok(())
    }

    /// `memorystatus_get_memlimit_properties_internal`: active limit and
    /// attributes, inactive limit and attributes.
    pub fn memlimit_properties(&self, pid: i32) -> Option<[u8; 16]> {
        let p = self.procs.get(&pid)?;
        let mut b = [0u8; 16];
        let active = if p.memlimit_active > 0 { p.memlimit_active } else { convert_limit(-1) };
        let inactive = if p.memlimit_inactive <= 0 { convert_limit(-1) } else { p.memlimit_inactive };
        b[0..4].copy_from_slice(&active.to_le_bytes());
        b[4..8].copy_from_slice(&u32::from(p.state & state::MEMLIMIT_ACTIVE_FATAL != 0).to_le_bytes());
        b[8..12].copy_from_slice(&inactive.to_le_bytes());
        b[12..16].copy_from_slice(&u32::from(p.state & state::MEMLIMIT_INACTIVE_FATAL != 0).to_le_bytes());
        Some(b)
    }

    /// `memorystatus_cmd_convert_memlimit_mb`.
    pub fn convert_memlimit_mb(&self, pid: i32, limit: i32) -> Result<i32, Errno> {
        let p = self.procs.get(&pid).ok_or(Errno::ESRCH)?;
        if limit <= 0 {
            let l = default_task_limit(p);
            Ok(if l <= 0 { MAX_TASK_FOOTPRINT_MB } else { l })
        } else {
            Ok(limit)
        }
    }

    /// `memorystatus_set_process_is_managed`.
    pub fn set_managed(&mut self, pid: i32, managed: bool) -> Result<(), Errno> {
        let p = self.procs.get_mut(&pid).ok_or(Errno::ESRCH)?;
        if managed {
            p.state |= state::MANAGED;
            p.state &= !state::FREEZE_DISABLED;
        } else {
            p.state &= !state::MANAGED;
        }
        Ok(())
    }

    /// `memorystatus_get_process_is_managed`.
    pub fn managed(&self, pid: i32) -> Option<bool> {
        self.procs.get(&pid).map(|p| p.state & state::MANAGED != 0)
    }

    /// `memorystatus_update_inactive_jetsam_priority_band`.
    pub fn elevated_inactive(&mut self, pid: i32, enable: bool, jetsam_prio: i32, effective_now: bool) -> Result<(), Errno> {
        let p = self.procs.get(&pid).ok_or(Errno::ESRCH)?;
        if enable == (p.state & state::USE_ELEVATED_INACTIVE_BAND != 0) {
            return Ok(());
        }
        let pm = self.p(pid);
        set_bit(&mut pm.state, state::USE_ELEVATED_INACTIVE_BAND, enable);
        self.invalidate_idle_demotion(pid, true);
        let pm = &self.procs[&pid];
        if enable {
            if effective_now {
                if pm.effective < jetsam_prio {
                    let fatal = cache_active(self.p(pid));
                    self.ledger_write(pid, true, fatal);
                    self.update_priority(pid, jetsam_prio, false, false);
                }
            } else if in_aging_bands(pm) {
                self.update_priority(pid, JETSAM_PRIORITY_IDLE, false, true);
            }
        } else if effective_now {
            if pm.effective == jetsam_prio {
                self.update_priority(pid, JETSAM_PRIORITY_IDLE, false, true);
            }
        } else if in_aging_bands(pm) {
            self.update_priority(pid, JETSAM_PRIORITY_IDLE, false, true);
        }
        Ok(())
    }

    /// `memorystatus_cmd_grp_set_priorities`: the (pid, priority) entries,
    /// checked as `memorystatus_update` checks a priority, then applied in
    /// the processes' band order (a process not in a band, or internal,
    /// skipped); a process leaving an aging band loses its demotion. Only
    /// the effective band moves.
    pub fn group_set_priority(&mut self, entries: &[(i32, i32)], entitled_range: bool) -> Result<(), Errno> {
        let mut checked = Vec::with_capacity(entries.len());
        for &(pid, mut prio) in entries {
            if prio == -1 {
                prio = JETSAM_PRIORITY_DEFAULT;
            } else if prio > JETSAM_PRIORITY_IDLE && prio <= APPLICATIONS_AGING_BAND {
                if prio > JETSAM_PRIORITY_ENTITLED_MAX || !entitled_range {
                    prio = JETSAM_PRIORITY_IDLE;
                }
            } else if prio == JETSAM_PRIORITY_IDLE_HEAD {
            } else if prio < 0 || prio as usize >= BUCKETS {
                return Err(Errno::EINVAL);
            }
            checked.push((pid, prio));
        }
        let mut table = Vec::new();
        'bands: for b in &self.buckets {
            for &pid in b {
                if table.len() == checked.len() {
                    break 'bands;
                }
                if let Some(&(_, prio)) = checked.iter().find(|(p, _)| *p == pid) {
                    table.push((pid, prio));
                }
            }
        }
        for (pid, prio) in table {
            let (prio, head) = if prio == JETSAM_PRIORITY_IDLE_HEAD { (JETSAM_PRIORITY_IDLE, true) } else { (prio, false) };
            let p = &self.procs[&pid];
            if p.state & state::INTERNAL != 0 {
                continue;
            }
            if p.effective == SYSTEM_PROCS_AGING_BAND || p.effective == APPLICATIONS_AGING_BAND {
                self.invalidate_idle_demotion(pid, true);
            }
            self.update_priority(pid, prio, head, false);
        }
        Ok(())
    }

    /// `memorystatus_set_process_is_freezable`'s change of state.
    pub fn set_freezable(&mut self, pid: i32, freezable: bool) -> Result<(), Errno> {
        let p = self.procs.get_mut(&pid).ok_or(Errno::ESRCH)?;
        set_bit(&mut p.state, state::FREEZE_DISABLED, !freezable);
        Ok(())
    }

    /// Whether `pid` may be frozen, and whether it is.
    pub fn freeze_state(&self, pid: i32) -> Option<(bool, bool)> {
        self.procs.get(&pid).map(|p| (p.state & state::FREEZE_DISABLED == 0, p.state & state::FROZEN != 0))
    }

    /// `memorystatus_privileged_listener`.
    pub fn privileged_listener(&mut self, pid: i32, enable: bool) {
        self.listeners.retain(|&x| x != pid);
        if enable {
            self.listeners.push(pid);
        }
    }

    pub fn set_lenient(&mut self, on: bool) {
        self.lenient = on;
    }

    pub fn lenient(&self) -> bool {
        self.lenient
    }
}

/// `memorystatus_control`'s commands.
mod cmd {
    pub const GET_PRIORITY_LIST: u32 = 1;
    pub const SET_PRIORITY_PROPERTIES: u32 = 2;
    pub const GET_JETSAM_SNAPSHOT: u32 = 3;
    pub const GET_PRESSURE_STATUS: u32 = 4;
    pub const SET_JETSAM_HIGH_WATER_MARK: u32 = 5;
    pub const SET_JETSAM_TASK_LIMIT: u32 = 6;
    pub const SET_MEMLIMIT_PROPERTIES: u32 = 7;
    pub const GET_MEMLIMIT_PROPERTIES: u32 = 8;
    pub const PRIVILEGED_LISTENER_ENABLE: u32 = 9;
    pub const PRIVILEGED_LISTENER_DISABLE: u32 = 10;
    pub const LENIENT_MODE_ENABLE: u32 = 11;
    pub const LENIENT_MODE_DISABLE: u32 = 12;
    pub const GET_MEMLIMIT_EXCESS: u32 = 13;
    pub const ELEVATED_INACTIVE_ENABLE: u32 = 14;
    pub const ELEVATED_INACTIVE_DISABLE: u32 = 15;
    pub const SET_PROCESS_IS_MANAGED: u32 = 16;
    pub const GET_PROCESS_IS_MANAGED: u32 = 17;
    pub const SET_PROCESS_IS_FREEZABLE: u32 = 18;
    pub const GET_PROCESS_IS_FREEZABLE: u32 = 19;
    pub const FREEZER_CONTROL: u32 = 20;
    pub const GET_LENIENT_MODE: u32 = 21;
    pub const GET_PROCESS_IS_FROZEN: u32 = 24;
    pub const MARK_PROCESS_COALITION_SWAPPABLE: u32 = 25;
    pub const GET_PROCESS_COALITION_IS_SWAPPABLE: u32 = 26;
    pub const CONVERT_MEMLIMIT_MB: u32 = 28;
    pub const GRP_SET_PROPERTIES: u32 = 100;
}

/// `MEMORYSTATUS_ENTITLEMENT`.
const MEMORYSTATUS_ENTITLEMENT: &str = "com.apple.private.memorystatus";
/// `MEMORYSTATUS_BUFFERSIZE_MAX`.
const BUFFERSIZE_MAX: u64 = 65536;
/// `MEMORYSTATUS_FLAGS_GRP_SET_*`.
const GRP_SET_PRIORITY: u32 = 0x8;
const GRP_SET_PROBABILITY: u32 = 0x10;
const GRP_SET_FREEZE_PRIORITY: u32 = 0x100;
const GRP_SET_DEMOTE_PRIORITY: u32 = 0x200;
/// `MEMORYSTATUS_MPE_VERSION_1`, and the entry's size (56 bytes, aligned).
const MPE_VERSION_1: i32 = 1;
const MPE_VERSION_1_SIZE: usize = 56;

impl crate::syscalls::Kernel {
    /// Whether this task holds the entitlement to use bands 1 to 9
    /// (`current_task_can_use_entitled_range`).
    fn jetsam_entitled_range(&self) -> bool {
        self.darwin_task_entitled("com.apple.private.internal-jetsam-range")
    }

    /// The entitlements that raise this task's default limit, as its image
    /// holds them.
    pub(crate) fn darwin_jetsam_entitlements(&mut self) {
        let e = Entitled {
            increased_memory_limit: self.darwin_task_entitled("com.apple.developer.kernel.increased-memory-limit"),
            legacy_footprint: self.darwin_task_entitled("com.apple.private.memory.legacy_footprint"),
            ios13extended_footprint: self.darwin_task_entitled("com.apple.developer.memory.ios13extended_footprint"),
        };
        self.procs.jetsam().set_entitled(self.pid, e);
    }

    /// What memorystatus left to do outside its lock: the ledger writes,
    /// the kills, and the demotion call's new time for every task's thread
    /// calls to wake for.
    pub(crate) fn darwin_jetsam_effects(&mut self) {
        let fx = std::mem::take(&mut self.procs.jetsam().effects);
        for w in fx.ledger {
            self.darwin_footprint_limit(w);
        }
        for pid in fx.kill {
            self.procs.post_kernel(pid, super::kern::signal_to_linux(super::signal::dsig::SIGKILL));
        }
        if fx.rescheduled {
            for l in self.ipc().links.values() {
                l.bell.ring();
            }
        }
    }

    /// `task_set_phys_footprint_limit_internal`: the limit written to the
    /// task's `phys_footprint` ledger.
    /// `task_set_phys_footprint_limit_internal` on a task's ledger; the
    /// task checks its balance against it when it next measures.
    fn darwin_footprint_limit(&mut self, w: LedgerWrite) {
        if let Some(l) = self.procs.jetsam().ledgers.get_mut(&w.pid) {
            l.set_footprint_limit(w.limit_mb, w.active, w.fatal);
        }
    }

    /// The idle demotion call, when it is due; when it is next.
    pub(crate) fn darwin_jetsam_tick(&mut self) -> Option<std::time::Instant> {
        let now = super::mach::absolute_time();
        let deadline = self.procs.jetsam().demotion_deadline;
        if deadline != 0 && now >= deadline {
            self.procs.jetsam().perform_idle_demotion(now);
            self.darwin_jetsam_effects();
        }
        let deadline = self.procs.jetsam().demotion_deadline;
        (deadline != 0).then(|| super::mach::abs_to_instant(deadline))
    }

    /// `cansignal(current, target, SIGKILL)`: root, the process itself, or
    /// one of the same uid (a process has one uid here).
    fn jetsam_cansignal(&self, pid: i32) -> bool {
        let uid = self.creds.uid();
        uid == 0 || pid == self.pid || self.procs.live_nice(pid).is_some_and(|(t, _)| t == uid)
    }

    /// `proc_dirtycontrol(pid, flavor, arg)`: `proc_info`'s
    /// PROC_INFO_CALL_DIRTYCONTROL. The value is the call's return.
    pub(crate) fn darwin_dirtycontrol(&mut self, pid: i32, flavor: u32, arg: u64) -> Result<u64, Errno> {
        const TRACK: u32 = 1;
        const SET: u32 = 2;
        const GET: u32 = 3;
        const CLEAR: u32 = 4;
        let pcontrol = arg as u32;
        let target = self.procs.live_nice(pid);
        let jetsam_has = self.procs.jetsam().get(pid).is_some();
        // proc_find, or a zombie for GET (proc_find_zombref).
        if target.is_none() && !(flavor == GET && jetsam_has) {
            return Err(Errno::ESRCH);
        }
        let me = pid == self.pid;
        let child = self.procs.ppid(pid) == self.pid;
        let r = match flavor {
            TRACK => {
                if !me && !child && self.creds.uid() != 0 {
                    return Err(Errno::EPERM);
                }
                self.procs.jetsam().dirty_track(pid, pcontrol).map(|_| 0)
            }
            SET => {
                if !self.jetsam_cansignal(pid) {
                    return Err(Errno::EPERM);
                }
                self.procs.jetsam().dirty_set(pid, me, pcontrol).map(|_| 0)
            }
            GET => Ok(u64::from(self.procs.jetsam().dirty_get(pid).unwrap_or(0))),
            CLEAR => {
                if !self.jetsam_cansignal(pid) {
                    return Err(Errno::EPERM);
                }
                self.procs.jetsam().dirty_clear(pid, pcontrol).map(|_| 0)
            }
            _ => Ok(0),
        };
        self.darwin_jetsam_effects();
        r
    }

    /// `memorystatus_control(command, pid, flags, buffer, buffersize)`: the
    /// value is the call's return (`*ret`).
    pub(crate) fn darwin_memorystatus_control(&mut self, m: &mut crate::GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        let (command, pid, flags, buffer, size) = (a[0] as u32, a[1] as i32, a[2] as u32, a[3], a[4]);
        let root = self.creds.uid() == 0;
        let entitled = self.darwin_task_entitled(MEMORYSTATUS_ENTITLEMENT);
        let skip_auth = matches!(command, cmd::SET_PROCESS_IS_FREEZABLE | cmd::GET_PROCESS_IS_FREEZABLE | cmd::GET_PROCESS_IS_FROZEN);
        if !root && !entitled && !skip_auth {
            return Err(Errno::EPERM);
        }
        if command != cmd::GET_JETSAM_SNAPSHOT && size > BUFFERSIZE_MAX {
            return Err(Errno::EINVAL);
        }
        let ledger_limit = |_pid: i32| MAX_TASK_FOOTPRINT_MB;
        let r = match command {
            cmd::GET_PRIORITY_LIST => {
                if pid != 0 {
                    // memorystatus_get_priority_pid (a size query is 24).
                    if buffer != 0 {
                        if size != 24 {
                            return Err(Errno::EINVAL);
                        }
                        let e = self.procs.jetsam().priority_entry(pid, &ledger_limit).ok_or(Errno::ESRCH)?;
                        m.write(buffer, &e)?;
                    }
                    Ok(24)
                } else {
                    let j = self.procs.jetsam();
                    let list_size = 24 * u64::from(j.list_count());
                    if buffer == 0 {
                        return Ok(list_size);
                    }
                    if size < list_size {
                        return Err(Errno::EINVAL);
                    }
                    let list = j.priority_list(&ledger_limit);
                    drop(j);
                    m.write(buffer, &list)?;
                    Ok(list.len() as u64)
                }
            }
            cmd::SET_PRIORITY_PROPERTIES => {
                // memorystatus_priority_properties_t: priority, user_data.
                const SET_PRIORITY_ASSERTION: u32 = 0x1;
                if pid == 0 || buffer == 0 || size != 16 || flags & !SET_PRIORITY_ASSERTION != 0 {
                    return Err(Errno::EINVAL);
                }
                let (prio, user_data) = (m.read_u32(buffer)? as i32, m.read_u64(buffer + 8)?);
                let range = self.jetsam_entitled_range();
                let mut j = self.procs.jetsam();
                match j.get(pid) {
                    None => return Err(Errno::ESRCH),
                    Some(p) if p.state & state::INTERNAL != 0 => return Err(Errno::EPERM),
                    Some(_) => {}
                }
                j.update(pid, prio, user_data, flags & SET_PRIORITY_ASSERTION != 0, false, None, range).map(|_| 0)
            }
            cmd::SET_MEMLIMIT_PROPERTIES => {
                // memorystatus_memlimit_properties_t: active, its attributes,
                // inactive, its attributes.
                if pid == 0 || buffer == 0 || size != 16 {
                    return Err(Errno::EINVAL);
                }
                let b = m.read(buffer, 16)?.to_vec();
                let w = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
                self.procs.jetsam().set_memlimit_properties(pid, w(0) as i32, w(4), w(8) as i32, w(12)).map(|_| 0)
            }
            cmd::GET_MEMLIMIT_PROPERTIES => {
                // The v1 entry, or the v2 one (with the limit increase that
                // only development kernels make: zero here).
                if pid == 0 || buffer == 0 || (size != 16 && size != 32) {
                    return Err(Errno::EINVAL);
                }
                let e = self.procs.jetsam().memlimit_properties(pid).ok_or(Errno::ESRCH)?;
                let mut out = vec![0u8; size as usize];
                out[..16].copy_from_slice(&e);
                m.write(buffer, &out)?;
                Ok(0)
            }
            cmd::SET_JETSAM_HIGH_WATER_MARK | cmd::SET_JETSAM_TASK_LIMIT => {
                let fatal = command == cmd::SET_JETSAM_TASK_LIMIT;
                let attr = if fatal { MEMLIMIT_ATTR_FATAL } else { 0 };
                self.procs.jetsam().set_memlimit_properties(pid, flags as i32, attr, flags as i32, attr).map(|_| 0)
            }
            cmd::CONVERT_MEMLIMIT_MB => self.procs.jetsam().convert_memlimit_mb(pid, flags as i32).map(|l| l as u32 as u64),
            cmd::GRP_SET_PROPERTIES => {
                let f = flags;
                if f & GRP_SET_PRIORITY == GRP_SET_PRIORITY {
                    if buffer == 0 || size == 0 {
                        return Err(Errno::EINVAL);
                    }
                    let count = size as usize / MPE_VERSION_1_SIZE;
                    if count == 0 {
                        return Err(Errno::EINVAL);
                    }
                    let b = m.read(buffer, size as usize)?.to_vec();
                    let w = |o: usize| i32::from_le_bytes(b[o..o + 4].try_into().unwrap());
                    if w(0) != MPE_VERSION_1 || size as usize % MPE_VERSION_1_SIZE != 0 {
                        return Err(Errno::EINVAL);
                    }
                    let entries: Vec<(i32, i32)> = (0..count).map(|i| (w(i * MPE_VERSION_1_SIZE + 4), w(i * MPE_VERSION_1_SIZE + 8))).collect();
                    let range = self.jetsam_entitled_range();
                    self.procs.jetsam().group_set_priority(&entries, range).map(|_| 0)
                } else if f & (GRP_SET_PROBABILITY | GRP_SET_FREEZE_PRIORITY | GRP_SET_DEMOTE_PRIORITY) != 0 {
                    self.darwin_unimplemented("memorystatus group probabilities and freezer lists (the freezer)".into());
                    Err(Errno::EINVAL)
                } else {
                    Err(Errno::EINVAL)
                }
            }
            cmd::LENIENT_MODE_ENABLE => {
                // memorystatus_aggressive_jetsam_lenient_allowed: already
                // allowed leaves the call's EINVAL.
                let mut j = self.procs.jetsam();
                if j.lenient() {
                    Err(Errno::EINVAL)
                } else {
                    j.set_lenient(true);
                    Ok(0)
                }
            }
            cmd::LENIENT_MODE_DISABLE => {
                self.procs.jetsam().set_lenient(false);
                Ok(0)
            }
            cmd::GET_LENIENT_MODE => Ok(u64::from(self.procs.jetsam().lenient())),
            cmd::PRIVILEGED_LISTENER_ENABLE | cmd::PRIVILEGED_LISTENER_DISABLE => {
                // task_low_mem_privileged_listener on the calling task.
                self.procs.jetsam().privileged_listener(self.pid, command == cmd::PRIVILEGED_LISTENER_ENABLE);
                Ok(0)
            }
            cmd::ELEVATED_INACTIVE_ENABLE | cmd::ELEVATED_INACTIVE_DISABLE => self.procs.jetsam().elevated_inactive(pid, command == cmd::ELEVATED_INACTIVE_ENABLE, JETSAM_PRIORITY_ELEVATED_INACTIVE, flags != 0).map(|_| 0),
            cmd::SET_PROCESS_IS_MANAGED => {
                if pid == 0 {
                    return Err(Errno::EINVAL);
                }
                self.procs.jetsam().set_managed(pid, flags != 0).map(|_| 0)
            }
            cmd::GET_PROCESS_IS_MANAGED => {
                if pid == 0 {
                    return Err(Errno::EINVAL);
                }
                self.procs.jetsam().managed(pid).map(u64::from).ok_or(Errno::ESRCH)
            }
            cmd::SET_PROCESS_IS_FREEZABLE => {
                let freezable = flags != 0;
                if pid == 0 {
                    return Err(Errno::EINVAL);
                }
                if freezable && !root && !entitled {
                    return Err(Errno::EPERM);
                }
                if self.procs.jetsam().get(pid).is_none() {
                    return Err(Errno::ESRCH);
                }
                if pid != self.pid && !root && !entitled {
                    // A coalition leader may change its members'.
                    self.darwin_unimplemented("memorystatus_set_process_is_freezable on another process by its coalition leader (coalitions)".into());
                    return Err(Errno::EPERM);
                }
                self.procs.jetsam().set_freezable(pid, freezable).map(|_| 0)
            }
            cmd::GET_PROCESS_IS_FREEZABLE => {
                if pid == 0 {
                    return Err(Errno::EINVAL);
                }
                let (freezable, _) = self.procs.jetsam().freeze_state(pid).ok_or(Errno::ESRCH)?;
                if pid != self.pid {
                    return Err(Errno::EPERM);
                }
                Ok(u64::from(freezable))
            }
            cmd::GET_PROCESS_IS_FROZEN => {
                if pid == 0 {
                    return Err(Errno::EINVAL);
                }
                if pid != self.pid {
                    return Err(Errno::EPERM);
                }
                Ok(u64::from(self.procs.jetsam().freeze_state(pid).is_some_and(|(_, f)| f)))
            }
            cmd::GET_JETSAM_SNAPSHOT | cmd::GET_PRESSURE_STATUS | cmd::GET_MEMLIMIT_EXCESS | cmd::FREEZER_CONTROL | cmd::MARK_PROCESS_COALITION_SWAPPABLE | cmd::GET_PROCESS_COALITION_IS_SWAPPABLE => {
                self.darwin_unimplemented(format!("memorystatus_control command {command} (the memory model: footprints, pressure, the freezer, coalitions)"));
                Err(Errno::EINVAL)
            }
            _ => Err(Errno::EINVAL),
        };
        self.darwin_jetsam_effects();
        r
    }
}
