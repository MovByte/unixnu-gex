//! A task's `phys_footprint`: its ledger entry (`ledger.c`), the limit
//! `task_set_phys_footprint_limit_internal` sets on it, and what crossing
//! it does (`task_footprint_exceeded`, `memorystatus_on_ledger_footprint_
//! exceeded`, `memorystatus_warn_process`).
//!
//! The balance is measured rather than credited page by page: the host's
//! own VM says which of the task's pages are its memory (`pmap.c` counts a
//! page as the task's when it is internal and not reusable, in memory or
//! compressed), and the page tables mapping them are counted as arm64's
//! pmap allocates them. A task measures itself on its thread calls, every
//! [`SAMPLE`]; a limit is crossed when a measurement says so, not at the
//! page that crossed it.

use super::vm::kind;
use crate::page_state as ps;
use crate::syscalls::Kernel;
use crate::GuestMem;
use std::time::{Duration, Instant};

/// How often a task measures its footprint.
pub const SAMPLE: Duration = Duration::from_millis(100);

/// `LEDGER_LIMIT_INFINITY`.
pub const LIMIT_INFINITY: i64 = i64::MAX;
/// `max_task_footprint`: j120's `kern.max_task_pmem`, 3072 MB.
pub const MAX_TASK_FOOTPRINT: i64 = 3072 << 20;
/// `max_task_footprint_warning_level`: 100 MB below the limit on a
/// device with at least 1 GB, as a percentage.
pub const MAX_TASK_FOOTPRINT_WARNING_LEVEL: u32 = ((3072 - 100) * 100) / 3072;
/// `PHYS_FOOTPRINT_WARNING_LEVEL`.
pub const PHYS_FOOTPRINT_WARNING_LEVEL: u32 = 80;
/// `LEDGER_PERCENT_NONE`.
const PERCENT_NONE: u32 = u16::MAX as u32;

/// The map's page (16 KiB) and arm64's tables over it: a leaf table maps
/// 32 MB, a twig table 64 GB; the root, of 8 entries, is 64 bytes
/// (`__ARM64_PMAP_SUBPAGE_L1__`, `T0SZ_BOOT` 25).
const PAGE: u64 = super::mach::PAGE_MASK + 1;
const L3_SHIFT: u32 = 25;
const L2_SHIFT: u32 = 36;
const ROOT_SIZE: u64 = 64;

/// The `phys_footprint` entry of a task's ledger, and the task's memory
/// limit state.
#[derive(Clone, Copy, Debug)]
pub struct Ledger {
    pub balance: i64,
    pub lifetime_max: i64,
    pub limit: i64,
    /// `le_warn_percent`: the warning level in 16.16, or none.
    warn_percent: u32,
    /// `LF_CALLED_BACK`, `LF_WARNED`.
    called_back: bool,
    warned: bool,
    pub memlimit_active: bool,
    pub memlimit_fatal: bool,
    /// `memlimit_{active,inactive}_exc_resource`.
    exc_active: bool,
    exc_inactive: bool,
}

/// `task_create_internal`'s ledger: the system-wide limit at the default
/// warning level, neither active nor fatal.
impl Default for Ledger {
    fn default() -> Ledger {
        let mut l = Ledger { balance: 0, lifetime_max: 0, limit: LIMIT_INFINITY, warn_percent: PERCENT_NONE, called_back: false, warned: false, memlimit_active: false, memlimit_fatal: false, exc_active: false, exc_inactive: false };
        l.set_limit(MAX_TASK_FOOTPRINT, PHYS_FOOTPRINT_WARNING_LEVEL);
        l
    }
}

/// A ledger callback (`LEDGER_WARNING_*`, or the limit itself).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Crossing {
    Exceeded,
    RoseAbove,
    DippedBelow,
}

impl Ledger {
    /// `ledger_set_limit`.
    fn set_limit(&mut self, limit: i64, warn_level: u32) {
        self.limit = limit;
        self.called_back = false;
        self.warned = false;
        self.warn_percent = if warn_level != 0 { warn_level * (1 << 16) / 100 } else { PERCENT_NONE };
    }

    /// `task_set_phys_footprint_limit_internal(new_limit_mb, active,
    /// fatal)`: the old limit in MB.
    pub fn set_footprint_limit(&mut self, new_limit_mb: i32, active: bool, fatal: bool) -> i32 {
        let old = (self.limit >> 20) as i32;
        if new_limit_mb == -1 {
            self.set_limit(MAX_TASK_FOOTPRINT, MAX_TASK_FOOTPRINT_WARNING_LEVEL);
            self.memlimit_active = active;
            self.memlimit_fatal = fatal;
            return old;
        }
        if active == self.memlimit_active && fatal == self.memlimit_fatal && i64::from(new_limit_mb) << 20 == self.limit {
            return old;
        }
        self.memlimit_active = active;
        self.memlimit_fatal = fatal;
        self.set_limit(i64::from(new_limit_mb) << 20, PHYS_FOOTPRINT_WARNING_LEVEL);
        old
    }

    fn limit_exceeded(&self) -> bool {
        (self.limit <= 0 && self.balance < self.limit) || (self.limit > 0 && self.balance > self.limit)
    }

    fn warn_level_exceeded(&self) -> bool {
        self.warn_percent != PERCENT_NONE && i128::from(self.balance) > (i128::from(self.limit) * i128::from(self.warn_percent)) >> 16
    }

    /// A new balance (`LF_TRACKING_MAX`), and the callback
    /// `ledger_check_needblock` makes of it.
    pub fn balance_is(&mut self, balance: i64) -> Option<Crossing> {
        self.balance = balance;
        self.lifetime_max = self.lifetime_max.max(balance);
        if !self.limit_exceeded() {
            if self.warn_level_exceeded() {
                if !self.warned {
                    self.warned = true;
                    return Some(Crossing::RoseAbove);
                }
            } else if self.warned {
                self.warned = false;
                return Some(Crossing::DippedBelow);
            }
            return None;
        }
        if self.called_back {
            return None;
        }
        self.called_back = true;
        Some(Crossing::Exceeded)
    }

    /// `task_has_triggered_exc_resource`, and its mark.
    fn exc_triggered(&mut self) -> bool {
        let t = if self.memlimit_active { &mut self.exc_active } else { &mut self.exc_inactive };
        std::mem::replace(t, true)
    }
}

impl Kernel {
    /// The task's footprint now, from the host's view of its pages; `None`
    /// where the host cannot say.
    pub(crate) fn darwin_phys_footprint(&mut self, m: &mut GuestMem<'_>) -> Option<u64> {
        let (alias, alias_end) = (gex_abi::DARWIN_COMMPAGE_ALIAS, gex_abi::DARWIN_COMMPAGE_ALIAS + (gex_abi::DARWIN_COMMPAGE_END - gex_abi::DARWIN_COMMPAGE_RO));
        // The wait words' page is gex's, not the task's.
        let waits = self.dtask.waits.page;
        let vmas: Vec<(u64, u64)> = self.mem.lock().vmas().iter().map(|v| (v.start, v.end)).filter(|&(s, e)| !(s >= alias && e <= alias_end) && !(waits != 0 && s <= waits && waits < e && e - s <= PAGE)).collect();
        let (mut internal, mut leaves, mut twigs) = (0u64, std::collections::BTreeSet::new(), std::collections::BTreeSet::new());
        let mut out = vec![0u8; 4096];
        for (s, e) in vmas {
            for (ps_, pe, a) in self.dtask.vm.pieces(s, e) {
                // The shared region's pages and tables are its own pmap's.
                if a.kind == kind::SUBMAP {
                    continue;
                }
                let mut at = ps_;
                while at < pe {
                    let n = ((pe - at) / PAGE).min(out.len() as u64);
                    if !m.page_states(at, n * PAGE, PAGE, &mut out[..n as usize]).ok()? {
                        return None;
                    }
                    for (i, &st) in out[..n as usize].iter().enumerate() {
                        let page = at + i as u64 * PAGE;
                        let own = st & ps::EXTERNAL == 0;
                        if own && st & (ps::PRESENT | ps::PAGED_OUT) != 0 && st & ps::REUSABLE == 0 {
                            internal += 1;
                        }
                        // A page table holds a resident page's entry, or a
                        // compressed one's marker.
                        if st & ps::PRESENT != 0 || (own && st & ps::PAGED_OUT != 0) {
                            leaves.insert(page >> L3_SHIFT);
                            twigs.insert(page >> L2_SHIFT);
                        }
                    }
                    at += n * PAGE;
                }
            }
        }
        Some(internal * PAGE + ROOT_SIZE + (leaves.len() + twigs.len()) as u64 * PAGE)
    }

    /// A task's thread calls: its footprint measured when it is due, and
    /// its ledger told; when it is next due.
    pub(crate) fn darwin_footprint_tick(&mut self, m: &mut GuestMem<'_>) -> Option<Instant> {
        let now = Instant::now();
        if let Some(next) = self.dtask.footprint_due.filter(|&t| t > now) {
            return Some(next);
        }
        let Some(fp) = self.darwin_phys_footprint(m) else {
            self.darwin_unimplemented("phys_footprint on a host that cannot say which pages are a task's".into());
            return None;
        };
        let pid = self.pid;
        let (crossing, ledger) = {
            let mut j = self.procs.jetsam();
            let Some(l) = j.ledgers.get_mut(&pid) else { return None };
            (l.balance_is(fp as i64), *l)
        };
        if let Some(c) = crossing {
            self.darwin_footprint_exceeded(m, c, ledger);
        }
        let next = now + SAMPLE;
        self.dtask.footprint_due = Some(next);
        Some(next)
    }

    /// `task_footprint_exceeded`: a warning, or the limit itself.
    fn darwin_footprint_exceeded(&mut self, m: &mut GuestMem<'_>, c: Crossing, l: Ledger) {
        let warning = match c {
            // Task memory limits warn only on the way up.
            Crossing::DippedBelow => return,
            Crossing::RoseAbove => true,
            Crossing::Exceeded => false,
        };
        const EXC_CORPSE_NOTIFY: usize = 13;
        let (active, fatal) = (l.memlimit_active, l.memlimit_fatal);
        if !warning {
            let triggered = self.procs.jetsam().ledgers.get_mut(&self.pid).map(|l| l.exc_triggered()).unwrap_or(true);
            // PROC_CROSSED_HIGH_WATERMARK__SEND_EXC_RESOURCE_AND_SUSPEND,
            // for a task that is not traced (none here is) and not launchd:
            // a fatal limit's EXC_RESOURCE is the corpse its kill makes
            // (corpse_for_fatal_memkill), a soft one's a forked corpse's.
            // Either reaches only a corpse notification handler.
            if !triggered && self.pid != 1 && self.darwin_task_exc_handled(EXC_CORPSE_NOTIFY) {
                self.darwin_unimplemented(format!("a corpse's EXC_RESOURCE for a crossed memory limit of {} MB (corpses)", l.limit >> 20));
            }
        }
        // memorystatus_on_ledger_footprint_exceeded.
        if warning {
            self.darwin_warn_process(m, active, fatal, false);
            return;
        }
        if fatal {
            // memorystatus_kill_process_sync(kMemorystatusKilledPerProcessLimit).
            self.procs.jetsam().effects.kill.push(self.pid);
            self.darwin_jetsam_effects();
        } else {
            self.procs.jetsam().hwm_candidates = true;
            self.darwin_warn_process(m, active, fatal, true);
        }
    }

    /// `memorystatus_warn_process`: this task's EVFILT_MEMORYSTATUS knotes
    /// told it is near (or, for a soft limit, past) its limit; whether it
    /// has any that listen.
    fn darwin_warn_process(&mut self, m: &mut GuestMem<'_>, _active: bool, _fatal: bool, exceeded: bool) -> bool {
        const PRESSURE_WARN: u32 = 0x02;
        const PRESSURE_CRITICAL: u32 = 0x04;
        const PROC_LIMIT_WARN: u32 = 0x10;
        const PROC_LIMIT_CRITICAL: u32 = 0x20;
        const PLATFORM_MACOS: u32 = 1;
        const PLATFORM_MACCATALYST: u32 = 6;
        const PLATFORM_DRIVERKIT: u32 = 10;
        let platform = self.dtask.platform.0;
        if matches!(platform, PLATFORM_MACOS | PLATFORM_MACCATALYST | PLATFORM_DRIVERKIT) {
            self.darwin_unimplemented("memory limit warnings to a macOS program (once per active and inactive limit)".into());
            return false;
        }
        let list = self.dtask.kevents.memorystatus_klist.clone();
        let (mut found, mut send) = (false, 0);
        for n in list {
            let k = self.knote(n);
            let f = if !exceeded {
                [PROC_LIMIT_WARN, PRESSURE_CRITICAL, PRESSURE_WARN].into_iter().find(|&f| k.sfflags & f != 0)
            } else {
                Some(PROC_LIMIT_CRITICAL).filter(|&f| k.sfflags & f != 0)
            };
            if let Some(f) = f {
                k.fflags = f;
                found = true;
                send += 1;
            }
        }
        if found && send > 0 {
            let list = self.dtask.kevents.memorystatus_klist.clone();
            self.knote_list(&list, 0);
            self.darwin_kevent_settle(m);
        }
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_limit_warns_at_80_percent_and_calls_back_once() {
        let mut l = Ledger::default();
        assert_eq!(l.limit, 3072 << 20);
        assert_eq!(MAX_TASK_FOOTPRINT_WARNING_LEVEL, 96);
        assert_eq!(l.balance_is(2000 << 20), None);
        assert_eq!(l.balance_is(2500 << 20), Some(Crossing::RoseAbove));
        assert_eq!(l.balance_is(2600 << 20), None);
        assert_eq!(l.balance_is(1000 << 20), Some(Crossing::DippedBelow));
        assert_eq!(l.balance_is(3100 << 20), Some(Crossing::Exceeded));
        assert_eq!(l.balance_is(3200 << 20), None);
        assert_eq!(l.balance_is(100 << 20), None);
        assert_eq!(l.balance_is(3200 << 20), None);
        assert_eq!(l.lifetime_max, 3200 << 20);
    }

    #[test]
    fn a_new_limit_rearms_and_minus_one_is_the_system_wide_one() {
        let mut l = Ledger::default();
        assert_eq!(l.set_footprint_limit(100, true, true), 3072);
        assert!(l.memlimit_active && l.memlimit_fatal);
        assert_eq!(l.balance_is(101 << 20), Some(Crossing::Exceeded));
        assert_eq!(l.set_footprint_limit(100, true, true), 100);
        assert_eq!(l.balance_is(102 << 20), None);
        assert_eq!(l.set_footprint_limit(200, true, true), 100);
        assert_eq!(l.balance_is(102 << 20), None);
        assert_eq!(l.balance_is(170 << 20), Some(Crossing::RoseAbove));
        assert_eq!(l.set_footprint_limit(-1, false, false), 200);
        assert_eq!(l.limit, MAX_TASK_FOOTPRINT);
        // 96 %: 2949 MB is past it, 2900 MB is not.
        assert_eq!(l.balance_is(2900 << 20), None);
        assert_eq!(l.balance_is(2960 << 20), Some(Crossing::RoseAbove));
    }

    #[test]
    fn an_exc_resource_is_once_per_kind_of_limit() {
        let mut l = Ledger::default();
        l.memlimit_active = true;
        assert!(!l.exc_triggered());
        assert!(l.exc_triggered());
        l.memlimit_active = false;
        assert!(!l.exc_triggered());
    }
}
