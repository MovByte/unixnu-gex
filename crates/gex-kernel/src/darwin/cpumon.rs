//! The CPU usage monitor (`osfmk/kern/task_policy.c`'s `task_set_cpuusage`,
//! `thread.c`'s `thread_set_cpulimit`, and the per-thread CPU time ledger
//! of `ledger.c`): a task-wide limit on how much of an interval any one of
//! its threads may compute, each thread's time credited to its own ledger,
//! refilled every interval; a thread over it is reported
//! (`SENDING_NOTIFICATION__THIS_THREAD_IS_CONSUMING_TOO_MUCH_CPU`) and the
//! monitor suspended.

use crate::syscalls::Kernel;

/// `TASK_RUSECPU_FLAGS_*`.
pub mod rflag {
    pub const PROC_LIMIT: u32 = 0x01;
    pub const PERTHR_LIMIT: u32 = 0x02;
    pub const DEADLINE: u32 = 0x04;
    pub const FATAL_CPUMON: u32 = 0x08;
    pub const FATAL_WAKEUPSMON: u32 = 0x10;
}

/// `TASK_POLICY_RESOURCE_ATTRIBUTE_*` (as `PROC_POLICY_RSRCACT_*`).
pub mod attr {
    pub const NONE: u16 = 0;
    pub const THROTTLE: u16 = 1;
    pub const SUSPEND: u16 = 2;
    pub const TERMINATE: u16 = 3;
    pub const NOTIFY_KQ: u16 = 4;
    pub const NOTIFY_EXC: u16 = 5;
}

/// `PROC_POLICY_CPUMON_DISABLE` and `PROC_POLICY_CPUMON_DEFAULTS`.
const CPUMON_DISABLE: u8 = 0xff;
const CPUMON_DEFAULTS: u8 = 0xfe;

/// `proc_max_cpumon_percentage` and `proc_max_cpumon_interval`: no boot
/// argument and no `kern.max_cpumon_*` in the device tree's `/defaults`
/// (iPad7,1's has neither), so `DEFAULT_CPUMON_PERCENTAGE` and
/// `DEFAULT_CPUMON_INTERVAL` (three minutes).
const MAX_CPUMON_PERCENTAGE: u8 = 50;
const MAX_CPUMON_INTERVAL: u64 = 3 * 60 * NSEC_PER_SEC;

const NSEC_PER_SEC: u64 = 1_000_000_000;

/// `MINIMUM_CPULIMIT_INTERVAL_MS`.
const MINIMUM_CPULIMIT_INTERVAL: u64 = 1_000_000;

/// `LEDGER_LIMIT_INFINITY`.
const LIMIT_INFINITY: i64 = i64::MAX;

/// `TASK_WAKEUPS_MONITOR_DEFAULT_LIMIT` (per second) and
/// `TASK_WAKEUPS_MONITOR_DEFAULT_INTERVAL` (in seconds).
const WAKEUPS_DEFAULT_RATE: i32 = 150;
const WAKEUPS_INTERVAL: i64 = 300;

/// The limit on a task's `interrupt_wakeups` ledger entry, which is what
/// the wakeups monitor is. The entry's count is not kept: no task is told
/// of crossing it, and turning the monitor to a rate of a task's own is
/// reported.
#[derive(Clone, Copy, Debug)]
pub struct WakeupsMonitor {
    pub limit: i64,
    pub period: u64,
    pub callback: bool,
}

impl Default for WakeupsMonitor {
    /// `task_create_internal`: every task starts with the defaults on.
    fn default() -> WakeupsMonitor {
        WakeupsMonitor { limit: i64::from(WAKEUPS_DEFAULT_RATE) * WAKEUPS_INTERVAL, period: WAKEUPS_INTERVAL as u64 * NSEC_PER_SEC, callback: true }
    }
}

/// A task's CPU usage limits (`task->rusage_cpu_*`, `policy_ru_cpu*`).
#[derive(Clone, Copy, Debug, Default)]
pub struct CpuUsage {
    pub flags: u32,
    pub perthr_percentage: u8,
    pub perthr_interval: u64,
    pub percentage: u8,
    pub interval: u64,
    pub deadline: u64,
    pub policy_ru_cpu: u16,
    pub policy_ru_cpu_ext: u16,
}

/// A thread's CPU time ledger entry (`thread_ledgers.cpu_time`), in Mach
/// time units: what it has run (credit), what refills took back (debit),
/// its limit and refill period, and the entry's flags.
#[derive(Clone, Copy, Debug)]
pub struct CpuLedger {
    pub credit: i64,
    pub debit: i64,
    pub limit: i64,
    pub period: u64,
    pub last_refill: u64,
    pub refill_scheduled: bool,
    pub called_back: bool,
    /// `TH_OPT_PROC_CPULIMIT`: the limit is the task's monitor's.
    pub proc_cpulimit: bool,
}

impl Default for CpuLedger {
    fn default() -> Self {
        CpuLedger { credit: 0, debit: 0, limit: LIMIT_INFINITY, period: 0, last_refill: 0, refill_scheduled: false, called_back: false, proc_cpulimit: false }
    }
}

impl CpuLedger {
    fn balance(&self) -> i64 {
        self.credit - self.debit
    }

    /// `limit_exceeded`.
    fn exceeded(&self) -> bool {
        let b = self.balance();
        (self.limit <= 0 && b < self.limit) || (self.limit > 0 && b > self.limit)
    }

    /// `ledger_refill(now, ...)`.
    fn refill(&mut self, now: u64) {
        if now <= self.last_refill {
            return;
        }
        let period = self.period;
        let mut elapsed = now - self.last_refill;
        if period == 0 || elapsed < period {
            return;
        }
        let mut periods = 0u64;
        while periods < 2 && elapsed > 0 {
            periods += 1;
            elapsed = elapsed.saturating_sub(period);
        }
        if elapsed > 0 {
            periods = (now - self.last_refill) / period;
        }
        let balance = self.balance();
        let mut due = (periods as i64).saturating_mul(self.limit);
        if balance - due < 0 {
            due = balance;
        }
        self.debit += due;
        if balance == due {
            self.last_refill = now;
        } else {
            self.last_refill += period * periods;
        }
        if !self.exceeded() {
            self.called_back = false;
        }
    }
}

/// Mach time units from nanoseconds (`nanoseconds_to_absolutetime`).
fn ns_to_abs(ns: u64) -> u64 {
    let (numer, denom) = super::mach::TIMEBASE;
    (u128::from(ns) * u128::from(denom) / u128::from(numer)) as u64
}

/// Nanoseconds from Mach time units (`absolutetime_to_nanoseconds`).
fn abs_to_ns(abs: u64) -> u64 {
    let (numer, denom) = super::mach::TIMEBASE;
    (u128::from(abs) * u128::from(numer) / u128::from(denom)) as u64
}

impl Kernel {
    /// `proc_rlimit_control(pid, flavor, arg)`.
    pub(crate) fn darwin_proc_rlimit_control(&mut self, m: &mut crate::GuestMem<'_>, a: &[u64; 6]) -> Result<u64, crate::errno::Errno> {
        use crate::errno::Errno;
        const RLIMIT_WAKEUPS_MONITOR: i32 = 1;
        const RLIMIT_CPU_USAGE_MONITOR: i32 = 2;
        const RLIMIT_THREAD_CPULIMITS: i32 = 3;
        const CPUMON_MAKE_FATAL: u32 = 0x1000;
        let (pid, flavor, arg) = (a[0] as i32, a[1] as i32, a[2]);
        if pid != -1 && pid != self.pid {
            if !self.procs.exists(pid) {
                return Err(Errno::ESRCH);
            }
            self.darwin_unimplemented(format!("proc_rlimit_control flavor {flavor} of another process"));
            return Err(Errno::EINVAL);
        }
        match flavor {
            RLIMIT_WAKEUPS_MONITOR => {
                let (mut flags, mut rate) = (m.read_u32(arg)?, m.read_u32(arg + 4)? as i32);
                if !self.darwin_wakeups_monitor_ctl(&mut flags, &mut rate) {
                    return Err(Errno::EINVAL);
                }
                m.write_u32(arg, flags)?;
                m.write_u32(arg + 4, rate as u32)?;
                Ok(0)
            }
            RLIMIT_CPU_USAGE_MONITOR => {
                if arg as u32 & CPUMON_MAKE_FATAL == 0 {
                    return Err(Errno::EINVAL);
                }
                self.dtask.cpuusage.flags |= rflag::FATAL_CPUMON;
                Ok(0)
            }
            RLIMIT_THREAD_CPULIMITS => {
                if pid != -1 || !(1..100).contains(&(arg as u32 & 0xff)) {
                    return Err(Errno::EINVAL);
                }
                self.darwin_unimplemented("proc_rlimit_control RLIMIT_THREAD_CPULIMITS (a thread blocked at its limit)".into());
                Err(Errno::EINVAL)
            }
            // CONFIG_LEDGER_INTERVAL_MAX is not in a device's kernel, and so
            // not RLIMIT_FOOTPRINT_INTERVAL.
            _ => Err(Errno::EINVAL),
        }
    }

    /// `task_wakeups_monitor_ctl`; false for KERN_INVALID_ARGUMENT.
    fn darwin_wakeups_monitor_ctl(&mut self, flags: &mut u32, rate: &mut i32) -> bool {
        const WAKEMON_ENABLE: u32 = 0x01;
        const WAKEMON_DISABLE: u32 = 0x02;
        const WAKEMON_GET_PARAMS: u32 = 0x04;
        const WAKEMON_SET_DEFAULTS: u32 = 0x08;
        const WAKEMON_MAKE_FATAL: u32 = 0x10;
        let w = self.dtask.wakeups;
        if *flags & WAKEMON_GET_PARAMS != 0 {
            if w.limit != LIMIT_INFINITY {
                *rate = (w.limit / (w.period / NSEC_PER_SEC) as i64) as i32;
                *flags = WAKEMON_ENABLE;
                if self.dtask.cpuusage.flags & rflag::FATAL_WAKEUPSMON != 0 {
                    *flags |= WAKEMON_MAKE_FATAL;
                }
            } else {
                *flags = WAKEMON_DISABLE;
                *rate = -1;
            }
            return true;
        }
        if *flags & WAKEMON_ENABLE != 0 {
            let defaults = *flags & WAKEMON_SET_DEFAULTS != 0;
            if defaults {
                *rate = WAKEUPS_DEFAULT_RATE;
            }
            if *flags & WAKEMON_MAKE_FATAL != 0 {
                self.dtask.cpuusage.flags |= rflag::FATAL_WAKEUPSMON;
            }
            if *rate <= 0 {
                return false;
            }
            if !defaults {
                self.darwin_unimplemented(format!("the wakeups monitor at {} per second (the task's interrupt wakeups are not counted)", *rate));
            }
            self.dtask.wakeups = WakeupsMonitor { limit: i64::from(*rate) * WAKEUPS_INTERVAL, period: WAKEUPS_INTERVAL as u64 * NSEC_PER_SEC, callback: true };
        } else if *flags & WAKEMON_DISABLE != 0 {
            // The refill and callback go; the limit stays, and a later
            // WAKEMON_GET_PARAMS still reports it.
            self.dtask.wakeups.callback = false;
        }
        true
    }

    /// `proc_set_task_ruse_cpu(task, policy, percentage, interval,
    /// deadline, cpumon_entitled)` on this task: the policy's scope (a
    /// percentage for THROTTLE and NOTIFY_EXC, a deadline for SUSPEND,
    /// TERMINATE and NOTIFY_KQ; ENOTSUP for the other), then
    /// `task_set_cpuusage`. A Darwin errno.
    pub(crate) fn darwin_set_task_ruse_cpu(&mut self, policy: u16, percentage: u8, interval: u64, deadline: u64, entitled: bool) -> Result<(), i32> {
        const ENOTSUP: i32 = 45;
        const EINVAL: i32 = 22;
        let scope = match policy {
            attr::NONE | attr::THROTTLE => {
                if deadline != 0 {
                    return Err(ENOTSUP);
                }
                rflag::PROC_LIMIT
            }
            attr::SUSPEND | attr::TERMINATE | attr::NOTIFY_KQ => {
                if percentage != 0 {
                    return Err(ENOTSUP);
                }
                rflag::DEADLINE
            }
            attr::NOTIFY_EXC => {
                if deadline != 0 {
                    return Err(ENOTSUP);
                }
                rflag::PERTHR_LIMIT
            }
            _ => return Err(EINVAL),
        };
        self.dtask.cpuusage.policy_ru_cpu = policy;
        self.darwin_task_set_cpuusage(percentage, interval, deadline, scope, entitled);
        Ok(())
    }

    /// `task_set_cpuusage`: a per-thread limit (the monitor) configured,
    /// clamped to the system's caps unless entitled, and enabled; a
    /// task-wide limit or a deadline is refused loudly (neither the
    /// blocking ledger action nor the deadline's thread call is here).
    fn darwin_task_set_cpuusage(&mut self, mut percentage: u8, mut interval: u64, deadline: u64, scope: u32, entitled: bool) {
        if interval == 0 {
            interval = NSEC_PER_SEC;
        }
        if percentage != 0 {
            if scope == rflag::PERTHR_LIMIT {
                let mut warn = false;
                if percentage == CPUMON_DISABLE {
                    if entitled {
                        self.darwin_task_disable_cpumon();
                        return;
                    }
                    warn = true;
                    percentage = CPUMON_DEFAULTS;
                }
                if percentage == CPUMON_DEFAULTS {
                    percentage = MAX_CPUMON_PERCENTAGE;
                    interval = MAX_CPUMON_INTERVAL;
                }
                percentage = percentage.min(100);
                if interval == u64::MAX {
                    interval = if self.dtask.cpuusage.flags & rflag::PERTHR_LIMIT != 0 { self.dtask.cpuusage.perthr_interval } else { MAX_CPUMON_INTERVAL };
                }
                if percentage > MAX_CPUMON_PERCENTAGE && !entitled {
                    warn = true;
                    percentage = MAX_CPUMON_PERCENTAGE;
                }
                if interval > MAX_CPUMON_INTERVAL && !entitled {
                    warn = true;
                    interval = MAX_CPUMON_INTERVAL;
                }
                if warn {
                    eprintln!("process {}[{}] denied attempt to escape CPU monitor (missing required entitlement).", self.darwin_p_name_str(), self.pid);
                }
                self.dtask.cpuusage.perthr_percentage = percentage;
                self.dtask.cpuusage.perthr_interval = interval;
                self.darwin_task_enable_cpumon();
            } else if scope == rflag::PROC_LIMIT {
                self.darwin_unimplemented(format!("a task-wide CPU limit of {percentage}% over {interval} ns (the cpu_time ledger's blocking action)"));
            }
        }
        if deadline != 0 {
            self.darwin_unimplemented(format!("a CPU usage deadline of {deadline} ns (task_action_cpuusage's thread call)"));
        }
    }

    /// `task_enable_cpumon_locked`: the monitor on, each thread to take
    /// the limit as it next returns to its program (`act_set_astledger`).
    fn darwin_task_enable_cpumon(&mut self) -> bool {
        let u = &mut self.dtask.cpuusage;
        if u.perthr_percentage == 0 || u.perthr_interval == 0 {
            return false;
        }
        u.flags |= rflag::PERTHR_LIMIT;
        true
    }

    /// `task_suspend_cpumon`: the monitor (and its fatality) off, each
    /// thread to drop the limit; false where it was not on.
    fn darwin_task_suspend_cpumon(&mut self) -> bool {
        let u = &mut self.dtask.cpuusage;
        if u.flags & rflag::PERTHR_LIMIT == 0 {
            return false;
        }
        u.flags &= !(rflag::PERTHR_LIMIT | rflag::FATAL_CPUMON);
        true
    }

    /// `task_disable_cpumon`: suspended, and its parameters gone.
    fn darwin_task_disable_cpumon(&mut self) {
        if self.darwin_task_suspend_cpumon() {
            self.dtask.cpuusage.perthr_percentage = 0;
            self.dtask.cpuusage.perthr_interval = 0;
        }
    }

    /// `proc_get_task_ruse_cpu`: the policy of the limit in force (the
    /// monitor's NOTIFY_EXC, a task-wide limit's THROTTLE, a deadline's
    /// NONE), its percentage, interval (nanoseconds) and deadline.
    pub(crate) fn darwin_get_task_ruse_cpu(&self) -> (u32, u8, u64, u64) {
        let u = &self.dtask.cpuusage;
        if u.flags & rflag::PERTHR_LIMIT != 0 {
            (u32::from(attr::NOTIFY_EXC), u.perthr_percentage, u.perthr_interval, 0)
        } else if u.flags & rflag::PROC_LIMIT != 0 {
            (u32::from(attr::THROTTLE), u.percentage, u.interval, 0)
        } else if u.flags & rflag::DEADLINE != 0 {
            (u32::from(attr::NONE), 0, 0, u.deadline)
        } else {
            // No scope: the policy is left as the caller's zero.
            (0, 0, 0, 0)
        }
    }

    /// `thread_set_cpulimit(THREAD_CPULIMIT_EXCEPTION or DISABLE, ...)` for
    /// the calling thread: the ledger's limit (that share of the interval)
    /// and refill period set, its balance zeroed from now.
    fn darwin_thread_set_cpulimit(&mut self, enable: Option<(u8, u64)>) {
        let now = super::mach::absolute_time();
        let me = self.dtask.threads.map.entry(self.tid).or_default();
        match enable {
            None => {
                if let Some(l) = &mut me.cpu_ledger {
                    l.limit = LIMIT_INFINITY;
                    l.refill_scheduled = false;
                    l.called_back = false;
                    l.proc_cpulimit = false;
                }
            }
            Some((percentage, interval)) => {
                if interval < MINIMUM_CPULIMIT_INTERVAL {
                    return;
                }
                let l = me.cpu_ledger.get_or_insert_with(CpuLedger::default);
                l.limit = ns_to_abs(interval * u64::from(percentage) / 100) as i64;
                l.called_back = false;
                l.period = ns_to_abs(interval);
                l.last_refill = now;
                // ledger_zero_balance.
                l.debit = l.credit;
                l.refill_scheduled = true;
                l.proc_cpulimit = true;
            }
        }
    }

    /// The calling thread's CPU time ledger brought up to date as it
    /// returns to its program (its time since credited, then `ledger_ast`):
    /// its limit made the task's monitor's, or dropped with it; refilled
    /// when a period is due; over it, the monitor's callback, once.
    pub(crate) fn darwin_ledger_ast(&mut self) {
        let task = self.dtask.cpuusage;
        let tid = self.tid;
        let has_ledger = self.dtask.threads.map.get(&tid).is_some_and(|t| t.cpu_ledger.is_some());
        if task.flags & rflag::PERTHR_LIMIT == 0 && !has_ledger {
            return;
        }
        // The time it has run, credited.
        let Some(total) = self.darwin_thread_cpu_abs(tid) else {
            self.darwin_unimplemented("the CPU usage monitor on a host without per-thread clocks".into());
            return;
        };
        let now = super::mach::absolute_time();
        {
            let me = self.dtask.threads.map.entry(tid).or_default();
            let delta = total.saturating_sub(me.cpu_credited);
            me.cpu_credited = total;
            if let Some(l) = &mut me.cpu_ledger {
                l.credit += delta as i64;
                // ledger_entry_check_new_balance's refill.
                if l.refill_scheduled && now.wrapping_sub(l.last_refill) > l.period {
                    l.refill(now);
                }
            }
        }
        // ledger_ast: the thread's limit kept the task's.
        let me = self.dtask.threads.map.entry(tid).or_default();
        let current = me.cpu_ledger.filter(|l| l.limit != LIMIT_INFINITY && l.period != 0).map(|l| {
            let pct = (abs_to_ns(l.limit as u64) * 100 / abs_to_ns(l.period)) as u8;
            (pct, abs_to_ns(l.period), l.proc_cpulimit)
        });
        if task.flags & rflag::PERTHR_LIMIT != 0 {
            let up_to_date = current.is_some_and(|(p, i, proc)| proc && p == task.perthr_percentage && i == task.perthr_interval);
            if !up_to_date {
                self.darwin_thread_set_cpulimit(Some((task.perthr_percentage, task.perthr_interval)));
            }
        } else if current.is_some_and(|(_, _, proc)| proc) {
            self.darwin_thread_set_cpulimit(None);
        }
        // ledger_check_needblock: over the limit, a refill if one is due,
        // then the callback (the monitor's ledger acts by callback alone).
        let me = self.dtask.threads.map.entry(tid).or_default();
        let Some(l) = &mut me.cpu_ledger else { return };
        if !l.exceeded() {
            return;
        }
        if l.refill_scheduled && l.last_refill + l.period <= now {
            l.refill(now);
            if !l.exceeded() {
                return;
            }
        }
        if std::mem::replace(&mut l.called_back, true) {
            return;
        }
        self.darwin_cpu_monitor_violation();
    }

    /// `p_name`, as printf's `%s` prints it.
    fn darwin_p_name_str(&self) -> String {
        let n = &self.dtask.p_name.0;
        String::from_utf8_lossy(&n[..n.iter().position(|&b| b == 0).unwrap_or(n.len())]).into_owned()
    }

    /// The thread's user and system time in Mach time units.
    fn darwin_thread_cpu_abs(&self, tid: i32) -> Option<u64> {
        let (u, s) = self.thread_signals.get(tid)?.cpu.times()?;
        Some(ns_to_abs(u + s))
    }

    /// `SENDING_NOTIFICATION__THIS_THREAD_IS_CONSUMING_TOO_MUCH_CPU`: the
    /// monitor suspended (the first thread over it reports; others find it
    /// off), the kernel's report, the RESOURCE_NOTIFY message to the host's
    /// resource notify port, the EXC_RESOURCE exception, and for a fatal
    /// monitor, jetsam's kill.
    fn darwin_cpu_monitor_violation(&mut self) {
        let fatal = self.dtask.cpuusage.flags & rflag::FATAL_CPUMON != 0;
        if !self.darwin_task_suspend_cpumon() {
            return;
        }
        let tid = self.tid;
        let Some(l) = self.dtask.threads.map.get(&tid).and_then(|t| t.cpu_ledger) else { return };
        let (percentage, interval_ns) = ((abs_to_ns(l.limit as u64) * 100 / abs_to_ns(l.period)) as u8, abs_to_ns(l.period));
        let interval_sec = (interval_ns / NSEC_PER_SEC) as u32;
        let (user, sys) = self.thread_signals.get(tid).and_then(|t| t.cpu.times()).unwrap_or((0, 0));
        let now = super::mach::absolute_time();
        let balance_ns = abs_to_ns(l.balance().max(0) as u64);
        let last_refill_ns = abs_to_ns(now.saturating_sub(l.last_refill));
        let usage_percent = if last_refill_ns > 0 { (balance_ns * 100 / last_refill_ns) as u32 } else { 0 };
        let thread_id = self.thread_signals.get(tid).map_or(0, |t| t.darwin_id());
        let name = self.darwin_p_name_str();
        let tv = |ns: u64| format!("{}.{:06}", ns / NSEC_PER_SEC, ns % NSEC_PER_SEC / 1000);
        eprintln!("process {name}[{}] thread {thread_id} caught burning CPU! It used more than {percentage}% CPU over {interval_sec} seconds", self.pid);
        eprintln!("  (actual recent usage: {usage_percent}% over ~{} seconds)", (last_refill_ns + NSEC_PER_SEC / 2) / NSEC_PER_SEC);
        eprintln!("  Thread lifetime cpu usage {}s, ({} user, {} sys)", tv(user + sys), tv(user), tv(sys));
        eprintln!("  Ledger balance: {}; mabs credit: {}; mabs debit: {}", l.balance(), l.credit, l.debit);
        eprintln!("  mabs limit: {}; mabs period: {} ns; last refill: {last_refill_ns} ns{}.", l.limit, interval_ns, if fatal { " [fatal violation]" } else { "" });
        // send_resource_violation: host_get_special_port's
        // HOST_RESOURCE_NOTIFY_PORT, which no task here can have set
        // (host_set_special_port), so the send has no destination.
        const MACH_SEND_INVALID_DEST: u32 = 0x1000_0003;
        eprintln!("send_resource_violation(CPU usage, ...): error {MACH_SEND_INVALID_DEST:#x}");
        // exception_triage(EXC_RESOURCE, code): with no handler but the
        // kernel's, nothing (EXC_RESOURCE is no signal).
        if self.darwin_exc_handled(super::exception::EXC_RESOURCE) {
            let mut code0 = 1u64 << 61 | (if fatal { 2u64 } else { 1 }) << 58;
            code0 |= (u64::from(interval_sec) & 0x1ff_ffff) << 7 | u64::from(percentage) & 0x7f;
            let code1 = u64::from(usage_percent) & 0x7f;
            self.darwin_unimplemented(format!("sending EXC_RESOURCE (CPU monitor, codes {code0:#x} {code1:#x}) to its exception handler (exception_triage)"));
        }
        if fatal {
            self.darwin_unimplemented("jetsam's kill for a fatal CPU monitor violation (jetsam_on_ledger_cpulimit_exceeded)".into());
        }
    }
}
