//! A task's policy (`osfmk/kern/task_policy.c`): what was asked of it (its
//! requested policy: app type, role, QoS clamp, throttles), what follows
//! from that (its effective policy and its priority range), and how a new
//! task, an exec and a spawn's attributes set it. Its threads' effective QoS
//! and base priority follow from it (`thread_policy.c`).
//!
//! The effects outside the task (SFI, coalitions, sockets, timers, I/O
//! throttling, the importance subsystem's donations) have nothing here to
//! act on yet; their inputs are kept as XNU computes them.

use super::workq::qos;

/// `TASK_APPTYPE_*`.
pub mod apptype {
    pub const NONE: u8 = 0;
    pub const DAEMON_INTERACTIVE: u8 = 1;
    pub const DAEMON_STANDARD: u8 = 2;
    pub const DAEMON_ADAPTIVE: u8 = 3;
    pub const DAEMON_BACKGROUND: u8 = 4;
    pub const APP_DEFAULT: u8 = 5;
    pub const APP_TAL: u8 = 6;
    pub const DRIVER: u8 = 7;
}

/// `task_role_t` (TASK_RENICED, -1, is never a requested role).
pub mod role {
    pub const UNSPECIFIED: u8 = 0;
    pub const FOREGROUND_APPLICATION: u8 = 1;
    pub const BACKGROUND_APPLICATION: u8 = 2;
    pub const CONTROL_APPLICATION: u8 = 3;
    pub const GRAPHICS_SERVER: u8 = 4;
    pub const THROTTLE_APPLICATION: u8 = 5;
    pub const NONUI_APPLICATION: u8 = 6;
    pub const DEFAULT_APPLICATION: u8 = 7;
    pub const DARWINBG_APPLICATION: u8 = 8;
}

/// `osfmk/kern/sched.h`.
pub mod pri {
    pub const MINPRI: i32 = 0;
    pub const MAXPRI: i32 = 127;
    pub const MAXPRI_THROTTLE: i32 = 4;
    pub const BASEPRI_UTILITY: i32 = 20;
    pub const MAXPRI_SUPPRESSED: i32 = 28;
    pub const BASEPRI_DEFAULT: i32 = 31;
    pub const BASEPRI_USER_INITIATED: i32 = 37;
    pub const BASEPRI_BACKGROUND: i32 = 46;
    pub const BASEPRI_CONTROL: i32 = 48;
    pub const MAXPRI_USER: i32 = 63;
    pub const BASEPRI_GRAPHICS: i32 = 76;
    pub const MAXPRI_RESERVED: i32 = 79;
}

/// `THROTTLE_LEVEL_TIER*`.
const TIER0: u8 = 0;
const TIER1: u8 = 1;
const TIER2: u8 = 2;
const TIER3: u8 = 3;

/// `proc_default_bg_iotier`, `proc_standard_daemon_tier`,
/// `proc_suppressed_disk_tier`, `proc_graphics_timer_qos`
/// (`LATENCY_QOS_TIER_0 & 0xFF`).
const DEFAULT_BG_IOTIER: u8 = TIER2;
const STANDARD_DAEMON_TIER: u8 = TIER1;
const SUPPRESSED_DISK_TIER: u8 = TIER1;
const GRAPHICS_TIMER_QOS: u8 = 1;

/// `thread_qos_policy_params`, by thread QoS: the base priority, the I/O
/// tier, and the throughput and latency QoS tiers (`QOS_EXTRACT`ed).
pub const QOS_PRI: [i32; 7] = [0, pri::MAXPRI_THROTTLE, pri::MAXPRI_THROTTLE, pri::BASEPRI_UTILITY, pri::BASEPRI_DEFAULT, pri::BASEPRI_USER_INITIATED, pri::BASEPRI_BACKGROUND];
const QOS_IOTIER: [u8; 7] = [TIER0, TIER3, TIER2, TIER1, TIER0, TIER0, TIER0];
const QOS_THROUGH: [u8; 7] = [0, 6, 6, 3, 2, 2, 1];
const QOS_LATENCY: [u8; 7] = [0, 4, 4, 4, 2, 2, 1];

/// `struct task_requested_policy`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Requested {
    pub int_darwinbg: bool,
    pub ext_darwinbg: bool,
    pub int_iotier: u8,
    pub ext_iotier: u8,
    pub int_iopassive: bool,
    pub ext_iopassive: bool,
    pub bg_iotier: u8,
    pub terminated: bool,
    pub base_latency_qos: u8,
    pub base_through_qos: u8,
    pub apptype: u8,
    pub boosted: bool,
    pub role: u8,
    pub over_latency_qos: u8,
    pub over_through_qos: u8,
    pub sfi_managed: bool,
    pub qos_clamp: u8,
    pub sup_active: bool,
    pub sup_lowpri_cpu: bool,
    pub sup_timer: u8,
    pub sup_disk: bool,
    pub sup_throughput: u8,
    pub sup_cpu: bool,
    pub sup_bg_sockets: bool,
}

/// `struct task_effective_policy`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Effective {
    pub darwinbg: bool,
    pub lowpri_cpu: bool,
    pub io_tier: u8,
    pub io_passive: bool,
    pub all_sockets_bg: bool,
    pub new_sockets_bg: bool,
    pub bg_iotier: u8,
    pub terminated: bool,
    pub qos_ui_is_urgent: bool,
    pub latency_qos: u8,
    pub through_qos: u8,
    pub tal_engaged: bool,
    pub watchers_bg: bool,
    pub sup_active: bool,
    pub role: u8,
    pub suppressed_cpu: bool,
    pub sfi_managed: bool,
    pub live_donor: bool,
    pub qos_clamp: u8,
    pub qos_ceiling: u8,
    pub adaptive_bg: bool,
}

/// The importance subsystem's marks on a task (`task_importance_mark_*`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Importance {
    pub donor: bool,
    pub live_donor: bool,
    pub receiver: bool,
    pub denap_receiver: bool,
}

/// A task's policy, and its priority range (`task->priority`,
/// `task->max_priority`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskPolicy {
    pub requested: Requested,
    pub effective: Effective,
    pub priority: i32,
    pub max_priority: i32,
    /// `task->importance`: the nice value's part of its priority.
    pub importance: i32,
    pub imp: Importance,
    /// `task_set_gpu_denied` and `task_set_game_mode`.
    pub gpu_denied: bool,
    pub game_mode: bool,
}

impl Default for TaskPolicy {
    /// `default_task_requested_policy` and `default_task_effective_policy`,
    /// at a user task's priority (`task_create_internal`).
    fn default() -> TaskPolicy {
        TaskPolicy {
            requested: Requested { bg_iotier: DEFAULT_BG_IOTIER, ..Default::default() },
            effective: Effective::default(),
            priority: pri::BASEPRI_DEFAULT,
            max_priority: pri::MAXPRI_USER,
            importance: 0,
            imp: Importance::default(),
            gpu_denied: false,
            game_mode: false,
        }
    }
}

impl TaskPolicy {
    /// `task_policy_create`: a new task's policy, from its parent's (an exec
    /// copy's, `exec`, keeps an adaptive daemon adaptive).
    pub fn create(parent: &TaskPolicy, exec: bool) -> TaskPolicy {
        let mut t = TaskPolicy::default();
        let p = parent.requested;
        let r = &mut t.requested;
        r.apptype = p.apptype;
        r.int_darwinbg = p.int_darwinbg;
        r.ext_darwinbg = p.ext_darwinbg;
        r.int_iotier = p.int_iotier;
        r.ext_iotier = p.ext_iotier;
        r.int_iopassive = p.int_iopassive;
        r.ext_iopassive = p.ext_iopassive;
        r.bg_iotier = p.bg_iotier;
        r.terminated = p.terminated;
        r.qos_clamp = p.qos_clamp;
        if r.apptype == apptype::DAEMON_ADAPTIVE && !exec {
            if p.boosted {
                r.apptype = apptype::DAEMON_INTERACTIVE;
                t.imp.donor = true;
            } else {
                r.apptype = apptype::DAEMON_BACKGROUND;
                t.imp.receiver = false;
            }
        }
        t.update(true);
        t.update_live_donor();
        t
    }

    /// `task_importance_update_live_donor`: a live donor donates as its
    /// effective policy says.
    fn update_live_donor(&mut self) {
        if self.imp.live_donor {
            self.imp.donor = self.effective.live_donor;
        }
    }

    /// `proc_set_task_spawnpolicy` without port watching: the app type's
    /// importance marks, the app type, the role (on embedded, an app given
    /// none is foreground) and the QoS clamp.
    pub fn spawnpolicy(&mut self, apptype: u8, qos_clamp: u8, role: u8) {
        if apptype != apptype::NONE {
            self.imp.receiver = false;
            self.imp.denap_receiver = false;
        }
        let imp = &mut self.imp;
        match apptype {
            apptype::APP_DEFAULT => {
                imp.donor = false;
                imp.live_donor = true;
            }
            // ipc_importance_interactive_receiver: false unless a boot-arg.
            apptype::DAEMON_INTERACTIVE => {
                imp.donor = true;
                imp.live_donor = false;
                imp.receiver = false;
            }
            apptype::DAEMON_STANDARD => {
                imp.donor = true;
                imp.live_donor = false;
            }
            apptype::DAEMON_ADAPTIVE => {
                imp.donor = false;
                imp.live_donor = false;
                imp.receiver = true;
            }
            apptype::DAEMON_BACKGROUND | apptype::DRIVER => {
                imp.donor = false;
                imp.live_donor = false;
            }
            _ => {}
        }
        if apptype != apptype::NONE {
            self.requested.apptype = apptype;
        }
        if apptype == apptype::APP_DEFAULT && role == role::UNSPECIFIED {
            self.requested.role = role::FOREGROUND_APPLICATION;
        } else if role != role::UNSPECIFIED {
            self.requested.role = role;
        }
        if qos_clamp != qos::UNSPECIFIED {
            self.requested.qos_clamp = qos_clamp;
        }
        self.update(false);
        self.update_live_donor();
    }

    /// `task_importance` (the nice value's, `-p_nice`): refused for a task
    /// whose effective role is a control application or above.
    pub fn set_importance(&mut self, importance: i32) -> bool {
        if self.effective.role >= role::CONTROL_APPLICATION {
            return false;
        }
        self.importance = importance;
        self.update(false);
        true
    }

    /// `proc_set_task_policy(TASK_POLICY_DARWIN_BG)`, from the task itself
    /// (internal) or another (external).
    pub fn set_darwinbg(&mut self, external: bool, on: bool) {
        if external {
            self.requested.ext_darwinbg = on;
        } else {
            self.requested.int_darwinbg = on;
        }
        self.update(false);
    }

    /// `proc_set_task_policy(TASK_POLICY_ROLE)`.
    pub fn set_role(&mut self, r: u8) {
        self.requested.role = r;
        self.update(false);
    }

    /// `task_is_app`.
    pub fn is_app(&self) -> bool {
        matches!(self.requested.apptype, apptype::APP_DEFAULT | apptype::APP_TAL)
    }

    /// `task_compute_main_thread_qos`: by the app type (at least
    /// user-initiated for pid 1), within the QoS clamp.
    pub fn main_thread_qos(&self, init: bool) -> u8 {
        let mut q = match self.requested.apptype {
            apptype::APP_TAL | apptype::APP_DEFAULT => qos::USER_INTERACTIVE,
            apptype::DAEMON_INTERACTIVE | apptype::DAEMON_STANDARD | apptype::DAEMON_ADAPTIVE | apptype::DRIVER => qos::LEGACY,
            apptype::DAEMON_BACKGROUND => qos::BACKGROUND,
            _ => qos::UNSPECIFIED,
        };
        if init {
            q = q.max(qos::USER_INITIATED);
        }
        let clamp = self.requested.qos_clamp;
        if clamp != qos::UNSPECIFIED {
            q = if q != qos::UNSPECIFIED { clamp.min(q) } else { clamp };
        }
        q
    }

    /// `task_policy_update_internal_locked`: the effective policy from the
    /// requested; for a task past creation, its priority range too.
    pub fn update(&mut self, in_create: bool) {
        let r = self.requested;
        let mut next = Effective { role: r.role, ..Default::default() };
        let mut role_clamp = qos::UNSPECIFIED;
        if r.apptype == apptype::APP_DEFAULT {
            match next.role {
                role::FOREGROUND_APPLICATION | role::CONTROL_APPLICATION | role::GRAPHICS_SERVER => {
                    next.qos_ui_is_urgent = true;
                    next.qos_ceiling = qos::UNSPECIFIED;
                }
                role::BACKGROUND_APPLICATION | role::DEFAULT_APPLICATION => next.qos_ceiling = qos::UNSPECIFIED,
                role::NONUI_APPLICATION => next.qos_ceiling = qos::LEGACY,
                role::THROTTLE_APPLICATION => {
                    next.qos_ceiling = qos::UTILITY;
                    role_clamp = qos::UTILITY;
                }
                role::DARWINBG_APPLICATION => next.qos_ceiling = qos::BACKGROUND,
                _ => next.qos_ceiling = qos::LEGACY,
            }
        } else {
            next.qos_ceiling = qos::USER_INITIATED;
        }
        next.qos_clamp = if role_clamp != qos::UNSPECIFIED {
            if r.qos_clamp != qos::UNSPECIFIED { role_clamp.min(r.qos_clamp) } else { role_clamp }
        } else {
            r.qos_clamp
        };

        let mut wants_darwinbg = false;
        let mut wants_all_sockets_bg = false;
        let mut wants_watchersbg = false;
        let mut adaptive_bg_only = false;
        if r.apptype == apptype::DAEMON_ADAPTIVE && !r.boosted {
            wants_darwinbg = true;
            adaptive_bg_only = true;
        }
        if r.int_darwinbg || r.ext_darwinbg || next.role == role::DARWINBG_APPLICATION {
            wants_watchersbg = true;
            wants_all_sockets_bg = true;
            wants_darwinbg = true;
            adaptive_bg_only = false;
        }
        if r.apptype == apptype::APP_DEFAULT && r.role == role::THROTTLE_APPLICATION {
            next.tal_engaged = true;
        }
        if r.apptype == apptype::DAEMON_BACKGROUND {
            wants_darwinbg = true;
            adaptive_bg_only = false;
        }
        if next.qos_clamp == qos::BACKGROUND || next.qos_clamp == qos::MAINTENANCE {
            wants_darwinbg = true;
            adaptive_bg_only = false;
        }
        if wants_darwinbg {
            next.darwinbg = true;
            next.new_sockets_bg = true;
            next.lowpri_cpu = true;
        }
        if wants_all_sockets_bg {
            next.all_sockets_bg = true;
        }
        if wants_watchersbg {
            next.watchers_bg = true;
        }
        next.adaptive_bg = adaptive_bg_only;
        if wants_darwinbg || (r.sup_lowpri_cpu && !r.boosted) {
            next.lowpri_cpu = true;
        }

        next.bg_iotier = r.bg_iotier;
        let mut iopol = TIER0;
        if wants_darwinbg {
            iopol = iopol.max(r.bg_iotier);
        }
        if r.apptype == apptype::DAEMON_STANDARD {
            iopol = iopol.max(STANDARD_DAEMON_TIER);
        }
        if r.sup_disk && !r.boosted {
            iopol = iopol.max(SUPPRESSED_DISK_TIER);
        }
        if next.qos_clamp != qos::UNSPECIFIED {
            iopol = iopol.max(QOS_IOTIER[next.qos_clamp as usize]);
        }
        iopol = iopol.max(r.int_iotier).max(r.ext_iotier);
        next.io_tier = iopol;
        if r.ext_iopassive || r.int_iopassive {
            next.io_passive = true;
        }
        if r.sup_active && !r.boosted {
            next.sup_active = true;
        }

        let mut latency = r.base_latency_qos;
        if r.sup_timer != 0 && !r.boosted {
            latency = r.sup_timer;
        }
        if next.qos_clamp != qos::UNSPECIFIED {
            latency = latency.max(QOS_LATENCY[next.qos_clamp as usize]);
        }
        if r.over_latency_qos != 0 {
            latency = r.over_latency_qos;
        }
        if r.role == role::GRAPHICS_SERVER {
            latency = GRAPHICS_TIMER_QOS;
        }
        next.latency_qos = latency;
        let mut through = r.base_through_qos;
        if r.sup_throughput != 0 && !r.boosted {
            through = r.sup_throughput;
        }
        if next.qos_clamp != qos::UNSPECIFIED {
            through = through.max(QOS_THROUGH[next.qos_clamp as usize]);
        }
        if r.over_through_qos != 0 {
            through = r.over_through_qos;
        }
        next.through_qos = through;
        if r.sup_cpu && !r.boosted {
            next.suppressed_cpu = true;
        }
        if r.sup_bg_sockets {
            next.all_sockets_bg = true;
            next.new_sockets_bg = true;
        }
        next.sfi_managed = r.sfi_managed;
        // task_policy_suppression_flags holds TASK_POLICY_SUPPRESSION_NONDONOR
        // by default: suppression makes an app no live donor.
        next.live_donor = matches!(r.apptype, apptype::APP_TAL | apptype::APP_DEFAULT) && !(r.ext_darwinbg || next.sup_active || next.role == role::DARWINBG_APPLICATION);
        if r.terminated {
            next.terminated = true;
            next.darwinbg = false;
            next.lowpri_cpu = false;
            next.io_tier = TIER0;
            next.tal_engaged = false;
            next.role = role::UNSPECIFIED;
            next.suppressed_cpu = false;
        }
        self.effective = next;
        if in_create {
            return;
        }

        // The task's priority range, from the policy just swapped in.
        let (mut priority, mut max_priority) = (pri::BASEPRI_DEFAULT, pri::MAXPRI_USER);
        if next.lowpri_cpu {
            priority = pri::MAXPRI_THROTTLE;
            max_priority = pri::MAXPRI_THROTTLE;
        } else if next.suppressed_cpu {
            priority = pri::MAXPRI_SUPPRESSED;
            max_priority = pri::MAXPRI_SUPPRESSED;
        } else {
            match next.role {
                role::CONTROL_APPLICATION => priority = pri::BASEPRI_CONTROL,
                role::GRAPHICS_SERVER => {
                    priority = pri::BASEPRI_GRAPHICS;
                    max_priority = pri::MAXPRI_RESERVED;
                }
                _ => {}
            }
            priority += self.importance;
            if self.effective.qos_clamp != qos::UNSPECIFIED {
                let clamp_pri = QOS_PRI[self.effective.qos_clamp as usize];
                priority = priority.min(clamp_pri);
                max_priority = max_priority.min(clamp_pri);
            }
            priority = priority.clamp(pri::MINPRI, max_priority);
        }
        self.priority = priority;
        self.max_priority = max_priority;
    }
}

/// `task_policy_flavor_t`s.
pub mod flavor {
    pub const CATEGORY_POLICY: i32 = 1;
    pub const SUPPRESSION_POLICY: i32 = 3;
    pub const POLICY_STATE: i32 = 4;
    pub const BASE_QOS_POLICY: i32 = 8;
    pub const OVERRIDE_QOS_POLICY: i32 = 9;
    pub const BASE_LATENCY_QOS_POLICY: i32 = 10;
    pub const BASE_THROUGHPUT_QOS_POLICY: i32 = 11;
}

/// The flavors' counts, in `integer_t`s.
const CATEGORY_POLICY_COUNT: u32 = 1;
const QOS_POLICY_COUNT: u32 = 2;
const SUPPRESSION_POLICY_COUNT: u32 = 16;
const POLICY_STATE_COUNT: u32 = 16;

/// `kern_return_t`s.
const KERN_PROTECTION_FAILURE: i32 = 2;
const KERN_INVALID_ARGUMENT: i32 = 4;

/// `LATENCY_QOS_TIER_*` and `THROUGHPUT_QOS_TIER_*` (0 is unspecified).
const LATENCY_TIER: u32 = 0xFF << 16;
const THROUGHPUT_TIER: u32 = 0xFE << 16;

/// `qos_latency_policy_validate` and `qos_throughput_policy_validate`.
fn tier_valid(t: u32, base: u32) -> bool {
    t == 0 || (base | 1..=base | 6).contains(&t)
}

/// `task_qos_policy_validate`.
fn qos_policy_validate(info: &[i32]) -> Result<(u8, u8), i32> {
    if (info.len() as u32) < QOS_POLICY_COUNT {
        return Err(KERN_INVALID_ARGUMENT);
    }
    let (l, t) = (info[0] as u32, info[1] as u32);
    if !tier_valid(l, LATENCY_TIER) || !tier_valid(t, THROUGHPUT_TIER) {
        return Err(KERN_INVALID_ARGUMENT);
    }
    // qos_extract
    Ok(((l & 0xFF) as u8, (t & 0xFF) as u8))
}

/// `qos_latency_policy_package` and `qos_throughput_policy_package`.
fn package(v: u8, base: u32) -> i32 {
    if v == 0 { 0 } else { (base | u32::from(v)) as i32 }
}

impl TaskPolicy {
    /// `task_policy_set` on the caller's own task (`self_task`), which on
    /// embedded may not set its own role.
    pub fn set(&mut self, flavor: i32, info: &[i32], self_task: bool) -> i32 {
        match flavor {
            flavor::CATEGORY_POLICY => {
                if (info.len() as u32) < CATEGORY_POLICY_COUNT || self_task {
                    return KERN_INVALID_ARGUMENT;
                }
                match info[0] {
                    1 | 2 | 7 => {
                        self.requested.role = info[0] as u8;
                        self.update(false);
                        0
                    }
                    // CONTROL_APPLICATION and GRAPHICS_SERVER only for the
                    // caller's own privileged task.
                    _ => KERN_INVALID_ARGUMENT,
                }
            }
            flavor::BASE_QOS_POLICY | flavor::OVERRIDE_QOS_POLICY => match qos_policy_validate(info) {
                Ok((l, t)) => {
                    if flavor == flavor::BASE_QOS_POLICY {
                        self.requested.base_latency_qos = l;
                        self.requested.base_through_qos = t;
                    } else {
                        self.requested.over_latency_qos = l;
                        self.requested.over_through_qos = t;
                    }
                    self.update(false);
                    0
                }
                Err(e) => e,
            },
            flavor::BASE_LATENCY_QOS_POLICY | flavor::BASE_THROUGHPUT_QOS_POLICY => match qos_policy_validate(info) {
                Ok((l, t)) => {
                    if flavor == flavor::BASE_LATENCY_QOS_POLICY {
                        self.requested.base_latency_qos = l;
                    } else {
                        self.requested.base_through_qos = t;
                    }
                    self.update(false);
                    0
                }
                Err(e) => e,
            },
            // Not enabled on embedded: apps are not de-nap receivers.
            flavor::SUPPRESSION_POLICY => KERN_INVALID_ARGUMENT,
            _ => KERN_INVALID_ARGUMENT,
        }
    }

    /// `task_policy_get`: the flavor's words (`count` of them, as asked),
    /// or the error. `privileged`: the caller's euid is 0
    /// (`task_is_privileged`). `None` for what needs the importance
    /// subsystem.
    pub fn get(&self, flavor: i32, count: u32, get_default: bool, privileged: bool) -> Option<Result<Vec<i32>, i32>> {
        let mut out = vec![0i32; count as usize];
        match flavor {
            flavor::CATEGORY_POLICY => {
                if count < CATEGORY_POLICY_COUNT {
                    return Some(Err(KERN_INVALID_ARGUMENT));
                }
                out[0] = if get_default { 0 } else { i32::from(self.requested.role) };
            }
            flavor::BASE_QOS_POLICY | flavor::OVERRIDE_QOS_POLICY => {
                if count < QOS_POLICY_COUNT {
                    return Some(Err(KERN_INVALID_ARGUMENT));
                }
                if !get_default {
                    let r = &self.requested;
                    let (l, t) = if flavor == flavor::BASE_QOS_POLICY { (r.base_latency_qos, r.base_through_qos) } else { (r.over_latency_qos, r.over_through_qos) };
                    out[0] = package(l, LATENCY_TIER);
                    out[1] = package(t, THROUGHPUT_TIER);
                }
            }
            flavor::POLICY_STATE => {
                if count < POLICY_STATE_COUNT {
                    return Some(Err(KERN_INVALID_ARGUMENT));
                }
                if !privileged {
                    return Some(Err(KERN_PROTECTION_FAILURE));
                }
                if !get_default {
                    return None;
                }
            }
            flavor::SUPPRESSION_POLICY => {
                if count < SUPPRESSION_POLICY_COUNT {
                    return Some(Err(KERN_INVALID_ARGUMENT));
                }
                if !get_default {
                    let r = &self.requested;
                    out[0] = i32::from(r.sup_active);
                    out[1] = i32::from(r.sup_lowpri_cpu);
                    out[2] = package(r.sup_timer, LATENCY_TIER);
                    out[3] = i32::from(r.sup_disk);
                    out[6] = package(r.sup_throughput, THROUGHPUT_TIER);
                    out[7] = i32::from(r.sup_cpu);
                    out[8] = i32::from(r.sup_bg_sockets);
                }
            }
            _ => return Some(Err(KERN_INVALID_ARGUMENT)),
        }
        Some(Ok(out))
    }
}

/// `proc_task_role_to_darwin_role`.
pub fn task_role_to_darwin_role(r: u8) -> i32 {
    match r {
        role::FOREGROUND_APPLICATION => 1,
        role::BACKGROUND_APPLICATION => 4,
        role::NONUI_APPLICATION => 3,
        role::DEFAULT_APPLICATION => 2,
        role::THROTTLE_APPLICATION => 5,
        role::DARWINBG_APPLICATION => 6,
        _ => 0,
    }
}

/// `proc_darwin_role_to_task_role`: a `PRIO_DARWIN_ROLE_*` as a task role,
/// `None` for one that is not.
pub fn darwin_role_to_task_role(r: u32) -> Option<u8> {
    Some(match r {
        0 => role::UNSPECIFIED,
        1 => role::FOREGROUND_APPLICATION,
        2 => role::DEFAULT_APPLICATION,
        3 => role::NONUI_APPLICATION,
        4 => role::BACKGROUND_APPLICATION,
        5 => role::THROTTLE_APPLICATION,
        6 => role::DARWINBG_APPLICATION,
        _ => return None,
    })
}

/// `exec_handle_spawnattr_policy`'s reading of a spawn's attributes: the
/// app type (`POSIX_SPAWN_PROC_TYPE_*`; an unknown one is none), the QoS
/// clamp (`POSIX_SPAWN_PROC_CLAMP_*`; an unknown one is none) and the role
/// (an unknown one is unspecified).
pub fn spawn_attrs(psa_apptype: u32, psa_qos_clamp: u64, psa_darwin_role: u32) -> (u8, u8, u8) {
    let ty = match psa_apptype & 0xf00 {
        0x400 => apptype::DAEMON_INTERACTIVE,
        0x300 => apptype::DAEMON_STANDARD,
        0x600 => apptype::DAEMON_ADAPTIVE,
        0x500 => apptype::DAEMON_BACKGROUND,
        0x100 => apptype::APP_DEFAULT,
        0x700 => apptype::DRIVER,
        _ => apptype::NONE,
    };
    let clamp = match psa_qos_clamp {
        1 => qos::UTILITY,
        2 => qos::BACKGROUND,
        3 => qos::MAINTENANCE,
        _ => qos::UNSPECIFIED,
    };
    let role = if psa_darwin_role != 0 { darwin_role_to_task_role(psa_darwin_role).unwrap_or(role::UNSPECIFIED) } else { role::UNSPECIFIED };
    (ty, clamp, role)
}

/// A thread's effective QoS policy, as `thread_policy_update_internal_
/// spinlocked` makes it from its requested QoS, the highest of its
/// overrides, and its task's effective policy: (QoS, relative priority as
/// requested (0 to -15), UI urgent, terminated).
pub fn thread_effective_qos(req_qos: u8, req_relpri: i32, overrides: u8, thread_darwinbg: bool, task: &Effective) -> (u8, i32, bool, bool) {
    let mut q = req_qos;
    if req_qos != qos::UNSPECIFIED {
        q = q.max(overrides);
    }
    if task.qos_clamp != qos::UNSPECIFIED {
        q = if q != qos::UNSPECIFIED { task.qos_clamp.min(q) } else { task.qos_clamp };
    }
    if task.qos_ceiling != qos::UNSPECIFIED && q != qos::UNSPECIFIED {
        q = task.qos_ceiling.min(q);
    }
    let mut relpri = if req_qos != qos::UNSPECIFIED && req_qos == q && overrides == qos::UNSPECIFIED { req_relpri } else { 0 };
    let darwinbg = task.darwinbg || thread_darwinbg || q == qos::BACKGROUND || q == qos::MAINTENANCE;
    if darwinbg && (q > qos::BACKGROUND || q == qos::UNSPECIFIED) {
        q = qos::BACKGROUND;
        relpri = 0;
    }
    if task.terminated {
        q = qos::UNSPECIFIED;
    }
    (q, relpri, task.qos_ui_is_urgent, task.terminated)
}

/// A thread's effective DARWIN_BG (`thep_darwinbg`): its task's, any it
/// requested, or a background or maintenance effective QoS (its requested
/// QoS and overrides under its task's clamp and ceiling); none once its
/// task is terminated.
pub fn thread_effective_darwinbg(req_qos: u8, overrides: u8, thread_darwinbg: bool, task: &Effective) -> bool {
    let mut q = req_qos;
    if req_qos != qos::UNSPECIFIED {
        q = q.max(overrides);
    }
    if task.qos_clamp != qos::UNSPECIFIED {
        q = if q != qos::UNSPECIFIED { task.qos_clamp.min(q) } else { task.qos_clamp };
    }
    if task.qos_ceiling != qos::UNSPECIFIED && q != qos::UNSPECIFIED {
        q = task.qos_ceiling.min(q);
    }
    let darwinbg = task.darwinbg || thread_darwinbg || q == qos::BACKGROUND || q == qos::MAINTENANCE;
    darwinbg && !task.terminated
}

/// `thread_qos_scaled_relative_priority`: a relative priority (0 to -15)
/// scaled into the band between a QoS's priority and the next lower one's.
fn scaled_relpri(q: u8, relpri: i32) -> i32 {
    if relpri == 0 {
        return 0;
    }
    let lower = match q {
        qos::USER_INTERACTIVE => qos::USER_INITIATED,
        qos::USER_INITIATED => qos::LEGACY,
        qos::LEGACY => qos::UTILITY,
        qos::UTILITY => qos::BACKGROUND,
        _ => 0,
    };
    let prio_range_max = QOS_PRI[q as usize];
    let prio_range_min = if lower != 0 { QOS_PRI[lower as usize] } else { 0 };
    -(((prio_range_max - prio_range_min) * -relpri) >> 4)
}

/// `thread_recompute_priority` for a thread out of the realtime and
/// work-interval worlds: from its effective QoS (scaled relative priority,
/// UI urgency) or else its precedence importance on its task's priority,
/// within its task's range, and on embedded never below MAXPRI_THROTTLE.
pub fn thread_base_priority(eff_qos: u8, relpri: i32, ui_urgent: bool, terminated: bool, importance: i32, task: &TaskPolicy) -> i32 {
    let mut priority = if eff_qos != qos::UNSPECIFIED {
        let mut s = scaled_relpri(eff_qos, relpri);
        if eff_qos == qos::USER_INTERACTIVE && ui_urgent {
            s += 1;
        }
        QOS_PRI[eff_qos as usize] + s
    } else {
        importance.clamp(-pri::MAXPRI, pri::MAXPRI) + task.priority
    };
    priority = priority.min(task.max_priority).max(pri::MINPRI);
    if terminated {
        priority = priority.max(task.priority).max(pri::BASEPRI_DEFAULT);
    }
    priority.max(pri::MAXPRI_THROTTLE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spawned(apptype: u8, clamp: u8, role: u8) -> TaskPolicy {
        let mut t = TaskPolicy::create(&TaskPolicy::default(), false);
        t.spawnpolicy(apptype, clamp, role);
        t
    }

    #[test]
    fn a_new_task_keeps_its_priority_until_its_policy_is_updated() {
        let mut parent = TaskPolicy::default();
        parent.requested.qos_clamp = qos::BACKGROUND;
        let t = TaskPolicy::create(&parent, false);
        // task_policy_create updates in creation: the range is untouched.
        assert_eq!((t.priority, t.max_priority), (pri::BASEPRI_DEFAULT, pri::MAXPRI_USER));
        assert!(t.effective.darwinbg && t.effective.qos_clamp == qos::BACKGROUND);
    }

    #[test]
    fn app_types_and_clamps_set_the_priority_range() {
        let bg = spawned(apptype::DAEMON_BACKGROUND, 0, 0);
        assert_eq!((bg.priority, bg.max_priority), (pri::MAXPRI_THROTTLE, pri::MAXPRI_THROTTLE));
        assert!(bg.effective.darwinbg && bg.effective.io_tier == TIER2);
        let std = spawned(apptype::DAEMON_STANDARD, 0, 0);
        assert_eq!((std.priority, std.max_priority, std.effective.io_tier), (pri::BASEPRI_DEFAULT, pri::MAXPRI_USER, TIER1));
        assert_eq!(std.effective.qos_ceiling, qos::USER_INITIATED);
        let app = spawned(apptype::APP_DEFAULT, qos::UTILITY, 0);
        assert_eq!(app.requested.role, role::FOREGROUND_APPLICATION);
        assert!(app.effective.qos_ui_is_urgent && app.effective.live_donor && app.imp.donor);
        assert_eq!((app.priority, app.max_priority), (pri::BASEPRI_UTILITY, pri::BASEPRI_UTILITY));
        assert_eq!((app.effective.latency_qos, app.effective.through_qos, app.effective.io_tier), (4, 3, TIER1));
    }

    #[test]
    fn a_threads_priority_follows_its_task() {
        // -15REL legacy: 31 - ((31 - 20) * 15 >> 4) = 21.
        let t = TaskPolicy { priority: pri::BASEPRI_DEFAULT, ..TaskPolicy::default() };
        let (q, r, u, x) = thread_effective_qos(qos::LEGACY, -15, 0, false, &t.effective);
        assert_eq!(thread_base_priority(q, r, u, x, 0, &t), 21);
        // A clamped task: its threads' QoS and priority are held down.
        let app = spawned(apptype::APP_DEFAULT, qos::UTILITY, 0);
        let (q, r, u, x) = thread_effective_qos(qos::USER_INTERACTIVE, -4, 0, false, &app.effective);
        assert_eq!((q, r), (qos::UTILITY, 0));
        assert_eq!(thread_base_priority(q, r, u, x, 0, &app), pri::BASEPRI_UTILITY);
        // A foreground app's user-interactive thread is urgent: 47.
        let fg = spawned(apptype::APP_DEFAULT, 0, 0);
        let (q, r, u, x) = thread_effective_qos(qos::USER_INTERACTIVE, 0, 0, false, &fg.effective);
        assert_eq!(thread_base_priority(q, r, u, x, 0, &fg), 47);
        // No QoS, a background daemon: never below MAXPRI_THROTTLE.
        let bg = spawned(apptype::DAEMON_BACKGROUND, 0, 0);
        let (q, r, u, x) = thread_effective_qos(qos::UNSPECIFIED, 0, 0, false, &bg.effective);
        assert_eq!(q, qos::BACKGROUND);
        assert_eq!(thread_base_priority(q, r, u, x, -20, &bg), pri::MAXPRI_THROTTLE);
    }

    #[test]
    fn spawn_attributes_are_read_as_the_policy_takes_them() {
        assert_eq!(spawn_attrs(0x100, 1, 1), (apptype::APP_DEFAULT, qos::UTILITY, role::FOREGROUND_APPLICATION));
        assert_eq!(spawn_attrs(0x800, 9, 9), (apptype::NONE, qos::UNSPECIFIED, role::UNSPECIFIED));
        assert_eq!(spawn_attrs(0x600, 3, 6), (apptype::DAEMON_ADAPTIVE, qos::MAINTENANCE, role::DARWINBG_APPLICATION));
    }
}
