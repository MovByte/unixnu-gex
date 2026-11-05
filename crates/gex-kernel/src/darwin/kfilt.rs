//! The kevent filters (`sysfilt_ops`): what attaching, an event, a touch,
//! processing and detaching do for each kind of knote.
//!
//! Here are `EVFILT_USER` and `EVFILT_TIMER` (`kern_event.c`),
//! `EVFILT_WORKLOOP` (`kern_event.c`), `EVFILT_MACHPORT` on a port or a
//! port set (`osfmk/ipc/ipc_pset.c`) and a kqueue's descriptor
//! (`kqread_filtops`). The filters with no implementation say so and fail
//! the registration; `bad_filtops` refuses as XNU does.

use super::ipc::{ty, Object, ObjId};
use super::kevent::{ev, evfilt, filter, filtid, kn, kq, Cont, Ctx, Kev, KnId, KqId, Utq};
use super::wait::Wait;
use super::workq::{qos, tr};
use crate::errno::Errno;
use crate::syscalls::{Kernel, SyscallOutcome};
use crate::GuestMem;

/// `NOTE_*` of `EVFILT_USER`.
mod user {
    pub const TRIGGER: u32 = 0x0100_0000;
    pub const FFAND: u32 = 0x4000_0000;
    pub const FFOR: u32 = 0x8000_0000;
    pub const FFCOPY: u32 = 0xc000_0000;
    pub const FFCTRLMASK: u32 = 0xc000_0000;
    pub const FFLAGSMASK: u32 = 0x00ff_ffff;
}

/// `NOTE_*` of `EVFILT_TIMER`.
mod tmr {
    pub const SECONDS: u32 = 0x01;
    pub const USECONDS: u32 = 0x02;
    pub const NSECONDS: u32 = 0x04;
    pub const ABSOLUTE: u32 = 0x08;
    pub const LEEWAY: u32 = 0x10;
    pub const MACHTIME: u32 = 0x100;
    /// `kn_hook32`: the timer's state and arming generation.
    pub const IDLE: u32 = 0x0;
    pub const ARMED: u32 = 0x1;
    pub const FIRED: u32 = 0x2;
    pub const IMMEDIATE: u32 = 0x3;
    pub const STATE_MASK: u32 = 0x3;
    pub const GEN_INC: u32 = 0x4;
}

/// `NOTE_WL_*` and `EV_EXTIDX_WL_*`.
mod wl {
    pub const THREAD_REQUEST: u32 = 0x0000_0001;
    pub const SYNC_WAIT: u32 = 0x0000_0004;
    pub const SYNC_WAKE: u32 = 0x0000_0008;
    pub const SYNC_IPC: u32 = 0x8000_0000;
    pub const COMMANDS_MASK: u32 = 0x8000_000f;
    pub const UPDATE_QOS: u32 = 0x0000_0010;
    pub const END_OWNERSHIP: u32 = 0x0000_0020;
    pub const DISCOVER_OWNER: u32 = 0x0000_0080;
    pub const IGNORE_ESTALE: u32 = 0x0000_0100;
    pub const UPDATES_MASK: u32 = 0x0000_01f0;
    pub const ADDR: usize = 1;
    pub const MASK: usize = 2;
    pub const VALUE: usize = 3;
}

/// The Mach options a port knote receives with (`kn_sfflags`).
mod mo {
    pub const RCV_MSG: u32 = 0x0000_0002;
    pub const RCV_LARGE: u32 = 0x0000_0004;
    pub const RCV_LARGE_IDENTITY: u32 = 0x0000_0008;
    pub const RCV_TIMEOUT: u32 = 0x0000_0100;
    pub const MSG_STRICT_REPLY: u32 = 0x0000_0200;
    pub const RCV_VOUCHER: u32 = 0x0000_0800;
    pub const RCV_SYNC_PEEK: u32 = 0x0000_8000;
    pub const RCV_TRAILER_MASK: u32 = 0xf << 24;
    pub const RCV_TOO_LARGE: u32 = 0x1000_4004;
}

/// `NOTE_MEMORYSTATUS_*` and `EVFILT_MEMORYSTATUS_ALL_MASK`.
mod ms {
    pub const PRESSURE_NORMAL: u32 = 0x01;
    pub const PRESSURE_WARN: u32 = 0x02;
    pub const PRESSURE_CRITICAL: u32 = 0x04;
    pub const LOW_SWAP: u32 = 0x08;
    pub const PROC_LIMIT_WARN: u32 = 0x10;
    pub const PROC_LIMIT_CRITICAL: u32 = 0x20;
    pub const MSL_STATUS: u32 = 0xf000_0000;
    pub const ALL_MASK: u32 = PRESSURE_NORMAL | PRESSURE_WARN | PRESSURE_CRITICAL | LOW_SWAP | PROC_LIMIT_WARN | PROC_LIMIT_CRITICAL | MSL_STATUS;
    /// The memorystatus notification events (`kMemorystatus*`).
    pub const EV_NO_PRESSURE: i64 = 0x1;
    pub const EV_PRESSURE: i64 = 0x2;
    pub const EV_LOW_SWAP: i64 = 0x4;
    pub const EV_PROC_LIMIT_WARN: i64 = 0x8;
    pub const EV_PROC_LIMIT_CRITICAL: i64 = 0x10;
}

/// `vm_pressure_level_t`.
#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum Pressure {
    Normal,
    Warning,
    Urgent,
    Critical,
}

/// `memorystatus_vm_pressure_level`. Nothing here measures the memory
/// the guest has left, so the level stays normal and no pressure,
/// low-swap or process-limit event is posted.
const MEMORYSTATUS_VM_PRESSURE_LEVEL: Pressure = Pressure::Normal;

/// `NOTE_SIGNAL`, shared with EVFILT_PROC.
const NOTE_SIGNAL: i64 = 0x0800_0000;

/// `ESTALE`.
const ESTALE: Errno = Errno(116);

/// `filt_wlupdate`'s operation.
#[derive(Clone, Copy, PartialEq, Eq)]
enum WlOp {
    Attach,
    Touch,
    Drop,
}

/// A filter's id, by its `EVFILT_*`.
fn id(f: i16) -> u8 {
    (!f) as u8
}

impl Kernel {
    /// `f_attach`.
    pub(crate) fn filt_attach(&mut self, m: &mut GuestMem<'_>, n: KnId, kev: &mut Kev) -> u32 {
        let fid = self.knote(n).filtid;
        match fid {
            f if f == id(evfilt::USER) => self.filt_userattach(n),
            f if f == id(evfilt::TIMER) => self.filt_timerattach(n, kev),
            f if f == id(evfilt::WORKLOOP) => self.filt_wlattach(m, n, kev),
            f if f == id(evfilt::MACHPORT) => self.filt_machportattach(n),
            f if f == id(evfilt::MEMORYSTATUS) => self.filt_memorystatusattach(n),
            f if f == id(evfilt::SIGNAL) => self.filt_sigattach(n),
            f if f == id(evfilt::PROC) => self.filt_procattach(n),
            f if f == id(evfilt::READ) => self.filt_fileattach(n),
            f if [evfilt::WRITE, evfilt::VNODE, evfilt::SOCK, evfilt::EXCEPT, evfilt::NW_CHANNEL].iter().any(|&e| id(e) == f) => self.filt_fileattach(n),
            // bad_filtops: filt_no_attach.
            f if [evfilt::AIO, -11, evfilt::VM, evfilt::EXCLAVES_NOTIFICATION].iter().any(|&e| id(e) == f) => {
                self.knote(n).set_error(Errno::EOPNOTSUPP);
                0
            }
            f => {
                let name = match f {
                    f if f == id(evfilt::FS) => "EVFILT_FS",
                    _ => "an unknown kevent filter",
                };
                self.darwin_unimplemented(format!("kevent {name}"));
                self.knote(n).set_error(Errno::EOPNOTSUPP);
                0
            }
        }
    }

    /// `f_detach`.
    pub(crate) fn filt_detach(&mut self, n: KnId) {
        match self.knote(n).filtid {
            f if f == id(evfilt::TIMER) => self.filt_timerdetach(n),
            f if f == id(evfilt::WORKLOOP) => self.filt_wldetach(n),
            filtid::MACH_PORT | filtid::MACH_PORT_SET => self.filt_machportdetach(n),
            filtid::KQREAD => self.filt_kqdetach(n),
            filtid::PIPE_N | filtid::PIPE_R | filtid::PIPE_W => self.filt_pipedetach(n),
            filtid::VN => {
                if let Some(id) = self.knote(n).vnote.take() {
                    crate::vnote::unlisten(id);
                }
            }
            f if f == id(evfilt::MEMORYSTATUS) => self.dtask.kevents.memorystatus_klist.retain(|&x| x != n),
            f if f == id(evfilt::SIGNAL) => self.dtask.kevents.sig_klist.retain(|&x| x != n),
            f if f == id(evfilt::PROC) => {
                if let Some(id) = self.knote(n).vnote.take() {
                    crate::procnote::unlisten(id);
                }
            }
            // filt_no_detach
            _ => {}
        }
    }

    /// `f_event`.
    pub(crate) fn filt_event(&mut self, n: KnId, hint: i64) -> u32 {
        match self.knote(n).filtid {
            filtid::MACH_PORT => {
                assert_eq!(hint, 0);
                let port = self.knote(n).ipc.expect("a port knote's port");
                self.filt_port_filter_result(n, port)
            }
            filtid::MACH_PORT_SET => filter::ACTIVE,
            filtid::KQREAD => self.filt_kqueue(n),
            filtid::PIPE_N => self.filt_pipe_draincommon(n),
            filtid::PIPE_R => self.filt_piperead_common(n, None),
            filtid::PIPE_W => self.filt_pipewrite_common(n, None),
            filtid::VN => self.filt_vnode_common(n, hint as u32, None),
            f if f == id(evfilt::MEMORYSTATUS) => self.filt_memorystatus(n, hint),
            f if f == id(evfilt::SIGNAL) => {
                // filt_signal: a post of the knote's signal counts.
                assert!(hint & NOTE_SIGNAL != 0, "filt_signal: detected NOTE_EXIT event");
                let k = self.knote(n);
                if k.ident == (hint & !NOTE_SIGNAL) as u64 {
                    k.hook32 += 1;
                }
                u32::from(k.hook32 != 0)
            }
            f if f == id(evfilt::PROC) => self.filt_procevent(n, hint as u32),
            f => panic!("filt_bad_event[{f}]({n}, {hint})"),
        }
    }

    /// `f_touch`.
    pub(crate) fn filt_touch(&mut self, m: &mut GuestMem<'_>, n: KnId, kev: &mut Kev) -> u32 {
        match self.knote(n).filtid {
            f if f == id(evfilt::USER) => self.filt_usertouch(n, kev),
            f if f == id(evfilt::TIMER) => self.filt_timertouch(n, kev),
            f if f == id(evfilt::WORKLOOP) => self.filt_wltouch(m, n, kev),
            filtid::MACH_PORT | filtid::MACH_PORT_SET => self.filt_machporttouch(n, kev),
            filtid::KQREAD => self.filt_kqueue(n),
            filtid::PIPE_N | filtid::PIPE_R | filtid::PIPE_W => {
                // The low water mark and its flag are the new ones.
                let k = self.knote(n);
                k.sdata = kev.data;
                k.sfflags = kev.fflags;
                match k.filtid {
                    filtid::PIPE_N => self.filt_pipe_draincommon(n),
                    filtid::PIPE_R => self.filt_piperead_common(n, None),
                    _ => self.filt_pipewrite_common(n, None),
                }
            }
            filtid::VN => {
                self.knote(n).sfflags = kev.fflags;
                self.filt_vnode_common(n, 0, None)
            }
            f if f == id(evfilt::SIGNAL) => u32::from(self.knote(n).hook32 > 0),
            // filt_proctouch: the new interest; what was collected stays.
            f if f == id(evfilt::PROC) => {
                let k = self.knote(n);
                k.sfflags = kev.fflags;
                u32::from(k.fflags != 0)
            }
            f if f == id(evfilt::MEMORYSTATUS) => {
                // filt_memorystatustouch: the knote's interest replaced; on
                // iOS no per-limit state is kept.
                let k = self.knote(n);
                k.sfflags = kev.fflags & ms::ALL_MASK;
                u32::from(k.fflags != 0)
            }
            f => panic!("filt_bad_touch[{f}]"),
        }
    }

    /// `f_process`.
    pub(crate) fn filt_process(&mut self, m: &mut GuestMem<'_>, n: KnId, kev: &mut Kev, ctx: &mut Ctx) -> u32 {
        match self.knote(n).filtid {
            f if f == id(evfilt::USER) => self.filt_userprocess(n, kev),
            f if f == id(evfilt::TIMER) => self.filt_timerprocess(n, kev),
            f if f == id(evfilt::WORKLOOP) => self.filt_wlprocess(n, kev),
            filtid::MACH_PORT | filtid::MACH_PORT_SET => self.filt_machportprocess(m, n, kev, ctx),
            filtid::KQREAD => self.filt_kqprocess(n, kev),
            filtid::PIPE_N => {
                let r = self.filt_pipe_draincommon(n);
                if r != 0 {
                    *kev = self.knote(n).fill_kevent(0);
                }
                r
            }
            filtid::PIPE_R => self.filt_piperead_common(n, Some(kev)),
            filtid::PIPE_W => self.filt_pipewrite_common(n, Some(kev)),
            filtid::VN => self.filt_vnode_common(n, 0, Some(kev)),
            // filt_procprocess: the collected events, the exit status as
            // the data.
            f if f == id(evfilt::PROC) => {
                let k = self.knote(n);
                if k.fflags == 0 {
                    return 0;
                }
                let data = k.hook32;
                *kev = k.fill_kevent(i64::from(data));
                k.hook32 = 0;
                1
            }
            f if f == id(evfilt::SIGNAL) => {
                let k = self.knote(n);
                if k.hook32 == 0 {
                    return 0;
                }
                let count = k.hook32;
                *kev = k.fill_kevent(i64::from(count));
                k.hook32 = 0;
                1
            }
            f if f == id(evfilt::MEMORYSTATUS) => {
                let k = self.knote(n);
                if k.fflags == 0 {
                    return 0;
                }
                *kev = k.fill_kevent(0);
                1
            }
            f => panic!("filt_bad_process[{f}]"),
        }
    }

    // -- EVFILT_USER ------------------------------------------------------------------------

    fn filt_userattach(&mut self, n: KnId) -> u32 {
        let k = self.knote(n);
        k.hook32 = if k.sfflags & user::TRIGGER != 0 { filter::ACTIVE } else { 0 };
        k.hook32
    }

    fn filt_usertouch(&mut self, n: KnId, kev: &Kev) -> u32 {
        let k = self.knote(n);
        let ffctrl = kev.fflags & user::FFCTRLMASK;
        let fflags = kev.fflags & user::FFLAGSMASK;
        match ffctrl {
            user::FFAND => k.sfflags &= fflags,
            user::FFOR => k.sfflags |= fflags,
            user::FFCOPY => k.sfflags = fflags,
            _ => {}
        }
        k.sdata = kev.data;
        if kev.fflags & user::TRIGGER != 0 {
            k.hook32 = filter::ACTIVE;
        }
        k.hook32
    }

    fn filt_userprocess(&mut self, n: KnId, kev: &mut Kev) -> u32 {
        let k = self.knote(n);
        let result = k.hook32;
        if result != 0 {
            *kev = k.fill_kevent_with_sdata();
            kev.fflags = k.sfflags;
            if k.flags & ev::CLEAR != 0 {
                k.hook32 = 0;
            }
        }
        result
    }

    // -- EVFILT_TIMER -----------------------------------------------------------------------

    /// `filt_timervalidate`: the deadline, leeway and interval, in absolute
    /// time units.
    fn filt_timervalidate(kev: &Kev) -> Result<(u64, u64, u64), Errno> {
        let ns_to_abs = |ns: u64| super::mach::ns_to_abs(ns);
        let (multiplier, use_abstime) = match kev.fflags & (tmr::SECONDS | tmr::USECONDS | tmr::NSECONDS | tmr::MACHTIME) {
            tmr::SECONDS => (1_000_000_000u64, false),
            tmr::USECONDS => (1_000, false),
            tmr::NSECONDS => (1, false),
            tmr::MACHTIME => (0, true),
            0 => (1_000_000, false),
            _ => return Err(Errno::EINVAL),
        };
        let leeway = if kev.fflags & tmr::LEEWAY != 0 {
            if use_abstime {
                kev.ext[1]
            } else {
                ns_to_abs(kev.ext[1].checked_mul(multiplier).ok_or(Errno::ERANGE)?)
            }
        } else {
            0
        };
        let now = super::mach::absolute_time();
        if kev.fflags & tmr::ABSOLUTE != 0 {
            let deadline = if use_abstime {
                kev.data as u64
            } else {
                let deadline_ns = (kev.data as u64).checked_mul(multiplier).ok_or(Errno::ERANGE)?;
                // A calendar deadline: what is left of it from now, on
                // the absolute (or continuous) clock.
                let now_ns = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64);
                if now_ns < deadline_ns {
                    now + ns_to_abs(deadline_ns - now_ns)
                } else {
                    0
                }
            };
            return Ok((deadline, leeway, 0));
        }
        if kev.data < 0 {
            // A negative interval fires at once, once.
            return Ok((0, leeway, 0));
        }
        let interval = if use_abstime { kev.data as u64 } else { ns_to_abs((kev.data as u64).checked_mul(multiplier).ok_or(Errno::ERANGE)?) };
        Ok((now + interval, leeway, interval))
    }

    /// `filt_timer_is_ready`.
    fn filt_timer_is_ready(&mut self, n: KnId) -> bool {
        let deadline = self.knote(n).ext[0];
        // The continuous clock is the absolute one: the machine never
        // sleeps.
        deadline == 0 || deadline <= super::mach::absolute_time()
    }

    /// `filt_timerarm`: the thread call armed for the deadline. It fires
    /// at the deadline, the earliest the leeway allows.
    fn filt_timerarm(&mut self, n: KnId) {
        let deadline = self.knote(n).ext[0];
        let k = self.knote(n);
        let state = (k.hook32 & !tmr::STATE_MASK).wrapping_add(tmr::GEN_INC + tmr::ARMED);
        k.hook32 = state;
        if let Some(key) = k.thcall.take() {
            self.dtask.timers.cancel(key);
        }
        let at = super::mach::abs_to_instant(deadline);
        let key = self.dtask.timers.arm(at, super::timer::Action::Knote(n, state));
        self.knote(n).thcall = Some(key);
    }

    /// `filt_timerexpire`: the thread call fired for the arming `state`.
    pub(crate) fn filt_timerexpire(&mut self, n: KnId, state: u32) {
        if !self.knote_exists(n) {
            return;
        }
        let k = self.knote(n);
        k.thcall = None;
        if k.hook32 == state {
            k.hook32 = state ^ tmr::ARMED ^ tmr::FIRED;
            self.knote_activate(n, filter::ACTIVE);
        }
    }

    /// `filt_timerfire_immediate`.
    fn filt_timerfire_immediate(&mut self, n: KnId) {
        let k = self.knote(n);
        let state = k.hook32;
        k.hook32 |= tmr::IMMEDIATE;
        if state & tmr::STATE_MASK == tmr::ARMED {
            if let Some(key) = k.thcall.take() {
                self.dtask.timers.cancel(key);
            }
        }
    }

    fn filt_timerattach(&mut self, n: KnId, kev: &Kev) -> u32 {
        let (deadline, leeway, interval) = match Self::filt_timervalidate(kev) {
            Ok(p) => p,
            Err(e) => {
                self.knote(n).set_error(e);
                return 0;
            }
        };
        let k = self.knote(n);
        k.ext[0] = deadline;
        k.ext[1] = leeway;
        k.sdata = interval as i64;
        k.flags |= ev::CLEAR;
        k.hook32 = tmr::IDLE;
        if k.sfflags & tmr::ABSOLUTE != 0 {
            k.flags |= ev::ONESHOT;
        }
        if self.filt_timer_is_ready(n) {
            self.knote(n).hook32 = tmr::IMMEDIATE;
            filter::ACTIVE
        } else {
            self.filt_timerarm(n);
            0
        }
    }

    fn filt_timerdetach(&mut self, n: KnId) {
        // thread_call_cancel_wait: the thread call runs under the kernel
        // lock, so it is never mid-run here.
        if let Some(key) = self.knote(n).thcall.take() {
            self.dtask.timers.cancel(key);
        }
    }

    fn filt_timertouch(&mut self, n: KnId, kev: &mut Kev) -> u32 {
        let kqid = self.knote(n).kq;
        if kev.qos != 0 && self.kq_state(kqid) & kq::WORKLOOP != 0 && super::thread::pp::qos(kev.qos as u32 as u64) == 0 {
            kev.set_error(Errno::ERANGE);
            return 0;
        }
        if (self.knote(n).sfflags ^ kev.fflags) & tmr::ABSOLUTE != 0 {
            kev.set_error(Errno::EINVAL);
            return 0;
        }
        let (deadline, leeway, interval) = match Self::filt_timervalidate(kev) {
            Ok(p) => p,
            Err(e) => {
                kev.set_error(e);
                return 0;
            }
        };
        let k = self.knote(n);
        k.ext[0] = deadline;
        k.ext[1] = leeway;
        k.sdata = interval as i64;
        k.sfflags = kev.fflags;
        if self.filt_timer_is_ready(n) {
            self.filt_timerfire_immediate(n);
            filter::ACTIVE | filter::UPDATE_REQ_QOS
        } else {
            self.filt_timerarm(n);
            filter::UPDATE_REQ_QOS
        }
    }

    fn filt_timerprocess(&mut self, n: KnId, kev: &mut Kev) -> u32 {
        let state = self.knote(n).hook32;
        if matches!(state & tmr::STATE_MASK, tmr::IDLE | tmr::ARMED) {
            return 0;
        }
        let k = self.knote(n);
        k.hook32 = state & !tmr::STATE_MASK;
        *kev = k.fill_kevent(1);
        kev.ext[0] = 0;
        if k.sdata != 0 {
            // An interval timer: how many intervals went by, and the next
            // deadline on the same grid.
            let now = super::mach::absolute_time();
            let first_deadline = k.ext[0];
            let interval = k.sdata as u64;
            let orig_arm_time = first_deadline - interval;
            assert!(now > orig_arm_time && now > first_deadline);
            let num_fired = (now - orig_arm_time) / interval;
            assert!(num_fired > 0);
            kev.data = num_fired as i64;
            if k.flags & ev::ONESHOT == 0 {
                let new_deadline = first_deadline + num_fired * interval;
                assert!(new_deadline > now);
                k.ext[0] = new_deadline;
                self.filt_timerarm(n);
            }
        }
        filter::ACTIVE
    }

    // -- EVFILT_WORKLOOP ----------------------------------------------------------------------

    /// `filt_wlturnstile_interlock_is_workq`.
    fn filt_wlturnstile_interlock_is_workq(&mut self, kqwl: KqId) -> bool {
        let req = self.wl_req(kqwl);
        self.kqr_thread_requested_pending(req)
    }

    /// `filt_wlupdate`: the workloop's owner and QoS after an attach,
    /// touch or drop, debounced against the value at `ext[ADDR]`.
    fn filt_wlupdate(&mut self, m: &mut GuestMem<'_>, kqwl: KqId, n: KnId, kev: &mut Kev, qos_index: u8, op: WlOp) -> Result<bool, Errno> {
        let uaddr = kev.ext[wl::ADDR];
        let req = self.wl_req(kqwl);
        let (kdata, mask) = (kev.ext[wl::VALUE], kev.ext[wl::MASK]);
        let cur_owner = self.kq(kqwl).owner;
        let mut new_owner = cur_owner;
        let mut action = Utq::None;
        let mut needs_wake = false;
        let mut error = Ok(());
        if uaddr != 0 {
            // copyin_atomic64: a fault is retried, then fails.
            let udata = m.read_u64(uaddr).map_err(|_| Errno::EFAULT)?;
            kev.ext[wl::VALUE] = udata;
            if udata & mask != kdata & mask {
                error = Err(ESTALE);
            } else if kev.fflags & wl::DISCOVER_OWNER != 0 {
                // The owner's thread port name is in the value, its low
                // two bits the lock's.
                let name = (udata as u32) & !0x3;
                if name != 0 {
                    // ipc_entry_name_mask: the generation's low bits back.
                    match self.darwin_name_to_thread(name | 0x3) {
                        Some(t) => new_owner = Some(t),
                        None => return Err(Errno::EOWNERDEAD),
                    }
                }
            }
        }
        if kev.fflags & wl::END_OWNERSHIP != 0 && new_owner == Some(self.tid) {
            new_owner = None;
        }
        if error.is_ok() {
            if kev.fflags & wl::THREAD_REQUEST != 0 && kev.flags & ev::DELETE != 0 {
                action = Utq::SetQosIndex;
            } else if qos_index != 0 && self.darwin_workq_req(req).kq_qos_index != qos_index {
                action = Utq::SetQosIndex;
            }
            match op {
                WlOp::Touch => {
                    let k = self.knote(n);
                    k.sfflags &= !wl::UPDATES_MASK;
                    k.sfflags |= kev.fflags;
                    if kev.fflags & wl::SYNC_WAKE != 0 {
                        needs_wake = k.thread.is_some();
                    }
                }
                WlOp::Drop => {
                    let k = self.knote(n);
                    if k.sfflags & (wl::SYNC_WAIT | wl::SYNC_WAKE) == wl::SYNC_WAIT {
                        // A waiter's knote being dropped wakes the waiter.
                        k.sfflags |= wl::SYNC_WAKE;
                        needs_wake = k.thread.is_some();
                    }
                }
                WlOp::Attach => {}
            }
        }
        if cur_owner == new_owner && action == Utq::None && !needs_wake {
            return error.map(|()| false);
        }
        if new_owner.is_some() && new_owner == self.kqr_thread(req) {
            new_owner = None;
        }
        let mut cur_override = qos::UNSPECIFIED;
        if cur_owner != new_owner {
            self.kq(kqwl).owner = new_owner;
            cur_override = self.kqworkloop_override(kqwl);
            if let Some(o) = new_owner {
                if cur_override != qos::UNSPECIFIED {
                    self.dtask.threads.map.entry(o).or_default().kevent_override = cur_override;
                }
                if self.kqr_thread_requested_pending(req) && action == Utq::None {
                    action = Utq::RedriveEvents;
                }
            } else if action == Utq::None && self.darwin_workq_req(req).state == tr::IDLE && self.kq(kqwl).wakeup_qos != 0 {
                action = Utq::RedriveEvents;
            }
        }
        if action != Utq::None {
            self.kqworkloop_update_threads_qos(kqwl, action, qos_index);
        }
        // The workloop's turnstile and its inheritor (the owner, else the
        // servicer) push priority only; nothing here runs by priority.
        let _ = self.filt_wlturnstile_interlock_is_workq(kqwl);
        let mut preempt_disabled = false;
        if needs_wake {
            let t = self.knote(n).thread.expect("a sync waiter");
            self.kevent_wake_later(t, super::wait::WaitResult::Awakened);
            if matches!(op, WlOp::Attach | WlOp::Touch) {
                preempt_disabled = true;
            }
        }
        if let Some(o) = cur_owner {
            if new_owner != cur_owner && cur_override != qos::UNSPECIFIED {
                self.dtask.threads.map.entry(o).or_default().kevent_override = qos::UNSPECIFIED;
            }
        }
        error.map(|()| preempt_disabled)
    }

    /// `filt_wlremember_last_update`.
    fn filt_wlremember_last_update(&mut self, n: KnId, kev: &Kev, error: &Result<bool, Errno>) {
        let k = self.knote(n);
        k.fflags = kev.fflags;
        k.sdata = match error {
            Err(e) => i64::from(super::errno::to_darwin(e.0)),
            Ok(_) => 0,
        };
        k.ext = kev.ext;
    }

    /// `kevent_register_wait_prepare`.
    fn kevent_register_wait_prepare(&mut self, n: KnId, kev: &mut Kev, rc: u32) -> u32 {
        let me = self.tid;
        let k = self.knote(n);
        match k.thread {
            None => k.thread = Some(me),
            Some(t) if t != me => {
                // A waiter can only be the thread that set it up.
                kev.set_error(Errno::EXDEV);
                return 0;
            }
            Some(_) => {}
        }
        filter::REGISTER_WAIT | rc
    }

    fn filt_wlattach(&mut self, m: &mut GuestMem<'_>, n: KnId, kev: &mut Kev) -> u32 {
        let kqwl = self.knote(n).kq;
        let mut result = 0;
        let mut qos_index = 0;
        let k = self.knote(n).clone();
        let command = k.sfflags & wl::COMMANDS_MASK;
        let r: Result<(), Errno> = (|| {
            if self.kq_state(kqwl) & kq::WORKLOOP == 0 {
                return Err(Errno::EOPNOTSUPP);
            }
            match command {
                wl::THREAD_REQUEST => {
                    if k.ident != self.kq(kqwl).dynamicid {
                        return Err(Errno::EINVAL);
                    }
                    qos_index = super::thread::pp::qos(k.qos as u32 as u64);
                    if qos_index == qos::UNSPECIFIED {
                        return Err(Errno::ERANGE);
                    }
                    let req = self.wl_req(kqwl);
                    if self.darwin_workq_req(req).kq_qos_index != 0 {
                        // One thread request per workloop.
                        return Err(Errno::EALREADY);
                    }
                }
                wl::SYNC_WAIT | wl::SYNC_WAKE => {
                    if k.ident == self.kq(kqwl).dynamicid || k.flags & ev::DISABLE == 0 || k.sfflags & wl::END_OWNERSHIP != 0 {
                        return Err(Errno::EINVAL);
                    }
                }
                wl::SYNC_IPC => {
                    if k.flags & ev::DISABLE == 0 || k.sfflags & (wl::UPDATE_QOS | wl::DISCOVER_OWNER) != 0 {
                        return Err(Errno::EINVAL);
                    }
                }
                _ => return Err(Errno::EINVAL),
            }
            if command == wl::SYNC_IPC {
                // filt_wlupdate_sync_ipc and filt_wlattach_sync_ipc: the
                // special reply port's or receive right's sync IPC link to
                // the workloop's turnstile.
                self.darwin_unimplemented("EVFILT_WORKLOOP NOTE_WL_SYNC_IPC".into());
                return Err(Errno::EOPNOTSUPP);
            }
            if self.filt_wlupdate(m, kqwl, n, kev, qos_index, WlOp::Attach)? {
                result = filter::THREADREQ_NODEFEER;
            }
            Ok(())
        })();
        if let Err(e) = r {
            if e == ESTALE && self.knote(n).sfflags & wl::IGNORE_ESTALE != 0 {
                // An ESTALE ignored: the knote is not attached.
                self.knote(n).flags |= ev::ERROR;
                self.knote(n).sdata = 0;
            } else {
                self.knote(n).set_error(e);
            }
            return result;
        }
        if command == wl::SYNC_WAIT {
            return self.kevent_register_wait_prepare(n, kev, result);
        }
        if command == wl::THREAD_REQUEST {
            // Thread requests are delivered, then stay until deleted.
            self.knote(n).flags |= ev::CLEAR;
            return result | filter::ACTIVE;
        }
        result
    }

    /// `filt_wlpost_register_wait`: the caller waits for its sync knote to
    /// be woken (`filt_wlwait_continue`).
    pub(crate) fn filt_wlpost_register_wait(&mut self, m: &mut GuestMem<'_>, kqwl: KqId, n: KnId, kev: Kev, eventout: i32, ueventlist: u64) -> SyscallOutcome {
        let _ = n;
        // The wait pushes on the owner, else the servicer, through the
        // workloop's turnstile, and hands the processor to it: priority
        // and scheduling only.
        let wait = Wait { deadline: None, cont: super::thread::Finish::Kevent(Cont::WlWait { kqwl, kev, eventout, ueventlist }) };
        self.darwin_kevent_settle(m);
        self.darwin_block(m, wait)
    }

    fn filt_wldetach(&mut self, n: KnId) {
        if self.knote(n).sfflags & wl::SYNC_IPC != 0 {
            unreachable!("a NOTE_WL_SYNC_IPC knote is never attached here");
        } else if self.knote(n).thread.is_some() {
            // kevent_register_wait_cleanup
            self.knote(n).thread = None;
        }
    }

    /// `filt_wlvalidate_kev_flags`.
    fn filt_wlvalidate_kev_flags(&mut self, n: KnId, kev: &Kev, qos_index: Option<&mut u8>) -> Result<(), Errno> {
        let new_commands = kev.fflags & wl::COMMANDS_MASK;
        let sav_commands = self.knote(n).sfflags & wl::COMMANDS_MASK;
        if kev.fflags & wl::DISCOVER_OWNER != 0 && kev.flags & ev::DELETE != 0 {
            return Err(Errno::EINVAL);
        }
        if kev.fflags & wl::UPDATE_QOS != 0 {
            if kev.flags & ev::DELETE != 0 || sav_commands != wl::THREAD_REQUEST {
                return Err(Errno::EINVAL);
            }
            let q = super::thread::pp::qos(kev.qos as u32 as u64);
            if q == 0 {
                return Err(Errno::ERANGE);
            }
            if let Some(qi) = qos_index {
                *qi = q;
            }
        }
        match new_commands {
            wl::THREAD_REQUEST => {
                if sav_commands != wl::THREAD_REQUEST {
                    return Err(Errno::EINVAL);
                }
            }
            wl::SYNC_WAIT | wl::SYNC_WAKE => {
                if new_commands == wl::SYNC_WAIT && kev.fflags & wl::END_OWNERSHIP != 0 {
                    return Err(Errno::EINVAL);
                }
                if sav_commands & (wl::SYNC_WAIT | wl::SYNC_WAKE) == 0 || kev.flags & (ev::ENABLE | ev::DELETE) == ev::ENABLE {
                    return Err(Errno::EINVAL);
                }
            }
            wl::SYNC_IPC => {
                if sav_commands != wl::SYNC_IPC || kev.flags & (ev::ENABLE | ev::DELETE) == ev::ENABLE {
                    return Err(Errno::EINVAL);
                }
            }
            _ => return Err(Errno::EINVAL),
        }
        Ok(())
    }

    fn filt_wltouch(&mut self, m: &mut GuestMem<'_>, n: KnId, kev: &mut Kev) -> u32 {
        let kqwl = self.knote(n).kq;
        let mut qos_index = qos::UNSPECIFIED;
        let mut result = 0;
        let command = kev.fflags & wl::COMMANDS_MASK;
        let r = self.filt_wlvalidate_kev_flags(n, kev, Some(&mut qos_index)).and_then(|()| {
            if command == wl::SYNC_IPC {
                unreachable!("a NOTE_WL_SYNC_IPC knote is never attached here");
            }
            let r = self.filt_wlupdate(m, kqwl, n, kev, qos_index, WlOp::Touch);
            self.filt_wlremember_last_update(n, kev, &r);
            r
        });
        match r {
            Ok(true) => result = filter::THREADREQ_NODEFEER,
            Ok(false) => {}
            Err(e) if e == ESTALE && kev.fflags & wl::IGNORE_ESTALE != 0 => return result,
            Err(e) => {
                kev.set_error(e);
                return result;
            }
        }
        if command == wl::SYNC_WAIT && self.knote(n).sfflags & wl::SYNC_WAKE == 0 {
            return self.kevent_register_wait_prepare(n, kev, result);
        }
        if command == wl::THREAD_REQUEST {
            if kev.fflags & wl::UPDATE_QOS != 0 {
                result |= filter::UPDATE_REQ_QOS;
            }
            result |= filter::ACTIVE;
        }
        result
    }

    /// `f_allow_drop`: the workloop filter's.
    pub(crate) fn filt_allow_drop(&mut self, m: &mut GuestMem<'_>, n: KnId, kev: &mut Kev) -> bool {
        let kqwl = self.knote(n).kq;
        let command = kev.fflags & wl::COMMANDS_MASK;
        let r = self.filt_wlvalidate_kev_flags(n, kev, None).and_then(|()| {
            if command == wl::SYNC_IPC {
                unreachable!("a NOTE_WL_SYNC_IPC knote is never attached here");
            }
            let r = self.filt_wlupdate(m, kqwl, n, kev, 0, WlOp::Drop);
            self.filt_wlremember_last_update(n, kev, &r);
            assert!(!matches!(r, Ok(true)));
            r.map(|_| ())
        });
        match r {
            Ok(()) => true,
            Err(e) if e == ESTALE && kev.fflags & wl::IGNORE_ESTALE != 0 => false,
            Err(e) => {
                kev.set_error(e);
                false
            }
        }
    }

    fn filt_wlprocess(&mut self, n: KnId, kev: &mut Kev) -> u32 {
        let kqwl = self.knote(n).kq;
        assert!(self.knote(n).sfflags & wl::THREAD_REQUEST != 0);
        let mut rc = 0;
        if self.kq(kqwl).owner.is_some() {
            // The workloop has an owner: its thread request is put back to
            // be delivered when the owner is done.
            self.knote_activate(n, filter::ACTIVE);
        } else {
            let k = self.knote(n);
            *kev = k.fill_kevent(0);
            kev.fflags = k.sfflags;
            rc |= filter::ACTIVE;
        }
        if rc & filter::ACTIVE != 0 {
            let req = self.wl_req(kqwl);
            self.darwin_workq_thread_set_max_qos(req);
        }
        rc
    }

    // -- EVFILT_MACHPORT ------------------------------------------------------------------------

    /// `filt_machport_link`: a knote that receives on a workloop's
    /// dispatch source goes after the first.
    fn filt_machport_link(&mut self, obj: ObjId, n: KnId) {
        let has_ts = self.filt_machport_kqueue_has_turnstile(n);
        let list = self.dtask.kevents.port_klist.entry(obj).or_default();
        if !list.is_empty() && has_ts {
            list.insert(1, n);
        } else {
            list.insert(0, n);
        }
        match self.dtask.ipc.objects.get_mut(&obj) {
            Some(Object::Port(p)) => p.knotes += 1,
            Some(Object::Pset(s)) => s.knotes += 1,
            None => unreachable!("a linked object exists"),
        }
    }

    /// `filt_machport_unlink`.
    fn filt_machport_unlink(&mut self, obj: ObjId, n: KnId) {
        let list = self.dtask.kevents.port_klist.entry(obj).or_default();
        list.retain(|&x| x != n);
        // The first knote that receives with a turnstile moves to the
        // front.
        if let Some(i) = list.clone().iter().position(|&x| self.filt_machport_kqueue_has_turnstile(x)) {
            let list = self.dtask.kevents.port_klist.get_mut(&obj).expect("the list");
            let x = list.remove(i);
            list.insert(0, x);
        }
        if self.dtask.kevents.port_klist.get(&obj).is_some_and(|l| l.is_empty()) {
            self.dtask.kevents.port_klist.remove(&obj);
        }
        match self.dtask.ipc.objects.get_mut(&obj) {
            Some(Object::Port(p)) => p.knotes -= 1,
            Some(Object::Pset(s)) => s.knotes -= 1,
            None => {}
        }
    }

    /// `filt_machport_kqueue_has_turnstile`.
    fn filt_machport_kqueue_has_turnstile(&self, n: KnId) -> bool {
        let k = &self.dtask.kevents.knotes[&n];
        k.sfflags & (mo::RCV_MSG | mo::RCV_SYNC_PEEK) != 0 && k.flags & ev::DISPATCH != 0
    }

    /// `filt_pset_filter_result`: a member with messages preposted.
    fn filt_pset_filter_result(&self, pset: ObjId) -> u32 {
        let ipc = &self.dtask.ipc;
        let any = ipc.queues.preposts.get(&pset).is_some_and(|q| q.iter().any(|&p| !ipc.port(p).messages.is_empty()));
        if any { filter::ACTIVE } else { 0 }
    }

    /// `filt_port_filter_result`.
    fn filt_port_filter_result(&self, n: KnId, port: ObjId) -> u32 {
        let k = &self.dtask.kevents.knotes[&n];
        let mut result = if k.sfflags & mo::RCV_MSG != 0 { filter::RESET_EVENT_QOS } else { 0 };
        let p = self.dtask.ipc.port(port);
        if !p.active {
            return result;
        }
        // The port's kernel I/O tier override is never set here, so it
        // never differs from the kqueue's.
        let Some(first) = p.messages.front() else { return result };
        result = filter::ACTIVE;
        if k.sfflags & mo::RCV_MSG != 0 {
            result |= filter::adjust_event_qos(first.qos_override);
        }
        result
    }

    fn filt_machportattach(&mut self, n: KnId) -> u32 {
        let name = self.knote(n).ident as u32;
        let k = self.knote(n);
        k.flags &= !ev::EOF;
        k.ext[3] = 0;
        // kqueue_alloc_turnstile: priority inheritance only.
        let Some(e) = self.dtask.ipc.space.lookup(name).copied() else {
            self.knote(n).set_error(Errno::ENOENT);
            return 0;
        };
        if e.bits & ty::PORT_SET != 0 {
            let pset = e.object.expect("a set's object");
            self.knote(n).filtid = filtid::MACH_PORT_SET;
            self.dtask.ipc.reference(pset);
            self.knote(n).ipc = Some(pset);
            self.filt_machport_link(pset, n);
            return self.filt_pset_filter_result(pset);
        }
        if e.bits & ty::RECEIVE != 0 {
            let port = e.object.expect("a receive right's object");
            self.knote(n).filtid = filtid::MACH_PORT;
            if self.dtask.ipc.port(port).specialreply {
                self.knote(n).set_error(Errno::EOPNOTSUPP);
                return 0;
            }
            self.dtask.ipc.reference(port);
            self.knote(n).ipc = Some(port);
            self.filt_machport_link(port, n);
            return self.filt_port_filter_result(n, port);
        }
        self.knote(n).set_error(Errno::EOPNOTSUPP);
        0
    }

    /// `filt_portdetach`, `filt_psetdetach`.
    fn filt_machportdetach(&mut self, n: KnId) {
        let obj = self.knote(n).ipc.take().expect("a Mach port knote's object");
        let k = self.knote(n);
        if k.status & kn::VANISHED == 0 && k.flags & ev::EOF == 0 {
            self.filt_machport_unlink(obj, n);
        }
        self.dtask.ipc.release(obj);
    }

    /// `filt_machporttouch`, `filt_porttouch`, `filt_psettouch`.
    fn filt_machporttouch(&mut self, n: KnId, kev: &mut Kev) -> u32 {
        let k = self.knote(n);
        if (k.sfflags ^ kev.fflags) & (mo::RCV_MSG | mo::RCV_SYNC_PEEK) != 0 {
            kev.set_error(Errno::EINVAL);
            return 0;
        }
        k.sfflags = kev.fflags;
        k.ext[0] = kev.ext[0];
        k.ext[1] = kev.ext[1];
        // EV_ENABLE: filt_machport_turnstile_complete, priority only.
        let obj = k.ipc.expect("a Mach port knote's object");
        if k.filtid == filtid::MACH_PORT_SET { self.filt_pset_filter_result(obj) } else { self.filt_port_filter_result(n, obj) }
    }

    /// `filt_machportprocess`: a receive on the knote's port or set into
    /// its buffer (or the call's data buffer), its results in the event.
    fn filt_machportprocess(&mut self, m: &mut GuestMem<'_>, n: KnId, kev: &mut Kev, ctx: &mut Ctx) -> u32 {
        use super::ipc::msg::{opt, RcvWait};
        let object = self.knote(n).ipc.expect("a Mach port knote's object");
        let k = self.knote(n);
        *kev = k.fill_kevent(0);
        kev.ext[3] = 0;
        if kev.flags & ev::EOF != 0 {
            return filter::ACTIVE | filter::RESET_EVENT_QOS;
        }
        let sf = k.sfflags;
        let mut options = u64::from(sf & (mo::RCV_MSG | mo::RCV_LARGE | mo::RCV_LARGE_IDENTITY | mo::RCV_TRAILER_MASK | mo::RCV_VOUCHER | mo::MSG_STRICT_REPLY));
        let (mut msg_addr, mut max_size, mut from_ctx) = (0u64, 0u32, false);
        if sf & mo::RCV_MSG != 0 {
            msg_addr = k.ext[0];
            max_size = k.ext[1] as u32;
            options |= opt::MSG_VECTOR | opt::RCV_LINEAR_VECTOR;
            if max_size == 0 {
                // No buffer of the knote's own: the call's data buffer.
                msg_addr = ctx.data_out;
                max_size = ctx.data_resid as u32;
                options |= opt::RCV_LARGE | opt::RCV_LARGE_IDENTITY;
                from_ctx = true;
                if ctx.process_flags & super::kevent::kf::STACK_DATA != 0 {
                    options |= opt::RCV_STACK;
                }
            }
        } else {
            // Not a receive: the size and name of what is there.
            options = opt::RCV_LARGE;
        }
        options |= u64::from(mo::RCV_TIMEOUT);
        let w = RcvWait { object, options, rcv_size: max_size, aux_size: 0 };
        let size_of = |k: &super::ipc::msg::Kmsg| k.size;
        let Some(rcv) = self.dtask.ipc.mqueue_receive(self.tid, object, w, true, &size_of) else {
            unreachable!("a receive with a zero timeout ends at once")
        };
        if rcv.state == super::ipc::msg::mr::RCV_TIMED_OUT || rcv.state == super::ipc::msg::mr::RCV_PORT_CHANGED {
            return 0;
        }
        if sf & mo::RCV_MSG == 0 {
            // Peeking: the name the message would be received on.
            kev.data = i64::from(rcv.receiver_name);
            return filter::ACTIVE;
        }
        self.dtask.ipc.reference(object);
        let bufs = super::mach_msg::RecvBufs { msg_addr, msg_size: max_size, aux_addr: 0, aux_size: 0 };
        let (fflags, msgr) = self.receive_results_msgr(m, object, rcv, bufs, options);
        kev.fflags = fflags;
        kev.ext[1] = u64::from(msgr.msg_size + msgr.trailer_size);
        kev.ext[3] = u64::from(msgr.aux_size);
        kev.data = if fflags == mo::RCV_TOO_LARGE && options & opt::RCV_LARGE_IDENTITY != 0 { i64::from(msgr.recv_name) } else { 0 };
        if from_ctx && fflags != mo::RCV_TOO_LARGE {
            let size = u64::from(msgr.msg_size + msgr.trailer_size + msgr.aux_size);
            ctx.data_resid -= size;
            if ctx.process_flags & super::kevent::kf::STACK_DATA == 0 {
                kev.ext[0] = ctx.data_out;
                ctx.data_out += size;
            } else {
                kev.ext[0] = ctx.data_out + ctx.data_resid;
            }
        }
        if fflags == super::ipc::msg::mr::SUCCESS {
            kev.ext[2] = (u64::from(msgr.priority) << 32) | super::thread::pp::from_qos(msgr.qos_ovrd, 0, 0);
        }
        filter::ACTIVE
    }

    /// Post the Mach port knotes the IPC layer owes: a message on an empty
    /// queue (`KNOTE(&port->ip_klist, 0)`), a set newly preposted
    /// (`ipc_pset_prepost`), a receive right or set gone (`knote_vanish`).
    pub(crate) fn darwin_machport_knotes(&mut self) {
        loop {
            let q = &mut self.dtask.ipc.queues;
            let (ports, psets, vanish) = (std::mem::take(&mut q.knotes), std::mem::take(&mut q.pset_knotes), std::mem::take(&mut q.vanish));
            if ports.is_empty() && psets.is_empty() && vanish.is_empty() {
                return;
            }
            for obj in vanish {
                // The space is the task's own, active while it runs.
                let list = self.dtask.kevents.port_klist.remove(&obj).unwrap_or_default();
                match self.dtask.ipc.objects.get_mut(&obj) {
                    Some(Object::Port(p)) => p.knotes = 0,
                    Some(Object::Pset(s)) => s.knotes = 0,
                    None => {}
                }
                self.knote_vanish(&list, true);
            }
            for port in ports {
                let list = self.dtask.kevents.port_klist.get(&port).cloned().unwrap_or_default();
                self.knote_list(&list, 0);
            }
            for (pset, port) in psets {
                let list = self.dtask.kevents.port_klist.get(&pset).cloned().unwrap_or_default();
                self.knote_list(&list, port as i64);
            }
        }
    }

    // -- EVFILT_SIGNAL ----------------------------------------------------------------------

    /// `filt_sigattach`: on the process's knote list.
    fn filt_sigattach(&mut self, n: KnId) -> u32 {
        let k = self.knote(n);
        k.flags |= ev::CLEAR;
        k.sdata = 0;
        self.dtask.kevents.sig_klist.insert(0, n);
        0
    }

    /// `proc_knote(p, NOTE_SIGNAL | signum)` for each process-directed
    /// signal posted since the last time, to this process's EVFILT_SIGNAL
    /// knotes, and of those it raised itself to the EVFILT_PROC knotes on it
    /// anywhere; whether there were any.
    pub(crate) fn darwin_signal_knotes(&mut self) -> bool {
        let posted = self.signals.process().take_posted();
        for &l in &posted {
            let Some(d) = super::signal::signal_from_linux(l) else { continue };
            let list = self.dtask.kevents.sig_klist.clone();
            self.knote_list(&list, NOTE_SIGNAL | i64::from(d));
        }
        // What it raised itself is told of here; what another process sent
        // was told of as the table posted it.
        for l in self.signals.process().take_local_posted() {
            if let Some(d) = super::signal::signal_from_linux(l) {
                crate::procnote::post(self.pid, crate::procnote::note::SIGNAL | d);
            }
        }
        !posted.is_empty()
    }

    // -- EVFILT_PROC --------------------------------------------------------------------------

    /// `filt_procattach`: no tracking across forks (ENOTSUP), a process
    /// that exists (ESRCH); EV_CLEAR, the data ignored, and on the
    /// process's list. The exit status is anyone's to ask for who may
    /// signal the process, which here is everyone: gex keeps one identity.
    fn filt_procattach(&mut self, n: KnId) -> u32 {
        use crate::procnote::note;
        let (pid, sfflags) = {
            let k = self.knote(n);
            (k.ident as i32, k.sfflags)
        };
        if sfflags & (note::TRACK | note::TRACKERR | note::CHILD) != 0 {
            self.knote(n).set_error(Errno::EOPNOTSUPP);
            return 0;
        }
        if !self.procs.alive(pid) {
            self.knote(n).set_error(Errno::ESRCH);
            return 0;
        }
        let inbox = std::sync::Arc::clone(&self.dtask.kevents.proc_inbox);
        let bell = self.darwin_timer_bell();
        let id = crate::procnote::listen(
            pid,
            std::sync::Arc::new(move |hint: u32| {
                inbox.lock().unwrap_or_else(|e| e.into_inner()).push((n, hint));
                bell.ring();
            }),
        );
        let k = self.knote(n);
        k.flags |= ev::CLEAR;
        k.sdata = 0;
        k.vnote = Some(id);
        0
    }

    /// `filt_procevent`: the event collected if asked for; an exit (or a
    /// reap, for a knote that waits for one) ends the knote; the exit
    /// status kept for the event's data with NOTE_EXITSTATUS.
    fn filt_procevent(&mut self, n: KnId, hint: u32) -> u32 {
        use crate::procnote::note;
        let event = hint & !note::PDATAMASK;
        let k = self.knote(n);
        if k.sfflags & event != 0 {
            k.fflags |= event;
        }
        if event == note::REAP || (event == note::EXIT && k.sfflags & note::REAP == 0) {
            k.flags |= ev::EOF | ev::ONESHOT;
        }
        if event == note::EXIT {
            k.hook32 = 0;
            if k.sfflags & note::EXITSTATUS != 0 {
                k.fflags |= note::EXITSTATUS;
                k.hook32 |= hint & note::PDATAMASK;
            }
            if k.sfflags & note::EXIT_DETAIL != 0 {
                // No jetsam, decryption or code-signing kill here to say.
                k.fflags |= note::EXIT_DETAIL;
            }
        }
        u32::from(k.fflags != 0)
    }

    /// The process notes the process's EVFILT_PROC knotes were sent: each
    /// knote told; whether any was.
    pub(crate) fn darwin_proc_knotes(&mut self) -> bool {
        let notes = std::mem::take(&mut *self.dtask.kevents.proc_inbox.lock().unwrap_or_else(|e| e.into_inner()));
        for &(n, hint) in &notes {
            if self.knote_exists(n) {
                self.knote_list(&[n], i64::from(hint));
            }
        }
        !notes.is_empty()
    }

    // -- EVFILT_MEMORYSTATUS ------------------------------------------------------------------

    /// `filt_memorystatusattach` and `memorystatus_knote_register`.
    fn filt_memorystatusattach(&mut self, n: KnId) -> u32 {
        let k = self.knote(n);
        k.flags |= ev::CLEAR;
        k.sdata = 0;
        k.ext = [0; 4];
        if k.sfflags & ms::ALL_MASK == k.sfflags {
            self.dtask.kevents.memorystatus_klist.insert(0, n);
        } else {
            self.knote(n).set_error(Errno::EOPNOTSUPP);
        }
        0
    }

    /// `filt_memorystatus`.
    fn filt_memorystatus(&mut self, n: KnId, hint: i64) -> u32 {
        let k = self.knote(n);
        let want = |k: &super::kevent::Knote, f: u32| k.sfflags & f != 0;
        match hint {
            ms::EV_NO_PRESSURE if want(k, ms::PRESSURE_NORMAL) => k.fflags = ms::PRESSURE_NORMAL,
            ms::EV_PRESSURE => match MEMORYSTATUS_VM_PRESSURE_LEVEL {
                Pressure::Warning | Pressure::Urgent if want(k, ms::PRESSURE_WARN) => k.fflags = ms::PRESSURE_WARN,
                Pressure::Critical if want(k, ms::PRESSURE_CRITICAL) => k.fflags = ms::PRESSURE_CRITICAL,
                _ => {}
            },
            ms::EV_LOW_SWAP if want(k, ms::LOW_SWAP) => k.fflags = ms::LOW_SWAP,
            ms::EV_PROC_LIMIT_WARN if want(k, ms::PROC_LIMIT_WARN) => k.fflags = ms::PROC_LIMIT_WARN,
            ms::EV_PROC_LIMIT_CRITICAL if want(k, ms::PROC_LIMIT_CRITICAL) => k.fflags = ms::PROC_LIMIT_CRITICAL,
            _ => {}
        }
        u32::from(k.fflags != 0)
    }

    // -- descriptors -------------------------------------------------------------------------

    /// `filt_fileattach`: `fo_kqfilter` of the knote's descriptor.
    fn filt_fileattach(&mut self, n: KnId) -> u32 {
        let fp = self.knote(n).fp.clone().expect("a descriptor knote's file");
        if let Some(h) = std::sync::Arc::clone(&fp.handle).as_kqueue() {
            return self.kqueue_kqfilter(n, h.id());
        }
        // An anonymous pipe (DTYPE_PIPE); a named one is a fifofs vnode.
        if fp.path.starts_with("pipe:[") && fp.handle.pipe_state().is_some() {
            return self.pipe_kqfilter(n, &fp);
        }
        let file_type = fp.handle.metadata().map(|md| md.file_type);
        if matches!(file_type, Ok(crate::vfs::FileType::Regular | crate::vfs::FileType::Directory | crate::vfs::FileType::Symlink)) {
            return self.vn_kqfilter(n, &fp, file_type.unwrap());
        }
        let name = match self.knote(n).filter {
            evfilt::READ => "EVFILT_READ",
            evfilt::WRITE => "EVFILT_WRITE",
            evfilt::VNODE => "EVFILT_VNODE",
            evfilt::SOCK => "EVFILT_SOCK",
            evfilt::EXCEPT => "EVFILT_EXCEPT",
            _ => "EVFILT_NW_CHANNEL",
        };
        self.darwin_unimplemented(format!("kevent {name} on {}", fp.path));
        self.knote(n).set_error(Errno::EOPNOTSUPP);
        0
    }

    /// `pipe_kqfilter`: a knote on either end of a pipe, on its read
    /// side's list. The wrong filter for an end is neutered: it fires only
    /// when the pipe dies.
    fn pipe_kqfilter(&mut self, n: KnId, fp: &std::sync::Arc<crate::file::OpenFile>) -> u32 {
        let fid = match self.knote(n).filter {
            evfilt::READ if fp.readable => filtid::PIPE_R,
            evfilt::WRITE if fp.writable && fp.handle.pipe_state().is_some_and(|st| st.xnu.is_some()) => filtid::PIPE_W,
            evfilt::WRITE if fp.writable => {
                // A Linux pipe has none of the buffer sizes filt_pipewrite
                // reports from.
                self.darwin_unimplemented(format!("kevent EVFILT_WRITE on {}, a pipe without XNU's rules", fp.path));
                self.knote(n).set_error(Errno::EOPNOTSUPP);
                return 0;
            }
            evfilt::READ | evfilt::WRITE => filtid::PIPE_N,
            _ => {
                self.knote(n).set_error(Errno::EINVAL);
                return 0;
            }
        };
        let k = self.knote(n);
        k.filtid = fid;
        k.seen = fp.handle.wakes();
        self.dtask.kevents.pipe_klist.push(n);
        self.dtask.kevents.pipe_watch.fetch_add(1, std::sync::atomic::Ordering::Release);
        match fid {
            filtid::PIPE_N => self.filt_pipe_draincommon(n),
            filtid::PIPE_R => self.filt_piperead_common(n, None),
            _ => self.filt_pipewrite_common(n, None),
        }
    }

    fn filt_pipedetach(&mut self, n: KnId) {
        let list = &mut self.dtask.kevents.pipe_klist;
        if let Some(i) = list.iter().position(|&x| x == n) {
            list.remove(i);
            self.dtask.kevents.pipe_watch.fetch_sub(1, std::sync::atomic::Ordering::Release);
        }
    }

    fn knote_pipe(&mut self, n: KnId) -> crate::vfs::PipeState {
        let fp = self.knote(n).fp.clone().expect("a pipe knote's file");
        fp.handle.pipe_state().expect("a pipe knote's pipe")
    }

    /// `filt_pipe_draincommon`: either end gone is EOF.
    fn filt_pipe_draincommon(&mut self, n: KnId) -> u32 {
        if self.knote_pipe(n).closed {
            self.knote(n).flags |= ev::EOF;
            return 1;
        }
        0
    }

    /// `filt_pipelowwat`: NOTE_LOWAT's mark, bounded by `MAX_PIPESIZE`
    /// while the buffer is there, or `def`.
    fn filt_pipelowwat(&mut self, n: KnId, def: i64) -> i64 {
        const NOTE_LOWAT: u32 = 0x1;
        let st = self.knote_pipe(n);
        let k = self.knote(n);
        if k.sfflags & NOTE_LOWAT == 0 {
            return def;
        }
        let sdata = k.sdata;
        match st.xnu {
            Some((size, max)) if size != 0 && sdata > max as i64 => max as i64,
            Some(_) => sdata.max(def),
            None => {
                self.darwin_unimplemented("kevent NOTE_LOWAT on a pipe without XNU's rules".into());
                sdata.max(def)
            }
        }
    }

    /// `filt_piperead_common`: readable at the low water mark (one byte, or
    /// NOTE_LOWAT's) or at EOF; the data is what is buffered.
    fn filt_piperead_common(&mut self, n: KnId, kev: Option<&mut Kev>) -> u32 {
        let data = self.knote_pipe(n).buffered as i64;
        let res = if self.filt_pipe_draincommon(n) != 0 {
            1
        } else {
            let lowwat = self.filt_pipelowwat(n, 1);
            u32::from(data >= lowwat)
        };
        if res != 0 {
            if let Some(kev) = kev {
                *kev = self.knote(n).fill_kevent(data);
            }
        }
        res
    }

    /// `filt_pipewrite_common`: writable with `PIPE_BUF` (or NOTE_LOWAT's
    /// mark) free of `MAX_PIPESIZE`, or at EOF; the data is the room.
    fn filt_pipewrite_common(&mut self, n: KnId, kev: Option<&mut Kev>) -> u32 {
        let mut data = 0;
        let res = if self.filt_pipe_draincommon(n) != 0 {
            1
        } else {
            let st = self.knote_pipe(n);
            let (_, max) = st.xnu.expect("a Darwin pipe");
            data = max as i64 - st.buffered as i64;
            let lowwat = self.filt_pipelowwat(n, crate::pipe::xnu::PIPE_BUF as i64);
            u32::from(data >= lowwat)
        };
        if res != 0 {
            if let Some(kev) = kev {
                *kev = self.knote(n).fill_kevent(data);
            }
        }
        res
    }

    /// Tell each pipe knote whose pipe has been woken since it was last
    /// told (the pipe's `KNOTE(&rpipe->pipe_sel.si_note)`); whether any was.
    pub(crate) fn darwin_pipe_knotes(&mut self) -> bool {
        let mut told = false;
        for n in self.dtask.kevents.pipe_klist.clone() {
            if !self.knote_exists(n) {
                continue;
            }
            let fp = self.knote(n).fp.clone().expect("a pipe knote's file");
            let now = fp.handle.wakes();
            if now != self.knote(n).seen {
                self.knote(n).seen = now;
                self.knote_list(&[n], 0);
                told = true;
            }
        }
        told
    }

    /// The vnode notes the process's knotes were sent: each knote told
    /// (`KNOTE(&vp->v_knotes, hint)`); whether any was.
    pub(crate) fn darwin_vnode_knotes(&mut self) -> bool {
        let notes = std::mem::take(&mut *self.dtask.kevents.vnote_inbox.lock().unwrap_or_else(|e| e.into_inner()));
        for &(n, hint) in &notes {
            if self.knote_exists(n) {
                self.knote_list(&[n], i64::from(hint));
            }
        }
        !notes.is_empty()
    }

    /// The vnode an open file is on, as the filesystems name it for their
    /// notes.
    pub(crate) fn darwin_vnote_key(&mut self, fp: &std::sync::Arc<crate::file::OpenFile>) -> Option<crate::inotify::Key> {
        if let Some(k) = fp.darwin_vnote_key.get() {
            return Some(*k);
        }
        let (fs, rel) = self.vfs.watch_target(&fp.path, true).ok()?;
        let key = fs.watch_key(&rel).ok()?.0?;
        Some(*fp.darwin_vnote_key.get_or_init(|| key))
    }

    /// The count of pipe knotes, for a host thread that says when pipes
    /// may have changed.
    pub fn darwin_pipe_watch(&self) -> std::sync::Arc<std::sync::atomic::AtomicUsize> {
        std::sync::Arc::clone(&self.dtask.kevents.pipe_watch)
    }

    /// `vn_kqfilter`: EVFILT_READ and EVFILT_WRITE on a regular file;
    /// another kind of vnode refuses them.
    fn vn_kqfilter(&mut self, n: KnId, fp: &std::sync::Arc<crate::file::OpenFile>, ty: crate::vfs::FileType) -> u32 {
        match self.knote(n).filter {
            evfilt::READ | evfilt::WRITE if ty == crate::vfs::FileType::Regular => {}
            evfilt::READ | evfilt::WRITE => {
                self.knote(n).set_error(Errno::EINVAL);
                return 0;
            }
            evfilt::VNODE => {}
            _ => {
                self.knote(n).set_error(Errno::EINVAL);
                return 0;
            }
        }
        // On the vnode's list: its notes come to the process to tell.
        let Some(key) = self.darwin_vnote_key(fp) else {
            self.darwin_unimplemented(format!("kevent on {}, whose filesystem names no vnode", fp.path));
            self.knote(n).set_error(Errno::EOPNOTSUPP);
            return 0;
        };
        let inbox = std::sync::Arc::clone(&self.dtask.kevents.vnote_inbox);
        let bell = self.darwin_timer_bell();
        let id = crate::vnote::listen(
            key,
            std::sync::Arc::new(move |notes: u32| {
                inbox.lock().unwrap_or_else(|e| e.into_inner()).push((n, notes));
                bell.ring();
            }),
        );
        let k = self.knote(n);
        k.filtid = filtid::VN;
        k.vnote = Some(id);
        self.filt_vnode_common(n, 0, None)
    }

    /// `filt_vnode_common`: EVFILT_READ readable while the file goes past
    /// the descriptor's offset (the data is how far), EVFILT_WRITE always
    /// writable (data 1), both looked at whatever the note; EVFILT_VNODE
    /// collects the notes (all of `hint`, if any is asked for).
    fn filt_vnode_common(&mut self, n: KnId, hint: u32, kev: Option<&mut Kev>) -> u32 {
        const EV_POLL: u16 = 0x1000;
        let fp = self.knote(n).fp.clone().expect("a vnode knote's file");
        let k = self.knote(n);
        let (data, activate) = match k.filter {
            evfilt::READ => {
                let data = if k.flags & EV_POLL != 0 {
                    1
                } else {
                    let size = fp.handle.metadata().map_or(0, |md| md.size);
                    (size as i128 - fp.offset() as i128).clamp(i64::MIN as i128, i64::MAX as i128) as i64
                };
                (data, data != 0)
            }
            evfilt::WRITE => (1, true),
            _ => {
                if k.sfflags & hint != 0 {
                    k.fflags |= hint;
                }
                (0, k.fflags != 0)
            }
        };
        let activate = u32::from(activate);
        if activate != 0 {
            if let Some(kev) = kev {
                *kev = self.knote(n).fill_kevent(data);
            }
        }
        activate
    }

    /// `kqueue_kqfilter`: a knote on a file kqueue's descriptor, readable
    /// while it has events.
    fn kqueue_kqfilter(&mut self, n: KnId, kqf: KqId) -> u32 {
        const MAX_NESTED_KQ: u16 = 10;
        let parent = self.knote(n).kq;
        if parent == kqf || self.knote(n).filter != evfilt::READ {
            self.knote(n).set_error(Errno::EINVAL);
            return 0;
        }
        if self.kq_state(parent) & (kq::WORKQ | kq::WORKLOOP) == 0 {
            let (plevel0, level) = (self.kq(parent).level, self.kq(kqf).level);
            if plevel0 > 0 && plevel0 < level {
                self.knote(n).set_error(Errno::EINVAL);
                return 0;
            }
            let mut plevel = if plevel0 == 0 { 2 } else { plevel0 };
            if plevel < level + 1 {
                if level + 1 > MAX_NESTED_KQ {
                    self.knote(n).set_error(Errno::EINVAL);
                    return 0;
                }
                plevel = level + 1;
            }
            self.kq(parent).level = plevel;
        }
        self.knote(n).filtid = filtid::KQREAD;
        self.knote(n).kqread = Some(kqf);
        let q = self.kq(kqf);
        q.sel.insert(0, n);
        if q.level == 0 {
            q.level = 1;
        }
        u32::from(q.count > 0)
    }

    fn filt_kqdetach(&mut self, n: KnId) {
        if let Some(kqf) = self.knote(n).kqread.take() {
            if self.kq_exists(kqf) {
                self.kq(kqf).sel.retain(|&x| x != n);
            }
        }
    }

    /// `filt_kqueue`, `filt_kqtouch`.
    fn filt_kqueue(&mut self, n: KnId) -> u32 {
        let kqf = self.knote(n).kqread.expect("a kqread knote's kqueue");
        u32::from(self.kq_exists(kqf) && self.kq(kqf).count > 0)
    }

    fn filt_kqprocess(&mut self, n: KnId, kev: &mut Kev) -> u32 {
        let kqf = self.knote(n).kqread.expect("a kqread knote's kqueue");
        let count = if self.kq_exists(kqf) { self.kq(kqf).count } else { 0 };
        if count == 0 {
            return 0;
        }
        *kev = self.knote(n).fill_kevent(i64::from(count));
        1
    }
}
