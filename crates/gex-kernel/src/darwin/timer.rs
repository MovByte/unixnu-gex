//! The kernel's timers: deadlines at which the kernel itself must act
//! (a Mach timer's expiry message, a kevent timer firing).
//!
//! Nothing runs the kernel by itself here; it runs when a thread enters
//! it. So every Darwin wait sleeps no later than the earliest timer
//! ([`super::wait`]), and the thread that wakes for it fires what is due.

use crate::syscalls::Kernel;
use crate::GuestMem;
use std::collections::BTreeMap;
use std::time::Instant;

/// What a timer does when it fires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {}

/// The armed timers, by deadline (and a sequence number, so two at the
/// same instant both stay).
#[derive(Debug, Default)]
pub struct Timers {
    armed: BTreeMap<(Instant, u64), Action>,
    next: u64,
}

impl Timers {
    /// Arm `action` for `at`; the key it can be cancelled by.
    pub fn arm(&mut self, at: Instant, action: Action) -> (Instant, u64) {
        self.next += 1;
        let key = (at, self.next);
        self.armed.insert(key, action);
        key
    }

    /// Cancel the timer armed as `key`; whether it was still armed.
    pub fn cancel(&mut self, key: (Instant, u64)) -> bool {
        self.armed.remove(&key).is_some()
    }
}

impl Kernel {
    /// The earliest armed timer's deadline.
    pub(crate) fn darwin_next_timer(&self) -> Option<Instant> {
        self.dtask.timers.armed.keys().next().map(|k| k.0)
    }

    /// Fire every timer that is due.
    pub(crate) fn darwin_fire_timers(&mut self, _m: &mut GuestMem<'_>) {
        let now = Instant::now();
        while let Some((&key, _)) = self.dtask.timers.armed.first_key_value() {
            if key.0 > now {
                break;
            }
            match self.dtask.timers.armed.remove(&key).expect("first key") {}
        }
    }
}
