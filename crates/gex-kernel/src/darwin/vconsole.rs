//! The kernel's video console (XNU's `osfmk/console/video_console.c`) as
//! the platform expert drives it: `IOPlatformExpert::setConsoleInfo` is
//! `PE_initialize_console` (`pexpert/arm/pe_init.c`), which hands the
//! console a framebuffer (graphics mode) and acquires or releases the
//! screen. The framebuffer's console mode ([`super::iomfb`],
//! 0xfffffff00678c44c) is its only caller after boot: it gives the
//! displayed surface and acquires the screen, which starts the progress
//! spinner after its delay, and releases it when a client swaps again.
//!
//! The boot left the console in graphics mode (`PE_create_console`: the
//! bootloader's logo is up, `v_display`), acquired (`kernel_bootstrap_thread`
//! after `PE_init_iokit`), with no spinner (iOS sets `show_progress` only
//! for `-progress`, which this boot does not pass) and the first acquire
//! delay (`kProgressAcquireDelay`, none). The first release sets up the
//! default spinner and makes the next acquire wait twelve hours
//! (`kProgressReacquireDelay`) unless `kern.progressoptions` says otherwise.
//!
//! Drawing is not modelled: the spinner's thread call (`vc_progress_task`,
//! which blits the gear onto the console's surface) and the text console
//! (`gc_enable`) are reported when they would run.

use std::sync::Mutex;

/// `PE_Video` as the framebuffer fills it: the surface whose memory is the
/// console's (its kernel mapping, `v_baseAddr`, plus `v_offset`), the bytes
/// a row, the width and height (the layer's source), the depth, and the
/// length of the memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Video {
    pub surface: u32,
    pub offset: u64,
    pub row_bytes: u64,
    pub width: u64,
    pub height: u64,
    pub depth: u64,
    pub length: u64,
}

/// `PE_initialize_console`'s operations (pexpert.h) that reach it here.
pub mod op {
    pub const GRAPHICS_MODE: u32 = 1;
    pub const ACQUIRE_SCREEN: u32 = 4;
    pub const RELEASE_SCREEN: u32 = 5;
}

/// `vc_progress_user_options.options` bits (video_console.h).
mod opt {
    pub const DARK_REBOOT: u32 = 0x1;
    pub const ACQUIRE_IMMEDIATE: u32 = 0x2;
    pub const DARK_BACKGROUND: u32 = 0x8;
    pub const LIGHT_BACKGROUND: u32 = 0x10;
}

/// `kProgressReacquireDelay`, in seconds.
const REACQUIRE_DELAY: u64 = 12 * 60 * 60;

/// `sizeof(struct vc_progress_user_options)`: the options, the spinner's
/// position and eight reserved words.
pub const USER_OPTIONS_SIZE: usize = 44;

struct State {
    /// `vinfo`'s framebuffer, once the framebuffer gave one.
    vinfo: Option<Video>,
    graphics_boot: bool,
    desire_text: bool,
    acquired: bool,
    /// `vc_progress` set up (`vc_progress_initialize`).
    progress: bool,
    /// `vc_progress_enable` and the thread call's deadline.
    progress_enable: bool,
    progress_deadline: u64,
    /// `vc_acquire_delay`, in seconds.
    acquire_delay: u64,
    progress_white: Option<bool>,
    /// `vc_user_options`, which `kern.progressoptions` and
    /// `kern.consoleoptions` set and an acquire takes.
    user_options: [u8; USER_OPTIONS_SIZE],
    progress_options: [u8; USER_OPTIONS_SIZE],
}

static STATE: Mutex<State> = Mutex::new(State {
    vinfo: None,
    graphics_boot: true,
    desire_text: false,
    acquired: true,
    progress: false,
    progress_enable: false,
    progress_deadline: 0,
    acquire_delay: 0,
    progress_white: None,
    user_options: [0; USER_OPTIONS_SIZE],
    progress_options: [0; USER_OPTIONS_SIZE],
});

fn state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    f(&mut STATE.lock().unwrap_or_else(|e| e.into_inner()))
}

/// `PE_initialize_console(info, op)`, at `now`: a release first sets up the
/// default spinner if none is (`vc_progress_initialize`); then
/// `initialize_screen`. `Err` says what is not modelled that it would do.
pub fn initialize_console(info: Option<Video>, op: u32, now: u64) -> Result<(), String> {
    state(|s| {
        if op == op::RELEASE_SCREEN && !s.progress {
            s.progress = true;
        }
        s.initialize_screen(info, op, now)
    })
}

impl State {
    /// `initialize_screen`: a framebuffer given replaces the console's
    /// (`gc_initialize`), then the operation.
    fn initialize_screen(&mut self, info: Option<Video>, op: u32, now: u64) -> Result<(), String> {
        if let Some(v) = info {
            self.vinfo = Some(v);
        }
        let graphics_now = self.graphics_boot && !self.desire_text;
        match op {
            op::GRAPHICS_MODE => {
                self.graphics_boot = true;
                self.desire_text = false;
            }
            op::ACQUIRE_SCREEN => {
                if self.acquired {
                    return Ok(());
                }
                self.progress_options = std::mem::replace(&mut self.user_options, [0; USER_OPTIONS_SIZE]);
                let options = u32::from_le_bytes(self.progress_options[..4].try_into().unwrap());
                let delay = if options & opt::ACQUIRE_IMMEDIATE != 0 {
                    0
                } else if options & opt::DARK_REBOOT != 0 {
                    120
                } else {
                    self.acquire_delay
                };
                if options & opt::DARK_BACKGROUND != 0 {
                    self.progress_white = Some(true);
                } else if options & opt::LIGHT_BACKGROUND != 0 {
                    self.progress_white = Some(false);
                }
                self.progress_set(graphics_now, delay, now);
                self.acquired = true;
                self.desire_text = false;
                // gc_enable(!graphics_now): the text console on the screen.
                if !graphics_now {
                    return Err("the video console's text mode on the framebuffer's surface (gc_enable)".to_string());
                }
            }
            op::RELEASE_SCREEN => {
                self.acquired = false;
                self.desire_text = false;
                if self.graphics_boot {
                    self.progress_set(false, 0, now);
                    self.acquire_delay = REACQUIRE_DELAY;
                    self.progress_white = Some(true);
                }
            }
            _ => return Err(format!("PE_initialize_console operation {op}")),
        }
        Ok(())
    }

    /// `vc_progress_set(enable, delay)`: with a spinner set up, enabling
    /// arms its thread call `delay` seconds on; disabling cancels it.
    fn progress_set(&mut self, enable: bool, delay: u64, now: u64) {
        if !self.progress || self.progress_enable == enable {
            return;
        }
        self.progress_enable = enable;
        if enable {
            let (numer, denom) = super::mach::TIMEBASE;
            self.progress_deadline = now + delay * 1_000_000_000 * u64::from(denom) / u64::from(numer);
        }
    }
}

/// What the console would draw by `now` that is not modelled: the
/// spinner's first frame once its thread call is due.
pub fn due(now: u64) -> Option<String> {
    state(|s| {
        (s.progress_enable && s.progress_deadline <= now).then(|| {
            s.progress_enable = false;
            let options = u32::from_le_bytes(s.progress_options[..4].try_into().unwrap());
            format!("the video console's progress spinner (vc_progress_task) drawing on {:?} (options {options:#x}, a white spinner {:?})", s.vinfo, s.progress_white)
        })
    })
}

/// `kern.progressoptions` (IOPMrootDomain's `sysctl_progressoptions`):
/// `vc_user_options` whole.
pub fn user_options() -> [u8; USER_OPTIONS_SIZE] {
    state(|s| s.user_options)
}

pub fn set_user_options(v: [u8; USER_OPTIONS_SIZE]) {
    state(|s| s.user_options = v);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_then_acquire_waits_twelve_hours() {
        let v = Video { surface: 7, offset: 0, row_bytes: 4096, width: 1024, height: 768, depth: 32, length: 4096 * 768 };
        // The boot acquired the screen already: an acquire then does nothing.
        initialize_console(None, op::ACQUIRE_SCREEN, 0).unwrap();
        assert!(due(u64::MAX).is_none());
        initialize_console(None, op::RELEASE_SCREEN, 0).unwrap();
        initialize_console(Some(v), op::GRAPHICS_MODE, 0).unwrap();
        initialize_console(None, op::ACQUIRE_SCREEN, 0).unwrap();
        let (numer, denom) = super::super::mach::TIMEBASE;
        let hours = REACQUIRE_DELAY * 1_000_000_000 * u64::from(denom) / u64::from(numer);
        assert!(due(hours - 1).is_none());
        assert!(due(hours).is_some());
    }
}
