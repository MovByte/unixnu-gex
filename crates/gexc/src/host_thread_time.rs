//! Guest threads' running time, for the Darwin kernel's workqueue quantum
//! (`gex_kernel::darwin::workq::set_thread_time`).
//!
//! Each guest thread's host thread is noted when it starts; the time is read
//! from another thread (the kernel's thread calls) through the host's
//! per-thread clock: the Mach thread port's `thread_info` on macOS,
//! `pthread_getcpuclockid` on Linux.

use std::collections::HashMap;
use std::sync::Mutex;

#[cfg(target_os = "macos")]
type Handle = libc::mach_port_t;
#[cfg(target_os = "linux")]
type Handle = libc::clockid_t;

static THREADS: Mutex<Option<HashMap<i32, Handle>>> = Mutex::new(None);

#[cfg(target_os = "linux")]
extern "C" {
    fn pthread_getcpuclockid(thread: libc::pthread_t, clock_id: *mut libc::clockid_t) -> libc::c_int;
}

/// Hand the kernel this host's per-thread clocks.
pub fn install() {
    gex_kernel::darwin::workq::set_thread_time(register, unregister, runtime);
}

/// Note the calling host thread as guest thread `tid`'s.
fn register(tid: i32) {
    #[cfg(target_os = "macos")]
    // SAFETY: pthread_self always names the calling thread, whose Mach port
    // pthread_mach_thread_np returns without taking a reference.
    let h = unsafe { libc::pthread_mach_thread_np(libc::pthread_self()) };
    #[cfg(target_os = "linux")]
    let h = {
        let mut c: libc::clockid_t = 0;
        // SAFETY: the calling thread's own clock, into a local.
        if unsafe { pthread_getcpuclockid(libc::pthread_self(), &mut c) } != 0 {
            return;
        }
        c
    };
    THREADS.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_with(HashMap::new).insert(tid, h);
}

/// Forget guest thread `tid`'s host thread, which is ending.
fn unregister(tid: i32) {
    if let Some(m) = THREADS.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
        m.remove(&tid);
    }
}

/// Guest thread `tid`'s running time in nanoseconds.
fn runtime(tid: i32) -> Option<u64> {
    let h = *THREADS.lock().unwrap_or_else(|e| e.into_inner()).as_ref()?.get(&tid)?;
    #[cfg(target_os = "macos")]
    {
        let mut info = std::mem::MaybeUninit::<libc::thread_basic_info>::zeroed();
        let mut count = libc::THREAD_BASIC_INFO_COUNT;
        // SAFETY: the port names a live registered thread; the out buffer is
        // a thread_basic_info, count words long.
        let r = unsafe { libc::thread_info(h, libc::THREAD_BASIC_INFO as u32, info.as_mut_ptr() as *mut libc::integer_t, &mut count) };
        if r != 0 {
            return None;
        }
        // SAFETY: thread_info filled it.
        let info = unsafe { info.assume_init() };
        let us = |t: libc::time_value_t| t.seconds as u64 * 1_000_000 + t.microseconds as u64;
        Some((us(info.user_time) + us(info.system_time)) * 1000)
    }
    #[cfg(target_os = "linux")]
    {
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: a thread CPU clock and a local timespec.
        if unsafe { libc::clock_gettime(h, &mut ts) } != 0 {
            return None;
        }
        Some(ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64)
    }
}
