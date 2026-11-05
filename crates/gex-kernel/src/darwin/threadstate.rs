//! `thread_get_state` and `thread_set_state` (`osfmk/kern/thread_act.c`,
//! `osfmk/arm64/status.c`) for a 64-bit thread: its general registers,
//! NEON and VFP registers, debug registers and page-in error, read from
//! and written to the register context it left user space with. Another
//! thread is held and stopped first (`thread_stop`): at once if it is off
//! its CPU, else the reply waits until it is.

use gex_abi::ctx;

use super::kobject::Deferred;
use crate::syscalls::Kernel;
use crate::GuestMem;

/// `thread_state_flavor_t`s (`mach/arm/thread_status.h`).
mod flavor {
    pub const FLAVOR_LIST: i32 = 0;
    pub const ARM_THREAD_STATE: i32 = 1;
    pub const ARM_VFP_STATE: i32 = 2;
    pub const ARM_EXCEPTION_STATE: i32 = 3;
    pub const ARM_DEBUG_STATE: i32 = 4;
    pub const ARM_THREAD_STATE64: i32 = 6;
    pub const ARM_EXCEPTION_STATE64: i32 = 7;
    pub const ARM_THREAD_STATE32: i32 = 9;
    pub const ARM_DEBUG_STATE32: i32 = 14;
    pub const ARM_DEBUG_STATE64: i32 = 15;
    pub const ARM_NEON_STATE: i32 = 16;
    pub const ARM_NEON_STATE64: i32 = 17;
    pub const ARM_PAGEIN_STATE: i32 = 27;
    pub const FLAVOR_LIST_NEW: i32 = 128;
    pub const FLAVOR_LIST_10_15: i32 = 129;
}

/// The flavors' counts, in words.
const THREAD_STATE64_COUNT: u32 = 68;
const UNIFIED_THREAD_STATE_COUNT: u32 = 70;
const THREAD_STATE32_COUNT: u32 = 17;
/// `sizeof(arm_neon_state64_t)` in words: 32 128-bit registers, fpsr and
/// fpcr, and the padding to its 16-byte alignment.
const NEON_STATE64_COUNT: u32 = 132;
const VFP_STATE_COUNT: u32 = 65;
const VFPV2_STATE_COUNT: u32 = 33;
const DEBUG_STATE64_COUNT: u32 = 130;
const PAGEIN_STATE_COUNT: u32 = 1;

const KERN_PROTECTION_FAILURE: i32 = 2;
const KERN_INVALID_ARGUMENT: i32 = 4;
const KERN_TERMINATED: i32 = 37;

/// `PSR64_USER_MASK` (NZCV): what a set copies of `cpsr`.
const PSR64_USER_MASK: u64 = 0xf000_0000;

fn words(b: &[u8]) -> Vec<u32> {
    b.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect()
}

impl Kernel {
    /// `machine_thread_get_state` for a 64-bit thread whose context is at
    /// `c`: the words and the count it answers, or the error.
    fn machine_thread_get_state(&self, m: &GuestMem<'_>, tid: i32, c: u64, fl: i32, count: u32) -> Result<Vec<u32>, i32> {
        let need = |n: u32| if count < n { Err(KERN_INVALID_ARGUMENT) } else { Ok(()) };
        let rd = |o: usize| m.read_u64(c + o as u64).unwrap_or(0);
        let state64 = || -> Vec<u32> {
            let mut w = Vec::with_capacity(THREAD_STATE64_COUNT as usize);
            let mut push = |v: u64| {
                w.push(v as u32);
                w.push((v >> 32) as u32);
            };
            for i in 0..29u8 {
                push(rd(ctx::x(i)));
            }
            push(rd(ctx::x(29)));
            push(rd(ctx::x(30)));
            push(rd(ctx::SP));
            push(rd(ctx::PC));
            w.push(crate::signal::read_pstate(m, c).unwrap_or(0) as u32);
            w.push(0);
            w
        };
        // The NEON registers and fpsr, fpcr (arm_neon_saved_state64).
        let neon = || -> Vec<u32> {
            let mut b = Vec::with_capacity(520);
            for n in 0..32u8 {
                b.extend_from_slice(m.read(c + ctx::v(n) as u64, 16).map(|s| s.to_vec()).unwrap_or_else(|_| vec![0; 16]).as_slice());
            }
            b.extend_from_slice(&m.read_u32(c + ctx::FPSR as u64).unwrap_or(0).to_le_bytes());
            b.extend_from_slice(&m.read_u32(c + ctx::FPCR as u64).unwrap_or(0).to_le_bytes());
            b.extend_from_slice(&[0u8; 8]);
            words(&b)
        };
        Ok(match fl {
            flavor::FLAVOR_LIST => {
                need(4)?;
                vec![1, 2, 3, 4]
            }
            flavor::FLAVOR_LIST_NEW => {
                need(4)?;
                vec![1, 2, 7, 15]
            }
            flavor::FLAVOR_LIST_10_15 => {
                need(5)?;
                vec![1, 2, 7, 15, 27]
            }
            flavor::ARM_THREAD_STATE => {
                // Fewer words than the unified state: a 32-bit client's.
                if count < UNIFIED_THREAD_STATE_COUNT {
                    need(THREAD_STATE32_COUNT)?;
                    return Err(KERN_INVALID_ARGUMENT);
                }
                let mut w = vec![flavor::ARM_THREAD_STATE64 as u32, THREAD_STATE64_COUNT];
                w.extend(state64());
                w
            }
            flavor::ARM_THREAD_STATE64 => {
                need(THREAD_STATE64_COUNT)?;
                state64()
            }
            flavor::ARM_THREAD_STATE32 | flavor::ARM_NEON_STATE => return Err(KERN_INVALID_ARGUMENT),
            flavor::ARM_EXCEPTION_STATE => {
                need(3)?;
                return Err(KERN_INVALID_ARGUMENT);
            }
            flavor::ARM_DEBUG_STATE => {
                need(64)?;
                return Err(KERN_INVALID_ARGUMENT);
            }
            flavor::ARM_DEBUG_STATE32 => {
                need(66)?;
                return Err(KERN_INVALID_ARGUMENT);
            }
            flavor::ARM_DEBUG_STATE64 => {
                need(DEBUG_STATE64_COUNT)?;
                // find_debug_state64: none is kept (one with anything enabled
                // is refused, one with nothing is freed).
                vec![0; DEBUG_STATE64_COUNT as usize]
            }
            // The 32-bit view of the NEON registers: s0..s(max-1), then the
            // word after them (bcopy of max + 1 words).
            flavor::ARM_VFP_STATE => {
                let n = if count >= VFP_STATE_COUNT {
                    VFP_STATE_COUNT
                } else if count >= VFPV2_STATE_COUNT {
                    VFPV2_STATE_COUNT
                } else {
                    return Err(KERN_INVALID_ARGUMENT);
                };
                neon()[..n as usize].to_vec()
            }
            flavor::ARM_NEON_STATE64 => {
                need(NEON_STATE64_COUNT)?;
                neon()
            }
            flavor::ARM_PAGEIN_STATE => {
                need(PAGEIN_STATE_COUNT)?;
                vec![0]
            }
            _ => return Err(KERN_INVALID_ARGUMENT),
        })
    }

    /// `machine_thread_set_state` for a 64-bit thread whose context is at
    /// `c`; a change to its general registers sends it back to user space
    /// at its (new) pc.
    fn machine_thread_set_state(&mut self, m: &mut GuestMem<'_>, tid: i32, c: u64, fl: i32, w: &[u32]) -> i32 {
        let n = w.len() as u32;
        let u64_at = |i: usize| u64::from(w[i]) | (u64::from(w[i + 1]) << 32);
        let mut set_state64 = |k: &mut Kernel, m: &mut GuestMem<'_>, s: &[u32]| {
            let at = |i: usize| u64::from(s[i]) | (u64::from(s[i + 1]) << 32);
            for i in 0..29u8 {
                let _ = m.write_u64(c + ctx::x(i) as u64, at(2 * i as usize));
            }
            let _ = m.write_u64(c + ctx::x(29) as u64, at(58));
            let _ = m.write_u64(c + ctx::x(30) as u64, at(60));
            let _ = m.write_u64(c + ctx::SP as u64, at(62));
            let _ = m.write_u64(c + ctx::PC as u64, at(64));
            // NZCV copied; the mode reset to EL0; the rest kept.
            let _ = crate::signal::write_pstate(m, c, u64::from(s[66]) & PSR64_USER_MASK);
            k.dtask.threads.map.entry(tid).or_default().redirect = true;
        };
        match fl {
            flavor::ARM_THREAD_STATE => {
                if n < UNIFIED_THREAD_STATE_COUNT {
                    // A 32-bit thread state, for a 64-bit thread.
                    return KERN_INVALID_ARGUMENT;
                }
                if w[0] as i32 != flavor::ARM_THREAD_STATE64 || w[1] != THREAD_STATE64_COUNT {
                    return KERN_INVALID_ARGUMENT;
                }
                set_state64(self, m, &w[2..]);
            }
            flavor::ARM_THREAD_STATE64 => {
                if n != THREAD_STATE64_COUNT {
                    return KERN_INVALID_ARGUMENT;
                }
                set_state64(self, m, w);
            }
            flavor::ARM_NEON_STATE64 => {
                if n != NEON_STATE64_COUNT {
                    return KERN_INVALID_ARGUMENT;
                }
                for r in 0..32u8 {
                    let b: Vec<u8> = w[4 * r as usize..4 * r as usize + 4].iter().flat_map(|x| x.to_le_bytes()).collect();
                    let _ = m.write(c + ctx::v(r) as u64, &b);
                }
                let _ = m.write_u32(c + ctx::FPSR as u64, w[128]);
                let _ = m.write_u32(c + ctx::FPCR as u64, w[129]);
            }
            flavor::ARM_DEBUG_STATE64 => {
                const TYPE_MASK: u64 = 1 << 21;
                const LINKED_MASK: u64 = 1 << 20;
                const ENABLE: u64 = 1;
                const MDSCR_SS: u64 = 1;
                if n != DEBUG_STATE64_COUNT {
                    return KERN_INVALID_ARGUMENT;
                }
                // bvr[16], bcr[16], wvr[16], wcr[16], mdscr_el1, as u64s.
                let (bcr, wcr) = (|i: usize| u64_at(32 + 2 * i), |i: usize| u64_at(96 + 2 * i));
                let mut enabled = u64_at(128) & MDSCR_SS != 0;
                for i in 0..16 {
                    // No context IDs, no linked breakpoints.
                    if bcr(i) & TYPE_MASK != 0 || bcr(i) & LINKED_MASK != 0 || wcr(i) & LINKED_MASK != 0 {
                        return KERN_PROTECTION_FAILURE;
                    }
                    if bcr(i) & ENABLE != 0 || wcr(i) & ENABLE != 0 {
                        enabled = true;
                    }
                }
                if enabled {
                    self.darwin_unimplemented("thread_set_state(ARM_DEBUG_STATE64) with a breakpoint, watchpoint or single step enabled (hardware debug registers)".into());
                    return KERN_INVALID_ARGUMENT;
                }
                // free_debug_state: there is none to free.
            }
            // Accepted and kept nowhere, as status.c does.
            flavor::ARM_EXCEPTION_STATE64 => {
                if n != 4 {
                    return KERN_INVALID_ARGUMENT;
                }
            }
            flavor::ARM_VFP_STATE => {
                if n != VFP_STATE_COUNT && n != VFPV2_STATE_COUNT {
                    return KERN_INVALID_ARGUMENT;
                }
                self.darwin_unimplemented("thread_set_state(ARM_VFP_STATE) of a 64-bit thread (its NEON state marked 32-bit)".into());
                return KERN_INVALID_ARGUMENT;
            }
            _ => return KERN_INVALID_ARGUMENT,
        }
        0
    }

    /// `thread_get_state(thread, flavor, &count)` and `thread_set_state`
    /// (`words` given): answered once the thread is stopped, the caller
    /// itself or one off its CPU on the call's way out, another held
    /// until it stops.
    pub(crate) fn darwin_thread_state(&mut self, tid: i32, fl: i32, count: u32, set: Option<Vec<u32>>) -> super::kobject::Reply {
        use super::kobject::Reply;
        if !self.darwin_thread_alive(tid) {
            return Reply::err(KERN_TERMINATED);
        }
        if fl == flavor::ARM_EXCEPTION_STATE64 && set.is_none() && count >= 4 {
            let mut r = Reply::err(KERN_INVALID_ARGUMENT);
            r.unimplemented = Some("thread_get_state(ARM_EXCEPTION_STATE64) (the saved exception's esr and far)".into());
            return r;
        }
        let held = tid != self.tid && !self.darwin_offcpu(tid);
        if held {
            self.dtask.threads.map.entry(tid).or_default().stop_holds += 1;
        }
        let mut r = Reply::ok(Vec::new());
        r.defer = Some((tid, match set {
            Some(state) => Deferred::SetState { flavor: fl, state, held },
            None => Deferred::GetState { flavor: fl, count, held },
        }));
        r
    }

    /// The state read or written, the thread stopped.
    pub(crate) fn darwin_thread_state_now(&mut self, m: &mut GuestMem<'_>, tid: i32, fl: i32, count: u32, set: Option<Vec<u32>>) -> super::kobject::Reply {
        use super::kobject::Reply;
        let Some(c) = self.dtask.threads.map.get(&tid).map(|t| t.ctx_addr).filter(|&c| c != 0) else {
            let mut r = Reply::err(KERN_INVALID_ARGUMENT);
            r.unimplemented = Some(format!("thread_get_state of thread {tid}, whose register context is not known"));
            return r;
        };
        match set {
            Some(w) => Reply::err(self.machine_thread_set_state(m, tid, c, fl, &w)),
            None => match self.machine_thread_get_state(m, tid, c, fl, count) {
                Ok(w) => {
                    let mut out = (w.len() as u32).to_le_bytes().to_vec();
                    for x in w {
                        out.extend_from_slice(&x.to_le_bytes());
                    }
                    Reply::ok(out)
                }
                Err(e) => Reply::err(e),
            },
        }
    }
}
