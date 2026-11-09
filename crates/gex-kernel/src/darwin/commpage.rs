//! The contents of Darwin's commpage (XNU's `osfmk/arm/cpu_capabilities.h`).
//!
//! libsystem and dyld read it at constant addresses instead of asking the
//! kernel: the CPU's features, its count, the page size, whether kdebug
//! tracing is on, the time bases. The read-write page holds them all, with
//! legacy copies of the few the read-only page has at the same offsets.
//! The time of day is zero until the first `gettimeofday`, and is older
//! than a second whenever none has been made for that long: the fast path
//! falls back to the system call, which refreshes it.

use std::sync::atomic::{fence, Ordering};

/// Field offsets from the start of either page.
pub mod off {
    pub const SIGNATURE: usize = 0x000;
    pub const CPU_CAPABILITIES64: usize = 0x010;
    pub const VERSION: usize = 0x01e;
    pub const CPU_CAPABILITIES: usize = 0x020;
    pub const NCPUS: usize = 0x022;
    pub const USER_PAGE_SHIFT_32: usize = 0x024;
    pub const USER_PAGE_SHIFT_64: usize = 0x025;
    pub const CACHE_LINESIZE: usize = 0x026;
    pub const CPU_CLUSTERS: usize = 0x02f;
    pub const ACTIVE_CPUS: usize = 0x034;
    pub const PHYSICAL_CPUS: usize = 0x035;
    pub const LOGICAL_CPUS: usize = 0x036;
    pub const KERNEL_PAGE_SHIFT: usize = 0x037;
    pub const MEMORY_SIZE: usize = 0x038;
    pub const CPUFAMILY: usize = 0x080;
    pub const DEV_FIRM: usize = 0x084;
    pub const TIMEBASE_OFFSET: usize = 0x088;
    pub const USER_TIMEBASE: usize = 0x090;
    pub const CONT_TIMEBASE: usize = 0x098;
    pub const BOOTTIME_USEC: usize = 0x0a0;
    pub const APPROX_TIME: usize = 0x0c0;
    pub const APPROX_TIME_SUPPORTED: usize = 0x0c8;
    pub const KDEBUG_ENABLE: usize = 0x100;
    pub const NEWTIMEOFDAY_DATA: usize = 0x120;
    pub const REMOTETIME_PARAMS: usize = 0x148;
    pub const CPU_QUIESCENT_COUNTER: usize = 0x180;
    pub const ASB_TARGET_VALUE: usize = 0x320;
    pub const ASB_TARGET_ADDRESS: usize = 0x328;
    pub const ASB_TARGET_KERN_VALUE: usize = 0x330;
    pub const ASB_TARGET_KERN_ADDRESS: usize = 0x338;
}

pub const PAGE_LEN: usize = 0x4000;
pub const THIS_VERSION: u16 = 3;

/// `kHas*` capability bits gex's translator implements.
pub mod cap {
    pub const CACHE64: u64 = 0x20;
    pub const FAST_TLS: u64 = 0x80;
    pub const ADV_SIMD: u64 = 0x100;
    pub const VFP: u64 = 0x400;
    pub const EVENT: u64 = 0x1000;
    pub const FMA: u64 = 0x2000;
    pub const UP: u64 = 0x8000;
    pub const NUM_CPUS_SHIFT: u32 = 16;
    pub const LSE: u64 = 0x0200_0000;
    pub const CRC32: u64 = 0x0400_0000;
}

/// `CPUFAMILY_ARM_HURRICANE`: the A10X of the iPad7,1 the profile runs.
pub const CPUFAMILY_ARM_HURRICANE: u32 = 0x67ce_ee93;

/// `USER_TIMEBASE_SPEC`: the A10X has neither `ACNTVCT` nor ARMv8.6's
/// self-synchronized counter, so a program reads `CNTVCT_EL0` after an `isb`.
const USER_TIMEBASE_SPEC: u8 = 1;

/// `BT_RESET_SENTINEL_TS`: no remote time base yet.
const BT_RESET_SENTINEL_TS: u64 = !3;

/// `MACH_VM_MAX_ADDRESS` and `VM_MIN_KERNEL_ADDRESS` on an H9 with KTRR.
const MACH_VM_MAX_ADDRESS: u64 = 0x0f_c000_0000;
const VM_MIN_KERNEL_ADDRESS: u64 = 0u64.wrapping_sub(144 << 30);

/// The device's time base in ticks a second (`ticks_per_sec`).
const TICKS_PER_SEC: u64 = 1_000_000_000 * super::mach::TIMEBASE.1 as u64 / super::mach::TIMEBASE.0 as u64;

/// `Ticks_scale`: the fraction of a second, as a 64-bit binary fraction,
/// that one tick is (`clock_calend.tick_scale_x` with no adjustment).
const TICK_SCALE: u64 = ((1u64 << 63) / TICKS_PER_SEC) * 2;

/// The commpage's two pages for a machine with `ncpus` CPUs and `memory`
/// bytes, in [`placements`] order: the read-only page and the read-write
/// one (`commpage_populate`).
pub fn pages(ncpus: u8, memory: u64) -> [Vec<u8>; 2] {
    let mut ro = vec![0u8; PAGE_LEN];
    ro[off::USER_PAGE_SHIFT_32] = 14;
    ro[off::USER_PAGE_SHIFT_64] = 14;
    ro[off::KERNEL_PAGE_SHIFT] = 14;
    // DEV_FIRM stays zero: `PE_i_can_has_debugger` on a production device.
    let mut p = vec![0u8; PAGE_LEN];
    let mut put = |o: usize, b: &[u8]| p[o..o + b.len()].copy_from_slice(b);
    put(off::SIGNATURE, b"commpage 64-bit\0");
    let mut caps = cap::CACHE64 | cap::FAST_TLS | cap::ADV_SIMD | cap::VFP | cap::EVENT | cap::FMA | cap::LSE | cap::CRC32;
    caps |= u64::from(ncpus) << cap::NUM_CPUS_SHIFT;
    if ncpus == 1 {
        caps |= cap::UP;
    }
    put(off::CPU_CAPABILITIES64, &caps.to_le_bytes());
    put(off::VERSION, &THIS_VERSION.to_le_bytes());
    put(off::CPU_CAPABILITIES, &(caps as u32).to_le_bytes());
    put(off::NCPUS, &[ncpus]);
    put(off::USER_PAGE_SHIFT_32, &[14]);
    put(off::USER_PAGE_SHIFT_64, &[14]);
    put(off::CACHE_LINESIZE, &64u16.to_le_bytes());
    put(off::CPU_CLUSTERS, &[1]);
    put(off::ACTIVE_CPUS, &[ncpus]);
    put(off::PHYSICAL_CPUS, &[ncpus]);
    put(off::LOGICAL_CPUS, &[ncpus]);
    put(off::KERNEL_PAGE_SHIFT, &[14]);
    put(off::MEMORY_SIZE, &memory.to_le_bytes());
    put(off::CPUFAMILY, &CPUFAMILY_ARM_HURRICANE.to_le_bytes());
    // The counter a program reads is this kernel's absolute time, so
    // TIMEBASE_OFFSET (`rtclock_base_abstime`) and CONT_TIMEBASE (the time
    // asleep: this system never sleeps) stay zero. No continuous hardware
    // clock (CONT_HWCLOCK), and DTrace is off in a release kernel.
    put(off::USER_TIMEBASE, &[USER_TIMEBASE_SPEC]);
    // commpage_update_boottime.
    put(off::BOOTTIME_USEC, &super::mach::boottime_usec().to_le_bytes());
    // CONFIG_MACH_APPROXIMATE_TIME: the scheduler's tick keeps APPROX_TIME
    // current ([`tick`]).
    put(off::APPROX_TIME_SUPPORTED, &[1]);
    // kdebug tracing off: KDEBUG_ENABLE stays zero.
    put(off::REMOTETIME_PARAMS, &BT_RESET_SENTINEL_TS.to_le_bytes());
    let [value, addr, kvalue, kaddr] = asb_targets();
    put(off::ASB_TARGET_VALUE, &value.to_le_bytes());
    put(off::ASB_TARGET_ADDRESS, &addr.to_le_bytes());
    put(off::ASB_TARGET_KERN_VALUE, &kvalue.to_le_bytes());
    put(off::ASB_TARGET_KERN_ADDRESS, &kaddr.to_le_bytes());
    [ro, p]
}

/// The security bounty's targets, chosen once a boot: the first index comes
/// from `read_random` and each target takes the next value of the table.
/// The addresses are unmapped for a process and for the kernel.
fn asb_targets() -> [u64; 4] {
    const VALS: [u64; 8] = [
        0x93e7_8adc_ded4_d3d5,
        0xd16c_5b76_ad99_bccf,
        0x67df_bbd1_2c4a_594e,
        0x7365_636e_6f6f_544f,
        0x239a_974c_9811_e04b,
        0xbf60_e7fa_4574_1446,
        0x08ac_f521_0b46_6b05,
        0x67df_bbd1_2c4a_594e,
    ];
    static RANDIDX: std::sync::OnceLock<u8> = std::sync::OnceLock::new();
    let first = *RANDIDX.get_or_init(|| {
        let mut b = [0u8; 1];
        crate::vfs::devfs::fill_random(&mut b);
        b[0]
    });
    let val = |i: u8| VALS[usize::from(first.wrapping_add(i)) % VALS.len()];
    [val(0), val(1) % (u64::MAX - MACH_VM_MAX_ADDRESS) + MACH_VM_MAX_ADDRESS, val(2), val(3) % VM_MIN_KERNEL_ADDRESS]
}

/// A running thread's quantum: `DEFAULT_PREEMPTION_RATE`, 100 a second.
pub const QUANTUM: std::time::Duration = std::time::Duration::from_millis(10);

fn word(mem: &[u8], o: usize) -> u64 {
    let at = placements()[1] as usize + o;
    u64::from_le_bytes(mem[at..at + 8].try_into().unwrap())
}

/// A word of the read-write page, in one aligned store: the guest reads
/// this memory as it runs (see the guest memory's own notes on races), and
/// a torn field is one a program could then see.
fn set_word(mem: &mut [u8], o: usize, v: u64) {
    let at = placements()[1] as usize + o;
    mem[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// The kernel's SMR generation (`cpu_quiescent_advance`), the same for
/// every process.
static QUIESCE_GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// One quantum of the scheduler's work on the commpage: the last known
/// absolute time (`commpage_update_mach_approximate_time`), only ever
/// forward, and the quiescent counter. A CPU running a program is outside
/// any kernel SMR section, so each tick the whole system has quiesced and
/// the generation advances. This tick is the process's one writer of both.
pub fn tick(mem: &mut [u8], abstime: u64) {
    if word(mem, off::APPROX_TIME) < abstime {
        set_word(mem, off::APPROX_TIME, abstime);
    }
    let gen = QUIESCE_GEN.fetch_add(1, Ordering::Relaxed) + 1;
    set_word(mem, off::CPU_QUIESCENT_COUNTER, gen);
}

/// `commpage_set_timestamp`: the calendar time `(sec, frac)` at absolute
/// time `tbr`, what `__commpage_gettimeofday` extrapolates from. A reader
/// retries while `TimeStamp_tick` changes under it, and calls the kernel
/// while it is zero. The kernel's own lock has one writer here at a time.
pub fn set_timestamp(mem: &mut [u8], tbr: u64, sec: u64, frac: u64) {
    let d = off::NEWTIMEOFDAY_DATA;
    set_word(mem, d, 0);
    fence(Ordering::SeqCst);
    set_word(mem, d + 8, sec);
    set_word(mem, d + 16, frac);
    set_word(mem, d + 24, TICK_SCALE);
    set_word(mem, d + 32, TICKS_PER_SEC);
    fence(Ordering::SeqCst);
    set_word(mem, d, tbr);
}

/// Where each page goes in a Darwin process's memory: the read-only page
/// and the read-write one, at their aliases at the top of the memory.
pub fn placements() -> [u64; 2] {
    let alias = |a: u64| gex_abi::DARWIN_COMMPAGE_ALIAS + (a - gex_abi::DARWIN_COMMPAGE_RO);
    [alias(gex_abi::DARWIN_COMMPAGE_RO), alias(gex_abi::DARWIN_COMMPAGE_RW)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_page_reads_back() {
        let [ro, p] = pages(2, 4 << 30);
        assert_eq!(ro[off::USER_PAGE_SHIFT_64], 14);
        assert_eq!(ro[off::NCPUS], 0, "only the shifts and DEV_FIRM are in the read-only page");
        assert_eq!(p[off::USER_TIMEBASE], 1);
        assert_eq!(p[off::APPROX_TIME_SUPPORTED], 1);
        assert_eq!(&p[..16], b"commpage 64-bit\0");
        assert_eq!(p[off::NCPUS], 2);
        assert_eq!(p[off::USER_PAGE_SHIFT_64], 14);
        assert_eq!(u32::from_le_bytes(p[off::KDEBUG_ENABLE..off::KDEBUG_ENABLE + 4].try_into().unwrap()), 0);
        let caps = u64::from_le_bytes(p[off::CPU_CAPABILITIES64..off::CPU_CAPABILITIES64 + 8].try_into().unwrap());
        assert_eq!((caps >> cap::NUM_CPUS_SHIFT) & 0xff, 2);
        assert_eq!(caps & 0x0100_0000, 0, "no crypto extensions claimed");
    }

    #[test]
    fn the_pages_sit_where_their_addresses_wrap() {
        let [ro, rw] = placements();
        assert_eq!(ro, gex_abi::DARWIN_COMMPAGE_RO & gex_abi::DARWIN_ADDR_MASK);
        assert_eq!(rw, gex_abi::DARWIN_COMMPAGE_RW & gex_abi::DARWIN_ADDR_MASK);
        assert_eq!(rw + PAGE_LEN as u64, gex_abi::LIMIT64);
    }
}
