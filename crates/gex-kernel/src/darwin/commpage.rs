//! The contents of Darwin's commpage (XNU's `osfmk/arm/cpu_capabilities.h`).
//!
//! libsystem and dyld read it at constant addresses instead of asking the
//! kernel: the CPU's features, its count, the page size, whether kdebug
//! tracing is on, the time bases. The same bytes go in the read-only page
//! and the read-write one, which share the field layout. A zero field
//! means "ask the kernel": the timebase and time-of-day fast paths fall
//! back to their system calls.

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
    pub const KDEBUG_ENABLE: usize = 0x100;
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

/// One page of commpage data for a machine with `ncpus` CPUs and
/// `memory` bytes. Pages are 4 KiB: gex's kernel maps at that grain, and
/// iOS's userland reads the size from here (as UniXNU's 4 KiB kernel has
/// it do).
pub fn page(ncpus: u8, memory: u64) -> Vec<u8> {
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
    put(off::USER_PAGE_SHIFT_32, &[12]);
    put(off::USER_PAGE_SHIFT_64, &[12]);
    put(off::CACHE_LINESIZE, &64u16.to_le_bytes());
    put(off::CPU_CLUSTERS, &[1]);
    put(off::ACTIVE_CPUS, &[ncpus]);
    put(off::PHYSICAL_CPUS, &[ncpus]);
    put(off::LOGICAL_CPUS, &[ncpus]);
    put(off::KERNEL_PAGE_SHIFT, &[12]);
    put(off::MEMORY_SIZE, &memory.to_le_bytes());
    put(off::CPUFAMILY, &CPUFAMILY_ARM_HURRICANE.to_le_bytes());
    // kdebug tracing off: KDEBUG_ENABLE stays zero.
    p
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
        let p = page(2, 4 << 30);
        assert_eq!(&p[..16], b"commpage 64-bit\0");
        assert_eq!(p[off::NCPUS], 2);
        assert_eq!(p[off::USER_PAGE_SHIFT_64], 12);
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
