//! The Darwin personality: a Mach-O process's system calls.
//!
//! Darwin enters the kernel with `svc #0x80` and the number in x16, and its
//! numbering says which kernel answers: a positive number is a BSD system
//! call, a negative one a Mach trap, and `0x8000_0000` the machine-dependent
//! calls (the thread's TSD pointer). BSD calls with a Linux counterpart are
//! renumbered onto it ([`bsd::translate`]) and run through the same
//! dispatch as a Linux process's, as the i386 and x86-64 numberings are;
//! the result goes back Darwin's way, with the carry flag set and a Darwin
//! errno in x0 on failure ([`set_result`]).

use crate::errno::Errno;
use crate::GuestMem;
use gex_abi::ctx;

pub mod bsd;
pub mod commpage;
pub mod errno;
mod kern;
pub mod mach;

/// Where a Darwin thread puts its system call number.
pub const NR_SLOT: usize = ctx::x(16);

/// The machine-dependent call class (`PLATFORM_SYSCALL_TRAP_NO`'s x16).
pub const PLATFORM: u64 = 0x8000_0000;

/// `machdep_call` numbers in x3 under [`PLATFORM`].
pub mod machdep {
    pub const ICACHE_INVALIDATE: u64 = 0;
    pub const DCACHE_FLUSH: u64 = 1;
    pub const THREAD_SET_TSD: u64 = 2;
}

/// A call answered here without going through the Linux dispatch: the
/// machine-dependent class. `None` for everything else.
pub fn direct(m: &mut GuestMem<'_>, ctx_addr: u64, raw: u64) -> Option<u64> {
    if raw as u32 as u64 != PLATFORM {
        return None;
    }
    let code = m.read_u64(ctx_addr + ctx::x(3) as u64).unwrap_or(!0);
    Some(match code {
        // gex keeps no instruction cache to invalidate, and its data
        // writes are already visible.
        machdep::ICACHE_INVALIDATE | machdep::DCACHE_FLUSH => 0,
        machdep::THREAD_SET_TSD => {
            let tsd = m.read_u64(ctx_addr + ctx::x(0) as u64).unwrap_or(0);
            match m.write_u64(ctx_addr + ctx::TPIDRRO as u64, tsd) {
                Ok(()) => 0,
                Err(e) => neg(e),
            }
        }
        _ => neg(Errno::ENOSYS),
    })
}

/// The `apple[]` strings exec passes a Darwin program: its path first,
/// then the per-process values libSystem and dyld read. Fixed, as the
/// Linux side's AT_RANDOM is, so runs are reproducible.
pub fn apple_strings(exe_path: &str) -> Vec<String> {
    vec![
        format!("executable_path={exe_path}"),
        "stack_guard=0x6a5b4c3d2e1f0f00".into(),
        "malloc_entropy=0x7a6b5c4d3e2f1001,0x1122334455667788".into(),
        "ptr_munge=0x1".into(),
    ]
}

fn neg(e: Errno) -> u64 {
    (-(e.0 as i64)) as u64
}

/// Whether x16's number is a Mach trap: negative as the 32-bit value
/// libsyscall loads (`mov w16, #-n`), the machine-dependent class aside.
pub fn mach_trap_number(raw: u64) -> Option<i32> {
    let t = raw as u32 as i32;
    (t < 0 && raw as u32 as u64 != PLATFORM).then_some(t)
}

/// Write a Mach trap's result: x0 only.
pub fn set_mach_result(m: &mut GuestMem<'_>, ctx_addr: u64, kr: u64) -> Result<(), Errno> {
    m.write_u64(ctx_addr + ctx::x(0) as u64, kr)
}

/// Write a result in the canonical encoding (a value, or `-errno` with a
/// Linux errno) back the way Darwin returns it: on success the value in x0
/// and carry clear, on failure the Darwin errno in x0 and carry set.
pub fn set_result(m: &mut GuestMem<'_>, ctx_addr: u64, ret: u64) -> Result<(), Errno> {
    let r = ret as i64;
    let (x0, carry) = if (-4095..0).contains(&r) { (errno::to_darwin(-r as i32) as u64, 1u8) } else { (ret, 0u8) };
    m.write_u64(ctx_addr + ctx::x(0) as u64, x0)?;
    m.write(ctx_addr + ctx::CF as u64, &[carry])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_mem() -> Vec<u8> {
        vec![0u8; ctx::TPIDRRO + 64]
    }

    #[test]
    fn success_clears_carry() {
        let mut b = ctx_mem();
        b[ctx::CF] = 1;
        let mut m = GuestMem::new(&mut b);
        set_result(&mut m, 0, 18).unwrap();
        assert_eq!(m.read_u64(ctx::x(0) as u64).unwrap(), 18);
        assert_eq!(b[ctx::CF], 0);
    }

    #[test]
    fn failure_sets_carry_and_the_darwin_errno() {
        let mut b = ctx_mem();
        let mut m = GuestMem::new(&mut b);
        // Linux EAGAIN (11) is Darwin's 35.
        set_result(&mut m, 0, (-11i64) as u64).unwrap();
        assert_eq!(m.read_u64(ctx::x(0) as u64).unwrap(), 35);
        assert_eq!(b[ctx::CF], 1);
    }

    #[test]
    fn thread_set_tsd_writes_tpidrro() {
        let mut b = ctx_mem();
        let mut m = GuestMem::new(&mut b);
        m.write_u64(ctx::x(0) as u64, 0x2_0000_8000).unwrap();
        m.write_u64(ctx::x(3) as u64, machdep::THREAD_SET_TSD).unwrap();
        assert_eq!(direct(&mut m, 0, PLATFORM), Some(0));
        assert_eq!(m.read_u64(ctx::TPIDRRO as u64).unwrap(), 0x2_0000_8000);
        assert_eq!(direct(&mut m, 0, 4), None);
    }
}
