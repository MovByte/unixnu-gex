//! Darwin calls that have no Linux counterpart to renumber onto and need
//! the process's kernel state.

use super::bsd::sys;
use crate::errno::Errno;
use crate::syscalls::Kernel;
use crate::GuestMem;

impl Kernel {
    /// Answer a Darwin-only BSD call, or `None` to leave it to the
    /// renumbering in [`super::bsd::translate`]. The result is in the
    /// canonical encoding (`-errno` on failure).
    pub(crate) fn darwin_call(&mut self, m: &mut GuestMem<'_>, raw: u64, a: &[u64; 6]) -> Option<u64> {
        let neg = |e: Errno| (-(e.0 as i64)) as u64;
        Some(match raw {
            // dyld asks where the shared cache is mapped; the kernel mapped
            // it before the process started.
            sys::SHARED_REGION_CHECK_NP => match self.darwin_region {
                (0, _) => neg(Errno::EINVAL),
                (start, _) => match m.write_u64(a[0], start) {
                    Ok(()) => 0,
                    Err(e) => neg(e),
                },
            },
            // No set-id programs here.
            sys::ISSETUGID => 0,
            _ => return None,
        })
    }
}
