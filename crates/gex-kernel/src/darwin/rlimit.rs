//! A Darwin process's resource limits (`bsd/kern/kern_resource.c`): what
//! the first process starts with (`bsd_init`'s `limit0`), `getrlimit`, and
//! `setrlimit`'s `dosetrlimit`, which moves the main stack's guard and
//! clamps the process count.

use crate::errno::Errno;
use crate::syscalls::Kernel;
use crate::GuestMem;

/// `RLIMIT_*` (`bsd/sys/resource.h`) and `RLIM_NLIMITS`.
pub mod res {
    pub const CPU: usize = 0;
    pub const FSIZE: usize = 1;
    pub const DATA: usize = 2;
    pub const STACK: usize = 3;
    pub const CORE: usize = 4;
    pub const AS: usize = 5;
    pub const MEMLOCK: usize = 6;
    pub const NPROC: usize = 7;
    pub const NOFILE: usize = 8;
}
pub const RLIM_NLIMITS: usize = 9;

/// `_RLIMIT_POSIX_FLAG`: set by the POSIX-conforming stubs, masked off.
const RLIMIT_POSIX_FLAG: u64 = 0x1000;

/// `RLIM_INFINITY`: `(1 << 63) - 1`.
pub const RLIM_INFINITY: u64 = (1 << 63) - 1;

/// `PAGE_MAX_SIZE` on arm64.
const PAGE_MAX_SIZE: u64 = 16 * 1024;

/// `bsd/arm/vmparam.h` for an embedded kernel: the main stack's initial
/// limit and its most.
pub const DFLSSIZ: u64 = (1 << 20) - 16 * 1024;
pub const MAXSSIZ: u64 = 1 << 20;
/// `maxsmap`.
const MAXSMAP: u64 = MAXSSIZ - PAGE_MAX_SIZE;
/// `DFLCSIZ`: no core file unless asked for.
const DFLCSIZ: u64 = 0;

/// `NOFILE` (`bsd/sys/param.h`): the default number of open files.
const NOFILE: u64 = 256;
/// `OPEN_MAX` (`bsd/sys/syslimits.h`).
const OPEN_MAX: u64 = 10_240;

/// What `scale_setup` makes of `NPROC` (1000 off x86-64) and `maxfiles`
/// on a 4 GiB device: `max_mem_actual` between 3 and 8 GiB scales by 2,
/// which raises `maxproc` and `maxprocperuid` and leaves the file counts.
pub const MAXPROC: u64 = 1000 * 2;
pub const MAXPROCPERUID: u64 = MAXPROC * 2 / 3;
pub const MAXFILES: u64 = 3 * OPEN_MAX;
pub const MAXFILESPERPROC: u64 = OPEN_MAX;

/// `ARG_MAX` for an embedded kernel (`bsd/sys/syslimits.h`), `kern.argmax`.
pub const ARG_MAX: u64 = 256 * 1024;

/// A process's limits, `[rlim_cur, rlim_max]` each, inherited by a fork
/// and kept by an exec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rlimits(pub [[u64; 2]; RLIM_NLIMITS]);

impl Default for Rlimits {
    /// `limit0`: unlimited but for the open files, the processes, the
    /// stack (`vm_initial_limit_stack`) and the core size.
    fn default() -> Self {
        let mut l = [[RLIM_INFINITY; 2]; RLIM_NLIMITS];
        l[res::NOFILE][0] = NOFILE;
        l[res::NPROC] = [MAXPROCPERUID, MAXPROC];
        l[res::STACK] = [DFLSSIZ, MAXSSIZ - PAGE_MAX_SIZE];
        l[res::CORE][0] = DFLCSIZ;
        Rlimits(l)
    }
}

impl Rlimits {
    pub fn cur(&self, which: usize) -> u64 {
        self.0[which][0]
    }
}

/// `round_page_64`: to the kernel's page.
fn round_page(v: u64) -> Option<u64> {
    v.checked_add(super::mach::PAGE_MASK).map(|r| r & !super::mach::PAGE_MASK)
}

impl Kernel {
    /// `proc_limitgetcur_nofile`, for the descriptor table to enforce.
    pub fn darwin_nofile_sync(&mut self) {
        let n = self.dtask.rlimits.cur(res::NOFILE).min(MAXFILESPERPROC);
        self.fds.set_limit_exact(n as usize);
    }

    /// `getrlimit(which, rlp)`.
    pub(crate) fn darwin_getrlimit(&mut self, m: &mut GuestMem<'_>, which: u64, rlp: u64) -> Result<u64, Errno> {
        let which = (which & !RLIMIT_POSIX_FLAG) as usize;
        if which >= RLIM_NLIMITS {
            return Err(Errno::EINVAL);
        }
        let [cur, max] = self.dtask.rlimits.0[which];
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&cur.to_le_bytes());
        b[8..].copy_from_slice(&max.to_le_bytes());
        m.write(rlp, &b)?;
        Ok(0)
    }

    /// `setrlimit(which, rlp)`.
    pub(crate) fn darwin_setrlimit(&mut self, m: &mut GuestMem<'_>, which: u64, rlp: u64) -> Result<u64, Errno> {
        let new = [m.read_u64(rlp)?, m.read_u64(rlp + 8)?];
        self.darwin_dosetrlimit(m, which, new).map(|()| 0)
    }

    /// `dosetrlimit`. EINVAL both for a bad request and for one the
    /// current use is already past (the stack below its new limit).
    fn darwin_dosetrlimit(&mut self, m: &mut GuestMem<'_>, which: u64, mut new: [u64; 2]) -> Result<(), Errno> {
        let which = (which & !RLIMIT_POSIX_FLAG) as usize;
        if which >= RLIM_NLIMITS {
            return Err(Errno::EINVAL);
        }
        let rlim = self.dtask.rlimits.0[which];
        if new[0] > new[1] {
            return Err(Errno::EINVAL);
        }
        if (new[0] > rlim[1] || new[1] > rlim[1]) && self.creds.uid() != 0 {
            return Err(Errno::EPERM);
        }
        match which {
            res::CPU => {
                if new[0] != RLIM_INFINITY {
                    self.darwin_unimplemented("setrlimit(RLIMIT_CPU) to a finite limit (the task's CPU-time timer and SIGXCPU)".into());
                    return Err(Errno::EINVAL);
                }
            }
            res::DATA | res::AS | res::MEMLOCK | res::FSIZE if new[0] != RLIM_INFINITY => {
                let what = match which {
                    res::DATA => "RLIMIT_DATA (vm_map_set_data_limit)",
                    res::AS => "RLIMIT_AS (vm_map_set_size_limit)",
                    res::MEMLOCK => "RLIMIT_MEMLOCK (vm_map_set_user_wire_limit)",
                    _ => "RLIMIT_FSIZE (the write paths' EFBIG and SIGXFSZ)",
                };
                self.darwin_unimplemented(format!("setrlimit({what}) to a finite limit"));
                return Err(Errno::EINVAL);
            }
            res::STACK => {
                if self.dtask.custom_stack {
                    return Err(Errno::EINVAL);
                }
                // What is past maxsmap is recorded but not mapped.
                let mut stack_rlim = [0u64; 2];
                for i in 0..2 {
                    if new[i] > MAXSMAP {
                        stack_rlim[i] = new[i];
                        new[i] = MAXSMAP;
                    }
                }
                let user_stack = self.darwin_user_stack;
                let page = |v: u64| round_page(v).unwrap_or(v);
                if new[0] > rlim[0] {
                    let size = round_page(new[0]).ok_or(Errno::EINVAL)? - page(rlim[0]);
                    let addr = user_stack.wrapping_sub(page(new[0]));
                    // VM_PROT_DEFAULT.
                    if size != 0 && self.vm_protect(m, addr, size, false, 3) != 0 {
                        return Err(Errno::EINVAL);
                    }
                } else if new[0] < rlim[0] {
                    let sp = m.read_u64(self.ctx_addr + gex_abi::ctx::SP as u64).unwrap_or(0);
                    if !(sp <= user_stack && sp > user_stack.wrapping_sub(page(rlim[0]))) {
                        return Err(Errno::EINVAL);
                    }
                    if sp <= user_stack.wrapping_sub(page(new[0])) {
                        return Err(Errno::EINVAL);
                    }
                    // The kernel protects `round(old) - round(old)` bytes
                    // here: none, so a lowered limit leaves the pages it
                    // gave up mapped.
                }
                for i in 0..2 {
                    if stack_rlim[i] != 0 {
                        new[i] = stack_rlim[i];
                    }
                }
            }
            res::NPROC => {
                let most = if self.creds.uid() == 0 { MAXPROC } else { MAXPROCPERUID };
                new[0] = new[0].min(most);
                new[1] = new[1].min(most);
            }
            _ => {}
        }
        self.dtask.rlimits.0[which] = new;
        if which == res::NOFILE {
            self.darwin_nofile_sync();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_process_has_limit0() {
        let l = Rlimits::default();
        assert_eq!(l.0[res::STACK], [0xfc000, 0xfc000]);
        assert_eq!(l.0[res::NOFILE], [256, RLIM_INFINITY]);
        assert_eq!(l.0[res::NPROC], [1333, 2000]);
        assert_eq!(l.0[res::CORE], [0, RLIM_INFINITY]);
        assert_eq!(l.0[res::CPU], [RLIM_INFINITY; 2]);
    }
}
