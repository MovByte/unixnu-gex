//! `gex-kernel` — the Linux personality.
//!
//! A syscall implementation, not a machine emulator. The kernel is
//! a plain Rust library that operates on the guest's linear memory as a byte
//! slice, which is what lets the same code be linked into the native host and
//! compiled to wasm for the browser without a second implementation.

#![forbid(unsafe_code)]

/// An address in the calling process's memory as it crosses between a
/// process's shim and the global kernel module (the remote ops below and the
/// browser's `k_*` imports): 64-bit for every flavour, since one kernel
/// module serves processes with a 32-bit memory and with a memory64
/// (gex-kmem).
pub type PAddr = u64;

/// `GEX_MEM_TRACE`: say where a guest memory fill or copy of 8 MiB or more
/// came from (what a process start spends its memset on).
#[track_caller]
#[inline]
pub fn big_op(what: &str, len: usize) {
    if len >= 8 << 20 {
        big_op_slow(what, len, std::panic::Location::caller());
    }
}

#[cold]
fn big_op_slow(what: &str, len: usize, at: &std::panic::Location<'_>) {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    if *ON.get_or_init(|| std::env::var_os("GEX_MEM_TRACE").is_some()) {
        eprintln!("gex-mem: {what} {} MiB at {at}", len >> 20);
    }
}

pub mod cpu;
pub mod cpus;
pub mod darwin;
pub mod errno;
pub mod eventfd;
pub mod inotify;
pub mod vnote;
pub mod procnote;
pub mod netlink;
pub mod file;
pub mod fs;
pub mod ftab;
pub mod futex;
pub mod mem;
pub mod net;
pub mod win;
pub mod pipe;
pub mod phase;
pub mod pidfd;
pub mod proc;
pub mod pty;
pub mod signal;
pub mod stdio;
pub mod sync;
pub mod tar;
pub mod syscalls;
pub mod timerfd;
pub mod tty;
pub mod vfs;
pub mod proclive;
pub mod wait;
pub mod unix;
/// The x87's extended-precision arithmetic (its own crate, shared with the
/// IR interpreter and the code generators).
pub use gex_f80 as f80;
pub mod x86;
pub mod i386;

pub use errno::Errno;
pub use proc::{ProcTable, INIT_PID};
pub use syscalls::{
    clock_ns, monotonic_held, set_monotonic_held, set_guest_clock, share_monotonic_base, share_monotonic_held, system_clock, BlockOp, Child, ChildHandle, ClockFn, CodeMap, Kernel,
    SyscallOutcome, ThreadState,
};
pub use proclive::{KernelProcSource, ProcCell};

/// Guest linear memory, addressed exactly as the guest addresses it.
///
/// Guest virtual address equals byte offset, so the kernel needs
/// no translation layer — just bounds checks, which are also the syscall
/// ABI's `EFAULT` checks.
pub struct GuestMem<'a> {
    pub bytes: &'a mut [u8],
    /// A Darwin process's call, its copies to and from the program checked
    /// as `copyin` and `copyout` check them ([`Self::set_user`]): the
    /// calling thread's context, which the kernel keeps in the runtime's
    /// memory below the floor, exempt.
    user: Option<(u64, u64)>,
}

impl<'a> GuestMem<'a> {
    pub fn new(bytes: &'a mut [u8]) -> GuestMem<'a> {
        GuestMem { bytes, user: None }
    }

    /// Check what is read and written from now on against the pages'
    /// protections (`gex_abi::PERM_TABLE64`), EFAULT where a page does not
    /// allow it, as a Darwin call's `copyin` and `copyout` fault: `ctx` is
    /// the calling thread's context, the kernel's own. `None` checks
    /// nothing. What was set before.
    pub fn set_user(&mut self, ctx: Option<(u64, u64)>) -> Option<(u64, u64)> {
        std::mem::replace(&mut self.user, ctx)
    }

    /// The same memory, unchecked: the kernel's own reads and writes in a
    /// call ([`Self::set_user`]), not the program's buffers.
    pub fn kernel(&mut self) -> GuestMem<'_> {
        GuestMem { bytes: &mut *self.bytes, user: None }
    }

    /// Whether `[addr, addr + len)` may be read (`need` the read bit) or
    /// written (the write bit) by a copy in a checked call.
    fn user_allows(&self, addr: u64, len: usize, need: u8) -> bool {
        let Some((cs, ce)) = self.user else { return true };
        if len == 0 {
            return true;
        }
        let end = addr.saturating_add(len as u64);
        if addr >= cs && end <= ce {
            return true;
        }
        let (first, last) = (addr >> gex_abi::PERM_PAGE_SHIFT, (end - 1) >> gex_abi::PERM_PAGE_SHIFT);
        if last >= gex_abi::PERM_TABLE_BYTES {
            return false;
        }
        let view = self.view();
        (first..=last).all(|p| view.get((gex_abi::PERM_TABLE64 + p) as usize).is_some_and(|b| b & need == need))
    }

    /// Where a checked call's string read from `start` must stop before
    /// `end`: the first byte of the first page from it that may not be
    /// read (`copyinstr` faults there), else `end`.
    fn user_readable_to(&self, start: usize, end: usize) -> usize {
        let Some((cs, ce)) = self.user else { return end };
        if start as u64 >= cs && end as u64 <= ce {
            return end;
        }
        let page = gex_abi::PERM_PAGE as usize;
        let mut at = start;
        while at < end {
            let p = at as u64 >> gex_abi::PERM_PAGE_SHIFT;
            let ok = p < gex_abi::PERM_TABLE_BYTES && self.view().get((gex_abi::PERM_TABLE64 + p) as usize).is_some_and(|b| b & gex_abi::perm::READ != 0);
            if !ok {
                return at;
            }
            at = (at & !(page - 1)) + page;
        }
        end
    }

    fn range_for(&self, addr: u64, len: usize, need: u8) -> Result<std::ops::Range<usize>, Errno> {
        let r = self.range(addr, len)?;
        if !self.user_allows(addr, len, need) {
            static TRACE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
            if *TRACE.get_or_init(|| std::env::var_os("GEX_TRACE_EFAULT").is_some()) {
                eprintln!("gex: a call's copy of {len} bytes at {addr:#x} faults (need {need:#x})\n{}", std::backtrace::Backtrace::force_capture());
            }
            return Err(Errno::EFAULT);
        }
        Ok(r)
    }

    /// The backing bytes, hidden from the optimiser on wasm.
    ///
    /// In the browser this slice spans the guest's whole address space via a
    /// pointer made from an integer. LLVM sees no provenance, assumes size zero,
    /// and folds the bounds checks below to "always out of range" at some call
    /// sites but not others. A barrier at each use leaves it nothing to fold;
    /// native hosts get a real slice and need none of this.
    #[inline(always)]
    fn view(&self) -> &[u8] {
        #[cfg(target_family = "wasm")]
        {
            std::hint::black_box(&*self.bytes)
        }
        #[cfg(not(target_family = "wasm"))]
        {
            self.bytes
        }
    }

    #[inline(always)]
    fn view_mut(&mut self) -> &mut [u8] {
        #[cfg(target_family = "wasm")]
        {
            std::hint::black_box(&mut *self.bytes)
        }
        #[cfg(not(target_family = "wasm"))]
        {
            self.bytes
        }
    }

    fn range(&self, addr: u64, len: usize) -> Result<std::ops::Range<usize>, Errno> {
        let start = addr as usize;
        let end = start.checked_add(len).ok_or(Errno::EFAULT)?;
        if addr > usize::MAX as u64 || end > self.limit() {
            return Err(Errno::EFAULT);
        }
        Ok(start..end)
    }

    /// The last address this memory really has, read live.
    ///
    /// Not `view().len()`: in the browser the view spans the whole 2 GiB a
    /// guest pointer may name, while the memory starts smaller and grows as the
    /// guest maps, so a check against the view passed for unbacked addresses and
    /// the access trapped. Live because it moves during a syscall -- an `mmap`
    /// grows the memory then zeroes what it just mapped.
    #[inline(always)]
    fn limit(&self) -> usize {
        #[cfg(target_family = "wasm")]
        {
            #[cfg(target_arch = "wasm32")]
            let pages = core::arch::wasm32::memory_size(0);
            #[cfg(target_arch = "wasm64")]
            let pages = core::arch::wasm64::memory_size(0);
            let live = (pages as u64) << 16;
            (live as usize).min(self.view().len())
        }
        #[cfg(not(target_family = "wasm"))]
        {
            self.view().len()
        }
    }

    pub fn read(&self, addr: u64, len: usize) -> Result<&[u8], Errno> {
        let r = self.range_for(addr, len, gex_abi::perm::READ)?;
        Ok(&self.view()[r])
    }

    /// A writable slice of guest memory, for a caller that fills it itself.
    ///
    /// Without it a `read` allocates a guest-sized buffer, fills it, and copies
    /// in -- and the guest chooses the size; that made one `apt-get update`
    /// claim 117 arena spans (1,872 MiB). See task 140.
    pub fn read_mut(&mut self, addr: u64, len: usize) -> Result<&mut [u8], Errno> {
        let r = self.range_for(addr, len, gex_abi::perm::WRITE)?;
        Ok(&mut self.view_mut()[r])
    }

    pub fn write(&mut self, addr: u64, data: &[u8]) -> Result<(), Errno> {
        let r = self.range_for(addr, data.len(), gex_abi::perm::WRITE)?;
        self.view_mut()[r].copy_from_slice(data);
        Ok(())
    }

    #[track_caller]
    pub fn zero(&mut self, addr: u64, len: usize) -> Result<(), Errno> {
        big_op("zero", len);
        let r = self.range_for(addr, len, gex_abi::perm::WRITE)?;
        self.view_mut()[r].fill(0);
        Ok(())
    }

    /// `len` bytes from `src` to `dst`, both guest addresses, overlap allowed:
    /// no host buffer in between (in the browser every host buffer is shim
    /// heap, and a frame-sized one per frame fragmented it to exhaustion).
    #[track_caller]
    pub fn copy_within(&mut self, src: u64, dst: u64, len: usize) -> Result<(), Errno> {
        big_op("copy_within", len);
        let s = self.range_for(src, len, gex_abi::perm::READ)?;
        let d = self.range_for(dst, len, gex_abi::perm::WRITE)?;
        self.view_mut().copy_within(s, d.start);
        Ok(())
    }

    /// As [`Self::zero`], writing only the 4 KiB pages that are not zero
    /// already. For fresh anonymous memory: reading a page the host never
    /// touched costs no memory, writing it commits it, so a large
    /// reservation zeroed with `zero` would cost its whole size in resident
    /// memory (a 1 GiB `PROT_NONE` mmap, ~1 GiB of RSS natively).
    #[track_caller]
    pub fn zero_dirty(&mut self, addr: u64, len: usize) -> Result<(), Errno> {
        big_op("zero_dirty", len);
        let r = self.range(addr, len)?;
        zero_dirty_bytes(&mut self.view_mut()[r]);
        Ok(())
    }

    /// Ask the host to do `a` with `len` bytes of guest pages at `addr`
    /// (both page aligned); whether it did. A host without a way to
    /// ([`set_host_vm`]: the browser's memory cannot) leaves them as they
    /// are.
    pub fn advise(&mut self, addr: u64, len: u64, a: HostAdvice) -> Result<bool, Errno> {
        let r = self.range(addr, usize::try_from(len).map_err(|_| Errno::EFAULT)?)?;
        let base = self.view_mut().as_mut_ptr() as usize;
        Ok(HOST_VM.get().is_some_and(|f| f(base + r.start, r.len(), a)))
    }

    /// Map `len` bytes of the host file `fd` from `offset` over the guest's
    /// pages at `addr`, copy on write, as a private mapping of it
    /// ([`set_host_map_file`]); whether the host did. Pages it maps are the
    /// file's until written, so they hold no memory of their own.
    pub fn map_file(&mut self, addr: u64, len: u64, fd: i32, offset: u64) -> Result<bool, Errno> {
        let r = self.range(addr, usize::try_from(len).map_err(|_| Errno::EFAULT)?)?;
        let base = self.view_mut().as_mut_ptr() as usize;
        Ok(HOST_MAP_FILE.get().is_some_and(|f| f(base + r.start, r.len(), fd, offset)))
    }

    /// The state of each `page`-byte page of `len` bytes at `addr`
    /// ([`page_state`]), as the host keeps it, into `out`; whether the host
    /// could say ([`set_host_pages`]).
    pub fn page_states(&mut self, addr: u64, len: u64, page: u64, out: &mut [u8]) -> Result<bool, Errno> {
        let r = self.range(addr, usize::try_from(len).map_err(|_| Errno::EFAULT)?)?;
        let base = self.view_mut().as_mut_ptr() as usize;
        Ok(HOST_PAGES.get().is_some_and(|f| f(base + r.start, r.len(), page as usize, out)))
    }

    /// `len` bytes at `addr` (page aligned) read as zero after: the host's
    /// fresh pages where it can give them ([`HostAdvice::Discard`], which
    /// reads nothing and frees what was there), else [`Self::zero_dirty`].
    #[track_caller]
    pub fn discard(&mut self, addr: u64, len: usize) -> Result<(), Errno> {
        if len != 0 && self.advise(addr, len as u64, HostAdvice::Discard)? {
            return Ok(());
        }
        self.zero_dirty(addr, len)
    }

    // The typed accessors: guest memory is little-endian.

    pub fn read_u64(&self, addr: u64) -> Result<u64, Errno> {
        let b: [u8; 8] = self.read(addr, 8)?.try_into().unwrap();
        Ok(u64::from_le_bytes(b))
    }

    pub fn write_u64(&mut self, addr: u64, v: u64) -> Result<(), Errno> {
        self.write(addr, &v.to_le_bytes())
    }

    pub fn read_u32(&self, addr: u64) -> Result<u32, Errno> {
        let b: [u8; 4] = self.read(addr, 4)?.try_into().unwrap();
        Ok(u32::from_le_bytes(b))
    }

    pub fn write_u32(&mut self, addr: u64, v: u32) -> Result<(), Errno> {
        self.write(addr, &v.to_le_bytes())
    }

    /// 64 bits of a guest bitmap made of C `long`s: a `sigset_t`, an
    /// `fd_set` word. Bit `n` is signal `n + 1` or descriptor `n`.
    pub fn read_bits64(&self, addr: u64) -> Result<u64, Errno> {
        self.read_u64(addr)
    }

    pub fn write_bits64(&mut self, addr: u64, v: u64) -> Result<(), Errno> {
        self.write_u64(addr, v)
    }

    /// Read a NUL-terminated guest string, bounded by `max` bytes.
    /// [`Self::read_cstr`] into `buf`: the string's length, or `None` when
    /// no NUL ends it within `buf` (and memory goes on), for the caller to
    /// read it whole.
    pub fn read_cstr_into(&self, addr: u64, buf: &mut [u8]) -> Result<Option<usize>, Errno> {
        let start = addr as usize;
        let limit = self.limit();
        if start >= limit {
            return Err(Errno::EFAULT);
        }
        let want = (start + buf.len()).min(limit);
        let end = self.user_readable_to(start, want);
        let slice = &self.view()[start..end];
        match slice.iter().position(|b| *b == 0) {
            Some(n) => {
                buf[..n].copy_from_slice(&slice[..n]);
                Ok(Some(n))
            }
            None if end < want => Err(Errno::EFAULT),
            None if end == limit => Err(Errno::ENAMETOOLONG),
            None => Ok(None),
        }
    }

    pub fn read_cstr(&self, addr: u64, max: usize) -> Result<Vec<u8>, Errno> {
        let start = addr as usize;
        let limit = self.limit();
        if start >= limit {
            return Err(Errno::EFAULT);
        }
        // Clamped to what exists, not what the view claims: a path near the top
        // of the stack is within a page of memory's end, and scanning `max`
        // bytes ran off into pages never mapped.
        let want = (start + max).min(limit);
        let end = self.user_readable_to(start, want);
        let slice = &self.view()[start..end];
        match slice.iter().position(|b| *b == 0) {
            Some(n) => Ok(slice[..n].to_vec()),
            None if end < want => Err(Errno::EFAULT),
            None => Err(Errno::ENAMETOOLONG),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No guest mapping is ever placed in the runtime's low region (thread
    /// contexts, the kernel's scratch, the dispatch directory).
    #[test]
    fn nothing_guest_visible_lives_in_the_runtime_region() {
        let line = gex_abi::DISPATCH_DIR_END;
        assert!(mem::hits_runtime(0x1000, 0x2000));
        assert!(mem::hits_runtime(line - 0x1000, line));
        assert!(!mem::hits_runtime(line, line + 0x1000));
        let mut map = mem::MemoryMap::new(gex_abi::PIE_BASE);
        let fixed = mem::flags::FIXED | mem::flags::PRIVATE | mem::flags::ANONYMOUS;
        assert!(map.mmap(0x10_0000, 0x1000, mem::prot::READ, fixed, "low").is_err());
        let any = mem::flags::PRIVATE | mem::flags::ANONYMOUS;
        let a = map.mmap(0, 0x1000, mem::prot::READ, any, "anon").unwrap();
        assert!(a >= line);
    }

    /// Every byte of the range reads as zero afterwards, whichever pages were
    /// dirty, including a range that starts and ends mid-page.
    #[test]
    fn page_is_zero_sees_every_byte() {
        let mut buf = vec![0u8; 4096 + 16];
        for off in [0usize, 1, 3, 8] {
            let p = &mut buf[off..off + 4096];
            assert!(super::page_is_zero(p));
            for i in [0usize, 1, 7, 255, 256, 2049, 4095] {
                p[i] = 0x80;
                assert!(!super::page_is_zero(p), "byte {i} at offset {off}");
                p[i] = 0;
            }
        }
    }

    #[test]
    fn zero_dirty_zeroes_what_was_written() {
        let mut buf = vec![0u8; 0x6000];
        buf[0x1000] = 1;
        buf[0x2fff] = 2;
        buf[0x3800] = 3;
        buf[0x5fff] = 4;
        let mut m = GuestMem::new(&mut buf);
        m.zero_dirty(0x1000, 0x4000).unwrap();
        assert!(m.read(0x1000, 0x4000).unwrap().iter().all(|&b| b == 0));
        // Outside the range is left alone.
        assert_eq!(m.read(0x5fff, 1).unwrap()[0], 4);
        let mut buf = vec![7u8; 0x3000];
        let mut m = GuestMem::new(&mut buf);
        m.zero_dirty(0x800, 0x1000).unwrap();
        let b = m.read(0, 0x3000).unwrap();
        assert!(b[0x800..0x1800].iter().all(|&x| x == 0));
        assert!(b[..0x800].iter().chain(&b[0x1800..]).all(|&x| x == 7));
    }
}

/// What a host may be asked to do with guest pages ([`GuestMem::advise`]),
/// the page advice Darwin's VM takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostAdvice {
    /// The contents may be discarded: each page reads as it was or as zero.
    Free,
    /// As [`HostAdvice::Free`], and not counted as the owner's memory while
    /// it is reusable.
    Reusable,
    /// Reusable pages are the owner's again.
    Reuse,
    /// Not wanted soon; the contents stay.
    Deactivate,
    /// Wanted soon: made resident now.
    WillNeed,
    /// Read as zero.
    Zero,
    /// Read as zero, holding no memory until written: the pages replaced by
    /// fresh ones.
    Discard,
}

static HOST_VM: std::sync::OnceLock<fn(usize, usize, HostAdvice) -> bool> = std::sync::OnceLock::new();

/// A guest page's state as the host keeps it ([`GuestMem::page_states`]).
pub mod page_state {
    /// In memory.
    pub const PRESENT: u8 = 0x1;
    /// Out of memory, compressed or paged out, and kept.
    pub const PAGED_OUT: u8 = 0x2;
    /// A file's page (not the owner's own memory).
    pub const EXTERNAL: u8 = 0x4;
    /// Made reusable, and not counted as the owner's.
    pub const REUSABLE: u8 = 0x8;
}

static HOST_PAGES: std::sync::OnceLock<fn(usize, usize, usize, &mut [u8]) -> bool> = std::sync::OnceLock::new();

/// Install the host's page state query: `f(host_address, len, page, out)`
/// fills one [`page_state`] byte per `page` bytes, true when it could.
pub fn set_host_pages(f: fn(usize, usize, usize, &mut [u8]) -> bool) {
    let _ = HOST_PAGES.set(f);
}

static HOST_MAP_FILE: std::sync::OnceLock<fn(usize, usize, i32, u64) -> bool> = std::sync::OnceLock::new();

/// Install the host's private file mapping over guest pages:
/// `f(host_address, len, fd, offset)`, true when it mapped them.
pub fn set_host_map_file(f: fn(usize, usize, i32, u64) -> bool) {
    let _ = HOST_MAP_FILE.set(f);
}

/// Install the host's page advice: `f(host_address, len, advice)`, true
/// when it was taken. Once per process; later calls are ignored.
pub fn set_host_vm(f: fn(usize, usize, HostAdvice) -> bool) {
    let _ = HOST_VM.set(f);
}

/// Zero `b`, writing only the 4 KiB stretches that are not zero already
/// (counted from the start of `b`). Reading a page the host never touched
/// costs nothing; writing one, even a zero, commits it -- in the browser a
/// page of the tab's resident memory that holds nothing. See
/// [`GuestMem::zero_dirty`].
pub fn zero_dirty_bytes(b: &mut [u8]) {
    for page in b.chunks_mut(4096) {
        if !page_is_zero(page) {
            page.fill(0);
        }
    }
}

/// Whether every byte of `b` is zero. The scan is the whole cost of
/// [`GuestMem::zero_dirty`] for the common clean page, and a 64-bit build
/// for wasm has no SIMD: a byte-wise fold is one load per byte, this is one
/// per eight (an unaligned 64-bit load), four running at once, with an early
/// out every 256 bytes.
fn page_is_zero(b: &[u8]) -> bool {
    let w = |c: &[u8]| u64::from_ne_bytes(c.try_into().unwrap());
    let mut blocks = b.chunks_exact(256);
    let clean = (&mut blocks).all(|c| {
        let (mut a, mut x, mut y, mut z) = (0u64, 0u64, 0u64, 0u64);
        for q in c.chunks_exact(32) {
            a |= w(&q[0..8]);
            x |= w(&q[8..16]);
            y |= w(&q[16..24]);
            z |= w(&q[24..32]);
        }
        a | x | y | z == 0
    });
    clean && blocks.remainder().iter().all(|&v| v == 0)
}

/// Bumped (after the push, under the kernel lock) whenever code is mapped or
/// retired (`Kernel::new_code`, `Kernel::retired_code`): a host checks this
/// before taking the kernel lock to drain them, on every syscall.
pub static CODE_EVENTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn note_code_change() {
    CODE_EVENTS.fetch_add(1, std::sync::atomic::Ordering::Release);
}

/// Why a range of code was retired, for the host's retire-storm diagnostic
/// (a page whose translations are thrown away again and again). Diagnostic
/// only: nothing reads it to decide what to retire.
#[derive(Clone, Copy, Debug)]
pub struct RetireWhy {
    pub start: u64,
    pub end: u64,
    /// The call that retired it: `munmap`, `mprotect`, `mmap-fixed`, `nt-*`.
    pub why: &'static str,
    /// The new protection, for `mprotect`.
    pub prot: u32,
    /// The guest pc of the syscall, 0 when unknown.
    pub pc: u64,
}

static RETIRE_WHY: std::sync::Mutex<Vec<RetireWhy>> = std::sync::Mutex::new(Vec::new());
static RETIRE_WHY_ON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Keep [`RetireWhy`]s for the host to take (its JIT diagnostics switch);
/// off, [`note_retire_why`] does nothing.
pub fn set_retire_why(on: bool) {
    RETIRE_WHY_ON.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// Note why `[start, end)` is retired (beside its `retired_code` push). Kept
/// to the last 1024 not yet taken, so a host that never takes them (native)
/// holds a fixed few KiB.
pub fn note_retire_why(w: RetireWhy) {
    if !RETIRE_WHY_ON.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    let mut v = RETIRE_WHY.lock().unwrap_or_else(|e| e.into_inner());
    if v.len() >= 1024 {
        v.remove(0);
    }
    v.push(w);
}

/// The reasons noted since the last call.
pub fn take_retire_why() -> Vec<RetireWhy> {
    std::mem::take(&mut *RETIRE_WHY.lock().unwrap_or_else(|e| e.into_inner()))
}

/// The process is i386 (a 32-bit guest on x86): its GPRs live in 64-bit
/// context slots whose high halves must stay zero, as a 32-bit write leaves
/// them on hardware, so that compiled code may keep and store only the low
/// 32 bits. Every host write of a GPR goes through [`gpr`].
static COMPAT32: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn set_compat32(on: bool) {
    COMPAT32.store(on, std::sync::atomic::Ordering::Relaxed);
}

pub fn compat32() -> bool {
    COMPAT32.load(std::sync::atomic::Ordering::Relaxed)
}

/// A GPR value as the host writes it into the context: zero-extended from 32
/// bits for an i386 process (a negative errno included), as it is.
#[inline]
pub fn gpr(v: u64) -> u64 {
    if compat32() {
        v & 0xffff_ffff
    } else {
        v
    }
}
