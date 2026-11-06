//! `kern_mman.c`'s `mmap` and `madvise`, and `mach_vm_behavior_set`
//! (`vm_map_behavior_set` and the advice it carries out, `vm_map.c`).
//!
//! A mapping's protections, tag, inheritance and object are kept in the
//! task's entries ([`super::vm`]); the host's mapping is the one gex's
//! canonical `mmap` makes. Advice that changes what pages hold or how they
//! are counted goes to the host for the guest's pages
//! ([`crate::HostAdvice`]) where it has a way to take it; without one the
//! contents stay as they were, which is what XNU leaves too until the pages
//! are reclaimed.

use super::ipc::kr;
use super::mach::{prot, PAGE_MASK};
use super::vm::{self, behavior, inherit, kind, Attrs};
use crate::errno::Errno;
use crate::syscalls::{nr, Kernel};
use crate::{GuestMem, HostAdvice};

const KERN_PROTECTION_FAILURE: u64 = 2;
const KERN_NO_ACCESS: u64 = 8;

/// `MAP_*`.
pub mod map {
    pub const SHARED: u32 = 0x1;
    pub const PRIVATE: u32 = 0x2;
    pub const FIXED: u32 = 0x10;
    pub const RENAME: u32 = 0x20;
    pub const NORESERVE: u32 = 0x40;
    pub const RESERVED0080: u32 = 0x80;
    pub const NOEXTEND: u32 = 0x100;
    pub const HASSEMAPHORE: u32 = 0x200;
    pub const NOCACHE: u32 = 0x400;
    pub const JIT: u32 = 0x800;
    pub const ANON: u32 = 0x1000;
    pub const RESILIENT_CODESIGN: u32 = 0x2000;
    pub const RESILIENT_MEDIA: u32 = 0x4000;
    pub const TRANSLATED_ALLOW_EXECUTE: u32 = 0x2_0000;
    pub const UNIX03: u32 = 0x4_0000;
    pub const TPRO: u32 = 0x8_0000;
    /// The flags `mmap` knows off macOS (`MAP_32BIT` is macOS's).
    pub const KNOWN: u32 = SHARED | PRIVATE | FIXED | RENAME | NORESERVE | RESERVED0080 | NOEXTEND | HASSEMAPHORE | NOCACHE | JIT | TPRO | ANON | RESILIENT_CODESIGN | RESILIENT_MEDIA | TRANSLATED_ALLOW_EXECUTE | UNIX03;
}

/// The `VM_FLAGS_*` an anonymous mapping's descriptor may carry.
mod vmf {
    pub const PURGABLE: u32 = 0x2;
    pub const CHUNK_4GB: u32 = 0x4;
    pub const SUPERPAGE_MASK: u32 = 0x7_0000;
    pub const ALIAS_MASK: u32 = 0xff00_0000;
}

/// `MADV_*`.
mod madv {
    pub const NORMAL: i32 = 0;
    pub const RANDOM: i32 = 1;
    pub const SEQUENTIAL: i32 = 2;
    pub const WILLNEED: i32 = 3;
    pub const DONTNEED: i32 = 4;
    pub const FREE: i32 = 5;
    pub const ZERO_WIRED_PAGES: i32 = 6;
    pub const FREE_REUSABLE: i32 = 7;
    pub const FREE_REUSE: i32 = 8;
    pub const CAN_REUSE: i32 = 9;
    pub const PAGEOUT: i32 = 10;
    pub const ZERO: i32 = 11;
}

/// The `vm_behavior_t`s that act at once, beyond [`behavior`]'s.
pub mod act {
    pub const WILLNEED: i32 = 4;
    pub const DONTNEED: i32 = 5;
    pub const FREE: i32 = 6;
    pub const ZERO_WIRED_PAGES: i32 = 7;
    pub const REUSABLE: i32 = 8;
    pub const REUSE: i32 = 9;
    pub const CAN_REUSE: i32 = 10;
    pub const ZERO: i32 = 12;
}

/// `vm_map_range_overflows` for a 16 KiB map.
fn range_overflows(addr: u64, size: u64) -> bool {
    if size == 0 {
        return false;
    }
    let start = addr & !PAGE_MASK;
    let end = addr.wrapping_add(size).wrapping_add(PAGE_MASK) & !PAGE_MASK;
    addr.checked_add(size).is_none() || end <= start
}

fn round(v: u64) -> u64 {
    v.wrapping_add(PAGE_MASK) & !PAGE_MASK
}

/// One piece of a task's map: a host mapping's protection with the entry
/// attributes over it.
#[derive(Clone, Copy, Debug)]
struct Piece {
    start: u64,
    end: u64,
    prot: u8,
    attrs: Attrs,
}

/// `vm_sync_t`'s flags `vm_map_msync` takes from advice.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Sync {
    Deactivate,
    KillPages,
}

impl Kernel {
    /// `proc_2020_fall_os_sdk_or_later`.
    fn darwin_fall_2020_sdk(&self) -> bool {
        let (platform, sdk) = self.dtask.platform;
        match platform {
            1 => sdk >= 0x000a_1000,
            2 | 6 | 7 => sdk >= 0x000e_0000,
            5 => sdk >= 0x0005_0000,
            3 | 8 => sdk >= 0x000e_0000,
            4 | 9 => sdk >= 0x0007_0000,
            _ => true,
        }
    }

    /// `mmap(addr, len, prot, flags, fd, pos)`.
    pub(crate) fn darwin_mmap(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        use map::*;
        let (mut addr, len, mut flags, fd, pos) = (a[0], a[1], a[3] as u32, a[4] as i32, a[5]);
        if range_overflows(addr, len) {
            return Err(Errno::EINVAL);
        }
        let mut cur = (a[2] as u32 & prot::ALL as u32) as u8;
        if cur & (prot::EXECUTE | prot::WRITE) as u8 != 0 {
            cur |= prot::READ as u8;
        }
        // An older program's unknown flags are taken and mean nothing.
        if flags & !KNOWN != 0 && self.darwin_fall_2020_sdk() {
            return Err(Errno::EINVAL);
        }
        let mut file_pos = pos;
        if pos.checked_add(len).and_then(|s| s.checked_add(PAGE_MASK)).is_none() {
            return Err(Errno::EINVAL);
        }
        if flags & UNIX03 != 0 && (file_pos & PAGE_MASK != 0 || flags & (PRIVATE | SHARED) == 0 || len == 0) {
            return Err(Errno::EINVAL);
        }
        let mut pageoff = file_pos & PAGE_MASK;
        file_pos -= pageoff;
        let mut size = round(len + pageoff);

        if flags & JIT != 0 && (flags & (FIXED | SHARED | RESILIENT_CODESIGN | RESILIENT_MEDIA | TPRO) != 0 || flags & ANON == 0) {
            return Err(Errno::EINVAL);
        }
        if flags & (RESILIENT_CODESIGN | RESILIENT_MEDIA) != 0 && flags & (ANON | JIT | TPRO) != 0 {
            return Err(Errno::EINVAL);
        }
        if flags & RESILIENT_CODESIGN != 0 {
            let reject = if flags & PRIVATE != 0 { prot::EXECUTE } else { prot::WRITE | prot::EXECUTE } as u8;
            if cur & reject != 0 {
                return Err(Errno::EPERM);
            }
        }
        // There is nowhere to put a zero page for a shared mapping, so its
        // MAP_RESILIENT_MEDIA has always been ignored.
        if flags & SHARED != 0 {
            flags &= !RESILIENT_MEDIA;
        }
        if flags & TPRO != 0 && (cur & prot::EXECUTE as u8 != 0 || cur & prot::WRITE as u8 == 0) {
            return Err(Errno::EPERM);
        }
        if flags & FIXED != 0 {
            addr = addr.wrapping_sub(pageoff);
            if addr & PAGE_MASK != 0 {
                return Err(Errno::EINVAL);
            }
        }
        // No code signing monitor on this device (vm_map_csm_allow_jit).

        let mut attrs = Attrs { inherit: if flags & SHARED != 0 { inherit::SHARE } else { inherit::DEFAULT }, no_cache: flags & NOCACHE != 0, ..Attrs::default() };
        let mut maxprot = prot::ALL as u8;
        let mapanon = flags & ANON != 0;
        let mut superpage = false;
        if mapanon {
            // mac_proc_check_map_anon: AMFI's say on a JIT region.
            if flags & JIT != 0 {
                self.darwin_unimplemented("mmap MAP_JIT (AMFI's map_anon check and JIT regions)".into());
                return Err(Errno::EINVAL);
            }
            // A descriptor carries VM flags: the tag, a superpage size.
            if fd != -1 {
                let vm_flags = fd as u32 & (vmf::ALIAS_MASK | vmf::SUPERPAGE_MASK | vmf::PURGABLE | vmf::CHUNK_4GB);
                if vm_flags != fd as u32 {
                    return Err(Errno::EINVAL);
                }
                if vm_flags & (vmf::PURGABLE | vmf::CHUNK_4GB) != 0 {
                    self.darwin_unimplemented(format!("mmap's VM flags {:#x} (purgeable objects, 4 GB chunks)", vm_flags & (vmf::PURGABLE | vmf::CHUNK_4GB)));
                    return Err(Errno::EINVAL);
                }
                attrs.alias = (vm_flags >> 24) as u8;
                superpage = vm_flags & vmf::SUPERPAGE_MASK != 0;
            }
            file_pos = 0;
            pageoff = 0;
        } else {
            if flags & JIT != 0 {
                return Err(Errno::EINVAL);
            }
            let f = self.fds.get(fd)?;
            if Arc::clone(&f.handle).as_posix_shm().is_some() {
                return self.darwin_pshm_mmap(m, a);
            }
            let ft = f.handle.metadata().map(|md| md.file_type).map_err(|_| Errno::EINVAL)?;
            match ft {
                crate::vfs::FileType::Regular => {}
                // The /dev/zero idiom is not taken: a device is not mapped.
                crate::vfs::FileType::CharDevice => return Err(Errno::ENODEV),
                _ => return Err(Errno::EINVAL),
            }
            maxprot = prot::EXECUTE as u8;
            if f.readable {
                maxprot |= prot::READ as u8;
            } else if cur & prot::READ as u8 != 0 {
                return Err(Errno::EACCES);
            }
            if flags & SHARED != 0 {
                if f.writable {
                    maxprot |= prot::WRITE as u8;
                } else if cur & prot::WRITE as u8 != 0 {
                    return Err(Errno::EACCES);
                }
                attrs.kind = kind::FILE_SHARED;
            } else {
                maxprot |= prot::WRITE as u8;
                attrs.kind = kind::FILE_PRIVATE;
            }
        }
        if size == 0 {
            return Ok(0);
        }
        size = round(size);
        if flags & FIXED == 0 {
            addr = round(addr);
        }
        // vm_map_enter: arm64 has no superpage size.
        if superpage {
            return Err(Errno::EINVAL);
        }
        if flags & TPRO != 0 {
            self.darwin_unimplemented("mmap MAP_TPRO (TPRO regions)".into());
            return Err(Errno::EINVAL);
        }
        if maxprot & (prot::EXECUTE | prot::WRITE) as u8 != 0 {
            maxprot |= prot::READ as u8;
        }
        if !mapanon && flags & RESILIENT_CODESIGN != 0 {
            // Strictly what was asked for.
            maxprot &= cur;
        }
        if !mapanon && size.checked_add(file_pos).is_none() {
            return Err(Errno::EINVAL);
        }
        // vm_map_enter: VM_MAP_POLICY_WX_STRIP_X (no entry here is a JIT
        // region).
        if cur & prot::WRITE as u8 != 0 && cur & prot::EXECUTE as u8 != 0 {
            cur &= !(prot::EXECUTE as u8);
        }
        attrs.max = maxprot;

        use crate::mem::flags as lf;
        let mut l = if flags & SHARED != 0 { lf::SHARED } else { lf::PRIVATE };
        if flags & FIXED != 0 {
            l |= lf::FIXED;
        }
        let (lfd, lpos) = if mapanon {
            l |= lf::ANONYMOUS;
            (u64::MAX, 0)
        } else {
            (fd as u64, file_pos)
        };
        let at = match self.canonical(m, nr::MMAP, [addr, size, u64::from(cur), l, lfd, lpos]) {
            Ok(at) => at,
            Err(Errno::ENOMEM) => return Err(Errno::ENOMEM),
            Err(Errno::EACCES) => return Err(Errno::EACCES),
            Err(_) => return Err(Errno::EINVAL),
        };
        self.dtask.vm.set(at, at + size, attrs);
        Ok(at + pageoff)
    }

    /// `pshm_mmap`: a POSIX shared memory object's own checks, then its
    /// object mapped shared, at most read and write (no write where the
    /// descriptor cannot).
    fn darwin_pshm_mmap(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        self.darwin_shm_mmap_check(a)?;
        let mut b = *a;
        let n = super::bsd::translate(super::bsd::sys::MMAP, &mut b);
        let at = self.canonical(m, n, b)?;
        let writable = self.fds.get(a[4] as i32).map(|f| f.writable).unwrap_or(false);
        let max = if writable { prot::READ | prot::WRITE } else { prot::READ } as u8;
        let end = round(at.saturating_add(a[1]));
        self.dtask.vm.set(at & !PAGE_MASK, end, Attrs { kind: kind::SHM, max, inherit: inherit::SHARE, ..Attrs::default() });
        Ok(at)
    }

    /// The task's map over `[start, end)`, piece by piece, holes left out.
    fn darwin_pieces(&self, start: u64, end: u64) -> Vec<Piece> {
        let vmas: Vec<(u64, u64, u8)> = {
            let mm = self.mem.lock();
            mm.vmas().iter().filter(|v| v.start < end && v.end > start).map(|v| (v.start.max(start), v.end.min(end), (v.prot & 7) as u8)).collect()
        };
        let mut out = Vec::new();
        for (s, e, p) in vmas {
            for (ps, pe, attrs) in self.dtask.vm.pieces(s, e) {
                out.push(Piece { start: ps, end: pe, prot: p, attrs });
            }
        }
        out
    }

    /// `vm_map_range_check`: `[start, end)` mapped without a hole.
    fn darwin_range_mapped(pieces: &[Piece], start: u64, end: u64) -> bool {
        let mut at = start;
        for p in pieces {
            if p.start > at {
                return false;
            }
            at = at.max(p.end);
        }
        at >= end && !pieces.is_empty()
    }

    /// `madvise(addr, len, behav)`.
    pub(crate) fn darwin_madvise(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        let (start, size, behav) = (a[0], a[1], a[2] as i32);
        let new = match behav {
            madv::RANDOM => i32::from(behavior::RANDOM),
            madv::SEQUENTIAL => i32::from(behavior::SEQUENTIAL),
            madv::NORMAL => i32::from(behavior::DEFAULT),
            madv::WILLNEED => act::WILLNEED,
            madv::DONTNEED => act::DONTNEED,
            madv::FREE => act::FREE,
            madv::ZERO_WIRED_PAGES => act::ZERO_WIRED_PAGES,
            madv::FREE_REUSABLE => act::REUSABLE,
            madv::FREE_REUSE => act::REUSE,
            madv::CAN_REUSE => act::CAN_REUSE,
            // VM_BEHAVIOR_PAGEOUT is MACH_ASSERT's.
            madv::PAGEOUT => return Err(Errno::EOPNOTSUPP),
            madv::ZERO => act::ZERO,
            _ => return Err(Errno::EINVAL),
        };
        if range_overflows(start, size) {
            return Err(Errno::EINVAL);
        }
        // FOURK_COMPAT: a 4K program's madvise of its "page zero".
        if start == 0 && size != 0 && (behav == madv::FREE || behav == madv::FREE_REUSABLE) {
            return Err(Errno::EINVAL);
        }
        match self.darwin_behavior_set(m, start, size, new) {
            kr::SUCCESS => Ok(0),
            kr::INVALID_ADDRESS => Err(Errno::EINVAL),
            kr::NO_SPACE => Err(Errno::ENOMEM),
            KERN_PROTECTION_FAILURE => Err(Errno::EPERM),
            KERN_NO_ACCESS => Err(Errno::EOPNOTSUPP),
            _ => Err(Errno::EINVAL),
        }
    }

    /// `mach_vm_behavior_set(map, start, size, new_behavior)`: the range
    /// rounded out to pages (a hardware page for the reuse advice, which is
    /// the map's page here), then `vm_map_behavior_set`.
    pub(crate) fn darwin_behavior_set(&mut self, m: &mut GuestMem<'_>, start: u64, size: u64, new: i32) -> u64 {
        if start.checked_add(size).is_none() {
            return kr::INVALID_ARGUMENT;
        }
        if size == 0 {
            return kr::SUCCESS;
        }
        let (s, e) = (start & !PAGE_MASK, round(start + size));
        self.darwin_vm_behavior_set(m, s, e, new)
    }

    /// `vm_map_behavior_set(map, start, end, new_behavior)`.
    fn darwin_vm_behavior_set(&mut self, m: &mut GuestMem<'_>, start: u64, end: u64, new: i32) -> u64 {
        if start > end || end > self.darwin_map_max() {
            return kr::NO_SPACE;
        }
        if range_overflows(start, end - start) {
            return kr::INVALID_ADDRESS;
        }
        const DEFAULT: i32 = behavior::DEFAULT as i32;
        const RSEQNTL: i32 = behavior::RSEQNTL as i32;
        match new {
            // A state the entries keep.
            DEFAULT..=RSEQNTL | act::ZERO_WIRED_PAGES => {
                if !Self::darwin_range_mapped(&self.darwin_pieces(start, end), start, end) {
                    return kr::INVALID_ADDRESS;
                }
                if new == act::ZERO_WIRED_PAGES {
                    self.dtask.vm.update(start, end, |a| a.zero_wired = true);
                } else {
                    self.dtask.vm.update(start, end, |a| a.behavior = new as u8);
                }
                kr::SUCCESS
            }
            act::WILLNEED => self.darwin_willneed(m, start, end),
            act::DONTNEED => self.darwin_msync_advice(m, start, end, Sync::Deactivate),
            act::FREE => self.darwin_msync_advice(m, start, end, Sync::KillPages),
            act::REUSABLE => self.darwin_reusable_pages(m, start, end),
            act::REUSE => self.darwin_reuse_pages(m, start, end),
            act::CAN_REUSE => self.darwin_can_reuse(start, end),
            act::ZERO => self.darwin_vm_zero(m, start, end),
            _ => kr::INVALID_ARGUMENT,
        }
    }

    /// The task map's highest address (`vm_map_max`).
    pub(crate) fn darwin_map_max(&self) -> u64 {
        if self.dtask.map_max != 0 { self.dtask.map_max } else { vm::MAP_MAX }
    }

    /// A segment the loader mapped for the image (`load_segment`): its
    /// file's pages copy-on-write, the zero fill past them anonymous.
    pub fn darwin_image_segment(&mut self, vaddr: u64, filesize: u64, memsize: u64) {
        let (start, end) = (vaddr & !PAGE_MASK, round(vaddr + memsize));
        let file_end = round(vaddr + filesize).min(end);
        self.dtask.vm.set(start, file_end, Attrs { kind: kind::FILE_PRIVATE, ..Attrs::default() });
        self.dtask.vm.clear(file_end, end);
    }

    /// The new image's map, as `proc_apply_jit_and_vm_policies` makes it
    /// once its signature is known: the shared region nested in it, and
    /// its size, which a JIT entitlement or an extended address space
    /// makes jumbo and a spawn's `psa_max_addr` may raise
    /// (`vm_map_set_max_addr`; the field holds the spawn's until now).
    pub(crate) fn darwin_vm_policies(&mut self) {
        let (base, size) = self.darwin_region;
        if base != 0 {
            self.dtask.vm.set(base, base + size, Attrs { kind: kind::SUBMAP, ..Attrs::default() });
        }
        // mac_proc_check_map_anon(MAP_JIT) is AMFI's.
        if self.darwin_task_entitled("dynamic-codesigning") {
            self.darwin_unimplemented("AMFI's MAP_JIT check of an entitled image (its jumbo map)".into());
        }
        let jumbo = self.darwin_task_entitled("com.apple.developer.kernel.extended-virtual-addressing");
        let mut max = if jumbo { vm::JUMBO_MAX } else { vm::MAP_MAX };
        let want = self.dtask.map_max & !PAGE_MASK;
        if want > max {
            max = want.min(vm::JUMBO_MAX);
        }
        self.dtask.map_max = max;
    }

    /// Pass advice for `[s, e)` to the host; whether it took it.
    fn darwin_host_advise(&self, m: &mut GuestMem<'_>, p: &Piece, s: u64, e: u64, a: HostAdvice) -> bool {
        // Executable contents may change: their translations go.
        if matches!(a, HostAdvice::Free | HostAdvice::Reusable) && p.prot & prot::EXECUTE as u8 != 0 {
            self.map_io().retire_code_why(s, e - s, "madvise", u32::from(p.prot));
        }
        m.advise(s, e - s, a).unwrap_or(false)
    }

    /// Whether advice that frees pages (`kill_pages`) reaches this piece's
    /// object: one not shared by a fork's copy and with no shadow, which
    /// for gex's private file mappings (copies made at the mapping) means
    /// none, since their pages are the vnode object's or a shadow's.
    fn darwin_kills(p: &Piece) -> bool {
        matches!(p.attrs.kind, kind::ANON | kind::SHM) && !p.attrs.cow
    }

    /// `vm_map_msync(map, start, end - start, sync | VM_SYNC_CONTIGUOUS)`
    /// for `MADV_DONTNEED` (deactivate) and `MADV_FREE` (kill pages).
    fn darwin_msync_advice(&mut self, m: &mut GuestMem<'_>, start: u64, end: u64, sync: Sync) -> u64 {
        let pieces = self.darwin_pieces(start, end);
        let mut at = start;
        let mut had_hole = false;
        for p in &pieces {
            if p.start > at {
                had_hole = true;
                // No pages are killed past a hole: someone else could map
                // there.
                if sync == Sync::KillPages {
                    break;
                }
            }
            at = p.end;
            // The shared region's objects are every task's.
            if p.attrs.kind == kind::SUBMAP {
                continue;
            }
            match sync {
                Sync::Deactivate => {
                    if p.attrs.kind == kind::ANON {
                        self.darwin_host_advise(m, p, p.start, p.end, HostAdvice::Deactivate);
                    }
                }
                Sync::KillPages => {
                    if Self::darwin_kills(p) {
                        self.darwin_host_advise(m, p, p.start, p.end, HostAdvice::Free);
                    }
                }
            }
        }
        if at < end {
            had_hole = true;
        }
        if had_hole { kr::INVALID_ADDRESS } else { kr::SUCCESS }
    }

    /// `vm_map_willneed`: anonymous memory faulted in (`vm_pre_fault`, for
    /// reading and writing, so only where the entry may be written); a
    /// file's read ahead, which gex's copies made at the mapping have done.
    fn darwin_willneed(&mut self, m: &mut GuestMem<'_>, start: u64, end: u64) -> u64 {
        let pieces = self.darwin_pieces(start, end);
        if !Self::darwin_range_mapped(&pieces, start, end) {
            return kr::INVALID_ADDRESS;
        }
        for p in &pieces {
            if p.attrs.kind == kind::SUBMAP || p.prot & prot::READ as u8 == 0 {
                continue;
            }
            if matches!(p.attrs.kind, kind::ANON | kind::SHM) && p.prot & prot::WRITE as u8 != 0 {
                self.darwin_host_advise(m, p, p.start, p.end, HostAdvice::WillNeed);
            }
        }
        kr::SUCCESS
    }

    /// `vm_map_entry_is_reusable` of a piece, or the reason it cannot be
    /// told: whether a fork's copy has since been written.
    fn darwin_entry_reusable(&mut self, p: &Piece) -> bool {
        match vm::reusable(&p.attrs, p.prot) {
            Some(r) => r,
            None => {
                self.darwin_unimplemented("madvise reuse advice on a malloc region copied by a fork (copy-on-write shadow objects)".into());
                false
            }
        }
    }

    /// `vm_map_reusable_pages`.
    fn darwin_reusable_pages(&mut self, m: &mut GuestMem<'_>, start: u64, end: u64) -> u64 {
        let pieces = self.darwin_pieces(start, end);
        if !Self::darwin_range_mapped(&pieces, start, end) {
            return kr::INVALID_ADDRESS;
        }
        for p in &pieces {
            if !self.darwin_entry_reusable(p) {
                return kr::INVALID_ADDRESS;
            }
            // Not writable: its contents cannot be discarded.
            if p.prot & prot::WRITE as u8 == 0 {
                return KERN_PROTECTION_FAILURE;
            }
            if Self::darwin_kills(p) {
                self.darwin_host_advise(m, p, p.start, p.end, HostAdvice::Reusable);
            }
            // A large malloc block's tag says it is reusable now. (XNU skips
            // an entry with no object yet, one never touched, which only
            // a region query would tell apart.)
            if matches!(p.attrs.alias, vm::tag::MALLOC_LARGE | vm::tag::MALLOC_LARGE_REUSED) {
                self.dtask.vm.update(p.start, p.end, |a| a.alias = vm::tag::MALLOC_LARGE_REUSABLE);
            }
        }
        kr::SUCCESS
    }

    /// `vm_map_reuse_pages`.
    fn darwin_reuse_pages(&mut self, m: &mut GuestMem<'_>, start: u64, end: u64) -> u64 {
        let pieces = self.darwin_pieces(start, end);
        if !Self::darwin_range_mapped(&pieces, start, end) {
            return kr::INVALID_ADDRESS;
        }
        for p in &pieces {
            if !self.darwin_entry_reusable(p) {
                return kr::INVALID_ADDRESS;
            }
            if matches!(p.attrs.kind, kind::ANON | kind::SHM) {
                self.darwin_host_advise(m, p, p.start, p.end, HostAdvice::Reuse);
            }
            if p.attrs.alias == vm::tag::MALLOC_LARGE_REUSABLE {
                self.dtask.vm.update(p.start, p.end, |a| a.alias = vm::tag::MALLOC_LARGE_REUSED);
            }
        }
        kr::SUCCESS
    }

    /// `vm_map_can_reuse`.
    fn darwin_can_reuse(&mut self, start: u64, end: u64) -> u64 {
        let pieces = self.darwin_pieces(start, end);
        if !Self::darwin_range_mapped(&pieces, start, end) {
            return kr::INVALID_ADDRESS;
        }
        for p in &pieces {
            if !self.darwin_entry_reusable(p) {
                return kr::INVALID_ADDRESS;
            }
        }
        kr::SUCCESS
    }

    /// `vm_map_zero`: writable, not executable anonymous memory reads zero,
    /// entry by entry (`vm_map_zero_entry_preflight`, then
    /// `vm_object_zero_preflight`).
    fn darwin_vm_zero(&mut self, m: &mut GuestMem<'_>, start: u64, end: u64) -> u64 {
        let pieces = self.darwin_pieces(start, end);
        if !Self::darwin_range_mapped(&pieces, start, end) {
            return kr::INVALID_ADDRESS;
        }
        for p in &pieces {
            if p.prot & prot::WRITE as u8 == 0 || p.prot & prot::EXECUTE as u8 != 0 {
                return KERN_PROTECTION_FAILURE;
            }
            // Copy on write: a fork's copy (needs_copy, then a shadow), a
            // private file mapping (the same), or the shared region.
            if p.attrs.cow || matches!(p.attrs.kind, kind::FILE_PRIVATE | kind::SUBMAP) {
                return KERN_NO_ACCESS;
            }
            // Zeroing is for anonymous memory: not a file's own pages.
            if p.attrs.kind == kind::FILE_SHARED {
                return KERN_PROTECTION_FAILURE;
            }
            if !self.darwin_host_advise(m, p, p.start, p.end, HostAdvice::Zero) && m.zero_dirty(p.start, (p.end - p.start) as usize).is_err() {
                return kr::INVALID_ADDRESS;
            }
        }
        kr::SUCCESS
    }
}

use std::sync::Arc;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_range_overflows_as_vm_map_range_overflows_says() {
        assert!(!range_overflows(0, 0));
        assert!(!range_overflows(0x4000, 1));
        assert!(range_overflows(u64::MAX - 0x3fff, 0x8000));
        assert!(range_overflows(u64::MAX - 0x100, 0x10));
    }

    #[test]
    fn a_hole_breaks_a_range() {
        let p = |s, e| Piece { start: s, end: e, prot: 3, attrs: Attrs::default() };
        assert!(Kernel::darwin_range_mapped(&[p(0x4000, 0x8000), p(0x8000, 0xc000)], 0x4000, 0xc000));
        assert!(!Kernel::darwin_range_mapped(&[p(0x4000, 0x8000), p(0xc000, 0x10000)], 0x4000, 0x10000));
        assert!(!Kernel::darwin_range_mapped(&[p(0x4000, 0x8000)], 0x4000, 0xc000));
        assert!(!Kernel::darwin_range_mapped(&[], 0x4000, 0x8000));
    }
}
