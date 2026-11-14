//! Shared regions (`osfmk/vm/vm_shared_region.c`, xnu-10063.141.1) and the
//! calls dyld makes on them (`bsd/vm/vm_unix.c`): `shared_region_check_np`
//! and `shared_region_map_and_slide_2_np`.
//!
//! A region is the system's, one per environment (`vm_shared_region_lookup`):
//! a task enters its environment's at exec (`vm_shared_region_enter`), and a
//! fork's child the parent's; the first is made empty. The first dyld to
//! find its region empty (`shared_region_check_np`'s ENOMEM) maps the cache
//! into it, and every task in the region sees what it mapped; a dyld after
//! that finds it mapped and uses it as it is. On a device the first is
//! launchd's, at boot.
//!
//! This kernel is built as the T8010's is (`RELEASE_ARM64_T8010`, from
//! `MASTER.arm64.iPhoneOS`): no pointer authentication, so no authenticated
//! sections to remap, one region for every CPU subtype and reslide never
//! part of an environment; no mixed page sizes; no `CONFIG_CSR`, so the
//! cache must be on the process's root volume or the preboot cryptex
//! volume; `scdir_enforce` 0; and no `bootarg_disable_aslr`, a DEVELOPMENT
//! kernel's.
//!
//! Each task's memory holds its own copy of the region's mappings, put in
//! when it enters a mapped region or when the region it is in is mapped
//! ([`Kernel::darwin_region_install`]): a file's pages copy on write where
//! the host can map them, a slid mapping's from its slid copy (made by the
//! first task to need it, and kept for the boot's next ones when the host
//! keeps them, [`set_slid_dir`]), what the shared region pager would page in.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::errno::Errno;
use crate::syscalls::Kernel;
use crate::vfs::FileHandle;
use crate::GuestMem;

/// `VM_PROT_*` bits of a mapping's protections, and the flags
/// `shared_file_mapping_slide_np` carries with them.
pub mod prot {
    pub const READ: u32 = 1;
    pub const WRITE: u32 = 2;
    pub const EXECUTE: u32 = 4;
    pub const ALL: u32 = READ | WRITE | EXECUTE;
    /// `VM_PROT_ZF`: zero-filled, not from the file.
    pub const ZF: u32 = 0x10;
    /// `VM_PROT_SLIDE`: relocated by the slide.
    pub const SLIDE: u32 = 0x20;
    /// `VM_PROT_NOAUTH`: no authenticated pointers (arm64e's).
    pub const NOAUTH: u32 = 0x40;
    /// `VM_PROT_TPRO`: dyld's read-only __DATA_CONST, for a pager that
    /// protects it (arm64e's).
    pub const TPRO: u32 = 0x200;
}

/// `SHARED_REGION_BASE_ARM64` and `SHARED_REGION_SIZE_ARM64` (the pmap
/// nesting covers the same range).
pub const BASE: u64 = 0x1_8000_0000;
pub const SIZE: u64 = 0x1_8000_0000;

/// `CPU_TYPE_ARM64` and `CPU_TYPE_ARM`.
pub const CPU_TYPE_ARM64: i32 = 0x0100_000c;
const CPU_TYPE_ARM: i32 = 12;
/// `CPU_SUBTYPE_ARM64E` and `CPU_SUBTYPE_ARM64_ALL`.
const CPU_SUBTYPE_ARM64E: i32 = 2;
const CPU_SUBTYPE_ARM64_ALL: i32 = 0;

/// The region map's pages: 16 KiB (`vm_map_set_page_shift(SIXTEENK)`).
const PAGE_MASK: u64 = 0x3fff;

/// `SLIDE_AMOUNT_MASK`: `~SIXTEENK_PAGE_MASK`.
const SLIDE_AMOUNT_MASK: u32 = !0x3fff;

/// `_SR_FILE_MAPPINGS_MAX_FILES` and `SFM_MAX`.
const MAX_FILES: u32 = 256;
const SFM_MAX: u32 = MAX_FILES * 8;

/// `sizeof(struct shared_file_np)` and of `shared_file_mapping_slide_np`.
const FILE_NP_SIZE: usize = 12;
const MAPPING_NP_SIZE: usize = 48;

/// `MIN_SLIDE_INFO_SIZE` (v1's, v3's and v5's 24-byte headers) and
/// `SANE_SLIDE_INFO_SIZE`.
const MIN_SLIDE_INFO_SIZE: u64 = 24;
const SANE_SLIDE_INFO_SIZE: u64 = 2560 * 1024;

/// `PAGE_SIZE_FOR_SR_SLIDE` and `PAGE_SIZE_FOR_SR_SLIDE_16KB`.
const PAGE_SIZE_FOR_SR_SLIDE: u32 = 4096;
const PAGE_SIZE_FOR_SR_SLIDE_16KB: u32 = 16384;

/// `shared_region_destroy_delay`: an unused region is kept this long in
/// case a new task can use it (the `vm_shared_region_destroy_delay` boot
/// argument, not given).
const DESTROY_DELAY: Duration = Duration::from_secs(120);

/// `kern_return_t` values these calls deal in.
pub mod kr {
    pub const SUCCESS: u32 = 0;
    pub const INVALID_ADDRESS: u32 = 1;
    pub const PROTECTION_FAILURE: u32 = 2;
    pub const NO_SPACE: u32 = 3;
    pub const INVALID_ARGUMENT: u32 = 4;
    pub const FAILURE: u32 = 5;
    pub const RESOURCE_SHORTAGE: u32 = 6;
    pub const MEMORY_PRESENT: u32 = 23;
}

/// The environment a region serves: what `vm_shared_region_lookup`
/// matches. The root directory is every task's root vnode's (NULL):
/// `chroot` is not implemented here (it is reported). `rsr_version` is
/// macOS's, 0 here; the page shift is matched only with mixed page sizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Env {
    pub cputype: i32,
    pub cpu_subtype: i32,
    pub is_64bit: bool,
    /// `IMGPF_DRIVER`: a spawn with `POSIX_SPAWN_PROC_TYPE_DRIVER`.
    pub driverkit: bool,
}

impl Env {
    /// `vm_map_exec`'s for an arm64 image on this kernel: `cpu_type()`, and
    /// subtype 0 (`all cpu_subtypes use the same shared region` without
    /// pointer authentication).
    pub fn arm64(driverkit: bool) -> Env {
        Env { cputype: CPU_TYPE_ARM64, cpu_subtype: 0, is_64bit: true, driverkit }
    }

    /// `match_subtype`: an arm64 region matches an existing arm64e one.
    fn matches(&self, other: &Env) -> bool {
        let subtype = self.cpu_subtype == other.cpu_subtype || (self.cputype == CPU_TYPE_ARM64 && self.cpu_subtype == CPU_SUBTYPE_ARM64E && other.cpu_subtype == CPU_SUBTYPE_ARM64_ALL);
        self.cputype == other.cputype && subtype && self.is_64bit == other.is_64bit && self.driverkit == other.driverkit
    }
}

/// A file mapped in a region: its vnode, held for the region's life as
/// `ubc_map` holds it.
pub struct File {
    pub handle: Arc<dyn FileHandle>,
    /// `vn_getpath`: links resolved.
    pub path: String,
    /// The vnode (its mount and inode, `Kernel::darwin_vnode_of`).
    pub vnode: (u64, u64),
}

impl std::fmt::Debug for File {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("File").field("path", &self.path).field("vnode", &self.vnode).finish()
    }
}

/// What a mapping's pages are.
#[derive(Clone, Debug)]
pub enum Source {
    /// A file's pages from `offset` (the file's pager).
    File { file: usize, offset: u64 },
    /// An anonymous object holding what dyld gave from its own memory (its
    /// file descriptor -1).
    Data(Arc<Vec<u8>>),
    /// Zero-filled (`VM_PROT_ZF`).
    Zero,
}

/// One entry of the region's map, at its absolute address.
#[derive(Clone, Debug)]
pub struct Mapping {
    pub address: u64,
    /// Rounded to the map's pages.
    pub size: u64,
    pub source: Source,
    pub init_prot: u32,
    pub max_prot: u32,
    /// The slide info its shared region pager relocates its pages by, as
    /// copied in (`si_slide_info_entry`).
    pub slide: Option<Arc<Vec<u8>>>,
}

/// What a region holds.
#[derive(Debug, Default)]
pub struct Contents {
    /// `sr_slide`.
    pub slide: u32,
    /// `sr_first_mapping`: the first mapping made, from the base; none
    /// while the region is empty.
    pub first_mapping: Option<u64>,
    pub files: Vec<Arc<File>>,
    /// The map's entries, in the order made.
    pub mappings: Vec<Mapping>,
    /// `sr_uuid`, once copied in.
    pub uuid: Option<[u8; 16]>,
}

impl Contents {
    /// `vm_shared_region_start_address`'s answer.
    pub fn start(&self) -> Option<u64> {
        self.first_mapping.map(|o| BASE + o)
    }

    /// The entries `shared_region_make_permanent` made "permanent",
    /// `[start, end)`: every one neither writable nor executable at its
    /// most, which nothing may remove or replace from a task's map.
    pub fn permanent(&self) -> Vec<(u64, u64)> {
        self.mappings.iter().filter(|m| make_permanent(m.max_prot)).map(|m| (m.address, m.address + m.size)).collect()
    }

    /// The entry holding `addr`.
    fn entry_at(&self, addr: u64) -> Option<usize> {
        self.mappings.iter().position(|m| m.address <= addr && addr < m.address + m.size)
    }
}

/// `shared_region_make_permanent` on arm64.
fn make_permanent(max_prot: u32) -> bool {
    max_prot & (prot::WRITE | prot::EXECUTE) == 0
}

/// A region: `struct vm_shared_region`.
#[derive(Debug)]
pub struct SharedRegion {
    /// `sr_id`.
    pub id: u32,
    pub env: Env,
    /// `sr_base_address` and `sr_size`.
    pub base: u64,
    pub size: u64,
    /// Held while mappings are made (`sr_mapping_in_progress`).
    contents: Mutex<Contents>,
    /// Kept under the queue's lock (`vm_shared_region_lock`).
    refs: Mutex<Refs>,
}

#[derive(Debug, Default)]
struct Refs {
    /// `sr_ref_count`.
    count: u32,
    /// `sr_timer_call`'s deadline, while it holds a reference.
    timer: Option<Instant>,
    /// `sr_stale`.
    stale: bool,
    /// The processes whose maps nest it: what sees its pages when they
    /// are mapped.
    holders: Vec<i32>,
}

impl SharedRegion {
    pub fn contents(&self) -> MutexGuard<'_, Contents> {
        self.contents.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn refs(&self) -> MutexGuard<'_, Refs> {
        self.refs.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// `vm_shared_region_queue`, `vm_shared_region_lastid` and
/// `vm_shared_region_peak`.
struct Queue {
    regions: Vec<Arc<SharedRegion>>,
    lastid: u32,
    peak: u32,
}

fn queue() -> MutexGuard<'static, Queue> {
    static Q: Mutex<Queue> = Mutex::new(Queue { regions: Vec::new(), lastid: 0, peak: 0 });
    Q.lock().unwrap_or_else(|e| e.into_inner())
}

/// `vm_shared_region_count` and `vm_shared_region_peak`.
pub fn counts() -> (u32, u32) {
    let mut q = queue();
    fire_timers(&mut q);
    (q.regions.len() as u32, q.peak)
}

/// `vm_shared_region_timeout` for each timer past its deadline: its
/// reference dropped, the region destroyed with it.
fn fire_timers(q: &mut Queue) {
    let now = Instant::now();
    q.regions.retain(|r| {
        let mut refs = r.refs();
        match refs.timer {
            Some(deadline) if deadline <= now => {
                refs.count -= 1;
                refs.count != 0
            }
            _ => true,
        }
    });
}

/// `vm_shared_region_reference_locked`: a pending timer is cancelled and
/// its reference dropped.
fn reference_locked(r: &SharedRegion, pid: Option<i32>) {
    let mut refs = r.refs();
    refs.count += 1;
    if refs.timer.take().is_some() {
        refs.count -= 1;
    }
    if let Some(pid) = pid {
        refs.holders.push(pid);
    }
}

/// A reference on a region, dropped as `vm_shared_region_deallocate`:
/// a task's (`task->shared_region`), or the boot's own.
#[derive(Debug)]
pub struct RegionRef {
    region: Arc<SharedRegion>,
    pid: Option<i32>,
}

impl RegionRef {
    pub fn region(&self) -> &Arc<SharedRegion> {
        &self.region
    }

    /// `task_create_internal`'s `vm_shared_region_get` of the parent's for
    /// a fork's child `pid`.
    pub fn for_child(&self, pid: i32) -> RegionRef {
        let _q = queue();
        reference_locked(&self.region, Some(pid));
        RegionRef { region: Arc::clone(&self.region), pid: Some(pid) }
    }
}

impl Drop for RegionRef {
    /// `vm_shared_region_deallocate`: at no references left, a timer holds
    /// one for [`DESTROY_DELAY`] in case a new task can use it (not for a
    /// stale region); when it fires, the region goes. Persistence
    /// (`shared_region_persistence`) is off.
    fn drop(&mut self) {
        let mut q = queue();
        let gone = {
            let mut refs = self.region.refs();
            if let Some(pid) = self.pid {
                if let Some(i) = refs.holders.iter().position(|&h| h == pid) {
                    refs.holders.swap_remove(i);
                }
            }
            refs.count -= 1;
            if refs.count == 0 {
                if refs.timer.is_none() && !refs.stale {
                    refs.count += 1;
                    refs.timer = Some(Instant::now() + DESTROY_DELAY);
                    false
                } else {
                    true
                }
            } else {
                false
            }
        };
        if gone {
            q.regions.retain(|r| !Arc::ptr_eq(r, &self.region));
        }
    }
}

/// `vm_shared_region_lookup`: the region for `env`, made empty if there is
/// none, with a reference for `pid`'s map; `None` for an environment no
/// region is made for (`vm_shared_region_create`'s default).
pub fn lookup(env: Env, pid: Option<i32>) -> Option<RegionRef> {
    let mut q = queue();
    fire_timers(&mut q);
    if let Some(r) = q.regions.iter().find(|r| r.env.matches(&env) && !r.refs().stale) {
        reference_locked(r, pid);
        return Some(RegionRef { region: Arc::clone(r), pid });
    }
    match (env.is_64bit, env.cputype) {
        (true, CPU_TYPE_ARM64) | (false, CPU_TYPE_ARM) => {}
        _ => return None,
    }
    if !env.is_64bit {
        // SHARED_REGION_BASE_ARM's region: 32-bit arm images are not
        // loaded by this kernel's exec.
        return None;
    }
    q.lastid = q.lastid.checked_add(1).expect("shared_region: vm_shared_region_lastid wrapped");
    let region = Arc::new(SharedRegion {
        id: q.lastid,
        env,
        base: BASE,
        size: SIZE,
        contents: Mutex::new(Contents::default()),
        refs: Mutex::new(Refs { count: 1, timer: None, stale: false, holders: pid.into_iter().collect() }),
    });
    q.regions.push(Arc::clone(&region));
    q.peak = q.peak.max(q.regions.len() as u32);
    Some(RegionRef { region, pid })
}

/// `vm_shared_region_pivot`: every region stale, so nothing new uses one
/// and each goes with its last user (its pending timer fires now).
pub fn pivot() {
    let mut q = queue();
    q.regions.retain(|r| {
        let mut refs = r.refs();
        refs.stale = true;
        if refs.timer.take().is_some() {
            refs.count -= 1;
        }
        refs.count != 0
    });
}

/// The boot's region references held for processes this kernel stands in
/// for (pid 1's, when pid 1 is the kernel's own: launchd holds the region
/// it mapped at boot for as long as it runs).
static STAND_IN: Mutex<Vec<RegionRef>> = Mutex::new(Vec::new());

/// The vnodes the shared region has mapped files of (`VSHARED_DYLD`).
static SHARED_DYLD: Mutex<Vec<(u64, u64)>> = Mutex::new(Vec::new());

/// Whether `vnode` is a file the shared region maps (`VSHARED_DYLD`).
pub fn shared_dyld(vnode: (u64, u64)) -> bool {
    SHARED_DYLD.lock().unwrap_or_else(|e| e.into_inner()).contains(&vnode)
}

/// A file of any region, by its volume's `f_fsid.val[0]` and its inode,
/// as `fsgetpath` finds what the cache's dynamic data names: its path.
pub fn file_path(fsid: u32, ino: u64) -> Option<String> {
    let q = queue();
    for r in &q.regions {
        let c = r.contents();
        if let Some(f) = c.files.iter().find(|f| f.vnode.1 == ino && super::kern::mount_of(&f.path).fsid as u32 == fsid) {
            return Some(f.path.clone());
        }
    }
    None
}

/// Where the host keeps slid mappings for later tasks; none keeps none.
static SLID_DIR: std::sync::OnceLock<fn() -> Option<std::path::PathBuf>> = std::sync::OnceLock::new();

/// Install the host's directory for slid mappings.
pub fn set_slid_dir(f: fn() -> Option<std::path::PathBuf>) {
    let _ = SLID_DIR.set(f);
}

/// `shared_region_map_and_slide_2_np`'s choice of slide from the first
/// file's `sf_slide`, dyld's `maxSlide`: `read_random`'s 32 bits modulo it,
/// on a 16 KiB boundary; none for a cache that cannot slide.
pub fn choose_slide(max_slide: u32) -> u32 {
    if max_slide == 0 {
        return 0;
    }
    let mut b = [0u8; 4];
    crate::vfs::devfs::fill_random(&mut b);
    (u32::from_le_bytes(b) % max_slide) & SLIDE_AMOUNT_MASK
}

/// `struct shared_file_np`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileNp {
    pub fd: i32,
    pub mappings_count: u32,
    pub slide: u32,
}

/// `struct shared_file_mapping_slide_np`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MappingNp {
    pub address: u64,
    pub size: u64,
    pub file_offset: u64,
    pub slide_size: u64,
    pub slide_start: u64,
    pub max_prot: u32,
    pub init_prot: u32,
}

impl FileNp {
    fn parse(b: &[u8]) -> FileNp {
        let u = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        FileNp { fd: u(0) as i32, mappings_count: u(4), slide: u(8) }
    }
}

impl MappingNp {
    fn parse(b: &[u8]) -> MappingNp {
        let q = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let u = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        MappingNp { address: q(0), size: q(8), file_offset: q(16), slide_size: q(24), slide_start: q(32), max_prot: u(40), init_prot: u(44) }
    }
}

/// `struct _sr_file_mappings`: a file and its mappings, as setup made it.
pub struct SrFile {
    pub fd: i32,
    pub file: Option<Arc<File>>,
    pub mappings: Vec<MappingNp>,
    pub slide: u32,
}

/// The address space a mapping call reads from: the calling task's, which
/// nests the region (`copyin`), and which sees the region's mappings as
/// they are made.
pub trait Space {
    /// `copyin` of `len` bytes at `addr`: an errno for what cannot be read.
    fn copyin(&mut self, c: &Contents, addr: u64, len: u64) -> Result<Vec<u8>, Errno>;
    /// The region's entry `i` was made (or replaced, slid).
    fn entered(&mut self, c: &Contents, i: usize);
    /// The region's entries `gone` were removed.
    fn removed(&mut self, gone: &[Mapping]);
}

/// The bytes the region's entries hold at `[addr, addr + len)`, as a task
/// nesting it reads them; `None` where no entry covers them.
pub fn region_bytes(c: &Contents, addr: u64, len: u64) -> Option<Vec<u8>> {
    let end = addr.checked_add(len)?;
    let mut out = Vec::with_capacity(len as usize);
    let mut at = addr;
    while at < end {
        let i = c.entry_at(at)?;
        let mp = &c.mappings[i];
        let n = (mp.address + mp.size).min(end) - at;
        let off = at - mp.address;
        let mut b = vec![0u8; n as usize];
        match &mp.source {
            Source::Zero => {}
            Source::Data(d) => {
                let from = (off as usize).min(d.len());
                let to = ((off + n) as usize).min(d.len());
                b[..to - from].copy_from_slice(&d[from..to]);
            }
            Source::File { file, offset } => {
                let mut got = 0;
                while got < b.len() {
                    match c.files[*file].handle.read_at(offset + off + got as u64, &mut b[got..]) {
                        Ok(0) | Err(_) => break,
                        Ok(k) => got += k as usize,
                    }
                }
            }
        }
        if let Some(info) = &mp.slide {
            // The pager's pages: the whole mapping slid, then the part asked.
            let mut whole = region_bytes_unslid(c, mp)?;
            gex_ld::dsc::apply_slide(&mut whole, info, u64::from(c.slide)).ok()?;
            b.copy_from_slice(&whole[off as usize..(off + n) as usize]);
        }
        out.extend_from_slice(&b);
        at += n;
    }
    Some(out)
}

/// A slid entry's file pages, before the slide.
fn region_bytes_unslid(c: &Contents, mp: &Mapping) -> Option<Vec<u8>> {
    let Source::File { file, offset } = &mp.source else { return None };
    let mut b = vec![0u8; mp.size as usize];
    let mut got = 0;
    while got < b.len() {
        match c.files[*file].handle.read_at(offset + got as u64, &mut b[got..]) {
            Ok(0) | Err(_) => break,
            Ok(k) => got += k as usize,
        }
    }
    Some(b)
}

/// `vm_map_enter` (or `vm_map_enter_mem_object`) of an entry at `target`
/// (from the base) in the region's map, `VM_FLAGS_FIXED` with
/// `vmkf_already`: what is already there exactly is KERN_MEMORY_PRESENT,
/// anything else in the way KERN_NO_SPACE.
fn map_enter(c: &Contents, region_size: u64, target: u64, size: u64, offset: u64, new: &Mapping) -> u32 {
    if size == 0 || offset & PAGE_MASK != 0 {
        return kr::INVALID_ARGUMENT;
    }
    let Some(end) = target.checked_add(size) else { return kr::INVALID_ADDRESS };
    if end > region_size || target >= end {
        return kr::INVALID_ADDRESS;
    }
    let (start, end) = (BASE + target, BASE + end);
    let mut overlapping = c.mappings.iter().filter(|m| m.address < end && start < m.address + m.size).peekable();
    if overlapping.peek().is_none() {
        return kr::SUCCESS;
    }
    // vm_map_lookup_entry of the start: only an entry holding it can be
    // what is already there; one after it in the way is KERN_NO_SPACE.
    let Some(i) = c.entry_at(start) else { return kr::NO_SPACE };
    let (mut tmp_start, mut tmp_offset) = (start, offset);
    let first = &c.mappings[i];
    if first.address < start {
        tmp_start -= start - first.address;
        tmp_offset = tmp_offset.wrapping_sub(start - first.address);
    }
    let mut order: Vec<&Mapping> = c.mappings.iter().filter(|m| m.address >= first.address && m.address < end).collect();
    order.sort_by_key(|m| m.address);
    for e in order {
        let same_object = match (&e.source, &new.source) {
            (Source::File { file: a, offset: oa }, Source::File { file: b, .. }) => Arc::ptr_eq(&c.files[*a], &c.files[*b]) && *oa == tmp_offset,
            // Both anonymous memory: equivalent.
            (Source::Zero | Source::Data(_), Source::Zero | Source::Data(_)) => true,
            _ => false,
        };
        if e.address != tmp_start || !same_object || e.init_prot != new.init_prot || e.max_prot != new.max_prot {
            return kr::NO_SPACE;
        }
        tmp_offset += e.size;
        tmp_start += e.size;
        if e.address + e.size >= end {
            break;
        }
    }
    kr::MEMORY_PRESENT
}

/// `vm_shared_region_slide_sanity_check` of slide info `s`.
fn slide_sanity_check(s: &[u8]) -> u32 {
    let u32_at = |o: usize| s.get(o..o + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));
    let size = s.len() as u64;
    let Some(version) = u32_at(0) else { return kr::FAILURE };
    let ok = match version {
        1 => {
            // Every table-of-contents entry names an entry that exists.
            let (Some(toc_offset), Some(toc_count), Some(entry_count)) = (u32_at(4), u32_at(8), u32_at(16)) else { return kr::FAILURE };
            (0..toc_count as usize).all(|i| {
                let o = toc_offset as usize + i * 2;
                s.get(o..o + 2).is_some_and(|b| u32::from(u16::from_le_bytes([b[0], b[1]])) < entry_count)
            })
        }
        2 | 4 => {
            const HEADER: u64 = 40;
            let (Some(page_size), Some(starts), Some(extras)) = (u32_at(4), u32_at(12), u32_at(20)) else { return kr::FAILURE };
            size >= HEADER && page_size == PAGE_SIZE_FOR_SR_SLIDE && HEADER + (u64::from(starts) + u64::from(extras)) * 2 <= size
        }
        3 | 5 => {
            const HEADER: u64 = 24;
            let want = if version == 3 { PAGE_SIZE_FOR_SR_SLIDE } else { PAGE_SIZE_FOR_SR_SLIDE_16KB };
            let (Some(page_size), Some(starts)) = (u32_at(4), u32_at(8)) else { return kr::FAILURE };
            size >= HEADER && page_size == want && HEADER + u64::from(starts) * 2 <= size
        }
        _ => false,
    };
    if ok {
        kr::SUCCESS
    } else {
        kr::FAILURE
    }
}

/// `vm_shared_region_map_file` (with its setup and final parts) of `files`
/// into `region`, from `space`: the entries made, each slid mapping then
/// overwritten with its pager's (`vm_shared_region_slide`); on a failure
/// what this call made is undone.
pub fn map_file(region: &SharedRegion, files: &mut [SrFile], space: &mut dyn Space) -> (u32, Option<String>) {
    let mut c = region.contents();
    // Did someone race in and map this shared region already?
    if c.first_mapping.is_some() {
        return (kr::FAILURE, None);
    }
    let mut made: Vec<usize> = Vec::new();
    let mut to_slide: Vec<(usize, MappingNp)> = Vec::new();
    let mut kret = kr::SUCCESS;
    let file_base = c.files.len();
    for srf in files.iter_mut() {
        if srf.mappings.is_empty() {
            continue;
        }
        // One slide for the region: a file's nonzero slide must match.
        if c.slide == 0 && srf.slide != 0 {
            c.slide = srf.slide;
        } else if c.slide != 0 && srf.slide != 0 && c.slide != srf.slide {
            kret = kr::INVALID_ARGUMENT;
            break;
        }
        if srf.slide & PAGE_MASK as u32 != 0 {
            kret = kr::INVALID_ARGUMENT;
            break;
        }
        if srf.fd == -1 {
            // An anonymous object with dyld's bytes, zeroed past them.
            let mp = srf.mappings[0];
            let obj_size = (mp.size + PAGE_MASK) & !PAGE_MASK;
            let data = match space.copyin(&c, mp.file_offset, mp.size) {
                Ok(d) => d,
                Err(e) => {
                    kret = match e {
                        Errno::EPERM | Errno::EACCES => kr::PROTECTION_FAILURE,
                        Errno::EFAULT => kr::INVALID_ADDRESS,
                        _ => kr::FAILURE,
                    };
                    break;
                }
            };
            let mut obj = data;
            obj.resize(obj_size as usize, 0);
            let entry = Mapping { address: mp.address, size: obj_size, source: Source::Data(Arc::new(obj)), init_prot: mp.init_prot & prot::ALL, max_prot: mp.max_prot & prot::ALL, slide: None };
            match map_enter(&c, region.size, mp.address.wrapping_sub(region.base), obj_size, 0, &entry) {
                kr::SUCCESS => {
                    c.mappings.push(entry);
                    made.push(c.mappings.len() - 1);
                    space.entered(&c, c.mappings.len() - 1);
                }
                k => {
                    kret = k;
                    break;
                }
            }
            if mp.address.checked_add(mp.size).is_none_or(|e| ((e + PAGE_MASK) & !PAGE_MASK) < mp.address) {
                kret = kr::INVALID_ARGUMENT;
                break;
            }
            continue;
        }
        let file_index = {
            let f = srf.file.as_ref().expect("a file for a descriptor");
            match c.files.iter().position(|g| Arc::ptr_eq(g, f)) {
                Some(i) => i,
                None => {
                    c.files.push(Arc::clone(f));
                    c.files.len() - 1
                }
            }
        };
        for i in 0..srf.mappings.len() {
            let mp = srf.mappings[i];
            if mp.address.checked_add(mp.size).is_none_or(|e| ((e + PAGE_MASK) & !PAGE_MASK) < mp.address) {
                kret = kr::INVALID_ARGUMENT;
                break;
            }
            let size = (mp.size + PAGE_MASK) & !PAGE_MASK;
            let source = if mp.init_prot & prot::ZF != 0 { Source::Zero } else { Source::File { file: file_index, offset: mp.file_offset } };
            let entry = Mapping { address: mp.address, size, source, init_prot: mp.init_prot & prot::ALL, max_prot: mp.max_prot & prot::ALL, slide: None };
            let offset = if mp.init_prot & prot::ZF != 0 { 0 } else { mp.file_offset };
            match map_enter(&c, region.size, mp.address.wrapping_sub(region.base), size, offset, &entry) {
                kr::SUCCESS => {
                    if c.first_mapping.is_none() {
                        c.first_mapping = Some(mp.address - region.base);
                    }
                    c.mappings.push(entry);
                    let at = c.mappings.len() - 1;
                    made.push(at);
                    if mp.max_prot & prot::SLIDE != 0 {
                        to_slide.push((at, mp));
                    }
                    space.entered(&c, at);
                }
                // Already there exactly: not made by this call, so neither
                // undone nor slid by it.
                kr::MEMORY_PRESENT => {}
                k => {
                    kret = k;
                    break;
                }
            }
        }
        if kret != kr::SUCCESS {
            break;
        }
    }
    if kret == kr::SUCCESS {
        // The relocated mappings, each with its slide info copied in from
        // the task (from its __LINKEDIT, mapped just now).
        for &(at, mp) in &to_slide {
            if mp.slide_size < MIN_SLIDE_INFO_SIZE || mp.slide_size > SANE_SLIDE_INFO_SIZE {
                kret = kr::FAILURE;
                break;
            }
            let info = match space.copyin(&c, mp.slide_start, mp.slide_size) {
                Ok(i) => i,
                Err(_) => {
                    kret = kr::INVALID_ADDRESS;
                    break;
                }
            };
            kret = slide_sanity_check(&info);
            if kret != kr::SUCCESS {
                break;
            }
            match gex_ld::dsc::slide_version(&info) {
                Ok(2 | 3 | 5) => {}
                Ok(v) => {
                    return undo(&mut c, &made, file_base, space, kr::FAILURE, Some(format!("the shared region pager's slide info version {v} (vm_shared_region_slide_page_v{v})")));
                }
                Err(_) => {
                    kret = kr::FAILURE;
                    break;
                }
            }
            c.mappings[at].slide = Some(Arc::new(info));
            space.entered(&c, at);
        }
    }
    if kret != kr::SUCCESS {
        return undo(&mut c, &made, file_base, space, kret, None);
    }
    // vm_shared_region_map_file_final: the cache's UUID, from the header
    // at the first mapping.
    if c.uuid.is_none() {
        if let Some(start) = c.start() {
            const UUID: u64 = 0x58;
            if let Ok(u) = space.copyin(&c, start + UUID, 16) {
                c.uuid = u.try_into().ok();
            }
        }
    }
    drop(c);
    // cleanup: each file's vnode is the shared cache's from now on.
    let mut sd = SHARED_DYLD.lock().unwrap_or_else(|e| e.into_inner());
    for srf in files.iter() {
        if let Some(f) = &srf.file {
            if !sd.contains(&f.vnode) {
                sd.push(f.vnode);
            }
        }
    }
    (kr::SUCCESS, None)
}

/// `vm_shared_region_undo_mappings` of what this call made, and the region
/// empty again (`sr_first_mapping` -1; `sr_slide` stays).
fn undo(c: &mut Contents, made: &[usize], file_base: usize, space: &mut dyn Space, k: u32, unported: Option<String>) -> (u32, Option<String>) {
    let mut gone = Vec::new();
    for &i in made.iter().rev() {
        gone.push(c.mappings.remove(i));
    }
    c.files.truncate(file_base);
    c.first_mapping = None;
    space.removed(&gone);
    (k, unported)
}

/// What `_shared_region_map_and_slide` makes of a `kern_return_t`.
fn kr_errno(k: u32) -> Errno {
    match k {
        kr::SUCCESS => Errno(0),
        kr::INVALID_ADDRESS => Errno::EFAULT,
        kr::PROTECTION_FAILURE => Errno::EPERM,
        kr::NO_SPACE => Errno::ENOMEM,
        _ => Errno::EINVAL,
    }
}

/// The calling task's address space, for a mapping call it makes.
struct TaskSpace<'k, 'm, 'g> {
    k: &'k mut Kernel,
    m: &'m mut GuestMem<'g>,
    /// Why an entry could not be put in a task's memory.
    unported: Vec<String>,
}

impl Space for TaskSpace<'_, '_, '_> {
    fn copyin(&mut self, _c: &Contents, addr: u64, len: u64) -> Result<Vec<u8>, Errno> {
        if !self.k.mem.lock().check_access(addr, len, crate::mem::prot::READ) {
            return Err(Errno::EFAULT);
        }
        Ok(self.m.read(addr, len as usize)?.to_vec())
    }

    fn entered(&mut self, c: &Contents, i: usize) {
        if let Err(why) = install(&self.k.mem, self.m, c, &c.mappings[i]) {
            self.unported.push(why);
        }
    }

    fn removed(&mut self, gone: &[Mapping]) {
        for mp in gone {
            uninstall(&self.k.mem, self.m, mp);
        }
    }
}

/// A region's entry put in a task's memory, and in its memory map with the
/// entry's protections.
fn install(mm: &crate::mem::Mm, m: &mut GuestMem<'_>, c: &Contents, mp: &Mapping) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    let (start, len) = (mp.address, mp.size);
    crate::big_op("shared cache", len as usize);
    match &mp.source {
        Source::Zero => {
            m.discard(start, len as usize).map_err(|e| format!("zeroing {start:#x}: {e:?}"))?;
        }
        Source::Data(d) => {
            let n = d.len().min(len as usize);
            m.write(start, &d[..n]).map_err(|e| format!("writing {start:#x}: {e:?}"))?;
        }
        Source::File { file, offset } => {
            let f = &c.files[*file];
            let fsize = f.handle.metadata().map(|md| md.size).unwrap_or(0);
            if offset.saturating_add(len) > fsize.div_ceil(PAGE_MASK + 1) * (PAGE_MASK + 1) {
                return Err(format!("a shared region mapping of {} past its end ({:#x}+{len:#x} of {fsize:#x} bytes): those pages fault on a device", f.path, offset));
            }
            match &mp.slide {
                None => {
                    let mapped = f.handle.host_fd().is_some_and(|fd| offset + len <= fsize && m.map_file(start, len, fd, *offset).unwrap_or(false));
                    if !mapped {
                        let mut b = vec![0u8; len as usize];
                        read_full(f.handle.as_ref(), *offset, &mut b);
                        m.write(start, &b).map_err(|e| format!("writing {start:#x}: {e:?}"))?;
                    }
                }
                Some(info) => {
                    let key = slid_name(c, f, *offset, len, info);
                    let kept = key.as_ref().and_then(|p| std::fs::File::open(p).ok()).filter(|h| h.metadata().is_ok_and(|md| md.len() == len));
                    let mapped = kept.is_some_and(|h| m.map_file(start, len, h.as_raw_fd(), 0).unwrap_or(false));
                    if !mapped {
                        let mut b = vec![0u8; len as usize];
                        read_full(f.handle.as_ref(), *offset, &mut b);
                        gex_ld::dsc::apply_slide(&mut b, info, u64::from(c.slide)).map_err(|e| format!("sliding {}: {e}", f.path))?;
                        m.write(start, &b).map_err(|e| format!("writing {start:#x}: {e:?}"))?;
                        if let Some(p) = key {
                            save_slid(&p, &b);
                        }
                    }
                }
            }
        }
    }
    let mut pr = 0;
    if mp.init_prot & prot::READ != 0 {
        pr |= crate::mem::prot::READ;
    }
    if mp.init_prot & prot::WRITE != 0 {
        pr |= crate::mem::prot::WRITE;
    }
    if mp.init_prot & prot::EXECUTE != 0 {
        pr |= crate::mem::prot::EXEC;
    }
    let name = if matches!(mp.source, Source::File { .. }) { "[shared-cache]" } else { "[shared-cache-data]" };
    mm.lock().insert(start, start + len, pr, name);
    Ok(())
}

/// A removed entry out of a task's memory and its map.
fn uninstall(mm: &crate::mem::Mm, m: &mut GuestMem<'_>, mp: &Mapping) {
    let _ = m.discard(mp.address, mp.size as usize);
    let _ = mm.lock().unmap(mp.address, mp.size);
}

fn read_full(h: &dyn FileHandle, at: u64, b: &mut [u8]) {
    let mut got = 0;
    while got < b.len() {
        match h.read_at(at + got as u64, &mut b[got..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => got += n as usize,
        }
    }
}

/// The file a slid mapping is kept in: named by the cache file's UUID, the
/// mapping, its slide info and the slide.
fn slid_name(c: &Contents, f: &File, offset: u64, len: u64, info: &[u8]) -> Option<std::path::PathBuf> {
    use sha2::Digest;
    let dir = SLID_DIR.get()?()?;
    let mut uuid = [0u8; 16];
    read_full(f.handle.as_ref(), 0x58, &mut uuid);
    let mut h = sha2::Sha256::new();
    h.update(b"gex dsc slid 1\0");
    h.update(uuid);
    h.update(offset.to_le_bytes());
    h.update(len.to_le_bytes());
    h.update(info);
    let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    Some(dir.join(format!("{hex}-{:x}.slid", c.slide)))
}

/// Keep a mapping's slid bytes for the boot's next task (written whole,
/// then renamed into place, so a reader never sees part of one). Each boot
/// slides anew, so the same mapping's copies at other slides are removed.
fn save_slid(path: &std::path::Path, bytes: &[u8]) {
    let Some(dir) = path.parent() else { return };
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    if std::fs::write(&tmp, bytes).is_ok() && std::fs::rename(&tmp, path).is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_string();
    let Some((stem, _)) = name.rsplit_once('-') else { return };
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let other = e.file_name();
        let other = other.to_string_lossy();
        if other != name && other.ends_with(".slid") && other.rsplit_once('-').is_some_and(|(s, _)| s == stem) {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// The boot's address space for a mapping this kernel makes for a process
/// it stands in for (launchd's dyld at boot): the region as mapped so far,
/// and dyld's own page of dynamic data at `data.0`.
struct BootSpace {
    data: (u64, Vec<u8>),
}

impl Space for BootSpace {
    fn copyin(&mut self, c: &Contents, addr: u64, len: u64) -> Result<Vec<u8>, Errno> {
        let (at, d) = (self.data.0, &self.data.1);
        if addr >= at && addr.checked_add(len).is_some_and(|e| e <= at + d.len() as u64) {
            let o = (addr - at) as usize;
            return Ok(d[o..o + len as usize].to_vec());
        }
        region_bytes(c, addr, len).ok_or(Errno::EFAULT)
    }

    fn entered(&mut self, _c: &Contents, _i: usize) {}

    fn removed(&mut self, _gone: &[Mapping]) {}
}

impl Kernel {
    /// `vm_map_exec`'s `vm_shared_region_enter` for the image this process
    /// starts: its environment's region, made empty if there is none, in
    /// place of the one it had; what it holds put in this task's memory.
    pub fn darwin_shared_region_enter(&mut self, m: &mut GuestMem<'_>, driverkit: bool) {
        let r = lookup(Env::arm64(driverkit), Some(self.pid));
        if let Some(r) = &r {
            let c = r.region().contents();
            for mp in &c.mappings {
                if let Err(why) = install(&self.mem, m, &c, mp) {
                    drop(c);
                    self.darwin_unimplemented(why);
                    break;
                }
            }
        }
        self.darwin_shared_region = r;
    }

    /// The region the boot's pid 1 mapped before this run's first program
    /// when pid 1 is this kernel's own (launchd's dyld at boot, which
    /// `mapSplitCacheSystemWide` does): the cache at `dir` (`main`, then its
    /// subcaches) preflighted as dyld preflights it (its code signatures
    /// added to the files), then mapped and slid by the same calls, with
    /// dyld's page of dynamic data. The reference is the stand-in's.
    pub fn darwin_boot_shared_region(&mut self, dir: &str, main: &str) -> Result<(), String> {
        let mut stand_in = STAND_IN.lock().unwrap_or_else(|e| e.into_inner());
        if !stand_in.is_empty() {
            return Ok(());
        }
        let Some(r) = lookup(Env::arm64(false), None) else { return Err("no shared region for arm64".into()) };
        let mut files: Vec<SrFile> = Vec::new();
        let (first, ids) = self.darwin_boot_preflight(&format!("{dir}/{main}"))?;
        let mut mappings_main = first.mappings.clone();
        let subcaches = first.subcaches.clone();
        let max_slide = u32::try_from(first.max_slide).map_err(|_| "the shared cache's maxSlide".to_string())?;
        files.push(SrFile { fd: 0, file: Some(first.file), mappings: std::mem::take(&mut mappings_main), slide: max_slide });
        for suffix in &subcaches {
            let (p, _) = self.darwin_boot_preflight(&format!("{dir}/{main}{suffix}"))?;
            files.push(SrFile { fd: 0, file: Some(p.file), mappings: p.mappings, slide: 0 });
        }
        // dyld's vm_allocate'd page of dynamic data, at an address no
        // region mapping holds (vm_allocate anywhere: below the region).
        const PAGE: u64 = 0x4000;
        let mut data = vec![0u8; PAGE as usize];
        let hdr = gex_ld::dsc::dynamic_data_header(u64::from(ids.0), ids.1);
        data[..hdr.len()].copy_from_slice(&hdr);
        let data_at = BASE - PAGE;
        let (start, _) = first.dynamic;
        files.push(SrFile { fd: -1, file: None, mappings: vec![MappingNp { address: start, size: PAGE, file_offset: data_at, slide_size: 0, slide_start: 0, max_prot: prot::READ, init_prot: prot::READ }], slide: 0 });
        // shared_region_map_and_slide_2_np's slide, every mapping moved by it.
        let slide = choose_slide(max_slide);
        for f in files.iter_mut() {
            f.slide = slide;
            for mp in f.mappings.iter_mut() {
                mp.address += u64::from(slide);
                if mp.slide_size != 0 {
                    mp.slide_start += u64::from(slide);
                }
            }
        }
        // Setup's checks as launchd meets them: root, and no sandbox.
        for f in &files {
            if let Some(file) = &f.file {
                self.darwin_sr_check_file(file, &f.mappings, None).map_err(|e| format!("{}: {e:?}", file.path))?;
            }
        }
        let mut space = BootSpace { data: (data_at, data) };
        match map_file(r.region(), &mut files, &mut space) {
            (kr::SUCCESS, _) => {}
            (k, Some(why)) => return Err(format!("{why} (kern_return {k})")),
            (k, None) => return Err(format!("mapping the shared cache: kern_return {k}")),
        }
        stand_in.push(r);
        Ok(())
    }

    /// dyld's `preflightCacheFile` of the cache file at `path`, as the
    /// mapping it asks for: the file opened, its header checked, its code
    /// signature added (`F_ADDFILESIGS_RETURN`), and its mappings (each slid
    /// one's slide info named by its address in the file's __LINKEDIT);
    /// with its `st_dev` and `st_ino` (what the dynamic data names).
    fn darwin_boot_preflight(&mut self, path: &str) -> Result<(Preflight, (u32, u64)), String> {
        use gex_ld::dsc;
        let handle = self.vfs.open(path, crate::fs::oflags::O_RDONLY, 0).map_err(|e| format!("opening {path}: {e:?}"))?;
        let md = handle.metadata().map_err(|e| format!("{path}: {e:?}"))?;
        let canonical = self.vfs.canonical(&self.vfs.absolute(path));
        let vnode = (self.vfs.mount_id_of(&canonical), md.ino);
        let ids = (super::kern::mount_of(&canonical).fsid as u32, md.ino);
        // The header and the tables it points at (dyld reads the first
        // page; the image list a main cache names is past it).
        let mut head = vec![0u8; md.size.min(8 << 20) as usize];
        read_full(handle.as_ref(), 0, &mut head);
        let h = dsc::parse_header(&head).map_err(|e| format!("{path}: {e}"))?;
        let u64_at = |o: usize| u64::from_le_bytes(head[o..o + 8].try_into().unwrap());
        let (cs_offset, cs_size) = (u64_at(0x28), u64_at(0x30));
        if cs_offset + cs_size != md.size {
            return Err(format!("{path}: shared cache code signature size is invalid"));
        }
        let mut blob = vec![0u8; cs_size as usize];
        read_full(handle.as_ref(), cs_offset, &mut blob);
        let (_, end) = super::codesign::add_blob(vnode, 0, &blob).map_err(|e| format!("{path}: code signature registration for shared cache failed ({e:?})"))?;
        if end < cs_offset {
            return Err(format!("{path}: code signature does not cover entire shared cache file"));
        }
        let linkedit = h.mappings.last().cloned();
        let mut mappings = Vec::new();
        for (i, m) in h.mappings.iter().enumerate() {
            let flags = mapping_flags(&head, i);
            let (mut init, mut max) = (m.init_prot, m.max_prot);
            // DYLD_CACHE_MAPPING_CONST_DATA: __DATA_CONST, kept read-only
            // (dyld's enableReadOnlyDataConst, on unless a boot argument
            // turns it off), for the kernel to protect.
            if flags & CONST_DATA != 0 {
                max |= prot::TPRO;
            }
            let mut mp = MappingNp { address: m.address, size: m.size, file_offset: m.file_offset, slide_size: 0, slide_start: 0, max_prot: max, init_prot: init };
            if let (Some((si_off, si_size)), Some(le)) = (m.slide_info, linkedit.as_ref()) {
                // DYLD_CACHE_MAPPING_AUTH_DATA clear: VM_PROT_NOAUTH.
                let auth = if flags & AUTH_DATA == 0 { prot::NOAUTH } else { 0 };
                mp.slide_start = le.address + (si_off - le.file_offset);
                mp.slide_size = si_size;
                init |= prot::SLIDE | auth;
                mp.init_prot = init;
                mp.max_prot = max | prot::SLIDE | auth;
            }
            mappings.push(mp);
        }
        let file = Arc::new(File { handle, path: canonical, vnode });
        let dynamic = (h.shared_region_start + h.dynamic_data.map_or(0, |d| d.0), h.dynamic_data.map_or(0, |d| d.1));
        let subcaches = h.subcaches.iter().map(|s| s.suffix.clone()).collect();
        Ok((Preflight { file, mappings, subcaches, max_slide: h.max_slide, dynamic }, ids))
    }

    /// `shared_region_map_and_slide_setup`'s checks of a vnode to map: a
    /// regular file, `mac_file_check_mmap` (Sandbox's, of everything),
    /// owned by root (as `stat` reports owners here: the caller's ids), on
    /// the process's root volume or the preboot cryptex volume, and every
    /// mapping but a zero-filled one covered by a code signature on it.
    /// `caller` is this process (`Some(uid)`), or none for launchd at boot,
    /// root with no sandbox.
    fn darwin_sr_check_file(&mut self, f: &File, mappings: &[MappingNp], caller: Option<u32>) -> Result<(), Errno> {
        let md = f.handle.metadata()?;
        if md.file_type != crate::vfs::FileType::Regular {
            return Err(Errno::EINVAL);
        }
        if let Some(uid) = caller {
            let v = super::macvfs::sb_vnode(&f.path, &md);
            let e = self.darwin_mac_check_file_mmap(v, u64::from(prot::ALL), shared_dyld(f.vnode));
            if e != 0 {
                return Err(super::errno::errno_of(e as i32));
            }
            if uid != 0 {
                return Err(Errno::EPERM);
            }
        }
        let file_mount = super::kern::mount_of(&f.path).on;
        if file_mount != super::kern::mount_of("/").on && Some(file_mount) != super::kern::preboot_cryptex_volume() {
            return Err(Errno::EPERM);
        }
        for mp in mappings {
            if mp.init_prot & prot::ZF != 0 {
                continue;
            }
            if !super::codesign::range_codesigned(f.vnode, mp.file_offset, mp.size) {
                return Err(Errno::EINVAL);
            }
        }
        Ok(())
    }

    /// `shared_region_check_np`: DYLD_VM_END_MWL ends `map_with_linking_np`
    /// for the process; a null address takes the region out of the task;
    /// else the region's first mapping (ENOMEM while it is empty), EINVAL
    /// with no region.
    pub(crate) fn darwin_shared_region_check_np(&mut self, m: &mut GuestMem<'_>, addr: u64) -> Result<u64, Errno> {
        if addr == super::mwl::DYLD_VM_END_MWL {
            self.dtask.disallow_mwl = true;
            return Ok(0);
        }
        let Some(r) = self.darwin_shared_region.as_ref() else { return Err(Errno::EINVAL) };
        let (base, size) = (r.region().base, r.region().size);
        if addr == 0 {
            self.darwin_shared_region_remove(m, base, size);
            self.darwin_shared_region = None;
            return Ok(0);
        }
        let start = r.region().contents().start().ok_or(Errno::ENOMEM)?;
        m.write_u64(addr, start)?;
        Ok(0)
    }

    /// `shared_region_map_and_slide_2_np`: the files and mappings copied
    /// in, the slide picked from the first file's `sf_slide` (dyld's
    /// `maxSlide`) and every mapping moved by it, then
    /// `_shared_region_map_and_slide`. A failure before that is its
    /// `kern_return_t` as the error number.
    pub(crate) fn darwin_shared_region_map_and_slide_2_np(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        let (files_count, files_at, mappings_count, mappings_at) = (a[0] as u32, a[1], a[2] as u32, a[3]);
        let kr_err = |k: u32| super::errno::errno_of(k as i32);
        if files_count == 0 {
            return Ok(0);
        }
        if files_count > MAX_FILES {
            return Err(kr_err(kr::FAILURE));
        }
        if mappings_count == 0 {
            return Ok(0);
        }
        if mappings_count > SFM_MAX {
            return Err(kr_err(kr::FAILURE));
        }
        // shared_region_copyin: copyin's error as the call's.
        let copyin = |k: &Kernel, m: &GuestMem<'_>, at: u64, len: usize| -> Result<Vec<u8>, Errno> {
            if !k.mem.lock().check_access(at, len as u64, crate::mem::prot::READ) {
                return Err(Errno::EFAULT);
            }
            Ok(m.read(at, len)?.to_vec())
        };
        let fb = copyin(self, m, files_at, files_count as usize * FILE_NP_SIZE)?;
        let mb = copyin(self, m, mappings_at, mappings_count as usize * MAPPING_NP_SIZE)?;
        let mut files: Vec<FileNp> = fb.chunks(FILE_NP_SIZE).map(FileNp::parse).collect();
        let mut mappings: Vec<MappingNp> = mb.chunks(MAPPING_NP_SIZE).map(MappingNp::parse).collect();
        let slide = choose_slide(files[0].slide);
        let mut k = 0usize;
        for f in files.iter_mut() {
            f.slide = slide;
            for _ in 0..f.mappings_count {
                if k >= mappings_count as usize {
                    return Err(kr_err(kr::FAILURE));
                }
                mappings[k].address = mappings[k].address.wrapping_add(u64::from(slide));
                if mappings[k].slide_size != 0 {
                    mappings[k].slide_start = mappings[k].slide_start.wrapping_add(u64::from(slide));
                }
                k += 1;
            }
        }
        self.darwin_map_and_slide(m, &files, &mappings)
    }

    /// `_shared_region_map_and_slide`: setup's checks of each file, then
    /// `vm_shared_region_map_file` into the task's region.
    fn darwin_map_and_slide(&mut self, m: &mut GuestMem<'_>, files: &[FileNp], mappings: &[MappingNp]) -> Result<u64, Errno> {
        if files.len() as u32 > MAX_FILES {
            return Err(Errno::E2BIG);
        }
        let mut srfs = Vec::with_capacity(files.len());
        let mut next = 0usize;
        for f in files {
            let n = f.mappings_count as usize;
            if next + n > mappings.len() {
                return Err(Errno::EINVAL);
            }
            srfs.push(SrFile { fd: f.fd, file: None, mappings: mappings[next..next + n].to_vec(), slide: f.slide });
            next += n;
        }
        let Some(region) = self.darwin_shared_region.as_ref().map(|r| Arc::clone(r.region())) else { return Err(Errno::EINVAL) };
        // The region's root directory and the process's: both the root
        // vnode's here (no chroot).
        for srf in srfs.iter_mut() {
            if srf.mappings.is_empty() {
                continue;
            }
            if srf.fd == -1 {
                if srf.mappings.len() > 1 {
                    return Err(Errno::EINVAL);
                }
                let mp = &srf.mappings[0];
                if mp.address & PAGE_MASK != 0 || mp.size & PAGE_MASK != 0 {
                    return Err(Errno::EINVAL);
                }
                continue;
            }
            let file = self.fds.get(srf.fd)?;
            if file.handle.pipe_end().is_some() || Arc::clone(&file.handle).as_kqueue().is_some() {
                return Err(Errno::EINVAL);
            }
            if !file.readable {
                return Err(Errno::EPERM);
            }
            let Some(vnode) = self.darwin_vnode_of(&file) else { return Err(Errno::EINVAL) };
            let path = self.vfs.canonical(&file.path);
            let f = Arc::new(File { handle: Arc::clone(&file.handle), path, vnode });
            let uid = self.creds.uid();
            self.darwin_sr_check_file(&f, &srf.mappings, Some(uid))?;
            srf.file = Some(f);
        }
        let mut space = TaskSpace { k: self, m, unported: Vec::new() };
        let (k, unported) = map_file(&region, &mut srfs, &mut space);
        let mut problems = std::mem::take(&mut space.unported);
        if let Some(u) = unported {
            problems.push(u);
        }
        for p in problems {
            self.darwin_unimplemented(p);
        }
        if k == kr::SUCCESS {
            // (P_NOSHLIB, which this would clear, is set nowhere.)
            self.darwin_shared_region_reach_holders(&region);
            return Ok(0);
        }
        Err(kr_errno(k))
    }

    /// The region just mapped seen by every other task nesting it: its
    /// mappings put in each one's memory.
    fn darwin_shared_region_reach_holders(&mut self, region: &Arc<SharedRegion>) {
        let others: Vec<i32> = region.refs().holders.iter().copied().filter(|&p| p != self.pid).collect();
        for pid in others {
            match self.procs.vm(pid) {
                Ok(peer) => {
                    let c = region.contents();
                    let mut err = None;
                    peer.mem.with_guest(&mut |gm| {
                        for mp in &c.mappings {
                            if let Err(why) = install(&peer.mm, gm, &c, mp) {
                                err = Some(why);
                                break;
                            }
                        }
                    });
                    drop(c);
                    if let Some(why) = err {
                        self.darwin_unimplemented(why);
                    }
                }
                Err(e) => self.darwin_unimplemented(format!("the shared region mapped while pid {pid} nests it, whose memory this host cannot reach ({e:?})")),
            }
        }
    }

    /// The region's entries put in this task's memory (a fork's child has
    /// its parent's copy already).
    pub fn darwin_region_install(&mut self, m: &mut GuestMem<'_>) {
        let Some(r) = self.darwin_shared_region.as_ref().map(|r| Arc::clone(r.region())) else { return };
        let c = r.contents();
        let mut err = None;
        for mp in &c.mappings {
            if let Err(why) = install(&self.mem, m, &c, mp) {
                err = Some(why);
                break;
            }
        }
        drop(c);
        if let Some(why) = err {
            self.darwin_unimplemented(why);
        }
    }

    /// `task_create_internal`: a new task (a fork's child, a spawn's before
    /// its exec) in its parent's region, once it has its pid.
    pub fn darwin_inherit_region(&mut self, parent: Option<&RegionRef>) {
        self.darwin_shared_region = parent.map(|r| r.for_child(self.pid));
    }

    /// The task's region and its range: `(base, size)`, or none.
    pub fn darwin_region_range(&self) -> Option<(u64, u64)> {
        self.darwin_shared_region.as_ref().map(|r| (r.region().base, r.region().size))
    }
}

/// What dyld's preflight of a cache file gives.
struct Preflight {
    file: Arc<File>,
    mappings: Vec<MappingNp>,
    subcaches: Vec<String>,
    max_slide: u64,
    /// The dynamic data's address (unslid) and its size.
    dynamic: (u64, u64),
}

/// `DYLD_CACHE_MAPPING_AUTH_DATA` and `DYLD_CACHE_MAPPING_CONST_DATA`.
const AUTH_DATA: u64 = 1;
const CONST_DATA: u64 = 4;

/// `dyld_cache_mapping_and_slide_info.flags` of mapping `i`.
fn mapping_flags(head: &[u8], i: usize) -> u64 {
    let u32_at = |o: usize| head.get(o..o + 4).map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()));
    let (wso, wsc) = (u32_at(0x138) as usize, u32_at(0x13c) as usize);
    if wso == 0 || i >= wsc {
        return 0;
    }
    let o = wso + i * 56 + 40;
    head.get(o..o + 8).map_or(0, |b| u64::from_le_bytes(b.try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_slide_is_on_a_16k_boundary_below_the_maximum() {
        for _ in 0..1000 {
            let s = choose_slide(0x2000_0000);
            assert!(s < 0x2000_0000 && s % 0x4000 == 0, "{s:#x}");
        }
        assert_eq!(choose_slide(0), 0);
    }

    fn entry(address: u64, max_prot: u32, source: Source) -> Mapping {
        Mapping { address, size: 0x4000, source, init_prot: max_prot, max_prot, slide: None }
    }

    #[test]
    fn read_only_mappings_are_permanent() {
        let c = Contents { mappings: vec![entry(BASE, 5, Source::Zero), entry(BASE + 0x4000, 3, Source::Zero), entry(BASE + 0x8000, 1, Source::Zero)], first_mapping: Some(0), ..Default::default() };
        assert_eq!(c.permanent(), vec![(BASE + 0x8000, BASE + 0xc000)]);
        assert_eq!(c.start(), Some(BASE));
    }

    #[test]
    fn an_entry_already_there_is_present_and_one_in_the_way_has_no_space() {
        let c = Contents { mappings: vec![entry(BASE + 0x4000, 1, Source::Zero)], ..Default::default() };
        let same = entry(BASE + 0x4000, 1, Source::Zero);
        assert_eq!(map_enter(&c, SIZE, 0x4000, 0x4000, 0, &same), kr::MEMORY_PRESENT);
        let other = entry(BASE + 0x4000, 3, Source::Zero);
        assert_eq!(map_enter(&c, SIZE, 0x4000, 0x4000, 0, &other), kr::NO_SPACE);
        // Overlapping its start from below: no entry holds the start.
        assert_eq!(map_enter(&c, SIZE, 0, 0x8000, 0, &entry(BASE, 1, Source::Zero)), kr::NO_SPACE);
        assert_eq!(map_enter(&c, SIZE, 0x8000, 0x4000, 0, &entry(BASE + 0x8000, 1, Source::Zero)), kr::SUCCESS);
        // Outside the region, and an unaligned file offset.
        assert_eq!(map_enter(&c, SIZE, SIZE, 0x4000, 0, &same), kr::INVALID_ADDRESS);
        assert_eq!(map_enter(&c, SIZE, 0x8000, 0x4000, 0x1000, &same), kr::INVALID_ARGUMENT);
        assert_eq!(map_enter(&c, SIZE, 0x8000, 0, 0, &same), kr::INVALID_ARGUMENT);
    }

    #[test]
    fn slide_info_is_checked_as_the_kernel_checks_it() {
        let mut v2 = vec![0u8; 40 + 4];
        v2[0..4].copy_from_slice(&2u32.to_le_bytes());
        v2[4..8].copy_from_slice(&4096u32.to_le_bytes());
        v2[12..16].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(slide_sanity_check(&v2), kr::SUCCESS);
        v2[12..16].copy_from_slice(&3u32.to_le_bytes());
        assert_eq!(slide_sanity_check(&v2), kr::FAILURE);
        v2[12..16].copy_from_slice(&2u32.to_le_bytes());
        v2[4..8].copy_from_slice(&16384u32.to_le_bytes());
        assert_eq!(slide_sanity_check(&v2), kr::FAILURE);
        let mut v5 = vec![0u8; 24 + 2];
        v5[0..4].copy_from_slice(&5u32.to_le_bytes());
        v5[4..8].copy_from_slice(&16384u32.to_le_bytes());
        v5[8..12].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(slide_sanity_check(&v5), kr::SUCCESS);
        let mut v7 = v5.clone();
        v7[0..4].copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(slide_sanity_check(&v7), kr::FAILURE);
    }

    #[test]
    fn a_region_is_kept_while_referenced_and_found_again_by_its_environment() {
        let env = Env { cputype: CPU_TYPE_ARM64, cpu_subtype: 0, is_64bit: true, driverkit: true };
        let a = lookup(env, Some(9001)).expect("a region");
        let b = lookup(env, Some(9002)).expect("the same region");
        assert!(Arc::ptr_eq(a.region(), b.region()));
        assert_eq!(a.region().refs().count, 2);
        let other = lookup(Env { driverkit: false, ..env }, Some(9003)).expect("another environment's");
        assert!(!Arc::ptr_eq(a.region(), other.region()));
        let id = a.region().id;
        drop(a);
        drop(b);
        // Unused: a timer holds it, and a new task finds it again.
        let c = lookup(env, Some(9004)).expect("kept by its timer");
        assert_eq!(c.region().id, id);
        assert_eq!(c.region().refs().count, 1);
        assert!(lookup(Env { cputype: 7, ..env }, None).is_none());
    }
}
