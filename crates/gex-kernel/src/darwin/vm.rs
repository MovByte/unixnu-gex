//! A Darwin task's VM map entries, what the host's mappings do not carry:
//! where each `vm_map_entry` starts and ends, as `vm_map_enter` makes them
//! and clipping splits them, its object offset, maximum protection, user
//! tag (`VME_ALIAS`), inheritance, paging behavior, `zero_wired_pages` and
//! `no_cache`, and whether a fork left it copy-on-write (`needs_copy`) or
//! shared.
//!
//! (A shared mapping of a file opened read-only, whose maximum lacks write,
//! is refused write by the host's `mprotect` as XNU refuses it.)

use std::collections::BTreeMap;

/// `VM_PROT_ALL`.
pub const PROT_ALL: u8 = 7;

/// A task map's highest address (`vm_map_max`): `vm_compute_max_offset`'s
/// `ARM_PMAP_MAX_OFFSET_DEVICE`, which for a device with more than 3 GB of
/// memory (j120's 4 GB) is `ARM64_MAX_OFFSET_DEVICE_LARGE`, 0x138000000
/// past `ARM64_MIN_MAX_ADDRESS` (the shared region's end, 0x300000000,
/// and 512 MB). A jumbo map (`vm_map_set_jumbo`) reaches further.
pub const MAP_MAX: u64 = 0x1_8000_0000 + 0x1_8000_0000 + 0x2000_0000 + 0x1_3800_0000;

/// A jumbo map's highest address: `ARM_PMAP_MAX_OFFSET_JUMBO`, iOS's
/// `MACH_VM_MAX_ADDRESS`.
pub const JUMBO_MAX: u64 = 0xf_c000_0000;

/// `vm_inherit_t`.
pub mod inherit {
    pub const SHARE: u8 = 0;
    pub const COPY: u8 = 1;
    pub const NONE: u8 = 2;
    pub const DEFAULT: u8 = COPY;
}

/// `vm_behavior_t`: the ones an entry keeps.
pub mod behavior {
    pub const DEFAULT: u8 = 0;
    pub const RANDOM: u8 = 1;
    pub const SEQUENTIAL: u8 = 2;
    pub const RSEQNTL: u8 = 3;
}

/// What an entry maps: the object behind it, as far as its advice cares.
pub mod kind {
    /// Anonymous memory: an internal object (or none, until touched).
    pub const ANON: u8 = 0;
    /// A file, copy-on-write: the vnode object until a write, then a
    /// shadow of it.
    pub const FILE_PRIVATE: u8 = 1;
    /// A file, shared: the vnode object itself.
    pub const FILE_SHARED: u8 = 2;
    /// A POSIX shared memory object: internal, and named.
    pub const SHM: u8 = 3;
    /// The shared region: a submap.
    pub const SUBMAP: u8 = 4;
}

/// `MACH_VM_MAX_ADDRESS` on iOS, `VM_MAX_ADDRESS` here.
pub const MACH_VM_MAX_ADDRESS: u64 = 0xf_c000_0000;

/// `vm_region_flavor_t`.
pub mod region {
    pub const BASIC_INFO_64: i32 = 9;
    pub const BASIC_INFO: i32 = 10;
    pub const EXTENDED_INFO_LEGACY: i32 = 7;
    pub const TOP_INFO: i32 = 12;
    pub const EXTENDED_INFO: i32 = 13;
    pub const BASIC_INFO_COUNT_64: u32 = 9;
    pub const BASIC_INFO_COUNT: u32 = 8;
}

/// `ANON_CHUNK_SIZE`: anonymous memory is entered in entries of at most this.
pub const ANON_CHUNK_SIZE: u64 = 128 << 20;

/// The `VM_MEMORY_*` tags a malloc region carries.
pub mod tag {
    pub const MALLOC: u8 = 1;
    pub const MALLOC_SMALL: u8 = 2;
    pub const MALLOC_LARGE: u8 = 3;
    pub const REALLOC: u8 = 6;
    pub const MALLOC_TINY: u8 = 7;
    pub const MALLOC_LARGE_REUSABLE: u8 = 8;
    pub const MALLOC_LARGE_REUSED: u8 = 9;
}

/// One entry's attributes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attrs {
    pub kind: u8,
    pub max: u8,
    pub alias: u8,
    pub inherit: u8,
    pub behavior: u8,
    pub zero_wired: bool,
    pub no_cache: bool,
    /// Copy-on-write since a fork: its object is shared with the other
    /// task's entry until one of them writes (and gets a shadow object).
    pub cow: bool,
    /// `used_for_jit`: the map's JIT region, writable and executable at
    /// once.
    pub jit: bool,
    /// `is_shared`: another map has the entry too.
    pub shared: bool,
}

impl Default for Attrs {
    fn default() -> Attrs {
        Attrs { kind: kind::ANON, max: PROT_ALL, alias: 0, inherit: inherit::DEFAULT, behavior: behavior::DEFAULT, zero_wired: false, no_cache: false, cow: false, jit: false, shared: false }
    }
}

/// One entry past its start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    end: u64,
    attrs: Attrs,
    /// `VME_OFFSET`.
    offset: u64,
}

/// What `mach_vm_region` reports of an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryInfo {
    pub start: u64,
    pub end: u64,
    pub attrs: Attrs,
    pub offset: u64,
}

/// A task's map entries, by start.
#[derive(Debug, Default)]
pub struct Entries {
    ranges: BTreeMap<u64, Entry>,
    /// `jit_entry_exists`: the map has had its JIT region (it stays set
    /// once the region is unmapped).
    pub jit_entry_exists: bool,
}

impl Entries {
    /// `vm_map_clip_start`: no entry crosses `at`; the upper half's offset
    /// moves with it.
    pub fn clip(&mut self, at: u64) {
        let Some((&s, &entry)) = self.ranges.range(..at).next_back() else { return };
        if entry.end > at {
            self.ranges.insert(s, Entry { end: at, ..entry });
            self.ranges.insert(at, Entry { offset: entry.offset + (at - s), ..entry });
        }
    }

    /// Clip at both ends of `[start, end)`.
    pub fn clip_range(&mut self, start: u64, end: u64) {
        self.clip(start);
        self.clip(end);
    }

    /// `[start, end)` no longer mapped.
    pub fn clear(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }
        self.clip_range(start, end);
        let inside: Vec<u64> = self.ranges.range(start..end).map(|(&s, _)| s).collect();
        for s in inside {
            self.ranges.remove(&s);
        }
    }

    /// `[start, end)` becomes one new entry, as a new mapping over it does.
    pub fn enter(&mut self, start: u64, end: u64, attrs: Attrs, offset: u64) {
        self.clear(start, end);
        if start < end {
            self.ranges.insert(start, Entry { end, attrs, offset });
        }
    }

    /// `vm_map_enter` of anonymous memory, `prev_same_prot` saying whether
    /// the entry below has the new one's current protection: entries of at
    /// most [`ANON_CHUNK_SIZE`] (unless the maximum protection is none), the
    /// first extending the entry below when it can.
    pub fn enter_anon(&mut self, start: u64, end: u64, attrs: Attrs, prev_same_prot: bool) {
        self.clear(start, end);
        if start >= end {
            return;
        }
        let size = end - start;
        let chunked = size > ANON_CHUNK_SIZE && attrs.max != 0;
        let first_end = if chunked { start + ANON_CHUNK_SIZE } else { end };
        if !self.coalesce(start, first_end, attrs, prev_same_prot) {
            self.ranges.insert(start, Entry { end: first_end, attrs, offset: 0 });
        }
        let mut at = first_end;
        while at < end {
            let e = if end - at > ANON_CHUNK_SIZE { at + ANON_CHUNK_SIZE } else { end };
            self.ranges.insert(at, Entry { end: e, attrs, offset: 0 });
            at = e;
        }
    }

    /// `vm_map_enter`'s extension of the entry below over `[start, end)`.
    /// `NO_COALESCE_LIMIT` is zero on this platform, so only a
    /// `VM_MEMORY_REALLOC` request can extend one (up to
    /// [`ANON_CHUNK_SIZE`]). The object must be its entry's alone
    /// (`vm_object_coalesce`): none since a fork left it shared.
    fn coalesce(&mut self, start: u64, end: u64, attrs: Attrs, prev_same_prot: bool) -> bool {
        if attrs.alias != tag::REALLOC || attrs.jit || !prev_same_prot {
            return false;
        }
        let Some((&s, prev)) = self.ranges.range_mut(..start).next_back() else { return false };
        let p = prev.attrs;
        let joins = prev.end == start
            && !p.shared
            && p.kind == kind::ANON
            && !p.cow
            && p.behavior == behavior::DEFAULT
            && p.max == attrs.max
            && p.inherit == attrs.inherit
            && p.no_cache == attrs.no_cache
            && !p.zero_wired
            && !p.jit
            && (prev.end - s) + (end - start) <= ANON_CHUNK_SIZE;
        if joins {
            prev.end = end;
        }
        joins
    }

    /// Change each entry of `[start, end)` by `f`, clipped to it.
    pub fn update(&mut self, start: u64, end: u64, f: impl Fn(&mut Attrs)) {
        self.clip_range(start, end);
        for (_, e) in self.ranges.range_mut(start..end) {
            f(&mut e.attrs);
        }
    }

    /// Change every entry overlapping `[start, end)` whole, unclipped, as
    /// the reusable-pages calls retag an entry.
    pub fn update_whole(&mut self, start: u64, end: u64, f: impl Fn(&mut Attrs)) {
        let first = self.ranges.range(..=start).next_back().filter(|(_, e)| e.end > start).map_or(start, |(&s, _)| s);
        for (_, e) in self.ranges.range_mut(first..end) {
            f(&mut e.attrs);
        }
    }

    /// The pieces of `[start, end)` and the attributes of each: the default
    /// ones for what no entry covers.
    pub fn pieces(&self, start: u64, end: u64) -> Vec<(u64, u64, Attrs)> {
        let mut out = Vec::new();
        if start >= end {
            return out;
        }
        let mut at = start;
        let first = self.ranges.range(..=start).next_back().filter(|(_, e)| e.end > start).map_or(start, |(&s, _)| s);
        for (&s, e) in self.ranges.range(first..end) {
            let (s, stop) = (s.max(start), e.end.min(end));
            if s > at {
                out.push((at, s, Attrs::default()));
            }
            out.push((s, stop, e.attrs));
            at = stop;
        }
        if at < end {
            out.push((at, end, Attrs::default()));
        }
        out
    }

    /// `vm_map_lookup_entry` then `vme_next`: the entry at `addr`, or the
    /// first past it.
    pub fn at_or_after(&self, addr: u64) -> Option<EntryInfo> {
        let hit = self.ranges.range(..=addr).next_back().filter(|(_, e)| e.end > addr);
        let (&start, e) = hit.or_else(|| self.ranges.range(addr..).next())?;
        Some(EntryInfo { start, end: e.end, attrs: e.attrs, offset: e.offset })
    }

    /// `vm_map_fork`'s mark on the forking task's map, over its mapped
    /// ranges `mapped`: an entry inherited by copy is copy-on-write
    /// afterwards, in both maps, and one inherited by share is shared.
    pub fn fork(&mut self, mapped: &[(u64, u64)]) {
        for &(s, e) in mapped {
            self.update(s, e, |a| match a.inherit {
                inherit::COPY => a.cow = true,
                inherit::SHARE => a.shared = true,
                _ => {}
            });
        }
    }

    /// The JIT region's ranges a fork's child inherits (`vm_inherit` made
    /// it so): its copy is to lose execute access.
    pub fn inherited_jit(&self) -> Vec<(u64, u64)> {
        self.ranges.iter().filter(|(_, e)| e.attrs.jit && e.attrs.inherit != inherit::NONE).map(|(&s, e)| (s, e.end)).collect()
    }

    /// The child's entries from a map [`Entries::fork`] has marked: those
    /// inherited by copy or share; one not inherited is absent.
    pub fn inherited(&self) -> Entries {
        let mut child = Entries::default();
        for (&s, &entry) in &self.ranges {
            let mut a = entry.attrs;
            if a.inherit != inherit::NONE {
                // vm_map_entry_copy_code_signing: an iOS map allows no copy
                // of a JIT region (VM_MAP_POLICY_ALLOW_JIT_COPY): the copy
                // loses execute access and is no JIT region.
                if a.jit {
                    a.jit = false;
                    a.max &= !4;
                }
                child.ranges.insert(s, Entry { attrs: a, ..entry });
            }
        }
        child
    }
}

/// `vm_map_entry_is_reusable` for an entry that is not wired and whose
/// protection is `prot`. `None` when the answer depends on whether either
/// task wrote to it since a fork (a shadow object).
pub fn reusable(a: &Attrs, prot: u8) -> Option<bool> {
    use tag::*;
    const VM_PROT_DEFAULT: u8 = 3;
    if a.kind == kind::SUBMAP {
        return Some(false);
    }
    if !matches!(a.alias, MALLOC | MALLOC_SMALL | MALLOC_LARGE | REALLOC | MALLOC_TINY | MALLOC_LARGE_REUSABLE | MALLOC_LARGE_REUSED) {
        return Some(true);
    }
    if prot != VM_PROT_DEFAULT || a.max != PROT_ALL || a.inherit != inherit::DEFAULT || a.no_cache || a.zero_wired {
        return Some(false);
    }
    // The object: none yet, or internal with no copy, no shadow and not
    // purgeable (a file's is external, or a shadow of it).
    match a.kind {
        kind::ANON if a.cow => None,
        kind::ANON | kind::SHM => Some(true),
        _ => Some(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: u64 = 0x4000;

    fn max(m: u8) -> Attrs {
        Attrs { max: m, ..Attrs::default() }
    }

    fn entry_starts(e: &Entries, end: u64) -> Vec<u64> {
        let mut out = Vec::new();
        let mut at = 0;
        while let Some(i) = e.at_or_after(at).filter(|i| i.start < end) {
            out.push(i.start);
            at = i.end;
        }
        out
    }

    #[test]
    fn a_clip_splits_and_nothing_rejoins() {
        let mut e = Entries::default();
        e.enter(0, 4 * K, Attrs::default(), 0);
        e.update(K, 2 * K, |a| a.max = 1);
        assert_eq!(entry_starts(&e, 4 * K), vec![0, K, 2 * K]);
        e.update(K, 2 * K, |a| a.max = 7);
        assert_eq!(entry_starts(&e, 4 * K), vec![0, K, 2 * K], "a clip is not undone");
    }

    #[test]
    fn the_offset_moves_with_the_upper_half() {
        let mut e = Entries::default();
        e.enter(4 * K, 8 * K, Attrs { kind: kind::FILE_PRIVATE, ..Attrs::default() }, 0x1000);
        e.clip(5 * K);
        assert_eq!(e.at_or_after(5 * K).unwrap().offset, 0x1000 + K);
        assert_eq!(e.at_or_after(4 * K).unwrap().offset, 0x1000);
    }

    #[test]
    fn only_realloc_memory_extends_the_entry_below() {
        let mut e = Entries::default();
        e.enter_anon(0, K, Attrs::default(), false);
        e.enter_anon(K, 2 * K, Attrs::default(), true);
        assert_eq!(entry_starts(&e, 2 * K), vec![0, K], "NO_COALESCE_LIMIT is zero");
        let r = Attrs { alias: tag::REALLOC, ..Attrs::default() };
        let mut e = Entries::default();
        e.enter_anon(0, K, r, false);
        e.enter_anon(K, 2 * K, r, true);
        assert_eq!(entry_starts(&e, 2 * K), vec![0]);
        e.enter_anon(2 * K, 3 * K, r, false);
        assert_eq!(entry_starts(&e, 3 * K), vec![0, 2 * K], "another protection");
    }

    #[test]
    fn large_anonymous_memory_is_entered_in_chunks() {
        let mut e = Entries::default();
        let size = 3 * ANON_CHUNK_SIZE - K;
        e.enter_anon(0, size, Attrs::default(), false);
        assert_eq!(entry_starts(&e, size), vec![0, ANON_CHUNK_SIZE, 2 * ANON_CHUNK_SIZE]);
        let mut e = Entries::default();
        e.enter_anon(0, size, max(0), false);
        assert_eq!(entry_starts(&e, size), vec![0], "no chunks for what can never be touched");
    }

    #[test]
    fn a_fork_copies_by_inheritance() {
        let mut e = Entries::default();
        e.enter(0, K, Attrs::default(), 0);
        e.enter(K, 2 * K, Attrs { inherit: inherit::SHARE, ..Attrs::default() }, 0);
        e.enter(2 * K, 3 * K, Attrs { inherit: inherit::NONE, ..Attrs::default() }, 0);
        e.fork(&[(0, 3 * K)]);
        let c = e.inherited();
        assert_eq!(entry_starts(&c, 3 * K), vec![0, K]);
        assert!(c.at_or_after(0).unwrap().attrs.cow);
        assert!(c.at_or_after(K).unwrap().attrs.shared);
        assert!(e.at_or_after(K).unwrap().attrs.shared, "the parent's is shared too");
    }

    #[test]
    fn only_a_malloc_region_in_its_first_state_is_reusable() {
        let rw = 3;
        assert_eq!(reusable(&Attrs::default(), 1), Some(true));
        let malloc = Attrs { alias: tag::MALLOC_TINY, ..Attrs::default() };
        assert_eq!(reusable(&malloc, rw), Some(true));
        assert_eq!(reusable(&malloc, 1), Some(false));
        assert_eq!(reusable(&Attrs { max: 3, ..malloc }, rw), Some(false));
        assert_eq!(reusable(&Attrs { zero_wired: true, ..malloc }, rw), Some(false));
        assert_eq!(reusable(&Attrs { cow: true, ..malloc }, rw), None);
        assert_eq!(reusable(&Attrs { kind: kind::FILE_PRIVATE, ..malloc }, rw), Some(false));
        assert_eq!(reusable(&Attrs { kind: kind::SUBMAP, ..Attrs::default() }, rw), Some(false));
    }
}
