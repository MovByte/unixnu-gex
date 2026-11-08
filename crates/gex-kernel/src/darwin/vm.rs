//! The parts of a Darwin task's VM map entries the host's mappings do not
//! carry: each entry's maximum protection (`max_protection`), user tag
//! (`VME_ALIAS`), inheritance, paging behavior, `zero_wired_pages` and
//! `no_cache`, and whether a fork left it copy-on-write (`needs_copy`).
//!
//! A range holds the attributes of the mapping made over it last; one
//! nothing was said about (or that was unmapped) has the defaults a plain
//! `vm_map_enter` gives. (A shared mapping of a file opened read-only,
//! whose maximum lacks write, is refused write by the host's `mprotect`
//! as XNU refuses it.)

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
}

impl Default for Attrs {
    fn default() -> Attrs {
        Attrs { kind: kind::ANON, max: PROT_ALL, alias: 0, inherit: inherit::DEFAULT, behavior: behavior::DEFAULT, zero_wired: false, no_cache: false, cow: false, jit: false }
    }
}

/// Ranges `[start, end)` whose attributes are not the defaults.
#[derive(Debug, Default)]
pub struct Entries {
    ranges: BTreeMap<u64, (u64, Attrs)>,
    /// `jit_entry_exists`: the map has had its JIT region (it stays set
    /// once the region is unmapped).
    pub jit_entry_exists: bool,
}

impl Entries {
    /// Split a range at `at`, so that no range crosses it.
    fn split(&mut self, at: u64) {
        let Some((&s, &(e, a))) = self.ranges.range(..at).next_back() else { return };
        if e > at {
            self.ranges.insert(s, (at, a));
            self.ranges.insert(at, (e, a));
        }
    }

    /// `[start, end)` back to the defaults.
    pub fn clear(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }
        self.split(start);
        self.split(end);
        let inside: Vec<u64> = self.ranges.range(start..end).map(|(&s, _)| s).collect();
        for s in inside {
            self.ranges.remove(&s);
        }
    }

    /// `[start, end)` takes `attrs`, as a new mapping over it does.
    pub fn set(&mut self, start: u64, end: u64, attrs: Attrs) {
        self.clear(start, end);
        if start < end && attrs != Attrs::default() {
            self.ranges.insert(start, (end, attrs));
        }
    }

    /// Change each piece of `[start, end)` by `f`, as a clip of the
    /// entries there and an update of each would.
    pub fn update(&mut self, start: u64, end: u64, f: impl Fn(&mut Attrs)) {
        for (s, e, mut a) in self.pieces(start, end) {
            f(&mut a);
            self.set(s, e, a);
        }
        self.merge(start, end);
    }

    /// Join equal neighbours in and around `[start, end)` into one range.
    fn merge(&mut self, start: u64, end: u64) {
        let mut at = self.ranges.range(..start).next_back().map_or(start, |(&s, _)| s);
        while let Some((&s, &(e, a))) = self.ranges.range(at..).next() {
            if s > end {
                break;
            }
            match self.ranges.get(&e) {
                Some(&(e1, a1)) if a1 == a => {
                    self.ranges.remove(&e);
                    self.ranges.insert(s, (e1, a));
                }
                _ => at = s + 1,
            }
        }
    }

    /// The pieces of `[start, end)` and the attributes of each.
    pub fn pieces(&self, start: u64, end: u64) -> Vec<(u64, u64, Attrs)> {
        let mut out = Vec::new();
        if start >= end {
            return out;
        }
        let mut at = start;
        let first = self.ranges.range(..=start).next_back().filter(|(_, &(e, _))| e > start).map(|(&s, _)| s).unwrap_or(start);
        for (&s, &(e, a)) in self.ranges.range(first..end) {
            let (s, e) = (s.max(start), e.min(end));
            if s > at {
                out.push((at, s, Attrs::default()));
            }
            out.push((s, e, a));
            at = e;
        }
        if at < end {
            out.push((at, end, Attrs::default()));
        }
        out
    }

    /// `vm_map_fork`'s mark on the forking task's map, over its mapped
    /// ranges `mapped`: an entry inherited by copy is copy-on-write
    /// afterwards, in both maps.
    pub fn fork(&mut self, mapped: &[(u64, u64)]) {
        for &(s, e) in mapped {
            self.update(s, e, |a| {
                if a.inherit == inherit::COPY {
                    a.cow = true;
                }
            });
        }
    }

    /// The JIT region's ranges a fork's child inherits (`vm_inherit` made
    /// it so): its copy is to lose execute access.
    pub fn inherited_jit(&self) -> Vec<(u64, u64)> {
        self.ranges.iter().filter(|(_, (_, a))| a.jit && a.inherit != inherit::NONE).map(|(&s, &(e, _))| (s, e)).collect()
    }

    /// The child's entries from a map [`Entries::fork`] has marked: those
    /// inherited by copy or share; one not inherited is absent.
    pub fn inherited(&self) -> Entries {
        let mut child = Entries::default();
        for (&s, &(e, mut a)) in &self.ranges {
            if a.inherit != inherit::NONE {
                // vm_map_entry_copy_code_signing: an iOS map allows no copy
                // of a JIT region (VM_MAP_POLICY_ALLOW_JIT_COPY): the copy
                // loses execute access and is no JIT region.
                if a.jit {
                    a.jit = false;
                    a.max &= !4;
                }
                child.ranges.insert(s, (e, a));
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

    fn max(m: u8) -> Attrs {
        Attrs { max: m, ..Attrs::default() }
    }

    #[test]
    fn a_lowered_maximum_splits_and_clears_by_range() {
        let mut m = Entries::default();
        m.set(0x1000, 0x5000, max(1));
        let maxes = |m: &Entries, s, e| m.pieces(s, e).into_iter().map(|(s, e, a)| (s, e, a.max)).collect::<Vec<_>>();
        assert_eq!(maxes(&m, 0, 0x6000), vec![(0, 0x1000, 7), (0x1000, 0x5000, 1), (0x5000, 0x6000, 7)]);
        m.clear(0x2000, 0x3000);
        assert_eq!(maxes(&m, 0x1000, 0x5000), vec![(0x1000, 0x2000, 1), (0x2000, 0x3000, 7), (0x3000, 0x5000, 1)]);
        m.set(0x4000, 0x6000, max(0));
        assert_eq!(maxes(&m, 0x3000, 0x6000), vec![(0x3000, 0x4000, 1), (0x4000, 0x6000, 0)]);
    }

    #[test]
    fn an_update_changes_one_field_and_rejoins_what_matches() {
        let mut m = Entries::default();
        m.set(0x4000, 0x8000, Attrs { alias: tag::MALLOC_LARGE, ..Attrs::default() });
        m.update(0x0, 0x8000, |a| a.behavior = behavior::RANDOM);
        let p = m.pieces(0, 0x8000);
        assert_eq!(p.len(), 2);
        assert_eq!((p[0].2.alias, p[0].2.behavior), (0, behavior::RANDOM));
        assert_eq!((p[1].2.alias, p[1].2.behavior), (tag::MALLOC_LARGE, behavior::RANDOM));
        m.update(0x0, 0x4000, |a| a.alias = tag::MALLOC_LARGE);
        assert_eq!(m.pieces(0, 0x8000), vec![(0, 0x8000, Attrs { alias: tag::MALLOC_LARGE, behavior: behavior::RANDOM, ..Attrs::default() })]);
        assert_eq!(m.ranges.len(), 1);
    }

    #[test]
    fn a_fork_copies_by_inheritance() {
        let mut m = Entries::default();
        m.set(0x4000, 0x8000, Attrs { inherit: inherit::SHARE, ..Attrs::default() });
        m.set(0x8000, 0xc000, Attrs { inherit: inherit::NONE, ..Attrs::default() });
        m.fork(&[(0, 0xc000)]);
        let c = m.inherited();
        assert!(m.pieces(0, 0x4000)[0].2.cow);
        assert!(!m.pieces(0x4000, 0x8000)[0].2.cow);
        assert_eq!(c.pieces(0, 0x4000)[0].2, Attrs { cow: true, ..Attrs::default() });
        assert_eq!(c.pieces(0x4000, 0x8000)[0].2.inherit, inherit::SHARE);
        // Not inherited: the child has nothing there (the defaults).
        assert_eq!(c.pieces(0x8000, 0xc000)[0].2, Attrs::default());
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
