//! The shared region the boot's arm64 tasks nest (`osfmk/vm/vm_shared_region.c`)
//! and the dyld shared cache mapped in it (`bsd/vm/vm_unix.c`'s
//! `shared_region_map_and_slide_2_np`).
//!
//! The region is the system's, not a task's: the first dyld to find it empty
//! (launchd's, at boot) maps the cache into it, and every task after enters it
//! as it is. dyld passes the cache's `maxSlide` as the first file's
//! `sf_slide`, and the kernel picks the slide from it, once: every mapping
//! moves by it and the slid mappings' pages are relocated by their slide info.
//! Here the host maps the region's mappings into each task's memory
//! ([`Region`] says what they are), and the boot's region is made as
//! launchd's dyld would have made it before the first program of the run.

use std::sync::{Arc, Mutex};

/// `VM_PROT_*` bits of a mapping's protections.
pub mod prot {
    pub const READ: u32 = 1;
    pub const WRITE: u32 = 2;
    pub const EXECUTE: u32 = 4;
}

/// One of the region's mappings (`shared_file_mapping_slide_np`), with the
/// slide applied: at `address` in every task.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub address: u64,
    pub size: u64,
    /// The file it maps, an index into [`Region::files`]; `None` for the
    /// page dyld supplied from its own memory (its file descriptor -1), which
    /// is [`Region::data`].
    pub file: Option<usize>,
    pub file_offset: u64,
    /// Where the mapping's slide info is in its file, `(offset, size)`: a
    /// mapping the slide relocates (`VM_PROT_SLIDE`).
    pub slide_info: Option<(u64, u64)>,
    pub max_prot: u32,
    pub init_prot: u32,
}

/// The region's contents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Region {
    /// `sr_slide`: what every mapping moved by.
    pub slide: u64,
    /// The cache's files, as the host opens them, and the UUID of each
    /// (what a kept slid copy is named by).
    pub files: Vec<(std::path::PathBuf, [u8; 16])>,
    /// In the order they were mapped: the first is `sr_first_mapping`.
    pub mappings: Vec<Mapping>,
    /// The contents of the mapping with no file.
    pub data: Vec<u8>,
}

impl Region {
    /// `vm_shared_region_start_address`: the region's first mapping, which
    /// `shared_region_check_np` answers with.
    pub fn start(&self) -> Option<u64> {
        self.mappings.first().map(|m| m.address)
    }

    /// The mappings `shared_region_make_permanent` made "permanent" in the
    /// region's map, `[start, end)`: on arm64, every one that is neither
    /// writable nor executable at its most, which nothing may remove or
    /// replace from a task's map.
    pub fn permanent(&self) -> Vec<(u64, u64)> {
        self.mappings.iter().filter(|m| m.max_prot & (prot::WRITE | prot::EXECUTE) == 0).map(|m| (m.address, m.address + m.size)).collect()
    }
}

/// `SIXTEENK_PAGE_MASK`, which `shared_region_map_and_slide_2_np` clears
/// from the slide (`SLIDE_AMOUNT_MASK` on a 16 KiB-page kernel).
const SLIDE_AMOUNT_MASK: u32 = !0x3fff;

/// `shared_region_map_and_slide_2_np`'s choice of slide from the first
/// file's `sf_slide`, dyld's `maxSlide`: `read_random`'s 32 bits modulo it,
/// on a 16 KiB boundary; none for a cache that cannot slide.
pub fn choose_slide(max_slide: u32) -> u64 {
    if max_slide == 0 {
        return 0;
    }
    let mut b = [0u8; 4];
    crate::vfs::devfs::fill_random(&mut b);
    u64::from((u32::from_le_bytes(b) % max_slide) & SLIDE_AMOUNT_MASK)
}

/// The boot's region, once it has been mapped.
static REGION: Mutex<Option<Arc<Region>>> = Mutex::new(None);

/// The boot's region, if anything has mapped it.
pub fn region() -> Option<Arc<Region>> {
    REGION.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// The boot's region: the one already mapped, or `make`'s, which becomes
/// it (the first dyld to map the region wins; a later one reuses it).
pub fn region_or(make: impl FnOnce() -> Result<Region, String>) -> Result<Arc<Region>, String> {
    let mut r = REGION.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(r) = r.as_ref() {
        return Ok(Arc::clone(r));
    }
    let made = Arc::new(make()?);
    *r = Some(Arc::clone(&made));
    Ok(made)
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

    #[test]
    fn read_only_mappings_are_permanent() {
        let m = |address, max_prot| Mapping { address, size: 0x4000, file: Some(0), file_offset: 0, slide_info: None, max_prot, init_prot: max_prot };
        let r = Region { slide: 0, files: Vec::new(), mappings: vec![m(0x1_8000_0000, 5), m(0x1_8000_4000, 3), m(0x1_8000_8000, 1)], data: Vec::new() };
        assert_eq!(r.permanent(), vec![(0x1_8000_8000, 0x1_8000_c000)]);
        assert_eq!(r.start(), Some(0x1_8000_0000));
    }
}
