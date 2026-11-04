//! The dyld shared cache: every system library of a Darwin release,
//! prelinked into one region that the kernel maps into each process.
//!
//! The cache is a main file and its subcaches (`.01`, `.02`, ...), each
//! with the same header layout and its own mappings. The kernel maps them
//! at the shared region and applies their slide info, which is not optional
//! even at a zero slide: pointers in the cache's data are stored as chains
//! (each holds the distance to the next in its high bits), and only the
//! rebase turns a chain entry into the address it names. dyld finds the
//! region already mapped (`shared_region_check_np`) and reads it from there.

use crate::elf::LoadError;

/// Fixed-size fields of `dyld_cache_header`. A field past the header's own
/// size (its `mappingOffset`) is absent in an older cache and reads as zero.
pub mod hdr {
    pub const MAGIC: usize = 0x00;
    pub const MAPPING_OFFSET: usize = 0x10;
    pub const MAPPING_COUNT: usize = 0x14;
    pub const IMAGES_OFFSET_OLD: usize = 0x18;
    pub const IMAGES_COUNT_OLD: usize = 0x1c;
    pub const DYLD_BASE: usize = 0x20;
    pub const LOCAL_SYMBOLS_OFFSET: usize = 0x48;
    pub const UUID: usize = 0x58;
    pub const DYLD_IN_CACHE_MH: usize = 0x78;
    pub const DYLD_IN_CACHE_ENTRY: usize = 0x80;
    pub const PLATFORM: usize = 0xd8;
    pub const SHARED_REGION_START: usize = 0xe0;
    pub const SHARED_REGION_SIZE: usize = 0xe8;
    pub const MAX_SLIDE: usize = 0xf0;
    pub const MAPPING_WITH_SLIDE_OFFSET: usize = 0x138;
    pub const MAPPING_WITH_SLIDE_COUNT: usize = 0x13c;
    pub const OS_VERSION: usize = 0x16c;
    pub const SUBCACHE_ARRAY_OFFSET: usize = 0x188;
    pub const SUBCACHE_ARRAY_COUNT: usize = 0x18c;
    pub const SYMBOL_FILE_UUID: usize = 0x190;
    pub const IMAGES_OFFSET: usize = 0x1c0;
    pub const IMAGES_COUNT: usize = 0x1c4;
    pub const CACHE_SUBTYPE: usize = 0x1c8;
}

/// `VM_PROT_*`, as mappings carry them.
pub const PROT_READ: u32 = 1;
pub const PROT_WRITE: u32 = 2;
pub const PROT_EXEC: u32 = 4;

/// One mapping of a cache file into the shared region.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub address: u64,
    pub size: u64,
    pub file_offset: u64,
    pub max_prot: u32,
    pub init_prot: u32,
    /// The mapping's slide info, as `(file offset, size)` in the same file.
    pub slide_info: Option<(u64, u64)>,
}

/// A library in the cache: its install name and where its header is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DylibEntry {
    pub path: String,
    pub address: u64,
}

/// A subcache the main file names: where it sits relative to the cache's
/// base, and the suffix of its file name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubCache {
    pub uuid: [u8; 16],
    pub vm_offset: u64,
    pub suffix: String,
}

/// One cache file's header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// `dyld_v1   arm64`, `dyld_v1  arm64e`, ...
    pub magic: String,
    pub uuid: [u8; 16],
    pub platform: u32,
    pub os_version: u32,
    pub shared_region_start: u64,
    pub shared_region_size: u64,
    pub max_slide: u64,
    /// dyld's own header and entry point, when dyld lives in the cache.
    pub dyld_in_cache: Option<(u64, u64)>,
    pub mappings: Vec<Mapping>,
    pub images: Vec<DylibEntry>,
    pub subcaches: Vec<SubCache>,
    pub symbol_file_uuid: Option<[u8; 16]>,
}

impl Header {
    pub fn is_arm64e(&self) -> bool {
        self.magic.ends_with("arm64e")
    }

    /// The address range this file's mappings cover: `[start, end)`.
    pub fn span(&self) -> (u64, u64) {
        let start = self.mappings.iter().map(|m| m.address).min().unwrap_or(0);
        let end = self.mappings.iter().map(|m| m.address + m.size).max().unwrap_or(0);
        (start, end)
    }
}

fn bad(m: impl Into<String>) -> LoadError {
    LoadError::MachO(format!("dyld shared cache: {}", m.into()))
}

fn u16_at(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(o..o.checked_add(2)?)?.try_into().ok()?))
}
fn u32_at(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(o..o.checked_add(4)?)?.try_into().ok()?))
}
fn u64_at(d: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(d.get(o..o.checked_add(8)?)?.try_into().ok()?))
}
fn uuid_at(d: &[u8], o: usize) -> Option<[u8; 16]> {
    d.get(o..o + 16)?.try_into().ok()
}
fn cstr(d: &[u8], o: usize) -> Option<String> {
    let b = d.get(o..)?;
    let n = b.iter().position(|&c| c == 0)?;
    Some(String::from_utf8_lossy(&b[..n]).into_owned())
}

pub fn is_cache(d: &[u8]) -> bool {
    d.starts_with(b"dyld_v1 ")
}

/// Parse a cache file's header. `d` needs only the header and the tables it
/// points at (the first few hundred kilobytes of the main file).
pub fn parse_header(d: &[u8]) -> Result<Header, LoadError> {
    if !is_cache(d) {
        return Err(bad("no dyld_v1 magic"));
    }
    let hsize = u32_at(d, hdr::MAPPING_OFFSET).ok_or_else(|| bad("truncated header"))? as usize;
    // A field the header is too old to have reads as zero.
    let f32 = |o: usize| if o + 4 <= hsize { u32_at(d, o).unwrap_or(0) } else { 0 };
    let f64_ = |o: usize| if o + 8 <= hsize { u64_at(d, o).unwrap_or(0) } else { 0 };
    let magic = cstr(d, hdr::MAGIC).unwrap_or_default();
    let uuid = uuid_at(d, hdr::UUID).ok_or_else(|| bad("truncated header"))?;

    let mut mappings = Vec::new();
    let (wso, wsc) = (f32(hdr::MAPPING_WITH_SLIDE_OFFSET) as usize, f32(hdr::MAPPING_WITH_SLIDE_COUNT) as usize);
    if wso != 0 && wsc != 0 {
        for i in 0..wsc {
            let o = wso + i * 56;
            let m = (|| {
                let (si_off, si_size) = (u64_at(d, o + 24)?, u64_at(d, o + 32)?);
                Some(Mapping {
                    address: u64_at(d, o)?,
                    size: u64_at(d, o + 8)?,
                    file_offset: u64_at(d, o + 16)?,
                    max_prot: u32_at(d, o + 48)?,
                    init_prot: u32_at(d, o + 52)?,
                    slide_info: (si_size != 0).then_some((si_off, si_size)),
                })
            })()
            .ok_or_else(|| bad(format!("mapping {i} is truncated")))?;
            mappings.push(m);
        }
    } else {
        let (mo, mc) = (hsize, f32(hdr::MAPPING_COUNT) as usize);
        for i in 0..mc {
            let o = mo + i * 32;
            let m = (|| {
                Some(Mapping {
                    address: u64_at(d, o)?,
                    size: u64_at(d, o + 8)?,
                    file_offset: u64_at(d, o + 16)?,
                    max_prot: u32_at(d, o + 24)?,
                    init_prot: u32_at(d, o + 28)?,
                    slide_info: None,
                })
            })()
            .ok_or_else(|| bad(format!("mapping {i} is truncated")))?;
            mappings.push(m);
        }
    }

    // The image list moved when the header grew; a subcache has none.
    let (io, ic) = match (f32(hdr::IMAGES_OFFSET), f32(hdr::IMAGES_COUNT)) {
        (o, c) if o != 0 && c != 0 => (o as usize, c as usize),
        _ => (f32(hdr::IMAGES_OFFSET_OLD) as usize, f32(hdr::IMAGES_COUNT_OLD) as usize),
    };
    let mut images = Vec::with_capacity(ic);
    for i in 0..ic {
        let o = io + i * 32;
        let (Some(address), Some(path_off)) = (u64_at(d, o), u32_at(d, o + 24)) else {
            return Err(bad(format!("image {i} is truncated")));
        };
        let path = cstr(d, path_off as usize).ok_or_else(|| bad(format!("image {i}'s path is outside the file")))?;
        images.push(DylibEntry { path, address });
    }

    // Subcache entries gained a file-name suffix when CACHE_SUBTYPE was added.
    let (so, sc) = (f32(hdr::SUBCACHE_ARRAY_OFFSET) as usize, f32(hdr::SUBCACHE_ARRAY_COUNT) as usize);
    let with_suffix = hsize > hdr::CACHE_SUBTYPE;
    let mut subcaches = Vec::with_capacity(sc);
    for i in 0..sc {
        let o = if with_suffix { so + i * 56 } else { so + i * 24 };
        let uuid = uuid_at(d, o).ok_or_else(|| bad(format!("subcache {i} is truncated")))?;
        let vm_offset = u64_at(d, o + 16).ok_or_else(|| bad(format!("subcache {i} is truncated")))?;
        let suffix = if with_suffix {
            let b = d.get(o + 24..o + 56).ok_or_else(|| bad(format!("subcache {i} is truncated")))?;
            let n = b.iter().position(|&c| c == 0).unwrap_or(32);
            String::from_utf8_lossy(&b[..n]).into_owned()
        } else {
            format!(".{}", i + 1)
        };
        subcaches.push(SubCache { uuid, vm_offset, suffix });
    }

    let dyld_mh = f64_(hdr::DYLD_IN_CACHE_MH);
    let symbol_file_uuid = if hsize > hdr::SYMBOL_FILE_UUID + 16 {
        uuid_at(d, hdr::SYMBOL_FILE_UUID).filter(|u| u.iter().any(|&b| b != 0))
    } else {
        None
    };
    Ok(Header {
        magic,
        uuid,
        platform: f32(hdr::PLATFORM),
        os_version: f32(hdr::OS_VERSION),
        shared_region_start: f64_(hdr::SHARED_REGION_START),
        shared_region_size: f64_(hdr::SHARED_REGION_SIZE),
        max_slide: f64_(hdr::MAX_SLIDE),
        dyld_in_cache: (dyld_mh != 0).then(|| (dyld_mh, f64_(hdr::DYLD_IN_CACHE_ENTRY))),
        mappings,
        images,
        subcaches,
        symbol_file_uuid,
    })
}

/// Rebase one mapping's bytes in place by its slide info, for a cache
/// mapped `slide` bytes above its linked address. `data` is the mapping's
/// contents (its `size` bytes from `file_offset`); `info` the slide info.
pub fn apply_slide(data: &mut [u8], info: &[u8], slide: u64) -> Result<u64, LoadError> {
    apply_slide_visit(data, info, slide, &mut |_, _| {})
}

/// [`apply_slide`], telling `visit` each rebased slot's offset in `data`
/// and the address it now holds.
pub fn apply_slide_visit(data: &mut [u8], info: &[u8], slide: u64, visit: &mut dyn FnMut(usize, u64)) -> Result<u64, LoadError> {
    match slide_version(info)? {
        2 => slide_v2(data, info, slide, visit),
        3 => slide_v3(data, info, slide, visit),
        5 => slide_v5(data, info, slide, visit),
        v => Err(bad(format!("slide info version {v} is not supported"))),
    }
}

pub fn slide_version(info: &[u8]) -> Result<u32, LoadError> {
    u32_at(info, 0).ok_or_else(|| bad("empty slide info"))
}

/// `dyld_cache_slide_info2` (arm64): chains of 4-byte-aligned pointers,
/// the distance to the next in the bits `delta_mask` selects.
fn slide_v2(data: &mut [u8], info: &[u8], slide: u64, visit: &mut dyn FnMut(usize, u64)) -> Result<u64, LoadError> {
    const ATTR_EXTRA: u16 = 0x8000;
    const ATTR_NO_REBASE: u16 = 0x4000;
    const ATTR_END: u16 = 0x8000;
    const VALUE: u16 = 0x3fff;
    let field = |o: usize| u32_at(info, o).ok_or_else(|| bad("slide info v2 is truncated"));
    let page_size = field(4)? as usize;
    let (starts, nstarts) = (field(8)? as usize, field(12)? as usize);
    let extras = field(16)? as usize;
    let delta_mask = u64_at(info, 24).ok_or_else(|| bad("slide info v2 is truncated"))?;
    let value_add = u64_at(info, 32).ok_or_else(|| bad("slide info v2 is truncated"))?;
    if delta_mask == 0 || page_size == 0 {
        return Err(bad("slide info v2 has no delta mask"));
    }
    let delta_shift = delta_mask.trailing_zeros() - 2;
    let mut fixed = 0u64;
    let mut chain = |data: &mut [u8], page: usize, mut off: usize| -> Result<(), LoadError> {
        loop {
            let at = page * page_size + off;
            let raw = u64_at(data, at).ok_or_else(|| bad("a v2 chain runs past its mapping"))?;
            let delta = ((raw & delta_mask) >> delta_shift) as usize;
            let mut value = raw & !delta_mask;
            if value != 0 {
                value = value.wrapping_add(value_add).wrapping_add(slide);
            }
            data[at..at + 8].copy_from_slice(&value.to_le_bytes());
            visit(at, value);
            fixed += 1;
            if delta == 0 {
                return Ok(());
            }
            off += delta;
        }
    };
    for page in 0..nstarts {
        let start = u16_at(info, starts + page * 2).ok_or_else(|| bad("slide info v2 is truncated"))?;
        if start == ATTR_NO_REBASE {
            continue;
        }
        if start & ATTR_EXTRA != 0 {
            let mut i = (start & VALUE) as usize;
            loop {
                let e = u16_at(info, extras + i * 2).ok_or_else(|| bad("slide info v2 extras are truncated"))?;
                chain(data, page, ((e & VALUE) as usize) * 4)?;
                if e & ATTR_END != 0 {
                    break;
                }
                i += 1;
            }
        } else {
            chain(data, page, (start as usize) * 4)?;
        }
    }
    Ok(fixed)
}

/// `dyld_cache_slide_info3` (arm64e): 8-byte chains whose entries are
/// either authenticated (a 32-bit offset from `auth_value_add`) or plain (a
/// 51-bit pointer with its top byte packed down).
fn slide_v3(data: &mut [u8], info: &[u8], slide: u64, visit: &mut dyn FnMut(usize, u64)) -> Result<u64, LoadError> {
    const NO_REBASE: u16 = 0xffff;
    let page_size = u32_at(info, 4).ok_or_else(|| bad("slide info v3 is truncated"))? as usize;
    let nstarts = u32_at(info, 8).ok_or_else(|| bad("slide info v3 is truncated"))? as usize;
    let auth_value_add = u64_at(info, 16).ok_or_else(|| bad("slide info v3 is truncated"))?;
    let mut fixed = 0u64;
    for page in 0..nstarts {
        let start = u16_at(info, 24 + page * 2).ok_or_else(|| bad("slide info v3 is truncated"))?;
        if start == NO_REBASE {
            continue;
        }
        let mut at = page * page_size + start as usize;
        loop {
            let raw = u64_at(data, at).ok_or_else(|| bad("a v3 chain runs past its mapping"))?;
            let next = ((raw >> 51) & 0x7ff) as usize * 8;
            let value = if raw >> 63 != 0 {
                // Authenticated: gex does not sign, so the plain address.
                (raw & 0xffff_ffff).wrapping_add(auth_value_add).wrapping_add(slide)
            } else {
                let v51 = raw & 0x0007_ffff_ffff_ffff;
                let top8 = v51 & 0x0007_f800_0000_0000;
                let bottom43 = v51 & 0x0000_07ff_ffff_ffff;
                ((top8 << 13) | bottom43).wrapping_add(slide)
            };
            data[at..at + 8].copy_from_slice(&value.to_le_bytes());
            visit(at, value);
            fixed += 1;
            if next == 0 {
                break;
            }
            at += next;
        }
    }
    Ok(fixed)
}

/// `dyld_cache_slide_info5` (arm64e, newer caches):
/// `dyld_chained_ptr_arm64e_shared_cache` chains, each entry a 34-bit
/// offset from `value_add`, a plain one with its top byte beside it.
fn slide_v5(data: &mut [u8], info: &[u8], slide: u64, visit: &mut dyn FnMut(usize, u64)) -> Result<u64, LoadError> {
    const NO_REBASE: u16 = 0xffff;
    let page_size = u32_at(info, 4).ok_or_else(|| bad("slide info v5 is truncated"))? as usize;
    let nstarts = u32_at(info, 8).ok_or_else(|| bad("slide info v5 is truncated"))? as usize;
    let value_add = u64_at(info, 16).ok_or_else(|| bad("slide info v5 is truncated"))?;
    let mut fixed = 0u64;
    for page in 0..nstarts {
        let start = u16_at(info, 24 + page * 2).ok_or_else(|| bad("slide info v5 is truncated"))?;
        if start == NO_REBASE {
            continue;
        }
        let mut at = page * page_size + start as usize;
        loop {
            let raw = u64_at(data, at).ok_or_else(|| bad("a v5 chain runs past its mapping"))?;
            let next = ((raw >> 52) & 0x7ff) as usize * 8;
            let target = (raw & 0x3_ffff_ffff).wrapping_add(value_add).wrapping_add(slide);
            let value = if raw >> 63 != 0 { target } else { target | (((raw >> 34) & 0xff) << 56) };
            data[at..at + 8].copy_from_slice(&value.to_le_bytes());
            visit(at, value);
            fixed += 1;
            if next == 0 {
                break;
            }
            at += next;
        }
    }
    Ok(fixed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put16(v: &mut [u8], o: usize, x: u16) {
        v[o..o + 2].copy_from_slice(&x.to_le_bytes());
    }
    fn put32(v: &mut [u8], o: usize, x: u32) {
        v[o..o + 4].copy_from_slice(&x.to_le_bytes());
    }
    fn put64(v: &mut [u8], o: usize, x: u64) {
        v[o..o + 8].copy_from_slice(&x.to_le_bytes());
    }

    #[test]
    fn v2_chains_strip_the_delta_and_add_value_add_and_slide() {
        // One page; pointers at 0x10 and 0x30 (delta 0x20 = 8 units of 4).
        let delta_mask = 0x00ff_ff00_0000_0000u64;
        let mut info = vec![0u8; 64];
        put32(&mut info, 0, 2);
        put32(&mut info, 4, 0x1000);
        put32(&mut info, 8, 40); // page starts
        put32(&mut info, 12, 1);
        put32(&mut info, 16, 48); // extras (unused)
        put64(&mut info, 24, delta_mask);
        put64(&mut info, 32, 0x1_8000_0000);
        put16(&mut info, 40, 0x10 / 4);
        let shift = delta_mask.trailing_zeros() - 2;
        let mut page = vec![0u8; 0x1000];
        put64(&mut page, 0x10, 0x1234 | ((0x20u64) << shift));
        put64(&mut page, 0x30, 0x5678);
        assert_eq!(apply_slide(&mut page, &info, 0x4000).unwrap(), 2);
        assert_eq!(u64_at(&page, 0x10), Some(0x1_8000_0000 + 0x1234 + 0x4000));
        assert_eq!(u64_at(&page, 0x30), Some(0x1_8000_0000 + 0x5678 + 0x4000));
    }

    #[test]
    fn v2_zero_stays_zero() {
        let mut info = vec![0u8; 64];
        put32(&mut info, 0, 2);
        put32(&mut info, 4, 0x1000);
        put32(&mut info, 8, 40);
        put32(&mut info, 12, 1);
        put64(&mut info, 24, 0x00ff_ff00_0000_0000);
        put64(&mut info, 32, 0x1_8000_0000);
        put16(&mut info, 40, 0);
        let mut page = vec![0u8; 0x1000];
        apply_slide(&mut page, &info, 0x4000).unwrap();
        assert_eq!(u64_at(&page, 0), Some(0));
    }

    #[test]
    fn v3_plain_and_authenticated_entries() {
        let mut info = vec![0u8; 32];
        put32(&mut info, 0, 3);
        put32(&mut info, 4, 0x4000);
        put32(&mut info, 8, 1);
        put64(&mut info, 16, 0x1_8000_0000);
        put16(&mut info, 24, 0x8);
        let mut page = vec![0u8; 0x4000];
        // Plain, next 2 (16 bytes): top byte 0x80 packed at bit 43.
        put64(&mut page, 0x8, (2u64 << 51) | (0x80u64 << 43) | 0x1_8000_1000);
        // Authenticated, last: offset 0x2000.
        put64(&mut page, 0x18, (1u64 << 63) | 0x2000);
        assert_eq!(apply_slide(&mut page, &info, 0).unwrap(), 2);
        assert_eq!(u64_at(&page, 0x8), Some(0x8000_0001_8000_1000));
        assert_eq!(u64_at(&page, 0x18), Some(0x1_8000_2000));
    }

    #[test]
    fn v5_entries_are_offsets_from_value_add() {
        let mut info = vec![0u8; 32];
        put32(&mut info, 0, 5);
        put32(&mut info, 4, 0x4000);
        put32(&mut info, 8, 1);
        put64(&mut info, 16, 0x1_8000_0000);
        put16(&mut info, 24, 0);
        let mut page = vec![0u8; 0x4000];
        put64(&mut page, 0, (1u64 << 52) | 0x100);
        put64(&mut page, 8, (1u64 << 63) | 0x200);
        assert_eq!(apply_slide(&mut page, &info, 0x10000).unwrap(), 2);
        assert_eq!(u64_at(&page, 0), Some(0x1_8001_0100));
        assert_eq!(u64_at(&page, 8), Some(0x1_8001_0200));
    }

    /// The host's own cache, when there is one (a Mac): the header parses,
    /// its images resolve, and each subcache is where the main file says.
    #[test]
    fn host_cache_parses() {
        let dir = "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld";
        let Ok(main) = std::fs::read(format!("{dir}/dyld_shared_cache_arm64e")) else { return };
        let h = parse_header(&main).unwrap();
        assert!(h.is_arm64e());
        assert!(!h.mappings.is_empty());
        assert!(h.images.len() > 1000, "{} images", h.images.len());
        assert!(h.images.iter().any(|i| i.path == "/usr/lib/libSystem.B.dylib"));
        assert!(h.shared_region_start > 0 && h.shared_region_size > 0);
        let base = h.mappings[0].address;
        for sc in h.subcaches.iter().take(4) {
            let Ok(f) = std::fs::File::open(format!("{dir}/dyld_shared_cache_arm64e{}", sc.suffix)) else { continue };
            let mut b = vec![0u8; 0x4000];
            use std::io::Read;
            let n = (&f).read(&mut b).unwrap();
            let sub = parse_header(&b[..n]).unwrap();
            assert_eq!(sub.uuid, sc.uuid, "{}", sc.suffix);
            assert_eq!(sub.span().0, base + sc.vm_offset, "{}", sc.suffix);
        }
    }
}
