//! `map_with_linking_np` (`bsd/vm/vm_unix.c`) and the dyld pager
//! (`osfmk/vm/vm_dyld_pager.c`): dyld hands the kernel an image's data
//! regions and their chained fixups, and the pager applies the fixups to
//! each page as it is paged in from the file.
//!
//! gex has no page-ins to hook, so each page is brought in and fixed up
//! when the region is mapped: the pages hold what the pager would have
//! given them on their first touch.

use crate::errno::Errno;
use crate::syscalls::{nr, Kernel};
use crate::GuestMem;

/// `MWL_INFO_VERS`, `MWL_MAX_REGION_COUNT`, `MWL_MAX_LINK_INFO_SIZE`.
const MWL_INFO_VERS: u32 = 7;
const MWL_MAX_REGION_COUNT: u32 = 5;
const MWL_MAX_LINK_INFO_SIZE: u32 = 64 * 1024 * 1024;
/// `sizeof(struct mwl_info_hdr)`: `MWL_MIN_LINK_INFO_SIZE`.
const HDR_SIZE: u32 = 40;
/// `sizeof(struct mwl_region)`.
const REGION_SIZE: usize = 32;
/// `sizeof(struct dyld_chained_starts_in_image)` and of
/// `dyld_chained_starts_in_segment`.
const STARTS_IN_IMAGE_SIZE: u32 = 8;
const STARTS_IN_SEGMENT_SIZE: u32 = 24;

/// `DYLD_VM_END_MWL`: `shared_region_check_np`'s argument that ends
/// `map_with_linking_np` for the process.
pub const DYLD_VM_END_MWL: u64 = u64::MAX;

/// `DYLD_CHAINED_PTR_*` the pager handles without pointer authentication.
mod fmt {
    pub const PTR_64: u16 = 2;
    pub const PTR_32: u16 = 3;
    pub const PTR_64_OFFSET: u16 = 6;
}
const START_NONE: u16 = 0xffff;
const START_MULTI: u16 = 0x8000;
const START_LAST: u16 = 0x8000;

/// `VM_PROT_*` the call checks.
const VM_PROT_WRITE: u32 = 0x2;
const VM_PROT_EXECUTE: u32 = 0x4;
const VM_PROT_DEFAULT: u32 = 0x3;
const VM_PROT_TPRO: u32 = 0x200;
/// `VM_PROT_ZF` (`osfmk/mach/shared_region.h`).
const VM_PROT_ZF: u32 = 0x10;

/// `kern_return_t`s the call maps onto an errno.
#[derive(Debug, PartialEq, Eq)]
enum Kr {
    Failure,
    ResourceShortage,
    InvalidArgument,
}

fn le16(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o + 2).map(|s| u16::from_le_bytes(s.try_into().unwrap()))
}
fn le32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4).map(|s| u32::from_le_bytes(s.try_into().unwrap()))
}
fn le64(b: &[u8], o: usize) -> Option<u64> {
    b.get(o..o + 8).map(|s| u64::from_le_bytes(s.try_into().unwrap()))
}

/// `struct mwl_region`.
#[derive(Clone, Copy, Debug)]
struct Region {
    fd: i32,
    prot: u32,
    file_offset: u64,
    address: u64,
    size: u64,
}

/// The pager's link info, `struct mwl_info_hdr` first.
struct Info<'a> {
    b: &'a [u8],
    pointer_format: u16,
    binds_offset: u32,
    binds_count: u32,
    chains_offset: u32,
    slide: u64,
    image_address: u64,
}

impl Info<'_> {
    fn bind(&self, ordinal: u32, wide: bool) -> u64 {
        let o = self.binds_offset as usize + ordinal as usize * if wide { 8 } else { 4 };
        if wide {
            le64(self.b, o).unwrap_or(0)
        } else {
            u64::from(le32(self.b, o).unwrap_or(0))
        }
    }
}

/// One page's fixups (`fixup_page`): the segment holding `user_va`, then
/// its chain by the pointer format. `Err` where the pager fails the page-in.
/// What goes wrong inside a chain only stops that chain, as there.
fn fixup_page(page: &mut [u8], user_va: u64, info: &Info, page_size: u64) -> Result<(), ()> {
    let b = info.b;
    let starts = info.chains_offset as usize;
    let seg_count = le32(b, starts).ok_or(())?;
    let mut found = None;
    for i in 0..seg_count as usize {
        let seg = starts + le32(b, starts + 4 + 4 * i).ok_or(())? as usize;
        if seg + STARTS_IN_SEGMENT_SIZE as usize > b.len() {
            return Err(());
        }
        let seg_offset = le64(b, seg + 8).unwrap();
        let seg_page_size = u64::from(le16(b, seg + 4).unwrap());
        let page_count = le16(b, seg + 20).unwrap();
        let start = info.image_address.wrapping_add(seg_offset);
        let end = start.wrapping_add(u64::from(page_count) * seg_page_size);
        if start <= user_va && user_va < end {
            let size = le32(b, seg).unwrap() as usize;
            let index = ((user_va - start) / page_size) as u32;
            if seg + size > b.len() || size < STARTS_IN_SEGMENT_SIZE as usize || seg + 22 + 2 * page_count as usize > b.len() || index >= u32::from(page_count) {
                return Err(());
            }
            found = Some((seg, index));
            break;
        }
    }
    let Some((seg, index)) = found else { return Err(()) };
    match info.pointer_format {
        fmt::PTR_64 => fixup_page64(page, info, seg, index, false, page_size),
        fmt::PTR_64_OFFSET => fixup_page64(page, info, seg, index, true, page_size),
        fmt::PTR_32 => fixup_page32(page, info, seg, index),
        _ => return Err(()),
    }
    Ok(())
}

/// `fixupPage64`.
fn fixup_page64(page: &mut [u8], info: &Info, seg: usize, index: u32, offset_based: bool, page_size: u64) {
    let first = le16(info.b, seg + 22 + 2 * index as usize).unwrap();
    if first == START_NONE {
        return;
    }
    let adjust = if offset_based { info.image_address } else { info.slide };
    let mut at = first as usize;
    loop {
        if at + 8 > page.len() {
            return;
        }
        let value = u64::from_le_bytes(page[at..at + 8].try_into().unwrap());
        let delta = (value >> 51) & 0xfff;
        let new = if value & (1 << 63) != 0 {
            let ordinal = (value & 0xff_ffff) as u32;
            if ordinal >= info.binds_count {
                return;
            }
            info.bind(ordinal, true).wrapping_add((value >> 24) & 0xff)
        } else {
            let target = value & 0xf_ffff_ffff;
            let high8 = (value >> 36) & 0xff;
            target.wrapping_add(adjust).wrapping_add(high8 << 56)
        };
        page[at..at + 8].copy_from_slice(&new.to_le_bytes());
        if delta * 4 >= page_size {
            return;
        }
        if delta == 0 {
            return;
        }
        at += (delta * 4) as usize;
    }
}

/// `fixupPage32`, with `fixupChain32` for each start.
fn fixup_page32(page: &mut [u8], info: &Info, seg: usize, index: u32) {
    let b = info.b;
    let max_valid = le32(b, seg + 16).unwrap();
    let start = le16(b, seg + 22 + 2 * index as usize).unwrap();
    if start == START_NONE {
        return;
    }
    let chain = |page: &mut [u8], mut at: usize| loop {
        if at + 4 > page.len() {
            return;
        }
        let value = u32::from_le_bytes(page[at..at + 4].try_into().unwrap());
        let delta = (value >> 26) & 0x1f;
        let new = if value & 0x8000_0000 != 0 {
            let ordinal = value & 0xf_ffff;
            if ordinal >= info.binds_count {
                return;
            }
            (info.bind(ordinal, false) as u32).wrapping_add((value >> 20) & 0x3f)
        } else {
            let target = value & 0x03ff_ffff;
            if target > max_valid {
                let bias = (0x0400_0000 + max_valid) / 2;
                target.wrapping_sub(bias)
            } else {
                target.wrapping_add(info.slide as u32)
            }
        };
        page[at..at + 4].copy_from_slice(&new.to_le_bytes());
        if delta == 0 {
            return;
        }
        at += delta as usize * 4;
    };
    if start & START_MULTI != 0 {
        let mut overflow = (start & !START_MULTI) as usize;
        loop {
            let Some(v) = le16(b, seg + 22 + 2 * overflow).filter(|_| seg + 22 + 2 * (overflow + 1) <= b.len()) else { return };
            chain(page, (v & !START_LAST) as usize);
            if v & START_LAST != 0 {
                return;
            }
            overflow += 1;
        }
    } else {
        chain(page, start as usize);
    }
}

impl Kernel {
    /// `map_with_linking_np(regions, region_count, link_info, link_info_size)`.
    pub(crate) fn darwin_map_with_linking(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        match self.darwin_mwl(m, a) {
            Ok(()) => Ok(0),
            Err(Kr::ResourceShortage) => Err(Errno::ENOMEM),
            Err(_) => Err(Errno::EINVAL),
        }
    }

    fn darwin_mwl(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<(), Kr> {
        if self.dtask.disallow_mwl {
            return Err(Kr::Failure);
        }
        let (region_count, link_info_size) = (a[1] as u32, a[3] as u32);
        if region_count == 0 || region_count > MWL_MAX_REGION_COUNT || link_info_size <= HDR_SIZE || link_info_size >= MWL_MAX_LINK_INFO_SIZE {
            return Err(Kr::Failure);
        }
        let rb = m.read(a[0], region_count as usize * REGION_SIZE).map_err(|_| Kr::Failure)?.to_vec();
        let regions: Vec<Region> = rb
            .chunks(REGION_SIZE)
            .map(|r| Region { fd: le32(r, 0).unwrap() as i32, prot: le32(r, 4).unwrap(), file_offset: le64(r, 8).unwrap(), address: le64(r, 16).unwrap(), size: le64(r, 24).unwrap() })
            .collect();
        let li = m.read(a[2], link_info_size as usize).map_err(|_| Kr::Failure)?.to_vec();
        let info = Info {
            b: &li,
            pointer_format: le16(&li, 6).unwrap(),
            binds_offset: le32(&li, 8).unwrap(),
            binds_count: le32(&li, 12).unwrap(),
            chains_offset: le32(&li, 16).unwrap(),
            slide: le64(&li, 24).unwrap(),
            image_address: le64(&li, 32).unwrap(),
        };
        let chains_size = le32(&li, 20).unwrap();
        if le32(&li, 0).unwrap() != MWL_INFO_VERS || info.binds_offset > link_info_size {
            return Err(Kr::Failure);
        }
        // The kernel's PAGE_SIZE.
        let page_size = super::mach::PAGE_MASK + 1;
        if u64::from(le16(&li, 4).unwrap()) != page_size {
            return Err(Kr::InvalidArgument);
        }
        let binds_size = u64::from(info.binds_count) * if info.pointer_format == fmt::PTR_32 { 4 } else { 8 };
        if binds_size > u64::from(link_info_size - info.binds_offset)
            || info.chains_offset > link_info_size
            || chains_size < STARTS_IN_IMAGE_SIZE
            || chains_size > link_info_size - info.chains_offset
        {
            return Err(Kr::Failure);
        }
        let fd = regions[0].fd;
        for r in &regions {
            if r.fd != fd || r.prot & VM_PROT_EXECUTE != 0 || r.prot & VM_PROT_ZF != 0 || (r.prot & VM_PROT_TPRO != 0 && r.prot & VM_PROT_WRITE == 0) {
                return Err(Kr::Failure);
            }
        }
        // fp_get_ftype(DTYPE_VNODE), FREAD, a regular file.
        let file = self.fds.get(fd).map_err(|_| Kr::Failure)?;
        let Some(vnode) = self.darwin_vnode_of(&file) else { return Err(Kr::Failure) };
        if !file.readable || file.handle.metadata().map_err(|_| Kr::Failure)?.file_type != crate::vfs::FileType::Regular {
            return Err(Kr::Failure);
        }
        // cs_system_enforcement(): every region inside the one signature
        // that covers its start.
        for r in &regions {
            if !super::codesign::range_codesigned(vnode, r.file_offset, r.size) {
                return Err(Kr::Failure);
            }
        }
        for r in &regions {
            self.darwin_mwl_region(m, fd, r, &regions, &info, page_size)?;
        }
        Ok(())
    }

    /// One region: the file mapped privately over it, at the protections
    /// asked for as current and most, then each page fixed up as
    /// `dyld_pager_data_request` fixes it up.
    fn darwin_mwl_region(&mut self, m: &mut GuestMem<'_>, fd: i32, r: &Region, all: &[Region], info: &Info, page_size: u64) -> Result<(), Kr> {
        use crate::mem::flags as lf;
        let prot = u64::from(r.prot & VM_PROT_DEFAULT);
        let size = r.size.checked_add(page_size - 1).ok_or(Kr::Failure)? & !(page_size - 1);
        self.canonical(m, nr::MMAP, [r.address, size, prot, lf::PRIVATE | lf::FIXED, fd as u64, r.file_offset]).map_err(|e| if e == Errno::ENOMEM { Kr::ResourceShortage } else { Kr::Failure })?;
        self.dtask.maxprot.set(r.address, r.address + size, prot as u8);
        let mut page = vec![0u8; page_size as usize];
        for i in 0..size / page_size {
            let o = r.file_offset + i * page_size;
            let at = r.address + i * page_size;
            // The pager's offset back to an address: the first range that
            // holds it.
            let Some(user_va) = all.iter().find(|q| q.file_offset <= o && o < q.file_offset + q.size).map(|q| q.address + (o - q.file_offset)) else {
                self.darwin_unimplemented("a dyld pager page outside its ranges (the page-in fails, and the access faults)".into());
                continue;
            };
            page.copy_from_slice(m.read(at, page_size as usize).map_err(|_| Kr::Failure)?);
            if fixup_page(&mut page, user_va, info, page_size).is_err() {
                self.darwin_unimplemented("a dyld pager page whose fixups fail (the page-in fails, and the access faults)".into());
                continue;
            }
            m.write(at, &page).map_err(|_| Kr::Failure)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A link info with one segment of `pages` pages of `DYLD_CHAINED_PTR_64`
    /// at `image`, its starts `starts`, and `binds`.
    fn info(image: u64, slide: u64, starts: &[u16], binds: &[u64]) -> Vec<u8> {
        let mut b = vec![0u8; 40];
        let binds_off = b.len() as u32;
        for v in binds {
            b.extend_from_slice(&v.to_le_bytes());
        }
        let chains_off = b.len() as u32;
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&8u32.to_le_bytes());
        let seg_size = 22 + 2 * starts.len() as u32;
        b.extend_from_slice(&seg_size.to_le_bytes());
        b.extend_from_slice(&4096u16.to_le_bytes());
        b.extend_from_slice(&fmt::PTR_64.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&(starts.len() as u16).to_le_bytes());
        for s in starts {
            b.extend_from_slice(&s.to_le_bytes());
        }
        let chains_size = b.len() as u32 - chains_off;
        let mut put = |o: usize, v: &[u8]| b[o..o + v.len()].copy_from_slice(v);
        put(0, &MWL_INFO_VERS.to_le_bytes());
        put(4, &4096u16.to_le_bytes());
        put(6, &fmt::PTR_64.to_le_bytes());
        put(8, &binds_off.to_le_bytes());
        put(12, &(binds.len() as u32).to_le_bytes());
        put(16, &chains_off.to_le_bytes());
        put(20, &chains_size.to_le_bytes());
        put(24, &slide.to_le_bytes());
        put(32, &image.to_le_bytes());
        b
    }

    #[test]
    fn a_chain_of_rebases_and_binds_is_applied() {
        let li = info(0x1_0000_0000, 0x4000, &[0x10, START_NONE], &[0xdead_0000]);
        let i = Info { b: &li, pointer_format: fmt::PTR_64, binds_offset: 40, binds_count: 1, chains_offset: 48, slide: 0x4000, image_address: 0x1_0000_0000 };
        let mut page = vec![0u8; 4096];
        // A rebase to 0x1234 with high8 0x12, next 2 words on; then a bind
        // of ordinal 0 with addend 8, the chain's end.
        let rebase = 0x1234u64 | 0x12 << 36 | 2 << 51;
        let bind: u64 = 1 << 63 | 8 << 24;
        page[0x10..0x18].copy_from_slice(&rebase.to_le_bytes());
        page[0x18..0x20].copy_from_slice(&bind.to_le_bytes());
        fixup_page(&mut page, 0x1_0000_0000, &i, 4096).unwrap();
        assert_eq!(u64::from_le_bytes(page[0x10..0x18].try_into().unwrap()), 0x1234 + 0x4000 + (0x12 << 56));
        assert_eq!(u64::from_le_bytes(page[0x18..0x20].try_into().unwrap()), 0xdead_0008);
        // The second page has no fixups; past the segment there is none.
        let mut p2 = vec![7u8; 4096];
        fixup_page(&mut p2, 0x1_0000_1000, &i, 4096).unwrap();
        assert!(p2.iter().all(|&b| b == 7));
        assert!(fixup_page(&mut p2, 0x1_0000_2000, &i, 4096).is_err());
    }
}
