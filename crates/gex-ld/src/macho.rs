//! Mach-O: Darwin's executable format, for the Darwin personality.
//!
//! A 64-bit arm64 image becomes the [`Image`] the translator and the loader
//! already understand: each `LC_SEGMENT_64` a [`Segment`] at its slid
//! address, the instruction sections as the code ranges, the symbol table's
//! defined functions as symbols, and the entry point from `LC_MAIN` or
//! `LC_UNIXTHREAD`. Fixups are not applied here. dyld applies its own and
//! the main executable's at run time, the way it does on Darwin, so only a
//! static image (or one with nothing to fix up) runs without it.

use crate::elf::{headers_only, Image, LoadError, Segment, Symbol};
use crate::stack::StackLayout;

/// Where a position-independent Mach-O executable is placed. Its linked
/// base, 0x1_0000_0000 past a 4 GiB `__PAGEZERO`, is where a 64-bit gex
/// memory keeps its dispatch tables, and the shared cache follows at
/// [`SHARED_REGION_BASE`]; iOS 17's runs to 0x2_4c5f_0000. Programs and
/// dyld go above both.
pub const PIE_BASE: u64 = 0x2_8000_0000;

/// Where arm64 Darwin maps the shared cache (`SHARED_REGION_BASE_ARM64`).
pub const SHARED_REGION_BASE: u64 = 0x1_8000_0000;

pub const MH_MAGIC_64: u32 = 0xfeed_facf;
pub const CPU_TYPE_ARM64: u32 = 0x0100_000c;

pub const MH_EXECUTE: u32 = 2;
pub const MH_DYLIB: u32 = 6;
pub const MH_DYLINKER: u32 = 7;

/// `mh_flags`: the image may be loaded at any address.
pub const MH_PIE: u32 = 0x0020_0000;

const LC_REQ_DYLD: u32 = 0x8000_0000;
pub const LC_SYMTAB: u32 = 0x2;
pub const LC_UNIXTHREAD: u32 = 0x5;
pub const LC_LOAD_DYLIB: u32 = 0xc;
pub const LC_ID_DYLIB: u32 = 0xd;
pub const LC_LOAD_DYLINKER: u32 = 0xe;
pub const LC_SEGMENT_64: u32 = 0x19;
pub const LC_UUID: u32 = 0x1b;
pub const LC_FUNCTION_STARTS: u32 = 0x26;
pub const LC_BUILD_VERSION: u32 = 0x32;
pub const LC_LOAD_WEAK_DYLIB: u32 = 0x18 | LC_REQ_DYLD;
pub const LC_REEXPORT_DYLIB: u32 = 0x1f | LC_REQ_DYLD;
pub const LC_MAIN: u32 = 0x28 | LC_REQ_DYLD;
pub const LC_DYLD_EXPORTS_TRIE: u32 = 0x33 | LC_REQ_DYLD;
pub const LC_DYLD_CHAINED_FIXUPS: u32 = 0x34 | LC_REQ_DYLD;

/// `VM_PROT_*`.
const PROT_READ: u32 = 1;
const PROT_WRITE: u32 = 2;
const PROT_EXEC: u32 = 4;

/// Section attributes that say a section holds instructions.
const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;
/// Section types with no file bytes.
const S_ZEROFILL: u32 = 0x1;
const S_GB_ZEROFILL: u32 = 0xc;
const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;
const SECTION_TYPE: u32 = 0xff;

/// `nlist_64.n_type`.
const N_STAB: u8 = 0xe0;
const N_TYPE: u8 = 0x0e;
const N_SECT: u8 = 0x0e;

/// `ARM_THREAD_STATE64` in an `LC_UNIXTHREAD`, and where its pc sits: after
/// x0-x28, fp, lr and sp.
const ARM_THREAD_STATE64: u32 = 6;
const THREAD_STATE_PC: usize = 32 * 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub segname: String,
    pub sectname: String,
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub flags: u32,
}

impl Section {
    pub fn has_instructions(&self) -> bool {
        self.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) != 0
    }

    fn zero_fill(&self) -> bool {
        matches!(self.flags & SECTION_TYPE, S_ZEROFILL | S_GB_ZEROFILL | S_THREAD_LOCAL_ZEROFILL)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seg {
    pub name: String,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: u32,
    pub initprot: u32,
    pub sections: Vec<Section>,
}

impl Seg {
    /// `__PAGEZERO` and its kind: an inaccessible reservation with nothing
    /// in it, which the loader leaves unmapped.
    pub fn is_guard(&self) -> bool {
        self.initprot == 0 && self.maxprot == 0 && self.filesize == 0
    }
}

/// Where a program starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entry {
    /// `LC_MAIN`: an offset from the start of the file's `__TEXT`, which
    /// dyld calls as `main`.
    Main { entryoff: u64, stacksize: u64 },
    /// `LC_UNIXTHREAD`: the pc the kernel starts the thread at (a static
    /// program, or dyld itself).
    Thread { pc: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Symtab {
    pub symoff: u32,
    pub nsyms: u32,
    pub stroff: u32,
    pub strsize: u32,
}

/// A parsed 64-bit Mach-O.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachO {
    pub filetype: u32,
    pub flags: u32,
    pub segments: Vec<Seg>,
    pub entry: Option<Entry>,
    /// `LC_LOAD_DYLINKER`: the dynamic linker the kernel maps for the
    /// program (`/usr/lib/dyld`).
    pub dylinker: Option<String>,
    /// `LC_ID_DYLIB`: a library's own install name.
    pub install_name: Option<String>,
    /// Every library the image links, weak and re-exported ones included,
    /// in load-command order.
    pub dylibs: Vec<String>,
    pub uuid: Option<[u8; 16]>,
    pub symtab: Option<Symtab>,
    /// `LC_FUNCTION_STARTS` and `LC_DYLD_CHAINED_FIXUPS`, as
    /// `(dataoff, datasize)` in the file.
    pub function_starts: Option<(u32, u32)>,
    pub chained_fixups: Option<(u32, u32)>,
    pub exports_trie: Option<(u32, u32)>,
    /// `LC_BUILD_VERSION`'s platform (2 is iOS) and SDK version
    /// (`xxxx.yy.zz` nibbles).
    pub platform: Option<u32>,
    pub sdk: Option<u32>,
}

pub fn is_macho(data: &[u8]) -> bool {
    u32_at(data, 0) == Some(MH_MAGIC_64)
}

fn u32_at(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(o..o.checked_add(4)?)?.try_into().ok()?))
}

fn u64_at(d: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(d.get(o..o.checked_add(8)?)?.try_into().ok()?))
}

/// A fixed-width name field (`segname`, `sectname`), up to its first NUL.
fn name16(d: &[u8], o: usize) -> Option<String> {
    let b = d.get(o..o + 16)?;
    let end = b.iter().position(|&c| c == 0).unwrap_or(16);
    Some(String::from_utf8_lossy(&b[..end]).into_owned())
}

/// A NUL-terminated string at `o`, bounded by `end`.
fn cstr(d: &[u8], o: usize, end: usize) -> Option<String> {
    let b = d.get(o..end.min(d.len()))?;
    let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    Some(String::from_utf8_lossy(&b[..n]).into_owned())
}

fn bad(m: impl Into<String>) -> LoadError {
    LoadError::MachO(m.into())
}

/// Parse a 64-bit arm64 Mach-O's header and load commands.
pub fn parse(d: &[u8]) -> Result<MachO, LoadError> {
    if d.len() < 32 {
        return Err(LoadError::TooShort);
    }
    if !is_macho(d) {
        return Err(bad("not a 64-bit little-endian Mach-O"));
    }
    let cputype = u32_at(d, 4).unwrap_or(0);
    if cputype != CPU_TYPE_ARM64 {
        return Err(bad(format!("cpu type {cputype:#x} is not arm64")));
    }
    let filetype = u32_at(d, 12).unwrap_or(0);
    let ncmds = u32_at(d, 16).unwrap_or(0) as usize;
    let sizeofcmds = u32_at(d, 20).unwrap_or(0) as usize;
    let flags = u32_at(d, 24).unwrap_or(0);
    let cmds_end = 32usize
        .checked_add(sizeofcmds)
        .filter(|&e| e <= d.len())
        .ok_or_else(|| bad("load commands run past the end of the file"))?;
    let mut m = MachO {
        filetype,
        flags,
        segments: Vec::new(),
        entry: None,
        dylinker: None,
        install_name: None,
        dylibs: Vec::new(),
        uuid: None,
        symtab: None,
        function_starts: None,
        chained_fixups: None,
        exports_trie: None,
        platform: None,
        sdk: None,
    };
    let mut o = 32usize;
    for i in 0..ncmds {
        let cmd = u32_at(d, o).ok_or_else(|| bad(format!("load command {i} is truncated")))?;
        let size = u32_at(d, o + 4).unwrap_or(0) as usize;
        if size < 8 || o + size > cmds_end {
            return Err(bad(format!("load command {i} ({cmd:#x}) has a bad size {size}")));
        }
        let c = &d[..o + size];
        let linkedit = |c: &[u8]| -> Option<(u32, u32)> { Some((u32_at(c, o + 8)?, u32_at(c, o + 12)?)) };
        // An `lc_str`: an offset from the command's start, inside it.
        let lc_str = |c: &[u8]| -> Option<String> { cstr(c, o + u32_at(c, o + 8)? as usize, o + size) };
        match cmd {
            LC_SEGMENT_64 => m.segments.push(segment(c, o).ok_or_else(|| bad(format!("LC_SEGMENT_64 {i} is truncated")))?),
            LC_MAIN => {
                m.entry = Some(Entry::Main {
                    entryoff: u64_at(c, o + 8).ok_or_else(|| bad("LC_MAIN is truncated"))?,
                    stacksize: u64_at(c, o + 16).unwrap_or(0),
                })
            }
            LC_UNIXTHREAD => {
                if m.entry.is_none() {
                    m.entry = thread_pc(c, o, size).map(|pc| Entry::Thread { pc });
                }
            }
            LC_LOAD_DYLINKER => m.dylinker = lc_str(c),
            LC_ID_DYLIB => m.install_name = lc_str(c),
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB => m.dylibs.extend(lc_str(c)),
            LC_UUID => m.uuid = c.get(o + 8..o + 24).and_then(|b| b.try_into().ok()),
            LC_SYMTAB => {
                m.symtab = (|| {
                    Some(Symtab {
                        symoff: u32_at(c, o + 8)?,
                        nsyms: u32_at(c, o + 12)?,
                        stroff: u32_at(c, o + 16)?,
                        strsize: u32_at(c, o + 20)?,
                    })
                })()
            }
            LC_FUNCTION_STARTS => m.function_starts = linkedit(c),
            LC_DYLD_CHAINED_FIXUPS => m.chained_fixups = linkedit(c),
            LC_DYLD_EXPORTS_TRIE => m.exports_trie = linkedit(c),
            LC_BUILD_VERSION => {
                m.platform = u32_at(c, o + 8);
                m.sdk = u32_at(c, o + 16);
            }
            _ => {}
        }
        o += size;
    }
    Ok(m)
}

fn segment(d: &[u8], o: usize) -> Option<Seg> {
    let nsects = u32_at(d, o + 64)? as usize;
    let mut sections = Vec::with_capacity(nsects);
    for s in 0..nsects {
        let so = o + 72 + s * 80;
        sections.push(Section {
            sectname: name16(d, so)?,
            segname: name16(d, so + 16)?,
            addr: u64_at(d, so + 32)?,
            size: u64_at(d, so + 40)?,
            offset: u32_at(d, so + 48)?,
            flags: u32_at(d, so + 64)?,
        });
    }
    Some(Seg {
        name: name16(d, o + 8)?,
        vmaddr: u64_at(d, o + 24)?,
        vmsize: u64_at(d, o + 32)?,
        fileoff: u64_at(d, o + 40)?,
        filesize: u64_at(d, o + 48)?,
        maxprot: u32_at(d, o + 56)?,
        initprot: u32_at(d, o + 60)?,
        sections,
    })
}

/// The pc of an `LC_UNIXTHREAD`'s `ARM_THREAD_STATE64`.
fn thread_pc(d: &[u8], o: usize, size: usize) -> Option<u64> {
    let mut p = o + 8;
    while p + 8 <= o + size {
        let flavor = u32_at(d, p)?;
        let count = u32_at(d, p + 4)? as usize;
        if flavor == ARM_THREAD_STATE64 {
            return u64_at(d, p + 8 + THREAD_STATE_PC);
        }
        p += 8 + count * 4;
    }
    None
}

/// An unsigned LEB128 at `*o`, advancing it.
fn uleb(d: &[u8], o: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    let mut shift = 0;
    loop {
        let b = *d.get(*o)?;
        *o += 1;
        if shift < 64 {
            v |= u64::from(b & 0x7f) << shift;
        }
        if b & 0x80 == 0 {
            return Some(v);
        }
        shift += 7;
    }
}

impl MachO {
    /// The segment that holds the file's header (`__TEXT`): its address is
    /// the image's unslid base.
    pub fn base(&self) -> u64 {
        self.segments.iter().find(|s| s.fileoff == 0 && s.filesize > 0).map_or(0, |s| s.vmaddr)
    }

    /// The span the image's mapped segments cover, unslid: `[start, end)`.
    pub fn span(&self) -> (u64, u64) {
        let mapped = self.segments.iter().filter(|s| !s.is_guard());
        let start = mapped.clone().map(|s| s.vmaddr).min().unwrap_or(0);
        let end = mapped.map(|s| s.vmaddr + s.vmsize).max().unwrap_or(0);
        (start, end)
    }

    /// A section by segment and name, unslid.
    pub fn section(&self, seg: &str, sect: &str) -> Option<&Section> {
        self.segments.iter().flat_map(|s| &s.sections).find(|s| s.segname == seg && s.sectname == sect)
    }

    pub fn is_pie(&self) -> bool {
        self.flags & MH_PIE != 0 || self.filetype != MH_EXECUTE
    }

    /// The entry point, unslid.
    pub fn entry_pc(&self) -> Option<u64> {
        match self.entry? {
            Entry::Main { entryoff, .. } => Some(self.base() + entryoff),
            Entry::Thread { pc } => Some(pc),
        }
    }

    /// `LC_FUNCTION_STARTS`, unslid: the address of every function the
    /// linker saw, decoded from its ULEB128 deltas from the image base.
    pub fn function_starts(&self, d: &[u8]) -> Vec<u64> {
        let Some((off, size)) = self.function_starts else { return Vec::new() };
        let (mut o, end) = (off as usize, (off as usize).saturating_add(size as usize).min(d.len()));
        let mut addr = self.base();
        let mut out = Vec::new();
        while o < end {
            match uleb(&d[..end], &mut o) {
                Some(0) | None => break,
                Some(delta) => {
                    addr = addr.wrapping_add(delta);
                    out.push(addr);
                }
            }
        }
        out
    }

    /// The symbol table's defined, non-debugging symbols that point into an
    /// instruction section, unslid.
    pub fn functions(&self, d: &[u8]) -> Vec<Symbol> {
        let Some(st) = &self.symtab else { return Vec::new() };
        let code: Vec<&Section> = self.segments.iter().flat_map(|s| &s.sections).filter(|s| s.has_instructions()).collect();
        let strtab_end = (st.stroff as usize).saturating_add(st.strsize as usize);
        let mut out = Vec::new();
        for i in 0..st.nsyms as usize {
            let e = st.symoff as usize + i * 16;
            let (Some(strx), Some(&n_type), Some(value)) = (u32_at(d, e), d.get(e + 4), u64_at(d, e + 8)) else { break };
            if n_type & N_STAB != 0 || n_type & N_TYPE != N_SECT {
                continue;
            }
            if !code.iter().any(|s| value >= s.addr && value < s.addr + s.size) {
                continue;
            }
            let Some(name) = cstr(d, st.stroff as usize + strx as usize, strtab_end) else { continue };
            out.push(Symbol { name, value, size: 0, ifunc: false });
        }
        out
    }

    /// The image as gex places it: every mapped segment moved by `slide`.
    pub fn to_image(&self, d: &[u8], slide: u64) -> Result<Image, LoadError> {
        let entry = self.entry_pc().map_or(0, |pc| pc.wrapping_add(slide));
        let mut img = headers_only(0, 0, 0, entry);
        img.bias = slide;
        img.pie = self.is_pie();
        img.interp = self.dylinker.clone();
        img.soname = self.install_name.clone();
        img.needed = self.dylibs.clone();
        let (mut text_lo, mut text_hi, mut brk) = (u64::MAX, 0u64, 0u64);
        for s in self.segments.iter().filter(|s| !s.is_guard() && s.vmsize > 0) {
            let lo = s.fileoff as usize;
            let hi = lo
                .checked_add(s.filesize as usize)
                .filter(|&h| h <= d.len())
                .ok_or_else(|| bad(format!("segment {} runs past the end of the file", s.name)))?;
            let mut bytes = d[lo..hi].to_vec();
            // A zero-fill section inside the file-backed range still reads
            // as zeros (a static image's __bss can sit there).
            for sec in s.sections.iter().filter(|x| x.zero_fill()) {
                let (a, b) = (sec.addr.saturating_sub(s.vmaddr) as usize, (sec.addr + sec.size).saturating_sub(s.vmaddr) as usize);
                if let Some(z) = bytes.get_mut(a..b.min(hi - lo)) {
                    z.fill(0);
                }
            }
            let vaddr = s.vmaddr.wrapping_add(slide);
            let exec = s.initprot & PROT_EXEC != 0;
            img.segments.push(Segment {
                vaddr,
                bytes,
                mem_size: s.vmsize,
                readable: s.initprot & PROT_READ != 0,
                writable: s.initprot & PROT_WRITE != 0,
                executable: exec,
            });
            if exec {
                text_lo = text_lo.min(vaddr);
                text_hi = text_hi.max(vaddr + s.vmsize);
            }
            brk = brk.max(vaddr + s.vmsize);
        }
        img.text_range = if text_hi > 0 { (text_lo, text_hi) } else { (0, 0) };
        img.brk = brk;
        img.code = self
            .segments
            .iter()
            .flat_map(|s| &s.sections)
            .filter(|s| s.has_instructions() && s.size > 0)
            .map(|s| (s.addr.wrapping_add(slide), s.addr.wrapping_add(slide) + s.size))
            .collect();
        let mut symbols = self.functions(d);
        let named: std::collections::BTreeSet<u64> = symbols.iter().map(|s| s.value).collect();
        // Function starts cover what a stripped symbol table no longer does.
        for a in self.function_starts(d) {
            if !named.contains(&a) {
                symbols.push(Symbol { name: format!("func_{a:x}"), value: a, size: 0, ifunc: false });
            }
        }
        for s in &mut symbols {
            s.value = s.value.wrapping_add(slide);
        }
        symbols.sort_by_key(|s| s.value);
        img.symbols = symbols;
        Ok(img)
    }
}

/// Load a Mach-O for running: a position-independent image moved so its
/// base is `pie_base`, anything else where it was linked.
pub fn load(d: &[u8], pie_base: u64) -> Result<(MachO, Image), LoadError> {
    let m = parse(d)?;
    if m.entry.is_none() && m.filetype == MH_EXECUTE {
        return Err(bad("an executable with neither LC_MAIN nor LC_UNIXTHREAD"));
    }
    let slide = if m.is_pie() { pie_base.wrapping_sub(m.span().0) } else { 0 };
    let img = m.to_image(d, slide)?;
    Ok((m, img))
}

/// Darwin's initial stack, laid out the way XNU's exec leaves it: for a
/// program dyld starts, the main executable's header address first (dyld
/// takes it from the stack), then `argc`, the argument, environment and
/// `apple[]` vectors, each ending in NULL, and their strings above them.
/// `sp` is 16-byte aligned and points at the first word.
pub fn build_stack(stack_top: u64, exe_header: Option<u64>, args: &[String], env: &[String], apple: &[String]) -> StackLayout {
    // Strings at the top, then the vectors below them.
    let strings: Vec<&String> = args.iter().chain(env).chain(apple).collect();
    let text: usize = strings.iter().map(|s| s.len() + 1).sum();
    let strings_low = (stack_top - text as u64) & !0xf;
    let mut addrs = Vec::with_capacity(strings.len());
    let mut a = strings_low;
    for s in &strings {
        addrs.push(a);
        a += s.len() as u64 + 1;
    }
    let (argv, rest) = addrs.split_at(args.len());
    let (envp, applev) = rest.split_at(env.len());
    let mut words: Vec<u64> = Vec::new();
    words.extend(exe_header);
    words.push(args.len() as u64);
    words.extend(argv);
    words.push(0);
    words.extend(envp);
    words.push(0);
    words.extend(applev);
    words.push(0);
    let sp = (strings_low - words.len() as u64 * 8) & !0xf;
    let mut bytes = vec![0u8; (stack_top - sp) as usize];
    for (i, w) in words.iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
    }
    let mut o = (strings_low - sp) as usize;
    for s in &strings {
        bytes[o..o + s.len()].copy_from_slice(s.as_bytes());
        o += s.len() + 1;
    }
    StackLayout { sp, low: sp, bytes }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put32(v: &mut Vec<u8>, x: u32) {
        v.extend_from_slice(&x.to_le_bytes());
    }
    fn put64(v: &mut Vec<u8>, x: u64) {
        v.extend_from_slice(&x.to_le_bytes());
    }
    fn name(v: &mut Vec<u8>, s: &str) {
        let mut b = [0u8; 16];
        b[..s.len()].copy_from_slice(s.as_bytes());
        v.extend_from_slice(&b);
    }

    /// A static executable: __PAGEZERO, a __TEXT with one __text section at
    /// file offset 0x400, and an LC_UNIXTHREAD.
    fn tiny(flags: u32) -> Vec<u8> {
        let mut cmds = Vec::new();
        // __PAGEZERO
        put32(&mut cmds, LC_SEGMENT_64);
        put32(&mut cmds, 72);
        name(&mut cmds, "__PAGEZERO");
        for x in [0u64, 0x1_0000_0000, 0, 0] {
            put64(&mut cmds, x);
        }
        for x in [0u32, 0, 0, 0] {
            put32(&mut cmds, x);
        }
        // __TEXT with __text
        put32(&mut cmds, LC_SEGMENT_64);
        put32(&mut cmds, 72 + 80);
        name(&mut cmds, "__TEXT");
        for x in [0x1_0000_0000u64, 0x4000, 0, 0x800] {
            put64(&mut cmds, x);
        }
        for x in [5u32, 5, 1, 0] {
            put32(&mut cmds, x);
        }
        name(&mut cmds, "__text");
        name(&mut cmds, "__TEXT");
        put64(&mut cmds, 0x1_0000_0400);
        put64(&mut cmds, 8);
        for x in [0x400u32, 2, 0, 0, S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS, 0, 0, 0] {
            put32(&mut cmds, x);
        }
        // LC_UNIXTHREAD, ARM_THREAD_STATE64: 34 registers then cpsr and pad.
        put32(&mut cmds, LC_UNIXTHREAD);
        put32(&mut cmds, 16 + 68 * 4);
        put32(&mut cmds, ARM_THREAD_STATE64);
        put32(&mut cmds, 68);
        for r in 0..34u64 {
            put64(&mut cmds, if r == 32 { 0x1_0000_0400 } else { 0 });
        }
        put32(&mut cmds, 0);
        put32(&mut cmds, 0);
        let mut f = Vec::new();
        for x in [MH_MAGIC_64, CPU_TYPE_ARM64, 0, MH_EXECUTE, 3, cmds.len() as u32, flags, 0] {
            put32(&mut f, x);
        }
        f.extend_from_slice(&cmds);
        f.resize(0x400, 0);
        // nop; ret
        f.extend_from_slice(&[0x1f, 0x20, 0x03, 0xd5, 0xc0, 0x03, 0x5f, 0xd6]);
        f.resize(0x800, 0);
        f
    }

    #[test]
    fn parses_a_static_executable() {
        let f = tiny(0);
        let m = parse(&f).unwrap();
        assert_eq!(m.filetype, MH_EXECUTE);
        assert_eq!(m.segments.len(), 2);
        assert!(m.segments[0].is_guard());
        assert_eq!(m.entry, Some(Entry::Thread { pc: 0x1_0000_0400 }));
        assert_eq!(m.base(), 0x1_0000_0000);
        assert!(!m.is_pie());
    }

    #[test]
    fn a_static_image_stays_where_it_was_linked() {
        let f = tiny(0);
        let (_, img) = load(&f, 0x2_0000_0000).unwrap();
        assert_eq!(img.entry, 0x1_0000_0400);
        assert_eq!(img.segments.len(), 1, "__PAGEZERO is not mapped");
        assert_eq!(img.segments[0].vaddr, 0x1_0000_0000);
        assert!(img.segments[0].executable);
        assert_eq!(img.code, vec![(0x1_0000_0400, 0x1_0000_0408)]);
        assert_eq!(&img.segments[0].bytes[0x400..0x408], &[0x1f, 0x20, 0x03, 0xd5, 0xc0, 0x03, 0x5f, 0xd6]);
    }

    #[test]
    fn a_pie_image_slides_to_the_base() {
        let f = tiny(MH_PIE);
        let (_, img) = load(&f, 0x2_0000_0000).unwrap();
        assert_eq!(img.segments[0].vaddr, 0x2_0000_0000);
        assert_eq!(img.entry, 0x2_0000_0400);
        assert_eq!(img.code, vec![(0x2_0000_0400, 0x2_0000_0408)]);
    }

    #[test]
    fn function_starts_decode_from_the_base() {
        let mut f = tiny(0);
        let off = f.len() as u32;
        // Two functions: base+0x400, then 0x20 further; a zero ends it.
        f.extend_from_slice(&[0x80, 0x08, 0x20, 0x00]);
        let mut m = parse(&f).unwrap();
        m.function_starts = Some((off, 4));
        assert_eq!(m.function_starts(&f), vec![0x1_0000_0400, 0x1_0000_0420]);
    }

    #[test]
    fn the_layout_clears_the_tables_and_the_shared_region() {
        assert!(SHARED_REGION_BASE >= gex_abi::HIGH_TABLES_END);
        assert!(PIE_BASE > SHARED_REGION_BASE + 0xcc5f_0000);
        assert!(PIE_BASE < gex_abi::LIMIT64);
    }

    #[test]
    fn the_stack_has_the_header_then_argc_and_the_vectors() {
        let top = 0x0580_0000;
        let args = ["/bin/hello".to_string(), "x".to_string()];
        let env = ["HOME=/var/mobile".to_string()];
        let apple = ["executable_path=/bin/hello".to_string()];
        let st = build_stack(top, Some(0x2_8000_0000), &args, &env, &apple);
        assert_eq!(st.sp % 16, 0);
        assert_eq!(st.low + st.bytes.len() as u64, top);
        let w = |i: usize| u64::from_le_bytes(st.bytes[i * 8..i * 8 + 8].try_into().unwrap());
        let s = |a: u64| {
            let o = (a - st.low) as usize;
            let n = st.bytes[o..].iter().position(|&c| c == 0).unwrap();
            String::from_utf8(st.bytes[o..o + n].to_vec()).unwrap()
        };
        assert_eq!(w(0), 0x2_8000_0000);
        assert_eq!(w(1), 2);
        assert_eq!(s(w(2)), "/bin/hello");
        assert_eq!(s(w(3)), "x");
        assert_eq!(w(4), 0);
        assert_eq!(s(w(5)), "HOME=/var/mobile");
        assert_eq!(w(6), 0);
        assert_eq!(s(w(7)), "executable_path=/bin/hello");
        assert_eq!(w(8), 0);
    }

    #[test]
    fn a_static_program_starts_at_argc() {
        let st = build_stack(0x0580_0000, None, &["a".to_string()], &[], &[]);
        assert_eq!(u64::from_le_bytes(st.bytes[0..8].try_into().unwrap()), 1);
    }

    #[test]
    fn rejects_other_formats() {
        assert!(!is_macho(b"\x7fELF\x02\x01\x01\0"));
        assert!(matches!(parse(&[0u8; 8]), Err(LoadError::TooShort)));
        let mut f = tiny(0);
        f[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes());
        assert!(matches!(parse(&f), Err(LoadError::MachO(_))));
    }
}
