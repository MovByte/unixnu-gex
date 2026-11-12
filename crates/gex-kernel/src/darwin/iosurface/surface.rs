//! A surface's description as `IOSurface::init` reads it from its creation
//! properties (0xfffffff005b99720 for the object, 0xfffffff005b99a6c for
//! the properties, in the 21H461 kernelcache): its flags, its pixel
//! geometry, its planes, and the size of its memory. Every failure of init
//! reaches the creator as kIOReturnBadArgument (the root releases the
//! object, 0xfffffff005baaadc, and the user client answers 0xe00002c2,
//! 0xfffffff005baf5fc); the message says which check refused it, as the
//! kext's IOLog does.

use super::super::osserialize::{Graph, Id, Obj};

/// `+0x3b0`: the surface's flag word, each bit named by the key that sets
/// it.
pub mod flag {
    pub const GLOBAL: u32 = 1 << 1;
    pub const PURGE_WHEN_NOT_IN_USE: u32 = 1 << 6;
    pub const RESET_DEFAULT_ATTACHMENTS_WHEN_NOT_IN_USE: u32 = 1 << 7;
    /// Set once init succeeds (0xfffffff005b99a20).
    pub const INITIALIZED: u32 = 1 << 8;
    pub const BUFFER_TILE_MODE: u32 = 1 << 9;
    pub const PREALLOC_PAGES: u32 = 1 << 11;
    pub const FENCE_ALLOW_TEARING: u32 = 1 << 13;
    pub const PREFETCH_PAGES: u32 = 1 << 14;
    /// Purgeable: `IOSurfaceNonPurgeable` clears it.
    pub const PURGEABLE: u32 = 1 << 15;
    pub const PIXEL_SIZE_CASTING_ALLOWED: u32 = 1 << 16;
    pub const USE_RESERVE: u32 = 1 << 17;
    pub const SYS_MEM_ONLY: u32 = 1 << 18;
    pub const PRIVATE: u32 = 1 << 19;
    pub const DISPLAYABLE: u32 = 1 << 20;
    pub const PROHIBIT_USE_COUNT: u32 = 1 << 21;
    pub const DISABLE_MAPPER_FLUSH: u32 = 1 << 23;
    pub const HOST_ONLY: u32 = 1 << 24;
    /// What the object starts with (0xfffffff005b998d0, 0x...9992c,
    /// 0x...99974, 0x...99988).
    pub const INITIAL: u32 = PREALLOC_PAGES | PURGEABLE | PIXEL_SIZE_CASTING_ALLOWED | SYS_MEM_ONLY;
}

/// The most planes a surface has (0xfffffff005b99e68).
pub const MAX_PLANES: usize = 20;

/// A plane's record (0x38 bytes at `+0x180`, zeroed per plane,
/// 0xfffffff005b99f98).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Plane {
    pub width: u64,
    pub height: u64,
    pub base: u64,
    pub offset: u64,
    pub bytes_per_row: u64,
    pub size: u64,
    pub bytes_per_element: u16,
    pub element_width: u8,
    pub element_height: u8,
    pub address_format: u8,
}

/// A plane's component description (0x18 bytes at `+0x2f8`):
/// parseAdditionalPlaneInfo's arrays, each of `count` entries.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Components {
    pub count: u8,
    pub bit_depths: [u8; 4],
    pub bit_offsets: [u8; 4],
    pub names: [u8; 4],
    pub types: [u8; 4],
    pub ranges: [u8; 4],
}

/// A plane's extended pixels (0x20 bytes at `+0x330`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Extended {
    pub right: u32,
    pub bottom: u32,
    pub left: u32,
    pub top: u32,
}

/// What the root lends init: its alignment masks (`+0xb0` for rows,
/// `+0xac` for plane offsets and sizes), the largest allocation (`+0x1a8`)
/// and its `iosurface_debug` flags (`+0x1b4`).
#[derive(Clone, Copy, Debug)]
pub struct RootParams {
    pub row_mask: u64,
    pub offset_mask: u64,
    pub max_alloc: u64,
    pub debug: u32,
    pub page_size: u64,
}

/// Why init refused: the check (`BadArgument`, what the creator sees), or
/// a feature this kernel does not have (`Unimplemented`, reported).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InitError {
    BadArgument(String),
    Unimplemented(String),
}

fn bad<T>(why: impl Into<String>) -> Result<T, InitError> {
    Err(InitError::BadArgument(why.into()))
}

/// A surface's description.
#[derive(Clone, Debug, Default)]
pub struct Desc {
    pub flags: u32,
    pub width: u64,
    pub height: u64,
    pub bytes_per_row: u64,
    pub bytes_per_element: u16,
    pub element_width: u8,
    pub element_height: u8,
    pub offset: u64,
    pub pixel_format: u32,
    pub alloc_size: u64,
    pub cache_mode: u32,
    pub planes: Vec<Plane>,
    pub components: Vec<Components>,
    pub extended: Vec<Extended>,
    pub subsampling: u32,
    pub protection: u64,
    pub tile_format: u32,
    pub map_cache_attribute: u32,
    pub direction: u32,
    pub slice_count: u32,
    pub allocate_from_superbuffer: u32,
    /// `IOSurfaceAddress` and `IOSurfaceAddressRanges`: client memory to
    /// wrap.
    pub address: Option<u64>,
    pub address_ranges: Option<Vec<u8>>,
    /// The memory regions named (`IOSurfaceMemoryRegion`).
    pub memory_regions: Vec<Vec<u8>>,
    /// `IOSurfaceDefaultAttachments` and `IOSurfaceDefaultBulkAttachments`
    /// (0x70 bytes).
    pub default_attachments: Option<Id>,
    pub default_bulk: Option<[u8; 0x70]>,
    /// The shared record's flags (`+0x178`): +0x14 tile mode, +0x2c pixel
    /// size casting, +0x2d displayable, +0x2e system memory only.
    pub shared_tile_mode: bool,
    pub shared_pixel_size_casting: bool,
    pub shared_displayable: bool,
    pub shared_sys_mem_only: bool,
    /// The shared record's bulk attachments (+0x30..+0xa0, 0x70 bytes).
    pub shared_bulk: Vec<u8>,
}

/// The property readers init uses, over the creation dictionary.
struct Props<'a> {
    g: &'a Graph,
    d: Id,
}

impl Props<'_> {
    fn obj(&self, key: &str) -> Option<&Obj> {
        self.g.lookup(self.d, key.as_bytes()).map(|i| self.g.get(i))
    }

    /// 0xfffffff005b9d030: an OSBoolean's value; `None` when absent or not
    /// a boolean.
    fn boolean(&self, key: &str) -> Option<bool> {
        match self.obj(key) {
            Some(Obj::Bool(b)) => Some(*b),
            _ => None,
        }
    }

    /// 0xfffffff005b9d114: an OSNumber's unsigned64BitValue.
    fn u64(&self, key: &str) -> Option<u64> {
        let i = self.g.lookup(self.d, key.as_bytes())?;
        self.g.u64_value(i)
    }

    /// 0xfffffff005b9d08c: a number that fits 32 bits; absent (or not a
    /// number) leaves the field, more is refused ("%s exceeds maximum
    /// value").
    fn u32(&self, key: &str) -> Result<Option<u32>, InitError> {
        match self.u64(key) {
            None => Ok(None),
            Some(v) if v > u64::from(u32::MAX) => bad(format!("IOSurface: {key} exceeds maximum value")),
            Some(v) => Ok(Some(v as u32)),
        }
    }

    /// 0xfffffff005b9d170: the same for 8 bits.
    fn u8(&self, key: &str) -> Result<Option<u8>, InitError> {
        match self.u64(key) {
            None => Ok(None),
            Some(v) if v > 0xff => bad(format!("IOSurface: {key} exceeds maximum value")),
            Some(v) => Ok(Some(v as u8)),
        }
    }

    fn array(&self, key: &str) -> Option<&Vec<Id>> {
        match self.obj(key) {
            Some(Obj::Array(v)) => Some(v),
            _ => None,
        }
    }
}

/// 0xfffffff005ba5364: one component array into the record: absent is
/// fine; 1 to 4 numbers, as many as any array before it; each a byte (a
/// value past one fails, an entry that is no number stays 0).
fn component_array(p: &Props<'_>, key: &str, c: &mut Components, field: fn(&mut Components) -> &mut [u8; 4]) -> Result<(), InitError> {
    let Some(a) = p.array(key) else { return Ok(()) };
    if a.len() > 4 {
        return bad(format!("IOSurface: {key} component count is too large."));
    }
    if a.is_empty() {
        return bad(format!("IOSurface: {key} component count is too small."));
    }
    if c.count != 0 && usize::from(c.count) != a.len() {
        return bad(format!("IOSurface: {key} component count mismatch."));
    }
    c.count = a.len() as u8;
    for (i, &e) in a.iter().enumerate() {
        if let Some(v) = p.g.u64_value(e) {
            if v > 0xff {
                return bad(format!("IOSurface: {key} component {i} exceeds a byte"));
            }
            field(c)[i] = v as u8;
        }
    }
    Ok(())
}

/// parseAdditionalPlaneInfo (0xfffffff005b9d1d8).
fn parse_components(p: &Props<'_>) -> Result<Components, InitError> {
    let mut c = Components::default();
    component_array(p, "IOSurfacePlaneComponentBitDepths", &mut c, |c| &mut c.bit_depths)?;
    component_array(p, "IOSurfacePlaneComponentBitOffsets", &mut c, |c| &mut c.bit_offsets)?;
    component_array(p, "IOSurfacePlaneComponentNames", &mut c, |c| &mut c.names)?;
    component_array(p, "IOSurfacePlaneComponentTypes", &mut c, |c| &mut c.types)?;
    component_array(p, "IOSurfacePlaneComponentRanges", &mut c, |c| &mut c.ranges)?;
    Ok(c)
}

/// The bytes per element a legacy creator's pixel format implies when it
/// gives none (0xfffffff005b9b15c).
fn legacy_bytes_per_element(format: u32) -> u16 {
    match &format.to_be_bytes() {
        b"4444" | b"5551" | b"L555" | b"L565" | b"S555" | b"S565" | b"s551" => 2,
        b"BGRA" | b"RGBA" | b"S32b" => 4,
        b"RGhA" => 8,
        b"RGfA" => 16,
        _ => 1,
    }
}

/// `(v + mask) & !mask`, or none when it wraps.
fn align(v: u64, mask: u64) -> Option<u64> {
    v.checked_add(mask).map(|x| x & !mask)
}

fn set(flags: &mut u32, bit: u32, on: bool) {
    if on { *flags |= bit } else { *flags &= !bit }
}

/// `IOSurface::init(props)` over a creation dictionary already holding
/// `IOSurfacePixelSizeCastingAllowed` (the outer init adds it), for a
/// surface whose parent (a child surface's) is `parent`.
pub fn init(g: &Graph, props: Id, parent: Option<&Desc>, root: &RootParams) -> Result<Desc, InitError> {
    let p = Props { g, d: props };
    let mut s = Desc {
        flags: flag::INITIAL,
        bytes_per_element: 1,
        element_width: 1,
        element_height: 1,
        direction: 3,
        shared_pixel_size_casting: true,
        shared_sys_mem_only: true,
        ..Default::default()
    };
    // 1a: flags (0xfffffff005b99aa0..0x...99cd0).
    if let Some(b) = p.boolean("IOSurfaceDisableMapperFlush") {
        set(&mut s.flags, flag::DISABLE_MAPPER_FLUSH, b);
    }
    let legacy = p.boolean("IOSurfaceCoreSurfaceLegacy") == Some(true);
    if let Some(b) = p.boolean("IOSurfacePreallocPages") {
        set(&mut s.flags, flag::PREALLOC_PAGES, b);
    }
    if let Some(b) = p.boolean("IOSurfacePrefetchPages") {
        set(&mut s.flags, flag::PREFETCH_PAGES, b);
    }
    if let Some(b) = p.boolean("IOSurfaceHostOnly") {
        set(&mut s.flags, flag::HOST_ONLY, b);
    }
    if s.flags & flag::PREFETCH_PAGES != 0 {
        s.flags &= !flag::PREALLOC_PAGES;
    }
    if let Some(b) = p.boolean("IOSurfaceUseReserve") {
        set(&mut s.flags, flag::USE_RESERVE, b);
    }
    if let Some(b) = p.boolean("IOSurfaceNonPurgeable") {
        set(&mut s.flags, flag::PURGEABLE, !b);
    }
    if let Some(b) = p.boolean("IsDisplayable") {
        set(&mut s.flags, flag::DISPLAYABLE, b);
    }
    s.shared_displayable = s.flags & flag::DISPLAYABLE != 0;
    if let Some(b) = p.boolean("IOSurfaceSysMemOnly") {
        set(&mut s.flags, flag::SYS_MEM_ONLY, b);
    }
    s.shared_sys_mem_only = s.flags & flag::SYS_MEM_ONLY != 0;
    if let Some(v) = p.u32("IOSurfaceSubsampling")? {
        s.subsampling = v;
    }
    if let Some(b) = p.boolean("IOSurfaceProhibitUseCount") {
        set(&mut s.flags, flag::PROHIBIT_USE_COUNT, b);
    }

    // The planes (0xfffffff005b99cdc), else one record of each kind read
    // from the top level (0xfffffff005b99d70).
    let plane_info: Option<Vec<Id>> = p.array("IOSurfacePlaneInfo").cloned();
    match &plane_info {
        Some(a) if a.is_empty() => return bad("IOSurface: kIOSurfacePlaneInfo array must not be empty."),
        Some(a) if a.len() > MAX_PLANES => return bad(format!("IOSurface: maximum plane count of {MAX_PLANES} exceeded.")),
        Some(_) => {}
        None => {
            match parse_components(&p) {
                Ok(c) => s.components.push(c),
                Err(_) => return bad("IOSurface: parseAdditionalPlaneInfo failed."),
            }
            // Their failures are ignored here, and they shape no geometry.
            let get = |k: &str| p.u32(k).ok().flatten().unwrap_or(0);
            s.extended.push(Extended { left: get("IOSurfacePlaneExtendedPixelsOnLeft"), right: get("IOSurfacePlaneExtendedPixelsOnRight"), bottom: get("IOSurfacePlaneExtendedPixelsOnBottom"), top: get("IOSurfacePlaneExtendedPixelsOnTop") });
        }
    }
    if let Some(planes) = &plane_info {
        for (i, &pd) in planes.iter().enumerate() {
            plane(g, pd, i, &mut s, parent, root)?;
        }
    }

    // 1b: protection (0xfffffff005b9af48).
    match parent {
        Some(par) => {
            if par.protection != 0 && root.debug & (1 << 13) == 0 {
                return bad("Cannot create children of protected surfaces");
            }
            s.protection = par.protection & 0xffff_ffff;
        }
        None => {
            let stats = p.boolean("IOSurfaceEnableStatistics") == Some(true);
            let mut v = p.u64("IOSurfaceProtectionOptions").unwrap_or(0);
            if v >= 0x10 {
                return bad(format!("Unsupported protection bits set: {v:016x}"));
            }
            if !(stats || v == 0) && root.debug & (1 << 16) != 0 && root.debug & (1 << 17) == 0 {
                v |= 8;
            }
            s.protection = v;
        }
    }

    // 1c (0xfffffff005b9b004..).
    if let Ok(Some(v)) = p.u32("IOSurfaceBufferTileFormat") {
        s.tile_format = v;
    }
    if let Some(b) = p.boolean("IOFenceAllowTearing") {
        set(&mut s.flags, flag::FENCE_ALLOW_TEARING, b);
    }
    if let Some(b) = p.boolean("IOSurfaceBufferTileMode") {
        set(&mut s.flags, flag::BUFFER_TILE_MODE, b);
    }
    s.shared_tile_mode = s.flags & flag::BUFFER_TILE_MODE != 0;
    if let Some(b) = p.boolean("IOSurfacePixelSizeCastingAllowed") {
        set(&mut s.flags, flag::PIXEL_SIZE_CASTING_ALLOWED, b);
    }
    s.shared_pixel_size_casting = s.flags & flag::PIXEL_SIZE_CASTING_ALLOWED != 0;
    if let Some(v) = p.u64("IOSurfacePixelFormat") {
        s.pixel_format = v as u32;
    }
    if let Some(v) = p.u64("IOSurfaceBitsPerBlock") {
        if v >= 0x10000 {
            return bad("IOSurface: IOSurfaceBitsPerBlock out of range");
        }
        s.bytes_per_element = ((v >> 3) & 0x1fff) as u16;
    }
    match p.u64("IOSurfaceBytesPerElement") {
        Some(v) if v >= 0x10000 => return bad("IOSurface: IOSurfaceBytesPerElement out of range"),
        Some(v) => s.bytes_per_element = v as u16,
        None if legacy => s.bytes_per_element = legacy_bytes_per_element(s.pixel_format),
        None => {}
    }
    let width = p.u64("IOSurfaceWidth");
    let height = p.u64("IOSurfaceHeight");
    if (width.is_none() || height.is_none()) && plane_info.is_some() {
        return bad("IOSurface: Planar surfaces must specify a valid buffer width and height.");
    }
    s.width = width.unwrap_or(0);
    s.height = height.unwrap_or(0);
    if let Some(v) = p.u64("IOSurfaceElementWidth") {
        if v > 0xff {
            return bad("IOSurface: IOSurfaceElementWidth out of range");
        }
        s.element_width = v as u8;
    }
    if let Some(v) = p.u64("IOSurfaceElementHeight") {
        if v > 0xff {
            return bad("IOSurface: IOSurfaceElementHeight out of range");
        }
        s.element_height = v as u8;
    }

    // Section 2: the buffer's own geometry, for every surface.
    if s.bytes_per_element == 0 {
        return bad("IOSurface: buffer bytes per element is zero.");
    }
    if s.element_width == 0 {
        return bad("IOSurface: buffer element width is zero.");
    }
    if s.element_height == 0 {
        return bad("IOSurface: buffer element height is zero.");
    }
    let (ew, eh) = (u64::from(s.element_width), u64::from(s.element_height));
    let Some(w_el) = s.width.checked_add(ew - 1).map(|w| w / ew) else { return bad("IOSurface: buffer width overflow") };
    let Some(min_bpr) = w_el.checked_mul(u64::from(s.bytes_per_element)) else { return bad("IOSurface: buffer required width in bytes overflow") };
    match p.u64("IOSurfaceBytesPerRow") {
        Some(v) => {
            if v < min_bpr {
                return bad("IOSurface: buffer bytes per row value is too small");
            }
            s.bytes_per_row = v;
        }
        None => match align(min_bpr, root.row_mask) {
            Some(v) => s.bytes_per_row = v,
            None => return bad("IOSurface: bytesPerRow calculation overflow"),
        },
    }
    s.offset = p.u64("IOSurfaceOffset").unwrap_or(0);

    // The allocation's size (0xfffffff005b9b664, 0x...9b7fc, 0x...9b91c,
    // 0x...9bbf8, 0x...9bc20).
    s.alloc_size = if let Some(par) = parent {
        par.alloc_size
    } else if let Some(v) = p.u64("IOSurfaceAllocSize") {
        v
    } else if let Some(last) = s.planes.last() {
        let Some(end) = last.base.checked_add(last.size) else { return bad("IOSurface: required planar allocation size overflow") };
        match align(end, root.offset_mask) {
            Some(v) => v,
            None => return bad("IOSurface: aligned allocation size overflow"),
        }
    } else {
        let Some(v) = s.bytes_per_row.checked_mul(s.height).and_then(|v| v.checked_add(s.offset)) else { return bad("IOSurface: required allocation size overflow") };
        match align(v, root.offset_mask) {
            Some(v) => v,
            None => return bad("IOSurface: aligned allocation size overflow"),
        }
    };
    if align(s.alloc_size, root.page_size - 1).map_or(true, |r| r < s.alloc_size) {
        return bad("IOSurface: allocation size overflow");
    }
    if let Some(par) = parent {
        if par.alloc_size < s.alloc_size {
            return bad("IOSurface: child surfaces must specify an allocation size less than or equal to the parent surface size");
        }
    }
    if s.alloc_size > root.max_alloc {
        return bad(format!("IOSurface: allocation size of {} exceeds limit of {} bytes", s.alloc_size, root.max_alloc));
    }
    if s.planes.is_empty() {
        // 0xfffffff005b9bc50.
        let Some(h_el) = s.height.checked_add(eh - 1).map(|h| h / eh) else { return bad("IOSurface: aligned height calculation overflow") };
        let Some(lines) = s.bytes_per_row.checked_mul(h_el.wrapping_sub(1)) else { return bad("IOSurface: required bytes per line overflow") };
        let Some(image) = lines.checked_add(w_el * u64::from(s.bytes_per_element)) else { return bad("IOSurface: required image bytes overflow") };
        let Some(required) = s.offset.checked_add(image) else { return bad("IOSurface: required allocation size overflow") };
        if s.alloc_size < required {
            return bad(format!("IOSurface: buffer allocation size is too small to cover valid image area: fAllocSize={}, requiredSizeInBytes={required}", s.alloc_size));
        }
    } else {
        // 0xfffffff005b9b9f4.
        for (i, pl) in s.planes.iter().enumerate() {
            let Some(limit) = pl.base.checked_add(pl.size) else { return bad("IOSurface: plane limit calculation overflow") };
            if s.alloc_size < limit {
                return bad(format!("IOSurface: buffer allocation size is too small to cover valid image area of plane {i}: fAllocSize={}, planeLimit={limit}", s.alloc_size));
            }
        }
    }

    if let Some(v) = p.u64("IOSurfaceDirection") {
        s.direction = v as u32;
        if s.direction & !1 != 2 {
            return bad("IOSurface: client direction not InOut or Out");
        }
    }
    if let Some(v) = p.u64("IOSurfaceAddressOffset") {
        if u64::from(v as u32) >= root.page_size {
            return bad("IOSurface: fClientAlignedOffset >= page_size");
        }
    }
    if let Some(o) = p.obj("IOSurfaceAddressRanges") {
        if let Obj::Data(d) = o {
            if d.len() < 16 || d.len() % 16 != 0 {
                return bad("IOSurface: address ranges size not multiple of IOAddressRange");
            }
            if s.protection != 0 {
                return bad("IOSurface: client address ranges for a protected surface");
            }
            s.address_ranges = Some(d.clone());
        }
    }
    if let Some(v) = p.u64("IOSurfaceAddress") {
        if s.protection != 0 {
            return bad("IOSurface: a client address for a protected surface");
        }
        s.address = Some(v);
    }
    if let Some(v) = p.u64("IOSurfaceCacheMode") {
        let m = (v as u32) & 0xf00;
        if m >= 0xa00 {
            return bad(format!("Unknown cache mode: {:08x}", v as u32));
        }
        s.cache_mode = m;
    }
    if let Some(v) = p.u64("IOSurfaceMapCacheAttribute") {
        s.map_cache_attribute = v as u32;
    }
    if let Some(b) = p.boolean("IOSurfaceIsGlobal") {
        set(&mut s.flags, flag::GLOBAL, b);
    }
    if let Some(b) = p.boolean("IOSurfaceIsPrivate") {
        set(&mut s.flags, flag::PRIVATE, b);
    }
    if s.flags & flag::GLOBAL != 0 && s.flags & flag::PRIVATE != 0 {
        return bad("IOSurface: Cannot set both global and private properties");
    }
    if let Some(b) = p.boolean("IOSurfacePurgeWhenNotInUse") {
        set(&mut s.flags, flag::PURGE_WHEN_NOT_IN_USE, b);
    }
    if let Some(b) = p.boolean("IOSurfaceResetDefaultAttachmentsWhenNotInUse") {
        set(&mut s.flags, flag::RESET_DEFAULT_ATTACHMENTS_WHEN_NOT_IN_USE, b);
    }
    if let Some(i) = g.lookup(props, b"IOSurfaceDefaultAttachments") {
        if matches!(g.get(i), Obj::Dict(_)) {
            s.default_attachments = Some(i);
        }
    }
    if let Some(Obj::Data(d)) = p.obj("IOSurfaceDefaultBulkAttachments") {
        let mut b = [0u8; 0x70];
        let n = d.len().min(0x70);
        b[..n].copy_from_slice(&d[..n]);
        s.default_bulk = Some(b);
    }
    match p.obj("IOSurfaceMemoryRegion") {
        Some(Obj::String(r)) => s.memory_regions.push(r.clone()),
        Some(Obj::Array(a)) => {
            for &e in a.iter().take(2) {
                if let Obj::String(r) = g.get(e) {
                    s.memory_regions.push(r.clone());
                }
            }
        }
        _ => {}
    }
    if let Some(v) = p.u64("IOSurfaceAllocateFromSuperbuffer") {
        s.allocate_from_superbuffer = v as u32;
    }
    // 0xfffffff005b9d380: the shared record takes the bulk attachments
    // (zeroes without), over what IOSurfaceYCbCrMatrix put at +0x6a.
    s.shared_bulk = s.default_bulk.unwrap_or([0; 0x70]).to_vec();
    Ok(s)
}

/// Plane `i` of `IOSurfacePlaneInfo` (0xfffffff005b99ec4..0x...9af44).
fn plane(g: &Graph, pd: Id, i: usize, s: &mut Desc, parent: Option<&Desc>, root: &RootParams) -> Result<(), InitError> {
    if !matches!(g.get(pd), Obj::Dict(_)) {
        return bad(format!("IOSurface: plane[{i}] is not a dictionary"));
    }
    let p = Props { g, d: pd };
    let mut pl = Plane::default();
    let (Some(w), Some(h)) = (p.u64("IOSurfacePlaneWidth"), p.u64("IOSurfacePlaneHeight")) else {
        return bad(format!("IOSurface: plane[{i}] width or height missing"));
    };
    pl.width = w;
    pl.height = h;
    let mut ext = Extended::default();
    ext.left = p.u32("IOSurfacePlaneExtendedPixelsOnLeft")?.unwrap_or(0);
    ext.right = p.u32("IOSurfacePlaneExtendedPixelsOnRight")?.unwrap_or(0);
    ext.top = p.u32("IOSurfacePlaneExtendedPixelsOnTop")?.unwrap_or(0);
    ext.bottom = p.u32("IOSurfacePlaneExtendedPixelsOnBottom")?.unwrap_or(0);
    // Bytes per element: the first of the three keys given.
    pl.bytes_per_element = if let Some(v) = p.u64("IOSurfacePlaneBytesPerElement") {
        if v >= 0x2000 {
            return bad("IOSurface: kIOSurfacePlaneBytesPerElement out of range");
        }
        v as u16
    } else if let Some(v) = p.u64("IOSurfacePlaneBitsPerElement") {
        if v >= 0x10000 {
            return bad("IOSurface: kIOSurfacePlaneBitsPerElement out of range");
        }
        ((v >> 3) & 0x1fff) as u16
    } else if let Some(v) = p.u64("IOSurfacePlaneBitsPerBlock") {
        if v >= 0x10000 {
            return bad("IOSurface: kIOSurfacePlaneBitsPerElement out of range");
        }
        ((v >> 3) & 0x1fff) as u16
    } else {
        1
    };
    if pl.bytes_per_element == 0 {
        return bad(format!("IOSurface: plane[{i}] bytes per element is zero."));
    }
    pl.element_width = p.u8("IOSurfacePlaneElementWidth")?.unwrap_or(1);
    pl.element_height = p.u8("IOSurfacePlaneElementHeight")?.unwrap_or(1);
    if pl.element_width == 0 {
        return bad(format!("IOSurface: plane[{i}] element width is zero."));
    }
    if pl.element_height == 0 {
        return bad(format!("IOSurface: plane[{i}] element height is zero."));
    }
    pl.address_format = p.u8("IOSurfaceAddressFormat")?.unwrap_or(0);
    let (ew, eh, bpe) = (u64::from(pl.element_width), u64::from(pl.element_height), u64::from(pl.bytes_per_element));
    let Some(w_el) = w.checked_add(u64::from(ext.right)).and_then(|x| x.checked_add(ew - 1)).map(|x| x / ew) else {
        return bad(format!("IOSurface: plane[{i}] extended width exceeds 64bit limit"));
    };
    let Some(left_el) = u64::from(ext.left).checked_add(ew - 1).map(|x| x / ew) else {
        return bad(format!("IOSurface: plane[{i}] extended left exceeds 64bit limit"));
    };
    let Some(min_bpr) = w_el.checked_add(left_el).and_then(|x| x.checked_mul(bpe)) else {
        return bad(format!("IOSurface: plane[{i}] minimum bytes per row value exceeds 64bit limit"));
    };
    pl.bytes_per_row = match p.u64("IOSurfacePlaneBytesPerRow") {
        Some(v) => v,
        None => match align(min_bpr, root.row_mask) {
            Some(v) => v,
            None => return bad(format!("IOSurface: plane[{i}] calculated bytesPerRow exceeds 64bit limit")),
        },
    };
    if pl.bytes_per_row < min_bpr {
        return bad(format!("IOSurface: plane[{i}] bytes per row value of {} is too small", pl.bytes_per_row));
    }
    let Some(h_el) = h.checked_add(u64::from(ext.bottom)).and_then(|x| x.checked_add(eh - 1)).map(|x| x / eh) else {
        return bad(format!("IOSurface: plane[{i}] extended height exceeds 64bit limit"));
    };
    pl.size = match p.u64("IOSurfacePlaneSize") {
        Some(v) => v,
        None => match pl.bytes_per_row.checked_mul(h_el) {
            Some(v) => v,
            None => return bad(format!("IOSurface: plane[{i}] calculated size value exceeds 64bit limit")),
        },
    };
    if pl.size == 0 {
        return bad(format!("IOSurface: plane[{i}] size is zero"));
    }
    pl.offset = match p.u64("IOSurfacePlaneOffset") {
        Some(v) => v,
        None => match s.planes.last() {
            None => 0,
            Some(prev) => match prev.base.checked_add(prev.size).and_then(|x| align(x, root.offset_mask)) {
                Some(v) => v,
                None => return bad(format!("IOSurface: plane[{i}] calculated offset value exceeds 64bit limit")),
            },
        },
    };
    pl.base = p.u64("IOSurfacePlaneBase").unwrap_or(pl.offset);
    if parent.is_none() && i > 0 {
        for (j, q) in s.planes.iter().enumerate() {
            if pl.base < q.base.wrapping_add(q.size) {
                return bad(format!("IOSurface: plane[{i}] base {:016x} overlaps with previous plane {j}", pl.base));
            }
        }
    }
    if pl.offset < pl.base {
        return bad(format!("IOSurface: plane[{i}] offset {:016x} is less than plane[{i}] base {:016x}", pl.offset, pl.base));
    }
    if pl.base.checked_add(pl.size).is_none() {
        return bad(format!("IOSurface: plane[{i}] base {:016x} plus plane size {:016x} exceeds 64bit limit", pl.base, pl.size));
    }
    let Some(lines) = pl.bytes_per_row.checked_mul(h_el.wrapping_sub(1)) else { return bad(format!("IOSurface: plane[{i}] required size exceeds 64bit limit")) };
    let Some(required) = lines.checked_add(w_el * bpe) else { return bad(format!("IOSurface: plane[{i}] total required size exceeds 64bit limit")) };
    let comps = match parse_components(&p) {
        Ok(c) => c,
        Err(_) => return bad(format!("IOSurface: plane[{i}] parseAdditionalPlaneInfo failed.")),
    };
    // Compression (0xfffffff005b9a5e0): types 1 to 4, or 0 with address
    // format 5, describe a compressed plane.
    let ctype = p.u64("IOSurfacePlaneCompressionType");
    if let Some(t) = ctype {
        if t > 4 {
            return bad(format!("IOSurface: plane[{i}] illegal compression type"));
        }
        if t != 0 || pl.address_format == 5 {
            return Err(InitError::Unimplemented(format!("IOSurface plane {i} compressed (type {t}, address format {}): the kext's compressed-plane layout rules", pl.address_format)));
        }
    }
    // The image within the plane (0xfffffff005b9a7a4).
    let limit = match parent {
        Some(par) => pl.base.checked_add(par.alloc_size),
        None => pl.base.checked_add(pl.size),
    };
    if pl.offset.checked_add(required).zip(limit).map_or(true, |(need, lim)| need > lim) {
        return bad(if parent.is_some() { format!("IOSurface: child surface plane[{i}] Image data doesn't fit within allocated parent plane size") } else { format!("IOSurface: plane[{i}] Image data doesn't fit within allocated plane size") });
    }
    s.planes.push(pl);
    s.components.push(comps);
    s.extended.push(ext);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: RootParams = RootParams { row_mask: 0x3f, offset_mask: 0x3fff, max_alloc: 1 << 30, debug: 0x10, page_size: 0x4000 };

    fn dict(g: &mut Graph, kv: &[(&str, Id)]) -> Id {
        g.add(Obj::Dict(kv.iter().map(|(k, v)| (k.as_bytes().to_vec(), *v)).collect()))
    }

    #[test]
    fn a_bgra_surface_takes_aligned_rows_and_pages() {
        let mut g = Graph::default();
        let (w, h, b, f) = (g.number(100, 32), g.number(50, 32), g.number(4, 32), g.number(0x4247_5241, 32));
        let d = dict(&mut g, &[("IOSurfaceWidth", w), ("IOSurfaceHeight", h), ("IOSurfaceBytesPerElement", b), ("IOSurfacePixelFormat", f)]);
        let s = init(&g, d, None, &ROOT).unwrap();
        assert_eq!((s.bytes_per_row, s.alloc_size, s.pixel_format), (448, 32768, 0x4247_5241));
        assert!(s.planes.is_empty());
        let r = g.number(512, 32);
        g.dict_set(d, b"IOSurfaceBytesPerRow", r);
        assert_eq!(init(&g, d, None, &ROOT).unwrap().bytes_per_row, 512);
        let r = g.number(396, 32);
        g.dict_set(d, b"IOSurfaceBytesPerRow", r);
        assert!(matches!(init(&g, d, None, &ROOT), Err(InitError::BadArgument(_))));
    }

    #[test]
    fn a_biplanar_surface_places_its_planes_on_pages() {
        let mut g = Graph::default();
        let mk = |g: &mut Graph, w: u64, h: u64, bpe: u64| {
            let (w, h, b) = (g.number(w, 32), g.number(h, 32), g.number(bpe, 32));
            dict(g, &[("IOSurfacePlaneWidth", w), ("IOSurfacePlaneHeight", h), ("IOSurfacePlaneBytesPerElement", b)])
        };
        let (p0, p1) = (mk(&mut g, 64, 64, 1), mk(&mut g, 32, 32, 2));
        let planes = g.add(Obj::Array(vec![p0, p1]));
        let (w, h, f) = (g.number(64, 32), g.number(64, 32), g.number(u64::from(u32::from_be_bytes(*b"420v")), 32));
        let d = dict(&mut g, &[("IOSurfaceWidth", w), ("IOSurfaceHeight", h), ("IOSurfacePixelFormat", f), ("IOSurfacePlaneInfo", planes)]);
        let s = init(&g, d, None, &ROOT).unwrap();
        assert_eq!(s.planes.len(), 2);
        assert_eq!((s.planes[0].bytes_per_row, s.planes[0].size, s.planes[0].offset), (64, 4096, 0));
        assert_eq!((s.planes[1].bytes_per_row, s.planes[1].size, s.planes[1].offset), (64, 2048, 16384));
        assert_eq!(s.alloc_size, 32768);
    }

    #[test]
    fn a_zero_height_never_fits() {
        let mut g = Graph::default();
        let (w, h) = (g.number(8, 32), g.number(0, 32));
        let d = dict(&mut g, &[("IOSurfaceWidth", w), ("IOSurfaceHeight", h)]);
        assert!(init(&g, d, None, &ROOT).is_err());
    }
}
