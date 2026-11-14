//! IOSurfaceRootUserClient's selectors and traps.

use super::super::iokit::{ret, MethodArgs};
use super::super::osserialize::{self as os, Graph, Id, Obj};
use super::{bump_value_seed, ensure_values, kr, map_into_task, release_handle, ro, ro_set_u32, ro_u32, root, rw, surface, surface_release, use_count_decrement, use_count_increment, Handle, Root, SendRight, Surface, VmPurgeable, REPLY_SIZE};
use crate::syscalls::Kernel;
use surface::{flag, InitError};

/// The user client's selector `a.selector`, its counts already checked.
pub fn call(k: &mut Kernel, uc: u32, a: &mut MethodArgs) -> i32 {
    let sc = |i: usize| a.scalar_in.get(i).copied().unwrap_or(0);
    match a.selector {
        0 => create(k, uc, a),
        1 => finalize(k, uc, sc(0) as u32),
        2 => lock_method(k, uc, a),
        3 => unlock_method(k, uc, a),
        4 => lookup(k, uc, a),
        5 => set_ycbcr_matrix(k, uc, sc(0) as u32, sc(1)),
        6 | 7 => {
            k.darwin_unimplemented(format!("IOSurfaceRootUserClient selector {} (a surface over the task's own memory: IOSurfaceAddress)", a.selector));
            ret::UNSUPPORTED
        }
        8 => get_ycbcr_matrix(uc, sc(0) as u32, a),
        9 => set_value(k, uc, a),
        10 => copy_value(k, uc, a, false),
        11 => remove_value(k, uc, a),
        13 => limits(uc, a),
        14 => use_count(k, uc, sc(0) as u32, sc(1), true),
        15 => use_count(k, uc, sc(0) as u32, sc(1), false),
        16 => in_use(uc, sc(0) as u32, a),
        19 => log(k, a),
        20 => set_purgeable(k, uc, sc(0) as u32, sc(1), a),
        21 | 44 => set_ownership(k, uc, a),
        22 => with_surface(uc, sc(0) as u32, |_, _| ret::UNSUPPORTED),
        23 => {
            let r = with_surface(uc, sc(0) as u32, |_, s| {
                a.scalar_out[0] = u64::from(s.desc.flags & flag::BUFFER_TILE_MODE != 0);
                ret::SUCCESS
            });
            r
        }
        24 => set_timestamp(k, uc, a),
        25 => {
            let r = with_surface(uc, sc(0) as u32, |_, s| {
                a.scalar_out[0] = u64::from(s.desc.tile_format);
                ret::SUCCESS
            });
            r
        }
        26 => copy_value(k, uc, a, true),
        27 => set_bulk(k, uc, a),
        28 => get_bulk(uc, a),
        30 => descriptions(k, uc, a),
        31 => set_tile_data_used(k, uc, sc(0) as u32, sc(1), sc(2)),
        32 => comm_page(uc, a),
        33 => set_indexed_timestamp(k, uc, sc(0) as u32, sc(1), sc(2)),
        34 => lookup_port(k, uc, a),
        35 => create_port(k, uc, sc(0) as u32, sc(1) as u32, a),
        43 => detach_mode(k, uc, sc(0) as u32, sc(1), sc(2), sc(3)),
        50 => set_data(k, uc, sc(0) as u32, sc(1), a),
        51 => get_data(uc, sc(0) as u32, sc(1), a),
        52 => clear_data(k, uc, a),
        53 => detach(k, uc, sc(0) as u32),
        s => {
            let what = match s {
                12 => "binding a surface to an accelerator (its device cache)",
                17 | 18 => "surface notifications",
                29 => "selector 29",
                36..=42 => "shared events",
                45 => "selector 45",
                46..=49 => "memory pools",
                _ => "a selector",
            };
            k.darwin_unimplemented(format!("IOSurfaceRootUserClient selector {s} ({what})"));
            ret::UNSUPPORTED
        }
    }
}

/// The handle of user client `uc` for surface `id`
/// (0xfffffff005bb1d0c: id 0, or one past the table, or an empty slot,
/// has none).
fn handle(r: &Root, uc: u32, id: u32) -> Option<Handle> {
    r.clients.get(&uc)?.handles.get(id as usize)?.clone()
}

/// `f` with the surface user client `uc` holds as `id`
/// (0xfffffff005bb1e58), else kIOReturnBadArgument.
fn with_surface(uc: u32, id: u32, f: impl FnOnce(&mut Root, &mut Surface) -> i32) -> i32 {
    root(|r| {
        if handle(r, uc, id).is_none() {
            return ret::BAD_ARGUMENT;
        }
        let Some(mut s) = r.surfaces.remove(&id) else { return ret::BAD_ARGUMENT };
        let v = f(r, &mut s);
        r.surfaces.insert(id, s);
        v
    })
}

/// The structure input's bytes: inband, or the descriptor's, read from the
/// caller (`map(kIOMapReadOnly)`: kIOReturnVMError when it does not map).
fn struct_input(k: &mut Kernel, a: &MethodArgs) -> Result<Vec<u8>, i32> {
    match a.ool_in {
        None => Ok(a.struct_in.clone()),
        Some((addr, len)) => k.darwin_vm_copyin(addr, len).map_err(|_| ret::VM_ERROR),
    }
}

/// The structure output written, inband or into the caller's descriptor,
/// its size set to `bytes`'.
fn struct_output(k: &mut Kernel, a: &mut MethodArgs, bytes: &[u8]) -> Result<(), i32> {
    match a.ool_out {
        None => {
            let n = bytes.len().min(a.struct_out.len());
            a.struct_out.truncate(n);
            a.struct_out.copy_from_slice(&bytes[..n]);
            Ok(())
        }
        Some((addr, len)) => {
            let n = (bytes.len() as u64).min(len);
            k.darwin_vm_copy_overwrite(addr, &bytes[..n as usize]).map_err(|_| ret::VM_ERROR)?;
            a.ool_out = Some((addr, n));
            Ok(())
        }
    }
}

/// `copyout(&v, addr, 4)` from a trap: the errno a bad address gives
/// (EFAULT), as the trap's result.
fn copyout_u32(k: &mut Kernel, addr: u64, v: u32) -> i32 {
    match k.darwin_vm_copy_overwrite(addr, &v.to_le_bytes()) {
        Ok(()) => 0,
        Err(_) => 14,
    }
}

// ---------------------------------------------------------------------------
// The reply.

/// The create, lookup and lock reply (0xfffffff005ba5cb4), zeroed first:
/// the handle's addresses, the surface's description, and up to 20 planes
/// of 0x98 bytes from 0x88.
fn reply(r: &Root, s: &Surface, h: &Handle) -> Vec<u8> {
    let mut b = vec![0u8; REPLY_SIZE];
    let put = |b: &mut Vec<u8>, at: usize, v: &[u8]| b[at..at + v.len()].copy_from_slice(v);
    let d = &s.desc;
    let n = d.planes.len().min(surface::MAX_PLANES);
    put(&mut b, 0x00, &h.base.to_le_bytes());
    put(&mut b, 0x08, &h.ro.to_le_bytes());
    put(&mut b, 0x10, &h.rw.to_le_bytes());
    put(&mut b, 0x18, &s.id.to_le_bytes());
    put(&mut b, 0x20, &d.alloc_size.to_le_bytes());
    put(&mut b, 0x28, &d.width.to_le_bytes());
    put(&mut b, 0x30, &d.height.to_le_bytes());
    put(&mut b, 0x38, &d.bytes_per_row.to_le_bytes());
    put(&mut b, 0x40, &d.offset.to_le_bytes());
    put(&mut b, 0x48, &d.pixel_format.to_le_bytes());
    put(&mut b, 0x50, &d.alloc_size.to_le_bytes());
    put(&mut b, 0x58, &(n as u32).to_le_bytes());
    put(&mut b, 0x5c, &u32::from(r.shared.ro_read(s.id, ro::YCBCR_MATRIX, 1)[0]).to_le_bytes());
    put(&mut b, 0x60, &d.bytes_per_element.to_le_bytes());
    b[0x62] = d.element_width;
    b[0x63] = d.element_height;
    put(&mut b, 0x64, &d.cache_mode.to_le_bytes());
    put(&mut b, 0x68, &ro_u32(r, s.id, ro::SEED).to_le_bytes());
    b[0x6c] = d.subsampling as u8;
    b[0x6d] = u8::from(d.flags & flag::PROHIBIT_USE_COUNT != 0);
    put(&mut b, 0x70, &s.parent.unwrap_or(0).to_le_bytes());
    // 0x74: the slice count, with compressed planes only (none here).
    put(&mut b, 0x78, &s.trace_id.to_le_bytes());
    put(&mut b, 0x80, &d.protection.to_le_bytes());
    // A plane's components and extended pixels (0xfffffff005ba61f0).
    let extras = |b: &mut Vec<u8>, i: usize| {
        let p = 0x88 + i * 0x98;
        if let Some(c) = d.components.get(i) {
            b[p + 0x34] = c.count.min(4);
            b[p + 0x38..p + 0x3c].copy_from_slice(&c.bit_depths);
            b[p + 0x3c..p + 0x40].copy_from_slice(&c.bit_offsets);
            b[p + 0x40..p + 0x44].copy_from_slice(&c.names);
            b[p + 0x44..p + 0x48].copy_from_slice(&c.types);
            b[p + 0x48..p + 0x4c].copy_from_slice(&c.ranges);
        }
        if let Some(e) = d.extended.get(i) {
            for (j, v) in [e.right, e.bottom, e.left, e.top].iter().enumerate() {
                b[p + 0x88 + 4 * j..p + 0x8c + 4 * j].copy_from_slice(&v.to_le_bytes());
            }
        }
    };
    if n == 0 {
        extras(&mut b, 0);
    }
    for (i, pl) in d.planes.iter().take(n).enumerate() {
        let p = 0x88 + i * 0x98;
        put(&mut b, p, &pl.width.to_le_bytes());
        put(&mut b, p + 0x08, &pl.height.to_le_bytes());
        put(&mut b, p + 0x10, &pl.base.to_le_bytes());
        put(&mut b, p + 0x18, &pl.offset.to_le_bytes());
        put(&mut b, p + 0x20, &pl.bytes_per_row.to_le_bytes());
        put(&mut b, p + 0x28, &pl.size.to_le_bytes());
        put(&mut b, p + 0x30, &pl.bytes_per_element.to_le_bytes());
        b[p + 0x32] = pl.element_width;
        b[p + 0x33] = pl.element_height;
        b[p + 0x35] = pl.address_format;
        extras(&mut b, i);
    }
    b
}

// ---------------------------------------------------------------------------
// Handles.

/// `IOSurfaceClient::withSurface(shared, surface, created)`
/// (0xfffffff005ba5860): the surface's records mapped into the task, the
/// memory mapped (unless the surface maps none), the surface retained and
/// its client count raised. kIOReturnNoMemory when a mapping fails.
fn new_handle(k: &mut Kernel, r: &mut Root, uc: u32, s: &mut Surface, created: bool) -> Result<Handle, i32> {
    let mut ts = std::mem::take(&mut r.clients.get_mut(&uc).unwrap().shared);
    let recs = r.shared.map_client(k, &mut ts, s.id);
    r.clients.get_mut(&uc).unwrap().shared = ts;
    let (ro_va, rw_va) = recs.map_err(|_| ret::NO_MEMORY)?;
    let base = map_into_task(k, s)?;
    s.refs += 1;
    s.clients += 1;
    Ok(Handle { id: s.id, created, base, ro: ro_va, rw: rw_va, use_counts: [0; 2] })
}

/// set_surface_handle (0xfffffff005bb1ecc) and the counts
/// (0xfffffff005bb2028): the handle in the client's table, grown to the
/// root's size when the id is past it.
fn install_handle(r: &mut Root, uc: u32, h: Handle) {
    let size = r.table_size as usize;
    let c = r.clients.get_mut(&uc).unwrap();
    if h.id as usize >= c.handles.len() {
        c.handles.resize(size.max(h.id as usize + 1), None);
    }
    c.total += 1;
    if h.created {
        c.created += 1;
        if c.created >= 0x2000 {
            c.warned_8k = true;
        }
        if c.created >= 0x3000 {
            c.warned_12k = true;
        }
    }
    let id = h.id as usize;
    c.handles[id] = Some(h);
}

/// Selector 0 (0xfffffff005badcd0, 0xfffffff005baf3f4): a surface made from
/// the serialized properties, a child of the parent named by scalar 0.
fn create(k: &mut Kernel, uc: u32, a: &mut MethodArgs) -> i32 {
    let parent_id = a.scalar_in[0];
    if parent_id >> 32 != 0 {
        return ret::BAD_ARGUMENT;
    }
    let input = match struct_input(k, a) {
        Ok(b) => b,
        Err(e) => return e,
    };
    if input.is_empty() {
        return ret::BAD_ARGUMENT;
    }
    if root(|r| r.clients.get(&uc).map_or(0, |c| c.created)) >> 14 != 0 {
        return ret::NO_RESOURCES;
    }
    let Some((g, props)) = super::unserialize(k, "IOSurface creation properties", &input) else { return ret::BAD_ARGUMENT };
    if !matches!(g.get(props), Obj::Dict(_)) {
        return ret::BAD_ARGUMENT;
    }
    let parent_id = parent_id as u32;
    if parent_id != 0 && root(|r| handle(r, uc, parent_id).is_none()) {
        return ret::BAD_ARGUMENT;
    }
    let result = root(|r| create_surface(k, r, uc, g, props, (parent_id != 0).then_some(parent_id)));
    match result {
        Ok(out) => {
            a.struct_out.copy_from_slice(&out);
            ret::SUCCESS
        }
        Err(e) => e,
    }
}

/// `IOSurfaceRoot::createSurface` (0xfffffff005baaa2c) and the rest of the
/// create: the object's init (0xfffffff005b99720), its memory, a handle
/// for it, and the reply.
fn create_surface(k: &mut Kernel, r: &mut Root, uc: u32, mut g: Graph, props: Id, parent: Option<u32>) -> Result<Vec<u8>, i32> {
    let trace_id = r.next_trace;
    r.next_trace += 1;
    // A child of a child is refused.
    if let Some(p) = parent {
        if r.surfaces.get(&p).is_some_and(|s| s.parent.is_some()) {
            return Err(ret::BAD_ARGUMENT);
        }
    }
    let Some(id) = r.alloc_id() else { return Err(ret::BAD_ARGUMENT) };
    r.shared.alloc(k, id);
    // The outer init's default: pixel size casting allowed unless the
    // root's debug flags' bit 1 says otherwise, put into the properties.
    if !matches!(g.lookup(props, b"IOSurfacePixelSizeCastingAllowed").map(|i| g.get(i)), Some(Obj::Bool(_))) {
        let b = g.add(Obj::Bool(r.params.debug & 2 == 0));
        g.dict_set(props, b"IOSurfacePixelSizeCastingAllowed", b);
    }
    let parent_desc = parent.and_then(|p| r.surfaces.get(&p)).map(|s| s.desc.clone());
    let desc = match surface::init(&g, props, parent_desc.as_ref(), &r.params) {
        Ok(d) => d,
        Err(InitError::BadArgument(_)) => {
            r.free_id(id);
            return Err(ret::BAD_ARGUMENT);
        }
        Err(InitError::Unimplemented(what)) => {
            r.free_id(id);
            k.darwin_unimplemented(what);
            return Err(ret::UNSUPPORTED);
        }
    };
    // allocate() (0xfffffff005b9c21c): the paths that place a surface over
    // other memory.
    let unimplemented = if parent.is_some() {
        Some("a child surface (it shares its parent's memory)".to_string())
    } else if desc.address.is_some() || desc.address_ranges.is_some() {
        Some("a surface over the task's own memory (IOSurfaceAddress, IOSurfaceAddressRanges)".to_string())
    } else if !desc.memory_regions.is_empty() {
        Some(format!("a surface in the memory region {:?}", desc.memory_regions.iter().map(|m| String::from_utf8_lossy(m).into_owned()).collect::<Vec<_>>()))
    } else if desc.allocate_from_superbuffer != 0 {
        Some("a surface allocated from a memory pool (IOSurfaceAllocateFromSuperbuffer)".to_string())
    } else {
        None
    };
    if let Some(what) = unimplemented {
        r.free_id(id);
        k.darwin_unimplemented(what);
        return Err(ret::UNSUPPORTED);
    }
    // IOBufferMemoryDescriptor::inTaskWithOptions(NULL, opts,
    // round_page(allocSize), page_size).
    let page = r.params.page_size;
    let memory = (desc.alloc_size != 0).then(|| super::memory::Memory::new((desc.alloc_size + page - 1) & !(page - 1)));
    let mut desc = desc;
    desc.flags |= flag::INITIALIZED;
    // Bit 5 after allocate unless the cache mode keeps the caches coherent
    // (0xfffffff005b9c810).
    if !matches!(desc.cache_mode, 0x100 | 0x400 | 0x700) {
        desc.flags |= 1 << 5;
    }
    // The shared record (`+0x178`) as init leaves it.
    let mut rec = r.shared.ro_read(id, 0, ro::SIZE as usize);
    rec[ro::TILED as usize] = u8::from(desc.shared_tile_mode);
    rec[ro::PIXEL_SIZE_CASTING as usize] = u8::from(desc.shared_pixel_size_casting);
    rec[ro::DISPLAYABLE as usize] = u8::from(desc.shared_displayable);
    rec[ro::SYS_MEM_ONLY as usize] = u8::from(desc.shared_sys_mem_only);
    rec[ro::BULK as usize..ro::BULK as usize + 0x70].copy_from_slice(&desc.shared_bulk);
    r.shared.ro_write(k, id, 0, &rec);
    let global = desc.flags & flag::GLOBAL != 0;
    let mut s = Surface {
        id,
        desc,
        refs: 1,
        creator: Some(k.pid),
        parent,
        trace_id,
        clients: 0,
        wired: 0,
        installed: false,
        ro_locks: 0,
        rw_locks: 0,
        purgeable: 2,
        vm_purgeable: VmPurgeable::NonVolatile,
        memory,
        graph: g,
        props,
        values: None,
        data: Default::default(),
        bulk15: (0, 0, 0),
        gpu: false,
    };
    ensure_values(&mut s);
    if let Some(p) = parent {
        if let Some(ps) = r.surfaces.get_mut(&p) {
            ps.refs += 1;
        }
    }
    // addSurface (0xfffffff005baa200).
    r.count += 1;
    if (0xfe00..=0x1_0000).contains(&r.count) {
        r.warned = true;
    }
    if global {
        if let Some(c) = r.clients.get_mut(&uc) {
            c.logged_global = true;
        }
    }
    let h = match new_handle(k, r, uc, &mut s, true) {
        Ok(h) => h,
        Err(e) => {
            r.surfaces.insert(id, s);
            surface_release(k, r, id);
            return Err(e);
        }
    };
    s.installed = true;
    let out = reply(r, &s, &h);
    r.surfaces.insert(id, s);
    install_handle(r, uc, h);
    // The creation's reference let go: the handle holds the surface.
    surface_release(k, r, id);
    Ok(out)
}

/// Selector 4 (0xfffffff005baddec, 0xfffffff005bafa5c): a surface by id.
/// The root finds it (0xfffffff005baa438) for its creator's task, or a
/// global one when the debug flags allow global lookups (not by default);
/// a private one never.
fn lookup(k: &mut Kernel, uc: u32, a: &mut MethodArgs) -> i32 {
    let id = a.scalar_in[0] as u32;
    let pid = k.pid;
    let r = root(|r| {
        if handle(r, uc, id).is_some() {
            return Err(ret::BAD_ARGUMENT);
        }
        let debug = r.params.debug;
        // The framebuffer's default temporary surface, the kernel's (not
        // global, not private), is found only when every lookup is allowed.
        if r.default_temp == Some(id) && debug & 1 != 0 {
            return Err(UNMODELLED);
        }
        let Some(mut s) = r.surfaces.remove(&id) else { return Err(ret::BAD_ARGUMENT) };
        let found = s.installed
            && (s.creator == Some(pid)
                || (s.desc.flags & flag::PRIVATE == 0 && ((debug & 4 != 0 && s.desc.flags & flag::GLOBAL != 0) || debug & 1 != 0)));
        if !found {
            r.surfaces.insert(id, s);
            return Err(ret::BAD_ARGUMENT);
        }
        let h = new_handle(k, r, uc, &mut s, false);
        let out = h.as_ref().map(|h| reply(r, &s, h)).map_err(|e| *e);
        r.surfaces.insert(id, s);
        install_handle(r, uc, h?);
        out
    });
    match r {
        Ok(out) => {
            a.struct_out.copy_from_slice(&out);
            ret::SUCCESS
        }
        Err(UNMODELLED) => {
            k.darwin_unimplemented(format!("looking up the framebuffer's default temporary surface {id} (its description follows the bootloader's /vram region)"));
            ret::UNSUPPORTED
        }
        Err(e) => e,
    }
}

/// A lookup's result for what is not modelled (no IOReturn has this value).
const UNMODELLED: i32 = 1;

/// Selector 34 (0xfffffff005bae798, 0xfffffff005bafb60): a surface by a
/// send right to it (`copyObjectForPortNameInTask`: a send right in the
/// caller's space to an IKOT_IOKIT_IDENT port, else kIOReturnIPCError; an
/// object that is no IOSurfaceSendRight, kIOReturnBadArgument). A surface
/// the client holds already answers -1 and its id.
fn lookup_port(k: &mut Kernel, uc: u32, a: &mut MethodArgs) -> i32 {
    let name = a.scalar_in[0] as u32;
    let obj = match k.ipc().translate_send(name) {
        Ok(p) => k.ipc().port(p).kobject.clone(),
        Err(_) => return ret::IPC_ERROR,
    };
    let sr = match obj {
        Some(super::super::ipc::Kobject::IoIdent(sr)) => sr,
        _ => return ret::IPC_ERROR,
    };
    let pid = k.pid;
    let r = root(|r| {
        let Some(id) = r.send_rights.get(&sr).map(|s| s.surface) else { return Err(ret::BAD_ARGUMENT) };
        if handle(r, uc, id).is_some() {
            let mut out = vec![0u8; REPLY_SIZE];
            out[..8].copy_from_slice(&u64::MAX.to_le_bytes());
            out[0x18..0x1c].copy_from_slice(&id.to_le_bytes());
            return Ok(out);
        }
        let Some(mut s) = r.surfaces.remove(&id) else { return Err(ret::BAD_ARGUMENT) };
        if s.desc.flags & flag::PRIVATE != 0 && s.creator != Some(pid) {
            r.surfaces.insert(id, s);
            return Err(ret::BAD_ARGUMENT);
        }
        let h = new_handle(k, r, uc, &mut s, false);
        let out = h.as_ref().map(|h| reply(r, &s, h)).map_err(|e| *e);
        r.surfaces.insert(id, s);
        install_handle(r, uc, h?);
        out
    });
    match r {
        Ok(out) => {
            a.struct_out.copy_from_slice(&out);
            ret::SUCCESS
        }
        Err(e) => e,
    }
}

/// Selector 35 (0xfffffff005bae7a8, 0xfffffff005bafcc8): the client's
/// surface by its handle (kIOReturnBadArgument without one), and a send
/// right to it in the caller's space ([`send_right_in_task`]).
fn create_port(k: &mut Kernel, uc: u32, id: u32, options: u32, a: &mut MethodArgs) -> i32 {
    a.scalar_out[0] = 0;
    if root(|r| handle(r, uc, id).is_none()) {
        return ret::BAD_ARGUMENT;
    }
    match send_right_in_task(k, id, options) {
        Ok(name) => {
            a.scalar_out[0] = u64::from(name);
            ret::SUCCESS
        }
        Err(e) => e,
    }
}

/// 0xfffffff005baa918, which selector 35 and the kernel's own callers
/// (0xfffffff005baa90c, with no options) reach: a send right to surface
/// `id` as a port name in the calling task (`copyPortNameForObjectInTask`);
/// option bit 0 wires it, bit 1 keeps it from holding a use count. A
/// surface that is gone is kIOReturnBadArgument.
pub fn send_right_in_task(k: &mut Kernel, id: u32, options: u32) -> Result<u32, i32> {
    let made: Result<u32, i32> = root(|r| {
        let s = r.surfaces.get_mut(&id).ok_or(ret::BAD_ARGUMENT)?;
        let wired = options & 1 != 0;
        // The wired kind forces bit 1 (0xfffffff005bb7d84).
        let opts = if wired { options | 2 } else { options };
        let uses = opts & 2 == 0 && s.desc.flags & flag::PROHIBIT_USE_COUNT == 0;
        s.refs += 1;
        s.clients += 1;
        if wired {
            s.wired += 1;
        }
        if uses {
            use_count_increment(k, r, id, 0);
        }
        let n = r.next_send_right;
        r.next_send_right += 1;
        r.send_rights.insert(n, SendRight { surface: id, uses, wired });
        Ok(n)
    });
    let n = made?;
    let port = k.ipc().kobject_port(super::super::ipc::Kobject::IoIdent(n));
    k.ipc().port_mut(port).owner = 0;
    k.ipc().make_send(port);
    k.ipc().port_mut(port).nsrequest_kobject = true;
    Ok(k.darwin_copyout_send(port))
}

/// Trap 4 and selector 53 (0xfffffff005baf794): the handle detached into
/// the client's invalidated list, which trap 5 finishes.
pub fn detach(_k: &mut Kernel, uc: u32, id: u32) -> i32 {
    root(|r| {
        let Some(c) = r.clients.get_mut(&uc) else { return ret::BAD_ARGUMENT };
        let Some(h) = c.handles.get_mut(id as usize).and_then(Option::take) else { return ret::BAD_ARGUMENT };
        c.invalidated.push(h);
        ret::SUCCESS
    })
}

/// Trap 5 and selector 1 (0xfffffff005baf6a0): the first detached handle
/// for the id released, and the client's counts with it.
pub fn finalize(k: &mut Kernel, uc: u32, id: u32) -> i32 {
    root(|r| {
        let Some(c) = r.clients.get_mut(&uc) else { return ret::BAD_ARGUMENT };
        let Some(i) = c.invalidated.iter().position(|h| h.id == id) else { return ret::BAD_ARGUMENT };
        let h = c.invalidated.remove(i);
        if h.created {
            c.created -= 1;
        }
        c.total -= 1;
        let pid = c.pid;
        release_handle(k, r, pid, h);
        ret::SUCCESS
    })
}

// ---------------------------------------------------------------------------
// Locks.

/// `IOSurface::lock` (0xfffffff005b9d73c) for the caller's handle `h`: the
/// counts, the memory brought up to date in the caller's view, the seed
/// raised by a lock that allows writing; the seed.
fn lock(k: &mut Kernel, r: &mut Root, h: &Handle, options: u32) -> Result<u32, i32> {
    let id = h.id;
    // Option 4: a fence (0xfffffff005ba200c) made and, nothing else
    // holding the surface, signalled at once: the use count it holds while
    // it lives.
    if options & 4 != 0 {
        use_count_increment(k, r, id, 0);
        use_count_decrement(k, r, id, 0);
    }
    let pid = k.pid;
    let s = r.surfaces.get_mut(&id).ok_or(ret::BAD_ARGUMENT)?;
    // AvoidSync while a device cache owns the surface: none ever does here
    // (binding to an accelerator is not served).
    let write = options & 1 == 0;
    if write {
        s.rw_locks += 1;
    } else {
        s.ro_locks += 1;
    }
    if let Some(mem) = s.memory.as_mut() {
        // What the GPU wrote since a task last locked it, into the backing
        // store, for the view to take with the tasks' changes.
        let gpu = s.gpu.then(super::executor::table).flatten();
        if let Some(t) = gpu {
            t.read_back(id, &mut mem.backing);
        }
        if let Some(v) = (h.base != 0).then(|| mem.view(pid, h.base)).flatten() {
            let _ = k.darwin_own_memory(|k, m| mem.lock(k, m, v, write));
        }
        // The tasks' changes gathered here are the GPU's to see.
        let changed = mem.take_changed();
        if let Some(t) = gpu.filter(|_| !changed.is_empty()) {
            t.cpu_wrote(id, &mem.backing, &changed);
        }
    }
    // Bit 4: clean the caches at the next lock (a coherent host has none
    // to clean).
    if s.desc.flags & (1 << 4) != 0 {
        s.desc.flags &= !((1 << 4) | (1 << 5));
    }
    if write {
        s.desc.flags |= 0xc;
        let v = ro_u32(r, id, ro::SEED).wrapping_add(1);
        ro_set_u32(k, r, id, ro::SEED, v);
    }
    Ok(ro_u32(r, id, ro::SEED))
}

/// `IOSurface::unlock` (0xfffffff005b9dc40): a lock of the kind released
/// (none held is kIOReturnBadArgument); one that allowed writing counts a
/// write unlock and sends the view's changes to the backing store; the
/// seed.
fn unlock(k: &mut Kernel, r: &mut Root, h: &Handle, options: u32) -> Result<u32, i32> {
    let id = h.id;
    let pid = k.pid;
    let s = r.surfaces.get_mut(&id).ok_or(ret::BAD_ARGUMENT)?;
    let write = options & 1 == 0;
    if write {
        if s.rw_locks == 0 {
            return Err(ret::BAD_ARGUMENT);
        }
        s.rw_locks -= 1;
        if !matches!(s.desc.cache_mode, 0x100 | 0x200 | 0x400 | 0x700) {
            s.desc.flags |= 1 << 5;
        }
    } else {
        if s.ro_locks == 0 {
            return Err(ret::BAD_ARGUMENT);
        }
        s.ro_locks -= 1;
    }
    if let Some(mem) = s.memory.as_mut() {
        if let Some(v) = (h.base != 0).then(|| mem.view(pid, h.base)).flatten() {
            let _ = k.darwin_own_memory(|k, m| mem.unlock(k, m, v, write));
        }
        // The view's changes are the GPU's to see from now on.
        let changed = mem.take_changed();
        if let Some(t) = s.gpu.then(super::executor::table).flatten().filter(|_| !changed.is_empty()) {
            t.cpu_wrote(id, &mem.backing, &changed);
        }
    }
    if write {
        let v = ro_u32(r, id, ro::WRITE_UNLOCKS).wrapping_add(1);
        ro_set_u32(k, r, id, ro::WRITE_UNLOCKS, v);
    }
    Ok(ro_u32(r, id, ro::SEED))
}

/// Trap 2 (0xfffffff005bb0764): lock, and the seed copied out to `p3` (an
/// errno when that faults, the lock taken).
pub fn lock_trap(k: &mut Kernel, uc: u32, id: u32, options: u32, out: u64) -> i32 {
    let r = root(|r| {
        let h = handle(r, uc, id).ok_or(ret::BAD_ARGUMENT)?;
        lock(k, r, &h, options)
    });
    match r {
        Ok(seed) => copyout_u32(k, out, seed),
        Err(e) => e,
    }
}

/// Trap 3 (0xfffffff005bb0864).
pub fn unlock_trap(k: &mut Kernel, uc: u32, id: u32, options: u32, out: u64) -> i32 {
    let r = root(|r| {
        let h = handle(r, uc, id).ok_or(ret::BAD_ARGUMENT)?;
        unlock(k, r, &h, options)
    });
    match r {
        Ok(seed) => copyout_u32(k, out, seed),
        Err(e) => e,
    }
}

/// The 12-byte lock input: id, options.
fn lock_input(a: &MethodArgs) -> Option<(u32, u32)> {
    let b = &a.struct_in;
    if b.len() < 8 {
        return None;
    }
    Some((u32::from_le_bytes(b[..4].try_into().unwrap()), u32::from_le_bytes(b[4..8].try_into().unwrap())))
}

/// Selector 2 (0xfffffff005baf8bc): lock, answered with the full reply
/// whose seed is the lock's.
fn lock_method(k: &mut Kernel, uc: u32, a: &mut MethodArgs) -> i32 {
    let Some((id, options)) = lock_input(a) else { return ret::BAD_ARGUMENT };
    if a.ool_out.is_some() {
        return ret::BAD_ARGUMENT;
    }
    let r = root(|r| {
        let h = handle(r, uc, id).ok_or(ret::BAD_ARGUMENT)?;
        let seed = lock(k, r, &h, options)?;
        let mut out = reply(r, &r.surfaces[&id], &h);
        out[0x68..0x6c].copy_from_slice(&seed.to_le_bytes());
        Ok(out)
    });
    match r {
        Ok(out) => {
            a.struct_out.copy_from_slice(&out);
            ret::SUCCESS
        }
        Err(e) => e,
    }
}

/// Selector 3 (0xfffffff005baf9d8): unlock, the seed out.
fn unlock_method(k: &mut Kernel, uc: u32, a: &mut MethodArgs) -> i32 {
    let Some((id, options)) = lock_input(a) else { return ret::BAD_ARGUMENT };
    let r = root(|r| {
        let h = handle(r, uc, id).ok_or(ret::BAD_ARGUMENT)?;
        unlock(k, r, &h, options)
    });
    match r {
        Ok(seed) => {
            a.struct_out.copy_from_slice(&seed.to_le_bytes());
            ret::SUCCESS
        }
        Err(e) => e,
    }
}

// ---------------------------------------------------------------------------
// Use counts.

/// Traps 0 and 1, selectors 14 and 15 (0xfffffff005bb0624,
/// 0xfffffff005bb06c4): the client's count of `category` raised or
/// lowered (saturating); its first use raises the surface's, its last
/// lowers it.
pub fn use_count(k: &mut Kernel, uc: u32, id: u32, category: u64, up: bool) -> i32 {
    if category as u32 > 1 {
        return ret::BAD_ARGUMENT;
    }
    let cat = category as usize;
    root(|r| {
        let Some(c) = r.clients.get_mut(&uc) else { return ret::BAD_ARGUMENT };
        let Some(h) = c.handles.get_mut(id as usize).and_then(Option::as_mut) else { return ret::BAD_ARGUMENT };
        let old = h.use_counts[cat];
        if up {
            h.use_counts[cat] = old.saturating_add(1);
            if old == 0 {
                use_count_increment(k, r, id, cat);
            }
        } else {
            h.use_counts[cat] = old.saturating_sub(1);
            if old == 1 {
                use_count_decrement(k, r, id, cat);
            }
        }
        ret::SUCCESS
    })
}

/// Selector 16 (0xfffffff005bb0a38): both global counts, summed.
fn in_use(uc: u32, id: u32, a: &mut MethodArgs) -> i32 {
    root(|r| {
        if handle(r, uc, id).is_none() {
            return ret::BAD_ARGUMENT;
        }
        a.scalar_out[0] = u64::from(ro_u32(r, id, ro::USE_COUNT).wrapping_add(ro_u32(r, id, ro::USE_COUNT + 4)));
        ret::SUCCESS
    })
}

// ---------------------------------------------------------------------------
// Purgeability.

/// Selector 20 (0xfffffff005bb0acc, 0xfffffff005b9e000): the memory's
/// purgeable state set (`setPurgeable` with IOKit's states:
/// NonVolatile 2, Volatile 3, Empty 4, KeepCurrent 1), the old one out in
/// IOSurface's (0 NonVolatile, 1 Volatile, 2 Empty).
fn set_purgeable(k: &mut Kernel, uc: u32, id: u32, state: u64, a: &mut MethodArgs) -> i32 {
    let state = state as u32;
    let mut old_out = 0u64;
    let r = with_surface(uc, id, |_, s| {
        if s.desc.flags & flag::PURGEABLE == 0 || s.memory.is_none() {
            old_out = 0;
            return ret::SUCCESS;
        }
        old_out = 2;
        if state & 0xf > 3 {
            s.purgeable = 0;
            return ret::BAD_ARGUMENT;
        }
        // Volatile becomes Empty while a device cache owns the surface;
        // none does here.
        let mapped = match state & 0xf {
            0 => 2,
            1 => 3,
            2 => 4,
            _ => 1,
        };
        if mapped != 1 {
            s.purgeable = mapped;
        }
        // vm_object_purgable_control: what is emptied stays empty; Empty
        // discards the contents.
        let old = s.vm_purgeable;
        let new = match mapped {
            2 => VmPurgeable::NonVolatile,
            3 if old == VmPurgeable::Empty => VmPurgeable::Empty,
            3 => VmPurgeable::Volatile,
            4 => VmPurgeable::Empty,
            _ => old,
        };
        s.vm_purgeable = new;
        if mapped == 4 {
            purge(k, s);
        }
        old_out = match old {
            VmPurgeable::NonVolatile => 0,
            VmPurgeable::Volatile => 1,
            VmPurgeable::Empty => 2,
        };
        // Contents made nonvolatile again after they were discarded are
        // no longer the surface's.
        if state & !0x760 == 0 && old == VmPurgeable::Empty {
            s.desc.flags = (s.desc.flags & !0xc) | 0x20;
        }
        ret::SUCCESS
    });
    a.scalar_out[0] = old_out;
    r
}

/// `vm_object_purge`: the pages discarded, so every task's view and the
/// backing store read zero.
fn purge(k: &mut Kernel, s: &mut Surface) {
    let Some(mem) = s.memory.as_mut() else { return };
    let len = mem.backing.len();
    let _ = k.darwin_own_memory(|k, m| {
        let zero = vec![0u8; len];
        mem.kernel_write(k, m, 0, &zero);
    });
}

// ---------------------------------------------------------------------------
// Values.

/// The method's id (the input's first word) and the rest of the input
/// after the second word; inputs of 9 bytes or more only.
fn id_and_payload(k: &mut Kernel, a: &MethodArgs) -> Result<(u32, Vec<u8>), i32> {
    let b = struct_input(k, a)?;
    if b.len() < 9 {
        return Err(ret::BAD_ARGUMENT);
    }
    Ok((u32::from_le_bytes(b[..4].try_into().unwrap()), b[8..].to_vec()))
}

/// `setValue(key, value)` (0xfffffff005ba0a30) in the surface's graph,
/// `value` of `from`: "CreationProperties" is ignored; "IOSurfaceName"
/// also names the memory descriptor (its context, which only the kernel's
/// own accounting reads).
fn set_one(s: &mut Surface, key: &[u8], from: &Graph, value: Id) {
    if key == b"CreationProperties" {
        return;
    }
    let v = ensure_values(s);
    let imported = s.graph.import(from, value);
    s.graph.dict_set(v, key, imported);
}

/// Selector 9 (0xfffffff005bade5c, 0xfffffff005bb01bc): {id, -, payload}:
/// an array of the value and, optionally, its key (a string); without a
/// key, a dictionary whose entries are each set. The new value seed out.
fn set_value(k: &mut Kernel, uc: u32, a: &mut MethodArgs) -> i32 {
    let (id, payload) = match id_and_payload(k, a) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if root(|r| handle(r, uc, id).is_none()) {
        return ret::BAD_ARGUMENT;
    }
    let Some((g, arr)) = super::unserialize(k, "an IOSurface value", &payload) else { return ret::BAD_ARGUMENT };
    let Obj::Array(items) = g.get(arr).clone() else { return ret::BAD_ARGUMENT };
    let Some(&value) = items.first() else { return ret::BAD_ARGUMENT };
    let key = match items.get(1) {
        None => None,
        Some(&kid) => match g.get(kid) {
            Obj::String(s) | Obj::Symbol(s) => Some(s.clone()),
            _ => return ret::BAD_ARGUMENT,
        },
    };
    let entries: Vec<(Vec<u8>, Id)> = match key {
        Some(key) => vec![(key, value)],
        None => match g.get(value) {
            Obj::Dict(e) => e.clone(),
            _ => Vec::new(),
        },
    };
    let ok = key_or_dict_ok(&g, value, items.get(1).is_some());
    let seed = root(|r| {
        if let Some(s) = r.surfaces.get_mut(&id) {
            if ok {
                for (key, v) in &entries {
                    set_one(s, key, &g, *v);
                }
            }
        }
        bump_value_seed(k, r, id)
    });
    a.struct_out.copy_from_slice(&seed.to_le_bytes());
    if ok { ret::SUCCESS } else { kr::INTERNAL_ERROR }
}

/// Whether a keyless value is a dictionary (the whole set fails else).
fn key_or_dict_ok(g: &Graph, value: Id, keyed: bool) -> bool {
    keyed || matches!(g.get(value), Obj::Dict(_))
}

/// The key a value method's payload names: `None` for all of them (an
/// empty string), `Err` when it does not end in a NUL.
fn payload_key(payload: &[u8]) -> Result<Option<Vec<u8>>, i32> {
    if payload[0] == 0 {
        return Ok(None);
    }
    if *payload.last().unwrap() != 0 {
        return Err(ret::BAD_ARGUMENT);
    }
    let n = payload.iter().position(|&c| c == 0).unwrap();
    Ok(Some(payload[..n].to_vec()))
}

/// Selector 10 (0xfffffff005bb02e4) and selector 26 (`data`,
/// 0xfffffff005bb22f8): a value (all of them for no key) serialized after
/// the value seed, or an OSData's bytes alone.
fn copy_value(k: &mut Kernel, uc: u32, a: &mut MethodArgs, data: bool) -> i32 {
    let (id, payload) = match id_and_payload(k, a) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let out_size = a.struct_out_size();
    if !data && out_size < 9 {
        return ret::BAD_ARGUMENT;
    }
    let key = match payload_key(&payload) {
        Ok(k) => k,
        Err(e) => return e,
    };
    enum Out {
        None,
        Bytes(Vec<u8>, u32),
        Err(i32),
    }
    let out = root(|r| {
        if handle(r, uc, id).is_none() {
            return Out::Err(ret::BAD_ARGUMENT);
        }
        let seed = ro_u32(r, id, ro::VALUE_SEED);
        let s = r.surfaces.get_mut(&id).unwrap();
        let values = ensure_values(s);
        let found = match &key {
            None => Some(values),
            Some(key) => s.graph.lookup(values, key),
        };
        let Some(v) = found else { return Out::None };
        if data {
            return match (key.is_some(), s.graph.get(v)) {
                (true, Obj::Data(d)) => Out::Bytes(d.clone(), seed),
                _ => Out::Err(ret::UNSUPPORTED),
            };
        }
        // binaryWithCapacity(outSize - 8) fails under a word.
        if out_size < 12 {
            return Out::Err(ret::NO_MEMORY);
        }
        Out::Bytes(os::serialize_binary(&s.graph, v), seed)
    });
    match out {
        Out::Err(e) => e,
        Out::None => {
            let _ = struct_output(k, a, &[]);
            ret::SUCCESS
        }
        Out::Bytes(bytes, seed) => {
            let len = bytes.len() as u64;
            // The size hint raised to what the value needs.
            root(|r| {
                if u64::from(ro_u32(r, id, ro::VALUE_SIZE_HINT)) < len {
                    ro_set_u32(k, r, id, ro::VALUE_SIZE_HINT, len as u32);
                }
            });
            if data {
                if len > out_size {
                    // The size it needs, told back.
                    match a.ool_out {
                        Some((addr, _)) => a.ool_out = Some((addr, len)),
                        None => a.struct_out.resize((len as usize).min(super::super::iokit::STRUCT_INBAND_MAX), 0),
                    }
                    return kr::NO_SPACE;
                }
                return match struct_output(k, a, &bytes) {
                    Ok(()) => ret::SUCCESS,
                    Err(e) => e,
                };
            }
            if len + 8 > out_size {
                return kr::NO_SPACE;
            }
            let mut out = vec![0u8; 8];
            out[4..8].copy_from_slice(&seed.to_le_bytes());
            out.extend_from_slice(&bytes);
            match struct_output(k, a, &out) {
                Ok(()) => ret::SUCCESS,
                Err(e) => e,
            }
        }
    }
}

/// Selector 11 (0xfffffff005bb04c4): a value removed (all of them, to be
/// made again from the defaults, for no key; "CreationProperties" never);
/// the new value seed out.
fn remove_value(k: &mut Kernel, uc: u32, a: &mut MethodArgs) -> i32 {
    let (id, payload) = match id_and_payload(k, a) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let key = match payload_key(&payload) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let r = root(|r| {
        if handle(r, uc, id).is_none() {
            return Err(ret::BAD_ARGUMENT);
        }
        let s = r.surfaces.get_mut(&id).unwrap();
        match &key {
            None => s.values = None,
            Some(key) if key == b"CreationProperties" => {}
            Some(key) => {
                let v = ensure_values(s);
                s.graph.dict_remove(v, key);
            }
        }
        Ok(bump_value_seed(k, r, id))
    });
    match r {
        Ok(seed) => {
            a.struct_out.copy_from_slice(&seed.to_le_bytes());
            ret::SUCCESS
        }
        Err(e) => e,
    }
}

// ---------------------------------------------------------------------------
// Bulk attachments.

/// The bulk record's fields: each mask bit's offset in the 0x70 bytes and
/// its length (0xfffffff005ba145c).
const BULK_FIELDS: [(usize, usize); 15] = [(0x00, 0x20), (0x20, 0x10), (0x30, 8), (0x38, 1), (0x39, 1), (0x3a, 1), (0x3b, 1), (0x3c, 1), (0x3d, 1), (0x3e, 1), (0x3f, 1), (0x40, 0x18), (0x58, 4), (0x5c, 8), (0x64, 1)];

/// Selector 27 (0xfffffff005bb0e08): the fields the mask (at 0x78) names
/// copied from the 136-byte input (id at 0x80) into the record; field 15
/// also into the surface.
fn set_bulk(k: &mut Kernel, uc: u32, a: &mut MethodArgs) -> i32 {
    let b = a.struct_in.clone();
    let mask = u64::from_le_bytes(b[0x78..0x80].try_into().unwrap());
    let id = u32::from_le_bytes(b[0x80..0x84].try_into().unwrap());
    root(|r| {
        if handle(r, uc, id).is_none() {
            return ret::BAD_ARGUMENT;
        }
        for (bit, &(off, len)) in BULK_FIELDS.iter().enumerate() {
            if mask & (1 << bit) != 0 {
                r.shared.ro_write(k, id, ro::BULK + off as u64, &b[off..off + len]);
            }
        }
        if mask & (1 << 15) != 0 {
            let f = (u32::from_le_bytes(b[0x68..0x6c].try_into().unwrap()), u16::from_le_bytes(b[0x6c..0x6e].try_into().unwrap()), u16::from_le_bytes(b[0x6e..0x70].try_into().unwrap()));
            r.surfaces.get_mut(&id).unwrap().bulk15 = f;
            r.shared.ro_write(k, id, ro::BULK + 0x68, &b[0x68..0x70]);
        }
        ret::SUCCESS
    })
}

/// Selector 28 (0xfffffff005bb0e60): the record's 0x70 bytes, field 15
/// from the surface and bytes 0x65 to 0x67 zero; the output's size 0x88.
fn get_bulk(uc: u32, a: &mut MethodArgs) -> i32 {
    let id = a.scalar_in[0] as u32;
    root(|r| {
        if handle(r, uc, id).is_none() {
            return ret::BAD_ARGUMENT;
        }
        let mut b = r.shared.ro_read(id, ro::BULK, 0x70);
        b[0x65..0x68].fill(0);
        let (x, y, z) = r.surfaces[&id].bulk15;
        b[0x68..0x6c].copy_from_slice(&x.to_le_bytes());
        b[0x6c..0x6e].copy_from_slice(&y.to_le_bytes());
        b[0x6e..0x70].copy_from_slice(&z.to_le_bytes());
        a.struct_out[..0x70].copy_from_slice(&b);
        ret::SUCCESS
    })
}

// ---------------------------------------------------------------------------
// The rest.

/// Selector 5 (0xfffffff005ba0950): the record's YCbCr matrix byte.
fn set_ycbcr_matrix(k: &mut Kernel, uc: u32, id: u32, m: u64) -> i32 {
    root(|r| {
        if handle(r, uc, id).is_none() {
            return ret::BAD_ARGUMENT;
        }
        r.shared.ro_write(k, id, ro::YCBCR_MATRIX, &[m as u8]);
        ret::SUCCESS
    })
}

/// Selector 8 (0xfffffff005bade2c): the matrix byte as the method's
/// result, the scalar out 0.
fn get_ycbcr_matrix(uc: u32, id: u32, a: &mut MethodArgs) -> i32 {
    a.scalar_out[0] = 0;
    root(|r| {
        if handle(r, uc, id).is_none() {
            return ret::BAD_ARGUMENT;
        }
        i32::from(r.shared.ro_read(id, ro::YCBCR_MATRIX, 1)[0])
    })
}

/// Selector 13 (0xfffffff005bae17c): the root's limits as IOGPU's start
/// left them (0xfffffff005baaf34 over AGXG9G's 0xfffffff005c2569c): the
/// offset mask 0x3fff, the row mask 0x3f, the largest row 0x8000 bytes,
/// width and height 0x4000; whether the client may write the read-write
/// records; version 1.
fn limits(uc: u32, a: &mut MethodArgs) -> i32 {
    let (params, privileged) = root(|r| (r.params, r.clients.get(&uc).is_some_and(|c| c.protected_access)));
    let mut b = [0u8; 40];
    b[0..4].copy_from_slice(&(params.offset_mask as u32).to_le_bytes());
    b[4..8].copy_from_slice(&(params.row_mask as u32).to_le_bytes());
    b[8..16].copy_from_slice(&0x8000u64.to_le_bytes());
    b[16..24].copy_from_slice(&0x4000u64.to_le_bytes());
    b[24..32].copy_from_slice(&0x4000u64.to_le_bytes());
    b[0x20] = u8::from(privileged);
    b[0x22..0x24].copy_from_slice(&1u16.to_le_bytes());
    a.struct_out.copy_from_slice(&b);
    ret::SUCCESS
}

/// Selector 19 (0xfffffff005bae258): a NUL-terminated line of at most 0x1ff
/// bytes, `kprintf("%.512s")` to the console.
fn log(k: &mut Kernel, a: &mut MethodArgs) -> i32 {
    if a.ool_in.is_some() {
        return ret::NO_MEMORY;
    }
    let b = &a.struct_in;
    if b.len() > 0x1ff {
        return ret::BAD_ARGUMENT;
    }
    if b.is_empty() || *b.last().unwrap() != 0 {
        return ret::BAD_ARGUMENT;
    }
    let n = b.iter().position(|&c| c == 0).unwrap().min(512);
    eprint!("{}", String::from_utf8_lossy(&b[..n]));
    let _ = k;
    ret::SUCCESS
}

/// Selectors 21 and 44 (0xfffffff005b9df94, 0xfffffff005bae8d4): the
/// memory's ledger owner set (`setOwnership`) to the task a send right (21)
/// or identity token (44) names.
fn set_ownership(k: &mut Kernel, uc: u32, a: &mut MethodArgs) -> i32 {
    let id = a.scalar_in[0] as u32;
    let name = a.scalar_in[1] as u32;
    if name == 0 || name == u32::MAX {
        return ret::BAD_ARGUMENT;
    }
    let is_task = match k.ipc().translate_send(name) {
        Ok(p) => matches!(k.ipc().port(p).kobject, Some(super::super::ipc::Kobject::Task)),
        Err(_) => false,
    };
    if !is_task {
        return ret::BAD_ARGUMENT;
    }
    let r = with_surface(uc, id, |_, s| if s.memory.is_none() { ret::BAD_ARGUMENT } else { ret::SUCCESS });
    if r != ret::SUCCESS {
        return r;
    }
    k.darwin_unimplemented(format!("IOSurfaceRootUserClient selector {}: the ledger ownership of IOSurface {id:#x}'s memory", a.selector));
    ret::UNSUPPORTED
}

/// Selector 24 (0xfffffff005bb0c40): {id, -, timestamp, [category, name]}.
/// Without the `iosurface_timestamp_enable` boot-arg it does nothing.
fn set_timestamp(k: &mut Kernel, uc: u32, a: &mut MethodArgs) -> i32 {
    let b = match struct_input(k, a) {
        Ok(b) => b,
        Err(e) => return e,
    };
    if b.len() < 17 {
        return ret::BAD_ARGUMENT;
    }
    let id = u32::from_le_bytes(b[..4].try_into().unwrap());
    if root(|r| handle(r, uc, id).is_none()) {
        return ret::BAD_ARGUMENT;
    }
    let Some((g, arr)) = super::unserialize(k, "an IOSurface timestamp", &b[16..]) else { return ret::BAD_ARGUMENT };
    match g.get(arr) {
        Obj::Array(v) if v.len() >= 2 && v[..2].iter().all(|&i| matches!(g.get(i), Obj::String(_) | Obj::Symbol(_))) => ret::SUCCESS,
        _ => ret::BAD_ARGUMENT,
    }
}

/// Selector 30 (0xfffffff005bb2c0c): the root's description of every
/// surface, for a client entitled to it.
fn descriptions(k: &mut Kernel, uc: u32, a: &mut MethodArgs) -> i32 {
    if !root(|r| r.clients.get(&uc).is_some_and(|c| c.info)) {
        return kr::NOT_PRIVILEGED;
    }
    let _ = a;
    k.darwin_unimplemented("IOSurfaceRootUserClient selector 30 (the root's description of its surfaces)".to_string());
    ret::UNSUPPORTED
}

/// Selector 31 (0xfffffff005ba3444): a plane's compressed tile data
/// memory used (planes 0 to 4).
fn set_tile_data_used(k: &mut Kernel, uc: u32, id: u32, plane: u64, value: u64) -> i32 {
    root(|r| {
        if handle(r, uc, id).is_none() {
            return ret::BAD_ARGUMENT;
        }
        if plane > 4 || plane >= r.surfaces[&id].desc.planes.len() as u64 {
            return ret::BAD_ARGUMENT;
        }
        r.shared.ro_write(k, id, ro::TILE_DATA_USED + 4 * plane, &(value as u32).to_le_bytes());
        ret::SUCCESS
    })
}

/// Selector 32 (0xfffffff005bae740): the graphics comm page's address in
/// the caller's task.
fn comm_page(uc: u32, a: &mut MethodArgs) -> i32 {
    let addr = root(|r| r.clients.get(&uc).map_or(0, |c| super::shared::comm_address(&c.shared)));
    if addr == 0 {
        return ret::NO_MEMORY;
    }
    a.scalar_out[0] = addr;
    ret::SUCCESS
}

/// Selector 33 (0xfffffff005ba33a8): indexed timestamp 0 to 4 of the
/// read-write record.
fn set_indexed_timestamp(k: &mut Kernel, uc: u32, id: u32, index: u64, value: u64) -> i32 {
    root(|r| {
        if handle(r, uc, id).is_none() {
            return ret::BAD_ARGUMENT;
        }
        if index > 4 {
            return ret::BAD_ARGUMENT;
        }
        r.shared.rw_write(k, id, rw::TIMESTAMPS + 8 * index, &value.to_le_bytes());
        ret::SUCCESS
    })
}

/// Selector 43 (0xfffffff005ba4ee4): the detach mode code's masked bits,
/// and its time when one is given.
fn detach_mode(k: &mut Kernel, uc: u32, id: u32, mask: u64, value: u64, ts: u64) -> i32 {
    root(|r| {
        if handle(r, uc, id).is_none() {
            return ret::BAD_ARGUMENT;
        }
        if ts != 0 {
            r.shared.rw_write(k, id, rw::DETACH_TIME, &ts.to_le_bytes());
        }
        let old = u64::from_le_bytes(r.shared.rw_read(k, id, rw::DETACH_MODE, 8).try_into().unwrap());
        r.shared.rw_write(k, id, rw::DETACH_MODE, &((old & !mask) | (value & mask)).to_le_bytes());
        ret::SUCCESS
    })
}

/// Selector 50 (0xfffffff005ba4fc4): data property `index` (0 to 3, at most
/// 0x400 bytes, inband only) set, its presence bit in the record.
fn set_data(k: &mut Kernel, uc: u32, id: u32, index: u64, a: &mut MethodArgs) -> i32 {
    if a.ool_in.is_some() || index > 3 || a.struct_in.len() > 0x400 {
        return ret::BAD_ARGUMENT;
    }
    let bytes = a.struct_in.clone();
    root(|r| {
        if handle(r, uc, id).is_none() {
            return ret::BAD_ARGUMENT;
        }
        let s = r.surfaces.get_mut(&id).unwrap();
        s.data[index as usize] = None;
        if bytes.is_empty() {
            return ret::SUCCESS;
        }
        s.data[index as usize] = Some(bytes);
        let bits = r.shared.ro_read(id, ro::DATA_PROPERTIES, 1)[0] | 1 << index;
        r.shared.ro_write(k, id, ro::DATA_PROPERTIES, &[bits]);
        ret::SUCCESS
    })
}

/// Selector 51 (0xfffffff005ba5118): data property `index`'s bytes, the
/// copy's result and the length as scalars (kIOReturnOverrun when they do
/// not fit).
fn get_data(uc: u32, id: u32, index: u64, a: &mut MethodArgs) -> i32 {
    if a.ool_out.is_some() || index > 3 {
        return ret::BAD_ARGUMENT;
    }
    root(|r| {
        if handle(r, uc, id).is_none() {
            return ret::BAD_ARGUMENT;
        }
        let d = r.surfaces[&id].data[index as usize].clone().unwrap_or_default();
        let fits = d.len() <= a.struct_out.len();
        a.scalar_out[0] = if fits { 0 } else { kr::OVERRUN as u32 as i64 as u64 };
        a.scalar_out[1] = d.len() as u64;
        if fits {
            a.struct_out.truncate(d.len());
            a.struct_out.copy_from_slice(&d);
        } else {
            a.struct_out.truncate(0);
        }
        ret::SUCCESS
    })
}

/// Selector 52 (0xfffffff005bb2e58): every data property freed.
fn clear_data(k: &mut Kernel, uc: u32, a: &mut MethodArgs) -> i32 {
    if a.ool_out.is_some() {
        return ret::BAD_ARGUMENT;
    }
    let id = a.scalar_in[0] as u32;
    root(|r| {
        if handle(r, uc, id).is_none() {
            return ret::BAD_ARGUMENT;
        }
        r.surfaces.get_mut(&id).unwrap().data = Default::default();
        r.shared.ro_write(k, id, ro::DATA_PROPERTIES, &[0]);
        ret::SUCCESS
    })
}
