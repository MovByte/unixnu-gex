//! IOSurface: `IOSurfaceRoot`, the service named `IOCoreSurfaceRoot` that
//! IOSurface.framework opens, its user client `IOSurfaceRootUserClient`,
//! and the surfaces they make, as `com.apple.iokit.IOSurface` in the 21H461
//! kernelcache has them (the addresses below are that kernelcache's).
//!
//! A surface is a description ([`surface`]), its memory ([`memory`]: a
//! kernel-owned backing store and each task's view of it), the records the
//! root keeps for it in pages every client maps ([`shared`]: its seed, use
//! counts, bulk attachments), and its values (attachments). A task reaches
//! one through a handle in its user client, the kernel's `IOSurfaceClient`,
//! made by creating the surface, by looking it up by id, or by looking it up
//! by a send right to it.

pub mod executor;
pub mod memory;
mod methods;
pub mod shared;
pub mod surface;

pub use methods::send_right_in_task;

use super::iokit::{ret, MethodArgs, Node, Prop, VARIABLE};
use super::osserialize::{self as os, Graph, Id, Obj};
use crate::syscalls::Kernel;
use crate::GuestMem;
use surface::{flag, Desc};

/// The service's class, its name (`setName`, 0xfffffff005ba9648) and its
/// user client's class.
pub const CLASS: &str = "IOSurfaceRoot";
pub const NAME: &str = "IOCoreSurfaceRoot";
pub const UC_CLASS: &str = "IOSurfaceRootUserClient";

/// The classes, most derived first: the root an `IOService`, its client an
/// `IOUserClient2022` (their OSMetaClass constructors, 0xfffffff005ba8adc
/// and 0xfffffff005bada18).
pub fn superclasses(class: &str) -> &'static [&'static str] {
    match class {
        CLASS => &[CLASS, "IOService", "IORegistryEntry"],
        UC_CLASS => &[UC_CLASS, "IOUserClient2022", "IOUserClient", "IOService", "IORegistryEntry"],
        _ => &[],
    }
}

/// Whether tree entry `i` is the root, whose properties are all those
/// [`shared::add_service`] gives it: a name it has none of is no property.
pub fn is_service(i: u32) -> bool {
    super::iokit::tree().get(i as usize).is_some_and(|n| n.class == CLASS)
}

/// Whether every service of `class` is here: there is one IOSurfaceRoot.
pub fn class_complete(class: &str) -> bool {
    class == CLASS
}

/// Whether every service named `name` is here: only the root takes its
/// name.
pub fn name_complete(name: &str) -> bool {
    name == NAME
}

/// IOReturn codes beyond [`ret`].
mod kr {
    pub const INTERNAL_ERROR: i32 = 0xe00002c9_u32 as i32;
    pub const NOT_PRIVILEGED: i32 = 0xe00002c1_u32 as i32;
    pub const NO_SPACE: i32 = 0xe00002db_u32 as i32;
    pub const OVERRUN: i32 = 0xe00002e8_u32 as i32;
}

/// The root's `iosurface_debug` with no boot-arg (0xfffffff005ba95c8).
const DEBUG_DEFAULT: u32 = 0x10;

/// The size of the create, lookup and lock replies.
pub const REPLY_SIZE: usize = 0xc68;

/// The service in the registry ([`shared::add_service`]).
pub fn add_service(t: &mut Vec<Node>, resources: u32) {
    shared::add_service(t, resources);
}

/// One surface.
pub struct Surface {
    pub id: u32,
    pub desc: Desc,
    /// `+0xc`: its references (each client's, each child's, each send
    /// right's).
    refs: u32,
    /// `+0x170`: the creating task, until its user client stops.
    creator: Option<i32>,
    parent: Option<u32>,
    trace_id: u64,
    /// `+0x39c`, `+0x390`: its clients (handles and send rights) and wired
    /// send rights.
    clients: u32,
    wired: u32,
    /// In the root's table (found by id) and its list.
    installed: bool,
    /// `+0x218`, `+0x21c`: read-only and read-write locks.
    ro_locks: u32,
    rw_locks: u32,
    /// `+0x208`: the purgeable state last set (IOKit's numbering).
    purgeable: u32,
    /// The memory's purgeable state (`vm_object_purgable_control`).
    vm_purgeable: VmPurgeable,
    /// Its memory (`+0x30`, an IOBufferMemoryDescriptor of the allocation
    /// rounded to pages): none for one with no allocation.
    memory: Option<memory::Memory>,
    /// The creation properties, the values and what they hold.
    graph: Graph,
    /// `+0x248`: the creation properties.
    props: Id,
    /// `+0x1a8`: the values, made when first needed.
    values: Option<Id>,
    /// `+0x1b0`: four data properties.
    data: [Option<Vec<u8>>; 4],
    /// `+0x368`, `+0x36c`, `+0x36e`: bulk field 15.
    bulk15: (u32, u16, u16),
    /// Bound to the GPU through the executor's surface table.
    gpu: bool,
}

/// The VM's purgeable states (`VM_PURGABLE_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VmPurgeable {
    NonVolatile,
    Volatile,
    Empty,
}

/// A handle: one user client's `IOSurfaceClient` (0x98 bytes) for one
/// surface.
#[derive(Clone, Debug)]
pub struct Handle {
    pub id: u32,
    /// `+0x70`: made by creating the surface.
    created: bool,
    /// `+0x50`: the memory's address in the task (0 when not mapped).
    base: u64,
    /// `+0x58`, `+0x60`: the shared records' addresses in the task.
    ro: u64,
    rw: u64,
    /// `+0x90`: the client's use counts, by category.
    use_counts: [u32; 2],
}

/// An `IOSurfaceRootUserClient` (0x138 bytes).
pub struct UserClient {
    pid: i32,
    /// `+0x100`: handles by surface id; its length is `+0x108`.
    handles: Vec<Option<Handle>>,
    /// `+0x130`: handles detached by trap 4, waiting for trap 5.
    invalidated: Vec<Handle>,
    /// `+0x120`, `+0x124`: surfaces created, and handles held.
    created: u32,
    total: u32,
    /// `+0x118`, `+0x11c`, `+0x11d`: messages given once.
    logged_global: bool,
    warned_8k: bool,
    warned_12k: bool,
    /// `+0x11a`: com.apple.private.iosurfaceinfo; `+0x11e`: that or
    /// com.apple.private.IOSurface.protected-access; `+0x11f`: a
    /// restricted GPU client.
    info: bool,
    protected_access: bool,
    pub restricted: bool,
    /// The task's mappings of the root's shared pages (`+0x110`) and of the
    /// graphics comm page (`+0x128`).
    shared: shared::TaskShared,
    /// Started and not stopped.
    live: bool,
}

/// The root (`IOSurfaceRoot`, 0x4a0 bytes).
pub struct Root {
    /// `+0xd8`: the id table's size; `+0xe8` the bitmap of ids in use;
    /// `+0xe0` the hint.
    table_size: u32,
    bitmap: Vec<u64>,
    hint: u64,
    surfaces: std::collections::BTreeMap<u32, Surface>,
    /// `+0x1f4`, `+0x1f0`: surfaces in the root's list, and whether their
    /// approach to the limit was told.
    count: u32,
    warned: bool,
    /// The trace id counter (0xfffffff005ba8ee8).
    next_trace: u64,
    pub shared: shared::Shared,
    clients: std::collections::BTreeMap<u32, UserClient>,
    next_client: u32,
    send_rights: std::collections::BTreeMap<u32, SendRight>,
    next_send_right: u32,
    params: surface::RootParams,
    /// `+0x250`: the displays that told the root what their layers show
    /// (eight at most, each its framebuffer and the allocation size of
    /// each of its four layers' surfaces), and `+0x248` the sum.
    displayed: [Option<(u64, [u64; 4])>; 8],
    displayed_bytes: u64,
}

/// An `IOSurfaceSendRight` (or `IOSurfaceWiredSendRight`): its surface,
/// whether it holds a category 0 use count, and whether it wires it.
struct SendRight {
    surface: u32,
    uses: bool,
    wired: bool,
}

static ROOT: std::sync::Mutex<Option<Root>> = std::sync::Mutex::new(None);

/// The root, started as `IOSurfaceRoot::start` leaves it at boot: its id
/// table grown once; its masks the cache line's (hw.cachelinesize, 64)
/// with what IOGPU's start adds (0xfffffff005baaf34 from
/// 0xfffffff005bd4310: the A10X accelerator's GPU page mask, 0x3fff, for
/// offsets and sizes, and 0xf for rows); its allocation limit a quarter of
/// `hw.memsize`.
fn root<R>(f: impl FnOnce(&mut Root) -> R) -> R {
    let mut g = ROOT.lock().unwrap_or_else(|e| e.into_inner());
    let r = g.get_or_insert_with(|| {
        let line = 64u64;
        let mut r = Root {
            table_size: 0,
            bitmap: Vec::new(),
            hint: 0,
            surfaces: Default::default(),
            count: 0,
            warned: false,
            next_trace: 0x0100_0000_0000_0000,
            shared: shared::Shared::default(),
            clients: Default::default(),
            next_client: 0,
            send_rights: Default::default(),
            next_send_right: 0,
            displayed: [None; 8],
            displayed_bytes: 0,
            params: surface::RootParams { row_mask: (line - 1) | 0xf, offset_mask: (line - 1) | 0x3fff, max_alloc: super::mig::machine::MEMORY >> 2, debug: DEBUG_DEFAULT, page_size: super::mach::PAGE_MASK + 1 },
        };
        r.grow();
        r
    });
    f(r)
}

impl Root {
    /// 0xfffffff005ba9848: the id table doubled (0x200 at first, never past
    /// 0x10000 entries); id 0 is never handed out.
    fn grow(&mut self) -> bool {
        let new = match self.table_size {
            0 => 0x200,
            s if s >= 0x1_0000 => return false,
            s => s * 2,
        };
        self.bitmap.resize((new / 64) as usize, 0);
        if self.table_size == 0 {
            self.bitmap[0] = 1;
        }
        self.table_size = new;
        true
    }

    /// alloc_surface_id (0xfffffff005babc40): the lowest free id from the
    /// hint up, the table grown when none is.
    fn alloc_id(&mut self) -> Option<u32> {
        loop {
            let from = (self.hint >> 6) as usize;
            if let Some((w, word)) = self.bitmap.iter().enumerate().skip(from).find(|(_, &w)| w != u64::MAX) {
                let bit = (!*word).trailing_zeros() as usize;
                let id = (w * 64 + bit) as u32;
                self.bitmap[w] |= 1 << bit;
                self.hint = u64::from(id) + 1;
                return Some(id);
            }
            let end = u64::from(self.table_size);
            if !self.grow() {
                return None;
            }
            self.hint = end;
        }
    }

    /// free_surface_id (0xfffffff005babe2c).
    fn free_id(&mut self, id: u32) {
        if id == 0 || id >= self.table_size {
            return;
        }
        self.hint = self.hint.min(u64::from(id));
        self.bitmap[(id / 64) as usize] &= !(1u64 << (id % 64));
    }
}

// ---------------------------------------------------------------------------
// The user client's life.

/// `IOSurfaceRoot::newUserClient` (0xfffffff005baa11c): type 0 only; the
/// client's `initWithTask` (0xfffffff005baed5c: its entitlements, its
/// IOSurfaceShared, the graphics comm page mapped into the task) and
/// `start` (0xfffffff005baf29c). Its number among the root's clients. A
/// failure (kIOReturnInternalError) sends IOService::newUserClient to the
/// service's IOUserClientClass, which it has none of: kIOReturnUnsupported.
pub fn new_user_client(k: &mut Kernel, ty: u32) -> Result<u32, i32> {
    if ty != 0 {
        return Err(ret::UNSUPPORTED);
    }
    let ent = |k: &Kernel, key: &str| {
        use super::codesign::Ent;
        k.dtask.codesign.as_ref().is_some_and(|c| matches!(c.ents.get(key.as_bytes()), Some(Ent::Bool(true))))
    };
    let info = ent(k, "com.apple.private.iosurfaceinfo");
    let protected_access = info || ent(k, "com.apple.private.IOSurface.protected-access");
    let restricted = ent(k, "com.apple.private.gpu-restricted") || ent(k, "com.apple.developer.gpu-restricted");
    let mut uc = UserClient {
        pid: k.pid,
        handles: Vec::new(),
        invalidated: Vec::new(),
        created: 0,
        total: 0,
        logged_global: false,
        warned_8k: false,
        warned_12k: false,
        info,
        protected_access,
        restricted,
        shared: shared::TaskShared::default(),
        live: true,
    };
    shared::start(k, &mut uc)?;
    Ok(root(|r| {
        let id = r.next_client;
        r.next_client += 1;
        r.clients.insert(id, uc);
        id
    }))
}

/// The properties `start` sets on the client (0xfffffff005baf29c).
pub fn client_property(name: &str) -> Option<Prop> {
    match name {
        "IOUserClientEntitlements" => Some(Prop::Bool(false)),
        "IOUserClientDefaultLocking" => Some(Prop::Bool(false)),
        "IOUserClientDefaultLockingSetProperties" => Some(Prop::Bool(true)),
        "IOUserClientDefaultLockingSingleThreadExternalMethod" => Some(Prop::Bool(false)),
        _ => None,
    }
}

/// Whether user client `uc` is a restricted GPU client (`+0x11f`).
pub fn restricted(uc: u32) -> bool {
    root(|r| r.clients.get(&uc).is_some_and(|c| c.restricted))
}

/// `clientClose` (0xfffffff005baf3d0: terminate, so `stop`,
/// 0xfffffff005baf368): unregistered from the root, and the surfaces its
/// task created no longer that task's own (0xfffffff005baafcc).
pub fn client_close(_k: &mut Kernel, uc: u32) {
    root(|r| {
        let Some(c) = r.clients.get_mut(&uc) else { return };
        if !c.live {
            return;
        }
        c.live = false;
        let pid = c.pid;
        for s in r.surfaces.values_mut() {
            if s.creator == Some(pid) {
                s.creator = None;
            }
        }
    });
}

/// `free` (0xfffffff005baf0e0): every handle, held or detached, released,
/// and the task's mappings of the shared pages with it.
pub fn client_free(k: &mut Kernel, uc: u32) {
    client_close(k, uc);
    let Some(c) = root(|r| r.clients.remove(&uc)) else { return };
    let pid = c.pid;
    for h in c.handles.into_iter().flatten().chain(c.invalidated) {
        root(|r| release_handle(k, r, pid, h));
    }
    shared::stop(k, pid, c.shared);
}

// ---------------------------------------------------------------------------
// Surfaces' references and mappings.

/// A reference on surface `id` let go: at the last, the surface is torn
/// down (0xfffffff005b9c878): out of the root's list and table, its id
/// freed, its records cleared, its parent's reference released.
fn surface_release(k: &mut Kernel, r: &mut Root, id: u32) {
    let Some(s) = r.surfaces.get_mut(&id) else { return };
    s.refs -= 1;
    if s.refs > 0 {
        return;
    }
    let s = r.surfaces.remove(&id).unwrap();
    // removeSurface (0xfffffff005baa374).
    r.count -= 1;
    if r.count <= 0x4000 {
        r.warned = false;
    }
    if s.gpu {
        if let Some(t) = executor::table() {
            t.released(id);
        }
    }
    r.free_id(id);
    if let Some(p) = s.parent {
        surface_release(k, r, p);
    }
}

/// The memory of surface `s` mapped into the calling task
/// (`createMappingInTask(task, 0, kIOMapAnywhere | cache mode, 0, 0)`,
/// 0xfffffff005ba5a00: the whole descriptor, writable since its direction
/// is InOut), or that task's mapping of it taken again; its address, or 0
/// for a surface that maps nothing (protected, host-only, or with no
/// memory).
fn map_into_task(k: &mut Kernel, s: &mut Surface) -> Result<u64, i32> {
    if s.desc.protection != 0 || s.desc.flags & flag::HOST_ONLY != 0 {
        return Ok(0);
    }
    let Some(mem) = s.memory.as_mut() else { return Ok(0) };
    mem.map(k, false, false).map_err(|_| ret::NO_MEMORY)
}

/// A handle released (`IOSurfaceClient::free`, 0xfffffff005ba5ad0): its
/// use counts given back, the surface's client count lowered (the last
/// clears flag bits 2 and 3), its mapping and its reference let go.
fn release_handle(k: &mut Kernel, r: &mut Root, pid: i32, h: Handle) {
    for cat in 0..2 {
        if h.use_counts[cat] != 0 {
            use_count_decrement(k, r, h.id, cat);
        }
    }
    if let Some(s) = r.surfaces.get_mut(&h.id) {
        s.clients -= 1;
        if s.clients == 0 {
            s.desc.flags &= !0xc;
        }
        if h.base != 0 {
            if let Some(mem) = s.memory.as_mut() {
                mem.unmap(k, pid, h.base);
            }
        }
    }
    surface_release(k, r, h.id);
}

// ---------------------------------------------------------------------------
// The shared records' fields.

/// Offsets in a surface's read-only record (0xb8 bytes).
pub mod ro {
    pub const DEVICE_TOKEN: u64 = 0x00;
    pub const SEED: u64 = 0x0c;
    pub const WRITE_UNLOCKS: u64 = 0x10;
    pub const TILED: u64 = 0x14;
    pub const USE_COUNT: u64 = 0x18;
    pub const VALUE_SEED: u64 = 0x20;
    pub const VALUE_SIZE_HINT: u64 = 0x28;
    pub const PIXEL_SIZE_CASTING: u64 = 0x2c;
    pub const DISPLAYABLE: u64 = 0x2d;
    pub const SYS_MEM_ONLY: u64 = 0x2e;
    pub const DATA_PROPERTIES: u64 = 0x2f;
    pub const BULK: u64 = 0x30;
    pub const YCBCR_MATRIX: u64 = 0x6a;
    pub const TILE_DATA_USED: u64 = 0xa0;
    pub const SIZE: u64 = 0xb8;
}

/// Offsets in a surface's read-write record (0x40 bytes).
pub mod rw {
    pub const TIMESTAMPS: u64 = 0x00;
    pub const DETACH_TIME: u64 = 0x10;
    pub const DETACH_MODE: u64 = 0x28;
    pub const SIZE: u64 = 0x40;
}

fn ro_u32(r: &Root, id: u32, at: u64) -> u32 {
    u32::from_le_bytes(r.shared.ro_read(id, at, 4).try_into().unwrap())
}

fn ro_set_u32(k: &mut Kernel, r: &mut Root, id: u32, at: u64, v: u32) {
    r.shared.ro_write(k, id, at, &v.to_le_bytes());
}

// ---------------------------------------------------------------------------
// Use counts.

/// The surface's use count of `cat` raised (0xfffffff005b9f758), and each
/// ancestor's, up to one that prohibits use counts.
fn use_count_increment(k: &mut Kernel, r: &mut Root, id: u32, cat: usize) {
    let mut at = Some(id);
    while let Some(i) = at {
        let Some(s) = r.surfaces.get(&i) else { return };
        if s.desc.flags & flag::PROHIBIT_USE_COUNT != 0 {
            return;
        }
        let parent = s.parent;
        let off = ro::USE_COUNT + 4 * cat as u64;
        let v = ro_u32(r, i, off);
        ro_set_u32(k, r, i, off, v.saturating_add(1));
        at = parent;
    }
}

/// The surface's use count of `cat` lowered (0xfffffff005b9f814), and each
/// ancestor's: a surface no longer in use does what it asked to then.
fn use_count_decrement(k: &mut Kernel, r: &mut Root, id: u32, cat: usize) {
    let mut at = Some(id);
    while let Some(i) = at {
        let Some(s) = r.surfaces.get(&i) else { return };
        if s.desc.flags & flag::PROHIBIT_USE_COUNT != 0 {
            return;
        }
        let parent = s.parent;
        let off = ro::USE_COUNT + 4 * cat as u64;
        let old = ro_u32(r, i, off);
        let new = old.saturating_sub(1);
        ro_set_u32(k, r, i, off, new);
        let other = ro_u32(r, i, ro::USE_COUNT + 4 * (1 - cat) as u64);
        if old == 1 && new == 0 && other == 0 {
            not_in_use(k, r, i);
        }
        at = parent;
    }
}

/// What a surface no longer in use does: drops its content flags
/// (PurgeWhenNotInUse), resets its values (ResetDefaultAttachments...), and
/// notifies the clients that asked (root's 0xfffffff005babacc).
fn not_in_use(k: &mut Kernel, r: &mut Root, id: u32) {
    let flags = r.surfaces[&id].desc.flags;
    if flags & flag::PURGE_WHEN_NOT_IN_USE != 0 {
        r.surfaces.get_mut(&id).unwrap().desc.flags &= !0xc;
    }
    if flags & flag::RESET_DEFAULT_ATTACHMENTS_WHEN_NOT_IN_USE != 0 {
        reset_default_attachments(k, r, id);
    }
    if r.shared.notifies(id) {
        k.darwin_unimplemented(format!("IOSurface {id:#x} no longer in use: its surface notifications (selector 17)"));
    }
}

/// 0xfffffff005b9f930: values that differ from the default attachments are
/// made again from them (the value seed raised); else only the bulk record
/// goes back to the defaults.
fn reset_default_attachments(k: &mut Kernel, r: &mut Root, id: u32) {
    let s = r.surfaces.get_mut(&id).unwrap();
    let bulk = s.desc.default_bulk.unwrap_or([0; 0x70]);
    let differ = match (s.values, s.desc.default_attachments) {
        (Some(v), Some(d)) => !dict_equal(&s.graph, v, d),
        _ => false,
    };
    if differ {
        s.values = None;
        ensure_values(s);
        r.shared.ro_write(k, id, ro::BULK, &bulk);
        bump_value_seed(k, r, id);
    } else {
        r.shared.ro_write(k, id, ro::BULK, &bulk);
    }
}

/// `OSDictionary::isEqualTo(OSDictionary)`: the same keys, each value
/// `isEqualTo` the other's.
fn dict_equal(g: &Graph, a: Id, b: Id) -> bool {
    fn eq(g: &Graph, a: Id, b: Id) -> bool {
        if a == b {
            return true;
        }
        match (g.get(a), g.get(b)) {
            (Obj::Dict(x), Obj::Dict(y)) => x.len() == y.len() && x.iter().all(|(k, v)| y.iter().find(|(k2, _)| k2 == k).is_some_and(|(_, v2)| eq(g, *v, *v2))),
            (Obj::Array(x), Obj::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| eq(g, *p, *q)),
            (Obj::Set(x), Obj::Set(y)) => x.len() == y.len() && x.iter().all(|p| y.iter().any(|q| eq(g, *p, *q))),
            (Obj::Number { .. }, Obj::Number { .. }) => g.u64_value(a) == g.u64_value(b),
            (Obj::String(x) | Obj::Symbol(x), Obj::String(y) | Obj::Symbol(y)) => x == y,
            (Obj::Data(x), Obj::Data(y)) => x == y,
            (Obj::Bool(x), Obj::Bool(y)) => x == y,
            _ => false,
        }
    }
    eq(g, a, b)
}

// ---------------------------------------------------------------------------
// Values.

/// 0xfffffff005b9d380: the values, made when first needed:
/// "CreationProperties", the creation's "IOSurfaceName" when it is a
/// string, and every default attachment but "CreationProperties".
fn ensure_values(s: &mut Surface) -> Id {
    if let Some(v) = s.values {
        return v;
    }
    let v = s.graph.add(Obj::Dict(Vec::new()));
    s.graph.dict_set(v, b"CreationProperties", s.props);
    if let Some(n) = s.graph.lookup(s.props, b"IOSurfaceName") {
        if matches!(s.graph.get(n), Obj::String(_)) {
            s.graph.dict_set(v, b"IOSurfaceName", n);
        }
    }
    if let Some(d) = s.desc.default_attachments {
        if let Obj::Dict(e) = s.graph.get(d).clone() {
            for (key, val) in e {
                if key != b"CreationProperties" {
                    s.graph.dict_set(v, &key, val);
                }
            }
        }
    }
    s.values = Some(v);
    v
}

/// The value seed raised past any a client could have cached:
/// `(seed | 1) + 2` (0xfffffff005ba0a78); the new seed.
fn bump_value_seed(k: &mut Kernel, r: &mut Root, id: u32) -> u32 {
    let v = (ro_u32(r, id, ro::VALUE_SEED) | 1).wrapping_add(2);
    ro_set_u32(k, r, id, ro::VALUE_SEED, v);
    v
}

// ---------------------------------------------------------------------------
// The methods.

/// `IOExternalMethodDispatch2022`: counts (or [`VARIABLE`]) and whether an
/// asynchronous call is allowed; none of IOSurface's names an entitlement.
#[derive(Clone, Copy)]
struct Dispatch2022 {
    scalar_in: u32,
    struct_in: u32,
    scalar_out: u32,
    struct_out: u32,
    allow_async: bool,
}

const V: u32 = VARIABLE;

/// The dispatch table (0xfffffff006d3bf98; the restricted table at
/// 0xfffffff006d3c808 has the same counts).
const METHODS: [Dispatch2022; 54] = {
    const fn d(scalar_in: u32, struct_in: u32, scalar_out: u32, struct_out: u32, allow_async: bool) -> Dispatch2022 {
        Dispatch2022 { scalar_in, struct_in, scalar_out, struct_out, allow_async }
    }
    [
        d(1, V, 0, 3176, false),
        d(1, 0, 0, 0, false),
        d(0, 12, 0, 3176, false),
        d(0, 12, 0, 4, false),
        d(1, 0, 0, 3176, false),
        d(2, 0, 0, 0, false),
        d(0, 32, 0, 3176, false),
        d(2, 0, 0, 3176, false),
        d(1, 0, 1, 0, false),
        d(0, V, 0, 4, false),
        d(0, V, 0, V, false),
        d(0, V, 0, 4, false),
        d(3, 0, 0, 0, false),
        d(0, 0, 0, 40, false),
        d(2, 0, 0, 0, false),
        d(2, 0, 0, 0, false),
        d(1, 0, 1, 0, false),
        d(0, 24, 0, 0, true),
        d(0, 24, 0, 0, false),
        d(0, V, 0, 0, false),
        d(2, 0, 1, 0, false),
        d(4, 0, 0, 0, false),
        d(2, 0, 0, 0, false),
        d(1, 0, 1, 0, false),
        d(0, V, 0, 0, false),
        d(1, 0, 1, 0, false),
        d(0, V, 0, V, false),
        d(0, 136, 0, 0, false),
        d(1, 0, 0, 136, false),
        d(2, 0, 0, 0, false),
        d(1, 0, 0, V, false),
        d(3, 0, 0, 0, false),
        d(0, 0, 1, 0, false),
        d(3, 0, 0, 0, false),
        d(1, 0, 0, 3176, false),
        d(2, 0, 1, 0, false),
        d(1, 0, 2, 0, false),
        d(2, 0, 0, 0, false),
        d(1, 0, 4, 0, false),
        d(5, 0, 0, 0, false),
        d(0, 0, 0, 0, true),
        d(1, 0, 0, 0, false),
        d(4, 0, 0, 0, false),
        d(4, 0, 0, 0, false),
        d(4, 0, 0, 0, false),
        d(3, 0, 0, 0, false),
        d(0, V, 2, 0, false),
        d(1, V, 0, 0, false),
        d(1, V, 0, 0, false),
        d(1, 0, 0, V, false),
        d(2, V, 0, 0, false),
        d(2, 0, 2, V, false),
        d(1, 0, 0, 0, false),
        d(1, 0, 0, 0, false),
    ]
};

/// The selectors the restricted table answers with kIOReturnNotPermitted
/// (0xfffffff005baed30).
const RESTRICTED: [u32; 23] = [4, 5, 6, 7, 8, 16, 17, 18, 19, 21, 22, 24, 25, 26, 28, 29, 30, 33, 43, 46, 47, 48, 49];

/// `IOSurfaceRootUserClient::externalMethod` (0xfffffff005bb1b10):
/// IOUserClient2022's `dispatchExternalMethod` (its checks in its order)
/// over the 54 selectors, through the restricted table for a restricted
/// client.
pub fn external_method(k: &mut Kernel, uc: u32, a: &mut MethodArgs) -> i32 {
    let Some(d) = METHODS.get(a.selector as usize) else { return ret::BAD_ARGUMENT };
    let ok = |want: u32, got: u64| want == V || u64::from(want) == got;
    if !ok(d.scalar_in, a.scalar_in.len() as u64) || !ok(d.struct_in, a.struct_in_size()) || !ok(d.scalar_out, a.scalar_out.len() as u64) || !ok(d.struct_out, a.struct_out_size()) {
        return ret::BAD_ARGUMENT;
    }
    if a.is_async && a.wake.is_some() && !d.allow_async {
        return ret::BAD_ARGUMENT;
    }
    if restricted(uc) && RESTRICTED.contains(&a.selector) {
        return ret::NOT_PERMITTED;
    }
    methods::call(k, uc, a)
}

/// `getTargetAndTrapForIndex` (0xfffffff005bb1b3c): eight traps, the
/// trap's arguments `p`.
pub fn trap(k: &mut Kernel, uc: u32, index: u32, p: [u64; 4]) -> i32 {
    match index {
        0 => methods::use_count(k, uc, p[0] as u32, p[1], true),
        1 => methods::use_count(k, uc, p[0] as u32, p[1], false),
        2 => methods::lock_trap(k, uc, p[0] as u32, p[1] as u32, p[2]),
        3 => methods::unlock_trap(k, uc, p[0] as u32, p[1] as u32, p[2]),
        4 => methods::detach(k, uc, p[0] as u32),
        5 => methods::finalize(k, uc, p[0] as u32),
        6 | 7 => {
            k.darwin_unimplemented(format!("IOSurfaceRootUserClient trap {index} (shared events)"));
            ret::UNSUPPORTED
        }
        // None past the table: success.
        _ => ret::SUCCESS,
    }
}

/// A send right's port (IKOT_IOKIT_IDENT) lost its last send right: the
/// `IOSurfaceSendRight` freed (0xfffffff005bb7a00): its use count and
/// wiring given back, the surface's client count lowered and its reference
/// released (the root's deferred release, 0xfffffff005bacc50).
pub fn send_right_no_senders(k: &mut Kernel, id: u32) {
    root(|r| {
        let Some(sr) = r.send_rights.remove(&id) else { return };
        if sr.uses {
            use_count_decrement(k, r, sr.surface, 0);
        }
        if let Some(s) = r.surfaces.get_mut(&sr.surface) {
            if sr.wired {
                s.wired -= 1;
            }
            s.clients -= 1;
            if s.clients == 0 {
                s.desc.flags &= !0xc;
            }
        }
        surface_release(k, r, sr.surface);
    });
}

/// A store by the calling process to `page` (a [`gex_abi::PERM_PAGE`]
/// number) whose write bit was taken from its protection table: noted by
/// the memory whose view has the page. A page no view has any more (the
/// task unmapped the view itself) gets its bit back. Whether the store was
/// one of these.
pub fn note_store(k: &mut Kernel, m: &mut GuestMem<'_>, page: u64) -> bool {
    if k.mem.lock().withheld(page) & gex_abi::perm::WRITE == 0 {
        return false;
    }
    let pid = k.pid;
    let claimed = {
        let mut g = ROOT.lock().unwrap_or_else(|e| e.into_inner());
        match g.as_mut() {
            Some(r) => r.surfaces.values_mut().any(|s| s.memory.as_mut().is_some_and(|mem| mem.note_write(k, m, pid, page))) || r.shared.note_write(k, m, pid, page),
            None => false,
        }
    };
    // The framebuffer's frame information queues are IOKit memory mapped
    // the same way.
    let claimed = claimed || super::iomfb::finfo::note_write(k, m, pid, page);
    if !claimed {
        let addr = page << gex_abi::PERM_PAGE_SHIFT;
        k.mem.lock().restore(addr, addr + gex_abi::PERM_PAGE, gex_abi::perm::WRITE);
    }
    true
}

/// Surface `id` as the executor's table describes it; none for an id no
/// surface has.
pub fn describe(id: u32) -> Option<executor::SurfaceDesc> {
    root(|r| {
        let s = r.surfaces.get(&id)?;
        let d = &s.desc;
        let planes = d
            .planes
            .iter()
            .map(|p| executor::PlaneDesc { offset: p.offset, width: p.width, height: p.height, bytes_per_row: p.bytes_per_row, bytes_per_element: u32::from(p.bytes_per_element), element_width: u32::from(p.element_width), element_height: u32::from(p.element_height), size: p.size })
            .collect();
        Some(executor::SurfaceDesc {
            id,
            width: d.width,
            height: d.height,
            bytes_per_row: d.bytes_per_row,
            bytes_per_element: u32::from(d.bytes_per_element),
            element_width: u32::from(d.element_width),
            element_height: u32::from(d.element_height),
            offset: d.offset,
            pixel_format: d.pixel_format,
            alloc_size: d.alloc_size,
            planes,
            seed: ro_u32(r, id, ro::SEED),
        })
    })
}

/// Surface `id` handed to the GPU (a GPU client's use of it: a texture or
/// buffer over its bytes) through the executor's surface table, with its
/// bytes as every task has left them; from then on its locks read the
/// GPU's writes back and the tasks' changes the kernel gathers are handed
/// over. A surface the GPU has already is left as it is, and an id no
/// surface has binds nothing (the executor finds no surface by it). `Err`
/// says what is missing: no executor. A surface whose bytes do
/// not start at its memory's first byte (`IOSurfaceOffset`) is refused:
/// where its planes start relative to its base address, as the executor
/// addresses them, is not checked against IOSurface.framework.
pub fn bind_gpu(k: &mut Kernel, id: u32) -> Result<(), String> {
    let Some(desc) = describe(id) else { return Ok(()) };
    if root(|r| r.surfaces.get(&id).is_some_and(|s| s.gpu)) {
        return Ok(());
    }
    if desc.offset != 0 {
        return Err(format!("binding IOSurface {id:#x} to the GPU: its IOSurfaceOffset {:#x} (where its planes start relative to its base address is not checked against IOSurface.framework)", desc.offset));
    }
    executor::bind(&desc)?;
    let t = executor::table().expect("bound through the table");
    root(|r| {
        let Some(s) = r.surfaces.get_mut(&id) else { return };
        s.gpu = true;
        if let Some(mem) = s.memory.as_mut() {
            let _ = k.darwin_own_memory(|k, m| mem.gather(k, m));
            mem.take_changed();
            let len = mem.backing.len() as u64;
            t.cpu_wrote(id, &mem.backing, &[(0, len)]);
        }
    });
    Ok(())
}

/// `f` with surface `id`'s bytes, every task's changes gathered into them
/// first: what the executor reads when the GPU uses the surface.
pub fn with_bytes<R>(k: &mut Kernel, id: u32, f: impl FnOnce(&mut [u8]) -> R) -> Option<R> {
    root(|r| {
        let mem = r.surfaces.get_mut(&id)?.memory.as_mut()?;
        k.darwin_own_memory(|k, m| mem.gather(k, m)).ok()?;
        Some(f(&mut mem.backing))
    })
}

/// A surface's geometry as a kext reads it through IOSurface's accessors
/// (0xfffffff005b9ebac and on): its flags (`+0x3b0`), pixel format
/// (`+0x80`), width and height (`+0x58`, `+0x60`), and its planes, a
/// surface with none being one plane of its own width, height, offset
/// (`+0x78`), bytes per row (`+0x68`), size (`+0x90`) and bytes per element
/// (`+0x70`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Geometry {
    pub id: u32,
    pub flags: u32,
    pub pixel_format: u32,
    pub width: u64,
    pub height: u64,
    pub alloc_size: u64,
    pub planes: Vec<surface::Plane>,
    pub plane_count: u32,
}

impl Geometry {
    /// The plane accessors (0xfffffff005b9eeb8 and the others): plane `i`
    /// of a planar surface, or the surface itself as plane 0 of one with
    /// none; none past them.
    pub fn plane(&self, i: u32) -> Option<surface::Plane> {
        if self.plane_count == 0 {
            return (i == 0).then(|| self.planes[0]);
        }
        self.planes.get(i as usize).copied()
    }
}

/// `IOSurfaceRoot::lookupSurface(id, task)` as a kext calls it
/// (0xfffffff005baa72c): the calling task's user client found
/// (0xfffffff005baa7cc), then the surface in the root's table
/// (0xfffffff005baa438) if the task created it, or that client holds it
/// (0xfffffff005bb2220), or a global lookup is allowed for it (the debug
/// flags; never for a private surface); and a reference taken unless its
/// count is already zero (0xfffffff005b9c9a0). The kext lets the
/// reference go with [`kernel_release`].
pub fn kernel_lookup(k: &mut Kernel, id: u32) -> Option<u32> {
    let pid = k.pid;
    root(|r| {
        if id == 0 || id >= r.table_size {
            return None;
        }
        let client = r.clients.iter().find(|(_, c)| c.pid == pid && c.live).map(|(uc, _)| *uc);
        let debug = r.params.debug;
        let held = client.is_some_and(|uc| r.clients.get(&uc).and_then(|c| c.handles.get(id as usize)).is_some_and(|h| h.is_some()));
        let s = r.surfaces.get_mut(&id)?;
        if !s.installed {
            return None;
        }
        let found = s.creator == Some(pid) || held || (s.desc.flags & flag::PRIVATE == 0 && ((debug & 4 != 0 && s.desc.flags & flag::GLOBAL != 0) || debug & 1 != 0));
        if !found || s.refs == 0 {
            return None;
        }
        s.refs += 1;
        Some(id)
    })
}

/// The root told that `display`'s layer `layer` shows `surface` now
/// (0xfffffff005bacfe0): the display's entry found, or the first free one
/// of eight taken (none free: nothing is kept), the layer's size the
/// surface's allocation size (or none), and the sum of every display's
/// kept. When the sum changes the callback registered for it
/// (0xfffffff005bad200) is called: IOGPU's scheduler registers one
/// (IOGPUScheduler::init, 0xfffffff005bca870), which the accelerator here
/// does not make, so none is.
pub fn displayed(display: u64, layer: u32, surface: Option<u32>) {
    root(|r| {
        let slot = match r.displayed.iter().position(|d| d.is_some_and(|(k, _)| k == display)) {
            Some(i) => i,
            None => match r.displayed.iter().position(Option::is_none) {
                Some(i) => {
                    r.displayed[i] = Some((display, [0; 4]));
                    i
                }
                None => return,
            },
        };
        if layer > 3 {
            return;
        }
        let size = surface.and_then(|id| r.surfaces.get(&id)).map_or(0, |s| s.desc.alloc_size);
        let (_, sizes) = r.displayed[slot].as_mut().expect("the display's entry");
        r.displayed_bytes = r.displayed_bytes - sizes[layer as usize] + size;
        sizes[layer as usize] = size;
    });
}

/// A reference [`kernel_lookup`] took let go.
pub fn kernel_release(k: &mut Kernel, id: u32) {
    root(|r| surface_release(k, r, id));
}

/// Surface `id`'s geometry; none for an id no surface has.
pub fn geometry(id: u32) -> Option<Geometry> {
    root(|r| {
        let s = r.surfaces.get(&id)?;
        let d = &s.desc;
        let planes = if d.planes.is_empty() {
            vec![surface::Plane { width: d.width, height: d.height, base: 0, offset: d.offset, bytes_per_row: d.bytes_per_row, size: d.alloc_size, bytes_per_element: d.bytes_per_element, element_width: d.element_width, element_height: d.element_height, address_format: 0 }]
        } else {
            d.planes.clone()
        };
        Some(Geometry { id, flags: d.flags, pixel_format: d.pixel_format, width: d.width, height: d.height, alloc_size: d.alloc_size, plane_count: d.planes.len() as u32, planes })
    })
}

/// The graphics comm page's first word (IOGPUFamily's selector 3).
pub fn comm_word() -> u32 {
    root(|r| r.shared.comm_word())
}

/// The graphics comm page mapped read-only into the calling task as
/// IOGPUFamily maps it (kIOMapUnique); its address and length.
pub fn comm_map_unique(k: &mut Kernel) -> Result<(u64, u64), u64> {
    root(|r| r.shared.map_comm(k, true))
}

/// A mapping of the comm page by `pid` let go.
pub fn comm_unmap(k: &mut Kernel, pid: i32, addr: u64) {
    root(|r| r.shared.unmap_comm(k, pid, addr));
}

/// What `OSUnserializeXML(buffer, size)` makes of a method's payload: the
/// binary form; XML text is not parsed here (reported).
fn unserialize(k: &mut Kernel, what: &str, b: &[u8]) -> Option<(Graph, Id)> {
    match os::unserialize(b) {
        os::Parsed::Binary(r) => r,
        os::Parsed::Xml => {
            k.darwin_unimplemented(format!("{what}: OSUnserializeXML of XML text"));
            None
        }
        os::Parsed::Invalid => None,
    }
}
