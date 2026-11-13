//! The framebuffer's swaps, its vertical blanks and its notifications, as
//! `IOMobileFramebufferLegacy` (IOMobileGraphicsFamily) runs them with
//! AppleMobileDispH9G's pipe beneath:
//!
//! - A client begins a swap (selector 4: a request with the next swap id,
//!   in the begun list) and ends it with its transaction (selector 5: the
//!   1288-byte record the framework builds), which `swap_submit`
//!   (0xfffffff00678f224) checks, the pipe verifies, and the request goes
//!   to the queue.
//! - The display controller takes the queue's head as its pending swap,
//!   and the vertical blank after makes it the displayed swap: then its
//!   layers reach the glass (the embedder's [`super::sink`]), and the swap
//!   it replaces retires, its surfaces let go.
//! - Swap waits (selector 6) wait on those steps.
//! - No vertical blank message is sent. The family's only sender of them
//!   (0xfffffff006796720, the records of type 5 with each blank's count,
//!   time and delta) is called only by
//!   `IOMobileFramebufferLegacy::clear_up_swap_queue_gated`
//!   (0xfffffff00678a428), which AppleCLCD overrides (vtable slot 346,
//!   0xfffffff006bf710c) with one that sends none; AppleMobileDispH9G
//!   sends no async message at all. Turning type 5 on lists the record and
//!   calls slot 316 (empty on AppleCLCD) and slot 290 (the pipe's kick).
//!
//! The panel is disp0's: its mode is the timing the device tree gives
//! (`display-timing-info`), and its vertical blanks come one frame apart,
//! a frame being two subframes of `subframe-duration-nclks` ([`Panel`]).
//! They are counted from the system's boot.

use std::collections::VecDeque;

use super::super::iokit::ret;
use super::sink;
use crate::syscalls::Kernel;
use crate::GuestMem;

/// IOReturn codes beyond [`ret`].
pub mod kr {
    pub const PORT_EXISTS: i32 = 0xe00002dd_u32 as i32;
    pub const NOT_PERMITTED: i32 = 0xe00002e2_u32 as i32;
    pub const BUSY: i32 = 0xe00002d5_u32 as i32;
    pub const ABORTED: i32 = 0xe00002eb_u32 as i32;
    pub const OFFLINE: i32 = 0xe00002e3_u32 as i32;
    pub const VM_ERROR: i32 = 0xe00002c8_u32 as i32;
}

/// The panel's mode and refresh.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Panel {
    /// The mode's active width and height (`fb+0x16b0`, `+0x16b4`): the
    /// first and fifth words of disp0's `display-timing-info`, which the
    /// kext reads when no link gave it timings (0xfffffff006bc1358, origin
    /// 3) and packs as horizontal and vertical halves of each pair
    /// (0xfffffff006bc1a80).
    pub width: u32,
    pub height: u32,
    /// A frame in absolute time: `subframe-duration-nclks` (the subframe in
    /// 24 MHz ticks) times the subframes a frame takes. The pipe's frame
    /// duration (0xfffffff006bd3e48) is the subframe duration times its
    /// subframe count (0xfffffff006bbd6d8), which starts at 2 for a panel
    /// whose display is neither external nor standalone (`+0x294`,
    /// 0xfffffff006bb5d74); disp0 has neither property.
    pub frame: u64,
}

impl Panel {
    /// The panel the device tree describes; `Err` says what it lacks.
    pub fn from_tree() -> Result<Panel, String> {
        let t = super::super::iokit::tree();
        let disp = t.iter().find(|n| n.props.iter().any(|(k, v)| k == "compatible" && v.split(|&c| c == 0).any(|c| c == b"disp0,t8011"))).ok_or("disp0 in the device tree")?;
        let prop = |name: &str| disp.props.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
        let timing = prop("display-timing-info").ok_or("disp0's display-timing-info")?;
        let word = |b: &[u8], i: usize| b.get(4 * i..4 * i + 4).map(|w| u32::from_le_bytes(w.try_into().unwrap()));
        let (Some(width), Some(height)) = (word(&timing, 0), word(&timing, 4)) else { return Err("disp0's display-timing-info of eight words".into()) };
        let sub = prop("subframe-duration-nclks").and_then(|v| word(&v, 0)).ok_or("disp0's subframe-duration-nclks")?;
        Ok(Panel { width: width & 0xffff, height: height & 0xffff, frame: u64::from(sub) * SUBFRAMES })
    }
}

/// The subframes a frame takes at the start (`+0x294`).
const SUBFRAMES: u64 = 2;

/// A layer of a request (the request's `+0x11 + 16 * n` source rectangle,
/// `+0x51 + 16 * n` destination, `+0x244 + 4 * n` transform), and the
/// surface it holds a reference on (`+0xa40 + 8 * n`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LayerReq {
    pub surface: Option<u32>,
    pub src: [i32; 4],
    pub dst: [i32; 4],
    pub transform: u32,
    pub active_regions: u32,
}

/// An `IOMFBSwapIORequest` (0xba0 bytes): its swap id (`+0x314`), the
/// client that began it and that client's task, whether it was handed to
/// swap_submit (`+0x54b`) or cancelled (`+0x54a`), its enabled layers
/// (`+0x318`) and the record's completed mask (`+0x31c`), its kind
/// (`+0x32c`), its presentation time (`+0x2d0`), and its layers.
#[derive(Clone, Debug, Default)]
pub struct Request {
    pub id: u32,
    pub client: u32,
    pub pid: i32,
    pub submitted: bool,
    pub cancelled: bool,
    pub enabled: u32,
    pub completed: u32,
    pub kind: u32,
    pub presentation: u64,
    pub layers: [LayerReq; 4],
}

/// A notification record a client listed for a type (`+0x118 + type *
/// 0xb0` of the client, listed at the framebuffer's `+0x1588 + type * 16`),
/// by its client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub client: u32,
}

/// The framebuffer's swap and display state.
struct Display {
    panel: Option<Panel>,
    /// `+0x16b8`: the last swap id given.
    next_id: u32,
    /// `+0x1578`: begun requests; `+0x1568`: the queue; `+0x1560`: the
    /// pending swap; the displayed swap and its id (`+0x16bc`).
    begun: Vec<Request>,
    queue: VecDeque<Request>,
    pending: Option<Request>,
    displayed: Option<Request>,
    display_swap_id: u32,
    /// The last vertical blank processed (its index since boot), the
    /// count (`+0x100`), its time (`+0x108`) and the time since the one
    /// before (`+0x110`).
    vbl_index: u64,
    vbl_count: u64,
    vbl_time: u64,
    vbl_delta: u64,
    /// `+0x16f8`: the swap clients registered.
    swap_clients: u32,
    records: [Vec<Record>; super::NOTIFY_TYPES],
    /// The clients started and not stopped.
    started: Vec<u32>,
}

static DISPLAY: std::sync::Mutex<Option<Display>> = std::sync::Mutex::new(None);

fn display<R>(f: impl FnOnce(&mut Display) -> R) -> R {
    let mut g = DISPLAY.lock().unwrap_or_else(|e| e.into_inner());
    let d = g.get_or_insert_with(|| Display {
        panel: Panel::from_tree().ok(),
        next_id: 0,
        begun: Vec::new(),
        queue: VecDeque::new(),
        pending: None,
        displayed: None,
        display_swap_id: 0,
        vbl_index: 0,
        vbl_count: 0,
        vbl_time: 0,
        vbl_delta: 0,
        swap_clients: 0,
        records: Default::default(),
        started: Vec::new(),
    });
    f(d)
}

/// The panel, or what the device tree lacks to describe it.
pub fn panel() -> Result<Panel, String> {
    display(|d| d.panel).ok_or_else(|| Panel::from_tree().err().unwrap_or_default())
}

// ---------------------------------------------------------------------------
// Swap clients.

/// `IOMobileFramebufferLegacy` slot 169 (0xfffffff0067891d8): a client
/// that swaps registered; the first powers the display on (slot 171),
/// which is on already here.
pub fn add_swap_client() {
    display(|d| d.swap_clients += 1);
}

/// Slot 170 (0xfffffff00678c998): the client's swaps cleared
/// (0xfffffff00678a214: its begun requests released, its queued ones
/// cancelled), and the last swap client's going powers down the display's
/// swap path (0xfffffff00678b544).
pub fn remove_swap_client(k: &mut Kernel, client: u32) {
    let released = display(|d| {
        let mut out = Vec::new();
        let mut i = 0;
        while i < d.begun.len() {
            if d.begun[i].client == client {
                out.push(d.begun.remove(i));
            } else {
                i += 1;
            }
        }
        for r in d.queue.iter_mut().filter(|r| r.client == client) {
            r.cancelled = true;
        }
        d.swap_clients = d.swap_clients.saturating_sub(1);
        out
    });
    for r in released {
        release_request(k, r);
    }
}

/// A client gone: its notification records dropped.
pub fn client_gone(_k: &mut Kernel, client: u32) {
    display(|d| d.records.iter_mut().for_each(|l| l.retain(|r| r.client != client)));
}

/// The frame information size selector 74 gave the client (`+0x3c8`),
/// which decides whether type 3 has a queue.
pub fn frame_info_size(_c: &super::Client) -> u32 {
    0
}

/// The surfaces a request holds let go.
fn release_request(k: &mut Kernel, r: Request) {
    for l in r.layers {
        if let Some(s) = l.surface {
            super::super::iosurface::kernel_release(k, s);
        }
    }
}

// ---------------------------------------------------------------------------
// Begin and submit.

/// Selector 4's `swap_begin` (0xfffffff00678e290, gated 0xfffffff00678e37c):
/// a new request with the next swap id (0xfffffff00678e534: one more, 0
/// skipped), at the begun list's tail.
pub fn begin(client: u32, pid: i32) -> u32 {
    display(|d| {
        d.next_id = d.next_id.wrapping_add(1);
        if d.next_id == 0 {
            d.next_id = 1;
        }
        let id = d.next_id;
        d.begun.push(Request { id, client, pid, ..Default::default() });
        id
    })
}

/// The transaction record's size (`CLCDTransaction`, selector 5).
pub const RECORD_SIZE: usize = 0x508;

/// What the framework's record holds, at its offsets (`swap_submit` copies
/// each into the request).
mod rec {
    pub const TIMESTAMPS: usize = 0x00;
    pub const SWAP_ID: usize = 0x98;
    pub const SURFACES: usize = 0x9c;
    pub const SRC: usize = 0xac;
    pub const DST: usize = 0x10c;
    pub const ENABLED: usize = 0x14c;
    pub const COMPLETED: usize = 0x150;
    pub const TRANSFORM: usize = 0x15c;
    pub const KIND: usize = 0x17c;
    pub const REGION_COUNT: usize = 0x188;
    pub const EXCLUDES: usize = 0x2cd;
    pub const KEEP_ON_SCREEN: usize = 0x336;
    pub const RELATIVE_TIME: usize = 0x338;
    pub const USER_DATA_FLAG: usize = 0x34e;
    pub const GAIN_MAP: usize = 0x3e7;
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

fn i32_at(b: &[u8], o: usize) -> i32 {
    u32_at(b, o) as i32
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// Whether the record asks for the gain map, which selector 5 lets only an
/// entitled task do (0xfffffff006779470).
pub fn wants_gain_map(record: &[u8]) -> bool {
    record[rec::GAIN_MAP] & 1 != 0
}

/// The swap id a record names.
pub fn record_swap_id(record: &[u8]) -> u32 {
    u32_at(record, rec::SWAP_ID)
}

/// Selector 5's `swap_submit` (0xfffffff00678f224) of `record` from the
/// calling task: its result.
pub fn submit(k: &mut Kernel, record: &[u8]) -> i32 {
    let id = record_swap_id(record);
    // The begun request by id (0xfffffff006790894): none, or one handed to
    // swap_submit already, is lost (kIOReturnNotFound to the lookup):
    // IOMFB_SWAP_SUBMIT_LOST, kIOReturnError.
    let req = display(|d| {
        let r = d.begun.iter_mut().find(|r| r.id == id)?;
        if r.submitted {
            return None;
        }
        r.submitted = true;
        Some(r.clone())
    });
    let Some(mut req) = req else { return ret::ERROR };
    // The record's fields the request takes.
    req.enabled = u32_at(record, rec::ENABLED);
    req.completed |= u32_at(record, rec::COMPLETED);
    req.kind = u32_at(record, rec::KIND);
    req.presentation = u64_at(record, rec::TIMESTAMPS);
    if record[rec::RELATIVE_TIME] & 1 != 0 {
        req.presentation = req.presentation.wrapping_add(super::super::mach::absolute_time());
    }
    if record[rec::USER_DATA_FLAG] & 1 != 0 && u64_at(record, 0x38) != 0 {
        k.darwin_unimplemented("an IOMobileFramebuffer swap's 0x20c bytes of user data (the transaction's +0x38, read from the task)".to_string());
        return give_back(k, id, req, ret::ERROR);
    }
    if req.kind == 9 {
        k.darwin_unimplemented("an IOMobileFramebuffer swap of kind 9, which shows the framebuffer's own surface on every layer".to_string());
        return give_back(k, id, req, ret::ERROR);
    }
    let mut valid = true;
    for n in 0..4usize {
        if req.enabled & (1 << n) == 0 {
            continue;
        }
        let rect = |at: usize| [i32_at(record, at), i32_at(record, at + 4), i32_at(record, at + 8), i32_at(record, at + 12)];
        let l = &mut req.layers[n];
        l.src = rect(rec::SRC + 16 * n);
        l.dst = rect(rec::DST + 16 * n);
        l.transform = u32_at(record, rec::TRANSFORM + 4 * n) & 7;
        // The active regions: at most four (more are cut to four).
        l.active_regions = u32_at(record, rec::REGION_COUNT + 4 * n).min(4);
        let surface_id = u32_at(record, rec::SURFACES + 4 * n);
        // The layer's surface, looked up for the calling task (the root's
        // lookupSurface); the framebuffer's own surface is never a
        // client's here, since the framebuffer allocated none.
        l.surface = if surface_id == 0 { None } else { super::super::iosurface::kernel_lookup(k, surface_id) };
        if surface_id != 0 && l.surface.is_none() {
            valid = false;
            break;
        }
        let Some(s) = l.surface else { continue };
        let Some(g) = super::super::iosurface::geometry(s) else {
            valid = false;
            break;
        };
        // Passthrough layers must cover the panel from its origin.
        if passthrough_format(g.pixel_format) {
            k.darwin_unimplemented(format!("an IOMobileFramebuffer layer of the passthrough format {}", fourcc(g.pixel_format)));
            return give_back(k, id, req, ret::ERROR);
        }
        // The source rectangle inside the surface.
        let [x, y, w, h] = l.src;
        if x < 0 || (g.width as u32) < (x.wrapping_add(w)) as u32 || y < 0 || (g.height as u32) < (y.wrapping_add(h)) as u32 {
            valid = false;
        }
        if !valid {
            break;
        }
    }
    if record[rec::EXCLUDES..rec::EXCLUDES + 5 * 21].chunks(21).any(|e| e[20] != 0) {
        k.darwin_unimplemented("an IOMobileFramebuffer swap's exclusion regions (UPBlock_DPB::verify_excludes)".to_string());
        return give_back(k, id, req, ret::ERROR);
    }
    if !valid {
        // The lookup's reference goes back; the request stays in the begun
        // list, handed to swap_submit, holding the surfaces it found
        // until it is cancelled.
        display(|d| {
            if let Some(r) = d.begun.iter_mut().find(|r| r.id == id) {
                *r = req;
            }
        });
        return ret::BAD_ARGUMENT;
    }
    if record[rec::KEEP_ON_SCREEN] & 1 != 0 {
        k.darwin_unimplemented("an IOMobileFramebuffer swap that keeps its layers on screen (the transaction's +0x336)".to_string());
        return give_back(k, id, req, ret::ERROR);
    }
    // The display is on (`+0x16cc`), so the request goes to the pipe
    // (0xfffffff0067909ac): verify_swap, the DRM checks, each layer's
    // surface prepared, and the request queued.
    let r = match verify(&mut req) {
        Err(what) => {
            k.darwin_unimplemented(what);
            Err(ret::ERROR)
        }
        Ok(false) => Err(ret::BAD_ARGUMENT),
        Ok(true) => enqueue(&req),
    };
    match r {
        Ok(()) => {
            display(|d| {
                if let Some(i) = d.begun.iter().position(|r| r.id == id) {
                    d.begun.remove(i);
                }
                if d.pending.is_none() {
                    d.pending = Some(req);
                } else {
                    d.queue.push_back(req);
                }
            });
            k.darwin_iomfb_arm();
            ret::SUCCESS
        }
        Err(e) => {
            // Failed in the pipe: out of the begun list and released
            // (0xfffffff006791258).
            display(|d| {
                if let Some(i) = d.begun.iter().position(|r| r.id == id) {
                    d.begun.remove(i);
                }
            });
            release_request(k, req);
            e
        }
    }
}

/// A request that could not be submitted for what is not modelled: out of
/// the begun list, its references let go, `e` returned.
fn give_back(k: &mut Kernel, id: u32, req: Request, e: i32) -> i32 {
    display(|d| d.begun.retain(|r| r.id != id));
    release_request(k, req);
    e
}

/// The passthrough formats (0xfffffff00679dc64): two codes past
/// 0x3d3d3d31 ('===1' and '===2'), and those 0xfffffff00679dc04 names.
fn passthrough_format(f: u32) -> bool {
    f.wrapping_add(0xc2c2c2ce) < 2
}

fn fourcc(f: u32) -> String {
    let b = f.to_be_bytes();
    if b.iter().all(|c| (0x20..0x7f).contains(c)) {
        String::from_utf8_lossy(&b).into_owned()
    } else {
        format!("{f:#x}")
    }
}

/// An entry of the pipe's pixel format table (0xfffffff0058a102c, 0x20
/// bytes each): the format, its class (3 for RGB) and its layout.
#[derive(Clone, Copy)]
struct Format {
    code: u32,
    class: u32,
    layout: u32,
}

/// The table's RGB entries, which are those a layer may show unscaled
/// here (`+0`, `+4`, `+8` of each entry).
const FORMATS: [Format; 12] = [
    Format { code: u32::from_be_bytes(*b"BGRA"), class: 3, layout: 2 },
    Format { code: u32::from_be_bytes(*b"ARGB"), class: 3, layout: 2 },
    Format { code: u32::from_be_bytes(*b"RGBA"), class: 3, layout: 2 },
    Format { code: u32::from_be_bytes(*b"L565"), class: 3, layout: 0 },
    Format { code: u32::from_be_bytes(*b"w40a"), class: 3, layout: 3 },
    Format { code: u32::from_be_bytes(*b"w10p"), class: 3, layout: 1 },
    Format { code: u32::from_be_bytes(*b"w30r"), class: 3, layout: 1 },
    Format { code: u32::from_be_bytes(*b"l10r"), class: 3, layout: 1 },
    Format { code: u32::from_be_bytes(*b"w18p"), class: 3, layout: 4 },
    Format { code: u32::from_be_bytes(*b"b3a8"), class: 3, layout: 4 },
    Format { code: u32::from_be_bytes(*b"f3a8"), class: 3, layout: 4 },
    Format { code: u32::from_be_bytes(*b"RGhA"), class: 3, layout: 8 },
];

/// The pipe's `verify_swap` (AppleCLCD slot 296 forwards to the pipe's
/// 0xfffffff006bb7edc) and the DRM checks (slot 297, 0xfffffff006bfad20,
/// which pass for an internal panel: `+0x1783` is clear): whether the
/// request is acceptable; `Err` for what is not ported. The pipe's
/// tiling manager and its blocks pass every request but for the display
/// pipe block's exclusion regions (`UPBlock_DPB::verify_excludes`,
/// 0xfffffff006be3afc), which a swap with none passes.
fn verify(req: &mut Request) -> Result<bool, String> {
    let panel = panel()?;
    // A layer the checks look at (0xfffffff006bd2c18): enabled, with a
    // surface, its rectangles not empty.
    let shown = |r: &Request, n: usize| r.enabled & (1 << n) != 0 && r.layers[n].surface.is_some();
    let live = |r: &Request, n: usize| {
        let l = &r.layers[n];
        shown(r, n) && l.src[2] != 0 && l.src[3] != 0 && l.dst[2] != 0 && l.dst[3] != 0
    };
    let geometry = |r: &Request, n: usize| super::super::iosurface::geometry(r.layers[n].surface.unwrap()).ok_or("a layer's surface, gone");
    // The bandwidth first (the pipe's parent checks, 0xfffffff006bb7454):
    // each layer's bits per pixel (0xfffffff006bd2e08) times its source
    // width, an eighth, against disp0's `max-avg-bpp` and `max-peak-bpp`
    // (16.16) times the panel's width; within the average, or within the
    // peak with each layer's rows rounded up. The pixel clock check before
    // it holds for a source no wider than twice the panel whatever the
    // clocks (the pixel clock is at least the video clock).
    let tree = super::super::iokit::tree();
    let disp = tree.iter().find(|n| n.props.iter().any(|(k, v)| k == "compatible" && v.split(|&c| c == 0).any(|c| c == b"disp0,t8011")));
    let fixed = |name: &str| disp.and_then(|n| n.props.iter().find(|(k, _)| k == name)).and_then(|(_, v)| v.get(..4)).map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()));
    let (avg, peak) = (fixed("max-avg-bpp") as f32 * 1.5258789e-05, fixed("max-peak-bpp") as f32 * 1.5258789e-05);
    if avg != 0.0 && peak != 0.0 {
        let (mut avg_used, mut peak_used) = (0f32, 0f32);
        for n in 0..4 {
            if !shown(req, n) {
                continue;
            }
            let l = req.layers[n];
            if l.src[2] > 2 * panel.width as i32 {
                return Err("verifying an IOMobileFramebuffer layer wider than twice the panel against the display's pixel and video clocks".to_string());
            }
            let g = geometry(req, n)?;
            let count = if g.plane_count == 0 { 1 } else { g.plane_count.min(8) };
            let bits: u64 = (0..count).filter_map(|p| g.plane(p)).map(|p| u64::from(p.bytes_per_element) * p.width * p.height * 8).sum();
            let area = g.width * g.height;
            let bpp = if area == 0 { 0 } else { ((bits + area - 1) / area) as u32 };
            let (sw, sh, dh) = (l.src[2], l.src[3], l.dst[3]);
            let rows = if dh == 0 { 0 } else { (sh + dh - 1) / dh };
            let line = bpp.wrapping_mul(sw as u32);
            avg_used += (sh as f32 / dh as f32) * line as f32 * 0.125;
            peak_used += ((rows as u32).wrapping_mul(line) >> 3) as f32;
        }
        if avg * (panel.width as f32) < avg_used && !(peak_used <= peak * panel.width as f32) {
            return Ok(false);
        }
    }
    // At most two layers blend (0xfffffff006bb7e58).
    if (0..4).filter(|&n| live(req, n)).count() > 2 {
        return Ok(false);
    }
    for n in 0..4 {
        if !live(req, n) {
            continue;
        }
        let g = geometry(req, n)?;
        let l = req.layers[n];
        // A tiled surface is refused (0xfffffff006bb77e4).
        if g.flags & super::super::iosurface::surface::flag::BUFFER_TILE_MODE != 0 {
            return Ok(false);
        }
        let Some(f) = FORMATS.iter().find(|f| f.code == g.pixel_format) else {
            return Err(format!("verifying an IOMobileFramebuffer layer of format {}: the pipe's other formats (YCbCr and compressed)", fourcc(g.pixel_format)));
        };
        // Half-float and the 'xw' layouts are refused with the unsupported
        // formats (0xfffffff006bc8d28, 0xfffffff006bc8da8).
        if f.layout == 8 || f.class == 2 {
            return Ok(false);
        }
        let count = if g.plane_count == 0 { 1 } else { g.plane_count };
        for p in 0..count {
            let Some(pl) = g.plane(p) else { break };
            if pl.bytes_per_row & 0x3f != 0 || pl.offset & 0x3f != 0 || pl.size < pl.bytes_per_row * pl.height {
                return Ok(false);
            }
            if p == 0 && (pl.width > 0x10000 || pl.height > 0x10000 || pl.width < 0x20 || pl.height < 0x20 || pl.height < (l.src[1].wrapping_add(l.src[3])) as u32 as u64) {
                return Ok(false);
            }
        }
    }
    // The source as the pipe takes it (0xfffffff006bb7ac0): a side under 32
    // grown to 32 from its far edge (the request keeps it so), then within
    // 65536 and a read of at most 4096 wide and 16 Mpixels.
    for n in 0..4 {
        if !live(req, n) {
            continue;
        }
        let [mut x, mut y, mut w, mut h] = req.layers[n].src;
        if w < 0x20 {
            x = (w + x - 0x20).max(0);
            w = 0x20;
        }
        if h < 0x20 {
            y = (h + y - 0x20).max(0);
            h = 0x20;
        }
        req.layers[n].src = [x, y, w, h];
        if w + x > 0x10000 || h + y > 0x10000 || w > 0x1000 || (h as i64) * (w as i64) > 0x100_0000 {
            return Ok(false);
        }
    }
    for n in 0..4 {
        if !shown(req, n) {
            continue;
        }
        let l = req.layers[n];
        // Active regions (0xfffffff006bb7c34).
        if live(req, n) && l.active_regions != 0 {
            return Err("verifying an IOMobileFramebuffer layer's active regions (0xfffffff006bb7c34)".to_string());
        }
        // A null rectangle, or scaling past 4 either way (0xfffffff006bb7684).
        let [sw, sh, dw, dh] = [l.src[2], l.src[3], l.dst[2], l.dst[3]];
        if sw == 0 || sh == 0 || dw == 0 || dh == 0 {
            return Ok(false);
        }
        if (dw / sw) as u32 >= 5 || (sw / dw) as u32 >= 5 || (dh / sh) as u32 >= 5 || (sh / dh) as u32 >= 5 {
            return Ok(false);
        }
        if sw != dw || sh != dh {
            return Err("an IOMobileFramebuffer layer scaled by the pipe's scaler".to_string());
        }
        if l.transform != 0 {
            return Err(format!("an IOMobileFramebuffer layer's transform {}", l.transform));
        }
    }
    Ok(true)
}

/// The request queued (0xfffffff0067916f8): one cancelled, or no longer
/// begun, is kIOReturnAborted. Its passthrough and keep-on-screen checks
/// (0xfffffff00678f070, 0xfffffff006799eb0) concern what was reported
/// before it.
fn enqueue(req: &Request) -> Result<(), i32> {
    let begun = display(|d| d.begun.iter().any(|r| r.id == req.id && !r.cancelled));
    if req.cancelled || !begun {
        return Err(kr::ABORTED);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Cancelling.

/// Slot 217's gated `swap_cancel` (0xfffffff006789460): a begun request
/// not yet handed to swap_submit goes (released); one being submitted, or
/// queued, is marked cancelled; none by that id is kIOReturnBadArgument.
/// The pending swap is not looked at.
pub fn cancel(k: &mut Kernel, id: u32) -> i32 {
    let (r, released) = display(|d| {
        if let Some(i) = d.begun.iter().position(|r| r.id == id) {
            if !d.begun[i].submitted {
                return (ret::SUCCESS, Some(d.begun.remove(i)));
            }
            d.begun[i].cancelled = true;
            return (ret::SUCCESS, None);
        }
        match d.queue.iter_mut().find(|r| r.id == id) {
            Some(r) => {
                r.cancelled = true;
                (ret::SUCCESS, None)
            }
            None => (ret::BAD_ARGUMENT, None),
        }
    });
    if let Some(req) = released {
        release_request(k, req);
    }
    r
}

/// Slot 218's `swap_cancel_all(time)` (0xfffffff0067a0488): every begun
/// request removed, and the queued ones from the first whose presentation
/// time is at `time` or later; the waiters woken.
pub fn cancel_all(k: &mut Kernel, time: u64) -> i32 {
    let gone = display(|d| {
        let mut gone: Vec<Request> = d.begun.drain(..).collect();
        if let Some(first) = d.queue.iter().position(|r| time <= r.presentation) {
            gone.extend(d.queue.drain(first..));
        }
        gone
    });
    for r in gone {
        release_request(k, r);
    }
    ret::SUCCESS
}

// ---------------------------------------------------------------------------
// Vertical blanks.

/// The vertical blanks up to now processed: at each, the pending swap
/// becomes the displayed one (its layers to the glass, the one it
/// replaces retired) and the queue's next uncancelled request becomes
/// pending; and the count, time and delta kept (0xfffffff00679662c).
fn advance(k: &mut Kernel, now: u64) {
    let Ok(panel) = panel() else { return };
    let index = now / panel.frame;
    loop {
        let step = display(|d| {
            if d.vbl_index >= index {
                return None;
            }
            // With nothing pending the blanks up to now change nothing but
            // the count.
            if d.pending.is_none() && d.queue.is_empty() && d.vbl_index + 1 < index {
                d.vbl_count += index - 1 - d.vbl_index;
                d.vbl_index = index - 1;
                d.vbl_time = d.vbl_index * panel.frame;
            }
            d.vbl_index += 1;
            let time = d.vbl_index * panel.frame;
            d.vbl_count += 1;
            d.vbl_delta = if d.vbl_time == 0 { panel.frame } else { time - d.vbl_time };
            d.vbl_time = time;
            let shown = d.pending.take();
            let retired = if shown.is_some() { d.displayed.take() } else { None };
            let mut dropped = Vec::new();
            while let Some(r) = d.queue.pop_front() {
                if r.cancelled {
                    dropped.push(r);
                    continue;
                }
                d.pending = Some(r);
                break;
            }
            if let Some(s) = &shown {
                if s.kind == 0 || s.kind == 0xf {
                    d.display_swap_id = s.id;
                }
            }
            Some((d.vbl_count, time, d.vbl_delta, shown, retired, dropped))
        });
        let Some((count, time, delta, shown, retired, dropped)) = step else { break };
        if let Some(s) = shown {
            present(k, &s, count, time, panel);
            display(|d| d.displayed = Some(s));
        }
        for r in retired.into_iter().chain(dropped) {
            release_request(k, r);
        }
        let _ = delta;
    }
}

/// The vertical blanks up to now processed, whoever calls: the display
/// runs whether or not the task that swapped is still there to watch it.
pub fn catch_up(k: &mut Kernel) {
    advance(k, super::super::mach::absolute_time());
}

/// Swap `s`'s layers to the glass.
fn present(k: &mut Kernel, s: &Request, vbl: u64, time: u64, panel: Panel) {
    let mut frame = sink::Frame { swap_id: s.id, vbl, time, panel: (panel.width, panel.height), layers: Vec::new() };
    for (n, l) in s.layers.iter().enumerate() {
        let Some(id) = l.surface else { continue };
        if s.enabled & (1 << n) == 0 {
            continue;
        }
        let Some(g) = super::super::iosurface::geometry(id) else { continue };
        let count = if g.plane_count == 0 { 1 } else { g.plane_count };
        let planes = (0..count)
            .filter_map(|p| g.plane(p))
            .map(|p| sink::Plane { offset: p.offset, width: p.width, height: p.height, bytes_per_row: p.bytes_per_row, bytes_per_element: u32::from(p.bytes_per_element), element_width: u32::from(p.element_width), element_height: u32::from(p.element_height), size: p.size })
            .collect();
        let size = g.alloc_size as usize;
        let bytes = super::super::iosurface::with_bytes(k, id, |b| b[..size.min(b.len())].to_vec()).unwrap_or_default();
        let rect = |r: [i32; 4]| sink::Rect { x: r[0], y: r[1], w: r[2], h: r[3] };
        frame.layers.push(sink::Layer { index: n as u32, surface: id, pixel_format: g.pixel_format, width: g.width, height: g.height, planes, bytes, src: rect(l.src), dst: rect(l.dst), transform: l.transform });
    }
    match sink::sink() {
        Some(s) => {
            if let Err(why) = s.present(&frame) {
                k.darwin_unimplemented(format!("presenting swap {} on the embedder's panel: {why}", frame.swap_id));
            }
        }
        None => k.darwin_unimplemented(format!("presenting swap {}: no presentation sink is installed", frame.swap_id)),
    }
}

/// Whether a swap was ever displayed.
pub fn any_displayed() -> bool {
    display(|d| d.displayed.is_some())
}

/// Whether the calling task has a reason for the framebuffer's thread
/// call: swaps it made still on their way to the glass, or swap waits of
/// its threads.
pub fn wants_blanks(pid: i32, waits: bool) -> bool {
    waits || display(|d| d.pending.as_ref().is_some_and(|r| r.pid == pid) || d.queue.iter().any(|r| r.pid == pid))
}

/// When the next vertical blank after now comes, in absolute time.
pub fn next_blank() -> Option<u64> {
    let panel = panel().ok()?;
    let now = super::super::mach::absolute_time();
    Some((now / panel.frame + 1) * panel.frame)
}

// ---------------------------------------------------------------------------
// Swap waits.

/// What a swap wait waits for, by its options' low bits: 0 until the swap
/// is gone from the display (neither pending, queued nor displayed); 1
/// until it is no longer pending or queued; 2 until nothing is pending or
/// queued.
fn wait_satisfied(d: &Display, id: u32, mode: u32) -> Option<i32> {
    let displayed = d.display_swap_id == id;
    let found = d.pending.as_ref().filter(|r| r.id == id).or_else(|| d.queue.iter().find(|r| r.id == id));
    if let Some(r) = found {
        if r.cancelled {
            return Some(kr::ABORTED);
        }
    }
    let done = match mode {
        0 => !displayed && found.is_none(),
        1 => found.is_none(),
        _ => d.pending.is_none() && d.queue.is_empty(),
    };
    done.then_some(ret::SUCCESS)
}

/// The outcome of selector 6 now (`swap_wait`, 0xfffffff00678d998, gated
/// 0xfffffff00678b960): `Some` its result, `None` to wait. Options 3 and
/// 4 ask whether the display is enabled (`+0x16d0`, set at start);
/// bit 31 does not wait (kIOReturnBusy where it would). A timeout arms the
/// swap's own timer, which is not modelled (`Err`).
pub fn wait(k: &mut Kernel, id: u32, options: u32, timeout: u32) -> Result<Option<i32>, String> {
    let now = super::super::mach::absolute_time();
    advance(k, now);
    let no_block = options & 0x8000_0000 != 0;
    let mode = options & 0x7fff_ffff;
    // `+0x16e0`, a power transition in progress, is never set here; the
    // display is enabled (`+0x16d0`).
    if no_block && mode == 3 {
        return Ok(Some(ret::SUCCESS));
    }
    if no_block && mode == 4 {
        return Ok(Some(kr::BUSY));
    }
    match mode {
        3 => return Ok(Some(ret::SUCCESS)),
        4 => return Ok(Some(ret::BAD_ARGUMENT)),
        _ => {}
    }
    if timeout != 0 {
        return Err(format!("an IOMobileFramebuffer swap wait with a timeout ({timeout} ms): the swap's timer"));
    }
    let r = display(|d| wait_satisfied(d, id, mode.min(2)));
    if r.is_some() {
        return Ok(r);
    }
    if no_block {
        return Ok(Some(kr::BUSY));
    }
    Ok(None)
}

/// A waiting swap wait's outcome now, if it has one: its client stopped
/// ends the wait's loop with kIOReturnAborted (0xfffffff00678b960's loop
/// runs while the client has started).
pub fn wait_done(client: u32, id: u32, options: u32) -> Option<i32> {
    display(|d| if d.started.contains(&client) { wait_satisfied(d, id, (options & 0x7fff_ffff).min(2)) } else { Some(kr::ABORTED) })
}

/// A framebuffer client started.
pub fn client_started(client: u32) {
    display(|d| d.started.push(client));
}

/// A framebuffer client stopped.
pub fn client_stopped(client: u32) {
    display(|d| d.started.retain(|&c| c != client));
}

// ---------------------------------------------------------------------------
// Notifications.

/// Selector 72 with a callout, the framebuffer's gated enable
/// (0xfffffff006795ec0): a record already listed, or a type past the
/// slots, is kIOReturnError; else its async reference is set
/// (`setAsyncReference64`, but for frame information through a queue: the
/// slot's port and the callout, which no message here carries) and it is
/// listed. Vertical blank (5) calls AppleCLCD's slots 316 (empty)
/// and 290 (the pipe's kick, which programs a pending swap, none waiting
/// here); frame information (3) and CRC (4) turn the hardware's on, which
/// is not modelled (`Err`).
pub fn enable_notifications(client: u32, ty: usize, listed: bool) -> Result<i32, String> {
    if listed || ty >= super::NOTIFY_TYPES {
        return Ok(ret::ERROR);
    }
    match ty {
        3 => return Err("IOMobileFramebuffer frame information notifications (the pipe's frame statistics)".to_string()),
        4 => return Err("IOMobileFramebuffer CRC notifications (the pipe's CRC hardware)".to_string()),
        _ => {}
    }
    display(|d| d.records[ty].push(Record { client }));
    Ok(ret::SUCCESS)
}

/// A client's record for `ty` unlisted (the gated disable,
/// 0xfffffff006796198).
pub fn disable_notifications(client: u32, ty: usize) {
    display(|d| {
        if let Some(l) = d.records.get_mut(ty) {
            l.retain(|r| r.client != client);
        }
    });
}

impl Kernel {
    /// The framebuffer's thread call armed for the next vertical blank,
    /// when the task has a reason for it.
    pub(crate) fn darwin_iomfb_arm(&mut self) {
        let waits = self.dtask.pending_replies.iter().any(|p| matches!(p.op, super::super::kobject::Deferred::IomfbSwapWait { .. }));
        if !wants_blanks(self.pid, waits) || self.dtask.iomfb_call.is_some() {
            return;
        }
        let Some(at) = next_blank() else { return };
        let key = self.dtask.timers.arm(super::super::mach::abs_to_instant(at), super::super::timer::Action::Iomfb);
        self.dtask.iomfb_call = Some(key);
    }

    /// The framebuffer's thread call: the vertical blanks up to now, the
    /// task's swap waits answered, and the call armed again while needed.
    pub(crate) fn darwin_iomfb_blank(&mut self, m: &mut GuestMem<'_>) {
        self.dtask.iomfb_call = None;
        advance(self, super::super::mach::absolute_time());
        self.darwin_pending_ready(m);
        self.darwin_ipc_settle(m);
        self.darwin_iomfb_arm();
    }
}
