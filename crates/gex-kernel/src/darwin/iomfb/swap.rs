//! The framebuffer's swaps, its vertical blanks, its power and its
//! notifications, as `IOMobileFramebufferLegacy` (IOMobileGraphicsFamily)
//! runs them with AppleMobileDispH9G's `AppleCLCD` and pipe beneath:
//!
//! - A client begins a swap (selector 4: a request with the next swap id,
//!   in the begun list) and ends it with its transaction (selector 5: the
//!   1288-byte record the framework builds), which `swap_submit`
//!   (0xfffffff00678f224) checks, the pipe verifies, and the request goes
//!   to the queue.
//! - The kick (AppleCLCD slot 290, 0xfffffff006bfb384) takes the queue's
//!   head as the pending swap while the display is powered, once each layer
//!   it enables is completed (at its queueing, or by a swap signal); it
//!   drops a head that would change nothing as shown at once, and the
//!   cancelled requests. The vertical blank after completes the pending
//!   swap (0xfffffff00678a96c): each layer it enables goes on the glass in
//!   place of the one there, whose surface is let go, and the layers it
//!   does not enable stay as earlier swaps left them (0xfffffff00679534c);
//!   the glass then reaches the embedder's [`super::sink`].
//! - The console mode (0xfffffff00678c44c) hands the surface on the glass
//!   to the kernel's video console ([`super::super::vconsole`]): a shown
//!   swap that keeps its layers on screen turns it on, the first swap
//!   client turns it off, and the last one's going blanks the glass with
//!   the kernel's own swap and turns it on (0xfffffff00678b544).
//! - Swap waits (selector 6, `swap_wait_gated` 0xfffffff00678b960) sleep on
//!   the queue's event, which a completed swap, a removed one and
//!   `swap_cancel_all` wake, each for five seconds at most.
//! - Power (selector 12, AppleCLCD 0xfffffff006bf792c): a request for a
//!   power state is run by the power scheduler, which waits for the
//!   pending swap to complete and then sets the soft power state; the
//!   controller and the panel follow it (0xfffffff006bf7bc4), the swap
//!   queue is flushed at each controller change, the controller's last
//!   frame blanks the glass, the vertical blanks stop while the controller
//!   is off, and the clients that asked for power notifications are told.
//!   A signal ends a swap wait's or a power request's sleep, as
//!   `thread_abort_safely` does on the device ([`interrupt`]).
//! - No vertical blank message is sent. The family's only sender of them
//!   (0xfffffff006796720, the records of type 5 with each blank's count,
//!   time and delta) is called only by
//!   `IOMobileFramebufferLegacy::clear_up_swap_queue_gated`
//!   (0xfffffff00678a428), which AppleCLCD overrides (vtable slot 346,
//!   0xfffffff006bf710c) with one that sends none; AppleMobileDispH9G
//!   sends no async message at all. Turning type 5 on lists the record and
//!   calls slot 316 (empty on AppleCLCD) and slot 290, the kick.
//!
//! The panel is disp0's: its mode is the timing the device tree gives
//! (`display-timing-info`), and its vertical blanks come one frame apart,
//! a frame being two subframes of `subframe-duration-nclks` ([`Panel`]).
//! They are counted from the system's boot, while the controller is on.
//!
//! The display is one for every task: what a call changes is done by the
//! kernel of the task that made it, and a method of another task that
//! answers later is answered in its own task ([`Effect::Answer`]).

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use super::super::iokit::{ret, ASYNC_REF64_COUNT};
use super::super::ipc::{ObjId, TaskLink};
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
    pub const TIMEOUT: i32 = 0xe00002d6_u32 as i32;
    pub const VM_ERROR: i32 = 0xe00002c8_u32 as i32;
}

/// `clock_interval_to_deadline(ms, kMillisecondScale)`'s interval: `ms`
/// milliseconds in absolute time.
fn ms_to_abs(ms: u64) -> u64 {
    let (numer, denom) = super::super::mach::TIMEBASE;
    ms * 1_000_000 * u64::from(denom) / u64::from(numer)
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

/// Whether the panel is built in: AppleCLCD's `+0x1782`, which its
/// 0xfffffff006bf5a30 sets at start to the inverse of `external`, read
/// from disp0's device tree entry there. `Err` when disp0 is not in the
/// tree.
pub fn builtin() -> Result<bool, String> {
    let t = super::super::iokit::tree();
    let disp = t.iter().find(|n| n.props.iter().any(|(k, v)| k == "compatible" && v.split(|&c| c == 0).any(|c| c == b"disp0,t8011"))).ok_or("disp0 in the device tree")?;
    Ok(!disp.props.iter().any(|(k, _)| k == "external"))
}

/// The subframes a frame takes at the start (`+0x294`).
const SUBFRAMES: u64 = 2;


/// A layer of a request (the request's `+0x11 + 16 * n` source rectangle,
/// `+0x51 + 16 * n` destination, `+0x244 + 4 * n` transform, and the
/// record's words at `+0xec + 4 * n` and `+0xfc + 4 * n`, which it keeps at
/// `+0x214 + 4 * n` and `+0x234 + 4 * n`), and the surface it holds a
/// reference on (`+0xa40 + 8 * n`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LayerReq {
    pub surface: Option<u32>,
    pub src: [i32; 4],
    pub dst: [i32; 4],
    pub transform: u32,
    pub active_regions: u32,
    pub word_ec: u32,
    pub word_fc: u32,
}

/// An `IOMFBSwapIORequest` (0xba0 bytes): its swap id (`+0x314`), the
/// client that began it (`+0xad0`) and that client's task, whether it was
/// handed to swap_submit (`+0x54b`) or cancelled (`+0x54a`), its enabled
/// layers (`+0x318`) and the record's completed mask (`+0x31c`), its kind
/// (`+0x32c`), its status (`+0x34c`, the family's swap history codes: 2
/// programmed, 3 flushed, 4 displayed, 5 timed out, 7 dropped), its
/// presentation time (`+0x2d0`), the deadline a swap wait with a timeout
/// gave it (`+0x2c8`), and its layers. From the record besides: the word at
/// `+0x154` (`+0x320`, the display's `+0x16c4` once a swap enabling bit 31
/// is shown), the two words at `+0x16c` and `+0x174` (`+0x1b1`, `+0x1b9`),
/// KeepOnScreen (`+0x336`, kept at `+0x551`) and the flag at `+0x337`
/// (`+0x552`), which keeps a swap from being dropped as a no-op.
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
    pub status: u32,
    pub presentation: u64,
    pub deadline: u64,
    pub layers: [LayerReq; 4],
    pub word_154: u32,
    pub words_16c: [u64; 2],
    pub keep_on_screen: bool,
    pub no_drop: bool,
    /// `+0x555` (the record's `+0x34f`): queued at the head.
    pub ahead: bool,
    /// `+0xa60 + 8 * n`: whether layer `n` would show a surface once this
    /// swap is shown (0xfffffff006799c68).
    pub shows: [bool; 4],
}

/// A notification record a client listed for a type (`+0x118 + type *
/// 0xb0` of the client, listed at the framebuffer's `+0x1588 + type * 16`):
/// its client, and the async reference the enable set
/// (`setAsyncReference64` at the record's `+0x18`: the slot's port, the
/// callout and its reference).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub client: u32,
    pub port: Option<ObjId>,
    pub reference: [u64; ASYNC_REF64_COUNT],
}

/// The display's power, AppleCLCD's: the hard power state (`+0x16cc`),
/// the soft one selector 12 sets (`+0x16d0`), the controller's and the
/// panel's (`+0x16d4`, `+0x16d8`), the state requested (`+0x16dc`) and
/// whether a request is with the power scheduler (`+0x16e0`). All are on
/// at start (0xfffffff006bf55ec). The power scheduler
/// (`iomfb_api_pstate_sched`, `+0x1dc8`) runs its actions in turn, and the
/// state changes take the PState ticket (`+0x1ed0`, `+0x1ed4`) in order,
/// each waiting for the pending swap to complete before it is made.
#[derive(Debug)]
struct Power {
    hard: u32,
    soft: u32,
    controller: bool,
    panel: bool,
    requested: u32,
    transition: bool,
    /// The timing generator (`+0x1e49`, AppleCLCD slot 345): enabled by the
    /// panel's link coming up (0xfffffff006bfe078, the link the bootloader
    /// brought up at boot) and as the controller comes on with the link up
    /// (0xfffffff006bf7bc4), disabled as it goes off (0xfffffff006bf6e20).
    timing: bool,
    /// The scheduler's actions not yet run, and whether one is running (its
    /// change waiting for its turn).
    jobs: u32,
    scheduling: bool,
    /// The changes holding or waiting for the ticket, in its order, and the
    /// task each was asked by.
    changes: VecDeque<(Change, i32)>,
}

/// A power state change (`AppleCLCD` slot 354, 0xfffffff006bf79a8).
#[derive(Clone, Debug)]
enum Change {
    /// The soft state set (0xfffffff00678b858 with no hard state): the
    /// power scheduler's action, which wakes the requests waiting on
    /// `+0x16e0` once made (`sched`), or the last swap client's going.
    Soft { state: u32, sched: bool },
    /// The states evaluated again (0xfffffff006795b18).
    Evaluate,
    /// Not a change: the last swap client's going (0xfffffff00678b544)
    /// goes on once the soft state it asked for is set, and the
    /// io_service_close waiting for it with it.
    LastClient(Option<(Arc<TaskLink>, u64)>),
}

/// How the pending swap completes (0xfffffff00678a96c): shown at the
/// vertical blank of that count and time, shown at once as a no-op
/// (0xfffffff006795b88), or not shown (a flush).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shown {
    Blank(u64, u64),
    NoOp,
    Flush,
}

/// 0xfffffff00679d40c: the kinds the kick's upkeep keeps (0, 3, 5 to 10,
/// 12, 13, 16, 18, 21), ahead of which it drops the others.
fn kind_lets_through(kind: u32) -> bool {
    matches!(kind, 0 | 3 | 5..=10 | 12 | 13 | 16 | 18 | 21)
}

/// What a sleeping swap wait or power request waits on: the power
/// scheduler (`+0x16e0`, 0xfffffff00678db9c), or the swap queue
/// (`+0x1568`, with a five-second deadline).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sleep {
    Power,
    Queue { deadline: u64 },
}

/// A swap wait asleep (selector 6): the token it answers by and the task
/// that waits, its client, swap id, mode (the options' low 31 bits) and
/// whether it may block (bit 31 clear), its timeout and the deadline that
/// gave the swap (`local_58`), the times it went to sleep on the queue
/// (`local_64`), and what it sleeps on.
#[derive(Debug)]
struct Waiter {
    token: u64,
    then: Then,
    pid: i32,
    client: u32,
    id: u32,
    mode: u32,
    no_block: bool,
    timeout: u32,
    swap_deadline: u64,
    sleeps: u32,
    on: Sleep,
}

/// What a swap wait does when it ends: a task's answers its call; the
/// kernel's own in the last swap client's going (0xfffffff00678b544, with
/// no client) goes on with that work, and then answers the io_service_close
/// that waits for it, if one does.
#[derive(Debug)]
enum Then {
    Answer(Arc<TaskLink>),
    LastClient(Option<(Arc<TaskLink>, u64)>),
}

/// The framebuffer as the IOSurface root knows it (its display table's key).
const DISPLAY_KEY: u64 = 1;

/// The kernel's own swaps and waits have no client.
pub const KERNEL: u32 = u32::MAX;

/// A power request asleep (selector 12 while a request is with the
/// scheduler): the token it answers by, its task and the state it asks.
#[derive(Debug)]
struct PowerCaller {
    token: u64,
    link: Arc<TaskLink>,
    state: u32,
}

/// The display's console mode (0xfffffff00678c44c): whether it is on
/// (`+0x178e`), whether a shown swap left it on (KeepOnScreen, `+0x178d`),
/// whether `IOMFBSetConsoleMode` holds it (`+0x1898`) or `IOMFBSkipSpinner`
/// keeps it off the surface (`+0x1899`), whether `IOMFBPreserveContents`
/// keeps the glass when the last swap client goes (`+0x1897`), the layers
/// whose surface it mapped for the console (`+0x1438 + 8 * n`), and the
/// service's `SystemConsoleMode` once set. The setters of `+0x1897` to
/// `+0x1899` are the framebuffer's setProperties, not modelled, so they
/// stay as start leaves them (clear).
#[derive(Debug, Default)]
struct Console {
    on: bool,
    kept: bool,
    forced: bool,
    skip_spinner: bool,
    preserve: bool,
    mapped: [bool; 4],
    property: Option<bool>,
}

/// What a change of the display does in the kernel that made it, once the
/// display's lock is let go.
#[derive(Debug)]
pub enum Effect {
    /// A request's surfaces let go.
    Release(Request),
    /// A surface the glass held let go.
    ReleaseSurface(u32),
    /// The glass after swap `.0` at the blank (its count and time): the
    /// layers on it, by index.
    Present(u32, u64, u64, Vec<(u32, LayerReq)>),
    /// A method that answered later answered, in its task.
    Answer { link: Arc<TaskLink>, token: u64, ret: i32 },
    /// An async result to a notification record's port
    /// (`sendAsyncResult64WithOptions` with `kIOUserNotifyOptionCanDrop`).
    Notify { port: ObjId, reference: [u64; ASYNC_REF64_COUNT], args: [u64; 2] },
    /// The panel lit or dark.
    Panel(bool),
    /// The IOSurface root told what a layer shows now (0xfffffff005bacfe0).
    Displayed(u32, Option<u32>),
    /// What is not modelled, reported.
    Unimplemented(String),
}

/// The framebuffer's swap, display and power state.
struct Display {
    panel: Option<Panel>,
    /// `+0x16b8`: the last swap id given.
    next_id: u32,
    /// `+0x1578`: begun requests; `+0x1568`: the queue; `+0x1560`: the
    /// pending swap; the display's swap id (`+0x16bc`).
    begun: Vec<Request>,
    queue: VecDeque<Request>,
    pending: Option<Request>,
    display_swap_id: u32,
    /// The layers on the glass (`+0x1358 + 8 * n` their surfaces, with the
    /// rectangles and transform their swaps gave), each holding a reference
    /// on its surface.
    glass: [Option<LayerReq>; 4],
    /// The glass's words at `+0x11f1` and `+0x11f9` (a shown layer 2's
    /// swap's `+0x16c` and `+0x174`), and bit 31's word (`+0x16c4`).
    glass_words_16c: [u64; 2],
    glass_154: u32,
    /// `+0x1787`: a client's swap (kind 0) was shown.
    swapped: bool,
    console: Console,
    /// The last vertical blank reached (its index since boot), the count
    /// (`+0x100`), its time (`+0x108`) and the time since the one before
    /// (`+0x110`).
    vbl_index: u64,
    vbl_count: u64,
    vbl_time: u64,
    vbl_delta: u64,
    /// `+0x16f8`: the swap clients registered.
    swap_clients: u32,
    records: [Vec<Record>; super::NOTIFY_TYPES],
    /// The clients started and not stopped.
    started: Vec<u32>,
    power: Power,
    waiters: Vec<Waiter>,
    power_callers: Vec<PowerCaller>,
    /// Each client's `+0xf8` and `+0x100`: the swap its swap wait waits for,
    /// and whether that swap was removed while it waited.
    client_wait: HashMap<u32, (u32, bool)>,
    /// `+0x118`: the swap timer's deadline, the earliest a swap wait gave a
    /// queued request; 0 when not armed.
    swap_timer: u64,
    /// `+0x16e4`: the requests the swap timer removed since a swap last
    /// completed.
    timed_out: u32,
    effects: Vec<Effect>,
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
        glass: [None; 4],
        glass_words_16c: [0; 2],
        glass_154: 0,
        swapped: false,
        console: Console::default(),
        display_swap_id: 0,
        vbl_index: 0,
        vbl_count: 0,
        vbl_time: 0,
        vbl_delta: 0,
        swap_clients: 0,
        records: Default::default(),
        started: Vec::new(),
        power: Power { hard: 1, soft: 1, controller: true, panel: true, requested: 0, transition: false, timing: true, jobs: 0, scheduling: false, changes: VecDeque::new() },
        waiters: Vec::new(),
        power_callers: Vec::new(),
        client_wait: HashMap::new(),
        swap_timer: 0,
        timed_out: 0,
        effects: Vec::new(),
    });
    f(d)
}

/// Run `f` on the display, then do what it left to do.
fn with_display<R>(k: &mut Kernel, f: impl FnOnce(&mut Display) -> R) -> R {
    let (r, effects) = display(|d| {
        let r = f(d);
        (r, std::mem::take(&mut d.effects))
    });
    perform(k, effects);
    r
}

/// The panel, or what the device tree lacks to describe it.
pub fn panel() -> Result<Panel, String> {
    display(|d| d.panel).ok_or_else(|| Panel::from_tree().err().unwrap_or_default())
}

/// The effects of a change done, in order.
fn perform(k: &mut Kernel, effects: Vec<Effect>) {
    for e in effects {
        match e {
            Effect::Release(r) => release_request(k, r),
            Effect::ReleaseSurface(id) => super::super::iosurface::kernel_release(k, id),
            Effect::Present(swap, vbl, time, layers) => present(k, swap, vbl, time, &layers),
            Effect::Answer { link, token, ret } => {
                link.mailbox.lock().unwrap_or_else(|e| e.into_inner()).push(super::super::ipc::Remote::Later { token, ret, scalars: Vec::new() });
                link.bell.ring();
            }
            Effect::Notify { port, reference, args } => k.darwin_io_async_result(port, &reference, ret::SUCCESS, &args, true),
            Effect::Panel(on) => match sink::sink() {
                Some(s) => {
                    if let Err(why) = s.panel(on) {
                        k.darwin_unimplemented(format!("turning the embedder's panel {}: {why}", if on { "on" } else { "off" }));
                    }
                }
                None => k.darwin_unimplemented(format!("turning the panel {}: no presentation sink is installed", if on { "on" } else { "off" })),
            },
            Effect::Displayed(layer, surface) => super::super::iosurface::displayed(DISPLAY_KEY, layer, surface),
            Effect::Unimplemented(what) => k.darwin_unimplemented(what),
        }
    }
}

// ---------------------------------------------------------------------------
// Swap clients.

/// `IOMobileFramebufferLegacy` slot 169 (0xfffffff0067891d8): a client
/// that swaps registered (`+0x16f8`). The first calls slot 171 (AppleCLCD's
/// 0xfffffff006bfc590, whose family and pipe parts are empty) and, unless
/// a shown swap left the console mode on (0xfffffff00678b834), turns the
/// console mode off (gated 0xfffffff00678c44c).
pub fn add_swap_client(k: &mut Kernel) {
    let pid = k.pid;
    with_display(k, |d| {
        d.swap_clients += 1;
        if d.swap_clients == 1 && !d.console.kept {
            d.console_mode(false, Gate::FirstClient, pid, super::super::mach::absolute_time());
        }
    });
    k.darwin_iomfb_arm();
}

/// Slot 170 (0xfffffff00678c998): the client's swaps cleared (gated
/// 0xfffffff00678a214), and the last swap client's going handled (gated
/// 0xfffffff00678b544, [`Display::last_client`]; slot 172, AppleCLCD's
/// 0xfffffff006bfc5f8, does nothing more for a panel neither external nor
/// standalone).
///
/// The clearing: each begun request of the client not yet handed to
/// swap_submit removed (status 7) and one handed to it marked cancelled;
/// each queued request of the client removed (status 7); the kick; and
/// the swap queue's waiters woken when the client was waiting for a swap
/// (`+0xf8`).
///
/// The last swap client's going sleeps in the calling thread (its power
/// change, and its wait for the kernel's blanking swap): `closer` is the
/// io_service_close that waits for it, answered once it is done; the
/// result is whether one waits.
pub fn remove_swap_client(k: &mut Kernel, client: u32, closer: Option<u64>) -> bool {
    let pid = k.pid;
    let link = k.dtask.ipc_raw.link.clone();
    let waits = with_display(k, |d| {
        let now = super::super::mach::absolute_time();
        let mut i = 0;
        while i < d.begun.len() {
            if d.begun[i].client != client {
                i += 1;
            } else if !d.begun[i].submitted {
                let r = d.begun.remove(i);
                d.remove_request(r, 7);
            } else {
                d.begun[i].cancelled = true;
                i += 1;
            }
        }
        let mut i = 0;
        while i < d.queue.len() {
            if d.queue[i].client == client {
                let r = d.queue.remove(i).expect("a queued request");
                d.remove_request(r, 7);
            } else {
                i += 1;
            }
        }
        d.kick(pid, now);
        if d.client_wait.get(&client).is_some_and(|w| w.0 != 0) {
            d.wake_queue(now);
        }
        d.swap_clients = d.swap_clients.saturating_sub(1);
        if d.swap_clients != 0 {
            return false;
        }
        let closer = closer.zip(link).map(|(token, link)| (link, token));
        let waits = closer.is_some();
        if !d.last_client(closer, pid, now) {
            return false;
        }
        waits
    });
    // The display's events the going waits for (its power change, the
    // kernel's swap) are this task's to watch.
    k.darwin_iomfb_arm();
    waits
}

/// A client gone: its notification records dropped.
pub fn client_gone(_k: &mut Kernel, client: u32) {
    display(|d| {
        d.records.iter_mut().for_each(|l| l.retain(|r| r.client != client));
        d.client_wait.remove(&client);
    });
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
    pub const WORD_154: usize = 0x154;
    pub const WORD_EC: usize = 0xec;
    pub const WORD_FC: usize = 0xfc;
    pub const TRANSFORM: usize = 0x15c;
    pub const WORDS_16C: usize = 0x16c;
    pub const KIND: usize = 0x17c;
    pub const REGION_COUNT: usize = 0x188;
    pub const EXCLUDES: usize = 0x2cd;
    pub const KEEP_ON_SCREEN: usize = 0x336;
    pub const NO_DROP: usize = 0x337;
    pub const AHEAD: usize = 0x34f;
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
    req.word_154 = u32_at(record, rec::WORD_154);
    req.kind = u32_at(record, rec::KIND);
    req.keep_on_screen = record[rec::KEEP_ON_SCREEN] & 1 != 0;
    req.no_drop = record[rec::NO_DROP] & 1 != 0;
    req.ahead = record[rec::AHEAD] & 1 != 0;
    req.words_16c = [u64_at(record, rec::WORDS_16C), u64_at(record, rec::WORDS_16C + 8)];
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
        l.word_ec = u32_at(record, rec::WORD_EC + 4 * n);
        l.word_fc = u32_at(record, rec::WORD_FC + 4 * n);
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
        // The record's presentation, frame generation and HID input times
        // (its first three words) go to IOSurface::setTimestamp
        // (0xfffffff005ba1234), which keeps nothing without the
        // `iosurface_timestamp_enable` boot-arg, which this boot does not
        // pass. The source rectangle inside the surface.
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
    // The display is on (`+0x16cc`), so the request goes to the pipe
    // (0xfffffff0067909ac): verify_swap, the DRM checks, each layer's
    // surface prepared, and the request queued.
    let r = match verify(&mut req) {
        Err(what) => {
            k.darwin_unimplemented(what);
            Err(ret::ERROR)
        }
        Ok(false) => Err(ret::BAD_ARGUMENT),
        Ok(true) => Ok(()),
    };
    // Queued (gated 0xfffffff0067916f8, [`Display::enqueue`]); a controller
    // that is off while the display is hard on evaluated again
    // (0xfffffff006791644: the soft state is not kept on by `+0x178a`,
    // never set here); and the kick.
    let pid = k.pid;
    let r = match r {
        Err(e) => Err((e, req)),
        Ok(()) => with_display(k, |d| {
            let now = super::super::mach::absolute_time();
            d.enqueue(req, pid, now)?;
            if !d.power.controller && d.power.hard != 0 {
                d.change(Change::Evaluate, pid, now);
            }
            d.kick(pid, now);
            Ok(())
        }),
    };
    match r {
        Ok(()) => {
            k.darwin_iomfb_arm();
            ret::SUCCESS
        }
        Err((e, req)) => {
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

/// Selector 20's `swap_signal(id, layer)` (slot 179, 0xfffffff006791ffc,
/// gated 0xfffffff0067869cc): a layer past 3 is kIOReturnBadArgument; a
/// queued request by that id has the layer marked completed and the kick
/// run, unless it does not enable the layer (kIOReturnBadArgument); a begun
/// one has it marked completed; none is kIOReturnError. The pending swap is
/// not looked at. (The frame statistics object it would tell, `+0x1650`,
/// is never made.)
pub fn signal(k: &mut Kernel, id: u32, layer: u32) -> i32 {
    if layer >= 4 {
        return ret::BAD_ARGUMENT;
    }
    let pid = k.pid;
    let r = with_display(k, |d| {
        let bit = 1u32 << layer;
        if let Some(r) = d.queue.iter_mut().find(|r| r.id == id) {
            if r.enabled & bit == 0 {
                return ret::BAD_ARGUMENT;
            }
            r.completed |= bit;
            d.kick(pid, super::super::mach::absolute_time());
            return ret::SUCCESS;
        }
        match d.begun.iter_mut().find(|r| r.id == id) {
            Some(r) => {
                r.completed |= bit;
                ret::SUCCESS
            }
            None => ret::ERROR,
        }
    });
    k.darwin_iomfb_arm();
    r
}

// ---------------------------------------------------------------------------
// Cancelling.

/// Slot 217's gated `swap_cancel` (0xfffffff006789460): a begun request
/// not yet handed to swap_submit is removed (status 7); one handed to it,
/// or a queued one, is marked cancelled; none by that id is
/// kIOReturnBadArgument. The pending swap is not looked at, and no waiter
/// is woken.
pub fn cancel(k: &mut Kernel, id: u32) -> i32 {
    with_display(k, |d| {
        if let Some(i) = d.begun.iter().position(|r| r.id == id) {
            if !d.begun[i].submitted {
                let r = d.begun.remove(i);
                d.remove_request(r, 7);
            } else {
                d.begun[i].cancelled = true;
            }
            return ret::SUCCESS;
        }
        match d.queue.iter_mut().find(|r| r.id == id) {
            Some(r) => {
                r.cancelled = true;
                ret::SUCCESS
            }
            None => ret::BAD_ARGUMENT,
        }
    })
}

/// Slot 218's `swap_cancel_all(time)` (0xfffffff0067a0488): each begun
/// request of kind 0 removed (status 7) if not yet handed to swap_submit,
/// else marked cancelled; the queued ones of kind 0 from the first whose
/// presentation time is at `time` or later marked cancelled; then slot 309
/// and the swap queue's waiters woken.
pub fn cancel_all(k: &mut Kernel, time: u64) -> i32 {
    with_display(k, |d| {
        d.cancel_all(time, super::super::mach::absolute_time());
        ret::SUCCESS
    })
}

// ---------------------------------------------------------------------------
// The display's state machine.

impl Display {
    /// 0xfffffff0067a0488 (see [`cancel_all`]).
    fn cancel_all(&mut self, time: u64, now: u64) {
        let mut i = 0;
        while i < self.begun.len() {
            if self.begun[i].kind != 0 {
                i += 1;
            } else if !self.begun[i].submitted {
                let r = self.begun.remove(i);
                self.remove_request(r, 7);
            } else {
                self.begun[i].cancelled = true;
                i += 1;
            }
        }
        if let Some(first) = self.queue.iter().position(|r| time <= r.presentation) {
            for r in self.queue.iter_mut().skip(first) {
                if r.kind == 0 {
                    r.cancelled = true;
                }
            }
        }
        self.wake_queue(now);
    }

    /// `IOMobileFramebufferLegacy`'s request removal (AppleCLCD slot 340,
    /// 0xfffffff006bf6798, to 0xfffffff006789698): the request marked
    /// cancelled with its status, its surfaces let go, and the client that
    /// began it told, when it is waiting for this swap, that it went
    /// (`+0x100`). The caller has taken it out of its list.
    fn remove_request(&mut self, mut r: Request, status: u32) {
        r.cancelled = true;
        r.status = status;
        if let Some(w) = self.client_wait.get_mut(&r.client) {
            if w.0 == r.id {
                w.1 = true;
            }
        }
        self.effects.push(Effect::Release(r));
    }

    /// The kick (AppleCLCD slot 290, 0xfffffff006bfb384), which programs the
    /// queue's head while the display is powered (the soft state, the
    /// controller and the timing generator on) and no swap is pending. Its
    /// queue upkeep first (0xfffffff00679c6c0, slot 311, runs only with the
    /// `iomfb_drop_obsolete_swap` boot-arg, which this boot has none of):
    /// - A no-op head dropped (0xfffffff00679d228, slot 313; on by default,
    ///   `+0x1895`, and `+0x178c` is never set): a head whose layers are all
    ///   completed and that would change nothing on the glass
    ///   ([`Display::noop`]) is made pending and completed as shown at once
    ///   (0xfffffff00679cf6c with 0xfffffff006795b88), no blank waited for.
    /// - Each request ahead of the first of a kind 0xfffffff00679d40c lets
    ///   through dropped (0xfffffff00679d584, slot 314).
    /// - Every cancelled request removed (0xfffffff00679c5ac, slot 309).
    ///
    /// Then the head is taken unless some of its enabled layers are not
    /// yet completed (`+0x318 != +0x31c`, "swap was not completed": it
    /// waits for its swap signals), status 2. The pipe's readiness check
    /// (0xfffffff006bd2f24) passes with `AOTEnable` off; the kinds with a
    /// path of their own here (8, 0x13) are refused at submission.
    fn kick(&mut self, pid: i32, now: u64) {
        if self.pending.is_some() || self.power.soft == 0 || !self.power.controller || !self.power.timing {
            return;
        }
        if self.queue.front().is_some_and(|h| h.enabled == h.completed && self.noop(h)) {
            let mut r = self.queue.pop_front().expect("a queued request");
            r.status = 8;
            self.pending = Some(r);
            self.complete_pending(Shown::NoOp, pid, now);
        }
        self.drop_ahead_of_kind(pid, now);
        let mut i = 0;
        while i < self.queue.len() {
            if self.queue[i].cancelled {
                let r = self.queue.remove(i).expect("a queued request");
                self.remove_request(r, 7);
            } else {
                i += 1;
            }
        }
        let Some(head) = self.queue.front() else { return };
        if head.enabled != head.completed {
            return;
        }
        let mut r = self.queue.pop_front().expect("a queued request");
        r.status = 2;
        self.pending = Some(r);
    }

    /// Slot 314 (0xfffffff00679d584): the first queued request of a kind
    /// 0xfffffff00679d40c lets through (0, 3, 5 to 10, 12, 13, 16, 18, 21),
    /// with no presentation time, has each request ahead of it but of kind
    /// 2 dropped (0xfffffff00679cf6c with no display: completed unshown).
    /// One with a presentation time asks the display's timing (slot 301,
    /// 0xfffffff006bf4b00), which is not modelled.
    fn drop_ahead_of_kind(&mut self, pid: i32, now: u64) {
        let Some(first) = self.queue.iter().position(|r| kind_lets_through(r.kind)) else { return };
        if first == 0 {
            return;
        }
        if self.queue[first].presentation != 0 {
            self.effects.push(Effect::Unimplemented(format!("dropping the IOMobileFramebuffer swaps queued ahead of swap {} (kind {}, presentation time {:#x}): the display's timing (AppleCLCD slot 301, 0xfffffff006bf4b00)", self.queue[first].id, self.queue[first].kind, self.queue[first].presentation)));
            return;
        }
        let (mut i, mut end) = (0, first);
        while i < end {
            if self.queue[i].kind == 2 {
                i += 1;
                continue;
            }
            let mut r = self.queue.remove(i).expect("a queued request");
            end -= 1;
            r.status = 8;
            self.pending = Some(r);
            self.complete_pending(Shown::Flush, pid, now);
        }
    }

    /// Whether `r` would change nothing on the glass (AppleCLCD slot 310,
    /// 0xfffffff006bfa974, then IOMobileFramebufferLegacy's,
    /// 0xfffffff00679c9d8): the record's words at `+0x174` as the glass has
    /// them (the pipe's slot 0xbd8 answers false); bit 31's word, when
    /// enabled, as shown; not kept from dropping (`+0x552`; slot 323 answers
    /// false); layer 2's words at `+0x16c` as shown when it has a surface;
    /// kind 0; and each enabled layer's surface as on the glass, and for one
    /// with a surface its source, transform, `+0x214` word, destination and
    /// DMA address (`+0x258`, the same for the same surface while the glass
    /// holds its mapping) as there.
    fn noop(&self, r: &Request) -> bool {
        if r.words_16c[1] != self.glass_words_16c[1] {
            return false;
        }
        if r.enabled & 0x8000_0000 != 0 && r.word_154 != self.glass_154 {
            return false;
        }
        if r.no_drop {
            return false;
        }
        if r.enabled & 4 != 0 && r.layers[2].surface.is_some() && r.words_16c[0] != self.glass_words_16c[0] {
            return false;
        }
        if r.kind != 0 {
            return false;
        }
        (0..4).filter(|n| r.enabled & (1 << n) != 0).all(|n| {
            let (l, g) = (&r.layers[n], self.glass[n]);
            match g {
                None => l.surface.is_none(),
                Some(g) => l.surface == g.surface && (l.surface.is_none() || (l.src == g.src && l.transform == g.transform && l.word_ec == g.word_ec && l.dst == g.dst)),
            }
        })
    }

    /// The pending swap completed (0xfffffff00678a96c), shown at a vertical
    /// blank, shown with no blank as a no-op, or flushed:
    /// - Shown (0xfffffff00679534c): each layer it enables goes on the glass
    ///   in place of the one there, whose surface is let go
    ///   (0xfffffff00679437c), with its rectangles, transform and words (a
    ///   layer with no surface clears the glass's layer and the glass's
    ///   words at `+0x16c`; layer 2's surface brings its swap's); bit 31's
    ///   word is kept (`+0x16c4`) when enabled; and after a blank the glass
    ///   reaches the sink, while a no-op leaves the panel as it was.
    /// - Flushed: each enabled layer dropped and the request cancelled,
    ///   status 7.
    ///
    /// Either way a swap of kind 0 or 15 is the display's swap id; one not
    /// cancelled of kind 0 marks that a client's swap was shown (`+0x1787`).
    /// The swap queue's waiters are woken, the swap timer's count of
    /// removals starts again, and with the soft state off and the
    /// controller on the power states are evaluated again once the pending
    /// swap is gone (0xfffffff006795b18). The residency counts kept for
    /// statistics (0xfffffff006795208, 0xfffffff006794ad4, slot 343) are
    /// read by nothing here.
    fn complete_pending(&mut self, shown: Shown, pid: i32, now: u64) {
        let Some(mut req) = self.pending.take() else { return };
        match shown {
            Shown::Blank(..) | Shown::NoOp => {
                req.status = 4;
                for n in 0..4 {
                    if req.enabled & (1 << n) == 0 {
                        continue;
                    }
                    if let Some(old) = self.glass[n].take().and_then(|l| l.surface) {
                        self.effects.push(Effect::ReleaseSurface(old));
                        // The console's mapping of it let go, the console
                        // mode turned off first while on.
                        if std::mem::take(&mut self.console.mapped[n]) && self.console.on {
                            self.console_mode(false, Gate::Completion, pid, now);
                        }
                    }
                    // The request's reference goes to the glass.
                    let l = std::mem::take(&mut req.layers[n]);
                    if l.surface.is_some() {
                        if n == 2 {
                            self.glass_words_16c = req.words_16c;
                        }
                        self.glass[n] = Some(l);
                    } else {
                        self.glass_words_16c = [0; 2];
                    }
                    // IOSurfaceDisplayTimes' "display-complete" for a layer
                    // with a surface goes through IOSurface::setTimestamp
                    // (0xfffffff005ba1234), which keeps nothing without the
                    // `iosurface_timestamp_enable` boot-arg (the root's
                    // `+0x1b0`), which this boot does not pass. Then the
                    // root is told what the layer shows.
                    self.effects.push(Effect::Displayed(n as u32, self.glass[n].and_then(|g| g.surface)));
                }
                if req.enabled & 0x8000_0000 != 0 {
                    self.glass_154 = req.word_154;
                }
                if let Shown::Blank(count, time) = shown {
                    let layers = (0..4u32).filter_map(|n| self.glass[n as usize].map(|l| (n, l))).collect();
                    self.effects.push(Effect::Present(req.id, count, time, layers));
                }
            }
            Shown::Flush => {
                if req.enabled & 0xf != 0 {
                    req.cancelled = true;
                }
                req.status = 7;
            }
        }
        if req.kind == 0 || req.kind == 0xf {
            self.display_swap_id = req.id;
        }
        // A shown swap's KeepOnScreen is the console mode's, when it differs.
        let toggle = !req.cancelled && req.kind == 0 && self.console.kept != req.keep_on_screen;
        if !req.cancelled && req.kind == 0 {
            self.swapped = true;
        }
        let kept = req.keep_on_screen;
        self.effects.push(Effect::Release(req));
        if toggle {
            self.console.kept = kept;
            self.console_mode(kept, Gate::Completion, pid, now);
        }
        self.wake_queue(now);
        self.timed_out = 0;
        if self.power.soft == 0 && self.power.controller {
            self.change(Change::Evaluate, pid, now);
        }
    }

    /// `clear_up_swap_queue_gated` (AppleCLCD slot 346, 0xfffffff006bf710c):
    /// a pending swap that is not being flushed (status 3) goes back to the
    /// queue's head, and (with no always-on display state in hand,
    /// `+0x1e4c`) each queued request in turn is made pending (in the place
    /// of one being flushed, which is dropped) and completed without being
    /// shown.
    fn flush(&mut self, pid: i32, now: u64) {
        if let Some(p) = self.pending.take() {
            if p.status == 3 {
                self.pending = Some(p);
            } else {
                self.queue.push_front(p);
            }
        }
        while let Some(mut r) = self.queue.pop_front() {
            r.status = 3;
            self.pending = Some(r);
            self.complete_pending(Shown::Flush, pid, now);
        }
    }

    /// The swap queue's event woken (`commandWakeup(&+0x1568)`): each swap
    /// wait asleep on it resumes, in turn.
    fn wake_queue(&mut self, now: u64) {
        let (woken, rest): (Vec<Waiter>, Vec<Waiter>) = std::mem::take(&mut self.waiters).into_iter().partition(|w| matches!(w.on, Sleep::Queue { .. }));
        self.waiters = rest;
        for w in woken {
            self.wait_resume(w, false, now);
        }
    }

    /// The power scheduler's event woken (`commandWakeup(&+0x16e0)`): the
    /// swap waits and power requests asleep on it look again.
    fn wake_power(&mut self, pid: i32, now: u64) {
        let (woken, rest): (Vec<Waiter>, Vec<Waiter>) = std::mem::take(&mut self.waiters).into_iter().partition(|w| w.on == Sleep::Power);
        self.waiters = rest;
        for w in woken {
            self.wait_power_done(w, now);
        }
        for c in std::mem::take(&mut self.power_callers) {
            if let Some(r) = self.request_power(c.state, pid, now) {
                self.effects.push(Effect::Answer { link: c.link, token: c.token, ret: r });
            } else {
                self.power_callers.push(c);
            }
        }
    }

    /// `swap_cancel_all` with the time now after `clear_up_swap_queue`: what
    /// a swap wait that gives up does (slots 346 and 218).
    fn clear_swaps(&mut self, pid: i32, now: u64) {
        self.flush(pid, now);
        self.cancel_all(now, now);
    }

    /// The swap timer (0xfffffff0067881b8): each queued request whose
    /// deadline has passed removed (status 5), the waiters woken if one was,
    /// the kick, and the timer armed again for the earliest deadline left.
    /// More than four removals before a swap completes panic only with
    /// `+0x189a`, which nothing sets here.
    fn swap_timer_fire(&mut self, pid: i32, now: u64) {
        self.swap_timer = 0;
        let mut removed = false;
        let mut next = 0u64;
        let mut i = 0;
        while i < self.queue.len() {
            let deadline = self.queue[i].deadline;
            if deadline == 0 {
                i += 1;
                continue;
            }
            if deadline < now {
                self.timed_out += 1;
                let r = self.queue.remove(i).expect("a queued request");
                self.remove_request(r, 5);
                removed = true;
                continue;
            }
            if next == 0 || deadline < next {
                next = deadline;
            }
            i += 1;
        }
        if removed {
            self.wake_queue(now);
        }
        self.kick(pid, now);
        if next != 0 {
            self.swap_timer = next;
        }
    }

    /// A vertical blank at `time`, index `index`: counted, the pending swap
    /// completed and shown, the kick, and a power change waiting for the
    /// pending swap made if none is pending now.
    fn blank(&mut self, index: u64, time: u64, pid: i32, now: u64) {
        let frame = self.panel.map_or(0, |p| p.frame);
        self.vbl_index = index;
        self.vbl_count += 1;
        self.vbl_delta = if self.vbl_time == 0 { frame } else { time - self.vbl_time };
        self.vbl_time = time;
        if self.pending.is_some() {
            self.complete_pending(Shown::Blank(self.vbl_count, time), pid, now);
        }
        self.kick(pid, now);
        self.power_turn(now);
    }

    /// The display's timed events up to `now`, in order: its vertical
    /// blanks while the controller is on, the swap timer, and the swap
    /// waits' five-second deadlines.
    fn advance(&mut self, pid: i32, now: u64) {
        let Some(panel) = self.panel else { return };
        loop {
            let blank = (self.power.controller).then(|| (self.vbl_index + 1) * panel.frame);
            let timer = (self.swap_timer != 0).then_some(self.swap_timer);
            let wait = self.waiters.iter().filter_map(|w| match w.on {
                Sleep::Queue { deadline } => Some(deadline),
                Sleep::Power => None,
            }).min();
            let next = [blank, timer, wait].into_iter().flatten().min();
            let Some(at) = next.filter(|&t| t <= now) else { break };
            if blank == Some(at) {
                // With nothing to complete, program or wait for, the blanks
                // before the next other event change nothing but the count.
                let idle = self.pending.is_none() && (self.queue.is_empty() || self.power.soft == 0) && self.power.changes.is_empty();
                let until = [timer, wait].into_iter().flatten().min().unwrap_or(u64::MAX).min(now);
                let last = until / panel.frame;
                if idle && last > self.vbl_index + 1 {
                    self.vbl_count += last - 1 - self.vbl_index;
                    self.vbl_index = last - 1;
                    self.vbl_time = self.vbl_index * panel.frame;
                }
                let index = self.vbl_index + 1;
                let time = index * panel.frame;
                self.blank(index, time, pid, time);
            } else if timer == Some(at) {
                self.swap_timer_fire(pid, at);
            } else {
                self.wait_deadline(at, pid, at);
            }
        }
        // While the controller is off no blank comes: the next is the first
        // after it is on again.
        if !self.power.controller {
            self.vbl_index = self.vbl_index.max(now / panel.frame);
        }
    }

    // -----------------------------------------------------------------------
    // Swap waits.

    /// A pass of `swap_wait_gated`'s loop for `w` (0xfffffff00678b960):
    /// for modes 0 to 2, done when the swap is gone from the display (0),
    /// is no longer pending or queued (1), or nothing is pending or queued
    /// (2), the swap found given the wait's deadline (0xfffffff00678dc30);
    /// then a wait that does not block is kIOReturnBusy, a cancelled swap
    /// kIOReturnAborted, and otherwise it sleeps on the queue for five
    /// seconds. `Some` is its result.
    fn wait_pass(&mut self, w: &mut Waiter, no_block: bool, now: u64) -> Option<i32> {
        let mut found_cancelled = None;
        if w.mode <= 2 {
            let displayed = w.id == self.display_swap_id;
            let (pending, queued) = (self.pending.is_some(), !self.queue.is_empty());
            let found = match self.pending.as_mut().filter(|r| r.id == w.id) {
                Some(r) => Some(r),
                None => self.queue.iter_mut().find(|r| r.id == w.id),
            };
            match w.mode {
                0 if !displayed && found.is_none() => return Some(ret::SUCCESS),
                1 if found.is_none() => return Some(ret::SUCCESS),
                2 if !pending && !queued => return Some(ret::SUCCESS),
                _ => {}
            }
            if let Some(r) = found {
                if w.timeout != 0 && (r.deadline == 0 || w.swap_deadline < r.deadline) {
                    r.deadline = w.swap_deadline;
                    if self.swap_timer == 0 || w.swap_deadline < self.swap_timer {
                        self.swap_timer = w.swap_deadline;
                    }
                }
                found_cancelled = Some(r.cancelled);
            }
        }
        if no_block {
            return Some(kr::BUSY);
        }
        if found_cancelled == Some(true) {
            return Some(kr::ABORTED);
        }
        // `+0x178a` is never set here: the sleep has its deadline.
        w.sleeps += 1;
        w.on = Sleep::Queue { deadline: now + ms_to_abs(5000) };
        None
    }

    /// A swap wait asleep on the queue woken (`timed_out`: its deadline
    /// passed instead): woken more than twice in mode 2, or timed out, it
    /// clears the swaps and is kIOReturnAborted; then its loop goes on
    /// while its client is started.
    fn wait_resume(&mut self, mut w: Waiter, timed_out: bool, now: u64) {
        let pid = w.pid;
        if timed_out || (w.sleeps > 2 && w.mode == 2) {
            self.clear_swaps(pid, now);
            return self.wait_answer(w, kr::ABORTED, now);
        }
        if w.client != KERNEL && !self.started.contains(&w.client) {
            return self.wait_answer(w, kr::ABORTED, now);
        }
        match self.wait_pass(&mut w, false, now) {
            Some(r) => self.wait_answer(w, r, now),
            None => self.waiters.push(w),
        }
    }

    /// The swap wait whose deadline is `at` gave up.
    fn wait_deadline(&mut self, at: u64, _pid: i32, now: u64) {
        let Some(i) = self.waiters.iter().position(|w| w.on == Sleep::Queue { deadline: at }) else { return };
        let w = self.waiters.remove(i);
        self.wait_resume(w, true, now);
    }

    /// A swap wait asleep on the power scheduler woken: asleep again while
    /// a request is with it, else on into the wait proper.
    fn wait_power_done(&mut self, mut w: Waiter, now: u64) {
        if self.power.transition {
            self.waiters.push(w);
            return;
        }
        let no_block = w.no_block;
        match self.wait_body(&mut w, no_block, now) {
            Some(r) => self.wait_answer(w, r, now),
            None => self.waiters.push(w),
        }
    }

    /// `swap_wait_gated` past the power scheduler: the swap's deadline from
    /// the timeout; modes 3 and 4, which ask whether the soft state is on
    /// (kIOReturnBadArgument where it is not as asked); the wait proper when
    /// the controller is on (the display's power change support, `+0x8c`,
    /// being on), else kIOReturnOffline.
    fn wait_body(&mut self, w: &mut Waiter, no_block: bool, now: u64) -> Option<i32> {
        if w.timeout != 0 {
            w.swap_deadline = now + ms_to_abs(u64::from(w.timeout));
        }
        match w.mode {
            3 => return Some(if self.power.soft == 0 { ret::BAD_ARGUMENT } else { ret::SUCCESS }),
            4 => return Some(if self.power.soft == 0 { ret::SUCCESS } else { ret::BAD_ARGUMENT }),
            _ => {}
        }
        if !self.power.controller {
            return Some(kr::OFFLINE);
        }
        self.wait_pass(w, no_block, now)
    }

    /// The client's `swap_wait` after the framebuffer's (0xfffffff006777390):
    /// kIOReturnTimeout when the swap it waited for was removed meanwhile
    /// (`+0x100`, the swap id kept), else the swap id cleared.
    fn wait_result(&mut self, client: u32, r: i32) -> i32 {
        match self.client_wait.get_mut(&client) {
            Some(w) if w.1 => kr::TIMEOUT,
            Some(w) => {
                w.0 = 0;
                r
            }
            None => r,
        }
    }

    /// A swap wait that slept answered.
    fn wait_answer(&mut self, w: Waiter, r: i32, now: u64) {
        let r = self.wait_result(w.client, r);
        match w.then {
            Then::Answer(link) => self.effects.push(Effect::Answer { link, token: w.token, ret: r }),
            Then::LastClient(closer) => self.last_client_blanked(r, closer, w.pid, now),
        }
    }

    // -----------------------------------------------------------------------
    // Power.

    /// Selector 12's gated action past the power scheduler's wait
    /// (0xfffffff006bf792c): the state requested and given to the
    /// scheduler, success. `None` while a request is with the scheduler.
    fn request_power(&mut self, state: u32, pid: i32, now: u64) -> Option<i32> {
        if self.power.transition {
            return None;
        }
        self.power.requested = state;
        self.power.transition = true;
        self.power.jobs += 1;
        self.run_scheduler(pid, now);
        Some(ret::SUCCESS)
    }

    /// The power scheduler's actions in turn (0xfffffff006c07b70, gated
    /// 0xfffffff006c07bd0): the request taken (`+0x16e0` cleared) and its
    /// state set (0xfffffff00678b858), one at a time.
    fn run_scheduler(&mut self, pid: i32, now: u64) {
        while !self.power.scheduling && self.power.jobs > 0 {
            self.power.jobs -= 1;
            if std::mem::replace(&mut self.power.transition, false) {
                self.power.scheduling = true;
                let state = self.power.requested;
                self.change(Change::Soft { state, sched: true }, pid, now);
            }
        }
    }

    /// A power state change asked for (slot 354, 0xfffffff006bf79a8): it
    /// takes the ticket after those before it and waits for the pending
    /// swap to complete. The `iomfb_handle_power=0` boot-arg (`+0x212d`)
    /// and the pipe's slot 0xb08, which would skip it, are neither here.
    fn change(&mut self, c: Change, pid: i32, now: u64) {
        self.power.changes.push_back((c, pid));
        self.power_turn(now);
    }

    /// The changes whose turn it is made while no swap is pending.
    fn power_turn(&mut self, now: u64) {
        while self.pending.is_none() {
            let Some((c, pid)) = self.power.changes.pop_front() else { break };
            match c {
                // The soft state set (0xfffffff00678b858's request leaves the
                // hard state and evaluates only on a change).
                Change::Soft { state, sched } => {
                    if state != self.power.soft {
                        self.power.soft = state;
                        self.evaluate(pid, now);
                    }
                    if sched {
                        self.power.scheduling = false;
                        self.wake_power(pid, now);
                        self.run_scheduler(pid, now);
                    }
                }
                Change::Evaluate => self.evaluate(pid, now),
                Change::LastClient(closer) => {
                    self.last_client_powered(closer, pid, now);
                }
            }
        }
    }

    /// The power states evaluated (0xfffffff006bf7bc4) for this panel:
    /// built in, the pipe without always-on display (slots 0x8d0, 0x250 and
    /// 0x850 false) and its runtime property `AOTEnable` (0xad) as started.
    /// The controller is on while the display is hard on and a swap is
    /// pending or the soft state is on; the panel while the soft state and
    /// the controller are. The panel going dark turns the backlight off
    /// (0xfffffff006bf8434); the controller going off stops the pipe and its
    /// vertical blanks, flushes the swap queue and lets the device go
    /// (`setActive`, `set_device_enabled_gated`); coming on, the reverse; and
    /// a change of either is told to the power notification records
    /// (slot 215, 0xfffffff006796d0c).
    fn evaluate(&mut self, pid: i32, now: u64) {
        let aot = super::rtprop::value(0xad);
        if aot != Some(0) {
            self.effects.push(Effect::Unimplemented(format!("the display's power states with the pipe's AOTEnable runtime property {aot:?} (the always-on display path of 0xfffffff006bf7bc4)")));
        }
        let soft = self.power.soft != 0;
        let controller = self.power.hard != 0 && (self.pending.is_some() || soft);
        let panel = soft && controller;
        let (was_controller, was_panel) = (self.power.controller, self.power.panel);
        self.power.panel = panel;
        if was_panel && !panel {
            self.effects.push(Effect::Panel(false));
        }
        if was_controller != controller {
            self.power.controller = controller;
            // Off (0xfffffff006bf6e20): with the pipe's timing generator
            // running (the pipe's slot 0x440, 0xfffffff006bc161c, its
            // enable) and no always-on display state (`+0x1e4c`), the
            // kernel's request of kind 15 takes the next swap id, enables
            // and completes every layer with no surface, and is made
            // pending with status 3 and programmed for the pipe's last
            // frame; then the timing generator is disabled. The flush below
            // keeps it (a queued request flushed after it takes its place,
            // and it is dropped), and the swap-complete interrupt of that
            // last frame (AppleCLCD's 0xfffffff006bfbf8c, which the work
            // loop runs once the power change lets it go) shows it, clearing
            // the glass. On: the panel's link is up and the pipe's slot
            // 0x250 answers false, so 0xfffffff006bf7bc4 enables it.
            if !controller && self.power.timing {
                self.next_id = self.next_id.wrapping_add(1);
                if self.next_id == 0 {
                    self.next_id = 1;
                }
                self.pending = Some(Request { id: self.next_id, client: KERNEL, pid, submitted: true, enabled: u32::MAX, completed: u32::MAX, kind: 0xf, status: 3, ..Default::default() });
            }
            self.power.timing = controller;
            if !controller {
                // The vertical blanks up to now counted; none comes while off.
                if let Some(p) = self.panel {
                    self.vbl_index = self.vbl_index.max(now / p.frame);
                }
            }
            self.flush(pid, now);
            if !controller && self.pending.as_ref().is_some_and(|r| r.kind == 0xf && r.client == KERNEL && r.status == 3) {
                self.vbl_count += 1;
                self.complete_pending(Shown::Blank(self.vbl_count, now), pid, now);
            }
        }
        if !was_panel && panel {
            self.effects.push(Effect::Panel(true));
        }
        if was_controller != controller || was_panel != panel {
            self.power_notify(now);
        }
    }

    /// `powerstate_notify` (slot 215): each listed power record (type 1)
    /// sent the time and the state, 2 for the controller on and 1 for the
    /// panel.
    fn power_notify(&mut self, now: u64) {
        let state = (if self.power.controller { 2 } else { 0 }) | u64::from(self.power.panel);
        for r in self.records[1].clone() {
            if let Some(port) = r.port {
                self.effects.push(Effect::Notify { port, reference: r.reference, args: [now, state] });
            }
        }
    }
}

/// Where the console mode is changed from, for what its own swap's wait
/// would hold up (0xfffffff0067950f8's swap wait sleeps in the caller).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Gate {
    /// The first swap client's registration (slot 169).
    FirstClient,
    /// A shown swap's completion (0xfffffff00678a96c, and
    /// 0xfffffff00679437c within it).
    Completion,
    /// The last swap client's going (0xfffffff00678b544).
    LastClient,
}

/// IOSurface's pixel formats the console takes (0xfffffff00678c44c), with
/// the depth it gives `PE_Video`.
fn console_depth(format: u32) -> Option<u64> {
    match &format.to_be_bytes() {
        b"BGRA" => Some(32),
        b"L565" => Some(16),
        b"b3a8" => Some(30),
        _ => None,
    }
}

impl Display {
    /// The request queued (gated 0xfffffff0067916f8): one cancelled, or no
    /// longer begun, is kIOReturnAborted. Then (slot 321, the pipe's 0x8a8,
    /// which takes nothing here) each layer it does not enable takes the
    /// surface it would show from the queue's head, the pending swap or the
    /// glass (0xfffffff006799c68); the passthrough check (0xfffffff00678f070,
    /// passthrough layers being refused before) and KeepOnScreen's
    /// (0xfffffff006799eb0: a swap of kind 0 that keeps its layers on screen
    /// shows at most one, and a swap of another kind enables no layer while
    /// a shown swap keeps the console mode on) and slot 342 (true): else
    /// kIOReturnBadArgument. Each layer with no surface is completed, and
    /// one with a surface asks IOSurface for a fence that waits for the
    /// surface's writes (0xfffffff006791984, `createWriteFence`
    /// 0xfffffff005ba20e8), which is granted at once: no fence holds a
    /// surface here (the GPU's writes are kept coherent at locks instead),
    /// so the layer is completed. The request goes from the begun list to
    /// the queue (0xfffffff0067997a4): a request of kind 0, 2, 9, 12 or 13
    /// at the tail unless it asks for the head (`+0x555`), any other at the
    /// head. `Err` gives the request back with the result.
    fn enqueue(&mut self, mut req: Request, _pid: i32, _now: u64) -> Result<(), (i32, Request)> {
        let Some(i) = self.begun.iter().position(|r| r.id == req.id) else { return Err((kr::ABORTED, req)) };
        if req.cancelled || self.begun[i].cancelled {
            return Err((kr::ABORTED, req));
        }
        // What the begun request took while swap_submit had it (its swap
        // signals) is the request's.
        req.completed |= self.begun[i].completed;
        let shows: [bool; 4] = std::array::from_fn(|n| {
            if req.enabled & (1 << n) != 0 {
                return req.layers[n].surface.is_some();
            }
            match self.queue.front().or(self.pending.as_ref()) {
                Some(r) => r.shows[n],
                None => self.glass[n].is_some(),
            }
        });
        req.shows = shows;
        let keep_ok = if req.kind == 0 { !req.keep_on_screen || shows.iter().filter(|&&s| s).count() <= 1 } else { !(self.console.kept && req.enabled & 0xf != 0) };
        if !keep_ok {
            return Err((ret::BAD_ARGUMENT, req));
        }
        for n in 0..4 {
            if req.enabled & (1 << n) != 0 || req.layers[n].surface.is_some() {
                req.completed |= 1 << n;
            }
        }
        self.begun.remove(i);
        req.submitted = true;
        if matches!(req.kind, 0 | 2 | 9 | 12 | 13) && !req.ahead {
            self.queue.push_back(req);
        } else {
            self.queue.push_front(req);
        }
        Ok(())
    }

    /// The console mode on or off (0xfffffff00678c44c, gated): only for a
    /// built-in panel, and neither while `IOMFBSetConsoleMode` holds it nor
    /// with `IOMFBSkipSpinner`. On: the surface on the glass's layer 1, or
    /// else layer 0 (`+0x1748`, which would first make a temporary surface
    /// through 0xfffffff006794ef8, is never set: the pipe's
    /// UPBlock_GenPipe_v1 slot 0xf8, 0xfffffff006baa620, gives no value),
    /// mapped for the console once per layer (`+0x1438 + 8 * n`), is handed
    /// to the video console in graphics mode when it is BGRA, L565 or b3a8
    /// (another is "Unsupported format for spinner"); with none on the glass
    /// nothing more is done. Then the screen acquired (on) or released
    /// (off), `SystemConsoleMode` set, and, going off with a surface on
    /// layer 1, the kernel's swap that clears layer 1
    /// (0xfffffff0067950f8), which its caller waits for.
    fn console_mode(&mut self, on: bool, gate: Gate, pid: i32, now: u64) {
        let builtin = builtin().unwrap_or(true);
        if !builtin || self.console.forced || self.console.skip_spinner {
            return;
        }
        self.console.on = on;
        if on {
            let Some((layer, l)) = [1usize, 0].into_iter().find_map(|n| self.glass[n].map(|l| (n, l))) else { return };
            let surface = l.surface.expect("a layer on the glass has its surface");
            self.console.mapped[layer] = true;
            match super::super::iosurface::geometry(surface) {
                Some(g) => {
                    if let Some(depth) = console_depth(g.pixel_format) {
                        let p0 = g.plane(0).expect("a surface's first plane");
                        let v = super::super::vconsole::Video { surface, offset: p0.offset & 0xffff_ffff, row_bytes: p0.bytes_per_row & 0xffff_ffff, width: l.src[2] as i64 as u64, height: l.src[3] as i64 as u64, depth, length: g.alloc_size };
                        if let Err(what) = super::super::vconsole::initialize_console(Some(v), super::super::vconsole::op::GRAPHICS_MODE, now) {
                            self.effects.push(Effect::Unimplemented(what));
                        }
                    }
                }
                None => self.effects.push(Effect::Unimplemented(format!("the console mode on layer {layer}'s surface {surface:#x}, which is gone"))),
            }
        }
        let op = if on { super::super::vconsole::op::ACQUIRE_SCREEN } else { super::super::vconsole::op::RELEASE_SCREEN };
        if let Err(what) = super::super::vconsole::initialize_console(None, op, now) {
            self.effects.push(Effect::Unimplemented(what));
        }
        self.console.property = Some(on);
        if !on && self.glass[1].is_some() {
            // A kind 0 swap enabling and completing layer 1 with no surface,
            // at mach_continuous_time, waited for with no timeout.
            let mut r = Request { client: KERNEL, pid, enabled: 2, completed: 2, presentation: now, ..Default::default() };
            match self.kernel_swap(&mut r, pid, now) {
                Ok(()) => self.effects.push(Effect::Unimplemented(format!("waiting for the kernel's swap {} that clears layer 1 as the console mode goes off ({gate:?}, 0xfffffff0067950f8's swap_wait_gated)", r.id))),
                Err(e) => self.effects.push(Effect::Unimplemented(format!("the kernel's swap that clears layer 1 as the console mode goes off, refused ({e:#x})"))),
            }
        }
    }

    /// A swap the kernel begins and submits itself (slots 177 and 178 with
    /// no client): a new swap id at the begun list's tail, then the record
    /// `r` (no surfaces, so verify_swap's checks, all of shown layers,
    /// pass) queued and the kick. `r` takes its id.
    fn kernel_swap(&mut self, r: &mut Request, pid: i32, now: u64) -> Result<(), i32> {
        self.next_id = self.next_id.wrapping_add(1);
        if self.next_id == 0 {
            self.next_id = 1;
        }
        r.id = self.next_id;
        r.client = KERNEL;
        r.pid = pid;
        self.begun.push(Request { id: r.id, client: KERNEL, pid, ..Default::default() });
        r.submitted = true;
        if let Err((e, back)) = self.enqueue(r.clone(), pid, now) {
            if let Some(i) = self.begun.iter().position(|b| b.id == back.id) {
                self.begun.remove(i);
            }
            return Err(e);
        }
        self.kick(pid, now);
        Ok(())
    }

    /// The last swap client's going (0xfffffff00678b544, gated): nothing
    /// while the framebuffer shuts down (`+0x189c`, slot 79) or the display
    /// is hard off. The main display (slot 184: built in, not standalone),
    /// or one a shown swap left in console mode, has its soft state set on
    /// (0xfffffff00678b858 with state 1, made once the pending swap
    /// completes) before the rest ([`Display::last_client_powered`]). The
    /// result is whether the work goes on past now.
    fn last_client(&mut self, closer: Option<(Arc<TaskLink>, u64)>, pid: i32, now: u64) -> bool {
        if self.power.hard == 0 {
            return false;
        }
        let main = builtin().unwrap_or(true) && !standalone();
        if main || self.console.kept {
            self.change(Change::Soft { state: 1, sched: false }, pid, now);
            self.change(Change::LastClient(closer), pid, now);
            return true;
        }
        self.last_client_powered(closer, pid, now)
    }

    /// 0xfffffff00678b544 past its power change: unless a shown swap left
    /// the console mode on or `IOMFBPreserveContents` keeps the glass, the
    /// glass blanked: with the panel built in (`+0x1788` clear), the
    /// controller and the timing generator on (slot 345), the kernel's swap
    /// of kind 7 (slot 339, 0xfffffff006bf94f0 to 0xfffffff00679de90: at
    /// the time now, every layer enabled and completed, no surface, from the
    /// record at `+0x638` that 0xfffffff006793694 cleared), waited for until
    /// it is no longer pending or queued for 34 ms at most
    /// ([`Display::last_client_blanked`]). The result is whether the work
    /// goes on past now.
    fn last_client_powered(&mut self, closer: Option<(Arc<TaskLink>, u64)>, pid: i32, now: u64) -> bool {
        if self.console.kept || self.console.preserve {
            self.last_client_done(closer);
            return false;
        }
        let external = !builtin().unwrap_or(true);
        if !external && self.power.controller && self.power.timing {
            let mut r = Request { kind: 7, enabled: u32::MAX, completed: u32::MAX, presentation: now, ..Default::default() };
            if self.kernel_swap(&mut r, pid, now).is_ok() {
                // swap_wait_gated(no client, the swap, mode 1, 34 ms).
                let mut w = Waiter { token: 0, then: Then::LastClient(closer), pid, client: KERNEL, id: r.id, mode: 1, no_block: false, timeout: 0x22, swap_deadline: 0, sleeps: 0, on: Sleep::Power };
                if self.power.transition {
                    self.waiters.push(w);
                } else {
                    match self.wait_body(&mut w, false, now) {
                        Some(r) => self.wait_answer(w, r, now),
                        None => self.waiters.push(w),
                    }
                }
                return true;
            }
        }
        self.last_client_blanked(0, closer, pid, now);
        false
    }

    /// 0xfffffff00678b544 after its wait for the kernel's swap of kind 7,
    /// which ended with `r` (0 when none was made): a failed wait ("something
    /// really bad happened") turns the main display's soft state off; else
    /// the canvas resized if a client set one (`+0x1896`, selector 53, which
    /// is refused here), the default surface cleared (`+0x1618`, never
    /// made), the kernel's swap of kind 6 asked for, which needs that
    /// surface (0xfffffff006788db4: kIOReturnUnsupported), and the console
    /// mode turned on.
    fn last_client_blanked(&mut self, r: i32, closer: Option<(Arc<TaskLink>, u64)>, pid: i32, now: u64) {
        if r != 0 {
            if builtin().unwrap_or(true) && !standalone() {
                self.change(Change::Soft { state: 0, sched: false }, pid, now);
            }
        } else {
            self.console_mode(true, Gate::LastClient, pid, now);
        }
        self.last_client_done(closer);
    }

    /// The io_service_close that waited for the last swap client's going
    /// answered (kIOReturnSuccess, as it always is).
    fn last_client_done(&mut self, closer: Option<(Arc<TaskLink>, u64)>) {
        if let Some((link, token)) = closer {
            self.effects.push(Effect::Answer { link, token, ret: ret::SUCCESS });
        }
    }
}

/// Whether the display is standalone (AppleCLCD's `+0x178b`, from disp0's
/// `standalone` in the device tree, 0xfffffff006bf5a30).
fn standalone() -> bool {
    let t = super::super::iokit::tree();
    t.iter().find(|n| n.props.iter().any(|(k, v)| k == "compatible" && v.split(|&c| c == 0).any(|c| c == b"disp0,t8011"))).is_some_and(|d| d.props.iter().any(|(k, v)| k == "standalone" && v.iter().any(|&b| b != 0)))
}

// ---------------------------------------------------------------------------
// Vertical blanks.

/// The display's timed events up to now processed, whoever calls: the
/// display runs whether or not the task that swapped is still there to
/// watch it.
pub fn catch_up(k: &mut Kernel) {
    let pid = k.pid;
    let now = super::super::mach::absolute_time();
    with_display(k, |d| d.advance(pid, now));
    if let Some(what) = super::super::vconsole::due(now) {
        k.darwin_unimplemented(what);
    }
}

/// `SystemConsoleMode` on the service, once the console mode was set
/// (0xfffffff00678c44c's `setProperty`, an OSBoolean).
pub fn console_property() -> Option<bool> {
    display(|d| d.console.property)
}

/// The glass after swap `swap`, its `layers`, to the sink.
fn present(k: &mut Kernel, swap: u32, vbl: u64, time: u64, layers: &[(u32, LayerReq)]) {
    let Ok(panel) = panel() else { return };
    let mut frame = sink::Frame { swap_id: swap, vbl, time, panel: (panel.width, panel.height), layers: Vec::new() };
    for &(n, l) in layers {
        let Some(id) = l.surface else { continue };
        let Some(g) = super::super::iosurface::geometry(id) else { continue };
        let count = if g.plane_count == 0 { 1 } else { g.plane_count };
        let planes = (0..count)
            .filter_map(|p| g.plane(p))
            .map(|p| sink::Plane { offset: p.offset, width: p.width, height: p.height, bytes_per_row: p.bytes_per_row, bytes_per_element: u32::from(p.bytes_per_element), element_width: u32::from(p.element_width), element_height: u32::from(p.element_height), size: p.size })
            .collect();
        let size = g.alloc_size as usize;
        let bytes = super::super::iosurface::with_bytes(k, id, |b| b[..size.min(b.len())].to_vec()).unwrap_or_default();
        let rect = |r: [i32; 4]| sink::Rect { x: r[0], y: r[1], w: r[2], h: r[3] };
        frame.layers.push(sink::Layer { index: n, surface: id, pixel_format: g.pixel_format, width: g.width, height: g.height, planes, bytes, src: rect(l.src), dst: rect(l.dst), transform: l.transform });
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

/// The surface on the glass in layer `layer` (`+0x1358 + 8 * layer`), if
/// any.
pub fn glass_surface(layer: u32) -> Option<u32> {
    display(|d| d.glass.get(layer as usize).copied().flatten().and_then(|l| l.surface))
}

/// When task `pid` wants the display's thread call: the next vertical
/// blank while it has swaps on their way to the glass, swap waits, or a
/// power change waiting for the pending swap; the swap timer while one of
/// its queued swaps has a deadline; its swap waits' deadlines.
fn next_event(pid: i32) -> Option<u64> {
    display(|d| {
        let panel = d.panel?;
        let now = super::super::mach::absolute_time();
        let swaps = d.pending.as_ref().is_some_and(|r| r.pid == pid) || d.queue.iter().any(|r| r.pid == pid);
        let waits = d.waiters.iter().any(|w| w.pid == pid && matches!(w.on, Sleep::Queue { .. }));
        let changes = d.power.changes.iter().any(|(_, p)| *p == pid);
        let blank = (d.power.controller && (swaps || waits || changes)).then(|| (now / panel.frame + 1) * panel.frame);
        let timer = (d.swap_timer != 0 && d.queue.iter().any(|r| r.pid == pid && r.deadline != 0)).then_some(d.swap_timer);
        let deadline = d.waiters.iter().filter(|w| w.pid == pid).filter_map(|w| match w.on {
            Sleep::Queue { deadline } => Some(deadline),
            Sleep::Power => None,
        }).min();
        [blank, timer, deadline].into_iter().flatten().min()
    })
}

// ---------------------------------------------------------------------------
// Swap waits.

/// Selector 6: the client's `swap_wait` (0xfffffff006777390: its `+0xf8`
/// the swap, `+0x100` cleared) and the framebuffer's (slot 176,
/// 0xfffffff00678d998). With bit 31 of the options, modes 3 and 4 answer
/// at once from the soft state and the power scheduler (kIOReturnBusy where
/// not as asked). Otherwise `swap_wait_gated` (0xfffffff00678b960) waits
/// for no request to be with the power scheduler, then goes on
/// ([`Display::wait_body`]). `Ok` is its result now; `Err(token)` that it
/// sleeps, answered later by that token.
pub fn wait(k: &mut Kernel, client: u32, id: u32, options: u32, timeout: u32) -> Result<i32, u64> {
    let (pid, link) = (k.pid, k.dtask.ipc_raw.link.clone());
    let r = with_display(k, |d| {
        let now = super::super::mach::absolute_time();
        d.advance(pid, now);
        let no_block = options & 0x8000_0000 != 0;
        let mode = options & 0x7fff_ffff;
        d.client_wait.insert(client, (id, false));
        if no_block && (mode == 3 || mode == 4) {
            let on = d.power.soft != 0;
            let asked = if mode == 3 { on } else { !on };
            let r = if !d.power.transition && asked { ret::SUCCESS } else { kr::BUSY };
            return Ok(d.wait_result(client, r));
        }
        let Some(link) = link else { unreachable!("a task serving a call has its link") };
        let mut w = Waiter { token: 0, then: Then::Answer(link), pid, client, id, mode, no_block, timeout, swap_deadline: 0, sleeps: 0, on: Sleep::Power };
        let r = if d.power.transition { None } else { d.wait_body(&mut w, no_block, now) };
        match r {
            Some(r) => Ok(d.wait_result(client, r)),
            None => {
                w.token = super::super::mig::later_token();
                let token = w.token;
                d.waiters.push(w);
                Err(token)
            }
        }
    });
    // A wait asleep on the queue has its deadline and the blanks to watch.
    k.darwin_iomfb_arm();
    r
}

/// A signal for the thread whose call answers later by `token`
/// (`thread_abort_safely`, which ends an abort-safe sleep interrupted): a
/// swap wait asleep on the power scheduler (0xfffffff00678db9c) is
/// kIOReturnAborted; one asleep on the swap queue (`commandSleep`, not
/// THREAD_AWAKENED) takes the five-second path, clearing the swaps (slot
/// 346 and `swap_cancel_all` with the time now) before kIOReturnAborted; a
/// power request asleep on the scheduler is kIOReturnAborted. Any other
/// token is not the display's.
pub fn interrupt(k: &mut Kernel, token: u64) {
    with_display(k, |d| {
        let now = super::super::mach::absolute_time();
        if let Some(i) = d.waiters.iter().position(|w| w.token == token && matches!(w.then, Then::Answer(_))) {
            let w = d.waiters.remove(i);
            match w.on {
                Sleep::Power => d.wait_answer(w, kr::ABORTED, now),
                Sleep::Queue { .. } => d.wait_resume(w, true, now),
            }
        } else if let Some(i) = d.power_callers.iter().position(|c| c.token == token) {
            let c = d.power_callers.remove(i);
            d.effects.push(Effect::Answer { link: c.link, token, ret: kr::ABORTED });
        }
    });
    k.darwin_iomfb_arm();
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
// Power.

/// Selector 12's power change for the framebuffer (AppleCLCD slot 229,
/// 0xfffffff006bf7900, the command gate's action 0xfffffff006bf792c): it
/// waits while a request is with the power scheduler
/// (0xfffffff00678db9c), then gives the scheduler the state and succeeds;
/// the scheduler sets it once the pending swap completes. `Ok` is its
/// result now; `Err(token)` that it sleeps, answered later by that token.
pub fn request_power_change(k: &mut Kernel, state: u32) -> Result<i32, u64> {
    let (pid, link) = (k.pid, k.dtask.ipc_raw.link.clone());
    let r = with_display(k, |d| {
        let now = super::super::mach::absolute_time();
        d.advance(pid, now);
        match d.request_power(state, pid, now) {
            Some(r) => Ok(r),
            None => {
                let Some(link) = link else { unreachable!("a task serving a call has its link") };
                let token = super::super::mig::later_token();
                d.power_callers.push(PowerCaller { token, link, state });
                Err(token)
            }
        }
    });
    k.darwin_iomfb_arm();
    r
}

// ---------------------------------------------------------------------------
// Notifications.

/// Selector 72 with a callout, the framebuffer's gated enable
/// (0xfffffff006795ec0): a record already listed, or a type past the
/// slots, is kIOReturnError; else its async reference is set
/// (`setAsyncReference64` with the slot's port, the callout and its
/// reference, in a 64-bit task; frame information through a queue sets
/// none) and it is listed. Vertical blank (5) calls AppleCLCD's slots 316
/// (empty) and 290 (the kick); frame information (3) and CRC (4) turn the
/// hardware's on, which is not modelled (`Err`).
pub fn enable_notifications(k: &mut Kernel, client: u32, ty: usize, listed: bool, port: Option<ObjId>, callout: u64, refcon: u64) -> Result<i32, String> {
    if listed || ty >= super::NOTIFY_TYPES {
        return Ok(ret::ERROR);
    }
    match ty {
        3 => return Err("IOMobileFramebuffer frame information notifications (the pipe's frame statistics)".to_string()),
        4 => return Err("IOMobileFramebuffer CRC notifications (the pipe's CRC hardware)".to_string()),
        _ => {}
    }
    // kIOUCAsync64Flag in the reserved word, beside the port.
    let mut reference = [0u64; ASYNC_REF64_COUNT];
    reference[0] = 1;
    reference[1] = callout;
    reference[2] = refcon;
    let pid = k.pid;
    with_display(k, |d| {
        d.records[ty].push(Record { client, port, reference });
        if ty == 5 {
            d.kick(pid, super::super::mach::absolute_time());
        }
    });
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
    /// The framebuffer's thread call armed for the display's next event
    /// this task wants ([`next_event`]), or again sooner when that is
    /// earlier than the one armed.
    pub(crate) fn darwin_iomfb_arm(&mut self) {
        let Some(at) = next_event(self.pid) else { return };
        let when = super::super::mach::abs_to_instant(at);
        if let Some(key) = self.dtask.iomfb_call {
            if key.0 <= when {
                return;
            }
            self.dtask.timers.cancel(key);
        }
        let key = self.dtask.timers.arm(when, super::super::timer::Action::Iomfb);
        self.dtask.iomfb_call = Some(key);
    }

    /// The framebuffer's thread call: the display's events up to now, and
    /// the call armed again while needed.
    pub(crate) fn darwin_iomfb_blank(&mut self, m: &mut GuestMem<'_>) {
        self.dtask.iomfb_call = None;
        catch_up(self);
        self.darwin_ipc_settle(m);
        self.darwin_iomfb_arm();
    }
}
