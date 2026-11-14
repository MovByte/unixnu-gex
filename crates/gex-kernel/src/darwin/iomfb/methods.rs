//! `IOMobileFramebufferUserClient`'s methods: its `externalMethod`
//! (0xfffffff006778d40) over the 90 entries of its dispatch table
//! (0xfffffff006f354c0), each a static method that calls the client's
//! member and the framebuffer's virtual.

use super::super::iokit::{ret, Dispatch, MethodArgs, VARIABLE};
use super::swap;
use super::Client;
use crate::syscalls::Kernel;

const V: u32 = VARIABLE;

/// The dispatch table's counts (scalar input count, structure input size,
/// scalar output count, structure output size) and whether its entry has a
/// method (59 to 65, 70 and 71 have none).
const METHODS: [(Dispatch, bool); 90] = {
    const fn d(scalar_in: u32, struct_in: u32, scalar_out: u32, struct_out: u32) -> (Dispatch, bool) {
        (Dispatch { scalar_in, struct_in, scalar_out, struct_out }, true)
    }
    const NONE: (Dispatch, bool) = (Dispatch { scalar_in: 0, struct_in: 0, scalar_out: 0, struct_out: 0 }, false);
    [
        d(3, 0, 0, 0),
        d(0, 0, 0, 0),
        d(0, 0, 0, 0),
        d(2, 0, 1, 0),
        d(0, 0, 1, 0),
        d(0, 1288, 0, 0),
        d(3, 0, 0, 0),
        d(0, 0, 1, 0),
        d(0, 0, 2, 0),
        d(2, 0, 0, 0),
        d(1, 0, 0, 0),
        d(2, 0, 0, 0),
        d(1, 0, 0, 0),
        d(1, 0, 0, 0),
        d(2, 0, 1, 0),
        d(2, 0, 1, 0),
        d(1, 0, 0, 0),
        d(0, 3084, 0, 0),
        d(0, 0, 1, 0),
        d(1, 0, 0, 0),
        d(2, 0, 0, 0),
        d(2, 0, 0, 0),
        d(1, 0, 0, 0),
        d(2, 0, 0, 0),
        d(0, 0, 0, 16),
        d(0, 0, 1, 0),
        d(0, 0, 0, 0),
        d(0, 0, 0, 3084),
        d(0, 0, 1, 0),
        d(0, 0, 0, 8),
        d(1, 0, 0, 0),
        d(1, 0, 0, 0),
        d(2, 0, 0, 0),
        d(1, 0, 0, 0),
        d(1, 0, 0, 0),
        d(1, 0, 0, 0),
        d(0, 0, 0, 0),
        d(0, 0, 0, 0),
        d(0, 0, 0, 0),
        d(0, 0, 0, 0),
        d(0, 0, 0, 0),
        d(1, 0, 0, 0),
        d(0, 0, 0, 20),
        d(0, 4, 0, 0),
        d(0, 16, 0, 0),
        d(0, 0, 0, 0),
        d(0, 0, 0, 0),
        d(4, 0, 0, 0),
        d(2, 0, 1, 0),
        d(1, 0, 1, 0),
        d(2, 0, 0, 0),
        d(1, 0, 0, 0),
        d(1, 0, 0, 0),
        d(2, 0, 0, 0),
        d(1, 0, 0, 72),
        d(1, 72, 0, 0),
        d(0, 156, 0, 0),
        d(0, 0, 1, 0),
        d(2, 0, 0, 0),
        NONE,
        NONE,
        NONE,
        NONE,
        NONE,
        NONE,
        NONE,
        d(2, 0, 0, 0),
        d(0, 0, 1, 0),
        d(1, 256, 0, 0),
        d(0, 136, 0, 0),
        NONE,
        NONE,
        d(4, 0, 0, 0),
        d(2, 0, 0, 0),
        d(1, 0, 2, 64),
        d(0, 32776, 0, 0),
        d(0, 0, 0, 0),
        d(0, 0, 1, 0),
        d(0, 0, 0, 0),
        d(0, 0, 0, 0),
        d(0, 0, 1, 0),
        d(2, 0, 0, 0),
        d(0, 0, 1, 0),
        d(1, 0, 1, 0),
        d(0, 4, 0, 0),
        d(0, 0, 0, 0),
        d(0, V, 1, 0),
        d(1, 0, 0, 0),
        d(1, 0, 0, 0),
        d(1, 0, 0, 0),
    ]
};

/// The entries whose method is the reserved one (0xfffffff00677af74:
/// "IOMFB: WARNING: reserved user client function called",
/// kIOReturnUnsupported).
const RESERVED: [u32; 14] = [1, 2, 9, 21, 32, 36, 37, 38, 39, 40, 45, 46, 58, 76];

/// IOMobileFramebuffer.framework's names for the selectors (its `kern_*`
/// functions that call them), for reports.
fn selector_name(s: u32) -> &'static str {
    match s {
        0 => "the legacy layer set",
        3 => "GetLayerDefaultSurface",
        4 => "SwapBegin",
        5 => "SwapEnd",
        6 => "SwapWait",
        7 => "GetID",
        8 => "GetDisplaySize",
        10 => "SetTVOutMode",
        11 => "SetWSSInfo",
        12 => "RequestPowerChange",
        13 => "EnableStatistics",
        14 => "SetFlags",
        15 => "SetDebugFlags",
        16 => "SetTVOutSignalType",
        17 => "SetGammaTable",
        18 => "IsMainDisplay",
        19 => "SetWhiteOnBlackMode",
        20 => "SwapSignal",
        22 => "SetDisplayDevice",
        23 => "SetDigitalOutMode",
        24 => "GetHDCPDownstreamState",
        25 => "GetDigitalOutState",
        26 => "printDisplayRegs",
        27 => "GetGammaTable",
        28 => "GetDotPitch",
        29 => "GetDisplayArea",
        30 => "EnableDisableDithering",
        31 => "SetUnderrunColor",
        33 => "EnableDisableVideoPowerSavings",
        34 => "SetVideoDACGain",
        35 => "SetLine21Data",
        41 => "EnableMirroring",
        42 => "GetMirroringCapability",
        43 => "SetRenderingAngle",
        44 => "SetMirrorContentRegion",
        47 => "HDCPSendRequest",
        48 => "HDCPGetReply",
        49 => "SurfaceIsReplaceable",
        50 => "SetBrightnessCorrection",
        51 => "SetColorRemapMode",
        52 => "SwapCancel",
        53 => "SetCanvasSize",
        54 => "GetMatrix",
        55 => "SetMatrix",
        56 => "KernelTests",
        57 => "GetColorRemapMode",
        66 => "SPLCSetBrightness",
        67 => "SPLCGetBrightness",
        68 => "SetParameter",
        69 => "SwapSetColorMatrix",
        72 => "Enable/DisableNotifications",
        73 => "ChangeFrameInfo",
        74 => "SupportedFrameInfo",
        75 => "FactoryPortal",
        77 => "GetCurrentAbsoluteTime",
        78 => "SetBlock",
        79 => "GetBlock",
        80 => "GetLinkQuality",
        81 => "SwapCancelAll",
        82 => "GetProtectionOptions",
        83 => "CopyLayerDisplayedSurface",
        84 => "SetContrast",
        85 => "GetBufBlock",
        86 => "the gain map encoder's finish",
        87 => "AnnounceNextSwapTimestamp",
        88 => "the client's open by name",
        89 => "SetClamshellState",
        _ => "an IOMobileFramebuffer method",
    }
}

/// `IOMobileFramebufferUserClient::externalMethod` (0xfffffff006778d40):
/// a selector past the table is 0xe0000001; the framebuffer's check
/// (AppleCLCD slot 182, 0xfffffff006c078bc) passes; selectors 68, 78 and
/// 85 take any scalar count and any inband structure (the entry's input
/// counts replaced by the call's, so an out-of-line one fails the size
/// check), and 79 any scalar count and any structure output; then
/// `IOUserClient::externalMethod`'s checks of the entry, and an entry with
/// no method is kIOReturnNoCompletion. An asynchronous call goes the same
/// way. A method that sleeps (a swap wait, a power request) answers later
/// ([`MethodArgs::later`]).
pub fn external_method(k: &mut Kernel, id: u32, c: &mut Client, a: &mut MethodArgs) -> i32 {
    const K_IO_RETURN_NO_COMPLETION: i32 = 0xe00002ea_u32 as i32;
    let Some(&(mut d, has_method)) = METHODS.get(a.selector as usize) else { return 0xe000_0001_u32 as i32 };
    match a.selector {
        68 | 78 | 85 => {
            d.scalar_in = a.scalar_in.len() as u32;
            d.struct_in = a.struct_in.len() as u32;
        }
        79 => {
            d.scalar_in = a.scalar_in.len() as u32;
            d.struct_out = a.struct_out.len() as u32;
        }
        _ => {}
    }
    if let Err(e) = super::super::iokit::dispatch_check(&d, a) {
        return e;
    }
    if !has_method {
        return K_IO_RETURN_NO_COMPLETION;
    }
    if RESERVED.contains(&a.selector) {
        return ret::UNSUPPORTED;
    }
    swap::catch_up(k);
    let sc = |i: usize| a.scalar_in[i];
    let r = match a.selector {
        // s_get_layer_default_surface (0xfffffff00677925c): the
        // framebuffer's default surface for the size asked (slot 174, its
        // gated 0xfffffff00678cca8), which AppleCLCD never allocates
        // (`+0x1618` is only ever cleared): "No Default FB Surface found",
        // kIOReturnError, 0 out.
        3 => {
            a.scalar_out[0] = 0;
            ret::ERROR
        }
        // s_swap_begin (0xfffffff006779418): the client made a swap client
        // (type 2, slot 169) if it is not one, the framebuffer's
        // swap_begin, and the swap id out.
        4 => {
            if c.ty != 2 {
                c.ty = 2;
                swap::add_swap_client(k);
            }
            a.scalar_out[0] = u64::from(swap::begin(id, k.pid));
            ret::SUCCESS
        }
        // s_swap_end (0xfffffff006779470): a record that asks for the gain
        // map needs com.apple.private.gain-map-access
        // (kIOReturnNotPrivileged); then swap_submit (0xfffffff00677722c,
        // the size being the table's 1288).
        5 => {
            // The table's 1288 bytes are inband (an out-of-line structure
            // is larger than the inband maximum, and so fails the size).
            let record = a.struct_in.clone();
            if swap::wants_gain_map(&record) && !k.darwin_entitled("com.apple.private.gain-map-access") {
                return ret::NOT_PRIVILEGED;
            }
            swap::submit(k, &record)
        }
        // s_swap_signal (0xfffffff00677a298, member 0xfffffff006777350):
        // the framebuffer's swap_signal with the swap id and the layer.
        20 => swap::signal(k, sc(0) as u32, sc(1) as u32),
        // s_swap_wait (0xfffffff006779518): the client's swap_wait
        // (0xfffffff006777390) and the framebuffer's (slot 176), with the
        // swap id, the options and the timeout in milliseconds.
        6 => match swap::wait(k, id, sc(0) as u32, sc(1) as u32, sc(2) as u32) {
            Ok(r) => r,
            Err(token) => {
                a.later = Some(token);
                ret::SUCCESS
            }
        },
        // s_get_id (0xfffffff006779614): the framebuffer's id (slot 175,
        // 0xfffffff006792774: `+0x1890`, which nothing sets on AppleCLCD),
        // -1 for none.
        7 => {
            a.scalar_out[0] = 0xffff_ffff;
            ret::SUCCESS
        }
        // s_get_display_size (0xfffffff00677966c): slot 249
        // (0xfffffff006c078f4), the panel's width and height.
        8 => match swap::panel() {
            Ok(p) => {
                a.scalar_out[0] = u64::from(p.width);
                a.scalar_out[1] = u64::from(p.height);
                ret::SUCCESS
            }
            Err(what) => {
                k.darwin_unimplemented(format!("the panel's size: the device tree's {what}"));
                ret::UNSUPPORTED
            }
        },
        // s_request_power_change (0xfffffff006779f24, member
        // 0xfffffff0067779f8): the client made a swap client (type 2, slot
        // 169) if it is not one. Slots 255, 256, 258, 260 and 261, the
        // external display and clamshell checks, all answer 0 on AppleCLCD,
        // so the request goes to slot 229 (0xfffffff006bf7900) while the
        // display supports power changes (`+0x8c` bit 0, which AppleCLCD's
        // display start sets, 0xfffffff006bf5170), with the state as an
        // int.
        12 => {
            if c.ty != 2 {
                c.ty = 2;
                swap::add_swap_client(k);
            }
            match swap::request_power_change(k, sc(0) as u32) {
                Ok(r) => r,
                Err(token) => {
                    a.later = Some(token);
                    ret::SUCCESS
                }
            }
        }
        // s_set_debug_flags (0xfffffff00677a014): slot 180
        // (0xfffffff006798404) is kIOReturnError without the debugger
        // (PE_i_can_has_debugger, which a production device does not
        // allow).
        15 => {
            a.scalar_out[0] = 0;
            ret::ERROR
        }
        // s_is_main_display (0xfffffff00677a130): slot 184
        // (0xfffffff00678cb20), the display not external (`+0x1782`) nor
        // standalone (`+0x178b`).
        18 => {
            a.scalar_out[0] = 1;
            ret::SUCCESS
        }
        // s_get_color_remap_mode (0xfffffff00677a200, member
        // 0xfffffff006777f40): the framebuffer's slot +0x670 (AppleCLCD
        // 0xfffffff006bfb2e4). A built-in panel's mode is the pipe's
        // runtime property 0, BlendOutputCSCMethod, through the five
        // pairs at 0xfffffff0058a3850 (each value 0 to 4 its own mode;
        // another is kIOReturnError, "Failed to translate CSC mode
        // enum"); an external display's is kIOReturnUnsupported.
        57 => match (swap::builtin(), super::rtprop::value(0)) {
            (Ok(false), _) => ret::UNSUPPORTED,
            (Ok(true), Some(v)) if v <= 4 => {
                a.scalar_out[0] = u64::from(v);
                ret::SUCCESS
            }
            (Ok(true), Some(_)) => ret::ERROR,
            (Ok(true), None) => {
                k.darwin_unimplemented("IOMobileFramebufferUserClient selector 57 (GetColorRemapMode): the pipe's runtime property 0".to_string());
                ret::UNSUPPORTED
            }
            (Err(what), _) => {
                k.darwin_unimplemented(format!("IOMobileFramebufferUserClient selector 57 (GetColorRemapMode): {what}"));
                ret::UNSUPPORTED
            }
        },
        // s_set_parameter (0xfffffff006779d3c): the parameter (the first
        // scalar) and its values (the structure input's 64-bit words).
        // Parameter 16 needs com.apple.private.gain-map-access
        // (kIOReturnNotPrivileged); parameter 1 given two words takes the
        // first; parameter 11 counts the client's power assertions
        // (`+0xfc`: up with a nonzero first word, else down); then the
        // framebuffer's slot 228.
        68 => {
            let Some(&param) = a.scalar_in.first() else {
                k.darwin_unimplemented("IOMobileFramebufferUserClient selector 68 (SetParameter) with no scalar: the method reads its first scalar unchecked".to_string());
                return ret::UNSUPPORTED;
            };
            let param = param as u32;
            let words: Vec<u64> = a.struct_in.chunks_exact(8).map(|w| u64::from_le_bytes(w.try_into().unwrap())).collect();
            let mut count = (a.struct_in.len() / 8) as u32;
            if param == 0x10 && !k.darwin_entitled("com.apple.private.gain-map-access") {
                return ret::NOT_PRIVILEGED;
            }
            if param == 1 && count == 2 {
                count = 1;
            } else if param == 0xb {
                let Some(&first) = words.first() else {
                    k.darwin_unimplemented(format!("IOMobileFramebufferUserClient selector 68 (SetParameter) 11 with {} bytes: the method reads its first word unchecked", a.struct_in.len()));
                    return ret::UNSUPPORTED;
                };
                if first == 0 {
                    c.power_assertions -= 1;
                } else {
                    c.power_assertions += 1;
                }
            }
            set_parameter(k, param, &words, count)
        }
        // s_change_frame_info (0xfffffff00677a6c0, member
        // 0xfffffff0067785f8): a type below 6, its record and the options
        // to the framebuffer's slot 210, as selector 72's option.
        73 => {
            let ty = sc(0) as u32;
            if ty as usize >= super::NOTIFY_TYPES {
                return ret::BAD_ARGUMENT;
            }
            swap::notification_options(id, ty, sc(1) as u32)
        }
        // s_supported_frame_info (0xfffffff00677a718, member
        // 0xfffffff006778688): the framebuffer's slot 211
        // (0xfffffff006bfa8e8) to the pipe's 0xfffffff006bb66b4, which
        // names frame information item `index` (of 14) and gives its size
        // (1): the count and the size out, the name in the 64-byte
        // structure (`strncpy`); an index past 13 is kIOReturnBadArgument.
        // Either way the size given (0 on a refusal) is the client's
        // `+0x3c8`.
        74 => {
            const NAMES: [&str; 14] = super::finfo::ITEMS;
            let index = sc(0) as u32;
            let Some(name) = NAMES.get(index as usize) else {
                a.scalar_out[0] = 0;
                a.scalar_out[1] = 0;
                c.frame_info_size = 0;
                return ret::BAD_ARGUMENT;
            };
            a.scalar_out[0] = NAMES.len() as u64;
            a.scalar_out[1] = 1;
            c.frame_info_size = 1;
            a.struct_out.iter_mut().for_each(|b| *b = 0);
            a.struct_out[..name.len()].copy_from_slice(name.as_bytes());
            ret::SUCCESS
        }
        // s_swap_cancel (0xfffffff006779574): slot 217's gated cancel.
        52 => swap::cancel(k, sc(0) as u32),
        // s_notifications (0xfffffff00677a658, member 0xfffffff006778460):
        // scalars {callout, refcon, type, extra}.
        72 => notifications(k, id, c, sc(0), sc(1), sc(2) as u32, sc(3) as u32),
        // s_get_current_absolute_time (0xfffffff00677ad48): slot 241, the
        // pipe's time (0xfffffff006bb6550; its display counter only in
        // the hardware mode the pipe leaves off), mach_continuous_time.
        77 => {
            a.scalar_out[0] = super::super::mach::absolute_time();
            ret::SUCCESS
        }
        // s_get_block (0xfffffff0067799b4).
        79 => get_block(k, a),
        // s_set_block (0xfffffff006779834).
        78 => set_block(k, c, a),
        // s_swap_cancel_all (0xfffffff0067795b0): slot 218 with the time
        // `scalar[0] << 32 | scalar[1]`.
        81 => swap::cancel_all(k, (sc(0) << 32) | (sc(1) & 0xffff_ffff)),
        // s_copy_layer_displayed_surface (0xfffffff0067792fc): one scalar
        // in and one out, the caller entitled to
        // com.apple.private.allow-explicit-graphics-priority
        // (kIOReturnNotPrivileged), a layer below 4.
        83 => {
            if !k.darwin_entitled("com.apple.private.allow-explicit-graphics-priority") {
                return ret::NOT_PRIVILEGED;
            }
            if sc(0) as u32 >= 4 {
                return ret::BAD_ARGUMENT;
            }
            // Slot 242's member (0xfffffff00678b450): the layer's surface on
            // the glass (`+0x1358 + 8 * layer`), which a vertical blank sets,
            // as a send right in the client's task by IOSurface's
            // 0xfffffff005baa90c (selector 35's maker with no options);
            // none is kIOReturnError.
            a.scalar_out[0] = 0;
            let Some(surface) = swap::glass_surface(sc(0) as u32) else { return ret::ERROR };
            match super::super::iosurface::send_right_in_task(k, surface, 0) {
                Ok(name) => {
                    a.scalar_out[0] = u64::from(name);
                    ret::SUCCESS
                }
                Err(e) => e,
            }
        }
        s => {
            k.darwin_unimplemented(format!("IOMobileFramebufferUserClient selector {s} ({})", selector_name(s)));
            ret::UNSUPPORTED
        }
    };
    r
}

/// A block handler the pipe's block manager (`+0x1b70`, made by
/// 0xfffffff006bd0b2c) has on this panel: its type (`+0x1c`), the extra
/// scalars it takes (`+0x30` to `+0x34`), its size (`+0x38`), and whether
/// it has a get (`+0x40`) and a set (`+0x48`).
struct Handler {
    ty: u32,
    extra: (u32, u32),
    size: u32,
    get: bool,
    set: bool,
}

/// The handlers 0xfffffff006bd1ce0 registers at the pipe's first block
/// setup, for the components this pipe makes (`+0xc0`, the 2D temperature
/// correction `+0xe8`, the temperature compensation `+0x100` and the
/// brightness compensation `+0x108`; not `+0xd0`, `+0xd8`, `+0xe0`, `+0xf0`
/// or `+0xf8`, whose types 0x4d, 0x4e, 0x14, 0x24, 0x25 and 0x26 it
/// registers only with them; nor 0x6a, which needs the pipe's slot +0x358
/// to answer 2, and it answers 1).
const HANDLERS: [Handler; 11] = [
    Handler { ty: 7, extra: (0, 0), size: 0x15c, get: true, set: false },
    Handler { ty: 2, extra: (0, 0), size: 0x70c, get: true, set: true },
    Handler { ty: 1, extra: (0, 1), size: 0x180, get: true, set: true },
    Handler { ty: 0x27, extra: (0, 0), size: 0xd4, get: true, set: false },
    Handler { ty: 0x28, extra: (0, 0), size: 0x14, get: true, set: false },
    Handler { ty: 0x29, extra: (0, 0), size: 0x118, get: true, set: false },
    Handler { ty: 0x5b, extra: (0, 0), size: 0x28, get: true, set: false },
    Handler { ty: 0x2a, extra: (0, 0), size: 0x20, get: true, set: false },
    Handler { ty: 0x62, extra: (0, 0), size: 0x28, get: false, set: true },
    Handler { ty: 0x55, extra: (0, 0), size: 0x48, get: false, set: true },
    Handler { ty: 0x78, extra: (0, 0), size: 0x40, get: true, set: false },
];

/// The types the other registration sites give a handler, each as a block
/// of the pipe starts (0xfffffff006ba8304: 9 to 12; 0xfffffff006bdf1c4: 6;
/// 0xfffffff006be254c: 3 to 5; 0xfffffff006be896c: 0x4b, 0x4c;
/// 0xfffffff006c09198: 0x1c): whether those blocks are made here is not
/// worked out.
const OTHER_TYPES: [u32; 11] = [3, 4, 5, 6, 9, 10, 11, 12, 0x1c, 0x4b, 0x4c];

/// The block manager's call for `ty` (0xfffffff006775618 after the pipe's
/// checks): a type with no handler is kIOReturnUnsupported. A handler's get
/// or set (its vtable's +0x38 or +0x40, the same template for each: a
/// missing function is kIOReturnUnsupported, an extra scalar count outside
/// its range or a size not its own kIOReturnBadArgument) then runs the
/// component's function, through the command gate, which is not modelled.
fn block_call(k: &mut Kernel, name: &str, ty: u32, set: bool, size: usize, extra: u32) -> i32 {
    let Some(h) = HANDLERS.iter().find(|h| h.ty == ty) else {
        if OTHER_TYPES.contains(&ty) {
            k.darwin_unimplemented(format!("IOMobileFramebufferUserClient {name} of block type {ty} ({size} bytes, {extra} extra scalars): whether the pipe's block that registers it is made"));
        }
        return ret::UNSUPPORTED;
    };
    if !(if set { h.set } else { h.get }) {
        return ret::UNSUPPORTED;
    }
    if extra < h.extra.0 || extra > h.extra.1 || size != h.size as usize {
        return ret::BAD_ARGUMENT;
    }
    k.darwin_unimplemented(format!("IOMobileFramebufferUserClient {name} of block type {ty} ({size} bytes, {extra} extra scalars): its component's function"));
    ret::UNSUPPORTED
}

/// Selector 79, GetBlock (0xfffffff0067799b4): at least two scalars, the
/// block type and a word that must be zero, then any extra scalars; the
/// structure output is the block (the inband output is never null, so its
/// check passes). The framebuffer's slot 0x700 (0xfffffff006bfeae0) goes to
/// the pipe (0xfffffff006bd6984: the second scalar's low word nonzero is
/// kIOReturnBadArgument) and its block manager ([`block_call`]).
/// QuartzCore's 0x4d, 72 and 74 have no handler here.
fn get_block(k: &mut Kernel, a: &MethodArgs) -> i32 {
    if a.scalar_in.len() < 2 {
        return ret::BAD_ARGUMENT;
    }
    let ty = a.scalar_in[0] as u32;
    if a.scalar_in[1] as u32 != 0 {
        return ret::BAD_ARGUMENT;
    }
    block_call(k, "selector 79 (GetBlock)", ty, false, a.struct_out.len(), (a.scalar_in.len() - 2) as u32)
}

/// The block types each block client profile 1 index may set
/// (0xfffffff006f35470: a pointer and a count for each of backboardd,
/// windowserver, iomfb_fdr_loader, iomfb_bics_daemon and thermal_monitor).
const SET_BLOCK_TYPES: [&[u32]; 5] = [
    &[78, 77, 64, 50, 51, 61, 107, 115, 119],
    &[78, 77, 64, 50, 51, 61, 97, 22, 107, 115, 119],
    &[9, 11, 10, 27, 26, 36, 46, 47, 38, 52, 8, 65, 67, 68, 54, 53, 5, 3, 82, 84, 83, 85, 35, 98, 99, 89, 90, 92, 94, 101, 103, 111, 112, 113, 95, 116, 117],
    &[13, 14, 58, 59],
    &[1, 2],
];

/// Selector 78, SetBlock (0xfffffff006779834): at least two scalars, the
/// block type and a word that must be zero, then any extra scalars, and
/// the block as the structure input (inband, so never missing): fewer
/// scalars is kIOReturnBadArgument. The task must be allowed the type
/// (0xfffffff006776eb4, the global override at 0xfffffff007b4d973 being
/// clear): a client of block profile 1 for the types its index lists, one
/// of profile 2 (a development kernel's) for any, and then only with
/// com.apple.private.iomfb.set-block; else kIOReturnNotPrivileged. Then the
/// framebuffer's slot 0x6f8 (0xfffffff006bfea00) to the pipe's
/// 0xfffffff006bd691c: the second scalar's low word nonzero is
/// kIOReturnBadArgument, and the block manager's set (0xfffffff006775dc8,
/// the lookup of 0xfffffff006775618, [`block_call`]).
fn set_block(k: &mut Kernel, c: &Client, a: &MethodArgs) -> i32 {
    if a.scalar_in.len() < 2 {
        return ret::BAD_ARGUMENT;
    }
    let ty = a.scalar_in[0] as u32;
    let listed = match c.block_profile {
        1 => SET_BLOCK_TYPES.get(c.block_profile_index as usize).is_some_and(|t| t.contains(&ty)),
        2 => true,
        _ => false,
    };
    if !listed || !k.darwin_entitled("com.apple.private.iomfb.set-block") {
        return ret::NOT_PRIVILEGED;
    }
    if a.scalar_in[1] as u32 != 0 {
        return ret::BAD_ARGUMENT;
    }
    block_call(k, "selector 78 (SetBlock)", ty, true, a.struct_in.len(), (a.scalar_in.len() - 2) as u32)
}

/// Selector 72's member (0xfffffff006778460): a type past the slots is
/// kIOReturnBadArgument; with a callout the record is set up with the
/// slot's port, the callout and its reference and listed (slot 208, gated
/// 0xfffffff006795ec0) and, with `extra`, slot 210 run with it as the
/// record's options ([`swap::notification_options`]), which only frame
/// information takes (kIOReturnBadArgument for any other type, the record
/// staying listed); without a callout it is unlisted (slot 209, gated
/// 0xfffffff006796198: kIOReturnError for a record not listed).
fn notifications(k: &mut Kernel, id: u32, c: &mut Client, callout: u64, refcon: u64, ty: u32, extra: u32) -> i32 {
    let ty = ty as usize;
    if ty >= super::NOTIFY_TYPES {
        return ret::BAD_ARGUMENT;
    }
    if callout == 0 {
        let r = swap::disable_notifications(id, ty);
        if r == ret::SUCCESS {
            c.slots[ty].enabled = false;
        }
        return r;
    }
    let r = swap::enable_notifications(k, id, ty, c.slots[ty].enabled, c.slots[ty].port, callout, refcon);
    if r != ret::SUCCESS {
        return r;
    }
    c.slots[ty].enabled = true;
    if extra != 0 {
        return swap::notification_options(id, ty as u32, extra);
    }
    ret::SUCCESS
}

/// SetParameter 3's value as the pipe's component at `+0xc8` keeps it
/// (`+0x198`), for the pipe's programming of its block.
static PIPE_C8_198: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// SetParameter 6's EDR scale (`+0x187c`, 1.0 at start) and whether one is
/// set (`+0x1879`).
static EDR_SCALE: std::sync::Mutex<(f32, bool)> = std::sync::Mutex::new((1.0, false));

/// A power assertion the client holds let go at its stop: the
/// framebuffer's `SetParameter(11, 0)` (slot 228), whose answer the stop
/// does not look at.
pub fn release_power_assertion(k: &mut Kernel) {
    set_parameter(k, 0xb, &[0], 1);
}

/// `IOMobileFramebufferLegacy::SetParameter` (slot 228,
/// 0xfffffff00679efb0, which AppleCLCD keeps): each parameter it knows runs
/// a gated action when given the count of values it takes (0: four; 1 to
/// 3, 6, 7 and 23: one; 4: one below 101; 5 and 9: none; 10: one or two;
/// 22: any), and any other parameter or count is kIOReturnBadArgument.
/// Parameter 11, the power assertions, is not one of them. QuartzCore sets
/// 3, 6, 7, 8 and 19.
fn set_parameter(k: &mut Kernel, param: u32, values: &[u64], count: u32) -> i32 {
    let known = match param {
        0 => count == 4,
        1 | 2 | 3 | 6 | 7 | 0x17 => count == 1,
        4 => count == 1 && values.first().is_some_and(|&v| v < 0x65),
        5 | 9 => count == 0,
        10 => count == 1 || count == 2,
        0x16 => true,
        _ => false,
    };
    if !known {
        return ret::BAD_ARGUMENT;
    }
    match param {
        // Gated slot 276 (AppleCLCD 0xfffffff006bfab28) to the pipe's
        // 0xfffffff006bd3b64: its component at `+0xc8` (made at the pipe's
        // start, 0xfffffff006bb5be0) takes the value at `+0x198` and clears
        // `+0x108`; success.
        3 => {
            PIPE_C8_198.store(values[0] as u32, std::sync::atomic::Ordering::Relaxed);
            return ret::SUCCESS;
        }
        // Gated 0xfffffff0067a0e84 (EDR scaling, `+0x1878`, on unless the
        // `iomfb_enable_edr_scaling` boot-arg turns it off, and this boot
        // passes none): a nonzero value is the scale in 16.16 (`+0x187c`),
        // and whether one is set is `+0x1879`; then slot 326 (AppleCLCD
        // 0xfffffff006bfec98: the family's part is empty, and the pipe's
        // 0xfffffff006bd6d30 reaches only its components at `+0xf0`,
        // `+0xf8` and `+0x110`, which it never makes, and slot 0xcb8, which
        // needs the first); success.
        6 => {
            let v = values[0] as u32 as i32;
            let mut edr = EDR_SCALE.lock().unwrap_or_else(|e| e.into_inner());
            if v != 0 {
                edr.0 = v as f32 / 65536.0;
            }
            edr.1 = v != 0;
            return ret::SUCCESS;
        }
        // Gated 0xfffffff0067a10e0: slot 330 (AppleCLCD 0xfffffff006bfeff8)
        // to the pipe's 0xfffffff006bd6db0, which needs its component at
        // `+0xf8` (only ever cleared): kIOReturnUnsupported.
        7 => return ret::UNSUPPORTED,
        _ => {}
    }
    k.darwin_unimplemented(format!("IOMobileFramebuffer SetParameter {param} with {count} values {:x?} (the framebuffer's gated action)", &values[..values.len().min(count as usize)]));
    ret::UNSUPPORTED
}
