//! IOMobileFramebuffer: the display's framebuffer service as the device's
//! kexts have it, `com.apple.iokit.IOMobileGraphicsFamily` 343.0.0 and
//! `com.apple.driver.AppleMobileDispH9G` 140.0 in the 21H461 kernelcache
//! (the addresses below are that kernelcache's).
//!
//! - The service. AppleMobileDispH9G's personality "AppleADBE0-8970X"
//!   matches its `AppleCLCD` (an `UnifiedPipeline`, and so an
//!   `IOMobileFramebufferLegacy`) on the `AppleARMIODevice` nub of arm-io's
//!   disp0 (`disp0,t8011`) in the `IOService` plane
//!   ([`super::platform`]).
//! - Its user client, `IOMobileFramebufferUserClient`, which
//!   IOMobileFramebuffer.framework opens with `IOServiceOpen` for any type
//!   (`IOMobileFramebuffer::newUserClient` checks none): its methods
//!   ([`methods`]), its notification ports, and the swaps a client makes
//!   ([`swap`]).
//! - The panel. A completed swap's surfaces go to the embedder's
//!   presentation sink ([`sink`]) at the panel's vertical blank, which the
//!   framebuffer counts at the panel's rate ([`swap::Panel`]).

pub mod methods;
pub mod sink;
pub mod swap;

use super::iokit::{ret, Node, Prop};
use super::ipc::ObjId;
use crate::syscalls::Kernel;

/// The service's class, and its user client's.
pub const CLASS: &str = "AppleCLCD";
pub const UC_CLASS: &str = "IOMobileFramebufferUserClient";

/// The classes, most derived first (to `IORegistryEntry`; `OSObject` is
/// above it). Each class's `OSMetaClass` and the image that constructs it:
/// - `AppleCLCD` 0xfffffff007c277c8 and `UnifiedPipeline` 0xfffffff007c277a0
///   (AppleMobileDispH9G).
/// - `IOMobileFramebufferLegacy` 0xfffffff007b35940,
///   `IOMobileFramebufferService` 0xfffffff007b31400, `IOMobileFramebuffer`
///   0xfffffff007b313d8 and `IOMobileFramebufferUserClient`
///   0xfffffff007b313b0 (IOMobileGraphicsFamily).
/// - The kernel's `IOUserClient` 0xfffffff007942770 < `IOService`
///   0xfffffff007942cb8 < `IORegistryEntry` 0xfffffff007940d48.
pub fn superclasses(class: &str) -> &'static [&'static str] {
    match class {
        CLASS => &[CLASS, "UnifiedPipeline", "IOMobileFramebufferLegacy", "IOMobileFramebufferService", "IOMobileFramebuffer", "IOService", "IORegistryEntry"],
        UC_CLASS => &[UC_CLASS, "IOUserClient", "IOService", "IORegistryEntry"],
        _ => &[],
    }
}

/// Whether every service of `class` is the display's framebuffer: the
/// device has one display controller, disp0.
pub fn class_complete(class: &str) -> bool {
    matches!(class, CLASS | "UnifiedPipeline" | "IOMobileFramebufferLegacy" | "IOMobileFramebufferService" | "IOMobileFramebuffer")
}

/// Whether tree entry `i` is the framebuffer.
pub fn is_service(i: u32) -> bool {
    super::iokit::tree().get(i as usize).is_some_and(|n| n.class == CLASS)
}

/// The framebuffer on disp0's nub `nub`, its provider in the `IOService`
/// plane, with the properties its personality and matching give it (see
/// [`super::platform`]):
/// - The personality "AppleADBE0-8970X": `IOClass`, `IOProviderClass`,
///   `IONameMatch` (an array) and `BacklightMatching`.
/// - `IOProbeScore` is the probe's. `AppleCLCD::probe`
///   (0xfffffff006bf54d0) sets the score to 1 unless its provider has a
///   nonzero `no-dcp-driver`, which disp0 has not.
/// - There is no `IOMatchCategory` in the personality.
///
/// What the framebuffer's start sets besides is reported when read (see
/// [`property_absent`] for the names no driver sets).
pub fn add_service(t: &mut Vec<Node>, nub: u32) {
    let s = |v: &str| Prop::Str(v.to_string());
    let sym = |v: &str| Prop::Sym(v.to_string());
    let backlight = Prop::Dict(vec![("IOPropertyMatch".to_string(), Prop::Dict(vec![("backlight-control".to_string(), Prop::Bool(true))]))]);
    let service_props = vec![
        ("CFBundleIdentifier".to_string(), sym("com.apple.driver.AppleMobileDispH9G")),
        ("CFBundleIdentifierKernel".to_string(), sym("com.apple.driver.AppleMobileDispH9G")),
        ("IOClass".to_string(), sym(CLASS)),
        ("IOProviderClass".to_string(), sym(super::platform::ARM_IO_DEVICE)),
        ("IONameMatch".to_string(), Prop::Strs(vec!["disp0,t8010".to_string(), "disp0,t8011".to_string()])),
        ("IONameMatched".to_string(), s("disp0,t8011")),
        ("IOMatchedAtBoot".to_string(), Prop::Bool(true)),
        ("IOMatchCategory".to_string(), sym("IODefaultMatchCategory")),
        ("IOProbeScore".to_string(), Prop::Num(1, 32)),
        ("BacklightMatching".to_string(), backlight),
    ];
    t.push(Node { name: CLASS.to_string(), props: Vec::new(), class: CLASS, service_props, parent: Some(nub), children: Vec::new(), kernel_only: false, nub: None });
}

/// Property names no driver sets on the framebuffer (entry `i`, the
/// service) or on its nub (the service's provider), which read on them are
/// answered as missing:
/// - Names no image of the 21H461 kernelcache has as a string:
///   `GainMapVersion`, which `IOMobileFramebufferOpen` reads from the
///   service; `canvas-width` and `canvas-height`, which it reads from the
///   service's provider (`getEDTProperty`; disp0's device tree entry has
///   neither); and `dfr`, which the framework's `iomfb_match_callback`
///   reads from each framebuffer it finds.
/// - Names other kexts use only otherwise: `AppleTV`, which
///   IOUSBDeviceFamily compares a model string with (0xfffffff00617c0c0),
///   and `hdcp-hoover-protocol`, which AUC reads from the framebuffer
///   (0xfffffff00655fb8c) and nothing sets.
/// - `IOMFBIntDcpUsedForExtWhenLidClose`, the name of the pipe's runtime
///   property 0x7f (IOMobileGraphicsFamily's names, 0xfffffff00677d36c).
///   The pipe publishes each runtime property it registers in its table
///   (`FUN_fffffff006bde66c`) as the framebuffer's registry property of
///   that name (the table's publisher, 0xfffffff006bea4e4), and
///   AppleMobileDispH9G registers no property 0x7f.
/// - On the service, `external`: AppleCLCD sets it (0xfffffff006bf55ec,
///   0xfffffff006bf5a54) only when its provider's device tree entry has
///   `external`.
pub fn property_absent(t: &[Node], i: u32, name: &str) -> bool {
    if matches!(name, "GainMapVersion" | "canvas-width" | "canvas-height" | "dfr" | "AppleTV" | "hdcp-hoover-protocol" | "IOMFBIntDcpUsedForExtWhenLidClose") {
        return true;
    }
    let Some(n) = t.get(i as usize) else { return false };
    if n.class != CLASS || name != "external" {
        return false;
    }
    let provider = n.parent.and_then(|p| t.get(p as usize));
    provider.is_some_and(|p| !p.props.iter().any(|(k, _)| k == "external"))
}

// ---------------------------------------------------------------------------
// The user client.

/// One notification slot of a client (`+0x110 + type * 0xb0`): the port
/// `registerNotificationPort` gave (a send right the client holds), its
/// reference, and whether the record the framebuffer lists (`+0x118`) is
/// on (`+0x18c`).
#[derive(Clone, Debug, Default)]
pub struct Slot {
    pub port: Option<ObjId>,
    /// Carried by the slot's messages, of which none is sent here.
    pub refcon: u32,
    pub enabled: bool,
}

/// The number of notification types (`registerNotificationPort` and
/// selector 72 refuse any past it): hot plug 0, power 1, HDCP 2, frame
/// information 3, CRC 4, vertical blank 5.
pub const NOTIFY_TYPES: usize = 6;

/// An `IOMobileFramebufferUserClient` (0x538 bytes): the task that opened
/// it (`+0xe8`), its type (`+0xf0`, 2 once it swaps), the block client
/// profile its entitlement gives (`+0x104`, `+0x108`), whether it started
/// and is not stopped (`+0xe0`), its power assertions (`+0xfc`), whether
/// it turned statistics on (`+0xf4`), and its notification slots.
pub struct Client {
    pub pid: i32,
    pub ty: u32,
    /// Read by the block selectors (78, 79, 85).
    pub block_profile: u32,
    pub block_profile_index: u32,
    pub started: bool,
    pub power_assertions: i32,
    pub statistics: bool,
    pub slots: [Slot; NOTIFY_TYPES],
}

/// The block client profile of the task opening a client
/// (0xfffffff0067763a8): its `com.apple.private.iomfb.set-block-client-profile`
/// string among the five at 0xfffffff006f35438 is profile 1 (and its index);
/// the two at 0xfffffff006f35460 count (profile 2) only on a development
/// kernel (`kern_config_is_development`), which a release one is not.
/// The value is cast to an OSString and used unchecked: any other kind is
/// reported. `Err`: what is not modelled.
fn block_profile(k: &Kernel) -> Result<(u32, u32), String> {
    use super::codesign::Ent;
    let Some(v) = k.dtask.codesign.as_ref().and_then(|c| c.ents.get(b"com.apple.private.iomfb.set-block-client-profile")) else { return Ok((0, 0)) };
    let Ent::String(s) = v else { return Err(format!("com.apple.private.iomfb.set-block-client-profile of a kind other than a string ({v:?}), which the kext dereferences as one")) };
    const PROFILE_1: [&str; 5] = ["backboardd", "windowserver", "iomfb_fdr_loader", "iomfb_bics_daemon", "thermal_monitor"];
    Ok(PROFILE_1.iter().position(|p| p.as_bytes() == s.as_slice()).map_or((0, 0), |i| (1, i as u32)))
}

/// `IOMobileFramebuffer::newUserClient(task, securityID, type, handler)`
/// (0xfffffff006789080, the four-argument form IOService's tries first):
/// any type. The client's `init` (0xfffffff006776810: the task and type
/// kept, the block client profile from the entitlement), `attach` and
/// `start` (0xfffffff0067769c8: the provider cast to an
/// IOMobileFramebuffer, the slots cleared, and for type 2 the client made
/// a swap client of the framebuffer, slot 169). None of those fails here;
/// a failure would be kIOReturnInternalError.
pub fn new_user_client(k: &mut Kernel, ty: u32) -> Result<Client, i32> {
    let (block_profile, block_profile_index) = match block_profile(k) {
        Ok(p) => p,
        Err(what) => {
            k.darwin_unimplemented(what);
            return Err(ret::UNSUPPORTED);
        }
    };
    let c = Client { pid: k.pid, ty, block_profile, block_profile_index, started: true, power_assertions: 0, statistics: false, slots: Default::default() };
    if ty == 2 {
        swap::add_swap_client();
    }
    Ok(c)
}

/// `clientClose` (0xfffffff006777138): terminate, so `stop`
/// (0xfffffff006776b28): the power assertions the client still holds
/// released (`SetParameter(11, 0)` each), its statistics turned off, the
/// HDCP client stopped, each slot's notifications turned off and its port
/// released, and a swap client unregistered. kIOReturnSuccess.
pub fn client_close(k: &mut Kernel, id: u32, c: &mut Client) {
    if !c.started {
        return;
    }
    // OSDecrementAtomic gives the old count: one release for each the
    // client holds, the count ending one below zero.
    loop {
        let old = c.power_assertions;
        c.power_assertions -= 1;
        if old <= 0 {
            break;
        }
        methods::release_power_assertion(k);
    }
    if c.statistics {
        k.darwin_unimplemented("IOMobileFramebufferUserClient::stop turning off the framebuffer's statistics (PerformanceStatistics)".to_string());
        c.statistics = false;
    }
    for ty in 0..NOTIFY_TYPES {
        if c.slots[ty].enabled {
            swap::disable_notifications(id, ty);
            c.slots[ty].enabled = false;
        }
        if let Some(p) = c.slots[ty].port.take() {
            // IOUserClient::releaseNotificationPort.
            k.ipc().release_send(p);
        }
    }
    c.started = false;
    swap::client_stopped(id);
    if c.ty == 2 {
        swap::remove_swap_client(k, id);
    }
}

/// The client freed: what it still holds let go.
pub fn client_free(k: &mut Kernel, id: u32, c: &mut Client) {
    client_close(k, id, c);
    swap::client_gone(k, id);
}

/// `registerNotificationPort(port, type, refCon)` (0xfffffff006777610):
/// a type past the slots is kIOReturnBadArgument and a slot that has a
/// port already kIOReturnPortExists; the port and reference are kept.
/// Type 3, frame information, also makes the client's shared data queue
/// when the framebuffer gives frame information through one, which is not
/// modelled.
pub fn register_notification_port(k: &mut Kernel, c: &mut Client, port: Option<ObjId>, ty: u32, reference: u64) -> i32 {
    const K_IO_RETURN_PORT_EXISTS: i32 = 0xe00002dd_u32 as i32;
    if ty as usize >= NOTIFY_TYPES {
        return ret::BAD_ARGUMENT;
    }
    let slot = &mut c.slots[ty as usize];
    if slot.port.is_some() {
        return K_IO_RETURN_PORT_EXISTS;
    }
    slot.port = port;
    slot.refcon = reference as u32;
    if ty == 3 && swap::frame_info_size(c) != 0 {
        k.darwin_unimplemented("IOMobileFramebufferUserClient frame information through its shared data queue (IOSharedDataQueue of 0x1040 bytes)".to_string());
    }
    ret::SUCCESS
}

/// `clientMemoryForType(type, options, memory)` (0xfffffff0067777d8):
/// type 3 is the frame information queue (kIOReturnNotReady without one);
/// any other is success with no memory, which maps nothing.
pub fn client_memory_for_type(_c: &Client, ty: u32) -> Result<(), i32> {
    if ty == 3 {
        return Err(ret::NOT_READY);
    }
    Ok(())
}

/// The client's properties: none of its own.
pub fn client_property(_c: &Client, _name: &str) -> Option<Prop> {
    None
}
