//! The GPU's accelerator service: `WebMetalAccelerator`, an `IOGPU` (and so
//! an `IOAcceleratorES`) driving the GPU's nub, `arm-io/sgx` (compatible
//! `gpu,t8011`), in place of AGXG9G's `AGXAcceleratorG9G_A0`.
//!
//! Metal.framework's `_MTLRegisterDevices` finds it by class
//! (`IOServiceMatching("IOAcceleratorES")`), loads the bundle its
//! `MetalPluginName` names from /System/Library/Extensions and makes the
//! class `MetalPluginClassName` names. IOGPU.framework's clients
//! (RunningBoard's `IOServiceMatching("IOGPU")`, then `IOGPUDeviceCreate`)
//! open its IOGPU device user client, type 1. The WebMetal plugin's own
//! connection is type 0, which carries the WebMetal wire protocol (the
//! public WebMetal `wire/README.md`, "Transport").
//!
//! Its user clients are attached to it in the IOService plane, so the
//! shipped Sandbox profiles admit them by that ancestry: their
//! `iokit-registry-entry-class` filter (`0xfffffff0069f2564`) walks the
//! entry's provider chain ([`super::platform`]) and each class's
//! superclasses, and the `container`, `backboardd`, `runningboardd` and
//! `com.apple.WebKit.GPU` profiles allow `iokit-open-user-client` under an
//! `IOGPU`.

pub mod iogpu;
pub mod wire;

use super::iokit::{ret, MethodArgs, Node, Prop};
use crate::syscalls::Kernel;

/// The service's class.
pub const CLASS: &str = "WebMetalAccelerator";

/// The WebMetal connection's class.
pub const WIRE_CLASS: &str = "WebMetalUserClient";

/// The classes of the service and its clients, most derived first:
/// IOGPUFamily's from its OSMetaClass constructors (`IOGPU` < `IOAcceleratorES`
/// < `IOService`, `IOGPUDeviceUserClient` and `IOGPUMemoryInfoUserClient`
/// < `IOUserClient`).
pub fn superclasses(class: &str) -> &'static [&'static str] {
    match class {
        CLASS => &[CLASS, "IOGPU", "IOAcceleratorES", "IOService", "IORegistryEntry"],
        "IOGPUDeviceUserClient" => &["IOGPUDeviceUserClient", "IOUserClient", "IOService", "IORegistryEntry"],
        "IOGPUMemoryInfoUserClient" => &["IOGPUMemoryInfoUserClient", "IOUserClient", "IOService", "IORegistryEntry"],
        WIRE_CLASS => &[WIRE_CLASS, "IOUserClient", "IOService", "IORegistryEntry"],
        _ => &[],
    }
}

/// Whether every service of `class` is the accelerator: the GPU has one.
pub fn class_complete(class: &str) -> bool {
    matches!(class, CLASS | "IOGPU" | "IOAcceleratorES")
}

/// Whether tree entry `i` is the accelerator.
pub fn is_service(i: u32) -> bool {
    super::iokit::tree().get(i as usize).is_some_and(|n| n.class == CLASS)
}

/// `IOGPU::start`'s `setProperty("KDebugVersion", 0x100000000, 64)`
/// (0xfffffff005bd3f20).
const KDEBUG_VERSION: u64 = 0x1_0000_0000;

/// The accelerator on the GPU's nub `gpu` (the `AppleARMIODevice` arm-io's
/// driver made of the entry whose `compatible` is `gpu,t8011`, AGXG9G_A0's
/// `IONameMatch`): its provider in the IOService plane. Its properties are
/// the wire documentation's (`IOMatchCategory`, `MetalPluginName`,
/// `MetalPluginClassName`), the class and provider class that place it, and
/// what `IOGPU::start` sets.
pub fn add_service(t: &mut Vec<Node>, gpu: u32) {
    let s = |v: &str| Prop::Str(v.to_string());
    let service_props = vec![
        ("IOClass".to_string(), s(CLASS)),
        ("IOProviderClass".to_string(), s("AppleARMIODevice")),
        ("IOMatchCategory".to_string(), s("IOAcceleratorES")),
        ("MetalPluginName".to_string(), s("WebMetal")),
        ("MetalPluginClassName".to_string(), s("WebMetalDevice")),
        ("KDebugVersion".to_string(), Prop::Num(KDEBUG_VERSION, 64)),
    ];
    t.push(Node { name: CLASS.to_string(), props: Vec::new(), class: CLASS, service_props, parent: Some(gpu), children: Vec::new(), kernel_only: false, nub: None });
}

/// Whether a property tree entry `i` does not have may be one not
/// modelled: for the accelerator, only `PerformanceStatistics`, which
/// IOGPUFamily's statistics (IOGPUStatistics) set on it from the GPU's
/// counters; its other properties are all the ones above.
pub fn property_unknown(name: &str) -> bool {
    name == "PerformanceStatistics"
}

/// A user client of the accelerator.
pub enum Client {
    /// Type 1: IOGPUFamily's device user client.
    Device(iogpu::Device),
    /// Type 33: IOGPUFamily's memory information client.
    MemoryInfo,
    /// Type 0: the WebMetal connection.
    Wire(wire::Wire),
}

/// The accelerator's `newUserClient(owningTask, securityID, type,
/// properties)`. `IOGPU::newUserClient` (0xfffffff005bd57d0) makes the
/// device client for type 1 (its low 16 bits; the high 16 are the client's
/// options) and the memory information client for 33, and refuses every
/// other type (kIOReturnBadArgument), after which `IOService::newUserClient`
/// finds no `IOUserClientClass` on the service (kIOReturnUnsupported). The
/// accelerator's own type 0 is the WebMetal connection.
pub fn new_user_client(k: &mut Kernel, service: u32, ty: u32) -> Result<(&'static str, Client), i32> {
    if ty == wire::TYPE {
        return Ok((WIRE_CLASS, Client::Wire(wire::Wire::new())));
    }
    match ty & 0xffff {
        1 => iogpu::Device::open(k, service, ty >> 16).map(|d| ("IOGPUDeviceUserClient", Client::Device(d))),
        33 => Ok(("IOGPUMemoryInfoUserClient", Client::MemoryInfo)),
        _ => Err(ret::UNSUPPORTED),
    }
}

/// `clientClose`.
pub fn client_close(k: &mut Kernel, c: &mut Client) {
    match c {
        Client::Device(d) => d.close(k),
        // IOGPUMemoryInfoUserClient::clientClose (0xfffffff005bdbee4):
        // terminate, which leaves no state here; kIOReturnSuccess.
        Client::MemoryInfo => {}
        Client::Wire(w) => w.close(k),
    }
}

/// The client freed: what it still holds let go.
pub fn client_free(k: &mut Kernel, c: &mut Client) {
    match c {
        Client::Device(d) => d.free(k),
        Client::MemoryInfo => {}
        Client::Wire(w) => w.close(k),
    }
}

/// `getService`: none of these clients overrides IOUserClient's.
pub fn client_service(_service: u32, _c: &Client) -> Option<u32> {
    None
}

/// `registerNotificationPort(port, type, refCon)`.
pub fn register_notification_port(k: &mut Kernel, c: &mut Client, port: Option<super::ipc::ObjId>, ty: u32, reference: u64) -> i32 {
    match c {
        Client::Device(d) => d.register_notification_port(k, port, ty, reference),
        // IOUserClient's: kIOReturnUnsupported.
        Client::MemoryInfo | Client::Wire(_) => ret::UNSUPPORTED,
    }
}

/// `externalMethod`.
pub fn external_method(k: &mut Kernel, c: &mut Client, a: &mut MethodArgs) -> i32 {
    match c {
        Client::Device(d) => d.external_method(k, a),
        Client::MemoryInfo => iogpu::memory_info_method(k, a),
        Client::Wire(w) => w.external_method(k, a),
    }
}

/// `getTargetAndTrapForIndex` and the trap's function: `p` is the trap's
/// first four arguments (the trap gets no more here).
pub fn trap(k: &mut Kernel, c: &mut Client, index: u32, p: [u64; 4]) -> i32 {
    match c {
        Client::Device(d) => d.trap(k, index, p),
        // IOUserClient's getTargetAndTrapForIndex: none, and so success.
        Client::MemoryInfo | Client::Wire(_) => ret::SUCCESS,
    }
}

/// A client's own property.
pub fn client_property(c: &super::iokit::UserClient, name: &str) -> Result<Option<Prop>, String> {
    match &c.kind {
        super::iokit::Kind::Accel(Client::Device(d)) => d.property(name),
        _ => Ok(None),
    }
}
