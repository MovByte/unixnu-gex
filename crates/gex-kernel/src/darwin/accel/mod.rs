//! The GPU's accelerator service, presented as the device's own:
//! `AGXAcceleratorG9G_A0`, AGXG9G's driver of the GPU's nub `arm-io/sgx`
//! (compatible `gpu,t8011`), an `IOGPU` and so an `IOAcceleratorES`. Its
//! work is WebMetal's: Metal's commands reach the host through the WebMetal
//! connection, not AGX's firmware.
//!
//! Metal.framework's `_MTLRegisterDevices` finds it by class
//! (`IOServiceMatching("IOAcceleratorES")`), loads the bundle its
//! `MetalPluginName` names from /System/Library/Extensions and makes the
//! class `MetalPluginClassName` names: WebMetal's, in place of AGXMetalA10's
//! (`AGXA10XDevice`, which AGXG9G sets at 0xfffffff005c28830).
//! IOGPU.framework's clients (RunningBoard's `IOServiceMatching("IOGPU")`,
//! then `IOGPUDeviceCreate`) open its device user client, type 1. The
//! WebMetal plugin's own connection is type 0, which carries the WebMetal
//! wire protocol (the public WebMetal `wire/README.md`, "Transport").
//!
//! Its classes, its clients' and its place in the `IOService` plane are the
//! device's, which the shipped Sandbox profiles decide by. Their
//! `iokit-connection` filter (0xfffffff0069f2564) walks an entry and its
//! providers up to the root ([`super::platform`]), each with its
//! superclasses. Their class filters walk an entry's own classes.

pub mod host;
pub mod iogpu;
pub mod wire;

use super::iokit::{ret, MethodArgs, Node, Prop};
use crate::syscalls::Kernel;

/// The service's class.
pub const CLASS: &str = "AGXAcceleratorG9G_A0";

/// The class of the device user client that AGXG9G's `newDeviceUserClient`
/// (vtable slot 199, 0xfffffff005be7e0c: `AGXDeviceUserClient`'s metaclass's
/// `alloc`) makes.
pub const DEVICE_CLIENT: &str = "AGXDeviceUserClient";

/// IOGPUFamily's memory information client's class.
pub const MEMORY_INFO_CLIENT: &str = "IOGPUMemoryInfoUserClient";

/// The classes of the service and its clients, most derived first (to
/// `IORegistryEntry`; `OSObject` is above it). Each class's `OSMetaClass`
/// constructor names its superclass's metaclass:
/// - `AGXAcceleratorG9G_A0` 0xfffffff007aecab0, `AGXAcceleratorG9`
///   0xfffffff007aecad8, `AGXAcceleratorG5` 0xfffffff007aec958,
///   `AGXFamilyAccelerator` 0xfffffff007aec8a8, `AGXAccelerator`
///   0xfffffff007aec5b0 and `AGXDeviceUserClient` 0xfffffff007aec4d0
///   (AGXG9G).
/// - `IOGPU` 0xfffffff007aeb6b0, `IOAcceleratorES` 0xfffffff007aeb688,
///   `IOGPUDeviceUserClient` 0xfffffff007aeb200 and
///   `IOGPUMemoryInfoUserClient` 0xfffffff007aeb7b0 (IOGPUFamily).
/// - The kernel's `IOUserClient` 0xfffffff007942770 < `IOService`
///   0xfffffff007942cb8 < `IORegistryEntry` 0xfffffff007940d48.
pub fn superclasses(class: &str) -> &'static [&'static str] {
    match class {
        CLASS => &[CLASS, "AGXAcceleratorG9", "AGXAcceleratorG5", "AGXFamilyAccelerator", "AGXAccelerator", "IOGPU", "IOAcceleratorES", "IOService", "IORegistryEntry"],
        DEVICE_CLIENT => &[DEVICE_CLIENT, "IOGPUDeviceUserClient", "IOUserClient", "IOService", "IORegistryEntry"],
        MEMORY_INFO_CLIENT => &[MEMORY_INFO_CLIENT, "IOUserClient", "IOService", "IORegistryEntry"],
        _ => &[],
    }
}

/// Whether every service of `class` is the accelerator: the GPU has one.
pub fn class_complete(class: &str) -> bool {
    matches!(class, CLASS | "AGXAcceleratorG9" | "AGXAcceleratorG5" | "AGXFamilyAccelerator" | "AGXAccelerator" | "IOGPU" | "IOAcceleratorES")
}

/// Whether tree entry `i` is the accelerator.
pub fn is_service(i: u32) -> bool {
    super::iokit::tree().get(i as usize).is_some_and(|n| n.class == CLASS)
}

/// `IOGPU::start`'s `setProperty("KDebugVersion", 0x100000000, 64)`
/// (0xfffffff005bd3f20).
const KDEBUG_VERSION: u64 = 0x1_0000_0000;

/// The accelerator on the GPU's nub `gpu`, its provider in the `IOService`
/// plane, with the properties the device's has from its personality
/// (AGXG9G's "AGXG9G_A0") and matching (see [`super::platform`]), and what
/// `IOGPU::start` sets. `MetalPluginName` and `MetalPluginClassName` name
/// the WebMetal bundle and its device class. What AGXG9G's start and probe
/// set besides is not modelled, and is reported when read:
/// - `IOProbeScore` is the probe's (0xfffffff005c02e48), from the GPU's
///   probed configuration.
/// - `PerformanceStatistics` is IOGPUStatistics'.
/// - There are the power, performance and firmware properties.
pub fn add_service(t: &mut Vec<Node>, gpu: u32) {
    let s = |v: &str| Prop::Str(v.to_string());
    let sym = |v: &str| Prop::Sym(v.to_string());
    let service_props = vec![
        ("CFBundleIdentifier".to_string(), sym("com.apple.AGXG9G")),
        ("CFBundleIdentifierKernel".to_string(), sym("com.apple.AGXG9G")),
        ("IOClass".to_string(), sym(CLASS)),
        ("IOProviderClass".to_string(), sym(super::platform::ARM_IO_DEVICE)),
        ("IOMatchCategory".to_string(), sym("IOAcceleratorES")),
        ("IONameMatch".to_string(), Prop::Strs(vec!["gpu,t8011".to_string()])),
        ("IONameMatched".to_string(), s("gpu,t8011")),
        ("IOMatchedAtBoot".to_string(), Prop::Bool(true)),
        ("IOGLESBundleName".to_string(), s("AppleMetalGLRenderer")),
        ("IOSourceVersion".to_string(), s("282.14")),
        ("MetalPluginName".to_string(), s("WebMetal")),
        ("MetalPluginClassName".to_string(), sym("WebMetalDevice")),
        ("KDebugVersion".to_string(), Prop::Num(KDEBUG_VERSION, 64)),
    ];
    t.push(Node { name: CLASS.to_string(), props: Vec::new(), class: CLASS, service_props, parent: Some(gpu), children: Vec::new(), kernel_only: false, nub: None });
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
/// properties)`. `IOGPU::newUserClient` (0xfffffff005bd57d0, which AGXG9G
/// does not override) makes:
/// - for type 1 (its low 16 bits; the high 16 are the client's options),
///   the device client its `newDeviceUserClient` gives, an
///   `AGXDeviceUserClient`;
/// - for type 33, the memory information client.
/// It refuses every other type (kIOReturnBadArgument), after which
/// `IOService::newUserClient` finds no `IOUserClientClass` on the service
/// (kIOReturnUnsupported). Type 0 is the WebMetal connection, which the
/// device's service refuses. It presents as the device client Metal's
/// driver opens there (`AGXDeviceUserClient`); its methods are WebMetal's.
pub fn new_user_client(k: &mut Kernel, service: u32, ty: u32) -> Result<(&'static str, Client), i32> {
    if ty == wire::TYPE {
        return Ok((DEVICE_CLIENT, Client::Wire(wire::Wire::new(k))));
    }
    match ty & 0xffff {
        1 => iogpu::Device::open(k, service, ty >> 16).map(|d| (DEVICE_CLIENT, Client::Device(d))),
        33 => Ok((MEMORY_INFO_CLIENT, Client::MemoryInfo)),
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

/// A client's own property. The WebMetal connection presents as a device
/// client, whose `AppUsage` (an `OSSerializer` of its device's use) it does
/// not model either.
pub fn client_property(c: &super::iokit::UserClient, name: &str) -> Result<Option<Prop>, String> {
    match &c.kind {
        super::iokit::Kind::Accel(Client::Device(d)) => d.property(name),
        super::iokit::Kind::Accel(Client::Wire(_)) if name == "AppUsage" && !c.closed => Err("the WebMetal connection's AppUsage (a device client's usage serialized)".to_string()),
        _ => Ok(None),
    }
}
