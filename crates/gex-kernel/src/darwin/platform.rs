//! The platform's drivers between the registry's root and the GPU, as the
//! device's kernelcache (21H461, iPad7,1) matches and publishes them over
//! its device tree in the `IOService` plane:
//!
//! ```text
//! Root                    IORegistryEntry
//!   J120AP                IOPlatformExpertDevice (the device tree's root)
//!     AppleARMPE          the platform expert
//!       arm-io            IOPlatformDevice, a nub of the device tree's arm-io
//!         AppleT8011IO    arm-io's driver
//!           sgx           AppleARMIODevice, a nub of arm-io's sgx
//!             (the GPU's accelerator, `super::accel`)
//!           disp0         AppleARMIODevice, a nub of arm-io's disp0
//!             (the display's framebuffer, `super::iomfb`)
//! ```
//!
//! - The platform expert. `AppleARMPE` (com.apple.driver.AppleARMPlatform)
//!   is the only personality whose `IOProviderClass` is
//!   `IOPlatformExpertDevice`. Its `IONameMatch` "AppleARM" is one of the
//!   root's `compatible` names. Its probe is IODTPlatformExpert's, which
//!   keeps the personality's score.
//! - The top-level nubs. AppleARMPE's start (0xfffffff00598f844) calls
//!   `IOPlatformExpert::start` through IODTPlatformExpert's vtable
//!   (0xfffffff00598f93c), which ends in `configure` and so in
//!   `processTopLevel`. AppleARMPE overrides neither of those, nor
//!   `createNub` or `createNubs` (vtable slots 174, 208, 211, 212).
//!   - The nubs are the root's children less its `excludeList`
//!     (0xfffffff00598fee8): `('chosen', 'memory', 'options', 'aliases')`.
//!     Its `deleteList` (0xfffffff00598fedc) is empty.
//!   - `IODTPlatformExpert::createNub` (0xfffffff00780d2f8) makes each an
//!     `IOPlatformDevice`; its vtable is stored at 0xfffffff00780d370.
//!   - `createNubs` attaches each to the expert (0xfffffff00780d500).
//! - arm-io's driver. `AppleT8011IO` (com.apple.driver.AppleT8011) is the
//!   only personality naming arm-io: `IOProviderClass` `IOPlatformDevice`,
//!   `IONameMatch` "arm-io,t8011". Its probe is IOService's (score 0).
//! - arm-io's nubs. AppleARMIO's publishing routine (vtable slot 178,
//!   0xfffffff00598c1d4) is not overridden by `AppleT801xIO` or
//!   `AppleT8011IO`.
//!   - It takes every child of its provider; the exclude list is empty
//!     (`IODTFindMatchingEntries` at 0xfffffff00598c278).
//!   - Each child becomes an `AppleARMIODevice` (slot 176, 0xfffffff00598c118:
//!     216 bytes, AppleARMIODevice's vtable stored at 0xfffffff00598c160).
//!   - Each is attached to the AppleARMIO (0xfffffff00598c2b8).
//!
//! Each class's superclasses are its `OSMetaClass` constructor's (the
//! metaclass, its name and its superclass's metaclass, from the kernel's and
//! each kext's static initializers).
//!
//! A driver's properties are its personality plus what matching adds:
//! - `CFBundleIdentifier`, the kext's, where the personality has none
//!   (`OSKext::copyPersonalitiesArray`).
//! - `CFBundleIdentifierKernel` (`uniquePersonalityProperties` in
//!   `IOCatalogue::addDrivers`, which also uniques `IOClass`,
//!   `IOProviderClass` and `IOMatchCategory` to OSSymbols).
//! - `IONameMatched`, the name `IONameMatch` matched (`matchInternal`).
//! - `IOMatchedAtBoot`, the kext being in the boot collection
//!   (`personalityIsBoot`).
//! - `IOMatchCategory` (`IODefaultMatchCategory` if the personality has
//!   none).
//! - `IOProbeScore`, a 32-bit number of the probe's score (`probeCandidates`).
//!
//! What each driver's start then sets is its own and not modelled: such a
//! property is reported when read. So are these drivers' other nubs and
//! clients, which are their children in the `IOService` plane.

use super::iokit::{Node, Prop};

/// The platform expert's class.
pub const PE: &str = "AppleARMPE";

/// arm-io's driver's class.
pub const ARM_IO: &str = "AppleT8011IO";

/// The class of a nub the platform expert publishes.
pub const PLATFORM_DEVICE: &str = "IOPlatformDevice";

/// The class of a nub arm-io's driver publishes.
pub const ARM_IO_DEVICE: &str = "AppleARMIODevice";

/// The classes of the drivers and nubs here, most derived first (to
/// `IORegistryEntry`; `OSObject` is above it). Each class's `OSMetaClass`
/// and the image that constructs it:
/// - `AppleARMPE` 0xfffffff007addf00 and `AppleARMIO` 0xfffffff007adddf8,
///   both AppleARMPlatform.
/// - `AppleARMIODevice` 0xfffffff007adde20, AppleARMPlatform.
/// - `AppleT8011IO` 0xfffffff007c2b130 and `AppleT801xIO` 0xfffffff007c2b158,
///   both AppleT8011.
/// - The kernel's: `IODTPlatformExpert` 0xfffffff007941798,
///   `IOPlatformExpert` 0xfffffff007941760, `IOPlatformIO`
///   0xfffffff007941850 and `IOPlatformDevice` 0xfffffff007941800.
pub fn superclasses(class: &str) -> &'static [&'static str] {
    match class {
        PE => &[PE, "IODTPlatformExpert", "IOPlatformExpert", "IOService", "IORegistryEntry"],
        ARM_IO => &[ARM_IO, "AppleT801xIO", "AppleARMIO", "IOPlatformIO", "IOService", "IORegistryEntry"],
        PLATFORM_DEVICE => &[PLATFORM_DEVICE, "IOService", "IORegistryEntry"],
        ARM_IO_DEVICE => &[ARM_IO_DEVICE, "IOService", "IORegistryEntry"],
        _ => &[],
    }
}

/// Whether `class` is one of the drivers here, whose children in the
/// `IOService` plane are not all modelled.
pub fn is_driver(class: &str) -> bool {
    matches!(class, PE | ARM_IO)
}

/// The NUL-separated strings of a device tree property.
fn strings(v: &[u8]) -> impl Iterator<Item = &[u8]> {
    v.split(|&c| c == 0).filter(|s| !s.is_empty())
}

/// `IODTCompareNubName`: whether `name` is one of the entry's `name`,
/// `compatible`, `device_type` or `model` strings.
fn names(n: &Node, name: &str) -> bool {
    ["name", "compatible", "device_type", "model"].iter().any(|key| n.props.iter().any(|(k, v)| k == key && strings(v).any(|s| s == name.as_bytes())))
}

/// Whether `IODTFindMatchingEntries` passes the entry over: one with
/// `AAPL,ignore`, or whose `device_type` is "associated-service".
fn skipped(n: &Node) -> bool {
    n.props.iter().any(|(k, v)| k == "AAPL,ignore" || (k == "device_type" && v.as_slice() == b"associated-service\0"))
}

/// The child of `parent` in the device tree that `IODTFindMatchingEntries`
/// gives and whose names include `name`, less the names `excluded`.
fn child(t: &[Node], parent: u32, name: &str, excluded: &[&str]) -> Option<u32> {
    t[parent as usize].children.iter().copied().find(|&c| {
        let n = &t[c as usize];
        !skipped(n) && !excluded.contains(&n.name.as_str()) && names(n, name)
    })
}

/// A driver's properties from its personality and matching (see the
/// module's documentation): its bundle, class, provider class, the name it
/// matched, its category and score.
fn driver_props(bundle: &str, class: &str, provider: &str, matched: &str, category: &str, score: u64, mut personality: Vec<(String, Prop)>) -> Vec<(String, Prop)> {
    let sym = |s: &str| Prop::Sym(s.to_string());
    let mut p = vec![
        ("CFBundleIdentifier".to_string(), sym(bundle)),
        ("CFBundleIdentifierKernel".to_string(), sym(bundle)),
        ("IOClass".to_string(), sym(class)),
        ("IOProviderClass".to_string(), sym(provider)),
        ("IONameMatched".to_string(), Prop::Str(matched.to_string())),
        ("IOMatchedAtBoot".to_string(), Prop::Bool(true)),
        ("IOMatchCategory".to_string(), sym(category)),
        ("IOProbeScore".to_string(), Prop::Num(score, 32)),
    ];
    p.append(&mut personality);
    p
}

/// Publish the platform expert and arm-io's driver, and make arm-io the
/// nub it is; arm-io's driver's entry, when the device tree has arm-io.
/// `t[0]` is the device tree's root, the `IOPlatformExpertDevice`.
pub fn add(t: &mut Vec<Node>) -> Option<u32> {
    let root = t.first()?;
    if !names(root, "AppleARM") {
        return None;
    }
    let driver = |name: &str, class: &'static str, parent: u32, service_props| Node { name: name.to_string(), props: Vec::new(), class, service_props, parent: Some(parent), children: Vec::new(), kernel_only: false, nub: None };
    let pe = t.len() as u32;
    // The personality "AppleARMPE": IONameMatch "AppleARM", IOProbeScore
    // 1000 (a 64-bit number, which the probe's 32-bit score replaces).
    let props = driver_props("com.apple.driver.AppleARMPlatform", PE, "IOPlatformExpertDevice", "AppleARM", "IODefaultMatchCategory", 1000, vec![("IONameMatch".to_string(), Prop::Str("AppleARM".to_string()))]);
    t.push(driver(PE, PE, 0, props));
    let arm_io = child(t, 0, "arm-io,t8011", &["chosen", "memory", "options", "aliases"])?;
    t[arm_io as usize].nub = Some((PLATFORM_DEVICE, pe));
    let io = t.len() as u32;
    // The personality "AppleT8011IO": IONameMatch "arm-io,t8011",
    // IOPlatformActiveAction 80000.
    let props = driver_props("com.apple.driver.AppleT8011", ARM_IO, PLATFORM_DEVICE, "arm-io,t8011", "IODefaultMatchCategory", 0, vec![
        ("IONameMatch".to_string(), Prop::Str("arm-io,t8011".to_string())),
        ("IOPlatformActiveAction".to_string(), Prop::Num(80000, 64)),
    ]);
    t.push(driver(ARM_IO, ARM_IO, arm_io, props));
    Some(io)
}

/// The `AppleARMIODevice` nub arm-io's driver `io` publishes for its
/// device tree child whose names include `name`, when there is one.
pub fn arm_io_nub(t: &mut [Node], io: u32, name: &str) -> Option<u32> {
    let arm_io = t[io as usize].parent?;
    let nub = child(t, arm_io, name, &[])?;
    t[nub as usize].nub = Some((ARM_IO_DEVICE, io));
    Some(nub)
}
