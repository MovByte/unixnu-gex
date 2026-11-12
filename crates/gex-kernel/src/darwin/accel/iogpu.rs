//! IOGPUFamily's user clients of the accelerator (IOGPUFamily 93.40.4 in
//! the 21H461 kernelcache): `IOGPUDeviceUserClient`, type 1, which
//! IOGPU.framework's `IOGPUDeviceCreate` opens, and
//! `IOGPUMemoryInfoUserClient`, type 33.
//!
//! The accelerator is an `IOGPU` with no IOGPU channels: Metal's work
//! reaches the host through the WebMetal connection, not IOGPU command
//! queues. So the device client answers what describes the device, and
//! what would make GPU objects for IOGPU's own submission path (resources,
//! command queues, shared memory, fences, events, IO queues) is reported.

use super::super::iokit::{dispatch_check, no_method, ret, Dispatch, MethodArgs, Prop, VARIABLE};
use super::super::ipc::ObjId;
use crate::syscalls::Kernel;

const V: u32 = VARIABLE;

/// `IOGPUDeviceUserClient::externalMethod`'s table (0xfffffff006d404d0):
/// each selector's scalar input count, structure input size, scalar
/// output count and structure output size.
const METHODS: [Dispatch; 50] = {
    const fn d(scalar_in: u32, struct_in: u32, scalar_out: u32, struct_out: u32) -> Dispatch {
        Dispatch { scalar_in, struct_in, scalar_out, struct_out }
    }
    [
        d(0, 0, 0, 64),
        d(0, 0, 0, 64),
        d(0, 0, 0, 536),
        d(0, 0, 0, 8),
        d(0, 0, 0, 32),
        d(0, 0, 0, 16),
        d(0, 16, 0, V),
        d(0, 1032, 0, 16),
        d(1, 0, 0, 0),
        d(0, V, 0, V),
        d(1, 0, 0, 0),
        d(2, 0, 0, 0),
        d(2, 0, 1, 0),
        d(2, 0, 0, 16),
        d(1, 0, 0, 0),
        d(2, 0, 0, 16),
        d(1, 0, 0, 0),
        d(0, 0, 0, 8),
        d(0, 0, 0, 4),
        d(1, 0, 0, 0),
        d(1, 0, 0, 24),
        d(1, 0, 0, 0),
        d(0, 0, 0, 48),
        d(0, 0, 0, V),
        d(0, 0, 1, 0),
        d(2, 0, 0, 0),
        d(4, V, 0, 0),
        d(1, 12, 1, 0),
        d(1, 4, 0, 0),
        d(0, 0, 2, 0),
        d(1, 0, 0, 0),
        d(2, 0, 0, 0),
        d(1, 0, 2, 0),
        d(2, 0, 0, 0),
        d(2, 0, 0, 0),
        d(1, 0, 1, 0),
        d(2, 0, 0, 0),
        d(3, 0, 1, 0),
        d(1, 0, 2, 0),
        d(1, 0, 0, 0),
        d(2, 0, 2, 0),
        d(1, 0, 0, 0),
        d(2, 0, 0, 0),
        d(1, V, 0, 0),
        d(1, 0, 2, 0),
        d(2, 0, 0, 0),
        d(2, 0, 0, 0),
        d(1, 0, 0, 0),
        d(1, 0, 0, 0),
        d(3, 0, 0, 0),
    ]
};

/// The selectors the restricted table (0xfffffff006d40980, used when the
/// client is restricted) answers with its refusal (0xfffffff005bbcd1c);
/// its counts are the same as the other table's.
const RESTRICTED: [u32; 22] = [22, 28, 29, 30, 31, 32, 33, 34, 35, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49];

/// The highest selector the tables have.
const LAST: u32 = 49;

/// The accelerator's stamp memory, what `deviceUserClientStart` asks the
/// IOGPU for (its virtual at vtable offset 1360, pure in IOGPU; AGXG9G's,
/// 0xfffffff005be5fe8, gives its own memory at offset 0): one page,
/// holding no stamp, the accelerator having no IOGPU channel, at offset 0.
const STAMP_MEMORY: u64 = 0x4000;

/// IOGPU.framework's names for what each selector does, for reports.
fn selector_name(s: u32) -> &'static str {
    match s {
        0 => "get config",
        1 => "get name",
        2 => "map stamps",
        3 => "get current trace filter",
        4 => "get trace object and task info",
        5 => "get next global trace ids",
        6 => "set API property",
        7 => "create command queue",
        8 => "destroy command queue",
        9 => "create resource",
        13 => "create device shared memory",
        14 => "destroy device shared memory",
        15 => "create notification queue",
        16 => "destroy notification queue",
        18 => "create fence",
        19 => "destroy fence",
        20 => "create event",
        21 => "destroy event",
        22 => "get memory data",
        24 => "get allocated size",
        25 => "create command queue with QoS",
        26 => "submit command buffers",
        27 => "set command queue priority and background",
        28 => "set command queue QoS",
        29 => "create late-eval event",
        30 => "destroy late-eval event",
        31 => "set late-eval event value",
        32 => "get late-eval event value",
        33 => "set display parameters",
        34 => "set app GPU role",
        35 => "get app GPU role",
        36 => "set resource owner identity",
        37 => "create resource from IOSurface",
        38 => "create VNIO descriptor",
        39 => "destroy VNIO descriptor",
        40 => "create IO command queue",
        41 => "destroy IO command queue",
        42 => "set IO command queue",
        43 => "submit IO commands",
        44 => "create IO command buffer",
        45 => "destroy IO command buffer",
        46 => "try cancel IO command buffer",
        47 => "perform IO",
        48 => "IO command buffer complete",
        49 => "IO command buffer barrier complete",
        _ => "an IOGPU method",
    }
}

/// The A10X accelerator's IOGPU configuration, which the accelerator
/// presents as `AGXAcceleratorG9G_A0` does: what IOGPU's defaults
/// (0xfffffff005bd3cd4) become once AGXG9G's start has set them
/// (0xfffffff005be636c, 0xfffffff005c2569c), at their offsets in the IOGPU.
mod config {
    /// +488: the name the configuration points at (0xfffffff005c256b8:
    /// "AGXG9G_A0").
    pub const NAME: &str = "AGXG9G_A0";
    /// +496 (0xfffffff005be6548, the constant at 0xfffffff00531a9c0) and
    /// +504 (0xfffffff005be654c).
    pub const CONFIG_BITS: u32 = 0x0040_4340;
    pub const DEVICE_BITS: u32 = 0;
    /// +520: what AGXG9G's texture memory query (0xfffffff005c281ac) and
    /// selector 0's video memory both read (0xfffffff005be6558).
    pub const VIDEO_RAM: u64 = 0;
    /// +556, +560, +564 (0xfffffff005be6560, 0xfffffff005be6564).
    pub const STAMP_INFO: [u32; 3] = [8, 8, 0];
    /// +600, +608, +610: no store sets them; the object is zero-filled.
    pub const FIELD_600: u64 = 0;
    pub const FIELD_608: u16 = 0;
    pub const FIELD_610: u16 = 0;
    /// The IOSurface accelerator id IOSurfaceRoot handed the accelerator
    /// (0xfffffff005baaef8 at IOGPU::start, 0xfffffff005bd4330): the
    /// accelerator registers first, before the scaler (AppleM2ScalerCSCDriver)
    /// that is the root's other registrant.
    pub const ACCEL_ID: u32 = 1;
}

/// The memory the configuration's sizes derive from: `hw.memsize_physical`,
/// which IOGPU::start reads (0xfffffff005bd4494) into +696.
const MEMSIZE: u64 = super::super::mig::machine::MEMORY;
const PAGE: u64 = super::super::mig::machine::PAGE_SIZE as u64;

/// +272, the shared (wired) memory limit: AGXG9G's 0xfffffff005be6774,
/// `roundup_page(fcvtzu((100 - reserve) * (float)memsize / 100))`, the
/// percentage reserved being the GPU nub's `gpu-sysmem-reserve-percent`
/// (a float) or 33.333332 (0x42055555) without one, as the J120 device
/// tree is.
fn shared_memory_size() -> u64 {
    let reserve = super::super::iokit::tree().iter().find(|n| n.props.iter().any(|(k, v)| k == "compatible" && v.split(|&c| c == 0).any(|c| c == b"gpu,t8011"))).and_then(|n| n.props.iter().find(|(k, _)| k == "gpu-sysmem-reserve-percent")).and_then(|(_, v)| v.get(..4)).map_or(f32::from_bits(0x4205_5555), |b| f32::from_le_bytes(b.try_into().unwrap()));
    let size = ((100.0f32 - reserve) * MEMSIZE as f32 / 100.0f32) as u64;
    (size + PAGE - 1) & !(PAGE - 1)
}

/// `IOGPU::getSharedMemorySize(0)` (0xfffffff005bd60fc): the
/// `iogpu.wired_limit_mb` sysctl's limit when one is set (0 here: nothing
/// sets it), else +272.
fn wired_limit() -> u64 {
    shared_memory_size()
}

/// The largest resource for a client (AGXG9G's 0xfffffff005be7eb4 over
/// IOGPU's 0xfffffff005bd6130): `max(round_down(memsize / 4, page),
/// 256 MiB)`, clamped by the client's GART flags, which are its open
/// options (0xfffffff005c29abc): bit 0 to 4 GiB less one page, bit 1 to
/// 0xffffffff, or 0x3fffffffc with bit 2.
fn max_resource_size(options: u32) -> u64 {
    let base = ((MEMSIZE >> 2) & !(PAGE - 1)).max(0x1000_0000);
    if options & 1 != 0 {
        return base.min((1u64 << 32) - PAGE);
    }
    if options & 2 != 0 {
        return base.min(if options & 4 != 0 { 0x3_ffff_fffc } else { 0xffff_ffff });
    }
    base
}

/// IOGPUFamily's object id counter (0xfffffff007aeb148, 1 in the image):
/// each device and each device client takes the next id
/// (0xfffffff005bcf01c, 0xfffffff005bbcefc), and selector 5 takes ranges.
static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// The restricted entitlements (0xfffffff005bcf814, through
/// 0xfffffff005bcf080): a key that is missing does not restrict, a boolean
/// is its value, any other value restricts.
fn restricted(k: &Kernel) -> bool {
    use super::super::codesign::Ent;
    let Some(c) = k.dtask.codesign.as_ref() else { return false };
    ["com.apple.private.gpu-restricted", "com.apple.developer.gpu-restricted"].iter().any(|key| match c.ents.get(key.as_bytes()) {
        None => false,
        Some(Ent::Bool(b)) => *b,
        Some(_) => true,
    })
}

/// An `IOGPUDeviceUserClient`: the task that opened it, its options (the
/// open type's high 16 bits), whether it is restricted (+259), whether its
/// start succeeded and it is not stopped (+256), the read-only mapping of
/// the accelerator's stamps in its task, and the `API` property selector 6
/// set.
pub struct Device {
    owner: i32,
    options: u32,
    restricted: bool,
    ready: bool,
    stamps: u64,
    api: Option<String>,
}

impl Device {
    /// `IOGPU::newUserClient` for type 1: an `IOGPUDeviceUserClient` (what
    /// IOGPU's own 0xfffffff005bd595c makes), its `init` (`initWithTask`
    /// and the task kept), `attach` and `start`, whose
    /// `deviceUserClientStart` (0xfffffff005bbce5c) maps the accelerator's
    /// stamp memory read-only into the task (`createMappingInTask` with
    /// kIOMapAnywhere | kIOMapReadOnly | kIOMapUnique), makes the client's
    /// IOGPUDevice (which takes an id), takes the client's trace id, and
    /// checks the restricted entitlements. A start that fails is detached:
    /// kIOReturnInternalError.
    pub fn open(k: &mut Kernel, _service: u32, options: u32) -> Result<Device, i32> {
        const K_IO_RETURN_INTERNAL_ERROR: i32 = 0xe00002c9_u32 as i32;
        let stamps = match k.darwin_own_memory(|k, m| k.darwin_iokit_map(m, STAMP_MEMORY, super::super::mach::prot::READ)) {
            Ok(Ok(addr)) => addr,
            _ => return Err(K_IO_RETURN_INTERNAL_ERROR),
        };
        use std::sync::atomic::Ordering::Relaxed;
        // The device's id, then the client's trace id (+232), which
        // selector 4 gives with IOSurfaceRoot's trace page.
        NEXT_ID.fetch_add(1, Relaxed);
        NEXT_ID.fetch_add(1, Relaxed);
        Ok(Device { owner: k.pid, options, restricted: restricted(k), ready: true, stamps, api: None })
    }

    /// `IOGPUDeviceUserClient::clientClose` (0xfffffff005bbd0f0): the
    /// client's IOGPUDevice closed and the client terminated, whose `stop`
    /// (0xfffffff005bbd08c) runs `deviceUserClientStop` (0xfffffff005bbd01c):
    /// `AppUsage` removed, the stamp mapping released (unmapped from the
    /// task) and the client no longer ready. kIOReturnSuccess.
    pub fn close(&mut self, k: &mut Kernel) {
        self.stop(k);
    }

    /// The client freed without a close: stopped as its termination stops it.
    pub fn free(&mut self, k: &mut Kernel) {
        self.stop(k);
    }

    fn stop(&mut self, k: &mut Kernel) {
        if !self.ready {
            return;
        }
        self.ready = false;
        if k.pid == self.owner {
            let addr = self.stamps;
            let _ = k.darwin_own_memory(|k, m| k.darwin_vm_deallocate(m, addr, STAMP_MEMORY));
        } else if k.procs.vm(self.owner).is_ok() {
            k.darwin_unimplemented(format!("unmapping a device client's stamp memory from pid {} for pid {}", self.owner, k.pid));
        }
    }

    /// Its properties: `AppUsage` (an `OSSerializer` of its device's use,
    /// 0xfffffff005bd0c84) while started, and `API` once selector 6 set it.
    pub fn property(&self, name: &str) -> Result<Option<Prop>, String> {
        match name {
            "AppUsage" if self.ready => Err("an IOGPU device client's AppUsage (its device's usage serialized)".to_string()),
            "API" => Ok(self.api.clone().map(Prop::Sym)),
            _ => Ok(None),
        }
    }

    /// `IOGPUDeviceUserClient::registerNotificationPort` (0xfffffff005bbd200):
    /// type 0 only (else kIOReturnUnsupported), for a notification queue of
    /// the client's device by its id (else kIOReturnBadArgument), which the
    /// accelerator's clients make none of.
    pub fn register_notification_port(&mut self, _k: &mut Kernel, _port: Option<ObjId>, ty: u32, _reference: u64) -> i32 {
        if ty != 0 {
            return ret::UNSUPPORTED;
        }
        ret::BAD_ARGUMENT
    }

    /// `IOGPUDeviceUserClient::externalMethod` (0xfffffff005bbd138): a
    /// client not started (or stopped) is kIOReturnNotReady; a selector past
    /// the table goes to IOUserClient's, which has none for it; an
    /// asynchronous call is kIOReturnBadArgument; then the table's checks,
    /// and a restricted client's refused selectors (0xfffffff005bbcd1c:
    /// kIOReturnNotPermitted).
    pub fn external_method(&mut self, k: &mut Kernel, a: &mut MethodArgs) -> i32 {
        if !self.ready {
            return ret::NOT_READY;
        }
        if a.selector > LAST {
            return no_method(a);
        }
        if a.is_async {
            return ret::BAD_ARGUMENT;
        }
        if let Err(e) = dispatch_check(&METHODS[a.selector as usize], a) {
            return e;
        }
        if self.restricted && RESTRICTED.contains(&a.selector) {
            return ret::NOT_PERMITTED;
        }
        let out = &mut a.struct_out;
        let put = |out: &mut Vec<u8>, at: usize, v: &[u8]| out[at..at + v.len()].copy_from_slice(v);
        match a.selector {
            // The configuration (0xfffffff005bbb490).
            0 => {
                let bits = (config::CONFIG_BITS & 0xffff) | ((config::CONFIG_BITS >> 9) & 0x1000);
                put(out, 0, &bits.to_le_bytes());
                put(out, 4, &config::DEVICE_BITS.to_le_bytes());
                put(out, 8, &config::VIDEO_RAM.to_le_bytes());
                put(out, 16, &config::VIDEO_RAM.to_le_bytes());
                put(out, 24, &config::ACCEL_ID.to_le_bytes());
                put(out, 32, &wired_limit().to_le_bytes());
                put(out, 40, &max_resource_size(self.options).to_le_bytes());
                put(out, 48, &config::FIELD_600.to_le_bytes());
                put(out, 56, &u32::from(config::FIELD_608).to_le_bytes());
                put(out, 60, &u32::from(config::FIELD_610).to_le_bytes());
                ret::SUCCESS
            }
            // The name, strlcpy'd into 64 bytes (0xfffffff005bbb544).
            1 => {
                put(out, 0, config::NAME.as_bytes());
                ret::SUCCESS
            }
            // The stamps (0xfffffff005bbb570): their mapping's address plus
            // the offset, +556..+567, and the count of stamps and each one's
            // offset; the accelerator has no IOGPU channel and so no stamp.
            2 => {
                put(out, 0, &self.stamps.to_le_bytes());
                put(out, 8, &config::STAMP_INFO[0].to_le_bytes());
                put(out, 12, &config::STAMP_INFO[1].to_le_bytes());
                put(out, 16, &config::STAMP_INFO[2].to_le_bytes());
                put(out, 20, &0u32.to_le_bytes());
                ret::SUCCESS
            }
            // The trace filter (0xfffffff005bbb618) and the trace object id
            // with the task's view of the trace page (0xfffffff005bbb644)
            // read IOSurfaceRoot's shared page (IOGPU::start's
            // 0xfffffff005bd4b64), which is IOSurface's.
            3 | 4 => {
                k.darwin_unimplemented(format!("IOGPUDeviceUserClient selector {} ({}): IOSurfaceRoot's shared trace page", a.selector, selector_name(a.selector)));
                ret::UNSUPPORTED
            }
            // A range of 0x1000000 ids (0xfffffff005bbb6f8).
            5 => {
                use std::sync::atomic::Ordering::Relaxed;
                let first = NEXT_ID.fetch_add(0x100_0000, Relaxed);
                put(out, 0, &first.to_le_bytes());
                put(out, 8, &(first + 0x100_0000).to_le_bytes());
                ret::SUCCESS
            }
            // The client's `API` property (0xfffffff005bbb754): the input
            // strlcpy'd into 17 bytes and set as an OSSymbol; the method
            // answers setProperty's bool, 1.
            6 => {
                let n = a.struct_in.iter().position(|&c| c == 0).unwrap_or(16);
                self.api = Some(String::from_utf8_lossy(&a.struct_in[..n]).into_owned());
                1
            }
            // The memory the device's namespaces hold (0xfffffff005bbbcec):
            // the client has made no resource, so all zero.
            22 => ret::SUCCESS,
            // 0xfffffff005bbbcf8.
            23 => ret::UNSUPPORTED,
            // The device's allocated size (0xfffffff005bd0110), its shared
            // slot 0's count: nothing allocated.
            24 => {
                a.scalar_out[0] = 0;
                ret::SUCCESS
            }
            // Display parameters: IOGPUDeviceUserClient's (0xfffffff005bbd270).
            33 => ret::UNSUPPORTED,
            // The app GPU role, set and got: the device's (IOGPUDevice's
            // 0xfffffff005bd0e4c and 0xfffffff005bd0e58), which keep none.
            34 | 35 => ret::UNSUPPORTED,
            s => {
                k.darwin_unimplemented(format!("IOGPUDeviceUserClient selector {s} ({}): IOGPU objects of the accelerator", selector_name(s)));
                ret::UNSUPPORTED
            }
        }
    }

    /// `getTargetAndTrapForIndex` (0xfffffff005bbd1b0): traps 0 to 3, which
    /// submit command buffers and finalize and purge resources the client
    /// has none of; none past them (a trap with none answers success).
    pub fn trap(&mut self, k: &mut Kernel, index: u32, _p: [u64; 4]) -> i32 {
        if index > 3 {
            return ret::SUCCESS;
        }
        k.darwin_unimplemented(format!("IOGPUDeviceUserClient trap {index}"));
        ret::UNSUPPORTED
    }
}

/// `IOGPUMemoryInfoUserClient::externalMethod` (0xfffffff005bdbf10): three
/// selectors (table 0xfffffff006d45058), kIOReturnBadArgument past them.
pub fn memory_info_method(k: &mut Kernel, a: &mut MethodArgs) -> i32 {
    const TABLE: [Dispatch; 3] = [
        Dispatch { scalar_in: 0, struct_in: 0, scalar_out: 1, struct_out: VARIABLE },
        Dispatch { scalar_in: 0, struct_in: VARIABLE, scalar_out: 0, struct_out: 112 },
        Dispatch { scalar_in: 0, struct_in: 0, scalar_out: 0, struct_out: 0 },
    ];
    let Some(d) = TABLE.get(a.selector as usize) else { return ret::BAD_ARGUMENT };
    if let Err(e) = dispatch_check(d, a) {
        return e;
    }
    k.darwin_unimplemented(format!("IOGPUMemoryInfoUserClient selector {} (the accelerator's IOGPU allocations)", a.selector));
    ret::UNSUPPORTED
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_follow_the_a10x_formulas() {
        // 4 GiB, no reserve property: two thirds wired, rounded to a page.
        assert_eq!(shared_memory_size(), 0xaaaa_c000);
        assert_eq!(max_resource_size(0), 0x4000_0000);
        assert_eq!(max_resource_size(1), 0x4000_0000);
        assert_eq!(max_resource_size(6), 0x4000_0000);
    }

    #[test]
    fn the_method_tables_check_every_count() {
        let mut a = MethodArgs { selector: 0, struct_out: vec![0; 64], ..Default::default() };
        assert_eq!(dispatch_check(&METHODS[0], &a), Ok(()));
        a.struct_out.pop();
        assert_eq!(dispatch_check(&METHODS[0], &a), Err(ret::BAD_ARGUMENT));
        // Selector 9: both structures any size, no scalars.
        let b = MethodArgs { selector: 9, struct_in: vec![1; 3], ool_out: Some((0x1000, 0x2000)), ..Default::default() };
        assert_eq!(dispatch_check(&METHODS[9], &b), Ok(()));
        let c = MethodArgs { selector: 9, scalar_in: vec![1], ..Default::default() };
        assert_eq!(dispatch_check(&METHODS[9], &c), Err(ret::BAD_ARGUMENT));
    }
}
