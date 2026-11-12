//! A Darwin (Mach-O) program's image as exec loads it: the executable at
//! its slide, dyld above it when it names one, and what the kernel takes
//! from them (the platform, the signature, `LC_MAIN`'s stack size, dyld's
//! image list). For `gexc run`'s first program and for an `execve` alike.

use anyhow::{bail, Context, Result};
use gex_ld::Program;

/// What loading found.
pub struct DarwinImage {
    pub program: Program,
    /// `LC_BUILD_VERSION`'s platform and SDK.
    pub platform: (u32, u32),
    /// `LC_CODE_SIGNATURE`'s blob.
    pub code_signature: Option<Vec<u8>>,
    /// `LC_MAIN`'s stack size (0: the default).
    pub stacksize: u64,
    /// `LC_LOAD_DYLINKER`'s path.
    pub dylinker: Option<String>,
    /// dyld's `dyld_all_image_infos` (its `__all_image_info`, slid): what
    /// the kernel records as the task's dyld info.
    pub dyld_infos: u64,
    /// Its size (`load_result.all_image_info_size`).
    pub dyld_infos_size: u64,
}

/// dyld goes above the program, on a 16 MiB boundary.
fn dyld_base(exe: &gex_ld::Image) -> u64 {
    const ALIGN: u64 = 16 << 20;
    (exe.brk + ALIGN + ALIGN - 1) & !(ALIGN - 1)
}

/// Load the Mach-O executable `bytes` (one slice), with its dyld read by
/// `read` (a guest path).
pub fn load(bytes: &[u8], name: &str, read: &dyn Fn(&str) -> Result<Vec<u8>>) -> Result<DarwinImage> {
    let (m, exe) = gex_ld::macho::load(bytes, gex_ld::macho::PIE_BASE).with_context(|| format!("loading {name}"))?;
    let code_signature = m.code_signature.and_then(|(o, n)| bytes.get(o as usize..(o as usize).checked_add(n as usize)?)).map(<[u8]>::to_vec);
    let stacksize = match &m.entry {
        Some(gex_ld::macho::Entry::Main { stacksize, .. }) => *stacksize,
        _ => 0,
    };
    let (mut dyld_infos, mut dyld_infos_size) = (0, 0);
    let interp = match &m.dylinker {
        None => None,
        Some(dyld) => {
            let dbytes = read(dyld).with_context(|| format!("{name} names {dyld}"))?;
            if !gex_ld::macho::is_macho(&dbytes) {
                bail!("{dyld} is not a Mach-O file");
            }
            let (dm, di) = gex_ld::macho::load(&dbytes, dyld_base(&exe)).with_context(|| format!("loading {dyld}"))?;
            if let Some(s) = dm.section("__DATA_DIRTY", "__all_image_info").or_else(|| dm.section("__DATA", "__all_image_info")) {
                dyld_infos = s.addr.wrapping_add(di.bias);
                dyld_infos_size = s.size;
            }
            Some(di)
        }
    };
    Ok(DarwinImage {
        program: Program { exe, interp, direct: None },
        platform: (m.platform.unwrap_or(0), m.sdk.unwrap_or(0)),
        code_signature,
        stacksize,
        dylinker: m.dylinker.clone(),
        dyld_infos,
        dyld_infos_size,
    })
}
