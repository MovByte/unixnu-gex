//! `gexc run` on a Darwin (Mach-O) program, on the Darwin personality.
//!
//! A static program (no `LC_LOAD_DYLINKER`) is mapped as it is and started
//! at its `LC_UNIXTHREAD` pc. A dynamic one starts in dyld, read from the
//! Darwin root (`--sysroot`), with the shared cache mapped where it was
//! linked: the root's cryptex copy, or `GEX_DARWIN_CACHE`.

use crate::{choose_mem, report_exit, set_wasm_libs, RunArgs};
use anyhow::{bail, Context, Result};
use gex_ld::Program;
use std::path::{Path, PathBuf};
use std::process::ExitCode;


/// dyld goes above the program, on a 16 MiB boundary.
fn dyld_base(exe: &gex_ld::Image) -> u64 {
    const ALIGN: u64 = 16 << 20;
    (exe.brk + ALIGN + ALIGN - 1) & !(ALIGN - 1)
}

pub fn run(mut ra: RunArgs, bytes: &[u8]) -> Result<ExitCode> {
    let (m, exe) = gex_ld::macho::load(bytes, gex_ld::macho::PIE_BASE).with_context(|| format!("loading {}", ra.path))?;
    let root = ra.opts.sysroot.clone();
    // The program's path as the guest sees it: inside the root when there
    // is one.
    let guest_path = match &root {
        Some(r) => Path::new(&ra.path).strip_prefix(r).map(|p| format!("/{}", p.display())).unwrap_or_else(|_| ra.path.clone()),
        None => ra.path.clone(),
    };
    let interp = match &m.dylinker {
        None => None,
        Some(dyld) => {
            let Some(root) = &root else {
                bail!("{} is a dynamic Darwin program (it names {dyld}); give the Darwin root with --sysroot", ra.path);
            };
            let host = root.join(dyld.trim_start_matches('/'));
            let dbytes = std::fs::read(&host).with_context(|| format!("reading {}", host.display()))?;
            let (dm, di) = gex_ld::macho::load(&dbytes, dyld_base(&exe)).with_context(|| format!("loading {}", host.display()))?;
            // dyld's image list, which the kernel names at exec.
            if let Some(s) = dm.section("__DATA_DIRTY", "__all_image_info").or_else(|| dm.section("__DATA", "__all_image_info")) {
                ra.opts.darwin_dyld_infos = s.addr.wrapping_add(di.bias);
            }
            let cache = match std::env::var_os("GEX_DARWIN_CACHE") {
                Some(p) => PathBuf::from(p),
                None => root.join(gex_kernel::darwin::CACHE_PATH.trim_start_matches('/')),
            };
            if !cache.exists() {
                bail!("no shared cache at {} (set GEX_DARWIN_CACHE)", cache.display());
            }
            ra.opts.darwin_cache = Some(cache);
            Some(di)
        }
    };
    let program = Program { exe, interp, direct: None };
    let mut argv = vec![ra.argv0.clone().unwrap_or_else(|| guest_path.clone())];
    argv.append(&mut ra.guest_args);
    ra.opts.args = argv;
    ra.opts.exe.get_or_insert(guest_path);
    if ra.opts.env.is_empty() {
        ra.opts.env = vec!["PATH=/usr/bin:/bin".into(), "HOME=/var/mobile".into()];
    }
    ra.opts.darwin = true;
    // Its commpage is folded below 4 GiB in everything translated for it,
    // which needs the addresses its code builds in registers seen as the
    // constants they are.
    gex_abi::set_commpage_fold(true);
    gex_ir::pass::set_forward_reg_consts(true);
    // dyld rebases and binds its data after its code is translated: no
    // load may be folded to what memory held at translation.
    gex_ir::pass::set_fold_through_memory(false);
    ra.opts.jit = ra.jit;
    // Darwin images live above 4 GiB: always a 64-bit memory.
    if ra.mem64 == Some(false) {
        bail!("--no-mem64: a Darwin program's images are above 4 GiB");
    }
    ra.mem64 = Some(true);
    choose_mem(&mut ra, bytes, true)?;
    set_wasm_libs()?;
    let (exit, _stats) = gex_native::run_program(&program, &ra.opts, &ra.xlate)?;
    Ok(report_exit(&exit, ra.opts.verbose))
}
