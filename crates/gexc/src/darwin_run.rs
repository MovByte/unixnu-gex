//! `gexc run` on a Darwin (Mach-O) program, on the Darwin personality.
//!
//! A static program (no `LC_LOAD_DYLINKER`) is mapped as it is and started
//! at its `LC_UNIXTHREAD` pc. A dynamic one needs dyld and the shared cache
//! it maps, which this runner does not set up yet.

use crate::{choose_mem, report_exit, set_wasm_libs, RunArgs};
use anyhow::{bail, Context, Result};
use gex_ld::Program;
use std::process::ExitCode;

pub fn run(mut ra: RunArgs, bytes: &[u8]) -> Result<ExitCode> {
    let (m, exe) = gex_ld::macho::load(bytes, gex_ld::macho::PIE_BASE).with_context(|| format!("loading {}", ra.path))?;
    if let Some(dyld) = &m.dylinker {
        bail!("{} is a dynamic Darwin program (it names {dyld}); running one needs dyld and a shared cache", ra.path);
    }
    let program = Program { exe, interp: None, direct: None };
    let mut argv = vec![ra.argv0.clone().unwrap_or_else(|| ra.path.clone())];
    argv.append(&mut ra.guest_args);
    ra.opts.args = argv;
    if ra.opts.env.is_empty() {
        ra.opts.env = vec!["PATH=/usr/bin:/bin".into(), "HOME=/var/mobile".into()];
    }
    ra.opts.darwin = true;
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
