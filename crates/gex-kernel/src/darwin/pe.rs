//! What the platform expert keeps of the boot (`pexpert/arm/pe_init.c`,
//! `pexpert/gen/bootargs.c`): the boot-args iBoot passed, which
//! `kern.bootargs` reports and `PE_parse_boot_argn` reads, and the boot
//! video console (`PE_state.video`, `PE_current_console`).

/// `PE_boot_args()`: the boot-args of a production boot, which has none.
pub const BOOT_ARGS: &str = "";

// `PE_parse_boot_argn_internal` returns at once for empty boot-args; its
// parse of names and values (`getval`) is not ported, so boot-args with
// anything in them do not build until it is.
const _: () = assert!(BOOT_ARGS.is_empty(), "boot-args need PE_parse_boot_argn_internal's parse (getval)");

/// `PE_parse_boot_argn(name, ...)`: whether the boot-args give `name`, and
/// its numeric value. Empty boot-args give nothing.
pub fn parse_boot_argn(_name: &str) -> Option<i64> {
    None
}

/// `SERIALMODE_OUTPUT` (`osfmk/console/serial_protos.h`).
pub const SERIALMODE_OUTPUT: u32 = 0x01;

/// `serialmode` as `arm_init` sets it: the `serial` boot-arg, else 0.
/// (`kern_feature_override(KF_SERIAL_OVRD)` only clears it.)
pub fn serialmode() -> u32 {
    parse_boot_argn("serial").map_or(0, |v| v as u32)
}

/// The boot video console's size as `PE_current_console` copies it from
/// `PE_state.video`: iBoot's `boot_args->Video` (`PE_init_platform`), or
/// what a framebuffer driver gave `PE_initialize_console` with
/// `kPEEnableScreen` since. Neither is known here.
pub fn current_console() -> Result<(u32, u32), String> {
    Err("the boot video console's width and height (PE_state.video from iBoot's boot_args Video, or a framebuffer driver's kPEEnableScreen)".into())
}
