//! AppleMobileFileIntegrity's MAC policy (`com.apple.driver.
//! AppleMobileFileIntegrity`, iOS 17.7.11): what it decides about a code
//! signature when it is added to a vnode, the code signing flags it gives
//! an exec, and its checks on task ports, JIT memory, executable mappings
//! and the dyld policy.
//!
//! Platform code is code whose cdhash is in a trust cache; anything else
//! must pass CoreTrust (a CMS signature) and amfid. Entitlements are the
//! DER blob's. Library validation is always on (`cs_require_lv` is the
//! constant 1 in this kernel).

use super::codesign::{CodeSign, Ent, Entitlements};

/// `cs_blobs.h`.
pub mod cs {
    pub const VALID: u32 = 0x1;
    pub const ADHOC: u32 = 0x2;
    pub const GET_TASK_ALLOW: u32 = 0x4;
    pub const INSTALLER: u32 = 0x8;
    pub const FORCED_LV: u32 = 0x10;
    pub const HARD: u32 = 0x100;
    pub const KILL: u32 = 0x200;
    pub const CHECK_EXPIRATION: u32 = 0x400;
    pub const RESTRICT: u32 = 0x800;
    pub const ENFORCEMENT: u32 = 0x1000;
    pub const REQUIRE_LV: u32 = 0x2000;
    pub const ENTITLEMENTS_VALIDATED: u32 = 0x4000;
    pub const NVRAM_UNRESTRICTED: u32 = 0x8000;
    pub const RUNTIME: u32 = 0x1_0000;
    pub const LINKER_SIGNED: u32 = 0x2_0000;
    pub const ALLOWED_MACHO: u32 = ADHOC | HARD | KILL | CHECK_EXPIRATION | RESTRICT | ENFORCEMENT | REQUIRE_LV | RUNTIME | LINKER_SIGNED;
    pub const EXEC_SET_HARD: u32 = 0x10_0000;
    pub const EXEC_SET_KILL: u32 = 0x20_0000;
    pub const EXEC_SET_ENFORCEMENT: u32 = 0x40_0000;
    pub const EXEC_INHERIT_SIP: u32 = 0x80_0000;
    pub const KILLED: u32 = 0x100_0000;
    pub const NO_UNTRUSTED_HELPERS: u32 = 0x200_0000;
    pub const PLATFORM_BINARY: u32 = 0x400_0000;
    pub const PLATFORM_PATH: u32 = 0x800_0000;
    pub const DEBUGGED: u32 = 0x1000_0000;
    pub const SIGNED: u32 = 0x2000_0000;
    pub const DEV_CODE: u32 = 0x4000_0000;
    pub const DATAVAULT_CONTROLLER: u32 = 0x8000_0000;
    pub const ENTITLEMENT_FLAGS: u32 = GET_TASK_ALLOW | INSTALLER | DATAVAULT_CONTROLLER | NVRAM_UNRESTRICTED;
    pub const EXECSEG_MAIN_BINARY: u64 = 0x1;
}

/// `CS_VALIDATION_CATEGORY_*`.
pub mod category {
    pub const INVALID: u32 = 0;
    pub const PLATFORM: u32 = 1;
    pub const NONE: u32 = 10;
}

/// Developer Mode (`developer_mode_state`): off, as on a device that has
/// not enabled it.
pub const DEVELOPER_MODE: bool = false;

/// What AMFI made of a signature: its flags (`csb_flags`), whether it is a
/// platform binary, its validation category and its entitlements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub flags: u32,
    pub platform_binary: bool,
    pub category: u32,
    pub ents: Entitlements,
}

/// Why AMFI refused a signature: a fatal failure's description (the exec's
/// crash reason), a plain refusal, or a path this port does not take yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    Fatal(String),
    Refused(String),
    Unported(String),
}

/// The entitlements a binary may not hold without Developer Mode.
const RESTRICTED: [&[u8]; 6] = [b"get-task-allow", b"task_for_pid-allow", b"com.apple.system-task-ports", b"com.apple.system-task-ports.control", b"com.apple.system-task-ports.token.control", b"com.apple.private.cs.debugger"];

/// `0x...ab81e8`: the entitlements AMFI validates a signature with. The DER
/// blob's: XML alone is refused, and a binary that is not a main binary
/// (a CodeDirectory that has the execution segment fields, without
/// CS_EXECSEG_MAIN_BINARY) has none.
fn load_entitlements(c: &CodeSign) -> Result<Entitlements, String> {
    if c.xml.is_none() && c.der.is_none() {
        return Ok(Entitlements::default());
    }
    if c.cd_version >= 0x20400 && c.exec_seg_flags & cs::EXECSEG_MAIN_BINARY == 0 {
        return Ok(Entitlements::default());
    }
    let Some(der) = &c.der else {
        return Err("entitlement validation failed, binary has XML entitlements but no DER slot is present.".into());
    };
    let body = &der[8..];
    if body.is_empty() {
        return Err("entitlements too small".into());
    }
    if body.len() > 0x20000 {
        return Err("entitlements too large".into());
    }
    super::codesign::parse_der_entitlements(body).ok_or_else(|| "failed parsing DER entitlements".into())
}

/// `mpo_vnode_check_signature` (`0x...b584c`): `flags` is the blob's,
/// `(cd.flags & CS_ALLOWED_MACHO) | CS_VALID`.
pub fn vnode_check_signature(c: &CodeSign, flags: u32) -> Result<Verdict, Refusal> {
    let fatal = |m: String| Refusal::Fatal(m);
    let ents = load_entitlements(c).map_err(|e| fatal(format!("The signature could not be validated because AMFI could not load its entitlements for validation: {e}")))?;
    let mut flags = flags;
    let (mut loader, mut runner) = (false, false);
    for (key, value) in &ents.0 {
        flags |= cs::KILL;
        let truth = *value == Ent::Bool(true);
        if key == b"get-task-allow" && truth {
            if DEVELOPER_MODE {
                flags |= cs::GET_TASK_ALLOW;
            } else {
                return Err(fatal(format!("Developer mode is disabled, {} is disallowed", String::from_utf8_lossy(key))));
            }
        }
        if !DEVELOPER_MODE && truth && RESTRICTED.contains(&key.as_slice()) {
            return Err(fatal(format!("Developer mode is disabled, {} is disallowed", String::from_utf8_lossy(key))));
        }
        if key == b"com.apple.private.oop-jit.loader" {
            if !matches!(value, Ent::String(_)) {
                return Err(fatal("OOP-JIT loader entitlement is an incorrect type".into()));
            }
            loader = true;
        }
        if key == b"com.apple.private.oop-jit.runner" {
            if !matches!(value, Ent::Array(_) | Ent::String(_)) {
                return Err(fatal("OOP-JIT runner entitlement is an incorrect type".into()));
            }
            runner = true;
        }
    }
    if loader && runner {
        return Err(fatal("Cannot be both OOP-JIT loader and runner simultaneously".into()));
    }
    let Some(cdhash) = c.cdhash else { return Err(fatal("Internal Error: No cdhash found.".into())) };
    // A trust cache's: platform code.
    let category = if super::trustcache::platform(&cdhash).is_some() {
        flags |= cs::PLATFORM_BINARY;
        // The best CodeDirectory of platform code hashes with SHA-256.
        if c.hash_type != 2 {
            return Err(fatal(format!("in-kernel: Hash type is not SHA256 (2) but {}.", c.hash_type)));
        }
        category::PLATFORM
    } else {
        // The compilation service's cdhashes: none are registered. Then
        // the CMS signature: an empty one is an ad-hoc signature, which
        // without a trust cache is unsuitable (OOP-JIT code aside).
        match c.cms {
            None => return Err(Refusal::Refused("no CMS blob".into())),
            Some(n) if n < 8 => return Err(Refusal::Refused("CMS blob too small".into())),
            Some(8) if flags & cs::ADHOC == 0 => return Err(Refusal::Refused("has zero length cms, but is not adhoc?".into())),
            Some(8) => {
                if c.cd_version >= 0x20600 {
                    return Err(Refusal::Unported("AMFI: an ad-hoc signature that may be OOP-JIT code".into()));
                }
                return Err(Refusal::Refused("unsuitable CT policy for an ad-hoc signature, rejecting signature".into()));
            }
            Some(_) => return Err(Refusal::Unported("AMFI: a CMS signature (CoreTrust and amfid)".into())),
        }
    };
    if ents.present(b"com.apple.developer.cs.allow-jit") && !ents.present(b"com.apple.developer.web-browser-engine.webcontent") {
        return Err(fatal("com.apple.developer.cs.allow-jit disallowed without com.apple.developer.web-browser-engine.webcontent".into()));
    }
    if ents.present(b"dynamic-codesigning") && category != category::PLATFORM {
        return Err(fatal("dynamic-codesigning disallowed on non-platform process".into()));
    }
    flags |= cs::SIGNED;
    Ok(Verdict { flags, platform_binary: flags & cs::PLATFORM_BINARY != 0, category, ents })
}

/// `mpo_vnode_check_exec`: an exec's flags gain CS_HARD and CS_KILL.
pub fn vnode_check_exec(csflags: &mut u32) {
    *csflags |= cs::HARD | cs::KILL;
}

/// `mpo_cred_label_update_execve` (`0x...b4004`): the new image's flags and
/// the entitlements its credential carries; an error kills the exec.
/// `sig` is the image's signature as added, none for unsigned code.
pub fn cred_label_update_execve(sig: Option<&CodeSign>, csflags: &mut u32) -> Result<Entitlements, String> {
    // cs_system_require_lv(): library validation, and with it a dyld that
    // is platform code.
    if *csflags & cs::NO_UNTRUSTED_HELPERS == 0 {
        return Err("dyld signature cannot be verified. You've probably got a dyld from somewhere other than your system.".into());
    }
    *csflags |= cs::REQUIRE_LV | cs::KILL;
    if *csflags & (cs::DATAVAULT_CONTROLLER | cs::NVRAM_UNRESTRICTED | cs::INSTALLER) != 0 {
        *csflags |= cs::EXEC_INHERIT_SIP | cs::REQUIRE_LV | cs::RESTRICT | cs::KILL;
    }
    let Some(sig) = sig else { return Err("no code signature".into()) };
    if *csflags & cs::VALID == 0 {
        return Ok(Entitlements::default());
    }
    let ents = sig.ents.clone();
    let any = |a: &[u8], b: &[u8]| ents.bool_true(a) || ents.bool_true(b);
    if any(b"com.apple.private.security.install", b"com.apple.rootless.install") {
        *csflags |= cs::INSTALLER;
    }
    if any(b"com.apple.private.security.install.heritable", b"com.apple.rootless.install.heritable") {
        *csflags |= cs::INSTALLER | cs::EXEC_INHERIT_SIP;
    }
    if any(b"com.apple.private.security.datavault.controller", b"com.apple.rootless.datavault.controller") {
        *csflags |= cs::DATAVAULT_CONTROLLER;
    }
    if any(b"com.apple.private.security.restricted-nvram-variables.heritable", b"com.apple.rootless.restricted-nvram-variables.heritable") {
        *csflags |= cs::NVRAM_UNRESTRICTED | cs::EXEC_INHERIT_SIP;
    }
    if *csflags & (cs::DATAVAULT_CONTROLLER | cs::NVRAM_UNRESTRICTED | cs::INSTALLER) != 0 {
        *csflags |= cs::REQUIRE_LV | cs::RESTRICT | cs::KILL;
    }
    Ok(ents)
}

/// `amfi_copy_seatbelt_profile_names` (`0x...ab5264`): the names the
/// `seatbelt-profiles` entitlement lists (an array of strings; none for any
/// other value; an error for an element that is not a string), and whether
/// the code is trusted to run outside a container: platform code (its
/// label's byte 74), or code entitled `platform-application`.
pub fn seatbelt_profile_names(platform_binary: bool, ents: &Entitlements) -> (Result<Vec<Vec<u8>>, ()>, bool) {
    let names = match ents.get(b"seatbelt-profiles") {
        Some(Ent::Array(a)) => a
            .iter()
            .map(|e| match e {
                Ent::String(s) => Ok(s.clone()),
                _ => Err(()),
            })
            .collect(),
        _ => Ok(Vec::new()),
    };
    (names, platform_binary || ents.bool_true(b"platform-application"))
}

/// `mpo_proc_check_map_anon` (`0x...b7d30`) for a `MAP_JIT` mapping: a
/// platform binary with `dynamic-codesigning`, or a browser's web content
/// allowed to JIT; else EPERM.
pub fn map_anon_jit(platform_binary: bool, ents: &Entitlements) -> Result<(), u32> {
    if (platform_binary && ents.bool_true(b"dynamic-codesigning")) || (ents.bool_true(b"com.apple.developer.web-browser-engine.webcontent") && ents.bool_true(b"com.apple.developer.cs.allow-jit")) {
        Ok(())
    } else {
        Err(1)
    }
}

/// `mpo_proc_check_mprotect`: EPERM for VM_PROT_TRUSTED.
pub fn mprotect(prot: u32) -> Result<(), u32> {
    if prot & 0x20 != 0 { Err(1) } else { Ok(()) }
}

/// The flavor of task port asked for (`mach_task_flavor_t`).
pub mod flavor {
    pub const CONTROL: u32 = 0;
    pub const READ: u32 = 1;
    pub const INSPECT: u32 = 2;
    pub const NAME: u32 = 3;
}

/// `mpo_proc_check_get_task_with_flavor` (`0x...b7ec0`): the caller's
/// entitlements, the target's (`get-task-allow`), the flavor. EPERM to
/// refuse.
pub fn get_task_with_flavor(caller: &Entitlements, target: &Entitlements, f: u32) -> Result<(), u32> {
    if f == flavor::NAME {
        return Ok(());
    }
    if DEVELOPER_MODE && target.bool_true(b"get-task-allow") {
        return Ok(());
    }
    let inspect = caller.bool_true(b"com.apple.system-task-ports.inspect");
    let read = caller.bool_true(b"com.apple.system-task-ports.read");
    if f >= flavor::INSPECT && inspect {
        return Ok(());
    }
    if f != flavor::CONTROL && !inspect && read {
        return Ok(());
    }
    if inspect || read {
        return Err(1);
    }
    let control = caller.bool_true(b"task_for_pid-allow") || caller.bool_true(b"com.apple.system-task-ports.control");
    if DEVELOPER_MODE && control { Ok(()) } else { Err(1) }
}

/// `mpo_proc_check_get_movable_control_port`: entitled, or Developer Mode
/// with CS_GET_TASK_ALLOW.
pub fn get_movable_control_port(ents: &Entitlements, csflags: u32) -> Result<(), u32> {
    if ents.bool_true(b"com.apple.security.get-movable-control-port") || (DEVELOPER_MODE && csflags & cs::GET_TASK_ALLOW != 0) {
        Ok(())
    } else {
        Err(1)
    }
}

/// `AMFI_DYLD_OUTPUT_*`.
pub mod dyld {
    pub const ALLOW_AT_PATH: u64 = 0x1;
    pub const ALLOW_PATH_VARS: u64 = 0x2;
    pub const ALLOW_CUSTOM_SHARED_CACHE: u64 = 0x4;
    pub const ALLOW_FALLBACK_PATHS: u64 = 0x8;
    pub const ALLOW_PRINT_VARS: u64 = 0x10;
    pub const ALLOW_FAILED_LIBRARY_INSERTION: u64 = 0x20;
    pub const ALLOW_LIBRARY_INTERPOSING: u64 = 0x40;
    pub const ALLOW_EMBEDDED_VARS: u64 = 0x80;
}

/// The dyld policy (`0x...ab8588`) of a process: what dyld may honor of its
/// environment.
pub fn dyld_policy(setugid: bool, csflags: u32, ents: &Entitlements) -> u64 {
    use dyld::*;
    let base = ALLOW_AT_PATH | ALLOW_FALLBACK_PATHS | ALLOW_LIBRARY_INTERPOSING;
    let dev = DEVELOPER_MODE && csflags & cs::GET_TASK_ALLOW != 0;
    let mut p = if setugid {
        base
    } else if dev {
        base | ALLOW_PATH_VARS | ALLOW_CUSTOM_SHARED_CACHE | ALLOW_PRINT_VARS
    } else if ents.bool_true(b"com.apple.developer.swift-playgrounds-app.development-build") {
        base | ALLOW_PATH_VARS | ALLOW_PRINT_VARS
    } else {
        base
    };
    if dev {
        p |= 0x100;
    }
    // cs_require_lv() is 1 in this kernel.
    p | ALLOW_FAILED_LIBRARY_INSERTION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_dyld_policy_of_a_release_process() {
        let none = Entitlements::default();
        assert_eq!(dyld_policy(false, cs::VALID, &none), 0x69);
        assert_eq!(dyld_policy(true, cs::VALID, &none), 0x69);
        let pg = Entitlements(vec![(b"com.apple.developer.swift-playgrounds-app.development-build".to_vec(), Ent::Bool(true))]);
        assert_eq!(dyld_policy(false, cs::VALID, &pg), 0x7b);
    }

    #[test]
    fn task_ports_without_developer_mode() {
        let none = Entitlements::default();
        let read = Entitlements(vec![(b"com.apple.system-task-ports.read".to_vec(), Ent::Bool(true))]);
        let inspect = Entitlements(vec![(b"com.apple.system-task-ports.inspect".to_vec(), Ent::Bool(true))]);
        assert_eq!(get_task_with_flavor(&none, &none, flavor::NAME), Ok(()));
        assert_eq!(get_task_with_flavor(&none, &none, flavor::CONTROL), Err(1));
        assert_eq!(get_task_with_flavor(&read, &none, flavor::READ), Ok(()));
        assert_eq!(get_task_with_flavor(&read, &none, flavor::CONTROL), Err(1));
        assert_eq!(get_task_with_flavor(&inspect, &none, flavor::INSPECT), Ok(()));
        assert_eq!(get_task_with_flavor(&inspect, &none, flavor::READ), Err(1));
    }
}
