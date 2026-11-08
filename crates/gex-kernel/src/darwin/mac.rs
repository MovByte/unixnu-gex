//! The MAC framework's checks (`security/mac_*.c`) as this system's two
//! policies answer them: AMFI, then Sandbox. A check asks each policy
//! that has the hook and keeps the error of most precedence
//! (`mac_error_select`).
//!
//! Sandbox's hooks build an argument block for the operation and evaluate
//! it (`cred_sb_evaluate`): the platform profile, which applies to every
//! process, then the process's own profile when it has a sandbox. No
//! process here has one: the profile Sandbox would apply at exec is not
//! chosen yet, and an exec that would get one is refused loudly.

use super::sandbox::{self, Facts, Outcome, Stop, Value};
use crate::syscalls::Kernel;

/// Darwin's errnos the framework selects between.
mod e {
    pub const EPERM: u32 = 1;
    pub const ENOENT: u32 = 2;
    pub const ESRCH: u32 = 3;
    pub const EDEADLK: u32 = 11;
    pub const EACCES: u32 = 13;
    pub const EINVAL: u32 = 22;
}

/// `mac_error_select`.
pub fn error_select(a: u32, b: u32) -> u32 {
    for x in [e::EDEADLK, e::EINVAL, e::ESRCH, e::ENOENT, e::EACCES, e::EPERM] {
        if a == x || b == x {
            return x;
        }
    }
    if a != 0 { a } else { b }
}

/// Sandbox's operations (its `operation_names` table) the hooks here use.
pub mod op {
    pub const DYNAMIC_CODE_GENERATION: usize = 9;
    pub const MACH_PRIV_TASK_PORT: usize = 99;
    pub const MACH_TASK_INSPECT: usize = 102;
    pub const MACH_TASK_NAME: usize = 103;
    pub const MACH_TASK_READ: usize = 104;
    pub const PROCESS_CODESIGNING: usize = 119;
    pub const PROCESS_FORK: usize = 122;
    pub const PROCESS_INFO_CODESIGNATURE: usize = 124;
    pub const PROCESS_LEGACY_CODESIGNING_STATUS_SET: usize = 142;
    pub const SIGNAL: usize = 146;
    pub const SYSTEM_KAS_INFO: usize = 166;
    pub const SYSTEM_MAC_SYSCALL: usize = 173;
}

/// The operations' names (the kext's `operation_names`), by index.
pub const OPERATION_NAMES: [&str; 191] = [
    "default", "appleevent-send", "authorization-right-obtain", "boot-arg-set", "device*",
    "device-camera", "device-microphone", "darwin-notification-post",
    "distributed-notification-post", "dynamic-code-generation", "file*", "file-chroot",
    "file-clone", "file-ioctl", "file-issue-extension", "file-link", "file-lock",
    "file-map-executable", "file-mknod", "file-mount", "file-mount-update", "file-read*",
    "file-read-data", "file-read-metadata", "file-read-xattr", "file-revoke", "file-search",
    "file-test-existence", "file-unmount", "file-write*", "file-write-acl", "file-write-create",
    "file-write-data", "file-write-finderinfo", "file-write-flags", "file-write-mode",
    "file-write-owner", "file-write-setugid", "file-write-times", "file-write-unlink",
    "file-write-xattr", "fs-quota*", "fs-quota-get", "fs-quota-on", "fs-quota-off", "fs-quota-set*",
    "fs-quota-set-limits", "fs-quota-set-usage", "fs-quota-stat", "fs-quota-sync", "fs-rename",
    "fs-snapshot*", "fs-snapshot-create", "fs-snapshot-delete", "fs-snapshot-mount",
    "fs-snapshot-revert", "generic-issue-extension", "qtn-user", "hid-control", "iokit*",
    "iokit-get-properties", "iokit-issue-extension", "iokit-open*", "iokit-open-user-client",
    "iokit-open-service", "iokit-set-properties", "ipc*", "ipc-posix*", "ipc-posix-issue-extension",
    "ipc-posix-sem*", "ipc-posix-sem-create", "ipc-posix-sem-open", "ipc-posix-sem-post",
    "ipc-posix-sem-unlink", "ipc-posix-sem-wait", "ipc-posix-shm*", "ipc-posix-shm-read-data",
    "ipc-posix-shm-write*", "ipc-posix-shm-write-create", "ipc-posix-shm-write-data",
    "ipc-posix-shm-write-unlink", "ipc-sysv*", "ipc-sysv-msg", "ipc-sysv-sem", "ipc-sysv-shm",
    "job-creation", "lsopen", "mach*", "mach-bootstrap", "mach-cross-domain-lookup",
    "mach-derive-port", "mach-host*", "mach-host-exception-port-set", "mach-host-special-port-set",
    "mach-issue-extension", "mach-kernel-endpoint", "mach-lookup", "mach-priv*",
    "mach-priv-host-port", "mach-priv-task-port", "mach-register", "mach-task*",
    "mach-task-inspect", "mach-task-name", "mach-task-read", "mach-task-special-port*",
    "mach-task-special-port-get", "mach-task-special-port-set", "necp-client-open", "network*",
    "network-inbound", "network-bind", "network-outbound", "nvram*", "nvram-delete", "nvram-get",
    "nvram-set", "opendirectory-user-modify", "process*", "process-codesigning", "process-exec*",
    "process-exec-interpreter", "process-fork", "process-info*", "process-info-codesignature",
    "process-info-dirtycontrol", "process-info-ledger", "process-info-listpids",
    "process-info-pidinfo", "process-info-pidfdinfo", "process-info-pidfileportinfo",
    "process-info-rusage", "process-info-sandbox-container", "process-info-setcontrol",
    "process-legacy-codesigning*", "process-legacy-codesigning-blob-get",
    "process-legacy-codesigning-cdhash-get", "process-legacy-codesigning-entitlements-blob-get",
    "process-legacy-codesigning-entitlements-der-blob-get",
    "process-legacy-codesigning-identity-get", "process-legacy-codesigning-status*",
    "process-legacy-codesigning-status-get", "process-legacy-codesigning-status-set",
    "process-legacy-codesigning-teamid-get", "process-legacy-codesigning-text-offset-get",
    "pseudo-tty", "signal", "socket-ioctl", "socket-option*", "socket-option-get",
    "socket-option-set", "syscall*", "syscall-unix", "syscall-mach", "syscall-mig", "sysctl*",
    "sysctl-read", "sysctl-write", "system*", "system-acct", "system-audit", "system-automount",
    "system-debug", "system-fcntl", "system-fsctl", "system-info", "system-kas-info",
    "system-kext*", "system-kext-load", "system-kext-unload", "system-kext-query", "system-mac*",
    "system-mac-label", "system-mac-syscall", "system-memorystatus-control",
    "system-necp-client-action", "system-nfssvc", "system-package-check", "system-privilege",
    "system-reboot", "system-sched", "system-set-time", "system-socket", "system-suspend-resume",
    "system-swap", "user-preference*", "user-preference-read", "managed-preference-read",
    "user-preference-write", "storage-class-map", "process-exec-update-label",
];

/// The operation an argument block describes: its kind, whether it is
/// quiet (no violation report), and what it names.
#[derive(Clone, Debug, Default)]
pub struct SbArgs {
    pub kind: u32,
    pub quiet: bool,
    /// A process operation's target (kind 4), by pid.
    pub target: Option<i32>,
    /// `args[0xd8]` as a number (a syscall number, a command), and
    /// `args[0xe0]`'s (a MAC syscall's call number).
    pub number: u32,
    pub number2: u32,
    /// `args[0xd8]` as a string (a MAC policy's name, a Mach service's, a
    /// POSIX IPC object's, a preference domain...).
    pub string: Option<Vec<u8>>,
    /// A Mach service name's: a global name (`args[0xe0]`), an XPC
    /// service's (`args[0xe1]`).
    pub global: bool,
    pub xpc: bool,
}

/// The kernel's answers to Sandbox's filters, for an operation of the
/// current process.
struct KernelFacts<'a> {
    k: &'a mut Kernel,
    a: &'a SbArgs,
}

impl KernelFacts<'_> {
    fn ents(&self) -> Option<&super::codesign::Entitlements> {
        self.k.dtask.codesign.as_ref().map(|c| &c.ents)
    }

    fn csflags(&self) -> u32 {
        self.k.dtask.csflags.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Another process's signature, by its pid (its task's link).
    fn sig_of(&mut self, pid: i32) -> Option<Option<super::codesign::CodeSign>> {
        if pid == self.k.pid {
            return Some(self.k.dtask.codesign.clone());
        }
        let ipc = self.k.ipc();
        ipc.links.values().find(|l| l.pid == pid).map(|l| l.codesign.clone())
    }
}

fn ent_value(e: &super::codesign::Ent) -> Value {
    use super::codesign::Ent;
    match e {
        Ent::Bool(b) => Value::Bool(*b),
        Ent::String(s) => Value::String(s.clone()),
        Ent::Array(a) => Value::Array(a.iter().map(ent_value).collect()),
        _ => Value::Other,
    }
}

impl Facts for KernelFacts<'_> {
    fn kind(&self) -> u32 {
        self.a.kind
    }
    // The subject is the calling process.
    fn ensure_proc(&mut self) -> Result<(), Stop> {
        Ok(())
    }
    fn cs_entitlement_flags(&mut self) -> Result<u32, Stop> {
        Ok(self.csflags() & super::amfi::cs::ENTITLEMENT_FLAGS)
    }
    fn cs_restricted(&mut self) -> Result<bool, Stop> {
        Ok(self.csflags() & super::amfi::cs::RESTRICT != 0)
    }
    fn initproc(&mut self) -> Result<bool, Stop> {
        Ok(self.k.pid == crate::proc::INIT_PID)
    }
    fn platform_binary(&mut self) -> Result<bool, Stop> {
        Ok(self.k.darwin_task_platform_binary())
    }
    fn proc_platform(&mut self) -> Result<u32, Stop> {
        Ok(self.k.dtask.platform.0)
    }
    // No translated (Rosetta) process runs on iOS.
    fn translated(&mut self) -> Result<bool, Stop> {
        Ok(false)
    }
    // No Rapid Security Response cryptex is mounted.
    fn rsr(&mut self) -> Result<bool, Stop> {
        Ok(false)
    }
    fn sandboxed(&self) -> bool {
        false
    }
    fn protoboxed(&self) -> Result<bool, Stop> {
        Ok(false)
    }
    fn sandbox_flag_3b(&self) -> Result<bool, Stop> {
        Ok(false)
    }
    fn entitlement_bool(&mut self, key: &[u8]) -> Result<Option<bool>, Stop> {
        Ok(self.ents().map(|e| e.bool_true(key)))
    }
    fn entitlement_present(&mut self, key: &[u8]) -> Result<Option<bool>, Stop> {
        Ok(self.ents().map(|e| e.present(key)))
    }
    fn entitlement_value(&mut self, key: &[u8]) -> Result<Option<Value>, Stop> {
        Ok(self.ents().and_then(|e| e.get(key)).map(ent_value))
    }
    fn ancestor_entitled(&mut self, key: &[u8]) -> Result<bool, Stop> {
        let mut pid = self.k.pid;
        loop {
            if self.sig_of(pid).flatten().is_some_and(|c| c.ents.bool_true(key)) {
                return Ok(true);
            }
            let ppid = self.k.procs.ppid(pid);
            if ppid < 2 {
                return Ok(false);
            }
            pid = ppid;
        }
    }
    fn ensure_target(&mut self) -> Result<(), Stop> {
        let target = self.a.target;
        match target {
            Some(t) if self.sig_of(t).is_some() => Ok(()),
            _ => Err(Stop::Refuse(sandbox::Decision { errno: sandbox::ESRCH, flags: 5 })),
        }
    }
    fn target_entitlement_bool(&mut self, key: &[u8]) -> Result<Option<bool>, Stop> {
        let t = self.a.target.unwrap_or(0);
        Ok(self.sig_of(t).flatten().map(|c| c.ents.bool_true(key)))
    }
    fn persona(&mut self) -> Result<Option<(i32, u32)>, Stop> {
        Ok(self.k.darwin_current_persona().map(|p| (p.get_uid() as i32, p.get_type() as u32)))
    }
    // Sandbox's user records come from its system calls; none were made.
    fn home(&mut self) -> Result<Option<Vec<u8>>, Stop> {
        Ok(None)
    }
    fn front_user_home(&mut self) -> Result<Option<Vec<u8>>, Stop> {
        Ok(None)
    }
    fn temp_dir(&mut self) -> Result<Option<Vec<u8>>, Stop> {
        Ok(None)
    }
    fn os_release_type(&self) -> Vec<u8> {
        super::sysctl::os_release_type()
    }
    fn developer_mode(&self) -> bool {
        super::amfi::DEVELOPER_MODE
    }
    fn host_special_port(&self) -> u16 {
        self.a.number as u16
    }
    fn reboot_flags(&self) -> u16 {
        self.a.number as u16
    }
    fn syscall_number(&self) -> u32 {
        self.a.number
    }
    fn mac_call(&self) -> u32 {
        self.a.number2
    }
    fn mac_policy(&self) -> Option<Vec<u8>> {
        self.a.string.clone()
    }
    fn posix_ipc_name(&self) -> Option<Vec<u8>> {
        self.a.string.clone()
    }
    fn vnode_type(&mut self) -> Result<Option<(u32, bool)>, Stop> {
        Ok(None)
    }
    fn mach_name(&mut self) -> Option<(Vec<u8>, bool, bool)> {
        self.a.string.clone().map(|s| (s, self.a.global, self.a.xpc))
    }
    fn object_string(&mut self) -> Option<Vec<u8>> {
        self.a.string.clone()
    }
    fn signing_identifier(&mut self) -> Result<Option<Vec<u8>>, Stop> {
        Ok(self.k.dtask.codesign.as_ref().and_then(|c| c.identity.clone()))
    }
    fn ancestor_signing_identifiers(&mut self) -> Result<Vec<Vec<u8>>, Stop> {
        let mut out = Vec::new();
        let mut pid = self.k.pid;
        loop {
            if let Some(id) = self.sig_of(pid).flatten().and_then(|c| c.identity) {
                out.push(id);
            }
            let ppid = self.k.procs.ppid(pid);
            if ppid < 2 {
                return Ok(out);
            }
            pid = ppid;
        }
    }
    fn target_signing_identifier(&mut self) -> Result<Option<Vec<u8>>, Stop> {
        let t = self.a.target.unwrap_or(0);
        Ok(self.sig_of(t).flatten().and_then(|c| c.identity))
    }
    fn process_path(&mut self) -> Result<Option<Vec<u8>>, Stop> {
        Ok(Some(self.k.exe_path.clone().into_bytes()))
    }
    fn uid(&mut self) -> Result<u32, Stop> {
        Ok(self.k.creds.uid())
    }
}

/// The Sandbox's platform profile, as the boot loaded it.
static PLATFORM: std::sync::OnceLock<Option<(Vec<u8>, sandbox::Profile)>> = std::sync::OnceLock::new();

/// Load the Sandbox's platform profile (the kext's own blob), once.
pub fn set_platform_profile(blob: Option<Vec<u8>>) -> Result<(), String> {
    let p = match blob {
        Some(b) => {
            let p = sandbox::single(&b).map_err(|e| format!("the sandbox platform profile: {e:?}"))?;
            Some((b, p))
        }
        None => None,
    };
    let _ = PLATFORM.set(p);
    Ok(())
}

impl Kernel {
    /// `cred_sb_evaluate` for the current process: the platform profile
    /// (but for system-kas-info), then a process profile when the process
    /// has a sandbox (none does here). The errno its hook returns; a
    /// report goes to the kernel's log unless quiet.
    pub(crate) fn darwin_sb_evaluate(&mut self, op: usize, a: &SbArgs) -> u32 {
        let Some(Some((blob, profile))) = PLATFORM.get() else {
            self.darwin_unimplemented("the Sandbox's platform profile (the boot payload's Sandbox/Platform)".into());
            return e::EPERM;
        };
        let (mut errno, mut flags) = (0u32, 0u32);
        if op != op::SYSTEM_KAS_INFO {
            let mut scratch = sandbox::Scratch::default();
            let out = sandbox::evaluate(blob, profile, op, &mut KernelFacts { k: self, a }, &mut scratch);
            let d = match out {
                Outcome::Decided(d, _) => d,
                Outcome::Unported(what) => {
                    self.darwin_unimplemented(format!("{what} (sandbox operation {op})"));
                    return e::EPERM;
                }
            };
            if d.flags & 1 != 0 {
                (errno, flags) = (d.errno, d.flags);
            } else {
                flags = d.flags & 0x1fff_ffff;
            }
            if u64::from(d.flags) << 32 & 0x85_0000_0000 != 0 {
                flags = 0x2000_0000 | (flags & 0x1fff_ffff);
            }
        }
        // Reported when its flags ask (bits 2, 7 and 24).
        if flags & 0x0100_0084 != 0 && !a.quiet && self.trace {
            eprintln!("[gex:{}] Sandbox: {}({}) {}({errno}) operation {op}", self.pid, self.exe_path, self.pid, if errno != 0 { "deny" } else { "allow" });
        }
        errno
    }

    /// `mac_proc_check_fork` (Sandbox's process-fork).
    pub(crate) fn darwin_mac_check_fork(&mut self) -> u32 {
        self.darwin_sb_evaluate(op::PROCESS_FORK, &SbArgs::default())
    }

    /// `mac_proc_check_syscall_mac` (Sandbox's system-mac-syscall).
    pub(crate) fn darwin_mac_check_syscall_mac(&mut self, policy: &[u8], call: u32) -> u32 {
        let a = SbArgs { kind: sandbox::kind::MAC_SYSCALL, number2: call, string: Some(policy.to_vec()), ..Default::default() };
        self.darwin_sb_evaluate(op::SYSTEM_MAC_SYSCALL, &a)
    }

    /// `mac_proc_check_signal` of `signum` to process `pid` (Sandbox's
    /// signal; AMFI has no hook): allowed for a target already exiting
    /// (`proc_exiting`), else one evaluation, quiet for signal 0.
    pub(crate) fn darwin_mac_check_signal(&mut self, pid: i32, signum: u32) -> u32 {
        if self.procs.exiting(pid) {
            return 0;
        }
        let a = SbArgs { kind: sandbox::kind::PROCESS, target: Some(pid), quiet: signum == 0, ..Default::default() };
        self.darwin_sb_evaluate(op::SIGNAL, &a)
    }

    /// `mac_proc_check_map_anon` for a MAP_JIT mapping: AMFI's (a probe,
    /// all of address, size and protection zero, as exec asks it, is the
    /// same question), then Sandbox's dynamic-code-generation, quiet for a
    /// probe without protection.
    pub(crate) fn darwin_mac_check_map_jit(&mut self, prot: u32) -> u32 {
        let platform = self.darwin_task_platform_binary();
        let ents = self.dtask.codesign.as_ref().map(|c| c.ents.clone()).unwrap_or_default();
        let amfi = super::amfi::map_anon_jit(platform, &ents).err().unwrap_or(0);
        let a = SbArgs { quiet: prot == 0, ..Default::default() };
        let sb = self.darwin_sb_evaluate(op::DYNAMIC_CODE_GENERATION, &a);
        error_select(amfi, sb)
    }

    /// `mac_proc_check_get_task` for process `pid`'s task port of flavor
    /// `f`: AMFI's (the caller's entitlements, the target's), then
    /// Sandbox's operation for the flavor. ESRCH when the target is gone.
    pub(crate) fn darwin_mac_check_get_task(&mut self, pid: i32, f: u32) -> u32 {
        let caller = self.dtask.codesign.as_ref().map(|c| c.ents.clone()).unwrap_or_default();
        let target = if pid == self.pid {
            Some(self.dtask.codesign.clone())
        } else {
            let ipc = self.ipc();
            ipc.links.values().find(|l| l.pid == pid).map(|l| l.codesign.clone())
        };
        let Some(target) = target else { return e::ESRCH };
        let target = target.map(|c| c.ents).unwrap_or_default();
        let amfi = super::amfi::get_task_with_flavor(&caller, &target, f).err().unwrap_or(0);
        let op = [op::MACH_PRIV_TASK_PORT, op::MACH_TASK_READ, op::MACH_TASK_INSPECT, op::MACH_TASK_NAME][f as usize & 3];
        let a = SbArgs { kind: sandbox::kind::PROCESS, target: Some(pid), ..Default::default() };
        let sb = self.darwin_sb_evaluate(op, &a);
        error_select(amfi, sb)
    }

    /// `mac_proc_check_get_cs_info` on process `pid` for csops `op`:
    /// Sandbox's (AMFI has none): the operation's legacy one, quietly,
    /// for those that have one, else process-info-codesignature; then
    /// process-codesigning.
    pub(crate) fn darwin_mac_check_get_cs_info(&mut self, pid: i32, csop: u32) -> u32 {
        const LEGACY: [(u32, usize); 8] = [(0, 141), (5, 136), (6, 144), (7, 137), (10, 135), (11, 139), (14, 143), (16, 138)];
        let a = SbArgs { kind: sandbox::kind::PROCESS, target: Some(pid), quiet: true, ..Default::default() };
        let legacy = LEGACY.iter().find(|(o, _)| *o == csop).map(|&(_, op)| self.darwin_sb_evaluate(op, &a));
        if legacy != Some(0) {
            let a = SbArgs { quiet: false, ..a.clone() };
            let r = self.darwin_sb_evaluate(op::PROCESS_INFO_CODESIGNATURE, &a);
            if r != 0 {
                return r;
            }
        }
        let a = SbArgs { kind: sandbox::kind::PROCESS, target: Some(pid), number: csop, ..Default::default() };
        self.darwin_sb_evaluate(op::PROCESS_CODESIGNING, &a)
    }

    /// `mac_proc_check_set_cs_info`: Sandbox's legacy status-set, quietly,
    /// then process-codesigning if that refused.
    pub(crate) fn darwin_mac_check_set_cs_info(&mut self, pid: i32, csop: u32) -> u32 {
        let a = SbArgs { kind: sandbox::kind::PROCESS, target: Some(pid), quiet: true, ..Default::default() };
        if self.darwin_sb_evaluate(op::PROCESS_LEGACY_CODESIGNING_STATUS_SET, &a) == 0 {
            return 0;
        }
        let a = SbArgs { kind: sandbox::kind::PROCESS, target: Some(pid), number: csop, ..Default::default() };
        self.darwin_sb_evaluate(op::PROCESS_CODESIGNING, &a)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn errors_are_selected_by_precedence() {
        use super::*;
        assert_eq!(error_select(0, 0), 0);
        assert_eq!(error_select(e::EPERM, 0), e::EPERM);
        assert_eq!(error_select(e::EPERM, e::ESRCH), e::ESRCH);
        assert_eq!(error_select(e::EACCES, e::EINVAL), e::EINVAL);
        assert_eq!(error_select(45, 0), 45);
    }
}
