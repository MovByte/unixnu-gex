//! The MAC framework's checks (`security/mac_*.c`) as this system's two
//! policies answer them: AMFI, then Sandbox. A check asks each policy
//! that has the hook and keeps the error of most precedence
//! (`mac_error_select`).
//!
//! Sandbox's hooks build an argument block for the operation and evaluate
//! it (`cred_sb_evaluate`, `0x...a03b90`): the platform profile, which
//! applies to every process, then, when the process has a sandbox and the
//! platform profile allowed, the sandbox's profile, deferring to the
//! protobox profile stacked under it where that profile says (flag 10).
//! How a process gets its sandbox is `sandboxes.rs`.
//!
//! Only the hooks below are wired, process-exec* and
//! process-exec-interpreter among them; Sandbox's others (the other vnode
//! checks among them: file-read*, file-write*, ...) are not called, for the
//! platform profile's rules as for a sandbox's. The call filters ask of the
//! Unix calls, Mach traps and kernel MIG routines a process's masks do not
//! let through (syscall-unix, syscall-mach, syscall-mig).

use std::sync::Arc;

use super::sandbox::{self, Facts, Outcome, Stop, Value};
use super::sandboxes::Sandbox;
use crate::syscalls::Kernel;

/// Darwin's errnos the framework selects between.
mod e {
    pub const EPERM: u32 = 1;
    pub const ENOENT: u32 = 2;
    pub const ESRCH: u32 = 3;
    pub const EDEADLK: u32 = 11;
    pub const EACCES: u32 = 13;
    pub const EINVAL: u32 = 22;
    pub const ENOTSUP: u32 = 45;
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
    pub const FILE_REVOKE: usize = 25;
    pub const MACH_HOST_SPECIAL_PORT_SET: usize = 93;
    pub const MACH_PRIV_HOST_PORT: usize = 98;
    pub const MACH_PRIV_TASK_PORT: usize = 99;
    pub const MACH_TASK_INSPECT: usize = 102;
    pub const MACH_TASK_NAME: usize = 103;
    pub const MACH_TASK_READ: usize = 104;
    pub const PROCESS_CODESIGNING: usize = 119;
    pub const PROCESS_EXEC: usize = 120;
    pub const PROCESS_EXEC_INTERPRETER: usize = 121;
    pub const PROCESS_FORK: usize = 122;
    pub const PROCESS_INFO_PIDINFO: usize = 128;
    pub const PROCESS_INFO_CODESIGNATURE: usize = 124;
    pub const PROCESS_LEGACY_CODESIGNING_STATUS_SET: usize = 142;
    pub const SIGNAL: usize = 146;
    pub const SYSCALL_UNIX: usize = 152;
    pub const SYSCALL_MACH: usize = 153;
    pub const SYSCALL_MIG: usize = 154;
    pub const SYSCTL_READ: usize = 156;
    pub const SYSCTL_WRITE: usize = 157;
    pub const SYSTEM_FSCTL: usize = 164;
    pub const SYSTEM_KAS_INFO: usize = 166;
    pub const SYSTEM_MAC_SYSCALL: usize = 173;
    pub const SYSTEM_SCHED: usize = 180;
    pub const SYSTEM_SUSPEND_RESUME: usize = 183;
    pub const STORAGE_CLASS_MAP: usize = 189;
    pub const PROCESS_EXEC_UPDATE_LABEL: usize = 190;
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
    /// A vnode operation's vnode (kind 1).
    pub vnode: Option<SbVnode>,
}

/// What a vnode operation's filters read of its vnode.
#[derive(Clone, Debug, Default)]
pub struct SbVnode {
    /// Its path (`vn_getpath`), canonical.
    pub path: Vec<u8>,
    /// Its mount point's length in the path (`args[0x160]`), -1 when the
    /// path is the mount point's own.
    pub mount_len: i64,
    /// `enum vtype`, and whether it is a terminal (`VISTTY`).
    pub vtype: u32,
    pub tty: bool,
    /// `va_mode & 0xfff`.
    pub mode: u16,
    /// `va_flags`.
    pub flags: u32,
}

impl SbVnode {
    /// The vnode at canonical `path`, of type `vtype`, mode `mode` and
    /// file flags `flags`, on the mount it is under.
    pub fn at(path: &str, vtype: u32, tty: bool, mode: u32, flags: u32) -> SbVnode {
        let on = super::kern::mount_of(path).on;
        let mount_len = if path == on { -1 } else { on.len() as i64 };
        SbVnode { path: path.as_bytes().to_vec(), mount_len, vtype, tty, mode: (mode & 0xfff) as u16, flags }
    }
}

/// The kernel's answers to Sandbox's filters, for an operation of the
/// current process evaluated with sandbox `sb` (its credential's, or the
/// one an exec carries over).
struct KernelFacts<'a> {
    k: &'a mut Kernel,
    a: &'a SbArgs,
    sb: Option<&'a Sandbox>,
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
    // The sandbox evaluated with: whether there is one, whether its
    // profile is the protobox collection's, its shared state's byte +59.
    fn sandboxed(&self) -> bool {
        self.sb.is_some()
    }
    fn protoboxed(&self) -> Result<bool, Stop> {
        Ok(self.sb.is_some_and(Sandbox::protoboxed))
    }
    fn sandbox_flag_3b(&self) -> Result<bool, Stop> {
        Ok(self.sb.is_some_and(|s| s.flag_3b))
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
    fn target_is(&mut self, which: u16) -> Result<bool, Stop> {
        let (me, t) = (self.k.pid, self.a.target.unwrap_or(0));
        let pgrp = |k: &Kernel, pid: i32| k.procs.pgid(pid, pid).ok();
        Ok(match which {
            1 => t == me,
            2 => pgrp(self.k, t) == pgrp(self.k, me),
            3 => pgrp(self.k, t) != pgrp(self.k, me),
            4 => self.k.procs.ppid(t) == me,
            // The target's credential's sandbox is the very one.
            5 => {
                let theirs = if t == me {
                    self.k.darwin_sandbox()
                } else {
                    let ipc = self.k.ipc();
                    ipc.links.values().find(|l| l.pid == t).and_then(|l| super::sandboxes::of(&l.sandbox))
                };
                match (theirs, self.sb) {
                    (Some(a), Some(b)) => std::ptr::eq(Arc::as_ptr(&a), b),
                    (None, None) => true,
                    _ => false,
                }
            }
            6 => t == crate::proc::INIT_PID,
            _ => self.sig_of(t).flatten().is_some_and(|c| c.platform_binary),
        })
    }
    fn has_extension(&mut self, class: &[u8]) -> bool {
        self.sb.is_some_and(|s| s.extensions.iter().any(|e| e.class == class))
    }
    fn persona(&mut self) -> Result<Option<(i32, u32)>, Stop> {
        Ok(self.k.darwin_current_persona().map(|p| (p.get_uid() as i32, p.get_type() as u32)))
    }
    // The user states policy_init made, of the credential's uid and of the
    // front user's.
    fn home(&mut self) -> Result<Option<Vec<u8>>, Stop> {
        Ok(super::sandboxes::user_state(self.k.creds.uid()).map(|u| u.home.as_bytes().to_vec()))
    }
    fn front_user_home(&mut self) -> Result<Option<Vec<u8>>, Stop> {
        Ok(super::sandboxes::user_state(super::sandboxes::FRONT_USER).map(|u| u.home.as_bytes().to_vec()))
    }
    fn temp_dir(&mut self) -> Result<Option<Vec<u8>>, Stop> {
        Ok(super::sandboxes::user_state(self.k.creds.uid()).map(|u| u.tmp.as_bytes().to_vec()))
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
    fn object_number(&mut self) -> Result<Option<u32>, Stop> {
        Ok((self.a.kind == sandbox::kind::FSCTL).then_some(self.a.number))
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
        Ok(self.a.vnode.as_ref().map(|v| (v.vtype, v.tty)))
    }
    fn path(&mut self) -> Result<Option<(Vec<u8>, i64)>, Stop> {
        Ok(self.a.vnode.as_ref().map(|v| (v.path.clone(), v.mount_len)))
    }
    fn vnode_mode(&mut self) -> Result<Option<u16>, Stop> {
        Ok(self.a.vnode.as_ref().map(|v| v.mode))
    }
    fn vnode_flags(&mut self) -> Result<Option<u32>, Stop> {
        Ok(self.a.vnode.as_ref().map(|v| v.flags))
    }
    /// The vnode's class (`0x...78cc`): a file Sandbox protects
    /// (SF_RESTRICTED, SF_NOUNLINK) or a data vault (UF_DATAVAULT) is
    /// classed by those first, which is not ported; any other has the class
    /// the platform profile's storage-class-map names for it, or none.
    fn storage_class(&mut self) -> Result<Option<Vec<u8>>, Stop> {
        let Some(v) = self.a.vnode.clone() else { return Ok(None) };
        if v.flags & 0x0018_0080 != 0 {
            return Err(Stop::Unported(format!("sandbox: the storage class of a file with flags {:#x}", v.flags)));
        }
        let Some(Some((blob, profile))) = PLATFORM.get() else {
            return Err(Stop::Unported("the Sandbox's platform profile (the boot payload's Sandbox/Platform)".into()));
        };
        let a = SbArgs { kind: sandbox::kind::VNODE, vnode: Some(v), ..Default::default() };
        let mut scratch = sandbox::Scratch::default();
        match sandbox::evaluate(blob, profile, op::STORAGE_CLASS_MAP, &mut KernelFacts { k: &mut *self.k, a: &a, sb: self.sb }, &mut scratch) {
            Outcome::Decided(_, fx) => Ok(fx.storage_class),
            Outcome::Unported(what) => Err(Stop::Unported(what)),
        }
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

/// The platform profile's masks (`0x...6f8e540`): what a process with no
/// sandbox is filtered by, and what a sandbox's are and-ed with.
static PLATFORM_MASKS: std::sync::OnceLock<[Option<sandbox::FilterMask>; 4]> = std::sync::OnceLock::new();

/// Load the Sandbox's platform profile (the kext's own blob), once, with
/// its masks (its loader's, for a profile that stacks nothing); a mask
/// that does not load fails the boot, as it panics the kernel.
pub fn set_platform_profile(blob: Option<Vec<u8>>) -> Result<(), String> {
    let (p, masks) = match blob {
        Some(b) => {
            let p = sandbox::single(&b).map_err(|e| format!("the sandbox platform profile: {e:?}"))?;
            let m = super::sandboxes::profile_masks(&b, &p, false).map_err(|e| format!("failed to initialize platform sandbox: {e}"))?;
            (Some((b, p)), m.map(|m| m.mask))
        }
        // No platform profile: no masks (each check is refused instead).
        None => (None, Default::default()),
    };
    let _ = PLATFORM.set(p);
    let _ = PLATFORM_MASKS.set(masks);
    Ok(())
}

/// The platform profile's masks: of the Unix calls, Mach traps, kernel MIG
/// routines and fcntl commands.
pub fn platform_masks() -> [Option<sandbox::FilterMask>; 4] {
    PLATFORM_MASKS.get().cloned().unwrap_or_default()
}

impl Kernel {
    /// `cred_sb_evaluate` for the current process, with its credential's
    /// sandbox. The errno its hook returns.
    pub(crate) fn darwin_sb_evaluate(&mut self, op: usize, a: &SbArgs) -> u32 {
        let sb = self.darwin_sandbox();
        self.darwin_sb_evaluate_with(sb.as_ref(), op, a).0
    }

    /// `cred_sb_evaluate` (`0x...a03b90`) of operation `op` with sandbox
    /// `sb`: the platform profile (but for system-kas-info), then, unless it
    /// denied or its flags have bit 6, the sandbox's profile, whose flag 10
    /// defers to the protobox profile under it (a denial, EPERM, without
    /// one). Its errno, its flags and what the terminals' modifiers left; a
    /// report goes to the kernel's log unless quiet.
    pub(crate) fn darwin_sb_evaluate_with(&mut self, sb: Option<&Arc<Sandbox>>, op: usize, a: &SbArgs) -> (u32, u32, sandbox::Effects) {
        let Some(Some((blob, profile))) = PLATFORM.get() else {
            self.darwin_unimplemented("the Sandbox's platform profile (the boot payload's Sandbox/Platform)".into());
            return (e::EPERM, 5, sandbox::Effects::default());
        };
        let sb = sb.map(Arc::as_ref);
        let mut scratch = sandbox::Scratch::default();
        let mut fx = sandbox::Effects::default();
        let (mut errno, mut flags) = (0u32, 0u32);
        if op != op::SYSTEM_KAS_INFO {
            let out = sandbox::evaluate(blob, profile, op, &mut KernelFacts { k: self, a, sb }, &mut scratch);
            let d = match out {
                Outcome::Decided(d, effects) => {
                    fx = effects;
                    d
                }
                Outcome::Unported(what) => {
                    self.darwin_unimplemented(format!("{what} (sandbox operation {op})"));
                    return (e::EPERM, 5, fx);
                }
            };
            if d.flags & 1 != 0 {
                (errno, flags) = (d.errno, d.flags);
            } else {
                flags = d.flags & 0x1fff_ffff;
            }
            if d.flags & 0x85 != 0 {
                flags = 0x2000_0000 | (flags & 0x1fff_ffff);
            }
        }
        if let Some(sb) = sb.filter(|_| errno == 0 && flags & 0x40 == 0) {
            let mut decide = |k: &mut Kernel, p: super::sandboxes::ProfileRef| match sandbox::evaluate(p.blob(), p.profile(), op, &mut KernelFacts { k, a, sb: Some(sb) }, &mut scratch) {
                Outcome::Decided(d, effects) => {
                    fx.message = fx.message.take().or(effects.message);
                    fx.message2 = fx.message2.take().or(effects.message2);
                    fx.profile = fx.profile.take().or(effects.profile);
                    Ok(d)
                }
                Outcome::Unported(what) => Err(what),
            };
            let d = match decide(self, sb.profile) {
                Ok(d) if d.flags & 0x400 == 0 => Ok((d, 0x6000_0000)),
                Ok(_) => match sb.protobox {
                    Some(p) => decide(self, p).map(|d| (d, 0x8000_0000)),
                    None => Ok((sandbox::Decision { errno: e::EPERM, flags: 5 }, 0x8000_0000)),
                },
                Err(what) => Err(what),
            };
            let (d, tag) = match d {
                Ok(d) => d,
                Err(what) => {
                    self.darwin_unimplemented(format!("{what} (sandbox operation {op}, profile {})", String::from_utf8_lossy(sb.profile.name())));
                    return (e::EPERM, 5, fx);
                }
            };
            // The two decisions' flags: an allowance adds the profile's to
            // the platform's; a denial is the profile's; either takes the
            // profile's tag when the platform's report bits do not already
            // cover the profile's.
            let (reports, own_reports) = (flags & 0x84, d.flags & 0x84);
            let tagged = if d.flags & 1 == 0 {
                flags |= d.flags & 0x1fff_ffff & !0x10;
                false
            } else {
                // (The platform's decision is never a denial here.)
                let platform_denied = flags & 1 != 0;
                (errno, flags) = (d.errno, d.flags & !0x10);
                !platform_denied
            };
            if tagged || (reports == 0 && own_reports != 0) {
                flags = (flags & 0x1fff_ffff) | tag;
            }
        }
        // Reported when its flags ask (bits 2, 7 and 24): the operation and
        // the object it names.
        if flags & 0x0100_0084 != 0 && !a.quiet && self.trace {
            let object = a.string.as_deref().map(|s| format!(" {}", String::from_utf8_lossy(s))).unwrap_or_default();
            eprintln!("[gex:{}] Sandbox: {}({}) {}({errno}) {}{object}", self.pid, self.exe_path, self.pid, if errno != 0 { "deny" } else { "allow" }, OPERATION_NAMES.get(op).copied().unwrap_or("?"));
        }
        (errno, flags, fx)
    }

    /// `mac_system_check_sysctlbyname` (Sandbox's hook; AMFI has none): a
    /// name-to-number walk is free; a read that names a process (its
    /// `kern.proc.pid` node, its arguments) passes on the Sandbox's
    /// process-info-pidinfo of that process; otherwise sysctl-read, then
    /// sysctl-write when a value is given.
    pub(crate) fn darwin_mac_check_sysctl(&mut self, name: &[u8], oid: &[i32], new: u64, newlen: u64) -> u32 {
        if oid == [0, 3] {
            return 0;
        }
        if new == 0 {
            let pid = if oid.len() >= 3 && oid[0] == 1 {
                if oid.len() >= 4 && oid[1] == 14 {
                    (oid[2] == 1).then(|| oid[3])
                } else {
                    (oid[1] == 0x31 || oid[1] == 0x26).then(|| oid[2])
                }
            } else {
                None
            };
            if let Some(pid) = pid.filter(|p| self.procs.exists(*p)) {
                let a = SbArgs { kind: sandbox::kind::PROCESS, target: Some(pid), ..Default::default() };
                if self.darwin_sb_evaluate(op::PROCESS_INFO_PIDINFO, &a) == 0 {
                    return 0;
                }
            }
        }
        let a = SbArgs { kind: sandbox::kind::SYSCTL, string: Some(name.to_vec()), ..Default::default() };
        let e = self.darwin_sb_evaluate(op::SYSCTL_READ, &a);
        if e != 0 || (new == 0 && newlen == 0) {
            return e;
        }
        self.darwin_sb_evaluate(op::SYSCTL_WRITE, &a)
    }

    /// `mac_vnode_check_exec` of the regular file at canonical `path`, of
    /// mode `mode` (AMFI's hook refuses nothing here): Sandbox's
    /// (`0x...a0a348`), process-exec* of the file, or
    /// process-exec-interpreter of a script's interpreter, for the caller's
    /// credential. The kernel's first exec, the initial process's, is not
    /// checked; here that is the run's first program, which the kernel
    /// starts without this lookup. A caller with a sandbox may not exec a
    /// set-id file its profiles allow unless their decision has flag 3
    /// (forbidden-exec-sugid), which marks the exec instead: its label
    /// update then asks its sandbox (or drops a protobox one). Whether the
    /// exec is marked, or the errno.
    pub(crate) fn darwin_mac_check_vnode_exec(&mut self, path: &str, mode: u32, interpreter: bool) -> Result<bool, u32> {
        let sb = self.darwin_sandbox();
        let op = if interpreter { op::PROCESS_EXEC_INTERPRETER } else { op::PROCESS_EXEC };
        let a = SbArgs { kind: sandbox::kind::VNODE, vnode: Some(SbVnode::at(path, 1, false, mode, 0)), ..Default::default() };
        let (errno, flags, _) = self.darwin_sb_evaluate_with(sb.as_ref(), op, &a);
        if sb.is_none() || errno != 0 {
            return if errno != 0 { Err(errno) } else { Ok(false) };
        }
        if flags & 8 != 0 {
            return Ok(true);
        }
        if mode & 0o6000 != 0 {
            self.darwin_sb_report("forbidden-exec-sugid");
            return Err(e::EPERM);
        }
        Ok(false)
    }

    /// `mac_proc_check_fork` (Sandbox's process-fork).
    /// Sandbox's `mpo_mount_check_fsctl`: `system-fsctl` for the command,
    /// but for two commands of APFS's that it lets through.
    pub(crate) fn darwin_mac_check_fsctl(&mut self, cmd: u64) -> u32 {
        if cmd == 0x4008_4a4a || cmd == 0xc008_4a44 {
            return 0;
        }
        let a = SbArgs { kind: sandbox::kind::FSCTL, number: cmd as u32, ..Default::default() };
        self.darwin_sb_evaluate(op::SYSTEM_FSCTL, &a)
    }

    /// `mac_vnode_check_revoke` (Sandbox's hook, slot 273 of its ops:
    /// file-revoke of the vnode; AMFI has none).
    pub(crate) fn darwin_mac_check_vnode_revoke(&mut self, v: SbVnode) -> u32 {
        let a = SbArgs { kind: sandbox::kind::VNODE, vnode: Some(v), ..Default::default() };
        self.darwin_sb_evaluate(op::FILE_REVOKE, &a)
    }

    /// `mac_task_check_set_host_special_port` (Sandbox's hook, slot 126:
    /// mach-host-special-port-set of the port's id, which must fit 16 bits;
    /// AMFI has none).
    pub(crate) fn darwin_mac_check_set_host_special_port(&mut self, id: i32) -> u32 {
        if (id as u32) >> 16 != 0 {
            return e::ENOTSUP;
        }
        let a = SbArgs { kind: sandbox::kind::HOST_SPECIAL_PORT, number: id as u32 & 0xffff, ..Default::default() };
        self.darwin_sb_evaluate(op::MACH_HOST_SPECIAL_PORT_SET, &a)
    }

    /// `unix_syscall`'s filter: call `code` (`SYS_invalid` past the table)
    /// is asked of the MAC policies when the process's mask does not let it
    /// through, and their error skips it.
    pub(crate) fn darwin_syscall_filter(&mut self, code: u64) -> Result<(), crate::errno::Errno> {
        let Some(mask) = &self.dtask.syscall_mask else { return Ok(()) };
        if sandbox::mask_allows(mask, code as usize) {
            return Ok(());
        }
        match self.darwin_mac_check_syscall_unix(code as u32) {
            0 => Ok(()),
            e => Err(super::errno::errno_of(e as i32)),
        }
    }

    /// `mac_proc_check_syscall_unix` (Sandbox's hook, slot 124:
    /// syscall-unix of the call's number; AMFI has none). Calls 1, 328, 520
    /// and 521 (exit, pthread_kill and the two that end a process with a
    /// payload) set the argument block's flag 8, which shapes only the
    /// violation's report (`0x...a0b778`).
    pub(crate) fn darwin_mac_check_syscall_unix(&mut self, code: u32) -> u32 {
        let a = SbArgs { kind: sandbox::kind::SYSCALL_UNIX, number: code, ..Default::default() };
        self.darwin_sb_evaluate(op::SYSCALL_UNIX, &a)
    }

    /// `mach_syscall`'s filter, for trap `call` (`-x16`, one of the table's
    /// traps): asked of Sandbox's callback when the task's mask does not let
    /// it through; a refusal is the trap's result.
    pub(crate) fn darwin_mach_trap_filter(&mut self, call: usize) -> Option<u64> {
        let mask = self.dtask.mach_trap_mask.clone()?;
        if sandbox::mask_allows(&mask, call) {
            return None;
        }
        match self.darwin_sb_mach_trap_evaluate(call as u32) {
            0 => None,
            kr => Some(kr),
        }
    }

    /// Sandbox's Mach trap filter callback (`0x...a01994`, which it
    /// registers with `proc_set_syscall_filter_callbacks`): syscall-mach of
    /// the trap's number, KERN_DENIED for a refusal.
    fn darwin_sb_mach_trap_evaluate(&mut self, call: u32) -> u64 {
        const KERN_DENIED: u64 = 53;
        let a = SbArgs { kind: sandbox::kind::SYSCALL_MACH, number: call, ..Default::default() };
        if self.darwin_sb_evaluate(op::SYSCALL_MACH, &a) == 0 { 0 } else { KERN_DENIED }
    }

    /// `ipc_kobject_server`'s filter, for a request of message id `id`: a
    /// routine Sandbox indexed that the task's mask does not let through
    /// is asked of Sandbox's callback; a refusal is the reply's error.
    pub(crate) fn darwin_kobj_filter(&mut self, id: u32) -> Option<i32> {
        let idx = super::sandboxes::kobj_index(id)?;
        let mask = self.dtask.kobj_mask.clone()?;
        if sandbox::mask_allows(&mask, idx) {
            return None;
        }
        match self.darwin_sb_kobj_msg_evaluate(idx as u32) {
            0 => None,
            kr => Some(kr),
        }
    }

    /// Sandbox's kernel MIG filter callback (`0x...a01ab0`): syscall-mig of
    /// the routine's index (the block holds its message id too, `+0xdc`),
    /// KERN_DENIED for a refusal. The exception raises' indexes (54 to 56,
    /// mach_exception_raise and its _state and _state_identity forms) set
    /// the block's flag 8, which shapes only the report.
    fn darwin_sb_kobj_msg_evaluate(&mut self, idx: u32) -> i32 {
        const KERN_DENIED: i32 = 53;
        let a = SbArgs { kind: sandbox::kind::SYSCALL_MIG, number: idx, ..Default::default() };
        if self.darwin_sb_evaluate(op::SYSCALL_MIG, &a) == 0 { 0 } else { KERN_DENIED }
    }

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
    fn a_vnodes_mount_length() {
        use super::SbVnode;
        // A device on devfs: "/dev", then "/null" within it.
        assert_eq!(SbVnode::at("/dev/null", 4, false, 0o20666, 0).mount_len, 4);
        // The root's own mount point, and a file under it.
        assert_eq!(SbVnode::at("/", 2, false, 0o40755, 0).mount_len, -1);
        assert_eq!(SbVnode::at("/usr/lib/dyld", 1, false, 0o100755, 0).mount_len, 1);
        assert_eq!(SbVnode::at("/dev/null", 4, false, 0o20666, 0).mode, 0o666);
    }

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
