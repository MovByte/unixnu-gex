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
//! let through (syscall-unix, syscall-mach, syscall-mig). The socket calls
//! ask network-bind, -inbound and -outbound, system-socket and the
//! socket-option and socket-ioctl operations, a unix socket's operations
//! being allowed at once. IOKit's opens ask iokit-open-service and
//! iokit-open-user-client (and the user client filter resolver asks the
//! latter again), its property reads iokit-get-properties or nvram-get.

use std::sync::Arc;

use super::sandbox::{self, Facts, Outcome, Stop, Value};
use super::sandboxes::Sandbox;
use crate::syscalls::Kernel;
use crate::GuestMem;

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
    pub const IOKIT_GET_PROPERTIES: usize = 60;
    pub const IOKIT_OPEN_USER_CLIENT: usize = 63;
    pub const IOKIT_OPEN_SERVICE: usize = 64;
    pub const FILE_CLONE: usize = 12;
    pub const FILE_IOCTL: usize = 13;
    pub const FILE_LINK: usize = 15;
    pub const FILE_LOCK: usize = 16;
    pub const FILE_MAP_EXECUTABLE: usize = 17;
    pub const FILE_MKNOD: usize = 18;
    pub const FILE_READ: usize = 21;
    pub const FILE_READ_DATA: usize = 22;
    pub const FILE_READ_METADATA: usize = 23;
    pub const FILE_READ_XATTR: usize = 24;
    pub const FILE_REVOKE: usize = 25;
    pub const FILE_TEST_EXISTENCE: usize = 27;
    pub const FILE_WRITE: usize = 29;
    pub const FILE_WRITE_ACL: usize = 30;
    pub const FILE_WRITE_CREATE: usize = 31;
    pub const FILE_WRITE_DATA: usize = 32;
    pub const FILE_WRITE_FINDERINFO: usize = 33;
    pub const FILE_WRITE_FLAGS: usize = 34;
    pub const FILE_WRITE_MODE: usize = 35;
    pub const FILE_WRITE_OWNER: usize = 36;
    pub const FILE_WRITE_SETUGID: usize = 37;
    pub const FILE_WRITE_TIMES: usize = 38;
    pub const FILE_WRITE_UNLINK: usize = 39;
    pub const FILE_WRITE_XATTR: usize = 40;
    pub const FS_RENAME: usize = 50;
    pub const HID_CONTROL: usize = 58;
    pub const MACH_HOST_EXCEPTION_PORT_SET: usize = 92;
    pub const MACH_HOST_SPECIAL_PORT_SET: usize = 93;
    pub const MACH_PRIV_HOST_PORT: usize = 98;
    pub const MACH_PRIV_TASK_PORT: usize = 99;
    pub const MACH_TASK_INSPECT: usize = 102;
    pub const MACH_TASK_NAME: usize = 103;
    pub const MACH_TASK_READ: usize = 104;
    pub const MACH_TASK_SPECIAL_PORT_GET: usize = 106;
    pub const MACH_TASK_SPECIAL_PORT_SET: usize = 107;
    pub const PROCESS_CODESIGNING: usize = 119;
    pub const PROCESS_EXEC: usize = 120;
    pub const PROCESS_EXEC_INTERPRETER: usize = 121;
    pub const PROCESS_FORK: usize = 122;
    pub const PROCESS_INFO_PIDINFO: usize = 128;
    pub const PROCESS_INFO_CODESIGNATURE: usize = 124;
    pub const PROCESS_LEGACY_CODESIGNING_STATUS_SET: usize = 142;
    pub const NETWORK_INBOUND: usize = 110;
    pub const NVRAM_GET: usize = 115;
    pub const NETWORK_BIND: usize = 111;
    pub const NETWORK_OUTBOUND: usize = 112;
    pub const SIGNAL: usize = 146;
    pub const SOCKET_IOCTL: usize = 147;
    pub const SOCKET_OPTION_GET: usize = 149;
    pub const SOCKET_OPTION_SET: usize = 150;
    pub const SYSCALL_UNIX: usize = 152;
    pub const SYSCALL_MACH: usize = 153;
    pub const SYSCALL_MIG: usize = 154;
    pub const SYSCTL_READ: usize = 156;
    pub const SYSCTL_WRITE: usize = 157;
    pub const SYSTEM_FCNTL: usize = 163;
    pub const SYSTEM_FSCTL: usize = 164;
    pub const SYSTEM_KAS_INFO: usize = 166;
    pub const SYSTEM_MAC_SYSCALL: usize = 173;
    pub const SYSTEM_MEMORYSTATUS_CONTROL: usize = 174;
    pub const SYSTEM_PACKAGE_CHECK: usize = 177;
    pub const SYSTEM_PRIVILEGE: usize = 178;
    pub const SYSTEM_SCHED: usize = 180;
    pub const SYSTEM_SOCKET: usize = 182;
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
    /// A POSIX semaphore's creator (kind 6): its pid and unique id, and
    /// whether it is the calling process.
    pub creator: Option<(i32, u64, bool)>,
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
    /// A vnode operation's vnode (kind 1), and the path a lookup's has once
    /// made canonical (`args[0xf8]`, kept for the profiles after the first).
    pub vnode: Option<SbVnode>,
    pub resolved: std::cell::RefCell<Option<(Vec<u8>, i64)>>,
    /// A socket operation's socket (kind 2).
    pub socket: Option<SbSocket>,
    /// An IOKit operation's object (kind 8).
    pub iokit: Option<sandbox::IoKitObject>,
}

/// What a socket operation's filters read of its socket: whether there is
/// one (`+0xe8`; `socket_check_create` has none yet), its domain, type and
/// protocol (`sock_gettype`, `+0x104`), its local address (`+0xd8`: the
/// hook's, else the socket's name, which the kext fetches when a filter
/// asks, and which an inet socket here always has), the remote one the hook
/// names (`+0xe0`), each as sockaddr bytes, a socket option's level and
/// name (`+0xfc`, `+0xf8`), and an ioctl's command (`+0xf0`).
#[derive(Clone, Debug, Default)]
pub struct SbSocket {
    pub present: bool,
    pub domain: u32,
    pub ty: u32,
    pub protocol: u32,
    pub local: Option<Vec<u8>>,
    pub remote: Option<Vec<u8>>,
    pub option: (u32, u32),
    pub command: u64,
}

/// What a vnode operation's filters read of its vnode (`args[0xd8]`), or
/// of the name under a directory it gives instead (`args[0xe0]`, with the
/// directory at `args[0xd8]`).
#[derive(Clone, Debug, Default)]
pub struct SbVnode {
    /// Its path (`vn_getpath`), canonical; a name's, the directory's path
    /// and the name; a lookup's (`args[0x190]` bit 2), the path it was
    /// given, made canonical when a filter asks.
    pub path: Vec<u8>,
    /// Its mount point's length in the path (`args[0x160]`), -1 when the
    /// path is the mount point's own; a name's, its directory's mount's;
    /// an absolute lookup's, 0.
    pub mount_len: i64,
    pub lookup: bool,
    /// Whether it is a name under a directory.
    pub named: bool,
    /// `enum vtype` (a name's: the one its hook gives, if any), and
    /// whether the vnode is a terminal (`VISTTY`; a name's, its
    /// directory's).
    pub vtype: Option<u32>,
    pub tty: bool,
    /// `va_mode & 0xfff`: none for a name.
    pub mode: Option<u16>,
    /// `va_flags` and `va_rdev` (a name's, its directory's).
    pub flags: u32,
    pub rdev: u32,
    /// The file whose `va_mode` and `va_flags` these are (the vnode's, a
    /// name's directory's): its canonical path and metadata, for its
    /// owner, mode and flags to be read when a filter asks
    /// ([`super::vattr`]), in place of `mode` and `flags`.
    pub of: Option<(String, crate::vfs::Metadata)>,
    /// Its filesystem's name (`vfs_name`).
    pub fs: &'static [u8],
    /// An extended attribute's name (`args[0xe8]`), an ioctl's command
    /// (`args[0x140]`).
    pub xattr: Option<Vec<u8>>,
    pub command: Option<u32>,
}

impl SbVnode {
    /// The vnode at canonical `path`, of type `vtype`, mode `mode` and
    /// file flags `flags`, on the mount it is under.
    pub fn at(path: &str, vtype: u32, tty: bool, mode: u32, flags: u32) -> SbVnode {
        let mnt = super::kern::mount_of(path);
        let mount_len = if path == mnt.on { -1 } else { mnt.on.len() as i64 };
        SbVnode { path: path.as_bytes().to_vec(), mount_len, vtype: Some(vtype), tty, mode: Some((mode & 0xfff) as u16), flags, fs: super::kern::fs_name(mnt), ..Default::default() }
    }
}

/// `getsockaddr` of the `len` bytes the caller's address at `at` has: its
/// length field the length, and AF_UNSPEC an inet socket's AF_INET for a
/// sockaddr_in's length when `translate_unspec`; none when there is none
/// to copy (no address, a length out of bounds, a fault).
fn sockaddr_in(m: &GuestMem<'_>, so: &SbSocket, at: u64, len: u64, translate_unspec: bool) -> Option<Vec<u8>> {
    if at == 0 || !(2..=255).contains(&len) {
        return None;
    }
    let mut sa = m.read(at, len as usize).ok()?.to_vec();
    sa[0] = len as u8;
    if translate_unspec && sa[1] == 0 && so.domain == 2 && len == 16 {
        sa[1] = 2;
    }
    Some(sa)
}

/// The socket behind file `h`, as Sandbox reads it (`sock_gettype`'s
/// domain, type and `pr_protocol`, and an inet socket's name); none for a
/// file that is no socket.
pub fn sb_socket(h: &Arc<dyn crate::vfs::FileHandle>) -> Option<SbSocket> {
    let so = |domain, ty, protocol, local| Some(SbSocket { present: true, domain, ty, protocol, local, ..Default::default() });
    if Arc::clone(h).as_unix_dgram().is_some() {
        return so(1, 2, 0, None);
    }
    if Arc::clone(h).as_unix_socket().is_some() || Arc::clone(h).as_remote_unix().is_some() {
        return so(1, 1, 0, None);
    }
    let s = Arc::clone(h).as_inet_socket()?;
    let (ip, port) = s.local();
    let (ty, protocol) = if s.kind == crate::net::Kind::Udp { (2, 17) } else { (1, 6) };
    so(2, ty, protocol, Some(super::sockaddr::out_inet(ip, port)))
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

    /// Process `t`'s relation `which` to the subject (`0x...a05584`): 1,
    /// it is the subject; 2, in its process group; 3, in another; 4, its
    /// child; 5, of the same sandbox (the one evaluated with, none being
    /// one); 6, the initial process; 7, platform code.
    fn relation(&mut self, t: i32, which: u16) -> bool {
        let me = self.k.pid;
        let pgrp = |k: &Kernel, pid: i32| k.procs.pgid(pid, pid).ok();
        match which {
            1 => t == me,
            2 => pgrp(self.k, t) == pgrp(self.k, me),
            3 => pgrp(self.k, t) != pgrp(self.k, me),
            4 => self.k.procs.ppid(t) == me,
            // The target's credential's sandbox is the very one.
            5 => {
                let theirs = if t == me { self.k.darwin_sandbox() } else { self.k.darwin_proc_find(t).and_then(|p| super::sandboxes::of(&p.sandbox)) };
                match (theirs, self.sb) {
                    (Some(a), Some(b)) => std::ptr::eq(Arc::as_ptr(&a), b),
                    (None, None) => true,
                    _ => false,
                }
            }
            6 => t == crate::proc::INIT_PID,
            _ => self.sig_of(t).flatten().is_some_and(|c| c.platform_binary),
        }
    }

    /// Another process's signature, by its pid (`proc_find`: none for one
    /// that has exited).
    fn sig_of(&mut self, pid: i32) -> Option<Option<Arc<super::codesign::CodeSign>>> {
        if pid == self.k.pid {
            return Some(self.k.dtask.codesign.clone().map(Arc::new));
        }
        self.k.darwin_proc_find(pid).map(|p| p.codesign)
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
        let t = self.a.target.unwrap_or(0);
        Ok(self.relation(t, which))
    }
    /// The semaphore's creator (`0x...a04ac0`): the calling process, or
    /// the live process of its pid whose unique id is the one recorded (a
    /// unique id of zero, a process gone, or one that has since taken the
    /// pid, matches nothing).
    fn creator_is(&mut self, which: u16) -> Result<bool, Stop> {
        let Some((pid, uniqueid, current)) = self.a.creator else { return Ok(false) };
        let t = if current {
            self.k.pid
        } else {
            if uniqueid == 0 {
                return Ok(false);
            }
            let theirs = if pid == self.k.pid { Some(self.k.dtask.uniqueid) } else { self.k.darwin_proc_find(pid).map(|p| p.uniqueid) };
            if theirs != Some(uniqueid) {
                return Ok(false);
            }
            pid
        };
        Ok(self.relation(t, which))
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
    fn iokit(&self) -> Option<sandbox::IoKitObject> {
        self.a.iokit.clone()
    }
    fn socket(&self) -> Option<sandbox::SocketType> {
        let s = self.a.socket.as_ref()?;
        Some(sandbox::SocketType { present: s.present, domain: s.domain, ty: s.ty, protocol: s.protocol })
    }
    fn socket_local(&mut self) -> Result<Option<Vec<u8>>, Stop> {
        Ok(self.a.socket.as_ref().and_then(|s| s.local.clone()))
    }
    fn socket_remote(&self) -> Option<Vec<u8>> {
        self.a.socket.as_ref().and_then(|s| s.remote.clone())
    }
    fn socket_option(&self) -> (u32, u32) {
        self.a.socket.as_ref().map_or((0, 0), |s| s.option)
    }
    fn socket_command(&self) -> u64 {
        self.a.socket.as_ref().map_or(0, |s| s.command)
    }
    fn host_address(&mut self, sa: &[u8]) -> Result<bool, Stop> {
        // The unspecified address is the host's; an interface's are not
        // modelled (only lo0 is, and not its addresses).
        match sa.get(1).copied().map(u32::from) {
            Some(2) if sa.len() >= 8 => {
                if sa[4..8] == [0; 4] {
                    return Ok(true);
                }
            }
            Some(30) if sa.len() >= 24 => {
                if sa[8..24] == [0; 16] {
                    return Ok(true);
                }
            }
            _ => return Ok(false),
        }
        Err(Stop::Unported("sandbox: whether an address is one of the host's interfaces' (ifnet_list_get)".into()))
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
        // (a vnode operation's `args[0x140]`, zero but for an ioctl's)
        if self.a.kind == sandbox::kind::VNODE {
            return Ok(Some(self.a.vnode.as_ref().and_then(|v| v.command).unwrap_or(0)));
        }
        Ok(matches!(self.a.kind, sandbox::kind::FSCTL | sandbox::kind::PRIVILEGE).then_some(self.a.number))
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
        Ok(self.a.vnode.as_ref().and_then(|v| v.vtype.map(|t| (t, v.tty))))
    }
    fn vnode_rdev(&mut self) -> Result<Option<u32>, Stop> {
        Ok(self.a.vnode.as_ref().map(|v| v.rdev))
    }
    /// The IOMedia whose `BSD Major` and `BSD Minor` are the device's:
    /// none, as no disk's node is made here (`devfs.rs`).
    fn media_device(&mut self, _rdev: u32, _class: &[u8]) -> Result<bool, Stop> {
        Ok(false)
    }
    /// A lookup's path (`0x...3874`, then `0x...a14b1c`) is made canonical
    /// once: the "`..`" after a component is checked first, and its error
    /// refuses as a filter helper's does.
    fn path(&mut self) -> Result<Option<(Vec<u8>, i64)>, Stop> {
        let a = self.a;
        let Some(v) = a.vnode.as_ref() else { return Ok(None) };
        if !v.lookup {
            return Ok(Some((v.path.clone(), v.mount_len)));
        }
        if let Some(p) = a.resolved.borrow().clone() {
            return Ok(Some(p));
        }
        let path = self.k.darwin_sb_canonical(&v.path).map_err(|errno| Stop::Refuse(sandbox::Decision { errno, flags: 5 }))?;
        let mount_len = if v.mount_len != 0 && v.mount_len == path.len() as i64 { -1 } else { v.mount_len };
        *a.resolved.borrow_mut() = Some((path.clone(), mount_len));
        Ok(Some((path, mount_len)))
    }
    fn vnode_mode(&mut self) -> Result<Option<u16>, Stop> {
        let Some(v) = self.a.vnode.as_ref() else { return Ok(None) };
        if v.mode.is_none() {
            return Ok(None);
        }
        match self.k.darwin_sb_attrs(v).map_err(Stop::Unported)? {
            Some(o) => Ok(Some((o.mode & 0xfff) as u16)),
            None => Ok(v.mode),
        }
    }
    fn vnode_flags(&mut self) -> Result<Option<u32>, Stop> {
        let Some(v) = self.a.vnode.as_ref() else { return Ok(None) };
        match self.k.darwin_sb_attrs(v).map_err(Stop::Unported)? {
            Some(o) => Ok(Some(o.flags)),
            None => Ok(Some(v.flags)),
        }
    }
    fn xattr_name(&mut self) -> Option<Vec<u8>> {
        self.a.vnode.as_ref().and_then(|v| v.xattr.clone())
    }
    fn filesystem_name(&mut self) -> Result<Option<Vec<u8>>, Stop> {
        Ok(self.a.vnode.as_ref().map(|v| v.fs.to_vec()))
    }
    fn holds_extensions(&mut self) -> bool {
        self.sb.is_some_and(|s| !s.extensions.is_empty())
    }
    fn extension_paths(&mut self, class: Option<&[u8]>) -> Vec<Vec<u8>> {
        let Some(s) = self.sb else { return Vec::new() };
        s.extensions.iter().filter(|e| class.is_none_or(|c| e.class == c)).map(|e| e.path.clone()).collect()
    }
    fn category_extension_paths(&mut self, category: &[u8]) -> Vec<Vec<u8>> {
        let Some(s) = self.sb else { return Vec::new() };
        s.extensions.iter().filter(|e| e.category.as_deref() == Some(category)).map(|e| e.path.clone()).collect()
    }
    /// The vnode's class (`0x...78cc`): a file Sandbox protects
    /// (SF_RESTRICTED, SF_NOUNLINK) or a data vault (UF_DATAVAULT) is
    /// classed by those first, which is not ported; any other has the class
    /// the platform profile's storage-class-map names for it, or none.
    fn storage_class(&mut self) -> Result<Option<Vec<u8>>, Stop> {
        let Some(v) = self.a.vnode.clone() else { return Ok(None) };
        // (a name is classed by the map alone)
        if !v.named {
            let flags = self.k.darwin_sb_attrs(&v).map_err(Stop::Unported)?.map_or(v.flags, |o| o.flags);
            if flags & 0x0018_0080 != 0 {
                return Err(Stop::Unported(format!("sandbox: the storage class of a file with flags {flags:#x}")));
            }
        }
        let Some(Some((blob, profile))) = PLATFORM.get() else {
            return Err(Stop::Unported("the Sandbox's platform profile (the boot payload's Sandbox/Platform)".into()));
        };
        // (a lookup's path made canonical once, for both)
        let a = SbArgs { kind: sandbox::kind::VNODE, vnode: Some(v), resolved: self.a.resolved.clone(), ..Default::default() };
        let mut scratch = sandbox::Scratch::default();
        let out = sandbox::evaluate(blob, profile, op::STORAGE_CLASS_MAP, &mut KernelFacts { k: &mut *self.k, a: &a, sb: self.sb }, &mut scratch);
        if self.a.resolved.borrow().is_none() {
            *self.a.resolved.borrow_mut() = a.resolved.borrow().clone();
        }
        match out {
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
            if let Some(id) = self.sig_of(pid).flatten().and_then(|c| c.identity.clone()) {
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
        Ok(self.sig_of(t).flatten().and_then(|c| c.identity.clone()))
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
    /// The storage class the platform profile's storage-class-map gives
    /// vnode `v`, evaluated with sandbox `sb`; none for the default. What
    /// it cannot decide is the error.
    pub(crate) fn darwin_sb_storage_class(&mut self, sb: Option<&Sandbox>, v: SbVnode) -> Result<Option<Vec<u8>>, String> {
        let a = SbArgs { kind: sandbox::kind::VNODE, vnode: Some(v), ..Default::default() };
        match (KernelFacts { k: self, a: &a, sb }).storage_class() {
            Ok(c) => Ok(c),
            Err(Stop::Unported(what)) => Err(what),
            Err(Stop::Refuse(d)) => Err(format!("sandbox: the storage class map's refusal (errno {})", d.errno)),
        }
    }

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
        // An allowed call of a mask's kind its flags report is let through
        // the sandbox's mask from now on (`0x...9f3a90`): not the platform
        // profile's masks, which a sandbox may share.
        if errno == 0 && flags & 0x0100_0084 != 0 {
            let slot = match (op, a.kind) {
                (op::SYSCALL_UNIX, _) => Some(0),
                (op::SYSCALL_MACH, _) => Some(1),
                (op::SYSCALL_MIG, sandbox::kind::SYSCALL_MIG) => Some(2),
                (op::SYSTEM_FCNTL, sandbox::kind::FCNTL) => Some(3),
                _ => None,
            };
            if let (Some(i), Some(sb)) = (slot, sb) {
                let number = if i == 3 { a.number as i32 as i64 as u64 } else { u64::from(a.number) };
                let platform = platform_masks();
                if let Some(mask) = &sb.masks[i] {
                    if (number as usize) < sandbox::MASK_BYTES * 8 && !platform.iter().flatten().any(|p| Arc::ptr_eq(p, mask)) {
                        sandbox::mask_set(mask, number as usize);
                    }
                }
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

    /// `mac_iokit_check_open_service` (Sandbox's hook, slot 201; AMFI has
    /// none): iokit-open-service of the service, with the user client type
    /// the open asks for.
    pub(crate) fn darwin_mac_check_iokit_open_service(&mut self, service: sandbox::IoKitObject, ty: u32) -> u32 {
        let a = SbArgs { kind: sandbox::kind::IOKIT, iokit: Some(sandbox::IoKitObject { client_type: ty, ..service }), ..Default::default() };
        self.darwin_sb_evaluate(op::IOKIT_OPEN_SERVICE, &a)
    }

    /// `mac_iokit_check_open` (slot 317): iokit-open-user-client of the new
    /// client (the type is not passed on).
    pub(crate) fn darwin_mac_check_iokit_open(&mut self, client: sandbox::IoKitObject) -> u32 {
        let a = SbArgs { kind: sandbox::kind::IOKIT, iokit: Some(client), ..Default::default() };
        self.darwin_sb_evaluate(op::IOKIT_OPEN_USER_CLIENT, &a)
    }

    /// Sandbox's IOUserClient filter resolver (`0x...9f3b14`, which it
    /// registers with `IOUserClient::registerFilterCallbacks`), asked at an
    /// open the MAC check allowed: iokit-open-user-client of the client
    /// again, whose modifier would associate the client's call filters;
    /// this collection's profiles associate none, so an allowance is
    /// kIOReturnUnsupported (the open goes on with no filter). A denial
    /// (EPERM) is kIOReturnNotPermitted, another error
    /// kIOReturnInternalError.
    pub(crate) fn darwin_sb_iokit_resolve(&mut self, client: sandbox::IoKitObject) -> i32 {
        const K_IO_RETURN_UNSUPPORTED: i32 = 0xe00002c7_u32 as i32;
        const K_IO_RETURN_NOT_PERMITTED: i32 = 0xe00002e2_u32 as i32;
        const K_IO_RETURN_INTERNAL_ERROR: i32 = 0xe00002c9_u32 as i32;
        let a = SbArgs { kind: sandbox::kind::IOKIT, iokit: Some(client), ..Default::default() };
        match self.darwin_sb_evaluate(op::IOKIT_OPEN_USER_CLIENT, &a) {
            0 => K_IO_RETURN_UNSUPPORTED,
            1 => K_IO_RETURN_NOT_PERMITTED,
            _ => K_IO_RETURN_INTERNAL_ERROR,
        }
    }

    /// `mac_iokit_check_get_property` (slot 334): nvram-get of the name for
    /// the NVRAM entry (`0x...9f2940`: IODTNVRAM, which is `/options`), but
    /// for the twelve names of the registry's own (`0x...9f2990`); else
    /// iokit-get-properties of the entry and the name.
    pub(crate) fn darwin_mac_check_iokit_get_property(&mut self, entry: sandbox::IoKitObject, nvram: bool, name: &[u8]) -> u32 {
        const REGISTRY_NAMES: [&[u8]; 12] = [
            b"BSD Major",
            b"BSD Minor",
            b"BSD Name",
            b"BSD Names",
            b"BSD Unit",
            b"IOClassNameOverride",
            b"IOMatchCategory",
            b"IONameMatch",
            b"IORegistryEntryAllowableSetProperties",
            b"IORegistryEntryDefaultLockingSetProperties",
            b"IOUserServiceProperties",
            b"exclave-assigned",
        ];
        if nvram && !REGISTRY_NAMES.contains(&name) {
            let a = SbArgs { kind: sandbox::kind::NVRAM, string: Some(name.to_vec()), ..Default::default() };
            return self.darwin_sb_evaluate(op::NVRAM_GET, &a);
        }
        let a = SbArgs { kind: sandbox::kind::IOKIT, iokit: Some(sandbox::IoKitObject { property: Some(name.to_vec()), ..entry }), ..Default::default() };
        self.darwin_sb_evaluate(op::IOKIT_GET_PROPERTIES, &a)
    }

    /// The socket of descriptor `fd`, as its operations' filters read it
    /// ([`SbSocket`]); none for a descriptor that is no socket.
    pub(crate) fn darwin_sb_socket_of(&self, fd: i32) -> Option<SbSocket> {
        let f = self.fd_io().fds.get(fd).ok()?;
        sb_socket(&f.handle)
    }

    /// Sandbox's socket hooks' common part (`0x...a00b50`): operation `op`
    /// of socket `so` (no user socket is the kernel's), with the local and
    /// remote addresses the hook names.
    fn darwin_sb_socket(&mut self, op: usize, mut so: SbSocket, local: Option<Vec<u8>>, remote: Option<Vec<u8>>) -> u32 {
        if local.is_some() {
            so.local = local;
        }
        so.remote = remote;
        let a = SbArgs { kind: sandbox::kind::SOCKET, socket: Some(so), ..Default::default() };
        self.darwin_sb_evaluate(op, &a)
    }

    /// The socket calls' MAC checks, at the places XNU makes them, before
    /// the protocols' own refusals; the error of a refusal. A descriptor
    /// that is no socket, or an address the call cannot copy in, is not
    /// asked about: the call fails as it would.
    pub(crate) fn darwin_sb_socket_call(&mut self, m: &GuestMem<'_>, raw: u64, a: &[u64; 6]) -> Option<crate::errno::Errno> {
        use super::sysno as sys;
        let refusal = |e: u32| (e != 0).then(|| super::errno::errno_of(e as i32));
        let so = |k: &Kernel| k.darwin_sb_socket_of(a[0] as i32);
        let e = match raw {
            // socket_common, first (socketpair has no check).
            sys::SOCKET => self.darwin_mac_check_socket_create(a[0] as u32, a[1] as u32, a[2] as u32),
            // bind, with its address (getsockaddr, AF_UNSPEC an inet
            // socket's AF_INET); an AF_SYSTEM one is not asked about.
            sys::BIND => {
                let so = so(self)?;
                let sa = sockaddr_in(m, &so, a[1], a[2], true)?;
                if u32::from(sa[1]) == 32 {
                    return None;
                }
                let unix = so.domain == 1;
                match self.darwin_mac_check_socket_bind(so, sa.clone()) {
                    // unp_bind's lookup and checks of a unix socket's name.
                    0 if unix => return self.darwin_sb_unix_name(a[0] as i32, &sa, true).err(),
                    e => e,
                }
            }
            sys::LISTEN => {
                let so = so(self)?;
                self.darwin_mac_check_socket_inbound(so)
            }
            // connectit (getsockaddr_s, AF_UNSPEC translated for a stream
            // socket).
            sys::CONNECT | sys::CONNECT_NOCANCEL => {
                let so = so(self)?;
                let dgram = so.ty == 2;
                let sa = sockaddr_in(m, &so, a[1], a[2], !dgram)?;
                let unix = so.domain == 1;
                match self.darwin_mac_check_socket_connect(so, sa.clone()) {
                    // unp_connect's lookup and check of the socket's file.
                    0 if unix => return self.darwin_sb_unix_name(a[0] as i32, &sa, false).err(),
                    e => e,
                }
            }
            // sendit, for a call naming a destination.
            sys::SENDTO | sys::SENDTO_NOCANCEL => {
                let so = so(self)?;
                let sa = sockaddr_in(m, &so, a[4], a[5], true)?;
                self.darwin_mac_check_socket_send(so, sa)
            }
            sys::SENDMSG | sys::SENDMSG_NOCANCEL => {
                let so = so(self)?;
                // struct msghdr: msg_name, then msg_namelen.
                let (name, len) = (m.read_u64(a[1]).ok()?, m.read_u32(a[1] + 8).ok()?);
                let sa = sockaddr_in(m, &so, name, u64::from(len), true)?;
                self.darwin_mac_check_socket_send(so, sa)
            }
            // recvit, for a socket that is not connected and whose protocol
            // does not ask it to be (an unconnected UDP socket here; unix
            // sockets' operations are always allowed).
            sys::RECVFROM | sys::RECVFROM_NOCANCEL | sys::RECVMSG | sys::RECVMSG_NOCANCEL => {
                let so = so(self)?;
                let f = self.fd_io().fds.get(a[0] as i32).ok()?;
                let inet = Arc::clone(&f.handle).as_inet_socket()?;
                if inet.kind != crate::net::Kind::Udp || inet.peer().is_some() {
                    return None;
                }
                self.darwin_mac_check_socket_inbound(so)
            }
            // setsockopt, past its EFAULT for a null value of a length;
            // getsockopt, past its copyin of the length.
            sys::SETSOCKOPT => {
                if a[3] == 0 && a[4] != 0 {
                    return None;
                }
                let so = so(self)?;
                self.darwin_mac_check_sockopt(so, true, a[1] as u32, a[2] as u32)
            }
            sys::GETSOCKOPT => {
                if a[4] != 0 && m.read_u32(a[4]).is_err() {
                    return None;
                }
                let so = so(self)?;
                self.darwin_mac_check_sockopt(so, false, a[1] as u32, a[2] as u32)
            }
            _ => return None,
        };
        refusal(e)
    }

    /// `mac_socket_check_create` (Sandbox's hook, slot 177): a unix, inet
    /// or inet6 stream or datagram socket is not asked about; another is
    /// system-socket of its domain, type and protocol.
    pub(crate) fn darwin_mac_check_socket_create(&mut self, domain: u32, ty: u32, protocol: u32) -> u32 {
        if domain <= 30 && (1u32 << domain) & 0x4000_0006 != 0 && matches!(ty, 1 | 2) {
            return 0;
        }
        let socket = SbSocket { domain, ty, protocol, ..Default::default() };
        let a = SbArgs { kind: sandbox::kind::SOCKET, socket: Some(socket), ..Default::default() };
        self.darwin_sb_evaluate(op::SYSTEM_SOCKET, &a)
    }

    /// `mac_socket_check_bind` (slot 175): network-bind of the address.
    pub(crate) fn darwin_mac_check_socket_bind(&mut self, so: SbSocket, addr: Vec<u8>) -> u32 {
        self.darwin_sb_socket(op::NETWORK_BIND, so, Some(addr), None)
    }

    /// `mac_socket_check_connect` (slot 176): network-outbound of the
    /// address, none asked of an address shorter than its family's field
    /// or of AF_UNSPEC.
    pub(crate) fn darwin_mac_check_socket_connect(&mut self, so: SbSocket, addr: Vec<u8>) -> u32 {
        if addr.len() < 2 || addr[0] < 2 || addr[1] == 0 {
            return 0;
        }
        self.darwin_sb_socket(op::NETWORK_OUTBOUND, so, None, Some(addr))
    }

    /// `mac_socket_check_listen` and `mac_socket_check_receive` (slots 181
    /// and 182): network-inbound.
    pub(crate) fn darwin_mac_check_socket_inbound(&mut self, so: SbSocket) -> u32 {
        self.darwin_sb_socket(op::NETWORK_INBOUND, so, None, None)
    }

    /// `mac_socket_check_send` (slot 185): network-outbound of the address.
    pub(crate) fn darwin_mac_check_socket_send(&mut self, so: SbSocket, addr: Vec<u8>) -> u32 {
        self.darwin_sb_socket(op::NETWORK_OUTBOUND, so, None, Some(addr))
    }

    /// `mac_socket_check_setsockopt` and `_getsockopt` (slots 187 and 188):
    /// socket-option-set or -get of the option's level and name.
    pub(crate) fn darwin_mac_check_sockopt(&mut self, mut so: SbSocket, set: bool, level: u32, name: u32) -> u32 {
        so.option = (level, name);
        let a = SbArgs { kind: sandbox::kind::SOCKET, socket: Some(so), ..Default::default() };
        self.darwin_sb_evaluate(if set { op::SOCKET_OPTION_SET } else { op::SOCKET_OPTION_GET }, &a)
    }

    /// `mac_socket_check_ioctl` (slot 212): socket-ioctl of the command,
    /// but for FIOASYNC, FIONBIO, FIODTYPE and FIONREAD, and an AF_AFP
    /// (36) stream socket of protocol 250.
    pub(crate) fn darwin_mac_check_socket_ioctl(&mut self, mut so: SbSocket, command: u64) -> u32 {
        if matches!(command, 0x8004_667d | 0x8004_667e | 0x4004_667a | 0x4004_667f) {
            return 0;
        }
        if (so.domain, so.ty, so.protocol) == (36, 1, 250) {
            return 0;
        }
        so.command = command;
        let a = SbArgs { kind: sandbox::kind::SOCKET, socket: Some(so), ..Default::default() };
        self.darwin_sb_evaluate(op::SOCKET_IOCTL, &a)
    }

    /// `priv_check_cred(cred, priv, flags)` (kern_priv.c): the MAC policies'
    /// `mac_priv_check` may deny (Sandbox's system-privilege of the
    /// privilege, slot 313, its errno, root's too); root has every privilege
    /// but with PRIVCHECK_DEFAULT_UNPRIVILEGED_FLAG; else a policy's
    /// `mac_priv_grant` may grant it (Sandbox's system-privilege again,
    /// quietly, slot 314: granted when the decision's flags have bit 1);
    /// else EPERM. AMFI has neither hook.
    pub(crate) fn darwin_priv_check_cred(&mut self, privilege: u32, flags: u32) -> Result<(), u32> {
        const PRIVCHECK_DEFAULT_UNPRIVILEGED_FLAG: u32 = 1;
        let a = SbArgs { kind: sandbox::kind::PRIVILEGE, number: privilege, ..Default::default() };
        let e = self.darwin_sb_evaluate(op::SYSTEM_PRIVILEGE, &a);
        if e != 0 {
            return Err(e);
        }
        if flags & PRIVCHECK_DEFAULT_UNPRIVILEGED_FLAG == 0 && self.creds.uid() == 0 {
            return Ok(());
        }
        let sb = self.darwin_sandbox();
        let (_, granted, _) = self.darwin_sb_evaluate_with(sb.as_ref(), op::SYSTEM_PRIVILEGE, &SbArgs { quiet: true, ..a });
        if granted & 0x2 != 0 {
            return Ok(());
        }
        Err(e::EPERM)
    }

    /// `mac_task_check_get_task_special_port` and `_set_` (Sandbox's hooks,
    /// slots 74 and 75): mach-task-special-port-get or -set of process
    /// `pid`'s task, for a port number that fits 16 bits (ENOTSUP for
    /// another).
    pub(crate) fn darwin_mac_check_task_special_port(&mut self, pid: i32, which: i32, set: bool) -> u32 {
        if (which as u32) >> 16 != 0 {
            return e::ENOTSUP;
        }
        let a = SbArgs { kind: sandbox::kind::PROCESS, target: Some(pid), ..Default::default() };
        self.darwin_sb_evaluate(if set { op::MACH_TASK_SPECIAL_PORT_SET } else { op::MACH_TASK_SPECIAL_PORT_GET }, &a)
    }

    /// `mac_task_check_set_host_exception_ports`: Sandbox's hook (slot 127,
    /// mach-host-exception-port-set) for each exception type of `mask`, the
    /// first refusal the answer.
    pub(crate) fn darwin_mac_check_set_host_exception_ports(&mut self, mask: u32) -> u32 {
        const EXC_TYPES_COUNT: u32 = 14;
        for exception in 1..EXC_TYPES_COUNT {
            if mask & (1 << exception) != 0 {
                let e = self.darwin_sb_evaluate(op::MACH_HOST_EXCEPTION_PORT_SET, &SbArgs::default());
                if e != 0 {
                    return e;
                }
            }
        }
        0
    }

    /// `mac_proc_check_memorystatus_control` (slot 198):
    /// system-memorystatus-control of the command.
    pub(crate) fn darwin_mac_check_memorystatus_control(&mut self, command: u32) -> u32 {
        let a = SbArgs { kind: sandbox::kind::MEMORYSTATUS, number: command, ..Default::default() };
        self.darwin_sb_evaluate(op::SYSTEM_MEMORYSTATUS_CONTROL, &a)
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

    /// `mac_proc_check_get_task` for the task port of flavor `f` of the
    /// process `ident` names (`proc_ident` of the one the caller found):
    /// AMFI's (the caller's entitlements, the target's), then Sandbox's
    /// operation for the flavor. ESRCH when `proc_find_ident` no longer
    /// finds it (it has exited, or its pid is another's).
    pub(crate) fn darwin_mac_check_get_task(&mut self, ident: super::procinfo::ProcIdent, f: u32) -> u32 {
        let pid = ident.pid;
        let caller = self.dtask.codesign.as_ref().map(|c| c.ents.clone()).unwrap_or_default();
        let target = if pid == self.pid {
            Some(self.dtask.codesign.as_ref().map(|c| c.ents.clone()))
        } else {
            self.darwin_proc_find_ident(ident).map(|p| p.codesign.map(|c| c.ents.clone()))
        };
        let Some(target) = target else { return e::ESRCH };
        let target = target.unwrap_or_default();
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
        assert_eq!(SbVnode::at("/dev/null", 4, false, 0o20666, 0).mode, Some(0o666));
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
