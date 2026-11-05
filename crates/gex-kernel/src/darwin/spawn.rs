//! `posix_spawn` (`bsd/kern/kern_exec.c`): a new process made by
//! `fork1(PROC_CREATE_SPAWN)` with none of the caller's memory, its
//! descriptors changed by the file actions, its image activated in its own
//! namespace from the caller's strings, and the attributes applied.
//!
//! Everything that can fail does so in the caller's call, and the child it
//! made then goes without its parent seeing it (`P_LIST_DEADPARENT`). The
//! host loads the image and starts the child on success.

use super::execve::Image;
use crate::errno::Errno;
use crate::syscalls::{nr, Kernel, SyscallOutcome};
use crate::GuestMem;

/// `posix_spawn` flags (`bsd/sys/spawn.h`).
pub mod flag {
    pub const RESETIDS: u16 = 0x0001;
    pub const SETPGROUP: u16 = 0x0002;
    pub const SETSIGDEF: u16 = 0x0004;
    pub const SETSIGMASK: u16 = 0x0008;
    pub const SETEXEC: u16 = 0x0040;
    pub const START_SUSPENDED: u16 = 0x0080;
    pub const NANO_ALLOCATOR: u16 = 0x0200;
    pub const SETSID: u16 = 0x0400;
    pub const CLOEXEC_DEFAULT: u16 = 0x4000;
}

/// `PSFA_*`.
mod psfa {
    pub const OPEN: u32 = 0;
    pub const CLOSE: u32 = 1;
    pub const DUP2: u32 = 2;
    pub const INHERIT: u32 = 3;
    pub const FILEPORT_DUP2: u32 = 4;
    pub const CHDIR: u32 = 5;
    pub const FCHDIR: u32 = 6;
}

/// The sizes of the structures passed in, as an arm64 process lays them
/// out (`bsd/sys/spawn_internal.h`).
const ARGS_DESC_SIZE: usize = 144;
/// `offsetof(struct _posix_spawnattr, psa_ports)`: what of the attributes
/// is copied in.
const ATTR_SIZE: usize = 192;
const PSFA_ACTION_SIZE: u64 = 1040;
const PSFA_HDR: u64 = 8;
const PORT_ACTION_SIZE: u64 = 24;
const PORT_HDR: u64 = 8;
const MAC_EXT_SIZE: u64 = 144;
const MAC_HDR: u64 = 8;
const PERSONA_INFO_SIZE: u64 = 88;
const POSIX_CRED_INFO_SIZE: u64 = 340;
/// `PATH_MAX`, and `NGROUPS_MAX`.
const PATH_MAX: usize = 1024;
const NGROUPS_MAX: u32 = 16;
/// `CPU_TYPE_ANY`.
const CPU_TYPE_ANY: u32 = u32::MAX;
/// `POSIX_SPAWN_PROC_TYPE_MASK`, `_DRIVER`, `POSIX_SPAWN_JETSAM_SET`.
const PROC_TYPE_MASK: u32 = 0xf00;
const PROC_TYPE_DRIVER: u32 = 0x700;
const JETSAM_SET: u16 = 0x8000;
/// `PSA_OPTION_DATALESS_IOPOLICY`.
const PSA_OPTION_DATALESS_IOPOLICY: u32 = 0x4;
/// `POSIX_SPAWN_POSIX_CRED_GROUPS`.
const POSIX_CRED_GROUPS: u32 = 0x0004_0000;

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// `struct _posix_spawnattr`, the parts the kernel acts on.
#[derive(Clone, Debug, Default)]
pub struct Attr {
    pub flags: u16,
    pub sigdefault: u32,
    pub sigmask: u32,
    pub pgroup: i32,
    /// `psa_binprefs` and `psa_subcpuprefs`.
    pub binprefs: [(u32, u32); 4],
    pub apptype: u32,
    pub cpumonitor_percent: u64,
    pub jetsam_flags: u16,
    pub qos_clamp: u64,
    pub darwin_role: u32,
    pub thread_limit: i32,
    pub options: u32,
    pub limits: [u32; 6],
    pub crash_behavior: u32,
}

impl Attr {
    fn parse(b: &[u8]) -> Attr {
        let mut binprefs = [(0, 0); 4];
        for (i, p) in binprefs.iter_mut().enumerate() {
            *p = (le32(b, 16 + 4 * i), le32(b, 112 + 4 * i));
        }
        Attr {
            flags: le16(b, 0),
            sigdefault: le32(b, 4),
            sigmask: le32(b, 8),
            pgroup: le32(b, 12) as i32,
            binprefs,
            apptype: le32(b, 36),
            cpumonitor_percent: le64(b, 40),
            jetsam_flags: le16(b, 64),
            qos_clamp: le64(b, 80),
            darwin_role: le32(b, 88),
            thread_limit: le32(b, 92) as i32,
            options: le32(b, 128),
            limits: [le32(b, 132), le32(b, 136), le32(b, 140), le32(b, 144), le32(b, 180), le32(b, 184)],
            crash_behavior: le32(b, 148),
        }
    }
}

/// What the child takes from its spawn once its image has switched in:
/// the attributes applied after `execsigs`, and the descriptors
/// `POSIX_SPAWN_CLOEXEC_DEFAULT` lets through (`UF_INHERIT`).
#[derive(Clone, Debug, Default)]
pub struct After {
    pub flags: u16,
    pub sigmask: u32,
    pub sigdefault: u32,
    pub inherit: Vec<i32>,
}

/// A small memory holding a path, for the calls that read one from the
/// caller.
struct Scratch(Vec<u8>);

impl Scratch {
    /// Where the path is.
    const AT: u64 = 16;

    fn path(p: &[u8]) -> Scratch {
        let mut b = vec![0u8; Self::AT as usize + PATH_MAX + 1];
        let n = p.iter().position(|&c| c == 0).unwrap_or(p.len()).min(PATH_MAX);
        b[Self::AT as usize..Self::AT as usize + n].copy_from_slice(&p[..n]);
        Scratch(b)
    }
}

impl Kernel {
    /// `forkproc` of this process's Darwin state: what a child takes (its
    /// signal actions, limits, the pthread registration's sizes and the
    /// dispatch queue offsets); the rest is the new task's own.
    pub(crate) fn darwin_fork_task(&self) -> super::Task {
        let t = &self.dtask;
        super::Task {
            strict: t.strict,
            sigacts: t.sigacts.clone(),
            rlimits: t.rlimits,
            dispatchqueue_serialno_offset: t.dispatchqueue_serialno_offset,
            dispatchqueue_label_offset: t.dispatchqueue_label_offset,
            ..super::Task::new_process()
        }
    }

    /// `posix_spawn(pid, path, adesc, argv, envp)`.
    pub(crate) fn darwin_posix_spawn(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> SyscallOutcome {
        match self.darwin_spawn(m, a) {
            Ok(child) => {
                self.darwin_spawned = Some(Box::new(child));
                let _ = super::set_result(m, self.ctx_addr, 0);
                SyscallOutcome::DarwinSpawn { pid_addr: a[0] }
            }
            Err(e) => {
                let _ = super::set_result(m, self.ctx_addr, e.as_return());
                SyscallOutcome::Continue
            }
        }
    }

    fn darwin_spawn(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<Kernel, Errno> {
        let (path, adesc, argv, envv) = (a[1], a[2], a[3], a[4]);
        let mut attr = None;
        let mut file_actions = None;
        let mut coal_info = 0;
        if adesc != 0 {
            let d = m.read(adesc, ARGS_DESC_SIZE)?.to_vec();
            let pair = |i: usize| (le64(&d, 16 * i), le64(&d, 16 * i + 8));
            let (attr_size, attrp) = pair(0);
            let (fa_size, fa) = pair(1);
            let (pa_size, pa) = pair(2);
            let (mx_size, mx) = pair(3);
            let (_, coal) = pair(4);
            let (persona_size, persona) = pair(5);
            let (cred_size, cred) = pair(6);
            let (root_size, _) = pair(7);
            coal_info = coal;
            if attr_size != 0 {
                attr = Some(Attr::parse(m.read(attrp, ATTR_SIZE)?));
            }
            if fa_size != 0 {
                let nofile = self.dtask.rlimits.cur(super::rlimit::res::NOFILE).min(super::rlimit::MAXFILESPERPROC);
                let max = PSFA_HDR + PSFA_ACTION_SIZE * nofile;
                if fa_size < PSFA_HDR + PSFA_ACTION_SIZE || fa_size > max {
                    return Err(Errno::EINVAL);
                }
                let b = m.read(fa, fa_size as usize)?.to_vec();
                if PSFA_HDR + PSFA_ACTION_SIZE * u64::from(le32(&b, 4)) != fa_size {
                    return Err(Errno::EINVAL);
                }
                file_actions = Some(b);
            }
            if pa_size != 0 {
                if pa_size < PORT_HDR + PORT_ACTION_SIZE || pa_size > super::exec::PAGE_SIZE {
                    return Err(Errno::EINVAL);
                }
                let b = m.read(pa, pa_size as usize)?;
                if PORT_HDR + PORT_ACTION_SIZE * u64::from(le32(b, 4)) != pa_size {
                    return Err(Errno::EINVAL);
                }
                // The special, exception and registered ports name rights of
                // this task for the child's: a port in two tasks' spaces.
                self.darwin_unimplemented("posix_spawn port actions (a right passed to another task's space)".into());
                return Err(Errno::EINVAL);
            }
            if persona_size != 0 && persona != 0 {
                if persona_size != PERSONA_INFO_SIZE {
                    return Err(Errno::ERANGE);
                }
                self.darwin_unimplemented("posix_spawn into a persona (personas)".into());
                return Err(Errno::EINVAL);
            }
            if cred_size != 0 && cred != 0 {
                if cred_size != POSIX_CRED_INFO_SIZE {
                    return Err(Errno::ERANGE);
                }
                if self.creds.uid() != 0 {
                    return Err(Errno::EPERM);
                }
                let c = m.read(cred, POSIX_CRED_INFO_SIZE as usize)?;
                if le32(c, 0) & POSIX_CRED_GROUPS != 0 && le32(c, 12) > NGROUPS_MAX {
                    return Err(Errno::EINVAL);
                }
                self.darwin_unimplemented("posix_spawn's POSIX credentials (another uid, gid, groups or login for the child)".into());
                return Err(Errno::EINVAL);
            }
            if mx_size != 0 {
                self.darwin_spawn_macpolicyinfo(m, mx_size, mx)?;
            }
            // A subsystem root takes an entitlement the caller is checked for.
            if root_size > 0 && root_size <= PATH_MAX as u64 && self.dtask.codesign.as_ref().is_some_and(|c| c.entitled("com.apple.private.spawn-subsystem-root")) {
                self.darwin_unimplemented("posix_spawn with a subsystem root path".into());
                return Err(Errno::EINVAL);
            }
        }
        if let Some(at) = &attr {
            if at.crash_behavior != 0 && self.dtask.codesign.as_ref().is_some_and(|c| c.entitled("com.apple.private.spawn-panic-crash-behavior")) {
                self.darwin_unimplemented("posix_spawn's panic-on-crash behavior".into());
                return Err(Errno::EINVAL);
            }
            // exec_validate_spawnattr_policy.
            if at.apptype & PROC_TYPE_MASK == PROC_TYPE_DRIVER && !self.dtask.codesign.as_ref().is_some_and(|c| c.entitled("com.apple.private.spawn-driver")) {
                return Err(Errno::EPERM);
            }
            if at.flags & flag::SETEXEC != 0 {
                self.darwin_unimplemented("posix_spawn with POSIX_SPAWN_SETEXEC".into());
                return Err(Errno::EINVAL);
            }
            if coal_info != 0 {
                self.darwin_unimplemented("posix_spawn into coalitions".into());
                return Err(Errno::EINVAL);
            }
            self.darwin_spawn_unported(at)?;
        }
        // fork1(PROC_CREATE_SPAWN): a new process of this one's, no memory.
        let mut child = self.fork_kernel();
        let pid = self.procs.spawn(self.pid);
        child.pid = pid;
        child.tid = pid;
        child.forget_own_pidfds();
        child.dtask = self.darwin_fork_task();
        match self.darwin_spawn_child(m, &mut child, attr.as_ref(), file_actions.as_deref(), path, argv, envv) {
            Ok(()) => Ok(child),
            Err(e) => {
                // exit1 with P_LIST_DEADPARENT: gone, unseen by its parent.
                child.close_all_fds();
                self.procs.reap(pid);
                Err(e)
            }
        }
    }

    /// The child's half: file actions, activation, then the attributes the
    /// spawner applies.
    #[allow(clippy::too_many_arguments)]
    fn darwin_spawn_child(&mut self, m: &GuestMem<'_>, child: &mut Kernel, attr: Option<&Attr>, file_actions: Option<&[u8]>, path: u64, argv: u64, envv: u64) -> Result<(), Errno> {
        let flags = attr.map_or(0, |a| a.flags);
        let mut after = After { flags, sigmask: attr.map_or(0, |a| a.sigmask), sigdefault: attr.map_or(0, |a| a.sigdefault), inherit: Vec::new() };
        if let Some(fa) = file_actions {
            after.inherit = child.darwin_file_actions(fa, flags)?;
        }
        let binprefs = attr.filter(|a| a.binprefs[0].0 != 0).map(|a| a.binprefs);
        let mut img: Image = child.darwin_exec_activate_with(m, path, argv, envv, binprefs)?;
        if let Some(at) = attr {
            if at.flags & flag::SETPGROUP != 0 {
                child.procs.setpgid(child.pid, child.pid, at.pgroup)?;
            }
            if at.flags & flag::SETSID != 0 {
                child.procs.setsid(child.pid)?;
            }
        }
        img.spawn = Some(after);
        child.darwin_exec = Some(Box::new(img));
        Ok(())
    }

    /// The attributes whose subsystems this kernel does not have yet, each
    /// refused when it asks for something.
    fn darwin_spawn_unported(&mut self, at: &Attr) -> Result<(), Errno> {
        let mut no = |k: &mut Kernel, what: &str| {
            k.darwin_unimplemented(format!("posix_spawn's {what}"));
            Err(Errno::EINVAL)
        };
        if at.flags & flag::START_SUSPENDED != 0 {
            return no(self, "POSIX_SPAWN_START_SUSPENDED (a suspended task its spawner resumes through its task port)");
        }
        if at.jetsam_flags & JETSAM_SET != 0 {
            return no(self, "jetsam priority and memory limits (memorystatus)");
        }
        if at.cpumonitor_percent != 0 && at.cpumonitor_percent < u64::from(u8::MAX) {
            return no(self, "CPU usage monitor");
        }
        if at.apptype & PROC_TYPE_MASK != 0 || at.qos_clamp != 0 || at.darwin_role != 0 {
            return no(self, "app type, QoS clamp or Darwin role (the task policy's spawn policy)");
        }
        if at.thread_limit > 0 {
            return no(self, "thread limit");
        }
        if at.limits.iter().any(|&l| l != 0) {
            return no(self, "port space, descriptor or workloop limits");
        }
        if at.options & PSA_OPTION_DATALESS_IOPOLICY != 0 {
            return no(self, "dataless file I/O policy");
        }
        Ok(())
    }

    /// `spawn_copyin_macpolicyinfo`: the extensions' sizes checked and
    /// their data copied in. No MAC policy is loaded to read them.
    fn darwin_spawn_macpolicyinfo(&mut self, m: &GuestMem<'_>, size: u64, at: u64) -> Result<(), Errno> {
        if size < MAC_HDR + MAC_EXT_SIZE || size > super::exec::PAGE_SIZE {
            return Err(Errno::EINVAL);
        }
        let b = m.read(at, size as usize)?.to_vec();
        let count = le32(&b, 4) as u64;
        if MAC_HDR + MAC_EXT_SIZE * count > size {
            return Err(Errno::EINVAL);
        }
        let mut total = 0u64;
        for i in 0..count as usize {
            let e = MAC_HDR as usize + MAC_EXT_SIZE as usize * i;
            let len = le64(&b, e + 136);
            if len == 0 || len > super::exec::PAGE_SIZE {
                return Err(Errno::EINVAL);
            }
            total = total.checked_add(len).ok_or(Errno::ENOMEM)?;
        }
        for i in 0..count as usize {
            let e = MAC_HDR as usize + MAC_EXT_SIZE as usize * i;
            m.read(le64(&b, e + 128), le64(&b, e + 136) as usize).map_err(|_| Errno::ENOMEM)?;
        }
        Ok(())
    }

    /// `exec_handle_file_actions` on this (the child's) descriptor table:
    /// each action in turn, stopping at the first that fails; with
    /// `POSIX_SPAWN_CLOEXEC_DEFAULT`, the descriptors they make or name are
    /// the ones the exec keeps.
    fn darwin_file_actions(&mut self, b: &[u8], flags: u16) -> Result<Vec<i32>, Errno> {
        let count = le32(b, 4) as usize;
        let at = |i: usize| PSFA_HDR as usize + PSFA_ACTION_SIZE as usize * i;
        for i in 0..count {
            let o = at(i);
            let (ty, fd) = (le32(b, o), le32(b, o + 4) as i32);
            match ty {
                psfa::OPEN => {
                    let (oflag, mode) = (le32(b, o + 8), le16(b, o + 12));
                    let path = &b[o + 14..o + 14 + PATH_MAX];
                    if oflag & 0x30 != 0 {
                        self.darwin_unimplemented("posix_spawn's PSFA_OPEN with O_EXLOCK or O_SHLOCK".into());
                        return Err(Errno::EINVAL);
                    }
                    // The mode under the umask, its permission bits only.
                    let mode = u32::from(mode) & !self.proc_fs.umask() & 0o777;
                    let mut s = Scratch::path(path);
                    let mut gm = GuestMem::new(&mut s.0);
                    let mut la = [Scratch::AT, u64::from(oflag), u64::from(mode), 0, 0, 0];
                    let n = super::bsd::translate(super::bsd::sys::OPEN, &mut la);
                    let got = self.canonical(&mut gm, n, la)? as i32;
                    if got != fd {
                        let r = self.darwin_dup2(got, fd);
                        let _ = self.darwin_close(got);
                        r?;
                    }
                }
                psfa::DUP2 => {
                    self.darwin_dup2(fd, le32(b, o + 8) as i32)?;
                }
                psfa::FILEPORT_DUP2 => {
                    self.darwin_unimplemented("posix_spawn's PSFA_FILEPORT_DUP2 (fileports)".into());
                    return Err(Errno::EINVAL);
                }
                psfa::CLOSE => self.darwin_close(fd)?,
                psfa::INHERIT => self.fds.set_cloexec(fd, false)?,
                psfa::CHDIR => {
                    let mut s = Scratch::path(&b[o + 8..o + 8 + PATH_MAX]);
                    let mut gm = GuestMem::new(&mut s.0);
                    self.canonical(&mut gm, nr::CHDIR, [Scratch::AT, 0, 0, 0, 0, 0])?;
                }
                psfa::FCHDIR => {
                    let mut s = Scratch(vec![0u8; 16]);
                    let mut gm = GuestMem::new(&mut s.0);
                    self.canonical(&mut gm, nr::FCHDIR, [fd as u64, 0, 0, 0, 0, 0])?;
                }
                _ => return Err(Errno::EINVAL),
            }
        }
        let mut inherit = Vec::new();
        if flags & flag::CLOEXEC_DEFAULT != 0 {
            for i in 0..count {
                let o = at(i);
                match le32(b, o) {
                    psfa::DUP2 | psfa::FILEPORT_DUP2 => inherit.push(le32(b, o + 8) as i32),
                    psfa::OPEN | psfa::INHERIT => inherit.push(le32(b, o + 4) as i32),
                    _ => {}
                }
            }
        }
        Ok(inherit)
    }

    /// Darwin's `dup2`: EBADF for a descriptor that is not open or past
    /// the limit; the same descriptor is left as it is.
    fn darwin_dup2(&mut self, old: i32, new: i32) -> Result<(), Errno> {
        self.fds.get(old)?;
        if new < 0 || new as usize >= self.fds.limit() {
            return Err(Errno::EBADF);
        }
        if old == new {
            return Ok(());
        }
        let mut s = Scratch(vec![0u8; 16]);
        let mut gm = GuestMem::new(&mut s.0);
        self.canonical(&mut gm, nr::DUP3, [old as u64, new as u64, 0, 0, 0, 0]).map(|_| ())
    }

    /// `close_nocancel` in the child.
    fn darwin_close(&mut self, fd: i32) -> Result<(), Errno> {
        let mut s = Scratch(vec![0u8; 16]);
        let mut gm = GuestMem::new(&mut s.0);
        self.canonical(&mut gm, nr::CLOSE, [fd as u64, 0, 0, 0, 0, 0]).map(|_| ())
    }
}

/// `binary_match`'s CPU type `CPU_TYPE_ANY`, for the activators.
pub(crate) fn is_any(cpu: u32) -> bool {
    cpu == CPU_TYPE_ANY
}
