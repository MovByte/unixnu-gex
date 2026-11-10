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
/// Darwin's ENOTSUP.
const ENOTSUP: i32 = 45;
/// `POSIX_SPAWN_POSIX_CRED_UID`, `_GID`, `_GROUPS`.
const POSIX_CRED_UID: u32 = 0x0001_0000;
const POSIX_CRED_GID: u32 = 0x0002_0000;
const POSIX_CRED_GROUPS: u32 = 0x0004_0000;

/// `struct _posix_spawn_posix_cred_info`: its flags, uid, gid, groups and
/// gmuid (its login name is not the kernel's to use).
#[derive(Clone, Debug)]
struct PosixCred {
    flags: u32,
    uid: u32,
    gid: u32,
    ngroups: u32,
    groups: [u32; NGROUPS_MAX as usize],
    gmuid: u32,
}

impl PosixCred {
    fn parse(b: &[u8]) -> PosixCred {
        let mut groups = [0; NGROUPS_MAX as usize];
        for (i, g) in groups.iter_mut().enumerate() {
            *g = le32(b, 16 + 4 * i);
        }
        PosixCred { flags: le32(b, 0), uid: le32(b, 4), gid: le32(b, 8), ngroups: le32(b, 12), groups, gmuid: le32(b, 80) }
    }
}

/// A spawn's credentials: its POSIX credentials and its persona.
#[derive(Clone, Debug, Default)]
struct SpawnCreds {
    pcred: Option<PosixCred>,
    persona: Option<super::persona::SpawnPersona>,
}

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
    /// `psa_pcontrol`: the process control on resource starvation.
    pub pcontrol: i32,
    pub apptype: u32,
    pub cpumonitor_percent: u64,
    /// `psa_cpumonitor_interval`, in seconds.
    pub cpumonitor_interval: u64,
    pub jetsam_flags: u16,
    /// `psa_priority`, `psa_memlimit_active`, `psa_memlimit_inactive`.
    pub jetsam_priority: i32,
    pub memlimit_active: i32,
    pub memlimit_inactive: i32,
    pub qos_clamp: u64,
    pub darwin_role: u32,
    pub thread_limit: i32,
    /// `psa_max_addr`.
    pub max_addr: u64,
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
            pcontrol: le32(b, 32) as i32,
            apptype: le32(b, 36),
            cpumonitor_percent: le64(b, 40),
            cpumonitor_interval: le64(b, 48),
            jetsam_flags: le16(b, 64),
            jetsam_priority: le32(b, 68) as i32,
            memlimit_active: le32(b, 72) as i32,
            memlimit_inactive: le32(b, 76) as i32,
            qos_clamp: le64(b, 80),
            darwin_role: le32(b, 88),
            thread_limit: le32(b, 92) as i32,
            max_addr: le64(b, 96),
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
    /// The spawn's flags (POSIX_SPAWN_SETEXEC: this process's own exec).
    pub flags: u16,
    /// Its app type, QoS clamp and role, read as the policy takes them.
    pub policy: (u8, u8, u8),
    pub sigmask: u32,
    pub sigdefault: u32,
    pub inherit: Vec<i32>,
    /// `psa_max_addr`: the highest address the new map is to have.
    pub max_addr: u64,
    /// The crash behavior a spawn of an entitled parent asked for.
    pub crash_behavior: u32,
    /// `psa_pcontrol`, when the spawn had attributes.
    pub pcontrol: Option<i32>,
    /// `psa_cpumonitor_percent` and `psa_cpumonitor_interval` (seconds).
    pub cpumonitor: (u64, u64),
}

/// The `p_pcaction` a spawn's `psa_pcontrol` gives (`POSIX_SPAWN_PCONTROL_*`
/// to `P_PC*`): throttle, suspend or kill, and none for anything else.
pub(crate) fn pcaction_of(pcontrol: i32) -> u32 {
    const POSIX_SPAWN_PCONTROL_THROTTLE: i32 = 1;
    const POSIX_SPAWN_PCONTROL_SUSPEND: i32 = 2;
    const POSIX_SPAWN_PCONTROL_KILL: i32 = 3;
    match pcontrol {
        POSIX_SPAWN_PCONTROL_THROTTLE => super::procinfo::P_PCTHROTTLE,
        POSIX_SPAWN_PCONTROL_SUSPEND => super::procinfo::P_PCSUSP,
        POSIX_SPAWN_PCONTROL_KILL => super::procinfo::P_PCKILL,
        _ => 0,
    }
}

/// What a spawn made.
enum Spawned {
    /// A new process, to be started.
    Child(Box<Kernel>),
    /// This process's own exec (POSIX_SPAWN_SETEXEC).
    Exec(Box<Image>),
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

/// The rights a spawn's port actions hold until the child's image is
/// active (`struct exec_port_actions`): its registered ports, and its
/// exception ports with each one's mask, behavior and flavor.
#[derive(Default)]
struct Held {
    registered: Vec<Option<super::ipc::ObjId>>,
    exc: Vec<(Option<super::ipc::right::Carried>, u32, i32, i32)>,
}

impl Held {
    /// `exec_port_actions_destroy`.
    fn release(self, k: &mut Kernel) {
        for p in self.registered.into_iter().flatten() {
            k.ipc().release_send(p);
        }
        for (c, ..) in self.exc {
            super::exception::release(k.ipc(), c);
        }
    }
}

impl Kernel {
    /// `forkproc` of this process's Darwin state: what a child takes (its
    /// signal actions, limits, libpthread's registration, the dispatch
    /// queue offsets, and its map's entries as `vm_map_fork` copies them;
    /// its task policy is made with its entry in the process table); the
    /// rest is the new task's own.
    pub(crate) fn darwin_fork_task(&self) -> super::Task {
        let t = &self.dtask;
        let (special, registered, exc) = t.child_ports.lock().unwrap_or_else(|e| e.into_inner()).take().unwrap_or_default();
        super::Task {
            live: std::sync::Arc::new(super::kinfo::Live {
                acflag: super::kinfo::ac::AFORK.into(),
                argc: t.live.argc.load(std::sync::atomic::Ordering::Relaxed).into(),
                argslen: t.live.argslen.load(std::sync::atomic::Ordering::Relaxed).into(),
                user_stack: t.live.user_stack.load(std::sync::atomic::Ordering::Relaxed).into(),
                ..Default::default()
            }),
            kports: super::kobject::Kports { special, registered, exc, ..Default::default() },
            strict: t.strict,
            pthread: t.pthread,
            sigacts: t.sigacts.clone(),
            rlimits: t.rlimits,
            // forkproc: the child's RLIMIT_CPU timer runs from its limit
            // (its threads' times start at nothing, their saves with them).
            rlim_cpu: super::itimer::fork_rlim_cpu(t.rlimits.cur(super::rlimit::res::CPU)),
            vtimer_bits: if super::itimer::fork_rlim_cpu(t.rlimits.cur(super::rlimit::res::CPU)) != (0, 0) { super::itimer::vt::RLIM } else { 0 },
            dispatchqueue_serialno_offset: t.dispatchqueue_serialno_offset,
            dispatchqueue_label_offset: t.dispatchqueue_label_offset,
            vm: t.vm.inherited(),
            map_max: t.map_max,
            map_min: t.map_min,
            // The child runs this image, with this credential's
            // entitlements, and its code signing flags but CS_KILLED.
            codesign: t.codesign.clone(),
            textoff: t.textoff,
            cputype: t.cputype,
            uuid: t.uuid,
            p_name: t.p_name,
            // forkproc: the credential, and P_SUGID with the flags it keeps.
            cred: t.cred.clone(),
            sugid: t.sugid,
            csflags: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(t.csflags.load(std::sync::atomic::Ordering::Acquire) & !super::amfi::cs::KILLED)),
            // forkproc: the parent's persona.
            persona: t.persona.clone(),
            // task_bank_init for the child, with the parent's credential.
            vouchers: super::voucher::Vouchers::forked(t.cred.uid, t.cred.gid()),
            puniqueid: t.uniqueid,
            // The ids and start time a fork chose for its child; a spawn's
            // child takes new ones.
            ..match t.fork_ids.lock().unwrap_or_else(|e| e.into_inner()).take() {
                Some((uniqueid, pidversion, start)) => super::Task { uniqueid, pidversion, start, ..super::Task::default() },
                None => super::Task::new_process(),
            }
        }
    }

    /// `fork1`'s checks before it makes a process: the table not full
    /// (`maxproc`, its last slot root's), the user's processes within
    /// RLIMIT_NPROC (root's are not counted against it), and the MAC
    /// policies' `mac_proc_check_fork`.
    pub(crate) fn darwin_fork1_checks(&mut self) -> Result<(), Errno> {
        // kauth_getruid(): processes are counted by their real uid.
        let uid = self.dtask.cred.ruid;
        let (nprocs, mine) = self.procs.counts(uid);
        let maxproc = super::rlimit::MAXPROC as usize;
        if (nprocs >= maxproc - 1 && uid != 0) || nprocs >= maxproc {
            return Err(Errno::EAGAIN);
        }
        if uid != 0 && (mine + 1) as u64 > self.dtask.rlimits.cur(super::rlimit::res::NPROC) {
            return Err(Errno::EAGAIN);
        }
        match self.darwin_mac_check_fork() {
            0 => Ok(()),
            e => Err(super::errno::errno_of(e as i32)),
        }
    }

    /// `fork()`: fork1(PROC_CREATE_FORK). The host makes the child, a copy
    /// of this process's memory and of its calling thread, with the kernel
    /// state `fork_kernel` gives it. This side returns the child's pid with
    /// x1 clear; the child's x0 is its own pid and x1 is 1.
    pub(crate) fn darwin_fork(&mut self, m: &mut GuestMem<'_>) -> SyscallOutcome {
        if let Err(e) = self.darwin_fork1_checks() {
            let _ = super::set_result(m, self.ctx_addr, e.as_return());
            return SyscallOutcome::Continue;
        }
        // forkproc's persona_proc_adopt of this process's persona, the
        // child counted against the real uid meanwhile.
        if self.darwin_persona_inherit(1).is_err() {
            let _ = super::set_result(m, self.ctx_addr, Errno::EAGAIN.as_return());
            return SyscallOutcome::Continue;
        }
        self.darwin_child_ports();
        let mapped: Vec<(u64, u64)> = self.mem.lock().vmas().iter().map(|v| (v.start, v.end)).collect();
        self.dtask.vm.fork(&mapped);
        let pid = self.procs.spawn(self.pid);
        // task_create_internal: the child's task is in its parent's
        // coalitions.
        super::coalition::fork(self.pid, pid);
        // forkproc's ids and start time for the child, which its task takes.
        let ids = (super::next_uniqueid(), super::next_pidversion(), super::procinfo::microtime());
        *self.dtask.fork_ids.lock().unwrap_or_else(|e| e.into_inner()) = Some(ids);
        // The child runs this image: its entitlements are these.
        let mut j = self.procs.jetsam();
        if let Some(e) = j.get(self.pid).map(|p| p.entitled) {
            j.set_entitled(pid, e);
        }
        drop(j);
        crate::procnote::post(self.pid, crate::procnote::note::FORK | pid as u32);
        let _ = super::set_result(m, self.ctx_addr, pid as u64);
        let _ = m.write_u64(self.ctx_addr + gex_abi::ctx::x(1) as u64, 0);
        SyscallOutcome::SpawnProcess { pid, child_stack: 0, tls: None, vfork: false }
    }

    /// `ipc_task_init`'s inheritance: the child task the next
    /// `fork_kernel` makes gets copies of this task's send rights to its
    /// registered ports and its bootstrap and task access ports, and its
    /// exception actions (its host port follows from its identity).
    fn darwin_child_ports(&mut self) {
        const TASK_BOOTSTRAP_PORT: i32 = 4;
        const TASK_ACCESS_PORT: i32 = 9;
        let k = &self.dtask.kports;
        let special: Vec<(i32, super::ipc::ObjId)> = [TASK_BOOTSTRAP_PORT, TASK_ACCESS_PORT].into_iter().filter_map(|w| k.special.get(&w).map(|&p| (w, p))).collect();
        let registered = k.registered;
        let task_exc = k.exc;
        let ipc = self.ipc();
        let exc = super::exception::copy_all(ipc, &task_exc);
        for &(_, p) in &special {
            ipc.copy_send(p);
        }
        for p in registered.into_iter().flatten() {
            ipc.copy_send(p);
        }
        let old = self.dtask.child_ports.lock().unwrap_or_else(|e| e.into_inner()).replace((special.into_iter().collect(), registered, exc));
        debug_assert!(old.is_none(), "a child's ports not taken");
    }

    /// The spawn attributes' credential steps for the process the spawn
    /// makes (this one): POSIX_SPAWN_RESETIDS's real ids as all its ids
    /// (`kauth_cred_model_setuidgid`, no P_SUGID), then for a spawn without
    /// exec its POSIX credentials (`spawn_posix_cred_adopt`) and its persona
    /// (`spawn_persona_adopt`), which an exec in place may not take.
    fn darwin_spawn_creds(&mut self, at: &Attr, creds: &SpawnCreds) -> Result<(), Errno> {
        let exec = at.flags & flag::SETEXEC != 0;
        if at.flags & flag::RESETIDS != 0 {
            let (ruid, rgid) = (self.dtask.cred.ruid, self.dtask.cred.rgid);
            if self.dtask.cred.setuidgid(ruid, rgid) {
                self.darwin_cred_tokens();
            }
        }
        if let Some(pc) = &creds.pcred {
            if exec {
                return Err(super::errno::errno_of(ENOTSUP));
            }
            if pc.flags & POSIX_CRED_GID != 0 {
                self.darwin_setgid(pc.gid)?;
            }
            if pc.flags & POSIX_CRED_GROUPS != 0 {
                self.darwin_setgroups_internal(pc.groups[..pc.ngroups as usize].to_vec(), pc.gmuid)?;
            }
            if pc.flags & POSIX_CRED_UID != 0 {
                self.darwin_setuid(pc.uid)?;
            }
        }
        if let Some(sp) = &creds.persona {
            if exec {
                return Err(super::errno::errno_of(ENOTSUP));
            }
            self.darwin_spawn_persona_adopt(sp)?;
        }
        Ok(())
    }

    /// `posix_spawn(pid, path, adesc, argv, envp)`.
    pub(crate) fn darwin_posix_spawn(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> SyscallOutcome {
        match self.darwin_spawn(m, a) {
            Ok(Spawned::Child(child)) => {
                self.darwin_spawned = Some(child);
                let _ = super::set_result(m, self.ctx_addr, 0);
                SyscallOutcome::DarwinSpawn { pid_addr: a[0] }
            }
            // POSIX_SPAWN_SETEXEC: this process's exec, as execve's, with no
            // pid to give.
            Ok(Spawned::Exec(img)) => {
                self.map_io().flush_all_shared(m);
                let lossy = |v: Vec<&[u8]>| v.into_iter().map(|s| String::from_utf8_lossy(s).into_owned()).collect::<Vec<_>>();
                let (argv, envp) = (lossy(img.strings.args()), lossy(img.strings.envs()));
                let path = img.path.clone();
                self.darwin_exec = Some(img);
                SyscallOutcome::Exec { path, argv, envp }
            }
            Err(e) => {
                let _ = super::set_result(m, self.ctx_addr, e.as_return());
                SyscallOutcome::Continue
            }
        }
    }

    fn darwin_spawn(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<Spawned, Errno> {
        let (path, adesc, argv, envv) = (a[1], a[2], a[3], a[4]);
        let mut attr = None;
        let mut file_actions = None;
        let mut port_actions: Option<Vec<u8>> = None;
        let (mut coal_info, mut coal_size) = (0, 0);
        let mut creds = SpawnCreds::default();
        if adesc != 0 {
            let d = m.read(adesc, ARGS_DESC_SIZE)?.to_vec();
            let pair = |i: usize| (le64(&d, 16 * i), le64(&d, 16 * i + 8));
            let (attr_size, attrp) = pair(0);
            let (fa_size, fa) = pair(1);
            let (pa_size, pa) = pair(2);
            let (mx_size, mx) = pair(3);
            let (csize, coal) = pair(4);
            let (persona_size, persona) = pair(5);
            let (cred_size, cred) = pair(6);
            let (root_size, _) = pair(7);
            coal_info = coal;
            coal_size = csize;
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
                port_actions = Some(b.to_vec());
            }
            if persona_size != 0 && persona != 0 {
                if persona_size != PERSONA_INFO_SIZE {
                    return Err(Errno::ERANGE);
                }
                let sp = super::persona::SpawnPersona::parse(m.read(persona, PERSONA_INFO_SIZE as usize)?);
                self.darwin_spawn_validate_persona(&sp)?;
                creds.persona = Some(sp);
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
                creds.pcred = Some(PosixCred::parse(c));
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
            // exec_validate_spawnattr_policy.
            if at.apptype & PROC_TYPE_MASK == PROC_TYPE_DRIVER && !self.dtask.codesign.as_ref().is_some_and(|c| c.entitled("com.apple.private.spawn-driver")) {
                return Err(Errno::EPERM);
            }
            self.darwin_spawn_unported(at)?;
            if at.flags & flag::SETEXEC != 0 {
                if port_actions.is_some() {
                    self.darwin_unimplemented("posix_spawn port actions with POSIX_SPAWN_SETEXEC (on the task the exec makes)".into());
                    return Err(Errno::EINVAL);
                }
                return self.darwin_spawn_setexec(m, at, file_actions.as_deref(), &creds, path, argv, envv).map(Spawned::Exec);
            }
        }
        // The coalitions it names (a spawn with attributes), activated
        // against their end until the child is in them.
        let mut coals = None;
        if attr.is_some() && coal_info != 0 {
            let n = (coal_size as usize).min(48);
            let mut info = [0u8; 48];
            info[..n].copy_from_slice(m.read(coal_info, n)?);
            let me = self.pid;
            let entitled = self.darwin_task_entitled("com.apple.private.coalition-spawn");
            coals = Some(super::coalition::Spawn::activate(&info, |k| super::coalition::privileged(me, k) || entitled)?);
        }
        let r = self.darwin_spawn_process(m, attr.as_ref(), file_actions.as_deref(), port_actions.as_deref(), &creds, path, argv, envv, coals.as_ref());
        // spawn_coalitions_release_all: the child holds them now.
        if let Some(mut c) = coals {
            let told = c.release_all();
            self.darwin_coalitions_notify(told);
        }
        r
    }

    /// `posix_spawn`'s new process: fork1, then the child's half.
    #[allow(clippy::too_many_arguments)]
    fn darwin_spawn_process(&mut self, m: &mut GuestMem<'_>, attr: Option<&Attr>, file_actions: Option<&[u8]>, port_actions: Option<&[u8]>, creds: &SpawnCreds, path: u64, argv: u64, envv: u64, coals: Option<&super::coalition::Spawn>) -> Result<Spawned, Errno> {
        // fork1(PROC_CREATE_SPAWN): a new process of this one's, no memory,
        // in this one's persona.
        self.darwin_fork1_checks()?;
        self.darwin_persona_inherit(1).map_err(|_| Errno::EAGAIN)?;
        self.darwin_child_ports();
        let mut child = self.fork_kernel();
        // A spawn is not a fork: CS_GET_TASK_ALLOW is not inherited, and
        // its thread is not a copy of this one (no thread_dup).
        child.dtask.csflags.fetch_and(!super::amfi::cs::GET_TASK_ALLOW, std::sync::atomic::Ordering::AcqRel);
        child.signals.thread().set_tsd(0);
        let pid = self.procs.spawn(self.pid);
        // Its task in the coalitions named, with its roles, or its parent's.
        match coals {
            Some(c) => c.place(self.pid, pid),
            None => super::coalition::fork(self.pid, pid),
        }
        // The spawner's NOTE_FORK, whatever becomes of the child.
        crate::procnote::post(self.pid, crate::procnote::note::FORK | pid as u32);
        child.pid = pid;
        child.tid = pid;
        // Its thread is in its task's list before it first runs.
        child.thread_sig(pid);
        child.forget_own_pidfds();
        child.darwin_publish();
        let spawned = self.darwin_spawn_child(m, &mut child, attr, file_actions, port_actions, creds, path, argv, envv);
        // A guard the file actions tripped is the spawning thread's.
        if child.dtask.fd_guard.is_some() {
            self.dtask.fd_guard = child.dtask.fd_guard.take();
        }
        match spawned {
            Ok(()) => Ok(Spawned::Child(Box::new(child))),
            Err(e) => {
                // exit1 with P_LIST_DEADPARENT: gone, unseen by its parent,
                // and the rights it inherited with it.
                let k = std::mem::take(&mut child.dtask.kports);
                for p in k.special.into_values().chain(k.registered.into_iter().flatten()) {
                    self.ipc().release_send(p);
                }
                super::exception::release_all(self.ipc(), &k.exc);
                child.close_all_fds();
                let told = super::coalition::task_terminated(pid);
                self.darwin_coalitions_notify(told);
                self.procs.reap(pid);
                Err(e)
            }
        }
    }

    /// The child's half: file actions, activation, then the attributes the
    /// spawner applies.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    fn darwin_spawn_child(&mut self, m: &GuestMem<'_>, child: &mut Kernel, attr: Option<&Attr>, file_actions: Option<&[u8]>, port_actions: Option<&[u8]>, creds: &SpawnCreds, path: u64, argv: u64, envv: u64) -> Result<(), Errno> {
        let flags = attr.map_or(0, |a| a.flags);
        let policy = attr.map_or((0, 0, 0), |a| super::taskpolicy::spawn_attrs(a.apptype, a.qos_clamp, a.darwin_role));
        let mut after = After { flags, policy, sigmask: attr.map_or(0, |a| a.sigmask), sigdefault: attr.map_or(0, |a| a.sigdefault), inherit: Vec::new(), max_addr: attr.map_or(0, |a| a.max_addr), crash_behavior: if self.dtask.codesign.as_ref().is_some_and(|c| c.entitled("com.apple.private.spawn-panic-crash-behavior")) { attr.map_or(0, |a| a.crash_behavior) } else { 0 }, pcontrol: attr.map(|a| a.pcontrol), cpumonitor: attr.map_or((0, 0), |a| (a.cpumonitor_percent, a.cpumonitor_interval)) };
        if let Some(fa) = file_actions {
            after.inherit = child.darwin_file_actions(fa, flags)?;
        }
        let mut held = match port_actions {
            Some(pa) => self.darwin_spawn_port_actions(child, pa)?,
            None => Held::default(),
        };
        // The attributes' credentials, before the image is activated (with
        // them): reset ids, POSIX credentials, then the persona.
        if let Some(at) = attr {
            if let Err(e) = child.darwin_spawn_creds(at, creds) {
                held.release(self);
                return Err(e);
            }
        }
        let binprefs = attr.filter(|a| a.binprefs[0].0 != 0).map(|a| a.binprefs);
        let mut img: Image = match child.darwin_exec_activate_with(m, path, argv, envv, binprefs) {
            Ok(img) => img,
            Err(e) => {
                held.release(self);
                return Err(e);
            }
        };
        if let Some(at) = attr {
            // setpgid() and setsid_internal() as the child calls them.
            let r = (|| {
                if at.flags & flag::SETPGROUP != 0 {
                    child.procs.darwin_setpgid(child.pid, child.pid, at.pgroup)?;
                }
                if at.flags & flag::SETSID != 0 {
                    child.procs.setsid(child.pid)?;
                }
                Ok(())
            })();
            if let Err(e) = r {
                held.release(self);
                return Err(e);
            }
        }
        // The image's signature, as its load added it.
        child.dtask.codesign = img.load.sig.as_deref().cloned();
        // task_bank_init, the child's credentials, persona and image in
        // place.
        child.darwin_task_bank_reinit();
        // exec_handle_exception_port_actions: now that the child's
        // signature is known, its exception ports as task_set_exception_ports
        // sets them (each held right consumed when set).
        let setter = super::exception::Setter {
            privileged: self.creds.uid() == 0,
            entitled: self.darwin_task_entitled("com.apple.private.set-exception-port") || self.darwin_task_entitled("com.apple.private.thread-set-state"),
            hardened: child.darwin_hardened(),
        };
        while !held.exc.is_empty() {
            let (port, mask, behavior, flavor) = held.exc.remove(0);
            let r = super::exception::set_port(self.ipc(), &mut child.dtask.kports.exc, super::exception::Level::Task, mask, port, behavior, flavor, &setter, false);
            super::exception::release(self.ipc(), port);
            if r.is_err() {
                held.release(self);
                return Err(Errno::EINVAL);
            }
        }
        // exec_handle_spawnattr_policy, in the spawner's call.
        let (apptype, clamp, role) = after.policy;
        if apptype != super::taskpolicy::apptype::NONE || clamp != super::workq::qos::UNSPECIFIED || role != super::taskpolicy::role::UNSPECIFIED {
            if let Some(p) = self.procs.task_policy(child.pid) {
                p.lock().unwrap_or_else(|e| e.into_inner()).spawnpolicy(apptype, clamp, role);
            }
        }
        if let Some(at) = attr {
            self.darwin_spawn_jetsam(child.pid, at);
        }
        // _kernelrpc_mach_ports_register3 with the registered ports held.
        if !held.registered.is_empty() {
            let mut ports = [None; 3];
            for (slot, p) in ports.iter_mut().zip(held.registered) {
                *slot = p;
            }
            if super::mig::ports_register(&mut child.dtask.kports, self.ipc(), ports) != 0 {
                return Err(Errno::EINVAL);
            }
        }
        // Upon a successful spawn with attributes, the process control.
        if let Some(pc) = after.pcontrol {
            child.dtask.pcaction.store(pcaction_of(pc), std::sync::atomic::Ordering::Release);
        }
        img.spawn = Some(after);
        child.darwin_exec = Some(Box::new(img));
        Ok(())
    }

    /// posix_spawn's jetsam attributes (`POSIX_SPAWN_JETSAM_SET`): the new
    /// process's priority and memory limits, by `memorystatus_update`. With
    /// POSIX_SPAWN_JETSAM_HIWATER_BACKGROUND, the inactive limit is the
    /// one given, not fatal, and the active one the system-wide, fatal.
    fn darwin_spawn_jetsam(&mut self, pid: i32, at: &Attr) {
        const USE_EFFECTIVE_PRIORITY: u16 = 0x01;
        const HIWATER_BACKGROUND: u16 = 0x02;
        const MEMLIMIT_ACTIVE_FATAL: u16 = 0x04;
        const MEMLIMIT_INACTIVE_FATAL: u16 = 0x08;
        let f = at.jetsam_flags;
        if f & JETSAM_SET == 0 {
            return;
        }
        let limits = if f & HIWATER_BACKGROUND != 0 {
            (-1, true, at.memlimit_inactive, false)
        } else {
            (at.memlimit_active, f & MEMLIMIT_ACTIVE_FATAL != 0, at.memlimit_inactive, f & MEMLIMIT_INACTIVE_FATAL != 0)
        };
        let range = self.darwin_task_entitled("com.apple.private.internal-jetsam-range");
        // Its result is not the spawn's.
        let _ = self.procs.jetsam().update(pid, at.jetsam_priority, 0, false, f & USE_EFFECTIVE_PRIORITY != 0, Some(limits), range);
        self.darwin_jetsam_effects();
    }

    /// `exec_handle_port_actions`: the actions checked (EINVAL for one of
    /// no known kind, or for more exception, watch or registered ports than
    /// a task has), then each named right copied in from this task's space
    /// (COPY_SEND, an immovable send right allowed) and acted on for the
    /// child: its special port set, a registered port held for the end of
    /// the spawn (returned), a pointer authentication task port consumed
    /// (there is no pointer authentication here). An action that fails
    /// releases its right and ends the spawn with EINVAL.
    fn darwin_spawn_port_actions(&mut self, child: &mut Kernel, pa: &[u8]) -> Result<Held, Errno> {
        use super::ipc::right::{msgt, Carried, CopyinFlags};
        const PSPA_SPECIAL: u32 = 0;
        const PSPA_EXCEPTION: u32 = 1;
        const PSPA_AU_SESSION: u32 = 2;
        const PSPA_IMP_WATCHPORTS: u32 = 3;
        const PSPA_REGISTERED_PORTS: u32 = 4;
        const PSPA_PTRAUTH_TASK_PORT: u32 = 5;
        // EXC_TYPES_COUNT, TASK_MAX_WATCHPORT_COUNT, TASK_PORT_REGISTER_MAX.
        const MAX_EXCEPTION: u32 = 14;
        const MAX_WATCHPORT: u32 = 128;
        const MAX_REGISTERED: u32 = 3;
        let count = le32(pa, 4) as usize;
        let raw = |i: usize| &pa[PORT_HDR as usize + i * PORT_ACTION_SIZE as usize..];
        let action = |i: usize| {
            let a = raw(i);
            (le32(a, 0), le32(a, 8), le32(a, 20) as i32)
        };
        let (mut exc, mut watch, mut reg, mut ptrauth) = (0, 0, 0, 0);
        for i in 0..count {
            let n = match action(i).0 {
                PSPA_SPECIAL | PSPA_AU_SESSION => continue,
                PSPA_EXCEPTION => { exc += 1; (exc, MAX_EXCEPTION) }
                PSPA_IMP_WATCHPORTS => { watch += 1; (watch, MAX_WATCHPORT) }
                PSPA_REGISTERED_PORTS => { reg += 1; (reg, MAX_REGISTERED) }
                PSPA_PTRAUTH_TASK_PORT => { ptrauth += 1; (ptrauth, 1) }
                _ => return Err(Errno::EINVAL),
            };
            if n.0 > n.1 {
                return Err(Errno::EINVAL);
            }
        }
        // Audit sessions and importance watch ports are not here.
        for i in 0..count {
            let what = match action(i).0 {
                PSPA_AU_SESSION => "a posix_spawn audit session port action (audit sessions)",
                PSPA_IMP_WATCHPORTS => "a posix_spawn watch port action (importance watch ports)",
                _ => continue,
            };
            self.darwin_unimplemented(what.into());
            return Err(Errno::EINVAL);
        }
        let mut held = Held::default();
        let fail = |k: &mut Kernel, held: Held| {
            held.release(k);
            Err(Errno::EINVAL)
        };
        for i in 0..count {
            let (kind, name, which) = action(i);
            // A null or dead name is carried as it is.
            let carried = if super::ipc::name_valid(name) {
                let flags = CopyinFlags { allow_immovable_send: true, ..Default::default() };
                match self.ipc().object_copyin(name, msgt::COPY_SEND, flags, 0, None) {
                    Ok(c) => Some(c),
                    Err(_) => return fail(self, held),
                }
            } else if name == super::ipc::PORT_DEAD {
                Some(Carried::Dead)
            } else {
                None
            };
            let port = match carried {
                Some(Carried::Port(p)) => Some(p),
                _ => None,
            };
            match kind {
                PSPA_SPECIAL => {
                    if super::mig::set_special_port(&mut child.dtask.kports, self.ipc(), which, port) != 0 {
                        if let Some(p) = port {
                            self.ipc().release_send(p);
                        }
                        return fail(self, held);
                    }
                }
                PSPA_REGISTERED_PORTS => held.registered.push(port),
                PSPA_EXCEPTION => {
                    let a = raw(i);
                    held.exc.push((carried, le32(a, 4), le32(a, 12) as i32, le32(a, 16) as i32));
                }
                _ => {
                    if let Some(p) = port {
                        self.ipc().release_send(p);
                    }
                }
            }
        }
        Ok(held)
    }

    /// POSIX_SPAWN_SETEXEC: `execve` with options (cloneproc's
    /// CLONEPROC_EXEC). The file actions act on a copy of this process's
    /// descriptors and directory, and the image is activated there, so a
    /// failure leaves this process as it was; on success the copy becomes
    /// its own and its group and session are set, as the spawn sets them
    /// after its switch of tasks (an error there reaches only the old
    /// image's thread, which ends: the new image runs).
    fn darwin_spawn_setexec(&mut self, m: &GuestMem<'_>, at: &Attr, file_actions: Option<&[u8]>, creds: &SpawnCreds, path: u64, argv: u64, envv: u64) -> Result<Box<Image>, Errno> {
        // cloneproc(CLONEPROC_EXEC), counted against the real uid meanwhile.
        self.darwin_persona_inherit(1).map_err(|_| Errno::ENOMEM)?;
        let mut copy = self.fork_kernel();
        copy.pid = self.pid;
        copy.tid = self.tid;
        // An exec's fdt_fork: the FP_CLOEXEC descriptors are not copied,
        // so no file action sees them, and the FP_CLOFORK ones a fork's
        // drops are, with their guards.
        for (fd, f, cloexec) in self.fds.entries() {
            if cloexec {
                let _ = copy.fds.close(fd);
                continue;
            }
            if self.fds.clofork(fd) && copy.fds.get(fd).is_err() {
                let _ = copy.fds.install(fd, f, cloexec);
                let _ = copy.fds.set_clofork(fd, true);
            }
            if let Some(g) = self.fds.guard(fd) {
                let _ = copy.fds.change_guard(fd, |slot, _, _| {
                    *slot = Some(g);
                    Ok(())
                });
            }
        }
        let mut after = After { flags: at.flags, policy: super::taskpolicy::spawn_attrs(at.apptype, at.qos_clamp, at.darwin_role), sigmask: at.sigmask, sigdefault: at.sigdefault, inherit: Vec::new(), max_addr: at.max_addr, crash_behavior: if self.dtask.codesign.as_ref().is_some_and(|c| c.entitled("com.apple.private.spawn-panic-crash-behavior")) { at.crash_behavior } else { 0 }, pcontrol: Some(at.pcontrol), cpumonitor: (at.cpumonitor_percent, at.cpumonitor_interval) };
        let activated = (|| {
            if let Some(fa) = file_actions {
                after.inherit = copy.darwin_file_actions(fa, at.flags)?;
            }
            copy.darwin_spawn_creds(at, creds)?;
            let binprefs = Some(at.binprefs).filter(|b| b[0].0 != 0);
            copy.darwin_exec_activate_with(m, path, argv, envv, binprefs)
        })();
        if copy.dtask.fd_guard.is_some() {
            self.dtask.fd_guard = copy.dtask.fd_guard.take();
        }
        // On a failure, what the actions opened goes with the copy (never
        // its close_all_fds, which would end this process's locks).
        let mut img = activated?;
        self.fds = std::sync::Arc::clone(&copy.fds);
        // POSIX_SPAWN_RESETIDS's credential, the exec's.
        if copy.dtask.cred != self.dtask.cred {
            self.dtask.cred = copy.dtask.cred.clone();
            self.darwin_cred_tokens();
        }
        // The directory the actions left the copy in, made this process's
        // as a chdir makes it.
        let cwd = copy.caller_cwd();
        if cwd != self.caller_cwd() {
            let mut s = Scratch::path(cwd.as_bytes());
            let mut gm = GuestMem::new(&mut s.0);
            self.canonical(&mut gm, nr::CHDIR, [Scratch::AT, 0, 0, 0, 0, 0])?;
        }
        if at.flags & flag::SETPGROUP != 0 {
            let _ = self.procs.darwin_setpgid(self.pid, self.pid, at.pgroup);
        }
        if at.flags & flag::SETSID != 0 {
            let _ = self.procs.setsid(self.pid);
        }
        // exec_activate_image's new task, and its ledger, before the
        // spawn's limits are set on it.
        self.procs.jetsam().ledgers.insert(self.pid, super::footprint::Ledger::default());
        self.darwin_spawn_jetsam(self.pid, at);
        img.spawn = Some(after);
        // The copy's thread (cloneproc's, for an exec in place) is the one
        // this process goes on in.
        img.thread_id = copy.signals.thread().darwin_id();
        Ok(Box::new(img))
    }

    /// The attributes whose subsystems this kernel does not have yet, each
    /// refused when it asks for something.
    fn darwin_spawn_unported(&mut self, at: &Attr) -> Result<(), Errno> {
        let no = |k: &mut Kernel, what: &str| {
            k.darwin_unimplemented(format!("posix_spawn's {what}"));
            Err(Errno::EINVAL)
        };
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
                psfa::INHERIT => {
                    if let Some(g) = self.fds.guard(fd) {
                        return Err(self.darwin_fp_guard_exception(fd, g, super::guarded::flavor::NOCLOEXEC));
                    }
                    self.fds.set_cloexec(fd, false)?
                }
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
        self.darwin_dup2_guards(old, new)?;
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
        self.darwin_close_guard(fd)?;
        let mut s = Scratch(vec![0u8; 16]);
        let mut gm = GuestMem::new(&mut s.0);
        self.canonical(&mut gm, nr::CLOSE, [fd as u64, 0, 0, 0, 0, 0]).map(|_| ())
    }
}

/// `binary_match`'s CPU type `CPU_TYPE_ANY`, for the activators.
pub(crate) fn is_any(cpu: u32) -> bool {
    cpu == CPU_TYPE_ANY
}
