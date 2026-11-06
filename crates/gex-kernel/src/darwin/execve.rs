//! `execve` and `__mac_execve` (`bsd/kern/kern_exec.c`): image activation
//! (`exec_activate_image`: the path saved and looked up, the file's
//! permissions, then the Mach-O, fat and interpreter activators in turn,
//! the arguments and environment taken), and what of the process the new
//! image keeps (`proc_exec_switch_task`, `fdt_exec`, `execsigs`).
//!
//! Activation fails back to the caller with an errno. Once the strings are
//! taken the old image is past saving: the host builds the new one, and a
//! load that fails then kills the process (`badtoolate`'s SIGKILL).

use super::exec::{Strings, PAGE_SIZE};
use crate::errno::Errno;
use crate::syscalls::{Kernel, SyscallOutcome};
use crate::GuestMem;

/// `IMG_SHSIZE`: the most of a `#!` line read.
const IMG_SHSIZE: usize = 512;
/// `EAI_ITERLIMIT`: images inside images.
const EAI_ITERLIMIT: u32 = 3;

/// `<mach-o/loader.h>`, `<mach-o/fat.h>`.
mod mh {
    pub const MAGIC: u32 = 0xfeed_face;
    pub const CIGAM: u32 = 0xcefa_edfe;
    pub const MAGIC_64: u32 = 0xfeed_facf;
    pub const CIGAM_64: u32 = 0xcffa_edfe;
    pub const EXECUTE: u32 = 2;
    pub const FAT_MAGIC: u32 = 0xcafe_babe;
}

/// `<mach/machine.h>`.
mod cpu {
    pub const ARCH_MASK: u32 = 0xff00_0000;
    pub const TYPE_ARM64: u32 = 0x0100_000c;
    pub const SUBTYPE_MASK: u32 = 0xff00_0000;
    pub const SUBTYPE_ANY: u32 = u32::MAX;
    pub const SUBTYPE_ARM64_ALL: u32 = 0;
    pub const SUBTYPE_ARM64_V8: u32 = 1;
}

/// The Darwin errnos `load_return_to_errno` gives that Linux has none for.
fn ebadarch() -> Errno {
    super::errno::native(86)
}
fn ebadmacho() -> Errno {
    super::errno::EBADMACHO
}

/// What exec found to run: the file and slice the host loads, and the
/// string area the new image's stack is built from.
#[derive(Debug)]
pub struct Image {
    /// The vnode, as looked up: the interpreter's for a script.
    pub path: String,
    pub arch_offset: u64,
    pub arch_size: u64,
    pub cputype: u32,
    pub cpusubtype: u32,
    pub strings: Strings,
    /// A spawn's, what the child takes after its switch.
    pub spawn: Option<super::spawn::After>,
    /// The image's signature as its load added it, and the load's code
    /// signing flags ([`Kernel::darwin_load_signatures`]).
    pub sig: Option<std::sync::Arc<super::codesign::CodeSign>>,
    pub load_csflags: u32,
}

/// An activator's answer: `-1`, `-2`, `-3`, or the image claimed.
enum Act {
    NotMine,
    Encapsulated,
    Interpreter,
    Done,
}

/// `image_params`, as activation fills it in.
struct Imgp {
    strings: Strings,
    vdata: Vec<u8>,
    interpret: bool,
    interp_buffer: Vec<u8>,
    origcputype: u32,
    origcpusubtype: u32,
    arch_offset: u64,
    arch_size: u64,
    path: String,
    size: u64,
    /// A spawn's `psa_binprefs` and `psa_subcpuprefs`.
    binprefs: Option<[(u32, u32); 4]>,
}

fn be32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes(b[o..o + 4].try_into().unwrap())
}
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

/// `grade_binary` on an arm64 host whose `cpu_subtype` is ARMv8 without
/// pointer authentication: an arm64 slice for it, then the generic one;
/// nothing else runs.
fn grade_binary(exectype: u32, execsubtype: u32) -> i32 {
    match (exectype, super::mig::machine::CPU_SUBTYPE) {
        (cpu::TYPE_ARM64, cpu::SUBTYPE_ARM64_V8) => match execsubtype {
            cpu::SUBTYPE_ARM64_V8 => 10,
            cpu::SUBTYPE_ARM64_ALL => 9,
            _ => 0,
        },
        _ => 0,
    }
}

/// `binary_match`.
fn binary_match(mask: u32, req_cpu: u32, req_sub: u32, test_cpu: u32, test_sub: u32) -> bool {
    if test_cpu & !mask != req_cpu & !mask {
        return false;
    }
    let (t, r) = (test_sub & !cpu::SUBTYPE_MASK, req_sub & !cpu::SUBTYPE_MASK);
    t == r || r == cpu::SUBTYPE_ANY & !cpu::SUBTYPE_MASK
}

/// `fatfile_validate_fatarches` of the header page, against the file's size.
fn fat_validate(h: &[u8], file_size: u64) -> Result<(), Errno> {
    let n = be32(h, 4) as usize;
    if n > (h.len() - 8) / 20 {
        return Err(ebadmacho());
    }
    let header_size = 8 + n * 20;
    let arch = |i: usize| (be32(h, 8 + 20 * i + 8), be32(h, 8 + 20 * i + 12), be32(h, 8 + 20 * i), be32(h, 8 + 20 * i + 4));
    for i in 0..n {
        let (ib, is, it, ist) = arch(i);
        if (ib as usize) < header_size || u32::MAX - is < ib || u64::from(ib + is) > file_size {
            return Err(ebadmacho());
        }
        let ie = ib + is;
        for j in i + 1..n {
            let (jb, js, jt, jst) = arch(j);
            if it == jt && ist == jst {
                return Err(ebadmacho());
            }
            if u32::MAX - js < jb {
                return Err(ebadmacho());
            }
            let je = jb + js;
            let overlap = if ib <= jb { ie > jb } else { ib < je };
            if overlap {
                return Err(ebadmacho());
            }
        }
    }
    Ok(())
}

/// `fatfile_getarch` with `fatfile_getbestarch`'s arguments: the best
/// graded slice for the host's CPU type, ignoring the architecture bits.
/// `(cputype, cpusubtype, offset, size)`.
fn fat_best(h: &[u8]) -> Result<(u32, u32, u32, u32), Errno> {
    fat_getarch(h, cpu::TYPE_ARM64, cpu::ARCH_MASK, cpu::SUBTYPE_ANY)
}

/// A file's Mach-O for this host: a fat file's best graded slice, or the
/// whole file. `(offset, size)`.
pub(crate) fn best_slice(b: &[u8]) -> Result<(u64, u64), Errno> {
    if b.len() >= 4 && be32(b, 0) == mh::FAT_MAGIC {
        fat_validate(b, b.len() as u64)?;
        let (_, _, off, size) = fat_best(b)?;
        return Ok((u64::from(off), u64::from(size)));
    }
    Ok((0, b.len() as u64))
}

/// `fatfile_getarch`: the best graded slice that matches the type asked
/// for, ignoring `mask`'s bits of it.
fn fat_getarch(h: &[u8], req_cpu: u32, mask: u32, req_sub: u32) -> Result<(u32, u32, u32, u32), Errno> {
    let n = be32(h, 4) as usize;
    if n > (h.len() - 8) / 20 {
        return Err(ebadmacho());
    }
    let mut best = None;
    let mut best_grade = 0;
    for i in 0..n {
        let o = 8 + 20 * i;
        let (ty, sub) = (be32(h, o), be32(h, o + 4));
        if !binary_match(mask, req_cpu, req_sub, ty, sub & !cpu::SUBTYPE_MASK) {
            continue;
        }
        let grade = grade_binary(ty, sub & !cpu::SUBTYPE_MASK);
        if grade > best_grade {
            best_grade = grade;
            best = Some((ty, sub, be32(h, o + 8), be32(h, o + 12)));
        }
    }
    best.ok_or_else(ebadarch)
}

/// `IS_WHITESPACE`, `IS_EOL`.
fn is_white(c: u8) -> bool {
    c == b' ' || c == b'\t'
}
fn is_eol(c: u8) -> bool {
    c == b'#' || c == b'\n'
}

impl Kernel {
    /// `execve(fname, argp, envp)` and `__mac_execve(fname, argp, envp,
    /// mac_p)`.
    pub(crate) fn darwin_execve(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6], mac: bool) -> SyscallOutcome {
        if mac && a[3] != 0 {
            // mac_execve_enter: a label to internalize, and no policy to
            // claim its elements.
            self.darwin_unimplemented("__mac_execve with a MAC label (mac_execve_enter's label internalization)".into());
            let _ = super::set_result(m, self.ctx_addr, Errno::EINVAL.as_return());
            return SyscallOutcome::Continue;
        }
        match self.darwin_exec_activate(m, a[0], a[1], a[2]) {
            Ok(img) => {
                self.map_io().flush_all_shared(m);
                let lossy = |v: Vec<&[u8]>| v.into_iter().map(|s| String::from_utf8_lossy(s).into_owned()).collect::<Vec<_>>();
                let (argv, envp) = (lossy(img.strings.args()), lossy(img.strings.envs()));
                let path = img.path.clone();
                if self.trace {
                    eprintln!("[gex:{}] darwin execve({path:?}, {} args)", self.pid, argv.len());
                }
                self.darwin_exec = Some(Box::new(img));
                SyscallOutcome::Exec { path, argv, envp }
            }
            Err(e) => {
                let _ = super::set_result(m, self.ctx_addr, e.as_return());
                SyscallOutcome::Continue
            }
        }
    }

    /// `exec_activate_image`.
    pub(crate) fn darwin_exec_activate(&mut self, m: &GuestMem<'_>, fname: u64, argv: u64, envv: u64) -> Result<Image, Errno> {
        self.darwin_exec_activate_with(m, fname, argv, envv, None)
    }

    /// `exec_activate_image` with a spawn's preferred CPU types.
    pub(crate) fn darwin_exec_activate_with(&mut self, m: &GuestMem<'_>, fname: u64, argv: u64, envv: u64, binprefs: Option<[(u32, u32); 4]>) -> Result<Image, Errno> {
        let mut strings = Strings::new();
        strings.save_user_path(m, fname)?;
        let mut img = Imgp { strings, vdata: Vec::new(), interpret: false, interp_buffer: Vec::new(), origcputype: 0, origcpusubtype: 0, arch_offset: 0, arch_size: 0, path: String::new(), size: 0, binprefs };
        let mut itercount = 0;
        'again: loop {
            self.darwin_exec_lookup(&mut img)?;
            img.vdata = self.darwin_exec_read_page(&img.path, 0)?;
            loop {
                itercount += 1;
                if itercount > EAI_ITERLIMIT {
                    return Err(super::errno::EBADEXEC);
                }
                let mut act = self.darwin_mach_imgact(m, &mut img, argv, envv, fname)?;
                if matches!(act, Act::NotMine) {
                    act = self.darwin_fat_imgact(&mut img)?;
                }
                if matches!(act, Act::NotMine) {
                    act = darwin_shell_imgact(&mut img)?;
                }
                match act {
                    Act::Encapsulated => continue,
                    Act::Interpreter => continue 'again,
                    Act::NotMine => return Err(Errno::ENOEXEC),
                    Act::Done => break 'again,
                }
            }
        }
        // load_machfile's signatures, before the exec commits.
        let bytes = self.read_file(&img.path).ok_or(Errno::EIO)?;
        let size = if img.arch_size != 0 { img.arch_size } else { bytes.len() as u64 };
        let slice = bytes.get(img.arch_offset as usize..(img.arch_offset + size) as usize).ok_or(ebadmacho())?;
        let (sig, load_csflags) = self.darwin_load_signatures(&img.path, img.arch_offset, slice)?;
        Ok(Image { path: img.path, arch_offset: img.arch_offset, arch_size: img.arch_size, cputype: img.origcputype, cpusubtype: img.origcpusubtype, strings: img.strings, spawn: None, sig, load_csflags })
    }

    /// `namei` of the saved path, links followed, then
    /// `exec_check_permissions`.
    fn darwin_exec_lookup(&mut self, img: &mut Imgp) -> Result<(), Errno> {
        let Ok(path) = std::str::from_utf8(img.strings.path()) else {
            self.darwin_unimplemented("execve of a path that is not UTF-8 (gex's namespace names files in UTF-8)".into());
            return Err(Errno::ENOENT);
        };
        let abs = self.vfs.absolute(path);
        let md = self.vfs.metadata(&abs)?;
        if md.file_type != crate::vfs::FileType::Regular {
            return Err(Errno::EACCES);
        }
        if md.mode & 0o111 == 0 {
            return Err(Errno::EACCES);
        }
        if md.size == 0 {
            return Err(Errno::ENOEXEC);
        }
        // vnode_authorize(KAUTH_VNODE_EXECUTE): no mount here is noexec; the
        // superuser needs only an execute bit, which there is. Anyone else
        // by the owner's bit, the file being owned by whom its stat says,
        // the caller (gex's files have no owner of their own).
        if self.creds.uid() != 0 && md.mode & 0o100 == 0 {
            return Err(Errno::EACCES);
        }
        img.arch_offset = 0;
        img.arch_size = md.size;
        img.size = md.size;
        img.path = abs;
        Ok(())
    }

    /// `vn_rdwr` of a page at `offset`, zero-filled past the file's end.
    fn darwin_exec_read_page(&self, path: &str, offset: u64) -> Result<Vec<u8>, Errno> {
        let h = self.vfs.open(path, crate::fs::oflags::O_RDONLY, 0)?;
        let mut page = vec![0u8; PAGE_SIZE as usize];
        let mut got = 0;
        while got < page.len() {
            let n = h.read_at(offset + got as u64, &mut page[got..])? as usize;
            if n == 0 {
                break;
            }
            got += n;
        }
        Ok(page)
    }

    /// `exec_mach_imgact`, to the strings: the header's checks, then
    /// `exec_extract_strings`.
    fn darwin_mach_imgact(&mut self, m: &GuestMem<'_>, img: &mut Imgp, argv: u64, envv: u64, fname: u64) -> Result<Act, Errno> {
        let magic = le32(&img.vdata, 0);
        if magic == mh::CIGAM || magic == mh::CIGAM_64 {
            return Err(ebadarch());
        }
        if magic != mh::MAGIC && magic != mh::MAGIC_64 {
            return Ok(Act::NotMine);
        }
        if le32(&img.vdata, 12) != mh::EXECUTE {
            return Ok(Act::NotMine);
        }
        let (cputype, cpusubtype) = (le32(&img.vdata, 4), le32(&img.vdata, 8));
        if img.origcputype != 0 {
            if img.origcputype != cputype || img.origcpusubtype != cpusubtype {
                return Err(ebadarch());
            }
        } else {
            img.origcputype = cputype;
            img.origcpusubtype = cpusubtype;
        }
        if let Some(prefs) = img.binprefs {
            let mut ok = false;
            for &(pref, subpref) in &prefs {
                if pref == 0 {
                    return Err(ebadarch());
                }
                if super::spawn::is_any(pref) || binary_match(cpu::ARCH_MASK, pref, subpref, img.origcputype, img.origcpusubtype) {
                    ok = true;
                    break;
                }
            }
            if !ok {
                return Err(ebadarch());
            }
        }
        if grade_binary(img.origcputype, img.origcpusubtype & !cpu::SUBTYPE_MASK) == 0 {
            return Err(ebadarch());
        }
        let interp = img.interpret.then(|| (img.interp_buffer.as_slice(), fname));
        img.strings.extract(m, argv, envv, interp)?;
        Ok(Act::Done)
    }

    /// `exec_fat_imgact`.
    fn darwin_fat_imgact(&mut self, img: &mut Imgp) -> Result<Act, Errno> {
        if img.origcputype != 0 || be32(&img.vdata, 0) != mh::FAT_MAGIC {
            return Ok(Act::NotMine);
        }
        fat_validate(&img.vdata, img.size)?;
        let chosen = match img.binprefs {
            // A spawn's preferences in order: each an exact type, or any
            // for the usual grading.
            Some(prefs) => {
                let mut chosen = None;
                for &(pref, subpref) in &prefs {
                    if pref == 0 {
                        return Err(ebadarch());
                    }
                    if super::spawn::is_any(pref) {
                        break;
                    }
                    if let Ok(c) = fat_getarch(&img.vdata, pref, 0, subpref) {
                        chosen = Some(c);
                        break;
                    }
                }
                match chosen {
                    Some(c) => c,
                    None if prefs.iter().any(|&(p, _)| super::spawn::is_any(p)) => fat_best(&img.vdata)?,
                    None => return Err(super::errno::EBADEXEC),
                }
            }
            None => fat_best(&img.vdata)?,
        };
        let (ty, sub, offset, size) = chosen;
        img.vdata = self.darwin_exec_read_page(&img.path, u64::from(offset))?;
        img.arch_offset = u64::from(offset);
        img.arch_size = u64::from(size);
        img.origcputype = ty;
        img.origcpusubtype = sub;
        Ok(Act::Encapsulated)
    }
}

impl Kernel {
    /// The task an exec leaves ([`Self::darwin_exec_switch_body`]).
    pub fn darwin_exec_switch(&mut self, spawn: Option<&super::spawn::After>) {
        self.darwin_exec_switch_body(spawn);
        self.darwin_ipc_leave();
    }

    /// The new image takes the process over, once it is loaded: what
    /// `fdt_exec`, `proc_exec_switch_task` and `execsigs` keep of the old.
    /// Its knotes go and its close-on-exec descriptors close, and its
    /// record locks stay only on the files still open; its task's and
    /// threads' ports die and its IPC space ends, every right in it with
    /// its notifications; the new task keeps the host and special ports
    /// the old one held, its signal actions as execsigs leaves them, its
    /// limits, app type and dispatch queue offsets.
    fn darwin_exec_switch_body(&mut self, spawn: Option<&super::spawn::After>) {
        // exec_mach_imgact: P_EXEC.
        self.procs.set_execed(self.pid);
        // knotes_dealloc, then the descriptors and the kqueues they held.
        let all: Vec<_> = self.dtask.kevents.knotes.keys().copied().collect();
        for n in all {
            if self.knote_exists(n) {
                self.knote_drop(n);
            }
        }
        self.fds.close_on_exec();
        // POSIX_SPAWN_CLOEXEC_DEFAULT: only what the file actions made or
        // named stays.
        if let Some(sp) = spawn.filter(|s| s.flags & super::spawn::flag::CLOEXEC_DEFAULT != 0) {
            for (fd, _, _) in self.fds.entries() {
                if !sp.inherit.contains(&fd) {
                    let _ = self.fds.close(fd);
                }
            }
        }
        self.darwin_kqueue_reap();
        let keep = self.darwin_lock_vnodes_open();
        super::lockf::exec_keep(self.pid, &keep);
        // ipc_thread_terminate, ipc_task_terminate.
        let tids: Vec<i32> = self.dtask.kports.threads.keys().copied().collect();
        for t in tids {
            self.darwin_thread_ports_terminate(t);
        }
        let name = self.ipc().task_name_port_take();
        let flavored = self.darwin_flavor_ports_take();
        let k = &mut self.dtask.kports;
        let task_ports: Vec<_> = k.task.take().map(|(a, b)| vec![a, b]).unwrap_or_default().into_iter().chain(name).chain(flavored).collect();
        let ipc = &mut self.ipc();
        for p in task_ports {
            ipc.port_mut(p).kobject = None;
            ipc.port_mut(p).pinned = false;
            ipc.port_destroy(p);
        }
        ipc.space_terminate();
        // The notifications it owed, while the old task's objects are there
        // to hear of their ports.
        self.darwin_ipc_notify_drain();
        // The old threads' exception handlers go with them.
        for a in std::mem::take(&mut self.dtask.kports.thread_exc).into_values() {
            super::exception::release_all(self.ipc(), &a);
        }
        let old = std::mem::take(&mut self.dtask);
        let (realtimer, vtimers) = (old.realtimer, old.vtimers);
        let kp = old.kports;
        self.dtask = super::Task {
            ipc_raw: old.ipc_raw,
            kports: super::kobject::Kports { special: kp.special, registered: kp.registered, exc: kp.exc, ..Default::default() },
            strict: old.strict,
            // proc_resetregister: libpthread registers again.
            pthread: super::thread::Registration { registered: false, ..old.pthread },
            pidversion: old.pidversion,
            ladvlock: old.ladvlock,
            sigacts: old.sigacts,
            rlimits: old.rlimits,
            dispatchqueue_serialno_offset: old.dispatchqueue_serialno_offset,
            dispatchqueue_label_offset: old.dispatchqueue_label_offset,
            policy: old.policy,
            said: old.said,
            // p_csflags: the exec's own, made at its start from these.
            csflags: old.csflags,
            // exec_handle_sugid: the credential kept (set-id images are not
            // honored on a release kernel), P_SUGID cleared, the saved ids
            // the effective ones.
            cred: {
                let mut c = old.cred;
                c.svuid = c.uid;
                c.svgid = c.gid();
                c
            },
            // Until the image's policies make it (`vm_map_set_max_addr`).
            map_max: spawn.map_or(0, |s| s.max_addr),
            ..Default::default()
        };
        if spawn.is_some_and(|s| s.flags & super::spawn::flag::START_SUSPENDED != 0) {
            self.darwin_start_suspended();
        }
        // An exec's task is new, and so is its ledger (a spawn's own exec
        // made it before its attributes set limits on it).
        if spawn.is_none() {
            self.procs.jetsam().ledgers.insert(self.pid, super::footprint::Ledger::default());
        }
        // A new process's policy came with its fork; an exec's task is an
        // exec copy of the old (task_policy_create) that inherits its role
        // (proc_inherit_task_role).
        if spawn.is_none_or(|s| s.flags & super::spawn::flag::SETEXEC != 0) {
            self.darwin_policy_with(|p| {
                let mut n = super::taskpolicy::TaskPolicy::create(p, true);
                n.requested.role = p.requested.role;
                n.update(false);
                *p = n;
            });
        }
        self.darwin_inherit_itimers(realtimer, vtimers);
        self.darwin_finish = None;
        self.darwin_pipe_sigpipe = None;
        self.darwin_execsigs();
        // An exec's NOTE_EXEC (a new process's came in its spawner's call).
        if spawn.is_none_or(|s| s.flags & super::spawn::flag::SETEXEC != 0) {
            crate::procnote::post(self.pid, crate::procnote::note::EXEC);
        }
        if let Some(sp) = spawn {
            if sp.flags & super::spawn::flag::SETSIGMASK != 0 {
                self.darwin_set_sigmask(sp.sigmask);
            }
            if sp.flags & super::spawn::flag::SETSIGDEF != 0 {
                self.darwin_sigdefault(sp.sigdefault);
            }
            // exec_handle_spawnattr_policy for POSIX_SPAWN_SETEXEC (a new
            // process's came in its spawner's call).
            let (apptype, clamp, role) = sp.policy;
            let any = apptype != super::taskpolicy::apptype::NONE || clamp != super::workq::qos::UNSPECIFIED || role != super::taskpolicy::role::UNSPECIFIED;
            if any && sp.flags & super::spawn::flag::SETEXEC != 0 {
                self.darwin_policy_with(|p| p.spawnpolicy(apptype, clamp, role));
            }
        }
    }
}

/// `exec_shell_imgact`: a `#!` line names the interpreter and its words,
/// and the interpreter is looked up in the image's place. Only one level:
/// an interpreter that is itself a script is not run.
fn darwin_shell_imgact(img: &mut Imgp) -> Result<Act, Errno> {
    let v = &img.vdata;
    if v[0] != b'#' || v[1] != b'!' || img.interpret || img.origcputype != 0 {
        return Ok(Act::NotMine);
    }
    img.interpret = true;
    let mut i = 2;
    while i < IMG_SHSIZE {
        if is_eol(v[i]) {
            return Err(Errno::ENOEXEC);
        }
        if !is_white(v[i]) {
            break;
        }
        i += 1;
    }
    if i == IMG_SHSIZE {
        return Err(Errno::ENOEXEC);
    }
    let start = i;
    while i < IMG_SHSIZE && !is_eol(v[i]) {
        i += 1;
    }
    if i == IMG_SHSIZE {
        return Err(Errno::ENOEXEC);
    }
    while is_eol(v[i]) || is_white(v[i]) {
        i -= 1;
    }
    let end = i + 1;
    let name_end = (start..end).find(|&j| is_white(v[j])).unwrap_or(end);
    let interp = v[start..name_end].to_vec();
    img.interp_buffer = v[start..end].to_vec();
    img.strings.reset();
    img.strings.save_path(&interp)?;
    Ok(Act::Interpreter)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fat(arches: &[(u32, u32, u32, u32)]) -> Vec<u8> {
        let mut h = vec![0u8; PAGE_SIZE as usize];
        h[0..4].copy_from_slice(&mh::FAT_MAGIC.to_be_bytes());
        h[4..8].copy_from_slice(&(arches.len() as u32).to_be_bytes());
        for (i, &(t, s, o, n)) in arches.iter().enumerate() {
            for (k, w) in [t, s, o, n, 14].iter().enumerate() {
                h[8 + 20 * i + 4 * k..8 + 20 * i + 4 * k + 4].copy_from_slice(&w.to_be_bytes());
            }
        }
        h
    }

    #[test]
    fn a_fat_file_runs_its_best_arm64_slice() {
        let h = fat(&[(0x0100_0007, 3, 0x4000, 0x100), (cpu::TYPE_ARM64, 0, 0x8000, 0x100), (cpu::TYPE_ARM64, 1, 0xc000, 0x100)]);
        assert_eq!(fat_validate(&h, 0x10000), Ok(()));
        assert_eq!(fat_best(&h), Ok((cpu::TYPE_ARM64, 1, 0xc000, 0x100)));
        // arm64e is not for this CPU.
        let e = fat(&[(cpu::TYPE_ARM64, 0x8000_0002, 0x4000, 0x100)]);
        assert_eq!(fat_best(&e), Err(ebadarch()));
        // Overlapping, or past the file's end.
        assert_eq!(fat_validate(&fat(&[(cpu::TYPE_ARM64, 0, 0x4000, 0x5000), (cpu::TYPE_ARM64, 1, 0x8000, 0x100)]), 0x10000), Err(ebadmacho()));
        assert_eq!(fat_validate(&fat(&[(cpu::TYPE_ARM64, 0, 0x4000, 0x100)]), 0x4000), Err(ebadmacho()));
    }

    fn script(line: &[u8]) -> Imgp {
        let mut vdata = vec![0u8; PAGE_SIZE as usize];
        vdata[..line.len()].copy_from_slice(line);
        Imgp { strings: Strings::new(), vdata, interpret: false, interp_buffer: Vec::new(), origcputype: 0, origcpusubtype: 0, arch_offset: 0, arch_size: 0, path: String::new(), size: 0, binprefs: None }
    }

    #[test]
    fn a_shebang_line_names_the_interpreter_and_its_words() {
        let mut i = script(b"#!  /bin/x  -a\tb  # c\n");
        assert!(matches!(darwin_shell_imgact(&mut i), Ok(Act::Interpreter)));
        assert_eq!(i.strings.path(), b"/bin/x");
        assert_eq!(i.interp_buffer, b"/bin/x  -a\tb");
        // An interpreter that is a script is not run.
        assert!(matches!(darwin_shell_imgact(&mut i), Ok(Act::NotMine)));
        assert_eq!(darwin_shell_imgact(&mut script(b"#!\n")).err(), Some(Errno::ENOEXEC));
        assert_eq!(darwin_shell_imgact(&mut script(b"#!   ")).err(), Some(Errno::ENOEXEC));
        let long = [b"#!/bin/x ".as_slice(), &[b'a'; 600]].concat();
        assert_eq!(darwin_shell_imgact(&mut script(&long)).err(), Some(Errno::ENOEXEC));
    }
}
