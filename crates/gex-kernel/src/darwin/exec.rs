//! A new Darwin image's start (`bsd/kern/kern_exec.c`): the string area
//! its stack is built from (`exec_save_path`, `exec_extract_strings`,
//! `exec_add_apple_strings`), the main thread's stack
//! (`create_unix_stack`), and the copy out (`exec_copyout_strings`).

use super::rlimit::{self, MAXSSIZ};
use crate::errno::Errno;
use crate::syscalls::Kernel;
use crate::GuestMem;

/// `NCARGS`: `ARG_MAX`, the arguments and environment together.
pub const NCARGS: isize = rlimit::ARG_MAX as isize;
/// The kernel's `PAGE_SIZE`: arm64 iOS's 16 KiB, the page the commpage
/// says the kernel and its maps use.
pub const PAGE_SIZE: u64 = super::mach::PAGE_MASK + 1;
/// `MAXPATHLEN`.
const MAXPATHLEN: usize = 1024;
const EXECUTABLE_KEY: &[u8] = b"executable_path=";
/// A 64-bit image's pointer.
const PTR: isize = 8;

fn round_page(v: u64) -> Option<u64> {
    v.checked_add(PAGE_SIZE - 1).map(|r| r & !(PAGE_SIZE - 1))
}

fn trunc_page(v: u64) -> u64 {
    v & !(PAGE_SIZE - 1)
}

/// `copyinstr(addr, .., max)`: the string without its NUL, ENAMETOOLONG
/// when there is none in `max` bytes, EFAULT where memory ends first.
pub(crate) fn copyinstr(m: &GuestMem<'_>, addr: u64, max: usize) -> Result<Vec<u8>, Errno> {
    match m.read_cstr(addr, max) {
        Err(Errno::ENAMETOOLONG) if m.read(addr, max).is_err() => Err(Errno::EFAULT),
        r => r,
    }
}

/// `image_params`' string area: `ip_strings` up to `ip_strendp`, and what
/// is left of it and of `NCARGS`.
#[derive(Clone, Debug)]
pub struct Strings {
    buf: Vec<u8>,
    strspace: isize,
    argspace: isize,
    startargv: usize,
    endargv: usize,
    endenvv: usize,
    pub argc: usize,
    pub envc: usize,
    applec: usize,
}

impl Default for Strings {
    fn default() -> Self {
        Self::new()
    }
}

impl Strings {
    /// `execargs_alloc`: `NCARGS` and a page for the path and `apple[]`.
    pub fn new() -> Strings {
        Strings { buf: Vec::new(), strspace: NCARGS + PAGE_SIZE as isize, argspace: NCARGS, startargv: 0, endargv: 0, endenvv: 0, argc: 0, envc: 0, applec: 0 }
    }

    /// `exec_reset_save_path`.
    pub fn reset(&mut self) {
        self.buf.clear();
        self.argspace = NCARGS;
        self.strspace = NCARGS + PAGE_SIZE as isize;
    }

    /// `exec_save_path` of a path already in the kernel: `executable_path=`
    /// and it, at the start of the area.
    pub fn save_path(&mut self, path: &[u8]) -> Result<(), Errno> {
        let len = MAXPATHLEN.min(self.strspace.max(0) as usize);
        let path = &path[..path.iter().position(|&b| b == 0).unwrap_or(path.len())];
        if path.len() + 1 > len {
            return Err(Errno::ENAMETOOLONG);
        }
        self.buf.clear();
        self.buf.extend_from_slice(EXECUTABLE_KEY);
        self.buf.extend_from_slice(path);
        self.buf.push(0);
        self.strspace -= (EXECUTABLE_KEY.len() + path.len() + 1) as isize;
        Ok(())
    }

    /// `exec_save_path` of the caller's path.
    pub fn save_user_path(&mut self, m: &GuestMem<'_>, addr: u64) -> Result<(), Errno> {
        let len = MAXPATHLEN.min(self.strspace.max(0) as usize);
        let path = copyinstr(m, addr, len)?;
        self.save_path(&path)
    }

    /// The saved path (`excpath`): what is looked up.
    pub fn path(&self) -> &[u8] {
        let s = &self.buf[EXECUTABLE_KEY.len()..];
        &s[..s.iter().position(|&b| b == 0).unwrap_or(s.len())]
    }

    /// `exec_add_user_string` of a string already in the kernel.
    fn add(&mut self, s: &[u8], ncargs: bool) -> Result<(), Errno> {
        let space = if ncargs { self.argspace } else { self.strspace };
        let n = (s.len() + 1) as isize;
        if space <= 0 || n > space {
            return Err(Errno::E2BIG);
        }
        self.buf.extend_from_slice(s);
        self.buf.push(0);
        self.strspace -= n;
        if ncargs {
            self.argspace -= n;
        }
        Ok(())
    }

    /// `exec_add_user_string` from the caller's memory.
    fn add_user(&mut self, m: &GuestMem<'_>, addr: u64, ncargs: bool) -> Result<(), Errno> {
        let space = if ncargs { self.argspace } else { self.strspace };
        if space <= 0 {
            return Err(Errno::E2BIG);
        }
        match copyinstr(m, addr, space as usize) {
            Ok(s) => self.add(&s, ncargs),
            Err(Errno::ENAMETOOLONG) => Err(Errno::E2BIG),
            Err(e) => Err(e),
        }
    }

    /// Room for one more vector entry.
    fn charge_ptr(&mut self) -> Result<(), Errno> {
        if self.argspace < PTR {
            return Err(Errno::E2BIG);
        }
        self.argspace -= PTR;
        Ok(())
    }

    /// The pointer-size padding after the path, not charged to `NCARGS`.
    fn pad_path(&mut self) {
        while self.strspace % PTR != 0 {
            self.buf.push(0);
            self.strspace -= 1;
        }
    }

    /// The padding after the environment, charged to `NCARGS`.
    fn pad_env(&mut self) -> Result<(), Errno> {
        while self.strspace % PTR != 0 {
            if self.argspace < 1 {
                return Err(Errno::E2BIG);
            }
            self.buf.push(0);
            self.strspace -= 1;
            self.argspace -= 1;
        }
        Ok(())
    }

    /// `exec_extract_strings` from the caller's `argv` and `envv`, after an
    /// interpreter line's words and the script's path when `interp` is the
    /// line (`IMGPF_INTERPRET`): the script's path replaces `argv[0]`.
    pub fn extract(&mut self, m: &GuestMem<'_>, mut argv: u64, mut envv: u64, interp: Option<(&[u8], u64)>) -> Result<(), Errno> {
        self.pad_path();
        self.startargv = self.buf.len();
        self.argc = 0;
        if let Some((line, fname)) = interp {
            let line = &line[..line.iter().position(|&b| b == 0).unwrap_or(line.len())];
            let mut words = Vec::new();
            let mut rest = line;
            loop {
                let end = rest.iter().position(|&c| c == b' ' || c == b'\t').unwrap_or(rest.len());
                words.push(&rest[..end]);
                if end == rest.len() {
                    break;
                }
                rest = &rest[end + 1..];
                while let [b' ' | b'\t', tail @ ..] = rest {
                    rest = tail;
                }
            }
            for w in words {
                self.add(w, true)?;
                self.charge_ptr()?;
                self.argc += 1;
            }
            if argv != 0 && m.read_u64(argv)? != 0 {
                argv += PTR as u64;
            }
            self.add_user(m, fname, true)?;
            self.charge_ptr()?;
            self.argc += 1;
        }
        while argv != 0 {
            let arg = m.read_u64(argv)?;
            if arg == 0 {
                break;
            }
            argv += PTR as u64;
            self.add_user(m, arg, true)?;
            self.charge_ptr()?;
            self.argc += 1;
        }
        self.charge_ptr()?;
        self.endargv = self.buf.len();
        self.envc = 0;
        while envv != 0 {
            let env = m.read_u64(envv)?;
            envv += PTR as u64;
            if env == 0 {
                break;
            }
            self.add_user(m, env, true)?;
            self.charge_ptr()?;
            self.envc += 1;
        }
        self.charge_ptr()?;
        self.pad_env()?;
        self.endenvv = self.buf.len();
        Ok(())
    }

    /// `exec_extract_strings` of vectors the kernel holds: the first
    /// program's, which no caller's memory holds.
    pub fn extract_kernel(&mut self, argv: &[impl AsRef<[u8]>], envv: &[impl AsRef<[u8]>]) -> Result<(), Errno> {
        self.pad_path();
        self.startargv = self.buf.len();
        self.argc = 0;
        for a in argv {
            self.add(a.as_ref(), true)?;
            self.charge_ptr()?;
            self.argc += 1;
        }
        self.charge_ptr()?;
        self.endargv = self.buf.len();
        self.envc = 0;
        for e in envv {
            self.add(e.as_ref(), true)?;
            self.charge_ptr()?;
            self.envc += 1;
        }
        self.charge_ptr()?;
        self.pad_env()?;
        self.endenvv = self.buf.len();
        Ok(())
    }

    /// One `apple[]` string.
    fn add_apple(&mut self, s: &[u8]) -> Result<(), Errno> {
        self.add(s, false)?;
        self.applec += 1;
        Ok(())
    }

    /// The vectors' strings, NUL-split: `argv`, then `envp`.
    pub fn args(&self) -> Vec<&[u8]> {
        self.buf[self.startargv..self.endargv].split(|&b| b == 0).take(self.argc).collect()
    }

    pub fn envs(&self) -> Vec<&[u8]> {
        self.buf[self.endargv..self.endenvv].split(|&b| b == 0).take(self.envc).collect()
    }

    /// `exec_copyout_strings` to a stack whose top is `user_stack`: the
    /// stack pointer (at `argc`) and the bytes from it to the top.
    pub fn copyout(&self, user_stack: u64) -> Result<(u64, Vec<u8>), Errno> {
        if self.strspace % PTR != 0 {
            return Err(Errno::EINVAL);
        }
        let string_size = self.buf.len() as u64;
        let string_area = user_stack - string_size;
        let ptr_area_size = (self.argc + self.envc + self.applec + 3) as u64 * PTR as u64;
        let ptr_area = string_area - ptr_area_size;
        let sp = ptr_area - PTR as u64;
        let mut ptrs: Vec<u64> = Vec::new();
        let run = |start: usize, count: usize, null_term: bool, ptrs: &mut Vec<u64>| {
            let mut at = start;
            for _ in 0..count {
                ptrs.push(string_area + at as u64);
                at += self.buf[at..].iter().position(|&b| b == 0).unwrap_or(0) + 1;
            }
            if null_term {
                ptrs.push(0);
            }
        };
        run(self.startargv, self.argc, true, &mut ptrs);
        run(self.endargv, self.envc, true, &mut ptrs);
        run(0, 1, false, &mut ptrs);
        run(self.endenvv, self.applec - 1, true, &mut ptrs);
        let mut out = Vec::with_capacity((user_stack - sp) as usize);
        out.extend_from_slice(&(self.argc as u64).to_le_bytes());
        for p in ptrs {
            out.extend_from_slice(&p.to_le_bytes());
        }
        out.extend_from_slice(&self.buf);
        Ok((sp, out))
    }
}

/// What the loader found that the start needs (`load_result_t`).
pub struct Loaded<'a> {
    /// The executable's Mach-O header, which dyld is handed on the stack.
    pub mach_header: u64,
    /// `LC_LOAD_DYLINKER`'s path: dyld runs first.
    pub dylinker: Option<&'a str>,
    /// `LC_MAIN`'s `stacksize` (0: the default).
    pub stacksize: u64,
    /// The executable as the guest names it, and where its slice starts.
    pub exe_path: &'a str,
    pub file_start: u64,
    /// Its `LC_CODE_SIGNATURE` blob.
    pub code_signature: Option<&'a [u8]>,
    /// An exec's image's signature as its load added it and the load's
    /// code signing flags; none for the run's first program, whose load is
    /// done here.
    pub signature: Option<super::codesign::LoadResult>,
    /// `_POSIX_SPAWN_NANO_ALLOCATOR` among a spawn's flags.
    pub nano: bool,
}

/// `USRSTACK64`: where an arm64 process's main stack starts, before the
/// image's slide moves it down ([`user_stack`]).
pub const USRSTACK64: u64 = 0x1_6FE0_0000;

/// `load_main`'s stack top for a main image slid by `slide`: "The stack
/// slides down from the default location".
pub fn user_stack(slide: u64) -> u64 {
    trunc_page(USRSTACK64 - slide)
}

/// The kernel's `random()`: 31 bits of `read_random`.
pub(crate) fn random() -> u32 {
    let mut b = [0u8; 4];
    crate::vfs::devfs::fill_random(&mut b);
    u32::from_le_bytes(b) & 0x7fff_ffff
}

/// `load_machfile`'s random offsets for a new 64-bit map, whose page is
/// 16 KiB (`vm_map_set_page_shift(map, SIXTEENK_PAGE_SHIFT)`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slides {
    /// A position-independent main image's: 1 to 1023 pages
    /// (`vm_map_get_max_aslr_slide_pages`, 16 MiB) and 0, 1 or 2 of
    /// `vm_map_get_max_aslr_slide_section`'s three sections, each
    /// `ARM_TT_TWIG_SIZE` (32 MiB with 16 KiB translation pages).
    pub main: u64,
    /// dyld's own: 1 to 255 pages (`vm_map_get_max_loader_aslr_slide_pages`,
    /// 4 MiB), from the main image's end when dyld is linked at 0.
    pub dyld: u64,
}

impl Slides {
    const PAGE_SHIFT: u32 = 14;
    const MAX_SLIDE_PAGES: u64 = 1 << (24 - Self::PAGE_SHIFT);
    const MAX_LOADER_SLIDE_PAGES: u64 = 1 << (22 - Self::PAGE_SHIFT);
    const MAX_SECTIONS: u64 = 3;
    const SECTION_SIZE: u64 = 32 << 20;

    /// The offsets, drawn as `load_machfile` draws them: the section, the
    /// main image's pages, then dyld's. A release kernel never leaves them
    /// out (`IMGPF_DISABLE_ASLR` comes only from `P_DISABLE_ASLR`, which
    /// `posix_spawn`'s `_POSIX_SPAWN_DISABLE_ASLR` sets only without
    /// `SECURE_KERNEL`, and the kernel's own process only on a DEVELOPMENT
    /// or DEBUG kernel).
    pub fn draw() -> Slides {
        let section = u64::from(random()) % Self::MAX_SECTIONS * Self::SECTION_SIZE;
        let pages = u64::from(random()) % (Self::MAX_SLIDE_PAGES - 1) + 1;
        let dyld = u64::from(random()) % (Self::MAX_LOADER_SLIDE_PAGES - 1) + 1;
        Slides { main: (pages << Self::PAGE_SHIFT) + section, dyld: dyld << Self::PAGE_SHIFT }
    }
}

/// The main thread's stack as `create_unix_stack` allocates it and the
/// strings copied out onto it.
pub struct MainStack {
    pub sp: u64,
    /// From `sp` to the top.
    pub bytes: Vec<u8>,
    /// The allocation, and how much of its bottom is the guard
    /// (`VM_PROT_NONE`).
    pub alloc: u64,
    pub size: u64,
    pub guard: u64,
}

/// `exe_boothash_salt`: random, once a boot.
fn boothash_salt(k: &Kernel) -> Result<u32, Errno> {
    static SALT: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    if let Some(&s) = SALT.get() {
        return Ok(s);
    }
    let s = k.darwin_read_random()? as u32;
    Ok(*SALT.get_or_init(|| s))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Kernel {
    /// `vnode_get_va_fsid` and `va_fileid` of `path`, links followed.
    pub(crate) fn darwin_file_id(&self, path: &str) -> Result<(u64, u64), Errno> {
        let md = self.vfs.metadata(path)?;
        let mnt = super::kern::mount_of(&self.vfs.canonical(&self.vfs.absolute(path)));
        let fsid = u64::from(mnt.fsid as u32) | u64::from(super::kern::vfsstat::APFS_TYPENUM) << 32;
        Ok((fsid, md.ino))
    }

    /// `exec_add_entropy_key`.
    fn darwin_entropy_key(&self, s: &mut Strings, key: &str, values: usize, embed_nul: bool) -> Result<(), Errno> {
        let mut v = (0..values).map(|_| self.darwin_read_random()).collect::<Result<Vec<u64>, Errno>>()?;
        if embed_nul {
            v[0] &= !(0xff << 8);
        }
        let text = v.iter().map(|x| format!("0x{x:x}")).collect::<Vec<_>>().join(",");
        s.add_apple(format!("{key}{text}").as_bytes())
    }

    /// `exec_add_apple_strings`, after `executable_path`.
    fn darwin_apple_strings(&mut self, s: &mut Strings, l: &Loaded, stack: [u64; 4]) -> Result<(), Errno> {
        s.applec = 1;
        // `commpage_text64_location`: no commpage text page without
        // CONFIG_ARM_PFZ, which an embedded arm64 kernel is built without.
        s.add_apple(b"pfz=0x0")?;
        if l.nano {
            s.add_apple(b"MallocNanoZone=1")?;
        }
        self.darwin_entropy_key(s, "stack_guard=", 1, true)?;
        self.darwin_entropy_key(s, "malloc_entropy=", 2, false)?;
        self.darwin_entropy_key(s, "ptr_munge=", 1, false)?;
        s.add_apple(format!("main_stack=0x{:x},0x{:x},0x{:x},0x{:x}", stack[0], stack[1], stack[2], stack[3]).as_bytes())?;
        let (fsid, fileid) = self.darwin_file_id(l.exe_path)?;
        s.add_apple(format!("executable_file=0x{fsid:x},0x{fileid:x}").as_bytes())?;
        self.dtask.image_files = vec![(fsid, fileid, self.vfs.canonical(l.exe_path))];
        if let Some(dyld) = l.dylinker {
            let (fsid, fileid) = self.darwin_file_id(dyld)?;
            if fsid != 0 || fileid != 0 {
                s.add_apple(format!("dyld_file=0x{fsid:x},0x{fileid:x}").as_bytes())?;
                self.dtask.image_files.push((fsid, fileid, self.vfs.canonical(dyld)));
            }
        }
        if let Some(cdhash) = l.code_signature.map(super::codesign::cdhash).transpose()? {
            s.add_apple(format!("executable_cdhash={}", hex(&cdhash)).as_bytes())?;
            // The cdhash mixed with the boot: SHA-256 of the salt, the boot
            // session's uuid_string_t (with its NUL) and the cdhash.
            use sha2::Digest;
            let mut uuid = [0u8; 37];
            let u = super::sysctl::bootsessionuuid().as_bytes();
            uuid[..u.len()].copy_from_slice(u);
            let mut h = sha2::Sha256::new();
            h.update(boothash_salt(self)?.to_le_bytes());
            h.update(uuid);
            h.update(cdhash);
            s.add_apple(format!("executable_boothash={}", hex(&h.finalize()[..20])).as_bytes())?;
        }
        // The main thread's port, a send right the program's libpthread
        // takes (and _bsdthread_terminate consumes).
        let port = self.darwin_thread_ports(self.tid).1;
        self.ipc().make_send(port);
        let name = self.darwin_copyout_send(port);
        s.add_apple(format!("th_port=0x{name:x}").as_bytes())?;
        let hr = self.dtask.codesign.as_ref().map_or(0, |cs| {
            [
                ("com.apple.developer.web-browser-engine.host", 0x01),
                ("com.apple.developer.web-browser-engine.rendering", 0x02),
                ("com.apple.developer.web-browser-engine.networking", 0x04),
                ("com.apple.developer.web-browser-engine.webcontent", 0x08),
            ]
            .iter()
            .filter(|(e, _)| cs.entitled(e))
            .fold(0u32, |a, &(_, m)| a | m)
        });
        if hr != 0 {
            s.add_apple(format!("HardenedRuntime=0x{hr:x}").as_bytes())?;
        }
        s.pad_path();
        Ok(())
    }

    /// A new image's start ([`Self::darwin_start_body`]).
    pub fn darwin_start(&mut self, strings: Option<Strings>, l: &Loaded, user_stack: u64) -> Result<MainStack, Errno> {
        let out = self.darwin_start_body(strings, l, user_stack);
        self.darwin_ipc_leave();
        out
    }

    /// A spawned child's image activated in its parent's `posix_spawn`, as
    /// XNU's `exec_activate_image` and `process_signature` do there before
    /// the call returns ([`Self::darwin_activate_body`]): the child's
    /// signature, credential labels and launch constraints are set when its
    /// parent goes on. The answer is kept for the child's start, which a
    /// refusal kills.
    pub fn darwin_activate(&mut self, l: &Loaded) {
        let out = self.darwin_activate_body(l);
        self.darwin_ipc_leave();
        self.dtask.activated = Some(out);
    }

    /// The image's code signing flags and its credential's entitlements
    /// (AMFI's label update), then Sandbox's label update, then the launch
    /// constraints (`process_signature`); a policy's refusal kills the exec.
    fn darwin_activate_body(&mut self, l: &Loaded) -> Result<(), Errno> {
        let lr = match l.signature.clone() {
            Some(s) => s,
            None => {
                let bytes = self.read_file(l.exe_path).ok_or(Errno::EIO)?;
                let (off, size) = super::execve::best_slice(&bytes)?;
                let slice = bytes.get(off as usize..(off + size) as usize).ok_or(super::errno::EBADMACHO)?;
                self.darwin_load_signatures(l.exe_path, off, slice)?
            }
        };
        self.dtask.textoff = l.file_start as i64;
        // p_uuid, p_cputype and p_cpusubtype: the image's.
        self.dtask.uuid = lr.uuid;
        self.dtask.cputype = lr.cputype;
        // set_proc_name: the image's file name.
        let name = l.exe_path.as_bytes().rsplit(|&c| c == b'/').next().unwrap_or_default();
        self.dtask.p_name.set(name);
        if let Err(why) = self.darwin_exec_csflags(lr.sig, lr.csflags) {
            if self.trace {
                eprintln!("[gex:{}] AMFI: killing {}: {why}", self.pid, l.exe_path);
            }
            return Err(Errno::EPERM);
        }
        // Then Sandbox's label update, of the script's vnode for a script;
        // its kill is the exec's error, EPERM (mac_error_select of AMFI's
        // none and its 1).
        let pending = self.dtask.exec_sandbox.take().unwrap_or_default();
        let vnode = self.vfs.canonical(&self.vfs.absolute(pending.script.as_deref().unwrap_or(l.exe_path)));
        if let Err(super::sandboxes::Kill(why)) = self.darwin_sb_label_update_execve(&super::sandboxes::Exec { path: &vnode, spawnattrs: pending.spawnattrs.as_deref(), marked: pending.marked }) {
            if self.trace {
                eprintln!("[gex:{}] Sandbox: hook..execve() killing {}[pid={}, uid={}]: {why}", self.pid, vnode, self.pid, self.creds.uid());
            }
            return Err(Errno::EPERM);
        }
        self.darwin_launch_constraints()
    }

    /// The new image's main stack with its strings on it: `create_unix_stack`
    /// below `user_stack`, the `apple[]` strings, `exec_copyout_strings`,
    /// and dyld's copy of the executable's header pushed below them.
    /// `strings` is the exec's area; the run's first program has its
    /// path and vectors from the kernel. A spawned child's image was
    /// activated in its parent's call ([`Self::darwin_activate`]); an
    /// exec's and the first program's is activated here.
    fn darwin_start_body(&mut self, strings: Option<Strings>, l: &Loaded, user_stack: u64) -> Result<MainStack, Errno> {
        match self.dtask.activated.take() {
            Some(r) => r?,
            None => self.darwin_activate_body(l)?,
        }
        self.darwin_publish();
        // The image's entitlements that raise its default memory limit.
        self.darwin_jetsam_entitlements();
        self.darwin_vm_policies();
        // mpo_proc_notify_exec_complete.
        if let Err(why) = self.darwin_sb_exec_complete() {
            if self.trace {
                eprintln!("[gex:{}] Sandbox: killing {}: {why}", self.pid, l.exe_path);
            }
            return Err(Errno::EPERM);
        }
        // task_set_main_thread_qos, for an exec's, a spawn's and the first
        // image's main thread alike.
        let q = self.darwin_main_thread_qos();
        let main = self.darwin_me();
        main.policy.qos = q;
        main.policy.relpri = 0;
        let mut s = match strings {
            Some(s) => s,
            None => {
                // The run's first program is exec'd as XNU execs its first
                // process (load_init_program): P_EXEC.
                self.procs.set_execed(self.pid);
                let mut s = Strings::new();
                s.save_path(l.exe_path.as_bytes())?;
                s.extract_kernel(&self.argv.clone(), &self.envp.clone())?;
                s
            }
        };
        // load_main: a stack size LC_MAIN gives, with its guard page.
        let (mut stack_size, alloc_size, custom) = if l.stacksize != 0 {
            if l.stacksize.checked_add(4 * PAGE_SIZE).is_none() {
                return Err(Errno::ENOMEM);
            }
            (l.stacksize, l.stacksize + PAGE_SIZE, true)
        } else {
            (0, MAXSSIZ, false)
        };
        let size = round_page(alloc_size).ok_or(Errno::ENOMEM)?;
        // create_unix_stack: the allocation right below the stack's top,
        // fixed; where that cannot be had, anywhere, the top then its end
        // (the load result's user_stack and p_user_stack follow it). Exec
        // fails without either.
        let (alloc, user_stack) = match user_stack.checked_sub(size).map(trunc_page).filter(|&a| self.darwin_fixed_fits(a, size)) {
            Some(a) => (a, user_stack),
            None => {
                let a = self.darwin_locate_space(0, size, 0).map_err(|_| Errno::ENOMEM)?;
                (a, a + size)
            }
        };
        let guard = if stack_size == 0 {
            stack_size = self.dtask.rlimits.cur(rlimit::res::STACK);
            trunc_page(size.checked_sub(stack_size).ok_or(Errno::ENOMEM)?)
        } else {
            PAGE_SIZE
        };
        self.darwin_user_stack = user_stack;
        self.dtask.custom_stack = custom;
        self.darwin_apple_strings(&mut s, l, [user_stack, stack_size, alloc, alloc_size])?;
        let (mut sp, mut bytes) = s.copyout(user_stack)?;
        // exec_copyout_strings: for sysctl_procargs to find them by.
        let live = &self.dtask.live;
        live.argc.store(s.argc as u32, std::sync::atomic::Ordering::Relaxed);
        live.argslen.store(s.buf.len() as u32, std::sync::atomic::Ordering::Relaxed);
        live.user_stack.store(user_stack, std::sync::atomic::Ordering::Relaxed);
        if l.dylinker.is_some() {
            sp -= PTR as u64;
            let mut b = l.mach_header.to_le_bytes().to_vec();
            b.extend_from_slice(&bytes);
            bytes = b;
        }
        // create_unix_stack's mach_vm_allocate_kernel(VM_MEMORY_STACK), and
        // its mach_vm_protect of the guard, which clips the entry there.
        const VM_MEMORY_STACK: u8 = 30;
        self.dtask.vm.enter_anon(alloc, alloc + size, super::vm::Attrs { alias: VM_MEMORY_STACK, ..Default::default() }, false);
        self.dtask.vm.clip_range(alloc, alloc + guard);
        Ok(MainStack { sp, bytes, alloc, size, guard })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_strings_area_is_laid_out_as_exec_copyout_strings_does() {
        let mut s = Strings::new();
        s.save_path(b"/bin/x").unwrap();
        s.extract_kernel(&["x", "-a"], &["A=1"]).unwrap();
        s.applec = 1;
        s.add_apple(b"k=v").unwrap();
        s.pad_path();
        let top = 0x1000_0000u64;
        let (sp, b) = s.copyout(top).unwrap();
        let word = |i: usize| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
        let cstr = |a: u64| {
            let o = (a - sp) as usize;
            let n = b[o..].iter().position(|&c| c == 0).unwrap();
            String::from_utf8(b[o..o + n].to_vec()).unwrap()
        };
        assert_eq!(word(0), 2);
        assert_eq!(cstr(word(1)), "x");
        assert_eq!(cstr(word(2)), "-a");
        assert_eq!(word(3), 0);
        assert_eq!(cstr(word(4)), "A=1");
        assert_eq!(word(5), 0);
        assert_eq!(cstr(word(6)), "executable_path=/bin/x");
        assert_eq!(cstr(word(7)), "k=v");
        assert_eq!(word(8), 0);
        // The strings start at the top less their size, which is
        // pointer-aligned; the path is first among them.
        assert_eq!(word(6), top - s.buf.len() as u64);
        assert_eq!(s.buf.len() % 8, 0);
        assert_eq!(sp % 8, 0);
    }

    #[test]
    fn the_slides_are_load_machfile_s() {
        for _ in 0..2000 {
            let s = Slides::draw();
            let (pages, section) = (s.main % (32 << 20), s.main / (32 << 20));
            assert!(pages % PAGE_SIZE == 0 && (PAGE_SIZE..=1023 * PAGE_SIZE).contains(&pages), "{s:x?}");
            assert!(section <= 2, "{s:x?}");
            assert!(s.dyld % PAGE_SIZE == 0 && (PAGE_SIZE..=255 * PAGE_SIZE).contains(&s.dyld), "{s:x?}");
        }
        assert_eq!(user_stack(0x2c_c000), 0x1_6fb3_4000);
    }

    #[test]
    fn the_arguments_are_held_to_ncargs() {
        let mut s = Strings::new();
        s.save_path(b"/bin/x").unwrap();
        let big = vec![b'a'; NCARGS as usize];
        assert_eq!(s.extract_kernel(&[big.as_slice()], &[] as &[&[u8]]), Err(Errno::E2BIG));
        let mut s = Strings::new();
        s.save_path(b"/bin/x").unwrap();
        let fits = vec![b'a'; NCARGS as usize - 1 - 3 * 8];
        assert_eq!(s.extract_kernel(&[fits.as_slice()], &[] as &[&[u8]]), Ok(()));
    }
}
