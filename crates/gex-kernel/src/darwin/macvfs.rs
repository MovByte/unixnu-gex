//! Sandbox's checks of the file calls: its vnode and file hooks
//! (`mpo_vnode_check_*`, `mpo_file_check_*`), each made where XNU calls
//! it: after the call's own checks of its arguments and its lookup, and
//! before its permission checks (`vnode_authorize`) and its work. A
//! refusal is the call's error.
//!
//! A lookup (`namei`) gives Sandbox the path it was given, and again each
//! time a symbolic link sends it on (`mac_vnode_check_lookup_preflight`:
//! file-test-existence of the path, made canonical if a filter asks for
//! it), and reads each link it follows only once Sandbox lets it
//! (`mac_vnode_check_readlink`). Where a lookup, or a check made before a
//! hook, fails, the hooks after it are not reached: the call goes on to
//! fail as it does.
//!
//! What a hook's filters read of its vnode is [`SbVnode`]: the vnode's
//! path with no link on it, its type, mode, device and flags, whether it
//! is a terminal, and its filesystem's name; a name under a directory (a
//! file being made, a lookup's path) has its directory's, and only the
//! type its hook gives.

use super::mac::{op, SbArgs, SbVnode};
use super::sandbox;
use super::sysno as sys;
use crate::errno::Errno;
use crate::syscalls::Kernel;
use crate::vfs::{FileType, Metadata};
use crate::GuestMem;

/// `MAXSYMLINKS`, `MAXPATHLEN`.
const MAXSYMLINKS: usize = 32;
const MAXPATHLEN: usize = 1024;
/// The extended calls' "no owner" (KAUTH_UID_NONE, KAUTH_GID_NONE) and
/// `_FILESEC_REMOVE_ACL`.
const NO_ID: u32 = !0 - 100;
const REMOVE_ACL: u64 = 1;

/// Darwin's `AT_*` flags, and renameatx_np's.
mod at {
    pub const EACCESS: u64 = 0x10;
    pub const SYMLINK_NOFOLLOW: u64 = 0x20;
    pub const SYMLINK_FOLLOW: u64 = 0x40;
    pub const REMOVEDIR: u64 = 0x80;
    pub const REMOVEDIR_DATALESS: u64 = 0x100;
    pub const REALDEV: u64 = 0x200;
    pub const FDONLY: u64 = 0x400;
    pub const SYMLINK_NOFOLLOW_ANY: u64 = 0x800;
    pub const RENAME_SECLUDE: u64 = 0x1;
    pub const RENAME_SWAP: u64 = 0x2;
    pub const RENAME_EXCL: u64 = 0x4;
    pub const RENAME_NOFOLLOW_ANY: u64 = 0x10;
}

/// `enum vtype`.
pub mod vt {
    pub const VNON: u32 = 0;
    pub const VREG: u32 = 1;
    pub const VDIR: u32 = 2;
    pub const VBLK: u32 = 3;
    pub const VCHR: u32 = 4;
    pub const VLNK: u32 = 5;
    pub const VSOCK: u32 = 6;
    pub const VFIFO: u32 = 7;
    pub const VBAD: u32 = 8;
}

/// The vnode type of a file of type `t`.
pub fn vtype_of(t: FileType) -> u32 {
    match t {
        FileType::Regular => vt::VREG,
        FileType::Directory => vt::VDIR,
        FileType::CharDevice => vt::VCHR,
        FileType::Symlink => vt::VLNK,
        FileType::Socket => vt::VSOCK,
        FileType::Fifo => vt::VFIFO,
    }
}

/// A file a lookup found: its path (no link on it), its attributes, and
/// the directory it was found in with the name it was found by, as the
/// call gave it (none for a path that ends in `.` or `..`, or is the
/// root).
#[derive(Clone, Debug)]
pub struct Found {
    pub path: String,
    pub md: Metadata,
    pub parent: Option<(String, String)>,
}

impl Found {
    pub fn is_dir(&self) -> bool {
        self.md.file_type == FileType::Directory
    }
}

/// What a lookup made of a path.
#[derive(Clone, Debug)]
pub enum Lookup {
    Found(Found),
    /// Its last component is not in directory `dir`: `name`, as the call
    /// gave it (with any slash after it).
    Missing { dir: Found, name: String },
    /// The lookup fails, for the call to report.
    Failed,
}

impl Lookup {
    pub fn found(self) -> Option<Found> {
        match self {
            Lookup::Found(f) => Some(f),
            _ => None,
        }
    }
}

/// `dir`'s path with `name` after it (no second slash after the root).
fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// A file's flags (`va_flags`): the filesystems here keep none, and devfs
/// gives its root UF_HIDDEN.
fn file_flags(path: &str) -> u32 {
    let mnt = super::kern::mount_of(path);
    if mnt.fs == super::kern::Fs::Devfs && path == mnt.on {
        super::devfs::UF_HIDDEN
    } else {
        0
    }
}

/// The vnode Sandbox reads of file `md` at `path` (no link on it).
pub fn sb_vnode(path: &str, md: &Metadata) -> SbVnode {
    let mnt = super::kern::mount_of(path);
    SbVnode {
        path: path.as_bytes().to_vec(),
        mount_len: if path == mnt.on { -1 } else { mnt.on.len() as i64 },
        vtype: Some(vtype_of(md.file_type)),
        tty: super::ttydev::vnode_is_tty(md),
        mode: Some((md.mode & 0xfff) as u16),
        flags: file_flags(path),
        rdev: if md.file_type == FileType::CharDevice { super::attrcall::darwin_dev(md.rdev) } else { 0 },
        fs: super::kern::fs_name(mnt),
        of: Some((path.to_string(), md.clone())),
        ..Default::default()
    }
}

/// Name `name` under directory `dir`, of type `vtype` when its hook gives
/// one (`args[0x190]` bit 7): the directory's path and the name
/// (`0x...9f4dbc`), on the directory's mount, with the directory's other
/// attributes and no mode.
pub fn sb_named(dir: &Found, name: &str, vtype: Option<u32>) -> SbVnode {
    let d = sb_vnode(&dir.path, &dir.md);
    let path = join(&dir.path, name);
    let on = super::kern::mount_of(&dir.path).on.len() as i64;
    SbVnode { mount_len: if on == path.len() as i64 { -1 } else { on }, path: path.into_bytes(), named: true, vtype, mode: None, ..d }
}

/// A lookup's path `name` (`args[0x190]` bit 2): under directory `dir`,
/// or from the root when absolute (on no mount: `args[0x160]` 0).
fn sb_lookup(dir: &Found, name: &str) -> SbVnode {
    let mut v = sb_named(dir, name, None);
    if name.starts_with('/') {
        v.path = name.as_bytes().to_vec();
        v.mount_len = 0;
    }
    v.lookup = true;
    v
}

impl Kernel {
    /// The owner, group, mode and flags of the file Sandbox's vnode `v`
    /// reads them of ([`SbVnode::of`]); none where `v` gives its own.
    pub(crate) fn darwin_sb_attrs(&self, v: &SbVnode) -> Result<Option<super::vattr::Owned>, String> {
        match &v.of {
            Some((path, md)) => super::vattr::of(&self.vfs, path, md, None).map(Some),
            None => Ok(None),
        }
    }

    fn darwin_sb_vnode_eval(&mut self, op: usize, v: SbVnode, quiet: bool) -> (u32, u32) {
        let sb = self.darwin_sandbox();
        let a = SbArgs { kind: sandbox::kind::VNODE, quiet, vnode: Some(v), ..Default::default() };
        let (errno, flags, _) = self.darwin_sb_evaluate_with(sb.as_ref(), op, &a);
        (errno, flags)
    }

    fn darwin_sb_vnode_check(&mut self, op: usize, v: SbVnode) -> u32 {
        self.darwin_sb_vnode_eval(op, v, false).0
    }

    /// The directory a lookup from descriptor `dirfd` (Darwin's numbering)
    /// starts in: the working directory's path, or the descriptor's, with
    /// no link on it; none when it is not one (the call reports why).
    fn darwin_sb_start(&self, dirfd: u64) -> Option<Found> {
        let p = self.path_io().at_path_str(super::bsd::dirfd(dirfd) as i32, ".").ok()?;
        let path = self.vfs.canonical(&p);
        let md = self.vfs.metadata(&path).ok()?;
        (md.file_type == FileType::Directory).then_some(Found { path, md, parent: None })
    }

    /// The working directory, where a lookup of a relative path starts.
    pub(crate) fn darwin_sb_start_cwd(&self) -> Option<Found> {
        self.darwin_sb_start(super::bsd::AT_FDCWD as u64)
    }

    /// The vnode an open descriptor `fd` names (`fp_getfvp`), none for one
    /// that is no vnode.
    pub(crate) fn darwin_sb_fd_vnode(&mut self, fd: i32) -> Option<Found> {
        let file = self.fds.get(fd).ok()?;
        self.darwin_vnode_of(&file)?;
        let md = file.handle.metadata().ok()?;
        Some(Found { path: super::vattr::vnode_path(&self.vfs, &file.path, &md), md, parent: None })
    }

    /// `namei` of the path at guest `path` from descriptor `dirfd`
    /// (Darwin's numbering), following a link at its end with `follow`, or
    /// none on the way with `nofollow_any` (NAMEI_NOFOLLOW_ANY). Sandbox's
    /// refusal is the error; a path that cannot be read, or a descriptor
    /// that is no directory, fails the lookup for the call to report.
    pub(crate) fn darwin_sb_namei(&mut self, m: &GuestMem<'_>, dirfd: u64, path: u64, follow: bool, nofollow_any: bool) -> Result<Lookup, Errno> {
        let Ok(raw) = m.read_cstr(path, MAXPATHLEN) else { return Ok(Lookup::Failed) };
        let Ok(raw) = String::from_utf8(raw) else { return Ok(Lookup::Failed) };
        if raw.is_empty() {
            return Ok(Lookup::Failed);
        }
        // (the directory only for a relative path, as nameiat asks)
        let start = if raw.starts_with('/') { None } else { self.darwin_sb_start(dirfd) };
        self.darwin_sb_lookup(start, &raw, follow, nofollow_any)
    }

    /// The lookup of path `raw` from directory `start` (`namei`'s loop):
    /// an absolute path from the root, its leading slashes dropped; each
    /// pass given to Sandbox first, then looked up a component at a time
    /// (`..` to the directory's parent), until a link it is to follow
    /// (one before the end, or the last with `follow` or a slash after it)
    /// sends it on, from the link's directory or the root, with the
    /// link's contents in place of its name; at most MAXSYMLINKS links.
    /// A relative path with no directory `start` fails.
    pub(crate) fn darwin_sb_lookup(&mut self, start: Option<Found>, raw: &str, follow: bool, nofollow_any: bool) -> Result<Lookup, Errno> {
        let (mut dir, mut rest) = if raw.starts_with('/') {
            let md = match self.vfs.metadata("/") {
                Ok(md) => md,
                Err(_) => return Ok(Lookup::Failed),
            };
            (Found { path: "/".into(), md, parent: None }, raw.trim_start_matches('/').to_string())
        } else {
            let Some(start) = start else { return Ok(Lookup::Failed) };
            (start, raw.to_string())
        };
        let mut links = 0;
        'pass: loop {
            let e = self.darwin_sb_vnode_check(op::FILE_TEST_EXISTENCE, sb_lookup(&dir, &rest));
            if e != 0 {
                return Err(super::errno::errno_of(e as i32));
            }
            // A path with no `.` or `..` and no link on the way is the
            // one its directory and components name.
            let plain = !rest.split('/').any(|c| c == "." || c == "..");
            let trailing = rest.ends_with('/');
            let abs = crate::vfs::normalize(&rest, &dir.path);
            if plain && self.vfs.no_link_on(&abs, follow || trailing) {
                return Ok(self.darwin_sb_plain(&abs, &rest, trailing));
            }
            let mut cur = dir.clone();
            let mut i = 0;
            loop {
                let b = rest.as_bytes();
                while i < b.len() && b[i] == b'/' {
                    i += 1;
                }
                if i >= b.len() {
                    return Ok(Lookup::Found(Found { parent: None, ..cur }));
                }
                if !cur.is_dir() {
                    return Ok(Lookup::Failed);
                }
                let end = rest[i..].find('/').map_or(rest.len(), |j| i + j);
                let comp = &rest[i..end];
                let tail = &rest[end..];
                let last = tail.bytes().all(|c| c == b'/');
                if comp == "." || comp == ".." {
                    if comp == ".." {
                        let up = crate::vfs::parent_of(&cur.path);
                        let Ok(md) = self.vfs.metadata(&up) else { return Ok(Lookup::Failed) };
                        cur = Found { path: up, md, parent: None };
                    }
                    cur.parent = None;
                    i = end;
                    continue;
                }
                let p = join(&cur.path, comp);
                let md = match self.vfs.metadata_nofollow(&p) {
                    Ok(md) => md,
                    Err(_) if last => return Ok(Lookup::Missing { name: rest[i..].to_string(), dir: cur }),
                    Err(_) => return Ok(Lookup::Failed),
                };
                if md.file_type == FileType::Symlink && (!last || follow || !tail.is_empty()) {
                    if nofollow_any {
                        return Ok(Lookup::Failed);
                    }
                    links += 1;
                    if links > MAXSYMLINKS {
                        return Ok(Lookup::Failed);
                    }
                    let e = self.darwin_mac_check_vnode_readlink(sb_vnode(&p, &md));
                    if e != 0 {
                        return Err(super::errno::errno_of(e as i32));
                    }
                    let target = match self.vfs.read_link(&p) {
                        Ok(t) if !t.is_empty() => t,
                        _ => return Ok(Lookup::Failed),
                    };
                    let next = format!("{target}{tail}");
                    if next.starts_with('/') {
                        let Ok(md) = self.vfs.metadata("/") else { return Ok(Lookup::Failed) };
                        dir = Found { path: "/".into(), md, parent: None };
                        rest = next.trim_start_matches('/').to_string();
                    } else {
                        dir = Found { parent: None, ..cur };
                        rest = next;
                    }
                    continue 'pass;
                }
                let name = rest[i..].to_string();
                let found = Found { path: p, md, parent: Some((cur.path.clone(), name)) };
                if last {
                    // (a slash after a last component that is no directory)
                    if !tail.is_empty() && !found.is_dir() {
                        return Ok(Lookup::Failed);
                    }
                    return Ok(Lookup::Found(found));
                }
                cur = found;
                i = end;
            }
        }
    }

    /// [`Kernel::darwin_sb_lookup`]'s end for a path `rest` with no `.`
    /// or `..` and no link to follow: what `abs` (its normal form) is.
    fn darwin_sb_plain(&mut self, abs: &str, rest: &str, trailing: bool) -> Lookup {
        let name = rest.trim_end_matches('/').rsplit('/').next().unwrap_or("");
        let given = &rest[rest.trim_end_matches('/').len() - name.len()..];
        let parent = crate::vfs::parent_of(abs);
        match self.vfs.metadata_nofollow(abs) {
            Ok(md) => {
                if trailing && md.file_type != FileType::Directory {
                    return Lookup::Failed;
                }
                let parent = (!name.is_empty()).then(|| (parent, given.to_string()));
                Lookup::Found(Found { path: abs.to_string(), md, parent })
            }
            Err(_) => match self.vfs.metadata(&parent) {
                Ok(md) if md.file_type == FileType::Directory && !name.is_empty() => Lookup::Missing { dir: Found { path: parent, md, parent: None }, name: given.to_string() },
                _ => Lookup::Failed,
            },
        }
    }

    /// Sandbox's canonical form of absolute `path` (`0x...a14b1c`): its
    /// slashes at the end and repeated slashes dropped, each `.` dropped,
    /// each `..` taking the component before it with it, a `..` at the root
    /// dropped. A `..` right after a component is let through only if
    /// file-test-existence of the path up to it is allowed (`0x...a03a34`:
    /// with the subject's sandbox, from the root vnode), whose error is
    /// this one's. A path that is not absolute is ENOTSUP.
    pub(crate) fn darwin_sb_canonical(&mut self, path: &[u8]) -> Result<Vec<u8>, u32> {
        if path.first() != Some(&b'/') {
            return Err(45);
        }
        let mut p = path.to_vec();
        while p.len() >= 2 && p.last() == Some(&b'/') {
            p.pop();
        }
        // `at` is at a slash; after a component, `..` asks about the path
        // up to it.
        let (mut at, mut after_component) = (0usize, false);
        while at < p.len() {
            let c = |p: &[u8], i: usize| p.get(i).copied().unwrap_or(0);
            match c(&p, at + 1) {
                b'/' => {
                    let mut n = 2;
                    while at + n < p.len() && p[at + n] == b'/' {
                        n += 1;
                    }
                    p.drain(at..at + n - 1);
                }
                b'.' if matches!(c(&p, at + 2), b'/' | 0) => {
                    if p.len() == 2 {
                        p.truncate(1);
                        break;
                    }
                    p.drain(at..at + 2);
                }
                b'.' if at + 3 <= p.len() && c(&p, at + 2) == b'.' && matches!(c(&p, at + 3), b'/' | 0) => {
                    if after_component {
                        let e = self.darwin_sb_probe(&p[..at]);
                        if e != 0 {
                            return Err(e);
                        }
                    }
                    let to = p[..at].iter().rposition(|&b| b == b'/').unwrap_or(0);
                    if p.len() - (at + 3) + to == 0 {
                        p.truncate(1);
                        p[0] = b'/';
                        break;
                    }
                    p.drain(to..at + 3);
                    at = to;
                    after_component = false;
                }
                _ => match p[at + 1..].iter().position(|&b| b == b'/') {
                    Some(i) => {
                        at += 1 + i;
                        after_component = true;
                    }
                    None => break,
                },
            }
        }
        Ok(p)
    }

    /// `0x...a03a34`: file-test-existence of absolute path `prefix` (a
    /// lookup's, from the root vnode), with the subject's sandbox.
    fn darwin_sb_probe(&mut self, prefix: &[u8]) -> u32 {
        let Ok(md) = self.vfs.metadata("/") else { return 1 };
        let root = Found { path: "/".into(), md, parent: None };
        let v = sb_lookup(&root, &String::from_utf8_lossy(prefix));
        self.darwin_sb_vnode_check(op::FILE_TEST_EXISTENCE, v)
    }

    /// Sandbox's `mpo_vnode_check_readlink`: file-read-metadata.
    pub(crate) fn darwin_mac_check_vnode_readlink(&mut self, v: SbVnode) -> u32 {
        self.darwin_sb_vnode_check(op::FILE_READ_METADATA, v)
    }

    /// `mpo_vnode_check_open` of open mode `fmode` (FREAD, FWRITE, O_TRUNC):
    /// file-read-data to read, then file-write-data to write or truncate.
    pub(crate) fn darwin_mac_check_vnode_open(&mut self, v: SbVnode, fmode: u32) -> u32 {
        const FREAD: u32 = 1;
        const FWRITE_OR_TRUNC: u32 = 0x402;
        if fmode & FREAD != 0 {
            let e = self.darwin_sb_vnode_check(op::FILE_READ_DATA, v.clone());
            if e != 0 {
                return e;
            }
        }
        if fmode & FWRITE_OR_TRUNC != 0 {
            return self.darwin_sb_vnode_check(op::FILE_WRITE_DATA, v);
        }
        0
    }

    /// `mpo_vnode_check_create` of `name` in `dir`, of type `vtype` (its
    /// `va_type`, if given): none, or no type it makes, is refused
    /// (forbidden-file-create-unknown, -unsupported, reported for a sandboxed
    /// process); a device (or VBAD) is file-mknod first; then
    /// file-write-create.
    pub(crate) fn darwin_mac_check_vnode_create(&mut self, dir: &Found, name: &str, vtype: Option<u32>) -> u32 {
        let sandboxed = self.darwin_sandbox().is_some();
        let Some(t) = vtype else {
            if sandboxed {
                self.darwin_sb_report("forbidden-file-create-unknown");
            }
            return 1;
        };
        let v = sb_named(dir, name, Some(t));
        match t {
            vt::VREG | vt::VDIR | vt::VLNK | vt::VSOCK | vt::VFIFO => self.darwin_sb_vnode_check(op::FILE_WRITE_CREATE, v),
            vt::VBLK | vt::VCHR | vt::VBAD => match self.darwin_sb_vnode_check(op::FILE_MKNOD, v.clone()) {
                0 => self.darwin_sb_vnode_check(op::FILE_WRITE_CREATE, v),
                e => e,
            },
            _ => {
                if sandboxed {
                    self.darwin_sb_report("forbidden-file-create-unsupported");
                }
                1
            }
        }
    }

    /// `mpo_vnode_check_stat` (a descriptor's, `file_cred` given, is let
    /// through): file-read-metadata.
    pub(crate) fn darwin_mac_check_vnode_stat(&mut self, v: SbVnode) -> u32 {
        self.darwin_sb_vnode_check(op::FILE_READ_METADATA, v)
    }

    /// `mpo_vnode_check_getattr` of the attributes a lookup read (a
    /// descriptor's, `file_cred` given, is let through): file-read-metadata,
    /// and whether the decision (flag 0x20) has the times taken out of
    /// them (`va_create_time`, `va_access_time`, `va_modify_time`,
    /// `va_change_time`, `va_backup_time` and `va_addedtime` zeroed).
    pub(crate) fn darwin_mac_check_vnode_getattr(&mut self, v: SbVnode) -> (u32, bool) {
        let (errno, flags) = self.darwin_sb_vnode_eval(op::FILE_READ_METADATA, v, false);
        (errno, flags & 0x20 != 0)
    }

    /// `mpo_vnode_check_access` of access mask `mask` ({R,W,X}_OK << 6),
    /// unreported: file-read-data to read, file-write-data to write, and
    /// process-exec to execute what is no directory.
    pub(crate) fn darwin_mac_check_vnode_access(&mut self, v: SbVnode, mask: u32) -> u32 {
        if mask & 0x1c0 == 0 {
            return 0;
        }
        let dir = v.vtype == Some(vt::VDIR);
        if mask & 0x100 != 0 {
            let e = self.darwin_sb_vnode_eval(op::FILE_READ_DATA, v.clone(), true).0;
            if e != 0 {
                return e;
            }
        }
        if mask & 0x80 != 0 {
            let e = self.darwin_sb_vnode_eval(op::FILE_WRITE_DATA, v.clone(), true).0;
            if e != 0 {
                return e;
            }
        }
        if mask & 0x40 != 0 && !dir {
            return self.darwin_sb_vnode_eval(op::PROCESS_EXEC, v, true).0;
        }
        0
    }

    /// `mpo_vnode_check_unlink`: file-write-unlink.
    pub(crate) fn darwin_mac_check_vnode_unlink(&mut self, v: SbVnode) -> u32 {
        self.darwin_sb_vnode_check(op::FILE_WRITE_UNLINK, v)
    }

    /// `mpo_vnode_check_rename` (`0x...9f9d90`) of `from` to `name` in
    /// `to_dir` (replacing `to`, if there): the target's unlink check, then
    /// file-write-unlink of the file, file-write-create of the new name (of
    /// the file's type), and for a file of more than one link
    /// (`0x...a0782c`: a directory's own count, which APFS keeps, else its
    /// `va_nlink`) the link check of the new name.
    pub(crate) fn darwin_mac_check_vnode_rename(&mut self, from: &Found, to_dir: &Found, name: &str, to: Option<&Found>) -> u32 {
        if let Some(t) = to {
            let e = self.darwin_mac_check_vnode_unlink(sb_vnode(&t.path, &t.md));
            if e != 0 {
                return e;
            }
        }
        let v = sb_vnode(&from.path, &from.md);
        let e = self.darwin_sb_vnode_check(op::FILE_WRITE_UNLINK, v.clone());
        if e != 0 {
            return e;
        }
        let e = self.darwin_sb_vnode_check(op::FILE_WRITE_CREATE, sb_named(to_dir, name, v.vtype));
        if e != 0 {
            return e;
        }
        let links = if from.is_dir() && super::kern::mount_of(&from.path).fs == super::kern::Fs::Apfs { 1 } else { from.md.nlink };
        if links > 1 {
            return self.darwin_mac_check_vnode_link(from, to_dir, name);
        }
        0
    }

    /// `mpo_vnode_check_link` (`0x...9fdeec`) of a new name `name` in `dir`
    /// for file `vp`: file-link of the file, file-write-create and
    /// file-link of the name (of the file's type); then, unreported, each
    /// of 37 operations is decided for both (file-mount, file-mount-update
    /// and file-unmount only for uid 0), and a name that would get what the
    /// file is denied is refused (forbidden-link-priv): the file denied and
    /// the name allowed, or denied by the platform (tag 1 or 2) where the
    /// file was by its sandbox, or the name's decision with flag 8 and the
    /// file's without.
    pub(crate) fn darwin_mac_check_vnode_link(&mut self, vp: &Found, dir: &Found, name: &str) -> u32 {
        const OPS: [usize; 37] = [10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 32, 33, 34, 35, 36, 37, 38, 40, 109, 110, 111, 112, 120, 121, 161, 190];
        let s = sb_vnode(&vp.path, &vp.md);
        let d = sb_named(dir, name, s.vtype);
        let mut e = self.darwin_sb_vnode_check(op::FILE_LINK, s.clone());
        if e == 0 {
            e = self.darwin_sb_vnode_check(op::FILE_WRITE_CREATE, d.clone());
            if e == 0 {
                e = self.darwin_sb_vnode_check(op::FILE_LINK, d.clone());
            }
        }
        if e != 0 {
            return e;
        }
        let root = self.dtask.cred.uid == 0;
        for (i, &o) in OPS.iter().enumerate() {
            if matches!(i, 9 | 10 | 18) && !root {
                continue;
            }
            let (_, df) = self.darwin_sb_vnode_eval(o, d.clone(), true);
            let (_, sf) = self.darwin_sb_vnode_eval(o, s.clone(), true);
            let (s_denied, d_denied) = (sf & 1 != 0, df & 1 != 0);
            let (s_tag, d_tag) = (sf >> 29, df >> 29);
            let forbidden = if s_denied {
                let platform = |t: u32| t == 1 || t == 2;
                !d_denied || (platform(s_tag) && !platform(d_tag)) || (df & 8 != 0 && sf & 8 == 0)
            } else {
                sf & 8 == 0 && df & 8 != 0
            };
            if forbidden {
                self.darwin_sb_report(&format!("forbidden-link-priv<{}>", super::mac::OPERATION_NAMES[o]));
                return 1;
            }
        }
        0
    }

    /// `mpo_vnode_check_clone` (`0x...9fcc50`) of file `vp` to `name` in
    /// `dir`: file-clone and file-read-data of the file, file-write-create
    /// of the name (of the file's type); then, unreported, file-read-metadata,
    /// file-read-data and file-read-xattr decided for both, and a name that
    /// would get what the file is denied is refused (forbidden-clone-priv):
    /// the name allowed, or denied by its sandbox where the file was by the
    /// platform (tag 1 or 2).
    pub(crate) fn darwin_mac_check_vnode_clone(&mut self, vp: &Found, dir: &Found, name: &str) -> u32 {
        let s = sb_vnode(&vp.path, &vp.md);
        let d = sb_named(dir, name, s.vtype);
        let mut e = self.darwin_sb_vnode_check(op::FILE_CLONE, s.clone());
        if e == 0 {
            e = self.darwin_sb_vnode_check(op::FILE_READ_DATA, s.clone());
        }
        if e != 0 {
            return e;
        }
        let e = self.darwin_sb_vnode_check(op::FILE_WRITE_CREATE, d.clone());
        if e != 0 {
            return e;
        }
        for o in [op::FILE_READ_METADATA, op::FILE_READ_DATA, op::FILE_READ_XATTR] {
            let (_, df) = self.darwin_sb_vnode_eval(o, d.clone(), true);
            let (_, sf) = self.darwin_sb_vnode_eval(o, s.clone(), true);
            if sf & 1 == 0 {
                continue;
            }
            let platform = |t: u32| t == 1 || t == 2;
            if df & 1 == 0 || (platform(sf >> 29) && !platform(df >> 29)) {
                self.darwin_sb_report(&format!("forbidden-clone-priv<{}>", super::mac::OPERATION_NAMES[o]));
                return 1;
            }
        }
        0
    }

    /// `mpo_vnode_check_setmode` to mode `mode`: file-write-mode; for a
    /// sandboxed process, its set-user-id or set-group-id bit changed is
    /// file-write-setugid too.
    pub(crate) fn darwin_mac_check_vnode_setmode(&mut self, v: SbVnode, mode: u32) -> u32 {
        let sandboxed = self.darwin_sandbox().is_some();
        let old = match self.darwin_sb_attrs(&v) {
            Ok(Some(o)) => o.mode,
            Ok(None) => u32::from(v.mode.unwrap_or(0)),
            Err(why) => {
                // (the old mode is read only for a sandboxed process)
                if sandboxed {
                    self.darwin_unimplemented(why);
                    return 1;
                }
                0
            }
        };
        let e = self.darwin_sb_vnode_check(op::FILE_WRITE_MODE, v.clone());
        if e != 0 || !sandboxed || (old ^ mode) & 0o6000 == 0 {
            return e;
        }
        self.darwin_sb_vnode_check(op::FILE_WRITE_SETUGID, v)
    }

    /// `mpo_vnode_check_setflags` (`0x...9fe8ec`) to flags `flags`:
    /// file-write-flags with the process's sandbox; allowed, a change that
    /// sets SF_RESTRICTED, SF_NOUNLINK or UF_DATAVAULT is file-write-flags
    /// again, the platform profile's alone, of the vnode with the new
    /// flags (`args[0x138]`, `args[0x190]` 0x42).
    pub(crate) fn darwin_mac_check_vnode_setflags(&mut self, v: SbVnode, flags: u32) -> u32 {
        let e = self.darwin_sb_vnode_check(op::FILE_WRITE_FLAGS, v.clone());
        if e != 0 || flags & 0x0018_0080 == 0 {
            return e;
        }
        let a = SbArgs { kind: sandbox::kind::VNODE, vnode: Some(SbVnode { flags, of: None, ..v }), ..Default::default() };
        self.darwin_sb_evaluate_with(None, op::FILE_WRITE_FLAGS, &a).0
    }

    /// `mpo_vnode_check_setowner`, `mpo_vnode_check_setutimes`,
    /// `mpo_vnode_check_truncate` (a descriptor's, `file_cred` given, is let
    /// through), `mpo_vnode_check_setacl`, `mpo_vnode_check_listextattr`,
    /// `mpo_vnode_check_getattrlist` and `mpo_vnode_check_fsgetpath`.
    pub(crate) fn darwin_mac_check_vnode_setowner(&mut self, v: SbVnode) -> u32 {
        self.darwin_sb_vnode_check(op::FILE_WRITE_OWNER, v)
    }
    pub(crate) fn darwin_mac_check_vnode_setutimes(&mut self, v: SbVnode) -> u32 {
        self.darwin_sb_vnode_check(op::FILE_WRITE_TIMES, v)
    }
    pub(crate) fn darwin_mac_check_vnode_truncate(&mut self, v: SbVnode) -> u32 {
        self.darwin_sb_vnode_check(op::FILE_WRITE_DATA, v)
    }
    pub(crate) fn darwin_mac_check_vnode_setacl(&mut self, v: SbVnode) -> u32 {
        self.darwin_sb_vnode_check(op::FILE_WRITE_ACL, v)
    }
    pub(crate) fn darwin_mac_check_vnode_listextattr(&mut self, v: SbVnode) -> u32 {
        self.darwin_sb_vnode_check(op::FILE_READ_METADATA, v)
    }
    pub(crate) fn darwin_mac_check_vnode_getattrlist(&mut self, v: SbVnode) -> u32 {
        self.darwin_sb_vnode_check(op::FILE_READ_METADATA, v)
    }
    pub(crate) fn darwin_mac_check_vnode_fsgetpath(&mut self, v: SbVnode) -> u32 {
        self.darwin_sb_vnode_check(op::FILE_TEST_EXISTENCE, v)
    }

    /// `mpo_vnode_check_getextattr` of attribute `name`: file-read-xattr.
    pub(crate) fn darwin_mac_check_vnode_getextattr(&mut self, mut v: SbVnode, name: &[u8]) -> u32 {
        v.xattr = Some(name.to_vec());
        self.darwin_sb_vnode_check(op::FILE_READ_XATTR, v)
    }

    /// `mpo_vnode_check_setextattr` and `mpo_vnode_check_deleteextattr` of
    /// attribute `name`: `com.apple.rootless` only for an installer or a
    /// data vault controller (`0x...a187b8`, else forbidden-rootless-xattr),
    /// then file-write-xattr.
    pub(crate) fn darwin_mac_check_vnode_setextattr(&mut self, mut v: SbVnode, name: &[u8]) -> u32 {
        const CS_INSTALLER: u32 = 0x8;
        const CS_DATAVAULT_CONTROLLER: u32 = 0x8000_0000;
        if name == b"com.apple.rootless" && self.dtask.csflags.load(std::sync::atomic::Ordering::Acquire) & (CS_INSTALLER | CS_DATAVAULT_CONTROLLER) == 0 {
            self.darwin_sb_report("forbidden-rootless-xattr");
            return 1;
        }
        v.xattr = Some(name.to_vec());
        self.darwin_sb_vnode_check(op::FILE_WRITE_XATTR, v)
    }

    /// `mpo_vnode_check_setattrlist` of attribute list `attrs` (its
    /// bitmap count and its common, volume, directory, file and fork
    /// attributes): a list of another count is file-write*; else
    /// ATTR_CMN_FNDRINFO is file-write-finderinfo, the volume's name
    /// (ATTR_VOL_INFO with ATTR_VOL_NAME) fs-rename, and anything else
    /// left file-write*.
    pub(crate) fn darwin_mac_check_vnode_setattrlist(&mut self, v: SbVnode, count: u16, attrs: [u32; 5]) -> u32 {
        const ATTR_CMN_FNDRINFO: u32 = 0x4000;
        const ATTR_VOL_NAME: u32 = 0x2000;
        const ATTR_VOL_INFO: u32 = 0x8000_0000;
        if count != 5 {
            return self.darwin_sb_vnode_check(op::FILE_WRITE, v);
        }
        let [mut common, mut vol, dir, file, fork] = attrs;
        if common & ATTR_CMN_FNDRINFO != 0 {
            let e = self.darwin_sb_vnode_check(op::FILE_WRITE_FINDERINFO, v.clone());
            if e != 0 {
                return e;
            }
            common &= !ATTR_CMN_FNDRINFO;
        }
        if vol & ATTR_VOL_INFO != 0 && vol & ATTR_VOL_NAME != 0 {
            let e = self.darwin_sb_vnode_check(op::FS_RENAME, v.clone());
            if e != 0 {
                return e;
            }
            vol &= !(ATTR_VOL_NAME | ATTR_VOL_INFO);
        }
        if common | vol | dir | file | fork == 0 {
            return 0;
        }
        self.darwin_sb_vnode_check(op::FILE_WRITE, v)
    }

    /// `mpo_vnode_check_exchangedata`: file-read* of each, then
    /// file-write* of each.
    pub(crate) fn darwin_mac_check_vnode_exchangedata(&mut self, a: SbVnode, b: SbVnode) -> u32 {
        for (o, v) in [(op::FILE_READ, &a), (op::FILE_READ, &b), (op::FILE_WRITE, &a), (op::FILE_WRITE, &b)] {
            let e = self.darwin_sb_vnode_check(o, v.clone());
            if e != 0 {
                return e;
            }
        }
        0
    }

    /// `mpo_vnode_check_ioctl` of command `cmd` (made with the current
    /// process's credential): the commands that only ask after the file or
    /// its terminal's size and settings, or set its non-blocking or
    /// asynchronous mode, are let through; TIOCSTI is hid-control first;
    /// then file-ioctl of the command.
    pub(crate) fn darwin_mac_check_vnode_ioctl(&mut self, mut v: SbVnode, cmd: u64) -> u32 {
        const FIODTYPE: u64 = 0x4004_667a;
        const FIONREAD: u64 = 0x4004_667f;
        const FIOASYNC: u64 = 0x8004_667d;
        const FIONBIO: u64 = 0x8004_667e;
        const TIOCGWINSZ: u64 = 0x4008_7468;
        const TIOCGETA_32: u64 = 0x402c_7413;
        const TIOCGETA: u64 = 0x4048_7413;
        const TIOCSTI: u64 = 0x8001_7472;
        if matches!(cmd, FIODTYPE | FIONREAD | FIOASYNC | FIONBIO | TIOCGWINSZ | TIOCGETA_32 | TIOCGETA) {
            return 0;
        }
        if cmd == TIOCSTI {
            let e = self.darwin_sb_evaluate(op::HID_CONTROL, &SbArgs::default());
            if e != 0 {
                return e;
            }
        }
        v.command = Some(cmd as u32);
        self.darwin_sb_vnode_check(op::FILE_IOCTL, v)
    }

    /// `mpo_file_check_fcntl` of command `cmd` (`0x...9f61b0`):
    /// F_PATHPKG_CHECK is system-package-check first; a command below 112
    /// that the sandbox's fcntl mask (the platform's without a sandbox) lets
    /// through goes on; any other is system-fcntl of the command.
    pub(crate) fn darwin_mac_check_file_fcntl(&mut self, cmd: u32) -> u32 {
        const F_PATHPKG_CHECK: u32 = 52;
        if cmd == F_PATHPKG_CHECK {
            let e = self.darwin_sb_evaluate(op::SYSTEM_PACKAGE_CHECK, &SbArgs::default());
            if e != 0 {
                return e;
            }
        }
        let sb = self.darwin_sandbox();
        let mask = match &sb {
            Some(s) => s.masks[3].clone(),
            None => super::mac::platform_masks()[3].clone(),
        };
        if cmd <= 111 && mask.is_some_and(|m| sandbox::mask_allows(&m, cmd as usize)) {
            return 0;
        }
        let a = SbArgs { kind: sandbox::kind::FCNTL, number: cmd, ..Default::default() };
        self.darwin_sb_evaluate_with(sb.as_ref(), op::SYSTEM_FCNTL, &a).0
    }

    /// `mpo_file_check_lock` of operation `op` on a vnode: F_SETLK is
    /// file-lock.
    pub(crate) fn darwin_mac_check_file_lock(&mut self, v: SbVnode, setlk: bool) -> u32 {
        if !setlk {
            return 0;
        }
        self.darwin_sb_vnode_check(op::FILE_LOCK, v)
    }

    /// `mpo_file_check_mmap` of a vnode with protection `prot`: an
    /// executable mapping is file-map-executable, but of a file of the dyld
    /// shared cache, one the shared region has mapped (VSHARED_DYLD).
    pub(crate) fn darwin_mac_check_file_mmap(&mut self, v: SbVnode, prot: u64, shared_dyld: bool) -> u32 {
        const PROT_EXEC: u64 = 4;
        if prot & PROT_EXEC == 0 || shared_dyld {
            return 0;
        }
        self.darwin_sb_vnode_check(op::FILE_MAP_EXECUTABLE, v)
    }

    /// `mpo_vnode_check_uipc_bind` of `name` in `dir` (no type given):
    /// network-bind; and `mpo_vnode_check_uipc_connect` of a socket's
    /// vnode: network-outbound.
    pub(crate) fn darwin_mac_check_vnode_uipc_bind(&mut self, dir: &Found, name: &str) -> u32 {
        self.darwin_sb_vnode_check(op::NETWORK_BIND, sb_named(dir, name, None))
    }
    pub(crate) fn darwin_mac_check_vnode_uipc_connect(&mut self, v: SbVnode) -> u32 {
        self.darwin_sb_vnode_check(op::NETWORK_OUTBOUND, v)
    }
}

/// A hook's errno as the call's error.
fn refused(e: u32) -> Result<(), Errno> {
    match e {
        0 => Ok(()),
        e => Err(super::errno::errno_of(e as i32)),
    }
}

impl Kernel {
    /// The Sandbox checks of Darwin call `raw` (arguments `a`) that its own
    /// code leaves to this: its lookups' and its hook's, made before the
    /// call runs, at the point XNU makes them. A refusal is the call's
    /// error; where the call fails before (its flags, a lookup), the call
    /// is left to report it.
    pub(crate) fn darwin_sb_file_call(&mut self, m: &GuestMem<'_>, raw: u64, a: &[u64; 6]) -> Option<Errno> {
        self.darwin_stat_scrub = false;
        self.darwin_creation = None;
        let cwd = super::bsd::AT_FDCWD as u64;
        let flag = |i: usize| a[i] as u32 as u64;
        let r = match raw {
            // vn_stat: the stat check, then the attributes' (getattr).
            sys::STAT | sys::STAT64 | sys::STAT_EXTENDED | sys::STAT64_EXTENDED => self.darwin_sb_stat_call(m, cwd, a[0], true, false),
            sys::LSTAT | sys::LSTAT64 | sys::LSTAT_EXTENDED | sys::LSTAT64_EXTENDED => self.darwin_sb_stat_call(m, cwd, a[0], false, false),
            sys::FSTATAT | sys::FSTATAT64 if flag(3) & !(at::SYMLINK_NOFOLLOW | at::REALDEV | at::FDONLY | at::SYMLINK_NOFOLLOW_ANY) == 0 && flag(3) & at::FDONLY == 0 => {
                self.darwin_sb_stat_call(m, a[0], a[1], flag(3) & (at::SYMLINK_NOFOLLOW | at::SYMLINK_NOFOLLOW_ANY) == 0, flag(3) & at::SYMLINK_NOFOLLOW_ANY != 0)
            }
            // access1.
            sys::ACCESS => self.darwin_sb_access_call(m, cwd, a[0], a[1], 0),
            sys::FACCESSAT if flag(3) & !(at::EACCESS | at::SYMLINK_NOFOLLOW | at::SYMLINK_NOFOLLOW_ANY) == 0 => self.darwin_sb_access_call(m, a[0], a[1], a[2], flag(3)),
            // readlinkat_internal: a link (EINVAL otherwise), then its check.
            sys::READLINK => self.darwin_sb_readlink_call(m, cwd, a[0]),
            sys::READLINKAT => self.darwin_sb_readlink_call(m, a[0], a[1]),
            sys::FREADLINK => match self.darwin_sb_fd_vnode(a[0] as i32) {
                Some(f) if f.md.file_type == FileType::Symlink => refused(self.darwin_mac_check_vnode_readlink(sb_vnode(&f.path, &f.md))),
                _ => Ok(()),
            },
            // unlinkat_internal and rmdirat_internal.
            sys::UNLINK => self.darwin_sb_unlink_call(m, cwd, a[0], false, false),
            sys::RMDIR => self.darwin_sb_unlink_call(m, cwd, a[0], true, false),
            sys::UNLINKAT if flag(2) & !(at::REMOVEDIR | at::REMOVEDIR_DATALESS | at::SYMLINK_NOFOLLOW_ANY) == 0 && flag(2) & at::REMOVEDIR_DATALESS == 0 => {
                self.darwin_sb_unlink_call(m, a[0], a[1], flag(2) & at::REMOVEDIR != 0, flag(2) & at::SYMLINK_NOFOLLOW_ANY != 0)
            }
            // renameat_internal.
            sys::RENAME => self.darwin_sb_rename_call(m, [cwd, a[0], cwd, a[1]], 0),
            sys::RENAMEAT => self.darwin_sb_rename_call(m, [a[0], a[1], a[2], a[3]], 0),
            sys::RENAMEATX_NP => {
                let f = flag(4);
                let bad = f & !(at::RENAME_SECLUDE | at::RENAME_EXCL | at::RENAME_SWAP | at::RENAME_NOFOLLOW_ANY) != 0 || f & (at::RENAME_EXCL | at::RENAME_SWAP) == at::RENAME_EXCL | at::RENAME_SWAP;
                if bad || f & at::RENAME_SECLUDE != 0 {
                    Ok(())
                } else {
                    self.darwin_sb_rename_call(m, [a[0], a[1], a[2], a[3]], f)
                }
            }
            // linkat_internal.
            sys::LINK => self.darwin_sb_link_call(m, [cwd, a[0], cwd, a[1]], true),
            sys::LINKAT if a[4] & !at::SYMLINK_FOLLOW == 0 => self.darwin_sb_link_call(m, [a[0], a[1], a[2], a[3]], a[4] & at::SYMLINK_FOLLOW != 0),
            // mkdir1at; mkdir_extended's, with no owner or list to set (the
            // others are refused).
            sys::MKDIR => self.darwin_sb_mkdir_call(m, cwd, a[0], self.darwin_mkdir_mode(a[1])),
            sys::MKDIRAT => self.darwin_sb_mkdir_call(m, a[0], a[1], self.darwin_mkdir_mode(a[2])),
            sys::MKDIR_EXTENDED if a[1] as u32 == NO_ID && a[2] as u32 == NO_ID && a[4] == 0 => self.darwin_sb_mkdir_call(m, cwd, a[0], self.darwin_mkdir_mode(a[3])),
            // chmod_extended and fchmod_extended with no owner to set and no
            // list but the one that removes it (the others are refused):
            // chmod_vnode's checks, of the mode (-1 leaves it) and the list.
            sys::CHMOD_EXTENDED | sys::FCHMOD_EXTENDED if a[1] as u32 == NO_ID && a[2] as u32 == NO_ID && (a[4] == 0 || (raw == sys::CHMOD_EXTENDED && a[4] == REMOVE_ACL)) => {
                let f = if raw == sys::CHMOD_EXTENDED {
                    match self.darwin_sb_namei(m, cwd, a[0], true, false) {
                        Ok(l) => l.found(),
                        Err(e) => return Some(e),
                    }
                } else {
                    self.darwin_sb_fd_vnode(a[0] as i32)
                };
                match f {
                    Some(f) => {
                        let v = sb_vnode(&f.path, &f.md);
                        let mode = if a[3] as i32 == -1 { Ok(()) } else { refused(self.darwin_mac_check_vnode_setmode(v.clone(), a[3] as u32 & 0o7777)) };
                        mode.and_then(|()| if a[4] == REMOVE_ACL { refused(self.darwin_mac_check_vnode_setacl(v)) } else { Ok(()) })
                    }
                    None => Ok(()),
                }
            }
            // symlinkat_internal.
            sys::SYMLINK => self.darwin_sb_symlink_call(m, a[0], cwd, a[1]),
            sys::SYMLINKAT => self.darwin_sb_symlink_call(m, a[0], a[1], a[2]),
            // chmodat and fchmod: chmod_vnode's checks.
            sys::CHMOD => self.darwin_sb_chmod_call(m, cwd, a[0], a[1], 0),
            sys::FCHMODAT if flag(3) & !(at::SYMLINK_NOFOLLOW | at::SYMLINK_NOFOLLOW_ANY) == 0 => self.darwin_sb_chmod_call(m, a[0], a[1], a[2], flag(3)),
            sys::FCHMOD => match self.darwin_sb_fd_vnode(a[0] as i32) {
                Some(f) => refused(self.darwin_mac_check_vnode_setmode(sb_vnode(&f.path, &f.md), a[1] as u32 & 0o7777)),
                None => Ok(()),
            },
            // chflags and fchflags: chflags0's check.
            sys::CHFLAGS => match self.darwin_sb_namei(m, cwd, a[0], true, false) {
                Ok(Lookup::Found(f)) => refused(self.darwin_mac_check_vnode_setflags(sb_vnode(&f.path, &f.md), a[1] as u32)),
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            },
            sys::FCHFLAGS => match self.darwin_sb_fd_vnode(a[0] as i32) {
                Some(f) => refused(self.darwin_mac_check_vnode_setflags(sb_vnode(&f.path, &f.md), a[1] as u32)),
                None => Ok(()),
            },
            // truncate: its length checked, then truncate_internal's check.
            sys::TRUNCATE if (a[1] as i64) >= 0 => match self.darwin_sb_namei(m, cwd, a[0], true, false) {
                Ok(Lookup::Found(f)) => refused(self.darwin_mac_check_vnode_truncate(sb_vnode(&f.path, &f.md))),
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            },
            // utimes and futimes: the times read, then setutimes' check.
            sys::UTIMES if a[1] == 0 || m.read(a[1], 32).is_ok() => match self.darwin_sb_namei(m, cwd, a[0], true, false) {
                Ok(Lookup::Found(f)) => refused(self.darwin_mac_check_vnode_setutimes(sb_vnode(&f.path, &f.md))),
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            },
            sys::FUTIMES => match self.darwin_sb_fd_vnode(a[0] as i32) {
                Some(f) if a[1] == 0 || m.read(a[1], 32).is_ok() => refused(self.darwin_mac_check_vnode_setutimes(sb_vnode(&f.path, &f.md))),
                _ => Ok(()),
            },
            // Lookups Sandbox has no hook after: their preflights.
            sys::CHDIR | sys::PTHREAD_CHDIR | sys::PATHCONF | sys::STATFS | sys::STATFS64 => self.darwin_sb_namei(m, cwd, a[0], true, false).map(|_| ()),
            // fcntl_nocancel: once the descriptor is found, before its
            // command is looked at.
            sys::FCNTL | sys::FCNTL_NOCANCEL if self.fds.get(a[0] as i32).is_ok() => refused(self.darwin_mac_check_file_fcntl(a[1] as u32)),
            _ => Ok(()),
        };
        r.err()
    }

    /// The process's file creation mask (`fd_cmask`): the calling thread's.
    pub(crate) fn darwin_umask(&self) -> u32 {
        self.path_io().fs.umask()
    }

    /// `mkdir1at`'s mode: its access permissions under the umask.
    fn darwin_mkdir_mode(&self, mode: u64) -> u32 {
        (mode as u32 & super::fsops::ACCESSPERMS as u32) & !self.darwin_umask()
    }

    /// A stat of the path at `path` from `dirfd`: the stat check, then the
    /// getattr check of its attributes, whose decision may take the times
    /// out of what the call writes.
    fn darwin_sb_stat_call(&mut self, m: &GuestMem<'_>, dirfd: u64, path: u64, follow: bool, nofollow_any: bool) -> Result<(), Errno> {
        let Lookup::Found(f) = self.darwin_sb_namei(m, dirfd, path, follow, nofollow_any)? else { return Ok(()) };
        let v = sb_vnode(&f.path, &f.md);
        refused(self.darwin_mac_check_vnode_stat(v.clone()))?;
        let (e, scrub) = self.darwin_mac_check_vnode_getattr(v);
        refused(e)?;
        self.darwin_stat_scrub = scrub;
        Ok(())
    }

    /// `faccessat_internal`'s lookup and `access1`'s checks of mode
    /// `amode`: Sandbox's, then `vnode_authorize` of what the mode asks
    /// (its R_OK, W_OK and X_OK as the rights they are of a file or a
    /// directory; an extended mode's own bits as rights), by the real user
    /// and group unless AT_EACCESS. F_OK asks nothing.
    fn darwin_sb_access_call(&mut self, m: &GuestMem<'_>, dirfd: u64, path: u64, amode: u64, flag: u64) -> Result<(), Errno> {
        use super::vauth::kauth;
        const X_OK: u32 = 1;
        const W_OK: u32 = 2;
        const R_OK: u32 = 4;
        const DELETE_OK: u32 = 1 << 12;
        const ACCESS_EXTENDED_MASK: u32 = 0x003f_fe00;
        let follow = flag & (at::SYMLINK_NOFOLLOW | at::SYMLINK_NOFOLLOW_ANY) == 0;
        let Lookup::Found(f) = self.darwin_sb_namei(m, dirfd, path, follow, flag & at::SYMLINK_NOFOLLOW_ANY != 0)? else { return Ok(()) };
        refused(self.darwin_mac_check_vnode_access(sb_vnode(&f.path, &f.md), (amode as u32) << 6))?;
        let uflags = amode as u32;
        let dir = f.is_dir();
        let action = if uflags & ACCESS_EXTENDED_MASK == 0 {
            let mut a = 0;
            if uflags & R_OK != 0 {
                a |= kauth::READ_DATA;
            }
            if uflags & W_OK != 0 {
                a |= if dir { kauth::ADD_FILE | kauth::ADD_SUBDIRECTORY } else { kauth::WRITE_DATA };
            }
            if uflags & X_OK != 0 {
                a |= if dir { kauth::SEARCH } else { kauth::EXECUTE };
            }
            a
        } else {
            uflags >> 8
        };
        if action == 0 {
            return Ok(());
        }
        let cred = if flag & at::EACCESS != 0 { self.dtask.cred.clone() } else { self.dtask.cred.copy_real() };
        let node = self.darwin_vnode_node(&f.path, &f.md, None);
        let dnode = if uflags & DELETE_OK != 0 {
            match self.darwin_sb_parent(&f) {
                Some((d, _)) => Some(self.darwin_vnode_node(&d.path, &d.md, None)),
                None => {
                    self.darwin_unimplemented(format!("access _DELETE_OK of {}, which has no directory to be deleted from", f.path));
                    return Err(Errno::EIO);
                }
            }
        } else {
            None
        };
        self.darwin_authorize(&cred, &node, dnode.as_ref(), action | kauth::ACCESS)
    }

    fn darwin_sb_readlink_call(&mut self, m: &GuestMem<'_>, dirfd: u64, path: u64) -> Result<(), Errno> {
        match self.darwin_sb_namei(m, dirfd, path, false, false)? {
            Lookup::Found(f) if f.md.file_type == FileType::Symlink => refused(self.darwin_mac_check_vnode_readlink(sb_vnode(&f.path, &f.md))),
            _ => Ok(()),
        }
    }

    /// The vnode of a removal, its last component not followed:
    /// `vn_authorize_unlink` (a mount's root is EBUSY, a directory EPERM)
    /// or `vn_authorize_rmdir` (EBUSY, ENOTDIR, and EINVAL for `.`), then
    /// the unlink check.
    fn darwin_sb_unlink_call(&mut self, m: &GuestMem<'_>, dirfd: u64, path: u64, rmdir: bool, nofollow_any: bool) -> Result<(), Errno> {
        let Lookup::Found(f) = self.darwin_sb_namei(m, dirfd, path, false, nofollow_any)? else { return Ok(()) };
        if f.parent.is_none() || super::kern::mount_of(&f.path).on == f.path || f.is_dir() != rmdir {
            return Ok(());
        }
        refused(self.darwin_mac_check_vnode_unlink(sb_vnode(&f.path, &f.md)))?;
        // vnode_authorize(vp, dvp, KAUTH_VNODE_DELETE).
        let Some((dir, _)) = self.darwin_sb_parent(&f) else { return Ok(()) };
        let cred = self.dtask.cred.clone();
        let (vp, dvp) = (self.darwin_vnode_node(&f.path, &f.md, None), self.darwin_vnode_node(&dir.path, &dir.md, None));
        self.darwin_authorize(&cred, &vp, Some(&dvp), super::vauth::kauth::DELETE)
    }

    /// A file about to take another name (a link, a rename): its attributes
    /// recorded on it where they are not yet, as what its old name gave it
    /// (the image's for a Data volume file of its own), for its new name
    /// to keep.
    pub(crate) fn darwin_keep_attrs(&mut self, f: &Found) {
        if super::kern::mount_of(&f.path).fs == super::kern::Fs::Devfs {
            return;
        }
        if let Ok(None) = super::vattr::recorded(&self.vfs, &f.path, None) {
            if let Ok(o) = super::vattr::of(&self.vfs, &f.path, &f.md, None) {
                if let Err(why) = super::vattr::record_new(&self.vfs, &f.path, None, &o) {
                    self.darwin_unimplemented(why);
                }
            }
        }
    }

    /// The directory a found file's name is in.
    fn darwin_sb_parent(&self, f: &Found) -> Option<(Found, String)> {
        let (dir, name) = f.parent.clone()?;
        let md = self.vfs.metadata(&dir).ok()?;
        Some((Found { path: dir, md, parent: None }, name))
    }

    /// `renameat_internal` of `[fromfd, from, tofd, to]` with renameatx_np's
    /// `flags`: both lookups (neither following its last component); the
    /// errors before the checks (a swap with nothing to swap with,
    /// RENAME_EXCL with something there, the same file, another mount, a
    /// directory's `.` or `..`); then the check, and for a swap the other
    /// way round too.
    fn darwin_sb_rename_call(&mut self, m: &GuestMem<'_>, p: [u64; 4], flags: u64) -> Result<(), Errno> {
        let nofollow_any = flags & at::RENAME_NOFOLLOW_ANY != 0;
        let Lookup::Found(from) = self.darwin_sb_namei(m, p[0], p[1], false, nofollow_any)? else { return Ok(()) };
        let Some((from_dir, from_name)) = self.darwin_sb_parent(&from) else { return Ok(()) };
        let (to_dir, to_name, to) = match self.darwin_sb_namei(m, p[2], p[3], false, nofollow_any)? {
            Lookup::Found(t) => match self.darwin_sb_parent(&t) {
                Some((d, n)) => (d, n, Some(t)),
                None => return Ok(()),
            },
            // (a name to make with a slash after it is ENOENT, unless a
            // directory moves there)
            Lookup::Missing { dir, name } if from.is_dir() || !name.ends_with('/') => (dir, name, None),
            _ => return Ok(()),
        };
        let swap = flags & at::RENAME_SWAP != 0;
        let mount = |p: &str| super::kern::mount_of(p).on;
        if (swap && to.is_none())
            || (flags & at::RENAME_EXCL != 0 && to.is_some())
            || to.as_ref().is_some_and(|t| t.path == from.path)
            || mount(&from.path) != mount(&to_dir.path)
            || (from.is_dir() && (from_name.trim_end_matches('/') == "." || to_name.trim_end_matches('/') == ".."))
        {
            return Ok(());
        }
        refused(self.darwin_mac_check_vnode_rename(&from, &to_dir, &to_name, to.as_ref()))?;
        if let (true, Some(t)) = (swap, to.as_ref()) {
            refused(self.darwin_mac_check_vnode_rename(t, &from_dir, &from_name, Some(&from)))?;
        }
        self.darwin_keep_attrs(&from);
        if let (true, Some(t)) = (swap, to.as_ref()) {
            self.darwin_keep_attrs(t);
        }
        Ok(())
    }

    /// `linkat_internal` of `[fd1, path, fd2, link]`: the file (followed
    /// with `follow`; a directory is EPERM), the new name's lookup (a name
    /// to make with a slash after it is ENOENT), then the link check,
    /// whether or not the name is there (EEXIST after).
    fn darwin_sb_link_call(&mut self, m: &GuestMem<'_>, p: [u64; 4], follow: bool) -> Result<(), Errno> {
        let Lookup::Found(vp) = self.darwin_sb_namei(m, p[0], p[1], follow, false)? else { return Ok(()) };
        if vp.is_dir() {
            return Ok(());
        }
        let (dir, name) = match self.darwin_sb_namei(m, p[2], p[3], false, false)? {
            Lookup::Found(t) => match self.darwin_sb_parent(&t) {
                Some(dn) => dn,
                None => return Ok(()),
            },
            Lookup::Missing { dir, name } if !name.ends_with('/') => (dir, name),
            _ => return Ok(()),
        };
        refused(self.darwin_mac_check_vnode_link(&vp, &dir, &name))?;
        // vnode_authorize of the file as a link's target; a name there is
        // EEXIST, another volume EXDEV, before adding to the directory is.
        use super::vauth::kauth;
        let cred = self.dtask.cred.clone();
        let node = self.darwin_vnode_node(&vp.path, &vp.md, None);
        self.darwin_authorize(&cred, &node, None, kauth::LINKTARGET)?;
        if self.vfs.metadata_nofollow(&join(&dir.path, &name)).is_ok() || super::kern::mount_of(&dir.path).on != super::kern::mount_of(&vp.path).on {
            return Ok(());
        }
        let dnode = self.darwin_vnode_node(&dir.path, &dir.md, None);
        self.darwin_authorize(&cred, &dnode, None, kauth::ADD_FILE)?;
        self.darwin_keep_attrs(&vp);
        Ok(())
    }

    /// `mkdir1at`: a name already there is EEXIST; else the create check
    /// of a directory, then `vn_authorize_mkdir`'s authorization; what it
    /// is made with (mode `mode`, the umask applied) is left for the call
    /// to record.
    fn darwin_sb_mkdir_call(&mut self, m: &GuestMem<'_>, dirfd: u64, path: u64, mode: u32) -> Result<(), Errno> {
        match self.darwin_sb_namei(m, dirfd, path, false, false)? {
            Lookup::Missing { dir, name } => {
                refused(self.darwin_mac_check_vnode_create(&dir, &name, Some(vt::VDIR)))?;
                self.darwin_creation = Some(self.darwin_creating(&dir, &name, super::vauth::kauth::ADD_SUBDIRECTORY, mode)?);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// `symlinkat_internal`: the link's contents read, the lookup (a name
    /// to make with a slash after it is ENOENT), then the create check of
    /// a link, whether or not the name is there (EEXIST after).
    fn darwin_sb_symlink_call(&mut self, m: &GuestMem<'_>, target: u64, dirfd: u64, path: u64) -> Result<(), Errno> {
        if m.read_cstr(target, MAXPATHLEN).is_err() {
            return Ok(());
        }
        let (dir, name) = match self.darwin_sb_namei(m, dirfd, path, false, false)? {
            Lookup::Found(t) => match self.darwin_sb_parent(&t) {
                Some(dn) => dn,
                None => return Ok(()),
            },
            Lookup::Missing { dir, name } if !name.ends_with('/') => (dir, name),
            _ => return Ok(()),
        };
        refused(self.darwin_mac_check_vnode_create(&dir, &name, Some(vt::VLNK)))?;
        // (a name there is EEXIST before the authorization) The link's mode
        // is every access permission the umask leaves.
        if self.vfs.metadata_nofollow(&join(&dir.path, &name)).is_err() {
            let mode = super::fsops::ACCESSPERMS as u32 & !self.darwin_umask();
            self.darwin_creation = Some(self.darwin_creating(&dir, &name, super::vauth::kauth::ADD_FILE, mode)?);
        }
        Ok(())
    }

    /// `chmodat`'s lookup (its last component not followed with
    /// AT_SYMLINK_NOFOLLOW, nor any on the way with
    /// AT_SYMLINK_NOFOLLOW_ANY), then the mode's check.
    fn darwin_sb_chmod_call(&mut self, m: &GuestMem<'_>, dirfd: u64, path: u64, mode: u64, flag: u64) -> Result<(), Errno> {
        let follow = flag & (at::SYMLINK_NOFOLLOW | at::SYMLINK_NOFOLLOW_ANY) == 0;
        let Lookup::Found(f) = self.darwin_sb_namei(m, dirfd, path, follow, flag & at::SYMLINK_NOFOLLOW_ANY != 0)? else { return Ok(()) };
        refused(self.darwin_mac_check_vnode_setmode(sb_vnode(&f.path, &f.md), mode as u32 & 0o7777))
    }
}

/// A file a call is about to make: its canonical path and the attributes
/// `vnode_authattr_new` gives it, recorded once it is made.
#[derive(Clone, Debug)]
pub struct Creating {
    pub path: String,
    pub owned: super::vattr::Owned,
}

impl Kernel {
    /// The authorization of a file to make as `name` in directory `dir`
    /// (`vn_authorize_create`'s, `vn_authorize_mkdir`'s: `action` on the
    /// directory, KAUTH_VNODE_ADD_FILE or KAUTH_VNODE_ADD_SUBDIRECTORY),
    /// and the attributes it is made with, mode `mode`.
    pub(crate) fn darwin_creating(&mut self, dir: &Found, name: &str, action: u32, mode: u32) -> Result<Creating, Errno> {
        let cred = self.dtask.cred.clone();
        let d = self.darwin_vnode_node(&dir.path, &dir.md, None);
        self.darwin_authorize(&cred, &d, None, action)?;
        let owned = match d.attrs {
            Ok(o) => super::vattr::new_file(cred.uid, &o, mode),
            Err(why) => {
                self.darwin_unimplemented(why);
                return Err(Errno::EIO);
            }
        };
        Ok(Creating { path: join(&dir.path, name.trim_end_matches('/')), owned })
    }

    /// The record of what a call made, once it has made it; reported if
    /// the filesystem cannot keep it.
    pub(crate) fn darwin_created(&mut self, c: &Creating, handle: Option<&dyn crate::vfs::FileHandle>) {
        if let Err(why) = super::vattr::record_new(&self.vfs, &c.path, handle, &c.owned) {
            self.darwin_unimplemented(why);
        }
    }

    /// `vn_open_auth`'s lookup and checks for an open of the path at guest
    /// `path` from `dirfd` with Darwin's open flags `flags`, after `open1`'s
    /// own: an O_CREAT lookup follows a link at the end unless O_EXCL or
    /// O_NOFOLLOW, any other unless O_NOFOLLOW or O_SYMLINK. A name to make
    /// (with no slash after it, ENOENT otherwise) has the create check of a
    /// regular file, then `vn_authorize_create`'s authorization; what it is
    /// made with (mode `cmode`) is returned. A file there (EEXIST with
    /// O_CREAT and O_EXCL) has `vn_authorize_open_existing`'s errors first
    /// (a directory to write, O_DIRECTORY on another file, a socket, a link
    /// with O_NOFOLLOW), then the open check of its open mode, then
    /// `vnode_authorize` of what the mode does: read, write (append, when
    /// appending without truncating).
    pub(crate) fn darwin_sb_open_check(&mut self, m: &GuestMem<'_>, dirfd: u64, path: u64, flags: u64, cmode: u32) -> Result<Option<Creating>, Errno> {
        const O_NOFOLLOW: u64 = 0x100;
        const O_CREAT: u64 = 0x200;
        const O_TRUNC: u64 = 0x400;
        const O_EXCL: u64 = 0x800;
        const O_DIRECTORY: u64 = 0x10_0000;
        const O_SYMLINK: u64 = 0x20_0000;
        const O_NOFOLLOW_ANY: u64 = 0x2000_0000;
        const O_APPEND: u64 = 0x8;
        const FREAD: u32 = 1;
        const FWRITE: u32 = 2;
        if (flags & O_NOFOLLOW_ANY != 0 && flags & (O_SYMLINK | O_NOFOLLOW) != 0) || (flags & O_CREAT != 0 && flags & O_DIRECTORY != 0) {
            return Ok(None);
        }
        let create = flags & O_CREAT != 0;
        let follow = if create { flags & (O_EXCL | O_NOFOLLOW) == 0 } else { flags & (O_NOFOLLOW | O_SYMLINK) == 0 };
        let f = match self.darwin_sb_namei(m, dirfd, path, follow, flags & O_NOFOLLOW_ANY != 0)? {
            Lookup::Missing { dir, name } if create && !name.ends_with('/') => {
                refused(self.darwin_mac_check_vnode_create(&dir, &name, Some(vt::VREG)))?;
                return self.darwin_creating(&dir, &name, super::vauth::kauth::ADD_FILE, cmode).map(Some);
            }
            Lookup::Found(f) if !(create && flags & O_EXCL != 0) => f,
            _ => return Ok(None),
        };
        // FFLAGS: the access mode's FREAD and FWRITE.
        let fmode = ((flags & !3) | ((flags & 3) + 1)) as u32;
        let t = f.md.file_type;
        let refused_first = if t == FileType::Directory {
            u64::from(fmode) & (2 | O_TRUNC) != 0
        } else {
            flags & O_DIRECTORY != 0 || t == FileType::Socket || (t == FileType::Symlink && flags & O_NOFOLLOW != 0)
        };
        if refused_first {
            return Ok(None);
        }
        refused(self.darwin_mac_check_vnode_open(sb_vnode(&f.path, &f.md), fmode))?;
        use super::vauth::kauth;
        let mut action = 0;
        if fmode & FREAD != 0 {
            action |= kauth::READ_DATA;
        }
        if fmode & FWRITE != 0 || flags & O_TRUNC != 0 {
            action |= if flags & O_APPEND != 0 && flags & O_TRUNC == 0 { kauth::APPEND_DATA } else { kauth::WRITE_DATA };
        }
        let cred = self.dtask.cred.clone();
        let node = self.darwin_vnode_node(&f.path, &f.md, None);
        self.darwin_authorize(&cred, &node, None, action)?;
        // APFS takes the set-user-id and set-group-id bits off a file a
        // user other than root writes to (measured on a Mac's APFS), which
        // the writes here do not do.
        if action & (kauth::WRITE_DATA | kauth::APPEND_DATA) != 0 && cred.uid != 0 && node.attrs.as_ref().is_ok_and(|o| o.mode & (super::vattr::S_ISUID | super::vattr::S_ISGID) != 0) {
            self.darwin_unimplemented(format!("{} opened for writing by a user other than root: APFS clears a set-id file's set-id bits as it is written", f.path));
            return Err(Errno::EIO);
        }
        Ok(None)
    }
}

impl Kernel {
    /// `mac_file_check_lock` of F_SETLK on open file `file`, a vnode: the
    /// lock check of its vnode.
    pub(crate) fn darwin_sb_setlk(&mut self, file: &std::sync::Arc<crate::file::OpenFile>) -> Result<(), Errno> {
        let md = file.handle.metadata()?;
        let v = sb_vnode(&self.vfs.canonical(&file.path), &md);
        refused(self.darwin_mac_check_file_lock(v, true))
    }

    /// `mac_file_check_mmap` of open file `file`, a vnode, mapped with
    /// protection `prot`.
    pub(crate) fn darwin_sb_mmap(&mut self, file: &std::sync::Arc<crate::file::OpenFile>, prot: u64) -> Result<(), Errno> {
        let md = file.handle.metadata()?;
        let v = sb_vnode(&self.vfs.canonical(&file.path), &md);
        let shared_dyld = self.darwin_vnode_of(file).is_some_and(super::shregion::shared_dyld);
        refused(self.darwin_mac_check_file_mmap(v, prot, shared_dyld))
    }
}

impl Kernel {
    /// `unp_bind` (with `bind`) and `unp_connect` of unix socket `fd` to
    /// address `sa` (its bytes, `sa_len` its length): the address's family
    /// and length checked (a bound socket's bind is EINVAL first), the
    /// path looked up (following a link at its end); a name to bind to has
    /// the create check of a socket, then the bind check (one there is
    /// EADDRINUSE); a socket to connect to (ENOTSOCK for anything else),
    /// the connect check.
    pub(crate) fn darwin_sb_unix_name(&mut self, fd: i32, sa: &[u8], bind: bool) -> Result<(), Errno> {
        const SOCK_MAXADDRLEN: usize = 255;
        if sa.len() < 2 || (sa[1] != 0 && sa[1] != 1) {
            return Ok(());
        }
        if bind {
            let Ok(file) = self.fds.get(fd) else { return Ok(()) };
            let h = &file.handle;
            let named = std::sync::Arc::clone(h).as_unix_socket().is_some_and(|s| s.bound_path().is_some()) || std::sync::Arc::clone(h).as_unix_dgram().is_some_and(|d| d.name().is_some());
            if named {
                return Ok(());
            }
        }
        let namelen = sa.len() - 2;
        if namelen == 0 || namelen >= SOCK_MAXADDRLEN {
            return Ok(());
        }
        let path = &sa[2..];
        let path = &path[..path.iter().position(|&b| b == 0).unwrap_or(path.len())];
        let Ok(path) = std::str::from_utf8(path) else { return Ok(()) };
        if path.is_empty() {
            return Ok(());
        }
        let start = if path.starts_with('/') { None } else { self.darwin_sb_start(super::bsd::AT_FDCWD as u64) };
        match (self.darwin_sb_lookup(start, path, true, false)?, bind) {
            (Lookup::Missing { dir, name }, true) => {
                refused(self.darwin_mac_check_vnode_create(&dir, &name, Some(vt::VSOCK)))?;
                refused(self.darwin_mac_check_vnode_uipc_bind(&dir, &name))?;
                // vnode_authorize of adding it to the directory; the socket
                // made with every access permission the umask leaves.
                let mode = super::fsops::ACCESSPERMS as u32 & !self.darwin_umask();
                self.darwin_creation = Some(self.darwin_creating(&dir, &name, super::vauth::kauth::ADD_FILE, mode)?);
                Ok(())
            }
            (Lookup::Found(f), false) if f.md.file_type == FileType::Socket => refused(self.darwin_mac_check_vnode_uipc_connect(sb_vnode(&f.path, &f.md))),
            _ => Ok(()),
        }
    }
}
