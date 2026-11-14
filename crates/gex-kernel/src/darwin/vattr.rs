//! A vnode's owner, group, mode and flags (`va_uid`, `va_gid`, `va_mode`
//! and `va_flags`), which `stat`, `getattrlist` and the permission checks
//! read, by where the file is:
//!
//! - devfs's nodes: devfs's own (`devfs_getattr`);
//! - the sealed volumes' files (the system volume, the SystemOS cryptex):
//!   their images' ([`super::volattrs`]), for a file of the type the image
//!   has at that path. An overlay file is the system volume's at its path,
//!   or the system's where the volume has none (`vfs::overlay`'s rule);
//! - the Data volume (`/private/var`), which restore fills with the system
//!   image's `/private/var` (restored's "copy var", a BOMCopier copy of
//!   `/mnt1/private/var` that keeps owners, modes and flags): a file the
//!   image has there, of its type and mode (the extraction kept the modes
//!   of every one, and neither owners nor flags), has the image's;
//! - a file the guest made, or whose owner, group, mode or flags it
//!   changed, wherever it is: what was recorded then ([`RECORD`]).
//!
//! What none of these covers has no attributes to give: a file of the
//! extraction the device does not have, or one put in place outside the
//! guest. The caller reports it and fails.

use super::volattrs::{self, Kind, Vol};
use crate::errno::Errno;
use crate::vfs::{FileHandle, FileType, Metadata, Namespace, XattrOp};

/// `st_flags` (`bsd/sys/stat.h`).
pub mod flags {
    pub const UF_SETTABLE: u32 = 0x0000_ffff;
    pub const UF_IMMUTABLE: u32 = 0x0000_0002;
    pub const UF_APPEND: u32 = 0x0000_0004;
    pub const UF_COMPRESSED: u32 = 0x0000_0020;
    pub const UF_DATAVAULT: u32 = 0x0000_0080;
    pub const SF_SETTABLE: u32 = 0x3fff_0000;
    pub const SF_SYNTHETIC: u32 = 0xc000_0000;
    pub const SF_IMMUTABLE: u32 = 0x0002_0000;
    pub const SF_APPEND: u32 = 0x0004_0000;
    pub const SF_RESTRICTED: u32 = 0x0008_0000;
    pub const SF_SUPPORTED: u32 = 0x009f_0000;
    pub const IMMUTABLE: u32 = UF_IMMUTABLE | SF_IMMUTABLE;
    pub const APPEND: u32 = UF_APPEND | SF_APPEND;
}

/// `S_ISUID`, `S_ISGID`, `S_ISTXT`, `ALLPERMS`.
pub const S_ISUID: u32 = 0o4000;
pub const S_ISGID: u32 = 0o2000;
pub const S_ISTXT: u32 = 0o1000;
pub const ALLPERMS: u32 = 0o7777;

/// A vnode's owner, group, permission bits (with the set-id and sticky
/// bits) and flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Owned {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub flags: u32,
}

/// The host extended attribute a file's attributes are recorded in once
/// the guest made it or changed them: `uid=U gid=G mode=OOOO flags=X`, in
/// the specifications' terms (the mode in octal, the flags in
/// hexadecimal). The test runner records the programs it copies in.
pub const RECORD: &str = "user.gex.darwin.attrs";

/// [`RECORD`] as a Darwin extended attribute call names it (the
/// filesystems keep a Darwin attribute behind `user.`): the guest's calls
/// do not reach it.
pub const RECORD_DARWIN_NAME: &str = "gex.darwin.attrs";

/// The Data volume's mount point on the device, a directory of the root
/// here.
const DATA: &str = "/private/var";

/// The device's other volumes, which this root has as directories of its
/// own (the device tree's `/filesystems/fstab`): their mount points, names
/// and whether they are mounted read-only. What they hold is not the
/// system image's.
const OTHER_VOLUMES: [(&str, &str, bool); 4] = [("/private/xarts", "xART", false), ("/private/preboot", "Preboot", true), ("/private/var/MobileSoftwareUpdate", "Update", false), ("/private/var/hardware", "Hardware", false)];

/// Whether `path` is `at` or below it.
fn within(path: &str, at: &str) -> bool {
    path == at || path.strip_prefix(at).is_some_and(|r| r.starts_with('/'))
}

/// Whether canonical path `path` is on the Data volume.
pub fn on_data(path: &str) -> bool {
    within(path, DATA) && !OTHER_VOLUMES.iter().any(|v| within(path, v.0))
}

/// The other volume `path` is on, if it is on one.
fn other_volume(path: &str) -> Option<(&'static str, &'static str, bool)> {
    OTHER_VOLUMES.iter().copied().find(|v| within(path, v.0))
}

/// Whether the device's volume `path` is on is mounted nosuid: the Data
/// volume and the others the fstab mounts so (all but the system
/// volume), and the cryptex graft's Preboot.
pub fn device_nosuid(path: &str) -> bool {
    let m = super::kern::mount_of(path);
    match m.vol {
        Some(Vol::System) => on_data(path) || other_volume(path).is_some(),
        Some(Vol::OsCryptex) => true,
        None => false,
    }
}

/// The mount flags `vnode_authorize` reads (`MNT_RDONLY`) of the device's
/// volume `path` is on: the system volume and the cryptex graft (on the
/// Preboot volume) read-only, the Data volume and the others the fstab
/// mounts `rw` writable, devfs writable.
pub fn device_mnt_flags(path: &str) -> u32 {
    use super::vauth::mnt;
    let m = super::kern::mount_of(path);
    if m.fs == super::kern::Fs::Devfs {
        return 0;
    }
    if m.vol == Some(Vol::System) {
        if on_data(path) {
            return 0;
        }
        if let Some((_, _, ro)) = other_volume(path) {
            return if ro { mnt::RDONLY } else { 0 };
        }
    }
    m.flags & mnt::RDONLY
}

impl Owned {
    /// The record's text.
    pub fn record(&self) -> String {
        format!("uid={} gid={} mode={:04o} flags={:x}", self.uid, self.gid, self.mode & ALLPERMS, self.flags)
    }

    /// A record read back.
    pub fn parse(b: &[u8]) -> Result<Owned, String> {
        let text = std::str::from_utf8(b).map_err(|_| "a record that is not text".to_string())?;
        let (mut uid, mut gid, mut mode, mut flags) = (None, None, None, None);
        for w in text.split_ascii_whitespace() {
            let (k, v) = w.split_once('=').ok_or_else(|| format!("the record {text:?}"))?;
            let bad = || format!("the record {text:?}");
            match k {
                "uid" => uid = Some(v.parse().map_err(|_| bad())?),
                "gid" => gid = Some(v.parse().map_err(|_| bad())?),
                "mode" => mode = Some(u32::from_str_radix(v, 8).ok().filter(|m| *m <= ALLPERMS).ok_or_else(bad)?),
                "flags" => flags = Some(u32::from_str_radix(v, 16).map_err(|_| bad())?),
                _ => return Err(bad()),
            }
        }
        match (uid, gid, mode, flags) {
            (Some(uid), Some(gid), Some(mode), Some(flags)) => Ok(Owned { uid, gid, mode, flags }),
            _ => Err(format!("the record {text:?}, which lacks a keyword")),
        }
    }
}

/// `vnode_authattr_new`'s attributes of a file `uid` makes with mode
/// `mode` (the call's, the umask applied) in directory `dir`: the maker's
/// effective user, the directory's group (BSD semantics), and the
/// directory's SF_RESTRICTED and UF_DATAVAULT, which a file made in it
/// inherits; no other flag.
pub fn new_file(uid: u32, dir: &Owned, mode: u32) -> Owned {
    Owned { uid, gid: dir.gid, mode: mode & ALLPERMS, flags: dir.flags & (flags::UF_DATAVAULT | flags::SF_RESTRICTED) }
}

/// The record of a file a call has just made, written once: a record
/// already there is another maker's, which won the race to make it.
pub fn record_new(ns: &Namespace, path: &str, handle: Option<&dyn FileHandle>, o: &Owned) -> Result<(), String> {
    let text = o.record();
    let op = || XattrOp::Set { name: RECORD, value: text.as_bytes(), flags: crate::vfs::XATTR_CREATE };
    let r = match handle.and_then(|h| h.xattr(op())) {
        Some(r) => r,
        None => ns.xattr(path, false, op()),
    };
    match r {
        Ok(_) | Err(Errno::EEXIST) => Ok(()),
        Err(e) => Err(format!("{path}: recording the owner, group, mode and flags of a file made ({e:?}: the filesystem keeps no extended attribute there)")),
    }
}

/// The attributes a call asks to set (a `struct vnode_attr`'s active
/// owner, group, mode, flags and times).
#[derive(Clone, Copy, Debug, Default)]
pub struct SetAttr {
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub mode: Option<u32>,
    pub flags: Option<u32>,
    /// Any time is set; and whether to now (`VA_UTIMES_NULL`).
    pub times: bool,
    pub utimes_null: bool,
}

/// `vnode_authattr` of `set` on a file with attributes `old`, by `cred`:
/// the rights the change needs (`KAUTH_VNODE_*`), its refusals (EPERM,
/// EACCES), and what is set as it leaves `set` (the set-id bits a change
/// of owner or group clears, the synthetic flags dropped).
pub fn authattr(cred: &super::cred::Cred, old: &Owned, set: &mut SetAttr) -> Result<u32, Errno> {
    use super::vauth::kauth;
    let suser = cred.uid == 0;
    let mut action = 0;
    if set.times {
        if suser || old.uid == cred.uid {
            action |= kauth::CHECKIMMUTABLE | kauth::WRITE_ATTRIBUTES;
        } else if set.utimes_null {
            action |= kauth::WRITE_ATTRIBUTES;
        } else {
            return Err(Errno::EACCES);
        }
    }
    if let Some(mode) = set.mode.filter(|m| *m != old.mode) {
        action |= if suser { kauth::CHECKIMMUTABLE } else { kauth::WRITE_SECURITY };
        if mode & S_ISGID != 0 {
            action |= kauth::CHECKIMMUTABLE;
            if !suser && !cred.is_member(set.gid.unwrap_or(old.gid)) {
                return Err(Errno::EPERM);
            }
        }
        if mode & S_ISUID != 0 {
            action |= kauth::CHECKIMMUTABLE;
            if !suser && set.uid.unwrap_or(old.uid) != cred.uid {
                return Err(Errno::EPERM);
            }
        }
    }
    if let Some(f) = set.flags.as_mut() {
        *f &= !flags::SF_SYNTHETIC;
        let fdelta = *f ^ (old.flags & !flags::SF_SYNTHETIC);
        if fdelta != 0 {
            action |= kauth::WRITE_SECURITY;
            let allowed = if suser { flags::UF_SETTABLE | flags::SF_SETTABLE } else { flags::UF_SETTABLE };
            if fdelta & !allowed != 0 {
                return Err(Errno::EPERM);
            }
            action |= kauth::NOIMMUTABLE;
        }
    }
    let (mut chowner, mut chgroup, mut clear_suid, mut clear_sgid) = (false, false, false, false);
    if let Some(uid) = set.uid {
        if uid != old.uid {
            if !suser && cred.uid != uid {
                return Err(Errno::EPERM);
            }
            chowner = true;
        }
        clear_suid = true;
    }
    if let Some(gid) = set.gid {
        if gid != old.gid {
            if !suser && !cred.is_member(gid) {
                return Err(Errno::EPERM);
            }
            chgroup = true;
        }
        clear_sgid = true;
    }
    if chowner || chgroup || clear_suid || clear_sgid {
        if suser {
            action |= kauth::CHECKIMMUTABLE;
        } else {
            if chowner {
                action |= kauth::TAKE_OWNERSHIP;
            }
            if chgroup && !chowner {
                action |= kauth::WRITE_SECURITY;
            }
        }
        // chown clears the set-id bits, root's too, unless the call sets
        // the mode with them (setattrlist).
        let mut newmode = set.mode.unwrap_or(old.mode);
        if newmode & (S_ISUID | S_ISGID) != 0 {
            if set.mode.is_none() {
                newmode &= !(S_ISUID | S_ISGID);
            }
            set.mode = Some(newmode);
        }
    }
    Ok(action)
}

/// Whether a specification's type is the file's.
fn same_kind(k: Kind, t: FileType) -> bool {
    matches!(
        (k, t),
        (Kind::Dir, FileType::Directory) | (Kind::File, FileType::Regular) | (Kind::Link, FileType::Symlink) | (Kind::Char, FileType::CharDevice) | (Kind::Fifo, FileType::Fifo) | (Kind::Socket, FileType::Socket)
    )
}

fn type_name(t: FileType) -> &'static str {
    match t {
        FileType::Regular => "file",
        FileType::Directory => "directory",
        FileType::Symlink => "symbolic link",
        FileType::CharDevice => "character device",
        FileType::Fifo => "FIFO",
        FileType::Socket => "socket",
    }
}

/// The canonical path of the file `md` that `path` names: a link's own
/// (its directory's canonical path and its name) for a link, the file it
/// leads to else.
pub fn vnode_path(ns: &Namespace, path: &str, md: &Metadata) -> String {
    if md.file_type == FileType::Symlink {
        let dir = ns.canonical(&crate::vfs::parent_of(path));
        let name = crate::vfs::basename(path);
        if dir == "/" {
            format!("/{name}")
        } else {
            format!("{dir}/{name}")
        }
    } else {
        ns.canonical(path)
    }
}

/// The record of a file, read through its open handle when there is one
/// (it may have no name left), else by path, its last link not followed:
/// `None` for a file with none.
pub fn recorded(ns: &Namespace, path: &str, handle: Option<&dyn FileHandle>) -> Result<Option<Owned>, String> {
    let mut buf = [0u8; 128];
    let r = match handle.and_then(|h| h.xattr(XattrOp::Get { name: RECORD, buf: &mut buf })) {
        Some(r) => r,
        None => ns.xattr(path, false, XattrOp::Get { name: RECORD, buf: &mut buf }),
    };
    match r {
        Ok(n) => Owned::parse(&buf[..n]).map(Some).map_err(|e| format!("{path}: {e}")),
        // No record, or a filesystem that keeps no attributes (where
        // nothing could have been recorded).
        Err(Errno::ENODATA) | Err(Errno::EOPNOTSUPP) => Ok(None),
        Err(e) => Err(format!("{path}: reading its record: {e:?}")),
    }
}

/// Record `o` as the attributes of the file at `path` (its last link not
/// followed), or of the open `handle`.
pub fn record(ns: &Namespace, path: &str, handle: Option<&dyn FileHandle>, o: &Owned) -> Result<(), String> {
    let text = o.record();
    let op = || XattrOp::Set { name: RECORD, value: text.as_bytes(), flags: 0 };
    let r = match handle.and_then(|h| h.xattr(op())) {
        Some(r) => r,
        None => ns.xattr(path, false, op()),
    };
    r.map(|_| ()).map_err(|e| format!("{path}: recording its owner, group, mode and flags ({e:?}: the filesystem keeps no extended attribute there)"))
}

/// The attributes of the file `md` at canonical `path` (its last link not
/// followed; a mount point is the mounted volume's root), and open as
/// `handle` if it is. `Err` says why there are none.
pub fn of(ns: &Namespace, path: &str, md: &Metadata, handle: Option<&dyn FileHandle>) -> Result<Owned, String> {
    let mnt = super::kern::mount_of(path);
    if mnt.fs == super::kern::Fs::Devfs {
        return devfs(path, md);
    }
    let Some(vol) = mnt.vol else {
        return Err(format!("the owner of {path}: the volume mounted on {} keeps none here", mnt.on));
    };
    if let Some(o) = recorded(ns, path, handle)? {
        return Ok(o);
    }
    if vol == Vol::System {
        if let Some((on, name, _)) = other_volume(path) {
            return Err(format!("the owner of {path}: on the device {on} is the {name} volume's, which is not modelled"));
        }
    }
    // The path below the volume's root.
    let rel = match path.strip_prefix(mnt.on.trim_end_matches('/')) {
        Some("") | None => "/",
        Some(r) => r,
    };
    let image = volattrs::lookup(vol, rel);
    let owned = |a: volattrs::Attrs| Owned { uid: a.uid, gid: a.gid, mode: a.mode, flags: a.flags };
    if vol == Vol::System && crate::vfs::overlay::is_own_ino(md.ino) {
        // An overlay file: the volume's at its path, else the system's.
        return Ok(match image {
            Ok(a) if same_kind(a.kind, md.file_type) => owned(a),
            _ => Owned { uid: 0, gid: 0, mode: md.mode & ALLPERMS, flags: 0 },
        });
    }
    let a = image.map_err(|e| format!("the owner of {path}: {e}"))?;
    if !same_kind(a.kind, md.file_type) {
        return Err(format!("the owner of {path}: the root has a {} there, where the device's image has another kind of file", type_name(md.file_type)));
    }
    if vol == Vol::System && on_data(path) && a.mode != md.mode & ALLPERMS {
        return Err(format!("the owner of {path}: a file of the Data volume whose mode ({:04o}) is not the image's ({:04o}): changed outside the guest", md.mode & ALLPERMS, a.mode));
    }
    Ok(owned(a))
}

/// [`of`], or reported (stopping a strict run when the call ends) and
/// `EIO`, the call's error: the volume's attributes cannot be read.
pub fn get(ns: &Namespace, path: &str, md: &Metadata, handle: Option<&dyn FileHandle>) -> Result<Owned, Errno> {
    of(ns, path, md, handle).map_err(|e| {
        super::note_unimplemented(e);
        Errno::EIO
    })
}

/// A devfs vnode's (`devfs_getattr`): the root's root, wheel and hidden;
/// a node's its own.
fn devfs(path: &str, md: &Metadata) -> Result<Owned, String> {
    if path == "/dev" {
        return Ok(Owned { uid: 0, gid: 0, mode: md.mode & ALLPERMS, flags: super::devfs::UF_HIDDEN });
    }
    if let Some((uid, gid)) = super::ttydev::node_owner(md) {
        return Ok(Owned { uid, gid, mode: md.mode & ALLPERMS, flags: 0 });
    }
    if let Some(n) = super::devfs::node_of(md) {
        return Ok(Owned { uid: n.uid, gid: n.gid, mode: md.mode & ALLPERMS, flags: 0 });
    }
    Err(format!("the owner of {path}: devfs has no node of this kind"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_read_back() {
        let o = Owned { uid: 501, gid: 0, mode: 0o4755, flags: 0x20 };
        assert_eq!(o.record(), "uid=501 gid=0 mode=4755 flags=20");
        assert_eq!(Owned::parse(o.record().as_bytes()), Ok(o));
        assert!(Owned::parse(b"uid=0 gid=0 mode=0755").is_err());
        assert!(Owned::parse(b"uid=0 gid=0 mode=17777 flags=0").is_err());
        assert!(Owned::parse(b"uid=0 gid=0 mode=0755 flags=0 size=3").is_err());
    }

    #[test]
    fn changing_owners_and_modes_follows_vnode_authattr() {
        use super::super::cred::Cred;
        use super::super::vauth::kauth;
        let mine = Owned { uid: 501, gid: 20, mode: 0o4755, flags: 0 };
        let me = Cred::of(501, 20);
        // chown to oneself clears the set-user-id bit, root's chown too.
        let mut s = SetAttr { uid: Some(501), ..Default::default() };
        assert_eq!(authattr(&me, &mine, &mut s), Ok(0));
        assert_eq!(s.mode, Some(0o755));
        let mut s = SetAttr { uid: Some(502), ..Default::default() };
        assert_eq!(authattr(&me, &mine, &mut s), Err(Errno::EPERM));
        let mut s = SetAttr { uid: Some(502), ..Default::default() };
        assert_eq!(authattr(&Cred::of(0, 0), &mine, &mut s), Ok(kauth::CHECKIMMUTABLE));
        assert_eq!(s.mode, Some(0o755));
        // A group one is not in, a set-group-id bit of one, a superuser
        // flag: EPERM.
        let mut s = SetAttr { gid: Some(80), ..Default::default() };
        assert_eq!(authattr(&me, &mine, &mut s), Err(Errno::EPERM));
        let mut s = SetAttr { mode: Some(0o2755), ..Default::default() };
        let theirs = Owned { gid: 80, ..mine };
        assert_eq!(authattr(&me, &theirs, &mut s), Err(Errno::EPERM));
        let mut s = SetAttr { flags: Some(flags::SF_IMMUTABLE), ..Default::default() };
        assert_eq!(authattr(&me, &mine, &mut s), Err(Errno::EPERM));
        let mut s = SetAttr { flags: Some(flags::UF_IMMUTABLE), ..Default::default() };
        assert_eq!(authattr(&me, &mine, &mut s), Ok(kauth::WRITE_SECURITY | kauth::NOIMMUTABLE));
        // A mode change by the owner needs WRITE_SECURITY.
        let mut s = SetAttr { mode: Some(0o644), ..Default::default() };
        assert_eq!(authattr(&me, &mine, &mut s), Ok(kauth::WRITE_SECURITY));
    }

    #[test]
    fn the_data_volume_is_private_var() {
        assert!(on_data("/private/var"));
        assert!(on_data("/private/var/tmp/x"));
        assert!(!on_data("/private/varx"));
        assert!(!on_data("/private"));
        assert!(!on_data("/private/var/hardware/x"));
        assert!(!on_data("/private/var/MobileSoftwareUpdate"));
        assert_eq!(device_mnt_flags("/private/var/tmp"), 0);
        assert_eq!(device_mnt_flags("/usr/lib"), super::super::vauth::mnt::RDONLY);
        assert_eq!(device_mnt_flags("/private/preboot/x"), super::super::vauth::mnt::RDONLY);
        assert_eq!(device_mnt_flags("/dev/null"), 0);
    }
}
