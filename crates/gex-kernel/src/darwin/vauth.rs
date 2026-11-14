//! `vnode_authorize` (`bsd/vfs/vfs_subr.c`): whether a credential may do
//! what a call asks of a vnode, by the vnode's owner, group, mode and
//! flags ([`super::vattr`]) and its volume's mount flags. No file here
//! carries an access control list (the device's images have none, and an
//! ACL the guest gives is reported where it is given), so the ACL
//! evaluations find none and defer to the POSIX permissions, as XNU's do
//! for a vnode without one; nothing is cached (`vnode_cache_authorized_action`
//! only spares the work, its answers are the uncached ones).
//!
//! Where a vnode's attributes are unknown, the check reads them only where
//! XNU's answer depends on them: the owner when the owner's bits disagree
//! with the others', and so on. An answer that needs what is unknown is
//! [`Denied::Unknown`], for the caller to report.

use super::cred::Cred;
use super::vattr::{flags, Owned, S_ISTXT};
use crate::errno::Errno;
use crate::syscalls::Kernel;
use crate::vfs::{FileHandle, FileType, Metadata};

/// `KAUTH_VNODE_*` (`bsd/sys/kauth.h`).
pub mod kauth {
    pub const READ_DATA: u32 = 1 << 1;
    pub const LIST_DIRECTORY: u32 = READ_DATA;
    pub const WRITE_DATA: u32 = 1 << 2;
    pub const ADD_FILE: u32 = WRITE_DATA;
    pub const EXECUTE: u32 = 1 << 3;
    pub const SEARCH: u32 = EXECUTE;
    pub const DELETE: u32 = 1 << 4;
    pub const APPEND_DATA: u32 = 1 << 5;
    pub const ADD_SUBDIRECTORY: u32 = APPEND_DATA;
    pub const DELETE_CHILD: u32 = 1 << 6;
    pub const READ_ATTRIBUTES: u32 = 1 << 7;
    pub const WRITE_ATTRIBUTES: u32 = 1 << 8;
    pub const READ_EXTATTRIBUTES: u32 = 1 << 9;
    pub const WRITE_EXTATTRIBUTES: u32 = 1 << 10;
    pub const READ_SECURITY: u32 = 1 << 11;
    pub const WRITE_SECURITY: u32 = 1 << 12;
    pub const TAKE_OWNERSHIP: u32 = 1 << 13;
    pub const CHANGE_OWNER: u32 = TAKE_OWNERSHIP;
    pub const LINKTARGET: u32 = 1 << 25;
    pub const CHECKIMMUTABLE: u32 = 1 << 26;
    pub const NOIMMUTABLE: u32 = 1 << 30;
    pub const ACCESS: u32 = 1 << 31;
    pub const WRITE_RIGHTS: u32 = ADD_FILE | ADD_SUBDIRECTORY | DELETE_CHILD | WRITE_DATA | APPEND_DATA | DELETE | WRITE_ATTRIBUTES | WRITE_EXTATTRIBUTES | WRITE_SECURITY | TAKE_OWNERSHIP | LINKTARGET | CHECKIMMUTABLE;
}

/// `MNT_RDONLY`, `MNT_NOEXEC`, `MNT_NOUSERXATTR`.
pub mod mnt {
    pub const RDONLY: u32 = 0x1;
    pub const NOEXEC: u32 = 0x4;
    pub const NOUSERXATTR: u32 = 0x0100_0000;
}

/// `VREAD`, `VWRITE`, `VEXEC`.
const VREAD: u32 = 0x100;
const VWRITE: u32 = 0x080;
const VEXEC: u32 = 0x040;

/// A vnode as the checks read it: its type, its attributes (or why they
/// are unknown) and its volume's mount flags.
pub struct Node {
    pub vtype: FileType,
    pub attrs: Result<Owned, String>,
    pub mnt_flags: u32,
}

/// Why a check refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denied {
    /// The call's error (`*errorp`, or EACCES).
    Errno(Errno),
    /// The answer needs attributes the vnode has none of: why.
    Unknown(String),
}

impl From<Errno> for Denied {
    fn from(e: Errno) -> Denied {
        Denied::Errno(e)
    }
}

/// Who asks: the credential, and whether its process ignores node
/// permissions on what it owns (`proc_ignores_node_permissions`,
/// `P_VFS_IOPOLICY_IGNORE_NODE_PERMISSIONS`).
pub struct Ctx<'a> {
    pub cred: &'a Cred,
    pub ignores_node_permissions: bool,
    /// `securelevel`.
    pub securelevel: i32,
}

fn attrs(n: &Node) -> Result<&Owned, Denied> {
    n.attrs.as_ref().map_err(|e| Denied::Unknown(e.clone()))
}

/// `vauth_node_owner`.
fn is_owner(ctx: &Ctx<'_>, n: &Node) -> Result<bool, Denied> {
    Ok(attrs(n)?.uid == ctx.cred.uid)
}

/// `vauth_node_group`: membership of the node's group.
fn in_group(ctx: &Ctx<'_>, n: &Node) -> Result<bool, Denied> {
    Ok(ctx.cred.is_member(attrs(n)?.gid))
}

/// `vnode_immutable`.
fn immutable(ctx: &Ctx<'_>, f: u32, append: bool, ignore: bool) -> Result<(), Errno> {
    let mut mask = flags::IMMUTABLE | flags::APPEND;
    if append {
        mask &= !flags::APPEND;
    }
    if ignore {
        if ctx.securelevel <= 0 {
            mask = 0;
        } else {
            mask &= !(flags::UF_IMMUTABLE | flags::UF_APPEND);
        }
    }
    if f & mask != 0 {
        return Err(Errno::EPERM);
    }
    Ok(())
}

/// `vnode_authorize_checkimmutable` of `n` (the file, or the directory
/// for a delete's `DELETE_CHILD`), `file` being the file whose ownership
/// the entitlement's override goes by.
fn check_immutable(ctx: &Ctx<'_>, n: &Node, file: &Node, dir: Option<&Node>, mut rights: u32, ignore: bool) -> Result<(), Denied> {
    if matches!(n.vtype, FileType::Socket | FileType::Fifo | FileType::CharDevice) {
        rights &= !kauth::WRITE_DATA;
    }
    if rights & kauth::WRITE_RIGHTS == 0 {
        return Ok(());
    }
    if rights & kauth::WRITE_EXTATTRIBUTES != 0 && n.mnt_flags & mnt::NOUSERXATTR != 0 {
        return Err(Errno::EACCES.into());
    }
    let append = if n.vtype == FileType::Directory {
        rights & (kauth::ADD_FILE | kauth::ADD_SUBDIRECTORY | kauth::WRITE_EXTATTRIBUTES | !kauth::WRITE_RIGHTS) == rights
    } else {
        rights & (kauth::APPEND_DATA | kauth::WRITE_EXTATTRIBUTES | !kauth::WRITE_RIGHTS) == rights
    };
    let f = attrs(n)?.flags;
    match immutable(ctx, f, append, ignore) {
        Ok(()) => Ok(()),
        Err(e) if !ignore && ctx.ignores_node_permissions => {
            let owner = match (rights & kauth::DELETE_CHILD != 0, dir) {
                (true, Some(d)) => is_owner(ctx, file)? && is_owner(ctx, d)?,
                _ => is_owner(ctx, file)?,
            };
            if owner {
                immutable(ctx, f, append, true).map_err(Denied::Errno)
            } else {
                Err(e.into())
            }
        }
        Err(e) => Err(e.into()),
    }
}

/// `vnode_authorize_posix` of `n` (the file, or for `on_dir` its
/// directory).
fn posix(ctx: &Ctx<'_>, n: &Node, action: u32) -> Result<(), Denied> {
    let mode = attrs(n)?.mode;
    let needed = |r: u32, w: u32, x: u32| {
        let mut b = 0;
        if action & VREAD != 0 {
            b |= r;
        }
        if action & VWRITE != 0 {
            b |= w;
        }
        if action & VEXEC != 0 {
            b |= x;
        }
        b
    };
    let n_owner = needed(0o400, 0o200, 0o100);
    let mut owner_ok = n_owner & mode == n_owner;
    if !owner_ok && ctx.ignores_node_permissions {
        owner_ok = true;
    }
    let n_group = needed(0o040, 0o020, 0o010);
    let group_ok = n_group & mode == n_group;
    let n_world = needed(0o004, 0o002, 0o001);
    let world_ok = n_world & mode == n_world;
    let deny = || Err(Denied::Errno(Errno::EACCES));
    if owner_ok && group_ok && world_ok {
        return Ok(());
    }
    if !owner_ok && !group_ok && !world_ok {
        return deny();
    }
    if is_owner(ctx, n)? {
        return if owner_ok { Ok(()) } else { deny() };
    }
    if group_ok && world_ok {
        return Ok(());
    }
    if !group_ok && !world_ok {
        return deny();
    }
    if in_group(ctx, n)? {
        return if group_ok { Ok(()) } else { deny() };
    }
    if world_ok {
        Ok(())
    } else {
        deny()
    }
}

/// `vnode_authorize_delete`, with no right cached on the directory.
fn delete(ctx: &Ctx<'_>, file: &Node, dir: &Node) -> Result<(), Denied> {
    posix(ctx, dir, VWRITE)?;
    if attrs(dir)?.mode & S_ISTXT != 0 && !is_owner(ctx, file)? && !is_owner(ctx, dir)? {
        return Err(Errno::EACCES.into());
    }
    Ok(())
}

/// `vnode_authorize_simple`, the node having no ACL.
fn simple(ctx: &Ctx<'_>, n: &Node, mut acl_rights: u32, preauth: u32) -> Result<(), Denied> {
    if acl_rights & kauth::WRITE_SECURITY != 0 && is_owner(ctx, n)? {
        acl_rights &= !kauth::WRITE_SECURITY;
    }
    if acl_rights & kauth::TAKE_OWNERSHIP != 0 && acl_rights & kauth::WRITE_SECURITY != 0 {
        acl_rights &= !kauth::WRITE_SECURITY;
    }
    if acl_rights == 0 {
        return Ok(());
    }
    let mut residual = acl_rights & !preauth;
    if residual & kauth::WRITE_ATTRIBUTES != 0 && is_owner(ctx, n)? {
        residual &= !kauth::WRITE_ATTRIBUTES;
    }
    if residual == 0 {
        return Ok(());
    }
    if residual & (kauth::CHANGE_OWNER | kauth::WRITE_SECURITY) != 0 {
        return Err(Errno::EACCES.into());
    }
    let mut action = 0;
    if residual & (kauth::READ_DATA | kauth::LIST_DIRECTORY | kauth::READ_EXTATTRIBUTES) != 0 {
        action |= VREAD;
    }
    if residual & (kauth::WRITE_DATA | kauth::ADD_FILE | kauth::ADD_SUBDIRECTORY | kauth::DELETE_CHILD | kauth::WRITE_ATTRIBUTES | kauth::WRITE_EXTATTRIBUTES) != 0 {
        action |= VWRITE;
    }
    if residual & (kauth::EXECUTE | kauth::SEARCH) != 0 {
        action |= VEXEC;
    }
    if action != 0 {
        posix(ctx, n, action)
    } else {
        Ok(())
    }
}

/// `vnode_authorize(vp, dvp, action)`: `dvp` is used for a `DELETE`
/// (which needs it). The error a refusal gives is the check's own
/// (`EROFS`, `EPERM`, ...), else EACCES.
pub fn authorize(ctx: &Ctx<'_>, vp: &Node, dvp: Option<&Node>, action: u32) -> Result<(), Denied> {
    let noimmutable = action & kauth::NOIMMUTABLE != 0;
    let rights = action & !(kauth::ACCESS | kauth::NOIMMUTABLE);
    let dvp = if rights & kauth::DELETE != 0 { dvp } else { None };
    if rights & kauth::DELETE != 0 && dvp.is_none() {
        return Err(Denied::Unknown("vnode_authorize of a delete without its directory".into()));
    }
    // Read-only and noexec volumes.
    if rights & kauth::WRITE_RIGHTS != 0 && vp.mnt_flags & mnt::RDONLY != 0 && (matches!(vp.vtype, FileType::Regular | FileType::Directory | FileType::Symlink) || rights & (kauth::DELETE | kauth::DELETE_CHILD) != 0) {
        return Err(Errno::EROFS.into());
    }
    if rights & kauth::EXECUTE != 0 && vp.vtype == FileType::Regular && vp.mnt_flags & mnt::NOEXEC != 0 {
        return Err(Errno::EACCES.into());
    }
    let is_suser = ctx.cred.uid == 0;
    if is_suser && rights & (kauth::EXECUTE | kauth::WRITE_RIGHTS) == 0 {
        return Ok(());
    }
    // vnode_attr_authorize_internal.
    check_immutable(ctx, vp, vp, dvp, rights, noimmutable)?;
    if rights & kauth::DELETE != 0 {
        if let Some(d) = dvp {
            check_immutable(ctx, d, vp, Some(d), kauth::DELETE_CHILD, false)?;
        }
    }
    let rights = rights & !(kauth::LINKTARGET | kauth::CHECKIMMUTABLE);
    if rights == 0 {
        return Ok(());
    }
    if !is_suser {
        if rights & kauth::DELETE != 0 {
            if let Some(d) = dvp {
                delete(ctx, vp, d)?;
            }
        }
        if rights & !kauth::DELETE != 0 {
            simple(ctx, vp, rights, rights & kauth::DELETE)?;
        }
    } else if rights & kauth::EXECUTE != 0 && vp.vtype == FileType::Regular && attrs(vp)?.mode & 0o111 == 0 {
        return Err(Errno::EPERM.into());
    }
    Ok(())
}

/// `P_VFS_IOPOLICY_IGNORE_NODE_PERMISSIONS`.
const P_VFS_IOPOLICY_IGNORE_NODE_PERMISSIONS: u32 = 0x0040;

impl Kernel {
    /// The vnode at canonical `path` (its last link not followed), open as
    /// `handle` if it is, as the checks read it.
    pub(crate) fn darwin_vnode_node(&self, path: &str, md: &Metadata, handle: Option<&dyn FileHandle>) -> Node {
        Node { vtype: md.file_type, attrs: super::vattr::of(&self.vfs, path, md, handle), mnt_flags: super::vattr::device_mnt_flags(path) }
    }

    /// [`authorize`] for `cred` in this process.
    pub(crate) fn darwin_authorize_check(&self, cred: &Cred, vp: &Node, dvp: Option<&Node>, action: u32) -> Result<(), Denied> {
        let ctx = Ctx { cred, ignores_node_permissions: self.dtask.vfs_iopolicy & P_VFS_IOPOLICY_IGNORE_NODE_PERMISSIONS != 0, securelevel: super::kern::DARWIN_SECURELEVEL };
        authorize(&ctx, vp, dvp, action)
    }

    /// `vnode_authorize` by `cred` in this process: what a refusal says,
    /// or, for an answer that needs attributes the vnode has none of,
    /// reported (a strict run stops) and EIO.
    pub(crate) fn darwin_authorize(&mut self, cred: &Cred, vp: &Node, dvp: Option<&Node>, action: u32) -> Result<(), Errno> {
        let r = self.darwin_authorize_check(cred, vp, dvp, action);
        if self.trace && r.is_err() {
            eprintln!("[gex:{}] vnode_authorize of {action:#x} by {}:{} refused: {:?} ({:?} {:?})", self.pid, cred.uid, cred.gid(), r, vp.vtype, vp.attrs);
        }
        match r {
            Ok(()) => Ok(()),
            Err(Denied::Errno(e)) => Err(e),
            Err(Denied::Unknown(why)) => {
                self.darwin_unimplemented(why);
                Err(Errno::EIO)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(t: FileType, uid: u32, gid: u32, mode: u32, f: u32) -> Node {
        Node { vtype: t, attrs: Ok(Owned { uid, gid, mode, flags: f }), mnt_flags: 0 }
    }

    fn ctx(c: &Cred) -> Ctx<'_> {
        Ctx { cred: c, ignores_node_permissions: false, securelevel: 0 }
    }

    const R: u32 = kauth::READ_DATA;
    const W: u32 = kauth::WRITE_DATA;
    const X: u32 = kauth::EXECUTE;

    #[test]
    fn the_owner_goes_by_the_owner_bits_alone() {
        let me = Cred::of(501, 20);
        let f = node(FileType::Regular, 501, 20, 0o044, 0);
        // The group and world may read; the owner, who may not, is refused.
        assert_eq!(authorize(&ctx(&me), &f, None, R), Err(Denied::Errno(Errno::EACCES)));
        let other = Cred::of(502, 30);
        assert_eq!(authorize(&ctx(&other), &f, None, R), Ok(()));
    }

    #[test]
    fn a_member_goes_by_the_group_bits() {
        let f = node(FileType::Regular, 0, 80, 0o604, 0);
        let mut member = Cred::of(501, 20);
        member.groups.push(80);
        assert_eq!(authorize(&ctx(&member), &f, None, R), Err(Denied::Errno(Errno::EACCES)));
        assert_eq!(authorize(&ctx(&Cred::of(501, 20)), &f, None, R), Ok(()));
    }

    #[test]
    fn root_reads_and_writes_but_executes_only_what_has_an_execute_bit() {
        let root = Cred::of(0, 0);
        let f = node(FileType::Regular, 501, 501, 0o600, 0);
        assert_eq!(authorize(&ctx(&root), &f, None, R | W), Ok(()));
        assert_eq!(authorize(&ctx(&root), &f, None, X), Err(Denied::Errno(Errno::EPERM)));
        let d = node(FileType::Directory, 501, 501, 0o600, 0);
        assert_eq!(authorize(&ctx(&root), &d, None, kauth::SEARCH), Ok(()));
    }

    #[test]
    fn read_only_volumes_and_immutable_files_refuse_writes() {
        let root = Cred::of(0, 0);
        let mut f = node(FileType::Regular, 0, 0, 0o644, 0);
        f.mnt_flags = mnt::RDONLY;
        assert_eq!(authorize(&ctx(&root), &f, None, W), Err(Denied::Errno(Errno::EROFS)));
        assert_eq!(authorize(&ctx(&root), &f, None, R), Ok(()));
        let i = node(FileType::Regular, 0, 0, 0o644, flags::UF_IMMUTABLE);
        assert_eq!(authorize(&ctx(&root), &i, None, W), Err(Denied::Errno(Errno::EPERM)));
        let a = node(FileType::Regular, 0, 0, 0o644, flags::UF_APPEND);
        assert_eq!(authorize(&ctx(&root), &a, None, kauth::APPEND_DATA), Ok(()));
        assert_eq!(authorize(&ctx(&root), &a, None, W), Err(Denied::Errno(Errno::EPERM)));
    }

    #[test]
    fn a_sticky_directory_keeps_others_files() {
        let dir = node(FileType::Directory, 0, 0, 0o1777, 0);
        let theirs = node(FileType::Regular, 502, 20, 0o644, 0);
        let mine = node(FileType::Regular, 501, 20, 0o644, 0);
        let me = Cred::of(501, 20);
        assert_eq!(authorize(&ctx(&me), &theirs, Some(&dir), kauth::DELETE), Err(Denied::Errno(Errno::EACCES)));
        assert_eq!(authorize(&ctx(&me), &mine, Some(&dir), kauth::DELETE), Ok(()));
    }

    #[test]
    fn an_unknown_owner_matters_only_where_the_bits_disagree() {
        let me = Cred::of(501, 20);
        let f = Node { vtype: FileType::Regular, attrs: Err("unknown".into()), mnt_flags: 0 };
        assert!(matches!(authorize(&ctx(&me), &f, None, R), Err(Denied::Unknown(_))));
        // Root reading needs nothing.
        assert_eq!(authorize(&ctx(&Cred::of(0, 0)), &f, None, R), Ok(()));
        // Every class may read and execute: the owner is not asked.
        let mut g = node(FileType::Regular, 0, 0, 0o755, 0);
        g.attrs = Ok(Owned { uid: 0, gid: 0, mode: 0o755, flags: 0 });
        assert_eq!(authorize(&ctx(&me), &g, None, R | X), Ok(()));
    }

    #[test]
    fn write_security_is_the_owners() {
        let me = Cred::of(501, 20);
        let mine = node(FileType::Regular, 501, 20, 0o000, 0);
        let theirs = node(FileType::Regular, 502, 20, 0o777, 0);
        assert_eq!(authorize(&ctx(&me), &mine, None, kauth::WRITE_SECURITY), Ok(()));
        assert_eq!(authorize(&ctx(&me), &theirs, None, kauth::WRITE_SECURITY), Err(Denied::Errno(Errno::EACCES)));
        assert_eq!(authorize(&ctx(&me), &theirs, None, kauth::TAKE_OWNERSHIP), Err(Denied::Errno(Errno::EACCES)));
    }
}
