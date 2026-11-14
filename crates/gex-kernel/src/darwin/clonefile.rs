//! `clonefileat`, `fclonefileat` (`clonefile_internal`) and `exchangedata`.
//!
//! What a clone keeps was measured on an APFS volume: a file's or link's
//! access, modification and creation times, its mode and extended
//! attributes; a directory's access and creation times, its entries cloned
//! and its modification time new; a new file number and change time. The
//! filesystems here have no shared extents, so the bytes are copied. Its
//! owner, group, mode and flags are `clonefile_internal`'s, recorded
//! ([`super::vattr`]).

use super::bsd::dirfd;
use crate::errno::Errno;
use crate::fs::oflags;
use crate::syscalls::Kernel;
use crate::vfs::{FileHandle, FileType, Metadata, XattrOp};
use crate::GuestMem;
use std::sync::Arc;

const CLONE_NOFOLLOW: u64 = 0x1;
const CLONE_NOOWNERCOPY: u64 = 0x2;
const CLONE_ACL: u64 = 0x4;
const FSOPT_NOFOLLOW: u64 = 0x1;
const CHUNK: usize = 1 << 20;
const XATTR_MAX: usize = 1 << 26;
const NATIVE_XATTR_PREFIX: &str = "user.";

impl Kernel {
    /// `clonefileat(src_dirfd, src, dst_dirfd, dst, flags)`.
    pub(crate) fn darwin_clonefileat(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        let flags = a[4] as u32 as u64;
        if flags & !(CLONE_NOFOLLOW | CLONE_NOOWNERCOPY | CLONE_ACL) != 0 {
            return Err(Errno::EINVAL);
        }
        let found = self.darwin_sb_namei(m, a[0], a[1], flags & CLONE_NOFOLLOW == 0, false)?.found();
        let abs = self.path_io().at_path(m, dirfd(a[0]) as i32, a[1])?;
        let md = if flags & CLONE_NOFOLLOW != 0 { self.vfs.metadata_nofollow(&abs) } else { self.vfs.metadata(&abs) }?;
        let abs = if flags & CLONE_NOFOLLOW != 0 { abs } else { self.vfs.canonical(&abs) };
        self.darwin_clone_internal(m, &abs, None, md, found, a[2], a[3], flags)
    }

    /// `fclonefileat(src_fd, dst_dirfd, dst, flags)`.
    pub(crate) fn darwin_fclonefileat(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        let flags = a[3] as u32 as u64;
        if flags & !(CLONE_NOFOLLOW | CLONE_NOOWNERCOPY | CLONE_ACL) != 0 {
            return Err(Errno::EINVAL);
        }
        let file = self.fds.get(a[0] as i32)?;
        if self.darwin_vnode_of(&file).is_none() {
            return Err(Errno::EOPNOTSUPP);
        }
        if !file.readable {
            return Err(Errno::EBADF);
        }
        let md = file.metadata()?;
        let path = super::vattr::vnode_path(&self.vfs, &file.path, &md);
        let found = self.darwin_sb_fd_vnode(a[0] as i32);
        self.darwin_clone_internal(m, &path, Some(Arc::clone(&file.handle)), md, found, a[1], a[2], flags)
    }

    #[allow(clippy::too_many_arguments)]
    fn darwin_clone_internal(&mut self, m: &GuestMem<'_>, src: &str, handle: Option<Arc<dyn FileHandle>>, md: Metadata, found: Option<super::macvfs::Found>, dst_dirfd: u64, dst: u64, flags: u64) -> Result<u64, Errno> {
        match md.file_type {
            FileType::Regular | FileType::Symlink => {}
            FileType::Directory if src == "/" || super::kern::MOUNTS.iter().any(|mnt| mnt.on == src) => return Err(Errno::EINVAL),
            FileType::Directory => {}
            _ => return Err(Errno::EINVAL),
        }
        if flags & CLONE_ACL != 0 {
            self.darwin_unimplemented("clonefile CLONE_ACL (the filesystems here keep no access control lists)".into());
            return Err(Errno::EINVAL);
        }
        let named = self.darwin_sb_namei(m, dst_dirfd, dst, false, false)?;
        let to = self.path_io().at_path(m, dirfd(dst_dirfd) as i32, dst)?;
        let parent = crate::vfs::parent_of(&to);
        let dir = self.vfs.metadata(&parent)?;
        if dir.file_type != FileType::Directory {
            return Err(Errno::ENOTDIR);
        }
        if self.vfs.metadata_nofollow(&to).is_ok() {
            return Err(Errno::EEXIST);
        }
        if super::kern::mount_of(src).fsid != super::kern::mount_of(&self.vfs.canonical(&parent)).fsid {
            return Err(Errno::EXDEV);
        }
        // clonefile_internal's MAC check of the file and the new name.
        if let (Some(f), super::macvfs::Lookup::Missing { dir, name }) = (&found, &named) {
            let e = self.darwin_mac_check_vnode_clone(f, dir, name);
            if e != 0 {
                return Err(super::errno::errno_of(e as i32));
            }
        }
        // Its authorization: adding to the directory, then reading the
        // file (its data unless a descriptor open for reading names it).
        use super::vauth::kauth;
        let cred = self.dtask.cred.clone();
        let dir_canon = self.vfs.canonical(&parent);
        let dnode = self.darwin_vnode_node(&dir_canon, &dir, None);
        let add = if md.file_type == FileType::Directory { kauth::ADD_SUBDIRECTORY } else { kauth::ADD_FILE };
        self.darwin_authorize(&cred, &dnode, None, add)?;
        let read = kauth::READ_DATA | kauth::READ_ATTRIBUTES | kauth::READ_EXTATTRIBUTES | kauth::READ_SECURITY;
        let read = if handle.is_some() { read & !kauth::READ_DATA } else { read };
        let fnode = self.darwin_vnode_node(src, &md, handle.as_deref());
        self.darwin_authorize(&cred, &fnode, None, read)?;
        // The clone's owner, group, mode and flags: the maker's and the
        // directory's group (vnode_authattr_new), or for root without
        // CLONE_NOOWNERCOPY the file's; the file's mode; its flags, but
        // for the directory's SF_RESTRICTED and UF_DATAVAULT in place of
        // its own.
        let (fo, d) = match (&fnode.attrs, &dnode.attrs) {
            (Ok(f), Ok(d)) => (*f, *d),
            (Err(why), _) | (_, Err(why)) => {
                self.darwin_unimplemented(why.clone());
                return Err(Errno::EIO);
            }
        };
        use super::vattr::flags as vf;
        let keep = vf::UF_DATAVAULT | vf::SF_RESTRICTED;
        let mut root = super::vattr::new_file(cred.uid, &d, fo.mode);
        if flags & CLONE_NOOWNERCOPY == 0 && cred.uid == 0 {
            (root.uid, root.gid) = (fo.uid, fo.gid);
        }
        root.flags = (fo.flags & !keep) | (d.flags & keep);
        let to_canon = format!("{}/{}", dir_canon.trim_end_matches('/'), crate::vfs::basename(&to));
        let done = self.darwin_clone_tree(src, handle, &md, &to).and_then(|()| {
            super::vattr::record(&self.vfs, &to_canon, None, &root).map_err(|why| {
                self.darwin_unimplemented(why);
                Errno::EIO
            })
        });
        if done.is_err() {
            self.darwin_clone_remove(&to);
        }
        done.map(|()| 0)
    }

    /// The record of a directory clone's entry `into`: its source's
    /// attributes, which APFS's clone of the hierarchy keeps (what APFS
    /// does with an entry the maker does not own, when it takes no owner
    /// from the source, is not modelled).
    fn darwin_clone_child_record(&mut self, from: &str, child: &Metadata, into: &str) -> Result<(), Errno> {
        let canon_from = self.vfs.canonical(&crate::vfs::parent_of(from));
        let canon_from = format!("{}/{}", canon_from.trim_end_matches('/'), crate::vfs::basename(from));
        let o = match super::vattr::of(&self.vfs, &canon_from, child, None) {
            Ok(o) => o,
            Err(why) => {
                self.darwin_unimplemented(why);
                return Err(Errno::EIO);
            }
        };
        if o.uid != self.dtask.cred.uid && self.dtask.cred.uid != 0 {
            self.darwin_unimplemented(format!("clonefile of {from}, another user's, in a directory clone (APFS's owner of the clone's entry)"));
            return Err(Errno::EIO);
        }
        let canon_into = self.vfs.canonical(&crate::vfs::parent_of(into));
        let canon_into = format!("{}/{}", canon_into.trim_end_matches('/'), crate::vfs::basename(into));
        super::vattr::record(&self.vfs, &canon_into, None, &o).map_err(|why| {
            self.darwin_unimplemented(why);
            Errno::EIO
        })
    }

    fn darwin_clone_tree(&mut self, src: &str, handle: Option<Arc<dyn FileHandle>>, md: &Metadata, to: &str) -> Result<(), Errno> {
        let times = |secs: i64, ns: u32| Some((secs, ns));
        let atime = times(md.times.atime, md.times.atime_ns);
        let mtime = times(md.mtime, md.times.mtime_ns);
        match md.file_type {
            FileType::Regular => {
                let from = match handle {
                    Some(h) => h,
                    None => self.vfs.open(src, oflags::O_RDONLY, 0)?,
                };
                let out = self.vfs.open(to, oflags::O_WRONLY | oflags::O_CREAT | oflags::O_EXCL, md.mode | 0o200)?;
                let mut buf = vec![0u8; CHUNK];
                let mut at = 0u64;
                loop {
                    let n = from.read_at(at, &mut buf)? as usize;
                    if n == 0 {
                        break;
                    }
                    let mut put = 0;
                    while put < n {
                        put += out.write_at(at + put as u64, &buf[put..n])? as usize;
                    }
                    at += n as u64;
                }
                drop(out);
                self.darwin_clone_xattrs(src, to, true)?;
                self.vfs.chmod(to, md.mode)?;
                self.vfs.set_times(to, atime, mtime, true)
            }
            FileType::Symlink => {
                let target = self.vfs.read_link(src)?;
                self.vfs.symlink(&target, to)?;
                self.vfs.set_times(to, atime, mtime, false)
            }
            FileType::Directory => {
                self.vfs.mkdir(to, md.mode | 0o700)?;
                self.darwin_clone_xattrs(src, to, true)?;
                for e in self.vfs.open(src, oflags::O_RDONLY | oflags::O_DIRECTORY, 0)?.read_dir()? {
                    if e.name == "." || e.name == ".." {
                        continue;
                    }
                    let (from, into) = (format!("{}/{}", src.trim_end_matches('/'), e.name), format!("{}/{}", to.trim_end_matches('/'), e.name));
                    let child = self.vfs.metadata_nofollow(&from)?;
                    self.darwin_clone_tree(&from, None, &child, &into)?;
                    self.darwin_clone_child_record(&from, &child, &into)?;
                }
                self.vfs.chmod(to, md.mode)?;
                self.vfs.set_times(to, atime, None, true)
            }
            _ => Err(Errno::EINVAL),
        }
    }

    /// A clone's extended attributes: those the guest can name (the host's
    /// own bookkeeping stays with the host).
    fn darwin_clone_xattrs(&self, src: &str, to: &str, follow: bool) -> Result<(), Errno> {
        let size = match self.vfs.xattr(src, follow, XattrOp::List { buf: &mut [] }) {
            Ok(n) => n,
            Err(Errno::EOPNOTSUPP) => return Ok(()),
            Err(e) => return Err(e),
        };
        let mut names = vec![0u8; size];
        let n = self.vfs.xattr(src, follow, XattrOp::List { buf: &mut names })?;
        for name in names[..n].split(|&b| b == 0).filter(|b| !b.is_empty()) {
            let name = std::str::from_utf8(name).map_err(|_| Errno::EINVAL)?;
            // (the record of the source's owner, group, mode and flags is
            // no attribute of the guest's: the clone has its own)
            if !name.starts_with(NATIVE_XATTR_PREFIX) || name == super::vattr::RECORD {
                continue;
            }
            let len = self.vfs.xattr(src, follow, XattrOp::Get { name, buf: &mut [] })?;
            if len > XATTR_MAX {
                return Err(Errno::E2BIG);
            }
            let mut value = vec![0u8; len];
            let got = if len == 0 { 0 } else { self.vfs.xattr(src, follow, XattrOp::Get { name, buf: &mut value })? };
            self.vfs.xattr(to, follow, XattrOp::Set { name, value: &value[..got], flags: 0 })?;
        }
        Ok(())
    }

    /// A clone that failed leaves nothing behind.
    fn darwin_clone_remove(&mut self, at: &str) {
        let Ok(md) = self.vfs.metadata_nofollow(at) else { return };
        if md.file_type != FileType::Directory {
            let _ = self.vfs.unlink(at);
            return;
        }
        if let Ok(entries) = self.vfs.open(at, oflags::O_RDONLY | oflags::O_DIRECTORY, 0).and_then(|d| d.read_dir()) {
            for e in entries {
                if e.name != "." && e.name != ".." {
                    self.darwin_clone_remove(&format!("{}/{}", at.trim_end_matches('/'), e.name));
                }
            }
        }
        let _ = self.vfs.rmdir(at);
    }

    /// `exchangedata(path1, path2, options)`: APFS has no VNOP_EXCHANGE, so
    /// what passes the checks is ENOTSUP.
    pub(crate) fn darwin_exchangedata(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        let follow = a[2] & FSOPT_NOFOLLOW == 0;
        let look = |k: &mut Kernel, m: &GuestMem<'_>, p: u64| -> Result<(String, Metadata, Option<super::macvfs::Found>), Errno> {
            let found = k.darwin_sb_namei(m, super::bsd::AT_FDCWD as u64, p, follow, false)?.found();
            let abs = k.path_io().at_path(m, dirfd(super::bsd::AT_FDCWD as u64) as i32, p)?;
            let md = if follow { k.vfs.metadata(&abs) } else { k.vfs.metadata_nofollow(&abs) }?;
            Ok((k.vfs.canonical(&abs), md, found))
        };
        let (p1, md1, f1) = look(self, m, a[0])?;
        let (p2, md2, f2) = look(self, m, a[1])?;
        if md1.ino == md2.ino && super::kern::mount_of(&p1).fsid == super::kern::mount_of(&p2).fsid {
            return Err(Errno::EINVAL);
        }
        if super::kern::mount_of(&p1).fsid != super::kern::mount_of(&p2).fsid {
            return Err(Errno::EXDEV);
        }
        if md1.file_type != FileType::Regular || md2.file_type != FileType::Regular {
            return Err(Errno::EINVAL);
        }
        if let (Some(f1), Some(f2)) = (f1, f2) {
            let e = self.darwin_mac_check_vnode_exchangedata(super::macvfs::sb_vnode(&f1.path, &f1.md), super::macvfs::sb_vnode(&f2.path, &f2.md));
            if e != 0 {
                return Err(super::errno::errno_of(e as i32));
            }
        }
        Err(Errno::EOPNOTSUPP)
    }
}
