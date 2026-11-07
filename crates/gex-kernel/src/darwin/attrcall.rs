//! The calls of the `getattrlist` family: finding the vnode, building its
//! attributes from the namespace, and handing the reply to the caller.
//! The buffer layout is [`super::attrlist`]'s.

use super::attrlist::{self as al, dir, ext, file, fsopt, vol, AttrList, AttrSet, Reply, VolCaps, VolInfo, Vn};
use super::bsd::dirfd;
use super::kern::{mount_of, vfsstat, Mount, MOUNTS};
use crate::errno::Errno;
use crate::syscalls::{Kernel, PathIo};
use crate::vfs::{FileType, Metadata};
use crate::GuestMem;

/// `VT_APFS`: `v_tag` of an APFS vnode.
const VT_APFS: u32 = 25;

/// `ATTR_CMN_SCRIPT` of a vnode whose filesystem names none
/// (`kTextEncodingMacUnicode`).
const ENCODING: u32 = 0x7e;

/// `va_write_gencount` of a file nobody has written to since the volume
/// was made. Measured on a Mac's APFS (macOS 27.0.1, 26A434) for files
/// and directories of a sealed system volume.
const GEN_COUNT: u32 = 1;

/// `va_dataprotect_class` of files on the system volume. Measured on the
/// same Mac's APFS (class C).
const DATAPROTECT: u32 = 3;

/// `va_iosize` APFS gives a file or directory. Measured.
const VNODE_IOSIZE: u32 = 4096;

/// `f_fssubtype`. Measured on the same volume.
pub const APFS_FSSUBTYPE: u32 = 1;

/// The volume capabilities an APFS volume reports
/// (`ATTR_VOL_CAPABILITIES` before XNU adds its own), measured on a Mac's
/// APFS and cut to the bits `sys/attr.h` of this kernel defines (the
/// newer release's APFS sets two more interface bits, which an iPadOS 17
/// kernel does not name).
pub const APFS_CAPS: VolCaps = VolCaps { capabilities: [0x039b_6edf, 0x00ad_6fc7, 0, 0], valid: [0x07ff_ffff, 0x007f_ffff, 0, 0] };

/// `f_attributes` of APFS, measured: what a volume can return
/// (`validattr`) and what it keeps itself (`nativeattr`), cut to this
/// kernel's masks, and without the attributes this kernel has no value
/// for.
pub fn apfs_attributes() -> [AttrSet; 2] {
    let cut = |a: AttrSet| AttrSet {
        common: a.common,
        vol: a.vol & vol::VALIDMASK & !VOL_UNSUPPORTED,
        dir: a.dir & dir::VALIDMASK,
        file: a.file & file::VALIDMASK,
        fork: a.fork & ext::VALIDMASK & !ext::PRIVATESIZE,
    };
    [
        cut(AttrSet { common: 0xffff_ffff, vol: 0x709f_ffff, dir: 0x7, file: 0x362f, fork: 0x1ffc }),
        cut(AttrSet { common: 0x3eff_feff, vol: 0x7086_fffd, dir: 0x7, file: 0x062f, fork: 0x1ffc }),
    ]
}

/// What the volume has no value for: the object counts (nothing here
/// counts the files of a root image) and its label (the image does not
/// carry one).
const VOL_UNSUPPORTED: u32 = vol::OBJCOUNT | vol::FILECOUNT | vol::DIRCOUNT | vol::NAME;

/// Darwin's `makedev` from Linux's encoding of a device number.
fn darwin_dev(linux: u64) -> u32 {
    let major = ((linux >> 8) & 0xfff) | ((linux >> 32) & !0xfff);
    let minor = (linux & 0xff) | ((linux >> 12) & !0xff);
    ((major as u32) << 24) | (minor as u32 & 0x00ff_ffff)
}

/// `W_OK | R_OK | X_OK` for a caller who owns the file (every file here is
/// the process's own, as `stat` says), who is `root` or not, on a mount
/// that is read-only or not.
fn user_access(mode: u32, is_dir: bool, root: bool, rdonly: bool) -> u32 {
    let owner = (mode >> 6) & 7;
    let (r, mut w, x) = if root { (true, true, is_dir || mode & 0o111 != 0) } else { (owner & 4 != 0, owner & 2 != 0, owner & 1 != 0) };
    if rdonly {
        w = false;
    }
    u32::from(w) * 2 | u32::from(r) * 4 | u32::from(x)
}

fn vtype_of(t: FileType) -> u32 {
    use al::vtype::*;
    match t {
        FileType::Regular => VREG,
        FileType::Directory => VDIR,
        FileType::CharDevice => VCHR,
        FileType::Symlink => VLNK,
        FileType::Socket => VSOCK,
        FileType::Fifo => VFIFO,
    }
}

fn roundup(n: u64, to: u64) -> u64 {
    n.div_ceil(to) * to
}

/// A path's last component.
fn last(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or("")
}

/// The vnode at `path` (absolute, with every link on it followed) as the
/// attribute code sees it.
fn vnode(pio: &PathIo<'_>, path: &str, md: &Metadata, name: Option<&str>, want_children: bool) -> Result<Vn, Errno> {
    let mnt: &Mount = mount_of(path);
    let st = Kernel::stat_from(md);
    let is_dir = md.file_type == FileType::Directory;
    let is_root = path == mnt.on;
    let parentid = if path == "/" {
        md.ino
    } else {
        let parent = crate::vfs::parent_of(path);
        pio.ns.metadata(&parent).map(|p| p.ino).unwrap_or(md.ino)
    };
    let nchildren = if is_dir && want_children {
        let h = pio.ns.open(path, crate::fs::oflags::O_RDONLY, 0)?;
        h.read_dir()?.iter().filter(|e| e.name != "." && e.name != "..").count() as u32
    } else {
        0
    };
    let name = match name {
        Some(n) => n.to_string(),
        // A root is named for its mount point; the root of the root has no
        // name of its own to give but its path.
        None if is_root && mnt.on != "/" => last(mnt.on).to_string(),
        None if path == "/" => "/".to_string(),
        None => last(path).to_string(),
    };
    let relpath = if mnt.on == "/" {
        path.to_string()
    } else {
        match path.strip_prefix(mnt.on) {
            Some("") | None => "/".to_string(),
            Some(r) => r.to_string(),
        }
    };
    let t = |s: i64, ns: u32| (s, i64::from(ns));
    let birth = t(st.mtime, st.mtime_ns);
    let rdonly = mnt.flags & 0x1 != 0;
    let (data_alloc, rdev) = match md.file_type {
        FileType::Regular => (roundup(md.size, u64::from(vfsstat::BSIZE)), 0),
        FileType::CharDevice => (0, darwin_dev(st.rdev)),
        _ => (0, 0),
    };
    Ok(Vn {
        vtype: vtype_of(md.file_type),
        tag: VT_APFS,
        name,
        path: path.to_string(),
        relpath,
        fsid: (mnt.fsid as u32, vfsstat::APFS_TYPENUM),
        is_mount_point: MOUNTS.iter().any(|m| m.on == path),
        fileid: md.ino,
        parentid,
        mode: md.mode & 0o7777,
        uid: pio.creds.uid(),
        gid: pio.creds.gid(),
        flags: 0,
        nlink: md.nlink.max(1),
        nchildren,
        // Nothing here keeps a creation or added time: both are the
        // modification time, as `stat` has the birth time.
        crtime: birth,
        modtime: t(st.mtime, st.mtime_ns),
        chgtime: t(st.ctime, st.ctime_ns),
        acctime: t(st.atime, st.atime_ns),
        bkuptime: (0, 0),
        addedtime: birth,
        data_size: md.size,
        data_alloc,
        rdev,
        iosize: VNODE_IOSIZE,
        user_access: user_access(md.mode, is_dir, pio.creds.uid() == 0, rdonly),
        finderinfo: None,
        encoding: ENCODING,
        gen_count: GEN_COUNT,
        document_id: 0,
        dataprotect: DATAPROTECT,
        unsupported: AttrSet { fork: ext::PRIVATESIZE, ..Default::default() },
        missing: Vec::new(),
    })
}

/// The volume's UUID. The root image keeps none, so each volume is given a
/// stable one of its own, made from where it is mounted and from what
/// (a name-based UUID, version 8 for the vendor-defined layout: FNV-1a over
/// the two names, twice with different seeds).
fn volume_uuid(mnt: &Mount) -> [u8; 16] {
    let hash = |seed: u64| {
        let mut h = 0xcbf2_9ce4_8422_2325u64 ^ seed;
        for b in mnt.on.bytes().chain([0]).chain(mnt.from.bytes()) {
            h = (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3);
        }
        h
    };
    let mut u = [0u8; 16];
    u[..8].copy_from_slice(&hash(0).to_be_bytes());
    u[8..].copy_from_slice(&hash(0x9e37_79b9_7f4a_7c15).to_be_bytes());
    u[6] = (u[6] & 0x0f) | 0x80;
    u[8] = (u[8] & 0x3f) | 0x80;
    u
}

/// The volume `mnt` as `getvolattrlist` has it.
fn volume(pio: &PathIo<'_>, mnt: &Mount) -> Result<VolInfo, Errno> {
    let md = pio.ns.metadata(mnt.on)?;
    let root = vnode(pio, mnt.on, &md, None, false)?;
    Ok(VolInfo {
        typenum: vfsstat::APFS_TYPENUM,
        typename: "apfs".into(),
        mntonname: mnt.on.into(),
        mntfromname: mnt.from.into(),
        mnt_flag: mnt.flags,
        bsize: vfsstat::BSIZE,
        iosize: vfsstat::IOSIZE,
        blocks: vfsstat::BLOCKS,
        bfree: vfsstat::BFREE,
        bavail: vfsstat::BAVAIL,
        fssubtype: APFS_FSSUBTYPE,
        caps: APFS_CAPS,
        attributes: apfs_attributes(),
        uuid: volume_uuid(mnt),
        // `f_maxobjcount`, as APFS says it: no limit.
        max_objcount: u32::MAX,
        quota: 0,
        reserved: 0,
        // The volume's times are its root directory's.
        create_time: root.crtime,
        modify_time: root.modtime,
        access_time: root.acctime,
        backup_time: (0, 0),
        unsupported: AttrSet { vol: VOL_UNSUPPORTED, ..Default::default() },
        root,
    })
}

/// What was asked of a volume that this kernel has no value for.
fn volume_missing(alist: &AttrList) -> Vec<String> {
    const NAMES: [(u32, &str); 4] = [
        (vol::OBJCOUNT, "ATTR_VOL_OBJCOUNT: the files of the root image are not counted"),
        (vol::FILECOUNT, "ATTR_VOL_FILECOUNT: the files of the root image are not counted"),
        (vol::DIRCOUNT, "ATTR_VOL_DIRCOUNT: the directories of the root image are not counted"),
        (vol::NAME, "ATTR_VOL_NAME: the root volume's label is not recorded"),
    ];
    NAMES.iter().filter(|(b, _)| alist.set.vol & b != 0).map(|(_, n)| format!("getattrlist {n}")).collect()
}

/// `ATTR_CMNEXT_PRIVATESIZE` has no value here either.
fn vnode_missing(alist: &AttrList, options: u64) -> Vec<String> {
    if options & fsopt::ATTR_CMN_EXTENDED != 0 && alist.set.fork & ext::PRIVATESIZE != 0 {
        vec!["getattrlist ATTR_CMNEXT_PRIVATESIZE: the space a file alone holds is not known".into()]
    } else {
        Vec::new()
    }
}

/// `NAMEI_NOFOLLOW_ANY`: a link the lookup would traverse is `ELOOP` (its
/// loop count starts at MAXSYMLINKS): one in any component before the
/// last, and the last when it is followed (`follow_last`, or a trailing
/// slash).
pub(crate) fn no_link_on_the_way(pio: &PathIo<'_>, abs_of_base: &str, rel: &str, follow_last: bool) -> Result<(), Errno> {
    let mut cur = abs_of_base.to_string();
    let comps: Vec<&str> = rel.split('/').filter(|c| !c.is_empty()).collect();
    let follow_last = follow_last || rel.ends_with('/');
    for (i, comp) in comps.iter().enumerate() {
        match *comp {
            "." => continue,
            ".." => cur = crate::vfs::parent_of(&cur),
            c => {
                cur = format!("{}/{}", cur.trim_end_matches('/'), c);
                if (i + 1 < comps.len() || follow_last) && pio.ns.metadata_nofollow(&cur)?.file_type == FileType::Symlink {
                    return Err(Errno::ELOOP);
                }
            }
        }
    }
    Ok(())
}

fn read_alist(m: &GuestMem<'_>, addr: u64) -> Result<AttrList, Errno> {
    Ok(AttrList::parse(m.read(addr, AttrList::SIZE)?))
}

/// The reply handed back through the caller's buffer.
fn deliver(m: &mut GuestMem<'_>, buf: u64, r: &Reply) -> Result<u64, Errno> {
    m.write(buf, &r.bytes[..r.copy])?;
    Ok(0)
}

impl Kernel {
    /// `getattrlist(path, alist, attributeBuffer, bufferSize, options)`.
    pub(crate) fn darwin_getattrlist(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        self.attrlist_path(m, -100, a[0], a[1], a[2], a[3], a[4])
    }

    /// `getattrlistat(fd, path, alist, attributeBuffer, bufferSize, options)`.
    pub(crate) fn darwin_getattrlistat(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        self.attrlist_path(m, dirfd(a[0]) as i32 as i64, a[1], a[2], a[3], a[4], a[5])
    }

    #[allow(clippy::too_many_arguments)]
    fn attrlist_path(&mut self, m: &mut GuestMem<'_>, dir: i64, path: u64, alist: u64, buf: u64, size: u64, options: u64) -> Result<u64, Errno> {
        // The attribute list is read before the path is looked up.
        let alist = read_alist(m, alist)?;
        let (result, missing) = {
            let pio = self.path_io();
            let raw = m.read_cstr(path, 4096)?;
            if self.trace {
                eprintln!("[gex:{}] getattrlist {:?} {:x?} options {options:#x} size {size}", self.pid, String::from_utf8_lossy(&raw), alist.set);
            }
            if raw.len() >= al::MAXPATHLEN {
                return Err(Errno::ENAMETOOLONG);
            }
            let given = std::str::from_utf8(&raw).map_err(|_| Errno::EINVAL)?;
            let abs = pio.at_path_str(dir as i32, given)?;
            if options & fsopt::NOFOLLOW_ANY != 0 {
                let base = if given.starts_with('/') { "/".to_string() } else { pio.at_path_str(dir as i32, ".")? };
                no_link_on_the_way(&pio, &base, given, false)?;
            }
            let nofollow = options & (fsopt::NOFOLLOW | fsopt::NOFOLLOW_ANY) != 0;
            let md = if nofollow { pio.ns.metadata_nofollow(&abs)? } else { pio.ns.metadata(&abs)? };
            let resolved = if nofollow {
                let parent = crate::vfs::parent_of(&abs);
                let name = crate::vfs::basename(&abs);
                if abs == "/" {
                    abs.clone()
                } else {
                    format!("{}/{}", pio.ns.canonical(&parent).trim_end_matches('/'), name)
                }
            } else {
                pio.ns.canonical(&abs)
            };
            self.attrlist_vnode(&pio, &resolved, &md, None, &alist, size as usize, options)
        };
        for what in missing {
            self.darwin_unimplemented(what);
        }
        deliver(m, buf, &result?)?;
        Ok(0)
    }

    /// `fgetattrlist(fd, alist, attributeBuffer, bufferSize, options)`.
    pub(crate) fn darwin_fgetattrlist(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        let fd = a[0] as i32;
        let (result, missing) = {
            let pio = self.path_io();
            let f = pio.map.fds.get(fd)?;
            // A descriptor that is not a vnode (a pipe, a socket, a kqueue)
            // is not one this works on.
            if !f.path.starts_with('/') {
                return Err(Errno::EINVAL);
            }
            let alist = read_alist(m, a[1])?;
            let md = f.metadata()?;
            let path = f.dir_path()?.unwrap_or_else(|| f.path.clone());
            self.attrlist_vnode(&pio, &path, &md, None, &alist, a[3] as usize, a[4])
        };
        for what in missing {
            self.darwin_unimplemented(what);
        }
        deliver(m, a[2], &result?)?;
        Ok(0)
    }

    /// `getattrlist_internal` and the volume form it hands over to.
    #[allow(clippy::too_many_arguments)]
    fn attrlist_vnode(&self, pio: &PathIo<'_>, path: &str, md: &Metadata, name: Option<&str>, alist: &AttrList, size: usize, options: u64) -> (Result<Reply, Errno>, Vec<String>) {
        let use_fork = options & fsopt::ATTR_CMN_EXTENDED != 0;
        let mut missing = Vec::new();
        if alist.bitmapcount == al::BIT_MAP_COUNT && size >= 4 && alist.set.vol != 0 {
            // Volume attributes are for the volume alone.
            if alist.set.file != 0 || alist.set.dir != 0 || (alist.set.fork != 0 && !use_fork) {
                return (Err(Errno::EINVAL), missing);
            }
            let r = volume(pio, mount_of(path)).and_then(|vi| {
                missing = volume_missing(alist);
                al::getvolattrlist(alist, size, options, &vi)
            });
            return (r, missing);
        }
        let want_children = alist.set.dir & dir::ENTRYCOUNT != 0;
        let r = vnode(pio, path, md, name, want_children).and_then(|vn| {
            missing = vnode_missing(alist, options);
            al::getattrlist(alist, size, options, &vn)
        });
        (r, missing)
    }

    /// `getattrlistbulk(dirfd, alist, attributeBuffer, bufferSize, options)`:
    /// the entries of a directory with their attributes, one call's worth
    /// at a time, resuming where the last stopped. Each entry is looked up
    /// and answered as `getattrlist` would, which is how a filesystem with
    /// no listing of its own (`readdirattr`) is served.
    pub(crate) fn darwin_getattrlistbulk(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        let fd = a[0] as i32;
        let buf = a[2];
        let size = a[3] as usize;
        let mut options = a[4];
        let mut notes: Vec<String> = Vec::new();
        let mut run = || -> Result<(Vec<u8>, u64), Errno> {
            let pio = self.path_io();
            let f = pio.map.fds.get(fd)?;
            if !f.path.starts_with('/') {
                return Err(Errno::EOPNOTSUPP);
            }
            if !f.readable {
                return Err(Errno::EBADF);
            }
            let dpath = f.dir_path()?.unwrap_or_else(|| f.path.clone());
            if options & fsopt::LIST_SNAPSHOT != 0 {
                if dpath != mount_of(&dpath).on {
                    return Err(Errno::EINVAL);
                }
                notes.push("getattrlistbulk FSOPT_LIST_SNAPSHOT: APFS snapshots are not kept".into());
                return Err(Errno::EOPNOTSUPP);
            }
            if f.metadata()?.file_type != FileType::Directory {
                return Err(Errno::ENOTDIR);
            }
            options |= fsopt::ATTR_CMN_EXTENDED;
            let alist = read_alist(m, a[1])?;
            if alist.set.vol != 0 || alist.set.common & al::BULK_REQUIRED != al::BULK_REQUIRED {
                return Err(Errno::EINVAL);
            }
            if size == 0 {
                // Nothing to put an entry in, and no end reached.
                return Err(Errno::ERANGE);
            }
            let mut out: Vec<u8> = Vec::new();
            let mut count = 0u64;
            let mut eof = false;
            let kern_size = size.min(al::ATTR_MAX_BUFFER);
            let mut resid = size;
            // `uio_resid` is not the room left in `out` once an entry has
            // been counted past what was copied: the two are kept apart.
            while resid > 32 {
                let Some(ent) = f.dir_entry(f.dir_cursor())? else {
                    eof = true;
                    break;
                };
                // ".", ".." and an entry with no inode or name.
                if ent.ino == 0 || ent.name.is_empty() || ent.name == "." || ent.name == ".." {
                    f.set_dir_cursor(f.dir_cursor() + 1);
                    continue;
                }
                let child = format!("{}/{}", dpath.trim_end_matches('/'), ent.name);
                // The entry may be gone by the time it is looked up: skipped.
                let Ok(cmd) = pio.ns.metadata_nofollow(&child) else {
                    f.set_dir_cursor(f.dir_cursor() + 1);
                    continue;
                };
                let isdir = cmd.file_type == FileType::Directory;
                let (r, missing) = self.attrlist_vnode(&pio, &child, &cmd, Some(&ent.name), &alist, kern_size, options | fsopt::REPORT_FULLSIZE);
                notes.extend(missing);
                let mut entry: Vec<u8> = match r {
                    Ok(r) => r.bytes[..r.copy].to_vec(),
                    Err(e) => al::error_entry(&alist.set, options, super::errno::to_darwin(e.0) as u32, &ent.name, isdir, kern_size),
                };
                entry.resize(kern_size.max(entry.len()), 0);
                let mut entlen = u32::from_le_bytes(entry[..4].try_into().unwrap()) as usize;
                let bytes_left = resid;
                if entlen == 0 || entlen > bytes_left {
                    break;
                }
                let pad = ((entlen + 7) & !7) - entlen;
                let mut new_resid = 0;
                if pad != 0 && entlen + pad <= bytes_left {
                    if entlen + pad <= kern_size {
                        entry[entlen..entlen + pad].fill(0);
                    } else {
                        entry[entlen..kern_size].fill(0);
                        new_resid = bytes_left - (entlen + pad);
                    }
                    entlen += pad;
                }
                entry[..4].copy_from_slice(&(entlen as u32).to_le_bytes());
                let moved = entlen.min(kern_size);
                out.extend_from_slice(&entry[..moved]);
                resid -= moved;
                if new_resid != 0 {
                    resid = new_resid;
                }
                count += 1;
                f.set_dir_cursor(f.dir_cursor() + 1);
            }
            if count == 0 && !eof {
                Err(Errno::ERANGE)
            } else {
                Ok((out, count))
            }
        };
        let result = run();
        for what in notes {
            self.darwin_unimplemented(what);
        }
        let (out, count) = result?;
        m.write(buf, &out)?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_numbers_become_darwins() {
        // Linux's /dev/null is 1:3
        assert_eq!(darwin_dev(0x103), 0x0100_0003);
        // major 136 minor 300: the minor's high bits sit above bit 8
        assert_eq!(darwin_dev((136 << 8) | (300 & 0xff) | ((300 >> 8) << 20)), (136 << 24) | 300);
    }

    #[test]
    fn access_follows_the_owner_and_the_mount() {
        assert_eq!(user_access(0o755, false, false, false), 7);
        assert_eq!(user_access(0o555, false, false, false), 5);
        assert_eq!(user_access(0o755, false, false, true), 5);
        assert_eq!(user_access(0o644, false, true, false), 6);
        assert_eq!(user_access(0o644, true, true, false), 7);
        assert_eq!(user_access(0o000, false, false, false), 0);
    }

    #[test]
    fn the_volume_attributes_are_cut_to_what_the_kernel_names_and_has() {
        let [valid, native] = apfs_attributes();
        assert_eq!(valid.vol & !vol::VALIDMASK, 0);
        assert_eq!(valid.vol & VOL_UNSUPPORTED, 0);
        assert_eq!(valid.fork & ext::PRIVATESIZE, 0);
        assert_eq!(native.file, 0x62f);
        assert_eq!(APFS_CAPS.valid[1] & !0x007f_ffff, 0);
    }

    #[test]
    fn a_volume_request_counts_what_has_no_value() {
        let a = AttrList { bitmapcount: 5, reserved: 0, set: AttrSet { vol: vol::NAME | vol::FSTYPE | vol::UUID, ..Default::default() } };
        assert_eq!(volume_missing(&a).len(), 1);
    }
}
