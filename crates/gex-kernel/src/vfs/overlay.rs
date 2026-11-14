//! A directory tree laid over the root filesystem as part of it: `gexc run
//! --overlay`. What the overlay holds is the root volume's own: it is one
//! filesystem (one mount, so one device, one `statfs`, nothing new in the
//! mount table), each of the overlay's files has an inode number of that
//! filesystem, and its directories' listings are merged with the root's.
//!
//! The layout is Linux overlayfs's in its `user.overlay.` form
//! (Documentation/filesystems/overlayfs.rst, "userxattr"). A directory of
//! the overlay merges with the root's directory of the same name, and its
//! entries shadow the root's of the same names. A directory whose
//! `user.overlay.opaque` is `y` is opaque: the root's directory of that
//! name is hidden entirely, not merged. The other `user.overlay.`
//! attributes (whiteouts, redirects, metacopy) are not implemented, and an
//! overlay holding one is refused, as is one holding a device, a FIFO or a
//! socket (a system volume has none).
//!
//! The overlay is a system volume's, which is read-only: a call that would
//! change what it holds fails with EROFS, as XNU's lookup fails a create,
//! delete or rename on a read-only mount. The root's own files, and the
//! root's directories that the overlay merges with, answer as the root
//! does.
//!
//! An overlay file that shadows a root file replaces it in kind: it has
//! that file's type, mode and extended attributes, and an overlay that
//! does not is refused. What the root has nothing at is the overlay's own,
//! and is reported when the overlay is read: its modes are the overlay's.
//! Owners and flags are not the overlay's to say: they are the root
//! volume's, answered for every file alike above this layer.

use super::{walk_links, within_any, DirEntry, FileHandle, FileSystem, FileType, Metadata, Moved, Walked, XattrOp};
use crate::errno::{Errno, SysResult};
use crate::fs::oflags;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

/// The first of the inode numbers the overlay gives its own files, and how
/// many there are: the top 2^16 of APFS's 60-bit object id space
/// (`OBJ_ID_MASK`), which a volume's ids never reach. They are handed out
/// in order, from `MIN_USER_INO_NUM` (16) up, or on a sealed system volume
/// from 2^60 - 2^32 + 16 up (the IPSW's manifest numbers the 21H461 system
/// volume's files so), and either would need billions of files to get
/// here. A root file numbered in this range fails its call with EIO, said
/// on stderr: the overlay's numbers would not be its own.
pub const OWN_INO_FIRST: u64 = 0x0fff_ffff_ffff_0000;
const OWN_INO_SLOTS: u64 = 0x1_0000;

/// The extended attribute that makes an overlay directory opaque, and the
/// prefix of the overlay's own attributes, which no guest sees.
const OPAQUE: &str = "user.overlay.opaque";
const MARKS: &str = "user.overlay.";

/// The root filesystem with an overlay over it.
pub struct OverlayFs {
    lower: Arc<dyn FileSystem>,
    upper: Arc<dyn FileSystem>,
    ix: Arc<Index>,
}

/// What the overlay holds, read when it is laid: the tree is the
/// overlay's from then on (a file added to the overlay's directory later
/// is not seen; one removed fails as the directory says).
struct Index {
    entries: BTreeMap<String, Entry>,
    /// The overlay's own files by inode number.
    by_ino: HashMap<u64, String>,
    /// Each entry that is not a merged directory but is in one, absolute,
    /// NUL-separated: where a walk of the root's names must stop, for this
    /// filesystem to go on with its own ([`OverlayFs::walk`]).
    stops: String,
    /// The order the root lists a directory in, when it is APFS's.
    order: Option<Order>,
}

struct Entry {
    file_type: FileType,
    kind: Kind,
    /// A directory's entries' names.
    children: Vec<String>,
}

enum Kind {
    /// A directory over the root's own: the root's, with the overlay's
    /// entries in it, its link count and size grown by them.
    Merged { nlink: i64, size: i64 },
    /// The overlay's own, with its inode number.
    Own { ino: u64 },
}

impl Entry {
    fn own_ino(&self) -> Option<u64> {
        match self.kind {
            Kind::Own { ino } => Some(ino),
            Kind::Merged { .. } => None,
        }
    }
}

/// Where a path is.
enum Place<'a> {
    /// The root's: nothing of the overlay's at it or above it but merged
    /// directories.
    Lower,
    /// An entry of the overlay.
    Entry(&'a Entry),
    /// Under a directory of the overlay's own, which has nothing of that
    /// name: the root's of that name, if any, is hidden.
    Missing,
    /// Under an overlay file.
    NotDir,
}

/// `parent/name`, relative.
fn join(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}/{name}")
    }
}

fn kind_name(t: FileType) -> &'static str {
    match t {
        FileType::Regular => "file",
        FileType::Directory => "directory",
        FileType::Symlink => "symbolic link",
        FileType::CharDevice => "device",
        FileType::Fifo => "FIFO",
        FileType::Socket => "socket",
    }
}

/// FNV-1a, 64 bits: where an own file's inode number is first sought.
fn fnv(s: &str) -> u64 {
    s.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3))
}

/// The order of an APFS directory's entries, which is its B-tree's order
/// of their hashed records (`j_drec_hashed_key_t`): by the name's 22-bit
/// hash, then its length with its NUL (`name_len_and_hash`), then the
/// name. The hash is CRC-32C, without its final inversion, of the name's
/// code points as UTF-32 after normalization (NFD), and after case folding
/// on a case-insensitive volume. A Mac's APFS lists its directories so
/// (measured: macOS 27.0, of the IPSW's root as extracted onto a
/// case-insensitive volume).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Order {
    pub case_insensitive: bool,
}

impl Order {
    /// A name's key, for an ASCII name (its normalization is itself and
    /// its case folding ASCII's); `None` for another, whose place would
    /// need Unicode's normalization and folding tables.
    pub fn key(self, name: &str) -> Option<(u32, usize, Vec<u8>)> {
        if !name.is_ascii() {
            return None;
        }
        let mut crc = !0u32;
        for c in name.bytes() {
            let c = if self.case_insensitive { c.to_ascii_lowercase() } else { c };
            for b in u32::from(c).to_le_bytes() {
                crc ^= u32::from(b);
                for _ in 0..8 {
                    crc = if crc & 1 != 0 { (crc >> 1) ^ 0x82f6_3b78 } else { crc >> 1 };
                }
            }
        }
        Some((crc & 0x3f_ffff, name.len() + 1, name.as_bytes().to_vec()))
    }

    /// Whether `names` are in this order.
    pub fn holds(self, names: &[&str]) -> bool {
        let mut prev = None;
        for n in names {
            let Some(k) = self.key(n) else { return false };
            if prev.as_ref().is_some_and(|p| *p > k) {
                return false;
            }
            prev = Some(k);
        }
        true
    }

    /// The order a directory listing `names` (without `.` and `..`) is
    /// in, of the two: `None` when it is in neither, or in both with no
    /// name to tell them apart.
    pub fn of(names: &[&str]) -> Option<Order> {
        let (fold, exact) = (Order { case_insensitive: true }, Order { case_insensitive: false });
        match (fold.holds(names), exact.holds(names)) {
            (true, false) => Some(fold),
            (false, true) => Some(exact),
            _ => None,
        }
    }
}

/// A listing's names, without `.` and `..`.
fn names_of(list: &[DirEntry]) -> Vec<&str> {
    list.iter().map(|e| e.name.as_str()).filter(|n| *n != "." && *n != "..").collect()
}

/// A filesystem's listing of `dir`.
fn list(fs: &dyn FileSystem, dir: &str) -> Result<Vec<DirEntry>, Errno> {
    fs.open(dir, oflags::O_RDONLY, 0)?.read_dir()
}

/// The extended attributes a guest sees on `path` of `fs` (the `user.`
/// ones but the overlay's own marks), with their values, by name. None
/// for a filesystem that keeps none.
fn visible_xattrs(fs: &dyn FileSystem, path: &str) -> Result<Vec<(String, Vec<u8>)>, Errno> {
    let size = match fs.xattr(path, XattrOp::List { buf: &mut [] }) {
        Err(Errno::EOPNOTSUPP) => return Ok(Vec::new()),
        r => r?,
    };
    let mut raw = vec![0u8; size];
    let n = fs.xattr(path, XattrOp::List { buf: &mut raw })?;
    let mut out = Vec::new();
    for name in raw[..n].split(|&c| c == 0).filter(|s| !s.is_empty()) {
        let name = String::from_utf8_lossy(name).into_owned();
        if !name.starts_with("user.") || name.starts_with(MARKS) {
            continue;
        }
        let len = fs.xattr(path, XattrOp::Get { name: &name, buf: &mut [] })?;
        let mut v = vec![0u8; len];
        let got = fs.xattr(path, XattrOp::Get { name: &name, buf: &mut v })?;
        v.truncate(got);
        out.push((name, v));
    }
    out.sort();
    Ok(out)
}

/// Whether the overlay's `path` is an opaque directory, its other marks
/// refused.
fn opaque(upper: &dyn FileSystem, path: &str) -> Result<bool, String> {
    let shown = format!("/{path}");
    let size = match upper.xattr(path, XattrOp::List { buf: &mut [] }) {
        Err(Errno::EOPNOTSUPP) => return Ok(false),
        r => r.map_err(|e| format!("{shown}: listing its extended attributes: errno {}", e.0))?,
    };
    let mut raw = vec![0u8; size];
    let n = upper.xattr(path, XattrOp::List { buf: &mut raw }).map_err(|e| format!("{shown}: errno {}", e.0))?;
    let mut is = false;
    for name in raw[..n].split(|&c| c == 0).filter(|s| !s.is_empty()) {
        let name = String::from_utf8_lossy(name);
        if name == OPAQUE {
            let mut v = [0u8; 2];
            let got = upper.xattr(path, XattrOp::Get { name: OPAQUE, buf: &mut v }).map_err(|e| format!("{shown}: {OPAQUE}: errno {}", e.0))?;
            if &v[..got] != b"y" {
                return Err(format!("{shown}: {OPAQUE} is {:?}, not \"y\"", String::from_utf8_lossy(&v[..got])));
            }
            is = true;
        } else if name.starts_with(MARKS) {
            return Err(format!("{shown}: {name}: overlayfs's whiteouts, redirects and metacopy are not implemented"));
        }
    }
    Ok(is)
}

/// `new` entries added to listing `out`: each where `order` puts it, when
/// `out` is in that order; after the rest when it is not (a listing in
/// another order says nothing of where a name goes).
fn put_in_order(out: &mut Vec<DirEntry>, new: Vec<DirEntry>, order: Option<Order>) {
    let ordered = order.filter(|o| o.holds(&names_of(out)));
    match ordered {
        Some(o) => {
            for e in new {
                let k = o.key(&e.name);
                let at = out.iter().position(|x| x.name != "." && x.name != ".." && o.key(&x.name) > k).unwrap_or(out.len());
                out.insert(at, e);
            }
        }
        None => out.extend(new),
    }
}

impl OverlayFs {
    /// Lay `upper`'s tree over `lower`, the root. What was found to report
    /// comes back with it: what the root has nothing at, which is the
    /// overlay's own.
    pub fn new(lower: Arc<dyn FileSystem>, upper: Arc<dyn FileSystem>) -> Result<(OverlayFs, Vec<String>), String> {
        let err = |p: &str, what: &str, e: Errno| format!("/{p}: {what}: errno {}", e.0);
        let root = upper.metadata_nofollow("").map_err(|e| err("", "the overlay's root", e))?;
        if root.file_type != FileType::Directory {
            return Err("the overlay is not a directory".into());
        }
        if opaque(&*upper, "")? {
            return Err("the overlay's root is opaque: it would hide the whole root".into());
        }
        let lower_root = list(&*lower, "").map_err(|e| err("", "listing the root", e))?;
        let order = Order::of(&names_of(&lower_root));
        let mut notes = Vec::new();
        // Each entry, found top down; what is under a directory found
        // after it. The root's file at each path, when its directories
        // are the root's own (no link among them): its type.
        struct Found {
            md: Metadata,
            real: Option<FileType>,
            merged: bool,
        }
        let mut found: BTreeMap<String, Found> = BTreeMap::new();
        let mut children: BTreeMap<String, Vec<String>> = BTreeMap::new();
        found.insert(String::new(), Found { md: root, real: Some(FileType::Directory), merged: true });
        let mut todo = vec![String::new()];
        while let Some(dir) = todo.pop() {
            let (dir_merged, dir_real) = {
                let d = &found[&dir];
                (d.merged, d.real == Some(FileType::Directory))
            };
            let mut names: Vec<String> = names_of(&list(&*upper, &dir).map_err(|e| err(&dir, "listing it", e))?).into_iter().map(str::to_string).collect();
            names.sort();
            for name in &names {
                let p = join(&dir, name);
                if order.is_some() && !name.is_ascii() {
                    return Err(format!("/{p}: its place in an APFS directory's order needs Unicode normalization and case folding, which are not implemented (ASCII names only)"));
                }
                let md = upper.metadata_nofollow(&p).map_err(|e| err(&p, "its attributes", e))?;
                if !matches!(md.file_type, FileType::Regular | FileType::Directory | FileType::Symlink) {
                    return Err(format!("/{p}: a {} (a system volume holds files, directories and symbolic links)", kind_name(md.file_type)));
                }
                let op = opaque(&*upper, &p)?;
                if op && md.file_type != FileType::Directory {
                    return Err(format!("/{p}: {OPAQUE} on a {}", kind_name(md.file_type)));
                }
                let real = if dir_real {
                    match lower.metadata_nofollow(&p) {
                        Ok(r) => Some(r),
                        Err(Errno::ENOENT) | Err(Errno::ENOTDIR) => None,
                        Err(e) => return Err(err(&p, "the root's file there", e)),
                    }
                } else {
                    None
                };
                let merged = dir_merged && !op && md.file_type == FileType::Directory && real.as_ref().is_some_and(|r| r.file_type == FileType::Directory);
                match &real {
                    Some(r) if r.file_type != md.file_type => {
                        return Err(format!("/{p}: a {} in place of the root's {}", kind_name(md.file_type), kind_name(r.file_type)));
                    }
                    Some(r) if !merged => {
                        if md.mode & 0o7777 != r.mode & 0o7777 {
                            return Err(format!("/{p}: mode {:04o} in place of the root's {:04o}", md.mode & 0o7777, r.mode & 0o7777));
                        }
                        let (mine, theirs) = (visible_xattrs(&*upper, &p).map_err(|e| err(&p, "its extended attributes", e))?, visible_xattrs(&*lower, &p).map_err(|e| err(&p, "the root's file's extended attributes", e))?);
                        if mine != theirs {
                            let names = |v: &[(String, Vec<u8>)]| v.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(", ");
                            return Err(format!("/{p}: extended attributes [{}] in place of the root's [{}] (or their values differ)", names(&mine), names(&theirs)));
                        }
                    }
                    Some(_) => {}
                    None if dir_real => notes.push(format!(
                        "/{p}: the root has nothing here; this {} {} the overlay's own, with the overlay's modes",
                        kind_name(md.file_type),
                        if md.file_type == FileType::Directory { "and what it holds are" } else { "is" }
                    )),
                    None => {}
                }
                if md.file_type == FileType::Directory {
                    todo.push(p.clone());
                }
                children.entry(dir.clone()).or_default().push(name.clone());
                found.insert(p, Found { md, real: real.map(|r| r.file_type), merged });
            }
        }
        // Inode numbers, in path order: each own file's first free one
        // from its path's hash; a hard link's (a name of an inode the
        // overlay has already numbered) its inode's.
        let mut entries = BTreeMap::new();
        let mut by_ino = HashMap::new();
        let mut taken = vec![false; OWN_INO_SLOTS as usize];
        let mut linked: HashMap<u64, u64> = HashMap::new();
        for (p, f) in &found {
            let kids = children.remove(p).unwrap_or_default();
            let kind = if f.merged {
                Kind::Merged { nlink: 0, size: 0 }
            } else {
                let shared = (f.md.file_type != FileType::Directory && f.md.nlink > 1).then(|| linked.get(&f.md.ino).copied()).flatten();
                let ino = match shared {
                    Some(ino) => ino,
                    None => {
                        let first = fnv(p) % OWN_INO_SLOTS;
                        let slot = (0..OWN_INO_SLOTS).map(|i| (first + i) % OWN_INO_SLOTS).find(|&s| !taken[s as usize]).ok_or("the overlay holds more than 65536 files")?;
                        taken[slot as usize] = true;
                        let ino = OWN_INO_FIRST + slot;
                        if f.md.file_type != FileType::Directory && f.md.nlink > 1 {
                            linked.insert(f.md.ino, ino);
                        }
                        ino
                    }
                };
                by_ino.entry(ino).or_insert_with(|| p.clone());
                Kind::Own { ino }
            };
            entries.insert(p.clone(), Entry { file_type: f.md.file_type, kind, children: kids });
        }
        // A merged directory counts the overlay's new names as the root
        // counts its own: its link count is 2 and its entries (APFS's), or
        // 2 and its subdirectories (a Unix filesystem's), as the root's
        // directory's was found to be; its size, on APFS, 32 bytes a link.
        let merged: Vec<String> = found.iter().filter(|(_, f)| f.merged).map(|(p, _)| p.clone()).collect();
        for d in &merged {
            let md = lower.metadata(d).map_err(|e| err(d, "the root's directory", e))?;
            let listing = list(&*lower, d).map_err(|e| err(d, "listing the root's directory", e))?;
            let all = names_of(&listing).len() as i64;
            let dirs = listing.iter().filter(|e| e.name != "." && e.name != ".." && e.file_type == FileType::Directory).count() as i64;
            let new: Vec<&Found> = entries[d].children.iter().map(|c| &found[&join(d, c)]).filter(|f| f.real.is_none()).collect();
            let new_dirs = new.iter().filter(|f| f.md.file_type == FileType::Directory).count() as i64;
            let nlink = i64::from(md.nlink);
            let dn = if nlink == all + 2 {
                new.len() as i64
            } else if nlink == dirs + 2 {
                new_dirs
            } else {
                0
            };
            let ds = if md.size as i64 == 32 * nlink { 32 * dn } else { 0 };
            if let Some(e) = entries.get_mut(d) {
                e.kind = Kind::Merged { nlink: dn, size: ds };
            }
        }
        let stops: Vec<String> = found.iter().filter(|(p, f)| !p.is_empty() && !f.merged && found[&super::parent_of(&format!("/{p}"))[1..]].merged).map(|(p, _)| format!("/{p}")).collect();
        let ix = Index { entries, by_ino, stops: stops.join("\0"), order };
        Ok((OverlayFs { lower, upper, ix: Arc::new(ix) }, notes))
    }

    fn place(&self, rel: &str) -> Place<'_> {
        let ix = &self.ix;
        let mut parent = &ix.entries[""];
        if rel.is_empty() {
            return Place::Entry(parent);
        }
        let mut start = 0;
        loop {
            let end = rel[start..].find('/').map_or(rel.len(), |i| start + i);
            match ix.entries.get(&rel[..end]) {
                Some(e) if end == rel.len() => return Place::Entry(e),
                Some(e) if e.file_type != FileType::Directory => return Place::NotDir,
                Some(e) => {
                    parent = e;
                    start = end + 1;
                }
                None => {
                    return match parent.kind {
                        Kind::Merged { .. } => Place::Lower,
                        Kind::Own { .. } => Place::Missing,
                    }
                }
            }
        }
    }

    /// The root's answer about one of its files, its inode number checked.
    fn lower_md(&self, md: Metadata) -> Result<Metadata, Errno> {
        own_range_check(md.ino)?;
        Ok(md)
    }

    /// A merged directory's attributes: the root's, counting the
    /// overlay's names too.
    fn merged_md(md: Metadata, kind: &Kind) -> Result<Metadata, Errno> {
        own_range_check(md.ino)?;
        let Kind::Merged { nlink, size } = *kind else { return Ok(md) };
        Ok(Metadata { nlink: (i64::from(md.nlink) + nlink) as u32, size: (md.size as i64 + size) as u64, ..md })
    }

    fn own_md(&self, rel: &str, e: &Entry, follow: bool) -> Result<Metadata, Errno> {
        if follow && e.file_type == FileType::Symlink {
            // Followed here as the walk does (only a caller that has not
            // walked the path asks this).
            let w = walk_links(format!("/{rel}"), true, "", &|r| self.read_link(r))?;
            return self.metadata_nofollow(w.path.trim_start_matches('/'));
        }
        let mut md = self.upper.metadata_nofollow(rel)?;
        md.ino = e.own_ino().unwrap_or(md.ino);
        Ok(md)
    }

    fn metadata_at(&self, rel: &str, follow: bool) -> Result<Metadata, Errno> {
        match self.place(rel) {
            Place::Lower if follow => self.lower_md(self.lower.metadata(rel)?),
            Place::Lower => self.lower_md(self.lower.metadata_nofollow(rel)?),
            Place::Entry(e) => match &e.kind {
                Kind::Merged { .. } => Self::merged_md(self.lower.metadata_nofollow(rel)?, &e.kind),
                Kind::Own { .. } => self.own_md(rel, e, follow),
            },
            Place::Missing => Err(Errno::ENOENT),
            Place::NotDir => Err(Errno::ENOTDIR),
        }
    }

    /// A call that changes the name `rel` (removes, renames or replaces
    /// it): the root's for its own names, EROFS for the overlay's.
    fn changing(&self, rel: &str) -> Result<(), Errno> {
        match self.place(rel) {
            Place::Lower => Ok(()),
            Place::Entry(_) => Err(Errno::EROFS),
            Place::Missing => Err(Errno::ENOENT),
            Place::NotDir => Err(Errno::ENOTDIR),
        }
    }

    /// A call that makes the name `rel`: the root's under its own
    /// directories (and the merged ones), EEXIST for a name the overlay
    /// holds, EROFS in a directory of the overlay's own.
    fn making(&self, rel: &str) -> Result<(), Errno> {
        match self.place(rel) {
            Place::Lower => Ok(()),
            Place::Entry(_) => Err(Errno::EEXIST),
            Place::Missing => Err(Errno::EROFS),
            Place::NotDir => Err(Errno::ENOTDIR),
        }
    }

    /// A call that changes the attributes of what `rel` names: the root's
    /// for its own files and its merged directories, EROFS for the
    /// overlay's own.
    fn attributes(&self, rel: &str) -> Result<(), Errno> {
        match self.place(rel) {
            Place::Lower => Ok(()),
            Place::Entry(e) if matches!(e.kind, Kind::Merged { .. }) => Ok(()),
            Place::Entry(_) => Err(Errno::EROFS),
            Place::Missing => Err(Errno::ENOENT),
            Place::NotDir => Err(Errno::ENOTDIR),
        }
    }

    fn open_with(&self, rel: &str, flags: u64, mode: u32, lower: impl Fn(&str, u64, u32) -> Result<Arc<dyn FileHandle>, Errno>) -> Result<Arc<dyn FileHandle>, Errno> {
        let acc = flags & oflags::ACCMODE;
        let write = acc == oflags::O_WRONLY || acc == oflags::O_RDWR;
        match self.place(rel) {
            Place::Lower => lower(rel, flags, mode),
            Place::Entry(e) => {
                if flags & oflags::O_CREAT != 0 && flags & oflags::O_EXCL != 0 {
                    return Err(Errno::EEXIST);
                }
                if e.file_type == FileType::Directory && write {
                    return Err(Errno::EISDIR);
                }
                match e.kind {
                    Kind::Merged { .. } => {
                        let inner = lower(rel, flags, mode)?;
                        Ok(Arc::new(MergedDir { inner, rel: rel.to_string(), ix: Arc::clone(&self.ix) }))
                    }
                    Kind::Own { ino } => {
                        if e.file_type == FileType::Symlink {
                            // Followed as the walk does (only a caller
                            // that has not walked the path opens a link).
                            let w = walk_links(format!("/{rel}"), true, "", &|r| self.read_link(r))?;
                            return self.open_with(w.path.trim_start_matches('/'), flags, mode, lower);
                        }
                        if write || flags & oflags::O_TRUNC != 0 {
                            return Err(Errno::EROFS);
                        }
                        let inner = self.upper.open(rel, flags & !(oflags::O_CREAT | oflags::O_EXCL), 0)?;
                        Ok(Arc::new(OwnHandle { inner, ino, rel: rel.to_string(), ix: Arc::clone(&self.ix) }))
                    }
                }
            }
            Place::Missing if flags & oflags::O_CREAT != 0 => Err(Errno::EROFS),
            Place::Missing => Err(Errno::ENOENT),
            Place::NotDir => Err(Errno::ENOTDIR),
        }
    }
}

thread_local! {
    /// The stops of the last walk on this thread ([`OverlayFs::walk`]): the
    /// overlay's, the mounts it was given, and the two together.
    static BOTH: std::cell::RefCell<(String, String, String)> = const { std::cell::RefCell::new((String::new(), String::new(), String::new())) };
}

/// [`OWN_INO_FIRST`]'s check of an inode number of the root's.
fn own_range_check(ino: u64) -> Result<(), Errno> {
    if (OWN_INO_FIRST..OWN_INO_FIRST + OWN_INO_SLOTS).contains(&ino) {
        eprintln!("gex: overlay: the root has a file numbered {ino:#x}, among the numbers of the overlay's own files");
        return Err(Errno::EIO);
    }
    Ok(())
}

impl FileSystem for OverlayFs {
    fn bound_subtree(&self, rel: &str) -> Option<Arc<dyn FileSystem>> {
        match self.place(rel) {
            Place::Lower => self.lower.bound_subtree(rel),
            _ => None,
        }
    }

    fn fs_type(&self) -> &'static str {
        self.lower.fs_type()
    }

    fn open(&self, path: &str, flags: u64, mode: u32) -> Result<Arc<dyn FileHandle>, Errno> {
        self.open_with(path, flags, mode, |p, f, m| self.lower.open(p, f, m))
    }

    fn open_mode(&self, path: &str, flags: u64, mode: u32) -> Result<Arc<dyn FileHandle>, Errno> {
        self.open_with(path, flags, mode, |p, f, m| self.lower.open_mode(p, f, m))
    }

    fn metadata(&self, path: &str) -> Result<Metadata, Errno> {
        self.metadata_at(path, true)
    }

    fn metadata_nofollow(&self, path: &str) -> Result<Metadata, Errno> {
        self.metadata_at(path, false)
    }

    fn access(&self, path: &str, mode: u32) -> Result<(), Errno> {
        match self.place(path) {
            Place::Lower => self.lower.access(path, mode),
            Place::Entry(e) => match e.kind {
                Kind::Merged { .. } => self.lower.access(path, mode),
                Kind::Own { .. } if mode & 2 != 0 => Err(Errno::EROFS),
                Kind::Own { .. } => self.upper.access(path, mode),
            },
            Place::Missing => Err(Errno::ENOENT),
            Place::NotDir => Err(Errno::ENOTDIR),
        }
    }

    fn read_link(&self, path: &str) -> Result<String, Errno> {
        match self.place(path) {
            Place::Lower => self.lower.read_link(path),
            Place::Entry(e) => match e.kind {
                Kind::Merged { .. } => Err(Errno::EINVAL),
                Kind::Own { .. } => self.upper.read_link(path),
            },
            Place::Missing => Err(Errno::ENOENT),
            Place::NotDir => Err(Errno::ENOTDIR),
        }
    }

    /// The root's own walk (a host's, a stretch of the path at a time),
    /// stopped where the overlay has something of its own; from there,
    /// [`walk_links`] by this filesystem's names.
    fn walk(&self, abs: &str, follow_final: bool, mounts: &str) -> Result<Walked, Errno> {
        let stops = &self.ix.stops;
        if stops.is_empty() {
            return self.lower.walk(abs, follow_final, mounts);
        }
        // The mounts and the overlay's stops together, made once for the
        // mounts a namespace has (a lookup allocates nothing).
        let w = BOTH.with(|both| {
            let mut both = both.borrow_mut();
            if both.0 != *stops || both.1 != mounts {
                let joined = if mounts.is_empty() { stops.clone() } else { format!("{mounts}\0{stops}") };
                *both = (stops.clone(), mounts.to_string(), joined);
            }
            self.lower.walk(abs, follow_final, &both.2)
        })?;
        if !w.at_mount {
            return Ok(w);
        }
        // Which stop it met: the first prefix of its path in one (a mount
        // before the overlay's own at the same place).
        let path = w.path.as_str();
        let mut end = 0;
        while end < path.len() {
            end = path[end + 1..].find('/').map_or(path.len(), |i| end + 1 + i);
            let prefix = &path[..end];
            if within_any(prefix, mounts) {
                return Ok(w);
            }
            if within_any(prefix, stops) {
                break;
            }
        }
        walk_links(w.path, follow_final, mounts, &|rel| self.read_link(rel))
    }

    fn unlink(&self, path: &str) -> Result<(), Errno> {
        self.changing(path)?;
        self.lower.unlink(path)
    }

    fn mkdir(&self, path: &str, mode: u32) -> Result<(), Errno> {
        self.making(path)?;
        self.lower.mkdir(path, mode)
    }

    fn rmdir(&self, path: &str) -> Result<(), Errno> {
        self.changing(path)?;
        self.lower.rmdir(path)
    }

    fn rename(&self, from: &str, to: &str) -> Result<(), Errno> {
        self.rename2(from, to, false)
    }

    fn rename2(&self, from: &str, to: &str, noreplace: bool) -> Result<(), Errno> {
        self.changing(from)?;
        match self.place(to) {
            Place::Lower => self.lower.rename2(from, to, noreplace),
            Place::Entry(_) if noreplace => Err(Errno::EEXIST),
            Place::Entry(_) | Place::Missing => Err(Errno::EROFS),
            Place::NotDir => Err(Errno::ENOTDIR),
        }
    }

    fn swap_names(&self, a: &str, b: &str) -> Result<(), Errno> {
        self.changing(a)?;
        self.changing(b)?;
        self.lower.swap_names(a, b)
    }

    fn chmod(&self, path: &str, mode: u32) -> Result<(), Errno> {
        self.attributes(path)?;
        self.lower.chmod(path, mode)
    }

    fn set_mtime(&self, path: &str, secs: i64) -> Result<(), Errno> {
        self.attributes(path)?;
        self.lower.set_mtime(path, secs)
    }

    fn set_times(&self, path: &str, atime: Option<(i64, u32)>, mtime: Option<(i64, u32)>) -> Result<(), Errno> {
        self.attributes(path)?;
        self.lower.set_times(path, atime, mtime)
    }

    fn link(&self, from: &str, to: &str) -> Result<(), Errno> {
        match self.place(from) {
            Place::Lower => {}
            Place::Entry(_) => {
                // A name for one of the overlay's files: made on its
                // read-only volume, or nowhere.
                self.making(to)?;
                return Err(Errno::EROFS);
            }
            Place::Missing => return Err(Errno::ENOENT),
            Place::NotDir => return Err(Errno::ENOTDIR),
        }
        self.making(to)?;
        self.lower.link(from, to)
    }

    fn symlink(&self, target: &str, path: &str) -> Result<(), Errno> {
        self.making(path)?;
        self.lower.symlink(target, path)
    }

    fn mksocket(&self, path: &str) -> Result<(), Errno> {
        self.making(path)?;
        self.lower.mksocket(path)
    }

    fn watch_key(&self, path: &str) -> Result<(Option<crate::inotify::Key>, bool), Errno> {
        match self.place(path) {
            Place::Lower => self.lower.watch_key(path),
            Place::Entry(e) => match e.kind {
                Kind::Merged { .. } => self.lower.watch_key(path),
                Kind::Own { .. } => self.upper.watch_key(path),
            },
            Place::Missing => Err(Errno::ENOENT),
            Place::NotDir => Err(Errno::ENOTDIR),
        }
    }

    fn watch_key_of(&self, ino: u64) -> Option<crate::inotify::Key> {
        if self.ix.by_ino.contains_key(&ino) {
            return None;
        }
        self.lower.watch_key_of(ino)
    }

    fn watched_remotely(&self) -> bool {
        self.lower.watched_remotely()
    }

    fn xattr(&self, path: &str, op: XattrOp<'_>) -> Result<usize, Errno> {
        match self.place(path) {
            Place::Lower => self.lower.xattr(path, op),
            Place::Entry(e) => match e.kind {
                Kind::Merged { .. } => self.lower.xattr(path, op),
                Kind::Own { .. } => own_xattr(op, |op| self.upper.xattr(path, op)),
            },
            Place::Missing => Err(Errno::ENOENT),
            Place::NotDir => Err(Errno::ENOTDIR),
        }
    }

    fn path_of_ino(&self, ino: u64) -> Option<String> {
        if let Some(p) = self.ix.by_ino.get(&ino) {
            return Some(p.clone());
        }
        // The root's file, unless the overlay hides it.
        let p = self.lower.path_of_ino(ino)?;
        matches!(self.place(&p), Place::Lower | Place::Entry(Entry { kind: Kind::Merged { .. }, .. })).then_some(p)
    }
}

/// An extended attribute call on one of the overlay's own files: read,
/// the overlay's marks unseen; changed, EROFS.
fn own_xattr(op: XattrOp<'_>, call: impl Fn(XattrOp<'_>) -> Result<usize, Errno>) -> Result<usize, Errno> {
    match op {
        XattrOp::Get { name, .. } if name.starts_with(MARKS) => Err(Errno::ENODATA),
        XattrOp::Get { name, buf } => call(XattrOp::Get { name, buf }),
        XattrOp::List { buf } => {
            let size = call(XattrOp::List { buf: &mut [] })?;
            let mut all = vec![0u8; size];
            let n = call(XattrOp::List { buf: &mut all })?;
            let mut seen = Vec::new();
            for name in all[..n].split(|&c| c == 0).filter(|s| !s.is_empty() && !s.starts_with(MARKS.as_bytes())) {
                seen.extend_from_slice(name);
                seen.push(0);
            }
            if buf.is_empty() {
                return Ok(seen.len());
            }
            if buf.len() < seen.len() {
                return Err(Errno::ERANGE);
            }
            buf[..seen.len()].copy_from_slice(&seen);
            Ok(seen.len())
        }
        XattrOp::Set { .. } | XattrOp::Remove { .. } => Err(Errno::EROFS),
    }
}

/// One of the overlay's own files or directories, open: the overlay's
/// file, numbered as the overlay numbers it, read-only.
struct OwnHandle {
    inner: Arc<dyn FileHandle>,
    ino: u64,
    rel: String,
    ix: Arc<Index>,
}

impl std::fmt::Debug for OwnHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OwnHandle(/{}, {:#x}, {:?})", self.rel, self.ino, self.inner)
    }
}

impl FileHandle for OwnHandle {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> SysResult {
        self.inner.read_at(offset, buf)
    }
    fn write_at(&self, offset: u64, buf: &[u8]) -> SysResult {
        self.inner.write_at(offset, buf)
    }
    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(Metadata { ino: self.ino, ..self.inner.metadata()? })
    }
    fn changes(&self) -> u64 {
        self.inner.changes()
    }
    fn metadata_changes(&self) -> Result<(Metadata, u64), Errno> {
        let (md, c) = self.inner.metadata_changes()?;
        Ok((Metadata { ino: self.ino, ..md }, c))
    }
    fn read_with(&self, offset: u64, len: usize, f: &mut dyn FnMut(&[u8])) -> Option<SysResult> {
        self.inner.read_with(offset, len, f)
    }
    fn moved(&self) -> Option<Result<Moved, Errno>> {
        self.inner.moved()
    }
    fn rename_epoch(&self) -> Option<u64> {
        self.inner.rename_epoch()
    }
    fn own_rename_epoch(&self) -> Option<u64> {
        self.inner.own_rename_epoch()
    }
    fn hold_renames(&self, owner: i32, on: bool) -> bool {
        self.inner.hold_renames(owner, on)
    }
    /// The overlay's entries in it, as the overlay numbers them, in the
    /// order the root lists a directory in when that is APFS's.
    fn read_dir(&self) -> Result<Vec<DirEntry>, Errno> {
        let all = self.inner.read_dir()?;
        let mut out = Vec::new();
        let mut kids = Vec::new();
        for e in all {
            match e.name.as_str() {
                "." => out.push(DirEntry { ino: self.ino, ..e }),
                ".." => out.push(e),
                name => {
                    // (what was added to the overlay's directory after it
                    // was read is not the overlay's)
                    let Some(entry) = self.ix.entries.get(&join(&self.rel, name)) else { continue };
                    kids.push(DirEntry { ino: entry.own_ino().unwrap_or(e.ino), file_type: entry.file_type, ..e });
                }
            }
        }
        if let Some(o) = self.ix.order {
            kids.sort_by_key(|e| o.key(&e.name));
        }
        out.extend(kids);
        Ok(out)
    }
    fn set_mtime(&self, _secs: i64) -> Result<(), Errno> {
        Err(Errno::EROFS)
    }
    fn set_times(&self, _atime: Option<(i64, u32)>, _mtime: Option<(i64, u32)>) -> Result<(), Errno> {
        Err(Errno::EROFS)
    }
    fn set_times_now(&self, _atime: Option<(i64, u32)>, _mtime: Option<(i64, u32)>, _now: i64) -> Result<(), Errno> {
        Err(Errno::EROFS)
    }
    fn truncate(&self, len: u64) -> Result<(), Errno> {
        self.inner.truncate(len)
    }
    fn advise(&self, offset: u64, len: u64, advice: u32) -> Result<(), Errno> {
        self.inner.advise(offset, len, advice)
    }
    fn sync(&self, data_only: bool) -> Result<(), Errno> {
        self.inner.sync(data_only)
    }
    fn chmod(&self, _mode: u32) -> Option<Result<(), Errno>> {
        Some(Err(Errno::EROFS))
    }
    /// Asked of the open file where the overlay's filesystem keeps
    /// attributes on it; `None`, by its path, where it does not.
    fn xattr(&self, op: XattrOp<'_>) -> Option<Result<usize, Errno>> {
        let _ = self.inner.xattr(XattrOp::List { buf: &mut [] })?;
        Some(own_xattr(op, |op| self.inner.xattr(op).unwrap_or(Err(Errno::EOPNOTSUPP))))
    }
    fn is_stream(&self) -> bool {
        self.inner.is_stream()
    }
    fn seek(&self, offset: i64, whence: u32) -> Option<SysResult> {
        self.inner.seek(offset, whence)
    }
    fn host_fd(&self) -> Option<i32> {
        self.inner.host_fd()
    }
    fn vn_close(&self) {
        self.inner.vn_close()
    }
}

/// A merged directory, open: the root's directory, listing the overlay's
/// entries in it too.
struct MergedDir {
    inner: Arc<dyn FileHandle>,
    rel: String,
    ix: Arc<Index>,
}

impl std::fmt::Debug for MergedDir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MergedDir(/{}, {:?})", self.rel, self.inner)
    }
}

impl MergedDir {
    fn entry(&self) -> &Entry {
        &self.ix.entries[&self.rel]
    }
}

impl FileHandle for MergedDir {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> SysResult {
        self.inner.read_at(offset, buf)
    }
    fn metadata(&self) -> Result<Metadata, Errno> {
        OverlayFs::merged_md(self.inner.metadata()?, &self.entry().kind)
    }
    fn changes(&self) -> u64 {
        self.inner.changes()
    }
    fn metadata_changes(&self) -> Result<(Metadata, u64), Errno> {
        let (md, c) = self.inner.metadata_changes()?;
        Ok((OverlayFs::merged_md(md, &self.entry().kind)?, c))
    }
    fn moved(&self) -> Option<Result<Moved, Errno>> {
        self.inner.moved()
    }
    fn rename_epoch(&self) -> Option<u64> {
        self.inner.rename_epoch()
    }
    fn own_rename_epoch(&self) -> Option<u64> {
        self.inner.own_rename_epoch()
    }
    fn hold_renames(&self, owner: i32, on: bool) -> bool {
        self.inner.hold_renames(owner, on)
    }
    /// The root's entries, those the overlay shadows as the overlay has
    /// them, and the overlay's new ones where the root's order puts them.
    fn read_dir(&self) -> Result<Vec<DirEntry>, Errno> {
        let mut out = self.inner.read_dir()?;
        let entry = self.entry();
        let mut seen = std::collections::HashSet::new();
        for e in out.iter_mut() {
            if e.name == "." || e.name == ".." {
                continue;
            }
            own_range_check(e.ino)?;
            if let Some(o) = self.ix.entries.get(&join(&self.rel, &e.name)) {
                seen.insert(e.name.clone());
                e.file_type = o.file_type;
                if let Some(ino) = o.own_ino() {
                    e.ino = ino;
                }
            }
        }
        let new: Vec<DirEntry> = entry
            .children
            .iter()
            .filter(|c| !seen.contains(*c))
            .filter_map(|c| {
                let o = self.ix.entries.get(&join(&self.rel, c))?;
                Some(DirEntry { name: c.clone(), file_type: o.file_type, ino: o.own_ino()? })
            })
            .collect();
        put_in_order(&mut out, new, self.ix.order);
        Ok(out)
    }
    fn set_mtime(&self, secs: i64) -> Result<(), Errno> {
        self.inner.set_mtime(secs)
    }
    fn set_times(&self, atime: Option<(i64, u32)>, mtime: Option<(i64, u32)>) -> Result<(), Errno> {
        self.inner.set_times(atime, mtime)
    }
    fn set_times_now(&self, atime: Option<(i64, u32)>, mtime: Option<(i64, u32)>, now: i64) -> Result<(), Errno> {
        self.inner.set_times_now(atime, mtime, now)
    }
    fn sync(&self, data_only: bool) -> Result<(), Errno> {
        self.inner.sync(data_only)
    }
    fn chmod(&self, mode: u32) -> Option<Result<(), Errno>> {
        self.inner.chmod(mode)
    }
    fn xattr(&self, op: XattrOp<'_>) -> Option<Result<usize, Errno>> {
        self.inner.xattr(op)
    }
    fn host_fd(&self) -> Option<i32> {
        self.inner.host_fd()
    }
    fn vn_close(&self) {
        self.inner.vn_close()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::oflags::{O_CREAT, O_EXCL, O_RDONLY, O_RDWR, O_WRONLY};
    use crate::vfs::{TmpFs, Vfs};

    const EXT: &str = "System/Library/Extensions";

    /// A root with two bundles in its extensions directory, one of which
    /// the overlay shadows with an opaque directory (and a file the root
    /// lacks), beside a bundle the root does not have.
    fn layers() -> (Arc<TmpFs>, Arc<TmpFs>) {
        let lower = Arc::new(TmpFs::new());
        lower.add_file(&format!("{EXT}/A.bundle/Info.plist"), b"real".to_vec());
        lower.add_file(&format!("{EXT}/A.bundle/0_0.bin"), b"hidden".to_vec());
        lower.add_symlink(&format!("{EXT}/A.bundle/out"), "/usr/lib");
        lower.add_file(&format!("{EXT}/B.kext/Info.plist"), b"b".to_vec());
        lower.add_file("usr/lib/libfoo.dylib", b"foo".to_vec());
        lower.add_symlink("ext", &format!("/{EXT}/A.bundle"));
        let upper = Arc::new(TmpFs::new());
        upper.add_file(&format!("{EXT}/A.bundle/Info.plist"), b"overlay".to_vec());
        upper.add_file(&format!("{EXT}/A.bundle/A"), b"\xcf\xfa\xed\xfe".to_vec());
        upper.add_file(&format!("{EXT}/New.bundle/Info.plist"), b"new".to_vec());
        upper.xattr(&format!("{EXT}/A.bundle"), XattrOp::Set { name: OPAQUE, value: b"y", flags: 0 }).unwrap();
        (lower, upper)
    }

    fn laid(lower: &Arc<TmpFs>, upper: &Arc<TmpFs>) -> Result<(OverlayFs, Vec<String>), String> {
        OverlayFs::new(Arc::clone(lower) as Arc<dyn FileSystem>, Arc::clone(upper) as Arc<dyn FileSystem>)
    }

    fn read(fs: &dyn FileSystem, p: &str) -> Vec<u8> {
        let h = fs.open(p, O_RDONLY, 0).unwrap();
        let mut b = [0u8; 64];
        let n = h.read_at(0, &mut b).unwrap() as usize;
        b[..n].to_vec()
    }

    fn own(ino: u64) -> bool {
        (OWN_INO_FIRST..OWN_INO_FIRST + OWN_INO_SLOTS).contains(&ino)
    }

    #[test]
    fn merged_directories_are_the_roots_counting_the_overlays_names() {
        let (lower, upper) = layers();
        let (fs, _) = laid(&lower, &upper).unwrap();
        for d in ["", "System", "System/Library", EXT] {
            let (mine, real) = (fs.metadata(d).unwrap(), lower.metadata(d).unwrap());
            assert_eq!(mine.ino, real.ino, "{d}");
            // TmpFs counts a directory's subdirectories: the overlay adds
            // New.bundle to the extensions, and shadows A.bundle.
            let more = u32::from(d == EXT);
            assert_eq!(mine.nlink, real.nlink + more, "{d}");
        }
        let h = fs.open(EXT, O_RDONLY, 0).unwrap();
        assert_eq!(h.metadata().unwrap().nlink, lower.metadata(EXT).unwrap().nlink + 1);
        assert_eq!(fs.metadata("usr/lib/libfoo.dylib").unwrap().ino, lower.metadata("usr/lib/libfoo.dylib").unwrap().ino);
    }

    #[test]
    fn an_opaque_directory_hides_the_roots_entirely() {
        let (lower, upper) = layers();
        let (fs, _) = laid(&lower, &upper).unwrap();
        let a = format!("{EXT}/A.bundle");
        let names: Vec<String> = fs.open(&a, O_RDONLY, 0).unwrap().read_dir().unwrap().into_iter().map(|e| e.name).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(sorted, [".", "..", "A", "Info.plist"]);
        assert_eq!(fs.metadata(&format!("{a}/0_0.bin")).err(), Some(Errno::ENOENT));
        assert_eq!(fs.metadata_nofollow(&format!("{a}/out")).err(), Some(Errno::ENOENT));
        assert_eq!(read(&fs, &format!("{a}/Info.plist")), b"overlay");
        let (dir, plist) = (fs.metadata(&a).unwrap().ino, fs.metadata(&format!("{a}/Info.plist")).unwrap().ino);
        assert!(own(dir) && own(plist) && dir != plist);
        assert_eq!(fs.open(&format!("{a}/Info.plist"), O_RDONLY, 0).unwrap().metadata().unwrap().ino, plist);
        // Under a file of the overlay's there is nothing.
        assert_eq!(fs.metadata(&format!("{a}/Info.plist/x")).err(), Some(Errno::ENOTDIR));
    }

    #[test]
    fn listings_merge_and_number_entries_as_their_files() {
        let (lower, upper) = layers();
        let (fs, _) = laid(&lower, &upper).unwrap();
        for dir in ["", "System", EXT, &format!("{EXT}/A.bundle"), &format!("{EXT}/New.bundle")] {
            let list = fs.open(dir, O_RDONLY, 0).unwrap().read_dir().unwrap();
            let mut names: Vec<&str> = list.iter().map(|e| e.name.as_str()).collect();
            names.sort();
            names.dedup();
            assert_eq!(names.len(), list.len(), "{dir}: a name twice");
            for e in list.iter().filter(|e| e.name != "." && e.name != "..") {
                let md = fs.metadata_nofollow(&join(dir, &e.name)).unwrap();
                assert_eq!((e.ino, e.file_type), (md.ino, md.file_type), "{dir}/{}", e.name);
            }
            if dir == EXT {
                let mut n: Vec<&str> = list.iter().map(|e| e.name.as_str()).filter(|n| !n.starts_with('.')).collect();
                n.sort();
                assert_eq!(n, ["A.bundle", "B.kext", "New.bundle"]);
            }
        }
    }

    #[test]
    fn what_the_overlay_holds_is_read_only() {
        let (lower, upper) = layers();
        let (fs, _) = laid(&lower, &upper).unwrap();
        let a = format!("{EXT}/A.bundle");
        let plist = format!("{a}/Info.plist");
        assert_eq!(fs.open(&plist, O_RDWR, 0).err(), Some(Errno::EROFS));
        assert_eq!(fs.open(&plist, O_RDONLY | O_CREAT | O_EXCL, 0o644).err(), Some(Errno::EEXIST));
        assert_eq!(fs.open(&a, O_WRONLY, 0).err(), Some(Errno::EISDIR));
        assert_eq!(fs.open(&format!("{a}/made"), O_WRONLY | O_CREAT, 0o644).err(), Some(Errno::EROFS));
        assert_eq!(fs.open(&format!("{a}/0_0.bin"), O_RDONLY, 0).err(), Some(Errno::ENOENT));
        assert_eq!(fs.unlink(&plist), Err(Errno::EROFS));
        assert_eq!(fs.unlink(&format!("{a}/0_0.bin")), Err(Errno::ENOENT));
        assert_eq!(fs.rmdir(EXT), Err(Errno::EROFS));
        assert_eq!(fs.mkdir(&a, 0o755), Err(Errno::EEXIST));
        assert_eq!(fs.mkdir(&format!("{a}/sub"), 0o755), Err(Errno::EROFS));
        assert_eq!(fs.symlink("x", &format!("{a}/l")), Err(Errno::EROFS));
        assert_eq!(fs.rename("usr/lib/libfoo.dylib", &a), Err(Errno::EROFS));
        assert_eq!(fs.rename("usr/lib/libfoo.dylib", &format!("{a}/libfoo")), Err(Errno::EROFS));
        assert_eq!(fs.rename2("usr/lib/libfoo.dylib", &plist, true), Err(Errno::EEXIST));
        assert_eq!(fs.rename(&plist, "usr/lib/x"), Err(Errno::EROFS));
        assert_eq!(fs.link(&plist, "usr/lib/x"), Err(Errno::EROFS));
        assert_eq!(fs.chmod(&a, 0o700), Err(Errno::EROFS));
        assert_eq!(fs.set_times(&plist, Some((1, 0)), Some((1, 0))), Err(Errno::EROFS));
        assert_eq!(fs.access(&plist, 2), Err(Errno::EROFS));
        assert_eq!(fs.access(&plist, 4), Ok(()));
        let h = fs.open(&plist, O_RDONLY, 0).unwrap();
        assert_eq!(h.chmod(0o600), Some(Err(Errno::EROFS)));
        assert_eq!(h.set_times(None, Some((1, 0))), Err(Errno::EROFS));
        // The root's own, and a merged directory (the root's), are as the
        // root has them: a file made in the extensions is the root's.
        assert_eq!(fs.chmod(EXT, 0o755), Ok(()));
        fs.open(&format!("{EXT}/made"), O_WRONLY | O_CREAT, 0o644).unwrap();
        assert!(lower.metadata(&format!("{EXT}/made")).is_ok());
        let names: Vec<String> = fs.open(EXT, O_RDONLY, 0).unwrap().read_dir().unwrap().into_iter().map(|e| e.name).collect();
        assert!(names.iter().any(|n| n == "made"));
        assert_eq!(fs.rename(&format!("{EXT}/made"), "usr/made"), Ok(()));
    }

    #[test]
    fn the_overlays_marks_are_unseen() {
        let (lower, upper) = layers();
        let (fs, _) = laid(&lower, &upper).unwrap();
        let a = format!("{EXT}/A.bundle");
        assert_eq!(fs.xattr(&a, XattrOp::List { buf: &mut [] }), Ok(0));
        assert_eq!(fs.xattr(&a, XattrOp::Get { name: OPAQUE, buf: &mut [] }), Err(Errno::ENODATA));
        assert_eq!(fs.xattr(&a, XattrOp::Set { name: "user.x", value: b"1", flags: 0 }), Err(Errno::EROFS));
        let h = fs.open(&a, O_RDONLY, 0).unwrap();
        if let Some(r) = h.xattr(XattrOp::List { buf: &mut [] }) {
            assert_eq!(r, Ok(0));
        }
    }

    #[test]
    fn a_walk_meets_the_overlays_names_not_the_hidden_ones() {
        let (lower, upper) = layers();
        upper.add_symlink(&format!("{EXT}/New.bundle/lib"), "/usr/lib");
        let (fs, _) = laid(&lower, &upper).unwrap();
        let mut v = Vfs::new();
        v.mount("/", Arc::new(fs));
        // The root's link into the opaque directory finds the overlay's.
        assert!(own(v.metadata("/ext/A").unwrap().ino));
        // The root's link inside it is hidden with it.
        assert_eq!(v.metadata("/ext/out/libfoo.dylib").err(), Some(Errno::ENOENT));
        assert_eq!(v.metadata(&format!("/{EXT}/A.bundle/out/libfoo.dylib")).err(), Some(Errno::ENOENT));
        // An overlay link is followed.
        assert_eq!(v.metadata(&format!("/{EXT}/New.bundle/lib/libfoo.dylib")).unwrap().ino, lower.metadata("usr/lib/libfoo.dylib").unwrap().ino);
        assert_eq!(v.read_link(&format!("/{EXT}/New.bundle/lib")).unwrap(), "/usr/lib");
        assert!(v.open("/usr/lib/libfoo.dylib", O_RDONLY, 0).is_ok());
        // A mount on the way still stops the walk first.
        let (fs2, _) = laid(&lower, &upper).unwrap();
        let w = fs2.walk(&format!("/{EXT}/A.bundle/A"), true, &format!("/{EXT}")).unwrap();
        assert!(w.at_mount);
    }

    #[test]
    fn the_overlays_files_are_found_by_number() {
        let (lower, upper) = layers();
        let (fs, _) = laid(&lower, &upper).unwrap();
        let plist = format!("{EXT}/A.bundle/Info.plist");
        assert_eq!(fs.path_of_ino(fs.metadata(&plist).unwrap().ino), Some(plist));
        assert_eq!(fs.path_of_ino(lower.metadata("usr/lib/libfoo.dylib").unwrap().ino), None);
        let mut v = Vfs::new();
        v.mount("/", Arc::new(fs));
        let ino = v.metadata(&format!("/{EXT}/New.bundle")).unwrap().ino;
        assert_eq!(v.root_path_of_ino(ino), Some(format!("/{EXT}/New.bundle")));
    }

    #[test]
    fn hard_links_share_a_number() {
        let (lower, upper) = layers();
        upper.link(&format!("{EXT}/New.bundle/Info.plist"), &format!("{EXT}/New.bundle/Copy.plist")).unwrap();
        let (fs, _) = laid(&lower, &upper).unwrap();
        let ino = |p: &str| fs.metadata(&format!("{EXT}/New.bundle/{p}")).unwrap().ino;
        assert_eq!(ino("Info.plist"), ino("Copy.plist"));
    }

    #[test]
    fn what_the_root_lacks_is_reported() {
        let (lower, upper) = layers();
        let (_, notes) = laid(&lower, &upper).unwrap();
        let said = |p: &str| notes.iter().any(|n| n.starts_with(&format!("/{EXT}/{p}:")));
        assert!(said("New.bundle") && said("A.bundle/A"));
        assert!(!said("A.bundle") && !said("A.bundle/Info.plist") && !said("New.bundle/Info.plist"));
    }

    #[test]
    fn an_overlay_that_does_not_replace_in_kind_is_refused() {
        let refused = |change: &dyn Fn(&TmpFs), why: &str| {
            let (lower, upper) = layers();
            change(&upper);
            match laid(&lower, &upper) {
                Err(e) => assert!(e.contains(why), "{e}"),
                Ok(_) => panic!("laid, though {why}"),
            }
        };
        refused(&|u| u.chmod(&format!("{EXT}/A.bundle/Info.plist"), 0o600).unwrap(), "mode 0600 in place of the root's 0644");
        refused(&|u| u.add_file(&format!("{EXT}/B.kext"), Vec::new()), "a file in place of the root's directory");
        refused(&|u| u.xattr(&format!("{EXT}/A.bundle/Info.plist"), XattrOp::Set { name: "user.overlay.whiteout", value: b"y", flags: 0 }).map(|_| ()).unwrap(), "not implemented");
        refused(&|u| u.xattr(&format!("{EXT}/A.bundle/Info.plist"), XattrOp::Set { name: "user.com.apple.x", value: b"1", flags: 0 }).map(|_| ()).unwrap(), "extended attributes");
        refused(&|u| u.xattr(&format!("{EXT}/New.bundle/Info.plist"), XattrOp::Set { name: OPAQUE, value: b"y", flags: 0 }).map(|_| ()).unwrap(), "on a file");
        refused(&|u| u.xattr(&format!("{EXT}/New.bundle"), XattrOp::Set { name: OPAQUE, value: b"n", flags: 0 }).map(|_| ()).unwrap(), "not \"y\"");
        refused(&|u| u.add_socket(&format!("{EXT}/New.bundle/s")), "a socket");
        refused(&|u| u.xattr("", XattrOp::Set { name: OPAQUE, value: b"y", flags: 0 }).map(|_| ()).unwrap(), "root is opaque");
    }

    /// The order a Mac's APFS (case-insensitive) lists the 21H461 root's
    /// extensions directory in, as `ls -f` showed it.
    const HOST_ORDER: [&str; 21] = [
        "AppleUVDM.kext", "AGXMetalA10.bundle", "AppleHPM.kext", "EXBrightKext.kext", "IOStreamFamily.kext", "AppleLockdownMode.kext", "AppleTopCase.kext",
        "IOUSBDeviceFamily.kext", "AppleGameControllerPersonality.kext", "AppleBiometricSensor.kext", "EAP-RSA.ppp", "lifs.kext", "AppleSPU.kext",
        "ApplePMUFirmwareDriver.kext", "AppleMultitouchSPI.kext", "IOHIDFamily.kext", "AppleMetalGLRenderer.bundle", "AGXGPURawCounterBundle.bundle",
        "IOUSBHostFamily.kext", "ASIOKit.kext", "AppleHDQGasGaugeControl.kext",
    ];

    #[test]
    fn apfs_lists_by_its_name_hashes() {
        assert_eq!(Order::of(&HOST_ORDER), Some(Order { case_insensitive: true }));
        let mut out: Vec<DirEntry> = [".", ".."].iter().chain(HOST_ORDER.iter()).map(|n| DirEntry { name: n.to_string(), file_type: FileType::Directory, ino: 1 }).collect();
        put_in_order(&mut out, vec![DirEntry { name: "WebMetal.bundle".into(), file_type: FileType::Directory, ino: 2 }], Order::of(&HOST_ORDER));
        assert_eq!(out.len(), HOST_ORDER.len() + 3);
        assert_eq!((out[0].name.as_str(), out[1].name.as_str()), (".", ".."));
        assert!(Order { case_insensitive: true }.holds(&names_of(&out)));
        // Out of order, a listing says nothing of where a name goes.
        let mut shuffled: Vec<DirEntry> = HOST_ORDER.iter().rev().map(|n| DirEntry { name: n.to_string(), file_type: FileType::Directory, ino: 1 }).collect();
        put_in_order(&mut shuffled, vec![DirEntry { name: "WebMetal.bundle".into(), file_type: FileType::Directory, ino: 2 }], Order::of(&HOST_ORDER));
        assert_eq!(shuffled.last().unwrap().name, "WebMetal.bundle");
    }
}
