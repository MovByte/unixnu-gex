//! `getattrlist` and its kin (`bsd/vfs/vfs_attrlist.c`, xnu-10063.141.1):
//! the attribute buffer's layout, how a request is checked and sized, and
//! how a short buffer cuts the result off.
//!
//! The files here answer as an APFS volume does. What a vnode's attributes
//! are comes from gex's namespace ([`Vn`]); what APFS leaves to the
//! generic code, XNU's own fallbacks give. Values the filesystem defines
//! and XNU does not (the volume capabilities, which attributes it can
//! return, protection classes) are as a Mac's APFS reports them.

use crate::errno::Errno;

/// `ATTR_MAX_BUFFER`: the most a reply may need.
pub const ATTR_MAX_BUFFER: usize = 8192;
/// `ATTR_BIT_MAP_COUNT`.
pub const BIT_MAP_COUNT: u16 = 5;
/// `MAXPATHLEN`.
pub const MAXPATHLEN: usize = 1024;

/// `ATTR_CMN_*`.
pub mod cmn {
    pub const NAME: u32 = 0x1;
    pub const DEVID: u32 = 0x2;
    pub const FSID: u32 = 0x4;
    pub const OBJTYPE: u32 = 0x8;
    pub const OBJTAG: u32 = 0x10;
    pub const OBJID: u32 = 0x20;
    pub const OBJPERMANENTID: u32 = 0x40;
    pub const PAROBJID: u32 = 0x80;
    pub const SCRIPT: u32 = 0x100;
    pub const CRTIME: u32 = 0x200;
    pub const MODTIME: u32 = 0x400;
    pub const CHGTIME: u32 = 0x800;
    pub const ACCTIME: u32 = 0x1000;
    pub const BKUPTIME: u32 = 0x2000;
    pub const FNDRINFO: u32 = 0x4000;
    pub const OWNERID: u32 = 0x8000;
    pub const GRPID: u32 = 0x10000;
    pub const ACCESSMASK: u32 = 0x20000;
    pub const FLAGS: u32 = 0x40000;
    pub const GEN_COUNT: u32 = 0x80000;
    pub const DOCUMENT_ID: u32 = 0x100000;
    pub const USERACCESS: u32 = 0x200000;
    pub const EXTENDED_SECURITY: u32 = 0x400000;
    pub const UUID: u32 = 0x800000;
    pub const GRPUUID: u32 = 0x1000000;
    pub const FILEID: u32 = 0x2000000;
    pub const PARENTID: u32 = 0x4000000;
    pub const FULLPATH: u32 = 0x8000000;
    pub const ADDEDTIME: u32 = 0x10000000;
    pub const ERROR: u32 = 0x20000000;
    pub const DATA_PROTECT_FLAGS: u32 = 0x40000000;
    pub const RETURNED_ATTRS: u32 = 0x80000000;
}

/// `ATTR_VOL_*`.
pub mod vol {
    pub const FSTYPE: u32 = 0x1;
    pub const SIGNATURE: u32 = 0x2;
    pub const SIZE: u32 = 0x4;
    pub const SPACEFREE: u32 = 0x8;
    pub const SPACEAVAIL: u32 = 0x10;
    pub const MINALLOCATION: u32 = 0x20;
    pub const ALLOCATIONCLUMP: u32 = 0x40;
    pub const IOBLOCKSIZE: u32 = 0x80;
    pub const OBJCOUNT: u32 = 0x100;
    pub const FILECOUNT: u32 = 0x200;
    pub const DIRCOUNT: u32 = 0x400;
    pub const MAXOBJCOUNT: u32 = 0x800;
    pub const MOUNTPOINT: u32 = 0x1000;
    pub const NAME: u32 = 0x2000;
    pub const MOUNTFLAGS: u32 = 0x4000;
    pub const MOUNTEDDEVICE: u32 = 0x8000;
    pub const ENCODINGSUSED: u32 = 0x10000;
    pub const CAPABILITIES: u32 = 0x20000;
    pub const UUID: u32 = 0x40000;
    pub const FSTYPENAME: u32 = 0x100000;
    pub const FSSUBTYPE: u32 = 0x200000;
    pub const SPACEUSED: u32 = 0x800000;
    pub const QUOTA_SIZE: u32 = 0x10000000;
    pub const RESERVED_SIZE: u32 = 0x20000000;
    pub const ATTRIBUTES: u32 = 0x40000000;
    pub const INFO: u32 = 0x80000000;
    /// `ATTR_VOL_VALIDMASK`.
    pub const VALIDMASK: u32 = 0xF0B7FFFF;
}

/// `ATTR_DIR_*`.
pub mod dir {
    pub const LINKCOUNT: u32 = 0x1;
    pub const ENTRYCOUNT: u32 = 0x2;
    pub const MOUNTSTATUS: u32 = 0x4;
    pub const ALLOCSIZE: u32 = 0x8;
    pub const IOBLOCKSIZE: u32 = 0x10;
    pub const DATALENGTH: u32 = 0x20;
    pub const VALIDMASK: u32 = 0x3f;
    /// `DIR_MNTSTATUS_MNTPOINT`.
    pub const MNTSTATUS_MNTPOINT: u32 = 0x1;
}

/// `ATTR_FILE_*`.
pub mod file {
    pub const LINKCOUNT: u32 = 0x1;
    pub const TOTALSIZE: u32 = 0x2;
    pub const ALLOCSIZE: u32 = 0x4;
    pub const IOBLOCKSIZE: u32 = 0x8;
    pub const CLUMPSIZE: u32 = 0x10;
    pub const DEVTYPE: u32 = 0x20;
    pub const DATALENGTH: u32 = 0x200;
    pub const DATAALLOCSIZE: u32 = 0x400;
    pub const RSRCLENGTH: u32 = 0x1000;
    pub const RSRCALLOCSIZE: u32 = 0x2000;
    pub const VALIDMASK: u32 = 0x37ff;
}

/// `ATTR_CMNEXT_*` (the fork group, with `FSOPT_ATTR_CMN_EXTENDED`).
pub mod ext {
    pub const RELPATH: u32 = 0x4;
    pub const PRIVATESIZE: u32 = 0x8;
    pub const LINKID: u32 = 0x10;
    pub const NOFIRMLINKPATH: u32 = 0x20;
    pub const REALDEVID: u32 = 0x40;
    pub const REALFSID: u32 = 0x80;
    pub const CLONEID: u32 = 0x100;
    pub const EXT_FLAGS: u32 = 0x200;
    pub const RECURSIVE_GENCOUNT: u32 = 0x400;
    pub const ATTRIBUTION_TAG: u32 = 0x800;
    pub const CLONE_REFCNT: u32 = 0x1000;
    pub const VALIDMASK: u32 = 0x1ffc;
    /// `ATTR_FORK_VALIDMASK`: the fork group proper, which is not accepted
    /// with the extended common attributes.
    pub const FORK_VALIDMASK: u32 = 0x3;
}

/// `FSOPT_*`.
pub mod fsopt {
    pub const NOFOLLOW: u64 = 0x1;
    pub const REPORT_FULLSIZE: u64 = 0x4;
    pub const PACK_INVAL_ATTRS: u64 = 0x8;
    pub const ATTR_CMN_EXTENDED: u64 = 0x20;
    pub const LIST_SNAPSHOT: u64 = 0x40;
    pub const RETURN_REALDEV: u64 = 0x200;
    pub const NOFOLLOW_ANY: u64 = 0x800;
}

/// `ATTR_BULK_REQUIRED`.
pub const BULK_REQUIRED: u32 = cmn::NAME | cmn::RETURNED_ATTRS;

/// `attribute_set_t`: the five groups of an attribute request or result.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AttrSet {
    pub common: u32,
    pub vol: u32,
    pub dir: u32,
    pub file: u32,
    pub fork: u32,
}

impl AttrSet {
    pub fn to_bytes(self) -> [u8; 20] {
        let mut b = [0u8; 20];
        for (i, v) in [self.common, self.vol, self.dir, self.file, self.fork].into_iter().enumerate() {
            b[4 * i..4 * i + 4].copy_from_slice(&v.to_le_bytes());
        }
        b
    }
}

/// `struct attrlist`, as the caller passes it (24 bytes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AttrList {
    pub bitmapcount: u16,
    pub reserved: u16,
    pub set: AttrSet,
}

impl AttrList {
    pub const SIZE: usize = 24;

    pub fn parse(b: &[u8]) -> AttrList {
        let w = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
        AttrList {
            bitmapcount: u16::from_le_bytes([b[0], b[1]]),
            reserved: u16::from_le_bytes([b[2], b[3]]),
            set: AttrSet { common: w(4), vol: w(8), dir: w(12), file: w(16), fork: w(20) },
        }
    }
}

/// How big one attribute is in the buffer.
#[derive(Clone, Copy)]
enum Size {
    Fixed(usize),
    /// `ATTR_TIME_SIZE`: a 64-bit process's `timespec`.
    Time,
}

use Size::{Fixed, Time};

/// `getattrlist_common_tab`: the sizes of the common attributes.
const COMMON_TAB: &[(u32, Size)] = &[
    (cmn::NAME, Fixed(8)),
    (cmn::DEVID, Fixed(4)),
    (cmn::FSID, Fixed(8)),
    (cmn::OBJTYPE, Fixed(4)),
    (cmn::OBJTAG, Fixed(4)),
    (cmn::OBJID, Fixed(8)),
    (cmn::OBJPERMANENTID, Fixed(8)),
    (cmn::PAROBJID, Fixed(8)),
    (cmn::SCRIPT, Fixed(4)),
    (cmn::CRTIME, Time),
    (cmn::MODTIME, Time),
    (cmn::CHGTIME, Time),
    (cmn::ACCTIME, Time),
    (cmn::BKUPTIME, Time),
    (cmn::FNDRINFO, Fixed(32)),
    (cmn::OWNERID, Fixed(4)),
    (cmn::GRPID, Fixed(4)),
    (cmn::ACCESSMASK, Fixed(4)),
    (cmn::FLAGS, Fixed(4)),
    (cmn::GEN_COUNT, Fixed(4)),
    (cmn::DOCUMENT_ID, Fixed(4)),
    (cmn::USERACCESS, Fixed(4)),
    (cmn::EXTENDED_SECURITY, Fixed(8)),
    (cmn::UUID, Fixed(16)),
    (cmn::GRPUUID, Fixed(16)),
    (cmn::FILEID, Fixed(8)),
    (cmn::PARENTID, Fixed(8)),
    (cmn::FULLPATH, Fixed(8)),
    (cmn::ADDEDTIME, Time),
    (cmn::RETURNED_ATTRS, Fixed(20)),
    (cmn::ERROR, Fixed(4)),
    (cmn::DATA_PROTECT_FLAGS, Fixed(4)),
];

const DIR_TAB: &[(u32, Size)] = &[
    (dir::LINKCOUNT, Fixed(4)),
    (dir::ENTRYCOUNT, Fixed(4)),
    (dir::MOUNTSTATUS, Fixed(4)),
    (dir::ALLOCSIZE, Fixed(8)),
    (dir::IOBLOCKSIZE, Fixed(4)),
    (dir::DATALENGTH, Fixed(8)),
];

const FILE_TAB: &[(u32, Size)] = &[
    (file::LINKCOUNT, Fixed(4)),
    (file::TOTALSIZE, Fixed(8)),
    (file::ALLOCSIZE, Fixed(8)),
    (file::IOBLOCKSIZE, Fixed(4)),
    (file::CLUMPSIZE, Fixed(4)),
    (file::DEVTYPE, Fixed(4)),
    (file::DATALENGTH, Fixed(8)),
    (file::DATAALLOCSIZE, Fixed(8)),
    (file::RSRCLENGTH, Fixed(8)),
    (file::RSRCALLOCSIZE, Fixed(8)),
];

const EXT_TAB: &[(u32, Size)] = &[
    (ext::RELPATH, Fixed(8)),
    (ext::PRIVATESIZE, Fixed(8)),
    (ext::LINKID, Fixed(8)),
    (ext::NOFIRMLINKPATH, Fixed(8)),
    (ext::REALDEVID, Fixed(4)),
    (ext::REALFSID, Fixed(8)),
    (ext::CLONEID, Fixed(8)),
    (ext::EXT_FLAGS, Fixed(8)),
    (ext::RECURSIVE_GENCOUNT, Fixed(8)),
    (ext::ATTRIBUTION_TAG, Fixed(8)),
    (ext::CLONE_REFCNT, Fixed(4)),
];

/// `getvolattrlist_common_tab`: a volume request takes fewer of the common
/// attributes.
const VOL_COMMON_TAB: &[(u32, Size)] = &[
    (cmn::NAME, Fixed(8)),
    (cmn::DEVID, Fixed(4)),
    (cmn::FSID, Fixed(8)),
    (cmn::OBJTYPE, Fixed(4)),
    (cmn::OBJTAG, Fixed(4)),
    (cmn::OBJID, Fixed(8)),
    (cmn::OBJPERMANENTID, Fixed(8)),
    (cmn::PAROBJID, Fixed(8)),
    (cmn::SCRIPT, Fixed(4)),
    (cmn::CRTIME, Time),
    (cmn::MODTIME, Time),
    (cmn::CHGTIME, Time),
    (cmn::ACCTIME, Time),
    (cmn::BKUPTIME, Time),
    (cmn::FNDRINFO, Fixed(32)),
    (cmn::OWNERID, Fixed(4)),
    (cmn::GRPID, Fixed(4)),
    (cmn::ACCESSMASK, Fixed(4)),
    (cmn::FLAGS, Fixed(4)),
    (cmn::USERACCESS, Fixed(4)),
    (cmn::EXTENDED_SECURITY, Fixed(8)),
    (cmn::UUID, Fixed(16)),
    (cmn::GRPUUID, Fixed(16)),
    (cmn::FILEID, Fixed(8)),
    (cmn::PARENTID, Fixed(8)),
    (cmn::RETURNED_ATTRS, Fixed(20)),
    (cmn::ERROR, Fixed(4)),
];

const VOL_TAB: &[(u32, Size)] = &[
    (vol::FSTYPE, Fixed(4)),
    (vol::FSTYPENAME, Fixed(8)),
    (vol::FSSUBTYPE, Fixed(4)),
    (vol::SIGNATURE, Fixed(4)),
    (vol::SIZE, Fixed(8)),
    (vol::SPACEFREE, Fixed(8)),
    (vol::SPACEAVAIL, Fixed(8)),
    (vol::MINALLOCATION, Fixed(8)),
    (vol::ALLOCATIONCLUMP, Fixed(8)),
    (vol::IOBLOCKSIZE, Fixed(4)),
    (vol::OBJCOUNT, Fixed(4)),
    (vol::FILECOUNT, Fixed(4)),
    (vol::DIRCOUNT, Fixed(4)),
    (vol::MAXOBJCOUNT, Fixed(4)),
    (vol::MOUNTPOINT, Fixed(8)),
    (vol::NAME, Fixed(8)),
    (vol::MOUNTFLAGS, Fixed(4)),
    (vol::MOUNTEDDEVICE, Fixed(8)),
    (vol::ENCODINGSUSED, Fixed(8)),
    (vol::CAPABILITIES, Fixed(32)),
    (vol::UUID, Fixed(16)),
    (vol::SPACEUSED, Fixed(8)),
    (vol::QUOTA_SIZE, Fixed(8)),
    (vol::RESERVED_SIZE, Fixed(8)),
    (vol::ATTRIBUTES, Fixed(40)),
    (vol::INFO, Fixed(0)),
];

/// `getattrlist_parsetab`: add up what the attributes of `attrs` found in
/// `tab` take, and say whether any was not in it. The sum is kept on an
/// error, as the callers that go on despite one use it.
fn parsetab(tab: &[(u32, Size)], attrs: u32, size: &mut usize) -> Result<(), Errno> {
    let mut recognised = 0;
    for &(attr, sz) in tab {
        if attr & attrs != 0 {
            recognised |= attr;
            *size += match sz {
                Fixed(n) => n,
                Time => 16,
            };
        }
    }
    if attrs & !recognised != 0 {
        Err(Errno::EINVAL)
    } else {
        Ok(())
    }
}

/// `getattrlist_setupvattr`: the fixed part of a reply for `al` on a
/// directory or not, and whether the request is one that can be answered.
/// The size is what was added up before an error, too.
pub fn setup_sizes(al: &AttrSet, isdir: bool, use_fork: bool) -> (usize, Result<(), Errno>) {
    let mut size = 4;
    let mut r = Ok(());
    let mut step = |tab: &[(u32, Size)], attrs: u32| {
        if r.is_ok() {
            r = parsetab(tab, attrs, &mut size);
        }
    };
    if al.common != 0 {
        step(COMMON_TAB, al.common);
    }
    if isdir && al.dir != 0 {
        step(DIR_TAB, al.dir);
    }
    if !isdir && al.file != 0 {
        step(FILE_TAB, al.file);
    }
    if use_fork && al.fork != 0 {
        step(EXT_TAB, al.fork);
    }
    (size, r)
}

fn roundup4(n: usize) -> usize {
    (n + 3) & !3
}

/// `struct _attrlist_buf`: the reply being built. `fixed` and `var` are
/// offsets from the start that may run past the end, which is how a reply
/// that does not fit is sized.
pub struct AttrBuf {
    pub base: Vec<u8>,
    pub fixed: usize,
    pub var: usize,
    pub needed: usize,
    pub actual: AttrSet,
    pub valid: AttrSet,
}

impl AttrBuf {
    /// A zeroed reply of `allocated` bytes.
    pub fn new(allocated: usize) -> AttrBuf {
        AttrBuf { base: vec![0; allocated], fixed: 0, var: 0, needed: 0, actual: AttrSet::default(), valid: AttrSet::default() }
    }

    fn allocated(&self) -> isize {
        self.base.len() as isize
    }

    /// `attrlist_pack_fixed`: as much of `src` as there is room for, and the
    /// cursor moves on by its size rounded up to 4 whether it fit or not.
    pub fn pack_fixed(&mut self, src: &[u8]) {
        let count = src.len() as isize;
        let fit = count.min(self.allocated() - self.fixed as isize);
        if fit > 0 {
            self.base[self.fixed..self.fixed + fit as usize].copy_from_slice(&src[..fit as usize]);
        }
        self.fixed += roundup4(src.len());
    }

    /// `ATTR_PACK4`: only when all of it fits, and then the cursor moves.
    pub fn pack4(&mut self, v: u32) {
        if self.allocated() - self.fixed as isize >= 4 {
            self.base[self.fixed..self.fixed + 4].copy_from_slice(&v.to_le_bytes());
            self.fixed += 4;
        }
    }

    /// `ATTR_PACK8`.
    pub fn pack8(&mut self, v: [u8; 8]) {
        if self.allocated() - self.fixed as isize >= 8 {
            self.base[self.fixed..self.fixed + 8].copy_from_slice(&v);
            self.fixed += 8;
        }
    }

    pub fn pack8u(&mut self, v: u64) {
        self.pack8(v.to_le_bytes());
    }

    /// `ATTR_PACK_TIME` for a 64-bit process: a `timespec`.
    pub fn pack_time(&mut self, (sec, nsec): (i64, i64)) {
        let mut t = [0u8; 16];
        t[..8].copy_from_slice(&sec.to_le_bytes());
        t[8..].copy_from_slice(&nsec.to_le_bytes());
        self.pack_fixed(&t);
    }

    /// `attrlist_pack_variable2`: an `attrreference` and then the data, as
    /// one (`src`) or two (`src` and `ext`) pieces.
    pub fn pack_variable2(&mut self, src: &[u8], ext: &[u8]) {
        let mut ar = [0u8; 8];
        ar[..4].copy_from_slice(&((self.var as isize - self.fixed as isize) as i32).to_le_bytes());
        ar[4..].copy_from_slice(&((src.len() + ext.len()) as u32).to_le_bytes());
        self.pack_fixed(&ar);
        for part in [src, ext] {
            let fit = (part.len() as isize).min(self.allocated() - self.var as isize);
            if fit > 0 {
                self.base[self.var..self.var + fit as usize].copy_from_slice(&part[..fit as usize]);
                self.var += fit as usize;
            }
        }
        self.var = roundup4(self.var);
    }

    pub fn pack_variable(&mut self, src: &[u8]) {
        self.pack_variable2(src, &[]);
    }

    /// `attrlist_pack_string`: an `attrreference` and the text with its NUL
    /// (`None` is the empty string). The cursor always moves by the whole
    /// string, even where it is cut off, and a cut string has no NUL.
    pub fn pack_string(&mut self, src: Option<&[u8]>) {
        let src = src.unwrap_or(&[]);
        let count = src.len();
        let mut ar = [0u8; 8];
        ar[..4].copy_from_slice(&((self.var as isize - self.fixed as isize) as i32).to_le_bytes());
        ar[4..].copy_from_slice(&(count as u32 + 1).to_le_bytes());
        self.pack_fixed(&ar);
        let space = self.allocated() - self.var as isize;
        let mut fit = (count as isize).min(space);
        if space > 0 {
            self.base[self.var..self.var + fit as usize].copy_from_slice(&src[..fit as usize]);
            if space > fit {
                self.base[self.var + fit as usize] = 0;
                fit += 1;
                let zero = ((roundup4(fit as usize) as isize) - fit).min(space - fit);
                if zero > 0 {
                    let at = self.var + fit as usize;
                    self.base[at..at + zero as usize].fill(0);
                }
            }
        }
        self.var += roundup4(count + 1);
    }
}

/// `kTextEncodingMacUnicode`, what a vnode with no encoding is given.
const ENCODING_UTF8: u32 = 0x7e;

/// What a vnode's attributes are, as the code that packs them needs them.
/// `unsupported` names what the filesystem cannot give for it
/// (`va_supported`), as the fixup after the attributes are fetched sees it.
#[derive(Clone, Debug, Default)]
pub struct Vn {
    /// `enum vtype`.
    pub vtype: u32,
    /// `v_tag`.
    pub tag: u32,
    /// The name the vnode was looked up by, or the mount's, for a root.
    pub name: String,
    /// `build_path`, and with `BUILDPATH_VOLUME_RELATIVE`.
    pub path: String,
    pub relpath: String,
    /// `f_fsid`.
    pub fsid: (u32, u32),
    pub is_mount_point: bool,
    pub fileid: u64,
    pub parentid: u64,
    /// `va_mode` without the type bits.
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub flags: u32,
    pub nlink: u32,
    pub nchildren: u32,
    pub crtime: (i64, i64),
    pub modtime: (i64, i64),
    pub chgtime: (i64, i64),
    pub acctime: (i64, i64),
    pub bkuptime: (i64, i64),
    pub addedtime: (i64, i64),
    pub data_size: u64,
    pub data_alloc: u64,
    /// `si_rdev`, in Darwin's `dev_t`.
    pub rdev: u32,
    pub iosize: u32,
    /// `W_OK | R_OK | X_OK` the caller has.
    pub user_access: u32,
    pub finderinfo: Option<[u8; 32]>,
    pub encoding: u32,
    pub gen_count: u32,
    pub document_id: u32,
    pub dataprotect: u32,
    pub unsupported: AttrSet,
    /// A reply asking for this has no way to be answered: said once.
    pub missing: Vec<String>,
    /// The filesystem's ids are 32 bits (no `VA_64BITOBJIDS`): an object
    /// id is an `fsobj_id_t`, the number cut to 32 bits and generation 0.
    pub obj32: bool,
}

pub mod vtype {
    pub const VREG: u32 = 1;
    pub const VDIR: u32 = 2;
    pub const VBLK: u32 = 3;
    pub const VCHR: u32 = 4;
    pub const VLNK: u32 = 5;
    pub const VSOCK: u32 = 6;
    pub const VFIFO: u32 = 7;
}

/// `S_IF*` for a `vtype`, or `None` where `vfs_attr_pack_internal` gives
/// EBADF (a type with no mode bits).
fn type_bits(vtype: u32) -> Option<u32> {
    Some(match vtype {
        vtype::VREG => 0o100000,
        vtype::VDIR => 0o040000,
        vtype::VBLK => 0o060000,
        vtype::VCHR => 0o020000,
        vtype::VLNK => 0o120000,
        vtype::VSOCK => 0o140000,
        vtype::VFIFO => 0o010000,
        _ => return None,
    })
}

/// `getattrlist_fixupattrs`: take from `asp` what the filesystem could not
/// return for the vnode, where it was asked for.
fn fixup(asp: &mut AttrSet, un: &AttrSet, use_fork: bool) {
    asp.common &= !un.common;
    asp.dir &= !un.dir;
    asp.file &= !un.file;
    if use_fork {
        asp.fork &= !un.fork;
    }
}

/// What it takes of `Vn::unsupported` for a request: the unsupported
/// attributes the request names (`va_active & ~va_supported`).
fn wanted_unsupported(al: &AttrSet, un: &AttrSet, isdir: bool, use_fork: bool) -> AttrSet {
    AttrSet {
        common: al.common & un.common,
        vol: 0,
        dir: if isdir { al.dir & un.dir } else { 0 },
        file: if isdir { 0 } else { al.file & un.file },
        fork: if use_fork { al.fork & un.fork } else { 0 },
    }
}

/// What a reply is: the bytes to give the caller, and how many of them.
#[derive(Debug)]
pub struct Reply {
    pub bytes: Vec<u8>,
    /// The `bufferSize` limits what is copied out.
    pub copy: usize,
}

/// `getattrlist_internal` for a file or directory: check the request
/// against the vnode, then pack the reply. `authoritative_name` is the name
/// a directory listing found the entry by.
pub fn getattrlist(al: &AttrList, buffer_size: usize, options: u64, vn: &Vn) -> Result<Reply, Errno> {
    let mut al = *al;
    let use_fork = options & fsopt::ATTR_CMN_EXTENDED != 0;
    if buffer_size < 4 {
        return Err(Errno::ERANGE);
    }
    if al.bitmapcount != BIT_MAP_COUNT {
        return Err(Errno::EINVAL);
    }
    if al.set.vol != 0 {
        // A volume request is [`getvolattrlist`]'s.
        return Err(Errno::EINVAL);
    }
    if al.set.common & (cmn::GEN_COUNT | cmn::DOCUMENT_ID) != 0 && !use_fork {
        return Err(Errno::EINVAL);
    }
    if !use_fork && al.set.fork & ext::VALIDMASK != 0 {
        return Err(Errno::EINVAL);
    }
    if use_fork && al.set.fork & ext::FORK_VALIDMASK != 0 {
        return Err(Errno::EINVAL);
    }
    let return_valid = al.set.common & cmn::RETURNED_ATTRS != 0;
    let pack_invalid = options & fsopt::PACK_INVAL_ATTRS != 0;
    if pack_invalid && (!return_valid || (al.set.fork != 0 && !use_fork)) {
        return Err(Errno::EINVAL);
    }
    let isdir = vn.vtype == vtype::VDIR;
    let (fixedsize, r) = setup_sizes(&al.set, isdir, use_fork);
    r?;
    let mut valid = AttrSet::default();
    if pack_invalid {
        valid = al.set;
    }
    // Attributes the filesystem did not return. With no encoding, one not
    // asking what is returned is given UTF-8's (`vattr_get_alt_data`).
    let mut un = wanted_unsupported(&al.set, &vn.unsupported, isdir, use_fork);
    if !return_valid {
        un.common &= !cmn::SCRIPT;
    }
    if un != AttrSet::default() {
        if return_valid && pack_invalid {
            fixup(&mut valid, &un, use_fork);
        } else if return_valid {
            fixup(&mut al.set, &un, use_fork);
        } else {
            return Err(Errno::EINVAL);
        }
    }
    let set = al.set;
    let varsize = var_size(&set, vn, use_fork);
    let allocated = fixedsize + varsize;
    if allocated > ATTR_MAX_BUFFER {
        return Err(Errno::ENOMEM);
    }
    let Some(tbits) = type_bits(vn.vtype) else {
        return Err(Errno::EBADF);
    };
    let mut ab = AttrBuf::new(allocated);
    ab.valid = valid;
    ab.fixed = 4;
    if return_valid {
        ab.fixed += 20;
    }
    ab.var = fixedsize;
    ab.needed = allocated;
    pack_common(&set, &mut ab, vn, return_valid, pack_invalid, tbits);
    if set.dir != 0 && isdir {
        pack_dir(&set, &mut ab, vn);
    }
    if set.file != 0 && !isdir {
        pack_file(&set, &mut ab, vn, return_valid, pack_invalid);
    }
    if use_fork {
        pack_ext(&set, &mut ab, vn, return_valid, pack_invalid);
    }
    // Every attribute asked for is packed or, where it was not, the reply
    // says so by its absence from the returned set.
    let len = if options & fsopt::REPORT_FULLSIZE != 0 { ab.needed } else { allocated.min(ab.needed) };
    ab.base[..4].copy_from_slice(&(len as u32).to_le_bytes());
    if return_valid {
        ab.actual.common |= cmn::RETURNED_ATTRS;
        if pack_invalid {
            ab.actual.common &= ab.valid.common;
            ab.actual.dir &= ab.valid.dir;
            ab.actual.file &= ab.valid.file;
        }
        let a = ab.actual.to_bytes();
        ab.base[4..24].copy_from_slice(&a);
    }
    let copy = buffer_size.min(allocated);
    Ok(Reply { bytes: ab.base, copy })
}

/// `calc_varsize`: the variable part of a reply.
fn var_size(al: &AttrSet, vn: &Vn, use_fork: bool) -> usize {
    let mut n = 0;
    if al.common & cmn::NAME != 0 {
        n += roundup4(vn.name.len() + 1);
    }
    if al.common & cmn::FULLPATH != 0 {
        n += roundup4(vn.path.len() + 1);
    }
    if use_fork && al.fork & ext::RELPATH != 0 {
        n += roundup4(vn.relpath.len() + 1);
    }
    if use_fork && al.fork & ext::NOFIRMLINKPATH != 0 {
        n += roundup4(vn.path.len() + 1);
    }
    n
}

fn pack_common(al: &AttrSet, ab: &mut AttrBuf, vn: &Vn, return_valid: bool, pack_invalid: bool, tbits: u32) {
    let c = al.common;
    let fill = !return_valid || pack_invalid;
    if c & cmn::ERROR != 0 && fill {
        ab.pack4(0);
        ab.actual.common |= cmn::ERROR;
    }
    if c & cmn::NAME != 0 {
        ab.pack_string(Some(vn.name.as_bytes()));
        ab.actual.common |= cmn::NAME;
    }
    if c & cmn::DEVID != 0 {
        ab.pack4(vn.fsid.0);
        ab.actual.common |= cmn::DEVID;
    }
    if c & cmn::FSID != 0 {
        ab.pack8(fsid_bytes(vn.fsid));
        ab.actual.common |= cmn::FSID;
    }
    if c & cmn::OBJTYPE != 0 {
        ab.pack4(vn.vtype);
        ab.actual.common |= cmn::OBJTYPE;
    }
    if c & cmn::OBJTAG != 0 {
        ab.pack4(vn.tag);
        ab.actual.common |= cmn::OBJTAG;
    }
    // APFS ids are 64 bits (`VA_64BITOBJIDS`), another filesystem's an
    // `fsobj_id_t`; a file has no link id of its own beside its file id.
    let objid = |id: u64| if vn.obj32 { u64::from(id as u32) } else { id };
    if c & cmn::OBJID != 0 {
        ab.pack8u(objid(vn.fileid));
        ab.actual.common |= cmn::OBJID;
    }
    if c & cmn::OBJPERMANENTID != 0 {
        ab.pack8u(objid(vn.fileid));
        ab.actual.common |= cmn::OBJPERMANENTID;
    }
    if c & cmn::PAROBJID != 0 {
        ab.pack8u(objid(vn.parentid));
        ab.actual.common |= cmn::PAROBJID;
    }
    if c & cmn::SCRIPT != 0 {
        if vn.unsupported.common & cmn::SCRIPT != 0 && return_valid {
            if fill {
                ab.pack4(ENCODING_UTF8);
            }
        } else {
            ab.pack4(vn.encoding);
            ab.actual.common |= cmn::SCRIPT;
        }
    }
    for (bit, t) in [(cmn::CRTIME, vn.crtime), (cmn::MODTIME, vn.modtime), (cmn::CHGTIME, vn.chgtime), (cmn::ACCTIME, vn.acctime), (cmn::BKUPTIME, vn.bkuptime)] {
        if c & bit != 0 {
            ab.pack_time(t);
            ab.actual.common |= bit;
        }
    }
    if c & cmn::FNDRINFO != 0 {
        match vn.finderinfo {
            Some(f) => {
                ab.pack_fixed(&f);
                ab.actual.common |= cmn::FNDRINFO;
            }
            // No `com.apple.FinderInfo` attribute: zeros, unless the
            // caller asked to be told what is returned.
            None if fill => {
                ab.pack_fixed(&[0; 32]);
                ab.actual.common |= cmn::FNDRINFO;
            }
            None => {}
        }
    }
    if c & cmn::OWNERID != 0 {
        ab.pack4(vn.uid);
        ab.actual.common |= cmn::OWNERID;
    }
    if c & cmn::GRPID != 0 {
        ab.pack4(vn.gid);
        ab.actual.common |= cmn::GRPID;
    }
    if c & cmn::ACCESSMASK != 0 {
        ab.pack4(vn.mode | tbits);
        ab.actual.common |= cmn::ACCESSMASK;
    }
    if c & cmn::FLAGS != 0 {
        ab.pack4(vn.flags);
        ab.actual.common |= cmn::FLAGS;
    }
    if c & cmn::GEN_COUNT != 0 {
        ab.pack4(vn.gen_count);
        ab.actual.common |= cmn::GEN_COUNT;
    }
    if c & cmn::DOCUMENT_ID != 0 {
        ab.pack4(vn.document_id);
        ab.actual.common |= cmn::DOCUMENT_ID;
    }
    if c & cmn::USERACCESS != 0 {
        ab.pack4(vn.user_access);
        ab.actual.common |= cmn::USERACCESS;
    }
    // No ACL on any file: the owner and group GUIDs are null.
    if c & cmn::EXTENDED_SECURITY != 0 && fill {
        ab.pack_variable(&[]);
    }
    if c & cmn::UUID != 0 {
        ab.pack_fixed(&[0; 16]);
        ab.actual.common |= cmn::UUID;
    }
    if c & cmn::GRPUUID != 0 {
        ab.pack_fixed(&[0; 16]);
        ab.actual.common |= cmn::GRPUUID;
    }
    if c & cmn::FILEID != 0 {
        ab.pack8u(vn.fileid);
        ab.actual.common |= cmn::FILEID;
    }
    if c & cmn::PARENTID != 0 {
        ab.pack8u(vn.parentid);
        ab.actual.common |= cmn::PARENTID;
    }
    if c & cmn::FULLPATH != 0 {
        ab.pack_string(Some(vn.path.as_bytes()));
        ab.actual.common |= cmn::FULLPATH;
    }
    if c & cmn::ADDEDTIME != 0 {
        ab.pack_time(vn.addedtime);
        ab.actual.common |= cmn::ADDEDTIME;
    }
    if c & cmn::DATA_PROTECT_FLAGS != 0 {
        ab.pack4(vn.dataprotect);
        ab.actual.common |= cmn::DATA_PROTECT_FLAGS;
    }
}

fn fsid_bytes((a, b): (u32, u32)) -> [u8; 8] {
    let mut r = [0u8; 8];
    r[..4].copy_from_slice(&a.to_le_bytes());
    r[4..].copy_from_slice(&b.to_le_bytes());
    r
}

fn pack_dir(al: &AttrSet, ab: &mut AttrBuf, vn: &Vn) {
    let d = al.dir;
    if d & dir::LINKCOUNT != 0 {
        // APFS counts a directory's links as one, whatever `st_nlink` says.
        ab.pack4(1);
        ab.actual.dir |= dir::LINKCOUNT;
    }
    if d & dir::ENTRYCOUNT != 0 {
        ab.pack4(vn.nchildren);
        ab.actual.dir |= dir::ENTRYCOUNT;
    }
    if d & dir::MOUNTSTATUS != 0 {
        ab.pack4(if vn.is_mount_point { dir::MNTSTATUS_MNTPOINT } else { 0 });
        ab.actual.dir |= dir::MOUNTSTATUS;
    }
    if d & dir::ALLOCSIZE != 0 {
        ab.pack8u(vn.data_alloc);
        ab.actual.dir |= dir::ALLOCSIZE;
    }
    if d & dir::IOBLOCKSIZE != 0 {
        ab.pack4(vn.iosize);
        ab.actual.dir |= dir::IOBLOCKSIZE;
    }
    if d & dir::DATALENGTH != 0 {
        ab.pack8u(vn.data_size);
        ab.actual.dir |= dir::DATALENGTH;
    }
}

fn pack_file(al: &AttrSet, ab: &mut AttrBuf, vn: &Vn, return_valid: bool, pack_invalid: bool) {
    let f = al.file;
    // No resource fork on any file here.
    let (rlength, ralloc) = (0u64, 0u64);
    if f & file::LINKCOUNT != 0 {
        ab.pack4(vn.nlink);
        ab.actual.file |= file::LINKCOUNT;
    }
    if f & file::TOTALSIZE != 0 {
        ab.pack8u(rlength + vn.data_size);
        ab.actual.file |= file::TOTALSIZE;
    }
    if f & file::ALLOCSIZE != 0 {
        ab.pack8u(ralloc + vn.data_alloc);
        ab.actual.file |= file::ALLOCSIZE;
    }
    if f & file::IOBLOCKSIZE != 0 {
        ab.pack4(vn.iosize);
        ab.actual.file |= file::IOBLOCKSIZE;
    }
    if f & file::CLUMPSIZE != 0 && (!return_valid || pack_invalid) {
        ab.pack4(0);
        ab.actual.file |= file::CLUMPSIZE;
    }
    if f & file::DEVTYPE != 0 {
        ab.pack4(if matches!(vn.vtype, vtype::VCHR | vtype::VBLK) { vn.rdev } else { 0 });
        ab.actual.file |= file::DEVTYPE;
    }
    if f & file::DATALENGTH != 0 {
        ab.pack8u(vn.data_size);
        ab.actual.file |= file::DATALENGTH;
    }
    if f & file::DATAALLOCSIZE != 0 {
        ab.pack8u(vn.data_alloc);
        ab.actual.file |= file::DATAALLOCSIZE;
    }
    if f & file::RSRCLENGTH != 0 {
        ab.pack8u(rlength);
        ab.actual.file |= file::RSRCLENGTH;
    }
    if f & file::RSRCALLOCSIZE != 0 {
        ab.pack8u(ralloc);
        ab.actual.file |= file::RSRCALLOCSIZE;
    }
}

fn pack_ext(al: &AttrSet, ab: &mut AttrBuf, vn: &Vn, return_valid: bool, pack_invalid: bool) {
    let x = al.fork;
    let fill = !return_valid || pack_invalid;
    if x & ext::RELPATH != 0 {
        ab.pack_string(Some(vn.relpath.as_bytes()));
        ab.actual.fork |= ext::RELPATH;
    }
    if x & ext::PRIVATESIZE != 0 && fill {
        ab.pack8u(0);
    }
    if x & ext::LINKID != 0 {
        ab.pack8u(vn.fileid);
        ab.actual.fork |= ext::LINKID;
    }
    if x & ext::NOFIRMLINKPATH != 0 {
        ab.pack_string(Some(vn.path.as_bytes()));
        ab.actual.fork |= ext::NOFIRMLINKPATH;
    }
    if x & ext::REALDEVID != 0 {
        ab.pack4(vn.fsid.0);
        ab.actual.fork |= ext::REALDEVID;
    }
    if x & ext::REALFSID != 0 {
        ab.pack8(fsid_bytes(vn.fsid));
        ab.actual.fork |= ext::REALFSID;
    }
    // A file that was never cloned is its own clone.
    if x & ext::CLONEID != 0 {
        ab.pack8u(if vn.unsupported.fork & ext::CLONEID != 0 { 0 } else { vn.fileid });
        ab.actual.fork |= ext::CLONEID;
    }
    for (bit, wide) in [(ext::EXT_FLAGS, true), (ext::RECURSIVE_GENCOUNT, true), (ext::ATTRIBUTION_TAG, true), (ext::CLONE_REFCNT, false)] {
        if x & bit != 0 {
            if wide {
                ab.pack8u(0);
            } else {
                ab.pack4(0);
            }
            ab.actual.fork |= bit;
        }
    }
}

/// `get_error_attributes`: what an entry of a listing is when its
/// attributes could not be had: the name, and the error if it was asked
/// for. `buf` is the room there is.
pub fn error_entry(al: &AttrSet, options: u64, error: u32, name: &str, isdir: bool, buf_size: usize) -> Vec<u8> {
    let needs_error = al.common & cmn::ERROR != 0;
    let mut a = *al;
    if options & fsopt::PACK_INVAL_ATTRS == 0 {
        a.common = BULK_REQUIRED;
        if needs_error {
            a.common |= cmn::ERROR;
        }
        a.file = 0;
        a.dir = 0;
    }
    let (fsiz, _) = setup_sizes(&a, isdir, options & fsopt::ATTR_CMN_EXTENDED != 0);
    let vsiz = roundup4(name.len() + 1);
    let needed = fsiz + vsiz;
    let mut out = vec![0u8; buf_size.max(4)];
    out[..4].copy_from_slice(&(needed as u32).to_le_bytes());
    if needed > buf_size {
        return out;
    }
    let mut ab = AttrBuf::new(needed);
    ab.needed = needed;
    ab.fixed = 4 + 20;
    ab.var = fsiz;
    if needs_error {
        ab.pack4(error);
        ab.actual.common |= cmn::ERROR;
    }
    ab.pack_string(Some(name.as_bytes()));
    ab.actual.common |= cmn::NAME | cmn::RETURNED_ATTRS;
    ab.base[..4].copy_from_slice(&(needed as u32).to_le_bytes());
    let act = ab.actual.to_bytes();
    ab.base[4..24].copy_from_slice(&act);
    out[..needed].copy_from_slice(&ab.base);
    out
}

/// `VOL_CAP_*` bits the volume code sets itself.
pub mod volcap {
    pub const FMT_NO_IMMUTABLE_FILES: u32 = 0x0020_0000;
    pub const FMT_NO_PERMISSIONS: u32 = 0x0040_0000;
    pub const INT_ATTRLIST: u32 = 0x2;
    pub const INT_EXTENDED_SECURITY: u32 = 0x400;
    pub const INT_USERACCESS: u32 = 0x800;
}

/// `VFS_DFLT_ATTR_VOL`.
const DFLT_VOL: u32 = vol::FSTYPE
    | vol::FSTYPENAME
    | vol::SIGNATURE
    | vol::SIZE
    | vol::SPACEFREE
    | vol::QUOTA_SIZE
    | vol::RESERVED_SIZE
    | vol::SPACEAVAIL
    | vol::MINALLOCATION
    | vol::ALLOCATIONCLUMP
    | vol::IOBLOCKSIZE
    | vol::MOUNTPOINT
    | vol::MOUNTFLAGS
    | vol::MOUNTEDDEVICE
    | vol::CAPABILITIES
    | vol::ATTRIBUTES
    | vol::ENCODINGSUSED;

/// `VFS_DFLT_ATTR_CMN`.
const DFLT_CMN: u32 = cmn::NAME
    | cmn::DEVID
    | cmn::FSID
    | cmn::OBJTYPE
    | cmn::OBJTAG
    | cmn::OBJID
    | cmn::PAROBJID
    | cmn::SCRIPT
    | cmn::MODTIME
    | cmn::CHGTIME
    | cmn::FNDRINFO
    | cmn::OWNERID
    | cmn::GRPID
    | cmn::ACCESSMASK
    | cmn::FLAGS
    | cmn::USERACCESS
    | cmn::FILEID
    | cmn::PARENTID
    | cmn::RETURNED_ATTRS
    | cmn::DOCUMENT_ID
    | cmn::GEN_COUNT
    | cmn::DATA_PROTECT_FLAGS;

/// `VFS_DFLT_ATTR_DIR` and `VFS_DFLT_ATTR_FILE`.
const DFLT_DIR: u32 = dir::LINKCOUNT | dir::MOUNTSTATUS;
const DFLT_FILE: u32 = file::LINKCOUNT
    | file::TOTALSIZE
    | file::ALLOCSIZE
    | file::IOBLOCKSIZE
    | file::DEVTYPE
    | file::DATALENGTH
    | file::DATAALLOCSIZE
    | file::RSRCLENGTH
    | file::RSRCALLOCSIZE;

/// The `vol_capabilities_attr_t` a filesystem reports: what it has, then
/// which of those it says anything about.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VolCaps {
    pub capabilities: [u32; 4],
    pub valid: [u32; 4],
}

/// A volume, as `getvolattrlist` has it from the mount and the filesystem
/// (`vfs_getattr`). Attributes in `unsupported` are ones the filesystem has
/// no value for, as `vs.f_supported` leaves them.
#[derive(Clone, Debug, Default)]
pub struct VolInfo {
    pub root: Vn,
    pub typenum: u32,
    pub typename: String,
    pub mntonname: String,
    pub mntfromname: String,
    pub mnt_flag: u32,
    pub bsize: u32,
    pub iosize: u32,
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub fssubtype: u32,
    pub uuid: [u8; 16],
    pub caps: VolCaps,
    /// `f_attributes`: `validattr` and `nativeattr`.
    pub attributes: [AttrSet; 2],
    pub max_objcount: u32,
    pub quota: u64,
    pub reserved: u64,
    pub create_time: (i64, i64),
    pub modify_time: (i64, i64),
    pub access_time: (i64, i64),
    pub backup_time: (i64, i64),
    /// What the filesystem returns no value for: `ATTR_VOL_*`, and the
    /// volume times among the common attributes.
    pub unsupported: AttrSet,
    /// `f_objcount`, `f_filecount`, `f_dircount`, `f_vol_name`.
    pub objcount: u32,
    pub filecount: u32,
    pub dircount: u32,
    pub vol_name: String,
    /// `vfs_extendedsecurity`: the mount keeps ACLs and UUIDs.
    pub ext_security: bool,
}

/// `getattrlist_findnamecomp`: the last component of a path.
fn last_component(p: &str) -> &str {
    p.trim_end_matches('/').rsplit('/').next().unwrap_or("")
}

/// `getvolattrlist`: the reply to a request for a volume's attributes.
pub fn getvolattrlist(al: &AttrList, buffer_size: usize, options: u64, vi: &VolInfo) -> Result<Reply, Errno> {
    let mut alp = al.set;
    let return_valid = alp.common & cmn::RETURNED_ATTRS != 0;
    let pack_invalid = options & fsopt::PACK_INVAL_ATTRS != 0;
    let mut valid = AttrSet::default();
    if pack_invalid {
        if !return_valid {
            return Err(Errno::EINVAL);
        }
        valid = alp;
    }
    // getvolattrlist_setupvfsattr
    let mut fixedsize = 4;
    if alp.common != 0 {
        const VOL_INVALID: u32 = cmn::EXTENDED_SECURITY | cmn::UUID | cmn::GRPUUID | cmn::FILEID | cmn::PARENTID;
        if alp.common & VOL_INVALID != 0 && alp.common & cmn::RETURNED_ATTRS == 0 {
            return Err(Errno::EINVAL);
        }
        parsetab(VOL_COMMON_TAB, alp.common, &mut fixedsize)?;
    }
    if alp.vol != 0 {
        parsetab(VOL_TAB, alp.vol, &mut fixedsize)?;
    }
    // Attributes the filesystem has no value for (`f_active & ~f_supported`).
    const VOL_TIMES: u32 = cmn::CRTIME | cmn::MODTIME | cmn::CHGTIME | cmn::ACCTIME | cmn::BKUPTIME;
    let un = vi.unsupported.vol & alp.vol;
    let unc = vi.unsupported.common & VOL_TIMES & alp.common;
    if un != 0 || unc != 0 {
        if return_valid {
            if pack_invalid {
                valid.vol &= !un;
                valid.common &= !unc;
            } else {
                alp.vol &= !un;
                alp.common &= !unc;
            }
        } else {
            return Err(Errno::EINVAL);
        }
    }
    // The root's encoding, where it has none: UTF-8's, unless the reply
    // says what it returns and does not pack the rest.
    let root_script_un = vi.root.unsupported.common & cmn::SCRIPT != 0;
    if root_script_un && alp.common & cmn::SCRIPT != 0 && return_valid && !pack_invalid {
        alp.common &= !cmn::SCRIPT;
    }
    let name = if vi.mntonname == "/" { vi.root.name.as_str() } else { last_component(&vi.mntonname) };
    let mut varsize = 0;
    if alp.common & cmn::NAME != 0 {
        varsize += roundup4(name.len() + 1);
    }
    if alp.vol & vol::MOUNTPOINT != 0 {
        varsize += roundup4(vi.mntonname.len() + 1);
    }
    if alp.vol & vol::NAME != 0 {
        varsize += roundup4(vi.vol_name.len() + 1);
    }
    if alp.vol & vol::MOUNTEDDEVICE != 0 {
        varsize += roundup4(vi.mntfromname.len() + 1);
    }
    if alp.vol & vol::FSTYPENAME != 0 {
        varsize += roundup4(vi.typename.len() + 1);
    }
    let allocated = fixedsize + varsize;
    if allocated > ATTR_MAX_BUFFER {
        return Err(Errno::ENOMEM);
    }
    if return_valid && allocated < 4 + 20 && options & fsopt::REPORT_FULLSIZE == 0 {
        // Not even the returned attributes fit: the length alone, as 4.
        return Ok(Reply { bytes: 4u32.to_le_bytes().to_vec(), copy: 4 });
    }
    let mut ab = AttrBuf::new(allocated);
    ab.valid = valid;
    ab.fixed = 4;
    if return_valid {
        ab.fixed += 20;
    }
    ab.var = fixedsize;
    ab.needed = allocated;
    let fill = !return_valid || pack_invalid;
    let root = &vi.root;
    let c = alp.common;
    if c & cmn::ERROR != 0 {
        ab.pack4(0);
        ab.actual.common |= cmn::ERROR;
    }
    if c & cmn::NAME != 0 {
        ab.pack_string(Some(name.as_bytes()));
        ab.actual.common |= cmn::NAME;
    }
    if c & cmn::DEVID != 0 {
        ab.pack4(root.fsid.0);
        ab.actual.common |= cmn::DEVID;
    }
    if c & cmn::FSID != 0 {
        ab.pack8(fsid_bytes(root.fsid));
        ab.actual.common |= cmn::FSID;
    }
    if c & cmn::OBJTYPE != 0 && fill {
        ab.pack4(0);
    }
    if c & cmn::OBJTAG != 0 {
        ab.pack4(root.tag);
        ab.actual.common |= cmn::OBJTAG;
    }
    for bit in [cmn::OBJID, cmn::OBJPERMANENTID, cmn::PAROBJID] {
        if c & bit != 0 && fill {
            ab.pack8u(0);
        }
    }
    if c & cmn::SCRIPT != 0 {
        ab.pack4(if root_script_un { ENCODING_UTF8 } else { root.encoding });
        ab.actual.common |= cmn::SCRIPT;
    }
    if c & cmn::CRTIME != 0 {
        ab.pack_time(vi.create_time);
        ab.actual.common |= cmn::CRTIME;
    }
    if c & cmn::MODTIME != 0 {
        ab.pack_time(vi.modify_time);
        ab.actual.common |= cmn::MODTIME;
    }
    if c & cmn::CHGTIME != 0 && fill {
        ab.pack_time(vi.modify_time);
    }
    if c & cmn::ACCTIME != 0 {
        ab.pack_time(vi.access_time);
        ab.actual.common |= cmn::ACCTIME;
    }
    if c & cmn::BKUPTIME != 0 {
        ab.pack_time(vi.backup_time);
        ab.actual.common |= cmn::BKUPTIME;
    }
    if c & cmn::FNDRINFO != 0 && fill {
        ab.pack_fixed(&[0; 32]);
    }
    if c & cmn::OWNERID != 0 {
        ab.pack4(root.uid);
        ab.actual.common |= cmn::OWNERID;
    }
    if c & cmn::GRPID != 0 {
        ab.pack4(root.gid);
        ab.actual.common |= cmn::GRPID;
    }
    // The root's `va_mode`, with its type.
    if c & cmn::ACCESSMASK != 0 {
        ab.pack4(root.mode | type_bits(root.vtype).unwrap_or(0));
        ab.actual.common |= cmn::ACCESSMASK;
    }
    if c & cmn::FLAGS != 0 {
        ab.pack4(root.flags);
        ab.actual.common |= cmn::FLAGS;
    }
    if c & cmn::USERACCESS != 0 {
        ab.pack4(root.user_access);
        ab.actual.common |= cmn::USERACCESS;
    }
    if pack_invalid {
        if c & cmn::EXTENDED_SECURITY != 0 {
            ab.pack_variable(&[]);
        }
        if c & cmn::UUID != 0 {
            ab.pack_fixed(&[0; 16]);
        }
        if c & cmn::GRPUUID != 0 {
            ab.pack_fixed(&[0; 16]);
        }
        if c & cmn::FILEID != 0 {
            ab.pack8u(0);
        }
        if c & cmn::PARENTID != 0 {
            ab.pack8u(0);
        }
    }
    // XNU's defaults for what the filesystem leaves out.
    let bsize = u64::from(vi.bsize);
    let bused = vi.blocks.saturating_sub(vi.bfree);
    let v = alp.vol;
    let put = |ab: &mut AttrBuf, bit: u32, f: &dyn Fn(&mut AttrBuf)| {
        if v & bit != 0 {
            f(ab);
            ab.actual.vol |= bit;
        }
    };
    put(&mut ab, vol::FSTYPE, &|ab| ab.pack4(vi.typenum));
    // `f_signature` is 'BD' where the filesystem has none.
    put(&mut ab, vol::SIGNATURE, &|ab| ab.pack4(0x4244));
    put(&mut ab, vol::SIZE, &|ab| ab.pack8u(bsize * vi.blocks));
    put(&mut ab, vol::SPACEFREE, &|ab| ab.pack8u(bsize * vi.bfree));
    put(&mut ab, vol::SPACEAVAIL, &|ab| ab.pack8u(bsize * vi.bavail));
    put(&mut ab, vol::SPACEUSED, &|ab| ab.pack8u(bsize * bused));
    put(&mut ab, vol::MINALLOCATION, &|ab| ab.pack8u(bsize));
    put(&mut ab, vol::ALLOCATIONCLUMP, &|ab| ab.pack8u(bsize));
    put(&mut ab, vol::IOBLOCKSIZE, &|ab| ab.pack4(vi.iosize));
    put(&mut ab, vol::OBJCOUNT, &|ab| ab.pack4(vi.objcount));
    put(&mut ab, vol::FILECOUNT, &|ab| ab.pack4(vi.filecount));
    put(&mut ab, vol::DIRCOUNT, &|ab| ab.pack4(vi.dircount));
    put(&mut ab, vol::MAXOBJCOUNT, &|ab| ab.pack4(vi.max_objcount));
    put(&mut ab, vol::MOUNTPOINT, &|ab| ab.pack_string(Some(vi.mntonname.as_bytes())));
    put(&mut ab, vol::NAME, &|ab| ab.pack_string(Some(vi.vol_name.as_bytes())));
    put(&mut ab, vol::MOUNTFLAGS, &|ab| ab.pack4(vi.mnt_flag));
    put(&mut ab, vol::MOUNTEDDEVICE, &|ab| ab.pack_string(Some(vi.mntfromname.as_bytes())));
    if v & vol::ENCODINGSUSED != 0 && fill {
        ab.pack8u(!0);
    }
    if v & vol::CAPABILITIES != 0 {
        let mut caps = vi.caps;
        // The filesystem is asked about attribute lists, and says yes; the
        // mount adds what it does for every filesystem here.
        caps.capabilities[1] |= volcap::INT_ATTRLIST | volcap::INT_USERACCESS;
        if vi.ext_security {
            caps.capabilities[1] |= volcap::INT_EXTENDED_SECURITY;
        } else {
            caps.capabilities[1] &= !volcap::INT_EXTENDED_SECURITY;
        }
        caps.valid[1] |= volcap::INT_ATTRLIST | volcap::INT_EXTENDED_SECURITY | volcap::INT_USERACCESS;
        for bit in [volcap::FMT_NO_IMMUTABLE_FILES, volcap::FMT_NO_PERMISSIONS] {
            if caps.valid[0] & bit == 0 {
                caps.capabilities[0] &= !bit;
                caps.valid[0] |= bit;
            }
        }
        let mut b = [0u8; 32];
        for (i, w) in caps.capabilities.iter().chain(caps.valid.iter()).enumerate() {
            b[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
        }
        ab.pack_fixed(&b);
        ab.actual.vol |= vol::CAPABILITIES;
    }
    put(&mut ab, vol::UUID, &|ab| ab.pack_fixed(&vi.uuid));
    put(&mut ab, vol::QUOTA_SIZE, &|ab| ab.pack8u(bsize * vi.quota));
    put(&mut ab, vol::RESERVED_SIZE, &|ab| ab.pack8u(bsize * vi.reserved));
    if v & vol::ATTRIBUTES != 0 {
        let (mut valid_attr, mut native) = (vi.attributes[0], vi.attributes[1]);
        valid_attr.common |= DFLT_CMN;
        valid_attr.vol |= DFLT_VOL;
        valid_attr.dir |= DFLT_DIR;
        valid_attr.file |= DFLT_FILE;
        const SECURITY: u32 = cmn::EXTENDED_SECURITY | cmn::UUID | cmn::GRPUUID;
        if vi.ext_security {
            valid_attr.common |= SECURITY;
        } else {
            valid_attr.common &= !SECURITY;
            native.common &= !SECURITY;
        }
        let mut b = [0u8; 40];
        b[..20].copy_from_slice(&valid_attr.to_bytes());
        b[20..].copy_from_slice(&native.to_bytes());
        ab.pack_fixed(&b);
        ab.actual.vol |= vol::ATTRIBUTES;
    }
    put(&mut ab, vol::FSTYPENAME, &|ab| ab.pack_string(Some(vi.typename.as_bytes())));
    put(&mut ab, vol::FSSUBTYPE, &|ab| ab.pack4(vi.fssubtype));
    // The count for the length is the caller's room, not the reply's, here.
    let len = if options & fsopt::REPORT_FULLSIZE != 0 { ab.needed } else { buffer_size.min(ab.needed) };
    ab.base[..4].copy_from_slice(&(len as u32).to_le_bytes());
    if return_valid && allocated >= 4 + 20 {
        ab.actual.common |= cmn::RETURNED_ATTRS;
        if pack_invalid {
            ab.actual.common &= ab.valid.common;
            ab.actual.vol &= ab.valid.vol;
        }
        let a = ab.actual.to_bytes();
        ab.base[4..24].copy_from_slice(&a);
    }
    let copy = buffer_size.min(ab.needed);
    Ok(Reply { bytes: ab.base, copy })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg() -> Vn {
        Vn {
            vtype: vtype::VREG,
            tag: 25,
            name: "true".into(),
            path: "/usr/bin/true".into(),
            relpath: "/usr/bin/true".into(),
            fsid: (0x0100_0002, 0x1a),
            fileid: 0x0fff_ffff_000b_2d2b,
            parentid: 0x0fff_ffff_000b_2d10,
            mode: 0o755,
            nlink: 1,
            data_size: 133184,
            data_alloc: 135168,
            iosize: 4096,
            user_access: 5,
            encoding: 0x7e,
            ..Default::default()
        }
    }

    fn al(common: u32, dir: u32, file: u32, fork: u32) -> AttrList {
        AttrList { bitmapcount: 5, reserved: 0, set: AttrSet { common, vol: 0, dir, file, fork } }
    }

    fn word(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
    }

    #[test]
    fn sizes_add_up_and_unknown_bits_are_refused() {
        // name (8) + objtype (4) + modtime (16) + 4 for the length
        let (n, r) = setup_sizes(&AttrSet { common: cmn::NAME | cmn::OBJTYPE | cmn::MODTIME, ..Default::default() }, false, false);
        assert_eq!((n, r), (32, Ok(())));
        // file attributes on a directory are not looked at; dir ones are
        let (n, r) = setup_sizes(&AttrSet { file: file::TOTALSIZE, dir: dir::LINKCOUNT, ..Default::default() }, true, false);
        assert_eq!((n, r), (8, Ok(())));
        // ATTR_FILE_FORKCOUNT (0x80) is not in the table; the sum is kept
        let (n, r) = setup_sizes(&AttrSet { file: file::TOTALSIZE | 0x80, ..Default::default() }, false, false);
        assert_eq!((n, r), (12, Err(Errno::EINVAL)));
    }

    #[test]
    fn a_name_and_a_type_lay_out_as_xnu_does() {
        let r = getattrlist(&al(cmn::RETURNED_ATTRS | cmn::NAME | cmn::OBJTYPE, 0, 0, 0), 256, 0, &reg()).unwrap();
        // length, 20 bytes of returned attributes, the name reference, the type
        assert_eq!(r.bytes.len(), 4 + 20 + 8 + 4 + 8);
        assert_eq!(word(&r.bytes, 0), 44);
        assert_eq!(word(&r.bytes, 4), cmn::RETURNED_ATTRS | cmn::NAME | cmn::OBJTYPE);
        // the reference is relative to itself: the text starts after the type
        assert_eq!(word(&r.bytes, 24) as i32, 12);
        assert_eq!(word(&r.bytes, 28), 5);
        assert_eq!(word(&r.bytes, 32), vtype::VREG);
        assert_eq!(&r.bytes[24 + 8 + 4..24 + 8 + 4 + 5], b"true\0");
        assert_eq!(r.copy, 44);
    }

    #[test]
    fn a_short_buffer_cuts_the_reply_but_not_its_length() {
        let a = al(cmn::NAME | cmn::OBJTYPE, 0, 0, 0);
        let r = getattrlist(&a, 14, 0, &reg()).unwrap();
        assert_eq!(r.copy, 14);
        assert_eq!(word(&r.bytes, 0), 24);
        let r = getattrlist(&a, 14, fsopt::REPORT_FULLSIZE, &reg()).unwrap();
        assert_eq!(word(&r.bytes, 0), 24);
        assert_eq!(getattrlist(&a, 3, 0, &reg()).unwrap_err(), Errno::ERANGE);
    }

    #[test]
    fn requests_are_checked_in_xnus_order() {
        let mut a = al(cmn::NAME, 0, 0, 0);
        a.bitmapcount = 4;
        assert_eq!(getattrlist(&a, 3, 0, &reg()).unwrap_err(), Errno::ERANGE);
        assert_eq!(getattrlist(&a, 64, 0, &reg()).unwrap_err(), Errno::EINVAL);
        // gen count and document id need the extended group
        let g = al(cmn::GEN_COUNT, 0, 0, 0);
        assert_eq!(getattrlist(&g, 64, 0, &reg()).unwrap_err(), Errno::EINVAL);
        assert!(getattrlist(&g, 64, fsopt::ATTR_CMN_EXTENDED, &reg()).is_ok());
        // fork attributes: the extended ones only with the option, the fork group's never
        assert_eq!(getattrlist(&al(0, 0, 0, ext::LINKID), 64, 0, &reg()).unwrap_err(), Errno::EINVAL);
        assert_eq!(getattrlist(&al(0, 0, 0, ext::FORK_VALIDMASK), 64, fsopt::ATTR_CMN_EXTENDED, &reg()).unwrap_err(), Errno::EINVAL);
        // pack-invalid wants returned attributes
        assert_eq!(getattrlist(&al(cmn::NAME, 0, 0, 0), 64, fsopt::PACK_INVAL_ATTRS, &reg()).unwrap_err(), Errno::EINVAL);
        // volume attributes are not this one's
        let mut v = al(cmn::NAME, 0, 0, 0);
        v.set.vol = vol::FSTYPE;
        assert_eq!(getattrlist(&v, 64, 0, &reg()).unwrap_err(), Errno::EINVAL);
    }

    #[test]
    fn what_the_filesystem_cannot_give_is_left_out_or_refused() {
        let mut vn = reg();
        vn.unsupported.fork = ext::PRIVATESIZE;
        let a = al(0, 0, 0, ext::PRIVATESIZE | ext::LINKID);
        assert_eq!(getattrlist(&a, 64, fsopt::ATTR_CMN_EXTENDED, &vn).unwrap_err(), Errno::EINVAL);
        let a = al(cmn::RETURNED_ATTRS, 0, 0, ext::PRIVATESIZE | ext::LINKID);
        let r = getattrlist(&a, 64, fsopt::ATTR_CMN_EXTENDED, &vn).unwrap();
        let ret = AttrSet {
            common: word(&r.bytes, 4),
            vol: word(&r.bytes, 8),
            dir: word(&r.bytes, 12),
            file: word(&r.bytes, 16),
            fork: word(&r.bytes, 20),
        };
        assert_eq!(ret.fork, ext::LINKID);
        // asked to pack invalid ones: the space is there, zeroed
        let r = getattrlist(&a, 64, fsopt::ATTR_CMN_EXTENDED | fsopt::PACK_INVAL_ATTRS, &vn).unwrap();
        assert_eq!(word(&r.bytes, 20), ext::LINKID);
        assert_eq!(u64::from_le_bytes(r.bytes[24..32].try_into().unwrap()), 0);
        assert_eq!(u64::from_le_bytes(r.bytes[32..40].try_into().unwrap()), vn.fileid);
    }

    #[test]
    fn strings_are_cut_and_still_moved_past() {
        let mut ab = AttrBuf::new(16);
        ab.fixed = 4;
        ab.var = 12;
        ab.pack_string(Some(b"abcdef"));
        // reference at 4..12, room for 4 text bytes only: no NUL
        assert_eq!(&ab.base[12..16], b"abcd");
        assert_eq!(word(&ab.base, 4), 8);
        assert_eq!(word(&ab.base, 8), 7);
        assert_eq!(ab.var, 12 + 8);
        // the last word fits; one after it does not, and does not move the cursor
        ab.pack4(7);
        assert_eq!(ab.fixed, 16);
        ab.pack4(8);
        assert_eq!(ab.fixed, 16);
        // a fixed field moves it whether it fit or not
        ab.pack_fixed(&[1; 8]);
        assert_eq!(ab.fixed, 24);
    }

    #[test]
    fn the_string_gets_its_nul_and_padding_when_it_fits() {
        let mut ab = AttrBuf::new(24);
        ab.fixed = 0;
        ab.var = 8;
        ab.base[8..24].fill(0xaa);
        ab.pack_string(Some(b"ab"));
        assert_eq!(&ab.base[8..12], b"ab\0\0");
        assert_eq!(ab.var, 12);
        assert_eq!(word(&ab.base, 0), 8);
        assert_eq!(word(&ab.base, 4), 3);
    }

    #[test]
    fn the_mode_carries_the_type_and_a_typeless_vnode_is_ebadf() {
        let r = getattrlist(&al(cmn::ACCESSMASK, 0, 0, 0), 64, 0, &reg()).unwrap();
        assert_eq!(word(&r.bytes, 4), 0o100755);
        let mut vn = reg();
        vn.vtype = 0;
        assert_eq!(getattrlist(&al(cmn::ACCESSMASK, 0, 0, 0), 64, 0, &vn).unwrap_err(), Errno::EBADF);
    }

    #[test]
    fn a_reply_over_the_limit_is_enomem() {
        let mut vn = reg();
        vn.path = "x".repeat(ATTR_MAX_BUFFER);
        assert_eq!(getattrlist(&al(cmn::FULLPATH, 0, 0, 0), 64, 0, &vn).unwrap_err(), Errno::ENOMEM);
    }

    #[test]
    fn a_directory_answers_the_directory_group_and_a_file_does_not() {
        let mut vn = reg();
        vn.vtype = vtype::VDIR;
        vn.nchildren = 9;
        let r = getattrlist(&al(0, dir::LINKCOUNT | dir::ENTRYCOUNT, file::TOTALSIZE, 0), 64, 0, &vn).unwrap();
        assert_eq!((word(&r.bytes, 4), word(&r.bytes, 8)), (1, 9));
        // directory attributes on a file are ignored: only the length comes back
        let r = getattrlist(&al(0, dir::LINKCOUNT, 0, 0), 64, 0, &reg()).unwrap();
        assert_eq!(word(&r.bytes, 0), 4);
    }

    #[test]
    fn a_listing_entry_that_failed_keeps_its_name_and_error() {
        let e = error_entry(&AttrSet { common: BULK_REQUIRED | cmn::ERROR | cmn::OBJTYPE, ..Default::default() }, 0, 13, "x", false, 128);
        // length, returned set, the error, the name reference, "x\0\0\0"
        assert_eq!(word(&e, 0), 4 + 20 + 4 + 8 + 4);
        assert_eq!(word(&e, 4), cmn::ERROR | cmn::NAME | cmn::RETURNED_ATTRS);
        assert_eq!(word(&e, 24), 13);
        assert_eq!(word(&e, 28), 8);
        assert_eq!(&e[36..38], b"x\0");
        // too small for it: only the length it needs
        let e = error_entry(&AttrSet { common: BULK_REQUIRED, ..Default::default() }, 0, 13, "x", false, 32);
        assert_eq!(word(&e, 0), 4 + 20 + 8 + 4);
    }
}
