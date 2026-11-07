//! The program's embedded code signature (`LC_CODE_SIGNATURE`,
//! `osfmk/kern/cs_blobs.h`): what the kernel asks of it about the task,
//! whether it is a platform binary and which entitlements it holds.
//!
//! The signature is a big-endian superblob of indexed blobs: the
//! CodeDirectory, whose `platform` byte is nonzero only for a platform
//! binary, and the entitlements (an XML property list).

use crate::syscalls::Kernel;
use crate::GuestMem;

/// `CSMAGIC_*`, `CSSLOT_*`.
const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xfade_7171;
const CSSLOT_CODEDIRECTORY: u32 = 0;
const CSSLOT_ENTITLEMENTS: u32 = 5;

/// An entitlement's value, as CoreEntitlements reads the DER form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ent {
    Bool(bool),
    Int(i64),
    String(Vec<u8>),
    Data(Vec<u8>),
    Array(Vec<Ent>),
    Dict(Vec<(Vec<u8>, Ent)>),
}

/// A program's entitlements: the DER blob's dictionary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Entitlements(pub Vec<(Vec<u8>, Ent)>);

impl Entitlements {
    pub fn get(&self, key: &[u8]) -> Option<&Ent> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// The query AMFI answers for a boolean entitlement (`SelectKey` then
    /// `MatchType(Bool)`): present and the boolean true.
    pub fn bool_true(&self, key: &[u8]) -> bool {
        self.get(key) == Some(&Ent::Bool(true))
    }

    /// `SelectKey` alone: the key is there, whatever its value.
    pub fn present(&self, key: &[u8]) -> bool {
        self.get(key).is_some()
    }
}

/// DER's tag classes and the universal tags entitlements use.
mod der {
    pub const CONSTRUCTED: u8 = 0x20;
    pub const APPLICATION: u8 = 0x40;
    pub const CONTEXT: u8 = 0x80;
    pub const BOOLEAN: u32 = 1;
    pub const INTEGER: u32 = 2;
    pub const OCTET_STRING: u32 = 4;
    pub const UTF8_STRING: u32 = 12;
    pub const SEQUENCE: u32 = 16;
}

/// One DER element at the start of `b`: its class and constructed bits,
/// its tag number, its contents and what follows it. Definite lengths
/// only, in their shortest form.
fn der_element(b: &[u8]) -> Option<(u8, u32, &[u8], &[u8])> {
    let (&first, mut rest) = b.split_first()?;
    let mut tag = u32::from(first & 0x1f);
    if tag == 0x1f {
        tag = 0;
        loop {
            let (&c, r) = rest.split_first()?;
            rest = r;
            tag = tag.checked_mul(128)? | u32::from(c & 0x7f);
            if c & 0x80 == 0 {
                break;
            }
        }
    }
    let (&n, r) = rest.split_first()?;
    rest = r;
    let len = if n & 0x80 == 0 {
        usize::from(n)
    } else {
        let k = usize::from(n & 0x7f);
        if k == 0 || k > 4 || rest.len() < k || rest[0] == 0 {
            return None;
        }
        let v = rest[..k].iter().fold(0usize, |a, &c| a << 8 | usize::from(c));
        rest = &rest[k..];
        if v < 0x80 {
            return None;
        }
        v
    };
    (rest.len() >= len).then(|| (first & 0xe0, tag, &rest[..len], &rest[len..]))
}

/// An entitlement value: a boolean, an integer, a string, data, an array
/// (a SEQUENCE) or a dictionary ([CONTEXT 16]).
fn der_value(class: u8, tag: u32, v: &[u8]) -> Option<Ent> {
    use der::*;
    Some(match (class, tag) {
        (0, BOOLEAN) => match v {
            [0] => Ent::Bool(false),
            [0xff] => Ent::Bool(true),
            _ => return None,
        },
        (0, INTEGER) => {
            if v.is_empty() || v.len() > 8 {
                return None;
            }
            let neg = v[0] & 0x80 != 0;
            Ent::Int(v.iter().fold(if neg { -1i64 } else { 0 }, |a, &c| a << 8 | i64::from(c)))
        }
        (0, UTF8_STRING) => Ent::String(v.to_vec()),
        (0, OCTET_STRING) => Ent::Data(v.to_vec()),
        (CONSTRUCTED, SEQUENCE) => {
            let mut items = Vec::new();
            let mut rest = v;
            while !rest.is_empty() {
                let (c, t, x, r) = der_element(rest)?;
                items.push(der_value(c, t, x)?);
                rest = r;
            }
            Ent::Array(items)
        }
        (c, SEQUENCE) if c == CONTEXT | CONSTRUCTED => Ent::Dict(der_dict(v)?),
        _ => return None,
    })
}

/// A dictionary's contents: SEQUENCEs of a UTF8String key and a value.
fn der_dict(mut v: &[u8]) -> Option<Vec<(Vec<u8>, Ent)>> {
    use der::*;
    let mut out = Vec::new();
    while !v.is_empty() {
        let (c, t, pair, r) = der_element(v)?;
        if (c, t) != (CONSTRUCTED, SEQUENCE) {
            return None;
        }
        let (kc, kt, key, after) = der_element(pair)?;
        if (kc, kt) != (0, UTF8_STRING) {
            return None;
        }
        let (vc, vt, val, end) = der_element(after)?;
        if !end.is_empty() {
            return None;
        }
        out.push((key.to_vec(), der_value(vc, vt, val)?));
        v = r;
    }
    Some(out)
}

/// The DER entitlements blob's contents (past its 8-byte header): an
/// [APPLICATION 16] SEQUENCE of the version (1) and the dictionary.
pub fn parse_der_entitlements(b: &[u8]) -> Option<Entitlements> {
    use der::*;
    let (c, t, body, rest) = der_element(b)?;
    if (c, t) != (APPLICATION | CONSTRUCTED, SEQUENCE) || !rest.is_empty() {
        return None;
    }
    let (vc, vt, version, after) = der_element(body)?;
    if (vc, vt) != (0, INTEGER) || version != [1] {
        return None;
    }
    let (dc, dt, dict, end) = der_element(after)?;
    if (dc, dt) != (CONTEXT | CONSTRUCTED, SEQUENCE) || !end.is_empty() {
        return None;
    }
    der_dict(dict).map(Entitlements)
}

/// The parts of a signature the kernel reads: its best CodeDirectory's
/// fields (`csblob`'s), its entitlement blobs and its CMS blob, and what
/// AMFI made of it when it was added.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CodeSign {
    /// The CodeDirectory's `platform`: not what makes a platform binary
    /// (AMFI's trust caches do).
    pub platform: u8,
    pub cd_flags: u32,
    pub cd_version: u32,
    pub hash_type: u8,
    pub exec_seg_flags: u64,
    /// The CodeDirectory's identifier and team identifier.
    pub identity: Option<Vec<u8>>,
    pub team_id: Option<Vec<u8>>,
    /// The XML and DER entitlement blobs (each with its 8-byte header), the
    /// CMS blob's length.
    pub xml: Option<Vec<u8>>,
    pub der: Option<Vec<u8>>,
    pub cms: Option<usize>,
    /// Launch constraints of its own (`CSSLOT_LAUNCH_CONSTRAINT_SELF`,
    /// `_PARENT`, `_RESPONSIBLE`).
    pub launch_constraints: bool,
    /// The blob as added (`csb_mem_kaddr`, `csb_mem_size`).
    pub blob: Vec<u8>,
    /// The cdhash of the best CodeDirectory.
    pub cdhash: Option<[u8; CDHASH_LEN]>,
    /// AMFI's verdict: the blob's flags (`csb_flags`), a platform binary
    /// (`csb_platform_binary`) and its trust cache entry, its validation
    /// category, and the entitlements it validated (the ones the
    /// credential's AMFI label holds).
    pub flags: u32,
    pub platform_binary: bool,
    pub trust_cache: Option<super::trustcache::Entry>,
    pub category: u32,
    pub ents: Entitlements,
}

fn be32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4).map(|s| u32::from_be_bytes(s.try_into().unwrap()))
}

impl CodeSign {
    /// The signature of the 64-bit Mach-O `slice`: its `LC_CODE_SIGNATURE`
    /// superblob, parsed (none when it has none).
    pub fn of_macho(slice: &[u8]) -> Option<CodeSign> {
        const MH_MAGIC_64: u32 = 0xfeed_facf;
        const LC_CODE_SIGNATURE: u32 = 0x1d;
        let le = |o: usize| slice.get(o..o + 4).map(|s| u32::from_le_bytes(s.try_into().unwrap()));
        if le(0)? != MH_MAGIC_64 {
            return None;
        }
        let ncmds = le(16)?;
        let mut at = 32usize;
        for _ in 0..ncmds {
            let (cmd, size) = (le(at)?, le(at + 4)? as usize);
            if cmd == LC_CODE_SIGNATURE {
                let (off, len) = (le(at + 8)? as usize, le(at + 12)? as usize);
                return Some(CodeSign::parse(slice.get(off..off + len)?));
            }
            if size < 8 {
                return None;
            }
            at += size;
        }
        None
    }

    /// Read an `LC_CODE_SIGNATURE` superblob: its best CodeDirectory (as
    /// `cs_validate_csblob` chooses it) and its other blobs; what is
    /// malformed or absent reads as none.
    pub fn parse(blob: &[u8]) -> CodeSign {
        let mut cs = CodeSign::default();
        if let Ok((off, len)) = validate_csblob(blob) {
            let cd = &blob[off..off + len];
            let cstr = |o: usize| (o != 0).then(|| cd.get(o..).map(|t| t[..t.iter().position(|&c| c == 0).unwrap_or(t.len())].to_vec())).flatten();
            cs.cd_version = be32(cd, 8).unwrap_or(0);
            cs.cd_flags = be32(cd, 12).unwrap_or(0);
            cs.hash_type = cd[37];
            cs.platform = cd[38];
            cs.identity = cstr(be32(cd, 20).unwrap_or(0) as usize);
            if cs.cd_version >= CS_SUPPORTSTEAMID {
                cs.team_id = cstr(be32(cd, 48).unwrap_or(0) as usize);
            }
            if cs.cd_version >= CS_SUPPORTSEXECSEG {
                cs.exec_seg_flags = cd.get(80..88).map_or(0, |b| u64::from_be_bytes(b.try_into().unwrap()));
            }
            cs.cdhash = cdhash(blob).ok();
        }
        if be32(blob, 0) != Some(CSMAGIC_EMBEDDED_SIGNATURE) {
            return cs;
        }
        let count = be32(blob, 8).unwrap_or(0) as usize;
        for i in 0..count {
            let (Some(ty), Some(off)) = (be32(blob, 12 + 8 * i), be32(blob, 16 + 8 * i)) else { break };
            let off = off as usize;
            let (Some(magic), Some(len)) = (be32(blob, off), be32(blob, off + 4)) else { continue };
            let Some(b) = blob.get(off..off + len as usize) else { continue };
            match (ty, magic) {
                (CSSLOT_ENTITLEMENTS, CSMAGIC_EMBEDDED_ENTITLEMENTS) => cs.xml = Some(b.to_vec()),
                (CSSLOT_DER_ENTITLEMENTS, CSMAGIC_EMBEDDED_DER_ENTITLEMENTS) => cs.der = Some(b.to_vec()),
                (CSSLOT_SIGNATURESLOT, CSMAGIC_BLOBWRAPPER) => cs.cms = Some(b.len()),
                (8..=10, CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT) => cs.launch_constraints = true,
                _ => {}
            }
        }
        cs
    }

    /// `IOTaskHasEntitlement`: the entitlement AMFI validated is the
    /// boolean true.
    pub fn entitled(&self, name: &str) -> bool {
        self.ents.bool_true(name.as_bytes())
    }
}

/// A blob on a vnode: where its slice starts in the file, the range its
/// signature covers, and the signature as AMFI judged it.
#[derive(Clone)]
struct Added {
    base: i64,
    start: u64,
    end: u64,
    sig: std::sync::Arc<CodeSign>,
}

/// The signatures added to each vnode (`ubc_cs_blob_add`).
fn blobs() -> &'static std::sync::Mutex<std::collections::HashMap<(u64, u64), Vec<Added>>> {
    static B: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<(u64, u64), Vec<Added>>>> = std::sync::OnceLock::new();
    B.get_or_init(Default::default)
}

/// The blob already on the vnode for the slice at `file_start`.
fn added(vnode: (u64, u64), file_start: i64) -> Option<Added> {
    blobs().lock().unwrap_or_else(|e| e.into_inner()).get(&vnode).and_then(|v| v.iter().find(|a| file_start >= a.base + a.start as i64 && file_start < a.base + a.end as i64).cloned())
}

/// Why `ubc_cs_blob_add` refused a blob.
#[derive(Debug)]
pub enum AddError {
    /// `cs_validate_csblob`'s refusal (EBADEXEC).
    Invalid,
    /// AMFI's: its message, and whether it is fatal (the exec's crash
    /// reason).
    Policy(String, bool),
    /// A signature AMFI judges on a path not ported yet.
    Unported(String),
}

/// `ubc_cs_blob_add` of a blob for the slice at `file_start`: validated,
/// judged by AMFI (`mac_vnode_check_signature`) and kept on the vnode; or
/// the one already there for that slice. The signature, and the end of
/// the range it covers (`csb_end_offset`).
pub fn add_blob(vnode: (u64, u64), file_start: i64, b: &[u8]) -> Result<(std::sync::Arc<CodeSign>, u64), AddError> {
    if let Some(a) = added(vnode, file_start) {
        return Ok((a.sig, a.end));
    }
    let (cd_at, cd_len) = validate_csblob(b).map_err(|_| AddError::Invalid)?;
    let cd = &b[cd_at..cd_at + cd_len];
    let end = end_offset(cd);
    // csb_start_offset: the first scattered page, if scattered.
    let scatter = be32(cd, 44).unwrap_or(0) as usize;
    let start = if be32(cd, 8).unwrap_or(0) >= CS_SUPPORTSSCATTER && scatter != 0 { u64::from(be32(cd, scatter + 4).unwrap_or(0)) << cd[39] } else { 0 };
    let mut sig = CodeSign::parse(b);
    sig.blob = b.to_vec();
    let flags = (sig.cd_flags & super::amfi::cs::ALLOWED_MACHO) | super::amfi::cs::VALID;
    let v = super::amfi::vnode_check_signature(&sig, flags).map_err(|r| match r {
        super::amfi::Refusal::Fatal(m) => AddError::Policy(m, true),
        super::amfi::Refusal::Refused(m) => AddError::Policy(m, false),
        super::amfi::Refusal::Unported(m) => AddError::Unported(m),
    })?;
    sig.flags = v.flags;
    sig.platform_binary = v.platform_binary;
    sig.trust_cache = sig.cdhash.as_ref().and_then(super::trustcache::platform);
    sig.category = v.category;
    sig.ents = v.ents;
    // A platform binary's team id is not kept.
    if sig.platform_binary {
        sig.team_id = None;
    }
    let sig = std::sync::Arc::new(sig);
    let mut all = blobs().lock().unwrap_or_else(|e| e.into_inner());
    all.entry(vnode).or_default().push(Added { base: file_start, start, end, sig: std::sync::Arc::clone(&sig) });
    Ok((sig, end))
}

/// `ubc_cs_is_range_codesigned`: one blob on the vnode covers the whole
/// of `[start, start + size)`, the one whose range holds `start`.
pub fn range_codesigned(vnode: (u64, u64), start: u64, size: u64) -> bool {
    if size == 0 || start.checked_add(size).is_none() {
        return false;
    }
    let Some(a) = added(vnode, start as i64) else { return false };
    let (lo, hi) = ((a.base + a.start as i64) as u64, (a.base + a.end as i64) as u64);
    lo <= start && start + size <= hi
}

/// `CS_MAX_BLOB_SIZE`.
const CS_MAX_BLOB_SIZE: u64 = 40 * 1024 * 1024;

impl Kernel {
    /// fcntl's F_ADDSIGS, F_ADDFILESIGS and F_ADDFILESIGS_RETURN: the
    /// signature of the slice at `fs_file_start`, from memory or from the
    /// file, added to the vnode as `ubc_cs_blob_add` adds it (found again,
    /// not added twice); for F_ADDFILESIGS_RETURN the end of the range it
    /// covers.
    pub(crate) fn darwin_addsigs(&mut self, m: &mut GuestMem<'_>, fd: i32, cmd: u64, argp: u64) -> Result<u64, crate::errno::Errno> {
        use crate::errno::Errno;
        const F_ADDSIGS: u64 = 59;
        const F_ADDFILESIGS_RETURN: u64 = 97;
        let file = self.fds.get(fd)?;
        let Some(vnode) = self.darwin_vnode_of(&file) else { return Err(Errno::EBADF) };
        let file_start = m.read_u64(argp)? as i64;
        let blob_start = m.read_u64(argp + 8)?;
        let blob_size = m.read_u64(argp + 16)?;
        let end = match added(vnode, file_start) {
            Some(a) => a.end,
            None => {
                if blob_size > CS_MAX_BLOB_SIZE {
                    return Err(Errno::E2BIG);
                }
                let mut b = vec![0u8; blob_size as usize];
                if cmd == F_ADDSIGS {
                    b.copy_from_slice(m.read(blob_start, blob_size as usize)?);
                } else {
                    let at = (file_start as u64).checked_add(blob_start).ok_or(Errno::EINVAL)?;
                    // vn_rdwr: what is past the file's end reads as zeros.
                    let mut got = 0;
                    while got < b.len() {
                        let n = file.handle.read_at(at + got as u64, &mut b[got..])? as usize;
                        if n == 0 {
                            break;
                        }
                        got += n;
                    }
                }
                // ubc_cs_blob_add's error: the policy's (EPERM).
                match add_blob(vnode, file_start, &b) {
                    Ok((_, end)) => end,
                    Err(AddError::Invalid) => return Err(super::errno::EBADEXEC),
                    Err(AddError::Policy(why, _)) => {
                        if self.trace {
                            eprintln!("[gex:{}] validation of code signature failed through MACF policy: {why}", self.pid);
                        }
                        return Err(Errno::EPERM);
                    }
                    Err(AddError::Unported(what)) => {
                        self.darwin_unimplemented(what);
                        return Err(Errno::EPERM);
                    }
                }
            }
        };
        if cmd == F_ADDFILESIGS_RETURN {
            m.write_u64(argp, end)?;
        }
        Ok(0)
    }

    /// fcntl's F_CHECK_LV: its argument read; library validation is a MAC
    /// policy's, and none is loaded, so the file may be mapped.
    pub(crate) fn darwin_check_lv(&mut self, m: &mut GuestMem<'_>, fd: i32, argp: u64) -> Result<u64, crate::errno::Errno> {
        let file = self.fds.get(fd)?;
        if self.darwin_vnode_of(&file).is_none() {
            return Err(crate::errno::Errno::EBADF);
        }
        m.read(argp, 24)?;
        Ok(0)
    }

    /// An open file's vnode (its mount and inode), or `None` for what is
    /// not a vnode.
    pub(crate) fn darwin_vnode_of(&mut self, file: &std::sync::Arc<crate::file::OpenFile>) -> Option<(u64, u64)> {
        if file.handle.pipe_end().is_some() || std::sync::Arc::clone(&file.handle).as_kqueue().is_some() || std::sync::Arc::clone(&file.handle).as_posix_shm().is_some() {
            return None;
        }
        let md = file.handle.metadata().ok()?;
        if md.file_type == crate::vfs::FileType::Socket {
            return None;
        }
        Some((self.vfs.mount_id_of(&file.path), md.ino))
    }

    /// `task_get_platform_binary`: the image's signature is platform code
    /// (in a trust cache).
    pub(crate) fn darwin_task_platform_binary(&self) -> bool {
        self.dtask.codesign.as_ref().is_some_and(|c| c.platform_binary)
    }

    /// `load_machfile`'s code signatures for an image: its own (the slice
    /// `slice` at `file_start` of `path`) and its dylinker's, each added to
    /// its vnode (`load_code_signature`, `ubc_cs_blob_add`); any refusal is
    /// the load's failure (EBADEXEC). The image's signature and the load's
    /// code signing flags: CS_NO_UNTRUSTED_HELPERS unless the dylinker is
    /// not platform code, and the blob's flags; and the image's UUID.
    pub(crate) fn darwin_load_signatures(&mut self, path: &str, file_start: u64, slice: &[u8]) -> Result<(Option<std::sync::Arc<CodeSign>>, u32, [u8; 16]), crate::errno::Errno> {
        use super::amfi::cs;
        let m = gex_ld::macho::parse(slice).map_err(|_| super::errno::EBADMACHO)?;
        let mut flags = cs::NO_UNTRUSTED_HELPERS;
        let sig = match m.code_signature {
            Some((off, len)) => {
                let blob = slice.get(off as usize..off as usize + len as usize).ok_or(super::errno::EBADEXEC)?;
                let sig = self.darwin_blob_add(path, file_start as i64, blob)?;
                flags |= sig.flags;
                Some(sig)
            }
            None => None,
        };
        if let Some(d) = &m.dylinker {
            let bytes = self.read_file(d).ok_or(crate::errno::Errno::ENOENT)?;
            let (off, size) = super::execve::best_slice(&bytes)?;
            let dslice = bytes.get(off as usize..(off + size) as usize).ok_or(super::errno::EBADMACHO)?;
            let dm = gex_ld::macho::parse(dslice).map_err(|_| super::errno::EBADMACHO)?;
            let platform = match dm.code_signature {
                Some((o, n)) => {
                    let blob = dslice.get(o as usize..o as usize + n as usize).ok_or(super::errno::EBADEXEC)?;
                    self.darwin_blob_add(d, off as i64, blob)?.platform_binary
                }
                None => false,
            };
            if !platform {
                flags &= !cs::NO_UNTRUSTED_HELPERS;
            }
        }
        // load_result.uuid: the image's LC_UUID.
        Ok((sig, flags, m.uuid.unwrap_or_default()))
    }

    /// `mac_proc_check_launch_constraints` (AMFI's): the image's trust cache
    /// category names the constraints it and its parent must meet, and an
    /// image may carry its own. Category 0 has none.
    pub(crate) fn darwin_launch_constraints(&mut self) -> Result<(), crate::errno::Errno> {
        let Some(c) = &self.dtask.codesign else { return Ok(()) };
        let category = c.trust_cache.and_then(|e| e.category).unwrap_or(0);
        let own = c.launch_constraints;
        if category != 0 || own {
            self.darwin_unimplemented(format!("AMFI launch constraints (trust cache category {category}{})", if own { ", the image's own" } else { "" }));
            return Err(crate::errno::Errno::EPERM);
        }
        Ok(())
    }

    /// `ubc_cs_blob_add` for an image's load: a refusal is EBADEXEC.
    fn darwin_blob_add(&mut self, path: &str, file_start: i64, blob: &[u8]) -> Result<std::sync::Arc<CodeSign>, crate::errno::Errno> {
        let abs = self.vfs.absolute(path);
        let ino = self.vfs.metadata(&abs)?.ino;
        match add_blob((self.vfs.mount_id_of(&abs), ino), file_start, blob) {
            Ok((sig, _)) => Ok(sig),
            Err(AddError::Invalid) => Err(super::errno::EBADEXEC),
            Err(AddError::Policy(why, _)) => {
                if self.trace {
                    eprintln!("[gex:{}] {path}: validation of code signature failed through MACF policy: {why}", self.pid);
                }
                Err(super::errno::EBADEXEC)
            }
            Err(AddError::Unported(what)) => {
                self.darwin_unimplemented(format!("{what} ({path})"));
                Err(super::errno::EBADEXEC)
            }
        }
    }

    /// The new image's code signing flags, as an exec makes them
    /// (`exec_check_permissions`' `mac_vnode_check_exec`, `exec_mach_imgact`,
    /// `exec_handle_sugid`'s `mac_cred_label_update_execve`, then
    /// `proc_csflags_update`), and the entitlements its credential carries.
    /// An error is the policy's refusal: the exec is killed.
    pub(crate) fn darwin_exec_csflags(&mut self, sig: Option<std::sync::Arc<CodeSign>>, load: u32) -> Result<(), String> {
        use super::amfi::cs;
        use std::sync::atomic::Ordering;
        let old = self.dtask.csflags.load(Ordering::Acquire);
        let mut ip = 0u32;
        super::amfi::vnode_check_exec(&mut ip);
        if load & cs::VALID != 0 {
            ip |= load & (cs::VALID | cs::SIGNED | cs::DEV_CODE | cs::LINKER_SIGNED | cs::HARD | cs::KILL | cs::RESTRICT | cs::ENFORCEMENT | cs::REQUIRE_LV | cs::FORCED_LV | cs::ENTITLEMENTS_VALIDATED | cs::NO_UNTRUSTED_HELPERS | cs::RUNTIME | cs::ENTITLEMENT_FLAGS | cs::EXEC_SET_HARD | cs::EXEC_SET_KILL | cs::EXEC_SET_ENFORCEMENT);
        } else {
            ip &= !cs::VALID;
        }
        if old & cs::EXEC_SET_HARD != 0 {
            ip |= cs::HARD;
        }
        if old & cs::EXEC_SET_KILL != 0 {
            ip |= cs::KILL;
        }
        if old & cs::EXEC_SET_ENFORCEMENT != 0 {
            ip |= cs::ENFORCEMENT;
        }
        if old & cs::EXEC_INHERIT_SIP != 0 {
            ip |= old & (cs::INSTALLER | cs::DATAVAULT_CONTROLLER | cs::NVRAM_UNRESTRICTED);
        }
        // The load's NO_UNTRUSTED_HELPERS reaches AMFI with a valid image's
        // flags; an image whose signature did not make it valid has none.
        let ents = super::amfi::cred_label_update_execve(sig.as_deref(), &mut ip)?;
        self.dtask.codesign = sig.map(|s| {
            let mut c = (*s).clone();
            c.ents = ents;
            c
        });
        self.dtask.csflags.store(ip, Ordering::Release);
        Ok(())
    }

    /// `IOTaskHasEntitlement`.
    pub(crate) fn darwin_task_entitled(&self, name: &str) -> bool {
        self.dtask.codesign.as_ref().is_some_and(|c| c.entitled(name))
    }
}

/// `CS_CodeDirectory`'s size, to its linkage fields (packed).
const CD_SIZE: usize = 108;
const CS_SUPPORTSSCATTER: u32 = 0x20100;
const CS_SUPPORTSTEAMID: u32 = 0x20200;
const CS_SUPPORTSLINKAGE: u32 = 0x20600;
const CS_SUPPORTSEXECSEG: u32 = 0x20400;
const CSSLOT_DER_ENTITLEMENTS: u32 = 7;
const CSSLOT_SIGNATURESLOT: u32 = 0x10000;
const CSMAGIC_BLOBWRAPPER: u32 = 0xfade_0b01;
const CSSLOT_LAUNCH_CONSTRAINT_SELF: u32 = 8;
const CSSLOT_LIBRARY_CONSTRAINT: u32 = 11;
const CSSLOT_ALTERNATE_CODEDIRECTORIES: u32 = 0x1000;
const CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT: u32 = 0x1005;
const CSMAGIC_EMBEDDED_DER_ENTITLEMENTS: u32 = 0xfade_7172;
const CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT: u32 = 0xfade_8181;
/// `PAGE_SHIFT_4K`, and the A10X's `PAGE_SHIFT`.
const PAGE_SHIFT_4K: u8 = 12;
const PAGE_SHIFT: u8 = 14;

/// `cs_find_md`'s hash sizes, by type.
fn hash_size(ty: u8) -> Option<usize> {
    match ty {
        1 => Some(20),
        2 => Some(32),
        3 => Some(20),
        4 => Some(48),
        _ => None,
    }
}

/// `hash_rank`: `hashPriorities` order, 0 for none.
fn hash_rank(ty: u8) -> u32 {
    [1u8, 3, 2, 4].iter().position(|&t| t == ty).map_or(0, |n| n as u32 + 1)
}

/// `cs_validate_codedirectory`.
fn validate_cd(cd: &[u8]) -> bool {
    if cd.len() < CD_SIZE || be32(cd, 0) != Some(CSMAGIC_CODEDIRECTORY) {
        return false;
    }
    let length = cd.len();
    let u = |o| be32(cd, o).unwrap_or(0) as usize;
    let (version, hash_offset, ident, nspecial, ncode) = (u(8) as u32, u(16), u(20), u(24), u(28));
    let (hsize, htype, page) = (cd[36], cd[37], cd[39]);
    if page != PAGE_SHIFT_4K && page != PAGE_SHIFT {
        return false;
    }
    let Some(size) = hash_size(htype) else { return false };
    if hsize as usize != size || length < hash_offset || hash_offset / size < nspecial || (length - hash_offset) / size < ncode {
        return false;
    }
    let scatter = u(44);
    if version >= CS_SUPPORTSSCATTER && scatter != 0 {
        if length < scatter {
            return false;
        }
        let (mut at, mut pages) = (scatter, 0u32);
        loop {
            // SC_Scatter: count, base, targetOffset (8), spare (8).
            if at + 24 > length {
                return false;
            }
            let count = be32(cd, at).unwrap_or(0);
            if count == 0 {
                break;
            }
            let Some(p) = pages.checked_add(count) else { return false };
            pages = p;
            at += 24;
        }
    }
    let cstr = |off: usize| length >= off && cd[off..].contains(&0);
    if length < ident || (ident != 0 && !cstr(ident)) {
        return false;
    }
    let team = u(48);
    if version >= CS_SUPPORTSTEAMID && team != 0 && (length < team || !cstr(team)) {
        return false;
    }
    if version >= CS_SUPPORTSLINKAGE && cd[96] != 0 {
        let (off, size) = (u(100), u(104));
        if off.checked_add(size).is_none_or(|end| end > length) {
            return false;
        }
    }
    true
}

/// `cs_validate_csblob`: a superblob (or a bare CodeDirectory) whose
/// blobs are all inside it; the offset and length of the CodeDirectory of
/// the best hash, or EBADEXEC.
pub fn validate_csblob(b: &[u8]) -> Result<(usize, usize), crate::errno::Errno> {
    let bad = Err(super::errno::EBADEXEC);
    let blob_ok = |at: usize, room: usize| room >= 8 && be32(b, at + 4).is_some_and(|l| room >= l as usize);
    if !blob_ok(0, b.len()) {
        return bad;
    }
    let length = be32(b, 4).unwrap() as usize;
    match be32(b, 0) {
        Some(CSMAGIC_EMBEDDED_SIGNATURE) => {
            if length < 12 {
                return bad;
            }
            let count = be32(b, 8).unwrap() as usize;
            if (length - 12) / 8 < count {
                return bad;
            }
            let (mut best, mut best_rank) = (None, 0);
            let (mut ents, mut der, mut cons) = (false, false, [false; 4]);
            for n in 0..count {
                let (ty, off) = (be32(b, 12 + 8 * n).unwrap(), be32(b, 16 + 8 * n).unwrap() as usize);
                if length < off || !blob_ok(off, length - off) {
                    return bad;
                }
                let sub_len = be32(b, off + 4).unwrap() as usize;
                let magic = be32(b, off).unwrap();
                let mut once = |seen: &mut bool, want: u32| -> bool {
                    if magic != want || *seen {
                        return false;
                    }
                    *seen = true;
                    true
                };
                if ty == CSSLOT_CODEDIRECTORY || (CSSLOT_ALTERNATE_CODEDIRECTORIES..CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT).contains(&ty) {
                    let cd = &b[off..off + sub_len];
                    if !validate_cd(cd) {
                        return bad;
                    }
                    let rank = hash_rank(cd[37]);
                    if best.is_none() || rank > best_rank {
                        best = Some((off, sub_len));
                        best_rank = rank;
                    } else if rank == best_rank {
                        return bad;
                    }
                } else if ty == CSSLOT_ENTITLEMENTS {
                    if !once(&mut ents, CSMAGIC_EMBEDDED_ENTITLEMENTS) {
                        return bad;
                    }
                } else if ty == CSSLOT_DER_ENTITLEMENTS {
                    if !once(&mut der, CSMAGIC_EMBEDDED_DER_ENTITLEMENTS) {
                        return bad;
                    }
                } else if (CSSLOT_LAUNCH_CONSTRAINT_SELF..=CSSLOT_LIBRARY_CONSTRAINT).contains(&ty) {
                    let i = (ty - CSSLOT_LAUNCH_CONSTRAINT_SELF) as usize;
                    if !once(&mut cons[i], CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT) {
                        return bad;
                    }
                }
            }
            best.ok_or(super::errno::EBADEXEC)
        }
        Some(CSMAGIC_CODEDIRECTORY) => {
            if validate_cd(&b[..length]) {
                Ok((0, length))
            } else {
                bad
            }
        }
        _ => bad,
    }
}

/// `CS_CDHASH_LEN`.
pub const CDHASH_LEN: usize = 20;

/// The blob's `csb_cdhash`: its best CodeDirectory's digest by that
/// directory's own hash type (`cs_find_md`), cut to `CS_CDHASH_LEN`.
/// EBADEXEC for a blob `cs_validate_csblob` refuses.
pub fn cdhash(blob: &[u8]) -> Result<[u8; CDHASH_LEN], crate::errno::Errno> {
    use sha2::Digest;
    let (off, len) = validate_csblob(blob)?;
    let cd = &blob[off..off + len];
    // ntohl(cd->length): the directory itself, not the slot's room.
    let cd = &cd[..be32(cd, 4).unwrap_or(0) as usize];
    let digest: Vec<u8> = match cd[37] {
        1 => sha1::Sha1::digest(cd).to_vec(),
        2 | 3 => sha2::Sha256::digest(cd).to_vec(),
        4 => sha2::Sha384::digest(cd).to_vec(),
        _ => return Err(super::errno::EBADEXEC),
    };
    let mut out = [0u8; CDHASH_LEN];
    out.copy_from_slice(&digest[..CDHASH_LEN]);
    Ok(out)
}

/// `ubc_cs_blob_add`'s `csb_end_offset`: the CodeDirectory's code limit,
/// to the end of its last hashed page.
pub fn end_offset(cd: &[u8]) -> u64 {
    let limit = u64::from(be32(cd, 32).unwrap_or(0));
    let mask = (1u64 << cd[39]) - 1;
    (limit + mask) & !mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_entitlements_read_as_coreentitlements_reads_them() {
        // {"com.apple.private.memorystatus": true, "s": "x", "a": [1, false]}
        let mut d = Vec::new();
        let pair = |k: &[u8], v: &[u8]| {
            let mut p = vec![0x0c, k.len() as u8];
            p.extend_from_slice(k);
            p.extend_from_slice(v);
            let mut s = vec![0x30, p.len() as u8];
            s.extend_from_slice(&p);
            s
        };
        d.extend(pair(b"com.apple.private.memorystatus", &[0x01, 0x01, 0xff]));
        d.extend(pair(b"s", &[0x0c, 0x01, b'x']));
        d.extend(pair(b"a", &[0x30, 0x06, 0x02, 0x01, 0x01, 0x01, 0x01, 0x00]));
        let mut body = vec![0x02, 0x01, 0x01, 0xb0, d.len() as u8];
        body.extend_from_slice(&d);
        let mut b = vec![0x70, body.len() as u8];
        b.extend_from_slice(&body);
        let e = parse_der_entitlements(&b).unwrap();
        assert!(e.bool_true(b"com.apple.private.memorystatus"));
        assert!(!e.bool_true(b"s") && e.present(b"s"));
        assert_eq!(e.get(b"a"), Some(&Ent::Array(vec![Ent::Int(1), Ent::Bool(false)])));
        // A version other than 1, a trailing byte: not entitlements.
        let mut bad = b.clone();
        bad[4] = 2;
        assert!(parse_der_entitlements(&bad).is_none());
        let mut bad = b.clone();
        bad.push(0);
        assert!(parse_der_entitlements(&bad).is_none());
    }

    #[test]
    fn a_signature_gives_its_best_directorys_fields() {
        // A version 0x20400 CodeDirectory: ad hoc, SHA-256, 16 KiB pages,
        // identifier "x", a main binary, no code slots.
        let mut cd = vec![0u8; 110];
        cd[0..4].copy_from_slice(&CSMAGIC_CODEDIRECTORY.to_be_bytes());
        cd[4..8].copy_from_slice(&110u32.to_be_bytes());
        cd[8..12].copy_from_slice(&0x20400u32.to_be_bytes());
        cd[12..16].copy_from_slice(&2u32.to_be_bytes());
        cd[16..20].copy_from_slice(&110u32.to_be_bytes());
        cd[20..24].copy_from_slice(&108u32.to_be_bytes());
        cd[36] = 32;
        cd[37] = 2;
        cd[38] = 13;
        cd[39] = 14;
        cd[80..88].copy_from_slice(&1u64.to_be_bytes());
        cd[108] = b'x';
        let mut sb = Vec::new();
        sb.extend_from_slice(&CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes());
        sb.extend_from_slice(&(20 + cd.len() as u32).to_be_bytes());
        sb.extend_from_slice(&1u32.to_be_bytes());
        sb.extend_from_slice(&0u32.to_be_bytes());
        sb.extend_from_slice(&20u32.to_be_bytes());
        sb.extend_from_slice(&cd);
        let c = CodeSign::parse(&sb);
        assert_eq!((c.cd_version, c.cd_flags, c.hash_type, c.platform, c.exec_seg_flags), (0x20400, 2, 2, 13, 1));
        assert_eq!(c.identity.as_deref(), Some(&b"x"[..]));
        assert_eq!(c.cdhash, cdhash(&sb).ok());
        assert!(c.cdhash.is_some() && c.der.is_none() && c.cms.is_none());
    }
}
