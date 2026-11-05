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

/// The parts of a signature the kernel reads.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CodeSign {
    /// The CodeDirectory's `platform`: zero for a program that is not a
    /// platform binary.
    pub platform: u8,
    pub cd_flags: u32,
    /// The entitlements' XML property list.
    pub entitlements: Option<String>,
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

    /// Read an `LC_CODE_SIGNATURE` superblob; what is malformed or absent
    /// reads as no CodeDirectory and no entitlements.
    pub fn parse(blob: &[u8]) -> CodeSign {
        let mut cs = CodeSign::default();
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
                (CSSLOT_CODEDIRECTORY, CSMAGIC_CODEDIRECTORY) => {
                    cs.cd_flags = be32(b, 12).unwrap_or(0);
                    cs.platform = b.get(38).copied().unwrap_or(0);
                }
                (CSSLOT_ENTITLEMENTS, CSMAGIC_EMBEDDED_ENTITLEMENTS) => {
                    cs.entitlements = Some(String::from_utf8_lossy(&b[8..]).into_owned());
                }
                _ => {}
            }
        }
        cs
    }

    /// Whether the top-level entitlement `name` is the boolean true
    /// (`IOTaskHasEntitlement`).
    pub fn entitled(&self, name: &str) -> bool {
        let Some(xml) = &self.entitlements else { return false };
        // Walk the property list's tags, keeping the depth of dicts and
        // arrays: a key at the top-level dict's depth names an entitlement,
        // its value the next element.
        let mut depth = 0i32;
        let mut rest = xml.as_str();
        let mut pending: Option<String> = None;
        while let Some(lt) = rest.find('<') {
            rest = &rest[lt..];
            let Some(gt) = rest.find('>') else { break };
            let tag = &rest[1..gt];
            rest = &rest[gt + 1..];
            if tag.starts_with('?') || tag.starts_with('!') {
                continue;
            }
            match tag.trim_end_matches('/').trim() {
                "dict" | "array" if !tag.ends_with('/') => {
                    if depth == 1 {
                        pending = None;
                    }
                    depth += 1;
                }
                "/dict" | "/array" => depth -= 1,
                "key" if depth == 1 => {
                    let end = rest.find("</key>").unwrap_or(rest.len());
                    pending = Some(rest[..end].to_string());
                    rest = &rest[end..];
                }
                "/key" | "plist" | "/plist" => {}
                t if depth == 1 && pending.is_some() && !t.starts_with('/') => {
                    if pending.take().as_deref() == Some(name) {
                        return t == "true" && tag.ends_with('/');
                    }
                }
                _ => {}
            }
        }
        false
    }
}

/// The signatures added to each vnode (`ubc_cs_blob_add`): where each
/// slice starts in the file, and the range its signature covers.
fn blobs() -> &'static std::sync::Mutex<std::collections::HashMap<(u64, u64), Vec<(i64, u64, u64)>>> {
    static B: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<(u64, u64), Vec<(i64, u64, u64)>>>> = std::sync::OnceLock::new();
    B.get_or_init(Default::default)
}

/// `ubc_cs_blob_add` of a validated blob for the slice at `file_start`:
/// kept on the vnode, or the one already there for that slice found. The
/// end of the range it covers (`csb_end_offset`).
pub fn register_blob(vnode: (u64, u64), file_start: i64, b: &[u8]) -> Result<u64, crate::errno::Errno> {
    let mut all = blobs().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(&(_, _, end)) = all.get(&vnode).and_then(|v| v.iter().find(|&&(base, start, end)| file_start >= base + start as i64 && file_start < base + end as i64)) {
        return Ok(end);
    }
    let (cd_at, cd_len) = validate_csblob(b)?;
    let cd = &b[cd_at..cd_at + cd_len];
    let end = end_offset(cd);
    // csb_start_offset: the first scattered page, if scattered.
    let scatter = be32(cd, 44).unwrap_or(0) as usize;
    let start = if be32(cd, 8).unwrap_or(0) >= CS_SUPPORTSSCATTER && scatter != 0 { u64::from(be32(cd, scatter + 4).unwrap_or(0)) << cd[39] } else { 0 };
    all.entry(vnode).or_default().push((file_start, start, end));
    Ok(end)
}

/// `ubc_cs_is_range_codesigned`: one blob on the vnode covers the whole
/// of `[start, start + size)`, the one whose range holds `start`.
pub fn range_codesigned(vnode: (u64, u64), start: u64, size: u64) -> bool {
    if size == 0 || start.checked_add(size).is_none() {
        return false;
    }
    let all = blobs().lock().unwrap_or_else(|e| e.into_inner());
    let Some(&(base, bstart, bend)) = all.get(&vnode).and_then(|v| {
        v.iter().find(|&&(base, s, e)| start as i64 >= base + s as i64 && (start as i64) < base + e as i64)
    }) else {
        return false;
    };
    let (lo, hi) = ((base + bstart as i64) as u64, (base + bend as i64) as u64);
    lo <= start && start + size <= hi
}

/// `CS_MAX_BLOB_SIZE`.
const CS_MAX_BLOB_SIZE: u64 = 40 * 1024 * 1024;

impl Kernel {
    /// fcntl's F_ADDSIGS, F_ADDFILESIGS and F_ADDFILESIGS_RETURN: the
    /// signature of the slice at `fs_file_start`, from memory or from the
    /// file, checked as `cs_validate_csblob` checks it and kept on the vnode
    /// (found again, not added twice); for F_ADDFILESIGS_RETURN the end of
    /// the range it covers. No MAC policy is loaded to judge it further.
    pub(crate) fn darwin_addsigs(&mut self, m: &mut GuestMem<'_>, fd: i32, cmd: u64, argp: u64) -> Result<u64, crate::errno::Errno> {
        use crate::errno::Errno;
        const F_ADDSIGS: u64 = 59;
        const F_ADDFILESIGS_RETURN: u64 = 97;
        let file = self.fds.get(fd)?;
        let Some(vnode) = self.darwin_vnode_of(&file) else { return Err(Errno::EBADF) };
        let file_start = m.read_u64(argp)? as i64;
        let blob_start = m.read_u64(argp + 8)?;
        let blob_size = m.read_u64(argp + 16)?;
        let found = blobs().lock().unwrap_or_else(|e| e.into_inner()).get(&vnode).and_then(|v| {
            v.iter().find(|&&(base, start, end)| file_start >= base + start as i64 && file_start < base + end as i64).copied()
        });
        let end = match found {
            Some((_, _, end)) => end,
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
                register_blob(vnode, file_start, &b)?
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

    /// `task_get_platform_binary`: the CodeDirectory names a platform. (AMFI
    /// takes it from the trust cache the binary is in; Apple's signing sets
    /// the field for exactly those binaries.)
    pub(crate) fn darwin_task_platform_binary(&self) -> bool {
        self.dtask.codesign.as_ref().is_some_and(|c| c.platform != 0)
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
const CSSLOT_DER_ENTITLEMENTS: u32 = 7;
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
    fn a_top_level_true_key_is_an_entitlement() {
        let cs = CodeSign {
            entitlements: Some(
                "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>a</key><true/><key>b</key><false/><key>c</key><dict><key>d</key><true/></dict><key>e</key><string>x</string></dict></plist>".into(),
            ),
            ..CodeSign::default()
        };
        assert!(cs.entitled("a"));
        assert!(!cs.entitled("b"));
        assert!(!cs.entitled("d"));
        assert!(!cs.entitled("e"));
        assert!(!cs.entitled("z"));
    }

    #[test]
    fn a_signature_gives_its_platform_byte() {
        // A superblob with one CodeDirectory whose platform byte is 13.
        let mut cd = vec![0u8; 44];
        cd[0..4].copy_from_slice(&CSMAGIC_CODEDIRECTORY.to_be_bytes());
        cd[4..8].copy_from_slice(&44u32.to_be_bytes());
        cd[38] = 13;
        let mut sb = Vec::new();
        sb.extend_from_slice(&CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes());
        sb.extend_from_slice(&(20 + 44u32).to_be_bytes());
        sb.extend_from_slice(&1u32.to_be_bytes());
        sb.extend_from_slice(&0u32.to_be_bytes());
        sb.extend_from_slice(&20u32.to_be_bytes());
        sb.extend_from_slice(&cd);
        assert_eq!(CodeSign::parse(&sb).platform, 13);
    }
}
