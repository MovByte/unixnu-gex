//! Personas (`kern_persona.c`, `sys_persona.c`): system-wide identities,
//! each with an id (a uid), a type, a login name, an optional path and a
//! uid of its own, that processes are spawned into and keep through fork
//! and exec. A process in a persona is counted against the persona's id
//! rather than its real uid, and Sandbox and the bank read the persona of
//! the current thread.

use crate::errno::Errno;
use crate::syscalls::Kernel;
use crate::GuestMem;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// `PERSONA_ID_NONE`.
pub const ID_NONE: u32 = u32::MAX;
/// `PERSONA_MGMT_ENTITLEMENT`.
const MGMT_ENTITLEMENT: &str = "com.apple.private.persona-mgmt";
const MAX_PERSONAS: usize = 512;
const FIRST_PERSONA_ID: u32 = 501;
const PERSONA_ID_STEP: u32 = 10;
/// `MAXPATHLEN`.
const MAXPATHLEN: usize = 1024;

/// `persona_type_t`.
pub mod ty {
    pub const INVALID: i32 = 0;
    pub const SYSTEM: i32 = 4;
    pub const SYSTEM_PROXY: i32 = 6;
    pub const MAX: i32 = 8;
}

/// `PERSONA_OP_*`.
mod op {
    pub const ALLOC: u64 = 1;
    pub const PALLOC: u64 = 2;
    pub const DEALLOC: u64 = 3;
    pub const GET: u64 = 4;
    pub const INFO: u64 = 5;
    pub const PIDINFO: u64 = 6;
    pub const FIND: u64 = 7;
    pub const GETPATH: u64 = 8;
    pub const FIND_BY_TYPE: u64 = 9;
}

/// `struct kpersona_info` (packed): its version, id, type, the unused
/// gid, group count, groups and gmuid, the login name, and from version 2
/// the uid.
mod kinfo {
    pub const V1: u32 = 1;
    pub const V2: u32 = 2;
    pub const ID: usize = 4;
    pub const TYPE: usize = 8;
    pub const NAME: usize = 88;
    pub const UID: usize = 344;
    /// `offsetof(struct kpersona_info, persona_uid)` and its size.
    pub const V1_SIZE: usize = 344;
    pub const V2_SIZE: usize = 348;
}

/// `struct _posix_spawn_persona_info`: the persona, the spawn's flags, and
/// the uid, gid and groups the spawn sets in it.
#[derive(Clone, Debug)]
pub struct SpawnPersona {
    pub id: u32,
    pub flags: u32,
    pub uid: u32,
    pub gid: u32,
    pub ngroups: u32,
    pub groups: [u32; super::cred::NGROUPS],
    pub gmuid: u32,
}

/// `POSIX_SPAWN_PERSONA_UID`, `_GID`, `_GROUPS`.
mod spawn_flag {
    pub const UID: u32 = 0x0001_0000;
    pub const GID: u32 = 0x0002_0000;
    pub const GROUPS: u32 = 0x0004_0000;
}

/// `sizeof(struct _posix_spawn_persona_info)`.
pub const SPAWN_INFO_SIZE: usize = 88;

impl SpawnPersona {
    pub fn parse(b: &[u8]) -> SpawnPersona {
        let w = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let mut groups = [0; super::cred::NGROUPS];
        for (i, g) in groups.iter_mut().enumerate() {
            *g = w(20 + 4 * i);
        }
        SpawnPersona { id: w(0), flags: w(4), uid: w(8), gid: w(12), ngroups: w(16), groups, gmuid: w(84) }
    }
}

/// `struct persona`.
#[derive(Debug)]
pub struct Persona {
    pub id: u32,
    ptype: i32,
    login: Vec<u8>,
    path: Option<Vec<u8>>,
    uid: u32,
    /// `persona_valid`: in the list, not yet deallocated.
    valid: AtomicBool,
}

impl Persona {
    /// `persona_get_type`: none once it is no longer valid.
    pub fn get_type(&self) -> i32 {
        if self.valid.load(Ordering::Acquire) { self.ptype } else { ty::INVALID }
    }

    /// `persona_get_uid`.
    pub fn get_uid(&self) -> u32 {
        if self.valid.load(Ordering::Acquire) { self.uid } else { super::cred::UID_NONE }
    }

    /// `persona_is_adoption_allowed`: a system or system proxy persona.
    pub fn adoption_allowed(&self) -> bool {
        self.ptype == ty::SYSTEM || self.ptype == ty::SYSTEM_PROXY
    }

    fn valid(&self) -> bool {
        self.valid.load(Ordering::Acquire)
    }
}

/// `all_personas`, the newest first, and `g_next_persona_id`.
struct Registry {
    list: Vec<Arc<Persona>>,
    next_id: u32,
}

fn registry() -> std::sync::MutexGuard<'static, Registry> {
    static R: Mutex<Registry> = Mutex::new(Registry { list: Vec::new(), next_id: FIRST_PERSONA_ID });
    R.lock().unwrap_or_else(|e| e.into_inner())
}

/// `persona_lookup`: the valid persona of id `id`.
pub fn lookup(id: u32) -> Option<Arc<Persona>> {
    registry().list.iter().find(|p| p.id == id && p.valid()).cloned()
}

/// `persona_find_all`: the personas matching every one of the login, the
/// id and the type given (at least one), the first `cap` of them, and how
/// many match.
fn find_all(login: Option<&[u8]>, uid: u32, ptype: i32, cap: usize) -> Result<(Vec<Arc<Persona>>, usize), (Errno, Option<usize>)> {
    let mut want = 0;
    if login.is_some() {
        want += 1;
    }
    if uid != ID_NONE {
        want += 1;
    }
    if ptype > ty::INVALID && ptype <= ty::MAX {
        want += 1;
    } else if ptype != ty::INVALID {
        return Err((Errno::EINVAL, None));
    }
    if want == 0 {
        return Err((Errno::EINVAL, None));
    }
    let r = registry();
    let mut out = Vec::new();
    let mut found = 0;
    for p in &r.list {
        let mut m = 0;
        if login.is_some_and(|l| l == p.login.as_slice()) {
            m += 1;
        }
        if uid != ID_NONE && uid == p.id {
            m += 1;
        }
        if ptype != ty::INVALID && ptype == p.ptype {
            m += 1;
        }
        if m == want {
            if cap > found {
                out.push(Arc::clone(p));
            }
            found += 1;
        }
    }
    if found == 0 {
        return Err((Errno::ESRCH, Some(0)));
    }
    Ok((out, found))
}

/// `kpersona_copyin`: the caller's `kpersona_info` of its version (V1's
/// has no uid: none), its name cut to MAXLOGNAME.
fn kpersona_copyin(m: &GuestMem<'_>, infop: u64) -> Result<Vec<u8>, Errno> {
    let v = m.read_u32(infop).map_err(|_| Errno::EFAULT)?;
    let size = match v {
        kinfo::V1 => kinfo::V1_SIZE,
        kinfo::V2 => kinfo::V2_SIZE,
        _ => return Err(Errno::EINVAL),
    };
    let mut k = vec![0u8; kinfo::V2_SIZE];
    k[kinfo::UID..kinfo::UID + 4].copy_from_slice(&super::cred::UID_NONE.to_le_bytes());
    k[..size].copy_from_slice(m.read(infop, size).map_err(|_| Errno::EFAULT)?);
    k[kinfo::NAME + super::cred::MAXLOGNAME] = 0;
    Ok(k)
}

/// `kpersona_copyout`: `k` as the version the caller's structure has.
fn kpersona_copyout(m: &mut GuestMem<'_>, k: &[u8], infop: u64) -> Result<(), Errno> {
    let v = m.read_u32(infop).map_err(|_| Errno::EFAULT)?;
    let size = match v {
        kinfo::V1 => kinfo::V1_SIZE,
        kinfo::V2 => kinfo::V2_SIZE,
        _ => return Err(Errno::EINVAL),
    };
    let mut k = k.to_vec();
    k[..4].copy_from_slice(&v.to_le_bytes());
    m.write(infop, &k[..size]).map_err(|_| Errno::EFAULT)
}

/// `kpersona_populate`: a version 2 `kpersona_info` of `p`.
fn populate(p: &Persona) -> Vec<u8> {
    let mut k = vec![0u8; kinfo::V2_SIZE];
    k[..4].copy_from_slice(&kinfo::V2.to_le_bytes());
    k[kinfo::ID..kinfo::ID + 4].copy_from_slice(&p.id.to_le_bytes());
    k[kinfo::TYPE..kinfo::TYPE + 4].copy_from_slice(&p.ptype.to_le_bytes());
    k[kinfo::UID..kinfo::UID + 4].copy_from_slice(&p.uid.to_le_bytes());
    let n = p.login.len().min(super::cred::MAXLOGNAME);
    k[kinfo::NAME..kinfo::NAME + n].copy_from_slice(&p.login[..n]);
    k
}

fn le32(k: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(k[o..o + 4].try_into().unwrap())
}

/// The login name in a `kpersona_info`: none when empty.
fn login_of(k: &[u8]) -> Option<Vec<u8>> {
    let name = &k[kinfo::NAME..kinfo::NAME + super::cred::MAXLOGNAME + 1];
    let n = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    (n != 0).then(|| name[..n].to_vec())
}

impl Kernel {
    /// `persona(operation, flags, info, id, idlen, path)`.
    pub(crate) fn darwin_persona(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        let (operation, infop, idp, idlenp, path) = (a[0] as u32 as u64, a[2], a[3], a[4], a[5]);
        match operation {
            op::ALLOC => self.kpersona_alloc(m, infop, idp, 0),
            op::PALLOC => self.kpersona_alloc(m, infop, idp, path),
            op::DEALLOC => self.kpersona_dealloc(m, idp),
            op::GET => {
                let p = lookup(self.darwin_current_persona_id()).ok_or(Errno::ESRCH)?;
                m.write_u32(idp, p.id).map_err(|_| Errno::EFAULT)
            }
            op::GETPATH => {
                if path == 0 {
                    return Err(Errno::EINVAL);
                }
                let p = self.kpersona_lookup_asked(m, idp)?;
                match &p.path {
                    Some(s) => {
                        let mut b = s[..s.len().min(MAXPATHLEN - 1)].to_vec();
                        b.push(0);
                        m.write(path, &b).map_err(|_| Errno::EFAULT)
                    }
                    None => Ok(()),
                }
            }
            op::INFO => {
                let p = self.kpersona_lookup_asked(m, idp)?;
                kpersona_copyout(m, &populate(&p), infop)
            }
            op::PIDINFO => {
                let pid = m.read_u32(idp).map_err(|_| Errno::EFAULT)? as i32;
                if self.dtask.cred.uid != 0 && pid != self.pid {
                    return Err(Errno::EPERM);
                }
                let p = self.darwin_persona_of(pid).ok_or(Errno::ESRCH)?;
                kpersona_copyout(m, &populate(&p), infop)
            }
            op::FIND | op::FIND_BY_TYPE => self.kpersona_find(m, infop, idp, idlenp),
            _ => Err(Errno::ENOSYS),
        }
        .map(|()| 0)
    }

    /// `kpersona_alloc_syscall`: a new persona, by the persona manager; its
    /// id the one asked for, or the next free from 501 in steps of 10. The
    /// login and the id must be unused.
    fn kpersona_alloc(&mut self, m: &mut GuestMem<'_>, infop: u64, idp: u64, path: u64) -> Result<(), Errno> {
        if !self.darwin_task_entitled(MGMT_ENTITLEMENT) {
            return Err(Errno::EPERM);
        }
        let mut k = kpersona_copyin(m, infop)?;
        let login = login_of(&k);
        let asked = le32(&k, kinfo::ID);
        let id = if asked != ID_NONE && asked != 0 { asked } else { ID_NONE };
        let path = if path != 0 { Some(super::exec::copyinstr(m, path, MAXPATHLEN)?) } else { None };
        // persona_alloc.
        let Some(login) = login else { return Err(Errno::EINVAL) };
        let ptype = le32(&k, kinfo::TYPE) as i32;
        if ptype <= ty::INVALID || ptype > ty::MAX {
            return Err(Errno::EINVAL);
        }
        let mut r = registry();
        if r.list.len() + 1 > MAX_PERSONAS {
            return Err(Errno::EBUSY);
        }
        // persona_init_begin.
        let mut pid = id;
        'again: loop {
            if id == ID_NONE {
                pid = r.next_id;
            }
            for t in &r.list {
                if id == ID_NONE && t.id == pid {
                    r.next_id = r.next_id.wrapping_add(PERSONA_ID_STEP);
                    continue 'again;
                }
                if t.login == login || t.id == pid {
                    return Err(Errno::EEXIST);
                }
            }
            break;
        }
        if id == ID_NONE {
            r.next_id = r.next_id.wrapping_add(PERSONA_ID_STEP);
        }
        let uid = le32(&k, kinfo::UID);
        let persona = Arc::new(Persona { id: pid, ptype, login, path, uid, valid: AtomicBool::new(true) });
        m.write_u32(idp, pid).map_err(|_| Errno::EFAULT)?;
        k[kinfo::ID..kinfo::ID + 4].copy_from_slice(&pid.to_le_bytes());
        kpersona_copyout(m, &k, infop)?;
        // persona_init_end.
        r.list.insert(0, persona);
        Ok(())
    }

    /// `kpersona_dealloc_syscall`: the persona invalidated, so no process
    /// is spawned into it again (those in it keep it).
    fn kpersona_dealloc(&mut self, m: &GuestMem<'_>, idp: u64) -> Result<(), Errno> {
        if !self.darwin_task_entitled(MGMT_ENTITLEMENT) {
            return Err(Errno::EPERM);
        }
        let id = m.read_u32(idp).map_err(|_| Errno::EFAULT)?;
        // persona_lookup_and_invalidate.
        let mut r = registry();
        let at = r.list.iter().position(|p| p.id == id).ok_or(Errno::ESRCH)?;
        if !r.list[at].valid() {
            return Err(Errno::ESRCH);
        }
        let p = r.list.remove(at);
        p.valid.store(false, Ordering::Release);
        Ok(())
    }

    /// The persona `kpersona_info_syscall` and `kpersona_getpath_syscall`
    /// look up: the current one, or another (by root or the persona
    /// manager).
    fn kpersona_lookup_asked(&mut self, m: &GuestMem<'_>, idp: u64) -> Result<Arc<Persona>, Errno> {
        let id = m.read_u32(idp).map_err(|_| Errno::EFAULT)?;
        let mut look = self.darwin_current_persona_id();
        if id != 0 && id != look {
            if self.dtask.cred.uid != 0 && !self.darwin_task_entitled(MGMT_ENTITLEMENT) {
                return Err(Errno::EPERM);
            }
            look = id;
        }
        lookup(look).ok_or(Errno::ESRCH)
    }

    /// `kpersona_find_syscall`: the ids of the personas the caller's
    /// `kpersona_info` matches, as many as `*idlenp` (at most 512), and how
    /// many matched in `*idlenp`.
    fn kpersona_find(&mut self, m: &mut GuestMem<'_>, infop: u64, idp: u64, idlenp: u64) -> Result<(), Errno> {
        let u_idlen = (m.read_u64(idlenp).map_err(|_| Errno::EFAULT)? as usize).min(MAX_PERSONAS);
        let mut k_idlen = u_idlen;
        let r = (|| {
            let k = match kpersona_copyin(m, infop) {
                Ok(k) => k,
                Err(e) => {
                    k_idlen = 0;
                    return Err(e);
                }
            };
            let login = login_of(&k);
            let (found, n) = match find_all(login.as_deref(), le32(&k, kinfo::ID), le32(&k, kinfo::TYPE) as i32, u_idlen) {
                Ok(f) => f,
                Err((e, n)) => {
                    if let Some(n) = n {
                        k_idlen = n;
                    }
                    return Err(e);
                }
            };
            k_idlen = n;
            for (i, p) in found.iter().enumerate().take(u_idlen) {
                m.write_u32(idp + 4 * i as u64, p.id).map_err(|_| Errno::EFAULT)?;
            }
            Ok(())
        })();
        let _ = m.write_u64(idlenp, k_idlen as u64);
        r
    }

    /// `current_persona_get_id`: the persona of the current thread's
    /// voucher's bank, or else of the process; none without one.
    pub(crate) fn darwin_current_persona_id(&mut self) -> u32 {
        if let Some(v) = self.dtask.threads.map.get(&self.tid).and_then(|t| t.voucher) {
            return self.darwin_bank_persona_id(v);
        }
        self.dtask.persona.as_ref().map_or(ID_NONE, |p| p.id)
    }

    /// `current_persona_get`: the current persona, while it is valid.
    pub(crate) fn darwin_current_persona(&mut self) -> Option<Arc<Persona>> {
        lookup(self.darwin_current_persona_id())
    }

    /// `persona_proc_get`: process `pid`'s persona, valid or not.
    fn darwin_persona_of(&self, pid: i32) -> Option<Arc<Persona>> {
        if pid == self.pid {
            return self.dtask.persona.clone();
        }
        // proc_find: not a zombie.
        let (r, zombie) = self.procs.darwin(pid)?;
        if zombie {
            return None;
        }
        r.downcast::<super::procinfo::Public>().ok()?.persona.clone()
    }

    /// The persona a new proc made from this one takes (forkproc's
    /// `persona_proc_adopt`), if this one has one: it must still be valid
    /// (EINVAL), and its id's count, with `extra` processes the caller has
    /// counted against the real uid meanwhile, within RLIMIT_NPROC
    /// (EACCES).
    pub(crate) fn darwin_persona_inherit(&self, extra: u64) -> Result<Option<u32>, Errno> {
        let Some(p) = self.dtask.persona.as_ref() else { return Ok(None) };
        if !p.valid() {
            return Err(Errno::EINVAL);
        }
        let mut count = self.procs.counts(p.id).1 as u64;
        if self.dtask.cred.ruid == p.id {
            count += extra;
        }
        if p.id != 0 && count > self.dtask.rlimits.cur(super::rlimit::res::NPROC) {
            return Err(Errno::EACCES);
        }
        Ok(Some(p.id))
    }

    /// `spawn_validate_persona`: a spawn into a persona is the persona
    /// manager's, of an existing persona, with at most NGROUPS groups, and
    /// only root's may make the ids 0.
    pub(crate) fn darwin_spawn_validate_persona(&mut self, sp: &SpawnPersona) -> Result<(), Errno> {
        if !self.darwin_task_entitled(MGMT_ENTITLEMENT) {
            return Err(Errno::EPERM);
        }
        if sp.flags & spawn_flag::GROUPS != 0 && sp.ngroups as usize > super::cred::NGROUPS {
            return Err(Errno::EINVAL);
        }
        lookup(sp.id).ok_or(Errno::ESRCH)?;
        if self.dtask.cred.uid != 0 && (sp.uid == 0 || sp.gid == 0) {
            return Err(Errno::EPERM);
        }
        Ok(())
    }

    /// `spawn_persona_adopt`: this process (a spawn's child) into the
    /// spawn's persona, its credential the uid, gid and groups the spawn
    /// gave.
    pub(crate) fn darwin_spawn_persona_adopt(&mut self, sp: &SpawnPersona) -> Result<(), Errno> {
        let p = lookup(sp.id).ok_or(Errno::ESRCH)?;
        self.darwin_persona_adopt(p, Some(sp))
    }

    /// `persona_proc_adopt`: this process into `persona` (a valid one),
    /// counted against the persona's id from now on unless that would pass
    /// its RLIMIT_NPROC (EACCES); with a spawn's ids, its credential
    /// changed as `kauth_cred_proc_update` changes it.
    pub(crate) fn darwin_persona_adopt(&mut self, persona: Arc<Persona>, derive: Option<&SpawnPersona>) -> Result<(), Errno> {
        if !persona.valid() {
            return Err(Errno::EINVAL);
        }
        // proc_set_persona_internal.
        if self.dtask.persona.as_ref().is_some_and(|p| Arc::ptr_eq(p, &persona)) {
            return Ok(());
        }
        let new_uid = persona.id;
        let nproc = self.dtask.rlimits.cur(super::rlimit::res::NPROC);
        if new_uid != 0 && self.procs.counts(new_uid).1 as u64 > nproc {
            return Err(Errno::EACCES);
        }
        if let Some(sp) = derive {
            let c = &mut self.dtask.cred;
            let mut updated = false;
            if sp.flags & spawn_flag::UID != 0 {
                updated |= c.setresuid(sp.uid, sp.uid, sp.uid, super::cred::UID_NONE);
            }
            if sp.flags & spawn_flag::GID != 0 {
                updated |= c.setresgid(sp.gid, sp.gid, sp.gid);
            }
            if sp.flags & spawn_flag::GROUPS != 0 {
                updated |= c.setgroups(&sp.groups[..sp.ngroups as usize], sp.gmuid);
            }
            if updated {
                self.darwin_cred_changed();
            }
        }
        self.procs.set_persona(self.pid, Some(new_uid));
        self.dtask.persona = Some(persona);
        // (A multi-user device copies the persona's login into the session;
        // MULTIUSER_CONFIG is never set here, host_set_multiuser_config_flags
        // not being served.)
        Ok(())
    }
}
