//! POSIX shared memory: `shm_open` and `shm_unlink`, and what is done with
//! the object they name (`bsd/kern/posix_shm.c`, xnu-10063.141.1).
//!
//! The names live in one table for the host process. An object is only
//! the bytes behind a descriptor, kept in a [`MemFd`]: a `MAP_SHARED`
//! mapping of it is the same eager copy a memfd's is, written back at
//! `msync` and `munmap`, so two processes that map one see each other's
//! writes only then.

use super::cred::Cred;
use crate::errno::{Errno, SysResult};
use crate::file::OpenFile;
use crate::syscalls::Kernel;
use crate::unix::MemFd;
use crate::vfs::{FileHandle, FileType, Metadata};
use crate::GuestMem;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// `PSHMNAMLEN`: a name is at most this many bytes, and the string with its
/// NUL fits in one more.
pub const PSHMNAMLEN: usize = 31;

/// `FREAD` and `FWRITE`, the kernel's spelling of the access mode.
const FREAD: u32 = 1;
const FWRITE: u32 = 2;

/// Darwin's `O_CREAT`, `O_TRUNC` and `O_EXCL`.
const O_TRUNC: u32 = 0x400;
const O_CREAT: u32 = 0x200;
const O_EXCL: u32 = 0x800;

/// `ALLPERMS`.
const ALLPERMS: u32 = 0o7777;

/// The page `ftruncate` rounds a size up to, and `mmap` bounds against.
const PAGE: u64 = 4096;

/// What the kernel can hold of one object: past this a size is refused as
/// the address space for it is (`ENOMEM`).
const MAX_SIZE: u64 = 1 << 32;

/// A POSIX shared memory object (`pshm_info_t`).
#[derive(Debug)]
pub struct Pshm {
    pub name: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// The process that made it.
    pub creator: i32,
    /// `pshm_length`; `None` until `ftruncate` allocates it (`PSHM_ALLOCATED`).
    length: Mutex<Option<u64>>,
    store: MemFd,
}

impl Pshm {
    fn new(name: &str, mode: u32, uid: u32, gid: u32, creator: i32) -> Pshm {
        Pshm { name: name.to_string(), mode, uid, gid, creator, length: Mutex::new(None), store: MemFd::new(name) }
    }

    pub fn length(&self) -> u64 {
        self.length.lock().unwrap().unwrap_or(0)
    }

    pub fn allocated(&self) -> bool {
        self.length.lock().unwrap().is_some()
    }

    /// `pshm_truncate`: the one allocation an object gets. The size is
    /// rounded up to a page; a second call, or one for a size too large for
    /// the memory, fails.
    pub fn allocate(&self, length: u64) -> Result<(), Errno> {
        let mut cur = self.length.lock().unwrap();
        if cur.is_some() {
            return Err(Errno::EINVAL);
        }
        let total = length.checked_add(PAGE - 1).ok_or(Errno::ENOMEM)? & !(PAGE - 1);
        if total > MAX_SIZE {
            return Err(Errno::ENOMEM);
        }
        *cur = Some(total);
        Ok(())
    }
}

/// `pshm_access`: whether the caller may open the object for `fmode`
/// (`FREAD`, `FWRITE`). Root always may; anyone else as `posix_cred_access`
/// says.
fn access(p: &Pshm, fmode: u32, cred: &Cred) -> Result<(), Errno> {
    if cred.uid == 0 {
        return Ok(());
    }
    let req = (if fmode & FREAD != 0 { 0o400 } else { 0 }) | (if fmode & FWRITE != 0 { 0o200 } else { 0 });
    super::cred::posix_cred_access(cred, p.uid, p.gid, p.mode, req)
}

/// The names (`pshm_head`).
#[derive(Debug, Default)]
pub struct Names {
    by_name: Mutex<BTreeMap<String, Arc<Pshm>>>,
}

impl Names {
    pub const fn new() -> Names {
        Names { by_name: Mutex::new(BTreeMap::new()) }
    }

    /// The object `shm_open(name, oflag, mode)` opens, and whether it was
    /// made by the call. `fmode` is `FFLAGS(oflag)`.
    fn open(&self, name: &str, fmode: u32, mode: u32, cred: &Cred, pid: i32) -> Result<(Arc<Pshm>, bool), Errno> {
        let mut names = self.by_name.lock().unwrap();
        match names.get(name) {
            Some(p) => {
                if fmode & (O_CREAT | O_EXCL) == (O_CREAT | O_EXCL) {
                    return Err(Errno::EEXIST);
                }
                // Truncating an object that has been given a size is refused.
                if fmode & O_TRUNC != 0 && p.allocated() {
                    return Err(Errno::EINVAL);
                }
                access(p, fmode, cred)?;
                Ok((Arc::clone(p), false))
            }
            None => {
                if fmode & O_CREAT == 0 {
                    return Err(Errno::ENOENT);
                }
                let p = Arc::new(Pshm::new(name, mode & ALLPERMS, cred.uid, cred.groups.first().copied().unwrap_or(0), pid));
                names.insert(name.to_string(), Arc::clone(&p));
                Ok((p, true))
            }
        }
    }

    /// `shm_unlink`: the name goes; the object lives while it is open.
    fn unlink(&self, name: &str, cred: &Cred) -> Result<(), Errno> {
        let mut names = self.by_name.lock().unwrap();
        let p = names.get(name).ok_or(Errno::ENOENT)?;
        if let Err(e) = access(p, FWRITE, cred) {
            if p.uid != cred.uid {
                return Err(e);
            }
        }
        names.remove(name);
        Ok(())
    }
}

/// The host process's names.
static NAMES: Names = Names::new();

/// The descriptor of an object: `DTYPE_PSXSHM`, which has no `read` or
/// `write` ([`Kernel::darwin_shm_fd`]).
#[derive(Debug)]
pub struct PshmHandle(pub Arc<Pshm>);

impl FileHandle for PshmHandle {
    fn as_posix_shm(self: Arc<Self>) -> Option<Arc<Pshm>> {
        Some(Arc::clone(&self.0))
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> SysResult {
        self.0.store.read_at(offset, buf)
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> SysResult {
        self.0.store.write_at(offset, buf)
    }

    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(Metadata {
            file_type: FileType::Regular,
            size: self.0.length(),
            mode: self.0.mode,
            ino: 0,
            mtime: 0,
            nlink: 1,
            rdev: 0,
            times: Default::default(),
        })
    }

    fn truncate(&self, len: u64) -> Result<(), Errno> {
        self.0.allocate(len)
    }
}

/// `shm_open`'s name: `copyinstr` into `PSHMNAMLEN + 1` bytes, and not empty.
fn get_name(m: &GuestMem<'_>, addr: u64) -> Result<String, Errno> {
    let raw = m.read_cstr(addr, PSHMNAMLEN + 1)?;
    if raw.is_empty() {
        return Err(Errno::EINVAL);
    }
    // The table compares bytes; a name that is not UTF-8 is kept as its
    // lossy spelling, which cannot collide with another that is.
    Ok(raw.iter().map(|&b| char::from(b)).collect())
}

impl Kernel {
    /// Whether `fd` is a shared memory object.
    pub(crate) fn darwin_shm_fd(&self, fd: u64) -> bool {
        self.fd_io().fds.get(fd as i32).is_ok_and(|f| Arc::clone(&f.handle).as_posix_shm().is_some())
    }

    /// `read` or `write` on an object: the descriptor has to be open that
    /// way, and then it has no such operation (`fo_no_read`, `fo_no_write`).
    pub(crate) fn darwin_shm_io(&self, fd: u64, write: bool) -> Errno {
        match self.fd_io().fds.get(fd as i32) {
            Ok(f) if (write && !f.writable) || (!write && !f.readable) => Errno::EBADF,
            _ => Errno::ENXIO,
        }
    }

    /// `shm_open(name, oflag, mode)`.
    pub(crate) fn darwin_shm_open(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        let name = get_name(m, a[0])?;
        let oflag = a[1] as u32;
        // `FFLAGS`: the access mode is one more than it was.
        let fmode = oflag.wrapping_add(1);
        if fmode & (FREAD | FWRITE) == 0 {
            return Err(Errno::EINVAL);
        }
        let (p, made) = NAMES.open(&name, fmode, a[2] as u32 & ALLPERMS, &self.dtask.cred, self.pid)?;
        if !made && p.creator != self.pid {
            self.darwin_unimplemented(format!(
                "shm_open {name:?}: the object is also held by process {}; their mappings of it agree only at msync and munmap",
                p.creator
            ));
        }
        let handle: Arc<dyn FileHandle> = Arc::new(PshmHandle(p));
        let file = OpenFile::new(handle, format!("/shm:{name}"), 0, fmode & FREAD != 0, fmode & FWRITE != 0);
        // Close-on-exec, as `FP_CLOEXEC`.
        self.fd_io().fds.insert(file, true).map(|fd| fd as u64)
    }

    /// `shm_unlink(name)`: any failure of the name is `EINVAL`.
    pub(crate) fn darwin_shm_unlink(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        let name = get_name(m, a[0]).map_err(|_| Errno::EINVAL)?;
        NAMES.unlink(&name, &self.dtask.cred).map(|_| 0)
    }

    /// `ftruncate(fd, length)` on an object (`pshm_truncate`).
    pub(crate) fn darwin_shm_ftruncate(&mut self, a: &[u64; 6]) -> Result<u64, Errno> {
        if (a[1] as i64) < 0 {
            return Err(Errno::EINVAL);
        }
        let f = self.fd_io().fds.get(a[0] as i32)?;
        f.handle.truncate(a[1]).map(|_| 0)
    }

    /// The checks `pshm_mmap` makes of a mapping of an object, before the
    /// mapping is made the ordinary way: `Ok` to go on.
    pub(crate) fn darwin_shm_mmap_check(&mut self, a: &[u64; 6]) -> Result<(), Errno> {
        const MAP_SHARED: u64 = 1;
        const PROT_WRITE: u64 = 2;
        let f = self.fd_io().fds.get(a[4] as i32)?;
        let Some(shm) = Arc::clone(&f.handle).as_posix_shm() else { return Ok(()) };
        let (len, prot, flags, pos) = (a[1], a[2], a[3], a[5]);
        // `mmap` has split a position off the page it is in and added it to
        // the length before `pshm_mmap` sees either.
        let pageoff = pos & (PAGE - 1);
        let pos = pos - pageoff;
        let size = len.checked_add(pageoff).ok_or(Errno::EINVAL)?;
        let size = size.checked_add(PAGE - 1).ok_or(Errno::EINVAL)? & !(PAGE - 1);
        if size == 0 {
            return Ok(());
        }
        if flags & MAP_SHARED == 0 {
            return Err(Errno::EINVAL);
        }
        if !f.writable && prot & PROT_WRITE != 0 {
            return Err(Errno::EPERM);
        }
        if !shm.allocated() {
            return Err(Errno::EINVAL);
        }
        let end = size.checked_add(pos).ok_or(Errno::EINVAL)?;
        if size > shm.length() || end > shm.length() {
            return Err(Errno::EINVAL);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RW: u32 = FREAD | FWRITE;

    fn open(n: &Names, name: &str, fmode: u32, mode: u32) -> Result<(Arc<Pshm>, bool), Errno> {
        n.open(name, fmode, mode, &Cred::of(501, 20), 7)
    }

    #[test]
    fn a_name_is_made_found_and_refused_as_posix_says() {
        let n = Names::new();
        assert_eq!(open(&n, "/a", RW, 0o600).unwrap_err(), Errno::ENOENT);
        let (a, made) = open(&n, "/a", RW | O_CREAT, 0o640).unwrap();
        assert!(made);
        assert_eq!((a.mode, a.uid, a.gid), (0o640, 501, 20));
        let (b, made) = open(&n, "/a", RW | O_CREAT, 0o600).unwrap();
        assert!(!made && Arc::ptr_eq(&a, &b));
        assert_eq!(open(&n, "/a", RW | O_CREAT | O_EXCL, 0o600).unwrap_err(), Errno::EEXIST);
        // the mode is cut to the permission bits
        let (c, _) = open(&n, "/c", RW | O_CREAT, 0o170777).unwrap();
        assert_eq!(c.mode, 0o7777 & 0o170777);
    }

    #[test]
    fn truncation_of_a_sized_object_is_refused_and_one_size_is_given() {
        let n = Names::new();
        let (a, _) = open(&n, "x", RW | O_CREAT, 0o600).unwrap();
        // not sized yet: O_TRUNC is fine
        open(&n, "x", RW | O_TRUNC, 0).unwrap();
        a.allocate(100).unwrap();
        assert_eq!(a.length(), 4096);
        assert_eq!(a.allocate(100), Err(Errno::EINVAL));
        assert_eq!(open(&n, "x", RW | O_TRUNC, 0).unwrap_err(), Errno::EINVAL);
        let (b, _) = open(&n, "y", RW | O_CREAT, 0o600).unwrap();
        assert_eq!(b.allocate(MAX_SIZE + 1), Err(Errno::ENOMEM));
        assert_eq!(b.allocate(u64::MAX), Err(Errno::ENOMEM));
        assert!(!b.allocated());
        b.allocate(0).unwrap();
        assert_eq!(b.length(), 0);
    }

    #[test]
    fn unlink_removes_the_name_and_leaves_the_object() {
        let n = Names::new();
        let (a, _) = open(&n, "x", RW | O_CREAT, 0o600).unwrap();
        n.unlink("x", &Cred::of(501, 20)).unwrap();
        assert_eq!(n.unlink("x", &Cred::of(501, 20)).unwrap_err(), Errno::ENOENT);
        assert_eq!(open(&n, "x", RW, 0).unwrap_err(), Errno::ENOENT);
        // the object is still there for whoever holds it
        a.allocate(1).unwrap();
        // a new one under the old name is another object
        let (b, made) = open(&n, "x", RW | O_CREAT, 0o600).unwrap();
        assert!(made && !Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn access_is_the_owners_the_groups_or_others() {
        let n = Names::new();
        open(&n, "x", RW | O_CREAT, 0o640).unwrap();
        // the group may read, not write; others nothing
        assert!(n.by_name.lock().unwrap().get("x").is_some());
        assert_eq!(n.open("x", FREAD, 0, &Cred::of(600, 20), 8).map(|_| ()), Ok(()));
        assert_eq!(n.open("x", FWRITE, 0, &Cred::of(600, 20), 8).unwrap_err(), Errno::EACCES);
        assert_eq!(n.open("x", FREAD, 0, &Cred::of(600, 30), 8).unwrap_err(), Errno::EACCES);
        // root may do anything
        assert!(n.open("x", RW, 0, &Cred::of(0, 0), 8).is_ok());
        // a non-owner may not unlink what he cannot write; the owner may whatever the mode
        assert_eq!(n.unlink("x", &Cred::of(600, 20)).unwrap_err(), Errno::EACCES);
        let (p, _) = open(&n, "ro", RW | O_CREAT, 0o400).unwrap();
        assert_eq!(p.uid, 501);
        n.unlink("ro", &Cred::of(501, 20)).unwrap();
    }

    #[test]
    fn the_owner_falls_through_to_the_group_and_others() {
        let n = Names::new();
        open(&n, "g", RW | O_CREAT, 0o044).unwrap();
        // no owner bits: the group's and others' let the owner read
        assert!(n.open("g", FREAD, 0, &Cred::of(501, 20), 8).is_ok());
        assert_eq!(n.open("g", FWRITE, 0, &Cred::of(501, 20), 8).unwrap_err(), Errno::EACCES);
        // a member of a group the bits refuse is refused, whatever others may
        open(&n, "w", RW | O_CREAT, 0o604).unwrap();
        assert_eq!(n.open("w", FREAD, 0, &Cred::of(600, 20), 8).unwrap_err(), Errno::EACCES);
        assert!(n.open("w", FREAD, 0, &Cred::of(600, 30), 8).is_ok());
        // supplementary groups count
        let mut c = Cred::of(600, 30);
        c.groups.push(20);
        open(&n, "s", RW | O_CREAT, 0o640).unwrap();
        assert!(n.open("s", FREAD, 0, &c, 8).is_ok());
    }
}
