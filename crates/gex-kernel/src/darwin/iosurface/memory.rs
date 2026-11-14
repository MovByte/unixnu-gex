//! A surface's memory across tasks. On the device a surface is one set of
//! pages mapped into each task that looks it up; here each task's memory is
//! its own, so the kernel keeps the surface's bytes (the backing store) and
//! each task maps a view of them, kept coherent with it:
//!
//! - when a view is made, and when its task locks the surface, the view is
//!   brought up to date: first every view's changes are gathered into the
//!   backing store, then the view takes what changed there since it last
//!   looked;
//! - when its task unlocks a lock that allowed writing, the view's changes
//!   go to the backing store;
//! - between those, the view's pages go without the write bit in the task's
//!   protection table ([`crate::mem::MemoryMap::withhold`]), so the task's
//!   first store to a page outside a lock faults to the kernel, which notes
//!   the page as written and lets the store run; a call's copy into one is
//!   noted the same way ([`crate::SoftPages`]). Those pages are gathered
//!   with the others at the next lock, by any task, so a write outside a
//!   lock is seen, never lost.
//!
//! A view's changes are what differs from the bytes it held when it last
//! synchronized (its base), byte by byte, so tasks writing different bytes
//! of one page under their own locks (IOSurface's lock excludes no one) all
//! keep theirs.

use super::super::mach::PAGE_MASK;
use crate::syscalls::Kernel;
use crate::GuestMem;

const PAGE: u64 = PAGE_MASK + 1;

/// One task's view of a surface's memory: where it is mapped, the bytes it
/// held when it last synchronized, the pages written since, and the locks
/// that allow writing it holds (while any is held its pages are not
/// watched, and all of them are gathered).
#[derive(Debug)]
pub struct View {
    pub pid: i32,
    /// The address space the view is in (`ProcTable::vm`'s, which an
    /// `execve` replaces): a view of one that is gone is gone.
    vm: usize,
    pub addr: u64,
    pub len: u64,
    base: Vec<u8>,
    dirty: Vec<bool>,
    write_locks: u32,
    /// A read-only mapping: the task cannot change it.
    read_only: bool,
}

impl View {
    fn pages(&self) -> usize {
        (self.len / PAGE) as usize
    }

    fn page_of(&self, addr: u64) -> Option<usize> {
        (addr >= self.addr && addr < self.addr + self.len).then(|| ((addr - self.addr) / PAGE) as usize)
    }
}

/// A kernel object's bytes and the views of them.
#[derive(Debug, Default)]
pub struct Memory {
    pub backing: Vec<u8>,
    pub views: Vec<View>,
    /// The tasks' mappings (`IOMemoryMap`s): each a view, how it was asked
    /// for, and the references to it.
    maps: Vec<Map>,
    /// The ranges of the backing store (offset, length) the tasks' and the
    /// kernel's writes changed since they were last taken
    /// ([`Memory::take_changed`]): disjoint, in order, none touching the
    /// next.
    changed: Vec<(u64, u64)>,
}

/// An `IOMemoryMap` of the memory in a task: its address, whether it is
/// read-only and was asked for as unique (kIOMapUnique), and its holders.
#[derive(Debug)]
struct Map {
    pid: i32,
    addr: u64,
    len: u64,
    read_only: bool,
    refs: u32,
}

/// The address space of `pid` as the process table publishes it, by
/// identity; `None` when the host keeps none.
fn vm_identity(k: &Kernel, pid: i32) -> Option<usize> {
    k.procs.vm(pid).ok().map(|v| std::sync::Arc::as_ptr(&v) as *const u8 as usize)
}

/// `f` with the memory of `pid`: the caller's own (`m`) or another
/// process's as the host shares it. `false` when there is none to reach.
fn with_memory(k: &mut Kernel, m: &mut GuestMem<'_>, pid: i32, f: &mut dyn FnMut(&mut GuestMem<'_>)) -> bool {
    if pid == k.pid {
        f(&mut m.kernel());
        return true;
    }
    match k.procs.vm(pid) {
        Ok(peer) => {
            peer.mem.with_guest(&mut |g| f(&mut g.kernel()));
            true
        }
        Err(_) => false,
    }
}

/// Take or give back the write bit of `[start, end)` in `pid`'s
/// protection table: the caller's own is written when its call returns,
/// another process's now.
fn set_watch(k: &mut Kernel, m: &mut GuestMem<'_>, pid: i32, start: u64, end: u64, watch: bool) {
    use gex_abi::perm::WRITE;
    if pid == k.pid {
        let mut mm = k.mem.lock();
        if watch { mm.withhold(start, end, WRITE) } else { mm.restore(start, end, WRITE) }
        return;
    }
    let _ = m;
    let Ok(peer) = k.procs.vm(pid) else { return };
    let writes = {
        let mut mm = peer.mm.lock();
        if watch { mm.withhold(start, end, WRITE) } else { mm.restore(start, end, WRITE) }
        mm.take_perm_writes()
    };
    peer.mem.with_guest(&mut |g| {
        for (page, bytes) in &writes {
            let _ = g.kernel().write(gex_abi::PERM_TABLE64 + page, bytes);
        }
    });
}

impl Memory {
    /// A surface's memory of `len` bytes (a whole number of pages), zeroed,
    /// as a new surface's is.
    pub fn new(len: u64) -> Memory {
        Memory { backing: vec![0; len as usize], views: Vec::new(), maps: Vec::new(), changed: Vec::new() }
    }

    /// Note that `[at, at + len)` of the backing store changed: merged
    /// with the ranges it overlaps or touches.
    fn note_changed(&mut self, at: u64, len: u64) {
        if len == 0 {
            return;
        }
        let (mut start, mut end) = (at, at + len);
        let first = self.changed.partition_point(|&(s, n)| s + n < start);
        let mut last = first;
        while last < self.changed.len() && self.changed[last].0 <= end {
            let (s, n) = self.changed[last];
            start = start.min(s);
            end = end.max(s + n);
            last += 1;
        }
        self.changed.splice(first..last, [(start, end - start)]);
    }

    /// The ranges of the backing store that changed since this was last
    /// asked, in order.
    pub fn take_changed(&mut self) -> Vec<(u64, u64)> {
        std::mem::take(&mut self.changed)
    }

    /// Whether `pid`'s view at `addr` is still in its address space.
    fn live(&self, k: &Kernel, i: usize) -> bool {
        vm_identity(k, self.views[i].pid) == Some(self.views[i].vm)
    }

    /// Bring view `i`'s changes into the backing store: the pages written
    /// since it last synchronized, or all of them while it holds a lock
    /// that allows writing; each byte that differs from its base. The
    /// pages gathered are watched again unless such a lock is held.
    fn gather_view(&mut self, k: &mut Kernel, m: &mut GuestMem<'_>, i: usize) {
        if self.views[i].read_only || !self.live(k, i) {
            return;
        }
        let v = &self.views[i];
        let all = v.write_locks > 0;
        let pages: Vec<usize> = (0..v.pages()).filter(|&p| all || v.dirty[p]).collect();
        if pages.is_empty() {
            return;
        }
        let (pid, addr) = (v.pid, v.addr);
        let mut cur: Vec<(usize, Vec<u8>)> = Vec::with_capacity(pages.len());
        with_memory(k, m, pid, &mut |g| {
            for &p in &pages {
                let at = addr + p as u64 * PAGE;
                if let Ok(b) = g.read(at, PAGE as usize) {
                    cur.push((p, b.to_vec()));
                }
            }
        });
        let v = &mut self.views[i];
        let mut runs: Vec<(u64, u64)> = Vec::new();
        for (p, bytes) in cur {
            let o = p * PAGE as usize;
            let base = &mut v.base[o..o + PAGE as usize];
            for (j, (&now, was)) in bytes.iter().zip(base.iter_mut()).enumerate() {
                if now != *was {
                    if let Some(b) = self.backing.get_mut(o + j) {
                        *b = now;
                        let at = (o + j) as u64;
                        match runs.last_mut() {
                            Some((s, n)) if *s + *n == at => *n += 1,
                            _ => runs.push((at, 1)),
                        }
                    }
                    *was = now;
                }
            }
        }
        for (at, n) in runs {
            self.note_changed(at, n);
        }
        let v = &mut self.views[i];
        if v.write_locks == 0 {
            let written: Vec<usize> = (0..v.pages()).filter(|&p| v.dirty[p]).collect();
            for &p in &written {
                v.dirty[p] = false;
            }
            let (pid, addr) = (v.pid, v.addr);
            for p in written {
                let at = addr + p as u64 * PAGE;
                set_watch(k, m, pid, at, at + PAGE, true);
            }
        }
    }

    /// Every view's changes into the backing store: what any task wrote,
    /// under a lock or not, is there afterwards.
    pub fn gather(&mut self, k: &mut Kernel, m: &mut GuestMem<'_>) {
        for i in 0..self.views.len() {
            self.gather_view(k, m, i);
        }
    }

    /// View `i` brought up to date with the backing store: each page whose
    /// bytes there differ from what the view last held is written into the
    /// task's view.
    fn refresh(&mut self, k: &mut Kernel, m: &mut GuestMem<'_>, i: usize) {
        if !self.live(k, i) {
            return;
        }
        let v = &self.views[i];
        let pages: Vec<usize> = (0..v.pages())
            .filter(|&p| {
                let o = p * PAGE as usize;
                self.backing[o..o + PAGE as usize] != v.base[o..o + PAGE as usize]
            })
            .collect();
        if pages.is_empty() {
            return;
        }
        let (pid, addr) = (v.pid, v.addr);
        let backing = &self.backing;
        with_memory(k, m, pid, &mut |g| {
            for &p in &pages {
                let o = p * PAGE as usize;
                let _ = g.write(addr + o as u64, &backing[o..o + PAGE as usize]);
            }
        });
        let v = &mut self.views[i];
        for p in pages {
            let o = p * PAGE as usize;
            v.base[o..o + PAGE as usize].copy_from_slice(&self.backing[o..o + PAGE as usize]);
        }
    }

    /// A view of the memory for `pid` at `addr` (mapped, `len` bytes, the
    /// memory's whole length): the backing store's bytes as every task has
    /// left them written into it, and its pages watched.
    pub fn add_view(&mut self, k: &mut Kernel, m: &mut GuestMem<'_>, pid: i32, addr: u64, len: u64, read_only: bool) {
        self.gather(k, m);
        let Some(vm) = vm_identity(k, pid) else {
            k.darwin_unimplemented(format!("an IOSurface's memory in pid {pid}, on a host that shares no process's memory with the kernel"));
            return;
        };
        let pages = (len / PAGE) as usize;
        let backing = &self.backing;
        with_memory(k, m, pid, &mut |g| {
            let _ = g.write(addr, &backing[..len as usize]);
        });
        self.views.push(View { pid, vm, addr, len, base: self.backing[..len as usize].to_vec(), dirty: vec![false; pages], write_locks: 0, read_only });
        if !read_only {
            set_watch(k, m, pid, addr, addr + len, true);
        }
    }

    /// `createMappingInTask(task, 0, kIOMapAnywhere | ...)` of the whole
    /// memory for the calling task: a mapping it holds already that is
    /// compatible (`IOMemoryMap::copyCompatible`: the same task and
    /// read-only bit), unless `unique` asks for a new one; else a new
    /// mapping (`IOMemoryDescriptorMapAlloc`: tagged VM_MEMORY_IOKIT,
    /// inherited by no child) that is a view of the memory. Its address,
    /// or the Mach error mapping failed with.
    pub fn map(&mut self, k: &mut Kernel, read_only: bool, unique: bool) -> Result<u64, u64> {
        use super::super::mach::prot;
        let pid = k.pid;
        if !unique {
            if let Some(m) = self.maps.iter_mut().find(|m| m.pid == pid && m.read_only == read_only) {
                m.refs += 1;
                return Ok(m.addr);
            }
        }
        let len = self.backing.len() as u64;
        let cur = if read_only { prot::READ } else { prot::READ | prot::WRITE };
        let addr = match k.darwin_own_memory(|k, m| k.darwin_iokit_map(m, len, cur)) {
            Ok(r) => r?,
            Err(_) => return Err(5),
        };
        let added = k.darwin_own_memory(|k, m| self.add_view(k, m, pid, addr, len, read_only));
        if added.is_err() {
            return Err(5);
        }
        self.maps.push(Map { pid, addr, len, read_only, refs: 1 });
        Ok(addr)
    }

    /// A reference on `pid`'s mapping at `addr` let go: the last removes
    /// the mapping from the task (`IOMemoryMap::free`), the view's changes
    /// kept first. A live task other than the caller's is not unmapped here
    /// (reported); its view is dropped.
    pub fn unmap(&mut self, k: &mut Kernel, pid: i32, addr: u64) {
        let Some(i) = self.maps.iter().position(|m| m.pid == pid && m.addr == addr) else { return };
        self.maps[i].refs -= 1;
        if self.maps[i].refs > 0 {
            return;
        }
        let map = self.maps.remove(i);
        let view = self.view(pid, addr);
        if pid == k.pid {
            let _ = k.darwin_own_memory(|k, m| {
                if let Some(v) = view {
                    self.remove_view(k, m, v);
                }
                k.darwin_vm_deallocate(m, map.addr, map.len);
            });
        } else {
            // A task that is gone took its mappings with its map.
            let gone = view.map_or(true, |v| !self.live(k, v));
            if let Some(v) = view {
                let _ = k.darwin_own_memory(|k, m| self.remove_view(k, m, v));
            }
            if !gone {
                k.darwin_unimplemented(format!("removing an IOKit mapping at {addr:#x} from pid {pid}'s map for pid {}", k.pid));
            }
        }
    }

    /// The kernel writes `bytes` at `off`: what the tasks wrote first
    /// gathered, then the bytes put in the backing store and in every view
    /// (the tasks see the kernel's stores as they would on the device's one
    /// page).
    pub fn kernel_write(&mut self, k: &mut Kernel, m: &mut GuestMem<'_>, off: u64, bytes: &[u8]) {
        if self.views.iter().any(|v| !v.read_only) {
            self.gather(k, m);
        }
        let o = off as usize;
        self.backing[o..o + bytes.len()].copy_from_slice(bytes);
        self.note_changed(off, bytes.len() as u64);
        for i in 0..self.views.len() {
            if !self.live(k, i) {
                continue;
            }
            let (pid, addr) = (self.views[i].pid, self.views[i].addr);
            if off + bytes.len() as u64 > self.views[i].len {
                continue;
            }
            with_memory(k, m, pid, &mut |g| {
                let _ = g.write(addr + off, bytes);
            });
            self.views[i].base[o..o + bytes.len()].copy_from_slice(bytes);
        }
    }

    /// The bytes at `off`, with what the tasks wrote gathered first.
    pub fn read(&mut self, k: &mut Kernel, m: &mut GuestMem<'_>, off: u64, len: usize) -> Vec<u8> {
        if self.views.iter().any(|v| !v.read_only) {
            self.gather(k, m);
        }
        self.backing[off as usize..off as usize + len].to_vec()
    }

    /// The view of `pid` at `addr`, by index.
    pub fn view(&self, pid: i32, addr: u64) -> Option<usize> {
        self.views.iter().position(|v| v.pid == pid && v.addr == addr)
    }

    /// The view `i` taken away (its task is unmapping it): its changes
    /// gathered first, and its pages no longer watched.
    pub fn remove_view(&mut self, k: &mut Kernel, m: &mut GuestMem<'_>, i: usize) {
        self.gather_view(k, m, i);
        let v = self.views.remove(i);
        if !v.read_only && vm_identity(k, v.pid) == Some(v.vm) {
            set_watch(k, m, v.pid, v.addr, v.addr + v.len, false);
        }
    }

    /// The task of view `i` locks the surface: every task's changes
    /// gathered and the view brought up to date; a lock that allows
    /// writing stops the watch over its pages until it is unlocked.
    pub fn lock(&mut self, k: &mut Kernel, m: &mut GuestMem<'_>, i: usize, write: bool) {
        self.gather(k, m);
        self.refresh(k, m, i);
        if write {
            let v = &mut self.views[i];
            v.write_locks += 1;
            if v.write_locks == 1 {
                let (pid, addr, len) = (v.pid, v.addr, v.len);
                set_watch(k, m, pid, addr, addr + len, false);
            }
        }
    }

    /// The task of view `i` unlocks a lock: when it was the last that
    /// allowed writing, the view's changes go to the backing store and its
    /// pages are watched again.
    pub fn unlock(&mut self, k: &mut Kernel, m: &mut GuestMem<'_>, i: usize, write: bool) {
        if !write || self.views[i].write_locks == 0 {
            return;
        }
        if self.views[i].write_locks > 1 {
            self.views[i].write_locks -= 1;
            return;
        }
        // Gathered as a locked view (all of it), then watched again.
        self.gather_view(k, m, i);
        let v = &mut self.views[i];
        v.write_locks = 0;
        v.dirty.iter_mut().for_each(|d| *d = false);
        let (pid, addr, len) = (v.pid, v.addr, v.len);
        if vm_identity(k, pid) == Some(v.vm) {
            set_watch(k, m, pid, addr, addr + len, true);
        }
    }

    /// A store by `pid` to `page` (a [`gex_abi::PERM_PAGE`] number) of one
    /// of its views, which faulted, or a call's copy that wrote it: the
    /// page is noted as written and no longer watched. Whether a view has
    /// the page.
    pub fn note_write(&mut self, k: &mut Kernel, m: &mut GuestMem<'_>, pid: i32, page: u64) -> bool {
        let addr = page << gex_abi::PERM_PAGE_SHIFT;
        let Some(i) = (0..self.views.len()).find(|&i| self.views[i].pid == pid && self.views[i].page_of(addr).is_some() && self.live(k, i)) else { return false };
        let p = self.views[i].page_of(addr).unwrap();
        self.views[i].dirty[p] = true;
        let at = self.views[i].addr + p as u64 * PAGE;
        set_watch(k, m, pid, at, at + PAGE, false);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changed_ranges_merge() {
        let mut m = Memory::new(PAGE);
        m.note_changed(10, 5);
        m.note_changed(30, 2);
        m.note_changed(15, 3);
        m.note_changed(0, 0);
        m.note_changed(29, 10);
        m.note_changed(12, 2);
        assert_eq!(m.take_changed(), vec![(10, 8), (29, 10)]);
        assert!(m.take_changed().is_empty());
        m.note_changed(5, 1);
        m.note_changed(1, 3);
        m.note_changed(4, 1);
        assert_eq!(m.take_changed(), vec![(1, 5)]);
    }

    #[test]
    fn views_find_their_pages() {
        let v = View { pid: 1, vm: 0, addr: 0x10_0000, len: 2 * PAGE, base: vec![0; 2 * PAGE as usize], dirty: vec![false; 2], write_locks: 0, read_only: false };
        assert_eq!(v.pages(), 2);
        assert_eq!(v.page_of(0x10_0000), Some(0));
        assert_eq!(v.page_of(0x10_0000 + PAGE + 5), Some(1));
        assert_eq!(v.page_of(0x10_0000 + 2 * PAGE), None);
        assert_eq!(v.page_of(0xf_ffff), None);
    }
}
