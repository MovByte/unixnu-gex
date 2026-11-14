//! The memory IOSurfaceRoot shares with every client's task: the surfaces'
//! records (`client_shared_ro`, `client_shared_rw`), the shared events'
//! values (`event_shared_ro`), and the graphics comm page; and the root's
//! entry in the registry.
//!
//! Each record list is a chain of 16 KiB chunks
//! (`IOBufferMemoryDescriptor::withOptions(kIOMemoryKernelUserShared |
//! kIODirectionInOut, 0x4000, page_size)`, 0xfffffff005bac8a8), a surface's
//! records at its id's place in them: 89 read-only records of 0xb8 bytes a
//! chunk, 256 read-write records of 0x40. A client's IOSurfaceShared
//! (0xfffffff005bb380c) maps each chunk into its task the first time it
//! needs one at or past it (`map_client_shared`, 0xfffffff005bb3afc):
//! read-only, the read-write chunks writable only for a client entitled to
//! protected access.

use super::memory::Memory;
use super::{ro, rw, UserClient};
use crate::darwin::iokit::{Node, Prop};
use crate::syscalls::Kernel;
use crate::GuestMem;

/// A chunk's size.
const CHUNK: u64 = 0x4000;
/// Records a chunk holds (`0x4000 / size`).
const RO_PER_CHUNK: u32 = (CHUNK / ro::SIZE) as u32;
const RW_PER_CHUNK: u32 = (CHUNK / rw::SIZE) as u32;

/// The root's registry entry: its personality's properties (the IOSurface
/// kext's one personality in `__PRELINK_INFO`), those the catalogue and
/// matching add (`CFBundleIdentifierKernel`, `IOMatchedAtBoot`,
/// `IOProbeScore` 0 for a personality with none), under its name. Its
/// provider is the IOResources nub `resources`, which its personality's
/// `IOProviderClass` names and on which its `IOResourceMatch`, "IOBSD",
/// matched. The device tree has no "non-coherent" property, so start sets
/// no "iosurface-non-coherent".
pub fn add_service(t: &mut Vec<Node>, resources: u32) {
    let s = |v: &str| Prop::Str(v.to_string());
    let service_props = vec![
        ("IOClass".to_string(), s(super::CLASS)),
        ("IOMatchCategory".to_string(), s("IOSurfaceRoot")),
        ("IOProviderClass".to_string(), s("IOResources")),
        ("IOResourceMatch".to_string(), s("IOBSD")),
        ("CFBundleIdentifier".to_string(), s("com.apple.iokit.IOSurface")),
        ("CFBundleIdentifierKernel".to_string(), s("com.apple.iokit.IOSurface")),
        ("IOMatchedAtBoot".to_string(), Prop::Bool(true)),
        ("IOProbeScore".to_string(), Prop::Num(0, 32)),
    ];
    let at = t.len() as u32;
    t.push(Node { name: super::NAME.to_string(), props: Vec::new(), class: super::CLASS, service_props, parent: Some(resources), children: Vec::new(), kernel_only: false, nub: None });
    t[resources as usize].children.push(at);
}

/// The root's shared memory.
#[derive(Default)]
pub struct Shared {
    ro: Vec<Memory>,
    rw: Vec<Memory>,
    /// `+0x1f8`: the graphics comm page, one page made at start. Its first
    /// word is IOGPUFamily's: 1 while the kdebug typefilter enables class
    /// 0x85's subclass 0x08 or 0x80 (its callback 0xfffffff005bd674c); with
    /// kdebug off it is never written, and the page stays zero.
    comm: Option<Memory>,
}

/// A client's IOSurfaceShared: the addresses of the chunks it has mapped
/// into its task, and of the comm page (`+0x128`).
#[derive(Default)]
pub struct TaskShared {
    ro: Vec<u64>,
    rw: Vec<u64>,
    rw_writable: bool,
    comm: u64,
}

impl Shared {
    fn comm(&mut self) -> &mut Memory {
        self.comm.get_or_insert_with(|| Memory::new(CHUNK))
    }

    /// The chunks of a list made up to the one holding `id`
    /// (0xfffffff005bac8a8: those missing are made on the way).
    fn ensure(list: &mut Vec<Memory>, per: u32, id: u32) {
        while list.len() <= (id / per) as usize {
            list.push(Memory::new(CHUNK));
        }
    }

    /// The records of a new surface (0xfffffff005bac7c8): both zeroed, the
    /// read-only one's value seed 1, size hint 0x1000, pixel size casting
    /// and system memory only set.
    pub fn alloc(&mut self, k: &mut Kernel, id: u32) {
        Self::ensure(&mut self.ro, RO_PER_CHUNK, id);
        Self::ensure(&mut self.rw, RW_PER_CHUNK, id);
        let mut rec = [0u8; ro::SIZE as usize];
        rec[ro::VALUE_SEED as usize..][..4].copy_from_slice(&1u32.to_le_bytes());
        rec[ro::VALUE_SIZE_HINT as usize..][..4].copy_from_slice(&0x1000u32.to_le_bytes());
        rec[ro::PIXEL_SIZE_CASTING as usize] = 1;
        rec[ro::SYS_MEM_ONLY as usize] = 1;
        self.ro_write(k, id, 0, &rec);
        self.rw_write(k, id, 0, &[0; rw::SIZE as usize]);
    }

    /// [`Shared::alloc`] before any task maps a chunk (at boot): the
    /// records written into the backing store, which every view takes when
    /// it is made.
    pub fn alloc_unmapped(&mut self, id: u32) {
        Self::ensure(&mut self.ro, RO_PER_CHUNK, id);
        Self::ensure(&mut self.rw, RW_PER_CHUNK, id);
        let (c, i) = ((id / RO_PER_CHUNK) as usize, u64::from(id % RO_PER_CHUNK));
        let o = (i * ro::SIZE) as usize;
        let rec = &mut self.ro[c].backing[o..o + ro::SIZE as usize];
        rec.fill(0);
        rec[ro::VALUE_SEED as usize..][..4].copy_from_slice(&1u32.to_le_bytes());
        rec[ro::VALUE_SIZE_HINT as usize..][..4].copy_from_slice(&0x1000u32.to_le_bytes());
        rec[ro::PIXEL_SIZE_CASTING as usize] = 1;
        rec[ro::SYS_MEM_ONLY as usize] = 1;
        let (c, i) = ((id / RW_PER_CHUNK) as usize, u64::from(id % RW_PER_CHUNK));
        let o = (i * rw::SIZE) as usize;
        self.rw[c].backing[o..o + rw::SIZE as usize].fill(0);
    }

    /// Bytes of surface `id`'s read-only record (which no task can write).
    pub fn ro_read(&self, id: u32, at: u64, len: usize) -> Vec<u8> {
        let (c, i) = ((id / RO_PER_CHUNK) as usize, u64::from(id % RO_PER_CHUNK));
        let o = (i * ro::SIZE + at) as usize;
        self.ro.get(c).map_or(vec![0; len], |m| m.backing[o..o + len].to_vec())
    }

    /// The kernel's store to surface `id`'s read-only record, seen at once
    /// by every task that maps it.
    pub fn ro_write(&mut self, k: &mut Kernel, id: u32, at: u64, bytes: &[u8]) {
        Self::ensure(&mut self.ro, RO_PER_CHUNK, id);
        let (c, i) = ((id / RO_PER_CHUNK) as usize, u64::from(id % RO_PER_CHUNK));
        let chunk = &mut self.ro[c];
        let _ = k.darwin_own_memory(|k, m| chunk.kernel_write(k, m, i * ro::SIZE + at, bytes));
    }

    /// Bytes of surface `id`'s read-write record, with what entitled tasks
    /// wrote there gathered.
    pub fn rw_read(&mut self, k: &mut Kernel, id: u32, at: u64, len: usize) -> Vec<u8> {
        Self::ensure(&mut self.rw, RW_PER_CHUNK, id);
        let (c, i) = ((id / RW_PER_CHUNK) as usize, u64::from(id % RW_PER_CHUNK));
        let chunk = &mut self.rw[c];
        k.darwin_own_memory(|k, m| chunk.read(k, m, i * rw::SIZE + at, len)).unwrap_or_else(|_| vec![0; len])
    }

    /// The kernel's store to surface `id`'s read-write record.
    pub fn rw_write(&mut self, k: &mut Kernel, id: u32, at: u64, bytes: &[u8]) {
        Self::ensure(&mut self.rw, RW_PER_CHUNK, id);
        let (c, i) = ((id / RW_PER_CHUNK) as usize, u64::from(id % RW_PER_CHUNK));
        let chunk = &mut self.rw[c];
        let _ = k.darwin_own_memory(|k, m| chunk.kernel_write(k, m, i * rw::SIZE + at, bytes));
    }

    /// map_client_shared for both lists: every chunk up to surface `id`'s
    /// mapped into the client's task that it has not mapped yet; the
    /// records' addresses there. A chunk that cannot be mapped fails the
    /// client (`Err`).
    pub fn map_client(&mut self, k: &mut Kernel, ts: &mut TaskShared, id: u32) -> Result<(u64, u64), ()> {
        Self::ensure(&mut self.ro, RO_PER_CHUNK, id);
        Self::ensure(&mut self.rw, RW_PER_CHUNK, id);
        let (rc, ri) = ((id / RO_PER_CHUNK) as usize, u64::from(id % RO_PER_CHUNK));
        let (wc, wi) = ((id / RW_PER_CHUNK) as usize, u64::from(id % RW_PER_CHUNK));
        while ts.ro.len() <= rc {
            let c = ts.ro.len();
            let a = self.ro[c].map(k, true, false).map_err(|_| ())?;
            ts.ro.push(a);
        }
        while ts.rw.len() <= wc {
            let c = ts.rw.len();
            let a = self.rw[c].map(k, !ts.rw_writable, false).map_err(|_| ())?;
            ts.rw.push(a);
        }
        Ok((ts.ro[rc] + ri * ro::SIZE, ts.rw[wc] + wi * rw::SIZE))
    }

    /// A store by `pid` to a watched page of a writable read-write chunk.
    pub fn note_write(&mut self, k: &mut Kernel, m: &mut GuestMem<'_>, pid: i32, page: u64) -> bool {
        self.rw.iter_mut().any(|c| c.note_write(k, m, pid, page))
    }

    /// Whether a client asked to be told when surface `id` is no longer in
    /// use: only selector 17 registers that, and it is not served here, so
    /// none has.
    pub fn notifies(&self, _id: u32) -> bool {
        false
    }

    /// The comm page's first word, which IOGPUFamily's selector 3 reads.
    pub fn comm_word(&mut self) -> u32 {
        u32::from_le_bytes(self.comm().backing[..4].try_into().unwrap())
    }

    /// The comm page mapped read-only into the calling task: a new mapping
    /// when `unique` (IOGPUFamily's, kIOMapUnique), else one the task holds
    /// already. Its address, and its length.
    pub fn map_comm(&mut self, k: &mut Kernel, unique: bool) -> Result<(u64, u64), u64> {
        let c = self.comm();
        let a = c.map(k, true, unique)?;
        Ok((a, CHUNK))
    }

    /// A mapping of the comm page let go.
    pub fn unmap_comm(&mut self, k: &mut Kernel, pid: i32, addr: u64) {
        self.comm().unmap(k, pid, addr);
    }
}

/// The client's init (0xfffffff005baed5c): its IOSurfaceShared (its
/// read-write chunks writable for protected access) and the comm page
/// mapped read-only into its task (`createMappingInTask(task, 0, 0x1001,
/// 0, 0)`); a mapping that fails fails the client.
pub fn start(k: &mut Kernel, uc: &mut UserClient) -> Result<(), i32> {
    uc.shared.rw_writable = uc.protected_access;
    let comm = super::root(|r| r.shared.map_comm(k, false));
    match comm {
        Ok((a, _)) => {
            uc.shared.comm = a;
            Ok(())
        }
        // newUserClient fails; IOService::newUserClient then finds no
        // IOUserClientClass.
        Err(_) => Err(crate::darwin::iokit::ret::UNSUPPORTED),
    }
}

/// The client's destruction: its chunk mappings and its comm page mapping
/// let go.
pub fn stop(k: &mut Kernel, pid: i32, ts: TaskShared) {
    super::root(|r| {
        for (c, a) in ts.ro.iter().enumerate() {
            r.shared.ro[c].unmap(k, pid, *a);
        }
        for (c, a) in ts.rw.iter().enumerate() {
            r.shared.rw[c].unmap(k, pid, *a);
        }
        if ts.comm != 0 {
            r.shared.unmap_comm(k, pid, ts.comm);
        }
    });
}

/// The comm page's address in the client's task (`+0x128`'s map), for
/// selector 32.
pub fn comm_address(ts: &TaskShared) -> u64 {
    ts.comm
}
