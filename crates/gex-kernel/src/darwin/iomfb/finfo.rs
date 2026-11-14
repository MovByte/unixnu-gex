//! Frame information (notification type 3) and CRC notifications (type 4):
//! what the pipe reports of each frame it shows, as AppleMobileDispH9G keeps
//! it and IOMobileGraphicsFamily hands it to the clients.
//!
//! - The pipe names 14 items (0xfffffff006bb66b4, [`ITEMS`]) and counts, for
//!   each, the clients' records that ask for it (`+0x1cc4`): a frame
//!   information record's items are its options (`+0x78`, set by
//!   ChangeFrameInfo, 0xfffffff006bb672c), and CRC notifications turned on
//!   ask for the blend and dither CRCs (0xfffffff006bb6888, `+0x1d2c`).
//! - AppleCLCD keeps a ring of 16 entries (`+0x18f0`, 0x4c bytes each; head
//!   `+0x18e8`, tail `+0x18ec`): each swap it programs (0xfffffff006bf8cc0),
//!   flushes (0xfffffff006bf710c) or makes for the controller's last frame
//!   (0xfffffff006bf6e20) takes the next entry (0xfffffff006bd5900) with the
//!   items asked for then ([`Ring`]); the pipe's power-on empties it
//!   (0xfffffff006bf89d0).
//! - At each swap's completion AppleCLCD's slot 337 (0xfffffff006bfa478)
//!   takes the ring's entries up to that swap's and reports each
//!   ([`super::swap`]): to each frame information record its items' values
//!   (0xfffffff006bb68f4) through its client's shared data queue, and to
//!   each CRC record the swap id and two CRCs (0xfffffff006796b7c).
//! - A frame information client's queue is an `IOSharedDataQueue` of 0x1040
//!   bytes (0xfffffff0067765a8), made when the client registers its port of
//!   type 3 after asking the pipe's item sizes (selector 74), mapped into
//!   its task then, and mapped again for each `clientMemoryForType(3)`
//!   ([`Queue`]).

use std::collections::HashMap;
use std::sync::Mutex;

use super::super::iosurface::memory::Memory;
use super::super::ipc::ObjId;
use crate::syscalls::Kernel;
use crate::GuestMem;

/// The pipe's frame information items, by index (its names table
/// 0xfffffff007c258f8). Items 0 to 5 are the hardware's CRCs of the layers,
/// the blend, the color manager and the dither.
pub const ITEMS: [&str; 14] = ["Layer_0_CRC", "Layer_1_CRC", "Layer_2_CRC", "Blend_CRC", "ColorManager_CRC", "Dither_CRC", "Presentation_time", "Presentation_delta", "Requested_presentation", "Issued_time", "Performance_headroom", "Thermal_throttle", "PRC_duration", "CA_mode"];

/// The items CRC notifications ask for (0xfffffff006bb6888): the blend's
/// and the dither's CRCs.
const CRC_ITEMS: u32 = 0x28;

/// A client's frame information record (`+0x118 + 3 * 0xb0`): the items it
/// asks for (`+0x78`) and the presentation time last sent it (`+0x80`).
#[derive(Clone, Copy, Debug, Default)]
pub struct Rec {
    pub items: u32,
    pub last: u64,
}

/// An entry of AppleCLCD's frame ring as 0xfffffff006bd5900 fills it: the
/// swap's issue and requested presentation times (its `+0x2d8`, `+0x2d0`),
/// its id, the items asked for (the pipe's slot 0x538, AppleCLCD's slot 270
/// answering false), and its kind.
#[derive(Clone, Copy, Debug, Default)]
pub struct Entry {
    pub issued: u64,
    pub requested: u64,
    pub id: u32,
    pub items: u32,
    pub kind: u32,
}

/// The ring. Its indices start where the pipe's power-on leaves them, at the
/// hardware's frame count (register 0x16030's bits 8 to 11), which nothing
/// here reads: only their difference, the entries outstanding, matters.
#[derive(Debug, Default)]
pub struct Ring {
    head: usize,
    tail: usize,
    entries: [Entry; 16],
}

impl Ring {
    /// The next entry taken for `e` (0xfffffff006bf7074's pattern): no room
    /// is checked, so a seventeenth outstanding entry would empty the ring.
    pub fn push(&mut self, e: Entry) {
        self.entries[self.tail] = e;
        self.tail = (self.tail + 1) & 0xf;
    }

    /// 0xfffffff006bf89d0: the ring emptied.
    pub fn reset(&mut self) {
        self.head = self.tail;
    }

    /// Slot 337's walk: nothing when no entry has swap `id`; else every
    /// entry up to the first that has it taken, and those that ask for
    /// items and are of kind 0 or 0x18 given back with whether they are
    /// that swap's.
    pub fn take_through(&mut self, id: u32) -> Vec<(Entry, bool)> {
        let mut i = self.head;
        loop {
            if i == self.tail {
                return Vec::new();
            }
            if self.entries[i].id == id {
                break;
            }
            i = (i + 1) & 0xf;
        }
        let mut out = Vec::new();
        loop {
            let e = self.entries[self.head];
            self.head = (self.head + 1) & 0xf;
            if e.items != 0 && (e.kind == 0x18 || e.kind == 0) {
                out.push((e, e.id == id));
            }
            if e.id == id {
                return out;
            }
        }
    }
}

/// The pipe's frame information: each item's count of records asking for
/// it (`+0x1cc4`), whether CRC notifications are on (`+0x1d2c`), the
/// performance headroom (`+0x4604`, set only through AppleCLCD's slot
/// 0x8f0 from a swap signal with the frame statistics, `+0x1650`, which is
/// never made) and the thermal throttle (`+0x1d4`, set by SetParameter 4);
/// the clients' records; and AppleCLCD's ring.
#[derive(Debug, Default)]
pub struct Pipe {
    refs: [u32; 14],
    crc: bool,
    pub headroom: u32,
    pub throttled: bool,
    pub records: HashMap<u32, Rec>,
    pub ring: Ring,
}

impl Pipe {
    /// 0xfffffff006bb6774: each item that changes from `old` to `new`
    /// counted up or down (a count already 0 stays, "Value underrun for
    /// CRC ref counter"); then the CRC blocks enabled for the items that
    /// are asked for (0xfffffff006bf1024), which nothing reads here but the
    /// CRCs themselves.
    pub fn update(&mut self, old: u32, new: u32) {
        for i in 0..14 {
            let bit = 1u32 << i;
            if (old ^ new) & bit == 0 {
                continue;
            }
            if new & bit != 0 {
                self.refs[i] += 1;
            } else if self.refs[i] != 0 {
                self.refs[i] -= 1;
            }
        }
    }

    /// The pipe's slot 0x538 (0xfffffff006bb68b8): the items some record
    /// asks for.
    pub fn items(&self) -> u32 {
        (0..14).filter(|&i| self.refs[i] != 0).fold(0, |m, i| m | 1 << i)
    }

    /// The pipe's slot 0x88 (0xfffffff006bb6888): CRC notifications on or
    /// off, their items counted when that changes.
    pub fn set_crc(&mut self, on: bool) {
        if self.crc == on {
            return;
        }
        self.crc = on;
        if on {
            self.update(0, CRC_ITEMS);
        } else {
            self.update(CRC_ITEMS, 0);
        }
    }
}

// ---------------------------------------------------------------------------
// A client's shared data queue.

/// `IOSharedDataQueue::withCapacity(0x1040)`.
const CAPACITY: u32 = 0x1040;
/// `DATA_QUEUE_MEMORY_HEADER_SIZE` (`queueSize`, `head`, `tail`),
/// `DATA_QUEUE_ENTRY_HEADER_SIZE` and `DATA_QUEUE_MEMORY_APPENDIX_SIZE`
/// (`version` and a `mach_msg_header_t`), IODataQueueShared.h.
const HEADER: u64 = 12;
const ENTRY_HEADER: u32 = 4;
const APPENDIX: u64 = 4 + 24;
/// `getMemoryDescriptor`'s length, which a mapping's `getSize` gives.
pub const DESCRIPTOR_LEN: u64 = CAPACITY as u64 + HEADER + APPENDIX;

/// A frame information client's queue (`+0x3b8`): its memory, the mapping
/// the client keeps in its task (`+0x3c0`, in the client's task, `+0xe8`)
/// and those `clientMemoryForType(3)` made (the user client's `mappings`),
/// each with its task, and the port its data-available message goes to.
struct Queue {
    mem: Memory,
    maps: Vec<(i32, u64)>,
    port: Option<ObjId>,
}

static QUEUES: Mutex<Option<HashMap<u32, Queue>>> = Mutex::new(None);

fn queues<R>(f: impl FnOnce(&mut HashMap<u32, Queue>) -> R) -> R {
    f(QUEUES.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_with(HashMap::new))
}

/// 0xfffffff0067765a8 and `setNotificationPort`: client `client`'s queue,
/// made if it has none (`IOSharedDataQueue::initWithCapacity`: whole pages,
/// zeroed, `queueSize` written, the appendix's version 0) and mapped into
/// the client's task, `owner` (`createMappingInTask(task, 0,
/// kIOMapAnywhere)`); its data-available message then goes to `port`.
/// `Err` is what is not modelled.
pub fn register(k: &mut Kernel, client: u32, owner: i32, port: Option<ObjId>) -> Result<(), String> {
    queues(|t| {
        if !t.contains_key(&client) {
            if k.pid != owner {
                return Err(format!("mapping a framebuffer client's frame information queue into pid {owner}'s task from pid {}", k.pid));
            }
            let len = (DESCRIPTOR_LEN + super::super::mach::PAGE_MASK) & !super::super::mach::PAGE_MASK;
            let mut mem = Memory::new(len);
            mem.backing[..4].copy_from_slice(&CAPACITY.to_le_bytes());
            let addr = mem.map(k, false, true).map_err(|e| format!("mapping a framebuffer client's frame information queue (Mach error {e:#x})"))?;
            t.insert(client, Queue { mem, maps: vec![(owner, addr)], port: None });
        }
        if let Some(q) = t.get_mut(&client) {
            q.port = port;
        }
        Ok(())
    })
}

/// Whether client `client` has a queue (`clientMemoryForType(3)` answers
/// kIOReturnNotReady without one).
pub fn has_queue(client: u32) -> bool {
    queues(|q| q.contains_key(&client))
}

/// `clientMemoryForType(3)` mapped by `IOUserClient::mapClientMemory64`
/// into the calling task: a descriptor made anew (`getMemoryDescriptor`)
/// has no mapping to reuse, so each is a new one, kept with the user client.
/// The address and `getSize`, or the Mach error; `None` with no queue.
pub fn map(k: &mut Kernel, client: u32) -> Option<Result<(u64, u64), u64>> {
    queues(|t| {
        let q = t.get_mut(&client)?;
        let r = q.mem.map(k, false, true);
        if let Ok(a) = r {
            q.maps.push((k.pid, a));
        }
        Some(r.map(|a| (a, DESCRIPTOR_LEN)))
    })
}

/// The client freed: its queue and every mapping of it let go.
pub fn free(k: &mut Kernel, client: u32) {
    let Some(mut q) = queues(|q| q.remove(&client)) else { return };
    for (pid, addr) in std::mem::take(&mut q.maps) {
        q.mem.unmap(k, pid, addr);
    }
}

/// A store by `pid` to `page`, a page of a queue's mapping that the kernel
/// watches: noted. Whether one has it.
pub fn note_write(k: &mut Kernel, m: &mut GuestMem<'_>, pid: i32, page: u64) -> bool {
    queues(|t| t.values_mut().any(|q| q.mem.note_write(k, m, pid, page)))
}

/// `IOSharedDataQueue::enqueue` of `data` on client `client`'s queue
/// (0xfffffff00677ae18; a client with no queue takes nothing and answers
/// success). The entry (its size, then the data) goes at the tail, or at the
/// start when it does not fit before the end and there is room ahead of the
/// head; a full queue refuses it. The tail is published, and when the queue
/// was empty its port is sent the data-available message. Whether it was
/// queued; `Err` is what is not modelled.
pub fn enqueue(k: &mut Kernel, client: u32, data: &[u8]) -> Result<bool, String> {
    let r = queues(|t| {
        let Some(q) = t.get_mut(&client) else { return Ok((true, None)) };
        let mem = &mut q.mem;
        let r = k.darwin_own_memory(|k, m| enqueue_in(k, m, mem, data)).map_err(|r| r.unimplemented.unwrap_or_default());
        r.map(|(queued, notify)| (queued, if notify { q.port } else { None }))
    });
    let (queued, notify) = r?;
    if let Some(p) = notify {
        data_available(k, p);
    }
    Ok(queued)
}

fn enqueue_in(k: &mut Kernel, m: &mut GuestMem<'_>, mem: &mut Memory, data: &[u8]) -> (bool, bool) {
    let word = |b: &[u8], at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
    let hdr = mem.read(k, m, 0, HEADER as usize);
    let (head, tail) = (word(&hdr, 4), word(&hdr, 8));
    let size = data.len() as u32;
    if size > u32::MAX - ENTRY_HEADER {
        return (false, false);
    }
    let entry = size + ENTRY_HEADER;
    if CAPACITY < tail || CAPACITY < head {
        return (false, false);
    }
    let at = |o: u32| HEADER + u64::from(o);
    let new_tail = if tail >= head {
        if entry <= u32::MAX - tail && tail + entry <= CAPACITY {
            mem.kernel_write(k, m, at(tail), &size.to_le_bytes());
            mem.kernel_write(k, m, at(tail) + 4, data);
            tail + entry
        } else if head > entry {
            mem.kernel_write(k, m, at(0), &size.to_le_bytes());
            if CAPACITY - tail >= ENTRY_HEADER {
                mem.kernel_write(k, m, at(tail), &size.to_le_bytes());
            }
            mem.kernel_write(k, m, at(0) + 4, data);
            entry
        } else {
            return (false, false);
        }
    } else if head - tail > entry {
        mem.kernel_write(k, m, at(tail), &size.to_le_bytes());
        mem.kernel_write(k, m, at(tail) + 4, data);
        tail + entry
    } else {
        return (false, false);
    };
    mem.kernel_write(k, m, 8, &new_tail.to_le_bytes());
    let head = if tail != head { word(&mem.read(k, m, 0, HEADER as usize), 4) } else { head };
    (true, tail == head)
}

/// `IODataQueue::sendDataAvailableNotification`: a message of only a header
/// (a copy of the send right, id 0), sent with `MACH64_SEND_TIMEOUT` and no
/// time, so a full port drops it.
fn data_available(k: &mut Kernel, port: ObjId) {
    use super::super::ipc::msg::{bits, Kmsg, Sender};
    use super::super::ipc::right::msgt;
    let ipc = k.ipc();
    if !ipc.port(port).active {
        return;
    }
    ipc.copy_send(port);
    let m = Kmsg { bits: bits::set(msgt::PORT_SEND, 0, 0, 0), size: 24, dest: port, reply: None, voucher: None, voucher_raw: 0, id: 0, body: Vec::new(), descs: Vec::new(), sender: Sender::KERNEL, aux: Vec::new(), keep_alive: false, ppriority: 0, qos_override: 0, imp: None };
    k.darwin_kernel_send_droppable(Box::new(m));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ring_gives_the_entries_up_to_a_swap() {
        let mut r = Ring::default();
        let e = |id, items, kind| Entry { issued: u64::from(id), requested: 0, id, items, kind };
        r.push(e(1, 0x40, 0));
        r.push(e(2, 0, 0));
        r.push(e(3, 0x40, 7));
        r.push(e(4, 0x40, 0));
        // No entry has swap 9: nothing taken.
        assert!(r.take_through(9).is_empty());
        // Up to swap 3: swap 1 (missed), swap 2 asking for nothing, and
        // swap 3 of kind 7 are taken; only swap 1 is reported.
        let got: Vec<(u32, bool)> = r.take_through(3).iter().map(|(e, m)| (e.id, *m)).collect();
        assert_eq!(got, vec![(1, false)]);
        let got: Vec<(u32, bool)> = r.take_through(4).iter().map(|(e, m)| (e.id, *m)).collect();
        assert_eq!(got, vec![(4, true)]);
        r.push(e(5, 0x40, 0));
        r.reset();
        assert!(r.take_through(5).is_empty());
    }

    #[test]
    fn items_are_counted_by_the_records_asking() {
        let mut p = Pipe::default();
        p.update(0, 0x40 | 0x100);
        p.update(0, 0x40);
        assert_eq!(p.items(), 0x140);
        p.update(0x40 | 0x100, 0);
        assert_eq!(p.items(), 0x40);
        // An underrun leaves the count at zero.
        p.update(0x200, 0);
        p.set_crc(true);
        p.set_crc(true);
        assert_eq!(p.items(), 0x68);
        p.set_crc(false);
        assert_eq!(p.items(), 0x40);
    }
}
