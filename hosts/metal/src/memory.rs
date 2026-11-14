//! The memory of a connection's task, as the GPU Worker reaches it.
//!
//! A process's memory is its Worker's shared wasm memory (a
//! `WebAssembly.Memory`, or its `SharedArrayBuffer`), which the page hands
//! the GPU Worker once per process
//! (`GpuWorker::attach_memory`), with the process's mapping table: a second
//! `SharedArrayBuffer` its kernel keeps current, in which each of the task's
//! mappings is an entry (its guest address range, its protection, and where
//! its bytes are in the memory). The executor's accesses are checked against
//! the table as the kernel's `TaskMemory` checks them against the task's
//! mappings, as a driver's `IOMemoryDescriptor` over the task's range would
//! be when prepared: every page mapped, readable for a read, writable for a
//! write; a write into an executable mapping is refused (the kernel's own
//! copies into one retire what was translated of it, which a copy from the
//! GPU Worker cannot).
//!
//! The table (little-endian 32-bit words):
//!
//! | Word | Content |
//! | --- | --- |
//! | 0 | sequence: odd while the kernel rewrites the table |
//! | 1 | entry count |
//! | 2 | 1 once the task is gone (it exited, or `execve` replaced its address space) |
//! | 3 | unused |
//! | 4 + 8 i | entry i: start (low, high), end (low, high), protection (`PROT_READ` 1, `PROT_WRITE` 2, `PROT_EXEC` 4), offset in the memory (low, high), unused |
//!
//! Entries are sorted by start and do not overlap.

/// `PROT_READ`, `PROT_WRITE`, `PROT_EXEC`.
pub const READ: u32 = 1;
pub const WRITE: u32 = 2;
pub const EXEC: u32 = 4;

/// Words before the first entry, and per entry.
pub const TABLE_HEADER: usize = 4;
pub const ENTRY: usize = 8;

/// One mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub start: u64,
    pub end: u64,
    pub prot: u32,
    /// Where `start`'s byte is in the memory.
    pub offset: u64,
}

/// Why an access failed (the kernel's `FaultKind`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultKind {
    Unmapped,
    Protection,
    Gone,
    Code,
}

/// A failed access: the first address that could not be reached, and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault {
    pub addr: u64,
    pub kind: FaultKind,
}

/// The pieces of `[addr, addr + len)` in the memory, as (offset, length), in
/// address order; or the fault. `size` is the memory's length.
pub fn pieces(map: &[Mapping], addr: u64, len: u64, need: u32, size: u64) -> Result<Vec<(u64, u64)>, Fault> {
    let mut out = Vec::new();
    if len == 0 {
        return Ok(out);
    }
    let end = addr.checked_add(len).ok_or(Fault { addr, kind: FaultKind::Unmapped })?;
    let mut at = addr;
    while at < end {
        let i = map.partition_point(|m| m.end <= at);
        let Some(m) = map.get(i).filter(|m| m.start <= at) else {
            return Err(Fault { addr: at, kind: FaultKind::Unmapped });
        };
        if m.prot & need != need {
            return Err(Fault { addr: at, kind: FaultKind::Protection });
        }
        if need & WRITE != 0 && m.prot & EXEC != 0 {
            return Err(Fault { addr: at, kind: FaultKind::Code });
        }
        let stop = end.min(m.end);
        let off = m.offset + (at - m.start);
        if off.checked_add(stop - at).is_none_or(|e| e > size) {
            // A mapping whose bytes are not in the memory: the table is the
            // kernel's, so this is a kernel defect, and nothing is read.
            return Err(Fault { addr: at, kind: FaultKind::Unmapped });
        }
        match out.last_mut() {
            Some((o, l)) if *o + *l == off => *l += stop - at,
            _ => out.push((off, stop - at)),
        }
        at = stop;
    }
    Ok(out)
}

/// The table's words as mappings; `None` when they are not a table (a count
/// past the words, or entries out of order).
pub fn parse(words: &[u32]) -> Option<Vec<Mapping>> {
    let count = *words.get(1)? as usize;
    let need = TABLE_HEADER.checked_add(count.checked_mul(ENTRY)?)?;
    if need > words.len() {
        return None;
    }
    let w = |i: usize, k: usize| words[TABLE_HEADER + ENTRY * i + k];
    let q = |lo: u32, hi: u32| u64::from(lo) | (u64::from(hi) << 32);
    let mut out: Vec<Mapping> = Vec::with_capacity(count);
    for i in 0..count {
        let m = Mapping { start: q(w(i, 0), w(i, 1)), end: q(w(i, 2), w(i, 3)), prot: w(i, 4), offset: q(w(i, 5), w(i, 6)) };
        if m.end <= m.start || out.last().is_some_and(|p| p.end > m.start) {
            return None;
        }
        out.push(m);
    }
    Some(out)
}

#[cfg(target_arch = "wasm32")]
pub use web::TaskMemory;

#[cfg(target_arch = "wasm32")]
mod web {
    use std::cell::RefCell;

    use js_sys::{Atomics, Int32Array, Reflect, SharedArrayBuffer, Uint8Array};
    use wasm_bindgen::{JsCast, JsValue};

    use super::*;

    /// A process's memory and mapping table, and the table as last read.
    pub struct TaskMemory {
        /// The `WebAssembly.Memory`, or the `SharedArrayBuffer` itself.
        source: JsValue,
        bytes: RefCell<Uint8Array>,
        table: Int32Array,
        cache: RefCell<(i32, Vec<Mapping>)>,
    }

    /// The memory's bytes as they are now: a shared memory that grows gets a
    /// longer buffer, and the earlier one keeps its length.
    fn view(source: &JsValue) -> Uint8Array {
        match source.dyn_ref::<SharedArrayBuffer>() {
            Some(b) => Uint8Array::new(b),
            None => Uint8Array::new(&Reflect::get(source, &JsValue::from_str("buffer")).unwrap_or(JsValue::UNDEFINED)),
        }
    }

    impl TaskMemory {
        /// `memory`: a shared `WebAssembly.Memory` or a `SharedArrayBuffer`.
        pub fn new(memory: JsValue, table: &SharedArrayBuffer) -> TaskMemory {
            let bytes = view(&memory);
            TaskMemory { source: memory, bytes: RefCell::new(bytes), table: Int32Array::new(table), cache: RefCell::new((-1, Vec::new())) }
        }

        /// The memory's length, after taking a grown buffer when `need`
        /// bytes are past the one held.
        fn size(&self, need: u64) -> u64 {
            let have = u64::from(self.bytes.borrow().length());
            if need > have {
                *self.bytes.borrow_mut() = view(&self.source);
            }
            u64::from(self.bytes.borrow().length())
        }

        /// The end of the furthest piece of an access.
        fn reach(map: &[Mapping], addr: u64, len: u64, need: u32) -> Result<u64, Fault> {
            Ok(pieces(map, addr, len, need, u64::MAX)?.iter().map(|(o, l)| o + l).max().unwrap_or(0))
        }

        fn load(&self, i: u32) -> i32 {
            Atomics::load(&self.table, i).unwrap_or(0)
        }

        /// The current mappings (read again when the sequence moved), or that
        /// the task is gone.
        fn mappings(&self) -> Result<std::cell::Ref<'_, (i32, Vec<Mapping>)>, Fault> {
            loop {
                if self.load(2) != 0 {
                    return Err(Fault { addr: 0, kind: FaultKind::Gone });
                }
                let seq = self.load(0);
                if seq & 1 != 0 {
                    continue;
                }
                if self.cache.borrow().0 == seq {
                    return Ok(self.cache.borrow());
                }
                let count = self.load(1).max(0) as usize;
                let n = (TABLE_HEADER + ENTRY * count).min(self.table.length() as usize);
                let mut words = vec![0i32; n];
                self.table.subarray(0, n as u32).copy_to(&mut words);
                if self.load(0) != seq {
                    continue;
                }
                let words: Vec<u32> = words.into_iter().map(|w| w as u32).collect();
                let Some(map) = parse(&words) else {
                    return Err(Fault { addr: 0, kind: FaultKind::Unmapped });
                };
                *self.cache.borrow_mut() = (seq, map);
                return Ok(self.cache.borrow());
            }
        }

        pub fn read(&self, addr: u64, dst: &mut [u8]) -> Result<(), Fault> {
            let m = self.mappings()?;
            let size = self.size(Self::reach(&m.1, addr, dst.len() as u64, READ)?);
            let bytes = self.bytes.borrow();
            let mut at = 0usize;
            for (off, len) in pieces(&m.1, addr, dst.len() as u64, READ, size)? {
                let len = len as usize;
                bytes.subarray(off as u32, (off as usize + len) as u32).copy_to(&mut dst[at..at + len]);
                at += len;
            }
            Ok(())
        }

        pub fn write(&self, addr: u64, src: &[u8]) -> Result<(), Fault> {
            let m = self.mappings()?;
            let size = self.size(Self::reach(&m.1, addr, src.len() as u64, WRITE)?);
            let bytes = self.bytes.borrow();
            let mut at = 0usize;
            for (off, len) in pieces(&m.1, addr, src.len() as u64, WRITE, size)? {
                let len = len as usize;
                bytes.subarray(off as u32, (off as usize + len) as u32).copy_from(&src[at..at + len]);
                at += len;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> Vec<Mapping> {
        vec![
            Mapping { start: 0x1000, end: 0x3000, prot: READ | WRITE, offset: 0x10000 },
            Mapping { start: 0x3000, end: 0x4000, prot: READ, offset: 0x12000 },
            Mapping { start: 0x5000, end: 0x6000, prot: READ | EXEC, offset: 0x20000 },
        ]
    }

    #[test]
    fn contiguous_mappings_join_and_holes_fault() {
        assert_eq!(pieces(&map(), 0x2ff0, 0x20, READ, 1 << 20), Ok(vec![(0x11ff0, 0x20)]));
        assert_eq!(pieces(&map(), 0x3ff0, 0x20, READ, 1 << 20), Err(Fault { addr: 0x4000, kind: FaultKind::Unmapped }));
        assert_eq!(pieces(&map(), 0x800, 0x10, READ, 1 << 20), Err(Fault { addr: 0x800, kind: FaultKind::Unmapped }));
        assert_eq!(pieces(&map(), 0x1000, 0, WRITE, 0), Ok(vec![]));
    }

    #[test]
    fn protections_are_checked_per_mapping() {
        assert_eq!(pieces(&map(), 0x2ff0, 0x20, WRITE, 1 << 20), Err(Fault { addr: 0x3000, kind: FaultKind::Protection }));
        assert_eq!(pieces(&map(), 0x5000, 4, WRITE, 1 << 20), Err(Fault { addr: 0x5000, kind: FaultKind::Protection }));
        let rwx = [Mapping { start: 0, end: 0x1000, prot: READ | WRITE | EXEC, offset: 0 }];
        assert_eq!(pieces(&rwx, 0x10, 4, WRITE, 1 << 20), Err(Fault { addr: 0x10, kind: FaultKind::Code }));
        assert_eq!(pieces(&rwx, 0x10, 4, READ, 1 << 20), Ok(vec![(0x10, 4)]));
    }

    #[test]
    fn split_mappings_give_pieces() {
        let m = [
            Mapping { start: 0x1000, end: 0x2000, prot: READ, offset: 0x8000 },
            Mapping { start: 0x2000, end: 0x3000, prot: READ, offset: 0x1000 },
        ];
        assert_eq!(pieces(&m, 0x1ff8, 0x10, READ, 1 << 20), Ok(vec![(0x8ff8, 8), (0x1000, 8)]));
        assert_eq!(pieces(&m, 0x1ff8, 0x10, READ, 0x1004).unwrap_err().kind, FaultKind::Unmapped);
    }

    #[test]
    fn tables_parse_and_reject_disorder() {
        let mut w = vec![2u32, 2, 0, 0];
        w.extend([0x1000, 0, 0x2000, 0, READ, 0x40, 0, 0]);
        w.extend([0x2000, 1, 0x3000, 1, READ | WRITE, 0x80, 0, 0]);
        let m = parse(&w).unwrap();
        assert_eq!(m[1], Mapping { start: 0x1_0000_2000, end: 0x1_0000_3000, prot: 3, offset: 0x80 });
        w[1] = 3;
        assert_eq!(parse(&w), None, "a count past the words");
        w[1] = 2;
        w[TABLE_HEADER + ENTRY + 1] = 0;
        w[TABLE_HEADER + ENTRY + 3] = 0;
        w[TABLE_HEADER + ENTRY] = 0x1800;
        assert_eq!(parse(&w), None, "overlapping entries");
    }
}
