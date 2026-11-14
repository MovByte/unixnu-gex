//! The executor's surface table (`gex_kernel::darwin::iosurface::executor`):
//! the bytes of each IOSurface the GPU uses, as the kernel hands them over
//! and as the GPU writes them.
//!
//! The kernel keeps a surface's memory (its backing store) coherent with
//! each task's view of it at the IOSurface boundaries; for a surface bound
//! to the GPU it also hands this table the bytes its tasks changed, each
//! time it gathers them ([`SurfaceTable::cpu_wrote`]), and before a task
//! locks the surface it takes back what the GPU wrote since it last asked
//! ([`SurfaceTable::read_back`]). The executor reads and writes a surface
//! here ([`Surfaces::read`], [`Surfaces::write_changed`]) on its own thread.
//!
//! A surface's bytes are its memory's, from its first byte; the executor
//! addresses them from the surface's own first byte (the description's
//! offset into its memory).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use gex_kernel::darwin::iosurface::executor::{SurfaceDesc, SurfaceTable};

/// One surface the GPU uses.
#[derive(Debug, Default)]
struct Mirror {
    /// Its memory: the kernel's backing store as handed over, with the GPU's
    /// writes.
    bytes: Vec<u8>,
    /// Advances each time the kernel hands over bytes the tasks changed: the
    /// executor reads the surface again when it moves.
    generation: u32,
    /// The GPU's writes the kernel has not taken back yet: runs of bytes by
    /// their offset in the memory, in the order they were written.
    gpu: Vec<(u64, Vec<u8>)>,
}

/// The surfaces the GPU uses, by id.
#[derive(Debug, Default)]
pub struct Surfaces {
    map: Mutex<HashMap<u32, Mirror>>,
}

/// Why the executor's access to a surface failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Miss {
    /// The GPU has no such surface.
    Unknown,
    /// The range lies outside its memory.
    OutOfRange,
}

impl Surfaces {
    fn map(&self) -> std::sync::MutexGuard<'_, HashMap<u32, Mirror>> {
        self.map.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The generation of surface `id`'s bytes; none for a surface the GPU
    /// does not have.
    pub fn generation(&self, id: u32) -> Option<u32> {
        self.map().get(&id).map(|m| m.generation)
    }

    /// Copy the bytes at `at` in surface `id`'s memory into `dst`.
    pub fn read(&self, id: u32, at: u64, dst: &mut [u8]) -> Result<(), Miss> {
        let map = self.map();
        let m = map.get(&id).ok_or(Miss::Unknown)?;
        let r = range(at, dst.len(), m.bytes.len()).ok_or(Miss::OutOfRange)?;
        dst.copy_from_slice(&m.bytes[r]);
        Ok(())
    }

    /// The GPU wrote `new` at `at` in surface `id`'s memory, where it last
    /// saw `shadow`: the bytes that differ are written, and kept for the
    /// kernel to take back.
    pub fn write_changed(&self, id: u32, at: u64, new: &[u8], shadow: &[u8]) -> Result<(), Miss> {
        assert_eq!(new.len(), shadow.len(), "write_changed: new and shadow differ in length");
        let mut map = self.map();
        let m = map.get_mut(&id).ok_or(Miss::Unknown)?;
        range(at, new.len(), m.bytes.len()).ok_or(Miss::OutOfRange)?;
        let mut i = 0;
        while i < new.len() {
            if new[i] == shadow[i] {
                i += 1;
                continue;
            }
            let start = i;
            while i < new.len() && new[i] != shadow[i] {
                i += 1;
            }
            let o = at as usize + start;
            m.bytes[o..o + (i - start)].copy_from_slice(&new[start..i]);
            m.gpu.push((o as u64, new[start..i].to_vec()));
        }
        Ok(())
    }
}

/// `[at, at + len)` as an index range into `size` bytes, if it fits.
fn range(at: u64, len: usize, size: usize) -> Option<std::ops::Range<usize>> {
    let start = usize::try_from(at).ok()?;
    let end = start.checked_add(len)?;
    (end <= size).then_some(start..end)
}

/// Cut `[at, at + len)` out of the runs: those bytes are the tasks' now.
fn cut(runs: &mut Vec<(u64, Vec<u8>)>, at: u64, len: u64) {
    let end = at + len;
    let mut out = Vec::with_capacity(runs.len());
    for (s, bytes) in runs.drain(..) {
        let e = s + bytes.len() as u64;
        if e <= at || s >= end {
            out.push((s, bytes));
            continue;
        }
        if s < at {
            out.push((s, bytes[..(at - s) as usize].to_vec()));
        }
        if e > end {
            out.push((end, bytes[(end - s) as usize..].to_vec()));
        }
    }
    *runs = out;
}

/// The table the kernel calls, over the shared surfaces.
pub struct Table(pub Arc<Surfaces>);

impl SurfaceTable for Table {
    fn bind(&self, desc: &SurfaceDesc) {
        self.0.map().entry(desc.id).or_default();
    }

    fn cpu_wrote(&self, id: u32, bytes: &[u8], ranges: &[(u64, u64)]) {
        let mut map = self.0.map();
        let Some(m) = map.get_mut(&id) else { return };
        if m.bytes.len() < bytes.len() {
            m.bytes.resize(bytes.len(), 0);
        }
        for &(at, len) in ranges {
            let Some(r) = range(at, len as usize, bytes.len()) else { continue };
            m.bytes[r.clone()].copy_from_slice(&bytes[r]);
            // The tasks wrote these after the GPU's writes reached the
            // surface: theirs are what a later lock sees.
            cut(&mut m.gpu, at, len);
        }
        m.generation = m.generation.wrapping_add(1);
    }

    fn read_back(&self, id: u32, bytes: &mut [u8]) -> bool {
        let mut map = self.0.map();
        let Some(m) = map.get_mut(&id) else { return false };
        let runs = std::mem::take(&mut m.gpu);
        for (at, run) in &runs {
            if let Some(r) = range(*at, run.len(), bytes.len()) {
                bytes[r].copy_from_slice(run);
            }
        }
        !runs.is_empty()
    }

    fn released(&self, id: u32) {
        self.0.map().remove(&id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desc(id: u32) -> SurfaceDesc {
        SurfaceDesc { id, width: 4, height: 1, bytes_per_row: 16, bytes_per_element: 4, element_width: 1, element_height: 1, offset: 0, pixel_format: 0, alloc_size: 16, planes: Vec::new(), seed: 0 }
    }

    #[test]
    fn cpu_writes_reach_the_gpu_and_move_the_generation() {
        let s = Arc::new(Surfaces::default());
        let t = Table(Arc::clone(&s));
        t.bind(&desc(7));
        let g0 = s.generation(7).unwrap();
        let mut backing = vec![0u8; 16];
        backing[4..8].copy_from_slice(&[1, 2, 3, 4]);
        t.cpu_wrote(7, &backing, &[(4, 4)]);
        assert_ne!(s.generation(7).unwrap(), g0);
        let mut out = [0u8; 4];
        s.read(7, 4, &mut out).unwrap();
        assert_eq!(out, [1, 2, 3, 4]);
        assert_eq!(s.read(7, 14, &mut out), Err(Miss::OutOfRange));
        assert_eq!(s.read(8, 0, &mut out), Err(Miss::Unknown));
    }

    #[test]
    fn gpu_writes_go_back_once_and_only_where_they_differ() {
        let s = Arc::new(Surfaces::default());
        let t = Table(Arc::clone(&s));
        t.bind(&desc(1));
        t.cpu_wrote(1, &[9u8; 16], &[(0, 16)]);
        s.write_changed(1, 2, &[9, 5, 5, 9], &[9, 9, 9, 9]).unwrap();
        // The kernel's store has a task's change elsewhere, which the GPU's
        // write must leave alone.
        let mut backing = vec![9u8; 16];
        backing[10] = 1;
        assert!(t.read_back(1, &mut backing));
        assert_eq!(&backing[..6], &[9, 9, 9, 5, 5, 9]);
        assert_eq!(backing[10], 1);
        assert!(!t.read_back(1, &mut backing), "taken once");
    }

    #[test]
    fn a_later_cpu_write_supersedes_the_gpu_bytes_it_covers() {
        let s = Arc::new(Surfaces::default());
        let t = Table(Arc::clone(&s));
        t.bind(&desc(2));
        t.cpu_wrote(2, &[0u8; 16], &[(0, 16)]);
        s.write_changed(2, 0, &[1, 1, 1, 1, 1, 1], &[0; 6]).unwrap();
        let mut cpu = vec![0u8; 16];
        cpu[2..4].copy_from_slice(&[7, 7]);
        t.cpu_wrote(2, &cpu, &[(2, 2)]);
        let mut backing = cpu.clone();
        assert!(t.read_back(2, &mut backing));
        assert_eq!(&backing[..6], &[1, 1, 7, 7, 1, 1]);
        t.released(2);
        assert_eq!(s.generation(2), None);
    }
}
