//! The executor's surface table in the GPU Worker: the bytes of each
//! IOSurface the GPU uses, as the kernel hands them over and as the GPU
//! writes them. It is the page's counterpart of gexc's
//! (`host_webmetal/surfaces.rs`), with the kernel's calls on its table
//! (`iosurface::executor::SurfaceTable`) arriving as ring messages:
//!
//! - `bind`: the surface is the GPU's from now on, with its description;
//! - `cpu_wrote`: the bytes the tasks changed, each time the kernel gathers
//!   them (only the changed runs travel);
//! - `read_back`: what the GPU wrote since the kernel last asked, which the
//!   kernel writes into the surface's memory before the next task's lock;
//! - `released`: the surface is gone.
//!
//! A surface's bytes are its memory's, from its first byte: the kernel
//! binds only surfaces whose bytes start at their memory's first byte, so
//! the executor's offsets are offsets in the memory.

use std::collections::HashMap;

use crate::protocol::SurfaceDesc;

/// One surface the GPU uses.
#[derive(Debug)]
struct Mirror {
    desc: SurfaceDesc,
    /// Its memory: the kernel's bytes as handed over, with the GPU's writes.
    bytes: Vec<u8>,
    /// Advances each time the kernel hands over bytes the tasks changed: the
    /// executor reads the surface again when it moves.
    generation: u32,
    /// The GPU's writes the kernel has not taken back yet: runs of bytes by
    /// their offset in the memory, in the order they were written.
    gpu: Vec<(u64, Vec<u8>)>,
}

/// Why the executor's access to a surface failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Miss {
    /// The GPU has no such surface.
    Unknown,
    /// The range lies outside its memory.
    OutOfRange,
}

/// The surfaces the GPU uses, by id.
#[derive(Debug, Default)]
pub struct Surfaces {
    map: HashMap<u32, Mirror>,
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

impl Surfaces {
    /// `bind`: a surface bound again keeps its bytes.
    pub fn bind(&mut self, desc: SurfaceDesc) {
        let size = usize::try_from(desc.alloc_size).unwrap_or(0);
        self.map
            .entry(desc.id)
            .and_modify(|m| m.desc = desc.clone())
            .or_insert_with(|| Mirror { bytes: vec![0; size], desc, generation: 0, gpu: Vec::new() });
    }

    /// `cpu_wrote`: the tasks' bytes of `runs` (offsets in the memory).
    pub fn cpu_wrote(&mut self, id: u32, runs: &[(u64, &[u8])]) {
        let Some(m) = self.map.get_mut(&id) else { return };
        for (at, bytes) in runs {
            let end = *at as usize + bytes.len();
            if m.bytes.len() < end {
                m.bytes.resize(end, 0);
            }
            m.bytes[*at as usize..end].copy_from_slice(bytes);
            // The tasks wrote these after the GPU's writes reached the
            // surface: theirs are what a later lock sees.
            cut(&mut m.gpu, *at, bytes.len() as u64);
        }
        m.generation = m.generation.wrapping_add(1);
    }

    /// `read_back`: the GPU's writes since the kernel last asked, taken once.
    pub fn read_back(&mut self, id: u32) -> Vec<(u64, Vec<u8>)> {
        self.map.get_mut(&id).map(|m| std::mem::take(&mut m.gpu)).unwrap_or_default()
    }

    /// `released`.
    pub fn released(&mut self, id: u32) {
        self.map.remove(&id);
    }

    /// Surface `id`'s description and the generation of its bytes.
    pub fn describe(&self, id: u32) -> Option<(&SurfaceDesc, u32)> {
        self.map.get(&id).map(|m| (&m.desc, m.generation))
    }

    /// Copy the bytes at `at` in surface `id`'s memory into `dst`.
    pub fn read(&self, id: u32, at: u64, dst: &mut [u8]) -> Result<(), Miss> {
        let m = self.map.get(&id).ok_or(Miss::Unknown)?;
        let r = range(at, dst.len(), m.bytes.len()).ok_or(Miss::OutOfRange)?;
        dst.copy_from_slice(&m.bytes[r]);
        Ok(())
    }

    /// The GPU wrote `new` at `at` in surface `id`'s memory, where it last
    /// saw `shadow`: the bytes that differ are written, and kept for the
    /// kernel to take back.
    pub fn write_changed(&mut self, id: u32, at: u64, new: &[u8], shadow: &[u8]) -> Result<(), Miss> {
        assert_eq!(new.len(), shadow.len(), "write_changed: new and shadow differ in length");
        let m = self.map.get_mut(&id).ok_or(Miss::Unknown)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn desc(id: u32) -> SurfaceDesc {
        SurfaceDesc {
            id,
            width: 4,
            height: 1,
            bytes_per_row: 16,
            bytes_per_element: 4,
            element_width: 1,
            element_height: 1,
            offset: 0,
            pixel_format: 0,
            alloc_size: 16,
            planes: Vec::new(),
            seed: 0,
        }
    }

    #[test]
    fn cpu_writes_reach_the_gpu_and_move_the_generation() {
        let mut s = Surfaces::default();
        s.bind(desc(7));
        let g0 = s.describe(7).unwrap().1;
        s.cpu_wrote(7, &[(4, &[1, 2, 3, 4])]);
        assert_ne!(s.describe(7).unwrap().1, g0);
        let mut out = [0u8; 4];
        s.read(7, 4, &mut out).unwrap();
        assert_eq!(out, [1, 2, 3, 4]);
        assert_eq!(s.read(7, 14, &mut out), Err(Miss::OutOfRange));
        assert_eq!(s.read(8, 0, &mut out), Err(Miss::Unknown));
    }

    #[test]
    fn gpu_writes_go_back_once_and_only_where_they_differ() {
        let mut s = Surfaces::default();
        s.bind(desc(1));
        s.cpu_wrote(1, &[(0, &[9u8; 16])]);
        s.write_changed(1, 2, &[9, 5, 5, 9], &[9, 9, 9, 9]).unwrap();
        assert_eq!(s.read_back(1), vec![(3, vec![5, 5])]);
        assert!(s.read_back(1).is_empty(), "taken once");
    }

    #[test]
    fn a_later_cpu_write_supersedes_the_gpu_bytes_it_covers() {
        let mut s = Surfaces::default();
        s.bind(desc(2));
        s.write_changed(2, 0, &[1, 1, 1, 1, 1, 1], &[0; 6]).unwrap();
        s.cpu_wrote(2, &[(2, &[7, 7])]);
        assert_eq!(s.read_back(2), vec![(0, vec![1, 1]), (4, vec![1, 1])]);
        s.released(2);
        assert!(s.describe(2).is_none());
    }
}
