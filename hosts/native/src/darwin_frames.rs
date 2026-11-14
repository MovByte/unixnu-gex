//! A presentation sink that records the frames the Darwin framebuffer
//! presents (`gex_kernel::darwin::iomfb::sink`), for tests: each frame goes
//! to its own file in a directory, `frame-<n>.bin` in the order presented,
//! with nothing converted. Each change of the panel's power goes to
//! `panel-<n>.txt`, numbered in the same order as the frames, holding
//! `on` or `off`.
//!
//! A file holds, all little-endian:
//!
//! | field | size |
//! | --- | --- |
//! | magic `GEXF` | 4 |
//! | version (1) | 4 |
//! | swap id | 4 |
//! | vertical blank count, its absolute time | 8, 8 |
//! | panel width, height | 4, 4 |
//! | layer count | 4 |
//!
//! then each layer: its index, surface id and pixel format (4 each), the
//! surface's width and height (8 each), the source and destination
//! rectangles (x, y, w, h, 4 each), the transform (4), the plane count (4)
//! and each plane (offset, width, height, bytes per row: 8 each; bytes per
//! element, element width, element height: 4 each; size: 8), then the
//! surface's byte count (8) and its bytes.

use gex_kernel::darwin::iomfb::sink::{Frame, PresentSink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

pub struct Recorder {
    dir: PathBuf,
    next: AtomicU32,
}

impl Recorder {
    pub fn new(dir: PathBuf) -> Recorder {
        Recorder { dir, next: AtomicU32::new(0) }
    }
}

fn encode(f: &Frame) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"GEXF");
    b.extend_from_slice(&1u32.to_le_bytes());
    b.extend_from_slice(&f.swap_id.to_le_bytes());
    b.extend_from_slice(&f.vbl.to_le_bytes());
    b.extend_from_slice(&f.time.to_le_bytes());
    b.extend_from_slice(&f.panel.0.to_le_bytes());
    b.extend_from_slice(&f.panel.1.to_le_bytes());
    b.extend_from_slice(&(f.layers.len() as u32).to_le_bytes());
    for l in &f.layers {
        b.extend_from_slice(&l.index.to_le_bytes());
        b.extend_from_slice(&l.surface.to_le_bytes());
        b.extend_from_slice(&l.pixel_format.to_le_bytes());
        b.extend_from_slice(&l.width.to_le_bytes());
        b.extend_from_slice(&l.height.to_le_bytes());
        for r in [l.src, l.dst] {
            for v in [r.x, r.y, r.w, r.h] {
                b.extend_from_slice(&v.to_le_bytes());
            }
        }
        b.extend_from_slice(&l.transform.to_le_bytes());
        b.extend_from_slice(&(l.planes.len() as u32).to_le_bytes());
        for p in &l.planes {
            for v in [p.offset, p.width, p.height, p.bytes_per_row] {
                b.extend_from_slice(&v.to_le_bytes());
            }
            for v in [p.bytes_per_element, p.element_width, p.element_height] {
                b.extend_from_slice(&v.to_le_bytes());
            }
            b.extend_from_slice(&p.size.to_le_bytes());
        }
        b.extend_from_slice(&(l.bytes.len() as u64).to_le_bytes());
        b.extend_from_slice(&l.bytes);
    }
    b
}

impl PresentSink for Recorder {
    fn present(&self, frame: &Frame) -> Result<(), String> {
        let n = self.next.fetch_add(1, Ordering::Relaxed);
        let path = self.dir.join(format!("frame-{n}.bin"));
        std::fs::write(&path, encode(frame)).map_err(|e| format!("recording the frame to {}: {e}", path.display()))
    }

    fn panel(&self, on: bool) -> Result<(), String> {
        let n = self.next.fetch_add(1, Ordering::Relaxed);
        let path = self.dir.join(format!("panel-{n}.txt"));
        std::fs::write(&path, if on { "on\n" } else { "off\n" }).map_err(|e| format!("recording the panel's power to {}: {e}", path.display()))
    }
}
