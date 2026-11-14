//! The messages between the guest's Workers and the GPU Worker, and their
//! byte encodings (little-endian). `js/metal-ring.mjs` in `hosts/browser`
//! encodes and decodes the same layouts; the ring that carries them is
//! [`crate::ring`]'s.
//!
//! Each message is a frame: a 16-byte header (payload length, kind, and two
//! words `a` and `b`) and the payload, padded to 8 bytes. The guest's side
//! sends requests on the shared request ring; the GPU Worker answers on the
//! ring of the endpoint `a` names (an endpoint is one process's kernel).
//!
//! The requests are the kernel's calls on its executor, one for one:
//!
//! | Kind | Kernel call | Payload |
//! | --- | --- | --- |
//! | [`OPEN`] | `Host::open` | conn u64, pid i32, memory u32 |
//! | [`CONTROL`] | `Host::control` | conn u64, token u64, the request record |
//! | [`CLOSE`] | `Host::close` | conn u64 |
//! | [`SURFACE_BIND`] | `SurfaceTable::bind` | [`SurfaceDesc`] |
//! | [`SURFACE_CPU_WROTE`] | `SurfaceTable::cpu_wrote` | id u32, count u32, count × (offset u64, length u64, bytes) |
//! | [`SURFACE_READ_BACK`] | `SurfaceTable::read_back` | id u32, pad u32, token u64 |
//! | [`SURFACE_RELEASED`] | `SurfaceTable::released` | id u32 |
//! | [`PRESENT`] | `PresentSink::present` | [`Frame`] |
//! | [`PANEL`] | `PresentSink::panel` | on u32 |
//!
//! The GPU Worker's messages to an endpoint:
//!
//! | Kind | Meaning | Payload |
//! | --- | --- | --- |
//! | [`REPLY`] | a control request answered (`Done::answer`) | token u64, outcome u32 (0 reply, 1 refused), pad u32, reply record or reason |
//! | [`RING`] | events pending for a queue (`wire::ring`) | conn u64, queue u64 (0: device-level) |
//! | [`REPORT`] | what the executor could not do (`wire::report`) | conn u64 (0: none), text |
//! | [`READ_BACK`] | the GPU's writes to a surface since it was last asked | token u64, count u32, pad u32, count × (offset u64, length u64, bytes) |
//! | [`PRESENTED`] | a frame shown, or why not (`present`'s result) | swap u32, outcome u32 (0 shown, 1 not), reason |
//! | [`PANEL_DONE`] | the panel's power changed, or why not (`panel`'s result) | outcome u32, pad u32, reason |

/// The header of a frame: payload length, kind, `a`, `b`.
pub const HEADER: usize = 16;

pub const OPEN: u32 = 1;
pub const CONTROL: u32 = 2;
pub const CLOSE: u32 = 3;
pub const SURFACE_BIND: u32 = 4;
pub const SURFACE_CPU_WROTE: u32 = 5;
pub const SURFACE_READ_BACK: u32 = 6;
pub const SURFACE_RELEASED: u32 = 7;
pub const PRESENT: u32 = 8;
pub const PANEL: u32 = 9;

pub const REPLY: u32 = 101;
pub const RING: u32 = 102;
pub const REPORT: u32 = 103;
pub const READ_BACK: u32 = 104;
pub const PRESENTED: u32 = 105;
pub const PANEL_DONE: u32 = 106;

/// Bytes a frame of `payload` bytes takes in a ring: header and payload,
/// padded to 8.
pub fn framed(payload: usize) -> usize {
    (HEADER + payload).next_multiple_of(8)
}

/// A frame's header and payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub kind: u32,
    pub a: u32,
    pub b: u32,
    pub payload: Vec<u8>,
}

impl Message {
    pub fn new(kind: u32, a: u32, payload: Vec<u8>) -> Message {
        Message { kind, a, b: 0, payload }
    }

    /// The frame's bytes: header, payload, padding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(framed(self.payload.len()));
        out.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.kind.to_le_bytes());
        out.extend_from_slice(&self.a.to_le_bytes());
        out.extend_from_slice(&self.b.to_le_bytes());
        out.extend_from_slice(&self.payload);
        out.resize(framed(self.payload.len()), 0);
        out
    }
}

/// Why a payload could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Malformed(pub String);

impl std::fmt::Display for Malformed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A reader over a payload.
pub struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
    what: &'static str,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8], what: &'static str) -> Reader<'a> {
        Reader { bytes, at: 0, what }
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Malformed> {
        let end = self.at.checked_add(n).filter(|&e| e <= self.bytes.len()).ok_or_else(|| {
            Malformed(format!("{}: {} bytes past the end of {} at {}", self.what, n, self.bytes.len(), self.at))
        })?;
        let s = &self.bytes[self.at..end];
        self.at = end;
        Ok(s)
    }

    pub fn u32(&mut self) -> Result<u32, Malformed> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub fn i32(&mut self) -> Result<i32, Malformed> {
        Ok(i32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub fn u64(&mut self) -> Result<u64, Malformed> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    /// The rest of the payload.
    pub fn rest(&mut self) -> &'a [u8] {
        let s = &self.bytes[self.at..];
        self.at = self.bytes.len();
        s
    }

    /// The payload read to its end.
    pub fn end(&self) -> Result<(), Malformed> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(Malformed(format!("{}: {} bytes left over", self.what, self.bytes.len() - self.at)))
        }
    }
}

/// A writer of a payload.
#[derive(Default)]
pub struct Writer(pub Vec<u8>);

impl Writer {
    pub fn u32(&mut self, v: u32) -> &mut Writer {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn i32(&mut self, v: i32) -> &mut Writer {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn u64(&mut self, v: u64) -> &mut Writer {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn bytes(&mut self, b: &[u8]) -> &mut Writer {
        self.0.extend_from_slice(b);
        self
    }
}

/// An IOSurface as the kernel hands it to the GPU (`SurfaceTable::bind`):
/// the kernel's `iosurface::executor::SurfaceDesc`, field for field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SurfaceDesc {
    pub id: u32,
    pub width: u64,
    pub height: u64,
    pub bytes_per_row: u64,
    pub bytes_per_element: u32,
    pub element_width: u32,
    pub element_height: u32,
    /// The offset of the surface's first byte in its memory.
    pub offset: u64,
    pub pixel_format: u32,
    pub alloc_size: u64,
    pub planes: Vec<Plane>,
    pub seed: u32,
}

/// One plane of a surface (the kernel's `PlaneDesc` and the sink's `Plane`
/// have the same fields).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Plane {
    pub offset: u64,
    pub width: u64,
    pub height: u64,
    pub bytes_per_row: u64,
    pub bytes_per_element: u32,
    pub element_width: u32,
    pub element_height: u32,
    pub size: u64,
}

fn put_plane(w: &mut Writer, p: &Plane) {
    w.u64(p.offset).u64(p.width).u64(p.height).u64(p.bytes_per_row);
    w.u32(p.bytes_per_element).u32(p.element_width).u32(p.element_height).u32(0);
    w.u64(p.size);
}

fn get_plane(r: &mut Reader<'_>) -> Result<Plane, Malformed> {
    let (offset, width, height, bytes_per_row) = (r.u64()?, r.u64()?, r.u64()?, r.u64()?);
    let (bytes_per_element, element_width, element_height, _) = (r.u32()?, r.u32()?, r.u32()?, r.u32()?);
    let size = r.u64()?;
    Ok(Plane { offset, width, height, bytes_per_row, bytes_per_element, element_width, element_height, size })
}

impl SurfaceDesc {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.u32(self.id).u32(self.planes.len() as u32);
        w.u64(self.width).u64(self.height).u64(self.bytes_per_row);
        w.u32(self.bytes_per_element).u32(self.element_width).u32(self.element_height).u32(self.pixel_format);
        w.u64(self.offset).u64(self.alloc_size);
        w.u32(self.seed).u32(0);
        for p in &self.planes {
            put_plane(&mut w, p);
        }
        w.0
    }

    pub fn decode(bytes: &[u8]) -> Result<SurfaceDesc, Malformed> {
        let mut r = Reader::new(bytes, "a surface description");
        let (id, count) = (r.u32()?, r.u32()?);
        let (width, height, bytes_per_row) = (r.u64()?, r.u64()?, r.u64()?);
        let (bytes_per_element, element_width, element_height, pixel_format) = (r.u32()?, r.u32()?, r.u32()?, r.u32()?);
        let (offset, alloc_size) = (r.u64()?, r.u64()?);
        let (seed, _) = (r.u32()?, r.u32()?);
        let planes = (0..count).map(|_| get_plane(&mut r)).collect::<Result<_, _>>()?;
        r.end()?;
        Ok(SurfaceDesc {
            id,
            width,
            height,
            bytes_per_row,
            bytes_per_element,
            element_width,
            element_height,
            offset,
            pixel_format,
            alloc_size,
            planes,
            seed,
        })
    }
}

/// Runs of bytes by their offset (a surface's changed ranges, or the GPU's
/// writes read back).
pub fn encode_runs(w: &mut Writer, runs: &[(u64, &[u8])]) {
    w.u32(runs.len() as u32).u32(0);
    for (at, bytes) in runs {
        w.u64(*at).u64(bytes.len() as u64).bytes(bytes);
        let pad = bytes.len().next_multiple_of(8) - bytes.len();
        w.bytes(&[0; 8][..pad]);
    }
}

pub fn decode_runs<'a>(r: &mut Reader<'a>) -> Result<Vec<(u64, &'a [u8])>, Malformed> {
    let (count, _) = (r.u32()?, r.u32()?);
    let mut out = Vec::new();
    for _ in 0..count {
        let (at, len) = (r.u64()?, r.u64()?);
        let len = usize::try_from(len).map_err(|_| Malformed(format!("a run of {len} bytes")))?;
        out.push((at, r.take(len)?));
        r.take(len.next_multiple_of(8) - len)?;
    }
    Ok(out)
}

/// A rectangle as the swap gives it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

/// One layer of a frame on the glass (the kernel's `iomfb::sink::Layer`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Layer {
    pub index: u32,
    pub surface: u32,
    pub pixel_format: u32,
    pub width: u64,
    pub height: u64,
    pub planes: Vec<Plane>,
    /// The surface's whole allocation.
    pub bytes: Vec<u8>,
    pub src: Rect,
    pub dst: Rect,
    /// The swap's 3 transform bits.
    pub transform: u32,
}

/// A frame on the glass (the kernel's `iomfb::sink::Frame`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Frame {
    pub swap_id: u32,
    pub vbl: u64,
    pub time: u64,
    pub panel: (u32, u32),
    pub layers: Vec<Layer>,
}

fn put_rect(w: &mut Writer, r: &Rect) {
    w.i32(r.x).i32(r.y).i32(r.w).i32(r.h);
}

fn get_rect(r: &mut Reader<'_>) -> Result<Rect, Malformed> {
    Ok(Rect { x: r.i32()?, y: r.i32()?, w: r.i32()?, h: r.i32()? })
}

impl Frame {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.u32(self.swap_id).u32(self.layers.len() as u32).u64(self.vbl).u64(self.time);
        w.u32(self.panel.0).u32(self.panel.1);
        for l in &self.layers {
            w.u32(l.index).u32(l.surface).u32(l.pixel_format).u32(l.planes.len() as u32);
            w.u64(l.width).u64(l.height);
            put_rect(&mut w, &l.src);
            put_rect(&mut w, &l.dst);
            w.u32(l.transform).u32(0);
            for p in &l.planes {
                put_plane(&mut w, p);
            }
            w.u64(l.bytes.len() as u64).bytes(&l.bytes);
            let pad = l.bytes.len().next_multiple_of(8) - l.bytes.len();
            w.bytes(&[0; 8][..pad]);
        }
        w.0
    }

    pub fn decode(bytes: &[u8]) -> Result<Frame, Malformed> {
        let mut r = Reader::new(bytes, "a frame");
        let (swap_id, count, vbl, time) = (r.u32()?, r.u32()?, r.u64()?, r.u64()?);
        let panel = (r.u32()?, r.u32()?);
        let mut layers = Vec::new();
        for _ in 0..count {
            let (index, surface, pixel_format, planes) = (r.u32()?, r.u32()?, r.u32()?, r.u32()?);
            let (width, height) = (r.u64()?, r.u64()?);
            let (src, dst) = (get_rect(&mut r)?, get_rect(&mut r)?);
            let (transform, _) = (r.u32()?, r.u32()?);
            let planes = (0..planes).map(|_| get_plane(&mut r)).collect::<Result<_, _>>()?;
            let len = r.u64()?;
            let len = usize::try_from(len).map_err(|_| Malformed(format!("a layer of {len} bytes")))?;
            let bytes = r.take(len)?.to_vec();
            r.take(len.next_multiple_of(8) - len)?;
            layers.push(Layer { index, surface, pixel_format, width, height, planes, bytes, src, dst, transform });
        }
        r.end()?;
        Ok(Frame { swap_id, vbl, time, panel, layers })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plane(o: u64) -> Plane {
        Plane { offset: o, width: 3, height: 2, bytes_per_row: 16, bytes_per_element: 4, element_width: 1, element_height: 1, size: 32 }
    }

    #[test]
    fn frames_round_trip() {
        let f = Frame {
            swap_id: 7,
            vbl: 99,
            time: 123456789,
            panel: (2224, 1668),
            layers: vec![Layer {
                index: 0,
                surface: 0x51,
                pixel_format: u32::from_be_bytes(*b"b3a8"),
                width: 3,
                height: 2,
                planes: vec![plane(0), plane(32)],
                bytes: (0..45u8).collect(),
                src: Rect { x: 0, y: 0, w: 3, h: 2 },
                dst: Rect { x: 1, y: -2, w: 3, h: 2 },
                transform: 5,
            }],
        };
        let e = f.encode();
        assert_eq!(e.len() % 8, 0);
        assert_eq!(Frame::decode(&e).unwrap(), f);
        assert!(Frame::decode(&e[..e.len() - 8]).is_err());
    }

    #[test]
    fn surface_descriptions_round_trip() {
        let d = SurfaceDesc {
            id: 3,
            width: 640,
            height: 480,
            bytes_per_row: 2560,
            bytes_per_element: 4,
            element_width: 1,
            element_height: 1,
            offset: 0,
            pixel_format: u32::from_be_bytes(*b"BGRA"),
            alloc_size: 2560 * 480,
            planes: vec![plane(0)],
            seed: 9,
        };
        assert_eq!(SurfaceDesc::decode(&d.encode()).unwrap(), d);
    }

    #[test]
    fn runs_round_trip_padded() {
        let mut w = Writer::default();
        encode_runs(&mut w, &[(4, &[1, 2, 3]), (100, &[9; 8])]);
        assert_eq!(w.0.len() % 8, 0);
        let mut r = Reader::new(&w.0, "runs");
        let runs = decode_runs(&mut r).unwrap();
        r.end().unwrap();
        assert_eq!(runs, vec![(4, &[1u8, 2, 3][..]), (100, &[9u8; 8][..])]);
    }

    #[test]
    fn messages_are_padded_frames() {
        let m = Message::new(CONTROL, 3, vec![1; 13]);
        let e = m.encode();
        assert_eq!(e.len(), 32);
        assert_eq!(u32::from_le_bytes(e[0..4].try_into().unwrap()), 13);
        assert_eq!(u32::from_le_bytes(e[4..8].try_into().unwrap()), CONTROL);
        assert_eq!(u32::from_le_bytes(e[8..12].try_into().unwrap()), 3);
    }
}
