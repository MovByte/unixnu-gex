//! The ring in shared memory between the guest's Workers and the GPU Worker
//! (plan section 3.3: "Requests come from the guest's Workers over a ring").
//!
//! One `SharedArrayBuffer` holds a request ring, which every endpoint writes
//! and the GPU Worker reads, and one ring per endpoint, which the GPU Worker
//! writes and that endpoint reads. An endpoint is one process's kernel; it
//! takes a number once (word [`NEXT_ENDPOINT`]) and keeps it. Messages are
//! the frames of [`crate::protocol`]. A frame longer than a ring's free space
//! goes in pieces: its writer writes what fits and waits for the reader to
//! free more, so any length passes through a ring of any size.
//!
//! The layout (little-endian 32-bit words, then the rings' bytes):
//!
//! | Word | Content |
//! | --- | --- |
//! | [`MAGIC`] | `0x574d5247` |
//! | [`VERSION`] | 1 |
//! | [`ENDPOINTS`] | how many endpoints the buffer holds |
//! | [`REQUEST_SIZE`] | the request ring's bytes (a power of two) |
//! | [`ENDPOINT_SIZE`] | each endpoint ring's bytes (a power of two) |
//! | [`REQUEST_LOCK`] | 1 while a writer writes a frame |
//! | [`REQUEST_HEAD`], [`REQUEST_TAIL`] | bytes written and read, counted modulo 2^32 |
//! | [`DOORBELL`] | advanced by a writer after writing a request, and by an endpoint after freeing space in its ring: the GPU Worker waits on it |
//! | [`NEXT_ENDPOINT`] | the next endpoint number to take |
//! | `16 + 4 e` | endpoint `e`: head, tail, bell (advanced by the GPU Worker after writing; the endpoint waits on it), unused |
//!
//! The request ring's bytes start at [`Layout::request_offset`], endpoint
//! `e`'s at [`Layout::endpoint_offset`]. `hosts/browser/js/metal-ring.mjs`
//! creates the buffer and is the endpoints' side.

pub const MAGIC: usize = 0;
pub const VERSION: usize = 1;
pub const ENDPOINTS: usize = 2;
pub const REQUEST_SIZE: usize = 3;
pub const ENDPOINT_SIZE: usize = 4;
pub const REQUEST_LOCK: usize = 5;
pub const REQUEST_HEAD: usize = 6;
pub const REQUEST_TAIL: usize = 7;
pub const DOORBELL: usize = 8;
pub const NEXT_ENDPOINT: usize = 9;
/// The first endpoint's words.
pub const ENDPOINT_WORDS: usize = 16;

pub const MAGIC_VALUE: u32 = 0x574d_5247;
pub const VERSION_VALUE: u32 = 1;

/// Where the parts of a ring buffer are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub endpoints: u32,
    pub request_size: u32,
    pub endpoint_size: u32,
}

impl Layout {
    /// An endpoint's head, tail and bell words.
    pub fn endpoint_words(e: u32) -> (usize, usize, usize) {
        let w = ENDPOINT_WORDS + 4 * e as usize;
        (w, w + 1, w + 2)
    }

    pub fn request_offset(&self) -> u32 {
        (4 * (ENDPOINT_WORDS as u32 + 4 * self.endpoints)).next_multiple_of(64)
    }

    pub fn endpoint_offset(&self, e: u32) -> u32 {
        self.request_offset() + self.request_size + e * self.endpoint_size
    }

    pub fn bytes(&self) -> u32 {
        self.endpoint_offset(self.endpoints)
    }

    /// Check the header words of a buffer of `len` bytes.
    pub fn check(words: [u32; 5], len: u32) -> Result<Layout, String> {
        if words[MAGIC] != MAGIC_VALUE || words[VERSION] != VERSION_VALUE {
            return Err(format!("not a ring of version {VERSION_VALUE} (magic {:#x}, version {})", words[MAGIC], words[VERSION]));
        }
        let l = Layout { endpoints: words[ENDPOINTS], request_size: words[REQUEST_SIZE], endpoint_size: words[ENDPOINT_SIZE] };
        if !l.request_size.is_power_of_two() || !l.endpoint_size.is_power_of_two() || l.request_size < 64 || l.endpoint_size < 64 {
            return Err(format!("ring sizes {} and {} are not powers of two of at least 64", l.request_size, l.endpoint_size));
        }
        let need = u64::from(l.request_offset()) + u64::from(l.request_size) + u64::from(l.endpoints) * u64::from(l.endpoint_size);
        if need > u64::from(len) {
            return Err(format!("the ring's layout needs {need} bytes; the buffer has {len}"));
        }
        Ok(l)
    }
}

/// A frame being read in pieces: its header, then its bytes as they arrive.
#[derive(Debug, Default)]
pub struct Reassembly {
    header: Vec<u8>,
    body: Vec<u8>,
    want: usize,
}

impl Reassembly {
    /// Take bytes from `avail` (what the ring holds): how many were taken,
    /// and the message when one is complete.
    pub fn feed(&mut self, avail: &[u8]) -> (usize, Option<crate::protocol::Message>) {
        use crate::protocol::{HEADER, Message, framed};
        let mut taken = 0;
        if self.header.len() < HEADER {
            let n = (HEADER - self.header.len()).min(avail.len());
            self.header.extend_from_slice(&avail[..n]);
            taken += n;
            if self.header.len() < HEADER {
                return (taken, None);
            }
            let len = u32::from_le_bytes(self.header[0..4].try_into().unwrap()) as usize;
            self.want = framed(len) - HEADER;
            self.body = Vec::with_capacity(self.want);
        }
        let n = (self.want - self.body.len()).min(avail.len() - taken);
        self.body.extend_from_slice(&avail[taken..taken + n]);
        taken += n;
        if self.body.len() < self.want {
            return (taken, None);
        }
        let h = &self.header;
        let word = |i: usize| u32::from_le_bytes(h[4 * i..4 * i + 4].try_into().unwrap());
        let len = word(0) as usize;
        let mut payload = std::mem::take(&mut self.body);
        payload.truncate(len);
        let m = Message { kind: word(1), a: word(2), b: word(3), payload };
        self.header.clear();
        self.want = 0;
        (taken, Some(m))
    }
}

#[cfg(target_arch = "wasm32")]
pub use web::Ring;

#[cfg(target_arch = "wasm32")]
mod web {
    use std::collections::{HashMap, VecDeque};

    use js_sys::{Atomics, Int32Array, SharedArrayBuffer, Uint8Array};

    use super::*;
    use crate::protocol::Message;

    /// The GPU Worker's side of the ring: it reads requests and writes each
    /// endpoint's messages, keeping what does not fit yet.
    pub struct Ring {
        pub words: Int32Array,
        bytes: Uint8Array,
        layout: Layout,
        reading: Reassembly,
        outbox: HashMap<u32, VecDeque<u8>>,
    }

    impl Ring {
        pub fn attach(buffer: &SharedArrayBuffer) -> Result<Ring, String> {
            let words = Int32Array::new(buffer);
            let bytes = Uint8Array::new(buffer);
            let h = std::array::from_fn(|i| Atomics::load(&words, i as u32).unwrap_or(0) as u32);
            let layout = Layout::check(h, bytes.length())?;
            Ok(Ring { words, bytes, layout, reading: Reassembly::default(), outbox: HashMap::new() })
        }

        fn load(&self, i: usize) -> u32 {
            Atomics::load(&self.words, i as u32).unwrap_or(0) as u32
        }

        fn store(&self, i: usize, v: u32) {
            let _ = Atomics::store(&self.words, i as u32, v as i32);
        }

        fn ring(&self, i: usize) {
            let _ = Atomics::add(&self.words, i as u32, 1);
            let _ = Atomics::notify(&self.words, i as u32);
        }

        /// The doorbell's value, to wait on.
        pub fn doorbell(&self) -> i32 {
            self.load(DOORBELL) as i32
        }

        /// Copy `len` bytes at ring position `pos` of the ring at `base` of
        /// `size` bytes.
        fn copy_out(&self, base: u32, size: u32, pos: u32, len: usize) -> Vec<u8> {
            let mut out = vec![0u8; len];
            let start = pos & (size - 1);
            let first = (len as u32).min(size - start) as usize;
            self.bytes.subarray(base + start, base + start + first as u32).copy_to(&mut out[..first]);
            if first < len {
                self.bytes.subarray(base, base + (len - first) as u32).copy_to(&mut out[first..]);
            }
            out
        }

        fn copy_in(&self, base: u32, size: u32, pos: u32, src: &[u8]) {
            let start = pos & (size - 1);
            let first = (src.len() as u32).min(size - start) as usize;
            self.bytes.subarray(base + start, base + start + first as u32).copy_from(&src[..first]);
            if first < src.len() {
                self.bytes.subarray(base, base + (src.len() - first) as u32).copy_from(&src[first..]);
            }
        }

        /// The next complete request, reading what has arrived; `None` until
        /// one is complete.
        pub fn next_request(&mut self) -> Option<Message> {
            loop {
                let head = self.load(REQUEST_HEAD);
                let tail = self.load(REQUEST_TAIL);
                let avail = head.wrapping_sub(tail) as usize;
                if avail == 0 {
                    return None;
                }
                // Up to the end of the frame being read, at most.
                let chunk = self.copy_out(self.layout.request_offset(), self.layout.request_size, tail, avail);
                let (taken, msg) = self.reading.feed(&chunk);
                self.store(REQUEST_TAIL, tail.wrapping_add(taken as u32));
                let _ = Atomics::notify(&self.words, REQUEST_TAIL as u32);
                if msg.is_some() {
                    return msg;
                }
                if taken == avail {
                    return None;
                }
            }
        }

        /// Queue `m` for endpoint `e`.
        pub fn send(&mut self, e: u32, m: &Message) {
            if e >= self.layout.endpoints {
                return;
            }
            self.outbox.entry(e).or_default().extend(m.encode());
        }

        /// Write what fits of each endpoint's queued messages: whether any
        /// remain.
        pub fn flush(&mut self) -> bool {
            let mut left = false;
            let es: Vec<u32> = self.outbox.keys().copied().collect();
            for e in es {
                let (hw, tw, bw) = Layout::endpoint_words(e);
                let (head, tail) = (self.load(hw), self.load(tw));
                let size = self.layout.endpoint_size;
                let free = size - head.wrapping_sub(tail).min(size);
                let q = self.outbox.get_mut(&e).unwrap();
                let n = (free as usize).min(q.len());
                if n > 0 {
                    let chunk: Vec<u8> = q.drain(..n).collect();
                    self.copy_in(self.layout.endpoint_offset(e), size, head, &chunk);
                    self.store(hw, head.wrapping_add(n as u32));
                    self.ring(bw);
                }
                if self.outbox[&e].is_empty() {
                    self.outbox.remove(&e);
                } else {
                    left = true;
                }
            }
            left
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Message;

    #[test]
    fn frames_reassemble_from_any_pieces() {
        let ms = [Message::new(2, 1, (0..37).collect()), Message::new(8, 3, vec![]), Message::new(5, 0, vec![7; 300])];
        let bytes: Vec<u8> = ms.iter().flat_map(|m| m.encode()).collect();
        for step in [1, 3, 8, 16, 17, 64, 1000] {
            let mut r = Reassembly::default();
            let mut got = Vec::new();
            let mut at = 0;
            while at < bytes.len() {
                let end = (at + step).min(bytes.len());
                let mut piece = &bytes[at..end];
                while !piece.is_empty() {
                    let (n, m) = r.feed(piece);
                    piece = &piece[n..];
                    at += n;
                    got.extend(m);
                    if n == 0 {
                        break;
                    }
                }
            }
            assert_eq!(got, ms.to_vec(), "pieces of {step}");
        }
    }

    #[test]
    fn layouts_are_checked() {
        let l = Layout { endpoints: 4, request_size: 1024, endpoint_size: 256 };
        let w = [MAGIC_VALUE, VERSION_VALUE, 4, 1024, 256];
        assert_eq!(Layout::check(w, l.bytes()), Ok(l));
        assert!(Layout::check(w, l.bytes() - 1).is_err());
        assert!(Layout::check([MAGIC_VALUE, VERSION_VALUE, 4, 1000, 256], 1 << 20).is_err());
        assert_eq!(l.request_offset() % 64, 0);
    }
}
