//! The page's GPU Worker (plan sections 3.3, 3.4 and 6.8): WebMetal's executor
//! on the browser's WebGPU, with the one `GPUDevice` of the whole guest
//! system, reached by the guest's Workers over a ring in shared memory; and
//! the display, a canvas the GPU Worker draws the framebuffer's frames on.
//!
//! - [`protocol`]: the messages, one per call the kernel makes on its
//!   executor, surface table and presentation sink, and their answers.
//! - [`ring`]: the shared memory that carries them.
//! - [`memory`]: a connection's task memory, checked against the task's
//!   mappings.
//! - [`surfaces`]: the bytes of the IOSurfaces the GPU uses.
//! - [`display`]: which frames the canvas shows, and their texels.
//! - `worker` (wasm32): the device, the executor and its embedder, the
//!   canvas, and the loop that serves the ring.

pub mod display;
pub mod memory;
pub mod protocol;
pub mod ring;
pub mod surfaces;
#[cfg(target_arch = "wasm32")]
pub mod worker;
