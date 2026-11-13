//! The executor's surface table: the Metal executor's side of a surface the
//! GPU uses (its texture or buffer of the surface's bytes), which the
//! kernel keeps coherent with the surface's backing store at the same
//! boundaries it keeps the tasks' views coherent at: before a task's lock
//! the GPU's writes are read back into the backing store, and after a task's
//! unlock the CPU's writes are handed to the executor.
//!
//! The embedder installs the table ([`install`]); a surface becomes the
//! GPU's when a GPU client binds it ([`bind`]). Until an embedder installs
//! one, binding a surface is reported and refused.

use std::sync::OnceLock;

/// A surface as the executor's table describes it: its id, its pixel
/// format, its size in bytes, each plane's geometry, and the seed of its
/// contents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SurfaceDesc {
    pub id: u32,
    pub pixel_format: u32,
    pub alloc_size: u64,
    pub planes: Vec<PlaneDesc>,
    pub seed: u32,
}

/// One plane: where it starts in the surface's bytes, its size in pixels
/// and in bytes, and its element geometry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlaneDesc {
    pub offset: u64,
    pub width: u64,
    pub height: u64,
    pub bytes_per_row: u64,
    pub bytes_per_element: u32,
    pub element_width: u32,
    pub element_height: u32,
    pub size: u64,
}

/// What the kernel asks of the executor about a surface the GPU uses.
pub trait SurfaceTable: Send + Sync {
    /// The surface is the GPU's from now on.
    fn bind(&self, desc: &SurfaceDesc);
    /// The CPU changed `ranges` (offsets and lengths) of its bytes, now in
    /// `bytes` (the whole backing store), before a GPU command that follows
    /// may read them.
    fn cpu_wrote(&self, id: u32, bytes: &[u8], ranges: &[(u64, u64)]);
    /// What the GPU wrote since it was last asked, into `bytes` (the whole
    /// backing store); whether it wrote anything.
    fn read_back(&self, id: u32, bytes: &mut [u8]) -> bool;
    /// The surface is gone.
    fn released(&self, id: u32);
}

static TABLE: OnceLock<Box<dyn SurfaceTable>> = OnceLock::new();

/// The embedder's table, once.
pub fn install(t: Box<dyn SurfaceTable>) -> Result<(), Box<dyn SurfaceTable>> {
    TABLE.set(t)
}

/// The executor's table, if an embedder installed one.
pub fn table() -> Option<&'static dyn SurfaceTable> {
    TABLE.get().map(|b| b.as_ref())
}

/// Hand surface `desc` to the GPU: `Err` with what is missing when no
/// executor is there to take it.
pub fn bind(desc: &SurfaceDesc) -> Result<(), String> {
    match table() {
        Some(t) => {
            t.bind(desc);
            Ok(())
        }
        None => Err(format!("binding IOSurface {:#x} to the GPU: no Metal executor's surface table is installed", desc.id)),
    }
}
