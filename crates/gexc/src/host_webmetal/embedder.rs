//! The host interface (`webmetal_host::embed::Embedder`) over gex's Darwin
//! kernel: the executor's tasks are the WebMetal connections, each with
//! its task's memory; IOSurfaces are the kernel's, through the surfaces the
//! GPU uses ([`super::surfaces`]); events are queued per connection and
//! command queue here, and their doorbells rung through the connection.
//!
//! A task of the executor is a connection, not a process: handles are
//! unique within a connection (wire `README.md`, "Handles"), and the
//! executor keeps one object table per task. Its memory is the memory of
//! the process that opened it.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

use gex_kernel::darwin::accel::host::{FaultKind, TaskMemory};
use gex_kernel::darwin::accel::wire;
use gex_kernel::darwin::iosurface;
use webmetal_host::embed::{
    Embedder, GuestMemoryError, GuestMemoryErrorKind, MonotonicNanos, PresentError, PresentedFrame, SharedEventError,
    SharedEventId, SurfaceDesc, SurfaceError, SurfacePlane, TaskId,
};
use webmetal_wire::{Event, Handle, SurfaceId};

use super::surfaces::{Miss, Surfaces};

/// Events posted and not yet fetched, per connection and command queue
/// (`None`: device-level events), in the order they were posted.
type Posted = HashMap<(TaskId, Option<Handle>), Vec<Event>>;

/// The embedder of the executor's thread.
pub struct GexEmbedder {
    /// Each open connection's task memory.
    tasks: RefCell<HashMap<TaskId, TaskMemory>>,
    events: RefCell<Posted>,
    surfaces: Arc<Surfaces>,
}

impl GexEmbedder {
    pub fn new(surfaces: Arc<Surfaces>) -> GexEmbedder {
        GexEmbedder { tasks: RefCell::new(HashMap::new()), events: RefCell::new(HashMap::new()), surfaces }
    }

    /// Connection `task` opened by the task whose memory is `memory`.
    pub fn open(&self, task: TaskId, memory: TaskMemory) {
        self.tasks.borrow_mut().insert(task, memory);
    }

    /// Connection `task` closed: its memory and its events are gone.
    pub fn close(&self, task: TaskId) {
        self.tasks.borrow_mut().remove(&task);
        self.events.borrow_mut().retain(|(t, _), _| *t != task);
    }

    /// The events posted for `queue` of `task`, taken in the order they were
    /// posted (FetchEvents).
    pub fn take_events(&self, task: TaskId, queue: Option<Handle>) -> Vec<Event> {
        self.events.borrow_mut().remove(&(task, queue)).unwrap_or_default()
    }

    fn memory(&self, task: TaskId, addr: u64, len: usize) -> Result<TaskMemory, GuestMemoryError> {
        self.tasks.borrow().get(&task).cloned().ok_or(GuestMemoryError {
            task,
            addr,
            len: len as u64,
            fault: addr,
            kind: GuestMemoryErrorKind::NoTask,
        })
    }

    /// The executor's failed access, as the interface names it. A write
    /// into an executable mapping, which the kernel's own copies make and
    /// the executor's cannot, is reported.
    fn fault(task: TaskId, addr: u64, len: usize, f: gex_kernel::darwin::accel::host::Fault) -> GuestMemoryError {
        let kind = match f.kind {
            FaultKind::Unmapped => GuestMemoryErrorKind::Unmapped,
            FaultKind::Protection => GuestMemoryErrorKind::Protection,
            FaultKind::Gone => GuestMemoryErrorKind::NoTask,
            FaultKind::Code => {
                wire::report(
                    task.0,
                    format!(
                        "the WebMetal executor writing {len} bytes at {addr:#x}, in an executable mapping at {:#x} (the kernel retires translated code its own copies overwrite; the executor's thread has none to retire)",
                        f.addr
                    ),
                );
                GuestMemoryErrorKind::Protection
            }
        };
        GuestMemoryError { task, addr, len: len as u64, fault: f.addr, kind }
    }

    /// Surface `id`'s description and the generation of the bytes the GPU
    /// has of it: a surface the GPU was given (the kernel binds only those
    /// whose bytes start at their memory's first byte, so the executor's
    /// offsets are offsets in the memory).
    fn describe(&self, id: SurfaceId) -> Result<(iosurface::executor::SurfaceDesc, u32), SurfaceError> {
        let d = iosurface::describe(id.0).ok_or(SurfaceError::Unknown(id))?;
        let generation = self.surfaces.generation(id.0).ok_or(SurfaceError::Unknown(id))?;
        Ok((d, generation))
    }
}

impl Embedder for GexEmbedder {
    fn read_guest(&self, task: TaskId, addr: u64, dst: &mut [u8]) -> Result<(), GuestMemoryError> {
        let m = self.memory(task, addr, dst.len())?;
        m.read(addr, dst).map_err(|f| Self::fault(task, addr, dst.len(), f))
    }

    fn write_guest(&self, task: TaskId, addr: u64, src: &[u8]) -> Result<(), GuestMemoryError> {
        let m = self.memory(task, addr, src.len())?;
        m.write(addr, src).map_err(|f| Self::fault(task, addr, src.len(), f))
    }

    fn surface_lookup(&self, id: SurfaceId) -> Result<SurfaceDesc, SurfaceError> {
        let (d, generation) = self.describe(id)?;
        let planes = d
            .planes
            .iter()
            .map(|p| SurfacePlane {
                width: p.width,
                height: p.height,
                bytes_per_row: p.bytes_per_row,
                bytes_per_element: u64::from(p.bytes_per_element),
                element_width: u64::from(p.element_width),
                element_height: u64::from(p.element_height),
                offset: p.offset,
                size: p.size,
            })
            .collect();
        Ok(SurfaceDesc {
            id,
            width: d.width,
            height: d.height,
            bytes_per_row: d.bytes_per_row,
            bytes_per_element: u64::from(d.bytes_per_element),
            element_width: u64::from(d.element_width),
            element_height: u64::from(d.element_height),
            pixel_format: d.pixel_format,
            alloc_size: d.alloc_size,
            planes,
            // The executor reads a surface again when its seed moves. What it
            // reads are the bytes the kernel handed over, which change when
            // the kernel hands over the tasks' writes (at their unlocks and
            // locks), not when a lock raises IOSurfaceGetSeed: the count of
            // those hand-overs is what moves with them.
            seed: generation,
        })
    }

    fn read_surface(&self, id: SurfaceId, offset: u64, dst: &mut [u8]) -> Result<(), SurfaceError> {
        self.describe(id)?;
        self.surfaces.read(id.0, offset, dst).map_err(|m| miss(m, id, offset, dst.len()))
    }

    fn write_surface_changed(&self, id: SurfaceId, offset: u64, new: &[u8], shadow: &[u8]) -> Result<(), SurfaceError> {
        self.describe(id)?;
        self.surfaces.write_changed(id.0, offset, new, shadow).map_err(|m| miss(m, id, offset, new.len()))
    }

    fn surface_note_gpu_write(&self, _id: SurfaceId, _plane: u32) {
        // The bytes are already kept for the kernel, which takes them back
        // into the surface's memory before the next task's lock.
    }

    fn shared_event_resolve(&self, task: TaskId, port: u32) -> Result<SharedEventId, SharedEventError> {
        wire::report(
            task.0,
            format!("a WebMetal shared event (send right {port:#x}): the kernel has no IOSurface shared events (IOSurfaceRootUserClient selectors 36 to 42)"),
        );
        Err(SharedEventError::NotAnEvent { task, port })
    }

    fn shared_event_value(&self, event: SharedEventId) -> Result<u64, SharedEventError> {
        Err(SharedEventError::Gone(event))
    }

    fn shared_event_signal(&self, event: SharedEventId, _value: u64) -> Result<(), SharedEventError> {
        Err(SharedEventError::Gone(event))
    }

    fn shared_event_release(&self, _event: SharedEventId) {}

    fn post(&self, task: TaskId, queue: Option<Handle>, event: Event) {
        self.events.borrow_mut().entry((task, queue)).or_default().push(event);
        wire::ring(task.0, queue.map_or(0, |h| h.0.get()));
    }

    fn present(&self, frame: &PresentedFrame) -> Result<(), PresentError> {
        // No display is attached to this executor.
        Err(PresentError::UnknownDisplay(frame.display))
    }

    fn now(&self) -> MonotonicNanos {
        // The guest's mach_absolute_time, in nanoseconds.
        let (numer, denom) = gex_kernel::darwin::mach::TIMEBASE;
        let ticks = gex_kernel::darwin::mach::absolute_time();
        MonotonicNanos((u128::from(ticks) * u128::from(numer) / u128::from(denom)) as u64)
    }
}

fn miss(m: Miss, id: SurfaceId, offset: u64, len: usize) -> SurfaceError {
    match m {
        Miss::Unknown => SurfaceError::Unknown(id),
        Miss::OutOfRange => SurfaceError::OutOfRange { id, offset, len: len as u64 },
    }
}
