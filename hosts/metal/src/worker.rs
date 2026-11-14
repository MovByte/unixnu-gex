//! The GPU Worker: the one `GPUDevice` of the guest system and WebMetal's
//! executor on it, serving the ring ([`crate::ring`]); and the display's
//! canvas ([`Sink`]).
//!
//! It mirrors gexc's executor thread (`host_webmetal`): the kernel hands it
//! each connection with its task's memory, each control request with what
//! answers it, and each connection's end; requests of different connections
//! run concurrently, as the executor's futures allow, and a connection's own
//! come one at a time (its kernel sends the next only after the answer).
//! FetchEvents is answered from the events the executor posted, as the
//! executor's interface asks of its embedder. What the executor reports it
//! could not do reaches the connection's kernel as a report. The executor
//! waits for the browser's promises from the Worker's event loop: the loop
//! below runs the executor whenever a request arrives, one of its futures is
//! woken, or a deadline it asked for passes.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::future::Future as _;
use std::rc::Rc;
use std::task::{Context, Poll, Wake, Waker};

use js_sys::{Int32Array, Promise, SharedArrayBuffer, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use webmetal_host::blit::BlitService;
use webmetal_host::compute::ComputeService;
use webmetal_host::embed::{
    Embedder, GuestMemoryError, GuestMemoryErrorKind, MonotonicNanos, PresentError, PresentedFrame, SharedEventError,
    SharedEventId, SurfaceDesc as HostSurfaceDesc, SurfaceError, SurfacePlane, TaskId,
};
use webmetal_host::exec::{fetch_events_reply, Config, ControlService, Executor, Services};
use webmetal_host::format::webgpu::{Feature, HostFeatures};
use webmetal_host::gpu::idl::{CanvasConfiguration, CanvasToneMapping, CanvasToneMappingMode, RequestAdapterOptions, TextureFormat};
use webmetal_host::gpu::scope::{Granularity, Policy};
use webmetal_host::gpu::web::{Web, WebDevice, WebGpu};
use webmetal_host::gpu::{negotiate, Adapter as _, Device as _, ExceptionKind, Gpu as _, GpuFuture, PredefinedColorSpace};
use webmetal_host::mem::service::MemoryServices;
use webmetal_host::pipeline::{self, PipelineServices};
use webmetal_host::present::web::CanvasTarget;
use webmetal_host::present::Target as _;
use webmetal_host::render::RenderServices;
use webmetal_host::state::StateServices;
use webmetal_wire::{DecodeError, Event, Handle, Request, SurfaceId};

use crate::display::{self, CanvasFormat};
use crate::memory::{Fault, FaultKind, TaskMemory};
use crate::protocol::{self, Frame, Message, Reader, SurfaceDesc, Writer};
use crate::ring::{Ring, DOORBELL};
use crate::surfaces::{Miss, Surfaces};

#[wasm_bindgen(module = "/js/glue.js")]
extern "C" {
    fn wake();
    fn next(words: &Int32Array, index: u32, seen: i32, ms: f64) -> Promise;
    fn now_ns() -> f64;
    #[wasm_bindgen(catch)]
    fn read_canvas(device: &JsValue, context: &JsValue, width: u32, height: u32, bytes_per_row: u32) -> Result<Promise, JsValue>;
}

/// How long the loop waits for a request while the executor has GPU work in
/// flight before it runs the executor again, as gexc's thread polls it.
const BUSY_MS: f64 = 1.0;

/// Events posted and not yet fetched, per connection and command queue
/// (`None`: device-level events), in the order they were posted.
type Posted = HashMap<(TaskId, Option<Handle>), Vec<Event>>;

/// What the executor's embedder and the loop share: messages for the
/// endpoints, written to the ring by the loop.
#[derive(Default)]
struct Outbox(RefCell<Vec<(u32, Message)>>);

impl Outbox {
    fn send(&self, endpoint: u32, m: Message) {
        self.0.borrow_mut().push((endpoint, m));
    }

    fn report(&self, endpoint: u32, conn: u64, what: &str) {
        let mut w = Writer::default();
        w.u64(conn).bytes(what.as_bytes());
        self.send(endpoint, Message::new(protocol::REPORT, 0, w.0));
    }
}

/// A connection: its endpoint and its task's memory.
struct Conn {
    endpoint: u32,
    memory: Rc<TaskMemory>,
}

/// The host interface over the page: the executor's tasks are the WebMetal
/// connections, each with its task's memory; IOSurfaces are the kernel's,
/// through the mirror the kernel's messages keep; events are queued per
/// connection and command queue, and their doorbells rung through the
/// connection's endpoint.
pub struct PageEmbedder {
    conns: RefCell<HashMap<TaskId, Conn>>,
    events: RefCell<Posted>,
    surfaces: RefCell<Surfaces>,
    outbox: Rc<Outbox>,
}

impl PageEmbedder {
    fn memory(&self, task: TaskId, addr: u64, len: usize) -> Result<Rc<TaskMemory>, GuestMemoryError> {
        self.conns.borrow().get(&task).map(|c| c.memory.clone()).ok_or(GuestMemoryError {
            task,
            addr,
            len: len as u64,
            fault: addr,
            kind: GuestMemoryErrorKind::NoTask,
        })
    }

    fn endpoint(&self, task: TaskId) -> Option<u32> {
        self.conns.borrow().get(&task).map(|c| c.endpoint)
    }

    /// The executor's failed access, as the interface names it. A write into
    /// an executable mapping is reported.
    fn fault(&self, task: TaskId, addr: u64, len: usize, f: Fault) -> GuestMemoryError {
        let kind = match f.kind {
            FaultKind::Unmapped => GuestMemoryErrorKind::Unmapped,
            FaultKind::Protection => GuestMemoryErrorKind::Protection,
            FaultKind::Gone => GuestMemoryErrorKind::NoTask,
            FaultKind::Code => {
                if let Some(e) = self.endpoint(task) {
                    self.outbox.report(
                        e,
                        task.0,
                        &format!(
                            "the WebMetal executor writing {len} bytes at {addr:#x}, in an executable mapping at {:#x} (the kernel retires translated code its own copies overwrite; the GPU Worker has none to retire)",
                            f.addr
                        ),
                    );
                }
                GuestMemoryErrorKind::Protection
            }
        };
        GuestMemoryError { task, addr, len: len as u64, fault: f.addr, kind }
    }

    fn take_events(&self, task: TaskId, queue: Option<Handle>) -> Vec<Event> {
        self.events.borrow_mut().remove(&(task, queue)).unwrap_or_default()
    }
}

fn miss(m: Miss, id: SurfaceId, offset: u64, len: usize) -> SurfaceError {
    match m {
        Miss::Unknown => SurfaceError::Unknown(id),
        Miss::OutOfRange => SurfaceError::OutOfRange { id, offset, len: len as u64 },
    }
}

impl Embedder for PageEmbedder {
    fn read_guest(&self, task: TaskId, addr: u64, dst: &mut [u8]) -> Result<(), GuestMemoryError> {
        let m = self.memory(task, addr, dst.len())?;
        m.read(addr, dst).map_err(|f| self.fault(task, addr, dst.len(), f))
    }

    fn write_guest(&self, task: TaskId, addr: u64, src: &[u8]) -> Result<(), GuestMemoryError> {
        let m = self.memory(task, addr, src.len())?;
        m.write(addr, src).map_err(|f| self.fault(task, addr, src.len(), f))
    }

    fn surface_lookup(&self, id: SurfaceId) -> Result<HostSurfaceDesc, SurfaceError> {
        let s = self.surfaces.borrow();
        let (d, generation) = s.describe(id.0).ok_or(SurfaceError::Unknown(id))?;
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
        Ok(HostSurfaceDesc {
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
            // As gexc's: the executor reads a surface again when the bytes the
            // kernel handed over change, which the count of hand-overs tracks.
            seed: generation,
        })
    }

    fn read_surface(&self, id: SurfaceId, offset: u64, dst: &mut [u8]) -> Result<(), SurfaceError> {
        self.surfaces.borrow().read(id.0, offset, dst).map_err(|m| miss(m, id, offset, dst.len()))
    }

    fn write_surface_changed(&self, id: SurfaceId, offset: u64, new: &[u8], shadow: &[u8]) -> Result<(), SurfaceError> {
        self.surfaces.borrow_mut().write_changed(id.0, offset, new, shadow).map_err(|m| miss(m, id, offset, new.len()))
    }

    fn surface_note_gpu_write(&self, _id: SurfaceId, _plane: u32) {
        // The bytes are already kept for the kernel, which takes them back
        // into the surface's memory before the next task's lock.
    }

    fn shared_event_resolve(&self, task: TaskId, port: u32) -> Result<SharedEventId, SharedEventError> {
        if let Some(e) = self.endpoint(task) {
            self.outbox.report(
                e,
                task.0,
                &format!("a WebMetal shared event (send right {port:#x}): the kernel has no IOSurface shared events (IOSurfaceRootUserClient selectors 36 to 42)"),
            );
        }
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
        if let Some(e) = self.endpoint(task) {
            let mut w = Writer::default();
            w.u64(task.0).u64(queue.map_or(0, |h| h.0.get()));
            self.outbox.send(e, Message::new(protocol::RING, 0, w.0));
        }
    }

    fn present(&self, frame: &PresentedFrame) -> Result<(), PresentError> {
        // The display is the framebuffer's (the kernel's PresentSink), not
        // the executor's.
        Err(PresentError::UnknownDisplay(frame.display))
    }

    fn now(&self) -> MonotonicNanos {
        MonotonicNanos(now_ns() as u64)
    }
}

type Exec = Executor<Web, PageEmbedder>;

/// The device and the executor on it.
struct Machine {
    device: WebDevice,
    exec: Exec,
}

/// The WebGPU device, with the features and limits the negotiation asks for,
/// and the executor with every service WebMetal provides: gexc's set-up, on
/// the browser's WebGPU.
async fn set_up(embedder: Rc<PageEmbedder>) -> Result<Machine, String> {
    let gpu = WebGpu::from_global().map_err(|e| e.to_string())?;
    let adapter = gpu
        .request_adapter(&RequestAdapterOptions::new())
        .await
        .map_err(|e| format!("requestAdapter: {e}"))?
        .ok_or("requestAdapter: no adapter")?;
    let mut descriptor =
        negotiate::plan(&adapter.features(), &adapter.limits()).map_err(|e| format!("negotiation: {e}"))?.descriptor;
    descriptor.label = "gex WebMetal".into();
    let device = adapter.request_device(&descriptor).await.map_err(|e| format!("requestDevice: {e}"))?;
    let names = device.features();
    let features = HostFeatures::new(Feature::ALL.into_iter().filter(|f| names.contains(f.name())));
    let memory = MemoryServices::new(&device, features, embedder.clone())
        .await
        .map_err(|e| format!("setting the memory services up: {e}"))?;
    // A browser that does not report wgslLanguageFeatures is taken to offer no
    // extension: a pipeline that needs one is refused, never assumed to work.
    let wgsl = match gpu.wgsl_language_features() {
        Ok(f) => f,
        Err(e) if e.kind == ExceptionKind::Unsupported => Default::default(),
        Err(e) => return Err(format!("wgslLanguageFeatures: {e}")),
    };
    let pipelines = PipelineServices::<Web>::new(&device, wgsl, pipeline::Config::default());
    let render = RenderServices::new(memory.memory());
    let services = Services {
        control: vec![
            memory.control() as Box<dyn ControlService<Web, PageEmbedder>>,
            Box::new(StateServices::new()),
            pipelines.control(),
            render.control(),
        ],
        render: Some(render.encoder()),
        compute: Some(Box::new(ComputeService::new(memory.memory()))),
        blit: Some(Box::new(BlitService::new(memory.memory()))),
        coherence: Some(memory.coherence()),
    };
    // Each WebGPU call in an error scope of its own, and an error that escapes
    // every scope an executor defect that stops the device.
    let config = Config { scopes: Policy { granularity: Granularity::PerCall, strict: true } };
    let exec = Executor::new(device.clone(), embedder, services, config);
    Ok(Machine { device, exec })
}

/// A control request with the executor.
struct InFlight {
    reply: GpuFuture<Result<Vec<u8>, DecodeError>>,
    endpoint: u32,
    token: u64,
}

/// An OPEN whose process memory has not been attached yet.
struct Waiting {
    endpoint: u32,
    conn: u64,
    memory: u32,
}

/// The display: the canvas, its configuration, and the frame it last showed.
struct Sink {
    target: Option<CanvasTarget>,
    configured: Option<CanvasFormat>,
    lit: bool,
    last: Option<display::Shown>,
    xr: [u16; 1024],
    alpha: [u16; 256],
}

/// What the loop keeps.
struct Server {
    ring: Ring,
    machine: Result<Machine, String>,
    embedder: Rc<PageEmbedder>,
    outbox: Rc<Outbox>,
    memories: HashMap<u32, Rc<TaskMemory>>,
    waiting: Option<Waiting>,
    inflight: Vec<InFlight>,
    sink: Sink,
    /// Presentation checks waiting for the canvas's bytes.
    reads: Vec<(u32, u32, JsFuture)>,
}

struct Wakeup;

impl Wake for Wakeup {
    fn wake(self: std::sync::Arc<Self>) {
        wake();
    }
}

fn reply(token: u64, refused: bool, bytes: &[u8]) -> Message {
    let mut w = Writer::default();
    w.u64(token).u32(u32::from(refused)).u32(0).bytes(bytes);
    Message::new(protocol::REPLY, 0, w.0)
}

impl Server {
    /// Handle one request. An OPEN whose memory is not attached yet waits
    /// (`waiting`), and the requests after it with it, in their order.
    fn handle(&mut self, m: Message) {
        let endpoint = m.a;
        let mut r = Reader::new(&m.payload, "a request");
        let result: Result<(), protocol::Malformed> = (|| {
            match m.kind {
                protocol::OPEN => {
                    let (conn, _pid, memory) = (r.u64()?, r.i32()?, r.u32()?);
                    let Some(mem) = self.memories.get(&memory).cloned() else {
                        self.waiting = Some(Waiting { endpoint, conn, memory });
                        return Ok(());
                    };
                    self.embedder.conns.borrow_mut().insert(TaskId(conn), Conn { endpoint, memory: mem });
                }
                protocol::CONTROL => {
                    let (conn, token) = (r.u64()?, r.u64()?);
                    let request = r.rest();
                    let machine = match &self.machine {
                        Ok(m) => m,
                        Err(dead) => {
                            self.outbox.send(endpoint, reply(token, true, dead.as_bytes()));
                            return Ok(());
                        }
                    };
                    // FetchEvents is the embedder's to answer, from the events
                    // the executor posted for the queue.
                    if let Ok((Request::FetchEvents(f), _)) = Request::decode(request, 0) {
                        let events = self.embedder.take_events(TaskId(conn), f.queue);
                        let out = match fetch_events_reply(&events) {
                            Ok(bytes) => reply(token, false, &bytes),
                            Err(e) => reply(token, true, format!("the FetchEvents reply does not encode: {e:?}").as_bytes()),
                        };
                        self.outbox.send(endpoint, out);
                        return Ok(());
                    }
                    let fut = machine.exec.control(TaskId(conn), request);
                    self.inflight.push(InFlight { reply: fut, endpoint, token });
                }
                protocol::CLOSE => {
                    let conn = r.u64()?;
                    if let Ok(m) = &self.machine {
                        m.exec.task_exited(TaskId(conn));
                    }
                    self.embedder.conns.borrow_mut().remove(&TaskId(conn));
                    self.embedder.events.borrow_mut().retain(|(t, _), _| *t != TaskId(conn));
                }
                protocol::SURFACE_BIND => {
                    self.embedder.surfaces.borrow_mut().bind(SurfaceDesc::decode(r.rest())?);
                }
                protocol::SURFACE_CPU_WROTE => {
                    let id = r.u32()?;
                    r.u32()?;
                    let mut runs_r = Reader::new(r.rest(), "the bytes a surface's tasks changed");
                    let runs = protocol::decode_runs(&mut runs_r)?;
                    runs_r.end()?;
                    self.embedder.surfaces.borrow_mut().cpu_wrote(id, &runs);
                }
                protocol::SURFACE_READ_BACK => {
                    let (id, _, token) = (r.u32()?, r.u32()?, r.u64()?);
                    let runs = self.embedder.surfaces.borrow_mut().read_back(id);
                    let mut w = Writer::default();
                    w.u64(token);
                    let refs: Vec<(u64, &[u8])> = runs.iter().map(|(a, b)| (*a, b.as_slice())).collect();
                    protocol::encode_runs(&mut w, &refs);
                    self.outbox.send(endpoint, Message::new(protocol::READ_BACK, 0, w.0));
                }
                protocol::SURFACE_RELEASED => {
                    self.embedder.surfaces.borrow_mut().released(r.u32()?);
                }
                protocol::PRESENT => {
                    let frame = Frame::decode(r.rest())?;
                    self.present(endpoint, &frame, m.b & 1 != 0);
                }
                protocol::PANEL => {
                    let on = r.u32()? != 0;
                    let out = self.panel(on);
                    let mut w = Writer::default();
                    w.u32(u32::from(out.is_err())).u32(0).bytes(out.err().unwrap_or_default().as_bytes());
                    self.outbox.send(endpoint, Message::new(protocol::PANEL_DONE, 0, w.0));
                }
                k => {
                    self.outbox.report(endpoint, 0, &format!("the GPU Worker received a message of kind {k}, which the ring does not define"));
                }
            }
            Ok(())
        })();
        if let Err(e) = result {
            self.outbox.report(endpoint, 0, &format!("the GPU Worker could not read a message of kind {}: {e}", m.kind));
        }
    }

    /// Show `frame`, answering PRESENTED; with `check`, the canvas's bytes
    /// are read back after the write and sent with the answer.
    fn present(&mut self, endpoint: u32, frame: &Frame, check: bool) {
        let swap = frame.swap_id;
        let answer = |outbox: &Outbox, err: Option<String>, bytes: &[u8]| {
            let mut w = Writer::default();
            w.u32(swap).u32(u32::from(err.is_some())).bytes(err.unwrap_or_default().as_bytes()).bytes(bytes);
            outbox.send(endpoint, Message::new(protocol::PRESENTED, 0, w.0));
        };
        let shown = match display::show(frame, &self.sink.xr, &self.sink.alpha) {
            Ok(s) => s,
            Err(why) => return answer(&self.outbox, Some(why), &[]),
        };
        if let Err(why) = self.draw(&shown) {
            return answer(&self.outbox, Some(why), &[]);
        }
        let (w, h, bpr) = (shown.width, shown.height, shown.bytes_per_row());
        self.sink.last = Some(shown);
        if !check {
            return answer(&self.outbox, None, &[]);
        }
        let (Ok(m), Some(t)) = (&self.machine, &self.sink.target) else { return answer(&self.outbox, None, &[]) };
        match read_canvas(m.device.js(), t.context(), w, h, bpr.next_multiple_of(256)) {
            Ok(p) => self.reads.push((endpoint, swap, JsFuture::from(p))),
            Err(e) => answer(&self.outbox, Some(format!("reading the canvas back: {e:?}")), &[]),
        }
    }

    /// Configure the canvas for `shown` (when its format changes) and write
    /// its texels, unless the panel is dark.
    fn draw(&mut self, shown: &display::Shown) -> Result<(), String> {
        let m = self.machine.as_ref().map_err(|dead| format!("the GPU Worker has no device: {dead}"))?;
        let t = self.sink.target.as_mut().ok_or("no canvas is attached to the GPU Worker")?;
        if !self.sink.lit {
            return Ok(());
        }
        if t.size() != (shown.width, shown.height) || self.sink.configured != Some(shown.format) {
            t.set_size(shown.width, shown.height);
            let format = match shown.format {
                CanvasFormat::Bgra8unorm => TextureFormat::Bgra8unorm,
                CanvasFormat::Rgba16float => TextureFormat::Rgba16float,
            };
            let mut c = CanvasConfiguration::<Web>::new(&m.device, format);
            // COPY_DST for writeTexture(); COPY_SRC so that what the canvas
            // holds can be read back and checked.
            c.usage = webmetal_host::gpu::idl::TextureUsage::COPY_DST | webmetal_host::gpu::idl::TextureUsage::COPY_SRC;
            c.color_space = PredefinedColorSpace::new("srgb");
            c.tone_mapping = CanvasToneMapping {
                mode: if shown.format.extended() { CanvasToneMappingMode::Extended } else { CanvasToneMappingMode::Standard },
            };
            self.sink.configured = None;
            t.configure(&c).map_err(|e| format!("configuring the canvas for {format:?}: {e}"))?;
            self.sink.configured = Some(shown.format);
        }
        t.write_frame(&m.device.queue(), &shown.texels, shown.bytes_per_row(), shown.width, shown.height)
            .map_err(|e| format!("writing the frame to the canvas: {e}"))
    }

    /// The panel goes dark (it shows black) or lights (it shows the frame
    /// on the glass, the last one shown).
    fn panel(&mut self, on: bool) -> Result<(), String> {
        self.sink.lit = on;
        let Some(last) = self.sink.last.clone() else { return Ok(()) };
        if on {
            return self.draw(&last);
        }
        // Zero texels: black, in both canvas formats.
        let black = display::Shown { texels: vec![0; last.texels.len()], ..last };
        self.sink.lit = true;
        let r = self.draw(&black);
        self.sink.lit = false;
        r
    }

    /// Run the executor and answer what it finished: whether anything
    /// progressed, and whether it has GPU work in flight.
    fn turn(&mut self, cx: &mut Context<'_>) -> (bool, bool) {
        let mut progressed = false;
        let mut busy = false;
        if let Ok(m) = &self.machine {
            busy = m.exec.pump(cx);
            let mut i = 0;
            while i < self.inflight.len() {
                match self.inflight[i].reply.as_mut().poll(cx) {
                    Poll::Pending => i += 1,
                    Poll::Ready(r) => {
                        let f = self.inflight.swap_remove(i);
                        let out = match r {
                            Ok(bytes) => reply(f.token, false, &bytes),
                            Err(e) => reply(f.token, true, format!("not a control request: {e:?}").as_bytes()),
                        };
                        self.outbox.send(f.endpoint, out);
                        progressed = true;
                    }
                }
            }
            for r in m.exec.take_reports() {
                let at = match (r.opcode, r.command_buffer, r.offset) {
                    (Some(op), _, _) => format!("request {op:#06x}"),
                    (None, Some(cb), Some(off)) => format!("command buffer {:#x}, record at {off:#x}", cb.0.get()),
                    (None, Some(cb), None) => format!("command buffer {:#x}", cb.0.get()),
                    _ => "a request".to_string(),
                };
                let status = match r.failure.status {
                    2 => "not implemented by the host",
                    3 => "a capability the host cannot honor",
                    _ => "refused",
                };
                if let Some(e) = self.embedder.endpoint(r.task) {
                    self.outbox.report(e, r.task.0, &format!("WebMetal executor, {at}: {status}: {}", r.failure.message));
                }
                progressed = true;
            }
        }
        let mut i = 0;
        while i < self.reads.len() {
            match std::pin::Pin::new(&mut self.reads[i].2).poll(cx) {
                Poll::Pending => i += 1,
                Poll::Ready(r) => {
                    let (endpoint, swap, _) = self.reads.swap_remove(i);
                    let mut w = Writer::default();
                    match r {
                        Ok(v) => {
                            w.u32(swap).u32(0).bytes(&Uint8Array::new(&v).to_vec());
                        }
                        Err(e) => {
                            w.u32(swap).u32(1).bytes(format!("reading the canvas back: {e:?}").as_bytes());
                        }
                    }
                    self.outbox.send(endpoint, Message { kind: protocol::PRESENTED, a: 0, b: 1, payload: w.0 });
                    progressed = true;
                }
            }
        }
        (progressed, busy)
    }

    /// The milliseconds to wait for a request: none while work is in flight
    /// past `BUSY_MS`, until the executor's next deadline, or for ever.
    fn wait_ms(&self, busy: bool) -> f64 {
        if busy || !self.inflight.is_empty() || !self.reads.is_empty() {
            return BUSY_MS;
        }
        match &self.machine {
            Ok(m) => match m.exec.next_deadline() {
                Some(d) => ((d.0.saturating_sub(now_ns() as u64)) as f64 / 1e6).max(0.0),
                None => -1.0,
            },
            Err(_) => -1.0,
        }
    }
}

/// The GPU Worker, as the page's script holds it.
#[wasm_bindgen]
pub struct GpuWorker {
    server: Rc<RefCell<Server>>,
}

#[wasm_bindgen]
impl GpuWorker {
    /// Set the device and the executor up and start serving the ring in
    /// `ring`. A device that cannot be set up leaves the GPU Worker serving
    /// the ring all the same, refusing every control request with the
    /// reason, as gexc's thread does.
    pub async fn start(ring: SharedArrayBuffer) -> Result<GpuWorker, JsValue> {
        let ring = Ring::attach(&ring).map_err(|e| JsValue::from_str(&e))?;
        let outbox = Rc::new(Outbox::default());
        let embedder = Rc::new(PageEmbedder {
            conns: RefCell::new(HashMap::new()),
            events: RefCell::new(HashMap::new()),
            surfaces: RefCell::new(Surfaces::default()),
            outbox: outbox.clone(),
        });
        let machine = set_up(embedder.clone()).await.map_err(|e| format!("the WebMetal executor has no WebGPU device (the browser's): {e}"));
        if let Err(e) = &machine {
            web_sys_warn(e);
        }
        let server = Rc::new(RefCell::new(Server {
            ring,
            machine,
            embedder,
            outbox,
            memories: HashMap::new(),
            waiting: None,
            inflight: Vec::new(),
            sink: Sink { target: None, configured: None, lit: true, last: None, xr: display::xr_halves(), alpha: display::unorm8_halves() },
            reads: Vec::new(),
        }));
        wasm_bindgen_futures::spawn_local(run(server.clone()));
        Ok(GpuWorker { server })
    }

    /// Why the device could not be set up, if it could not.
    pub fn dead(&self) -> Option<String> {
        self.server.borrow().machine.as_ref().err().cloned()
    }

    /// Process memory `id`: `memory` (a shared `WebAssembly.Memory` or a
    /// `SharedArrayBuffer`) and its mapping table (`crate::memory`).
    pub fn attach_memory(&self, id: u32, memory: JsValue, table: SharedArrayBuffer) {
        self.server.borrow_mut().memories.insert(id, Rc::new(TaskMemory::new(memory, &table)));
        wake();
    }

    /// Process memory `id` is gone: its connections' accesses fault until
    /// they close.
    pub fn detach_memory(&self, id: u32) {
        self.server.borrow_mut().memories.remove(&id);
    }

    /// The display's canvas: an `OffscreenCanvas` the page transferred, whose
    /// `getContext("webgpu")` is `context`.
    pub fn attach_canvas(&self, context: JsValue) -> Result<(), JsValue> {
        let t = CanvasTarget::new(context).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let mut s = self.server.borrow_mut();
        s.sink.target = Some(t);
        s.sink.configured = None;
        Ok(())
    }
}

fn web_sys_warn(s: &str) {
    let console = js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("console")).unwrap_or(JsValue::UNDEFINED);
    if let Ok(f) = js_sys::Reflect::get(&console, &JsValue::from_str("warn")) {
        if let Some(f) = f.dyn_ref::<js_sys::Function>() {
            let _ = f.call1(&console, &JsValue::from_str(s));
        }
    }
}

/// The loop: requests read and handled in order, the executor run, the
/// endpoints' messages written, then a wait for the next of these.
async fn run(server: Rc<RefCell<Server>>) {
    let waker = Waker::from(std::sync::Arc::new(Wakeup));
    let mut cx = Context::from_waker(&waker);
    let seen = Cell::new(0);
    loop {
        let (words, wait) = {
            let mut s = server.borrow_mut();
            seen.set(s.ring.doorbell());
            // An OPEN that waited for its memory, first.
            if let Some(w) = s.waiting.take() {
                match s.memories.get(&w.memory).cloned() {
                    Some(mem) => {
                        s.embedder.conns.borrow_mut().insert(TaskId(w.conn), Conn { endpoint: w.endpoint, memory: mem });
                    }
                    None => s.waiting = Some(w),
                }
            }
            while s.waiting.is_none() {
                let Some(m) = s.ring.next_request() else { break };
                s.handle(m);
            }
            let (_, busy) = s.turn(&mut cx);
            let out: Vec<(u32, Message)> = std::mem::take(&mut *s.outbox.0.borrow_mut());
            for (e, m) in out {
                s.ring.send(e, &m);
            }
            let left = s.ring.flush();
            let ms = if left { BUSY_MS } else { s.wait_ms(busy) };
            (s.ring.words.clone(), ms)
        };
        let _ = JsFuture::from(next(&words, DOORBELL as u32, seen.get(), wait)).await;
    }
}
