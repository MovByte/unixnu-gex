//! The WebMetal host executor for the Darwin personality: the GPU behind
//! the accelerator's WebMetal connections (`gex_kernel::darwin::accel`).
//!
//! One host thread owns the one WebGPU device of the whole guest system
//! (every process's Metal objects live on it, and IOSurface textures cross
//! processes) and runs WebMetal's executor (`webmetal_host`) on it, over
//! the native WebGPU implementation the build links: Dawn or wgpu-native
//! through webgpu.h, chosen as WebMetal's own builds choose it
//! (`WEBGPU_NATIVE` and `WEBGPU_NATIVE_DIR`, `webmetal_host`'s build
//! script). The thread starts with the first connection.
//!
//! The kernel hands the thread each connection with its task's memory, each
//! control request with what to call when it is answered, and each
//! connection's end ([`gex_kernel::darwin::accel::host::Host`]). Requests of
//! different connections run concurrently on the thread, as the executor's
//! futures allow; a connection's own come one at a time. FetchEvents is
//! answered from the events the executor posted ([`embedder`]), as the
//! executor's interface asks of its embedder. What the executor reports it
//! could not do (status 2 and 3) reaches the connection's task, which
//! reports it as the kernel reports what it does not implement.
//!
//! The executor's IOSurfaces are the kernel's: the surface table the kernel
//! calls ([`surfaces`]) is installed with the executor.

mod embedder;
mod surfaces;

use std::rc::Rc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use gex_kernel::darwin::accel::host::{Done, Host, Outcome, TaskMemory};
use gex_kernel::darwin::accel::wire;
use webmetal_host::blit::BlitService;
use webmetal_host::compute::ComputeService;
use webmetal_host::embed::{Embedder as _, TaskId};
use webmetal_host::exec::{fetch_events_reply, Config, ControlService, Executor, Services};
use webmetal_host::format::webgpu::{Feature, HostFeatures};
use webmetal_host::gpu::idl::RequestAdapterOptions;
use webmetal_host::gpu::native::{Native, NativeGpu};
use webmetal_host::gpu::scope::{Granularity, Policy};
use webmetal_host::gpu::{negotiate, Adapter as _, Device as _, ExceptionKind, Gpu as _, GpuFuture};
use webmetal_host::mem::service::MemoryServices;
use webmetal_host::pipeline::{self, PipelineServices};
use webmetal_host::render::RenderServices;
use webmetal_host::state::StateServices;
use webmetal_wire::{DecodeError, Request};

use embedder::GexEmbedder;
use surfaces::Surfaces;

/// How long setting the device up may go without any WebGPU operation
/// completing before it is given up.
const STALL: Duration = Duration::from_secs(120);

/// The WebGPU implementation the build links.
pub fn implementation() -> &'static str {
    webmetal_host::gpu::native::sys::meta::IMPLEMENTATION
}

/// Install the executor and its surface table in the kernel.
pub fn install() {
    let surfaces = Arc::new(Surfaces::default());
    let host = Gex { surfaces: Arc::clone(&surfaces), jobs: Mutex::new(None) };
    if gex_kernel::darwin::accel::host::install(Box::new(host)).is_err() {
        return;
    }
    let _ = gex_kernel::darwin::iosurface::executor::install(Box::new(surfaces::Table(surfaces)));
}

/// What the kernel asks of the executor's thread.
enum Job {
    Open { conn: u64, memory: TaskMemory },
    Control { conn: u64, request: Vec<u8>, done: Done },
    Close { conn: u64 },
}

/// The executor as the kernel reaches it: the queue to its thread, made
/// with the first connection.
struct Gex {
    surfaces: Arc<Surfaces>,
    jobs: Mutex<Option<Sender<Job>>>,
}

impl Gex {
    fn send(&self, job: Job) {
        let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
        let tx = jobs.get_or_insert_with(|| {
            let (tx, rx) = mpsc::channel();
            let surfaces = Arc::clone(&self.surfaces);
            std::thread::Builder::new()
                .name("gex-webmetal".into())
                .spawn(move || thread(surfaces, rx))
                .expect("starting the WebMetal executor's thread");
            tx
        });
        // A job the thread can no longer take answers its request as it is
        // dropped (`Done`'s own drop).
        let _ = tx.send(job);
    }
}

impl Host for Gex {
    fn open(&self, conn: u64, memory: TaskMemory) {
        self.send(Job::Open { conn, memory });
    }

    fn surfaces(&self, request: &[u8]) -> Vec<u32> {
        match Request::decode(request, 0) {
            Ok((Request::CreateTextureWithIOSurface(r), _)) => vec![r.iosurface.0],
            _ => Vec::new(),
        }
    }

    fn control(&self, conn: u64, request: Vec<u8>, done: Done) {
        self.send(Job::Control { conn, request, done });
    }

    fn close(&self, conn: u64) {
        self.send(Job::Close { conn });
    }
}

type Exec = Executor<Native, GexEmbedder>;

/// The device and the executor on it.
struct Machine {
    gpu: NativeGpu,
    exec: Exec,
    embedder: Rc<GexEmbedder>,
}

/// The WebGPU device, with the features and limits the negotiation asks
/// for, and the executor with every service WebMetal provides.
fn set_up(surfaces: Arc<Surfaces>) -> Result<Machine, String> {
    let gpu = NativeGpu::new();
    let device = gpu
        .block_on(
            async {
                let adapter = gpu
                    .request_adapter(&RequestAdapterOptions::new())
                    .await
                    .map_err(|e| format!("requestAdapter: {e:?}"))?
                    .ok_or("requestAdapter: no adapter")?;
                let mut descriptor =
                    negotiate::plan(&adapter.features(), &adapter.limits()).map_err(|e| format!("negotiation: {e}"))?.descriptor;
                descriptor.label = "gex WebMetal".into();
                adapter.request_device(&descriptor).await.map_err(|e| format!("requestDevice: {e:?}"))
            },
            STALL,
        )
        .map_err(|s| format!("the device request stalled: {s}"))??;
    let names = device.features();
    let features = HostFeatures::new(Feature::ALL.into_iter().filter(|f| names.contains(f.name())));
    let embedder = Rc::new(GexEmbedder::new(surfaces));
    let memory = gpu
        .block_on(MemoryServices::new(&device, features, embedder.clone()), STALL)
        .map_err(|s| format!("setting the memory services up stalled: {s}"))?
        .map_err(|e| format!("setting the memory services up: {e}"))?;
    // An implementation that does not report wgslLanguageFeatures
    // (wgpu-native) is taken to offer no extension: a pipeline that needs
    // one is refused, never assumed to work.
    let wgsl = match gpu.wgsl_language_features() {
        Ok(f) => f,
        Err(e) if e.kind == ExceptionKind::Unsupported => Default::default(),
        Err(e) => return Err(format!("wgslLanguageFeatures: {e}")),
    };
    let pipelines = PipelineServices::<Native>::new(&device, wgsl, pipeline::Config::default());
    let render = RenderServices::new(memory.memory());
    let services = Services {
        control: vec![
            memory.control() as Box<dyn ControlService<Native, GexEmbedder>>,
            Box::new(StateServices::new()),
            pipelines.control(),
            render.control(),
        ],
        render: Some(render.encoder()),
        compute: Some(Box::new(ComputeService::new(memory.memory()))),
        blit: Some(Box::new(BlitService::new(memory.memory()))),
        coherence: Some(memory.coherence()),
    };
    // Each WebGPU call in an error scope of its own, and an error that
    // escapes every scope an executor defect that stops the thread.
    let config = Config { scopes: Policy { granularity: Granularity::PerCall, strict: true } };
    let exec = Executor::new(device, embedder.clone(), services, config);
    Ok(Machine { gpu, exec, embedder })
}

/// A control request with the executor.
struct InFlight {
    reply: GpuFuture<Result<Vec<u8>, DecodeError>>,
    done: Done,
}

/// The executor's thread: the device set up, then jobs taken and the
/// executor kept moving until the kernel is gone. A panic of the executor
/// (a defect, such as a WebGPU error no scope caught) ends the device: the
/// requests it held are answered as refused as they are dropped, and every
/// later one is refused with the reason.
fn thread(surfaces: Arc<Surfaces>, jobs: Receiver<Job>) {
    let dead = match set_up(surfaces) {
        Ok(m) => {
            let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(m, &jobs)));
            match run {
                Ok(()) => return,
                Err(p) => {
                    let what = p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
                    format!("the WebMetal executor stopped: {what}")
                }
            }
        }
        Err(e) => format!("the WebMetal executor has no WebGPU device ({}): {e}", implementation()),
    };
    eprintln!("gexc: {dead}");
    for job in jobs.iter() {
        match job {
            Job::Control { done, .. } => done.answer(Outcome::Refused(dead.clone())),
            Job::Open { .. } | Job::Close { .. } => {}
        }
    }
}

fn run(m: Machine, jobs: &Receiver<Job>) {
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let mut inflight: Vec<InFlight> = Vec::new();
    loop {
        let busy = m.exec.pump(&mut cx);
        let mut i = 0;
        while i < inflight.len() {
            match inflight[i].reply.as_mut().poll(&mut cx) {
                Poll::Pending => i += 1,
                Poll::Ready(r) => {
                    let f = inflight.swap_remove(i);
                    f.done.answer(match r {
                        Ok(bytes) => Outcome::Reply(bytes),
                        Err(e) => Outcome::Refused(format!("not a control request: {e:?}")),
                    });
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
            wire::report(r.task.0, format!("WebMetal executor, {at}: {status}: {}", r.failure.message));
        }
        let wait = if busy || !inflight.is_empty() {
            m.gpu.process_events();
            Some(Duration::from_millis(1))
        } else {
            m.exec.next_deadline().map(|d| Duration::from_nanos(d.0.saturating_sub(m.embedder.now().0)))
        };
        let job = match wait {
            Some(w) => match jobs.recv_timeout(w) {
                Ok(job) => job,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => return,
            },
            None => match jobs.recv() {
                Ok(job) => job,
                Err(_) => return,
            },
        };
        match job {
            Job::Open { conn, memory } => m.embedder.open(TaskId(conn), memory),
            Job::Close { conn } => {
                m.exec.task_exited(TaskId(conn));
                m.embedder.close(TaskId(conn));
            }
            Job::Control { conn, request, done } => {
                // FetchEvents is the embedder's to answer, from the events
                // the executor posted for the queue.
                if let Ok((Request::FetchEvents(f), _)) = Request::decode(&request, 0) {
                    let events = m.embedder.take_events(TaskId(conn), f.queue);
                    done.answer(match fetch_events_reply(&events) {
                        Ok(bytes) => Outcome::Reply(bytes),
                        Err(e) => Outcome::Refused(format!("the FetchEvents reply does not encode: {e:?}")),
                    });
                    continue;
                }
                let reply = m.exec.control(TaskId(conn), &request);
                inflight.push(InFlight { reply, done });
            }
        }
    }
}
