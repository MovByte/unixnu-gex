// The GPU Worker (hosts/metal): the one Worker that owns the guest system's
// GPUDevice and runs WebMetal's executor on it, serving the ring
// (metal-ring.mjs). The page starts it with
//
//   { start: { glue, ring } }   glue: the URL of hosts/metal's wasm-bindgen
//                               output (gex_metal_page.js); ring: createRing()'s
//
// and then hands it, in any order:
//
//   { attach: id, memory, table }  process memory `id` (a shared
//                                  WebAssembly.Memory or SharedArrayBuffer)
//                                  and its mapping table (hosts/metal/src/memory.rs)
//   { detach: id }                 that process's memory is gone
//   { canvas }                     the display's OffscreenCanvas
//
// It answers { started: true } or { started: false, dead: reason } once the
// device is set up (a device that cannot be set up leaves the Worker
// refusing every request with the reason), and { failed: reason } for a
// message it cannot take.
//
// A panic of the executor (a defect, such as a WebGPU error no scope caught)
// traps the module, which WebAssembly cannot unwind: the Worker answers
// nothing more, where gexc's thread goes on refusing every request with the
// reason. It posts { trapped: reason } so that the page knows.

let worker = null;
const early = [];

const trapped = (why) => postMessage({ trapped: String(why && why.stack ? why.stack : why) });
self.addEventListener('error', (e) => trapped(e.error || e.message));
self.addEventListener('unhandledrejection', (e) => trapped(e.reason));

function take(m) {
  if (m.attach !== undefined) worker.attach_memory(m.attach, m.memory, m.table);
  else if (m.detach !== undefined) worker.detach_memory(m.detach);
  else if (m.canvas) worker.attach_canvas(m.canvas.getContext('webgpu'));
  else postMessage({ failed: `the GPU Worker takes no message ${Object.keys(m)}` });
}

self.onmessage = async (e) => {
  const m = e.data;
  if (!m.start) {
    if (worker) {
      try { take(m); } catch (err) { postMessage({ failed: String(err) }); }
    } else {
      early.push(m);
    }
    return;
  }
  try {
    const glue = await import(m.start.glue);
    await glue.default();
    worker = await glue.GpuWorker.start(m.start.ring);
    for (const x of early.splice(0)) take(x);
    const dead = worker.dead();
    postMessage(dead ? { started: false, dead } : { started: true });
  } catch (err) {
    postMessage({ failed: String(err && err.stack ? err.stack : err) });
  }
};
