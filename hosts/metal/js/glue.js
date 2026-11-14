// The GPU Worker's waits and clock (src/worker.rs).

let resolveNext = null;
let woken = false;
let doorWait = null;

/** Wake the pending (or the next) `next()`: a future of the executor's made progress. */
export function wake() {
  if (resolveNext) resolveNext();
  else woken = true;
}

/** Settles when word `index` of `words` is no longer `seen`, when `wake()` is called, or after `ms` milliseconds
 *  (never, for a negative `ms`). One wait on the word is kept per value, so waits that end another way do not pile
 *  up on it. */
export function next(words, index, seen, ms) {
  if (woken) {
    woken = false;
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    let timer;
    const done = () => {
      if (resolveNext !== done) return;
      resolveNext = null;
      if (timer !== undefined) clearTimeout(timer);
      resolve();
    };
    resolveNext = done;
    if (ms >= 0) timer = setTimeout(done, ms);
    if (Atomics.load(words, index) !== seen) {
      done();
      return;
    }
    if (!doorWait || doorWait.seen !== seen) {
      const w = Atomics.waitAsync(words, index, seen);
      doorWait = { seen, promise: w.async ? w.value : Promise.resolve() };
      doorWait.promise.then(() => { if (doorWait && doorWait.seen === seen) doorWait = null; });
    }
    doorWait.promise.then(done);
  });
}

/** The page's monotonic clock, in nanoseconds: the time origin of the Worker plus its `performance.now()`. */
export function now_ns() {
  return (performance.timeOrigin + performance.now()) * 1e6;
}

/** Copy the canvas's current texture into a buffer and resolve with its bytes (rows of `bytesPerRow`, a multiple
 *  of 256). The texture is the one just written, in the same task. */
export async function read_canvas(device, context, width, height, bytesPerRow) {
  const texture = context.getCurrentTexture();
  const buffer = device.createBuffer({ size: bytesPerRow * height, usage: GPUBufferUsage.COPY_DST | GPUBufferUsage.MAP_READ });
  const e = device.createCommandEncoder();
  e.copyTextureToBuffer({ texture }, { buffer, bytesPerRow, rowsPerImage: height }, { width, height, depthOrArrayLayers: 1 });
  device.queue.submit([e.finish()]);
  await buffer.mapAsync(GPUMapMode.READ);
  const out = new Uint8Array(buffer.getMappedRange()).slice();
  buffer.unmap();
  buffer.destroy();
  return out;
}
