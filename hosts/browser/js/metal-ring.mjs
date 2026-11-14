// The ring between the guest's Workers and the GPU Worker (hosts/metal): the
// page makes it (`createRing`), the GPU Worker serves it, and each process's
// kernel is an endpoint of it (`Endpoint`). The layout and the messages are
// hosts/metal/src/ring.rs's and hosts/metal/src/protocol.rs's.
//
// An endpoint's calls block (Atomics.wait), as the kernel's calls on its
// executor do: they are made from a Worker.

export const KIND = Object.freeze({
  OPEN: 1, CONTROL: 2, CLOSE: 3, SURFACE_BIND: 4, SURFACE_CPU_WROTE: 5, SURFACE_READ_BACK: 6,
  SURFACE_RELEASED: 7, PRESENT: 8, PANEL: 9,
  REPLY: 101, RING: 102, REPORT: 103, READ_BACK: 104, PRESENTED: 105, PANEL_DONE: 106,
});

const W = Object.freeze({
  MAGIC: 0, VERSION: 1, ENDPOINTS: 2, REQUEST_SIZE: 3, ENDPOINT_SIZE: 4, REQUEST_LOCK: 5,
  REQUEST_HEAD: 6, REQUEST_TAIL: 7, DOORBELL: 8, NEXT_ENDPOINT: 9, ENDPOINT_WORDS: 16,
});
const MAGIC = 0x574d5247;
const VERSION = 1;
const HEADER = 16;

const framed = (n) => (HEADER + n + 7) & ~7;
const requestOffset = (endpoints) => ((4 * (W.ENDPOINT_WORDS + 4 * endpoints)) + 63) & ~63;

/** A ring buffer: `endpoints` endpoints, a request ring of `requestSize` bytes and endpoint rings of
 *  `endpointSize` bytes (powers of two). */
export function createRing({ endpoints = 1024, requestSize = 1 << 20, endpointSize = 1 << 14 } = {}) {
  const pow2 = (v) => v >= 64 && (v & (v - 1)) === 0;
  if (!pow2(requestSize) || !pow2(endpointSize)) throw new RangeError('ring sizes must be powers of two of at least 64');
  const bytes = requestOffset(endpoints) + requestSize + endpoints * endpointSize;
  const sab = new SharedArrayBuffer(bytes);
  const w = new Int32Array(sab);
  w[W.MAGIC] = MAGIC;
  w[W.VERSION] = VERSION;
  w[W.ENDPOINTS] = endpoints;
  w[W.REQUEST_SIZE] = requestSize;
  w[W.ENDPOINT_SIZE] = endpointSize;
  return sab;
}

/** One process's kernel's side of the ring. */
export class Endpoint {
  constructor(sab) {
    this.w = new Int32Array(sab);
    this.b = new Uint8Array(sab);
    if (this.w[W.MAGIC] !== MAGIC || this.w[W.VERSION] !== VERSION) throw new Error('not a ring of version 1');
    this.endpoints = this.w[W.ENDPOINTS];
    this.requestSize = this.w[W.REQUEST_SIZE];
    this.endpointSize = this.w[W.ENDPOINT_SIZE];
    this.requestBase = requestOffset(this.endpoints);
    this.id = Atomics.add(this.w, W.NEXT_ENDPOINT, 1);
    if (this.id >= this.endpoints) {
      throw new Error(`the ring has no endpoint left (it holds ${this.endpoints}; numbers are not reused)`);
    }
    this.base = this.requestBase + this.requestSize + this.id * this.endpointSize;
    const e = W.ENDPOINT_WORDS + 4 * this.id;
    this.HEAD = e;
    this.TAIL = e + 1;
    this.BELL = e + 2;
    this.partial = null;
    this.inbox = [];
  }

  /** Send a message: kind, `a` (this endpoint, for requests the GPU Worker answers), `b`, payload bytes. Blocks
   *  while the request ring is full, writing a long frame in pieces as the GPU Worker frees space. */
  send(kind, payload = new Uint8Array(0), b = 0) {
    const w = this.w;
    while (Atomics.compareExchange(w, W.REQUEST_LOCK, 0, 1) !== 0) Atomics.wait(w, W.REQUEST_LOCK, 1, 100);
    try {
      const frame = new Uint8Array(framed(payload.length));
      const dv = new DataView(frame.buffer);
      dv.setUint32(0, payload.length, true);
      dv.setUint32(4, kind, true);
      dv.setUint32(8, this.id, true);
      dv.setUint32(12, b, true);
      frame.set(payload, HEADER);
      let at = 0;
      const size = this.requestSize;
      while (at < frame.length) {
        const head = Atomics.load(w, W.REQUEST_HEAD) >>> 0;
        const tail = Atomics.load(w, W.REQUEST_TAIL) >>> 0;
        const free = size - ((head - tail) >>> 0);
        if (free === 0) {
          Atomics.wait(w, W.REQUEST_TAIL, tail | 0, 100);
          continue;
        }
        const n = Math.min(free, frame.length - at);
        const start = head & (size - 1);
        const first = Math.min(n, size - start);
        this.b.set(frame.subarray(at, at + first), this.requestBase + start);
        if (first < n) this.b.set(frame.subarray(at + first, at + n), this.requestBase);
        Atomics.store(w, W.REQUEST_HEAD, (head + n) | 0);
        Atomics.add(w, W.DOORBELL, 1);
        Atomics.notify(w, W.DOORBELL);
        at += n;
      }
    } finally {
      Atomics.store(w, W.REQUEST_LOCK, 0);
      Atomics.notify(w, W.REQUEST_LOCK, 1);
    }
  }

  /** Read what the GPU Worker wrote to this endpoint into `inbox`, freeing its space. */
  drain() {
    const w = this.w;
    const size = this.endpointSize;
    for (;;) {
      const head = Atomics.load(w, this.HEAD) >>> 0;
      const tail = Atomics.load(w, this.TAIL) >>> 0;
      const avail = (head - tail) >>> 0;
      if (avail === 0) return;
      const start = tail & (size - 1);
      const first = Math.min(avail, size - start);
      const chunk = new Uint8Array(avail);
      chunk.set(this.b.subarray(this.base + start, this.base + start + first));
      if (first < avail) chunk.set(this.b.subarray(this.base, this.base + avail - first), first);
      this.feed(chunk);
      Atomics.store(w, this.TAIL, (tail + avail) | 0);
      Atomics.add(w, W.DOORBELL, 1);
      Atomics.notify(w, W.DOORBELL);
    }
  }

  feed(chunk) {
    let at = 0;
    while (at < chunk.length) {
      if (!this.partial) this.partial = { header: new Uint8Array(HEADER), got: 0, body: null, bodyGot: 0 };
      const p = this.partial;
      if (p.got < HEADER) {
        const n = Math.min(HEADER - p.got, chunk.length - at);
        p.header.set(chunk.subarray(at, at + n), p.got);
        p.got += n;
        at += n;
        if (p.got < HEADER) return;
        const len = new DataView(p.header.buffer).getUint32(0, true);
        p.body = new Uint8Array(framed(len) - HEADER);
      }
      const n = Math.min(p.body.length - p.bodyGot, chunk.length - at);
      p.body.set(chunk.subarray(at, at + n), p.bodyGot);
      p.bodyGot += n;
      at += n;
      if (p.bodyGot === p.body.length) {
        const dv = new DataView(p.header.buffer);
        const len = dv.getUint32(0, true);
        this.inbox.push({ kind: dv.getUint32(4, true), a: dv.getUint32(8, true), b: dv.getUint32(12, true), payload: p.body.subarray(0, len) });
        this.partial = null;
      }
    }
  }

  /** The next message for which `match(m)` holds, waiting at most `ms` milliseconds for it (for ever when `ms` is
   *  Infinity); null when none came. Other messages stay in the inbox, in order. */
  receive(match = () => true, ms = Infinity) {
    const end = ms === Infinity ? Infinity : Date.now() + ms;
    for (;;) {
      this.drain();
      const i = this.inbox.findIndex(match);
      if (i >= 0) return this.inbox.splice(i, 1)[0];
      const bell = Atomics.load(this.w, this.BELL);
      this.drain();
      if (this.inbox.findIndex(match) >= 0) continue;
      const left = end - Date.now();
      if (left <= 0) return null;
      Atomics.wait(this.w, this.BELL, bell, Math.min(left, 1000));
    }
  }
}
