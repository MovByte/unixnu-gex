// The task side of examples/check_task.rs: a Worker that stands where a
// process's kernel stands, with an endpoint of the ring and a process memory.
// The Worker sets globalThis.__task = { endpoint, mem, log: [], results: [] }.

const T = () => globalThis.__task;

export function ep_send(kind, b, payload) {
  T().endpoint.send(kind, payload, b);
}

/** The payload of the next message of `kind` (its `b` in `ep_last_b`), or undefined after `ms`. */
export function ep_receive(kind, ms) {
  const m = T().endpoint.receive((x) => x.kind === kind, ms);
  if (!m) return undefined;
  T().lastB = m.b;
  return m.payload.slice();
}

export function ep_last_b() {
  return T().lastB;
}

export function ep_id() {
  return T().endpoint.id;
}

/** Messages of `kind` waiting in the inbox, without waiting. */
export function ep_pending(kind) {
  T().endpoint.drain();
  return T().endpoint.inbox.filter((m) => m.kind === kind).length;
}

export function mem_write(offset, bytes) {
  T().mem.set(bytes, offset);
}

export function mem_read(offset, len) {
  return T().mem.slice(offset, offset + len);
}

/** Set the mapping table: `words` (Uint32Array) as hosts/metal/src/memory.rs lays it out, under its sequence. */
export function table_set(words) {
  const t = T().table;
  const seq = Atomics.load(t, 0);
  Atomics.store(t, 0, seq + 1);
  for (let i = 1; i < words.length; i++) Atomics.store(t, i, words[i]);
  Atomics.store(t, 0, seq + 2);
}

export function fetch_bytes(path) {
  const x = new XMLHttpRequest();
  x.open('GET', path, false);
  x.responseType = 'arraybuffer';
  x.send();
  return x.status === 200 ? new Uint8Array(x.response) : undefined;
}

export function log(s) {
  T().log.push(s);
}

export function result(name, ok, detail) {
  T().results.push({ name, ok, detail });
}
