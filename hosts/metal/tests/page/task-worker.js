// A process's kernel's stand-in: an endpoint of the ring and the process memory, running examples/check_task.rs.
import { Endpoint } from '/js/metal-ring.mjs';

self.onmessage = async (e) => {
  const { ring, memory, table, glue } = e.data;
  globalThis.__task = { endpoint: new Endpoint(ring), mem: new Uint8Array(memory), table: new Int32Array(table), log: [], results: [] };
  const t = globalThis.__task;
  try {
    const g = await import(glue);
    await g.default();
    g.run_checks();
    postMessage({ results: t.results, log: t.log });
  } catch (err) {
    postMessage({ results: t.results, log: t.log, error: String(err && err.stack ? err.stack : err) });
  }
};
