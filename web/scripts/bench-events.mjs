// REV-UI-003: fixed retained-history + 10,000 live-event workload.
import { performance } from "node:perf_hooks";
import { createServer } from "vite";

const server = await createServer({ configFile: false, optimizeDeps: { noDiscovery: true, include: [] }, server: { middlewareMode: true, hmr: false, ws: false, watch: null } });
try {
  const reducers = await server.ssrLoadModule("/src/ui/events.ts");
  const merge = (rows, incoming) => reducers.retainEvents
    ? reducers.retainEvents(rows, [incoming]) : reducers.mergeEvent(rows, incoming);
  const event = (id) => ({ schema_version: 1, id, time: "2026-10-03T00:00:00Z", category: "authen", type: "ascii.login", result: "pass" });
  const fixture = Array.from({ length: 11000 }, (_, i) => event(i + 1));
  const samples = [];
  let retained = 0;
  for (let sample = 0; sample < 8; sample += 1) {
    globalThis.gc?.();
    let rows = fixture.slice(0, 1000).reverse();
    const started = performance.now();
    for (const incoming of fixture.slice(1000)) rows = merge(rows, incoming);
    const elapsed = performance.now() - started;
    if (sample > 0) samples.push(elapsed);
    retained = rows.length;
  }
  samples.sort((a, b) => a - b);
  console.log(JSON.stringify({ workload: "1000 history + 10000 live events", samples: samples.length,
    median_ms: samples[3], p95_ms: samples[6], retained_events: retained, node: process.version }, null, 2));
} finally {
  await server.close();
}
