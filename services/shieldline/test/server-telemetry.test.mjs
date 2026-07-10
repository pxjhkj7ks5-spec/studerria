import assert from "node:assert/strict";
import test from "node:test";
import { instrumentHttpHandler, renderPrometheusMetrics } from "../serverTelemetry.mjs";

test("HTTP telemetry records normalized Prometheus counters and histograms", async () => {
  const handler = instrumentHttpHandler(async (_req, res) => { res.statusCode = 204; });
  await handler({ method: "GET", url: "/shieldline/api/operations/run-secret/events" }, { statusCode: 200 });
  const metrics = renderPrometheusMetrics();
  assert.match(metrics, /shieldline_http_requests_total/);
  assert.match(metrics, /operations\/:id\/events/);
  assert.doesNotMatch(metrics, /run-secret/);
});
