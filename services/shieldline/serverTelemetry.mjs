import { SpanStatusCode, trace } from "@opentelemetry/api";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { resourceFromAttributes } from "@opentelemetry/resources";
import { BatchSpanProcessor } from "@opentelemetry/sdk-trace-base";
import { NodeTracerProvider } from "@opentelemetry/sdk-trace-node";
import { ATTR_SERVICE_NAME, ATTR_SERVICE_VERSION } from "@opentelemetry/semantic-conventions";

const serviceVersion = process.env.SHIELDLINE_RELEASE_VERSION || "development";
const processors = [];
if (process.env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT) {
  processors.push(new BatchSpanProcessor(new OTLPTraceExporter({ url: process.env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT })));
}
const provider = new NodeTracerProvider({
  resource: resourceFromAttributes({ [ATTR_SERVICE_NAME]: "shieldline", [ATTR_SERVICE_VERSION]: serviceVersion }),
  spanProcessors: processors,
});
provider.register();
const tracer = trace.getTracer("shieldline.http", serviceVersion);
const requests = new Map();
const durations = new Map();
const analyticsEvents = new Map();
const durationBuckets = [0.05, 0.1, 0.25, 0.5, 1, 2, 5];

function routeName(url = "/") {
  const pathname = new URL(url, "http://127.0.0.1").pathname;
  return pathname
    .replace(/\/(operations|runs|rooms)\/[^/]+/g, "/$1/:id")
    .replace(/\/(reports)\/\d{4}-\d{2}-\d{2}/g, "/$1/:day");
}

function increment(map, key, amount = 1) { map.set(key, (map.get(key) || 0) + amount); }

function record(method, route, status, durationSeconds) {
  const labels = `${method}|${route}|${status}`;
  increment(requests, labels);
  const durationKey = `${method}|${route}`;
  const current = durations.get(durationKey) || { count: 0, sum: 0, buckets: durationBuckets.map(() => 0) };
  current.count += 1;
  current.sum += durationSeconds;
  durationBuckets.forEach((bucket, index) => { if (durationSeconds <= bucket) current.buckets[index] += 1; });
  durations.set(durationKey, current);
}

export function instrumentHttpHandler(handler) {
  return async (req, res) => {
    const method = String(req.method || "GET").toUpperCase();
    const route = routeName(req.url);
    const started = process.hrtime.bigint();
    return tracer.startActiveSpan(`${method} ${route}`, { attributes: { "http.request.method": method, "url.path": route } }, async (span) => {
      try {
        await handler(req, res);
        span.setAttribute("http.response.status_code", res.statusCode);
        span.setStatus({ code: res.statusCode >= 500 ? SpanStatusCode.ERROR : SpanStatusCode.OK });
      } catch (error) {
        span.recordException(error);
        span.setStatus({ code: SpanStatusCode.ERROR, message: error instanceof Error ? error.message : "Unhandled request error" });
        throw error;
      } finally {
        const durationSeconds = Number(process.hrtime.bigint() - started) / 1e9;
        record(method, route, res.statusCode, durationSeconds);
        console.log(JSON.stringify({ timestamp: new Date().toISOString(), level: "info", component: "shieldline.http", traceId: span.spanContext().traceId, method, route, status: res.statusCode, durationMs: Math.round(durationSeconds * 1000) }));
        span.end();
      }
    });
  };
}

function labels(method, route, status) {
  return `{method="${method}",route="${route}",status="${status}"}`;
}

export function renderPrometheusMetrics() {
  const lines = ["# HELP shieldline_http_requests_total HTTP requests handled by Shieldline.", "# TYPE shieldline_http_requests_total counter"];
  for (const [key, count] of requests) {
    const [method, route, status] = key.split("|");
    lines.push(`shieldline_http_requests_total${labels(method, route, status)} ${count}`);
  }
  lines.push("# HELP shieldline_http_request_duration_seconds HTTP request duration.", "# TYPE shieldline_http_request_duration_seconds histogram");
  for (const [key, value] of durations) {
    const [method, route] = key.split("|");
    durationBuckets.forEach((bucket, index) => lines.push(`shieldline_http_request_duration_seconds_bucket{method="${method}",route="${route}",le="${bucket}"} ${value.buckets[index]}`));
    lines.push(`shieldline_http_request_duration_seconds_bucket{method="${method}",route="${route}",le="+Inf"} ${value.count}`);
    lines.push(`shieldline_http_request_duration_seconds_sum{method="${method}",route="${route}"} ${value.sum}`);
    lines.push(`shieldline_http_request_duration_seconds_count{method="${method}",route="${route}"} ${value.count}`);
  }
  lines.push("# HELP shieldline_analytics_events_total Accepted Shieldline analytics events.", "# TYPE shieldline_analytics_events_total counter");
  for (const [key, count] of analyticsEvents) {
    const [eventName, channel] = key.split("|");
    lines.push(`shieldline_analytics_events_total{event_name="${eventName}",channel="${channel}"} ${count}`);
  }
  return `${lines.join("\n")}\n`;
}

export function recordAnalyticsMetric(eventName, channel) { increment(analyticsEvents, `${eventName}|${channel}`); }

export async function shutdownTelemetry() { await provider.shutdown(); }
