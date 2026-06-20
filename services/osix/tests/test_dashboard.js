const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function createElement(value = "") {
  return {
    value,
    innerHTML: "",
    textContent: "",
    listeners: {},
    addEventListener(name, listener) {
      this.listeners[name] = listener;
    },
  };
}

test("dashboard reloads automatically for every statistics filter", async () => {
  const elements = {
    dataset: createElement("general_losses"),
    metric: createElement("personnel"),
    period: createElement("all"),
    start: createElement(""),
    end: createElement(""),
    refresh: createElement(),
    loginForm: createElement(),
    reingest: createElement(),
    backfillMod: createElement(),
    sourceConfig: createElement(),
    adminStatus: createElement(),
    summary: createElement(),
    health: createElement(),
    errors: createElement(),
    totalChart: createElement(),
    deltaChart: createElement(),
    comparisonChart: createElement(),
  };
  const requests = [];
  const latest = {
    metrics: [
      {metric: "personnel", metric_label: "Personnel", value: 100, observed_date: "2026-06-20"},
      {metric: "tanks", metric_label: "Tanks", value: 10, observed_date: "2026-06-20"},
    ],
  };
  const context = {
    Chart: class {
      destroy() {}
    },
    FormData: class {},
    console,
    document: {getElementById: (id) => elements[id]},
    fetch: async (url) => {
      requests.push(url);
      let data = {};
      if (url.includes("/metrics/latest")) data = latest;
      if (url.includes("/metrics/series")) data = {series: []};
      if (url.includes("/source-health")) data = {health: []};
      if (url.includes("/parser-errors")) data = {errors: []};
      if (url.includes("/sources")) data = {sources: []};
      return {ok: true, json: async () => data};
    },
  };
  const script = fs.readFileSync(path.join(__dirname, "../app/dashboard/static/app.js"), "utf8");
  vm.runInNewContext(script, context);
  await new Promise((resolve) => setImmediate(resolve));

  for (const controlId of ["dataset", "metric", "period", "start", "end"]) {
    assert.equal(typeof elements[controlId].listeners.change, "function", `${controlId} has no change handler`);
  }

  requests.length = 0;
  elements.metric.value = "tanks";
  elements.period.value = "custom";
  elements.start.value = "2026-05-01";
  elements.end.value = "2026-06-20";
  await elements.metric.listeners.change();

  assert.ok(
    requests.some((url) =>
      url.includes("metric=tanks&period=custom&start=2026-05-01&end=2026-06-20"),
    ),
  );
});
