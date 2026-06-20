const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function createElement(value = "") {
  return {
    value,
    checked: false,
    hidden: false,
    innerHTML: "",
    textContent: "",
    listeners: {},
    attributes: {},
    addEventListener(name, listener) {
      this.listeners[name] = listener;
    },
    setAttribute(name, value) {
      this.attributes[name] = value;
    },
  };
}

test("dashboard reloads automatically for every statistics filter", async () => {
  const elements = {
    dataset: createElement("general_losses"),
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
    metricPickerToggle: createElement(),
    metricCount: createElement(),
    metricMenu: createElement(),
    normalize: createElement(),
    datasetNote: createElement(),
  };
  const requests = [];
  const charts = [];
  let checkedInputs = [];
  const latest = {
    metrics: [
      {metric: "personnel", metric_label: "Personnel", value: 100, observed_date: "2026-06-20"},
      {metric: "tanks", metric_label: "Tanks", value: 10, observed_date: "2026-06-20"},
    ],
  };
  const oilLatest = {
    metrics: [
      {metric: "oil_total_tonnes", metric_label: "Total oil exports, tonnes/day", value: 900000, observed_date: "2026-06-19"},
      {metric: "oil_export_revenue_eur", metric_label: "Oil export revenue, EUR/day", value: 540000000, observed_date: "2026-06-19"},
    ],
  };
  const context = {
    Chart: class {
      constructor(_context, config) {
        this.config = config;
        charts.push(config);
      }
      destroy() {}
    },
    FormData: class {},
    console,
    document: {
      getElementById: (id) => elements[id],
      querySelectorAll: () => checkedInputs,
    },
    fetch: async (url) => {
      requests.push(url);
      let data = {};
      if (url.includes("/metrics/latest")) data = url.includes("russia_oil_exports") ? oilLatest : latest;
      if (url.includes("metric=personnel")) data = {series: [{observed_date: "2026-06-19", value: 90, daily_delta: 5}, {observed_date: "2026-06-20", value: 100, daily_delta: 10}]};
      if (url.includes("metric=tanks")) data = {series: [{observed_date: "2026-06-19", value: 9, daily_delta: 1}, {observed_date: "2026-06-20", value: 10, daily_delta: 1}]};
      if (url.includes("metric=oil_total_tonnes")) data = {series: [{observed_date: "2026-06-18", value: 850000, daily_delta: 10000}, {observed_date: "2026-06-19", value: 900000, daily_delta: 50000}]};
      if (url.includes("/source-health")) data = {health: []};
      if (url.includes("/parser-errors")) data = {errors: []};
      if (url.includes("/sources")) data = {sources: []};
      return {ok: true, json: async () => data};
    },
  };
  const script = fs.readFileSync(path.join(__dirname, "../app/dashboard/static/app.js"), "utf8");
  vm.runInNewContext(script, context);
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(context.signedNumber(-500), "-500");

  for (const controlId of ["dataset", "period", "start", "end", "normalize"]) {
    assert.equal(typeof elements[controlId].listeners.change, "function", `${controlId} has no change handler`);
  }
  assert.equal(typeof elements.metricMenu.listeners.change, "function");

  requests.length = 0;
  elements.period.value = "custom";
  elements.start.value = "2026-05-01";
  elements.end.value = "2026-06-20";
  checkedInputs = [{value: "personnel"}, {value: "tanks"}];
  elements.metricMenu.listeners.change({target: {type: "checkbox", value: "tanks", checked: true}});
  await new Promise((resolve) => setImmediate(resolve));

  assert.ok(requests.some((url) => url.includes("metric=personnel&period=custom&start=2026-05-01&end=2026-06-20")));
  assert.ok(requests.some((url) => url.includes("metric=tanks&period=custom&start=2026-05-01&end=2026-06-20")));
  assert.equal(elements.metricCount.textContent, "2");
  assert.equal(charts.at(-3).data.datasets.length, 2);

  elements.normalize.checked = true;
  await elements.normalize.listeners.change();
  assert.equal(charts.at(-3).options.scales.y.title.text, "Індекс (перше значення = 100)");

  requests.length = 0;
  elements.dataset.value = "russia_oil_exports";
  await elements.dataset.listeners.change();
  assert.ok(requests.some((url) => url.includes("dataset=russia_oil_exports&metric=oil_total_tonnes")));
  assert.match(elements.datasetNote.innerHTML, /CREA Russia Fossil Tracker/);
});
