const api = (path) => `/osix/api/v1${path}`;

let totalChart;
let deltaChart;
let comparisonChart;
let dashboardRequestId = 0;
let selectedMetrics = ["personnel"];

const chartColors = ["#1677ff", "#f97316", "#14b8a6", "#8b5cf6", "#e11d48"];

const datasetNotes = {
  general_losses:
    'Щоденні накопичувальні оцінки від 24.02.2022. <a href="https://github.com/PetroIvaniuk/2022-Ukraine-Russia-War-Dataset" target="_blank" rel="noreferrer">Структурований архів</a> повідомлень Генштабу ЗСУ; актуальні записи перевіряються за <a href="https://mod.gov.ua/news/tag-vidsich-agresoru" target="_blank" rel="noreferrer">Міноборони України</a>.',
  russia_oil_exports:
    'Щоденні оцінки експорту нафти з РФ: обсяги, виручка та напрямки. Джерело — <a href="https://www.russiafossiltracker.com/" target="_blank" rel="noreferrer">CREA Russia Fossil Tracker</a> (Kpler, Eurostat і митні дані).',
  sbs_stats: 'Публічна статистика Сил безпілотних систем України.',
};

const metricPriority = [
  "oil_total_tonnes",
  "crude_oil_tonnes",
  "oil_products_tonnes",
  "pipeline_oil_tonnes",
  "oil_export_revenue_eur",
  "oil_to_china_tonnes",
  "oil_to_india_tonnes",
  "oil_to_eu_tonnes",
  "oil_to_turkiye_tonnes",
  "oil_to_other_tonnes",
  "total_hit",
  "total_destroyed",
  "personnel",
  "personnel_killed",
  "personnel_wounded",
  "flights_strike",
  "flights_recon",
  "tanks",
  "tanks_hit",
  "tanks_destroyed",
  "armored_vehicles",
  "armored_vehicles_hit",
  "armored_vehicles_destroyed",
  "artillery_systems",
  "guns_howitzers_hit",
  "guns_howitzers_destroyed",
  "mlrs",
  "mlrs_air_defense_hit",
  "mlrs_air_defense_destroyed",
  "air_defense_systems",
  "aircraft",
  "helicopters",
  "uav",
  "cruise_missiles",
  "vehicles_fuel_tanks",
  "special_equipment",
  "ships_boats",
  "submarines",
];

function serializeDate(name, element) {
  return element.value ? `&${name}=${encodeURIComponent(element.value)}` : "";
}

async function getJson(path) {
  const response = await fetch(api(path), { credentials: "same-origin" });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

function rows(items, columns) {
  if (!items.length) return '<p class="muted">Немає даних</p>';
  const head = columns.map((column) => `<th>${column.label}</th>`).join("");
  const body = items
    .map((item) => `<tr>${columns.map((column) => `<td>${escapeHtml(item[column.key])}</td>`).join("")}</tr>`)
    .join("");
  return `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function signedNumber(value) {
  if (value == null || Number(value) === 0) return "";
  const number = Number(value);
  return `${number > 0 ? "+" : ""}${number.toLocaleString("uk-UA")}`;
}

function orderedMetrics(metrics) {
  return [...metrics].sort((left, right) => {
    const leftIndex = metricPriority.indexOf(left.metric);
    const rightIndex = metricPriority.indexOf(right.metric);
    const leftRank = leftIndex === -1 ? metricPriority.length : leftIndex;
    const rightRank = rightIndex === -1 ? metricPriority.length : rightIndex;
    return leftRank - rightRank || String(left.metric).localeCompare(String(right.metric));
  });
}

function updateMetricOptions(metrics) {
  const available = orderedMetrics(metrics);
  if (!available.length) return selectedMetrics;
  const availableNames = new Set(available.map((item) => item.metric));
  selectedMetrics = selectedMetrics.filter((metric) => availableNames.has(metric));
  if (!selectedMetrics.length) selectedMetrics = [available[0].metric];
  document.getElementById("metricMenu").innerHTML = available
    .map(
      (item) => `
        <label class="metric-choice">
          <input type="checkbox" value="${escapeHtml(item.metric)}" ${selectedMetrics.includes(item.metric) ? "checked" : ""} />
          <span>${escapeHtml(item.metric_label || item.metric)}</span>
        </label>
      `,
    )
    .join("");
  document.getElementById("metricCount").textContent = String(selectedMetrics.length);
  return [...selectedMetrics];
}

function drawChart(existing, canvasId, labels, datasets, type, axisLabel = "") {
  if (existing) existing.destroy();
  const context = document.getElementById(canvasId);
  return new Chart(context, {
    type,
    data: { labels, datasets },
    options: {
      animation: false,
      responsive: true,
      maintainAspectRatio: false,
      resizeDelay: 120,
      interaction: { mode: "index", intersect: false },
      plugins: { legend: { display: datasets.length > 1, position: "bottom" } },
      scales: {
        x: { ticks: { maxTicksLimit: 8 } },
        y: { beginAtZero: false, title: { display: Boolean(axisLabel), text: axisLabel } },
      },
    },
  });
}

function alignSeries(labels, series, valueKey) {
  const byDate = new Map(series.map((point) => [String(point.observed_date), point[valueKey] ?? null]));
  return labels.map((label) => byDate.get(label) ?? null);
}

function normalizedValues(values) {
  const base = values.find((value) => Number.isFinite(Number(value)) && Number(value) !== 0);
  if (base == null) return values;
  return values.map((value) => (value == null ? null : (Number(value) / Number(base)) * 100));
}

function percentageChanges(values) {
  return values.map((value, index) => {
    if (index === 0 || value == null || values[index - 1] == null || Number(values[index - 1]) === 0) return null;
    return ((Number(value) - Number(values[index - 1])) / Number(values[index - 1])) * 100;
  });
}

function chartDataset(label, values, index, type) {
  const color = chartColors[index % chartColors.length];
  return {
    label,
    data: values,
    borderColor: color,
    backgroundColor: type === "bar" ? `${color}99` : `${color}1f`,
    borderWidth: 2,
    tension: 0.2,
    fill: false,
    spanGaps: false,
  };
}

async function loadDashboard() {
  const requestId = ++dashboardRequestId;
  const dataset = document.getElementById("dataset").value;
  const period = document.getElementById("period").value;
  const start = document.getElementById("start");
  const end = document.getElementById("end");
  const normalize = document.getElementById("normalize").checked;
  document.getElementById("datasetNote").innerHTML = datasetNotes[dataset] || "";
  const custom = period === "custom" ? `${serializeDate("start", start)}${serializeDate("end", end)}` : "";
  const latestData = await getJson(`/metrics/latest?dataset=${encodeURIComponent(dataset)}`);
  if (requestId !== dashboardRequestId) return;
  const latestMetrics = orderedMetrics(latestData.metrics || []);
  const metrics = updateMetricOptions(latestMetrics);
  const latestByMetric = new Map(latestMetrics.map((item) => [item.metric, item]));

  const [seriesResults, healthData, errorsData] = await Promise.all([
    Promise.all(
      metrics.map((metric) =>
        getJson(`/metrics/series?dataset=${encodeURIComponent(dataset)}&metric=${encodeURIComponent(metric)}&period=${encodeURIComponent(period)}${custom}`),
      ),
    ),
    getJson("/source-health"),
    getJson("/parser-errors"),
  ]);
  if (requestId !== dashboardRequestId) return;

  const seriesByMetric = metrics.map((metric, index) => ({ metric, series: seriesResults[index].series || [] }));
  const labels = [...new Set(seriesByMetric.flatMap((item) => item.series.map((point) => String(point.observed_date))))].sort();
  const totalDatasets = seriesByMetric.map((item, index) => {
    const values = alignSeries(labels, item.series, "value");
    const label = latestByMetric.get(item.metric)?.metric_label || item.metric;
    return chartDataset(label, normalize ? normalizedValues(values) : values, index, "line");
  });
  const deltaDatasets = seriesByMetric.map((item, index) => {
    const rawValues = alignSeries(labels, item.series, "value");
    const values = normalize ? percentageChanges(rawValues) : alignSeries(labels, item.series, "daily_delta");
    const label = latestByMetric.get(item.metric)?.metric_label || item.metric;
    return chartDataset(label, values, index, "bar");
  });
  const hasSeries = labels.length > 0;
  totalChart = drawChart(totalChart, "totalChart", labels, totalDatasets, "line", normalize ? "Індекс (перше значення = 100)" : "Значення");
  deltaChart = drawChart(deltaChart, "deltaChart", labels, deltaDatasets, "bar", normalize ? "Зміна, %" : "Добова зміна");
  const comparison = latestMetrics.slice(0, 10);
  comparisonChart = drawChart(
    comparisonChart,
    "comparisonChart",
    comparison.map((item) => item.metric_label || item.metric),
    [chartDataset("Latest values", comparison.map((item) => item.value), 0, "bar")],
    "bar",
    "Значення",
  );

  if (!hasSeries && !(latestData.metrics || []).length) {
    document.getElementById("summary").innerHTML = '<article class="metric wide"><span>Дані ще не зібрані</span><strong>0</strong><small>Перевір source health і parser errors.</small></article>';
  } else {
    document.getElementById("summary").innerHTML = latestMetrics
      .slice(0, 8)
      .map(
        (item) => `
          <article class="metric">
            <span>${escapeHtml(item.metric_label || item.metric)}</span>
            <strong>${Number(item.value || 0).toLocaleString("uk-UA")}</strong>
            <small>${escapeHtml(item.observed_date || "")}${item.daily_delta ? ` ${signedNumber(item.daily_delta)}` : ""}</small>
          </article>
        `,
      )
      .join("");
  }

  document.getElementById("health").innerHTML = rows(healthData.health || [], [
    { key: "source_id", label: "Source" },
    { key: "status", label: "Status" },
    { key: "checked_at", label: "Checked" },
    { key: "message", label: "Message" },
  ]);
  document.getElementById("errors").innerHTML = rows(errorsData.errors || [], [
    { key: "source_id", label: "Source" },
    { key: "occurred_at", label: "Time" },
    { key: "error_type", label: "Type" },
    { key: "message", label: "Message" },
  ]);
  await loadSourceConfig();
}

async function loadSourceConfig() {
  const data = await getJson("/sources");
  document.getElementById("sourceConfig").innerHTML = (data.sources || [])
    .map(
      (source) => `
        <form class="source-row" data-source-id="${escapeHtml(source.id)}">
          <label>
            <input type="checkbox" name="enabled" ${source.enabled ? "checked" : ""} />
            ${escapeHtml(source.name)}
          </label>
          <input name="url" value="${escapeHtml(source.url)}" />
          <button type="submit">Save</button>
        </form>
      `,
    )
    .join("");
}

function refreshDashboard() {
  return loadDashboard().catch((error) => {
    document.getElementById("adminStatus").textContent = error.message;
  });
}

document.getElementById("refresh").addEventListener("click", refreshDashboard);

["dataset", "period", "start", "end", "normalize"].forEach((controlId) => {
  document.getElementById(controlId).addEventListener("change", refreshDashboard);
});

document.getElementById("metricPickerToggle").addEventListener("click", () => {
  const menu = document.getElementById("metricMenu");
  menu.hidden = !menu.hidden;
  document.getElementById("metricPickerToggle").setAttribute("aria-expanded", String(!menu.hidden));
});

document.getElementById("metricMenu").addEventListener("change", (event) => {
  if (event.target.type !== "checkbox") return;
  const checked = [...document.querySelectorAll('#metricMenu input[type="checkbox"]:checked')];
  if (!checked.length) {
    event.target.checked = true;
    return;
  }
  if (checked.length > chartColors.length) {
    event.target.checked = false;
    document.getElementById("adminStatus").textContent = `Можна порівнювати до ${chartColors.length} показників одночасно.`;
    return;
  }
  selectedMetrics = checked.map((input) => input.value);
  document.getElementById("metricCount").textContent = String(selectedMetrics.length);
  refreshDashboard();
});

document.getElementById("loginForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const response = await fetch(api("/admin/login"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: form.get("username"), password: form.get("password") }),
    credentials: "same-origin",
  });
  document.getElementById("adminStatus").textContent = response.ok ? "Admin session active" : "Login failed";
});

document.getElementById("reingest").addEventListener("click", async () => {
  const response = await fetch(api("/admin/reingest"), { method: "POST", credentials: "same-origin" });
  document.getElementById("adminStatus").textContent = response.ok ? "Reingest started" : "Reingest denied";
  if (response.ok) await loadDashboard();
});

document.getElementById("backfillMod").addEventListener("click", async () => {
  document.getElementById("adminStatus").textContent = "Backfill started";
  const response = await fetch(api("/admin/backfill/mod-losses"), { method: "POST", credentials: "same-origin" });
  document.getElementById("adminStatus").textContent = response.ok ? "MOD backfill completed" : "Backfill denied";
  if (response.ok) await loadDashboard();
});

document.getElementById("sourceConfig").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  const sourceId = form.dataset.sourceId;
  const body = {
    enabled: Boolean(form.elements.enabled.checked),
    url: form.elements.url.value,
  };
  const response = await fetch(api(`/admin/sources/${encodeURIComponent(sourceId)}`), {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    credentials: "same-origin",
  });
  document.getElementById("adminStatus").textContent = response.ok ? "Source saved" : "Source update denied";
  if (response.ok) await loadSourceConfig();
});

refreshDashboard();
