const api = (path) => `/osix/api/v1${path}`;

let totalChart;
let deltaChart;
let comparisonChart;

const metricPriority = [
  "personnel",
  "tanks",
  "armored_vehicles",
  "artillery_systems",
  "mlrs",
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

function serializeDate(value) {
  return value ? `&${value.name}=${encodeURIComponent(value.value)}` : "";
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

function orderedMetrics(metrics) {
  return [...metrics].sort((left, right) => {
    const leftIndex = metricPriority.indexOf(left.metric);
    const rightIndex = metricPriority.indexOf(right.metric);
    const leftRank = leftIndex === -1 ? metricPriority.length : leftIndex;
    const rightRank = rightIndex === -1 ? metricPriority.length : rightIndex;
    return leftRank - rightRank || String(left.metric).localeCompare(String(right.metric));
  });
}

function drawChart(existing, canvasId, labels, values, type, label) {
  if (existing) existing.destroy();
  const context = document.getElementById(canvasId);
  return new Chart(context, {
    type,
    data: {
      labels,
      datasets: [
        {
          label,
          data: values,
          borderColor: "#1677ff",
          backgroundColor: type === "bar" ? "#70a7ff" : "rgba(22, 119, 255, 0.12)",
          tension: 0.2,
          fill: type !== "bar",
        },
      ],
    },
    options: {
      animation: false,
      responsive: true,
      maintainAspectRatio: false,
      resizeDelay: 120,
      plugins: { legend: { display: false } },
      scales: { x: { ticks: { maxTicksLimit: 8 } }, y: { beginAtZero: true } },
    },
  });
}

async function loadDashboard() {
  const dataset = document.getElementById("dataset").value;
  const metric = document.getElementById("metric").value;
  const period = document.getElementById("period").value;
  const start = document.getElementById("start");
  const end = document.getElementById("end");
  const custom = period === "custom" ? `${serializeDate(start)}${serializeDate(end)}` : "";

  const [seriesData, latestData, healthData, errorsData] = await Promise.all([
    getJson(`/metrics/series?dataset=${encodeURIComponent(dataset)}&metric=${encodeURIComponent(metric)}&period=${encodeURIComponent(period)}${custom}`),
    getJson(`/metrics/latest?dataset=${encodeURIComponent(dataset)}`),
    getJson("/source-health"),
    getJson("/parser-errors"),
  ]);

  const series = seriesData.series || [];
  const hasSeries = series.length > 0;
  const labels = series.map((point) => String(point.observed_date));
  totalChart = drawChart(totalChart, "totalChart", labels, series.map((point) => point.value), "line", metric);
  deltaChart = drawChart(deltaChart, "deltaChart", labels, series.map((point) => point.daily_delta || 0), "bar", `${metric} delta`);
  const latestMetrics = orderedMetrics(latestData.metrics || []);
  const comparison = latestMetrics.slice(0, 10);
  comparisonChart = drawChart(
    comparisonChart,
    "comparisonChart",
    comparison.map((item) => item.metric_label || item.metric),
    comparison.map((item) => item.value),
    "bar",
    "Latest values",
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
            <small>${escapeHtml(item.observed_date || "")}${item.daily_delta ? ` +${Number(item.daily_delta).toLocaleString("uk-UA")}` : ""}</small>
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

document.getElementById("refresh").addEventListener("click", () => {
  loadDashboard().catch((error) => {
    document.getElementById("adminStatus").textContent = error.message;
  });
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

loadDashboard().catch((error) => {
  document.getElementById("adminStatus").textContent = error.message;
});
