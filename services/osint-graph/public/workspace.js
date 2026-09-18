(() => {
  "use strict";
  const $ = (s) => document.querySelector(s);
  const esc = (v) =>
    String(v ?? "").replace(
      /[&<>"']/g,
      (c) =>
        ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;",
        })[c],
    );
  const uk = window.OsintUk;
  const names = uk.entities;
  const relName = (r) =>
    r.metadata?.label ||
    uk.relationships[r.relationship_type] ||
    r.relationship_type;
  const plural = (n, forms) => uk.count(n, forms).replace(/^[\d\s ]+/, "");
  const glyph = (t) =>
    ({
      PERSON: "●",
      ORGANIZATION: "▣",
      SOCIAL_ACCOUNT: "◈",
      USERNAME: "@",
      EMAIL: "✉",
      PHONE: "☎",
      WEBSITE: "◎",
      DOMAIN: "⬡",
      LOCATION: "⌖",
      POST: "≡",
      DOCUMENT: "▤",
      IMAGE: "▧",
      EVENT: "□",
    })[t] || "◇";
  const shape = (t) =>
    ({
      PERSON: "ellipse",
      ORGANIZATION: "round-rectangle",
      SOCIAL_ACCOUNT: "diamond",
      DOMAIN: "hexagon",
      LOCATION: "pentagon",
      DOCUMENT: "rectangle",
      IMAGE: "rectangle",
      EVENT: "round-rectangle",
    })[t] || "ellipse";
  const state = {
    id: null,
    w: null,
    analysis: null,
    cy: null,
    view: "Graph",
    selected: null,
    hiddenLayers: new Set(),
    connect: null,
    positions: {},
    table: "entities",
    inspectorTab: "overview",
    saveQueue: new Map(),
    saveTimer: null,
    saving: false,
  };
  const recs = (kind) => state.w?.records.filter((r) => r.kind === kind) || [];
  const linked = (record, kind, id) =>
    record.links.some((l) => l.kind === kind && l.id === id);
  const sources = (kind, id) =>
    recs("source").filter((r) => linked(r, kind, id));
  const name = (id) =>
    state.w?.entities.find((e) => e.id === id)?.display_name || "—";
  const date = (v) =>
    v
      ? new Date(v).toLocaleString("uk-UA", {
          dateStyle: "medium",
          timeStyle: "short",
        })
      : "—";
  const badge = (status) =>
    `<span class="badge ${esc(status)}" title="${esc(uk.hints[status] || "")}">${esc(uk.statuses[status] || status)}</span>`;
  function toast(message) {
    $("#toast").textContent = message;
    $("#toast").hidden = false;
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => ($("#toast").hidden = true), 5500);
  }
  async function api(path, options = {}) {
    const response = await fetch("/osint/api" + path, {
      ...options,
      headers: {
        "x-osint-csrf": document.body.dataset.csrf,
        ...(options.body instanceof FormData
          ? {}
          : { "Content-Type": "application/json" }),
        ...options.headers,
      },
    });
    if (response.status === 401) {
      location.assign("/osint");
      throw Error("Потрібен вхід");
    }
    const data = await response.json();
    if (!response.ok) throw Error(uk.error(data.error));
    return data;
  }
  const route = (path) => `/investigations/${state.id}${path}`;
  const send = (path, body, method = "POST") =>
    api(route(path), { method, body: JSON.stringify(body) });
  function guarded(fn) {
    return (...args) =>
      Promise.resolve()
        .then(() => fn(...args))
        .catch((e) => toast(uk.error(e)));
  }
  function requireCase() {
    if (!state.id) {
      editCase();
      return false;
    }
    return true;
  }
  async function loadCases(selected = state.id) {
    const data = await api("/investigations");
    $("#cases").innerHTML =
      '<option value="">Оберіть розслідування</option>' +
      data.investigations
        .map((i) => `<option value="${i.id}">${esc(i.name)}</option>`)
        .join("");
    if (selected && data.investigations.some((i) => i.id === selected)) {
      $("#cases").value = selected;
      await openCase(selected);
    }
  }
  async function openCase(id) {
    await flushLayout();
    state.cy?.destroy();
    state.cy = null;
    state.id = id;
    state.selected = null;
    state.positions = {};
    state.hiddenLayers.clear();
    setConnect(null);
    resetFilters();
    $("#search").value = "";
    $("#inspector").innerHTML =
      '<div class="placeholder"><h2>Деталі та докази</h2><p>Оберіть сутність або зв’язок.</p></div>';
    await refresh();
  }
  async function refresh() {
    if (!state.id) return;
    const caseId = state.id;
    const data = await api(`/investigations/${caseId}/workspace`);
    if (caseId !== state.id) return;
    state.w = data.workspace;
    state.analysis = data.analysis;
    $("#caseTitle").textContent = state.w.investigation.name;
    renderStats();
    renderFilters();
    renderSidebar();
    renderGraph();
    renderView();
    if (state.selected) inspect(state.selected.kind, state.selected.id, false);
  }
  function renderStats() {
    const counts = [
      [state.w.entities.length, ["сутність", "сутності", "сутностей"]],
      [state.w.relationships.length, ["зв’язок", "зв’язки", "зв’язків"]],
      [
        recs("lead").filter(
          (r) => !["CONFIRMED", "DISMISSED"].includes(r.data.status),
        ).length,
        ["відкрита зачіпка", "відкриті зачіпки", "відкритих зачіпок"],
      ],
      [recs("source").length, ["доказ", "докази", "доказів"]],
    ];
    $("#stats").innerHTML = counts
      .map(
        ([n, forms]) =>
          `<span class="count-chip"><b>${new Intl.NumberFormat("uk-UA").format(n)}</b>${esc(plural(n, forms))}</span>`,
      )
      .join("");
  }
  function renderFilters() {
    for (const [id, values] of [
      [
        "typeFilter",
        [...new Set(state.w.entities.map((e) => e.type))].map((x) => [
          x,
          names[x] || x,
        ]),
      ],
      [
        "relationFilter",
        [...new Set(state.w.relationships.map((e) => e.relationship_type))].map(
          (x) => [x, uk.relationships[x] || x],
        ),
      ],
      ["sourceFilter", recs("source").map((r) => [r.id, r.data.title])],
    ]) {
      const el = $("#" + id),
        old = el.value;
      el.innerHTML =
        '<option value="">Усі</option>' +
        values
          .map(([v, t]) => `<option value="${esc(v)}">${esc(t)}</option>`)
          .join("");
      el.value = old;
    }
  }
  function passes(kind, item) {
    const search = $("#search").value.trim().toLowerCase(),
      type = $("#typeFilter").value,
      status = $("#statusFilter").value,
      rel = $("#relationFilter").value,
      evidence = $("#evidenceFilter").value,
      source = $("#sourceFilter").value,
      after = $("#dateFilter").value;
    if (kind === "entity" && type && item.type !== type) return false;
    if (
      kind === "relationship" &&
      ((status && item.epistemic_status !== status) ||
        (rel && item.relationship_type !== rel))
    )
      return false;
    if (search && $("#onlyMatches").checked && !matches(kind, item))
      return false;
    const count =
      sources(kind, item.id).length +
      (kind === "relationship"
        ? (item.evidence || []).filter((e) => /^https?:/.test(e.source_url))
            .length
        : 0);
    if ((evidence === "yes" && !count) || (evidence === "no" && count))
      return false;
    if (source && !sources(kind, item.id).some((r) => r.id === source))
      return false;
    if (
      after &&
      new Date(item.created_at || item.first_observed_at) < new Date(after)
    )
      return false;
    const memberships = recs("layer").filter((r) => linked(r, kind, item.id));
    if (
      memberships.length &&
      memberships.every((r) => state.hiddenLayers.has(r.id))
    )
      return false;
    return true;
  }
  function renderSidebar() {
    if (!state.w) return;
    $("#entityList").innerHTML =
      state.w.entities
        .filter((e) => passes("entity", e) && matches("entity", e))
        .map(
          (e) =>
            `<div class="entity-choice"><input type="checkbox" data-select-entity="${e.id}" aria-label="Вибрати: ${esc(e.display_name)}" ${state.cy?.getElementById(e.id).selected() ? "checked" : ""}><button class="list-row" data-inspect="entity" data-id="${e.id}"><span class="glyph">${glyph(e.type)}</span><span>${esc(e.display_name)}</span></button></div>`,
        )
        .join("") ||
      "<p class='empty-list'>Немає сутностей за цим запитом.</p>";
    $("#layers").innerHTML =
      recs("layer")
        .map(
          (r) =>
            `<div class="checkrow"><input type="checkbox" aria-label="${esc(r.data.title)}" data-layer="${r.id}" ${state.hiddenLayers.has(r.id) ? "" : "checked"}><span>${esc(r.data.title)}</span><button data-record="${r.id}" aria-label="Редагувати шар">⋯</button></div>`,
        )
        .join("") || "<small>Шари ще не створені</small>";
    $("#leadList").innerHTML =
      recs("lead")
        .filter((r) => !["CONFIRMED", "DISMISSED"].includes(r.data.status))
        .slice(0, 8)
        .map(
          (r) =>
            `<button class="list-row" data-inspect="lead" data-id="${r.id}"><span class="glyph">↗</span><span>${esc(r.data.title)}</span></button>`,
        )
        .join("") || "<small>Немає відкритих зачіпок</small>";
  }
  function renderGraph() {
    const previous = state.cy;
    const w = state.w;
    if (!w) return;
    const entities = w.entities;
    const groups = recs("group");
    const parent = new Map();
    groups.forEach((g) =>
      g.links.forEach((l) => {
        if (l.kind === "entity" && !parent.has(l.id)) parent.set(l.id, g.id);
      }),
    );
    const elements = [
      ...groups.map((g) => ({
        data: { id: g.id, label: g.data.title, group: true },
      })),
      ...entities.map((e, i) => ({
        data: {
          id: e.id,
          label: e.display_name,
          type: e.type,
          shape: shape(e.type),
          parent: parent.get(e.id),
        },
        position: state.positions[e.id] ||
          e.metadata.position || {
            x: 140 + (i % 5) * 170,
            y: 110 + Math.floor(i / 5) * 140,
          },
      })),
      ...w.relationships.map((r) => ({
        data: {
          id: r.id,
          source: r.source_entity_id,
          target: r.target_entity_id,
          label: relName(r),
          status: r.epistemic_status,
        },
      })),
    ];
    if (previous) {
      previous.batch(() => {
        const ids = new Set(elements.map((e) => e.data.id));
        previous
          .elements()
          .filter((e) => !ids.has(e.id()))
          .remove();
        for (const el of elements) {
          const node = previous.getElementById(el.data.id);
          if (!node.length) {
            previous.add(el);
            continue;
          }
          if (
            node.isNode() &&
            !el.data.group &&
            node.parent().id() !== el.data.parent
          )
            node.move({ parent: el.data.parent || null });
          if (
            node.isEdge() &&
            (node.source().id() !== el.data.source ||
              node.target().id() !== el.data.target)
          )
            node.move({ source: el.data.source, target: el.data.target });
          node.data(el.data);
        }
      });
      applyVisibility();
      selectionTools();
      return;
    }
    state.cy = cytoscape({
      container: $("#graph"),
      elements,
      layout: { name: "preset", fit: !previous, padding: 70 },
      boxSelectionEnabled: true,
      selectionType: "additive",
      minZoom: 0.12,
      maxZoom: 3,
      style: [
        {
          selector: "node",
          style: {
            "background-color": "#728d83",
            "border-color": "#aec1b8",
            "border-width": 1,
            width: 36,
            height: 36,
            shape: "data(shape)",
            label: "data(label)",
            color: "#cfd8d3",
            "font-size": 11,
            "min-zoomed-font-size": 8,
            "text-valign": "bottom",
            "text-margin-y": 9,
            "text-max-width": 130,
            "text-wrap": "ellipsis",
            "overlay-opacity": 0,
          },
        },
        {
          selector: ":parent",
          style: {
            "background-opacity": 0.08,
            "background-color": "#9fb9af",
            "border-style": "dashed",
            "border-color": "#53655e",
            shape: "round-rectangle",
            padding: 24,
            "text-valign": "top",
            "text-margin-y": -8,
            "font-size": 13,
          },
        },
        {
          selector: "edge",
          style: {
            width: 1.5,
            "line-color": "#849d92",
            "target-arrow-color": "#849d92",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "data(label)",
            "font-size": 9,
            "min-zoomed-font-size": 7,
            color: "#9daea5",
            "text-rotation": "autorotate",
            "text-background-color": "#111418",
            "text-background-opacity": 0.95,
            "text-background-padding": 3,
          },
        },
        {
          selector: 'edge[status="INFERENCE"]',
          style: {
            "line-style": "dashed",
            "line-color": "#b0a58d",
            "target-arrow-color": "#b0a58d",
          },
        },
        {
          selector: 'edge[status="HYPOTHESIS"]',
          style: {
            "line-style": "dotted",
            "line-color": "#9690a9",
            "target-arrow-color": "#9690a9",
          },
        },
        {
          selector: ":selected",
          style: {
            "border-width": 3,
            "border-color": "#d5eee4",
            "line-color": "#d5eee4",
            "target-arrow-color": "#d5eee4",
            width: 3,
          },
        },
        { selector: "node:selected", style: { width: 42, height: 42 } },
        { selector: ".filtered", style: { display: "none" } },
        {
          selector: ".search-match",
          style: {
            "border-color": "#f0e1a2",
            "border-width": 3,
            "line-color": "#f0e1a2",
          },
        },
      ],
    });
    if (!previous && state.cy.zoom() > 1.25) {
      state.cy.zoom(1.25);
      state.cy.center();
    }
    state.cy.on("tap", "node", (e) => {
      if (e.target.isParent()) {
        editRecord(state.w.records.find((r) => r.id === e.target.id()));
        return;
      }
      if (state.connect !== null) {
        if (!state.connect) setConnect(e.target.id());
        else if (state.connect !== e.target.id()) {
          const from = state.connect;
          setConnect(null);
          editRelationship(null, from, e.target.id());
        }
      } else inspect("entity", e.target.id());
    });
    state.cy.on("tap", "edge", (e) => inspect("relationship", e.target.id()));
    let lastTap = 0;
    state.cy.on("tap", (e) => {
      if (e.target !== state.cy) return;
      const now = Date.now();
      if (now - lastTap < 320) editEntity(null, { position: e.position });
      lastTap = now;
      $("#context").hidden = true;
    });
    state.cy.on("cxttap", "node", (e) => {
      if (!e.target.isParent()) context(e.target.id(), e.originalEvent);
    });
    state.cy.on("select unselect", selectionTools);
    state.cy.on("dragfree", "node", () =>
      queuePositions(state.cy.nodes().filter((n) => !n.isParent())),
    );
    let dragFrom = null;
    state.cy.on("mousedown", "node", (e) => {
      if (e.originalEvent?.shiftKey && !e.target.isParent()) {
        dragFrom = e.target.id();
        state.cy.nodes().ungrabify();
      }
    });
    state.cy.on("mouseup", (e) => {
      if (dragFrom) {
        const from = dragFrom;
        dragFrom = null;
        state.cy.nodes().grabify();
        if (
          e.target !== state.cy &&
          e.target.isNode() &&
          !e.target.isParent() &&
          e.target.id() !== from
        )
          editRelationship(null, from, e.target.id());
      }
    });
    applyVisibility();
    selectionTools();
  }
  function matches(kind, item) {
    const q = $("#search").value.trim().toLocaleLowerCase("uk");
    if (!q) return true;
    const data = [
      item.display_name,
      item.canonical_name,
      item.username,
      item.profile_url,
      item.explanation,
      item.metadata?.notes,
      item.metadata?.username,
      item.metadata?.url,
      item.metadata?.email,
      item.metadata?.phone,
      item.metadata?.aliases,
      kind === "relationship" ? relName(item) : names[item.type],
      ...recs("note")
        .filter((r) => linked(r, kind, item.id))
        .flatMap((r) => [r.data.title, r.data.description, r.data.notes]),
    ];
    return data.filter(Boolean).join(" ").toLocaleLowerCase("uk").includes(q);
  }
  function applyVisibility() {
    if (!state.cy || !state.w) return;
    const edges = state.w.relationships.filter((r) =>
      passes("relationship", r),
    );
    const edgeFilter = $("#statusFilter").value || $("#relationFilter").value;
    const endpoints = new Set(
      edges.flatMap((r) => [r.source_entity_id, r.target_entity_id]),
    );
    const ids = new Set(
      state.w.entities
        .filter((e) => (edgeFilter ? endpoints.has(e.id) : passes("entity", e)))
        .map((e) => e.id),
    );
    state.cy.batch(() => {
      for (const e of state.w.entities)
        state.cy
          .getElementById(e.id)
          .toggleClass("filtered", !ids.has(e.id))
          .toggleClass(
            "search-match",
            !!$("#search").value && matches("entity", e),
          );
      const allowedEdges = new Set(
        edges
          .filter(
            (r) => ids.has(r.source_entity_id) && ids.has(r.target_entity_id),
          )
          .map((r) => r.id),
      );
      for (const r of state.w.relationships)
        state.cy
          .getElementById(r.id)
          .toggleClass("filtered", !allowedEdges.has(r.id))
          .toggleClass(
            "search-match",
            !!$("#search").value && matches("relationship", r),
          );
      state.cy
        .nodes(":parent")
        .forEach((g) =>
          g.toggleClass(
            "filtered",
            !g.descendants().some((n) => !n.hasClass("filtered")),
          ),
        );
    });
    $("#empty").hidden = ids.size > 0 || state.view !== "Graph";
    $("#empty h2").textContent = state.w.entities.length
      ? "Немає збігів"
      : "Додайте першу сутність";
    $("#empty p").textContent = state.w.entities.length
      ? "Скиньте фільтри, щоб повернути об’єкти на карту."
      : "Подвійний клік на полотні або кнопка «Додати сутність».";
    $("#emptyCreate").textContent = state.w.entities.length
      ? "Скинути фільтри"
      : "Додати сутність";
    $("#filterCount").textContent =
      [
        "typeFilter",
        "relationFilter",
        "statusFilter",
        "evidenceFilter",
        "sourceFilter",
        "dateFilter",
      ].filter((id) => $("#" + id).value).length +
      state.hiddenLayers.size +
      Number($("#onlyMatches").checked);
  }
  function resetFilters() {
    for (const id of [
      "typeFilter",
      "relationFilter",
      "statusFilter",
      "evidenceFilter",
      "sourceFilter",
      "dateFilter",
    ])
      $("#" + id).value = "";
    $("#onlyMatches").checked = false;
    state.hiddenLayers.clear();
  }
  function selectionTools() {
    if (!state.cy) return;
    const n = state.cy.nodes(":selected").filter((n) => !n.isParent()).length;
    $("#selectionTools").hidden = n < 2;
    $("#selectionCount").textContent = `Вибрано: ${n}`;
    document
      .querySelectorAll("[data-select-entity]")
      .forEach(
        (c) =>
          (c.checked = state.cy
            .getElementById(c.dataset.selectEntity)
            .selected()),
      );
    $("#mergeSelected").disabled = n !== 2;
  }
  function setConnect(id) {
    state.connect = id;
    $("#connectHint").hidden = id === null;
    $("#connectMode").setAttribute("aria-pressed", String(id !== null));
    $("#connectHint span").textContent = id
      ? `Перша сутність: ${name(id)}. Оберіть другу.`
      : "Оберіть першу сутність на графі.";
  }
  function queuePositions(nodes) {
    nodes.forEach((n) => {
      const p = { id: n.id(), ...n.position() };
      state.positions[n.id()] = { x: p.x, y: p.y };
      state.saveQueue.set(n.id(), p);
    });
    $("#saveStatus").textContent = "Зберігається…";
    $("#saveStatus").classList.remove("failed");
    clearTimeout(state.saveTimer);
    state.saveTimer = setTimeout(() => flushLayout().catch(() => {}), 250);
  }
  async function flushLayout() {
    clearTimeout(state.saveTimer);
    if (state.saving) {
      await state.saving;
      if (state.saveQueue.size) return flushLayout();
      return;
    }
    if (!state.saveQueue.size) return;
    $("#saveStatus").textContent = "Зберігається…";
    $("#saveStatus").classList.remove("failed");
    const positions = [...state.saveQueue.values()],
      inv = state.id;
    state.saveQueue.clear();
    state.saving = api(`/investigations/${inv}/layout`, {
      method: "PATCH",
      body: JSON.stringify({ positions }),
    })
      .then(() => {
        for (const p of positions) {
          const e = state.w?.entities.find((e) => e.id === p.id);
          if (e) e.metadata.position = { x: p.x, y: p.y };
        }
        $("#saveStatus").textContent = state.saveQueue.size
          ? "Зберігається…"
          : "Збережено";
        $("#retryLayout").hidden = true;
      })
      .catch((e) => {
        for (const p of positions)
          if (!state.saveQueue.has(p.id)) state.saveQueue.set(p.id, p);
        $("#saveStatus").textContent = "Не вдалося зберегти";
        $("#saveStatus").classList.add("failed");
        $("#retryLayout").hidden = false;
        throw e;
      })
      .finally(() => {
        state.saving = false;
      });
    await state.saving;
  }
  function inspect(kind, id, reveal = true) {
    if (state.selected?.id !== id) state.inspectorTab = "overview";
    state.selected = { kind, id };
    const item =
      kind === "entity"
        ? state.w.entities.find((e) => e.id === id)
        : kind === "relationship"
          ? state.w.relationships.find((r) => r.id === id)
          : state.w.records.find((r) => r.id === id);
    if (!item) {
      state.selected = null;
      $("#inspector").innerHTML = '<p class="muted">Оберіть об’єкт</p>';
      return;
    }
    const title =
      kind === "entity"
        ? item.display_name
        : kind === "relationship"
          ? relName(item)
          : item.data.title;
    const notes =
      item.metadata?.notes || item.data?.notes || item.data?.description || "";
    const status = item.epistemic_status || item.data?.epistemic_status;
    const connected =
      kind === "entity"
        ? state.w.relationships.filter(
            (r) => r.source_entity_id === id || r.target_entity_id === id,
          )
        : [];
    const evidence = sources(kind, id);
    if (reveal) {
      document.querySelector(".shell").classList.remove("inspector-collapsed");
      document.querySelector(".shell").classList.add("inspector-open");
      document.querySelector(".shell").classList.remove("sidebar-open");
      $("#toggleInspector").setAttribute("aria-expanded", "true");
      $("#toggleSidebar").setAttribute("aria-expanded", "false");
    }
    $("#inspector").innerHTML =
      `<section data-inspector-section="overview"><p class="eyebrow">${esc(kind === "entity" ? names[item.type] || item.type : uk.kinds[kind])}</p><h2>${esc(title)}</h2><div class="sub">${status ? badge(status) : ""} ${item.confidence != null ? `Впевненість ${Math.round(item.confidence * 100)}%` : ""}</div>${kind === "relationship" ? `<p>${esc(name(item.source_entity_id))} → ${esc(name(item.target_entity_id))}</p>` : ""}<div class="sub">Створено ${date(item.created_at || item.first_observed_at)}<br>Автор: ${esc(item.created_by || "Імпорт / попередня версія")}</div><p>${esc(item.explanation || "")}</p><p>${esc(notes)}</p>${kind === "entity" ? `<div class="sub">${esc(item.metadata.platform || item.platform || "")} ${esc(item.metadata.username || item.username || "")}<br>${urlLink(item.metadata.url || item.profile_url)}</div>` : ""}<div class="actions"><button data-edit-selected>Редагувати</button>${kind === "entity" ? "<button data-connect>З’єднати</button><button data-duplicate>Дублювати</button>" : ""}<button data-add-linked="source">＋ Доказ</button><button data-add-linked="note">＋ Нотатка</button><button data-add-linked="lead">＋ Зачіпка</button><button class="danger" data-delete-selected>Видалити</button></div>${kind === "lead" ? `<div class="actions"><button data-lead-entity>Створити сутність</button><button data-lead-relationship>Створити зв’язок</button><button data-lead-state="CONFIRMED">Підтвердити</button><button data-lead-state="DISMISSED">Відхилити</button><button data-lead-state="INVESTIGATING">Повернути в роботу</button></div><p>${esc(uk.leads[item.data.status])} · ${esc(uk.priorities[item.data.priority])}</p>` : ""}</section><section data-inspector-section="evidence"><h3>Джерела та докази · ${evidence.length}</h3>${evidence.map(sourceCard).join("") || '<p class="muted">Джерела ще не прикріплені.</p>'}${(item.evidence || []).map((e) => `<div class="evidence-item">${urlLink(e.source_url)}<small>${esc(e.collector)} · ${date(e.observed_at)}</small></div>`).join("")}</section><section data-inspector-section="notes"><h3>Нотатки</h3>${
        recs("note")
          .filter((r) => linked(r, kind, id))
          .map(
            (r) =>
              `<div class="evidence-item"><button data-record="${r.id}">${esc(r.data.title)}</button><p>${esc(r.data.description)}</p></div>`,
          )
          .join("") || "<small>Нотаток поки немає.</small>"
      }</section><section data-inspector-section="connections"><h3>Пов’язані сутності</h3>${connected.map((r) => `<button class="list-row" data-inspect="relationship" data-id="${r.id}">${badge(r.epistemic_status)} ${esc(name(r.source_entity_id === id ? r.target_entity_id : r.source_entity_id))}</button>`).join("")}${kind === "relationship" ? [item.source_entity_id, item.target_entity_id].map((e) => `<button class="list-row" data-inspect="entity" data-id="${e}">${esc(name(e))}</button>`).join("") : ""}${
        kind === "lead"
          ? item.links
              .filter((l) => l.kind === "entity")
              .map(
                (l) =>
                  `<button class="list-row" data-inspect="entity" data-id="${l.id}">${esc(name(l.id))}</button>`,
              )
              .join("")
          : ""
      }<h3>Зачіпки</h3>${recs("lead")
        .filter((r) => linked(r, kind, id))
        .map(
          (r) =>
            `<button class="list-row" data-inspect="lead" data-id="${r.id}">${esc(r.data.title)} · ${esc(uk.leads[r.data.status])}</button>`,
        )
        .join("")}</section>`;
    inspectorTabs();
  }
  function inspectorTabs() {
    document
      .querySelectorAll("[data-inspector-section]")
      .forEach(
        (e) => (e.hidden = e.dataset.inspectorSection !== state.inspectorTab),
      );
    document
      .querySelectorAll("[data-inspector-tab]")
      .forEach((e) =>
        e.classList.toggle(
          "active",
          e.dataset.inspectorTab === state.inspectorTab,
        ),
      );
  }
  function urlLink(value) {
    try {
      const u = new URL(value);
      if (["https:", "http:"].includes(u.protocol))
        return `<a href="${esc(u.href)}" target="_blank" rel="noopener noreferrer">${esc(u.hostname + u.pathname)}</a>`;
    } catch {}
    return "";
  }
  function sourceCard(r) {
    return `<div class="evidence-item"><button data-record="${r.id}">${esc(r.data.title)}</button> ${badge(r.data.epistemic_status || "FACT")}<p>${esc(r.data.quote || r.data.description || "")}</p>${urlLink(r.data.url)}${r.file_name ? `<p><a href="/osint/api${route("/sources/" + r.id + "/file")}">↓ ${esc(r.file_name)}</a> ${/\.(png|jpe?g|webp)$/i.test(r.file_name) ? `<button data-preview="${r.id}">Переглянути зображення</button>` : ""}</p>` : ""}<small>${date(r.data.observed_at || r.created_at)} · Автор ${esc(r.data.author || r.created_by)}</small>${r.data.merge_snapshot || r.data.entity_origins || r.data.legacy_raw_data || r.data.legacy_metadata ? `<details><summary>Походження запису</summary><pre>${esc(JSON.stringify(r.data.merge_snapshot || r.data, null, 2))}</pre></details>` : ""}</div>`;
  }
  function renderView() {
    const graph = state.view === "Graph";
    $("#graph").hidden = !graph;
    $("#graphFooter").hidden = !graph;
    $("#viewContent").hidden = graph;
    $("#empty").hidden = !graph || !!state.w?.entities.length;
    document
      .querySelectorAll("[data-view]")
      .forEach((b) =>
        b.classList.toggle("active", b.dataset.view === state.view),
      );
    if (graph) {
      applyVisibility();
      state.cy?.resize();
      return;
    }
    if (!state.w) {
      $("#viewContent").innerHTML =
        "<p>Створіть або оберіть розслідування.</p>";
      return;
    }
    const el = $("#viewContent");
    if (state.view === "Table") {
      const entities = state.table === "entities";
      const rows = entities
        ? state.w.entities.filter((e) => passes("entity", e))
        : state.w.relationships.filter((r) => passes("relationship", r));
      el.innerHTML = `<div class="view-head"><h2>Таблиця</h2><div><button data-table="entities">Сутності</button> <button data-table="relationships">Зв’язки</button></div></div><table><thead><tr>${(entities ? ["Тип", "Назва", "Ідентифікатори", "Зв’язки", "Джерела", "Нотатки", "Створено"] : ["Від → До", "Тип", "Статус", "Впевненість", "Джерела", "Нотатки", "Створено"]).map((h) => `<th>${h}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr tabindex="0" role="button" data-inspect="${entities ? "entity" : "relationship"}" data-id="${r.id}">${(entities ? [names[r.type] || r.type, r.display_name, [r.metadata.username || r.username, r.metadata.url || r.profile_url, r.canonical_name].filter(Boolean).join(" · "), state.w.relationships.filter((x) => x.source_entity_id === r.id || x.target_entity_id === r.id).length, sources("entity", r.id).length, r.metadata.notes, date(r.created_at)] : [`${name(r.source_entity_id)} → ${name(r.target_entity_id)}`, relName(r), uk.statuses[r.epistemic_status], Math.round(r.confidence * 100) + "%", sources("relationship", r.id).length + (r.evidence?.length || 0), r.metadata.notes || r.explanation, date(r.created_at || r.first_observed_at)]).map((v) => `<td>${esc(v)}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
    } else if (state.view === "Timeline") {
      const items = [];
      for (const [kind, list] of [
        ["entity", state.w.entities],
        ["relationship", state.w.relationships],
        ["source", recs("source")],
      ])
        for (const r of list) {
          const d = r.metadata || r.data || {};
          let count = 0;
          for (const field of [
            "event_date",
            "valid_from",
            "valid_to",
            "observed_at",
          ])
            if (d[field]) {
              items.push({ kind, r, field, time: d[field] });
              count++;
            }
          if (!count)
            items.push({
              kind,
              r,
              field: "created_at",
              time: r.created_at || r.first_observed_at,
            });
        }
      items.sort((a, b) => new Date(a.time) - new Date(b.time));
      el.innerHTML =
        '<div class="view-head"><h2>Хронологія</h2><small>Події, спостереження та зміни</small></div>' +
        items
          .map(
            ({ kind, r, field, time }) =>
              `<div class="timeline-row"><small>${date(time)} · ${esc(uk.dates[field] || field)}</small><button ${kind === "source" ? `data-record="${r.id}"` : `data-inspect="${kind}" data-id="${r.id}"`}>${esc(r.display_name || r.data?.title || relName(r))}</button> ${r.epistemic_status ? badge(r.epistemic_status) : ""}</div>`,
          )
          .join("");
    } else if (["Evidence", "Leads", "Notes"].includes(state.view)) {
      const kind = { Evidence: "source", Leads: "lead", Notes: "note" }[
        state.view
      ];
      const query = $("#search").value.trim().toLowerCase();
      el.innerHTML =
        `<div class="view-head"><h2>${uk.views[state.view]}</h2><button data-action="${kind}" class="primary">＋ Додати</button></div>` +
        recs(kind)
          .filter(
            (r) =>
              !query || JSON.stringify(r.data).toLowerCase().includes(query),
          )
          .map((r) =>
            kind === "source"
              ? sourceCard(r)
              : `<div class="record-row"><div class="content"><h2>${esc(r.data.title)}</h2><p>${esc(r.data.description)}</p><small>${esc(uk.leads[r.data.status] || "")} ${esc(uk.priorities[r.data.priority] || "")} · ${date(r.created_at)}</small><p>${r.links
                  .filter((l) => l.kind === "entity")
                  .map((l) => esc(name(l.id)))
                  .join(
                    " · ",
                  )}</p></div><button ${kind === "lead" ? `data-inspect="lead" data-id="${r.id}"` : `data-record="${r.id}"`}>Відкрити</button></div>`,
          )
          .join("");
      if (!el.querySelector(".evidence-item,.record-row"))
        el.innerHTML +=
          '<p class="empty-list">Записів поки немає або вони не відповідають пошуку. Додайте запис чи змініть запит.</p>';
    } else if (state.view === "Analysis") {
      const a = state.analysis;
      el.innerHTML = `<div class="view-head"><h2>Аналіз</h2><button id="runAnalysis">Зберегти аналіз</button></div><p class="muted">Структура поточного графа. Центральність не підтверджує гіпотези чи особисті зв’язки.</p><h3>Шлях та спільні сусіди</h3><div class="pair"><label>Від<select id="pathFrom">${entityOptions()}</select></label><label>До<select id="pathTo">${entityOptions()}</select></label></div><button id="findPath">Знайти</button><p id="pathResult"></p><h3>Центральність за кількістю зв’язків</h3><table><thead><tr><th>Сутність</th><th>Сусіди</th><th>Центральність</th></tr></thead><tbody>${(a.metrics || []).map((m) => `<tr tabindex="0" role="button" data-inspect="entity" data-id="${m.entityId}"><td>${esc(name(m.entityId))}</td><td>${m.degree}</td><td>${esc(new Intl.NumberFormat("uk-UA", { minimumFractionDigits: 3, maximumFractionDigits: 3 }).format(m.degree / Math.max(1, state.w.entities.length - 1)))}</td></tr>`).join("")}</tbody></table><h3>Вузли, що з’єднують частини графа</h3><p>${(a.bridgeEntityIds || []).map(name).map(esc).join(" · ") || "Немає"}</p><h3>Компоненти зв’язності</h3><p>${(a.connectedComponents || []).map((ids) => ids.map(name).map(esc).join(" · ")).join("<br>")}</p><h3>Спільноти</h3>${Object.entries(
        a.communities || {},
      )
        .map(
          ([id, c]) =>
            `<p>${esc(name(id))} · Спільнота ${esc(c.split("-").pop())}</p>`,
        )
        .join("")}`;
      el.innerHTML +=
        "<h3>Збережені висновки</h3>" +
        (state.w.findings || [])
          .map(
            (f) =>
              `<div class="record-row"><div class="content"><strong>${esc(f.title)}</strong><p>${esc(f.explanation)}</p><small>${date(f.created_at)} · структурний аналіз</small></div></div>`,
          )
          .join("");
    }
  }
  const options = (values, selected) =>
    values
      .map((x) => {
        const [v, t] = Array.isArray(x)
          ? x
          : [x, uk.statuses[x] || uk.leads[x] || uk.priorities[x] || x];
        return `<option value="${esc(v)}" ${String(v) === String(selected) ? "selected" : ""}>${esc(t)}</option>`;
      })
      .join("");
  const input = (label, key, value = "", type = "text", required = false) =>
    `<label>${label}<input name="${key}" type="${type}" value="${esc(value)}" ${required ? "required" : ""} ${type === "text" ? 'maxlength="500"' : ""}></label>`;
  const area = (label, key, value = "") =>
    `<label>${label}<textarea name="${key}" maxlength="4000">${esc(value)}</textarea></label>`;
  const select = (label, key, values, value) =>
    `<label>${label}<select name="${key}">${options(values, value)}</select></label>`;
  const entityOptions = (selected) =>
    options(
      state.w?.entities.map((e) => [e.id, e.display_name]) || [],
      selected,
    );
  const multi = (label, key, values, selected = []) =>
    `<fieldset class="picker" data-picker="${key}"><legend>${label}</legend><input type="search" placeholder="Знайти у списку" aria-label="Пошук: ${label}"><div class="chosen"></div><div class="picker-options">${values.map(([v, t]) => `<label><input type="checkbox" name="${key}" value="${esc(v)}" ${selected.includes(v) ? "checked" : ""}>${esc(t)}</label>`).join("")}</div></fieldset>`;
  function updatePickers() {
    document.querySelectorAll(".picker").forEach((p) => {
      const q = p
        .querySelector("input[type=search]")
        .value.toLocaleLowerCase("uk");
      p.querySelectorAll(".picker-options label").forEach(
        (l) => (l.hidden = !l.textContent.toLocaleLowerCase("uk").includes(q)),
      );
      p.querySelector(".chosen").textContent =
        [...p.querySelectorAll("input:checked")]
          .map((c) => c.parentElement.textContent)
          .join(" · ") || "Нічого не вибрано";
    });
  }
  function typePicker(dictionary, value) {
    return `<div class="type-picker"><label>Пошук типу<input type="search" data-type-search placeholder="Почніть вводити назву"></label><label>Тип<select name="type">${options([...Object.entries(dictionary), ["__custom", "Власний тип"]], dictionary[value] ? value : "__custom")}</select></label><label data-custom-type ${dictionary[value] ? "hidden" : ""}>Власний тип<input name="custom_type" ${dictionary[value] ? "" : "required"} maxlength="80" value="${esc(dictionary[value] ? "" : value)}"></label></div>`;
  }
  function entityFields() {
    const type = $("#fields select[name=type]")?.value;
    for (const key of ["platform", "username", "url"]) {
      const el = $("#fields input[name=" + key + "]");
      if (!el) continue;
      const label = el.closest("label");
      if (key === "platform")
        label.hidden = !["SOCIAL_ACCOUNT", "PUBLIC_CHANNEL"].includes(type);
      if (key === "username") {
        label.hidden = ![
          "SOCIAL_ACCOUNT",
          "PUBLIC_CHANNEL",
          "USERNAME",
          "EMAIL",
          "PHONE",
        ].includes(type);
        label.firstChild.textContent =
          type === "EMAIL"
            ? "Адреса електронної пошти"
            : type === "PHONE"
              ? "Номер телефону"
              : "Ім’я користувача";
      }
      if (key === "url")
        label.hidden = ![
          "SOCIAL_ACCOUNT",
          "PUBLIC_CHANNEL",
          "WEBSITE",
          "DOMAIN",
          "POST",
          "DOCUMENT",
          "IMAGE",
        ].includes(type);
    }
  }
  function dates(d = {}) {
    return (
      '<details class="form-extra"><summary>Дати й час</summary><p class="muted">Час показано в часовому поясі пристрою. Незмінені дати зберігають початкову точність.</p>' +
      Object.keys(uk.dates)
        .filter((k) => k !== "created_at")
        .map((k) => {
          const original = d[k] || "";
          const dt = original ? new Date(original) : null;
          const local =
            dt && !isNaN(dt)
              ? new Date(dt.getTime() - dt.getTimezoneOffset() * 60000)
                  .toISOString()
                  .slice(0, 23)
              : "";
          return `<label>${uk.dates[k]}<input type="datetime-local" step="0.001" name="${k}" value="${local}" data-initial="${local}" data-original-date="${esc(original)}"></label>`;
        })
        .join("") +
      "</details>"
    );
  }
  let draftStack = [],
    draftBaseline = "",
    returnFocus = null,
    editorBusy = false;
  const fingerprint = () =>
    JSON.stringify(
      [...new FormData($("#editorForm"))].map(([k, v]) => [
        k,
        v instanceof File ? [v.name, v.size, v.lastModified] : v,
      ]),
    );
  function askConfirm(title, text) {
    return new Promise((resolve) => {
      const d = $("#confirmDialog");
      $("#confirmTitle").textContent = title;
      $("#confirmText").textContent = text;
      const done = (value) => {
        d.close();
        resolve(value);
      };
      $("#confirmYes").onclick = () => done(true);
      $("#confirmNo").onclick = () => done(false);
      d.oncancel = (e) => {
        e.preventDefault();
        done(false);
      };
      d.showModal();
    });
  }
  function finishEditor(sourceId) {
    if (draftStack.length) {
      const d = draftStack.pop();
      $("#fields").replaceChildren(...d.nodes);
      $("#editorTitle").textContent = d.title;
      $("#editorForm").onsubmit = d.submit;
      $("#formError").textContent = d.error;
      draftBaseline = d.baseline;
      if (sourceId) {
        const picker = $("[data-picker=source_ids]");
        if (picker) {
          const selected = [...picker.querySelectorAll("input:checked")].map(
            (e) => e.value,
          );
          selected.push(sourceId);
          picker.outerHTML = multi(
            "Прикріпити джерела",
            "source_ids",
            recs("source").map((r) => [r.id, r.data.title]),
            selected,
          );
        }
      }
      updatePickers();
      d.focus?.focus();
      return;
    }
    $("#editor").close();
    (returnFocus?.isConnected && returnFocus.getClientRects().length
      ? returnFocus
      : $("#inspector [data-edit-selected]") || $(".tools [data-action=entity]")
    )?.focus();
  }
  async function closeEditor() {
    if (editorBusy) {
      toast("Зачекайте завершення збереження.");
      return;
    }
    if (
      fingerprint() !== draftBaseline &&
      !(await askConfirm(
        "Відкинути чернетку?",
        "Незбережені зміни цієї форми буде втрачено.",
      ))
    )
      return;
    finishEditor();
  }
  function dialog(title, html, save) {
    if (!$("#editor").open) returnFocus = document.activeElement;
    $("#editorTitle").textContent = title;
    $("#fields").innerHTML = html;
    $("#formError").textContent = "";
    $("#editorForm button[type=submit]").textContent = "Зберегти";
    document
      .querySelectorAll("[data-original-date]")
      .forEach((i) => (i.dataset.initial = i.value));
    draftBaseline = fingerprint();
    updatePickers();
    $(
      "#fields input:not([type=hidden]),#fields select,#fields textarea",
    )?.focus();
    $("#editorForm").onsubmit = async (e) => {
      e.preventDefault();
      const button = e.submitter || $("#editorForm button[type=submit]");
      if (editorBusy) return;
      editorBusy = true;
      button.disabled = true;
      try {
        const f = new FormData(e.target);
        document
          .querySelectorAll("[data-original-date]")
          .forEach((i) =>
            f.set(
              i.name,
              i.value === i.dataset.initial
                ? i.dataset.originalDate
                : i.value
                  ? new Date(i.value).toISOString()
                  : "",
            ),
          );
        if (f.get("type") === "__custom") f.set("type", f.get("custom_type"));
        f.delete("custom_type");
        const result = await save(f);
        finishEditor(result);
      } catch (error) {
        $("#formError").textContent = uk.error(error);
      } finally {
        editorBusy = false;
        button.disabled = false;
      }
    };
    if (!$("#editor").open) $("#editor").showModal();
    $(
      "#fields input:not([type=hidden]),#fields select,#fields textarea",
    )?.focus();
  }
  function editCase(existing = false) {
    const i = existing ? state.w?.investigation : null;
    dialog(
      i ? "Розслідування" : "Нове розслідування",
      input("Назва", "name", i?.name || "", "text", true) +
        area("Опис", "description", i?.description || "") +
        (i
          ? '<button type="button" class="danger" id="deleteCase">Видалити розслідування</button>'
          : ""),
      async (f) => {
        const d = Object.fromEntries(f);
        const result = i
          ? await send("", d, "PATCH")
          : await api("/investigations", {
              method: "POST",
              body: JSON.stringify(d),
            });
        await loadCases(result.investigation.id);
      },
    );
  }
  function editEntity(item = null, preset = {}, lead = null) {
    if (!requireCase()) return;
    const d = item?.metadata || preset;
    dialog(
      item ? "Редагувати сутність" : "Нова сутність",
      typePicker(uk.entities, item?.type || "PERSON") +
        input(
          "Назва",
          "display_name",
          item?.display_name || preset.title || "",
          "text",
          true,
        ) +
        input(
          "Платформа (для акаунта)",
          "platform",
          d.platform || item?.platform || "",
        ) +
        input(
          "Ім’я користувача, адреса пошти або телефон",
          "username",
          d.username || item?.username || "",
        ) +
        input("Посилання", "url", d.url || item?.profile_url || "", "url") +
        '<details class="form-extra"><summary>Додаткові відомості</summary>' +
        area("Нотатки", "notes", d.notes || "") +
        "</details>" +
        dates(d),
      async (f) => {
        const body = Object.fromEntries(f);
        body.metadata = {
          ...d,
          ...Object.fromEntries(
            ["event_date", "valid_from", "valid_to", "observed_at"].map((k) => [
              k,
              body[k],
            ]),
          ),
        };
        if (item) body.canonical_name = item.canonical_name;
        const result = await send(
          item ? "/entities/" + item.id : "/manual/entities",
          body,
          item ? "PATCH" : "POST",
        );
        if (lead) await linkLead(lead, "entity", result.entity.id);
        await refresh();
        inspect("entity", result.entity.id);
      },
    );
    entityFields();
  }
  function editRelationship(item = null, from = null, to = null, lead = null) {
    if (!requireCase()) return;
    if (state.w.entities.length < 2) {
      toast("Додайте щонайменше дві сутності");
      return;
    }
    const d = item?.metadata || {};
    dialog(
      item ? "Редагувати зв’язок" : "Новий зв’язок",
      `<div class="pair"><label>Від<select name="source">${entityOptions(item?.source_entity_id || from)}</select></label><label>До<select name="target">${entityOptions(item?.target_entity_id || to || state.w.entities.find((e) => e.id !== (from || state.w.entities[0].id))?.id)}</select></label></div>` +
        typePicker(uk.relationships, item?.relationship_type || "RELATED_TO") +
        input("Власна назва зв’язку", "label", d.label || "") +
        '<div class="pair">' +
        select(
          "Статус",
          "epistemic_status",
          ["FACT", "INFERENCE", "HYPOTHESIS"],
          item?.epistemic_status || "HYPOTHESIS",
        ) +
        `<label>Впевненість аналітика, %<input type="number" min="0" max="100" step="any" name="confidence" value="${Number(((item?.confidence ?? 0.5) * 100).toFixed(10))}" required></label></div>` +
        '<p class="muted">Оцінка впевненості не перетворює гіпотезу на факт. Для факту потрібне джерело або опис безпосереднього спостереження. Аналітичний висновок — інтерпретація відомостей; гіпотеза — припущення для перевірки.</p>' +
        area(
          "Підстава / безпосереднє спостереження",
          "explanation",
          item?.explanation || "",
        ) +
        area("Нотатки", "notes", d.notes || "") +
        multi(
          "Прикріпити джерела",
          "source_ids",
          recs("source").map((r) => [r.id, r.data.title]),
          item ? sources("relationship", item.id).map((r) => r.id) : [],
        ) +
        '<button type="button" id="inlineSource">＋ Створити джерело</button>' +
        dates(d),
      async (f) => {
        const body = Object.fromEntries(f);
        body.confidence = Number(body.confidence) / 100;
        body.source_ids = f.getAll("source_ids");
        body.metadata = d;
        const result = await send(
          item ? "/relationships/" + item.id : "/relationships",
          body,
          item ? "PATCH" : "POST",
        );
        if (lead) await linkLead(lead, "relationship", result.relationship.id);
        await refresh();
        inspect("relationship", result.relationship.id);
      },
    );
  }
  async function linkLead(lead, kind, id) {
    await send(
      "/records/" + lead.id,
      { links: [...lead.links, { kind, id }] },
      "PATCH",
    );
    for (const r of [
      ...sources("lead", lead.id),
      ...recs("note").filter((n) => linked(n, "lead", lead.id)),
    ])
      await send(
        "/records/" + r.id,
        { links: [...r.links, { kind, id }] },
        "PATCH",
      );
  }
  function editRecord(record = null, kind = "note", target = null) {
    if (!requireCase()) return;
    kind = record?.kind || kind;
    const d = record?.data || {};
    const allTargets = [
      ...state.w.entities.map((e) => ["entity:" + e.id, e.display_name]),
      ...state.w.relationships.map((r) => [
        "relationship:" + r.id,
        `${name(r.source_entity_id)} → ${name(r.target_entity_id)} · ${relName(r)}`,
      ]),
      ...recs("lead")
        .filter((r) => r.id !== record?.id)
        .map((r) => ["lead:" + r.id, "Зачіпка: " + r.data.title]),
    ];
    const current = record?.links || (target ? [target] : []);
    let html =
      input("Назва", "title", d.title || "", "text", true) +
      area("Опис", "description", d.description || "");
    if (kind === "source")
      html +=
        input("Посилання", "url", d.url || "", "url") +
        area("Цитата", "quote", d.quote || "") +
        input("Автор джерела", "author", d.author || "") +
        select(
          "Статус спостереження",
          "epistemic_status",
          ["FACT", "INFERENCE", "HYPOTHESIS"],
          d.epistemic_status || "FACT",
        ) +
        `<label>Файл / знімок екрана (до 10 МіБ)<input type="file" name="file"></label>${record?.file_name ? `<small>Збережено: ${esc(record.file_name)}</small>` : ""}` +
        dates(d);
    if (kind === "lead")
      html +=
        '<div class="pair">' +
        select(
          "Статус",
          "status",
          ["NEW", "TO_CHECK", "INVESTIGATING", "CONFIRMED", "DISMISSED"],
          d.status || "NEW",
        ) +
        select(
          "Пріоритет",
          "priority",
          ["LOW", "MEDIUM", "HIGH"],
          d.priority || "MEDIUM",
        ) +
        "</div>" +
        input("Джерело / URL", "url", d.url || "", "url");
    html +=
      area("Нотатки", "notes", d.notes || "") +
      multi(
        kind === "group" ? "Сутності групи" : "Пов’язані об’єкти",
        "links",
        kind === "group"
          ? allTargets.filter(([v]) => v.startsWith("entity:"))
          : allTargets,
        current.map((l) => l.kind + ":" + l.id),
      );
    if (record)
      html += `<button type="button" class="danger" data-delete-record="${record.id}">Видалити</button>`;
    let savedBody = null;
    dialog(
      {
        source: "Джерело / доказ",
        lead: "Зачіпка",
        note: "Нотатка",
        layer: "Шар",
        group: "Візуальна група",
      }[kind],
      html,
      async (f) => {
        const data = Object.fromEntries(f);
        delete data.links;
        delete data.file;
        const body = {
          kind,
          data,
          links: f.getAll("links").map((v) => {
            const [kind, id] = v.split(":");
            return { kind, id };
          }),
        };
        const result =
          savedBody === JSON.stringify(body)
            ? { record }
            : await send(
                record ? "/records/" + record.id : "/records",
                body,
                record ? "PATCH" : "POST",
              );
        record = result.record;
        savedBody = JSON.stringify(body);
        const file = f.get("file");
        if (file?.size) {
          const fd = new FormData();
          fd.append("file", file);
          await api(route("/sources/" + result.record.id + "/file"), {
            method: "POST",
            body: fd,
          });
        }
        await refresh();
        if (kind === "lead") inspect("lead", result.record.id);
        return kind === "source" ? result.record.id : null;
      },
    );
  }
  function context(id, event) {
    state.selected = { kind: "entity", id };
    const el = $("#context");
    el.innerHTML = [
      ["edit", "Редагувати"],
      ["connect", "З’єднати"],
      ["lead", "Додати зачіпку"],
      ["source", "Додати доказ"],
      ["note", "Додати нотатку"],
      ["duplicate", "Дублювати"],
      ["delete", "Видалити"],
    ]
      .map(([a, t]) => `<button data-context="${a}">${t}</button>`)
      .join("");
    el.style.left = Math.min(event.clientX, innerWidth - 185) + "px";
    el.style.top = Math.min(event.clientY, innerHeight - 290) + "px";
    el.hidden = false;
  }
  function selectedItem() {
    const s = state.selected;
    return s?.kind === "entity"
      ? state.w.entities.find((e) => e.id === s.id)
      : s?.kind === "relationship"
        ? state.w.relationships.find((r) => r.id === s.id)
        : state.w.records.find((r) => r.id === s?.id);
  }
  async function deleteSelected() {
    const s = state.selected;
    if (
      !s ||
      !(await askConfirm(
        "Видалити «" +
          (selectedItem()?.display_name ||
            selectedItem()?.data?.title ||
            relName(selectedItem())) +
          "»?",
        "Об’єкт і його прив’язки буде видалено. Джерела залишаться в розділі «Докази».",
      ))
    )
      return;
    await flushLayout();
    await send(
      s.kind === "entity"
        ? "/entities/" + s.id
        : s.kind === "relationship"
          ? "/relationships/" + s.id
          : "/records/" + s.id,
      {},
      "DELETE",
    );
    await refresh();
  }
  function editSelected() {
    const item = selectedItem();
    if (!item) return;
    if (state.selected.kind === "entity") editEntity(item);
    else if (state.selected.kind === "relationship") editRelationship(item);
    else editRecord(item);
  }
  function duplicate() {
    const item = selectedItem();
    if (item)
      editEntity(null, {
        ...item.metadata,
        title: item.display_name + " (копія)",
      });
  }
  async function merge() {
    if (!requireCase()) return;
    await flushLayout();
    const selected = state.cy
      .nodes(":selected")
      .filter((n) => !n.isParent())
      .map((n) => n.id());
    if (selected.length !== 2) {
      toast("Оберіть рівно дві сутності на графі.");
      return;
    }
    dialog(
      "Об’єднати дублікати",
      `<p class="muted">Першу сутність буде приєднано до другої. Спочатку перегляньте зміни.</p><label>Дублікат<select name="from">${entityOptions(selected[0])}</select></label><label>Зберегти<select name="to">${entityOptions(selected[1])}</select></label><button type="button" id="previewMerge">Переглянути зміни</button><div id="mergePreview"></div>`,
      async (f) => {
        const body = Object.fromEntries(f);
        if ($("#mergePreview").dataset.key !== JSON.stringify(body))
          throw Error("Спочатку перегляньте зміни для вибраної пари");
        await send("/merge", body);
        state.selected = null;
        $("#inspector").innerHTML =
          '<p class="muted">Оберіть сутність або зв’язок.</p>';
        await refresh();
        toast("Сутності об’єднано; походження даних збережено");
      },
    );
    $("#editorForm button[type=submit]").textContent = "Об’єднати";
  }
  function action(a) {
    if (a === "entity") editEntity();
    else if (a === "relationship") editRelationship();
    else editRecord(null, a);
  }
  document.addEventListener(
    "click",
    guarded(async (event) => {
      const b = event.target.closest("button,[data-inspect]");
      if (!b) return;
      if (b.dataset.side) {
        document
          .querySelectorAll("[data-side-panel]")
          .forEach((e) => (e.hidden = e.dataset.sidePanel !== b.dataset.side));
        document
          .querySelectorAll("[data-side]")
          .forEach((e) => e.classList.toggle("active", e === b));
      }
      if (b.dataset.inspectorTab) {
        state.inspectorTab = b.dataset.inspectorTab;
        inspectorTabs();
      }
      if (b.dataset.closePanel) {
        document
          .querySelector(".shell")
          .classList.remove(b.dataset.closePanel + "-open");
        if (b.dataset.closePanel === "inspector")
          document.querySelector(".shell").classList.add("inspector-collapsed");
        state.cy?.resize();
      }
      if (b.dataset.closePanel) {
        syncPanels();
        $(
          b.dataset.closePanel === "sidebar"
            ? "#toggleSidebar"
            : "#toggleInspector",
        ).focus();
      }
      if (b.dataset.preview) {
        $("#evidenceImage").src =
          "/osint/api" + route("/sources/" + b.dataset.preview + "/preview");
        $("#imageError").hidden = true;
        $("#imageDialog").showModal();
      }
      if (b.id === "inlineSource") {
        draftStack.push({
          nodes: [...$("#fields").childNodes],
          title: $("#editorTitle").textContent,
          submit: $("#editorForm").onsubmit,
          error: $("#formError").textContent,
          baseline: draftBaseline,
          focus: b,
        });
        editRecord(null, "source");
      }
      if (b.dataset.action) {
        document.querySelector(".more-menu").open = false;
        action(b.dataset.action);
        return;
      }
      if (b.dataset.inspect) {
        if (b.dataset.inspect === "entity" && state.connect !== null) {
          if (!state.connect) {
            setConnect(b.dataset.id);
          } else if (state.connect !== b.dataset.id) {
            const from = state.connect;
            setConnect(null);
            editRelationship(null, from, b.dataset.id);
          }
          return;
        }
        inspect(b.dataset.inspect, b.dataset.id);
        if (b.dataset.inspect === "entity") {
          const node = state.cy?.getElementById(b.dataset.id);
          node?.select();
          if (node?.length) state.cy.center(node);
        }
        return;
      }
      if (b.dataset.record) {
        editRecord(state.w.records.find((r) => r.id === b.dataset.record));
        return;
      }
      if (b.dataset.view) {
        state.view = b.dataset.view;
        renderView();
        return;
      }
      if (b.dataset.table) {
        state.table = b.dataset.table;
        renderView();
        return;
      }
      if (b.hasAttribute("data-edit-selected")) editSelected();
      if (b.hasAttribute("data-connect")) {
        setConnect(state.selected.id);
        toast("Оберіть другу сутність на графі");
      }
      if (b.hasAttribute("data-duplicate")) duplicate();
      if (b.hasAttribute("data-delete-selected")) await deleteSelected();
      if (b.dataset.addLinked)
        editRecord(null, b.dataset.addLinked, state.selected);
      if (b.dataset.deleteRecord) {
        if (
          await askConfirm(
            "Видалити «" +
              (state.w.records.find((r) => r.id === b.dataset.deleteRecord)
                ?.data.title || "запис") +
              "»?",
            "Запис і його вкладення буде остаточно видалено.",
          )
        ) {
          await send("/records/" + b.dataset.deleteRecord, {}, "DELETE");
          $("#editor").close();
          await refresh();
        }
        return;
      }
      if (b.hasAttribute("data-lead-entity"))
        editEntity(
          null,
          {
            title: selectedItem().data.title,
            notes: selectedItem().data.description,
          },
          selectedItem(),
        );
      if (b.hasAttribute("data-lead-relationship"))
        editRelationship(null, null, null, selectedItem());
      if (b.dataset.leadState) {
        await send(
          "/records/" + state.selected.id,
          { data: { status: b.dataset.leadState } },
          "PATCH",
        );
        await refresh();
      }
      if (b.dataset.context) {
        $("#context").hidden = true;
        const a = b.dataset.context;
        if (a === "edit") editSelected();
        else if (a === "delete") await deleteSelected();
        else if (a === "duplicate") duplicate();
        else if (a === "connect") {
          setConnect(state.selected.id);
          toast("Оберіть другу сутність");
        } else editRecord(null, a, state.selected);
      }
      if (
        b.id === "deleteCase" &&
        (await askConfirm(
          "Видалити «" + state.w.investigation.name + "»?",
          "Усі сутності, зв’язки, докази та вкладення буде остаточно видалено.",
        ))
      ) {
        await send("", {}, "DELETE");
        $("#editor").close();
        state.id = null;
        state.w = null;
        location.reload();
      }
      if (b.id === "previewMerge") {
        const body = Object.fromEntries(new FormData($("#editorForm")));
        const { preview: p } = await send("/merge-preview", body);
        $("#mergePreview").innerHTML =
          `<h3>${esc(p.from.display_name)} → ${esc(p.to.display_name)}</h3><p>Буде перенесено зв’язків: ${p.relationships.length}. Джерела, нотатки, зачіпки й шари будуть переприв’язані. Оригінальні дані збережуться окремим доказом.</p><ul>${p.relationships.map((r) => `<li>${esc(name(r.source_entity_id))} → ${esc(name(r.target_entity_id))} · ${esc(relName(r))} · ${esc(uk.statuses[r.epistemic_status])}</li>`).join("")}</ul>`;
        $("#mergePreview").dataset.key = JSON.stringify(body);
      }
      if (b.id === "findPath") {
        const from = $("#pathFrom").value,
          to = $("#pathTo").value;
        const [p, n] = await Promise.all([
          api(route(`/path?from=${from}&to=${to}`)),
          api(route(`/common-neighbors?from=${from}&to=${to}`)),
        ]);
        $("#pathResult").textContent =
          "Шлях: " +
          (p.path.map((e) => e.display_name).join(" → ") || "немає") +
          ". Спільні сусіди: " +
          (n.ids.map(name).join(", ") || "немає");
      }
      if (b.id === "runAnalysis") {
        const { run } = await send("/analyze", {});
        toast("Аналіз запущено");
        let active = run;
        while (["queued", "running"].includes(active.status)) {
          await new Promise((r) => setTimeout(r, 1200));
          active = (await api(route("/runs/" + run.id))).run;
        }
        if (active.status === "failed") throw Error(active.error);
        toast("Аналіз збережено");
        await refresh();
      }
    }),
  );
  $("#newCase").onclick = () => editCase();
  $("#caseMenu").onclick = () => requireCase() && editCase(true);
  $("#emptyCreate").onclick = () => {
    if (state.w?.entities.length) {
      resetFilters();
      renderSidebar();
      applyVisibility();
    } else state.id ? editEntity() : editCase();
  };
  $("#cases").onchange = guarded(
    (e) => e.target.value && openCase(e.target.value),
  );
  $("#closeEditor").onclick = $("#cancelEditor").onclick = closeEditor;
  $("#editor").addEventListener("cancel", (e) => {
    e.preventDefault();
    closeEditor();
  });
  $("#editor").addEventListener("close", () => {
    $("#editorForm button[type=submit]").textContent = "Зберегти";
  });
  $("#logout").onclick = guarded(async () => {
    await api("/auth/logout", { method: "POST", body: "{}" });
    location.assign("/osint");
  });
  for (const id of [
    "search",
    "onlyMatches",
    "typeFilter",
    "relationFilter",
    "statusFilter",
    "evidenceFilter",
    "sourceFilter",
    "dateFilter",
  ])
    $("#" + id).addEventListener("input", () => {
      renderSidebar();
      applyVisibility();
      renderView();
    });
  $("#layers").onchange = (e) => {
    if (e.target.dataset.layer) {
      if (e.target.checked) state.hiddenLayers.delete(e.target.dataset.layer);
      else state.hiddenLayers.add(e.target.dataset.layer);
      applyVisibility();
      renderSidebar();
    }
  };
  $("#fit").onclick = () => state.cy?.fit(state.cy.elements(":visible"), 65);
  $("#layout").onclick = () => {
    state.cy?.one("layoutstop", () =>
      queuePositions(state.cy.nodes().filter((n) => !n.isParent())),
    );
    state.cy
      ?.layout({
        name: "cose",
        animate: !matchMedia("(prefers-reduced-motion:reduce)").matches,
        padding: 65,
        nodeRepulsion: () => 7000,
      })
      .run();
  };
  $("#groupSelected").onclick = () => {
    if (!requireCase()) return;
    const ids = state.cy
      .nodes(":selected")
      .filter((n) => !n.isParent())
      .map((n) => n.id());
    editRecord(null, "group");
    document
      .querySelectorAll("#fields input[name=links]")
      .forEach((o) => (o.checked = ids.includes(o.value.split(":")[1])));
    updatePickers();
    draftBaseline = fingerprint();
  };
  $("#mergeSelected").onclick = guarded(merge);
  $("#import").onclick = () => {
    if (!requireCase()) return;
    dialog(
      "Імпорт JSON / CSV",
      '<label>Один JSON або до двох CSV<input type="file" name="files" accept=".json,.csv" multiple required></label><p class="muted">CSV: entities (id,type,name) та relationships (source,target,type,epistemic_status,source_url). Без статусу зв’язки імпортуються як HYPOTHESIS.</p>',
      async (f) => {
        const files = f.getAll("files");
        let full = false;
        if (files.length === 1 && files[0].name.endsWith(".json")) {
          try {
            full =
              JSON.parse(await files[0].text()).schema ===
              "osint-investigation/v1";
          } catch {}
        }
        if (full) {
          const fd = new FormData();
          fd.append("file", files[0]);
          await api(route("/restore"), { method: "POST", body: fd });
        } else await api(route("/import"), { method: "POST", body: f });
        await refresh();
      },
    );
  };
  $("#export").onclick = () => {
    if (!requireCase()) return;
    dialog(
      "Експорт розслідування",
      '<p class="muted">JSON містить джерела, вкладення, нотатки, шари й походження даних.</p>' +
        ["json", "entities", "relationships"]
          .map(
            (format) =>
              `<p><a href="/osint/api${route("/export?format=" + format)}" download>↓ ${format === "json" ? "Повний JSON" : format === "entities" ? "CSV сутності" : "CSV зв’язки"}</a></p>`,
          )
          .join(""),
      async () => {},
    );
  };
  document.addEventListener("keydown", (e) => {
    if (
      (e.key === "Enter" || e.key === " ") &&
      e.target.matches("tr[data-inspect]")
    ) {
      e.preventDefault();
      e.target.click();
    }
    if (e.key === "Escape") {
      $("#context").hidden = true;
      setConnect(null);
      if (!$("#editor").open && !$("#imageDialog").open) {
        document
          .querySelector(".shell")
          .classList.remove("sidebar-open", "inspector-open");
        syncPanels();
      }
    }
  });
  $("#toggleFilters").onclick = () => {
    $("#filtersPanel").hidden = !$("#filtersPanel").hidden;
    $("#toggleFilters").setAttribute(
      "aria-expanded",
      String(!$("#filtersPanel").hidden),
    );
  };
  $("#resetFilters").onclick = () => {
    resetFilters();
    $("#search").value = "";
    renderSidebar();
    applyVisibility();
    renderView();
  };
  $("#connectMode").onclick = () =>
    requireCase() && setConnect(state.connect === null ? "" : null);
  $("#cancelConnect").onclick = () => setConnect(null);
  $("#connectForm").onclick = () => {
    const from = state.connect;
    setConnect(null);
    editRelationship(null, from || null);
  };
  $("#retryLayout").onclick = guarded(flushLayout);
  function syncPanels() {
    const shell = document.querySelector(".shell");
    $("#toggleSidebar").setAttribute(
      "aria-expanded",
      String(shell.classList.contains("sidebar-open")),
    );
    $("#toggleInspector").setAttribute(
      "aria-expanded",
      String(
        matchMedia("(max-width:950px)").matches
          ? shell.classList.contains("inspector-open")
          : !shell.classList.contains("inspector-collapsed"),
      ),
    );
  }
  $("#toggleInspector").onclick = () => {
    document.querySelector(".shell").classList.toggle("inspector-collapsed");
    document.querySelector(".shell").classList.toggle("inspector-open");
    syncPanels();
    state.cy?.resize();
  };
  $("#toggleSidebar").onclick = () => {
    document.querySelector(".shell").classList.toggle("sidebar-open");
    syncPanels();
  };
  $("#closeImage").onclick = () => $("#imageDialog").close();
  $("#evidenceImage").onerror = () => {
    $("#imageError").hidden = false;
  };
  document.addEventListener("input", (e) => {
    if (e.target.closest(".picker")) updatePickers();
    if (e.target.hasAttribute("data-type-search")) {
      const q = e.target.value.toLocaleLowerCase("uk");
      e.target
        .closest(".type-picker")
        .querySelectorAll("option")
        .forEach(
          (o) =>
            (o.hidden =
              o.value !== "__custom" &&
              !o.textContent.toLocaleLowerCase("uk").includes(q)),
        );
    }
  });
  document.addEventListener("change", (e) => {
    if (e.target.dataset.selectEntity) {
      const n = state.cy?.getElementById(e.target.dataset.selectEntity);
      if (e.target.checked) n?.select();
      else n?.unselect();
    }
    if (e.target.name === "type") {
      const custom = $("[data-custom-type]");
      if (custom) {
        custom.hidden = e.target.value !== "__custom";
        custom.querySelector("input").required = !custom.hidden;
      }
      if ($("#fields input[name=display_name]")) entityFields();
    }
  });
  window.addEventListener("beforeunload", (e) => {
    if (
      draftStack.length ||
      state.saveQueue.size ||
      state.saving ||
      editorBusy ||
      ($("#editor").open && fingerprint() !== draftBaseline)
    ) {
      e.preventDefault();
      e.returnValue = "";
    }
  });
  loadCases().catch((e) => toast(uk.error(e)));
})();
