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
  const types = [
    "PERSON",
    "ORGANIZATION",
    "SOCIAL_ACCOUNT",
    "USERNAME",
    "EMAIL",
    "PHONE",
    "WEBSITE",
    "DOMAIN",
    "LOCATION",
    "POST",
    "DOCUMENT",
    "IMAGE",
    "EVENT",
    "OTHER",
  ];
  const relations = [
    "OWNS",
    "USES",
    "WORKS_AT",
    "FOUNDED",
    "MEMBER_OF",
    "FOLLOWS",
    "MENTIONS",
    "TAGGED",
    "COMMENTED",
    "COLLABORATED_WITH",
    "LINKED_TO",
    "LOCATED_AT",
    "PARTICIPATED_IN",
    "SAME_PERSON_AS",
    "POSSIBLY_SAME_PERSON_AS",
    "ASSOCIATED_WITH",
    "RELATED_TO",
  ];
  const names = {
    PERSON: "Людина",
    ORGANIZATION: "Організація",
    SOCIAL_ACCOUNT: "Соціальний акаунт",
    USERNAME: "Username",
    EMAIL: "Email",
    PHONE: "Телефон",
    WEBSITE: "Сайт",
    DOMAIN: "Домен",
    LOCATION: "Місце",
    POST: "Публікація",
    DOCUMENT: "Документ",
    IMAGE: "Зображення",
    EVENT: "Подія",
    OTHER: "Інше",
  };
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
    `<span class="badge ${esc(status)}">${esc(status)}</span>`;
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
    if (!response.ok) throw Error(data.error || "Помилка запиту");
    return data;
  }
  const route = (path) => `/investigations/${state.id}${path}`;
  const send = (path, body, method = "POST") =>
    api(route(path), { method, body: JSON.stringify(body) });
  function guarded(fn) {
    return (...args) =>
      Promise.resolve()
        .then(() => fn(...args))
        .catch((e) => toast(e.message));
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
    state.cy?.destroy();
    state.cy = null;
    state.id = id;
    state.selected = null;
    state.positions = {};
    state.hiddenLayers.clear();
    $("#inspector").innerHTML =
      '<div class="placeholder"><h2>Деталі та докази</h2><p>Оберіть сутність або зв’язок.</p></div>';
    await refresh();
  }
  async function refresh() {
    if (!state.id) return;
    const data = await api(route("/workspace"));
    state.w = data.workspace;
    state.analysis = data.analysis;
    $("#caseTitle").textContent = state.w.investigation.name;
    renderStats();
    renderFilters();
    renderSidebar();
    renderGraph();
    renderView();
    if (state.selected) inspect(state.selected.kind, state.selected.id);
  }
  function renderStats() {
    const w = state.w;
    const counts = [
      [w.entities.length, "сутностей"],
      [w.relationships.length, "зв’язків"],
      [recs("lead").length, "зачіпок"],
      [
        recs("lead").filter(
          (r) => !["CONFIRMED", "DISMISSED"].includes(r.data.status),
        ).length,
        "відкритих",
      ],
      ...["FACT", "INFERENCE", "HYPOTHESIS"].map((s) => [
        w.relationships.filter((r) => r.epistemic_status === s).length,
        s,
      ]),
      [recs("source").length, "доказів"],
    ];
    $("#stats").innerHTML = counts
      .map(([v, k]) => `<span><b>${v}</b>${k}</span>`)
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
          (x) => [x, x],
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
    if (
      search &&
      !JSON.stringify([
        item,
        ...recs("note")
          .filter((r) => linked(r, kind, item.id))
          .map((r) => r.data),
      ])
        .toLowerCase()
        .includes(search)
    )
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
        .filter((e) => passes("entity", e))
        .map(
          (e) =>
            `<button class="list-row" data-inspect="entity" data-id="${e.id}"><span class="glyph">${glyph(e.type)}</span><span>${esc(e.display_name)}</span></button>`,
        )
        .join("") || "<small>Немає сутностей</small>";
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
    const viewport = previous
      ? { zoom: previous.zoom(), pan: previous.pan() }
      : {};
    if (previous) {
      previous
        .nodes()
        .filter((n) => !n.isParent())
        .forEach((n) => (state.positions[n.id()] = n.position()));
      previous.destroy();
    }
    const w = state.w;
    if (!w) return;
    const entities = w.entities.filter((e) => passes("entity", e)),
      ids = new Set(entities.map((e) => e.id));
    const groups = recs("group").filter((g) =>
      g.links.some((l) => l.kind === "entity" && ids.has(l.id)),
    );
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
      ...w.relationships
        .filter(
          (r) =>
            ids.has(r.source_entity_id) &&
            ids.has(r.target_entity_id) &&
            passes("relationship", r),
        )
        .map((r) => ({
          data: {
            id: r.id,
            source: r.source_entity_id,
            target: r.target_entity_id,
            label: r.metadata.label || r.relationship_type,
            status: r.epistemic_status,
          },
        })),
    ];
    state.cy = cytoscape({
      container: $("#graph"),
      elements,
      ...viewport,
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
      if (state.connect && state.connect !== e.target.id()) {
        const from = state.connect;
        state.connect = null;
        editRelationship(null, from, e.target.id());
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
    state.cy.on(
      "dragfree",
      "node",
      guarded(async (e) => {
        if (e.target.isParent()) return;
        state.positions[e.target.id()] = e.target.position();
        const entity = w.entities.find((x) => x.id === e.target.id());
        await send(
          "/entities/" + entity.id,
          { metadata: { ...entity.metadata, position: e.target.position() } },
          "PATCH",
        );
        entity.metadata.position = e.target.position();
      }),
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
    $("#empty").hidden = entities.length > 0 || state.view !== "Graph";
    $("#empty h2").textContent = w.entities.length
      ? "Немає збігів"
      : "Додайте першу сутність";
    $("#empty p").textContent = w.entities.length
      ? "Змініть фільтри, щоб повернути об’єкти на карту."
      : "Подвійний клік на canvas або кнопка «Сутність».";
    $("#emptyCreate").textContent = "＋ Сутність";
  }
  function inspect(kind, id) {
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
          ? item.metadata.label || item.relationship_type
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
    $("#inspector").innerHTML =
      `<p class="eyebrow">${esc(kind === "entity" ? names[item.type] || item.type : kind)}</p><h2>${esc(title)}</h2><div class="sub">${status ? badge(status) : ""} ${item.confidence != null ? `Confidence ${Math.round(item.confidence * 100)}%` : ""}</div>${kind === "relationship" ? `<p>${esc(name(item.source_entity_id))} → ${esc(name(item.target_entity_id))}</p>` : ""}<div class="sub">Створено ${date(item.created_at || item.first_observed_at)}<br>Автор: ${esc(item.created_by || "Імпорт / попередня версія")}</div><p>${esc(item.explanation || "")}</p><p>${esc(notes)}</p>${kind === "entity" ? `<div class="sub">${esc(item.metadata.platform || item.platform || "")} ${esc(item.metadata.username || item.username || "")}<br>${urlLink(item.metadata.url || item.profile_url)}</div>` : ""}<div class="actions"><button data-edit-selected>Редагувати</button>${kind === "entity" ? "<button data-connect>З’єднати</button><button data-duplicate>Дублювати</button>" : ""}<button data-add-linked="source">＋ Доказ</button><button data-add-linked="note">＋ Нотатка</button><button data-add-linked="lead">＋ Зачіпка</button><button class="danger" data-delete-selected>Видалити</button></div>${kind === "lead" ? `<div class="actions"><button data-lead-entity>Створити сутність</button><button data-lead-relationship>Створити зв’язок</button><button data-close-lead>Закрити зачіпку</button></div><p>${esc(item.data.status)} · ${esc(item.data.priority)}</p>` : ""}<h3>Джерела та докази · ${evidence.length}</h3>${evidence.map(sourceCard).join("") || '<p class="muted">Джерела ще не прикріплені.</p>'}${(item.evidence || []).map((e) => `<div class="evidence-item">${urlLink(e.source_url)}<small>${esc(e.collector)} · ${date(e.observed_at)}</small></div>`).join("")}<h3>Нотатки</h3>${
        recs("note")
          .filter((r) => linked(r, kind, id))
          .map(
            (r) =>
              `<div class="evidence-item"><button data-record="${r.id}">${esc(r.data.title)}</button><p>${esc(r.data.description)}</p></div>`,
          )
          .join("") || "<small>Нотаток поки немає.</small>"
      }<h3>Пов’язані сутності</h3>${connected.map((r) => `<button class="list-row" data-inspect="relationship" data-id="${r.id}">${badge(r.epistemic_status)} ${esc(name(r.source_entity_id === id ? r.target_entity_id : r.source_entity_id))}</button>`).join("")}${kind === "relationship" ? [item.source_entity_id, item.target_entity_id].map((e) => `<button class="list-row" data-inspect="entity" data-id="${e}">${esc(name(e))}</button>`).join("") : ""}${
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
            `<button class="list-row" data-inspect="lead" data-id="${r.id}">${esc(r.data.title)} · ${esc(r.data.status)}</button>`,
        )
        .join("")}`;
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
    return `<div class="evidence-item"><button data-record="${r.id}">${esc(r.data.title)}</button> ${badge(r.data.epistemic_status || "FACT")}<p>${esc(r.data.quote || r.data.description || "")}</p>${urlLink(r.data.url)}${r.file_name ? `<p><a href="/osint/api${route("/sources/" + r.id + "/file")}">↓ ${esc(r.file_name)}</a></p>` : ""}<small>${date(r.data.observed_at || r.created_at)} · Автор ${esc(r.created_by)}</small>${r.data.merge_snapshot || r.data.entity_origins || r.data.legacy_raw_data || r.data.legacy_metadata ? `<details><summary>Походження запису</summary><pre>${esc(JSON.stringify(r.data.merge_snapshot || r.data, null, 2))}</pre></details>` : ""}</div>`;
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
      el.innerHTML = `<div class="view-head"><h2>Таблиця</h2><div><button data-table="entities">Сутності</button> <button data-table="relationships">Зв’язки</button></div></div><table><thead><tr>${(entities ? ["Тип", "Назва", "Ідентифікатори", "Зв’язки", "Джерела", "Нотатки", "Створено"] : ["Від → До", "Тип", "Статус", "Confidence", "Джерела", "Нотатки", "Створено"]).map((h) => `<th>${h}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr data-inspect="${entities ? "entity" : "relationship"}" data-id="${r.id}">${(entities ? [names[r.type] || r.type, r.display_name, [r.metadata.username || r.username, r.metadata.url || r.profile_url, r.canonical_name].filter(Boolean).join(" · "), state.w.relationships.filter((x) => x.source_entity_id === r.id || x.target_entity_id === r.id).length, sources("entity", r.id).length, r.metadata.notes, date(r.created_at)] : [`${name(r.source_entity_id)} → ${name(r.target_entity_id)}`, r.metadata.label || r.relationship_type, r.epistemic_status, Math.round(r.confidence * 100) + "%", sources("relationship", r.id).length + (r.evidence?.length || 0), r.metadata.notes || r.explanation, date(r.created_at || r.first_observed_at)]).map((v) => `<td>${esc(v)}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
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
              `<div class="timeline-row"><small>${date(time)} · ${field}</small><button ${kind === "source" ? `data-record="${r.id}"` : `data-inspect="${kind}" data-id="${r.id}"`}>${esc(r.display_name || r.data?.title || r.metadata?.label || r.relationship_type)}</button> ${r.epistemic_status ? badge(r.epistemic_status) : ""}</div>`,
          )
          .join("");
    } else if (["Evidence", "Leads", "Notes"].includes(state.view)) {
      const kind = { Evidence: "source", Leads: "lead", Notes: "note" }[
        state.view
      ];
      const query = $("#search").value.trim().toLowerCase();
      el.innerHTML =
        `<div class="view-head"><h2>${state.view}</h2><button data-action="${kind}" class="primary">＋ Додати</button></div>` +
        recs(kind)
          .filter(
            (r) =>
              !query || JSON.stringify(r.data).toLowerCase().includes(query),
          )
          .map((r) =>
            kind === "source"
              ? sourceCard(r)
              : `<div class="record-row"><div class="content"><h2>${esc(r.data.title)}</h2><p>${esc(r.data.description)}</p><small>${esc(r.data.status || "")} ${esc(r.data.priority || "")} · ${date(r.created_at)}</small><p>${r.links
                  .filter((l) => l.kind === "entity")
                  .map((l) => esc(name(l.id)))
                  .join(
                    " · ",
                  )}</p></div><button ${kind === "lead" ? `data-inspect="lead" data-id="${r.id}"` : `data-record="${r.id}"`}>Відкрити</button></div>`,
          )
          .join("");
    } else if (state.view === "Analysis") {
      const a = state.analysis;
      el.innerHTML = `<div class="view-head"><h2>Analysis</h2><button id="runAnalysis">Зберегти аналіз</button></div><p class="muted">Структура поточного графа. Центральність не підтверджує гіпотези чи особисті зв’язки.</p><h3>Шлях та спільні сусіди</h3><div class="pair"><label>Від<select id="pathFrom">${entityOptions()}</select></label><label>До<select id="pathTo">${entityOptions()}</select></label></div><button id="findPath">Знайти</button><p id="pathResult"></p><h3>Degree centrality</h3><table><thead><tr><th>Сутність</th><th>Degree</th><th>Centrality</th></tr></thead><tbody>${(a.metrics || []).map((m) => `<tr data-inspect="entity" data-id="${m.entityId}"><td>${esc(name(m.entityId))}</td><td>${m.degree}</td><td>${esc((m.degree / Math.max(1, state.w.entities.length - 1)).toFixed(3))}</td></tr>`).join("")}</tbody></table><h3>Bridge nodes</h3><p>${(a.bridgeEntityIds || []).map(name).map(esc).join(" · ") || "Немає"}</p><h3>Connected components</h3><p>${(a.connectedComponents || []).map((ids) => ids.map(name).map(esc).join(" · ")).join("<br>")}</p><h3>Communities</h3>${Object.entries(
        a.communities || {},
      )
        .map(([id, c]) => `<p>${esc(name(id))} · ${esc(c)}</p>`)
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
        const [v, t] = Array.isArray(x) ? x : [x, x];
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
    `<label>${label}<select name="${key}" multiple>${values.map(([v, t]) => `<option value="${esc(v)}" ${selected.includes(v) ? "selected" : ""}>${esc(t)}</option>`).join("")}</select><small>⌘ / Ctrl — вибрати декілька</small></label>`;
  function dates(d = {}) {
    return (
      "<details><summary>Дати</summary>" +
      ["event_date", "valid_from", "valid_to", "observed_at"]
        .map((k) =>
          input(
            {
              event_date: "Дата події",
              valid_from: "Дійсне від",
              valid_to: "Дійсне до",
              observed_at: "Дата спостереження",
            }[k],
            k,
            d[k] ? String(d[k]).slice(0, 10) : "",
            "date",
          ),
        )
        .join("") +
      "</details>"
    );
  }
  function dialog(title, html, save) {
    $("#editorTitle").textContent = title;
    $("#fields").innerHTML = html;
    $("#formError").textContent = "";
    $("#editorForm").onsubmit = async (e) => {
      e.preventDefault();
      const button = e.submitter;
      button.disabled = true;
      try {
        await save(new FormData(e.target));
        $("#editor").close();
      } catch (error) {
        $("#formError").textContent = error.message;
      } finally {
        button.disabled = false;
      }
    };
    $("#editor").showModal();
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
      `<div class="pair"><label>Тип<input name="type" list="entityTypes" value="${esc(item?.type || "PERSON")}" required maxlength="80"><datalist id="entityTypes">${options(types.map((t) => [t, names[t]]))}</datalist></label>${input("Назва", "display_name", item?.display_name || preset.title || "", "text", true)}</div>` +
        input("Платформа", "platform", d.platform || item?.platform || "") +
        input(
          "Username / Email / Телефон",
          "username",
          d.username || item?.username || "",
        ) +
        input("URL", "url", d.url || item?.profile_url || "", "url") +
        area("Нотатки", "notes", d.notes || "") +
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
      `<div class="pair"><label>Від<select name="source">${entityOptions(item?.source_entity_id || from)}</select></label><label>До<select name="target">${entityOptions(item?.target_entity_id || to || state.w.entities.find((e) => e.id !== (from || state.w.entities[0].id))?.id)}</select></label></div><label>Тип<input name="type" list="relationTypes" value="${esc(item?.relationship_type || "RELATED_TO")}" required maxlength="80"><datalist id="relationTypes">${options(relations)}</datalist></label>` +
        input("Власна назва зв’язку", "label", d.label || "") +
        '<div class="pair">' +
        select(
          "Статус",
          "epistemic_status",
          ["FACT", "INFERENCE", "HYPOTHESIS"],
          item?.epistemic_status || "HYPOTHESIS",
        ) +
        `<label>Confidence (0–1)<input type="number" min="0" max="1" step="0.05" name="confidence" value="${item?.confidence ?? 0.5}" required></label></div>` +
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
        dates(d),
      async (f) => {
        const body = Object.fromEntries(f);
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
        `${name(r.source_entity_id)} → ${name(r.target_entity_id)} · ${r.metadata.label || r.relationship_type}`,
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
        input("URL", "url", d.url || "", "url") +
        area("Цитата", "quote", d.quote || "") +
        select(
          "Статус спостереження",
          "epistemic_status",
          ["FACT", "INFERENCE", "HYPOTHESIS"],
          d.epistemic_status || "FACT",
        ) +
        `<label>Файл / screenshot (до 10 MB)<input type="file" name="file"></label>${record?.file_name ? `<small>Збережено: ${esc(record.file_name)}</small>` : ""}` +
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
        const result = await send(
          record ? "/records/" + record.id : "/records",
          body,
          record ? "PATCH" : "POST",
        );
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
      !confirm(
        "Видалити об’єкт і його прив’язки? Джерела залишаться в Evidence.",
      )
    )
      return;
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
    const selected = state.cy
      .nodes(":selected")
      .filter((n) => !n.isParent())
      .map((n) => n.id());
    dialog(
      "Об’єднати дублікати",
      `<p class="muted">Першу сутність буде приєднано до другої. Спочатку перегляньте зміни.</p><label>Дублікат<select name="from">${entityOptions(selected[0])}</select></label><label>Зберегти<select name="to">${entityOptions(selected[1])}</select></label><button type="button" id="previewMerge">Переглянути зміни</button><div id="mergePreview"></div>`,
      async (f) => {
        const body = Object.fromEntries(f);
        if ($("#mergePreview").dataset.key !== JSON.stringify(body))
          throw Error("Спочатку перегляньте зміни для вибраної пари");
        await send("/merge", body);
        state.selected = null;
        await refresh();
        toast("Сутності об’єднано; оригінал збережено у provenance");
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
      if (b.dataset.action) {
        action(b.dataset.action);
        return;
      }
      if (b.dataset.inspect) {
        inspect(b.dataset.inspect, b.dataset.id);
        if (b.dataset.inspect === "entity") {
          state.cy?.getElementById(b.dataset.id).select();
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
        state.connect = state.selected.id;
        toast("Оберіть другу сутність на графі");
      }
      if (b.hasAttribute("data-duplicate")) duplicate();
      if (b.hasAttribute("data-delete-selected")) await deleteSelected();
      if (b.dataset.addLinked)
        editRecord(null, b.dataset.addLinked, state.selected);
      if (b.dataset.deleteRecord) {
        if (confirm("Видалити запис і його вкладення?")) {
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
      if (b.hasAttribute("data-close-lead")) {
        await send(
          "/records/" + state.selected.id,
          { data: { status: "CONFIRMED" } },
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
          state.connect = state.selected.id;
          toast("Оберіть другу сутність");
        } else editRecord(null, a, state.selected);
      }
      if (
        b.id === "deleteCase" &&
        confirm("Остаточно видалити розслідування з усіма даними?")
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
          `<h3>${esc(p.from.display_name)} → ${esc(p.to.display_name)}</h3><p>Буде перенесено зв’язків: ${p.relationships.length}. Джерела, нотатки, зачіпки й шари будуть переприв’язані. Оригінальні дані збережуться окремим доказом.</p><ul>${p.relationships.map((r) => `<li>${esc(name(r.source_entity_id))} → ${esc(name(r.target_entity_id))} · ${esc(r.relationship_type)} · ${esc(r.epistemic_status)}</li>`).join("")}</ul>`;
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
  $("#emptyCreate").onclick = () => (state.id ? editEntity() : editCase());
  $("#cases").onchange = guarded(
    (e) => e.target.value && openCase(e.target.value),
  );
  $("#closeEditor").onclick = $("#cancelEditor").onclick = () =>
    $("#editor").close();
  $("#editor").addEventListener("close", () => {
    $("#editorForm button[type=submit]").textContent = "Зберегти";
  });
  $("#logout").onclick = guarded(async () => {
    await api("/auth/logout", { method: "POST", body: "{}" });
    location.assign("/osint");
  });
  for (const id of [
    "search",
    "typeFilter",
    "relationFilter",
    "statusFilter",
    "evidenceFilter",
    "sourceFilter",
    "dateFilter",
  ])
    $("#" + id).addEventListener("input", () => {
      renderSidebar();
      renderGraph();
      renderView();
    });
  $("#layers").onchange = (e) => {
    if (e.target.dataset.layer) {
      if (e.target.checked) state.hiddenLayers.delete(e.target.dataset.layer);
      else state.hiddenLayers.add(e.target.dataset.layer);
      renderGraph();
      renderSidebar();
    }
  };
  $("#fit").onclick = () => state.cy?.fit(undefined, 65);
  $("#layout").onclick = () =>
    state.cy
      ?.layout({
        name: "cose",
        animate: !matchMedia("(prefers-reduced-motion:reduce)").matches,
        padding: 65,
        nodeRepulsion: () => 7000,
      })
      .run();
  $("#groupSelected").onclick = () => {
    if (!requireCase()) return;
    const ids = state.cy
      .nodes(":selected")
      .filter((n) => !n.isParent())
      .map((n) => n.id());
    editRecord(null, "group");
    const select = $("#fields select[name=links]");
    for (const o of select.options)
      o.selected = ids.includes(o.value.split(":")[1]);
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
    if (e.key === "Escape") {
      $("#context").hidden = true;
      state.connect = null;
    }
  });
  loadCases().catch((e) => toast(e.message));
})();
