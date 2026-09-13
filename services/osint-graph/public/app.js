(() => {
  'use strict';

  const state = { investigations: [], current: null, graph: null, analysis: null, cy: null, selectedId: null, findings: [] };
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const escapeHtml = (value) => String(value ?? '').replace(/[&<>'"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[char]));
  const safeUrl = (value) => { try { const url = new URL(value); return ['http:', 'https:'].includes(url.protocol) ? url.toString() : null; } catch (_error) { return null; } };
  const iconFor = (entity) => ({ PERSON: '●', SOCIAL_ACCOUNT: '◆', ORGANIZATION: '▲', DOMAIN: '⬡', WEBSITE: '■', EMAIL: '✦', PUBLIC_CHANNEL: '◫', OTHER: '○' }[entity.type] || '○');
  const shapeFor = (entity) => ({ PERSON: 'ellipse', SOCIAL_ACCOUNT: 'diamond', ORGANIZATION: 'triangle', DOMAIN: 'hexagon', WEBSITE: 'round-rectangle', EMAIL: 'star', PUBLIC_CHANNEL: 'rectangle' }[entity.type] || 'ellipse');
  const colorFor = (entity) => ({ github: '#6f7a8b', instagram: '#dd5287', telegram: '#3e9ed8', x: '#30343b', linkedin: '#3276b5', tiktok: '#d04a72' }[entity.platform] || ({ PERSON: '#38a47a', ORGANIZATION: '#d49a3e', DOMAIN: '#826bd3', WEBSITE: '#826bd3', EMAIL: '#bd668c', PUBLIC_CHANNEL: '#3e9ed8' }[entity.type] || '#78909c'));

  async function api(path, options = {}) {
    const method = String(options.method || 'GET').toUpperCase();
    const response = await fetch(`/osint/api${path}`, { credentials: 'same-origin', headers: { accept: 'application/json', ...(options.body instanceof FormData ? {} : { 'content-type': 'application/json' }), ...(!['GET', 'HEAD', 'OPTIONS'].includes(method) ? { 'x-osint-csrf': document.body.dataset.csrf } : {}), ...(options.headers || {}) }, ...options });
    const payload = await response.json().catch(() => ({ ok: false, error: 'invalid_response' }));
    if (response.status === 401) { window.location.assign('/osint'); throw new Error('authentication_required'); }
    if (!response.ok) throw new Error(payload.error || `request_${response.status}`);
    return payload;
  }

  function toast(message, error = false) {
    const item = document.createElement('div');
    item.className = `toast${error ? ' error' : ''}`;
    item.textContent = message;
    $('#toastStack').append(item);
    setTimeout(() => item.remove(), 3600);
  }

  function setActions(enabled) { $$('[data-open="addEntity"],[data-open="importGraph"],[data-open="collectData"],[data-open="findPath"],#analyzeGraph,#deleteInvestigation').forEach((button) => { button.disabled = !enabled; }); }

  async function loadInvestigations(selectId = null) {
    const payload = await api('/investigations');
    state.investigations = payload.investigations;
    renderInvestigationList();
    const target = selectId || state.current?.id;
    if (target && state.investigations.some((item) => item.id === target)) await selectInvestigation(target);
  }

  function renderInvestigationList() {
    const query = $('#investigationSearch').value.trim().toLowerCase();
    const list = $('#investigationList');
    list.replaceChildren();
    state.investigations.filter((item) => !query || item.name.toLowerCase().includes(query)).forEach((item) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = `investigation-item${state.current?.id === item.id ? ' active' : ''}`;
      button.innerHTML = `<strong>${escapeHtml(item.name)}</strong><time>${new Date(item.updated_at).toLocaleDateString('uk-UA')}</time><small>${item.entity_count} entities · ${item.relationship_count} links</small>`;
      button.addEventListener('click', () => selectInvestigation(item.id));
      list.append(button);
    });
    if (!list.children.length) {
      const empty = document.createElement('small');
      empty.textContent = query ? 'Нічого не знайдено' : 'Ще немає investigations';
      empty.style.padding = '12px'; empty.style.color = 'var(--muted)';
      list.append(empty);
    }
  }

  async function selectInvestigation(id) {
    const currentPayload = await api(`/investigations/${id}`);
    state.current = currentPayload.investigation;
    state.findings = currentPayload.findings || [];
    renderInvestigationList();
    $('#investigationTitle').textContent = state.current.name;
    $('#investigationMeta').textContent = `Updated ${new Date(state.current.updated_at).toLocaleString('uk-UA')}`;
    setActions(true);
    await loadGraph();
    renderFindings();
  }

  function graphElements() {
    if (!state.graph) return [];
    const nodes = state.graph.entities.map((entity) => ({ data: {
      id: String(entity.id), label: `${iconFor(entity)}  ${entity.display_name}`, type: entity.type, platform: entity.platform || '',
      cluster: state.analysis?.communities?.[entity.id] || 'unclustered', shape: shapeFor(entity), color: colorFor(entity), raw: entity,
    } }));
    const edges = state.graph.relationships.map((edge) => ({ data: {
      id: String(edge.id), source: String(edge.source_entity_id), target: String(edge.target_entity_id), type: edge.relationship_type,
      confidence: Number(edge.confidence), status: edge.epistemic_status, weight: Number(edge.weight), raw: edge,
    } }));
    return nodes.concat(edges);
  }

  function renderGraph() {
    if (state.cy) state.cy.destroy();
    const hasNodes = Boolean(state.graph?.entities?.length);
    $('#emptyState').hidden = hasNodes;
    $('#legend').hidden = !hasNodes;
    if (!hasNodes) { state.cy = null; populateFilters(); return; }
    const colors = getComputedStyle(document.documentElement);
    const textColor = colors.getPropertyValue('--text').trim();
    const backgroundColor = colors.getPropertyValue('--bg').trim();
    const mutedColor = colors.getPropertyValue('--muted').trim();
    const accentColor = colors.getPropertyValue('--accent').trim();
    const surfaceColor = colors.getPropertyValue('--surface-solid').trim();
    state.cy = cytoscape({
      container: $('#graph'), elements: graphElements(), minZoom: .18, maxZoom: 3,
      style: [
        { selector: 'node', style: { width: 34, height: 34, shape: 'data(shape)', 'background-color': 'data(color)', label: 'data(label)', color: textColor, 'font-size': 10, 'font-weight': 600, 'text-valign': 'bottom', 'text-margin-y': 8, 'text-background-color': backgroundColor, 'text-background-opacity': .74, 'text-background-padding': 3, 'border-width': 2, 'border-color': surfaceColor, 'transition-property': 'opacity,width,height,border-width', 'transition-duration': '.18s' } },
        { selector: 'node:selected', style: { width: 46, height: 46, 'border-width': 5, 'border-color': accentColor, 'z-index': 20 } },
        { selector: 'edge', style: { width: 'mapData(weight,0,10,1,4)', 'line-color': mutedColor, opacity: 'mapData(confidence,0,1,.12,.62)', 'curve-style': 'bezier', 'target-arrow-shape': 'triangle', 'target-arrow-color': mutedColor, 'arrow-scale': .7, 'line-style': 'solid' } },
        { selector: 'edge[status="INFERENCE"]', style: { 'line-style': 'dashed', 'line-color': '#c4872c', 'target-arrow-color': '#c4872c' } },
        { selector: '.dimmed', style: { opacity: .08 } }, { selector: '.hidden', style: { display: 'none' } },
        { selector: '.search-match', style: { 'border-width': 5, 'border-color': '#42d2e8', width: 44, height: 44 } },
        { selector: '.path-highlight', style: { opacity: 1, 'line-color': '#42d2e8', 'target-arrow-color': '#42d2e8', 'z-index': 30, width: 5 } },
      ],
      layout: { name: 'cose', animate: true, animationDuration: 650, fit: true, padding: 100, nodeRepulsion: 9000, idealEdgeLength: 100, gravity: .24, randomize: true },
    });
    state.cy.on('tap', 'node', (event) => selectEntity(event.target.id()));
    state.cy.on('mouseover', 'node', (event) => {
      const neighborhood = event.target.closedNeighborhood();
      state.cy.elements().difference(neighborhood).addClass('dimmed');
    });
    state.cy.on('mouseout', 'node', () => state.cy.elements().removeClass('dimmed'));
    populateFilters(); applyFilters();
    const count = state.graph.entities.length;
    $('#nodeWarning').hidden = count < Number(document.body.dataset.warningNodes);
    $('#nodeWarning').textContent = `${count}/${document.body.dataset.maxNodes} nodes · наближення до hard limit`;
  }

  function populateFilters() {
    const fill = (select, values) => {
      const current = select.value;
      select.replaceChildren(new Option('Усі', 'all'));
      values.forEach((value) => select.add(new Option(value, value)));
      if (values.includes(current)) select.value = current;
    };
    fill($('#platformFilter'), Array.from(new Set((state.graph?.entities || []).map((item) => item.platform || item.type).filter(Boolean))).sort());
    fill($('#relationshipFilter'), Array.from(new Set((state.graph?.relationships || []).map((item) => item.relationship_type))).sort());
    fill($('#clusterFilter'), Array.from(new Set(Object.values(state.analysis?.communities || {}))).sort());
    const selects = $$('[data-form="find-path"] select');
    selects.forEach((select) => {
      select.replaceChildren();
      (state.graph?.entities || []).forEach((entity) => select.add(new Option(entity.display_name, entity.id)));
    });
    if (selects[1] && selects[1].options.length > 1) selects[1].selectedIndex = 1;
  }

  function applyFilters() {
    if (!state.cy) return;
    const platform = $('#platformFilter').value;
    const relationship = $('#relationshipFilter').value;
    const confidence = Number($('#confidenceFilter').value);
    const cluster = $('#clusterFilter').value;
    $('#confidenceOutput').textContent = confidence.toFixed(2);
    state.cy.nodes().forEach((node) => {
      const visible = (platform === 'all' || node.data('platform') === platform || node.data('type') === platform)
        && (cluster === 'all' || node.data('cluster') === cluster);
      node.toggleClass('hidden', !visible);
    });
    state.cy.edges().forEach((edge) => {
      const visible = !edge.source().hasClass('hidden') && !edge.target().hasClass('hidden')
        && (relationship === 'all' || edge.data('type') === relationship) && edge.data('confidence') >= confidence;
      edge.toggleClass('hidden', !visible);
    });
  }

  async function loadGraph() {
    const payload = await api(`/investigations/${state.current.id}/graph`);
    state.graph = payload.graph; state.analysis = payload.analysis;
    renderGraph();
  }

  async function selectEntity(id) {
    state.selectedId = id;
    const payload = await api(`/investigations/${state.current.id}/entities/${id}`);
    renderInspector(payload.entity, payload.connectionScores || []);
    $('#inspector').classList.add('open');
  }

  function renderInspector(entity, scores) {
    const profileUrl = safeUrl(entity.profile_url);
    const relationships = entity.relationships || [];
    const lastObserved = entity.observed_at || entity.observations?.[0]?.observed_at || null;
    const scoreById = new Map(scores.map((item) => [String(item.entityId), item]));
    const relationHtml = relationships.slice(0, 30).map((relationship) => {
      const otherId = String(relationship.source_entity_id) === String(entity.id) ? relationship.target_entity_id : relationship.source_entity_id;
      const otherName = String(relationship.source_entity_id) === String(entity.id) ? relationship.target_name : relationship.source_name;
      const score = scoreById.get(String(otherId));
      const parts = score?.components?.map((part) => `<span>+${part.points} ${escapeHtml(part.key.replaceAll('_', ' '))}</span>`).join('') || '<span>Observed fact only</span>';
      return `<button class="connection-item" data-select-entity="${escapeHtml(otherId)}"><strong>${escapeHtml(otherName)}</strong> <em class="${relationship.epistemic_status === 'FACT' ? 'fact-badge' : 'inference-badge'}">${escapeHtml(relationship.epistemic_status)}</em><small>${escapeHtml(relationship.relationship_type)} · confidence ${Number(relationship.confidence).toFixed(2)}</small>${score ? `<div class="score-ring"><b class="score-value">${score.score}</b><span class="score-parts">${parts}</span></div><small>${escapeHtml(score.disclaimer)}</small>` : ''}</button>`;
    }).join('');
    const sourceMap = new Map();
    (entity.observations || []).forEach((observation) => sourceMap.set(observation.source_url, observation));
    relationships.flatMap((relationship) => relationship.evidence || []).forEach((evidence) => sourceMap.set(evidence.source_url, evidence));
    const sources = Array.from(sourceMap.values()).slice(0, 30).map((source) => {
      const url = safeUrl(source.source_url);
      return `<div class="source-item"><span class="fact-badge">source</span>${url ? `<a href="${escapeHtml(url)}" target="_blank" rel="noreferrer noopener">${escapeHtml(url)}</a>` : `<span>${escapeHtml(source.source_url)}</span>`}<small>${escapeHtml(source.collector)} · ${new Date(source.observed_at).toLocaleString('uk-UA')}</small></div>`;
    }).join('');
    $('#inspector').innerHTML = `<div class="entity-head"><span class="entity-icon">${iconFor(entity)}</span><div><h2>${escapeHtml(entity.display_name)}</h2><p>${entity.platform ? `${escapeHtml(entity.platform)} · @${escapeHtml(entity.username)}` : escapeHtml(entity.type)}</p></div></div><div class="inspector-actions"><button data-focus>Focus</button><button data-expand="1">1 hop</button><button data-expand="2">2 hops</button><button data-hide>Hide</button></div><section class="inspector-section"><div class="section-title"><h3>Public metadata</h3><span class="fact-badge">Observed</span></div><dl class="metadata-list"><dt>Type</dt><dd>${escapeHtml(entity.type)}</dd><dt>Profile</dt><dd>${profileUrl ? `<a href="${escapeHtml(profileUrl)}" target="_blank" rel="noreferrer noopener">Open source ↗</a>` : '—'}</dd><dt>Bio</dt><dd>${escapeHtml(entity.bio || '—')}</dd><dt>Followers</dt><dd>${entity.followers_count ?? '—'}</dd><dt>Following</dt><dd>${entity.following_count ?? '—'}</dd><dt>Observed</dt><dd>${lastObserved ? new Date(lastObserved).toLocaleString('uk-UA') : '—'}</dd></dl></section><section class="inspector-section"><div class="section-title"><h3>Connections</h3><span>${relationships.length}</span></div>${relationHtml || '<p class="form-note">Немає зв’язків.</p>'}</section><section class="inspector-section"><div class="section-title"><h3>Why do we think this?</h3><span>${sourceMap.size}</span></div>${sources || '<p class="form-note">Source ще не додано.</p>'}</section>`;
    $$('[data-select-entity]', $('#inspector')).forEach((button) => button.addEventListener('click', () => { state.cy?.getElementById(button.dataset.selectEntity).select(); selectEntity(button.dataset.selectEntity); }));
    $('[data-focus]', $('#inspector'))?.addEventListener('click', () => state.cy?.animate({ center: { eles: state.cy.getElementById(entity.id) }, zoom: 1.55 }, { duration: 350 }));
    $('[data-hide]', $('#inspector'))?.addEventListener('click', () => { state.cy?.getElementById(entity.id).addClass('hidden'); $('#inspector').classList.remove('open'); });
    $$('[data-expand]', $('#inspector')).forEach((button) => button.addEventListener('click', async () => {
      const payload = await api(`/investigations/${state.current.id}/entities/${entity.id}/neighbors?depth=${button.dataset.expand}`);
      const ids = new Set(payload.entities.map((item) => String(item.id)));
      state.cy.elements().addClass('dimmed');
      state.cy.nodes().filter((node) => ids.has(node.id())).closedNeighborhood().removeClass('dimmed');
      state.cy.animate({ fit: { eles: state.cy.nodes().filter((node) => ids.has(node.id())), padding: 90 } }, { duration: 400 });
    }));
  }

  function renderFindings(runResult = null) {
    $('#findingCount').textContent = String(state.findings.length);
    if (runResult?.summary) $('#analysisSummary').textContent = runResult.summary;
    $('#findingsList').innerHTML = state.findings.map((finding) => `<article class="finding"><span>${escapeHtml(finding.finding_type)}</span><h3>${escapeHtml(finding.title)}</h3><p>${escapeHtml(finding.explanation)}</p></article>`).join('') || '<p class="form-note">Запустіть Analyze, щоб отримати структурні findings.</p>';
  }

  async function pollRun(run) {
    $('#runStatus').hidden = false;
    $('#runStatus strong').textContent = run.kind === 'ANALYSIS' ? 'Graph analysis running' : `${run.collector} collector running`;
    try {
      for (let attempt = 0; attempt < 90; attempt += 1) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
        const payload = await api(`/investigations/${run.investigation_id}/runs/${run.id}`);
        if (payload.run.status === 'completed') {
          toast('Run completed');
          await selectInvestigation(run.investigation_id);
          if (run.kind === 'ANALYSIS') { renderFindings(payload.run.result); $('#findingsDrawer').classList.add('open'); }
          return;
        }
        if (payload.run.status === 'failed') throw new Error(payload.run.error || 'run_failed');
      }
      throw new Error('run_timeout');
    } finally { $('#runStatus').hidden = true; }
  }

  $$('[data-open]').forEach((button) => button.addEventListener('click', () => { const dialog = document.getElementById(button.dataset.open); if (dialog && !button.disabled) dialog.showModal(); }));
  $$('dialog form').forEach((form) => form.addEventListener('submit', (event) => event.preventDefault()));
  $$('dialog header button,dialog footer button[value="cancel"]').forEach((button) => button.addEventListener('click', () => button.closest('dialog').close()));

  $('[data-form="new-investigation"]').addEventListener('click', async (event) => {
    if (!event.target.closest('button.primary')) return;
    const form = event.currentTarget; if (!form.reportValidity()) return;
    try { const payload = await api('/investigations', { method: 'POST', body: JSON.stringify(Object.fromEntries(new FormData(form))) }); form.closest('dialog').close(); form.reset(); await loadInvestigations(payload.investigation.id); } catch (error) { toast(error.message, true); }
  });
  $('[data-form="add-entity"]').addEventListener('click', async (event) => {
    if (!event.target.closest('button.primary')) return;
    const form = event.currentTarget; if (!form.reportValidity()) return;
    try { await api(`/investigations/${state.current.id}/entities`, { method: 'POST', body: JSON.stringify(Object.fromEntries(new FormData(form))) }); form.closest('dialog').close(); form.reset(); await selectInvestigation(state.current.id); toast('Entity added'); } catch (error) { toast(error.message, true); }
  });
  $('[data-form="import-graph"]').addEventListener('click', async (event) => {
    if (!event.target.closest('button.primary')) return;
    const form = event.currentTarget; if (!form.reportValidity()) return;
    try { const data = new FormData(form); await api(`/investigations/${state.current.id}/import`, { method: 'POST', body: data }); form.closest('dialog').close(); form.reset(); await selectInvestigation(state.current.id); toast('Graph imported'); } catch (error) { toast(error.message, true); }
  });
  $('#collectorSelect').addEventListener('change', () => $$('[data-collector-field]').forEach((field) => { field.hidden = field.dataset.collectorField !== $('#collectorSelect').value; }));
  $('[data-form="collect"]').addEventListener('click', async (event) => {
    if (!event.target.closest('button.primary')) return;
    const form = event.currentTarget; const values = Object.fromEntries(new FormData(form));
    if ((values.collector === 'github' && !values.username) || (values.collector === 'web' && !values.url)) return toast('Заповніть collector input', true);
    try { const payload = await api(`/investigations/${state.current.id}/collect`, { method: 'POST', body: JSON.stringify(values) }); form.closest('dialog').close(); pollRun(payload.run).catch((error) => toast(error.message, true)); } catch (error) { toast(error.message, true); }
  });
  $('[data-form="find-path"]').addEventListener('click', async (event) => {
    if (!event.target.closest('button.primary')) return;
    const form = event.currentTarget; const values = Object.fromEntries(new FormData(form));
    try {
      const payload = await api(`/investigations/${state.current.id}/path?from=${encodeURIComponent(values.from)}&to=${encodeURIComponent(values.to)}`);
      $('#pathResult').innerHTML = payload.path.length ? payload.path.map((entity) => `<span class="path-node">${escapeHtml(entity.display_name)}</span>`).join(' → ') : 'Шляху в observed graph не знайдено.';
      if (state.cy && payload.path.length) {
        state.cy.elements().removeClass('path-highlight dimmed').addClass('dimmed');
        payload.path.forEach((entity, index) => {
          const node = state.cy.getElementById(entity.id); node.removeClass('dimmed').addClass('path-highlight');
          if (index) state.cy.getElementById(payload.path[index - 1].id).edgesWith(node).removeClass('dimmed').addClass('path-highlight');
        });
      }
    } catch (error) { toast(error.message, true); }
  });
  $('#analyzeGraph').addEventListener('click', async () => { try { const payload = await api(`/investigations/${state.current.id}/analyze`, { method: 'POST', body: '{}' }); pollRun(payload.run).catch((error) => toast(error.message, true)); } catch (error) { toast(error.message, true); } });
  $('#deleteInvestigation').addEventListener('click', async () => {
    if (!state.current || !confirm(`Видалити “${state.current.name}” разом з усіма graph data?`)) return;
    try { await api(`/investigations/${state.current.id}`, { method: 'DELETE', body: '{}' }); state.current = null; state.graph = null; state.findings = []; setActions(false); renderGraph(); renderFindings(); $('#investigationTitle').textContent = 'Social Graph'; await loadInvestigations(); toast('Investigation deleted'); } catch (error) { toast(error.message, true); }
  });
  async function createDemo() { try { const payload = await api('/demo', { method: 'POST', body: '{}' }); await loadInvestigations(payload.investigation.id); toast('Demo graph ready'); } catch (error) { toast(error.message, true); } }
  $('#createDemo').addEventListener('click', createDemo); $('#emptyDemo').addEventListener('click', createDemo);
  $('#investigationSearch').addEventListener('input', renderInvestigationList);
  ['platformFilter','relationshipFilter','confidenceFilter','clusterFilter'].forEach((id) => document.getElementById(id).addEventListener('input', applyFilters));
  $('#graphSearch').addEventListener('input', (event) => { if (!state.cy) return; const query = event.target.value.trim().toLowerCase(); state.cy.nodes().removeClass('search-match'); if (!query) return; const matches = state.cy.nodes().filter((node) => node.data('raw').display_name.toLowerCase().includes(query) || String(node.data('raw').username || '').toLowerCase().includes(query)); matches.addClass('search-match'); if (matches.length) state.cy.animate({ fit: { eles: matches, padding: 140 } }, { duration: 300 }); });
  $('#graphSearch').addEventListener('keydown', (event) => {
    if (event.key !== 'Enter' || !state.cy) return;
    const match = state.cy.nodes('.search-match').first();
    if (!match?.length) return;
    event.preventDefault();
    match.select();
    selectEntity(match.id()).catch((error) => toast(error.message, true));
  });
  $('#fitGraph').addEventListener('click', () => state.cy?.animate({ fit: { eles: state.cy.elements(':visible'), padding: 90 } }, { duration: 350 }));
  $('#toggleFindings').addEventListener('click', () => $('#findingsDrawer').classList.toggle('open'));
  $('#themeToggle').addEventListener('click', () => { const root = document.documentElement; const next = root.dataset.theme === 'dark' ? 'light' : 'dark'; root.dataset.theme = next; localStorage.setItem('osint-theme', next); if (state.graph) renderGraph(); });
  $('#logoutButton').addEventListener('click', async () => { try { await api('/auth/logout', { method: 'POST', body: '{}' }); } finally { window.location.assign('/osint'); } });
  const savedTheme = localStorage.getItem('osint-theme'); if (savedTheme) document.documentElement.dataset.theme = savedTheme; else if (matchMedia('(prefers-color-scheme:dark)').matches) document.documentElement.dataset.theme = 'dark';
  loadInvestigations().catch((error) => toast(error.message, true));
})();
