'use strict';

const path = require('path');
const fs = require('fs');
const { randomUUID } = require('crypto');
const express = require('express');
const helmet = require('helmet');
const multer = require('multer');
const { createSessionToken, passwordMatches, readSession, requireAdminSession, requireCsrf } = require('./auth/adminSession');
const { parseImportFiles, parseJsonDataset } = require('./import/parser');
const { analyzeGraph, buildGraph, shortestPath } = require('./analysis/graphEngine');
const { attachConnectionScores } = require('./jobs');
const { normalizeEntityInput } = require('./security/validation');

function createRateLimiter({ limit, now = () => Date.now() }) {
  const buckets = new Map();
  return (req, res, next) => {
    const actor = String(req.osintActor?.id || 'anonymous');
    const minute = Math.floor(now() / 60000);
    const key = `${actor}:${minute}`;
    const count = (buckets.get(key) || 0) + 1;
    buckets.set(key, count);
    if (buckets.size > 2000) {
      for (const oldKey of buckets.keys()) if (!oldKey.endsWith(`:${minute}`)) buckets.delete(oldKey);
    }
    res.setHeader('RateLimit-Limit', String(limit));
    res.setHeader('RateLimit-Remaining', String(Math.max(0, limit - count)));
    if (count > limit) return res.status(429).json({ ok: false, error: 'rate_limited' });
    return next();
  };
}

function createLoginLimiter({ limit = 8, windowMs = 15 * 60 * 1000, now = () => Date.now() } = {}) {
  const buckets = new Map();
  return (req, res, next) => {
    const key = String(req.ip || req.socket?.remoteAddress || 'unknown');
    const current = now();
    const bucket = buckets.get(key);
    if (!bucket || bucket.expiresAt <= current) {
      buckets.set(key, { count: 1, expiresAt: current + windowMs });
      if (buckets.size > 2000) {
        for (const [bucketKey, value] of buckets.entries()) if (value.expiresAt <= current) buckets.delete(bucketKey);
        while (buckets.size > 2000) buckets.delete(buckets.keys().next().value);
      }
      return next();
    }
    bucket.count += 1;
    if (bucket.count > limit) return res.status(429).json({ ok: false, error: 'login_rate_limited' });
    return next();
  };
}

function requireSameOrigin(req, res, next) {
  const fetchSite = String(req.headers['sec-fetch-site'] || '').toLowerCase();
  if (fetchSite === 'cross-site') return res.status(403).json({ ok: false, error: 'origin_forbidden' });
  const origin = String(req.headers.origin || '').trim();
  if (!origin) return next();
  try {
    if (new URL(origin).host !== String(req.headers.host || '')) return res.status(403).json({ ok: false, error: 'origin_forbidden' });
  } catch (_error) {
    return res.status(403).json({ ok: false, error: 'origin_forbidden' });
  }
  return next();
}

function safeApiError(error) {
  const code = String(error?.code || error?.message || 'internal_error').split('\n')[0].slice(0, 160);
  const known = new Set([
    'investigation_not_found','invalid_json','invalid_csv','invalid_dataset_shape','too_many_records','unknown_csv_shape',
    'unsupported_import_type','import_file_required','graph_node_limit_exceeded','graph_relationship_limit_exceeded',
    'invalid_instagram_export_zip','invalid_instagram_export_json','instagram_export_files_missing','instagram_export_no_connections',
    'instagram_export_too_large','instagram_export_too_many_files','instagram_export_zip_must_be_single','encrypted_import_not_supported',
    'invalid_entity_type','invalid_relationship_type','invalid_username','invalid_url','required_text_missing','text_too_long',
    'fact_requires_evidence_or_direct_observation','invalid_epistemic_status','invalid_metadata','self_relationship','invalid_weight','invalid_confidence','metadata_too_deep','metadata_too_large','invalid_metadata_key',
  ]);
  if (code.startsWith('relationship_reference_missing:')) return { status: 400, code: 'relationship_reference_missing' };
  if (known.has(code)) return { status: error.status || (code === 'investigation_not_found' ? 404 : 400), code };
  return { status: error?.status || 500, code: error?.status && error.status < 500 ? code : 'internal_error' };
}

function createApp({ config, store, collectors, executor }) {
  const app = express();
  const apiBase = `${config.basePath}/api`;
  app.disable('x-powered-by');
  app.set('views', path.join(__dirname, '..', 'views'));
  app.set('view engine', 'ejs');
  app.use((req, res, next) => {
    req.requestId = String(req.headers['x-request-id'] || randomUUID()).slice(0, 100);
    res.setHeader('X-Request-Id', req.requestId);
    req.requestStartedAt = Date.now();
    res.on('finish', () => {
      console.info(JSON.stringify({ event: 'osint_request', request_id: req.requestId, method: req.method, path: req.path, status: res.statusCode, duration_ms: Date.now() - req.requestStartedAt, actor_id: req.osintActor?.id || null }));
    });
    next();
  });
  app.use(helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'https:'],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'self'"],
      },
    },
    crossOriginEmbedderPolicy: false,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  }));
  app.use(express.json({ limit: config.maxImportBytes }));

  app.get(`${apiBase}/health`, async (_req, res) => {
    try {
      const database = await store.health();
      return res.json({ ok: true, status: 'healthy', database: database.database, databaseUser: database.user });
    } catch (_error) {
      return res.status(503).json({ ok: false, status: 'unhealthy' });
    }
  });

  app.use(`${config.basePath}/assets`, express.static(path.join(__dirname, '..', 'public'), { immutable: config.isProduction, maxAge: config.isProduction ? '1d' : 0 }));
  app.get(`${config.basePath}/vendor/cytoscape.min.js`, (_req, res) => res.sendFile(require.resolve('cytoscape/dist/cytoscape.min.js')));
  app.post(`${apiBase}/auth/login`, requireSameOrigin, createLoginLimiter(), async (req, res) => {
    const username = String(req.body?.username || '').trim().slice(0, 120);
    const password = String(req.body?.password || '').slice(0, 256);
    if (!passwordMatches(username, config.adminUsername) || !passwordMatches(password, config.adminPassword)) {
      console.warn(JSON.stringify({ event: 'osint_login_failed', request_id: req.requestId }));
      return res.status(401).json({ ok: false, error: 'invalid_credentials' });
    }
    const token = createSessionToken({ username: config.adminUsername, secret: config.sessionSecret, ttlSeconds: config.adminSessionTtlSeconds });
    res.cookie(config.adminCookieName, token, {
      httpOnly: true,
      secure: config.adminCookieSecure,
      sameSite: 'strict',
      path: config.basePath,
      maxAge: config.adminSessionTtlSeconds * 1000,
    });
    await store.audit(1, 'auth.login', 'session', null, { username: config.adminUsername });
    return res.json({ ok: true });
  });

  app.get([config.basePath, `${config.basePath}/`], (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    const actor = readSession(req, config);
    if (!actor) return res.render('login', { basePath: config.basePath });
    return res.render('index', {
      actor,
      csrfToken: actor.csrf,
      limits: { maxNodes: config.maxGraphNodes, warningNodes: config.warningGraphNodes },
    });
  });

  app.use(apiBase, (_req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
  }, requireAdminSession(config), requireCsrf, createRateLimiter({ limit: config.rateLimitPerMinute }));
  app.post(`${apiBase}/auth/logout`, async (req, res) => {
    res.clearCookie(config.adminCookieName, { httpOnly: true, secure: config.adminCookieSecure, sameSite: 'strict', path: config.basePath });
    await store.audit(req.osintActor.id, 'auth.logout', 'session', null, { username: req.osintActor.label });
    return res.json({ ok: true });
  });
  app.get(`${apiBase}/auth/session`, (req, res) => res.json({ ok: true, actor: { label: req.osintActor.label }, csrfToken: req.osintActor.csrf }));

  app.get('/osint/api/collectors', (_req, res) => res.json({ ok: true, collectors: [] }));
  app.get('/osint/api/investigations', async (_req, res, next) => {
    try { res.json({ ok: true, investigations: await store.listInvestigations() }); } catch (error) { next(error); }
  });
  app.post('/osint/api/investigations', async (req, res, next) => {
    try {
      const investigation = await store.createInvestigation({ name: req.body?.name, description: req.body?.description, actorId: req.osintActor.id });
      res.status(201).json({ ok: true, investigation });
    } catch (error) { next(error); }
  });
  app.get('/osint/api/investigations/:id', async (req, res, next) => {
    try {
      const investigation = await store.getInvestigation(req.params.id);
      if (!investigation) return res.status(404).json({ ok: false, error: 'investigation_not_found' });
      return res.json({ ok: true, investigation, findings: await store.listFindings(req.params.id) });
    } catch (error) { return next(error); }
  });
  app.delete('/osint/api/investigations/:id', async (req, res, next) => {
    try {
      const deleted = await store.deleteInvestigation(req.params.id, req.osintActor.id);
      if (!deleted) return res.status(404).json({ ok: false, error: 'investigation_not_found' });
      return res.json({ ok: true, deleted });
    } catch (error) { return next(error); }
  });
  app.post('/osint/api/investigations/:id/entities', async (req, res, next) => {
    try {
      normalizeEntityInput(req.body || {});
      const current = await store.getGraph(req.params.id);
      if (current.entities.length >= config.maxGraphNodes) return res.status(409).json({ ok: false, error: 'graph_node_limit_exceeded' });
      const entity = await store.addEntity(req.params.id, req.body, { actorId: req.osintActor.id });
      return res.status(201).json({ ok: true, entity });
    } catch (error) { return next(error); }
  });

  const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: config.maxImportBytes, files: 2, fields: 4, parts: 8 },
    fileFilter: (_req, file, callback) => {
      const name = String(file.originalname || '').toLowerCase();
      const mime = String(file.mimetype || '').toLowerCase();
      const jsonMime = ['application/json', 'text/json', 'application/octet-stream'].includes(mime);
      const csvMime = ['text/csv', 'application/csv', 'application/vnd.ms-excel', 'text/plain', 'application/octet-stream'].includes(mime);
      const zipMime = ['application/zip', 'application/x-zip-compressed', 'application/octet-stream'].includes(mime);
      const allowed = (name.endsWith('.json') && jsonMime) || (name.endsWith('.csv') && csvMime) || (name.endsWith('.zip') && zipMime);
      callback(allowed ? null : new Error('unsupported_import_type'), allowed);
    },
  });
  app.post('/osint/api/investigations/:id/import', upload.array('files', 2), async (req, res, next) => {
    try {
      const isInstagramExport = req.files?.length === 1 && String(req.files[0].originalname || '').toLowerCase().endsWith('.zip');
      const dataset = await parseImportFiles(req.files, {
        maxRecords: config.maxImportRecords,
        ownerUsername: req.body?.instagram_username,
        maxUncompressedBytes: config.maxImportBytes * 2,
      });
      const result = await store.importDataset(req.params.id, dataset, {
        actorId: req.osintActor.id,
        collector: isInstagramExport ? 'instagram-data-export' : 'manual-import',
        maxNodes: config.maxGraphNodes,
        maxRelationships: config.maxGraphRelationships,
      });
      return res.status(201).json({ ok: true, result });
    } catch (error) { return next(error); }
  });
  app.post('/osint/api/demo', async (req, res, next) => {
    try {
      const file = fs.readFileSync(path.join(__dirname, '..', 'fixtures', 'demo-social-graph.json'));
      const dataset = parseJsonDataset(file, { maxRecords: config.maxImportRecords });
      const investigation = await store.createInvestigation({ name: 'Demo · Public Signals', description: 'Fictitious data for safe product evaluation.', actorId: req.osintActor.id });
      const result = await store.importDataset(investigation.id, dataset, {
        actorId: req.osintActor.id,
        collector: 'demo-fixture',
        maxNodes: config.maxGraphNodes,
        maxRelationships: config.maxGraphRelationships,
      });
      return res.status(201).json({ ok: true, investigation, result });
    } catch (error) { return next(error); }
  });
  app.post('/osint/api/investigations/:id/collect', (_req, res) => res.status(410).json({ ok: false, error: 'collectors_disabled_manual_workspace' }));
  app.post('/osint/api/investigations/:id/analyze', async (req, res, next) => {
    try {
      const run = await store.createRun({ investigationId: req.params.id, kind: 'ANALYSIS', parameters: {}, actorId: req.osintActor.id });
      executor.enqueue(run);
      return res.status(202).json({ ok: true, run });
    } catch (error) { return next(error); }
  });
  app.get('/osint/api/investigations/:id/runs/:runId', async (req, res, next) => {
    try {
      const run = await store.getRun(req.params.id, req.params.runId);
      if (!run) return res.status(404).json({ ok: false, error: 'run_not_found' });
      return res.json({ ok: true, run });
    } catch (error) { return next(error); }
  });
  app.get('/osint/api/investigations/:id/graph', async (req, res, next) => {
    try {
      const graph = await store.getGraph(req.params.id);
      const analysis = analyzeGraph(graph.entities, graph.relationships);
      return res.json({ ok: true, graph, analysis, limits: { maxNodes: config.maxGraphNodes, warningNodes: config.warningGraphNodes } });
    } catch (error) { return next(error); }
  });
  app.get('/osint/api/investigations/:id/entities/:entityId', async (req, res, next) => {
    try {
      const entity = await store.getEntity(req.params.id, req.params.entityId);
      if (!entity) return res.status(404).json({ ok: false, error: 'entity_not_found' });
      const graph = await store.getGraph(req.params.id);
      return res.json({ ok: true, entity, connectionScores: attachConnectionScores(graph, req.params.entityId) });
    } catch (error) { return next(error); }
  });
  app.get('/osint/api/investigations/:id/entities/:entityId/neighbors', async (req, res, next) => {
    try {
      const depth = Math.min(2, Math.max(1, Number(req.query.depth) || 1));
      const graphData = await store.getGraph(req.params.id);
      const graph = buildGraph(graphData.entities, graphData.relationships);
      const root = String(req.params.entityId);
      if (!graph.nodes.has(root)) return res.status(404).json({ ok: false, error: 'entity_not_found' });
      const ids = new Set([root]);
      let frontier = [root];
      for (let hop = 0; hop < depth; hop += 1) {
        const nextFrontier = [];
        for (const node of frontier) for (const neighbor of graph.undirected.get(node)) if (!ids.has(neighbor)) { ids.add(neighbor); nextFrontier.push(neighbor); }
        frontier = nextFrontier;
      }
      return res.json({ ok: true, depth, entities: graphData.entities.filter((entity) => ids.has(String(entity.id))).slice(0, config.maxGraphNodes) });
    } catch (error) { return next(error); }
  });
  app.get('/osint/api/investigations/:id/path', async (req, res, next) => {
    try {
      const graphData = await store.getGraph(req.params.id);
      const pathIds = shortestPath(buildGraph(graphData.entities, graphData.relationships), req.query.from, req.query.to);
      const byId = new Map(graphData.entities.map((entity) => [String(entity.id), entity]));
      return res.json({ ok: true, path: pathIds.map((id) => byId.get(id)).filter(Boolean) });
    } catch (error) { return next(error); }
  });
  app.get('/osint/api/path', async (req, res, next) => {
    req.params.id = req.query.investigation;
    if (!req.params.id) return res.status(400).json({ ok: false, error: 'investigation_required' });
    try {
      const graphData = await store.getGraph(req.params.id);
      const pathIds = shortestPath(buildGraph(graphData.entities, graphData.relationships), req.query.from, req.query.to);
      return res.json({ ok: true, path: pathIds });
    } catch (error) { return next(error); }
  });

  require('./workspace').registerWorkspace(app, { store, config });

  app.use((error, _req, res, _next) => {
    if (error instanceof multer.MulterError) {
      return res.status(error.code === 'LIMIT_FILE_SIZE' ? 413 : 400).json({ ok: false, error: error.code.toLowerCase() });
    }
    const safe = safeApiError(error);
    if (safe.status >= 500) console.error(JSON.stringify({ event: 'osint_error', error: String(error?.message || error).slice(0, 200) }));
    return res.status(safe.status).json({ ok: false, error: safe.code });
  });
  return app;
}

module.exports = { createApp, createRateLimiter, safeApiError };
