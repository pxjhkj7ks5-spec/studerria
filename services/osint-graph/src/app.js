'use strict';

const path = require('path');
const fs = require('fs');
const { randomUUID } = require('crypto');
const express = require('express');
const helmet = require('helmet');
const multer = require('multer');
const { createAssertionVerifier, gatewayAuthMiddleware } = require('./auth/gatewayAssertion');
const { parseImportFiles, parseJsonDataset } = require('./import/parser');
const { analyzeGraph, buildGraph, shortestPath } = require('./analysis/graphEngine');
const { attachConnectionScores } = require('./jobs');
const { normalizeEntityInput, cleanText } = require('./security/validation');

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

function safeApiError(error) {
  const code = String(error?.code || error?.message || 'internal_error').split('\n')[0].slice(0, 160);
  const known = new Set([
    'investigation_not_found','invalid_json','invalid_csv','invalid_dataset_shape','too_many_records','unknown_csv_shape',
    'unsupported_import_type','import_file_required','graph_node_limit_exceeded','graph_relationship_limit_exceeded',
    'invalid_entity_type','invalid_relationship_type','invalid_username','invalid_url','required_text_missing','text_too_long',
    'self_relationship','invalid_weight','invalid_confidence','metadata_too_deep','metadata_too_large','invalid_metadata_key',
  ]);
  if (code.startsWith('relationship_reference_missing:')) return { status: 400, code: 'relationship_reference_missing' };
  if (known.has(code)) return { status: error.status || (code === 'investigation_not_found' ? 404 : 400), code };
  return { status: error?.status || 500, code: error?.status && error.status < 500 ? code : 'internal_error' };
}

function createApp({ config, store, collectors, executor }) {
  const app = express();
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

  app.get('/api/osint/health', async (_req, res) => {
    try {
      const database = await store.health();
      return res.json({ ok: true, status: 'healthy', database: database.database, databaseUser: database.user });
    } catch (_error) {
      return res.status(503).json({ ok: false, status: 'unhealthy' });
    }
  });

  const verify = createAssertionVerifier({ secret: config.gatewaySecret, maxAgeSeconds: config.assertionMaxAgeSeconds });
  app.use(gatewayAuthMiddleware(verify));
  app.use(createRateLimiter({ limit: config.rateLimitPerMinute }));
  app.use('/osint/assets', express.static(path.join(__dirname, '..', 'public'), { immutable: config.isProduction, maxAge: config.isProduction ? '1d' : 0 }));
  app.get('/osint/vendor/cytoscape.min.js', (_req, res) => res.sendFile(require.resolve('cytoscape/dist/cytoscape.min.js')));

  app.get(['/osint', '/osint/'], (req, res) => res.render('index', {
    actor: req.osintActor,
    limits: { maxNodes: config.maxGraphNodes, warningNodes: config.warningGraphNodes },
  }));

  app.get('/api/osint/collectors', (_req, res) => res.json({ ok: true, collectors: Array.from(collectors.entries()).filter(([key]) => key !== 'manual').map(([key, collector]) => ({ key, ...collector.describe() })) }));
  app.get('/api/osint/investigations', async (_req, res, next) => {
    try { res.json({ ok: true, investigations: await store.listInvestigations() }); } catch (error) { next(error); }
  });
  app.post('/api/osint/investigations', async (req, res, next) => {
    try {
      const investigation = await store.createInvestigation({ name: req.body?.name, description: req.body?.description, actorId: req.osintActor.id });
      res.status(201).json({ ok: true, investigation });
    } catch (error) { next(error); }
  });
  app.get('/api/osint/investigations/:id', async (req, res, next) => {
    try {
      const investigation = await store.getInvestigation(req.params.id);
      if (!investigation) return res.status(404).json({ ok: false, error: 'investigation_not_found' });
      return res.json({ ok: true, investigation, findings: await store.listFindings(req.params.id) });
    } catch (error) { return next(error); }
  });
  app.delete('/api/osint/investigations/:id', async (req, res, next) => {
    try {
      const deleted = await store.deleteInvestigation(req.params.id, req.osintActor.id);
      if (!deleted) return res.status(404).json({ ok: false, error: 'investigation_not_found' });
      return res.json({ ok: true, deleted });
    } catch (error) { return next(error); }
  });
  app.post('/api/osint/investigations/:id/entities', async (req, res, next) => {
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
      const allowed = (name.endsWith('.json') && jsonMime) || (name.endsWith('.csv') && csvMime);
      callback(allowed ? null : new Error('unsupported_import_type'), allowed);
    },
  });
  app.post('/api/osint/investigations/:id/import', upload.array('files', 2), async (req, res, next) => {
    try {
      const dataset = parseImportFiles(req.files, { maxRecords: config.maxImportRecords });
      const result = await store.importDataset(req.params.id, dataset, {
        actorId: req.osintActor.id,
        collector: 'manual-import',
        maxNodes: config.maxGraphNodes,
        maxRelationships: config.maxGraphRelationships,
      });
      return res.status(201).json({ ok: true, result });
    } catch (error) { return next(error); }
  });
  app.post('/api/osint/demo', async (req, res, next) => {
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
  app.post('/api/osint/investigations/:id/collect', async (req, res, next) => {
    try {
      const collectorKey = cleanText(req.body?.collector, { max: 40, required: true }).toLowerCase();
      if (!['github', 'web'].includes(collectorKey) || !collectors.has(collectorKey)) return res.status(400).json({ ok: false, error: 'collector_not_supported' });
      const parameters = collectorKey === 'github'
        ? { username: cleanText(req.body?.username, { max: 160, required: true }), depth: Math.min(2, Math.max(1, Number(req.body?.depth) || 1)) }
        : { url: cleanText(req.body?.url, { max: 2048, required: true }) };
      const run = await store.createRun({ investigationId: req.params.id, kind: 'COLLECTOR', collector: collectorKey, parameters, actorId: req.osintActor.id });
      executor.enqueue(run);
      return res.status(202).json({ ok: true, run });
    } catch (error) { return next(error); }
  });
  app.post('/api/osint/investigations/:id/analyze', async (req, res, next) => {
    try {
      const run = await store.createRun({ investigationId: req.params.id, kind: 'ANALYSIS', parameters: {}, actorId: req.osintActor.id });
      executor.enqueue(run);
      return res.status(202).json({ ok: true, run });
    } catch (error) { return next(error); }
  });
  app.get('/api/osint/investigations/:id/runs/:runId', async (req, res, next) => {
    try {
      const run = await store.getRun(req.params.id, req.params.runId);
      if (!run) return res.status(404).json({ ok: false, error: 'run_not_found' });
      return res.json({ ok: true, run });
    } catch (error) { return next(error); }
  });
  app.get('/api/osint/investigations/:id/graph', async (req, res, next) => {
    try {
      const graph = await store.getGraph(req.params.id);
      const analysis = analyzeGraph(graph.entities, graph.relationships);
      return res.json({ ok: true, graph, analysis, limits: { maxNodes: config.maxGraphNodes, warningNodes: config.warningGraphNodes } });
    } catch (error) { return next(error); }
  });
  app.get('/api/osint/investigations/:id/entities/:entityId', async (req, res, next) => {
    try {
      const entity = await store.getEntity(req.params.id, req.params.entityId);
      if (!entity) return res.status(404).json({ ok: false, error: 'entity_not_found' });
      const graph = await store.getGraph(req.params.id);
      return res.json({ ok: true, entity, connectionScores: attachConnectionScores(graph, req.params.entityId) });
    } catch (error) { return next(error); }
  });
  app.get('/api/osint/investigations/:id/entities/:entityId/neighbors', async (req, res, next) => {
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
  app.get('/api/osint/investigations/:id/path', async (req, res, next) => {
    try {
      const graphData = await store.getGraph(req.params.id);
      const pathIds = shortestPath(buildGraph(graphData.entities, graphData.relationships), req.query.from, req.query.to);
      const byId = new Map(graphData.entities.map((entity) => [String(entity.id), entity]));
      return res.json({ ok: true, path: pathIds.map((id) => byId.get(id)).filter(Boolean) });
    } catch (error) { return next(error); }
  });
  app.get('/api/osint/path', async (req, res, next) => {
    req.params.id = req.query.investigation;
    if (!req.params.id) return res.status(400).json({ ok: false, error: 'investigation_required' });
    try {
      const graphData = await store.getGraph(req.params.id);
      const pathIds = shortestPath(buildGraph(graphData.entities, graphData.relationships), req.query.from, req.query.to);
      return res.json({ ok: true, path: pathIds });
    } catch (error) { return next(error); }
  });

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
