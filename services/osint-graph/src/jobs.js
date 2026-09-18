'use strict';

const { analyzeGraph, buildGraph, commonNeighbors, shortestPath } = require('./analysis/graphEngine');
const { scoreConnection } = require('./analysis/connectionScoring');
const { summarizeAnalysis } = require('./analysis/summarizer');

function analysisFindings(graphData, analysis) {
  const byId = new Map(graphData.entities.map((entity) => [String(entity.id), entity]));
  const findings = [];
  for (const metric of analysis.metrics.slice(0, 5)) {
    const entity = byId.get(String(metric.entityId));
    if (!entity || metric.degree < 1) continue;
    findings.push({
      type: 'TOP_CONNECTED',
      title: entity.display_name,
      explanation: `${entity.display_name}: кількість окремих сусідів у графі — ${metric.degree}. Це характеристика структури, а не підтвердження реальних відносин.`,
      entityIds: [entity.id],
      metadata: metric,
    });
  }
  for (const id of analysis.bridgeEntityIds.slice(0, 10)) {
    const entity = byId.get(String(id));
    if (!entity) continue;
    findings.push({
      type: 'BRIDGE_ENTITY',
      title: entity.display_name,
      explanation: `Видалення цієї сутності розділяє частини графа. Це характеристика структури, а не впливу чи намірів.`,
      entityIds: [entity.id],
      metadata: {},
    });
  }
  const communities = new Map();
  for (const [entityId, cluster] of Object.entries(analysis.communities)) {
    if (!communities.has(cluster)) communities.set(cluster, []);
    communities.get(cluster).push(entityId);
  }
  for (const [cluster, ids] of communities.entries()) {
    if (ids.length < 2) continue;
    findings.push({
      type: 'CLUSTER',
      title: `Спільнота ${cluster.split('-').pop()} · сутностей: ${ids.length}`,
      explanation: `Ці сутності утворюють щільно пов’язану спільноту. Аналіз враховує також аналітичні висновки й гіпотези.`,
      entityIds: ids,
      metadata: { cluster, size: ids.length },
    });
  }
  for (const [left, right] of analysis.mutualConnections.slice(0, 10)) {
    const leftEntity = byId.get(String(left));
    const rightEntity = byId.get(String(right));
    if (!leftEntity || !rightEntity) continue;
    findings.push({
      type: 'MUTUAL_CONNECTION',
      title: `${leftEntity.display_name} ↔ ${rightEntity.display_name}`,
      explanation: 'У графі зафіксовано зв’язок в обох напрямках. Перевірте статус і джерела в панелі доказів.',
      confidence: null,
      entityIds: [left, right],
      metadata: {},
    });
  }
  const graph = buildGraph(graphData.entities, graphData.relationships);
  const bridgeId = analysis.bridgeEntityIds[0];
  if (bridgeId) {
    const sides = Array.from(graph.undirected.get(String(bridgeId)) || []);
    let path = [];
    for (let leftIndex = 0; leftIndex < sides.length && path.length < 3; leftIndex += 1) {
      for (let rightIndex = leftIndex + 1; rightIndex < sides.length && path.length < 3; rightIndex += 1) {
        const candidate = shortestPath(graph, sides[leftIndex], sides[rightIndex]);
        if (candidate.includes(String(bridgeId)) && candidate.length >= 3) path = candidate;
      }
    }
    if (path.length >= 3) {
      findings.push({
        type: 'INTERESTING_PATH',
        title: path.map((id) => byId.get(String(id))?.display_name || id).join(' → '),
        explanation: 'Найкоротший шлях проходить через вузол, який з’єднує частини графа. Це не є підтвердженням особистих відносин.',
        entityIds: path,
        metadata: { hops: path.length - 1 },
      });
    }
  }
  return findings;
}

class RunExecutor {
  constructor({ store, collectors, config }) {
    this.store = store;
    this.collectors = collectors;
    this.config = config;
    this.queue = [];
    this.running = 0;
  }

  enqueue(run) {
    this.queue.push(run);
    setImmediate(() => this.drain());
  }

  async drain() {
    while (this.running < this.config.runConcurrency && this.queue.length) {
      const run = this.queue.shift();
      this.running += 1;
      this.execute(run).finally(() => {
        this.running -= 1;
        setImmediate(() => this.drain());
      });
    }
  }

  async execute(run) {
    const started = Date.now();
    const active = await this.store.startRun(run.id);
    if (!active) return;
    try {
      let result;
      if (run.kind === 'COLLECTOR') {
        throw new Error('collectors_disabled_manual_workspace');
      } else {
        const graphData = await this.store.getGraph(run.investigation_id);
        const analysis = analyzeGraph(graphData.entities, graphData.relationships);
        const findings = analysisFindings(graphData, analysis);
        await this.store.saveFindings(run.investigation_id, run.id, findings);
        result = { ...analysis, findingsCount: findings.length, summary: summarizeAnalysis({ entities: graphData.entities, analysis }) };
      }
      await this.store.finishRun(run.id, { ...result, durationMs: Date.now() - started });
      await this.store.audit(run.created_by, 'run.complete', 'analysis_run', run.id, {
        investigation_id: run.investigation_id,
        kind: run.kind,
        collector: run.collector || null,
        duration_ms: Date.now() - started,
        status: 'completed',
      });
      console.info(JSON.stringify({ event: 'osint_run', run_id: run.id, collector: run.collector || null, duration_ms: Date.now() - started, status: 'completed' }));
    } catch (error) {
      await this.store.failRun(run.id, error);
      await this.store.audit(run.created_by, 'run.fail', 'analysis_run', run.id, {
        investigation_id: run.investigation_id,
        kind: run.kind,
        collector: run.collector || null,
        duration_ms: Date.now() - started,
        status: 'failed',
        error_code: String(error.code || error.message || 'run_failed').slice(0, 120),
      });
      console.error(JSON.stringify({ event: 'osint_run', run_id: run.id, collector: run.collector || null, duration_ms: Date.now() - started, status: 'failed', error: String(error.code || error.message || 'run_failed').slice(0, 120) }));
    }
  }
}

function attachConnectionScores(graphData, entityId) {
  const graph = buildGraph(graphData.entities, graphData.relationships);
  const neighborIds = Array.from(graph.undirected.get(String(entityId)) || []);
  return neighborIds.map((neighborId) => ({
    entityId: neighborId,
    ...scoreConnection({
      leftId: entityId,
      rightId: neighborId,
      entities: graphData.entities,
      relationships: graphData.relationships,
      interactions: graphData.interactions,
      commonNeighborIds: commonNeighbors(graph, entityId, neighborId),
    }),
  })).sort((a, b) => b.score - a.score || a.entityId.localeCompare(b.entityId));
}

module.exports = { RunExecutor, analysisFindings, attachConnectionScores };
