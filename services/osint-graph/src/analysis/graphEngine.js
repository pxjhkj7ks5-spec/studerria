'use strict';

function buildGraph(entities = [], relationships = []) {
  const nodes = new Map(entities.map((entity) => [String(entity.id), entity]));
  const outgoing = new Map();
  const incoming = new Map();
  const undirected = new Map();
  for (const id of nodes.keys()) {
    outgoing.set(id, new Set());
    incoming.set(id, new Set());
    undirected.set(id, new Set());
  }
  for (const edge of relationships) {
    const source = String(edge.source_entity_id);
    const target = String(edge.target_entity_id);
    if (!nodes.has(source) || !nodes.has(target) || source === target) continue;
    outgoing.get(source).add(target);
    incoming.get(target).add(source);
    undirected.get(source).add(target);
    undirected.get(target).add(source);
  }
  return { nodes, relationships, outgoing, incoming, undirected };
}

function nodeMetrics(graph) {
  return Array.from(graph.nodes.keys()).map((id) => ({
    entityId: id,
    degree: graph.undirected.get(id).size,
    inDegree: graph.incoming.get(id).size,
    outDegree: graph.outgoing.get(id).size,
  }));
}

function connectedComponents(graph) {
  const visited = new Set();
  const components = [];
  for (const start of graph.nodes.keys()) {
    if (visited.has(start)) continue;
    const component = [];
    const queue = [start];
    visited.add(start);
    while (queue.length) {
      const current = queue.shift();
      component.push(current);
      for (const neighbor of graph.undirected.get(current)) {
        if (!visited.has(neighbor)) {
          visited.add(neighbor);
          queue.push(neighbor);
        }
      }
    }
    components.push(component.sort());
  }
  return components.sort((a, b) => b.length - a.length || a[0].localeCompare(b[0]));
}

function shortestPath(graph, from, to, { directed = false } = {}) {
  const start = String(from);
  const target = String(to);
  if (!graph.nodes.has(start) || !graph.nodes.has(target)) return [];
  const adjacency = directed ? graph.outgoing : graph.undirected;
  const queue = [start];
  const previous = new Map([[start, null]]);
  while (queue.length) {
    const current = queue.shift();
    if (current === target) break;
    for (const neighbor of adjacency.get(current)) {
      if (!previous.has(neighbor)) {
        previous.set(neighbor, current);
        queue.push(neighbor);
      }
    }
  }
  if (!previous.has(target)) return [];
  const path = [];
  for (let current = target; current !== null; current = previous.get(current)) path.unshift(current);
  return path;
}

function commonNeighbors(graph, left, right) {
  const a = graph.undirected.get(String(left));
  const b = graph.undirected.get(String(right));
  if (!a || !b) return [];
  return Array.from(a).filter((id) => b.has(id)).sort();
}

function mutualConnections(graph) {
  const pairs = [];
  const seen = new Set();
  for (const [source, targets] of graph.outgoing.entries()) {
    for (const target of targets) {
      const key = [source, target].sort().join(':');
      if (!seen.has(key) && graph.outgoing.get(target)?.has(source)) {
        seen.add(key);
        pairs.push([source, target].sort());
      }
    }
  }
  return pairs.sort((a, b) => a.join(':').localeCompare(b.join(':')));
}

function articulationPoints(graph) {
  const discovery = new Map();
  const low = new Map();
  const parent = new Map();
  const points = new Set();
  let time = 0;
  function visit(node) {
    discovery.set(node, ++time);
    low.set(node, discovery.get(node));
    let children = 0;
    for (const neighbor of graph.undirected.get(node)) {
      if (!discovery.has(neighbor)) {
        children += 1;
        parent.set(neighbor, node);
        visit(neighbor);
        low.set(node, Math.min(low.get(node), low.get(neighbor)));
        if (!parent.has(node) && children > 1) points.add(node);
        if (parent.has(node) && low.get(neighbor) >= discovery.get(node)) points.add(node);
      } else if (parent.get(node) !== neighbor) {
        low.set(node, Math.min(low.get(node), discovery.get(neighbor)));
      }
    }
  }
  for (const node of graph.nodes.keys()) if (!discovery.has(node)) visit(node);
  return Array.from(points).sort();
}

function detectCommunities(graph, maxIterations = 12) {
  const weighted = new Map(Array.from(graph.nodes.keys()).map((id) => [id, new Map()]));
  for (const edge of graph.relationships) {
    const source = String(edge.source_entity_id);
    const target = String(edge.target_entity_id);
    if (!weighted.has(source) || !weighted.has(target) || source === target) continue;
    const value = Math.max(0.01, Number(edge.weight) || 1) * Math.max(0.01, Number(edge.confidence) || 1);
    weighted.get(source).set(target, (weighted.get(source).get(target) || 0) + value);
    weighted.get(target).set(source, (weighted.get(target).get(source) || 0) + value);
  }
  const labels = new Map(Array.from(graph.nodes.keys()).map((id) => [id, id]));
  const ordered = Array.from(graph.nodes.keys()).sort((a, b) => {
    const strength = (id) => Array.from(weighted.get(id).values()).reduce((sum, value) => sum + value, 0);
    return strength(b) - strength(a) || a.localeCompare(b);
  });
  for (let iteration = 0; iteration < maxIterations; iteration += 1) {
    let changed = false;
    for (const node of ordered) {
      const weights = new Map();
      for (const [neighbor, edgeWeight] of weighted.get(node)) {
        const label = labels.get(neighbor);
        weights.set(label, (weights.get(label) || 0) + edgeWeight);
      }
      if (!weights.size) continue;
      const best = Array.from(weights.entries()).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))[0][0];
      if (labels.get(node) !== best) {
        labels.set(node, best);
        changed = true;
      }
    }
    if (!changed) break;
  }
  const normalized = new Map();
  let index = 0;
  const groups = new Map();
  for (const [node, label] of labels.entries()) {
    if (!groups.has(label)) groups.set(label, []);
    groups.get(label).push(node);
  }
  const sortedGroups = Array.from(groups.values()).sort((a, b) => b.length - a.length || a.sort()[0].localeCompare(b.sort()[0]));
  for (const group of sortedGroups) {
    const communityId = `cluster-${++index}`;
    for (const node of group) normalized.set(node, communityId);
  }
  return normalized;
}

function analyzeGraph(entities, relationships) {
  const graph = buildGraph(entities, relationships);
  const metrics = nodeMetrics(graph).sort((a, b) => b.degree - a.degree || a.entityId.localeCompare(b.entityId));
  const communities = detectCommunities(graph);
  return {
    metrics,
    connectedComponents: connectedComponents(graph),
    bridgeEntityIds: articulationPoints(graph),
    mutualConnections: mutualConnections(graph),
    communities: Object.fromEntries(communities),
  };
}

module.exports = {
  buildGraph,
  nodeMetrics,
  connectedComponents,
  shortestPath,
  commonNeighbors,
  mutualConnections,
  articulationPoints,
  detectCommunities,
  analyzeGraph,
};
