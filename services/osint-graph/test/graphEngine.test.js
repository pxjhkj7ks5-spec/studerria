'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { buildGraph, nodeMetrics, connectedComponents, shortestPath, commonNeighbors, mutualConnections, articulationPoints, detectCommunities } = require('../src/analysis/graphEngine');
const { parseJsonDataset } = require('../src/import/parser');

const entities = ['a','b','c','d','e'].map((id) => ({ id }));
const relationships = [
  { source_entity_id: 'a', target_entity_id: 'b', relationship_type: 'FOLLOWS' },
  { source_entity_id: 'b', target_entity_id: 'a', relationship_type: 'FOLLOWS' },
  { source_entity_id: 'b', target_entity_id: 'c', relationship_type: 'LINKED_TO' },
  { source_entity_id: 'c', target_entity_id: 'd', relationship_type: 'LINKED_TO' },
];

test('graph engine calculates degrees, components, paths and mutual connections', () => {
  const graph = buildGraph(entities, relationships);
  assert.deepEqual(nodeMetrics(graph).find((item) => item.entityId === 'b'), { entityId: 'b', degree: 2, inDegree: 1, outDegree: 2 });
  assert.deepEqual(connectedComponents(graph).map((items) => items.length), [4, 1]);
  assert.deepEqual(shortestPath(graph, 'a', 'd'), ['a','b','c','d']);
  assert.deepEqual(commonNeighbors(graph, 'a', 'c'), ['b']);
  assert.deepEqual(mutualConnections(graph), [['a','b']]);
  assert.deepEqual(articulationPoints(graph), ['b','c']);
});

test('community detection returns deterministic labels for every entity', () => {
  const graph = buildGraph(entities, relationships);
  const first = Object.fromEntries(detectCommunities(graph));
  const second = Object.fromEntries(detectCommunities(graph));
  assert.deepEqual(first, second);
  assert.deepEqual(Object.keys(first).sort(), ['a','b','c','d','e']);
});

test('demo data exposes three communities and multiple structural bridges', () => {
  const dataset = parseJsonDataset(fs.readFileSync(path.join(__dirname, '..', 'fixtures', 'demo-social-graph.json')));
  const graph = buildGraph(
    dataset.entities.map((entity) => ({ id: entity.externalId })),
    dataset.relationships.map((relationship, index) => ({
      id: String(index),
      source_entity_id: relationship.source,
      target_entity_id: relationship.target,
      weight: relationship.weight,
      confidence: relationship.confidence,
    }))
  );
  assert.equal(dataset.entities.length, 24);
  assert.equal(new Set(detectCommunities(graph).values()).size, 3);
  assert.ok(articulationPoints(graph).length >= 3);
});
