'use strict';

function summarizeAnalysis({ entities = [], analysis = {} }) {
  const byId = new Map(entities.map((entity) => [String(entity.id), entity]));
  const top = (analysis.metrics || []).slice(0, 3).map((item) => byId.get(String(item.entityId))?.display_name).filter(Boolean);
  const bridgeNames = (analysis.bridgeEntityIds || []).slice(0, 5).map((id) => byId.get(String(id))?.display_name).filter(Boolean);
  const sentences = [];
  if (top.length) sentences.push(`${top.join(', ')} ${top.length === 1 ? 'is' : 'are'} structurally central in this observed network.`);
  if (bridgeNames.length) sentences.push(`${bridgeNames.join(', ')} connect otherwise less-connected parts of the observed graph.`);
  sentences.push(`The graph contains ${(analysis.connectedComponents || []).length} connected component(s). These are structural observations, not claims about personal intent or real-world leadership.`);
  return sentences.join(' ');
}

module.exports = { summarizeAnalysis };
