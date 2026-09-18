'use strict';

function summarizeAnalysis({ entities = [], analysis = {} }) {
  const byId = new Map(entities.map((entity) => [String(entity.id), entity]));
  const top = (analysis.metrics || []).slice(0, 3).map((item) => byId.get(String(item.entityId))?.display_name).filter(Boolean);
  const bridgeNames = (analysis.bridgeEntityIds || []).slice(0, 5).map((id) => byId.get(String(id))?.display_name).filter(Boolean);
  const sentences = [];
  if (top.length) sentences.push(`Найбільше зв’язків у графі: ${top.join(', ')}.`);
  if (bridgeNames.length) sentences.push(`Частини графа з’єднують: ${bridgeNames.join(', ')}.`);
  sentences.push(`Кількість компонентів зв’язності: ${(analysis.connectedComponents || []).length}. Це структурні спостереження, а не висновки про наміри чи реальне лідерство.`);
  return sentences.join(' ');
}

module.exports = { summarizeAnalysis };
