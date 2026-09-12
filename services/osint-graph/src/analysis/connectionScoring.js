'use strict';

const DEFAULT_SCORING = Object.freeze({
  mutualFollow: 20,
  commonConnectionEach: 5,
  commonConnectionsMax: 25,
  interactionEach: 5,
  interactionsMax: 25,
  mentionEach: 5,
  mentionsMax: 15,
  sharedOrganization: 15,
});

function scoreConnection({ leftId, rightId, entities = [], relationships = [], interactions = [], commonNeighborIds = [] }, weights = DEFAULT_SCORING) {
  const left = String(leftId);
  const right = String(rightId);
  const between = relationships.filter((edge) => {
    const source = String(edge.source_entity_id);
    const target = String(edge.target_entity_id);
    return (source === left && target === right) || (source === right && target === left);
  });
  const followsForward = between.some((edge) => edge.relationship_type === 'FOLLOWS' && String(edge.source_entity_id) === left);
  const followsBack = between.some((edge) => edge.relationship_type === 'FOLLOWS' && String(edge.source_entity_id) === right);
  const explicitMutual = between.some((edge) => edge.relationship_type === 'MUTUAL_FOLLOW');
  const components = [];
  if ((followsForward && followsBack) || explicitMutual) {
    components.push({ key: 'mutual_follow', points: weights.mutualFollow, explanation: 'Public reciprocal follow is observed.' });
  }
  const commonPoints = Math.min(weights.commonConnectionsMax, commonNeighborIds.length * weights.commonConnectionEach);
  if (commonPoints) components.push({ key: 'common_connections', points: commonPoints, explanation: `${commonNeighborIds.length} common observed connection(s).` });
  const pairInteractions = interactions.filter((event) => {
    const source = String(event.source_entity_id);
    const target = String(event.target_entity_id);
    return (source === left && target === right) || (source === right && target === left);
  });
  const interactionPoints = Math.min(weights.interactionsMax, pairInteractions.length * weights.interactionEach);
  if (interactionPoints) components.push({ key: 'public_interactions', points: interactionPoints, explanation: `${pairInteractions.length} public interaction(s) are recorded.` });
  const mentionCount = between.filter((edge) => edge.relationship_type === 'MENTIONS').length;
  const mentionPoints = Math.min(weights.mentionsMax, mentionCount * weights.mentionEach);
  if (mentionPoints) components.push({ key: 'co_mentions', points: mentionPoints, explanation: `${mentionCount} public mention relationship(s).` });
  const entityById = new Map(entities.map((entity) => [String(entity.id), entity]));
  const sharedOrganizationIds = commonNeighborIds.filter((id) => ['ORGANIZATION', 'PUBLIC_CHANNEL'].includes(entityById.get(String(id))?.type));
  if (sharedOrganizationIds.length) {
    components.push({ key: 'shared_organization', points: weights.sharedOrganization, explanation: 'A shared public organization or community is observed.' });
  }
  const total = Math.min(100, components.reduce((sum, item) => sum + item.points, 0));
  return {
    score: total,
    components,
    disclaimer: 'This structural score is not proof that two people know each other.',
  };
}

module.exports = { DEFAULT_SCORING, scoreConnection };
