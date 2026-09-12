'use strict';

const { BaseCollector } = require('./baseCollector');

class ManualCollector extends BaseCollector {
  constructor() {
    super({ name: 'manual-import', platform: 'manual', capabilities: ['json', 'entities_csv', 'relationships_csv'], rateLimit: 'server import limits' });
  }

  async collect({ dataset }) {
    return this.normalize({ entities: dataset.entities || [], relationships: dataset.relationships || [], observations: [], interactions: [] });
  }
}

module.exports = { ManualCollector };
