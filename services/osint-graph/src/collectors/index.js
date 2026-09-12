'use strict';

const { GitHubCollector } = require('./github');
const { WebCollector } = require('./web');
const { ManualCollector } = require('./manual');

function createCollectors(config) {
  const collectors = new Map();
  collectors.set('github', new GitHubCollector({ token: config.githubToken, timeoutMs: config.collectorTimeoutMs, maxNodes: config.maxGraphNodes }));
  collectors.set('web', new WebCollector({ timeoutMs: config.collectorTimeoutMs, maxBytes: config.webMaxResponseBytes, maxPages: config.webMaxPages }));
  collectors.set('manual', new ManualCollector());
  return collectors;
}

module.exports = { createCollectors };
