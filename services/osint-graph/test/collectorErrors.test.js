'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { GitHubCollector } = require('../src/collectors/github');
const { extractPage, socialIdentity } = require('../src/collectors/web');

function response(status, payload = {}) {
  return { status, ok: status >= 200 && status < 300, headers: { get: () => '0' }, json: async () => payload };
}

test('GitHub collector reports not-found and rate-limit failures explicitly', async () => {
  await assert.rejects(() => new GitHubCollector({ fetchImpl: async () => response(404) }).collect({ username: 'missing' }), (error) => error.code === 'github_not_found');
  await assert.rejects(() => new GitHubCollector({ fetchImpl: async () => response(429) }).collect({ username: 'limited' }), (error) => error.code === 'github_rate_limited');
});

test('GitHub collector keeps official contributor provenance for public co-contributors', async () => {
  const user = (login) => ({ login, id: login === 'seed' ? 1 : 2, html_url: `https://github.com/${login}` });
  const collector = new GitHubCollector({ maxNodes: 20, fetchImpl: async (url) => {
    if (url.endsWith('/users/seed')) return response(200, { ...user('seed'), followers: 0, following: 0, public_repos: 1 });
    if (url.includes('/repos/acme/demo/contributors')) return response(200, [{ ...user('peer'), contributions: 7 }]);
    if (url.includes('/users/seed/repos')) return response(200, [{ id: 10, full_name: 'acme/demo', html_url: 'https://github.com/acme/demo', fork: false }]);
    return response(200, []);
  } });
  const dataset = await collector.collect({ username: 'seed' });
  const relation = dataset.relationships.find((item) => item.target === 'github:peer');
  assert.equal(relation.type, 'COLLABORATED_WITH');
  assert.equal(relation.source_url, 'https://github.com/acme/demo/graphs/contributors');
  assert.equal(relation.metadata.public_contributions, 7);
});

test('web normalization extracts bounded metadata and supported social links', () => {
  const page = extractPage('<title> Public Page </title><meta name="description" content="Open profile"><a href="https://github.com/octocat">GitHub</a>', 'https://example.org');
  assert.equal(page.title, 'Public Page');
  assert.equal(page.links.length, 1);
  assert.deepEqual(socialIdentity(page.links[0]), { platform: 'github', username: 'octocat', url: 'https://github.com/octocat' });
});
