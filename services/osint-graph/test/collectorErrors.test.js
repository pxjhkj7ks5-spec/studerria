'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { GitHubCollector } = require('../src/collectors/github');
const { InstagramCollector } = require('../src/collectors/instagram');
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

test('Instagram collector requires an explicit provider token', async () => {
  const collector = new InstagramCollector();
  assert.equal(collector.describe().configured, false);
  await assert.rejects(() => collector.collect({ username: 'public.account' }), (error) => error.code === 'instagram_provider_not_configured');
});

test('Instagram collector accepts a public profile URL and rejects non-Instagram URLs', async () => {
  const seen = [];
  const collector = new InstagramCollector({ token: 'provider-token', fetchImpl: async (_url, options) => {
    const input = JSON.parse(options.body);
    seen.push(input.targets[0]);
    return response(200, [{ source_username: 'public.account', list_type: input.scrapeType, username: 'peer' }]);
  } });
  await collector.collect({ username: 'https://www.instagram.com/Public.Account/', direction: 'followers', limit: 10 });
  assert.deepEqual(seen, ['public.account']);
  await assert.rejects(() => collector.collect({ username: 'https://example.org/Public.Account/' }), (error) => error.code === 'instagram_invalid_username');
});

test('Instagram collector structures bounded followers and following with provider provenance', async () => {
  const requests = [];
  const collector = new InstagramCollector({
    token: 'provider-token', maxConnections: 4, maxCostUsd: 1,
    fetchImpl: async (url, options) => {
      requests.push({ url, options, body: JSON.parse(options.body) });
      const rows = JSON.parse(options.body).scrapeType === 'followers'
        ? [
          { source_username: 'seed.name', list_type: 'followers', username: 'alice', full_name: 'Alice', user_id: '1' },
          { source_username: 'seed.name', list_type: 'followers', username: 'mutual', full_name: 'Mutual', user_id: '2' },
        ]
        : [
          { source_username: 'seed.name', list_type: 'following', username: 'mutual', full_name: 'Mutual', user_id: '2' },
          { source_username: 'seed.name', list_type: 'following', username: 'bob', full_name: 'Bob', user_id: '3', private: true },
        ];
      return response(200, rows);
    },
  });
  const dataset = await collector.collect({ username: '@Seed.Name', direction: 'both', limit: 4 });
  assert.equal(collector.describe().official, false);
  assert.equal(dataset.entities.length, 4);
  assert.equal(dataset.relationships.length, 4);
  assert.ok(dataset.relationships.some((item) => item.source === 'instagram:alice' && item.target === 'instagram:seed.name'));
  assert.ok(dataset.relationships.some((item) => item.source === 'instagram:seed.name' && item.target === 'instagram:bob'));
  assert.equal(dataset.relationships.every((item) => item.confidence === 0.9 && item.metadata.direct_platform_api === false), true);
  assert.equal(requests.length, 2);
  assert.equal(requests.every((item) => item.options.headers.authorization === 'Bearer provider-token'), true);
  assert.equal(requests.every((item) => !item.url.includes('provider-token') && item.body.maxResults === 2), true);
});

test('Instagram collector maps provider authorization failures without leaking the token', async () => {
  const collector = new InstagramCollector({ token: 'do-not-leak', fetchImpl: async () => response(401) });
  await assert.rejects(() => collector.collect({ username: 'seed' }), (error) => error.code === 'instagram_provider_unauthorized' && !error.message.includes('do-not-leak'));
});

test('Instagram collector preserves a successful direction when the other provider request fails', async () => {
  const collector = new InstagramCollector({ token: 'provider-token', fetchImpl: async (_url, options) => {
    const input = JSON.parse(options.body);
    return input.scrapeType === 'followers'
      ? response(200, [{ source_username: 'seed', list_type: 'followers', username: 'alice' }])
      : response(429);
  } });
  const dataset = await collector.collect({ username: 'seed', direction: 'both', limit: 10 });
  assert.equal(dataset.relationships.length, 1);
  assert.equal(dataset.provider.partial, true);
  assert.deepEqual(dataset.provider.warnings, ['instagram_provider_rate_limited']);
});
