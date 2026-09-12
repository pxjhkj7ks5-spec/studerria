'use strict';

const { BaseCollector } = require('./baseCollector');
const { cleanUsername } = require('../security/validation');

class CollectorError extends Error {
  constructor(code, details = {}) {
    super(code);
    this.name = 'CollectorError';
    this.code = code;
    this.details = details;
  }
}

class GitHubCollector extends BaseCollector {
  constructor({ token = '', timeoutMs = 15000, maxNodes = 500, fetchImpl = global.fetch } = {}) {
    super({
      name: 'github-public-rest',
      platform: 'github',
      capabilities: ['profile', 'followers', 'following', 'organizations', 'repositories', 'contributors', 'public_events'],
      rateLimit: token ? '5,000 requests/hour (authenticated baseline)' : '60 requests/hour per source IP',
    });
    this.token = token;
    this.timeoutMs = timeoutMs;
    this.maxNodes = maxNodes;
    this.fetchImpl = fetchImpl;
  }

  async request(path) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetchImpl(`https://api.github.com${path}`, {
        headers: {
          accept: 'application/vnd.github+json',
          'x-github-api-version': '2022-11-28',
          'user-agent': 'Studerria-Social-Graph/0.1',
          ...(this.token ? { authorization: `Bearer ${this.token}` } : {}),
        },
        signal: controller.signal,
      });
      const remaining = Number(response.headers?.get?.('x-ratelimit-remaining'));
      if (response.status === 404) throw new CollectorError('github_not_found');
      if (response.status === 403 || response.status === 429) throw new CollectorError('github_rate_limited', { remaining: Number.isFinite(remaining) ? remaining : null });
      if (!response.ok) throw new CollectorError('github_request_failed', { status: response.status });
      return { data: response.status === 204 ? [] : await response.json(), remaining: Number.isFinite(remaining) ? remaining : null };
    } catch (error) {
      if (error.name === 'AbortError') throw new CollectorError('github_timeout');
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  async collect({ username, depth = 1 } = {}) {
    const safeUsername = cleanUsername(username);
    const boundedDepth = Math.min(2, Math.max(1, Number(depth) || 1));
    const encoded = encodeURIComponent(safeUsername);
    const profileResult = await this.request(`/users/${encoded}`);
    const profile = profileResult.data;
    const sourceUrl = profile.html_url || `https://github.com/${safeUsername}`;
    const entity = (user) => ({
      id: `github:${String(user.login).toLowerCase()}`,
      type: 'SOCIAL_ACCOUNT',
      canonical_name: `github:${String(user.login).toLowerCase()}`,
      display_name: user.name || user.login,
      platform: 'github',
      username: user.login,
      url: user.html_url || `https://github.com/${user.login}`,
      bio: user.bio || '',
      metadata: {
        github_id: user.id,
        avatar_url: user.avatar_url || null,
        company: user.company || null,
        location: user.location || null,
        blog: user.blog || null,
        followers_count: user.followers ?? null,
        following_count: user.following ?? null,
        public_repos: user.public_repos ?? null,
      },
    });
    const entities = [entity(profile)];
    const relationships = [];
    const observations = [{ entity: `github:${profile.login.toLowerCase()}`, source_type: 'GITHUB_API', source_url: sourceUrl, collector: this.name, raw_data: { login: profile.login, id: profile.id, public_repos: profile.public_repos } }];
    const interactions = [];
    const limit = Math.max(1, Math.min(100, this.maxNodes - 1));
    const [followersResult, followingResult, orgsResult, reposResult, eventsResult] = await Promise.all([
      this.request(`/users/${encoded}/followers?per_page=${limit}`),
      this.request(`/users/${encoded}/following?per_page=${limit}`),
      this.request(`/users/${encoded}/orgs?per_page=${Math.min(100, limit)}`),
      this.request(`/users/${encoded}/repos?per_page=${Math.min(50, limit)}&sort=updated`),
      this.request(`/users/${encoded}/events/public?per_page=${Math.min(30, limit)}`),
    ]);
    const remainingValues = [profileResult, followersResult, followingResult, orgsResult, reposResult, eventsResult]
      .map((result) => result.remaining).filter(Number.isFinite);
    const addUser = (user) => {
      if (entities.length >= this.maxNodes) return false;
      const key = `github:${String(user.login).toLowerCase()}`;
      if (!entities.some((item) => item.id === key)) entities.push(entity(user));
      return true;
    };
    for (const follower of followersResult.data) {
      if (!addUser(follower)) break;
      relationships.push({ source: `github:${follower.login.toLowerCase()}`, target: `github:${profile.login.toLowerCase()}`, type: 'FOLLOWS', confidence: 1, source_url: `${sourceUrl}?tab=followers` });
    }
    for (const followed of followingResult.data) {
      if (!addUser(followed)) break;
      relationships.push({ source: `github:${profile.login.toLowerCase()}`, target: `github:${followed.login.toLowerCase()}`, type: 'FOLLOWS', confidence: 1, source_url: `${sourceUrl}?tab=following` });
    }
    for (const org of orgsResult.data) {
      if (entities.length >= this.maxNodes) break;
      const key = `github-org:${String(org.login).toLowerCase()}`;
      entities.push({ id: key, type: 'ORGANIZATION', canonical_name: key, display_name: org.login, url: `https://github.com/${org.login}`, metadata: { github_id: org.id, avatar_url: org.avatar_url || null } });
      relationships.push({ source: `github:${profile.login.toLowerCase()}`, target: key, type: 'MEMBER_OF', confidence: 1, source_url: `${sourceUrl}?tab=organizations` });
    }
    for (const repo of reposResult.data) {
      if (entities.length >= this.maxNodes) break;
      const key = `github-repo:${String(repo.full_name).toLowerCase()}`;
      entities.push({ id: key, type: 'OTHER', canonical_name: key, display_name: repo.full_name, url: repo.html_url, metadata: { kind: 'GITHUB_REPOSITORY', language: repo.language || null, stars: repo.stargazers_count || 0, fork: Boolean(repo.fork) } });
      relationships.push({ source: `github:${profile.login.toLowerCase()}`, target: key, type: 'ASSOCIATED_WITH', confidence: 1, source_url: repo.html_url });
    }
    const contributorRepos = reposResult.data.filter((repo) => !repo.fork && repo.full_name).slice(0, 3);
    for (const repo of contributorRepos) {
      if (entities.length >= this.maxNodes) break;
      const result = await this.request(`/repos/${repo.full_name.split('/').map(encodeURIComponent).join('/')}/contributors?per_page=${Math.min(20, this.maxNodes - entities.length)}`);
      if (Number.isFinite(result.remaining)) remainingValues.push(result.remaining);
      for (const contributor of result.data) {
        if (!contributor.login || contributor.login.toLowerCase() === profile.login.toLowerCase()) continue;
        if (!addUser(contributor)) break;
        relationships.push({
          source: `github:${profile.login.toLowerCase()}`,
          target: `github:${contributor.login.toLowerCase()}`,
          type: 'COLLABORATED_WITH',
          weight: Math.max(1, Number(contributor.contributions) || 1),
          confidence: 1,
          source_url: `${repo.html_url}/graphs/contributors`,
          metadata: { repository: repo.full_name, public_contributions: Number(contributor.contributions) || 0 },
        });
      }
    }
    for (const event of eventsResult.data) {
      if (!event.repo?.name) continue;
      const key = `github-repo:${String(event.repo.name).toLowerCase()}`;
      if (!entities.some((item) => item.id === key) && entities.length < this.maxNodes) {
        entities.push({ id: key, type: 'OTHER', canonical_name: key, display_name: event.repo.name, url: `https://github.com/${event.repo.name}`, metadata: { kind: 'GITHUB_REPOSITORY' } });
      }
      if (entities.some((item) => item.id === key)) interactions.push({ source: `github:${profile.login.toLowerCase()}`, target: key, type: event.type || 'PUBLIC_EVENT', source_url: `https://github.com/${event.repo.name}`, timestamp: event.created_at || null, metadata: { github_event_id: event.id } });
    }
    if (boundedDepth === 2) {
      const candidates = entities.filter((item) => item.platform === 'github' && item.id !== `github:${profile.login.toLowerCase()}`).slice(0, Math.min(10, Math.floor((this.maxNodes - entities.length) / 2)));
      for (const candidate of candidates) {
        if (entities.length >= this.maxNodes) break;
        const result = await this.request(`/users/${encodeURIComponent(candidate.username)}/following?per_page=${Math.min(30, this.maxNodes - entities.length)}`);
        if (Number.isFinite(result.remaining)) remainingValues.push(result.remaining);
        for (const followed of result.data) {
          if (!addUser(followed)) break;
          relationships.push({ source: candidate.id, target: `github:${followed.login.toLowerCase()}`, type: 'FOLLOWS', confidence: 1, source_url: `${candidate.url}?tab=following` });
        }
      }
    }
    return this.normalize({ entities, relationships, observations, interactions, rateLimitRemaining: remainingValues.length ? Math.min(...remainingValues) : null });
  }
}

module.exports = { GitHubCollector, CollectorError };
