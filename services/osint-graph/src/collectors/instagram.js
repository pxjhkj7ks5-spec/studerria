'use strict';

const { BaseCollector } = require('./baseCollector');
const { cleanUsername } = require('../security/validation');

class InstagramCollectorError extends Error {
  constructor(code, details = {}) {
    super(code);
    this.name = 'InstagramCollectorError';
    this.code = code;
    this.details = details;
  }
}

function cleanInstagramUsername(value) {
  let candidate = String(value || '').trim();
  if (/^https?:\/\//i.test(candidate)) {
    let parsed;
    try { parsed = new URL(candidate); } catch (_error) { throw new InstagramCollectorError('instagram_invalid_username'); }
    if (!/(^|\.)instagram\.com$/i.test(parsed.hostname)) throw new InstagramCollectorError('instagram_invalid_username');
    candidate = parsed.pathname.split('/').filter(Boolean)[0] || '';
  }
  const username = cleanUsername(candidate).toLowerCase();
  if (username.length > 30 || !/^[a-z0-9._]+$/.test(username) || ['accounts', 'direct', 'explore', 'p', 'reel', 'reels', 'stories'].includes(username)) {
    throw new InstagramCollectorError('instagram_invalid_username');
  }
  return username;
}

function normalizeProviderRow(row, seedUsername, expectedDirection) {
  if (!row || typeof row !== 'object' || Array.isArray(row)) return null;
  const usernameValue = row.username || row.userName || row.handle;
  let username;
  try { username = cleanInstagramUsername(usernameValue); } catch (_error) { return null; }
  const sourceUsername = String(row.source_username || row.sourceUsername || seedUsername).replace(/^@/, '').toLowerCase();
  if (sourceUsername && sourceUsername !== seedUsername) return null;
  const listType = String(row.list_type || row.listType || expectedDirection).toLowerCase();
  if (listType !== expectedDirection) return null;
  return {
    username,
    displayName: String(row.full_name || row.fullName || row.name || `@${username}`).trim().slice(0, 500) || `@${username}`,
    instagramId: String(row.user_id || row.userId || row.id || '').slice(0, 100) || null,
    verified: Boolean(row.verified ?? row.is_verified ?? row.isVerified),
    private: Boolean(row.private ?? row.is_private ?? row.isPrivate),
    avatarUrl: typeof (row.profile_pic_url || row.profilePicUrl || row.avatar_url) === 'string'
      ? String(row.profile_pic_url || row.profilePicUrl || row.avatar_url).slice(0, 2048)
      : null,
  };
}

class InstagramCollector extends BaseCollector {
  constructor({
    token = '', actorId = 'zaver.api~instagram-followers-scraper', timeoutMs = 120000,
    maxConnections = 200, maxCostUsd = 1, fetchImpl = global.fetch,
  } = {}) {
    super({
      name: 'instagram-public-provider',
      platform: 'instagram',
      capabilities: ['public_profile', 'followers', 'following'],
      rateLimit: 'third-party provider limits and configured cost cap',
    });
    this.token = token;
    this.actorId = actorId;
    this.timeoutMs = timeoutMs;
    this.maxConnections = maxConnections;
    this.maxCostUsd = maxCostUsd;
    this.fetchImpl = fetchImpl;
  }

  describe() {
    return { ...super.describe(), configured: Boolean(this.token && this.actorId), provider: 'apify', official: false };
  }

  async requestList(username, listType, limit, costCap) {
    if (!this.token || !this.actorId) throw new InstagramCollectorError('instagram_provider_not_configured');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    const query = new URLSearchParams({
      timeout: String(Math.max(30, Math.min(300, Math.ceil(this.timeoutMs / 1000)))),
      memory: '256',
      maxItems: String(limit),
      maxTotalChargeUsd: String(costCap),
      clean: '1',
    });
    const endpoint = `https://api.apify.com/v2/actors/${encodeURIComponent(this.actorId)}/run-sync-get-dataset-items?${query}`;
    try {
      const response = await this.fetchImpl(endpoint, {
        method: 'POST',
        headers: { accept: 'application/json', authorization: `Bearer ${this.token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ targets: [username], scrapeType: listType, maxResults: limit, excludePrivate: false, enrichProfiles: false }),
        signal: controller.signal,
      });
      if ([401, 403].includes(response.status)) throw new InstagramCollectorError('instagram_provider_unauthorized');
      if (response.status === 408) throw new InstagramCollectorError('instagram_provider_timeout');
      if (response.status === 429) throw new InstagramCollectorError('instagram_provider_rate_limited');
      if (!response.ok) throw new InstagramCollectorError('instagram_provider_failed', { status: response.status });
      const payload = await response.json();
      if (!Array.isArray(payload)) throw new InstagramCollectorError('instagram_provider_invalid_response');
      return payload.slice(0, limit);
    } catch (error) {
      if (error.name === 'AbortError') throw new InstagramCollectorError('instagram_provider_timeout');
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  async collect({ username, direction = 'both', limit } = {}) {
    const seedUsername = cleanInstagramUsername(username);
    const selectedDirection = ['followers', 'following', 'both'].includes(direction) ? direction : 'both';
    const boundedLimit = Math.max(1, Math.min(this.maxConnections, Math.floor(Number(limit) || this.maxConnections)));
    const directions = selectedDirection === 'both' ? ['followers', 'following'] : [selectedDirection];
    const baseLimit = Math.floor(boundedLimit / directions.length);
    const allocations = directions.map((listType, index) => ({
      listType,
      limit: Math.max(1, baseLimit + (index < boundedLimit % directions.length ? 1 : 0)),
    }));
    const costPerRun = Math.max(0.01, Number((this.maxCostUsd / directions.length).toFixed(2)));
    const attempts = await Promise.allSettled(allocations.map(async ({ listType, limit: listLimit }) => ({
      listType,
      rows: await this.requestList(seedUsername, listType, listLimit, costPerRun),
    })));
    const batches = attempts.filter((attempt) => attempt.status === 'fulfilled').map((attempt) => attempt.value);
    const warnings = attempts.filter((attempt) => attempt.status === 'rejected').map((attempt) => String(attempt.reason?.code || attempt.reason?.message || 'instagram_provider_failed').slice(0, 120));
    if (!batches.length) throw attempts[0].reason;

    const seedKey = `instagram:${seedUsername}`;
    const profileUrl = `https://www.instagram.com/${seedUsername}/`;
    const entities = [{
      id: seedKey, type: 'SOCIAL_ACCOUNT', canonical_name: seedKey, display_name: `@${seedUsername}`,
      platform: 'instagram', username: seedUsername, url: profileUrl,
      metadata: { provider: 'apify', provider_actor: this.actorId, collection_scope: selectedDirection },
    }];
    const entityKeys = new Set([seedKey]);
    const relationships = [];
    const observations = [{
      entity: seedKey, source_type: 'THIRD_PARTY_PUBLIC_PROVIDER', source_url: profileUrl, collector: this.name,
      raw_data: { username: seedUsername, provider: 'apify', provider_actor: this.actorId, collection_scope: selectedDirection },
    }];
    const observedEntities = new Set([seedKey]);
    let rejectedRows = 0;

    for (const batch of batches) {
      for (const rawRow of batch.rows) {
        if (rawRow && typeof rawRow === 'object' && (rawRow.error || rawRow.errorMessage || rawRow.error_message)) {
          if (!warnings.includes('instagram_provider_row_error')) warnings.push('instagram_provider_row_error');
        }
        const row = normalizeProviderRow(rawRow, seedUsername, batch.listType);
        if (!row || row.username === seedUsername) { rejectedRows += 1; continue; }
        const key = `instagram:${row.username}`;
        const url = `https://www.instagram.com/${row.username}/`;
        if (!entityKeys.has(key)) {
          entityKeys.add(key);
          entities.push({
            id: key, type: 'SOCIAL_ACCOUNT', canonical_name: key, display_name: row.displayName,
            platform: 'instagram', username: row.username, url,
            metadata: { instagram_id: row.instagramId, verified: row.verified, private: row.private, avatar_url: row.avatarUrl, provider: 'apify' },
          });
        }
        if (!observedEntities.has(key)) {
          observedEntities.add(key);
          observations.push({
            entity: key, source_type: 'THIRD_PARTY_PUBLIC_PROVIDER', source_url: url, collector: this.name,
            raw_data: { username: row.username, instagram_id: row.instagramId, verified: row.verified, private: row.private, provider: 'apify' },
          });
        }
        const isFollower = batch.listType === 'followers';
        relationships.push({
          source: isFollower ? key : seedKey,
          target: isFollower ? seedKey : key,
          type: 'FOLLOWS',
          confidence: 0.9,
          source_url: `${profileUrl}${batch.listType}/`,
          metadata: { provider: 'apify', provider_actor: this.actorId, observed_list: batch.listType, direct_platform_api: false },
        });
      }
    }
    if (!relationships.length) throw new InstagramCollectorError('instagram_no_public_connections', { rejectedRows });
    return this.normalize({
      entities, relationships, observations, interactions: [], rateLimitRemaining: null,
      provider: { name: 'apify', actor: this.actorId, official: false, rejectedRows, warnings, partial: warnings.length > 0 },
    });
  }
}

module.exports = { InstagramCollector, InstagramCollectorError, cleanInstagramUsername, normalizeProviderRow };
