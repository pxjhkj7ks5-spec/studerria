'use strict';

const { BaseCollector } = require('./baseCollector');
const { safeFetchHtml, validateUrlShape } = require('../security/ssrf');

function decodeHtml(value) {
  return String(value || '').replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').trim();
}

function extractPage(html, pageUrl) {
  const title = decodeHtml((html.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1]).replace(/\s+/g, ' ').slice(0, 300);
  const descriptionMatch = html.match(/<meta[^>]+(?:name|property)=["'](?:description|og:description)["'][^>]+content=["']([^"']*)["']/i)
    || html.match(/<meta[^>]+content=["']([^"']*)["'][^>]+(?:name|property)=["'](?:description|og:description)["']/i);
  const description = decodeHtml(descriptionMatch?.[1]).replace(/\s+/g, ' ').slice(0, 1000);
  const links = [];
  const regex = /<a\b[^>]*href=["']([^"']+)["'][^>]*>/gi;
  let match;
  while ((match = regex.exec(html)) && links.length < 500) {
    try { links.push(new URL(decodeHtml(match[1]), pageUrl).toString()); } catch (_error) { /* ignore */ }
  }
  return { title, description, links: Array.from(new Set(links)) };
}

function socialIdentity(url) {
  const patterns = [
    ['github', /^(?:www\.)?github\.com\/([^/?#]+)/i],
    ['instagram', /^(?:www\.)?instagram\.com\/([^/?#]+)/i],
    ['telegram', /^(?:t\.me|telegram\.me)\/([^/?#]+)/i],
    ['x', /^(?:www\.)?(?:x\.com|twitter\.com)\/([^/?#]+)/i],
    ['linkedin', /^(?:www\.)?linkedin\.com\/(?:in|company)\/([^/?#]+)/i],
    ['tiktok', /^(?:www\.)?tiktok\.com\/@([^/?#]+)/i],
  ];
  let parsed;
  try { parsed = new URL(url); } catch (_error) { return null; }
  for (const [platform, pattern] of patterns) {
    const match = `${parsed.hostname}${parsed.pathname}`.match(pattern);
    if (match && match[1]) return { platform, username: match[1], url: parsed.toString() };
  }
  return null;
}

class WebCollector extends BaseCollector {
  constructor({ timeoutMs = 15000, maxBytes = 2 * 1024 * 1024, maxPages = 5, fetchHtml = safeFetchHtml } = {}) {
    super({ name: 'public-web', platform: 'web', capabilities: ['title', 'description', 'links', 'social_links', 'mailto_contacts'], rateLimit: 'bounded to configured pages per run' });
    this.timeoutMs = timeoutMs;
    this.maxBytes = maxBytes;
    this.maxPages = maxPages;
    this.fetchHtml = fetchHtml;
  }

  async collect({ url }) {
    const seedUrl = validateUrlShape(url);
    const seedHost = seedUrl.hostname.toLowerCase();
    const queue = [seedUrl.toString()];
    const visited = new Set();
    const pages = [];
    while (queue.length && pages.length < this.maxPages) {
      const next = queue.shift();
      if (visited.has(next)) continue;
      visited.add(next);
      const response = await this.fetchHtml(next, { timeoutMs: this.timeoutMs, maxBytes: this.maxBytes });
      const page = extractPage(response.html, response.url);
      pages.push({ url: response.url, ...page });
      for (const link of page.links) {
        try {
          const candidate = new URL(link);
          candidate.hash = '';
          if (candidate.hostname.toLowerCase() === seedHost && ['http:', 'https:'].includes(candidate.protocol) && !visited.has(candidate.toString())) queue.push(candidate.toString());
        } catch (_error) { /* ignore */ }
      }
    }
    const domainKey = `domain:${seedHost}`;
    const websiteKey = `website:${seedUrl.origin.toLowerCase()}`;
    const entities = [
      { id: domainKey, type: 'DOMAIN', canonical_name: domainKey, display_name: seedHost, url: seedUrl.origin, metadata: {} },
      { id: websiteKey, type: 'WEBSITE', canonical_name: websiteKey, display_name: pages[0]?.title || seedHost, url: seedUrl.origin, metadata: { title: pages[0]?.title || '', description: pages[0]?.description || '', pages_observed: pages.length } },
    ];
    const relationships = [{ source: websiteKey, target: domainKey, type: 'SAME_DOMAIN', confidence: 1, source_url: pages[0]?.url || seedUrl.toString() }];
    const observations = pages.map((page) => ({ entity: websiteKey, source_type: 'PUBLIC_WEB', source_url: page.url, collector: this.name, raw_data: { title: page.title, description: page.description, outbound_link_count: page.links.length } }));
    const socialSeen = new Set();
    const emailSeen = new Set();
    for (const page of pages) {
      for (const link of page.links) {
        const social = socialIdentity(link);
        if (social) {
          const key = `${social.platform}:${social.username.toLowerCase()}`;
          if (!socialSeen.has(key)) {
            socialSeen.add(key);
            entities.push({ id: key, type: 'SOCIAL_ACCOUNT', canonical_name: key, display_name: `@${social.username}`, platform: social.platform, username: social.username, url: social.url, metadata: {} });
            relationships.push({ source: websiteKey, target: key, type: 'LINKED_TO', confidence: 1, source_url: page.url });
          }
        }
        if (link.toLowerCase().startsWith('mailto:')) {
          const email = decodeURIComponent(link.slice(7).split('?')[0]).trim().toLowerCase();
          if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && !emailSeen.has(email) && emailSeen.size < 10) {
            emailSeen.add(email);
            const key = `email:${email}`;
            entities.push({ id: key, type: 'EMAIL', canonical_name: key, display_name: email, metadata: { public_mailto: true } });
            relationships.push({ source: websiteKey, target: key, type: 'LINKED_TO', confidence: 1, source_url: page.url });
          }
        }
      }
    }
    return this.normalize({ entities, relationships, observations, interactions: [] });
  }
}

module.exports = { WebCollector, extractPage, socialIdentity };
