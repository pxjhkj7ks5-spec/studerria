'use strict';

const dns = require('dns').promises;
const http = require('http');
const https = require('https');
const net = require('net');

class SsrfError extends Error {
  constructor(code) {
    super(code);
    this.name = 'SsrfError';
    this.code = code;
  }
}

function ipv4Number(address) {
  const parts = address.split('.').map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return (((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0;
}

function inCidr4(address, network, prefix) {
  const value = ipv4Number(address);
  const base = ipv4Number(network);
  if (value === null || base === null) return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (value & mask) === (base & mask);
}

function isPublicIp(address) {
  const version = net.isIP(address);
  if (version === 4) {
    const blocked = [
      ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
      ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.168.0.0', 16],
      ['198.18.0.0', 15], ['224.0.0.0', 4], ['240.0.0.0', 4],
    ];
    return !blocked.some(([network, prefix]) => inCidr4(address, network, prefix));
  }
  if (version === 6) {
    const normalized = address.toLowerCase();
    if (normalized === '::' || normalized === '::1') return false;
    if (normalized.startsWith('fc') || normalized.startsWith('fd') || /^fe[89ab]/.test(normalized)) return false;
    if (normalized.startsWith('ff')) return false;
    const mapped = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    return mapped ? isPublicIp(mapped[1]) : true;
  }
  return false;
}

function validateUrlShape(rawUrl) {
  let url;
  try { url = new URL(String(rawUrl || '')); } catch (_error) { throw new SsrfError('invalid_url'); }
  if (!['http:', 'https:'].includes(url.protocol)) throw new SsrfError('unsupported_scheme');
  if (url.username || url.password) throw new SsrfError('credentials_not_allowed');
  const hostname = url.hostname.toLowerCase().replace(/\.$/, '');
  if (!hostname || hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.local')) throw new SsrfError('blocked_hostname');
  if (['metadata.google.internal', 'metadata', 'instance-data', '169.254.169.254'].includes(hostname)) throw new SsrfError('blocked_hostname');
  const port = url.port ? Number(url.port) : (url.protocol === 'https:' ? 443 : 80);
  if (![80, 443].includes(port)) throw new SsrfError('blocked_port');
  return url;
}

async function resolvePublicAddress(url, resolver = dns.lookup) {
  const directVersion = net.isIP(url.hostname);
  const records = directVersion
    ? [{ address: url.hostname, family: directVersion }]
    : await resolver(url.hostname, { all: true, verbatim: true });
  if (!records.length || records.some((record) => !isPublicIp(record.address))) throw new SsrfError('private_address');
  return records[0];
}

async function safeFetchHtml(rawUrl, {
  timeoutMs = 15000,
  maxBytes = 2 * 1024 * 1024,
  maxRedirects = 3,
  resolver = dns.lookup,
  requestImpl = null,
} = {}) {
  async function fetchOne(value, redirectsLeft) {
    const url = validateUrlShape(value);
    const address = await resolvePublicAddress(url, resolver);
    if (requestImpl) return requestImpl({ url, address, redirectsLeft });
    const transport = url.protocol === 'https:' ? https : http;
    return new Promise((resolve, reject) => {
      const request = transport.request(url, {
        method: 'GET',
        headers: { 'user-agent': 'Studerria-Social-Graph/0.1 (+public-metadata-only)', accept: 'text/html,application/xhtml+xml' },
        timeout: timeoutMs,
        servername: url.hostname,
        lookup: (_hostname, _options, callback) => callback(null, address.address, address.family),
      }, (response) => {
        const status = Number(response.statusCode || 0);
        if ([301, 302, 303, 307, 308].includes(status) && response.headers.location) {
          response.resume();
          if (redirectsLeft < 1) return reject(new SsrfError('too_many_redirects'));
          return resolve(fetchOne(new URL(response.headers.location, url).toString(), redirectsLeft - 1));
        }
        if (status < 200 || status >= 300) {
          response.resume();
          return reject(new SsrfError(`http_${status}`));
        }
        const type = String(response.headers['content-type'] || '').toLowerCase();
        if (!type.includes('text/html') && !type.includes('application/xhtml+xml')) {
          response.resume();
          return reject(new SsrfError('unsupported_content_type'));
        }
        const declared = Number(response.headers['content-length'] || 0);
        if (declared > maxBytes) {
          response.resume();
          return reject(new SsrfError('response_too_large'));
        }
        const chunks = [];
        let total = 0;
        response.on('data', (chunk) => {
          total += chunk.length;
          if (total > maxBytes) {
            response.destroy(new SsrfError('response_too_large'));
            return;
          }
          chunks.push(chunk);
        });
        response.on('end', () => resolve({ url: url.toString(), status, html: Buffer.concat(chunks).toString('utf8'), headers: response.headers }));
        response.on('error', reject);
      });
      request.on('timeout', () => request.destroy(new SsrfError('request_timeout')));
      request.on('error', reject);
      request.end();
    });
  }
  return fetchOne(rawUrl, maxRedirects);
}

module.exports = { SsrfError, ipv4Number, inCidr4, isPublicIp, validateUrlShape, resolvePublicAddress, safeFetchHtml };
