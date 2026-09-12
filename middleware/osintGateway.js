'use strict';

const { randomUUID, createHmac } = require('crypto');
const { createProxyMiddleware, fixRequestBody } = require('http-proxy-middleware');

const IDENTITY_HEADERS = [
  'x-studerria-osint-actor', 'x-studerria-osint-label', 'x-studerria-osint-timestamp',
  'x-studerria-osint-nonce', 'x-studerria-osint-signature',
];

function assertionPayload({ actorId, label, timestamp, nonce }) {
  return ['v1', String(actorId), String(label), String(timestamp), String(nonce)].join('\n');
}

function createGatewayAssertion(actor, secret, { now = () => Date.now(), nonce = () => randomUUID() } = {}) {
  const fields = {
    actorId: Number(actor.id),
    label: String(actor.label || '').replace(/[\r\n]/g, ' ').slice(0, 120),
    timestamp: Math.floor(now() / 1000),
    nonce: nonce(),
  };
  fields.signature = createHmac('sha256', secret).update(assertionPayload(fields)).digest('hex');
  return fields;
}

function requireOsintAccess(req, res, next) {
  if (!req.session?.user) {
    if (req.originalUrl.startsWith('/api/')) return res.status(401).json({ ok: false, error: 'authentication_required' });
    return res.redirect(`/login?next=${encodeURIComponent(req.originalUrl || '/osint')}`);
  }
  if (!req.canAccessOsint) {
    if (req.originalUrl.startsWith('/api/')) return res.status(403).json({ ok: false, error: 'osint_permission_required' });
    return res.status(403).send('Forbidden (OSINT permission required)');
  }
  return next();
}

function createOsintProxy({ target, gatewaySecret, prefix }) {
  return createProxyMiddleware({
    target,
    changeOrigin: false,
    ws: false,
    pathRewrite: (requestPath) => `${prefix}${requestPath === '/' ? '' : requestPath}`,
    on: {
      proxyReq(proxyReq, req) {
        IDENTITY_HEADERS.forEach((header) => proxyReq.removeHeader(header));
        proxyReq.removeHeader('cookie');
        proxyReq.removeHeader('authorization');
        const assertion = createGatewayAssertion({
          id: req.session.user.id,
          label: req.session.user.full_name || req.session.user.username || req.session.username || `user-${req.session.user.id}`,
        }, gatewaySecret);
        proxyReq.setHeader('x-studerria-osint-actor', String(assertion.actorId));
        proxyReq.setHeader('x-studerria-osint-label', assertion.label);
        proxyReq.setHeader('x-studerria-osint-timestamp', String(assertion.timestamp));
        proxyReq.setHeader('x-studerria-osint-nonce', assertion.nonce);
        proxyReq.setHeader('x-studerria-osint-signature', assertion.signature);
        proxyReq.setHeader('x-request-id', String(req.headers['x-request-id'] || randomUUID()).slice(0, 100));
        fixRequestBody(proxyReq, req);
      },
      error(error, req, res) {
        console.error('OSINT proxy error', { message: error.message, path: req.originalUrl });
        if (res.headersSent) return;
        if (req.originalUrl.startsWith('/api/')) return res.status(502).json({ ok: false, error: 'osint_service_unavailable' });
        return res.status(502).send('OSINT service unavailable');
      },
    },
  });
}

function registerOsintGateway(app, {
  target = process.env.OSINT_PROXY_TARGET || 'http://osint-graph:8080',
  gatewaySecret = process.env.OSINT_GATEWAY_SECRET || '',
} = {}) {
  if (process.env.NODE_ENV === 'production' && gatewaySecret.length < 32) {
    throw new Error('OSINT_GATEWAY_SECRET must contain at least 32 characters in production');
  }
  const secret = gatewaySecret || 'local-only-osint-gateway-secret-change-me';
  app.use('/api/osint', requireOsintAccess, createOsintProxy({ target, gatewaySecret: secret, prefix: '/api/osint' }));
  app.use('/osint', requireOsintAccess, createOsintProxy({ target, gatewaySecret: secret, prefix: '/osint' }));
}

module.exports = { IDENTITY_HEADERS, assertionPayload, createGatewayAssertion, requireOsintAccess, createOsintProxy, registerOsintGateway };
