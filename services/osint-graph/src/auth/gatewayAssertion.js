'use strict';

const { createHmac, timingSafeEqual } = require('crypto');

const HEADER = Object.freeze({
  actor: 'x-studerria-osint-actor',
  label: 'x-studerria-osint-label',
  timestamp: 'x-studerria-osint-timestamp',
  nonce: 'x-studerria-osint-nonce',
  signature: 'x-studerria-osint-signature',
});

function assertionPayload({ actorId, label, timestamp, nonce }) {
  return ['v1', String(actorId), String(label), String(timestamp), String(nonce)].join('\n');
}

function signAssertion(fields, secret) {
  return createHmac('sha256', secret).update(assertionPayload(fields)).digest('hex');
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left || ''), 'utf8');
  const b = Buffer.from(String(right || ''), 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}

function createAssertionVerifier({ secret, maxAgeSeconds = 60, now = () => Date.now() }) {
  const seenNonces = new Map();
  return function verify(headers = {}) {
    const actorId = Number(headers[HEADER.actor]);
    const label = String(headers[HEADER.label] || '').slice(0, 120);
    const timestamp = Number(headers[HEADER.timestamp]);
    const nonce = String(headers[HEADER.nonce] || '');
    const signature = String(headers[HEADER.signature] || '');
    const nowMs = now();
    const timestampMs = timestamp * 1000;
    const maxAgeMs = maxAgeSeconds * 1000;
    for (const [key, expiresAt] of seenNonces.entries()) {
      if (expiresAt <= nowMs) seenNonces.delete(key);
    }
    if (!Number.isSafeInteger(actorId) || actorId < 1 || !label || !Number.isFinite(timestampMs)) {
      return { ok: false, reason: 'missing_identity' };
    }
    if (!/^[a-f0-9-]{16,80}$/i.test(nonce) || Math.abs(nowMs - timestampMs) > maxAgeMs) {
      return { ok: false, reason: 'expired_assertion' };
    }
    if (seenNonces.has(nonce)) return { ok: false, reason: 'replayed_assertion' };
    const expected = signAssertion({ actorId, label, timestamp, nonce }, secret);
    if (!safeEqual(signature, expected)) return { ok: false, reason: 'invalid_signature' };
    seenNonces.set(nonce, nowMs + maxAgeMs);
    return { ok: true, actor: { id: actorId, label } };
  };
}

function gatewayAuthMiddleware(verifier) {
  return (req, res, next) => {
    const result = verifier(req.headers || {});
    if (!result.ok) return res.status(403).json({ ok: false, error: 'gateway_forbidden' });
    req.osintActor = result.actor;
    return next();
  };
}

module.exports = { HEADER, assertionPayload, signAssertion, createAssertionVerifier, gatewayAuthMiddleware };
