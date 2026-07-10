import assert from "node:assert/strict";
import test from "node:test";
import { createFixedWindowRateLimiter, createPersistentSessionCodec, createSessionCodec, hashSessionToken, readCookie } from "../serverSecurity.mjs";

test("signed Shieldline sessions reject tampering and expiry", () => {
  let now = 1_000;
  const codec = createSessionCodec({ secret: "01234567890123456789012345678901", ttlSeconds: 10, now: () => now });
  const token = codec.issue("tg-42");
  assert.equal(codec.verify(token), "tg-42");
  assert.equal(codec.verify(`${token}x`), null);
  now = 12_000;
  assert.equal(codec.verify(token), null);
});

test("cookie parsing and fixed-window limiting are deterministic", () => {
  assert.equal(readCookie("foo=1; shieldline_sid=abc.def; bar=2", "shieldline_sid"), "abc.def");
  let now = 0;
  const limiter = createFixedWindowRateLimiter({ limit: 2, windowMs: 100, now: () => now });
  assert.equal(limiter.allow("client"), true);
  assert.equal(limiter.allow("client"), true);
  assert.equal(limiter.allow("client"), false);
  now = 101;
  assert.equal(limiter.allow("client"), true);
});

test("persistent sessions store only token hashes and rotate opaque cookies", async () => {
  let now = 0;
  let tokenIndex = 0;
  const sessions = new Map();
  const repository = {
    async createSession(tokenHash, actorId, expiresAt) { sessions.set(tokenHash, { actorId, expiresAt, rotatedAt: new Date(now).toISOString() }); },
    async findSession(tokenHash) { return sessions.get(tokenHash) || null; },
    async revokeSession(tokenHash) { sessions.delete(tokenHash); },
  };
  const tokens = ["a".repeat(43), "b".repeat(43)];
  const codec = createPersistentSessionCodec({ repository, ttlSeconds: 10, rotationSeconds: 1, now: () => now, generateToken: () => tokens[tokenIndex++] });
  const issued = await codec.issue("tg-42");
  assert.equal(sessions.has(issued.token), false);
  assert.equal(sessions.has(hashSessionToken(issued.token)), true);
  assert.equal((await codec.verify(issued.token)).actorId, "tg-42");
  now = 2_000;
  const rotated = await codec.verify(issued.token);
  assert.match(rotated.replacementHeader, /shieldline_sid=b{43}/);
  assert.equal(await codec.verify(issued.token), null);
});
