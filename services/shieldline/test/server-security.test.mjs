import assert from "node:assert/strict";
import test from "node:test";
import { createFixedWindowRateLimiter, createSessionCodec, readCookie } from "../serverSecurity.mjs";

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
