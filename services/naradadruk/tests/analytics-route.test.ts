import assert from "node:assert/strict";
import test from "node:test";
import { POST } from "../src/app/api/analytics/route";
import { prisma } from "../src/lib/prisma";

test("analytics records direct visits and campaigns without relaxing validation", async (t) => {
  const saved: unknown[] = [];
  const original = prisma.analyticsEvent.create;
  t.after(() => { prisma.analyticsEvent.create = original; });
  prisma.analyticsEvent.create = (async (input: unknown) => {
    saved.push(input);
    return { id: 1 };
  }) as typeof original;

  for (const campaign of ["", undefined, "telegram-post"]) {
    const response = await POST(new Request("http://localhost/api/analytics", {
      method: "POST",
      headers: { "content-type": "application/json", "sec-fetch-site": "same-origin" },
      body: JSON.stringify({ name: "Page View", path: "/naradadruk", sessionId: "visitor", props: { campaign } }),
    }));
    assert.equal(response.status, 204);
  }
  assert.equal(saved.length, 3);
  assert.equal(JSON.stringify(saved).includes('"campaign":""'), true);
  for (const campaign of ["https://private.example/?email=person", "a".repeat(81)]) {
    const response = await POST(new Request("http://localhost/api/analytics", {
      method: "POST",
      body: JSON.stringify({ name: "Page View", props: { campaign } }),
    }));
    assert.equal(response.status, 400);
  }
  assert.equal(saved.length, 3);
});
