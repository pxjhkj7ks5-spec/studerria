import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const readSource = (relativePath) => readFile(new URL(relativePath, import.meta.url), "utf8");

test("the app checks for service worker updates without the HTTP cache", async () => {
  const source = await readSource("../src/main.tsx");

  assert.match(source, /updateViaCache:\s*"none"/);
  assert.match(source, /registration\.update\(\)/);
});

test("service worker navigations bypass Safari's HTTP cache", async () => {
  const source = await readSource("../public/sw.js");

  assert.match(source, /new Request\(event\.request, \{ cache: "no-store" \}\)/);
  assert.match(source, /shieldline-runtime-v4/);
});

test("mutable shell files are served with revalidation headers", async () => {
  const source = await readSource("../server.mjs");

  assert.match(source, /no-store, no-cache, must-revalidate/);
  assert.match(source, /Pragma: "no-cache", Expires: "0"/);
});
