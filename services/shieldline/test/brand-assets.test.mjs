import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const read = (path) => readFile(new URL(path, import.meta.url), "utf8");

test("the vector ShieldLine mark is the favicon and shared UI brand", async () => {
  const [index, offline, manifest, mark, mask, app, command, admin, auth, account, mode] = await Promise.all([
    read("../index.html"),
    read("../public/offline.html"),
    read("../public/manifest.webmanifest"),
    read("../public/shieldline-mark.svg"),
    read("../public/shieldline-mask.svg"),
    read("../src/App.tsx"),
    read("../src/components/CommandApp.tsx"),
    read("../src/components/AdminApp.tsx"),
    read("../src/components/AuthGate.tsx"),
    read("../src/components/AccountSettings.tsx"),
    read("../src/components/ModeSelection.tsx"),
  ]);

  for (const page of [index, offline]) {
    assert.match(page, /favicon\.ico\?v=4/);
    assert.match(page, /shieldline-mark\.svg\?v=4/);
    assert.match(page, /favicon-32\.png\?v=4/);
    assert.match(page, /rel="mask-icon"/);
    assert.match(page, /apple-touch-icon\.png\?v=4/);
  }
  assert.match(index, /manifest\.webmanifest\?v=4/);
  assert.match(manifest, /icon-192\.png\?v=4/);
  assert.match(manifest, /icon-512\.png\?v=4/);
  assert.match(mark, /#f6c547/);
  assert.match(mark, /stroke-width="4\.8"/);
  assert.match(mark, /M10\.5 32h43/);
  assert.match(mask, /fill="#000"/);
  for (const source of [app, command, admin, auth, account, mode]) {
    assert.match(source, /<BrandMark/);
  }
  assert.doesNotMatch(command, /<ShieldCheck/);
  assert.doesNotMatch(admin, /<ShieldCheck/);
  assert.doesNotMatch(auth, /<ShieldCheck/);
});
