import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const read = (path) => readFile(new URL(path, import.meta.url), "utf8");

test("the vector ShieldLine mark is the favicon and shared UI brand", async () => {
  const [index, mark, mask, app, command, admin, auth, account, mode] = await Promise.all([
    read("../index.html"),
    read("../public/shieldline-mark.svg"),
    read("../public/shieldline-mask.svg"),
    read("../src/App.tsx"),
    read("../src/components/CommandApp.tsx"),
    read("../src/components/AdminApp.tsx"),
    read("../src/components/AuthGate.tsx"),
    read("../src/components/AccountSettings.tsx"),
    read("../src/components/ModeSelection.tsx"),
  ]);

  assert.match(index, /shieldline-mark\.svg\?v=3/);
  assert.match(index, /favicon-32\.png\?v=3/);
  assert.match(index, /rel="mask-icon"/);
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
