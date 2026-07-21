import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const read = (path) => readFile(new URL(path, import.meta.url), "utf8");

test("the vector ShieldLine mark is the favicon and shared UI brand", async () => {
  const [index, mark, app, command, admin, auth, account, mode] = await Promise.all([
    read("../index.html"),
    read("../public/shieldline-mark.svg"),
    read("../src/App.tsx"),
    read("../src/components/CommandApp.tsx"),
    read("../src/components/AdminApp.tsx"),
    read("../src/components/AuthGate.tsx"),
    read("../src/components/AccountSettings.tsx"),
    read("../src/components/ModeSelection.tsx"),
  ]);

  assert.match(index, /shieldline-mark\.svg/);
  assert.match(mark, /#f6c547/);
  assert.match(mark, /M10\.5 32h43/);
  for (const source of [app, command, admin, auth, account, mode]) {
    assert.match(source, /<BrandMark/);
  }
  assert.doesNotMatch(command, /<ShieldCheck/);
  assert.doesNotMatch(admin, /<ShieldCheck/);
  assert.doesNotMatch(auth, /<ShieldCheck/);
});
