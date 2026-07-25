import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { soundCueNames } from "../src/audio/soundCues";

test("sound and event lab exposes every production sound cue exactly once", async () => {
  const source = await readFile(new URL("../src/components/SoundEventLab.tsx", import.meta.url), "utf8");
  const catalogSource = source.slice(source.indexOf("export const soundEventLabGroups"), source.indexOf("const threatLabels"));
  const registered = [...catalogSource.matchAll(/cue:\s*"([^"]+)"/g)].map((match) => match[1]);

  assert.equal(registered.length, soundCueNames.length);
  assert.deepEqual(registered.sort(), [...soundCueNames].sort());
  assert.equal(new Set(registered).size, registered.length);
});

test("selected sound lab blocks do not add a one-sided accent stripe", async () => {
  const styles = await readFile(new URL("../src/styles/app.css", import.meta.url), "utf8");
  const activeRule = styles.match(/\.sound-lab-group button\.is-active\s*\{([^}]*)\}/)?.[1];

  assert.ok(activeRule);
  assert.doesNotMatch(activeRule, /border-left|inset\s+\d+px\s+0/);
});
