import assert from "node:assert/strict";
import test from "node:test";
import { performance } from "node:perf_hooks";
import { createDeterministicRandom } from "../src/game/deterministicRandom.ts";
import { advanceSimulation, startAttackNow } from "../src/game/liveSimulation.ts";
import { createScenarioState } from "../src/game/initialState.ts";

test("campaign live simulation stays below the two-second acceptance budget", () => {
  const random = createDeterministicRandom("performance-golden");
  let game = createScenarioState(() => random.next(), "crisis", "thirty-days-under-pressure");
  game = startAttackNow(game, () => random.next());
  const started = performance.now();
  for (let index = 0; index < 1_000; index += 1) game = advanceSimulation(game, 300, () => random.next());
  const elapsed = performance.now() - started;
  assert.ok(elapsed < 2_000, `1,000 live ticks took ${elapsed.toFixed(1)}ms`);
});
