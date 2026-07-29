import assert from "node:assert/strict";
import test from "node:test";
import { buildAfterActionPresentation, buildCampaignCatalogPresentation, localizeThreatClass } from "../src/game/campaignPresentation";
import { createCampaignState } from "../src/game/campaignMeta";
import { createScenarioState } from "../src/game/initialState";
import type { CampaignMissionResult } from "../src/types/game";

function missionResult(overrides: Partial<CampaignMissionResult> = {}): CampaignMissionResult {
  return {
    outcome: "victory",
    missionIndex: 1,
    missionId: "first-contact",
    title: "Перший контакт",
    durationSeconds: 600,
    totalTargets: 23,
    interceptions: 21,
    impacts: 2,
    killReward: 45,
    bonusRewards: 20,
    penaltyCosts: 3,
    walletAfterMission: 86,
    civilianResilienceAfterMission: 66,
    minimumCityHp: 66,
    missionGrant: 24,
    depotHealth: 82,
    depotStock: 18,
    depotProduced: 8,
    depotLost: 2,
    objectiveMet: true,
    objectiveSummary: "Київ утримано.",
    rewardLines: [],
    ...overrides,
  };
}

test("campaign catalog presentation covers new, active and completed states", () => {
  const game = createScenarioState(() => .5);
  const fresh = buildCampaignCatalogPresentation(game);
  assert.equal(fresh.currentIndex, 1);
  assert.equal(fresh.ctaLabel, "Почати кампанію");
  assert.equal(fresh.depotStock, 10);
  assert.equal(fresh.minimumCityHp, 100);
  assert.equal(fresh.timeline[0].state, "current");

  game.campaign = createCampaignState();
  game.campaign.previousMissionResults.push(missionResult());
  game.campaign.campaignWallet = 86.5;
  game.campaign.depot.stock = 18;
  game.campaign.intermission = true;
  const active = buildCampaignCatalogPresentation(game);
  assert.equal(active.wallet, 86.5);
  assert.equal(active.currentIndex, 2);
  assert.equal(active.ctaLabel, "Продовжити кампанію");
  assert.equal(active.timeline[0].state, "completed");
  assert.equal(active.timeline[1].state, "current");
  assert.equal(active.progressPercent, 20);

  game.campaign.completed = true;
  const completed = buildCampaignCatalogPresentation(game);
  assert.equal(completed.ctaLabel, "Кампанію завершено");
  assert.ok(completed.timeline.every((item) => item.state === "completed"));
});

test("briefing and report presentation use Ukrainian labels and campaign truth", () => {
  assert.deepEqual(
    ["Recon", "Jammer", "Decoy", "Low-signature cruise", "Ballistic"].map(localizeThreatClass),
    ["Розвідники", "РЕП", "Приманки", "Малопомітні ракети", "Балістика"],
  );

  const game = createScenarioState(() => .5);
  game.campaign = createCampaignState();
  game.campaign.lastAttemptResult = missionResult({ outcome: "defeat", objectiveMet: false, failedCityId: "kyiv" });
  const report = buildAfterActionPresentation(game);
  assert.equal(report.outcomeLabel, "Поразка");
  assert.equal(report.interceptions, 21);
  assert.equal(report.totalTargets, 23);
  assert.equal(report.minimumCityHp, 66);
  assert.deepEqual(report.economy.map((line) => line.value), [24, 45, 20, -3]);
  assert.equal(report.finalWallet, 86);
});
