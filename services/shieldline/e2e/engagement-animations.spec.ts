import { expect, test } from "@playwright/test";

async function setEngagement(page: import("@playwright/test").Page, result: "success" | "miss", progress: number) {
  await page.evaluate(async ({ result, progress }) => {
    const { useGameStore } = await import("/shieldline/src/store/useGameStore.ts");
    const current = useGameStore.getState().game;
    useGameStore.setState({
      game: {
        ...current,
        engagementEvents: [{
          id: "visual-engagement",
          unitId: "visual-battery",
          targetId: "visual-target",
          unitType: "patriot",
          startPosition: { lat: 49.1, lng: 29.4 },
          targetStartPosition: { lat: 49.8, lng: 31.1 },
          targetPredictedPosition: { lat: 49.55, lng: 30.55 },
          result,
          startedAtMs: current.elapsedMs,
          durationMs: 30_000,
          progress,
          resolved: false,
          style: "missile",
        }],
      },
    });
  }, { result, progress });
}

async function setBattleNotice(page: import("@playwright/test").Page) {
  await page.evaluate(async () => {
    const { useGameStore } = await import("/shieldline/src/store/useGameStore.ts");
    const current = useGameStore.getState().game;
    useGameStore.setState({
      game: {
        ...current,
        log: [{
          id: "desktop-launch-notice",
          time: "T+00:01",
          title: "Missile Launch",
          body: "Launch detected.",
          tone: "danger",
          eventType: "launch",
          locationLabel: "kharkiv",
        }, ...current.log],
      },
    });
  });
}

test("engagement visuals stay Leaflet-native and distinguish success from miss", async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem("shieldline-tutorial-complete-v1", "true");
    localStorage.setItem("shieldline-live-v7", JSON.stringify({
      state: { campaignMode: "training", activeGameMode: "training", pendingCampaignMode: null, mapMode: "live", operationPhase: "planning" },
      version: 18,
    }));
  });
  await page.goto("/shieldline/?legacy=1&mode=training");
  await expect(page.locator(".leaflet-stage")).toBeVisible();

  await setEngagement(page, "miss", 0.35);
  await expect(page.locator(".engagement-projectile--missile")).toBeVisible();
  await expect(page.locator(".engagement-effect--travel")).toBeVisible();
  await expect(page.locator(".leaflet-overlay-pane path")).not.toHaveCount(0);

  await setEngagement(page, "miss", 0.9);
  await expect(page.locator(".engagement-effect--miss")).toBeVisible();

  await setEngagement(page, "success", 0.9);
  await expect(page.locator(".engagement-effect--success")).toBeVisible();

  const before = await page.locator(".engagement-effect--success").boundingBox();
  await page.locator(".leaflet-stage").dispatchEvent("wheel", { deltaY: -160, bubbles: true, cancelable: true });
  await expect(page.locator(".engagement-effect--success")).toBeVisible();
  const after = await page.locator(".engagement-effect--success").boundingBox();
  expect(before && after && Number.isFinite(after.x) && Number.isFinite(after.y)).toBeTruthy();
});

test("desktop shows the same live battle notices as mobile", async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem("shieldline-tutorial-complete-v1", "true");
    localStorage.setItem("shieldline-live-v7", JSON.stringify({
      state: { campaignMode: "training", activeGameMode: "training", pendingCampaignMode: null, mapMode: "live", operationPhase: "planning" },
      version: 18,
    }));
  });
  await page.goto("/shieldline/?legacy=1&mode=training");
  await expect(page.locator(".shell--mobile-live")).toHaveCount(0);

  await setBattleNotice(page);

  const notice = page.locator(".map-feedback-slot--launch");
  await expect(notice).toBeVisible();
  await expect(notice).toContainText("Пуски: Харків");
  await expect(notice).toBeHidden({ timeout: 6_000 });
});
