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
          id: "desktop-detection-notice",
          time: "T+00:01",
          title: "Radar Contact",
          body: "Target detected.",
          tone: "warning",
          eventType: "detection",
          locationLabel: "kyiv",
        }, {
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

async function setMovingThreat(page: import("@playwright/test").Page) {
  await page.evaluate(async () => {
    const { useGameStore } = await import("/shieldline/src/store/useGameStore.ts");
    const current = useGameStore.getState().game;
    useGameStore.setState({
      game: {
        ...current,
        liveThreats: [{
          id: "moving-zoom-target",
          kind: "geran2",
          status: "inbound",
          origin: { lat: 49.2, lng: 28.8 },
          target: { lat: 49.2, lng: 34.8 },
          targetCityId: "kyiv",
          launchSectorId: "test-sector",
          launchSectorName: "Test sector",
          progress: 0.2,
          speed: 1 / 8_000,
          speedKph: 180,
          altitudeM: 120,
          difficulty: 10,
          damage: 3,
          confidence: 95,
          classification: "confirmed-type",
          displayLabel: "Тип підтверджено: Geran-2",
          saturation: 1,
          headingDeg: 90,
          revealed: true,
          trackQuality: 95,
          fireControlQuality: 95,
          speedModifier: 1,
          damageModifier: 1,
          reward: 2,
        }],
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

test("target markers keep moving while the desktop map zooms and pans", async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem("shieldline-tutorial-complete-v1", "true");
    localStorage.setItem("shieldline-live-v7", JSON.stringify({
      state: { campaignMode: "training", activeGameMode: "training", pendingCampaignMode: null, mapMode: "live", operationPhase: "planning" },
      version: 18,
    }));
  });
  await page.goto("/shieldline/?legacy=1&mode=training");
  const map = page.locator(".leaflet-stage");
  await expect(map).toBeVisible();
  await setMovingThreat(page);

  const target = page.locator(".threat-marker-wrap[data-visual-progress]").first();
  await expect(target).toBeVisible();
  const progress = () => target.evaluate((element) => Number((element as HTMLElement).dataset.visualProgress || 0));
  const mapBox = await map.boundingBox();
  if (!mapBox) throw new Error("Desktop map did not render.");

  const beforeZoom = await progress();
  await page.mouse.move(mapBox.x + mapBox.width * 0.55, mapBox.y + mapBox.height * 0.5);
  await Promise.all([
    expect.poll(async () => target.evaluate((element, initialProgress) => {
      const currentProgress = Number((element as HTMLElement).dataset.visualProgress || 0);
      const transform = getComputedStyle(element).transform;
      return currentProgress > initialProgress + 0.004
        && transform !== "none"
        && transform !== "matrix(1, 0, 0, 1, 0, 0)";
    }, beforeZoom)).toBe(true),
    (async () => {
      for (let step = 0; step < 8; step += 1) {
        await page.mouse.wheel(0, -90);
        await page.waitForTimeout(55);
      }
    })(),
  ]);
  await expect(map).not.toHaveClass(/leaflet-zoom-anim/);

  const beforePan = await progress();
  await page.mouse.move(mapBox.x + mapBox.width * 0.55, mapBox.y + mapBox.height * 0.5);
  await page.mouse.down();
  await page.mouse.move(mapBox.x + mapBox.width * 0.48, mapBox.y + mapBox.height * 0.56, { steps: 4 });
  await expect.poll(progress).toBeGreaterThan(beforePan + 0.004);
  await page.mouse.up();
});

test("desktop shows the same live battle notices as mobile", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name.startsWith("mobile"), "Desktop-only placement check");
  await page.addInitScript(() => {
    localStorage.setItem("shieldline-tutorial-complete-v1", "true");
    localStorage.setItem("shieldline-live-v7", JSON.stringify({
      state: { campaignMode: "training", activeGameMode: "training", pendingCampaignMode: null, mapMode: "live", operationPhase: "planning" },
      version: 18,
    }));
  });
  await page.goto("/shieldline/?legacy=1&mode=training");
  await expect(page.locator(".shell--mobile-live")).toHaveCount(0);
  await expect(page.locator(".map-stage")).toBeVisible();

  await setBattleNotice(page);

  const notice = page.locator(".map-feedback-slot--launch");
  await expect(notice).toBeVisible();
  await expect(notice).toContainText("Пуски: Харків");
  await expect(notice).toBeHidden({ timeout: 6_000 });
});
