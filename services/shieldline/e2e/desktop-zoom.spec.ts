import { expect, test } from "@playwright/test";

test("desktop trackpad and mouse wheel zoom use bounded intuitive steps", async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem("shieldline-tutorial-complete-v1", "true");
    localStorage.setItem("shieldline-live-v7", JSON.stringify({
      state: { campaignMode: "training", activeGameMode: "training", pendingCampaignMode: null, mapMode: "live", operationPhase: "planning" },
      version: 15,
    }));
  });
  await page.goto("/shieldline/?legacy=1&mode=training");

  const map = page.locator(".leaflet-stage");
  await expect(map).toBeVisible();
  expect(await page.evaluate(() => matchMedia("(pointer: fine)").matches)).toBe(true);
  const cityMarkers = page.locator(".leaflet-marker-icon").filter({ has: page.locator(".city-marker-label") });
  await expect(cityMarkers.nth(1)).toBeVisible();

  const markerDistance = () => cityMarkers.evaluateAll((markers) => {
    const centers = markers.slice(0, 2).map((marker) => {
      const box = marker.getBoundingClientRect();
      return { x: box.left + box.width / 2, y: box.top + box.height / 2 };
    });
    return Math.hypot(centers[1].x - centers[0].x, centers[1].y - centers[0].y);
  });
  const before = await markerDistance();
  const mapBox = await map.boundingBox();
  if (!mapBox) throw new Error("Desktop map did not render.");
  await page.mouse.move(mapBox.x + mapBox.width * 0.55, mapBox.y + mapBox.height * 0.5);
  await page.mouse.wheel(0, -12);
  await expect.poll(markerDistance).toBeGreaterThan(before * 1.05);
  const afterTrackpadStep = await markerDistance();
  expect(afterTrackpadStep).toBeLessThan(before * 1.35);

  await page.mouse.wheel(0, -1_000);
  await expect.poll(markerDistance).toBeGreaterThan(afterTrackpadStep * 1.05);
  expect(await markerDistance()).toBeLessThan(afterTrackpadStep * 2.6);
});

test("desktop defense cards expand in flow and radar telemetry stays sensor-specific", async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem("shieldline-tutorial-complete-v1", "true");
    localStorage.setItem("shieldline-live-v7", JSON.stringify({
      state: { campaignMode: "training", activeGameMode: "training", pendingCampaignMode: null, mapMode: "live", operationPhase: "planning" },
      version: 15,
    }));
  });
  await page.goto("/shieldline/?legacy=1&mode=training");

  const drawer = page.getByRole("complementary", { name: /ППО/ });
  await expect(drawer).toBeVisible();
  await expect(page.locator(".map-feedback-slot--guidance")).toContainText("Спочатку встановіть радар");
  const cards = drawer.locator(".unit-card");
  const radar = cards.filter({ hasText: "Radar 35D6" });
  const nextCard = radar.locator("xpath=following-sibling::article[1]");
  await expect(radar.locator(":scope > strong")).toHaveText("Radar 35D6");
  await expect(radar.getByText("Радіус", { exact: true })).toBeVisible();
  await expect(radar.getByText("БК", { exact: true })).toHaveCount(0);
  await expect(drawer.getByText("READY", { exact: true })).toHaveCount(0);
  await expect(drawer.locator(".readiness-track, .readiness-caption")).toHaveCount(0);

  await radar.hover();
  await expect(radar.getByText(/Радіус виявлення/)).toBeVisible();
  await expect.poll(async () => (await radar.boundingBox())?.height || 0).toBeGreaterThan(108);
  const radarBox = await radar.boundingBox();
  const nextBox = await nextCard.boundingBox();
  expect(radarBox && nextBox && radarBox.y + radarBox.height <= nextBox.y).toBeTruthy();

  const list = drawer.locator(".unit-list");
  const lastCard = cards.last();
  await lastCard.hover();
  await expect.poll(async () => (await lastCard.boundingBox())?.height || 0).toBeGreaterThan(108);
  await expect.poll(async () => {
    const listBox = await list.boundingBox();
    const cardBox = await lastCard.boundingBox();
    return Boolean(listBox && cardBox && cardBox.y + cardBox.height <= listBox.y + listBox.height + 1);
  }).toBe(true);
});
