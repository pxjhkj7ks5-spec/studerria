import { expect, test } from "@playwright/test";

test("desktop trackpad zoom is continuous and anchored under the pointer", async ({ page }) => {
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
  const markerAnchor = () => cityMarkers.nth(0).evaluate((marker) => {
    const box = marker.getBoundingClientRect();
    const style = getComputedStyle(marker);
    return { x: box.left - Number.parseFloat(style.marginLeft), y: box.top - Number.parseFloat(style.marginTop) };
  });
  const before = await markerDistance();
  const mapBox = await map.boundingBox();
  if (!mapBox) throw new Error("Desktop map did not render.");
  const anchor = await markerAnchor();
  await page.mouse.move(anchor.x, anchor.y);
  for (let step = 0; step < 12; step += 1) await page.mouse.wheel(0, -12);
  await expect.poll(markerDistance).toBeGreaterThan(before * 1.05);
  await expect.poll(async () => {
    const current = await markerAnchor();
    return Math.hypot(current.x - anchor.x, current.y - anchor.y);
  }).toBeLessThan(4);

  const zoomBeforePinch = await markerDistance();
  await map.dispatchEvent("wheel", { deltaY: -30, ctrlKey: true, clientX: anchor.x, clientY: anchor.y });
  await expect.poll(markerDistance).toBeGreaterThan(zoomBeforePinch);
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
  const nextCard = cards.nth(1);
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
