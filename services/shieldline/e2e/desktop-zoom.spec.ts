import { expect, test } from "@playwright/test";

test("desktop mouse and trackpad wheel zoom respond around the pointer", async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem("shieldline-tutorial-complete-v1", "true");
    localStorage.setItem("shieldline-live-v7", JSON.stringify({
      state: { campaignMode: "training", activeGameMode: "training", pendingCampaignMode: null, mapMode: "live", operationPhase: "planning" },
      version: 14,
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
  await page.mouse.wheel(0, -240);
  await expect.poll(markerDistance).toBeGreaterThan(before * 1.05);
});
