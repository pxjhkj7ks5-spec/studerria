import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("mobile Campaign runs at real-time speed and reconnects without replay controls", async ({ page }) => {
  test.setTimeout(85_000);
  await page.addInitScript(() => {
    Object.defineProperty(globalThis.crypto, "randomUUID", { value: () => "e2e", configurable: true });
  });
  await page.goto("/shieldline/");
  await page.getByRole("button", { name: /Campaign/ }).click();
  const tutorial = page.locator(".tutorial-overlay");
  const tutorialAppeared = await tutorial.waitFor({ state: "visible", timeout: 5_000 }).then(() => true).catch(() => false);
  if (tutorialAppeared) {
    await tutorial.getByRole("button").last().click();
    await tutorial.waitFor({ state: "hidden" });
  }

  await expect(page.locator(".launch-sector-marker--idle").first()).toBeVisible();
  const launchMarkers = page.locator(".leaflet-marker-icon").filter({ has: page.locator(".launch-sector-marker--idle") });
  const visibleLaunchMarkerIndex = await launchMarkers.evaluateAll((markers) => markers.findIndex((marker) => {
    const box = marker.getBoundingClientRect();
    return box.left >= 0 && box.right <= window.innerWidth && box.top >= 180 && box.bottom <= window.innerHeight - 90;
  }));
  expect(visibleLaunchMarkerIndex).toBeGreaterThanOrEqual(0);
  await launchMarkers.nth(visibleLaunchMarkerIndex).dispatchEvent("mouseover");
  const launchTooltip = page.locator(".launch-sector-tooltip:visible");
  await expect(launchTooltip).toBeVisible();
  const tooltipBox = await launchTooltip.boundingBox();
  const viewport = page.viewportSize();
  expect(tooltipBox && viewport && tooltipBox.x >= 8 && tooltipBox.x + tooltipBox.width <= viewport.width - 8).toBeTruthy();
  expect(tooltipBox && tooltipBox.width <= 260).toBeTruthy();

  await page.getByRole("navigation", { name: "Панелі Shieldline" }).getByRole("button", { name: "ППО" }).click();
  const drawer = page.getByRole("complementary", { name: /ППО/ });
  await expect(drawer).toBeVisible();
  const drawerBox = await drawer.boundingBox();
  const navigationBox = await page.getByRole("navigation", { name: "Панелі Shieldline" }).boundingBox();
  expect(drawerBox && navigationBox && drawerBox.y + drawerBox.height <= navigationBox.y + 8).toBeTruthy();

  const map = page.locator(".leaflet-stage");
  const mapBox = await map.boundingBox();
  if (!mapBox) throw new Error("Campaign map did not render.");
  await page.getByRole("button", { name: /Radar 35D6/ }).click();
  await page.mouse.click(mapBox.x + mapBox.width * .49, mapBox.y + mapBox.height * .58);
  await expect(page.locator(".map-marker--battery")).toHaveCount(1);
  await page.getByRole("navigation", { name: "Панелі Shieldline" }).getByRole("button", { name: "ППО" }).click();
  await page.getByRole("button", { name: /МВГ/ }).click();
  await page.mouse.click(mapBox.x + mapBox.width * .43, mapBox.y + mapBox.height * .58);
  await expect(page.locator(".map-marker--battery")).toHaveCount(2);

  await expect(page.locator(".launch-point-marker").first()).toBeVisible({ timeout: 40_000 });
  await expect(page.locator(".launch-sector-marker--launching").first()).toHaveCSS("opacity", "1");
  await expect(page.locator(".launch-sector-marker--cooldown").first()).toHaveCSS("opacity", "0.88", { timeout: 22_000 });
  await expect(page.locator(".campaign-event-stream")).toHaveCount(0);
  await expect(page.getByText(/North|South|East|West/, { exact: true })).toHaveCount(0);
  await expect(page.locator(".launch-sector-debug-radius, .launch-point-debug")).toHaveCount(0);
  await expect(page.getByLabel("Campaign tactical replay")).toHaveCount(0);

  await page.reload();
  await expect(page.locator(".launch-point-marker").first()).toBeVisible({ timeout: 15_000 });

  const accessibility = await new AxeBuilder({ page }).include(".app-rail").include(".command-drawer").analyze();
  expect(accessibility.violations.filter((violation) => violation.impact === "critical")).toEqual([]);
});

test("Safari discards an outdated IndexedDB projection instead of showing a blank screen", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "mobile-webkit");
  await page.goto("/shieldline/offline.html");
  await page.evaluate(async () => {
    await new Promise<void>((resolve, reject) => {
      const request = indexedDB.open("shieldline-offline-v1", 2);
      request.onupgradeneeded = () => {
        const database = request.result;
        if (!database.objectStoreNames.contains("projections")) database.createObjectStore("projections");
        if (!database.objectStoreNames.contains("pendingCommands")) database.createObjectStore("pendingCommands", { keyPath: "id", autoIncrement: true });
        if (!database.objectStoreNames.contains("replayChunks")) database.createObjectStore("replayChunks");
        if (!database.objectStoreNames.contains("preferences")) database.createObjectStore("preferences");
      };
      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        const database = request.result;
        const transaction = database.transaction("projections", "readwrite");
        transaction.objectStore("projections").put({ schemaVersion: 1, updatedAt: "9999-01-01T00:00:00.000Z", game: { launchSectors: [{ id: "stale" }] } }, "current-game");
        transaction.oncomplete = () => { database.close(); resolve(); };
        transaction.onerror = () => reject(transaction.error);
      };
    });
  });
  await page.goto("/shieldline/");
  await page.getByRole("button", { name: /Campaign/ }).click();
  await expect(page.locator(".leaflet-stage")).toBeVisible();
  await expect(page.locator(".app-recovery")).toHaveCount(0);
});
