import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("mobile Campaign opens its tactical depot state and reconnects without replay controls", async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(globalThis.crypto, "randomUUID", { value: () => "e2e-campaign-seed", configurable: true });
  });
  await page.goto("/shieldline/");
  await expect(page.getByRole("heading", { name: "Утримайте рубіж." })).toBeVisible();
  await expect(page.getByText("0 з 5 місій")).toBeVisible();
  await page.getByRole("button", { name: "Почати кампанію" }).click();
  await expect(page.getByRole("heading", { name: "Перший контакт" })).toBeVisible();
  await expect(page.getByText("Ймовірний район атаки")).toBeVisible();
  await expect(page.getByText("10 БК · повні магазини")).toBeVisible();
  const shellAccessibility = await new AxeBuilder({ page }).include(".briefing-screen").analyze();
  expect(shellAccessibility.violations.filter((violation) => violation.impact === "critical")).toEqual([]);
  await page.getByRole("button", { name: "Перейти до розгортання" }).click();
  const tutorial = page.locator(".tutorial-overlay");
  const tutorialAppeared = await tutorial.waitFor({ state: "visible", timeout: 5_000 }).then(() => true).catch(() => false);
  if (tutorialAppeared) {
    await tutorial.getByRole("button").last().click();
    await tutorial.waitFor({ state: "hidden" });
  }

  await expect(page.locator(".leaflet-stage")).toBeVisible();
  await expect(page.locator(".map-marker--ammo-depot")).toHaveCount(1);
  const depotCard = page.locator(".resource-card").filter({ hasText: "Склад БК" });
  await expect(depotCard).toContainText("HP 100%");
  await expect(depotCard).toContainText("+2/45 с");
  const campaignState = await page.evaluate(() => JSON.parse(localStorage.getItem("shieldline-live-v7") || "{}").state);
  expect(campaignState.activeGameMode).toBe("campaign");
  expect(campaignState.game.campaign.missionIndex).toBe(1);
  expect(campaignState.game.resources.budget).toBe(24);
  expect(campaignState.game.cities.every((city: { infrastructure: number }) => city.infrastructure === 100)).toBe(true);
  await expect(page.locator(".campaign-event-stream")).toHaveCount(0);
  await expect(page.getByText(/North|South|East|West/, { exact: true })).toHaveCount(0);
  await expect(page.locator(".launch-sector-debug-radius, .launch-point-debug")).toHaveCount(0);
  await expect(page.getByLabel("Campaign tactical replay")).toHaveCount(0);

  await page.reload();
  await expect(page.locator(".map-marker--ammo-depot")).toHaveCount(1);
  await expect(depotCard).toContainText("HP 100%");

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
  await page.getByRole("button", { name: "Почати кампанію" }).click();
  await page.getByRole("button", { name: "Перейти до розгортання" }).click();
  await expect(page.locator(".leaflet-stage")).toBeVisible();
  await expect(page.locator(".app-recovery")).toHaveCount(0);
});
