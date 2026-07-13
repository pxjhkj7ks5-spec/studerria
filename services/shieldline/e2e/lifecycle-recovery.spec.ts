import { expect, test } from "@playwright/test";

test("a running operation recovers after backgrounding and a stale offline projection", async ({ page }) => {
  test.setTimeout(40_000);
  await page.addInitScript(() => {
    localStorage.setItem("shieldline-tutorial-complete-v1", "true");
    if (!localStorage.getItem("shieldline-live-v7")) {
      localStorage.setItem("shieldline-live-v7", JSON.stringify({
        state: { campaignMode: "training", activeGameMode: "training", pendingCampaignMode: null, mapMode: "live", operationPhase: "planning" },
        version: 15,
      }));
    }
  });
  await page.goto("/shieldline/?legacy=1&mode=training");
  const navigation = page.getByRole("navigation", { name: "Панелі Shieldline" });
  const map = page.locator(".leaflet-stage");
  await expect(map).toBeVisible();
  const mapBox = await map.boundingBox();
  if (!mapBox) throw new Error("Shieldline map did not render.");

  const placeUnit = async (name: RegExp, x: number, y: number) => {
    await navigation.getByRole("button", { name: "ППО" }).click();
    await page.getByRole("complementary", { name: /ППО/ }).getByRole("button", { name }).click();
    await page.mouse.click(mapBox.x + mapBox.width * x, mapBox.y + mapBox.height * y);
  };
  await placeUnit(/Radar 35D6/, .43, .58);
  await placeUnit(/МВГ 6 млн/, .5, .62);

  const persistedState = () => page.evaluate(() => JSON.parse(localStorage.getItem("shieldline-live-v7") || "{}").state);
  await expect.poll(async () => (await persistedState()).operationPhase, { timeout: 8_000 }).toBe("running");
  const elapsedBeforeBackground = (await persistedState()).game.elapsedMs as number;

  await page.evaluate(() => {
    const lifecycleWindow = window as typeof window & { __shieldlineTestHidden?: boolean };
    lifecycleWindow.__shieldlineTestHidden = true;
    Object.defineProperty(document, "hidden", { configurable: true, get: () => Boolean(lifecycleWindow.__shieldlineTestHidden) });
    document.dispatchEvent(new Event("visibilitychange"));
    window.dispatchEvent(new Event("pagehide"));
  });
  await page.waitForTimeout(1_200);
  const elapsedWhileHidden = (await persistedState()).game.elapsedMs as number;
  expect(elapsedWhileHidden - elapsedBeforeBackground).toBeLessThan(600);

  await page.evaluate(async () => {
    const lifecycleWindow = window as typeof window & { __shieldlineTestHidden?: boolean };
    lifecycleWindow.__shieldlineTestHidden = false;
    window.dispatchEvent(new Event("pageshow"));
    document.dispatchEvent(new Event("visibilitychange"));
    const state = JSON.parse(localStorage.getItem("shieldline-live-v7") || "{}").state;
    await new Promise<void>((resolve, reject) => {
      const request = indexedDB.open("shieldline-offline-v1", 3);
      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        const database = request.result;
        const transaction = database.transaction("projections", "readwrite");
        transaction.objectStore("projections").put({
          schemaVersion: 2,
          updatedAt: "9999-01-01T00:00:00.000Z",
          game: state.game,
          activeGameMode: state.activeGameMode,
          operationPhase: state.operationPhase,
          simulationSeed: state.simulationSeed,
          simulationRandomCursor: state.simulationRandomCursor,
        }, "current-game");
        transaction.oncomplete = () => { database.close(); resolve(); };
        transaction.onerror = () => reject(transaction.error);
      };
    });
  });

  const elapsedBeforeReload = (await persistedState()).game.elapsedMs as number;
  await page.reload();
  await expect(map).toBeVisible();
  await expect.poll(async () => (await persistedState()).operationPhase).toBe("running");
  await expect.poll(async () => (await persistedState()).game.elapsedMs, { timeout: 5_000 }).toBeGreaterThan(elapsedBeforeReload + 600);
  await expect.poll(() => page.evaluate(async () => new Promise<number | null>((resolve) => {
    const request = indexedDB.open("shieldline-offline-v1", 3);
    request.onsuccess = () => {
      const database = request.result;
      const transaction = database.transaction("projections", "readonly");
      const projectionRequest = transaction.objectStore("projections").get("current-game");
      projectionRequest.onsuccess = () => {
        const schemaVersion = projectionRequest.result?.schemaVersion;
        database.close();
        resolve(typeof schemaVersion === "number" ? schemaVersion : null);
      };
    };
    request.onerror = () => resolve(null);
  }))).toBe(3);
});
