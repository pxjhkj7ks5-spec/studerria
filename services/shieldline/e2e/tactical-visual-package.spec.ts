import { expect, test } from "@playwright/test";

async function openTacticalView(page: import("@playwright/test").Page) {
  await page.addInitScript(() => {
    localStorage.setItem("shieldline-tutorial-complete-v1", "true");
    localStorage.setItem("shieldline-live-v7", JSON.stringify({
      state: { campaignMode: "training", activeGameMode: "training", pendingCampaignMode: null, mapMode: "live", operationPhase: "planning" },
      version: 18,
    }));
  });
  await page.goto("/shieldline/?legacy=1&mode=training");
  await expect(page.locator(".shell--map-first")).toBeVisible();
}

async function completeOperation(page: import("@playwright/test").Page, reportId: string) {
  await page.evaluate(async (id) => {
    const { useGameStore } = await import("/shieldline/src/store/useGameStore.ts");
    const current = useGameStore.getState().game;
    const report = {
      id,
      day: current.day,
      generatedAtMs: current.elapsedMs,
      archetype: "combined" as const,
      situationSummary: "Повітряну атаку завершено. Командування отримало підсумкові дані.",
      threatOverview: { totalTracks: 8, confirmedThreats: 6, decoys: 2, unidentifiedTracks: 0 },
      defensePerformance: { interceptions: 6, missedThreats: 2, ammoSpent: 9, averageReadinessChange: -8, strongestUnit: "ППО", weakestCoverageArea: "Схід" },
      damageReport: { damagedCities: ["Харків"], systems: { infrastructure: 92, energy: 88, communications: 95, logistics: 90, civilMorale: 84, repairCapacity: 91 } },
      resourceChanges: { budget: -12, ammo: -9, energy: -4, morale: -2, political: 1 },
      recommendation: "Посилити східний сектор.",
      actionEffects: [],
      logisticsNotes: [],
    };
    useGameStore.setState({ game: { ...current, latestReportId: id, afterActionReports: [report, ...current.afterActionReports] }, operationPhase: "completed" });
  }, reportId);
}

test("visual presets persist and completed operations open the full-screen report", async ({ page }) => {
  await openTacticalView(page);

  await page.getByRole("navigation", { name: "Панелі Shieldline" }).getByRole("button", { name: "Налаштування" }).click();
  const settings = page.getByRole("complementary", { name: /Налаштування/ });
  await settings.getByRole("button", { name: "День" }).click();
  await settings.getByRole("button", { name: "Туман" }).click();
  await settings.getByRole("checkbox", { name: /Режим продуктивності/ }).check();
  await expect(page.locator(".shell--map-first")).toHaveClass(/environment--day/);
  await expect(page.locator(".shell--map-first")).toHaveClass(/weather--fog/);
  await expect(page.locator(".shell--map-first")).toHaveClass(/shell--performance-mode/);
  await expect.poll(() => page.evaluate(() => JSON.parse(localStorage.getItem("shieldline-display-preferences-v1") || "null"))).toEqual({ environmentTime: "day", environmentWeather: "fog", performanceMode: true });

  await page.reload();
  await expect(page.locator(".shell--map-first")).toHaveClass(/environment--day/);
  await expect(page.locator(".shell--map-first")).toHaveClass(/weather--fog/);
  await expect(page.locator(".shell--map-first")).toHaveClass(/shell--performance-mode/);

  await completeOperation(page, "visual-report-1");
  const report = page.getByRole("dialog", { name: "Післяопераційний звіт" });
  await expect(report).toBeVisible();
  await expect(report.getByRole("button", { name: "Оглянути мапу" })).toBeVisible();
  await expect(report.getByRole("button", { name: "До вибору режимів" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(report).toBeHidden();
  await expect(page.locator(".map-stage")).toBeVisible();

  await completeOperation(page, "visual-report-2");
  await expect(report).toBeVisible();
  await report.getByRole("button", { name: "До вибору режимів" }).click();
  await expect(page).toHaveURL(/\/shieldline\/?$/);
});
