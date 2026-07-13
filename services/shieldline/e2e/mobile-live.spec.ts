import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

async function openTrainingLive(page: import("@playwright/test").Page) {
  await page.addInitScript(() => {
    localStorage.setItem("shieldline-tutorial-complete-v1", "true");
    localStorage.setItem("shieldline-live-v7", JSON.stringify({
      state: { campaignMode: "training", activeGameMode: "training", pendingCampaignMode: null, mapMode: "live", operationPhase: "planning" },
      version: 12,
    }));
  });
  await page.goto("/shieldline/?legacy=1&mode=training");
  await expect(page.locator(".shell--mobile-live")).toBeVisible();
}

test("mobile live mode is map-first and uses full-screen panels", async ({ page }, testInfo) => {
  await openTrainingLive(page);

  const navigation = page.getByRole("navigation", { name: "Панелі Shieldline" });
  await expect(navigation).toBeVisible();
  for (const label of ["Меню", "ППО", "План", "Розвідка", "Налаштування"]) {
    const button = navigation.getByRole("button", { name: label });
    await expect(button).toBeVisible();
    const box = await button.boundingBox();
    expect(box && box.height >= 44).toBeTruthy();
  }

  const hudBox = await page.locator(".map-status-strip").boundingBox();
  const navBox = await navigation.boundingBox();
  const viewport = page.viewportSize();
  if (viewport && viewport.height > viewport.width) {
    expect(hudBox && navBox && hudBox.height + navBox.height <= viewport.height * .2).toBeTruthy();
  }

  await navigation.getByRole("button", { name: "Меню" }).click();
  const menu = page.getByRole("complementary", { name: /Меню/ });
  await expect(menu).toBeVisible();
  await expect(page.locator(".map-stage")).toHaveCSS("visibility", "hidden");
  await expect(navigation).toBeVisible();
  await expect(menu.getByText("Умовні позначення", { exact: true }).first()).toBeVisible();
  await menu.getByRole("button", { name: "Закрити" }).click();

  await navigation.getByRole("button", { name: "ППО" }).click();
  const catalog = page.getByRole("complementary", { name: /ППО/ });
  await expect(catalog).toBeVisible();
  await catalog.getByRole("button", { name: /Radar 35D6/ }).click();
  await expect(catalog).toBeHidden();
  await expect(page.getByText(/Розмістіть: Radar\b/)).toBeVisible();

  const map = page.locator(".leaflet-stage");
  const mapBox = await map.boundingBox();
  if (!mapBox) throw new Error("Mobile live map did not render.");
  await page.mouse.click(mapBox.x + 5, mapBox.y + 130);
  await expect(page.getByText(/Розмістіть: Radar\b/)).toBeVisible();
  await expect(page.getByText(/ППО можна розміщувати лише в межах України/)).toBeVisible();
  await page.getByRole("button", { name: "Скасувати" }).click();
  await expect(page.getByText(/Розмістіть:/)).toBeHidden();

  await navigation.getByRole("button", { name: "ППО" }).click();
  await page.getByRole("complementary", { name: /ППО/ }).getByRole("button", { name: /Radar 35D6/ }).click();
  await page.mouse.click(mapBox.x + mapBox.width * .43, mapBox.y + mapBox.height * .58);
  await expect(page.locator(".map-marker--battery")).toHaveCount(1);
  await expect(page.locator(".leaflet-overlay-pane canvas").first()).toBeVisible();
  await page.locator(".map-marker--battery").first().evaluate((node) => node.setAttribute("data-stability-id", "stable-battery"));
  if (testInfo.project.name !== "mobile-webkit") await page.evaluate(async () => {
    const mapElement = document.querySelector<HTMLElement>(".leaflet-stage");
    if (!mapElement || typeof Touch !== "function") return;
    const mapBounds = mapElement.getBoundingClientRect();
    const centerX = mapBounds.left + mapBounds.width / 2;
    const centerY = mapBounds.top + mapBounds.height / 2;
    const touch = (identifier: number, x: number) => new Touch({ identifier, target: mapElement, clientX: x, clientY: centerY });
    const dispatch = (target: EventTarget, type: string, touches: Touch[]) => target.dispatchEvent(new TouchEvent(type, {
      bubbles: true,
      cancelable: true,
      touches,
      targetTouches: touches,
      changedTouches: touches,
    }));
    const startTouches = [touch(1, centerX - 50), touch(2, centerX + 50)];
    dispatch(mapElement, "touchstart", startTouches);
    const movedTouches = [touch(1, centerX - 65), touch(2, centerX + 65)];
    dispatch(document, "touchmove", movedTouches);
    await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
    dispatch(document, "touchend", []);
    await new Promise((resolve) => window.setTimeout(resolve, 350));
  });
  await expect(page.locator('[data-stability-id="stable-battery"]')).toHaveCount(1);

  await page.locator(".map-marker--battery").click({ force: true });
  await expect(page.locator(".map-marker--selected, .selected-unit-card")).toHaveCount(0);

  const accessibility = await new AxeBuilder({ page }).include(".app-rail").include(".map-status-strip").analyze();
  expect(accessibility.violations.filter((violation) => violation.impact === "critical")).toEqual([]);

  if (testInfo.project.name === "mobile-live-landscape") {
    await navigation.getByRole("button", { name: "Налаштування" }).click();
    const drawerBox = await page.getByRole("complementary", { name: /Налаштування/ }).boundingBox();
    const landscapeNav = await navigation.boundingBox();
    expect(drawerBox && landscapeNav && drawerBox.y + drawerBox.height <= landscapeNav.y + 2).toBeTruthy();
  }
});
