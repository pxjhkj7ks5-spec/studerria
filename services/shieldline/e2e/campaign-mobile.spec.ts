import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("mobile Campaign runs from placement through authoritative replay and reconnect", async ({ page }) => {
  test.setTimeout(70_000);
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

  await expect(page.locator(".launch-sector-marker").first()).toBeVisible({ timeout: 25_000 });
  await expect(page.locator(".launch-sector-debug-radius, .launch-point-debug")).toHaveCount(0);
  await expect(page.getByText(/Авторитетний результат сервера|Authoritative server result/)).toBeVisible({ timeout: 55_000 });
  await expect(page.getByLabel("Campaign tactical replay")).toBeVisible();

  await page.reload();
  await expect(page.getByText(/Авторитетний результат сервера|Authoritative server result/)).toBeVisible({ timeout: 15_000 });

  const accessibility = await new AxeBuilder({ page }).include(".app-rail").include(".command-drawer").analyze();
  expect(accessibility.violations.filter((violation) => violation.impact === "critical")).toEqual([]);
});
