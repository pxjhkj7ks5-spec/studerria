import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("mobile Campaign runs from placement through authoritative replay and reconnect", async ({ page }) => {
  await page.goto("/shieldline/");
  await page.getByRole("button", { name: /Campaign/ }).click();
  const tutorial = page.locator(".tutorial-overlay");
  const tutorialAppeared = await tutorial.waitFor({ state: "visible", timeout: 5_000 }).then(() => true).catch(() => false);
  if (tutorialAppeared) {
    await tutorial.getByRole("button").last().click();
    await tutorial.waitFor({ state: "hidden" });
  }

  const drawer = page.getByRole("complementary", { name: /Defense units/ });
  await expect(drawer).toBeVisible();
  const drawerBox = await drawer.boundingBox();
  const navigationBox = await page.getByRole("navigation", { name: "Shieldline panels" }).boundingBox();
  expect(drawerBox && navigationBox && drawerBox.y + drawerBox.height <= navigationBox.y + 2).toBeTruthy();

  const map = page.locator(".leaflet-stage");
  const mapBox = await map.boundingBox();
  if (!mapBox) throw new Error("Campaign map did not render.");
  await page.getByRole("button", { name: /Radar 35D6/ }).click();
  await page.mouse.click(mapBox.x + 265, mapBox.y + 300);
  await page.getByRole("button", { name: /МВГ/ }).click();
  await page.mouse.click(mapBox.x + 175, mapBox.y + 275);

  await expect(page.getByText(/Authoritative server result/)).toBeVisible({ timeout: 15_000 });
  await expect(page.getByLabel("Campaign tactical replay")).toBeVisible();

  await page.reload();
  await page.getByTestId("panel-report").click();
  await expect(page.getByText(/Authoritative server result/)).toBeVisible();

  const accessibility = await new AxeBuilder({ page }).include(".app-rail").include(".command-drawer").analyze();
  expect(accessibility.violations.filter((violation) => violation.impact === "critical")).toEqual([]);
});
