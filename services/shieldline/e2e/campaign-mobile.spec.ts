import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("mobile Campaign runs from placement through authoritative replay and reconnect", async ({ page }) => {
  await page.goto("/shieldline/");
  await page.getByRole("button", { name: /Campaign/ }).click();
  const tutorialButton = page.getByRole("button", { name: /Begin watch/ });
  if (await tutorialButton.isVisible()) await tutorialButton.click();

  const drawer = page.getByRole("complementary", { name: /Defense units/ });
  const controls = page.getByRole("region", { name: "Operation controls" });
  await expect(drawer).toBeVisible();
  await expect(controls).toBeVisible();
  const drawerBox = await drawer.boundingBox();
  const controlsBox = await controls.boundingBox();
  expect(drawerBox && controlsBox && drawerBox.y + drawerBox.height <= controlsBox.y + 2).toBeTruthy();

  const map = page.locator(".leaflet-stage");
  const mapBox = await map.boundingBox();
  if (!mapBox) throw new Error("Campaign map did not render.");
  await page.getByRole("button", { name: /Radar 35D6/ }).click();
  await page.mouse.click(mapBox.x + 265, mapBox.y + 300);
  await page.getByRole("button", { name: /МВГ/ }).click();
  await page.mouse.click(mapBox.x + 175, mapBox.y + 275);

  await expect(page.getByRole("button", { name: /Start operation/ })).toBeEnabled();
  await page.getByRole("button", { name: "x60" }).click();
  await page.getByRole("button", { name: /Start operation/ }).click();
  await expect(page.getByText(/Authoritative server result/)).toBeVisible({ timeout: 15_000 });
  await expect(page.getByLabel("Campaign tactical replay")).toBeVisible();

  await page.reload();
  await expect(page.getByRole("button", { name: /New operation/ })).toBeVisible();
  await page.getByRole("button", { name: /Report/ }).click();
  await expect(page.getByText(/Authoritative server result/)).toBeVisible();

  const accessibility = await new AxeBuilder({ page }).include(".app-rail").include(".operation-controls").include(".command-drawer").analyze();
  expect(accessibility.violations.filter((violation) => violation.impact === "critical")).toEqual([]);
});
