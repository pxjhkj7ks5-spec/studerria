import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

async function openTrainingLive(page: import("@playwright/test").Page) {
  await page.addInitScript(() => {
    const testWindow = window as typeof window & { __telegramBottomShowCount?: number };
    testWindow.__telegramBottomShowCount = 0;
    testWindow.Telegram = {
      WebApp: {
        ready: () => undefined,
        expand: () => undefined,
        onEvent: () => undefined,
        offEvent: () => undefined,
        BackButton: { show: () => undefined, hide: () => undefined },
        BottomButton: { show: () => { testWindow.__telegramBottomShowCount = (testWindow.__telegramBottomShowCount || 0) + 1; } },
      },
    } as typeof testWindow.Telegram;
    localStorage.setItem("shieldline-tutorial-complete-v1", "true");
    localStorage.setItem("shieldline-live-v7", JSON.stringify({
      state: { campaignMode: "training", activeGameMode: "training", pendingCampaignMode: null, mapMode: "live", operationPhase: "planning" },
      version: 14,
    }));
  });
  await page.goto("/shieldline/?legacy=1&mode=training");
  await expect(page.locator(".shell--mobile-live")).toBeVisible();
}

test("mobile live mode is map-first and uses full-screen panels", async ({ page }, testInfo) => {
  await openTrainingLive(page);
  expect(await page.evaluate(() => (window as typeof window & { __telegramBottomShowCount?: number }).__telegramBottomShowCount)).toBe(0);

  const navigation = page.getByRole("navigation", { name: "Панелі Shieldline" });
  await expect(navigation).toBeVisible();
  const resourceBar = page.locator(".map-status-strip .resource-bar");
  await expect(resourceBar.locator(".resource-card")).toHaveCount(4);
  for (const label of ["Бюджет", "БК", "Мораль", "Час"]) await expect(resourceBar.getByText(label, { exact: true })).toBeVisible();
  await expect(resourceBar.getByText("Енергія", { exact: true })).toHaveCount(0);
  await expect(resourceBar.getByText("Політичний ресурс", { exact: true })).toHaveCount(0);
  const resourceLayout = await resourceBar.evaluate((bar) => ({
    clientWidth: bar.clientWidth,
    scrollWidth: bar.scrollWidth,
    backgroundColor: getComputedStyle(bar).backgroundColor,
  }));
  expect(resourceLayout.scrollWidth).toBeLessThanOrEqual(resourceLayout.clientWidth);
  expect(resourceLayout.backgroundColor).toBe("rgba(0, 0, 0, 0)");
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
  await expect(page.locator(".coverage-ring")).toHaveCount(1);

  await navigation.getByRole("button", { name: "ППО" }).click();
  await page.getByRole("complementary", { name: /ППО/ }).getByRole("button", { name: /МВГ 6 млн/ }).click();
  await page.mouse.click(mapBox.x + mapBox.width * .5, mapBox.y + mapBox.height * .62);
  await expect(page.locator(".map-marker--battery")).toHaveCount(2);
  const operationPhase = () => page.evaluate(() => JSON.parse(localStorage.getItem("shieldline-live-v7") || "{}").state?.operationPhase);
  await expect.poll(operationPhase).toBe("countdown");
  await expect.poll(operationPhase, { timeout: 8_000 }).toBe("running");
  expect(await page.evaluate(() => (window as typeof window & { __telegramBottomShowCount?: number }).__telegramBottomShowCount)).toBe(0);

  const runtimeGeometryMutations = await page.locator(".coverage-ring").first().evaluate(async (ring) => {
    let changes = 0;
    const observer = new MutationObserver((mutations) => {
      changes += mutations.filter((mutation) => mutation.attributeName === "d").length;
    });
    observer.observe(ring, { attributes: true, attributeFilter: ["d"] });
    await new Promise((resolve) => window.setTimeout(resolve, 750));
    observer.disconnect();
    return changes;
  });
  expect(runtimeGeometryMutations).toBe(0);

  const zoomSamplesPromise = page.evaluate(async () => {
    const ring = document.querySelector<SVGElement>(".coverage-ring");
    const marker = document.querySelector<HTMLElement>(".map-marker--battery");
    if (!ring || !marker) return [];
    const samples: Array<{ width: number; centerDelta: number }> = [];
    const started = performance.now();
    while (performance.now() - started < 650) {
      const ringBox = ring.getBoundingClientRect();
      const markerBox = marker.getBoundingClientRect();
      samples.push({
        width: ringBox.width,
        centerDelta: Math.hypot(
          ringBox.left + ringBox.width / 2 - (markerBox.left + markerBox.width / 2),
          ringBox.top + ringBox.height / 2 - (markerBox.top + markerBox.height / 2),
        ),
      });
      await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
    }
    return samples;
  });
  await map.focus();
  await page.keyboard.press("+");
  const zoomSamples = await zoomSamplesPromise;
  expect(zoomSamples.length).toBeGreaterThan(10);
  expect(Math.max(...zoomSamples.map((sample) => sample.centerDelta))).toBeLessThan(3);
  const widths = zoomSamples.map((sample) => sample.width).filter((width) => width > 0);
  const backwardsJump = Math.max(0, ...widths.slice(1).map((width, index) => widths[index] - width));
  expect(backwardsJump).toBeLessThan(1.5);

  await page.locator(".map-marker--battery").first().click({ force: true });
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
