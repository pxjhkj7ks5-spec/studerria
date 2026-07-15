import { expect, test } from "@playwright/test";

test("registers a unique nickname and signs another device in with a one-time code", async ({ browser, page }) => {
  const nickname = `Sokil_${Date.now().toString().slice(-8)}`;
  await page.goto("/shieldline/?onboarding=1");
  await expect(page.getByRole("heading", { name: "Створіть позивний" })).toBeVisible();
  await page.getByLabel("Нікнейм").fill(nickname);
  await expect(page.getByText("Нікнейм вільний")).toBeVisible();
  await page.locator(".auth-consent").click();
  await page.getByRole("button", { name: /Створити профіль/ }).click();
  await expect(page.getByRole("button", { name: "Відкрити профіль" })).toContainText(nickname);
  await page.getByRole("button", { name: "Відкрити профіль" }).click();
  await page.getByRole("button", { name: "Створити код входу" }).click();
  const code = (await page.locator(".account-transfer button").innerText()).replace(/\D/g, "");
  expect(code).toHaveLength(6);

  const secondDevice = await browser.newContext();
  const secondPage = await secondDevice.newPage();
  await secondPage.goto(`${new URL(page.url()).origin}/shieldline/?onboarding=1`);
  await secondPage.getByRole("tab", { name: "Вхід за кодом" }).click();
  await secondPage.getByLabel("Цифра 1").focus();
  await secondPage.keyboard.type(code);
  await secondPage.getByRole("button", { name: "Увійти на цьому пристрої" }).click();
  await expect(secondPage.getByRole("button", { name: "Відкрити профіль" })).toContainText(nickname);
  await secondDevice.close();
});

test("invalid Telegram initData falls back to safe web onboarding", async ({ page }) => {
  await page.addInitScript(() => {
    window.Telegram = { WebApp: { initData: "auth_date=1&user=%7B%22id%22%3A42%7D&hash=invalid", ready() {}, expand() {} } };
  });
  await page.goto("/shieldline/?onboarding=1");
  await expect(page.getByRole("heading", { name: "Створіть позивний" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Немає зв’язку" })).toHaveCount(0);
});
