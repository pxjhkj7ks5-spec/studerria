import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  reporter: "line",
  use: {
    baseURL: "http://127.0.0.1:4174",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  projects: [
    { name: "mobile-chromium", use: { ...devices["iPhone 13"], browserName: "chromium", viewport: { width: 390, height: 844 } } },
    { name: "mobile-webkit", use: { ...devices["iPhone 13"], browserName: "webkit", viewport: { width: 390, height: 844 } } },
    {
      name: "mobile-live-landscape",
      testMatch: /mobile-live\.spec\.ts/,
      use: { ...devices["iPhone 13 landscape"], browserName: "chromium", viewport: { width: 844, height: 390 } },
    },
    {
      name: "desktop-chromium-zoom",
      testMatch: /desktop-zoom\.spec\.ts/,
      use: { browserName: "chromium", viewport: { width: 1440, height: 900 } },
    },
    {
      name: "desktop-webkit-zoom",
      testMatch: /desktop-zoom\.spec\.ts/,
      use: { browserName: "webkit", viewport: { width: 1440, height: 900 } },
    },
  ],
  webServer: {
    command: "npm run dev -- --port 4174",
    url: "http://127.0.0.1:4174/shieldline/",
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
  },
});
