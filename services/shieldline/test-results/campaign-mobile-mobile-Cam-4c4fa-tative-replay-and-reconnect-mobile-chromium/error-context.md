# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: campaign-mobile.spec.ts >> mobile Campaign runs from placement through authoritative replay and reconnect
- Location: e2e/campaign-mobile.spec.ts:4:1

# Error details

```
Test timeout of 30000ms exceeded.
```

```
Error: locator.click: Test timeout of 30000ms exceeded.
Call log:
  - waiting for getByRole('button', { name: /Report/ })

```

# Page snapshot

```yaml
- main "Shieldline real-time defense simulation" [ref=e3]:
  - navigation "Shieldline panels" [ref=e4]:
    - button "Back to command modes" [ref=e5] [cursor=pointer]:
      - img [ref=e6]
    - generic [ref=e7]:
      - button "Layers" [ref=e8] [cursor=pointer]:
        - img [ref=e9]
      - button "Defense units" [pressed] [ref=e13] [cursor=pointer]:
        - img [ref=e14]
      - button "Planning" [ref=e16] [cursor=pointer]:
        - img [ref=e17]
      - button "Live intelligence" [ref=e18] [cursor=pointer]:
        - img [ref=e19]
      - button "After-action" [ref=e25] [cursor=pointer]:
        - img [ref=e26]
      - button "Settings" [ref=e29] [cursor=pointer]:
        - img [ref=e30]
  - region "Live defense map" [ref=e33]:
    - generic [ref=e34]:
      - generic:
        - generic:
          - img
        - generic:
          - button [ref=e38] [cursor=pointer]
          - button [ref=e39] [cursor=pointer]
          - button [ref=e40] [cursor=pointer]
          - button [ref=e41] [cursor=pointer]
          - button "88% 🛡️" [ref=e42] [cursor=pointer]:
            - generic:
              - generic: 88% 🛡️
          - button "76% 🛡️" [ref=e43] [cursor=pointer]:
            - generic:
              - generic: 76% 🛡️
          - button "74% 🛡️" [ref=e44] [cursor=pointer]:
            - generic:
              - generic: 74% 🛡️
          - button "82% 🛡️" [ref=e45] [cursor=pointer]:
            - generic:
              - generic: 82% 🛡️
          - button "72% 🛡️" [ref=e46] [cursor=pointer]:
            - generic:
              - generic: 72% 🛡️
          - button "78% 🛡️" [ref=e47] [cursor=pointer]:
            - generic:
              - generic: 78% 🛡️
          - button "70% 🛡️" [ref=e48] [cursor=pointer]:
            - generic:
              - generic: 70% 🛡️
          - button "70% 🛡️" [ref=e49] [cursor=pointer]:
            - generic:
              - generic: 70% 🛡️
          - button "68% 🛡️" [ref=e50] [cursor=pointer]:
            - generic:
              - generic: 68% 🛡️
          - button "72% 🛡️" [ref=e51] [cursor=pointer]:
            - generic:
              - generic: 72% 🛡️
          - button "72% 🛡️" [ref=e52] [cursor=pointer]:
            - generic:
              - generic: 72% 🛡️
          - button "70% 🛡️" [ref=e53] [cursor=pointer]:
            - generic:
              - generic: 70% 🛡️
          - button "74% 🛡️" [ref=e54] [cursor=pointer]:
            - generic:
              - generic: 74% 🛡️
          - button "70% 🛡️" [ref=e55] [cursor=pointer]:
            - generic:
              - generic: 70% 🛡️
          - button "72% 🛡️" [ref=e56] [cursor=pointer]:
            - generic:
              - generic: 72% 🛡️
          - button "70% 🛡️" [ref=e57] [cursor=pointer]:
            - generic:
              - generic: 70% 🛡️
          - button "68% 🛡️" [ref=e58] [cursor=pointer]:
            - generic:
              - generic: 68% 🛡️
          - button "68% 🛡️" [ref=e59] [cursor=pointer]:
            - generic:
              - generic: 68% 🛡️
          - button "68% 🛡️" [ref=e60] [cursor=pointer]:
            - generic:
              - generic: 68% 🛡️
          - button "68% 🛡️" [ref=e61] [cursor=pointer]:
            - generic:
              - generic: 68% 🛡️
          - button "66% 🛡️" [ref=e62] [cursor=pointer]:
            - generic:
              - generic: 66% 🛡️
          - button [ref=e63] [cursor=pointer]
          - button [ref=e65] [cursor=pointer]
          - button
          - button
          - button [ref=e67] [cursor=pointer]
          - button [ref=e68] [cursor=pointer]
          - button [ref=e69] [cursor=pointer]
      - generic [ref=e70]:
        - link "Leaflet" [ref=e71] [cursor=pointer]:
          - /url: https://leafletjs.com
          - img [ref=e72]
          - text: Leaflet
        - text: "| © OpenStreetMap contributors © CARTO"
    - generic "Campaign status":
      - generic:
        - img
        - generic:
          - heading "Shieldline" [level=1]
          - generic: "Night 01: Signal Window · Authoritative stream"
    - region "Operation controls" [ref=e76]:
      - generic [ref=e77]:
        - generic [ref=e78]: completed
        - strong [ref=e79]: Defense plan ready.
      - generic [ref=e80]:
        - button "New operation" [ref=e81] [cursor=pointer]:
          - img [ref=e82]
          - text: New operation
        - generic "Simulation speed" [ref=e85]:
          - button "x1" [ref=e86] [cursor=pointer]
          - button "x8" [ref=e87] [cursor=pointer]
          - button "x60" [ref=e88] [cursor=pointer]
  - complementary "Defense units panel" [ref=e89]:
    - generic [ref=e90]:
      - generic [ref=e91]:
        - generic [ref=e92]: Shieldline
        - strong [ref=e93]: Defense units
      - button "Close" [ref=e94] [cursor=pointer]:
        - img [ref=e95]
    - generic [ref=e98]:
      - button "Cancel placement" [disabled] [ref=e99]:
        - img [ref=e100]
        - text: Cancel placement
      - generic [ref=e107]: 2 placed PPO units
    - generic [ref=e108]:
      - button "0/0 Radar 35D6 25 млн ₴ · 100/100 km · ready Radar detail Primary 100 km · Outer 100 km Ammo 0/0 · Reload 0.0s · Shot pause 0.0s Primary acc 0% · Outer acc 0% Mobility 1/4 · Maintenance risk Low Fatigue 8% · Nominal · strained Radar 35D6 readiness" [ref=e109] [cursor=pointer]:
        - generic [ref=e111]: 0/0
        - strong [ref=e112]: Radar 35D6
        - generic [ref=e113]: 25 млн ₴ · 100/100 km · ready
        - tooltip "Radar detail Primary 100 km · Outer 100 km Ammo 0/0 · Reload 0.0s · Shot pause 0.0s Primary acc 0% · Outer acc 0% Mobility 1/4 · Maintenance risk Low Fatigue 8% · Nominal · strained":
          - strong: Radar detail
          - generic: Primary 100 km · Outer 100 km
          - generic: Ammo 0/0 · Reload 0.0s · Shot pause 0.0s
          - generic: Primary acc 0% · Outer acc 0%
          - generic: Mobility 1/4 · Maintenance risk Low
          - generic: Fatigue 8% · Nominal · strained
        - generic "Radar 35D6 readiness" [ref=e114]
      - button "5/5 МВГ 6 млн ₴ · 9/18 km · ready МВГ detail Primary 9 km · Outer 18 km Ammo 5/5 · Reload 20s · Shot pause 3s Primary acc 68% · Outer acc 31.3% Mobility 4/4 · Maintenance risk Low Fatigue 8% · Nominal · strained МВГ readiness" [ref=e116] [cursor=pointer]:
        - generic [ref=e118]: 5/5
        - strong [ref=e119]: МВГ
        - generic [ref=e120]: 6 млн ₴ · 9/18 km · ready
        - tooltip "МВГ detail Primary 9 km · Outer 18 km Ammo 5/5 · Reload 20s · Shot pause 3s Primary acc 68% · Outer acc 31.3% Mobility 4/4 · Maintenance risk Low Fatigue 8% · Nominal · strained":
          - strong: МВГ detail
          - generic: Primary 9 km · Outer 18 km
          - generic: Ammo 5/5 · Reload 20s · Shot pause 3s
          - generic: Primary acc 68% · Outer acc 31.3%
          - generic: Mobility 4/4 · Maintenance risk Low
          - generic: Fatigue 8% · Nominal · strained
        - generic "МВГ readiness" [ref=e121]
      - button "6 Катер Гюрза-М 11 млн ₴ · 12/24 km · ready Катер detail Primary 12 km · Outer 24 km Ammo 6 · Reload 17s · Shot pause 2s Primary acc 74% · Outer acc 34% Mobility 3/4 · Maintenance risk Low Fatigue 0% · Nominal · not placed Катер Гюрза-М readiness" [ref=e123] [cursor=pointer]:
        - generic [ref=e125]: "6"
        - strong [ref=e126]: Катер Гюрза-М
        - generic [ref=e127]: 11 млн ₴ · 12/24 km · ready
        - tooltip "Катер detail Primary 12 km · Outer 24 km Ammo 6 · Reload 17s · Shot pause 2s Primary acc 74% · Outer acc 34% Mobility 3/4 · Maintenance risk Low Fatigue 0% · Nominal · not placed":
          - strong: Катер detail
          - generic: Primary 12 km · Outer 24 km
          - generic: Ammo 6 · Reload 17s · Shot pause 2s
          - generic: Primary acc 74% · Outer acc 34%
          - generic: Mobility 3/4 · Maintenance risk Low
          - generic: Fatigue 0% · Nominal · not placed
        - generic "Катер Гюрза-М readiness" [ref=e128]
      - button "inf Комплекс РЕБ 18 млн ₴ · 15/17 km · ready РЕБ detail Primary 15 km · Outer 17 km Ammo inf · Reload 0.0s · Shot pause 5s Primary acc 12% · Outer acc 8% Mobility 2/4 · Maintenance risk Low Fatigue 0% · Nominal · not placed Комплекс РЕБ readiness" [ref=e130] [cursor=pointer]:
        - generic [ref=e132]: inf
        - strong [ref=e133]: Комплекс РЕБ
        - generic [ref=e134]: 18 млн ₴ · 15/17 km · ready
        - tooltip "РЕБ detail Primary 15 km · Outer 17 km Ammo inf · Reload 0.0s · Shot pause 5s Primary acc 12% · Outer acc 8% Mobility 2/4 · Maintenance risk Low Fatigue 0% · Nominal · not placed":
          - strong: РЕБ detail
          - generic: Primary 15 km · Outer 17 km
          - generic: Ammo inf · Reload 0.0s · Shot pause 5s
          - generic: Primary acc 12% · Outer acc 8%
          - generic: Mobility 2/4 · Maintenance risk Low
          - generic: Fatigue 0% · Nominal · not placed
        - generic "Комплекс РЕБ readiness" [ref=e135]
      - button "3 ПЗРК Stinger 12 млн ₴ · 16/31 km · ready ПЗРК detail Primary 16 km · Outer 31 km Ammo 3 · Reload 26s · Shot pause 4s Primary acc 75% · Outer acc 34.5% Mobility 4/4 · Maintenance risk Low Fatigue 0% · Nominal · not placed ПЗРК Stinger readiness" [ref=e137] [cursor=pointer]:
        - generic [ref=e139]: "3"
        - strong [ref=e140]: ПЗРК Stinger
        - generic [ref=e141]: 12 млн ₴ · 16/31 km · ready
        - tooltip "ПЗРК detail Primary 16 km · Outer 31 km Ammo 3 · Reload 26s · Shot pause 4s Primary acc 75% · Outer acc 34.5% Mobility 4/4 · Maintenance risk Low Fatigue 0% · Nominal · not placed":
          - strong: ПЗРК detail
          - generic: Primary 16 km · Outer 31 km
          - generic: Ammo 3 · Reload 26s · Shot pause 4s
          - generic: Primary acc 75% · Outer acc 34.5%
          - generic: Mobility 4/4 · Maintenance risk Low
          - generic: Fatigue 0% · Nominal · not placed
        - generic "ПЗРК Stinger readiness" [ref=e142]
      - button "8 Gepard 22 млн ₴ · 20/40 km · ready Gepard detail Primary 20 km · Outer 40 km Ammo 8 · Reload 22s · Shot pause 1.5s Primary acc 85% · Outer acc 39.1% Mobility 2/4 · Maintenance risk Moderate Fatigue 0% · Nominal · not placed Gepard readiness" [ref=e144] [cursor=pointer]:
        - generic [ref=e146]: "8"
        - strong [ref=e147]: Gepard
        - generic [ref=e148]: 22 млн ₴ · 20/40 km · ready
        - tooltip "Gepard detail Primary 20 km · Outer 40 km Ammo 8 · Reload 22s · Shot pause 1.5s Primary acc 85% · Outer acc 39.1% Mobility 2/4 · Maintenance risk Moderate Fatigue 0% · Nominal · not placed":
          - strong: Gepard detail
          - generic: Primary 20 km · Outer 40 km
          - generic: Ammo 8 · Reload 22s · Shot pause 1.5s
          - generic: Primary acc 85% · Outer acc 39.1%
          - generic: Mobility 2/4 · Maintenance risk Moderate
          - generic: Fatigue 0% · Nominal · not placed
        - generic "Gepard readiness" [ref=e149]
      - button "4 Бук 45 млн ₴ · 35/69 km · ready Бук detail Primary 35 km · Outer 69 km Ammo 4 · Reload 34s · Shot pause 6s Primary acc 78% · Outer acc 35.9% Mobility 2/4 · Maintenance risk Moderate Fatigue 0% · Nominal · not placed Бук readiness" [ref=e151] [cursor=pointer]:
        - generic [ref=e153]: "4"
        - strong [ref=e154]: Бук
        - generic [ref=e155]: 45 млн ₴ · 35/69 km · ready
        - tooltip "Бук detail Primary 35 km · Outer 69 km Ammo 4 · Reload 34s · Shot pause 6s Primary acc 78% · Outer acc 35.9% Mobility 2/4 · Maintenance risk Moderate Fatigue 0% · Nominal · not placed":
          - strong: Бук detail
          - generic: Primary 35 km · Outer 69 km
          - generic: Ammo 4 · Reload 34s · Shot pause 6s
          - generic: Primary acc 78% · Outer acc 35.9%
          - generic: Mobility 2/4 · Maintenance risk Moderate
          - generic: Fatigue 0% · Nominal · not placed
        - generic "Бук readiness" [ref=e156]
      - button "4 С-300 70 млн ₴ · 45/90 km · ready С-300 detail Primary 45 km · Outer 90 km Ammo 4 · Reload 42s · Shot pause 7s Primary acc 78% · Outer acc 38% Mobility 1/4 · Maintenance risk Moderate Fatigue 0% · Nominal · not placed С-300 readiness" [ref=e158] [cursor=pointer]:
        - generic [ref=e160]: "4"
        - strong [ref=e161]: С-300
        - generic [ref=e162]: 70 млн ₴ · 45/90 km · ready
        - tooltip "С-300 detail Primary 45 km · Outer 90 km Ammo 4 · Reload 42s · Shot pause 7s Primary acc 78% · Outer acc 38% Mobility 1/4 · Maintenance risk Moderate Fatigue 0% · Nominal · not placed":
          - strong: С-300 detail
          - generic: Primary 45 km · Outer 90 km
          - generic: Ammo 4 · Reload 42s · Shot pause 7s
          - generic: Primary acc 78% · Outer acc 38%
          - generic: Mobility 1/4 · Maintenance risk Moderate
          - generic: Fatigue 0% · Nominal · not placed
        - generic "С-300 readiness" [ref=e163]
      - button "4 IRIS-T 90 млн ₴ · 43/86 km · ready IRIS-T detail Primary 43 km · Outer 86 km Ammo 4 · Reload 48s · Shot pause 4s Primary acc 92% · Outer acc 42.3% Mobility 1/4 · Maintenance risk Moderate Fatigue 0% · Nominal · not placed IRIS-T readiness" [ref=e165] [cursor=pointer]:
        - generic [ref=e167]: "4"
        - strong [ref=e168]: IRIS-T
        - generic [ref=e169]: 90 млн ₴ · 43/86 km · ready
        - tooltip "IRIS-T detail Primary 43 km · Outer 86 km Ammo 4 · Reload 48s · Shot pause 4s Primary acc 92% · Outer acc 42.3% Mobility 1/4 · Maintenance risk Moderate Fatigue 0% · Nominal · not placed":
          - strong: IRIS-T detail
          - generic: Primary 43 km · Outer 86 km
          - generic: Ammo 4 · Reload 48s · Shot pause 4s
          - generic: Primary acc 92% · Outer acc 42.3%
          - generic: Mobility 1/4 · Maintenance risk Moderate
          - generic: Fatigue 0% · Nominal · not placed
        - generic "IRIS-T readiness" [ref=e170]
      - button "6 NASAMS 100 млн ₴ · 37/75 km · ready NASAMS detail Primary 37 km · Outer 75 km Ammo 6 · Reload 45s · Shot pause 5s Primary acc 90% · Outer acc 41.4% Mobility 1/4 · Maintenance risk Moderate Fatigue 0% · Nominal · not placed NASAMS readiness" [disabled] [ref=e172]:
        - generic [ref=e174]: "6"
        - strong [ref=e175]: NASAMS
        - generic [ref=e176]: 100 млн ₴ · 37/75 km · ready
        - tooltip "NASAMS detail Primary 37 km · Outer 75 km Ammo 6 · Reload 45s · Shot pause 5s Primary acc 90% · Outer acc 41.4% Mobility 1/4 · Maintenance risk Moderate Fatigue 0% · Nominal · not placed":
          - strong: NASAMS detail
          - generic: Primary 37 km · Outer 75 km
          - generic: Ammo 6 · Reload 45s · Shot pause 5s
          - generic: Primary acc 90% · Outer acc 41.4%
          - generic: Mobility 1/4 · Maintenance risk Moderate
          - generic: Fatigue 0% · Nominal · not placed
        - generic "NASAMS readiness" [ref=e177]
      - button "2 Patriot PAC-3 220 млн ₴ · 64/128 km · ready Patriot detail Primary 64 km · Outer 128 km Ammo 2 · Reload 65s · Shot pause 6s Primary acc 95% · Outer acc 43.7% Mobility 1/4 · Maintenance risk Moderate Fatigue 0% · Nominal · not placed Patriot PAC-3 readiness" [disabled] [ref=e179]:
        - generic [ref=e181]: "2"
        - strong [ref=e182]: Patriot PAC-3
        - generic [ref=e183]: 220 млн ₴ · 64/128 km · ready
        - tooltip "Patriot detail Primary 64 km · Outer 128 km Ammo 2 · Reload 65s · Shot pause 6s Primary acc 95% · Outer acc 43.7% Mobility 1/4 · Maintenance risk Moderate Fatigue 0% · Nominal · not placed":
          - strong: Patriot detail
          - generic: Primary 64 km · Outer 128 km
          - generic: Ammo 2 · Reload 65s · Shot pause 6s
          - generic: Primary acc 95% · Outer acc 43.7%
          - generic: Mobility 1/4 · Maintenance risk Moderate
          - generic: Fatigue 0% · Nominal · not placed
        - generic "Patriot PAC-3 readiness" [ref=e184]
      - button "6 Interceptor Drone Operators 30 mln UAH · 18/30 km · ready Drone Ops detail Primary 18 km · Outer 30 km Ammo 6 · Reload 35s · Shot pause 3s Primary acc 82% · Outer acc 44% Mobility 4/4 · Maintenance risk Moderate Fatigue 0% · Nominal · not placed Interceptor Drone Operators readiness" [ref=e186] [cursor=pointer]:
        - generic [ref=e188]: "6"
        - strong [ref=e189]: Interceptor Drone Operators
        - generic [ref=e190]: 30 mln UAH · 18/30 km · ready
        - tooltip "Drone Ops detail Primary 18 km · Outer 30 km Ammo 6 · Reload 35s · Shot pause 3s Primary acc 82% · Outer acc 44% Mobility 4/4 · Maintenance risk Moderate Fatigue 0% · Nominal · not placed":
          - strong: Drone Ops detail
          - generic: Primary 18 km · Outer 30 km
          - generic: Ammo 6 · Reload 35s · Shot pause 3s
          - generic: Primary acc 82% · Outer acc 44%
          - generic: Mobility 4/4 · Maintenance risk Moderate
          - generic: Fatigue 0% · Nominal · not placed
        - generic "Interceptor Drone Operators readiness" [ref=e191]
```

# Test source

```ts
  1  | import AxeBuilder from "@axe-core/playwright";
  2  | import { expect, test } from "@playwright/test";
  3  | 
  4  | test("mobile Campaign runs from placement through authoritative replay and reconnect", async ({ page }) => {
  5  |   await page.goto("/shieldline/");
  6  |   await page.getByRole("button", { name: /Campaign/ }).click();
  7  |   const tutorialButton = page.getByRole("button", { name: /Begin watch/ });
  8  |   if (await tutorialButton.isVisible()) await tutorialButton.click();
  9  | 
  10 |   const drawer = page.getByRole("complementary", { name: /Defense units/ });
  11 |   const controls = page.getByRole("region", { name: "Operation controls" });
  12 |   await expect(drawer).toBeVisible();
  13 |   await expect(controls).toBeVisible();
  14 |   const drawerBox = await drawer.boundingBox();
  15 |   const controlsBox = await controls.boundingBox();
  16 |   expect(drawerBox && controlsBox && drawerBox.y + drawerBox.height <= controlsBox.y + 2).toBeTruthy();
  17 | 
  18 |   const map = page.locator(".leaflet-stage");
  19 |   const mapBox = await map.boundingBox();
  20 |   if (!mapBox) throw new Error("Campaign map did not render.");
  21 |   await page.getByRole("button", { name: /Radar 35D6/ }).click();
  22 |   await page.mouse.click(mapBox.x + 265, mapBox.y + 300);
  23 |   await page.getByRole("button", { name: /МВГ/ }).click();
  24 |   await page.mouse.click(mapBox.x + 175, mapBox.y + 275);
  25 | 
  26 |   await expect(page.getByRole("button", { name: /Start operation/ })).toBeEnabled();
  27 |   await page.getByRole("button", { name: "x60" }).click();
  28 |   await page.getByRole("button", { name: /Start operation/ }).click();
  29 |   await expect(page.getByText(/Authoritative server result/)).toBeVisible({ timeout: 15_000 });
  30 |   await expect(page.getByLabel("Campaign tactical replay")).toBeVisible();
  31 | 
  32 |   await page.reload();
  33 |   await expect(page.getByRole("button", { name: /New operation/ })).toBeVisible();
> 34 |   await page.getByRole("button", { name: /Report/ }).click();
     |                                                      ^ Error: locator.click: Test timeout of 30000ms exceeded.
  35 |   await expect(page.getByText(/Authoritative server result/)).toBeVisible();
  36 | 
  37 |   const accessibility = await new AxeBuilder({ page }).include(".app-rail").include(".operation-controls").include(".command-drawer").analyze();
  38 |   expect(accessibility.violations.filter((violation) => violation.impact === "critical")).toEqual([]);
  39 | });
  40 | 
```