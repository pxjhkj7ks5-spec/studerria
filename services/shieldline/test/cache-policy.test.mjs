import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const readSource = (relativePath) => readFile(new URL(relativePath, import.meta.url), "utf8");

test("the app checks for service worker updates without the HTTP cache", async () => {
  const source = await readSource("../src/main.tsx");

  assert.match(source, /updateViaCache:\s*"none"/);
  assert.match(source, /registration\.update\(\)/);
  assert.match(source, /Boolean\(navigator\.serviceWorker\.controller\)/);
  assert.match(source, /addEventListener\("controllerchange"/);
  assert.match(source, /window\.location\.reload\(\)/);
});

test("service worker navigations bypass Safari's HTTP cache", async () => {
  const source = await readSource("../public/sw.js");

  assert.match(source, /new Request\(event\.request, \{ cache: "no-store" \}\)/);
  assert.match(source, /shieldline-runtime-v6/);
  assert.match(source, /caches\.open\(CACHE\)/);
  assert.doesNotMatch(source, /caches\.match\(/);
});

test("mutable shell files are served with revalidation headers", async () => {
  const source = await readSource("../server.mjs");

  assert.match(source, /no-store, no-cache, must-revalidate/);
  assert.match(source, /Pragma: "no-cache", Expires: "0"/);
});

test("the Telegram shell loads before the app and may execute under CSP", async () => {
  const [html, server] = await Promise.all([
    readSource("../index.html"),
    readSource("../server.mjs"),
  ]);

  const telegramScript = html.indexOf("https://telegram.org/js/telegram-web-app.js");
  const appScript = html.indexOf('src="/src/main.tsx"');
  assert.ok(telegramScript >= 0 && telegramScript < appScript);
  assert.match(html, /id="telegram-web-app-sdk" async/);
  assert.match(server, /script-src 'self' https:\/\/telegram\.org/);
});

test("Telegram safe-area changes keep the mobile HUD below native controls", async () => {
  const [shell, styles] = await Promise.all([
    readSource("../src/platform/telegramShell.ts"),
    readSource("../src/styles/app.css"),
  ]);

  assert.match(shell, /onEvent\?\.\("safeAreaChanged", sync\)/);
  assert.match(shell, /onEvent\?\.\("contentSafeAreaChanged", sync\)/);
  assert.match(styles, /--tg-content-safe-area-inset-top/);
  assert.match(styles, /\.shell--mobile-live \.strip-brand \{\s*display: flex/);
});

test("stale offline projections cannot overwrite the migrated game state", async () => {
  const [offlineStore, main] = await Promise.all([
    readSource("../src/platform/offlineStore.ts"),
    readSource("../src/main.tsx"),
  ]);

  assert.match(offlineStore, /PROJECTION_SCHEMA_VERSION = 2/);
  assert.match(offlineStore, /projection\.schemaVersion !== PROJECTION_SCHEMA_VERSION/);
  assert.match(offlineStore, /normalizePersistedGame/);
  assert.match(main, /AppErrorBoundary/);
});
