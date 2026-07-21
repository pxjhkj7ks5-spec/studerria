import { expect, test } from "@playwright/test";

async function installAudioHarness(page: import("@playwright/test").Page) {
  await page.addInitScript(() => {
    const audioWindow = window as typeof window & {
      __audioFetches: string[];
      __audioStarts: Array<{ offset: number; duration: number }>;
      __audioStops: number;
    };
    audioWindow.__audioFetches = [];
    audioWindow.__audioStarts = [];
    audioWindow.__audioStops = 0;

    class FakeAudioParam {
      value = 1;
      setTargetAtTime(value: number) { this.value = value; }
    }
    class FakeGain {
      gain = new FakeAudioParam();
      connect() { return this; }
      disconnect() { return undefined; }
    }
    class FakeSource {
      buffer: { duration: number } | null = null;
      playbackRate = new FakeAudioParam();
      private ended: (() => void) | null = null;
      connect() { return this; }
      disconnect() { return undefined; }
      addEventListener(_name: string, listener: () => void) { this.ended = listener; }
      start(_when: number, offset: number, duration: number) {
        audioWindow.__audioStarts.push({ offset, duration });
        window.setTimeout(() => this.ended?.(), 0);
      }
      stop() { audioWindow.__audioStops += 1; this.ended?.(); }
    }
    class FakeAudioContext {
      state: "suspended" | "running" = "suspended";
      currentTime = 0;
      destination = {};
      createGain() { return new FakeGain(); }
      createBufferSource() { return new FakeSource(); }
      decodeAudioData() { return Promise.resolve({ duration: 40 }); }
      resume() { this.state = "running"; return Promise.resolve(); }
      suspend() { this.state = "suspended"; return Promise.resolve(); }
    }
    Object.defineProperty(window, "AudioContext", { configurable: true, value: FakeAudioContext });
    const nativeFetch = window.fetch.bind(window);
    window.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (/\/audio\/sfx\/.*\.mp3(?:$|\?)/.test(url)) {
        audioWindow.__audioFetches.push(url);
        return Promise.resolve(new Response(new Uint8Array([1, 2, 3]), { status: 200, headers: { "Content-Type": "audio/mpeg" } }));
      }
      return nativeFetch(input, init);
    };
    localStorage.setItem("shieldline-tutorial-complete-v1", "true");
    localStorage.setItem("shieldline-live-v7", JSON.stringify({
      state: { campaignMode: "training", activeGameMode: "training", pendingCampaignMode: null, mapMode: "live", operationPhase: "planning" },
      version: 20,
    }));
  });
}

test("audio unlocks on player interaction, respects mute, and never replays hydrated combat cues", async ({ page }) => {
  await installAudioHarness(page);
  await page.goto("/shieldline/?legacy=1&mode=training");
  await expect(page.locator(".leaflet-stage")).toBeVisible();

  await page.evaluate(async () => {
    const { useGameStore } = await import("/shieldline/src/store/useGameStore.ts");
    const current = useGameStore.getState().game;
    useGameStore.setState({ game: { ...current, log: [{ id: "pre-unlock-impact", time: "20:00", title: "Impact", body: "Old impact", tone: "danger", soundCue: "result.impact" }, ...current.log] } });
  });
  await page.waitForTimeout(100);

  const navigation = page.getByRole("navigation", { name: "Панелі Shieldline" });
  await navigation.getByRole("button", { name: "Налаштування" }).click();
  await expect.poll(() => page.evaluate(() => (window as typeof window & { __audioStarts: unknown[] }).__audioStarts.length)).toBeGreaterThan(0);
  expect(await page.evaluate(() => (window as typeof window & { __audioFetches: string[] }).__audioFetches.some((url) => url.includes("impact.mp3")))).toBe(false);

  await page.evaluate(async () => {
    const { useGameStore } = await import("/shieldline/src/store/useGameStore.ts");
    const current = useGameStore.getState().game;
    useGameStore.setState({ game: { ...current, log: [{ id: "new-impact", time: "20:01", title: "Impact", body: "New impact", tone: "danger", soundCue: "result.impact" }, ...current.log] } });
  });
  await expect.poll(() => page.evaluate(() => (window as typeof window & { __audioFetches: string[] }).__audioFetches.filter((url) => url.includes("impact.mp3")).length)).toBe(1);

  await page.getByRole("checkbox", { name: "Увімкнути звуковий супровід" }).uncheck();
  await page.waitForTimeout(100);
  const afterMute = await page.evaluate(() => (window as typeof window & { __audioStarts: unknown[] }).__audioStarts.length);
  await navigation.getByRole("button", { name: "ППО" }).click();
  await page.waitForTimeout(200);
  expect(await page.evaluate(() => (window as typeof window & { __audioStarts: unknown[] }).__audioStarts.length)).toBe(afterMute);
});

test("air raid sounds once for a global escalation and hidden updates are not replayed", async ({ page }) => {
  await installAudioHarness(page);
  await page.goto("/shieldline/?legacy=1&mode=training");
  await expect(page.locator(".leaflet-stage")).toBeVisible();
  await page.getByRole("navigation", { name: "Панелі Shieldline" }).getByRole("button", { name: "ППО" }).click();

  const setAlerts = (states: string[]) => page.evaluate(async (nextStates) => {
    const { useGameStore } = await import("/shieldline/src/store/useGameStore.ts");
    const current = useGameStore.getState().game;
    useGameStore.setState({ game: { ...current, cities: current.cities.map((city, index) => ({ ...city, alertState: (nextStates[index] || city.alertState) as typeof city.alertState })) } });
  }, states);

  await setAlerts(["air-raid", "air-raid"]);
  await expect.poll(() => page.evaluate(() => (window as typeof window & { __audioFetches: string[] }).__audioFetches.filter((url) => url.includes("siren.mp3")).length)).toBe(1);
  await setAlerts(["air-raid", "air-raid", "air-raid"]);
  await page.waitForTimeout(150);
  expect(await page.evaluate(() => (window as typeof window & { __audioFetches: string[] }).__audioFetches.filter((url) => url.includes("siren.mp3")).length)).toBe(1);

  await page.evaluate(() => {
    const audioWindow = window as typeof window & { __shieldlineHidden: boolean };
    audioWindow.__shieldlineHidden = true;
    Object.defineProperty(document, "hidden", { configurable: true, get: () => audioWindow.__shieldlineHidden });
    document.dispatchEvent(new Event("visibilitychange"));
  });
  await page.evaluate(async () => {
    const { useGameStore } = await import("/shieldline/src/store/useGameStore.ts");
    const current = useGameStore.getState().game;
    useGameStore.setState({ game: { ...current, log: [{ id: "hidden-impact", time: "20:02", title: "Impact", body: "Hidden", tone: "danger", soundCue: "result.impact" }, ...current.log] } });
  });
  await page.evaluate(() => {
    const audioWindow = window as typeof window & { __shieldlineHidden: boolean };
    audioWindow.__shieldlineHidden = false;
    document.dispatchEvent(new Event("visibilitychange"));
  });
  await page.waitForTimeout(200);
  expect(await page.evaluate(() => (window as typeof window & { __audioFetches: string[] }).__audioFetches.some((url) => url.includes("impact.mp3")))).toBe(false);
});
