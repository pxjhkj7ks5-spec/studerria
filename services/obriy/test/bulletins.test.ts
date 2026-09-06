import { afterEach, describe, expect, it, vi } from "vitest";
import { parseBulletin, normalizeText } from "../src/bulletins/parser.js";
import { matchingAreas, AREAS } from "../src/bulletins/areas.js";
import { parseChannelHtml } from "../src/bulletins/html.js";
import {
  fetchChannelPage,
  BulletinCollector,
} from "../src/bulletins/collector.js";
import { loadConfig } from "../src/config.js";
import type { BulletinStore } from "../src/bulletins/store.js";

// Pagination pauses are transport pacing, not part of these deterministic cursor assertions.
vi.mock("node:timers/promises", () => ({ setTimeout: async () => undefined }));

function html(
  id = 101,
  text = "Київ — повітряна тривога",
  extra = "",
  at = new Date().toISOString(),
) {
  return `<div class="tgme_channel_info"></div><div class="tgme_widget_message" data-post="AerisRimor/${id}"><div class="tgme_widget_message_text">${text}</div><a class="tgme_widget_message_date"><time datetime="${at}"></time></a>${extra}</div>`;
}
describe("civil bulletin parser", () => {
  it.each([
    ["Київ — повітряна тривога!", "kyiv"],
    ["Бориспіль, увага!", "boryspil"],
    ["Броварський/Бориспільський район — повітряна тривога", "brovary-raion"],
    ["У Київській області повітряна тривога", "kyiv-oblast"],
    ["У Білій Церкві повітряна тривога", "bilatserkva"],
    ["Київ: ймовірна загроза", "kyiv"],
    ["Бориспіь, увага", "boryspil"],
    ["Броваpи, увага", "brovary"],
    ["Київ: тривга", "kyiv"],
  ])("recognizes an explicit locality in %s", (text, area) => {
    expect(parseBulletin(text)).toMatchObject({
      kind: "warning",
      areaIds: expect.arrayContaining([area]),
    });
  });
  it.each([
    "Ще один",
    "Другий теж",
    "На Васік 2",
    "Київ",
    "Київ: вчора була тривога",
    "Бровари: навчальна тривога",
    "Київ: тестове попередження, тривога",
    "У Києві авто влетіло у відбійник",
    "Бровари: завтра навчальна тривога",
    "Увага, збір коштів для Києва",
    "Новини Києва. Увага в іншому місті",
    "Київ: футбол. Повітряна тривога",
    "Тривога",
    "До нас!",
  ])("does not infer a warning from %s", (text) =>
    expect(parseBulletin(text).kind).toBe("other"),
  );
  it.each([
    "Київ — відбій тривоги",
    "Київ — загрози немає",
    "Київ: хибна тривога",
    "Київ: тривога не підтвердилась",
  ])("keeps %s distinct from a warning", (text) =>
    expect(parseBulletin(text).kind).toBe("all_clear_report"),
  );
  it("uses an explicit correction in the same post", () => {
    expect(parseBulletin("Київ: тривога. Київ: відбій").kind).toBe(
      "all_clear_report",
    );
    expect(parseBulletin("Київ: відбій. Бориспіль: увага").areaIds).toEqual([
      "boryspil",
    ]);
  });
  it("marks typo matches as uncertain and preserves input", () => {
    expect(parseBulletin("Бориспіь, увага").uncertain).toBe(true);
    expect(normalizeText("  Броваpи—УВАГА\n")).toBe("бровари увага");
  });
  it("does not expand a city warning to the entire oblast", () => {
    expect(matchingAreas(["kyiv-oblast"], ["boryspil"])).toEqual([]);
    expect(
      matchingAreas(["boryspil"], ["kyiv-oblast", "boryspil-raion"]),
    ).toEqual(["kyiv-oblast", "boryspil-raion"]);
    expect(matchingAreas(["kyiv"], ["kyiv-oblast"])).toEqual([]);
    expect(matchingAreas(["irpin"], ["brovary-raion"])).toEqual([]);
  });
  it.each(AREAS)("supports the displayed name $label", (area) =>
    expect(parseBulletin(`${area.label}: повітряна тривога`).areaIds).toContain(
      area.id,
    ),
  );
});
describe("public HTML contract", () => {
  it("retains captions, line breaks and safe source links, ignoring reactions", () => {
    const now = new Date();
    const a = parseChannelHtml(
      html(
        101,
        "Київ<br>увага &amp; обережно",
        '<span class="tgme_widget_message_views">10</span>',
        now.toISOString(),
      ),
      "AerisRimor",
      now,
    )[0];
    const b = parseChannelHtml(
      html(
        101,
        "Київ<br>увага &amp; обережно",
        '<span class="tgme_widget_message_views">1000</span>',
        now.toISOString(),
      ),
      "AerisRimor",
      now,
    )[0];
    expect(a.text).toBe("Київ\nувага & обережно");
    expect(a.contentHash).toBe(b.contentHash);
    expect(a.url).toBe("https://t.me/AerisRimor/101");
  });
  it("stores reply metadata but does not use it to infer a bulletin", () => {
    const a = parseChannelHtml(
      html(
        102,
        "Ще один",
        '<a class="tgme_widget_message_reply" href="https://t.me/AerisRimor/101">quoted warning</a>',
      ),
      "AerisRimor",
    )[0];
    expect(a.replyTo).toBe(101);
    expect(parseBulletin(a.text).kind).toBe("other");
  });
  it("changes the content hash on an edit", () => {
    expect(
      parseChannelHtml(html(1, "Київ: увага"), "AerisRimor")[0].contentHash,
    ).not.toBe(
      parseChannelHtml(html(1, "Київ: відбій"), "AerisRimor")[0].contentHash,
    );
  });
  it.each([
    "<html>login</html>",
    "<html>captcha</html>",
    html().replace("AerisRimor/101", "other/101"),
    html(101, "text", "", "2099-01-01T00:00:00Z"),
  ])("fails closed on unavailable or malformed pages", (body) => {
    expect(() => parseChannelHtml(body, "AerisRimor")).toThrow();
  });
  it("handles media-only messages without inventing text", () =>
    expect(parseChannelHtml(html(1, ""), "AerisRimor")[0].text).toBe(""));
  it("rejects 429, oversized bodies, redirects and invalid content types", async () => {
    const signal = new AbortController().signal;
    await expect(
      fetchChannelPage(
        "AerisRimor",
        undefined,
        signal,
        async () =>
          new Response("", { status: 429, headers: { "retry-after": "120" } }),
      ),
    ).rejects.toMatchObject({ waitMs: 120000 });
    await expect(
      fetchChannelPage(
        "AerisRimor",
        undefined,
        signal,
        async () =>
          new Response("x", {
            headers: {
              "content-type": "text/html",
              "content-length": "9999999",
            },
          }),
      ),
    ).rejects.toThrow();
    await expect(
      fetchChannelPage(
        "AerisRimor",
        undefined,
        signal,
        async () =>
          new Response("{}", {
            headers: { "content-type": "application/json" },
          }),
      ),
    ).rejects.toThrow();
    const fetcher = vi.fn(
      async () =>
        new Response(html(), { headers: { "content-type": "text/html" } }),
    );
    await fetchChannelPage("AerisRimor", 100, signal, fetcher);
    expect(fetcher.mock.calls[0]).toEqual([
      "https://t.me/s/AerisRimor?before=100",
      expect.objectContaining({ redirect: "error" }),
    ]);
  });
});
afterEach(() => vi.useRealTimers());
describe("collector cursor recovery", () => {
  function setup(cursor: number | null) {
    const ingest = vi.fn(async () => {});
    const getRuntime = vi.fn(async () => null);
    const store = {
      cursor: async () => cursor,
      ingest,
      store: { getRuntime },
    } as unknown as BulletinStore;
    return { ingest, store, getRuntime };
  }
  it("bootstraps without allowing historical delivery", async () => {
    const { store, ingest } = setup(null);
    const collector = new BulletinCollector(
      loadConfig({}),
      store,
      async () =>
        new Response(html(), { headers: { "content-type": "text/html" } }),
    );
    await collector.poll("AerisRimor");
    expect(ingest.mock.calls[0]).toEqual([
      "AerisRimor",
      expect.any(Array),
      101,
      false,
      true,
      null,
    ]);
    expect(collector.health().AerisRimor.state).toBe("live");
  });
  it("fetches a missing page before committing the cursor", async () => {
    vi.useFakeTimers();
    const { store, ingest } = setup(100);
    const fetcher = vi.fn(
      async (url: string) =>
        new Response(html(url.includes("before=") ? 100 : 120), {
          headers: { "content-type": "text/html" },
        }),
    );
    const collector = new BulletinCollector(loadConfig({}), store, fetcher);
    const task = collector.poll("AerisRimor");
    await vi.runAllTimersAsync();
    await task;
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(ingest.mock.calls[0]).toEqual([
      "AerisRimor",
      expect.any(Array),
      120,
      true,
      true,
      null,
    ]);
  });
  it("never advances the cursor on malformed HTML", async () => {
    const { store, ingest } = setup(100);
    const collector = new BulletinCollector(
      loadConfig({}),
      store,
      async () =>
        new Response("broken", { headers: { "content-type": "text/html" } }),
    );
    await expect(collector.poll("AerisRimor")).rejects.toThrow();
    expect(ingest).not.toHaveBeenCalled();
  });
  it("persists a large-gap marker and advances only the original head after recovery", async () => {
    vi.useFakeTimers();
    const { store, ingest, getRuntime } = setup(1);
    const fetcher = vi.fn(
      async (url: string) =>
        new Response(
          html(
            url.includes("before=")
              ? Number(new URL(url).searchParams.get("before")) - 1
              : 100,
          ),
          { headers: { "content-type": "text/html" } },
        ),
    );
    const first = new BulletinCollector(loadConfig({}), store, fetcher);
    const task = first.poll("AerisRimor");
    await vi.runAllTimersAsync();
    await task;
    expect(ingest.mock.calls[0]).toEqual([
      "AerisRimor",
      expect.any(Array),
      100,
      true,
      false,
      { before: 90, highId: 100 },
    ]);
    getRuntime.mockResolvedValue({ before: 2, highId: 100 } as never);
    const second = new BulletinCollector(
      loadConfig({}),
      store,
      async (url) =>
        new Response(html(url.includes("before=") ? 1 : 120), {
          headers: { "content-type": "text/html" },
        }),
    );
    const next = second.poll("AerisRimor");
    await vi.runAllTimersAsync();
    await next;
    expect(ingest.mock.calls[1]).toEqual([
      "AerisRimor",
      expect.any(Array),
      100,
      true,
      true,
      null,
    ]);
  });
});
