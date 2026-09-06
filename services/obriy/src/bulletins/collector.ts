import { setTimeout as delay } from "node:timers/promises";
import type { Config } from "../config.js";
import type { SourceHealth } from "../ingestion/types.js";
import { retryAfterMs, type SourceFetch } from "../ingestion/http.js";
import { parseChannelHtml } from "./html.js";
import { CHANNELS, type Channel, type ChannelMessage } from "./types.js";
import { BulletinStore } from "./store.js";

class ChannelFetchError extends Error {
  constructor(readonly waitMs = 0) {
    super("channel_fetch_failed");
  }
}
export async function fetchChannelPage(
  channel: Channel,
  before: number | undefined,
  signal: AbortSignal,
  fetcher: SourceFetch = fetch,
): Promise<ChannelMessage[]> {
  if (
    !CHANNELS.includes(channel) ||
    (before !== undefined && (!Number.isSafeInteger(before) || before < 1))
  )
    throw new Error("channel_not_allowed");
  const response = await fetcher(
    `https://t.me/s/${channel}${before ? `?before=${before}` : ""}`,
    {
      headers: { Accept: "text/html" },
      redirect: "error",
      signal: AbortSignal.any([signal, AbortSignal.timeout(10000)]),
    },
  );
  if (!response.ok) {
    await response.body?.cancel();
    throw new ChannelFetchError(
      retryAfterMs(response.headers.get("retry-after"), Date.now(), 30000),
    );
  }
  const maxBytes = 2_097_152;
  if (
    !response.body ||
    Number(response.headers.get("content-length")) > maxBytes ||
    !response.headers.get("content-type")?.includes("text/html")
  ) {
    await response.body?.cancel();
    throw new ChannelFetchError();
  }
  const reader = response.body.getReader(),
    chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      size += part.value.byteLength;
      if (size > maxBytes) {
        await reader.cancel();
        throw new ChannelFetchError();
      }
      chunks.push(part.value);
    }
  } finally {
    reader.releaseLock();
  }
  return parseChannelHtml(
    Buffer.concat(chunks, size).toString("utf8"),
    channel,
  );
}

export class BulletinCollector {
  private controller = new AbortController();
  private tasks: Promise<void>[] = [];
  private states = Object.fromEntries(
    CHANNELS.map((c) => [c, { state: "connecting", transport: "public-web" }]),
  ) as Record<Channel, SourceHealth>;
  constructor(
    readonly config: Config,
    readonly store: BulletinStore,
    readonly fetcher: SourceFetch = fetch,
  ) {}
  health() {
    return structuredClone(this.states);
  }
  start() {
    if (this.tasks.length) return;
    this.tasks = CHANNELS.map((c, i) =>
      this.loop(
        c,
        i * Math.floor(this.config.OBRIY_BULLETIN_POLL_MS / CHANNELS.length),
      ),
    );
    this.tasks.push(this.worker());
  }
  async poll(channel: Channel) {
    const signal = this.controller.signal;
    const cursor = await this.store.cursor(channel);
    let page = await fetchChannelPage(channel, undefined, signal, this.fetcher);
    const latest = page.at(-1)!.messageId;
    const messages = new Map(page.map((m) => [m.messageId, m]));
    let complete = cursor === null || page[0].messageId <= cursor;
    // Recover up to 200 posts per poll. Larger gaps advance a durable backfill marker.
    const key = `bulletin-backfill:${channel}`;
    const backfill = await this.store.store.getRuntime<{
      before: number;
      highId: number;
    }>(key);
    let before = backfill?.before ?? page[0].messageId;
    for (let n = 0; !complete && n < 10; n++) {
      await delay(1000, undefined, { signal });
      page = await fetchChannelPage(channel, before, signal, this.fetcher);
      if (page[0].messageId >= before)
        throw new Error("channel_pagination_stalled");
      page.forEach((m) => messages.set(m.messageId, m));
      before = page[0].messageId;
      complete = before <= cursor!;
    }
    await this.store.ingest(
      channel,
      [...messages.values()].sort((a, b) => a.messageId - b.messageId),
      backfill?.highId ?? latest,
      cursor !== null,
      complete,
      complete ? null : { before, highId: backfill?.highId ?? latest },
    );
    if (!complete) {
      this.states[channel] = { ...this.states[channel], state: "degraded" };
      return;
    }
    this.states[channel] = {
      state: "live",
      transport: "public-web",
      lastSuccessAt: new Date().toISOString(),
      lastEventAt: page.at(-1)?.publishedAt,
    };
  }
  private async loop(channel: Channel, initialMs: number) {
    const signal = this.controller.signal;
    let failures = 0,
      waitMs = initialMs;
    while (!signal.aborted) {
      try {
        await delay(waitMs, undefined, { signal });
        await this.poll(channel);
        failures = 0;
        waitMs = this.config.OBRIY_BULLETIN_POLL_MS;
      } catch (error) {
        if (signal.aborted) break;
        failures++;
        this.states[channel] = { ...this.states[channel], state: "degraded" };
        waitMs =
          Math.max(
            Math.min(300000, 15000 * 2 ** Math.min(failures, 5)),
            error instanceof ChannelFetchError ? error.waitMs : 0,
          ) + Math.floor(Math.random() * 1000);
      }
    }
  }
  private async worker() {
    const signal = this.controller.signal;
    while (!signal.aborted) {
      try {
        for (let i = 0; i < 50 && !signal.aborted; i++)
          if (!(await this.store.processOne())) break;
        await this.store.store.setRuntime("bulletin-worker", {
          lastSuccessAt: new Date().toISOString(),
        });
      } catch {
        await this.store.store
          .setRuntime("bulletin-worker", { state: "degraded" })
          .catch(() => {});
      }
      try {
        await delay(1000, undefined, { signal });
      } catch {
        break;
      }
    }
  }
  async stop() {
    this.controller.abort();
    await Promise.all(this.tasks);
  }
}
