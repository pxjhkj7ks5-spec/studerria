import WebSocket, { type ClientOptions, type RawData } from "ws";
import { createHash } from "node:crypto";
import { z } from "zod";
import {
  fetchSourceJson,
  retryAfterMs,
  sourceDate,
  SourceRequestError,
  type SourceFetch,
} from "./http.js";
import type { SourceHealth } from "./types.js";

export interface CollectorSocket {
  on(event: "open", listener: () => void): this;
  on(
    event: "message",
    listener: (data: RawData, isBinary: boolean) => void,
  ): this;
  on(event: "close", listener: () => void): this;
  on(event: "error", listener: (error: Error) => void): this;
  terminate(): void;
}

export interface NeptunCollectorOptions {
  wsUrl: string;
  restUrl: string;
  pollMs: number;
  heartbeatMs: number;
  onSnapshot: (raw: unknown[], at: Date) => Promise<void>;
  onUpsert: (raw: unknown, at: Date) => Promise<void>;
  onRemove: (id: string, at: Date) => Promise<void>;
  onAlerts: (raw: unknown, at: Date) => Promise<void>;
  onHeartbeat?: (at: Date) => Promise<void>;
  onError?: (code: string) => void;
  fetch?: SourceFetch;
  socketFactory?: (url: string, options: ClientOptions) => CollectorSocket;
  now?: () => number;
  random?: () => number;
  maxFrameBytes?: number;
  maxQueueEntries?: number;
}

const envelopeSchema = z.object({
  type: z.string().max(64),
  ts: z.string().max(64),
  data: z.unknown().optional(),
});
const snapshotSchema = z.object({ threats: z.array(z.unknown()).max(10_000) });
const idSchema = z.object({ id: z.string().min(1).max(256) });
const alertSchema = z.object({
  raions: z.array(z.unknown()).max(10_000),
  oblasts: z.array(z.unknown()).max(100),
});

interface Work {
  run: () => Promise<void>;
  generation?: number;
  finish: (success: boolean) => void;
}

export class NeptunCollector {
  private stopped = true;
  private sourceHealth: SourceHealth = { state: "disabled" };
  private controller = new AbortController();
  private socket?: CollectorSocket;
  private generation = 0;
  private openedAt = 0;
  private lastFrameAt = 0;
  private synchronized = false;
  private alertsSynchronized = false;
  private lastAlertsAt = 0;
  private retries = 0;
  private reconnectTimer?: ReturnType<typeof setTimeout>;
  private pollTimer?: ReturnType<typeof setTimeout>;
  private watchdogTimer?: ReturnType<typeof setInterval>;
  private pollTask?: Promise<void>;
  private drainTask?: Promise<void>;
  private queue: Work[] = [];
  private latestMutationAt = 0;
  private snapshotFloorAt = 0;
  private versions = new Map<
    string,
    { at: number; removed: boolean; fingerprint?: string }
  >();
  private readonly now: () => number;
  private readonly random: () => number;
  private readonly fetcher: SourceFetch;
  private readonly maxBytes: number;
  private readonly pollMs: number;
  private readonly queueLimit: number;

  constructor(private readonly options: NeptunCollectorOptions) {
    this.now = options.now ?? Date.now;
    this.random = options.random ?? Math.random;
    this.fetcher = options.fetch ?? fetch;
    this.pollMs = Math.max(5000, options.pollMs);
    this.maxBytes = Math.min(
      4_194_304,
      Math.max(1024, options.maxFrameBytes ?? 1_048_576),
    );
    this.queueLimit = Math.max(1, Math.min(256, options.maxQueueEntries ?? 64));
  }

  health(): SourceHealth {
    return { ...this.sourceHealth };
  }

  start(): void {
    if (!this.stopped) return;
    this.stopped = false;
    this.controller = new AbortController();
    this.sourceHealth = { ...this.sourceHealth, state: "connecting" };
    this.connect();
    this.schedulePoll(this.pollMs);
    this.watchdogTimer = setInterval(
      () => this.watchdog(),
      Math.max(25, Math.min(5000, this.options.heartbeatMs / 2)),
    );
  }

  async stop(): Promise<void> {
    this.stopped = true;
    this.controller.abort();
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    if (this.pollTimer) clearTimeout(this.pollTimer);
    if (this.watchdogTimer) clearInterval(this.watchdogTimer);
    this.reconnectTimer = undefined;
    this.pollTimer = undefined;
    this.generation++;
    const socket = this.socket;
    this.socket = undefined;
    socket?.terminate();
    for (const work of this.queue.splice(0)) work.finish(false);
    await Promise.allSettled(
      [this.pollTask, this.drainTask].filter((task): task is Promise<void> =>
        Boolean(task),
      ),
    );
    this.sourceHealth.state = "disabled";
  }

  private error(code: string): void {
    try {
      this.options.onError?.(code);
    } catch {
      /* Telemetry must not break ingestion. */
    }
  }

  private connect(): void {
    if (this.stopped || this.socket) return;
    const generation = ++this.generation;
    this.synchronized = false;
    this.alertsSynchronized = false;
    this.openedAt = this.now();
    this.lastFrameAt = this.openedAt;
    if (this.sourceHealth.state !== "live")
      this.sourceHealth.state = "connecting";
    let socket: CollectorSocket;
    try {
      socket = this.options.socketFactory
        ? this.options.socketFactory(this.options.wsUrl, {
            handshakeTimeout: 10_000,
            maxPayload: this.maxBytes,
            followRedirects: false,
          })
        : new WebSocket(this.options.wsUrl, {
            handshakeTimeout: 10_000,
            maxPayload: this.maxBytes,
            followRedirects: false,
          });
    } catch {
      this.error("neptun_connect_failed");
      this.sourceHealth.state = "degraded";
      this.scheduleReconnect();
      return;
    }
    this.socket = socket;
    socket.on("open", () => {
      if (this.stopped || generation !== this.generation) return;
      this.openedAt = this.now();
      this.lastFrameAt = this.openedAt;
    });
    socket.on("message", (data) => {
      if (!this.stopped && generation === this.generation)
        this.receive(data, generation);
    });
    socket.on("error", () => {
      if (this.stopped || generation !== this.generation) return;
      this.error("neptun_socket_error");
      socket.terminate();
    });
    socket.on("close", () => {
      if (this.stopped || generation !== this.generation) return;
      this.generation++;
      this.socket = undefined;
      this.synchronized = false;
      this.alertsSynchronized = false;
      this.sourceHealth.state = "degraded";
      this.error("neptun_disconnected");
      this.scheduleReconnect();
    });
  }

  private scheduleReconnect(): void {
    if (this.stopped || this.reconnectTimer) return;
    const base = Math.min(60_000, 1000 * 2 ** Math.min(this.retries++, 6));
    const delay = Math.min(
      60_000,
      base + Math.floor(this.random() * Math.min(1000, base / 4)),
    );
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = undefined;
      this.connect();
    }, delay);
  }

  private watchdog(): void {
    if (this.stopped || !this.socket) return;
    if (
      this.now() - this.lastFrameAt > this.options.heartbeatMs ||
      (!this.synchronized &&
        this.now() - this.openedAt > this.options.heartbeatMs)
    ) {
      this.sourceHealth.state = "degraded";
      this.error("neptun_heartbeat_timeout");
      this.socket.terminate();
    }
  }

  private receive(data: RawData, generation: number): void {
    const size = Array.isArray(data)
      ? data.reduce((total, item) => total + item.byteLength, 0)
      : data.byteLength;
    if (size > this.maxBytes) {
      this.error("neptun_frame_too_large");
      this.socket?.terminate();
      return;
    }
    let raw: unknown;
    try {
      const buffer = Array.isArray(data)
        ? Buffer.concat(data)
        : Buffer.from(data as ArrayBuffer);
      raw = JSON.parse(buffer.toString("utf8")) as unknown;
    } catch {
      this.error("neptun_invalid_json");
      return;
    }
    const parsed = envelopeSchema.safeParse(raw);
    if (!parsed.success) {
      this.error("neptun_invalid_envelope");
      return;
    }
    const envelope = parsed.data;
    const at = sourceDate(envelope.ts, this.now());
    if (!at) {
      this.error("neptun_invalid_timestamp");
      return;
    }
    if (
      !["snapshot", "upsert", "remove", "heartbeat", "alerts"].includes(
        envelope.type,
      )
    ) {
      this.error("neptun_unknown_event");
      return;
    }
    // Heartbeats are documented keep-alives and observed live without a data property.
    if (envelope.type === "heartbeat") {
      this.lastFrameAt = this.now();
      const receivedAt = new Date(this.now());
      this.sourceHealth.lastEventAt = receivedAt.toISOString();
      // A stream with a persisted snapshot remains current even when no targets change.
      // This refreshes transport freshness, never a track's observation timestamp.
      if (this.synchronized)
        this.sourceHealth.lastSuccessAt = receivedAt.toISOString();
      if (this.options.onHeartbeat)
        void this.enqueue(async () => {
          // Do not revive old official-alert rows before this connection provided its state.
          if (this.synchronized && this.alertsSynchronized)
            await this.options.onHeartbeat!(receivedAt);
        }, generation);
      return;
    }
    const valid =
      envelope.type === "snapshot"
        ? snapshotSchema.safeParse(envelope.data).success
        : envelope.type === "alerts"
          ? alertSchema.safeParse(envelope.data).success
          : idSchema.safeParse(envelope.data).success;
    if (!valid) {
      this.error("neptun_invalid_data");
      return;
    }
    this.lastFrameAt = this.now();
    void this.enqueue(async () => {
      const receivedAt = new Date(this.now()).toISOString();
      if (envelope.type === "snapshot") {
        const { threats } = snapshotSchema.parse(envelope.data);
        if (await this.applySnapshot(threats, at)) {
          if (this.stopped || generation !== this.generation) return;
          this.synchronized = true;
          this.retries = 0;
          this.sourceHealth = {
            ...this.sourceHealth,
            state: "live",
            transport: "websocket",
            lastEventAt: receivedAt,
            lastSuccessAt: receivedAt,
          };
        }
      } else if (envelope.type === "alerts") {
        if (at.getTime() < this.lastAlertsAt) {
          this.error("neptun_old_alerts");
          return;
        }
        await this.options.onAlerts(envelope.data, at);
        this.lastAlertsAt = at.getTime();
        if (this.stopped || generation !== this.generation) return;
        this.alertsSynchronized = true;
        this.sourceHealth.lastEventAt = receivedAt;
      } else if (this.synchronized) {
        const { id } = idSchema.parse(envelope.data);
        const prior = this.versions.get(id);
        const fingerprint =
          envelope.type === "upsert"
            ? createHash("sha256")
                .update(JSON.stringify(envelope.data))
                .digest("hex")
            : undefined;
        if (
          at.getTime() < this.snapshotFloorAt ||
          (prior &&
            (at.getTime() < prior.at ||
              (at.getTime() === prior.at &&
                (prior.removed || prior.fingerprint === fingerprint))))
        )
          return;
        if (envelope.type === "upsert")
          await this.options.onUpsert(envelope.data, at);
        else await this.options.onRemove(id, at);
        this.versions.set(id, {
          at: at.getTime(),
          removed: envelope.type === "remove",
          fingerprint,
        });
        this.latestMutationAt = Math.max(this.latestMutationAt, at.getTime());
        if (this.stopped || generation !== this.generation) return;
        this.sourceHealth = {
          ...this.sourceHealth,
          state: "live",
          transport: "websocket",
          lastEventAt: receivedAt,
          lastSuccessAt: receivedAt,
        };
        this.pruneVersions();
      }
    }, generation);
  }

  private async applySnapshot(threats: unknown[], at: Date): Promise<boolean> {
    // A delayed REST response/reconnect snapshot must not remove state received afterward.
    if (
      at.getTime() < this.latestMutationAt ||
      at.getTime() < this.snapshotFloorAt
    ) {
      this.error("neptun_old_snapshot");
      return false;
    }
    await this.options.onSnapshot(threats, at);
    this.latestMutationAt = at.getTime();
    this.snapshotFloorAt = at.getTime();
    this.versions.clear();
    this.sourceHealth.lastSnapshotAt = at.toISOString();
    return true;
  }

  private pruneVersions(): void {
    if (this.versions.size <= 20_000) return;
    // A snapshot floor already rejects older events; entries below it can be discarded.
    for (const [id, version] of this.versions)
      if (version.at <= this.snapshotFloorAt) this.versions.delete(id);
    if (this.versions.size > 20_000) {
      this.error("neptun_state_limit");
      this.socket?.terminate();
    }
  }

  private enqueue(
    run: () => Promise<void>,
    generation?: number,
  ): Promise<boolean> {
    if (this.stopped) return Promise.resolve(false);
    if (this.queue.length >= this.queueLimit) {
      this.sourceHealth.state = "error";
      this.error("neptun_queue_overflow");
      this.socket?.terminate();
      return Promise.resolve(false);
    }
    const result = new Promise<boolean>((finish) =>
      this.queue.push({ run, generation, finish }),
    );
    this.startDrain();
    return result;
  }

  private startDrain(): void {
    if (this.drainTask || !this.queue.length) return;
    this.drainTask = this.drain().finally(() => {
      this.drainTask = undefined;
      this.startDrain();
    });
  }

  private async drain(): Promise<void> {
    while (this.queue.length) {
      const work = this.queue.shift()!;
      if (
        this.stopped ||
        (work.generation !== undefined && work.generation !== this.generation)
      ) {
        work.finish(false);
        continue;
      }
      try {
        await work.run();
        work.finish(true);
      } catch {
        this.sourceHealth.state = "error";
        this.error("neptun_callback_failed");
        work.finish(false);
        // Partial persistence must converge from a new full snapshot before more deltas.
        this.synchronized = false;
        this.socket?.terminate();
      }
    }
  }

  private schedulePoll(delay: number): void {
    if (this.stopped) return;
    this.pollTimer = setTimeout(() => {
      this.pollTimer = undefined;
      this.pollTask = this.poll().finally(() => {
        this.pollTask = undefined;
      });
    }, delay);
  }

  private async poll(): Promise<void> {
    let delay = this.pollMs;
    try {
      if (
        this.stopped ||
        (this.socket &&
          this.synchronized &&
          this.now() - this.lastFrameAt <= this.options.heartbeatMs)
      )
        return;
      const response = await fetchSourceJson(
        this.fetcher,
        this.options.restUrl,
        this.controller.signal,
        {},
        this.maxBytes,
      );
      if (this.stopped) return;
      if (response.status !== 200) {
        this.sourceHealth.state = "degraded";
        this.error(`neptun_http_${response.status}`);
        if (response.status === 429)
          delay = retryAfterMs(
            response.retryAfter,
            this.now(),
            Math.max(60_000, this.pollMs),
          );
        return;
      }
      const data = z
        .object({
          serverTime: z.string(),
          threats: z.array(z.unknown()).max(10_000),
        })
        .safeParse(response.data);
      const at = data.success
        ? sourceDate(data.data.serverTime, this.now())
        : null;
      if (!data.success || !at) {
        this.error("neptun_invalid_snapshot");
        this.sourceHealth.state = "error";
        return;
      }
      await this.enqueue(async () => {
        if (await this.applySnapshot(data.data.threats, at)) {
          this.sourceHealth = {
            ...this.sourceHealth,
            state: "live",
            transport: "rest",
            lastSuccessAt: new Date(this.now()).toISOString(),
          };
        }
      });
    } catch (error) {
      if (!this.stopped) {
        this.sourceHealth.state = "degraded";
        this.error(
          error instanceof SourceRequestError
            ? `neptun_${error.code}`
            : "neptun_fetch_failed",
        );
      }
    } finally {
      // One request at a time, with at least five seconds after completion across retries.
      this.schedulePoll(delay);
    }
  }
}
