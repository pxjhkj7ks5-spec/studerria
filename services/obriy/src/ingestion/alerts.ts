import { z } from "zod";
import {
  fetchSourceJson,
  retryAfterMs,
  SourceRequestError,
  type SourceFetch,
} from "./http.js";
import type { SourceHealth } from "./types.js";

export interface AlertsCollectorOptions {
  url: string;
  token: string;
  pollMs: number;
  onAlerts: (raw: unknown, at: Date) => Promise<void>;
  onError?: (code: string) => void;
  fetch?: SourceFetch;
  now?: () => number;
}

const alertsSchema = z.object({ alerts: z.array(z.unknown()).max(10_000) });

export class AlertsCollector {
  private sourceHealth: SourceHealth = { state: "disabled" };
  private stopped = true;
  private controller = new AbortController();
  private timer?: ReturnType<typeof setTimeout>;
  private task?: Promise<void>;
  private lastModified?: string;
  private cached?: unknown;
  private failures = 0;
  private readonly now: () => number;
  private readonly fetcher: SourceFetch;
  private readonly pollMs: number;

  constructor(private readonly options: AlertsCollectorOptions) {
    this.now = options.now ?? Date.now;
    this.fetcher = options.fetch ?? fetch;
    this.pollMs = Math.max(12_000, options.pollMs);
  }

  health(): SourceHealth {
    return { ...this.sourceHealth };
  }

  start(): void {
    if (!this.stopped || !this.options.token.trim()) return;
    this.stopped = false;
    this.controller = new AbortController();
    this.sourceHealth.state = "connecting";
    this.schedule(0);
  }

  async stop(): Promise<void> {
    this.stopped = true;
    this.controller.abort();
    if (this.timer) clearTimeout(this.timer);
    this.timer = undefined;
    await this.task;
    this.sourceHealth.state = "disabled";
  }

  private error(code: string): void {
    try {
      this.options.onError?.(code);
    } catch {
      /* No raw provider errors or tokens reach telemetry. */
    }
  }

  private schedule(delay: number): void {
    if (this.stopped) return;
    this.timer = setTimeout(() => {
      this.timer = undefined;
      this.task = this.poll().finally(() => {
        this.task = undefined;
      });
    }, delay);
  }

  private async poll(): Promise<void> {
    let delay = this.pollMs;
    try {
      const headers: Record<string, string> = {
        Authorization: `Bearer ${this.options.token}`,
      };
      if (this.lastModified) headers["If-Modified-Since"] = this.lastModified;
      const response = await fetchSourceJson(
        this.fetcher,
        this.options.url,
        this.controller.signal,
        headers,
      );
      if (this.stopped) return;
      const now = new Date(this.now());
      if (response.status === 304) {
        if (this.cached === undefined) {
          this.lastModified = undefined;
          this.sourceHealth.state = "degraded";
          this.error("alerts_304_without_snapshot");
          return;
        }
        // Reapply with receive time so unchanged official alerts remain fresh context.
        await this.options.onAlerts(this.cached, now);
        this.failures = 0;
        this.sourceHealth = {
          ...this.sourceHealth,
          state: "live",
          transport: "https",
          lastSuccessAt: now.toISOString(),
          lastEventAt: now.toISOString(),
        };
        return;
      }
      if (response.status !== 200) {
        this.failures++;
        this.sourceHealth.state =
          response.status === 401 || response.status === 403
            ? "error"
            : "degraded";
        this.error(`alerts_http_${response.status}`);
        delay =
          response.status === 401 || response.status === 403
            ? 300_000
            : response.status === 429
              ? retryAfterMs(
                  response.retryAfter,
                  this.now(),
                  Math.max(60_000, this.pollMs),
                )
              : Math.min(
                  300_000,
                  this.pollMs * 2 ** Math.min(this.failures, 4),
                );
        return;
      }
      const data = alertsSchema.safeParse(response.data);
      if (!data.success) {
        this.sourceHealth.state = "error";
        this.error("alerts_invalid_snapshot");
        return;
      }
      await this.options.onAlerts(response.data, now);
      this.cached = response.data;
      this.lastModified = response.lastModified ?? undefined;
      this.failures = 0;
      this.sourceHealth = {
        state: "live",
        transport: "https",
        lastSuccessAt: now.toISOString(),
        lastEventAt: now.toISOString(),
        lastSnapshotAt: now.toISOString(),
      };
    } catch (error) {
      if (!this.stopped) {
        this.failures++;
        delay = Math.min(
          300_000,
          this.pollMs * 2 ** Math.min(this.failures, 4),
        );
        this.sourceHealth.state = "degraded";
        this.error(
          error instanceof SourceRequestError
            ? `alerts_${error.code}`
            : "alerts_fetch_failed",
        );
      }
    } finally {
      this.schedule(delay);
    }
  }
}
