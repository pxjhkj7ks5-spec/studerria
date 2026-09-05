import { type Config } from "./config.js";
import { Store } from "./store.js";
import {
  normalizeTrack,
  normalizeOfficialAlerts,
  assess,
  transition,
  type Zone,
  type OfficialAlertEvent,
} from "./engine/index.js";
import {
  NeptunCollector,
  AlertsCollector,
  type SourceHealth,
} from "./ingestion/index.js";
import { TelegramBot, Dispatcher, riskText } from "./telegram.js";
import { hash, logEvent } from "./security.js";
const disabled = (): SourceHealth => ({ state: "disabled" });
export class Runtime {
  neptun?: NeptunCollector;
  alerts?: AlertsCollector;
  bot: TelegramBot;
  dispatcher: Dispatcher;
  leader = false;
  rejected = 0;
  private stopped = false;
  private agingTimer?: ReturnType<typeof setInterval>;
  private cleanupTimer?: ReturnType<typeof setInterval>;
  private work: Promise<void> = Promise.resolve();
  constructor(
    readonly config: Config,
    readonly store: Store,
    private readonly onFatal: () => void = () =>
      process.kill(process.pid, "SIGTERM"),
  ) {
    this.bot = new TelegramBot(store, config);
    this.dispatcher = new Dispatcher(store, this.bot.client, () =>
      this.sourceFresh(),
    );
  }
  health() {
    return {
      neptun: this.neptun?.health() ?? disabled(),
      alerts: this.alerts?.health() ?? disabled(),
    };
  }
  sourceFresh() {
    const h = this.neptun?.health();
    return Boolean(
      h?.state === "live" &&
      (h.transport === "websocket" ? h.lastEventAt : h.lastSuccessAt) &&
      Date.now() -
        Date.parse(
          (h.transport === "websocket" ? h.lastEventAt : h.lastSuccessAt)!,
        ) <
        this.config.OBRIY_HEARTBEAT_MS,
    );
  }
  private run(fn: () => Promise<void>) {
    const task = this.work.then(fn);
    this.work = task.catch(() => {
      logEvent("background_operation_failed");
    });
    return task;
  }
  async start() {
    this.leader = await this.store.acquireLeader(() => {
      this.leader = false;
      logEvent("leader_connection_lost");
      this.onFatal();
    });
    if (!this.leader)
      throw new Error("Another Obriy ingestion owner is active");
    if (this.config.OBRIY_COLLECTORS_ENABLED === "true") {
      this.neptun = new NeptunCollector({
        wsUrl: this.config.OBRIY_NEPTUN_WS_URL,
        restUrl: this.config.OBRIY_NEPTUN_REST_URL,
        pollMs: this.config.OBRIY_NEPTUN_POLL_MS,
        heartbeatMs: this.config.OBRIY_HEARTBEAT_MS,
        onSnapshot: (raw, at) =>
          this.run(async () => {
            const ids: string[] = [];
            let canReconcile = true,
              validCount = 0;
            for (const item of raw) {
              const id = (item as { id?: unknown })?.id;
              if (typeof id === "string") ids.push(id);
              else if (typeof id === "number" && Number.isSafeInteger(id))
                ids.push(String(id));
              else canReconcile = false;
              let track;
              try {
                track = normalizeTrack(item, at);
              } catch {
                this.rejected++;
                continue;
              }
              await this.store.putTrack(
                track,
                hash(
                  `neptun:${track.source.externalTrackId}:${track.updatedAt}`,
                ),
              );
              validCount++;
            }
            if (raw.length > 0 && validCount === 0)
              throw new Error("Snapshot has no valid records");
            if (canReconcile) await this.store.reconcile(ids, at);
            setImmediate(() => {
              if (!this.stopped) void this.reevaluate().catch(() => {});
            });
          }),
        onUpsert: (raw, at) =>
          this.run(async () => {
            let track;
            try {
              track = normalizeTrack(raw, at);
            } catch {
              this.rejected++;
              return;
            }
            if (
              await this.store.putTrack(
                track,
                hash(
                  `neptun:${track.source.externalTrackId}:${track.updatedAt}`,
                ),
              )
            )
              await this.evaluate(
                `upsert:${track.internalId}:${track.updatedAt}`,
                track.internalId,
              );
          }),
        onRemove: (id, at) =>
          this.run(async () => {
            const trackId = await this.store.resolveTrack(id, at);
            if (trackId)
              await this.evaluate(`remove:${id}:${at.toISOString()}`, trackId);
          }),
        onAlerts: (raw, at) =>
          this.run(async () => {
            await this.store.official(
              "neptun",
              normalizeOfficialAlerts(raw, "neptun", at),
            );
          }),
        onHeartbeat: () => this.run(() => this.store.refreshOfficial("neptun")),
        onError: () => {
          this.rejected++;
        },
      });
      this.neptun.start();
      if (this.config.OBRIY_ALERTS_TOKEN) {
        this.alerts = new AlertsCollector({
          url: this.config.OBRIY_ALERTS_URL,
          token: this.config.OBRIY_ALERTS_TOKEN,
          pollMs: this.config.OBRIY_ALERTS_POLL_MS,
          onAlerts: (raw, at) =>
            this.run(async () => {
              await this.store.official(
                "alerts.in.ua",
                normalizeOfficialAlerts(raw, "alerts.in.ua", at),
              );
            }),
          onError: () => {
            this.rejected++;
          },
        });
        this.alerts.start();
      }
    }
    if (
      this.config.configured &&
      this.config.OBRIY_TELEGRAM_BOT_TOKEN &&
      this.config.OBRIY_TELEGRAM_MODE !== "disabled"
    ) {
      this.bot.start();
      this.dispatcher.start();
    }
    this.agingTimer = setInterval(() => {
      void this.run(async () => {
        await this.store.setRuntime("source-health", this.health());
        await this.evaluate(`age:${Math.floor(Date.now() / 15000)}`);
      }).catch(() => {});
    }, 15000);
    this.cleanupTimer = setInterval(() => {
      void this.store.cleanup().catch(() => logEvent("retention_failed"));
    }, 3600000);
    await this.store.cleanup();
  }
  private officialFor(zone: Zone, events: OfficialAlertEvent[]): boolean {
    return events.some((e) => {
      if (!e.active || e.kind !== "air_raid") return false;
      if (
        zone.regionUid &&
        e.provider === "alerts.in.ua" &&
        e.regionUid === zone.regionUid
      )
        return true;
      if (e.raion || e.raionUid || e.locality) return false;
      return Boolean(
        zone.oblast &&
        e.oblast &&
        zone.oblast.toLocaleLowerCase("uk") ===
          e.oblast.toLocaleLowerCase("uk"),
      );
    });
  }
  async reevaluate() {
    return this.run(() => this.evaluate(`zones:${Date.now()}`));
  }
  private async evaluate(eventKey: string, onlyTrackId?: string) {
    if (!this.config.configured || this.stopped) return;
    const [tracks, zones, alerts] = await Promise.all([
      this.store.tracks(),
      this.store.zones(),
      this.store.activeAlerts(),
    ]);
    const now = new Date(),
      fresh = this.sourceFresh();
    let work = 0;
    for (const zone of zones.filter((z) => z.enabled))
      for (const original of tracks.filter(
        (t) => !onlyTrackId || t.internalId === onlyTrackId,
      )) {
        const track =
          !fresh && original.status === "active"
            ? { ...original, status: "stale" as const }
            : original;
        const assessment = assess(
          track,
          zone,
          now,
          this.officialFor(zone, alerts),
        );
        await this.store.recordAssessment(
          zone,
          track,
          assessment,
          (old) =>
            transition(old, assessment, {
              now,
              eventKey: `${eventKey}:${track.updatedAt}`,
            }),
          (level) => riskText(track, assessment, level),
          eventKey,
        );
        if (++work % 25 === 0)
          await new Promise<void>((resolve) => setImmediate(resolve));
      }
  }
  async stop() {
    if (this.stopped) return;
    this.stopped = true;
    if (this.agingTimer) clearInterval(this.agingTimer);
    if (this.cleanupTimer) clearInterval(this.cleanupTimer);
    await Promise.all([
      this.neptun?.stop(),
      this.alerts?.stop(),
      this.bot.stop(),
      this.dispatcher.stop(),
    ]);
    await this.work;
  }
}
