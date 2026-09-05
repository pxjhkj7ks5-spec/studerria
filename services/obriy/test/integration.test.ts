import { beforeAll, afterAll, beforeEach, describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import { loadConfig } from "../src/config.js";
import { Store } from "../src/store.js";
import { Runtime } from "../src/runtime.js";
import { buildServer } from "../src/server.js";
import { Vault, hash } from "../src/security.js";
import {
  normalizeTrack,
  assess,
  transition,
  type Zone,
  type NormalizedTrack,
  type AlertState,
} from "../src/engine/index.js";
import {
  Dispatcher,
  TelegramClient,
  TelegramError,
  riskText,
  TelegramBot,
} from "../src/telegram.js";
const url = process.env.OBRIY_TEST_DATABASE_URL;
const integration = describe.skipIf(!url);
integration("real PostgreSQL privacy, ownership and delivery", () => {
  const config = loadConfig({
    NODE_ENV: "test",
    OBRIY_DATABASE_URL: url,
    OBRIY_ENCRYPTION_KEY: "a".repeat(64),
    OBRIY_ADMIN_TOKEN: "test-only-admin-token-".repeat(3),
    OBRIY_COLLECTORS_ENABLED: "false",
    OBRIY_TELEGRAM_BOT_TOKEN: "123456:" + "a".repeat(32),
    OBRIY_TELEGRAM_MODE: "disabled",
  });
  const store = new Store(config),
    runtime = new Runtime(config, store);
  let app: Awaited<ReturnType<typeof buildServer>>;
  const zoneInput = {
    label: "zone-a",
    lat: 0,
    lon: 0,
    radiusKm: 10,
    enabled: true,
  };
  beforeAll(async () => {
    await store.migrate();
    app = await buildServer(config, store, runtime);
  });
  beforeEach(async () => {
    await store.pool.query(
      "TRUNCATE obriy.users,obriy.tracks,obriy.source_events,obriy.runtime_state,obriy.telegram_updates CASCADE",
    );
  });
  afterAll(async () => {
    await app.close();
    await runtime.stop();
    await store.close();
  });
  async function login() {
    const res = await app.inject({
      method: "POST",
      url: "/obriy/api/v1/session",
      payload: { token: config.OBRIY_ADMIN_TOKEN },
    });
    expect(res.statusCode).toBe(200);
    const signup = await app.inject({
      method: "POST",
      url: "/obriy/api/v1/auth/register",
      cookies: { obriy_gate: res.cookies[0].value },
      payload: {
        username: "fixture_user",
        password: "тихий вітер над осіннім озером",
      },
    });
    expect(signup.statusCode, signup.body).toBe(200);
    return signup.cookies[0].value;
  }
  async function linkedUser() {
    const uid = await store.owner(),
      { code } = await store.pairingCode(uid);
    await store.transaction((c) => store.linkChat(c, code, "987654321"));
    return uid;
  }
  function riskTrack(
    id: string,
    at: Date,
    patch: Record<string, unknown> = {},
  ) {
    return normalizeTrack(
      {
        id,
        type: "uav",
        lat: 0,
        lon: 0.2,
        positionQuality: "confirmed",
        confidenceLevel: "high",
        sourceCount: 4,
        uncertaintyKm: 2,
        velocity: { speedKmh: 200, bearingDeg: 270 },
        updatedAt: at.toISOString(),
        confirmedAt: at.toISOString(),
        status: "active",
        ...patch,
      },
      at,
    );
  }
  async function recordRisk(
    zone: Zone,
    track: NormalizedTrack,
    eventKey: string,
  ) {
    await store.putTrack(track, `source:${eventKey}`);
    const assessment = assess(track, zone, new Date(track.updatedAt), true);
    await store.recordAssessment(
      zone,
      track,
      assessment,
      (previous) => transition(previous, assessment, { eventKey }),
      (level) => riskText(track, assessment, level),
      eventKey,
    );
  }
  async function queuedHigh(zone: Zone, id: string) {
    const now = new Date();
    await recordRisk(
      zone,
      riskTrack(id, new Date(now.getTime() - 1000)),
      `${id}:first`,
    );
    const track = riskTrack(id, now);
    await recordRisk(zone, track, `${id}:second`);
    return track;
  }
  it("runs migration twice and serves usable UI without external assets", async () => {
    await store.migrate();
    const res = await app.inject("/obriy");
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain("Обрій");
    expect(res.body).not.toContain("__APP_BASE__");
    expect(res.headers["content-security-policy"]).toContain(
      "connect-src 'self'",
    );
  });
  it("locks private APIs, metrics and invalid webhook before parsing", async () => {
    expect((await app.inject("/obriy/api/v1/me")).statusCode).toBe(401);
    expect((await app.inject("/obriy/metrics")).statusCode).toBe(404);
    const response = await app.inject({
      method: "POST",
      url: "/obriy/telegram/webhook",
      headers: { "content-type": "application/json" },
      payload: "not json",
    });
    expect(response.statusCode).toBe(403);
  });
  it("uses HttpOnly session, validates zones, rejects cross-site requests", async () => {
    const token = await login(),
      cookies = { obriy_session: token };
    expect(
      (
        await app.inject({
          method: "POST",
          url: "/obriy/api/v1/zones",
          cookies,
          payload: { ...zoneInput, lat: 91 },
        })
      ).statusCode,
    ).toBe(400);
    expect(
      (
        await app.inject({
          method: "POST",
          url: "/obriy/api/v1/zones",
          cookies,
          headers: { origin: "https://evil.example" },
          payload: zoneInput,
        })
      ).statusCode,
    ).toBe(403);
    const res = await app.inject({
      method: "POST",
      url: "/obriy/api/v1/zones",
      cookies,
      payload: zoneInput,
    });
    expect(res.statusCode).toBe(201);
    const id = res.json().zone.id,
      rows = await store.pool.query("SELECT data_enc FROM obriy.zones");
    expect(rows.rows[0].data_enc).not.toContain('"lat"');
    expect(
      (
        await app.inject({
          method: "PATCH",
          url: `/obriy/api/v1/zones/${id}`,
          cookies,
          payload: { regionUid: null, oblast: null },
        })
      ).statusCode,
    ).toBe(200);
    const foreign = randomUUID();
    await store.pool.query("INSERT INTO obriy.users(id) VALUES($1)", [foreign]);
    const foreignZone = await store.saveZone(foreign, zoneInput);
    expect(
      (
        await app.inject({
          method: "DELETE",
          url: `/obriy/api/v1/zones/${foreignZone!.id}`,
          cookies,
        })
      ).statusCode,
    ).toBe(404);
    expect(
      (
        await app.inject({ method: "GET", url: "/obriy/api/v1/me", cookies })
      ).json().zones,
    ).toHaveLength(1);
  });
  it("binds ciphertext to owner/field and detects tampering", () => {
    const vault = new Vault("b".repeat(64)),
      enc = vault.encrypt(zoneInput, "zone:one");
    expect(vault.decrypt(enc, "zone:one")).toEqual(zoneInput);
    expect(() => vault.decrypt(enc, "zone:two")).toThrow();
    expect(() => new Vault("c".repeat(64)).decrypt(enc, "zone:one")).toThrow();
  });
  it("pairing is one-use; no raw chat identifier at rest", async () => {
    const uid = await linkedUser();
    expect(await store.chatUser("987654321")).toBe(uid);
    const { rows } = await store.pool.query(
      "SELECT chat_enc,chat_hash FROM obriy.users",
    );
    expect(JSON.stringify(rows)).not.toContain("987654321");
    const { code } = await store.pairingCode(uid);
    expect(
      await store.transaction((c) => store.linkChat(c, code, "987654321")),
    ).toBe(uid);
    expect(
      await store.transaction((c) => store.linkChat(c, code, "987654321")),
    ).toBeNull();
  });
  it("deduplicates/rejects old tracks and survives restart with resolution tombstone", async () => {
    const now = new Date(),
      raw = {
        id: "synthetic-1",
        type: "uav",
        lat: 0,
        lon: 1,
        positionQuality: "confirmed",
        updatedAt: now.toISOString(),
        status: "active",
      };
    const t = normalizeTrack(raw, now);
    expect(await store.putTrack(t, "event-one")).toBe(true);
    expect(await store.putTrack(t, "event-one")).toBe(false);
    expect(
      await store.putTrack(
        normalizeTrack(
          { ...raw, updatedAt: new Date(now.getTime() - 1000).toISOString() },
          now,
        ),
        "old",
      ),
    ).toBe(false);
    await store.resolveTrack(raw.id, new Date(now.getTime() + 1000));
    expect(await store.putTrack(t, "late-after-remove")).toBe(false);
    const another = new Store(config);
    expect((await another.tracks())[0].status).toBe("resolved");
    await another.close();
  });
  it("risk state and outbox commit atomically and replay creates one item", async () => {
    const uid = await linkedUser(),
      zone = (await store.saveZone(uid, zoneInput))!,
      now = new Date();
    const make = (dt: number) =>
      normalizeTrack(
        {
          id: "synthetic-risk",
          type: "uav",
          lat: 0,
          lon: 0.2,
          positionQuality: "confirmed",
          uncertaintyKm: 2,
          confidenceLevel: "high",
          sourceCount: 4,
          updatedAt: new Date(now.getTime() + dt).toISOString(),
          confirmedAt: new Date(now.getTime() + dt).toISOString(),
          velocity: { speedKmh: 200, bearingDeg: 270 },
          status: "active",
        },
        new Date(now.getTime() + dt),
      );
    for (const dt of [0, 1000, 1000]) {
      const t = make(dt);
      await store.putTrack(t, `raw:${dt}`);
      const a = assess(t, zone, new Date(now.getTime() + dt), true);
      await store.recordAssessment(
        zone,
        t,
        a,
        (old) => transition(old, a, { eventKey: `risk:${dt}` }),
        (level) => riskText(t, a, level),
        `risk:${dt}`,
      );
    }
    const result = await store.pool.query(
      "SELECT * FROM obriy.notification_outbox",
    );
    expect(result.rows).toHaveLength(1);
    expect(result.rows[0].payload_enc).not.toContain("Потенційна");
    const d = await store.claim();
    expect(d).not.toBeNull();
    expect(d!.text).not.toContain("zone-a");
    expect(d!.text).not.toContain("0.2");
    expect(d!.text).toContain("не замінюють");
  });
  it("rolls back state when outbox insertion fails", async () => {
    const uid = await linkedUser();
    await expect(
      store.transaction(async (c) => {
        await c.query(
          "UPDATE obriy.users SET paused_until=now()+interval '1 hour' WHERE id=$1",
          [uid],
        );
        await c.query("INSERT INTO obriy.notification_outbox(id) VALUES($1)", [
          randomUUID(),
        ]);
      }),
    ).rejects.toThrow();
    expect((await store.user(uid))!.pausedUntil).toBeNull();
  });
  it("retries 429 durably and reclaims an expired worker lease", async () => {
    const uid = await linkedUser();
    await store.transaction((c) =>
      store.enqueue(c, uid, "safe test", "retry-one"),
    );
    const fake = {
      send: async () => {
        throw new TelegramError("http_429", 17);
      },
    } as unknown as TelegramClient;
    await new Dispatcher(store, fake, () => true).tick();
    const pending = await store.pool.query(
      "SELECT status,retry_at,attempts FROM obriy.notification_outbox",
    );
    expect(pending.rows[0].status).toBe("pending");
    expect(pending.rows[0].retry_at.getTime()).toBeGreaterThan(
      Date.now() + 15000,
    );
    await store.pool.query(
      "UPDATE obriy.notification_outbox SET status='sending',lease_until=now()-interval '1 minute',retry_at=now()-interval '1 minute'",
    );
    await store.pool.query("UPDATE obriy.users SET last_delivery_at=NULL");
    expect(await store.claim()).not.toBeNull();
  });
  it("pause and zone changes cancel pending risk delivery; profile delete cascades", async () => {
    const uid = await linkedUser(),
      zone = (await store.saveZone(uid, zoneInput))!,
      t = normalizeTrack(
        {
          id: "delete-track",
          type: "uav",
          updatedAt: new Date().toISOString(),
        },
        new Date(),
      );
    await store.putTrack(t, "delete-track");
    await store.transaction((c) =>
      store.enqueue(c, uid, "safe", "pending-risk", {
        zoneId: zone.id,
        trackId: t.internalId,
      }),
    );
    await store.pause(uid, 60);
    expect(
      (await store.pool.query("SELECT status FROM obriy.notification_outbox"))
        .rows[0].status,
    ).toBe("cancelled");
    await store.session(uid);
    await store.deleteUser(uid);
    for (const table of [
      "users",
      "zones",
      "sessions",
      "pairing_codes",
      "alert_state",
      "risk_assessments",
      "notification_outbox",
      "notifications",
    ])
      expect(
        Number(
          (await store.pool.query(`SELECT count(*) FROM obriy.${table}`))
            .rows[0].count,
        ),
      ).toBe(0);
  });
  it("private Telegram commands are idempotent, and delete removes the linked identity", async () => {
    const uid = await linkedUser(),
      bot = new TelegramBot(store, config, {
        send: async () => {},
      } as unknown as TelegramClient);
    const update = {
      update_id: 900,
      message: {
        chat: { id: 987654321, type: "private" },
        from: { id: 987654321 },
        text: "/pause",
      },
    };
    await bot.handle(update);
    await bot.handle(update);
    expect((await store.user(uid))!.pausedUntil).not.toBeNull();
    expect(
      (await store.pool.query("SELECT * FROM obriy.notification_outbox")).rows,
    ).toHaveLength(1);
    await bot.handle({
      ...update,
      update_id: 901,
      message: { ...update.message, text: "/delete_me" },
    });
    expect(await store.user(uid)).toBeNull();
  });
  it("rejects second ingestion owner without starting duplicate streams", async () => {
    const first = new Store(config),
      second = new Store(config);
    expect(await first.acquireLeader(() => {})).toBe(true);
    expect(await second.acquireLeader(() => {})).toBe(false);
    await first.close();
    await second.close();
  });
  it("keeps resolved upserts available for resolution grace and summaries", async () => {
    const now = new Date(),
      track = riskTrack("resolved-upsert", now);
    await store.putTrack(track, "resolved-upsert:active");
    const later = new Date(now.getTime() + 1);
    const resolved = riskTrack("resolved-upsert", later, {
      status: "resolved",
    });
    expect(await store.putTrack(resolved, "resolved-upsert:resolved")).toBe(
      true,
    );
    expect(
      (await store.tracks()).find((t) => t.internalId === track.internalId)
        ?.status,
    ).toBe("resolved");
    const row = await store.pool.query(
      "SELECT resolved_at FROM obriy.tracks WHERE id=$1",
      [track.internalId],
    );
    expect(row.rows[0].resolved_at).toBeInstanceOf(Date);
  });
  it.each([
    ["stale", { status: "stale" }],
    ["advisory", { advisory: true }],
    ["area-only", { areaOnly: true }],
    ["resolved", { status: "resolved" }],
    [
      "old observation",
      { confirmedAt: new Date(Date.now() - 660000).toISOString() },
    ],
  ])(
    "rejects queued HIGH immediately when the latest source track becomes %s",
    async (_name, patch) => {
      const uid = await linkedUser(),
        zone = (await store.saveZone(uid, zoneInput))!;
      const track = await queuedHigh(zone, "changed-before-delivery");
      const delivery = await store.claim();
      expect(delivery).not.toBeNull();
      expect(await store.deliverable(delivery!)).toBe(true);
      const at = new Date(
        Math.max(Date.now(), Date.parse(track.updatedAt) + 1),
      );
      await store.putTrack(
        riskTrack(
          "changed-before-delivery",
          at,
          patch as Record<string, unknown>,
        ),
        "changed-before-delivery:guard",
      );
      // No risk assessment has run yet: the delivery guard must use the latest persisted source state.
      expect(await store.deliverable(delivery!)).toBe(false);
    },
  );
  it("allows a safe resolution summary while denying a pending trajectory warning", async () => {
    const uid = await linkedUser(),
      zone = (await store.saveZone(uid, zoneInput))!;
    const track = await queuedHigh(zone, "safe-resolution");
    const warning = await store.claim();
    expect(warning).not.toBeNull();
    await store.finish(warning!, "sent");
    await store.resolveTrack(
      track.source.externalTrackId,
      new Date(Math.max(Date.now(), Date.parse(track.updatedAt) + 1)),
    );
    await store.transaction((c) =>
      store.enqueue(
        c,
        uid,
        "Джерело більше не показує попереднє спостереження. Це не означає відбій тривоги.",
        "safe-resolution:summary",
        { zoneId: zone.id, trackId: track.internalId, level: "RESOLVED" },
      ),
    );
    await store.pool.query(
      "UPDATE obriy.users SET last_delivery_at=NULL WHERE id=$1",
      [uid],
    );
    const summary = await store.claim();
    expect(summary?.level).toBe("RESOLVED");
    expect(await store.deliverable(summary!)).toBe(true);
  });
  it("pause clears queued-notification cooldown while retaining the actual delivered-warning fact", async () => {
    const uid = await linkedUser(),
      zone = (await store.saveZone(uid, zoneInput))!;
    const track = await queuedHigh(zone, "pause-notification-flags");
    const delivered = await store.claim();
    expect(delivered).not.toBeNull();
    await store.finish(delivered!, "sent");
    await store.transaction((c) =>
      store.enqueue(
        c,
        uid,
        "Потенційна загроза",
        "pause-notification-flags:pending",
        { zoneId: zone.id, trackId: track.internalId, level: "HIGH" },
      ),
    );
    await store.pause(uid, 60);
    const { rows } = await store.pool.query(
      "SELECT data FROM obriy.alert_state WHERE zone_id=$1 AND track_id=$2",
      [zone.id, track.internalId],
    );
    const state = rows[0].data as AlertState;
    expect(state.lastNotificationAt).toBeUndefined();
    expect(state.lastNotifiedLevel).toBeUndefined();
    expect(state.lastNotifiedDistanceBandRank).toBeUndefined();
    expect(state.hadHighLevelNotification).toBe(true);
    await store.pause(uid, 0);
    const fresh = riskTrack(
      "pause-notification-flags",
      new Date(Math.max(Date.now(), Date.parse(track.updatedAt) + 1)),
    );
    await recordRisk(zone, fresh, "pause-notification-flags:after-resume");
    const pending = await store.pool.query(
      "SELECT id FROM obriy.notification_outbox WHERE user_id=$1 AND status='pending' AND category='risk'",
      [uid],
    );
    expect(pending.rows).toHaveLength(1);
  });
  it("concurrent zone edits, assessment, delivery completion and pause finish without deadlock", async () => {
    const uid = await linkedUser(),
      zone = (await store.saveZone(uid, zoneInput))!;
    // Several independent episodes repeatedly overlap the real row-locking paths.
    for (let iteration = 0; iteration < 8; iteration++) {
      await store.pause(uid, 0);
      const track = await queuedHigh(zone, `concurrent-${iteration}`);
      await store.pool.query(
        "UPDATE obriy.users SET last_delivery_at=NULL WHERE id=$1",
        [uid],
      );
      const delivery = await store.claim();
      expect(delivery).not.toBeNull();
      const fresh = riskTrack(
        `concurrent-${iteration}`,
        new Date(Math.max(Date.now(), Date.parse(track.updatedAt) + 1)),
      );
      const outcomes = await Promise.allSettled([
        store.saveZone(
          uid,
          { ...zoneInput, label: `zone-edit-${iteration}` },
          zone.id,
        ),
        recordRisk(zone, fresh, `concurrent-${iteration}:update`),
        store.finish(delivery!, "sent"),
        store.pause(uid, 60),
      ]);
      for (const outcome of outcomes)
        expect(
          outcome.status,
          outcome.status === "rejected" ? String(outcome.reason) : "",
        ).toBe("fulfilled");
      expect((await store.zones(uid))[0]?.id).toBe(zone.id);
    }
  }, 20000);
});
