import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import { randomUUID } from "node:crypto";
import pg from "pg";
import { loadConfig } from "../src/config.js";
import { Store } from "../src/store.js";
import { BulletinStore } from "../src/bulletins/store.js";
import { parseChannelHtml } from "../src/bulletins/html.js";
import { CHANNELS } from "../src/bulletins/types.js";
import { Dispatcher, type TelegramClient } from "../src/telegram.js";
import { Runtime } from "../src/runtime.js";
import { buildServer } from "../src/server.js";
import { Accounts } from "../src/accounts.js";

const url = process.env.OBRIY_TEST_DATABASE_URL;
describe.skipIf(!url)("civil bulletins with isolated PostgreSQL", () => {
  const name = `obriy_bulletins_${process.pid}_${randomUUID().slice(0, 8)}`;
  let admin: pg.Client,
    store: Store,
    bulletins: BulletinStore,
    runtime: Runtime,
    app: Awaited<ReturnType<typeof buildServer>>;
  let uid: string, zoneId: string, token: string;
  const zoneInput = {
    label: "Місце A",
    lat: 0,
    lon: 0,
    radiusKm: 10,
    enabled: true,
    bulletinAreas: ["kyiv"],
  };
  beforeAll(async () => {
    const connection = new URL(url!);
    connection.pathname = "/postgres";
    admin = new pg.Client({ connectionString: connection.toString() });
    await admin.connect();
    await admin.query(`CREATE DATABASE "${name}"`);
    connection.pathname = `/${name}`;
    store = new Store(
      loadConfig({
        NODE_ENV: "test",
        OBRIY_DATABASE_URL: connection.toString(),
        OBRIY_ENCRYPTION_KEY: "f".repeat(64),
        OBRIY_ADMIN_TOKEN: "test-".repeat(9),
        OBRIY_COLLECTORS_ENABLED: "false",
        OBRIY_TELEGRAM_MODE: "polling",
        OBRIY_BULLETIN_MODE: "live",
        OBRIY_BULLETIN_APPROVED: "true",
      }),
    );
    await store.migrate();
    await store.migrate();
    bulletins = new BulletinStore(store);
    runtime = new Runtime(store.config, store);
    app = await buildServer(store.config, store, runtime);
  }, 30000);
  beforeEach(async () => {
    store.config.OBRIY_BULLETIN_MODE = "live";
    store.config.OBRIY_BULLETIN_APPROVED = "true";
    await store.pool.query(
      "TRUNCATE obriy.users,obriy.channel_messages,obriy.channel_cursors,obriy.runtime_state CASCADE",
    );
    token = await new Accounts(store.config, store).register(
      "bulletin_fixture",
      "a very long test-only password",
    );
    uid = (await store.sessionUser(token))!;
    const code = await store.pairingCode(uid);
    await store.transaction((c) => store.linkChat(c, code.code, "987654321"));
    zoneId = (await store.saveZone(uid, zoneInput))!.id;
    for (const channel of CHANNELS)
      await store.pool.query(
        "INSERT INTO obriy.channel_cursors(channel,high_id,last_success_at,initialized_at) VALUES($1,1,now(),now()-interval '25 hours')",
        [channel],
      );
  });
  afterAll(async () => {
    await app?.close();
    await runtime?.stop();
    await store?.close();
    if (admin) {
      await admin.query(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);
      await admin.end();
    }
  });
  function message(
    text = "Київ — повітряна тривога",
    id = 2,
    age = 0,
    channel: (typeof CHANNELS)[number] = "AerisRimor",
  ) {
    const at = new Date();
    return parseChannelHtml(
      `<div class="tgme_channel_info"></div><div class="tgme_widget_message" data-post="${channel}/${id}"><div class="tgme_widget_message_text">${text}</div><a class="tgme_widget_message_date"><time datetime="${new Date(at.getTime() - age).toISOString()}"></time></a></div>`,
      channel,
      at,
    )[0];
  }
  async function ingest(
    text = "Київ — повітряна тривога",
    id = 2,
    age = 0,
    channel: (typeof CHANNELS)[number] = "AerisRimor",
  ) {
    const m = message(text, id, age, channel);
    await bulletins.ingest(channel, [m], id, true, true);
    await bulletins.processOne();
    return m;
  }
  async function pending() {
    return (
      await store.pool.query(
        "SELECT * FROM obriy.notification_outbox WHERE category='telegram_observation' AND status='pending'",
      )
    ).rows;
  }
  it("persists encrypted originals and processes each revision once", async () => {
    const m = message();
    await bulletins.ingest(m.channel, [m], 2, true, true);
    expect(
      (
        await store.pool.query(
          "SELECT processed_revision,revision,data_enc FROM obriy.channel_messages",
        )
      ).rows[0],
    ).toMatchObject({
      revision: 1,
      processed_revision: 0,
      data_enc: expect.not.stringContaining("Київ"),
    });
    const restarted = new BulletinStore(store);
    expect(await restarted.processOne()).toBe(true);
    expect(await restarted.processOne()).toBe(false);
    await restarted.ingest(m.channel, [m], 2, true, true);
    expect(await restarted.processOne()).toBe(false);
    expect(await pending()).toHaveLength(1);
    expect(
      (await store.pool.query("SELECT * FROM obriy.channel_message_revisions"))
        .rows,
    ).toHaveLength(1);
    expect(
      (await store.pool.query("SELECT * FROM obriy.tracks")).rows,
    ).toHaveLength(0);
  });
  it("dispatches a civil bulletin with NEPTUN unavailable", async () => {
    await ingest();
    const send = vi.fn(async () => {});
    const dispatcher = new Dispatcher(
      store,
      { send } as unknown as TelegramClient,
      () => false,
    );
    await dispatcher.tick();
    expect(send).toHaveBeenCalledOnce();
    expect(send.mock.calls[0]).toEqual([
      "987654321",
      expect.stringContaining("Канал опублікував попередження"),
    ]);
  });
  it("cancels a claimed message immediately when a post is edited", async () => {
    const m = await ingest();
    const delivery = await store.claim();
    expect(await store.deliverable(delivery!)).toBe(true);
    const edit = { ...message("Київ: відбій", 2), publishedAt: m.publishedAt };
    await bulletins.ingest(edit.channel, [edit], 2, true, true);
    expect(await store.deliverable(delivery!)).toBe(false);
    await bulletins.processOne();
    expect(await pending()).toHaveLength(0);
    expect((await bulletins.feed(uid))[0].kind).toBe("all_clear_report");
  });
  it("sends an explicit correction after a delivered warning, without claiming official all-clear", async () => {
    await ingest();
    const delivery = (await store.claim())!;
    await store.finish(delivery, "sent");
    await ingest("Київ: хибна тривога");
    await store.pool.query("UPDATE obriy.users SET last_delivery_at=NULL");
    const correction = (await store.claim())!;
    expect(correction.level).toBe("CORRECTION");
    expect(correction.text).toContain("Це не означає відбій");
    expect(await store.deliverable(correction)).toBe(true);
  });
  it("suppresses equal cross-channel warnings but keeps both source records", async () => {
    await ingest();
    await ingest("Київ: повітряна тривога", 2, 0, "kyiv_airdef");
    expect(await pending()).toHaveLength(1);
    expect(await bulletins.feed(uid)).toHaveLength(2);
  });
  it.each(["shadow", "disabled"] as const)(
    "collects without sending in %s mode",
    async (mode) => {
      store.config.OBRIY_BULLETIN_MODE = mode;
      await ingest();
      expect(await pending()).toHaveLength(0);
      expect(await bulletins.feed(uid)).toHaveLength(1);
    },
  );
  it("requires both approval and the full 24-hour warmup", async () => {
    store.config.OBRIY_BULLETIN_APPROVED = "false";
    expect(await bulletins.deliveryReady()).toBe(false);
    store.config.OBRIY_BULLETIN_APPROVED = "true";
    await store.pool.query(
      "UPDATE obriy.channel_cursors SET initialized_at=now() WHERE channel='kyiv_airdef'",
    );
    expect(await bulletins.deliveryReady()).toBe(false);
    await ingest();
    expect(await pending()).toHaveLength(0);
  });
  it("does not send bootstrap or stale posts after activation", async () => {
    const m = message();
    await bulletins.ingest(m.channel, [m], 2, false, true);
    await bulletins.processOne();
    await ingest("Київ: увага", 3, 300000);
    expect(await pending()).toHaveLength(0);
    expect(await bulletins.feed(uid)).toHaveLength(2);
  });
  it("kills pending delivery after pause, zone changes or mode switch", async () => {
    await ingest();
    const delivery = (await store.claim())!;
    store.config.OBRIY_BULLETIN_MODE = "shadow";
    expect(await store.deliverable(delivery)).toBe(false);
    store.config.OBRIY_BULLETIN_MODE = "live";
    await store.pause(uid, 60);
    expect(await store.deliverable(delivery)).toBe(false);
    expect(await pending()).toHaveLength(0);
    await store.pause(uid, 0);
    await ingest("Київ: можлива загроза", 3);
    await store.saveZone(
      uid,
      { ...zoneInput, bulletinAreas: ["boryspil"] },
      zoneId,
    );
    expect(await pending()).toHaveLength(0);
    expect(await bulletins.feed(uid)).toHaveLength(0);
  });
  it("fails closed on stale channel health, but not on quiet fresh pages", async () => {
    await ingest();
    const delivery = (await store.claim())!;
    expect(await store.deliverable(delivery)).toBe(true);
    await store.pool.query(
      "UPDATE obriy.channel_cursors SET last_success_at=now()-interval '100 seconds'",
    );
    expect(await store.deliverable(delivery)).toBe(false);
  });
  it("keeps administrative subscriptions explicit and private", async () => {
    await ingest();
    const other = randomUUID();
    await store.pool.query("INSERT INTO obriy.users(id) VALUES($1)", [other]);
    await store.saveZone(other, { ...zoneInput, bulletinAreas: ["boryspil"] });
    expect(await bulletins.feed(other)).toHaveLength(0);
    const unauth = await app.inject({ url: "/obriy/api/v1/bulletins" });
    expect(unauth.statusCode).toBe(401);
    const auth = await app.inject({
      url: "/obriy/api/v1/bulletins",
      cookies: { obriy_session: token },
    });
    expect(auth.statusCode).toBe(200);
    expect(auth.json().items).toHaveLength(1);
    expect(JSON.stringify(auth.json())).not.toContain('"lat"');
    expect(JSON.stringify(auth.json())).not.toContain('"text"');
    const invalid = await app.inject({
      method: "PATCH",
      url: `/obriy/api/v1/zones/${zoneId}`,
      cookies: { obriy_session: token },
      payload: { bulletinAreas: ["invented"] },
    });
    expect(invalid.statusCode).toBe(400);
  });
  it("rolls back content and cursor together if storage fails", async () => {
    const m = message();
    const spy = vi.spyOn(store.vault, "encrypt").mockImplementationOnce(() => {
      throw new Error("synthetic storage fault");
    });
    await expect(
      bulletins.ingest(m.channel, [m], 2, true, true),
    ).rejects.toThrow();
    spy.mockRestore();
    expect(await bulletins.cursor(m.channel)).toBe(1);
    expect(
      (await store.pool.query("SELECT * FROM obriy.channel_messages")).rows,
    ).toHaveLength(0);
  });
  it("deletes personalized bulletin rows with their user", async () => {
    await ingest();
    await store.deleteUser(uid);
    expect(
      (await store.pool.query("SELECT * FROM obriy.bulletin_decisions")).rows,
    ).toHaveLength(0);
    expect(await pending()).toHaveLength(0);
  });
});
