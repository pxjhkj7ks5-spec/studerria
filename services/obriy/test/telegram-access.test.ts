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
import { hash } from "../src/security.js";
import { TelegramBot, type TelegramClient } from "../src/telegram.js";

const connection = process.env.OBRIY_TEST_DATABASE_URL;
const integration = describe.skipIf(!connection);
const CHAT_ID = 987654321;

integration("Telegram access with an isolated real PostgreSQL database", () => {
  const databaseName = `obriy_telegram_access_${process.pid}_${randomUUID().slice(0, 8)}`;
  let admin: pg.Client | undefined;
  let databaseCreated = false;
  let store: Store | undefined;
  let bot: TelegramBot;
  const send = vi.fn(async () => {});

  beforeAll(async () => {
    const adminUrl = new URL(connection!);
    adminUrl.pathname = "/postgres";
    admin = new pg.Client({ connectionString: adminUrl.toString() });
    await admin.connect();
    await admin.query(`CREATE DATABASE "${databaseName}"`);
    databaseCreated = true;
    const fixtureUrl = new URL(connection!);
    fixtureUrl.pathname = `/${databaseName}`;
    const config = loadConfig({
      NODE_ENV: "test",
      OBRIY_DATABASE_URL: fixtureUrl.toString(),
      OBRIY_ENCRYPTION_KEY: "d".repeat(64),
      OBRIY_ADMIN_TOKEN: "synthetic-telegram-access-key-".repeat(3),
      OBRIY_COLLECTORS_ENABLED: "false",
      OBRIY_TELEGRAM_MODE: "disabled",
    });
    store = new Store(config);
    await store.migrate();
    // Never contact Telegram: all replies remain in the fixture's encrypted outbox.
    bot = new TelegramBot(store, config, { send } as unknown as TelegramClient);
  }, 30000);

  beforeEach(async () => {
    await store!.pool.query(
      "TRUNCATE obriy.users, obriy.telegram_updates CASCADE",
    );
    send.mockClear();
  });

  afterAll(async () => {
    try {
      await store?.close();
    } finally {
      if (admin && databaseCreated)
        await admin.query(`DROP DATABASE "${databaseName}" WITH (FORCE)`);
      await admin?.end();
    }
  }, 30000);

  async function start(updateId: number, code?: string, chatId = CHAT_ID) {
    await bot.handle({
      update_id: updateId,
      message: {
        chat: { id: chatId, type: "private" },
        from: { id: chatId, is_bot: false },
        text: code === undefined ? "/start" : `/start ${code}`,
      },
    });
  }

  async function textFor(updateId: number): Promise<string | null> {
    const { rows } = await store!.pool.query(
      "SELECT id,payload_enc FROM obriy.notification_outbox WHERE dedupe_key=$1",
      [`telegram:${updateId}`],
    );
    return rows[0]
      ? store!.vault.decrypt<{ text: string }>(
          rows[0].payload_enc,
          `outbox:${rows[0].id}`,
        ).text
      : null;
  }

  async function expectUnlinked() {
    expect(await store!.chatUser(String(CHAT_ID))).toBeNull();
    expect(
      (
        await store!.pool.query(
          "SELECT count(*)::int AS n FROM obriy.notification_outbox",
        )
      ).rows[0].n,
    ).toBe(0);
    expect(send).not.toHaveBeenCalled();
  }

  it("plain /start cannot create or claim an owner in an empty database", async () => {
    await start(100);
    await expectUnlinked();
    expect(
      (await store!.pool.query("SELECT count(*)::int AS n FROM obriy.users"))
        .rows[0].n,
    ).toBe(0);
  });

  it("plain /start cannot consume a pending code or bind the existing owner", async () => {
    const owner = await store!.owner();
    await store!.pairingCode(owner);
    await start(101);
    await expectUnlinked();
    expect((await store!.user(owner))!.telegramLinked).toBe(false);
    expect(
      (
        await store!.pool.query(
          "SELECT count(*)::int AS n FROM obriy.pairing_codes",
        )
      ).rows[0].n,
    ).toBe(1);
  });

  it("distinguishes newly paired /start CODE from plain /start in an already linked chat", async () => {
    const owner = await store!.owner();
    const { code } = await store!.pairingCode(owner);
    await start(102, code);
    expect(await store!.chatUser(String(CHAT_ID))).toBe(owner);
    expect(await textFor(102)).toMatch(/^Обрій підключено\./);

    await start(103);
    expect(await store!.chatUser(String(CHAT_ID))).toBe(owner);
    expect(await textFor(103)).toMatch(/^Цей чат уже підключений до Обрію\./);
    expect(await textFor(103)).not.toMatch(/^Обрій підключено\./);
    expect(send).not.toHaveBeenCalled();
  });

  it("rejects an invalid code without consuming the owner's valid code", async () => {
    const owner = await store!.owner();
    const { code } = await store!.pairingCode(owner);
    await start(104, "synthetic-invalid-code");
    await expectUnlinked();
    const { rows } = await store!.pool.query(
      "SELECT code_hash FROM obriy.pairing_codes",
    );
    expect(rows).toEqual([{ code_hash: hash(code) }]);
  });

  it("rejects an expired code without binding a chat or confirming a connection", async () => {
    const owner = await store!.owner();
    const { code } = await store!.pairingCode(owner);
    await store!.pool.query(
      "UPDATE obriy.pairing_codes SET expires_at=now()-interval '1 second' WHERE code_hash=$1",
      [hash(code)],
    );
    await start(105, code);
    await expectUnlinked();
    expect((await store!.user(owner))!.telegramLinked).toBe(false);
  });

  it("rejects a used code in both the linked chat and a different private chat", async () => {
    const owner = await store!.owner();
    const { code } = await store!.pairingCode(owner);
    await start(106, code);
    await start(107, code);
    await start(108, code, CHAT_ID + 1);
    expect(await store!.chatUser(String(CHAT_ID))).toBe(owner);
    expect(await store!.chatUser(String(CHAT_ID + 1))).toBeNull();
    expect(await textFor(107)).toBeNull();
    expect(await textFor(108)).toBeNull();
    expect(
      (
        await store!.pool.query(
          "SELECT count(*)::int AS n FROM obriy.notification_outbox",
        )
      ).rows[0].n,
    ).toBe(1);
    expect(send).not.toHaveBeenCalled();
  });

  it("replaying a Telegram update does not enqueue a second confirmation", async () => {
    const owner = await store!.owner();
    const { code } = await store!.pairingCode(owner);
    await start(109, code);
    await start(109, code);
    expect(await store!.chatUser(String(CHAT_ID))).toBe(owner);
    expect(
      (
        await store!.pool.query(
          "SELECT count(*)::int AS n FROM obriy.notification_outbox",
        )
      ).rows[0].n,
    ).toBe(1);
    expect(send).not.toHaveBeenCalled();
  });
  it("does not deliver an already claimed message to a removed chat binding", async () => {
    const owner = await store!.owner(),
      first = await store!.pairingCode(owner);
    await store!.transaction((c) =>
      store!.linkChat(c, first.code, String(CHAT_ID)),
    );
    await store!.transaction((c) =>
      store!.enqueue(
        c,
        owner,
        "private command reply",
        "rebind-fixture",
        undefined,
        300,
      ),
    );
    const delivery = await store!.claim();
    expect(delivery).toBeTruthy();
    expect(await store!.deliverable(delivery!)).toBe(true);
    const next = await store!.pairingCode(owner);
    await store!.transaction((c) =>
      store!.linkChat(c, next.code, String(CHAT_ID + 1)),
    );
    expect(await store!.chatUser(String(CHAT_ID))).toBeNull();
    expect(await store!.deliverable(delivery!)).toBe(false);
    expect(send).not.toHaveBeenCalled();
  });
});
