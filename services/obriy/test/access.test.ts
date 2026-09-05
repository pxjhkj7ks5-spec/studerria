import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import pg from "pg";
import { loadConfig, type Config } from "../src/config.js";
import { Store } from "../src/store.js";
import { Runtime } from "../src/runtime.js";
import { buildServer } from "../src/server.js";
import { hash } from "../src/security.js";

const connection = process.env.OBRIY_TEST_DATABASE_URL;
const integration = describe.skipIf(!connection);
const TOKEN = "test-only-existing-obriy-access-key-".repeat(3);
type App = Awaited<ReturnType<typeof buildServer>>;
const base = "/obriy";

integration(
  "existing access-key gate with an isolated PostgreSQL fixture",
  () => {
    const databaseName = `obriy_access_${process.pid}_${randomUUID().slice(0, 8)}`;
    let admin: pg.Client | undefined;
    let databaseCreated = false;
    let store: Store | undefined;
    let runtime: Runtime | undefined;
    let app: App | undefined;
    let config: Config;

    beforeAll(async () => {
      const adminUrl = new URL(connection!);
      adminUrl.pathname = "/postgres";
      admin = new pg.Client({ connectionString: adminUrl.toString() });
      await admin.connect();
      await admin.query(`CREATE DATABASE "${databaseName}"`);
      databaseCreated = true;
      const fixtureUrl = new URL(connection!);
      fixtureUrl.pathname = `/${databaseName}`;
      config = loadConfig({
        NODE_ENV: "test",
        OBRIY_DATABASE_URL: fixtureUrl.toString(),
        OBRIY_ENCRYPTION_KEY: "d".repeat(64),
        OBRIY_ADMIN_TOKEN: TOKEN,
        OBRIY_COLLECTORS_ENABLED: "false",
        OBRIY_TELEGRAM_MODE: "disabled",
      });
      store = new Store(config);
      await store.migrate();
    }, 30000);

    beforeEach(async () => {
      await app?.close();
      await runtime?.stop();
      await store!.pool.query(
        "TRUNCATE obriy.users,obriy.access_gates,obriy.login_attempts CASCADE",
      );
      runtime = new Runtime(config, store!);
      app = await buildServer(config, store!, runtime);
    });

    afterAll(async () => {
      try {
        await app?.close();
        await runtime?.stop();
        await store?.close();
      } finally {
        if (admin && databaseCreated)
          await admin.query(`DROP DATABASE "${databaseName}" WITH (FORCE)`);
        await admin?.end();
      }
    }, 30000);

    function expectLoginPage(body: string) {
      expect(body).toContain('class="login-page"');
      expect(body).toContain('id="login-form"');
      expect(body).toMatch(/type=["']password["']/);
      expect(body).not.toContain('id="zones-list"');
      expect(body).not.toContain('class="app-shell"');
    }

    async function gate(remoteAddress = "127.0.0.1") {
      const response = await app!.inject({
        method: "POST",
        url: `${base}/api/v1/session`,
        remoteAddress,
        payload: { token: TOKEN },
      });
      expect(response.statusCode, response.body).toBe(200);
      const cookie = response.cookies.find(
        (item) => item.name === "obriy_gate",
      );
      expect(cookie).toBeDefined();
      return cookie!.value;
    }

    const PASSWORD = "тихий вітер над осіннім озером";
    async function register(
      username = "test_user",
      gateToken?: string,
      legacy?: string,
    ) {
      const access = gateToken ?? (await gate());
      return app!.inject({
        method: "POST",
        url: `${base}/api/v1/auth/register`,
        cookies: {
          obriy_gate: access,
          ...(legacy ? { obriy_session: legacy } : {}),
        },
        payload: { username, password: PASSWORD },
      });
    }
    async function login(remoteAddress = "127.0.0.1") {
      const access = await gate(remoteAddress),
        response = await register("test_user", access);
      expect(response.statusCode, response.body).toBe(200);
      return response.cookies.find((c) => c.name === "obriy_session")!.value;
    }
    async function signIn(
      username: string,
      password = PASSWORD,
      gateToken?: string,
    ) {
      return app!.inject({
        method: "POST",
        url: `${base}/api/v1/auth/login`,
        cookies: { obriy_gate: gateToken ?? (await gate()) },
        payload: { username, password },
      });
    }
    function sessionCookie(response: Awaited<ReturnType<typeof register>>) {
      return response.cookies.find((c) => c.name === "obriy_session")!.value;
    }
    async function me(token: string) {
      return app!.inject({
        url: `${base}/api/v1/me`,
        cookies: { obriy_session: token },
      });
    }

    it.each([base, `${base}/`, `${base}/index.html`])(
      "serves only the login page at %s without an authenticated session",
      async (path) => {
        const response = await app!.inject(path);
        expect(response.statusCode).toBe(200);
        expect(response.headers["content-type"]).toContain("text/html");
        expect(response.headers["cache-control"]).toContain("no-store");
        expectLoginPage(response.body);
      },
    );

    it("opens the dashboard with the configured existing key", async () => {
      const cookie = await login();
      for (const path of [base, `${base}/`, `${base}/index.html`]) {
        const response = await app!.inject({
          url: path,
          cookies: { obriy_session: cookie },
        });
        expect(response.statusCode).toBe(200);
        expect(response.body).toContain('id="zones-list"');
        expect(response.body).toContain('class="app-shell"');
        expect(response.body).not.toContain('id="login-form"');
        expect(response.body).not.toContain(TOKEN);
      }
      expect(
        (
          await app!.inject({
            url: `${base}/api/v1/me`,
            cookies: { obriy_session: cookie },
          })
        ).statusCode,
      ).toBe(200);
    });

    it("returns to the login gate immediately after logout", async () => {
      const cookie = await login();
      const logout = await app!.inject({
        method: "DELETE",
        url: `${base}/api/v1/session`,
        cookies: { obriy_session: cookie },
      });
      expect(logout.statusCode).toBe(200);
      const response = await app!.inject({
        url: base,
        cookies: { obriy_session: cookie },
      });
      expect(response.statusCode).toBe(200);
      expectLoginPage(response.body);
      expect(
        (
          await app!.inject({
            url: `${base}/api/v1/me`,
            cookies: { obriy_session: cookie },
          })
        ).statusCode,
      ).toBe(401);
    });

    it("rejects an expired session before delivering dashboard HTML", async () => {
      const cookie = await login();
      await store!.pool.query(
        "UPDATE obriy.sessions SET expires_at=now()-interval '1 second' WHERE token_hash=$1",
        [hash(cookie)],
      );
      const response = await app!.inject({
        url: `${base}/index.html`,
        cookies: { obriy_session: cookie },
      });
      expect(response.statusCode).toBe(200);
      expectLoginPage(response.body);
      expect(
        (
          await app!.inject({
            url: `${base}/api/v1/me`,
            cookies: { obriy_session: cookie },
          })
        ).statusCode,
      ).toBe(401);
    });

    it.each(["me", "zones", "tracks"])(
      "keeps the private %s API unavailable before login",
      async (resource) => {
        const response = await app!.inject(`${base}/api/v1/${resource}`);
        expect(response.statusCode).toBe(401);
        expect(response.headers["content-type"]).toContain("application/json");
      },
    );

    it.each([
      `${base}/%69ndex.html`,
      `${base}/index%2ehtml`,
      `${base}/%2e/index.html`,
      `${base}//index.html`,
      `${base}/%2findex.html`,
      `${base}/%2569ndex.html`,
      `${base}/%69ndex.html?cachebust=1`,
    ])(
      "does not reveal dashboard markup through the static alias %s",
      async (path) => {
        const response = await app!.inject(path);
        expect([200, 301, 302, 303, 307, 308, 400, 403, 404]).toContain(
          response.statusCode,
        );
        expect(response.body).not.toContain('id="zones-list"');
        expect(response.body).not.toContain('class="app-shell"');
        if (response.statusCode === 200) expectLoginPage(response.body);
      },
    );

    it("limits wrong keys with 429 while the configured key still works from the same gateway IP", async () => {
      const remoteAddress = "192.0.2.18";
      const codes: number[] = [];
      for (let attempt = 0; attempt < 14; attempt++) {
        const response = await app!.inject({
          method: "POST",
          url: `${base}/api/v1/session`,
          remoteAddress,
          payload: { token: "incorrect-test-access-key-".repeat(3) },
        });
        codes.push(response.statusCode);
        expect(
          response.cookies.some(
            (cookie) => cookie.name === "obriy_session" && cookie.value,
          ),
        ).toBe(false);
      }
      expect(codes.slice(0, 10)).toEqual(Array(10).fill(401));
      expect(codes.slice(10)).toEqual(Array(4).fill(429));
      const cookie = await login(remoteAddress);
      const dashboard = await app!.inject({
        url: base,
        remoteAddress,
        cookies: { obriy_session: cookie },
      });
      expect(dashboard.statusCode).toBe(200);
      expect(dashboard.body).toContain('id="zones-list"');
    });

    it("the common key opens account entry but never exposes a profile", async () => {
      const token = await gate();
      const page = await app!.inject({
        url: base,
        cookies: { obriy_gate: token },
      });
      expect(page.body).toContain('id="account-form"');
      expect(page.body).not.toContain('id="zones-list"');
      expect(
        (
          await app!.inject({
            url: `${base}/api/v1/me`,
            cookies: { obriy_gate: token },
          })
        ).statusCode,
      ).toBe(401);
      expect(
        (await store!.pool.query("SELECT count(*)::int n FROM obriy.users"))
          .rows[0].n,
      ).toBe(0);
      expect(
        (
          await app!.inject({
            method: "POST",
            url: `${base}/api/v1/auth/register`,
            payload: { username: "outsider", password: PASSWORD },
          })
        ).statusCode,
      ).toBe(403);
    });
    it("stores salted hashes and permits normalized username/password login", async () => {
      const a = await register("АнДрІй");
      expect(a.statusCode).toBe(200);
      const account = (await me(sessionCookie(a))).json().account;
      expect(account.username).toBe("андрій");
      const row = (
        await store!.pool.query("SELECT password_hash FROM obriy.accounts")
      ).rows[0];
      expect(row.password_hash).toMatch(/^scrypt-v1/);
      expect(row.password_hash).not.toContain(PASSWORD);
      expect(
        (await signIn("АНДРІЙ", PASSWORD.normalize("NFD"))).statusCode,
      ).toBe(200);
      expect((await signIn("андрій", "wrong")).statusCode).toBe(401);
      expect((await register("андрій")).statusCode).toBe(409);
      const access = await gate();
      expect(
        (
          await app!.inject({
            method: "POST",
            url: `${base}/api/v1/auth/register`,
            cookies: { obriy_gate: access },
            payload: { username: "weak_user", password: "short" },
          })
        ).statusCode,
      ).toBe(400);
    });
    it("isolates users zones, pairing, deletion and sessions", async () => {
      const a = sessionCookie(await register("alice")),
        b = sessionCookie(await register("bob"));
      const aid = (await me(a)).json().user.id,
        bid = (await me(b)).json().user.id;
      expect(aid).not.toBe(bid);
      const zone = (
        await app!.inject({
          method: "POST",
          url: `${base}/api/v1/zones`,
          cookies: { obriy_session: a },
          payload: { label: "Alice private", lat: 50, lon: 30, radiusKm: 10 },
        })
      ).json().zone;
      expect((await me(a)).json().zones).toHaveLength(1);
      expect((await me(b)).json().zones).toHaveLength(0);
      for (const method of ["PATCH", "DELETE"] as const) {
        expect(
          (
            await app!.inject({
              method,
              url: `${base}/api/v1/zones/${zone.id}`,
              cookies: { obriy_session: b },
              ...(method === "PATCH" ? { payload: { label: "stolen" } } : {}),
            })
          ).statusCode,
        ).toBe(404);
      }
      const ac = await store!.pairingCode(aid),
        bc = await store!.pairingCode(bid);
      await store!.transaction((c) => store!.linkChat(c, ac.code, "100001"));
      expect(
        await store!.transaction((c) => store!.linkChat(c, bc.code, "100001")),
      ).toBeNull();
      expect(
        await store!.transaction((c) => store!.linkChat(c, bc.code, "100002")),
      ).toBe(bid);
      expect(await store!.chatUser("100001")).toBe(aid);
      expect(await store!.chatUser("100002")).toBe(bid);
      expect(
        (
          await app!.inject({
            method: "DELETE",
            url: `${base}/api/v1/me`,
            cookies: { obriy_session: a },
          })
        ).statusCode,
      ).toBe(200);
      expect((await me(a)).statusCode).toBe(401);
      expect((await me(b)).statusCode).toBe(200);
      expect(await store!.chatUser("100002")).toBe(bid);
    });
    it("only a surviving legacy session may attach an existing profile to a new account", async () => {
      const owner = await store!.owner(),
        oldSession = await store!.session(owner);
      await store!.saveZone(owner, {
        label: "existing private zone",
        lat: 50,
        lon: 30,
        radiusKm: 10,
        enabled: true,
      });
      const stranger = sessionCookie(await register("newcomer"));
      expect((await me(stranger)).json().zones).toHaveLength(0);
      const access = await gate();
      const upgraded = await register("original_owner", access, oldSession);
      expect(upgraded.statusCode, upgraded.body).toBe(200);
      const own = (await me(sessionCookie(upgraded))).json();
      expect(own.user.id).toBe(owner);
      expect(own.zones).toHaveLength(1);
      expect((await me(oldSession)).statusCode).toBe(401);
    });
    it("changes password, revokes prior sessions and leaves another account active", async () => {
      const a = sessionCookie(await register("alice")),
        a2 = sessionCookie(await signIn("alice")),
        b = sessionCookie(await register("bob"));
      const changed = "широка річка за тихим осіннім лісом";
      const response = await app!.inject({
        method: "POST",
        url: `${base}/api/v1/auth/password`,
        cookies: { obriy_session: a },
        payload: { currentPassword: PASSWORD, password: changed },
      });
      expect(response.statusCode, response.body).toBe(200);
      expect((await me(a)).statusCode).toBe(401);
      expect((await me(a2)).statusCode).toBe(401);
      expect((await me(b)).statusCode).toBe(200);
      expect((await me(sessionCookie(response))).statusCode).toBe(200);
      expect((await signIn("alice")).statusCode).toBe(401);
      expect((await signIn("alice", changed)).statusCode).toBe(200);
    });
    it("persists account attempt limits across gate tokens without blocking other accounts", async () => {
      await register("alice");
      await register("bob");
      for (let i = 0; i < 10; i++)
        expect(
          (await signIn("alice", "incorrect", await gate())).statusCode,
        ).toBe(401);
      expect((await signIn("alice")).statusCode).toBe(429);
      expect((await signIn("bob")).statusCode).toBe(200);
    }, 15000);

    it("bounds concurrent password derivation without blocking the service", async () => {
      await register("alice");
      const access = await gate();
      const results = await Promise.all([
        signIn("alice", PASSWORD, access),
        signIn("alice", PASSWORD, access),
      ]);
      expect(results.map((r) => r.statusCode).sort()).toEqual([200, 429]);
      expect((await app!.inject(`${base}/healthz`)).statusCode).toBe(200);
    });
    it("does not retain a registration after a failed account insert", async () => {
      await register("alice");
      await register("alice");
      expect(
        (await store!.pool.query("SELECT count(*)::int n FROM obriy.users"))
          .rows[0].n,
      ).toBe(1);
    });
  },
);
