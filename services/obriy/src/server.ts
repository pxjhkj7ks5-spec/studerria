import Fastify, { type FastifyRequest } from "fastify";
import cookie from "@fastify/cookie";
import rateLimit from "@fastify/rate-limit";
import staticFiles from "@fastify/static";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import { type Config } from "./config.js";
import { type Store } from "./store.js";
import { type Runtime } from "./runtime.js";
import { equalSecret } from "./security.js";
const zoneBody = z
  .object({
    label: z.string().trim().min(1).max(40),
    lat: z.number().finite().min(-90).max(90),
    lon: z.number().finite().min(-180).max(180),
    radiusKm: z.number().finite().min(1).max(100),
    oblast: z
      .string()
      .trim()
      .max(100)
      .nullable()
      .transform((v) => v ?? undefined)
      .optional(),
    regionUid: z
      .string()
      .trim()
      .regex(/^\d{1,12}$/)
      .nullable()
      .transform((v) => v ?? undefined)
      .optional(),
    enabled: z.boolean().default(true),
  })
  .strict();
const uuid = z.string().uuid();
export async function buildServer(
  config: Config,
  store: Store,
  runtime: Runtime,
) {
  const app = Fastify({
    logger: false,
    bodyLimit: 16384,
    requestTimeout: 15000,
    connectionTimeout: 15000,
    trustProxy: false,
  });
  const b = config.base,
    sessionName = "obriy_session",
    secure = config.NODE_ENV === "production";
  const cookieOptions = {
    path: b || "/",
    httpOnly: true,
    secure,
    sameSite: "strict" as const,
    maxAge: config.OBRIY_SESSION_HOURS * 3600,
  };
  await app.register(cookie);
  await app.register(rateLimit, {
    max: 180,
    timeWindow: "1 minute",
    errorResponseBuilder: () => ({
      error: "Забагато запитів. Спробуйте пізніше.",
    }),
  });
  const identify = async (req: FastifyRequest) =>
    config.configured && req.cookies[sessionName]
      ? store.sessionUser(req.cookies[sessionName]!)
      : null;
  app.addHook("onRequest", async (req, reply) => {
    reply
      .header("Cache-Control", "no-store")
      .header("X-Content-Type-Options", "nosniff")
      .header("Referrer-Policy", "no-referrer")
      .header("X-Frame-Options", "DENY")
      .header(
        "Permissions-Policy",
        "geolocation=(self), camera=(), microphone=()",
      )
      .header(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
      );
    const routePath = req.url.split("?")[0];
    if (routePath === `${b}/telegram/webhook`) {
      if (
        config.OBRIY_TELEGRAM_MODE !== "webhook" ||
        !config.configured ||
        !config.OBRIY_TELEGRAM_BOT_TOKEN ||
        !equalSecret(
          String(req.headers["x-telegram-bot-api-secret-token"] ?? ""),
          config.OBRIY_TELEGRAM_WEBHOOK_SECRET,
        )
      )
        return reply.code(403).send({ error: "Forbidden" });
    } else if (!["GET", "HEAD", "OPTIONS"].includes(req.method)) {
      const origin = req.headers.origin,
        fetchSite = req.headers["sec-fetch-site"];
      if (
        fetchSite === "cross-site" ||
        (origin && origin !== new URL(config.OBRIY_PUBLIC_URL).origin)
      )
        return reply
          .code(403)
          .send({ error: "Запит з іншого сайту заборонено." });
    }
  });
  app.setErrorHandler((err, _req, reply) => {
    const error = err as { statusCode?: number };
    const code =
      error.statusCode && error.statusCode >= 400 && error.statusCode < 500
        ? error.statusCode
        : 500;
    reply
      .code(code)
      .send({
        error:
          code === 500
            ? "Сервіс тимчасово недоступний."
            : "Перевірте введені дані.",
      });
  });
  const requireUser = async (req: FastifyRequest) => {
    const id = await identify(req);
    if (!id)
      throw Object.assign(new Error("Unauthorized"), { statusCode: 401 });
    return id;
  };
  app.get(`${b}/healthz`, async () => ({ ok: true }));
  app.get(`${b}/readyz`, async (_req, reply) => {
    let db = true;
    try {
      await store.ping();
    } catch {
      db = false;
    }
    const ready =
      db && config.configured && runtime.leader && runtime.sourceFresh();
    return reply
      .code(ready ? 200 : 503)
      .send({
        ready,
        database: db,
        configured: config.configured,
        sourceFresh: runtime.sourceFresh(),
      });
  });
  app.get(`${b}/api/v1/status`, async (req) => ({
    service: "Обрій",
    version: config.OBRIY_RELEASE_VERSION,
    configured: config.configured,
    defaults: { radiusKm: config.OBRIY_DEFAULT_RADIUS_KM },
    authenticated: Boolean(await identify(req)),
    sources: runtime.health(),
    delivery: {
      configured: Boolean(
        config.OBRIY_TELEGRAM_BOT_TOKEN &&
        config.OBRIY_TELEGRAM_MODE !== "disabled",
      ),
      state: runtime.dispatcher.lastError
        ? "degraded"
        : runtime.bot.lastError
          ? "degraded"
          : "ready",
    },
    counts: { tracks: (await store.counts()).tracks },
    serverTime: new Date().toISOString(),
  }));
  app.post(
    `${b}/api/v1/session`,
    { config: { rateLimit: { max: 10, timeWindow: "15 minutes" } } },
    async (req, reply) => {
      const body = z.object({ token: z.string().max(512) }).safeParse(req.body);
      if (
        !config.configured ||
        !body.success ||
        !equalSecret(body.data.token, config.OBRIY_ADMIN_TOKEN)
      )
        return reply.code(401).send({ error: "Ключ доступу не підійшов." });
      const id = await store.owner(),
        token = await store.session(id);
      return reply
        .setCookie(sessionName, token, cookieOptions)
        .send({ ok: true });
    },
  );
  app.delete(`${b}/api/v1/session`, async (req, reply) => {
    if (req.cookies[sessionName]) await store.logout(req.cookies[sessionName]!);
    return reply.clearCookie(sessionName, cookieOptions).send({ ok: true });
  });
  app.get(`${b}/api/v1/me`, async (req) => {
    const id = await requireUser(req);
    return {
      user: await store.user(id),
      zones: await store.zones(id),
      assessments: await store.assessments(id),
    };
  });
  app.delete(`${b}/api/v1/me`, async (req, reply) => {
    await store.deleteUser(await requireUser(req));
    return reply.clearCookie(sessionName, cookieOptions).send({ ok: true });
  });
  app.get(`${b}/api/v1/zones`, async (req) => ({
    zones: await store.zones(await requireUser(req)),
  }));
  app.post(`${b}/api/v1/zones`, async (req, reply) => {
    const id = await requireUser(req),
      body = zoneBody.safeParse(req.body);
    if (!body.success)
      return reply
        .code(400)
        .send({ error: "Перевірте назву, координати та радіус 1–100 км." });
    const zone = await store.saveZone(id, body.data);
    void runtime.reevaluate().catch(() => {});
    return reply.code(201).send({ zone });
  });
  app.patch(`${b}/api/v1/zones/:id`, async (req, reply) => {
    const userId = await requireUser(req),
      id = uuid.safeParse((req.params as { id: string }).id),
      patch = zoneBody.partial().safeParse(req.body);
    if (!id.success || !patch.success)
      return reply.code(400).send({ error: "Невірні дані зони." });
    const prior = (await store.zones(userId)).find((z) => z.id === id.data);
    if (!prior) return reply.code(404).send({ error: "Зону не знайдено." });
    const { id: _id, userId: _uid, ...data } = prior;
    const zone = await store.saveZone(
      userId,
      zoneBody.parse({ ...data, ...patch.data }),
      id.data,
    );
    void runtime.reevaluate().catch(() => {});
    return { zone };
  });
  app.delete(`${b}/api/v1/zones/:id`, async (req, reply) => {
    const userId = await requireUser(req),
      id = uuid.safeParse((req.params as { id: string }).id);
    if (!id.success)
      return reply.code(400).send({ error: "Невірний ідентифікатор." });
    return (await store.deleteZone(userId, id.data))
      ? { ok: true }
      : reply.code(404).send({ error: "Зону не знайдено." });
  });
  app.post(`${b}/api/v1/preferences`, async (req, reply) => {
    const id = await requireUser(req),
      body = z
        .object({ pausedMinutes: z.union([z.literal(0), z.literal(60)]) })
        .safeParse(req.body);
    if (!body.success)
      return reply.code(400).send({ error: "Невірне значення паузи." });
    await store.pause(id, body.data.pausedMinutes);
    return { ok: true };
  });
  app.post(
    `${b}/api/v1/telegram/link`,
    { config: { rateLimit: { max: 10, timeWindow: "1 minute" } } },
    async (req, reply) => {
      const id = await requireUser(req);
      if (
        !config.OBRIY_TELEGRAM_BOT_TOKEN ||
        config.OBRIY_TELEGRAM_MODE === "disabled"
      )
        return reply
          .code(409)
          .send({ error: "Власник ще не підключив Telegram-бота." });
      return {
        ...(await store.pairingCode(id)),
        botUsername: config.OBRIY_TELEGRAM_BOT_USERNAME || undefined,
      };
    },
  );
  app.post(`${b}/telegram/webhook`, async (req) => {
    await runtime.bot.handle(req.body);
    return { ok: true };
  });
  app.get(`${b}/api/v1/tracks`, async (req) => {
    await requireUser(req);
    return {
      tracks: (await store.tracks()).map((t) => ({
        id: t.internalId,
        type: t.threat.type,
        status: t.status,
        updatedAt: t.updatedAt,
        areaOnly: t.position.areaOnly,
        advisory: t.advisory,
        confidence: t.confidence.upstreamLevel,
      })),
    };
  });
  app.get(`${b}/metrics`, async (req, reply) => {
    if (
      !config.OBRIY_METRICS_TOKEN ||
      !equalSecret(
        String(req.headers.authorization ?? ""),
        `Bearer ${config.OBRIY_METRICS_TOKEN}`,
      )
    )
      return reply.code(404).send();
    const counts = await store.counts();
    return reply
      .type("text/plain; version=0.0.4")
      .send(
        `obriy_source_fresh ${runtime.sourceFresh() ? 1 : 0}\nobriy_leader ${runtime.leader ? 1 : 0}\nobriy_rejected_events_total ${runtime.rejected}\nobriy_active_tracks ${counts.tracks}\nobriy_outbox_pending ${counts.pending}\nobriy_outbox_dead ${counts.dead}\n`,
      );
  });
  app.get(`${b}/changelog.json`, async () => ({
    items: [
      {
        version: config.OBRIY_RELEASE_VERSION,
        date: "2026-09-05",
        items: ["Початковий випуск персонального моніторингу зон."],
      },
    ],
  }));
  const html = await readFile(path.resolve("public/index.html"), "utf8");
  app.get(b || "/", async (_req, reply) =>
    reply.type("text/html").send(html.replaceAll("__APP_BASE__", b)),
  );
  if (b)
    app.get(`${b}/`, async (_req, reply) =>
      reply.type("text/html").send(html.replaceAll("__APP_BASE__", b)),
    );
  await app.register(staticFiles, {
    root: path.resolve("public"),
    prefix: `${b}/`,
    index: false,
    decorateReply: false,
    cacheControl: false,
  });
  return app;
}
