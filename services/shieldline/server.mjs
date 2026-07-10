import { createServer } from "node:http";
import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { createReadStream, existsSync, statSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, extname, join, normalize, resolve } from "node:path";
import { createGameStore, dayKey } from "./serverGame.mjs";
import { createConfiguredPostgresStore } from "./serverPostgresStore.mjs";
import { createFixedWindowRateLimiter, createPersistentSessionCodec, createSessionCodec, readCookie } from "./serverSecurity.mjs";
import { parseAnalyticsEvent, parseCampaignCommand, parseOperationCommand, parseOperationInput } from "./serverSchemas.mjs";
import { instrumentHttpHandler, recordAnalyticsMetric, renderPrometheusMetrics, shutdownTelemetry } from "./serverTelemetry.mjs";

const port = Number(process.env.PORT || 8080);
const basePath = normalizeBasePath(process.env.SHIELDLINE_BASE_PATH || "/shieldline");
const distDir = resolve("dist");
const indexPath = join(distDir, "index.html");
const controlOverlayFile = process.env.SHIELDLINE_CONTROL_OVERLAY_FILE || "/data/control-overlay.json";
const adminPassword = process.env.SHIELDLINE_ADMIN_PASSWORD || "";
const legacyGameStore = await createGameStore(process.env.SHIELDLINE_GAME_STORE_FILE || "/data/game-store.json");
const storageDriver = process.env.SHIELDLINE_STORAGE_DRIVER || "json";
const gameStore = storageDriver === "postgres" ? await createConfiguredPostgresStore({ legacyStore: legacyGameStore }) : legacyGameStore;
const telegramBotToken = process.env.SHIELDLINE_TELEGRAM_BOT_TOKEN || "";
const telegramAuthMaxAgeSeconds = Number(process.env.SHIELDLINE_TELEGRAM_AUTH_MAX_AGE_SECONDS || 86400);
const production = process.env.NODE_ENV === "production";
const sessionCodec = createSessionCodec({
  secret: process.env.SHIELDLINE_SESSION_SECRET || "shieldline-development-session-secret",
  basePath: basePath || "/",
  secure: production,
  ttlSeconds: Number(process.env.SHIELDLINE_SESSION_MAX_AGE_SECONDS || 2_592_000),
});
const persistentSessionCodec = gameStore.createSession ? createPersistentSessionCodec({
  repository: gameStore,
  basePath: basePath || "/",
  secure: production,
  ttlSeconds: Number(process.env.SHIELDLINE_SESSION_MAX_AGE_SECONDS || 2_592_000),
  rotationSeconds: Number(process.env.SHIELDLINE_SESSION_ROTATION_SECONDS || 86_400),
}) : null;
const apiRateLimiter = createFixedWindowRateLimiter({ limit: Number(process.env.SHIELDLINE_API_RATE_LIMIT_PER_MINUTE || 180) });

const securityHeaders = {
  "Content-Security-Policy": "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self' https://api.telegram.org; frame-ancestors 'self' https://*.telegram.org",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "SAMEORIGIN",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
};

const contentTypes = new Map([
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".webmanifest", "application/manifest+json; charset=utf-8"],
  [".svg", "image/svg+xml"],
  [".png", "image/png"],
  [".jpg", "image/jpeg"],
  [".jpeg", "image/jpeg"],
  [".webp", "image/webp"],
  [".ico", "image/x-icon"],
  [".woff", "font/woff"],
  [".woff2", "font/woff2"],
]);

function normalizeBasePath(value) {
  const raw = String(value || "").trim();
  if (!raw || raw === "/") return "";
  const withLeading = raw.startsWith("/") ? raw : `/${raw}`;
  return withLeading.replace(/\/+$/, "");
}

function sendFile(res, filePath) {
  const ext = extname(filePath).toLowerCase();
  const fileName = filePath.split(/[\\/]/).at(-1);
  const mutableShell = ext === ".html" || fileName === "sw.js";
  const cacheControl = mutableShell
    ? "no-store, no-cache, must-revalidate"
    : fileName === "manifest.webmanifest"
      ? "no-cache, must-revalidate"
      : "public, max-age=31536000, immutable";
  res.writeHead(200, {
    "Content-Type": contentTypes.get(ext) || "application/octet-stream",
    "Cache-Control": cacheControl,
    ...(mutableShell ? { Pragma: "no-cache", Expires: "0" } : {}),
    ...securityHeaders,
  });
  createReadStream(filePath).pipe(res);
}

function resolveAssetPath(pathname) {
  const withoutBase = basePath && pathname.startsWith(basePath)
    ? pathname.slice(basePath.length) || "/"
    : pathname;
  const decoded = decodeURIComponent(withoutBase.split("?")[0]);
  const normalizedPath = normalize(decoded).replace(/^(\.\.[/\\])+/, "");
  const filePath = join(distDir, normalizedPath);
  if (!filePath.startsWith(distDir)) return null;
  if (!existsSync(filePath) || !statSync(filePath).isFile()) return null;
  return filePath;
}

function sendJson(res, status, payload) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    ...securityHeaders,
  });
  res.end(JSON.stringify(payload));
}

function isControlOverlayApi(pathname) {
  return pathname === `${basePath}/api/control-overlay` || (!basePath && pathname === "/api/control-overlay");
}

function isControlOverlayAuthApi(pathname) {
  return pathname === `${basePath}/api/control-overlay/auth` || (!basePath && pathname === "/api/control-overlay/auth");
}

function isGameApi(pathname) {
  const apiBase = `${basePath}/api` || "/api";
  return pathname === apiBase || pathname.startsWith(`${apiBase}/`);
}

function gameApiPath(pathname) {
  const apiBase = `${basePath}/api` || "/api";
  return pathname.slice(apiBase.length) || "/";
}

async function safeActor(req, res) {
  const token = readCookie(req.headers.cookie, "shieldline_sid");
  if (persistentSessionCodec) {
    const existing = await persistentSessionCodec.verify(token);
    if (existing) {
      if (existing.replacementHeader) res.setHeader("Set-Cookie", existing.replacementHeader);
      return existing.actorId;
    }
    const issued = `guest-${randomUUID().slice(0, 18)}`;
    res.setHeader("Set-Cookie", (await persistentSessionCodec.issue(issued)).header);
    return issued;
  }
  const existing = sessionCodec.verify(token);
  if (existing) return existing;
  const issued = `guest-${randomUUID().slice(0, 18)}`;
  res.setHeader("Set-Cookie", sessionCodec.header(issued));
  return issued;
}

async function issueActorCookie(res, actorId) {
  res.setHeader("Set-Cookie", persistentSessionCodec ? (await persistentSessionCodec.issue(actorId)).header : sessionCodec.header(actorId));
}

function validateTelegramInitData(initData) {
  if (!telegramBotToken) throw new Error("Telegram auth is not configured.");
  const params = new URLSearchParams(String(initData || ""));
  const hash = params.get("hash") || "";
  params.delete("hash");
  const checkString = [...params.entries()].sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0).map(([key, value]) => `${key}=${value}`).join("\n");
  const secret = createHmac("sha256", "WebAppData").update(telegramBotToken).digest();
  const expected = createHmac("sha256", secret).update(checkString).digest("hex");
  if (!hash || hash.length !== expected.length || !timingSafeEqual(Buffer.from(hash), Buffer.from(expected))) throw new Error("Telegram initData signature is invalid.");
  const authDate = Number(params.get("auth_date") || 0);
  if (!authDate || Math.abs(Date.now() / 1000 - authDate) > telegramAuthMaxAgeSeconds) throw new Error("Telegram initData has expired.");
  const user = JSON.parse(params.get("user") || "{}");
  if (!Number.isSafeInteger(user.id)) throw new Error("Telegram user is missing.");
  return user;
}

async function deliverTelegramNotifications() {
  if (!telegramBotToken) return;
  for (const { item, chatId } of await gameStore.pendingNotificationDeliveries()) {
    const text = item.type === "daily.report.ready" ? "Shieldline: your daily defense report is ready." : "Shieldline: you have a new command update.";
    try {
      const response = await fetch(`https://api.telegram.org/bot${telegramBotToken}/sendMessage`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ chat_id: chatId, text }) });
      if (response.ok) await gameStore.markNotificationDelivered(item.id, chatId);
    } catch { /* Keep the outbox item for the next worker pass. */ }
  }
}

async function handleGameApi(req, res, pathname) {
  const path = gameApiPath(pathname);
  try {
    if (req.method === "GET" && path === "/health") {
      sendJson(res, 200, { ok: true, simVersion: "2.1.0", ...(gameStore.health ? await gameStore.health() : { storage: "json", redis: "disabled" }) });
      return;
    }
    if (req.method === "GET" && path === "/metrics") {
      res.writeHead(200, { "Content-Type": "text/plain; version=0.0.4; charset=utf-8", "Cache-Control": "no-store", ...securityHeaders });
      res.end(renderPrometheusMetrics());
      return;
    }
    if (req.method === "POST" && path === "/analytics") {
      const event = parseAnalyticsEvent(await readRequestJson(req));
      const actorId = await safeActor(req, res);
      if (gameStore.recordAnalytics) await gameStore.recordAnalytics(actorId, event);
      else console.log(JSON.stringify({ timestamp: new Date().toISOString(), level: "info", component: "shieldline.analytics", actorId, ...event }));
      recordAnalyticsMetric(event.eventName, event.channel);
      sendJson(res, 202, { accepted: true });
      return;
    }
    if (req.method === "POST" && path === "/operations") {
      const body = parseOperationInput(await readRequestJson(req));
      const actorId = await safeActor(req, res);
      const modeId = String(body.modeId || "training");
      if (!new Set(["campaign", "rapid-response", "ranked-challenge", "co-op-command", "sandbox", "training"]).has(modeId)) throw new Error("Unknown live operation mode.");
      if (production && actorId.startsWith("guest-") && (modeId === "ranked-challenge" || modeId === "co-op-command")) throw Object.assign(new Error("Telegram authorization is required for competitive modes."), { statusCode: 401 });
      const seed = String(body.seed || `${modeId}-${dayKey()}-${actorId}`).replace(/[^a-z0-9_-]/gi, "").slice(0, 80);
      const source = modeId === "ranked-challenge" ? "ranked" : modeId === "co-op-command" ? "co-op" : modeId === "campaign" ? "campaign" : "command";
      const run = await gameStore.runMission(seed || dayKey(), actorId, body.plan, String(body.missionId || "campaign-night-01"), source);
      sendJson(res, 201, { runId: run.id, revision: run.revision || 1, status: run.status || "completed", seed: run.seed, simVersion: run.simVersion || "1.0.0", run });
      return;
    }
    const operationEventsMatch = path.match(/^\/operations\/([^/]+)\/events$/);
    if (req.method === "GET" && operationEventsMatch) {
      const query = new URL(req.url || "/", "http://127.0.0.1").searchParams;
      const events = await gameStore.getRunEvents(operationEventsMatch[1], Math.max(0, Number(query.get("after") || 0)));
      if (!events) { sendJson(res, 404, { error: "Operation not found." }); return; }
      sendJson(res, 200, { events });
      return;
    }
    const operationSnapshotsMatch = path.match(/^\/operations\/([^/]+)\/snapshots$/);
    if (req.method === "GET" && operationSnapshotsMatch) {
      const query = new URL(req.url || "/", "http://127.0.0.1").searchParams;
      const requestedTick = query.has("tick") ? Number(query.get("tick")) : Number.POSITIVE_INFINITY;
      const snapshots = await gameStore.getRunSnapshots(operationSnapshotsMatch[1], requestedTick);
      if (!snapshots) { sendJson(res, 404, { error: "Operation not found." }); return; }
      sendJson(res, 200, { snapshots });
      return;
    }
    const operationCommandsMatch = path.match(/^\/operations\/([^/]+)\/commands$/);
    if (req.method === "POST" && operationCommandsMatch) {
      const body = parseOperationCommand(await readRequestJson(req));
      sendJson(res, 201, await gameStore.appendOperationCommand(operationCommandsMatch[1], await safeActor(req, res), body));
      return;
    }
    const operationMatch = path.match(/^\/operations\/([^/]+)$/);
    if (req.method === "GET" && operationMatch) {
      const run = await gameStore.getRun(operationMatch[1]);
      if (!run) { sendJson(res, 404, { error: "Operation not found." }); return; }
      sendJson(res, 200, run);
      return;
    }
    if (req.method === "GET" && path === "/daily") {
      const query = new URL(req.url || "/", "http://127.0.0.1").searchParams;
      sendJson(res, 200, await gameStore.getDailyReport(query.get("day") || dayKey(), {}, await safeActor(req, res)));
      return;
    }
    if (req.method === "POST" && path === "/daily/resolve") {
      const body = await readRequestJson(req);
      const key = /^\d{4}-\d{2}-\d{2}$/.test(String(body.dayKey || "")) ? body.dayKey : dayKey();
      sendJson(res, 200, await gameStore.getDailyReport(key, body.plan, await safeActor(req, res)));
      return;
    }
    if (req.method === "GET" && path === "/daily/city") {
      sendJson(res, 200, await gameStore.getDailyCity(await safeActor(req, res)));
      return;
    }
    if (req.method === "POST" && path === "/daily/city") {
      const body = await readRequestJson(req);
      sendJson(res, 200, await gameStore.saveDailyCity(await safeActor(req, res), body.plan));
      return;
    }
    if (req.method === "POST" && path === "/auth/telegram/init") {
      const user = validateTelegramInitData((await readRequestJson(req)).initData);
      const actorId = `tg-${user.id}`;
      await issueActorCookie(res, actorId);
      sendJson(res, 200, { user: { id: actorId, displayName: [user.first_name, user.last_name].filter(Boolean).join(" ") || user.username || "Telegram commander", platform: "telegram" } });
      return;
    }
    if (req.method === "POST" && path === "/auth/logout") {
      const token = readCookie(req.headers.cookie, "shieldline_sid");
      if (persistentSessionCodec) await persistentSessionCodec.revoke(token);
      res.setHeader("Set-Cookie", persistentSessionCodec ? persistentSessionCodec.clearHeader() : sessionCodec.clearHeader());
      sendJson(res, 200, { ok: true });
      return;
    }
    if (req.method === "POST" && path === "/notifications/preferences") {
      const body = await readRequestJson(req);
      const actorId = await safeActor(req, res);
      if (!actorId.startsWith("tg-")) throw new Error("Telegram authorization is required for bot notifications.");
      sendJson(res, 200, await gameStore.setNotificationPreference(actorId, actorId.slice(3), body.enabled));
      return;
    }
    if (req.method === "GET" && path === "/leaderboard") {
      sendJson(res, 200, { entries: await gameStore.leaderboard() });
      return;
    }
    if (req.method === "GET" && path === "/ranked/current") {
      const query = new URL(req.url || "/", "http://127.0.0.1").searchParams;
      const key = /^\d{4}-\d{2}-\d{2}$/.test(String(query.get("day") || "")) ? query.get("day") : dayKey();
      sendJson(res, 200, gameStore.rankedChallenge(key));
      return;
    }
    if (req.method === "POST" && path === "/ranked/submit") {
      const body = await readRequestJson(req);
      sendJson(res, 201, await gameStore.submitRanked(String(body.challengeId || ""), body.plan, await safeActor(req, res)));
      return;
    }
    if (req.method === "POST" && path === "/missions/run") {
      const body = await readRequestJson(req);
      const actorId = await safeActor(req, res);
      const seed = String(body.seed || `${dayKey()}-${actorId}`).replace(/[^a-z0-9_-]/gi, "").slice(0, 80);
      const run = await gameStore.runMission(seed || dayKey(), actorId, body.plan, String(body.missionId || "campaign-night-01"), String(body.source || "campaign"));
      sendJson(res, 201, run);
      return;
    }
    if (req.method === "GET" && path === "/campaign/state") {
      sendJson(res, 200, await gameStore.campaignState(await safeActor(req, res)));
      return;
    }
    if (req.method === "POST" && path === "/campaign/commands") {
      const body = parseCampaignCommand(await readRequestJson(req));
      await gameStore.recordCampaignCommand(await safeActor(req, res), String(body.type || "unknown"), body.payload);
      sendJson(res, 201, { ok: true });
      return;
    }
    if (req.method === "GET" && path.startsWith("/runs/")) {
      const run = await gameStore.getRun(path.slice("/runs/".length));
      if (!run) { sendJson(res, 404, { error: "Run not found." }); return; }
      sendJson(res, 200, run);
      return;
    }
    if (req.method === "GET" && path.startsWith("/rooms/")) {
      const viewerId = await safeActor(req, res);
      sendJson(res, 200, { ...(await gameStore.getRoom(path.slice("/rooms/".length))), viewerId });
      return;
    }
    const roomMatch = path.match(/^\/rooms\/([^/]+)\/claim$/);
    if (req.method === "POST" && roomMatch) {
      const body = await readRequestJson(req);
      const sectorId = String(body.sectorId || "");
      if (!new Set(["north", "south", "east", "west", "hq"]).has(sectorId)) { sendJson(res, 400, { error: "Unknown sector." }); return; }
      const viewerId = await safeActor(req, res);
      sendJson(res, 200, { ...(await gameStore.claimSector(roomMatch[1], sectorId, viewerId)), viewerId });
      return;
    }
    const commandMatch = path.match(/^\/rooms\/([^/]+)\/commands$/);
    if (req.method === "POST" && commandMatch) {
      const body = await readRequestJson(req);
      const sectorId = String(body.sectorId || "");
      if (!new Set(["north", "south", "east", "west"]).has(sectorId)) { sendJson(res, 400, { error: "Unknown sector." }); return; }
      const viewerId = await safeActor(req, res);
      sendJson(res, 201, { ...(await gameStore.appendRoomCommand(commandMatch[1], viewerId, sectorId, String(body.type || "unknown"), body.payload)), viewerId });
      return;
    }
    const resolveRoomMatch = path.match(/^\/rooms\/([^/]+)\/resolve$/);
    if (req.method === "POST" && resolveRoomMatch) {
      const viewerId = await safeActor(req, res);
      sendJson(res, 201, await gameStore.resolveCoOpRoom(resolveRoomMatch[1], viewerId));
      return;
    }
    if (req.method === "GET" && path === "/telegram/status") {
      sendJson(res, 200, { configured: Boolean(telegramBotToken), authMaxAgeSeconds: telegramAuthMaxAgeSeconds });
      return;
    }
    if (req.method === "GET" && path === "/notifications/outbox") {
      sendJson(res, 200, { items: await gameStore.notificationOutbox() });
      return;
    }
    sendJson(res, 404, { error: "Unknown Shieldline game API route." });
  } catch (error) {
    const status = Number(error?.statusCode) || 400;
    const reason = error instanceof Error ? error.message : "Game command could not be processed.";
    const details = error?.validationIssues ? { validationIssues: error.validationIssues } : error?.latestPatch ? { latestPatch: error.latestPatch } : {};
    console.warn(JSON.stringify({ timestamp: new Date().toISOString(), level: "warn", component: "shieldline.api", method: req.method, path, status, reason, ...details }));
    if (gameStore.auditRejectedCommand) await gameStore.auditRejectedCommand({ method: req.method || "UNKNOWN", path, reason, details }).catch(() => undefined);
    sendJson(res, status, { error: reason, ...details });
  }
}

function hasAdminAccess(req) {
  if (!adminPassword) return false;
  if (req.headers["x-shieldline-admin-password"] === adminPassword) return true;
  const authorization = String(req.headers.authorization || "");
  if (!authorization.startsWith("Basic ")) return false;
  try {
    const decoded = Buffer.from(authorization.slice(6), "base64").toString("utf8");
    return decoded === `admin:${adminPassword}`;
  } catch {
    return false;
  }
}

function readRequestJson(req) {
  return new Promise((resolveRequest, rejectRequest) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 131072) {
        rejectRequest(new Error("Request body too large."));
        req.destroy();
      }
    });
    req.on("end", () => {
      try {
        resolveRequest(JSON.parse(body || "{}"));
      } catch {
        rejectRequest(new Error("Invalid JSON body."));
      }
    });
    req.on("error", rejectRequest);
  });
}

async function handleControlOverlayApi(req, res) {
  if (req.method === "GET") {
    try {
      if (!existsSync(controlOverlayFile)) {
        sendJson(res, 200, { overlay: null });
        return;
      }
      const raw = await readFile(controlOverlayFile, "utf8");
      sendJson(res, 200, { overlay: JSON.parse(raw) });
    } catch {
      sendJson(res, 500, { error: "Could not read control overlay." });
    }
    return;
  }

  if (req.method === "PUT") {
    if (!hasAdminAccess(req)) {
      sendJson(res, 401, { error: "Admin password is required." });
      return;
    }
    try {
      const payload = await readRequestJson(req);
      await mkdir(dirname(controlOverlayFile), { recursive: true });
      await writeFile(controlOverlayFile, `${JSON.stringify(payload.overlay || payload, null, 2)}\n`, "utf8");
      sendJson(res, 200, { ok: true });
    } catch (error) {
      sendJson(res, 400, { error: error instanceof Error ? error.message : "Could not save control overlay." });
    }
    return;
  }

  res.writeHead(405, { Allow: "GET, PUT" });
  res.end();
}

function handleControlOverlayAuth(req, res) {
  if (req.method !== "POST") {
    res.writeHead(405, { Allow: "POST" });
    res.end();
    return;
  }
  if (!hasAdminAccess(req)) {
    sendJson(res, 401, { error: "Admin password is required." });
    return;
  }
  sendJson(res, 200, { ok: true });
}

const handleHttpRequest = async (req, res) => {
  const requestUrl = new URL(req.url || "/", "http://127.0.0.1");
  const pathname = requestUrl.pathname.replace(/\/+$/, "") || "/";

  if (basePath && pathname !== basePath && !pathname.startsWith(`${basePath}/`)) {
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Not found");
    return;
  }

  if (isControlOverlayApi(pathname)) {
    await handleControlOverlayApi(req, res);
    return;
  }

  if (isControlOverlayAuthApi(pathname)) {
    handleControlOverlayAuth(req, res);
    return;
  }

  if (isGameApi(pathname)) {
    const forwarded = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
    const clientKey = forwarded || req.socket.remoteAddress || "unknown";
    if (!apiRateLimiter.allow(clientKey)) {
      sendJson(res, 429, { error: "Too many Shieldline API requests." });
      return;
    }
    await handleGameApi(req, res, pathname);
    return;
  }

  const filePath = resolveAssetPath(requestUrl.pathname);
  if (filePath) {
    sendFile(res, filePath);
    return;
  }

  if (!existsSync(indexPath)) {
    res.writeHead(503, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Shieldline build is not available.");
    return;
  }

  sendFile(res, indexPath);
};

createServer(instrumentHttpHandler(handleHttpRequest)).listen(port, "0.0.0.0", () => {
  console.log(`Shieldline listening on 0.0.0.0:${port}${basePath || "/"}`);
});

if (storageDriver === "json") {
  const notificationTimer = setInterval(() => { void deliverTelegramNotifications(); }, 30_000);
  notificationTimer.unref();
}
process.once("SIGTERM", () => { void shutdownTelemetry(); });
