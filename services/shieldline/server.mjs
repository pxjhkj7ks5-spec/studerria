import { createServer } from "node:http";
import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { createReadStream, existsSync, statSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, extname, join, normalize, resolve } from "node:path";
import { createGameStore, dayKey } from "./serverGame.mjs";

const port = Number(process.env.PORT || 8080);
const basePath = normalizeBasePath(process.env.SHIELDLINE_BASE_PATH || "/shieldline");
const distDir = resolve("dist");
const indexPath = join(distDir, "index.html");
const controlOverlayFile = process.env.SHIELDLINE_CONTROL_OVERLAY_FILE || "/data/control-overlay.json";
const adminPassword = process.env.SHIELDLINE_ADMIN_PASSWORD || "";
const gameStore = await createGameStore(process.env.SHIELDLINE_GAME_STORE_FILE || "/data/game-store.json");
const telegramBotToken = process.env.SHIELDLINE_TELEGRAM_BOT_TOKEN || "";
const telegramAuthMaxAgeSeconds = Number(process.env.SHIELDLINE_TELEGRAM_AUTH_MAX_AGE_SECONDS || 86400);

const contentTypes = new Map([
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
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
  res.writeHead(200, {
    "Content-Type": contentTypes.get(ext) || "application/octet-stream",
    "Cache-Control": ext === ".html" ? "no-store" : "public, max-age=31536000, immutable",
    "X-Content-Type-Options": "nosniff",
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
    "X-Content-Type-Options": "nosniff",
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

function safeActor(req, res) {
  const existing = String(req.headers.cookie || "").match(/(?:^|;\s*)shieldline_sid=([a-z0-9_-]{8,64})/i)?.[1];
  if (existing) return existing;
  const issued = `guest-${randomUUID().slice(0, 18)}`;
  res.setHeader("Set-Cookie", `shieldline_sid=${issued}; Path=${basePath || "/"}; HttpOnly; SameSite=Lax; Max-Age=2592000`);
  return issued;
}

function issueActorCookie(res, actorId) {
  res.setHeader("Set-Cookie", `shieldline_sid=${actorId}; Path=${basePath || "/"}; HttpOnly; SameSite=Lax; Max-Age=2592000`);
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
    if (req.method === "GET" && path === "/daily") {
      const query = new URL(req.url || "/", "http://127.0.0.1").searchParams;
      sendJson(res, 200, await gameStore.getDailyReport(query.get("day") || dayKey(), { assetCount: Math.max(0, Math.min(32, Number(query.get("assets") || 0))) }));
      return;
    }
    if (req.method === "POST" && path === "/daily/resolve") {
      const body = await readRequestJson(req);
      const key = /^\d{4}-\d{2}-\d{2}$/.test(String(body.dayKey || "")) ? body.dayKey : dayKey();
      sendJson(res, 200, await gameStore.getDailyReport(key, body.plan));
      return;
    }
    if (req.method === "POST" && path === "/auth/telegram/init") {
      const user = validateTelegramInitData((await readRequestJson(req)).initData);
      const actorId = `tg-${user.id}`;
      issueActorCookie(res, actorId);
      sendJson(res, 200, { user: { id: actorId, displayName: [user.first_name, user.last_name].filter(Boolean).join(" ") || user.username || "Telegram commander", platform: "telegram" } });
      return;
    }
    if (req.method === "POST" && path === "/notifications/preferences") {
      const body = await readRequestJson(req);
      const actorId = safeActor(req, res);
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
      sendJson(res, 201, await gameStore.submitRanked(String(body.challengeId || ""), body.plan, safeActor(req, res)));
      return;
    }
    if (req.method === "POST" && path === "/missions/run") {
      const body = await readRequestJson(req);
      const actorId = safeActor(req, res);
      const seed = String(body.seed || `${dayKey()}-${actorId}`).replace(/[^a-z0-9_-]/gi, "").slice(0, 80);
      const run = await gameStore.runMission(seed || dayKey(), actorId, body.plan);
      sendJson(res, 201, run);
      return;
    }
    if (req.method === "POST" && path === "/campaign/commands") {
      const body = await readRequestJson(req);
      await gameStore.recordCampaignCommand(safeActor(req, res), String(body.type || "unknown"), body.payload);
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
      const viewerId = safeActor(req, res);
      sendJson(res, 200, { ...(await gameStore.getRoom(path.slice("/rooms/".length))), viewerId });
      return;
    }
    const roomMatch = path.match(/^\/rooms\/([^/]+)\/claim$/);
    if (req.method === "POST" && roomMatch) {
      const body = await readRequestJson(req);
      const sectorId = String(body.sectorId || "");
      if (!new Set(["north", "south", "east", "west", "hq"]).has(sectorId)) { sendJson(res, 400, { error: "Unknown sector." }); return; }
      const viewerId = safeActor(req, res);
      sendJson(res, 200, { ...(await gameStore.claimSector(roomMatch[1], sectorId, viewerId)), viewerId });
      return;
    }
    const commandMatch = path.match(/^\/rooms\/([^/]+)\/commands$/);
    if (req.method === "POST" && commandMatch) {
      const body = await readRequestJson(req);
      const sectorId = String(body.sectorId || "");
      if (!new Set(["north", "south", "east", "west"]).has(sectorId)) { sendJson(res, 400, { error: "Unknown sector." }); return; }
      const viewerId = safeActor(req, res);
      sendJson(res, 201, { ...(await gameStore.appendRoomCommand(commandMatch[1], viewerId, sectorId, String(body.type || "unknown"), body.payload)), viewerId });
      return;
    }
    if (req.method === "GET" && path === "/notifications/outbox") {
      sendJson(res, 200, { items: await gameStore.notificationOutbox() });
      return;
    }
    sendJson(res, 404, { error: "Unknown Shieldline game API route." });
  } catch (error) {
    sendJson(res, 400, { error: error instanceof Error ? error.message : "Game command could not be processed." });
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
      if (body.length > 512000) {
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

createServer(async (req, res) => {
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
}).listen(port, "0.0.0.0", () => {
  console.log(`Shieldline listening on 0.0.0.0:${port}${basePath || "/"}`);
});

const notificationTimer = setInterval(() => { void deliverTelegramNotifications(); }, 30_000);
notificationTimer.unref();
