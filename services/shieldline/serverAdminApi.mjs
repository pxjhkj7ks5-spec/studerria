import { randomUUID, timingSafeEqual } from "node:crypto";
import { createFixedWindowRateLimiter, readCookie } from "./serverSecurity.mjs";

const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);

function safeEqual(left, right) {
  const a = Buffer.from(String(left || ""));
  const b = Buffer.from(String(right || ""));
  return a.length === b.length && timingSafeEqual(a, b);
}

function cookieHeader(token, { basePath, secure, maxAge = 28_800 }) {
  return `shieldline_admin_sid=${token}; Path=${basePath || "/"}; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure ? "; Secure" : ""}`;
}

function csrfCookieHeader(token, { basePath, secure, maxAge = 28_800 }) {
  return `shieldline_admin_csrf=${token}; Path=${basePath || "/"}; SameSite=Strict; Max-Age=${maxAge}${secure ? "; Secure" : ""}`;
}

function requestOriginAllowed(req) {
  const origin = String(req.headers.origin || "");
  if (!origin) return false;
  try {
    const parsed = new URL(origin);
    const forwardedHost = String(req.headers["x-forwarded-host"] || "").split(",")[0].trim();
    const host = forwardedHost || String(req.headers.host || "");
    return parsed.host === host;
  } catch { return false; }
}

export function createAdminApi({ store, adminPassword, adminLabel = "owner", basePath = "/shieldline", secure = false, sendJson, readJson, readOverlay, writeOverlay }) {
  const loginLimiter = createFixedWindowRateLimiter({ limit: 5, windowMs: 15 * 60_000 });
  const adminBase = `${basePath}/api/admin`;
  const actorFor = (session) => ({ source: "web", label: session.label });

  async function requireAdmin(req, res, { csrf = false } = {}) {
    const token = readCookie(req.headers.cookie, "shieldline_admin_sid");
    const csrfToken = csrf ? String(req.headers["x-shieldline-admin-csrf"] || "") : null;
    const session = await store.verifySession(token, csrfToken);
    if (!session) {
      sendJson(res, 401, { error: "Адміністративна сесія недійсна або завершилася." });
      return null;
    }
    if (csrf && !requestOriginAllowed(req)) {
      sendJson(res, 403, { error: "Запит заблоковано перевіркою походження." });
      return null;
    }
    return session;
  }

  async function action(req, res, session, actorId, name, body) {
    const actor = actorFor(session);
    const requestId = String(req.headers["x-request-id"] || randomUUID());
    const reason = String(body.reason || "").trim();
    const handlers = {
      suspend: () => store.suspend(actor, actorId, reason, requestId),
      activate: () => store.activate(actor, actorId, reason, requestId),
      "revoke-sessions": () => store.revokeSessions(actor, actorId, reason, requestId),
      "revoke-devices": () => store.revokeDevices(actor, actorId, reason, requestId),
      "reset-consent": () => store.resetConsent(actor, actorId, reason, requestId),
      "unlink-telegram": () => store.unlinkTelegram(actor, actorId, reason, requestId),
      "reset-progress": () => store.resetProgress(actor, actorId, reason, requestId),
      anonymize: () => store.anonymize(actor, actorId, reason, requestId),
      note: () => store.updateNote(actor, actorId, body.note, reason, requestId),
    };
    if (!handlers[name]) return false;
    sendJson(res, 200, { user: await handlers[name]() });
    return true;
  }

  return async function handleAdminApi(req, res, pathname, url) {
    if (pathname !== adminBase && !pathname.startsWith(`${adminBase}/`)) return false;
    const path = pathname.slice(adminBase.length) || "/";
    try {
      if (req.method === "POST" && path === "/auth/login") {
        const forwarded = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
        const clientKey = forwarded || req.socket.remoteAddress || "unknown";
        if (!loginLimiter.allow(clientKey)) throw Object.assign(new Error("Забагато спроб входу. Спробуйте пізніше."), { statusCode: 429 });
        if (!requestOriginAllowed(req)) throw Object.assign(new Error("Запит заблоковано перевіркою походження."), { statusCode: 403 });
        const body = await readJson(req);
        if (!adminPassword || !safeEqual(body.password, adminPassword)) throw Object.assign(new Error("Неправильний пароль адміністратора."), { statusCode: 401 });
        const issued = await store.createSession(adminLabel);
        res.setHeader("Set-Cookie", [cookieHeader(issued.token, { basePath: basePath || "/", secure }), csrfCookieHeader(issued.csrf, { basePath: basePath || "/", secure })]);
        sendJson(res, 200, { admin: { label: issued.adminLabel, expiresAt: issued.expiresAt }, csrfToken: issued.csrf });
        return true;
      }

      if (req.method === "GET" && path === "/me") {
        const session = await requireAdmin(req, res);
        if (session) sendJson(res, 200, { admin: session });
        return true;
      }

      if (req.method === "POST" && path === "/auth/logout") {
        const token = readCookie(req.headers.cookie, "shieldline_admin_sid");
        const session = await requireAdmin(req, res, { csrf: true });
        if (session) {
          await store.revokeSession(token);
          res.setHeader("Set-Cookie", [cookieHeader("", { basePath: basePath || "/", secure, maxAge: 0 }), csrfCookieHeader("", { basePath: basePath || "/", secure, maxAge: 0 })]);
          sendJson(res, 200, { ok: true });
        }
        return true;
      }

      const session = await requireAdmin(req, res, { csrf: MUTATING.has(req.method || "") });
      if (!session) return true;

      if (req.method === "GET" && path === "/dashboard") { sendJson(res, 200, await store.dashboard()); return true; }
      if (req.method === "GET" && path === "/users") {
        sendJson(res, 200, await store.listUsers({ query: url.searchParams.get("query") || "", status: url.searchParams.get("status") || "", telegram: url.searchParams.get("telegram") || "", activity: url.searchParams.get("activity") || "", cursor: url.searchParams.get("cursor") || "", limit: url.searchParams.get("limit") || 50 }));
        return true;
      }
      const userMatch = path.match(/^\/users\/([^/]+)$/);
      if (req.method === "GET" && userMatch) {
        const result = await store.userDetails(decodeURIComponent(userMatch[1]));
        sendJson(res, result ? 200 : 404, result || { error: "Користувача не знайдено." });
        return true;
      }
      const userActionMatch = path.match(/^\/users\/([^/]+)\/([^/]+)$/);
      if (req.method === "POST" && userActionMatch) {
        const body = await readJson(req);
        if (await action(req, res, session, decodeURIComponent(userActionMatch[1]), userActionMatch[2], body)) return true;
      }
      if (req.method === "DELETE" && userMatch) {
        const body = await readJson(req);
        sendJson(res, 200, await store.deleteUser(actorFor(session), decodeURIComponent(userMatch[1]), body.confirmation, body.reason, String(req.headers["x-request-id"] || randomUUID())));
        return true;
      }
      if (req.method === "GET" && path === "/operations") { sendJson(res, 200, await store.listOperations({ cursor: url.searchParams.get("cursor") || "", limit: url.searchParams.get("limit") || 50 })); return true; }
      const operationMatch = path.match(/^\/operations\/([^/]+)$/);
      if (req.method === "GET" && operationMatch) { const result = await store.operationDetails(decodeURIComponent(operationMatch[1])); sendJson(res, result ? 200 : 404, result || { error: "Операцію не знайдено." }); return true; }
      if (req.method === "GET" && path === "/audit") { sendJson(res, 200, { items: await store.listAudit(url.searchParams.get("limit") || 100) }); return true; }
      if (req.method === "GET" && path === "/system") { sendJson(res, 200, await store.systemHealth()); return true; }
      if (req.method === "GET" && path === "/broadcasts") { sendJson(res, 200, { items: await store.listBroadcasts() }); return true; }
      if (req.method === "GET" && path === "/broadcasts/preview") { sendJson(res, 200, await store.previewBroadcast()); return true; }
      if (req.method === "POST" && path === "/broadcasts") {
        const body = await readJson(req);
        sendJson(res, 201, await store.queueBroadcast(actorFor(session), body.text, body.reason, String(req.headers["x-request-id"] || randomUUID())));
        return true;
      }
      if (req.method === "POST" && path === "/broadcasts/test") {
        const body = await readJson(req);
        sendJson(res, 201, await store.queueTestNotification(actorFor(session), body.target, body.text, body.reason, String(req.headers["x-request-id"] || randomUUID())));
        return true;
      }
      if (req.method === "POST" && path === "/outbox/retry") {
        const body = await readJson(req);
        sendJson(res, 200, await store.retryOutbox(actorFor(session), body.reason, String(req.headers["x-request-id"] || randomUUID())));
        return true;
      }
      if (req.method === "GET" && path === "/zones") { sendJson(res, 200, { overlay: await readOverlay() }); return true; }
      if (req.method === "PUT" && path === "/zones") {
        const body = await readJson(req);
        await writeOverlay(body.overlay || body);
        sendJson(res, 200, { ok: true });
        return true;
      }
      sendJson(res, 404, { error: "Невідомий маршрут адміністративного API." });
      return true;
    } catch (error) {
      sendJson(res, Number(error?.statusCode) || 400, { error: error instanceof Error ? error.message : "Адміністративну дію не виконано." });
      return true;
    }
  };
}
