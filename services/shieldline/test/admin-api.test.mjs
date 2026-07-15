import assert from "node:assert/strict";
import test from "node:test";
import { createAdminApi } from "../serverAdminApi.mjs";

function responseCapture() {
  return { headers: {}, status: 0, payload: null, setHeader(name, value) { this.headers[name] = value; } };
}

function request(method, path, body = {}, headers = {}) {
  return { method, body, headers: { host: "shieldline.test", origin: "https://shieldline.test", ...headers }, socket: { remoteAddress: "127.0.0.1" }, url: path };
}

test("admin API creates a secure password session and requires CSRF for mutations", async () => {
  const sessions = new Map();
  const store = {
    async createSession() { sessions.set("session", "csrf"); return { token: "session", csrf: "csrf", expiresAt: "2099-01-01", adminLabel: "owner" }; },
    async verifySession(token, csrf) { return sessions.has(token) && (csrf === null || csrf === sessions.get(token)) ? { source: "web", label: "owner" } : null; },
    async revokeSession(token) { sessions.delete(token); },
    async dashboard() { return { users: 1 }; },
  };
  const sendJson = (res, status, payload) => { res.status = status; res.payload = payload; };
  const api = createAdminApi({ store, adminPassword: "correct-password", basePath: "/shieldline", secure: true, sendJson, readJson: async (req) => req.body, readOverlay: async () => null, writeOverlay: async () => undefined });
  const loginRes = responseCapture();
  assert.equal(await api(request("POST", "/shieldline/api/admin/auth/login", { password: "correct-password" }), loginRes, "/shieldline/api/admin/auth/login", new URL("https://shieldline.test/shieldline/api/admin/auth/login")), true);
  assert.equal(loginRes.status, 200);
  assert.equal(loginRes.headers["Set-Cookie"].length, 2);
  assert.match(loginRes.headers["Set-Cookie"][0], /HttpOnly; SameSite=Strict/);
  assert.match(loginRes.headers["Set-Cookie"][0], /; Secure/);

  const missingCsrf = responseCapture();
  await api(request("POST", "/shieldline/api/admin/auth/logout", {}, { cookie: "shieldline_admin_sid=session" }), missingCsrf, "/shieldline/api/admin/auth/logout", new URL("https://shieldline.test/shieldline/api/admin/auth/logout"));
  assert.equal(missingCsrf.status, 401);

  const logoutRes = responseCapture();
  await api(request("POST", "/shieldline/api/admin/auth/logout", {}, { cookie: "shieldline_admin_sid=session", "x-shieldline-admin-csrf": "csrf" }), logoutRes, "/shieldline/api/admin/auth/logout", new URL("https://shieldline.test/shieldline/api/admin/auth/logout"));
  assert.equal(logoutRes.status, 200);
  assert.equal(sessions.size, 0);
});

test("admin API rejects password login from a foreign origin", async () => {
  const store = { async createSession() { throw new Error("must not issue"); } };
  const sendJson = (res, status, payload) => { res.status = status; res.payload = payload; };
  const api = createAdminApi({ store, adminPassword: "password", basePath: "/shieldline", sendJson, readJson: async (req) => req.body, readOverlay: async () => null, writeOverlay: async () => undefined });
  const res = responseCapture();
  await api(request("POST", "/shieldline/api/admin/auth/login", { password: "password" }, { origin: "https://attacker.test" }), res, "/shieldline/api/admin/auth/login", new URL("https://shieldline.test/shieldline/api/admin/auth/login"));
  assert.equal(res.status, 403);
});
