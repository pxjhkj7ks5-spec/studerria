import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import type { Request, Response } from "express";
import type { Db } from "./db.js";
import type { AppConfig } from "./config.js";

export type Role = "dev" | "deanery" | "teacher";

export type SessionUser = {
  id: number;
  email: string;
  displayName: string;
  role: Role;
};

const cookieName = "wa_tasks_session";

function base64Url(input: Buffer | string) {
  return Buffer.from(input).toString("base64url");
}

function sign(payload: string, secret: string) {
  return crypto.createHmac("sha256", secret).update(payload).digest("base64url");
}

export function createSessionToken(userId: number, secret: string) {
  const payload = base64Url(JSON.stringify({ uid: userId, exp: Date.now() + 7 * 24 * 60 * 60 * 1000 }));
  return `${payload}.${sign(payload, secret)}`;
}

export function verifySessionToken(token: string, secret: string) {
  const [payload, signature] = String(token || "").split(".");
  if (!payload || !signature) return null;
  const expected = sign(payload, secret);
  if (signature.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
  try {
    const decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as { uid?: number; exp?: number };
    if (!decoded.uid || !decoded.exp || decoded.exp < Date.now()) return null;
    return decoded.uid;
  } catch {
    return null;
  }
}

export function parseCookies(header = "") {
  const cookies = new Map<string, string>();
  for (const part of header.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (!key || !rest.length) continue;
    cookies.set(key, decodeURIComponent(rest.join("=")));
  }
  return cookies;
}

export async function loadSessionUser(req: Request, pool: Db, config: AppConfig): Promise<SessionUser | null> {
  const token = parseCookies(req.headers.cookie || "").get(cookieName);
  const userId = token ? verifySessionToken(token, config.sessionSecret) : null;
  if (!userId) return null;
  const result = await pool.query(
    "SELECT id, email, display_name, role FROM wa_users WHERE id = $1 AND is_active = true",
    [userId],
  );
  const row = result.rows[0];
  if (!row) return null;
  return {
    id: Number(row.id),
    email: row.email,
    displayName: row.display_name,
    role: row.role,
  };
}

export async function authenticate(pool: Db, email: string, password: string) {
  const result = await pool.query(
    "SELECT id, email, display_name, role, password_hash FROM wa_users WHERE email = $1 AND is_active = true",
    [email.trim().toLowerCase()],
  );
  const row = result.rows[0];
  if (!row || !row.password_hash) return null;
  const ok = await bcrypt.compare(password, row.password_hash);
  if (!ok) return null;
  await pool.query("UPDATE wa_users SET last_login_at = NOW(), updated_at = NOW() WHERE id = $1", [row.id]);
  return {
    id: Number(row.id),
    email: row.email,
    displayName: row.display_name,
    role: row.role as Role,
  };
}

export function setSessionCookie(res: Response, userId: number, config: AppConfig) {
  const token = createSessionToken(userId, config.sessionSecret);
  const secure = config.nodeEnv === "production" ? "; Secure" : "";
  res.setHeader("Set-Cookie", `${cookieName}=${encodeURIComponent(token)}; Path=${config.basePath || "/"}; HttpOnly; SameSite=Lax; Max-Age=604800${secure}`);
}

export function clearSessionCookie(res: Response, config: AppConfig) {
  res.setHeader("Set-Cookie", `${cookieName}=; Path=${config.basePath || "/"}; HttpOnly; SameSite=Lax; Max-Age=0`);
}

export function canManageUsers(actor: SessionUser, targetRole: Role) {
  if (actor.role === "dev") return true;
  return actor.role === "deanery" && targetRole === "teacher";
}

export function canManageTasks(actor: SessionUser) {
  return actor.role === "dev" || actor.role === "deanery";
}
