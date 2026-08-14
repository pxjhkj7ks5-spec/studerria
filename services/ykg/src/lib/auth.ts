import { createHash, createHmac, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import type { StaffRole } from "@prisma/client";
import { cookies } from "next/headers";
import { notFound, redirect } from "next/navigation";
import { adminSessionTtlSeconds } from "@/lib/constants";
import { withBasePath } from "@/lib/base-path";
import { prisma } from "@/lib/prisma";

export type StaffIdentity = {
  id: number;
  username: string;
  displayName: string;
  role: StaffRole;
  telegramUserId: string | null;
};

function isProduction() {
  return process.env.NODE_ENV === "production";
}

function normalizeAdminPath(value?: string) {
  const trimmed = value?.trim().replace(/^\/+|\/+$/g, "");
  return trimmed || "admin";
}

function requireSecretEnv(name: string, value: string | undefined, minimumLength: number, fallback: string) {
  const normalized = value?.trim();
  const placeholder = Boolean(normalized && /^(?:change-me|replace-with|ykg-local)/i.test(normalized));
  if (normalized && normalized.length >= minimumLength && !placeholder) return normalized;
  if (!isProduction()) return fallback;
  throw new Error(`${name} must be set to at least ${minimumLength} characters in production.`);
}

function getSessionSecret() {
  return requireSecretEnv("YKG_SESSION_SECRET", process.env.YKG_SESSION_SECRET, 32, "ykg-local-session-secret-for-development");
}

export function getBootstrapToken() {
  return requireSecretEnv("YKG_BOOTSTRAP_TOKEN", process.env.YKG_BOOTSTRAP_TOKEN, 24, "ykg-local-bootstrap-token");
}

export function getAdminPath() {
  return normalizeAdminPath(process.env.ADMIN_PATH);
}

function getAdminCookieName() {
  return isProduction() ? "__Secure-ykg-staff" : "ykg-staff";
}

export function getAdminRoute(adminPath = getAdminPath()) {
  return `/${normalizeAdminPath(adminPath)}`;
}

function getAdminCookiePath(adminPath = getAdminPath()) {
  return withBasePath(getAdminRoute(adminPath));
}

function hashToken(token: string) {
  return createHash("sha256").update(token).digest("base64url");
}

export function createPrivacyHash(namespace: string, value: string) {
  return createHmac("sha256", getSessionSecret()).update(`${namespace}\0${value}`).digest("base64url");
}

export function hashPassword(password: string) {
  const salt = randomBytes(16).toString("base64url");
  const hash = scryptSync(password, salt, 64).toString("base64url");
  return `scrypt$${salt}$${hash}`;
}

export function verifyPassword(password: string, encoded: string) {
  const [algorithm, salt, expectedValue] = encoded.split("$");
  if (algorithm !== "scrypt" || !salt || !expectedValue) return false;
  const expected = Buffer.from(expectedValue, "base64url");
  const actual = scryptSync(password, salt, expected.length);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

export function compareSecret(left: string, right: string) {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

export function assertAdminPath(adminPath: string) {
  if (adminPath !== getAdminPath()) notFound();
}

export async function getStaffSession(): Promise<StaffIdentity | null> {
  const cookieStore = await cookies();
  const token = cookieStore.get(getAdminCookieName())?.value;
  if (!token) return null;
  const session = await prisma.staffSession.findUnique({
    where: { tokenHash: hashToken(token) },
    include: { user: true },
  });
  if (!session || session.expiresAt <= new Date() || !session.user.isActive) {
    if (session) await prisma.staffSession.delete({ where: { id: session.id } }).catch(() => undefined);
    return null;
  }
  return {
    id: session.user.id,
    username: session.user.username,
    displayName: session.user.displayName,
    role: session.user.role,
    telegramUserId: session.user.telegramUserId,
  };
}

export async function isAdminAuthenticated() {
  return Boolean(await getStaffSession());
}

export async function requireAdminSession(requiredRole?: StaffRole) {
  const staff = await getStaffSession();
  if (!staff) redirect(getAdminRoute());
  if (requiredRole === "owner" && staff.role !== "owner") notFound();
  return staff;
}

export async function createAdminSession(userId: number) {
  const cookieStore = await cookies();
  const token = randomBytes(32).toString("base64url");
  const expiresAt = new Date(Date.now() + adminSessionTtlSeconds * 1000);
  await prisma.$transaction([
    prisma.staffSession.create({ data: { tokenHash: hashToken(token), userId, expiresAt } }),
    prisma.staffSession.deleteMany({ where: { expiresAt: { lte: new Date() } } }),
  ]);
  cookieStore.set(getAdminCookieName(), token, {
    httpOnly: true,
    sameSite: "strict",
    secure: isProduction(),
    path: getAdminCookiePath(),
    maxAge: adminSessionTtlSeconds,
    priority: "high",
  });
}

export async function clearAdminSession() {
  const cookieStore = await cookies();
  const token = cookieStore.get(getAdminCookieName())?.value;
  if (token) await prisma.staffSession.deleteMany({ where: { tokenHash: hashToken(token) } });
  cookieStore.set(getAdminCookieName(), "", {
    httpOnly: true,
    sameSite: "strict",
    secure: isProduction(),
    path: getAdminCookiePath(),
    maxAge: 0,
    priority: "high",
  });
}
