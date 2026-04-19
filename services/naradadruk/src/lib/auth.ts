import { createHmac, timingSafeEqual } from "node:crypto";
import { cookies } from "next/headers";
import { notFound, redirect } from "next/navigation";
import { adminSessionTtlSeconds } from "@/lib/constants";
import { withBasePath } from "@/lib/base-path";

type SessionPayload = {
  exp: number;
  scope: "admin";
};

function isProduction() {
  return process.env.NODE_ENV === "production";
}

function normalizeAdminPath(value?: string) {
  const trimmed = value?.trim().replace(/^\/+|\/+$/g, "");
  return trimmed || "admin";
}

function requireSecretEnv(
  name: string,
  value: string | undefined,
  minimumLength: number,
  fallback: string,
) {
  const normalized = value?.trim();
  const looksLikePlaceholder = Boolean(
    normalized && /^(?:change-me|replace-with|naradadruk-local)/i.test(normalized),
  );

  if (normalized && normalized.length >= minimumLength && !looksLikePlaceholder) {
    return normalized;
  }

  if (!isProduction()) {
    return fallback;
  }

  throw new Error(`${name} must be set to at least ${minimumLength} characters in production.`);
}

function getSessionSecret() {
  return requireSecretEnv(
    "SESSION_SECRET",
    process.env.SESSION_SECRET,
    32,
    "naradadruk-local-session-secret",
  );
}

export function getAdminPath() {
  return normalizeAdminPath(process.env.ADMIN_PATH);
}

export function getAdminPassword() {
  return requireSecretEnv(
    "ADMIN_PASSWORD",
    process.env.ADMIN_PASSWORD,
    12,
    "naradadruk-local-admin",
  );
}

function getAdminCookieName() {
  return isProduction() ? "__Secure-naradadruk-admin" : "naradadruk-admin";
}

export function getAdminRoute(adminPath = getAdminPath()) {
  return `/${normalizeAdminPath(adminPath)}`;
}

function getAdminCookiePath(adminPath = getAdminPath()) {
  return withBasePath(getAdminRoute(adminPath));
}

function encode(input: string | Buffer) {
  return Buffer.from(input).toString("base64url");
}

function sign(value: string) {
  return createHmac("sha256", getSessionSecret()).update(value).digest("base64url");
}

function serializeSession(payload: SessionPayload) {
  const serializedPayload = encode(JSON.stringify(payload));
  const signature = sign(serializedPayload);
  return `${serializedPayload}.${signature}`;
}

function verifySession(token?: string | null) {
  if (!token) {
    return false;
  }

  const [serializedPayload, signature] = token.split(".");

  if (!serializedPayload || !signature) {
    return false;
  }

  const expected = Buffer.from(sign(serializedPayload));
  const received = Buffer.from(signature);

  if (expected.length !== received.length || !timingSafeEqual(expected, received)) {
    return false;
  }

  try {
    const payload = JSON.parse(Buffer.from(serializedPayload, "base64url").toString("utf8")) as SessionPayload;
    return payload.scope === "admin" && payload.exp > Date.now();
  } catch {
    return false;
  }
}

export function assertAdminPath(adminPath: string) {
  if (adminPath !== getAdminPath()) {
    notFound();
  }
}

export async function isAdminAuthenticated() {
  const cookieStore = await cookies();
  return verifySession(cookieStore.get(getAdminCookieName())?.value);
}

export async function requireAdminSession() {
  if (!(await isAdminAuthenticated())) {
    redirect(getAdminRoute());
  }
}

export async function createAdminSession() {
  const cookieStore = await cookies();
  const token = serializeSession({
    exp: Date.now() + adminSessionTtlSeconds * 1000,
    scope: "admin",
  });

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

  cookieStore.set(getAdminCookieName(), "", {
    httpOnly: true,
    sameSite: "strict",
    secure: isProduction(),
    path: getAdminCookiePath(),
    maxAge: 0,
    priority: "high",
  });
}
