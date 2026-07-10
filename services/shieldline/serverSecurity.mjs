import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";

function signature(secret, payload) {
  return createHmac("sha256", secret).update(payload).digest("base64url");
}

function safeEqual(left, right) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

export function createSessionCodec({ secret, basePath = "/", secure = false, ttlSeconds = 2_592_000, now = () => Date.now() }) {
  if (!secret || String(secret).length < 24) throw new Error("SHIELDLINE_SESSION_SECRET must contain at least 24 characters.");
  const cookiePath = basePath || "/";

  function issue(actorId) {
    const payload = Buffer.from(JSON.stringify({ actorId, expiresAt: now() + ttlSeconds * 1000, nonce: randomUUID() })).toString("base64url");
    return `${payload}.${signature(secret, payload)}`;
  }

  function verify(value) {
    const [payload, supplied, ...rest] = String(value || "").split(".");
    if (!payload || !supplied || rest.length || !safeEqual(signature(secret, payload), supplied)) return null;
    try {
      const session = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
      if (typeof session.actorId !== "string" || session.actorId.length > 96 || Number(session.expiresAt) <= now()) return null;
      return session.actorId;
    } catch {
      return null;
    }
  }

  function header(actorId) {
    return `shieldline_sid=${issue(actorId)}; Path=${cookiePath}; HttpOnly; SameSite=Lax; Max-Age=${ttlSeconds}${secure ? "; Secure" : ""}`;
  }

  function clearHeader() {
    return `shieldline_sid=; Path=${cookiePath}; HttpOnly; SameSite=Lax; Max-Age=0${secure ? "; Secure" : ""}`;
  }

  return { issue, verify, header, clearHeader };
}

export function readCookie(cookieHeader, name) {
  for (const segment of String(cookieHeader || "").split(";")) {
    const [key, ...parts] = segment.trim().split("=");
    if (key === name) return parts.join("=");
  }
  return "";
}

export function createFixedWindowRateLimiter({ limit = 180, windowMs = 60_000, now = () => Date.now() } = {}) {
  const entries = new Map();
  return {
    allow(key) {
      const current = now();
      const existing = entries.get(key);
      if (!existing || existing.resetAt <= current) {
        entries.set(key, { count: 1, resetAt: current + windowMs });
        return true;
      }
      existing.count += 1;
      return existing.count <= limit;
    },
  };
}

export function hashSessionToken(token) {
  return createHash("sha256").update(String(token)).digest("hex");
}

export function createPersistentSessionCodec({ repository, basePath = "/", secure = false, ttlSeconds = 2_592_000, rotationSeconds = 86_400, now = () => Date.now(), generateToken = () => randomBytes(32).toString("base64url") }) {
  const cookiePath = basePath || "/";
  const headerFor = (token, maxAge = ttlSeconds) => `shieldline_sid=${token}; Path=${cookiePath}; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure ? "; Secure" : ""}`;
  return {
    async issue(actorId) {
      const token = generateToken();
      const expiresAt = new Date(now() + ttlSeconds * 1000).toISOString();
      await repository.createSession(hashSessionToken(token), actorId, expiresAt);
      return { actorId, token, header: headerFor(token), expiresAt };
    },
    async verify(token) {
      if (!/^[A-Za-z0-9_-]{32,128}$/.test(String(token || ""))) return null;
      const tokenHash = hashSessionToken(token);
      const session = await repository.findSession(tokenHash);
      if (!session || new Date(session.expiresAt).getTime() <= now()) return null;
      const rotatedAt = new Date(session.rotatedAt || 0).getTime();
      if (now() - rotatedAt >= rotationSeconds * 1000) {
        const replacement = await this.issue(session.actorId);
        await repository.revokeSession(tokenHash);
        return { actorId: session.actorId, replacementHeader: replacement.header };
      }
      return { actorId: session.actorId, replacementHeader: null };
    },
    async revoke(token) {
      if (/^[A-Za-z0-9_-]{32,128}$/.test(String(token || ""))) await repository.revokeSession(hashSessionToken(token));
    },
    clearHeader() {
      return headerFor("", 0);
    },
  };
}
