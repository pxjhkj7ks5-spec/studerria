import { createHmac, timingSafeEqual } from "node:crypto";

export const ACCESS_COOKIE_NAME = "withlforl_access";

const TOKEN_MESSAGE = "withlforl-access-v1";

export function getAccessPassword() {
  return process.env.WITHLFORL_PASSWORD?.trim() ?? "";
}

export function getAccessCookiePath() {
  const basePath = process.env.NEXT_PUBLIC_BASE_PATH?.trim() ?? "/withlforl";
  if (!basePath || basePath === "/") {
    return "/";
  }

  return basePath.startsWith("/") ? basePath.replace(/\/+$/, "") : `/${basePath.replace(/\/+$/, "")}`;
}

export function createAccessToken(password: string) {
  return createHmac("sha256", password).update(TOKEN_MESSAGE).digest("base64url");
}

export function isValidAccessToken(token: string | undefined, password = getAccessPassword()) {
  if (!token || !password) {
    return false;
  }

  const expected = createAccessToken(password);
  const tokenBuffer = Buffer.from(token);
  const expectedBuffer = Buffer.from(expected);

  if (tokenBuffer.length !== expectedBuffer.length) {
    return false;
  }

  return timingSafeEqual(tokenBuffer, expectedBuffer);
}
