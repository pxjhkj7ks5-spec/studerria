import { NextResponse } from "next/server";
import { findAllowedUserByTelegramId, normalizeTelegramId } from "@/lib/config";
import { buildState, syncTelegramProfile } from "@/lib/data";
import { clearSessionCookie, getCurrentSession, setSessionCookie } from "@/lib/api-session";
import { createSessionToken } from "@/lib/session";
import { validateTelegramInitData, type TelegramUser } from "@/lib/telegram-auth";

export const dynamic = "force-dynamic";

type SessionBody = {
  initData?: string;
  devTelegramUserId?: string;
};

function initDataMaxAgeSeconds() {
  const parsed = Number(process.env.SLASHTG_INIT_DATA_MAX_AGE_SECONDS || 86400);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 86400;
}

function isDevelopmentMockAllowed() {
  return process.env.NODE_ENV !== "production";
}

async function createAuthenticatedResponse(telegramUser: TelegramUser) {
  const profile = await syncTelegramProfile(telegramUser);
  const state = await buildState(profile.keyName as "userA" | "userB");
  const response = NextResponse.json(state);
  setSessionCookie(
    response,
    createSessionToken({
      keyName: profile.keyName as "userA" | "userB",
      telegramId: String(telegramUser.id),
      issuedAt: Math.floor(Date.now() / 1000),
    }),
  );
  return response;
}

export async function GET() {
  const session = await getCurrentSession();
  if (!session) {
    return NextResponse.json({ ok: true, authenticated: false });
  }

  try {
    return NextResponse.json(await buildState(session.keyName));
  } catch {
    const response = NextResponse.json({ ok: true, authenticated: false });
    clearSessionCookie(response);
    return response;
  }
}

export async function POST(request: Request) {
  let body: SessionBody = {};
  try {
    body = (await request.json()) as SessionBody;
  } catch {
    body = {};
  }

  const initData = String(body.initData || "").trim();
  if (initData) {
    try {
      const validated = validateTelegramInitData(initData, {
        botToken: process.env.SLASHTG_BOT_TOKEN || "",
        maxAgeSeconds: initDataMaxAgeSeconds(),
      });
      return createAuthenticatedResponse(validated.user);
    } catch {
      return NextResponse.json({ ok: false, error: "telegram_auth_failed" }, { status: 401 });
    }
  }

  const devTelegramUserId = normalizeTelegramId(
    body.devTelegramUserId || process.env.SLASHTG_DEV_TELEGRAM_USER_ID,
  );
  const allowedDevUser = findAllowedUserByTelegramId(devTelegramUserId);
  if (isDevelopmentMockAllowed() && allowedDevUser) {
    return createAuthenticatedResponse({
      id: allowedDevUser.telegramId,
      first_name: allowedDevUser.label,
      username: "slash_tg_dev",
    });
  }

  return NextResponse.json({ ok: false, error: "telegram_auth_required" }, { status: 401 });
}

export async function DELETE() {
  const response = NextResponse.json({ ok: true, authenticated: false });
  clearSessionCookie(response);
  return response;
}
