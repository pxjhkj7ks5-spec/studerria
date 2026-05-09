import { cookies } from "next/headers";
import type { NextResponse } from "next/server";
import {
  parseSessionToken,
  slashSessionCookieName,
  slashSessionMaxAgeSeconds,
  type SlashSession,
} from "@/lib/session";

export async function getCurrentSession(): Promise<SlashSession | null> {
  const cookieStore = await cookies();
  return parseSessionToken(cookieStore.get(slashSessionCookieName)?.value);
}

export function setSessionCookie(response: NextResponse, token: string) {
  const isProduction = process.env.NODE_ENV === "production";
  response.cookies.set(slashSessionCookieName, token, {
    httpOnly: true,
    sameSite: isProduction ? "none" : "lax",
    secure: isProduction,
    path: "/",
    maxAge: slashSessionMaxAgeSeconds,
  });
}

export function clearSessionCookie(response: NextResponse) {
  const isProduction = process.env.NODE_ENV === "production";
  response.cookies.set(slashSessionCookieName, "", {
    httpOnly: true,
    sameSite: isProduction ? "none" : "lax",
    secure: isProduction,
    path: "/",
    maxAge: 0,
  });
}
