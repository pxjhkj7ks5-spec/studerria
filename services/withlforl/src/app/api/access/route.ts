import { NextResponse } from "next/server";
import { ACCESS_COOKIE_NAME, createAccessToken, getAccessCookiePath, getAccessPassword } from "@/lib/access";

const COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 30;

export async function POST(request: Request) {
  const configuredPassword = getAccessPassword();
  const contentType = request.headers.get("content-type") ?? "";
  const expectsRedirect = contentType.includes("application/x-www-form-urlencoded") || contentType.includes("multipart/form-data");

  if (!configuredPassword) {
    if (expectsRedirect) {
      return redirectWithStatus(request, "denied");
    }

    return NextResponse.json({ ok: false, error: "not_configured" }, { status: 503 });
  }

  let password = "";

  try {
    if (expectsRedirect) {
      const body = await request.formData();
      const value = body.get("password");
      password = typeof value === "string" ? value.trim() : "";
    } else {
      const body = (await request.json()) as { password?: unknown };
      password = typeof body.password === "string" ? body.password.trim() : "";
    }
  } catch {
    if (expectsRedirect) {
      return redirectWithStatus(request, "denied");
    }

    return NextResponse.json({ ok: false, error: "invalid_request" }, { status: 400 });
  }

  if (password !== configuredPassword) {
    if (expectsRedirect) {
      return redirectWithStatus(request, "denied");
    }

    return NextResponse.json({ ok: false, error: "denied" }, { status: 401 });
  }

  const response = expectsRedirect ? NextResponse.redirect(new URL(getAccessCookiePath(), request.url), 303) : NextResponse.json({ ok: true });
  response.cookies.set({
    name: ACCESS_COOKIE_NAME,
    value: createAccessToken(configuredPassword),
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: COOKIE_MAX_AGE_SECONDS,
    path: getAccessCookiePath(),
  });

  return response;
}

function redirectWithStatus(request: Request, status: "denied") {
  const url = new URL(getAccessCookiePath(), request.url);
  url.searchParams.set(status, "1");
  return NextResponse.redirect(url, 303);
}
