import { NextResponse } from "next/server";
import { ACCESS_COOKIE_NAME, getAccessCookiePath } from "@/lib/access";

export async function POST() {
  const response = new NextResponse(null, {
    status: 303,
    headers: {
      Location: getAccessCookiePath(),
    },
  });

  response.cookies.set({
    name: ACCESS_COOKIE_NAME,
    value: "",
    httpOnly: true,
    sameSite: "lax",
    maxAge: 0,
    path: getAccessCookiePath(),
  });

  return response;
}
