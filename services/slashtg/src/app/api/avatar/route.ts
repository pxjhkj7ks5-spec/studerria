import { NextResponse } from "next/server";
import { getCurrentSession } from "@/lib/api-session";
import { saveAvatar } from "@/lib/data";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const session = await getCurrentSession();
  if (!session) {
    return NextResponse.json({ ok: false, error: "not_authenticated" }, { status: 401 });
  }

  let body: { avatarUrl?: string } = {};
  try {
    body = (await request.json()) as { avatarUrl?: string };
  } catch {
    body = {};
  }

  try {
    return NextResponse.json(await saveAvatar(session.keyName, body.avatarUrl));
  } catch (error) {
    if (error instanceof Error && error.message === "invalid_avatar_url") {
      return NextResponse.json({ ok: false, error: "invalid_avatar_url" }, { status: 400 });
    }
    return NextResponse.json({ ok: false, error: "slashtg_unavailable" }, { status: 500 });
  }
}
