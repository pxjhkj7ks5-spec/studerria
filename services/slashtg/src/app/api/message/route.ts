import { NextResponse } from "next/server";
import { getCurrentSession } from "@/lib/api-session";
import { saveMessage } from "@/lib/data";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const session = await getCurrentSession();
  if (!session) {
    return NextResponse.json({ ok: false, error: "not_authenticated" }, { status: 401 });
  }

  let body: { text?: string; animationType?: string } = {};
  try {
    body = (await request.json()) as { text?: string; animationType?: string };
  } catch {
    body = {};
  }

  try {
    return NextResponse.json(await saveMessage(session.keyName, body.text, body.animationType));
  } catch {
    return NextResponse.json({ ok: false, error: "slashtg_unavailable" }, { status: 500 });
  }
}
