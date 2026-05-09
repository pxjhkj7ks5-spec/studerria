import { NextResponse } from "next/server";
import { getCurrentSession } from "@/lib/api-session";
import { buildState } from "@/lib/data";

export const dynamic = "force-dynamic";

export async function GET() {
  const session = await getCurrentSession();
  if (!session) {
    return NextResponse.json({ ok: false, error: "not_authenticated" }, { status: 401 });
  }

  try {
    return NextResponse.json(await buildState(session.keyName));
  } catch {
    return NextResponse.json({ ok: false, error: "slashtg_unavailable" }, { status: 500 });
  }
}
