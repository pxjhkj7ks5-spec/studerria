import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    await prisma.$queryRaw`SELECT 1`;
    return NextResponse.json({ status: "ok", service: "ykg" }, { headers: { "cache-control": "no-store" } });
  } catch {
    return NextResponse.json({ status: "error", service: "ykg" }, { status: 503, headers: { "cache-control": "no-store" } });
  }
}
