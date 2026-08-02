import { NextResponse } from "next/server";
import { searchCities } from "@/lib/nova-poshta";

export async function GET(request: Request) {
  const query = new URL(request.url).searchParams.get("q")?.slice(0, 100) || "";
  try {
    return NextResponse.json(await searchCities(query));
  } catch {
    return NextResponse.json({ configured: true, options: [], unavailable: true });
  }
}

