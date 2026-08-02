import { NextResponse } from "next/server";
import { searchWarehouses } from "@/lib/nova-poshta";

export async function GET(request: Request) {
  const params = new URL(request.url).searchParams;
  const cityRef = params.get("cityRef")?.slice(0, 100) || "";
  const query = params.get("q")?.slice(0, 100) || "";
  const method = params.get("method") === "parcel_locker" ? "parcel_locker" : "branch";
  try {
    return NextResponse.json(await searchWarehouses(cityRef, query, method));
  } catch {
    return NextResponse.json({ configured: true, options: [], unavailable: true });
  }
}

