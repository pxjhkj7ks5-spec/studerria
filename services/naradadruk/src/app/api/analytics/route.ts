import { NextResponse } from "next/server";
import { z } from "zod";
import { analyticsEventNames } from "@/lib/analytics";
import { prisma } from "@/lib/prisma";

export const dynamic = "force-dynamic";

const analyticsPayloadSchema = z.object({
  name: z.enum(analyticsEventNames),
  path: z.string().trim().max(240).default(""),
  sessionId: z.string().trim().max(80).default(""),
  props: z
    .object({
      location: z.string().trim().max(80).optional(),
      intent: z.enum(["product", "custom", "catalog"]).optional(),
      product_slug: z.string().trim().max(120).optional(),
      category: z.string().trim().max(120).optional(),
    })
    .optional(),
});

export async function POST(request: Request) {
  const fetchSite = request.headers.get("sec-fetch-site");
  const contentLength = Number(request.headers.get("content-length") ?? 0);

  if (fetchSite && !["same-origin", "same-site", "none"].includes(fetchSite)) {
    return NextResponse.json({ ok: false }, { status: 403 });
  }

  if (Number.isFinite(contentLength) && contentLength > 4_096) {
    return NextResponse.json({ ok: false }, { status: 413 });
  }

  try {
    const parsed = analyticsPayloadSchema.safeParse(await request.json());

    if (!parsed.success) {
      return NextResponse.json({ ok: false }, { status: 400 });
    }

    const event = await prisma.analyticsEvent.create({
      data: {
        name: parsed.data.name,
        path: parsed.data.path,
        sessionId: parsed.data.sessionId,
        location: parsed.data.props?.location ?? "",
        intent: parsed.data.props?.intent ?? "",
        productSlug: parsed.data.props?.product_slug ?? "",
        category: parsed.data.props?.category ?? "",
      },
    });

    if (event.id % 250 === 0) {
      await prisma.analyticsEvent.deleteMany({
        where: {
          createdAt: {
            lt: new Date(Date.now() - 400 * 24 * 60 * 60 * 1000),
          },
        },
      });
    }

    return new NextResponse(null, {
      status: 204,
      headers: {
        "Cache-Control": "no-store",
      },
    });
  } catch {
    return NextResponse.json({ ok: false }, { status: 400 });
  }
}
