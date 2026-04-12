import { readFile } from "node:fs/promises";
import path from "node:path";
import { NextResponse } from "next/server";
import {
  contentTypeForUpload,
  isSafeUploadFileName,
  resolveUploadDir,
} from "@/lib/storage";

export const dynamic = "force-dynamic";

type UploadRouteProps = {
  params: Promise<{
    fileName: string;
  }>;
};

export async function GET(_request: Request, { params }: UploadRouteProps) {
  const { fileName } = await params;

  if (!isSafeUploadFileName(fileName)) {
    return new NextResponse("Not found", {
      status: 404,
      headers: {
        "Cache-Control": "no-store",
      },
    });
  }

  try {
    const filePath = path.join(resolveUploadDir(), fileName);
    const file = await readFile(filePath);

    return new NextResponse(file, {
      headers: {
        "Cache-Control": "public, max-age=31536000, immutable",
        "Content-Type": contentTypeForUpload(fileName),
        "X-Content-Type-Options": "nosniff",
      },
    });
  } catch {
    return new NextResponse("Not found", {
      status: 404,
      headers: {
        "Cache-Control": "no-store",
      },
    });
  }
}
