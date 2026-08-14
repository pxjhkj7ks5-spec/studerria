import { readUploadFile, contentTypeForUpload, isSafeUploadFileName } from "@/lib/storage";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type UploadRouteProps = {
  params: Promise<{
    fileName: string;
  }>;
};

export async function GET(_request: Request, { params }: UploadRouteProps) {
  const { fileName } = await params;

  if (!isSafeUploadFileName(fileName)) {
    return new Response("Not found", { status: 404 });
  }

  try {
    const file = await readUploadFile(fileName);
    return new Response(file, {
      status: 200,
      headers: {
        "Content-Type": contentTypeForUpload(fileName),
        "Cache-Control": "public, max-age=31536000, immutable",
      },
    });
  } catch {
    return new Response("Not found", { status: 404 });
  }
}
