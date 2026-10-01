import { NextResponse } from "next/server";
import { getAdminPath, isAdminAuthenticated } from "@/lib/auth";
import { prisma } from "@/lib/prisma";
import { readPrivateAttachment } from "@/lib/custom-request-storage";

export const runtime = "nodejs";
export async function GET(_request: Request, { params }: { params: Promise<{adminPath:string;publicId:string;attachmentId:string}> }) {
  const input = await params;
  const headers = {"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff","X-Robots-Tag":"noindex, nofollow"};
  if (input.adminPath !== getAdminPath()) return new NextResponse(null,{status:404,headers});
  if (!(await isAdminAuthenticated())) return new NextResponse(null,{status:401,headers});
  if (!/^\d+$/.test(input.attachmentId)) return new NextResponse(null,{status:404,headers});
  const attachment = await prisma.customRequestAttachment.findFirst({where:{id:Number(input.attachmentId),request:{publicId:input.publicId}}});
  if (!attachment) return new NextResponse(null,{status:404,headers});
  try {
    const bytes = await readPrivateAttachment(attachment.fileName);
    return new NextResponse(new Uint8Array(bytes),{headers:{...headers,"Content-Type":"application/octet-stream","Content-Disposition":`attachment; filename="attachment"; filename*=UTF-8''${encodeURIComponent(attachment.originalName).replace(/'/g,"%27")}`}});
  } catch { return NextResponse.json({error:"Файл недоступний. Перевірте постійне сховище."},{status:404,headers}); }
}
