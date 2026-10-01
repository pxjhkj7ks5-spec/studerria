import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { POST } from "../src/app/api/custom-requests/route";
import { prisma } from "../src/lib/prisma";
import { deliverCustomRequestNotification } from "../src/lib/custom-request-notification";
import { trustedClientIpHeader } from "../src/lib/analytics-ip";
import { readPrivateAttachment } from "../src/lib/custom-request-storage";

async function main() {
  assert.match(process.env.DATABASE_URL ?? "", /(?:\.next|\.data)\/audit\/storefront\.db$/);
  assert.match(process.env.UPLOAD_DIR ?? "", /Temp\/narada-printparadise-uploads$/);
  const originalFetch = globalThis.fetch;
  const before = await Promise.all([prisma.product.count(),prisma.order.count(),prisma.review.count(),prisma.category.count()]);
  const ip = `203.0.113.${Math.floor(Math.random()*200)+1}`;
  const key = randomUUID();
  function form(submissionKey = key, description = "Тестова підставка для локальної перевірки", attachment = true) {
    const data = new FormData();
    for (const [name,value] of Object.entries({submissionKey,mode:attachment ? "file" : "model",name:"Тест",telegramContact:"@local_test",description,quantity:"2",analyticsSessionId:randomUUID()})) data.set(name,value);
    if (attachment) data.append("files",new Blob(["solid sample\nendsolid sample"],{type:"application/octet-stream"}),"part.stl");
    return data;
  }
  async function submit(data:FormData) { return POST(new Request("http://localhost:3095/naradadruk/api/custom-requests",{method:"POST",headers:{[trustedClientIpHeader]:ip},body:data})); }
  const first = await submit(form()); assert.equal(first.status,201);
  const receipt = await first.json();
  const saved = await prisma.customRequest.findUniqueOrThrow({where:{publicId:receipt.publicId},include:{attachments:true}});
  assert.equal(saved.attachments.length,1);
  assert.equal(saved.notificationStatus,"skipped");
  assert.equal((await readPrivateAttachment(saved.attachments[0].fileName)).toString(),"solid sample\nendsolid sample");
  const repeat = await submit(form()); assert.equal(repeat.status,200); assert.equal((await repeat.json()).publicId,receipt.publicId);
  assert.equal((await submit(form(key,"Змінений опис тієї самої заявки"))).status,409);
  const invalid = form(randomUUID()); invalid.set("files",new Blob(["bad"]),"part.png"); assert.equal((await submit(invalid)).status,400);
  const missing = form(randomUUID(),"Заявка без файлу для перевірки",false); missing.set("mode","file"); assert.equal((await submit(missing)).status,400);
  const large = form(randomUUID()); large.set("files",new Blob([new Uint8Array(10*1024*1024+1)]),"part.stl"); assert.equal((await submit(large)).status,413);
  const five = form(randomUUID()); for(let i=1;i<5;i++) five.append("files",new Blob(["solid s\nendsolid s"]),`${i}.stl`); assert.equal((await submit(five)).status,400);
  const model = await submit(form(randomUUID(),"Моделювання нової підставки без готового файлу",false)); assert.equal(model.status,201);
  // Stub Telegram transport in this process; no real message is sent.
  process.env.NARADADRUK_ORDER_TELEGRAM_BOT_TOKEN = "test-token";
  process.env.NARADADRUK_ORDER_TELEGRAM_CHAT_ID = "123";
  globalThis.fetch = async () => new Response("{}",{status:503});
  await deliverCustomRequestNotification(receipt.publicId);
  assert.equal((await prisma.customRequest.findUniqueOrThrow({where:{publicId:receipt.publicId}})).notificationStatus,"failed");
  let sent = 0;
  globalThis.fetch = async () => { sent++; await new Promise(resolve=>setTimeout(resolve,30)); return Response.json({ok:true}); };
  await Promise.all([deliverCustomRequestNotification(receipt.publicId),deliverCustomRequestNotification(receipt.publicId)]);
  assert.equal(sent,1);
  assert.equal((await prisma.customRequest.findUniqueOrThrow({where:{publicId:receipt.publicId}})).notificationStatus,"sent");
  delete process.env.NARADADRUK_ORDER_TELEGRAM_BOT_TOKEN;
  delete process.env.NARADADRUK_ORDER_TELEGRAM_CHAT_ID;
  globalThis.fetch = originalFetch;
  const attachmentUrl = `http://localhost:3095/naradadruk/admin/custom-requests/${receipt.publicId}/attachments/${saved.attachments[0].id}`;
  assert.equal((await fetch(attachmentUrl)).status,401);
  assert.equal((await fetch(`http://localhost:3095/naradadruk/uploads/${saved.attachments[0].fileName}`)).status,404);
  for(let i=0;i<3;i++) assert.equal((await submit(form(randomUUID(),`Ще одна локальна задача ${i}`,false))).status,201);
  assert.equal((await submit(form(randomUUID(),"Шоста локальна задача перевищує ліміт",false))).status,429);
  const after = await Promise.all([prisma.product.count(),prisma.order.count(),prisma.review.count(),prisma.category.count()]);
  assert.deepEqual(after,before);
  console.info("PASS: persistence, duplicates, validation, limits, Telegram failure/retry, private attachments, preserved commerce data.");
}
main().catch(error=>{console.error(error);process.exitCode=1;}).finally(()=>prisma.$disconnect());
