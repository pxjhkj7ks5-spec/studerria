import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { customRequestSchema, customRequestContentHash, validateAttachment } from "../src/lib/custom-request-validation";
import { buildCustomRequestReport } from "../src/lib/custom-request-report";

const input = { submissionKey:randomUUID(),mode:"model",name:"Олена",telegramContact:"@test_print",description:"Потрібна підставка під пристрій",quantity:1,budget:"",phone:"",modelUrl:"" };
test("custom request validates both contact channels, optional fields, and external URL schemes", () => {
  const parsed = customRequestSchema.parse(input);
  assert.equal(parsed.budget,null);
  assert.equal(customRequestSchema.safeParse({...input,telegramContact:"+380671234567"}).success,true);
  assert.equal(customRequestSchema.safeParse({...input,telegramContact:"----------"}).success,false);
  assert.equal(customRequestSchema.safeParse({...input,phone:"123------"}).success,false);
  for (const patch of [{quantity:0},{quantity:1.5},{budget:"no"},{telegramContact:"x"},{modelUrl:"javascript:alert(1)"},{modelUrl:"https://user:password@example.com"}]) assert.equal(customRequestSchema.safeParse({...input,...patch}).success,false);
});
test("duplicate content hash is independent of retry key and file order", () => {
  const parsed = customRequestSchema.parse(input);
  assert.equal(customRequestContentHash(parsed,["a","b"]),customRequestContentHash({...parsed,submissionKey:randomUUID()},["b","a"]));
  assert.notEqual(customRequestContentHash(parsed,[]),customRequestContentHash({...parsed,quantity:2},[]));
});
test("attachments reject empty, disguised, malformed and unsupported files", () => {
  assert.equal(validateAttachment("part.stl",Buffer.from("solid sample\nendsolid sample")).extension,"stl");
  const binary = Buffer.alloc(84); binary.writeUInt32LE(0,80);
  assert.equal(validateAttachment("part.stl",binary).extension,"stl");
  assert.equal(validateAttachment("part.obj",Buffer.from("v 0 0 0\nv 0 1 0\n")).extension,"obj");
  assert.equal(validateAttachment("part.pdf",Buffer.from("%PDF-1.7 test")).mimeType,"application/pdf");
  for (const [name,bytes] of [["part.exe",Buffer.from("bad")],["part.png",Buffer.from("<script>bad</script>")],["part.stl",Buffer.from("bad")],["part.obj",Buffer.from("text")],["part.3mf",Buffer.from("bad")],["part.pdf",Buffer.alloc(0)]] as const) assert.throws(()=>validateAttachment(name,bytes));
  assert.equal(validateAttachment("../part.pdf",Buffer.from("%PDF-1.7 test")).originalName,".._part.pdf");
});
test("14-day report separates periods, sessions and successful persistence", () => {
  const now = new Date("2026-10-01T12:00:00Z");
  const events = [
    {name:"Custom Request Open",sessionId:"session-a",createdAt:new Date("2026-09-30")},
    {name:"Custom Request Start",sessionId:"session-a",createdAt:new Date("2026-09-30")},
    {name:"Custom Request Start",sessionId:"session-a",createdAt:new Date("2026-09-30")},
    {name:"Custom Request Submitted",sessionId:"session-a",createdAt:new Date("2026-09-30")},
    {name:"Custom Request Open",sessionId:"session-b",createdAt:new Date("2026-09-10")},
    {name:"Custom Request Submitted",sessionId:"old",createdAt:new Date("2026-08-01")},
  ];
  const report = buildCustomRequestReport(events,now);
  assert.deepEqual(report.current,{opens:1,starts:1,submissions:1,completionRate:100});
  assert.deepEqual(report.previous,{opens:1,starts:0,submissions:0,completionRate:null});
  assert.equal(JSON.stringify(report).includes("session-a"),false);
  const extra = buildCustomRequestReport([...events,{name:"Custom Request Submitted",sessionId:"without-start",createdAt:new Date("2026-09-30")}],now);
  assert.equal(extra.current.submissions,2);
  assert.equal(extra.current.completionRate,100);
});
