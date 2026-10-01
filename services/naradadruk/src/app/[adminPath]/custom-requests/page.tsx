import { notFound } from "next/navigation";
import { prisma } from "@/lib/prisma";
import { assertAdminPath, getAdminRoute, requireAdminSession } from "@/lib/auth";
import { withBasePath } from "@/lib/base-path";
import { customRequestStatuses } from "@/lib/custom-request-validation";
import { buildCustomRequestReport } from "@/lib/custom-request-report";

export const dynamic = "force-dynamic";
export default async function Page({params,searchParams}:{params:Promise<{adminPath:string}>;searchParams:Promise<{status?:string}>}) {
  await requireAdminSession(); assertAdminPath((await params).adminPath);
  const query = await searchParams;
  if (query.status && !Object.hasOwn(customRequestStatuses,query.status)) notFound();
  const status = query.status as keyof typeof customRequestStatuses | undefined;
  const now = new Date();
  const [requests, events] = await Promise.all([
    prisma.customRequest.findMany({where:status ? {status} : {},include:{_count:{select:{attachments:true}}},orderBy:{createdAt:"desc"},take:200}),
    prisma.analyticsEvent.findMany({where:{name:{in:["Custom Request Open","Custom Request Start","Custom Request Submitted"]},createdAt:{gte:new Date(now.getTime()-28*86_400_000)}},select:{name:true,sessionId:true,createdAt:true}}),
  ]);
  const report = buildCustomRequestReport(events, now);
  const path = `${getAdminRoute()}/custom-requests`;
  return <main className="mx-auto max-w-[1200px] px-4 py-8"><a className="ghost-pill" href={withBasePath(getAdminRoute())}>До огляду</a><h1 className="my-6 text-3xl">Індивідуальні заявки</h1><section className="grid gap-4 md:grid-cols-2">{[["Останні 14 днів",report.current],["Попередні 14 днів",report.previous]].map(([title,period]) => { const data = period as typeof report.current; return <article key={String(title)} className="glass-panel rounded-2xl p-5"><h2>{String(title)}</h2><p>Відкриття: {data.opens} · початки: {data.starts} · успішне надсилання: {data.submissions}</p><p>Завершення заявки: {data.completionRate === null ? "Недостатньо даних" : `${data.completionRate}%`}</p></article>; })}</section><p className="mt-3 text-sm">Рахуємо сесії з подіями; без ідентифікатора — окремі події. Конверсія враховує лише сесії з початком і наступним збереженням у цьому періоді. Невеликі вибірки не підтверджують зміну конверсії.</p><nav className="my-6 flex flex-wrap gap-2" aria-label="Статуси заявок"><a className="ghost-pill" href={withBasePath(path)}>Усі</a>{Object.entries(customRequestStatuses).map(([value,label]) => <a className={value === status ? "accent-pill" : "ghost-pill"} href={withBasePath(`${path}?status=${value}`)} key={value}>{label}</a>)}</nav><p>До 200 останніх заявок.</p><div className="mt-4 grid gap-3">{requests.length ? requests.map((request) => <article className="glass-panel rounded-2xl p-5" key={request.id}><a className="underline" href={withBasePath(`${path}/${request.publicId}`)}>{request.publicId} · {request.name}</a><p>{customRequestStatuses[request.status]} · {request.mode === "file" ? "Друк файлу" : "Моделювання"} · {request.quantity} шт. · вкладень: {request._count.attachments}</p><p>{new Intl.DateTimeFormat("uk-UA",{dateStyle:"medium",timeStyle:"short",timeZone:"Europe/Kyiv"}).format(request.createdAt)}</p></article>) : <p>Заявок із цим статусом ще немає.</p>}</div></main>;
}
