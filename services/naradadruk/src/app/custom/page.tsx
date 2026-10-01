import type { Metadata } from "next";
import { PublicFrame } from "@/components/site/public-frame";
import { CustomRequestForm } from "@/components/site/custom-request-form";
import { getSiteSettings, getProductBySlug } from "@/lib/data";
import { absoluteSiteUrl } from "@/lib/site-url";
export const dynamic = "force-dynamic";
export const metadata: Metadata = { title:"Індивідуальний 3D-друк і моделювання",alternates:{canonical:absoluteSiteUrl("/custom")} };
export default async function Page({ searchParams }: { searchParams: Promise<{ mode?: string; product?: string }> }) {
  const query = await searchParams;
  const [settings,product] = await Promise.all([getSiteSettings(),query.product && /^[a-z0-9-]{1,160}$/.test(query.product) ? getProductBySlug(query.product) : null]);
  return <PublicFrame telegramUrl={settings.telegramUrl}><main className="site-container custom-page"><p className="eyebrow">Від задачі до деталі</p><h1>Надрукуємо вашу ідею</h1><p className="custom-page__intro">Готова модель, адаптація виробу або моделювання з нуля. Опишіть задачу — погодимо ціну й термін у Telegram.</p><CustomRequestForm initialMode={query.mode === "model" ? "model" : "file"} productSlug={product?.slug ?? ""} productTitle={product?.title ?? ""} telegramUrl={settings.telegramUrl} /></main></PublicFrame>;
}
