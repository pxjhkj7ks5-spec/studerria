import type { Metadata } from "next";
import { InformationPage } from "@/components/site/information-page";
import { getSiteSettings } from "@/lib/data";
import { absoluteSiteUrl } from "@/lib/site-url";
export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Індивідуальний виріб", alternates: { canonical: absoluteSiteUrl("/custom") } };
export default async function Page() {
  const settings = await getSiteSettings();
  return <InformationPage title="Індивідуальний виріб"><h2>Друк вашого файлу</h2><p>Надішліть STL, 3MF або OBJ, кількість і бажані розміри. Оцінимо задачу й погодимо матеріал, ціну та строк перед виготовленням.</p><h2>Потрібна 3D-модель?</h2><p>Опишіть ідею, додайте фото або ескіз. Обговоримо моделювання з нуля або адаптацію деталі під вашу задачу.</p><p><a className="ghost-pill" href={settings.telegramUrl} target="_blank" rel="noreferrer">Описати задачу в Telegram</a></p></InformationPage>;
}
