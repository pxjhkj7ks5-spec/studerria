import type { Metadata } from "next";
import { InformationPage } from "@/components/site/information-page";
import { getSiteSettings } from "@/lib/data";
import { absoluteSiteUrl } from "@/lib/site-url";
export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Контакти", alternates: { canonical: absoluteSiteUrl("/contacts") } };
export default async function Page() {
  const settings = await getSiteSettings();
  return <InformationPage title="Контакти"><h2>Напишіть нам у Telegram</h2><p>{settings.contactNote}</p><p><a href={settings.telegramUrl} target="_blank" rel="noreferrer">Відкрити Telegram Narada Druk</a></p><h2>Де ми працюємо</h2><p>Київ. Доставляємо по Україні; час і місце самовивозу погоджуємо особисто.</p><h2>Щоб швидше розібратися із задачею</h2><p>Надішліть модель, фото або ескіз, бажані розміри та кількість. Для запитання про готове замовлення вкажіть його номер.</p></InformationPage>;
}
