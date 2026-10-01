import type { Metadata } from "next";
import { InformationPage } from "@/components/site/information-page";
import { getSiteSettings } from "@/lib/data";
import { absoluteSiteUrl } from "@/lib/site-url";
export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Про майстерню", alternates: { canonical: absoluteSiteUrl("/about") } };
export default async function Page() {
  const settings = await getSiteSettings();
  return <InformationPage title="Про майстерню"><h2>Від ідеї до готового виробу</h2><p>Narada Druk — 3D-друк у Києві з доставкою по Україні. Виготовляємо практичні деталі, аксесуари для сетапу, декор і вироби для страйкболу.</p><h2>Готовий виріб або власна задача</h2><p>Готові позиції замовляйте через каталог. Для друку свого файлу, адаптації або моделювання з нуля залиште індивідуальний запит. Можливість виготовлення, ціну й термін погодимо перед початком.</p><h2>Матеріали та виготовлення</h2><p>{settings.materialsNote}</p><p>{settings.leadTimeNote}</p><p>Приклади наших виробів — у каталозі й галереях товарів.</p></InformationPage>;
}
