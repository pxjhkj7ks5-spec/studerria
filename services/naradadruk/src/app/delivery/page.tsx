import type { Metadata } from "next";
import { InformationPage } from "@/components/site/information-page";
import { getSiteSettings } from "@/lib/data";
import { absoluteSiteUrl } from "@/lib/site-url";
export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Доставка, оплата й повернення", alternates: { canonical: absoluteSiteUrl("/delivery") } };
export default async function Page() {
  const settings = await getSiteSettings();
  return <InformationPage title="Доставка, оплата й повернення"><h2>Як отримати замовлення</h2><p>{settings.deliveryNote}</p><p>У кошику доступні відділення, поштомат і кур’єр Нової пошти. Вартість доставки визначає перевізник; вона не включена до вартості виробів. Самовивіз у Києві погоджуємо в Telegram.</p><h2>Виготовлення</h2><p>{settings.leadTimeNote}</p><p>Термін конкретного виробу вказано на його сторінці. Для індивідуальної задачі окремо погодимо строк після оцінки файлу або опису.</p><h2>Оплата й підтвердження</h2><p>Замовлення підтверджує власник у Telegram. Доступні післяплата та переказ після підтвердження. Реквізити передаємо особисто після погодження деталей.</p><h2>Якщо потрібна заміна або повернення</h2><p>Напишіть нам у Telegram, вкажіть номер замовлення й опишіть проблему. Для пошкодження або невідповідності додайте фото. Перевіримо обставини та погодимо подальші дії відповідно до законодавства України. Для індивідуальних виробів умови погоджуємо перед виготовленням; це не обмежує ваших законних прав щодо якості товару.</p></InformationPage>;
}
