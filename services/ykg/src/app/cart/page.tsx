import { CartCheckout } from "@/components/site/cart-checkout";
import type { Metadata } from "next";
import { PublicFrame } from "@/components/site/public-frame";
import { getSiteSettings } from "@/lib/data";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Кошик", robots: { index: false, follow: false } };

export default async function CartPage() {
  const settings = await getSiteSettings();
  return (
    <PublicFrame telegramUrl={settings.telegramUrl}>
      <main className="cart-page site-container">
        <CartCheckout />
      </main>
    </PublicFrame>
  );
}
