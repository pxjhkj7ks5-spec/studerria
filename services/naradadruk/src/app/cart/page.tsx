import { CartCheckout } from "@/components/site/cart-checkout";
import { PublicFrame } from "@/components/site/public-frame";
import { getSiteSettings } from "@/lib/data";

export const dynamic = "force-dynamic";

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

