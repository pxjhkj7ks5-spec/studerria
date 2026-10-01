import type { Metadata } from "next";
import { InformationPage } from "@/components/site/information-page";
import { absoluteSiteUrl } from "@/lib/site-url";
import { withBasePath } from "@/lib/base-path";
export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Більше про Narada Druk", alternates: { canonical: absoluteSiteUrl("/more") } };
export default async function Page() {
  return <InformationPage title="Більше про Narada Druk"><nav className="information-links" aria-label="Довідка">{[["/reviews", "Відгуки"], ["/delivery", "Доставка й оплата"], ["/about", "Про майстерню"], ["/contacts", "Контакти"], ["/privacy", "Конфіденційність"]].map(([path, label]) => <a className="ghost-pill" key={path} href={withBasePath(path)}>{label}</a>)}</nav></InformationPage>;
}
