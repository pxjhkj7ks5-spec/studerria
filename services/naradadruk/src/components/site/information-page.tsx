import type { ReactNode } from "react";
import { PublicFrame } from "@/components/site/public-frame";
import { getSiteSettings } from "@/lib/data";
import { withBasePath } from "@/lib/base-path";

export async function InformationPage({ title, children }: { title: string; children: ReactNode }) {
  const settings = await getSiteSettings();
  return <PublicFrame telegramUrl={settings.telegramUrl}><main className="site-container information-page"><p className="eyebrow">Narada Druk</p><h1>{title}</h1><div className="information-content">{children}</div>{title !== "Індивідуальний виріб" ? <a className="accent-pill" href={withBasePath("/custom")}>Обговорити свій виріб</a> : null}</main></PublicFrame>;
}
