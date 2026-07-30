import type { ReactNode } from "react";
import { SiteFooter } from "@/components/site/site-footer";
import { SiteHeader } from "@/components/site/site-header";

type PublicFrameProps = {
  children: ReactNode;
  telegramUrl: string;
};

export function PublicFrame({ children, telegramUrl }: PublicFrameProps) {
  return (
    <div className="storefront">
      <SiteHeader telegramUrl={telegramUrl} />
      <div className="storefront__content">{children}</div>
      <SiteFooter telegramUrl={telegramUrl} />
    </div>
  );
}
