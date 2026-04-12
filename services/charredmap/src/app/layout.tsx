import type { Metadata } from "next";
import { Bricolage_Grotesque, Manrope } from "next/font/google";
import { SiteFooter } from "@/components/site/site-footer";
import { siteDescription, siteName } from "@/lib/constants";
import "./globals.css";

const displayFont = Bricolage_Grotesque({
  subsets: ["latin", "cyrillic"],
  variable: "--font-display",
});

const bodyFont = Manrope({
  subsets: ["latin", "cyrillic"],
  variable: "--font-body",
});

export const metadata: Metadata = {
  title: siteName,
  description: siteDescription,
};

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="uk">
      <body className={`${displayFont.variable} ${bodyFont.variable}`}>
        <div className="relative min-h-screen overflow-x-hidden bg-[--ink] text-[--paper]">
          <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top,_rgba(255,132,56,0.16),_transparent_34%),radial-gradient(circle_at_bottom_right,_rgba(218,59,59,0.14),_transparent_26%)]" />
          <div className="relative flex min-h-screen flex-col">
            <div className="flex-1">{children}</div>
            <SiteFooter />
          </div>
        </div>
      </body>
    </html>
  );
}
