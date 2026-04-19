import type { Metadata } from "next";
import { Manrope, Outfit } from "next/font/google";
import { SiteFooter } from "@/components/site/site-footer";
import { siteDescription, siteName } from "@/lib/constants";
import "./globals.css";

const displayFont = Outfit({
  subsets: ["latin"],
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

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="uk">
      <body className={`${displayFont.variable} ${bodyFont.variable}`}>
        <div className="relative min-h-screen overflow-x-hidden bg-[--ink] text-white">
          <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_left,_rgba(255,135,61,0.18),_transparent_32%),radial-gradient(circle_at_top_right,_rgba(41,76,120,0.22),_transparent_28%),linear-gradient(180deg,_rgba(255,255,255,0.05),_transparent_24%)]" />
          <div className="pointer-events-none absolute inset-x-0 top-0 h-[38rem] bg-[radial-gradient(circle_at_center,_rgba(255,255,255,0.07),_transparent_60%)] opacity-70" />
          <div className="relative flex min-h-screen flex-col">
            <div className="flex-1">{children}</div>
            <SiteFooter />
          </div>
        </div>
      </body>
    </html>
  );
}
