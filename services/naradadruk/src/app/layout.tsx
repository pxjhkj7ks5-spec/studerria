import type { Metadata } from "next";
import { Manrope, Outfit } from "next/font/google";
import { SiteFooter } from "@/components/site/site-footer";
import {
  siteBaseUrl,
  siteDescription,
  siteName,
  sitePath,
  siteShareDescription,
  siteShareTitle,
} from "@/lib/constants";
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
  metadataBase: new URL(siteBaseUrl),
  applicationName: siteName,
  alternates: {
    canonical: sitePath,
  },
  openGraph: {
    type: "website",
    locale: "uk_UA",
    url: sitePath,
    siteName,
    title: siteShareTitle,
    description: siteShareDescription,
  },
  twitter: {
    card: "summary",
    title: siteShareTitle,
    description: siteShareDescription,
  },
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
          <div className="ambient-layer ambient-layer--warm pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_18%_28%,_rgba(255,135,61,0.16),_transparent_30%),radial-gradient(circle_at_82%_26%,_rgba(41,76,120,0.2),_transparent_26%),linear-gradient(180deg,_rgba(255,255,255,0.04),_transparent_22%)]" />
          <div className="ambient-layer ambient-layer--halo pointer-events-none absolute inset-x-0 top-[10rem] h-[42rem] bg-[radial-gradient(circle_at_center,_rgba(255,255,255,0.08),_transparent_60%)] opacity-70" />
          <div className="relative flex min-h-screen flex-col">
            <div className="flex-1">{children}</div>
            <SiteFooter />
          </div>
        </div>
      </body>
    </html>
  );
}
