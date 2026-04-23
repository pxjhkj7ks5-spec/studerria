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
          <div className="relative flex min-h-screen flex-col">
            <div className="flex-1">{children}</div>
            <SiteFooter />
          </div>
        </div>
      </body>
    </html>
  );
}
