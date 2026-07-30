import type { Metadata } from "next";
import { Manrope } from "next/font/google";
import { AnalyticsScript } from "@/components/site/analytics-script";
import {
  siteBaseUrl,
  siteDescription,
  siteName,
  sitePath,
  siteShareDescription,
  siteShareTitle,
} from "@/lib/constants";
import "./globals.css";
import "./storefront.css";

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
      <body className={bodyFont.variable}>
        {children}
        <AnalyticsScript />
      </body>
    </html>
  );
}
