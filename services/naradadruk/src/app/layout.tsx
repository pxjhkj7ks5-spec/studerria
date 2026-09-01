import type { Metadata } from "next";
import { Manrope } from "next/font/google";
import { AnalyticsScript } from "@/components/site/analytics-script";
import { StructuredData } from "@/components/site/structured-data";
import {
  defaultTelegramUrl,
  siteDescription,
  siteAlternateNames,
  siteName,
  siteShareDescription,
  siteShareTitle,
} from "@/lib/constants";
import { absoluteSiteUrl, siteBaseUrl } from "@/lib/site-url";
import "./globals.css";
import "./storefront.css";

const bodyFont = Manrope({
  subsets: ["latin", "cyrillic"],
  variable: "--font-body",
});

export const metadata: Metadata = {
  title: {
    default: siteShareTitle,
    template: `%s | ${siteName}`,
  },
  description: siteDescription,
  metadataBase: new URL(siteBaseUrl),
  applicationName: siteName,
  alternates: {
    canonical: absoluteSiteUrl(),
  },
  openGraph: {
    type: "website",
    locale: "uk_UA",
    url: absoluteSiteUrl(),
    siteName,
    title: siteShareTitle,
    description: siteShareDescription,
    images: [{ url: absoluteSiteUrl("/naradadruk-hero.webp"), alt: "3D-друк Narada Druk" }],
  },
  twitter: {
    card: "summary_large_image",
    title: siteShareTitle,
    description: siteShareDescription,
    images: [absoluteSiteUrl("/naradadruk-hero.webp")],
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
        <StructuredData data={[
          {
            "@context": "https://schema.org",
            "@type": "Organization",
            "@id": `${absoluteSiteUrl()}#organization`,
            name: siteName,
            alternateName: siteAlternateNames,
            url: absoluteSiteUrl(),
            logo: absoluteSiteUrl("/icon.svg"),
            description: siteDescription,
            sameAs: [defaultTelegramUrl],
          },
          {
            "@context": "https://schema.org",
            "@type": "WebSite",
            "@id": `${absoluteSiteUrl()}#website`,
            name: siteName,
            alternateName: siteAlternateNames,
            url: absoluteSiteUrl(),
            description: siteDescription,
            inLanguage: "uk-UA",
            publisher: { "@id": `${absoluteSiteUrl()}#organization` },
            potentialAction: {
              "@type": "SearchAction",
              target: {
                "@type": "EntryPoint",
                urlTemplate: absoluteSiteUrl("/catalog?q={search_term_string}"),
              },
              "query-input": "required name=search_term_string",
            },
          },
        ]} />
        {children}
        <AnalyticsScript />
      </body>
    </html>
  );
}
