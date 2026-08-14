import type { Metadata } from "next";
import "@fontsource-variable/manrope";
import "@fontsource-variable/oswald";
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
    images: [{ url: absoluteSiteUrl("/ykg-editorial-hero.png"), alt: "YKG editorial" }],
  },
  twitter: {
    card: "summary_large_image",
    title: siteShareTitle,
    description: siteShareDescription,
    images: [absoluteSiteUrl("/ykg-editorial-hero.png")],
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="uk" data-scroll-behavior="smooth">
      <body>
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
          },
        ]} />
        {children}
        <AnalyticsScript />
      </body>
    </html>
  );
}
