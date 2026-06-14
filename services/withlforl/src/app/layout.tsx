import type { Metadata, Viewport } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "для тебе",
  description: "A private greeting page.",
  applicationName: "Withlforl",
  icons: {
    icon: "/withlforl/icon.svg",
    shortcut: "/withlforl/icon.svg",
  },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  viewportFit: "cover",
  themeColor: "#f6f0e8",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="uk">
      <body>{children}</body>
    </html>
  );
}
