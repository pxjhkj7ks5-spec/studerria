import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "China Border Atlas | Studerria",
  description: "Interactive classroom atlas about China's territorial transformations from the 1920s to 2026.",
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
