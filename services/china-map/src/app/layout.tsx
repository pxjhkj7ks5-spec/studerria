import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Атлас кордонів Китаю | Studerria",
  description: "Інтерактивний навчальний атлас про територіальні трансформації Китаю від 1920-х до 2026 року.",
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
