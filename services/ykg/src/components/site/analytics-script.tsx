import Script from "next/script";

export function AnalyticsScript() {
  const scriptSrc = process.env.NEXT_PUBLIC_PLAUSIBLE_SCRIPT_SRC?.trim();

  if (!scriptSrc) {
    return null;
  }

  return <Script src={scriptSrc} strategy="afterInteractive" />;
}
