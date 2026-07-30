"use client";

import { useEffect, useRef } from "react";
import { usePathname } from "next/navigation";
import { trackAnalytics } from "@/lib/analytics";

export function PageViewTracker() {
  const pathname = usePathname();
  const lastPathname = useRef<string | null>(null);

  useEffect(() => {
    if (!pathname || lastPathname.current === pathname) {
      return;
    }

    lastPathname.current = pathname;
    trackAnalytics("Page View", { location: "page" });
  }, [pathname]);

  return null;
}
