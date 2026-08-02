import type { MetadataRoute } from "next";
import { absoluteSiteUrl, sitePath } from "@/lib/constants";
import { getAdminRoute } from "@/lib/auth";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: {
      userAgent: "*",
      allow: `${sitePath}/`,
      disallow: [
        `${sitePath}${getAdminRoute()}`,
        `${sitePath}/api/`,
        `${sitePath}/cart`,
        `${sitePath}/order/`,
      ],
    },
    sitemap: absoluteSiteUrl("/sitemap.xml"),
    host: "https://studerria.com",
  };
}
