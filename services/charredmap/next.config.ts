import type { NextConfig } from "next";

function normalizeBasePath(basePath?: string) {
  if (!basePath || basePath === "/") {
    return "";
  }

  const trimmed = basePath.trim();

  if (!trimmed) {
    return "";
  }

  const withLeadingSlash = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  return withLeadingSlash.replace(/\/+$/, "");
}

function normalizeRouteSegment(segment?: string) {
  const trimmed = segment?.trim().replace(/^\/+|\/+$/g, "");
  return trimmed || "admin";
}

const basePath = normalizeBasePath(process.env.NEXT_PUBLIC_BASE_PATH ?? "/charredmap");
const adminPath = normalizeRouteSegment(process.env.ADMIN_PATH ?? "admin");

const securityHeaders = [
  {
    key: "Referrer-Policy",
    value: "strict-origin-when-cross-origin",
  },
  {
    key: "X-Content-Type-Options",
    value: "nosniff",
  },
  {
    key: "X-Frame-Options",
    value: "DENY",
  },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=()",
  },
];

const adminHeaders = [
  {
    key: "Cache-Control",
    value: "private, no-store, no-cache, max-age=0",
  },
  {
    key: "X-Robots-Tag",
    value: "noindex, nofollow, noarchive, nosnippet",
  },
];

const nextConfig: NextConfig = {
  basePath,
  poweredByHeader: false,
  reactStrictMode: true,
  output: "standalone",
  experimental: {
    serverActions: {
      bodySizeLimit: "8mb",
    },
  },
  async headers() {
    return [
      {
        source: "/:path*",
        headers: securityHeaders,
      },
      {
        source: `/${adminPath}`,
        headers: adminHeaders,
      },
      {
        source: `/${adminPath}/:path*`,
        headers: adminHeaders,
      },
    ];
  },
};

export default nextConfig;
