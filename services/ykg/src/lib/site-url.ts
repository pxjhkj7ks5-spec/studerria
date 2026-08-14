const defaultPublicSiteUrl = "https://studerria.com/ykg";

export type PublicSiteLocation = {
  baseUrl: string;
  path: string;
  url: string;
};

export function resolvePublicSiteLocation(rawUrl?: string): PublicSiteLocation {
  const candidate = rawUrl?.trim() || defaultPublicSiteUrl;
  let parsed: URL;

  try {
    parsed = new URL(candidate);
  } catch {
    parsed = new URL(defaultPublicSiteUrl);
  }

  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    parsed = new URL(defaultPublicSiteUrl);
  }

  parsed.hash = "";
  parsed.search = "";
  const normalizedPath = parsed.pathname.replace(/\/+$/, "");
  const path = normalizedPath === "/" ? "" : normalizedPath;
  const url = new URL(path || "/", parsed.origin).toString();

  return {
    baseUrl: parsed.origin,
    path,
    url,
  };
}

const publicSiteLocation = resolvePublicSiteLocation(
  process.env.YKG_PUBLIC_URL,
);

export const siteBaseUrl = publicSiteLocation.baseUrl;
export const sitePath = publicSiteLocation.path;

export function absoluteSiteUrl(path = "/") {
  const normalized = path === "/" ? "" : `/${path.replace(/^\/+|\/+$/g, "")}`;
  return new URL(`${sitePath}${normalized}` || "/", siteBaseUrl).toString();
}
