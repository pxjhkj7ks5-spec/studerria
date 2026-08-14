import { isIP } from "node:net";
import { createPrivacyHash } from "@/lib/auth";

export const trustedClientIpHeader = "x-studerria-client-ip";
export const trustedClientIpSourceHeader = "x-studerria-client-ip-source";
export type TrustedClientIpSource = "trusted-forwarded" | "socket-peer" | "missing";

export function normalizeIpAddress(value: string) {
  let candidate = value.trim();
  if (candidate.startsWith("[") && candidate.endsWith("]")) {
    candidate = candidate.slice(1, -1);
  }

  const mappedIpv4 = candidate.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i)?.[1];
  if (mappedIpv4 && isIP(mappedIpv4) === 4) candidate = mappedIpv4;

  const family = isIP(candidate);
  if (family === 4) {
    return candidate.split(".").map((part) => String(Number(part))).join(".");
  }
  if (family === 6) {
    try {
      const hostname = new URL(`http://[${candidate}]/`).hostname;
      return hostname.slice(1, -1).toLowerCase();
    } catch {
      return null;
    }
  }
  return null;
}

export function getTrustedClientAddress(request: Request) {
  return normalizeIpAddress(request.headers.get(trustedClientIpHeader) ?? "");
}

export function getTrustedClientAddressSource(request: Request): TrustedClientIpSource {
  const source = request.headers.get(trustedClientIpSourceHeader);
  return source === "trusted-forwarded" || source === "socket-peer" ? source : "missing";
}

export function hashAnalyticsIp(address: string) {
  return createPrivacyHash("ykg-analytics-ip-exclusion-v1", address);
}

export function analyticsIpHint(address: string) {
  if (isIP(address) === 4) {
    return `IPv4 ···.${address.split(".").at(-1)}`;
  }
  const segments = address.split(":").filter(Boolean);
  return `IPv6 ${segments[0] || "::"}:…:${segments.at(-1) || "::"}`;
}
