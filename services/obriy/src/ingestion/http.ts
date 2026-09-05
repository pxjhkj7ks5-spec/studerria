export type SourceFetch = (
  input: string,
  init?: RequestInit,
) => Promise<Response>;

export interface SourceResponse {
  status: number;
  lastModified: string | null;
  retryAfter: string | null;
  data?: unknown;
}

/** Provider bodies and token-bearing URLs must never escape into an error/logger. */
export class SourceRequestError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

export async function fetchSourceJson(
  fetcher: SourceFetch,
  url: string,
  signal: AbortSignal,
  headers: Record<string, string> = {},
  maxBytes = 1_048_576,
  timeoutMs = 10_000,
): Promise<SourceResponse> {
  const response = await fetcher(url, {
    method: "GET",
    headers: { Accept: "application/json", ...headers },
    signal: AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)]),
    // Redirects could leak credentials to a different provider or evade the URL allowlist.
    redirect: "error",
  });
  const result: SourceResponse = {
    status: response.status,
    lastModified: response.headers.get("last-modified"),
    retryAfter: response.headers.get("retry-after"),
  };
  if (response.status !== 200) {
    await response.body?.cancel();
    return result;
  }
  if (Number(response.headers.get("content-length")) > maxBytes) {
    await response.body?.cancel();
    throw new SourceRequestError("body_too_large");
  }
  if (!response.body) throw new SourceRequestError("empty_body");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > maxBytes) {
        await reader.cancel();
        throw new SourceRequestError("body_too_large");
      }
      chunks.push(chunk.value);
    }
  } finally {
    reader.releaseLock();
  }
  try {
    result.data = JSON.parse(
      Buffer.concat(chunks, size).toString("utf8"),
    ) as unknown;
  } catch {
    throw new SourceRequestError("invalid_json");
  }
  return result;
}

export function retryAfterMs(
  value: string | null,
  now: number,
  fallbackMs: number,
): number {
  if (!value) return fallbackMs;
  const seconds = Number(value);
  const retryMs =
    Number.isFinite(seconds) && seconds >= 0
      ? seconds * 1000
      : Date.parse(value) - now;
  // Node turns an overflowing timer into a 1 ms timer, which would hammer the provider.
  return Number.isFinite(retryMs)
    ? Math.min(2_147_483_647, Math.max(fallbackMs, retryMs))
    : fallbackMs;
}

export function sourceDate(value: unknown, now: number): Date | null {
  if (typeof value !== "string" || value.length > 64) return null;
  const time = Date.parse(value);
  return Number.isFinite(time) &&
    time >= Date.UTC(2000, 0, 1) &&
    time <= now + 60_000
    ? new Date(time)
    : null;
}
