export interface AdminUser {
  id: string;
  nickname: string | null;
  displayName: string;
  platform: string;
  status: "active" | "suspended" | "anonymized";
  suspensionReason?: string | null;
  createdAt: string;
  lastSeenAt: string | null;
  lastLoginAt: string | null;
  registrationCompletedAt: string | null;
  consentVersion: string | null;
  consentAcceptedAt: string | null;
  adminNote: string;
  telegram: { id: string; username?: string; firstName?: string; lastName?: string } | null;
  deviceCount: number;
  sessionCount: number;
  operationCount: number;
}

const base = `${(import.meta.env.BASE_URL || "/shieldline/").replace(/\/+$/, "")}/api/admin`;

export function adminCsrfToken() {
  return document.cookie.split(";").map((value) => value.trim()).find((value) => value.startsWith("shieldline_admin_csrf="))?.split("=").slice(1).join("=") || "";
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = String(init.method || "GET").toUpperCase();
  const response = await fetch(`${base}${path}`, {
    ...init,
    credentials: "same-origin",
    headers: {
      ...(init.body ? { "Content-Type": "application/json" } : {}),
      ...(["POST", "PUT", "PATCH", "DELETE"].includes(method) ? { "X-ShieldLine-Admin-CSRF": adminCsrfToken() } : {}),
      ...init.headers,
    },
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw Object.assign(new Error(payload.error || "Адміністративний запит не виконано."), { status: response.status });
  return payload as T;
}

export const adminApi = {
  login: (password: string) => request<{ admin: { label: string; expiresAt: string }; csrfToken: string }>("/auth/login", { method: "POST", body: JSON.stringify({ password }) }),
  me: () => request<{ admin: { label: string; expiresAt: string } }>("/me"),
  logout: () => request<{ ok: boolean }>("/auth/logout", { method: "POST", body: "{}" }),
  dashboard: () => request<Record<string, number>>("/dashboard"),
  users: (params = "") => request<{ items: AdminUser[]; nextCursor: string | null }>(`/users${params ? `?${params}` : ""}`),
  user: (id: string) => request<{ user: AdminUser; devices: unknown[]; sessions: unknown[]; operations: Array<Record<string, unknown>>; audit: Array<Record<string, unknown>> }>(`/users/${encodeURIComponent(id)}`),
  action: (id: string, action: string, body: Record<string, unknown>) => request<{ user: AdminUser }>(`/users/${encodeURIComponent(id)}/${action}`, { method: "POST", body: JSON.stringify(body) }),
  deleteUser: (id: string, body: Record<string, unknown>) => request<{ deleted: boolean }>(`/users/${encodeURIComponent(id)}`, { method: "DELETE", body: JSON.stringify(body) }),
  operations: () => request<{ items: Array<Record<string, unknown>> }>("/operations"),
  operation: (id: string) => request<{ operation: Record<string, unknown>; events: Array<Record<string, unknown>> }>(`/operations/${encodeURIComponent(id)}`),
  audit: () => request<{ items: Array<Record<string, unknown>> }>("/audit"),
  system: () => request<Record<string, unknown>>("/system"),
  broadcasts: () => request<{ items: Array<Record<string, unknown>> }>("/broadcasts"),
  broadcastPreview: () => request<{ recipientCount: number }>("/broadcasts/preview"),
  sendBroadcast: (text: string, reason: string) => request<Record<string, unknown>>("/broadcasts", { method: "POST", body: JSON.stringify({ text, reason }) }),
  sendTestNotification: (target: string, text: string) => request<Record<string, unknown>>("/broadcasts/test", { method: "POST", body: JSON.stringify({ target, text, reason: "Тест із вебадмінки" }) }),
  retryOutbox: (reason: string) => request<{ queued: number }>("/outbox/retry", { method: "POST", body: JSON.stringify({ reason }) }),
  zones: () => request<{ overlay: unknown }>("/zones"),
  saveZones: (overlay: unknown) => request<{ ok: boolean }>("/zones", { method: "PUT", body: JSON.stringify({ overlay }) }),
};
