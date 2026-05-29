import crypto from "node:crypto";
import type { Db } from "./db.js";
import type { AppConfig } from "./config.js";

export type WhatsAppTemplateName = "wa_task_assigned_uk" | "wa_task_reminder_uk" | "wa_task_overdue_uk";

export function verifyWhatsAppSignature(rawBody: Buffer, signatureHeader: string | string[] | undefined, appSecret: string) {
  if (!appSecret) return false;
  const signature = Array.isArray(signatureHeader) ? signatureHeader[0] : signatureHeader;
  if (!signature || !signature.startsWith("sha256=")) return false;
  const received = signature.slice("sha256=".length);
  const expected = crypto.createHmac("sha256", appSecret).update(rawBody).digest("hex");
  if (received.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(received, "hex"), Buffer.from(expected, "hex"));
}

export function redactWhatsAppPayload(payload: unknown) {
  const text = JSON.stringify(payload ?? {});
  return JSON.parse(
    text.replace(/"access_token"\s*:\s*"[^"]+"/gi, '"access_token":"[redacted]"')
      .replace(/"text"\s*:\s*"[^"]{25,}"/gi, '"text":"[redacted-text]"'),
  ) as Record<string, unknown>;
}

export function isWhatsAppConfigured(config: AppConfig) {
  return Boolean(config.whatsapp.accessToken && config.whatsapp.phoneNumberId);
}

type TemplateParams = {
  to: string;
  templateName: WhatsAppTemplateName;
  bodyParams: string[];
};

export async function sendTemplateMessage(config: AppConfig, params: TemplateParams) {
  if (!isWhatsAppConfigured(config)) {
    return {
      ok: false,
      skipped: true,
      status: 0,
      messageId: "",
      error: "whatsapp_not_configured",
      payload: {},
    };
  }

  const payload = {
    messaging_product: "whatsapp",
    to: params.to,
    type: "template",
    template: {
      name: params.templateName,
      language: { code: "uk" },
      components: [
        {
          type: "body",
          parameters: params.bodyParams.map((text) => ({ type: "text", text })),
        },
      ],
    },
  };

  const response = await fetch(`https://graph.facebook.com/${config.whatsapp.graphVersion}/${config.whatsapp.phoneNumberId}/messages`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${config.whatsapp.accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
  const data = await response.json().catch(() => ({})) as { messages?: Array<{ id?: string }>; error?: { message?: string } };
  return {
    ok: response.ok,
    skipped: false,
    status: response.status,
    messageId: data.messages?.[0]?.id || "",
    error: response.ok ? "" : data.error?.message || `whatsapp_http_${response.status}`,
    payload: redactWhatsAppPayload(data),
  };
}

export async function sendTextMessage(config: AppConfig, to: string, text: string) {
  if (!isWhatsAppConfigured(config)) {
    return { ok: false, skipped: true, status: 0, messageId: "", error: "whatsapp_not_configured", payload: {} };
  }
  const payload = {
    messaging_product: "whatsapp",
    to,
    type: "text",
    text: { preview_url: false, body: text.slice(0, 3500) },
  };
  const response = await fetch(`https://graph.facebook.com/${config.whatsapp.graphVersion}/${config.whatsapp.phoneNumberId}/messages`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${config.whatsapp.accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
  const data = await response.json().catch(() => ({})) as { messages?: Array<{ id?: string }>; error?: { message?: string } };
  return {
    ok: response.ok,
    skipped: false,
    status: response.status,
    messageId: data.messages?.[0]?.id || "",
    error: response.ok ? "" : data.error?.message || `whatsapp_http_${response.status}`,
    payload: redactWhatsAppPayload(data),
  };
}

export async function logOutboundMessage(pool: Db, input: {
  whatsappMessageId?: string;
  contactWaId?: string;
  userId?: number | null;
  taskId?: number | null;
  kind: string;
  status: string;
  payload?: Record<string, unknown>;
  error?: string;
}) {
  await pool.query(
    `
      INSERT INTO wa_message_logs (direction, whatsapp_message_id, contact_wa_id, user_id, task_id, kind, status, payload, error)
      VALUES ('outbound', NULLIF($1, ''), NULLIF($2, ''), $3, $4, $5, $6, $7::jsonb, NULLIF($8, ''))
      ON CONFLICT (whatsapp_message_id) DO UPDATE
      SET status = EXCLUDED.status,
          payload = EXCLUDED.payload,
          error = EXCLUDED.error,
          updated_at = NOW()
    `,
    [
      input.whatsappMessageId || "",
      input.contactWaId || "",
      input.userId || null,
      input.taskId || null,
      input.kind,
      input.status,
      JSON.stringify(input.payload || {}),
      input.error || "",
    ],
  );
}
