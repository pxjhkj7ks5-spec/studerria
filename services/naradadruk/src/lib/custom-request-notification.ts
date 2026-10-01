import { prisma } from "@/lib/prisma";
import { getAdminRoute } from "@/lib/auth";
import { absoluteSiteUrl } from "@/lib/site-url";

export async function deliverCustomRequestNotification(publicId: string) {
  // A persisted lease prevents concurrent retry clicks from sending two notifications.
  const now = new Date();
  const claimed = await prisma.customRequest.updateMany({ where: { publicId, OR: [{ notificationLease: null }, { notificationLease: { lt: new Date(now.getTime() - 60_000) } }] }, data: { notificationLease: now } });
  if (!claimed.count) return;
  let status: "sent" | "failed" | "skipped" = "skipped";
  let error = "";
  try {
    const request = await prisma.customRequest.findUniqueOrThrow({ where: { publicId }, include: { attachments: true } });
    const token = process.env.NARADADRUK_ORDER_TELEGRAM_BOT_TOKEN?.trim();
    const chatId = process.env.NARADADRUK_ORDER_TELEGRAM_CHAT_ID?.trim();
    if (token && chatId) {
      const text = [`Нова індивідуальна заявка ${request.publicId}`, request.mode === "file" ? "Друк файлу" : "Моделювання", `Ім’я: ${request.name}`, `Telegram: ${request.telegramContact}`, request.phone ? `Телефон: ${request.phone}` : "", `Кількість: ${request.quantity}`, request.description.slice(0,1800), `Вкладень: ${request.attachments.length}`, `Деталі: ${absoluteSiteUrl(`${getAdminRoute()}/custom-requests/${request.publicId}`)}`].filter(Boolean).join("\n");
      const response = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ chat_id: chatId, text, disable_web_page_preview: true }), signal: AbortSignal.timeout(8000) });
      const payload = await response.json().catch(() => null);
      if (!response.ok || !payload?.ok) throw new Error("notification");
      status = "sent";
    }
  } catch { status = "failed"; error = "Telegram недоступний. Спробуйте надіслати повторно."; }
  await prisma.customRequest.update({ where: { publicId }, data: { notificationStatus: status, notificationError: error, notificationLease: null } });
}
