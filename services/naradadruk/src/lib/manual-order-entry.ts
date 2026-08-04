import { createManualOrderSession, type ManualOrderSession } from "./manual-order";

export type OwnerBotMessage = {
  chat: { id: number; type: string };
  from?: { id: number };
  text?: string;
};

export type OwnerBotAccess = {
  ownerChatId: string;
  postsChatId: string;
  ownerUserIds: ReadonlySet<string>;
};

type SendOwnerMessage = (
  chatId: string,
  text: string,
  replyMarkup?: Record<string, unknown>,
) => Promise<unknown>;

export const manualOrderFirstPrompt = "<b>Ручне замовлення</b>\nКрок 1 із 4: надішліть імʼя клієнта.";

export function isAuthorizedOwnerMessage(
  message: OwnerBotMessage,
  access: OwnerBotAccess,
  actorId = message.from?.id,
) {
  const chatId = String(message.chat.id);
  return message.chat.type !== "channel"
    && chatId === access.ownerChatId
    && chatId !== access.postsChatId
    && access.ownerUserIds.has(String(actorId ?? ""));
}

export function isOwnerAdminGroup(message: OwnerBotMessage, access: OwnerBotAccess) {
  return (message.chat.type === "group" || message.chat.type === "supergroup")
    && String(message.chat.id) === access.ownerChatId
    && String(message.chat.id) !== access.postsChatId;
}

export async function beginManualOrder(
  chatId: string,
  sessions: Map<string, ManualOrderSession>,
  sendMessage: SendOwnerMessage,
) {
  sessions.set(chatId, createManualOrderSession());
  await sendMessage(chatId, manualOrderFirstPrompt, {
    inline_keyboard: [[{ text: "Скасувати", callback_data: "manual:cancel" }]],
  });
}

export async function handleManualOrderTextUpdate(
  message: OwnerBotMessage,
  access: OwnerBotAccess,
  sessions: Map<string, ManualOrderSession>,
  sendMessage: SendOwnerMessage,
) {
  if (!/^\/manual(?:@[a-zA-Z0-9_]+)?(?:\s|$)/i.test(message.text?.trim() ?? "")) return false;
  if (!isAuthorizedOwnerMessage(message, access) || !isOwnerAdminGroup(message, access)) return false;

  await beginManualOrder(String(message.chat.id), sessions, sendMessage);
  return true;
}
