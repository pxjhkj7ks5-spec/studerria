import assert from "node:assert/strict";
import test from "node:test";
import {
  handleManualOrderTextUpdate,
  isAuthorizedOwnerMessage,
  manualOrderFirstPrompt,
  type OwnerBotAccess,
} from "../src/lib/manual-order-entry";
import type { ManualOrderSession } from "../src/lib/manual-order";
import type { OwnerBotTransientStates } from "../src/lib/owner-bot-transient-messages";

const access: OwnerBotAccess = {
  ownerChatId: "-1001111111111",
  postsChatId: "-1002222222222",
  ownerUserIds: new Set(["123456789"]),
};

test("an authorized /manual text update in the configured admin supergroup sends the first step", async () => {
  const sessions = new Map<string, ManualOrderSession>();
  const transientStates: OwnerBotTransientStates = new Map();
  const sent: Array<{ chatId: string; text: string; replyMarkup?: Record<string, unknown> }> = [];
  const deleted: number[] = [];
  const message = {
    message_id: 100,
    chat: { id: -1001111111111, type: "supergroup" },
    from: { id: 123456789 },
    text: "/manual",
  };

  const handled = await handleManualOrderTextUpdate(
    message,
    access,
    sessions,
    transientStates,
    async (chatId, text, replyMarkup) => {
      sent.push({ chatId, text, replyMarkup });
      return { message_id: 101 };
    },
    async (_chatId, messageId) => {
      deleted.push(messageId);
    },
  );

  assert.equal(handled, true);
  assert.equal(sessions.get("-1001111111111")?.step, "name");
  assert.deepEqual(sent, [{
    chatId: "-1001111111111",
    text: manualOrderFirstPrompt,
    replyMarkup: { inline_keyboard: [[{ text: "Скасувати", callback_data: "manual:cancel" }]] },
  }]);
  assert.deepEqual(deleted, [100]);
});

test("an unrelated public channel is never authorized as the staff chat", async () => {
  const misconfiguredAccess: OwnerBotAccess = {
    ...access,
    ownerChatId: access.postsChatId,
  };
  const channelMessage = {
    message_id: 200,
    chat: { id: -1002222222222, type: "channel" },
    from: { id: 123456789 },
    text: "/manual",
  };
  const sessions = new Map<string, ManualOrderSession>();
  const transientStates: OwnerBotTransientStates = new Map();
  let sendCount = 0;

  assert.equal(isAuthorizedOwnerMessage(channelMessage, misconfiguredAccess), false);
  assert.equal(await handleManualOrderTextUpdate(
    channelMessage,
    misconfiguredAccess,
    sessions,
    transientStates,
    async () => {
      sendCount += 1;
      return { message_id: 201 };
    },
    async () => undefined,
  ), false);
  assert.equal(sendCount, 0);
  assert.equal(sessions.size, 0);
});

test("a different group or an unlisted actor cannot start /manual", async () => {
  const sessions = new Map<string, ManualOrderSession>();
  const transientStates: OwnerBotTransientStates = new Map();
  const sendMessage = async () => ({ message_id: 301 });
  const deleteMessage = async () => undefined;

  assert.equal(await handleManualOrderTextUpdate({
    message_id: 300,
    chat: { id: -1003333333333, type: "supergroup" },
    from: { id: 123456789 },
    text: "/manual",
  }, access, sessions, transientStates, sendMessage, deleteMessage), false);
  assert.equal(await handleManualOrderTextUpdate({
    message_id: 302,
    chat: { id: -1001111111111, type: "group" },
    from: { id: 987654321 },
    text: "/manual",
  }, access, sessions, transientStates, sendMessage, deleteMessage), false);
  assert.equal(sessions.size, 0);
});
