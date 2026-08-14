export type OwnerBotTransientScope = "manual" | "order-comment";

export type OwnerBotTransientState = {
  promptMessageId: number | null;
  correctionMessageIds: number[];
};

export type OwnerBotTransientStates = Map<string, OwnerBotTransientState>;
export type SentTelegramMessage = { message_id: number };
export type DeleteTelegramMessage = (chatId: string, messageId: number) => Promise<unknown>;

export function transientStateKey(scope: OwnerBotTransientScope, chatId: string) {
  return `${scope}:${chatId}`;
}

function validMessageId(value: number | null | undefined) {
  return Number.isSafeInteger(value) && Number(value) > 0 ? Number(value) : null;
}

async function deleteBestEffort(
  chatId: string,
  messageIds: Array<number | null | undefined>,
  deleteMessage: DeleteTelegramMessage,
) {
  const uniqueIds = [...new Set(messageIds.map(validMessageId).filter((id): id is number => id !== null))];
  await Promise.all(uniqueIds.map((messageId) => deleteMessage(chatId, messageId).catch(() => undefined)));
}

export async function advanceOwnerBotTransient(
  states: OwnerBotTransientStates,
  scope: OwnerBotTransientScope,
  chatId: string,
  triggerMessageId: number,
  sendNextPrompt: () => Promise<SentTelegramMessage>,
  deleteMessage: DeleteTelegramMessage,
) {
  const key = transientStateKey(scope, chatId);
  const previous = states.get(key);
  const nextPrompt = await sendNextPrompt();
  const nextPromptMessageId = validMessageId(nextPrompt.message_id);
  if (!nextPromptMessageId) throw new Error("Telegram did not return a message ID for the owner-bot prompt.");

  states.set(key, { promptMessageId: nextPromptMessageId, correctionMessageIds: [] });
  await deleteBestEffort(chatId, [
    previous?.promptMessageId,
    ...(previous?.correctionMessageIds ?? []),
    triggerMessageId,
  ], deleteMessage);
  return nextPrompt;
}

export async function rememberOwnerBotCorrection(
  states: OwnerBotTransientStates,
  scope: OwnerBotTransientScope,
  chatId: string,
  inputMessageId: number,
  sendCorrection: () => Promise<SentTelegramMessage>,
) {
  const correction = await sendCorrection();
  const key = transientStateKey(scope, chatId);
  const previous = states.get(key) ?? { promptMessageId: null, correctionMessageIds: [] };
  const correctionMessageIds = [
    ...previous.correctionMessageIds,
    inputMessageId,
    correction.message_id,
  ].map(validMessageId).filter((id): id is number => id !== null);
  states.set(key, { ...previous, correctionMessageIds: [...new Set(correctionMessageIds)] });
  return correction;
}

export async function completeOwnerBotTransient(
  states: OwnerBotTransientStates,
  scope: OwnerBotTransientScope,
  chatId: string,
  triggerMessageId: number,
  sendFinal: () => Promise<unknown>,
  deleteMessage: DeleteTelegramMessage,
) {
  const key = transientStateKey(scope, chatId);
  const previous = states.get(key);
  await sendFinal();
  states.delete(key);
  await deleteBestEffort(chatId, [
    previous?.promptMessageId,
    ...(previous?.correctionMessageIds ?? []),
    triggerMessageId,
  ], deleteMessage);
}

export async function clearOwnerBotTransient(
  states: OwnerBotTransientStates,
  scope: OwnerBotTransientScope,
  chatId: string,
  triggerMessageId: number,
  deleteMessage: DeleteTelegramMessage,
) {
  return completeOwnerBotTransient(states, scope, chatId, triggerMessageId, async () => undefined, deleteMessage);
}
