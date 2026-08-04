import assert from "node:assert/strict";
import test from "node:test";
import {
  advanceOwnerBotTransient,
  completeOwnerBotTransient,
  rememberOwnerBotCorrection,
  transientStateKey,
  type OwnerBotTransientStates,
} from "../src/lib/owner-bot-transient-messages";

test("a successful manual text step removes only its tracked prompt and admin answers", async () => {
  const states: OwnerBotTransientStates = new Map([
    [transientStateKey("manual", "-1001"), { promptMessageId: 10, correctionMessageIds: [] }],
  ]);
  const deleted: number[] = [];
  const deleteMessage = async (_chatId: string, messageId: number) => {
    deleted.push(messageId);
    if (messageId === 11) throw new Error("message already deleted");
  };

  await rememberOwnerBotCorrection(states, "manual", "-1001", 11, async () => ({ message_id: 12 }));
  await advanceOwnerBotTransient(states, "manual", "-1001", 13, async () => ({ message_id: 14 }), deleteMessage);

  assert.deepEqual(deleted.sort((left, right) => left - right), [10, 11, 12, 13]);
  assert.deepEqual(states.get(transientStateKey("manual", "-1001")), {
    promptMessageId: 14,
    correctionMessageIds: [],
  });
});

test("a successful manual callback removes the pressed inline prompt only once", async () => {
  const states: OwnerBotTransientStates = new Map([
    [transientStateKey("manual", "-1001"), { promptMessageId: 20, correctionMessageIds: [] }],
  ]);
  const deleted: number[] = [];

  await advanceOwnerBotTransient(states, "manual", "-1001", 20, async () => ({ message_id: 21 }), async (_chatId, messageId) => {
    deleted.push(messageId);
  });

  assert.deepEqual(deleted, [20]);
  assert.equal(states.get(transientStateKey("manual", "-1001"))?.promptMessageId, 21);
});

test("a marketplace callback cleans only its own interactive prompt and pressed button", async () => {
  const states: OwnerBotTransientStates = new Map([
    [transientStateKey("marketplace", "-1001"), { promptMessageId: 40, correctionMessageIds: [] }],
    [transientStateKey("manual", "-1001"), { promptMessageId: 90, correctionMessageIds: [] }],
  ]);
  const deleted: number[] = [];

  await advanceOwnerBotTransient(states, "marketplace", "-1001", 41, async () => ({ message_id: 42 }), async (_chatId, messageId) => {
    deleted.push(messageId);
  });

  assert.deepEqual(deleted.sort((left, right) => left - right), [40, 41]);
  assert.equal(states.get(transientStateKey("marketplace", "-1001"))?.promptMessageId, 42);
  assert.equal(states.get(transientStateKey("manual", "-1001"))?.promptMessageId, 90);
});

test("final order messages remain while the transient confirmation is removed", async () => {
  const states: OwnerBotTransientStates = new Map([
    [transientStateKey("manual", "-1001"), { promptMessageId: 30, correctionMessageIds: [] }],
  ]);
  const finalMessageIds: number[] = [];
  const deleted: number[] = [];

  await completeOwnerBotTransient(states, "manual", "-1001", 30, async () => {
    finalMessageIds.push(31, 32);
  }, async (_chatId, messageId) => {
    deleted.push(messageId);
  });

  assert.deepEqual(finalMessageIds, [31, 32]);
  assert.deepEqual(deleted, [30]);
  assert.equal(states.has(transientStateKey("manual", "-1001")), false);
  assert.equal(deleted.some((messageId) => finalMessageIds.includes(messageId)), false);
});
