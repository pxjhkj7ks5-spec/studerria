import assert from "node:assert/strict";
import test from "node:test";
import { generateInviteCode, normalizePhone, parseDoneCommand } from "./domain.js";

test("normalizes E.164 phone numbers and rejects unsafe values", () => {
  assert.equal(normalizePhone("+38 (067) 123-45-67"), "+380671234567");
  assert.throws(() => normalizePhone("0671234567"), /invalid_phone/);
});

test("invite code is operator-friendly", () => {
  assert.match(generateInviteCode(), /^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
});

test("parses Ukrainian and English done commands with optional comment", () => {
  assert.deepEqual(parseDoneCommand("готово перевірено"), { comment: "перевірено" });
  assert.deepEqual(parseDoneCommand("#15 done файл завантажено"), { comment: "файл завантажено" });
  assert.equal(parseDoneCommand("коли дедлайн?"), null);
});
