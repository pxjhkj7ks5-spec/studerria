import assert from "node:assert/strict";
import test from "node:test";
import { canManageTasks, canManageUsers, createSessionToken, verifySessionToken, type SessionUser } from "./auth.js";

const dev: SessionUser = { id: 1, email: "dev@example.com", displayName: "Dev", role: "dev" };
const deanery: SessionUser = { id: 2, email: "dean@example.com", displayName: "Deanery", role: "deanery" };
const teacher: SessionUser = { id: 3, email: "teacher@example.com", displayName: "Teacher", role: "teacher" };

test("session token validates and rejects tampering", () => {
  const token = createSessionToken(42, "secret");
  assert.equal(verifySessionToken(token, "secret"), 42);
  assert.equal(verifySessionToken(`${token}x`, "secret"), null);
  assert.equal(verifySessionToken(token, "other"), null);
});

test("role permissions keep dev as role owner and deanery teacher-scoped", () => {
  assert.equal(canManageUsers(dev, "deanery"), true);
  assert.equal(canManageUsers(dev, "teacher"), true);
  assert.equal(canManageUsers(deanery, "teacher"), true);
  assert.equal(canManageUsers(deanery, "deanery"), false);
  assert.equal(canManageUsers(teacher, "teacher"), false);
  assert.equal(canManageTasks(dev), true);
  assert.equal(canManageTasks(deanery), true);
  assert.equal(canManageTasks(teacher), false);
});
