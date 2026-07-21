import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createGameStore } from "../serverGame.mjs";

test("JSON auth store keeps nicknames unique and transfers one profile between devices", async () => {
  const directory = await mkdtemp(join(tmpdir(), "shieldline-auth-"));
  try {
    const store = await createGameStore(join(directory, "store.json"));
    await store.completeRegistration("guest-alpha", { nickname: "Сокіл", nicknameNormalized: "сокіл", consentVersion: "v1" });
    assert.equal(await store.nicknameAvailable("сокіл", "guest-beta"), false);
    assert.equal(await store.nicknameAvailable("сокіл", "guest-alpha"), true);
    const parallel = await Promise.allSettled([
      store.completeRegistration("guest-parallel-a", { nickname: "Обрій", nicknameNormalized: "обрій", consentVersion: "v1" }),
      store.completeRegistration("guest-parallel-b", { nickname: "ОБРІЙ", nicknameNormalized: "обрій", consentVersion: "v1" }),
    ]);
    assert.equal(parallel.filter((result) => result.status === "fulfilled").length, 1);
    assert.equal(parallel.filter((result) => result.status === "rejected").length, 1);
    await store.bindDevice("guest-alpha", "device-hash-a", { platform: "web" });
    assert.deepEqual(await store.findDevice("device-hash-a"), { actorId: "guest-alpha" });
    assert.equal((await store.getAuthProfile("guest-alpha")).deviceCount, 1);
    await store.attachIdentity("guest-alpha", "telegram", "42", { username: "sokil" });
    assert.equal((await store.getAuthProfile("guest-alpha")).telegram.username, "sokil");
    await assert.rejects(() => store.attachIdentity("guest-beta", "telegram", "42", {}), /іншого профілю/);
    await store.createTransferCode("guest-alpha", "code-hash", new Date(Date.now() + 60_000).toISOString());
    assert.deepEqual(await store.consumeTransferCode("code-hash"), { actorId: "guest-alpha" });
    await assert.rejects(() => store.consumeTransferCode("code-hash"), /недійсний/);
    const firstProgress = await store.savePlayerProgress("guest-alpha", 0, { campaign: { mission: 2 } });
    assert.equal(firstProgress.revision, 1);
    assert.deepEqual(await store.getPlayerProgress("guest-alpha"), firstProgress);
    const secondProgress = await store.savePlayerProgress("guest-alpha", 1, { campaign: { mission: 3 } });
    assert.equal(secondProgress.revision, 2);
    await assert.rejects(
      () => store.savePlayerProgress("guest-alpha", 1, { campaign: { mission: 1 } }),
      (error) => error.statusCode === 409 && error.latestPatch.accountProgress.revision === 2,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
