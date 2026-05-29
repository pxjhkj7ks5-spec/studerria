import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { redactWhatsAppPayload, verifyWhatsAppSignature } from "./whatsapp.js";

test("validates Meta WhatsApp webhook signature", () => {
  const body = Buffer.from(JSON.stringify({ hello: "world" }));
  const digest = crypto.createHmac("sha256", "app-secret").update(body).digest("hex");
  assert.equal(verifyWhatsAppSignature(body, `sha256=${digest}`, "app-secret"), true);
  assert.equal(verifyWhatsAppSignature(body, `sha256=${digest}`, "wrong"), false);
  assert.equal(verifyWhatsAppSignature(body, "sha1=nope", "app-secret"), false);
});

test("redacts sensitive message payload fields", () => {
  const redacted = redactWhatsAppPayload({
    access_token: "secret",
    text: "this is a long message body that should not be logged verbatim",
  });
  assert.equal(redacted.access_token, "[redacted]");
  assert.equal(redacted.text, "[redacted-text]");
});
