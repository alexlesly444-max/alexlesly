import assert from "node:assert/strict";
import test from "node:test";
import { addPadding, base64UrlToBytes, bytesToBase64Url, decryptMessage, encryptMessage, MAX_PLAINTEXT_BYTES, parsePayload, removePadding } from "./app.js";

test("Base64URL round-trips every byte", () => {
  const bytes = Uint8Array.from({ length: 256 }, (_, index) => index);
  assert.deepEqual(base64UrlToBytes(bytesToBase64Url(bytes)), bytes);
});

test("padding uses buckets and restores UTF-8 bytes", () => {
  const bytes = new TextEncoder().encode("Привет 👋");
  const padded = addPadding(bytes);
  assert.equal(padded.length, 256);
  assert.deepEqual(removePadding(padded), bytes);
  const near = addPadding(new Uint8Array(250));
  assert.equal(near.length, 256);
  assert.equal(addPadding(new Uint8Array(251)).length, 256);
  assert.throws(() => removePadding(Uint8Array.from(padded, (value, index) => index === bytes.length + 4 ? 1 : value)));
  assert.throws(() => addPadding(new Uint8Array(MAX_PLAINTEXT_BYTES + 1)));
});

test("AES-GCM authenticates payload and preserves untrusted text", async () => {
  const message = "<script>alert(1)</script>\n<img src=x onerror=alert(1)>";
  const first = await encryptMessage(message), second = await encryptMessage(message);
  assert.notEqual(first.password, second.password);
  assert.notEqual(first.payload, second.payload);
  assert.equal(await decryptMessage(first.payload, first.password), message);
  await assert.rejects(decryptMessage(first.payload, second.password));
  const parts = first.payload.split(".");
  parts[2] = `${parts[2].startsWith("A") ? "B" : "A"}${parts[2].slice(1)}`;
  await assert.rejects(decryptMessage(parts.join("."), first.password));
  const nonceParts = first.payload.split(".");
  nonceParts[1] = `${nonceParts[1].startsWith("A") ? "B" : "A"}${nonceParts[1].slice(1)}`;
  await assert.rejects(decryptMessage(nonceParts.join("."), first.password));
  assert.throws(() => parsePayload("v1.a." + "a".repeat(100_001)));
});
