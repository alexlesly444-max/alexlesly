import assert from "node:assert/strict";
import test from "node:test";
import {
  addPadding,
  base64UrlToBytes,
  bytesToBase64Url,
  decryptMessage,
  encryptMessage,
  formatRemaining,
  MAX_FRAGMENT_LENGTH,
  MAX_PLAINTEXT_BYTES,
  parsePayload,
  removePadding
} from "./app.js";

test("Base64URL round-trips every byte and rejects malformed encodings", () => {
  const bytes = Uint8Array.from({ length: 256 }, (_, index) => index);
  assert.deepEqual(base64UrlToBytes(bytesToBase64Url(bytes)), bytes);
  for (const malformed of ["", "a", "a+", "a/", "a=", "A*"]) {
    assert.throws(() => base64UrlToBytes(malformed));
  }
  assert.throws(() => base64UrlToBytes("AB"), /Non-canonical/);
});

test("padding uses byte buckets, preserves Unicode, and validates zero padding", () => {
  const bytes = new TextEncoder().encode("Привет 👋");
  const padded = addPadding(bytes);
  assert.equal(padded.length, 256);
  assert.deepEqual(removePadding(padded), bytes);
  assert.equal(addPadding(new Uint8Array(250)).length, 256);
  assert.equal(addPadding(new Uint8Array(253)).length, 512);
  assert.throws(() => removePadding(Uint8Array.from(padded, (value, index) => index === bytes.length + 4 ? 1 : value)));
  assert.throws(() => addPadding(new Uint8Array(MAX_PLAINTEXT_BYTES + 1)));
});

test("encryption round-trips Unicode and rejects empty or oversized plaintext", async () => {
  const unicode = "Строка 👋\n漢字\nمرحبا";
  const encrypted = await encryptMessage(unicode);
  assert.equal(await decryptMessage(encrypted.payload, encrypted.secretKey), unicode);
  await assert.rejects(encryptMessage(""));
  await assert.rejects(encryptMessage("a".repeat(MAX_PLAINTEXT_BYTES + 1)));
});

test("maximum plaintext is accepted and recovered byte-for-byte", async () => {
  const maximum = "a".repeat(MAX_PLAINTEXT_BYTES);
  const encrypted = await encryptMessage(maximum);
  assert.equal((await decryptMessage(encrypted.payload, encrypted.secretKey)).length, MAX_PLAINTEXT_BYTES);
});

test("payload parser rejects unsupported, truncated, malformed, and oversized input", async () => {
  const encrypted = await encryptMessage("parser fixture");
  const [, nonce, ciphertext] = encrypted.payload.split(".");
  assert.throws(() => parsePayload(`v2.${nonce}.${ciphertext}`));
  assert.throws(() => parsePayload(`v1.${nonce}`));
  assert.throws(() => parsePayload(`v1.*.${ciphertext}`));
  assert.throws(() => parsePayload(`v1.${bytesToBase64Url(new Uint8Array(11))}.${ciphertext}`));
  assert.throws(() => parsePayload(`v1.${nonce}.${bytesToBase64Url(new Uint8Array(271))}`));
  assert.throws(() => parsePayload("a".repeat(MAX_FRAGMENT_LENGTH + 1)));
});

test("AES-GCM rejects a wrong key, ciphertext, nonce, and AAD", async () => {
  const encrypted = await encryptMessage("authenticated");
  const other = await encryptMessage("other key");
  await assert.rejects(decryptMessage(encrypted.payload, other.secretKey));

  const ciphertextParts = encrypted.payload.split(".");
  ciphertextParts[2] = `${ciphertextParts[2][0] === "A" ? "B" : "A"}${ciphertextParts[2].slice(1)}`;
  await assert.rejects(decryptMessage(ciphertextParts.join("."), encrypted.secretKey));

  const nonceParts = encrypted.payload.split(".");
  nonceParts[1] = `${nonceParts[1][0] === "A" ? "B" : "A"}${nonceParts[1].slice(1)}`;
  await assert.rejects(decryptMessage(nonceParts.join("."), encrypted.secretKey));

  const { nonce, ciphertext } = parsePayload(encrypted.payload);
  const key = await crypto.subtle.importKey("raw", base64UrlToBytes(encrypted.secretKey), { name: "AES-GCM" }, false, ["decrypt"]);
  await assert.rejects(crypto.subtle.decrypt({
    name: "AES-GCM",
    iv: nonce,
    additionalData: new TextEncoder().encode("copycat:v2"),
    tagLength: 128
  }, key, ciphertext));
});

test("a retained valid payload and key can be replayed", async () => {
  const encrypted = await encryptMessage("not globally one-time");
  assert.equal(await decryptMessage(encrypted.payload, encrypted.secretKey), "not globally one-time");
  assert.equal(await decryptMessage(encrypted.payload, encrypted.secretKey), "not globally one-time");
});

test("timer display rounds up and never shows negative time", () => {
  assert.equal(formatRemaining(30_000), "00:30");
  assert.equal(formatRemaining(60_001), "01:01");
  assert.equal(formatRemaining(-1), "00:00");
});
