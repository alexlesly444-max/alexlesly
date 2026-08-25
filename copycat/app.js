const VERSION = "v1";
const AAD = new TextEncoder().encode("copycat:v1");
const HEADER_BYTES = 4;
export const MAX_PLAINTEXT_BYTES = 48 * 1024;
export const MAX_FRAGMENT_LENGTH = 100_000;

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export function bytesToBase64Url(bytes) {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function base64UrlToBytes(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) throw new Error("Invalid Base64URL");
  const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function paddedLength(contentLength) {
  const required = contentLength + HEADER_BYTES;
  let bucket = 256;
  while (bucket < required) bucket *= 2;
  if (bucket > 65536) throw new Error("Message too large");
  return bucket;
}

export function addPadding(plaintext) {
  if (plaintext.length > MAX_PLAINTEXT_BYTES) throw new Error("Message too large");
  const padded = new Uint8Array(paddedLength(plaintext.length));
  new DataView(padded.buffer).setUint32(0, plaintext.length, false);
  padded.set(plaintext, HEADER_BYTES);
  return padded;
}

export function removePadding(padded) {
  if (padded.length < 256 || (padded.length & (padded.length - 1)) !== 0) throw new Error("Invalid padding bucket");
  const length = new DataView(padded.buffer, padded.byteOffset, padded.byteLength).getUint32(0, false);
  if (length > MAX_PLAINTEXT_BYTES || length + HEADER_BYTES > padded.length) throw new Error("Invalid padding length");
  for (let index = length + HEADER_BYTES; index < padded.length; index += 1) if (padded[index] !== 0) throw new Error("Invalid padding");
  return padded.slice(HEADER_BYTES, HEADER_BYTES + length);
}

export function parsePayload(fragment) {
  if (fragment.length > MAX_FRAGMENT_LENGTH) throw new Error("Fragment too large");
  const parts = fragment.split(".");
  if (parts.length !== 3 || parts[0] !== VERSION) throw new Error("Invalid payload format");
  const nonce = base64UrlToBytes(parts[1]);
  const ciphertext = base64UrlToBytes(parts[2]);
  if (nonce.length !== 12 || ciphertext.length < 272 || ciphertext.length > 65552) throw new Error("Invalid payload size");
  return { nonce, ciphertext };
}

export async function encryptMessage(message) {
  const plaintext = encoder.encode(message);
  if (plaintext.length === 0 || plaintext.length > MAX_PLAINTEXT_BYTES) throw new Error("Message size is invalid");
  const keyBytes = crypto.getRandomValues(new Uint8Array(32));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt"]);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: AAD, tagLength: 128 }, key, addPadding(plaintext)));
  return { password: bytesToBase64Url(keyBytes), payload: `${VERSION}.${bytesToBase64Url(nonce)}.${bytesToBase64Url(ciphertext)}` };
}

export async function decryptMessage(payload, password) {
  const { nonce, ciphertext } = parsePayload(payload);
  const keyBytes = base64UrlToBytes(password.trim());
  if (keyBytes.length !== 32) throw new Error("Invalid password");
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
  const padded = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: AAD, tagLength: 128 }, key, ciphertext));
  return decoder.decode(removePadding(padded));
}

function setupPage() {
  const byId = (id) => document.getElementById(id);
  const compose = byId("compose-view"), result = byId("result-view"), unlock = byId("unlock-view"), messageView = byId("message-view");
  let fragment = location.hash.slice(1);
  if (fragment) {
    compose.hidden = true;
    unlock.hidden = false;
    try { parsePayload(fragment); } catch { byId("unlock-error").textContent = "Не удалось открыть"; byId("unlock-error").hidden = false; byId("open").disabled = true; }
    byId("open").addEventListener("click", async () => {
      try {
        const plaintext = await decryptMessage(fragment, byId("password").value);
        history.replaceState(null, "", location.pathname + location.search);
        fragment = "";
        byId("password").value = "";
        unlock.hidden = true;
        byId("plaintext").textContent = plaintext;
        messageView.hidden = false;
      } catch { byId("unlock-error").textContent = "Не удалось открыть"; byId("unlock-error").hidden = false; }
    });
    return;
  }
  byId("send").addEventListener("click", async () => {
    const error = byId("compose-error");
    try {
      const { password, payload } = await encryptMessage(byId("message").value);
      const link = `${location.origin}${location.pathname}#${payload}`;
      compose.hidden = true;
      byId("paste-link").textContent = link;
      byId("paste-password").textContent = password;
      result.hidden = false;
      byId("copy").addEventListener("click", async () => {
        try { await navigator.clipboard.writeText(`${link}\n${password}`); byId("copy-status").textContent = "Скопировано"; } catch { byId("copy-status").textContent = "Не удалось скопировать"; }
      });
    } catch { error.textContent = "Введите сообщение до 48 КБ"; error.hidden = false; }
  });
}

if (typeof document !== "undefined") setupPage();
