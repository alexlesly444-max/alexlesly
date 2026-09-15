const VERSION = "v1";
const FORMAT_AAD = new TextEncoder().encode("copycat:v1");
const HEADER_BYTES = 4;
const GCM_TAG_BYTES = 16;
const MIN_PADDED_BYTES = 256;
const MAX_PADDED_BYTES = 65_536;

export const MAX_PLAINTEXT_BYTES = 48 * 1024;
export const MAX_FRAGMENT_LENGTH = 100_000;
export const Lifecycle = Object.freeze({
  EMPTY: "EMPTY",
  CREATED: "CREATED",
  LOCKED: "LOCKED",
  DECRYPTED: "DECRYPTED",
  BURNED: "BURNED"
});

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
  const standard = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  let bytes;
  try {
    bytes = Uint8Array.from(atob(standard), (character) => character.charCodeAt(0));
  } catch {
    throw new Error("Invalid Base64URL");
  }
  if (bytesToBase64Url(bytes) !== value) throw new Error("Non-canonical Base64URL");
  return bytes;
}

function paddedLength(contentLength) {
  const required = contentLength + HEADER_BYTES;
  let bucket = MIN_PADDED_BYTES;
  while (bucket < required) bucket *= 2;
  if (bucket > MAX_PADDED_BYTES) throw new Error("Message too large");
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
  if (padded.length < MIN_PADDED_BYTES || padded.length > MAX_PADDED_BYTES || (padded.length & (padded.length - 1)) !== 0) {
    throw new Error("Invalid padding bucket");
  }
  const length = new DataView(padded.buffer, padded.byteOffset, padded.byteLength).getUint32(0, false);
  if (length > MAX_PLAINTEXT_BYTES || length + HEADER_BYTES > padded.length) throw new Error("Invalid padding length");
  for (let index = length + HEADER_BYTES; index < padded.length; index += 1) {
    if (padded[index] !== 0) throw new Error("Invalid padding");
  }
  return padded.slice(HEADER_BYTES, HEADER_BYTES + length);
}

export function parsePayload(fragment) {
  if (typeof fragment !== "string" || fragment.length === 0 || fragment.length > MAX_FRAGMENT_LENGTH) {
    throw new Error("Invalid fragment size");
  }
  const parts = fragment.split(".");
  if (parts.length !== 3 || parts[0] !== VERSION) throw new Error("Unsupported or malformed payload");
  const nonce = base64UrlToBytes(parts[1]);
  const ciphertext = base64UrlToBytes(parts[2]);
  const paddedBytes = ciphertext.length - GCM_TAG_BYTES;
  if (nonce.length !== 12 || paddedBytes < MIN_PADDED_BYTES || paddedBytes > MAX_PADDED_BYTES || (paddedBytes & (paddedBytes - 1)) !== 0) {
    throw new Error("Invalid payload dimensions");
  }
  return { nonce, ciphertext };
}

export async function encryptMessage(message) {
  const plaintext = encoder.encode(message);
  if (plaintext.length === 0 || plaintext.length > MAX_PLAINTEXT_BYTES) throw new Error("Message size is invalid");

  const keyBytes = crypto.getRandomValues(new Uint8Array(32));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  try {
    const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt"]);
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: FORMAT_AAD, tagLength: 128 },
      key,
      addPadding(plaintext)
    ));
    return {
      secretKey: bytesToBase64Url(keyBytes),
      payload: `${VERSION}.${bytesToBase64Url(nonce)}.${bytesToBase64Url(ciphertext)}`
    };
  } finally {
    // Best effort only: JavaScript runtimes may retain copies outside this buffer.
    keyBytes.fill(0);
    plaintext.fill(0);
  }
}

export async function decryptMessage(payload, secretKey) {
  const { nonce, ciphertext } = parsePayload(payload);
  const keyBytes = base64UrlToBytes(secretKey.trim());
  if (keyBytes.length !== 32) throw new Error("Invalid key");
  try {
    const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
    const padded = new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: FORMAT_AAD, tagLength: 128 },
      key,
      ciphertext
    ));
    try {
      return decoder.decode(removePadding(padded));
    } finally {
      padded.fill(0);
    }
  } finally {
    keyBytes.fill(0);
  }
}

export function formatRemaining(milliseconds) {
  const seconds = Math.max(0, Math.ceil(milliseconds / 1000));
  return `${String(Math.floor(seconds / 60)).padStart(2, "0")}:${String(seconds % 60).padStart(2, "0")}`;
}

function setupPage() {
  const byId = (id) => document.getElementById(id);
  const views = ["compose-view", "result-view", "unlock-view", "message-view", "burned-view"];
  const initialFragment = location.hash.slice(1);
  const runtime = {
    state: initialFragment ? Lifecycle.LOCKED : Lifecycle.EMPTY,
    fragment: initialFragment,
    plaintext: "",
    generatedLink: "",
    generatedKey: "",
    timerId: null,
    timerDeadline: 0
  };

  function showView(id) {
    for (const view of views) byId(view).hidden = view !== id;
  }

  function removeFragment() {
    if (location.hash) history.replaceState(null, "", location.pathname + location.search);
  }

  function cancelTimer() {
    if (runtime.timerId !== null) clearInterval(runtime.timerId);
    runtime.timerId = null;
    runtime.timerDeadline = 0;
    byId("burn-timer").textContent = "";
    byId("burn-timer").hidden = true;
  }

  function clearSensitiveDom() {
    byId("message").value = "";
    byId("paste-link").textContent = "";
    byId("paste-secret-key").textContent = "";
    byId("secret-key").value = "";
    byId("plaintext").textContent = "";
    byId("copy-status").textContent = "";
    byId("unlock-error").textContent = "";
  }

  function burn() {
    if (runtime.state !== Lifecycle.DECRYPTED) return;
    cancelTimer();
    removeFragment();
    clearSensitiveDom();
    // Best-effort local cleanup; JS cannot guarantee erasure of runtime/OS copies.
    runtime.fragment = "";
    runtime.plaintext = "";
    runtime.generatedLink = "";
    runtime.generatedKey = "";
    runtime.state = Lifecycle.BURNED;
    showView("burned-view");
  }

  function startTimer(seconds) {
    cancelTimer();
    if (seconds === 0) return;
    runtime.timerDeadline = Date.now() + seconds * 1000;
    const update = () => {
      const remaining = runtime.timerDeadline - Date.now();
      if (remaining <= 0) {
        burn();
        return;
      }
      byId("burn-timer").textContent = `Локальное удаление через ${formatRemaining(remaining)}`;
      byId("burn-timer").hidden = false;
    };
    update();
    runtime.timerId = setInterval(update, 250);
  }

  byId("burn").addEventListener("click", burn);
  byId("start-over").addEventListener("click", () => {
    if (runtime.state !== Lifecycle.BURNED) return;
    runtime.state = Lifecycle.EMPTY;
    byId("compose-error").hidden = true;
    showView("compose-view");
    byId("message").focus();
  });

  if (initialFragment) {
    showView("unlock-view");
    try {
      parsePayload(initialFragment);
    } catch {
      byId("unlock-error").textContent = "Не удалось открыть";
      byId("unlock-error").hidden = false;
      byId("open").disabled = true;
    }
    byId("open").addEventListener("click", async () => {
      if (runtime.state !== Lifecycle.LOCKED) return;
      try {
        let plaintext = await decryptMessage(runtime.fragment, byId("secret-key").value);
        removeFragment();
        runtime.fragment = "";
        byId("secret-key").value = "";
        byId("unlock-error").hidden = true;
        runtime.plaintext = plaintext;
        byId("plaintext").textContent = plaintext;
        plaintext = "";
        runtime.state = Lifecycle.DECRYPTED;
        showView("message-view");
        startTimer(Number(byId("auto-burn").value));
      } catch {
        byId("unlock-error").textContent = "Не удалось открыть";
        byId("unlock-error").hidden = false;
      }
    });
    return;
  }

  showView("compose-view");
  byId("send").addEventListener("click", async () => {
    if (runtime.state !== Lifecycle.EMPTY) return;
    const error = byId("compose-error");
    try {
      const { secretKey, payload } = await encryptMessage(byId("message").value);
      runtime.generatedLink = `${location.origin}${location.pathname}#${payload}`;
      runtime.generatedKey = secretKey;
      runtime.state = Lifecycle.CREATED;
      byId("message").value = "";
      byId("paste-link").textContent = runtime.generatedLink;
      byId("paste-secret-key").textContent = runtime.generatedKey;
      error.hidden = true;
      showView("result-view");
    } catch {
      error.textContent = "Введите сообщение до 48 КБ";
      error.hidden = false;
    }
  });

  async function copyValue(value, successMessage) {
    try {
      await navigator.clipboard.writeText(value);
      byId("copy-status").textContent = successMessage;
    } catch {
      byId("copy-status").textContent = "Не удалось скопировать";
    }
  }

  byId("copy-link").addEventListener("click", () => copyValue(runtime.generatedLink, "Ссылка скопирована"));
  byId("copy-key").addEventListener("click", () => copyValue(runtime.generatedKey, "Ключ скопирован"));
  addEventListener("pagehide", () => {
    cancelTimer();
    runtime.plaintext = "";
  }, { once: true });
}

if (typeof document !== "undefined") setupPage();
