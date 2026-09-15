import { expect, test } from "@playwright/test";

async function createPaste(page, message) {
  await page.goto("/copycat/");
  await page.getByLabel("Сообщение").fill(message);
  await page.getByRole("button", { name: "Отправить" }).click();
  return {
    link: await page.locator("#paste-link").textContent(),
    password: await page.locator("#paste-password").textContent()
  };
}

function mutatePart(link, partIndex) {
  const url = new URL(link);
  const parts = url.hash.slice(1).split(".");
  parts[partIndex] = `${parts[partIndex][0] === "A" ? "B" : "A"}${parts[partIndex].slice(1)}`;
  url.hash = parts.join(".");
  return url.href;
}

async function openSharedLink(page, link) {
  // A recipient starts in a separate browsing context, rather than changing the
  // hash on the sender's already-running result view.
  await page.goto("about:blank");
  await page.goto(link);
}

test("sender copies exactly the URL and separate 256-bit key", async ({ page }) => {
  const { link, password } = await createPaste(page, "секрет");
  expect(password).toMatch(/^[A-Za-z0-9_-]{43}$/);
  expect(link).not.toContain(password);
  expect(new URL(link).search).toBe("");
  expect(new URL(link).hash).toMatch(/^#v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  await page.getByRole("button", { name: "Копировать" }).click();
  await expect(page.locator("#copy-status")).toHaveText("Скопировано");
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(`${link}\n${password}`);
});

test("successful read clears the fragment and refresh removes plaintext", async ({ page }) => {
  const message = "Строка 1\nСтрока 2 👋";
  const { link, password } = await createPaste(page, message);
  await openSharedLink(page, link);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Открыть" }).click();
  await expect(page.locator("#plaintext")).toHaveText(message);
  await expect(page).toHaveURL(/\/copycat\/$/);
  await page.reload();
  await expect(page.getByLabel("Сообщение")).toBeVisible();
  await expect(page.locator("#plaintext")).toBeHidden();
});

test("wrong key leaves the fragment available for a retry", async ({ page }) => {
  const { link, password } = await createPaste(page, "retry me");
  await openSharedLink(page, link);
  const originalHash = await page.evaluate(() => location.hash);
  const wrong = `${password[0] === "A" ? "B" : "A"}${password.slice(1)}`;
  await page.getByLabel("Password").fill(wrong);
  await page.getByRole("button", { name: "Открыть" }).click();
  await expect(page.locator("#unlock-error")).toHaveText("Не удалось открыть");
  expect(await page.evaluate(() => location.hash)).toBe(originalHash);
  await expect(page.locator("#plaintext")).toBeHidden();
});

test("malformed, modified ciphertext, and modified nonce never reveal data", async ({ page }) => {
  const { link, password } = await createPaste(page, "authenticated");
  for (const candidate of [new URL("#broken", link).href, mutatePart(link, 2), mutatePart(link, 1)]) {
    await openSharedLink(page, candidate);
    if (candidate.endsWith("#broken")) {
      await expect(page.getByRole("button", { name: "Открыть" })).toBeDisabled();
    } else {
      await page.getByLabel("Password").fill(password);
      await page.getByRole("button", { name: "Открыть" }).click();
    }
    await expect(page.locator("#plaintext")).toBeHidden();
    expect(await page.evaluate(() => location.hash)).not.toBe("");
  }
});

test("paste HTML is rendered as inert text", async ({ page }) => {
  const xss = "<script>alert(1)</script>\n<img src=x onerror=alert(1)>";
  const dialogs = [];
  page.on("dialog", async (dialog) => { dialogs.push(dialog.message()); await dialog.dismiss(); });
  const { link, password } = await createPaste(page, xss);
  await openSharedLink(page, link);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Открыть" }).click();
  await expect(page.locator("#plaintext")).toHaveText(xss);
  expect(dialogs).toEqual([]);
  expect(await page.locator("#plaintext script, #plaintext img").count()).toBe(0);
});

test("equal messages generate distinct keys, nonces, and ciphertext", async ({ page }) => {
  const first = await createPaste(page, "same");
  await page.reload();
  const second = await createPaste(page, "same");
  expect(second.password).not.toBe(first.password);
  expect(second.link).not.toBe(first.link);
  const firstParts = new URL(first.link).hash.split(".");
  const secondParts = new URL(second.link).hash.split(".");
  expect(secondParts[1]).not.toBe(firstParts[1]);
  expect(secondParts[2]).not.toBe(firstParts[2]);
});

test("no secret-bearing or third-party request occurs", async ({ page }) => {
  const requests = [];
  page.on("request", (request) => requests.push({ method: request.method(), url: request.url() }));
  const { link, password } = await createPaste(page, "network secret");
  await openSharedLink(page, link);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Открыть" }).click();
  await page.waitForTimeout(100);
  expect(requests.length).toBeGreaterThan(0);
  for (const request of requests) {
    expect(request.method).toBe("GET");
    expect(new URL(request.url).origin).toBe("http://127.0.0.1:4173");
    expect(request.url).not.toContain("#");
    expect(request.url).not.toContain(password);
    expect(request.url).not.toContain("network%20secret");
  }
});
