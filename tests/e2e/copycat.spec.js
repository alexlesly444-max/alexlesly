import { expect, test } from "@playwright/test";

async function createPaste(page, message) {
  await page.goto("/copycat/");
  await page.getByLabel("Сообщение").fill(message);
  await page.getByRole("button", { name: "Зашифровать" }).click();
  return {
    link: await page.locator("#paste-link").textContent(),
    secretKey: await page.locator("#paste-secret-key").textContent()
  };
}

async function openSharedLink(page, link, secretKey, autoBurn = "0") {
  await page.goto("about:blank");
  await page.goto(link);
  await page.getByLabel("Ключ расшифрования").fill(secretKey);
  await page.getByLabel("Локальное автоудаление после открытия").selectOption(autoBurn);
  await page.getByRole("button", { name: "Открыть" }).click();
}

function mutatePart(link, partIndex) {
  const url = new URL(link);
  const parts = url.hash.slice(1).split(".");
  parts[partIndex] = `${parts[partIndex][0] === "A" ? "B" : "A"}${parts[partIndex].slice(1)}`;
  url.hash = parts.join(".");
  return url.href;
}

test("UI states the local-only threat model", async ({ page }) => {
  await page.goto("/copycat/");
  await expect(page.getByText("Текст шифруется в этом браузере.")).toBeVisible();
  await expect(page.getByText("Сохранённые ссылка и ключ позволяют открыть записку снова.")).toBeVisible();
  await expect(page.getByText(/только локальную очистку/)).toBeVisible();
});

test("sender copies the link and 256-bit decryption key separately", async ({ page }) => {
  const { link, secretKey } = await createPaste(page, "секрет");
  expect(secretKey).toMatch(/^[A-Za-z0-9_-]{43}$/);
  expect(link).not.toContain(secretKey);
  expect(new URL(link).search).toBe("");
  expect(new URL(link).hash).toMatch(/^#v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);

  await page.getByRole("button", { name: "Копировать ссылку" }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(link);
  await expect(page.locator("#copy-status")).toHaveText("Ссылка скопирована");

  await page.getByRole("button", { name: "Копировать ключ" }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(secretKey);
  await expect(page.locator("#copy-status")).toHaveText("Ключ скопирован");
});

test("successful decrypt clears the fragment and never auto-copies plaintext", async ({ page }) => {
  const message = "Строка 1\nСтрока 2 👋";
  const { link, secretKey } = await createPaste(page, message);
  await page.evaluate(() => navigator.clipboard.writeText("unchanged"));
  await openSharedLink(page, link, secretKey);
  await expect(page.locator("#plaintext")).toHaveText(message);
  await expect(page).toHaveURL(/\/copycat\/$/);
  await expect(page.locator("#secret-key")).toHaveValue("");
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("unchanged");

  await page.reload();
  await expect(page.getByLabel("Сообщение")).toBeVisible();
  await expect(page.locator("#plaintext")).toBeHidden();
});

test("wrong key leaves the fragment and plaintext hidden", async ({ page }) => {
  const { link, secretKey } = await createPaste(page, "retry me");
  await page.goto("about:blank");
  await page.goto(link);
  const originalHash = await page.evaluate(() => location.hash);
  const wrong = `${secretKey[0] === "A" ? "B" : "A"}${secretKey.slice(1)}`;
  await page.getByLabel("Ключ расшифрования").fill(wrong);
  await page.getByRole("button", { name: "Открыть" }).click();
  await expect(page.locator("#unlock-error")).toHaveText("Не удалось открыть");
  expect(await page.evaluate(() => location.hash)).toBe(originalHash);
  await expect(page.locator("#plaintext")).toBeHidden();
});

test("malformed, truncated, modified ciphertext, and modified nonce fail closed", async ({ page }) => {
  const { link, secretKey } = await createPaste(page, "authenticated");
  await openSharedLink(page, link, secretKey);
  await expect(page.locator("#plaintext")).toHaveText("authenticated");
  const url = new URL(link);
  const parts = url.hash.slice(1).split(".");
  const candidates = [
    new URL("#broken", link).href,
    new URL(`#v2.${parts[1]}.${parts[2]}`, link).href,
    new URL(`#v1.${parts[1]}`, link).href,
    mutatePart(link, 2),
    mutatePart(link, 1)
  ];

  for (const candidate of candidates) {
    await page.goto("about:blank");
    await page.goto(candidate);
    const open = page.getByRole("button", { name: "Открыть" });
    if (await open.isEnabled()) {
      await page.getByLabel("Ключ расшифрования").fill(secretKey);
      await open.click();
    }
    await expect(page.locator("#plaintext")).toBeHidden();
    await expect(page.locator("#plaintext")).toHaveText("");
    expect(await page.evaluate(() => location.hash)).not.toBe("");
  }
});

test("decrypted HTML remains inert text", async ({ page }) => {
  const xss = "<script>alert(1)</script>\n<img src=x onerror=alert(1)>";
  const dialogs = [];
  page.on("dialog", async (dialog) => { dialogs.push(dialog.message()); await dialog.dismiss(); });
  const { link, secretKey } = await createPaste(page, xss);
  await openSharedLink(page, link, secretKey);
  await expect(page.locator("#plaintext")).toHaveText(xss);
  expect(dialogs).toEqual([]);
  expect(await page.locator("#plaintext script, #plaintext img").count()).toBe(0);
});

test("manual Burn performs idempotent best-effort local cleanup", async ({ page }) => {
  const { link, secretKey } = await createPaste(page, "burn me");
  await openSharedLink(page, link, secretKey);
  await page.evaluate(() => { location.hash = "residual-test-fragment"; });
  await page.getByRole("button", { name: "Удалить локально" }).click();

  await expect(page.locator("#burned-view")).toBeVisible();
  await expect(page.locator("#plaintext")).toHaveText("");
  await expect(page.locator("#secret-key")).toHaveValue("");
  await expect(page.locator("#paste-link")).toHaveText("");
  await expect(page.locator("#paste-secret-key")).toHaveText("");
  await expect(page).toHaveURL(/\/copycat\/$/);

  await page.locator("#burn").evaluate((button) => { button.click(); button.click(); });
  await expect(page.locator("#burned-view")).toBeVisible();
});

test("auto-burn starts after decrypt and performs the same cleanup", async ({ page }) => {
  await page.clock.install();
  const { link, secretKey } = await createPaste(page, "short lived");
  await openSharedLink(page, link, secretKey, "30");
  await expect(page.locator("#burn-timer")).toContainText("00:30");
  await page.clock.fastForward(31_000);
  await expect(page.locator("#burned-view")).toBeVisible();
  await expect(page.locator("#plaintext")).toHaveText("");
  await expect(page.locator("#burn-timer")).toBeHidden();
});

test("manual Burn cancels a pending auto-burn timer", async ({ page }) => {
  await page.clock.install();
  const { link, secretKey } = await createPaste(page, "cancel timer");
  await openSharedLink(page, link, secretKey, "30");
  await page.clock.fastForward(5_000);
  await page.getByRole("button", { name: "Удалить локально" }).click();
  await page.clock.fastForward(60_000);
  await expect(page.locator("#burned-view")).toBeVisible();
  await expect(page.locator("#burn-timer")).toBeHidden();
});

test("a retained payload and key can be opened again in another viewer", async ({ page }) => {
  const { link, secretKey } = await createPaste(page, "replay is possible");
  await openSharedLink(page, link, secretKey);
  await expect(page.locator("#plaintext")).toHaveText("replay is possible");
  await openSharedLink(page, link, secretKey);
  await expect(page.locator("#plaintext")).toHaveText("replay is possible");
});

test("equal messages generate distinct keys, nonces, and ciphertext", async ({ page }) => {
  const first = await createPaste(page, "same");
  await page.reload();
  const second = await createPaste(page, "same");
  expect(second.secretKey).not.toBe(first.secretKey);
  expect(second.link).not.toBe(first.link);
  const firstParts = new URL(first.link).hash.split(".");
  const secondParts = new URL(second.link).hash.split(".");
  expect(secondParts[1]).not.toBe(firstParts[1]);
  expect(secondParts[2]).not.toBe(firstParts[2]);
});

test("no secret-bearing or third-party request occurs", async ({ page }) => {
  const requests = [];
  page.on("request", (request) => requests.push({ method: request.method(), url: request.url() }));
  const { link, secretKey } = await createPaste(page, "network secret");
  await openSharedLink(page, link, secretKey);
  await page.waitForTimeout(100);
  expect(requests.length).toBeGreaterThan(0);
  for (const request of requests) {
    expect(request.method).toBe("GET");
    expect(new URL(request.url).origin).toBe("http://127.0.0.1:4173");
    expect(request.url).not.toContain("#");
    expect(request.url).not.toContain(secretKey);
    expect(request.url).not.toContain("network%20secret");
  }
});
