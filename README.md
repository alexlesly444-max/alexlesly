# Secure Paste / Burn After Open

Статическое приложение [`/copycat/`](./copycat/) шифрует и расшифровывает текст в браузере. Оно рассчитано на GitHub Pages и не имеет application backend, API, базы записок, аналитики или внешних runtime-зависимостей.

> Будущее P2P-направление описано отдельно в
> [Burner Messenger Architecture v0.1](./docs/burner-messenger-architecture.md). Оно не является частью работающего Secure Paste.

## Architecture

1. Отправитель вводит текст. Браузер создаёт новый случайный AES key и nonce, добавляет byte-level padding и локально шифрует текст.
2. URL получает только versioned encrypted payload во fragment. Отдельный ключ расшифрования отображается рядом и никогда автоматически не добавляется в URL.
3. Получатель открывает ссылку, вручную вводит ключ и локально расшифровывает данные.
4. После успешной аутентифицированной расшифровки fragment немедленно удаляется через `history.replaceState`.
5. Пользователь вручную запускает Burn либо заранее выбирает локальный timer на 30 секунд, 1 минуту или 5 минут. Burn очищает DOM и доступные приложению ссылки на чувствительные значения.

Состояния UI следуют lifecycle `EMPTY → CREATED` для отправителя и `LOCKED → DECRYPTED → BURNED` для получателя. После `BURNED` можно перейти в новое состояние `EMPTY`.

## Cryptographic design

- Web Crypto API, AES-256-GCM.
- Новый 32-byte key создаётся каждым вызовом `crypto.getRandomValues`; он напрямую импортируется как raw AES key без KDF. UI называет его **ключом расшифрования**, а не паролем.
- Новый независимый 96-bit nonce создаётся `crypto.getRandomValues` для каждого шифрования. Nonce не выводится из текста и не используется повторно с тем же key.
- Стандартный 128-bit authentication tag проверяет key, nonce, ciphertext и AAD.
- AAD — UTF-8 bytes строки `copycat:v1`; это аутентифицирует версию формата.
- Plaintext сначала кодируется UTF-8, затем дополняется нулевыми bytes до bucket 256, 512, 1024, …, 65536 bytes. Первые четыре зашифрованных bytes содержат исходную длину.

Padding уменьшает точность утечки длины, но не устраняет анализ размера URL, timing, browser history или локальных артефактов.

## Payload format

```text
v1.<nonce-base64url>.<ciphertext-and-gcm-tag-base64url>
```

- `v1` — единственная поддерживаемая версия.
- `nonce` — ровно 12 bytes.
- ciphertext включает padded plaintext и 16-byte GCM authentication tag.
- допустимый размер padded plaintext — power-of-two bucket от 256 до 65536 bytes;
- исходный plaintext ограничен 48 KiB UTF-8 bytes;
- fragment ограничен 100 000 символами **до** Base64URL decoding;
- Base64URL принимается только в canonical unpadded форме с алфавитом `A-Z a-z 0-9 _ -`.

Parser отклоняет неизвестные версии, лишние/пропущенные части, неправильный Base64URL, неверный nonce, невозможный размер ciphertext и oversized fragment. Пользователь видит одну generic error, без различения неправильного key и повреждённого payload.

## Local burn semantics

**Burn after open означает best-effort локальное уничтожение текущего отображённого plaintext и доступного приложению состояния.** После успешного decrypt URL fragment уже удалён. Burn дополнительно:

- останавливает auto-burn timer;
- удаляет plaintext из DOM;
- очищает key/link/payload fields;
- очищает доступные JavaScript references;
- оставляет нейтральный экран.

Auto-burn начинается только после успешной расшифровки и выполняет тот же cleanup. JavaScript не может гарантировать физическое стирание strings/bytes: runtime, браузер и ОС управляют памятью и могли создать копии.

Это **не** cryptographically enforced global one-time access. Любой, кто сохранил исходные ciphertext и key, может расшифровать их повторно, в том числе другим или изменённым клиентом.

## Security guarantees

При условии, что загруженные static assets не подменены и endpoint не скомпрометирован:

- plaintext и key обрабатываются локально;
- URL содержит ciphertext и nonce, но не key или plaintext;
- URL fragment обычно не входит в HTTP request к GitHub Pages;
- приложение не выполняет `fetch`, XHR, WebSocket, beacon или telemetry requests;
- plaintext выводится только через `textContent`, без HTML/Markdown interpretation;
- AES-GCM fail-closed отклоняет неправильный key или изменённые nonce/AAD/ciphertext;
- CSP запрещает сетевые подключения и remote scripts/styles/fonts.

Для более высокой конфиденциальности ссылку и ключ следует передавать разными каналами.

## Non-goals

Приложение не гарантирует:

- глобальное «прочитать ровно один раз»;
- удаление копии у получателя;
- защиту от screenshots, screen recording, clipboard managers или browser extensions;
- анонимность, сокрытие IP или traffic analysis;
- безопасность скомпрометированного endpoint;
- отзыв уже переданных ссылки и ключа;
- гарантированное удаление из RAM, swap, crash dumps, backups или browser/OS artifacts.

Browser storage (`localStorage`, `sessionStorage`, IndexedDB, cookies) намеренно не используется как фиктивное доказательство consumption.

## Browser and OS limitations

- Web Crypto и Clipboard API требуют secure context; GitHub Pages предоставляет HTTPS.
- Clipboard permission и поведение различаются между Chromium, Firefox и Safari.
- History, extensions, screenshots и OS-level diagnostics находятся за пределами контроля приложения.
- Meta CSP полезен на GitHub Pages, но не равноценен CSP/security headers в HTTP response.
- Best-effort buffer zeroing не гарантирует удаление оптимизированных или скопированных runtime values.

## Deployment

GitHub Pages должен публиковать репозиторий как статические файлы. `/copycat/index.html` использует только относительные `./app.js` и `./styles.css`, поэтому работает и под project subdirectory. Не добавляйте analytics, service worker, remote CDN или runtime API без повторного пересмотра threat model и CSP.

## Testing

```bash
npm ci
npx playwright install --with-deps chromium
npm test
```

- `npm run test:copycat` проверяет Base64URL, padding, Unicode, empty/max size policy, strict parsing, AES-GCM authentication, wrong key/AAD, corruption, oversized fragments и повторное использование сохранённых payload/key.
- `npm run test:e2e` проверяет реальный Chromium flow: точность UI claims, раздельный clipboard, decrypt, fragment removal, XSS inertness, manual Burn, auto-burn, timer cancellation, idempotent Burn, malformed input и отсутствие secret-bearing/third-party requests.
- GitHub Actions запускает оба набора для push и pull request.

Playwright static server существует только для тестов и не является application backend.

См. также [`SECURITY.md`](./SECURITY.md).
