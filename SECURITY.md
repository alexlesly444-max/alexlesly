# Secure Paste security model

## Scope

`copycat/` — client-only encrypted paste viewer. Его security boundary включает неизменённые static HTML/CSS/JavaScript assets, Web Crypto implementation браузера и нескомпрометированный endpoint пользователя.

## Protected

- Каждый paste шифруется локально новым AES-256-GCM key и новым случайным 96-bit nonce.
- Key передаётся пользователем отдельно и не входит в сгенерированный URL.
- Hosting server получает запрос static page/assets, но не URL fragment, plaintext или отдельно переданный key.
- AES-GCM аутентифицирует ciphertext и format AAD; malformed/tampered input обрабатывается fail-closed.
- Plaintext отображается как текст, а restrictive CSP запрещает remote scripts и network connections.
- После decrypt fragment удаляется. Manual/automatic Burn выполняет best-effort cleanup DOM, timer и доступных application references.

## Not protected

- Сохранённые ciphertext и key можно расшифровать повторно. Local Burn не является global read-once enforcement.
- Получатель может сохранить, скопировать, сфотографировать или переслать plaintext.
- Browser extensions, clipboard/history tooling, malware, OS diagnostics, swap, backups и physical memory находятся вне контроля приложения.
- Компрометация GitHub account, deployment pipeline или опубликованного JavaScript позволяет изменить клиент и нарушает модель доверия.
- Ciphertext size bucket, время загрузки страницы, IP address и обычный static-asset traffic не скрываются.

## Local cleanup limitation

JavaScript не предоставляет гарантированное secure memory erasure. Код обнуляет доступные mutable byte buffers и удаляет DOM/application references, но strings, `CryptoKey` internals и runtime/OS copies могут сохраниться. Поэтому интерфейс использует термин **локальное удаление**, а не guaranteed deletion.

## Vulnerability reporting

Не публикуйте действующие secrets или paste URLs в issue. В отчёте укажите browser/version, точные шаги воспроизведения, ожидаемое и фактическое поведение. До появления отдельного private security contact используйте GitHub private vulnerability reporting, если оно включено для репозитория.
