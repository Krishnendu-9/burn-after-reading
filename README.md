# 🔥 Burn After Reading

Share a password, API key, or note through a link that works **exactly once**.
The message is encrypted at rest with AES-256-GCM and the database row is deleted
the instant the link is opened.

**Stack:** Node.js · Express 5 · better-sqlite3 · native `crypto` · EJS · Tailwind CSS 4 · Vite

---

## Quick start

```bash
npm install
npm run keygen          # prints a SECRET_KEY line
cp .env.example .env    # paste the key in
npm run dev             # http://localhost:3000
```

`npm run dev` runs `vite build --watch` and `node --watch server.js` side by side,
so both CSS and server changes reload automatically.

For production:

```bash
npm run build
npm start
```

## Tests

```bash
npm test
```

47 tests on Node's built-in runner, no framework. Each run gets a throwaway SQLite
file and a fresh key. They cover the guarantees the whole project rests on:

- a secret reveals exactly once, and the row is genuinely gone from disk after
- eight worker threads racing the same link — exactly one wins
- repeated `GET`s never burn it, and a `GET` is byte-identical whether the secret
  is live, burned, or never existed
- a cross-site `POST` can't burn it
- a wrong passphrase costs an attempt, not the secret; five wrong ones destroy it
- the operator's key alone cannot read a passphrase-protected secret
- a rotated key still reads secrets written under the previous one
- a malformed request body never reaches the logs, and the token never appears in
  a log line
- rate-limit counts survive a restart
- tampered ciphertext throws instead of returning altered plaintext

## Interface

- Dark/light theme with a header toggle, applied before first paint so there's no flash
- Live character counter with a fill bar, `Ctrl`/`⌘` + `Enter` to submit
- Selectable expiry (1 hour / 1 day / 1 week)
- Revealed secrets are blurred behind a click-to-reveal shade — the blur is added by
  JavaScript, so a visitor with scripts disabled still sees the (already burned) text
- One-tap copy with a clipboard fallback for non-HTTPS origins
- Respects `prefers-reduced-motion`
- Plays nicely with Dark Reader: the page carries a `darkreader-lock` meta tag so the
  extension steps aside for our own dark theme instead of re-tinting it, declares
  `color-scheme` so native widgets follow the active theme, and falls back to solid
  colours if an older build repaints the page anyway

## How it works

| Step | What happens |
| --- | --- |
| `GET /` | Renders the compose form. |
| `POST /api/secrets` | Encrypts the message with `crypto.createCipheriv` (AES-256-GCM), stores it under a UUID v4 token, returns `{ token, url, expiresInHours, protected }`. Accepts an optional `passphrase`. |
| `GET /healthz` | Liveness probe. `200` with `{"status":"ok"}`, or `503` if the database stops answering. |
| `GET /s/:token` | Renders the confirmation screen. Never touches the database — the same page comes back for every token. |
| `POST /s/:token` | The burn. Runs `DELETE ... RETURNING` — one atomic statement — then decrypts with `crypto.createDecipheriv` and renders the plaintext. |
| Any later `POST` | 404 → the "self-destructed" screen. |

The stored payload is `iv:authTag:ciphertext`, all hex. A fresh 96-bit IV is
generated per secret and the GCM auth tag means a tampered row fails to decrypt
rather than returning garbage.

### Why the reveal takes two steps

Slack, Teams, WhatsApp, iMessage and most mail scanners fetch URLs server-side to
build link previews. If `GET` performed the burn, a preview bot would destroy the
secret before the recipient ever clicked — and chat is exactly where these links
get sent. So the destroying is done by a same-origin `POST` from the confirmation
form, and preview bots don't issue POSTs.

The form is plain HTML, so the flow works with JavaScript disabled.

### Why `GET` doesn't look the secret up

The obvious version of that handler checks whether the row exists and 404s if it
doesn't. That quietly hands out a read receipt: anyone holding a link — including
whoever intercepted it — could poll the URL to learn whether the secret was still
waiting, silently, without burning anything.

So `GET /s/:token` never queries the database at all. It renders the same
confirmation page for a live token, an expired one, a burned one and one that
never existed. The only way to find out which it is, is to destroy it.

The cost is that the confirmation screen can't show when the secret was created
or when it expires, and a dead link takes one click to discover.

### Why the burn is one transaction

Fetch, unseal and delete all happen inside a single `BEGIN IMMEDIATE`
transaction. The write lock is taken *before* the read, so two people submitting
the same link at the same moment are serialised rather than both being handed the
plaintext.

This is not theoretical. Swapping in the obvious `SELECT`-then-`DELETE` version
and running the test suite's 8-thread race gives:

```
exactly one thread may burn the secret, got 7
```

Seven of eight callers received the same secret. There's a test that races eight
worker threads, each on its own SQLite connection, released together through an
`Atomics` barrier.

### Optional passphrase

A sender can attach a passphrase. The message is then sealed with a key derived
from it via `scrypt`, and *that* is sealed with the server key as usual — so the
operator can no longer read it. Unwrapping the outer layer with `SECRET_KEY`
yields nothing but the inner ciphertext, which a test asserts directly.

A wrong passphrase does **not** destroy the secret; it costs one of five
attempts, so a typo is survivable but an online guessing attack is not.

## Project layout

```
server.js              Express app: routes, middleware, error handling
src/db.js              better-sqlite3 setup, schema, prepared statements
src/crypto.js          encrypt() / decrypt() — AES-256-GCM
src/security.js        CSP with a per-request nonce, plus the other headers
src/limits.js          per-IP rate limiters
src/assets.js          resolves Vite's hashed filenames from the manifest
src/client/main.js     form submission, reveal, theme, copy-to-clipboard
src/client/style.css   Tailwind entry + component utilities
views/                 index · reveal · secret · destroyed · too-many (EJS)
scripts/keygen.js      generates a SECRET_KEY
```

## Schema

```sql
CREATE TABLE secrets (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  token       TEXT    NOT NULL UNIQUE,   -- UUID v4, the URL segment
  payload     TEXT    NOT NULL,          -- iv:authTag:ciphertext
  created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
  expires_at  TEXT    NOT NULL           -- unread secrets die on their own too
);
```

An hourly sweep deletes expired rows so unread secrets don't linger on disk.

## Environment

| Variable | Purpose |
| --- | --- |
| `SECRET_KEY` | 32 bytes as 64 hex chars. Generate with `npm run keygen`. |
| `SECRET_KEY_PREVIOUS` | Optional, comma-separated. Old keys kept for decryption only, so rotation doesn't orphan existing secrets. |
| `MAX_SECRETS` | Ceiling on stored rows, default `10000`. Bounds disk use against traffic spread across many addresses. |
| `LOG_REQUESTS` | One line per request with the token redacted. `false` to silence. |
| `LOG_FORMAT` | `text` (default, readable in a terminal) or `json` (one object per line, for a log aggregator). |
| `PORT` | Default `3000`. |
| `BASE_URL` | Public origin used to build shareable links. |
| `DATABASE_PATH` | Default `data/app.db`, relative to the project root. |
| `REPO_URL` | Optional. Shows a "Source" link in the header; hidden when unset. |
| `TRUST_PROXY` | How many reverse-proxy hops to trust. **Off by default, and it must stay off unless a proxy really is in front** — otherwise a client can forge `X-Forwarded-For` and bypass every rate limit. Set to `1` on Render, Fly, Railway or behind nginx. |

## Docker

With Compose — it reads your existing `.env`, so there's nothing else to wire up:

```bash
docker compose up -d --build
docker compose logs -f
docker compose down      # stops; the volume and your secrets survive
docker compose down -v   # stops and deletes the database too
```

Or plain Docker:

```bash
docker build -t burn-after-reading .
docker run -d -p 3000:3000 \
  -e SECRET_KEY=$(node scripts/keygen.js | grep -o '[0-9a-f]\{64\}') \
  -e BASE_URL=https://your-domain \
  -e TRUST_PROXY=1 \
  -v bar-data:/app/data \
  burn-after-reading
```

Multi-stage: the build stage compiles the front end, the runtime stage installs
production dependencies only. Runs as the unprivileged `node` user, and declares a
`HEALTHCHECK` against `/healthz`.

**Mount a volume at `/app/data`** — that's where SQLite lives, and without one
every unread secret dies with the container.

`CMD` is in exec form so node runs as PID 1 and receives `SIGTERM` directly;
`docker stop` then triggers the graceful shutdown rather than a hard kill.

## Threat model

Being specific about this matters more than the encryption itself — a tool like
this earns misplaced trust when it stays vague.

**What it protects against**

- **Retention.** The secret stops existing after one read, or after its TTL,
  instead of sitting in a chat log or inbox indefinitely.
- **Database theft.** Rows are AES-256-GCM ciphertext; a stolen `app.db` or a
  leaked backup is useless without `SECRET_KEY`, which lives outside it.
- **Silent interception.** Reads are destructive and single-use, so if someone
  gets there first the recipient sees "already destroyed" — you find out.
- **Tampering.** GCM authenticates the ciphertext; an edited row fails to
  decrypt rather than returning altered plaintext.
- **Preview bots.** Link unfurlers can't burn a secret, because burning needs a
  POST.
- **Silent read receipts.** `GET` returns an identical page for every token, so
  probing a link tells an observer nothing about whether it has been read. (One
  bounded exception applies to passphrase-protected secrets — see below.)

**What it does not protect against**

- **The operator — unless you set a passphrase.** `SECRET_KEY` lives on the
  server, so without a passphrase whoever runs the instance can decrypt anything
  in the database. With one, they cannot: the inner layer needs a key derived from
  the passphrase, which is never sent to the server in storable form. Note this is
  still not full zero-knowledge — the passphrase does reach the server in the
  reveal request, it is simply never written down. True zero-knowledge means
  encrypting in the browser with the key in the URL fragment.
- **Whoever holds the link**, if no passphrase is set. The URL is a bearer token:
  whoever reads it first gets the secret. A passphrase is what makes the link
  alone insufficient.
- **Your transport.** If the channel carrying the link is compromised, so is the
  secret. This shortens the window; it doesn't secure the delivery.
- **A malicious recipient.** Once revealed, the plaintext is theirs to keep.
- **Probing a passphrase-protected link — up to five times.** A wrong passphrase
  deliberately does *not* burn the secret, so that a typo is survivable. The cost
  is that `POST` then answers differently depending on whether the secret is
  there:

  ```
  secret exists, wrong passphrase : 401
  token never existed             : 404
  ```

  So someone holding the link can confirm it is still unread without consuming
  it. This is a real, knowing weakening of the no-read-receipt property above,
  and it applies **only** to passphrase-protected secrets — for an unprotected
  one, any `POST` burns it, so there is no way to look without destroying.

  It is bounded rather than open-ended: the fifth wrong attempt destroys the
  secret, so a prober gets four silent checks and then annihilates the thing
  they were watching. The alternative — answering 404 for a wrong passphrase —
  would mean a single typo silently destroys the secret from the user's point of
  view, which is worse. If you need the stronger property, don't set a
  passphrase.
- **Server-side logs.** Your reverse proxy or platform may log request paths,
  which include the token. The token is worthless after the burn, but it exists
  in those logs until they rotate.

## Other notes

- **Rate limits** are per-IP over a 15-minute window: 20 creates, 60 reveals, 300
  requests overall. Tune them in `src/limits.js`. Counts live in SQLite rather
  than memory, so they survive a restart and stay correct across processes.
- **Fonts are bundled**, not loaded from Google — opening a secret link shouldn't
  announce itself to a third party. It also keeps the CSP locked to `'self'`.
- **SQLite and ephemeral disks.** On platforms with ephemeral filesystems
  (Heroku, default Fly machines), mount a volume or `data/app.db` disappears on
  every deploy.
- **Put it behind HTTPS**, and set `TRUST_PROXY=1` when you do. HSTS is only sent
  when the request arrives over TLS, and with TLS terminating at a proxy the app
  only sees that if it trusts the forwarded headers.
- **`GET /healthz`** returns `{"status":"ok"}` with a `200`, or `503` if the
  database has stopped answering. It sits above the rate limiter, so frequent
  polling by the platform can't exhaust the request budget.
- **Nothing from a request body is ever logged.** Malformed payloads are answered
  with a `400` and logged by error type only — the parse error carries the raw
  body, which on this app is the plaintext secret.

## License

MIT
