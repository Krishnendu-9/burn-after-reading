# 🔥 Burn After Reading

Share a password, API key, or note through a link that works **exactly once**.
The message is encrypted in your browser with AES-256-GCM before it is sent, the
key travels only in the link's `#fragment`, and the database row is deleted the
instant the link is opened.

**Stack:** Node.js · Express 5 · better-sqlite3 · native `crypto` · WebCrypto · EJS · Tailwind CSS 4 · Vite

---

## Quick start

Requires Node.js 22 or newer.

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

71 tests on Node's built-in runner, no framework. Each run gets a throwaway SQLite
file and a fresh key. They cover the guarantees the whole project rests on:

- a secret reveals exactly once, and the row is genuinely gone from disk after
- eight worker threads racing the same link — exactly one wins; the same holds
  for simultaneous correct passphrases, the widest race window in the app
- repeated `GET`s never burn it, and a `GET` is byte-identical whether the secret
  is live, burned, or never existed
- a cross-site `POST` can't burn it
- a wrong passphrase costs an attempt, not the secret; five wrong ones destroy it,
  and simultaneous wrong guesses are each counted
- an end-to-end secret round-trips through the same `e2e.js` the browser runs,
  and the server's key alone recovers nothing but browser ciphertext
- the operator's key alone cannot read a passphrase-protected secret
- a rotated key still reads secrets written under the previous one, and a secret
  the server can no longer decrypt is reported as such — never counted as a wrong
  passphrase, never destroyed
- a malformed request body never reaches the logs, and the token never appears in
  a log line
- the compose form can't submit on its own without JavaScript, so the plaintext
  can never end up in a URL
- rate-limit counts survive a restart
- tampered ciphertext throws instead of returning altered plaintext, and a
  payload copied into another row will not decrypt there

## Interface

- Dark/light theme with a header toggle, applied before first paint so there's no flash
- Live character counter with a fill bar, `Ctrl`/`⌘` + `Enter` to submit
- Selectable expiry (1 hour / 1 day / 1 week)
- Revealed secrets are blurred behind a click-to-reveal shade — the blur is added by
  JavaScript, so it never hides a secret from a visitor whose scripts didn't run
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
| `POST /api/secrets` | Takes `ciphertext` (already encrypted by the browser) or plain `message` (API clients), plus optional `ttlHours` and `passphrase`. Seals it with the server key, stores it under a random UUID v4 token, returns `{ token, url, expiresInHours, protected, endToEnd }`. |
| `GET /healthz` | Liveness probe. `200` with `{"status":"ok"}`, or `503` if the database stops answering. |
| `GET /s/:token` | Renders the confirmation screen. Never touches the database — the same page comes back for every token. |
| `POST /s/:token` | The burn. Reads the row, unseals it, and deletes it; only the request whose `DELETE` removes the row gets the content. For an end-to-end secret that content is still ciphertext, which the page decrypts with the key from the `#fragment`. |
| Any later `POST` | 404 → the "self-destructed" screen. |

The server layer stores `iv:authTag:ciphertext`, all hex, with a fresh 96-bit IV
per secret; the GCM auth tag means a tampered row fails to decrypt rather than
returning garbage. The row's token is authenticated too, as GCM associated data,
so a payload copied into a different row fails the same way. Without that,
anyone able to write to the database could move a secret into a row whose link
they hold and read it there, leaving the original untouched. Layers stack from
the inside out:

```
browser key (in the #fragment)   AES-256-GCM, WebCrypto     — end-to-end secrets
passphrase (optional)            scrypt → AES-256-GCM
SECRET_KEY                       AES-256-GCM                 — always
```

### End-to-end encryption

The compose page generates a fresh 256-bit key with WebCrypto, encrypts the
message with it, and sends only the ciphertext. The key is appended to the link
after a `#`:

```
https://example.com/s/3f0c…e91a#Qm9vc3RlZC1rZXktZ29lcy1oZXJlLWFuZC1pcy00My1j
```

Browsers never send the fragment in a request, so the server never has the key
— not when storing, not when revealing. A test unwraps a stored row with
`SECRET_KEY` and asserts it gets back exactly the browser's ciphertext and
nothing more.

Two details make the flow work. The reveal form's `action` has the fragment
appended by script, because a form `POST` otherwise lands on a URL without it;
and once decrypted, the key is stripped from the address bar and history, since
the row is gone and the key has no further use.

WebCrypto only exists in a secure context (HTTPS or `localhost`). On a plain-HTTP
origin the form falls back to sending the plaintext for the server to encrypt,
and the result screen says so. API clients can still send plaintext `message`
too; those secrets are readable by the operator, as before.

### Why the reveal takes two steps

Slack, Teams, WhatsApp, iMessage and most mail scanners fetch URLs server-side to
build link previews. If `GET` performed the burn, a preview bot would destroy the
secret before the recipient ever clicked — and chat is exactly where these links
get sent. So the destroying is done by a same-origin `POST` from the confirmation
form, and preview bots don't issue POSTs.

The form is plain HTML, so revealing a secret created through the API works
with JavaScript disabled. End-to-end secrets can't — decryption happens in the
browser — so the confirmation page warns no-JS visitors before they burn one.

Creating a secret always needs JavaScript, since that is where it's encrypted.
Without it, the compose form is inert: its button starts disabled and it posts
rather than gets, because a default `GET` form would put the plaintext in the
address bar — and from there into browser history and proxy logs.

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

### Why only one reader can win

The burn reads the row, unseals it, then deletes it — and unsealing a
passphrase-protected secret takes ~100ms of `scrypt` on the thread pool, so no
lock can be held across it. Several requests can therefore read and unseal the
same row at once. What decides the winner is the `DELETE`: SQLite runs it
atomically, so it removes the row for exactly one of them, and only that request
is given the content. Every other one gets the "self-destructed" page, exactly as
if it had arrived a moment later.

This is not theoretical. Returning the content because the `SELECT` found a row
— the obvious version — and running the test suite's 8-thread race gives:

```
exactly one thread may burn the secret, got 8
```

Every caller received the same secret. The race test runs eight worker threads,
each on its own SQLite connection, released together through an `Atomics`
barrier; a second test fires simultaneous correct-passphrase reveals over HTTP.

Wrong passphrases go the other way: counting one is a read-then-write, so it runs
in a `BEGIN IMMEDIATE` transaction that takes the write lock before the read, and
simultaneous wrong guesses are each counted instead of overwriting each other.

### Optional passphrase

A sender can attach a passphrase. The message is then sealed with a key derived
from it via `scrypt`, and *that* is sealed with the server key as usual. On its
own that keeps the operator out; alongside end-to-end encryption its job is to
make the link alone insufficient — send the passphrase over a different channel.

A wrong passphrase does **not** destroy the secret; it costs one of five
attempts, so a typo is survivable but an online guessing attack is not.

`scrypt` runs asynchronously on libuv's thread pool. The synchronous version
would block the event loop for each guess, letting a burst of wrong passphrases
from many addresses — each within its own rate limit — stall the whole server.

## Project layout

```
server.js                 entry point: config, hourly purge, graceful shutdown
src/app.js                Express app: routes, middleware, error handling
src/db.js                 better-sqlite3 setup, schema, migrations, the burn
src/crypto.js             server layer (AES-256-GCM, key rotation) + passphrase layer (scrypt)
src/security.js           CSP with a per-request nonce, plus the other headers
src/limits.js             per-IP rate limiters
src/rate-limit-store.js   SQLite-backed store, so limits survive restarts
src/logging.js            text/JSON logs with tokens redacted
src/env.js                env readers that treat blank values as unset
src/assets.js             resolves Vite's hashed filenames from the manifest
src/client/e2e.js         browser-side encryption (WebCrypto), also run by the tests
src/client/main.js        form submission, reveal, decrypt, theme, copy-to-clipboard
src/client/style.css      Tailwind entry + component utilities
views/                    index · reveal · secret · destroyed · too-many (EJS)
test/                     burn · crypto · infra · race (worker threads)
scripts/keygen.js         generates a SECRET_KEY
```

## Schema

```sql
CREATE TABLE secrets (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  token                TEXT    NOT NULL UNIQUE,   -- UUID v4, the URL segment
  payload              TEXT    NOT NULL,          -- iv:authTag:ciphertext
  created_at           TEXT    NOT NULL DEFAULT (datetime('now')),
  expires_at           TEXT    NOT NULL,          -- unread secrets die on their own too
  requires_passphrase  INTEGER NOT NULL DEFAULT 0,
  attempts             INTEGER NOT NULL DEFAULT 0, -- wrong passphrases so far
  client_encrypted     INTEGER NOT NULL DEFAULT 0  -- 1: payload wraps browser ciphertext
);

CREATE TABLE rate_limits (
  key       TEXT    PRIMARY KEY,                   -- "<limiter>:<ip>"
  hits      INTEGER NOT NULL,
  reset_at  INTEGER NOT NULL                       -- epoch milliseconds
);
```

The last three `secrets` columns are added by an in-place migration, so databases
created by earlier versions keep working. Rows written before payloads were bound
to their tokens do not: they fail to decrypt and are reported as unreadable until
their TTL runs out, a week at most. That break was deliberate; a fallback for
them would have left every such payload movable. An hourly sweep deletes expired rows
and elapsed rate-limit windows so nothing lingers on disk.

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
| `REPO_URL` | Optional. Shows GitHub links in the header, footer and security section; hidden when unset. |
| `AUTHOR_NAME` | Optional. Credits you in the footer ("Built by …"); hidden when unset. |
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
- **The operator, for secrets made in the browser.** The server stores and
  returns ciphertext whose key it never receives, so even whoever runs the
  instance — or has `SECRET_KEY` and a copy of the database — cannot read them.
- **Database theft.** Rows are AES-256-GCM ciphertext; a stolen `app.db` or a
  leaked backup is useless without `SECRET_KEY`, which lives outside it — and
  for end-to-end secrets, useless even with it.
- **Silent interception.** Reads are destructive and single-use, so if someone
  gets there first the recipient sees "already destroyed" — you find out.
- **Tampering.** GCM authenticates the ciphertext and the token it belongs to;
  an edited row fails to decrypt rather than returning altered plaintext, and so
  does a payload copied in from another row.
- **Preview bots.** Link unfurlers can't burn a secret, because burning needs a
  POST.
- **Silent read receipts.** `GET` returns an identical page for every token, so
  probing a link tells an observer nothing about whether it has been read. (One
  bounded exception applies to passphrase-protected secrets — see below.)

**What it does not protect against**

- **A malicious operator who changes the code.** End-to-end encryption trusts
  the JavaScript the server sends. An operator willing to ship a modified
  `main.js` could capture keys before encryption. This is the limit of every
  web-delivered end-to-end tool; self-host if it matters to you.
- **The operator, for plaintext submissions.** Secrets sent as `message` — by API
  clients, or by browsers without WebCrypto on a plain-HTTP origin — are
  encrypted with `SECRET_KEY` on the server, so whoever runs the instance could
  read them unless a passphrase was set. The passphrase itself does reach the
  server in the reveal request; it is simply never written down.
- **Whoever holds the link**, if no passphrase is set. The URL — key included —
  is a bearer token: whoever reads it first gets the secret. A passphrase is what
  makes the link alone insufficient.
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
  in those logs until they rotate. The `#key` of an end-to-end link is never
  sent, so it never reaches any log.

## Other notes

- **Rate limits** are per-IP over a 15-minute window: 20 creates, 60 reveals, 300
  requests overall. Tune them in `src/limits.js`. Counts live in SQLite rather
  than memory, so they survive a restart and stay correct across processes.
- **Fonts are bundled**, not loaded from Google — opening a secret link shouldn't
  announce itself to a third party. It also keeps the CSP locked to `'self'`.
- **SQLite and ephemeral disks.** On platforms with ephemeral filesystems
  (Heroku, default Fly machines), mount a volume or `data/app.db` disappears on
  every deploy.
- **Put it behind HTTPS** — browsers only expose WebCrypto on secure origins, so
  without it links fall back to server-side encryption. Set `TRUST_PROXY=1` when
  you do. HSTS is only sent
  when the request arrives over TLS, and with TLS terminating at a proxy the app
  only sees that if it trusts the forwarded headers.
- **`GET /healthz`** returns `{"status":"ok"}` with a `200`, or `503` if the
  database has stopped answering. It sits above the rate limiter, so frequent
  polling by the platform can't exhaust the request budget.
- **Nothing from a request body is ever logged.** Malformed payloads are answered
  with a `400` and logged by error type only — the parse error carries the raw
  body, which on this app is the plaintext secret.

## License

[MIT](LICENSE)
