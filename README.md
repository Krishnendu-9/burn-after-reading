# 🔥 Burn After Reading

Share a password, API key, or note through a link that works **exactly once**.
The message is encrypted in your browser with AES-256-GCM before it is sent, the
key travels only in the link's `#fragment`, and the database row is deleted the
instant the secret is revealed. Unread secrets expire after 1 hour, 1 day or 7 days.

**Stack:** Node.js · Express 5 · better-sqlite3 · native `crypto` · WebCrypto · EJS · Tailwind CSS 4 · Vite

## Quick start

Requires Node.js 22.12 or newer.

```bash
npm install
npm run keygen          # prints a SECRET_KEY line
cp .env.example .env    # paste the key in
npm run dev             # builds once, then watches: http://localhost:3000
```

better-sqlite3 ships its compiled binary inside the package. npm 11 uses it as
is; npm 10 (bundled with Node 22) compiles it from source anyway, which needs
Python and a C++ toolchain. On npm 10 without those, install with
`npm install --ignore-scripts`: no dependency needs an install script.

For production, `npm run build`, set `NODE_ENV=production` (in `.env` or the
environment), and `npm start`. Without it the asset manifest is re-read on every
page and the startup checks for `BASE_URL` and `TRUST_PROXY` stay quiet.
`.env` is read by Node itself; values already in the environment win.

`npm test` runs the suite on Node's built-in runner; CI runs it on Node 22 and 24,
checks that every test file actually ran, and gates on `npm audit`.

## How it works

| Request | What happens |
| --- | --- |
| `POST /api/secrets` | Takes `ciphertext` (encrypted by the browser) or plain `message` (API clients), with optional `ttlHours` (1, 24 or 168) and `passphrase`. Seals it with the server key under a random UUID v4 token and returns `{ token, url, expiresInHours, protected, endToEnd }`. |
| `GET /s/:token` | The confirmation page. Never touches the database: every token gets the same page. Other spellings (`/S/…`, a trailing slash, upper case) redirect to `/s/<token>`; anything that isn't a UUID gets the "destroyed" page. |
| `POST /s/:token` | The burn: reads the row, unseals it, deletes it. Only the request whose `DELETE` removes the row gets the content. |
| `GET /healthz` | `200` while the database answers, `503` when it doesn't. |

Both `POST` routes refuse requests that a browser marks as coming from another
site (`Sec-Fetch-Site`), so no other page can burn a secret or create them on its
visitors' behalf. Clients that send no such header, such as `curl`, are unaffected.

```
browser key (in the #fragment)   AES-256-GCM, WebCrypto           — end-to-end secrets
passphrase (optional)            scrypt → AES-256-GCM
SECRET_KEY                       AES-256-GCM, bound to the token   — always
```

**End-to-end.** The page encrypts with a fresh 256-bit key and sends only the
ciphertext; the key goes after the `#`, which browsers never send. As the
confirmation page loads, it moves the key into the tab's `sessionStorage`, so
Back and Forward never show it; the page that ends the reveal decrypts and
deletes it. On plain HTTP (no WebCrypto) the server would have to encrypt, so the
form says so before sending and waits for the sender to tick "send it
unencrypted anyway".

**Two steps.** Chat apps and mail scanners fetch links to build previews. If `GET`
burned the secret, a preview bot would destroy it before the recipient clicked,
so the burn is a same-origin `POST` from the confirmation form.

**No lookup on `GET`.** Checking whether the row exists would hand anyone holding
the link a silent read receipt. The page is identical for live, burned, expired
and invented tokens, at the cost of not showing when a secret expires.

**One winner.** Unsealing a passphrase secret takes ~100 ms of scrypt, so no lock
is held across it and several requests can unseal the same row. The `DELETE`
decides: SQLite removes the row for exactly one of them. Hand out the content
because the `SELECT` found a row instead, and the eight-thread race test fails
with `got N` readers: in 13 runs N was 8 nine times, and never below 4.

**Bound to its row.** The token is GCM associated data, so a payload copied into
another row fails to decrypt. Otherwise anyone able to write to the database could
move a secret into a row whose link they hold and read it there, leaving the
original untouched. Rows written before the binding no longer decrypt; that break
was deliberate.

**Passphrases.** A wrong passphrase costs one of five attempts, not the secret.
scrypt runs on libuv's thread pool, so a burst of guesses can't stall the server.

## Project layout

```
server.js                entry point: config, hourly purge, graceful shutdown
src/load-env.js          reads .env with Node's own loader, before anything else
src/app.js               routes, middleware, validation, error handling
src/db.js                SQLite schema, migrations, the burn and the storage ceiling
src/crypto.js            server layer (AES-256-GCM, key rotation) + passphrase layer
src/security.js          CSP with a per-request nonce, and the other headers
src/limits.js            rate limiters, with their SQLite store in rate-limit-store.js
src/logging.js, env.js   redacted text/JSON logs; env readers (blank = unset)
src/client/              main.js (the pages), e2e.js (WebCrypto), link-key.js (#key handling)
views/                   index · reveal · secret · destroyed · refused · too-many (EJS)
test/                    burn · crypto · infra · link-key · race (.test.js)
```

## Configuration

| Variable | Purpose |
| --- | --- |
| `SECRET_KEY` | 32 bytes as 64 hex chars; `npm run keygen` makes one. |
| `SECRET_KEY_PREVIOUS` | Optional old keys, comma-separated, decryption only, for rotation. |
| `BASE_URL` | Public origin used to build links. Must be the real `https://` URL in production; the server warns at startup when it isn't. |
| `NODE_ENV` | `production` in production: caches the asset manifest and turns on the startup warnings. |
| `TRUST_PROXY` | **Off by default. Set it (`1` behind one proxy) only if a proxy really is in front**, or clients can forge `X-Forwarded-For` and bypass every rate limit. |
| `PORT` · `DATABASE_PATH` · `MAX_SECRETS` | Defaults `3000`, `data/app.db`, `10000` stored rows. |
| `LOG_REQUESTS` · `LOG_FORMAT` | Per-request logs with tokens redacted; `text` or `json`. |
| `REPO_URL` · `AUTHOR_NAME` | Optional GitHub links and footer credit. |

Rate limits are per IP per 15 minutes (20 creates, 60 reveals, 300 requests). They
live in SQLite, so they survive restarts and are shared by every process using the
same database file.

## Docker

```bash
docker compose up -d --build   # reads your .env
docker compose down            # the volume, and your secrets, survive
```

With plain `docker run`, pass `SECRET_KEY`, `BASE_URL` and `TRUST_PROXY=1`, and
**mount a volume at `/app/data`**: SQLite lives there, and without one every
unread secret dies with the container. The image is multi-stage, runs as the
unprivileged `node` user, has a `HEALTHCHECK` on `/healthz`, and shuts down
cleanly on `docker stop`. Serve it over HTTPS: browsers only encrypt in the page
on secure origins.

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
- **Checking whether a passphrase-protected link is unread — four times.** So
  that a typo is survivable, a wrong passphrase doesn't burn the secret: `POST`
  answers `401` while it exists and `404` once it doesn't. Someone holding the
  link can confirm it is unread without consuming it, a knowing weakening of the
  no-read-receipt property above, and only for protected secrets (any other
  `POST` burns). It is bounded: four wrong attempts answer quietly, and the fifth
  destroys the secret. Answering `404` instead would make one typo look like a
  destroyed secret. If you need the stronger property, don't set a passphrase.
- **Destruction by someone who has the link but not the passphrase.** Five wrong
  passphrases destroy a protected secret, and a `POST` with no passphrase counts
  as wrong, so whoever intercepts the link can destroy what they cannot read.
  Without the limit they could do nothing to it, but could keep guessing from as
  many addresses as they liked for the whole TTL. The trade is deliberate: a
  passphrase turns an intercepted link from disclosure into, at worst,
  destruction — which the recipient notices, and which a new link fixes.
- **Server-side logs.** Your reverse proxy or platform may log request paths,
  which include the token. The token is worthless after the burn, but it exists
  in those logs until they rotate. The `#key` of an end-to-end link is never
  sent, so it never reaches any log.

## Known limitations

These follow from the design, or from the platform under it. They are not on a
to-do list: no change inside this project removes them, though how it is
deployed can narrow some of them.

- **Plaintext sits in ordinary JavaScript strings** — the parsed request body, the
  decrypted result, the rendered page. Strings are immutable and freely copied,
  so they can't be zeroed; they stay in the heap until garbage collection and
  reuse, and until then can turn up in a core dump, a heap snapshot or swap.
  (Zeroing the cipher's `Buffer`s wouldn't help: the bytes already exist as
  strings.) On the server this covers plaintext submissions and every passphrase,
  which reaches the server even for end-to-end secrets; the browser holds
  end-to-end plaintext the same way. Disabling core dumps and swap narrows this;
  it does not close it.
- **A burn is a delete, not an erasure.** SQLite's `secure_delete` is on, so a
  burned row is zeroed in the database file, and the hourly sweep resets the
  write-ahead log, but until then the log still holds the page as it was.
  Below SQLite the bytes can survive in filesystem journals, SSD
  wear-levelling, snapshots and backups, none of which the app can reach. What
  survives is ciphertext, so its safety rests on the keys; see the next two
  points.
- **No forward secrecy for server-encrypted secrets.** `SECRET_KEY` is
  long-lived, and for a plaintext submission without a passphrase it is the only
  key involved. Anyone who has a copy of the database (a backup, a snapshot, the
  leftover bytes above) and later obtains `SECRET_KEY` can read every such
  secret in that copy, including ones burned after the copy was taken. Rotating
  the key does not reach copies that already exist.
- **The attempt limit only holds online.** Five wrong passphrases destroy a
  secret on the server. With a copy of the database and `SECRET_KEY`, the
  passphrase layer can be attacked offline instead, at scrypt's cost per guess
  and with no limit on attempts. For a secret that is not also end-to-end, the
  strength of the passphrase is then all that is left.
- **A link outlives its secret, and an end-to-end link carries its key.** Links
  get copied to places the app cannot clean: chat history, the clipboard and
  clipboard-history tools, and the browser's list of visited pages, which
  records the link, key included, as it first loads and before any script on
  the page can run (and syncs it, where sync is on). Once the secret is burned,
  those copies are harmless only if the server's copy of the ciphertext is really
  gone. An operator who kept a copy, or anyone holding a leftover one together
  with `SECRET_KEY`, can decrypt an end-to-end secret whenever its link turns up.
- **"You will know if someone got there first" only covers people using the
  app.** The single read is enforced by the server deleting the row, not by the
  cryptography. Anyone with read access to the database or the server can copy a
  payload without burning it, and the recipient sees nothing unusual. For an
  end-to-end secret that copy is useless without the link (the point above).
- **Nothing proves who created a secret.** Anyone can create one, so a link
  from this instance says nothing about its sender. Identify the sender through
  the channel the link arrived on, not the link.

## License

[MIT](LICENSE)
