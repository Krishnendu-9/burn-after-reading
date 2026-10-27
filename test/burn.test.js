import test, { before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';

import {
  bootTestApp,
  createSecret,
  createEncryptedSecret,
  reveal,
  ciphertextFrom
} from './helpers.js';

let app;
let serverCrypto;
let e2e;

before(async () => {
  app = await bootTestApp();
  serverCrypto = await import('../src/crypto.js');
  e2e = await import('../src/client/e2e.js');
});

// Every request here comes from 127.0.0.1, so without this the suite would
// share one rate-limit budget and start failing with 429s as it grows. The
// limiter has its own tests in infra.test.js.
beforeEach(() => {
  app.db.db.prepare('DELETE FROM rate_limits').run();
});

after(async () => {
  await app.close();
});

/* ------------------------------------------------------------ the core flow */

test('a secret can be created and revealed exactly once', async () => {
  const message = 'sk-live-4242424242';
  const { status, body } = await createSecret(app, message);

  assert.equal(status, 201);
  assert.match(body.url, /\/s\/[0-9a-f-]{36}$/);

  const first = await reveal(app, body.token);
  assert.equal(first.status, 200);
  assert.match(await first.text(), new RegExp(message));

  const second = await reveal(app, body.token);
  assert.equal(second.status, 404);
  assert.match(await second.text(), /self-destructed/);
});

test('the row is gone from the database after the burn', async () => {
  const { body } = await createSecret(app, 'delete me');

  assert.equal(app.db.countLive(body.token), 1);
  await reveal(app, body.token);
  assert.equal(app.db.countLive(body.token), 0);
});

test('ten simultaneous reveals of the same link: exactly one gets the secret', async () => {
  const message = 'only-one-of-you-gets-this';
  const { body } = await createSecret(app, message);

  // Fired together, end to end over HTTP. Without a passphrase nothing yields
  // between the read and the delete, so this checks the route's handling rather
  // than the race itself — the passphrase test below and race.test.js are the
  // ones that force concurrent readers, and both fail if the DELETE check goes.
  const responses = await Promise.all(
    Array.from({ length: 10 }, () => reveal(app, body.token))
  );
  const bodies = await Promise.all(responses.map((r) => r.text()));

  const winners = bodies.filter((html) => html.includes(message));
  const losers = responses.filter((r) => r.status === 404);

  assert.equal(winners.length, 1, `exactly one caller may see the secret, got ${winners.length}`);
  assert.equal(losers.length, 9);
  assert.equal(app.db.countLive(body.token), 0);
});

test('simultaneous correct passphrases: still exactly one reader', async () => {
  // The widest window there is: every request spends ~100ms in scrypt on the
  // thread pool after reading the row, and all of them succeed at unsealing.
  const message = 'passphrase-race';
  const { body } = await createSecret(app, message, { passphrase: 'shared-secret' });

  const responses = await Promise.all(
    Array.from({ length: 6 }, () => reveal(app, body.token, 'shared-secret'))
  );
  const bodies = await Promise.all(responses.map((r) => r.text()));

  assert.equal(bodies.filter((html) => html.includes(message)).length, 1);
  assert.equal(responses.filter((r) => r.status === 404).length, 5);
  assert.equal(app.db.countLive(body.token), 0);
});

test('simultaneous wrong passphrases are each counted', async () => {
  const { body } = await createSecret(app, 'count-every-guess', { passphrase: 'the-real-one' });

  const responses = await Promise.all(
    Array.from({ length: 3 }, (_, i) => reveal(app, body.token, `guess-${i}`))
  );

  assert.deepEqual(
    responses.map((r) => r.status),
    [401, 401, 401]
  );
  const row = app.db.db.prepare('SELECT attempts FROM secrets WHERE token = ?').get(body.token);
  assert.equal(row.attempts, 3, 'no guess may be lost to a read-modify-write race');
});

/* -------------------------------------------------- the link-preview defence */

test('GET does not burn the secret, however many times it is fetched', async () => {
  const message = 'survives-link-previews';
  const { body } = await createSecret(app, message);

  for (let i = 0; i < 5; i += 1) {
    const response = await fetch(app.url(`/s/${body.token}`));
    const html = await response.text();

    assert.equal(response.status, 200);
    assert.match(html, /Reveal and destroy/);
    // The confirmation screen must never contain the plaintext.
    assert.doesNotMatch(html, new RegExp(message));
  }

  // Still readable afterwards.
  const burned = await reveal(app, body.token);
  assert.match(await burned.text(), new RegExp(message));
});

test('GET gives away nothing about whether a secret is still live', async () => {
  const { body } = await createSecret(app, 'existence-probe');

  // Two things legitimately vary and have to be normalised out: the CSP nonce,
  // which is fresh per response, and the token itself, which the caller supplied
  // and so already knows.
  const fetchPage = async (token) => {
    const response = await fetch(app.url(`/s/${token}`));
    const html = (await response.text())
      .replace(/nonce="[^"]*"/g, 'nonce="_"')
      .replaceAll(token, 'TOKEN');
    return { status: response.status, html };
  };

  const live = await fetchPage(body.token);
  const neverExisted = await fetchPage('99999999-9999-4999-8999-999999999999');

  await reveal(app, body.token);
  const burned = await fetchPage(body.token);

  // A live token, a token that never existed, and a token that was just burned
  // must all be indistinguishable to anyone probing over HTTP.
  assert.equal(live.status, 200);
  assert.equal(neverExisted.status, 200);
  assert.equal(burned.status, 200);
  assert.equal(live.html, neverExisted.html);
  assert.equal(live.html, burned.html);
});

test('a cross-site POST cannot burn a secret, and is not told it did', async () => {
  const { body } = await createSecret(app, 'csrf-target');

  for (const site of ['cross-site', 'same-site']) {
    const forged = await fetch(app.url(`/s/${body.token}`), {
      method: 'POST',
      headers: { 'Sec-Fetch-Site': site }
    });
    const html = await forged.text();

    assert.equal(forged.status, 403, site);
    // The secret is untouched, so the "self-destructed" page would be a lie.
    assert.match(html, /turned away/);
    assert.doesNotMatch(html, /self-destructed/);
  }

  // Survived the forged requests.
  const legitimate = await reveal(app, body.token);
  assert.equal(legitimate.status, 200);
});

/* ------------------------------------------------------------------ expiry */

test('an expired secret is unreadable and never returns its payload', async () => {
  const token = '11111111-1111-4111-8111-111111111111';

  app.db.db
    .prepare(
      `INSERT INTO secrets (token, payload, expires_at)
       VALUES (?, 'iv:tag:cipher', datetime('now', '-1 hours'))`
    )
    .run(token);

  assert.equal(app.db.countLive(token), 0);
  assert.equal((await app.db.burnSecret(token, (row) => row.payload)).status, 'missing');

  // The row is still on disk until the sweep runs, but no request can reach it.
  const response = await reveal(app, token);
  assert.equal(response.status, 404);
  assert.match(await response.text(), /self-destructed/);
});

test('purgeExpired removes expired rows and leaves live ones alone', async () => {
  const { body } = await createSecret(app, 'still valid', { ttlHours: 24 });

  app.db.db
    .prepare(
      `INSERT INTO secrets (token, payload, expires_at)
       VALUES ('22222222-2222-4222-8222-222222222222', 'x', datetime('now', '-2 hours'))`
    )
    .run();

  assert.ok(app.db.purgeExpired() >= 1);
  assert.equal(app.db.countLive(body.token), 1);
});

/* -------------------------------------------------------------- validation */

test('rejects an empty message', async () => {
  const { status, body } = await createSecret(app, '   ');

  assert.equal(status, 400);
  assert.match(body.error, /required/i);
});

test('rejects a message over the length limit', async () => {
  const { status, body } = await createSecret(app, 'x'.repeat(10_001));

  assert.equal(status, 413);
  assert.match(body.error, /too long/i);
});

test('falls back to the default TTL when given an unsupported value', async () => {
  const { body } = await createSecret(app, 'ttl check', { ttlHours: 9999 });
  assert.equal(body.expiresInHours, 24);
});

test('revealing an unknown token shows the destroyed screen rather than an error', async () => {
  const response = await reveal(app, 'does-not-exist');

  assert.equal(response.status, 404);
  assert.match(await response.text(), /self-destructed/);
});

/* --------------------------------------------------- malformed input safety */

test('malformed JSON is a 400, not a 500', async () => {
  const response = await fetch(app.url('/api/secrets'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{"message":"broken",,,}'
  });

  assert.equal(response.status, 400);
  assert.match((await response.json()).error, /could not read/i);
});

test('a malformed body is never written to the logs', async () => {
  const marker = 'PLAINTEXT-MUST-NOT-BE-LOGGED';
  const written = [];

  // body-parser attaches the raw body to the error it throws, and V8's JSON
  // messages quote the input too, so logging the error object would put the
  // secret straight into stdout.
  const realError = console.error;
  const realWarn = console.warn;
  console.error = (...args) => written.push(...args.map(String));
  console.warn = (...args) => written.push(...args.map(String));

  try {
    await fetch(app.url('/api/secrets'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: `{"message":"${marker}",,,}`
    });
  } finally {
    console.error = realError;
    console.warn = realWarn;
  }

  assert.ok(written.length > 0, 'expected the request to be logged at all');
  assert.ok(
    !written.join('\n').includes(marker),
    'the plaintext body leaked into the logs'
  );
});

test('an oversized body is rejected without a server error', async () => {
  const response = await fetch(app.url('/api/secrets'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message: 'x'.repeat(400_000) })
  });

  assert.ok(response.status >= 400 && response.status < 500, `got ${response.status}`);
});

/* ----------------------------------------------------- passphrase protection */

test('a passphrase-protected secret opens with the right passphrase', async () => {
  const message = 'guarded-by-a-passphrase';
  const { status, body } = await createSecret(app, message, { passphrase: 'correct horse' });

  assert.equal(status, 201);
  assert.equal(body.protected, true);

  const response = await reveal(app, body.token, 'correct horse');
  assert.equal(response.status, 200);
  assert.match(await response.text(), new RegExp(message));
});

test('a wrong passphrase does NOT destroy the secret', async () => {
  const message = 'survives-a-typo';
  const { body } = await createSecret(app, message, { passphrase: 'the-real-one' });

  const wrong = await reveal(app, body.token, 'not-it');
  assert.equal(wrong.status, 401);
  assert.match(await wrong.text(), /was not correct/i);

  // Still there, and still openable with the right passphrase.
  assert.equal(app.db.countLive(body.token), 1);

  const right = await reveal(app, body.token, 'the-real-one');
  assert.equal(right.status, 200);
  assert.match(await right.text(), new RegExp(message));
});

test('omitting the passphrase entirely does not destroy it either', async () => {
  const { body } = await createSecret(app, 'needs-a-passphrase', { passphrase: 'sesame' });

  const response = await reveal(app, body.token);
  assert.equal(response.status, 401);
  assert.match(await response.text(), /passphrase-protected/i);
  assert.equal(app.db.countLive(body.token), 1);
});

test('five wrong attempts destroy the secret', async () => {
  const { body } = await createSecret(app, 'brute-force-target', { passphrase: 'the-real-one' });

  for (let attempt = 1; attempt <= 4; attempt += 1) {
    const response = await reveal(app, body.token, `guess-${attempt}`);
    assert.equal(response.status, 401, `attempt ${attempt} should be rejected, not fatal`);
  }
  assert.equal(app.db.countLive(body.token), 1, 'should survive four wrong guesses');

  const fifth = await reveal(app, body.token, 'guess-5');
  assert.equal(fifth.status, 404);
  assert.match(await fifth.text(), /too many incorrect passphrases/i);
  assert.equal(app.db.countLive(body.token), 0, 'the fifth wrong guess destroys it');

  // Even the correct passphrase cannot bring it back.
  const tooLate = await reveal(app, body.token, 'the-real-one');
  assert.equal(tooLate.status, 404);
});

test('the server alone cannot read a passphrase-protected secret', async () => {
  const message = 'operator-should-not-see-this';
  const { body } = await createSecret(app, message, { passphrase: 'a-good-passphrase' });

  // Unwrap the outer layer exactly as the operator could, holding SECRET_KEY.
  const row = app.db.db.prepare('SELECT payload FROM secrets WHERE token = ?').get(body.token);
  const unwrapped = serverCrypto.decrypt(row.payload, body.token);

  assert.ok(!unwrapped.includes(message), 'the plaintext must not survive the outer unwrap');
  assert.match(unwrapped, /^[0-9a-f]+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+$/);
});

test('a passphrase shorter than the minimum is rejected', async () => {
  const { status, body } = await createSecret(app, 'too weak', { passphrase: 'ab' });

  assert.equal(status, 400);
  assert.match(body.error, /at least/i);
});

test('a passphrase on one secret does not affect unprotected ones', async () => {
  const { body } = await createSecret(app, 'no passphrase here');

  // A passphrase supplied for a secret that has none is simply ignored.
  const response = await reveal(app, body.token, 'irrelevant');
  assert.equal(response.status, 200);
  assert.match(await response.text(), /no passphrase here/);
});

/* ------------------------------------------------ end-to-end (browser) mode */

test('an end-to-end secret round-trips, and only the key holder can read it', async () => {
  const message = 'e2e: sk-live-🔥-café';
  const { status, body, key } = await createEncryptedSecret(app, message);

  assert.equal(status, 201);
  assert.equal(body.endToEnd, true);
  assert.ok(!body.url.includes('#'), 'the server must not put a key in the link');

  const response = await reveal(app, body.token);
  const html = await response.text();

  assert.equal(response.status, 200);
  assert.ok(!html.includes(message), 'the page must carry ciphertext, never plaintext');

  // What the browser does on that page, with the key from the fragment.
  assert.equal(await e2e.decryptMessage(ciphertextFrom(html), key), message);
  assert.equal(app.db.countLive(body.token), 0);
});

test('the server key alone yields only the browser ciphertext', async () => {
  const message = 'operator-cannot-read-e2e';
  const { body, ciphertext } = await createEncryptedSecret(app, message);

  // Exactly what an operator holding SECRET_KEY could recover from the row.
  const row = app.db.db.prepare('SELECT payload FROM secrets WHERE token = ?').get(body.token);
  const unwrapped = serverCrypto.decrypt(row.payload, body.token);

  assert.equal(unwrapped, ciphertext);
  assert.ok(!unwrapped.includes(message));
});

test('the wrong key cannot decrypt an end-to-end secret', async () => {
  const { body } = await createEncryptedSecret(app, 'needs-the-right-key');
  const { key: otherKey } = await e2e.encryptMessage('unrelated');

  const html = await (await reveal(app, body.token)).text();

  await assert.rejects(e2e.decryptMessage(ciphertextFrom(html), otherKey));
});

test('end-to-end and passphrase layers combine', async () => {
  const message = 'belt-and-braces';
  const { body, key } = await createEncryptedSecret(app, message, { passphrase: 'second factor' });

  assert.equal(body.protected, true);
  assert.equal((await reveal(app, body.token, 'wrong one')).status, 401);

  const html = await (await reveal(app, body.token, 'second factor')).text();
  assert.equal(await e2e.decryptMessage(ciphertextFrom(html), key), message);
});

test('malformed or oversized ciphertext is rejected', async () => {
  const post = (ciphertext) =>
    fetch(app.url('/api/secrets'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ciphertext })
    });

  assert.equal((await post('not base64url!')).status, 400);
  assert.equal((await post('')).status, 400);
  assert.equal((await post('AAAA')).status, 400, 'too short to hold an IV and a tag');
  assert.equal((await post('A'.repeat(41_000))).status, 413);
});

test('the largest message the form allows still fits as ciphertext', async () => {
  // 10,000 code units of 3-byte UTF-8 is the worst case the bound allows for.
  const { status } = await createEncryptedSecret(app, '€'.repeat(10_000));
  assert.equal(status, 201);
});

/* --------------------------------------------------------- storage ceiling */

test('refuses to create once storage is full, then recovers when space frees up', async () => {
  const fill = app.db.db.prepare(
    `INSERT INTO secrets (token, payload, expires_at)
     VALUES (?, 'iv:tag:cipher', datetime('now', '+24 hours'))`
  );
  const tokens = [];

  // Fill to the ceiling with live rows the purge cannot reclaim.
  while (app.db.countAll() < 40) {
    const token = `fill-${tokens.length}`;
    fill.run(token);
    tokens.push(token);
  }

  const rejected = await createSecret(app, 'no room at the inn');
  assert.equal(rejected.status, 503);
  assert.match(rejected.body.error, /full/i);

  // Free one slot; the next attempt should go through.
  app.db.db.prepare('DELETE FROM secrets WHERE token = ?').run(tokens.pop());

  const accepted = await createSecret(app, 'room again');
  assert.equal(accepted.status, 201);

  for (const token of tokens) {
    app.db.db.prepare('DELETE FROM secrets WHERE token = ?').run(token);
  }
});

test('expired rows are reclaimed rather than blocking new secrets', async () => {
  const fill = app.db.db.prepare(
    `INSERT INTO secrets (token, payload, expires_at)
     VALUES (?, 'iv:tag:cipher', datetime('now', '-1 hours'))`
  );

  let i = 0;
  while (app.db.countAll() < 40) fill.run(`expired-${i++}`);

  // The ceiling is reached, but every row is dead — the sweep should make room
  // instead of turning the request away.
  const { status } = await createSecret(app, 'should still work');
  assert.equal(status, 201);
});

/* ------------------------------------------------------------ health check */

test('the health endpoint reports ok', async () => {
  const response = await fetch(app.url('/healthz'));
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.status, 'ok');
});

test('the health endpoint is not rate limited', async () => {
  // Platforms poll this every few seconds; if it counted against the global
  // budget the app would eventually mark itself unhealthy.
  const codes = [];
  for (let i = 0; i < 40; i += 1) {
    codes.push((await fetch(app.url('/healthz'))).status);
  }

  assert.ok(
    codes.every((code) => code === 200),
    `expected all 200s, got ${[...new Set(codes)].join(', ')}`
  );
});

/* ------------------------------------------------ no-JavaScript compose form */

test('the compose form can never submit the plaintext as a GET', async () => {
  // Without JavaScript, a form with no method is a GET, and the browser puts
  // every field in the URL — /?message=<the secret>. The button must start
  // disabled (main.js enables it) and the method must be POST.
  const html = await (await fetch(app.url('/'))).text();

  const form = html.match(/<form[^>]*data-secret-form[^>]*>/)?.[0] ?? '';
  const button = html.match(/<button[^>]*data-submit[^>]*>/)?.[0] ?? '';

  assert.match(form, /method="post"/);
  assert.match(button, /\sdisabled[\s>]/);
  assert.match(html, /<noscript>[\s\S]*Creating a secret needs JavaScript/);
});

/* --------------------------------------------- secrets the server can't open */

/** Replaces a row's payload with one no configured key can decrypt. */
function corrupt(token) {
  const unreadable = `${'00'.repeat(12)}:${'00'.repeat(16)}:abcdef`;
  app.db.db.prepare('UPDATE secrets SET payload = ? WHERE token = ?').run(unreadable, token);
}

/** Runs fn with console.error captured; returns what was written. */
async function captureErrors(fn) {
  const written = [];
  const real = console.error;
  console.error = (...args) => written.push(args.map(String).join(' '));
  try {
    await fn();
  } finally {
    console.error = real;
  }
  return written.join('\n');
}

test('a secret the server cannot decrypt is reported as unreadable, not as a passphrase problem', async () => {
  // E.g. SECRET_KEY changed without SECRET_KEY_PREVIOUS. This used to count as
  // a wrong passphrase: the page asked for a passphrase the secret never had,
  // and five tries destroyed it.
  const { body } = await createSecret(app, 'written under an old key');
  corrupt(body.token);

  let response;
  const logged = await captureErrors(async () => {
    response = await reveal(app, body.token);
  });
  const html = await response.text();

  assert.equal(response.status, 500);
  assert.match(html, /can.t be opened/);
  assert.doesNotMatch(html, /passphrase-protected/);

  // Nothing counted, nothing destroyed — restoring the key would make it readable.
  const row = app.db.db.prepare('SELECT attempts FROM secrets WHERE token = ?').get(body.token);
  assert.equal(row.attempts, 0);
  assert.equal(app.db.countLive(body.token), 1);

  // The operator is told, without the token.
  assert.match(logged, /could not be decrypted/);
  assert.ok(!logged.includes(body.token), 'the token must not be logged');
});

test('an unreadable passphrase secret does not use up attempts either', async () => {
  const { body } = await createSecret(app, 'protected, old key', { passphrase: 'the-real-one' });
  corrupt(body.token);

  await captureErrors(async () => {
    for (let i = 0; i < 6; i += 1) {
      assert.equal((await reveal(app, body.token, 'the-real-one')).status, 500);
    }
  });

  const row = app.db.db.prepare('SELECT attempts FROM secrets WHERE token = ?').get(body.token);
  assert.equal(row.attempts, 0, 'six tries, none counted');
  assert.equal(app.db.countLive(body.token), 1, 'still there');
});

test('a payload copied into another row does not decrypt there', async () => {
  // Someone who can write to the database, but has no SECRET_KEY, copies a
  // victim's payload into a row whose link they hold. If the payload were not
  // bound to its token, revealing their own link would hand them the victim's
  // secret and leave the victim's row intact, so the read would go unnoticed.
  const message = 'moved-payload-target';
  const victim = await createSecret(app, message);
  const attacker = await createSecret(app, 'attacker-owned');

  const { payload } = app.db.db
    .prepare('SELECT payload FROM secrets WHERE token = ?')
    .get(victim.body.token);
  app.db.db
    .prepare('UPDATE secrets SET payload = ? WHERE token = ?')
    .run(payload, attacker.body.token);

  let response;
  await captureErrors(async () => {
    response = await reveal(app, attacker.body.token);
  });
  const html = await response.text();

  assert.equal(response.status, 500, 'reported as unreadable');
  assert.ok(!html.includes(message), 'the victim plaintext must not be served');

  // The victim's own link is unaffected and still opens exactly once.
  const genuine = await reveal(app, victim.body.token);
  assert.equal(genuine.status, 200);
  assert.match(await genuine.text(), new RegExp(message));
});

/* ----------------------------------------------------------- created time */

test('the secret page carries its creation time as unambiguous UTC', async () => {
  // SQLite's "YYYY-MM-DD HH:MM:SS" has no zone; parsed as-is, a browser reads
  // it as local time and shifts it by the reader's offset. The page must hand
  // over an ISO string with an explicit Z for main.js to localise correctly.
  const { body } = await createSecret(app, 'when was this made');
  const html = await (await reveal(app, body.token)).text();

  const iso = html.match(/<time[^>]*datetime="([^"]+)"/)?.[1];
  assert.match(iso ?? '', /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);

  const skew = Math.abs(Date.parse(iso) - Date.now());
  assert.ok(skew < 60_000, `created time should be about now, off by ${skew}ms`);

  // Readable without JavaScript too: the server's fallback text states UTC.
  assert.match(html, /created \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC/);
});

/* ---------------------------------------------------------------- headers */

test('secret pages are marked no-store and carry a CSP', async () => {
  const { body } = await createSecret(app, 'header check');
  const response = await reveal(app, body.token);

  assert.match(response.headers.get('cache-control'), /no-store/);
  assert.match(response.headers.get('content-security-policy'), /default-src 'self'/);
  assert.equal(response.headers.get('referrer-policy'), 'no-referrer');
});

test('bundled assets are cached for a year; pages still are not', async () => {
  // securityHeaders sets no-store on everything first, and serve-static only
  // adds its own Cache-Control when none is set, so assets were once never
  // cached at all and every page load fetched the fonts, CSS and JS again.
  const page = await fetch(app.url('/'));
  const html = await page.text();
  const script = html.match(/src="(\/dist\/[^"]+\.js)"/)?.[1];
  assert.ok(script, 'the page links its bundle');

  const asset = await fetch(app.url(script));
  await asset.arrayBuffer();

  assert.equal(asset.status, 200);
  assert.equal(asset.headers.get('cache-control'), 'public, max-age=31536000, immutable');
  assert.match(page.headers.get('cache-control'), /no-store/);
});

/* --------------------------------------------------- one address per link */

test('other spellings of a link are redirected to the one the reveal uses', async () => {
  // The confirmation page files the #key under its own path for the page that
  // ends the reveal, which is always /s/<token>. Reached at a variant, the key
  // was filed under another name, and the secret burned undecryptable.
  const { body } = await createSecret(app, 'one-address');

  for (const variant of [
    `/S/${body.token}`,
    `/s/${body.token}/`,
    `/s/${body.token.toUpperCase()}`
  ]) {
    const response = await fetch(app.url(variant), { redirect: 'manual' });
    assert.equal(response.status, 301, variant);
    assert.equal(response.headers.get('location'), `/s/${body.token}`, variant);
  }

  // The canonical address itself is served as before, and nothing was burned.
  assert.equal((await fetch(app.url(`/s/${body.token}`), { redirect: 'manual' })).status, 200);
  assert.equal(app.db.countLive(body.token), 1);
});

test('something that is not a token gets the destroyed page without a lookup', async () => {
  for (const pathname of ['/s/not-a-token', `/s/${'f'.repeat(36)}`]) {
    const response = await fetch(app.url(pathname));
    assert.equal(response.status, 404, pathname);
    assert.match(await response.text(), /self-destructed/);
  }
});

/* ------------------------------------------------------- tokens in the logs */

/** Runs fn with every console method captured; returns the lines written. */
async function captureLogs(fn) {
  const lines = [];
  const real = { log: console.log, warn: console.warn, error: console.error };
  for (const method of Object.keys(real)) {
    console[method] = (...args) => lines.push(args.map(String).join(' '));
  }
  try {
    await fn();
  } finally {
    Object.assign(console, real);
  }
  return lines;
}

test('an error on a reveal never writes the token to the logs', async () => {
  // The error handler once logged req.path as it was, so a malformed body sent
  // to /s/<token> put the token, which is as good as the secret, in the log.
  const { body } = await createSecret(app, 'token-stays-out-of-the-logs');

  let response;
  const lines = await captureLogs(async () => {
    response = await fetch(app.url(`/s/${body.token}`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Sec-Fetch-Site': 'same-origin' },
      body: '{"passphrase":'
    });
  });
  const html = await response.text();

  assert.equal(response.status, 400);
  assert.ok(lines.some((line) => line.includes('client-error')), 'the error is still logged');
  assert.ok(!lines.join('\n').includes(body.token), 'but without the token');

  // And the page doesn't claim the secret is gone: it isn't.
  assert.doesNotMatch(html, /self-destructed/);
  assert.equal(app.db.countLive(body.token), 1);
});

/* ------------------------------------------------- cross-site API requests */

test('another site cannot create secrets through its visitors', async () => {
  // A plain HTML form on any site can post urlencoded fields here. Without the
  // check, every visitor to that page would spend their own rate limit, from
  // their own address, filling this instance's storage ceiling.
  const before = app.db.countAll();

  const forged = await fetch(app.url('/api/secrets'), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Sec-Fetch-Site': 'cross-site'
    },
    body: 'message=from-another-site'
  });

  assert.equal(forged.status, 403);
  assert.match((await forged.json()).error, /other sites/);
  assert.equal(app.db.countAll(), before, 'nothing was stored');

  // The page's own request, and API clients that send no such header, still work.
  const own = await fetch(app.url('/api/secrets'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Sec-Fetch-Site': 'same-origin' },
    body: JSON.stringify({ message: 'from this site' })
  });
  assert.equal(own.status, 201);
});
