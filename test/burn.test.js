import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';

import { bootTestApp, createSecret, reveal } from './helpers.js';

let app;
let crypto2;

/** Create a secret with an optional passphrase. */
async function createSecret2(message, passphrase) {
  const response = await fetch(app.url('/api/secrets'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message, passphrase })
  });

  return { status: response.status, body: await response.json() };
}

before(async () => {
  app = await bootTestApp();
  crypto2 = await import('../src/crypto.js');
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

  // Fired without awaiting in between, so they queue against the server together.
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

test('a cross-site POST cannot burn a secret', async () => {
  const { body } = await createSecret(app, 'csrf-target');

  const forged = await fetch(app.url(`/s/${body.token}`), {
    method: 'POST',
    headers: { 'Sec-Fetch-Site': 'cross-site' }
  });
  assert.equal(forged.status, 403);

  // Survived the forged request.
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
  assert.equal(app.db.burnSecret(token, (row) => row.payload).status, 'missing');

  // The row is still on disk until the sweep runs, but no request can reach it.
  const response = await reveal(app, token);
  assert.equal(response.status, 404);
  assert.match(await response.text(), /self-destructed/);
});

test('purgeExpired removes expired rows and leaves live ones alone', async () => {
  const { body } = await createSecret(app, 'still valid', 24);

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
  const { body } = await createSecret(app, 'ttl check', 9999);
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

/** Submit the reveal form with a passphrase, the way the browser would. */
function revealWith(token, passphrase) {
  return fetch(app.url(`/s/${token}`), {
    method: 'POST',
    headers: {
      'Sec-Fetch-Site': 'same-origin',
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams({ passphrase }).toString()
  });
}

test('a passphrase-protected secret opens with the right passphrase', async () => {
  const message = 'guarded-by-a-passphrase';
  const { status, body } = await createSecret2(message, 'correct horse');

  assert.equal(status, 201);
  assert.equal(body.protected, true);

  const response = await revealWith(body.token, 'correct horse');
  assert.equal(response.status, 200);
  assert.match(await response.text(), new RegExp(message));
});

test('a wrong passphrase does NOT destroy the secret', async () => {
  const message = 'survives-a-typo';
  const { body } = await createSecret2(message, 'the-real-one');

  const wrong = await revealWith(body.token, 'not-it');
  assert.equal(wrong.status, 401);
  assert.match(await wrong.text(), /was not correct/i);

  // Still there, and still openable with the right passphrase.
  assert.equal(app.db.countLive(body.token), 1);

  const right = await revealWith(body.token, 'the-real-one');
  assert.equal(right.status, 200);
  assert.match(await right.text(), new RegExp(message));
});

test('omitting the passphrase entirely does not destroy it either', async () => {
  const { body } = await createSecret2('needs-a-passphrase', 'sesame');

  const response = await reveal(app, body.token);
  assert.equal(response.status, 401);
  assert.match(await response.text(), /passphrase-protected/i);
  assert.equal(app.db.countLive(body.token), 1);
});

test('five wrong attempts destroy the secret', async () => {
  const { body } = await createSecret2('brute-force-target', 'the-real-one');

  for (let attempt = 1; attempt <= 4; attempt += 1) {
    const response = await revealWith(body.token, `guess-${attempt}`);
    assert.equal(response.status, 401, `attempt ${attempt} should be rejected, not fatal`);
  }
  assert.equal(app.db.countLive(body.token), 1, 'should survive four wrong guesses');

  const fifth = await revealWith(body.token, 'guess-5');
  assert.equal(fifth.status, 404);
  assert.match(await fifth.text(), /too many incorrect passphrases/i);
  assert.equal(app.db.countLive(body.token), 0, 'the fifth wrong guess destroys it');

  // Even the correct passphrase cannot bring it back.
  const tooLate = await revealWith(body.token, 'the-real-one');
  assert.equal(tooLate.status, 404);
});

test('the server alone cannot read a passphrase-protected secret', async () => {
  const message = 'operator-should-not-see-this';
  const { body } = await createSecret2(message, 'a-good-passphrase');

  // Unwrap the outer layer exactly as the operator could, holding SECRET_KEY.
  const row = app.db.db.prepare('SELECT payload FROM secrets WHERE token = ?').get(body.token);
  const unwrapped = crypto2.decrypt(row.payload);

  assert.ok(!unwrapped.includes(message), 'the plaintext must not survive the outer unwrap');
  assert.match(unwrapped, /^[0-9a-f]+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+$/);
});

test('a passphrase shorter than the minimum is rejected', async () => {
  const { status, body } = await createSecret2('too weak', 'ab');

  assert.equal(status, 400);
  assert.match(body.error, /at least/i);
});

test('a passphrase on one secret does not affect unprotected ones', async () => {
  const { body } = await createSecret(app, 'no passphrase here');

  // A passphrase supplied for a secret that has none is simply ignored.
  const response = await revealWith(body.token, 'irrelevant');
  assert.equal(response.status, 200);
  assert.match(await response.text(), /no passphrase here/);
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

/* ---------------------------------------------------------------- headers */

test('secret pages are marked no-store and carry a CSP', async () => {
  const { body } = await createSecret(app, 'header check');
  const response = await reveal(app, body.token);

  assert.match(response.headers.get('cache-control'), /no-store/);
  assert.match(response.headers.get('content-security-policy'), /default-src 'self'/);
  assert.equal(response.headers.get('referrer-policy'), 'no-referrer');
});
