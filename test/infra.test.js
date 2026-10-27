import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

let dir;
let store;
let db;
let redactPath;

before(async () => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bar-infra-'));
  process.env.DATABASE_PATH = path.join(dir, 'infra.db');
  process.env.SECRET_KEY = crypto.randomBytes(32).toString('hex');

  db = await import('../src/db.js');
  store = await import('../src/rate-limit-store.js');
  ({ redactPath } = await import('../src/logging.js'));
});

after(() => {
  db.closeDatabase();
  fs.rmSync(dir, { recursive: true, force: true });
});

/* ----------------------------------------------------- rate limit store */

test('counts survive a new store instance, the way they survive a restart', () => {
  const first = new store.SqliteRateLimitStore('test-a');
  first.init({ windowMs: 60_000 });

  for (let i = 0; i < 5; i += 1) first.increment('1.2.3.4');

  // A fresh instance is what a restarted process gets. An in-memory store would
  // start again from zero here.
  const second = new store.SqliteRateLimitStore('test-a');
  second.init({ windowMs: 60_000 });

  assert.equal(second.increment('1.2.3.4').totalHits, 6);
});

test('different limiters keep separate counts for the same address', () => {
  const create = new store.SqliteRateLimitStore('test-create');
  const reveal = new store.SqliteRateLimitStore('test-reveal');
  create.init({ windowMs: 60_000 });
  reveal.init({ windowMs: 60_000 });

  create.increment('9.9.9.9');
  create.increment('9.9.9.9');

  assert.equal(reveal.increment('9.9.9.9').totalHits, 1);
});

test('an elapsed window starts counting again from one', () => {
  const shortLived = new store.SqliteRateLimitStore('test-window');
  shortLived.init({ windowMs: -1 }); // already expired the moment it is written

  shortLived.increment('5.5.5.5');
  assert.equal(shortLived.increment('5.5.5.5').totalHits, 1);
});

test('resetKey clears just that key', () => {
  const limiter = new store.SqliteRateLimitStore('test-reset');
  limiter.init({ windowMs: 60_000 });

  limiter.increment('7.7.7.7');
  limiter.increment('8.8.8.8');
  limiter.resetKey('7.7.7.7');

  assert.equal(limiter.increment('7.7.7.7').totalHits, 1);
  assert.equal(limiter.increment('8.8.8.8').totalHits, 2);
});

test('purgeRateLimits drops elapsed windows and keeps live ones', () => {
  const stale = new store.SqliteRateLimitStore('test-purge-old');
  const live = new store.SqliteRateLimitStore('test-purge-new');
  stale.init({ windowMs: -1 });
  live.init({ windowMs: 600_000 });

  stale.increment('1.1.1.1');
  live.increment('2.2.2.2');

  assert.ok(store.purgeRateLimits() >= 1);
  assert.equal(live.increment('2.2.2.2').totalHits, 2, 'live window should survive');
});

/* ------------------------------------------------- blank environment values */

// .env.example ships every optional value blank, so a copied .env is full of
// lines like `MAX_SECRETS=`. The .env loader reads those as empty strings, and `??` does
// not treat an empty string as missing — which once turned the storage ceiling
// into zero and made the app refuse every secret.
test('a blank value is treated the same as an unset one', async () => {
  const { envString, envNumber, envFlag, envTrustProxy } = await import('../src/env.js');

  process.env.BAR_BLANK = '';
  process.env.BAR_SPACES = '   ';
  delete process.env.BAR_UNSET;

  assert.equal(envString('BAR_BLANK', 'fallback'), 'fallback');
  assert.equal(envString('BAR_SPACES', 'fallback'), 'fallback');
  assert.equal(envString('BAR_UNSET', 'fallback'), 'fallback');
  assert.equal(envString('BAR_UNSET'), null);

  assert.equal(envNumber('BAR_BLANK', 10_000), 10_000);
  assert.equal(envNumber('BAR_UNSET', 10_000), 10_000);

  assert.equal(envFlag('BAR_BLANK', true), true);
  assert.equal(envTrustProxy('BAR_BLANK'), false);

  delete process.env.BAR_BLANK;
  delete process.env.BAR_SPACES;
});

test('numbers that would silently disable a feature fall back instead', async () => {
  const { envNumber } = await import('../src/env.js');

  for (const bad of ['0', '-5', 'abc', 'NaN']) {
    process.env.BAR_NUM = bad;
    assert.equal(envNumber('BAR_NUM', 10_000), 10_000, `"${bad}" should fall back`);
  }

  process.env.BAR_NUM = '250';
  assert.equal(envNumber('BAR_NUM', 10_000), 250);

  delete process.env.BAR_NUM;
});

test('trust proxy accepts counts, booleans and named values', async () => {
  const { envTrustProxy } = await import('../src/env.js');

  const cases = [
    ['', false],
    ['false', false],
    ['true', true],
    ['1', 1],
    ['2', 2],
    ['loopback', 'loopback']
  ];

  for (const [raw, expected] of cases) {
    process.env.BAR_TP = raw;
    assert.equal(envTrustProxy('BAR_TP'), expected, `TRUST_PROXY="${raw}"`);
  }

  delete process.env.BAR_TP;
});

test('flags read false/0/no/off as off and anything else as on', async () => {
  const { envFlag } = await import('../src/env.js');

  for (const off of ['false', 'FALSE', '0', 'no', 'off']) {
    process.env.BAR_FLAG = off;
    assert.equal(envFlag('BAR_FLAG', true), false, `"${off}" should be off`);
  }

  for (const on of ['true', '1', 'yes', 'anything']) {
    process.env.BAR_FLAG = on;
    assert.equal(envFlag('BAR_FLAG', false), true, `"${on}" should be on`);
  }

  delete process.env.BAR_FLAG;
});

/* ------------------------------------------------------------- log safety */

test('a secret URL is never written to the log in full', () => {
  const token = crypto.randomUUID();

  assert.equal(redactPath(`/s/${token}`), '/s/:token');
  assert.ok(!redactPath(`/s/${token}`).includes(token));
});

test('ordinary paths are logged as they are', () => {
  assert.equal(redactPath('/'), '/');
  assert.equal(redactPath('/healthz'), '/healthz');
  assert.equal(redactPath('/api/secrets'), '/api/secrets');
});

test('every spelling of a secret URL is redacted, not just the lowercase one', () => {
  // Express routes are case-insensitive, so /S/<token> reaches the reveal, and
  // only "/s/" used to be redacted.
  const token = crypto.randomUUID();

  for (const pathname of [
    `/S/${token}`,
    `/s/${token}/`,
    `//s/${token}`,
    `/s/${token.toUpperCase()}`,
    `/somewhere/${token}`,
    `/x/${token.toUpperCase()}/y`
  ]) {
    const redacted = redactPath(pathname);
    assert.ok(!redacted.toLowerCase().includes(token), `${pathname} -> ${redacted}`);
  }

  assert.equal(redactPath(`/S/${token}`), '/s/:token');
  assert.equal(redactPath(`/x/${token}/y`), '/x/:token/y');
});

/* ------------------------------------------------------- secrets from files */

test('a secret can come from the file NAME_FILE points at', async () => {
  const { envSecret } = await import('../src/env.js');
  const file = path.join(dir, 'secret.txt');

  fs.writeFileSync(file, '  from-a-file\n');
  process.env.BAR_SECRET_FILE = file;
  assert.equal(envSecret('BAR_SECRET'), 'from-a-file', 'trimmed, like any other value');

  fs.writeFileSync(file, '\n');
  assert.equal(envSecret('BAR_SECRET'), null, 'a blank file counts as unset');

  delete process.env.BAR_SECRET_FILE;
  process.env.BAR_SECRET = 'direct';
  assert.equal(envSecret('BAR_SECRET'), 'direct', 'the plain variable still works');

  delete process.env.BAR_SECRET;
  assert.equal(envSecret('BAR_SECRET'), null);
});

test('a secret set both ways, or in a missing file, fails without echoing it', async () => {
  const { envSecret } = await import('../src/env.js');
  const file = path.join(dir, 'both.txt');
  fs.writeFileSync(file, 'file-value');

  process.env.BAR_SECRET = 'direct-value';
  process.env.BAR_SECRET_FILE = file;
  assert.throws(() => envSecret('BAR_SECRET'), (error) => {
    assert.match(error.message, /Set only one/);
    assert.ok(!error.message.includes('direct-value') && !error.message.includes('file-value'));
    return true;
  });

  delete process.env.BAR_SECRET;
  process.env.BAR_SECRET_FILE = path.join(dir, 'missing.txt');
  assert.throws(() => envSecret('BAR_SECRET'), /could not be read \(ENOENT\)/);

  delete process.env.BAR_SECRET_FILE;
});

/* -------------------------------------------------------- what is on disk */

test('deleted secrets are overwritten in the file, not just unlinked', () => {
  assert.equal(db.db.pragma('secure_delete', { simple: true }), 1);
});

test('the sweep empties the write-ahead log, where burned pages linger', async () => {
  const token = crypto.randomUUID();
  db.createSecret({ token, payload: 'iv:tag:cipher', ttlHours: 1 });
  await db.burnSecret(token, (row) => row.payload);

  const wal = `${process.env.DATABASE_PATH}-wal`;
  assert.ok(fs.statSync(wal).size > 0, 'the burn went through the log');

  db.checkpointWal();
  assert.equal(fs.statSync(wal).size, 0);
});

test('the database file is readable by its owner only', (t) => {
  if (process.platform === 'win32') {
    // Windows has no POSIX modes for chmod to set. CI runs this on Linux.
    t.diagnostic('POSIX permissions: not applicable on Windows');
    return;
  }
  for (const suffix of ['', '-wal', '-shm']) {
    const file = `${process.env.DATABASE_PATH}${suffix}`;
    if (!fs.existsSync(file)) continue;
    assert.equal(fs.statSync(file).mode & 0o777, 0o600, file);
  }
});

test('createSecret refuses past maxRows, after reclaiming expired rows', () => {
  db.db.prepare('DELETE FROM secrets').run();
  const expired = db.db.prepare(
    `INSERT INTO secrets (token, payload, expires_at)
     VALUES (?, 'x', datetime('now', '-1 hours'))`
  );
  expired.run('old-1');
  expired.run('old-2');

  const row = (token) => ({ token, payload: 'iv:tag:cipher', ttlHours: 1 });

  // Full of dead rows: they are purged, and the insert goes through.
  assert.equal(db.createSecret(row('new-1'), { maxRows: 2 }), true);
  assert.equal(db.countAll(), 1);

  assert.equal(db.createSecret(row('new-2'), { maxRows: 2 }), true);
  assert.equal(db.createSecret(row('new-3'), { maxRows: 2 }), false, 'full of live rows');
  assert.equal(db.countLive('new-3'), 0);

  db.db.prepare('DELETE FROM secrets').run();
});

/* ------------------------------------------------- rate limiter's warnings */

test('rate-limit warnings go through logEvent, by code, with no client address', async () => {
  // express-rate-limit used to print these straight to the console, as plain
  // text in the middle of a JSON log stream; some of them quote the client IP.
  const { configureLogging } = await import('../src/logging.js');
  const { rateLimitLogger } = await import('../src/limits.js');
  configureLogging({ format: 'json' });

  const warning = Object.assign(
    new Error('An invalid request.ip (203.0.113.9) was detected.'),
    { code: 'ERR_ERL_INVALID_IP_ADDRESS', help: 'https://express-rate-limit.github.io/x/' }
  );
  const lines = capture(() => {
    rateLimitLogger.error(warning);
    rateLimitLogger.error(new Error('database is locked'), 'error from store');
  });
  configureLogging({ format: 'text' });

  const [config, store] = lines.map((line) => JSON.parse(line));
  assert.equal(config.event, 'rate_limit_config');
  assert.equal(config.code, 'ERR_ERL_INVALID_IP_ADDRESS');
  assert.ok(!lines[0].includes('203.0.113.9'), 'the address must not be logged');

  assert.equal(store.event, 'rate_limit_error');
  assert.equal(store.message, 'database is locked');
});

/* ---------------------------------------------------------- log format */

/** Captures whatever the logger writes, whichever console method it uses. */
function capture(run) {
  const lines = [];
  const real = { log: console.log, warn: console.warn, error: console.error };

  console.log = (...args) => lines.push(args.join(' '));
  console.warn = (...args) => lines.push(args.join(' '));
  console.error = (...args) => lines.push(args.join(' '));

  try {
    run();
  } finally {
    Object.assign(console, real);
  }

  return lines;
}

test('the text format stays human-readable', async () => {
  const { configureLogging, logEvent } = await import('../src/logging.js');
  configureLogging({ format: 'text' });

  const [line] = capture(() =>
    logEvent('info', 'request', { method: 'GET', status: 200 }, '[req] GET / 200 1.0ms')
  );

  assert.equal(line, '[req] GET / 200 1.0ms');
});

test('the json format emits one parseable object per line', async () => {
  const { configureLogging, logEvent } = await import('../src/logging.js');
  configureLogging({ format: 'json' });

  const [line] = capture(() =>
    logEvent('warn', 'request', { method: 'POST', path: '/s/:token', status: 401 }, 'ignored')
  );

  const parsed = JSON.parse(line);
  assert.equal(parsed.level, 'warn');
  assert.equal(parsed.event, 'request');
  assert.equal(parsed.path, '/s/:token');
  assert.equal(parsed.status, 401);
  assert.ok(!Number.isNaN(Date.parse(parsed.ts)), 'ts should be a timestamp');

  configureLogging({ format: 'text' });
});

test('an unrecognised format falls back to text rather than failing', async () => {
  const { configureLogging } = await import('../src/logging.js');

  assert.equal(configureLogging({ format: 'yaml' }), 'text');
  assert.equal(configureLogging({}), 'text');
  assert.equal(configureLogging({ format: 'json' }), 'json');

  configureLogging({ format: 'text' });
});

test('json mode never writes a token, whatever the caller passes as text', async () => {
  const { configureLogging, logEvent, redactPath } = await import('../src/logging.js');
  configureLogging({ format: 'json' });

  const token = crypto.randomUUID();
  const [line] = capture(() =>
    logEvent('info', 'request', { path: redactPath(`/s/${token}`) }, `/s/${token}`)
  );

  assert.ok(!line.includes(token), 'the token must not survive into the json line');
  assert.equal(JSON.parse(line).path, '/s/:token');

  configureLogging({ format: 'text' });
});
