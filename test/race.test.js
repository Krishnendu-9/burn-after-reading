import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { Worker } from 'node:worker_threads';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WORKER = path.join(__dirname, 'race-worker.js');
const WORKERS = 8;

let dir;
let dbPath;
let key;
let db;

before(async () => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bar-race-'));
  dbPath = path.join(dir, 'race.db');
  key = crypto.randomBytes(32).toString('hex');

  process.env.DATABASE_PATH = dbPath;
  process.env.SECRET_KEY = key;

  db = await import('../src/db.js');
});

after(() => {
  db.closeDatabase();
  fs.rmSync(dir, { recursive: true, force: true });
});

/**
 * Starts N worker threads, each with its own database connection, all parked on
 * an Atomics barrier. Opening the barrier releases them at once.
 */
async function race(token) {
  const gate = new SharedArrayBuffer(4);
  const gateView = new Int32Array(gate);

  const workers = [];
  const results = [];

  const ready = [];
  const finished = [];

  for (let i = 0; i < WORKERS; i += 1) {
    const worker = new Worker(WORKER, {
      workerData: { dbPath, key, token, gate }
    });
    workers.push(worker);

    let markReady;
    let markFinished;
    ready.push(new Promise((resolve) => { markReady = resolve; }));
    finished.push(new Promise((resolve) => { markFinished = resolve; }));

    worker.on('message', (message) => {
      if (message.ready) return markReady();
      results.push(message);
      markFinished();
    });
  }

  // Everyone is loaded and waiting — now release them together.
  await Promise.all(ready);
  Atomics.store(gateView, 0, 1);
  Atomics.notify(gateView, 0);

  await Promise.all(finished);
  await Promise.all(workers.map((worker) => worker.terminate()));

  return results;
}

test(`${WORKERS} threads racing the same link: exactly one wins`, async () => {
  const token = crypto.randomUUID();
  db.createSecret({ token, payload: 'iv:tag:cipher', ttlHours: 1 });

  const results = await race(token);

  const errors = results.filter((r) => r.error);
  const winners = results.filter((r) => r.won);

  assert.equal(results.length, WORKERS, 'every worker should have reported back');
  assert.deepEqual(errors, [], `no worker should error: ${JSON.stringify(errors)}`);
  assert.equal(
    winners.length,
    1,
    `exactly one thread may burn the secret, got ${winners.length}`
  );
  assert.equal(db.countLive(token), 0, 'the row must be gone afterwards');
});

test('racing a token that does not exist produces no winners', async () => {
  const results = await race(crypto.randomUUID());

  assert.equal(results.filter((r) => r.won).length, 0);
  assert.deepEqual(results.filter((r) => r.error), []);
});

/* ------------------------------------------------------ several processes */

/**
 * Starts N workers, each with its own connection to `file`, and releases them
 * together twice: once to open the database, once to start counting. This is
 * cluster mode in miniature, every worker sharing one SQLite file.
 */
async function cluster(file, increments) {
  const openGate = new SharedArrayBuffer(4);
  const runGate = new SharedArrayBuffer(4);
  const release = (gate) => {
    Atomics.store(new Int32Array(gate), 0, 1);
    Atomics.notify(new Int32Array(gate), 0);
  };

  const workers = [];
  const outcomes = await new Promise((resolve) => {
    let loaded = 0;
    let settled = 0;
    const results = [];
    const settle = () => {
      settled += 1;
      if (settled === WORKERS) release(runGate);
    };

    for (let i = 0; i < WORKERS; i += 1) {
      const worker = new Worker(path.join(__dirname, 'rate-limit-worker.js'), {
        workerData: { dbPath: file, key, openGate, runGate, increments }
      });
      workers.push(worker);

      worker.on('message', (message) => {
        if (message.loaded && ++loaded === WORKERS) release(openGate);
        if (message.ready) settle();
        if (message.startupError) {
          results.push(message);
          settle();
        }
        if (message.done) results.push(message);
        if (results.length === WORKERS) resolve(results);
      });
    }
  });
  await Promise.all(workers.map((worker) => worker.terminate()));

  return {
    startupErrors: outcomes.filter((o) => o.startupError).map((o) => o.startupError),
    errors: outcomes.flatMap((o) => o.errors ?? []),
    counted: outcomes.reduce((sum, o) => sum + (o.counted ?? 0), 0)
  };
}

test(`${WORKERS} connections opening a brand-new database together all start`, async () => {
  // Switching a new file to WAL once failed with SQLITE_BUSY for whichever
  // workers lost the race, so they crashed before serving anything. It does
  // not happen on every opening, so several fresh files are tried.
  const ROUNDS = 6;
  const failures = [];

  for (let round = 0; round < ROUNDS; round += 1) {
    const { startupErrors } = await cluster(path.join(dir, `fresh-${round}.db`), 0);
    failures.push(...startupErrors);
  }

  assert.deepEqual(failures, [], `${failures.length} of ${ROUNDS * WORKERS} workers failed to open`);
});

test(`${WORKERS} connections counting the same client at once: no errors, no lost hits`, async () => {
  // A deferred transaction in the store made most of these fail with
  // SQLITE_BUSY: it reads first, and SQLite refuses the later upgrade to a write
  // without waiting whenever another connection wrote in between.
  const INCREMENTS = 100;
  const file = path.join(dir, 'counting.db');
  const { startupErrors, errors, counted } = await cluster(file, INCREMENTS);

  assert.deepEqual(startupErrors, []);
  assert.equal(errors.length, 0, `${errors.length} increments threw, e.g. ${errors[0]}`);
  assert.equal(counted, WORKERS * INCREMENTS);

  // Read back through a connection of its own to the shared file.
  const Database = (await import('better-sqlite3')).default;
  const check = new Database(file, { readonly: true });
  const { hits } = check.prepare('SELECT hits FROM rate_limits WHERE key = ?').get('cluster:203.0.113.7');
  check.close();

  assert.equal(hits, WORKERS * INCREMENTS, 'no hit may be lost');
});
