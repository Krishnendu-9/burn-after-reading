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
