import { parentPort, workerData } from 'node:worker_threads';

// One of several separate connections to the same, brand-new SQLite file: the
// situation of cluster-mode workers on first boot.
process.env.DATABASE_PATH = workerData.dbPath;
process.env.SECRET_KEY = workerData.key;

const openGate = new Int32Array(workerData.openGate);
const runGate = new Int32Array(workerData.runGate);

// Load the native driver first, so that after the gate the only work left is
// db.js opening the file; otherwise load times spread the workers out and they
// rarely collide.
await import('better-sqlite3');

parentPort.postMessage({ loaded: true });
Atomics.wait(openGate, 0, 0); // every worker opens the file at the same moment

let store;
try {
  const { SqliteRateLimitStore } = await import('../src/rate-limit-store.js');
  store = new SqliteRateLimitStore('cluster');
  store.init({ windowMs: 600_000 });
} catch (error) {
  parentPort.postMessage({ startupError: error.code ?? error.message });
  process.exit(0);
}

parentPort.postMessage({ ready: true });
Atomics.wait(runGate, 0, 0); // and then they all start counting at once

let counted = 0;
const errors = [];
for (let i = 0; i < workerData.increments; i += 1) {
  try {
    store.increment('203.0.113.7');
    counted += 1;
  } catch (error) {
    errors.push(error.code ?? error.message);
  }
}

parentPort.postMessage({ done: true, counted, errors });
