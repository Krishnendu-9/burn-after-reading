import { parentPort, workerData } from 'node:worker_threads';

// Each worker opens its own connection to the same SQLite file, so this is a
// genuine multi-connection race rather than a single-threaded loop.
process.env.DATABASE_PATH = workerData.dbPath;
process.env.SECRET_KEY = workerData.key;

const { burnSecret } = await import('../src/db.js');

const gate = new Int32Array(workerData.gate);

parentPort.postMessage({ ready: true });

// Block until the main thread opens the gate, so every worker calls burnSecret
// at as close to the same instant as the OS will allow.
Atomics.wait(gate, 0, 0);

let won = false;
let error = null;

try {
  // No passphrase in play here — the unseal step just hands the payload back, so
  // the test measures the transaction, not the crypto.
  won = burnSecret(workerData.token, (row) => row.payload).status === 'ok';
} catch (thrown) {
  error = thrown.message;
}

parentPort.postMessage({ won, error });
