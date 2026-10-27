import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

/**
 * Points the app at a throwaway database and a known key, then imports it.
 *
 * Both src/db.js and src/crypto.js read their configuration at module load, so
 * the environment has to be set before the first import — hence the dynamic
 * import here rather than a static one at the top of each test file.
 */
export async function bootTestApp() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bar-test-'));

  process.env.DATABASE_PATH = path.join(dir, 'test.db');
  process.env.SECRET_KEY = crypto.randomBytes(32).toString('hex');
  process.env.NODE_ENV = 'test';
  // Low enough that the storage-ceiling test can reach it without inserting
  // thousands of rows, high enough that no other test bumps into it.
  process.env.MAX_SECRETS = '40';

  const [{ createApp }, db] = await Promise.all([
    import('../src/app.js'),
    import('../src/db.js')
  ]);

  const server = createApp({
    baseUrl: 'http://127.0.0.1',
    logRequests: false // keeps the test output readable
  }).listen(0);
  await new Promise((resolve) => server.once('listening', resolve));

  const { port } = server.address();

  return {
    db,
    url: (pathname) => `http://127.0.0.1:${port}${pathname}`,
    async close() {
      await new Promise((resolve) => server.close(resolve));
      db.db.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  };
}

/** POST to the create endpoint and return the status and parsed body. */
async function postSecret(app, fields) {
  const response = await fetch(app.url('/api/secrets'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(fields)
  });

  return { status: response.status, body: await response.json() };
}

/**
 * Create a secret the way an API client does: plaintext, encrypted server-side.
 * @param {{ ttlHours?: number, passphrase?: string }} [options]
 */
export function createSecret(app, message, { ttlHours, passphrase } = {}) {
  return postSecret(app, { message, ttlHours, passphrase });
}

/**
 * Create a secret the way the web form does: encrypted first with the same
 * module the browser runs, so only ciphertext is sent, and with a passphrase
 * sent as the stand-in the page derives from it, never as itself. Also returns
 * the key that would go after the # in the link, and that stand-in, which is
 * what a reveal must then send.
 */
export async function createEncryptedSecret(app, message, { ttlHours, passphrase } = {}) {
  const { encryptMessage, passphraseVerifier } = await import('../src/client/e2e.js');
  const { ciphertext, key } = await encryptMessage(message);
  const standIn = passphrase ? await passphraseVerifier(passphrase, key) : undefined;

  return {
    ...(await postSecret(app, { ciphertext, ttlHours, passphrase: standIn })),
    key,
    ciphertext,
    standIn
  };
}

/**
 * Submit the reveal form the way a browser would, optionally with a passphrase.
 */
export function reveal(app, token, passphrase) {
  const headers = { 'Sec-Fetch-Site': 'same-origin' };
  if (passphrase === undefined) {
    return fetch(app.url(`/s/${token}`), { method: 'POST', headers });
  }

  return fetch(app.url(`/s/${token}`), {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ passphrase }).toString()
  });
}

/** Pulls the ciphertext out of the secret page's data attribute. */
export function ciphertextFrom(html) {
  return html.match(/data-ciphertext="([A-Za-z0-9_-]+)"/)?.[1] ?? null;
}
