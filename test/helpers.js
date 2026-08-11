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

/** POST a secret and return the parsed response body. */
export async function createSecret(app, message, ttlHours) {
  const response = await fetch(app.url('/api/secrets'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message, ttlHours })
  });

  return { status: response.status, body: await response.json() };
}

/** Submit the reveal form the way a browser would. */
export function reveal(app, token) {
  return fetch(app.url(`/s/${token}`), {
    method: 'POST',
    headers: { 'Sec-Fetch-Site': 'same-origin' }
  });
}
