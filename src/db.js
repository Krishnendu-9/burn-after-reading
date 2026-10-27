import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';

import { envString } from './env.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');

const configuredPath = envString('DATABASE_PATH');
const DB_PATH = configuredPath
  ? path.resolve(ROOT, configuredPath)
  : path.join(ROOT, 'data', 'app.db');

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

export const db = new Database(DB_PATH);

/**
 * WAL keeps reads from blocking the write that burns a secret.
 *
 * Switching a brand-new file to WAL needs every other connection out of the way,
 * and SQLite answers SQLITE_BUSY at once instead of waiting out the busy timeout.
 * That only happens when several processes open a new database together, such
 * as cluster mode on first boot, so retry briefly rather than crash the worker.
 * Once the file is in WAL mode it stays there, and this succeeds first time.
 */
function enableWal() {
  const deadline = Date.now() + 5_000;
  const pause = new Int32Array(new SharedArrayBuffer(4));

  for (;;) {
    try {
      db.pragma('journal_mode = WAL');
      return;
    } catch (error) {
      if (error.code !== 'SQLITE_BUSY' || Date.now() >= deadline) throw error;
      Atomics.wait(pause, 0, 0, 25); // a synchronous 25 ms pause; this runs once, at startup
    }
  }
}

enableWal();

const addedColumns = {
  requires_passphrase: 'INTEGER NOT NULL DEFAULT 0',
  attempts: 'INTEGER NOT NULL DEFAULT 0',
  // 1 when the browser encrypted the message before sending it, so the stored
  // payload wraps ciphertext the server holds no key for.
  client_encrypted: 'INTEGER NOT NULL DEFAULT 0'
};

/**
 * Creates the table and adds any columns an older database lacks.
 *
 * One immediate transaction, for the same reason as the store's increment():
 * the migration reads the columns and then alters the table, and two processes
 * opening a new file together could both see a column missing, so the second
 * ALTER failed with "duplicate column name" (SQLITE_ERROR) and that process
 * crashed at startup. Taking the write lock first makes the second process wait,
 * then find the columns already there.
 */
const migrate = db.transaction(() => {
  // `token` needs no index of its own: UNIQUE already creates one.
  db.exec(`
    CREATE TABLE IF NOT EXISTS secrets (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      token       TEXT    NOT NULL UNIQUE,
      payload     TEXT    NOT NULL,
      created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
      expires_at  TEXT    NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_secrets_expires_at ON secrets (expires_at);

    -- Older databases carry a second, redundant index on token.
    DROP INDEX IF EXISTS idx_secrets_token;
  `);

  // Additive migrations for databases created before these columns existed.
  // SQLite has no "ADD COLUMN IF NOT EXISTS", so check what is already there.
  const existingColumns = new Set(
    db.prepare('PRAGMA table_info(secrets)').all().map((column) => column.name)
  );

  for (const [name, definition] of Object.entries(addedColumns)) {
    if (!existingColumns.has(name)) {
      db.exec(`ALTER TABLE secrets ADD COLUMN ${name} ${definition}`);
    }
  }
});

migrate.immediate();

/**
 * Wrong passphrases allowed before the secret is destroyed.
 *
 * It bounds online guessing per secret, however many addresses the guesses
 * come from. Rate limits are per address, so on their own they would let a
 * guesser spread across many addresses keep going for the whole TTL, up to a
 * week, and a short passphrase would not survive that.
 *
 * It also bounds probing. A wrong passphrase answers 401 where a missing secret
 * answers 404, so every attempt confirms the secret is still unread. A request
 * with no passphrase at all counts as wrong for the same reason; otherwise that
 * check would be free and unlimited.
 *
 * The cost is a denial of service that only exists because of this limit. For an
 * unprotected secret nothing changes, since anyone holding the link can already
 * destroy it by reading it. For a protected one it is new: someone who has the
 * link but not the passphrase could not otherwise touch the secret, and with the
 * limit five POSTs destroy it. That is accepted on purpose. The passphrase is
 * there so that an intercepted link does not disclose the secret, and the limit
 * is what keeps that true; the price is that interception can still end in
 * destruction. Destruction is visible, because the recipient finds the secret
 * already gone, and recoverable, because the sender can send a new link over a
 * better channel. Unbounded guessing would instead end in disclosure, which
 * nothing undoes.
 */
export const MAX_PASSPHRASE_ATTEMPTS = 5;

const statements = {
  insert: db.prepare(`
    INSERT INTO secrets (token, payload, expires_at, requires_passphrase, client_encrypted)
    VALUES (@token, @payload, datetime('now', @ttl), @requiresPassphrase, @clientEncrypted)
  `),
  selectForBurn: db.prepare(`
    SELECT payload, created_at, requires_passphrase, client_encrypted, attempts
    FROM secrets
    WHERE token = ? AND expires_at > datetime('now')
  `),
  consume: db.prepare(`
    DELETE FROM secrets
    WHERE token = ? AND expires_at > datetime('now')
  `),
  deleteByToken: db.prepare('DELETE FROM secrets WHERE token = ?'),
  bumpAttempts: db.prepare('UPDATE secrets SET attempts = attempts + 1 WHERE token = ?'),
  purgeExpired: db.prepare(`DELETE FROM secrets WHERE expires_at <= datetime('now')`),
  countLive: db.prepare(`
    SELECT COUNT(*) AS n
    FROM secrets
    WHERE token = ? AND expires_at > datetime('now')
  `),
  ping: db.prepare('SELECT 1 AS ok'),
  countAll: db.prepare('SELECT COUNT(*) AS n FROM secrets')
};

/**
 * Store an encrypted payload under a token.
 * @param {{ token: string, payload: string, ttlHours: number,
 *           requiresPassphrase?: boolean, clientEncrypted?: boolean }} secret
 */
export function createSecret({
  token,
  payload,
  ttlHours,
  requiresPassphrase = false,
  clientEncrypted = false
}) {
  statements.insert.run({
    token,
    payload,
    ttl: `+${ttlHours} hours`,
    requiresPassphrase: requiresPassphrase ? 1 : 0,
    clientEncrypted: clientEncrypted ? 1 : 0
  });
}

/**
 * Counts one wrong passphrase, destroying the secret on the last allowed one.
 *
 * Read-then-write, so it runs as an immediate transaction: the write lock is
 * taken before the read, and two wrong guesses arriving together are counted as
 * two rather than both reading the same count and both writing count+1.
 */
const recordFailedAttempt = db.transaction((token) => {
  const row = statements.selectForBurn.get(token);
  if (!row) return { status: 'missing' };

  const used = row.attempts + 1;

  if (used >= MAX_PASSPHRASE_ATTEMPTS) {
    statements.deleteByToken.run(token);
    return { status: 'exhausted' };
  }

  statements.bumpAttempts.run(token);
  return { status: 'locked', attemptsLeft: MAX_PASSPHRASE_ATTEMPTS - used };
});

/**
 * Thrown by an `unseal` callback when the server itself can't open a row — its
 * key has changed without rotation, or the stored payload is damaged. That is
 * never the reader's fault, so it must not cost a passphrase attempt, and the
 * row is kept: restoring the key (SECRET_KEY_PREVIOUS) makes it readable again.
 */
export class UnreadableSecretError extends Error {
  constructor(cause) {
    super('The server could not decrypt this secret', { cause });
    this.name = 'UnreadableSecretError';
  }
}

/**
 * Fetch, unseal and destroy a secret, handing the plaintext to exactly one caller.
 *
 * The whole guarantee of this app lives in this function. Any number of callers
 * may read the row and unseal it at the same moment — unsealing is async, since
 * scrypt runs on the thread pool, so a lock cannot be held across it. What
 * decides the winner is the DELETE afterwards: SQLite executes it atomically, so
 * it removes the row for exactly one caller. Only that caller is given the
 * message; every other one sees `missing`, as if it had arrived after the burn.
 *
 * The naive version — return the message because the SELECT found a row —
 * hands the same secret to every concurrent reader. The race test catches that.
 *
 * `unseal` decides the outcome. If it throws — a wrong passphrase — the row is
 * kept and the attempt counted, so a typo does not destroy the secret. If it
 * throws UnreadableSecretError, the row is kept and nothing is counted. Only a
 * successful unseal deletes.
 *
 * @param {string} token
 * @param {(row: { payload: string, requires_passphrase: number }) => string | Promise<string>} unseal
 * @returns {Promise<{ status: 'ok', message: string, createdAt: string, clientEncrypted: boolean }
 *          | { status: 'missing' }
 *          | { status: 'unreadable' }
 *          | { status: 'exhausted' }
 *          | { status: 'locked', attemptsLeft: number }>}
 */
export async function burnSecret(token, unseal) {
  const row = statements.selectForBurn.get(token);
  if (!row) return { status: 'missing' };

  let message;
  try {
    message = await unseal(row);
  } catch (error) {
    if (error instanceof UnreadableSecretError) return { status: 'unreadable' };
    return recordFailedAttempt.immediate(token);
  }

  if (statements.consume.run(token).changes !== 1) {
    return { status: 'missing' };
  }

  return {
    status: 'ok',
    message,
    createdAt: row.created_at,
    clientEncrypted: row.client_encrypted === 1
  };
}

/**
 * Count live rows for a token. Not used by any route — deliberately, since an
 * existence check reachable over HTTP is exactly the leak the two-step reveal
 * avoids. It exists so tests can assert what is actually on disk.
 */
export function countLive(token) {
  return statements.countLive.get(token).n;
}

/**
 * Total rows on disk, expired ones included. Used to enforce the storage
 * ceiling — rate limits are per address, so they cap one abuser, not a crowd.
 */
export function countAll() {
  return statements.countAll.get().n;
}

/** Drop rows nobody will ever be able to read again. */
export function purgeExpired() {
  return statements.purgeExpired.run().changes;
}

/**
 * Cheap round trip proving the database file is still open and answering.
 * Throws if it is not, which is what the health endpoint reports on.
 */
export function pingDatabase() {
  return statements.ping.get().ok === 1;
}

/**
 * Closes the database cleanly on shutdown. The WAL checkpoint folds the
 * write-ahead log back into the main file, so a container restart doesn't leave
 * `-wal` and `-shm` files behind for the next boot to recover.
 */
export function closeDatabase() {
  if (!db.open) return;
  try {
    db.pragma('wal_checkpoint(TRUNCATE)');
  } finally {
    db.close();
  }
}
