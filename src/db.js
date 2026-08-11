import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');

const DB_PATH = process.env.DATABASE_PATH
  ? path.resolve(ROOT, process.env.DATABASE_PATH)
  : path.join(ROOT, 'data', 'app.db');

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

export const db = new Database(DB_PATH);

// WAL keeps reads from blocking the write that burns a secret.
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS secrets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token       TEXT    NOT NULL UNIQUE,
    payload     TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    expires_at  TEXT    NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_secrets_token ON secrets (token);
  CREATE INDEX IF NOT EXISTS idx_secrets_expires_at ON secrets (expires_at);
`);

// Additive migrations for databases created before passphrases existed. SQLite
// has no "ADD COLUMN IF NOT EXISTS", so check what is already there.
const existingColumns = new Set(
  db.prepare('PRAGMA table_info(secrets)').all().map((column) => column.name)
);

if (!existingColumns.has('requires_passphrase')) {
  db.exec('ALTER TABLE secrets ADD COLUMN requires_passphrase INTEGER NOT NULL DEFAULT 0');
}
if (!existingColumns.has('attempts')) {
  db.exec('ALTER TABLE secrets ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0');
}

/**
 * Wrong passphrases allowed before the secret is destroyed. Bounds an online
 * guessing attack, and restores the property that probing a link is not free:
 * a prober who keeps getting it wrong ends up burning the thing they were
 * probing. Anyone holding the link could destroy it by revealing it anyway, so
 * this adds no denial-of-service that was not already available.
 */
export const MAX_PASSPHRASE_ATTEMPTS = 5;

const statements = {
  insert: db.prepare(`
    INSERT INTO secrets (token, payload, expires_at, requires_passphrase)
    VALUES (@token, @payload, datetime('now', @ttl), @requiresPassphrase)
  `),
  selectForBurn: db.prepare(`
    SELECT payload, created_at, requires_passphrase, attempts
    FROM secrets
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
 * @param {{ token: string, payload: string, ttlHours: number }} secret
 */
export function createSecret({ token, payload, ttlHours, requiresPassphrase = false }) {
  statements.insert.run({
    token,
    payload,
    ttl: `+${ttlHours} hours`,
    requiresPassphrase: requiresPassphrase ? 1 : 0
  });
}

/**
 * Fetch, unseal and destroy a secret — all inside one immediate transaction.
 *
 * The whole guarantee of this app lives in this function. `BEGIN IMMEDIATE` takes
 * the write lock before reading, so two callers arriving together are serialised
 * rather than both reading the row and both being handed the plaintext. (A
 * deferred transaction would not do: both would read, then one would fail on
 * upgrade.)
 *
 * `unseal` is run inside the transaction and decides the outcome. If it throws —
 * a wrong passphrase — the row is kept and the attempt counted, so a typo does
 * not destroy the secret. Only a successful unseal deletes.
 *
 * @param {string} token
 * @param {(row: { payload: string, requires_passphrase: number }) => string} unseal
 * @returns {{ status: 'ok', message: string, createdAt: string }
 *          | { status: 'missing' }
 *          | { status: 'exhausted' }
 *          | { status: 'locked', attemptsLeft: number }}
 */
export function burnSecret(token, unseal) {
  const run = db.transaction(() => {
    const row = statements.selectForBurn.get(token);
    if (!row) return { status: 'missing' };

    let message;
    try {
      message = unseal(row);
    } catch {
      const used = row.attempts + 1;

      if (used >= MAX_PASSPHRASE_ATTEMPTS) {
        statements.deleteByToken.run(token);
        return { status: 'exhausted' };
      }

      statements.bumpAttempts.run(token);
      return { status: 'locked', attemptsLeft: MAX_PASSPHRASE_ATTEMPTS - used };
    }

    statements.deleteByToken.run(token);
    return { status: 'ok', message, createdAt: row.created_at };
  });

  return run.immediate();
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

export { DB_PATH };
