import { db } from './db.js';

/**
 * A rate-limit store backed by the SQLite file the app already has open.
 *
 * express-rate-limit ships with an in-memory store, which has two problems here:
 * counters reset on every restart (so an attacker just waits for a deploy), and
 * running more than one process gives each its own budget — two instances of a
 * "20 per 15 minutes" limit quietly allow 40.
 *
 * Redis would be the usual answer. Using the existing database keeps the project
 * to a single file with no extra service to run, which is the whole point of
 * choosing SQLite in the first place.
 */

db.exec(`
  CREATE TABLE IF NOT EXISTS rate_limits (
    key      TEXT    PRIMARY KEY,
    hits     INTEGER NOT NULL,
    reset_at INTEGER NOT NULL          -- epoch milliseconds
  );

  CREATE INDEX IF NOT EXISTS idx_rate_limits_reset_at ON rate_limits (reset_at);
`);

const statements = {
  get: db.prepare('SELECT hits, reset_at FROM rate_limits WHERE key = ?'),
  start: db.prepare(`
    INSERT INTO rate_limits (key, hits, reset_at) VALUES (?, 1, ?)
    ON CONFLICT(key) DO UPDATE SET hits = 1, reset_at = excluded.reset_at
  `),
  bump: db.prepare('UPDATE rate_limits SET hits = hits + 1 WHERE key = ?'),
  decrement: db.prepare(
    'UPDATE rate_limits SET hits = hits - 1 WHERE key = ? AND hits > 0'
  ),
  reset: db.prepare('DELETE FROM rate_limits WHERE key = ?'),
  purge: db.prepare('DELETE FROM rate_limits WHERE reset_at <= ?')
};

/** Drops windows that have already elapsed. Called from the hourly sweep. */
export function purgeRateLimits() {
  return statements.purge.run(Date.now()).changes;
}

export class SqliteRateLimitStore {
  /** express-rate-limit hands each store its own key prefix. */
  constructor(prefix) {
    this.prefix = prefix;
    this.windowMs = 60_000;
    // Tells express-rate-limit the counts are shared, not per-process.
    this.localKeys = false;
  }

  init(options) {
    this.windowMs = options.windowMs;
  }

  #key(key) {
    return `${this.prefix}:${key}`;
  }

  /**
   * Reading and writing in one transaction matters: without it, two requests
   * arriving together can both read the same count and both write count+1,
   * losing a hit and letting a caller slip past the limit.
   */
  increment(key) {
    const scoped = this.#key(key);
    const now = Date.now();

    const run = db.transaction(() => {
      const existing = statements.get.get(scoped);

      // No window yet, or the previous one has elapsed — start a fresh one.
      if (!existing || existing.reset_at <= now) {
        const resetAt = now + this.windowMs;
        statements.start.run(scoped, resetAt);
        return { hits: 1, resetAt };
      }

      statements.bump.run(scoped);
      return { hits: existing.hits + 1, resetAt: existing.reset_at };
    });

    // Immediate, for the same reason as recordFailedAttempt in db.js: it takes
    // the write lock before the read. A deferred transaction reads first and
    // then has to upgrade, and SQLite refuses that upgrade with SQLITE_BUSY,
    // without waiting, whenever another connection has written in between.
    // Immediate waits its turn instead (the 5 s busy timeout), so several
    // processes sharing the file all get counted.
    const { hits, resetAt } = run.immediate();
    return { totalHits: hits, resetTime: new Date(resetAt) };
  }

  decrement(key) {
    statements.decrement.run(this.#key(key));
  }

  resetKey(key) {
    statements.reset.run(this.#key(key));
  }
}
