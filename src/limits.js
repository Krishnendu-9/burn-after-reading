import { rateLimit } from 'express-rate-limit';

import { SqliteRateLimitStore } from './rate-limit-store.js';

const WINDOW_MS = 15 * 60 * 1000;

/**
 * Shared config. `standardHeaders` emits the RateLimit-* headers so a caller can
 * see its own budget; the legacy X-RateLimit-* set is redundant, so it is off.
 *
 * Counts live in SQLite rather than memory, so they survive a restart and stay
 * consistent if the app is ever run as more than one process.
 */
function limiter({ name, limit, message }) {
  return rateLimit({
    windowMs: WINDOW_MS,
    limit,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    store: new SqliteRateLimitStore(name),
    handler(req, res) {
      // By path rather than per limiter, the same rule as the error handler in
      // app.js: the global limiter also covers the JSON API, and an HTML page
      // there left the compose form with nothing it could show.
      if (req.originalUrl.startsWith('/api/')) {
        return res.status(429).json({ error: message });
      }
      res.status(429).render('too-many', { message });
    }
  });
}

/**
 * Creating secrets is the expensive path — every call writes a row that sticks
 * around until it is read or expires, so an unthrottled endpoint is a way to
 * fill the disk.
 */
export const createLimiter = limiter({
  name: 'create',
  limit: 20,
  message: 'Too many secrets created from this address. Try again in a few minutes.'
});

/**
 * Tokens are UUID v4 (122 bits of entropy), so guessing one is not a realistic
 * attack. This exists to stop someone hammering the endpoint for its own sake.
 */
export const revealLimiter = limiter({
  name: 'reveal',
  limit: 60,
  message: 'Too many attempts from this address. Try again in a few minutes.'
});

/** Catch-all backstop for everything else. */
export const globalLimiter = limiter({
  name: 'global',
  limit: 300,
  message: 'Too many requests from this address. Try again in a few minutes.'
});
