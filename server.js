import './src/load-env.js';

import { createApp } from './src/app.js';
import { purgeExpired, checkpointWal, closeDatabase } from './src/db.js';
import { purgeRateLimits } from './src/rate-limit-store.js';
import { envNumber, envString, envFlag, envTrustProxy } from './src/env.js';
import { configureLogging, logEvent } from './src/logging.js';

const PORT = envNumber('PORT', 3000);
const BASE_URL = envString('BASE_URL', `http://localhost:${PORT}`).replace(/\/+$/, '');
const SWEEP_INTERVAL_MS = 60 * 60 * 1000;
const SHUTDOWN_GRACE_MS = 10_000;

/**
 * How many reverse-proxy hops to trust for `req.ip` and `req.secure`.
 *
 * Off by default, and it must stay off unless a proxy really is in front. With
 * it on and nothing between the app and the internet, a client can send its own
 * `X-Forwarded-For` header and every rate limit keys off that forged address —
 * rotate the value and the limits never trigger at all.
 */
const trustProxy = envTrustProxy('TRUST_PROXY');

// Set before anything logs, so the whole stream is one format.
const logFormat = configureLogging({ format: envString('LOG_FORMAT', 'text') });

/* ------------------------------------------------------------------- start */

let app;
try {
  app = createApp({
    baseUrl: BASE_URL,
    repoUrl: envString('REPO_URL'),
    authorName: envString('AUTHOR_NAME'),
    trustProxy,
    logRequests: envFlag('LOG_REQUESTS', true)
  });
} catch (error) {
  // The two things that realistically stop a first run, both with a fix the
  // operator can act on immediately rather than a raw stack trace.
  console.error(`\n  Cannot start burn-after-reading.\n  ${error.message}\n`);

  if (/SECRET_KEY/i.test(error.message)) {
    console.error('  Fix: run `npm run keygen` and put the printed line in your .env file.\n');
  } else if (/manifest/i.test(error.message)) {
    console.error('  Fix: run `npm run build` to compile the CSS and JavaScript first.\n');
  } else {
    console.error(error.stack);
  }

  process.exit(1);
}

/**
 * Deletes expired rows. Wrapped because this runs on a timer, and an exception
 * thrown from a timer callback is an uncaught exception — a failed sweep would
 * otherwise take the whole server down at some quiet hour. A missed sweep is
 * harmless: the burn query already refuses to return expired rows, so they are
 * unreadable either way and the next run clears them.
 */
function sweepExpired() {
  try {
    const removed = purgeExpired();
    if (removed > 0) {
      logEvent('info', 'purge', { removed }, `[purge] removed ${removed} expired secret${removed === 1 ? '' : 's'}`);
    }
    // Elapsed rate-limit windows are dead weight once their reset time passes.
    purgeRateLimits();
    // Burned and purged secrets leave page images in the write-ahead log until
    // it is reset; this empties it.
    checkpointWal();
  } catch (error) {
    logEvent('error', 'purge_failed', { message: error.message }, `[purge] sweep failed, will retry next hour — ${error.message}`);
  }
}

sweepExpired();
const sweepTimer = setInterval(sweepExpired, SWEEP_INTERVAL_MS);
sweepTimer.unref();

const server = app.listen(PORT, () => {
  logEvent(
    'info',
    'listening',
    { url: BASE_URL, port: PORT, trustProxy, logFormat },
    `burn-after-reading listening on ${BASE_URL}`
  );

  // Every link is built from BASE_URL, so a wrong one ships broken links. And
  // over plain HTTP the browser cannot encrypt, so the end-to-end layer is gone.
  if (process.env.NODE_ENV === 'production' && !isPublicHttps(BASE_URL)) {
    logEvent(
      'warn',
      'base_url_not_public_https',
      { baseUrl: BASE_URL, hint: 'Set BASE_URL to the https:// address people actually reach.' },
      `[warn] BASE_URL is ${BASE_URL}. Links are built from it, so in production it\n` +
        '       must be the public https:// address; over plain HTTP browsers cannot\n' +
        '       encrypt secrets themselves.'
    );
  }

  if (process.env.NODE_ENV === 'production' && trustProxy === false) {
    logEvent(
      'warn',
      'trust_proxy_off',
      { hint: 'Set TRUST_PROXY=1 if a reverse proxy is in front.' },
      '[warn] TRUST_PROXY is off. Behind a reverse proxy this makes every client\n' +
        '       look like the proxy (so one visitor can exhaust the rate limit for\n' +
        '       everyone) and stops HSTS being sent. Set TRUST_PROXY=1 if there is\n' +
        '       a proxy in front. Leave it off if the app is exposed directly.'
    );
  }
});

/** An https:// URL whose host is not this machine. */
function isPublicHttps(url) {
  try {
    const { protocol, hostname } = new URL(url);
    return protocol === 'https:' && !['localhost', '127.0.0.1', '[::1]'].includes(hostname);
  } catch {
    return false;
  }
}

/* ---------------------------------------------------------------- shutdown */

let shuttingDown = false;

/**
 * Stops accepting connections, lets in-flight requests finish, then closes
 * SQLite properly. Without this, a container restart is effectively a kill -9 on
 * the database and leaves the write-ahead log to be recovered on next boot.
 */
function shutdown(reason, exitCode = 0) {
  if (shuttingDown) return;
  shuttingDown = true;

  logEvent('info', 'shutdown', { reason }, `\n[shutdown] ${reason} — closing down`);
  clearInterval(sweepTimer);

  // Never hang forever on a request that refuses to finish.
  const forceExit = setTimeout(() => {
    logEvent(
      'error',
      'shutdown_timeout',
      { graceMs: SHUTDOWN_GRACE_MS },
      '[shutdown] timed out waiting for connections, forcing exit'
    );
    process.exit(exitCode || 1);
  }, SHUTDOWN_GRACE_MS);
  forceExit.unref();

  server.close(() => {
    try {
      closeDatabase();
    } catch (error) {
      logEvent(
        'error',
        'shutdown_db_close_failed',
        { message: error.message },
        `[shutdown] closing the database failed — ${error.message}`
      );
    }
    clearTimeout(forceExit);
    process.exit(exitCode);
  });
}

// SIGTERM is what container platforms send before stopping a process; SIGINT is
// Ctrl+C in a terminal.
process.on('SIGTERM', () => shutdown('SIGTERM received'));
process.on('SIGINT', () => shutdown('SIGINT received'));

// Last resort. Node's default for both of these is to print and die immediately,
// which skips the database close. Log the cause, shut down cleanly, exit non-zero
// so the platform knows to restart us.
process.on('unhandledRejection', (reason) => {
  const message = reason instanceof Error ? reason.message : String(reason);
  const stack = reason instanceof Error ? (reason.stack ?? null) : null;
  logEvent(
    'error',
    'unhandled_rejection',
    { message, stack },
    `[fatal] unhandled promise rejection — ${message}\n${stack ?? ''}`
  );
  shutdown('unhandled rejection', 1);
});

process.on('uncaughtException', (error) => {
  logEvent(
    'error',
    'uncaught_exception',
    { message: error.message, stack: error.stack ?? null },
    `[fatal] uncaught exception — ${error.message}\n${error.stack ?? ''}`
  );
  shutdown('uncaught exception', 1);
});
