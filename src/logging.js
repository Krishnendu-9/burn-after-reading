/**
 * Logging, built around what must *not* be recorded.
 *
 * The URL of a secret is the secret — anyone reading `/s/<token>` out of a log
 * file before the recipient opens the link gets the plaintext. So the token is
 * replaced before anything is written, and the request body is never touched at
 * all.
 *
 * Client IPs are deliberately left out too. Rate limiting already handles abuse,
 * and a tool built so that secrets stop existing should not keep a durable record
 * of who opened which link and when.
 */

let format = 'text';

/**
 * `text` is readable in a terminal; `json` emits one object per line for a log
 * aggregator. Set once at startup — every log line in the app goes through
 * logEvent(), so the whole stream stays in one format rather than mixing the two,
 * which is what breaks aggregator parsing.
 */
export function configureLogging({ format: requested } = {}) {
  format = requested === 'json' ? 'json' : 'text';
  return format;
}

/**
 * @param {'info'|'warn'|'error'} level
 * @param {string} event      machine-readable name, e.g. "request"
 * @param {object} fields     structured detail; must never contain a token,
 *                            a passphrase, or anything from a request body
 * @param {string} [text]     human-readable rendering for the text format
 */
export function logEvent(level, event, fields = {}, text) {
  const write = level === 'error' ? console.error : level === 'warn' ? console.warn : console.log;

  if (format === 'json') {
    write(JSON.stringify({ ts: new Date().toISOString(), level, event, ...fields }));
    return;
  }

  write(
    text ??
      `[${event}] ${Object.entries(fields)
        .map(([key, value]) => `${key}=${value}`)
        .join(' ')}`
  );
}

// The shape of every token: a UUID, matched in either case.
const TOKEN_ANYWHERE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;

/**
 * Anything under /s/ carries a token, whatever shape it is and in whatever
 * case: Express routes are case-insensitive, so /S/<token> reaches the same
 * handler, and was once logged in full because only "/s/" was checked. A
 * token anywhere else in a path is replaced too, so a link mangled on its way
 * here (a doubled slash, an extra prefix) is still never written down.
 */
function redactPath(pathname) {
  if (/^\/+s(\/|$)/i.test(pathname)) return '/s/:token';
  return pathname.replace(TOKEN_ANYWHERE, ':token');
}

export function requestLogger(req, res, next) {
  const startedAt = process.hrtime.bigint();

  res.on('finish', () => {
    const ms = Number(process.hrtime.bigint() - startedAt) / 1e6;
    // originalUrl, not path: a mounted handler such as express.static('/dist')
    // strips its prefix from req.path, so bundle requests logged as /assets/….
    // The query string is dropped; nothing in this app puts data there.
    const path = redactPath(req.originalUrl.split('?')[0]);
    const status = res.statusCode;

    // 5xx is ours to fix, 4xx is worth noticing, everything else is routine.
    const level = status >= 500 ? 'error' : status >= 400 ? 'warn' : 'info';

    logEvent(
      level,
      'request',
      { method: req.method, path, status, ms: Number(ms.toFixed(1)) },
      `[req] ${req.method} ${path} ${status} ${ms.toFixed(1)}ms`
    );
  });

  next();
}

export { redactPath };
