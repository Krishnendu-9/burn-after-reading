import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';

import {
  createSecret,
  burnSecret,
  pingDatabase,
  countAll,
  purgeExpired,
  UnreadableSecretError
} from './db.js';
import { encrypt, decrypt, encryptWithPassphrase, openPassphraseLayer } from './crypto.js';
import { assets } from './assets.js';
import { createLimiter, revealLimiter, globalLimiter } from './limits.js';
import { securityHeaders } from './security.js';
import { requestLogger, logEvent, redactPath } from './logging.js';
import { envNumber } from './env.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');

export const MAX_SECRET_LENGTH = 10_000;
export const TTL_CHOICES = [1, 24, 168]; // hours: 1 hour, 1 day, 1 week
const DEFAULT_TTL_HOURS = 24;

export const MIN_PASSPHRASE_LENGTH = 4;
export const MAX_PASSPHRASE_LENGTH = 200;

/**
 * Bounds for a message the browser encrypted itself, sent as
 * base64url(iv ‖ ciphertext ‖ tag) — see src/client/e2e.js. The server cannot
 * measure the plaintext, so the ceiling is derived from MAX_SECRET_LENGTH
 * instead: one UTF-16 code unit is at most 3 bytes of UTF-8, plus the 12-byte
 * IV and 16-byte tag, then base64's 4/3 growth.
 */
const E2E_OVERHEAD_BYTES = 12 + 16;
export const MAX_CIPHERTEXT_LENGTH = Math.ceil(
  ((MAX_SECRET_LENGTH * 3 + E2E_OVERHEAD_BYTES) * 4) / 3
);
const MIN_CIPHERTEXT_LENGTH = Math.ceil(((E2E_OVERHEAD_BYTES + 1) * 4) / 3);
const BASE64URL = /^[A-Za-z0-9_-]+$/;

/**
 * Every token comes from crypto.randomUUID(): a lowercase UUID. Anything that
 * isn't one cannot name a secret, so it is turned away without a database
 * lookup. That gives nothing away, since no real link looks any different.
 */
const TOKEN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * Hard ceiling on stored rows. Rate limits cap a single address; they do nothing
 * about traffic spread across many. Without a ceiling the disk is the limit, and
 * SQLite failing on a full disk takes the whole app down rather than one request.
 */
const MAX_STORED_SECRETS = envNumber('MAX_SECRETS', 10_000);

/**
 * Cheap CSRF guard for the burn. Browsers set Sec-Fetch-Site on every request;
 * anything but same-origin is another site submitting a form on its visitors'
 * behalf. Non-browser clients omit the header entirely and are left alone.
 *
 * The reveal answers with its own page, not the "destroyed" one: the secret
 * was not touched, and that page would also have told main.js to discard the
 * link's key.
 */
function sameOriginOnly(req, res, next) {
  const fetchSite = req.get('sec-fetch-site');
  if (!fetchSite || fetchSite === 'same-origin') return next();

  const token = req.params.token?.toLowerCase();
  res.status(403).render('refused', {
    heading: 'That request was turned away',
    message:
      'A secret can only be revealed from this site’s own page, so a request ' +
      'from anywhere else is refused. Nothing was changed: the secret is still ' +
      'there. Open the link again and reveal it from the page it shows.',
    back: token && TOKEN.test(token) ? { href: `/s/${token}`, label: 'Back to the secret' } : null
  });
}

/**
 * Builds the Express app. Kept separate from server.js so tests can mount it on
 * an ephemeral port without starting the background purge or claiming PORT.
 *
 * @param {object} options
 * @param {string} options.baseUrl   Origin used to build shareable links.
 * @param {string|null} [options.repoUrl]
 * @param {string|null} [options.authorName] Credited in the footer when set.
 * @param {boolean|number|string} [options.trustProxy]
 *   How many proxy hops to trust for `req.ip` and `req.secure`. Defaults to
 *   `false`, meaning trust nothing. This must stay off unless a proxy really is
 *   in front: with it on, a direct client can put any address it likes in
 *   `X-Forwarded-For` and every rate limit keys off that forged value.
 * @param {boolean} [options.logRequests] One line per request, tokens redacted.
 */
export function createApp({
  baseUrl,
  repoUrl = null,
  authorName = null,
  trustProxy = false,
  logRequests = true
}) {
  // Fail fast on a missing or malformed SECRET_KEY rather than at the first POST.
  encrypt('startup check', 'startup-check');
  // Same idea for the compiled front end: without it every page render throws a
  // confusing 500, so surface the real problem while the operator is still
  // looking at the terminal.
  assets();

  const app = express();

  app.set('view engine', 'ejs');
  app.set('views', path.join(ROOT, 'views'));
  app.set('trust proxy', trustProxy);
  app.disable('x-powered-by');

  if (logRequests) app.use(requestLogger);

  app.use(securityHeaders);

  app.use(express.json({ limit: '256kb' }));
  app.use(express.urlencoded({ extended: false, limit: '256kb' }));
  app.use(
    '/dist',
    express.static(path.join(ROOT, 'public', 'dist'), {
      // securityHeaders has already set Cache-Control: no-store, and
      // serve-static only adds its own header when none is set, so a `maxAge`
      // option was silently ignored and every page load fetched the fonts, CSS
      // and JS again. Filenames carry a content hash, so a year is safe.
      setHeaders(res) {
        res.set('Cache-Control', 'public, max-age=31536000, immutable');
      }
    })
  );

  app.locals.assets = assets;
  // Both optional. The GitHub links and the footer credit are hidden entirely
  // when unset, so the app never ships a dead placeholder.
  app.locals.repoUrl = repoUrl;
  app.locals.authorName = authorName;
  // Shared with the templates so the form's minlength/maxlength can't drift from
  // what the API enforces.
  app.locals.passphraseLength = { min: MIN_PASSPHRASE_LENGTH, max: MAX_PASSPHRASE_LENGTH };

  // Liveness probe for the host platform. Mounted above the rate limiter on
  // purpose: platforms poll this every few seconds, which would otherwise eat the
  // global budget and eventually get the app marked unhealthy by its own limiter.
  app.get('/healthz', (req, res) => {
    try {
      pingDatabase();
      res.json({ status: 'ok', uptime: Math.round(process.uptime()) });
    } catch {
      res.status(503).json({ status: 'error' });
    }
  });

  // Static assets and the health probe are served above this line, so the budget
  // is spent on real page and API traffic rather than on CSS and JS requests.
  app.use(globalLimiter);

  /* ---------------------------------------------------------------- routes */

  // Home: the compose form.
  app.get('/', (req, res) => {
    res.render('index', {
      maxLength: MAX_SECRET_LENGTH,
      ttlChoices: TTL_CHOICES,
      defaultTtlHours: DEFAULT_TTL_HOURS
    });
  });

  // Create a secret. Returns the one-time URL as JSON.
  //
  // Two shapes are accepted. The web form sends `ciphertext`: the browser has
  // already encrypted the message under a key that lives only in the link's
  // #fragment, so the server stores something it cannot read. `message` is
  // plaintext, for API clients and for browsers without WebCrypto (a non-HTTPS
  // origin); the server encrypts that one itself, and so could read it.
  app.post('/api/secrets', createLimiter, async (req, res) => {
    const body = req.body ?? {};
    const ciphertext = typeof body.ciphertext === 'string' ? body.ciphertext : null;
    const message = typeof body.message === 'string' ? body.message : '';
    const passphrase = typeof body.passphrase === 'string' ? body.passphrase.trim() : '';
    const ttlHours = TTL_CHOICES.includes(Number(body.ttlHours))
      ? Number(body.ttlHours)
      : DEFAULT_TTL_HOURS;
    const tooLong = `Message is too long (max ${MAX_SECRET_LENGTH.toLocaleString()} characters).`;

    if (ciphertext !== null) {
      if (ciphertext.length > MAX_CIPHERTEXT_LENGTH) {
        return res.status(413).json({ error: tooLong });
      }
      if (ciphertext.length < MIN_CIPHERTEXT_LENGTH || !BASE64URL.test(ciphertext)) {
        return res.status(400).json({ error: 'The encrypted message is malformed.' });
      }
    } else {
      if (!message.trim()) {
        return res.status(400).json({ error: 'A message is required.' });
      }
      if (message.length > MAX_SECRET_LENGTH) {
        return res.status(413).json({ error: tooLong });
      }
    }
    if (passphrase && passphrase.length < MIN_PASSPHRASE_LENGTH) {
      return res.status(400).json({
        error: `A passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters.`
      });
    }
    if (passphrase.length > MAX_PASSPHRASE_LENGTH) {
      return res.status(400).json({ error: 'That passphrase is too long.' });
    }

    // Reclaim dead rows before refusing — the ceiling is about live storage, and
    // a sweep is cheap next to turning a legitimate request away.
    if (countAll() >= MAX_STORED_SECRETS) {
      purgeExpired();

      if (countAll() >= MAX_STORED_SECRETS) {
        return res.status(503).json({
          error: 'Storage is full right now. Please try again shortly.'
        });
      }
    }

    const clientEncrypted = ciphertext !== null;
    const content = clientEncrypted ? ciphertext : message;

    const token = crypto.randomUUID();
    // Bound to the token, so the payload only decrypts in this row.
    const payload = passphrase
      ? await encryptWithPassphrase(content, passphrase, token)
      : encrypt(content, token);

    createSecret({
      token,
      payload,
      ttlHours,
      requiresPassphrase: Boolean(passphrase),
      clientEncrypted
    });

    // The URL carries no key. For an end-to-end secret the browser appends
    // "#<key>" itself; the server never sees it.
    res.status(201).json({
      token,
      url: `${baseUrl}/s/${token}`,
      expiresInHours: ttlHours,
      protected: Boolean(passphrase),
      endToEnd: clientEncrypted
    });
  });

  // Step 1 of the reveal.
  //
  // Burning on GET meant link previews destroyed secrets before the recipient
  // clicked — Slack, Teams, WhatsApp, iMessage and most mail scanners fetch URLs
  // to build them, and chat is exactly where these links get sent.
  //
  // This handler deliberately never touches the database. Looking the token up
  // would make a live link answer differently from a dead one, and anyone holding
  // a link could then poll it to learn whether it had been read — silently, and
  // without burning it. Every GET returns the same page, so watching one tells an
  // observer nothing. Whether the secret still exists is only revealed by the
  // POST that destroys it.
  app.get('/s/:token', revealLimiter, (req, res) => {
    const token = req.params.token.toLowerCase();
    if (!TOKEN.test(token)) {
      return res.status(404).render('destroyed');
    }

    // One address per secret. Routes match /S/<token> and a trailing slash
    // too, and the confirmation page files the #key under its own path for
    // the page that ends the reveal to find. Arriving at a variant, the reveal
    // posted to /s/<token> and looked under a different name, so the key was
    // lost and the secret burned unread. Browsers carry the #fragment across
    // a redirect.
    if (req.path !== `/s/${token}`) {
      return res.redirect(301, `/s/${token}`);
    }

    res.render('reveal', { token, error: null });
  });

  // Step 2: the burn. Preview bots never issue POSTs, so reaching here means a
  // human chose to destroy the secret.
  app.post('/s/:token', sameOriginOnly, revealLimiter, async (req, res) => {
    const token = req.params.token.toLowerCase();
    if (!TOKEN.test(token)) {
      return res.status(404).render('destroyed', { reason: null });
    }

    const passphrase =
      typeof req.body?.passphrase === 'string' ? req.body.passphrase.trim() : '';

    // Throwing means "do not destroy this" — a wrong passphrase costs an
    // attempt, not the secret.
    const result = await burnSecret(token, (row) => {
      // The server layer first, on its own. Failing here is never the reader's
      // doing — the key changed without rotation, or the row is damaged or holds
      // a payload copied from another row — so it is reported as unreadable
      // instead of being counted as a wrong guess.
      // Counting it used to tell the reader to enter a passphrase that a secret
      // without one could never accept, then destroy it after five tries.
      let inner;
      try {
        inner = decrypt(row.payload, token);
      } catch (error) {
        throw new UnreadableSecretError(error);
      }

      if (!row.requires_passphrase) return inner;
      if (!passphrase) throw new Error('passphrase required');
      return openPassphraseLayer(inner, passphrase);
    });

    if (result.status === 'missing') {
      return res.status(404).render('destroyed', { reason: null });
    }

    if (result.status === 'unreadable') {
      // An operator problem, so it is logged loudly — but without the token.
      logEvent(
        'error',
        'secret_unreadable',
        {
          hint:
            'SECRET_KEY changed? Put the old key in SECRET_KEY_PREVIOUS. ' +
            'Otherwise the row was altered.'
        },
        '[error] a secret could not be decrypted with any configured key — ' +
          'SECRET_KEY changed? Put the old key in SECRET_KEY_PREVIOUS. ' +
          'Otherwise the row was altered.'
      );
      return res.status(500).render('destroyed', {
        heading: 'This secret can’t be opened',
        reason:
          'The server can no longer decrypt it, most likely because its encryption ' +
          'key was changed. It hasn’t been used up — if the key is restored, the ' +
          'same link will work. Otherwise, ask the sender for a new link.'
      });
    }

    if (result.status === 'exhausted') {
      return res.status(404).render('destroyed', {
        reason: 'Too many incorrect passphrases were entered, so this secret was destroyed.'
      });
    }

    if (result.status === 'locked') {
      const left = result.attemptsLeft;
      return res.status(401).render('reveal', {
        token,
        error: passphrase
          ? `That passphrase was not correct. ${left} attempt${left === 1 ? '' : 's'} left before this secret is destroyed.`
          : 'This secret is passphrase-protected. Enter the passphrase the sender gave you.'
      });
    }

    // For an end-to-end secret `message` is still ciphertext here. The page hands
    // it to the browser, which decrypts it with the key from the #fragment.
    res.render('secret', {
      message: result.message,
      createdAt: result.createdAt,
      clientEncrypted: result.clientEncrypted
    });
  });

  /* ----------------------------------------------------- errors & fallback */

  app.use((req, res) => {
    res.status(404).render('destroyed');
  });

  // Error pages use `refused`, not `destroyed`: a request that failed here may
  // well have left its secret in place, and the "destroyed" page would both say
  // otherwise and tell main.js to discard the link's key.
  app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);

    const status = Number(err.status ?? err.statusCode) || 500;
    const wantsJson = req.path.startsWith('/api/');
    // The path of a reveal carries its token, which is as good as the secret.
    const logPath = redactPath(req.path);

    if (status < 500) {
      // Malformed or oversized bodies land here. body-parser attaches the raw
      // request body to the error, and V8's JSON parse messages quote the input
      // too — which on this route is the plaintext secret. So nothing from the
      // error is logged beyond its type: the whole point of the app is that the
      // secret never gets written anywhere durable, and stdout is durable.
      logEvent(
        'warn',
        'client_error',
        { method: req.method, path: logPath, status, type: err.type ?? null },
        `[client-error] ${req.method} ${logPath} — ${err.type ?? status}`
      );

      if (wantsJson) {
        return res.status(status).json({ error: 'Could not read the request.' });
      }
      return res.status(status).render('refused', {
        heading: 'That request couldn’t be read',
        message:
          'Nothing was changed, so if you were revealing a secret, it is still there. ' +
          'Go back and try again.',
        back: null
      });
    }

    // Genuine server faults. Message and stack are safe to log — they come from
    // our own code and from SQLite, never from the request body. Still logged
    // field by field rather than as an object, so no attached property can ride
    // along unnoticed.
    logEvent(
      'error',
      'server_error',
      { method: req.method, path: logPath, message: err.message, stack: err.stack ?? null },
      `[error] ${req.method} ${logPath} — ${err.message}\n${err.stack ?? ''}`
    );

    if (wantsJson) {
      return res.status(500).json({ error: 'Something went wrong.' });
    }
    res.status(500).render('refused', {
      heading: 'Something went wrong',
      message:
        'The server ran into an error. If you were revealing a secret, it may still ' +
        'be there: go back and try again in a moment.',
      back: null
    });
  });

  return app;
}
