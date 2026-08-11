import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { v4 as uuidv4 } from 'uuid';

import { createSecret, burnSecret, pingDatabase, countAll, purgeExpired } from './db.js';
import {
  encrypt,
  decrypt,
  encryptWithPassphrase,
  decryptWithPassphrase
} from './crypto.js';
import { assets } from './assets.js';
import { createLimiter, revealLimiter, globalLimiter } from './limits.js';
import { securityHeaders } from './security.js';
import { requestLogger, logEvent } from './logging.js';
import { envNumber } from './env.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');

export const MAX_SECRET_LENGTH = 10_000;
export const TTL_CHOICES = [1, 24, 168]; // hours: 1 hour, 1 day, 1 week
const DEFAULT_TTL_HOURS = 24;

export const MIN_PASSPHRASE_LENGTH = 4;
export const MAX_PASSPHRASE_LENGTH = 200;

/**
 * Hard ceiling on stored rows. Rate limits cap a single address; they do nothing
 * about traffic spread across many. Without a ceiling the disk is the limit, and
 * SQLite failing on a full disk takes the whole app down rather than one request.
 */
const MAX_STORED_SECRETS = envNumber('MAX_SECRETS', 10_000);

/**
 * Builds the Express app. Kept separate from server.js so tests can mount it on
 * an ephemeral port without starting the background purge or claiming PORT.
 *
 * @param {object} options
 * @param {string} options.baseUrl   Origin used to build shareable links.
 * @param {string|null} [options.repoUrl]
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
  trustProxy = false,
  logRequests = true
}) {
  // Fail fast on a missing or malformed SECRET_KEY rather than at the first POST.
  encrypt('startup check');
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
    express.static(path.join(ROOT, 'public', 'dist'), { immutable: true, maxAge: '1y' })
  );

  app.locals.assets = assets;
  // Optional. The "Source" link is hidden entirely when this is unset, so the app
  // never ships a dead placeholder URL.
  app.locals.repoUrl = repoUrl;

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
    res.render('index', { maxLength: MAX_SECRET_LENGTH, ttlChoices: TTL_CHOICES });
  });

  // Create a secret. Returns the one-time URL as JSON.
  app.post('/api/secrets', createLimiter, (req, res) => {
    const message = typeof req.body?.message === 'string' ? req.body.message : '';
    const passphrase = typeof req.body?.passphrase === 'string' ? req.body.passphrase.trim() : '';
    const ttlHours = TTL_CHOICES.includes(Number(req.body?.ttlHours))
      ? Number(req.body.ttlHours)
      : DEFAULT_TTL_HOURS;

    if (!message.trim()) {
      return res.status(400).json({ error: 'A message is required.' });
    }
    if (message.length > MAX_SECRET_LENGTH) {
      return res.status(413).json({
        error: `Message is too long (max ${MAX_SECRET_LENGTH.toLocaleString()} characters).`
      });
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

    const token = uuidv4();
    const payload = passphrase ? encryptWithPassphrase(message, passphrase) : encrypt(message);

    createSecret({ token, payload, ttlHours, requiresPassphrase: Boolean(passphrase) });

    res.status(201).json({
      token,
      url: `${baseUrl}/s/${token}`,
      expiresInHours: ttlHours,
      protected: Boolean(passphrase)
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
    res.render('reveal', { token: req.params.token, error: null });
  });

  // Step 2: the burn. Preview bots never issue POSTs, so reaching here means a
  // human chose to destroy the secret.
  app.post('/s/:token', revealLimiter, (req, res) => {
    // Cheap CSRF guard. Browsers set Sec-Fetch-Site on every request; anything
    // cross-origin is a forged submission rather than our own form. Non-browser
    // clients omit the header entirely and are left alone.
    const fetchSite = req.get('sec-fetch-site');
    if (fetchSite && fetchSite !== 'same-origin') {
      return res.status(403).render('destroyed');
    }

    const passphrase =
      typeof req.body?.passphrase === 'string' ? req.body.passphrase.trim() : '';

    // Runs inside the burn transaction. Throwing means "do not destroy this" —
    // a wrong passphrase costs an attempt, not the secret.
    const result = burnSecret(req.params.token, (row) => {
      if (!row.requires_passphrase) return decrypt(row.payload);
      if (!passphrase) throw new Error('passphrase required');
      return decryptWithPassphrase(row.payload, passphrase);
    });

    if (result.status === 'missing') {
      return res.status(404).render('destroyed', { reason: null });
    }

    if (result.status === 'exhausted') {
      return res.status(404).render('destroyed', {
        reason: 'Too many incorrect passphrases were entered, so this secret was destroyed.'
      });
    }

    if (result.status === 'locked') {
      const left = result.attemptsLeft;
      return res.status(401).render('reveal', {
        token: req.params.token,
        error: passphrase
          ? `That passphrase was not correct. ${left} attempt${left === 1 ? '' : 's'} left before this secret is destroyed.`
          : 'This secret is passphrase-protected. Enter the passphrase the sender gave you.'
      });
    }

    res.render('secret', { message: result.message, createdAt: result.createdAt });
  });

  /* ----------------------------------------------------- errors & fallback */

  app.use((req, res) => {
    res.status(404).render('destroyed');
  });

  app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);

    const status = Number(err.status ?? err.statusCode) || 500;
    const wantsJson = req.path.startsWith('/api/');

    if (status < 500) {
      // Malformed or oversized bodies land here. body-parser attaches the raw
      // request body to the error, and V8's JSON parse messages quote the input
      // too — which on this route is the plaintext secret. So nothing from the
      // error is logged beyond its type: the whole point of the app is that the
      // secret never gets written anywhere durable, and stdout is durable.
      logEvent(
        'warn',
        'client_error',
        { method: req.method, path: req.path, status, type: err.type ?? null },
        `[client-error] ${req.method} ${req.path} — ${err.type ?? status}`
      );

      if (wantsJson) {
        return res.status(status).json({ error: 'Could not read the request.' });
      }
      return res.status(status).render('destroyed');
    }

    // Genuine server faults. Message and stack are safe to log — they come from
    // our own code and from SQLite, never from the request body. Still logged
    // field by field rather than as an object, so no attached property can ride
    // along unnoticed.
    logEvent(
      'error',
      'server_error',
      { method: req.method, path: req.path, message: err.message, stack: err.stack ?? null },
      `[error] ${req.method} ${req.path} — ${err.message}\n${err.stack ?? ''}`
    );

    if (wantsJson) {
      return res.status(500).json({ error: 'Something went wrong.' });
    }
    res.status(500).render('destroyed');
  });

  return app;
}
