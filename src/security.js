import crypto from 'node:crypto';

/**
 * Content-Security-Policy for this app.
 *
 * Everything the pages need is served from our own origin — fonts are bundled by
 * Vite rather than fetched from Google — so the only exceptions are `data:`
 * images (the emoji favicon and the CSS dropdown chevron) and a per-request
 * nonce for the one inline script that applies the saved theme before paint.
 */
function contentSecurityPolicy(nonce) {
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}'`,
    "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    // Nothing here is ever framed, submits off-site, or loads plugins.
    "frame-ancestors 'none'",
    "form-action 'self'",
    "object-src 'none'",
    "base-uri 'none'"
  ].join('; ');
}

/**
 * Sets the response headers every page depends on. Mounted before the static
 * handler so bundled assets are covered too; `express.static` then replaces
 * Cache-Control with its own long-lived value for hashed filenames.
 */
export function securityHeaders(req, res, next) {
  const nonce = crypto.randomBytes(16).toString('base64');
  res.locals.nonce = nonce;

  // Secrets must never be retained by a browser, proxy, or CDN.
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.set('Content-Security-Policy', contentSecurityPolicy(nonce));
  // Keeps the token out of the Referer header on any outbound navigation.
  res.set('Referrer-Policy', 'no-referrer');
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'DENY');
  res.set('Cross-Origin-Opener-Policy', 'same-origin');
  res.set('Cross-Origin-Resource-Policy', 'same-origin');
  res.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), interest-cohort=()');

  // Only meaningful over TLS, and setting it in local development would pin
  // localhost to HTTPS in the developer's browser.
  if (req.secure) {
    res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }

  next();
}
