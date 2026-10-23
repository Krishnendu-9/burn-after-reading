// Smoke test against a running instance, the way CI runs the Docker image:
// health, create a secret, reveal it once, and find it gone the second time.
//
// Usage: node .github/ci/smoke-test.mjs [base url]   (default http://localhost:3000)
// No dependencies, so it runs before or without npm ci.

import crypto from 'node:crypto';

const base = (process.argv[2] ?? 'http://localhost:3000').replace(/\/+$/, '');
const HEALTH_TIMEOUT_MS = 60_000;

const pass = (what) => console.log(`  ok  ${what}`);

function fail(what) {
  console.log(`::error title=Smoke test::${what}`);
  process.exit(1);
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/* ------------------------------------------------------------------ health */

const deadline = Date.now() + HEALTH_TIMEOUT_MS;
let health = null;
while (!health) {
  try {
    const response = await fetch(`${base}/healthz`);
    if (response.ok) health = await response.json();
  } catch {
    // Not listening yet.
  }
  if (!health) {
    if (Date.now() > deadline) fail(`${base}/healthz never answered 200 within ${HEALTH_TIMEOUT_MS / 1000} s`);
    await sleep(1000);
  }
}
if (health.status !== 'ok') fail(`/healthz answered ${JSON.stringify(health)}`);
pass(`/healthz is ok`);

/* ------------------------------------------------------------------ create */

const message = `smoke-test-${crypto.randomUUID()}`;
const created = await fetch(`${base}/api/secrets`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ message, ttlHours: 1 })
});
const body = await created.json().catch(() => ({}));

if (created.status !== 201) fail(`creating a secret answered ${created.status}: ${JSON.stringify(body)}`);
if (!/^[0-9a-f-]{36}$/.test(body.token ?? '')) fail(`no token in ${JSON.stringify(body)}`);
if (body.url !== `${base}/s/${body.token}`) fail(`the link is ${body.url}; is BASE_URL set to ${base}?`);
pass('created a secret (201)');

/* ------------------------------------------------------------------ reveal */

const page = await fetch(`${base}/s/${body.token}`);
const confirmation = await page.text();
if (page.status !== 200 || !/Reveal and destroy/.test(confirmation)) {
  fail(`the confirmation page answered ${page.status} without the reveal button`);
}
if (confirmation.includes(message)) fail('the confirmation page contains the secret');
pass('the confirmation page loads and does not contain the secret');

const reveal = () => fetch(`${base}/s/${body.token}`, { method: 'POST' });

const first = await reveal();
const revealed = await first.text();
if (first.status !== 200 || !revealed.includes(message)) {
  fail(`the first reveal answered ${first.status}${revealed.includes(message) ? '' : ' without the secret'}`);
}
if (!/default-src 'self'/.test(first.headers.get('content-security-policy') ?? '')) {
  fail('the secret page has no Content-Security-Policy');
}
pass('the first reveal returns the secret, with the security headers');

const second = await reveal();
const after = await second.text();
if (second.status !== 404 || after.includes(message)) {
  fail(`the second reveal answered ${second.status}; the secret should be gone`);
}
pass('the second reveal finds it destroyed (404)');

console.log(`Smoke test passed against ${base}`);
