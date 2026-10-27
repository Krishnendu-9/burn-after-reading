/**
 * Environment readers that treat "unset" and "set but empty" as the same thing.
 *
 * This exists because of a real bug. `.env.example` ships every optional value
 * blank, so a copied `.env` contains lines like `MAX_SECRETS=`. The .env loader
 * (dotenv then, Node's own now) reads that as an empty string, and
 * `process.env.MAX_SECRETS ?? 10000` returns `''` — `??` only catches null and
 * undefined. `Number('')` is 0, so the storage ceiling
 * became zero and the app refused to store anything at all.
 *
 * Anything read from the environment should go through here.
 */

import fs from 'node:fs';

/** @returns {string|null} the trimmed value, or `fallback` when blank/unset. */
export function envString(name, fallback = null) {
  const raw = process.env[name];
  if (raw === undefined || raw === null) return fallback;

  const trimmed = raw.trim();
  return trimmed === '' ? fallback : trimmed;
}

/**
 * A secret, from `NAME` itself or from the file that `NAME_FILE` points at.
 *
 * The file form is how Docker and Kubernetes hand over secrets: the value never
 * enters the container's environment, so it stays out of `docker inspect`, the
 * process listing and anything else that dumps the environment. Setting both
 * is refused rather than silently preferring one.
 *
 * @returns {string|null} the trimmed value, or null when neither is set.
 */
export function envSecret(name) {
  const direct = envString(name);
  const file = envString(`${name}_FILE`);

  if (direct !== null && file !== null) {
    throw new Error(`Both ${name} and ${name}_FILE are set. Set only one of them.`);
  }
  if (file === null) return direct;

  let contents;
  try {
    contents = fs.readFileSync(file, 'utf8');
  } catch (error) {
    // The path only, never the contents.
    throw new Error(
      `${name}_FILE points at ${file}, which could not be read (${error.code ?? error.message}).`,
      { cause: error }
    );
  }

  const trimmed = contents.trim();
  return trimmed === '' ? null : trimmed;
}

/**
 * A positive number, or the fallback. Zero, negatives, and anything unparseable
 * fall back rather than silently disabling whatever they configure.
 */
export function envNumber(name, fallback) {
  const raw = envString(name);
  if (raw === null) return fallback;

  const value = Number(raw);
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

/** Anything but false/0/no/off counts as on. */
export function envFlag(name, fallback) {
  const raw = envString(name);
  if (raw === null) return fallback;

  return !/^(false|0|no|off)$/i.test(raw);
}

/**
 * How many reverse-proxy hops to trust. Accepts a count, a boolean, or a named
 * value Express understands such as `loopback`.
 */
export function envTrustProxy(name) {
  const raw = envString(name);
  if (raw === null || raw === 'false') return false;
  if (raw === 'true') return true;
  if (/^\d+$/.test(raw)) return Number(raw);
  return raw;
}
