import crypto from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(crypto.scrypt);

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96-bit nonce, the recommended size for GCM
const AUTH_TAG_LENGTH = 16;

let cachedKeys = null;

// Checked as text first: Buffer.from(…, 'hex') stops quietly at the first
// non-hex character and drops a trailing odd one, so a 65-character value, or
// one with a stray character at the end, used to pass as 32 bytes.
const HEX_KEY = /^[0-9a-f]{64}$/i;

function parseKey(raw, label) {
  const text = String(raw).trim();

  if (!HEX_KEY.test(text)) {
    // The length only; the value itself is never echoed.
    const detail = text.length === 64 ? 'some of them not hex' : `got ${text.length}`;
    throw new Error(`${label} must be 32 bytes encoded as 64 hex characters (${detail}).`);
  }

  return Buffer.from(text, 'hex');
}

/**
 * Every key this process can decrypt with, newest first.
 *
 * `SECRET_KEY` is the only one used to encrypt. `SECRET_KEY_PREVIOUS` — a
 * comma-separated list — is accepted for decryption only, which is what makes
 * rotation possible: set the new key as SECRET_KEY, move the old one to
 * SECRET_KEY_PREVIOUS, and secrets written before the change stay readable
 * instead of being orphaned. Once everything older than the longest TTL has
 * expired, drop the previous key.
 *
 * Fails loudly at first use rather than silently encrypting with a bad key.
 */
function getKeys() {
  if (cachedKeys) return cachedKeys;

  const primary = process.env.SECRET_KEY;
  if (!primary) {
    throw new Error('SECRET_KEY is not set. Run `npm run keygen` and add it to .env');
  }

  const keys = [parseKey(primary, 'SECRET_KEY')];

  const previous = (process.env.SECRET_KEY_PREVIOUS ?? '')
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean);

  previous.forEach((raw, index) => {
    keys.push(parseKey(raw, `SECRET_KEY_PREVIOUS[${index}]`));
  });

  cachedKeys = keys;
  return cachedKeys;
}

/** The key new secrets are encrypted with. */
function getKey() {
  return getKeys()[0];
}

/**
 * The token a payload belongs to, as GCM additional authenticated data.
 *
 * Without it, a payload is valid in any row. Someone who can write to the
 * database but does not hold SECRET_KEY could copy a secret's payload into a
 * row whose link they hold, reveal that link, and get the plaintext, while the
 * original row stays untouched and its recipient never learns. With the token
 * bound in, a moved payload fails the tag check like any other tampering.
 *
 * Payloads written before this binding have no associated data, so they fail
 * that check too. That break is deliberate and has no fallback: a decrypt that
 * also accepted unbound payloads would leave every one of them movable, and at
 * the time of the change no live secret was stored in the old form.
 *
 * Required rather than optional, so no caller can skip the binding by accident.
 */
function associatedData(token) {
  if (typeof token !== 'string' || token === '') {
    throw new Error('A payload must be bound to a token');
  }
  return Buffer.from(token, 'utf8');
}

/**
 * Encrypts plaintext with AES-256-GCM, bound to the token it is stored under.
 * @returns {string} "iv:authTag:ciphertext", all hex encoded.
 */
export function encrypt(plaintext, token) {
  const aad = associatedData(token);
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, getKey(), iv, {
    authTagLength: AUTH_TAG_LENGTH
  });
  cipher.setAAD(aad);

  const ciphertext = Buffer.concat([
    cipher.update(String(plaintext), 'utf8'),
    cipher.final()
  ]);

  return [iv, cipher.getAuthTag(), ciphertext].map((b) => b.toString('hex')).join(':');
}

/**
 * Reverses encrypt() using an explicit key.
 * @param {Buffer} key
 * @param {Buffer} [aad] Associated data the payload was sealed with, if any.
 */
function decryptWith(key, iv, authTag, ciphertext, aad) {
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH
  });
  if (aad) decipher.setAAD(aad);
  decipher.setAuthTag(authTag);

  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

/**
 * Reverses encrypt(). Throws if the payload was tampered with, was written for a
 * different token, or if none of the configured keys can read it.
 *
 * Each key is tried in turn. That is safe to do blindly because GCM authenticates
 * the ciphertext: a wrong key fails the tag check and throws, it never returns
 * plausible-looking rubbish. Normally the first key succeeds; the loop only does
 * real work during a rotation, for secrets written under the old key.
 */
export function decrypt(payload, token) {
  // Before the loop, so a missing token is reported as itself rather than
  // swallowed below as "no key could read it".
  const aad = associatedData(token);
  const parts = String(payload).split(':');
  if (parts.length !== 3) {
    throw new Error('Malformed payload');
  }

  const [iv, authTag, ciphertext] = parts.map((part) => Buffer.from(part, 'hex'));

  for (const key of getKeys()) {
    try {
      return decryptWith(key, iv, authTag, ciphertext, aad);
    } catch {
      // Wrong key for this payload — try the next one.
    }
  }

  throw new Error('Could not decrypt payload with any configured key');
}

/* ------------------------------------------------ optional passphrase layer */

const SALT_LENGTH = 16;
// Deliberately slow. Roughly 100ms per attempt on ordinary hardware, which is
// nothing for one honest reader and ruinous for anyone working through a word
// list. N=16384, r=8 needs ~16MB, comfortably inside Node's default maxmem.
const SCRYPT_PARAMS = { N: 16_384, r: 8, p: 1 };

/**
 * Async on purpose. scryptSync would hold the event loop for the full ~100ms,
 * so a burst of wrong-passphrase guesses spread across many addresses — each
 * one inside its own rate limit — would stall every other request on the
 * server. The async form runs on libuv's thread pool instead.
 */
function deriveKey(passphrase, salt) {
  return scrypt(String(passphrase).normalize('NFKC'), salt, 32, SCRYPT_PARAMS);
}

/**
 * Adds a second encryption layer that only the reader's passphrase can remove.
 *
 * The message is sealed with a key derived from the passphrase, and *that* is
 * then sealed with the server key as usual. The practical difference is that the
 * operator can no longer read it: holding SECRET_KEY unwraps the outer layer and
 * yields nothing but the inner ciphertext.
 *
 * Only the outer layer carries the token. The inner one cannot be moved without
 * the outer, and is useless to anyone without the passphrase anyway.
 *
 * @returns {Promise<string>} A normal payload whose plaintext is "salt:iv:authTag:ciphertext".
 */
export async function encryptWithPassphrase(plaintext, passphrase, token) {
  const salt = crypto.randomBytes(SALT_LENGTH);
  const key = await deriveKey(passphrase, salt);

  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH
  });

  const ciphertext = Buffer.concat([
    cipher.update(String(plaintext), 'utf8'),
    cipher.final()
  ]);

  const inner = [salt, iv, cipher.getAuthTag(), ciphertext]
    .map((b) => b.toString('hex'))
    .join(':');

  return encrypt(inner, token);
}

/**
 * Removes the passphrase layer from what decrypt() returned for a
 * passphrase-protected payload. Rejects on the wrong passphrase — the GCM tag
 * makes that a definite answer rather than a guess, and the caller relies on the
 * rejection to decide *not* to destroy the secret.
 *
 * Kept separate from the server layer so a caller can tell the two failures
 * apart: a wrong passphrase is the reader's mistake, a server-layer failure
 * never is.
 */
export async function openPassphraseLayer(inner, passphrase) {
  const parts = String(inner).split(':');
  if (parts.length !== 4) {
    throw new Error('Malformed passphrase payload');
  }

  const [salt, iv, authTag, ciphertext] = parts.map((part) => Buffer.from(part, 'hex'));

  return decryptWith(await deriveKey(passphrase, salt), iv, authTag, ciphertext);
}

/** Reverses encryptWithPassphrase(): the server layer, then the passphrase layer. */
export async function decryptWithPassphrase(payload, passphrase, token) {
  return openPassphraseLayer(decrypt(payload, token), passphrase);
}
