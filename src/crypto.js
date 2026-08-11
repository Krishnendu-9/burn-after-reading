import crypto from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96-bit nonce, the recommended size for GCM
const AUTH_TAG_LENGTH = 16;

let cachedKeys = null;

function parseKey(raw, label) {
  const key = Buffer.from(String(raw).trim(), 'hex');

  if (key.length !== 32) {
    throw new Error(
      `${label} must be 32 bytes encoded as 64 hex characters (got ${key.length} bytes).`
    );
  }

  return key;
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
 * Encrypts plaintext with AES-256-GCM.
 * @returns {string} "iv:authTag:ciphertext", all hex encoded.
 */
export function encrypt(plaintext) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, getKey(), iv, {
    authTagLength: AUTH_TAG_LENGTH
  });

  const ciphertext = Buffer.concat([
    cipher.update(String(plaintext), 'utf8'),
    cipher.final()
  ]);

  return [iv, cipher.getAuthTag(), ciphertext].map((b) => b.toString('hex')).join(':');
}

/**
 * Reverses encrypt() using an explicit key.
 * @param {Buffer} key
 */
function decryptWith(key, iv, authTag, ciphertext) {
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH
  });
  decipher.setAuthTag(authTag);

  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

/**
 * Reverses encrypt(). Throws if the payload was tampered with, or if none of the
 * configured keys can read it.
 *
 * Each key is tried in turn. That is safe to do blindly because GCM authenticates
 * the ciphertext: a wrong key fails the tag check and throws, it never returns
 * plausible-looking rubbish. Normally the first key succeeds; the loop only does
 * real work during a rotation, for secrets written under the old key.
 */
export function decrypt(payload) {
  const parts = String(payload).split(':');
  if (parts.length !== 3) {
    throw new Error('Malformed payload');
  }

  const [iv, authTag, ciphertext] = parts.map((part) => Buffer.from(part, 'hex'));

  for (const key of getKeys()) {
    try {
      return decryptWith(key, iv, authTag, ciphertext);
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

function deriveKey(passphrase, salt) {
  return crypto.scryptSync(String(passphrase).normalize('NFKC'), salt, 32, SCRYPT_PARAMS);
}

/**
 * Adds a second encryption layer that only the reader's passphrase can remove.
 *
 * The message is sealed with a key derived from the passphrase, and *that* is
 * then sealed with the server key as usual. The practical difference is that the
 * operator can no longer read it: holding SECRET_KEY unwraps the outer layer and
 * yields nothing but the inner ciphertext.
 *
 * @returns {string} A normal payload whose plaintext is "salt:iv:authTag:ciphertext".
 */
export function encryptWithPassphrase(plaintext, passphrase) {
  const salt = crypto.randomBytes(SALT_LENGTH);
  const key = deriveKey(passphrase, salt);

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

  return encrypt(inner);
}

/**
 * Reverses encryptWithPassphrase(). Throws on the wrong passphrase — the GCM tag
 * makes that a definite answer rather than a guess, and the caller relies on the
 * throw to decide *not* to destroy the secret.
 */
export function decryptWithPassphrase(payload, passphrase) {
  const inner = decrypt(payload).split(':');
  if (inner.length !== 4) {
    throw new Error('Malformed passphrase payload');
  }

  const [salt, iv, authTag, ciphertext] = inner.map((part) => Buffer.from(part, 'hex'));

  return decryptWith(deriveKey(passphrase, salt), iv, authTag, ciphertext);
}
