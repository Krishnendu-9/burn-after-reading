/**
 * End-to-end encryption, done in the browser before anything is sent.
 *
 * The message is sealed with a fresh AES-256-GCM key that exists only in the
 * link's #fragment. Browsers never include the fragment in a request, so the
 * server stores — and later hands back — ciphertext it has no way to open. It
 * still wraps that in its own server-key layer as usual, so a stolen database
 * is sealed twice.
 *
 * Wire format: base64url(iv ‖ ciphertext ‖ tag). WebCrypto appends the GCM tag
 * to the ciphertext itself.
 *
 * No DOM access in here, so the test suite runs this exact file under Node.
 */

const ALGORITHM = 'AES-GCM';
const IV_LENGTH = 12; // 96-bit nonce, the recommended size for GCM

/** WebCrypto only exists in a secure context: HTTPS, or localhost. */
export const isSupported = () => Boolean(globalThis.crypto?.subtle);

function toBase64Url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function fromBase64Url(text) {
  const base64 = text.replaceAll('-', '+').replaceAll('_', '/');
  const binary = atob(base64 + '='.repeat((4 - (base64.length % 4)) % 4));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

/**
 * @param {string} plaintext
 * @returns {Promise<{ ciphertext: string, key: string }>} both base64url; the
 *   ciphertext goes to the server, the key goes after the # in the link.
 */
export async function encryptMessage(plaintext) {
  const key = await crypto.subtle.generateKey({ name: ALGORITHM, length: 256 }, true, [
    'encrypt'
  ]);
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

  const sealed = new Uint8Array(
    await crypto.subtle.encrypt({ name: ALGORITHM, iv }, key, new TextEncoder().encode(plaintext))
  );

  const payload = new Uint8Array(iv.length + sealed.length);
  payload.set(iv);
  payload.set(sealed, iv.length);

  const rawKey = new Uint8Array(await crypto.subtle.exportKey('raw', key));

  return { ciphertext: toBase64Url(payload), key: toBase64Url(rawKey) };
}

const VERIFIER_LABEL = new TextEncoder().encode('burn-after-reading passphrase v1:');
const VERIFIER_ITERATIONS = 100_000;

/**
 * What the browser sends in place of the passphrase, for an end-to-end secret.
 *
 * People reuse passphrases, so the real one should not reach the server even
 * though the server never writes it down. This derives a stand-in from it,
 * salted with the link's key. The server treats the stand-in exactly as it
 * would the passphrase (its scrypt layer and the five-attempt limit work
 * unchanged), but cannot turn it back into the passphrase, and cannot even try
 * guesses against it without the key, which only the link carries.
 *
 * Both ends derive it the same way: the page that creates the secret, and the
 * confirmation page before it submits. The passphrase is trimmed and
 * NFKC-normalised first, as the server does, so the same words typed on a
 * different keyboard give the same result.
 *
 * @param {string} passphrase as typed; must not be blank
 * @param {string} keyText the link's key, base64url
 * @returns {Promise<string>} base64url, 43 characters
 */
export async function passphraseVerifier(passphrase, keyText) {
  const material = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase.trim().normalize('NFKC')),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const key = fromBase64Url(keyText);
  const salt = new Uint8Array(VERIFIER_LABEL.length + key.length);
  salt.set(VERIFIER_LABEL);
  salt.set(key, VERIFIER_LABEL.length);

  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: VERIFIER_ITERATIONS },
    material,
    256
  );

  return toBase64Url(new Uint8Array(bits));
}

/**
 * Reverses encryptMessage(). Rejects on a wrong or truncated key, or on
 * tampered ciphertext — GCM makes that a definite failure, never garbage.
 */
export async function decryptMessage(ciphertext, keyText) {
  const bytes = fromBase64Url(ciphertext);
  const key = await crypto.subtle.importKey('raw', fromBase64Url(keyText), ALGORITHM, false, [
    'decrypt'
  ]);

  const plaintext = await crypto.subtle.decrypt(
    { name: ALGORITHM, iv: bytes.subarray(0, IV_LENGTH) },
    key,
    bytes.subarray(IV_LENGTH)
  );

  return new TextDecoder().decode(plaintext);
}
