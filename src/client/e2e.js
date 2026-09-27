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
