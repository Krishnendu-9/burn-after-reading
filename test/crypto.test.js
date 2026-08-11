import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

process.env.SECRET_KEY = crypto.randomBytes(32).toString('hex');

const { encrypt, decrypt } = await import('../src/crypto.js');

test('round-trips a message unchanged', () => {
  const message = 'correct horse battery staple';
  assert.equal(decrypt(encrypt(message)), message);
});

test('round-trips multi-line text and non-ASCII characters', () => {
  const message = 'line one\nline two\t🔥 café — ünïcode';
  assert.equal(decrypt(encrypt(message)), message);
});

test('uses a fresh IV, so the same plaintext never produces the same ciphertext', () => {
  const a = encrypt('same input');
  const b = encrypt('same input');

  assert.notEqual(a, b);
  assert.equal(decrypt(a), decrypt(b));
});

test('stores payloads as iv:authTag:ciphertext', () => {
  const parts = encrypt('anything').split(':');

  assert.equal(parts.length, 3);
  assert.equal(Buffer.from(parts[0], 'hex').length, 12); // 96-bit GCM nonce
  assert.equal(Buffer.from(parts[1], 'hex').length, 16); // auth tag
});

test('rejects a tampered ciphertext instead of returning altered plaintext', () => {
  const [iv, tag, ciphertext] = encrypt('transfer $10').split(':');

  // Flip the final byte of the ciphertext.
  const bytes = Buffer.from(ciphertext, 'hex');
  bytes[bytes.length - 1] ^= 0xff;

  assert.throws(() => decrypt(`${iv}:${tag}:${bytes.toString('hex')}`));
});

test('rejects a forged auth tag', () => {
  const [iv, , ciphertext] = encrypt('transfer $10').split(':');
  const forged = crypto.randomBytes(16).toString('hex');

  assert.throws(() => decrypt(`${iv}:${forged}:${ciphertext}`));
});

test('rejects a malformed payload', () => {
  assert.throws(() => decrypt('not-a-payload'), /Malformed payload/);
  assert.throws(() => decrypt('only:two'), /Malformed payload/);
});

test('cannot decrypt with a different key', async () => {
  const payload = encrypt('secret under key A');

  // A fresh module instance picks up the new key, since the old one is cached.
  process.env.SECRET_KEY = crypto.randomBytes(32).toString('hex');
  const other = await import(`../src/crypto.js?key=b`);

  assert.throws(() => other.decrypt(payload), /any configured key/);
});

/* ------------------------------------------------------------ key rotation */

test('a rotated key still reads secrets written under the old one', async () => {
  const oldKey = crypto.randomBytes(32).toString('hex');
  const newKey = crypto.randomBytes(32).toString('hex');
  const message = 'written before the rotation';

  process.env.SECRET_KEY = oldKey;
  delete process.env.SECRET_KEY_PREVIOUS;
  const before = await import('../src/crypto.js?rotate=before');
  const payload = before.encrypt(message);

  // Rotate: new key becomes primary, old one is kept for reading only.
  process.env.SECRET_KEY = newKey;
  process.env.SECRET_KEY_PREVIOUS = oldKey;
  const after = await import('../src/crypto.js?rotate=after');

  assert.equal(after.decrypt(payload), message, 'old secret should still be readable');

  // Anything written now uses the new key, so a process holding only the new key
  // can read it — which is what lets the old key be dropped later.
  const fresh = after.encrypt('written after the rotation');
  process.env.SECRET_KEY = newKey;
  delete process.env.SECRET_KEY_PREVIOUS;
  const newOnly = await import('../src/crypto.js?rotate=newonly');

  assert.equal(newOnly.decrypt(fresh), 'written after the rotation');
  assert.throws(() => newOnly.decrypt(payload), /any configured key/);
});

test('several previous keys can be listed at once', async () => {
  const keyA = crypto.randomBytes(32).toString('hex');
  const keyB = crypto.randomBytes(32).toString('hex');
  const keyC = crypto.randomBytes(32).toString('hex');

  process.env.SECRET_KEY = keyA;
  delete process.env.SECRET_KEY_PREVIOUS;
  const underA = (await import('../src/crypto.js?multi=a')).encrypt('from key A');

  process.env.SECRET_KEY = keyC;
  process.env.SECRET_KEY_PREVIOUS = `${keyB}, ${keyA}`;
  const multi = await import('../src/crypto.js?multi=c');

  assert.equal(multi.decrypt(underA), 'from key A');
});

test('a malformed previous key is rejected loudly, naming which one', async () => {
  process.env.SECRET_KEY = crypto.randomBytes(32).toString('hex');
  process.env.SECRET_KEY_PREVIOUS = 'not-a-valid-key';
  const broken = await import('../src/crypto.js?badprev=1');

  assert.throws(() => broken.encrypt('anything'), /SECRET_KEY_PREVIOUS\[0\]/);

  delete process.env.SECRET_KEY_PREVIOUS;
});
