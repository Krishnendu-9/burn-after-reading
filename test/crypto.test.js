import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

const KEY = crypto.randomBytes(32).toString('hex');
process.env.SECRET_KEY = KEY;

const { encrypt, decrypt } = await import('../src/crypto.js');

// Payloads are bound to the token of the row they are stored in.
const TOKEN = '3f0c6a1e-8b7d-4c2a-9e5f-1a2b3c4d5e6f';
const OTHER_TOKEN = '9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d';

test('round-trips a message unchanged', () => {
  const message = 'correct horse battery staple';
  assert.equal(decrypt(encrypt(message, TOKEN), TOKEN), message);
});

test('round-trips multi-line text and non-ASCII characters', () => {
  const message = 'line one\nline two\t🔥 café — ünïcode';
  assert.equal(decrypt(encrypt(message, TOKEN), TOKEN), message);
});

test('uses a fresh IV, so the same plaintext never produces the same ciphertext', () => {
  const a = encrypt('same input', TOKEN);
  const b = encrypt('same input', TOKEN);

  assert.notEqual(a, b);
  assert.equal(decrypt(a, TOKEN), decrypt(b, TOKEN));
});

test('stores payloads as iv:authTag:ciphertext', () => {
  const parts = encrypt('anything', TOKEN).split(':');

  assert.equal(parts.length, 3);
  assert.equal(Buffer.from(parts[0], 'hex').length, 12); // 96-bit GCM nonce
  assert.equal(Buffer.from(parts[1], 'hex').length, 16); // auth tag
});

test('rejects a tampered ciphertext instead of returning altered plaintext', () => {
  const [iv, tag, ciphertext] = encrypt('transfer $10', TOKEN).split(':');

  // Flip the final byte of the ciphertext.
  const bytes = Buffer.from(ciphertext, 'hex');
  bytes[bytes.length - 1] ^= 0xff;

  assert.throws(() => decrypt(`${iv}:${tag}:${bytes.toString('hex')}`, TOKEN));
});

test('rejects a forged auth tag', () => {
  const [iv, , ciphertext] = encrypt('transfer $10', TOKEN).split(':');
  const forged = crypto.randomBytes(16).toString('hex');

  assert.throws(() => decrypt(`${iv}:${forged}:${ciphertext}`, TOKEN));
});

test('rejects a malformed payload', () => {
  assert.throws(() => decrypt('not-a-payload', TOKEN), /Malformed payload/);
  assert.throws(() => decrypt('only:two', TOKEN), /Malformed payload/);
});

/* ------------------------------------------------------- token binding */

test('a payload only decrypts under the token it was written for', () => {
  const payload = encrypt('bound to one row', TOKEN);

  assert.equal(decrypt(payload, TOKEN), 'bound to one row');
  assert.throws(() => decrypt(payload, OTHER_TOKEN), /any configured key/);
});

test('encrypting or decrypting without a token is refused', () => {
  const payload = encrypt('anything', TOKEN);

  assert.throws(() => encrypt('unbound'), /bound to a token/);
  assert.throws(() => encrypt('unbound', ''), /bound to a token/);
  assert.throws(() => decrypt(payload), /bound to a token/);
});

test('payloads from before token binding are rejected, deliberately', () => {
  // The old format: the same iv:authTag:ciphertext encoding, no associated
  // data. There is no fallback for it; see associatedData() in src/crypto.js.
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(KEY, 'hex'), iv);
  const ciphertext = Buffer.concat([cipher.update('written before binding', 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  const legacy = [iv, tag, ciphertext].map((b) => b.toString('hex')).join(':');

  // Proves the fixture is a real old-format payload under the current key, so
  // the rejection below comes from the missing binding and nothing else.
  const old = crypto.createDecipheriv('aes-256-gcm', Buffer.from(KEY, 'hex'), iv);
  old.setAuthTag(tag);
  assert.equal(
    Buffer.concat([old.update(ciphertext), old.final()]).toString('utf8'),
    'written before binding'
  );

  assert.throws(() => decrypt(legacy, TOKEN), /any configured key/);
});

test('cannot decrypt with a different key', async () => {
  const payload = encrypt('secret under key A', TOKEN);

  // A fresh module instance picks up the new key, since the old one is cached.
  process.env.SECRET_KEY = crypto.randomBytes(32).toString('hex');
  const other = await import(`../src/crypto.js?key=b`);

  assert.throws(() => other.decrypt(payload, TOKEN), /any configured key/);
});

/* ------------------------------------------------------------ key rotation */

test('a rotated key still reads secrets written under the old one', async () => {
  const oldKey = crypto.randomBytes(32).toString('hex');
  const newKey = crypto.randomBytes(32).toString('hex');
  const message = 'written before the rotation';

  process.env.SECRET_KEY = oldKey;
  delete process.env.SECRET_KEY_PREVIOUS;
  const before = await import('../src/crypto.js?rotate=before');
  const payload = before.encrypt(message, TOKEN);

  // Rotate: new key becomes primary, old one is kept for reading only.
  process.env.SECRET_KEY = newKey;
  process.env.SECRET_KEY_PREVIOUS = oldKey;
  const after = await import('../src/crypto.js?rotate=after');

  assert.equal(after.decrypt(payload, TOKEN), message, 'old secret should still be readable');

  // Anything written now uses the new key, so a process holding only the new key
  // can read it — which is what lets the old key be dropped later.
  const fresh = after.encrypt('written after the rotation', TOKEN);
  process.env.SECRET_KEY = newKey;
  delete process.env.SECRET_KEY_PREVIOUS;
  const newOnly = await import('../src/crypto.js?rotate=newonly');

  assert.equal(newOnly.decrypt(fresh, TOKEN), 'written after the rotation');
  assert.throws(() => newOnly.decrypt(payload, TOKEN), /any configured key/);
});

test('several previous keys can be listed at once', async () => {
  const keyA = crypto.randomBytes(32).toString('hex');
  const keyB = crypto.randomBytes(32).toString('hex');
  const keyC = crypto.randomBytes(32).toString('hex');

  process.env.SECRET_KEY = keyA;
  delete process.env.SECRET_KEY_PREVIOUS;
  const underA = (await import('../src/crypto.js?multi=a')).encrypt('from key A', TOKEN);

  process.env.SECRET_KEY = keyC;
  process.env.SECRET_KEY_PREVIOUS = `${keyB}, ${keyA}`;
  const multi = await import('../src/crypto.js?multi=c');

  assert.equal(multi.decrypt(underA, TOKEN), 'from key A');
});

test('a malformed previous key is rejected loudly, naming which one', async () => {
  process.env.SECRET_KEY = crypto.randomBytes(32).toString('hex');
  process.env.SECRET_KEY_PREVIOUS = 'not-a-valid-key';
  const broken = await import('../src/crypto.js?badprev=1');

  assert.throws(() => broken.encrypt('anything', TOKEN), /SECRET_KEY_PREVIOUS\[0\]/);

  delete process.env.SECRET_KEY_PREVIOUS;
});

test('a key with a stray character is rejected, not quietly truncated', async () => {
  // Buffer.from(…, 'hex') stops at the first non-hex character and drops a
  // trailing odd one, so both of these used to pass as 32-byte keys.
  const good = crypto.randomBytes(32).toString('hex');
  const cases = [`${good}0`, `${good.slice(0, 63)}z`];

  for (const [index, bad] of cases.entries()) {
    process.env.SECRET_KEY = bad;
    const broken = await import(`../src/crypto.js?stray=${index}`);

    assert.throws(() => broken.encrypt('anything', TOKEN), (error) => {
      assert.match(error.message, /64 hex characters/);
      assert.ok(!error.message.includes(bad.slice(0, 16)), 'the key is never echoed');
      return true;
    });
  }

  process.env.SECRET_KEY = KEY;
});
