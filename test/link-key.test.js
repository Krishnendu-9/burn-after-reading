import test, { before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';

import { takeKey, releaseKey } from '../src/client/link-key.js';
import { bootTestApp, createSecret, createEncryptedSecret, reveal } from './helpers.js';

/*
 * A browser tab, reduced to what link-key.js touches: session history entries
 * (a URL and a state object each), sessionStorage, and the page scripts that
 * main.js runs on the confirmation page and on the pages that end a reveal.
 *
 * It follows the HTML spec's rules for these: a new document pushes an entry
 * and drops any forward ones, replaceState rewrites the current entry, a
 * fragment-only navigation pushes an entry without loading a new document, and
 * a restored session brings back every entry with its state and the tab's
 * sessionStorage. Back and Forward reload the page, as they do for no-store
 * pages; a back/forward cache restore runs the same applyKey via pageshow.
 */
const ORIGIN = 'https://example.test';
const LINK = '/s/3f0c6a1e-8b7d-4c2a-9e5f-1a2b3c4d5e6f';
const KEY = 'Qm9vc3RlZC1rZXktZ29lcy1oZXJlLWFuZC1pcy00My1j';

class Storage {
  constructor(entries = []) {
    this.map = new Map(entries);
  }
  getItem(name) {
    return this.map.has(name) ? this.map.get(name) : null;
  }
  setItem(name, value) {
    this.map.set(name, String(value));
  }
  removeItem(name) {
    this.map.delete(name);
  }
}

/** Storage that throws on every call, as it does where the browser blocks it. */
const blockedStorage = {
  getItem() {
    throw new Error('SecurityError');
  },
  setItem() {
    throw new Error('SecurityError');
  },
  removeItem() {
    throw new Error('SecurityError');
  }
};

class Tab {
  constructor({ storage = new Storage(), entries = [], index = -1 } = {}) {
    this.storage = storage;
    this.entries = entries;
    this.index = index;
    this.page = null;
  }

  get entry() {
    return this.entries[this.index];
  }

  get location() {
    const url = new URL(this.entry.url, ORIGIN);
    return { hash: url.hash, pathname: url.pathname, search: url.search };
  }

  get history() {
    const tab = this;
    return {
      get state() {
        return structuredClone(tab.entry.state);
      },
      replaceState(state, _unused, url) {
        tab.entry.state = structuredClone(state);
        const resolved = new URL(url, new URL(tab.entry.url, ORIGIN));
        tab.entry.url = `${resolved.pathname}${resolved.search}${resolved.hash}`;
      }
    };
  }

  /** A navigation that loads a new document. `kind` is what the server sends. */
  navigate(url, kind) {
    this.entries = this.entries.slice(0, this.index + 1);
    this.entries.push({ url, state: null, kind });
    this.index += 1;
    this.load();
  }

  /** Runs the page script for the current entry, as main.js does on load. */
  load() {
    const { kind } = this.entry;
    this.page = { kind };

    if (kind === 'confirm') this.applyKey();
    if (kind === 'ended') {
      this.page.key = releaseKey(this.location, this.history, this.storage);
    }
  }

  /** main.js's applyKey, on the confirmation page. */
  applyKey() {
    const { key, inUrl } = takeKey(this.location, this.history, this.storage);
    this.page.key = key;
    this.page.action = inUrl ? `${LINK}#${key}` : LINK;
  }

  /** Submits the reveal form; `outcome` is the page the server answers with. */
  submit(outcome) {
    assert.equal(this.page.kind, 'confirm', 'only the confirmation page has the form');
    this.navigate(this.page.action, outcome);
  }

  back() {
    this.index -= 1;
    this.load();
  }

  forward() {
    this.index += 1;
    this.load();
  }

  reload() {
    this.load();
  }

  /** Pasting the link into a tab already on this page: no reload, a new entry. */
  navigateFragment(url) {
    assert.equal(new URL(url, ORIGIN).pathname, this.location.pathname);
    this.entries = this.entries.slice(0, this.index + 1);
    this.entries.push({ url, state: null, kind: this.entry.kind });
    this.index += 1;
    if (this.page.kind === 'confirm') this.applyKey(); // hashchange
  }

  /** A back/forward cache restore of the confirmation page fires pageshow. */
  restoreFromCache() {
    if (this.page.kind === 'confirm') this.applyKey();
  }

  /** The process dies; the restored tab gets its entries, states and storage back. */
  crashAndRestore() {
    const saved = JSON.parse(
      JSON.stringify({ entries: this.entries, index: this.index, storage: [...this.storage.map] })
    );
    const restored = new Tab({
      storage: new Storage(saved.storage),
      entries: saved.entries,
      index: saved.index
    });
    restored.load();
    return restored;
  }

  /** Every history entry that still has the key in its URL or its state. */
  entriesHolding(key) {
    return this.entries.filter(
      (entry) => entry.url.includes(key) || JSON.stringify(entry.state ?? null).includes(key)
    );
  }
}

const storedKeys = (tab) => [...tab.storage.map.values()];

/** Opens the link from somewhere else, the way a reader arrives from chat. */
function openLink() {
  const tab = new Tab();
  tab.navigate('/elsewhere', 'other');
  tab.navigate(`${LINK}#${KEY}`, 'confirm');
  return tab;
}

test('opening a link takes the key out of the URL before anything else happens', () => {
  const tab = openLink();

  assert.equal(tab.page.key, KEY, 'the page still has the key');
  assert.equal(tab.entry.url, LINK);
  assert.deepEqual(tab.entriesHolding(KEY), []);
  assert.equal(tab.page.action, LINK, 'the reveal form does not carry the key in its URL');
});

test('reloading, or a crash restore, before the reveal keeps the key usable', () => {
  let tab = openLink();

  tab.reload();
  assert.equal(tab.page.key, KEY, 'after a reload');

  tab = tab.crashAndRestore();
  assert.equal(tab.page.key, KEY, 'after a crash restore');
  assert.deepEqual(tab.entriesHolding(KEY), []);

  tab.submit('ended');
  assert.equal(tab.page.key, KEY, 'the secret page gets the key after a restore');
});

test('after the reveal, Back, Back twice and Forward find no key anywhere', () => {
  const tab = openLink();
  tab.submit('ended');

  assert.equal(tab.page.key, KEY, 'the secret page gets the key');
  assert.deepEqual(storedKeys(tab), [], 'and storage gives it up');

  tab.back();
  assert.equal(tab.page.kind, 'confirm');
  assert.equal(tab.page.key, null, 'Back: the confirmation page has nothing left');

  tab.back();
  assert.equal(tab.page.kind, 'other', 'Back twice: the page before the link');

  tab.forward();
  assert.equal(tab.page.key, null);
  tab.forward();

  assert.deepEqual(tab.entriesHolding(KEY), []);
  assert.deepEqual(storedKeys(tab), []);
});

test('a crash restore after the reveal brings back no key', () => {
  let tab = openLink();
  tab.submit('ended');
  tab.back();

  tab = tab.crashAndRestore();

  assert.equal(tab.page.key, null);
  assert.deepEqual(tab.entriesHolding(KEY), []);
  assert.deepEqual(storedKeys(tab), []);
});

test('the back/forward cache cannot bring a used key back', () => {
  const tab = openLink();
  tab.submit('ended');

  // Back to a cached copy of the confirmation page: no reload, just pageshow.
  tab.index -= 1;
  tab.page = { kind: 'confirm', key: KEY, action: LINK };
  tab.restoreFromCache();

  assert.equal(tab.page.key, null);
});

test('a wrong passphrase, then Back, still leaves the key for the next try', () => {
  // The 401 answer is the confirmation page again, as its own history entry.
  // Clearing the key on submit would strand a reader who goes Back from it.
  const tab = openLink();

  tab.submit('confirm');
  assert.equal(tab.page.key, KEY, 'the 401 page has the key');

  tab.back();
  assert.equal(tab.page.key, KEY, 'and so does the entry before it');

  tab.submit('ended');
  assert.equal(tab.page.key, KEY);
  assert.deepEqual(tab.entriesHolding(KEY), []);
  assert.deepEqual(storedKeys(tab), []);
});

test('reopening the link in the same tab takes the key out of the new entry too', () => {
  const tab = openLink();

  // Same path, so the browser only changes the fragment and pushes an entry.
  tab.navigateFragment(`${LINK}#${KEY}`);

  assert.equal(tab.entries.length, 3);
  assert.equal(tab.page.key, KEY);
  assert.deepEqual(tab.entriesHolding(KEY), []);
});

test('reopening the link after the reveal leaves nothing behind either', () => {
  const tab = openLink();
  tab.submit('ended');

  // Opened again from the chat message; the server now answers "destroyed".
  tab.navigate(`${LINK}#${KEY}`, 'confirm');
  tab.submit('ended');

  assert.deepEqual(tab.entriesHolding(KEY), []);
  assert.deepEqual(storedKeys(tab), []);
});

test('the rate-limit page leaves the key in storage for the next attempt', () => {
  const tab = openLink();

  tab.submit('other'); // 429: not a page that ends the reveal
  assert.deepEqual(storedKeys(tab), [KEY]);

  tab.back();
  assert.equal(tab.page.key, KEY);
});

test('without storage, the key stays in the URL so the reveal still works', () => {
  const tab = new Tab({ storage: blockedStorage });
  tab.navigate(`${LINK}#${KEY}`, 'confirm');

  assert.equal(tab.page.key, KEY);
  assert.equal(tab.entry.url, `${LINK}#${KEY}`, 'left alone: losing the key would be worse');
  assert.equal(tab.page.action, `${LINK}#${KEY}`, 'so the form carries it');

  tab.submit('ended');
  assert.equal(tab.page.key, KEY);
  assert.equal(tab.entry.url, LINK, 'the secret page still strips its own URL');
});

test('a link reached at another spelling still hands its key to the secret page', () => {
  // The server redirects these to /s/<token>, but the two ends must agree even
  // without that: the form always posts to the canonical path, and a key filed
  // under /S/… or /s/…/ was never found, so the secret burned unread.
  for (const variant of [LINK.toUpperCase(), `${LINK}/`]) {
    const tab = new Tab();
    tab.navigate(`${variant}#${KEY}`, 'confirm');
    assert.equal(tab.page.key, KEY, variant);

    tab.submit('ended');
    assert.equal(tab.page.key, KEY, `${variant}: the secret page finds the key`);
    assert.deepEqual(storedKeys(tab), [], `${variant}: and nothing is left behind`);
  }
});

/* ------------------------------------------------------------ page wiring */

/*
 * The model above decides what each kind of page does with the key. Which kind
 * a real page is comes from one attribute: main.js releases the key only on a
 * page whose <body> carries data-reveal-ended. These tests check the server
 * renders it on exactly the pages that end a reveal. A missing one leaves the
 * key in storage after the burn; a stray one throws it away before the reveal.
 */
let app;

before(async () => {
  app = await bootTestApp();
});

// Every request comes from 127.0.0.1, so each test starts with a fresh budget.
beforeEach(() => {
  app.db.db.prepare('DELETE FROM rate_limits').run();
});

after(async () => {
  await app.close();
});

const NEVER_EXISTED = '99999999-9999-4999-8999-999999999999';

/** Whether the page's <body> tag carries data-reveal-ended. */
async function endsReveal(response) {
  const html = await response.text();
  const body = html.match(/<body\b[^>]*>/)?.[0];
  assert.ok(body, 'the page has a <body> tag');
  return /\sdata-reveal-ended[\s=>]/.test(body);
}

test('the secret page is marked as ending the reveal', async () => {
  const { body } = await createSecret(app, 'wiring: plain');
  const response = await reveal(app, body.token);

  assert.equal(response.status, 200);
  assert.equal(await endsReveal(response), true);
});

test('the end-to-end secret page is marked as ending the reveal', async () => {
  const { body } = await createEncryptedSecret(app, 'wiring: e2e');
  const response = await reveal(app, body.token);

  assert.equal(response.status, 200);
  assert.equal(await endsReveal(response), true);
});

test('the destroyed page is marked as ending the reveal', async () => {
  const response = await reveal(app, NEVER_EXISTED);

  assert.equal(response.status, 404);
  assert.equal(await endsReveal(response), true);
});

test('the confirmation page is not marked, so the key waits for the reveal', async () => {
  const response = await fetch(app.url(`/s/${NEVER_EXISTED}`));

  assert.equal(response.status, 200);
  assert.equal(await endsReveal(response), false);
});

test('the confirmation page after a wrong passphrase is not marked either', async () => {
  // Releasing here would strand a reader who goes Back to try again.
  const { body } = await createSecret(app, 'wiring: 401', { passphrase: 'the-real-one' });
  const response = await reveal(app, body.token, 'not-it');

  assert.equal(response.status, 401);
  assert.equal(await endsReveal(response), false);
});

test('a refused cross-site reveal is not marked: the secret was not touched', async () => {
  const { body } = await createSecret(app, 'wiring: refused');
  const response = await fetch(app.url(`/s/${body.token}`), {
    method: 'POST',
    headers: { 'Sec-Fetch-Site': 'cross-site' }
  });

  assert.equal(response.status, 403);
  assert.equal(await endsReveal(response), false);
});

test('the error page for an unreadable request is not marked either', async () => {
  const { body } = await createSecret(app, 'wiring: bad body');
  const response = await fetch(app.url(`/s/${body.token}`), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Sec-Fetch-Site': 'same-origin' },
    body: '{not json'
  });

  assert.equal(response.status, 400);
  assert.equal(await endsReveal(response), false);
});

test('the rate-limit page is not marked, so the key survives being turned away', async () => {
  let response;
  for (let i = 0; i < 100; i += 1) {
    response = await fetch(app.url(`/s/${NEVER_EXISTED}`));
    if (response.status === 429) break;
    await response.body?.cancel();
  }

  assert.equal(response.status, 429, 'the reveal limiter should have answered');
  assert.equal(await endsReveal(response), false);
});
