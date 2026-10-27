/**
 * Keeps an end-to-end link's key out of the browser's session history.
 *
 * The key arrives in the #fragment, so the confirmation page's history entry
 * starts out holding it in its URL, where Back, the tab's history and a
 * restored session can all show it long after the secret is gone. Instead:
 *
 * - The confirmation page moves the key out of its URL as it loads, into
 *   sessionStorage under the link's path. The reveal form no longer carries the
 *   key, so it never appears in another URL either.
 * - Every page that ends a reveal (the secret, or the "destroyed" page) reads
 *   the key from there, removes it, and strips any fragment from its own URL.
 *
 * Why storage, rather than memory or the history entry's state: until the reveal
 * the key must survive a reload and a crash restore, or the reveal that follows
 * destroys the secret with no way to decrypt it. sessionStorage survives both and
 * belongs to the tab, not to an entry, so removing it on the result page also
 * covers a reader who went Back after a wrong passphrase. history.state would
 * need clearing on submit, before the outcome is known.
 *
 * If storage is unavailable, the URL keeps the key as before. Losing the key
 * would be worse than leaving it there.
 *
 * What this cannot reach: the browser records the original URL, key included,
 * in its global history when the page first loads, before any script runs. The
 * README's known limitations cover that.
 *
 * No DOM access in here, so the test suite runs this exact file under Node.
 */

// Lowercased and without a trailing slash, matching the /s/<token> the reveal
// form posts to. The server redirects other spellings of a link to that one,
// but if a page is ever reached at a variant (/S/…, /s/…/), the two ends must
// still agree, or the secret page finds no key and the secret burns unread.
const storageKey = (location) =>
  `e2e-key:${location.pathname.toLowerCase().replace(/\/+$/, '')}`;

const fragmentOf = (location) => (location.hash.length > 1 ? location.hash.slice(1) : null);

const withoutFragment = (location) => `${location.pathname}${location.search}`;

function read(storage, location) {
  try {
    return storage.getItem(storageKey(location));
  } catch {
    return null;
  }
}

/**
 * For the confirmation page: on load, on hashchange (a link pasted into a tab
 * already showing this page), and on a back/forward cache restore.
 *
 * @param {{ hash: string, pathname: string, search: string }} location
 * @param {{ state: any, replaceState: (state: any, unused: string, url: string) => void }} history
 * @param {Storage | null} storage sessionStorage, or null where it is unavailable
 * @returns {{ key: string | null, inUrl: boolean }} `inUrl` means storage failed
 *   and the key is still in the address bar, so the form must carry it itself.
 */
export function takeKey(location, history, storage) {
  const fromUrl = fragmentOf(location);
  if (!fromUrl) return { key: read(storage, location), inUrl: false };

  try {
    storage.setItem(storageKey(location), fromUrl);
  } catch {
    return { key: fromUrl, inUrl: true };
  }

  history.replaceState(history.state, '', withoutFragment(location));
  return { key: fromUrl, inUrl: false };
}

/**
 * For any page that ends a reveal. Returns the key, if there was one, and
 * leaves none behind in storage or in this page's URL.
 */
export function releaseKey(location, history, storage) {
  const key = fragmentOf(location) ?? read(storage, location);

  try {
    storage.removeItem(storageKey(location));
  } catch {
    // Nothing was stored, or storage is unavailable.
  }

  if (location.hash) history.replaceState(history.state, '', withoutFragment(location));
  return key;
}
