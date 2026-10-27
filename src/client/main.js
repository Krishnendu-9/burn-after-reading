// Fonts are bundled rather than pulled from Google. A secret-sharing tool should
// not tell a third party that someone just opened a link, and self-hosting lets
// the Content-Security-Policy stay locked to 'self'.
import '@fontsource/inter/latin-400.css';
import '@fontsource/inter/latin-500.css';
import '@fontsource/inter/latin-600.css';
import '@fontsource/inter/latin-700.css';
import '@fontsource/jetbrains-mono/latin-400.css';
import '@fontsource/jetbrains-mono/latin-500.css';

import './style.css';

import * as e2e from './e2e.js';
import * as linkKey from './link-key.js';

/* ---------------------------------------------------------------- theming */

const root = document.documentElement;

// Dark Reader honours the `darkreader-lock` meta tag and leaves us alone. Builds
// predating that tag repaint the page anyway, so watch for their injected
// stylesheet and flag it — style.css uses the flag to swap effects that survive
// a repaint badly (gradient-clipped text in particular) for plain colours.
const detectExtensionTint = () => {
  const tinted =
    root.hasAttribute('data-darkreader-scheme') ||
    root.hasAttribute('data-darkreader-mode') ||
    document.querySelector('style.darkreader') !== null;

  root.toggleAttribute('data-extension-tinted', tinted);
  return tinted;
};

if (!detectExtensionTint()) {
  // The extension injects shortly after parse, so keep looking briefly.
  const observer = new MutationObserver(detectExtensionTint);
  observer.observe(root, { attributes: true, childList: true, subtree: true });
  setTimeout(() => observer.disconnect(), 5000);
}
const syncThemeIcons = () => {
  const dark = root.classList.contains('dark');
  document.querySelector('[data-icon-sun]')?.classList.toggle('hidden', !dark);
  document.querySelector('[data-icon-moon]')?.classList.toggle('hidden', dark);
};

syncThemeIcons();

document.querySelector('[data-theme-toggle]')?.addEventListener('click', () => {
  const dark = root.classList.toggle('dark');
  try {
    localStorage.setItem('theme', dark ? 'dark' : 'light');
  } catch {
    // Private browsing with storage disabled — the toggle still works for this page.
  }
  syncThemeIcons();
});

/* ------------------------------------------------------- floating nav pill */

// Deepen the pill's shadow once it is floating over scrolled content.
const nav = document.querySelector('[data-nav]');

if (nav) {
  const syncNavShadow = () => {
    nav.toggleAttribute('data-scrolled', window.scrollY > 8);
  };

  syncNavShadow();
  window.addEventListener('scroll', syncNavShadow, { passive: true });
}

/* -------------------------------------------------- passphrase show/hide */

/**
 * Wires an eye button to the passphrase input in the same
 * [data-passphrase-field] wrapper, so a typo can be caught before it costs a
 * send or a reveal attempt. Used by the compose form and the reveal page.
 *
 * @returns {(visible: boolean) => void} sets the state directly, e.g. to hide
 *   the passphrase again once the form has been submitted.
 */
function bindPassphraseToggle(button) {
  const input = button.closest('[data-passphrase-field]').querySelector('input');

  const setVisible = (visible) => {
    input.type = visible ? 'text' : 'password';
    button.setAttribute('aria-pressed', String(visible));
    button.setAttribute('aria-label', visible ? 'Hide passphrase' : 'Show passphrase');
    button.querySelector('[data-eye]').classList.toggle('hidden', visible);
    button.querySelector('[data-eye-off]').classList.toggle('hidden', !visible);
  };

  button.addEventListener('click', () => setVisible(input.type === 'password'));
  return setVisible;
}

/* ----------------------------------------------------------- compose form */

const form = document.querySelector('[data-secret-form]');

if (form) {
  const textarea = form.querySelector('[data-message]');
  const submit = form.querySelector('[data-submit]');
  const submitLabel = form.querySelector('[data-submit-label]');
  const counter = document.querySelector('[data-counter]');
  const progress = document.querySelector('[data-progress]');
  const errorBox = document.querySelector('[data-error]');
  // Swapped with the `hidden` attribute, not the class: both panels carry
  // xl:flex for the two-column layout, which would override a `hidden` class.
  const composePanel = document.querySelector('[data-compose]');
  const resultPanel = document.querySelector('[data-result]');
  const linkInput = document.querySelector('[data-link]');
  const expiryLabel = document.querySelector('[data-expiry]');
  const maxLength = Number(textarea.getAttribute('maxlength')) || 10000;
  const passphraseInput = form.querySelector('[name="passphrase"]');
  const minPassphrase = Number(passphraseInput.getAttribute('minlength')) || 4;

  // Without WebCrypto (a page served over plain HTTP from anywhere but
  // localhost) this browser cannot encrypt, so the message would travel to the
  // server as plaintext. That is said before anything is sent, and sending it
  // anyway takes a deliberate tick, rather than a note on the result screen
  // once it is too late.
  const encryptsLocally = e2e.isSupported();
  const insecureAck = form.querySelector('[data-insecure-ack]');
  if (!encryptsLocally) form.querySelector('[data-insecure]')?.classList.remove('hidden');

  const showError = (message) => {
    errorBox.querySelector('[data-error-text]').textContent = message ?? '';
    errorBox.classList.toggle('hidden', !message);
  };

  // Grow with the content instead of opening as a tall empty box. The CSS
  // max-height caps it, after which it scrolls.
  const autoGrow = () => {
    textarea.style.height = 'auto';
    textarea.style.height = `${textarea.scrollHeight}px`;
  };

  const sync = () => {
    const used = textarea.value.length;
    counter.textContent = `${used.toLocaleString()} / ${maxLength.toLocaleString()}`;
    counter.toggleAttribute('data-near-limit', used >= maxLength * 0.9);
    progress.style.width = `${Math.min((used / maxLength) * 100, 100)}%`;
    submit.disabled =
      textarea.value.trim().length === 0 || (!encryptsLocally && !insecureAck?.checked);
    autoGrow();
  };

  textarea.addEventListener('input', sync);
  insecureAck?.addEventListener('change', sync);
  sync();

  // The shortcut hint defaults to Ctrl; Apple keyboards use ⌘ instead.
  const isApple = /Mac|iPhone|iPad/.test(
    navigator.userAgentData?.platform ?? navigator.platform ?? ''
  );
  const shortcut = form.querySelector('[data-shortcut]');
  if (shortcut && isApple) shortcut.textContent = '⌘ ↵';

  const setPassphraseVisible = bindPassphraseToggle(
    form.querySelector('[data-toggle-passphrase]')
  );

  // Ctrl/Cmd + Enter submits.
  textarea.addEventListener('keydown', (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key === 'Enter') {
      event.preventDefault();
      form.requestSubmit();
    }
  });

  const fitLink = () => {
    if (resultPanel.hidden) return;
    linkInput.style.height = 'auto';
    const borders = linkInput.offsetHeight - linkInput.clientHeight;
    linkInput.style.height = `${linkInput.scrollHeight + borders}px`;
  };
  // The link rewraps when the window changes width.
  window.addEventListener('resize', fitLink, { passive: true });

  const humanise = (hours) => {
    if (hours < 24) return `${hours} hour${hours === 1 ? '' : 's'}`;
    const days = hours / 24;
    return `${days} day${days === 1 ? '' : 's'}`;
  };

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    showError('');
    submit.disabled = true;
    submitLabel.textContent = 'Encrypting…';

    try {
      const fields = new FormData(form);
      const passphrase = String(fields.get('passphrase') ?? '');
      const request = { ttlHours: Number(fields.get('ttlHours')) };

      // The server checks this as well, but for an end-to-end secret it only
      // ever sees the stand-in below, which is always long enough.
      if (passphrase.trim() && passphrase.trim().length < minPassphrase) {
        throw new Error(`A passphrase must be at least ${minPassphrase} characters.`);
      }

      // Encrypt here whenever the browser can, so only ciphertext leaves the
      // page and the key never reaches the server at all. Without WebCrypto
      // (a plain-HTTP origin) the server encrypts it instead; the form warned
      // about that before sending, and the result screen says so again.
      let key = null;
      if (encryptsLocally) {
        const sealed = await e2e.encryptMessage(textarea.value);
        request.ciphertext = sealed.ciphertext;
        key = sealed.key;
        // A stand-in derived with the link's key; the passphrase stays here.
        if (passphrase.trim()) request.passphrase = await e2e.passphraseVerifier(passphrase, key);
      } else {
        request.message = textarea.value;
        request.passphrase = passphrase;
      }

      const response = await fetch('/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request)
      });

      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'Could not create the link.');

      // The fragment is the key. It is added here, after the request, because
      // the server must never see it.
      linkInput.value = key ? `${data.url}#${key}` : data.url;
      expiryLabel.textContent = humanise(data.expiresInHours);

      // Only mention the passphrase when one was actually set.
      document
        .querySelector('[data-passphrase-note]')
        ?.classList.toggle('hidden', !data.protected);
      document.querySelector('[data-e2e-note]')?.classList.toggle('hidden', Boolean(key));

      composePanel.hidden = true;
      resultPanel.hidden = false;

      // Sized once visible (a hidden element measures as zero) so the whole
      // link shows, key included. scrollHeight leaves out the borders, which
      // border-box sizing counts, so they are added back or the last line
      // clips.
      fitLink();

      // Focus the copy button rather than pre-selecting the link: a selected
      // link is harder to read, and copying is the next step anyway — Enter
      // or Space does it from here.
      resultPanel.querySelector('[data-copy]')?.focus();
      textarea.value = '';
      passphraseInput.value = '';
      setPassphraseVisible(false);
      // Each plaintext send is its own decision.
      if (insecureAck) insecureAck.checked = false;
    } catch (error) {
      showError(error.message);
    } finally {
      submitLabel.textContent = 'Create secret link';
      sync();
    }
  });

  document.querySelector('[data-new]')?.addEventListener('click', () => {
    resultPanel.hidden = true;
    composePanel.hidden = false;
    // Measured again now that it is visible; a hidden textarea reports no height.
    sync();
    textarea.focus();
  });
}

/* ------------------------------------------------------ reveal confirmation */

// The form works on its own. This stops an impatient double-click from firing
// two POSTs, where the second would land on an already-burned row, and for an
// end-to-end link sends a stand-in for the passphrase rather than the
// passphrase itself.
const revealForm = document.querySelector('[data-reveal-form]');

// sessionStorage can throw on access where storage is blocked; link-key.js
// treats null as unavailable.
const tabStorage = (() => {
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
})();

if (revealForm) {
  const baseAction = revealForm.getAttribute('action');
  const keyFound = document.querySelector('[data-key-found]');
  const button = revealForm.querySelector('[data-reveal-submit]');
  const label = revealForm.querySelector('[data-reveal-label]');
  const idleLabel = label?.textContent;
  const passphraseField = revealForm.querySelector('[name="passphrase"]');
  // The link's key, once applyKey has found it; null for a link without one.
  let linkKeyText = null;

  // An end-to-end link keeps its key in the #fragment. It leaves this page's
  // URL as the page loads and waits in sessionStorage for the page that ends
  // the reveal (see link-key.js), so no history entry keeps it. Run again on
  // hashchange, for a link pasted into a tab already on this page, and on a
  // back/forward cache restore, by which time the reveal may have used it up.
  const applyKey = () => {
    const { key, inUrl } = linkKey.takeKey(location, history, tabStorage);
    linkKeyText = key;
    // Only when storage failed does the key still need to travel in the URL.
    // Browsers never send a fragment to the server either way.
    revealForm.action = inUrl ? `${baseAction}#${key}` : baseAction;
    // Reassurance that the link arrived whole. Checked in the browser only;
    // nothing about it is sent anywhere.
    keyFound?.toggleAttribute('hidden', !key);
  };

  /** Undoes what submitting did, for a page that comes back without a reload. */
  const resetForm = () => {
    if (button) button.disabled = false;
    if (label) label.textContent = idleLabel;
    if (passphraseField) passphraseField.disabled = false;
    revealForm.querySelector('[data-stand-in]')?.remove();
  };

  applyKey();
  window.addEventListener('hashchange', applyKey);
  window.addEventListener('pageshow', (event) => {
    if (!event.persisted) return;
    applyKey();
    // A back/forward cache restore brings the page back as it was left:
    // mid-submit, with the button disabled.
    resetForm();
  });

  const toggle = revealForm.querySelector('[data-toggle-passphrase]');
  const setPassphraseVisible = toggle ? bindPassphraseToggle(toggle) : null;

  passphraseField?.addEventListener('input', () => passphraseField.setCustomValidity(''));

  revealForm.addEventListener('submit', async (event) => {
    if (button) button.disabled = true;
    if (label) label.textContent = 'Decrypting…';
    // Masked again before the page goes, so the passphrase isn't left on
    // screen while the next page loads.
    setPassphraseVisible?.(false);

    // With the link's key in hand, the passphrase is swapped for the stand-in
    // the sender's page derived from it (see e2e.js), so it never reaches the
    // server. A link without a key was encrypted by the server, and its
    // passphrase goes as typed, just as it went when the secret was created.
    if (!linkKeyText || !passphraseField?.value.trim() || !e2e.isSupported()) return;

    event.preventDefault();
    try {
      const standIn = document.createElement('input');
      standIn.type = 'hidden';
      standIn.name = 'passphrase';
      standIn.dataset.standIn = '';
      standIn.value = await e2e.passphraseVerifier(passphraseField.value, linkKeyText);
      // A disabled field is left out of the submission, so only the stand-in goes.
      passphraseField.disabled = true;
      revealForm.append(standIn);
      revealForm.submit();
    } catch {
      // Only a key too damaged to decode gets here. The secret could not be
      // decrypted with it anyway, so nothing is sent.
      resetForm();
      passphraseField.setCustomValidity(
        'The key in this link is damaged, so it can’t be used. Ask the sender for a fresh link.'
      );
      passphraseField.reportValidity();
    }
  });
}

/* ------------------------------------------------------ end-to-end decrypt */

// The pages that end a reveal (the secret itself, or the "destroyed" page) carry
// data-reveal-ended. The row is gone or out of reach by then, so the key leaves
// storage and this page's URL here, whether or not the page has a use for it.
// Others under /s/, such as the rate-limit page, leave it for the next attempt.
const revealEndKey = document.body.hasAttribute('data-reveal-ended')
  ? linkKey.releaseKey(location, history, tabStorage)
  : null;

// The server handed back ciphertext it cannot read; the key came with the link.
const sealedBody = document.querySelector('[data-secret][data-ciphertext]');

if (sealedBody) {
  const key = revealEndKey;

  const fail = (text) => {
    sealedBody.textContent = text;
    sealedBody.classList.remove('is-masked');
    document.querySelector('[data-reveal]')?.remove();
    document.querySelector('[data-copy="#secret-body"]')?.remove();
  };

  if (!key) {
    fail(
      'This link was missing its decryption key — the part after the "#". The ' +
        'secret has been deleted and cannot be recovered. Ask the sender for a ' +
        'fresh link, and copy all of it.'
    );
  } else {
    e2e.decryptMessage(sealedBody.dataset.ciphertext, key).then(
      (plaintext) => {
        sealedBody.textContent = plaintext;
      },
      () => {
        fail(
          'The decryption key in this link is wrong or incomplete. The secret has ' +
            'been deleted and cannot be recovered. Ask the sender for a fresh link.'
        );
      }
    );
  }
}

/* ------------------------------------------------- shoulder-surfing guard */

// Masking is applied here rather than in the template: the secret is already
// deleted server-side, so it must stay readable if this script never runs.
const secretBody = document.querySelector('[data-secret]');
const revealButton = document.querySelector('[data-reveal]');

if (secretBody && revealButton) {
  secretBody.classList.add('is-masked');
  revealButton.classList.remove('hidden');
  revealButton.classList.add('flex');

  revealButton.addEventListener('click', () => {
    secretBody.classList.remove('is-masked');
    revealButton.remove();
  });
}

/* -------------------------------------------------- creation time, locally */

// The server renders UTC because it can't know the reader's time zone; the
// browser can. "created 2 minutes ago · 27 Sep 2026, 1:34 PM", in the
// reader's own locale and zone. The exact UTC value stays in the title.
const createdAt = document.querySelector('[data-created]');
const created = createdAt ? new Date(createdAt.dateTime) : null;

if (created && !Number.isNaN(created.getTime())) {
  const absolute = new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short'
  }).format(created);
  const relativeFormat = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });

  const relative = () => {
    // Clamped at zero: a server clock slightly ahead would otherwise read as
    // "in 1 minute".
    const seconds = Math.max(0, (Date.now() - created.getTime()) / 1000);
    for (const [unit, size] of [['day', 86_400], ['hour', 3_600], ['minute', 60]]) {
      if (seconds >= size) return relativeFormat.format(-Math.floor(seconds / size), unit);
    }
    return 'just now';
  };

  const render = () => {
    createdAt.textContent = `created ${relative()} · ${absolute}`;
  };

  render();
  // Keeps "2 minutes ago" honest while the page stays open.
  setInterval(render, 30_000);
}

/* ------------------------------------------------------ copy to clipboard */

for (const button of document.querySelectorAll('[data-copy]')) {
  button.addEventListener('click', async () => {
    const target = document.querySelector(button.dataset.copy);
    if (!target) return;

    const value = 'value' in target ? target.value : target.textContent;

    try {
      await navigator.clipboard.writeText(value);
    } catch {
      // The Clipboard API needs a secure context; fall back to the legacy path.
      const scratch = document.createElement('textarea');
      scratch.value = value;
      scratch.setAttribute('readonly', '');
      scratch.style.position = 'fixed';
      scratch.style.opacity = '0';
      document.body.append(scratch);
      scratch.select();
      document.execCommand('copy');
      scratch.remove();
    }

    const label = button.querySelector('[data-copy-label]') ?? button;
    if (label.dataset.busy) return;

    // Swap the copy icon for a check while the label says so.
    const setCopied = (copied) => {
      button.querySelector('[data-copy-icon]')?.classList.toggle('hidden', copied);
      button.querySelector('[data-copied-icon]')?.classList.toggle('hidden', !copied);
    };

    const original = label.textContent;
    label.dataset.busy = '1';
    label.textContent = 'Copied';
    setCopied(true);
    setTimeout(() => {
      label.textContent = original;
      setCopied(false);
      delete label.dataset.busy;
    }, 1800);
  });
}
