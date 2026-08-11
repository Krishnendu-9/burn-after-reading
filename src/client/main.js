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

/* ----------------------------------------------------------- compose form */

const form = document.querySelector('[data-secret-form]');

if (form) {
  const textarea = form.querySelector('[data-message]');
  const submit = form.querySelector('[data-submit]');
  const submitLabel = form.querySelector('[data-submit-label]');
  const counter = document.querySelector('[data-counter]');
  const progress = document.querySelector('[data-progress]');
  const errorBox = document.querySelector('[data-error]');
  const composePanel = document.querySelector('[data-compose]');
  const resultPanel = document.querySelector('[data-result]');
  const linkInput = document.querySelector('[data-link]');
  const expiryLabel = document.querySelector('[data-expiry]');
  const maxLength = Number(textarea.getAttribute('maxlength')) || 10000;

  const showError = (message) => {
    errorBox.textContent = message ? `⚠️ ${message}` : '';
    errorBox.classList.toggle('hidden', !message);
    errorBox.classList.toggle('flex', Boolean(message));
  };

  const sync = () => {
    const used = textarea.value.length;
    counter.textContent = `${used.toLocaleString()} / ${maxLength.toLocaleString()}`;
    progress.style.width = `${Math.min((used / maxLength) * 100, 100)}%`;
    submit.disabled = textarea.value.trim().length === 0;
  };

  textarea.addEventListener('input', sync);
  sync();

  // Ctrl/Cmd + Enter submits.
  textarea.addEventListener('keydown', (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key === 'Enter') {
      event.preventDefault();
      form.requestSubmit();
    }
  });

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

      const response = await fetch('/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: textarea.value,
          ttlHours: Number(fields.get('ttlHours')),
          passphrase: String(fields.get('passphrase') ?? '')
        })
      });

      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'Could not create the link.');

      linkInput.value = data.url;
      expiryLabel.textContent = humanise(data.expiresInHours);

      // Only mention the passphrase when one was actually set.
      document
        .querySelector('[data-passphrase-note]')
        ?.classList.toggle('hidden', !data.protected);

      composePanel.classList.add('hidden');
      resultPanel.classList.remove('hidden');
      linkInput.focus();
      linkInput.select();
      textarea.value = '';
      form.querySelector('[name="passphrase"]').value = '';
    } catch (error) {
      showError(error.message);
    } finally {
      submitLabel.textContent = 'Create secret link';
      sync();
    }
  });

  document.querySelector('[data-new]')?.addEventListener('click', () => {
    resultPanel.classList.add('hidden');
    composePanel.classList.remove('hidden');
    textarea.focus();
  });
}

/* ------------------------------------------------------ reveal confirmation */

// The form works on its own; this only stops an impatient double-click from
// firing two POSTs, where the second would land on an already-burned row.
const revealForm = document.querySelector('[data-reveal-form]');

if (revealForm) {
  revealForm.addEventListener('submit', () => {
    const button = revealForm.querySelector('[data-reveal-submit]');
    const label = revealForm.querySelector('[data-reveal-label]');
    if (button) button.disabled = true;
    if (label) label.textContent = 'Decrypting…';
  });
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

    const original = label.textContent;
    label.dataset.busy = '1';
    label.textContent = '✅ Copied';
    setTimeout(() => {
      label.textContent = original;
      delete label.dataset.busy;
    }, 1800);
  });
}
