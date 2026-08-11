import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const MANIFEST_PATH = path.join(__dirname, '..', 'public', 'dist', '.vite', 'manifest.json');
const ENTRY = 'src/client/main.js';

let cached = null;

/**
 * Resolves the hashed filenames Vite produced for our single entry point.
 * In dev (`vite build --watch`) the manifest is re-read on every request so a
 * rebuild shows up without restarting Express.
 */
export function assets() {
  if (cached && process.env.NODE_ENV === 'production') return cached;

  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf8'));
  } catch {
    throw new Error('Asset manifest not found. Run `npm run build` (or `npm run dev`) first.');
  }

  const entry = manifest[ENTRY];
  if (!entry) {
    throw new Error(`Entry "${ENTRY}" missing from the Vite manifest.`);
  }

  cached = {
    js: `/dist/${entry.file}`,
    css: (entry.css ?? []).map((file) => `/dist/${file}`)
  };

  return cached;
}
