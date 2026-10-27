import { defineConfig } from 'vite';
import tailwindcss from '@tailwindcss/vite';

// `npm run dev` builds once first (the predev script) and only then starts the
// watcher alongside the server, because the server refuses to start without
// the manifest. node --watch restarts only when an imported file changes, so a
// server that started too early stayed down. The watcher must not empty the
// folder again as it starts, or it deletes the manifest out from under the
// server that just started from it.
const watching = process.argv.includes('--watch');

// Vite is used purely as an asset pipeline here: Express owns the HTTP layer and
// renders EJS, Vite just compiles Tailwind + client JS into public/dist and
// writes a manifest that src/assets.js reads to resolve hashed filenames.
export default defineConfig({
  plugins: [tailwindcss()],
  // Express serves public/dist at /dist, so URLs Vite writes into the bundle —
  // the font files referenced from the CSS — must carry that prefix. With the
  // default '/', every font 404s and the pages silently fall back to system
  // fonts.
  base: '/dist/',
  // Without this, Vite would treat ./public as its static dir and copy it into
  // its own output directory (public/dist) on every build.
  publicDir: false,
  build: {
    outDir: 'public/dist',
    emptyOutDir: !watching,
    manifest: true,
    rolldownOptions: {
      input: 'src/client/main.js'
    }
  }
});
