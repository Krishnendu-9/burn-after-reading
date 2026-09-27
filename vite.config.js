import { defineConfig } from 'vite';
import tailwindcss from '@tailwindcss/vite';

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
    emptyOutDir: true,
    manifest: true,
    rollupOptions: {
      input: 'src/client/main.js'
    }
  }
});
