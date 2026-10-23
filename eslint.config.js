import js from '@eslint/js';
import globals from 'globals';

// Same shape as the other projects' configs: the recommended rules, ES modules,
// and the right globals for where each file runs.
export default [
  {
    // Build output, and the private notes folder (Markdown only, never linted).
    ignores: ['public/dist/**', 'data/**', 'dev_docs/**']
  },
  js.configs.recommended,
  {
    files: ['**/*.{js,mjs}'],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: 'module',
      globals: { ...globals.node }
    },
    rules: {
      'no-undef': 'error',
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      // Cheap bug catchers beyond the recommended set. None fire today.
      eqeqeq: ['error', 'always'],
      'no-var': 'error',
      'prefer-const': 'error',
      'no-throw-literal': 'error',
      'no-template-curly-in-string': 'error'
    }
  },
  {
    // Every server log line goes through logEvent() in src/logging.js, so the
    // stream stays one format and no one logs a whole error object: body-parser
    // attaches the raw request body, which here is the plaintext secret. In the
    // browser, a console line would put the secret in the dev tools. server.js
    // is outside src/ and keeps its human-readable startup failure message.
    files: ['src/**/*.js'],
    ignores: ['src/logging.js'],
    rules: {
      'no-console': 'error'
    }
  },
  {
    // Runs in the browser. e2e.js and link-key.js are also imported by the tests
    // under Node, so they may only use what both have (WebCrypto, btoa/atob).
    files: ['src/client/**/*.js'],
    languageOptions: {
      globals: { ...globals.browser }
    }
  }
];
