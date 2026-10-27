/**
 * Loads ./.env into process.env with Node's own parser, the job dotenv used to
 * do.
 *
 * server.js imports this first, ahead of every module that reads its
 * configuration at load time (src/db.js, src/crypto.js); ES modules evaluate
 * in import order, so those see the file's values. Anything already in the
 * environment wins over the file, so a platform's own settings are never
 * overridden. A missing file is fine: containers and hosted platforms set the
 * environment directly.
 */
try {
  process.loadEnvFile();
} catch (error) {
  if (error.code !== 'ENOENT') throw error;
}
