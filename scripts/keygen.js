import crypto from 'node:crypto';

const key = crypto.randomBytes(32).toString('hex');

console.log('\nAdd this line to your .env file:\n');
console.log(`SECRET_KEY=${key}\n`);
console.log('Changing this key permanently orphans every secret already in the database.\n');
