// Usage: node scripts/hash-password.js "your long passphrase"
// Prints the values to paste into Vercel -> Settings -> Environment Variables.
const crypto = require('crypto');

const password = process.argv[2];
if (!password || password.length < 12) {
  console.error('Provide a password of at least 12 characters:\n  node scripts/hash-password.js "your long passphrase"');
  process.exit(1);
}
const salt = crypto.randomBytes(16);
const hash = crypto.scryptSync(password, salt, 64);

console.log('AUTH_USERNAME=choose-a-username');
console.log('AUTH_PASSWORD_HASH=' + salt.toString('hex') + ':' + hash.toString('hex'));
console.log('SESSION_SECRET=' + crypto.randomBytes(48).toString('base64url'));
console.log('SESSION_HOURS=4   # optional');
