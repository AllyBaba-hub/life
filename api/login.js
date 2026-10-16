const crypto = require('crypto');

const COOKIE_NAME = '__Host-los_session';
const SESSION_HOURS = Number(process.env.SESSION_HOURS) || 4; // absolute server-side lifetime
const MAX_FAILS = 5;
const WINDOW_MS = 15 * 60 * 1000;

// Best-effort throttle (per warm serverless instance). Add a Vercel WAF rate-limit rule for a hard limit.
const attempts = new Map();

const b64url = (buf) => Buffer.from(buf).toString('base64url');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function verifyPassword(password, stored) {
  // stored format: saltHex:hashHex (scrypt, 64-byte key)
  const [saltHex, hashHex] = String(stored || '').split(':');
  if (!saltHex || !hashHex) return false;
  const expected = Buffer.from(hashHex, 'hex');
  const actual = crypto.scryptSync(password, Buffer.from(saltHex, 'hex'), expected.length);
  return crypto.timingSafeEqual(actual, expected);
}

function sign(payload, secret) {
  return crypto.createHmac('sha256', secret).update(payload).digest('base64url');
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // CSRF defence in depth (cookie is also SameSite=Strict)
  const type = String(req.headers['content-type'] || '');
  if (!type.includes('application/json')) return res.status(415).json({ error: 'Unsupported' });
  const origin = req.headers.origin;
  if (origin && new URL(origin).host !== req.headers.host) return res.status(403).json({ error: 'Forbidden' });

  const { AUTH_USERNAME, AUTH_PASSWORD_HASH, SESSION_SECRET } = process.env;
  if (!AUTH_USERNAME || !AUTH_PASSWORD_HASH || !SESSION_SECRET) {
    return res.status(500).json({ error: 'Server not configured' });
  }

  const ip = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'unknown';
  const now = Date.now();
  const rec = attempts.get(ip);
  if (rec && now - rec.first < WINDOW_MS && rec.count >= MAX_FAILS) {
    return res.status(429).json({ error: 'Too many attempts. Try again later.' });
  }

  const body = typeof req.body === 'object' && req.body ? req.body : {};
  const username = typeof body.username === 'string' ? body.username : '';
  const password = typeof body.password === 'string' ? body.password.slice(0, 256) : '';

  // Always evaluate both checks so timing doesn't reveal which one failed.
  const userOk = safeEqual(username, AUTH_USERNAME);
  const passOk = verifyPassword(password, AUTH_PASSWORD_HASH);

  if (!(userOk && passOk)) {
    const fresh = !rec || now - rec.first >= WINDOW_MS;
    attempts.set(ip, { first: fresh ? now : rec.first, count: fresh ? 1 : rec.count + 1 });
    await sleep(500);
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  attempts.delete(ip);
  const payload = b64url(JSON.stringify({
    sub: 'owner',
    iat: now,
    exp: now + SESSION_HOURS * 60 * 60 * 1000,
    jti: crypto.randomBytes(8).toString('hex'),
  }));
  const token = `${payload}.${sign(payload, SESSION_SECRET)}`;

  // No Max-Age / Expires => session cookie: discarded when the browser closes. Never persisted.
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict`);
  return res.status(200).json({ ok: true });
};
