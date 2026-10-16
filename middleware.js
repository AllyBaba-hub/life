// Runs at the edge BEFORE any page or API route is served.
// Anything not on the allow-list below requires a valid, unexpired session cookie.
import { next } from '@vercel/edge';

export const config = {
  matcher: ['/((?!login\\.html|api/login|favicon\\.ico|icons/).*)'],
};

const COOKIE_NAME = '__Host-los_session';
const enc = new TextEncoder();

function b64urlToBytes(str) {
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(str.length / 4) * 4, '=');
  const bin = atob(b64);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function getCookie(request, name) {
  const header = request.headers.get('cookie') || '';
  for (const part of header.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return v.join('=');
  }
  return null;
}

async function isValid(token, secret) {
  try {
    const [payload, sig] = token.split('.');
    if (!payload || !sig) return false;
    const key = await crypto.subtle.importKey(
      'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
    );
    const ok = await crypto.subtle.verify('HMAC', key, b64urlToBytes(sig), enc.encode(payload));
    if (!ok) return false;
    const data = JSON.parse(new TextDecoder().decode(b64urlToBytes(payload)));
    return typeof data.exp === 'number' && data.exp > Date.now();
  } catch {
    return false;
  }
}

export default async function middleware(request) {
  const secret = process.env.SESSION_SECRET;
  const token = getCookie(request, COOKIE_NAME);

  // Fail closed: no secret configured, no cookie, bad signature or expired => not authenticated.
  if (secret && token && (await isValid(token, secret))) {
    return next({ headers: { 'Cache-Control': 'private, no-store' } });
  }

  const { pathname } = new URL(request.url);
  if (pathname.startsWith('/api/')) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    });
  }
  return new Response(null, {
    status: 302,
    headers: { Location: '/login.html', 'Cache-Control': 'no-store' },
  });
}
