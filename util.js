// Shared helpers: auth, JSON responses, database setup
const enc = new TextEncoder();

export const RESERVED = new Set(['admin','api','img','index','template','login','favicon','robots','static','assets','404']);
export const SLUG_RE = /^[a-z0-9][a-z0-9_-]{0,59}$/;

export function json(obj, status = 200, headers = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers }
  });
}

async function hmac(secret, msg) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(msg));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function same(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

export function configProblems(env) {
  const p = [];
  if (!env.DB) p.push('DB (the D1 database binding)');
  if (!env.ADMIN_PASSWORD) p.push('ADMIN_PASSWORD');
  if (!env.SESSION_SECRET) p.push('SESSION_SECRET');
  return p;
}

export async function checkPassword(env, pw) {
  const a = await hmac(env.SESSION_SECRET, 'pw:' + String(pw));
  const b = await hmac(env.SESSION_SECRET, 'pw:' + env.ADMIN_PASSWORD);
  return same(a, b);
}
export async function makeCookie(env) {
  const exp = Date.now() + 30 * 864e5;
  const sig = await hmac(env.SESSION_SECRET, 's:' + exp);
  return `ck=${exp}.${sig}; Path=/; Max-Age=${30 * 86400}; HttpOnly; Secure; SameSite=Strict`;
}
export function clearCookie() {
  return 'ck=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict';
}
export async function isAuthed(request, env) {
  if (!env.SESSION_SECRET) return false;
  const m = /(?:^|;\s*)ck=([^;]+)/.exec(request.headers.get('cookie') || '');
  if (!m) return false;
  const [exp, sig] = m[1].split('.');
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  return same(sig, await hmac(env.SESSION_SECRET, 's:' + exp));
}

// India time day string, offset in days
export function dayStr(offset = 0) {
  return new Date(Date.now() + 5.5 * 3600e3 + offset * 864e5).toISOString().slice(0, 10);
}

export async function ensureSchema(env) {
  await env.DB.batch([
    env.DB.prepare("CREATE TABLE IF NOT EXISTS clients(slug TEXT PRIMARY KEY, name TEXT, status TEXT DEFAULT 'draft', data TEXT NOT NULL, meta TEXT NOT NULL DEFAULT '{}', created INTEGER, updated INTEGER)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS images(id TEXT PRIMARY KEY, slug TEXT, mime TEXT, b64 TEXT, created INTEGER)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS views(slug TEXT, day TEXT, src TEXT, n INTEGER DEFAULT 0, PRIMARY KEY(slug, day, src))"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT)")
  ]);
}
