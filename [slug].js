// Serves every client page: /rahul  ->  reads Rahul's data and renders template.html
import { RESERVED, SLUG_RE, isAuthed, dayStr } from './_lib/util.js';

const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const BOT = /bot|crawl|spider|preview|facebookexternalhit|whatsapp|telegram|slack|curl|wget|headless|monitor/i;

async function loadTemplate(env, request) {
  let u = new URL('/template', request.url);
  for (let i = 0; i < 4; i++) {
    const r = await env.ASSETS.fetch(u);
    if (r.status >= 300 && r.status < 400) { u = new URL(r.headers.get('location'), u); continue; }
    return r.text();
  }
  throw new Error('template not found');
}

const unavailable = () => new Response(
  '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Page unavailable</title>' +
  '<body style="font:16px/1.6 system-ui,sans-serif;max-width:420px;margin:18vh auto;padding:0 22px;color:#0e2233"><h1 style="font-size:24px;margin:0 0 8px">This page is not available right now</h1>' +
  '<p style="color:#586a78">Please contact the owner for an updated link.</p></body>',
  { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } }
);

export async function onRequestGet(ctx) {
  const { request, env, params, next } = ctx;
  const slug = String(params.slug || '').toLowerCase();
  if (!SLUG_RE.test(slug) || RESERVED.has(slug) || !env.DB) return next();

  let row;
  try { row = await env.DB.prepare('SELECT data,status FROM clients WHERE slug=?').bind(slug).first(); }
  catch (e) { return next(); }
  if (!row) return next();

  const authed = await isAuthed(request, env);
  if (row.status !== 'live' && !authed) return unavailable();

  const url = new URL(request.url);
  const ua = request.headers.get('user-agent') || '';
  if (!authed && !BOT.test(ua) && url.searchParams.get('p') !== '1') {
    const s = url.searchParams.get('s');
    const src = s === 'n' || s === 'q' ? s : 'o';
    ctx.waitUntil(env.DB.prepare('INSERT INTO views(slug,day,src,n) VALUES(?,?,?,1) ON CONFLICT(slug,day,src) DO UPDATE SET n=n+1').bind(slug, dayStr(), src).run().catch(() => {}));
  }

  let data;
  try { data = JSON.parse(row.data); } catch (e) { return next(); }
  const tpl = await loadTemplate(env, request);

  const title = (data.name || 'Profile') + (data.title ? ' | ' + data.title : '');
  const desc = data.tagline || data.about || data.title || '';
  const imgPath = data.photo || data.cover;
  const img = imgPath ? new URL(imgPath, url.origin).href : '';
  const meta =
    `<title>${esc(title)}</title>` +
    `<meta name="description" content="${esc(String(desc).slice(0, 180))}">` +
    `<meta property="og:title" content="${esc(title)}">` +
    `<meta property="og:description" content="${esc(String(desc).slice(0, 180))}">` +
    `<meta property="og:type" content="website">` +
    `<meta property="og:url" content="${esc(url.origin + '/' + slug)}">` +
    (img ? `<meta property="og:image" content="${esc(img)}">` : '') +
    `<meta name="twitter:card" content="summary">`;
  const dataJson = JSON.stringify(data).replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');

  const html = tpl
    .replace('<!--__META__-->', () => meta)
    .replace('/*__DATA__*/null', () => dataJson)
    .replace('__SLUG__', () => slug);

  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' } });
}
