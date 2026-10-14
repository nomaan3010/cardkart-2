// All admin and public API endpoints live here.
import { json, isAuthed, checkPassword, makeCookie, clearCookie, configProblems, ensureSchema, dayStr, RESERVED, SLUG_RE } from '../_lib/util.js';

const DEFAULT_SITE = {
  whatsapp: '',
  instagram: '',
  packages: [
    { name: 'Starter', price: 499, points: ['NFC card with a QR on it', 'Clean one-page profile', 'Call, WhatsApp and Save Contact buttons'] },
    { name: 'Pro', price: 999, flag: 'Most chosen', points: ['Everything in Starter', 'Custom-designed mini website', 'Gallery, services, Google review and UPI buttons', 'Free edits for 1 year'] },
    { name: 'Business', price: 1799, points: ['Everything in Pro', 'Google review stand with QR', 'Monthly offer banner for 6 months'] }
  ]
};

const safeParse = (s, d) => { try { return JSON.parse(s); } catch (e) { return d; } };
const rid = () => [...crypto.getRandomValues(new Uint8Array(9))].map(b => b.toString(16).padStart(2, '0')).join('');

export async function onRequest(ctx) {
  const { request, env, params } = ctx;
  const parts = Array.isArray(params.path) ? params.path : [params.path].filter(Boolean);
  const method = request.method;
  const [a, b] = parts;

  try {
    /* ---------- public ---------- */
    if (a === 'health' && method === 'GET') {
      const missing = configProblems(env);
      if (env.DB) { try { await ensureSchema(env); } catch (e) { missing.push('DB tables could not be created: ' + e.message); } }
      return json({ ok: missing.length === 0, missing });
    }
    if (a === 'site' && method === 'GET') {
      let site = DEFAULT_SITE;
      if (env.DB) {
        try {
          const row = await env.DB.prepare("SELECT v FROM settings WHERE k='site'").first();
          if (row) site = { ...DEFAULT_SITE, ...safeParse(row.v, {}) };
        } catch (e) { /* tables not created yet */ }
      }
      return json(site, 200, { 'Cache-Control': 'public, max-age=60' });
    }
    if (a === 'login' && method === 'POST') {
      const missing = configProblems(env);
      if (missing.length) return json({ error: 'Setup is not finished. Missing: ' + missing.join(', ') }, 500);
      await ensureSchema(env);
      const body = await request.json().catch(() => ({}));
      if (!(await checkPassword(env, body.password))) {
        await new Promise(r => setTimeout(r, 500));
        return json({ error: 'Wrong password' }, 401);
      }
      return json({ ok: true }, 200, { 'Set-Cookie': await makeCookie(env) });
    }
    if (a === 'logout' && method === 'POST') return json({ ok: true }, 200, { 'Set-Cookie': clearCookie() });

    /* ---------- everything below needs login ---------- */
    if (!(await isAuthed(request, env))) return json({ error: 'Please log in' }, 401);
    if (a === 'me') return json({ ok: true });

    if (a === 'site' && method === 'PUT') {
      const body = await request.json();
      const clean = {
        whatsapp: String(body.whatsapp || '').replace(/\D/g, ''),
        instagram: String(body.instagram || '').replace(/^@/, '').trim(),
        packages: (Array.isArray(body.packages) ? body.packages : []).slice(0, 8).map(p => ({
          name: String(p.name || '').slice(0, 40),
          price: Number(p.price) || 0,
          flag: p.flag ? String(p.flag).slice(0, 30) : undefined,
          points: (Array.isArray(p.points) ? p.points : []).slice(0, 8).map(x => String(x).slice(0, 120))
        })).filter(p => p.name)
      };
      await env.DB.prepare("INSERT INTO settings(k,v) VALUES('site',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(JSON.stringify(clean)).run();
      return json({ ok: true });
    }

    if (a === 'clients' && !b && method === 'GET') {
      const rows = (await env.DB.prepare('SELECT slug,name,status,meta,updated FROM clients ORDER BY updated DESC').all()).results || [];
      const v = (await env.DB.prepare('SELECT slug,SUM(n) AS t FROM views WHERE day>=? GROUP BY slug').bind(dayStr(-30)).all()).results || [];
      const vm = {}; v.forEach(x => vm[x.slug] = x.t);
      return json(rows.map(r => ({ slug: r.slug, name: r.name, status: r.status, updated: r.updated, meta: safeParse(r.meta, {}), views30: vm[r.slug] || 0 })));
    }

    if (a === 'clients' && b) {
      const slug = String(b).toLowerCase();
      if (!SLUG_RE.test(slug) || RESERVED.has(slug)) return json({ error: 'That link name is not allowed. Use letters, numbers and hyphens only.' }, 400);

      if (method === 'GET') {
        const r = await env.DB.prepare('SELECT * FROM clients WHERE slug=?').bind(slug).first();
        if (!r) return json({ error: 'Not found' }, 404);
        return json({ slug: r.slug, name: r.name, status: r.status, created: r.created, updated: r.updated, data: safeParse(r.data, {}), meta: safeParse(r.meta, {}) });
      }
      if (method === 'PUT') {
        const body = await request.json();
        const data = body.data && typeof body.data === 'object' ? body.data : {};
        const meta = body.meta && typeof body.meta === 'object' ? body.meta : {};
        const status = ['draft', 'live', 'paused'].includes(body.status) ? body.status : 'draft';
        const dj = JSON.stringify(data), mj = JSON.stringify(meta);
        if (dj.length > 120000 || mj.length > 40000) return json({ error: 'Too much content in one client' }, 413);
        const exists = await env.DB.prepare('SELECT slug FROM clients WHERE slug=?').bind(slug).first();
        if (body.create && exists) return json({ error: 'That link name is already used. Choose another.' }, 409);
        const now = Date.now();
        const name = String(data.name || meta.contact || slug).slice(0, 120);
        await env.DB.prepare(
          'INSERT INTO clients(slug,name,status,data,meta,created,updated) VALUES(?,?,?,?,?,?,?) ON CONFLICT(slug) DO UPDATE SET name=excluded.name,status=excluded.status,data=excluded.data,meta=excluded.meta,updated=excluded.updated'
        ).bind(slug, name, status, dj, mj, now, now).run();
        return json({ ok: true, slug });
      }
      if (method === 'DELETE') {
        await env.DB.batch([
          env.DB.prepare('DELETE FROM clients WHERE slug=?').bind(slug),
          env.DB.prepare('DELETE FROM images WHERE slug=?').bind(slug),
          env.DB.prepare('DELETE FROM views WHERE slug=?').bind(slug)
        ]);
        return json({ ok: true });
      }
    }

    if (a === 'stats' && b && method === 'GET') {
      const rows = (await env.DB.prepare('SELECT day,src,n FROM views WHERE slug=? AND day>=? ORDER BY day').bind(String(b).toLowerCase(), dayStr(-29)).all()).results || [];
      return json({ rows });
    }

    if (a === 'images' && method === 'POST') {
      const body = await request.json();
      const slug = String(body.slug || '').toLowerCase();
      const m = /^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$/.exec(body.dataUrl || '');
      if (!m || !SLUG_RE.test(slug)) return json({ error: 'Invalid image' }, 400);
      if (m[2].length > 950000) return json({ error: 'Image is too large. Try a smaller photo.' }, 413);
      const id = rid();
      await env.DB.prepare('INSERT INTO images(id,slug,mime,b64,created) VALUES(?,?,?,?,?)').bind(id, slug, m[1], m[2], Date.now()).run();
      return json({ ok: true, id, url: '/img/' + id });
    }
    if (a === 'images' && b && method === 'DELETE') {
      await env.DB.prepare('DELETE FROM images WHERE id=?').bind(String(b).replace(/[^a-z0-9]/gi, '')).run();
      return json({ ok: true });
    }

    return json({ error: 'Not found' }, 404);
  } catch (e) {
    return json({ error: String((e && e.message) || e) }, 500);
  }
}
