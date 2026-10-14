// src/util.js
var enc = new TextEncoder();
var RESERVED = /* @__PURE__ */ new Set(["admin", "api", "img", "index", "template", "login", "favicon", "robots", "static", "assets", "404"]);
var SLUG_RE = /^[a-z0-9][a-z0-9_-]{0,59}$/;
function json(obj, status = 200, headers = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers }
  });
}
async function hmac(secret, msg) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(msg));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function same(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
function configProblems(env) {
  const p = [];
  if (!env.DB) p.push("DB (the D1 database binding)");
  if (!env.ADMIN_PASSWORD) p.push("ADMIN_PASSWORD");
  if (!env.SESSION_SECRET) p.push("SESSION_SECRET");
  return p;
}
async function checkPassword(env, pw) {
  const a = await hmac(env.SESSION_SECRET, "pw:" + String(pw));
  const b = await hmac(env.SESSION_SECRET, "pw:" + env.ADMIN_PASSWORD);
  return same(a, b);
}
async function makeCookie(env) {
  const exp = Date.now() + 30 * 864e5;
  const sig = await hmac(env.SESSION_SECRET, "s:" + exp);
  return `ck=${exp}.${sig}; Path=/; Max-Age=${30 * 86400}; HttpOnly; Secure; SameSite=Strict`;
}
function clearCookie() {
  return "ck=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict";
}
async function isAuthed(request, env) {
  if (!env.SESSION_SECRET) return false;
  const m = /(?:^|;\s*)ck=([^;]+)/.exec(request.headers.get("cookie") || "");
  if (!m) return false;
  const [exp, sig] = m[1].split(".");
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  return same(sig, await hmac(env.SESSION_SECRET, "s:" + exp));
}
function dayStr(offset = 0) {
  return new Date(Date.now() + 5.5 * 36e5 + offset * 864e5).toISOString().slice(0, 10);
}
async function ensureSchema(env) {
  await env.DB.batch([
    env.DB.prepare("CREATE TABLE IF NOT EXISTS clients(slug TEXT PRIMARY KEY, name TEXT, status TEXT DEFAULT 'draft', data TEXT NOT NULL, meta TEXT NOT NULL DEFAULT '{}', created INTEGER, updated INTEGER)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS images(id TEXT PRIMARY KEY, slug TEXT, mime TEXT, b64 TEXT, created INTEGER)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS views(slug TEXT, day TEXT, src TEXT, n INTEGER DEFAULT 0, PRIMARY KEY(slug, day, src))"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT)")
  ]);
}

// src/api.js
var DEFAULT_SITE = {
  whatsapp: "",
  instagram: "",
  packages: [
    { name: "Starter", price: 499, points: ["NFC card with a QR on it", "Clean one-page profile", "Call, WhatsApp and Save Contact buttons"] },
    { name: "Pro", price: 999, flag: "Most chosen", points: ["Everything in Starter", "Custom-designed mini website", "Gallery, services, Google review and UPI buttons", "Free edits for 1 year"] },
    { name: "Business", price: 1799, points: ["Everything in Pro", "Google review stand with QR", "Monthly offer banner for 6 months"] }
  ]
};
var safeParse = (s, d) => {
  try {
    return JSON.parse(s);
  } catch (e) {
    return d;
  }
};
var rid = () => [...crypto.getRandomValues(new Uint8Array(9))].map((b) => b.toString(16).padStart(2, "0")).join("");
async function handleApi(ctx) {
  const { request, env, params } = ctx;
  const parts = Array.isArray(params.path) ? params.path : [params.path].filter(Boolean);
  const method = request.method;
  const [a, b] = parts;
  try {
    if (a === "health" && method === "GET") {
      const missing = configProblems(env);
      if (env.DB) {
        try {
          await ensureSchema(env);
        } catch (e) {
          missing.push("DB tables could not be created: " + e.message);
        }
      }
      return json({ ok: missing.length === 0, missing });
    }
    if (a === "site" && method === "GET") {
      let site = DEFAULT_SITE;
      if (env.DB) {
        try {
          const row = await env.DB.prepare("SELECT v FROM settings WHERE k='site'").first();
          if (row) site = { ...DEFAULT_SITE, ...safeParse(row.v, {}) };
        } catch (e) {
        }
      }
      return json(site, 200, { "Cache-Control": "public, max-age=60" });
    }
    if (a === "login" && method === "POST") {
      const missing = configProblems(env);
      if (missing.length) return json({ error: "Setup is not finished. Missing: " + missing.join(", ") }, 500);
      await ensureSchema(env);
      const body = await request.json().catch(() => ({}));
      if (!await checkPassword(env, body.password)) {
        await new Promise((r) => setTimeout(r, 500));
        return json({ error: "Wrong password" }, 401);
      }
      return json({ ok: true }, 200, { "Set-Cookie": await makeCookie(env) });
    }
    if (a === "logout" && method === "POST") return json({ ok: true }, 200, { "Set-Cookie": clearCookie() });
    if (!await isAuthed(request, env)) return json({ error: "Please log in" }, 401);
    if (a === "me") return json({ ok: true });
    if (a === "site" && method === "PUT") {
      const body = await request.json();
      const clean = {
        whatsapp: String(body.whatsapp || "").replace(/\D/g, ""),
        instagram: String(body.instagram || "").replace(/^@/, "").trim(),
        packages: (Array.isArray(body.packages) ? body.packages : []).slice(0, 8).map((p) => ({
          name: String(p.name || "").slice(0, 40),
          price: Number(p.price) || 0,
          flag: p.flag ? String(p.flag).slice(0, 30) : void 0,
          points: (Array.isArray(p.points) ? p.points : []).slice(0, 8).map((x) => String(x).slice(0, 120))
        })).filter((p) => p.name)
      };
      await env.DB.prepare("INSERT INTO settings(k,v) VALUES('site',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(JSON.stringify(clean)).run();
      return json({ ok: true });
    }
    if (a === "clients" && !b && method === "GET") {
      const rows = (await env.DB.prepare("SELECT slug,name,status,meta,updated FROM clients ORDER BY updated DESC").all()).results || [];
      const v = (await env.DB.prepare("SELECT slug,SUM(n) AS t FROM views WHERE day>=? GROUP BY slug").bind(dayStr(-30)).all()).results || [];
      const vm = {};
      v.forEach((x) => vm[x.slug] = x.t);
      return json(rows.map((r) => ({ slug: r.slug, name: r.name, status: r.status, updated: r.updated, meta: safeParse(r.meta, {}), views30: vm[r.slug] || 0 })));
    }
    if (a === "clients" && b) {
      const slug = String(b).toLowerCase();
      if (!SLUG_RE.test(slug) || RESERVED.has(slug)) return json({ error: "That link name is not allowed. Use letters, numbers and hyphens only." }, 400);
      if (method === "GET") {
        const r = await env.DB.prepare("SELECT * FROM clients WHERE slug=?").bind(slug).first();
        if (!r) return json({ error: "Not found" }, 404);
        return json({ slug: r.slug, name: r.name, status: r.status, created: r.created, updated: r.updated, data: safeParse(r.data, {}), meta: safeParse(r.meta, {}) });
      }
      if (method === "PUT") {
        const body = await request.json();
        const data = body.data && typeof body.data === "object" ? body.data : {};
        const meta = body.meta && typeof body.meta === "object" ? body.meta : {};
        const status = ["draft", "live", "paused"].includes(body.status) ? body.status : "draft";
        const dj = JSON.stringify(data), mj = JSON.stringify(meta);
        if (dj.length > 12e4 || mj.length > 4e4) return json({ error: "Too much content in one client" }, 413);
        const exists = await env.DB.prepare("SELECT slug FROM clients WHERE slug=?").bind(slug).first();
        if (body.create && exists) return json({ error: "That link name is already used. Choose another." }, 409);
        const now = Date.now();
        const name = String(data.name || meta.contact || slug).slice(0, 120);
        await env.DB.prepare(
          "INSERT INTO clients(slug,name,status,data,meta,created,updated) VALUES(?,?,?,?,?,?,?) ON CONFLICT(slug) DO UPDATE SET name=excluded.name,status=excluded.status,data=excluded.data,meta=excluded.meta,updated=excluded.updated"
        ).bind(slug, name, status, dj, mj, now, now).run();
        return json({ ok: true, slug });
      }
      if (method === "DELETE") {
        await env.DB.batch([
          env.DB.prepare("DELETE FROM clients WHERE slug=?").bind(slug),
          env.DB.prepare("DELETE FROM images WHERE slug=?").bind(slug),
          env.DB.prepare("DELETE FROM views WHERE slug=?").bind(slug)
        ]);
        return json({ ok: true });
      }
    }
    if (a === "stats" && b && method === "GET") {
      const rows = (await env.DB.prepare("SELECT day,src,n FROM views WHERE slug=? AND day>=? ORDER BY day").bind(String(b).toLowerCase(), dayStr(-29)).all()).results || [];
      return json({ rows });
    }
    if (a === "images" && method === "POST") {
      const body = await request.json();
      const slug = String(body.slug || "").toLowerCase();
      const m = /^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$/.exec(body.dataUrl || "");
      if (!m || !SLUG_RE.test(slug)) return json({ error: "Invalid image" }, 400);
      if (m[2].length > 95e4) return json({ error: "Image is too large. Try a smaller photo." }, 413);
      const id = rid();
      await env.DB.prepare("INSERT INTO images(id,slug,mime,b64,created) VALUES(?,?,?,?,?)").bind(id, slug, m[1], m[2], Date.now()).run();
      return json({ ok: true, id, url: "/img/" + id });
    }
    if (a === "images" && b && method === "DELETE") {
      await env.DB.prepare("DELETE FROM images WHERE id=?").bind(String(b).replace(/[^a-z0-9]/gi, "")).run();
      return json({ ok: true });
    }
    return json({ error: "Not found" }, 404);
  } catch (e) {
    return json({ error: String(e && e.message || e) }, 500);
  }
}

// src/img.js
async function handleImg({ env, params }) {
  try {
    const id = String(params.id || "").replace(/[^a-z0-9]/gi, "");
    const row = await env.DB.prepare("SELECT mime,b64 FROM images WHERE id=?").bind(id).first();
    if (!row) return new Response("Not found", { status: 404 });
    const bin = atob(row.b64);
    const u8 = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
    return new Response(u8, { headers: { "Content-Type": row.mime, "Cache-Control": "public, max-age=31536000, immutable" } });
  } catch (e) {
    return new Response("Not found", { status: 404 });
  }
}

// public/template.html
var template_default = `<!DOCTYPE html>
<html lang="en" data-theme="marine">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<!--__META__-->
<meta name="theme-color" content="#0b7a75">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Crect width='100' height='100' rx='22' fill='%230b7a75'/%3E%3Cpath d='M28 38h44M28 50h30M28 62h18' stroke='white' stroke-width='8' stroke-linecap='round'/%3E%3C/svg%3E">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:wght@600;700&family=Figtree:wght@400;500;700&family=Fraunces:wght@600&family=Manrope:wght@700;800&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#f2f5f7;--surface:#fff;--ink:#0e2233;--muted:#586a78;--line:#d9e1e7;
  --accent:#0b7a75;--accent-ink:#fff;--r:14px;--wa:#1a9d52;
  --display:"Bricolage Grotesque","Figtree",system-ui,sans-serif;
  --body:"Figtree",system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
}
[data-theme=gulmohar]{--bg:#fff6f9;--surface:#fff;--ink:#2b1021;--muted:#7a5a6c;--line:#f0d6e1;--accent:#c4205a;--accent-ink:#fff;--r:18px;--display:"Fraunces",Georgia,serif}
[data-theme=slate]{--bg:#fff;--surface:#f5f6f8;--ink:#111827;--muted:#5b6472;--line:#e3e6eb;--accent:#2d4bff;--accent-ink:#fff;--r:10px;--display:"Manrope",system-ui,sans-serif}

*{box-sizing:border-box;margin:0;padding:0}
html{-webkit-text-size-adjust:100%}
body{font:400 16px/1.55 var(--body);background:var(--bg);color:var(--ink);-webkit-font-smoothing:antialiased}
a{color:inherit}
.wrap{max-width:480px;margin:0 auto;min-height:100vh;background:var(--bg)}
@media(min-width:520px){body{background:color-mix(in srgb,var(--ink) 7%,var(--bg))}.wrap{box-shadow:0 0 0 1px var(--line)}}
:focus-visible{outline:3px solid color-mix(in srgb,var(--accent) 55%,transparent);outline-offset:2px}

/* top block */
.top{position:relative;background:var(--accent);color:var(--accent-ink);padding:max(18px,env(safe-area-inset-top)) 22px 28px;background-size:cover;background-position:center}
.top.hascover{color:#fff}
.langs{display:flex;justify-content:flex-end;gap:14px;font-size:14px}
.langs button{background:none;border:0;color:inherit;font:inherit;opacity:.7;cursor:pointer;padding:4px 0}
.langs button.on{opacity:1;font-weight:700;text-decoration:underline;text-underline-offset:4px}
.av{width:84px;height:84px;border-radius:24px;background:color-mix(in srgb,currentColor 16%,transparent);display:grid;place-items:center;font:700 30px var(--display);overflow:hidden;margin:20px 0 16px}
.av img{width:100%;height:100%;object-fit:cover;display:block}
h1{font:700 32px/1.1 var(--display);letter-spacing:-.01em}
.role{margin-top:6px;font-weight:500;opacity:.92}
.tag{margin-top:10px;opacity:.85;max-width:34ch}

/* actions */
.acts{padding:18px 18px 0;display:grid;gap:10px}
.pair{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.pair.one{grid-template-columns:1fr}
.btn{display:flex;align-items:center;justify-content:center;gap:10px;min-height:52px;padding:0 16px;border-radius:var(--r);font:700 16px var(--body);text-decoration:none;border:1.5px solid transparent;cursor:pointer;transition:transform .08s}
.btn:active{transform:scale(.98)}
.btn.fill{background:var(--accent);color:var(--accent-ink)}
.btn.line{background:var(--surface);border-color:var(--line);color:var(--ink)}
.btn.line .wa{color:var(--wa)}
.btn.inv{background:#fff;color:#0e2233}
.btn.ghost{background:transparent;border-color:rgba(255,255,255,.55);color:inherit}
.row{display:flex;align-items:center;gap:14px;width:100%;min-height:56px;padding:0 2px;background:none;border:0;border-bottom:1px solid var(--line);color:inherit;font:500 16px var(--body);text-decoration:none;text-align:left;cursor:pointer}
.row .ic{width:36px;height:36px;border-radius:10px;display:grid;place-items:center;background:color-mix(in srgb,var(--accent) 12%,var(--surface));color:var(--accent);flex:none}
.row .go{margin-left:auto;opacity:.4;display:flex}

/* sections */
section{padding:28px 22px 0}
h2{font:700 20px/1.2 var(--display);margin-bottom:12px}
.about{white-space:pre-line;max-width:60ch}
.meta{margin-top:12px;color:var(--muted);font-size:15px}
.offer{margin:20px 18px 0;padding:14px 16px;border-left:5px solid var(--accent);background:color-mix(in srgb,var(--accent) 10%,var(--surface));border-radius:0 var(--r) var(--r) 0;font-weight:500}
.svc{display:flex;align-items:baseline;gap:8px;padding:9px 0 3px}
.svc .n{font-weight:700}
.svc .dots{flex:1;border-bottom:2px dotted var(--line);transform:translateY(-4px)}
.svc .p{font-weight:700;font-variant-numeric:tabular-nums}
.svc-d{color:var(--muted);font-size:14px;max-width:44ch}
.gal{display:grid;grid-template-columns:1fr 1fr;gap:6px}
.gal img{width:100%;aspect-ratio:1;object-fit:cover;border-radius:calc(var(--r) - 6px);cursor:zoom-in;background:var(--line);display:block}
.gal img:first-child{grid-column:span 2;aspect-ratio:16/10}
.lnk{display:inline-block;margin:0 16px 8px 0;font-weight:700;color:var(--accent);text-underline-offset:3px}
.form input,.form textarea{width:100%;font:inherit;padding:12px 14px;border:1.5px solid var(--line);border-radius:var(--r);background:var(--surface);color:var(--ink);margin-bottom:10px}
footer{padding:36px 22px max(28px,env(safe-area-inset-bottom));color:var(--muted);font-size:14px}
.lb{position:fixed;inset:0;background:rgba(0,0,0,.88);display:grid;place-items:center;z-index:9;padding:16px;cursor:zoom-out}
.lb img{max-width:100%;max-height:100%;border-radius:8px}
.toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%);background:var(--ink);color:var(--bg);padding:10px 16px;border-radius:999px;font-size:14px;z-index:10}


.q{border-left:4px solid var(--accent);padding:2px 0 2px 14px;margin:0 0 16px}
.q p{max-width:52ch}
.q cite{display:block;margin-top:4px;color:var(--muted);font-size:14px;font-style:normal;font-weight:700}
</style>
</head>
<body>
<div id="app"></div>
<script>
const SITE={brand:"CardKart"};
const C=/*__DATA__*/null;
const SLUG="__SLUG__";
const LABELS = {
  en:{call:"Call",whatsapp:"WhatsApp",save:"Save contact",email:"Email",directions:"Get directions",about:"About",services:"What we offer",gallery:"Photos",testimonials:"What customers say",links:"Find us online",review:"Leave a Google review",pay:"Pay with UPI",share:"Share this page",enquiry:"Send an enquiry",yourname:"Your name",yourmsg:"What would you like to ask?",send:"Send on WhatsApp",copied:"Link copied",nf:"This page isn't available",nfm:"The link may be wrong or the page was removed. Please ask the owner for the correct link."},
  hi:{call:"\u0915\u0949\u0932 \u0915\u0930\u0947\u0902",whatsapp:"\u0935\u094D\u0939\u093E\u091F\u094D\u0938\u0910\u092A",save:"\u0938\u0902\u092A\u0930\u094D\u0915 \u0938\u0947\u0935 \u0915\u0930\u0947\u0902",email:"\u0908\u092E\u0947\u0932",directions:"\u0930\u093E\u0938\u094D\u0924\u093E \u0926\u0947\u0916\u0947\u0902",about:"\u092A\u0930\u093F\u091A\u092F",services:"\u0939\u092E\u093E\u0930\u0940 \u0938\u0947\u0935\u093E\u090F\u0901",gallery:"\u0924\u0938\u094D\u0935\u0940\u0930\u0947\u0902",testimonials:"\u0917\u094D\u0930\u093E\u0939\u0915 \u0915\u094D\u092F\u093E \u0915\u0939\u0924\u0947 \u0939\u0948\u0902",links:"\u0939\u092E\u0947\u0902 \u092F\u0939\u093E\u0901 \u092D\u0940 \u0916\u094B\u091C\u0947\u0902",review:"Google \u0930\u093F\u0935\u094D\u092F\u0942 \u0926\u0947\u0902",pay:"UPI \u0938\u0947 \u092D\u0941\u0917\u0924\u093E\u0928 \u0915\u0930\u0947\u0902",share:"\u092F\u0939 \u092A\u0947\u091C \u0936\u0947\u092F\u0930 \u0915\u0930\u0947\u0902",enquiry:"\u092A\u0942\u091B\u0924\u093E\u091B \u092D\u0947\u091C\u0947\u0902",yourname:"\u0906\u092A\u0915\u093E \u0928\u093E\u092E",yourmsg:"\u0906\u092A \u0915\u094D\u092F\u093E \u092A\u0942\u091B\u0928\u093E \u091A\u093E\u0939\u0924\u0947 \u0939\u0948\u0902?",send:"\u0935\u094D\u0939\u093E\u091F\u094D\u0938\u0910\u092A \u092A\u0930 \u092D\u0947\u091C\u0947\u0902",copied:"\u0932\u093F\u0902\u0915 \u0915\u0949\u092A\u0940 \u0939\u094B \u0917\u092F\u093E"},
  mr:{call:"\u0915\u0949\u0932 \u0915\u0930\u093E",whatsapp:"\u0935\u094D\u0939\u0949\u091F\u094D\u0938\u0905\u200D\u0945\u092A",save:"\u0938\u0902\u092A\u0930\u094D\u0915 \u0938\u0947\u0935\u094D\u0939 \u0915\u0930\u093E",email:"\u0908\u092E\u0947\u0932",directions:"\u092E\u093E\u0930\u094D\u0917 \u092A\u0939\u093E",about:"\u092E\u093E\u0939\u093F\u0924\u0940",services:"\u0906\u092E\u091A\u094D\u092F\u093E \u0938\u0947\u0935\u093E",gallery:"\u092B\u094B\u091F\u094B",testimonials:"\u0917\u094D\u0930\u093E\u0939\u0915 \u0915\u093E\u092F \u092E\u094D\u0939\u0923\u0924\u093E\u0924",links:"\u0906\u092E\u094D\u0939\u093E\u0932\u093E \u0907\u0925\u0947\u0939\u0940 \u0936\u094B\u0927\u093E",review:"Google \u0930\u093F\u0935\u094D\u0939\u094D\u092F\u0942 \u0926\u094D\u092F\u093E",pay:"UPI \u0928\u0947 \u092A\u0948\u0938\u0947 \u0926\u094D\u092F\u093E",share:"\u0939\u0947 \u092A\u0947\u091C \u0936\u0947\u0905\u0930 \u0915\u0930\u093E",enquiry:"\u091A\u094C\u0915\u0936\u0940 \u092A\u093E\u0920\u0935\u093E",yourname:"\u0924\u0941\u092E\u091A\u0947 \u0928\u093E\u0935",yourmsg:"\u0924\u0941\u092E\u094D\u0939\u093E\u0932\u093E \u0915\u093E\u092F \u0935\u093F\u091A\u093E\u0930\u093E\u092F\u091A\u0947 \u0906\u0939\u0947?",send:"\u0935\u094D\u0939\u0949\u091F\u094D\u0938\u0905\u200D\u0945\u092A\u0935\u0930 \u092A\u093E\u0920\u0935\u093E",copied:"\u0932\u093F\u0902\u0915 \u0915\u0949\u092A\u0940 \u091D\u093E\u0932\u0940"}
};

const IC = {
  phone:'<path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72c.13.96.36 1.9.7 2.81a2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45c.91.34 1.85.57 2.81.7A2 2 0 0 1 22 16.92z"/>',
  chat:'<path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/>',
  userplus:'<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M19 8v6M22 11h-6"/>',
  mail:'<path d="M4 4h16a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z"/><path d="m22 6-10 7L2 6"/>',
  pin:'<path d="M21 10c0 7-9 13-9 13S3 17 3 10a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/>',
  star:'<path d="m12 2 3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/>',
  rupee:'<path d="M6 3h12M6 8h12M6 13l8.5 8M6 13h3M9 13c6.667 0 6.667-10 0-10"/>',
  share:'<path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8M16 6l-4-4-4 4M12 2v13"/>',
  chev:'<path d="m9 18 6-6-6-6"/>'
};
function svg(n,cls){
  const t=document.createElement('span');
  t.innerHTML='<svg class="'+(cls||'')+'" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'+IC[n]+'</svg>';
  return t.firstChild;
}
function h(tag,attrs,...kids){
  const e=document.createElement(tag);
  for(const k in (attrs||{})){
    const v=attrs[k];
    if(v==null||v===false)continue;
    if(k==='class')e.className=v;
    else if(k.slice(0,2)==='on')e.addEventListener(k.slice(2),v);
    else e.setAttribute(k,v===true?'':v);
  }
  for(const c of kids.flat()){
    if(c==null||c===false)continue;
    e.append(typeof c==='object'?c:document.createTextNode(String(c)));
  }
  return e;
}
const $app=document.getElementById('app');
function safe(u){u=String(u||'').trim();if(!u)return '';return /^(https?:|tel:|mailto:|upi:|\\/)/i.test(u)?u:'https://'+u;}
function intl(n){let d=String(n||'').replace(/\\D/g,'');if(d.length===10)d='91'+d;return d;}
function inkFor(hex){const m=/^#?([0-9a-f]{6})$/i.exec(hex||'');if(!m)return '#fff';const n=parseInt(m[1],16);return (0.299*(n>>16)+0.587*((n>>8)&255)+0.114*(n&255))>165?'#111':'#fff';}
function toast(msg){const t=h('div',{class:'toast'},msg);document.body.append(t);setTimeout(()=>t.remove(),1800);}
function row(icon,label,href,fn){
  const el=href?h('a',{class:'row',href:href,target:/^https?:/.test(href)?'_blank':null,rel:'noopener'}):h('button',{class:'row',type:'button',onclick:fn});
  el.append(h('span',{class:'ic'},svg(icon)),h('span',{},label),h('span',{class:'go'},svg('chev')));
  return el;
}
function lightbox(src){
  const lb=h('div',{class:'lb',onclick:()=>lb.remove()},h('img',{src:src,alt:''}));
  document.body.append(lb);
}

/* ---------- vCard (Save contact) ---------- */
function vcard(c){
  const e=s=>String(s||'').replace(/\\\\/g,'\\\\\\\\').replace(/\\n/g,'\\\\n').replace(/,/g,'\\\\,').replace(/;/g,'\\\\;');
  const parts=String(c.name||'').trim().split(/\\s+/);
  const last=parts.length>1?parts.pop():'';
  const first=parts.join(' ');
  const L=['BEGIN:VCARD','VERSION:3.0','N:'+e(last)+';'+e(first)+';;;','FN:'+e(c.name)];
  if(c.org)L.push('ORG:'+e(c.org));
  if(c.title)L.push('TITLE:'+e(c.title));
  if(c.phone)L.push('TEL;TYPE=CELL:+'+intl(c.phone));
  if(c.email)L.push('EMAIL:'+e(c.email));
  if(c.website)L.push('URL:'+safe(c.website));
  if(c.address)L.push('ADR;TYPE=WORK:;;'+e(c.address)+';;;;');
  if(c.tagline)L.push('NOTE:'+e(c.tagline));
  L.push('END:VCARD');
  return L.join('\\r\\n');
}
function saveContact(c,slug){
  const blob=new Blob([vcard(c)],{type:'text/vcard'});
  const u=URL.createObjectURL(blob);
  const a=document.createElement('a');
  a.href=u;a.download=(slug||'contact')+'.vcf';
  document.body.append(a);a.click();a.remove();
  setTimeout(()=>URL.revokeObjectURL(u),3000);
}


/* ---------- client page ---------- */
function renderClient(c,slug){
  const themes=['marine','gulmohar','slate'];
  const root=document.documentElement;
  root.setAttribute('data-theme',themes.indexOf(c.theme)>-1?c.theme:'marine');
  if(c.accent){root.style.setProperty('--accent',c.accent);root.style.setProperty('--accent-ink',inkFor(c.accent));}
  const tc=document.querySelector('meta[name=theme-color]');
  if(tc)tc.content=getComputedStyle(root).getPropertyValue('--accent').trim()||'#0b7a75';

  const T=c.translations||{};
  const langs=['en'].concat(['hi','mr'].filter(l=>T[l]));
  let lang='en';

  function draw(){
    const L=Object.assign({},LABELS.en,LABELS[lang]);
    const tr=k=>(lang!=='en'&&T[lang]&&T[lang][k])||c[k];
    const phone=c.phone?intl(c.phone):'';
    const wa=intl(c.whatsapp||c.phone);
    const wrap=h('div',{class:'wrap'});

    /* top */
    const top=h('div',{class:'top'+(c.cover?' hascover':'')});
    if(c.cover)top.style.backgroundImage='linear-gradient(rgba(0,0,0,.52),rgba(0,0,0,.52)),url("'+safe(c.cover)+'")';
    if(langs.length>1)top.append(h('div',{class:'langs'},langs.map(l=>h('button',{type:'button',class:l===lang?'on':'',onclick:()=>{lang=l;draw();}},{en:'English',hi:'\u0939\u093F\u0902\u0926\u0940',mr:'\u092E\u0930\u093E\u0920\u0940'}[l]))));
    const initials=String(c.name||'?').split(/\\s+/).map(w=>w[0]).slice(0,2).join('').toUpperCase();
    top.append(h('div',{class:'av'},c.photo?h('img',{src:safe(c.photo),alt:c.name||''}):initials));
    top.append(h('h1',{},c.name||''));
    if(c.title)top.append(h('p',{class:'role'},c.title));
    if(tr('tagline'))top.append(h('p',{class:'tag'},tr('tagline')));
    wrap.append(top);

    /* actions */
    const acts=h('div',{class:'acts'});
    const pair=[];
    if(phone)pair.push(h('a',{class:'btn fill',href:'tel:+'+phone},svg('phone'),L.call));
    if(wa)pair.push(h('a',{class:'btn line',href:'https://wa.me/'+wa,target:'_blank',rel:'noopener'},svg('chat','wa'),L.whatsapp));
    if(pair.length)acts.append(h('div',{class:'pair'+(pair.length===1?' one':'')},pair));
    const rows=h('div',{});
    rows.append(row('userplus',L.save,null,()=>saveContact(c,slug)));
    if(c.email)rows.append(row('mail',L.email,'mailto:'+c.email));
    if(c.maps||c.address)rows.append(row('pin',L.directions,c.maps?safe(c.maps):'https://www.google.com/maps/search/?api=1&query='+encodeURIComponent(c.address)));
    if(c.upi)rows.append(row('rupee',L.pay,'upi://pay?pa='+encodeURIComponent(c.upi)+'&pn='+encodeURIComponent(c.name||'')+'&cu=INR'));
    if(c.review)rows.append(row('star',L.review,safe(c.review)));
    rows.append(row('share',L.share,null,async()=>{
      try{
        if(navigator.share)await navigator.share({title:c.name,text:c.tagline||c.title||'',url:location.href});
        else{await navigator.clipboard.writeText(location.href);toast(L.copied);}
      }catch(e){}
    }));
    acts.append(rows);
    wrap.append(acts);

    /* offer */
    const offerText=(lang!=='en'&&T[lang]&&T[lang].offer)||(c.offer&&c.offer.text);
    const offerOk=c.offer&&(!c.offer.until||new Date(c.offer.until+'T23:59:59')>=new Date());
    if(offerText&&offerOk)wrap.append(h('div',{class:'offer'},offerText));

    /* about */
    if(tr('about')||c.hours||c.address){
      const s=h('section',{},h('h2',{},L.about));
      if(tr('about'))s.append(h('p',{class:'about'},tr('about')));
      if(c.hours)s.append(h('p',{class:'meta'},c.hours));
      if(c.address)s.append(h('p',{class:'meta'},c.address));
      wrap.append(s);
    }

    /* services */
    if(c.services&&c.services.length){
      const s=h('section',{},h('h2',{},L.services));
      c.services.forEach(x=>{
        s.append(h('div',{class:'svc'},h('span',{class:'n'},x.name||''),h('span',{class:'dots'}),x.price?h('span',{class:'p'},x.price):null));
        if(x.desc)s.append(h('p',{class:'svc-d'},x.desc));
      });
      wrap.append(s);
    }

    /* gallery */
    if(c.gallery&&c.gallery.length){
      const g=h('div',{class:'gal'},c.gallery.map(src=>h('img',{src:safe(src),alt:'',loading:'lazy',onclick:()=>lightbox(safe(src))})));
      wrap.append(h('section',{},h('h2',{},L.gallery),g));
    }

    /* links */
    const links=(c.links||[]).slice();
    if(c.instagram)links.unshift({label:'Instagram',url:'https://instagram.com/'+String(c.instagram).replace(/^@/,'')});
    if(c.website)links.unshift({label:'Website',url:c.website});
    if(links.length)wrap.append(h('section',{},h('h2',{},L.links),h('div',{},links.map(l=>h('a',{class:'lnk',href:safe(l.url),target:'_blank',rel:'noopener'},l.label)))));

    /* testimonials */
    if(c.testimonials&&c.testimonials.length){
      wrap.append(h('section',{},h('h2',{},L.testimonials),c.testimonials.map(t=>h('blockquote',{class:'q'},h('p',{},t.text||''),t.name?h('cite',{},t.name):null))));
    }

    /* enquiry */
    if(wa&&c.enquiry!==false){
      const nm=h('input',{placeholder:L.yourname,autocomplete:'name'});
      const ms=h('textarea',{rows:'3',placeholder:L.yourmsg});
      const go=h('button',{type:'button',class:'btn fill',style:'width:100%',onclick:()=>{
        const t='Hi '+(c.name||'')+', this is '+(nm.value.trim()||'a visitor')+'. '+ms.value.trim();
        window.location.href='https://wa.me/'+wa+'?text='+encodeURIComponent(t);
      }},L.send);
      wrap.append(h('section',{class:'form'},h('h2',{},L.enquiry),nm,ms,go));
    }

    wrap.append(h('footer',{},c.hide_branding?null:h('a',{href:'/'},'Made with '+SITE.brand)));
    $app.replaceChildren(wrap);
    document.documentElement.lang=lang;
  }
  draw();
}


if(C){renderClient(C,SLUG);}else{location.replace('/');}
<\/script>
</body>
</html>
`;

// src/page.js
var esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
var BOT = /bot|crawl|spider|preview|facebookexternalhit|whatsapp|telegram|slack|curl|wget|headless|monitor/i;
var unavailable = () => new Response(
  '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Page unavailable</title><body style="font:16px/1.6 system-ui,sans-serif;max-width:420px;margin:18vh auto;padding:0 22px;color:#0e2233"><h1 style="font-size:24px;margin:0 0 8px">This page is not available right now</h1><p style="color:#586a78">Please contact the owner for an updated link.</p></body>',
  { status: 200, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } }
);
async function handlePage(ctx) {
  const { request, env, params, next } = ctx;
  const slug = String(params.slug || "").toLowerCase();
  if (!SLUG_RE.test(slug) || RESERVED.has(slug) || !env.DB) return next();
  let row;
  try {
    row = await env.DB.prepare("SELECT data,status FROM clients WHERE slug=?").bind(slug).first();
  } catch (e) {
    return next();
  }
  if (!row) return next();
  const authed = await isAuthed(request, env);
  if (row.status !== "live" && !authed) return unavailable();
  const url = new URL(request.url);
  const ua = request.headers.get("user-agent") || "";
  if (!authed && !BOT.test(ua) && url.searchParams.get("p") !== "1") {
    const s = url.searchParams.get("s");
    const src = s === "n" || s === "q" ? s : "o";
    ctx.waitUntil(env.DB.prepare("INSERT INTO views(slug,day,src,n) VALUES(?,?,?,1) ON CONFLICT(slug,day,src) DO UPDATE SET n=n+1").bind(slug, dayStr(), src).run().catch(() => {
    }));
  }
  let data;
  try {
    data = JSON.parse(row.data);
  } catch (e) {
    return next();
  }
  const tpl = template_default;
  const title = (data.name || "Profile") + (data.title ? " | " + data.title : "");
  const desc = data.tagline || data.about || data.title || "";
  const imgPath = data.photo || data.cover;
  const img = imgPath ? new URL(imgPath, url.origin).href : "";
  const meta = `<title>${esc(title)}</title><meta name="description" content="${esc(String(desc).slice(0, 180))}"><meta property="og:title" content="${esc(title)}"><meta property="og:description" content="${esc(String(desc).slice(0, 180))}"><meta property="og:type" content="website"><meta property="og:url" content="${esc(url.origin + "/" + slug)}">` + (img ? `<meta property="og:image" content="${esc(img)}">` : "") + `<meta name="twitter:card" content="summary">`;
  const dataJson = JSON.stringify(data).replace(/</g, "\\u003c").replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");
  const html2 = tpl.replace("<!--__META__-->", () => meta).replace("/*__DATA__*/null", () => dataJson).replace("__SLUG__", () => slug);
  return new Response(html2, { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" } });
}

// public/index.html
var public_default = `<!DOCTYPE html>
<html lang="en" data-theme="marine">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>CardKart | Tap the card, your whole business opens</title>
<meta name="description" content="Smart NFC and QR cards that open a professional page: call, WhatsApp, directions, offers and more.">
<meta name="theme-color" content="#0b7a75">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Crect width='100' height='100' rx='22' fill='%230b7a75'/%3E%3Cpath d='M28 38h44M28 50h30M28 62h18' stroke='white' stroke-width='8' stroke-linecap='round'/%3E%3C/svg%3E">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:wght@600;700&family=Figtree:wght@400;500;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#f2f5f7;--surface:#fff;--ink:#0e2233;--muted:#586a78;--line:#d9e1e7;
  --accent:#0b7a75;--accent-ink:#fff;--r:14px;--wa:#1a9d52;
  --display:"Bricolage Grotesque","Figtree",system-ui,sans-serif;
  --body:"Figtree",system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
}
[data-theme=gulmohar]{--bg:#fff6f9;--surface:#fff;--ink:#2b1021;--muted:#7a5a6c;--line:#f0d6e1;--accent:#c4205a;--accent-ink:#fff;--r:18px;--display:"Fraunces",Georgia,serif}
[data-theme=slate]{--bg:#fff;--surface:#f5f6f8;--ink:#111827;--muted:#5b6472;--line:#e3e6eb;--accent:#2d4bff;--accent-ink:#fff;--r:10px;--display:"Manrope",system-ui,sans-serif}

*{box-sizing:border-box;margin:0;padding:0}
html{-webkit-text-size-adjust:100%}
body{font:400 16px/1.55 var(--body);background:var(--bg);color:var(--ink);-webkit-font-smoothing:antialiased}
a{color:inherit}
.wrap{max-width:480px;margin:0 auto;min-height:100vh;background:var(--bg)}
@media(min-width:520px){body{background:color-mix(in srgb,var(--ink) 7%,var(--bg))}.wrap{box-shadow:0 0 0 1px var(--line)}}
:focus-visible{outline:3px solid color-mix(in srgb,var(--accent) 55%,transparent);outline-offset:2px}

/* top block */
.top{position:relative;background:var(--accent);color:var(--accent-ink);padding:max(18px,env(safe-area-inset-top)) 22px 28px;background-size:cover;background-position:center}
.top.hascover{color:#fff}
.langs{display:flex;justify-content:flex-end;gap:14px;font-size:14px}
.langs button{background:none;border:0;color:inherit;font:inherit;opacity:.7;cursor:pointer;padding:4px 0}
.langs button.on{opacity:1;font-weight:700;text-decoration:underline;text-underline-offset:4px}
.av{width:84px;height:84px;border-radius:24px;background:color-mix(in srgb,currentColor 16%,transparent);display:grid;place-items:center;font:700 30px var(--display);overflow:hidden;margin:20px 0 16px}
.av img{width:100%;height:100%;object-fit:cover;display:block}
h1{font:700 32px/1.1 var(--display);letter-spacing:-.01em}
.role{margin-top:6px;font-weight:500;opacity:.92}
.tag{margin-top:10px;opacity:.85;max-width:34ch}

/* actions */
.acts{padding:18px 18px 0;display:grid;gap:10px}
.pair{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.pair.one{grid-template-columns:1fr}
.btn{display:flex;align-items:center;justify-content:center;gap:10px;min-height:52px;padding:0 16px;border-radius:var(--r);font:700 16px var(--body);text-decoration:none;border:1.5px solid transparent;cursor:pointer;transition:transform .08s}
.btn:active{transform:scale(.98)}
.btn.fill{background:var(--accent);color:var(--accent-ink)}
.btn.line{background:var(--surface);border-color:var(--line);color:var(--ink)}
.btn.line .wa{color:var(--wa)}
.btn.inv{background:#fff;color:#0e2233}
.btn.ghost{background:transparent;border-color:rgba(255,255,255,.55);color:inherit}
.row{display:flex;align-items:center;gap:14px;width:100%;min-height:56px;padding:0 2px;background:none;border:0;border-bottom:1px solid var(--line);color:inherit;font:500 16px var(--body);text-decoration:none;text-align:left;cursor:pointer}
.row .ic{width:36px;height:36px;border-radius:10px;display:grid;place-items:center;background:color-mix(in srgb,var(--accent) 12%,var(--surface));color:var(--accent);flex:none}
.row .go{margin-left:auto;opacity:.4;display:flex}

/* sections */
section{padding:28px 22px 0}
h2{font:700 20px/1.2 var(--display);margin-bottom:12px}
.about{white-space:pre-line;max-width:60ch}
.meta{margin-top:12px;color:var(--muted);font-size:15px}
.offer{margin:20px 18px 0;padding:14px 16px;border-left:5px solid var(--accent);background:color-mix(in srgb,var(--accent) 10%,var(--surface));border-radius:0 var(--r) var(--r) 0;font-weight:500}
.svc{display:flex;align-items:baseline;gap:8px;padding:9px 0 3px}
.svc .n{font-weight:700}
.svc .dots{flex:1;border-bottom:2px dotted var(--line);transform:translateY(-4px)}
.svc .p{font-weight:700;font-variant-numeric:tabular-nums}
.svc-d{color:var(--muted);font-size:14px;max-width:44ch}
.gal{display:grid;grid-template-columns:1fr 1fr;gap:6px}
.gal img{width:100%;aspect-ratio:1;object-fit:cover;border-radius:calc(var(--r) - 6px);cursor:zoom-in;background:var(--line);display:block}
.gal img:first-child{grid-column:span 2;aspect-ratio:16/10}
.lnk{display:inline-block;margin:0 16px 8px 0;font-weight:700;color:var(--accent);text-underline-offset:3px}
.form input,.form textarea{width:100%;font:inherit;padding:12px 14px;border:1.5px solid var(--line);border-radius:var(--r);background:var(--surface);color:var(--ink);margin-bottom:10px}
footer{padding:36px 22px max(28px,env(safe-area-inset-bottom));color:var(--muted);font-size:14px}
.lb{position:fixed;inset:0;background:rgba(0,0,0,.88);display:grid;place-items:center;z-index:9;padding:16px;cursor:zoom-out}
.lb img{max-width:100%;max-height:100%;border-radius:8px}
.toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%);background:var(--ink);color:var(--bg);padding:10px 16px;border-radius:999px;font-size:14px;z-index:10}

/* landing */
.hero h1{font-size:38px;max-width:14ch}
.hero p{margin-top:14px;max-width:34ch;opacity:.92;font-size:17px}
.hero .btns{display:grid;gap:10px;margin-top:26px}
.steps{list-style:none;counter-reset:s}
.steps li{counter-increment:s;display:flex;gap:14px;padding:12px 0;border-bottom:1px solid var(--line)}
.steps li::before{content:counter(s);flex:none;width:28px;height:28px;border-radius:50%;background:var(--accent);color:var(--accent-ink);display:grid;place-items:center;font-weight:700;font-size:14px}
.pk{padding:14px 0;border-bottom:1px solid var(--line)}
.pk .top-r{display:flex;align-items:baseline;gap:8px}
.pk .nm{font:700 18px var(--display)}
.pk .pr{font:700 18px var(--display)}
.pk .dots{flex:1;border-bottom:2px dotted var(--line);transform:translateY(-4px)}
.pk ul{margin:6px 0 0 18px;color:var(--muted);font-size:15px}
.pk .flag{font-size:13px;font-weight:700;color:var(--accent);margin-left:4px}
.center{text-align:center}
</style>
</head>
<body>
<div id="app"></div>
<script>
const IC={chat:'<path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/>'};
function svg(n){const t=document.createElement('span');t.innerHTML='<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'+IC[n]+'</svg>';return t.firstChild;}
function h(tag,attrs,...kids){
  const e=document.createElement(tag);
  for(const k in (attrs||{})){const v=attrs[k];if(v==null||v===false)continue;if(k==='class')e.className=v;else e.setAttribute(k,v===true?'':v);}
  for(const c of kids.flat()){if(c==null||c===false)continue;e.append(typeof c==='object'?c:document.createTextNode(String(c)));}
  return e;
}
const rupee=n=>'\u20B9'+Number(n).toLocaleString('en-IN');

function render(S){
  const wa=String(S.whatsapp||'').replace(/\\D/g,'');
  const waLink=wa?'https://wa.me/'+(wa.length===10?'91'+wa:wa)+'?text='+encodeURIComponent('Hi, I want a CardKart smart card for my business.'):'';
  const top=h('div',{class:'top hero'},
    h('p',{style:'font-weight:700;font-family:var(--display);font-size:18px'},'CardKart'),
    h('div',{style:'height:34px'}),
    h('h1',{},'Tap the card. Your whole business opens.'),
    h('p',{},'A smart card with a QR on it. Customers tap or scan and land on your page: call, WhatsApp, directions, offers. Change anything later without reprinting.'),
    h('div',{class:'btns'},
      h('a',{class:'btn inv',href:'/demo'},'See a live example'),
      waLink?h('a',{class:'btn ghost',href:waLink},svg('chat'),'Order on WhatsApp'):null
    )
  );
  const how=h('section',{},h('h2',{},'How it works'),
    h('ol',{class:'steps'},
      h('li',{},'We build your page and write its link onto an NFC card. The same link is printed as a QR.'),
      h('li',{},'A customer taps the card on their phone. If their phone has no NFC, they scan the QR.'),
      h('li',{},'Your page opens. When your number, menu or offer changes, message us and it is updated. The card stays the same.')
    ));
  const prices=h('section',{},h('h2',{},'Plans'),(S.packages||[]).map(p=>h('div',{class:'pk'},
    h('div',{class:'top-r'},h('span',{class:'nm'},p.name),p.flag?h('span',{class:'flag'},p.flag):null,h('span',{class:'dots'}),h('span',{class:'pr'},rupee(p.price))),
    h('ul',{},(p.points||[]).map(x=>h('li',{},x)))
  )));
  const cta=h('section',{class:'center'},
    h('h2',{},'Want one for your business?'),
    waLink?h('a',{class:'btn fill',href:waLink},svg('chat'),'Message us on WhatsApp'):null,
    S.instagram?h('p',{class:'meta'},h('a',{href:'https://instagram.com/'+S.instagram,target:'_blank',rel:'noopener'},'@'+S.instagram)):null
  );
  document.getElementById('app').replaceChildren(h('div',{class:'wrap'},top,how,prices,cta,h('footer',{class:'center'},'CardKart')));
}
fetch('/api/site').then(r=>r.json()).then(render).catch(()=>render({packages:[]}));
<\/script>
</body>
</html>
`;

// public/admin.html
var admin_default = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>CardKart Studio</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Crect width='100' height='100' rx='22' fill='%230b7a75'/%3E%3Cpath d='M28 38h44M28 50h30M28 62h18' stroke='white' stroke-width='8' stroke-linecap='round'/%3E%3C/svg%3E">
<style>
:root{--bg:#f2f5f7;--surface:#fff;--ink:#0e2233;--muted:#586a78;--line:#d9e1e7;--accent:#0b7a75;--danger:#b3261e;--r:12px}
*{box-sizing:border-box;margin:0;padding:0}
body{font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--ink);-webkit-font-smoothing:antialiased}
a{color:var(--accent)}
button{font:inherit;cursor:pointer}
.bar{background:var(--ink);color:#fff;position:sticky;top:0;z-index:5}
.bar .in{max-width:900px;margin:0 auto;padding:12px 16px;display:flex;align-items:center;gap:14px}
.bar b{font-size:18px;letter-spacing:-.01em}
.bar .sp{flex:1}
.bar a,.bar button{color:#fff;background:none;border:0;font-size:15px;text-decoration:none;opacity:.85}
main{max-width:900px;margin:0 auto;padding:18px 16px 110px}
h1{font-size:24px;margin:4px 0 14px;letter-spacing:-.01em}
h2{font-size:18px;margin:26px 0 10px}
h3{font-size:15px;margin:18px 0 6px}
.muted{color:var(--muted)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;min-height:44px;padding:0 18px;border-radius:var(--r);border:1.5px solid transparent;font-weight:700;background:var(--accent);color:#fff;text-decoration:none}
.btn.alt{background:var(--surface);color:var(--ink);border-color:var(--line)}
.btn.danger{background:#fff;color:var(--danger);border-color:#e8c4c1}
.btn.sm{min-height:36px;padding:0 12px;font-size:14px}
.btn:disabled{opacity:.5;cursor:default}
.card{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:16px}
.grid{display:grid;gap:12px}
.g2{grid-template-columns:1fr 1fr}.g3{grid-template-columns:repeat(3,1fr)}
@media(max-width:620px){.g2{grid-template-columns:1fr}}
label.f{display:block;margin-top:12px}
label.f>span{display:block;font-weight:600;font-size:14px;margin-bottom:4px}
label.f>small{display:block;color:var(--muted);font-size:13px;margin:-2px 0 4px}
input,textarea,select{width:100%;font:inherit;padding:10px 12px;border:1.5px solid var(--line);border-radius:10px;background:#fff;color:inherit}
input[type=checkbox]{width:20px;height:20px;flex:none}
input[type=color]{padding:2px;height:42px}
textarea{min-height:84px;resize:vertical}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:16px}
@media(max-width:620px){.kpis{grid-template-columns:1fr 1fr}}
.kpi{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:12px 14px}
.kpi b{display:block;font-size:22px;letter-spacing:-.01em}
.kpi span{color:var(--muted);font-size:13px}
.row{display:flex;align-items:center;gap:12px;padding:14px;border-bottom:1px solid var(--line);cursor:pointer;background:var(--surface)}
.row:first-child{border-radius:14px 14px 0 0}.row:last-child{border-bottom:0;border-radius:0 0 14px 14px}.row:only-child{border-radius:14px}
.row:hover{background:#fafcfd}
.row .t{flex:1;min-width:0}
.row .t b{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.row .t span{color:var(--muted);font-size:14px}
.row .r{text-align:right;font-size:14px;color:var(--muted);white-space:nowrap}
.badge{display:inline-block;font-size:12px;font-weight:700;padding:2px 9px;border-radius:99px;background:#e6eef3;color:#2d4558}
.badge.live{background:#d9f2e3;color:#13683a}.badge.draft{background:#fdeccd;color:#8a5a00}.badge.paused{background:#f5d9d7;color:#8c1f18}
.chips{display:flex;gap:8px;overflow-x:auto;padding:2px 0 10px}
.chip{flex:none;border:1.5px solid var(--line);background:#fff;border-radius:99px;padding:6px 14px;font-size:14px;font-weight:600;color:var(--ink)}
.chip.on{background:var(--ink);color:#fff;border-color:var(--ink)}
.tabs{display:flex;gap:4px;border-bottom:1.5px solid var(--line);margin:6px 0 4px;overflow-x:auto}
.tab{flex:none;background:none;border:0;padding:10px 14px;font-weight:700;color:var(--muted);border-bottom:3px solid transparent;margin-bottom:-1.5px}
.tab.on{color:var(--ink);border-color:var(--accent)}
.savebar{position:fixed;left:0;right:0;bottom:0;background:#fff;border-top:1px solid var(--line);padding:10px 16px calc(10px + env(safe-area-inset-bottom));z-index:6}
.savebar .in{max-width:900px;margin:0 auto;display:flex;gap:10px;align-items:center}
.savebar .msg{flex:1;font-size:14px;color:var(--muted)}
.check{display:flex;gap:12px;align-items:flex-start;padding:9px 0;border-bottom:1px solid var(--line)}
.check:last-child{border:0}
.check label{flex:1;cursor:pointer}
.prog{height:8px;background:#e3eaef;border-radius:9px;overflow:hidden;margin:6px 0 4px}
.prog i{display:block;height:100%;background:var(--accent)}
.li{display:grid;gap:8px;padding:12px;border:1px solid var(--line);border-radius:12px;margin-bottom:8px;background:#fafcfd}
.li .rm{justify-self:end}
.thumbs{display:grid;grid-template-columns:repeat(auto-fill,minmax(110px,1fr));gap:10px;margin-top:10px}
.thumb{position:relative;aspect-ratio:1;border-radius:10px;overflow:hidden;background:var(--line)}
.thumb img{width:100%;height:100%;object-fit:cover;display:block}
.thumb button{position:absolute;top:6px;right:6px;width:28px;height:28px;border-radius:50%;border:0;background:rgba(0,0,0,.7);color:#fff;font-size:16px;line-height:1}
pre.msg{white-space:pre-wrap;word-break:break-word;background:#f6f9fb;border:1px solid var(--line);border-radius:12px;padding:12px;font:14px/1.5 system-ui,sans-serif;max-height:300px;overflow:auto}
.qrbox img{width:200px;height:200px;border:1px solid var(--line);border-radius:12px;display:block}
iframe{width:100%;height:560px;border:1px solid var(--line);border-radius:14px;background:#fff}
.bars{display:flex;align-items:flex-end;gap:3px;height:80px;margin-top:10px}
.bars i{flex:1;background:var(--accent);border-radius:3px 3px 0 0;min-height:2px;opacity:.85}
.login{max-width:360px;margin:16vh auto;padding:0 18px}
.err{color:var(--danger);font-weight:600;margin-top:10px}
.ok{color:#13683a;font-weight:600}
.row2{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}
.toast{position:fixed;left:50%;bottom:90px;transform:translateX(-50%);background:var(--ink);color:#fff;padding:10px 16px;border-radius:99px;font-size:14px;z-index:20}
</style>
</head>
<body>
<div id="root"></div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"><\/script>
<script>
/* ================= helpers ================= */
const root=document.getElementById('root');
function h(tag,attrs,...kids){
  const e=document.createElement(tag);
  for(const k in (attrs||{})){
    const v=attrs[k];
    if(v==null||v===false)continue;
    if(k==='class')e.className=v;
    else if(k.slice(0,2)==='on')e.addEventListener(k.slice(2),v);
    else e.setAttribute(k,v===true?'':v);
  }
  for(const c of kids.flat()){
    if(c==null||c===false)continue;
    e.append(typeof c==='object'?c:document.createTextNode(String(c)));
  }
  return e;
}
const inr=n=>'\u20B9'+(Number(n)||0).toLocaleString('en-IN');
const slugify=s=>String(s||'').toLowerCase().replace(/['\u2019\`]/g,'').replace(/&/g,' and ').replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,'').slice(0,40);
function toast(m){const t=h('div',{class:'toast'},m);document.body.append(t);setTimeout(()=>t.remove(),2200);}
async function api(path,opts){
  opts=opts||{};
  const r=await fetch('/api'+path,{method:opts.method||'GET',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:opts.body?JSON.stringify(opts.body):undefined});
  const j=await r.json().catch(()=>({}));
  if(r.status===401&&path!=='/login'){showLogin();throw new Error('Please log in');}
  if(!r.ok)throw new Error(j.error||('Error '+r.status));
  return j;
}
async function copy(text,label){try{await navigator.clipboard.writeText(text);toast(label||'Copied');}catch(e){prompt('Copy this:',text);}}

/* ================= constants ================= */
const STAGES=[['confirmed','Order confirmed'],['collecting','Collecting details'],['building','Building page'],['approval','Sent for approval'],['live','Live'],['delivered','Card delivered']];
const CHECK=[
 {g:'Must have',items:[
  ['name','Name or business name to show on the page'],
  ['role','What they do, in a few words (job title or business type)'],
  ['phone','Phone number for the Call button'],
  ['whatsapp','WhatsApp number (if different from the phone number)'],
  ['logo','Logo or profile photo (clear and square works best)'],
  ['about','2 to 4 lines about the business, in the owner\\'s own words']]},
 {g:'Makes the page look professional',items:[
  ['photos','4 to 8 good photos of their work, shop or products'],
  ['services','List of services or products with prices (up to 10)'],
  ['address','Full address and the Google Maps location link'],
  ['hours','Opening hours and weekly off day'],
  ['social','Instagram, Facebook, YouTube or website links'],
  ['colors','Brand colour (or the logo, and we will match it)']]},
 {g:'Extra features',items:[
  ['review','Google review link'],
  ['upi','UPI ID for the Pay button'],
  ['offer','Current offer with its last date (optional)'],
  ['testimonials','2 or 3 happy customer quotes with first names'],
  ['languages','Hindi or Marathi version needed? If yes, send the text']]},
 {g:'Admin',items:[
  ['consent','Permission to publish their number, photos and details'],
  ['advance','Advance payment received'],
  ['delivery','Where and when to deliver the card'],
  ['approve','They have seen the draft page and approved it']]}
];
const ADMIN_ONLY=new Set(['advance','approve','consent','delivery']);

/* ================= state ================= */
let SITE={packages:[]};
let LIST=[];
let CUR=null;       // {slug,isNew,status,data,meta,created}
let TAB='order';
let dirty=false;
window.addEventListener('beforeunload',e=>{if(dirty){e.preventDefault();e.returnValue='';}});

/* ================= login ================= */
async function showLogin(note){
  let health={ok:true,missing:[]};
  try{health=await (await fetch('/api/health')).json();}catch(e){}
  const pw=h('input',{type:'password',placeholder:'Admin password',autocomplete:'current-password'});
  const err=h('p',{class:'err'});
  const go=async()=>{
    err.textContent='';
    try{await api('/login',{method:'POST',body:{password:pw.value}});start();}
    catch(e){err.textContent=e.message;}
  };
  pw.addEventListener('keydown',e=>{if(e.key==='Enter')go();});
  root.replaceChildren(h('div',{class:'login'},
    h('h1',{},'CardKart Studio'),
    h('p',{class:'muted',style:'margin-bottom:16px'},'Sign in to manage your clients.'),
    !health.ok?h('div',{class:'card',style:'margin-bottom:14px;border-color:#e8c4c1'},h('b',{},'Setup is not finished yet'),h('p',{class:'muted'},'Missing: '+health.missing.join(', ')+'. Follow the setup steps, then reload.')):null,
    pw,h('div',{style:'height:10px'}),h('button',{class:'btn',style:'width:100%',onclick:go},'Sign in'),err));
  setTimeout(()=>pw.focus(),50);
}

/* ================= layout ================= */
function shell(content,opts){
  opts=opts||{};
  root.replaceChildren(
    h('div',{class:'bar'},h('div',{class:'in'},
      h('b',{},'CardKart Studio'),h('span',{class:'sp'}),
      h('a',{href:'#/'},'Clients'),h('a',{href:'#/settings'},'Settings'),
      h('button',{onclick:async()=>{await api('/logout',{method:'POST'});showLogin();}},'Log out'))),
    h('main',{},content),
    opts.savebar||null);
  window.scrollTo(0,0);
}
function go(hash){if(dirty&&!confirm('You have unsaved changes. Leave without saving?'))return;dirty=false;location.hash=hash;}

/* ================= list ================= */
let FILTER='all',QUERY='';
function drawList(){
  const live=LIST.filter(c=>c.status==='live').length;
  const total=LIST.reduce((s,c)=>s+(+c.meta.price||0),0);
  const paid=LIST.reduce((s,c)=>s+(+c.meta.paid||0),0);
  const rows=LIST.filter(c=>(FILTER==='all'||(FILTER==='due'?((+c.meta.price||0)-(+c.meta.paid||0))>0:c.meta.stage===FILTER))&&(!QUERY||(c.name+' '+c.slug+' '+(c.meta.contact||'')).toLowerCase().includes(QUERY.toLowerCase())));
  const search=h('input',{type:'search',placeholder:'Search clients',value:QUERY});
  search.addEventListener('input',()=>{QUERY=search.value;drawList();setTimeout(()=>{const s=document.querySelector('input[type=search]');s&&(s.focus(),s.setSelectionRange(99,99));},0);});
  const chips=[['all','All'],['due','Balance due']].concat(STAGES).map(([k,l])=>h('button',{class:'chip'+(FILTER===k?' on':''),onclick:()=>{FILTER=k;drawList();}},l));
  shell([
    h('div',{style:'display:flex;align-items:center;gap:12px'},h('h1',{style:'flex:1;margin:0'},'Clients'),h('a',{class:'btn',href:'#/new'},'New order')),
    h('div',{class:'kpis',style:'margin-top:14px'},
      h('div',{class:'kpi'},h('b',{},LIST.length),h('span',{},'Clients')),
      h('div',{class:'kpi'},h('b',{},live),h('span',{},'Pages live')),
      h('div',{class:'kpi'},h('b',{},inr(paid)),h('span',{},'Collected')),
      h('div',{class:'kpi'},h('b',{},inr(total-paid)),h('span',{},'Balance due'))),
    search,h('div',{style:'height:10px'}),h('div',{class:'chips'},chips),
    rows.length?h('div',{},rows.map(c=>{
      const due=(+c.meta.price||0)-(+c.meta.paid||0);
      const st=(STAGES.find(s=>s[0]===c.meta.stage)||[0,'New'])[1];
      return h('div',{class:'row',onclick:()=>go('#/c/'+c.slug)},
        h('div',{class:'t'},h('b',{},c.name||c.slug),h('span',{},'/'+c.slug+' \xB7 '+(c.meta.package||'No package')+' \xB7 '+st)),
        h('div',{class:'r'},h('span',{class:'badge '+c.status},c.status),h('div',{},c.views30+' visits'),due>0?h('div',{style:'color:#8a5a00;font-weight:700'},inr(due)+' due'):null));
    })):h('div',{class:'card muted'},LIST.length?'No clients match.':'No clients yet. Tap New order when your first customer confirms.')
  ]);
}
async function showList(){
  try{LIST=await api('/clients');}catch(e){if(e.message!=='Please log in')toast(e.message);return;}
  drawList();
}

/* ================= new order ================= */
function showNew(){
  const o={business:'',contact:'',phone:'',pkg:(SITE.packages[1]||SITE.packages[0]||{}).name||'',price:'',paid:'',slug:''};
  let slugTouched=false;
  const pkgSel=h('select',{});
  SITE.packages.forEach(p=>pkgSel.append(h('option',{value:p.name},p.name+' ('+inr(p.price)+')')));
  pkgSel.append(h('option',{value:'Custom'},'Custom'));
  pkgSel.value=o.pkg||'Custom';
  const priceIn=h('input',{type:'number',inputmode:'numeric'});
  const setPrice=()=>{const p=SITE.packages.find(x=>x.name===pkgSel.value);priceIn.value=p?p.price:'';};
  pkgSel.addEventListener('change',setPrice);setPrice();
  const slugIn=h('input',{placeholder:'auto from business name'});
  slugIn.addEventListener('input',()=>{slugTouched=true;});
  const biz=h('input',{placeholder:'e.g. Aisha\\'s Glow Studio'});
  biz.addEventListener('input',()=>{if(!slugTouched)slugIn.value=slugify(biz.value);});
  const contact=h('input',{placeholder:'Person who ordered'});
  const phone=h('input',{type:'tel',placeholder:'10-digit mobile',inputmode:'numeric'});
  const paid=h('input',{type:'number',inputmode:'numeric',placeholder:'0'});
  const err=h('p',{class:'err'});
  const create=async()=>{
    err.textContent='';
    const slug=slugify(slugIn.value||biz.value);
    if(!biz.value.trim()||!slug){err.textContent='Enter the business or person name.';return;}
    const meta={contact:contact.value.trim(),contactPhone:phone.value.replace(/\\D/g,''),package:pkgSel.value,price:+priceIn.value||0,paid:+paid.value||0,stage:'confirmed',checklist:{},notes:''};
    if(meta.paid>0)meta.checklist.advance=true;
    const data={name:biz.value.trim(),theme:'marine'};
    if(phone.value.replace(/\\D/g,'').length>=10)data.phone=phone.value.replace(/\\D/g,'');
    try{await api('/clients/'+slug,{method:'PUT',body:{create:true,data,meta,status:'draft'}});TAB='order';location.hash='#/c/'+slug;}
    catch(e){err.textContent=e.message;}
  };
  shell([
    h('a',{href:'#/'},'Back to clients'),h('h1',{style:'margin-top:8px'},'New order'),
    h('p',{class:'muted',style:'margin-bottom:6px'},'Create it when the customer says yes. You will get the list of things to collect on the next screen.'),
    h('div',{class:'card'},
      h('label',{class:'f'},h('span',{},'Business or person name'),biz),
      h('label',{class:'f'},h('span',{},'Page link'),h('small',{},'Becomes yourdomain/this-name. It cannot be changed later because cards carry it.'),slugIn),
      h('div',{class:'grid g2'},
        h('label',{class:'f'},h('span',{},'Who ordered'),contact),
        h('label',{class:'f'},h('span',{},'Their WhatsApp number'),phone)),
      h('div',{class:'grid g3'},
        h('label',{class:'f'},h('span',{},'Package'),pkgSel),
        h('label',{class:'f'},h('span',{},'Price (\u20B9)'),priceIn),
        h('label',{class:'f'},h('span',{},'Advance paid (\u20B9)'),paid)),
      err,
      h('div',{class:'row2'},h('button',{class:'btn',onclick:create},'Create order')))
  ]);
}

/* ================= editor ================= */
function inp(label,obj,key,o){
  o=o||{};
  const el=o.area?h('textarea',{rows:o.rows||3,placeholder:o.ph||''}):h('input',{type:o.type||'text',placeholder:o.ph||'',inputmode:o.mode||null});
  el.value=obj[key]==null?'':obj[key];
  el.addEventListener('input',()=>{obj[key]=o.num?(el.value===''?'':Number(el.value)):el.value;dirty=true;if(o.on)o.on(el.value);});
  return h('label',{class:'f'},h('span',{},label),o.hint?h('small',{},o.hint):null,el);
}
function listEditor(title,hint,arr,fields,blank){
  const box=h('div',{});
  const draw=()=>{
    box.replaceChildren(
      ...arr.map((it,i)=>h('div',{class:'li'},
        ...fields.map(f=>inp(f.label,it,f.key,{area:f.area,rows:2,ph:f.ph})),
        h('button',{class:'btn danger sm rm',onclick:()=>{arr.splice(i,1);dirty=true;draw();}},'Remove'))),
      h('button',{class:'btn alt sm',onclick:()=>{arr.push(Object.assign({},blank));dirty=true;draw();}},'+ Add')
    );
  };
  draw();
  return h('div',{},h('h3',{},title),hint?h('p',{class:'muted',style:'font-size:14px;margin-bottom:8px'},hint):null,box);
}

function clientUrl(){return location.origin+'/'+CUR.slug;}

function checklistBlock(){
  const m=CUR.meta;m.checklist=m.checklist||{};
  const all=CHECK.flatMap(g=>g.items);
  const done=()=>all.filter(i=>m.checklist[i[0]]).length;
  const prog=h('div',{class:'prog'},h('i',{style:'width:0'}));
  const label=h('span',{class:'muted',style:'font-size:14px'});
  const upd=()=>{prog.firstChild.style.width=(100*done()/all.length)+'%';label.textContent=done()+' of '+all.length+' collected';};
  const groups=CHECK.map(g=>h('div',{},h('h3',{},g.g),...g.items.map(([id,text])=>{
    const cb=h('input',{type:'checkbox',id:'ck-'+id});cb.checked=!!m.checklist[id];
    cb.addEventListener('change',()=>{m.checklist[id]=cb.checked;dirty=true;upd();});
    return h('div',{class:'check'},cb,h('label',{for:'ck-'+id},text));
  })));
  upd();
  return h('div',{class:'card'},h('h2',{style:'margin-top:0'},'What to collect from this client'),label,prog,groups);
}
function waMessage(){
  const m=CUR.meta;m.checklist=m.checklist||{};
  const missing=CHECK.flatMap(g=>g.items).filter(i=>!m.checklist[i[0]]&&!ADMIN_ONLY.has(i[0]));
  const first=m.contact?m.contact.split(' ')[0]:(CUR.data.name||'there');
  const lines=missing.map((i,n)=>(n+1)+'. '+i[1]);
  return 'Hi '+first+'! Thank you for choosing CardKart. Your '+(m.package||'')+' order ('+inr(m.price)+') is confirmed.\\n\\n'+
    (lines.length?'To build your page, please send me these on WhatsApp:\\n'+lines.join('\\n')+'\\n\\nPhotos are best sent as normal images, not screenshots.':'I have everything I need. Your page will be ready soon.')+
    '\\n\\nOnce I have everything, I will send you a link to check your page before your card is made.';
}

function orderTab(){
  const m=CUR.meta;
  const bal=h('b',{});const updBal=()=>{bal.textContent=inr((+m.price||0)-(+m.paid||0));};updBal();
  const stage=h('select',{});STAGES.forEach(([k,l])=>stage.append(h('option',{value:k},l)));stage.value=m.stage||'confirmed';
  stage.addEventListener('change',()=>{m.stage=stage.value;dirty=true;});
  const msg=h('pre',{class:'msg'},waMessage());
  const refresh=()=>{msg.textContent=waMessage();};
  const pkgSel=h('select',{});[...SITE.packages.map(p=>p.name),'Custom'].forEach(n=>pkgSel.append(h('option',{value:n},n)));
  pkgSel.value=m.package||'Custom';pkgSel.addEventListener('change',()=>{m.package=pkgSel.value;dirty=true;refresh();});
  const waNum=(m.contactPhone||'').length===10?'91'+m.contactPhone:(m.contactPhone||'');
  return h('div',{},
    h('div',{class:'card',style:'margin-top:14px'},
      h('div',{class:'grid g2'},
        h('label',{class:'f'},h('span',{},'Stage'),stage),
        h('label',{class:'f'},h('span',{},'Package'),pkgSel)),
      h('div',{class:'grid g3'},
        inp('Price (\u20B9)',m,'price',{type:'number',mode:'numeric',num:true,on:()=>{updBal();refresh();}}),
        inp('Paid so far (\u20B9)',m,'paid',{type:'number',mode:'numeric',num:true,on:updBal}),
        h('label',{class:'f'},h('span',{},'Balance due'),h('div',{style:'padding:10px 0;font-size:20px'},bal))),
      h('div',{class:'grid g2'},
        inp('Who ordered',m,'contact',{on:refresh}),
        inp('Their WhatsApp number',m,'contactPhone',{type:'tel',mode:'numeric',on:refresh})),
      inp('Renewal date',m,'renewal',{type:'date',hint:'When their yearly hosting and edits fee is due.'}),
      inp('Private notes',m,'notes',{area:true,rows:3,ph:'Only you can see this'})),
    h('div',{style:'height:14px'}),
    checklistBlock(),
    h('h2',{},'Message to send this client'),
    h('p',{class:'muted',style:'font-size:14px;margin-bottom:8px'},'Lists only what you have not yet collected. Tick items above, press Refresh, and it updates.'),
    msg,
    h('div',{class:'row2'},
      h('button',{class:'btn alt',onclick:refresh},'Refresh message'),
      h('button',{class:'btn',onclick:()=>copy(msg.textContent,'Message copied')},'Copy message'),
      waNum?h('a',{class:'btn alt',target:'_blank',rel:'noopener',onclick:()=>{refresh();},href:'#',onmousedown:e=>{e.currentTarget.href='https://wa.me/'+waNum+'?text='+encodeURIComponent(waMessage());}},'Open in WhatsApp'):null));
}

function detailsTab(){
  const d=CUR.data;
  d.offer=d.offer||{};d.translations=d.translations||{};d.translations.hi=d.translations.hi||{};d.translations.mr=d.translations.mr||{};
  d.services=d.services||[];d.links=d.links||[];d.testimonials=d.testimonials||[];
  const accentOn=h('input',{type:'checkbox'});accentOn.checked=!!d.accent;
  const accent=h('input',{type:'color',value:d.accent||'#0b7a75'});
  accentOn.addEventListener('change',()=>{if(accentOn.checked)d.accent=accent.value;else delete d.accent;dirty=true;});
  accent.addEventListener('input',()=>{accentOn.checked=true;d.accent=accent.value;dirty=true;});
  const theme=h('select',{});[['marine','Marine: clean teal'],['gulmohar','Gulmohar: warm pink'],['slate','Slate: sharp blue']].forEach(([v,l])=>theme.append(h('option',{value:v},l)));
  theme.value=d.theme||'marine';theme.addEventListener('change',()=>{d.theme=theme.value;dirty=true;});
  const brand=h('input',{type:'checkbox'});brand.checked=!!d.hide_branding;brand.addEventListener('change',()=>{d.hide_branding=brand.checked;dirty=true;});
  const enq=h('input',{type:'checkbox'});enq.checked=d.enquiry!==false;enq.addEventListener('change',()=>{d.enquiry=enq.checked;dirty=true;});
  return h('div',{},
    h('h2',{},'Main details'),
    h('div',{class:'card'},
      h('div',{class:'grid g2'},inp('Name shown on page',d,'name'),inp('Business name (saved in contact)',d,'org')),
      inp('What they do',d,'title',{ph:'Hair and makeup salon'}),
      inp('One-line tagline',d,'tagline'),
      inp('About',d,'about',{area:true,rows:4,hint:'2 to 4 short sentences in the owner\\'s own words.'})),
    h('h2',{},'Contact and links'),
    h('div',{class:'card'},
      h('div',{class:'grid g2'},inp('Phone',d,'phone',{type:'tel',mode:'numeric'}),inp('WhatsApp',d,'whatsapp',{type:'tel',mode:'numeric',hint:'Leave empty to use the phone number.'})),
      h('div',{class:'grid g2'},inp('Email',d,'email',{type:'email'}),inp('Website',d,'website',{ph:'https://'})),
      h('div',{class:'grid g2'},inp('Instagram username',d,'instagram'),inp('Google review link',d,'review',{ph:'https://g.page/r/...'})),
      h('div',{class:'grid g2'},inp('UPI ID',d,'upi',{ph:'name@bank'}),inp('Opening hours',d,'hours',{ph:'Mon to Sat, 10am to 8pm'})),
      inp('Address',d,'address'),
      inp('Google Maps link',d,'maps',{hint:'Optional. If empty, the address is used for directions.'})),
    h('h2',{},'Offer banner'),
    h('div',{class:'card'},
      inp('Offer text',d.offer,'text',{ph:'Diwali offer: 20% off until 15 November'}),
      inp('Show until',d.offer,'until',{type:'date',hint:'The banner hides itself after this date.'})),
    h('h2',{},'Lists'),
    h('div',{class:'card'},
      listEditor('Services or products','Shown with prices, like a menu.',d.services,[{label:'Name',key:'name'},{label:'Price',key:'price',ph:'\u20B9300'},{label:'Short description (optional)',key:'desc'}],{name:'',price:'',desc:''}),
      listEditor('Extra links','Brochure, menu PDF, YouTube, anything.',d.links,[{label:'Label',key:'label'},{label:'Link',key:'url',ph:'https://'}],{label:'',url:''}),
      listEditor('Customer testimonials','Real quotes with first names.',d.testimonials,[{label:'Quote',key:'text',area:true},{label:'Name',key:'name'}],{text:'',name:''})),
    h('h2',{},'Look'),
    h('div',{class:'card'},
      h('label',{class:'f'},h('span',{},'Theme'),theme),
      h('div',{style:'display:flex;gap:10px;align-items:center;margin-top:14px'},accentOn,h('span',{style:'font-weight:600'},'Use the client\\'s brand colour'),h('span',{style:'flex:1'}),accent),
      h('div',{style:'display:flex;gap:10px;align-items:center;margin-top:14px'},enq,h('span',{style:'font-weight:600'},'Show the enquiry form')),
      h('div',{style:'display:flex;gap:10px;align-items:center;margin-top:14px'},brand,h('span',{style:'font-weight:600'},'Hide "Made with CardKart" (premium option)'))),
    h('h2',{},'Hindi and Marathi (optional)'),
    h('div',{class:'card'},
      h('div',{class:'grid g2'},
        h('div',{},inp('Hindi tagline',d.translations.hi,'tagline'),inp('Hindi about',d.translations.hi,'about',{area:true}),inp('Hindi offer',d.translations.hi,'offer')),
        h('div',{},inp('Marathi tagline',d.translations.mr,'tagline'),inp('Marathi about',d.translations.mr,'about',{area:true}),inp('Marathi offer',d.translations.mr,'offer')))));
}

/* ---- photos ---- */
function fileToJpeg(file,max,q){
  return new Promise((res,rej)=>{
    const img=new Image();const u=URL.createObjectURL(file);
    img.onload=()=>{
      const s=Math.min(1,max/Math.max(img.naturalWidth,img.naturalHeight));
      const c=document.createElement('canvas');c.width=Math.round(img.naturalWidth*s);c.height=Math.round(img.naturalHeight*s);
      c.getContext('2d').drawImage(img,0,0,c.width,c.height);
      URL.revokeObjectURL(u);res(c.toDataURL('image/jpeg',q));
    };
    img.onerror=()=>{URL.revokeObjectURL(u);rej(new Error('Could not read that image'));};
    img.src=u;
  });
}
async function uploadImage(file,max){
  const dataUrl=await fileToJpeg(file,max,0.82);
  const r=await api('/images',{method:'POST',body:{slug:CUR.slug,dataUrl}});
  return r.url;
}
function dropOld(url){if(url&&url.startsWith('/img/'))api('/images/'+url.slice(5),{method:'DELETE'}).catch(()=>{});}

function photosTab(){
  const d=CUR.data;d.gallery=d.gallery||[];
  const box=h('div',{});
  const draw=()=>{
    const single=(label,key,max,hint)=>{
      const fi=h('input',{type:'file',accept:'image/*',style:'display:none'});
      fi.addEventListener('change',async()=>{
        if(!fi.files[0])return;
        try{toast('Uploading\u2026');const url=await uploadImage(fi.files[0],max);dropOld(d[key]);d[key]=url;dirty=true;toast('Uploaded. Press Save.');draw();}
        catch(e){toast(e.message);}
      });
      return h('div',{class:'card',style:'margin-bottom:12px'},h('b',{},label),h('p',{class:'muted',style:'font-size:14px'},hint),
        d[key]?h('div',{class:'thumbs',style:'grid-template-columns:140px'},h('div',{class:'thumb'},h('img',{src:d[key],alt:''}),h('button',{title:'Remove',onclick:()=>{dropOld(d[key]);delete d[key];dirty=true;draw();}},'\xD7'))):null,
        h('div',{class:'row2'},h('button',{class:'btn alt sm',onclick:()=>fi.click()},d[key]?'Replace':'Choose photo'),fi));
    };
    const gi=h('input',{type:'file',accept:'image/*',multiple:true,style:'display:none'});
    gi.addEventListener('change',async()=>{
      const files=[...gi.files];if(!files.length)return;
      try{
        for(let i=0;i<files.length;i++){toast('Uploading '+(i+1)+' of '+files.length+'\u2026');d.gallery.push(await uploadImage(files[i],1100));}
        dirty=true;toast('Uploaded. Press Save.');draw();
      }catch(e){toast(e.message);}
    });
    box.replaceChildren(
      single('Logo or profile photo','photo',600,'Square or close to square. Shown in the top block.'),
      single('Cover image (optional)','cover',1400,'Wide photo behind the name. Skip it if the photo is not great.'),
      h('div',{class:'card'},h('b',{},'Gallery'),h('p',{class:'muted',style:'font-size:14px'},'4 to 8 sharp photos. The first one is shown large.'),
        h('div',{class:'thumbs'},d.gallery.map((u,i)=>h('div',{class:'thumb'},h('img',{src:u,alt:''}),h('button',{title:'Remove',onclick:()=>{dropOld(u);d.gallery.splice(i,1);dirty=true;draw();}},'\xD7')))),
        h('div',{class:'row2'},h('button',{class:'btn alt sm',onclick:()=>gi.click()},'Add photos'),gi)));
  };
  draw();
  return h('div',{},h('h2',{},'Photos'),h('p',{class:'muted',style:'font-size:14px;margin-bottom:10px'},'Photos are shrunk automatically so pages load fast.'),box);
}

/* ---- share & QR ---- */
function makeQrCanvas(text){
  const tmp=document.createElement('div');
  new QRCode(tmp,{text,width:512,height:512,correctLevel:QRCode.CorrectLevel.H});
  const src=tmp.querySelector('canvas');
  const out=document.createElement('canvas');out.width=out.height=640;
  const x=out.getContext('2d');x.fillStyle='#fff';x.fillRect(0,0,640,640);x.drawImage(src,64,64,512,512);
  return out;
}
function shareTab(){
  const base=clientUrl();
  const nfc=base+'?s=n',qr=base+'?s=q';
  const status=h('select',{});[['draft','Draft (only you can see it)'],['live','Published'],['paused','Paused (shows "not available")']].forEach(([v,l])=>status.append(h('option',{value:v},l)));
  status.value=CUR.status;status.addEventListener('change',()=>{CUR.status=status.value;dirty=true;});
  let qrImg;
  try{const c=makeQrCanvas(qr);qrImg=h('img',{src:c.toDataURL('image/png'),alt:'QR code'});CUR._qr=c;}catch(e){qrImg=h('p',{class:'err'},'The QR library did not load. Check your internet and reload.');}
  const stats=h('div',{class:'card muted'},'Loading visits\u2026');
  api('/stats/'+CUR.slug).then(({rows})=>{
    let n=0,q=0,o=0;const byDay={};
    rows.forEach(r=>{if(r.src==='n')n+=r.n;else if(r.src==='q')q+=r.n;else o+=r.n;byDay[r.day]=(byDay[r.day]||0)+r.n;});
    const days=[];for(let i=29;i>=0;i--){days.push(new Date(Date.now()+5.5*3600e3-i*864e5).toISOString().slice(0,10));}
    const mx=Math.max(1,...days.map(d=>byDay[d]||0));
    stats.className='card';
    stats.replaceChildren(
      h('div',{class:'grid g3'},
        h('div',{class:'kpi'},h('b',{},n),h('span',{},'NFC taps')),
        h('div',{class:'kpi'},h('b',{},q),h('span',{},'QR scans')),
        h('div',{class:'kpi'},h('b',{},o),h('span',{},'Other visits'))),
      h('div',{class:'bars'},days.map(d=>h('i',{title:d+': '+(byDay[d]||0),style:'height:'+Math.max(3,(byDay[d]||0)/mx*100)+'%'}))),
      h('p',{class:'muted',style:'font-size:13px;margin-top:6px'},'Last 30 days. Your own visits while logged in are not counted.'));
  }).catch(()=>{stats.textContent='Visits could not be loaded.';});
  const del=h('button',{class:'btn danger',onclick:async()=>{
    if(prompt('This deletes the page, photos and visit counts permanently. Type the link name to confirm: '+CUR.slug)!==CUR.slug)return;
    try{await api('/clients/'+CUR.slug,{method:'DELETE'});dirty=false;toast('Deleted');location.hash='#/';}catch(e){toast(e.message);}
  }},'Delete this client');
  return h('div',{},
    h('h2',{},'Publish'),
    h('div',{class:'card'},h('label',{class:'f',style:'margin-top:0'},h('span',{},'Page status'),status),
      h('p',{class:'muted',style:'font-size:14px;margin-top:8px'},'Set to Published when the client approves. Set to Paused if they stop paying. Press Save after changing.')),
    h('h2',{},'Links'),
    h('div',{class:'card'},
      h('p',{},h('b',{},'Write this on the NFC card:')),h('p',{style:'word-break:break-all'},nfc),
      h('div',{class:'row2'},h('button',{class:'btn sm',onclick:()=>copy(nfc,'NFC link copied')},'Copy NFC link'),h('a',{class:'btn alt sm',href:'/'+CUR.slug,target:'_blank',rel:'noopener'},'Open page')),
      h('p',{class:'muted',style:'font-size:14px;margin-top:12px'},'Write it with the NFC Tools app: Write, Add a record, URL/URI. Only write cards after your own domain is connected. The link never changes, even when you edit the page.')),
    h('h2',{},'QR code'),
    h('div',{class:'card'},h('div',{class:'qrbox'},qrImg),h('p',{style:'word-break:break-all;margin-top:10px;font-size:14px'},qr),
      h('div',{class:'row2'},h('button',{class:'btn sm',onclick:()=>{if(!CUR._qr)return;const a=document.createElement('a');a.href=CUR._qr.toDataURL('image/png');a.download=CUR.slug+'-qr.png';document.body.append(a);a.click();a.remove();}},'Download QR (PNG)')),
      h('p',{class:'muted',style:'font-size:14px;margin-top:10px'},'This QR points to the same page as the NFC card, so editing the page updates both. If you open this dashboard from the pages.dev address, the QR will carry that address. Open it from your own domain before printing.')),
    h('h2',{},'Visits'),stats,
    h('h2',{},'Preview'),
    h('iframe',{src:'/'+CUR.slug+'?p=1',title:'Preview'}),
    h('h2',{},'Danger zone'),h('div',{},del));
}

function cleanData(d){
  const out={};
  Object.keys(d).forEach(k=>{
    let v=d[k];
    if(Array.isArray(v)){v=v.filter(x=>x&&Object.values(x).some(y=>String(y).trim()));if(!v.length)return;}
    else if(v&&typeof v==='object'){const c=cleanData(v);if(!Object.keys(c).length)return;v=c;}
    else if(typeof v==='string'){v=v.trim();if(!v)return;}
    else if(v===undefined||v===null||v==='')return;
    out[k]=v;
  });
  return out;
}

async function showEditor(slug){
  let rec;
  try{rec=await api('/clients/'+slug);}catch(e){toast(e.message);location.hash='#/';return;}
  CUR={slug,status:rec.status,data:rec.data||{},meta:rec.meta||{},created:rec.created};
  dirty=false;drawEditor();
}
function drawEditor(){
  const tabs=[['order','Order and checklist'],['details','Page details'],['photos','Photos'],['share','Publish and QR']];
  const msg=h('span',{class:'msg'},'');
  const save=h('button',{class:'btn',onclick:async()=>{
    save.disabled=true;msg.textContent='Saving\u2026';
    try{
      CUR.data=cleanData(CUR.data);
      CUR.data.enquiry=CUR.data.enquiry; // keep explicit false
      await api('/clients/'+CUR.slug,{method:'PUT',body:{data:CUR.data,meta:CUR.meta,status:CUR.status}});
      dirty=false;msg.textContent='Saved. Changes are live now.';
      const f=document.querySelector('iframe');if(f)f.src=f.src;
    }catch(e){msg.textContent=e.message;msg.className='msg err';}
    save.disabled=false;
  }},'Save');
  const body=TAB==='order'?orderTab():TAB==='details'?detailsTab():TAB==='photos'?photosTab():shareTab();
  shell([
    h('a',{href:'#/',onclick:e=>{if(dirty&&!confirm('You have unsaved changes. Leave without saving?'))e.preventDefault();else dirty=false;}},'Back to clients'),
    h('div',{style:'display:flex;gap:10px;align-items:center;margin-top:8px'},h('h1',{style:'margin:0;flex:1'},CUR.data.name||CUR.slug),h('span',{class:'badge '+CUR.status},CUR.status)),
    h('p',{class:'muted'},'/'+CUR.slug),
    h('div',{class:'tabs'},tabs.map(([k,l])=>h('button',{class:'tab'+(TAB===k?' on':''),onclick:()=>{TAB=k;drawEditor();}},l))),
    body
  ],{savebar:h('div',{class:'savebar'},h('div',{class:'in'},msg,save))});
}

/* ================= settings ================= */
function showSettings(){
  const s=JSON.parse(JSON.stringify(SITE));
  const wa=h('input',{value:s.whatsapp||'',placeholder:'919876543210',inputmode:'numeric'});
  const ig=h('input',{value:s.instagram||'',placeholder:'cardkart'});
  const pk=h('textarea',{rows:10});
  pk.value=(s.packages||[]).map(p=>[p.name,p.price,p.flag||'',(p.points||[]).join('; ')].join(' | ')).join('\\n');
  const msg=h('p',{});
  const save=async()=>{
    const packages=pk.value.split('\\n').map(l=>l.trim()).filter(Boolean).map(l=>{const [name,price,flag,points]=l.split('|').map(x=>(x||'').trim());return {name,price:Number(String(price).replace(/[^\\d.]/g,''))||0,flag:flag||undefined,points:(points||'').split(';').map(x=>x.trim()).filter(Boolean)};});
    try{await api('/site',{method:'PUT',body:{whatsapp:wa.value,instagram:ig.value,packages}});SITE=await api('/site');msg.className='ok';msg.textContent='Saved. Your home page is updated.';}
    catch(e){msg.className='err';msg.textContent=e.message;}
  };
  shell([
    h('h1',{},'Settings'),
    h('div',{class:'card'},
      h('label',{class:'f'},h('span',{},'Your WhatsApp number'),h('small',{},'Country code first, digits only. Shown on your home page.'),wa),
      h('label',{class:'f'},h('span',{},'Your Instagram username'),ig),
      h('label',{class:'f'},h('span',{},'Packages'),h('small',{},'One per line: Name | price | tag (optional) | feature; feature; feature'),pk),
      h('div',{class:'row2'},h('button',{class:'btn',onclick:save},'Save settings')),msg),
    h('p',{class:'muted',style:'margin-top:16px;font-size:14px'},'Your public home page is the main address of your site. Prices here fill the New order form.')
  ]);
}

/* ================= router ================= */
async function route(){
  const hash=location.hash||'#/';
  if(hash==='#/'||hash==='')return showList();
  if(hash==='#/new')return showNew();
  if(hash==='#/settings')return showSettings();
  const m=/^#\\/c\\/([a-z0-9_-]+)$/.exec(hash);
  if(m)return showEditor(m[1]);
  location.hash='#/';
}
window.addEventListener('hashchange',route);
async function start(){
  try{await api('/me');}catch(e){return showLogin();}
  try{SITE=await api('/site');}catch(e){}
  route();
}
start();
<\/script>
</body>
</html>
`;

// public/404.html
var __default = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Page not found</title></head>
<body style="font:16px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;max-width:420px;margin:18vh auto;padding:0 22px;color:#0e2233">
<h1 style="font-size:26px;margin:0 0 8px">This page isn't available</h1>
<p style="color:#586a78">The link may be wrong, or the page was removed. Please ask the owner for the correct link.</p>
<p><a href="/" style="color:#0b7a75;font-weight:700">Go to CardKart</a></p>
</body></html>
`;

// src/index.js
var htmlHeaders = { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" };
var html = (body, status = 200) => new Response(body, { status, headers: htmlHeaders });
var notFound = () => html(__default, 404);
var index_default = {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts.length === 0) return html(public_default);
    if (parts[0] === "api") {
      return handleApi({ request, env, params: { path: parts.slice(1) }, waitUntil: (p) => ctx.waitUntil(p) });
    }
    if (parts[0] === "img" && parts.length === 2 && request.method === "GET") {
      return handleImg({ env, params: { id: parts[1] } });
    }
    if (parts.length === 1 && parts[0].toLowerCase() === "admin") return html(admin_default);
    if (parts.length === 1 && request.method === "GET") {
      return handlePage({ request, env, params: { slug: parts[0] }, waitUntil: (p) => ctx.waitUntil(p), next: notFound });
    }
    return notFound();
  }
};
export {
  index_default as default
};
