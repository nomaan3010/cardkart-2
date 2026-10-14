// Serves client photos stored in the database
export async function onRequestGet({ env, params }) {
  try {
    const id = String(params.id || '').replace(/[^a-z0-9]/gi, '');
    const row = await env.DB.prepare('SELECT mime,b64 FROM images WHERE id=?').bind(id).first();
    if (!row) return new Response('Not found', { status: 404 });
    const bin = atob(row.b64);
    const u8 = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
    return new Response(u8, { headers: { 'Content-Type': row.mime, 'Cache-Control': 'public, max-age=31536000, immutable' } });
  } catch (e) {
    return new Response('Not found', { status: 404 });
  }
}
