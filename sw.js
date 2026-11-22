/* Arbre généalogique – service worker
   Déchiffre l'application (vault/app.bin) et les images (vault/m/*.bin) à la volée,
   avec la clé privée gardée sur l'appareil après le premier déverrouillage. */
const VERSION = 'arbre-v1';
const SHELL = ['./', './index.html', './manifest.webmanifest', './icons/icon-192.png', './icons/icon-512.png'];
const SCOPE = self.registration.scope;
const abs = p => new URL(p, SCOPE).href;

self.addEventListener('install', e => { self.skipWaiting(); e.waitUntil(caches.open(VERSION).then(c => c.addAll(SHELL)).catch(() => {})); });
self.addEventListener('activate', e => e.waitUntil((async () => {
  for (const k of await caches.keys()) if (k !== VERSION) await caches.delete(k);
  await self.clients.claim();
})()));

// ---------- IndexedDB (clé privée non exportable) ----------
function idb() { return new Promise((res, rej) => { const r = indexedDB.open('arbre-vault', 1); r.onupgradeneeded = () => r.result.createObjectStore('k'); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); }); }
async function idbGet(k) { const db = await idb(); return new Promise((res, rej) => { const t = db.transaction('k').objectStore('k').get(k); t.onsuccess = () => res(t.result || null); t.onerror = () => rej(t.error); }); }

let priv = null, ring = null; const kcache = {};
self.addEventListener('message', e => { if (e.data === 'lock') { priv = null; ring = null; for (const k in kcache) delete kcache[k]; } });
async function getPriv() { if (!priv) priv = await idbGet('priv'); return priv; }

const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
async function netFirst(p) {
  const c = await caches.open(VERSION);
  try { const r = await fetch(abs(p), { cache: 'no-store' }); if (r.ok) { c.put(abs(p), r.clone()); return r; } } catch (e) {}
  const m = await c.match(abs(p)); if (m) return m; throw new Error('offline: ' + p);
}
async function staleWhileRevalidate(p) {
  const c = await caches.open(VERSION); const m = await c.match(abs(p));
  const net = fetch(abs(p)).then(r => { if (r.ok) c.put(abs(p), r.clone()); return r; }).catch(() => null);
  if (m) return m; const r = await net; if (r && r.ok) return r; throw new Error('missing: ' + p);
}
async function keyFor(kid) {
  if (kcache[kid]) return kcache[kid];
  if (!ring || !ring[kid]) ring = await (await netFirst('vault/keys.json')).json();
  if (!ring[kid]) throw new Error('unknown key ' + kid);
  const raw = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, await getPriv(), b64(ring[kid]));
  return (kcache[kid] = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']));
}
async function openBox(buf) {
  const u = new Uint8Array(buf);
  if (u[0] !== 65 || u[1] !== 71 || u[2] !== 49) throw new Error('bad box');
  const kid = String.fromCharCode(...u.slice(3, 11));
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: u.slice(11, 23) }, await keyFor(kid), u.slice(23));
}

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (url.origin !== location.origin || !url.href.startsWith(SCOPE) || e.request.method !== 'GET') return;
  const rel = url.href.slice(SCOPE.length).split(/[?#]/)[0];
  if (rel === 'app.html') e.respondWith((async () => {
    try {
      if (!(await getPriv())) return Response.redirect(abs('./index.html'), 302);
      const html = await openBox(await (await netFirst('vault/app.bin')).arrayBuffer());
      return new Response(html, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
    } catch (err) { return Response.redirect(abs('./index.html?e=1'), 302); }
  })());
  else if (rel.startsWith('media/')) e.respondWith((async () => {
    try {
      const id = rel.slice(6).replace(/\.jpg$/, '');
      const data = await openBox(await (await staleWhileRevalidate('vault/m/' + id + '.bin')).arrayBuffer());
      return new Response(data, { headers: { 'content-type': 'image/jpeg' } });
    } catch (err) { return new Response('', { status: 404 }); }
  })());
  else if (rel.startsWith('vault/')) return; // fichiers chiffrés : réseau direct
  else e.respondWith((async () => {
    const c = await caches.open(VERSION);
    try { const r = await fetch(e.request); if (r.ok) c.put(e.request, r.clone()); return r; }
    catch (err) { return (await c.match(e.request)) || (await c.match(abs('./index.html'))) || Response.error(); }
  })());
});
