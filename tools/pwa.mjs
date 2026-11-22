#!/usr/bin/env node
// Chiffre l'arbre complet (HTML autonome + images) pour la web app GitHub Pages.
//
//   node tools/pwa.mjs init --password 1981          (une seule fois : crée la paire de clés)
//   node tools/pwa.mjs deploy --app <index.html> --media <dossier des images>
//
// Principe : une paire RSA. La clé publique (vault/pub.json) sert à chiffrer chaque mise à jour,
// sans connaître le mot de passe. La clé privée n'existe que chiffrée par le mot de passe
// (vault/lock.json, PBKDF2-SHA256 600 000 itérations + AES-GCM) ; changer le mot de passe
// ne réécrit que ce fichier. Chaque déploiement tire une clé AES neuve, enveloppée par RSA-OAEP
// dans vault/keys.json ; les images déjà présentes gardent la leur.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const V = p => path.join(ROOT, 'vault', p);
const args = Object.fromEntries(process.argv.slice(3).reduce((a, x, i, all) => (x.startsWith('--') ? a.concat([[x.slice(2), all[i + 1] && !all[i + 1].startsWith('--') ? all[i + 1] : true]]) : a), []));
const cmd = process.argv[2];
const ITER = 600000;
const b64 = b => Buffer.from(b).toString('base64');
const readJSON = (p, d) => (fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, 'utf8')) : d);
const writeJSON = (p, o) => fs.writeFileSync(p, JSON.stringify(o, null, 1) + '\n');
export const mediaId = rel => crypto.createHash('sha256').update('arbre-media:' + rel).digest('hex').slice(0, 24);

function gcm(key, data) { // => iv | ciphertext | tag  (format WebCrypto : ciphertext||tag)
  const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', key, iv);
  return { iv, ct: Buffer.concat([c.update(data), c.final(), c.getAuthTag()]) };
}
function box(kid, key, data) { const { iv, ct } = gcm(key, data); return Buffer.concat([Buffer.from('AG1' + kid, 'ascii'), iv, ct]); }

if (cmd === 'init') {
  if (fs.existsSync(V('lock.json')) && !args.force) { console.error('vault/lock.json existe déjà (--force pour recréer : tout serait à rechiffrer).'); process.exit(1); }
  const pw = String(args.password || '');
  if (!pw) { console.error('--password manquant'); process.exit(1); }
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 3072, publicKeyEncoding: { type: 'spki', format: 'der' }, privateKeyEncoding: { type: 'pkcs8', format: 'der' } });
  const salt = crypto.randomBytes(16), kek = crypto.pbkdf2Sync(pw, salt, ITER, 32, 'sha256');
  const { iv, ct } = gcm(kek, privateKey);
  fs.mkdirSync(V('m'), { recursive: true });
  writeJSON(V('pub.json'), { v: 1, alg: 'RSA-OAEP-3072-SHA256', spki: b64(publicKey) });
  writeJSON(V('lock.json'), { v: 1, kdf: 'PBKDF2-SHA256', iter: ITER, salt: b64(salt), iv: b64(iv), data: b64(ct) });
  writeJSON(V('keys.json'), {});
  console.log('Clés créées.');
} else if (cmd === 'deploy') {
  const pub = crypto.createPublicKey({ key: Buffer.from(readJSON(V('pub.json')).spki, 'base64'), format: 'der', type: 'spki' });
  const kid = crypto.randomBytes(4).toString('hex'), K = crypto.randomBytes(32);
  const ring = readJSON(V('keys.json'), {});
  ring[kid] = b64(crypto.publicEncrypt({ key: pub, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, K));
  const sums = readJSON(V('media.json'), {});
  let html = fs.readFileSync(args.app, 'utf8');
  const mediaDir = args.media ? path.resolve(args.media) : null;
  const refs = new Set(html.match(/\b(?:actes|faces|photos|thumbs)\/[A-Za-z0-9_\-]+\.jpg/g) || []);
  let added = 0, kept = 0; const missing = [];
  for (const rel of refs) {
    const id = mediaId(rel), out = V('m/' + id + '.bin'), src = mediaDir && path.join(mediaDir, rel);
    if (src && fs.existsSync(src)) {
      const data = fs.readFileSync(src), sha = crypto.createHash('sha256').update(data).digest('hex');
      if (sums[id] === sha && fs.existsSync(out)) kept++;
      else { fs.writeFileSync(out, box(kid, K, data)); sums[id] = sha; added++; }
    } else if (fs.existsSync(out)) kept++;
    else missing.push(rel);
  }
  html = html.replace(/\b(?:actes|faces|photos|thumbs)\/[A-Za-z0-9_\-]+\.jpg/g, rel => 'media/' + mediaId(rel) + '.jpg');
  // web app : manifeste, couleur, icône + module « Sécurité »
  html = html.replace('</head>', '<link rel="manifest" href="manifest.webmanifest">\n<meta name="theme-color" content="#121a28">\n<link rel="icon" href="icons/icon-192.png">\n</head>');
  const addon = fs.readFileSync(path.join(ROOT, 'tools/app-addon.html'), 'utf8'), i = html.lastIndexOf('</body>');
  html = html.slice(0, i) + addon + html.slice(i);
  fs.writeFileSync(V('app.bin'), box(kid, K, Buffer.from(html, 'utf8')));
  writeJSON(V('keys.json'), ring); writeJSON(V('media.json'), sums);
  console.log(`Clé ${kid} · app chiffrée · images : ${added} chiffrées, ${kept} déjà présentes, ${missing.length} manquantes`);
  if (missing.length) { fs.writeFileSync(path.join(ROOT, 'tools/missing.txt'), missing.join('\n') + '\n'); console.log('  -> liste dans tools/missing.txt'); }
} else {
  console.log('Usage : node tools/pwa.mjs init --password … | deploy --app … --media …');
}
