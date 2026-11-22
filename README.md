# Arbre généalogique (web app privée)

Web app installable (PWA) servie par GitHub Pages. **Tout le contenu est chiffré** :
l'application et les images ne s'ouvrent qu'avec le mot de passe.

## Fonctionnement

- `index.html` : écran de mot de passe (le seul fichier lisible).
- `sw.js` : service worker qui déchiffre l'application (`vault/app.bin`) et les images
  (`vault/m/*.bin`) sur l'appareil, et les garde en cache pour une consultation hors ligne.
- `vault/lock.json` : clé privée RSA chiffrée par le mot de passe (PBKDF2-SHA256, 600 000 itérations, AES-GCM).
  Changer le mot de passe (menu Sécurité de l'app) ne réécrit que ce fichier.
- `vault/pub.json` : clé publique, utilisée pour chiffrer chaque mise à jour sans connaître le mot de passe.
- `vault/keys.json` : clés AES de chaque mise à jour, enveloppées par la clé publique.

## Mettre à jour

L'arbre est reconstruit à partir des versions publiées dans Claude, puis chiffré :

```
node tools/pwa.mjs deploy --app <arbre-complet.html> --media <dossier des images>
git add -A && git commit -m "Mise à jour de l'arbre" && git push
```

Les images déjà présentes et inchangées ne sont pas rechiffrées.
