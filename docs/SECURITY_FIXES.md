# 🛡️ CORRECTIONS DE SÉCURITÉ v2.0

## Les 14 Protections Implémentées

---

## Vue d'Ensemble

| # | Vulnérabilité | Protection | Fichier(s) |
|---|---------------|------------|------------|
| 1 | Admin Login (htpasswd) | Basic Auth Nginx | `nginx/nginx.conf`, `nginx/htpasswd` |
| 2 | User-Agent / Referer | Middleware validation | `middlewares/headersSecurity.js` |
| 3 | Cookie Hash Manipulation | Cookies signés + httpOnly | `middlewares/auth.js` |
| 4 | SQL Injection — User | Sequelize ORM | `models/User.js` |
| 5 | SQL Injection — Image | Sequelize ORM | `models/Image.js` |
| 6 | Hidden Input (Recover) | Validation + CSRF | `validators/*.js`, `middlewares/csrf.js` |
| 7 | Login Bruteforce | Rate limit + Lockout + **Argon2id** | `middlewares/rateLimiter.js`, `utils/argon2.js` |
| 8 | Labyrinthe .hidden | Blocage Nginx | `nginx/nginx.conf` |
| 9 | Open Redirect | Whitelist URLs | `middlewares/redirectValidator.js` |
| 10 | LFI / Data URI | Validation paths | `middlewares/lfiProtection.js` |
| 11 | Survey Input Validation | express-validator | `validators/*.js` |
| 12 | Image Upload Bypass | Magic bytes + MIME | `middlewares/uploadSecurity.js` |
| 13 | Path Traversal | Sanitization | `middlewares/lfiProtection.js` |
| 14 | HTML Injection / XSS | Helmet CSP + escape | `middlewares/security.js`, `app.js` |

---

## 1. Admin Login (htpasswd)

### Configuration Nginx
```nginx
location /admin {
    auth_basic "Zone Administrative";
    auth_basic_user_file /etc/nginx/htpasswd;
    # ...
}
```

### Fichier htpasswd
```
admin:$apr1$xyz12345$LKg8bQwJzTJhZ5QnM5YH/0
```

---

## 2. User-Agent / Referer Header

### Middleware `headersSecurity.js`
- Bloque les User-Agents de scanners (sqlmap, nikto, burp...)
- Valide les Referers autorisés
- Log les tentatives suspectes

---

## 3. Cookie Hash Manipulation

### Protection
- Cookies `httpOnly` (inaccessibles en JavaScript)
- Cookies `secure` (HTTPS uniquement)
- Cookies `sameSite=strict` (anti-CSRF)
- Signature des cookies avec secret

---

## 4 & 5. SQL Injection (User & Image)

### Utilisation de Sequelize ORM
```javascript
// ❌ Vulnérable
db.query(`SELECT * FROM users WHERE id = ${id}`);

// ✅ Sécurisé avec ORM
const user = await User.findByPk(id);
```

---

## 6. Hidden Input (Recover)

### Protection CSRF
- Token CSRF dans les cookies
- Validation côté serveur
- Double Submit Cookie pattern

---

## 7. Login Bruteforce

### Triple protection
1. **Rate limiting** : 5 tentatives / 15 min
2. **Account lockout** : Blocage progressif (5min → 15min → 1h)
3. **Argon2id** : Hachage lent (300ms par tentative)

---

## 8. Labyrinthe .hidden

### Blocage Nginx
```nginx
location ~ /\. {
    deny all;
    return 404;
}

location ~* \.hidden {
    deny all;
    return 404;
}
```

---

## 9. Open Redirect

### Validation des URLs
- Whitelist des domaines autorisés
- Blocage des protocoles dangereux (javascript:, data:)
- Décodage récursif anti-bypass

---

## 10. LFI / Data URI

### Protection `lfiProtection.js`
- Détection de `../` (path traversal)
- Blocage des Data URIs
- Validation des chemins de fichiers

---

## 11. Survey Input Validation

### express-validator
```javascript
body('content')
  .trim()
  .isLength({ min: 1, max: 1000 })
  .escape()
```

---

## 12. Image Upload Bypass

### Triple validation
1. **Extension** : Whitelist (.jpg, .png, .gif, .webp)
2. **MIME type** : Vérification Content-Type
3. **Magic bytes** : Vérification signature binaire

---

## 13. Path Traversal

### Sanitization
```javascript
const sanitizePath = (input) => {
  return input
    .replace(/\.\.\//g, '')
    .replace(/%2e%2e%2f/gi, '')
    .replace(/\x00/g, '');
};
```

---

## 14. HTML Injection / XSS

### Protection multi-couches
1. **Helmet CSP** : Content-Security-Policy
2. **xss-clean** : Sanitization automatique
3. **DOMPurify** : Côté frontend
4. **escape()** : Dans les templates

---

## 🔐 Argon2id (Recommandation OWASP 2023)

### Pourquoi Argon2id ?
- Résistant aux attaques GPU
- Memory-hard (64 MB)
- Temps constant (anti timing attacks)

### Configuration
```javascript
const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 65536,  // 64 MB
  timeCost: 3,        // 3 itérations
  parallelism: 4,     // 4 threads
  hashLength: 32,     // 256 bits
};
```

---

## Conformité OWASP Top 10 (2021)

| # | Catégorie | Statut |
|---|-----------|--------|
| A01 | Broken Access Control | ✅ |
| A02 | Cryptographic Failures | ✅ (Argon2id) |
| A03 | Injection | ✅ (ORM) |
| A04 | Insecure Design | ✅ (Security by Design) |
| A05 | Security Misconfiguration | ✅ (Helmet, CORS) |
| A06 | Vulnerable Components | ✅ (npm audit) |
| A07 | Auth Failures | ✅ (Rate limit, lockout) |
| A08 | Data Integrity Failures | ✅ (Validation) |
| A09 | Logging Failures | ✅ (Winston) |
| A10 | SSRF | ✅ (Validation URLs) |

---

**Projet IPSSI - Module Cybersécurité**
